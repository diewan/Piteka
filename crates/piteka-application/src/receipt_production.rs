//! Receipt production and evidence collection (Master Plan §60 E-06).
//!
//! This module implements the application-level webhook event processor that
//! transforms authenticated, deduplicated GitHub deployment-status webhooks into
//! structured evidence nodes and canonical execution receipts.
//!
//! # Flow
//!
//! 1. A validated `deployment_status` webhook arrives via the ingestion layer.
//! 2. The processor matches the webhook's deployment ID to an execution attempt.
//! 3. The GitHub-reported outcome is mapped to a [`ReceiptOutcome`].
//! 4. Evidence nodes (Observation from GitHub, Claim from Piteka, EvidenceGap)
//!    are created with full source attribution.
//! 5. A canonical receipt is produced and stored.
//!
//! # Source attribution
//!
//! Per Master Plan §10.5, every evidence node records whether it comes from
//! Piteka, an external provider (GitHub), or the verifier. This distinction
//! is preserved in storage and in exported bundles.
//!
//! # Missing evidence
//!
//! When required evidence is unavailable (e.g. no artifact attestation), an
//! `EvidenceGap` node is created rather than inferring success or failure.
//! The outcome remains `Unknown` when target evidence cannot be established.

use async_trait::async_trait;
use sha2::{Digest, Sha256};

use piteka_storage::digest::ContentDigest;
use piteka_storage::model::{
    EvidenceNodeRecord, EvidenceSource, ReceiptOutcome, ReceiptProjection,
};
use piteka_storage::ports::{
    AuditLog, EvidenceNodeStore, ExecutionAttemptStore, ReceiptProjectionStore,
};

use crate::Clock;
use crate::webhook_ingestion::WebhookEventProcessor;
use crate::webhook_ingestion::error::{WebhookError, WebhookResult};

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Errors returned by the receipt production use case.
#[derive(Debug)]
pub enum ReceiptProductionError {
    /// A storage failure occurred.
    Storage(piteka_storage::StorageError),
    /// The execution attempt was not found.
    AttemptNotFound(String),
}

impl From<piteka_storage::StorageError> for ReceiptProductionError {
    fn from(err: piteka_storage::StorageError) -> Self {
        Self::Storage(err)
    }
}

impl core::fmt::Display for ReceiptProductionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Storage(err) => write!(f, "storage error: {err}"),
            Self::AttemptNotFound(id) => write!(f, "execution attempt `{id}` not found"),
        }
    }
}

impl std::error::Error for ReceiptProductionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Storage(err) => Some(err),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// GitHub deployment status parsing
// ---------------------------------------------------------------------------

/// A parsed GitHub deployment status event.
#[derive(Clone, Debug)]
pub struct DeploymentStatusEvent {
    /// The GitHub-assigned deployment ID.
    pub deployment_id: u64,
    /// The deployment status state.
    pub state: String,
    /// GitHub's description of the outcome.
    pub description: Option<String>,
    /// URL to the deployment status details.
    pub target_url: Option<String>,
    /// When the status was updated (Unix seconds).
    pub updated_at: u64,
}

/// Parses a raw GitHub deployment_status webhook payload.
pub fn parse_deployment_status(payload: &[u8]) -> Option<DeploymentStatusEvent> {
    let value: serde_json::Value = serde_json::from_slice(payload).ok()?;

    let deployment_id = value.get("deployment")?.get("id")?.as_u64()?;
    // GitHub's live webhook schema nests these fields under
    // `deployment_status`. Retained fixtures used the status object itself.
    let status = value.get("deployment_status").unwrap_or(&value);
    let state = status.get("state")?.as_str()?.to_string();
    let description = status
        .get("description")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let target_url = status
        .get("target_url")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    // GitHub's API uses an ISO-8601 string. Numeric timestamps remain accepted
    // for retained fixtures, but negative values must never wrap into the
    // distant future.
    let updated_at_value = status.get("updated_at")?;
    let updated_at = if let Some(value) = updated_at_value.as_u64() {
        value
    } else if let Some(value) = updated_at_value.as_i64() {
        u64::try_from(value).ok()?
    } else {
        let value = updated_at_value.as_str()?;
        u64::try_from(
            chrono::DateTime::parse_from_rfc3339(value)
                .ok()?
                .timestamp(),
        )
        .ok()?
    };

    Some(DeploymentStatusEvent {
        deployment_id,
        state,
        description,
        target_url,
        updated_at,
    })
}

/// Maps a GitHub deployment status state to a Piteka [`ReceiptOutcome`].
pub fn map_github_state_to_outcome(github_state: &str) -> ReceiptOutcome {
    match github_state.to_lowercase().as_str() {
        "success" => ReceiptOutcome::Succeeded,
        "failure" | "error" => ReceiptOutcome::Failed,
        "inactive" | "pending" | "queued" => ReceiptOutcome::Unknown,
        _ => ReceiptOutcome::Unknown,
    }
}

// ---------------------------------------------------------------------------
// Evidence node construction
// ---------------------------------------------------------------------------

fn compute_evidence_node_id(
    source: &EvidenceSource,
    mandate_id: &str,
    attempt_id: &str,
    evidence_type: &str,
    extra: &str,
) -> ContentDigest {
    let mut hasher = Sha256::new();
    match source {
        EvidenceSource::Piteka => hasher.update(b"piteka"),
        EvidenceSource::Provider(p) => hasher.update(p.as_bytes()),
        EvidenceSource::Verifier => hasher.update(b"verifier"),
    }
    hasher.update(mandate_id.as_bytes());
    hasher.update(b"|");
    hasher.update(attempt_id.as_bytes());
    hasher.update(b"|");
    hasher.update(evidence_type.as_bytes());
    hasher.update(b"|");
    hasher.update(extra.as_bytes());
    ContentDigest::from_bytes(hasher.finalize().into())
}

fn create_observation_node(
    mandate_id: &str,
    attempt_id: &str,
    event: &DeploymentStatusEvent,
    collected_at: i64,
) -> EvidenceNodeRecord {
    let node_id = compute_evidence_node_id(
        &EvidenceSource::Provider("github".to_string()),
        mandate_id,
        attempt_id,
        "deployment_status",
        &event.state,
    );

    let payload = serde_json::json!({
        "deployment_id": event.deployment_id,
        "state": event.state,
        "description": event.description,
        "target_url": event.target_url,
        "updated_at": event.updated_at,
    });

    let payload_bytes = serde_json::to_vec(&payload).unwrap_or_default();
    let content_digest = ContentDigest::of(&payload_bytes);

    EvidenceNodeRecord {
        node_id_hex: format!("ev-{}", node_id.to_hex()),
        registry_id: "org.diewan.evidence.observation.v1".to_string(),
        source: EvidenceSource::Provider("github".to_string()),
        producer_identity: "github".to_string(),
        collected_at_unix_seconds: collected_at,
        asserted_event_at_unix_seconds: Some(event.updated_at as i64),
        content_digest,
        media_type: "application/github-deployment-status+json".to_string(),
        disclosure_classification: "disclosed".to_string(),
        relationships: vec![],
    }
}

fn create_claim_node(
    mandate_id: &str,
    attempt_id: &str,
    outcome: &ReceiptOutcome,
    collected_at: i64,
) -> EvidenceNodeRecord {
    let node_id = compute_evidence_node_id(
        &EvidenceSource::Piteka,
        mandate_id,
        attempt_id,
        "outcome_claim",
        outcome_as_str(outcome),
    );

    let payload = serde_json::json!({
        "outcome": outcome_as_str(outcome),
        "claimed_by": "piteka",
    });

    let payload_bytes = serde_json::to_vec(&payload).unwrap_or_default();
    let content_digest = ContentDigest::of(&payload_bytes);

    EvidenceNodeRecord {
        node_id_hex: format!("ev-{}", node_id.to_hex()),
        registry_id: "org.diewan.evidence.claim.v1".to_string(),
        source: EvidenceSource::Piteka,
        producer_identity: "piteka".to_string(),
        collected_at_unix_seconds: collected_at,
        asserted_event_at_unix_seconds: None,
        content_digest,
        media_type: "application/piteka-outcome-claim+json".to_string(),
        disclosure_classification: "disclosed".to_string(),
        relationships: vec![],
    }
}

fn create_gap_node(
    mandate_id: &str,
    attempt_id: &str,
    missing_class: &str,
    reason: &str,
    collected_at: i64,
) -> EvidenceNodeRecord {
    let mut hasher = Sha256::new();
    hasher.update(mandate_id.as_bytes());
    hasher.update(b"|");
    hasher.update(attempt_id.as_bytes());
    hasher.update(b"|");
    hasher.update(b"evidence_gap");
    hasher.update(b"|");
    hasher.update(missing_class.as_bytes());
    hasher.update(b"|");
    hasher.update(reason.as_bytes());
    let node_id = ContentDigest::from_bytes(hasher.finalize().into());

    let reason_digest = ContentDigest::of(reason.as_bytes());

    EvidenceNodeRecord {
        node_id_hex: format!("ev-{}", node_id.to_hex()),
        registry_id: "org.diewan.evidence.gap.v1".to_string(),
        source: EvidenceSource::Piteka,
        producer_identity: "piteka".to_string(),
        collected_at_unix_seconds: collected_at,
        asserted_event_at_unix_seconds: None,
        content_digest: ContentDigest::from_bytes(*reason_digest.as_bytes()),
        media_type: "text/plain".to_string(),
        disclosure_classification: "disclosed".to_string(),
        relationships: vec![],
    }
}

/// Converts a receipt outcome to its string representation.
pub fn outcome_as_str(outcome: &ReceiptOutcome) -> &'static str {
    match outcome {
        ReceiptOutcome::Succeeded => "succeeded",
        ReceiptOutcome::Failed => "failed",
        ReceiptOutcome::Rejected => "rejected",
        ReceiptOutcome::Unknown => "unknown",
    }
}

// ---------------------------------------------------------------------------
// Receipt production
// ---------------------------------------------------------------------------

/// The result of a receipt production operation.
#[derive(Debug, Clone)]
pub struct ReceiptProductionResult {
    /// The receipt identifier.
    pub receipt_id_hex: String,
    /// The reported outcome.
    pub outcome: ReceiptOutcome,
    /// Evidence node IDs produced during receipt creation.
    pub evidence_node_ids: Vec<String>,
    /// Evidence gap IDs for missing required evidence.
    pub evidence_gaps: Vec<String>,
}

/// Produces an execution receipt from a deployment status webhook.
///
/// This is the core E-06 use case. It:
///
/// 1. Finds the execution attempt by matching the GitHub deployment ID.
/// 2. Maps the GitHub state to a [`ReceiptOutcome`].
/// 3. Creates structured evidence nodes with source attribution.
/// 4. Detects missing evidence gaps.
/// 5. Stores the receipt and evidence nodes.
/// 6. Records audit events.
pub async fn produce_receipt_from_webhook<R, E, A, C>(
    tenant: &piteka_storage::TenantScope,
    receipt_store: &R,
    evidence_store: &E,
    audit_log: &A,
    attempt_store: &dyn ExecutionAttemptStore,
    event: &DeploymentStatusEvent,
    clock: &C,
) -> Result<ReceiptProductionResult, ReceiptProductionError>
where
    R: ReceiptProjectionStore,
    E: EvidenceNodeStore,
    A: AuditLog,
    C: Clock,
{
    let now = clock.unix_seconds() as i64;

    // 1. Find the execution attempt by deployment ID.
    let attempt = attempt_store
        .by_deployment_id(tenant, event.deployment_id)
        .await?
        .ok_or_else(|| {
            ReceiptProductionError::AttemptNotFound(format!(
                "no attempt found for deployment_id={}",
                event.deployment_id
            ))
        })?;

    let attempt_id_hex = &attempt.attempt_id_hex;
    let mandate_id_hex = &attempt.mandate_id_hex;
    let intent_id_hex = &attempt.intent_id_hex;

    // 2. Map GitHub state to outcome.
    let outcome = map_github_state_to_outcome(&event.state);

    // 3. Create evidence nodes with source attribution.
    let observation_node = create_observation_node(mandate_id_hex, attempt_id_hex, event, now);
    let claim_node = create_claim_node(mandate_id_hex, attempt_id_hex, &outcome, now);

    // 4. Detect missing evidence gaps.
    let mut evidence_gaps = Vec::new();

    if outcome == ReceiptOutcome::Unknown {
        let gap = create_gap_node(
            mandate_id_hex,
            attempt_id_hex,
            "target_outcome",
            "GitHub deployment status is pending/inactive; outcome cannot be determined",
            now,
        );
        evidence_gaps.push(gap.node_id_hex.clone());
        evidence_store.insert(tenant, gap).await?;
    }

    // 5. Store evidence nodes.
    evidence_store
        .insert(tenant, observation_node.clone())
        .await?;
    evidence_store.insert(tenant, claim_node.clone()).await?;

    // 6. Build and store the receipt.
    let receipt_id_hex = format!("rcpt-{}", attempt_id_hex);
    let receipt = ReceiptProjection {
        receipt_id_hex: receipt_id_hex.clone(),
        mandate_id_hex: mandate_id_hex.clone(),
        intent_id_hex: intent_id_hex.clone(),
        attempt_id_hex: attempt_id_hex.clone(),
        outcome: outcome.clone(),
        created_at_unix_seconds: now,
        dispatch_evidence_refs: vec![claim_node.node_id_hex.clone()],
        target_evidence_refs: vec![observation_node.node_id_hex.clone()],
        evidence_gaps: evidence_gaps.clone(),
        canonical_bytes: None,
    };

    receipt_store.insert(tenant, receipt).await?;

    // 7. Audit.
    audit_log
        .append(
            tenant,
            piteka_storage::model::AuditEvent {
                occurred_at_unix_seconds: now,
                actor: None,
                action: "receipt.produced".to_string(),
                decision: outcome_as_str(&outcome).to_string(),
                detail: format!(
                    "receipt={} mandate={} attempt={} github_state={} outcome={}",
                    receipt_id_hex,
                    mandate_id_hex,
                    attempt_id_hex,
                    event.state,
                    outcome_as_str(&outcome)
                ),
            },
        )
        .await?;

    Ok(ReceiptProductionResult {
        receipt_id_hex,
        outcome,
        evidence_node_ids: vec![observation_node.node_id_hex, claim_node.node_id_hex],
        evidence_gaps,
    })
}

// ---------------------------------------------------------------------------
// WebhookEventProcessor implementation
// ---------------------------------------------------------------------------

/// A receipt-producing webhook event processor.
pub struct ReceiptProducingProcessor<R, E, A>
where
    R: ReceiptProjectionStore,
    E: EvidenceNodeStore,
    A: AuditLog,
{
    tenant: piteka_storage::TenantScope,
    receipt_store: R,
    evidence_store: E,
    audit_log: A,
    attempt_store: std::sync::Arc<dyn ExecutionAttemptStore>,
}

impl<R, E, A> Clone for ReceiptProducingProcessor<R, E, A>
where
    R: ReceiptProjectionStore + Clone,
    E: EvidenceNodeStore + Clone,
    A: AuditLog + Clone,
{
    fn clone(&self) -> Self {
        Self {
            tenant: self.tenant.clone(),
            receipt_store: self.receipt_store.clone(),
            evidence_store: self.evidence_store.clone(),
            audit_log: self.audit_log.clone(),
            attempt_store: self.attempt_store.clone(),
        }
    }
}

impl<R, E, A> ReceiptProducingProcessor<R, E, A>
where
    R: ReceiptProjectionStore,
    E: EvidenceNodeStore,
    A: AuditLog,
{
    #[must_use]
    pub fn new(
        tenant: piteka_storage::TenantScope,
        receipt_store: R,
        evidence_store: E,
        audit_log: A,
        attempt_store: std::sync::Arc<dyn ExecutionAttemptStore>,
    ) -> Self {
        Self {
            tenant,
            receipt_store,
            evidence_store,
            audit_log,
            attempt_store,
        }
    }
}

#[async_trait]
impl<R, E, A> WebhookEventProcessor for ReceiptProducingProcessor<R, E, A>
where
    R: ReceiptProjectionStore + 'static,
    E: EvidenceNodeStore + 'static,
    A: AuditLog + 'static,
{
    async fn process(
        &self,
        event_type: &str,
        payload: &[u8],
        delivery_id: &str,
        _out_of_order: bool,
    ) -> WebhookResult<()> {
        if event_type != "deployment_status" {
            return Err(WebhookError::UnsupportedEventType(event_type.to_string()));
        }

        let event = parse_deployment_status(payload).ok_or_else(|| {
            WebhookError::Malformed("invalid deployment_status payload".to_string())
        })?;

        // Provider progress is evidence of activity, not an execution outcome.
        // Preserve ingestion/audit records but defer the immutable receipt
        // until GitHub reports one terminal state.
        if !matches!(event.state.as_str(), "success" | "failure" | "error") {
            self.audit_log
                .append(
                    &self.tenant,
                    piteka_storage::model::AuditEvent {
                        occurred_at_unix_seconds: crate::SystemClock.unix_seconds() as i64,
                        actor: None,
                        action: "webhook.status_non_terminal".to_string(),
                        decision: "deferred".to_string(),
                        detail: format!(
                            "delivery_id={delivery_id} deployment_id={} state={}",
                            event.deployment_id, event.state
                        ),
                    },
                )
                .await
                .map_err(WebhookError::Storage)?;
            return Ok(());
        }

        let clock = crate::SystemClock;

        match produce_receipt_from_webhook(
            &self.tenant,
            &self.receipt_store,
            &self.evidence_store,
            &self.audit_log,
            &*self.attempt_store,
            &event,
            &clock,
        )
        .await
        {
            Ok(result) => {
                let _ = self
                    .audit_log
                    .append(
                        &self.tenant,
                        piteka_storage::model::AuditEvent {
                            occurred_at_unix_seconds: clock.unix_seconds() as i64,
                            actor: None,
                            action: "webhook.receipt_produced".to_string(),
                            decision: outcome_as_str(&result.outcome).to_string(),
                            detail: format!(
                                "delivery_id={} receipt={} outcome={} evidence_nodes={} gaps={}",
                                delivery_id,
                                result.receipt_id_hex,
                                outcome_as_str(&result.outcome),
                                result.evidence_node_ids.len(),
                                result.evidence_gaps.len()
                            ),
                        },
                    )
                    .await;
                Ok(())
            }
            Err(ReceiptProductionError::AttemptNotFound(_)) => {
                let _ = self
                    .audit_log
                    .append(
                        &self.tenant,
                        piteka_storage::model::AuditEvent {
                            occurred_at_unix_seconds: clock.unix_seconds() as i64,
                            actor: None,
                            action: "webhook.attempt_not_found".to_string(),
                            decision: "skipped".to_string(),
                            detail: format!(
                                "delivery_id={} deployment_id={} no matching attempt",
                                delivery_id, event.deployment_id
                            ),
                        },
                    )
                    .await;
                Ok(())
            }
            Err(err) => {
                let _ = self
                    .audit_log
                    .append(
                        &self.tenant,
                        piteka_storage::model::AuditEvent {
                            occurred_at_unix_seconds: clock.unix_seconds() as i64,
                            actor: None,
                            action: "webhook.receipt_production_error".to_string(),
                            decision: "error".to_string(),
                            detail: format!("delivery_id={} error={}", delivery_id, err),
                        },
                    )
                    .await;
                Ok(())
            }
        }
    }
}
