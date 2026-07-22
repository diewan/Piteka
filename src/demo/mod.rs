//! Demo actors for the Master Plan §3 vertical slice.
//!
//! DEMO-01 (Scenario A): an autonomous agent client drives the Piteka MCP tools
//! under a single-use mandate, replacing the human/script "execute" click of the
//! controlled demo. The agent speaks only the constrained MCP surface
//! ([`piteka_mcp::handle`]); it never touches the use cases, the database, or a
//! GitHub execution credential directly.
//!
//! Authority boundaries preserved here:
//!
//! - The **agent** may propose ([`AgentActor::request_deployment`]), read status,
//!   execute an already-approved mandate, and read a receipt. It has no approval
//!   tool — approval is a human act.
//! - The **human approver** is modelled by [`human_approve`], a path the agent
//!   cannot reach through MCP. Approval issues the single-use mandate projection.
//! - The **server** recomputes the intent digest from the actual parameters and
//!   rejects any mismatch (changed parameters after approval never dispatch), and
//!   the Postgres/in-memory CAS reservation makes a second execute a visible
//!   replay rejection with no provider call.
//!
//! The same [`AgentDemoBackend`] runs against in-memory stores with a fake GitHub
//! port (the deterministic e2e test) and against Postgres with the live GitHub App
//! adapter (the `agent_demo_flow` binary). No simulated mandates, receipts, or
//! verdicts are produced: every artifact comes from the real use cases.

use std::sync::Arc;

use async_trait::async_trait;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use piteka_application::dispatch::compute_attempt_digest;
use piteka_application::mcp::{
    AccountabilityTools, ExecuteDeployment, McpError, McpIdentity, RequestDeployment,
};
use piteka_application::{
    ActionRequestPorts, ActionRequestUseCase, Clock, DispatchOutcome, DispatchPorts,
    DispatchUseCase,
};
use piteka_domain::UserId;
use piteka_ports::github::GitHubAppPort;
use piteka_storage::{
    ActionRequestStore, ApprovalDecisionStore, AuditLog, ExecutionAttemptStore,
    MandateProjectionStore, ReceiptProjectionStore,
};

pub mod agent;

pub use agent::{AgentActor, AgentError, DeploymentPlan};

/// The digest label namespace ties every derived id to this demo profile so a
/// value can never be mistaken for a production Parwana object id.
const INTENT_LABEL: &str = "piteka-demo-intent-v1";
const MANDATE_LABEL: &str = "piteka-demo-mandate-v1";
const RESERVATION_LABEL: &str = "piteka-demo-reservation-v1";

fn digest(label: &str, values: &[&str]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(label.as_bytes());
    for value in values {
        hasher.update(b"|");
        hasher.update(value.as_bytes());
    }
    hex::encode(hasher.finalize())
}

/// Server-authoritative intent digest for the demo profile.
///
/// This is the single derivation both the agent (to propose a matching intent)
/// and the server (to recompute and reject mismatches) rely on. It binds the
/// tenant to the exact deployment parameters; changing any one produces a
/// different digest.
#[must_use]
pub fn demo_intent_id(
    tenant: &str,
    repository_id: u64,
    commit_sha: &str,
    environment_id: u64,
) -> String {
    digest(
        INTENT_LABEL,
        &[
            tenant,
            &repository_id.to_string(),
            commit_sha,
            &environment_id.to_string(),
        ],
    )
}

/// The single-use mandate id bound to an authorized intent digest.
#[must_use]
pub fn demo_mandate_id(intent_id: &str) -> String {
    digest(MANDATE_LABEL, &[intent_id])
}

/// Digest of the reservation token that CAS-reserves the mandate. The secret
/// itself is never handed to the agent; only its digest reaches storage.
#[must_use]
pub fn demo_reservation_digest(mandate_id: &str) -> String {
    digest(RESERVATION_LABEL, &[mandate_id])
}

/// Provider-side correlation key derived from the mandate id.
#[must_use]
pub fn demo_correlation_key(mandate_id: &str) -> String {
    format!("piteka:{}", &mandate_id[..24])
}

/// A cloneable bundle of the stores and clock the demo use cases require.
///
/// Holding trait objects lets one concrete type serve both the in-memory test
/// wiring and the Postgres binary wiring without duplicating the port glue.
#[derive(Clone)]
pub struct DemoPorts {
    /// Action request store (proposal + approval status projection).
    pub requests: Arc<dyn ActionRequestStore>,
    /// Approval decision store.
    pub decisions: Arc<dyn ApprovalDecisionStore>,
    /// Single-use mandate live-state projection (CAS reservation authority).
    pub mandates: Arc<dyn MandateProjectionStore>,
    /// Execution attempt journal.
    pub attempts: Arc<dyn ExecutionAttemptStore>,
    /// Receipt projection store.
    pub receipts: Arc<dyn ReceiptProjectionStore>,
    /// Append-only audit log.
    pub audit: Arc<dyn AuditLog>,
    /// Clock for timestamps.
    pub clock: Arc<dyn Clock>,
}

impl ActionRequestPorts for DemoPorts {
    fn request_store(&self) -> &dyn ActionRequestStore {
        self.requests.as_ref()
    }
    fn decision_store(&self) -> &dyn ApprovalDecisionStore {
        self.decisions.as_ref()
    }
    fn audit_log(&self) -> &dyn AuditLog {
        self.audit.as_ref()
    }
    fn clock(&self) -> &dyn Clock {
        self.clock.as_ref()
    }
}

impl DispatchPorts for DemoPorts {
    fn request_store(&self) -> &dyn ActionRequestStore {
        self.requests.as_ref()
    }
    fn mandate_store(&self) -> &dyn MandateProjectionStore {
        self.mandates.as_ref()
    }
    fn attempt_store(&self) -> &dyn ExecutionAttemptStore {
        self.attempts.as_ref()
    }
    fn receipt_store(&self) -> &dyn ReceiptProjectionStore {
        self.receipts.as_ref()
    }
    fn audit_log(&self) -> &dyn AuditLog {
        self.audit.as_ref()
    }
    fn clock(&self) -> &dyn Clock {
        self.clock.as_ref()
    }
}

/// The human approval step, deliberately outside the MCP surface.
///
/// The approver reviews the exact `intent_id` and approves the pending request;
/// approval issues the single-use mandate projection at version 1. Returns the
/// mandate id the agent will later execute. The agent has no way to call this.
///
/// # Errors
///
/// Returns an error if the request is not pending, the approval CAS conflicts,
/// or the mandate projection cannot be issued.
pub async fn human_approve(
    ports: &DemoPorts,
    approver: &str,
    request_id: &str,
    intent_id: &str,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let actions = ActionRequestUseCase::new(ports.clone());
    actions
        .approve(
            request_id,
            UserId::new(approver)?,
            Some(intent_id.to_string()),
            1,
        )
        .await?;
    let mandate_id = demo_mandate_id(intent_id);
    ports.mandates.insert(&mandate_id, "issued").await?;
    Ok(mandate_id)
}

/// A real [`AccountabilityTools`] backend wired to the Piteka use cases.
///
/// Generic over the GitHub port so the same logic runs with a fake port in the
/// deterministic e2e test and the live GitHub App adapter in the binary. The
/// backend owns no live state of its own: reservation and consumption live in
/// the mandate projection store's CAS.
pub struct AgentDemoBackend<G: GitHubAppPort> {
    ports: DemoPorts,
    github: G,
}

impl<G: GitHubAppPort> AgentDemoBackend<G> {
    /// Constructs a backend over the given ports and GitHub port.
    pub const fn new(ports: DemoPorts, github: G) -> Self {
        Self { ports, github }
    }

    /// Borrows the ports (used by the orchestrator to drive the human approval
    /// step and to inspect final projections).
    #[must_use]
    pub fn ports(&self) -> &DemoPorts {
        &self.ports
    }

    /// Confirms the MCP-supplied provider ids match this backend's configured
    /// installation. A demo backend serves exactly one repository/environment;
    /// an agent asking for any other target is rejected before reservation.
    fn check_target(&self, repository_id: u64, environment_id: u64) -> Result<(), McpError> {
        let context = self.github.installation_context();
        if repository_id != context.repository_id.as_u64()
            || environment_id != context.environment_id.as_u64()
        {
            return Err(McpError::new(
                "TARGET_NOT_CONFIGURED",
                "The requested repository/environment is not the configured demo target",
            ));
        }
        Ok(())
    }
}

#[async_trait]
impl<G: GitHubAppPort> AccountabilityTools for AgentDemoBackend<G> {
    async fn recompute_intent_id(
        &self,
        tenant: &str,
        repository_id: u64,
        commit_sha: &str,
        environment_id: u64,
    ) -> Result<String, McpError> {
        Ok(demo_intent_id(tenant, repository_id, commit_sha, environment_id))
    }

    async fn request_deployment(
        &self,
        identity: &McpIdentity,
        input: RequestDeployment,
    ) -> Result<Value, McpError> {
        self.check_target(input.repository_id, input.environment_id)?;
        let requester = UserId::new(identity.service_identity())
            .map_err(|_| McpError::new("UNAUTHENTICATED", "Invalid service identity"))?;
        let actions = ActionRequestUseCase::new(self.ports.clone());
        actions
            .propose(&input.request_id, requester, Some(input.intent_id.clone()))
            .await
            .map_err(|error| {
                McpError::new("REQUEST_REJECTED", format!("Proposal rejected: {error}"))
            })?;
        Ok(json!({
            "status": "pending",
            "request_id": input.request_id,
            "intent_id": input.intent_id,
            "tenant": identity.tenant_id(),
        }))
    }

    async fn get_action_status(
        &self,
        identity: &McpIdentity,
        id: &str,
    ) -> Result<Value, McpError> {
        let request = self
            .ports
            .requests
            .get(id)
            .await
            .map_err(|error| McpError::new("INTERNAL_ERROR", format!("Status read failed: {error}")))?
            .ok_or_else(|| McpError::new("NOT_FOUND", "Unknown action request"))?;

        let status = format!("{:?}", request.status).to_lowercase();
        let mut value = json!({
            "request_id": request.request_id,
            "status": status,
            "intent_id": request.intent_id_hex,
            "tenant": identity.tenant_id(),
        });

        // Once approved, disclose the single-use mandate id the agent must
        // execute — but only if the mandate projection has actually been issued.
        if request.status == piteka_storage::model::ActionRequestStatus::Approved {
            if let Some(intent_id) = request.intent_id_hex.as_deref() {
                let mandate_id = demo_mandate_id(intent_id);
                if self
                    .ports
                    .mandates
                    .get(&mandate_id)
                    .await
                    .map_err(|error| {
                        McpError::new("INTERNAL_ERROR", format!("Mandate read failed: {error}"))
                    })?
                    .is_some()
                {
                    value
                        .as_object_mut()
                        .expect("json object")
                        .insert("mandate_id".into(), json!(mandate_id));
                }
            }
        }
        Ok(value)
    }

    async fn execute_approved_deployment(
        &self,
        identity: &McpIdentity,
        input: ExecuteDeployment,
    ) -> Result<Value, McpError> {
        self.check_target(input.repository_id, input.environment_id)?;

        // The mandate presented must be the one bound to the authorized intent.
        // call_tool already recomputed and matched the intent; this closes the
        // remaining gap that a caller could pair a valid intent with a foreign
        // mandate id.
        let expected_mandate = demo_mandate_id(&input.intent_id);
        if input.mandate_id != expected_mandate {
            let mut error = McpError::new(
                "MANDATE_MISMATCH",
                "The mandate does not correspond to the authorized intent",
            );
            error.details = Some(json!({
                "supplied_mandate_id": input.mandate_id,
                "expected_mandate_id": expected_mandate,
            }));
            return Err(error);
        }

        let executor = identity.service_identity();
        let reservation_digest = demo_reservation_digest(&input.mandate_id);
        let correlation_key = demo_correlation_key(&input.mandate_id);

        let dispatch = DispatchUseCase::new(self.ports.clone());
        let reserved = dispatch
            .reserve(
                &input.request_id,
                &input.mandate_id,
                &input.intent_id,
                executor,
                &reservation_digest,
                &correlation_key,
                1,
            )
            .await
            .map_err(|error| {
                McpError::new("DISPATCH_ERROR", format!("Reservation failed: {error}"))
            })?;

        let dispatched = match reserved {
            DispatchOutcome::Dispatched(value) => value,
            // A second execute of a consumed/quarantined mandate: the CAS
            // rejection is authoritative and no provider call was made.
            DispatchOutcome::ReplayRejected(rejection) => return Err(rejection.into()),
            DispatchOutcome::ReservationFailed(failed) => {
                return Err(McpError::new(
                    "RESERVATION_CONTESTED",
                    format!(
                        "Another executor holds mandate {} at version {}",
                        failed.mandate_id_hex, failed.winner_version
                    ),
                ));
            }
            DispatchOutcome::DispatchFailed { error, .. } => {
                return Err(McpError::new(
                    "DISPATCH_FAILED",
                    format!("Mandate quarantined before provider call: {error}"),
                ));
            }
        };

        let attempt_digest = compute_attempt_digest(
            &dispatched.attempt_id_hex,
            &input.mandate_id,
            &input.intent_id,
        );

        // The dispatch boundary: hand the exact intent to the provider through
        // the injected port. The agent never holds these credentials.
        let context = self.github.installation_context();
        let created = self
            .github
            .create_deployment(
                &context.installation_id,
                &context.repository_id,
                &input.commit_sha,
                &context.environment_name,
                false,
                &input.intent_id,
                attempt_digest,
            )
            .await;

        match created {
            Ok(created) => {
                dispatch
                    .complete_dispatch(
                        &dispatched.attempt_id_hex,
                        &input.mandate_id,
                        &input.intent_id,
                        true,
                        Some(created.deployment_id),
                        executor,
                        2,
                    )
                    .await
                    .map_err(|error| {
                        McpError::new(
                            "DISPATCH_ERROR",
                            format!("Completion failed after provider acceptance: {error}"),
                        )
                    })?;
                Ok(json!({
                    "dispatched": true,
                    "request_id": input.request_id,
                    "mandate_id": input.mandate_id,
                    "intent_id": input.intent_id,
                    "attempt_id": dispatched.attempt_id_hex,
                    "attempt_digest": hex::encode(attempt_digest),
                    "github_deployment_id": created.deployment_id,
                    "github_deployment_url": created.url,
                    "tenant": identity.tenant_id(),
                }))
            }
            Err(error) => {
                // Provider rejected/uncertain: quarantine through the normal
                // path. The mandate never becomes executable again.
                dispatch
                    .complete_dispatch(
                        &dispatched.attempt_id_hex,
                        &input.mandate_id,
                        &input.intent_id,
                        false,
                        None,
                        executor,
                        2,
                    )
                    .await
                    .map_err(|error| {
                        McpError::new(
                            "DISPATCH_ERROR",
                            format!("Completion failed after provider error: {error}"),
                        )
                    })?;
                Err(McpError::new(
                    "PROVIDER_DISPATCH_FAILED",
                    format!("GitHub deployment failed; mandate quarantined: {error}"),
                ))
            }
        }
    }

    async fn get_receipt(&self, identity: &McpIdentity, id: &str) -> Result<Value, McpError> {
        // The demo "receipt" is the durable execution-attempt journal produced
        // by the real dispatch flow. `id` may be the attempt id directly or the
        // mandate id (the agent knows the latter from execute).
        let attempt = if let Some(attempt) = self
            .ports
            .attempts
            .get(id)
            .await
            .map_err(read_error)?
        {
            Some(attempt)
        } else {
            self.ports
                .attempts
                .by_mandate(id)
                .await
                .map_err(read_error)?
                .into_iter()
                .next()
        };

        let attempt = attempt.ok_or_else(|| McpError::new("NOT_FOUND", "No execution attempt"))?;
        Ok(json!({
            "attempt_id": attempt.attempt_id_hex,
            "mandate_id": attempt.mandate_id_hex,
            "intent_id": attempt.intent_id_hex,
            "state": format!("{:?}", attempt.state).to_lowercase(),
            "github_deployment_id": attempt.github_deployment_id,
            "tenant": identity.tenant_id(),
            "limitation": "Demo identity is not production identity.",
        }))
    }

    async fn export_dispute_bundle(
        &self,
        _identity: &McpIdentity,
        _id: &str,
    ) -> Result<Value, McpError> {
        // Dispute export is DEMO-03 scope; the agent actor does not drive it.
        Err(McpError::new(
            "NOT_IMPLEMENTED",
            "Dispute export is not part of the Scenario A agent flow",
        ))
    }

    async fn verify_bundle(&self, _identity: &McpIdentity, _id: &str) -> Result<Value, McpError> {
        Err(McpError::new(
            "NOT_IMPLEMENTED",
            "Bundle verification is not part of the Scenario A agent flow",
        ))
    }
}

fn read_error(error: impl std::fmt::Display) -> McpError {
    McpError::new("INTERNAL_ERROR", format!("Read failed: {error}"))
}
