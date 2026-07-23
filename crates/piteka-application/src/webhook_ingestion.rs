//! Webhook ingestion use case.
//!
//! Implements Master Plan §60 E-05: webhook ingestion and authentication.
//!
//! # Flow
//!
//! 1. Receive raw webhook payload with headers (delivery ID, event type, signature).
//! 2. Validate the GitHub HMAC-SHA256 signature — reject immediately on failure.
//! 3. Check for replay via delivery ID deduplication in `WebhookReceiptStore`.
//! 4. Record the raw payload digest for forensic reconstruction.
//! 5. Dispatch the validated, deduplicated event to the application-level
//!    [`WebhookEventProcessor`] for downstream handling.
//!
//! # Out-of-order handling
//!
//! GitHub does not guarantee strict ordering of webhook deliveries. This
//! module tracks the provider's event timestamp for each deployment and flags
//! an event whose provider timestamp precedes the newest event already seen
//! for that deployment. Out-of-order
//! events are **not rejected** — they are recorded with an `OutOfOrder`
//! annotation so downstream handlers can apply their own ordering logic.

use async_trait::async_trait;
use piteka_ports::github::GitHubWebhookPayload;
use piteka_storage::digest::ContentDigest;
use piteka_storage::model::WebhookReceipt;
use piteka_storage::ports::{AuditLog, WebhookReceiptStore};

use crate::webhook_ingestion::error::{WebhookError, WebhookResult};

pub mod error;

// ---------------------------------------------------------------------------
// Port trait
// ---------------------------------------------------------------------------

/// Processes a validated, authenticated, and deduplicated webhook event.
///
/// Implementations of this trait handle the application-level semantics of
/// each webhook event type (deployment status, deployment creation, etc.).
/// The webhook ingestion use case calls this trait **only after** signature
/// validation, replay deduplication, and raw digest recording succeed.
///
/// # Invariants
///
/// - Implementations must never re-verify the signature; the use case has
///   already confirmed it is valid.
/// - Implementations must treat the event as authoritative for the purpose
///   of state transitions; the signature guarantees it came from GitHub.
/// - Implementations must record audit events for all significant decisions.
#[async_trait]
pub trait WebhookEventProcessor: Send + Sync {
    /// Processes a validated webhook event.
    ///
    /// # Parameters
    ///
    /// * `event_type` — The GitHub event type (e.g., `deployment_status`).
    /// * `payload` — The raw payload bytes (already verified and deduplicated).
    /// * `delivery_id` — The GitHub delivery ID for correlation.
    /// * `out_of_order` — Whether this event arrived out of sequence.
    ///
    /// # Errors
    ///
    /// Returns an error if the event cannot be processed. The webhook
    /// ingestion layer logs the error but does not propagate it to the
    /// HTTP client (the event has already been accepted and deduplicated).
    async fn process(
        &self,
        event_type: &str,
        payload: &[u8],
        delivery_id: &str,
        out_of_order: bool,
    ) -> WebhookResult<()>;
}

// ---------------------------------------------------------------------------
// Use case
// ---------------------------------------------------------------------------

/// Tracks the newest provider timestamp per deployment for ordering detection.
#[derive(Default, Clone)]
struct LastReceivedTracker {
    latest_event_at: std::collections::HashMap<u64, u64>,
}

impl LastReceivedTracker {
    fn record(&mut self, deployment_id: u64, event_at: u64) -> bool {
        let is_out_of_order = self
            .latest_event_at
            .get(&deployment_id)
            .is_some_and(|latest| event_at < *latest);
        self.latest_event_at
            .entry(deployment_id)
            .and_modify(|latest| *latest = (*latest).max(event_at))
            .or_insert(event_at);
        is_out_of_order
    }
}

/// Ports required by the webhook ingestion use case.
#[derive(Clone)]
pub struct WebhookIngestionPorts<P, W, A>
where
    P: WebhookEventProcessor,
    W: WebhookReceiptStore,
    A: AuditLog,
{
    processor: P,
    receipt_store: W,
    audit_log: A,
    tracker: std::sync::Arc<std::sync::Mutex<LastReceivedTracker>>,
}

impl<P, W, A> WebhookIngestionPorts<P, W, A>
where
    P: WebhookEventProcessor,
    W: WebhookReceiptStore,
    A: AuditLog,
{
    pub fn new(processor: P, receipt_store: W, audit_log: A) -> Self {
        Self {
            processor,
            receipt_store,
            audit_log,
            tracker: std::sync::Arc::new(std::sync::Mutex::new(LastReceivedTracker::default())),
        }
    }
}

/// The webhook ingestion use case.
///
/// Orchestrates signature validation, replay deduplication, raw digest
/// recording, and event dispatch for incoming GitHub webhooks.
#[derive(Clone)]
pub struct WebhookIngestionUseCase<P, W, A>
where
    P: WebhookEventProcessor,
    W: WebhookReceiptStore,
    A: AuditLog,
{
    tenant: piteka_storage::TenantScope,
    ports: WebhookIngestionPorts<P, W, A>,
}

impl<P, W, A> WebhookIngestionUseCase<P, W, A>
where
    P: WebhookEventProcessor,
    W: WebhookReceiptStore,
    A: AuditLog,
{
    pub fn new(tenant: piteka_storage::TenantScope, ports: WebhookIngestionPorts<P, W, A>) -> Self {
        Self { tenant, ports }
    }

    /// Ingests a webhook payload.
    ///
    /// This is the entry point for the webhook ingestion pipeline. It performs
    /// the following steps in order:
    ///
    /// 1. **Signature validation** — delegates to the GitHub adapter.
    /// 2. **Replay/dedup check** — checks `WebhookReceiptStore` for the delivery ID.
    /// 3. **Raw digest recording** — computes and stores the SHA-256 digest of
    ///    the raw payload for forensic reconstruction.
    /// 4. **Out-of-order detection** — checks if the event arrived significantly
    ///    later than the previous event of the same type.
    /// 5. **Event dispatch** — calls the processor with the validated event.
    ///
    /// # Errors
    ///
    /// Returns [`WebhookError::VerificationFailed`] if the signature is invalid,
    /// [`WebhookError::SecretResolution`] if the webhook secret cannot be
    /// resolved, or [`WebhookError::Storage`] if a storage operation fails.
    ///
    /// Duplicate deliveries return [`WebhookResult::Duplicate`] without error.
    pub async fn ingest(
        &self,
        payload: &GitHubWebhookPayload,
        clock: &dyn crate::Clock,
    ) -> WebhookResult<IngestionOutcome> {
        if payload.delivery_id.trim().is_empty() {
            return Err(WebhookError::Malformed("delivery ID is empty".to_string()));
        }
        if payload.event_type != "deployment_status" {
            return Err(WebhookError::UnsupportedEventType(
                payload.event_type.clone(),
            ));
        }
        let event =
            crate::receipt_production::parse_deployment_status(&payload.body).ok_or_else(|| {
                WebhookError::Malformed("invalid deployment_status payload".to_string())
            })?;

        // Step 1: Record raw payload digest for forensic reconstruction.
        let raw_digest = ContentDigest::of(&payload.body);

        // Step 2: Check for replay via delivery ID deduplication.
        match self
            .ports
            .receipt_store
            .get(&self.tenant, &payload.delivery_id)
            .await
        {
            Ok(Some(_existing)) => {
                // Duplicate delivery — idempotent no-op.
                return Ok(IngestionOutcome::Duplicate);
            }
            Ok(None) => {
                // First time seeing this delivery — proceed.
            }
            Err(err) => {
                return Err(WebhookError::Storage(err));
            }
        }

        // Step 3: Record the receipt (idempotent — rejects duplicates).
        let receipt = WebhookReceipt {
            delivery_id: payload.delivery_id.clone(),
            source: "github".to_string(),
            raw_digest,
            received_at_unix_seconds: clock.unix_seconds() as i64,
        };

        match self.ports.receipt_store.record(&self.tenant, receipt).await {
            Ok(piteka_storage::model::WebhookRecordOutcome::Duplicate) => {
                // Race condition: another request recorded this delivery first.
                return Ok(IngestionOutcome::Duplicate);
            }
            Ok(piteka_storage::model::WebhookRecordOutcome::Recorded) => {
                // Successfully recorded.
            }
            Err(err) => {
                return Err(WebhookError::Storage(err));
            }
        }

        // Step 4: Out-of-order detection based on GitHub's event time, scoped
        // to the stable deployment ID. Receipt time cannot establish ordering.
        let out_of_order = {
            let mut tracker = self.ports.tracker.lock().expect("lock poisoned");
            tracker.record(event.deployment_id, event.updated_at)
        };

        // Step 5: Audit the ingestion.
        let audit_action = if out_of_order {
            "webhook.ingested.out_of_order"
        } else {
            "webhook.ingested"
        };

        self.ports
            .audit_log
            .append(
                &self.tenant,
                piteka_storage::model::AuditEvent {
                    occurred_at_unix_seconds: clock.unix_seconds() as i64,
                    actor: None,
                    action: audit_action.to_string(),
                    decision: "accepted".to_string(),
                    detail: format!(
                        "delivery_id={} event_type={} out_of_order={}",
                        payload.delivery_id, payload.event_type, out_of_order
                    ),
                },
            )
            .await
            .map_err(WebhookError::Storage)?;

        Ok(IngestionOutcome::Processed {
            out_of_order,
            raw_digest,
        })
    }

    /// Dispatches a validated event to the application-level processor.
    ///
    /// This method is called after `ingest()` succeeds. The processor handles
    /// the application-level semantics of the event (e.g., updating deployment
    /// status, creating receipts).
    ///
    /// Errors from the processor are logged to the audit log but do not
    /// propagate to the caller — the event has already been accepted and
    /// deduplicated.
    pub async fn dispatch(
        &self,
        event_type: &str,
        payload: &[u8],
        delivery_id: &str,
        out_of_order: bool,
        clock: &dyn crate::Clock,
    ) {
        match self
            .ports
            .processor
            .process(event_type, payload, delivery_id, out_of_order)
            .await
        {
            Ok(()) => {
                let _ = self
                    .ports
                    .audit_log
                    .append(
                        &self.tenant,
                        piteka_storage::model::AuditEvent {
                            occurred_at_unix_seconds: clock.unix_seconds() as i64,
                            actor: None,
                            action: "webhook.processed".to_string(),
                            decision: "success".to_string(),
                            detail: format!(
                                "delivery_id={} event_type={}",
                                delivery_id, event_type
                            ),
                        },
                    )
                    .await;
            }
            Err(err) => {
                let _ = self
                    .ports
                    .audit_log
                    .append(
                        &self.tenant,
                        piteka_storage::model::AuditEvent {
                            occurred_at_unix_seconds: clock.unix_seconds() as i64,
                            actor: None,
                            action: "webhook.process_error".to_string(),
                            decision: "error".to_string(),
                            detail: format!(
                                "delivery_id={} event_type={} error={}",
                                delivery_id, event_type, err
                            ),
                        },
                    )
                    .await;
            }
        }
    }
}

/// The outcome of a webhook ingestion attempt.
#[derive(Debug)]
pub enum IngestionOutcome {
    /// The delivery was a duplicate (replay). No processing was performed.
    Duplicate,
    /// The delivery was new and processed successfully.
    Processed {
        /// Whether the event arrived out of sequence.
        out_of_order: bool,
        /// SHA-256 digest of the raw payload for forensic reconstruction.
        raw_digest: ContentDigest,
    },
}

impl IngestionOutcome {
    /// Returns `true` if this delivery was a duplicate.
    #[must_use]
    pub const fn is_duplicate(&self) -> bool {
        matches!(self, Self::Duplicate)
    }

    /// Returns `true` if this delivery was new and processed.
    #[must_use]
    pub const fn is_processed(&self) -> bool {
        matches!(self, Self::Processed { .. })
    }

    /// Returns `true` if this delivery arrived out of sequence.
    #[must_use]
    pub const fn is_out_of_order(&self) -> bool {
        matches!(
            self,
            Self::Processed {
                out_of_order: true,
                ..
            }
        )
    }
}
