//! Dispatch use case: atomic reserve-and-dispatch (E-03).
//!
//! This module implements the critical-path use case where an approved mandate
//! is atomically reserved and dispatched to a provider (GitHub). The flow is:
//!
//! 1. **Reserve** — CAS on the mandate projection (`Issued → Reserved`).
//!    Exactly one concurrent caller wins; all others receive a conflict.
//! 2. **Dispatch** — If reservation succeeds, the provider is called
//!    (`create_deployment`). The mandate transitions to `Quarantined` once the
//!    provider *may* have accepted the action.
//! 3. **Consume** — If the provider accepts, the mandate transitions
//!    `Reserved → Consumed` and a receipt is recorded.
//! 4. **Quarantine** — If the provider outcome is ambiguous (e.g. timeout),
//!    the mandate enters `Quarantined` and MUST NOT become executable again
//!    merely because a query returned no result.
//!
//! # Invariants enforced
//!
//! - **One concurrent winner.** The CAS on the mandate projection guarantees
//!   exactly one reservation succeeds. A second concurrent attempt receives a
//!   [`DispatchError::ReservationConflict`].
//! - **Durable journal.** Every state transition is recorded in the execution
//!   attempt store and the mandate projection store before the method returns.
//! - **Exact dispatch boundary.** The mandate transitions to `Quarantined` the
//!   moment the provider call completes (success or failure). No dispatch
//!   happens without a successful reservation.
//! - **No simulated success.** If the provider call fails, the mandate is
//!   quarantined (not consumed). The outcome is `Unknown`, never `Succeeded`.
//!
//! # Security
//!
//! Execution credentials (GitHub private key) never leave the adapter layer.
//! The raw reservation token is secret and is never written to exported bundles.

use piteka_storage::model::{ExecutionAttempt, ExecutionAttemptState};
use piteka_storage::ports::{
    ActionRequestStore, AuditLog, ExecutionAttemptStore, MandateProjectionStore,
    ReceiptProjectionStore,
};
use piteka_storage::{ActionRequestStatus, CasOutcome, StorageError};

use crate::Clock;

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Errors returned by the dispatch use case.
#[derive(Debug)]
pub enum DispatchError {
    /// A storage failure occurred.
    Storage(StorageError),
    /// The action request was not found.
    NotFound(String),
    /// The request status does not allow dispatch.
    InvalidTransition { current: ActionRequestStatus },
    /// The mandate projection was not found.
    MandateNotFound(String),
    /// Reservation failed due to a concurrent winner.
    ReservationConflict { current_version: i64 },
    /// The mandate was already consumed or in a terminal state.
    AlreadyConsumed(String),
    /// The GitHub dispatch call failed.
    DispatchFailed(String),
    /// GitHub reported acceptance without the required deployment ID.
    InvalidProviderResponse(String),
    /// The executor identity does not match the allowed subject.
    UnauthorizedExecutor(String),
}

impl From<StorageError> for DispatchError {
    fn from(err: StorageError) -> Self {
        Self::Storage(err)
    }
}

impl core::fmt::Display for DispatchError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Storage(err) => write!(f, "storage error: {err}"),
            Self::NotFound(id) => write!(f, "action request `{id}` not found"),
            Self::InvalidTransition { current } => {
                write!(f, "cannot dispatch from status {:?}", current)
            }
            Self::MandateNotFound(id) => write!(f, "mandate projection `{id}` not found"),
            Self::ReservationConflict { current_version } => {
                write!(
                    f,
                    "reservation conflict: another caller won, current version {current_version}"
                )
            }
            Self::AlreadyConsumed(id) => {
                write!(f, "mandate `{id}` is already consumed or terminal")
            }
            Self::DispatchFailed(msg) => write!(f, "dispatch to provider failed: {msg}"),
            Self::InvalidProviderResponse(msg) => write!(f, "invalid provider response: {msg}"),
            Self::UnauthorizedExecutor(executor) => {
                write!(f, "executor `{executor}` is not the authorized subject")
            }
        }
    }
}

impl std::error::Error for DispatchError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Storage(err) => Some(err),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Result types
// ---------------------------------------------------------------------------

/// The outcome of a successful reserve-and-dispatch.
#[derive(Debug, Clone)]
pub struct DispatchedExecution {
    /// The mandate id that was reserved.
    pub mandate_id_hex: String,
    /// The attempt id that was created.
    pub attempt_id_hex: String,
    /// The intent that was dispatched.
    pub intent_id_hex: String,
    /// The executor identity.
    pub executor_identity: String,
    /// The correlation key used for provider-side matching.
    pub correlation_key: String,
    /// Whether the provider accepted the dispatch.
    pub provider_accepted: bool,
    /// The GitHub-assigned deployment ID, set after `create_deployment` succeeds.
    ///
    /// E-04: This field is `None` until the provider call completes. It is the
    /// stable reference used for webhook correlation and reconciliation.
    pub github_deployment_id: Option<u64>,
}

/// The outcome of a failed reservation (concurrent winner).
#[derive(Debug, Clone)]
pub struct ReservationConflict {
    /// The mandate id that was contested.
    pub mandate_id_hex: String,
    /// The version currently held by the winner.
    pub winner_version: i64,
}

/// The outcome of the provider dispatch call.
///
/// E-04: This struct carries the GitHub deployment ID and attempt digest
/// returned by the provider, enabling webhook correlation.
#[derive(Debug)]
pub struct ProviderDispatchResult {
    /// The GitHub-assigned deployment ID.
    pub deployment_id: u64,
    /// SHA-256 digest of the correlation payload sent to the provider.
    pub attempt_digest: [u8; 32],
}

/// The outcome of the dispatch use case.
#[derive(Debug)]
pub enum DispatchOutcome {
    /// The mandate was reserved and dispatched successfully.
    Dispatched(DispatchedExecution),
    /// Another caller won the reservation.
    ReservationFailed(ReservationConflict),
    /// A second use of a terminal single-use mandate was rejected before any
    /// provider call. The appended audit event is the Piteka-produced evidence
    /// of the rejected attempt.
    ReplayRejected(ReplayRejection),
    /// The dispatch failed (mandate quarantined).
    DispatchFailed {
        mandate_id_hex: String,
        attempt_id_hex: String,
        error: String,
    },
}

/// Evidence returned for a rejected repeat use of a single-use mandate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayRejection {
    /// Stable reason code suitable for MCP and UI surfaces.
    pub reason_code: &'static str,
    /// The mandate whose repeat use was rejected.
    pub mandate_id_hex: String,
    /// The request presented by the repeat caller.
    pub request_id: String,
    /// Identity that attempted the repeat use.
    pub executor_identity: String,
    /// Authoritative terminal state observed by Piteka.
    pub mandate_state: String,
    /// Human-readable sentence defined by the product language authority.
    pub message: String,
}

// ---------------------------------------------------------------------------
// Ports
// ---------------------------------------------------------------------------

/// Ports required by the dispatch use case.
pub trait DispatchPorts: Send + Sync {
    /// Action request store for status checks.
    fn request_store(&self) -> &dyn ActionRequestStore;

    /// Mandate projection store for CAS reservation.
    fn mandate_store(&self) -> &dyn MandateProjectionStore;

    /// Execution attempt store for the durable journal.
    fn attempt_store(&self) -> &dyn ExecutionAttemptStore;

    /// Receipt projection store.
    fn receipt_store(&self) -> &dyn ReceiptProjectionStore;

    /// Audit log for recording dispatch events.
    fn audit_log(&self) -> &dyn AuditLog;

    /// Clock for timestamps.
    fn clock(&self) -> &dyn Clock;
}

/// Computes the attempt digest for provider-side correlation.
///
/// E-04: The digest is a SHA-256 over the attempt ID, mandate ID, and intent ID.
/// It is incorporated into the GitHub deployment payload so that incoming
/// webhooks can be correlated back to the Piteka execution attempt.
pub fn compute_attempt_digest(attempt_id: &str, mandate_id: &str, intent_id: &str) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(attempt_id.as_bytes());
    hasher.update(b"|");
    hasher.update(mandate_id.as_bytes());
    hasher.update(b"|");
    hasher.update(intent_id.as_bytes());
    hasher.finalize().into()
}

// ---------------------------------------------------------------------------
// Use case
// ---------------------------------------------------------------------------

/// Orchestrates the atomic reserve-and-dispatch flow.
///
/// # Dispatch boundary (E-03)
///
/// The dispatch boundary is the exact point where the mandate transitions from
/// `Reserved` to either `Consumed` (provider accepted) or `Quarantined`
/// (provider outcome ambiguous or call failed). No dispatch to the provider
/// happens without a successful CAS reservation.
///
/// ```text
/// ┌─────────────┐    CAS success    ┌──────────────┐
/// │   Issued    │ ────────────────► │   Reserved   │
/// └─────────────┘                   └──────┬───────┘
///                                          │
///                    ┌─────────────────────┼─────────────────────┐
///                    │                     │                     │
///              provider              provider              provider
///              accepts                 fails              timeout
///                    │                     │                     │
///                    ▼                     ▼                     ▼
///            ┌─────────────┐      ┌──────────────┐    ┌──────────────┐
///            │  Consumed   │      │ Quarantined  │    │ Quarantined  │
///            └─────────────┘      └──────────────┘    └──────────────┘
/// ```
///
/// Once the mandate is `Consumed`, `Quarantined`, or `Abandoned`, it cannot
/// be dispatched again. A second dispatch attempt on the same mandate will
/// fail with [`DispatchError::AlreadyConsumed`].
#[derive(Clone)]
pub struct DispatchUseCase<P> {
    tenant: piteka_storage::TenantScope,
    ports: P,
}

impl<P: DispatchPorts> DispatchUseCase<P> {
    /// Creates a new dispatch use-case orchestrator.
    #[must_use]
    pub fn new(tenant: piteka_storage::TenantScope, ports: P) -> Self {
        Self { tenant, ports }
    }

    /// Reserves a mandate and dispatches to the provider.
    ///
    /// This is the atomic reserve-and-dispatch operation (E-03). The flow is:
    ///
    /// 1. Verify the action request exists and is in `Approved` status.
    /// 2. Apply CAS on the mandate projection to reserve it.
    /// 3. If CAS succeeds, create an execution attempt and dispatch to the provider.
    /// 4. Record the attempt state and mandate state transition.
    /// 5. Return the outcome.
    ///
    /// # Concurrency
    ///
    /// The CAS on the mandate projection ensures exactly one concurrent winner.
    /// If another caller has already reserved the mandate, this method returns
    /// [`DispatchOutcome::ReservationFailed`] without dispatching.
    ///
    /// # Dispatch boundary
    ///
    /// The mandate transitions to `Quarantined` the moment the provider call
    /// completes (success or failure). This is the dispatch boundary: once
    /// crossed, the mandate is no longer executable.
    ///
    /// # Parameters
    ///
    /// * `request_id` — The action request to dispatch (must be `Approved`).
    /// * `mandate_id_hex` — The mandate to reserve and dispatch.
    /// * `intent_id_hex` — The intent digest this dispatch targets.
    /// * `executor_identity` — The service identity performing the dispatch.
    /// * `reservation_token_digest` — Digest of the reservation token (secret).
    /// * `correlation_key` — Provider-side correlation key.
    /// * `expected_mandate_version` — The expected version for CAS.
    ///
    /// # Provider dispatch
    ///
    /// The actual provider call (`create_deployment`) is performed by the
    /// caller after this method returns `DispatchOutcome::Dispatched`. This
    /// method sets up the execution attempt and mandate state; the caller
    /// records the final outcome.
    ///
    /// To perform the full reserve → dispatch → consume flow in one call,
    /// use [`DispatchUseCase::reserve_and_dispatch`].
    #[allow(clippy::too_many_arguments)]
    pub async fn reserve(
        &self,
        request_id: &str,
        mandate_id_hex: &str,
        intent_id_hex: &str,
        executor_identity: &str,
        reservation_token_digest: &str,
        correlation_key: &str,
        expected_mandate_version: i64,
    ) -> Result<DispatchOutcome, DispatchError> {
        let now = self.ports.clock().unix_seconds() as i64;

        // 1. Verify the request exists and is Approved.
        let request = self
            .ports
            .request_store()
            .get(&self.tenant, request_id)
            .await?
            .ok_or_else(|| DispatchError::NotFound(request_id.to_string()))?;

        if request.status != ActionRequestStatus::Approved {
            return Err(DispatchError::InvalidTransition {
                current: request.status,
            });
        }

        // 2. Apply CAS on the mandate projection.
        let cas_result = self
            .ports
            .mandate_store()
            .compare_and_swap(
                &self.tenant,
                mandate_id_hex,
                expected_mandate_version,
                "reserved",
            )
            .await?;

        match cas_result {
            CasOutcome::Applied { .. } => {
                // 3. Create the execution attempt (Prepared state).
                let attempt_id_hex = format!("att-{}", mandate_id_hex);
                let attempt = ExecutionAttempt {
                    attempt_id_hex: attempt_id_hex.clone(),
                    mandate_id_hex: mandate_id_hex.to_string(),
                    intent_id_hex: intent_id_hex.to_string(),
                    reservation_token_digest: reservation_token_digest.to_string(),
                    executor_identity: executor_identity.to_string(),
                    correlation_key: correlation_key.to_string(),
                    started_at_unix_seconds: now,
                    dispatch_boundary_at_unix_seconds: None,
                    state: ExecutionAttemptState::Prepared,
                    github_deployment_id: None,
                    protocol_closure: None,
                };

                self.ports
                    .attempt_store()
                    .insert(&self.tenant, attempt)
                    .await?;

                // 4. Transition attempt to Dispatching.
                self.ports
                    .attempt_store()
                    .update_state(
                        &self.tenant,
                        &attempt_id_hex,
                        ExecutionAttemptState::Dispatching,
                    )
                    .await?;

                // 5. Record audit event.
                self.ports
                    .audit_log()
                    .append(
                        &self.tenant,
                        piteka_storage::AuditEvent {
                            occurred_at_unix_seconds: now,
                            actor: Some(executor_identity.to_string()),
                            action: "reserve_mandate".to_string(),
                            decision: "granted".to_string(),
                            detail: format!(
                                "mandate {} reserved for request {}, attempt {}, version {}",
                                mandate_id_hex,
                                request_id,
                                attempt_id_hex,
                                expected_mandate_version
                            ),
                        },
                    )
                    .await?;

                Ok(DispatchOutcome::Dispatched(DispatchedExecution {
                    mandate_id_hex: mandate_id_hex.to_string(),
                    attempt_id_hex,
                    intent_id_hex: intent_id_hex.to_string(),
                    executor_identity: executor_identity.to_string(),
                    correlation_key: correlation_key.to_string(),
                    provider_accepted: false, // not yet known
                    github_deployment_id: None,
                }))
            }
            CasOutcome::Conflict { current_version } => {
                // A conflict against a terminal live-state projection is not a
                // routine race: it is a repeat-use attempt. Record it before
                // returning so the rejection itself becomes append-only
                // evidence. A merely reserved mandate remains a normal
                // concurrent reservation conflict.
                if let Some(projection) = self
                    .ports
                    .mandate_store()
                    .get(&self.tenant, mandate_id_hex)
                    .await?
                {
                    if matches!(
                        projection.state.as_str(),
                        "consumed" | "quarantined" | "abandoned"
                    ) {
                        let reason_code = "MANDATE.REPLAY_DETECTED";
                        let message = format!(
                            "Repeat use rejected. Approval {mandate_id_hex} was already used; nothing was sent to GitHub."
                        );
                        self.ports
                            .audit_log()
                            .append(&self.tenant, piteka_storage::AuditEvent {
                                occurred_at_unix_seconds: now,
                                actor: Some(executor_identity.to_string()),
                                action: "execute_approved_deployment".to_string(),
                                decision: "denied".to_string(),
                                detail: format!(
                                    "{reason_code}: mandate {mandate_id_hex} is {}; request {request_id}; provider dispatch suppressed",
                                    projection.state
                                ),
                            })
                            .await?;

                        return Ok(DispatchOutcome::ReplayRejected(ReplayRejection {
                            reason_code,
                            mandate_id_hex: mandate_id_hex.to_string(),
                            request_id: request_id.to_string(),
                            executor_identity: executor_identity.to_string(),
                            mandate_state: projection.state,
                            message,
                        }));
                    }
                }
                Ok(DispatchOutcome::ReservationFailed(ReservationConflict {
                    mandate_id_hex: mandate_id_hex.to_string(),
                    winner_version: current_version,
                }))
            }
            CasOutcome::Missing => Err(DispatchError::MandateNotFound(mandate_id_hex.to_string())),
        }
    }

    /// Completes the dispatch flow: records provider acceptance and transitions
    /// the mandate to `Consumed`, or records failure and transitions to
    /// `Quarantined`.
    ///
    /// This method is called after the provider dispatch call completes. It
    /// records the outcome in the execution attempt and receipt stores.
    ///
    /// E-04: The `deployment_id` is recorded in the execution attempt record
    /// when the provider accepts the dispatch. This enables webhook correlation:
    /// when a deployment-status webhook arrives, Piteka can match it to the
    /// correct attempt by comparing the deployment ID.
    ///
    /// # Parameters
    ///
    /// * `attempt_id_hex` — The attempt to complete.
    /// * `mandate_id_hex` — The mandate to transition.
    /// * `intent_id_hex` — The intent digest.
    /// * `provider_accepted` — Whether the provider accepted the dispatch.
    /// * `deployment_id` — The GitHub-assigned deployment ID, if the provider accepted.
    /// * `executor_identity` — The executor identity (for audit).
    /// * `expected_mandate_version` — Expected version for CAS on mandate.
    #[allow(clippy::too_many_arguments)]
    pub async fn complete_dispatch(
        &self,
        attempt_id_hex: &str,
        mandate_id_hex: &str,
        _intent_id_hex: &str,
        provider_accepted: bool,
        deployment_id: Option<u64>,
        executor_identity: &str,
        expected_mandate_version: i64,
    ) -> Result<(), DispatchError> {
        let now = self.ports.clock().unix_seconds() as i64;
        let missing_deployment_id = provider_accepted && deployment_id.is_none();
        // An acceptance response without GitHub's required ID is ambiguous:
        // quarantine it through the normal uncertainty path, then surface the
        // malformed response to the caller.
        let provider_accepted = provider_accepted && !missing_deployment_id;

        if provider_accepted {
            let deployment_id = deployment_id.expect("checked above");

            // Provider accepted: transition attempt to Accepted, mandate to Consumed.
            self.ports
                .attempt_store()
                .update_state(
                    &self.tenant,
                    attempt_id_hex,
                    ExecutionAttemptState::Accepted,
                )
                .await?;

            // Record the GitHub deployment ID for webhook correlation (E-04).
            self.ports
                .attempt_store()
                .update_deployment_id(&self.tenant, attempt_id_hex, deployment_id)
                .await?;

            // CAS the mandate to Consumed.
            let cas_result = self
                .ports
                .mandate_store()
                .compare_and_swap(
                    &self.tenant,
                    mandate_id_hex,
                    expected_mandate_version,
                    "consumed",
                )
                .await?;

            match cas_result {
                CasOutcome::Applied { .. } => {
                    // Receipt production is deferred until authenticated
                    // provider outcome evidence arrives via webhook.
                    self.ports
                        .audit_log()
                        .append(
                            &self.tenant,
                            piteka_storage::AuditEvent {
                                occurred_at_unix_seconds: now,
                                actor: Some(executor_identity.to_string()),
                                action: "consume_mandate".to_string(),
                                decision: "granted".to_string(),
                                detail: format!(
                                    "mandate {} consumed after provider acceptance, attempt {}",
                                    mandate_id_hex, attempt_id_hex
                                ),
                            },
                        )
                        .await?;
                }
                CasOutcome::Conflict { .. } => {
                    // Another caller already consumed the mandate.
                    // This should not happen in normal flow, but we handle it.
                    return Err(DispatchError::AlreadyConsumed(mandate_id_hex.to_string()));
                }
                CasOutcome::Missing => {
                    return Err(DispatchError::MandateNotFound(mandate_id_hex.to_string()));
                }
            }
        } else {
            // Provider failed or outcome ambiguous: transition to Quarantined.
            self.ports
                .attempt_store()
                .update_state(
                    &self.tenant,
                    attempt_id_hex,
                    ExecutionAttemptState::OutcomeAmbiguous,
                )
                .await?;

            // CAS the mandate to Quarantined.
            let cas_result = self
                .ports
                .mandate_store()
                .compare_and_swap(
                    &self.tenant,
                    mandate_id_hex,
                    expected_mandate_version,
                    "quarantined",
                )
                .await?;

            match cas_result {
                CasOutcome::Applied { .. } => {
                    // No receipt is fabricated for an ambiguous boundary.
                    // Reconciliation or authenticated provider evidence owns
                    // subsequent receipt production.
                    self.ports
                        .audit_log()
                        .append(
                            &self.tenant,
                            piteka_storage::AuditEvent {
                                occurred_at_unix_seconds: now,
                                actor: Some(executor_identity.to_string()),
                                action: "quarantine_mandate".to_string(),
                                decision: "denied".to_string(),
                                detail: format!(
                                    "mandate {} quarantined after provider failure, attempt {}",
                                    mandate_id_hex, attempt_id_hex
                                ),
                            },
                        )
                        .await?;
                }
                CasOutcome::Conflict { .. } => {
                    // Mandate was already consumed by another path.
                    // The attempt is already in OutcomeAmbiguous state.
                }
                CasOutcome::Missing => {
                    return Err(DispatchError::MandateNotFound(mandate_id_hex.to_string()));
                }
            }
        }

        if missing_deployment_id {
            Err(DispatchError::InvalidProviderResponse(
                "accepted GitHub deployment response did not include a deployment ID".to_string(),
            ))
        } else {
            Ok(())
        }
    }

    /// Full atomic reserve-and-dispatch in one call.
    ///
    /// This is the canonical E-03 operation: reserve the mandate, dispatch to
    /// the provider, and record the outcome — all in a single method call.
    ///
    /// E-04: The attempt digest is computed from the attempt ID, mandate ID,
    /// and intent ID. It is passed to the provider dispatch function so that
    /// the GitHub deployment payload carries a correlation value. The returned
    /// deployment ID is recorded in the execution attempt for webhook matching.
    ///
    /// # Parameters
    ///
    /// * `request_id` — The action request to dispatch.
    /// * `mandate_id_hex` — The mandate to reserve.
    /// * `intent_id_hex` — The intent digest.
    /// * `executor_identity` — The executor identity.
    /// * `reservation_token_digest` — Digest of the reservation token.
    /// * `correlation_key` — Provider correlation key.
    /// * `expected_mandate_version` — Expected CAS version.
    /// * `dispatch_fn` — A closure that performs the actual provider dispatch.
    ///   It receives the correlation key and attempt digest, and returns
    ///   `Some(deployment_id)` if the provider accepted, `None` otherwise.
    #[allow(clippy::too_many_arguments)]
    pub async fn reserve_and_dispatch<F>(
        &self,
        request_id: &str,
        mandate_id_hex: &str,
        intent_id_hex: &str,
        executor_identity: &str,
        reservation_token_digest: &str,
        correlation_key: &str,
        expected_mandate_version: i64,
        dispatch_fn: F,
    ) -> Result<DispatchOutcome, DispatchError>
    where
        F: FnOnce(&str, [u8; 32]) -> Option<u64>,
    {
        // Step 1: Reserve the mandate.
        let reserve_result = self
            .reserve(
                request_id,
                mandate_id_hex,
                intent_id_hex,
                executor_identity,
                reservation_token_digest,
                correlation_key,
                expected_mandate_version,
            )
            .await?;

        match &reserve_result {
            DispatchOutcome::ReplayRejected(rejection) => {
                // Terminal mandates fail before the provider closure is
                // invoked. Preserve the structured rejection for MCP/UI.
                Ok(DispatchOutcome::ReplayRejected(rejection.clone()))
            }
            DispatchOutcome::ReservationFailed(failed) => {
                // Another caller won; return immediately.
                let failed_copy = failed.clone();
                Ok(DispatchOutcome::ReservationFailed(failed_copy))
            }
            DispatchOutcome::DispatchFailed { .. } => {
                // Reserve already quarantined the mandate.
                Ok(reserve_result)
            }
            DispatchOutcome::Dispatched(dispatched) => {
                // Step 2: Compute the attempt digest for provider correlation (E-04).
                let attempt_digest = compute_attempt_digest(
                    &dispatched.attempt_id_hex,
                    mandate_id_hex,
                    intent_id_hex,
                );

                // Step 3: Dispatch to the provider with the attempt digest.
                let deployment_id = dispatch_fn(&dispatched.correlation_key, attempt_digest);

                // Step 4: Complete the dispatch.
                let cas_version = expected_mandate_version + 1; // version was incremented by reserve CAS

                if let Some(deploy_id) = deployment_id {
                    // Provider accepted: consume the mandate.
                    self.complete_dispatch(
                        &dispatched.attempt_id_hex,
                        mandate_id_hex,
                        intent_id_hex,
                        true,
                        Some(deploy_id),
                        executor_identity,
                        cas_version,
                    )
                    .await?;

                    // Update the dispatched result to reflect provider acceptance.
                    let dispatched_owned = dispatched.clone();
                    Ok(DispatchOutcome::Dispatched(DispatchedExecution {
                        provider_accepted: true,
                        github_deployment_id: Some(deploy_id),
                        ..dispatched_owned
                    }))
                } else {
                    // Provider failed: quarantine the mandate.
                    self.complete_dispatch(
                        &dispatched.attempt_id_hex,
                        mandate_id_hex,
                        intent_id_hex,
                        false,
                        None,
                        executor_identity,
                        cas_version,
                    )
                    .await?;

                    Ok(DispatchOutcome::DispatchFailed {
                        mandate_id_hex: mandate_id_hex.to_string(),
                        attempt_id_hex: dispatched.attempt_id_hex.clone(),
                        error: "provider rejected or timeout".to_string(),
                    })
                }
            }
        }
    }
}
