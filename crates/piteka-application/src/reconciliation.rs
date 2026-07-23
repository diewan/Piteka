//! Ambiguous outcome reconciliation (Master Plan §60 E-07).
//!
//! This module implements the reconciliation use case for mandates that entered
//! `Quarantined` state because the provider dispatch outcome was ambiguous
//! (e.g. network timeout after dispatch).
//!
//! # Flow
//!
//! 1. A mandate is in `Quarantined` state with an attempt in `OutcomeAmbiguous`
//!    state (set by the dispatch use case when the provider call failed or
//!    timed out).
//! 2. An operator or automated process calls `reconcile` with the mandate ID.
//! 3. The use case checks the provider (GitHub) for the deployment status.
//! 4. If a correlated deployment is found, the mandate transitions
//!    `Quarantined → Consumed` and the attempt transitions to
//!    `ReconciledAccepted`.
//! 5. If correlation is absent or the provider is unavailable, state remains
//!    quarantined. A separate explicit operator decision may permanently
//!    abandon the ambiguity with an Unknown receipt.
//!
//! # Invariants enforced
//!
//! - **No automatic release/retry.** Reconciliation is always explicit —
//!   triggered by an explicit application call.
//!   There is no automatic release of quarantined mandates.
//! - **GitHub v1 has no `Quarantined → Released` path.** For the
//!   `GitHubDeploymentIntentV1` profile, the only terminal transitions from
//!   `Quarantined` are `Consumed` (reconciliation found accepted action) and
//!   `Abandoned` (unresolved). The `Released` state is unreachable.
//! - **Absence is not non-occurrence.** Missing correlation never mutates live
//!   state. Explicit abandonment produces an `AbandonedAmbiguous` attempt and
//!   an `Unknown` receipt, making the mandate permanently non-executable.
//! - **No simulated success.** The reconciliation never invents success.
//!   If the provider cannot confirm acceptance, state remains quarantined.
//!
//! # Security
//!
//! Reconciliation requires the caller to present the mandate ID and an
//! expected version for CAS. This prevents race conditions where a
//! reconciliation runs while another process is dispatching or consuming
//! the mandate.

use async_trait::async_trait;
use piteka_storage::model::{ExecutionAttemptState, ReceiptOutcome};
use piteka_storage::ports::{
    AuditLog, ExecutionAttemptStore, MandateProjectionStore, ReceiptProjectionStore,
};
use piteka_storage::{CasOutcome, StorageError, StorageResult};

use crate::Clock;

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Errors returned by the reconciliation use case.
#[derive(Debug)]
pub enum ReconciliationError {
    /// A storage failure occurred.
    Storage(StorageError),
    /// The mandate was not found.
    MandateNotFound(String),
    /// The mandate is not in Quarantined state.
    NotQuarantined { current_state: String },
    /// The mandate is already in a terminal state.
    AlreadyTerminal { current_state: String },
    /// The CAS operation failed (concurrent modification).
    CasConflict { current_version: i64 },
    /// The provider could not confirm the deployment status.
    ProviderUnavailable(String),
    /// The executor identity does not match the allowed subject.
    UnauthorizedExecutor(String),
}

impl From<StorageError> for ReconciliationError {
    fn from(err: StorageError) -> Self {
        Self::Storage(err)
    }
}

impl core::fmt::Display for ReconciliationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Storage(err) => write!(f, "storage error: {err}"),
            Self::MandateNotFound(id) => write!(f, "mandate `{id}` not found"),
            Self::NotQuarantined { current_state } => {
                write!(
                    f,
                    "mandate is not quarantined, current state: `{current_state}`"
                )
            }
            Self::AlreadyTerminal { current_state } => {
                write!(f, "mandate is already in terminal state: `{current_state}`")
            }
            Self::CasConflict { current_version } => {
                write!(
                    f,
                    "CAS conflict: another caller modified the mandate, current version {current_version}"
                )
            }
            Self::ProviderUnavailable(msg) => {
                write!(f, "provider unavailable: {msg}")
            }
            Self::UnauthorizedExecutor(executor) => {
                write!(f, "executor `{executor}` is not authorized")
            }
        }
    }
}

impl std::error::Error for ReconciliationError {
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

/// The outcome of a reconciliation attempt.
#[derive(Debug, Clone)]
pub enum ReconciliationOutcome {
    /// Reconciliation found a correlated deployment; mandate consumed.
    ReconciledAccepted {
        mandate_id_hex: String,
        attempt_id_hex: String,
        new_version: i64,
    },
    /// An operator permanently closed an unresolved ambiguity.
    AbandonedAmbiguous {
        mandate_id_hex: String,
        attempt_id_hex: String,
        new_version: i64,
    },
    /// Available provider information cannot establish acceptance; state is unchanged.
    Unresolved {
        mandate_id_hex: String,
        reason: String,
    },
}

impl ReconciliationOutcome {
    /// Returns `true` if the mandate was reconciled as accepted.
    #[must_use]
    pub const fn is_accepted(&self) -> bool {
        matches!(self, Self::ReconciledAccepted { .. })
    }

    /// Returns `true` if the mandate was abandoned as ambiguous.
    #[must_use]
    pub const fn is_abandoned(&self) -> bool {
        matches!(self, Self::AbandonedAmbiguous { .. })
    }

    /// Returns `true` if the provider was unavailable.
    #[must_use]
    pub const fn is_unavailable(&self) -> bool {
        matches!(self, Self::Unresolved { .. })
    }
}

// ---------------------------------------------------------------------------
// Port trait
// ---------------------------------------------------------------------------

/// A provider deployment whose immutable correlation payload matches the
/// quarantined execution attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CorrelatedDeployment {
    /// GitHub's stable deployment identifier.
    pub deployment_id: u64,
}

/// Provider port for finding a deployment during reconciliation.
///
/// Implementations of this trait check the external provider (GitHub) to
/// determine whether a deployment was accepted for a given deployment ID.
#[async_trait]
pub trait DeploymentStatusProvider: Send + Sync {
    /// Finds a deployment whose provider-retained correlation payload matches
    /// this exact attempt.
    ///
    /// # Parameters
    ///
    /// * `attempt` — The quarantined attempt, including its correlation key
    ///   and exact intent/mandate binding.
    ///
    /// # Returns
    ///
    /// - `Ok(Some(_))` if a correlated deployment was accepted by GitHub.
    /// - `Ok(None)` if current provider data cannot establish acceptance.
    ///   This is unresolved, never proof of non-occurrence.
    /// - `Err` if the provider is unavailable or the check failed.
    ///
    /// Implementations MUST match the opaque correlation payload and exact
    /// intent binding. A deployment ID recorded on the attempt is a useful
    /// lookup key, but cannot be required: a timeout-after-request can occur
    /// after GitHub accepts the request and before Piteka receives that ID.
    async fn find_correlated_deployment(
        &self,
        attempt: &piteka_storage::model::ExecutionAttempt,
    ) -> StorageResult<Option<CorrelatedDeployment>>;
}

/// Ports required by the reconciliation use case.
pub trait ReconciliationPorts: Send + Sync {
    /// Mandate projection store for CAS on mandate state.
    fn mandate_store(&self) -> &dyn MandateProjectionStore;

    /// Execution attempt store for updating attempt state.
    fn attempt_store(&self) -> &dyn ExecutionAttemptStore;

    /// Receipt projection store for recording reconciliation receipts.
    fn receipt_store(&self) -> &dyn ReceiptProjectionStore;

    /// Audit log for recording reconciliation events.
    fn audit_log(&self) -> &dyn AuditLog;

    /// Clock for timestamps.
    fn clock(&self) -> &dyn Clock;

    /// Provider for checking deployment status.
    fn deployment_provider(&self) -> &dyn DeploymentStatusProvider;
}

// ---------------------------------------------------------------------------
// Use case
// ---------------------------------------------------------------------------

/// Orchestrates ambiguous outcome reconciliation.
///
/// This is the E-07 use case. It handles mandates that entered `Quarantined`
/// state because the provider dispatch outcome was ambiguous.
///
/// # Reconciliation flow
///
/// ```text
/// ┌──────────────┐
/// │  Quarantined │
/// └──────┬───────┘
///        │
///        ▼
///  ┌─────────────┐
///  │ Check provider
///  │ deployment   │
///  └──────┬──────┘
///         │
///    ┌────┴────┐
///    │         │
///    ▼         ▼
/// accepted   unresolved
///    │         │
///    ▼         ▼
/// ┌────────┐ ┌──────────┐
/// │Consumed│ │Quarantined│
/// └────────┘ └───────────┘
/// ```
///
/// # GitHub v1 constraint
///
/// For `GitHubDeploymentIntentV1`, the `Quarantined → Released` transition
/// is **unreachable**. The only terminal paths from `Quarantined` are:
/// - `Quarantined → Consumed` (reconciliation found accepted action)
/// - `Quarantined → Abandoned` (unresolved, permanently non-executable)
#[derive(Clone)]
pub struct ReconciliationUseCase<P>
where
    P: ReconciliationPorts,
{
    tenant: piteka_storage::TenantScope,
    ports: P,
}

impl<P: ReconciliationPorts> ReconciliationUseCase<P> {
    /// Creates a new reconciliation use-case orchestrator.
    #[must_use]
    pub fn new(tenant: piteka_storage::TenantScope, ports: P) -> Self {
        Self { tenant, ports }
    }

    /// Reconciles a quarantined mandate by checking the provider for the
    /// deployment status.
    ///
    /// # Parameters
    ///
    /// * `mandate_id_hex` — The mandate to reconcile.
    /// * `executor_identity` — The identity performing the reconciliation.
    /// * `expected_mandate_version` — The expected version for CAS.
    ///
    /// # Behavior
    ///
    /// 1. Fetches the mandate projection and verifies it is in `Quarantined`
    ///    state.
    /// 2. Finds the execution attempt for this mandate and verifies it is
    ///    in `OutcomeAmbiguous` state.
    /// 3. Checks the provider for the deployment status using the
    ///    `github_deployment_id` from the attempt.
    /// 4. If the provider confirms acceptance:
    ///    - Transitions mandate `Quarantined → Consumed`
    ///    - Transitions attempt `OutcomeAmbiguous → ReconciledAccepted`
    /// 5. If current provider information does not establish acceptance,
    ///    leaves mandate and attempt state unchanged.
    ///
    /// # Invariants
    ///
    /// - **No automatic release.** This method must be called explicitly.
    ///   There is no background process that automatically releases
    ///   quarantined mandates.
    /// - **No `Quarantined → Released` for GitHub v1.** The `Released`
    ///   state is never used for this profile.
    /// - **No simulated success.** Provider absence leaves the case unresolved.
    pub async fn reconcile(
        &self,
        mandate_id_hex: &str,
        executor_identity: &str,
        expected_mandate_version: i64,
    ) -> Result<ReconciliationOutcome, ReconciliationError> {
        if executor_identity.trim().is_empty() {
            return Err(ReconciliationError::UnauthorizedExecutor(
                executor_identity.to_string(),
            ));
        }
        let now = self.ports.clock().unix_seconds() as i64;

        // 1. Fetch the mandate projection.
        let mandate = self
            .ports
            .mandate_store()
            .get(&self.tenant, mandate_id_hex)
            .await?
            .ok_or_else(|| ReconciliationError::MandateNotFound(mandate_id_hex.to_string()))?;

        // 2. Verify the mandate is in Quarantined state.
        if mandate.state != "quarantined" {
            if is_terminal_state(&mandate.state) {
                return Err(ReconciliationError::AlreadyTerminal {
                    current_state: mandate.state.clone(),
                });
            }
            return Err(ReconciliationError::NotQuarantined {
                current_state: mandate.state.clone(),
            });
        }

        // 3. Find the execution attempt for this mandate.
        let attempts = self
            .ports
            .attempt_store()
            .by_mandate(&self.tenant, mandate_id_hex)
            .await?;

        let attempt = attempts
            .into_iter()
            .find(|a| a.state == ExecutionAttemptState::OutcomeAmbiguous)
            .ok_or_else(|| ReconciliationError::NotQuarantined {
                current_state: "no ambiguous attempt found".to_string(),
            })?;

        let attempt_id_hex = &attempt.attempt_id_hex;

        // 4. Query by the provider-retained correlation payload. This also
        // covers timeout-after-request, where GitHub may have accepted the
        // deployment but its response (and therefore deployment ID) was lost.
        let correlated = match self
            .ports
            .deployment_provider()
            .find_correlated_deployment(&attempt)
            .await
        {
            Ok(Some(deployment)) => deployment,
            Ok(None) => {
                return Ok(ReconciliationOutcome::Unresolved {
                    mandate_id_hex: mandate_id_hex.to_string(),
                    reason: "provider data did not establish correlated acceptance; absence does not prove non-occurrence".to_string(),
                });
            }
            Err(error) => {
                return Ok(ReconciliationOutcome::Unresolved {
                    mandate_id_hex: mandate_id_hex.to_string(),
                    reason: format!("provider unavailable: {error}"),
                });
            }
        };

        // 5. Apply the reconciliation outcome.
        {
            // ReconciledAccepted: mandate → Consumed, attempt → ReconciledAccepted
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
                CasOutcome::Applied { new_version } => {
                    // Persist the ID recovered from the provider before marking
                    // the attempt reconciled, so webhook correlation is durable.
                    if attempt.github_deployment_id != Some(correlated.deployment_id) {
                        self.ports
                            .attempt_store()
                            .update_deployment_id(
                                &self.tenant,
                                attempt_id_hex,
                                correlated.deployment_id,
                            )
                            .await?;
                    }
                    self.ports
                        .attempt_store()
                        .update_state(
                            &self.tenant,
                            attempt_id_hex,
                            ExecutionAttemptState::ReconciledAccepted,
                        )
                        .await?;

                    // Audit.
                    self.ports
                        .audit_log()
                        .append(&self.tenant, piteka_storage::model::AuditEvent {
                            occurred_at_unix_seconds: now,
                            actor: Some(executor_identity.to_string()),
                            action: "reconciliation.accepted".to_string(),
                            decision: "granted".to_string(),
                            detail: format!(
                                "mandate {} reconciled as accepted, attempt {}, deployment_id={}",
                                mandate_id_hex, attempt_id_hex, correlated.deployment_id
                            ),
                        })
                        .await?;

                    Ok(ReconciliationOutcome::ReconciledAccepted {
                        mandate_id_hex: mandate_id_hex.to_string(),
                        attempt_id_hex: attempt_id_hex.clone(),
                        new_version,
                    })
                }
                CasOutcome::Conflict { current_version } => {
                    Err(ReconciliationError::CasConflict { current_version })
                }
                CasOutcome::Missing => Err(ReconciliationError::MandateNotFound(
                    mandate_id_hex.to_string(),
                )),
            }
        }
    }

    /// Permanently abandons an ambiguity that an operator has decided cannot
    /// be resolved. Provider absence alone never calls this operation.
    pub async fn abandon_unresolved(
        &self,
        mandate_id_hex: &str,
        executor_identity: &str,
        expected_mandate_version: i64,
        reason: &str,
    ) -> Result<ReconciliationOutcome, ReconciliationError> {
        if executor_identity.trim().is_empty() {
            return Err(ReconciliationError::UnauthorizedExecutor(
                executor_identity.to_string(),
            ));
        }
        if reason.trim().is_empty() {
            return Err(ReconciliationError::ProviderUnavailable(
                "an explicit abandonment reason is required".to_string(),
            ));
        }
        let now = self.ports.clock().unix_seconds() as i64;
        let mandate = self
            .ports
            .mandate_store()
            .get(&self.tenant, mandate_id_hex)
            .await?
            .ok_or_else(|| ReconciliationError::MandateNotFound(mandate_id_hex.to_string()))?;
        if mandate.state != "quarantined" {
            return Err(ReconciliationError::NotQuarantined {
                current_state: mandate.state,
            });
        }
        let attempt = self
            .ports
            .attempt_store()
            .by_mandate(&self.tenant, mandate_id_hex)
            .await?
            .into_iter()
            .find(|attempt| attempt.state == ExecutionAttemptState::OutcomeAmbiguous)
            .ok_or_else(|| ReconciliationError::NotQuarantined {
                current_state: "no ambiguous attempt found".to_string(),
            })?;
        let attempt_id_hex = attempt.attempt_id_hex;
        let intent_id_hex = attempt.intent_id_hex;

        let cas_result = self
            .ports
            .mandate_store()
            .compare_and_swap(
                &self.tenant,
                mandate_id_hex,
                expected_mandate_version,
                "abandoned",
            )
            .await?;

        match cas_result {
            CasOutcome::Applied { new_version } => {
                self.ports
                    .attempt_store()
                    .update_state(
                        &self.tenant,
                        &attempt_id_hex,
                        ExecutionAttemptState::AbandonedAmbiguous,
                    )
                    .await?;

                // Record receipt with Unknown outcome.
                let receipt_id_hex = format!("rcpt-abandoned-{}", attempt_id_hex);
                self.ports
                    .receipt_store()
                    .insert(
                        &self.tenant,
                        piteka_storage::model::ReceiptProjection {
                            receipt_id_hex,
                            mandate_id_hex: mandate_id_hex.to_string(),
                            intent_id_hex: intent_id_hex.clone(),
                            attempt_id_hex: attempt_id_hex.clone(),
                            outcome: ReceiptOutcome::Unknown,
                            created_at_unix_seconds: now,
                            dispatch_evidence_refs: vec![],
                            target_evidence_refs: vec![],
                            evidence_gaps: vec!["target_outcome".to_string()],
                            canonical_bytes: None,
                        },
                    )
                    .await?;

                // Audit.
                self.ports
                    .audit_log()
                    .append(
                        &self.tenant,
                        piteka_storage::model::AuditEvent {
                            occurred_at_unix_seconds: now,
                            actor: Some(executor_identity.to_string()),
                            action: "reconciliation.abandoned".to_string(),
                            decision: "abandoned".to_string(),
                            detail: format!(
                                "mandate {} abandoned (ambiguous), attempt {}, reason={}",
                                mandate_id_hex, attempt_id_hex, reason
                            ),
                        },
                    )
                    .await?;

                Ok(ReconciliationOutcome::AbandonedAmbiguous {
                    mandate_id_hex: mandate_id_hex.to_string(),
                    attempt_id_hex: attempt_id_hex.clone(),
                    new_version,
                })
            }
            CasOutcome::Conflict { current_version } => {
                Err(ReconciliationError::CasConflict { current_version })
            }
            CasOutcome::Missing => Err(ReconciliationError::MandateNotFound(
                mandate_id_hex.to_string(),
            )),
        }
    }
}

/// Returns `true` if the given state is a terminal mandate state.
fn is_terminal_state(state: &str) -> bool {
    matches!(
        state,
        "consumed" | "expired" | "revoked" | "abandoned" | "released"
    )
}
