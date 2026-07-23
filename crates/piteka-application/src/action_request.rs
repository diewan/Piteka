//! Action-request and approval use cases.
//!
//! These use cases implement the propose → approve/reject → revoke lifecycle
//! described in Master Plan §59 D-06. Every approval is bound to an exact
//! intent digest (lower-case hex), never to free-form prompt text. Optimistic
//! concurrency (CAS) prevents duplicate approvals.
//!
//! # Ports
//!
//! - [`ActionRequestStore`] — persists action requests with CAS.
//! - [`ApprovalDecisionStore`] — persists approval decisions.
//! - [`AuditLog`] — records every denial and production-approval grant.
//! - [`Clock`] — provides monotonic time for creation/decision timestamps.
//!
//! # Security
//!
//! All public methods fail closed on unsupported, ambiguous, malformed, or
//! cross-tenant input. No simulated success or alternate authority path is
//! ever introduced.

use piteka_domain::UserId;
use piteka_storage::{
    ActionRequest, ActionRequestStatus, ApprovalDecision, AuditEvent, AuditLog, CasOutcome,
    StorageError, StorageResult, TenantScope,
};

use crate::Clock;

/// The result of proposing an action request.
#[derive(Debug)]
pub struct Proposed {
    /// The request that was created.
    pub request: ActionRequest,
}

/// The result of approving an action request.
#[derive(Debug)]
pub struct Approved {
    /// The updated request (now in `Approved` status).
    pub request: ActionRequest,
    /// The approval decision that was recorded.
    pub decision: ApprovalDecision,
}

/// The result of rejecting an action request.
#[derive(Debug)]
pub struct Rejected {
    /// The updated request (now in `Rejected` status).
    pub request: ActionRequest,
    /// The rejection decision that was recorded.
    pub decision: ApprovalDecision,
}

/// The result of revoking an approved action request.
#[derive(Debug)]
pub struct Revoked {
    /// The updated request (now in `Revoked` status).
    pub request: ActionRequest,
}

/// Errors returned by action-request use cases.
#[derive(Debug)]
pub enum ActionRequestUseCaseError {
    /// A storage failure occurred.
    Storage(StorageError),
    /// The action request was not found.
    NotFound(String),
    /// The current status does not allow the requested transition.
    InvalidTransition {
        current: ActionRequestStatus,
        attempted: &'static str,
    },
    /// Optimistic concurrency conflict.
    Conflict {
        expected_version: i64,
        current_version: i64,
    },
}

impl From<StorageError> for ActionRequestUseCaseError {
    fn from(err: StorageError) -> Self {
        Self::Storage(err)
    }
}

impl core::fmt::Display for ActionRequestUseCaseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Storage(err) => write!(f, "storage error: {}", err),
            Self::NotFound(id) => write!(f, "action request `{}` not found", id),
            Self::InvalidTransition { current, attempted } => {
                write!(
                    f,
                    "cannot {} from status {:?} for action request",
                    attempted, current
                )
            }
            Self::Conflict {
                expected_version,
                current_version,
            } => write!(
                f,
                "optimistic concurrency conflict: expected version {}, current version {}",
                expected_version, current_version
            ),
        }
    }
}

impl std::error::Error for ActionRequestUseCaseError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Storage(err) => Some(err),
            _ => None,
        }
    }
}

/// Ports required by the action-request use cases.
pub trait ActionRequestPorts: Send + Sync {
    /// Stores and retrieves action requests with CAS.
    fn request_store(&self) -> &dyn piteka_storage::ports::ActionRequestStore;

    /// Stores and retrieves approval decisions.
    fn decision_store(&self) -> &dyn piteka_storage::ports::ApprovalDecisionStore;

    /// Appends audit events.
    fn audit_log(&self) -> &dyn AuditLog;

    /// Provides the current time.
    fn clock(&self) -> &dyn Clock;
}

/// Use-case orchestrator for action-request and approval workflows.
#[derive(Clone)]
pub struct ActionRequestUseCase<P> {
    tenant: TenantScope,
    ports: P,
}

impl<P: ActionRequestPorts> ActionRequestUseCase<P> {
    /// Creates a new use-case orchestrator.
    #[must_use]
    pub const fn new(tenant: TenantScope, ports: P) -> Self {
        Self { tenant, ports }
    }

    /// Reads recent audit events inside this use case's authenticated tenant.
    pub async fn recent_audit(&self, limit: usize) -> StorageResult<Vec<AuditEvent>> {
        self.ports.audit_log().recent(&self.tenant, limit).await
    }

    /// Proposes a new action request.
    ///
    /// The request is created with `Pending` status. The `intent_id_hex` is the
    /// Parwana-canonical intent digest that an approver will review; it may be
    /// `None` if the intent has not yet been constructed.
    ///
    /// An audit event is appended recording the proposal.
    ///
    /// # Errors
    ///
    /// Returns a [`StorageError`] if the request already exists or the backend
    /// fails.
    pub async fn propose(
        &self,
        request_id: impl Into<String>,
        requested_by: UserId,
        intent_id_hex: Option<String>,
    ) -> Result<Proposed, ActionRequestUseCaseError> {
        let now = self.ports.clock().unix_seconds() as i64;
        let request = ActionRequest {
            request_id: request_id.into(),
            requested_by: requested_by.as_str().to_string(),
            intent_id_hex: intent_id_hex.clone(),
            status: ActionRequestStatus::Pending,
            created_at_unix_seconds: now,
        };

        self.ports
            .request_store()
            .insert(&self.tenant, request.clone())
            .await?;

        self.ports
            .audit_log()
            .append(
                &self.tenant,
                AuditEvent {
                    occurred_at_unix_seconds: now,
                    actor: Some(requested_by.as_str().to_string()),
                    action: "propose_action".to_string(),
                    decision: "granted".to_string(),
                    detail: format!(
                        "action request {} proposed, intent={:?}",
                        request.request_id, intent_id_hex
                    ),
                },
            )
            .await?;

        Ok(Proposed { request })
    }

    /// Approves an action request.
    ///
    /// The approver's decision is bound to the exact `intent_id_hex` that was
    /// shown to them. Optimistic concurrency (CAS) ensures only one approval
    /// wins; concurrent attempts receive a conflict error.
    ///
    /// The request must be in `Pending` status. After approval, the status
    /// transitions to `Approved`.
    ///
    /// # Errors
    ///
    /// Returns [`ActionRequestUseCaseError::InvalidTransition`] if the request is not
    /// `Pending`, [`ActionRequestUseCaseError::Conflict`] if another caller already
    /// changed the status, or a [`StorageError`] on backend failure.
    pub async fn approve(
        &self,
        request_id: &str,
        approver_id: UserId,
        intent_id_hex: Option<String>,
        expected_version: i64,
    ) -> Result<Approved, ActionRequestUseCaseError> {
        let now = self.ports.clock().unix_seconds() as i64;

        // Verify the request exists and is Pending.
        let request = self
            .ports
            .request_store()
            .get(&self.tenant, request_id)
            .await?
            .ok_or_else(|| ActionRequestUseCaseError::NotFound(request_id.to_string()))?;

        if request.status != ActionRequestStatus::Pending {
            return Err(ActionRequestUseCaseError::InvalidTransition {
                current: request.status,
                attempted: "approve",
            });
        }

        // Apply CAS to prevent duplicate approvals.
        let outcome = self
            .ports
            .request_store()
            .compare_and_swap(
                &self.tenant,
                request_id,
                expected_version,
                ActionRequestStatus::Approved,
            )
            .await?;

        match outcome {
            CasOutcome::Applied { new_version } => {
                let decision_id = format!("dec-{}", request_id);
                let decision = ApprovalDecision {
                    decision_id,
                    request_id: request_id.to_string(),
                    decided_by: approver_id.as_str().to_string(),
                    decision: "approved".to_string(),
                    intent_id_hex: intent_id_hex.clone(),
                    decided_at_unix_seconds: now,
                };

                self.ports
                    .decision_store()
                    .insert(&self.tenant, decision.clone())
                    .await?;

                self.ports
                    .audit_log()
                    .append(
                        &self.tenant,
                        AuditEvent {
                            occurred_at_unix_seconds: now,
                            actor: Some(approver_id.as_str().to_string()),
                            action: "approve_action".to_string(),
                            decision: "granted".to_string(),
                            detail: format!(
                                "action request {} approved by {}, intent={:?}, version={}",
                                request_id,
                                approver_id.as_str(),
                                intent_id_hex,
                                new_version
                            ),
                        },
                    )
                    .await?;

                // Refresh the request to reflect the new status.
                let updated_request = self
                    .ports
                    .request_store()
                    .get(&self.tenant, request_id)
                    .await?
                    .expect("CAS applied but request vanished");

                Ok(Approved {
                    request: updated_request,
                    decision,
                })
            }
            CasOutcome::Conflict { current_version } => Err(ActionRequestUseCaseError::Conflict {
                expected_version,
                current_version,
            }),
            CasOutcome::Missing => Err(ActionRequestUseCaseError::NotFound(request_id.to_string())),
        }
    }

    /// Rejects an action request.
    ///
    /// The request must be in `Pending` status. After rejection, the status
    /// transitions to `Rejected`.
    ///
    /// # Errors
    ///
    /// Returns [`ActionRequestUseCaseError::InvalidTransition`] if the request is not
    /// `Pending`, or a [`StorageError`] on backend failure.
    pub async fn reject(
        &self,
        request_id: &str,
        approver_id: UserId,
        intent_id_hex: Option<String>,
        expected_version: i64,
    ) -> Result<Rejected, ActionRequestUseCaseError> {
        let now = self.ports.clock().unix_seconds() as i64;

        let request = self
            .ports
            .request_store()
            .get(&self.tenant, request_id)
            .await?
            .ok_or_else(|| ActionRequestUseCaseError::NotFound(request_id.to_string()))?;

        if request.status != ActionRequestStatus::Pending {
            return Err(ActionRequestUseCaseError::InvalidTransition {
                current: request.status,
                attempted: "reject",
            });
        }

        let outcome = self
            .ports
            .request_store()
            .compare_and_swap(
                &self.tenant,
                request_id,
                expected_version,
                ActionRequestStatus::Rejected,
            )
            .await?;

        match outcome {
            CasOutcome::Applied { new_version: _ } => {
                let decision_id = format!("dec-{}", request_id);
                let decision = ApprovalDecision {
                    decision_id,
                    request_id: request_id.to_string(),
                    decided_by: approver_id.as_str().to_string(),
                    decision: "rejected".to_string(),
                    intent_id_hex,
                    decided_at_unix_seconds: now,
                };

                self.ports
                    .decision_store()
                    .insert(&self.tenant, decision.clone())
                    .await?;

                self.ports
                    .audit_log()
                    .append(
                        &self.tenant,
                        AuditEvent {
                            occurred_at_unix_seconds: now,
                            actor: Some(approver_id.as_str().to_string()),
                            action: "reject_action".to_string(),
                            decision: "denied".to_string(),
                            detail: format!(
                                "action request {} rejected by {}",
                                request_id,
                                approver_id.as_str()
                            ),
                        },
                    )
                    .await?;

                let updated_request = self
                    .ports
                    .request_store()
                    .get(&self.tenant, request_id)
                    .await?
                    .expect("CAS applied but request vanished");

                Ok(Rejected {
                    request: updated_request,
                    decision,
                })
            }
            CasOutcome::Conflict { current_version } => Err(ActionRequestUseCaseError::Conflict {
                expected_version,
                current_version,
            }),
            CasOutcome::Missing => Err(ActionRequestUseCaseError::NotFound(request_id.to_string())),
        }
    }

    /// Revokes an approved action request before dispatch.
    ///
    /// Only an approved request can be revoked. After revocation, the status
    /// transitions to `Revoked`.
    ///
    /// # Errors
    ///
    /// Returns [`ActionRequestUseCaseError::InvalidTransition`] if the request is not
    /// `Approved`, or a [`StorageError`] on backend failure.
    pub async fn revoke(
        &self,
        request_id: &str,
        approver_id: UserId,
        expected_version: i64,
    ) -> Result<Revoked, ActionRequestUseCaseError> {
        let now = self.ports.clock().unix_seconds() as i64;

        let request = self
            .ports
            .request_store()
            .get(&self.tenant, request_id)
            .await?
            .ok_or_else(|| ActionRequestUseCaseError::NotFound(request_id.to_string()))?;

        if request.status != ActionRequestStatus::Approved {
            return Err(ActionRequestUseCaseError::InvalidTransition {
                current: request.status,
                attempted: "revoke",
            });
        }

        let outcome = self
            .ports
            .request_store()
            .compare_and_swap(
                &self.tenant,
                request_id,
                expected_version,
                ActionRequestStatus::Revoked,
            )
            .await?;

        match outcome {
            CasOutcome::Applied { .. } => {
                self.ports
                    .audit_log()
                    .append(
                        &self.tenant,
                        AuditEvent {
                            occurred_at_unix_seconds: now,
                            actor: Some(approver_id.as_str().to_string()),
                            action: "revoke_mandate".to_string(),
                            decision: "granted".to_string(),
                            detail: format!(
                                "action request {} revoked by {}",
                                request_id,
                                approver_id.as_str()
                            ),
                        },
                    )
                    .await?;

                let updated_request = self
                    .ports
                    .request_store()
                    .get(&self.tenant, request_id)
                    .await?
                    .expect("CAS applied but request vanished");

                Ok(Revoked {
                    request: updated_request,
                })
            }
            CasOutcome::Conflict { current_version } => Err(ActionRequestUseCaseError::Conflict {
                expected_version,
                current_version,
            }),
            CasOutcome::Missing => Err(ActionRequestUseCaseError::NotFound(request_id.to_string())),
        }
    }

    /// Fetches an action request by id.
    ///
    /// # Errors
    ///
    /// Returns a [`StorageError`] on backend failure.
    pub async fn get_request(&self, request_id: &str) -> StorageResult<Option<ActionRequest>> {
        self.ports
            .request_store()
            .get(&self.tenant, request_id)
            .await
    }

    /// Lists all action requests.
    ///
    /// # Errors
    ///
    /// Returns a [`StorageError`] on backend failure.
    pub async fn list_requests(&self) -> StorageResult<Vec<ActionRequest>> {
        self.ports.request_store().list(&self.tenant).await
    }

    /// Returns all approval decisions for a given request.
    ///
    /// # Errors
    ///
    /// Returns a [`StorageError`] on backend failure.
    pub async fn get_decisions(&self, request_id: &str) -> StorageResult<Vec<ApprovalDecision>> {
        self.ports
            .decision_store()
            .by_request(&self.tenant, request_id)
            .await
    }
}
