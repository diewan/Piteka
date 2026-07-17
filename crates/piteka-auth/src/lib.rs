#![forbid(unsafe_code)]

//! Demo authorization boundary (Master Plan §59 D-04).
//!
//! [`DemoAuthorizationBoundary`] enforces role capabilities over an authenticated
//! session, requires a recent re-authentication before a production approval, and
//! records **every denial** (and every production-approval grant) as an
//! append-only audit event. Each decision carries a clear non-production identity
//! warning: the demo authenticates with local `DemoLocalV1` sessions, not OIDC or
//! SSO (see `piteka/docs/adr/ADR-0001-demo-identity-and-sessions.md`). OIDC and
//! full RBAC/ABAC precede any pilot.

use piteka_application::{
    AuthenticatedSession, AuthorizationRequest, Clock, Denial, ReauthPolicy,
};
use piteka_storage::{AuditEvent, AuditLog, StorageError};

/// Clear warning that the demo identity layer is not production-grade.
pub const NON_PRODUCTION_IDENTITY_WARNING: &str = "Non-production identity: demo sessions are \
signed with the local DemoLocalV1 signer and are not backed by OIDC/SSO or a KMS. Do not use for \
real production authorization. See ADR-0001.";

/// A granted authorization. Holds the non-production identity warning so callers
/// always surface it alongside an authorized production action.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Grant {
    request: AuthorizationRequest,
}

impl Grant {
    /// The request that was granted.
    #[must_use]
    pub fn request(&self) -> AuthorizationRequest {
        self.request
    }

    /// The non-production identity warning to display to the operator.
    #[must_use]
    pub fn identity_warning(&self) -> &'static str {
        NON_PRODUCTION_IDENTITY_WARNING
    }
}

/// A denied authorization. The denial has already been written to the audit log.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Denied {
    denial: Denial,
}

impl Denied {
    /// The reason for denial.
    #[must_use]
    pub fn denial(&self) -> Denial {
        self.denial
    }

    /// The non-production identity warning to display to the operator.
    #[must_use]
    pub fn identity_warning(&self) -> &'static str {
        NON_PRODUCTION_IDENTITY_WARNING
    }
}

/// The result of an authorization attempt.
pub type AuthorizationOutcome = Result<Grant, Denied>;

/// Enforces the demo authorization policy and records denials.
pub struct DemoAuthorizationBoundary<L, C> {
    audit: L,
    clock: C,
    policy: ReauthPolicy,
}

impl<L: AuditLog, C: Clock> DemoAuthorizationBoundary<L, C> {
    /// Builds a boundary over an audit log, clock, and re-auth policy.
    pub const fn new(audit: L, clock: C, policy: ReauthPolicy) -> Self {
        Self {
            audit,
            clock,
            policy,
        }
    }

    /// Borrows the audit log, for inspection of recorded decisions.
    pub const fn audit(&self) -> &L {
        &self.audit
    }

    /// Authorizes `request` for `session`, describing the action for the audit
    /// trail with `action_detail` (for example the target intent id).
    ///
    /// Denials — and grants of production approvals — are appended to the audit
    /// log before returning.
    ///
    /// # Errors
    ///
    /// Returns a [`StorageError`] only if writing the audit event fails; a
    /// denied-but-recorded decision is an `Ok(Err(Denied))`, never an error.
    pub async fn authorize(
        &self,
        session: &AuthenticatedSession,
        request: &AuthorizationRequest,
        action_detail: &str,
    ) -> Result<AuthorizationOutcome, StorageError> {
        let now = self.clock.unix_seconds();
        let actor = session.identity().user_id().as_str().to_string();

        match self.policy.evaluate(session, request, now) {
            Ok(()) => {
                if request.sensitivity == piteka_application::ActionSensitivity::ProductionApproval {
                    self.audit
                        .append(event(now, &actor, action_detail, "granted", "production approval"))
                        .await?;
                }
                Ok(Ok(Grant { request: *request }))
            }
            Err(denial) => {
                self.audit
                    .append(event(now, &actor, action_detail, "denied", &denial.to_string()))
                    .await?;
                Ok(Err(Denied { denial }))
            }
        }
    }
}

fn event(now_unix_seconds: u64, actor: &str, action: &str, decision: &str, detail: &str) -> AuditEvent {
    AuditEvent {
        occurred_at_unix_seconds: i64::try_from(now_unix_seconds).unwrap_or(i64::MAX),
        actor: Some(actor.to_string()),
        action: action.to_string(),
        decision: decision.to_string(),
        detail: detail.to_string(),
    }
}

#[cfg(test)]
mod tests;
