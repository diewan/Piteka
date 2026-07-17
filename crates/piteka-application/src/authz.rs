//! Pure authorization policy for the demo slice.
//!
//! Given an authenticated session and a requested action, [`ReauthPolicy`]
//! decides grant or denial with no side effects. The auditing boundary that
//! records denials lives in `piteka-auth`; keeping the decision pure makes every
//! rule directly testable.

use piteka_domain::Capability;

use crate::session::AuthenticatedSession;

/// How sensitive an action is for re-confirmation purposes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActionSensitivity {
    /// A normal action; role enforcement is sufficient.
    Standard,
    /// A production approval; requires a recent re-authentication.
    ProductionApproval,
}

/// A capability request tagged with its sensitivity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthorizationRequest {
    /// The capability the action requires.
    pub capability: Capability,
    /// The action's sensitivity.
    pub sensitivity: ActionSensitivity,
}

impl AuthorizationRequest {
    /// A standard action requiring `capability`.
    #[must_use]
    pub const fn standard(capability: Capability) -> Self {
        Self {
            capability,
            sensitivity: ActionSensitivity::Standard,
        }
    }

    /// A production approval requiring `capability` and a recent re-auth.
    #[must_use]
    pub const fn production_approval(capability: Capability) -> Self {
        Self {
            capability,
            sensitivity: ActionSensitivity::ProductionApproval,
        }
    }
}

/// Why an authorization was denied.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Denial {
    /// The authenticated role does not grant the required capability.
    Unauthorized(Capability),
    /// A production approval needs a fresher re-authentication than the session.
    ReconfirmationRequired {
        /// The maximum accepted session age, seconds.
        max_age_seconds: u64,
        /// The session's actual age at decision time, seconds.
        session_age_seconds: u64,
    },
}

impl core::fmt::Display for Denial {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Unauthorized(capability) => {
                write!(f, "role does not grant capability {capability:?}")
            }
            Self::ReconfirmationRequired {
                max_age_seconds,
                session_age_seconds,
            } => write!(
                f,
                "production approval requires re-authentication within {max_age_seconds}s \
                 (session age {session_age_seconds}s)"
            ),
        }
    }
}

/// Requires production approvals to ride a session re-authenticated recently.
#[derive(Clone, Copy, Debug)]
pub struct ReauthPolicy {
    /// Maximum session age, in seconds, accepted for a production approval.
    pub reauth_window_seconds: u64,
}

impl ReauthPolicy {
    /// Builds a policy with the given re-authentication window.
    #[must_use]
    pub const fn new(reauth_window_seconds: u64) -> Self {
        Self {
            reauth_window_seconds,
        }
    }

    /// Evaluates a request against a session at time `now`.
    ///
    /// # Errors
    ///
    /// Returns [`Denial::Unauthorized`] when the role lacks the capability, or
    /// [`Denial::ReconfirmationRequired`] when a production approval rides a
    /// session older than the re-authentication window.
    pub fn evaluate(
        &self,
        session: &AuthenticatedSession,
        request: &AuthorizationRequest,
        now_unix_seconds: u64,
    ) -> Result<(), Denial> {
        if !session.can(request.capability) {
            return Err(Denial::Unauthorized(request.capability));
        }
        if request.sensitivity == ActionSensitivity::ProductionApproval {
            let issued = session.claims().issued_at_unix_seconds();
            let age = now_unix_seconds.saturating_sub(issued);
            if age > self.reauth_window_seconds {
                return Err(Denial::ReconfirmationRequired {
                    max_age_seconds: self.reauth_window_seconds,
                    session_age_seconds: age,
                });
            }
        }
        Ok(())
    }
}
