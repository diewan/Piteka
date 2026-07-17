#![forbid(unsafe_code)]

pub mod authz;
pub mod session;

#[cfg(test)]
mod authz_tests;
#[cfg(test)]
mod session_tests;

pub use authz::{ActionSensitivity, AuthorizationRequest, Denial, ReauthPolicy};
pub use session::{
    AuthError, AuthenticatedSession, SessionAuthority, SessionSigner, Signature, SignatureAlgorithm,
    SignedSession,
};

use piteka_domain::{Health, ServiceStatus};

pub trait Clock: Send + Sync {
    fn unix_seconds(&self) -> u64;
}

pub struct HealthQuery<C> {
    clock: C,
}

impl<C: Clock> HealthQuery<C> {
    pub const fn new(clock: C) -> Self {
        Self { clock }
    }

    pub fn execute(&self) -> Health {
        Health {
            status: ServiceStatus::Ready,
            observed_at_unix_seconds: self.clock.unix_seconds(),
        }
    }
}
