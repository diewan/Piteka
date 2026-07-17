#![forbid(unsafe_code)]

pub mod identity;
pub mod session;

#[cfg(test)]
mod identity_tests;
#[cfg(test)]
mod session_tests;

pub use identity::{
    Capability, ConfiguredOrganization, Identity, IdentityError, Organization, OrganizationId, Role,
    UserId,
};
pub use session::{SessionClaims, SessionError, SessionId};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServiceStatus {
    Ready,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Health {
    pub status: ServiceStatus,
    pub observed_at_unix_seconds: u64,
}
