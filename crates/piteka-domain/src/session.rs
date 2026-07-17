//! Local session claims for the demo authorization slice.
//!
//! A [`SessionClaims`] value binds a subject identity, its organization, and its
//! role to a bounded validity window. The application layer signs the claims'
//! [`SessionClaims::signing_bytes`] with a [`crate`]-external signer port.
//!
//! These bytes are a **Piteka-local** session encoding. They are not a Parwana
//! accountability object and are never fed to the protocol's canonical
//! serializer or verifier; there is no second protocol serializer here.

use crate::identity::{OrganizationId, Role, UserId};

/// Domain tag separating demo session bytes from every other signed message.
const SESSION_DOMAIN_TAG: &[u8] = b"piteka-demo-session-v1";

/// A validation failure while constructing session claims.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SessionError {
    /// A required identifier was empty.
    EmptyField(&'static str),
    /// The validity window did not end strictly after it began.
    NonPositiveLifetime {
        /// Issue time, Unix seconds.
        issued_at_unix_seconds: u64,
        /// Expiry time, Unix seconds.
        expires_at_unix_seconds: u64,
    },
}

impl core::fmt::Display for SessionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::EmptyField(field) => write!(f, "session field `{field}` must not be empty"),
            Self::NonPositiveLifetime {
                issued_at_unix_seconds,
                expires_at_unix_seconds,
            } => write!(
                f,
                "session expiry {expires_at_unix_seconds} must be after issue {issued_at_unix_seconds}"
            ),
        }
    }
}

impl std::error::Error for SessionError {}

/// A unique session identifier (anti-replay nonce).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SessionId([u8; 16]);

impl SessionId {
    /// Wraps 16 nonce bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Borrows the nonce bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

/// The signed content of a local demo session.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionClaims {
    session_id: SessionId,
    subject: UserId,
    organization: OrganizationId,
    role: Role,
    issued_at_unix_seconds: u64,
    expires_at_unix_seconds: u64,
}

impl SessionClaims {
    /// Constructs session claims with a bounded, non-empty validity window.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::NonPositiveLifetime`] when `expires_at` is not
    /// strictly after `issued_at`, or [`SessionError::EmptyField`] when an
    /// identifier is empty.
    pub fn new(
        session_id: SessionId,
        subject: UserId,
        organization: OrganizationId,
        role: Role,
        issued_at_unix_seconds: u64,
        expires_at_unix_seconds: u64,
    ) -> Result<Self, SessionError> {
        if subject.as_str().is_empty() {
            return Err(SessionError::EmptyField("subject"));
        }
        if organization.as_str().is_empty() {
            return Err(SessionError::EmptyField("organization"));
        }
        if expires_at_unix_seconds <= issued_at_unix_seconds {
            return Err(SessionError::NonPositiveLifetime {
                issued_at_unix_seconds,
                expires_at_unix_seconds,
            });
        }
        Ok(Self {
            session_id,
            subject,
            organization,
            role,
            issued_at_unix_seconds,
            expires_at_unix_seconds,
        })
    }

    /// The session identifier.
    #[must_use]
    pub fn session_id(&self) -> SessionId {
        self.session_id
    }

    /// The subject user identity.
    #[must_use]
    pub fn subject(&self) -> &UserId {
        &self.subject
    }

    /// The subject's organization.
    #[must_use]
    pub fn organization(&self) -> &OrganizationId {
        &self.organization
    }

    /// The claimed role.
    #[must_use]
    pub fn role(&self) -> Role {
        self.role
    }

    /// The issue time, Unix seconds.
    #[must_use]
    pub fn issued_at_unix_seconds(&self) -> u64 {
        self.issued_at_unix_seconds
    }

    /// The expiry time, Unix seconds.
    #[must_use]
    pub fn expires_at_unix_seconds(&self) -> u64 {
        self.expires_at_unix_seconds
    }

    /// Whether the claims are active at `now` (`issued <= now < expires`).
    #[must_use]
    pub fn is_active_at(&self, now_unix_seconds: u64) -> bool {
        now_unix_seconds >= self.issued_at_unix_seconds
            && now_unix_seconds < self.expires_at_unix_seconds
    }

    /// The exact bytes a signer commits to.
    ///
    /// Deterministic and length-prefixed so distinct claims never collide.
    #[must_use]
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        push_bytes(&mut out, SESSION_DOMAIN_TAG);
        out.extend_from_slice(self.session_id.as_bytes());
        push_bytes(&mut out, self.subject.as_str().as_bytes());
        push_bytes(&mut out, self.organization.as_str().as_bytes());
        out.push(self.role.tag());
        out.extend_from_slice(&self.issued_at_unix_seconds.to_be_bytes());
        out.extend_from_slice(&self.expires_at_unix_seconds.to_be_bytes());
        out
    }
}

fn push_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}
