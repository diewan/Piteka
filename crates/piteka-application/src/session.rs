//! Signed local session issuance and authentication for the demo slice.
//!
//! [`SessionAuthority`] issues a [`SignedSession`] for a configured member and
//! later authenticates one, failing closed on a bad signature, an expired or
//! not-yet-valid window, an unknown subject, a role or organization that does
//! not match the configured directory, or a signature-algorithm mismatch.
//!
//! # Demo only
//!
//! Signing is delegated to a [`SessionSigner`] port. The first slice binds a
//! [`SignatureAlgorithm::DemoLocalV1`] local signer; it is not an OIDC or
//! multi-tenant identity system. The concrete signer and its key material are
//! wired by the demo authorization boundary (ticket D-04). See the demo-identity
//! ADR under `piteka/docs/adr/`. This module makes no production security claim.

use piteka_domain::{
    Capability, ConfiguredOrganization, Identity, Role, SessionClaims, SessionId, UserId,
};

use crate::Clock;

/// The signature scheme used for a signed session.
///
/// A single variant today; authentication rejects any session whose algorithm
/// does not match the bound signer, so a future scheme cannot be silently
/// accepted by an old verifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SignatureAlgorithm {
    /// Local demo signer. Not for production authorization.
    DemoLocalV1,
}

/// A detached signature over [`SessionClaims::signing_bytes`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signature {
    algorithm: SignatureAlgorithm,
    bytes: Vec<u8>,
}

impl Signature {
    /// Wraps signature bytes tagged with their algorithm.
    #[must_use]
    pub fn new(algorithm: SignatureAlgorithm, bytes: Vec<u8>) -> Self {
        Self { algorithm, bytes }
    }

    /// The signature algorithm.
    #[must_use]
    pub fn algorithm(&self) -> SignatureAlgorithm {
        self.algorithm
    }

    /// The raw signature bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// A port that signs and verifies session bytes with a locally held key.
///
/// Implementations live in the infrastructure layer; the concrete demo signer
/// and its key are provided by the demo authorization boundary (D-04). The port
/// keeps this use case free of any key-management or cryptography dependency.
pub trait SessionSigner: Send + Sync {
    /// The algorithm this signer produces and accepts.
    fn algorithm(&self) -> SignatureAlgorithm;

    /// Signs `message`, returning an algorithm-tagged signature.
    fn sign(&self, message: &[u8]) -> Signature;

    /// Verifies `signature` over `message` in constant-ish time as feasible.
    fn verify(&self, message: &[u8], signature: &Signature) -> bool;
}

/// A session with its detached signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedSession {
    claims: SessionClaims,
    signature: Signature,
}

impl SignedSession {
    /// Reassembles a signed session from claims and a detached signature.
    ///
    /// Used when a session arrives from transport (for example a cookie). It
    /// performs no verification; call [`SessionAuthority::authenticate`] before
    /// trusting it.
    #[must_use]
    pub fn from_parts(claims: SessionClaims, signature: Signature) -> Self {
        Self { claims, signature }
    }

    /// The signed claims.
    #[must_use]
    pub fn claims(&self) -> &SessionClaims {
        &self.claims
    }

    /// The detached signature.
    #[must_use]
    pub fn signature(&self) -> &Signature {
        &self.signature
    }
}

/// A session that passed signature, temporal, and directory checks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthenticatedSession {
    identity: Identity,
    claims: SessionClaims,
}

impl AuthenticatedSession {
    /// The configured identity the session authenticated as.
    #[must_use]
    pub fn identity(&self) -> &Identity {
        &self.identity
    }

    /// The authenticated claims.
    #[must_use]
    pub fn claims(&self) -> &SessionClaims {
        &self.claims
    }

    /// The authenticated role.
    #[must_use]
    pub fn role(&self) -> Role {
        self.identity.role()
    }

    /// Whether the authenticated role grants `capability`.
    #[must_use]
    pub fn can(&self, capability: Capability) -> bool {
        self.identity.role().grants(capability)
    }
}

/// A failure issuing or authenticating a session. Every variant is a hard deny.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthError {
    /// The subject is not a member of the configured organization.
    UnknownSubject(UserId),
    /// The signature did not verify for these claims.
    InvalidSignature,
    /// The session algorithm did not match the bound signer.
    AlgorithmMismatch {
        /// The signer's algorithm.
        expected: SignatureAlgorithm,
        /// The session's algorithm.
        found: SignatureAlgorithm,
    },
    /// The current time is at or after the session's expiry.
    Expired {
        /// Expiry, Unix seconds.
        expires_at_unix_seconds: u64,
        /// Now, Unix seconds.
        now_unix_seconds: u64,
    },
    /// The current time is before the session's issue time.
    NotYetValid {
        /// Issue time, Unix seconds.
        issued_at_unix_seconds: u64,
        /// Now, Unix seconds.
        now_unix_seconds: u64,
    },
    /// The claimed role did not match the configured member's role.
    RoleMismatch {
        /// The configured role.
        configured: Role,
        /// The claimed role.
        claimed: Role,
    },
    /// The claimed organization did not match the configured member's.
    CrossOrganization,
    /// The authenticated role does not grant the required capability.
    Unauthorized(Capability),
}

impl core::fmt::Display for AuthError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnknownSubject(user) => write!(f, "unknown subject `{}`", user.as_str()),
            Self::InvalidSignature => f.write_str("session signature did not verify"),
            Self::AlgorithmMismatch { expected, found } => {
                write!(f, "session algorithm {found:?} does not match signer {expected:?}")
            }
            Self::Expired {
                expires_at_unix_seconds,
                now_unix_seconds,
            } => write!(
                f,
                "session expired at {expires_at_unix_seconds}, now {now_unix_seconds}"
            ),
            Self::NotYetValid {
                issued_at_unix_seconds,
                now_unix_seconds,
            } => write!(
                f,
                "session not valid until {issued_at_unix_seconds}, now {now_unix_seconds}"
            ),
            Self::RoleMismatch { configured, claimed } => {
                write!(f, "claimed role {claimed:?} but member holds {configured:?}")
            }
            Self::CrossOrganization => f.write_str("session organization does not match member"),
            Self::Unauthorized(capability) => {
                write!(f, "role does not grant capability {capability:?}")
            }
        }
    }
}

impl std::error::Error for AuthError {}

/// Issues and authenticates signed local sessions against a configured directory.
pub struct SessionAuthority<S, C> {
    signer: S,
    clock: C,
    directory: ConfiguredOrganization,
}

impl<S: SessionSigner, C: Clock> SessionAuthority<S, C> {
    /// Binds a signer, clock, and configured organization directory.
    pub const fn new(signer: S, clock: C, directory: ConfiguredOrganization) -> Self {
        Self {
            signer,
            clock,
            directory,
        }
    }

    /// The configured organization this authority serves.
    pub const fn directory(&self) -> &ConfiguredOrganization {
        &self.directory
    }

    /// Issues a signed session for a configured member.
    ///
    /// The role and organization are taken from the configured directory, never
    /// from the caller, so a requester cannot self-issue an approver session.
    ///
    /// The lifetime is clamped to at least one second so the issued window is
    /// always non-empty; a caller cannot mint an already-expired session.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::UnknownSubject`] when `subject` is not a configured
    /// member.
    pub fn issue(
        &self,
        subject: &UserId,
        session_id: SessionId,
        lifetime_seconds: u64,
    ) -> Result<SignedSession, AuthError> {
        let member = self
            .directory
            .member(subject)
            .ok_or_else(|| AuthError::UnknownSubject(subject.clone()))?;
        let issued_at = self.clock.unix_seconds();
        let expires_at = issued_at.saturating_add(lifetime_seconds.max(1));
        let claims = SessionClaims::new(
            session_id,
            member.user_id().clone(),
            member.organization().clone(),
            member.role(),
            issued_at,
            expires_at,
        )
        .expect("directory-derived claims with a positive lifetime are well-formed");
        let signature = self.signer.sign(&claims.signing_bytes());
        Ok(SignedSession { claims, signature })
    }

    /// Authenticates a signed session, failing closed on any discrepancy.
    ///
    /// # Errors
    ///
    /// Returns the matching [`AuthError`] variant for an algorithm mismatch,
    /// an invalid signature, an expired or not-yet-valid window, an unknown
    /// subject, or a role/organization that disagrees with the directory.
    pub fn authenticate(
        &self,
        session: &SignedSession,
    ) -> Result<AuthenticatedSession, AuthError> {
        let expected_algorithm = self.signer.algorithm();
        if session.signature.algorithm() != expected_algorithm {
            return Err(AuthError::AlgorithmMismatch {
                expected: expected_algorithm,
                found: session.signature.algorithm(),
            });
        }

        let claims = &session.claims;
        if !self
            .signer
            .verify(&claims.signing_bytes(), &session.signature)
        {
            return Err(AuthError::InvalidSignature);
        }

        let now = self.clock.unix_seconds();
        if now >= claims.expires_at_unix_seconds() {
            return Err(AuthError::Expired {
                expires_at_unix_seconds: claims.expires_at_unix_seconds(),
                now_unix_seconds: now,
            });
        }
        if now < claims.issued_at_unix_seconds() {
            return Err(AuthError::NotYetValid {
                issued_at_unix_seconds: claims.issued_at_unix_seconds(),
                now_unix_seconds: now,
            });
        }

        let member = self
            .directory
            .member(claims.subject())
            .ok_or_else(|| AuthError::UnknownSubject(claims.subject().clone()))?;
        if member.organization() != claims.organization() {
            return Err(AuthError::CrossOrganization);
        }
        if member.role() != claims.role() {
            return Err(AuthError::RoleMismatch {
                configured: member.role(),
                claimed: claims.role(),
            });
        }

        Ok(AuthenticatedSession {
            identity: member.clone(),
            claims: claims.clone(),
        })
    }

    /// Authorizes an authenticated session for a required capability.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::Unauthorized`] when the role does not grant it.
    pub fn authorize(
        &self,
        session: &AuthenticatedSession,
        capability: Capability,
    ) -> Result<(), AuthError> {
        if session.can(capability) {
            Ok(())
        } else {
            Err(AuthError::Unauthorized(capability))
        }
    }
}
