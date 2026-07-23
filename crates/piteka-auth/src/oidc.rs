//! Production OIDC claim validation and server-side RBAC.
//!
//! Cryptographic JWT verification and discovery are adapter responsibilities.
//! This module validates the trusted result against the configured issuer,
//! audience, nonce, tenant mapping, time bounds and an allow-listed role map.

use std::collections::{HashMap, HashSet};

/// Claims returned only after adapter-level signature verification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedOidcClaims {
    /// Token issuer.
    pub issuer: String,
    /// Token audiences.
    pub audiences: Vec<String>,
    /// Stable provider subject.
    pub subject: String,
    /// Authorization-code flow nonce.
    pub nonce: String,
    /// Expiration time.
    pub expires_at_unix_seconds: u64,
    /// Issued-at time.
    pub issued_at_unix_seconds: u64,
    /// Provider tenant/organization claim.
    pub tenant_claim: String,
    /// Provider groups/roles.
    pub groups: Vec<String>,
    /// Provider session id used for logout/revocation.
    pub session_id: String,
}

/// Product roles. Route visibility must never substitute for these checks.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ProductionRole {
    /// May request actions.
    Requester,
    /// May approve production actions after step-up.
    Approver,
    /// May dispatch approved actions.
    Executor,
    /// May investigate and export evidence.
    Investigator,
    /// May administer security configuration.
    SecurityAdmin,
}

/// Server-side capabilities checked at every mutation boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Capability {
    /// Propose an action.
    RequestAction,
    /// Approve an action.
    ApproveProduction,
    /// Execute an approved action.
    ExecuteAction,
    /// Read/export evidence.
    Investigate,
    /// Change security configuration.
    AdministerSecurity,
}

/// Authenticated production principal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProductionPrincipal {
    /// Provider subject.
    pub subject: String,
    /// Server-mapped internal tenant.
    pub tenant_id: String,
    /// Allow-listed roles.
    pub roles: HashSet<ProductionRole>,
    /// Provider session id.
    pub session_id: String,
    /// Session expiry.
    pub expires_at_unix_seconds: u64,
}

impl ProductionPrincipal {
    /// Performs the authoritative server-side RBAC decision.
    pub fn require(&self, capability: Capability) -> Result<(), OidcError> {
        let role = match capability {
            Capability::RequestAction => ProductionRole::Requester,
            Capability::ApproveProduction => ProductionRole::Approver,
            Capability::ExecuteAction => ProductionRole::Executor,
            Capability::Investigate => ProductionRole::Investigator,
            Capability::AdministerSecurity => ProductionRole::SecurityAdmin,
        };
        self.roles
            .contains(&role)
            .then_some(())
            .ok_or(OidcError::Forbidden)
    }
}

/// Strict OIDC/RBAC policy.
#[derive(Clone, Debug)]
pub struct OidcPolicy {
    /// Exact issuer from discovery configuration.
    pub issuer: String,
    /// Required client audience.
    pub audience: String,
    /// Maximum permitted token lifetime.
    pub max_token_lifetime_seconds: u64,
    /// Explicit provider-tenant to internal-tenant mapping.
    pub tenants: HashMap<String, String>,
    /// Explicit provider group to role mapping.
    pub groups: HashMap<String, ProductionRole>,
}

/// OIDC validation failures.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OidcError {
    /// Issuer mismatch.
    InvalidIssuer,
    /// Audience mismatch.
    InvalidAudience,
    /// Nonce mismatch.
    InvalidNonce,
    /// Expired, future-issued, or excessive-lifetime token.
    InvalidLifetime,
    /// Missing stable identity/session claims.
    MissingIdentity,
    /// Provider tenant is not allow-listed.
    UnmappedTenant,
    /// No allow-listed role resulted.
    NoRoles,
    /// Capability denied by server policy.
    Forbidden,
    /// Session was logged out or revoked.
    Revoked,
}

/// In-memory revocation view; production adapters can hydrate it from durable storage.
#[derive(Default)]
pub struct SessionRevocations {
    revoked: std::sync::RwLock<HashSet<String>>,
}

impl SessionRevocations {
    /// Revokes a provider session id. Logout is idempotent.
    pub fn revoke(&self, session_id: impl Into<String>) {
        self.revoked.write().unwrap().insert(session_id.into());
    }

    /// Rejects a revoked session.
    pub fn check(&self, session_id: &str) -> Result<(), OidcError> {
        if self.revoked.read().unwrap().contains(session_id) {
            Err(OidcError::Revoked)
        } else {
            Ok(())
        }
    }
}

impl OidcPolicy {
    /// Validates trusted claims and maps only configured roles and tenants.
    pub fn authenticate(
        &self,
        claims: VerifiedOidcClaims,
        expected_nonce: &str,
        now_unix_seconds: u64,
        revocations: &SessionRevocations,
    ) -> Result<ProductionPrincipal, OidcError> {
        if claims.issuer != self.issuer {
            return Err(OidcError::InvalidIssuer);
        }
        if !claims.audiences.iter().any(|aud| aud == &self.audience) {
            return Err(OidcError::InvalidAudience);
        }
        if claims.nonce != expected_nonce || expected_nonce.is_empty() {
            return Err(OidcError::InvalidNonce);
        }
        if claims.expires_at_unix_seconds <= now_unix_seconds
            || claims.issued_at_unix_seconds > now_unix_seconds
            || claims
                .expires_at_unix_seconds
                .saturating_sub(claims.issued_at_unix_seconds)
                > self.max_token_lifetime_seconds
        {
            return Err(OidcError::InvalidLifetime);
        }
        if claims.subject.is_empty() || claims.session_id.is_empty() {
            return Err(OidcError::MissingIdentity);
        }
        revocations.check(&claims.session_id)?;
        let tenant_id = self
            .tenants
            .get(&claims.tenant_claim)
            .cloned()
            .ok_or(OidcError::UnmappedTenant)?;
        let roles: HashSet<_> = claims
            .groups
            .iter()
            .filter_map(|group| self.groups.get(group).copied())
            .collect();
        if roles.is_empty() {
            return Err(OidcError::NoRoles);
        }
        Ok(ProductionPrincipal {
            subject: claims.subject,
            tenant_id,
            roles,
            session_id: claims.session_id,
            expires_at_unix_seconds: claims.expires_at_unix_seconds,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> OidcPolicy {
        OidcPolicy {
            issuer: "https://id.example".into(),
            audience: "piteka".into(),
            max_token_lifetime_seconds: 3600,
            tenants: HashMap::from([("org-a".into(), "tenant-a".into())]),
            groups: HashMap::from([("approvers".into(), ProductionRole::Approver)]),
        }
    }

    fn claims() -> VerifiedOidcClaims {
        VerifiedOidcClaims {
            issuer: "https://id.example".into(),
            audiences: vec!["piteka".into()],
            subject: "alice".into(),
            nonce: "nonce".into(),
            expires_at_unix_seconds: 2000,
            issued_at_unix_seconds: 1000,
            tenant_claim: "org-a".into(),
            groups: vec!["approvers".into(), "self-asserted-admin".into()],
            session_id: "sid-1".into(),
        }
    }

    #[test]
    fn issuer_audience_nonce_and_escalation_fail_closed() {
        let revocations = SessionRevocations::default();
        let principal = policy()
            .authenticate(claims(), "nonce", 1500, &revocations)
            .unwrap();
        assert!(principal.require(Capability::ApproveProduction).is_ok());
        assert_eq!(
            principal.require(Capability::AdministerSecurity),
            Err(OidcError::Forbidden)
        );
        let mut bad = claims();
        bad.issuer = "https://evil.example".into();
        assert_eq!(
            policy().authenticate(bad, "nonce", 1500, &revocations),
            Err(OidcError::InvalidIssuer)
        );
        let mut bad = claims();
        bad.audiences = vec!["other".into()];
        assert_eq!(
            policy().authenticate(bad, "nonce", 1500, &revocations),
            Err(OidcError::InvalidAudience)
        );
        assert_eq!(
            policy().authenticate(claims(), "different", 1500, &revocations),
            Err(OidcError::InvalidNonce)
        );
    }

    #[test]
    fn logout_revokes_session() {
        let revocations = SessionRevocations::default();
        revocations.revoke("sid-1");
        assert_eq!(
            policy().authenticate(claims(), "nonce", 1500, &revocations),
            Err(OidcError::Revoked)
        );
    }
}
