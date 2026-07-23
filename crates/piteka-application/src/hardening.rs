//! Pilot security boundaries for production approval and execution.
//!
//! The types in this module are deliberately provider-neutral. KMS/HSM and
//! WebAuthn implementations live outside the application layer and can return
//! signatures/assertions, but private key material can never cross these APIs.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::sync::Mutex;
use thiserror::Error;

/// Stable identifier for a key managed by a KMS or HSM.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ManagedKeyId(String);

impl ManagedKeyId {
    /// Validates a non-secret provider key identifier.
    pub fn parse(value: impl Into<String>) -> Result<Self, SigningError> {
        let value = value.into();
        if value.trim().is_empty() || value.len() > 512 || value.chars().any(char::is_control) {
            return Err(SigningError::InvalidKeyId);
        }
        Ok(Self(value))
    }

    /// Returns the non-secret identifier.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The only production signing purposes accepted by the application.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyPurpose {
    /// Sign a mandate issued after approval.
    Mandate,
    /// Sign an accountability receipt.
    Receipt,
    /// Sign a worker capability.
    WorkerCapability,
}

/// Lifecycle state reported by the external key authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyStatus {
    /// May sign new objects and verify existing signatures.
    Active,
    /// Cannot sign new objects; old signatures remain verifiable.
    VerifyOnly,
    /// Compromised/revoked. Verification policy must bound the compromise time.
    Compromised { not_after_unix_seconds: u64 },
}

/// An externally produced signature plus public lifecycle metadata.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManagedSignature {
    /// Provider key version used for signing.
    pub key_id: ManagedKeyId,
    /// Stable algorithm identifier.
    pub algorithm: String,
    /// Opaque signature bytes.
    pub signature: Vec<u8>,
    /// Signing time asserted by the trusted adapter.
    pub signed_at_unix_seconds: u64,
}

/// Fail-closed signing failures.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum SigningError {
    /// Key identifier is malformed.
    #[error("invalid managed key identifier")]
    InvalidKeyId,
    /// The key is not active for new signatures.
    #[error("managed key is not active")]
    KeyNotActive,
    /// The provider returned an empty or mismatched response.
    #[error("invalid managed signing response")]
    InvalidResponse,
    /// The external signing authority is unavailable.
    #[error("managed signing service unavailable")]
    Unavailable,
}

/// Port to a KMS/HSM. It intentionally has no import/export/private-key API.
#[async_trait]
pub trait ProductionSigner: Send + Sync {
    /// Returns current public lifecycle state.
    async fn key_status(&self, key_id: &ManagedKeyId) -> Result<KeyStatus, SigningError>;

    /// Signs an already canonicalized digest for one explicit purpose.
    async fn sign_digest(
        &self,
        key_id: &ManagedKeyId,
        purpose: KeyPurpose,
        digest: [u8; 32],
        now_unix_seconds: u64,
    ) -> Result<ManagedSignature, SigningError>;
}

/// Minimal append-only security audit boundary.
#[async_trait]
pub trait AuditSink: Send + Sync {
    /// Records a stable event name and non-secret detail.
    async fn record(&self, event: &'static str, detail: String) -> Result<(), String>;
}

/// Exact, server-canonicalized approval intent.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanonicalIntent {
    /// Tenant owning the intent.
    pub tenant_id: String,
    /// Action request identifier.
    pub request_id: String,
    /// Exact environment.
    pub environment: String,
    /// Exact repository.
    pub repository: String,
    /// Exact immutable revision.
    pub revision: String,
}

impl CanonicalIntent {
    /// Produces one deterministic digest without relying on JSON map ordering.
    pub fn digest(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        for field in [
            self.tenant_id.as_bytes(),
            self.request_id.as_bytes(),
            self.environment.as_bytes(),
            self.repository.as_bytes(),
            self.revision.as_bytes(),
        ] {
            hasher.update((field.len() as u64).to_be_bytes());
            hasher.update(field);
        }
        hasher.finalize().into()
    }

    /// Hex digest shown in the server-rendered approval summary.
    pub fn digest_hex(&self) -> String {
        hex::encode(self.digest())
    }
}

/// A single-use challenge bound to tenant, approver, and exact intent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApprovalChallenge {
    /// Random challenge bytes generated by a CSPRNG adapter.
    pub challenge: Vec<u8>,
    /// Tenant scope.
    pub tenant_id: String,
    /// Authenticated approver.
    pub approver_id: String,
    /// Exact digest displayed to the approver.
    pub intent_digest: [u8; 32],
    /// Expiry.
    pub expires_at_unix_seconds: u64,
}

/// Verified WebAuthn result returned by a credential adapter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApprovalProof {
    /// Credential identifier.
    pub credential_id: String,
    /// Authenticator monotonic counter.
    pub sign_count: u64,
    /// Digest embedded in the signed ceremony.
    pub intent_digest: [u8; 32],
}

/// WebAuthn assertion verifier boundary.
#[async_trait]
pub trait ApprovalAssertionVerifier: Send + Sync {
    /// Verifies origin, RP ID, challenge, user verification, signature and counter.
    async fn verify(
        &self,
        challenge: &ApprovalChallenge,
        assertion: &[u8],
    ) -> Result<ApprovalProof, ApprovalCeremonyError>;
}

/// Approval ceremony failures.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ApprovalCeremonyError {
    /// Challenge has expired.
    #[error("approval challenge expired")]
    Expired,
    /// Challenge was consumed already.
    #[error("approval challenge replayed")]
    Replayed,
    /// Tenant, approver, or intent differs.
    #[error("approval challenge is bound to a different context")]
    ContextMismatch,
    /// Authenticator assertion failed verification.
    #[error("invalid WebAuthn assertion")]
    InvalidAssertion,
    /// Audit trail could not be persisted.
    #[error("approval audit unavailable")]
    AuditUnavailable,
}

/// Coordinates single-use WebAuthn approval challenges.
pub struct ApprovalCeremony<V, A> {
    verifier: V,
    audit: A,
    consumed: Mutex<HashSet<Vec<u8>>>,
}

impl<V, A> ApprovalCeremony<V, A>
where
    V: ApprovalAssertionVerifier,
    A: AuditSink,
{
    /// Creates a ceremony coordinator.
    pub fn new(verifier: V, audit: A) -> Self {
        Self {
            verifier,
            audit,
            consumed: Mutex::new(HashSet::new()),
        }
    }

    /// Verifies and atomically consumes a challenge.
    pub async fn complete(
        &self,
        challenge: &ApprovalChallenge,
        tenant_id: &str,
        approver_id: &str,
        displayed_intent: &CanonicalIntent,
        assertion: &[u8],
        now_unix_seconds: u64,
    ) -> Result<ApprovalProof, ApprovalCeremonyError> {
        if now_unix_seconds > challenge.expires_at_unix_seconds {
            return Err(ApprovalCeremonyError::Expired);
        }
        if challenge.tenant_id != tenant_id
            || challenge.approver_id != approver_id
            || challenge.intent_digest != displayed_intent.digest()
        {
            return Err(ApprovalCeremonyError::ContextMismatch);
        }
        {
            let consumed = self.consumed.lock().expect("challenge lock poisoned");
            if consumed.contains(&challenge.challenge) {
                return Err(ApprovalCeremonyError::Replayed);
            }
        }
        let proof = self.verifier.verify(challenge, assertion).await?;
        if proof.intent_digest != challenge.intent_digest {
            return Err(ApprovalCeremonyError::ContextMismatch);
        }
        {
            let mut consumed = self.consumed.lock().expect("challenge lock poisoned");
            if !consumed.insert(challenge.challenge.clone()) {
                return Err(ApprovalCeremonyError::Replayed);
            }
        }
        self.audit
            .record(
                "webauthn_approval_completed",
                format!(
                    "tenant={tenant_id},approver={approver_id},intent={}",
                    hex::encode(proof.intent_digest)
                ),
            )
            .await
            .map_err(|_| ApprovalCeremonyError::AuditUnavailable)?;
        Ok(proof)
    }
}

/// Intent-integrity failures at the final mutation boundary.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum IntentBindingError {
    /// The submitted digest is not the current server-derived digest.
    #[error("approval intent changed after display")]
    StaleOrMutated,
}

/// Recomputes the intent at mutation time and rejects stale browser state.
pub fn verify_intent_binding(
    current: &CanonicalIntent,
    displayed_digest_hex: &str,
) -> Result<(), IntentBindingError> {
    if current.digest_hex() == displayed_digest_hex {
        Ok(())
    } else {
        Err(IntentBindingError::StaleOrMutated)
    }
}

/// Short-lived, signed authority for exactly one reserved execution.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkerCapability {
    /// Owning tenant.
    pub tenant_id: String,
    /// Approved request.
    pub request_id: String,
    /// Exact canonical intent.
    pub intent_digest_hex: String,
    /// Exact mandate reservation.
    pub reservation_id: String,
    /// Intended worker identity.
    pub worker_id: String,
    /// Unique replay identifier.
    pub nonce: String,
    /// Hard expiry.
    pub expires_at_unix_seconds: u64,
    /// Managed-key signature.
    pub signature: ManagedSignature,
}

/// Capability validation failures.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum WorkerCapabilityError {
    /// Capability has expired.
    #[error("worker capability expired")]
    Expired,
    /// Worker, tenant, intent, request, or reservation does not match the job.
    #[error("worker capability context mismatch")]
    ContextMismatch,
    /// Nonce was used already.
    #[error("worker capability replayed")]
    Replayed,
    /// Managed signature is invalid or no longer acceptable.
    #[error("worker capability signature invalid")]
    InvalidSignature,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    struct Verifier;
    #[async_trait]
    impl ApprovalAssertionVerifier for Verifier {
        async fn verify(
            &self,
            challenge: &ApprovalChallenge,
            assertion: &[u8],
        ) -> Result<ApprovalProof, ApprovalCeremonyError> {
            if assertion != b"valid" {
                return Err(ApprovalCeremonyError::InvalidAssertion);
            }
            Ok(ApprovalProof {
                credential_id: "credential-1".into(),
                sign_count: 2,
                intent_digest: challenge.intent_digest,
            })
        }
    }

    #[derive(Clone, Default)]
    struct Audit(Arc<Mutex<Vec<String>>>);
    #[async_trait]
    impl AuditSink for Audit {
        async fn record(&self, event: &'static str, detail: String) -> Result<(), String> {
            self.0.lock().unwrap().push(format!("{event}:{detail}"));
            Ok(())
        }
    }

    fn intent(revision: &str) -> CanonicalIntent {
        CanonicalIntent {
            tenant_id: "tenant-a".into(),
            request_id: "request-1".into(),
            environment: "production".into(),
            repository: "acme/service".into(),
            revision: revision.into(),
        }
    }

    #[tokio::test]
    async fn challenge_is_exact_intent_bound_and_single_use() {
        let shown = intent("abc");
        let challenge = ApprovalChallenge {
            challenge: vec![7; 32],
            tenant_id: "tenant-a".into(),
            approver_id: "alice".into(),
            intent_digest: shown.digest(),
            expires_at_unix_seconds: 200,
        };
        let ceremony = ApprovalCeremony::new(Verifier, Audit::default());
        ceremony
            .complete(&challenge, "tenant-a", "alice", &shown, b"valid", 100)
            .await
            .unwrap();
        assert_eq!(
            ceremony
                .complete(&challenge, "tenant-a", "alice", &shown, b"valid", 100)
                .await,
            Err(ApprovalCeremonyError::Replayed)
        );
        let changed = intent("def");
        let fresh = ApprovalChallenge {
            challenge: vec![8; 32],
            ..challenge
        };
        assert_eq!(
            ceremony
                .complete(&fresh, "tenant-a", "alice", &changed, b"valid", 100)
                .await,
            Err(ApprovalCeremonyError::ContextMismatch)
        );
    }

    #[test]
    fn post_display_mutation_invalidates_binding() {
        let shown = intent("abc");
        let displayed = shown.digest_hex();
        assert!(verify_intent_binding(&shown, &displayed).is_ok());
        assert_eq!(
            verify_intent_binding(&intent("def"), &displayed),
            Err(IntentBindingError::StaleOrMutated)
        );
    }
}
