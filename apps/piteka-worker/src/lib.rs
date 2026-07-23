#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! Explicit worker entry point for ambiguous GitHub deployment outcomes.
//!
//! This crate deliberately contains no timer, retry loop, or release action.
//! Queue/API assembly submits one [`ReconciliationJob`] and [`run_job`] invokes
//! the application use case once. Provider absence therefore leaves the
//! mandate quarantined; only an explicit `Abandon` job can permanently close
//! an unresolved case.

use piteka_application::{
    ReconciliationError, ReconciliationOutcome, ReconciliationPorts, ReconciliationUseCase,
};
use piteka_application::{WorkerCapability, WorkerCapabilityError};
use std::collections::HashSet;
use std::sync::Mutex;

/// Authoritative job data loaded from the tenant-scoped database, never from
/// worker-controlled queue payload fields.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorizedExecution {
    /// Tenant.
    pub tenant_id: String,
    /// Approved request.
    pub request_id: String,
    /// Current intent digest.
    pub intent_digest_hex: String,
    /// Current active reservation.
    pub reservation_id: String,
    /// Expected isolated worker identity.
    pub worker_id: String,
}

/// Verifies the managed signature on a serialized worker capability.
#[async_trait::async_trait]
pub trait CapabilitySignatureVerifier: Send + Sync {
    /// Verification must apply current key lifecycle/revocation policy.
    async fn verify(&self, capability: &WorkerCapability) -> Result<(), WorkerCapabilityError>;
}

/// Fail-closed guard used immediately before obtaining provider credentials.
pub struct ExecutionGuard<V> {
    verifier: V,
    consumed_nonces: Mutex<HashSet<String>>,
}

impl<V: CapabilitySignatureVerifier> ExecutionGuard<V> {
    /// Creates a guard.
    pub fn new(verifier: V) -> Self {
        Self {
            verifier,
            consumed_nonces: Mutex::new(HashSet::new()),
        }
    }

    /// Verifies signature, expiry, worker identity and current database state,
    /// then consumes the nonce exactly once.
    pub async fn authorize(
        &self,
        capability: &WorkerCapability,
        authoritative: &AuthorizedExecution,
        now_unix_seconds: u64,
    ) -> Result<(), WorkerCapabilityError> {
        if capability.expires_at_unix_seconds <= now_unix_seconds {
            return Err(WorkerCapabilityError::Expired);
        }
        if capability.tenant_id != authoritative.tenant_id
            || capability.request_id != authoritative.request_id
            || capability.intent_digest_hex != authoritative.intent_digest_hex
            || capability.reservation_id != authoritative.reservation_id
            || capability.worker_id != authoritative.worker_id
        {
            return Err(WorkerCapabilityError::ContextMismatch);
        }
        self.verifier.verify(capability).await?;
        let mut nonces = self.consumed_nonces.lock().unwrap();
        if !nonces.insert(capability.nonce.clone()) {
            return Err(WorkerCapabilityError::Replayed);
        }
        Ok(())
    }
}

/// A single, explicitly authorized reconciliation operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReconciliationJob {
    /// Query GitHub for a deployment carrying the attempt's correlation data.
    Reconcile {
        /// Quarantined mandate identifier.
        mandate_id_hex: String,
        /// Authenticated worker or operator identity.
        operator_identity: String,
        /// Mandate projection version used by compare-and-swap.
        expected_mandate_version: i64,
    },
    /// Permanently close an ambiguity after an explicit investigation decision.
    Abandon {
        /// Quarantined mandate identifier.
        mandate_id_hex: String,
        /// Authenticated operator identity.
        operator_identity: String,
        /// Mandate projection version used by compare-and-swap.
        expected_mandate_version: i64,
        /// Non-empty investigation reason retained in the audit event.
        reason: String,
    },
}

/// Executes exactly one reconciliation job.
///
/// There is intentionally no automatic retry here. An unresolved result is a
/// successful, uncertainty-preserving outcome and remains quarantined until a
/// later explicit job is submitted.
pub async fn run_job<P: ReconciliationPorts>(
    use_case: &ReconciliationUseCase<P>,
    job: ReconciliationJob,
) -> Result<ReconciliationOutcome, ReconciliationError> {
    match job {
        ReconciliationJob::Reconcile {
            mandate_id_hex,
            operator_identity,
            expected_mandate_version,
        } => {
            use_case
                .reconcile(
                    &mandate_id_hex,
                    &operator_identity,
                    expected_mandate_version,
                )
                .await
        }
        ReconciliationJob::Abandon {
            mandate_id_hex,
            operator_identity,
            expected_mandate_version,
            reason,
        } => {
            use_case
                .abandon_unresolved(
                    &mandate_id_hex,
                    &operator_identity,
                    expected_mandate_version,
                    &reason,
                )
                .await
        }
    }
}

#[cfg(test)]
mod hardening_tests {
    use super::*;
    use piteka_application::{ManagedKeyId, ManagedSignature};

    struct Verifier;
    #[async_trait::async_trait]
    impl CapabilitySignatureVerifier for Verifier {
        async fn verify(&self, capability: &WorkerCapability) -> Result<(), WorkerCapabilityError> {
            if capability.signature.signature == b"valid" {
                Ok(())
            } else {
                Err(WorkerCapabilityError::InvalidSignature)
            }
        }
    }

    fn authoritative() -> AuthorizedExecution {
        AuthorizedExecution {
            tenant_id: "tenant-a".into(),
            request_id: "request-1".into(),
            intent_digest_hex: "intent-1".into(),
            reservation_id: "reservation-1".into(),
            worker_id: "worker-a".into(),
        }
    }

    fn capability() -> WorkerCapability {
        WorkerCapability {
            tenant_id: "tenant-a".into(),
            request_id: "request-1".into(),
            intent_digest_hex: "intent-1".into(),
            reservation_id: "reservation-1".into(),
            worker_id: "worker-a".into(),
            nonce: "nonce-1".into(),
            expires_at_unix_seconds: 200,
            signature: ManagedSignature {
                key_id: ManagedKeyId::parse("kms://workers/v1").unwrap(),
                algorithm: "Ed25519".into(),
                signature: b"valid".to_vec(),
                signed_at_unix_seconds: 100,
            },
        }
    }

    #[tokio::test]
    async fn forged_stale_and_replayed_jobs_fail_closed() {
        let guard = ExecutionGuard::new(Verifier);
        let mut forged = capability();
        forged.signature.signature = b"forged".to_vec();
        assert_eq!(
            guard.authorize(&forged, &authoritative(), 110).await,
            Err(WorkerCapabilityError::InvalidSignature)
        );
        let mut stale = authoritative();
        stale.reservation_id = "reservation-2".into();
        assert_eq!(
            guard.authorize(&capability(), &stale, 110).await,
            Err(WorkerCapabilityError::ContextMismatch)
        );
        guard
            .authorize(&capability(), &authoritative(), 110)
            .await
            .unwrap();
        assert_eq!(
            guard.authorize(&capability(), &authoritative(), 110).await,
            Err(WorkerCapabilityError::Replayed)
        );
    }
}
