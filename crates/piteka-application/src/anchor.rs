//! Independent single-use anchoring, run off the dispatch hot path (Master Plan §5.9).
//!
//! [`AnchorUseCase`] corroborates a mandate's single use with a Single-Use Seal that is
//! enforced *independently* of Piteka's authoritative Postgres reservation. It creates a
//! seal bound to the authorized intent id, consumes it exactly once with the mandate's
//! reservation-token digest, and persists the resulting proof through a
//! [`SealConsumptionStore`]. A dispute bundle later carries that proof as a Parwana
//! `SealConsumptionRecord` that an offline verifier re-checks.
//!
//! This never runs inside the provider dispatch call: the Postgres compare-and-swap stays
//! the sole liveness authority, and the seal is written asynchronously around it. Both
//! seal operations are idempotent, so a retried completion path re-produces the same proof
//! rather than failing.

use piteka_ports::anchor::{AnchorError, AnchorPort, Digest32};
use piteka_storage::{SealConsumptionProofRecord, SealConsumptionStore, StorageError};
use sha2::{Digest, Sha256};

/// Domain tag separating the seal-id derivation from any other hash of a mandate id.
const SEAL_ID_DOMAIN: &[u8] = b"piteka.single-use-seal.v1\0";

/// A failure while recording an independent single-use anchor.
#[derive(Debug)]
pub enum AnchorUseCaseError {
    /// The seal backing rejected an operation.
    Anchor(AnchorError),
    /// Persisting the consumption proof failed.
    Storage(StorageError),
    /// An input digest was not exactly 32 hex-encoded bytes.
    MalformedDigest(&'static str),
}

impl core::fmt::Display for AnchorUseCaseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Anchor(err) => write!(f, "anchor backing error: {err:?}"),
            Self::Storage(err) => write!(f, "seal-consumption storage error: {err}"),
            Self::MalformedDigest(field) => write!(f, "malformed 32-byte digest: {field}"),
        }
    }
}

impl std::error::Error for AnchorUseCaseError {}

/// Records independent single-use anchors, off the dispatch hot path.
pub struct AnchorUseCase<A, S> {
    anchor: A,
    store: S,
}

impl<A: AnchorPort, S: SealConsumptionStore> AnchorUseCase<A, S> {
    /// Builds a use case over an anchor backing and a consumption-proof store.
    pub const fn new(anchor: A, store: S) -> Self {
        Self { anchor, store }
    }

    /// Records a mandate's independent single use and returns the persisted proof.
    ///
    /// Derives the seal id from the mandate id, creates the seal binding the authorized
    /// intent id (`intent_id_hex`), consumes it once with the mandate's reservation-token
    /// digest (`reservation_token_digest_hex`), and stores the resulting proof. Idempotent.
    ///
    /// # Errors
    ///
    /// Returns [`AnchorUseCaseError`] if an input digest is malformed, the seal backing
    /// rejects the create/consume, or the store rejects the proof.
    pub async fn record_single_use(
        &self,
        mandate_id_hex: &str,
        intent_id_hex: &str,
        reservation_token_digest_hex: &str,
    ) -> Result<SealConsumptionProofRecord, AnchorUseCaseError> {
        let commitment = decode_digest(intent_id_hex, "intent_id")?;
        let nullifier = decode_digest(reservation_token_digest_hex, "reservation_token_digest")?;
        let seal_id = seal_id_for(mandate_id_hex);

        self.anchor
            .create_seal(seal_id, commitment)
            .await
            .map_err(AnchorUseCaseError::Anchor)?;
        let proof = self
            .anchor
            .consume_seal(seal_id, nullifier)
            .await
            .map_err(AnchorUseCaseError::Anchor)?;

        let record = SealConsumptionProofRecord {
            mandate_id_hex: mandate_id_hex.to_string(),
            seal_id_hex: hex::encode(proof.seal_id),
            nullifier_hex: hex::encode(proof.nullifier),
            commitment_hex: hex::encode(proof.commitment),
            anchor_backend: proof.backend,
        };
        self.store
            .put(record.clone())
            .await
            .map_err(AnchorUseCaseError::Storage)?;
        Ok(record)
    }
}

/// Deterministically derives a 32-byte seal id from a mandate id, domain-separated.
fn seal_id_for(mandate_id_hex: &str) -> Digest32 {
    let mut hasher = Sha256::new();
    hasher.update(SEAL_ID_DOMAIN);
    hasher.update(mandate_id_hex.as_bytes());
    hasher.finalize().into()
}

/// Decodes exactly 32 hex bytes, failing closed on any other length or malformed hex.
fn decode_digest(hex_str: &str, field: &'static str) -> Result<Digest32, AnchorUseCaseError> {
    let bytes = hex::decode(hex_str).map_err(|_| AnchorUseCaseError::MalformedDigest(field))?;
    bytes
        .try_into()
        .map_err(|_| AnchorUseCaseError::MalformedDigest(field))
}

#[cfg(test)]
mod tests {
    use super::*;
    use piteka_ports::anchor::{AnchorRef, ConsumptionProof, LOCAL_SEAL_BACKEND};
    use piteka_storage::InMemorySealConsumptionStore;
    use std::collections::HashMap;
    use std::sync::Mutex;

    /// A minimal single-use seal backing that mirrors the local infra adapter's semantics
    /// without pulling the infra layer into the application crate's tests.
    #[derive(Default)]
    struct MockAnchor {
        seals: Mutex<HashMap<Digest32, (Digest32, Option<Digest32>)>>,
    }

    #[async_trait::async_trait]
    impl AnchorPort for MockAnchor {
        async fn create_seal(
            &self,
            seal_id: Digest32,
            commitment: Digest32,
        ) -> Result<AnchorRef, AnchorError> {
            let mut seals = self.seals.lock().unwrap();
            match seals.get(&seal_id) {
                Some((existing, _)) if *existing == commitment => {}
                Some(_) => return Err(AnchorError::SealAlreadyExists),
                None => {
                    seals.insert(seal_id, (commitment, None));
                }
            }
            Ok(AnchorRef {
                backend: LOCAL_SEAL_BACKEND.to_string(),
                reference: seal_id.to_vec(),
            })
        }

        async fn consume_seal(
            &self,
            seal_id: Digest32,
            nullifier: Digest32,
        ) -> Result<ConsumptionProof, AnchorError> {
            let mut seals = self.seals.lock().unwrap();
            let (commitment, consumed_by) =
                seals.get_mut(&seal_id).ok_or(AnchorError::SealNotFound)?;
            match consumed_by {
                Some(existing) if *existing == nullifier => {}
                Some(_) => return Err(AnchorError::SealAlreadyConsumed),
                None => *consumed_by = Some(nullifier),
            }
            Ok(ConsumptionProof {
                seal_id,
                nullifier,
                commitment: *commitment,
                backend: LOCAL_SEAL_BACKEND.to_string(),
            })
        }

        async fn anchor_commitment(
            &self,
            bundle_digest: Digest32,
        ) -> Result<AnchorRef, AnchorError> {
            Ok(AnchorRef {
                backend: LOCAL_SEAL_BACKEND.to_string(),
                reference: bundle_digest.to_vec(),
            })
        }
    }

    #[tokio::test]
    async fn records_a_proof_binding_the_intent_and_reservation_token() {
        let intent_id = "a1".repeat(32);
        let reservation_token = "b2".repeat(32);
        let use_case = AnchorUseCase::new(
            MockAnchor::default(),
            InMemorySealConsumptionStore::default(),
        );

        let record = use_case
            .record_single_use("mandate-1", &intent_id, &reservation_token)
            .await
            .expect("anchor recorded");

        assert_eq!(record.mandate_id_hex, "mandate-1");
        assert_eq!(record.commitment_hex, intent_id);
        assert_eq!(record.nullifier_hex, reservation_token);
        assert_eq!(record.anchor_backend, LOCAL_SEAL_BACKEND);
        // The seal id is a deterministic 32-byte derivation of the mandate id.
        assert_eq!(record.seal_id_hex, hex::encode(seal_id_for("mandate-1")));
    }

    #[tokio::test]
    async fn re_recording_the_same_mandate_is_idempotent() {
        let intent_id = "a1".repeat(32);
        let reservation_token = "b2".repeat(32);
        let use_case = AnchorUseCase::new(
            MockAnchor::default(),
            InMemorySealConsumptionStore::default(),
        );

        let first = use_case
            .record_single_use("mandate-1", &intent_id, &reservation_token)
            .await
            .expect("first record");
        let second = use_case
            .record_single_use("mandate-1", &intent_id, &reservation_token)
            .await
            .expect("idempotent re-record");
        assert_eq!(first, second);
    }

    #[tokio::test]
    async fn a_malformed_input_digest_fails_closed() {
        let use_case = AnchorUseCase::new(
            MockAnchor::default(),
            InMemorySealConsumptionStore::default(),
        );
        let result = use_case
            .record_single_use("mandate-1", "not-hex", &"b2".repeat(32))
            .await;
        assert!(matches!(
            result,
            Err(AnchorUseCaseError::MalformedDigest("intent_id"))
        ));
    }
}
