//! Ephemeral in-process Single-Use Seal anchoring adapter (Phase B, §5.9).
//!
//! [`InMemoryCsvSealAnchor`] is the in-process backing for [`AnchorPort`]: seals live in a
//! `Mutex`-guarded map. The `InMemory` qualifier is the durability statement — this
//! backing loses every seal on restart, so it corroborates single use only for the
//! lifetime of the process. A durable backing (the on-chain CSVSeal path) is selectable
//! later behind the same trait. It enforces single use independently of Piteka's Postgres
//! reservation — a seal binds a commitment at creation and can be consumed exactly once —
//! and preserves a [`ConsumptionProof`] that re-checks offline.
//!
//! The stored backend discriminator value [`LOCAL_SEAL_BACKEND`] (`csv-seal.local.v1`) is
//! unchanged by this rename: it is written to `seal_consumption_proofs.anchor_backend` and
//! into exported bundles, so its bytes are a compatibility surface, not a source name.
//!
//! It is intended to run off the dispatch hot path (from the reconciliation/worker
//! background infrastructure), never in the provider dispatch call. The real on-chain
//! CSVSeal path is selectable later by configuration behind the same [`AnchorPort`] trait.

use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;
use piteka_ports::anchor::{
    AnchorError, AnchorPort, AnchorRef, ConsumptionProof, Digest32, LOCAL_SEAL_BACKEND,
};

/// The state of one local seal.
#[derive(Clone, Debug)]
struct SealState {
    commitment: Digest32,
    consumed_by: Option<Digest32>,
}

/// Ephemeral in-process single-use seal store implementing [`AnchorPort`].
///
/// State is lost on restart; it is corroborating evidence, never the authoritative
/// reservation, which remains Piteka's PostgreSQL compare-and-swap.
#[derive(Default)]
pub struct InMemoryCsvSealAnchor {
    seals: Mutex<HashMap<Digest32, SealState>>,
}

impl InMemoryCsvSealAnchor {
    /// Creates an empty local seal store.
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<Digest32, SealState>> {
        // A poisoned lock means a prior consume/create panicked mid-mutation; the seal map
        // is a corroboration side-store, so recover the guard rather than propagate.
        self.seals
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

#[async_trait]
impl AnchorPort for InMemoryCsvSealAnchor {
    async fn create_seal(
        &self,
        seal_id: Digest32,
        commitment: Digest32,
    ) -> Result<AnchorRef, AnchorError> {
        let mut seals = self.lock();
        match seals.get(&seal_id) {
            // Re-creating a seal with the same commitment is idempotent.
            Some(existing) if existing.commitment == commitment => {}
            Some(_) => return Err(AnchorError::SealAlreadyExists),
            None => {
                seals.insert(
                    seal_id,
                    SealState {
                        commitment,
                        consumed_by: None,
                    },
                );
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
        let mut seals = self.lock();
        let seal = seals.get_mut(&seal_id).ok_or(AnchorError::SealNotFound)?;
        match seal.consumed_by {
            // Idempotent re-consumption with the same nullifier returns the same proof.
            Some(existing) if existing == nullifier => {}
            // A different nullifier against a consumed seal is a double use.
            Some(_) => return Err(AnchorError::SealAlreadyConsumed),
            None => seal.consumed_by = Some(nullifier),
        }
        Ok(ConsumptionProof {
            seal_id,
            nullifier,
            commitment: seal.commitment,
            backend: LOCAL_SEAL_BACKEND.to_string(),
        })
    }

    async fn anchor_commitment(&self, bundle_digest: Digest32) -> Result<AnchorRef, AnchorError> {
        // The local backing simply witnesses the digest; the reference is the digest itself.
        Ok(AnchorRef {
            backend: LOCAL_SEAL_BACKEND.to_string(),
            reference: bundle_digest.to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(byte: u8) -> Digest32 {
        [byte; 32]
    }

    #[tokio::test]
    async fn create_then_consume_yields_a_binding_proof() {
        let anchor = InMemoryCsvSealAnchor::new();
        anchor.create_seal(d(1), d(2)).await.unwrap();
        let proof = anchor.consume_seal(d(1), d(3)).await.unwrap();
        assert_eq!(proof.seal_id, d(1));
        assert_eq!(proof.commitment, d(2));
        assert_eq!(proof.nullifier, d(3));
        assert_eq!(proof.backend, LOCAL_SEAL_BACKEND);
    }

    #[tokio::test]
    async fn re_consuming_with_the_same_nullifier_is_idempotent() {
        let anchor = InMemoryCsvSealAnchor::new();
        anchor.create_seal(d(1), d(2)).await.unwrap();
        let first = anchor.consume_seal(d(1), d(3)).await.unwrap();
        let second = anchor.consume_seal(d(1), d(3)).await.unwrap();
        assert_eq!(first, second);
    }

    #[tokio::test]
    async fn a_second_nullifier_is_rejected_as_double_use() {
        let anchor = InMemoryCsvSealAnchor::new();
        anchor.create_seal(d(1), d(2)).await.unwrap();
        anchor.consume_seal(d(1), d(3)).await.unwrap();
        assert_eq!(
            anchor.consume_seal(d(1), d(9)).await,
            Err(AnchorError::SealAlreadyConsumed)
        );
    }

    #[tokio::test]
    async fn consuming_an_unknown_seal_fails_closed() {
        let anchor = InMemoryCsvSealAnchor::new();
        assert_eq!(
            anchor.consume_seal(d(1), d(3)).await,
            Err(AnchorError::SealNotFound)
        );
    }

    #[tokio::test]
    async fn recreating_a_seal_with_a_different_commitment_is_rejected() {
        let anchor = InMemoryCsvSealAnchor::new();
        anchor.create_seal(d(1), d(2)).await.unwrap();
        assert_eq!(
            anchor.create_seal(d(1), d(5)).await,
            Err(AnchorError::SealAlreadyExists)
        );
    }
}

#[cfg(test)]
mod nam02_rename_compatibility {
    use super::*;

    fn d(byte: u8) -> Digest32 {
        [byte; 32]
    }

    /// NAM-02 renamed `LocalCsvSealAnchor` to `InMemoryCsvSealAnchor` so the type
    /// name states its durability. The backend discriminator it writes is a
    /// *stored* value — it lands in `seal_consumption_proofs.anchor_backend` and in
    /// exported dispute bundles — so it must not move with the type name. If this
    /// assertion ever needs changing, that is a data migration, not a rename.
    #[tokio::test]
    async fn stored_backend_discriminator_is_unchanged_by_the_type_rename() {
        assert_eq!(LOCAL_SEAL_BACKEND, "csv-seal.local.v1");

        let anchor = InMemoryCsvSealAnchor::new();
        let reference = anchor.create_seal(d(1), d(2)).await.unwrap();
        assert_eq!(reference.backend, "csv-seal.local.v1");

        let proof = anchor.consume_seal(d(1), d(3)).await.unwrap();
        assert_eq!(proof.backend, "csv-seal.local.v1");

        let anchored = anchor.anchor_commitment(d(4)).await.unwrap();
        assert_eq!(anchored.backend, "csv-seal.local.v1");
    }
}
