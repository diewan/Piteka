//! Bridge from the anchoring port DTOs to the Parwana accountability contract.
//!
//! This is the single place where a [`piteka_ports::anchor::ConsumptionProof`] produced by
//! an [`piteka_ports::anchor::AnchorPort`] backing (for example the local seal store) is
//! mapped to the Parwana [`SealConsumptionRecord`] that a dispute bundle preserves and the
//! reference verifier re-checks offline. Keeping the mapping in the adapter means neither
//! the port layer nor the infrastructure adapters ever depend on a `csv-*` protocol crate.

use piteka_ports::anchor::ConsumptionProof;

use crate::protocol::SealConsumptionRecord;

/// Maps a port-level consumption proof to the canonical Parwana consumption record.
///
/// The record binds the same nullifier (the mandate's reservation-token digest) and
/// commitment (the authorized intent id) the seal enforced, so an independent verifier can
/// re-check single use from bundle bytes alone.
#[must_use]
pub fn consumption_record_from_proof(proof: &ConsumptionProof) -> SealConsumptionRecord {
    SealConsumptionRecord {
        seal_id: proof.seal_id,
        nullifier: proof.nullifier,
        commitment: proof.commitment,
        anchor_backend: proof.backend.clone(),
    }
}

#[cfg(test)]
mod tests {
    use piteka_ports::anchor::{ConsumptionProof, LOCAL_SEAL_BACKEND};

    use super::*;
    use crate::protocol::SingleUseAnchorAssessment;

    /// The full Phase-B loop across the repo boundary: a port consumption proof maps to a
    /// canonical record that re-checks offline as independent single-use enforcement when
    /// it binds the mandate's reservation-token digest (nullifier) and intent id
    /// (commitment).
    #[test]
    fn port_proof_maps_to_a_record_that_corroborates_single_use_offline() {
        let reservation_token_digest = [12u8; 32];
        let intent_id = [7u8; 32];
        let proof = ConsumptionProof {
            seal_id: [42u8; 32],
            nullifier: reservation_token_digest,
            commitment: intent_id,
            backend: LOCAL_SEAL_BACKEND.to_string(),
        };

        let record = consumption_record_from_proof(&proof);
        record.validate().expect("record is well-formed");
        assert_eq!(record.anchor_backend, LOCAL_SEAL_BACKEND);

        // Re-check offline against the mandate's expected nullifier and commitment.
        assert_eq!(
            record.assess(reservation_token_digest, intent_id),
            SingleUseAnchorAssessment::IndependentlyEnforced
        );
        // A different reservation token no longer corroborates this mandate.
        assert_eq!(
            record.assess([9u8; 32], intent_id),
            SingleUseAnchorAssessment::Inconsistent
        );
    }
}
