//! Bridge from the anchoring port DTOs to the Parwana accountability contract.
//!
//! This is the single place where a [`piteka_ports::anchor::ConsumptionProof`] produced by
//! an [`piteka_ports::anchor::AnchorPort`] backing (for example the local seal store) is
//! mapped to the Parwana [`SealConsumptionRecord`] that a dispute bundle preserves and the
//! reference verifier re-checks offline. Keeping the mapping in the adapter means neither
//! the port layer nor the infrastructure adapters ever depend on a `csv-*` protocol crate.

use piteka_ports::anchor::ConsumptionProof;
use piteka_ports::chain_anchor::ChainAnchorRecord;

use crate::protocol::{AnchorFinality, ChainAnchor, SealConsumptionRecord};

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

/// Maps a port-level on-chain anchor record to the canonical Parwana [`ChainAnchor`]
/// (ANCHOR-01).
///
/// This is the single place a [`ChainAnchorRecord`] produced by a
/// [`piteka_ports::chain_anchor::ChainAnchorPort`] backing is mapped to the
/// canonical protocol value a bundle preserves and an offline verifier
/// re-checks. The finality reading is projected through
/// [`AnchorFinality::from_confirmations`], so the mapping never asserts finality —
/// it is derived from the observed depth against the required depth.
#[must_use]
pub fn chain_anchor_from_record(record: &ChainAnchorRecord) -> ChainAnchor {
    ChainAnchor {
        commitment: record.commitment,
        chain_id: record.chain_id.clone(),
        anchor_ref: record.anchor_ref.clone(),
        block_height: record.block_height,
        block_hash: record.block_hash,
        finality: AnchorFinality::from_confirmations(
            record.observed_confirmations,
            record.required_confirmations,
        ),
        anchor_backend: record.backend.clone(),
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

    /// ANCHOR-01: a port-level chain anchor maps to a canonical `ChainAnchor`
    /// that re-verifies offline from its exact bytes — a pending reading stays
    /// pending, and a final reading assesses as anchored-final for the expected
    /// commitment.
    #[test]
    fn chain_anchor_record_maps_to_a_value_that_reverifies_offline() {
        use crate::protocol::{ChainAnchor, ChainAnchorAssessment};

        let commitment = [0x11u8; 32];
        let pending_record = ChainAnchorRecord {
            commitment,
            chain_id: "ethereum-sepolia".to_string(),
            anchor_ref: vec![0xde, 0xad, 0xbe, 0xef],
            block_height: 1,
            block_hash: [0x22u8; 32],
            observed_confirmations: 3,
            required_confirmations: 12,
            backend: "chain.local.v1".to_string(),
        };

        let anchor = chain_anchor_from_record(&pending_record);
        // Offline re-verification: exact canonical-byte round-trip.
        let bytes = anchor.canonical_bytes().expect("canonical bytes");
        assert_eq!(ChainAnchor::from_canonical_bytes(&bytes).unwrap(), anchor);
        assert_eq!(
            anchor.assess(commitment),
            ChainAnchorAssessment::AnchoredPending
        );

        // Once enough confirmations accrue, the same commitment assesses as final.
        let final_record = ChainAnchorRecord {
            observed_confirmations: 12,
            ..pending_record
        };
        let final_anchor = chain_anchor_from_record(&final_record);
        assert!(final_anchor.finality.is_final());
        assert_eq!(
            final_anchor.assess(commitment),
            ChainAnchorAssessment::AnchoredFinal
        );
        // A different commitment cannot corroborate this object.
        assert_eq!(
            final_anchor.assess([0x99u8; 32]),
            ChainAnchorAssessment::Inconsistent
        );
    }
}
