//! Local deterministic on-chain anchoring adapter (ANCHOR-01, §5.9).
//!
//! [`LocalChainAnchor`] is an in-process backing for [`ChainAnchorPort`], used as
//! the deterministic stand-in for a real chain adapter until a live RPC backing
//! is configured behind the same trait. Anchoring a commitment records it as
//! *pending*; each finality read advances the confirmation depth by a fixed step
//! until it reaches the reorg-safe requirement, so a test can drive the
//! pending → final transition without a live chain. It never fabricates
//! finality: the confirmation depth only ever advances, and finality is derived
//! from it, never asserted directly.
//!
//! It is intended to run off the dispatch hot path, never in the provider
//! dispatch call.

use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;
use piteka_ports::anchor::{AnchorError, Digest32};
use piteka_ports::chain_anchor::{ChainAnchorPort, ChainAnchorRecord};

/// Stable identifier of the local deterministic chain-anchor backing.
pub const LOCAL_CHAIN_ANCHOR_BACKEND: &str = "chain.local.v1";

/// Confirmations gained per finality read.
const CONFIRMATIONS_PER_READ: u64 = 4;
/// Reorg-safe confirmations required before an anchor is final.
const REQUIRED_CONFIRMATIONS: u64 = 12;

#[derive(Clone, Debug)]
struct AnchorState {
    record: ChainAnchorRecord,
}

/// In-process deterministic chain-anchor store implementing [`ChainAnchorPort`].
#[derive(Default)]
pub struct LocalChainAnchor {
    anchors: Mutex<HashMap<Vec<u8>, AnchorState>>,
}

impl LocalChainAnchor {
    /// Creates an empty local chain-anchor store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Derives a deterministic anchor reference and block hash from the
    /// commitment and chain id, so the same commitment always anchors to the
    /// same reference.
    fn derive(commitment: Digest32, chain_id: &str) -> (Vec<u8>, Digest32) {
        // A simple, stable derivation — this is a deterministic stand-in, not a
        // real chain, so it needs to be reproducible rather than cryptographic.
        let mut anchor_ref = Vec::with_capacity(chain_id.len() + 8);
        anchor_ref.extend_from_slice(chain_id.as_bytes());
        anchor_ref.extend_from_slice(&commitment[..8]);
        let mut block_hash = commitment;
        for (i, byte) in chain_id.bytes().enumerate() {
            block_hash[i % 32] ^= byte;
        }
        // A non-zero block hash is required by the protocol validator.
        if block_hash == [0u8; 32] {
            block_hash[0] = 1;
        }
        (anchor_ref, block_hash)
    }
}

#[async_trait]
impl ChainAnchorPort for LocalChainAnchor {
    async fn anchor_commitment_on_chain(
        &self,
        commitment: Digest32,
        chain_id: &str,
    ) -> Result<ChainAnchorRecord, AnchorError> {
        if chain_id.is_empty() {
            return Err(AnchorError::Backend("empty chain id".to_string()));
        }
        let (anchor_ref, block_hash) = Self::derive(commitment, chain_id);
        let record = ChainAnchorRecord {
            commitment,
            chain_id: chain_id.to_string(),
            anchor_ref: anchor_ref.clone(),
            block_height: 1,
            block_hash,
            // A freshly anchored commitment starts pending: zero confirmations.
            observed_confirmations: 0,
            required_confirmations: REQUIRED_CONFIRMATIONS,
            backend: LOCAL_CHAIN_ANCHOR_BACKEND.to_string(),
        };
        let mut anchors = self.anchors.lock().expect("anchor store lock");
        // Anchoring the same commitment again returns the existing record.
        let state = anchors
            .entry(anchor_ref)
            .or_insert_with(|| AnchorState {
                record: record.clone(),
            });
        Ok(state.record.clone())
    }

    async fn read_finality(
        &self,
        record: &ChainAnchorRecord,
    ) -> Result<ChainAnchorRecord, AnchorError> {
        let mut anchors = self.anchors.lock().expect("anchor store lock");
        let state = anchors
            .get_mut(&record.anchor_ref)
            .ok_or(AnchorError::SealNotFound)?;
        // Advance confirmations monotonically toward the requirement; the depth
        // never decreases, so finality (derived from it) is never withdrawn.
        state.record.observed_confirmations = state
            .record
            .observed_confirmations
            .saturating_add(CONFIRMATIONS_PER_READ)
            .min(state.record.required_confirmations);
        state.record.block_height = state.record.block_height.saturating_add(1);
        Ok(state.record.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn anchor_starts_pending_and_reads_advance_to_final() {
        let adapter = LocalChainAnchor::new();
        let commitment = [0x11u8; 32];

        let anchored = adapter
            .anchor_commitment_on_chain(commitment, "ethereum-sepolia")
            .await
            .unwrap();
        assert!(!anchored.is_final(), "fresh anchor is pending");
        assert_eq!(anchored.observed_confirmations, 0);

        // Repeated reads advance confirmations until final; depth never exceeds
        // the requirement and never decreases.
        let mut current = anchored;
        let mut last_depth = 0;
        for _ in 0..5 {
            current = adapter.read_finality(&current).await.unwrap();
            assert!(current.observed_confirmations >= last_depth);
            last_depth = current.observed_confirmations;
        }
        assert!(current.is_final(), "reads reach reorg-safe finality");
        assert_eq!(current.observed_confirmations, REQUIRED_CONFIRMATIONS);

        // Anchoring the same commitment again returns the existing anchor ref.
        let again = adapter
            .anchor_commitment_on_chain(commitment, "ethereum-sepolia")
            .await
            .unwrap();
        assert_eq!(again.anchor_ref, current.anchor_ref);
    }

    #[tokio::test]
    async fn reading_an_unknown_anchor_fails_closed() {
        let adapter = LocalChainAnchor::new();
        let phantom = ChainAnchorRecord {
            commitment: [1u8; 32],
            chain_id: "ethereum-sepolia".to_string(),
            anchor_ref: vec![9, 9, 9],
            block_height: 1,
            block_hash: [2u8; 32],
            observed_confirmations: 0,
            required_confirmations: 12,
            backend: LOCAL_CHAIN_ANCHOR_BACKEND.to_string(),
        };
        assert_eq!(
            adapter.read_finality(&phantom).await,
            Err(AnchorError::SealNotFound)
        );
    }
}
