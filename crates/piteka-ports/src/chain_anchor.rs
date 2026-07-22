//! On-chain commitment anchoring, run off the dispatch hot path (ANCHOR-01, §5.9).
//!
//! [`ChainAnchorPort`] produces and reads back an on-chain anchor for an
//! accountability commitment. It is dependency-light: the Parwana
//! `ChainAnchor` value type is mapped from [`ChainAnchorRecord`] in
//! `piteka-parwana`, so this crate stays free of the protocol SDK. Like seal
//! anchoring, it runs asynchronously around the authoritative Postgres
//! reservation, never inside the provider dispatch call, and the real on-chain
//! adapter is selectable behind the same trait.

use async_trait::async_trait;

use crate::anchor::{AnchorError, Digest32};

/// A backend-neutral projection of an on-chain commitment anchor and its
/// finality reading. Maps 1:1 to a Parwana `ChainAnchor`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainAnchorRecord {
    /// The anchored commitment digest.
    pub commitment: Digest32,
    /// Canonical chain identifier (for example `ethereum-sepolia`).
    pub chain_id: String,
    /// Opaque, backend-defined anchor reference (for example a txid).
    pub anchor_ref: Vec<u8>,
    /// Height of the including block.
    pub block_height: u64,
    /// Hash of the including block, used to detect reorgs across reads.
    pub block_hash: Digest32,
    /// Confirmations observed so far.
    pub observed_confirmations: u64,
    /// Reorg-safe confirmations required before the anchor is final.
    pub required_confirmations: u64,
    /// Stable identifier of the backing that produced this record.
    pub backend: String,
}

impl ChainAnchorRecord {
    /// Whether the reading has reached reorg-safe finality.
    #[must_use]
    pub fn is_final(&self) -> bool {
        self.required_confirmations > 0 && self.observed_confirmations >= self.required_confirmations
    }
}

/// On-chain commitment anchoring behind a port, off the dispatch hot path.
#[async_trait]
pub trait ChainAnchorPort: Send + Sync {
    /// Anchors `commitment` on `chain_id`, returning the initial (typically
    /// pending) anchor record.
    async fn anchor_commitment_on_chain(
        &self,
        commitment: Digest32,
        chain_id: &str,
    ) -> Result<ChainAnchorRecord, AnchorError>;

    /// Re-reads finality for a previously produced anchor. The returned record
    /// carries the current confirmation depth (and block hash, which changes on a
    /// reorg).
    async fn read_finality(
        &self,
        record: &ChainAnchorRecord,
    ) -> Result<ChainAnchorRecord, AnchorError>;
}
