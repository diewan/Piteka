//! Independent single-use anchoring port (Master Plan §5.9).
//!
//! An anchor backing enforces a mandate's single use *independently* of Piteka's private
//! Postgres reservation: a Single-Use Seal is created when a mandate is issued and consumed
//! exactly once when the mandate is used. The resulting [`ConsumptionProof`] is preserved
//! as corroborating evidence that re-checks offline (it maps to a Parwana
//! `SealConsumptionRecord` in `piteka-parwana`).
//!
//! This port is deliberately dependency-light — plain 32-byte digests, no chain and no
//! Parwana types — so the accountability contract never leaks into the port layer. The
//! concrete backing (a local seal store first, an on-chain CSVSeal later) lives in
//! `piteka-infra` and runs off the dispatch hot path.

use async_trait::async_trait;

/// A 32-byte digest used for seal ids, nullifiers, and commitments.
pub type Digest32 = [u8; 32];

/// Stable identifier of the local seal backing.
pub const LOCAL_SEAL_BACKEND: &str = "csv-seal.local.v1";

/// An opaque, backend-defined reference to an anchored commitment or created seal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnchorRef {
    /// Stable identifier of the backing that produced this reference.
    pub backend: String,
    /// Backend-defined reference bytes (for example a seal id or an anchor locator).
    pub reference: Vec<u8>,
}

/// Preserved proof that exactly one seal was consumed for a mandate.
///
/// Structurally mirrors a Parwana `SealConsumptionRecord`: `nullifier` is the mandate's
/// reservation-token digest and `commitment` is the authorized intent id.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConsumptionProof {
    /// Identifier of the consumed single-use seal.
    pub seal_id: Digest32,
    /// Consumption nullifier (the mandate's reservation-token digest).
    pub nullifier: Digest32,
    /// Commitment the seal bound at issue (the authorized intent id).
    pub commitment: Digest32,
    /// Stable identifier of the backing that produced this proof.
    pub backend: String,
}

/// A failure from the anchoring backing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AnchorError {
    /// No seal exists for the requested seal id.
    SealNotFound,
    /// The seal was already consumed by a different nullifier (double use).
    SealAlreadyConsumed,
    /// The consumption commitment does not match the seal's committed value.
    CommitmentMismatch,
    /// A seal id collided with an existing, differently-committed seal.
    SealAlreadyExists,
    /// The backing rejected the operation for a backend-specific reason.
    Backend(String),
}

/// Independent single-use anchoring, run off the dispatch hot path (§5.9).
///
/// The Postgres compare-and-swap stays the authoritative liveness reservation; the seal is
/// independent corroboration written asynchronously around it, never in the provider
/// dispatch path.
#[async_trait]
pub trait AnchorPort: Send + Sync {
    /// Creates a single-use seal binding `commitment`, at mandate issue.
    async fn create_seal(
        &self,
        seal_id: Digest32,
        commitment: Digest32,
    ) -> Result<AnchorRef, AnchorError>;

    /// Consumes the seal exactly once with `nullifier`, at mandate use.
    ///
    /// Consuming a seal a second time with the *same* nullifier is idempotent and returns
    /// the same proof; a second consumption with a *different* nullifier fails closed as a
    /// double use.
    async fn consume_seal(
        &self,
        seal_id: Digest32,
        nullifier: Digest32,
    ) -> Result<ConsumptionProof, AnchorError>;

    /// Anchors a bundle digest as an external commitment, at bundle export.
    async fn anchor_commitment(&self, bundle_digest: Digest32) -> Result<AnchorRef, AnchorError>;
}
