//! Content addressing for locally stored evidence blobs.
//!
//! This is a Piteka **storage-level** content address (SHA-256 of the bytes). It
//! is not a Parwana object identifier; canonical protocol objects keep their own
//! Parwana-computed ids, which Piteka stores unchanged.

use sha2::{Digest, Sha256};

/// A SHA-256 content address for a stored blob.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ContentDigest([u8; 32]);

impl ContentDigest {
    /// Computes the content address of `bytes`.
    #[must_use]
    pub fn of(bytes: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        Self(hasher.finalize().into())
    }

    /// Wraps raw digest bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The raw digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// The lower-case hex encoding of the digest.
    #[must_use]
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Parses a lower-case hex digest.
    ///
    /// # Errors
    ///
    /// Returns `None` when `value` is not 64 lower-case hex characters.
    #[must_use]
    pub fn from_hex(value: &str) -> Option<Self> {
        if value.len() != 64
            || !value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return None;
        }
        let mut out = [0u8; 32];
        hex::decode_to_slice(value, &mut out).ok()?;
        Some(Self(out))
    }
}

impl core::fmt::Debug for ContentDigest {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "ContentDigest({})", self.to_hex())
    }
}
