//! Storage error type shared by every adapter.

use crate::digest::ContentDigest;

/// A persistence failure. Every variant is a hard, fail-closed error.
#[derive(Debug)]
pub enum StorageError {
    /// A protocol object with this id already exists with different bytes.
    ///
    /// Canonical Parwana objects are immutable blobs addressed by id; rewriting
    /// one with different content is always rejected.
    ImmutableViolation {
        /// The object identifier (lower-case hex).
        object_id_hex: String,
    },
    /// A stored evidence blob did not match its content address on read.
    EvidenceDigestMismatch {
        /// The address requested.
        expected: ContentDigest,
        /// The digest actually computed from the stored bytes.
        found: ContentDigest,
    },
    /// A required field was empty.
    EmptyField(&'static str),
    /// A backend (I/O or database) failure with a human-readable message.
    Backend(String),
}

impl core::fmt::Display for StorageError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::ImmutableViolation { object_id_hex } => write!(
                f,
                "protocol object `{object_id_hex}` already stored with different bytes"
            ),
            Self::EvidenceDigestMismatch { expected, found } => write!(
                f,
                "evidence content address mismatch: expected {}, found {}",
                expected.to_hex(),
                found.to_hex()
            ),
            Self::EmptyField(field) => write!(f, "storage field `{field}` must not be empty"),
            Self::Backend(message) => write!(f, "storage backend error: {message}"),
        }
    }
}

impl std::error::Error for StorageError {}

impl From<std::io::Error> for StorageError {
    fn from(error: std::io::Error) -> Self {
        Self::Backend(error.to_string())
    }
}

/// Convenience result alias for storage operations.
pub type StorageResult<T> = Result<T, StorageError>;
