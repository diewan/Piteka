//! Persistence ports. Adapters (in-memory, filesystem, Postgres) implement these.

use async_trait::async_trait;

use crate::digest::ContentDigest;
use crate::error::StorageResult;
use crate::model::{
    AuditEvent, CasOutcome, EvidenceDescriptor, MandateProjection, ProtocolObjectRecord,
    WebhookReceipt, WebhookRecordOutcome,
};

/// Immutable, id-addressed storage for canonical Parwana objects.
#[async_trait]
pub trait ProtocolObjectStore: Send + Sync {
    /// Stores a canonical object.
    ///
    /// Storing the same id with identical bytes is idempotent. Storing an
    /// existing id with different bytes is an [`crate::StorageError::ImmutableViolation`].
    ///
    /// # Errors
    ///
    /// Returns an error on an immutability violation or a backend failure.
    async fn put(&self, record: ProtocolObjectRecord) -> StorageResult<()>;

    /// Fetches a canonical object by id.
    ///
    /// # Errors
    ///
    /// Returns a backend error on failure.
    async fn get(&self, object_id_hex: &str) -> StorageResult<Option<ProtocolObjectRecord>>;
}

/// Live mandate projection storage with optimistic-concurrency CAS.
#[async_trait]
pub trait MandateProjectionStore: Send + Sync {
    /// Inserts a new projection at version 1.
    ///
    /// # Errors
    ///
    /// Returns a backend error, including when the mandate already exists.
    async fn insert(&self, mandate_id_hex: &str, state: &str) -> StorageResult<()>;

    /// Fetches the current projection.
    ///
    /// # Errors
    ///
    /// Returns a backend error on failure.
    async fn get(&self, mandate_id_hex: &str) -> StorageResult<Option<MandateProjection>>;

    /// Applies a new state only if the stored version equals `expected_version`.
    ///
    /// Exactly one concurrent caller with the same `expected_version` can win.
    ///
    /// # Errors
    ///
    /// Returns a backend error on failure.
    async fn compare_and_swap(
        &self,
        mandate_id_hex: &str,
        expected_version: i64,
        new_state: &str,
    ) -> StorageResult<CasOutcome>;
}

/// Idempotent webhook delivery storage keyed by unique delivery id.
#[async_trait]
pub trait WebhookReceiptStore: Send + Sync {
    /// Records a delivery once. A repeated delivery id is a no-op duplicate.
    ///
    /// # Errors
    ///
    /// Returns a backend error on failure.
    async fn record(&self, receipt: WebhookReceipt) -> StorageResult<WebhookRecordOutcome>;

    /// Fetches a previously recorded delivery.
    ///
    /// # Errors
    ///
    /// Returns a backend error on failure.
    async fn get(&self, delivery_id: &str) -> StorageResult<Option<WebhookReceipt>>;
}

/// Content-addressed storage for immutable evidence blobs.
#[async_trait]
pub trait EvidenceObjectStore: Send + Sync {
    /// Stores `bytes` and returns their content address. Idempotent.
    ///
    /// # Errors
    ///
    /// Returns a backend error on failure.
    async fn put(&self, bytes: &[u8]) -> StorageResult<ContentDigest>;

    /// Fetches a blob by content address, verifying the returned bytes.
    ///
    /// # Errors
    ///
    /// Returns [`crate::StorageError::EvidenceDigestMismatch`] when stored bytes
    /// do not match the requested address, or a backend error on failure.
    async fn get(&self, digest: &ContentDigest) -> StorageResult<Option<Vec<u8>>>;

    /// Records descriptor metadata for a stored blob.
    ///
    /// # Errors
    ///
    /// Returns a backend error on failure.
    async fn put_descriptor(&self, descriptor: EvidenceDescriptor) -> StorageResult<()>;
}

/// Append-only audit event storage.
#[async_trait]
pub trait AuditLog: Send + Sync {
    /// Appends an audit event. Events are never updated or removed.
    ///
    /// # Errors
    ///
    /// Returns a backend error on failure.
    async fn append(&self, event: AuditEvent) -> StorageResult<()>;

    /// Returns recorded events in insertion order (demo aid; bounded by caller).
    ///
    /// # Errors
    ///
    /// Returns a backend error on failure.
    async fn recent(&self, limit: usize) -> StorageResult<Vec<AuditEvent>>;
}
