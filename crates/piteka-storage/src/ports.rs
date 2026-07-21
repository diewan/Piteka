//! Persistence ports. Adapters (in-memory, filesystem, Postgres) implement these.

use async_trait::async_trait;

use crate::digest::ContentDigest;
use crate::error::StorageResult;
use crate::model::{
    ActionRequest, ActionRequestStatus, ApprovalDecision, AuditEvent, CasOutcome,
    EvidenceDescriptor, EvidenceNodeRecord, ExecutionAttempt, MandateProjection,
    ProtocolObjectRecord, ReceiptProjection, SealConsumptionProofRecord, WebhookReceipt,
    WebhookRecordOutcome,
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

/// Immutable, mandate-addressed storage for Single-Use Seal consumption proofs (§5.9).
///
/// The proof is corroborating evidence written off the dispatch hot path; the Postgres
/// mandate CAS remains the authoritative liveness reservation.
#[async_trait]
pub trait SealConsumptionStore: Send + Sync {
    /// Stores a consumption proof for a mandate.
    ///
    /// Storing the same mandate id with an identical proof is idempotent. Storing an
    /// existing mandate id with a different proof is an
    /// [`crate::StorageError::ImmutableViolation`].
    ///
    /// # Errors
    ///
    /// Returns an error on an immutability violation or a backend failure.
    async fn put(&self, record: SealConsumptionProofRecord) -> StorageResult<()>;

    /// Fetches the consumption proof for a mandate, if one was recorded.
    ///
    /// # Errors
    ///
    /// Returns a backend error on failure.
    async fn get(&self, mandate_id_hex: &str) -> StorageResult<Option<SealConsumptionProofRecord>>;
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

/// Storage for structured evidence nodes (Master Plan §10.6).
///
/// Evidence nodes are append-only; each node is keyed by its content address.
#[async_trait]
pub trait EvidenceNodeStore: Send + Sync {
    /// Inserts a new evidence node.
    ///
    /// # Errors
    ///
    /// Returns a backend error if the node id already exists.
    async fn insert(&self, node: EvidenceNodeRecord) -> StorageResult<()>;

    /// Fetches an evidence node by id.
    ///
    /// # Errors
    ///
    /// Returns a backend error on failure.
    async fn get(&self, node_id_hex: &str) -> StorageResult<Option<EvidenceNodeRecord>>;

    /// Returns all evidence nodes for a given mandate id (by scanning node ids
    /// that start with the mandate prefix).
    ///
    /// # Errors
    ///
    /// Returns a backend error on failure.
    async fn by_mandate(&self, mandate_id_hex: &str) -> StorageResult<Vec<EvidenceNodeRecord>>;
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

/// Storage for action requests with optimistic-concurrency CAS on status transitions.
#[async_trait]
pub trait ActionRequestStore: Send + Sync {
    /// Inserts a new action request at version 1.
    ///
    /// # Errors
    ///
    /// Returns a backend error if the request id already exists.
    async fn insert(&self, request: ActionRequest) -> StorageResult<()>;

    /// Fetches an action request by id.
    ///
    /// # Errors
    ///
    /// Returns a backend error on failure.
    async fn get(&self, request_id: &str) -> StorageResult<Option<ActionRequest>>;

    /// Returns all action requests in insertion order (bounded by caller).
    ///
    /// # Errors
    ///
    /// Returns a backend error on failure.
    async fn list(&self) -> StorageResult<Vec<ActionRequest>>;

    /// Applies a new status only if the stored version equals `expected_version`.
    ///
    /// Exactly one concurrent caller with the same `expected_version` can win.
    ///
    /// # Errors
    ///
    /// Returns a backend error on failure.
    async fn compare_and_swap(
        &self,
        request_id: &str,
        expected_version: i64,
        new_status: ActionRequestStatus,
    ) -> StorageResult<CasOutcome>;
}

/// Storage for approval decisions.
#[async_trait]
pub trait ApprovalDecisionStore: Send + Sync {
    /// Inserts a new approval decision.
    ///
    /// # Errors
    ///
    /// Returns a backend error if the decision id already exists.
    async fn insert(&self, decision: ApprovalDecision) -> StorageResult<()>;

    /// Fetches a decision by id.
    ///
    /// # Errors
    ///
    /// Returns a backend error on failure.
    async fn get(&self, decision_id: &str) -> StorageResult<Option<ApprovalDecision>>;

    /// Returns all decisions for a given request id.
    ///
    /// # Errors
    ///
    /// Returns a backend error on failure.
    async fn by_request(&self, request_id: &str) -> StorageResult<Vec<ApprovalDecision>>;
}

/// Storage for execution attempts.
///
/// Each attempt is keyed by a unique `attempt_id_hex`. The store is append-only
/// for new attempts; state transitions are done by updating the existing row.
#[async_trait]
pub trait ExecutionAttemptStore: Send + Sync {
    /// Inserts a new execution attempt at version 1.
    ///
    /// # Errors
    ///
    /// Returns a backend error if the attempt id already exists.
    async fn insert(&self, attempt: ExecutionAttempt) -> StorageResult<()>;

    /// Fetches an execution attempt by id.
    ///
    /// # Errors
    ///
    /// Returns a backend error on failure.
    async fn get(&self, attempt_id_hex: &str) -> StorageResult<Option<ExecutionAttempt>>;

    /// Updates the state of an existing attempt.
    ///
    /// Fails if the attempt does not exist.
    ///
    /// # Errors
    ///
    /// Returns a backend error on failure.
    async fn update_state(
        &self,
        attempt_id_hex: &str,
        new_state: crate::model::ExecutionAttemptState,
    ) -> StorageResult<()>;

    /// Records the GitHub deployment ID after a successful `create_deployment` call.
    ///
    /// E-04: This method is called after the provider dispatch succeeds. It
    /// records the GitHub-assigned deployment ID so that incoming webhooks
    /// can be correlated to the correct execution attempt.
    ///
    /// Fails if the attempt does not exist.
    ///
    /// # Errors
    ///
    /// Returns a backend error on failure.
    async fn update_deployment_id(
        &self,
        attempt_id_hex: &str,
        deployment_id: u64,
    ) -> StorageResult<()>;

    /// Returns all attempts for a given mandate id.
    ///
    /// # Errors
    ///
    /// Returns a backend error on failure.
    async fn by_mandate(&self, mandate_id_hex: &str) -> StorageResult<Vec<ExecutionAttempt>>;

    /// Finds an execution attempt by its GitHub deployment ID.
    ///
    /// E-06: Used by the webhook processor to match incoming deployment-status
    /// webhooks to the correct execution attempt.
    ///
    /// # Errors
    ///
    /// Returns a backend error on failure.
    async fn by_deployment_id(&self, deployment_id: u64)
    -> StorageResult<Option<ExecutionAttempt>>;
}

/// Storage for receipt projections.
///
/// Receipts are append-only; each receipt is keyed by a unique `receipt_id_hex`.
#[async_trait]
pub trait ReceiptProjectionStore: Send + Sync {
    /// Inserts a new receipt projection.
    ///
    /// # Errors
    ///
    /// Returns a backend error if the receipt id already exists.
    async fn insert(&self, receipt: ReceiptProjection) -> StorageResult<()>;

    /// Fetches a receipt by id.
    ///
    /// # Errors
    ///
    /// Returns a backend error on failure.
    async fn get(&self, receipt_id_hex: &str) -> StorageResult<Option<ReceiptProjection>>;

    /// Returns all receipts for a given mandate id.
    ///
    /// # Errors
    ///
    /// Returns a backend error on failure.
    async fn by_mandate(&self, mandate_id_hex: &str) -> StorageResult<Vec<ReceiptProjection>>;
}
