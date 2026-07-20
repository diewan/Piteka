//! In-memory adapters.
//!
//! These are honest reference implementations that enforce the same immutability,
//! CAS, uniqueness, and append-only rules as the Postgres adapters. They back the
//! default test suite and single-process demos; they are not durable storage.

use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;

use crate::digest::ContentDigest;
use crate::error::{StorageError, StorageResult};
use crate::model::{
    ActionRequest, ActionRequestStatus, ApprovalDecision, AuditEvent, CasOutcome,
    EvidenceDescriptor, EvidenceNodeRecord, ExecutionAttempt, ExecutionAttemptState,
    MandateProjection, ProtocolObjectRecord, ReceiptProjection, WebhookReceipt,
    WebhookRecordOutcome,
};
use crate::ports::{
    ActionRequestStore, ApprovalDecisionStore, AuditLog, EvidenceNodeStore, EvidenceObjectStore,
    ExecutionAttemptStore, MandateProjectionStore, ProtocolObjectStore, ReceiptProjectionStore,
    WebhookReceiptStore,
};

/// In-memory immutable protocol-object store.
#[derive(Default)]
pub struct InMemoryProtocolObjectStore {
    objects: Mutex<HashMap<String, ProtocolObjectRecord>>,
}

#[async_trait]
impl ProtocolObjectStore for InMemoryProtocolObjectStore {
    async fn put(&self, record: ProtocolObjectRecord) -> StorageResult<()> {
        if record.object_id_hex.is_empty() {
            return Err(StorageError::EmptyField("object_id_hex"));
        }
        let mut objects = self.objects.lock().expect("lock poisoned");
        if let Some(existing) = objects.get(&record.object_id_hex) {
            if existing.bytes != record.bytes {
                return Err(StorageError::ImmutableViolation {
                    object_id_hex: record.object_id_hex,
                });
            }
            return Ok(());
        }
        objects.insert(record.object_id_hex.clone(), record);
        Ok(())
    }

    async fn get(&self, object_id_hex: &str) -> StorageResult<Option<ProtocolObjectRecord>> {
        Ok(self
            .objects
            .lock()
            .expect("lock poisoned")
            .get(object_id_hex)
            .cloned())
    }
}

/// In-memory mandate projection store with version CAS.
#[derive(Default)]
pub struct InMemoryMandateProjectionStore {
    projections: Mutex<HashMap<String, MandateProjection>>,
}

#[async_trait]
impl MandateProjectionStore for InMemoryMandateProjectionStore {
    async fn insert(&self, mandate_id_hex: &str, state: &str) -> StorageResult<()> {
        if mandate_id_hex.is_empty() {
            return Err(StorageError::EmptyField("mandate_id_hex"));
        }
        let mut projections = self.projections.lock().expect("lock poisoned");
        if projections.contains_key(mandate_id_hex) {
            return Err(StorageError::Backend(format!(
                "mandate projection `{mandate_id_hex}` already exists"
            )));
        }
        projections.insert(
            mandate_id_hex.to_string(),
            MandateProjection {
                mandate_id_hex: mandate_id_hex.to_string(),
                version: 1,
                state: state.to_string(),
            },
        );
        Ok(())
    }

    async fn get(&self, mandate_id_hex: &str) -> StorageResult<Option<MandateProjection>> {
        Ok(self
            .projections
            .lock()
            .expect("lock poisoned")
            .get(mandate_id_hex)
            .cloned())
    }

    async fn compare_and_swap(
        &self,
        mandate_id_hex: &str,
        expected_version: i64,
        new_state: &str,
    ) -> StorageResult<CasOutcome> {
        let mut projections = self.projections.lock().expect("lock poisoned");
        let Some(projection) = projections.get_mut(mandate_id_hex) else {
            return Ok(CasOutcome::Missing);
        };
        if projection.version != expected_version {
            return Ok(CasOutcome::Conflict {
                current_version: projection.version,
            });
        }
        projection.version += 1;
        projection.state = new_state.to_string();
        Ok(CasOutcome::Applied {
            new_version: projection.version,
        })
    }
}

/// In-memory webhook receipt store keyed by unique delivery id.
#[derive(Default)]
pub struct InMemoryWebhookReceiptStore {
    receipts: Mutex<HashMap<String, WebhookReceipt>>,
}

#[async_trait]
impl WebhookReceiptStore for InMemoryWebhookReceiptStore {
    async fn record(&self, receipt: WebhookReceipt) -> StorageResult<WebhookRecordOutcome> {
        if receipt.delivery_id.is_empty() {
            return Err(StorageError::EmptyField("delivery_id"));
        }
        let mut receipts = self.receipts.lock().expect("lock poisoned");
        if receipts.contains_key(&receipt.delivery_id) {
            return Ok(WebhookRecordOutcome::Duplicate);
        }
        receipts.insert(receipt.delivery_id.clone(), receipt);
        Ok(WebhookRecordOutcome::Recorded)
    }

    async fn get(&self, delivery_id: &str) -> StorageResult<Option<WebhookReceipt>> {
        Ok(self
            .receipts
            .lock()
            .expect("lock poisoned")
            .get(delivery_id)
            .cloned())
    }
}

/// In-memory content-addressed evidence store.
#[derive(Default)]
pub struct InMemoryEvidenceStore {
    blobs: Mutex<HashMap<[u8; 32], Vec<u8>>>,
    descriptors: Mutex<HashMap<[u8; 32], EvidenceDescriptor>>,
}

#[async_trait]
impl EvidenceObjectStore for InMemoryEvidenceStore {
    async fn put(&self, bytes: &[u8]) -> StorageResult<ContentDigest> {
        let digest = ContentDigest::of(bytes);
        self.blobs
            .lock()
            .expect("lock poisoned")
            .entry(*digest.as_bytes())
            .or_insert_with(|| bytes.to_vec());
        Ok(digest)
    }

    async fn get(&self, digest: &ContentDigest) -> StorageResult<Option<Vec<u8>>> {
        let Some(bytes) = self
            .blobs
            .lock()
            .expect("lock poisoned")
            .get(digest.as_bytes())
            .cloned()
        else {
            return Ok(None);
        };
        let found = ContentDigest::of(&bytes);
        if &found != digest {
            return Err(StorageError::EvidenceDigestMismatch {
                expected: *digest,
                found,
            });
        }
        Ok(Some(bytes))
    }

    async fn put_descriptor(&self, descriptor: EvidenceDescriptor) -> StorageResult<()> {
        self.descriptors
            .lock()
            .expect("lock poisoned")
            .insert(*descriptor.digest.as_bytes(), descriptor);
        Ok(())
    }
}

/// In-memory structured evidence node store.
#[derive(Default)]
pub struct InMemoryEvidenceNodeStore {
    nodes: Mutex<HashMap<String, EvidenceNodeRecord>>,
    by_mandate: Mutex<HashMap<String, Vec<String>>>,
}

#[async_trait]
impl EvidenceNodeStore for InMemoryEvidenceNodeStore {
    async fn insert(&self, node: EvidenceNodeRecord) -> StorageResult<()> {
        if node.node_id_hex.is_empty() {
            return Err(StorageError::EmptyField("node_id_hex"));
        }
        let mut nodes = self.nodes.lock().expect("lock poisoned");
        if nodes.contains_key(&node.node_id_hex) {
            return Err(StorageError::Backend(format!(
                "evidence node `{}` already exists",
                node.node_id_hex
            )));
        }
        nodes.insert(node.node_id_hex.clone(), node.clone());
        // Index by mandate prefix (nodes are stored with "ev-<mandate_id_hex>-..." prefix)
        for mandate_id in MANDATE_PREFIXES {
            if node.node_id_hex.starts_with(mandate_id) {
                self.by_mandate
                    .lock()
                    .expect("lock poisoned")
                    .entry(mandate_id.to_string())
                    .or_default()
                    .push(node.node_id_hex.clone());
                break;
            }
        }
        Ok(())
    }

    async fn get(&self, node_id_hex: &str) -> StorageResult<Option<EvidenceNodeRecord>> {
        Ok(self
            .nodes
            .lock()
            .expect("lock poisoned")
            .get(node_id_hex)
            .cloned())
    }

    async fn by_mandate(&self, mandate_id_hex: &str) -> StorageResult<Vec<EvidenceNodeRecord>> {
        let nodes = self.nodes.lock().expect("lock poisoned");
        if mandate_id_hex.is_empty() {
            Ok(nodes.values().cloned().collect())
        } else {
            let ids = self
                .by_mandate
                .lock()
                .expect("lock poisoned")
                .get(mandate_id_hex)
                .cloned()
                .unwrap_or_default();
            Ok(ids.iter().filter_map(|id| nodes.get(id).cloned()).collect())
        }
    }
}

/// Prefixes used to index evidence nodes by mandate.
const MANDATE_PREFIXES: &[&str] = &["mand-"];

/// In-memory append-only audit log.
#[derive(Default)]
pub struct InMemoryAuditLog {
    events: Mutex<Vec<AuditEvent>>,
}

#[async_trait]
impl AuditLog for InMemoryAuditLog {
    async fn append(&self, event: AuditEvent) -> StorageResult<()> {
        self.events.lock().expect("lock poisoned").push(event);
        Ok(())
    }

    async fn recent(&self, limit: usize) -> StorageResult<Vec<AuditEvent>> {
        let events = self.events.lock().expect("lock poisoned");
        let start = events.len().saturating_sub(limit);
        Ok(events[start..].to_vec())
    }
}

/// In-memory action request store with version CAS.
#[derive(Default)]
pub struct InMemoryActionRequestStore {
    requests: Mutex<HashMap<String, ActionRequest>>,
    versions: Mutex<HashMap<String, i64>>,
}

#[async_trait]
impl ActionRequestStore for InMemoryActionRequestStore {
    async fn insert(&self, request: ActionRequest) -> StorageResult<()> {
        if request.request_id.is_empty() {
            return Err(StorageError::EmptyField("request_id"));
        }
        let mut requests = self.requests.lock().expect("lock poisoned");
        if requests.contains_key(&request.request_id) {
            return Err(StorageError::Backend(format!(
                "action request `{}` already exists",
                request.request_id
            )));
        }
        requests.insert(request.request_id.clone(), request);
        Ok(())
    }

    async fn get(&self, request_id: &str) -> StorageResult<Option<ActionRequest>> {
        Ok(self
            .requests
            .lock()
            .expect("lock poisoned")
            .get(request_id)
            .cloned())
    }

    async fn list(&self) -> StorageResult<Vec<ActionRequest>> {
        let requests = self.requests.lock().expect("lock poisoned");
        Ok(requests.values().cloned().collect())
    }

    async fn compare_and_swap(
        &self,
        request_id: &str,
        expected_version: i64,
        new_status: ActionRequestStatus,
    ) -> StorageResult<CasOutcome> {
        let mut requests = self.requests.lock().expect("lock poisoned");
        let mut versions = self.versions.lock().expect("lock poisoned");
        let Some(request) = requests.get_mut(request_id) else {
            return Ok(CasOutcome::Missing);
        };
        let current_version = versions.get(request_id).copied().unwrap_or(1);
        if current_version != expected_version {
            return Ok(CasOutcome::Conflict { current_version });
        }
        let new_version = current_version + 1;
        versions.insert(request_id.to_string(), new_version);
        request.status = new_status;
        Ok(CasOutcome::Applied { new_version })
    }
}

/// In-memory approval decision store.
#[derive(Default)]
pub struct InMemoryApprovalDecisionStore {
    decisions: Mutex<HashMap<String, ApprovalDecision>>,
    by_request: Mutex<HashMap<String, Vec<String>>>,
}

#[async_trait]
impl ApprovalDecisionStore for InMemoryApprovalDecisionStore {
    async fn insert(&self, decision: ApprovalDecision) -> StorageResult<()> {
        if decision.decision_id.is_empty() {
            return Err(StorageError::EmptyField("decision_id"));
        }
        let mut decisions = self.decisions.lock().expect("lock poisoned");
        if decisions.contains_key(&decision.decision_id) {
            return Err(StorageError::Backend(format!(
                "approval decision `{}` already exists",
                decision.decision_id
            )));
        }
        decisions.insert(decision.decision_id.clone(), decision.clone());
        self.by_request
            .lock()
            .expect("lock poisoned")
            .entry(decision.request_id)
            .or_default()
            .push(decision.decision_id);
        Ok(())
    }

    async fn get(&self, decision_id: &str) -> StorageResult<Option<ApprovalDecision>> {
        Ok(self
            .decisions
            .lock()
            .expect("lock poisoned")
            .get(decision_id)
            .cloned())
    }

    async fn by_request(&self, request_id: &str) -> StorageResult<Vec<ApprovalDecision>> {
        let decisions = self.decisions.lock().expect("lock poisoned");
        let ids = self
            .by_request
            .lock()
            .expect("lock poisoned")
            .get(request_id)
            .cloned()
            .unwrap_or_default();
        Ok(ids
            .iter()
            .filter_map(|id| decisions.get(id).cloned())
            .collect())
    }
}

/// In-memory execution attempt store.
#[derive(Default)]
pub struct InMemoryExecutionAttemptStore {
    attempts: Mutex<HashMap<String, ExecutionAttempt>>,
    by_mandate: Mutex<HashMap<String, Vec<String>>>,
}

#[async_trait]
impl ExecutionAttemptStore for InMemoryExecutionAttemptStore {
    async fn insert(&self, attempt: ExecutionAttempt) -> StorageResult<()> {
        if attempt.attempt_id_hex.is_empty() {
            return Err(StorageError::EmptyField("attempt_id_hex"));
        }
        let mut attempts = self.attempts.lock().expect("lock poisoned");
        if attempts.contains_key(&attempt.attempt_id_hex) {
            return Err(StorageError::Backend(format!(
                "execution attempt `{}` already exists",
                attempt.attempt_id_hex
            )));
        }
        attempts.insert(attempt.attempt_id_hex.clone(), attempt.clone());
        self.by_mandate
            .lock()
            .expect("lock poisoned")
            .entry(attempt.mandate_id_hex.clone())
            .or_default()
            .push(attempt.attempt_id_hex);
        Ok(())
    }

    async fn get(&self, attempt_id_hex: &str) -> StorageResult<Option<ExecutionAttempt>> {
        Ok(self
            .attempts
            .lock()
            .expect("lock poisoned")
            .get(attempt_id_hex)
            .cloned())
    }

    async fn update_state(
        &self,
        attempt_id_hex: &str,
        new_state: ExecutionAttemptState,
    ) -> StorageResult<()> {
        let mut attempts = self.attempts.lock().expect("lock poisoned");
        let Some(attempt) = attempts.get_mut(attempt_id_hex) else {
            return Err(StorageError::Backend(format!(
                "execution attempt `{attempt_id_hex}` not found"
            )));
        };
        attempt.state = new_state;
        Ok(())
    }

    async fn update_deployment_id(
        &self,
        attempt_id_hex: &str,
        deployment_id: u64,
    ) -> StorageResult<()> {
        let mut attempts = self.attempts.lock().expect("lock poisoned");
        let Some(attempt) = attempts.get_mut(attempt_id_hex) else {
            return Err(StorageError::Backend(format!(
                "execution attempt `{attempt_id_hex}` not found"
            )));
        };
        attempt.github_deployment_id = Some(deployment_id);
        Ok(())
    }

    async fn by_mandate(&self, mandate_id_hex: &str) -> StorageResult<Vec<ExecutionAttempt>> {
        let attempts = self.attempts.lock().expect("lock poisoned");
        let ids = self
            .by_mandate
            .lock()
            .expect("lock poisoned")
            .get(mandate_id_hex)
            .cloned()
            .unwrap_or_default();
        Ok(ids
            .iter()
            .filter_map(|id| attempts.get(id).cloned())
            .collect())
    }

    async fn by_deployment_id(
        &self,
        deployment_id: u64,
    ) -> StorageResult<Option<ExecutionAttempt>> {
        let attempts = self.attempts.lock().expect("lock poisoned");
        Ok(attempts
            .values()
            .find(|a| a.github_deployment_id == Some(deployment_id))
            .cloned())
    }
}

/// In-memory receipt projection store.
#[derive(Default)]
pub struct InMemoryReceiptProjectionStore {
    receipts: Mutex<HashMap<String, ReceiptProjection>>,
    by_mandate: Mutex<HashMap<String, Vec<String>>>,
}

#[async_trait]
impl ReceiptProjectionStore for InMemoryReceiptProjectionStore {
    async fn insert(&self, receipt: ReceiptProjection) -> StorageResult<()> {
        if receipt.receipt_id_hex.is_empty() {
            return Err(StorageError::EmptyField("receipt_id_hex"));
        }
        let mut receipts = self.receipts.lock().expect("lock poisoned");
        if receipts.contains_key(&receipt.receipt_id_hex) {
            return Err(StorageError::Backend(format!(
                "receipt projection `{}` already exists",
                receipt.receipt_id_hex
            )));
        }
        receipts.insert(receipt.receipt_id_hex.clone(), receipt.clone());
        self.by_mandate
            .lock()
            .expect("lock poisoned")
            .entry(receipt.mandate_id_hex.clone())
            .or_default()
            .push(receipt.receipt_id_hex);
        Ok(())
    }

    async fn get(&self, receipt_id_hex: &str) -> StorageResult<Option<ReceiptProjection>> {
        Ok(self
            .receipts
            .lock()
            .expect("lock poisoned")
            .get(receipt_id_hex)
            .cloned())
    }

    async fn by_mandate(&self, mandate_id_hex: &str) -> StorageResult<Vec<ReceiptProjection>> {
        let receipts = self.receipts.lock().expect("lock poisoned");
        let ids = self
            .by_mandate
            .lock()
            .expect("lock poisoned")
            .get(mandate_id_hex)
            .cloned()
            .unwrap_or_default();
        Ok(ids
            .iter()
            .filter_map(|id| receipts.get(id).cloned())
            .collect())
    }
}

// Blanket impl: Arc<T> implements the store traits when T does.
#[async_trait]
impl ActionRequestStore for std::sync::Arc<InMemoryActionRequestStore> {
    async fn insert(&self, request: ActionRequest) -> StorageResult<()> {
        self.as_ref().insert(request).await
    }
    async fn get(&self, request_id: &str) -> StorageResult<Option<ActionRequest>> {
        self.as_ref().get(request_id).await
    }
    async fn list(&self) -> StorageResult<Vec<ActionRequest>> {
        self.as_ref().list().await
    }
    async fn compare_and_swap(
        &self,
        request_id: &str,
        expected_version: i64,
        new_status: ActionRequestStatus,
    ) -> StorageResult<CasOutcome> {
        self.as_ref()
            .compare_and_swap(request_id, expected_version, new_status)
            .await
    }
}

#[async_trait]
impl ApprovalDecisionStore for std::sync::Arc<InMemoryApprovalDecisionStore> {
    async fn insert(&self, decision: ApprovalDecision) -> StorageResult<()> {
        self.as_ref().insert(decision).await
    }
    async fn get(&self, decision_id: &str) -> StorageResult<Option<ApprovalDecision>> {
        self.as_ref().get(decision_id).await
    }
    async fn by_request(&self, request_id: &str) -> StorageResult<Vec<ApprovalDecision>> {
        self.as_ref().by_request(request_id).await
    }
}

#[async_trait]
impl AuditLog for std::sync::Arc<InMemoryAuditLog> {
    async fn append(&self, event: AuditEvent) -> StorageResult<()> {
        self.as_ref().append(event).await
    }
    async fn recent(&self, limit: usize) -> StorageResult<Vec<AuditEvent>> {
        self.as_ref().recent(limit).await
    }
}

#[async_trait]
impl WebhookReceiptStore for std::sync::Arc<InMemoryWebhookReceiptStore> {
    async fn record(&self, receipt: WebhookReceipt) -> StorageResult<WebhookRecordOutcome> {
        self.as_ref().record(receipt).await
    }
    async fn get(&self, delivery_id: &str) -> StorageResult<Option<WebhookReceipt>> {
        self.as_ref().get(delivery_id).await
    }
}

#[async_trait]
impl EvidenceNodeStore for std::sync::Arc<InMemoryEvidenceNodeStore> {
    async fn insert(&self, node: EvidenceNodeRecord) -> StorageResult<()> {
        self.as_ref().insert(node).await
    }
    async fn get(&self, node_id_hex: &str) -> StorageResult<Option<EvidenceNodeRecord>> {
        self.as_ref().get(node_id_hex).await
    }
    async fn by_mandate(&self, mandate_id_hex: &str) -> StorageResult<Vec<EvidenceNodeRecord>> {
        self.as_ref().by_mandate(mandate_id_hex).await
    }
}

#[async_trait]
impl ReceiptProjectionStore for std::sync::Arc<InMemoryReceiptProjectionStore> {
    async fn insert(&self, receipt: ReceiptProjection) -> StorageResult<()> {
        self.as_ref().insert(receipt).await
    }
    async fn get(&self, receipt_id_hex: &str) -> StorageResult<Option<ReceiptProjection>> {
        self.as_ref().get(receipt_id_hex).await
    }
    async fn by_mandate(&self, mandate_id_hex: &str) -> StorageResult<Vec<ReceiptProjection>> {
        self.as_ref().by_mandate(mandate_id_hex).await
    }
}

#[async_trait]
impl ExecutionAttemptStore for std::sync::Arc<InMemoryExecutionAttemptStore> {
    async fn insert(&self, attempt: ExecutionAttempt) -> StorageResult<()> {
        self.as_ref().insert(attempt).await
    }
    async fn get(&self, attempt_id_hex: &str) -> StorageResult<Option<ExecutionAttempt>> {
        self.as_ref().get(attempt_id_hex).await
    }
    async fn update_state(
        &self,
        attempt_id_hex: &str,
        new_state: ExecutionAttemptState,
    ) -> StorageResult<()> {
        self.as_ref().update_state(attempt_id_hex, new_state).await
    }
    async fn update_deployment_id(
        &self,
        attempt_id_hex: &str,
        deployment_id: u64,
    ) -> StorageResult<()> {
        self.as_ref()
            .update_deployment_id(attempt_id_hex, deployment_id)
            .await
    }
    async fn by_mandate(&self, mandate_id_hex: &str) -> StorageResult<Vec<ExecutionAttempt>> {
        self.as_ref().by_mandate(mandate_id_hex).await
    }
    async fn by_deployment_id(
        &self,
        deployment_id: u64,
    ) -> StorageResult<Option<ExecutionAttempt>> {
        self.as_ref().by_deployment_id(deployment_id).await
    }
}

#[async_trait]
impl ProtocolObjectStore for std::sync::Arc<InMemoryProtocolObjectStore> {
    async fn put(&self, record: ProtocolObjectRecord) -> StorageResult<()> {
        self.as_ref().put(record).await
    }
    async fn get(&self, object_id_hex: &str) -> StorageResult<Option<ProtocolObjectRecord>> {
        self.as_ref().get(object_id_hex).await
    }
}

#[async_trait]
impl EvidenceObjectStore for std::sync::Arc<InMemoryEvidenceStore> {
    async fn put(&self, bytes: &[u8]) -> StorageResult<ContentDigest> {
        self.as_ref().put(bytes).await
    }
    async fn get(&self, digest: &ContentDigest) -> StorageResult<Option<Vec<u8>>> {
        self.as_ref().get(digest).await
    }
    async fn put_descriptor(&self, descriptor: EvidenceDescriptor) -> StorageResult<()> {
        self.as_ref().put_descriptor(descriptor).await
    }
}

#[async_trait]
impl MandateProjectionStore for std::sync::Arc<InMemoryMandateProjectionStore> {
    async fn insert(&self, mandate_id_hex: &str, state: &str) -> StorageResult<()> {
        self.as_ref().insert(mandate_id_hex, state).await
    }
    async fn get(&self, mandate_id_hex: &str) -> StorageResult<Option<MandateProjection>> {
        self.as_ref().get(mandate_id_hex).await
    }
    async fn compare_and_swap(
        &self,
        mandate_id_hex: &str,
        expected_version: i64,
        new_state: &str,
    ) -> StorageResult<CasOutcome> {
        self.as_ref()
            .compare_and_swap(mandate_id_hex, expected_version, new_state)
            .await
    }
}
