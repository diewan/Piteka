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
    CaseAppendOutcome, CaseEvent, EvidenceDescriptor, EvidenceNodeRecord, ExecutionAttempt,
    ExecutionAttemptState, InvestigatorCase, MandateProjection, ProtocolObjectRecord,
    ReceiptProjection, SealConsumptionProofRecord, TenantScope, WebhookDeliveryRecord,
    WebhookRecordOutcome,
};
use crate::ports::{
    ActionRequestStore, ApprovalDecisionStore, AuditLog, EvidenceNodeStore, EvidenceObjectStore,
    ExecutionAttemptStore, InvestigatorCaseStore, MandateProjectionStore, ProtocolObjectStore,
    ReceiptProjectionStore, SealConsumptionStore, WebhookDeliveryStore,
};

/// In-memory investigator-case repository enforcing tenant scope and append-only history.
#[derive(Default)]
pub struct InMemoryInvestigatorCaseStore {
    cases: Mutex<HashMap<(String, String), InvestigatorCase>>,
    events: Mutex<HashMap<(String, String), Vec<CaseEvent>>>,
}

#[async_trait]
impl InvestigatorCaseStore for InMemoryInvestigatorCaseStore {
    async fn create(&self, tenant: &TenantScope, case: InvestigatorCase) -> StorageResult<()> {
        if case.tenant_id != tenant.as_str() || case.case_id.trim().is_empty() {
            return Err(StorageError::EmptyField("case_scope"));
        }
        if case.version != 0 {
            return Err(StorageError::Backend(
                "new investigator case must start at version zero".into(),
            ));
        }
        let key = (case.tenant_id.clone(), case.case_id.clone());
        let mut cases = self.cases.lock().expect("lock poisoned");
        if cases.contains_key(&key) {
            return Err(StorageError::Backend(
                "investigator case already exists".into(),
            ));
        }
        cases.insert(key, case);
        Ok(())
    }

    async fn get(
        &self,
        tenant: &TenantScope,
        case_id: &str,
    ) -> StorageResult<Option<InvestigatorCase>> {
        Ok(self
            .cases
            .lock()
            .expect("lock poisoned")
            .get(&(tenant.as_str().to_string(), case_id.to_string()))
            .cloned())
    }

    async fn list(&self, tenant: &TenantScope) -> StorageResult<Vec<InvestigatorCase>> {
        let mut cases = self
            .cases
            .lock()
            .expect("lock poisoned")
            .values()
            .filter(|case| case.tenant_id == tenant.as_str())
            .cloned()
            .collect::<Vec<_>>();
        cases.sort_by(|left, right| left.case_id.cmp(&right.case_id));
        Ok(cases)
    }

    async fn append(
        &self,
        tenant: &TenantScope,
        case_id: &str,
        expected_version: i64,
        mut event: CaseEvent,
    ) -> StorageResult<CaseAppendOutcome> {
        if event.tenant_id != tenant.as_str() || event.case_id != case_id {
            return Err(StorageError::Backend("case event scope mismatch".into()));
        }
        let key = (tenant.as_str().to_string(), case_id.to_string());
        let mut cases = self.cases.lock().expect("lock poisoned");
        let Some(case) = cases.get_mut(&key) else {
            return Ok(CaseAppendOutcome::Missing);
        };
        if case.version != expected_version {
            return Ok(CaseAppendOutcome::Conflict {
                current_version: case.version,
            });
        }
        let mut events = self.events.lock().expect("lock poisoned");
        if events
            .values()
            .flatten()
            .any(|existing| existing.event_id == event.event_id)
        {
            return Err(StorageError::Backend("case event id already exists".into()));
        }
        case.version += 1;
        event.sequence = case.version;
        events.entry(key).or_default().push(event);
        Ok(CaseAppendOutcome::Applied {
            new_version: case.version,
        })
    }

    async fn history(&self, tenant: &TenantScope, case_id: &str) -> StorageResult<Vec<CaseEvent>> {
        if self.get(tenant, case_id).await?.is_none() {
            return Ok(Vec::new());
        }
        Ok(self
            .events
            .lock()
            .expect("lock poisoned")
            .get(&(tenant.as_str().to_string(), case_id.to_string()))
            .cloned()
            .unwrap_or_default())
    }
}

#[async_trait]
impl InvestigatorCaseStore for std::sync::Arc<InMemoryInvestigatorCaseStore> {
    async fn create(&self, tenant: &TenantScope, case: InvestigatorCase) -> StorageResult<()> {
        self.as_ref().create(tenant, case).await
    }
    async fn get(
        &self,
        tenant: &TenantScope,
        case_id: &str,
    ) -> StorageResult<Option<InvestigatorCase>> {
        self.as_ref().get(tenant, case_id).await
    }
    async fn list(&self, tenant: &TenantScope) -> StorageResult<Vec<InvestigatorCase>> {
        self.as_ref().list(tenant).await
    }
    async fn append(
        &self,
        tenant: &TenantScope,
        case_id: &str,
        expected_version: i64,
        event: CaseEvent,
    ) -> StorageResult<CaseAppendOutcome> {
        self.as_ref()
            .append(tenant, case_id, expected_version, event)
            .await
    }
    async fn history(&self, tenant: &TenantScope, case_id: &str) -> StorageResult<Vec<CaseEvent>> {
        self.as_ref().history(tenant, case_id).await
    }
}

/// In-memory immutable protocol-object store.
#[derive(Default)]
pub struct InMemoryProtocolObjectStore {
    objects: Mutex<HashMap<(String, String), ProtocolObjectRecord>>,
}

#[async_trait]
impl ProtocolObjectStore for InMemoryProtocolObjectStore {
    async fn put(&self, tenant: &TenantScope, record: ProtocolObjectRecord) -> StorageResult<()> {
        if record.object_id_hex.is_empty() {
            return Err(StorageError::EmptyField("object_id_hex"));
        }
        let mut objects = self.objects.lock().expect("lock poisoned");
        let key = (tenant.as_str().to_owned(), record.object_id_hex.clone());
        if let Some(existing) = objects.get(&key) {
            if existing.bytes != record.bytes {
                return Err(StorageError::ImmutableViolation {
                    object_id_hex: record.object_id_hex,
                });
            }
            return Ok(());
        }
        objects.insert(key, record);
        Ok(())
    }

    async fn get(
        &self,
        tenant: &TenantScope,
        object_id_hex: &str,
    ) -> StorageResult<Option<ProtocolObjectRecord>> {
        Ok(self
            .objects
            .lock()
            .expect("lock poisoned")
            .get(&(tenant.as_str().to_owned(), object_id_hex.to_owned()))
            .cloned())
    }
}

/// In-memory immutable seal-consumption proof store.
#[derive(Default)]
pub struct InMemorySealConsumptionStore {
    proofs: Mutex<HashMap<(String, String), SealConsumptionProofRecord>>,
}

#[async_trait]
impl SealConsumptionStore for InMemorySealConsumptionStore {
    async fn put(
        &self,
        tenant: &TenantScope,
        record: SealConsumptionProofRecord,
    ) -> StorageResult<()> {
        if record.mandate_id_hex.is_empty() {
            return Err(StorageError::EmptyField("mandate_id_hex"));
        }
        let mut proofs = self.proofs.lock().expect("lock poisoned");
        let key = (tenant.as_str().to_owned(), record.mandate_id_hex.clone());
        if let Some(existing) = proofs.get(&key) {
            if existing != &record {
                return Err(StorageError::ImmutableViolation {
                    object_id_hex: record.mandate_id_hex,
                });
            }
            return Ok(());
        }
        proofs.insert(key, record);
        Ok(())
    }

    async fn get(
        &self,
        tenant: &TenantScope,
        mandate_id_hex: &str,
    ) -> StorageResult<Option<SealConsumptionProofRecord>> {
        Ok(self
            .proofs
            .lock()
            .expect("lock poisoned")
            .get(&(tenant.as_str().to_owned(), mandate_id_hex.to_owned()))
            .cloned())
    }
}

/// In-memory mandate projection store with version CAS.
#[derive(Default)]
pub struct InMemoryMandateProjectionStore {
    projections: Mutex<HashMap<(String, String), MandateProjection>>,
}

#[async_trait]
impl MandateProjectionStore for InMemoryMandateProjectionStore {
    async fn insert(
        &self,
        tenant: &TenantScope,
        mandate_id_hex: &str,
        state: &str,
    ) -> StorageResult<()> {
        if mandate_id_hex.is_empty() {
            return Err(StorageError::EmptyField("mandate_id_hex"));
        }
        let mut projections = self.projections.lock().expect("lock poisoned");
        let key = (tenant.as_str().to_owned(), mandate_id_hex.to_owned());
        if projections.contains_key(&key) {
            return Err(StorageError::Backend(format!(
                "mandate projection `{mandate_id_hex}` already exists"
            )));
        }
        projections.insert(
            key,
            MandateProjection {
                mandate_id_hex: mandate_id_hex.to_string(),
                version: 1,
                state: state.to_string(),
            },
        );
        Ok(())
    }

    async fn get(
        &self,
        tenant: &TenantScope,
        mandate_id_hex: &str,
    ) -> StorageResult<Option<MandateProjection>> {
        Ok(self
            .projections
            .lock()
            .expect("lock poisoned")
            .get(&(tenant.as_str().to_owned(), mandate_id_hex.to_owned()))
            .cloned())
    }

    async fn compare_and_swap(
        &self,
        tenant: &TenantScope,
        mandate_id_hex: &str,
        expected_version: i64,
        new_state: &str,
    ) -> StorageResult<CasOutcome> {
        let mut projections = self.projections.lock().expect("lock poisoned");
        let Some(projection) =
            projections.get_mut(&(tenant.as_str().to_owned(), mandate_id_hex.to_owned()))
        else {
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
pub struct InMemoryWebhookDeliveryStore {
    receipts: Mutex<HashMap<(String, String), WebhookDeliveryRecord>>,
}

#[async_trait]
impl WebhookDeliveryStore for InMemoryWebhookDeliveryStore {
    async fn record(
        &self,
        tenant: &TenantScope,
        receipt: WebhookDeliveryRecord,
    ) -> StorageResult<WebhookRecordOutcome> {
        if receipt.delivery_id.is_empty() {
            return Err(StorageError::EmptyField("delivery_id"));
        }
        let mut receipts = self.receipts.lock().expect("lock poisoned");
        let key = (tenant.as_str().to_owned(), receipt.delivery_id.clone());
        if receipts.contains_key(&key) {
            return Ok(WebhookRecordOutcome::Duplicate);
        }
        receipts.insert(key, receipt);
        Ok(WebhookRecordOutcome::Recorded)
    }

    async fn get(
        &self,
        tenant: &TenantScope,
        delivery_id: &str,
    ) -> StorageResult<Option<WebhookDeliveryRecord>> {
        Ok(self
            .receipts
            .lock()
            .expect("lock poisoned")
            .get(&(tenant.as_str().to_owned(), delivery_id.to_owned()))
            .cloned())
    }
}

/// An evidence blob keyed by tenant scope and content address.
///
/// The tenant is part of the key, not a filter applied afterwards, so a lookup
/// cannot reach across tenants even if a caller supplies a digest it observed
/// elsewhere.
type TenantScopedByDigest<V> = Mutex<HashMap<(String, [u8; 32]), V>>;

/// In-memory content-addressed evidence store.
#[derive(Default)]
pub struct InMemoryEvidenceStore {
    blobs: TenantScopedByDigest<Vec<u8>>,
    descriptors: TenantScopedByDigest<EvidenceDescriptor>,
}

#[async_trait]
impl EvidenceObjectStore for InMemoryEvidenceStore {
    async fn put(&self, tenant: &TenantScope, bytes: &[u8]) -> StorageResult<ContentDigest> {
        let digest = ContentDigest::of(bytes);
        self.blobs
            .lock()
            .expect("lock poisoned")
            .entry((tenant.as_str().to_owned(), *digest.as_bytes()))
            .or_insert_with(|| bytes.to_vec());
        Ok(digest)
    }

    async fn get(
        &self,
        tenant: &TenantScope,
        digest: &ContentDigest,
    ) -> StorageResult<Option<Vec<u8>>> {
        let Some(bytes) = self
            .blobs
            .lock()
            .expect("lock poisoned")
            .get(&(tenant.as_str().to_owned(), *digest.as_bytes()))
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

    async fn put_descriptor(
        &self,
        tenant: &TenantScope,
        descriptor: EvidenceDescriptor,
    ) -> StorageResult<()> {
        self.descriptors.lock().expect("lock poisoned").insert(
            (tenant.as_str().to_owned(), *descriptor.digest.as_bytes()),
            descriptor,
        );
        Ok(())
    }
}

/// In-memory structured evidence node store.
#[derive(Default)]
pub struct InMemoryEvidenceNodeStore {
    nodes: Mutex<HashMap<(String, String), EvidenceNodeRecord>>,
    by_mandate: Mutex<HashMap<(String, String), Vec<String>>>,
}

#[async_trait]
impl EvidenceNodeStore for InMemoryEvidenceNodeStore {
    async fn insert(&self, tenant: &TenantScope, node: EvidenceNodeRecord) -> StorageResult<()> {
        if node.node_id_hex.is_empty() {
            return Err(StorageError::EmptyField("node_id_hex"));
        }
        let mut nodes = self.nodes.lock().expect("lock poisoned");
        let key = (tenant.as_str().to_owned(), node.node_id_hex.clone());
        if nodes.contains_key(&key) {
            return Err(StorageError::Backend(format!(
                "evidence node `{}` already exists",
                node.node_id_hex
            )));
        }
        nodes.insert(key, node.clone());
        // Index by mandate prefix (nodes are stored with "ev-<mandate_id_hex>-..." prefix)
        for mandate_id in MANDATE_PREFIXES {
            if node.node_id_hex.starts_with(mandate_id) {
                self.by_mandate
                    .lock()
                    .expect("lock poisoned")
                    .entry((tenant.as_str().to_owned(), mandate_id.to_string()))
                    .or_default()
                    .push(node.node_id_hex.clone());
                break;
            }
        }
        Ok(())
    }

    async fn get(
        &self,
        tenant: &TenantScope,
        node_id_hex: &str,
    ) -> StorageResult<Option<EvidenceNodeRecord>> {
        Ok(self
            .nodes
            .lock()
            .expect("lock poisoned")
            .get(&(tenant.as_str().to_owned(), node_id_hex.to_owned()))
            .cloned())
    }

    async fn by_mandate(
        &self,
        tenant: &TenantScope,
        mandate_id_hex: &str,
    ) -> StorageResult<Vec<EvidenceNodeRecord>> {
        let nodes = self.nodes.lock().expect("lock poisoned");
        if mandate_id_hex.is_empty() {
            Ok(nodes
                .iter()
                .filter(|((stored_tenant, _), _)| stored_tenant == tenant.as_str())
                .map(|(_, node)| node.clone())
                .collect())
        } else {
            let ids = self
                .by_mandate
                .lock()
                .expect("lock poisoned")
                .get(&(tenant.as_str().to_owned(), mandate_id_hex.to_owned()))
                .cloned()
                .unwrap_or_default();
            Ok(ids
                .iter()
                .filter_map(|id| {
                    nodes
                        .get(&(tenant.as_str().to_owned(), id.clone()))
                        .cloned()
                })
                .collect())
        }
    }
}

/// Prefixes used to index evidence nodes by mandate.
const MANDATE_PREFIXES: &[&str] = &["mand-"];

/// In-memory append-only audit log.
#[derive(Default)]
pub struct InMemoryAuditLog {
    events: Mutex<Vec<(String, AuditEvent)>>,
}

#[async_trait]
impl AuditLog for InMemoryAuditLog {
    async fn append(&self, tenant: &TenantScope, event: AuditEvent) -> StorageResult<()> {
        self.events
            .lock()
            .expect("lock poisoned")
            .push((tenant.as_str().to_owned(), event));
        Ok(())
    }

    async fn recent(&self, tenant: &TenantScope, limit: usize) -> StorageResult<Vec<AuditEvent>> {
        let events = self.events.lock().expect("lock poisoned");
        let mut scoped = events
            .iter()
            .filter(|(stored_tenant, _)| stored_tenant == tenant.as_str())
            .map(|(_, event)| event.clone())
            .collect::<Vec<_>>();
        let start = scoped.len().saturating_sub(limit);
        Ok(scoped.split_off(start))
    }
}

/// In-memory action request store with version CAS.
#[derive(Default)]
pub struct InMemoryActionRequestStore {
    requests: Mutex<HashMap<(String, String), ActionRequest>>,
    versions: Mutex<HashMap<(String, String), i64>>,
}

#[async_trait]
impl ActionRequestStore for InMemoryActionRequestStore {
    async fn insert(&self, tenant: &TenantScope, request: ActionRequest) -> StorageResult<()> {
        if request.request_id.is_empty() {
            return Err(StorageError::EmptyField("request_id"));
        }
        let mut requests = self.requests.lock().expect("lock poisoned");
        let key = (tenant.as_str().to_owned(), request.request_id.clone());
        if requests.contains_key(&key) {
            return Err(StorageError::Backend(format!(
                "action request `{}` already exists",
                request.request_id
            )));
        }
        requests.insert(key, request);
        Ok(())
    }

    async fn get(
        &self,
        tenant: &TenantScope,
        request_id: &str,
    ) -> StorageResult<Option<ActionRequest>> {
        Ok(self
            .requests
            .lock()
            .expect("lock poisoned")
            .get(&(tenant.as_str().to_owned(), request_id.to_owned()))
            .cloned())
    }

    async fn list(&self, tenant: &TenantScope) -> StorageResult<Vec<ActionRequest>> {
        let requests = self.requests.lock().expect("lock poisoned");
        Ok(requests
            .iter()
            .filter(|((stored_tenant, _), _)| stored_tenant == tenant.as_str())
            .map(|(_, request)| request.clone())
            .collect())
    }

    async fn compare_and_swap(
        &self,
        tenant: &TenantScope,
        request_id: &str,
        expected_version: i64,
        new_status: ActionRequestStatus,
    ) -> StorageResult<CasOutcome> {
        let mut requests = self.requests.lock().expect("lock poisoned");
        let mut versions = self.versions.lock().expect("lock poisoned");
        let key = (tenant.as_str().to_owned(), request_id.to_owned());
        let Some(request) = requests.get_mut(&key) else {
            return Ok(CasOutcome::Missing);
        };
        let current_version = versions.get(&key).copied().unwrap_or(1);
        if current_version != expected_version {
            return Ok(CasOutcome::Conflict { current_version });
        }
        let new_version = current_version + 1;
        versions.insert(key, new_version);
        request.status = new_status;
        Ok(CasOutcome::Applied { new_version })
    }
}

/// In-memory approval decision store.
#[derive(Default)]
pub struct InMemoryApprovalDecisionStore {
    decisions: Mutex<HashMap<(String, String), ApprovalDecision>>,
    by_request: Mutex<HashMap<(String, String), Vec<String>>>,
}

#[async_trait]
impl ApprovalDecisionStore for InMemoryApprovalDecisionStore {
    async fn insert(&self, tenant: &TenantScope, decision: ApprovalDecision) -> StorageResult<()> {
        if decision.decision_id.is_empty() {
            return Err(StorageError::EmptyField("decision_id"));
        }
        let mut decisions = self.decisions.lock().expect("lock poisoned");
        let key = (tenant.as_str().to_owned(), decision.decision_id.clone());
        if decisions.contains_key(&key) {
            return Err(StorageError::Backend(format!(
                "approval decision `{}` already exists",
                decision.decision_id
            )));
        }
        decisions.insert(key, decision.clone());
        self.by_request
            .lock()
            .expect("lock poisoned")
            .entry((tenant.as_str().to_owned(), decision.request_id))
            .or_default()
            .push(decision.decision_id);
        Ok(())
    }

    async fn get(
        &self,
        tenant: &TenantScope,
        decision_id: &str,
    ) -> StorageResult<Option<ApprovalDecision>> {
        Ok(self
            .decisions
            .lock()
            .expect("lock poisoned")
            .get(&(tenant.as_str().to_owned(), decision_id.to_owned()))
            .cloned())
    }

    async fn by_request(
        &self,
        tenant: &TenantScope,
        request_id: &str,
    ) -> StorageResult<Vec<ApprovalDecision>> {
        let decisions = self.decisions.lock().expect("lock poisoned");
        let ids = self
            .by_request
            .lock()
            .expect("lock poisoned")
            .get(&(tenant.as_str().to_owned(), request_id.to_owned()))
            .cloned()
            .unwrap_or_default();
        Ok(ids
            .iter()
            .filter_map(|id| {
                decisions
                    .get(&(tenant.as_str().to_owned(), id.clone()))
                    .cloned()
            })
            .collect())
    }
}

/// In-memory execution attempt store.
#[derive(Default)]
pub struct InMemoryExecutionAttemptStore {
    attempts: Mutex<HashMap<(String, String), ExecutionAttempt>>,
    by_mandate: Mutex<HashMap<(String, String), Vec<String>>>,
}

#[async_trait]
impl ExecutionAttemptStore for InMemoryExecutionAttemptStore {
    async fn insert(&self, tenant: &TenantScope, attempt: ExecutionAttempt) -> StorageResult<()> {
        if attempt.attempt_id_hex.is_empty() {
            return Err(StorageError::EmptyField("attempt_id_hex"));
        }
        let mut attempts = self.attempts.lock().expect("lock poisoned");
        let key = (tenant.as_str().to_owned(), attempt.attempt_id_hex.clone());
        if attempts.contains_key(&key) {
            return Err(StorageError::Backend(format!(
                "execution attempt `{}` already exists",
                attempt.attempt_id_hex
            )));
        }
        attempts.insert(key, attempt.clone());
        self.by_mandate
            .lock()
            .expect("lock poisoned")
            .entry((tenant.as_str().to_owned(), attempt.mandate_id_hex.clone()))
            .or_default()
            .push(attempt.attempt_id_hex);
        Ok(())
    }

    async fn get(
        &self,
        tenant: &TenantScope,
        attempt_id_hex: &str,
    ) -> StorageResult<Option<ExecutionAttempt>> {
        Ok(self
            .attempts
            .lock()
            .expect("lock poisoned")
            .get(&(tenant.as_str().to_owned(), attempt_id_hex.to_owned()))
            .cloned())
    }

    async fn update_state(
        &self,
        tenant: &TenantScope,
        attempt_id_hex: &str,
        new_state: ExecutionAttemptState,
    ) -> StorageResult<()> {
        let mut attempts = self.attempts.lock().expect("lock poisoned");
        let Some(attempt) =
            attempts.get_mut(&(tenant.as_str().to_owned(), attempt_id_hex.to_owned()))
        else {
            return Err(StorageError::Backend(format!(
                "execution attempt `{attempt_id_hex}` not found"
            )));
        };
        attempt.state = new_state;
        Ok(())
    }

    async fn update_deployment_id(
        &self,
        tenant: &TenantScope,
        attempt_id_hex: &str,
        deployment_id: u64,
    ) -> StorageResult<()> {
        let mut attempts = self.attempts.lock().expect("lock poisoned");
        let Some(attempt) =
            attempts.get_mut(&(tenant.as_str().to_owned(), attempt_id_hex.to_owned()))
        else {
            return Err(StorageError::Backend(format!(
                "execution attempt `{attempt_id_hex}` not found"
            )));
        };
        attempt.github_deployment_id = Some(deployment_id);
        Ok(())
    }

    async fn by_mandate(
        &self,
        tenant: &TenantScope,
        mandate_id_hex: &str,
    ) -> StorageResult<Vec<ExecutionAttempt>> {
        let attempts = self.attempts.lock().expect("lock poisoned");
        let ids = self
            .by_mandate
            .lock()
            .expect("lock poisoned")
            .get(&(tenant.as_str().to_owned(), mandate_id_hex.to_owned()))
            .cloned()
            .unwrap_or_default();
        Ok(ids
            .iter()
            .filter_map(|id| {
                attempts
                    .get(&(tenant.as_str().to_owned(), id.clone()))
                    .cloned()
            })
            .collect())
    }

    async fn by_deployment_id(
        &self,
        tenant: &TenantScope,
        deployment_id: u64,
    ) -> StorageResult<Option<ExecutionAttempt>> {
        let attempts = self.attempts.lock().expect("lock poisoned");
        Ok(attempts
            .iter()
            .find(|((stored_tenant, _), attempt)| {
                stored_tenant == tenant.as_str()
                    && attempt.github_deployment_id == Some(deployment_id)
            })
            .map(|(_, attempt)| attempt)
            .cloned())
    }
}

/// In-memory receipt projection store.
#[derive(Default)]
pub struct InMemoryReceiptProjectionStore {
    receipts: Mutex<HashMap<(String, String), ReceiptProjection>>,
    by_mandate: Mutex<HashMap<(String, String), Vec<String>>>,
}

#[async_trait]
impl ReceiptProjectionStore for InMemoryReceiptProjectionStore {
    async fn insert(&self, tenant: &TenantScope, receipt: ReceiptProjection) -> StorageResult<()> {
        if receipt.receipt_id_hex.is_empty() {
            return Err(StorageError::EmptyField("receipt_id_hex"));
        }
        let mut receipts = self.receipts.lock().expect("lock poisoned");
        let key = (tenant.as_str().to_owned(), receipt.receipt_id_hex.clone());
        if receipts.contains_key(&key) {
            return Err(StorageError::Backend(format!(
                "receipt projection `{}` already exists",
                receipt.receipt_id_hex
            )));
        }
        receipts.insert(key, receipt.clone());
        self.by_mandate
            .lock()
            .expect("lock poisoned")
            .entry((tenant.as_str().to_owned(), receipt.mandate_id_hex.clone()))
            .or_default()
            .push(receipt.receipt_id_hex);
        Ok(())
    }

    async fn get(
        &self,
        tenant: &TenantScope,
        receipt_id_hex: &str,
    ) -> StorageResult<Option<ReceiptProjection>> {
        Ok(self
            .receipts
            .lock()
            .expect("lock poisoned")
            .get(&(tenant.as_str().to_owned(), receipt_id_hex.to_owned()))
            .cloned())
    }

    async fn by_mandate(
        &self,
        tenant: &TenantScope,
        mandate_id_hex: &str,
    ) -> StorageResult<Vec<ReceiptProjection>> {
        let receipts = self.receipts.lock().expect("lock poisoned");
        let ids = self
            .by_mandate
            .lock()
            .expect("lock poisoned")
            .get(&(tenant.as_str().to_owned(), mandate_id_hex.to_owned()))
            .cloned()
            .unwrap_or_default();
        Ok(ids
            .iter()
            .filter_map(|id| {
                receipts
                    .get(&(tenant.as_str().to_owned(), id.clone()))
                    .cloned()
            })
            .collect())
    }
}

// Blanket impl: Arc<T> implements the store traits when T does.
#[async_trait]
impl ActionRequestStore for std::sync::Arc<InMemoryActionRequestStore> {
    async fn insert(&self, tenant: &TenantScope, request: ActionRequest) -> StorageResult<()> {
        self.as_ref().insert(tenant, request).await
    }
    async fn get(
        &self,
        tenant: &TenantScope,
        request_id: &str,
    ) -> StorageResult<Option<ActionRequest>> {
        self.as_ref().get(tenant, request_id).await
    }
    async fn list(&self, tenant: &TenantScope) -> StorageResult<Vec<ActionRequest>> {
        self.as_ref().list(tenant).await
    }
    async fn compare_and_swap(
        &self,
        tenant: &TenantScope,
        request_id: &str,
        expected_version: i64,
        new_status: ActionRequestStatus,
    ) -> StorageResult<CasOutcome> {
        self.as_ref()
            .compare_and_swap(tenant, request_id, expected_version, new_status)
            .await
    }
}

#[async_trait]
impl ApprovalDecisionStore for std::sync::Arc<InMemoryApprovalDecisionStore> {
    async fn insert(&self, tenant: &TenantScope, decision: ApprovalDecision) -> StorageResult<()> {
        self.as_ref().insert(tenant, decision).await
    }
    async fn get(
        &self,
        tenant: &TenantScope,
        decision_id: &str,
    ) -> StorageResult<Option<ApprovalDecision>> {
        self.as_ref().get(tenant, decision_id).await
    }
    async fn by_request(
        &self,
        tenant: &TenantScope,
        request_id: &str,
    ) -> StorageResult<Vec<ApprovalDecision>> {
        self.as_ref().by_request(tenant, request_id).await
    }
}

#[async_trait]
impl AuditLog for std::sync::Arc<InMemoryAuditLog> {
    async fn append(&self, tenant: &TenantScope, event: AuditEvent) -> StorageResult<()> {
        self.as_ref().append(tenant, event).await
    }
    async fn recent(&self, tenant: &TenantScope, limit: usize) -> StorageResult<Vec<AuditEvent>> {
        self.as_ref().recent(tenant, limit).await
    }
}

#[async_trait]
impl WebhookDeliveryStore for std::sync::Arc<InMemoryWebhookDeliveryStore> {
    async fn record(
        &self,
        tenant: &TenantScope,
        receipt: WebhookDeliveryRecord,
    ) -> StorageResult<WebhookRecordOutcome> {
        self.as_ref().record(tenant, receipt).await
    }
    async fn get(
        &self,
        tenant: &TenantScope,
        delivery_id: &str,
    ) -> StorageResult<Option<WebhookDeliveryRecord>> {
        self.as_ref().get(tenant, delivery_id).await
    }
}

#[async_trait]
impl EvidenceNodeStore for std::sync::Arc<InMemoryEvidenceNodeStore> {
    async fn insert(&self, tenant: &TenantScope, node: EvidenceNodeRecord) -> StorageResult<()> {
        self.as_ref().insert(tenant, node).await
    }
    async fn get(
        &self,
        tenant: &TenantScope,
        node_id_hex: &str,
    ) -> StorageResult<Option<EvidenceNodeRecord>> {
        self.as_ref().get(tenant, node_id_hex).await
    }
    async fn by_mandate(
        &self,
        tenant: &TenantScope,
        mandate_id_hex: &str,
    ) -> StorageResult<Vec<EvidenceNodeRecord>> {
        self.as_ref().by_mandate(tenant, mandate_id_hex).await
    }
}

#[async_trait]
impl ReceiptProjectionStore for std::sync::Arc<InMemoryReceiptProjectionStore> {
    async fn insert(&self, tenant: &TenantScope, receipt: ReceiptProjection) -> StorageResult<()> {
        self.as_ref().insert(tenant, receipt).await
    }
    async fn get(
        &self,
        tenant: &TenantScope,
        receipt_id_hex: &str,
    ) -> StorageResult<Option<ReceiptProjection>> {
        self.as_ref().get(tenant, receipt_id_hex).await
    }
    async fn by_mandate(
        &self,
        tenant: &TenantScope,
        mandate_id_hex: &str,
    ) -> StorageResult<Vec<ReceiptProjection>> {
        self.as_ref().by_mandate(tenant, mandate_id_hex).await
    }
}

#[async_trait]
impl ExecutionAttemptStore for std::sync::Arc<InMemoryExecutionAttemptStore> {
    async fn insert(&self, tenant: &TenantScope, attempt: ExecutionAttempt) -> StorageResult<()> {
        self.as_ref().insert(tenant, attempt).await
    }
    async fn get(
        &self,
        tenant: &TenantScope,
        attempt_id_hex: &str,
    ) -> StorageResult<Option<ExecutionAttempt>> {
        self.as_ref().get(tenant, attempt_id_hex).await
    }
    async fn update_state(
        &self,
        tenant: &TenantScope,
        attempt_id_hex: &str,
        new_state: ExecutionAttemptState,
    ) -> StorageResult<()> {
        self.as_ref()
            .update_state(tenant, attempt_id_hex, new_state)
            .await
    }
    async fn update_deployment_id(
        &self,
        tenant: &TenantScope,
        attempt_id_hex: &str,
        deployment_id: u64,
    ) -> StorageResult<()> {
        self.as_ref()
            .update_deployment_id(tenant, attempt_id_hex, deployment_id)
            .await
    }
    async fn by_mandate(
        &self,
        tenant: &TenantScope,
        mandate_id_hex: &str,
    ) -> StorageResult<Vec<ExecutionAttempt>> {
        self.as_ref().by_mandate(tenant, mandate_id_hex).await
    }
    async fn by_deployment_id(
        &self,
        tenant: &TenantScope,
        deployment_id: u64,
    ) -> StorageResult<Option<ExecutionAttempt>> {
        self.as_ref().by_deployment_id(tenant, deployment_id).await
    }
}

#[async_trait]
impl ProtocolObjectStore for std::sync::Arc<InMemoryProtocolObjectStore> {
    async fn put(&self, tenant: &TenantScope, record: ProtocolObjectRecord) -> StorageResult<()> {
        self.as_ref().put(tenant, record).await
    }
    async fn get(
        &self,
        tenant: &TenantScope,
        object_id_hex: &str,
    ) -> StorageResult<Option<ProtocolObjectRecord>> {
        self.as_ref().get(tenant, object_id_hex).await
    }
}

#[async_trait]
impl SealConsumptionStore for std::sync::Arc<InMemorySealConsumptionStore> {
    async fn put(
        &self,
        tenant: &TenantScope,
        record: SealConsumptionProofRecord,
    ) -> StorageResult<()> {
        self.as_ref().put(tenant, record).await
    }
    async fn get(
        &self,
        tenant: &TenantScope,
        mandate_id_hex: &str,
    ) -> StorageResult<Option<SealConsumptionProofRecord>> {
        self.as_ref().get(tenant, mandate_id_hex).await
    }
}

#[async_trait]
impl EvidenceObjectStore for std::sync::Arc<InMemoryEvidenceStore> {
    async fn put(&self, tenant: &TenantScope, bytes: &[u8]) -> StorageResult<ContentDigest> {
        self.as_ref().put(tenant, bytes).await
    }
    async fn get(
        &self,
        tenant: &TenantScope,
        digest: &ContentDigest,
    ) -> StorageResult<Option<Vec<u8>>> {
        self.as_ref().get(tenant, digest).await
    }
    async fn put_descriptor(
        &self,
        tenant: &TenantScope,
        descriptor: EvidenceDescriptor,
    ) -> StorageResult<()> {
        self.as_ref().put_descriptor(tenant, descriptor).await
    }
}

#[async_trait]
impl MandateProjectionStore for std::sync::Arc<InMemoryMandateProjectionStore> {
    async fn insert(
        &self,
        tenant: &TenantScope,
        mandate_id_hex: &str,
        state: &str,
    ) -> StorageResult<()> {
        self.as_ref().insert(tenant, mandate_id_hex, state).await
    }
    async fn get(
        &self,
        tenant: &TenantScope,
        mandate_id_hex: &str,
    ) -> StorageResult<Option<MandateProjection>> {
        self.as_ref().get(tenant, mandate_id_hex).await
    }
    async fn compare_and_swap(
        &self,
        tenant: &TenantScope,
        mandate_id_hex: &str,
        expected_version: i64,
        new_state: &str,
    ) -> StorageResult<CasOutcome> {
        self.as_ref()
            .compare_and_swap(tenant, mandate_id_hex, expected_version, new_state)
            .await
    }
}
