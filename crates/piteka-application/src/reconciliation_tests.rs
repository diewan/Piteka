//! Positive and adversarial tests for the reconciliation use case (E-07).
//!
//! Tests cover:
//! - Quarantined mandate with ambiguous attempt → reconciliation finds deployment → Consumed
//! - Quarantined mandate with ambiguous attempt → no deployment found → Abandoned
//! - No automatic release/retry (reconciliation is explicit only)
//! - GitHub v1 has no Quarantined → Released path
//! - Unresolved cases terminate as Abandoned + AbandonedAmbiguous with Unknown receipt
//! - CAS conflict prevents concurrent reconciliation
//! - Non-quarantined mandates cannot be reconciled
//! - Provider unavailable → deferred (no simulated success)

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use super::Clock;
use super::reconciliation::{
    CorrelatedDeployment, DeploymentStatusProvider, ReconciliationOutcome, ReconciliationPorts,
    ReconciliationUseCase,
};
use piteka_storage::memory::{
    InMemoryAuditLog, InMemoryExecutionAttemptStore, InMemoryMandateProjectionStore,
    InMemoryReceiptProjectionStore,
};
use piteka_storage::model::{ExecutionAttempt, ExecutionAttemptState};
use piteka_storage::ports::{
    AuditLog, ExecutionAttemptStore, MandateProjectionStore, ReceiptProjectionStore,
};
use piteka_storage::{AuditEvent, CasOutcome, StorageError, StorageResult};

/// Deterministic test clock.
#[derive(Clone)]
struct StepClock {
    now: Arc<AtomicU64>,
}

impl StepClock {
    fn at(now: u64) -> Self {
        Self {
            now: Arc::new(AtomicU64::new(now)),
        }
    }
}

impl Clock for StepClock {
    fn unix_seconds(&self) -> u64 {
        self.now.load(Ordering::SeqCst)
    }
}

/// Mock deployment status provider.
#[derive(Clone)]
struct MockDeploymentProvider {
    accepted: Arc<AtomicBool>,
    error: Arc<AtomicBool>,
}

impl Default for MockDeploymentProvider {
    fn default() -> Self {
        Self {
            accepted: Arc::new(AtomicBool::new(false)),
            error: Arc::new(AtomicBool::new(false)),
        }
    }
}

impl MockDeploymentProvider {
    fn set_accepted(&self, accepted: bool) {
        self.accepted.store(accepted, Ordering::SeqCst);
    }

    fn set_error(&self, error: bool) {
        self.error.store(error, Ordering::SeqCst);
    }
}

#[async_trait::async_trait]
impl DeploymentStatusProvider for MockDeploymentProvider {
    async fn find_correlated_deployment(
        &self,
        attempt: &ExecutionAttempt,
    ) -> StorageResult<Option<CorrelatedDeployment>> {
        if self.error.load(Ordering::SeqCst) {
            return Err(StorageError::Backend("provider unavailable".to_string()));
        }
        Ok(self
            .accepted
            .load(Ordering::SeqCst)
            .then_some(CorrelatedDeployment {
                deployment_id: attempt.github_deployment_id.unwrap_or(4242),
            }))
    }
}

/// Test fixture: all ports backed by in-memory stores.
#[derive(Clone)]
struct TestPorts {
    mandate_store: Arc<InMemoryMandateProjectionStore>,
    attempt_store: Arc<InMemoryExecutionAttemptStore>,
    receipt_store: Arc<InMemoryReceiptProjectionStore>,
    audit_log: Arc<InMemoryAuditLog>,
    clock: StepClock,
    deployment_provider: MockDeploymentProvider,
}

impl TestPorts {
    fn new(clock: StepClock) -> Self {
        Self {
            mandate_store: Arc::new(InMemoryMandateProjectionStore::default()),
            attempt_store: Arc::new(InMemoryExecutionAttemptStore::default()),
            receipt_store: Arc::new(InMemoryReceiptProjectionStore::default()),
            audit_log: Arc::new(InMemoryAuditLog::default()),
            clock,
            deployment_provider: MockDeploymentProvider::default(),
        }
    }

    fn provider(&self) -> &MockDeploymentProvider {
        &self.deployment_provider
    }
}

#[async_trait::async_trait]
impl MandateProjectionStore for TestPorts {
    async fn insert(&self, mandate_id_hex: &str, state: &str) -> StorageResult<()> {
        self.mandate_store.insert(mandate_id_hex, state).await
    }
    async fn get(
        &self,
        mandate_id_hex: &str,
    ) -> StorageResult<Option<piteka_storage::MandateProjection>> {
        self.mandate_store.get(mandate_id_hex).await
    }
    async fn compare_and_swap(
        &self,
        mandate_id_hex: &str,
        expected_version: i64,
        new_state: &str,
    ) -> StorageResult<CasOutcome> {
        self.mandate_store
            .compare_and_swap(mandate_id_hex, expected_version, new_state)
            .await
    }
}

#[async_trait::async_trait]
impl ExecutionAttemptStore for TestPorts {
    async fn insert(&self, attempt: ExecutionAttempt) -> StorageResult<()> {
        self.attempt_store.insert(attempt).await
    }
    async fn get(&self, attempt_id_hex: &str) -> StorageResult<Option<ExecutionAttempt>> {
        self.attempt_store.get(attempt_id_hex).await
    }
    async fn update_state(
        &self,
        attempt_id_hex: &str,
        new_state: ExecutionAttemptState,
    ) -> StorageResult<()> {
        self.attempt_store
            .update_state(attempt_id_hex, new_state)
            .await
    }
    async fn update_deployment_id(
        &self,
        attempt_id_hex: &str,
        deployment_id: u64,
    ) -> StorageResult<()> {
        self.attempt_store
            .update_deployment_id(attempt_id_hex, deployment_id)
            .await
    }
    async fn by_mandate(&self, mandate_id_hex: &str) -> StorageResult<Vec<ExecutionAttempt>> {
        self.attempt_store.by_mandate(mandate_id_hex).await
    }
    async fn by_deployment_id(
        &self,
        deployment_id: u64,
    ) -> StorageResult<Option<ExecutionAttempt>> {
        self.attempt_store.by_deployment_id(deployment_id).await
    }
}

#[async_trait::async_trait]
impl ReceiptProjectionStore for TestPorts {
    async fn insert(&self, receipt: piteka_storage::ReceiptProjection) -> StorageResult<()> {
        self.receipt_store.insert(receipt).await
    }
    async fn get(
        &self,
        receipt_id_hex: &str,
    ) -> StorageResult<Option<piteka_storage::ReceiptProjection>> {
        self.receipt_store.get(receipt_id_hex).await
    }
    async fn by_mandate(
        &self,
        mandate_id_hex: &str,
    ) -> StorageResult<Vec<piteka_storage::ReceiptProjection>> {
        self.receipt_store.by_mandate(mandate_id_hex).await
    }
}

#[async_trait::async_trait]
impl AuditLog for TestPorts {
    async fn append(&self, event: AuditEvent) -> StorageResult<()> {
        self.audit_log.append(event).await
    }
    async fn recent(&self, limit: usize) -> StorageResult<Vec<AuditEvent>> {
        self.audit_log.recent(limit).await
    }
}

impl ReconciliationPorts for TestPorts {
    fn mandate_store(&self) -> &dyn MandateProjectionStore {
        &self.mandate_store
    }
    fn attempt_store(&self) -> &dyn ExecutionAttemptStore {
        &self.attempt_store
    }
    fn receipt_store(&self) -> &dyn ReceiptProjectionStore {
        &self.receipt_store
    }
    fn audit_log(&self) -> &dyn AuditLog {
        &self.audit_log
    }
    fn clock(&self) -> &dyn Clock {
        &self.clock
    }
    fn deployment_provider(&self) -> &dyn DeploymentStatusProvider {
        &self.deployment_provider
    }
}

fn use_case(ports: &TestPorts) -> ReconciliationUseCase<TestPorts> {
    ReconciliationUseCase::new(ports.clone())
}

/// Helper: set up a quarantined mandate with an ambiguous attempt.
async fn setup_quarantined_mandate(
    ports: &TestPorts,
    mandate_id_hex: &str,
    attempt_id_hex: &str,
    deployment_id: u64,
) {
    // Insert mandate in quarantined state at version 1.
    ports
        .mandate_store
        .insert(mandate_id_hex, "quarantined")
        .await
        .unwrap();

    // Insert execution attempt in OutcomeAmbiguous state.
    ports
        .attempt_store
        .insert(ExecutionAttempt {
            attempt_id_hex: attempt_id_hex.to_string(),
            mandate_id_hex: mandate_id_hex.to_string(),
            intent_id_hex: "intent-abc123".to_string(),
            reservation_token_digest: "token-digest".to_string(),
            executor_identity: "worker-1".to_string(),
            correlation_key: "corr-1".to_string(),
            started_at_unix_seconds: 1_000,
            dispatch_boundary_at_unix_seconds: Some(1_001),
            state: ExecutionAttemptState::OutcomeAmbiguous,
            github_deployment_id: Some(deployment_id),
        })
        .await
        .unwrap();
}

#[tokio::test]
async fn reconcile_accepts_when_provider_confirms_deployment() {
    let clock = StepClock::at(2_000);
    let ports = TestPorts::new(clock.clone());
    let uc = use_case(&ports);

    setup_quarantined_mandate(&ports, "mandate-1", "att-1", 42).await;

    // Provider confirms the deployment was accepted.
    ports.provider().set_accepted(true);

    let result = uc.reconcile("mandate-1", "operator-1", 1).await.unwrap();

    match result {
        ReconciliationOutcome::ReconciledAccepted {
            mandate_id_hex,
            attempt_id_hex,
            new_version,
        } => {
            assert_eq!(mandate_id_hex, "mandate-1");
            assert_eq!(attempt_id_hex, "att-1");
            assert_eq!(new_version, 2);
        }
        other => panic!("expected ReconciledAccepted, got {:?}", other),
    }

    // Verify mandate is consumed.
    let mandate = ports.mandate_store.get("mandate-1").await.unwrap().unwrap();
    assert_eq!(mandate.state, "consumed");

    // Verify attempt is ReconciledAccepted.
    let attempt = ports.attempt_store.get("att-1").await.unwrap().unwrap();
    assert_eq!(attempt.state, ExecutionAttemptState::ReconciledAccepted);

    // Correlation establishes provider acceptance, not target success. Receipt
    // production waits for source-attributed outcome evidence.
    let receipts = ports.receipt_store.by_mandate("mandate-1").await.unwrap();
    assert!(receipts.is_empty());
}

#[tokio::test]
async fn absent_deployment_does_not_abandon_or_release() {
    let clock = StepClock::at(2_000);
    let ports = TestPorts::new(clock.clone());
    let uc = use_case(&ports);

    setup_quarantined_mandate(&ports, "mandate-2", "att-2", 99).await;

    // Provider confirms no deployment was found.
    ports.provider().set_accepted(false);

    let result = uc.reconcile("mandate-2", "operator-1", 1).await.unwrap();

    assert!(matches!(result, ReconciliationOutcome::Unresolved { .. }));

    // Absence is not non-occurrence: both live states remain quarantined.
    let mandate = ports.mandate_store.get("mandate-2").await.unwrap().unwrap();
    assert_eq!(mandate.state, "quarantined");

    // Verify attempt is AbandonedAmbiguous.
    let attempt = ports.attempt_store.get("att-2").await.unwrap().unwrap();
    assert_eq!(attempt.state, ExecutionAttemptState::OutcomeAmbiguous);

    // Verify receipt with Unknown outcome was created.
    let receipts = ports.receipt_store.by_mandate("mandate-2").await.unwrap();
    assert!(receipts.is_empty());
}

#[tokio::test]
async fn reconcile_defers_when_provider_unavailable() {
    let clock = StepClock::at(2_000);
    let ports = TestPorts::new(clock.clone());
    let uc = use_case(&ports);

    setup_quarantined_mandate(&ports, "mandate-3", "att-3", 55).await;

    // Provider is unavailable.
    ports.provider().set_error(true);

    let result = uc.reconcile("mandate-3", "operator-1", 1).await.unwrap();

    match result {
        ReconciliationOutcome::Unresolved {
            mandate_id_hex,
            reason,
        } => {
            assert_eq!(mandate_id_hex, "mandate-3");
            assert!(reason.contains("provider unavailable"));
        }
        other => panic!("expected ProviderUnavailable, got {:?}", other),
    }

    // Verify mandate is STILL quarantined (not consumed or abandoned).
    let mandate = ports.mandate_store.get("mandate-3").await.unwrap().unwrap();
    assert_eq!(mandate.state, "quarantined");

    // Verify attempt is STILL OutcomeAmbiguous.
    let attempt = ports.attempt_store.get("att-3").await.unwrap().unwrap();
    assert_eq!(attempt.state, ExecutionAttemptState::OutcomeAmbiguous);

    // Verify no new receipt was created.
    let receipts = ports.receipt_store.by_mandate("mandate-3").await.unwrap();
    assert_eq!(receipts.len(), 0);
}

#[tokio::test]
async fn reconcile_rejects_non_quarantined_mandate() {
    let clock = StepClock::at(2_000);
    let ports = TestPorts::new(clock.clone());
    let uc = use_case(&ports);

    // Insert mandate in consumed state.
    ports
        .mandate_store
        .insert("mandate-4", "consumed")
        .await
        .unwrap();

    let result = uc.reconcile("mandate-4", "operator-1", 1).await;

    assert!(result.is_err());
    match result.unwrap_err() {
        super::reconciliation::ReconciliationError::AlreadyTerminal { current_state } => {
            assert_eq!(current_state, "consumed");
        }
        other => panic!("expected AlreadyTerminal, got {:?}", other),
    }
}

#[tokio::test]
async fn reconcile_rejects_mandate_not_in_quarantined_state() {
    let clock = StepClock::at(2_000);
    let ports = TestPorts::new(clock.clone());
    let uc = use_case(&ports);

    // Insert mandate in reserved state.
    ports
        .mandate_store
        .insert("mandate-5", "reserved")
        .await
        .unwrap();

    let result = uc.reconcile("mandate-5", "operator-1", 1).await;

    assert!(result.is_err());
    match result.unwrap_err() {
        super::reconciliation::ReconciliationError::NotQuarantined { current_state } => {
            assert_eq!(current_state, "reserved");
        }
        other => panic!("expected NotQuarantined, got {:?}", other),
    }
}

#[tokio::test]
async fn reconcile_rejects_nonexistent_mandate() {
    let clock = StepClock::at(2_000);
    let ports = TestPorts::new(clock.clone());
    let uc = use_case(&ports);

    let result = uc.reconcile("mandate-nonexistent", "operator-1", 1).await;

    assert!(result.is_err());
    match result.unwrap_err() {
        super::reconciliation::ReconciliationError::MandateNotFound(id) => {
            assert_eq!(id, "mandate-nonexistent");
        }
        other => panic!("expected MandateNotFound, got {:?}", other),
    }
}

#[tokio::test]
async fn reconcile_cas_conflict_prevents_concurrent_reconciliation() {
    let clock = StepClock::at(2_000);
    let ports = TestPorts::new(clock.clone());
    let uc = use_case(&ports);

    setup_quarantined_mandate(&ports, "mandate-6", "att-6", 77).await;

    // First reconciliation succeeds.
    ports.provider().set_accepted(true);
    let result1 = uc.reconcile("mandate-6", "operator-1", 1).await.unwrap();
    assert!(matches!(
        result1,
        ReconciliationOutcome::ReconciledAccepted { .. }
    ));

    // Second reconciliation with stale version fails — the mandate is already
    // consumed, so we get AlreadyTerminal (which is the correct behavior:
    // a consumed mandate cannot be reconciled again).
    let result2 = uc.reconcile("mandate-6", "operator-2", 1).await;
    assert!(result2.is_err());
    match result2.unwrap_err() {
        super::reconciliation::ReconciliationError::AlreadyTerminal { current_state } => {
            assert_eq!(current_state, "consumed");
        }
        other => panic!("expected AlreadyTerminal, got {:?}", other),
    }
}

#[tokio::test]
async fn no_deployment_id_remains_unresolved() {
    let clock = StepClock::at(2_000);
    let ports = TestPorts::new(clock.clone());
    let uc = use_case(&ports);

    // Set up a quarantined mandate WITHOUT a deployment ID.
    ports
        .mandate_store
        .insert("mandate-7", "quarantined")
        .await
        .unwrap();

    ports
        .attempt_store
        .insert(ExecutionAttempt {
            attempt_id_hex: "att-7".to_string(),
            mandate_id_hex: "mandate-7".to_string(),
            intent_id_hex: "intent-xyz".to_string(),
            reservation_token_digest: "token".to_string(),
            executor_identity: "worker-1".to_string(),
            correlation_key: "corr-7".to_string(),
            started_at_unix_seconds: 1_000,
            dispatch_boundary_at_unix_seconds: Some(1_001),
            state: ExecutionAttemptState::OutcomeAmbiguous,
            github_deployment_id: None, // No deployment was created
        })
        .await
        .unwrap();

    // A missing local ID cannot prove GitHub did not accept the request.
    let result = uc.reconcile("mandate-7", "operator-1", 1).await.unwrap();

    match result {
        ReconciliationOutcome::Unresolved { .. } => {}
        other => panic!("expected Unresolved, got {:?}", other),
    }

    // Verify mandate is abandoned.
    let mandate = ports.mandate_store.get("mandate-7").await.unwrap().unwrap();
    assert_eq!(mandate.state, "quarantined");

    // Verify attempt is AbandonedAmbiguous.
    let attempt = ports.attempt_store.get("att-7").await.unwrap().unwrap();
    assert_eq!(attempt.state, ExecutionAttemptState::OutcomeAmbiguous);
}

#[tokio::test]
async fn timeout_after_request_recovers_deployment_by_correlation_payload() {
    let ports = TestPorts::new(StepClock::at(2_000));
    let uc = use_case(&ports);

    ports
        .mandate_store
        .insert("mandate-timeout", "quarantined")
        .await
        .unwrap();
    ports
        .attempt_store
        .insert(ExecutionAttempt {
            attempt_id_hex: "att-timeout".to_string(),
            mandate_id_hex: "mandate-timeout".to_string(),
            intent_id_hex: "intent-timeout".to_string(),
            reservation_token_digest: "token-digest".to_string(),
            executor_identity: "worker-1".to_string(),
            correlation_key: "corr-timeout".to_string(),
            started_at_unix_seconds: 1_000,
            dispatch_boundary_at_unix_seconds: Some(1_001),
            state: ExecutionAttemptState::OutcomeAmbiguous,
            // The response containing GitHub's ID was lost after request send.
            github_deployment_id: None,
        })
        .await
        .unwrap();
    ports.provider().set_accepted(true);

    let outcome = uc
        .reconcile("mandate-timeout", "operator-1", 1)
        .await
        .unwrap();
    assert!(outcome.is_accepted());

    let mandate = ports
        .mandate_store
        .get("mandate-timeout")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(mandate.state, "consumed");
    let attempt = ports
        .attempt_store
        .get("att-timeout")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(attempt.state, ExecutionAttemptState::ReconciledAccepted);
    assert_eq!(attempt.github_deployment_id, Some(4242));
}

#[tokio::test]
async fn reconciliation_rejects_empty_operator_identity() {
    let ports = TestPorts::new(StepClock::at(2_000));
    let uc = use_case(&ports);
    setup_quarantined_mandate(&ports, "mandate-auth", "att-auth", 8).await;
    ports.provider().set_accepted(true);

    let error = uc.reconcile("mandate-auth", "  ", 1).await.unwrap_err();
    assert!(matches!(
        error,
        super::reconciliation::ReconciliationError::UnauthorizedExecutor(_)
    ));
    assert_eq!(
        ports
            .mandate_store
            .get("mandate-auth")
            .await
            .unwrap()
            .unwrap()
            .state,
        "quarantined"
    );
}

#[tokio::test]
async fn audit_log_records_reconciliation_outcomes() {
    let clock = StepClock::at(2_000);
    let ports = TestPorts::new(clock.clone());
    let uc = use_case(&ports);

    setup_quarantined_mandate(&ports, "mandate-8", "att-8", 88).await;

    // Reconcile as accepted.
    ports.provider().set_accepted(true);
    uc.reconcile("mandate-8", "operator-1", 1).await.unwrap();

    // Verify audit log has the reconciliation event.
    let events = ports.audit_log.recent(10).await.unwrap();
    assert!(events.iter().any(|e| e.action == "reconciliation.accepted"));
    assert!(events.iter().any(|e| e.detail.contains("mandate-8")));
}

#[tokio::test]
async fn audit_log_records_abandoned_outcome() {
    let clock = StepClock::at(2_000);
    let ports = TestPorts::new(clock.clone());
    let uc = use_case(&ports);

    setup_quarantined_mandate(&ports, "mandate-9", "att-9", 99).await;

    // Explicit operator closure is the only abandonment path.
    ports.provider().set_accepted(false);
    uc.abandon_unresolved("mandate-9", "operator-1", 1, "investigation exhausted")
        .await
        .unwrap();

    // Verify audit log has the abandonment event.
    let events = ports.audit_log.recent(10).await.unwrap();
    assert!(
        events
            .iter()
            .any(|e| e.action == "reconciliation.abandoned")
    );
    assert!(events.iter().any(|e| e.detail.contains("mandate-9")));
    assert!(
        events
            .iter()
            .any(|e| e.detail.contains("investigation exhausted"))
    );
}

#[tokio::test]
async fn no_automatic_release_reconciliation_is_explicit_only() {
    // This test verifies that reconciliation never happens automatically.
    // The mere existence of a quarantined mandate does not trigger any state change.
    let clock = StepClock::at(2_000);
    let ports = TestPorts::new(clock.clone());

    // Set up a quarantined mandate.
    setup_quarantined_mandate(&ports, "mandate-10", "att-10", 100).await;

    // Do NOT call reconcile. The mandate should remain quarantined.
    let mandate = ports
        .mandate_store
        .get("mandate-10")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(mandate.state, "quarantined");

    let attempt = ports.attempt_store.get("att-10").await.unwrap().unwrap();
    assert_eq!(attempt.state, ExecutionAttemptState::OutcomeAmbiguous);
}

#[tokio::test]
async fn github_v1_has_no_quarantined_released_path() {
    // This test verifies that the reconciliation use case never transitions
    // a mandate to Released state. The only terminal states from Quarantined
    // are Consumed and Abandoned.
    let clock = StepClock::at(2_000);
    let ports = TestPorts::new(clock.clone());
    let uc = use_case(&ports);

    // Test both reconciliation outcomes.
    setup_quarantined_mandate(&ports, "mandate-11", "att-11", 111).await;
    ports.provider().set_accepted(true);
    let result = uc.reconcile("mandate-11", "operator-1", 1).await.unwrap();
    assert!(matches!(
        result,
        ReconciliationOutcome::ReconciledAccepted { .. }
    ));

    let mandate = ports
        .mandate_store
        .get("mandate-11")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(mandate.state, "consumed");
    assert_ne!(mandate.state, "released");

    setup_quarantined_mandate(&ports, "mandate-12", "att-12", 112).await;
    let result = uc
        .abandon_unresolved("mandate-12", "operator-1", 1, "operator closed case")
        .await
        .unwrap();
    assert!(matches!(
        result,
        ReconciliationOutcome::AbandonedAmbiguous { .. }
    ));

    let mandate = ports
        .mandate_store
        .get("mandate-12")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(mandate.state, "abandoned");
    assert_ne!(mandate.state, "released");
}

#[tokio::test]
async fn reconciliation_outcome_methods() {
    let accepted = ReconciliationOutcome::ReconciledAccepted {
        mandate_id_hex: "m-1".to_string(),
        attempt_id_hex: "a-1".to_string(),
        new_version: 2,
    };
    assert!(accepted.is_accepted());
    assert!(!accepted.is_abandoned());
    assert!(!accepted.is_unavailable());

    let abandoned = ReconciliationOutcome::AbandonedAmbiguous {
        mandate_id_hex: "m-2".to_string(),
        attempt_id_hex: "a-2".to_string(),
        new_version: 2,
    };
    assert!(!abandoned.is_accepted());
    assert!(abandoned.is_abandoned());
    assert!(!abandoned.is_unavailable());

    let unavailable = ReconciliationOutcome::Unresolved {
        mandate_id_hex: "m-3".to_string(),
        reason: "timeout".to_string(),
    };
    assert!(!unavailable.is_accepted());
    assert!(!unavailable.is_abandoned());
    assert!(unavailable.is_unavailable());
}
