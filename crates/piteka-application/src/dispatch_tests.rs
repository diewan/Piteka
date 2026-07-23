//! Positive and adversarial coverage for the dispatch use case (E-03).
//!
//! Tests cover:
//! - One concurrent winner (CAS on mandate projection)
//! - Durable journal (execution attempts + receipts recorded)
//! - Exact dispatch boundary (mandate transitions to Quarantined on failure)
//! - No dispatch without reservation
//! - No replay after consumption

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::Clock;
use crate::dispatch::{DispatchOutcome, DispatchPorts, DispatchUseCase};
use piteka_domain::UserId;
use piteka_storage::memory::{
    InMemoryActionRequestStore, InMemoryApprovalDecisionStore, InMemoryAuditLog,
    InMemoryExecutionAttemptStore, InMemoryMandateProjectionStore, InMemoryReceiptProjectionStore,
};
use piteka_storage::model::ExecutionAttemptState;
use piteka_storage::ports::{
    ActionRequestStore, ApprovalDecisionStore, AuditLog, ExecutionAttemptStore,
    MandateProjectionStore, ReceiptProjectionStore,
};

fn tenant() -> piteka_storage::TenantScope {
    piteka_storage::TenantScope::new("test-tenant").unwrap()
}
use piteka_storage::{ActionRequest, ActionRequestStatus, ApprovalDecision, AuditEvent};

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

    fn set(&self, now: u64) {
        self.now.store(now, Ordering::SeqCst);
    }
}

impl Clock for StepClock {
    fn unix_seconds(&self) -> u64 {
        self.now.load(Ordering::SeqCst)
    }
}

/// Test fixture: all ports backed by in-memory stores.
#[derive(Clone)]
struct TestPorts {
    request_store: Arc<InMemoryActionRequestStore>,
    decision_store: Arc<InMemoryApprovalDecisionStore>,
    mandate_store: Arc<InMemoryMandateProjectionStore>,
    attempt_store: Arc<InMemoryExecutionAttemptStore>,
    receipt_store: Arc<InMemoryReceiptProjectionStore>,
    audit_log: Arc<InMemoryAuditLog>,
    clock: StepClock,
}

impl TestPorts {
    fn new(clock: StepClock) -> Self {
        Self {
            request_store: Arc::new(InMemoryActionRequestStore::default()),
            decision_store: Arc::new(InMemoryApprovalDecisionStore::default()),
            mandate_store: Arc::new(InMemoryMandateProjectionStore::default()),
            attempt_store: Arc::new(InMemoryExecutionAttemptStore::default()),
            receipt_store: Arc::new(InMemoryReceiptProjectionStore::default()),
            audit_log: Arc::new(InMemoryAuditLog::default()),
            clock,
        }
    }
}

impl DispatchPorts for TestPorts {
    fn request_store(&self) -> &dyn ActionRequestStore {
        &self.request_store
    }
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
}

fn use_case(ports: &TestPorts) -> DispatchUseCase<TestPorts> {
    DispatchUseCase::new(tenant(), ports.clone())
}

fn requester() -> UserId {
    UserId::new("requester").unwrap()
}

fn approver() -> UserId {
    UserId::new("approver").unwrap()
}

/// Helper: create an approved action request and a mandate projection.
async fn setup_approved_request(ports: &TestPorts, request_id: &str, mandate_id_hex: &str) {
    // Create the action request in Approved status.
    let now = ports.clock.unix_seconds() as i64;
    let request = ActionRequest {
        request_id: request_id.to_string(),
        requested_by: requester().as_str().to_string(),
        intent_id_hex: Some("intent-abc123".to_string()),
        status: ActionRequestStatus::Approved,
        created_at_unix_seconds: now,
    };
    ports
        .request_store
        .insert(&tenant(), request)
        .await
        .unwrap();

    // Create the mandate projection in Issued state.
    ports
        .mandate_store
        .insert(&tenant(), mandate_id_hex, "issued")
        .await
        .unwrap();
}

#[tokio::test]
async fn reserve_succeeds_for_approved_request() {
    let clock = StepClock::at(1_000);
    let ports = TestPorts::new(clock.clone());
    let uc = use_case(&ports);

    setup_approved_request(&ports, "req-1", "mandate-1").await;

    let result = uc
        .reserve(
            "req-1",
            "mandate-1",
            "intent-abc123",
            "worker-1",
            "token-digest-1",
            "corr-1",
            1,
        )
        .await
        .unwrap();

    match result {
        DispatchOutcome::Dispatched(dispatched) => {
            assert_eq!(dispatched.mandate_id_hex, "mandate-1");
            assert_eq!(dispatched.attempt_id_hex, "att-mandate-1");
            assert_eq!(dispatched.intent_id_hex, "intent-abc123");
            assert_eq!(dispatched.executor_identity, "worker-1");
            assert!(!dispatched.provider_accepted);
        }
        other => panic!("expected Dispatched, got {:?}", other),
    }

    // Verify the mandate is now reserved.
    let mandate = ports
        .mandate_store
        .get(&tenant(), "mandate-1")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(mandate.state, "reserved");

    // Verify the attempt was created.
    let attempt = ports
        .attempt_store
        .get(&tenant(), "att-mandate-1")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(attempt.state, ExecutionAttemptState::Dispatching);
    assert_eq!(attempt.mandate_id_hex, "mandate-1");
}

#[tokio::test]
async fn reserve_rejects_non_approved_request() {
    let clock = StepClock::at(1_000);
    let ports = TestPorts::new(clock.clone());
    let uc = use_case(&ports);

    // Create a Pending request (not Approved).
    let now = ports.clock.unix_seconds() as i64;
    let request = ActionRequest {
        request_id: "req-1".to_string(),
        requested_by: requester().as_str().to_string(),
        intent_id_hex: None,
        status: ActionRequestStatus::Pending,
        created_at_unix_seconds: now,
    };
    ports
        .request_store
        .insert(&tenant(), request)
        .await
        .unwrap();

    let result = uc
        .reserve(
            "req-1",
            "mandate-1",
            "intent-abc123",
            "worker-1",
            "token-1",
            "corr-1",
            1,
        )
        .await
        .unwrap_err();

    assert!(matches!(
        result,
        crate::dispatch::DispatchError::InvalidTransition { .. }
    ));
}

#[tokio::test]
async fn one_concurrent_winner_on_reserve() {
    let clock = StepClock::at(1_000);
    let ports = TestPorts::new(clock.clone());
    let uc = use_case(&ports);

    setup_approved_request(&ports, "req-1", "mandate-1").await;

    // First caller wins the reservation.
    let result1 = uc
        .reserve(
            "req-1",
            "mandate-1",
            "intent-abc123",
            "worker-1",
            "token-1",
            "corr-1",
            1,
        )
        .await
        .unwrap();
    assert!(matches!(result1, DispatchOutcome::Dispatched { .. }));

    // Second caller with the same expected version loses.
    let result2 = uc
        .reserve(
            "req-1",
            "mandate-1",
            "intent-abc123",
            "worker-2",
            "token-2",
            "corr-2",
            1,
        )
        .await
        .unwrap();

    match result2 {
        DispatchOutcome::ReservationFailed(failed) => {
            assert_eq!(failed.mandate_id_hex, "mandate-1");
            assert_eq!(failed.winner_version, 2);
        }
        other => panic!("expected ReservationFailed, got {:?}", other),
    }

    // Verify only one attempt was created.
    let attempts = ports
        .attempt_store
        .by_mandate(&tenant(), "mandate-1")
        .await
        .unwrap();
    assert_eq!(attempts.len(), 1);
}

#[tokio::test]
async fn complete_dispatch_consumes_mandate_on_provider_acceptance() {
    let clock = StepClock::at(1_000);
    let ports = TestPorts::new(clock.clone());
    let uc = use_case(&ports);

    setup_approved_request(&ports, "req-1", "mandate-1").await;

    // Reserve first.
    let result = uc
        .reserve(
            "req-1",
            "mandate-1",
            "intent-abc123",
            "worker-1",
            "token-1",
            "corr-1",
            1,
        )
        .await
        .unwrap();

    let attempt_id = match result {
        DispatchOutcome::Dispatched(d) => d.attempt_id_hex,
        other => panic!("expected Dispatched, got {:?}", other),
    };

    // Complete with provider acceptance.
    uc.complete_dispatch(
        &attempt_id,
        "mandate-1",
        "intent-abc123",
        true,     // provider accepted
        Some(42), // deployment_id from GitHub
        "worker-1",
        2, // version after reserve CAS
    )
    .await
    .unwrap();

    // Verify mandate is consumed.
    let mandate = ports
        .mandate_store
        .get(&tenant(), "mandate-1")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(mandate.state, "consumed");

    // Verify attempt is Accepted.
    let attempt = ports
        .attempt_store
        .get(&tenant(), &attempt_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(attempt.state, ExecutionAttemptState::Accepted);

    // Receipt production waits for authenticated provider evidence.
    let receipts = ports
        .receipt_store
        .by_mandate(&tenant(), "mandate-1")
        .await
        .unwrap();
    assert!(receipts.is_empty());
}

#[tokio::test]
async fn complete_dispatch_quarantines_mandate_on_provider_failure() {
    let clock = StepClock::at(1_000);
    let ports = TestPorts::new(clock.clone());
    let uc = use_case(&ports);

    setup_approved_request(&ports, "req-1", "mandate-1").await;

    // Reserve first.
    let result = uc
        .reserve(
            "req-1",
            "mandate-1",
            "intent-abc123",
            "worker-1",
            "token-1",
            "corr-1",
            1,
        )
        .await
        .unwrap();

    let attempt_id = match result {
        DispatchOutcome::Dispatched(d) => d.attempt_id_hex,
        other => panic!("expected Dispatched, got {:?}", other),
    };

    // Complete with provider failure.
    uc.complete_dispatch(
        &attempt_id,
        "mandate-1",
        "intent-abc123",
        false, // provider failed
        None,  // no deployment_id
        "worker-1",
        2,
    )
    .await
    .unwrap();

    // Verify mandate is quarantined.
    let mandate = ports
        .mandate_store
        .get(&tenant(), "mandate-1")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(mandate.state, "quarantined");

    // Verify attempt is OutcomeAmbiguous.
    let attempt = ports
        .attempt_store
        .get(&tenant(), &attempt_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(attempt.state, ExecutionAttemptState::OutcomeAmbiguous);

    // Ambiguity does not fabricate a receipt.
    let receipts = ports
        .receipt_store
        .by_mandate(&tenant(), "mandate-1")
        .await
        .unwrap();
    assert!(receipts.is_empty());
}

#[tokio::test]
async fn no_dispatch_without_reservation() {
    let clock = StepClock::at(1_000);
    let ports = TestPorts::new(clock.clone());
    let uc = use_case(&ports);

    // Request exists but is not Approved.
    let now = ports.clock.unix_seconds() as i64;
    let request = ActionRequest {
        request_id: "req-1".to_string(),
        requested_by: requester().as_str().to_string(),
        intent_id_hex: None,
        status: ActionRequestStatus::Pending,
        created_at_unix_seconds: now,
    };
    ports
        .request_store
        .insert(&tenant(), request)
        .await
        .unwrap();

    // No mandate projection exists.
    let result = uc
        .reserve(
            "req-1",
            "mandate-1",
            "intent-abc123",
            "worker-1",
            "token-1",
            "corr-1",
            1,
        )
        .await
        .unwrap_err();

    assert!(matches!(
        result,
        crate::dispatch::DispatchError::InvalidTransition { .. }
    ));
}

#[tokio::test]
async fn audit_log_records_reserve_and_consume() {
    let clock = StepClock::at(1_000);
    let ports = TestPorts::new(clock.clone());
    let uc = use_case(&ports);

    setup_approved_request(&ports, "req-1", "mandate-1").await;

    // Reserve.
    let result = uc
        .reserve(
            "req-1",
            "mandate-1",
            "intent-abc123",
            "worker-1",
            "token-1",
            "corr-1",
            1,
        )
        .await
        .unwrap();

    let attempt_id = match result {
        DispatchOutcome::Dispatched(d) => d.attempt_id_hex,
        other => panic!("expected Dispatched, got {:?}", other),
    };

    // Consume.
    uc.complete_dispatch(
        &attempt_id,
        "mandate-1",
        "intent-abc123",
        true,
        Some(42),
        "worker-1",
        2,
    )
    .await
    .unwrap();

    // Verify audit log has both events.
    let events = ports.audit_log.recent(&tenant(), 10).await.unwrap();
    assert!(events.len() >= 2);
    assert_eq!(events[events.len() - 2].action, "reserve_mandate");
    assert_eq!(events[events.len() - 1].action, "consume_mandate");
}

#[tokio::test]
async fn reserve_and_dispatch_full_flow_provider_accepts() {
    let clock = StepClock::at(1_000);
    let ports = TestPorts::new(clock.clone());
    let uc = use_case(&ports);

    setup_approved_request(&ports, "req-1", "mandate-1").await;

    // Full flow with provider accepting.
    let result = uc
        .reserve_and_dispatch(
            "req-1",
            "mandate-1",
            "intent-abc123",
            "worker-1",
            "token-1",
            "corr-1",
            1,
            |_corr_key, _digest| Some(42), // provider accepts, returns deployment_id
        )
        .await
        .unwrap();

    match result {
        DispatchOutcome::Dispatched(dispatched) => {
            assert!(dispatched.provider_accepted);
        }
        other => panic!("expected Dispatched, got {:?}", other),
    }

    // Verify mandate is consumed.
    let mandate = ports
        .mandate_store
        .get(&tenant(), "mandate-1")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(mandate.state, "consumed");

    // Receipt production waits for authenticated provider evidence.
    let receipts = ports
        .receipt_store
        .by_mandate(&tenant(), "mandate-1")
        .await
        .unwrap();
    assert!(receipts.is_empty());
}

#[tokio::test]
async fn reserve_and_dispatch_full_flow_provider_rejects() {
    let clock = StepClock::at(1_000);
    let ports = TestPorts::new(clock.clone());
    let uc = use_case(&ports);

    setup_approved_request(&ports, "req-1", "mandate-1").await;

    // Full flow with provider rejecting.
    let result = uc
        .reserve_and_dispatch(
            "req-1",
            "mandate-1",
            "intent-abc123",
            "worker-1",
            "token-1",
            "corr-1",
            1,
            |_corr_key, _digest| None, // provider rejects
        )
        .await
        .unwrap();

    match result {
        DispatchOutcome::DispatchFailed { .. } => {
            // Expected: dispatch failed, mandate quarantined.
        }
        other => panic!("expected DispatchFailed, got {:?}", other),
    }

    // Verify mandate is quarantined.
    let mandate = ports
        .mandate_store
        .get(&tenant(), "mandate-1")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(mandate.state, "quarantined");

    // Ambiguity does not fabricate a receipt.
    let receipts = ports
        .receipt_store
        .by_mandate(&tenant(), "mandate-1")
        .await
        .unwrap();
    assert!(receipts.is_empty());
}

#[tokio::test]
async fn reservation_failed_outcome_returns_immediately() {
    let clock = StepClock::at(1_000);
    let ports = TestPorts::new(clock.clone());
    let uc = use_case(&ports);

    setup_approved_request(&ports, "req-1", "mandate-1").await;

    // First caller wins.
    uc.reserve_and_dispatch(
        "req-1",
        "mandate-1",
        "intent-abc123",
        "worker-1",
        "token-1",
        "corr-1",
        1,
        |_corr_key, _digest| Some(42),
    )
    .await
    .unwrap();

    // Second caller gets an explicit replay rejection without dispatching.
    let result = uc
        .reserve_and_dispatch(
            "req-1",
            "mandate-1",
            "intent-abc123",
            "worker-2",
            "token-2",
            "corr-2",
            1,
            |_corr_key, _digest| panic!("dispatch_fn should not be called for reservation failure"),
        )
        .await
        .unwrap();

    assert!(matches!(result, DispatchOutcome::ReplayRejected(_)));

    // Verify only one attempt was created.
    let attempts = ports
        .attempt_store
        .by_mandate(&tenant(), "mandate-1")
        .await
        .unwrap();
    assert_eq!(attempts.len(), 1);
}

#[tokio::test]
async fn no_second_dispatch_after_consumption() {
    let clock = StepClock::at(1_000);
    let ports = TestPorts::new(clock.clone());
    let uc = use_case(&ports);

    setup_approved_request(&ports, "req-1", "mandate-1").await;

    // First dispatch succeeds and consumes the mandate.
    let provider_dispatches = Arc::new(AtomicU64::new(0));
    let first_counter = provider_dispatches.clone();
    uc.reserve_and_dispatch(
        "req-1",
        "mandate-1",
        "intent-abc123",
        "worker-1",
        "token-1",
        "corr-1",
        1,
        move |_corr_key, _digest| {
            first_counter.fetch_add(1, Ordering::SeqCst);
            Some(42)
        },
    )
    .await
    .unwrap();

    // Second dispatch attempt: mandate is already consumed.
    let result = uc
        .reserve_and_dispatch(
            "req-1",
            "mandate-1",
            "intent-abc123",
            "worker-2",
            "token-2",
            "corr-2",
            1, // stale version
            {
                let provider_dispatches = provider_dispatches.clone();
                move |_corr_key, _digest| {
                    provider_dispatches.fetch_add(1, Ordering::SeqCst);
                    Some(43)
                }
            },
        )
        .await
        .unwrap();

    let rejection = match result {
        DispatchOutcome::ReplayRejected(rejection) => rejection,
        other => panic!("expected ReplayRejected, got {:?}", other),
    };
    assert_eq!(rejection.reason_code, "MANDATE.REPLAY_DETECTED");
    assert_eq!(rejection.mandate_state, "consumed");
    assert!(rejection.message.contains("nothing was sent to GitHub"));
    assert_eq!(provider_dispatches.load(Ordering::SeqCst), 1);

    // The rejected second call is evidence, while the provider-facing attempt
    // journal still contains exactly one dispatch.
    let events = ports.audit_log.recent(&tenant(), 10).await.unwrap();
    let replay = events
        .iter()
        .find(|event| event.detail.contains("MANDATE.REPLAY_DETECTED"))
        .expect("replay rejection audit evidence");
    assert_eq!(replay.decision, "denied");
    assert!(replay.detail.contains("provider dispatch suppressed"));
    assert_eq!(
        ports
            .attempt_store
            .by_mandate(&tenant(), "mandate-1")
            .await
            .unwrap()
            .len(),
        1
    );
}

// ---------------------------------------------------------------------------
// E-04: GitHub Deployments API execution and correlation tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn deployment_id_is_recorded_in_attempt_on_provider_acceptance() {
    let clock = StepClock::at(1_000);
    let ports = TestPorts::new(clock.clone());
    let uc = use_case(&ports);

    setup_approved_request(&ports, "req-1", "mandate-1").await;

    // Full flow with provider accepting and returning deployment_id=99.
    let result = uc
        .reserve_and_dispatch(
            "req-1",
            "mandate-1",
            "intent-abc123",
            "worker-1",
            "token-1",
            "corr-1",
            1,
            |_corr_key, _digest| Some(99),
        )
        .await
        .unwrap();

    match result {
        DispatchOutcome::Dispatched(dispatched) => {
            assert_eq!(dispatched.github_deployment_id, Some(99));
            assert!(dispatched.provider_accepted);
        }
        other => panic!("expected Dispatched, got {:?}", other),
    }

    // Verify the attempt has the deployment ID recorded.
    let attempt = ports
        .attempt_store
        .get(&tenant(), "att-mandate-1")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(attempt.github_deployment_id, Some(99));
}

#[tokio::test]
async fn deployment_id_is_none_on_provider_rejection() {
    let clock = StepClock::at(1_000);
    let ports = TestPorts::new(clock.clone());
    let uc = use_case(&ports);

    setup_approved_request(&ports, "req-1", "mandate-1").await;

    // Full flow with provider rejecting.
    let result = uc
        .reserve_and_dispatch(
            "req-1",
            "mandate-1",
            "intent-abc123",
            "worker-1",
            "token-1",
            "corr-1",
            1,
            |_corr_key, _digest| None,
        )
        .await
        .unwrap();

    match result {
        DispatchOutcome::DispatchFailed { .. } => {}
        other => panic!("expected DispatchFailed, got {:?}", other),
    }

    // Verify the attempt has no deployment ID.
    let attempt = ports
        .attempt_store
        .get(&tenant(), "att-mandate-1")
        .await
        .unwrap()
        .unwrap();
    assert!(attempt.github_deployment_id.is_none());
}

#[tokio::test]
async fn attempt_digest_is_deterministic() {
    use crate::dispatch::compute_attempt_digest;

    let digest1 = compute_attempt_digest("att-1", "mandate-1", "intent-1");
    let digest2 = compute_attempt_digest("att-1", "mandate-1", "intent-1");
    let digest3 = compute_attempt_digest("att-2", "mandate-1", "intent-1");

    assert_eq!(digest1, digest2, "same inputs produce same digest");
    assert_ne!(
        digest1, digest3,
        "different attempt ID produces different digest"
    );
}

#[tokio::test]
async fn attempt_digest_changes_with_mandate_id() {
    use crate::dispatch::compute_attempt_digest;

    let digest1 = compute_attempt_digest("att-1", "mandate-1", "intent-1");
    let digest2 = compute_attempt_digest("att-1", "mandate-2", "intent-1");

    assert_ne!(
        digest1, digest2,
        "different mandate ID produces different digest"
    );
}

#[tokio::test]
async fn attempt_digest_changes_with_intent_id() {
    use crate::dispatch::compute_attempt_digest;

    let digest1 = compute_attempt_digest("att-1", "mandate-1", "intent-1");
    let digest2 = compute_attempt_digest("att-1", "mandate-1", "intent-2");

    assert_ne!(
        digest1, digest2,
        "different intent ID produces different digest"
    );
}

#[tokio::test]
async fn complete_dispatch_records_deployment_id_separately() {
    let clock = StepClock::at(1_000);
    let ports = TestPorts::new(clock.clone());
    let uc = use_case(&ports);

    setup_approved_request(&ports, "req-1", "mandate-1").await;

    // Reserve first.
    let result = uc
        .reserve(
            "req-1",
            "mandate-1",
            "intent-abc123",
            "worker-1",
            "token-1",
            "corr-1",
            1,
        )
        .await
        .unwrap();

    let attempt_id = match result {
        DispatchOutcome::Dispatched(d) => d.attempt_id_hex,
        other => panic!("expected Dispatched, got {:?}", other),
    };

    // Complete with provider acceptance and deployment_id=123.
    uc.complete_dispatch(
        &attempt_id,
        "mandate-1",
        "intent-abc123",
        true,
        Some(123),
        "worker-1",
        2,
    )
    .await
    .unwrap();

    // Verify the attempt has the deployment ID.
    let attempt = ports
        .attempt_store
        .get(&tenant(), &attempt_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(attempt.github_deployment_id, Some(123));
    assert_eq!(attempt.state, ExecutionAttemptState::Accepted);
}

#[tokio::test]
async fn accepted_dispatch_without_deployment_id_fails_closed() {
    let clock = StepClock::at(1_000);
    let ports = TestPorts::new(clock.clone());
    let uc = use_case(&ports);

    setup_approved_request(&ports, "req-1", "mandate-1").await;
    let reserved = uc
        .reserve(
            "req-1",
            "mandate-1",
            "intent-abc123",
            "worker-1",
            "token-1",
            "corr-1",
            1,
        )
        .await
        .unwrap();
    let attempt_id = match reserved {
        DispatchOutcome::Dispatched(dispatched) => dispatched.attempt_id_hex,
        other => panic!("expected Dispatched, got {other:?}"),
    };

    let error = uc
        .complete_dispatch(
            &attempt_id,
            "mandate-1",
            "intent-abc123",
            true,
            None,
            "worker-1",
            2,
        )
        .await
        .unwrap_err();

    assert!(matches!(
        error,
        crate::dispatch::DispatchError::InvalidProviderResponse(_)
    ));
    let attempt = ports
        .attempt_store
        .get(&tenant(), &attempt_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(attempt.state, ExecutionAttemptState::OutcomeAmbiguous);
    assert_eq!(attempt.github_deployment_id, None);
    let mandate = ports
        .mandate_store
        .get(&tenant(), "mandate-1")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(mandate.state, "quarantined");
}

#[tokio::test]
async fn dispatched_result_contains_deployment_id() {
    let clock = StepClock::at(1_000);
    let ports = TestPorts::new(clock.clone());
    let uc = use_case(&ports);

    setup_approved_request(&ports, "req-1", "mandate-1").await;

    let result = uc
        .reserve_and_dispatch(
            "req-1",
            "mandate-1",
            "intent-abc123",
            "worker-1",
            "token-1",
            "corr-1",
            1,
            |_corr_key, _digest| Some(777),
        )
        .await
        .unwrap();

    match result {
        DispatchOutcome::Dispatched(d) => {
            assert_eq!(d.github_deployment_id, Some(777));
            assert_eq!(d.mandate_id_hex, "mandate-1");
            assert_eq!(d.attempt_id_hex, "att-mandate-1");
        }
        other => panic!("expected Dispatched, got {:?}", other),
    }
}
