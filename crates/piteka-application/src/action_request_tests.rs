//! Positive and adversarial coverage for action-request and approval use cases.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::Clock;
use crate::action_request::{
    ActionRequestPorts, ActionRequestUseCase, ActionRequestUseCaseError, Approved,
};
use piteka_domain::UserId;
use piteka_storage::ActionRequestStatus;
use piteka_storage::memory::{
    InMemoryActionRequestStore, InMemoryApprovalDecisionStore, InMemoryAuditLog,
};
use piteka_storage::ports::{ActionRequestStore, ApprovalDecisionStore, AuditLog};

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

/// Test fixture: ports backed by in-memory stores.
struct TestPorts {
    request_store: InMemoryActionRequestStore,
    decision_store: InMemoryApprovalDecisionStore,
    audit_log: InMemoryAuditLog,
    clock: StepClock,
}

impl TestPorts {
    fn new(clock: StepClock) -> Self {
        Self {
            request_store: InMemoryActionRequestStore::default(),
            decision_store: InMemoryApprovalDecisionStore::default(),
            audit_log: InMemoryAuditLog::default(),
            clock,
        }
    }
}

impl ActionRequestPorts for TestPorts {
    fn request_store(&self) -> &dyn ActionRequestStore {
        &self.request_store
    }

    fn decision_store(&self) -> &dyn ApprovalDecisionStore {
        &self.decision_store
    }

    fn audit_log(&self) -> &dyn AuditLog {
        &self.audit_log
    }

    fn clock(&self) -> &dyn Clock {
        &self.clock
    }
}

fn use_case(clock: StepClock) -> ActionRequestUseCase<TestPorts> {
    ActionRequestUseCase::new(
        piteka_storage::TenantScope::new("test-tenant").unwrap(),
        TestPorts::new(clock),
    )
}

fn requester() -> UserId {
    UserId::new("requester").unwrap()
}

fn approver() -> UserId {
    UserId::new("approver").unwrap()
}

#[tokio::test]
async fn propose_creates_a_pending_request_and_audits() {
    let clock = StepClock::at(1_000);
    let uc = use_case(clock.clone());

    let result = uc
        .propose("req-1", requester(), Some("intent-abc123".to_string()))
        .await
        .unwrap();

    assert_eq!(result.request.status, ActionRequestStatus::Pending);
    assert_eq!(result.request.request_id, "req-1");
    assert_eq!(
        result.request.intent_id_hex,
        Some("intent-abc123".to_string())
    );

    let events = uc.recent_audit(10).await.unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].action, "propose_action");
    assert_eq!(events[0].decision, "granted");
    assert_eq!(events[0].actor.as_deref(), Some("requester"));
}

#[tokio::test]
async fn propose_without_intent_id_is_allowed() {
    let clock = StepClock::at(1_000);
    let uc = use_case(clock.clone());

    let result = uc.propose("req-2", requester(), None).await.unwrap();
    assert_eq!(result.request.status, ActionRequestStatus::Pending);
    assert!(result.request.intent_id_hex.is_none());
}

#[tokio::test]
async fn approve_transitions_pending_to_approved_with_cas() {
    let clock = StepClock::at(1_000);
    let uc = use_case(clock.clone());

    uc.propose("req-1", requester(), Some("intent-abc123".to_string()))
        .await
        .unwrap();

    let result = uc
        .approve("req-1", approver(), Some("intent-abc123".to_string()), 1)
        .await
        .unwrap();

    assert_eq!(result.request.status, ActionRequestStatus::Approved);
    assert_eq!(result.decision.decision, "approved");
    assert_eq!(
        result.decision.intent_id_hex,
        Some("intent-abc123".to_string())
    );
    assert_eq!(result.decision.decided_by, "approver");

    let events = uc.recent_audit(10).await.unwrap();
    assert_eq!(events.len(), 2); // propose + approve
    assert_eq!(events[1].action, "approve_action");
    assert_eq!(events[1].decision, "granted");
}

#[tokio::test]
async fn approve_rejects_non_pending_request() {
    let clock = StepClock::at(1_000);
    let uc = use_case(clock.clone());

    uc.propose("req-1", requester(), None).await.unwrap();
    uc.reject("req-1", approver(), None, 1).await.unwrap();

    let result = uc.approve("req-1", approver(), None, 1).await.unwrap_err();

    assert!(matches!(
        result,
        ActionRequestUseCaseError::InvalidTransition {
            current: ActionRequestStatus::Rejected,
            attempted: "approve"
        }
    ));
}

#[tokio::test]
async fn approve_conflict_on_duplicate_cas() {
    let clock = StepClock::at(1_000);
    let uc = use_case(clock.clone());

    uc.propose("req-1", requester(), Some("intent-abc123".to_string()))
        .await
        .unwrap();

    // First approval wins.
    uc.approve("req-1", approver(), Some("intent-abc123".to_string()), 1)
        .await
        .unwrap();

    // Second approval with stale version loses — status is now Approved,
    // so the transition check fires before the CAS even runs.
    let result = uc
        .approve("req-1", approver(), Some("intent-abc123".to_string()), 1)
        .await
        .unwrap_err();

    assert!(matches!(
        result,
        ActionRequestUseCaseError::InvalidTransition {
            current: ActionRequestStatus::Approved,
            attempted: "approve"
        }
    ));
}

#[tokio::test]
async fn reject_transitions_pending_to_rejected() {
    let clock = StepClock::at(1_000);
    let uc = use_case(clock.clone());

    uc.propose("req-1", requester(), Some("intent-abc123".to_string()))
        .await
        .unwrap();

    let result = uc
        .reject("req-1", approver(), Some("intent-abc123".to_string()), 1)
        .await
        .unwrap();

    assert_eq!(result.request.status, ActionRequestStatus::Rejected);
    assert_eq!(result.decision.decision, "rejected");

    let events = uc.recent_audit(10).await.unwrap();
    assert_eq!(events.len(), 2);
    assert_eq!(events[1].action, "reject_action");
    assert_eq!(events[1].decision, "denied");
}

#[tokio::test]
async fn reject_nonexistent_request_fails() {
    let clock = StepClock::at(1_000);
    let uc = use_case(clock.clone());

    let result = uc
        .reject("nonexistent", approver(), None, 1)
        .await
        .unwrap_err();

    assert!(matches!(result, ActionRequestUseCaseError::NotFound(_)));
}

#[tokio::test]
async fn revoke_transitions_approved_to_revoked() {
    let clock = StepClock::at(1_000);
    let uc = use_case(clock.clone());

    uc.propose("req-1", requester(), Some("intent-abc123".to_string()))
        .await
        .unwrap();

    uc.approve("req-1", approver(), Some("intent-abc123".to_string()), 1)
        .await
        .unwrap();

    let result = uc.revoke("req-1", approver(), 2).await.unwrap();
    assert_eq!(result.request.status, ActionRequestStatus::Revoked);

    let events = uc.recent_audit(10).await.unwrap();
    assert_eq!(events.len(), 3); // propose + approve + revoke
    assert_eq!(events[2].action, "revoke_mandate");
    assert_eq!(events[2].decision, "granted");
}

#[tokio::test]
async fn revoke_non_approved_request_fails() {
    let clock = StepClock::at(1_000);
    let uc = use_case(clock.clone());

    uc.propose("req-1", requester(), None).await.unwrap();

    let result = uc.revoke("req-1", approver(), 1).await.unwrap_err();
    assert!(matches!(
        result,
        ActionRequestUseCaseError::InvalidTransition {
            current: ActionRequestStatus::Pending,
            attempted: "revoke"
        }
    ));
}

#[tokio::test]
async fn decisions_are_queryable_by_request() {
    let clock = StepClock::at(1_000);
    let uc = use_case(clock.clone());

    uc.propose("req-1", requester(), Some("intent-abc123".to_string()))
        .await
        .unwrap();

    uc.approve("req-1", approver(), Some("intent-abc123".to_string()), 1)
        .await
        .unwrap();

    let decisions = uc.get_decisions("req-1").await.unwrap();
    assert_eq!(decisions.len(), 1);
    assert_eq!(decisions[0].decision, "approved");
    assert_eq!(decisions[0].request_id, "req-1");
}

#[tokio::test]
async fn list_requests_returns_all() {
    let clock = StepClock::at(1_000);
    let uc = use_case(clock.clone());

    uc.propose("req-1", requester(), None).await.unwrap();
    uc.propose("req-2", requester(), None).await.unwrap();

    let requests = uc.list_requests().await.unwrap();
    assert_eq!(requests.len(), 2);
}

#[tokio::test]
async fn intent_id_is_bound_to_approval_not_prompt_text() {
    let clock = StepClock::at(1_000);
    let uc = use_case(clock.clone());

    uc.propose("req-1", requester(), Some("intent-abc123".to_string()))
        .await
        .unwrap();

    let Approved { decision, .. } = uc
        .approve("req-1", approver(), Some("intent-abc123".to_string()), 1)
        .await
        .unwrap();

    // The decision binds to the intent digest, not to any free-form text.
    assert_eq!(decision.intent_id_hex, Some("intent-abc123".to_string()));
    assert_eq!(decision.decision, "approved");
}

#[tokio::test]
async fn approve_with_different_intent_digest_fails_before_mutation() {
    let clock = StepClock::at(1_000);
    let uc = use_case(clock.clone());

    uc.propose(
        "req-1",
        requester(),
        Some("intent-server-canonical".to_string()),
    )
    .await
    .unwrap();

    let error = uc
        .approve(
            "req-1",
            approver(),
            Some("intent-reviewed-xyz".to_string()),
            1,
        )
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        ActionRequestUseCaseError::IntentMismatch { .. }
    ));
    assert_eq!(
        uc.list_requests().await.unwrap()[0].status,
        ActionRequestStatus::Pending
    );
}

#[tokio::test]
async fn revoked_request_cannot_be_approved_or_rejected() {
    let clock = StepClock::at(1_000);
    let uc = use_case(clock.clone());

    uc.propose("req-1", requester(), None).await.unwrap();
    uc.approve("req-1", approver(), None, 1).await.unwrap();
    uc.revoke("req-1", approver(), 2).await.unwrap();

    // Cannot approve a revoked request.
    let result = uc.approve("req-1", approver(), None, 3).await.unwrap_err();
    assert!(matches!(
        result,
        ActionRequestUseCaseError::InvalidTransition {
            current: ActionRequestStatus::Revoked,
            attempted: "approve"
        }
    ));

    // Cannot reject a revoked request.
    let result = uc.reject("req-1", approver(), None, 3).await.unwrap_err();
    assert!(matches!(
        result,
        ActionRequestUseCaseError::InvalidTransition {
            current: ActionRequestStatus::Revoked,
            attempted: "reject"
        }
    ));
}
