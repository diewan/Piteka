//! PostgreSQL integration tests.
//!
//! Ignored by default; run against a disposable database:
//!
//! ```bash
//! DATABASE_URL=postgres://localhost/piteka_test \
//!   cargo test -p piteka-storage --features postgres --test postgres \
//!   -- --ignored --test-threads=1
//! ```
//!
//! Run serially (`--test-threads=1`): the tests share one database and reset
//! tables between runs.
//!
//! They assert the Postgres adapters uphold the same immutability, CAS,
//! webhook-uniqueness, and append-only rules the in-memory adapters enforce.
#![cfg(feature = "postgres")]

use piteka_storage::model::{
    ActionRequest, ActionRequestStatus, ApprovalDecision, AuditEvent, CasOutcome,
    ProtocolObjectRecord, ReceiptOutcome, ReceiptProjection, WebhookReceipt, WebhookRecordOutcome,
};
use piteka_storage::ports::{
    ActionRequestStore, ApprovalDecisionStore, AuditLog, MandateProjectionStore,
    ProtocolObjectStore, ReceiptProjectionStore, WebhookReceiptStore,
};
use piteka_storage::postgres::{
    PgActionRequestStore, PgApprovalDecisionStore, PgAuditLog, PgMandateProjectionStore,
    PgProtocolObjectStore, PgReceiptProjectionStore, PgWebhookReceiptStore, connect,
    run_migrations,
};
use piteka_storage::{ContentDigest, StorageError, TenantScope};

fn tenant() -> TenantScope {
    TenantScope::new("test-tenant").unwrap()
}
use sqlx::postgres::PgPool;

async fn fresh_pool() -> PgPool {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set for --ignored tests");
    let pool = connect(&url).await.expect("connect");
    run_migrations(&pool).await.expect("migrations");
    // Isolate each run: truncate the tables these tests touch.
    for table in [
        "protocol_objects",
        "mandate_projections",
        "webhook_receipts",
        "audit_events",
        "approval_decisions",
        "action_requests",
        "receipt_projections",
    ] {
        sqlx::query(&format!("TRUNCATE TABLE {table} RESTART IDENTITY CASCADE"))
            .execute(&pool)
            .await
            .expect("truncate");
    }
    pool
}

fn object(id: &str, bytes: &[u8]) -> ProtocolObjectRecord {
    ProtocolObjectRecord {
        kind: "action_intent".to_string(),
        object_id_hex: id.to_string(),
        bytes: bytes.to_vec(),
    }
}

#[tokio::test]
#[ignore = "requires DATABASE_URL"]
async fn protocol_objects_are_immutable() {
    let pool = fresh_pool().await;
    let store = PgProtocolObjectStore::new(pool);

    store
        .put(&tenant(), object("aa", b"canonical"))
        .await
        .unwrap();
    store
        .put(&tenant(), object("aa", b"canonical"))
        .await
        .unwrap(); // idempotent
    let err = store
        .put(&tenant(), object("aa", b"tampered"))
        .await
        .unwrap_err();
    assert!(matches!(err, StorageError::ImmutableViolation { .. }));
    assert_eq!(
        store.get(&tenant(), "aa").await.unwrap().unwrap().bytes,
        b"canonical"
    );
}

#[tokio::test]
#[ignore = "requires DATABASE_URL"]
async fn mandate_cas_admits_one_winner() {
    let pool = fresh_pool().await;
    let store = PgMandateProjectionStore::new(pool);

    store.insert(&tenant(), "m1", "reserved").await.unwrap();
    let first = store
        .compare_and_swap(&tenant(), "m1", 1, "consumed")
        .await
        .unwrap();
    let second = store
        .compare_and_swap(&tenant(), "m1", 1, "abandoned")
        .await
        .unwrap();
    assert_eq!(first, CasOutcome::Applied { new_version: 2 });
    assert_eq!(second, CasOutcome::Conflict { current_version: 2 });
    assert_eq!(
        store
            .compare_and_swap(&tenant(), "absent", 1, "x")
            .await
            .unwrap(),
        CasOutcome::Missing
    );
}

#[tokio::test]
#[ignore = "requires DATABASE_URL"]
async fn webhook_deliveries_are_unique() {
    let pool = fresh_pool().await;
    let store = PgWebhookReceiptStore::new(pool);
    let receipt = WebhookReceipt {
        delivery_id: "d-1".to_string(),
        source: "github".to_string(),
        raw_digest: ContentDigest::of(b"payload"),
        received_at_unix_seconds: 1_700_000_000,
    };
    assert_eq!(
        store.record(&tenant(), receipt.clone()).await.unwrap(),
        WebhookRecordOutcome::Recorded
    );
    assert_eq!(
        store.record(&tenant(), receipt).await.unwrap(),
        WebhookRecordOutcome::Duplicate
    );
}

#[tokio::test]
#[ignore = "requires DATABASE_URL"]
async fn action_request_cas_admits_one_approver() {
    let pool = fresh_pool().await;
    let store = PgActionRequestStore::new(pool);

    store
        .insert(
            &tenant(),
            ActionRequest {
                request_id: "r1".to_string(),
                requested_by: "alice".to_string(),
                intent_id_hex: Some("deadbeef".to_string()),
                status: ActionRequestStatus::Pending,
                created_at_unix_seconds: 1_700_000_000,
            },
        )
        .await
        .unwrap();

    // Duplicate id is rejected.
    let dup = store
        .insert(
            &tenant(),
            ActionRequest {
                request_id: "r1".to_string(),
                requested_by: "alice".to_string(),
                intent_id_hex: None,
                status: ActionRequestStatus::Pending,
                created_at_unix_seconds: 1_700_000_001,
            },
        )
        .await;
    assert!(dup.is_err());

    // Round-trips the stored request including its status.
    let fetched = store.get(&tenant(), "r1").await.unwrap().unwrap();
    assert_eq!(fetched.status, ActionRequestStatus::Pending);
    assert_eq!(fetched.intent_id_hex.as_deref(), Some("deadbeef"));

    // Exactly one approver at version 1 wins; the loser sees the new version.
    let first = store
        .compare_and_swap(&tenant(), "r1", 1, ActionRequestStatus::Approved)
        .await
        .unwrap();
    let second = store
        .compare_and_swap(&tenant(), "r1", 1, ActionRequestStatus::Rejected)
        .await
        .unwrap();
    assert_eq!(first, CasOutcome::Applied { new_version: 2 });
    assert_eq!(second, CasOutcome::Conflict { current_version: 2 });
    assert_eq!(
        store.get(&tenant(), "r1").await.unwrap().unwrap().status,
        ActionRequestStatus::Approved
    );
    assert_eq!(
        store
            .compare_and_swap(&tenant(), "absent", 1, ActionRequestStatus::Approved)
            .await
            .unwrap(),
        CasOutcome::Missing
    );

    assert_eq!(store.list(&tenant()).await.unwrap().len(), 1);
}

#[tokio::test]
#[ignore = "requires DATABASE_URL"]
async fn approval_decisions_are_recorded_per_request() {
    let pool = fresh_pool().await;
    // A decision references an action request (FK), so seed the request first.
    let requests = PgActionRequestStore::new(pool.clone());
    requests
        .insert(
            &tenant(),
            ActionRequest {
                request_id: "r1".to_string(),
                requested_by: "alice".to_string(),
                intent_id_hex: Some("deadbeef".to_string()),
                status: ActionRequestStatus::Pending,
                created_at_unix_seconds: 1_700_000_000,
            },
        )
        .await
        .unwrap();

    let store = PgApprovalDecisionStore::new(pool);
    store
        .insert(
            &tenant(),
            ApprovalDecision {
                decision_id: "d1".to_string(),
                request_id: "r1".to_string(),
                decided_by: "bob".to_string(),
                decision: "approved".to_string(),
                intent_id_hex: Some("deadbeef".to_string()),
                decided_at_unix_seconds: 1_700_000_100,
            },
        )
        .await
        .unwrap();

    // The decision is bound to the exact intent digest the approver reviewed.
    let fetched = store.get(&tenant(), "d1").await.unwrap().unwrap();
    assert_eq!(fetched.intent_id_hex.as_deref(), Some("deadbeef"));
    assert_eq!(fetched.decision, "approved");

    let by_request = store.by_request(&tenant(), "r1").await.unwrap();
    assert_eq!(by_request.len(), 1);
    assert_eq!(by_request[0].decision_id, "d1");
    assert!(
        store
            .by_request(&tenant(), "other")
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
#[ignore = "requires DATABASE_URL"]
async fn audit_events_are_append_only_and_ordered() {
    let pool = fresh_pool().await;
    let log = PgAuditLog::new(pool);
    for decision in ["granted", "denied"] {
        log.append(
            &tenant(),
            AuditEvent {
                occurred_at_unix_seconds: 1,
                actor: Some("requester".to_string()),
                action: "approve".to_string(),
                decision: decision.to_string(),
                detail: String::new(),
            },
        )
        .await
        .unwrap();
    }
    let recent = log.recent(&tenant(), 10).await.unwrap();
    assert_eq!(recent.len(), 2);
    assert_eq!(recent[0].decision, "granted");
    assert_eq!(recent[1].decision, "denied");
}

#[tokio::test]
#[ignore = "requires DATABASE_URL"]
async fn tenant_composite_keys_and_background_listing_fail_closed() {
    let pool = fresh_pool().await;
    let a = TenantScope::new("tenant-a").unwrap();
    let b = TenantScope::new("tenant-b").unwrap();
    let outsider = TenantScope::new("tenant-c").unwrap();

    let objects = PgProtocolObjectStore::new(pool.clone());
    objects.put(&a, object("same-id", b"a")).await.unwrap();
    objects.put(&b, object("same-id", b"b")).await.unwrap();
    assert_eq!(
        objects.get(&a, "same-id").await.unwrap().unwrap().bytes,
        b"a"
    );
    assert_eq!(
        objects.get(&b, "same-id").await.unwrap().unwrap().bytes,
        b"b"
    );
    assert!(objects.get(&outsider, "same-id").await.unwrap().is_none());

    let mandates = PgMandateProjectionStore::new(pool.clone());
    mandates.insert(&a, "same-id", "issued").await.unwrap();
    mandates.insert(&b, "same-id", "issued").await.unwrap();
    mandates
        .compare_and_swap(&a, "same-id", 1, "consumed")
        .await
        .unwrap();
    assert_eq!(
        mandates.get(&b, "same-id").await.unwrap().unwrap().state,
        "issued"
    );
    assert_eq!(
        mandates
            .compare_and_swap(&outsider, "same-id", 1, "consumed")
            .await
            .unwrap(),
        CasOutcome::Missing
    );

    let receipts = PgReceiptProjectionStore::new(pool);
    for (scope, id) in [(&a, "receipt-a"), (&b, "receipt-b")] {
        receipts
            .insert(
                scope,
                ReceiptProjection {
                    receipt_id_hex: id.into(),
                    mandate_id_hex: "same-id".into(),
                    intent_id_hex: "intent".into(),
                    attempt_id_hex: format!("attempt-{id}"),
                    outcome: ReceiptOutcome::Succeeded,
                    created_at_unix_seconds: 1,
                    dispatch_evidence_refs: vec![],
                    target_evidence_refs: vec![],
                    evidence_gaps: vec![],
                    canonical_bytes: None,
                },
            )
            .await
            .unwrap();
    }
    assert_eq!(
        receipts.list_ids_ordered(&a).await.unwrap(),
        vec![("receipt-a".into(), 1)]
    );
    assert_eq!(
        receipts.list_ids_ordered(&b).await.unwrap(),
        vec![("receipt-b".into(), 1)]
    );
    assert!(
        receipts
            .list_ids_ordered(&outsider)
            .await
            .unwrap()
            .is_empty()
    );
}
