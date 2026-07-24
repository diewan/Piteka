//! PostgreSQL integration tests.
//!
//! Ignored by default because they need a database. Bring one up from the
//! repository's own deployment stack and run them:
//!
//! ```bash
//! deployment/scripts/up.sh infra
//! DATABASE_URL=postgres://zorvan@127.0.0.1:55432/postgres \
//!   cargo test -p piteka-storage --features postgres --test postgres -- --ignored
//! ```
//!
//! They assert the Postgres adapters uphold the same immutability, CAS,
//! webhook-uniqueness, and append-only rules the in-memory adapters enforce.
//!
//! # Isolation
//!
//! Each test works inside its own generated [`TenantScope`], so they are safe to
//! run in parallel and need no `--test-threads=1`. Isolating by tenant rather
//! than by truncating shared tables is deliberate: the schema's composite
//! `(tenant_id, …)` keys are the same mechanism production relies on, so the
//! tests exercise it on every run instead of only in
//! `tenant_composite_keys_and_background_listing_fail_closed`. It also means a
//! failed run leaves its rows behind for inspection rather than having the next
//! run erase them, and a developer's own data in a shared database is never
//! destroyed by running the suite.
#![cfg(feature = "postgres")]

use piteka_storage::model::{
    ActionRequest, ActionRequestStatus, ApprovalDecision, AuditEvent, CasOutcome,
    ProtocolObjectRecord, ReceiptOutcome, ReceiptProjection, WebhookDeliveryRecord,
    WebhookRecordOutcome,
};
use piteka_storage::ports::{
    ActionRequestStore, ApprovalDecisionStore, AuditLog, MandateProjectionStore,
    ProtocolObjectStore, ReceiptProjectionStore, WebhookDeliveryStore,
};
use piteka_storage::postgres::{
    PgActionRequestStore, PgApprovalDecisionStore, PgAuditLog, PgMandateProjectionStore,
    PgProtocolObjectStore, PgReceiptProjectionStore, PgWebhookDeliveryStore, connect,
    run_migrations,
};
use piteka_storage::{ContentDigest, StorageError, TenantScope};

use sqlx::postgres::PgPool;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// Returns a tenant scope unique to this call, and therefore to this test.
///
/// The process id and start time separate concurrent or repeated runs against a
/// shared database; the counter separates tests within one run. `label` keeps a
/// leftover row from a failed run traceable to the test that wrote it.
fn unique_tenant(label: &str) -> TenantScope {
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    static RUN_ID: std::sync::OnceLock<String> = std::sync::OnceLock::new();

    let run = RUN_ID.get_or_init(|| {
        let seconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock is after the Unix epoch")
            .as_secs();
        format!("{}-{seconds}", std::process::id())
    });
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    TenantScope::new(format!("it-{run}-{n}-{label}")).expect("generated tenant scope is valid")
}

/// Connects and ensures the schema exists.
///
/// `run_migrations` is safe to call from every test: sqlx takes a Postgres
/// advisory lock for the duration of a migration run, so concurrent callers
/// serialize and only the first does any work.
async fn pool() -> PgPool {
    let url = std::env::var("DATABASE_URL").expect(
        "DATABASE_URL must be set for --ignored tests; \
         start one with deployment/scripts/up.sh infra",
    );
    let pool = connect(&url).await.expect("connect");
    run_migrations(&pool).await.expect("migrations");
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
    let tenant = unique_tenant("protocol-objects");
    let store = PgProtocolObjectStore::new(pool().await);

    store
        .put(&tenant, object("aa", b"canonical"))
        .await
        .unwrap();
    store
        .put(&tenant, object("aa", b"canonical"))
        .await
        .unwrap(); // idempotent
    let err = store
        .put(&tenant, object("aa", b"tampered"))
        .await
        .unwrap_err();
    assert!(matches!(err, StorageError::ImmutableViolation { .. }));
    assert_eq!(
        store.get(&tenant, "aa").await.unwrap().unwrap().bytes,
        b"canonical"
    );
}

#[tokio::test]
#[ignore = "requires DATABASE_URL"]
async fn mandate_cas_admits_one_winner() {
    let tenant = unique_tenant("mandate-cas");
    let store = PgMandateProjectionStore::new(pool().await);

    store.insert(&tenant, "m1", "reserved").await.unwrap();
    let first = store
        .compare_and_swap(&tenant, "m1", 1, "consumed")
        .await
        .unwrap();
    let second = store
        .compare_and_swap(&tenant, "m1", 1, "abandoned")
        .await
        .unwrap();
    assert_eq!(first, CasOutcome::Applied { new_version: 2 });
    assert_eq!(second, CasOutcome::Conflict { current_version: 2 });
    assert_eq!(
        store
            .compare_and_swap(&tenant, "absent", 1, "x")
            .await
            .unwrap(),
        CasOutcome::Missing
    );
}

#[tokio::test]
#[ignore = "requires DATABASE_URL"]
async fn webhook_deliveries_are_unique() {
    let tenant = unique_tenant("webhook-deliveries");
    let store = PgWebhookDeliveryStore::new(pool().await);
    let receipt = WebhookDeliveryRecord {
        delivery_id: "d-1".to_string(),
        source: "github".to_string(),
        raw_digest: ContentDigest::of(b"payload"),
        received_at_unix_seconds: 1_700_000_000,
    };
    assert_eq!(
        store.record(&tenant, receipt.clone()).await.unwrap(),
        WebhookRecordOutcome::Recorded
    );
    assert_eq!(
        store.record(&tenant, receipt).await.unwrap(),
        WebhookRecordOutcome::Duplicate
    );
}

#[tokio::test]
#[ignore = "requires DATABASE_URL"]
async fn action_request_cas_admits_one_approver() {
    let tenant = unique_tenant("action-request-cas");
    let store = PgActionRequestStore::new(pool().await);

    store
        .insert(
            &tenant,
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
            &tenant,
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
    let fetched = store.get(&tenant, "r1").await.unwrap().unwrap();
    assert_eq!(fetched.status, ActionRequestStatus::Pending);
    assert_eq!(fetched.intent_id_hex.as_deref(), Some("deadbeef"));

    // Exactly one approver at version 1 wins; the loser sees the new version.
    let first = store
        .compare_and_swap(&tenant, "r1", 1, ActionRequestStatus::Approved)
        .await
        .unwrap();
    let second = store
        .compare_and_swap(&tenant, "r1", 1, ActionRequestStatus::Rejected)
        .await
        .unwrap();
    assert_eq!(first, CasOutcome::Applied { new_version: 2 });
    assert_eq!(second, CasOutcome::Conflict { current_version: 2 });
    assert_eq!(
        store.get(&tenant, "r1").await.unwrap().unwrap().status,
        ActionRequestStatus::Approved
    );
    assert_eq!(
        store
            .compare_and_swap(&tenant, "absent", 1, ActionRequestStatus::Approved)
            .await
            .unwrap(),
        CasOutcome::Missing
    );

    assert_eq!(store.list(&tenant).await.unwrap().len(), 1);
}

#[tokio::test]
#[ignore = "requires DATABASE_URL"]
async fn approval_decisions_are_recorded_per_request() {
    let tenant = unique_tenant("approval-decisions");
    let pool = pool().await;
    // A decision references an action request (FK), so seed the request first.
    let requests = PgActionRequestStore::new(pool.clone());
    requests
        .insert(
            &tenant,
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
            &tenant,
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
    let fetched = store.get(&tenant, "d1").await.unwrap().unwrap();
    assert_eq!(fetched.intent_id_hex.as_deref(), Some("deadbeef"));
    assert_eq!(fetched.decision, "approved");

    let by_request = store.by_request(&tenant, "r1").await.unwrap();
    assert_eq!(by_request.len(), 1);
    assert_eq!(by_request[0].decision_id, "d1");
    assert!(store.by_request(&tenant, "other").await.unwrap().is_empty());
}

#[tokio::test]
#[ignore = "requires DATABASE_URL"]
async fn audit_events_are_append_only_and_ordered() {
    let tenant = unique_tenant("audit-events");
    let log = PgAuditLog::new(pool().await);
    for decision in ["granted", "denied"] {
        log.append(
            &tenant,
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
    let recent = log.recent(&tenant, 10).await.unwrap();
    assert_eq!(recent.len(), 2);
    assert_eq!(recent[0].decision, "granted");
    assert_eq!(recent[1].decision, "denied");
}

#[tokio::test]
#[ignore = "requires DATABASE_URL"]
async fn tenant_composite_keys_and_background_listing_fail_closed() {
    let pool = pool().await;
    // Three distinct tenants that use the *same* object ids: the point is that
    // the composite key, not the id, is what keeps them apart.
    let a = unique_tenant("composite-a");
    let b = unique_tenant("composite-b");
    let outsider = unique_tenant("composite-outsider");

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
