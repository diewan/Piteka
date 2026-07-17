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
    AuditEvent, CasOutcome, ProtocolObjectRecord, WebhookReceipt, WebhookRecordOutcome,
};
use piteka_storage::ports::{
    AuditLog, MandateProjectionStore, ProtocolObjectStore, WebhookReceiptStore,
};
use piteka_storage::postgres::{
    PgAuditLog, PgMandateProjectionStore, PgProtocolObjectStore, PgWebhookReceiptStore, connect,
    run_migrations,
};
use piteka_storage::{ContentDigest, StorageError};
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

    store.put(object("aa", b"canonical")).await.unwrap();
    store.put(object("aa", b"canonical")).await.unwrap(); // idempotent
    let err = store.put(object("aa", b"tampered")).await.unwrap_err();
    assert!(matches!(err, StorageError::ImmutableViolation { .. }));
    assert_eq!(store.get("aa").await.unwrap().unwrap().bytes, b"canonical");
}

#[tokio::test]
#[ignore = "requires DATABASE_URL"]
async fn mandate_cas_admits_one_winner() {
    let pool = fresh_pool().await;
    let store = PgMandateProjectionStore::new(pool);

    store.insert("m1", "reserved").await.unwrap();
    let first = store.compare_and_swap("m1", 1, "consumed").await.unwrap();
    let second = store.compare_and_swap("m1", 1, "abandoned").await.unwrap();
    assert_eq!(first, CasOutcome::Applied { new_version: 2 });
    assert_eq!(second, CasOutcome::Conflict { current_version: 2 });
    assert_eq!(
        store.compare_and_swap("absent", 1, "x").await.unwrap(),
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
        store.record(receipt.clone()).await.unwrap(),
        WebhookRecordOutcome::Recorded
    );
    assert_eq!(
        store.record(receipt).await.unwrap(),
        WebhookRecordOutcome::Duplicate
    );
}

#[tokio::test]
#[ignore = "requires DATABASE_URL"]
async fn audit_events_are_append_only_and_ordered() {
    let pool = fresh_pool().await;
    let log = PgAuditLog::new(pool);
    for decision in ["granted", "denied"] {
        log.append(AuditEvent {
            occurred_at_unix_seconds: 1,
            actor: Some("requester".to_string()),
            action: "approve".to_string(),
            decision: decision.to_string(),
            detail: String::new(),
        })
        .await
        .unwrap();
    }
    let recent = log.recent(10).await.unwrap();
    assert_eq!(recent.len(), 2);
    assert_eq!(recent[0].decision, "granted");
    assert_eq!(recent[1].decision, "denied");
}
