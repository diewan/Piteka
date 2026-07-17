//! Portable adapter tests: immutability, CAS, webhook dedup, evidence, audit.
//!
//! These run without a database. The Postgres adapters are validated by the
//! `#[ignore]`d integration tests in `tests/postgres.rs` against the same rules.

use crate::digest::ContentDigest;
use crate::error::StorageError;
use crate::evidence::LocalEvidenceStore;
use crate::memory::{
    InMemoryAuditLog, InMemoryMandateProjectionStore, InMemoryProtocolObjectStore,
    InMemoryWebhookReceiptStore,
};
use crate::model::{
    AuditEvent, CasOutcome, EvidenceDescriptor, ProtocolObjectRecord, WebhookReceipt,
    WebhookRecordOutcome,
};
use crate::ports::{
    AuditLog, EvidenceObjectStore, MandateProjectionStore, ProtocolObjectStore, WebhookReceiptStore,
};

fn record(id: &str, bytes: &[u8]) -> ProtocolObjectRecord {
    ProtocolObjectRecord {
        kind: "action_intent".to_string(),
        object_id_hex: id.to_string(),
        bytes: bytes.to_vec(),
    }
}

#[tokio::test]
async fn protocol_objects_are_immutable_but_idempotent() {
    let store = InMemoryProtocolObjectStore::default();
    store.put(record("aa", b"canonical-bytes")).await.unwrap();

    // Identical bytes: idempotent.
    store.put(record("aa", b"canonical-bytes")).await.unwrap();
    assert_eq!(
        store.get("aa").await.unwrap().unwrap().bytes,
        b"canonical-bytes".to_vec()
    );

    // Different bytes for the same id: rejected, original preserved.
    let err = store.put(record("aa", b"tampered")).await.unwrap_err();
    assert!(matches!(err, StorageError::ImmutableViolation { .. }));
    assert_eq!(
        store.get("aa").await.unwrap().unwrap().bytes,
        b"canonical-bytes".to_vec()
    );
}

#[tokio::test]
async fn mandate_cas_admits_exactly_one_winner() {
    let store = InMemoryMandateProjectionStore::default();
    store.insert("m1", "reserved").await.unwrap();
    let start = store.get("m1").await.unwrap().unwrap();
    assert_eq!(start.version, 1);

    // Two racers read version 1; only the first CAS applies.
    let first = store.compare_and_swap("m1", 1, "consumed").await.unwrap();
    let second = store.compare_and_swap("m1", 1, "abandoned").await.unwrap();

    assert_eq!(first, CasOutcome::Applied { new_version: 2 });
    assert_eq!(second, CasOutcome::Conflict { current_version: 2 });
    assert_eq!(store.get("m1").await.unwrap().unwrap().state, "consumed");
}

#[tokio::test]
async fn mandate_cas_reports_missing() {
    let store = InMemoryMandateProjectionStore::default();
    assert_eq!(
        store.compare_and_swap("absent", 1, "x").await.unwrap(),
        CasOutcome::Missing
    );
}

#[tokio::test]
async fn webhook_deliveries_are_unique_and_idempotent() {
    let store = InMemoryWebhookReceiptStore::default();
    let receipt = WebhookReceipt {
        delivery_id: "delivery-123".to_string(),
        source: "github".to_string(),
        raw_digest: ContentDigest::of(b"payload"),
        received_at_unix_seconds: 1_700_000_000,
    };
    assert_eq!(
        store.record(receipt.clone()).await.unwrap(),
        WebhookRecordOutcome::Recorded
    );
    // A replayed delivery id is a no-op duplicate, not a second record.
    assert_eq!(
        store.record(receipt).await.unwrap(),
        WebhookRecordOutcome::Duplicate
    );
    assert!(store.get("delivery-123").await.unwrap().is_some());
}

#[tokio::test]
async fn audit_log_is_append_only_and_ordered() {
    let log = InMemoryAuditLog::default();
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

#[tokio::test]
async fn local_evidence_store_is_content_addressed_and_verifies_reads() {
    let dir = tempfile::tempdir().unwrap();
    let store = LocalEvidenceStore::open(dir.path()).unwrap();

    let digest = store.put(b"evidence-bytes").await.unwrap();
    assert_eq!(digest, ContentDigest::of(b"evidence-bytes"));
    // Idempotent re-put yields the same address.
    assert_eq!(store.put(b"evidence-bytes").await.unwrap(), digest);

    assert_eq!(
        store.get(&digest).await.unwrap().unwrap(),
        b"evidence-bytes".to_vec()
    );
    assert!(
        store
            .get(&ContentDigest::of(b"never-stored"))
            .await
            .unwrap()
            .is_none()
    );

    store
        .put_descriptor(EvidenceDescriptor {
            digest,
            media_type: "application/json".to_string(),
            size_bytes: 14,
        })
        .await
        .unwrap();
}

#[tokio::test]
async fn local_evidence_store_detects_corruption_on_read() {
    let dir = tempfile::tempdir().unwrap();
    let store = LocalEvidenceStore::open(dir.path()).unwrap();
    let digest = store.put(b"good-bytes").await.unwrap();

    // Corrupt the blob on disk under its content address.
    let blob = dir.path().join("blobs").join(digest.to_hex());
    std::fs::write(&blob, b"corrupted").unwrap();

    let err = store.get(&digest).await.unwrap_err();
    assert!(matches!(err, StorageError::EvidenceDigestMismatch { .. }));
}

#[tokio::test]
async fn local_evidence_store_survives_backup_and_restore() {
    // Filesystem backup/restore smoke test (the Postgres counterpart is the
    // ignored pg_dump/pg_restore integration test).
    let source = tempfile::tempdir().unwrap();
    let store = LocalEvidenceStore::open(source.path()).unwrap();
    let a = store.put(b"artifact-a").await.unwrap();
    let b = store.put(b"artifact-b").await.unwrap();

    // "Back up" by copying the tree, then restore into a fresh location.
    let restore = tempfile::tempdir().unwrap();
    copy_tree(source.path(), restore.path()).unwrap();
    let restored = LocalEvidenceStore::open(restore.path()).unwrap();

    assert_eq!(restored.get(&a).await.unwrap().unwrap(), b"artifact-a".to_vec());
    assert_eq!(restored.get(&b).await.unwrap().unwrap(), b"artifact-b".to_vec());
}

fn copy_tree(from: &std::path::Path, to: &std::path::Path) -> std::io::Result<()> {
    for entry in std::fs::read_dir(from)? {
        let entry = entry?;
        let target = to.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            std::fs::create_dir_all(&target)?;
            copy_tree(&entry.path(), &target)?;
        } else {
            std::fs::copy(entry.path(), target)?;
        }
    }
    Ok(())
}
