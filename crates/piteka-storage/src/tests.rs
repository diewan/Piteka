//! Portable adapter tests: immutability, CAS, webhook dedup, evidence, audit.
//!
//! These run without a database. The Postgres adapters are validated by the
//! `#[ignore]`d integration tests in `tests/postgres.rs` against the same rules.

use crate::digest::ContentDigest;
use crate::error::StorageError;
use crate::evidence::LocalEvidenceStore;
use crate::memory::{
    InMemoryAuditLog, InMemoryExecutionAttemptStore, InMemoryMandateProjectionStore,
    InMemoryProtocolObjectStore, InMemoryReceiptProjectionStore, InMemoryWebhookReceiptStore,
};
use crate::model::{
    AuditEvent, CasOutcome, EvidenceDescriptor, ExecutionAttempt, ExecutionAttemptState,
    ProtocolObjectRecord, ReceiptOutcome, ReceiptProjection, WebhookReceipt, WebhookRecordOutcome,
};
use crate::ports::{
    AuditLog, EvidenceObjectStore, ExecutionAttemptStore, MandateProjectionStore,
    ProtocolObjectStore, ReceiptProjectionStore, WebhookReceiptStore,
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

// ---------------------------------------------------------------------------
// Execution attempt and receipt projection tests (E-03)
// ---------------------------------------------------------------------------

fn make_attempt(id: &str, mandate: &str) -> ExecutionAttempt {
    ExecutionAttempt {
        attempt_id_hex: id.to_string(),
        mandate_id_hex: mandate.to_string(),
        intent_id_hex: "intent-abc123".to_string(),
        reservation_token_digest: "tok-digest".to_string(),
        executor_identity: "piteka-worker".to_string(),
        correlation_key: "corr-1".to_string(),
        started_at_unix_seconds: 1_000,
        dispatch_boundary_at_unix_seconds: None,
        state: ExecutionAttemptState::Prepared,
        github_deployment_id: None,
    }
}

#[tokio::test]
async fn execution_attempts_are_append_only() {
    let store = InMemoryExecutionAttemptStore::default();

    store.insert(make_attempt("att-1", "m1")).await.unwrap();
    store.insert(make_attempt("att-2", "m1")).await.unwrap();

    // Duplicate id is rejected.
    let err = store.insert(make_attempt("att-1", "m1")).await.unwrap_err();
    assert!(err.to_string().contains("already exists"));

    // Both attempts are retrievable.
    assert!(store.get("att-1").await.unwrap().is_some());
    assert!(store.get("att-2").await.unwrap().is_some());
    assert!(store.get("att-missing").await.unwrap().is_none());
}

#[tokio::test]
async fn execution_attempt_state_transitions_are_recorded() {
    let store = InMemoryExecutionAttemptStore::default();
    store.insert(make_attempt("att-1", "m1")).await.unwrap();

    store
        .update_state("att-1", ExecutionAttemptState::Dispatching)
        .await
        .unwrap();

    let attempt = store.get("att-1").await.unwrap().unwrap();
    assert_eq!(attempt.state, ExecutionAttemptState::Dispatching);

    // Updating a non-existent attempt fails.
    let err = store
        .update_state("att-missing", ExecutionAttemptState::Accepted)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("not found"));
}

#[tokio::test]
async fn execution_attempts_queryable_by_mandate() {
    let store = InMemoryExecutionAttemptStore::default();
    store.insert(make_attempt("att-1", "m1")).await.unwrap();
    store.insert(make_attempt("att-2", "m1")).await.unwrap();
    store.insert(make_attempt("att-3", "m2")).await.unwrap();

    let m1_attempts = store.by_mandate("m1").await.unwrap();
    assert_eq!(m1_attempts.len(), 2);

    let m2_attempts = store.by_mandate("m2").await.unwrap();
    assert_eq!(m2_attempts.len(), 1);

    let empty = store.by_mandate("m3").await.unwrap();
    assert!(empty.is_empty());
}

#[tokio::test]
async fn execution_attempts_queryable_by_deployment_id() {
    let store = InMemoryExecutionAttemptStore::default();
    
    let mut attempt1 = make_attempt("att-1", "m1");
    attempt1.github_deployment_id = Some(12345);
    store.insert(attempt1).await.unwrap();
    
    store.insert(make_attempt("att-2", "m1")).await.unwrap();
    store.insert(make_attempt("att-3", "m2")).await.unwrap();

    let found = store.by_deployment_id(12345).await.unwrap();
    assert!(found.is_some());
    assert_eq!(found.unwrap().attempt_id_hex, "att-1");

    let not_found = store.by_deployment_id(99999).await.unwrap();
    assert!(not_found.is_none());
}

#[tokio::test]
async fn receipt_projections_are_append_only() {
    let store = InMemoryReceiptProjectionStore::default();

    store.insert(ReceiptProjection {
        receipt_id_hex: "rcpt-1".to_string(),
        mandate_id_hex: "m1".to_string(),
        intent_id_hex: "intent-abc123".to_string(),
        attempt_id_hex: "att-1".to_string(),
        outcome: ReceiptOutcome::Succeeded,
        created_at_unix_seconds: 2_000,
        dispatch_evidence_refs: vec![],
        target_evidence_refs: vec![],
        evidence_gaps: vec![],
        canonical_bytes: None,
    })
    .await
    .unwrap();

    // Duplicate id is rejected.
    let err = store.insert(ReceiptProjection {
        receipt_id_hex: "rcpt-1".to_string(),
        mandate_id_hex: "m1".to_string(),
        intent_id_hex: "intent-abc123".to_string(),
        attempt_id_hex: "att-1".to_string(),
        outcome: ReceiptOutcome::Failed,
        created_at_unix_seconds: 2_001,
        dispatch_evidence_refs: vec![],
        target_evidence_refs: vec![],
        evidence_gaps: vec![],
        canonical_bytes: None,
    })
    .await
    .unwrap_err();
    assert!(err.to_string().contains("already exists"));
}

#[tokio::test]
async fn receipts_queryable_by_mandate() {
    let store = InMemoryReceiptProjectionStore::default();

    store.insert(ReceiptProjection {
        receipt_id_hex: "rcpt-1".to_string(),
        mandate_id_hex: "m1".to_string(),
        intent_id_hex: "intent-abc123".to_string(),
        attempt_id_hex: "att-1".to_string(),
        outcome: ReceiptOutcome::Succeeded,
        created_at_unix_seconds: 2_000,
        dispatch_evidence_refs: vec![],
        target_evidence_refs: vec![],
        evidence_gaps: vec![],
        canonical_bytes: None,
    })
    .await
    .unwrap();

    store.insert(ReceiptProjection {
        receipt_id_hex: "rcpt-2".to_string(),
        mandate_id_hex: "m1".to_string(),
        intent_id_hex: "intent-abc123".to_string(),
        attempt_id_hex: "att-2".to_string(),
        outcome: ReceiptOutcome::Unknown,
        created_at_unix_seconds: 2_001,
        dispatch_evidence_refs: vec![],
        target_evidence_refs: vec![],
        evidence_gaps: vec![],
        canonical_bytes: None,
    })
    .await
    .unwrap();

    let receipts = store.by_mandate("m1").await.unwrap();
    assert_eq!(receipts.len(), 2);
    assert_eq!(receipts[0].outcome, ReceiptOutcome::Succeeded);
    assert_eq!(receipts[1].outcome, ReceiptOutcome::Unknown);
}

#[tokio::test]
async fn execution_attempt_state_terminal_check() {
    assert!(!ExecutionAttemptState::Prepared.is_terminal());
    assert!(!ExecutionAttemptState::Dispatching.is_terminal());
    assert!(ExecutionAttemptState::Accepted.is_terminal());
    assert!(ExecutionAttemptState::Rejected.is_terminal());
    assert!(ExecutionAttemptState::OutcomeAmbiguous.is_terminal());
    assert!(ExecutionAttemptState::ReconciledAccepted.is_terminal());
    assert!(ExecutionAttemptState::ReconciledNotAccepted.is_terminal());
    assert!(ExecutionAttemptState::AbandonedAmbiguous.is_terminal());
}
