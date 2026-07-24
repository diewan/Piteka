//! Portable adapter tests: immutability, CAS, webhook dedup, evidence, audit.
//!
//! These run without a database. The Postgres adapters are validated by the
//! `#[ignore]`d integration tests in `tests/postgres.rs` against the same rules.

use crate::digest::ContentDigest;
use crate::error::StorageError;
use crate::evidence::LocalEvidenceStore;
use crate::memory::{
    InMemoryAuditLog, InMemoryExecutionAttemptStore, InMemoryInvestigatorCaseStore,
    InMemoryMandateProjectionStore, InMemoryProtocolObjectStore, InMemoryReceiptProjectionStore,
    InMemoryWebhookDeliveryStore,
};
use crate::model::{
    AuditEvent, CasOutcome, EvidenceDescriptor, ExecutionAttempt, ExecutionAttemptState,
    InvestigatorCase, ProtocolObjectRecord, ReceiptOutcome, ReceiptProjection,
    WebhookDeliveryRecord, WebhookRecordOutcome,
};
use crate::ports::{
    AuditLog, EvidenceObjectStore, ExecutionAttemptStore, InvestigatorCaseStore,
    MandateProjectionStore, ProtocolObjectStore, ReceiptProjectionStore, WebhookDeliveryStore,
};

fn scope(id: &str) -> crate::TenantScope {
    crate::TenantScope::new(id).unwrap()
}

fn record(id: &str, bytes: &[u8]) -> ProtocolObjectRecord {
    ProtocolObjectRecord {
        kind: "action_intent".to_string(),
        object_id_hex: id.to_string(),
        bytes: bytes.to_vec(),
    }
}

#[tokio::test]
async fn investigator_cases_are_partitioned_by_tenant() {
    let store = InMemoryInvestigatorCaseStore::default();
    for tenant in ["tenant-a", "tenant-b"] {
        store
            .create(
                &scope(tenant),
                InvestigatorCase {
                    tenant_id: tenant.into(),
                    case_id: "same-id".into(),
                    version: 0,
                    title: tenant.into(),
                    opened_by: "investigator".into(),
                    created_at_unix_seconds: 1,
                },
            )
            .await
            .unwrap();
    }
    assert_eq!(store.list(&scope("tenant-a")).await.unwrap().len(), 1);
    assert_eq!(
        store
            .get(&scope("tenant-a"), "same-id")
            .await
            .unwrap()
            .unwrap()
            .title,
        "tenant-a"
    );
    assert_eq!(
        store
            .get(&scope("tenant-b"), "same-id")
            .await
            .unwrap()
            .unwrap()
            .title,
        "tenant-b"
    );
    assert!(
        store
            .get(&scope("tenant-c"), "same-id")
            .await
            .unwrap()
            .is_none()
    );
}

#[test]
fn tenant_scope_rejects_unscoped_and_path_like_values() {
    for invalid in ["", " ", "../tenant", "tenant/child", "tenant\\child"] {
        assert!(
            crate::TenantScope::new(invalid).is_err(),
            "accepted {invalid:?}"
        );
    }
    assert!(crate::TenantScope::new("org-1:prod.eu").is_ok());
}

#[tokio::test]
async fn identical_ids_and_mutations_are_isolated_between_tenants() {
    let a = scope("tenant-a");
    let b = scope("tenant-b");
    let outsider = scope("tenant-c");

    let objects = InMemoryProtocolObjectStore::default();
    objects.put(&a, record("same-id", b"a")).await.unwrap();
    objects.put(&b, record("same-id", b"b")).await.unwrap();
    assert_eq!(
        objects.get(&a, "same-id").await.unwrap().unwrap().bytes,
        b"a"
    );
    assert_eq!(
        objects.get(&b, "same-id").await.unwrap().unwrap().bytes,
        b"b"
    );
    assert!(objects.get(&outsider, "same-id").await.unwrap().is_none());

    let mandates = InMemoryMandateProjectionStore::default();
    mandates.insert(&a, "same-id", "issued").await.unwrap();
    mandates.insert(&b, "same-id", "issued").await.unwrap();
    assert_eq!(
        mandates
            .compare_and_swap(&a, "same-id", 1, "consumed")
            .await
            .unwrap(),
        CasOutcome::Applied { new_version: 2 }
    );
    assert_eq!(
        mandates.get(&a, "same-id").await.unwrap().unwrap().state,
        "consumed"
    );
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

    let audit = InMemoryAuditLog::default();
    for (tenant, decision) in [(&a, "a"), (&b, "b")] {
        audit
            .append(
                tenant,
                AuditEvent {
                    occurred_at_unix_seconds: 1,
                    actor: None,
                    action: "test".into(),
                    decision: decision.into(),
                    detail: String::new(),
                },
            )
            .await
            .unwrap();
    }
    assert_eq!(audit.recent(&a, 10).await.unwrap()[0].decision, "a");
    assert_eq!(audit.recent(&b, 10).await.unwrap()[0].decision, "b");
    assert!(audit.recent(&outsider, 10).await.unwrap().is_empty());
}

#[tokio::test]
async fn filesystem_evidence_paths_are_tenant_partitioned() {
    let dir = tempfile::tempdir().unwrap();
    let store = LocalEvidenceStore::open(dir.path()).unwrap();
    let a = scope("tenant-a");
    let b = scope("tenant-b");
    let digest = store.put(&a, b"shared bytes").await.unwrap();

    assert_eq!(
        store.get(&a, &digest).await.unwrap().unwrap(),
        b"shared bytes"
    );
    assert!(store.get(&b, &digest).await.unwrap().is_none());
    assert!(
        dir.path()
            .join("blobs")
            .join("tenant-a")
            .join(digest.to_hex())
            .is_file()
    );
    assert!(
        !dir.path()
            .join("blobs")
            .join("tenant-b")
            .join(digest.to_hex())
            .exists()
    );
}

#[tokio::test]
async fn protocol_objects_are_immutable_but_idempotent() {
    let store = InMemoryProtocolObjectStore::default();
    store
        .put(&scope("test-tenant"), record("aa", b"canonical-bytes"))
        .await
        .unwrap();

    // Identical bytes: idempotent.
    store
        .put(&scope("test-tenant"), record("aa", b"canonical-bytes"))
        .await
        .unwrap();
    assert_eq!(
        store
            .get(&scope("test-tenant"), "aa")
            .await
            .unwrap()
            .unwrap()
            .bytes,
        b"canonical-bytes".to_vec()
    );

    // Different bytes for the same id: rejected, original preserved.
    let err = store
        .put(&scope("test-tenant"), record("aa", b"tampered"))
        .await
        .unwrap_err();
    assert!(matches!(err, StorageError::ImmutableViolation { .. }));
    assert_eq!(
        store
            .get(&scope("test-tenant"), "aa")
            .await
            .unwrap()
            .unwrap()
            .bytes,
        b"canonical-bytes".to_vec()
    );
}

#[tokio::test]
async fn mandate_cas_admits_exactly_one_winner() {
    let store = InMemoryMandateProjectionStore::default();
    store
        .insert(&scope("test-tenant"), "m1", "reserved")
        .await
        .unwrap();
    let start = store
        .get(&scope("test-tenant"), "m1")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(start.version, 1);

    // Two racers read version 1; only the first CAS applies.
    let first = store
        .compare_and_swap(&scope("test-tenant"), "m1", 1, "consumed")
        .await
        .unwrap();
    let second = store
        .compare_and_swap(&scope("test-tenant"), "m1", 1, "abandoned")
        .await
        .unwrap();

    assert_eq!(first, CasOutcome::Applied { new_version: 2 });
    assert_eq!(second, CasOutcome::Conflict { current_version: 2 });
    assert_eq!(
        store
            .get(&scope("test-tenant"), "m1")
            .await
            .unwrap()
            .unwrap()
            .state,
        "consumed"
    );
}

#[tokio::test]
async fn mandate_cas_reports_missing() {
    let store = InMemoryMandateProjectionStore::default();
    assert_eq!(
        store
            .compare_and_swap(&scope("test-tenant"), "absent", 1, "x")
            .await
            .unwrap(),
        CasOutcome::Missing
    );
}

#[tokio::test]
async fn webhook_deliveries_are_unique_and_idempotent() {
    let store = InMemoryWebhookDeliveryStore::default();
    let receipt = WebhookDeliveryRecord {
        delivery_id: "delivery-123".to_string(),
        source: "github".to_string(),
        raw_digest: ContentDigest::of(b"payload"),
        received_at_unix_seconds: 1_700_000_000,
    };
    assert_eq!(
        store
            .record(&scope("test-tenant"), receipt.clone())
            .await
            .unwrap(),
        WebhookRecordOutcome::Recorded
    );
    // A replayed delivery id is a no-op duplicate, not a second record.
    assert_eq!(
        store.record(&scope("test-tenant"), receipt).await.unwrap(),
        WebhookRecordOutcome::Duplicate
    );
    assert!(
        store
            .get(&scope("test-tenant"), "delivery-123")
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn audit_log_is_append_only_and_ordered() {
    let log = InMemoryAuditLog::default();
    for decision in ["granted", "denied"] {
        log.append(
            &scope("test-tenant"),
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
    let recent = log.recent(&scope("test-tenant"), 10).await.unwrap();
    assert_eq!(recent.len(), 2);
    assert_eq!(recent[0].decision, "granted");
    assert_eq!(recent[1].decision, "denied");
}

#[tokio::test]
async fn local_evidence_store_is_content_addressed_and_verifies_reads() {
    let dir = tempfile::tempdir().unwrap();
    let store = LocalEvidenceStore::open(dir.path()).unwrap();

    let digest = store
        .put(&scope("test-tenant"), b"evidence-bytes")
        .await
        .unwrap();
    assert_eq!(digest, ContentDigest::of(b"evidence-bytes"));
    // Idempotent re-put yields the same address.
    assert_eq!(
        store
            .put(&scope("test-tenant"), b"evidence-bytes")
            .await
            .unwrap(),
        digest
    );

    assert_eq!(
        store
            .get(&scope("test-tenant"), &digest)
            .await
            .unwrap()
            .unwrap(),
        b"evidence-bytes".to_vec()
    );
    assert!(
        store
            .get(&scope("test-tenant"), &ContentDigest::of(b"never-stored"))
            .await
            .unwrap()
            .is_none()
    );

    store
        .put_descriptor(
            &scope("test-tenant"),
            EvidenceDescriptor {
                digest,
                media_type: "application/json".to_string(),
                size_bytes: 14,
            },
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn local_evidence_store_detects_corruption_on_read() {
    let dir = tempfile::tempdir().unwrap();
    let store = LocalEvidenceStore::open(dir.path()).unwrap();
    let digest = store
        .put(&scope("test-tenant"), b"good-bytes")
        .await
        .unwrap();

    // Corrupt the blob on disk under its content address.
    let blob = dir
        .path()
        .join("blobs")
        .join(scope("test-tenant").as_str())
        .join(digest.to_hex());
    std::fs::write(&blob, b"corrupted").unwrap();

    let err = store.get(&scope("test-tenant"), &digest).await.unwrap_err();
    assert!(matches!(err, StorageError::EvidenceDigestMismatch { .. }));
}

#[tokio::test]
async fn local_evidence_store_survives_backup_and_restore() {
    // Filesystem backup/restore smoke test (the Postgres counterpart is the
    // ignored pg_dump/pg_restore integration test).
    let source = tempfile::tempdir().unwrap();
    let store = LocalEvidenceStore::open(source.path()).unwrap();
    let a = store
        .put(&scope("test-tenant"), b"artifact-a")
        .await
        .unwrap();
    let b = store
        .put(&scope("test-tenant"), b"artifact-b")
        .await
        .unwrap();

    // "Back up" by copying the tree, then restore into a fresh location.
    let restore = tempfile::tempdir().unwrap();
    copy_tree(source.path(), restore.path()).unwrap();
    let restored = LocalEvidenceStore::open(restore.path()).unwrap();

    assert_eq!(
        restored
            .get(&scope("test-tenant"), &a)
            .await
            .unwrap()
            .unwrap(),
        b"artifact-a".to_vec()
    );
    assert_eq!(
        restored
            .get(&scope("test-tenant"), &b)
            .await
            .unwrap()
            .unwrap(),
        b"artifact-b".to_vec()
    );
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

    store
        .insert(&scope("test-tenant"), make_attempt("att-1", "m1"))
        .await
        .unwrap();
    store
        .insert(&scope("test-tenant"), make_attempt("att-2", "m1"))
        .await
        .unwrap();

    // Duplicate id is rejected.
    let err = store
        .insert(&scope("test-tenant"), make_attempt("att-1", "m1"))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("already exists"));

    // Both attempts are retrievable.
    assert!(
        store
            .get(&scope("test-tenant"), "att-1")
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        store
            .get(&scope("test-tenant"), "att-2")
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        store
            .get(&scope("test-tenant"), "att-missing")
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn execution_attempt_state_transitions_are_recorded() {
    let store = InMemoryExecutionAttemptStore::default();
    store
        .insert(&scope("test-tenant"), make_attempt("att-1", "m1"))
        .await
        .unwrap();

    store
        .update_state(
            &scope("test-tenant"),
            "att-1",
            ExecutionAttemptState::Dispatching,
        )
        .await
        .unwrap();

    let attempt = store
        .get(&scope("test-tenant"), "att-1")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(attempt.state, ExecutionAttemptState::Dispatching);

    // Updating a non-existent attempt fails.
    let err = store
        .update_state(
            &scope("test-tenant"),
            "att-missing",
            ExecutionAttemptState::Accepted,
        )
        .await
        .unwrap_err();
    assert!(err.to_string().contains("not found"));
}

#[tokio::test]
async fn execution_attempts_queryable_by_mandate() {
    let store = InMemoryExecutionAttemptStore::default();
    store
        .insert(&scope("test-tenant"), make_attempt("att-1", "m1"))
        .await
        .unwrap();
    store
        .insert(&scope("test-tenant"), make_attempt("att-2", "m1"))
        .await
        .unwrap();
    store
        .insert(&scope("test-tenant"), make_attempt("att-3", "m2"))
        .await
        .unwrap();

    let m1_attempts = store.by_mandate(&scope("test-tenant"), "m1").await.unwrap();
    assert_eq!(m1_attempts.len(), 2);

    let m2_attempts = store.by_mandate(&scope("test-tenant"), "m2").await.unwrap();
    assert_eq!(m2_attempts.len(), 1);

    let empty = store.by_mandate(&scope("test-tenant"), "m3").await.unwrap();
    assert!(empty.is_empty());
}

#[tokio::test]
async fn execution_attempts_queryable_by_deployment_id() {
    let store = InMemoryExecutionAttemptStore::default();

    let mut attempt1 = make_attempt("att-1", "m1");
    attempt1.github_deployment_id = Some(12345);
    store.insert(&scope("test-tenant"), attempt1).await.unwrap();

    store
        .insert(&scope("test-tenant"), make_attempt("att-2", "m1"))
        .await
        .unwrap();
    store
        .insert(&scope("test-tenant"), make_attempt("att-3", "m2"))
        .await
        .unwrap();

    let found = store
        .by_deployment_id(&scope("test-tenant"), 12345)
        .await
        .unwrap();
    assert!(found.is_some());
    assert_eq!(found.unwrap().attempt_id_hex, "att-1");

    let not_found = store
        .by_deployment_id(&scope("test-tenant"), 99999)
        .await
        .unwrap();
    assert!(not_found.is_none());
}

#[tokio::test]
async fn receipt_projections_are_append_only() {
    let store = InMemoryReceiptProjectionStore::default();

    store
        .insert(
            &scope("test-tenant"),
            ReceiptProjection {
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
            },
        )
        .await
        .unwrap();

    // Duplicate id is rejected.
    let err = store
        .insert(
            &scope("test-tenant"),
            ReceiptProjection {
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
            },
        )
        .await
        .unwrap_err();
    assert!(err.to_string().contains("already exists"));
}

#[tokio::test]
async fn receipts_queryable_by_mandate() {
    let store = InMemoryReceiptProjectionStore::default();

    store
        .insert(
            &scope("test-tenant"),
            ReceiptProjection {
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
            },
        )
        .await
        .unwrap();

    store
        .insert(
            &scope("test-tenant"),
            ReceiptProjection {
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
            },
        )
        .await
        .unwrap();

    let receipts = store.by_mandate(&scope("test-tenant"), "m1").await.unwrap();
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

// ── NAM-02 rename compatibility ─────────────────────────────────────────────
//
// NAM-02 renamed `WebhookReceipt` to `WebhookDeliveryRecord` (and its store
// traits with it) so a transport deduplication row stops borrowing the
// protocol's reserved `Receipt` vocabulary. Nothing about the stored data
// changed: no table, column, or discriminator value moved, so there is no
// forward or backward migration and rollback is a source-level revert.

/// The rename is source-only: the SQL emitted by the Postgres store still names
/// the `webhook_receipts` table and its original columns.
#[test]
fn webhook_delivery_rename_did_not_move_the_table_or_columns() {
    let sql = include_str!("postgres.rs");
    assert!(
        sql.contains(
            "INSERT INTO webhook_receipts (tenant_id, delivery_id, source, raw_digest, received_at)"
        ),
        "the webhook_receipts insert must keep its table and column names"
    );
    assert!(
        sql.contains("FROM webhook_receipts WHERE tenant_id = $1 AND delivery_id = $2"),
        "the webhook_receipts lookup must keep its table and predicate"
    );

    // The migration that created the table is unchanged; no NAM-02 migration exists.
    let migration = include_str!("../../../migrations/0001_init.sql");
    assert!(migration.contains("webhook_receipts"));
}

/// A delivery record round-trips through the renamed in-memory store with every
/// field intact, and a repeat delivery id is still reported as a duplicate
/// rather than silently overwriting the retained raw digest.
#[tokio::test]
async fn webhook_delivery_record_round_trips_and_still_deduplicates() {
    let store = InMemoryWebhookDeliveryStore::default();
    let tenant = scope("tenant-a");
    let record = WebhookDeliveryRecord {
        delivery_id: "delivery-nam02".to_string(),
        source: "github".to_string(),
        raw_digest: ContentDigest::of(b"payload"),
        received_at_unix_seconds: 1_700_000_000,
    };

    assert_eq!(
        store.record(&tenant, record.clone()).await.unwrap(),
        WebhookRecordOutcome::Recorded
    );
    assert_eq!(
        store.record(&tenant, record.clone()).await.unwrap(),
        WebhookRecordOutcome::Duplicate,
        "a repeat delivery id must stay idempotent after the rename"
    );

    let found = store
        .get(&tenant, "delivery-nam02")
        .await
        .unwrap()
        .expect("recorded delivery must be readable");
    assert_eq!(found, record);
}
