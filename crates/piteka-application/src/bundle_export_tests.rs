//! Tests for bundle export (E-06).

use crate::SystemClock;
use crate::bundle_export::{assemble_bundle, export_manifest_bytes};
use crate::receipt_production::{parse_deployment_status, produce_receipt_from_webhook};
use piteka_storage::memory::{
    InMemoryAuditLog, InMemoryEvidenceNodeStore, InMemoryEvidenceStore,
    InMemoryExecutionAttemptStore, InMemoryProtocolObjectStore, InMemoryReceiptProjectionStore,
    InMemorySealConsumptionStore,
};
use piteka_storage::model::{ExecutionAttempt, ExecutionAttemptState, SealConsumptionProofRecord};
use piteka_storage::ports::{
    ExecutionAttemptStore, ProtocolObjectStore, ReceiptProjectionStore, SealConsumptionStore,
};

fn sample_attempt(deployment_id: u64) -> ExecutionAttempt {
    ExecutionAttempt {
        attempt_id_hex: "att-mand-002".to_string(),
        mandate_id_hex: "mand-002".to_string(),
        intent_id_hex: "intent-002".to_string(),
        reservation_token_digest: "secret".to_string(),
        executor_identity: "piteka-worker".to_string(),
        correlation_key: "deploy-staging-001".to_string(),
        started_at_unix_seconds: 1699999999,
        dispatch_boundary_at_unix_seconds: Some(1699999999),
        state: ExecutionAttemptState::Accepted,
        github_deployment_id: Some(deployment_id),
    }
}

fn success_payload() -> Vec<u8> {
    br#"{"status":"completed","state":"success","deployment":{"id":42},"updated_at":1700000000}"#
        .to_vec()
}

#[tokio::test]
async fn assemble_bundle_success() {
    let clock = SystemClock;

    // Setup all stores.
    let attempt_store = std::sync::Arc::new(InMemoryExecutionAttemptStore::default());
    let receipt_store = std::sync::Arc::new(InMemoryReceiptProjectionStore::default());
    let evidence_store = std::sync::Arc::new(InMemoryEvidenceNodeStore::default());
    let evidence_blob_store = std::sync::Arc::new(InMemoryEvidenceStore::default());
    let audit_log = std::sync::Arc::new(InMemoryAuditLog::default());
    let protocol_store = std::sync::Arc::new(InMemoryProtocolObjectStore::default());

    // Insert execution attempt.
    let attempt = sample_attempt(42);
    attempt_store.insert(attempt).await.unwrap();

    // Produce receipt via webhook processing.
    let payload = success_payload();
    let event = parse_deployment_status(&payload).expect("should parse");
    let result = produce_receipt_from_webhook(
        &*receipt_store,
        &*evidence_store,
        &*audit_log,
        &*attempt_store,
        &event,
        &clock,
    )
    .await
    .unwrap();

    // Assemble bundle.
    let bundle = assemble_bundle(
        &*receipt_store,
        &*evidence_store,
        &*evidence_blob_store,
        &*protocol_store,
        &InMemorySealConsumptionStore::default(),
        &result.receipt_id_hex,
    )
    .await;
    assert!(bundle.is_ok(), "bundle assembly should succeed");

    let bundle = bundle.unwrap();
    assert!(!bundle.bundle_id_hex.is_empty());
    assert_eq!(bundle.receipt_id_hex, result.receipt_id_hex);
    assert_eq!(bundle.mandate_id_hex, "mand-002");
    assert!(!bundle.evidence_node_ids.is_empty());
}

#[tokio::test]
async fn manifest_discloses_a_stored_single_use_anchor_and_omits_an_absent_one() {
    let receipt_store = InMemoryReceiptProjectionStore::default();
    let evidence_store = InMemoryEvidenceNodeStore::default();
    let seal_store = InMemorySealConsumptionStore::default();

    receipt_store
        .insert(piteka_storage::model::ReceiptProjection {
            receipt_id_hex: "rcpt-anchor".into(),
            mandate_id_hex: "mandate-anchor".into(),
            intent_id_hex: "intent".into(),
            attempt_id_hex: "attempt".into(),
            outcome: piteka_storage::model::ReceiptOutcome::Succeeded,
            created_at_unix_seconds: 1,
            dispatch_evidence_refs: vec![],
            target_evidence_refs: vec![],
            evidence_gaps: vec![],
            canonical_bytes: None,
        })
        .await
        .unwrap();

    // With no stored proof, the manifest carries an explicit null anchor (a limitation).
    let bytes = export_manifest_bytes(&receipt_store, &evidence_store, &seal_store, "rcpt-anchor")
        .await
        .unwrap();
    let manifest: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert!(manifest["single_use_anchor"].is_null());

    // Once the proof exists for the receipt's mandate, the manifest discloses it verbatim.
    seal_store
        .put(SealConsumptionProofRecord {
            mandate_id_hex: "mandate-anchor".into(),
            seal_id_hex: "aa".repeat(32),
            nullifier_hex: "bb".repeat(32),
            commitment_hex: "cc".repeat(32),
            anchor_backend: "csv-seal.local.v1".into(),
        })
        .await
        .unwrap();
    let bytes = export_manifest_bytes(&receipt_store, &evidence_store, &seal_store, "rcpt-anchor")
        .await
        .unwrap();
    let manifest: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let anchor = &manifest["single_use_anchor"];
    assert_eq!(anchor["seal_id_hex"], "aa".repeat(32));
    assert_eq!(anchor["nullifier_hex"], "bb".repeat(32));
    assert_eq!(anchor["commitment_hex"], "cc".repeat(32));
    assert_eq!(anchor["anchor_backend"], "csv-seal.local.v1");
}

#[tokio::test]
async fn assemble_bundle_receipt_not_found() {
    let evidence_store = std::sync::Arc::new(InMemoryEvidenceNodeStore::default());
    let evidence_blob_store = std::sync::Arc::new(InMemoryEvidenceStore::default());
    let protocol_store = std::sync::Arc::new(InMemoryProtocolObjectStore::default());
    let receipt_store = std::sync::Arc::new(InMemoryReceiptProjectionStore::default());

    let result = assemble_bundle(
        &*receipt_store,
        &*evidence_store,
        &*evidence_blob_store,
        &*protocol_store,
        &InMemorySealConsumptionStore::default(),
        "rcpt-nonexistent",
    )
    .await;
    assert!(result.is_err());
}

#[tokio::test]
async fn assemble_bundle_fails_closed_when_referenced_evidence_is_missing() {
    let receipt_store = InMemoryReceiptProjectionStore::default();
    let evidence_store = InMemoryEvidenceNodeStore::default();
    let evidence_blob_store = InMemoryEvidenceStore::default();
    let protocol_store = InMemoryProtocolObjectStore::default();

    receipt_store
        .insert(piteka_storage::model::ReceiptProjection {
            receipt_id_hex: "rcpt-missing".into(),
            mandate_id_hex: "mandate".into(),
            intent_id_hex: "intent".into(),
            attempt_id_hex: "attempt".into(),
            outcome: piteka_storage::model::ReceiptOutcome::Unknown,
            created_at_unix_seconds: 1,
            dispatch_evidence_refs: vec!["ev-absent".into()],
            target_evidence_refs: vec![],
            evidence_gaps: vec![],
            canonical_bytes: None,
        })
        .await
        .unwrap();

    let error = assemble_bundle(
        &receipt_store,
        &evidence_store,
        &evidence_blob_store,
        &protocol_store,
        &InMemorySealConsumptionStore::default(),
        "rcpt-missing",
    )
    .await
    .expect_err("missing referenced evidence must reject export");

    assert!(matches!(
        error,
        crate::bundle_export::BundleExportError::IncompleteEvidence { missing, .. }
            if missing == vec!["ev-absent"]
    ));
}

#[tokio::test]
async fn bundle_contains_source_attribution() {
    let clock = SystemClock;

    let attempt_store = std::sync::Arc::new(InMemoryExecutionAttemptStore::default());
    let receipt_store = std::sync::Arc::new(InMemoryReceiptProjectionStore::default());
    let evidence_store = std::sync::Arc::new(InMemoryEvidenceNodeStore::default());
    let evidence_blob_store = std::sync::Arc::new(InMemoryEvidenceStore::default());
    let audit_log = std::sync::Arc::new(InMemoryAuditLog::default());
    let protocol_store = std::sync::Arc::new(InMemoryProtocolObjectStore::default());

    let attempt = sample_attempt(42);
    attempt_store.insert(attempt).await.unwrap();

    let payload = success_payload();
    let event = parse_deployment_status(&payload).expect("should parse");
    let result = produce_receipt_from_webhook(
        &*receipt_store,
        &*evidence_store,
        &*audit_log,
        &*attempt_store,
        &event,
        &clock,
    )
    .await
    .unwrap();

    let bundle = assemble_bundle(
        &*receipt_store,
        &*evidence_store,
        &*evidence_blob_store,
        &*protocol_store,
        &InMemorySealConsumptionStore::default(),
        &result.receipt_id_hex,
    )
    .await
    .unwrap();

    // The bundle should have evidence nodes.
    assert!(!bundle.evidence_node_ids.is_empty());

    // The protocol store should contain the bundle.
    let stored = protocol_store.get(&bundle.bundle_id_hex).await.unwrap();
    assert!(
        stored.is_some(),
        "bundle should be stored in protocol objects"
    );
}
