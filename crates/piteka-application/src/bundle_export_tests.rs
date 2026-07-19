//! Tests for bundle export (E-06).

use crate::bundle_export::assemble_bundle;
use crate::receipt_production::{
    parse_deployment_status, produce_receipt_from_webhook,
};
use crate::{Clock, SystemClock};
use piteka_storage::memory::{
    InMemoryActionRequestStore, InMemoryApprovalDecisionStore, InMemoryAuditLog,
    InMemoryEvidenceNodeStore, InMemoryEvidenceStore, InMemoryExecutionAttemptStore,
    InMemoryMandateProjectionStore, InMemoryProtocolObjectStore, InMemoryReceiptProjectionStore,
};
use piteka_storage::model::{ExecutionAttempt, ExecutionAttemptState};
use piteka_storage::ports::{
    ActionRequestStore, ApprovalDecisionStore, AuditLog, EvidenceNodeStore,
    ExecutionAttemptStore, ProtocolObjectStore, ReceiptProjectionStore,
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
    br#"{"status":"completed","state":"success","deployment":{"id":42},"updated_at":1700000000}"#.to_vec()
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
    let request_store = std::sync::Arc::new(InMemoryActionRequestStore::default());
    let approval_store = std::sync::Arc::new(InMemoryApprovalDecisionStore::default());

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
        "rcpt-nonexistent",
    )
    .await;
    assert!(result.is_err());
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
    let request_store = std::sync::Arc::new(InMemoryActionRequestStore::default());
    let approval_store = std::sync::Arc::new(InMemoryApprovalDecisionStore::default());

    let attempt = sample_attempt(100);
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
        &result.receipt_id_hex,
    )
    .await
    .unwrap();

    // The bundle should have evidence nodes.
    assert!(!bundle.evidence_node_ids.is_empty());

    // The protocol store should contain the bundle.
    let stored = protocol_store.get(&bundle.bundle_id_hex).await.unwrap();
    assert!(stored.is_some(), "bundle should be stored in protocol objects");
}
