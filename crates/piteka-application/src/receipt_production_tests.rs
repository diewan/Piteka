//! Tests for receipt production (E-06).

use crate::SystemClock;
use crate::receipt_production::{
    map_github_state_to_outcome, parse_deployment_status, produce_receipt_from_webhook,
};
use piteka_storage::memory::{
    InMemoryAuditLog, InMemoryEvidenceNodeStore, InMemoryExecutionAttemptStore,
    InMemoryReceiptProjectionStore,
};
use piteka_storage::model::{
    EvidenceSource, ExecutionAttempt, ExecutionAttemptState, ReceiptOutcome,
};
use piteka_storage::ports::{EvidenceNodeStore, ExecutionAttemptStore, ReceiptProjectionStore};

fn tenant() -> piteka_storage::TenantScope {
    piteka_storage::TenantScope::new("test-tenant").unwrap()
}

// ---------------------------------------------------------------------------
// Helper: create a sample deployment status payload
// ---------------------------------------------------------------------------

fn sample_deployment_success_payload(deployment_id: u64) -> Vec<u8> {
    format!(r#"{{"status":"completed","state":"success","deployment":{{"id":{}}},"updated_at":1700000000}}"#, deployment_id).into_bytes()
}

#[test]
fn parse_deployment_status_accepts_github_rfc3339_timestamp() {
    let payload =
        br#"{"state":"success","deployment":{"id":42},"updated_at":"2023-11-14T22:13:20Z"}"#;
    let event = parse_deployment_status(payload).expect("GitHub timestamp should parse");
    assert_eq!(event.updated_at, 1_700_000_000);
}

#[test]
fn parse_deployment_status_accepts_live_github_envelope() {
    let payload = br#"{
      "deployment":{"id":5519643441},
      "deployment_status":{
        "state":"success",
        "description":"Piteka deployment consumer terminal status",
        "target_url":"https://github.com/zorvan/piteka-demo/actions/runs/29732092691",
        "updated_at":"2026-07-20T09:36:51Z"
      }
    }"#;
    let event = parse_deployment_status(payload).expect("live GitHub envelope should parse");
    assert_eq!(event.deployment_id, 5_519_643_441);
    assert_eq!(event.state, "success");
    assert_eq!(event.updated_at, 1_784_540_211);
}

#[test]
fn parse_deployment_status_rejects_negative_timestamp() {
    let payload = br#"{"state":"success","deployment":{"id":42},"updated_at":-1}"#;
    assert!(parse_deployment_status(payload).is_none());
}

fn sample_deployment_failure_payload(deployment_id: u64) -> Vec<u8> {
    format!(r#"{{"status":"completed","state":"failure","deployment":{{"id":{}}},"description":"Build failed","updated_at":1700000000}}"#, deployment_id).into_bytes()
}

fn sample_deployment_pending_payload(deployment_id: u64) -> Vec<u8> {
    format!(r#"{{"status":"in_progress","state":"pending","deployment":{{"id":{}}},"updated_at":1700000000}}"#, deployment_id).into_bytes()
}

// ---------------------------------------------------------------------------
// Helper: create a sample execution attempt
// ---------------------------------------------------------------------------

fn sample_attempt(deployment_id: u64) -> ExecutionAttempt {
    ExecutionAttempt {
        attempt_id_hex: "att-mand-001".to_string(),
        mandate_id_hex: "mand-001".to_string(),
        intent_id_hex: "intent-001".to_string(),
        reservation_token_digest: "secret-token".to_string(),
        executor_identity: "piteka-worker".to_string(),
        correlation_key: "deploy-prod-001".to_string(),
        started_at_unix_seconds: 1699999999,
        dispatch_boundary_at_unix_seconds: Some(1699999999),
        state: ExecutionAttemptState::Accepted,
        github_deployment_id: Some(deployment_id),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn parse_deployment_status_success() {
    let payload = sample_deployment_success_payload(12345);
    let event = parse_deployment_status(&payload).expect("should parse");

    assert_eq!(event.deployment_id, 12345);
    assert_eq!(event.state, "success");
    assert_eq!(event.updated_at, 1700000000);
}

#[tokio::test]
async fn parse_deployment_status_failure() {
    let payload = sample_deployment_failure_payload(99999);
    let event = parse_deployment_status(&payload).expect("should parse");

    assert_eq!(event.state, "failure");
    assert_eq!(event.description, Some("Build failed".to_string()));
}

#[tokio::test]
async fn parse_deployment_status_pending() {
    let payload = sample_deployment_pending_payload(77777);
    let event = parse_deployment_status(&payload).expect("should parse");

    assert_eq!(event.state, "pending");
}

#[tokio::test]
async fn parse_deployment_status_invalid() {
    let payload: &[u8] = b"not json";
    let event = parse_deployment_status(payload);
    assert!(event.is_none());
}

#[tokio::test]
async fn map_github_state_to_outcome_success() {
    assert_eq!(
        map_github_state_to_outcome("success"),
        ReceiptOutcome::Succeeded
    );
}

#[tokio::test]
async fn map_github_state_to_outcome_failure() {
    assert_eq!(
        map_github_state_to_outcome("failure"),
        ReceiptOutcome::Failed
    );
    assert_eq!(map_github_state_to_outcome("error"), ReceiptOutcome::Failed);
}

#[tokio::test]
async fn map_github_state_to_outcome_unknown() {
    assert_eq!(
        map_github_state_to_outcome("pending"),
        ReceiptOutcome::Unknown
    );
    assert_eq!(
        map_github_state_to_outcome("inactive"),
        ReceiptOutcome::Unknown
    );
    assert_eq!(
        map_github_state_to_outcome("queued"),
        ReceiptOutcome::Unknown
    );
}

#[tokio::test]
async fn produce_receipt_from_webhook_success() {
    let clock = SystemClock;

    // Setup stores.
    let attempt_store = InMemoryExecutionAttemptStore::default();
    let receipt_store = InMemoryReceiptProjectionStore::default();
    let evidence_store = InMemoryEvidenceNodeStore::default();
    let audit_log = InMemoryAuditLog::default();

    // Insert a sample execution attempt.
    let attempt = sample_attempt(12345);
    attempt_store
        .insert(&tenant(), attempt.clone())
        .await
        .unwrap();

    let payload = sample_deployment_success_payload(12345);
    let event = parse_deployment_status(&payload).expect("should parse");

    let result = produce_receipt_from_webhook(
        &tenant(),
        &receipt_store,
        &evidence_store,
        &audit_log,
        &attempt_store,
        &event,
        &clock,
    )
    .await;
    assert!(result.is_ok(), "receipt production should succeed");

    let result = result.unwrap();
    assert_eq!(result.outcome, ReceiptOutcome::Succeeded);
    assert!(!result.evidence_node_ids.is_empty());
    assert!(result.evidence_gaps.is_empty());

    // Verify receipt was stored.
    let stored_receipt = receipt_store
        .get(&tenant(), &result.receipt_id_hex)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored_receipt.outcome, ReceiptOutcome::Succeeded);
    assert_eq!(stored_receipt.mandate_id_hex, "mand-001");

    // Verify evidence nodes were stored.
    let nodes = evidence_store.by_mandate(&tenant(), "").await.unwrap();
    assert!(!nodes.is_empty());

    // Verify source attribution.
    let observation = nodes
        .iter()
        .find(|n| matches!(&n.source, EvidenceSource::Provider(p) if p == "github"));
    assert!(
        observation.is_some(),
        "should have a GitHub observation node"
    );

    let claim = nodes
        .iter()
        .find(|n| matches!(&n.source, EvidenceSource::Piteka));
    assert!(claim.is_some(), "should have a Piteka claim node");
}

#[tokio::test]
async fn produce_receipt_from_webhook_failure_outcome() {
    let clock = SystemClock;

    let attempt_store = InMemoryExecutionAttemptStore::default();
    let receipt_store = InMemoryReceiptProjectionStore::default();
    let evidence_store = InMemoryEvidenceNodeStore::default();
    let audit_log = InMemoryAuditLog::default();

    let attempt = sample_attempt(99999);
    attempt_store.insert(&tenant(), attempt).await.unwrap();

    let payload = sample_deployment_failure_payload(99999);
    let event = parse_deployment_status(&payload).expect("should parse");

    let result = produce_receipt_from_webhook(
        &tenant(),
        &receipt_store,
        &evidence_store,
        &audit_log,
        &attempt_store,
        &event,
        &clock,
    )
    .await
    .unwrap();
    assert_eq!(result.outcome, ReceiptOutcome::Failed);
}

#[tokio::test]
async fn produce_receipt_from_webhook_unknown_outcome() {
    let clock = SystemClock;

    let attempt_store = InMemoryExecutionAttemptStore::default();
    let receipt_store = InMemoryReceiptProjectionStore::default();
    let evidence_store = InMemoryEvidenceNodeStore::default();
    let audit_log = InMemoryAuditLog::default();

    let attempt = sample_attempt(77777);
    attempt_store.insert(&tenant(), attempt).await.unwrap();

    let payload = sample_deployment_pending_payload(77777);
    let event = parse_deployment_status(&payload).expect("should parse");

    let result = produce_receipt_from_webhook(
        &tenant(),
        &receipt_store,
        &evidence_store,
        &audit_log,
        &attempt_store,
        &event,
        &clock,
    )
    .await
    .unwrap();
    assert_eq!(result.outcome, ReceiptOutcome::Unknown);
    // Unknown outcomes should have evidence gaps.
    assert!(!result.evidence_gaps.is_empty());
}

#[tokio::test]
async fn produce_receipt_from_webhook_no_matching_attempt() {
    let clock = SystemClock;

    let attempt_store = InMemoryExecutionAttemptStore::default();
    let receipt_store = InMemoryReceiptProjectionStore::default();
    let evidence_store = InMemoryEvidenceNodeStore::default();
    let audit_log = InMemoryAuditLog::default();

    // No attempt inserted — deployment ID 11111 doesn't match anything.

    let payload = sample_deployment_success_payload(12345);
    let event = parse_deployment_status(&payload).expect("should parse");

    let result = produce_receipt_from_webhook(
        &tenant(),
        &receipt_store,
        &evidence_store,
        &audit_log,
        &attempt_store,
        &event,
        &clock,
    )
    .await;
    assert!(result.is_err());
    match result.unwrap_err() {
        crate::receipt_production::ReceiptProductionError::AttemptNotFound(_) => {
            // Expected.
        }
        other => panic!("expected AttemptNotFound, got {:?}", other),
    }
}

#[tokio::test]
async fn evidence_nodes_have_source_attribution() {
    let clock = SystemClock;

    let attempt_store = InMemoryExecutionAttemptStore::default();
    let receipt_store = InMemoryReceiptProjectionStore::default();
    let evidence_store = InMemoryEvidenceNodeStore::default();
    let audit_log = InMemoryAuditLog::default();

    let attempt = sample_attempt(55555);
    attempt_store.insert(&tenant(), attempt).await.unwrap();

    let payload = sample_deployment_success_payload(55555);
    let event = parse_deployment_status(&payload).expect("should parse");

    let _ = produce_receipt_from_webhook(
        &tenant(),
        &receipt_store,
        &evidence_store,
        &audit_log,
        &attempt_store,
        &event,
        &clock,
    )
    .await
    .unwrap();

    let nodes = evidence_store.by_mandate(&tenant(), "").await.unwrap();

    // Count sources.
    let mut piteka_count = 0;
    let mut github_count = 0;
    let mut verifier_count = 0;

    for node in &nodes {
        match &node.source {
            EvidenceSource::Piteka => piteka_count += 1,
            EvidenceSource::Provider(p) if p == "github" => github_count += 1,
            EvidenceSource::Verifier => verifier_count += 1,
            _ => {}
        }
    }

    // Should have at least one Piteka claim and one GitHub observation.
    assert!(piteka_count >= 1, "should have Piteka claim nodes");
    assert!(github_count >= 1, "should have GitHub observation nodes");
    assert_eq!(
        verifier_count, 0,
        "collection must not invent verifier evidence"
    );
}

#[tokio::test]
async fn receipt_stores_evidence_references() {
    let clock = SystemClock;

    let attempt_store = InMemoryExecutionAttemptStore::default();
    let receipt_store = InMemoryReceiptProjectionStore::default();
    let evidence_store = InMemoryEvidenceNodeStore::default();
    let audit_log = InMemoryAuditLog::default();

    let attempt = sample_attempt(33333);
    attempt_store.insert(&tenant(), attempt).await.unwrap();

    let payload = sample_deployment_success_payload(33333);
    let event = parse_deployment_status(&payload).expect("should parse");

    let result = produce_receipt_from_webhook(
        &tenant(),
        &receipt_store,
        &evidence_store,
        &audit_log,
        &attempt_store,
        &event,
        &clock,
    )
    .await
    .unwrap();

    let stored = receipt_store
        .get(&tenant(), &result.receipt_id_hex)
        .await
        .unwrap()
        .unwrap();

    // Receipt should reference the evidence nodes.
    assert!(!stored.dispatch_evidence_refs.is_empty());
    assert!(!stored.target_evidence_refs.is_empty());

    // The dispatch_evidence_refs should contain the claim node ID (second element).
    assert!(
        stored
            .dispatch_evidence_refs
            .contains(&result.evidence_node_ids[1])
    );
}
