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

fn tenant() -> piteka_storage::TenantScope {
    piteka_storage::TenantScope::new("test-tenant").unwrap()
}

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
        protocol_closure: None,
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
    attempt_store.insert(&tenant(), attempt).await.unwrap();

    // Produce receipt via webhook processing.
    let payload = success_payload();
    let event = parse_deployment_status(&payload).expect("should parse");
    let result = produce_receipt_from_webhook(
        &tenant(),
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
        &tenant(),
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
        .insert(
            &tenant(),
            piteka_storage::model::ReceiptProjection {
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
            },
        )
        .await
        .unwrap();

    // With no stored proof, the manifest carries an explicit null anchor (a limitation).
    let bytes = export_manifest_bytes(
        &tenant(),
        &receipt_store,
        &evidence_store,
        &seal_store,
        "rcpt-anchor",
    )
    .await
    .unwrap();
    let manifest: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert!(manifest["single_use_anchor"].is_null());

    // Once the proof exists for the receipt's mandate, the manifest discloses it verbatim.
    seal_store
        .put(
            &tenant(),
            SealConsumptionProofRecord {
                mandate_id_hex: "mandate-anchor".into(),
                seal_id_hex: "aa".repeat(32),
                nullifier_hex: "bb".repeat(32),
                commitment_hex: "cc".repeat(32),
                anchor_backend: "csv-seal.local.v1".into(),
            },
        )
        .await
        .unwrap();
    let bytes = export_manifest_bytes(
        &tenant(),
        &receipt_store,
        &evidence_store,
        &seal_store,
        "rcpt-anchor",
    )
    .await
    .unwrap();
    let manifest: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let anchor = &manifest["single_use_anchor"];
    assert_eq!(anchor["seal_id_hex"], "aa".repeat(32));
    assert_eq!(anchor["nullifier_hex"], "bb".repeat(32));
    assert_eq!(anchor["commitment_hex"], "cc".repeat(32));
    assert_eq!(anchor["anchor_backend"], "csv-seal.local.v1");
}

// ── The feed publishes only what Piteka observed and produced (PIT-NE-006) ──

/// Builds an evidence node with the source and the two times stated separately.
fn evidence_node(
    node_id: &str,
    source: piteka_storage::model::EvidenceSource,
    collected_at: i64,
    asserted_event_at: Option<i64>,
) -> piteka_storage::model::EvidenceNodeRecord {
    piteka_storage::model::EvidenceNodeRecord {
        node_id_hex: node_id.to_string(),
        registry_id: "diewan.evidence.observation.v1".to_string(),
        source,
        producer_identity: "producer".to_string(),
        collected_at_unix_seconds: collected_at,
        asserted_event_at_unix_seconds: asserted_event_at,
        content_digest: piteka_storage::digest::ContentDigest::of(node_id.as_bytes()),
        media_type: "application/json".to_string(),
        disclosure_classification: "internal".to_string(),
        relationships: Vec::new(),
    }
}

/// A receipt with the given evidence already stored, and its exported manifest.
async fn manifest_for(
    dispatch: Vec<piteka_storage::model::EvidenceNodeRecord>,
    target: Vec<piteka_storage::model::EvidenceNodeRecord>,
) -> serde_json::Value {
    use piteka_storage::ports::EvidenceNodeStore;

    let receipt_store = InMemoryReceiptProjectionStore::default();
    let evidence_store = InMemoryEvidenceNodeStore::default();
    let seal_store = InMemorySealConsumptionStore::default();
    let dispatch_refs: Vec<String> = dispatch.iter().map(|n| n.node_id_hex.clone()).collect();
    let target_refs: Vec<String> = target.iter().map(|n| n.node_id_hex.clone()).collect();
    for node in dispatch.into_iter().chain(target) {
        evidence_store.insert(&tenant(), node).await.unwrap();
    }
    receipt_store
        .insert(
            &tenant(),
            piteka_storage::model::ReceiptProjection {
                receipt_id_hex: "rcpt-scope".into(),
                mandate_id_hex: "mandate".into(),
                intent_id_hex: "intent".into(),
                attempt_id_hex: "attempt".into(),
                outcome: piteka_storage::model::ReceiptOutcome::Succeeded,
                created_at_unix_seconds: 1,
                dispatch_evidence_refs: dispatch_refs,
                target_evidence_refs: target_refs,
                evidence_gaps: vec![],
                canonical_bytes: None,
            },
        )
        .await
        .unwrap();

    let bytes = export_manifest_bytes(
        &tenant(),
        &receipt_store,
        &evidence_store,
        &seal_store,
        "rcpt-scope",
    )
    .await
    .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

#[tokio::test]
async fn a_verifier_conclusion_is_withheld_from_the_signed_feed() {
    use piteka_storage::model::EvidenceSource;

    let manifest = manifest_for(
        vec![evidence_node("claim-1", EvidenceSource::Piteka, 100, Some(90))],
        vec![
            evidence_node(
                "observed-1",
                EvidenceSource::Provider("github".into()),
                110,
                Some(95),
            ),
            evidence_node("verdict-1", EvidenceSource::Verifier, 120, Some(99)),
        ],
    )
    .await;

    // The verdict is not in the payload Piteka signs.
    let published: Vec<&str> = manifest["dispatch_evidence"]
        .as_array()
        .unwrap()
        .iter()
        .chain(manifest["target_evidence"].as_array().unwrap())
        .map(|node| node["node_id"].as_str().unwrap())
        .collect();
    assert_eq!(published, vec!["claim-1", "observed-1"]);
    assert!(
        !manifest.to_string().contains("\"source\":\"verifier\""),
        "no published node may be attributed to a verifier"
    );

    // Nor is it silently dropped: it is named, digested, and given a reason.
    let withheld = manifest["withheld_verifier_conclusions"].as_array().unwrap();
    assert_eq!(withheld.len(), 1);
    assert_eq!(withheld[0]["node_id"], "verdict-1");
    assert!(withheld[0]["content_digest"].as_str().is_some_and(|d| d.len() == 64));
    assert!(withheld[0]["reason"].as_str().is_some_and(|r| !r.is_empty()));
}

#[tokio::test]
async fn the_feed_no_longer_carries_a_published_verdict_count() {
    use piteka_storage::model::EvidenceSource;

    let manifest = manifest_for(
        vec![evidence_node("claim-1", EvidenceSource::Piteka, 100, Some(90))],
        vec![],
    )
    .await;
    let attribution = &manifest["source_attribution"];

    // `verifier_conclusions` published a verdict count as if the feed had the
    // authority to report one. It is gone; what remains records withholding.
    assert!(attribution.get("verifier_conclusions").is_none());
    assert_eq!(attribution["withheld_verifier_conclusions"], 0);
    assert_eq!(attribution["piteka_claims"], 1);
}

#[tokio::test]
async fn attribution_counts_every_published_node_wherever_it_was_filed() {
    use piteka_storage::model::EvidenceSource;

    // A Piteka claim filed as target evidence used to be counted in neither
    // bucket, which understated what the feed was signing.
    let manifest = manifest_for(
        vec![evidence_node(
            "observed-1",
            EvidenceSource::Provider("github".into()),
            100,
            None,
        )],
        vec![evidence_node("claim-1", EvidenceSource::Piteka, 105, None)],
    )
    .await;

    assert_eq!(manifest["source_attribution"]["piteka_claims"], 1);
    assert_eq!(manifest["source_attribution"]["provider_observations"], 1);
}

#[tokio::test]
async fn source_asserted_time_observed_time_and_checkpoint_stay_distinct() {
    use piteka_storage::model::EvidenceSource;

    let manifest = manifest_for(
        vec![evidence_node("claim-1", EvidenceSource::Piteka, 100, Some(90))],
        vec![evidence_node(
            "observed-1",
            EvidenceSource::Provider("github".into()),
            140,
            Some(95),
        )],
    )
    .await;

    let claim = &manifest["dispatch_evidence"][0];
    assert_eq!(claim["source"], "piteka");
    assert_eq!(claim["asserted_event_at"], 90);
    assert_eq!(claim["observed_at"], 100);

    let observation = &manifest["target_evidence"][0];
    assert_eq!(observation["source"], "github");
    assert_eq!(observation["asserted_event_at"], 95);
    assert_eq!(observation["observed_at"], 140);

    // The checkpoint is Piteka's own collection horizon: the newest thing it
    // collected, not the receipt's asserted creation time and not any
    // source-asserted event time.
    assert_eq!(manifest["export_checkpoint"]["evidence_collected_through"], 140);
    assert_eq!(manifest["export_checkpoint"]["published_evidence_count"], 2);
    assert_eq!(manifest["receipt"]["created_at"], 1);
}

#[tokio::test]
async fn an_undisclosed_assertion_time_stays_null_rather_than_borrowing_the_clock() {
    use piteka_storage::model::EvidenceSource;

    let manifest = manifest_for(
        vec![evidence_node("claim-1", EvidenceSource::Piteka, 100, None)],
        vec![],
    )
    .await;

    // Falling back to the collection time would turn Piteka's clock into the
    // source's claim about when the event happened.
    assert!(manifest["dispatch_evidence"][0]["asserted_event_at"].is_null());
    assert_eq!(manifest["dispatch_evidence"][0]["observed_at"], 100);
}

#[tokio::test]
async fn an_export_with_nothing_published_has_no_collection_checkpoint() {
    let manifest = manifest_for(vec![], vec![]).await;

    // A checkpoint over no evidence is not zero.
    assert!(manifest["export_checkpoint"]["evidence_collected_through"].is_null());
    assert_eq!(manifest["export_checkpoint"]["published_evidence_count"], 0);
}

#[tokio::test]
async fn the_manifest_declares_the_version_a_consumer_must_read_it_under() {
    let manifest = manifest_for(vec![], vec![]).await;
    assert_eq!(
        manifest["bundle_version"],
        crate::bundle_export::EXPORT_MANIFEST_VERSION
    );
    assert_eq!(manifest["bundle_version"], "0.2");
}

#[tokio::test]
async fn assemble_bundle_receipt_not_found() {
    let evidence_store = std::sync::Arc::new(InMemoryEvidenceNodeStore::default());
    let evidence_blob_store = std::sync::Arc::new(InMemoryEvidenceStore::default());
    let protocol_store = std::sync::Arc::new(InMemoryProtocolObjectStore::default());
    let receipt_store = std::sync::Arc::new(InMemoryReceiptProjectionStore::default());

    let result = assemble_bundle(
        &tenant(),
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
async fn export_cannot_read_a_receipt_from_another_tenant() {
    let receipt_store = InMemoryReceiptProjectionStore::default();
    let evidence_store = InMemoryEvidenceNodeStore::default();
    let seal_store = InMemorySealConsumptionStore::default();
    let owner = piteka_storage::TenantScope::new("owner").unwrap();
    let attacker = piteka_storage::TenantScope::new("attacker").unwrap();

    receipt_store
        .insert(
            &owner,
            piteka_storage::model::ReceiptProjection {
                receipt_id_hex: "same-receipt".into(),
                mandate_id_hex: "mandate".into(),
                intent_id_hex: "intent".into(),
                attempt_id_hex: "attempt".into(),
                outcome: piteka_storage::model::ReceiptOutcome::Succeeded,
                created_at_unix_seconds: 1,
                dispatch_evidence_refs: vec![],
                target_evidence_refs: vec![],
                evidence_gaps: vec![],
                canonical_bytes: None,
            },
        )
        .await
        .unwrap();

    let error = export_manifest_bytes(
        &attacker,
        &receipt_store,
        &evidence_store,
        &seal_store,
        "same-receipt",
    )
    .await
    .expect_err("cross-tenant export must fail closed");
    assert!(matches!(
        error,
        crate::bundle_export::BundleExportError::ReceiptNotFound(_)
    ));
}

#[tokio::test]
async fn assemble_bundle_fails_closed_when_referenced_evidence_is_missing() {
    let receipt_store = InMemoryReceiptProjectionStore::default();
    let evidence_store = InMemoryEvidenceNodeStore::default();
    let evidence_blob_store = InMemoryEvidenceStore::default();
    let protocol_store = InMemoryProtocolObjectStore::default();

    receipt_store
        .insert(
            &tenant(),
            piteka_storage::model::ReceiptProjection {
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
            },
        )
        .await
        .unwrap();

    let error = assemble_bundle(
        &tenant(),
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
    attempt_store.insert(&tenant(), attempt).await.unwrap();

    let payload = success_payload();
    let event = parse_deployment_status(&payload).expect("should parse");
    let result = produce_receipt_from_webhook(
        &tenant(),
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
        &tenant(),
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
    let stored = protocol_store
        .get(&tenant(), &bundle.bundle_id_hex)
        .await
        .unwrap();
    assert!(
        stored.is_some(),
        "bundle should be stored in protocol objects"
    );
}
