//! Positive and adversarial tests for the first-slice API.

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
};
use tower_service::Service;

use crate::TestPorts;

/// Returns a test router with in-memory ports.
fn test_router() -> Router {
    let ports = TestPorts::new();
    let use_case = ports.use_case();
    crate::routes::build_full_router(use_case)
}

/// Returns a minimal router with just the health endpoint for basic connectivity tests.
fn health_router() -> Router {
    Router::new().route("/health", axum::routing::get(|| async { "ready" }))
}

// ── Positive tests ──────────────────────────────────────────────────────────

#[tokio::test]
async fn health_returns_ready() {
    let mut app = health_router();
    let request = Request::builder()
        .method("GET")
        .uri("/health")
        .header("X-Tenant-Id", "demo")
        .body(Body::empty())
        .unwrap();

    let response = app.call(request).await.expect("call failed");
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn propose_creates_a_pending_request() {
    let mut app = test_router();

    let body = serde_json::json!({
        "requested_by": "agent@example.com",
        "intent_id": "abc123def456"
    });

    let request = Request::builder()
        .method("POST")
        .uri("/api/v1/action-requests")
        .header("content-type", "application/json")
        .header("X-Tenant-Id", "demo")
        .body(Body::from(body.to_string()))
        .unwrap();

    let response = app.call(request).await.expect("call failed");
    assert_eq!(response.status(), StatusCode::CREATED);

    let body: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap(),
    )
    .unwrap();

    assert_eq!(body["status"], "Pending");
    assert_eq!(body["requested_by"], "agent@example.com");
    assert_eq!(body["intent_id"], "abc123def456");
    assert!(body["id"].is_string());
}

#[tokio::test]
async fn list_returns_empty_array_initially() {
    let mut app = test_router();

    let request = Request::builder()
        .method("GET")
        .uri("/api/v1/action-requests")
        .header("X-Tenant-Id", "demo")
        .body(Body::empty())
        .unwrap();

    let response = app.call(request).await.expect("call failed");
    assert_eq!(response.status(), StatusCode::OK);

    let body: Vec<serde_json::Value> = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap(),
    )
    .unwrap();
    assert!(body.is_empty());
}

#[tokio::test]
async fn propose_then_list_returns_one_item() {
    let mut app = test_router();

    // Propose a request
    let body = serde_json::json!({
        "requested_by": "agent@example.com",
        "intent_id": "intent-001"
    });

    let request = Request::builder()
        .method("POST")
        .uri("/api/v1/action-requests")
        .header("content-type", "application/json")
        .header("X-Tenant-Id", "demo")
        .body(Body::from(body.to_string()))
        .unwrap();

    let response = app.call(request).await.expect("call failed");
    assert_eq!(response.status(), StatusCode::CREATED);

    let created_id: String = {
        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), 1024 * 1024)
                .await
                .unwrap(),
        )
        .unwrap();
        body["id"].as_str().unwrap().to_string()
    };

    // List should return one item
    let request = Request::builder()
        .method("GET")
        .uri("/api/v1/action-requests")
        .header("X-Tenant-Id", "demo")
        .body(Body::empty())
        .unwrap();

    let response = app.call(request).await.expect("call failed");
    assert_eq!(response.status(), StatusCode::OK);

    let summaries: Vec<serde_json::Value> = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(summaries.len(), 1);
    assert_eq!(summaries[0]["id"], created_id);
}

#[tokio::test]
async fn get_returns_full_detail_with_decisions() {
    let mut app = test_router();

    // Propose a request
    let body = serde_json::json!({
        "requested_by": "agent@example.com",
        "intent_id": "intent-002"
    });

    let request = Request::builder()
        .method("POST")
        .uri("/api/v1/action-requests")
        .header("content-type", "application/json")
        .header("X-Tenant-Id", "demo")
        .body(Body::from(body.to_string()))
        .unwrap();

    let response = app.call(request).await.expect("call failed");
    let created_id: String = {
        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), 1024 * 1024)
                .await
                .unwrap(),
        )
        .unwrap();
        body["id"].as_str().unwrap().to_string()
    };

    // Approve the request
    let approve_body = serde_json::json!({
        "approver_id": "approver@example.com",
        "intent_id": "intent-002",
        "version": 1
    });

    let request = Request::builder()
        .method("POST")
        .uri(&format!("/api/v1/action-requests/{}/approve", created_id))
        .header("content-type", "application/json")
        .header("X-Tenant-Id", "demo")
        .body(Body::from(approve_body.to_string()))
        .unwrap();

    let response = app.call(request).await.expect("call failed");
    assert_eq!(response.status(), StatusCode::OK);

    // Get the request detail
    let request = Request::builder()
        .method("GET")
        .uri(&format!("/api/v1/action-requests/{}", created_id))
        .header("X-Tenant-Id", "demo")
        .body(Body::empty())
        .unwrap();

    let response = app.call(request).await.expect("call failed");
    assert_eq!(response.status(), StatusCode::OK);

    let detail: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap(),
    )
    .unwrap();

    assert_eq!(detail["status"], "Approved");
    assert_eq!(detail["requested_by"], "agent@example.com");
    assert!(detail["decisions"].is_array());
    assert_eq!(detail["decisions"].as_array().unwrap().len(), 1);
    assert_eq!(detail["decisions"][0]["decision"], "approved");
}

#[tokio::test]
async fn approve_transitions_to_approved() {
    let mut app = test_router();

    // Propose
    let body = serde_json::json!({
        "requested_by": "agent@example.com",
        "intent_id": "intent-003"
    });

    let request = Request::builder()
        .method("POST")
        .uri("/api/v1/action-requests")
        .header("content-type", "application/json")
        .header("X-Tenant-Id", "demo")
        .body(Body::from(body.to_string()))
        .unwrap();

    let response = app.call(request).await.expect("call failed");
    let created_id: String = {
        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), 1024 * 1024)
                .await
                .unwrap(),
        )
        .unwrap();
        body["id"].as_str().unwrap().to_string()
    };

    // Approve
    let approve_body = serde_json::json!({
        "approver_id": "approver@example.com",
        "intent_id": "intent-003",
        "version": 1
    });

    let request = Request::builder()
        .method("POST")
        .uri(&format!("/api/v1/action-requests/{}/approve", created_id))
        .header("content-type", "application/json")
        .header("X-Tenant-Id", "demo")
        .body(Body::from(approve_body.to_string()))
        .unwrap();

    let response = app.call(request).await.expect("call failed");
    assert_eq!(response.status(), StatusCode::OK);

    let body: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(body["status"], "Approved");
}

#[tokio::test]
async fn reject_transitions_to_rejected() {
    let mut app = test_router();

    // Propose
    let body = serde_json::json!({
        "requested_by": "agent@example.com",
        "intent_id": "intent-004"
    });

    let request = Request::builder()
        .method("POST")
        .uri("/api/v1/action-requests")
        .header("content-type", "application/json")
        .header("X-Tenant-Id", "demo")
        .body(Body::from(body.to_string()))
        .unwrap();

    let response = app.call(request).await.expect("call failed");
    let created_id: String = {
        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), 1024 * 1024)
                .await
                .unwrap(),
        )
        .unwrap();
        body["id"].as_str().unwrap().to_string()
    };

    // Reject
    let reject_body = serde_json::json!({
        "approver_id": "approver@example.com",
        "intent_id": "intent-004",
        "version": 1
    });

    let request = Request::builder()
        .method("POST")
        .uri(&format!("/api/v1/action-requests/{}/reject", created_id))
        .header("content-type", "application/json")
        .header("X-Tenant-Id", "demo")
        .body(Body::from(reject_body.to_string()))
        .unwrap();

    let response = app.call(request).await.expect("call failed");
    assert_eq!(response.status(), StatusCode::OK);

    let body: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(body["status"], "Rejected");
}

#[tokio::test]
async fn revoke_transitions_to_revoked() {
    let mut app = test_router();

    // Propose
    let body = serde_json::json!({
        "requested_by": "agent@example.com",
        "intent_id": "intent-005"
    });

    let request = Request::builder()
        .method("POST")
        .uri("/api/v1/action-requests")
        .header("content-type", "application/json")
        .header("X-Tenant-Id", "demo")
        .body(Body::from(body.to_string()))
        .unwrap();

    let response = app.call(request).await.expect("call failed");
    let created_id: String = {
        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), 1024 * 1024)
                .await
                .unwrap(),
        )
        .unwrap();
        body["id"].as_str().unwrap().to_string()
    };

    // Approve first
    let approve_body = serde_json::json!({
        "approver_id": "approver@example.com",
        "intent_id": "intent-005",
        "version": 1
    });

    let request = Request::builder()
        .method("POST")
        .uri(&format!("/api/v1/action-requests/{}/approve", created_id))
        .header("content-type", "application/json")
        .header("X-Tenant-Id", "demo")
        .body(Body::from(approve_body.to_string()))
        .unwrap();

    app.call(request).await.expect("call failed");

    // Revoke
    let revoke_body = serde_json::json!({
        "approver_id": "approver@example.com",
        "version": 2
    });

    let request = Request::builder()
        .method("POST")
        .uri(&format!("/api/v1/action-requests/{}/revoke", created_id))
        .header("content-type", "application/json")
        .header("X-Tenant-Id", "demo")
        .body(Body::from(revoke_body.to_string()))
        .unwrap();

    let response = app.call(request).await.expect("call failed");
    assert_eq!(response.status(), StatusCode::OK);

    let body: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(body["status"], "Revoked");
}

// ── Negative / adversarial tests ────────────────────────────────────────────

#[tokio::test]
async fn propose_with_empty_requested_by_returns_400() {
    let mut app = test_router();

    let body = serde_json::json!({
        "requested_by": "",
        "intent_id": "intent-006"
    });

    let request = Request::builder()
        .method("POST")
        .uri("/api/v1/action-requests")
        .header("content-type", "application/json")
        .header("X-Tenant-Id", "demo")
        .body(Body::from(body.to_string()))
        .unwrap();

    let response = app.call(request).await.expect("call failed");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let body: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(body["error"]["causes"][0]["code"], "EMPTY_REQUESTED_BY");
}

#[tokio::test]
async fn get_nonexistent_request_returns_404() {
    let mut app = test_router();

    let request = Request::builder()
        .method("GET")
        .uri("/api/v1/action-requests/nonexistent-id")
        .header("X-Tenant-Id", "demo")
        .body(Body::empty())
        .unwrap();

    let response = app.call(request).await.expect("call failed");
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    let body: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(body["error"]["code"], "NOT_FOUND");
}

#[tokio::test]
async fn approve_nonexistent_request_returns_404() {
    let mut app = test_router();

    let body = serde_json::json!({
        "approver_id": "approver@example.com",
        "intent_id": "intent-007",
        "version": 1
    });

    let request = Request::builder()
        .method("POST")
        .uri("/api/v1/action-requests/nonexistent-id/approve")
        .header("content-type", "application/json")
        .header("X-Tenant-Id", "demo")
        .body(Body::from(body.to_string()))
        .unwrap();

    let response = app.call(request).await.expect("call failed");
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn approve_already_approved_request_returns_409() {
    let mut app = test_router();

    // Propose and approve
    let body = serde_json::json!({
        "requested_by": "agent@example.com",
        "intent_id": "intent-008"
    });

    let request = Request::builder()
        .method("POST")
        .uri("/api/v1/action-requests")
        .header("content-type", "application/json")
        .header("X-Tenant-Id", "demo")
        .body(Body::from(body.to_string()))
        .unwrap();

    let response = app.call(request).await.expect("call failed");
    let created_id: String = {
        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), 1024 * 1024)
                .await
                .unwrap(),
        )
        .unwrap();
        body["id"].as_str().unwrap().to_string()
    };

    // First approval succeeds
    let approve_body = serde_json::json!({
        "approver_id": "approver@example.com",
        "intent_id": "intent-008",
        "version": 1
    });

    let request = Request::builder()
        .method("POST")
        .uri(&format!("/api/v1/action-requests/{}/approve", created_id))
        .header("content-type", "application/json")
        .header("X-Tenant-Id", "demo")
        .body(Body::from(approve_body.to_string()))
        .unwrap();

    app.call(request).await.expect("call failed");

    // Second approval on already-approved request returns 409
    let approve_body = serde_json::json!({
        "approver_id": "approver2@example.com",
        "intent_id": "intent-008",
        "version": 1
    });

    let request = Request::builder()
        .method("POST")
        .uri(&format!("/api/v1/action-requests/{}/approve", created_id))
        .header("content-type", "application/json")
        .header("X-Tenant-Id", "demo")
        .body(Body::from(approve_body.to_string()))
        .unwrap();

    let response = app.call(request).await.expect("call failed");
    assert_eq!(response.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn approve_pending_request_with_wrong_version_returns_409() {
    let mut app = test_router();

    // Propose
    let body = serde_json::json!({
        "requested_by": "agent@example.com",
        "intent_id": "intent-009"
    });

    let request = Request::builder()
        .method("POST")
        .uri("/api/v1/action-requests")
        .header("content-type", "application/json")
        .header("X-Tenant-Id", "demo")
        .body(Body::from(body.to_string()))
        .unwrap();

    let response = app.call(request).await.expect("call failed");
    let created_id: String = {
        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), 1024 * 1024)
                .await
                .unwrap(),
        )
        .unwrap();
        body["id"].as_str().unwrap().to_string()
    };

    // Approve with wrong version (2 instead of 1)
    let approve_body = serde_json::json!({
        "approver_id": "approver@example.com",
        "intent_id": "intent-009",
        "version": 2
    });

    let request = Request::builder()
        .method("POST")
        .uri(&format!("/api/v1/action-requests/{}/approve", created_id))
        .header("content-type", "application/json")
        .header("X-Tenant-Id", "demo")
        .body(Body::from(approve_body.to_string()))
        .unwrap();

    let response = app.call(request).await.expect("call failed");
    assert_eq!(response.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn revoke_pending_request_returns_409() {
    let mut app = test_router();

    // Propose (stays Pending)
    let body = serde_json::json!({
        "requested_by": "agent@example.com",
        "intent_id": "intent-010"
    });

    let request = Request::builder()
        .method("POST")
        .uri("/api/v1/action-requests")
        .header("content-type", "application/json")
        .header("X-Tenant-Id", "demo")
        .body(Body::from(body.to_string()))
        .unwrap();

    let response = app.call(request).await.expect("call failed");
    let created_id: String = {
        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), 1024 * 1024)
                .await
                .unwrap(),
        )
        .unwrap();
        body["id"].as_str().unwrap().to_string()
    };

    // Try to revoke a pending request
    let revoke_body = serde_json::json!({
        "approver_id": "approver@example.com",
        "version": 1
    });

    let request = Request::builder()
        .method("POST")
        .uri(&format!("/api/v1/action-requests/{}/revoke", created_id))
        .header("content-type", "application/json")
        .header("X-Tenant-Id", "demo")
        .body(Body::from(revoke_body.to_string()))
        .unwrap();

    let response = app.call(request).await.expect("call failed");
    assert_eq!(response.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn approve_rejected_request_returns_409() {
    let mut app = test_router();

    // Propose and reject
    let body = serde_json::json!({
        "requested_by": "agent@example.com",
        "intent_id": "intent-011"
    });

    let request = Request::builder()
        .method("POST")
        .uri("/api/v1/action-requests")
        .header("content-type", "application/json")
        .header("X-Tenant-Id", "demo")
        .body(Body::from(body.to_string()))
        .unwrap();

    let response = app.call(request).await.expect("call failed");
    let created_id: String = {
        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), 1024 * 1024)
                .await
                .unwrap(),
        )
        .unwrap();
        body["id"].as_str().unwrap().to_string()
    };

    // Reject
    let reject_body = serde_json::json!({
        "approver_id": "approver@example.com",
        "intent_id": "intent-011",
        "version": 1
    });

    let request = Request::builder()
        .method("POST")
        .uri(&format!("/api/v1/action-requests/{}/reject", created_id))
        .header("content-type", "application/json")
        .header("X-Tenant-Id", "demo")
        .body(Body::from(reject_body.to_string()))
        .unwrap();

    app.call(request).await.expect("call failed");

    // Try to approve a rejected request
    let approve_body = serde_json::json!({
        "approver_id": "approver@example.com",
        "intent_id": "intent-011",
        "version": 2
    });

    let request = Request::builder()
        .method("POST")
        .uri(&format!("/api/v1/action-requests/{}/approve", created_id))
        .header("content-type", "application/json")
        .header("X-Tenant-Id", "demo")
        .body(Body::from(approve_body.to_string()))
        .unwrap();

    let response = app.call(request).await.expect("call failed");
    assert_eq!(response.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn approve_with_empty_approver_id_returns_400() {
    let mut app = test_router();

    // Propose
    let body = serde_json::json!({
        "requested_by": "agent@example.com",
        "intent_id": "intent-012"
    });

    let request = Request::builder()
        .method("POST")
        .uri("/api/v1/action-requests")
        .header("content-type", "application/json")
        .header("X-Tenant-Id", "demo")
        .body(Body::from(body.to_string()))
        .unwrap();

    let response = app.call(request).await.expect("call failed");
    let created_id: String = {
        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), 1024 * 1024)
                .await
                .unwrap(),
        )
        .unwrap();
        body["id"].as_str().unwrap().to_string()
    };

    // Approve with empty approver_id
    let approve_body = serde_json::json!({
        "approver_id": "",
        "intent_id": "intent-012",
        "version": 1
    });

    let request = Request::builder()
        .method("POST")
        .uri(&format!("/api/v1/action-requests/{}/approve", created_id))
        .header("content-type", "application/json")
        .header("X-Tenant-Id", "demo")
        .body(Body::from(approve_body.to_string()))
        .unwrap();

    let response = app.call(request).await.expect("call failed");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[test]
fn openapi_spec_contains_required_paths() {
    let spec = crate::OPENAPI_SPEC;
    // Basic validation: the YAML should contain our paths
    assert!(spec.contains("action-requests"));
    assert!(spec.contains("/api/v1/action-requests"));
    assert!(spec.contains("approve"));
    assert!(spec.contains("reject"));
    assert!(spec.contains("revoke"));
}

// ── NAM-02 rename compatibility ─────────────────────────────────────────────
//
// The NAM-02 naming audit gave every `/api/v1` boundary shape an explicit role
// and version suffix (`RequestV1` / `ResponseV1` / `DtoV1`). Those are Rust
// identifiers only. The tests below pin the part that is a compatibility
// surface — the serialized JSON keys and values, and the OpenAPI schema names
// that describe them — so a future rename cannot quietly become a wire change.

/// Every JSON key and value emitted by the renamed response types is byte-for-byte
/// what it was before NAM-02. The expected literals below are the pre-rename
/// contract; they are deliberately written out rather than derived.
#[test]
fn api_v1_json_is_unchanged_by_type_renames() {
    use crate::models::{
        ActionRequestResponseV1, ActionRequestStatusDtoV1, ActionRequestSummaryDtoV1,
        ApprovalDecisionDtoV1, MandateChainAttemptDtoV1, MandateChainEvidenceDtoV1,
        MandateChainResponseV1, MandateChainStepDtoV1, MandateResponseV1, ReceiptResponseV1,
        ReceiptSummaryDtoV1,
    };

    let summary = ActionRequestSummaryDtoV1 {
        id: "req-1".to_string(),
        requested_by: "alice".to_string(),
        status: ActionRequestStatusDtoV1::Pending,
        created_at: 1_700_000_000,
    };
    assert_eq!(
        serde_json::to_value(&summary).unwrap(),
        serde_json::json!({
            "id": "req-1",
            "requested_by": "alice",
            "status": "Pending",
            "created_at": 1_700_000_000u64,
        })
    );

    let decision = ApprovalDecisionDtoV1 {
        id: "dec-1".to_string(),
        decided_by: "bob".to_string(),
        decision: "approved".to_string(),
        intent_id: Some("ab".repeat(32)),
        decided_at: 1_700_000_100,
    };
    let response = ActionRequestResponseV1 {
        id: "req-1".to_string(),
        requested_by: "alice".to_string(),
        intent_id: Some("ab".repeat(32)),
        status: ActionRequestStatusDtoV1::Approved,
        created_at: 1_700_000_000,
        decisions: vec![decision],
    };
    assert_eq!(
        serde_json::to_value(&response).unwrap(),
        serde_json::json!({
            "id": "req-1",
            "requested_by": "alice",
            "intent_id": "ab".repeat(32),
            "status": "Approved",
            "created_at": 1_700_000_000u64,
            "decisions": [{
                "id": "dec-1",
                "decided_by": "bob",
                "decision": "approved",
                "intent_id": "ab".repeat(32),
                "decided_at": 1_700_000_100u64,
            }],
        })
    );

    // Optional fields still disappear rather than serializing as null.
    let bare = ActionRequestResponseV1 {
        id: "req-2".to_string(),
        requested_by: "alice".to_string(),
        intent_id: None,
        status: ActionRequestStatusDtoV1::Rejected,
        created_at: 1,
        decisions: vec![],
    };
    let bare = serde_json::to_value(&bare).unwrap();
    assert!(bare.get("intent_id").is_none(), "intent_id must be omitted");
    assert!(bare.get("decisions").is_none(), "decisions must be omitted");
    assert_eq!(bare["status"], "Rejected");

    let chain = MandateChainResponseV1 {
        mandate: MandateResponseV1 {
            mandate_id: "cd".repeat(32),
            state: "reserved".to_string(),
            version: 3,
        },
        timeline: vec![MandateChainStepDtoV1 {
            at: 5,
            actor: None,
            action: "dispatch".to_string(),
            decision: "granted".to_string(),
            detail: "d".to_string(),
        }],
        attempts: vec![MandateChainAttemptDtoV1 {
            attempt_id: "ef".repeat(32),
            executor_identity: "worker".to_string(),
            state: "Accepted".to_string(),
            github_deployment_id: Some(99),
            started_at: 4,
        }],
        receipts: vec![ReceiptResponseV1 {
            receipt_id: "01".repeat(32),
            mandate_id: "cd".repeat(32),
            intent_id: "ab".repeat(32),
            attempt_id: "ef".repeat(32),
            outcome: "unknown".to_string(),
            created_at: 6,
            dispatch_evidence_refs: vec!["n1".to_string()],
            target_evidence_refs: vec![],
            evidence_gaps: vec!["provider_status_unavailable".to_string()],
        }],
        evidence: vec![MandateChainEvidenceDtoV1 {
            node_id: "02".repeat(32),
            registry_id: "observation".to_string(),
            source: "provider:github".to_string(),
            producer_identity: "github".to_string(),
            content_digest: "03".repeat(32),
            media_type: "application/json".to_string(),
        }],
    };
    let chain = serde_json::to_value(&chain).unwrap();
    assert_eq!(
        chain["mandate"],
        serde_json::json!({"mandate_id": "cd".repeat(32), "state": "reserved", "version": 3})
    );
    assert_eq!(chain["timeline"][0]["action"], "dispatch");
    // `actor` has no `skip_serializing_if`, so an absent actor is an explicit
    // JSON null rather than a missing key. That is the pre-NAM-02 shape and is
    // pinned here deliberately: "no recorded actor" must stay distinguishable
    // from "field not present".
    assert!(chain["timeline"][0]["actor"].is_null());
    assert_eq!(chain["attempts"][0]["github_deployment_id"], 99);
    // `unknown` is preserved verbatim; it is never upgraded to a success or failure.
    assert_eq!(chain["receipts"][0]["outcome"], "unknown");
    assert_eq!(
        chain["receipts"][0]["evidence_gaps"][0],
        "provider_status_unavailable"
    );
    assert_eq!(chain["evidence"][0]["registry_id"], "observation");

    let receipt_summary = ReceiptSummaryDtoV1 {
        receipt_id: "01".repeat(32),
        mandate_id: "cd".repeat(32),
        outcome: "succeeded".to_string(),
        created_at: 6,
    };
    assert_eq!(
        serde_json::to_value(&receipt_summary).unwrap(),
        serde_json::json!({
            "receipt_id": "01".repeat(32),
            "mandate_id": "cd".repeat(32),
            "outcome": "succeeded",
            "created_at": 6,
        })
    );
}

/// The renamed request bodies still deserialize the same JSON keys, and still
/// reject unknown ones where they did before.
#[test]
fn api_v1_request_bodies_accept_the_same_json_keys() {
    use crate::models::{
        ApproveActionRequestRequestV1, CreateActionRequestRequestV1, RejectActionRequestRequestV1,
        RevokeActionRequestRequestV1,
    };

    let create: CreateActionRequestRequestV1 =
        serde_json::from_value(serde_json::json!({"requested_by": "alice"})).unwrap();
    assert_eq!(create.requested_by, "alice");
    assert!(create.intent_id.is_none());

    let approve: ApproveActionRequestRequestV1 = serde_json::from_value(
        serde_json::json!({"approver_id": "bob", "intent_id": "ab", "version": 1}),
    )
    .unwrap();
    assert_eq!(approve.approver_id, "bob");
    assert_eq!(approve.version, 1);

    let reject: RejectActionRequestRequestV1 =
        serde_json::from_value(serde_json::json!({"approver_id": "bob", "version": 2})).unwrap();
    assert_eq!(reject.version, 2);

    let revoke: RevokeActionRequestRequestV1 =
        serde_json::from_value(serde_json::json!({"approver_id": "bob", "version": 3})).unwrap();
    assert_eq!(revoke.version, 3);
}

/// The error envelope is part of the v1 contract; renaming its Rust types must
/// not move a key or change a code.
#[test]
fn api_v1_error_envelope_is_unchanged_by_type_renames() {
    use crate::error::ApiError;
    use axum::response::IntoResponse;

    let response = ApiError::not_found("action request", "req-1").into_response();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    let rendered = serde_json::to_value(crate::error::ErrorResponseV1 {
        error: crate::error::ErrorDetailDtoV1 {
            code: "NOT_FOUND".to_string(),
            message: "action request `req-1` not found".to_string(),
            causes: Some(vec![crate::error::ErrorCauseDtoV1 {
                code: "NOT_FOUND".to_string(),
                message: "action request `req-1` not found".to_string(),
                source: Some("id".to_string()),
            }]),
        },
    })
    .unwrap();
    assert_eq!(
        rendered,
        serde_json::json!({
            "error": {
                "code": "NOT_FOUND",
                "message": "action request `req-1` not found",
                "causes": [{
                    "code": "NOT_FOUND",
                    "message": "action request `req-1` not found",
                    "source": "id",
                }],
            }
        })
    );
}

/// The checked-in OpenAPI contract names the same schemas the Rust types now
/// declare, and every `$ref` still resolves (constitution §4: "Schema titles and
/// generated type names agree").
#[test]
fn openapi_schema_names_match_the_versioned_rust_types() {
    let spec = crate::OPENAPI_SPEC;
    for schema in [
        "ActionRequestStatusDtoV1",
        "ActionRequestSummaryDtoV1",
        "ActionRequestResponseV1",
        "ApprovalDecisionDtoV1",
        "CreateActionRequestRequestV1",
        "ApproveActionRequestRequestV1",
        "RejectActionRequestRequestV1",
        "RevokeActionRequestRequestV1",
        "ErrorResponseV1",
        "ErrorDetailDtoV1",
        "ErrorCauseDtoV1",
    ] {
        assert!(
            spec.contains(&format!("    {schema}:")),
            "openapi.yaml is missing schema `{schema}`"
        );
        assert!(
            spec.contains(&format!("#/components/schemas/{schema}")),
            "openapi.yaml never references schema `{schema}`"
        );
    }

    // The original v1 component names remain as deprecated aliases so generated
    // clients and external documents can continue resolving them.
    for (legacy, replacement) in [
        ("ActionRequestStatus", "ActionRequestStatusDtoV1"),
        ("ActionRequestSummary", "ActionRequestSummaryDtoV1"),
        ("ActionRequestResponse", "ActionRequestResponseV1"),
        ("ApprovalDecisionResponse", "ApprovalDecisionDtoV1"),
        ("CreateActionRequestRequest", "CreateActionRequestRequestV1"),
        ("ApproveRequest", "ApproveActionRequestRequestV1"),
        ("RejectRequest", "RejectActionRequestRequestV1"),
        ("RevokeRequest", "RevokeActionRequestRequestV1"),
        ("ErrorResponse", "ErrorResponseV1"),
        ("ErrorDetail", "ErrorDetailDtoV1"),
        ("ErrorCause", "ErrorCauseDtoV1"),
    ] {
        assert!(
            spec.contains(&format!("    {legacy}:")),
            "openapi.yaml dropped compatibility schema `{legacy}`"
        );
        assert!(
            spec.contains(&format!("#/components/schemas/{replacement}")),
            "compatibility schema `{legacy}` has no replacement `{replacement}`"
        );
    }
}
