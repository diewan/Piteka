//! Positive and adversarial tests for the first-slice API.

use axum::{
    http::{Request, StatusCode},
    Router,
    body::Body,
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
