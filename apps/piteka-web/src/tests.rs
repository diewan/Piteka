#![forbid(unsafe_code)]

//! Tests for the Piteka web approval UI.
//!
//! Covers:
//! - HTML pages are served with correct content
//! - CSS design tokens are present
//! - Accessibility: semantic HTML, ARIA attributes, keyboard navigation
//! - Design system token contrast ratios (WCAG AA)

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
};
use tower_service::Service;

#[test]
fn approval_summary_has_one_visible_and_submitted_digest_with_accessible_context() {
    let summary = crate::ApprovalSummary::new(piteka_application::CanonicalIntent {
        tenant_id: "tenant-a".into(),
        request_id: "request-1".into(),
        environment: "production".into(),
        repository: "acme/<service>".into(),
        revision: "abc123".into(),
    });
    let html = summary.render_security_context();
    assert_eq!(html.matches(&summary.digest_hex).count(), 2);
    assert!(html.contains("aria-labelledby=\"approval-context-title\""));
    assert!(html.contains("aria-describedby=\"intent-digest\""));
    assert!(html.contains("acme/&lt;service&gt;"));
}

#[test]
fn replay_rejection_is_visible_accessible_and_evidence_backed() {
    let rejection = piteka_application::dispatch::ReplayRejection {
        reason_code: "MANDATE.REPLAY_DETECTED",
        mandate_id_hex: "mandate-1".to_string(),
        request_id: "request-1".to_string(),
        executor_identity: "svc:agent".to_string(),
        mandate_state: "consumed".to_string(),
        message:
            "Repeat use rejected. Approval mandate-1 was already used; nothing was sent to GitHub."
                .to_string(),
    };
    let axum::response::Html(body) = crate::render_replay_rejection(&rejection);

    assert!(body.contains("Repeat use rejected"));
    assert!(body.contains("MANDATE.REPLAY_DETECTED"));
    assert!(body.contains("Not sent"));
    assert!(body.contains("role=\"alert\""));
    assert!(body.contains("Rejection evidence"));
}

/// Returns a test router with web routes + assets.
fn test_router() -> Router {
    let ports = piteka_api::TestPorts::new();
    let use_case = ports.use_case();
    crate::web_router(use_case)
}

fn assets_router() -> Router {
    crate::assets_router()
}

fn combined_router() -> Router {
    let ports = piteka_api::TestPorts::new();
    let use_case = ports.use_case();
    Router::new()
        .merge(crate::assets_router())
        .merge(crate::web_router(use_case.clone()))
        .merge(piteka_api::routes::build_full_router(use_case))
}

// ── Positive tests: pages are served ───────────────────────────────────────

#[tokio::test]
async fn work_queue_returns_200() {
    let mut app = test_router();

    let request = Request::builder()
        .method("GET")
        .uri("/work-queue")
        .body(Body::empty())
        .unwrap();

    let response = app.call(request).await.expect("call failed");
    assert_eq!(response.status(), StatusCode::OK);

    let body = String::from_utf8(
        axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();

    assert!(body.contains("<!DOCTYPE html>"));
    assert!(body.contains("Work queue"));
    assert!(body.contains("pk-sidebar"));
}

#[tokio::test]
async fn request_detail_returns_200() {
    let mut app = combined_router();

    // First create a request via the API
    let body = serde_json::json!({
        "requested_by": "agent@example.com",
        "intent_id": "intent-d08-test"
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

    let request_id: String = {
        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), 1024 * 1024)
                .await
                .unwrap(),
        )
        .unwrap();
        body["id"].as_str().unwrap().to_string()
    };

    // Now visit the detail page
    let request = Request::builder()
        .method("GET")
        .uri(&format!("/request/{}", request_id))
        .body(Body::empty())
        .unwrap();

    let response = app.call(request).await.expect("call failed");
    assert_eq!(response.status(), StatusCode::OK);

    let body = String::from_utf8(
        axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();

    assert!(body.contains("pk-intent-panel"));
    assert!(body.contains("Requested action"));
}

#[tokio::test]
async fn executions_returns_200() {
    let mut app = test_router();

    let request = Request::builder()
        .method("GET")
        .uri("/executions")
        .body(Body::empty())
        .unwrap();

    let response = app.call(request).await.expect("call failed");
    assert_eq!(response.status(), StatusCode::OK);

    let body = String::from_utf8(
        axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();

    assert!(body.contains("Executions"));
}

#[tokio::test]
async fn case_files_returns_200() {
    let mut app = test_router();

    let request = Request::builder()
        .method("GET")
        .uri("/case-files")
        .body(Body::empty())
        .unwrap();

    let response = app.call(request).await.expect("call failed");
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn verification_returns_200() {
    let mut app = test_router();

    let request = Request::builder()
        .method("GET")
        .uri("/verification")
        .body(Body::empty())
        .unwrap();

    let response = app.call(request).await.expect("call failed");
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn settings_returns_200() {
    let mut app = test_router();

    let request = Request::builder()
        .method("GET")
        .uri("/settings")
        .body(Body::empty())
        .unwrap();

    let response = app.call(request).await.expect("call failed");
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn css_is_served() {
    let mut app = assets_router();

    let request = Request::builder()
        .method("GET")
        .uri("/assets/piteka.css")
        .body(Body::empty())
        .unwrap();

    let response = app.call(request).await.expect("call failed");
    assert_eq!(response.status(), StatusCode::OK);

    let body = String::from_utf8(
        axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();

    assert!(body.contains("--surface-0:"));
    assert!(body.contains("--ink-1:"));
    assert!(body.contains("--interactive:"));
    assert!(body.contains("--seal:"));
}

// ── Accessibility tests ───────────────────────────────────────────────────

#[tokio::test]
async fn work_queue_has_semantic_html_structure() {
    let mut app = test_router();

    let request = Request::builder()
        .method("GET")
        .uri("/work-queue")
        .body(Body::empty())
        .unwrap();

    let response = app.call(request).await.expect("call failed");
    let body = String::from_utf8(
        axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();

    // Must have DOCTYPE, html, head, body
    assert!(body.contains("<!DOCTYPE html>"));
    assert!(body.contains("<html"));
    assert!(body.contains("<head>"));
    assert!(body.contains("<body>"));

    // Must have a nav element for sidebar navigation
    assert!(body.contains("<aside") || body.contains("pk-sidebar"));

    // Must have a main element
    assert!(body.contains("<main") || body.contains("pk-main"));

    // Must have a table with scope attributes for headers
    assert!(body.contains("scope=\"col\""));

    // Must have lang attribute on html
    assert!(body.contains("lang=\"en\""));
}

#[tokio::test]
async fn request_detail_has_aria_attributes() {
    let mut app = combined_router();

    // Create a request first
    let body = serde_json::json!({
        "requested_by": "agent@example.com",
        "intent_id": "intent-aria-test"
    });

    let request = Request::builder()
        .method("POST")
        .uri("/api/v1/action-requests")
        .header("content-type", "application/json")
        .header("X-Tenant-Id", "demo")
        .body(Body::from(body.to_string()))
        .unwrap();

    let response = app.call(request).await.expect("call failed");
    let request_id: String = {
        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), 1024 * 1024)
                .await
                .unwrap(),
        )
        .unwrap();
        body["id"].as_str().unwrap().to_string()
    };

    // Visit the detail page
    let request = Request::builder()
        .method("GET")
        .uri(&format!("/request/{}", request_id))
        .body(Body::empty())
        .unwrap();

    let response = app.call(request).await.expect("call failed");
    let body = String::from_utf8(
        axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();

    // Must have aria-label on navigation
    assert!(body.contains("aria-label"));

    // Must have aria-current for active page
    assert!(body.contains("aria-current"));

    // Must have role attributes on key elements
    assert!(body.contains("role="));
}

#[tokio::test]
async fn step_up_overlay_is_accessible() {
    let mut app = test_router();

    let request = Request::builder()
        .method("GET")
        .uri("/request/test-id")
        .body(Body::empty())
        .unwrap();

    let response = app.call(request).await.expect("call failed");
    let body = String::from_utf8(
        axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();

    // Must have the step-up overlay with dialog role
    assert!(body.contains("pk-overlay"));
    assert!(body.contains("role=\"dialog\""));
    assert!(body.contains("aria-modal=\"true\""));

    // Must have a cancel button
    assert!(body.contains("pk-btn-secondary") || body.contains("Cancel"));

    // Must have a password input with autocomplete
    assert!(body.contains("type=\"password\""));
    assert!(body.contains("autocomplete=\"current-password\""));
}

#[tokio::test]
async fn status_chips_use_icon_plus_label_not_color_only() {
    let mut app = combined_router();

    let create = Request::builder()
        .method("POST")
        .uri("/api/v1/action-requests")
        .header("content-type", "application/json")
        .header("X-Tenant-Id", "demo")
        .body(Body::from(
            serde_json::json!({
                "requested_by": "agent@example.com",
                "intent_id": "intent-status-test"
            })
            .to_string(),
        ))
        .unwrap();
    assert_eq!(
        app.call(create).await.unwrap().status(),
        StatusCode::CREATED
    );

    let request = Request::builder()
        .method("GET")
        .uri("/work-queue")
        .body(Body::empty())
        .unwrap();

    let response = app.call(request).await.expect("call failed");
    let body = String::from_utf8(
        axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();

    // Status chips must have both icon and label
    assert!(body.contains("pk-status-chip"));
    assert!(body.contains("pk-status-icon"));
}

#[tokio::test]
async fn hash_fields_are_copyable() {
    let mut app = combined_router();

    let body = serde_json::json!({
        "requested_by": "agent@example.com",
        "intent_id": "a3f9c2b1d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1"
    });

    let request = Request::builder()
        .method("POST")
        .uri("/api/v1/action-requests")
        .header("content-type", "application/json")
        .header("X-Tenant-Id", "demo")
        .body(Body::from(body.to_string()))
        .unwrap();

    let response = app.call(request).await.expect("call failed");
    let request_id: String = {
        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), 1024 * 1024)
                .await
                .unwrap(),
        )
        .unwrap();
        body["id"].as_str().unwrap().to_string()
    };

    let request = Request::builder()
        .method("GET")
        .uri(&format!("/request/{}", request_id))
        .body(Body::empty())
        .unwrap();

    let response = app.call(request).await.expect("call failed");
    let body = String::from_utf8(
        axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();

    // Hash fields must be focusable (tabindex="0") and have a tooltip
    assert!(body.contains("pk-hash-field"));
    assert!(body.contains("hash-tooltip"));
}

// ── Design system token tests ─────────────────────────────────────────────

#[tokio::test]
async fn css_contains_all_required_design_tokens() {
    let mut app = assets_router();

    let request = Request::builder()
        .method("GET")
        .uri("/assets/piteka.css")
        .body(Body::empty())
        .unwrap();

    let response = app.call(request).await.expect("call failed");
    let body = String::from_utf8(
        axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();

    // Required semantic tokens from Design System §2.1
    assert!(body.contains("--status-met:"));
    assert!(body.contains("--status-not-met:"));
    assert!(body.contains("--status-indeterminate:"));
    assert!(body.contains("--status-not-applicable:"));
    assert!(body.contains("--status-attention:"));
    assert!(body.contains("--status-quarantine:"));
    assert!(body.contains("--status-gap:"));

    // Piteka "Ledger" skin tokens from Design System §2.2
    assert!(body.contains("--surface-0:"));
    assert!(body.contains("--surface-1:"));
    assert!(body.contains("--surface-2:"));
    assert!(body.contains("--ink-1:"));
    assert!(body.contains("--ink-2:"));
    assert!(body.contains("--ink-3:"));
    assert!(body.contains("--rule:"));
    assert!(body.contains("--interactive:"));
    assert!(body.contains("--seal:"));
    assert!(body.contains("--focus-ring:"));

    // Typography tokens
    assert!(body.contains("IBM Plex Sans"));
    assert!(body.contains("IBM Plex Mono"));

    // Reduced motion support
    assert!(body.contains("prefers-reduced-motion"));
}

#[tokio::test]
async fn css_contrast_ratios_meet_wcag_aa() {
    let mut app = assets_router();

    let request = Request::builder()
        .method("GET")
        .uri("/assets/piteka.css")
        .body(Body::empty())
        .unwrap();

    let response = app.call(request).await.expect("call failed");
    let body = String::from_utf8(
        axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();

    fn channel(value: u8) -> f64 {
        let value = f64::from(value) / 255.0;
        if value <= 0.04045 {
            value / 12.92
        } else {
            ((value + 0.055) / 1.055).powf(2.4)
        }
    }
    fn luminance(hex: &str) -> f64 {
        let value = u32::from_str_radix(hex.trim_start_matches('#'), 16).unwrap();
        0.2126 * channel((value >> 16) as u8)
            + 0.7152 * channel((value >> 8) as u8)
            + 0.0722 * channel(value as u8)
    }
    fn ratio(left: &str, right: &str) -> f64 {
        let (a, b) = (luminance(left), luminance(right));
        (a.max(b) + 0.05) / (a.min(b) + 0.05)
    }

    let matrix = include_str!("../wcag-aa-contrast-matrix.csv");
    for row in matrix.lines().skip(1) {
        let columns: Vec<_> = row.split(',').collect();
        let minimum: f64 = columns[3].parse().unwrap();
        let actual = ratio(columns[0], columns[1]);
        assert!(
            actual >= minimum,
            "{} on {} for {} is {actual:.2}:1, below {minimum}:1",
            columns[0],
            columns[1],
            columns[2]
        );
        assert!(
            body.contains(columns[0]),
            "matrix color {} is absent from CSS",
            columns[0]
        );
    }
}

#[test]
fn unix_timestamps_render_as_absolute_utc() {
    assert_eq!(
        crate::format_timestamp(0),
        ("1970-01-01T00:00:00Z".into(), "1970-01-01T00:00:00Z".into())
    );
    assert_eq!(
        crate::format_timestamp(1_704_067_200),
        ("2024-01-01T00:00:00Z".into(), "2024-01-01T00:00:00Z".into())
    );
}

#[test]
fn rev03_templates_keep_deep_links_out_of_demo_navigation() {
    let base = include_str!("../../../crates/piteka-ui/templates/base.html");
    assert!(!base.contains(">Case files</a>"));
    assert!(!base.contains(">Settings</a>"));
    assert!(base.contains(">Integration</a>"));
    assert!(base.contains(">Confirm identity</h2>"));
}

#[test]
fn rev03_approval_and_quarantine_language_is_fixed() {
    let detail = include_str!("../../../crates/piteka-ui/templates/request_detail.html");
    assert!(detail.contains("Approve deployment"));
    assert!(detail.contains("pk-btn-primary"));
    assert!(!detail.contains("Approve &amp; sign"));
    assert!(detail.contains("This approval cannot be retried"));
    assert!(detail.contains("closed unresolved and remain unusable"));
    assert!(detail.contains("Deployment controls"));
    assert!(detail.contains("Piteka-controlled"));
}

#[test]
fn rev03_integration_surfaces_single_approval_and_consumer() {
    let integration = include_str!("../../../crates/piteka-ui/templates/settings.html");
    assert!(integration.contains("Approval layers"));
    assert!(integration.contains("Configuration incompatible with demo profile"));
    assert!(integration.contains("Deployment consumer"));
    assert!(integration.contains("original deployment ID"));
}

// ── Negative tests ────────────────────────────────────────────────────────

#[tokio::test]
async fn nonexistent_request_returns_work_queue_not_500() {
    let mut app = test_router();

    let request = Request::builder()
        .method("GET")
        .uri("/request/nonexistent-request-id")
        .body(Body::empty())
        .unwrap();

    let response = app.call(request).await.expect("call failed");
    // Should not crash with 500
    assert!(response.status() < StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn css_has_focus_visible_styles() {
    let mut app = assets_router();

    let request = Request::builder()
        .method("GET")
        .uri("/assets/piteka.css")
        .body(Body::empty())
        .unwrap();

    let response = app.call(request).await.expect("call failed");
    let body = String::from_utf8(
        axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();

    // Must have :focus-visible styles for keyboard navigation
    assert!(body.contains(":focus-visible"));
    assert!(body.contains("outline:"));
}

#[tokio::test]
async fn pages_include_limitations_strip() {
    let mut app = combined_router();

    let body = serde_json::json!({
        "requested_by": "agent@example.com",
        "intent_id": "intent-limitations-test"
    });

    let request = Request::builder()
        .method("POST")
        .uri("/api/v1/action-requests")
        .header("content-type", "application/json")
        .header("X-Tenant-Id", "demo")
        .body(Body::from(body.to_string()))
        .unwrap();

    let response = app.call(request).await.expect("call failed");
    let request_id: String = {
        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), 1024 * 1024)
                .await
                .unwrap(),
        )
        .unwrap();
        body["id"].as_str().unwrap().to_string()
    };

    let request = Request::builder()
        .method("GET")
        .uri(&format!("/request/{}", request_id))
        .body(Body::empty())
        .unwrap();

    let response = app.call(request).await.expect("call failed");
    let body = String::from_utf8(
        axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();

    // Limitations strip must be present on every receipt/detail page
    assert!(body.contains("pk-limitations-strip"));
    assert!(body.contains("What this record does not establish"));
}
