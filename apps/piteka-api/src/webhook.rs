//! Webhook ingestion HTTP endpoint.
//!
//! Implements Master Plan §60 E-05: webhook ingestion and authentication.
//!
//! # Endpoint
//!
//! | Method | Path | Description |
//! |--------|------|-------------|
//! | `POST` | `/api/v1/webhooks/github` | Receive GitHub webhook events |
//!
//! # Authentication
//!
//! The endpoint validates the HMAC-SHA256 signature from the
//! `X-Hub-Signature-256` header against the raw payload body using the
//! configured GitHub webhook secret. Requests with missing, malformed, or
//! invalid signatures are rejected with a 401 status.
//!
//! # Replay protection
//!
//! Each delivery is keyed by the `X-GitHub-Delivery` header. Duplicate
//! deliveries (replays) are silently accepted with a 200 status — the
//! ingestion pipeline deduplicates them idempotently.
//!
//! # Out-of-order handling
//!
//! GitHub does not guarantee strict ordering of webhook deliveries. Events
//! whose provider timestamp precedes a previously received status for the same
//! deployment are flagged as out-of-order but **not rejected**. The flag is logged
//! to the audit trail for downstream handlers to use.

use axum::{
    Json,
    extract::{Request, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use piteka_application::{IngestionOutcome, SystemClock, WebhookEventProcessor};
use piteka_ports::github::{
    GitHubAppPort, GitHubWebhookPayload, GitHubWebhookSecret, WebhookSignatureResult,
};

use crate::error::ApiError;
use crate::{MockGitHubAdapter, MockWebhookProcessor};
use piteka_storage::ports::{AuditLog, WebhookDeliveryStore};

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

/// Concrete state type for the webhook handler.
pub type WebhookState = crate::webhook::WebhookStateConcrete;

/// State available to the webhook handler.
#[derive(Clone)]
pub struct WebhookStateConcrete<
    P = MockWebhookProcessor,
    W = std::sync::Arc<piteka_storage::memory::InMemoryWebhookDeliveryStore>,
    A = std::sync::Arc<piteka_storage::memory::InMemoryAuditLog>,
    G = MockGitHubAdapter,
> where
    P: WebhookEventProcessor,
    W: WebhookDeliveryStore,
    A: AuditLog,
    G: GitHubAppPort,
{
    /// The webhook ingestion use case.
    pub ingestion: piteka_application::WebhookIngestionUseCase<P, W, A>,
    /// The clock for time-dependent operations.
    pub clock: SystemClock,
    /// Adapter used to resolve the configured secret and verify the signature.
    pub github: std::sync::Arc<G>,
    /// Reference to the configured webhook signing secret.
    pub webhook_secret: GitHubWebhookSecret,
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// Handles incoming GitHub webhook events.
///
/// # Flow
///
/// 1. Extract headers: delivery ID, event type, signature.
/// 2. Reject if any required header is missing.
/// 3. Validate the HMAC-SHA256 signature.
/// 4. Deduplicate by delivery ID.
/// 5. Record raw payload digest.
/// 6. Dispatch to the application-level processor.
///
/// # HTTP responses
///
/// | Status | Condition |
/// |--------|-----------|
/// | `200 OK` | Valid signature, new or duplicate delivery. |
/// | `400 Bad Request` | Missing required headers. |
/// | `401 Unauthorized` | Invalid or missing signature. |
/// | `500 Internal Server Error` | Storage or processing error. |
pub async fn handle_webhook<P, W, A, G>(
    State(state): State<WebhookStateConcrete<P, W, A, G>>,
    request: Request,
) -> Response
where
    P: WebhookEventProcessor + Clone + 'static,
    W: WebhookDeliveryStore + Clone + 'static,
    A: AuditLog + Clone + 'static,
    G: GitHubAppPort + 'static,
{
    let headers = request.headers().clone();

    // Step 1: Validate required headers.
    let delivery_id = match headers
        .get("X-GitHub-Delivery")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
    {
        Some(id) if !id.is_empty() => id,
        _ => {
            return ApiError::bad_request(
                "MISSING_DELIVERY_ID",
                "The `X-GitHub-Delivery` header is required",
            )
            .into_response();
        }
    };

    let event_type = match headers
        .get("X-GitHub-Event")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
    {
        Some(et) if !et.is_empty() => et,
        _ => {
            return ApiError::bad_request(
                "MISSING_EVENT_TYPE",
                "The `X-GitHub-Event` header is required",
            )
            .into_response();
        }
    };

    let signature = match headers
        .get("X-Hub-Signature-256")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
    {
        Some(sig) if !sig.is_empty() => sig,
        _ => {
            return ApiError::unauthorized(
                "MISSING_SIGNATURE",
                "The `X-Hub-Signature-256` header is required",
            )
            .into_response();
        }
    };

    // Step 2: Read the raw body.
    let body = match axum::body::to_bytes(request.into_body(), usize::MAX).await {
        Ok(b) => b,
        Err(_) => return ApiError::internal("Failed to read request body").into_response(),
    };

    let payload = GitHubWebhookPayload {
        delivery_id: delivery_id.clone(),
        event_type: event_type.clone(),
        signature: signature.clone(),
        body: body.to_vec(),
    };

    // Step 3: Validate through the injected adapter. The API never embeds or
    // logs raw secret material.
    let sig_result = match state
        .github
        .verify_webhook_signature(&payload, &state.webhook_secret)
        .await
    {
        Ok(result) => result,
        Err(_) => {
            return ApiError::internal("Webhook authentication is unavailable").into_response();
        }
    };

    match sig_result {
        WebhookSignatureResult::Valid => {
            // Signature is valid — proceed with ingestion.
        }
        WebhookSignatureResult::MissingOrMalformed => {
            return ApiError::unauthorized(
                "MISSING_OR_MALFORMED_SIGNATURE",
                "The `X-Hub-Signature-256` header is missing or malformed",
            )
            .into_response();
        }
        WebhookSignatureResult::Invalid => {
            return ApiError::unauthorized(
                "INVALID_SIGNATURE",
                "The webhook signature does not match the payload",
            )
            .into_response();
        }
    }

    // GitHub sends `ping` when the App webhook is created or updated. It is
    // authenticated above but is connectivity metadata, not deployment
    // evidence, so acknowledge it without entering the ingestion pipeline.
    if event_type == "ping" {
        return (StatusCode::OK, Json(WebhookResponse::ping(delivery_id))).into_response();
    }

    // Step 4 & 5: Ingest (dedup + raw digest recording).
    let outcome = match state.ingestion.ingest(&payload, &state.clock).await {
        Ok(o) => o,
        Err(piteka_application::webhook_ingestion::error::WebhookError::Malformed(message)) => {
            return ApiError::bad_request("MALFORMED_WEBHOOK", message).into_response();
        }
        Err(piteka_application::webhook_ingestion::error::WebhookError::UnsupportedEventType(
            _,
        )) => {
            return ApiError::bad_request(
                "UNSUPPORTED_EVENT_TYPE",
                "The GitHub event type is not supported",
            )
            .into_response();
        }
        Err(_) => return ApiError::internal("Webhook ingestion failed").into_response(),
    };

    // Step 6: Dispatch to application-level processor (fire-and-forget for
    // the HTTP response; errors are logged to the audit trail).
    match &outcome {
        IngestionOutcome::Duplicate => {
            // Duplicate delivery — idempotent no-op. In particular, do not
            // invoke receipt production a second time.
            (
                StatusCode::OK,
                Json(WebhookResponse::duplicate(delivery_id)),
            )
                .into_response()
        }
        IngestionOutcome::Processed {
            out_of_order,
            raw_digest,
        } => {
            // New delivery — dispatch and return 200.
            state
                .ingestion
                .dispatch(
                    &event_type,
                    &payload.body,
                    &delivery_id,
                    *out_of_order,
                    &state.clock,
                )
                .await;
            (
                StatusCode::OK,
                Json(WebhookResponse::processed(
                    delivery_id,
                    *out_of_order,
                    raw_digest.to_hex(),
                )),
            )
                .into_response()
        }
    }
}

/// Response body for webhook ingestion.
#[derive(Debug, serde::Serialize)]
pub struct WebhookResponse {
    /// The delivery ID that was processed.
    delivery_id: String,
    /// The outcome: `duplicate` or `processed`.
    outcome: String,
    /// Whether the event arrived out of sequence (only present for `processed`).
    #[serde(skip_serializing_if = "Option::is_none")]
    out_of_order: Option<bool>,
    /// SHA-256 hex digest of the raw payload (only present for `processed`).
    #[serde(skip_serializing_if = "Option::is_none")]
    raw_digest_hex: Option<String>,
}

impl WebhookResponse {
    fn ping(delivery_id: String) -> Self {
        Self {
            delivery_id,
            outcome: "ping".to_string(),
            out_of_order: None,
            raw_digest_hex: None,
        }
    }

    fn duplicate(delivery_id: String) -> Self {
        Self {
            delivery_id,
            outcome: "duplicate".to_string(),
            out_of_order: None,
            raw_digest_hex: None,
        }
    }

    fn processed(delivery_id: String, out_of_order: bool, raw_digest_hex: String) -> Self {
        Self {
            delivery_id,
            outcome: "processed".to_string(),
            out_of_order: Some(out_of_order),
            raw_digest_hex: Some(raw_digest_hex),
        }
    }
}

#[cfg(test)]
mod tests {
    use axum::{Router, body::Body, http::Request};
    use piteka_ports::github::WebhookSignatureResult;
    use piteka_storage::ports::WebhookDeliveryStore;
    use tower_service::Service;

    use super::*;

    fn payload(updated_at: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "deployment": { "id": 42 },
            "state": "success",
            "updated_at": updated_at
        }))
        .unwrap()
    }

    fn request(delivery_id: &str, body: Vec<u8>) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri("/api/v1/webhooks/github")
            .header("X-GitHub-Delivery", delivery_id)
            .header("X-GitHub-Event", "deployment_status")
            .header("X-Hub-Signature-256", format!("sha256={}", "00".repeat(32)))
            .body(Body::from(body))
            .unwrap()
    }

    fn router(ports: &crate::TestPorts) -> Router {
        Router::new()
            .route(
                "/api/v1/webhooks/github",
                axum::routing::post(handle_webhook),
            )
            .with_state(ports.webhook_state())
    }

    #[tokio::test]
    async fn authenticated_delivery_records_digest_and_delivery_id() {
        let ports = crate::TestPorts::new();
        *ports.github_adapter.verify_result.lock().unwrap() = Some(WebhookSignatureResult::Valid);
        let raw = payload("2026-07-19T10:00:00Z");
        let response = router(&ports)
            .call(request("delivery-1", raw.clone()))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let stored = ports
            .webhook_receipt_store
            .get(&ports.tenant, "delivery-1")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            stored.raw_digest,
            piteka_storage::digest::ContentDigest::of(&raw)
        );
        assert_eq!(ports.webhook_processor.recorded.lock().unwrap().len(), 1);

        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), 64 * 1024)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(body["delivery_id"], "delivery-1");
        assert_eq!(body["outcome"], "processed");
    }

    #[tokio::test]
    async fn authenticated_ping_is_acknowledged_without_recording_evidence() {
        let ports = crate::TestPorts::new();
        *ports.github_adapter.verify_result.lock().unwrap() = Some(WebhookSignatureResult::Valid);
        let ping = Request::builder()
            .method("POST")
            .uri("/api/v1/webhooks/github")
            .header("X-GitHub-Delivery", "ping-delivery")
            .header("X-GitHub-Event", "ping")
            .header("X-Hub-Signature-256", format!("sha256={}", "00".repeat(32)))
            .body(Body::from(r#"{"zen":"Keep it logically awesome."}"#))
            .unwrap();
        let response = router(&ports).call(ping).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(
            ports
                .webhook_receipt_store
                .get(&ports.tenant, "ping-delivery")
                .await
                .unwrap()
                .is_none()
        );
        assert!(ports.webhook_processor.recorded.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn invalid_signature_fails_before_storage_or_processing() {
        let ports = crate::TestPorts::new();
        let response = router(&ports)
            .call(request("forged", payload("2026-07-19T10:00:00Z")))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert!(
            ports
                .webhook_receipt_store
                .get(&ports.tenant, "forged")
                .await
                .unwrap()
                .is_none()
        );
        assert!(ports.webhook_processor.recorded.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn replay_is_idempotent_and_does_not_dispatch_twice() {
        let ports = crate::TestPorts::new();
        *ports.github_adapter.verify_result.lock().unwrap() = Some(WebhookSignatureResult::Valid);
        let mut app = router(&ports);
        let raw = payload("2026-07-19T10:00:00Z");
        assert_eq!(
            app.call(request("same-delivery", raw.clone()))
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
        let response = app.call(request("same-delivery", raw)).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), 64 * 1024)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(body["delivery_id"], "same-delivery");
        assert_eq!(body["outcome"], "duplicate");
        assert_eq!(ports.webhook_processor.recorded.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn older_provider_event_is_flagged_out_of_order() {
        let ports = crate::TestPorts::new();
        *ports.github_adapter.verify_result.lock().unwrap() = Some(WebhookSignatureResult::Valid);
        let mut app = router(&ports);
        app.call(request("newer", payload("2026-07-19T10:01:00Z")))
            .await
            .unwrap();
        let response = app
            .call(request("older", payload("2026-07-19T10:00:00Z")))
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), 64 * 1024)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(body["out_of_order"], true);
        let events = ports.webhook_processor.recorded.lock().unwrap();
        assert!(events[1].out_of_order);
    }
}
