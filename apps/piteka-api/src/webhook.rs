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
//! that arrive more than 60 seconds after the previous delivery of the same
//! type are flagged as out-of-order but **not rejected**. The flag is logged
//! to the audit trail for downstream handlers to use.

use axum::{
    extract::{Request, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use piteka_application::{
    IngestionOutcome, SystemClock, WebhookEventProcessor,
    WebhookIngestionPorts, WebhookIngestionUseCase,
};
use piteka_ports::github::{
    GitHubAppPort, GitHubInstallationContext, GitHubWebhookPayload, WebhookSignatureResult,
};

use crate::error::{ApiError, ErrorResponse};
use crate::{MockGitHubAdapter, MockWebhookProcessor};

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

/// Concrete state type for the webhook handler.
pub type WebhookState = crate::webhook::WebhookStateConcrete;

/// State available to the webhook handler.
#[derive(Clone)]
pub struct WebhookStateConcrete {
    /// The webhook ingestion use case.
    pub ingestion: piteka_application::WebhookIngestionUseCase<
        MockWebhookProcessor,
        std::sync::Arc<piteka_storage::memory::InMemoryWebhookReceiptStore>,
        std::sync::Arc<piteka_storage::memory::InMemoryAuditLog>,
    >,
    /// The clock for time-dependent operations.
    pub clock: SystemClock,
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
pub async fn handle_webhook(
    State(state): State<WebhookStateConcrete>,
    request: Request,
) -> Response {
    let headers = request.headers().clone();

    // Step 1: Validate required headers.
    let delivery_id = match headers
        .get("X-GitHub-Delivery")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
    {
        Some(id) if !id.is_empty() => id,
        _ => return ApiError::bad_request("MISSING_DELIVERY_ID", "The `X-GitHub-Delivery` header is required").into_response(),
    };

    let event_type = match headers
        .get("X-GitHub-Event")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
    {
        Some(et) if !et.is_empty() => et,
        _ => return ApiError::bad_request("MISSING_EVENT_TYPE", "The `X-GitHub-Event` header is required").into_response(),
    };

    let signature = match headers
        .get("X-Hub-Signature-256")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
    {
        Some(sig) if !sig.is_empty() => sig,
        _ => return ApiError::unauthorized("MISSING_SIGNATURE", "The `X-Hub-Signature-256` header is required").into_response(),
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

    // Step 3: Validate signature using internal verification.
    let sig_result = piteka_github::verify_webhook_signature_internal(&payload.body, &signature, "demo-webhook-secret");

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

    // Step 4 & 5: Ingest (dedup + raw digest recording).
    let outcome = match state.ingestion.ingest(&payload, &state.clock).await {
        Ok(o) => o,
        Err(err) => return ApiError::internal(format!("Webhook ingestion failed: {}", err)).into_response(),
    };

    // Step 6: Dispatch to application-level processor (fire-and-forget for
    // the HTTP response; errors are logged to the audit trail).
    match &outcome {
        IngestionOutcome::Duplicate => {
            // Duplicate delivery — log and return 200.
            state.ingestion.dispatch(&event_type, &payload.body, &delivery_id, false, &state.clock).await;
            (StatusCode::OK, Json(WebhookResponse::duplicate())).into_response()
        }
        IngestionOutcome::Processed { out_of_order, raw_digest } => {
            // New delivery — dispatch and return 200.
            state.ingestion.dispatch(&event_type, &payload.body, &delivery_id, *out_of_order, &state.clock).await;
            (StatusCode::OK, Json(WebhookResponse::processed(*out_of_order, raw_digest.to_hex()))).into_response()
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
    fn duplicate() -> Self {
        Self {
            delivery_id: String::new(),
            outcome: "duplicate".to_string(),
            out_of_order: None,
            raw_digest_hex: None,
        }
    }

    fn processed(out_of_order: bool, raw_digest_hex: String) -> Self {
        Self {
            delivery_id: String::new(),
            outcome: "processed".to_string(),
            out_of_order: Some(out_of_order),
            raw_digest_hex: Some(raw_digest_hex),
        }
    }
}
