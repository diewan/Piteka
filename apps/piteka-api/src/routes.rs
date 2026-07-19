//! Axum route definitions for the first-slice API.

use axum::{
    Json, Router,
    extract::State,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use piteka_application::ActionRequestUseCase;

use crate::TestPorts;
use crate::error::ApiError;
use crate::models::{
    ActionRequestResponse, ActionRequestSummary, ApproveRequest, CreateActionRequestRequest,
    RejectRequest, RevokeRequest,
};

/// Builds the action-requests router mounted at `/api/v1/action-requests`.
pub fn action_requests(use_case: ActionRequestUseCase<TestPorts>) -> Router {
    Router::new()
        .route("/", get(list_action_requests))
        .route("/", post(propose_action_request))
        .route("/{id}", get(get_action_request))
        .route("/{id}/approve", post(approve_action_request))
        .route("/{id}/reject", post(reject_action_request))
        .route("/{id}/revoke", post(revoke_action_request))
        .with_state(use_case)
}

/// Builds the full API router with all first-slice endpoints.
///
/// Mounts at `/api/v1` and serves the OpenAPI spec at `/api/v1/openapi.json`.
pub fn build_full_router(use_case: ActionRequestUseCase<TestPorts>) -> Router {
    let action_routes = action_requests(use_case);

    Router::new()
        .nest("/api/v1/action-requests", action_routes)
        .route(
            "/api/v1/openapi.json",
            axum::routing::get(|| async {
                let spec: serde_json::Value = serde_json::from_str(crate::OPENAPI_SPEC).unwrap();
                axum::response::Json(spec)
            }),
        )
}

/// Builds the full API router including the authenticated GitHub webhook.
pub fn build_full_router_with_webhook(ports: TestPorts) -> Router {
    build_full_router(ports.use_case()).merge(
        Router::new()
            .route(
                "/api/v1/webhooks/github",
                post(crate::webhook::handle_webhook),
            )
            .with_state(ports.webhook_state()),
    )
}

// ── Handlers ────────────────────────────────────────────────────────────────

async fn list_action_requests(State(use_case): State<ActionRequestUseCase<TestPorts>>) -> Response {
    let requests = match use_case.list_requests().await {
        Ok(r) => r,
        Err(err) => return ApiError::from(err).into_response(),
    };

    let summaries: Vec<ActionRequestSummary> = requests
        .into_iter()
        .map(|r| ActionRequestSummary {
            id: r.request_id,
            requested_by: r.requested_by,
            status: r.status.into(),
            created_at: r.created_at_unix_seconds as u64,
        })
        .collect();

    Json(summaries).into_response()
}

async fn get_action_request(
    State(use_case): State<ActionRequestUseCase<TestPorts>>,
    axum::extract::Path(request_id): axum::extract::Path<String>,
) -> Response {
    let request = match use_case.get_request(&request_id).await {
        Ok(r) => r,
        Err(err) => return ApiError::from(err).into_response(),
    };

    let request = match request {
        Some(r) => r,
        None => return ApiError::not_found("action request", &request_id).into_response(),
    };

    let decisions = match use_case.get_decisions(&request_id).await {
        Ok(d) => d,
        Err(err) => return ApiError::from(err).into_response(),
    };

    let response = ActionRequestResponse {
        id: request.request_id,
        requested_by: request.requested_by,
        intent_id: request.intent_id_hex,
        status: request.status.into(),
        created_at: request.created_at_unix_seconds as u64,
        decisions: decisions.into_iter().map(|d| d.into()).collect(),
    };

    Json(response).into_response()
}

async fn propose_action_request(
    State(use_case): State<ActionRequestUseCase<TestPorts>>,
    Json(body): Json<CreateActionRequestRequest>,
) -> Response {
    if body.requested_by.is_empty() {
        return ApiError::bad_request("EMPTY_REQUESTED_BY", "The `requested_by` field is required")
            .into_response();
    }

    let user_id = piteka_domain::UserId::new(&body.requested_by)
        .unwrap_or_else(|_| piteka_domain::UserId::new("unknown").unwrap());

    let request_id = uuid::Uuid::new_v4().to_string();

    let proposed = match use_case.propose(&request_id, user_id, body.intent_id).await {
        Ok(p) => p,
        Err(err) => return ApiError::from(err).into_response(),
    };

    let request = proposed.request;
    let response = ActionRequestResponse {
        id: request.request_id,
        requested_by: request.requested_by,
        intent_id: request.intent_id_hex,
        status: request.status.into(),
        created_at: request.created_at_unix_seconds as u64,
        decisions: Vec::new(),
    };

    (axum::http::StatusCode::CREATED, Json(response)).into_response()
}

async fn approve_action_request(
    State(use_case): State<ActionRequestUseCase<TestPorts>>,
    axum::extract::Path(request_id): axum::extract::Path<String>,
    Json(body): Json<ApproveRequest>,
) -> Response {
    if body.approver_id.is_empty() {
        return ApiError::bad_request("EMPTY_APPROVER_ID", "The `approver_id` field is required")
            .into_response();
    }

    let user_id = piteka_domain::UserId::new(&body.approver_id)
        .unwrap_or_else(|_| piteka_domain::UserId::new("unknown").unwrap());

    let approved = match use_case
        .approve(&request_id, user_id, body.intent_id, body.version)
        .await
    {
        Ok(a) => a,
        Err(err) => return ApiError::from(err).into_response(),
    };

    let decisions = match use_case.get_decisions(&request_id).await {
        Ok(d) => d,
        Err(err) => return ApiError::from(err).into_response(),
    };

    let response = ActionRequestResponse {
        id: approved.request.request_id,
        requested_by: approved.request.requested_by,
        intent_id: approved.request.intent_id_hex,
        status: approved.request.status.into(),
        created_at: approved.request.created_at_unix_seconds as u64,
        decisions: decisions.into_iter().map(|d| d.into()).collect(),
    };

    Json(response).into_response()
}

async fn reject_action_request(
    State(use_case): State<ActionRequestUseCase<TestPorts>>,
    axum::extract::Path(request_id): axum::extract::Path<String>,
    Json(body): Json<RejectRequest>,
) -> Response {
    if body.approver_id.is_empty() {
        return ApiError::bad_request("EMPTY_APPROVER_ID", "The `approver_id` field is required")
            .into_response();
    }

    let user_id = piteka_domain::UserId::new(&body.approver_id)
        .unwrap_or_else(|_| piteka_domain::UserId::new("unknown").unwrap());

    let rejected = match use_case
        .reject(&request_id, user_id, body.intent_id, body.version)
        .await
    {
        Ok(r) => r,
        Err(err) => return ApiError::from(err).into_response(),
    };

    let decisions = match use_case.get_decisions(&request_id).await {
        Ok(d) => d,
        Err(err) => return ApiError::from(err).into_response(),
    };

    let response = ActionRequestResponse {
        id: rejected.request.request_id,
        requested_by: rejected.request.requested_by,
        intent_id: rejected.request.intent_id_hex,
        status: rejected.request.status.into(),
        created_at: rejected.request.created_at_unix_seconds as u64,
        decisions: decisions.into_iter().map(|d| d.into()).collect(),
    };

    Json(response).into_response()
}

async fn revoke_action_request(
    State(use_case): State<ActionRequestUseCase<TestPorts>>,
    axum::extract::Path(request_id): axum::extract::Path<String>,
    Json(body): Json<RevokeRequest>,
) -> Response {
    if body.approver_id.is_empty() {
        return ApiError::bad_request("EMPTY_APPROVER_ID", "The `approver_id` field is required")
            .into_response();
    }

    let user_id = piteka_domain::UserId::new(&body.approver_id)
        .unwrap_or_else(|_| piteka_domain::UserId::new("unknown").unwrap());

    let revoked = match use_case.revoke(&request_id, user_id, body.version).await {
        Ok(r) => r,
        Err(err) => return ApiError::from(err).into_response(),
    };

    let decisions = match use_case.get_decisions(&request_id).await {
        Ok(d) => d,
        Err(err) => return ApiError::from(err).into_response(),
    };

    let response = ActionRequestResponse {
        id: revoked.request.request_id,
        requested_by: revoked.request.requested_by,
        intent_id: revoked.request.intent_id_hex,
        status: revoked.request.status.into(),
        created_at: revoked.request.created_at_unix_seconds as u64,
        decisions: decisions.into_iter().map(|d| d.into()).collect(),
    };

    Json(response).into_response()
}
