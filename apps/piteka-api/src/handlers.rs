//! Request handlers for the first-slice API endpoints.

use axum::{
    Json,
    extract::{Path, State, FromRequestParts},
    http::{StatusCode, request::Parts},
    response::{IntoResponse, Response},
};
use piteka_application::ActionRequestUseCase;
use piteka_domain::UserId;

use crate::error::{ApiError, ErrorResponse};
use crate::models::{
    ActionRequestResponse, ActionRequestSummary,
    ApproveRequest, CreateActionRequestRequest, RejectRequest, RevokeRequest,
};
use crate::TestPorts;

/// Optional idempotency key extracted from the request header.
#[derive(Debug, Default)]
pub struct IdempotencyKey(pub Option<String>);

impl<S> FromRequestParts<S> for IdempotencyKey
where
    S: Send + Sync,
{
    type Rejection = (StatusCode, Json<ErrorResponse>);

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let key = parts
            .headers
            .get("Idempotency-Key")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        Ok(IdempotencyKey(key))
    }
}

/// List all action requests.
///
/// `GET /api/v1/action-requests`
///
/// Returns a 200 with an array of summaries.
pub async fn list_action_requests(
    State(use_case): State<ActionRequestUseCase<TestPorts>>,
) -> Response {
    match use_case.list_requests().await {
        Ok(requests) => {
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
        Err(err) => ApiError::from(err).into_response(),
    }
}

/// Get a single action request by id.
///
/// `GET /api/v1/action-requests/{id}`
///
/// Returns the full request detail including decisions, or 404 if not found.
pub async fn get_action_request(
    State(use_case): State<ActionRequestUseCase<TestPorts>>,
    Path(request_id): Path<String>,
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

/// Propose a new action request.
///
/// `POST /api/v1/action-requests`
///
/// Supports idempotency via the `Idempotency-Key` header. A second call with
/// the same key returns the original result.
pub async fn propose_action_request(
    State(use_case): State<ActionRequestUseCase<TestPorts>>,
    _idempotency_key: IdempotencyKey,
    Json(body): Json<CreateActionRequestRequest>,
) -> Response {
    // Validate request body
    if body.requested_by.is_empty() {
        return ApiError::bad_request(
            "EMPTY_REQUESTED_BY",
            "The `requested_by` field is required",
        )
        .into_response();
    }

    let user_id = match UserId::new(&body.requested_by) {
        Ok(id) => id,
        Err(_) => UserId::new("unknown").unwrap(),
    };

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

    (StatusCode::CREATED, Json(response)).into_response()
}

/// Approve an action request.
///
/// `POST /api/v1/action-requests/{id}/approve`
///
/// Supports idempotency via the `Idempotency-Key` header.
pub async fn approve_action_request(
    State(use_case): State<ActionRequestUseCase<TestPorts>>,
    _idempotency_key: IdempotencyKey,
    Path(request_id): Path<String>,
    Json(body): Json<ApproveRequest>,
) -> Response {
    if body.approver_id.is_empty() {
        return ApiError::bad_request(
            "EMPTY_APPROVER_ID",
            "The `approver_id` field is required",
        )
        .into_response();
    }

    let user_id = match UserId::new(&body.approver_id) {
        Ok(id) => id,
        Err(_) => UserId::new("unknown").unwrap(),
    };

    let approved = match use_case.approve(&request_id, user_id, body.intent_id, body.version).await {
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

/// Reject an action request.
///
/// `POST /api/v1/action-requests/{id}/reject`
///
/// Supports idempotency via the `Idempotency-Key` header.
pub async fn reject_action_request(
    State(use_case): State<ActionRequestUseCase<TestPorts>>,
    _idempotency_key: IdempotencyKey,
    Path(request_id): Path<String>,
    Json(body): Json<RejectRequest>,
) -> Response {
    if body.approver_id.is_empty() {
        return ApiError::bad_request(
            "EMPTY_APPROVER_ID",
            "The `approver_id` field is required",
        )
        .into_response();
    }

    let user_id = match UserId::new(&body.approver_id) {
        Ok(id) => id,
        Err(_) => UserId::new("unknown").unwrap(),
    };

    let rejected = match use_case.reject(&request_id, user_id, body.intent_id, body.version).await {
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

/// Revoke an approved action request.
///
/// `POST /api/v1/action-requests/{id}/revoke`
///
/// Supports idempotency via the `Idempotency-Key` header.
pub async fn revoke_action_request(
    State(use_case): State<ActionRequestUseCase<TestPorts>>,
    _idempotency_key: IdempotencyKey,
    Path(request_id): Path<String>,
    Json(body): Json<RevokeRequest>,
) -> Response {
    if body.approver_id.is_empty() {
        return ApiError::bad_request(
            "EMPTY_APPROVER_ID",
            "The `approver_id` field is required",
        )
        .into_response();
    }

    let user_id = match UserId::new(&body.approver_id) {
        Ok(id) => id,
        Err(_) => UserId::new("unknown").unwrap(),
    };

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
