//! Axum route definitions for the first-slice API.

use axum::{
    Json, Router,
    extract::{Path, State},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use piteka_application::ActionRequestUseCase;
use piteka_application::bundle_export::export_manifest_bytes;
use piteka_storage::postgres::{
    PgAuditLog, PgEvidenceNodeStore, PgExecutionAttemptStore, PgMandateProjectionStore,
    PgReceiptProjectionStore,
};
use piteka_storage::{
    AuditLog, EvidenceNodeRecord, EvidenceNodeStore, EvidenceSource, ExecutionAttempt,
    ExecutionAttemptState, ExecutionAttemptStore, MandateProjectionStore, ReceiptOutcome,
    ReceiptProjection, ReceiptProjectionStore,
};

use crate::TestPorts;
use crate::error::ApiError;
use crate::models::{
    ActionRequestResponse, ActionRequestSummary, ApproveRequest, ChainAttempt, ChainEvidence,
    ChainStep, CreateActionRequestRequest, MandateChain, MandateDetail, ReceiptDetail,
    ReceiptSummary, RejectRequest, RevokeRequest,
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

/// Builds the PostgreSQL-backed live webhook route.
pub async fn build_live_webhook_router(
    database_url: &str,
) -> Result<Router, piteka_storage::StorageError> {
    let pool = piteka_storage::postgres::connect(database_url).await?;
    piteka_storage::postgres::run_migrations(&pool).await?;
    let webhook_receipts = piteka_storage::postgres::PgWebhookReceiptStore::new(pool.clone());
    let audit = piteka_storage::postgres::PgAuditLog::new(pool.clone());
    let attempts = std::sync::Arc::new(piteka_storage::postgres::PgExecutionAttemptStore::new(
        pool.clone(),
    ));
    let processor = piteka_application::ReceiptProducingProcessor::new(
        piteka_storage::postgres::PgReceiptProjectionStore::new(pool.clone()),
        piteka_storage::postgres::PgEvidenceNodeStore::new(pool),
        audit.clone(),
        attempts,
    );
    let ingestion = piteka_application::WebhookIngestionUseCase::new(
        piteka_application::WebhookIngestionPorts::new(processor, webhook_receipts, audit),
    );
    let state = crate::webhook::WebhookStateConcrete {
        ingestion,
        clock: piteka_application::SystemClock,
        github: std::sync::Arc::new(crate::MockGitHubAdapter::default()),
        webhook_secret: piteka_ports::github::GitHubWebhookSecret::new(
            "live-webhook-secret-reference",
        )
        .expect("static secret reference is non-empty"),
    };
    Ok(Router::new()
        .route(
            "/api/v1/webhooks/github",
            post(crate::webhook::handle_webhook),
        )
        .with_state(state))
}

/// Shared state for the Postgres-backed read API. Holds the projection stores;
/// each is a cheap clone over a shared connection pool.
#[derive(Clone)]
pub struct ReadState {
    receipts: PgReceiptProjectionStore,
    evidence: PgEvidenceNodeStore,
    mandates: PgMandateProjectionStore,
    attempts: PgExecutionAttemptStore,
    audit: PgAuditLog,
}

/// Builds the PostgreSQL-backed **read** API that Hemion's explorer drills into.
///
/// These endpoints expose Piteka's own projections (receipts, mandates, the
/// assembled accountability chain, and bundle exports). They are read-only:
/// Hemion recomputes validity locally against the Parwana verifier and never
/// trusts a verdict from here (Master Plan §32).
pub async fn build_live_read_router(
    database_url: &str,
) -> Result<Router, piteka_storage::StorageError> {
    let pool = piteka_storage::postgres::connect(database_url).await?;
    piteka_storage::postgres::run_migrations(&pool).await?;
    let state = ReadState {
        receipts: PgReceiptProjectionStore::new(pool.clone()),
        evidence: PgEvidenceNodeStore::new(pool.clone()),
        mandates: PgMandateProjectionStore::new(pool.clone()),
        attempts: PgExecutionAttemptStore::new(pool.clone()),
        audit: PgAuditLog::new(pool),
    };
    Ok(Router::new()
        .route("/api/v1/receipts", get(list_receipts))
        .route("/api/v1/receipts/{id}", get(get_receipt))
        .route("/api/v1/receipts/{id}/export", get(export_receipt))
        .route("/api/v1/mandates/{id}", get(get_mandate))
        .route("/api/v1/mandates/{id}/chain", get(get_mandate_chain))
        .with_state(state))
}

// ── Read-model handlers ──────────────────────────────────────────────────────

/// `GET /api/v1/receipts` — every receipt, newest first.
async fn list_receipts(State(state): State<ReadState>) -> Response {
    let ids = match state.receipts.list_ids_ordered().await {
        Ok(ids) => ids,
        Err(err) => return ApiError::from(err).into_response(),
    };
    let mut summaries = Vec::with_capacity(ids.len());
    for (id, _created) in ids {
        match state.receipts.get(&id).await {
            Ok(Some(receipt)) => summaries.push(ReceiptSummary {
                receipt_id: receipt.receipt_id_hex,
                mandate_id: receipt.mandate_id_hex,
                outcome: outcome_str(&receipt.outcome).to_string(),
                created_at: receipt.created_at_unix_seconds,
            }),
            Ok(None) => {}
            Err(err) => return ApiError::from(err).into_response(),
        }
    }
    summaries.reverse();
    Json(summaries).into_response()
}

/// `GET /api/v1/receipts/{id}` — one receipt projection.
async fn get_receipt(State(state): State<ReadState>, Path(id): Path<String>) -> Response {
    match state.receipts.get(&id).await {
        Ok(Some(receipt)) => Json(receipt_detail(receipt)).into_response(),
        Ok(None) => ApiError::not_found("receipt", &id).into_response(),
        Err(err) => ApiError::from(err).into_response(),
    }
}

/// `GET /api/v1/receipts/{id}/export` — the bundle-export manifest bytes for
/// local verification in Hemion.
async fn export_receipt(State(state): State<ReadState>, Path(id): Path<String>) -> Response {
    match state.receipts.get(&id).await {
        Ok(None) => return ApiError::not_found("receipt", &id).into_response(),
        Err(err) => return ApiError::from(err).into_response(),
        Ok(Some(_)) => {}
    }
    match export_manifest_bytes(&state.receipts, &state.evidence, &id).await {
        Ok(bytes) => (
            [(axum::http::header::CONTENT_TYPE, "application/json")],
            bytes,
        )
            .into_response(),
        Err(err) => ApiError::internal(format!("cannot export receipt {id}: {err}")).into_response(),
    }
}

/// `GET /api/v1/mandates/{id}` — one mandate projection.
async fn get_mandate(State(state): State<ReadState>, Path(id): Path<String>) -> Response {
    match state.mandates.get(&id).await {
        Ok(Some(mandate)) => Json(MandateDetail {
            mandate_id: mandate.mandate_id_hex,
            state: mandate.state,
            version: mandate.version,
        })
        .into_response(),
        Ok(None) => ApiError::not_found("mandate", &id).into_response(),
        Err(err) => ApiError::from(err).into_response(),
    }
}

/// `GET /api/v1/mandates/{id}/chain` — the assembled accountability chain:
/// mandate → audit timeline → execution attempts → receipts → evidence nodes.
async fn get_mandate_chain(State(state): State<ReadState>, Path(id): Path<String>) -> Response {
    let mandate = match state.mandates.get(&id).await {
        Ok(Some(mandate)) => mandate,
        Ok(None) => return ApiError::not_found("mandate", &id).into_response(),
        Err(err) => return ApiError::from(err).into_response(),
    };
    let receipts = match state.receipts.by_mandate(&id).await {
        Ok(receipts) => receipts,
        Err(err) => return ApiError::from(err).into_response(),
    };
    let attempts = match state.attempts.by_mandate(&id).await {
        Ok(attempts) => attempts,
        Err(err) => return ApiError::from(err).into_response(),
    };

    // Resolve every distinct evidence node the receipts reference.
    let mut evidence_ids: Vec<String> = Vec::new();
    for receipt in &receipts {
        for node_id in receipt
            .dispatch_evidence_refs
            .iter()
            .chain(receipt.target_evidence_refs.iter())
        {
            if !evidence_ids.contains(node_id) {
                evidence_ids.push(node_id.clone());
            }
        }
    }
    let mut evidence = Vec::with_capacity(evidence_ids.len());
    for node_id in &evidence_ids {
        match state.evidence.get(node_id).await {
            Ok(Some(node)) => evidence.push(chain_evidence(node)),
            Ok(None) => {}
            Err(err) => return ApiError::from(err).into_response(),
        }
    }

    // Correlate audit events to this chain by the ids that appear in `detail`.
    // (A structured subject column would make this exact; see plan notes.)
    let mut match_ids: Vec<String> = vec![id.clone()];
    for receipt in &receipts {
        if !receipt.intent_id_hex.is_empty() {
            match_ids.push(receipt.intent_id_hex.clone());
        }
        if !receipt.attempt_id_hex.is_empty() {
            match_ids.push(receipt.attempt_id_hex.clone());
        }
    }
    for attempt in &attempts {
        match_ids.push(attempt.attempt_id_hex.clone());
    }
    let recent = match state.audit.recent(2000).await {
        Ok(events) => events,
        Err(err) => return ApiError::from(err).into_response(),
    };
    let mut timeline: Vec<ChainStep> = recent
        .into_iter()
        .filter(|event| match_ids.iter().any(|needle| event.detail.contains(needle.as_str())))
        .map(|event| ChainStep {
            at: event.occurred_at_unix_seconds,
            actor: event.actor,
            action: event.action,
            decision: event.decision,
            detail: event.detail,
        })
        .collect();
    // Present the chain chronologically. A stable sort by timestamp preserves
    // the audit log's insertion order for same-second ties (propose → approve
    // → reserve → consume).
    timeline.sort_by_key(|step| step.at);

    let response = MandateChain {
        mandate: MandateDetail {
            mandate_id: mandate.mandate_id_hex,
            state: mandate.state,
            version: mandate.version,
        },
        timeline,
        attempts: attempts.into_iter().map(chain_attempt).collect(),
        receipts: receipts.into_iter().map(receipt_detail).collect(),
        evidence,
    };
    Json(response).into_response()
}

fn receipt_detail(receipt: ReceiptProjection) -> ReceiptDetail {
    ReceiptDetail {
        receipt_id: receipt.receipt_id_hex,
        mandate_id: receipt.mandate_id_hex,
        intent_id: receipt.intent_id_hex,
        attempt_id: receipt.attempt_id_hex,
        outcome: outcome_str(&receipt.outcome).to_string(),
        created_at: receipt.created_at_unix_seconds,
        dispatch_evidence_refs: receipt.dispatch_evidence_refs,
        target_evidence_refs: receipt.target_evidence_refs,
        evidence_gaps: receipt.evidence_gaps,
    }
}

fn chain_attempt(attempt: ExecutionAttempt) -> ChainAttempt {
    ChainAttempt {
        attempt_id: attempt.attempt_id_hex,
        executor_identity: attempt.executor_identity,
        state: attempt_state_str(&attempt.state).to_string(),
        github_deployment_id: attempt.github_deployment_id,
        started_at: attempt.started_at_unix_seconds,
    }
}

fn chain_evidence(node: EvidenceNodeRecord) -> ChainEvidence {
    ChainEvidence {
        node_id: node.node_id_hex,
        registry_id: node.registry_id,
        source: source_str(&node.source),
        producer_identity: node.producer_identity,
        content_digest: node.content_digest.to_hex(),
        media_type: node.media_type,
    }
}

fn outcome_str(outcome: &ReceiptOutcome) -> &'static str {
    match outcome {
        ReceiptOutcome::Succeeded => "succeeded",
        ReceiptOutcome::Failed => "failed",
        ReceiptOutcome::Rejected => "rejected",
        ReceiptOutcome::Unknown => "unknown",
    }
}

fn attempt_state_str(state: &ExecutionAttemptState) -> &'static str {
    match state {
        ExecutionAttemptState::Prepared => "prepared",
        ExecutionAttemptState::Dispatching => "dispatching",
        ExecutionAttemptState::Accepted => "accepted",
        ExecutionAttemptState::Rejected => "rejected",
        ExecutionAttemptState::OutcomeAmbiguous => "outcome_ambiguous",
        ExecutionAttemptState::ReconciledAccepted => "reconciled_accepted",
        ExecutionAttemptState::ReconciledNotAccepted => "reconciled_not_accepted",
        ExecutionAttemptState::AbandonedAmbiguous => "abandoned_ambiguous",
    }
}

fn source_str(source: &EvidenceSource) -> String {
    match source {
        EvidenceSource::Piteka => "piteka".to_string(),
        EvidenceSource::Provider(name) => format!("provider:{name}"),
        EvidenceSource::Verifier => "verifier".to_string(),
    }
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
