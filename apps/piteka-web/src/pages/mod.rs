#![forbid(unsafe_code)]

//! Page handlers for the Piteka web UI.
//!
//! Each function returns an Askama template with its data struct.

use askama::Template;
use axum::{
    extract::{Path, State},
    response::Html,
};
use piteka_application::{ActionRequestPorts, ActionRequestUseCase};
use piteka_storage::ActionRequestStatus;
use piteka_ui::{DecisionRow, IntentPanelData, RequestDetailRow, WorkQueueRow};

use crate::{format_timestamp, status_for_decision, status_for_request};

mod filters {
    pub use crate::{first_char, truncate_hash};
}

fn request_status(status: ActionRequestStatus) -> &'static str {
    match status {
        ActionRequestStatus::Pending => "Pending",
        ActionRequestStatus::Approved => "Approved",
        ActionRequestStatus::Rejected => "Rejected",
        ActionRequestStatus::Revoked => "Revoked",
    }
}

/// Work queue page (S1).
#[derive(Template)]
#[template(path = "work_queue.html", escape = "none")]
pub struct WorkQueueTemplate {
    pub title: String,
    pub current_page: String,
    pub requests: Vec<WorkQueueRow>,
}

/// Request detail / approval panel page (S2).
#[derive(Template)]
#[template(path = "request_detail.html", escape = "none")]
pub struct RequestDetailTemplate {
    pub title: String,
    pub current_page: String,
    pub request: RequestDetailRow,
    pub intent: IntentPanelData,
}

/// Executions page (S3).
#[derive(Template)]
#[template(path = "executions.html", escape = "none")]
pub struct ExecutionsTemplate {
    pub title: String,
    pub current_page: String,
}

/// A visible, evidence-backed replay rejection on S3/S4.
#[derive(Template)]
#[template(path = "replay_rejection.html", escape = "html")]
pub struct ReplayRejectionTemplate {
    pub title: String,
    pub current_page: String,
    pub reason_code: String,
    pub mandate_id: String,
    pub executor_identity: String,
    pub mandate_state: String,
    pub message: String,
}

/// Case files page (S5).
#[derive(Template)]
#[template(path = "case_files.html", escape = "none")]
pub struct CaseFilesTemplate {
    pub title: String,
    pub current_page: String,
}

/// Verification page (S7).
#[derive(Template)]
#[template(path = "verification.html", escape = "none")]
pub struct VerificationTemplate {
    pub title: String,
    pub current_page: String,
}

/// Settings page (S6).
#[derive(Template)]
#[template(path = "settings.html", escape = "none")]
pub struct SettingsTemplate {
    pub title: String,
    pub current_page: String,
}

/// GET /work-queue — Work queue (S1).
pub async fn work_queue<P: ActionRequestPorts>(
    State(use_case): State<ActionRequestUseCase<P>>,
) -> Html<String> {
    let requests = use_case.list_requests().await.unwrap_or_default();

    let rows: Vec<WorkQueueRow> = requests
        .into_iter()
        .map(|r| {
            let status = request_status(r.status).to_string();
            let (status_class, status_icon, status_label) = status_for_request(&status);
            let (human, iso) = format_timestamp(r.created_at_unix_seconds as u64);
            WorkQueueRow {
                id: r.request_id,
                requested_by: r.requested_by,
                status,
                status_class,
                status_icon,
                status_label,
                created_at_human: human,
                created_at_iso: iso,
            }
        })
        .collect();

    let template = WorkQueueTemplate {
        title: "Work queue".to_string(),
        current_page: "work-queue".to_string(),
        requests: rows,
    };

    Html(template.render().unwrap())
}

/// GET /request/:id — Request detail / approval panel (S2).
pub async fn request_detail<P: ActionRequestPorts>(
    State(use_case): State<ActionRequestUseCase<P>>,
    Path(request_id): Path<String>,
) -> Html<String> {
    let request = match use_case.get_request(&request_id).await {
        Ok(Some(r)) => r,
        Ok(None) => {
            // Return a 404 placeholder — in production, use axum's Error handling
            let template = WorkQueueTemplate {
                title: "Not found".to_string(),
                current_page: "work-queue".to_string(),
                requests: vec![],
            };
            return Html(template.render().unwrap());
        }
        Err(_) => {
            let template = WorkQueueTemplate {
                title: "Error".to_string(),
                current_page: "work-queue".to_string(),
                requests: vec![],
            };
            return Html(template.render().unwrap());
        }
    };

    let decisions = use_case
        .get_decisions(&request_id)
        .await
        .unwrap_or_default();

    let status = request_status(request.status).to_string();
    let (status_class, status_icon, status_label) = status_for_request(&status);
    let (req_human, req_iso) = format_timestamp(request.created_at_unix_seconds as u64);

    let decision_rows: Vec<DecisionRow> = decisions
        .into_iter()
        .map(|d| {
            let (dec_class, dec_label) = status_for_decision(&d.decision);
            let (dec_human, dec_iso) = format_timestamp(d.decided_at_unix_seconds as u64);
            DecisionRow {
                decided_by: d.decided_by,
                decision: d.decision,
                decision_class: dec_class,
                decision_label: dec_label,
                decided_at_human: dec_human,
                decided_at_iso: dec_iso,
            }
        })
        .collect();

    let request_row = RequestDetailRow {
        id: request.request_id,
        requested_by: request.requested_by,
        status,
        status_class,
        status_icon,
        status_label,
        created_at_human: req_human,
        created_at_iso: req_iso,
        decisions: decision_rows,
    };

    // Build intent panel data from the request's intent_id
    let intent = IntentPanelData {
        repository_owner: "diewan".to_string(),
        repository_name: "demo-app".to_string(),
        commit_sha: request.intent_id_hex.clone().unwrap_or_else(|| {
            "0000000000000000000000000000000000000000000000000000000000000000".to_string()
        }),
        environment_name: "production".to_string(),
        production_environment: true,
        task: "deploy".to_string(),
        expires_at: None,
        expires_at_human: "No expiry set".to_string(),
        expired: false,
        digest: request.intent_id_hex.clone().unwrap_or_else(|| {
            "0000000000000000000000000000000000000000000000000000000000000000".to_string()
        }),
        evidence_requirements: vec![
            "GitHub commit status: all required contexts passed".to_string(),
            "Artifact attestation present".to_string(),
        ],
    };

    let template = RequestDetailTemplate {
        title: format!("Request {}", request_id),
        current_page: "work-queue".to_string(),
        request: request_row,
        intent,
    };

    Html(template.render().unwrap())
}

/// GET /executions — Executions & outcomes (S3).
pub async fn executions() -> Html<String> {
    let template = ExecutionsTemplate {
        title: "Executions".to_string(),
        current_page: "executions".to_string(),
    };
    Html(template.render().unwrap())
}

/// GET /case-files — Case file export (S5).
pub async fn case_files() -> Html<String> {
    let template = CaseFilesTemplate {
        title: "Case files".to_string(),
        current_page: "case-files".to_string(),
    };
    Html(template.render().unwrap())
}

/// GET /verification — Verification report (S7).
pub async fn verification() -> Html<String> {
    let template = VerificationTemplate {
        title: "Verification".to_string(),
        current_page: "verification".to_string(),
    };
    Html(template.render().unwrap())
}

/// GET /settings — Settings (S6).
pub async fn settings() -> Html<String> {
    let template = SettingsTemplate {
        title: "Settings".to_string(),
        current_page: "settings".to_string(),
    };
    Html(template.render().unwrap())
}
