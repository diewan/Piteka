#![forbid(unsafe_code)]

//! Piteka web approval UI — the primary target of Master Plan §59 D-08.
//!
//! Serves HTML pages for the Piteka enterprise workbench, implementing the
//! screens defined in the UX Flow Spec:
//!
//! | ID | Screen | Route |
//! |----|--------|-------|
//! | S1 | Work queue | `/work-queue` |
//! | S2 | Request detail / Approval panel | `/request/:id` |
//! | S3 | Executions & outcomes | `/executions` |
//! | S4 | Action Journey | (from S2) |
//! | S5 | Case file export | `/case-files` |
//! | S7 | Verification report | `/verification` |
//! | S6 | Settings | `/settings` |
//!
//! The design system (CSS tokens, components) lives in `piteka-ui`.

pub mod pages;

use askama::Template;
use axum::{Router, response::Html, routing::get};
use piteka_application::ActionRequestUseCase;
use serde::Deserialize;

/// Renders the replay-rejection evidence returned by the authoritative
/// dispatch use case. Keeping this renderer input typed prevents navigation or
/// browser state from manufacturing a rejection.
pub fn render_replay_rejection(
    rejection: &piteka_application::dispatch::ReplayRejection,
) -> Html<String> {
    let template = pages::ReplayRejectionTemplate {
        title: "Repeat use rejected".to_string(),
        current_page: "executions".to_string(),
        reason_code: rejection.reason_code.to_string(),
        mandate_id: rejection.mandate_id_hex.clone(),
        executor_identity: rejection.executor_identity.clone(),
        mandate_state: rejection.mandate_state.clone(),
        message: rejection.message.clone(),
    };
    Html(
        template
            .render()
            .expect("replay rejection template is valid"),
    )
}

/// Query params for the request detail page.
#[derive(Deserialize)]
pub struct RequestQuery {
    #[serde(default)]
    pub approver: Option<String>,
}

/// Builds the web UI router mounted at `/`.
pub fn web_router(use_case: ActionRequestUseCase<piteka_api::TestPorts>) -> Router {
    Router::new()
        .route("/work-queue", get(pages::work_queue))
        .route("/request/{id}", get(pages::request_detail))
        .route("/executions", get(pages::executions))
        .route("/case-files", get(pages::case_files))
        .route("/verification", get(pages::verification))
        .route("/settings", get(pages::settings))
        .route("/health", get(|| async { "ready" }))
        .with_state(use_case)
}

/// Serves static assets from the `assets/` directory.
pub fn assets_router() -> Router {
    Router::new().route(
        "/assets/piteka.css",
        get(|| async {
            Html(include_str!("../../../crates/piteka-ui/assets/piteka.css").to_string())
        }),
    )
}

/// Formats a Unix timestamp as a human-readable string.
fn format_timestamp(unix_secs: u64) -> (String, String) {
    // Simple formatting: use the raw value for ISO, a readable form for display.
    // In production, use a proper datetime crate.
    let iso = "1970-01-01T00:00:00Z".to_string(); // Placeholder — would use chrono in production
    let human = format!("{}s", unix_secs);
    (human, iso)
}

/// Truncates a hash for display: first 6 + "…" + last 4.
/// Used by the askama truncate_hash filter.
pub fn truncate_hash(hash: &str) -> askama::Result<String> {
    Ok(if hash.len() <= 12 {
        hash.to_string()
    } else {
        format!("{}…{}", &hash[..6], &hash[hash.len() - 4..])
    })
}

/// Gets the first character of a string for avatar initials.
pub fn first_char(s: &str) -> askama::Result<String> {
    Ok(s.chars()
        .next()
        .map(|c| c.to_ascii_uppercase())
        .unwrap_or('?')
        .to_string())
}

/// Determines the status class and label for a request.
fn status_for_request(status: &str) -> (String, String, String) {
    match status {
        "Pending" => (
            "pending".to_string(),
            "⏳".to_string(),
            "Awaiting review".to_string(),
        ),
        "Approved" => (
            "approved".to_string(),
            "✓".to_string(),
            "Approved — not yet used".to_string(),
        ),
        "Rejected" => (
            "rejected".to_string(),
            "✗".to_string(),
            "Rejected".to_string(),
        ),
        "Revoked" => (
            "revoked".to_string(),
            "↩".to_string(),
            "Revoked".to_string(),
        ),
        _ => (
            "indeterminate".to_string(),
            "?".to_string(),
            status.to_string(),
        ),
    }
}

/// Determines the status class and label for a decision.
fn status_for_decision(decision: &str) -> (String, String) {
    match decision {
        "approved" => ("approved".to_string(), "Approved".to_string()),
        "rejected" => ("rejected".to_string(), "Rejected".to_string()),
        _ => ("indeterminate".to_string(), decision.to_string()),
    }
}

#[cfg(test)]
mod tests;
