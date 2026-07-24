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
//! | S5 | Case file export | `/case-files` (deep link from an action) |
//! | S7 | Verification report | `/verification` |
//! | S6 | Integration | `/settings` (security operator only) |
//!
//! The design system (CSS tokens, components) lives in `piteka-ui`.

pub mod pages;

use askama::Template;
use axum::{Router, response::Html, routing::get};
use piteka_application::{ActionRequestPorts, ActionRequestUseCase};
use serde::Deserialize;

/// Server-derived approval presentation. The visible digest and submitted
/// digest are populated from the same immutable field.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApprovalSummary {
    /// The exact server-derived approval-ceremony intent being displayed.
    pub intent: piteka_application::ApprovalCeremonyIntent,
    /// Approval-ceremony digest both displayed and submitted.
    ///
    /// This is not the Parwana intent id; it is the local binding digest that
    /// proves the approver signed exactly what was rendered.
    pub digest_hex: String,
}

impl ApprovalSummary {
    /// Creates a summary only from the server-derived approval-ceremony intent.
    pub fn new(intent: piteka_application::ApprovalCeremonyIntent) -> Self {
        let digest_hex = intent.digest_hex();
        Self { intent, digest_hex }
    }

    /// Renders an accessible security context. The mutation handler must still
    /// verify this digest against a freshly loaded approval-ceremony intent.
    ///
    /// The digest is labelled "Approval digest" rather than "Intent digest":
    /// it is a Piteka-local binding over the displayed fields, and an operator
    /// must not read it as the Parwana intent id, which is a different value
    /// with different authority.
    pub fn render_security_context(&self) -> String {
        format!(
            "<section aria-labelledby=\"approval-context-title\">\
             <h2 id=\"approval-context-title\">Exact production intent</h2>\
             <dl><dt>Environment</dt><dd>{}</dd>\
             <dt>Repository</dt><dd>{}</dd>\
             <dt>Revision</dt><dd>{}</dd>\
             <dt>Approval digest</dt><dd id=\"intent-digest\"><code>{}</code></dd></dl>\
             <input type=\"hidden\" name=\"displayed_intent_digest\" value=\"{}\" \
             aria-describedby=\"intent-digest\">\
             </section>",
            escape_html(&self.intent.environment),
            escape_html(&self.intent.repository),
            escape_html(&self.intent.revision),
            self.digest_hex,
            self.digest_hex,
        )
    }
}

fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

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
///
/// Generic over the ports `P` so the server-rendered pages read from the same
/// backing store as the REST API: in-memory [`piteka_api::TestPorts`] with no
/// database, or the Postgres-backed `piteka_api::LiveActionRequestPorts` when
/// `DATABASE_URL` is set.
pub fn web_router<P>(use_case: ActionRequestUseCase<P>) -> Router
where
    P: ActionRequestPorts + Clone + Send + Sync + 'static,
{
    Router::new()
        .route("/work-queue", get(pages::work_queue::<P>))
        .route("/request/{id}", get(pages::request_detail::<P>))
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
    // Howard Hinnant's civil-from-days conversion. Keeping this small formatter
    // local avoids a second time interpretation: stored Unix seconds are always
    // rendered as an absolute UTC instant.
    let seconds = i64::try_from(unix_secs).unwrap_or(i64::MAX);
    let days = seconds.div_euclid(86_400);
    let day_seconds = seconds.rem_euclid(86_400);
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 }.div_euclid(146_097);
    let day_of_era = z - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    let hour = day_seconds / 3_600;
    let minute = day_seconds % 3_600 / 60;
    let second = day_seconds % 60;
    let iso = format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z");
    (iso.clone(), iso)
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
