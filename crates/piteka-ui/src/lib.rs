#![forbid(unsafe_code)]

//! Piteka shared UI components and templates.
//!
//! This crate provides the design system (CSS tokens, components) and Askama
//! HTML templates for the Piteka web approval UI. It is the secondary target
//! of Master Plan §59 D-08.
//!
//! Authority: `DIEWAN_DESIGN_SYSTEM_AND_LANGUAGE.md`, `DIEWAN_UX_FLOW_SPEC.md`

use serde::Serialize;

// Every public type in this crate is UI-ready state: strings already formatted
// for display, plus presentation-only fields such as CSS classes and icons.
// They are therefore `ViewModel`s. The earlier `*Row` names borrowed a suffix
// the naming constitution reserves for relational persistence mappings, which
// made rendered table items look like `piteka_storage` rows — the opposite of
// the truth, since none of these values is stored or authoritative.

/// UI-ready state for the work queue page (S1).
#[derive(Serialize)]
pub struct WorkQueuePageViewModel {
    pub title: String,
    pub current_page: String,
    pub requests: Vec<WorkQueueItemViewModel>,
}

/// UI-ready state for one item in the work queue table.
#[derive(Serialize)]
pub struct WorkQueueItemViewModel {
    pub id: String,
    pub requested_by: String,
    pub status: String,
    pub status_class: String,
    pub status_icon: String,
    pub status_label: String,
    pub created_at_human: String,
    pub created_at_iso: String,
}

/// UI-ready state for the request detail / approval panel page (S2).
#[derive(Serialize)]
pub struct RequestDetailPageViewModel {
    pub title: String,
    pub current_page: String,
    pub request: RequestDetailItemViewModel,
    pub intent: IntentPanelViewModel,
}

/// UI-ready state for the request shown on the detail page.
#[derive(Serialize)]
pub struct RequestDetailItemViewModel {
    pub id: String,
    pub requested_by: String,
    pub status: String,
    pub status_class: String,
    pub status_icon: String,
    pub status_label: String,
    pub created_at_human: String,
    pub created_at_iso: String,
    pub decisions: Vec<ApprovalDecisionItemViewModel>,
}

/// UI-ready state for one recorded approval decision.
#[derive(Serialize)]
pub struct ApprovalDecisionItemViewModel {
    pub decided_by: String,
    pub decision: String,
    pub decision_class: String,
    pub decision_label: String,
    pub decided_at_human: String,
    pub decided_at_iso: String,
}

/// UI-ready state for the IntentPanel — the approval's centerpiece.
///
/// Presentation only: `intent_id_hex` is a string to render, never a value the UI
/// may compare or act on. Approval integrity is decided server-side against a
/// freshly loaded `ApprovalCeremonyIntent`.
///
/// # Every field is optional on purpose
///
/// This panel is built from `piteka_storage::ActionRequest`, which records the
/// request id, requester, status, creation time, and — once the intent is
/// constructed — the Parwana intent id. It does **not** record the deployment's
/// repository, commit, environment, or task; those live inside the canonical
/// `ActionIntent` in `protocol_objects`, which this read path does not load.
///
/// So each parameter is `Option` and renders as an explicit "Not recorded in this
/// view" when absent. Filling them with plausible defaults would be a simulated
/// intent on an approval screen (charter §8, and the approval-UI integrity threat
/// where a display must never disagree with what is signed). Absence is shown as
/// absence.
#[derive(Serialize)]
pub struct IntentPanelViewModel {
    /// The Parwana intent digest bound to this request, if one is bound yet.
    pub intent_id_hex: Option<String>,
    /// Deployment repository, when a view that loads the canonical intent supplies it.
    pub repository: Option<String>,
    /// Exact commit SHA, when supplied. Never the intent id.
    pub commit_sha: Option<String>,
    /// Target environment name, when supplied.
    pub environment_name: Option<String>,
    /// Deployment task, when supplied.
    pub task: Option<String>,
    /// Absolute expiry instant, when one is recorded.
    pub expires_at: Option<String>,
    /// Human-rendered expiry, empty when `expires_at` is `None`.
    pub expires_at_human: String,
    /// Whether a recorded expiry has passed.
    pub expired: bool,
}

impl IntentPanelViewModel {
    /// Builds the panel from the only intent-related value the action-request
    /// store actually holds.
    #[must_use]
    pub fn from_recorded_intent_id(intent_id_hex: Option<String>) -> Self {
        Self {
            intent_id_hex,
            repository: None,
            commit_sha: None,
            environment_name: None,
            task: None,
            expires_at: None,
            expires_at_human: String::new(),
            expired: false,
        }
    }
}

/// UI-ready state for placeholder pages.
#[derive(Serialize)]
pub struct PlaceholderPageViewModel {
    pub title: String,
    pub current_page: String,
}
