#![forbid(unsafe_code)]

//! Piteka shared UI components and templates.
//!
//! This crate provides the design system (CSS tokens, components) and Askama
//! HTML templates for the Piteka web approval UI. It is the secondary target
//! of Master Plan §59 D-08.
//!
//! Authority: `DIEWAN_DESIGN_SYSTEM_AND_LANGUAGE.md`, `DIEWAN_UX_FLOW_SPEC.md`

use serde::Serialize;

/// Data for the work queue page (S1).
#[derive(Serialize)]
pub struct WorkQueuePage {
    pub title: String,
    pub current_page: String,
    pub requests: Vec<WorkQueueRow>,
}

/// A single row in the work queue table.
#[derive(Serialize)]
pub struct WorkQueueRow {
    pub id: String,
    pub requested_by: String,
    pub status: String,
    pub status_class: String,
    pub status_icon: String,
    pub status_label: String,
    pub created_at_human: String,
    pub created_at_iso: String,
}

/// Data for the request detail / approval panel page (S2).
#[derive(Serialize)]
pub struct RequestDetailPage {
    pub title: String,
    pub current_page: String,
    pub request: RequestDetailRow,
    pub intent: IntentPanelData,
}

/// A request row on the detail page.
#[derive(Serialize)]
pub struct RequestDetailRow {
    pub id: String,
    pub requested_by: String,
    pub status: String,
    pub status_class: String,
    pub status_icon: String,
    pub status_label: String,
    pub created_at_human: String,
    pub created_at_iso: String,
    pub decisions: Vec<DecisionRow>,
}

/// A decision row.
#[derive(Serialize)]
pub struct DecisionRow {
    pub decided_by: String,
    pub decision: String,
    pub decision_class: String,
    pub decision_label: String,
    pub decided_at_human: String,
    pub decided_at_iso: String,
}

/// The IntentPanel data — the approval's centerpiece.
#[derive(Serialize)]
pub struct IntentPanelData {
    pub repository_owner: String,
    pub repository_name: String,
    pub commit_sha: String,
    pub environment_name: String,
    pub production_environment: bool,
    pub task: String,
    pub expires_at: Option<String>,
    pub expires_at_human: String,
    pub expired: bool,
    pub digest: String,
    pub evidence_requirements: Vec<String>,
}

/// Data for placeholder pages.
#[derive(Serialize)]
pub struct PlaceholderPage {
    pub title: String,
    pub current_page: String,
}
