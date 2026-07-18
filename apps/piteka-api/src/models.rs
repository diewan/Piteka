//! Request and response types for the first-slice API.
//!
//! All types derive `Serialize` / `Deserialize` for JSON wire format.

use serde::{Deserialize, Serialize};

/// The status of an action request as returned to the client.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ActionRequestStatus {
    /// Awaiting an approver's decision.
    Pending,
    /// Approved by an authorized approver.
    Approved,
    /// Rejected by an authorized approver.
    Rejected,
    /// Approved but later revoked before dispatch.
    Revoked,
}

impl From<piteka_storage::ActionRequestStatus> for ActionRequestStatus {
    fn from(status: piteka_storage::ActionRequestStatus) -> Self {
        match status {
            piteka_storage::ActionRequestStatus::Pending => Self::Pending,
            piteka_storage::ActionRequestStatus::Approved => Self::Approved,
            piteka_storage::ActionRequestStatus::Rejected => Self::Rejected,
            piteka_storage::ActionRequestStatus::Revoked => Self::Revoked,
        }
    }
}

/// A compact summary returned by the list endpoint.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionRequestSummary {
    /// The request identifier.
    pub id: String,
    /// The user who proposed the request.
    pub requested_by: String,
    /// Current status.
    pub status: ActionRequestStatus,
    /// Creation time, Unix seconds.
    pub created_at: u64,
}

/// Full action request detail returned by the get endpoint.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionRequestResponse {
    /// The request identifier.
    pub id: String,
    /// The user who proposed the request.
    pub requested_by: String,
    /// Parwana intent digest (lower-case hex), if already constructed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub intent_id: Option<String>,
    /// Current status.
    pub status: ActionRequestStatus,
    /// Creation time, Unix seconds.
    pub created_at: u64,
    /// Approval decisions recorded for this request.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub decisions: Vec<ApprovalDecisionResponse>,
}

/// An approval or rejection decision.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalDecisionResponse {
    /// The decision identifier.
    pub id: String,
    /// The user who made the decision.
    pub decided_by: String,
    /// `approved` or `rejected`.
    pub decision: String,
    /// The intent digest the approver reviewed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub intent_id: Option<String>,
    /// Decision time, Unix seconds.
    pub decided_at: u64,
}

impl From<piteka_storage::ApprovalDecision> for ApprovalDecisionResponse {
    fn from(d: piteka_storage::ApprovalDecision) -> Self {
        Self {
            id: d.decision_id,
            decided_by: d.decided_by,
            decision: d.decision,
            intent_id: d.intent_id_hex,
            decided_at: d.decided_at_unix_seconds as u64,
        }
    }
}

/// Request body for proposing a new action request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateActionRequestRequest {
    /// The user proposing the action.
    pub requested_by: String,
    /// Parwana intent digest (lower-case hex), if already constructed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub intent_id: Option<String>,
}

/// Request body for approving an action request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApproveRequest {
    /// The approver's user id.
    pub approver_id: String,
    /// The intent digest the approver reviewed (must match the request's intent).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub intent_id: Option<String>,
    /// The expected version for optimistic concurrency (CAS).
    pub version: i64,
}

/// Request body for rejecting an action request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RejectRequest {
    /// The approver's user id.
    pub approver_id: String,
    /// The intent digest the approver reviewed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub intent_id: Option<String>,
    /// The expected version for optimistic concurrency (CAS).
    pub version: i64,
}

/// Request body for revoking an approved action request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevokeRequest {
    /// The approver's user id.
    pub approver_id: String,
    /// The expected version for optimistic concurrency (CAS).
    pub version: i64,
}
