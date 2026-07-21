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

// ── Read-model responses (Hemion explorer drill-down) ────────────────────────
//
// These serialize Piteka's Postgres projections for the developer console.
// They are read-only views; validity is always recomputed locally in Hemion
// against the Parwana verifier, never trusted from these payloads.

/// A row in the receipts list.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptSummary {
    /// Receipt identifier (lower-case hex).
    pub receipt_id: String,
    /// The mandate this receipt is about.
    pub mandate_id: String,
    /// Reported outcome (`succeeded`, `failed`, `rejected`, `unknown`).
    pub outcome: String,
    /// Receipt production time, Unix seconds.
    pub created_at: i64,
}

/// Full receipt projection with its evidence references.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptDetail {
    /// Receipt identifier (lower-case hex).
    pub receipt_id: String,
    /// The mandate this receipt is about.
    pub mandate_id: String,
    /// The intent digest this receipt is about (empty if never bound).
    pub intent_id: String,
    /// The execution attempt this receipt covers.
    pub attempt_id: String,
    /// Reported outcome.
    pub outcome: String,
    /// Receipt production time, Unix seconds.
    pub created_at: i64,
    /// Evidence nodes produced at the dispatch/executor boundary.
    pub dispatch_evidence_refs: Vec<String>,
    /// Evidence nodes produced at the target/provider boundary.
    pub target_evidence_refs: Vec<String>,
    /// Evidence gaps: required evidence that is missing or unavailable.
    pub evidence_gaps: Vec<String>,
}

/// A mandate projection.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MandateDetail {
    /// Mandate identifier (lower-case hex).
    pub mandate_id: String,
    /// Projected state label (for example `reserved`, `consumed`).
    pub state: String,
    /// Optimistic-concurrency version.
    pub version: i64,
}

/// One audit-log step in a mandate's chain, chronological.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainStep {
    /// Event time, Unix seconds.
    pub at: i64,
    /// Acting identity, if any.
    pub actor: Option<String>,
    /// The attempted action or capability.
    pub action: String,
    /// The decision recorded.
    pub decision: String,
    /// Free-form investigator detail.
    pub detail: String,
}

/// An execution attempt in a mandate's chain.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainAttempt {
    /// Attempt identifier (lower-case hex).
    pub attempt_id: String,
    /// Executor service identity.
    pub executor_identity: String,
    /// Current attempt state.
    pub state: String,
    /// GitHub-assigned deployment id, once the provider call completes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub github_deployment_id: Option<u64>,
    /// When the attempt was prepared, Unix seconds.
    pub started_at: i64,
}

/// A structured evidence node referenced by a receipt in the chain.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainEvidence {
    /// Content-addressed node identifier.
    pub node_id: String,
    /// Registered node type (claim, observation, attestation, gap).
    pub registry_id: String,
    /// Source attribution (`piteka`, `provider:github`, `verifier`).
    pub source: String,
    /// Producer identity.
    pub producer_identity: String,
    /// Content digest of the evidence payload (hex).
    pub content_digest: String,
    /// Registered media type.
    pub media_type: String,
}

/// The assembled accountability chain for one mandate: authority → action →
/// provider deployment → receipt → evidence, with the audit timeline.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MandateChain {
    /// The mandate at the root of the chain.
    pub mandate: MandateDetail,
    /// The audit timeline, chronological.
    pub timeline: Vec<ChainStep>,
    /// Execution attempts against this mandate.
    pub attempts: Vec<ChainAttempt>,
    /// Receipts produced for this mandate.
    pub receipts: Vec<ReceiptDetail>,
    /// Evidence nodes referenced by those receipts.
    pub evidence: Vec<ChainEvidence>,
}
