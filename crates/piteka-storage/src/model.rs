//! Storage records and operation outcomes.
//!
//! Records are Piteka-local. The `protocol_objects` record holds canonical
//! Parwana bytes as an opaque immutable blob keyed by the Parwana object id;
//! Piteka never re-interprets or re-serializes those bytes here.

use crate::digest::ContentDigest;

/// A canonical Parwana object stored as an immutable, id-addressed blob.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProtocolObjectRecord {
    /// Parwana object kind (for example `action_intent`), stored verbatim.
    pub kind: String,
    /// Parwana object identifier, lower-case hex. Primary key.
    pub object_id_hex: String,
    /// Exact canonical bytes produced by Parwana's serializer.
    pub bytes: Vec<u8>,
}

/// The mutable projection of a single-use mandate's live state.
///
/// The authoritative live state is the Piteka database row; `version` drives the
/// compare-and-swap that keeps exactly one active reservation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MandateProjection {
    /// Parwana mandate identifier, lower-case hex.
    pub mandate_id_hex: String,
    /// Optimistic-concurrency version. Starts at 1 on insert.
    pub version: i64,
    /// Opaque projected state label (for example `reserved`, `consumed`).
    pub state: String,
}

/// The outcome of a compare-and-swap on a mandate projection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CasOutcome {
    /// The swap applied; the returned version is the new value.
    Applied {
        /// The version after applying the swap.
        new_version: i64,
    },
    /// The expected version did not match; no change was made.
    Conflict {
        /// The version currently stored.
        current_version: i64,
    },
    /// No projection exists for the mandate id.
    Missing,
}

/// A received provider webhook, recorded once per delivery id.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WebhookReceipt {
    /// Provider-unique delivery identifier. Unique key.
    pub delivery_id: String,
    /// Source label (for example `github`).
    pub source: String,
    /// Digest of the raw payload retained for forensic reconstruction.
    pub raw_digest: ContentDigest,
    /// Receipt time, Unix seconds.
    pub received_at_unix_seconds: i64,
}

/// The outcome of recording a webhook delivery.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WebhookRecordOutcome {
    /// The delivery was new and stored.
    Recorded,
    /// The delivery id was already present; the call was idempotent.
    Duplicate,
}

/// Metadata describing a content-addressed evidence blob.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvidenceDescriptor {
    /// Content address of the blob.
    pub digest: ContentDigest,
    /// Registered media type of the evidence.
    pub media_type: String,
    /// Size of the blob in bytes.
    pub size_bytes: u64,
}

/// An append-only audit event. Audit events are never updated or deleted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditEvent {
    /// Event time, Unix seconds.
    pub occurred_at_unix_seconds: i64,
    /// Acting identity (for example a user id), if any.
    pub actor: Option<String>,
    /// The attempted action or capability.
    pub action: String,
    /// The decision recorded (for example `granted`, `denied`).
    pub decision: String,
    /// Free-form detail for investigators.
    pub detail: String,
}

/// The current status of an action request.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
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

/// A request for authorization to perform a consequential action.
///
/// Created by a requester, reviewed and decided by an approver. The
/// `intent_id_hex` is the Parwana-canonical intent digest that the approver
/// reviews; the approval decision is bound to that exact digest, never to
/// free-form prompt text.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActionRequest {
    /// Opaque internal request identifier.
    pub request_id: String,
    /// The user id of the requester.
    pub requested_by: String,
    /// Parwana intent identifier (lower-case hex), if already constructed.
    pub intent_id_hex: Option<String>,
    /// Current status of this request.
    pub status: ActionRequestStatus,
    /// Creation time, Unix seconds.
    pub created_at_unix_seconds: i64,
}

/// A human approval or rejection decision on an action request.
///
/// The decision is immutable once recorded; corrections are append-only
/// superseding records. The `intent_id_hex` binds the decision to the exact
/// intent digest the approver reviewed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApprovalDecision {
    /// Opaque internal decision identifier.
    pub decision_id: String,
    /// The action request this decision applies to.
    pub request_id: String,
    /// The user id of the approver.
    pub decided_by: String,
    /// `approved` or `rejected`.
    pub decision: String,
    /// The intent digest the approver reviewed (lower-case hex).
    pub intent_id_hex: Option<String>,
    /// Decision time, Unix seconds.
    pub decided_at_unix_seconds: i64,
}
