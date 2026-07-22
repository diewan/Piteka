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

/// A preserved Single-Use Seal consumption proof for one mandate (Phase B, §5.9).
///
/// Written off the dispatch hot path by the local seal backing and immutable once
/// stored. It corroborates that the mandate's single use was enforced independently of
/// the private Postgres reservation: `nullifier_hex` is the mandate's reservation-token
/// digest and `commitment_hex` is the authorized intent id. A dispute bundle carries it
/// as a Parwana `SealConsumptionRecord` that an offline verifier re-checks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealConsumptionProofRecord {
    /// Mandate the proof corroborates, lower-case hex. Primary key.
    pub mandate_id_hex: String,
    /// Identifier of the consumed single-use seal, lower-case hex.
    pub seal_id_hex: String,
    /// Consumption nullifier (the mandate's reservation-token digest), lower-case hex.
    pub nullifier_hex: String,
    /// Commitment the seal bound at issue (the authorized intent id), lower-case hex.
    pub commitment_hex: String,
    /// Stable identifier of the backing that produced the proof.
    pub anchor_backend: String,
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

/// Tenant-scoped investigator case. Mutable state is limited to an optimistic
/// version; all investigator content lives in append-only [`CaseEvent`] rows.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InvestigatorCase {
    /// Server-derived tenant identifier.
    pub tenant_id: String,
    /// Opaque case identifier unique within the tenant.
    pub case_id: String,
    /// Optimistic version incremented for every appended event.
    pub version: i64,
    /// Human-readable title fixed when the case is opened.
    pub title: String,
    /// Investigator identity that opened the case.
    pub opened_by: String,
    /// Creation time in Unix seconds.
    pub created_at_unix_seconds: i64,
}

/// One immutable event in an investigator case history.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CaseEvent {
    /// Globally unique event identifier.
    pub event_id: String,
    /// Tenant copied from the owning case and enforced by the repository.
    pub tenant_id: String,
    /// Owning case identifier.
    pub case_id: String,
    /// Strictly increasing sequence equal to the resulting case version.
    pub sequence: i64,
    /// Authenticated investigator identity.
    pub actor: String,
    /// Stable event kind such as `evidence_attached` or `finding_recorded`.
    pub kind: String,
    /// Investigator-authored detail; corrections are later events.
    pub detail: String,
    /// Immutable content digest required for evidence and finding events.
    pub evidence_digest_hex: Option<String>,
    /// Event time in Unix seconds.
    pub occurred_at_unix_seconds: i64,
}

/// Result of appending a case event under optimistic concurrency.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CaseAppendOutcome {
    /// The event was appended atomically.
    Applied {
        /// New case version and event sequence.
        new_version: i64,
    },
    /// Another writer changed the case first.
    Conflict {
        /// Current version observed by the repository.
        current_version: i64,
    },
    /// No case exists in the supplied tenant scope.
    Missing,
}

// ---------------------------------------------------------------------------
// Execution attempt and receipt projections (E-03)
// ---------------------------------------------------------------------------

/// The state of an execution attempt against a reserved mandate.
///
/// Mirrors the execution attempt state machine from Master Plan §10.4.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum ExecutionAttemptState {
    /// The attempt has been prepared but not yet dispatched.
    Prepared,
    /// The dispatch to the provider has been initiated.
    Dispatching,
    /// The provider has accepted the action.
    Accepted,
    /// The provider has explicitly rejected the action.
    Rejected,
    /// The outcome is ambiguous (e.g. network timeout after dispatch).
    OutcomeAmbiguous,
    /// Reconciliation confirmed the provider accepted.
    ReconciledAccepted,
    /// Reconciliation confirmed the provider did not accept.
    ReconciledNotAccepted,
    /// The attempt was abandoned due to unresolved ambiguity.
    AbandonedAmbiguous,
}

impl ExecutionAttemptState {
    /// Returns `true` if this state is terminal (no further transitions allowed).
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        matches!(
            self,
            Self::Accepted
                | Self::Rejected
                | Self::OutcomeAmbiguous
                | Self::ReconciledAccepted
                | Self::ReconciledNotAccepted
                | Self::AbandonedAmbiguous
        )
    }
}

/// An execution attempt binding a reserved mandate to one dispatch attempt.
///
/// See Master Plan §10.4 for the semantic model. The raw reservation token is
/// secret and is never written here or to exported bundles.
///
/// E-04: The `github_deployment_id` field records the GitHub-assigned deployment
/// ID once the Deployments API call succeeds. This enables webhook correlation:
/// when a deployment-status webhook arrives, Piteka can match it to the correct
/// attempt by comparing the deployment ID in the webhook payload against this
/// field.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutionAttempt {
    /// Attempt identifier, lower-case hex. Primary key.
    pub attempt_id_hex: String,
    /// The mandate this attempt was dispatched against.
    pub mandate_id_hex: String,
    /// The intent digest this attempt targets.
    pub intent_id_hex: String,
    /// Digest of the reservation token used for this attempt.
    pub reservation_token_digest: String,
    /// Identity of the executor (service identity).
    pub executor_identity: String,
    /// Correlation key for provider-side matching.
    pub correlation_key: String,
    /// When the attempt was prepared.
    pub started_at_unix_seconds: i64,
    /// When the dispatch boundary was crossed, if known.
    pub dispatch_boundary_at_unix_seconds: Option<i64>,
    /// Current state of this attempt.
    pub state: ExecutionAttemptState,
    /// GitHub-assigned deployment ID, set after `create_deployment` succeeds.
    ///
    /// E-04: This field is `None` until the provider call completes. It is the
    /// stable reference used for webhook correlation and reconciliation.
    pub github_deployment_id: Option<u64>,
}

/// The outcome reported by an execution receipt.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum ReceiptOutcome {
    /// The action succeeded.
    Succeeded,
    /// The action failed.
    Failed,
    /// The action was rejected by the provider.
    Rejected,
    /// The outcome could not be determined.
    Unknown,
}

/// The source of an evidence node or receipt claim.
///
/// Master Plan §10.5: receipts MUST distinguish Piteka claims, provider
/// observations, and verifier conclusions.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum EvidenceSource {
    /// Claimed by Piteka (the enterprise workbench).
    Piteka,
    /// Observed from an external provider (e.g. GitHub).
    Provider(String),
    /// Verifier conclusion derived from evidence.
    Verifier,
}

/// A structured evidence node stored locally.
///
/// Mirrors the four v0.1 node types from Master Plan §10.6: Claim, Observation,
/// Attestation, and EvidenceGap. Each node records its producer, collection time,
/// content digest, and source attribution.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvidenceNodeRecord {
    /// Content-addressed node identifier (lower-case hex).
    pub node_id_hex: String,
    /// Registered type identifier (claim, observation, attestation, gap).
    pub registry_id: String,
    /// The source that produced this node.
    pub source: EvidenceSource,
    /// Identity of the producer.
    pub producer_identity: String,
    /// When the evidence was collected.
    pub collected_at_unix_seconds: i64,
    /// When the asserted event occurred, if known.
    pub asserted_event_at_unix_seconds: Option<i64>,
    /// Content digest of the evidence payload.
    pub content_digest: ContentDigest,
    /// Registered media type.
    pub media_type: String,
    /// Disclosure classification.
    pub disclosure_classification: String,
    /// Related node IDs (canonically sorted).
    pub relationships: Vec<String>,
}

/// A projection of an execution receipt.
///
/// Binds authority (mandate) to action (attempt) and reported outcome.
/// See Master Plan §10.5 for the semantic model.
///
/// E-06: Extended with source attribution, evidence references, and gap tracking.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceiptProjection {
    /// Receipt identifier, lower-case hex. Primary key.
    pub receipt_id_hex: String,
    /// The mandate this receipt is about.
    pub mandate_id_hex: String,
    /// The intent digest this receipt is about.
    pub intent_id_hex: String,
    /// The attempt this receipt covers.
    pub attempt_id_hex: String,
    /// The reported outcome.
    pub outcome: ReceiptOutcome,
    /// When the receipt was produced.
    pub created_at_unix_seconds: i64,
    /// Evidence nodes produced at the dispatch/executor boundary.
    pub dispatch_evidence_refs: Vec<String>,
    /// Evidence nodes produced at the target/provider boundary.
    pub target_evidence_refs: Vec<String>,
    /// Evidence gaps: required evidence that is missing or unavailable.
    pub evidence_gaps: Vec<String>,
    /// The canonical Parwana receipt bytes, if already serialized.
    pub canonical_bytes: Option<Vec<u8>>,
}
