#![forbid(unsafe_code)]

//! Piteka persistence: ports and adapters.
//!
//! Piteka's PostgreSQL database is the sole live-state authority for the mandate
//! reservation CAS (Master Plan §6, §18). This crate defines the persistence
//! [`ports`] and provides:
//!
//! - portable [`memory`] adapters (honest reference implementations),
//! - a content-addressed filesystem [`evidence`] store,
//! - Postgres adapters and the migration runner behind the `postgres` feature.
//!
//! Canonical Parwana bytes are stored as immutable, id-addressed blobs; this
//! crate never re-serializes or re-verifies them, so no protocol serializer or
//! verifier is duplicated here.

pub mod digest;
pub mod error;
pub mod evidence;
pub mod memory;
pub mod model;
pub mod ports;

#[cfg(feature = "postgres")]
pub mod postgres;

pub use digest::ContentDigest;
pub use error::{StorageError, StorageResult};
pub use evidence::LocalEvidenceStore;
pub use model::{
    ActionRequest, ActionRequestStatus, ApprovalDecision, AuditEvent, CasOutcome,
    EvidenceDescriptor, MandateProjection, ProtocolObjectRecord, WebhookReceipt,
    WebhookRecordOutcome,
};
pub use ports::{
    ActionRequestStore, ApprovalDecisionStore, AuditLog, EvidenceObjectStore, MandateProjectionStore,
    ProtocolObjectStore, WebhookReceiptStore,
};

#[cfg(test)]
mod tests;
