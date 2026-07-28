//! Product orchestration around Parwana-owned portable source closure.
//!
//! PostgreSQL reservation remains Piteka's live-state authority. These types
//! decide when dispatch may proceed and preserve the SDK-produced closure
//! identity; they do not verify or reinterpret protocol proof material.

use piteka_parwana::closure::inspect;
use piteka_storage::model::ProtocolClosureIdentity;
use sha2::{Digest, Sha256};

/// Closure requirement declared by an execution profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PortableExclusivity {
    /// Dispatch requires a canonical, verifier-produced V2 closure artifact.
    Required,
    /// The profile explicitly makes no portable exclusivity claim.
    NotRequired,
}

/// Recovery state across the local reservation and irreversible closure seam.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClosureRecoveryState {
    /// Nothing external happened; the local reservation may be released.
    PreClosureFailure,
    /// Closure exists but provider dispatch is not known to have happened.
    ClosedBeforeDispatch,
    /// Provider dispatch may have happened; operator reconciliation is required.
    DispatchOutcomeUnknown,
    /// Both closure and accepted provider dispatch are durably recorded.
    Complete,
}

/// Fail-closed recovery action.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecoveryAction {
    ReleaseReservation,
    Quarantine,
    Consume,
}

impl ClosureRecoveryState {
    #[must_use]
    pub const fn action(self) -> RecoveryAction {
        match self {
            Self::PreClosureFailure => RecoveryAction::ReleaseReservation,
            Self::ClosedBeforeDispatch | Self::DispatchOutcomeUnknown => RecoveryAction::Quarantine,
            Self::Complete => RecoveryAction::Consume,
        }
    }
}

/// Result of the profile gate immediately before provider dispatch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PortableExecutionGrounding {
    /// Canonical V2 closure identity that must be recorded with the attempt.
    Grounded(ProtocolClosureIdentity),
    /// Explicit limitation for a profile that does not promise external closure.
    Ungrounded {
        limitation: &'static str,
    },
}

/// Applies the profile's portable-exclusivity gate.
///
/// `verification_status` must be a registry value emitted by the verifier. This
/// boundary structurally inspects canonical bytes but never upgrades that value.
pub fn ground_execution(
    requirement: PortableExclusivity,
    canonical_consignment: Option<&[u8]>,
    verification_status: Option<&str>,
) -> Result<PortableExecutionGrounding, String> {
    if requirement == PortableExclusivity::NotRequired {
        return Ok(PortableExecutionGrounding::Ungrounded {
            limitation: "portable source closure is not required by this execution profile",
        });
    }
    let bytes = canonical_consignment
        .ok_or_else(|| "portable-exclusivity profile requires V2 consignment bytes".to_string())?;
    let status = verification_status
        .filter(|status| *status == "satisfied")
        .ok_or_else(|| "source closure is not verifier-satisfied".to_string())?;
    let consignment = inspect(bytes).map_err(|error| error.to_string())?;
    let source = &consignment.payload.source;
    Ok(PortableExecutionGrounding::Grounded(
        ProtocolClosureIdentity {
            source_state_id_hex: hex::encode(source.to_canonical_bytes()),
            transition_id_hex: hex::encode(
                consignment.payload.successor.commitment().as_bytes(),
            ),
            closure_id_hex: hex::encode(
                consignment.payload.source_closure.commitment().as_bytes(),
            ),
            consignment_digest_hex: hex::encode(Sha256::digest(bytes)),
            checkpoint_hex: hex::encode(
                consignment
                    .payload
                    .proof_requirements
                    .checkpoint
                    .commitment()
                    .as_bytes(),
            ),
            assurance_status: status.into(),
        },
    ))
}
