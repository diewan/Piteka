#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! Narrow adapter binding Piteka to the pinned Parwana accountability contract.
//!
//! # Boundary
//!
//! This crate is the single inward-pointing seam between Piteka and Parwana
//! (`development/ARCHITECTURE.md` §4, §5.1, §7). Piteka's domain, application,
//! and infrastructure crates depend on `piteka-parwana`; none of them depend on
//! `csv-accountability`, `csv-wire`, or any other `csv-*` crate directly. That
//! keeps a single, auditable dependency edge on the protocol and prevents Piteka
//! from ever holding a product-local copy of a Parwana domain struct.
//!
//! The adapter links only the public [`csv_sdk`] facade, pinned to an exact
//! contract version (see [`PINNED_CONTRACT_VERSION`] and the `=0.1.5`
//! requirement in `Cargo.toml`). `latest` is prohibited.
//!
//! # Owns no protocol meaning
//!
//! The adapter never re-serializes, re-hashes, or re-validates accountability
//! objects. Canonical serialization stays in Parwana's sole serializer; this
//! crate forwards to it and preserves the exact bytes it returns. There is no
//! second serializer, verifier, or live-state authority here.

use core::fmt;

/// Parwana's supported accountability vocabulary, re-exported through the SDK.
///
/// Piteka imports every accountability type from this module so that the
/// dependency on the protocol package stays confined to `piteka-parwana`. These
/// are the canonical Parwana types themselves — not copies — surfaced via the
/// public [`csv_sdk::accountability`] facade.
pub mod protocol {
    pub use csv_sdk::accountability::{
        ACCOUNTABILITY_OBJECT_VERSION, ACCOUNTABILITY_PROTOCOL_VERSION, AccountabilityObjectKind,
        ActionIntent, ActionIntentWire, ActionMandate, AssuranceProfile,
        CanonicalAccountabilityObjectWire, DisputeBundle, EvidenceNode, ExecutionAttempt,
        ExecutionReceipt, GateProfileId, GitHubDeploymentIntentV1, GitHubDeploymentIntentV1Wire,
        IntentError, MandateSignatureEnvelope, ObjectVersion, ProfileCodec, ProfileDescriptor,
        ProfileId, ProfileRegistry, ProtocolVersion, RequiredContexts, RequiredContextsWire,
        VerificationContext, default_registry, github_deployment_descriptor,
    };
}

use csv_sdk::accountability;

use protocol::{
    AccountabilityObjectKind, ActionIntent, ActionIntentWire, CanonicalAccountabilityObjectWire,
};

/// Exact Parwana contract package version this adapter is pinned to.
///
/// Mirrors `contract_version` in `development/contract-pins/piteka.toml` and the
/// `=0.1.5` requirement on `csv-sdk`. Kept as a human-facing constant so the pin
/// is auditable from a running Piteka; the binding compatibility check lives in
/// [`verify_contract_versions`].
pub const PINNED_CONTRACT_VERSION: &str = "0.1.6";

/// Accountability protocol version (major, minor) this adapter is built against.
pub const EXPECTED_PROTOCOL_VERSION: (u16, u16) = (0, 1);

/// Accountability object schema version this adapter is built against.
pub const EXPECTED_OBJECT_VERSION: u16 = 1;

/// Concrete accountability contract versions observed from the linked SDK.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ContractVersions {
    /// Accountability protocol major version.
    pub protocol_major: u16,
    /// Accountability protocol minor version.
    pub protocol_minor: u16,
    /// Accountability object schema version.
    pub object_version: u16,
}

impl ContractVersions {
    /// The versions the linked `csv-sdk` reports at run time.
    ///
    /// Read from the SDK's own constants, so a mismatched dependency graph is
    /// observable rather than assumed.
    #[must_use]
    pub fn from_linked_sdk() -> Self {
        let protocol = accountability::ACCOUNTABILITY_PROTOCOL_VERSION;
        Self {
            protocol_major: protocol.major(),
            protocol_minor: protocol.minor(),
            object_version: accountability::ACCOUNTABILITY_OBJECT_VERSION.get(),
        }
    }

    /// The versions this adapter was compiled against.
    #[must_use]
    pub const fn expected() -> Self {
        Self {
            protocol_major: EXPECTED_PROTOCOL_VERSION.0,
            protocol_minor: EXPECTED_PROTOCOL_VERSION.1,
            object_version: EXPECTED_OBJECT_VERSION,
        }
    }
}

impl fmt::Display for ContractVersions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "protocol {}.{}, object v{}",
            self.protocol_major, self.protocol_minor, self.object_version
        )
    }
}

/// A failure at the Piteka/Parwana adapter boundary.
///
/// Every variant is a hard rejection: the adapter fails closed and never
/// downgrades a protocol error to a best-effort or simulated success.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AdapterError {
    /// The linked SDK's contract versions do not match the pinned expectation.
    ContractMismatch {
        /// Versions this adapter was built against.
        expected: ContractVersions,
        /// Versions the linked SDK reports.
        found: ContractVersions,
    },
    /// An action intent failed Parwana's canonical validation.
    ///
    /// Carries the protocol serializer's diagnostic. The adapter deliberately
    /// does not name the protocol error type, keeping Piteka's dependency on the
    /// contract confined to the public SDK facade.
    InvalidIntent(String),
    /// A receipt failed Parwana's binding or canonical validation.
    InvalidReceipt(String),
    /// A canonical envelope was malformed or its bytes failed to round-trip.
    CorruptCanonicalObject,
}

impl fmt::Display for AdapterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ContractMismatch { expected, found } => write!(
                f,
                "pinned Parwana contract {PINNED_CONTRACT_VERSION} expects {expected}, \
                 but the linked SDK reports {found}"
            ),
            Self::InvalidIntent(reason) => write!(f, "invalid action intent: {reason}"),
            Self::InvalidReceipt(reason) => write!(f, "invalid execution receipt: {reason}"),
            Self::CorruptCanonicalObject => {
                f.write_str("canonical accountability object is malformed")
            }
        }
    }
}

impl std::error::Error for AdapterError {}

/// Verifies that observed contract versions match the pinned expectation.
///
/// Returns [`AdapterError::ContractMismatch`] on any deviation. This is the
/// fail-closed gate that [`ParwanaContract::bind`] runs; it is exposed so the
/// rejection path is directly testable without a mismatched dependency graph.
///
/// # Errors
///
/// Returns an error when `found` differs from [`ContractVersions::expected`].
pub fn verify_contract_versions(found: ContractVersions) -> Result<(), AdapterError> {
    let expected = ContractVersions::expected();
    if found == expected {
        Ok(())
    } else {
        Err(AdapterError::ContractMismatch { expected, found })
    }
}

/// A canonical accountability object: exact protocol bytes and their envelope.
///
/// Holds the [`CanonicalAccountabilityObjectWire`] produced by Parwana's sole
/// serializer, unchanged. The adapter never mutates or re-derives these bytes;
/// Piteka persists and transports exactly what Parwana emitted so an independent
/// verifier reconstructs the same object.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalObject {
    wire: CanonicalAccountabilityObjectWire,
}

impl CanonicalObject {
    /// The semantic object kind carried by this envelope.
    #[must_use]
    pub fn kind(&self) -> AccountabilityObjectKind {
        self.wire.kind
    }

    /// The accountability object schema version of this envelope.
    #[must_use]
    pub fn object_version(&self) -> u16 {
        self.wire.object_version
    }

    /// The domain-separated semantic identifier, lower-case hex.
    #[must_use]
    pub fn object_id_hex(&self) -> &str {
        &self.wire.object_id_hex
    }

    /// The exact canonical bytes produced by Parwana's serializer.
    ///
    /// Decoded and bound-checked by the SDK envelope; the bytes are returned
    /// unchanged, never re-serialized.
    ///
    /// # Errors
    ///
    /// Returns [`AdapterError::CorruptCanonicalObject`] if the stored envelope
    /// is malformed.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, AdapterError> {
        self.wire
            .canonical_bytes()
            .map_err(|_| AdapterError::CorruptCanonicalObject)
    }

    /// Borrows the underlying transport envelope for storage or serialization.
    #[must_use]
    pub fn as_wire(&self) -> &CanonicalAccountabilityObjectWire {
        &self.wire
    }

    /// Consumes the object and returns its transport envelope.
    #[must_use]
    pub fn into_wire(self) -> CanonicalAccountabilityObjectWire {
        self.wire
    }

    /// Rebuilds a canonical object from a stored transport envelope.
    ///
    /// Validates the envelope's integrity (identifier shape, bytes present, and
    /// within the transport bound) without altering the bytes.
    ///
    /// # Errors
    ///
    /// Returns [`AdapterError::CorruptCanonicalObject`] if the envelope is
    /// malformed or its bytes fail the protocol bound check.
    pub fn from_wire(wire: CanonicalAccountabilityObjectWire) -> Result<Self, AdapterError> {
        wire.canonical_bytes()
            .map_err(|_| AdapterError::CorruptCanonicalObject)?;
        Ok(Self { wire })
    }
}

/// A version-checked handle to the pinned Parwana accountability contract.
///
/// Obtain one with [`ParwanaContract::bind`]. Holding a value is evidence that
/// the linked SDK matched the pinned contract at bind time; the encode/decode
/// methods route every call through Parwana's canonical serializer.
#[derive(Clone, Copy, Debug)]
pub struct ParwanaContract {
    versions: ContractVersions,
}

impl ParwanaContract {
    /// Binds to the linked Parwana SDK, verifying the pinned contract version.
    ///
    /// # Errors
    ///
    /// Returns [`AdapterError::ContractMismatch`] when the linked SDK does not
    /// match the pinned accountability contract.
    pub fn bind() -> Result<Self, AdapterError> {
        let versions = ContractVersions::from_linked_sdk();
        verify_contract_versions(versions)?;
        Ok(Self { versions })
    }

    /// The exact pinned contract package version.
    #[must_use]
    pub const fn contract_version(&self) -> &'static str {
        PINNED_CONTRACT_VERSION
    }

    /// The contract versions verified at bind time.
    #[must_use]
    pub const fn versions(&self) -> ContractVersions {
        self.versions
    }

    /// Encodes a validated action intent into a canonical object.
    ///
    /// Delegates to Parwana's canonical serializer; the resulting bytes are
    /// stored unchanged. Invalid intents are rejected, never coerced.
    ///
    /// # Errors
    ///
    /// Returns [`AdapterError::InvalidIntent`] if the intent fails Parwana's
    /// canonical validation.
    pub fn encode_action_intent(
        &self,
        intent: &ActionIntent,
    ) -> Result<CanonicalObject, AdapterError> {
        let wire = accountability::encode_action_intent(intent)
            .map_err(|error| AdapterError::InvalidIntent(format!("{error:?}")))?;
        Ok(CanonicalObject { wire })
    }

    /// Decodes and validates the public JSON wire form of an action intent.
    ///
    /// # Errors
    ///
    /// Returns [`AdapterError::InvalidIntent`] if the wire representation fails
    /// Parwana's canonical validation.
    pub fn decode_action_intent(
        &self,
        wire: ActionIntentWire,
    ) -> Result<ActionIntent, AdapterError> {
        accountability::action_intent_from_wire(wire)
            .map_err(|error| AdapterError::InvalidIntent(format!("{error:?}")))
    }

    /// Encodes a signed execution receipt with Parwana's sole canonical
    /// serializer after validating its mandate and attempt bindings.
    ///
    /// # Errors
    ///
    /// Returns [`AdapterError::InvalidReceipt`] when the receipt is malformed
    /// or does not bind exactly to `mandate` and `attempt`.
    pub fn encode_execution_receipt(
        &self,
        receipt: &protocol::ExecutionReceipt,
        mandate: &protocol::ActionMandate,
        attempt: &protocol::ExecutionAttempt,
    ) -> Result<CanonicalObject, AdapterError> {
        let bytes = receipt
            .canonical_bytes(mandate, attempt)
            .map_err(|error| AdapterError::InvalidReceipt(format!("{error:?}")))?;
        let object_id = receipt
            .id(mandate, attempt)
            .map_err(|error| AdapterError::InvalidReceipt(format!("{error:?}")))?
            .into_bytes();
        let wire = protocol::CanonicalAccountabilityObjectWire::new(
            protocol::AccountabilityObjectKind::ExecutionReceipt,
            object_id,
            &bytes,
        )
        .map_err(|reason| AdapterError::InvalidReceipt(reason.to_string()))?;
        Ok(CanonicalObject { wire })
    }
}

#[cfg(test)]
mod tests;
