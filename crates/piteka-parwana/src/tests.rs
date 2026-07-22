//! Positive and adversarial coverage for the Parwana adapter boundary.

use super::{
    AdapterError, ContractVersions, PINNED_CONTRACT_VERSION, ParwanaContract,
    verify_contract_versions,
};
use crate::protocol::{
    AccountabilityObjectKind, ActionIntent, ActionIntentWire, GitHubDeploymentIntentV1,
    RequiredContexts,
};

/// A full, lower-case hexadecimal SHA-1 (40 characters).
const COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";

/// Builds a valid GitHub deployment action intent through the public SDK types.
fn valid_intent() -> ActionIntent {
    let required_contexts = RequiredContexts::AllSubmitted;
    let gate = required_contexts
        .gate_policy_id()
        .expect("gate policy id derivable");
    let profile = GitHubDeploymentIntentV1 {
        repository_id: 42,
        repository_owner: "diewan".to_string(),
        repository_name: "piteka".to_string(),
        commit_sha: COMMIT.to_string(),
        exact_ref: COMMIT.to_string(),
        environment_id: 7,
        environment_name: "production".to_string(),
        required_contexts,
        payload_commitment: [0x11; 32],
        artifact_digest: None,
        deployment_gate_policy_digest: gate,
    };
    ActionIntent::github_deployment(
        b"requester-identity".to_vec(),
        1_700_000_000,
        [0x33; 32],
        vec![[0x44; 32]],
        profile,
    )
    .expect("fixture intent is valid")
}

#[test]
fn bind_reports_the_pinned_contract() {
    let contract = ParwanaContract::bind().expect("linked SDK matches the pinned contract");
    assert_eq!(contract.contract_version(), "0.1.8");
    assert_eq!(contract.contract_version(), PINNED_CONTRACT_VERSION);
    assert_eq!(contract.versions(), ContractVersions::expected());
}

#[test]
fn linked_sdk_matches_the_pin() {
    // The pinned expectation must equal what the linked SDK actually reports,
    // otherwise the `=0.1.5` dependency and this adapter have drifted apart.
    let found = ContractVersions::from_linked_sdk();
    assert_eq!(found, ContractVersions::expected());
    assert!(verify_contract_versions(found).is_ok());
}

#[test]
fn verify_rejects_protocol_drift() {
    let expected = ContractVersions::expected();
    let drifted = ContractVersions {
        protocol_minor: expected.protocol_minor + 1,
        ..expected
    };
    match verify_contract_versions(drifted) {
        Err(AdapterError::ContractMismatch { expected: e, found }) => {
            assert_eq!(e, expected);
            assert_eq!(found, drifted);
        }
        other => panic!("expected ContractMismatch, got {other:?}"),
    }
}

#[test]
fn verify_rejects_object_version_drift() {
    let expected = ContractVersions::expected();
    let drifted = ContractVersions {
        object_version: expected.object_version + 1,
        ..expected
    };
    assert!(matches!(
        verify_contract_versions(drifted),
        Err(AdapterError::ContractMismatch { .. })
    ));
}

#[test]
fn encode_preserves_canonical_bytes_unchanged() {
    let contract = ParwanaContract::bind().unwrap();
    let intent = valid_intent();

    let object = contract
        .encode_action_intent(&intent)
        .expect("valid intent encodes");

    assert_eq!(object.kind(), AccountabilityObjectKind::ActionIntent);
    assert_eq!(object.object_version(), 1);

    // The adapter stores exactly the bytes Parwana's sole serializer produced;
    // it neither re-serializes nor normalizes them.
    let stored = object.canonical_bytes().expect("stored bytes decode");
    let canonical = intent.canonical_bytes().expect("protocol canonical bytes");
    assert_eq!(stored, canonical);
}

#[test]
fn canonical_object_round_trips_through_the_transport_envelope() {
    let contract = ParwanaContract::bind().unwrap();
    let object = contract.encode_action_intent(&valid_intent()).unwrap();
    let original = object.canonical_bytes().unwrap();

    let wire = object.into_wire();
    let restored = super::CanonicalObject::from_wire(wire).expect("well-formed envelope");

    assert_eq!(restored.canonical_bytes().unwrap(), original);
}

#[test]
fn wire_intent_round_trips_and_stays_byte_identical() {
    let contract = ParwanaContract::bind().unwrap();
    let intent = valid_intent();

    let wire = ActionIntentWire::from(&intent);
    let decoded = contract
        .decode_action_intent(wire)
        .expect("valid wire decodes");

    assert_eq!(decoded, intent);
    assert_eq!(
        decoded.canonical_bytes().unwrap(),
        intent.canonical_bytes().unwrap()
    );
}

#[test]
fn decode_rejects_a_tampered_deployment_profile() {
    let contract = ParwanaContract::bind().unwrap();
    let mut wire = ActionIntentWire::from(&valid_intent());

    // An agent-side tamper: swap in a different approved SHA's profile bytes while
    // leaving the committed target and parameters commitment untouched. The opaque
    // envelope is re-verified against the registered codec, so the swap is rejected.
    let tampered_profile = GitHubDeploymentIntentV1 {
        required_contexts: RequiredContexts::AllSubmitted,
        repository_id: 42,
        repository_owner: "diewan".to_string(),
        repository_name: "piteka".to_string(),
        commit_sha: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
        exact_ref: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
        environment_id: 7,
        environment_name: "production".to_string(),
        payload_commitment: [0x11; 32],
        artifact_digest: None,
        deployment_gate_policy_digest: RequiredContexts::AllSubmitted.gate_policy_id().unwrap(),
    };
    tampered_profile
        .validate()
        .expect("tampered profile is itself structurally valid");
    let alt = ActionIntent::github_deployment(
        b"requester-identity".to_vec(),
        1_700_000_000,
        [0x33; 32],
        vec![[0x44; 32]],
        tampered_profile.clone(),
    )
    .unwrap();
    wire.profile_bytes_hex = ActionIntentWire::from(&alt).profile_bytes_hex;

    match contract.decode_action_intent(wire) {
        Err(AdapterError::InvalidIntent(_)) => {}
        other => panic!("tampered profile must be rejected, got {other:?}"),
    }
}

#[test]
fn decode_rejects_noncanonical_profile_bytes() {
    let contract = ParwanaContract::bind().unwrap();
    let mut wire = ActionIntentWire::from(&valid_intent());
    // A trailing byte makes the profile encoding non-canonical; decode fails closed.
    wire.profile_bytes_hex.push_str("00");

    assert!(matches!(
        contract.decode_action_intent(wire),
        Err(AdapterError::InvalidIntent(_))
    ));
}

#[test]
fn from_wire_rejects_a_malformed_envelope() {
    let contract = ParwanaContract::bind().unwrap();
    let object = contract.encode_action_intent(&valid_intent()).unwrap();
    let mut wire = object.into_wire();

    // Odd-length hex can never be exact canonical bytes.
    wire.canonical_bytes_hex.push('a');

    assert_eq!(
        super::CanonicalObject::from_wire(wire),
        Err(AdapterError::CorruptCanonicalObject)
    );
}

#[test]
fn from_wire_rejects_a_truncated_object_id() {
    let contract = ParwanaContract::bind().unwrap();
    let object = contract.encode_action_intent(&valid_intent()).unwrap();
    let mut wire = object.into_wire();

    wire.object_id_hex.pop();

    assert!(matches!(
        super::CanonicalObject::from_wire(wire),
        Err(AdapterError::CorruptCanonicalObject)
    ));
}
