//! Positive and adversarial coverage for the Parwana adapter boundary.

use super::{
    AdapterError, ContractVersions, EXPECTED_OBJECT_VERSION, EXPECTED_PROTOCOL_VERSION,
    PINNED_CONTRACT_PROTOCOL_VERSION, PINNED_CONTRACT_VERSION, PINNED_SDK_PACKAGE_REQUIREMENT,
    PINNED_WIRE_VERSION, ParwanaContract, pinned_contract_summary, verify_contract_versions,
};
use crate::protocol::{
    AccountabilityObjectKind, ActionIntent, ActionIntentWireV1, GitHubDeploymentIntentV1,
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
    assert_eq!(contract.contract_version(), PINNED_CONTRACT_VERSION);
    assert_eq!(contract.versions(), ContractVersions::expected());
}

// ── The five pinned version lines (PIT-NE-001) ──────────────────────────────

/// Reads one `key = "value"` pair out of a flat TOML preamble.
///
/// Deliberately naive rather than a TOML dependency: this crate is the narrow
/// protocol seam and gains no runtime dependency for a test. It only reads keys
/// that live above the first table header, which is where all of them are.
fn declared(source: &str, key: &str) -> String {
    let preamble = source.split("\n[").next().unwrap_or(source);
    for line in preamble.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix(key)
            && let Some(value) = rest.trim_start().strip_prefix('=')
        {
            return value.trim().trim_matches('"').to_string();
        }
    }
    panic!("`{key}` is not declared in:\n{source}");
}

/// Every declared pin must equal the file that is its authority.
///
/// This is the test that would have caught the drift this ticket fixes:
/// `PINNED_CONTRACT_VERSION` read `0.1.9` while the pin file said `0.1.10`, and
/// nothing compared them. The five lines are checked against their own
/// authorities and never against each other — they are independent version
/// lines and reconciling them to one number would pin a combination that never
/// existed.
#[test]
fn the_pinned_version_lines_agree_with_their_authorities() {
    let crate_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let repo_root = crate_root
        .parent()
        .and_then(std::path::Path::parent)
        .expect("piteka-parwana lives at <repo>/crates/piteka-parwana");

    let manifest = std::fs::read_to_string(crate_root.join("Cargo.toml"))
        .expect("the adapter manifest is readable");
    let pin = std::fs::read_to_string(repo_root.join(".diewan/parwana-contract.toml"))
        .expect("the repository-local contract pin is readable");

    // Contract package line.
    assert_eq!(PINNED_CONTRACT_VERSION, declared(&pin, "contract_version"));
    // Contract-package protocol line — not the accountability object protocol
    // version, which is checked against the linked SDK instead.
    assert_eq!(
        PINNED_CONTRACT_PROTOCOL_VERSION,
        declared(&pin, "protocol_version")
    );
    // Wire line.
    assert_eq!(PINNED_WIRE_VERSION, declared(&pin, "wire_version"));
    // Package line, declared in two places that must not drift: the pin file
    // and the Cargo requirement that actually binds the build.
    assert_eq!(
        PINNED_SDK_PACKAGE_REQUIREMENT,
        declared(&pin, "sdk_package_requirement")
    );
    assert!(
        manifest.contains(&format!(r#"csv-sdk = {{ version = "{PINNED_SDK_PACKAGE_REQUIREMENT}""#)),
        "the Cargo requirement on csv-sdk must be exactly {PINNED_SDK_PACKAGE_REQUIREMENT}"
    );
    // `latest` is prohibited in CI and deployments, so the requirement is
    // always exact.
    assert!(PINNED_SDK_PACKAGE_REQUIREMENT.starts_with('='));
    assert!(!manifest.contains(r#"csv-sdk = { version = "latest"#));

    // The two lines the linked SDK can be asked about directly.
    assert_eq!(
        ContractVersions::from_linked_sdk(),
        ContractVersions::expected()
    );
    assert_eq!(
        (
            EXPECTED_PROTOCOL_VERSION.0,
            EXPECTED_PROTOCOL_VERSION.1,
            EXPECTED_OBJECT_VERSION
        ),
        (0, 1, 1)
    );

    // The operator-facing summary names every line, so a mismatch report never
    // invites reconciling one against another.
    let summary = pinned_contract_summary();
    for line in [
        PINNED_CONTRACT_VERSION,
        PINNED_CONTRACT_PROTOCOL_VERSION,
        PINNED_WIRE_VERSION,
        PINNED_SDK_PACKAGE_REQUIREMENT,
    ] {
        assert!(summary.contains(line), "summary omits {line}: {summary}");
    }
}

/// The contract package line and the crate line are different numbers, and the
/// adapter must not quietly assume they are the same.
#[test]
fn the_contract_package_line_is_not_the_crate_version_line() {
    assert_ne!(
        PINNED_CONTRACT_VERSION,
        PINNED_SDK_PACKAGE_REQUIREMENT.trim_start_matches('=')
    );
}

/// Startup must refuse to continue on a mismatch, and a *partial* match is a
/// mismatch: the right protocol version against the wrong object version fails
/// exactly as a total disagreement does.
#[test]
fn a_partial_version_match_fails_closed_like_a_total_one() {
    let expected = ContractVersions::expected();

    let wrong_object = ContractVersions {
        object_version: expected.object_version + 1,
        ..expected
    };
    let wrong_protocol = ContractVersions {
        protocol_minor: expected.protocol_minor + 1,
        ..expected
    };

    for found in [wrong_object, wrong_protocol] {
        assert_eq!(
            verify_contract_versions(found),
            Err(AdapterError::ContractMismatch { expected, found }),
            "a partial match must not be accepted"
        );
    }

    // The linked SDK does match, so the startup gate binds rather than refusing.
    assert!(ParwanaContract::bind_or_refuse_to_start().is_ok());
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

    let wire = ActionIntentWireV1::from(&intent);
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
    let mut wire = ActionIntentWireV1::from(&valid_intent());

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
    wire.profile_bytes_hex = ActionIntentWireV1::from(&alt).profile_bytes_hex;

    match contract.decode_action_intent(wire) {
        Err(AdapterError::InvalidIntent(_)) => {}
        other => panic!("tampered profile must be rejected, got {other:?}"),
    }
}

#[test]
fn decode_rejects_noncanonical_profile_bytes() {
    let contract = ParwanaContract::bind().unwrap();
    let mut wire = ActionIntentWireV1::from(&valid_intent());
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

// ── The V2 closure vocabulary reaches Piteka unchanged (PIT-NE-002) ─────────

/// All four V2 capabilities are reachable through the adapter, in Parwana's own
/// types.
///
/// The assertions are compile-time: naming each type through `crate::closure`
/// is what proves the re-export exists, and binding it to the SDK path is what
/// proves it is the *same* type rather than a Piteka-local one that happens to
/// share a name.
#[test]
fn the_v2_closure_vocabulary_is_reachable_through_the_adapter() {
    fn same_type<T>(_: std::marker::PhantomData<T>, _: std::marker::PhantomData<T>) {}

    // 1. The consumed state reference.
    same_type(
        std::marker::PhantomData::<crate::closure::ConsumedStateRef>,
        std::marker::PhantomData::<csv_sdk::v2::ConsumedStateRef>,
    );
    // 2. Closure proof and the trust anchor a conclusion stands on.
    same_type(
        std::marker::PhantomData::<crate::closure::ClosureProof>,
        std::marker::PhantomData::<csv_sdk::v2::ClosureProof>,
    );
    same_type(
        std::marker::PhantomData::<crate::closure::ClosureTrustMode>,
        std::marker::PhantomData::<csv_sdk::v2::ClosureTrustMode>,
    );
    // 3. The V2 consignment descriptor.
    same_type(
        std::marker::PhantomData::<crate::closure::ConsignmentV2>,
        std::marker::PhantomData::<csv_sdk::v2::ConsignmentV2>,
    );
    // 4. The typed verification report.
    same_type(
        std::marker::PhantomData::<crate::closure::VerificationReport>,
        std::marker::PhantomData::<csv_sdk::v2::VerificationReport>,
    );
    same_type(
        std::marker::PhantomData::<crate::closure::VerificationDimension>,
        std::marker::PhantomData::<csv_sdk::v2::VerificationDimension>,
    );
}

/// Inspection is structural. It must not be reachable as a verification result.
///
/// ARCHITECTURE.md §8 forbids structural-only verification presented as
/// cryptographic success, and `inspect` is exactly the call a consumer could
/// mistake for one. Malformed bytes are rejected rather than coerced, and the
/// success type carries no boolean a caller could read as "verified".
#[test]
fn structural_inspection_rejects_malformed_bytes_and_asserts_nothing() {
    assert!(crate::closure::inspect(b"not a canonical consignment").is_err());
    assert!(crate::closure::inspect(&[]).is_err());
}

/// A verification report is decoded, never constructed.
///
/// Its fields stay private in `csv-verifier`, so no Piteka code can assemble a
/// report or edit one into a stronger reading. Undecodable bytes fail closed
/// instead of yielding an empty report, which would read as a verifier that
/// found no problems.
#[test]
fn a_verification_report_is_decoded_and_never_assembled_locally() {
    let Err(error) = crate::closure::decode_verification_report(b"not a canonical report") else {
        panic!("undecodable report bytes must not yield a report");
    };
    assert!(!error.detail.is_empty(), "a rejection must say why");
}

/// No Piteka crate outside the adapter defines its own version of these types.
///
/// ARCHITECTURE.md §5.1: Piteka must not copy Parwana domain structs into
/// product-local equivalents. A copy would not fail to compile — it would
/// compile and quietly mean something slightly different from the protocol, so
/// the boundary is asserted over the source tree.
#[test]
fn no_piteka_crate_defines_a_product_local_closure_type() {
    let crates = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("piteka-parwana lives under <repo>/crates");

    let mut offenders = Vec::new();
    let mut scanned = 0_usize;
    let mut stack = vec![crates.to_path_buf()];
    while let Some(directory) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&directory) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                if path.file_name().is_some_and(|name| name == "target") {
                    continue;
                }
                stack.push(path);
                continue;
            }
            if path.extension().is_none_or(|extension| extension != "rs") {
                continue;
            }
            // The adapter is where these names are supposed to appear.
            if path.starts_with(crates.join("piteka-parwana")) {
                continue;
            }
            let Ok(source) = std::fs::read_to_string(&path) else {
                continue;
            };
            scanned += 1;
            for name in [
                "ConsumedStateRef",
                "ClosureProof",
                "ConsignmentV2",
                "VerificationReport",
                "ClosureTrustMode",
            ] {
                for keyword in ["struct", "enum", "type"] {
                    if source.contains(&format!("{keyword} {name}")) {
                        offenders.push(format!("{} defines {keyword} {name}", path.display()));
                    }
                }
            }
        }
    }
    // A walk that silently reached nothing would pass without checking anything.
    assert!(
        scanned > 20,
        "the boundary scan reached only {scanned} source files"
    );
    assert!(
        offenders.is_empty(),
        "protocol types must come from piteka-parwana::closure, not be redefined: {offenders:?}"
    );
}
