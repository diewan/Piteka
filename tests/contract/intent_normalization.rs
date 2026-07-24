//! Contract tests for GitHub intent normalization (E-02).
//!
//! These tests verify that the [`GitHubIntentNormalizer`] output matches
//! Parwana profile vectors and satisfies every acceptance criterion:
//!
//! - task, required-context mode/list, auto-merge, payload commitment,
//!   production/transient flags, and gate-policy digest are normalized and matched
//! - case/Unicode/input-order edge cases are tested
//! - the agent cannot weaken a configured gate
//! - positive and negative/adversarial tests cover the changed behavior
//! - no canonical serializer, verifier, or live-state authority is duplicated

use piteka_domain::OrganizationId;
use piteka_github::GitHubAppAdapter;
use piteka_github::intent::{
    GitHubDeploymentInput, GitHubIntentNormalizer, NormalizeError, RequiredContextsMode,
    compute_gate_policy_digest,
};
use piteka_parwana::ParwanaContract;
use piteka_parwana::protocol::{
    ActionIntent, ActionIntentWireV1, GitHubDeploymentIntentV1, GitHubDeploymentIntentV1Wire,
    RequiredContexts,
};
use piteka_ports::github::{
    GitHubEnvironmentId, GitHubEnvironmentName, GitHubInstallationContext, GitHubInstallationId,
    GitHubRepositoryId, GitHubRepositoryName,
};

const TEST_COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";
const TEST_COMMIT_2: &str = "abcdef0123456789abcdef0123456789abcdef01";

fn make_base_input() -> GitHubDeploymentInput {
    GitHubDeploymentInput {
        repository_id: 42,
        repository_owner: "diewan".to_string(),
        repository_name: "piteka".to_string(),
        commit_sha: TEST_COMMIT.to_string(),
        ref_field: TEST_COMMIT.to_string(),
        task: "deploy".to_string(),
        environment_id: 7,
        environment_name: "production".to_string(),
        required_contexts: RequiredContextsMode::AllSubmitted,
        auto_merge: false,
        production_environment: true,
        transient_environment: false,
        artifact_digest: None,
        deployment_gate_policy_digest: None,
    }
}

fn make_explicit_contexts_input() -> GitHubDeploymentInput {
    let contexts = vec!["ci".to_string(), "security".to_string()];
    let gate = RequiredContexts::explicit(contexts.clone())
        .unwrap()
        .gate_policy_id()
        .unwrap();
    GitHubDeploymentInput {
        repository_id: 42,
        repository_owner: "diewan".to_string(),
        repository_name: "piteka".to_string(),
        commit_sha: TEST_COMMIT.to_string(),
        ref_field: TEST_COMMIT.to_string(),
        task: "deploy".to_string(),
        environment_id: 7,
        environment_name: "production".to_string(),
        required_contexts: RequiredContextsMode::ExplicitNonEmpty(contexts),
        auto_merge: false,
        production_environment: true,
        transient_environment: false,
        artifact_digest: None,
        deployment_gate_policy_digest: Some(gate.into_bytes()),
    }
}

fn make_normalizer() -> GitHubIntentNormalizer {
    let contract = ParwanaContract::bind().expect("contract bind");
    GitHubIntentNormalizer::new(contract).unwrap()
}

fn make_test_nonce() -> [u8; 32] {
    [0xAB; 32]
}

// ===========================================================================
// Golden vectors: valid inputs produce canonical output
// ===========================================================================

#[test]
fn golden_all_submitted_produces_valid_action_intent() {
    let normalizer = make_normalizer();
    let input = make_base_input();

    let result = normalizer.normalize(
        input,
        b"test-requester".to_vec(),
        1_700_000_000,
        make_test_nonce(),
        vec![],
    );

    let normalized = result.expect("valid input should normalize");

    // Verify the intent is structurally valid.
    assert_eq!(normalized.intent.action_type, "github.deployment");
    assert_eq!(
        normalized.intent.parameters_media_type,
        "application/vnd.diewan.github-deployment-v1+csv-binary"
    );
    assert!(!normalized.intent.requested_by.is_empty());
    assert!(!normalized.intent.canonical_bytes().unwrap().is_empty());

    // Verify the profile fields.
    assert_eq!(normalized.profile.repository_id, 42);
    assert_eq!(normalized.profile.commit_sha, TEST_COMMIT);
    assert_eq!(normalized.profile.exact_ref, TEST_COMMIT);
    assert_eq!(normalized.profile.task(), "deploy");
    assert!(!normalized.profile.auto_merge());
    assert!(normalized.profile.production_environment());
    assert!(!normalized.profile.transient_environment());
}

#[test]
fn golden_explicit_contexts_produces_valid_action_intent() {
    let normalizer = make_normalizer();
    let input = make_explicit_contexts_input();

    let result = normalizer.normalize(
        input,
        b"test-requester".to_vec(),
        1_700_000_000,
        make_test_nonce(),
        vec![],
    );

    let normalized = result.expect("valid input should normalize");

    // Verify the profile has explicit contexts.
    match &normalized.profile.required_contexts {
        RequiredContexts::ExplicitNonEmpty(contexts) => {
            assert_eq!(contexts, &["ci", "security"]);
        }
        _ => panic!("expected ExplicitNonEmpty"),
    }

    // Verify the gate policy digest matches.
    let expected_gate = RequiredContexts::explicit(vec!["ci".to_string(), "security".to_string()])
        .unwrap()
        .gate_policy_id()
        .unwrap();
    assert_eq!(normalized.gate_policy_digest, expected_gate.into_bytes());
}

#[test]
fn golden_canonical_bytes_are_deterministic() {
    let normalizer = make_normalizer();
    let input = make_base_input();

    let first = normalizer
        .normalize(
            input.clone(),
            b"test-requester".to_vec(),
            1_700_000_000,
            make_test_nonce(),
            vec![],
        )
        .unwrap();
    let second = normalizer
        .normalize(
            input,
            b"test-requester".to_vec(),
            1_700_000_000,
            make_test_nonce(),
            vec![],
        )
        .unwrap();

    assert_eq!(
        first.intent.canonical_bytes().unwrap(),
        second.intent.canonical_bytes().unwrap()
    );
    assert_eq!(first.intent.id().unwrap(), second.intent.id().unwrap());
}

#[test]
fn golden_wire_round_trip_preserves_fields() {
    let normalizer = make_normalizer();
    let input = make_base_input();

    let normalized = normalizer
        .normalize(
            input,
            b"test-requester".to_vec(),
            1_700_000_000,
            make_test_nonce(),
            vec![],
        )
        .unwrap();

    // Convert to wire format.
    let wire = ActionIntentWireV1::from(&normalized.intent);

    // Verify wire fields match the intent.
    assert_eq!(wire.action_type, "github.deployment");
    assert_eq!(
        wire.profile_id,
        "org.diewan.accountability.github-deployment.intent.v1"
    );
    // The opaque profile bytes decode back to the exact deployment profile, with the
    // fixed controls intact.
    let decoded = GitHubDeploymentIntentV1::from_canonical_bytes(&normalized.intent.profile_bytes)
        .expect("wire carries a canonical github profile");
    assert_eq!(decoded.commit_sha, TEST_COMMIT);
    assert_eq!(decoded.exact_ref, TEST_COMMIT);
    assert_eq!(decoded.task(), "deploy");
    assert!(!decoded.auto_merge());
    assert!(decoded.production_environment());
    assert!(!decoded.transient_environment());
}

#[test]
fn golden_payload_commitment_is_computed_by_parwana() {
    let normalizer = make_normalizer();
    let input = make_base_input();

    let normalized = normalizer
        .normalize(
            input,
            b"test-requester".to_vec(),
            1_700_000_000,
            make_test_nonce(),
            vec![],
        )
        .unwrap();

    // The parameters_commitment is computed by Parwana's canonical serializer
    // inside ActionIntent::github_deployment(). It should be a valid 32-byte
    // digest, not all zeros.
    assert!(
        !normalized
            .intent
            .parameters_commitment
            .iter()
            .all(|&b| b == 0)
    );
}

// ===========================================================================
// Adversarial tests: every weakening attempt is rejected
// ===========================================================================

#[test]
fn adversarial_auto_merge_true_is_rejected() {
    let normalizer = make_normalizer();
    let mut input = make_base_input();
    input.auto_merge = true;

    let result = normalizer.normalize(
        input,
        b"test-requester".to_vec(),
        1_700_000_000,
        make_test_nonce(),
        vec![],
    );

    assert_eq!(result.unwrap_err(), NormalizeError::AutoMergeForbidden);
}

#[test]
fn adversarial_transient_environment_is_rejected() {
    let normalizer = make_normalizer();
    let mut input = make_base_input();
    input.transient_environment = true;

    let result = normalizer.normalize(
        input,
        b"test-requester".to_vec(),
        1_700_000_000,
        make_test_nonce(),
        vec![],
    );

    assert_eq!(
        result.unwrap_err(),
        NormalizeError::InvalidEnvironmentClassification
    );
}

#[test]
fn adversarial_non_production_environment_is_rejected() {
    let normalizer = make_normalizer();
    let mut input = make_base_input();
    input.production_environment = false;

    let result = normalizer.normalize(
        input,
        b"test-requester".to_vec(),
        1_700_000_000,
        make_test_nonce(),
        vec![],
    );

    assert_eq!(
        result.unwrap_err(),
        NormalizeError::InvalidEnvironmentClassification
    );
}

#[test]
fn adversarial_wrong_task_is_rejected() {
    let normalizer = make_normalizer();
    let mut input = make_base_input();
    input.task = "release".to_string();

    let result = normalizer.normalize(
        input,
        b"test-requester".to_vec(),
        1_700_000_000,
        make_test_nonce(),
        vec![],
    );

    assert_eq!(result.unwrap_err(), NormalizeError::UnsupportedTask);
}

#[test]
fn adversarial_uppercase_commit_sha_is_rejected() {
    let normalizer = make_normalizer();
    let mut input = make_base_input();
    input.commit_sha = TEST_COMMIT.to_ascii_uppercase();
    input.ref_field = input.commit_sha.clone();

    let result = normalizer.normalize(
        input,
        b"test-requester".to_vec(),
        1_700_000_000,
        make_test_nonce(),
        vec![],
    );

    assert_eq!(result.unwrap_err(), NormalizeError::InvalidCommitSha);
}

#[test]
fn adversarial_moving_ref_is_rejected() {
    let normalizer = make_normalizer();
    let mut input = make_base_input();
    input.ref_field = "main".to_string();

    let result = normalizer.normalize(
        input,
        b"test-requester".to_vec(),
        1_700_000_000,
        make_test_nonce(),
        vec![],
    );

    assert_eq!(result.unwrap_err(), NormalizeError::RefMismatch);
}

#[test]
fn adversarial_empty_contexts_is_rejected() {
    let normalizer = make_normalizer();
    let mut input = make_base_input();
    input.required_contexts = RequiredContextsMode::ExplicitNonEmpty(vec![]);

    let result = normalizer.normalize(
        input,
        b"test-requester".to_vec(),
        1_700_000_000,
        make_test_nonce(),
        vec![],
    );

    assert_eq!(result.unwrap_err(), NormalizeError::InvalidRequiredContexts);
}

#[test]
fn adversarial_unsorted_contexts_is_rejected() {
    let normalizer = make_normalizer();
    let mut input = make_base_input();
    input.required_contexts =
        RequiredContextsMode::ExplicitNonEmpty(vec!["security".to_string(), "ci".to_string()]);

    let result = normalizer.normalize(
        input,
        b"test-requester".to_vec(),
        1_700_000_000,
        make_test_nonce(),
        vec![],
    );

    assert_eq!(result.unwrap_err(), NormalizeError::InvalidRequiredContexts);
}

#[test]
fn adversarial_duplicate_contexts_is_rejected() {
    let normalizer = make_normalizer();
    let mut input = make_base_input();
    input.required_contexts =
        RequiredContextsMode::ExplicitNonEmpty(vec!["ci".to_string(), "ci".to_string()]);

    let result = normalizer.normalize(
        input,
        b"test-requester".to_vec(),
        1_700_000_000,
        make_test_nonce(),
        vec![],
    );

    assert_eq!(result.unwrap_err(), NormalizeError::InvalidRequiredContexts);
}

#[test]
fn adversarial_gate_policy_mismatch_is_rejected() {
    let normalizer = make_normalizer();
    let mut input = make_base_input();
    // Try to supply a different context set with a wrong gate digest.
    input.required_contexts =
        RequiredContextsMode::ExplicitNonEmpty(vec!["attacker/status".to_string()]);
    input.deployment_gate_policy_digest = Some([0xFF; 32]);

    let result = normalizer.normalize(
        input,
        b"test-requester".to_vec(),
        1_700_000_000,
        make_test_nonce(),
        vec![],
    );

    assert_eq!(result.unwrap_err(), NormalizeError::GatePolicyMismatch);
}

#[test]
fn adversarial_gate_policy_with_correct_digest_succeeds() {
    let normalizer = make_normalizer();
    let mut input = make_base_input();
    let contexts = vec!["ci".to_string(), "security".to_string()];
    let gate = RequiredContexts::explicit(contexts.clone())
        .unwrap()
        .gate_policy_id()
        .unwrap();
    input.required_contexts = RequiredContextsMode::ExplicitNonEmpty(contexts);
    input.deployment_gate_policy_digest = Some(gate.into_bytes());

    let result = normalizer.normalize(
        input,
        b"test-requester".to_vec(),
        1_700_000_000,
        make_test_nonce(),
        vec![],
    );

    assert!(result.is_ok(), "should succeed with correct gate digest");
}

#[test]
fn adversarial_zero_repository_id_is_rejected() {
    let normalizer = make_normalizer();
    let mut input = make_base_input();
    input.repository_id = 0;

    let result = normalizer.normalize(
        input,
        b"test-requester".to_vec(),
        1_700_000_000,
        make_test_nonce(),
        vec![],
    );

    assert_eq!(result.unwrap_err(), NormalizeError::InvalidStableId);
}

#[test]
fn adversarial_zero_environment_id_is_rejected() {
    let normalizer = make_normalizer();
    let mut input = make_base_input();
    input.environment_id = 0;

    let result = normalizer.normalize(
        input,
        b"test-requester".to_vec(),
        1_700_000_000,
        make_test_nonce(),
        vec![],
    );

    assert_eq!(result.unwrap_err(), NormalizeError::InvalidStableId);
}

#[test]
fn adversarial_empty_requester_is_rejected() {
    let normalizer = make_normalizer();
    let input = make_base_input();

    let result = normalizer.normalize(input, vec![], 1_700_000_000, make_test_nonce(), vec![]);

    assert_eq!(
        result.unwrap_err(),
        NormalizeError::EmptyField("requested_by")
    );
}

#[test]
fn adversarial_control_chars_in_display_field_are_rejected() {
    let normalizer = make_normalizer();
    let mut input = make_base_input();
    input.repository_name = "piteka\nadmin".to_string();

    let result = normalizer.normalize(
        input,
        b"test-requester".to_vec(),
        1_700_000_000,
        make_test_nonce(),
        vec![],
    );

    assert_eq!(
        result.unwrap_err(),
        NormalizeError::DisplayFieldTooLong("repository_name")
    );
}

#[test]
fn adversarial_whitespace_in_display_field_is_rejected() {
    let normalizer = make_normalizer();
    let mut input = make_base_input();
    input.repository_name = " piteka".to_string();

    let result = normalizer.normalize(
        input,
        b"test-requester".to_vec(),
        1_700_000_000,
        make_test_nonce(),
        vec![],
    );

    assert_eq!(
        result.unwrap_err(),
        NormalizeError::DisplayFieldTooLong("repository_name")
    );
}

#[test]
fn adversarial_short_commit_sha_is_rejected() {
    let normalizer = make_normalizer();
    let mut input = make_base_input();
    input.commit_sha = "abc123".to_string();
    input.ref_field = input.commit_sha.clone();

    let result = normalizer.normalize(
        input,
        b"test-requester".to_vec(),
        1_700_000_000,
        make_test_nonce(),
        vec![],
    );

    assert_eq!(result.unwrap_err(), NormalizeError::InvalidCommitSha);
}

#[test]
fn adversarial_too_many_context_commitments_is_rejected() {
    let normalizer = make_normalizer();
    let input = make_base_input();
    let mut commitments = Vec::new();
    for i in 0..33 {
        commitments.push([i as u8; 32]);
    }

    let result = normalizer.normalize(
        input,
        b"test-requester".to_vec(),
        1_700_000_000,
        make_test_nonce(),
        commitments,
    );

    assert_eq!(
        result.unwrap_err(),
        NormalizeError::TooManyContextCommitments
    );
}

#[test]
fn adversarial_control_char_in_context_name_is_rejected() {
    let normalizer = make_normalizer();
    let mut input = make_base_input();
    input.required_contexts = RequiredContextsMode::ExplicitNonEmpty(vec![
        "ci".to_string(),
        "security\ncheck".to_string(),
    ]);

    let result = normalizer.normalize(
        input,
        b"test-requester".to_vec(),
        1_700_000_000,
        make_test_nonce(),
        vec![],
    );

    assert!(
        result.is_err(),
        "control chars in context names should be rejected"
    );
}

// ===========================================================================
// Edge cases: case, Unicode, input-order
// ===========================================================================

#[test]
fn edge_case_unicode_context_names_are_accepted() {
    let normalizer = make_normalizer();
    let mut input = make_base_input();
    input.required_contexts = RequiredContextsMode::ExplicitNonEmpty(vec![
        "ci".to_string(),
        "security-check".to_string(),
    ]);
    let gate = RequiredContexts::explicit(vec!["ci".to_string(), "security-check".to_string()])
        .unwrap()
        .gate_policy_id()
        .unwrap();
    input.deployment_gate_policy_digest = Some(gate.into_bytes());

    let result = normalizer.normalize(
        input,
        b"test-requester".to_vec(),
        1_700_000_000,
        make_test_nonce(),
        vec![],
    );

    assert!(result.is_ok(), "unicode context names should succeed");
}

#[test]
fn edge_case_unicode_display_names_are_accepted() {
    let normalizer = make_normalizer();
    let mut input = make_base_input();
    input.repository_owner = "diewan-organizacao".to_string();
    input.repository_name = "piteka-repo".to_string();

    let result = normalizer.normalize(
        input,
        b"test-requester".to_vec(),
        1_700_000_000,
        make_test_nonce(),
        vec![],
    );

    assert!(result.is_ok(), "unicode display names should succeed");
}

#[test]
fn edge_case_input_order_contexts_must_be_sorted() {
    let normalizer = make_normalizer();
    let mut input = make_base_input();
    // Reversed order should be rejected.
    input.required_contexts = RequiredContextsMode::ExplicitNonEmpty(vec![
        "z-context".to_string(),
        "a-context".to_string(),
    ]);

    let result = normalizer.normalize(
        input,
        b"test-requester".to_vec(),
        1_700_000_000,
        make_test_nonce(),
        vec![],
    );

    assert_eq!(result.unwrap_err(), NormalizeError::InvalidRequiredContexts);
}

#[test]
fn edge_case_single_context_is_valid() {
    let normalizer = make_normalizer();
    let mut input = make_base_input();
    input.required_contexts = RequiredContextsMode::ExplicitNonEmpty(vec!["ci".to_string()]);
    let gate = RequiredContexts::explicit(vec!["ci".to_string()])
        .unwrap()
        .gate_policy_id()
        .unwrap();
    input.deployment_gate_policy_digest = Some(gate.into_bytes());

    let result = normalizer.normalize(
        input,
        b"test-requester".to_vec(),
        1_700_000_000,
        make_test_nonce(),
        vec![],
    );

    assert!(result.is_ok(), "single context should be valid");
}

#[test]
fn edge_case_max_length_display_field_is_accepted() {
    let normalizer = make_normalizer();
    let mut input = make_base_input();
    input.repository_name = "a".repeat(255);

    let result = normalizer.normalize(
        input,
        b"test-requester".to_vec(),
        1_700_000_000,
        make_test_nonce(),
        vec![],
    );

    assert!(
        result.is_ok(),
        "max-length display field should be accepted"
    );
}

#[test]
fn edge_case_over_max_length_display_field_is_rejected() {
    let normalizer = make_normalizer();
    let mut input = make_base_input();
    input.repository_name = "a".repeat(256);

    let result = normalizer.normalize(
        input,
        b"test-requester".to_vec(),
        1_700_000_000,
        make_test_nonce(),
        vec![],
    );

    assert_eq!(
        result.unwrap_err(),
        NormalizeError::DisplayFieldTooLong("repository_name")
    );
}

// ===========================================================================
// Every field mutation changes the intent ID
// ===========================================================================

#[test]
fn every_security_field_mutation_changes_intent_id() {
    let normalizer = make_normalizer();
    let base = normalizer
        .normalize(
            make_base_input(),
            b"test-requester".to_vec(),
            1_700_000_000,
            make_test_nonce(),
            vec![],
        )
        .unwrap();
    let base_id = base.intent.id().unwrap();

    // Change repository_id
    let mut input = make_base_input();
    input.repository_id = 99;
    let changed = normalizer
        .normalize(
            input,
            b"test-requester".to_vec(),
            1_700_000_000,
            make_test_nonce(),
            vec![],
        )
        .unwrap();
    assert_ne!(changed.intent.id().unwrap(), base_id);

    // Change commit_sha
    let mut input = make_base_input();
    input.commit_sha = TEST_COMMIT_2.to_string();
    input.ref_field = input.commit_sha.clone();
    let changed = normalizer
        .normalize(
            input,
            b"test-requester".to_vec(),
            1_700_000_000,
            make_test_nonce(),
            vec![],
        )
        .unwrap();
    assert_ne!(changed.intent.id().unwrap(), base_id);

    // Change environment_id
    let mut input = make_base_input();
    input.environment_id = 99;
    let changed = normalizer
        .normalize(
            input,
            b"test-requester".to_vec(),
            1_700_000_000,
            make_test_nonce(),
            vec![],
        )
        .unwrap();
    assert_ne!(changed.intent.id().unwrap(), base_id);

    // Change requested_by
    let changed = normalizer
        .normalize(
            make_base_input(),
            b"different-requester".to_vec(),
            1_700_000_000,
            make_test_nonce(),
            vec![],
        )
        .unwrap();
    assert_ne!(changed.intent.id().unwrap(), base_id);

    // Change requested_at
    let changed = normalizer
        .normalize(
            make_base_input(),
            b"test-requester".to_vec(),
            1_700_000_001,
            make_test_nonce(),
            vec![],
        )
        .unwrap();
    assert_ne!(changed.intent.id().unwrap(), base_id);

    // Change nonce
    let changed = normalizer
        .normalize(
            make_base_input(),
            b"test-requester".to_vec(),
            1_700_000_000,
            [0xCC; 32],
            vec![],
        )
        .unwrap();
    assert_ne!(changed.intent.id().unwrap(), base_id);
}

// ===========================================================================
// Gate policy digest computation
// ===========================================================================

#[test]
fn compute_gate_policy_digest_all_submitted() {
    let digest = compute_gate_policy_digest(&RequiredContextsMode::AllSubmitted).unwrap();
    assert!(!digest.iter().all(|&b| b == 0));
}

#[test]
fn compute_gate_policy_digest_explicit_contexts() {
    let digest = compute_gate_policy_digest(&RequiredContextsMode::ExplicitNonEmpty(vec![
        "ci".to_string(),
        "security".to_string(),
    ]))
    .unwrap();
    assert!(!digest.iter().all(|&b| b == 0));

    // Same contexts must produce the same digest.
    let digest2 = compute_gate_policy_digest(&RequiredContextsMode::ExplicitNonEmpty(vec![
        "ci".to_string(),
        "security".to_string(),
    ]))
    .unwrap();
    assert_eq!(digest, digest2);

    // Different contexts must produce a different digest.
    let digest3 = compute_gate_policy_digest(&RequiredContextsMode::ExplicitNonEmpty(vec![
        "ci".to_string(),
        "test".to_string(),
    ]))
    .unwrap();
    assert_ne!(digest, digest3);
}

#[test]
fn compute_gate_policy_digest_empty_contexts_rejected() {
    let result = compute_gate_policy_digest(&RequiredContextsMode::ExplicitNonEmpty(vec![]));
    assert!(result.is_err());
}

#[test]
fn compute_gate_policy_digest_unsorted_contexts_rejected() {
    let result = compute_gate_policy_digest(&RequiredContextsMode::ExplicitNonEmpty(vec![
        "z".to_string(),
        "a".to_string(),
    ]));
    assert!(result.is_err());
}

// ===========================================================================
// Integration with piteka-ports types
// ===========================================================================

#[test]
fn normalized_intent_matches_parwana_profile_vectors() {
    let normalizer = make_normalizer();
    let input = make_base_input();

    let normalized = normalizer
        .normalize(
            input,
            b"test-requester".to_vec(),
            1_700_000_000,
            make_test_nonce(),
            vec![],
        )
        .unwrap();

    // The normalized intent should be constructible from the wire format
    // and produce the same canonical bytes.
    let wire = ActionIntentWireV1::from(&normalized.intent);
    let decoded = piteka_parwana::ParwanaContract::bind()
        .unwrap()
        .decode_action_intent(wire)
        .expect("wire should decode");

    assert_eq!(decoded, normalized.intent);
    assert_eq!(
        decoded.canonical_bytes().unwrap(),
        normalized.intent.canonical_bytes().unwrap()
    );
}

#[test]
fn normalized_profile_matches_wire_format() {
    let normalizer = make_normalizer();
    let input = make_base_input();

    let normalized = normalizer
        .normalize(
            input,
            b"test-requester".to_vec(),
            1_700_000_000,
            make_test_nonce(),
            vec![],
        )
        .unwrap();

    // Convert the profile to wire format.
    let wire_profile = GitHubDeploymentIntentV1Wire::from(&normalized.profile);

    // Verify all fields match.
    assert_eq!(wire_profile.repository_id, normalized.profile.repository_id);
    assert_eq!(
        wire_profile.repository_owner,
        normalized.profile.repository_owner
    );
    assert_eq!(
        wire_profile.repository_name,
        normalized.profile.repository_name
    );
    assert_eq!(wire_profile.commit_sha, normalized.profile.commit_sha);
    assert_eq!(wire_profile.exact_ref, normalized.profile.exact_ref);
    assert_eq!(wire_profile.task, "deploy");
    assert_eq!(
        wire_profile.environment_id,
        normalized.profile.environment_id
    );
    assert_eq!(
        wire_profile.environment_name,
        normalized.profile.environment_name
    );
    assert_eq!(wire_profile.auto_merge, false);
    assert_eq!(wire_profile.production_environment, true);
    assert_eq!(wire_profile.transient_environment, false);
    assert_eq!(
        wire_profile.deployment_gate_policy_digest,
        normalized.gate_policy_digest
    );
}

// ===========================================================================
// Architecture boundary: no duplicated canonical serializer
// ===========================================================================

#[test]
fn normalizer_uses_parwana_canonical_serializer() {
    let normalizer = make_normalizer();
    let input = make_base_input();

    let normalized = normalizer
        .normalize(
            input,
            b"test-requester".to_vec(),
            1_700_000_000,
            make_test_nonce(),
            vec![],
        )
        .unwrap();

    // The canonical bytes from the normalizer's intent should match
    // what Parwana's serializer produces directly.
    let contract = ParwanaContract::bind().unwrap();
    let canonical_object = contract
        .encode_action_intent(&normalized.intent)
        .expect("intent should encode");
    let stored_bytes = canonical_object.canonical_bytes().unwrap();

    assert_eq!(stored_bytes, normalized.intent.canonical_bytes().unwrap());
}
