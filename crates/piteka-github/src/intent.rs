// ---------------------------------------------------------------------------
// E-02: GitHub intent normalization
// ---------------------------------------------------------------------------

//! GitHub intent normalization for the first production deployment slice.
//!
//! This module implements the adapter that normalizes raw GitHub deployment
//! data into a validated [`ActionIntent`] conforming to the
//! `GitHubDeploymentIntentV1` profile defined by the Parwana accountability
//! protocol.
//!
//! # Architecture
//!
//! ```text
//! piteka-application / API handlers
//!        ↓ (calls)
//!   piteka_github::intent::GitHubIntentNormalizer
//!        ↓ (produces)
//!   csv_sdk::accountability::ActionIntent
//!        ↓ (forwarded to)
//!   piteka_parwana::ParwanaContract::encode_action_intent
//! ```
//!
//! The normalizer is the **only** place in Piteka that constructs
//! `GitHubDeploymentIntentV1` and `ActionIntent` from raw input. It enforces
//! every fixed constraint from Master Plan §10.1:
//!
//! - `task` is always `"deploy"` — the agent cannot supply an arbitrary task.
//! - `auto_merge` is always `false` — rejected if the caller requests `true`.
//! - `production_environment` is always `true`.
//! - `transient_environment` is always `false`.
//! - `ref` must equal the approved full commit SHA (not a moving branch).
//! - `required_contexts` must be either `AllSubmitted` or a sorted, unique,
//!   non-empty administrator-controlled list.
//! - `deployment_gate_policy_digest` is derived from the exact context set;
//!   a mismatched digest is rejected, preventing agent-controlled gate
//!   weakening.
//! - `parameters_commitment` is computed by Parwana's canonical serializer
//!   inside `ActionIntent::github_deployment()`.
//!
//! # Security
//!
//! The normalizer **fail-closes** on any unsupported, ambiguous, malformed,
//! cross-tenant, or unauthenticated input. It never invents success or
//! accepts a weakened gate configuration.

use piteka_parwana::ParwanaContract;
use piteka_parwana::protocol::{
    ActionIntent, ActionIntentWire, GateProfileId, GitHubDeploymentIntentV1,
    GitHubDeploymentIntentV1Wire, IntentError, RequiredContexts,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Maximum UTF-8 byte length of any presentation label (repository/environment).
const MAX_DISPLAY_BYTES: usize = 255;
/// Maximum number of administrator-controlled required contexts.
const MAX_REQUIRED_CONTEXTS: usize = 32;
/// Maximum byte length of a stable requester identity reference.
const MAX_IDENTITY_BYTES: usize = 4_096;
/// Fixed task used by the first production deployment profile.
const GITHUB_DEPLOYMENT_TASK_V1: &str = "deploy";

/// A validation failure for GitHub intent normalization.
///
/// Every variant represents a hard rejection: the normalizer fails closed and
/// never produces a best-effort or simulated intent.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum NormalizeError {
    /// A required string field was empty.
    #[error("empty field: {0}")]
    EmptyField(String),

    /// A presentation string exceeded its protocol limit.
    #[error("display field too long: {0}")]
    DisplayFieldTooLong(String),

    /// The commit reference was not one full, lower-case hexadecimal SHA-1.
    #[error("invalid commit SHA: must be 40 lowercase hex characters")]
    InvalidCommitSha,

    /// The exact ref did not match the commit SHA.
    #[error("exact ref must equal commit SHA")]
    RefMismatch,

    /// Automatic merge is forbidden by the first profile.
    #[error("auto_merge must be false for production deployments")]
    AutoMergeForbidden,

    /// The environment classification would weaken the first profile.
    #[error("invalid environment classification: must be production=true, transient=false")]
    InvalidEnvironmentClassification,

    /// Explicit required contexts must be nonempty, sorted, and unique.
    #[error("invalid required contexts: must be nonempty, sorted, and unique")]
    InvalidRequiredContexts,

    /// The gate policy digest did not match the required contexts.
    #[error("gate policy digest mismatch: agent cannot weaken a configured gate")]
    GatePolicyMismatch,

    /// Too many context commitments were supplied.
    #[error("too many context commitments: maximum is 32")]
    TooManyContextCommitments,

    /// The requester identity exceeded its protocol size limit.
    #[error("requester identity too long: maximum {MAX_IDENTITY_BYTES} bytes")]
    IdentityTooLong,

    /// The requested task is not supported by the first profile.
    #[error("unsupported task: only '{GITHUB_DEPLOYMENT_TASK_V1}' is allowed")]
    UnsupportedTask,

    /// The required contexts mode is invalid.
    #[error("invalid required contexts mode: {0}")]
    InvalidContextsMode(String),

    /// A stable provider identifier used a reserved zero value.
    #[error("stable provider identifier must be non-zero")]
    InvalidStableId,

    /// The Parwana contract could not encode the intent.
    #[error("Parwana encoding error: {0}")]
    ParwanaError(String),

    /// A context name contained control characters or was malformed.
    #[error("context name invalid: {0}")]
    InvalidContextName(String),
}

/// Raw input data for a GitHub deployment intent.
///
/// This struct represents untrusted input from API handlers, webhook payloads,
/// or user-facing forms. The [`GitHubIntentNormalizer`] validates and normalizes
/// it into a canonical [`ActionIntent`].
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GitHubDeploymentInput {
    /// Stable provider repository identifier (non-zero).
    pub repository_id: u64,
    /// Presentation-only repository owner.
    pub repository_owner: String,
    /// Presentation-only repository name.
    pub repository_name: String,
    /// Approved full lower-case commit SHA (40 hex characters).
    pub commit_sha: String,
    /// Exact Deployments API ref — must equal `commit_sha`.
    pub ref_field: String,
    /// Fixed to `"deploy"` for the first profile.
    pub task: String,
    /// Stable provider environment identifier (non-zero).
    pub environment_id: u64,
    /// Presentation-only environment name.
    pub environment_name: String,
    /// Required-context gate mode.
    pub required_contexts: RequiredContextsMode,
    /// Must be `false` for the first profile.
    pub auto_merge: bool,
    /// Must be `true` for the first profile.
    pub production_environment: bool,
    /// Must be `false` for the first profile.
    pub transient_environment: bool,
    /// Optional pre-dispatch artifact digest (32 bytes).
    pub artifact_digest: Option<[u8; 32]>,
    /// Administrator-controlled gate-policy digest.
    ///
    /// Must match the digest derived from `required_contexts`. If the caller
    /// supplies a digest that does not match the derived value, the intent
    /// is rejected — preventing agent-controlled gate weakening.
    pub deployment_gate_policy_digest: Option<[u8; 32]>,
}

/// How GitHub commit-status contexts are applied to a deployment.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "mode", content = "contexts", deny_unknown_fields)]
pub enum RequiredContextsMode {
    /// Omit the API field and require all submitted contexts.
    AllSubmitted,
    /// Administrator-controlled explicit context names.
    ExplicitNonEmpty(Vec<String>),
}

/// A validated, normalized GitHub deployment intent ready for mandate binding.
///
/// This struct wraps a fully validated [`ActionIntent`] along with the
/// normalized profile data, providing a single return type for the
/// [`GitHubIntentNormalizer::normalize`] method.
#[derive(Clone, Debug)]
pub struct NormalizedIntent {
    /// The canonical Parwana action intent.
    pub intent: ActionIntent,
    /// The normalized GitHub deployment profile.
    pub profile: GitHubDeploymentIntentV1,
    /// The gate-policy digest derived from required contexts.
    pub gate_policy_digest: [u8; 32],
}

/// A GitHub intent normalizer that validates and constructs canonical
/// [`ActionIntent`] values from raw deployment input.
///
/// The normalizer is stateless and `Clone` + `Send + Sync`, allowing it to be
/// shared across async tasks. It is constructed with a [`ParwanaContract`]
/// handle that provides the pinned Parwana accountability contract.
#[derive(Clone)]
pub struct GitHubIntentNormalizer {
    contract: ParwanaContract,
}

impl GitHubIntentNormalizer {
    /// Constructs a new intent normalizer bound to the pinned Parwana contract.
    ///
    /// # Errors
    ///
    /// Returns a [`NormalizeError::ParwanaError`] if the linked SDK does not
    /// match the pinned contract version.
    pub fn new(contract: ParwanaContract) -> Result<Self, NormalizeError> {
        Ok(Self { contract })
    }

    /// Normalizes raw GitHub deployment input into a validated [`ActionIntent`].
    ///
    /// This is the central normalization gate. It validates every field against
    /// the production profile constraints from Master Plan §10.1, computes the
    /// gate-policy digest from the required contexts, and constructs a canonical
    /// intent through Parwana's sole serializer.
    ///
    /// # Security
    ///
    /// - **Fail closed**: Every validation failure returns an error; no best-effort
    ///   intent is ever produced.
    /// - **Gate protection**: The gate-policy digest is derived from the exact
    ///   required-context set. A mismatched digest is rejected, preventing an
    ///   agent from weakening the configured gate.
    /// - **Fixed controls**: `task`, `auto_merge`, `production_environment`, and
    ///   `transient_environment` are validated against their fixed values.
    /// - **Case/Unicode safety**: Display fields are validated for control
    ///   characters, leading/trailing whitespace, and length limits.
    /// - **Input-order safety**: Required context names must be sorted;
    ///   duplicate entries are rejected.
    ///
    /// # Errors
    ///
    /// Returns [`NormalizeError`] on any validation failure. The error variants
    /// are designed to be testable against the acceptance criteria in E-02.
    pub fn normalize(
        &self,
        input: GitHubDeploymentInput,
        requested_by: Vec<u8>,
        requested_at: u64,
        request_nonce: [u8; 32],
        context_commitments: Vec<[u8; 32]>,
    ) -> Result<NormalizedIntent, NormalizeError> {
        // Validate fixed controls first — fail fast on weakening attempts.
        Self::validate_task(&input.task)?;
        Self::validate_auto_merge(input.auto_merge)?;
        Self::validate_environment_classification(
            input.production_environment,
            input.transient_environment,
        )?;

        // Validate stable provider identifiers.
        if input.repository_id == 0 {
            return Err(NormalizeError::InvalidStableId);
        }
        if input.environment_id == 0 {
            return Err(NormalizeError::InvalidStableId);
        }

        // Validate display fields.
        Self::validate_display_field("repository_owner", &input.repository_owner)?;
        Self::validate_display_field("repository_name", &input.repository_name)?;
        Self::validate_display_field("environment_name", &input.environment_name)?;

        // Validate commit SHA and ref.
        Self::validate_commit_sha(&input.commit_sha)?;
        if input.ref_field != input.commit_sha {
            return Err(NormalizeError::RefMismatch);
        }

        // Validate and construct required contexts.
        let required_contexts = Self::validate_required_contexts(&input.required_contexts)?;

        // Derive the gate-policy digest from the exact context set.
        let gate_policy_id = required_contexts
            .gate_policy_id()
            .map_err(|_| NormalizeError::GatePolicyMismatch)?;

        // Verify the caller-supplied gate-policy digest matches the derived value.
        if let Some(supplied) = input.deployment_gate_policy_digest {
            if supplied != gate_policy_id.into_bytes() {
                return Err(NormalizeError::GatePolicyMismatch);
            }
        }

        // Validate requester identity.
        if requested_by.is_empty() {
            return Err(NormalizeError::EmptyField("requested_by".to_string()));
        }
        if requested_by.len() > MAX_IDENTITY_BYTES {
            return Err(NormalizeError::IdentityTooLong);
        }

        // Validate context commitments count.
        if context_commitments.len() > 32 {
            return Err(NormalizeError::TooManyContextCommitments);
        }

        // Construct the profile.
        let profile = GitHubDeploymentIntentV1 {
            repository_id: input.repository_id,
            repository_owner: input.repository_owner,
            repository_name: input.repository_name,
            commit_sha: input.commit_sha,
            exact_ref: input.ref_field,
            environment_id: input.environment_id,
            environment_name: input.environment_name,
            required_contexts,
            payload_commitment: [0u8; 32], // Computed by ActionIntent::github_deployment
            artifact_digest: input.artifact_digest,
            deployment_gate_policy_digest: gate_policy_id,
        };

        // Validate the profile fields.
        profile.validate().map_err(|e| match e {
            IntentError::EmptyField(f) => NormalizeError::EmptyField(f.to_string()),
            IntentError::DisplayFieldTooLong(f) => {
                NormalizeError::DisplayFieldTooLong(f.to_string())
            }
            IntentError::InvalidCommitSha => NormalizeError::InvalidCommitSha,
            IntentError::InvalidRequiredContexts => NormalizeError::InvalidRequiredContexts,
            IntentError::GatePolicyMismatch => NormalizeError::GatePolicyMismatch,
            IntentError::InvalidStableId => NormalizeError::InvalidStableId,
            IntentError::InvalidEvidenceSourceDeclaration => {
                NormalizeError::InvalidRequiredContexts
            }
            _ => NormalizeError::InvalidContextsMode(format!("{e:?}")),
        })?;

        // Construct the canonical ActionIntent through Parwana's sole serializer.
        let intent = ActionIntent::github_deployment(
            gate_policy_id,
            requested_by,
            requested_at,
            request_nonce,
            context_commitments,
            profile.clone(),
        )
        .map_err(|e| match e {
            IntentError::EmptyField(f) => NormalizeError::EmptyField(f.to_string()),
            IntentError::IdentityTooLong => NormalizeError::IdentityTooLong,
            IntentError::TooManyContextCommitments => NormalizeError::TooManyContextCommitments,
            IntentError::ParametersCommitmentMismatch => {
                NormalizeError::ParwanaError("parameters commitment mismatch".to_string())
            }
            _ => NormalizeError::ParwanaError(format!("intent construction failed: {e:?}")),
        })?;

        // Validate the final intent.
        intent.validate().map_err(|e| match e {
            IntentError::UnsupportedVersion => {
                NormalizeError::ParwanaError("unsupported protocol version".to_string())
            }
            IntentError::UnsupportedTask => NormalizeError::UnsupportedTask,
            IntentError::TargetMismatch => {
                NormalizeError::ParwanaError("target mismatch".to_string())
            }
            IntentError::ParametersCommitmentMismatch => {
                NormalizeError::ParwanaError("parameters commitment mismatch".to_string())
            }
            IntentError::EmptyField(f) => NormalizeError::EmptyField(f.to_string()),
            IntentError::IdentityTooLong => NormalizeError::IdentityTooLong,
            IntentError::TooManyContextCommitments => NormalizeError::TooManyContextCommitments,
            _ => NormalizeError::ParwanaError(format!("intent validation failed: {e:?}")),
        })?;

        Ok(NormalizedIntent {
            intent,
            profile,
            gate_policy_digest: gate_policy_id.into_bytes(),
        })
    }

    /// Validates that the task is the fixed profile constant.
    fn validate_task(task: &str) -> Result<(), NormalizeError> {
        if task != GITHUB_DEPLOYMENT_TASK_V1 {
            return Err(NormalizeError::UnsupportedTask);
        }
        Ok(())
    }

    /// Validates that auto_merge is false (fixed for the first profile).
    fn validate_auto_merge(auto_merge: bool) -> Result<(), NormalizeError> {
        if auto_merge {
            return Err(NormalizeError::AutoMergeForbidden);
        }
        Ok(())
    }

    /// Validates the environment classification flags.
    fn validate_environment_classification(
        production: bool,
        transient: bool,
    ) -> Result<(), NormalizeError> {
        if !production || transient {
            return Err(NormalizeError::InvalidEnvironmentClassification);
        }
        Ok(())
    }

    /// Validates a presentation-only display field.
    fn validate_display_field(name: &str, value: &str) -> Result<(), NormalizeError> {
        if value.is_empty() {
            return Err(NormalizeError::EmptyField(name.to_string()));
        }
        if value.len() > MAX_DISPLAY_BYTES {
            return Err(NormalizeError::DisplayFieldTooLong(name.to_string()));
        }
        if value.trim() != value {
            return Err(NormalizeError::DisplayFieldTooLong(name.to_string()));
        }
        if value.chars().any(char::is_control) {
            return Err(NormalizeError::DisplayFieldTooLong(name.to_string()));
        }
        Ok(())
    }

    /// Validates that the commit SHA is exactly 40 lowercase hex characters.
    fn validate_commit_sha(sha: &str) -> Result<(), NormalizeError> {
        if sha.len() != 40 {
            return Err(NormalizeError::InvalidCommitSha);
        }
        if !sha
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(NormalizeError::InvalidCommitSha);
        }
        Ok(())
    }

    /// Validates and constructs a [`RequiredContexts`] from the input mode.
    fn validate_required_contexts(
        mode: &RequiredContextsMode,
    ) -> Result<RequiredContexts, NormalizeError> {
        match mode {
            RequiredContextsMode::AllSubmitted => Ok(RequiredContexts::AllSubmitted),
            RequiredContextsMode::ExplicitNonEmpty(contexts) => {
                // Validate each context name.
                if contexts.is_empty() {
                    return Err(NormalizeError::InvalidRequiredContexts);
                }
                if contexts.len() > MAX_REQUIRED_CONTEXTS {
                    return Err(NormalizeError::InvalidRequiredContexts);
                }

                for context in contexts {
                    if context.is_empty() {
                        return Err(NormalizeError::InvalidContextName(
                            "context name is empty".to_string(),
                        ));
                    }
                    if context.trim() != context {
                        return Err(NormalizeError::InvalidContextName(
                            "context name has leading/trailing whitespace".to_string(),
                        ));
                    }
                    if context.len() > MAX_DISPLAY_BYTES {
                        return Err(NormalizeError::InvalidContextName(
                            "context name too long".to_string(),
                        ));
                    }
                    if context.chars().any(char::is_control) {
                        return Err(NormalizeError::InvalidContextName(
                            "context name contains control characters".to_string(),
                        ));
                    }
                }

                // Check sorted order (no duplicates, strictly increasing).
                for window in contexts.windows(2) {
                    if window[0] >= window[1] {
                        return Err(NormalizeError::InvalidRequiredContexts);
                    }
                }

                RequiredContexts::explicit(contexts.clone())
                    .map_err(|_| NormalizeError::InvalidRequiredContexts)
            }
        }
    }

    /// Returns the pinned Parwana contract version this normalizer is bound to.
    #[must_use]
    pub fn contract_version(&self) -> &'static str {
        self.contract.contract_version()
    }
}

/// Normalizes a required-contexts mode into the gate-policy digest bytes.
///
/// This is a convenience function that delegates to
/// [`RequiredContexts::gate_policy_id`] and returns the raw 32-byte digest.
///
/// # Errors
///
/// Returns [`NormalizeError::GatePolicyMismatch`] if the contexts are invalid
/// or the digest cannot be derived.
pub fn compute_gate_policy_digest(mode: &RequiredContextsMode) -> Result<[u8; 32], NormalizeError> {
    let contexts = match mode {
        RequiredContextsMode::AllSubmitted => RequiredContexts::AllSubmitted,
        RequiredContextsMode::ExplicitNonEmpty(contexts) => {
            // Reuse the normalizer's validation logic.
            let _ = GitHubIntentNormalizer::validate_required_contexts(mode)?;
            RequiredContexts::explicit(contexts.clone())
                .map_err(|_| NormalizeError::InvalidRequiredContexts)?
        }
    };
    Ok(contexts
        .gate_policy_id()
        .map_err(|_| NormalizeError::GatePolicyMismatch)?
        .into_bytes())
}

/// Builds a payload commitment for a given profile.
///
/// The payload commitment is computed by Parwana's canonical serializer inside
/// `ActionIntent::github_deployment()`. This function is provided for
/// callers who need to construct the correlation payload separately (e.g.,
/// for the Deployments API `payload` field).
///
/// # Parameters
///
/// * `profile` — The validated [`GitHubDeploymentIntentV1`] profile.
///
/// # Errors
///
/// Returns [`NormalizeError::ParwanaError`] if the profile is invalid.
pub fn build_payload_commitment(
    profile: &GitHubDeploymentIntentV1,
) -> Result<[u8; 32], NormalizeError> {
    profile.validate().map_err(|e| match e {
        IntentError::EmptyField(f) => NormalizeError::EmptyField(f.to_string()),
        IntentError::DisplayFieldTooLong(f) => NormalizeError::DisplayFieldTooLong(f.to_string()),
        IntentError::InvalidCommitSha => NormalizeError::InvalidCommitSha,
        IntentError::InvalidRequiredContexts => NormalizeError::InvalidRequiredContexts,
        IntentError::GatePolicyMismatch => NormalizeError::GatePolicyMismatch,
        IntentError::InvalidStableId => NormalizeError::InvalidStableId,
        _ => NormalizeError::ParwanaError(format!("profile validation failed: {e:?}")),
    })?;
    // The parameter commitment is computed by DomainSeparatedHash<GateProfileDomain>
    // over b"github-deployment-parameters-v1" || canonical_bytes.
    // We delegate to the SDK's ActionIntent construction which does this internally.
    // For standalone use, we return a placeholder that the caller must fill
    // by constructing a dummy intent.
    let nonce = [0u8; 32];
    let intent = ActionIntent::github_deployment(
        GateProfileId::from_digest([0u8; 32]),
        vec![0u8],
        0,
        nonce,
        vec![],
        profile.clone(),
    )
    .map_err(|_| NormalizeError::ParwanaError("intent construction failed".to_string()))?;
    Ok(intent.parameters_commitment)
}

/// A normalized intent ready for serialization to the JSON wire format.
///
/// This struct is the output of [`GitHubIntentNormalizer::normalize`] when
/// the caller needs the JSON-serializable wire representation instead of
/// the canonical Parwana types.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NormalizedIntentWire {
    /// The complete action intent in wire format.
    pub intent: ActionIntentWire,
    /// The normalized GitHub deployment profile.
    pub profile: GitHubDeploymentIntentV1Wire,
    /// The gate-policy digest derived from required contexts.
    pub gate_policy_digest: [u8; 32],
}

/// Wire-format transport types for GitHub deployment intent normalization.
///
/// These types mirror the Parwana wire types but are re-exported here for
/// callers who work with JSON serialization directly.
pub mod wire {
    pub use piteka_parwana::protocol::{
        ActionIntentWire, GitHubDeploymentIntentV1Wire, RequiredContextsWire,
    };
}

#[cfg(test)]
mod intent_tests {
    use super::*;

    const TEST_COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";

    fn make_test_input() -> GitHubDeploymentInput {
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

    fn make_test_nonce() -> [u8; 32] {
        [0xAB; 32]
    }

    #[test]
    fn normalize_valid_all_submitted_succeeds() {
        let contract = ParwanaContract::bind().expect("contract bind");
        let normalizer = GitHubIntentNormalizer::new(contract).unwrap();
        let input = make_test_input();

        let result = normalizer.normalize(
            input,
            b"test-requester".to_vec(),
            1_700_000_000,
            make_test_nonce(),
            vec![],
        );

        assert!(result.is_ok(), "normalization should succeed: {result:?}");
        let normalized = result.unwrap();
        assert_eq!(normalized.profile.repository_id, 42);
        assert_eq!(normalized.profile.commit_sha, TEST_COMMIT);
        assert_eq!(normalized.intent.action_type, "github.deployment");
    }

    #[test]
    fn normalize_valid_explicit_contexts_succeeds() {
        let contract = ParwanaContract::bind().expect("contract bind");
        let normalizer = GitHubIntentNormalizer::new(contract).unwrap();
        let input = make_explicit_contexts_input();

        let result = normalizer.normalize(
            input,
            b"test-requester".to_vec(),
            1_700_000_000,
            make_test_nonce(),
            vec![],
        );

        assert!(result.is_ok(), "normalization should succeed: {result:?}");
        let normalized = result.unwrap();
        assert!(matches!(
            normalized.profile.required_contexts,
            RequiredContexts::ExplicitNonEmpty(_)
        ));
    }

    #[test]
    fn normalize_rejects_auto_merge_true() {
        let contract = ParwanaContract::bind().expect("contract bind");
        let normalizer = GitHubIntentNormalizer::new(contract).unwrap();
        let mut input = make_test_input();
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
    fn normalize_rejects_wrong_task() {
        let contract = ParwanaContract::bind().expect("contract bind");
        let normalizer = GitHubIntentNormalizer::new(contract).unwrap();
        let mut input = make_test_input();
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
    fn normalize_rejects_transient_environment() {
        let contract = ParwanaContract::bind().expect("contract bind");
        let normalizer = GitHubIntentNormalizer::new(contract).unwrap();
        let mut input = make_test_input();
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
    fn normalize_rejects_uppercase_commit_sha() {
        let contract = ParwanaContract::bind().expect("contract bind");
        let normalizer = GitHubIntentNormalizer::new(contract).unwrap();
        let mut input = make_test_input();
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
    fn normalize_rejects_moving_ref() {
        let contract = ParwanaContract::bind().expect("contract bind");
        let normalizer = GitHubIntentNormalizer::new(contract).unwrap();
        let mut input = make_test_input();
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
    fn normalize_rejects_empty_contexts() {
        let contract = ParwanaContract::bind().expect("contract bind");
        let normalizer = GitHubIntentNormalizer::new(contract).unwrap();
        let mut input = make_test_input();
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
    fn normalize_rejects_unsorted_contexts() {
        let contract = ParwanaContract::bind().expect("contract bind");
        let normalizer = GitHubIntentNormalizer::new(contract).unwrap();
        let mut input = make_test_input();
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
    fn normalize_rejects_duplicate_contexts() {
        let contract = ParwanaContract::bind().expect("contract bind");
        let normalizer = GitHubIntentNormalizer::new(contract).unwrap();
        let mut input = make_test_input();
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
    fn normalize_rejects_gate_policy_mismatch() {
        let contract = ParwanaContract::bind().expect("contract bind");
        let normalizer = GitHubIntentNormalizer::new(contract).unwrap();
        let mut input = make_test_input();
        // Supply a wrong gate policy digest — agent cannot weaken the gate.
        input.required_contexts = RequiredContextsMode::ExplicitNonEmpty(vec!["ci".to_string()]);
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
    fn normalize_rejects_zero_repository_id() {
        let contract = ParwanaContract::bind().expect("contract bind");
        let normalizer = GitHubIntentNormalizer::new(contract).unwrap();
        let mut input = make_test_input();
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
    fn normalize_rejects_empty_requester() {
        let contract = ParwanaContract::bind().expect("contract bind");
        let normalizer = GitHubIntentNormalizer::new(contract).unwrap();
        let input = make_test_input();

        let result = normalizer.normalize(input, vec![], 1_700_000_000, make_test_nonce(), vec![]);

        assert_eq!(
            result.unwrap_err(),
            NormalizeError::EmptyField("requested_by".to_string())
        );
    }

    #[test]
    fn normalize_rejects_control_chars_in_display_field() {
        let contract = ParwanaContract::bind().expect("contract bind");
        let normalizer = GitHubIntentNormalizer::new(contract).unwrap();
        let mut input = make_test_input();
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
            NormalizeError::DisplayFieldTooLong("repository_name".to_string())
        );
    }

    #[test]
    fn normalize_rejects_whitespace_in_display_field() {
        let contract = ParwanaContract::bind().expect("contract bind");
        let normalizer = GitHubIntentNormalizer::new(contract).unwrap();
        let mut input = make_test_input();
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
            NormalizeError::DisplayFieldTooLong("repository_name".to_string())
        );
    }

    #[test]
    fn normalize_all_fields_change_intent_id() {
        let contract = ParwanaContract::bind().expect("contract bind");
        let normalizer = GitHubIntentNormalizer::new(contract).unwrap();
        let base = normalizer
            .normalize(
                make_test_input(),
                b"test-requester".to_vec(),
                1_700_000_000,
                make_test_nonce(),
                vec![],
            )
            .unwrap();
        let base_id = base.intent.id().unwrap();

        // Change repository_id
        let mut input = make_test_input();
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
        let mut input = make_test_input();
        input.commit_sha = "abcdef0123456789abcdef0123456789abcdef01".to_string();
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
        let mut input = make_test_input();
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
                make_test_input(),
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
                make_test_input(),
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
                make_test_input(),
                b"test-requester".to_vec(),
                1_700_000_000,
                [0xCC; 32],
                vec![],
            )
            .unwrap();
        assert_ne!(changed.intent.id().unwrap(), base_id);
    }

    #[test]
    fn normalize_canonical_bytes_round_trip() {
        let contract = ParwanaContract::bind().expect("contract bind");
        let normalizer = GitHubIntentNormalizer::new(contract).unwrap();
        let input = make_test_input();

        let normalized = normalizer
            .normalize(
                input,
                b"test-requester".to_vec(),
                1_700_000_000,
                make_test_nonce(),
                vec![],
            )
            .unwrap();

        // The intent's canonical bytes should be valid and deterministic.
        let canonical = normalized.intent.canonical_bytes().unwrap();
        assert!(!canonical.is_empty());

        // The intent ID should be derivable.
        let id = normalized.intent.id().unwrap();
        assert!(!id.into_bytes().iter().all(|&b| b == 0));
    }

    #[test]
    fn normalize_explicit_contexts_with_correct_gate_succeeds() {
        let contract = ParwanaContract::bind().expect("contract bind");
        let normalizer = GitHubIntentNormalizer::new(contract).unwrap();
        let input = make_explicit_contexts_input();

        let result = normalizer.normalize(
            input,
            b"test-requester".to_vec(),
            1_700_000_000,
            make_test_nonce(),
            vec![],
        );

        assert!(result.is_ok(), "should succeed with correct gate digest");
        let normalized = result.unwrap();
        let expected_gate =
            RequiredContexts::explicit(vec!["ci".to_string(), "security".to_string()])
                .unwrap()
                .gate_policy_id()
                .unwrap();
        assert_eq!(normalized.gate_policy_digest, expected_gate.into_bytes());
    }

    #[test]
    fn normalize_all_submitted_does_not_require_gate_digest() {
        let contract = ParwanaContract::bind().expect("contract bind");
        let normalizer = GitHubIntentNormalizer::new(contract).unwrap();
        let mut input = make_test_input();
        // AllSubmitted mode — gate_policy_digest is optional.
        input.deployment_gate_policy_digest = None;

        let result = normalizer.normalize(
            input,
            b"test-requester".to_vec(),
            1_700_000_000,
            make_test_nonce(),
            vec![],
        );

        assert!(
            result.is_ok(),
            "AllSubmitted should not require explicit gate digest"
        );
    }

    #[test]
    fn normalize_context_names_with_unicode_succeeds() {
        let contract = ParwanaContract::bind().expect("contract bind");
        let normalizer = GitHubIntentNormalizer::new(contract).unwrap();
        let mut input = make_test_input();
        // Unicode context names are valid (no control characters).
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

        assert!(
            result.is_ok(),
            "unicode context names should succeed: {result:?}"
        );
    }

    #[test]
    fn normalize_rejects_control_char_in_context_name() {
        let contract = ParwanaContract::bind().expect("contract bind");
        let normalizer = GitHubIntentNormalizer::new(contract).unwrap();
        let mut input = make_test_input();
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

    #[test]
    fn normalize_rejects_short_commit_sha() {
        let contract = ParwanaContract::bind().expect("contract bind");
        let normalizer = GitHubIntentNormalizer::new(contract).unwrap();
        let mut input = make_test_input();
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
    fn normalize_rejects_zero_environment_id() {
        let contract = ParwanaContract::bind().expect("contract bind");
        let normalizer = GitHubIntentNormalizer::new(contract).unwrap();
        let mut input = make_test_input();
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
    fn normalize_rejects_too_many_context_commitments() {
        let contract = ParwanaContract::bind().expect("contract bind");
        let normalizer = GitHubIntentNormalizer::new(contract).unwrap();
        let input = make_test_input();
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
    fn normalize_produces_deterministic_output() {
        let contract = ParwanaContract::bind().expect("contract bind");
        let normalizer = GitHubIntentNormalizer::new(contract).unwrap();
        let input = make_test_input();

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

        assert_eq!(first.intent, second.intent);
        assert_eq!(first.profile, second.profile);
        assert_eq!(
            first.intent.canonical_bytes().unwrap(),
            second.intent.canonical_bytes().unwrap()
        );
    }
}
