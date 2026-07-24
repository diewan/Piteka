//! GitHub App integration port and stable provider identifiers.
//!
//! # Stable provider IDs
//!
//! GitHub exposes numeric identifiers for installations, repositories, and
//! environments. These types wrap those identifiers and provide validation
//! so that Piteka never accepts an empty or malformed ID. They are the
//! stable references stored in the Piteka database and used in mandate
//! parameters — not display names.
//!
//! # Least privilege
//!
//! The GitHub App used by Piteka should be configured with the minimum
//! permissions required for the first vertical slice:
//!
//! - **Deployments** — Read and write (to create and monitor deployments)
//! - **Repository contents** — Read-only (to verify the committed SHA exists)
//! - **Webhooks** — Not required for the App itself; Piteka receives webhooks
//!   via a separate endpoint, not through the App's own webhook subscription.
//!
//! The App should be scoped to the specific repository (or organization)
//! being used in the demo, not granted org-wide access.
//!
//! # Secret management
//!
//! Piteka never stores raw GitHub App private key bytes. Instead, it stores
//! a [`GitHubSecretReference`] — an opaque identifier that points to where
//! the secret lives (a KMS key, a vault path, or a file path in local dev).
//! The actual secret is resolved at runtime by the adapter through the
//! [`GitHubSecretResolver`] trait. This design supports secret rotation
//! without requiring Piteka to re-process or re-store any data.

use std::fmt;

use async_trait::async_trait;

use piteka_domain::OrganizationId;

// ---------------------------------------------------------------------------
// Stable provider identifiers
// ---------------------------------------------------------------------------

/// A validation failure for a GitHub stable identifier.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GitHubIdError {
    /// The identifier was empty or whitespace-only.
    Empty,
    /// The identifier contained non-numeric characters.
    NonNumeric,
}

impl fmt::Display for GitHubIdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("GitHub identifier must not be empty"),
            Self::NonNumeric => f.write_str("GitHub identifier must contain only digits"),
        }
    }
}

impl std::error::Error for GitHubIdError {}

/// A stable GitHub installation identifier.
///
/// GitHub assigns a unique numeric ID to each App installation. This ID
/// is stable across repository deletions and recreations within the same
/// GitHub account.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct GitHubInstallationId(String);

impl GitHubInstallationId {
    /// Constructs an installation identifier, rejecting empty or non-numeric values.
    ///
    /// # Errors
    ///
    /// Returns [`GitHubIdError::Empty`] when `value` is blank, or
    /// [`GitHubIdError::NonNumeric`] when it contains non-digit characters.
    pub fn new(value: impl Into<String>) -> Result<Self, GitHubIdError> {
        let value = value.into();
        if value.trim().is_empty() {
            return Err(GitHubIdError::Empty);
        }
        if !value.bytes().all(|b| b.is_ascii_digit()) {
            return Err(GitHubIdError::NonNumeric);
        }
        Ok(Self(value))
    }

    /// Borrows the identifier text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Parses the identifier as a u64.
    #[must_use]
    pub fn as_u64(&self) -> u64 {
        self.0.parse().unwrap_or(0)
    }
}

/// A stable GitHub repository identifier.
///
/// GitHub assigns a unique numeric ID to each repository. This ID is stable
/// even if the repository is renamed.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct GitHubRepositoryId(String);

impl GitHubRepositoryId {
    /// Constructs a repository identifier, rejecting empty or non-numeric values.
    ///
    /// # Errors
    ///
    /// Returns [`GitHubIdError::Empty`] when `value` is blank, or
    /// [`GitHubIdError::NonNumeric`] when it contains non-digit characters.
    pub fn new(value: impl Into<String>) -> Result<Self, GitHubIdError> {
        let value = value.into();
        if value.trim().is_empty() {
            return Err(GitHubIdError::Empty);
        }
        if !value.bytes().all(|b| b.is_ascii_digit()) {
            return Err(GitHubIdError::NonNumeric);
        }
        Ok(Self(value))
    }

    /// Borrows the identifier text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Parses the identifier as a u64.
    #[must_use]
    pub fn as_u64(&self) -> u64 {
        self.0.parse().unwrap_or(0)
    }
}

/// A stable GitHub environment identifier.
///
/// GitHub assigns a unique numeric ID to each environment within a repository.
/// This ID is stable across environment renames.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct GitHubEnvironmentId(String);

impl GitHubEnvironmentId {
    /// Constructs an environment identifier, rejecting empty or non-numeric values.
    ///
    /// # Errors
    ///
    /// Returns [`GitHubIdError::Empty`] when `value` is blank, or
    /// [`GitHubIdError::NonNumeric`] when it contains non-digit characters.
    pub fn new(value: impl Into<String>) -> Result<Self, GitHubIdError> {
        let value = value.into();
        if value.trim().is_empty() {
            return Err(GitHubIdError::Empty);
        }
        if !value.bytes().all(|b| b.is_ascii_digit()) {
            return Err(GitHubIdError::NonNumeric);
        }
        Ok(Self(value))
    }

    /// Borrows the identifier text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Parses the identifier as a u64.
    #[must_use]
    pub fn as_u64(&self) -> u64 {
        self.0.parse().unwrap_or(0)
    }
}

/// A human-readable repository name (owner/repo).
///
/// This is a presentation field. Security-relevant operations use
/// [`GitHubRepositoryId`], not this type.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct GitHubRepositoryName(String);

impl GitHubRepositoryName {
    /// Constructs a repository name, rejecting empty values.
    ///
    /// # Errors
    ///
    /// Returns [`GitHubIdError::Empty`] when `value` is blank.
    pub fn new(value: impl Into<String>) -> Result<Self, GitHubIdError> {
        let value = value.into();
        if value.trim().is_empty() {
            return Err(GitHubIdError::Empty);
        }
        Ok(Self(value))
    }

    /// Borrows the repository name text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A human-readable environment name.
///
/// This is a presentation field. Security-relevant operations use
/// [`GitHubEnvironmentId`], not this type.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct GitHubEnvironmentName(String);

impl GitHubEnvironmentName {
    /// Constructs an environment name, rejecting empty values.
    ///
    /// # Errors
    ///
    /// Returns [`GitHubIdError::Empty`] when `value` is blank.
    pub fn new(value: impl Into<String>) -> Result<Self, GitHubIdError> {
        let value = value.into();
        if value.trim().is_empty() {
            return Err(GitHubIdError::Empty);
        }
        Ok(Self(value))
    }

    /// Borrows the environment name text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

// ---------------------------------------------------------------------------
// Secret reference and resolution
// ---------------------------------------------------------------------------

/// An opaque reference to a GitHub App private key stored outside Piteka.
///
/// Piteka never stores raw GitHub App private key bytes. Instead, it stores
/// this reference and resolves the actual secret at runtime through a
/// [`GitHubSecretResolver`] implementation. This design supports:
///
/// - **Secret rotation** without re-processing or re-storing any Piteka data.
/// - **Least privilege** — the Piteka database never contains execution credentials.
/// - **Multi-tenant isolation** — different tenants can reference different secrets.
///
/// The format of the reference is adapter-specific. For example:
/// - `vault:path/to/github-app-key` for HashiCorp Vault
/// - `aws:kms:key-id-123` for AWS KMS
/// - `file:/etc/piteka/github-app.pem` for local file-based secrets (dev only)
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct GitHubSecretReference(String);

impl GitHubSecretReference {
    /// Constructs a secret reference, rejecting empty values.
    ///
    /// # Errors
    ///
    /// Returns `GitHubIdError::Empty` when `value` is blank.
    pub fn new(value: impl Into<String>) -> Result<Self, GitHubIdError> {
        let value = value.into();
        if value.trim().is_empty() {
            return Err(GitHubIdError::Empty);
        }
        Ok(Self(value))
    }

    /// Borrows the reference text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A GitHub App webhook signing secret.
///
/// Like the private key, this is stored as a reference, not raw bytes.
/// Webhook verification uses the resolved secret at runtime.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct GitHubWebhookSecret(String);

impl GitHubWebhookSecret {
    /// Constructs a webhook secret reference, rejecting empty values.
    ///
    /// # Errors
    ///
    /// Returns `GitHubIdError::Empty` when `value` is blank.
    pub fn new(value: impl Into<String>) -> Result<Self, GitHubIdError> {
        let value = value.into();
        if value.trim().is_empty() {
            return Err(GitHubIdError::Empty);
        }
        Ok(Self(value))
    }

    /// Borrows the reference text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Resolves a [`GitHubSecretReference`] to its actual secret bytes at runtime.
///
/// Implementations of this trait are responsible for fetching the secret from
/// whatever backing store is configured (KMS, vault, file, environment variable).
/// Piteka never implements this trait directly; it is provided by the
/// infrastructure layer.
///
/// # Security
///
/// Implementations must ensure that resolved secrets do not leak into logs,
/// telemetry, or error messages. The resolved bytes should be used only for
/// the specific cryptographic operation and then dropped.
#[async_trait]
pub trait GitHubSecretResolver: Send + Sync {
    /// Resolves a GitHub App private key reference to its raw bytes.
    ///
    /// # Errors
    ///
    /// Returns an error when the reference is unknown, the backing store is
    /// unavailable, or the resolved bytes are empty.
    async fn resolve_app_secret(
        &self,
        reference: &GitHubSecretReference,
    ) -> Result<Vec<u8>, GitHubSecretError>;

    /// Resolves a webhook signing secret reference to its raw bytes.
    ///
    /// # Errors
    ///
    /// Returns an error when the reference is unknown, the backing store is
    /// unavailable, or the resolved bytes are empty.
    async fn resolve_webhook_secret(
        &self,
        secret: &GitHubWebhookSecret,
    ) -> Result<Vec<u8>, GitHubSecretError>;
}

/// A failure resolving a GitHub secret.
#[derive(Debug)]
pub enum GitHubSecretError {
    /// The secret reference is not known to the resolver.
    UnknownReference(String),
    /// The backing store was unavailable.
    StoreUnavailable(String),
    /// The resolved secret was empty.
    EmptySecret,
}

impl fmt::Display for GitHubSecretError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownReference(reference) => {
                write!(f, "unknown secret reference: {reference}")
            }
            Self::StoreUnavailable(source) => {
                write!(f, "secret store unavailable: {source}")
            }
            Self::EmptySecret => f.write_str("resolved secret was empty"),
        }
    }
}

impl std::error::Error for GitHubSecretError {}

// ---------------------------------------------------------------------------
// Port trait
// ---------------------------------------------------------------------------

/// A GitHub webhook payload with metadata needed for verification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GitHubWebhookPayload {
    /// The GitHub-provided delivery identifier (X-GitHub-Delivery header).
    pub delivery_id: String,
    /// The GitHub event type (X-GitHub-Event header).
    pub event_type: String,
    /// The HMAC-SHA256 signature from the X-Hub-Signature-256 header.
    pub signature: String,
    /// The raw payload bytes.
    pub body: Vec<u8>,
}

/// The result of verifying a GitHub webhook signature.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WebhookSignatureResult {
    /// The signature is valid for the given secret and payload.
    Valid,
    /// The signature header is missing or malformed.
    MissingOrMalformed,
    /// The signature does not match the payload and secret.
    Invalid,
}

/// The GitHub Deployments API's reply to a create-deployment call.
///
/// `Response` is deliberate: everything here is what GitHub told us, not
/// something Piteka established. It is not named `DeploymentCreated`, which
/// reads as an `Event` — an immutable statement that a named transition was
/// emitted — and would claim more than one API reply can prove. Whether the
/// deployment actually happened is settled later, by a receipt that may honestly
/// report `Unknown`.
///
/// E-04: The `deployment_id` is the GitHub-assigned ID returned from the
/// Deployments API response. It is the stable reference used for webhook
/// correlation and reconciliation. The `attempt_digest` binds the Piteka-side
/// execution attempt to the GitHub-side deployment record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeploymentCreationResponse {
    /// The GitHub-assigned deployment ID.
    pub deployment_id: u64,
    /// The GitHub deployment URL.
    pub url: String,
    /// SHA-256 digest of the correlation payload sent to GitHub.
    ///
    /// This digest is derived from the attempt ID, mandate ID, and intent ID.
    /// It is stored in the execution attempt record for forensic correlation
    /// and enables reconciliation when a webhook arrives out of band.
    pub attempt_digest: [u8; 32],
}

/// A failure during a GitHub App operation.
#[derive(Debug)]
pub enum GitHubAppError {
    /// The secret resolver could not resolve a required secret.
    SecretResolution(GitHubSecretError),
    /// The GitHub API returned an error.
    ApiError(String),
    /// The request was not authorized (wrong installation, missing permissions).
    Unauthorized(String),
    /// The payload failed verification.
    VerificationFailed,
    /// A required field was empty.
    EmptyField(&'static str),
}

impl fmt::Display for GitHubAppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SecretResolution(err) => write!(f, "secret resolution failed: {err}"),
            Self::ApiError(message) => write!(f, "GitHub API error: {message}"),
            Self::Unauthorized(message) => write!(f, "unauthorized: {message}"),
            Self::VerificationFailed => f.write_str("webhook signature verification failed"),
            Self::EmptyField(field) => write!(f, "field `{field}` must not be empty"),
        }
    }
}

impl std::error::Error for GitHubAppError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::SecretResolution(err) => Some(err),
            _ => None,
        }
    }
}

/// Port trait for the GitHub App integration.
///
/// This trait declares the operations Piteka needs from a GitHub App adapter.
/// The concrete implementation lives in `piteka-github` and is provided to
/// the application layer through dependency injection.
///
/// # Security invariants
///
/// - Execution credentials (private key) never leave the adapter layer.
/// - Webhook payloads are verified before any downstream processing.
/// - All operations require a valid installation context.
#[async_trait]
pub trait GitHubAppPort: Send + Sync {
    /// Verifies that a received webhook payload has a valid GitHub signature.
    ///
    /// This is the first gate in the webhook ingestion pipeline. Invalid
    /// signatures are rejected before any state is read or written.
    ///
    /// # Errors
    ///
    /// Returns [`GitHubAppError::VerificationFailed`] when the signature
    /// does not match, or a secret resolution error.
    async fn verify_webhook_signature(
        &self,
        payload: &GitHubWebhookPayload,
        webhook_secret: &GitHubWebhookSecret,
    ) -> Result<WebhookSignatureResult, GitHubAppError>;

    /// Creates a deployment via the GitHub Deployments API.
    ///
    /// This is the dispatch boundary: once GitHub accepts this request, the
    /// mandate transitions to `Quarantined` (Master Plan §10.3). The adapter
    /// must use the credentials resolved from `app_secret_reference`.
    ///
    /// E-04: The `attempt_digest` is incorporated into the GitHub deployment
    /// payload so that incoming webhooks can be correlated back to the
    /// Piteka execution attempt. The returned [`DeploymentCreationResponse`] includes
    /// this digest for storage in the attempt record.
    ///
    /// # Parameters
    ///
    /// * `installation_id` — The GitHub App installation that owns the token.
    /// * `repository_id` — The target repository.
    /// * `commit_sha` — The exact commit SHA to deploy.
    /// * `environment` — The target environment name.
    /// * `auto_merge` — Whether to auto-merge the deployment ref (must be `false`).
    /// * `payload_commitment` — A SHA-256 hex digest correlating this dispatch to the mandate.
    /// * `attempt_digest` — SHA-256 digest of the attempt ID + mandate ID + intent ID.
    ///
    /// # Errors
    ///
    /// Returns an error when the secret cannot be resolved, the GitHub API
    /// rejects the request, or required fields are empty.
    #[allow(clippy::too_many_arguments)]
    async fn create_deployment(
        &self,
        installation_id: &GitHubInstallationId,
        repository_id: &GitHubRepositoryId,
        commit_sha: &str,
        environment: &GitHubEnvironmentName,
        auto_merge: bool,
        payload_commitment: &str,
        attempt_digest: [u8; 32],
    ) -> Result<DeploymentCreationResponse, GitHubAppError>;

    /// Returns the stable IDs configured for this GitHub App installation.
    ///
    /// These IDs are stored in Piteka's configuration and referenced in
    /// mandates and action requests. They are stable across rotations of
    /// the app secret.
    fn installation_context(&self) -> GitHubInstallationContext;

    /// Returns the configured organization ID that this adapter serves.
    fn serving_organization(&self) -> &OrganizationId;
}

/// Stable configuration for a GitHub App installation.
///
/// These values are set once during installation and remain stable across
/// secret rotations. They are the identifiers stored in Piteka's database
/// and referenced in mandates.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GitHubInstallationContext {
    /// The GitHub App installation ID (numeric).
    pub installation_id: GitHubInstallationId,
    /// The GitHub repository ID (numeric).
    pub repository_id: GitHubRepositoryId,
    /// The GitHub repository name (owner/repo, presentation only).
    pub repository_name: GitHubRepositoryName,
    /// The target environment ID (numeric).
    pub environment_id: GitHubEnvironmentId,
    /// The target environment name (presentation only).
    pub environment_name: GitHubEnvironmentName,
}

impl GitHubInstallationContext {
    /// Constructs an installation context, validating all fields.
    ///
    /// # Errors
    ///
    /// Returns an error if any required field is empty or malformed.
    pub fn new(
        installation_id: impl Into<String>,
        repository_id: impl Into<String>,
        repository_name: impl Into<String>,
        environment_id: impl Into<String>,
        environment_name: impl Into<String>,
    ) -> Result<Self, GitHubAppError> {
        Ok(Self {
            installation_id: GitHubInstallationId::new(installation_id)
                .map_err(|_| GitHubAppError::EmptyField("installation_id"))?,
            repository_id: GitHubRepositoryId::new(repository_id)
                .map_err(|_| GitHubAppError::EmptyField("repository_id"))?,
            repository_name: GitHubRepositoryName::new(repository_name)
                .map_err(|_| GitHubAppError::EmptyField("repository_name"))?,
            environment_id: GitHubEnvironmentId::new(environment_id)
                .map_err(|_| GitHubAppError::EmptyField("environment_id"))?,
            environment_name: GitHubEnvironmentName::new(environment_name)
                .map_err(|_| GitHubAppError::EmptyField("environment_name"))?,
        })
    }
}
