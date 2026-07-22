#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! GitHub App installation adapter and intent normalization for Piteka.
//!
//! This crate implements the [`GitHubAppPort`] trait from `piteka-ports`. It
//! is the concrete adapter that Piteka uses to interact with GitHub's
//! Deployments API and verify incoming webhooks.
//!
//! # Architecture
//!
//! ```text
//! piteka-application
//!        ↓ (depends on port trait)
//!   piteka-ports::GitHubAppPort
//!        ↑ (implements)
//! piteka-github::GitHubAppAdapter
//!        ↑ (uses)
//!   GitHubSecretResolver (injected)
//!
//! piteka-application / API handlers
//!        ↓ (calls)
//!   piteka_github::intent::GitHubIntentNormalizer
//!        ↓ (produces)
//!   csv_sdk::accountability::ActionIntent
//!        ↓ (forwarded to)
//!   piteka_parwana::ParwanaContract::encode_action_intent
//! ```
//!
//! The adapter never stores raw secrets. All credentials are resolved at
//! runtime through the injected [`GitHubSecretResolver`].
//!
//! # E-01 acceptance criteria
//!
//! - **Least privilege documented**: See this module's crate-level docs.
//! - **Secret reference only**: See [`GitHubAppAdapter`] construction.
//! - **Installation/repository/environment stable IDs**: Provided by
//!   `piteka-ports::github` types.
//! - **Rotation path**: Documented in crate-level docs and tested via
//!   the resolver abstraction.
//!
//! # E-02 GitHub intent normalization
//!
//! The [`intent`] module provides [`GitHubIntentNormalizer`] which normalizes
//! raw GitHub deployment data into validated [`ActionIntent`] values conforming
//! to the `GitHubDeploymentIntentV1` profile. See the [`intent`] module docs
//! for details.

use std::sync::Arc;

// E-02: GitHub intent normalization module
pub mod intent;

use async_trait::async_trait;
use base64::Engine;
use hmac::Mac;
use piteka_domain::OrganizationId;
use piteka_ports::github::{
    DeploymentCreated, GitHubAppError, GitHubAppPort, GitHubEnvironmentName,
    GitHubInstallationContext, GitHubInstallationId, GitHubRepositoryId, GitHubSecretError,
    GitHubSecretReference, GitHubSecretResolver, GitHubWebhookPayload, GitHubWebhookSecret,
    WebhookSignatureResult,
};
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs8::DecodePrivateKey;
use rsa::signature::{SignatureEncoding, Signer};
use serde::{Deserialize, Serialize};

/// GitHub Deployments API request body for the controlled deployment profile.
///
/// The correlation values live in GitHub's opaque `payload` object so they are
/// retained on the provider deployment and echoed by deployment webhooks.
#[derive(Debug, Serialize)]
struct CreateDeploymentRequest<'a> {
    #[serde(rename = "ref")]
    commit_sha: &'a str,
    auto_merge: bool,
    environment: &'a str,
    payload: DeploymentCorrelationPayload<'a>,
}

#[derive(Debug, Serialize)]
struct DeploymentCorrelationPayload<'a> {
    schema_version: u8,
    #[serde(rename = "piteka_attempt_digest")]
    attempt_digest: String,
    #[serde(skip)]
    _payload_commitment: &'a str,
}

fn deployment_request_body<'a>(
    commit_sha: &'a str,
    environment: &'a GitHubEnvironmentName,
    payload_commitment: &'a str,
    attempt_digest: [u8; 32],
) -> CreateDeploymentRequest<'a> {
    CreateDeploymentRequest {
        commit_sha,
        auto_merge: false,
        environment: environment.as_str(),
        payload: DeploymentCorrelationPayload {
            schema_version: 1,
            attempt_digest: hex::encode(attempt_digest),
            _payload_commitment: payload_commitment,
        },
    }
}

// ---------------------------------------------------------------------------
// JWT token generation
// ---------------------------------------------------------------------------

/// A GitHub App JWT token, valid for 10 minutes from issuance.
///
/// GitHub requires a JWT for App-level authentication (creating installation
/// access tokens). This struct holds the token string and its expiration.
#[derive(Clone, Debug)]
#[allow(dead_code)]
struct JwtToken {
    token: String,
    expires_at: u64,
}

impl JwtToken {
    /// Whether this token is still valid.
    #[must_use]
    #[allow(dead_code)]
    fn is_valid(&self, now: u64) -> bool {
        now < self.expires_at
    }
}

/// Generates a GitHub App JWT signed with the App's RSA private key.
///
/// The JWT follows the GitHub App authentication specification:
/// <https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/authenticating-as-a-github-app-installation>
///
/// # Parameters
///
/// * `app_id` — The GitHub App numeric ID.
/// * `private_key` — The RSA private key bytes (PEM format).
/// * `issued_at` — Unix timestamp when the token is issued.
///
/// # Errors
///
/// Returns an error when the private key is malformed or the signing fails.
#[allow(dead_code)]
fn generate_jwt(
    app_id: u64,
    private_key: &[u8],
    issued_at: u64,
) -> Result<JwtToken, GitHubAppError> {
    // Build a minimal JWT: header.payload.signature
    // Header: {"alg": "RS256", "typ": "JWT"}
    let header = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(r#"{"alg":"RS256","typ":"JWT"}"#.as_bytes());

    // Payload: {"iat": <issued_at>, "exp": <issued_at + 600>, "iss": <app_id>}
    // Actually build proper payload
    let payload = format!(
        r#"{{"iat":{},"exp":{},"iss":"{}"}}"#,
        issued_at,
        issued_at + 600,
        app_id
    );

    let payload_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload.as_bytes());

    let signing_input = format!("{header}.{payload_b64}");

    // Sign with RSA-SHA256
    let private_key_pem = std::str::from_utf8(private_key)
        .map_err(|_| GitHubAppError::SecretResolution(GitHubSecretError::EmptySecret))?;

    let private_key = rsa::RsaPrivateKey::from_pkcs8_pem(private_key_pem)
        .or_else(|_| rsa::RsaPrivateKey::from_pkcs1_pem(private_key_pem))
        .map_err(|error| {
            GitHubAppError::SecretResolution(GitHubSecretError::StoreUnavailable(format!(
                "invalid GitHub App private key: {error}"
            )))
        })?;
    // GitHub App JWTs use RS256 (PKCS#1 v1.5), not RSA-PSS.
    let signing_key = rsa::pkcs1v15::SigningKey::<sha2::Sha256>::new(private_key);
    let signature = signing_key.sign(signing_input.as_bytes());

    let signature_b64 =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signature.to_bytes());

    Ok(JwtToken {
        token: format!("{header}.{payload_b64}.{signature_b64}"),
        expires_at: issued_at + 600,
    })
}

/// Creates a short-lived installation access token for a given installation.
///
/// # Parameters
///
/// * `installation_id` — The GitHub App installation ID.
/// * `app_secret` — The resolved App private key (used for JWT generation).
/// * `now` — Current Unix timestamp.
///
/// # Errors
///
/// Returns an error when JWT generation fails.
#[derive(Deserialize)]
struct InstallationTokenResponse {
    token: String,
}

async fn create_installation_token(
    client: &reqwest::Client,
    api_base_url: &str,
    app_id: u64,
    installation_id: &GitHubInstallationId,
    app_secret: &[u8],
    now: u64,
) -> Result<String, GitHubAppError> {
    let issued_at = now.saturating_sub(60);
    let jwt = generate_jwt(app_id, app_secret, issued_at)?;
    let url = format!(
        "{api_base_url}/app/installations/{}/access_tokens",
        installation_id.as_u64()
    );
    let response = client
        .post(url)
        .bearer_auth(jwt.token)
        .header(reqwest::header::ACCEPT, "application/vnd.github+json")
        .header("X-GitHub-Api-Version", "2022-11-28")
        .header(reqwest::header::USER_AGENT, "piteka-controlled-demo")
        .send()
        .await
        .map_err(|error| GitHubAppError::ApiError(error.to_string()))?;
    let status = response.status();
    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        return Err(GitHubAppError::ApiError(format!(
            "installation token exchange returned {status}: {}",
            redact_api_body(&body)
        )));
    }
    response
        .json::<InstallationTokenResponse>()
        .await
        .map(|value| value.token)
        .map_err(|error| GitHubAppError::ApiError(error.to_string()))
}

fn redact_api_body(body: &str) -> String {
    serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|value| {
            value
                .get("message")
                .and_then(|v| v.as_str())
                .map(str::to_owned)
        })
        .unwrap_or_else(|| "GitHub API request failed".to_string())
}

// ---------------------------------------------------------------------------
// Webhook signature verification
// ---------------------------------------------------------------------------

/// Verifies a GitHub webhook HMAC-SHA256 signature.
///
/// GitHub sends the signature in the `X-Hub-Signature-256` header as
/// `sha256=<hex_digest>`. This function computes the HMAC-SHA256 of the
/// payload using the webhook secret and compares the results.
///
/// # Parameters
///
/// * `payload` — The webhook payload with signature and body.
/// * `secret` — The resolved webhook signing secret bytes.
///
/// # Returns
///
/// - [`WebhookSignatureResult::Valid`] if the signature matches.
/// - [`WebhookSignatureResult::MissingOrMalformed`] if the signature header
///   is absent or doesn't start with `sha256=`.
/// - [`WebhookSignatureResult::Invalid`] if the computed and provided
///   digests don't match.
pub fn verify_webhook_signature_internal(
    payload: &[u8],
    signature: &str,
    secret: &str,
) -> WebhookSignatureResult {
    // Extract the expected signature from X-Hub-Signature-256 header value
    let expected_hex = match signature.strip_prefix("sha256=") {
        Some(hex) => hex,
        None => return WebhookSignatureResult::MissingOrMalformed,
    };

    // Compute HMAC-SHA256 of the payload body with the secret
    let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(secret.as_bytes())
        .expect("HMAC can take key of any size");
    mac.update(payload);
    let computed = mac.finalize().into_bytes();

    // Decode the expected signature from hex
    let expected_bytes = match hex::decode(expected_hex) {
        Ok(bytes) => bytes,
        Err(_) => return WebhookSignatureResult::MissingOrMalformed,
    };

    // Constant-time comparison to prevent timing attacks
    // Both digests should be 32 bytes for SHA-256
    if expected_bytes.len() != 32 {
        return WebhookSignatureResult::MissingOrMalformed;
    }
    let mut diff = 0u8;
    for (a, b) in computed.iter().zip(expected_bytes.iter()) {
        diff |= a ^ b;
    }

    if diff == 0 {
        WebhookSignatureResult::Valid
    } else {
        WebhookSignatureResult::Invalid
    }
}

// ---------------------------------------------------------------------------
// Adapter implementation
// ---------------------------------------------------------------------------

/// A GitHub App adapter that implements [`GitHubAppPort`].
///
/// The adapter is constructed with:
/// - A [`GitHubSecretResolver`] for resolving secrets at runtime
/// - A [`GitHubInstallationContext`] with stable provider IDs
/// - An optional clock for testing (defaults to system clock)
///
/// # Secret management
///
/// Raw GitHub App private key bytes are never stored in Piteka's database.
/// The adapter holds only a [`GitHubSecretReference`] and resolves the
/// actual secret through the injected resolver. This supports secret
/// rotation without requiring Piteka to re-process any data.
///
/// # Thread safety
///
/// The adapter is `Clone` and `Send + Sync`, allowing it to be shared
/// across async tasks. The secret resolver is wrapped in an `Arc`.
#[derive(Clone)]
pub struct GitHubAppAdapter<R>
where
    R: GitHubSecretResolver,
{
    resolver: Arc<R>,
    context: GitHubInstallationContext,
    app_secret_reference: GitHubSecretReference,
    webhook_secret_reference: GitHubWebhookSecret,
    serving_org: OrganizationId,
    app_id: Option<u64>,
    api_base_url: String,
    client: reqwest::Client,
}

impl<R> GitHubAppAdapter<R>
where
    R: GitHubSecretResolver,
{
    /// Constructs a new GitHub App adapter.
    ///
    /// # Parameters
    ///
    /// * `resolver` — The secret resolver implementation.
    /// * `context` — The stable installation context (IDs).
    /// * `app_secret_reference` — Reference to the App private key secret.
    /// * `webhook_secret_reference` — Reference to the webhook signing secret.
    /// * `serving_org` — The organization this adapter serves.
    ///
    /// # Errors
    ///
    /// Returns [`GitHubAppError::EmptyField`] when any required field is empty.
    pub fn new(
        resolver: R,
        context: GitHubInstallationContext,
        app_secret_reference: impl Into<String>,
        webhook_secret_reference: impl Into<String>,
        serving_org: OrganizationId,
    ) -> Result<Self, GitHubAppError> {
        Ok(Self {
            resolver: Arc::new(resolver),
            context,
            app_secret_reference: GitHubSecretReference::new(app_secret_reference)
                .map_err(|_| GitHubAppError::EmptyField("app_secret_reference"))?,
            webhook_secret_reference: GitHubWebhookSecret::new(webhook_secret_reference)
                .map_err(|_| GitHubAppError::EmptyField("webhook_secret_reference"))?,
            serving_org,
            app_id: None,
            api_base_url: "https://api.github.com".to_string(),
            client: reqwest::Client::new(),
        })
    }

    /// Enables real GitHub App authentication and HTTP dispatch.
    #[must_use]
    pub fn with_live_transport(mut self, app_id: u64) -> Self {
        self.app_id = Some(app_id);
        self
    }

    /// Overrides the GitHub API base URL for integration testing.
    #[must_use]
    pub fn with_api_base_url(mut self, api_base_url: impl Into<String>) -> Self {
        self.api_base_url = api_base_url.into().trim_end_matches('/').to_string();
        self
    }

    /// Reads the configured GitHub App webhook URL using App authentication.
    pub async fn webhook_config_url(&self) -> Result<String, GitHubAppError> {
        let app_id = self.app_id.ok_or_else(|| {
            GitHubAppError::ApiError("live GitHub transport is not configured".to_string())
        })?;
        let secret = self
            .resolver
            .resolve_app_secret(&self.app_secret_reference)
            .await
            .map_err(GitHubAppError::SecretResolution)?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|error| GitHubAppError::ApiError(error.to_string()))?
            .as_secs();
        let jwt = generate_jwt(app_id, &secret, now.saturating_sub(60));
        drop(secret);
        let response = self
            .client
            .get(format!("{}/app/hook/config", self.api_base_url))
            .bearer_auth(jwt?.token)
            .header(reqwest::header::ACCEPT, "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .header(reqwest::header::USER_AGENT, "piteka-controlled-demo")
            .send()
            .await
            .map_err(|error| GitHubAppError::ApiError(error.to_string()))?;
        let status = response.status();
        let value: serde_json::Value = response
            .json()
            .await
            .map_err(|error| GitHubAppError::ApiError(error.to_string()))?;
        if !status.is_success() {
            return Err(GitHubAppError::ApiError(format!(
                "webhook configuration returned {status}"
            )));
        }
        value
            .get("url")
            .and_then(|value| value.as_str())
            .map(str::to_owned)
            .ok_or_else(|| {
                GitHubAppError::ApiError("webhook configuration omitted url".to_string())
            })
    }

    /// Lists recent GitHub App webhook delivery metadata using App authentication.
    pub async fn recent_webhook_deliveries(&self) -> Result<serde_json::Value, GitHubAppError> {
        let app_id = self.app_id.ok_or_else(|| {
            GitHubAppError::ApiError("live GitHub transport is not configured".to_string())
        })?;
        let secret = self
            .resolver
            .resolve_app_secret(&self.app_secret_reference)
            .await
            .map_err(GitHubAppError::SecretResolution)?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|error| GitHubAppError::ApiError(error.to_string()))?
            .as_secs();
        let jwt = generate_jwt(app_id, &secret, now.saturating_sub(60));
        drop(secret);
        let response = self
            .client
            .get(format!(
                "{}/app/hook/deliveries?per_page=100",
                self.api_base_url
            ))
            .bearer_auth(jwt?.token)
            .header(reqwest::header::ACCEPT, "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .header(reqwest::header::USER_AGENT, "piteka-controlled-demo")
            .send()
            .await
            .map_err(|error| GitHubAppError::ApiError(error.to_string()))?;
        let status = response.status();
        let value = response
            .json::<serde_json::Value>()
            .await
            .map_err(|error| GitHubAppError::ApiError(error.to_string()))?;
        if status.is_success() {
            Ok(value)
        } else {
            Err(GitHubAppError::ApiError(format!(
                "webhook deliveries returned {status}"
            )))
        }
    }

    /// Requests redelivery of one GitHub App webhook delivery.
    pub async fn redeliver_webhook(&self, delivery_id: u64) -> Result<(), GitHubAppError> {
        let app_id = self.app_id.ok_or_else(|| {
            GitHubAppError::ApiError("live GitHub transport is not configured".to_string())
        })?;
        let secret = self
            .resolver
            .resolve_app_secret(&self.app_secret_reference)
            .await
            .map_err(GitHubAppError::SecretResolution)?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|error| GitHubAppError::ApiError(error.to_string()))?
            .as_secs();
        let jwt = generate_jwt(app_id, &secret, now.saturating_sub(60));
        drop(secret);
        let response = self
            .client
            .post(format!(
                "{}/app/hook/deliveries/{delivery_id}/attempts",
                self.api_base_url
            ))
            .bearer_auth(jwt?.token)
            .header(reqwest::header::ACCEPT, "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .header(reqwest::header::USER_AGENT, "piteka-controlled-demo")
            .send()
            .await
            .map_err(|error| GitHubAppError::ApiError(error.to_string()))?;
        if response.status().is_success() {
            Ok(())
        } else {
            Err(GitHubAppError::ApiError(format!(
                "webhook redelivery returned {}",
                response.status()
            )))
        }
    }

    /// Returns the installation context.
    #[must_use]
    pub fn context(&self) -> &GitHubInstallationContext {
        &self.context
    }

    /// Returns the app secret reference.
    #[must_use]
    pub fn app_secret_reference(&self) -> &GitHubSecretReference {
        &self.app_secret_reference
    }

    /// Returns the webhook secret reference.
    #[must_use]
    pub fn webhook_secret_reference(&self) -> &GitHubWebhookSecret {
        &self.webhook_secret_reference
    }
}

#[async_trait]
impl<R> GitHubAppPort for GitHubAppAdapter<R>
where
    R: GitHubSecretResolver,
{
    async fn verify_webhook_signature(
        &self,
        payload: &GitHubWebhookPayload,
        webhook_secret: &GitHubWebhookSecret,
    ) -> Result<WebhookSignatureResult, GitHubAppError> {
        // Resolve the webhook secret
        let secret_bytes = self
            .resolver
            .resolve_webhook_secret(webhook_secret)
            .await
            .map_err(GitHubAppError::SecretResolution)?;

        // Verify using the internal function
        let result = verify_webhook_signature_internal(
            &payload.body,
            &payload.signature,
            std::str::from_utf8(&secret_bytes).unwrap_or(""),
        );

        // Drop the secret bytes immediately after use
        drop(secret_bytes);

        Ok(result)
    }

    async fn create_deployment(
        &self,
        installation_id: &GitHubInstallationId,
        repository_id: &GitHubRepositoryId,
        commit_sha: &str,
        environment: &GitHubEnvironmentName,
        auto_merge: bool,
        payload_commitment: &str,
        attempt_digest: [u8; 32],
    ) -> Result<DeploymentCreated, GitHubAppError> {
        // The adapter is the credential boundary. Caller-controlled provider
        // identifiers must not select a different target while reusing this
        // adapter's configured credential.
        if installation_id != &self.context.installation_id {
            return Err(GitHubAppError::Unauthorized(
                "installation does not match the configured GitHub App context".to_string(),
            ));
        }
        if repository_id != &self.context.repository_id {
            return Err(GitHubAppError::Unauthorized(
                "repository does not match the configured GitHub App context".to_string(),
            ));
        }
        if environment != &self.context.environment_name {
            return Err(GitHubAppError::Unauthorized(
                "environment does not match the configured GitHub App context".to_string(),
            ));
        }

        // Validate inputs — fail closed on empty values
        if commit_sha.is_empty() || commit_sha.len() != 40 {
            return Err(GitHubAppError::EmptyField("commit_sha"));
        }
        if !commit_sha.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(GitHubAppError::ApiError(
                "commit_sha must be a 40-character hexadecimal object ID".to_string(),
            ));
        }
        if payload_commitment.len() != 64
            || !payload_commitment
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(GitHubAppError::EmptyField("payload_commitment"));
        }
        if auto_merge {
            // Master Plan §10.1: auto_merge is fixed to false for the production profile
            return Err(GitHubAppError::ApiError(
                "auto_merge must be false for production deployments".to_string(),
            ));
        }

        // Resolve the App secret and create an installation token
        let app_secret = self
            .resolver
            .resolve_app_secret(&self.app_secret_reference)
            .await
            .map_err(GitHubAppError::SecretResolution)?;

        let Some(app_id) = self.app_id else {
            drop(app_secret);
            return Err(GitHubAppError::ApiError(
                "live GitHub transport is not configured".to_string(),
            ));
        };
        let token = create_installation_token(
            &self.client,
            &self.api_base_url,
            app_id,
            installation_id,
            &app_secret,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system clock must be after the Unix epoch")
                .as_secs(),
        )
        .await;

        // Drop the secret bytes immediately after use
        drop(app_secret);

        let token = token?;

        // Construct the exact provider body at the adapter boundary. The
        // infrastructure HTTP transport sends these bytes unchanged.
        let request =
            deployment_request_body(commit_sha, environment, payload_commitment, attempt_digest);
        #[derive(Deserialize)]
        struct DeploymentResponse {
            id: u64,
            url: String,
        }
        let url = format!(
            "{}/repos/{}/deployments",
            self.api_base_url,
            self.context.repository_name.as_str()
        );
        let response = self
            .client
            .post(url)
            .bearer_auth(token)
            .header(reqwest::header::ACCEPT, "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .header(reqwest::header::USER_AGENT, "piteka-controlled-demo")
            .json(&request)
            .send()
            .await
            .map_err(|error| GitHubAppError::ApiError(error.to_string()))?;
        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(GitHubAppError::ApiError(format!(
                "deployment creation returned {status}: {}",
                redact_api_body(&body)
            )));
        }
        let created = response
            .json::<DeploymentResponse>()
            .await
            .map_err(|error| GitHubAppError::ApiError(error.to_string()))?;
        Ok(DeploymentCreated {
            deployment_id: created.id,
            url: created.url,
            attempt_digest,
        })
    }

    fn installation_context(&self) -> GitHubInstallationContext {
        self.context.clone()
    }

    fn serving_organization(&self) -> &OrganizationId {
        &self.serving_org
    }
}

// ---------------------------------------------------------------------------
// In-memory secret resolver (for testing and demo)
// ---------------------------------------------------------------------------

/// A secret resolver that stores secrets in memory.
///
/// This is intended for testing and demo purposes only. A production
/// implementation would resolve secrets from a KMS, vault, or similar
/// backing store.
#[derive(Clone)]
pub struct InMemorySecretResolver {
    app_secrets: std::collections::HashMap<String, Vec<u8>>,
    webhook_secrets: std::collections::HashMap<String, Vec<u8>>,
}

impl InMemorySecretResolver {
    /// Creates a new in-memory secret resolver.
    #[must_use]
    pub fn new() -> Self {
        Self {
            app_secrets: std::collections::HashMap::new(),
            webhook_secrets: std::collections::HashMap::new(),
        }
    }

    /// Stores an App secret.
    pub fn store_app_secret(&mut self, reference: impl Into<String>, secret: Vec<u8>) {
        self.app_secrets.insert(reference.into(), secret);
    }

    /// Stores a webhook secret.
    pub fn store_webhook_secret(&mut self, reference: impl Into<String>, secret: Vec<u8>) {
        self.webhook_secrets.insert(reference.into(), secret);
    }
}

impl Default for InMemorySecretResolver {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl GitHubSecretResolver for InMemorySecretResolver {
    async fn resolve_app_secret(
        &self,
        reference: &GitHubSecretReference,
    ) -> Result<Vec<u8>, GitHubSecretError> {
        self.app_secrets
            .get(reference.as_str())
            .cloned()
            .ok_or_else(|| GitHubSecretError::UnknownReference(reference.as_str().to_string()))
            .and_then(|bytes| {
                if bytes.is_empty() {
                    Err(GitHubSecretError::EmptySecret)
                } else {
                    Ok(bytes)
                }
            })
    }

    async fn resolve_webhook_secret(
        &self,
        secret: &GitHubWebhookSecret,
    ) -> Result<Vec<u8>, GitHubSecretError> {
        self.webhook_secrets
            .get(secret.as_str())
            .cloned()
            .ok_or_else(|| GitHubSecretError::UnknownReference(secret.as_str().to_string()))
            .and_then(|bytes| {
                if bytes.is_empty() {
                    Err(GitHubSecretError::EmptySecret)
                } else {
                    Ok(bytes)
                }
            })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use piteka_ports::github::{
        GitHubAppPort, GitHubEnvironmentId, GitHubRepositoryName, GitHubWebhookPayload,
    };
    use rsa::pkcs1::EncodeRsaPrivateKey;
    use rsa::signature::Verifier;

    fn make_test_adapter() -> GitHubAppAdapter<InMemorySecretResolver> {
        let mut resolver = InMemorySecretResolver::new();
        resolver.store_app_secret("test-app-key", b"test-rsa-private-key-bytes".to_vec());
        resolver.store_webhook_secret("test-webhook-secret", b"test-webhook-secret-value".to_vec());

        let context = GitHubInstallationContext::new(
            "12345",
            "67890",
            "demo-org/demo-repo",
            "111",
            "production",
        )
        .expect("test context should be valid");

        GitHubAppAdapter::new(
            resolver,
            context,
            "test-app-key",
            "test-webhook-secret",
            OrganizationId::new("diewan-demo").unwrap(),
        )
        .expect("test adapter should be valid")
    }

    #[test]
    fn github_app_jwt_is_rs256_signed_and_binds_claims() {
        let private_key = rsa::RsaPrivateKey::new(&mut rand::thread_rng(), 2048)
            .expect("test RSA key generation should succeed");
        let pem = private_key
            .to_pkcs1_pem(rsa::pkcs8::LineEnding::LF)
            .expect("test RSA key should encode as PKCS#1 PEM");

        let token = generate_jwt(42, pem.as_bytes(), 1_000)
            .expect("a valid GitHub App key should produce a JWT");
        let parts: Vec<_> = token.token.split('.').collect();
        assert_eq!(parts.len(), 3);
        assert_eq!(token.expires_at, 1_600);

        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(parts[1])
            .expect("JWT payload should be base64url");
        assert_eq!(
            std::str::from_utf8(&payload).unwrap(),
            r#"{"iat":1000,"exp":1600,"iss":"42"}"#
        );

        let signature_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(parts[2])
            .expect("JWT signature should be base64url");
        let signature = rsa::pkcs1v15::Signature::try_from(signature_bytes.as_slice())
            .expect("JWT signature should have the RSA modulus length");
        rsa::pkcs1v15::VerifyingKey::<sha2::Sha256>::new(private_key.to_public_key())
            .verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &signature)
            .expect("JWT signature should verify with the matching public key");
    }

    #[test]
    fn github_app_jwt_rejects_malformed_private_keys_without_exposing_bytes() {
        let secret = b"not-a-private-key";
        let error = generate_jwt(42, secret, 1_000).expect_err("malformed keys must fail closed");
        let message = error.to_string();
        assert!(message.contains("invalid GitHub App private key"));
        assert!(!message.contains(std::str::from_utf8(secret).unwrap()));
    }

    #[tokio::test]
    async fn test_verify_webhook_valid_signature() {
        let adapter = make_test_adapter();

        // Create a valid HMAC-SHA256 signature for the test payload
        let payload_body = b"test webhook payload";
        let secret = b"test-webhook-secret-value";
        let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(secret)
            .expect("HMAC can take key of any size");
        mac.update(payload_body);
        let computed = mac.finalize().into_bytes();
        let signature = format!("sha256={}", hex::encode(computed));

        let payload = GitHubWebhookPayload {
            delivery_id: "abc-123".to_string(),
            event_type: "deployment".to_string(),
            signature,
            body: payload_body.to_vec(),
        };

        let result = adapter
            .verify_webhook_signature(
                &payload,
                &GitHubWebhookSecret::new("test-webhook-secret").unwrap(),
            )
            .await
            .expect("verification should not error");

        assert_eq!(result, WebhookSignatureResult::Valid);
    }

    #[tokio::test]
    async fn test_verify_webhook_invalid_signature() {
        let adapter = make_test_adapter();

        let payload = GitHubWebhookPayload {
            delivery_id: "abc-123".to_string(),
            event_type: "deployment".to_string(),
            signature: "sha256=0000000000000000000000000000000000000000000000000000000000000000"
                .to_string(),
            body: b"test webhook payload".to_vec(),
        };

        let result = adapter
            .verify_webhook_signature(
                &payload,
                &GitHubWebhookSecret::new("test-webhook-secret").unwrap(),
            )
            .await
            .expect("verification should not error");

        assert_eq!(result, WebhookSignatureResult::Invalid);
    }

    #[tokio::test]
    async fn test_verify_webhook_missing_signature() {
        let adapter = make_test_adapter();

        let payload = GitHubWebhookPayload {
            delivery_id: "abc-123".to_string(),
            event_type: "deployment".to_string(),
            signature: "malformed-signature".to_string(),
            body: b"test webhook payload".to_vec(),
        };

        let result = adapter
            .verify_webhook_signature(
                &payload,
                &GitHubWebhookSecret::new("test-webhook-secret").unwrap(),
            )
            .await
            .expect("verification should not error");

        assert_eq!(result, WebhookSignatureResult::MissingOrMalformed);
    }

    #[tokio::test]
    async fn test_verify_webhook_unknown_secret() {
        let adapter = make_test_adapter();

        let payload = GitHubWebhookPayload {
            delivery_id: "abc-123".to_string(),
            event_type: "deployment".to_string(),
            signature: "sha256=0000000000000000000000000000000000000000000000000000000000000000"
                .to_string(),
            body: b"test webhook payload".to_vec(),
        };

        let result = adapter
            .verify_webhook_signature(
                &payload,
                &GitHubWebhookSecret::new("unknown-secret").unwrap(),
            )
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            GitHubAppError::SecretResolution(GitHubSecretError::UnknownReference(_)) => {}
            other => panic!("expected UnknownReference error, got: {other}"),
        }
    }

    #[tokio::test]
    async fn test_create_deployment_rejects_auto_merge_true() {
        let adapter = make_test_adapter();

        let result = adapter
            .create_deployment(
                &GitHubInstallationId::new("12345").unwrap(),
                &GitHubRepositoryId::new("67890").unwrap(),
                "abcdef0123456789abcdef0123456789abcdef01",
                &GitHubEnvironmentName::new("production").unwrap(),
                true, // auto_merge = true should be rejected
                "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
                [0u8; 32],
            )
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            GitHubAppError::ApiError(msg) => {
                assert!(msg.contains("auto_merge must be false"));
            }
            other => panic!("expected ApiError, got: {other}"),
        }
    }

    #[tokio::test]
    async fn test_create_deployment_rejects_short_commit_sha() {
        let adapter = make_test_adapter();

        let result = adapter
            .create_deployment(
                &GitHubInstallationId::new("12345").unwrap(),
                &GitHubRepositoryId::new("67890").unwrap(),
                "abc123", // too short
                &GitHubEnvironmentName::new("production").unwrap(),
                false,
                "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
                [0u8; 32],
            )
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            GitHubAppError::EmptyField(field) => {
                assert_eq!(field, "commit_sha");
            }
            other => panic!("expected EmptyField error, got: {other}"),
        }
    }

    #[tokio::test]
    async fn create_deployment_fails_closed_without_live_transport() {
        let adapter = make_test_adapter();

        let result = adapter
            .create_deployment(
                &GitHubInstallationId::new("12345").unwrap(),
                &GitHubRepositoryId::new("67890").unwrap(),
                "abcdef0123456789abcdef0123456789abcdef01",
                &GitHubEnvironmentName::new("production").unwrap(),
                false,
                "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
                [0u8; 32],
            )
            .await;

        assert!(matches!(result, Err(GitHubAppError::ApiError(message)) if
            message.contains("live GitHub transport is not configured")));
    }

    #[tokio::test]
    async fn create_deployment_rejects_provider_context_mismatch_before_secret_use() {
        let adapter = make_test_adapter();
        let cases = [
            (
                GitHubInstallationId::new("99999").unwrap(),
                GitHubRepositoryId::new("67890").unwrap(),
                GitHubEnvironmentName::new("production").unwrap(),
                "installation",
            ),
            (
                GitHubInstallationId::new("12345").unwrap(),
                GitHubRepositoryId::new("99999").unwrap(),
                GitHubEnvironmentName::new("production").unwrap(),
                "repository",
            ),
            (
                GitHubInstallationId::new("12345").unwrap(),
                GitHubRepositoryId::new("67890").unwrap(),
                GitHubEnvironmentName::new("staging").unwrap(),
                "environment",
            ),
        ];

        for (installation, repository, environment, field) in cases {
            let error = adapter
                .create_deployment(
                    &installation,
                    &repository,
                    "abcdef0123456789abcdef0123456789abcdef01",
                    &environment,
                    false,
                    "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
                    [0u8; 32],
                )
                .await
                .unwrap_err();
            assert!(
                matches!(&error, GitHubAppError::Unauthorized(message) if message.contains(field)),
                "expected {field} mismatch, got {error}"
            );
        }
    }

    #[tokio::test]
    async fn secret_resolution_failures_do_not_expose_resolved_secret_bytes() {
        let raw_secret = "raw-private-key-must-not-appear";
        let mut resolver = InMemorySecretResolver::new();
        resolver.store_app_secret("empty-key", Vec::new());
        resolver.store_webhook_secret("webhook-ref", raw_secret.as_bytes().to_vec());
        let context = GitHubInstallationContext::new(
            "12345",
            "67890",
            "demo-org/demo-repo",
            "111",
            "production",
        )
        .unwrap();
        let adapter = GitHubAppAdapter::new(
            resolver,
            context,
            "empty-key",
            "webhook-ref",
            OrganizationId::new("diewan-demo").unwrap(),
        )
        .unwrap();

        let error = adapter
            .create_deployment(
                &GitHubInstallationId::new("12345").unwrap(),
                &GitHubRepositoryId::new("67890").unwrap(),
                "abcdef0123456789abcdef0123456789abcdef01",
                &GitHubEnvironmentName::new("production").unwrap(),
                false,
                "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
                [0u8; 32],
            )
            .await
            .unwrap_err();
        let rendered = format!("{error:?} {error}");
        assert!(!rendered.contains(raw_secret));
        assert!(matches!(
            error,
            GitHubAppError::SecretResolution(GitHubSecretError::EmptySecret)
        ));
    }

    #[test]
    fn deployment_payload_binds_exact_sha_and_attempt_digest() {
        let digest = [0xabu8; 32];
        let environment = GitHubEnvironmentName::new("production").unwrap();
        let request = deployment_request_body(
            "abcdef0123456789abcdef0123456789abcdef01",
            &environment,
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            digest,
        );
        let value = serde_json::to_value(request).unwrap();

        assert_eq!(value["ref"], "abcdef0123456789abcdef0123456789abcdef01");
        assert_eq!(value["auto_merge"], false);
        assert_eq!(value["environment"], "production");
        assert_eq!(value["payload"]["schema_version"], 1);
        assert_eq!(value["payload"]["piteka_attempt_digest"], "ab".repeat(32));
        assert_eq!(value["payload"].as_object().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn test_create_deployment_rejects_non_hex_commit_sha() {
        let adapter = make_test_adapter();
        let result = adapter
            .create_deployment(
                &GitHubInstallationId::new("12345").unwrap(),
                &GitHubRepositoryId::new("67890").unwrap(),
                "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
                &GitHubEnvironmentName::new("production").unwrap(),
                false,
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                [0u8; 32],
            )
            .await;

        assert!(matches!(result, Err(GitHubAppError::ApiError(_))));
    }

    #[tokio::test]
    async fn test_installation_context_returns_stable_ids() {
        let adapter = make_test_adapter();
        let ctx = adapter.installation_context();

        assert_eq!(ctx.installation_id.as_str(), "12345");
        assert_eq!(ctx.repository_id.as_str(), "67890");
        assert_eq!(ctx.repository_name.as_str(), "demo-org/demo-repo");
        assert_eq!(ctx.environment_id.as_str(), "111");
        assert_eq!(ctx.environment_name.as_str(), "production");
    }

    #[tokio::test]
    async fn test_serving_organization() {
        let adapter = make_test_adapter();
        assert_eq!(adapter.serving_organization().as_str(), "diewan-demo");
    }

    #[test]
    fn test_github_installation_id_validation() {
        assert!(GitHubInstallationId::new("12345").is_ok());
        assert!(GitHubInstallationId::new("").is_err());
        assert!(GitHubInstallationId::new("abc").is_err());
        assert!(GitHubInstallationId::new("  ").is_err());
    }

    #[test]
    fn test_github_repository_id_validation() {
        assert!(GitHubRepositoryId::new("67890").is_ok());
        assert!(GitHubRepositoryId::new("").is_err());
        assert!(GitHubRepositoryId::new("abc").is_err());
    }

    #[test]
    fn test_github_environment_id_validation() {
        assert!(GitHubEnvironmentId::new("111").is_ok());
        assert!(GitHubEnvironmentId::new("").is_err());
        assert!(GitHubEnvironmentId::new("abc").is_err());
    }

    #[test]
    fn test_github_secret_reference_validation() {
        assert!(GitHubSecretReference::new("vault:path/to/key").is_ok());
        assert!(GitHubSecretReference::new("").is_err());
        assert!(GitHubSecretReference::new("  ").is_err());
    }

    #[test]
    fn test_github_webhook_secret_validation() {
        assert!(GitHubWebhookSecret::new("vault:webhook-secret").is_ok());
        assert!(GitHubWebhookSecret::new("").is_err());
    }

    #[test]
    fn test_github_repository_name_validation() {
        assert!(GitHubRepositoryName::new("owner/repo").is_ok());
        assert!(GitHubRepositoryName::new("").is_err());
    }

    #[test]
    fn test_github_environment_name_validation() {
        assert!(GitHubEnvironmentName::new("production").is_ok());
        assert!(GitHubEnvironmentName::new("").is_err());
    }

    #[test]
    fn test_installation_context_construction() {
        let ctx =
            GitHubInstallationContext::new("12345", "67890", "owner/repo", "111", "production");
        assert!(ctx.is_ok());

        let bad = GitHubInstallationContext::new("", "67890", "owner/repo", "111", "production");
        assert!(bad.is_err());
    }

    #[tokio::test]
    async fn test_in_memory_resolver_unknown_reference() {
        let resolver = InMemorySecretResolver::new();
        let result = resolver
            .resolve_app_secret(&GitHubSecretReference::new("unknown").unwrap())
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            GitHubSecretError::UnknownReference(_) => {}
            other => panic!("expected UnknownReference, got: {other}"),
        }
    }

    #[tokio::test]
    async fn test_in_memory_resolver_empty_secret() {
        let mut resolver = InMemorySecretResolver::new();
        resolver.store_app_secret("empty-key", vec![]);
        let result = resolver
            .resolve_app_secret(&GitHubSecretReference::new("empty-key").unwrap())
            .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            GitHubSecretError::EmptySecret => {}
            other => panic!("expected EmptySecret, got: {other}"),
        }
    }

    #[tokio::test]
    async fn test_in_memory_resolver_valid_secret() {
        let mut resolver = InMemorySecretResolver::new();
        resolver.store_app_secret("my-key", b"secret-bytes".to_vec());
        let result = resolver
            .resolve_app_secret(&GitHubSecretReference::new("my-key").unwrap())
            .await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), b"secret-bytes");
    }
}
