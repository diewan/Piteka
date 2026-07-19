//! Error types for webhook ingestion.

use thiserror::Error;

/// A result type alias for webhook ingestion operations.
pub type WebhookResult<T> = Result<T, WebhookError>;

/// Errors that can occur during webhook ingestion.
#[derive(Error, Debug)]
pub enum WebhookError {
    /// The webhook signature verification failed.
    ///
    /// This is a security-rejection: the payload did not match the expected
    /// HMAC-SHA256 digest for the configured webhook secret.
    #[error("webhook signature verification failed")]
    VerificationFailed,

    /// The webhook secret could not be resolved.
    #[error("webhook secret resolution failed: {0}")]
    SecretResolution(#[from] piteka_ports::github::GitHubSecretError),

    /// A storage operation failed.
    #[error("storage error: {0}")]
    Storage(#[from] piteka_storage::StorageError),

    /// The webhook payload was malformed (missing required fields).
    #[error("malformed webhook: {0}")]
    Malformed(String),

    /// The webhook event type is not supported.
    #[error("unsupported event type: {0}")]
    UnsupportedEventType(String),
}
