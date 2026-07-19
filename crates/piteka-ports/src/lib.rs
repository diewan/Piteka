#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! External integration ports for Piteka.
//!
//! This crate defines the interface traits that infrastructure adapters
//! implement. It has zero external dependencies and lives between
//! `piteka-domain` and the infrastructure crates in the dependency graph.
//!
//! # GitHub App port
//!
//! The [`GitHubAppPort`] trait declares the operations Piteka needs from a
//! GitHub App integration: creating deployments, verifying webhooks, and
//! resolving stable provider IDs. The concrete implementation lives in
//! `piteka-github`.
//!
//! # Stable provider IDs
//!
//! GitHub exposes numeric identifiers for installations, repositories, and
//! environments. These types wrap those identifiers and provide validation
//! so that Piteka never accepts an empty or malformed ID. They are the
//! stable references stored in the Piteka database and used in mandate
//! parameters — not display names.

pub mod github;

pub use github::{
    GitHubAppPort, GitHubEnvironmentId, GitHubInstallationId, GitHubRepositoryId,
    GitHubSecretReference, GitHubWebhookPayload, GitHubWebhookSecret,
};
