//! Shared harness for the agent demo e2e tests (DEMO-01 / DEMO-03).
//!
//! Provides in-memory ports and a fake GitHub port that records provider calls,
//! so the real `AgentDemoBackend` + `AgentActor` run deterministically with no
//! network or database.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use async_trait::async_trait;

use piteka::demo::DemoPorts;
use piteka_application::SystemClock;
use piteka_application::mcp::McpIdentity;
use piteka_domain::OrganizationId;
use piteka_ports::github::{
    DeploymentCreated, GitHubAppError, GitHubAppPort, GitHubEnvironmentName,
    GitHubInstallationContext, GitHubInstallationId, GitHubRepositoryId, GitHubWebhookPayload,
    GitHubWebhookSecret, WebhookSignatureResult,
};
use piteka_storage::memory::{
    InMemoryActionRequestStore, InMemoryApprovalDecisionStore, InMemoryAuditLog,
    InMemoryExecutionAttemptStore, InMemoryMandateProjectionStore, InMemoryReceiptProjectionStore,
};

pub const TENANT: &str = "tenant-demo";
pub const AGENT: &str = "svc:demo-agent";
pub const REPO_ID: u64 = 99;
pub const ENV_ID: u64 = 7;
pub const SHA: &str = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0";
pub const DEPLOYMENT_ID: u64 = 4242;

/// A fake GitHub port that records each `create_deployment` call and returns a
/// deterministic deployment id. It never touches the network.
pub struct FakeGitHub {
    context: GitHubInstallationContext,
    org: OrganizationId,
    calls: Arc<AtomicUsize>,
}

impl FakeGitHub {
    pub fn new(calls: Arc<AtomicUsize>) -> Self {
        Self {
            context: GitHubInstallationContext::new(
                "1234",
                REPO_ID.to_string(),
                "diewan/piteka-demo",
                ENV_ID.to_string(),
                "piteka-demo-production",
            )
            .expect("valid context"),
            org: OrganizationId::new("diewan-demo").expect("org"),
            calls,
        }
    }
}

#[async_trait]
impl GitHubAppPort for FakeGitHub {
    async fn verify_webhook_signature(
        &self,
        _payload: &GitHubWebhookPayload,
        _webhook_secret: &GitHubWebhookSecret,
    ) -> Result<WebhookSignatureResult, GitHubAppError> {
        Ok(WebhookSignatureResult::Valid)
    }

    async fn create_deployment(
        &self,
        _installation_id: &GitHubInstallationId,
        _repository_id: &GitHubRepositoryId,
        _commit_sha: &str,
        _environment: &GitHubEnvironmentName,
        auto_merge: bool,
        _payload_commitment: &str,
        attempt_digest: [u8; 32],
    ) -> Result<DeploymentCreated, GitHubAppError> {
        assert!(!auto_merge, "auto_merge must be false");
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(DeploymentCreated {
            deployment_id: DEPLOYMENT_ID,
            url: format!("https://github.test/deployments/{DEPLOYMENT_ID}"),
            attempt_digest,
        })
    }

    fn installation_context(&self) -> GitHubInstallationContext {
        self.context.clone()
    }

    fn serving_organization(&self) -> &OrganizationId {
        &self.org
    }
}

pub fn in_memory_ports() -> DemoPorts {
    DemoPorts {
        requests: Arc::new(InMemoryActionRequestStore::default()),
        decisions: Arc::new(InMemoryApprovalDecisionStore::default()),
        mandates: Arc::new(InMemoryMandateProjectionStore::default()),
        attempts: Arc::new(InMemoryExecutionAttemptStore::default()),
        receipts: Arc::new(InMemoryReceiptProjectionStore::default()),
        audit: Arc::new(InMemoryAuditLog::default()),
        clock: Arc::new(SystemClock),
    }
}

pub fn identity() -> McpIdentity {
    McpIdentity::new(AGENT, TENANT).expect("identity")
}
