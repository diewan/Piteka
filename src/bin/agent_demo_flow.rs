#![forbid(unsafe_code)]

//! DEMO-01 (Scenario A) live runner: an autonomous agent drives the real Piteka
//! MCP tools against Postgres and the live GitHub App adapter, under a single-use
//! mandate. It replaces the human/script "execute" click of `controlled_demo_flow`
//! — the operator still *approves*, but the **agent** proposes, executes, and
//! reads the receipt purely through the constrained MCP surface, and a second
//! execute is visibly rejected as a replay.
//!
//! Required environment (mirrors `controlled_demo_flow`):
//!
//! - `DATABASE_URL`
//! - `PITEKA_DEMO_REPOSITORY`, `PITEKA_CONFIRM_LIVE_DEMO` (must match), `PITEKA_DEMO_ENVIRONMENT`
//! - `PITEKA_DEMO_COMMIT_SHA`
//! - `PITEKA_GITHUB_APP_ID`, `PITEKA_GITHUB_APP_PRIVATE_KEY_FILE`
//! - `PITEKA_GITHUB_INSTALLATION_ID`, `PITEKA_GITHUB_REPOSITORY_ID`, `PITEKA_GITHUB_ENVIRONMENT_ID`
//! - `PITEKA_DEMO_JOURNAL` (output path)
//! - optional `PITEKA_DEMO_TENANT` (default `diewan-agent-demo`)

use std::{env, fs, sync::Arc};

use piteka::demo::{AgentActor, AgentDemoBackend, DemoPorts, DeploymentPlan, human_approve};
use piteka_application::SystemClock;
use piteka_application::mcp::McpIdentity;
use piteka_domain::OrganizationId;
use piteka_github::{GitHubAppAdapter, InMemorySecretResolver};
use piteka_ports::github::GitHubInstallationContext;

fn required(name: &str) -> Result<String, String> {
    env::var(name).map_err(|_| format!("{name} is required"))
}

async fn connect_ports(database_url: &str) -> Result<DemoPorts, Box<dyn std::error::Error>> {
    let pool = piteka_storage::postgres::connect(database_url).await?;
    piteka_storage::postgres::run_migrations(&pool).await?;
    Ok(DemoPorts {
        requests: Arc::new(piteka_storage::memory::InMemoryActionRequestStore::default()),
        decisions: Arc::new(piteka_storage::memory::InMemoryApprovalDecisionStore::default()),
        mandates: Arc::new(piteka_storage::postgres::PgMandateProjectionStore::new(pool.clone())),
        attempts: Arc::new(piteka_storage::postgres::PgExecutionAttemptStore::new(pool.clone())),
        receipts: Arc::new(piteka_storage::postgres::PgReceiptProjectionStore::new(pool.clone())),
        audit: Arc::new(piteka_storage::postgres::PgAuditLog::new(pool)),
        clock: Arc::new(SystemClock),
    })
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let repository = required("PITEKA_DEMO_REPOSITORY")?;
    if env::var("PITEKA_CONFIRM_LIVE_DEMO").as_deref() != Ok(repository.as_str()) {
        return Err("PITEKA_CONFIRM_LIVE_DEMO must exactly match PITEKA_DEMO_REPOSITORY".into());
    }
    let commit_sha = required("PITEKA_DEMO_COMMIT_SHA")?;
    let environment = required("PITEKA_DEMO_ENVIRONMENT")?;
    let tenant = env::var("PITEKA_DEMO_TENANT").unwrap_or_else(|_| "diewan-agent-demo".to_string());

    let installation_id = required("PITEKA_GITHUB_INSTALLATION_ID")?;
    let repository_id = required("PITEKA_GITHUB_REPOSITORY_ID")?;
    let environment_id = required("PITEKA_GITHUB_ENVIRONMENT_ID")?;
    let repository_id_u64: u64 = repository_id.parse()?;
    let environment_id_u64: u64 = environment_id.parse()?;

    // Live GitHub App adapter — execution credentials stay here, never with the agent.
    let key = fs::read(required("PITEKA_GITHUB_APP_PRIVATE_KEY_FILE")?)?;
    let mut resolver = InMemorySecretResolver::new();
    resolver.store_app_secret("agent-demo-key", key);
    resolver.store_webhook_secret("agent-demo-webhook", b"unused-by-dispatch".to_vec());
    let adapter = GitHubAppAdapter::new(
        resolver,
        GitHubInstallationContext::new(
            &installation_id,
            &repository_id,
            &repository,
            &environment_id,
            &environment,
        )?,
        "agent-demo-key",
        "agent-demo-webhook",
        OrganizationId::new("diewan-agent-demo")?,
    )?
    .with_live_transport(required("PITEKA_GITHUB_APP_ID")?.parse()?);

    let ports = connect_ports(&required("DATABASE_URL")?).await?;
    let backend = AgentDemoBackend::new(ports, adapter);

    let plan = DeploymentPlan {
        request_id: format!("req-agent-{}", &commit_sha[..12]),
        repository_id: repository_id_u64,
        environment_id: environment_id_u64,
        commit_sha: commit_sha.clone(),
    };
    let intent_id = plan.intent_id(&tenant);

    let identity = McpIdentity::new("svc:diewan-demo-agent", &tenant)
        .map_err(|error| format!("identity: {}", error.message))?;
    let mut agent = AgentActor::new(&backend, identity);

    // 1. Agent proposes through MCP.
    let proposed = agent
        .request_deployment(&plan)
        .await
        .map_err(|error| format!("request_deployment: {error}"))?;
    println!("proposed: {proposed}");

    // 2. Human operator approves out of band (issues the single-use mandate).
    let mandate_id = human_approve(backend.ports(), "demo-approver", &plan.request_id, &intent_id)
        .await
        .map_err(|error| format!("human approve: {error}"))?;
    println!("operator approved; mandate {mandate_id}");

    // 3. Agent learns the mandate id and executes — no human performs this step.
    let learned = agent
        .wait_for_mandate(&plan.request_id, 5)
        .await
        .map_err(|error| format!("wait_for_mandate: {error}"))?;
    assert_eq!(learned, mandate_id, "agent observed the issued mandate");
    let executed = agent
        .execute(&plan, &mandate_id)
        .await
        .map_err(|error| format!("execute: {error}"))?;
    println!("agent executed: {executed}");

    // 4. Agent reads the receipt.
    let receipt = agent
        .get_receipt(&mandate_id)
        .await
        .map_err(|error| format!("get_receipt: {error}"))?;
    println!("receipt: {receipt}");

    // 5. Single-use proof: a second execute is rejected with no provider call.
    match agent.execute(&plan, &mandate_id).await {
        Ok(value) => return Err(format!("SECURITY: replay was not rejected: {value}").into()),
        Err(error) => println!("replay correctly rejected: {error}"),
    }

    let journal = serde_json::json!({
        "schema_version": 1,
        "profile": "agent-demo-postgres-v1",
        "scenario": "A",
        "actor": "autonomous-agent-via-mcp",
        "tenant": tenant,
        "request_id": plan.request_id,
        "intent_id": intent_id,
        "mandate_id": mandate_id,
        "execute": executed,
        "receipt": receipt,
        "repository": repository,
        "commit_sha": commit_sha,
        "environment": environment,
        "limitation": "Demo identity is not production identity.",
    });
    let journal_path = required("PITEKA_DEMO_JOURNAL")?;
    fs::write(&journal_path, serde_json::to_vec_pretty(&journal)?)?;
    println!("journal={journal_path}");
    Ok(())
}
