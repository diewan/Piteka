#![forbid(unsafe_code)]

use std::{env, fs, sync::Arc};

use piteka_application::dispatch::compute_attempt_digest;
use piteka_application::{
    ActionRequestPorts, ActionRequestUseCase, AnchorUseCase, Clock, DispatchOutcome, DispatchPorts,
    DispatchUseCase, SystemClock,
};
use piteka_domain::{OrganizationId, UserId};
use piteka_github::{GitHubAppAdapter, InMemorySecretResolver};
use piteka_infra::LocalCsvSealAnchor;
use piteka_ports::github::{
    GitHubAppPort, GitHubEnvironmentName, GitHubInstallationContext, GitHubInstallationId,
    GitHubRepositoryId,
};
use piteka_storage::{
    ActionRequestStore, ApprovalDecisionStore, AuditLog, ExecutionAttemptStore,
    MandateProjectionStore, ReceiptProjectionStore,
    memory::{InMemoryActionRequestStore, InMemoryApprovalDecisionStore},
};
use sha2::{Digest, Sha256};

#[derive(Clone)]
struct DemoPorts {
    requests: Arc<InMemoryActionRequestStore>,
    decisions: Arc<InMemoryApprovalDecisionStore>,
    mandates: piteka_storage::postgres::PgMandateProjectionStore,
    attempts: piteka_storage::postgres::PgExecutionAttemptStore,
    receipts: piteka_storage::postgres::PgReceiptProjectionStore,
    seals: piteka_storage::postgres::PgSealConsumptionStore,
    audit: piteka_storage::postgres::PgAuditLog,
}

impl DemoPorts {
    async fn connect(database_url: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let pool = piteka_storage::postgres::connect(database_url).await?;
        piteka_storage::postgres::run_migrations(&pool).await?;
        Ok(Self {
            requests: Arc::new(InMemoryActionRequestStore::default()),
            decisions: Arc::new(InMemoryApprovalDecisionStore::default()),
            mandates: piteka_storage::postgres::PgMandateProjectionStore::new(pool.clone()),
            attempts: piteka_storage::postgres::PgExecutionAttemptStore::new(pool.clone()),
            receipts: piteka_storage::postgres::PgReceiptProjectionStore::new(pool.clone()),
            seals: piteka_storage::postgres::PgSealConsumptionStore::new(pool.clone()),
            audit: piteka_storage::postgres::PgAuditLog::new(pool),
        })
    }
}

impl ActionRequestPorts for DemoPorts {
    fn request_store(&self) -> &dyn ActionRequestStore {
        &self.requests
    }
    fn decision_store(&self) -> &dyn ApprovalDecisionStore {
        &self.decisions
    }
    fn audit_log(&self) -> &dyn AuditLog {
        &self.audit
    }
    fn clock(&self) -> &dyn Clock {
        &SystemClock
    }
}

impl DispatchPorts for DemoPorts {
    fn request_store(&self) -> &dyn ActionRequestStore {
        &self.requests
    }
    fn mandate_store(&self) -> &dyn MandateProjectionStore {
        &self.mandates
    }
    fn attempt_store(&self) -> &dyn ExecutionAttemptStore {
        &self.attempts
    }
    fn receipt_store(&self) -> &dyn ReceiptProjectionStore {
        &self.receipts
    }
    fn audit_log(&self) -> &dyn AuditLog {
        &self.audit
    }
    fn clock(&self) -> &dyn Clock {
        &SystemClock
    }
}

fn required(name: &str) -> Result<String, String> {
    env::var(name).map_err(|_| format!("{name} is required"))
}

fn digest(label: &str, values: &[&str]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(label.as_bytes());
    for value in values {
        hasher.update(b"|");
        hasher.update(value.as_bytes());
    }
    hex::encode(hasher.finalize())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let repository = required("PITEKA_DEMO_REPOSITORY")?;
    if env::var("PITEKA_CONFIRM_LIVE_DEMO").as_deref() != Ok(repository.as_str()) {
        return Err("PITEKA_CONFIRM_LIVE_DEMO must exactly match PITEKA_DEMO_REPOSITORY".into());
    }
    let commit_sha = required("PITEKA_DEMO_COMMIT_SHA")?;
    let environment = required("PITEKA_DEMO_ENVIRONMENT")?;
    let run_id = required("PITEKA_DEMO_RUN_ID")?;
    let intent_id = digest(
        "piteka-demo-intent-v1",
        &[&repository, &commit_sha, &environment, &run_id],
    );
    let mandate_id = digest("piteka-demo-mandate-v1", &[&intent_id]);
    let request_id = format!("req-{}", &intent_id[..16]);
    let reservation_digest = digest("piteka-demo-reservation-v1", &[&mandate_id]);
    let correlation_key = format!("piteka:{}", &mandate_id[..24]);

    let ports = DemoPorts::connect(&required("DATABASE_URL")?).await?;
    let actions = ActionRequestUseCase::new(ports.clone());
    actions
        .propose(
            &request_id,
            UserId::new("demo-requester")?,
            Some(intent_id.clone()),
        )
        .await?;
    actions
        .approve(
            &request_id,
            UserId::new("demo-approver")?,
            Some(intent_id.clone()),
            1,
        )
        .await?;
    ports.mandates.insert(&mandate_id, "issued").await?;

    let dispatch = DispatchUseCase::new(ports.clone());
    let reserved = dispatch
        .reserve(
            &request_id,
            &mandate_id,
            &intent_id,
            "piteka-controlled-demo",
            &reservation_digest,
            &correlation_key,
            1,
        )
        .await?;
    let dispatched = match reserved {
        DispatchOutcome::Dispatched(value) => value,
        other => return Err(format!("reservation did not dispatch: {other:?}").into()),
    };
    let attempt_digest =
        compute_attempt_digest(&dispatched.attempt_id_hex, &mandate_id, &intent_id);

    let key = fs::read(required("PITEKA_GITHUB_APP_PRIVATE_KEY_FILE")?)?;
    let mut resolver = InMemorySecretResolver::new();
    resolver.store_app_secret("controlled-demo-key", key);
    resolver.store_webhook_secret("controlled-demo-webhook", b"unused-by-dispatch".to_vec());
    let installation_id = required("PITEKA_GITHUB_INSTALLATION_ID")?;
    let repository_id = required("PITEKA_GITHUB_REPOSITORY_ID")?;
    let environment_id = required("PITEKA_GITHUB_ENVIRONMENT_ID")?;
    let adapter = GitHubAppAdapter::new(
        resolver,
        GitHubInstallationContext::new(
            &installation_id,
            &repository_id,
            &repository,
            &environment_id,
            &environment,
        )?,
        "controlled-demo-key",
        "controlled-demo-webhook",
        OrganizationId::new("diewan-controlled-demo")?,
    )?
    .with_live_transport(required("PITEKA_GITHUB_APP_ID")?.parse()?);

    if env::var("PITEKA_PRINT_WEBHOOK_URL").as_deref() == Ok("1") {
        println!("webhook_url={}", adapter.webhook_config_url().await?);
    }

    let created = adapter
        .create_deployment(
            &GitHubInstallationId::new(installation_id)?,
            &GitHubRepositoryId::new(repository_id)?,
            &commit_sha,
            &GitHubEnvironmentName::new(environment.clone())?,
            false,
            &intent_id,
            attempt_digest,
        )
        .await;

    let created = match created {
        Ok(value) => {
            dispatch
                .complete_dispatch(
                    &dispatched.attempt_id_hex,
                    &mandate_id,
                    &intent_id,
                    true,
                    Some(value.deployment_id),
                    "piteka-controlled-demo",
                    2,
                )
                .await?;
            value
        }
        Err(error) => {
            dispatch
                .complete_dispatch(
                    &dispatched.attempt_id_hex,
                    &mandate_id,
                    &intent_id,
                    false,
                    None,
                    "piteka-controlled-demo",
                    2,
                )
                .await?;
            return Err(error.into());
        }
    };

    // Independent single-use anchor (Phase B, §5.9), recorded off the dispatch hot path:
    // the provider call already returned above, so this only corroborates — the Postgres
    // reservation stays the authoritative liveness check. Create the seal binding the
    // authorized intent id, consume it once with the mandate's reservation-token digest,
    // and persist the proof so the exported bundle manifest can disclose it. A failure here
    // is a corroboration gap, never a reason to fail an otherwise-completed mandate.
    let anchor = AnchorUseCase::new(LocalCsvSealAnchor::new(), ports.seals.clone());
    match anchor
        .record_single_use(&mandate_id, &intent_id, &reservation_digest)
        .await
    {
        Ok(record) => println!(
            "recorded independent single-use anchor: seal {} backend {}",
            record.seal_id_hex, record.anchor_backend
        ),
        Err(error) => eprintln!("single-use anchor not recorded (corroboration gap): {error}"),
    }

    let mandate = ports
        .mandates
        .get(&mandate_id)
        .await?
        .ok_or("mandate disappeared")?;
    let attempt = ports
        .attempts
        .get(&dispatched.attempt_id_hex)
        .await?
        .ok_or("attempt disappeared")?;
    let journal = serde_json::json!({
        "schema_version": 1,
        "profile": "controlled-demo-postgres-v1",
        "run_id": run_id,
        "request_id": request_id,
        "request_status": "approved",
        "approver": "demo-approver",
        "intent_id": intent_id,
        "mandate_id": mandate_id,
        "mandate_state": mandate.state,
        "mandate_version": mandate.version,
        "attempt_id": attempt.attempt_id_hex,
        "attempt_state": format!("{:?}", attempt.state).to_lowercase(),
        "attempt_digest": hex::encode(attempt_digest),
        "github_deployment_id": created.deployment_id,
        "github_deployment_url": created.url,
        "repository": repository,
        "commit_sha": commit_sha,
        "environment": environment,
        "limitation": "Demo identity is not production identity."
    });
    let journal_path = required("PITEKA_DEMO_JOURNAL")?;
    fs::write(&journal_path, serde_json::to_vec_pretty(&journal)?)?;
    println!("deployment_id={}", created.deployment_id);
    println!("journal={journal_path}");
    Ok(())
}
