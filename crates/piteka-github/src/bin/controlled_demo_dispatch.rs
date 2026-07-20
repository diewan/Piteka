#![forbid(unsafe_code)]

use std::{env, fs};

use piteka_domain::OrganizationId;
use piteka_github::{GitHubAppAdapter, InMemorySecretResolver};
use piteka_ports::github::{
    GitHubAppPort, GitHubEnvironmentName, GitHubInstallationContext, GitHubInstallationId,
    GitHubRepositoryId,
};

fn required(name: &str) -> Result<String, String> {
    env::var(name).map_err(|_| format!("{name} is required"))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    if env::var("PITEKA_CONFIRM_LIVE_DEMO").as_deref() != Ok("zorvan/piteka-demo") {
        return Err(
            "set PITEKA_CONFIRM_LIVE_DEMO=zorvan/piteka-demo to authorize the live dispatch".into(),
        );
    }

    let key_path = required("PITEKA_GITHUB_APP_PRIVATE_KEY_FILE")?;
    let key =
        fs::read(&key_path).map_err(|error| format!("cannot read private key file: {error}"))?;
    let app_id: u64 = required("PITEKA_GITHUB_APP_ID")?.parse()?;
    let installation_id = required("PITEKA_GITHUB_INSTALLATION_ID")?;
    let repository_id = required("PITEKA_GITHUB_REPOSITORY_ID")?;
    let repository = required("PITEKA_DEMO_REPOSITORY")?;
    let environment_id = required("PITEKA_GITHUB_ENVIRONMENT_ID")?;
    let environment = required("PITEKA_DEMO_ENVIRONMENT")?;
    let commit_sha = required("PITEKA_DEMO_COMMIT_SHA")?;
    let payload_commitment = required("PITEKA_DEMO_PAYLOAD_COMMITMENT")?;
    let attempt_digest_hex = required("PITEKA_DEMO_ATTEMPT_DIGEST")?;
    let attempt_bytes = hex::decode(attempt_digest_hex)?;
    let attempt_digest: [u8; 32] = attempt_bytes
        .try_into()
        .map_err(|_| "PITEKA_DEMO_ATTEMPT_DIGEST must be 64 hexadecimal characters")?;

    let context = GitHubInstallationContext::new(
        &installation_id,
        &repository_id,
        &repository,
        &environment_id,
        &environment,
    )?;
    let mut resolver = InMemorySecretResolver::new();
    resolver.store_app_secret("controlled-demo-key", key);
    resolver.store_webhook_secret("controlled-demo-webhook", b"unused-by-dispatch".to_vec());
    let adapter = GitHubAppAdapter::new(
        resolver,
        context,
        "controlled-demo-key",
        "controlled-demo-webhook",
        OrganizationId::new("diewan-controlled-demo")?,
    )?
    .with_live_transport(app_id);

    if env::var("PITEKA_INSPECT_WEBHOOK_ONLY").as_deref() == Ok("1") {
        if let Ok(delivery_id) = env::var("PITEKA_REDELIVER_ID") {
            adapter.redeliver_webhook(delivery_id.parse()?).await?;
            println!("redelivered={delivery_id}");
        }
        println!("webhook_url={}", adapter.webhook_config_url().await?);
        println!("deliveries={}", adapter.recent_webhook_deliveries().await?);
        return Ok(());
    }

    let created = adapter
        .create_deployment(
            &GitHubInstallationId::new(installation_id)?,
            &GitHubRepositoryId::new(repository_id)?,
            &commit_sha,
            &GitHubEnvironmentName::new(environment)?,
            false,
            &payload_commitment,
            attempt_digest,
        )
        .await?;

    println!("deployment_id={}", created.deployment_id);
    println!("deployment_url={}", created.url);
    println!("attempt_digest={}", hex::encode(created.attempt_digest));
    Ok(())
}
