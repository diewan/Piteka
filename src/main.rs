use std::net::SocketAddr;

use axum::{Router, routing::get};
use piteka_application::HealthQuery;
use piteka_infra::SystemClock;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Fail closed before anything is served (PIT-NE-001). A process that
    // reached its listener without binding the pinned contract would answer
    // requests against a contract nobody checked.
    piteka_parwana::ParwanaContract::bind_or_refuse_to_start()?;

    // Build the API with in-memory test ports (demo only).
    let test_ports = piteka_api::TestPorts::new();
    let api_router = piteka_api::routes::build_full_router_with_webhook(test_ports);

    let app = Router::new().merge(api_router).route(
        "/health",
        get(|| async {
            let _health = HealthQuery::new(SystemClock).execute();
            "ready"
        }),
    );

    let address = SocketAddr::from(([127, 0, 0, 1], 3000));
    let listener = tokio::net::TcpListener::bind(address).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
