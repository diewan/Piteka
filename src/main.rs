use std::net::SocketAddr;

use axum::{Router, routing::get};
use piteka_application::HealthQuery;
use piteka_infra::SystemClock;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let app = Router::new().route(
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
