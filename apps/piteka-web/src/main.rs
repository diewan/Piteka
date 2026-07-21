#![forbid(unsafe_code)]

//! Piteka web approval UI — binary entry point.
//!
//! Serves the HTML approval interface alongside the REST API.
//! Implements Master Plan §59 D-08.

use axum::Router;
use piteka_api::TestPorts;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Build the API with in-memory test ports (demo only).
    let test_ports = TestPorts::new();
    let use_case = test_ports.use_case();

    // Build the web UI router
    let web_router = piteka_web::web_router(use_case.clone());
    let assets_router = piteka_web::assets_router();

    // Build the API router. With a database configured, mount the live webhook
    // and the Postgres-backed read API (mandate/receipt/chain/export) that the
    // Hemion explorer drills into.
    let api_router = if let Ok(database_url) = std::env::var("DATABASE_URL") {
        piteka_api::routes::build_full_router(test_ports.use_case())
            .merge(piteka_api::routes::build_live_webhook_router(&database_url).await?)
            .merge(piteka_api::routes::build_live_read_router(&database_url).await?)
    } else {
        piteka_api::routes::build_full_router_with_webhook(test_ports)
    };

    // Combine everything
    let app = Router::new()
        .merge(assets_router)
        .merge(web_router)
        .merge(api_router);

    let address = std::net::SocketAddr::from(([127, 0, 0, 1], 3000));
    eprintln!("Piteka web approval UI listening on http://{}", address);
    axum::serve(tokio::net::TcpListener::bind(address).await?, app).await?;
    Ok(())
}
