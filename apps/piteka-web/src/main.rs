#![forbid(unsafe_code)]

//! Piteka web approval UI — binary entry point.
//!
//! Serves the HTML approval interface alongside the REST API.
//! Implements Master Plan §59 D-08.

use axum::Router;
use piteka_api::TestPorts;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let assets_router = piteka_web::assets_router();

    // With DATABASE_URL set, the whole write path is live: the action-request
    // approval workflow (propose → approve/reject → revoke) is persisted to
    // Postgres and shared by BOTH the server-rendered UI and the REST API over
    // one connection pool, so the work queue and the API never disagree.
    // Alongside it run the live webhook and the Postgres-backed read API
    // (mandate/receipt/chain/export) the Hemion explorer drills into. Without a
    // database, everything falls back to in-memory TestPorts for a
    // zero-dependency demo.
    let (web_router, api_router) = if let Ok(database_url) = std::env::var("DATABASE_URL") {
        let live = piteka_api::LiveActionRequestPorts::connect(&database_url).await?;
        let web = piteka_web::web_router(live.use_case());
        let api = piteka_api::routes::build_full_router(live.use_case())
            .merge(piteka_api::routes::build_live_webhook_router(&database_url).await?)
            .merge(piteka_api::routes::build_live_read_router(&database_url).await?);
        (web, api)
    } else {
        let test_ports = TestPorts::new();
        let web = piteka_web::web_router(test_ports.use_case());
        let api = piteka_api::routes::build_full_router_with_webhook(test_ports);
        (web, api)
    };

    // Combine everything
    let app = Router::new()
        .merge(assets_router)
        .merge(web_router)
        .merge(api_router);

    // Listen address is configurable (mirrors evidence_feed_server's
    // PITEKA_FEED_BIND). Defaults to loopback for host runs; containerized
    // deployments set PITEKA_WEB_BIND=0.0.0.0:3000 so the published port is
    // reachable from the host / other containers.
    let address: std::net::SocketAddr = std::env::var("PITEKA_WEB_BIND")
        .unwrap_or_else(|_| "127.0.0.1:3000".to_string())
        .parse()?;
    eprintln!("Piteka web approval UI listening on http://{}", address);
    axum::serve(tokio::net::TcpListener::bind(address).await?, app).await?;
    Ok(())
}
