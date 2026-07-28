#![forbid(unsafe_code)]

//! Piteka web approval UI — binary entry point.
//!
//! Serves the HTML approval interface alongside the REST API.
//! Implements Master Plan §59 D-08.

use axum::{
    Router,
    http::{HeaderValue, Method, header},
};
use piteka_api::TestPorts;
use tower_http::cors::{AllowOrigin, CorsLayer};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Fail closed before anything is served (PIT-NE-001). A process that
    // reached its listener without binding the pinned contract would answer
    // requests against a contract nobody checked.
    piteka_parwana::ParwanaContract::bind_or_refuse_to_start()?;

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
        let tenant = piteka_storage::TenantScope::new(
            std::env::var("PITEKA_TENANT_ID").unwrap_or_else(|_| "local-demo".to_string()),
        )?;
        let live =
            piteka_api::LiveActionRequestPorts::connect(&database_url, tenant.clone()).await?;
        let web = piteka_web::web_router(live.use_case());
        let api = piteka_api::routes::build_full_router(live.use_case())
            .merge(
                piteka_api::routes::build_live_webhook_router(&database_url, tenant.clone())
                    .await?,
            )
            .merge(piteka_api::routes::build_live_read_router(&database_url, tenant).await?);
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
        .merge(api_router)
        .layer(cors_layer()?);

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

/// Browser origins allowed to use Piteka's read-only explorer endpoints.
/// Production deployments must set this explicitly; local Hemion origins are
/// the safe development default.
fn cors_layer() -> Result<CorsLayer, Box<dyn std::error::Error>> {
    let configured = std::env::var("PITEKA_CORS_ORIGINS")
        .unwrap_or_else(|_| "http://127.0.0.1:8181,http://localhost:8181".to_string());
    let origins = configured
        .split(',')
        .map(str::trim)
        .filter(|origin| !origin.is_empty())
        .map(str::parse::<HeaderValue>)
        .collect::<Result<Vec<_>, _>>()?;
    if origins.is_empty() {
        return Err("PITEKA_CORS_ORIGINS must contain at least one origin".into());
    }
    Ok(CorsLayer::new()
        .allow_origin(AllowOrigin::list(origins))
        .allow_methods([Method::GET, Method::POST, Method::DELETE])
        .allow_headers([
            header::AUTHORIZATION,
            header::CONTENT_TYPE,
            header::HeaderName::from_static("x-tenant-id"),
        ]))
}
