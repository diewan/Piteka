#![forbid(unsafe_code)]

//! Piteka signed evidence-export feed server.
//!
//! Post-demo Master Plan increment (§23): Piteka remains the single GitHub
//! webhook consumer and evidence authority, and *exports* an immutable,
//! authenticated pull feed that Tuppira's `PitekaEvidenceFeedConnector`
//! consumes. Tuppira never registers a competing webhook.
//!
//! Each feed entry wraps the exact bundle-export manifest bytes for one receipt
//! in a `SignedPitekaExport` envelope, detached-signed with ed25519 over a
//! domain-separated byte layout that byte-matches the connector's verifier.
//!
//! Configuration (environment):
//!   DATABASE_URL                  PostgreSQL connection string (required)
//!   PITEKA_FEED_SIGNING_KEY_FILE  file holding a 64-hex-char ed25519 seed
//!   PITEKA_FEED_SIGNING_KEY_ID    signing-key identifier echoed in the feed
//!   PITEKA_FEED_TENANT_ID         tenant the exports belong to
//!   PITEKA_FEED_BEARER_TOKEN      shared bearer token required on every pull
//!   PITEKA_FEED_RECEIPTS          comma-separated receipt IDs, in feed order
//!   PITEKA_FEED_BIND              listen address (default 127.0.0.1:3200)

use std::{env, fs, net::SocketAddr, sync::Arc, time::SystemTime};

use axum::{
    Json, Router,
    extract::{Query, State},
    http::{HeaderMap, StatusCode, header},
    routing::get,
};
use ed25519_dalek::{Signer, SigningKey};
use piteka_application::bundle_export::export_manifest_bytes;
use piteka_storage::postgres::{PgEvidenceNodeStore, PgReceiptProjectionStore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const FEED_SCHEMA_VERSION: u16 = 1;
const MEDIA_TYPE: &str = "application/vnd.diewan.piteka-evidence-export+json";
const SIGNATURE_DOMAIN: &[u8] = b"diewan.piteka.evidence-feed.v1\0";

/// One export and its detached feed signature. Field names and types mirror the
/// Tuppira connector's `SignedPitekaExport` so the JSON round-trips exactly.
#[derive(Clone, Serialize, Deserialize)]
struct SignedPitekaExport {
    schema_version: u16,
    sequence: u64,
    export_id: String,
    revision: u32,
    supersedes_export_id: Option<String>,
    tenant_id: String,
    emitted_at: u64,
    payload: Vec<u8>,
    payload_sha256: [u8; 32],
    signing_key_id: String,
    signature: Vec<u8>,
}

impl SignedPitekaExport {
    /// Domain-separated signing preimage. Must byte-match the connector's
    /// `SignedPitekaExport::signing_bytes`.
    fn signing_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(SIGNATURE_DOMAIN.len() + self.payload.len() + 256);
        bytes.extend_from_slice(SIGNATURE_DOMAIN);
        bytes.extend_from_slice(&self.schema_version.to_be_bytes());
        bytes.extend_from_slice(&self.sequence.to_be_bytes());
        put_text(&mut bytes, &self.export_id);
        bytes.extend_from_slice(&self.revision.to_be_bytes());
        match &self.supersedes_export_id {
            Some(value) => {
                bytes.push(1);
                put_text(&mut bytes, value);
            }
            None => bytes.push(0),
        }
        put_text(&mut bytes, &self.tenant_id);
        bytes.extend_from_slice(&self.emitted_at.to_be_bytes());
        bytes.extend_from_slice(&self.payload_sha256);
        bytes.extend_from_slice(&(self.payload.len() as u64).to_be_bytes());
        bytes.extend_from_slice(&self.payload);
        bytes
    }
}

fn put_text(out: &mut Vec<u8>, value: &str) {
    out.extend_from_slice(&(value.len() as u32).to_be_bytes());
    out.extend_from_slice(value.as_bytes());
}

/// A bounded page of the immutable feed. Mirrors the connector's `PitekaFeedPage`.
#[derive(Clone, Serialize, Deserialize)]
struct PitekaFeedPage {
    schema_version: u16,
    exports: Vec<SignedPitekaExport>,
    next_sequence: u64,
}

#[derive(Deserialize)]
struct FeedQuery {
    #[serde(default)]
    after_sequence: u64,
    #[serde(default = "default_limit")]
    limit: u32,
}

fn default_limit() -> u32 {
    64
}

#[derive(Clone)]
struct FeedState {
    bearer_token: Arc<String>,
    exports: Arc<Vec<SignedPitekaExport>>,
}

fn required(name: &str) -> Result<String, String> {
    env::var(name).map_err(|_| format!("{name} is required"))
}

fn load_signing_key(path: &str) -> Result<SigningKey, String> {
    let raw = fs::read_to_string(path).map_err(|e| format!("cannot read {path}: {e}"))?;
    let seed_hex = raw.trim();
    let seed = hex::decode(seed_hex)
        .map_err(|_| format!("{path} must contain a 64-hex-char ed25519 seed"))?;
    let seed: [u8; 32] = seed
        .try_into()
        .map_err(|_| format!("{path} must decode to exactly 32 bytes"))?;
    Ok(SigningKey::from_bytes(&seed))
}

/// Builds every signed export once at startup so the feed is immutable and the
/// sequence numbers are stable across pulls.
async fn build_exports(
    receipts: PgReceiptProjectionStore,
    evidence: PgEvidenceNodeStore,
    receipt_ids: &[String],
    tenant_id: &str,
    signing_key_id: &str,
    key: &SigningKey,
) -> Result<Vec<SignedPitekaExport>, String> {
    let emitted_base = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_err(|e| format!("clock error: {e}"))?
        .as_secs();

    let mut exports = Vec::with_capacity(receipt_ids.len());
    for (index, receipt_id) in receipt_ids.iter().enumerate() {
        let payload = export_manifest_bytes(&receipts, &evidence, receipt_id)
            .await
            .map_err(|e| format!("cannot export receipt {receipt_id}: {e}"))?;
        let payload_sha256: [u8; 32] = Sha256::digest(&payload).into();
        // Each export gets a strictly increasing emission clock so the consumer's
        // per-observation sync cursor advances monotonically.
        let mut export = SignedPitekaExport {
            schema_version: FEED_SCHEMA_VERSION,
            sequence: (index as u64) + 1,
            export_id: receipt_id.clone(),
            revision: 1,
            supersedes_export_id: None,
            tenant_id: tenant_id.to_string(),
            emitted_at: emitted_base + index as u64,
            payload,
            payload_sha256,
            signing_key_id: signing_key_id.to_string(),
            signature: Vec::new(),
        };
        export.signature = key.sign(&export.signing_bytes()).to_bytes().to_vec();
        exports.push(export);
    }
    Ok(exports)
}

async fn serve_feed(
    State(state): State<FeedState>,
    headers: HeaderMap,
    Query(query): Query<FeedQuery>,
) -> Result<Json<PitekaFeedPage>, StatusCode> {
    let presented = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "));
    if presented != Some(state.bearer_token.as_str()) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    if query.limit == 0 || query.limit > 1024 {
        return Err(StatusCode::BAD_REQUEST);
    }

    let selected: Vec<SignedPitekaExport> = state
        .exports
        .iter()
        .filter(|export| export.sequence > query.after_sequence)
        .take(query.limit as usize)
        .cloned()
        .collect();
    let next_sequence = selected
        .last()
        .map_or(query.after_sequence, |export| export.sequence);

    Ok(Json(PitekaFeedPage {
        schema_version: FEED_SCHEMA_VERSION,
        exports: selected,
        next_sequence,
    }))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let database_url = required("DATABASE_URL")?;
    let signing_key = load_signing_key(&required("PITEKA_FEED_SIGNING_KEY_FILE")?)?;
    let signing_key_id = required("PITEKA_FEED_SIGNING_KEY_ID")?;
    let tenant_id = required("PITEKA_FEED_TENANT_ID")?;
    let bearer_token = required("PITEKA_FEED_BEARER_TOKEN")?;
    let receipt_ids: Vec<String> = required("PITEKA_FEED_RECEIPTS")?
        .split(',')
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .collect();
    if receipt_ids.is_empty() {
        return Err("PITEKA_FEED_RECEIPTS must list at least one receipt id".into());
    }
    let bind: SocketAddr = env::var("PITEKA_FEED_BIND")
        .unwrap_or_else(|_| "127.0.0.1:3200".to_string())
        .parse()?;

    let pool = piteka_storage::postgres::connect(&database_url).await?;
    piteka_storage::postgres::run_migrations(&pool).await?;
    let receipts = PgReceiptProjectionStore::new(pool.clone());
    let evidence = PgEvidenceNodeStore::new(pool);

    let exports = build_exports(
        receipts,
        evidence,
        &receipt_ids,
        &tenant_id,
        &signing_key_id,
        &signing_key,
    )
    .await?;

    println!(
        "verifying_key_hex={}",
        hex::encode(signing_key.verifying_key().to_bytes())
    );
    println!("signing_key_id={signing_key_id}");
    println!("tenant_id={tenant_id}");
    println!("exports={} media_type={MEDIA_TYPE}", exports.len());
    for export in &exports {
        println!(
            "  sequence={} export_id={} payload_sha256={}",
            export.sequence,
            export.export_id,
            hex::encode(export.payload_sha256)
        );
    }

    let state = FeedState {
        bearer_token: Arc::new(bearer_token),
        exports: Arc::new(exports),
    };
    let app = Router::new()
        .route("/feed", get(serve_feed))
        .route(
            "/health",
            get(|| async { StatusCode::OK }),
        )
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(bind).await?;
    println!("piteka evidence feed listening on http://{bind}/feed");
    axum::serve(listener, app).await?;
    Ok(())
}
