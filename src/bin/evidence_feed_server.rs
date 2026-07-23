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
//!   PITEKA_FEED_RECEIPTS          optional comma-separated receipt-id allow-list;
//!                                 when unset the feed publishes every receipt in
//!                                 the store, so new deployments appear live
//!   PITEKA_FEED_BIND              listen address (default 127.0.0.1:3200)

use std::{env, fs, net::SocketAddr, sync::Arc};

use axum::{
    Json, Router,
    extract::{Query, State},
    http::{HeaderMap, StatusCode, header},
    routing::get,
};
use ed25519_dalek::{Signer, SigningKey};
use piteka_application::bundle_export::export_manifest_bytes;
use piteka_storage::ReceiptProjectionStore;
use piteka_storage::postgres::{
    PgEvidenceNodeStore, PgReceiptProjectionStore, PgSealConsumptionStore,
};
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

/// Shared feed state. Exports are rebuilt from the live store on every pull so
/// receipts produced after startup appear without restarting the server.
#[derive(Clone)]
struct FeedState {
    tenant: piteka_storage::TenantScope,
    bearer_token: Arc<String>,
    receipts: PgReceiptProjectionStore,
    evidence: PgEvidenceNodeStore,
    seals: PgSealConsumptionStore,
    signing_key: Arc<SigningKey>,
    signing_key_id: Arc<String>,
    tenant_id: Arc<String>,
    /// Optional receipt-id allow-list (from `PITEKA_FEED_RECEIPTS`). When `None`
    /// the feed publishes every receipt currently in the store.
    allow_list: Option<Arc<Vec<String>>>,
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

/// Builds the signed exports for the given receipts, in feed order.
///
/// `receipts` is a list of `(receipt_id, created_at)` pairs, oldest-first.
/// Sequence numbers follow that order (stable as new receipts append at the
/// end), and each export's emission clock is derived from the receipt's own
/// immutable `created_at` — bumped to stay *strictly* increasing — so the
/// consumer's per-observation sync cursor advances monotonically and the same
/// receipt keeps the same `emitted_at` across pulls.
async fn build_exports(
    tenant: &piteka_storage::TenantScope,
    receipts: &PgReceiptProjectionStore,
    evidence: &PgEvidenceNodeStore,
    seals: &PgSealConsumptionStore,
    ordered_receipts: &[(String, i64)],
    tenant_id: &str,
    signing_key_id: &str,
    key: &SigningKey,
) -> Result<Vec<SignedPitekaExport>, String> {
    let mut exports = Vec::with_capacity(ordered_receipts.len());
    let mut last_emitted: u64 = 0;
    for (receipt_id, created_at) in ordered_receipts.iter() {
        // A receipt that cannot be assembled into a bundle (e.g. incomplete
        // evidence) is skipped, not fatal: one bad receipt must not take the
        // whole feed offline. Skipping is deterministic, so sequence numbers
        // over the successful receipts stay stable across pulls.
        let payload =
            match export_manifest_bytes(tenant, receipts, evidence, seals, receipt_id).await {
                Ok(payload) => payload,
                Err(error) => {
                    eprintln!("feed: skipping receipt {receipt_id}: {error}");
                    continue;
                }
            };
        let payload_sha256: [u8; 32] = Sha256::digest(&payload).into();
        let emitted_at = (*created_at).max(0) as u64;
        let emitted_at = emitted_at.max(last_emitted + 1);
        last_emitted = emitted_at;
        let mut export = SignedPitekaExport {
            schema_version: FEED_SCHEMA_VERSION,
            sequence: (exports.len() as u64) + 1,
            export_id: receipt_id.clone(),
            revision: 1,
            supersedes_export_id: None,
            tenant_id: tenant_id.to_string(),
            emitted_at,
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

/// Resolves the receipts to publish, oldest-first, as `(id, created_at)` pairs.
/// Uses the allow-list when configured, otherwise every receipt in the store.
async fn current_receipts(state: &FeedState) -> Result<Vec<(String, i64)>, String> {
    match &state.allow_list {
        Some(ids) => {
            let mut pairs = Vec::with_capacity(ids.len());
            for id in ids.iter() {
                let receipt = state
                    .receipts
                    .get(&state.tenant, id)
                    .await
                    .map_err(|e| format!("cannot load receipt {id}: {e}"))?
                    .ok_or_else(|| format!("receipt {id} not found"))?;
                pairs.push((id.clone(), receipt.created_at_unix_seconds));
            }
            // Keep the deterministic oldest-first order the exports rely on.
            pairs.sort_by(|a, b| a.1.cmp(&b.1).then_with(|| a.0.cmp(&b.0)));
            Ok(pairs)
        }
        None => state
            .receipts
            .list_ids_ordered(&state.tenant)
            .await
            .map_err(|e| format!("cannot list receipts: {e}")),
    }
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

    // Rebuild the feed from the live store on each pull so receipts produced
    // after startup are published without a restart.
    let ordered = current_receipts(&state).await.map_err(|error| {
        eprintln!("feed: {error}");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    let exports = build_exports(
        &state.tenant,
        &state.receipts,
        &state.evidence,
        &state.seals,
        &ordered,
        &state.tenant_id,
        &state.signing_key_id,
        &state.signing_key,
    )
    .await
    .map_err(|error| {
        eprintln!("feed: {error}");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let selected: Vec<SignedPitekaExport> = exports
        .into_iter()
        .filter(|export| export.sequence > query.after_sequence)
        .take(query.limit as usize)
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
    let tenant = piteka_storage::TenantScope::new(&tenant_id)?;
    let bearer_token = required("PITEKA_FEED_BEARER_TOKEN")?;
    // Optional allow-list. When unset, the feed publishes every receipt in the
    // store so new deployments appear live.
    let allow_list: Option<Arc<Vec<String>>> = env::var("PITEKA_FEED_RECEIPTS")
        .ok()
        .map(|raw| {
            raw.split(',')
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty())
                .collect::<Vec<_>>()
        })
        .filter(|ids| !ids.is_empty())
        .map(Arc::new);
    let bind: SocketAddr = env::var("PITEKA_FEED_BIND")
        .unwrap_or_else(|_| "127.0.0.1:3200".to_string())
        .parse()?;

    let pool = piteka_storage::postgres::connect(&database_url).await?;
    piteka_storage::postgres::run_migrations(&pool).await?;
    let receipts = PgReceiptProjectionStore::new(pool.clone());
    let evidence = PgEvidenceNodeStore::new(pool.clone());
    let seals = PgSealConsumptionStore::new(pool);

    println!(
        "verifying_key_hex={}",
        hex::encode(signing_key.verifying_key().to_bytes())
    );
    println!("signing_key_id={signing_key_id}");
    println!("tenant_id={tenant_id}");
    println!("media_type={MEDIA_TYPE}");
    match &allow_list {
        Some(ids) => println!("receipt allow-list: {} id(s)", ids.len()),
        None => println!("publishing all receipts in the store (live)"),
    }

    let state = FeedState {
        tenant,
        bearer_token: Arc::new(bearer_token),
        receipts,
        evidence,
        seals,
        signing_key: Arc::new(signing_key),
        signing_key_id: Arc::new(signing_key_id),
        tenant_id: Arc::new(tenant_id),
        allow_list,
    };
    let app = Router::new()
        .route("/feed", get(serve_feed))
        .route("/health", get(|| async { StatusCode::OK }))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(bind).await?;
    println!("piteka evidence feed listening on http://{bind}/feed");
    axum::serve(listener, app).await?;
    Ok(())
}
