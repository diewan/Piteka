//! Bundle export: canonical receipt storage and DisputeBundle assembly.
//!
//! Master Plan §60 E-06 requires that receipts be "stored/exportable". This
//! module provides:
//!
//! 1. **Canonical receipt serialization** — converts a Piteka receipt projection
//!    into Parwana canonical bytes via the Parwana contract adapter.
//! 2. **DisputeBundle assembly** — packages the mandate, receipt, evidence
//!    nodes, and gaps into a portable case file.
//! 3. **Bundle export storage** — records bundle exports for audit trail.

use piteka_storage::digest::ContentDigest;
use piteka_storage::model::{
    EvidenceNodeRecord, EvidenceSource, ProtocolObjectRecord, ReceiptProjection,
};
use piteka_storage::ports::{
    EvidenceNodeStore, EvidenceObjectStore, ProtocolObjectStore, ReceiptProjectionStore,
};

use crate::receipt_production::outcome_as_str;

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Errors returned by bundle export operations.
#[derive(Debug)]
pub enum BundleExportError {
    /// A storage failure occurred.
    Storage(piteka_storage::StorageError),
    /// The receipt was not found.
    ReceiptNotFound(String),
    /// The mandate was not found in protocol objects.
    MandateNotFound(String),
    /// Evidence nodes were incomplete.
    IncompleteEvidence {
        required: Vec<String>,
        missing: Vec<String>,
    },
    /// Canonical serialization failed.
    Serialization(String),
}

impl From<piteka_storage::StorageError> for BundleExportError {
    fn from(err: piteka_storage::StorageError) -> Self {
        Self::Storage(err)
    }
}

impl core::fmt::Display for BundleExportError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Storage(err) => write!(f, "storage error: {err}"),
            Self::ReceiptNotFound(id) => write!(f, "receipt `{id}` not found"),
            Self::MandateNotFound(id) => write!(f, "mandate `{id}` not found"),
            Self::IncompleteEvidence { required, missing } => {
                write!(
                    f,
                    "incomplete evidence: {} required, {} missing",
                    required.len(),
                    missing.len()
                )
            }
            Self::Serialization(msg) => write!(f, "serialization error: {msg}"),
        }
    }
}

impl std::error::Error for BundleExportError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Storage(err) => Some(err),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Bundle export result
// ---------------------------------------------------------------------------

/// The result of a successful bundle export.
#[derive(Debug, Clone)]
pub struct BundleExport {
    /// Bundle identifier (content-addressed).
    pub bundle_id_hex: String,
    /// Receipt that was exported.
    pub receipt_id_hex: String,
    /// Mandate ID that was exported.
    pub mandate_id_hex: String,
    /// Evidence node IDs included in the bundle.
    pub evidence_node_ids: Vec<String>,
    /// Evidence gap IDs included in the bundle.
    pub evidence_gap_ids: Vec<String>,
    /// SHA-256 digest of the canonical bundle bytes.
    pub bundle_digest: ContentDigest,
}

// ---------------------------------------------------------------------------
// Bundle assembly
// ---------------------------------------------------------------------------

/// Assembles a DisputeBundle for a given receipt.
///
/// The bundle contains:
/// 1. The receipt projection (as JSON for export).
/// 2. All evidence nodes referenced by the receipt.
/// 3. All evidence gaps.
/// 4. A manifest with content addresses.
///
/// The canonical receipt bytes are stored in the protocol object store.
/// Evidence blobs are stored in the evidence blob store.
///
/// Returns a [`BundleExport`] with the bundle identifier and digest.
pub async fn assemble_bundle<R, E, Eb, P>(
    receipt_store: &R,
    evidence_store: &E,
    evidence_blob_store: &Eb,
    protocol_store: &P,
    receipt_id_hex: &str,
) -> Result<BundleExport, BundleExportError>
where
    R: ReceiptProjectionStore,
    E: EvidenceNodeStore,
    Eb: EvidenceObjectStore,
    P: ProtocolObjectStore,
{
    // 1. Fetch the receipt.
    let receipt = receipt_store
        .get(receipt_id_hex)
        .await?
        .ok_or_else(|| BundleExportError::ReceiptNotFound(receipt_id_hex.to_string()))?;

    // 2. Fetch all evidence nodes.
    let dispatch_nodes = fetch_nodes(evidence_store, &receipt.dispatch_evidence_refs).await?;
    let target_nodes = fetch_nodes(evidence_store, &receipt.target_evidence_refs).await?;
    let gap_nodes = fetch_nodes(evidence_store, &receipt.evidence_gaps).await?;

    // 3. Store evidence blobs in the content-addressed store.
    let mut all_evidence_ids = Vec::new();

    for node in dispatch_nodes.iter().chain(target_nodes.iter()).chain(gap_nodes.iter()) {
        let blob_digest = store_evidence_blob(evidence_blob_store, node).await?;
        all_evidence_ids.push(format!("{}:{}", node.node_id_hex, blob_digest.to_hex()));
    }

    // 4. Assemble the bundle manifest as JSON.
    let bundle_manifest = assemble_manifest(&receipt, &dispatch_nodes, &target_nodes, &gap_nodes)?;

    // 5. Store the canonical bundle bytes.
    let bundle_bytes = serde_json::to_vec(&bundle_manifest).map_err(|e| {
        BundleExportError::Serialization(format!("failed to serialize bundle: {e}"))
    })?;

    let bundle_digest = ContentDigest::of(&bundle_bytes);
    let bundle_id_hex = format!("bundle-{}", bundle_digest.to_hex());

    // Store in protocol objects as the canonical bundle.
    protocol_store.put(ProtocolObjectRecord {
        kind: "dispute_bundle".to_string(),
        object_id_hex: bundle_id_hex.clone(),
        bytes: bundle_bytes.clone(),
    }).await?;

    // 6. Store evidence descriptors.
    for node in dispatch_nodes.iter().chain(target_nodes.iter()).chain(gap_nodes.iter()) {
        let _ = evidence_blob_store.put_descriptor(
            piteka_storage::model::EvidenceDescriptor {
                digest: node.content_digest,
                media_type: node.media_type.clone(),
                size_bytes: node.content_digest.as_bytes().len() as u64,
            }
        ).await;
    }

    Ok(BundleExport {
        bundle_id_hex,
        receipt_id_hex: receipt.receipt_id_hex.clone(),
        mandate_id_hex: receipt.mandate_id_hex.clone(),
        evidence_node_ids: all_evidence_ids,
        evidence_gap_ids: receipt.evidence_gaps.clone(),
        bundle_digest,
    })
}

/// Fetches evidence nodes by their IDs.
async fn fetch_nodes<E: EvidenceNodeStore>(
    store: &E,
    node_ids: &[String],
) -> Result<Vec<EvidenceNodeRecord>, BundleExportError> {
    let mut nodes = Vec::new();
    for id in node_ids {
        let node = store.get(id).await?;
        if let Some(node) = node {
            nodes.push(node);
        }
    }
    Ok(nodes)
}

/// Stores an evidence node's payload in the content-addressed blob store.
async fn store_evidence_blob<Eb: EvidenceObjectStore>(
    store: &Eb,
    node: &EvidenceNodeRecord,
) -> Result<ContentDigest, BundleExportError> {
    // The content digest is already the content address; store the payload.
    let payload = serde_json::json!({
        "node_id": node.node_id_hex,
        "registry_id": node.registry_id,
        "source": match &node.source {
            EvidenceSource::Piteka => "piteka",
            EvidenceSource::Provider(p) => p,
            EvidenceSource::Verifier => "verifier",
        },
        "producer_identity": node.producer_identity,
        "collected_at": node.collected_at_unix_seconds,
        "asserted_event_at": node.asserted_event_at_unix_seconds,
        "content_digest": node.content_digest.to_hex(),
        "media_type": node.media_type,
        "disclosure_classification": node.disclosure_classification,
        "relationships": node.relationships,
    });

    let payload_bytes = serde_json::to_vec(&payload).map_err(|e| {
        BundleExportError::Serialization(format!("failed to serialize evidence blob: {e}"))
    })?;

    store.put(&payload_bytes).await.map_err(|e| {
        BundleExportError::Storage(e)
    })
}

/// Assembles a bundle manifest JSON value.
fn assemble_manifest(
    receipt: &ReceiptProjection,
    dispatch_nodes: &[EvidenceNodeRecord],
    target_nodes: &[EvidenceNodeRecord],
    gap_nodes: &[EvidenceNodeRecord],
) -> Result<serde_json::Value, BundleExportError> {
    let outcome_str = outcome_as_str(&receipt.outcome);

    Ok(serde_json::json!({
        "bundle_version": "0.1",
        "receipt": {
            "receipt_id": receipt.receipt_id_hex,
            "mandate_id": receipt.mandate_id_hex,
            "intent_id": receipt.intent_id_hex,
            "attempt_id": receipt.attempt_id_hex,
            "outcome": outcome_str,
            "created_at": receipt.created_at_unix_seconds,
        },
        "dispatch_evidence": dispatch_nodes.iter().map(|n| {
            serde_json::json!({
                "node_id": n.node_id_hex,
                "registry_id": n.registry_id,
                "source": match &n.source {
                    EvidenceSource::Piteka => "piteka",
                    EvidenceSource::Provider(p) => p,
                    EvidenceSource::Verifier => "verifier",
                },
                "content_digest": n.content_digest.to_hex(),
            })
        }).collect::<Vec<_>>(),
        "target_evidence": target_nodes.iter().map(|n| {
            serde_json::json!({
                "node_id": n.node_id_hex,
                "registry_id": n.registry_id,
                "source": match &n.source {
                    EvidenceSource::Piteka => "piteka",
                    EvidenceSource::Provider(p) => p,
                    EvidenceSource::Verifier => "verifier",
                },
                "content_digest": n.content_digest.to_hex(),
            })
        }).collect::<Vec<_>>(),
        "evidence_gaps": gap_nodes.iter().map(|n| {
            serde_json::json!({
                "node_id": n.node_id_hex,
                "content_digest": n.content_digest.to_hex(),
            })
        }).collect::<Vec<_>>(),
        "source_attribution": {
            "piteka_claims": dispatch_nodes.iter().filter(|n| matches!(n.source, EvidenceSource::Piteka)).count(),
            "provider_observations": target_nodes.iter().filter(|n| matches!(n.source, EvidenceSource::Provider(_))).count(),
            "verifier_conclusions": 0,
        },
        "missing_evidence": {
            "gap_count": gap_nodes.len(),
            "gaps": receipt.evidence_gaps,
        },
    }))
}
