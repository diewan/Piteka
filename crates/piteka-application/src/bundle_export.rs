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

use piteka_storage::TenantScope;
use piteka_storage::digest::ContentDigest;
use piteka_storage::model::{
    EvidenceNodeRecord, EvidenceSource, ProtocolObjectRecord, ReceiptProjection,
    SealConsumptionProofRecord,
};
use piteka_storage::ports::{
    EvidenceNodeStore, EvidenceObjectStore, ProtocolObjectStore, ReceiptProjectionStore,
    SealConsumptionStore,
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
pub async fn assemble_bundle<R, E, Eb, P, SC>(
    tenant: &TenantScope,
    receipt_store: &R,
    evidence_store: &E,
    evidence_blob_store: &Eb,
    protocol_store: &P,
    seal_consumption_store: &SC,
    receipt_id_hex: &str,
) -> Result<BundleExport, BundleExportError>
where
    R: ReceiptProjectionStore,
    E: EvidenceNodeStore,
    Eb: EvidenceObjectStore,
    P: ProtocolObjectStore,
    SC: SealConsumptionStore,
{
    // 1. Fetch the receipt.
    let receipt = receipt_store
        .get(tenant, receipt_id_hex)
        .await?
        .ok_or_else(|| BundleExportError::ReceiptNotFound(receipt_id_hex.to_string()))?;

    // 2. Fetch all evidence nodes.
    let dispatch_nodes =
        fetch_nodes(tenant, evidence_store, &receipt.dispatch_evidence_refs).await?;
    let target_nodes = fetch_nodes(tenant, evidence_store, &receipt.target_evidence_refs).await?;
    let gap_nodes = fetch_nodes(tenant, evidence_store, &receipt.evidence_gaps).await?;

    // 3. Store evidence blobs in the content-addressed store.
    let mut all_evidence_ids = Vec::new();
    let mut evidence_descriptors = Vec::new();

    for node in dispatch_nodes
        .iter()
        .chain(target_nodes.iter())
        .chain(gap_nodes.iter())
    {
        let (blob_digest, size_bytes) =
            store_evidence_blob(tenant, evidence_blob_store, node).await?;
        all_evidence_ids.push(format!("{}:{}", node.node_id_hex, blob_digest.to_hex()));
        evidence_descriptors.push(piteka_storage::model::EvidenceDescriptor {
            digest: blob_digest,
            media_type: "application/vnd.diewan.evidence-node+json".to_string(),
            size_bytes,
        });
    }

    // 4. Assemble the bundle manifest as JSON, including any independent single-use anchor.
    let anchor = seal_consumption_store
        .get(tenant, &receipt.mandate_id_hex)
        .await?;
    let bundle_manifest = assemble_manifest(
        &receipt,
        &dispatch_nodes,
        &target_nodes,
        &gap_nodes,
        anchor.as_ref(),
    )?;

    // 5. Store the canonical bundle bytes.
    let bundle_bytes = serde_json::to_vec(&bundle_manifest).map_err(|e| {
        BundleExportError::Serialization(format!("failed to serialize bundle: {e}"))
    })?;

    let bundle_digest = ContentDigest::of(&bundle_bytes);
    let bundle_id_hex = format!("bundle-{}", bundle_digest.to_hex());

    // Store in protocol objects as the canonical bundle.
    protocol_store
        .put(
            tenant,
            ProtocolObjectRecord {
                kind: "dispute_bundle".to_string(),
                object_id_hex: bundle_id_hex.clone(),
                bytes: bundle_bytes.clone(),
            },
        )
        .await?;

    // 6. Store evidence descriptors.
    for descriptor in evidence_descriptors {
        evidence_blob_store
            .put_descriptor(tenant, descriptor)
            .await?;
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

/// Assembles the portable evidence-export **manifest bytes** for a receipt
/// without storing evidence blobs.
///
/// These bytes are the exact JSON payload that Piteka signs into its evidence
/// feed and that Tuppira's `PitekaEvidenceFeedConnector` deserializes as an
/// `ExportManifest` (`bundle_version` `"0.1"`). Keeping this side-effect free
/// lets the feed producer publish observations from already-captured evidence.
pub async fn export_manifest_bytes<R, E, SC>(
    tenant: &TenantScope,
    receipt_store: &R,
    evidence_store: &E,
    seal_consumption_store: &SC,
    receipt_id_hex: &str,
) -> Result<Vec<u8>, BundleExportError>
where
    R: ReceiptProjectionStore,
    E: EvidenceNodeStore,
    SC: SealConsumptionStore,
{
    let receipt = receipt_store
        .get(tenant, receipt_id_hex)
        .await?
        .ok_or_else(|| BundleExportError::ReceiptNotFound(receipt_id_hex.to_string()))?;

    let dispatch_nodes =
        fetch_nodes(tenant, evidence_store, &receipt.dispatch_evidence_refs).await?;
    let target_nodes = fetch_nodes(tenant, evidence_store, &receipt.target_evidence_refs).await?;
    let gap_nodes = fetch_nodes(tenant, evidence_store, &receipt.evidence_gaps).await?;
    let anchor = seal_consumption_store
        .get(tenant, &receipt.mandate_id_hex)
        .await?;

    let manifest = assemble_manifest(
        &receipt,
        &dispatch_nodes,
        &target_nodes,
        &gap_nodes,
        anchor.as_ref(),
    )?;
    serde_json::to_vec(&manifest)
        .map_err(|e| BundleExportError::Serialization(format!("failed to serialize manifest: {e}")))
}

/// Fetches evidence nodes by their IDs.
async fn fetch_nodes<E: EvidenceNodeStore>(
    tenant: &TenantScope,
    store: &E,
    node_ids: &[String],
) -> Result<Vec<EvidenceNodeRecord>, BundleExportError> {
    let mut nodes = Vec::with_capacity(node_ids.len());
    let mut missing = Vec::new();
    for id in node_ids {
        let node = store.get(tenant, id).await?;
        if let Some(node) = node {
            nodes.push(node);
        } else {
            missing.push(id.clone());
        }
    }
    if missing.is_empty() {
        Ok(nodes)
    } else {
        Err(BundleExportError::IncompleteEvidence {
            required: node_ids.to_vec(),
            missing,
        })
    }
}

/// Stores an evidence node's payload in the content-addressed blob store.
async fn store_evidence_blob<Eb: EvidenceObjectStore>(
    tenant: &TenantScope,
    store: &Eb,
    node: &EvidenceNodeRecord,
) -> Result<(ContentDigest, u64), BundleExportError> {
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

    let size_bytes = payload_bytes.len() as u64;
    let digest = store
        .put(tenant, &payload_bytes)
        .await
        .map_err(BundleExportError::Storage)?;
    Ok((digest, size_bytes))
}

/// Renders a stored seal-consumption proof as the manifest's `single_use_anchor` object.
///
/// The field is present only when the mandate's single use was independently anchored;
/// its absence is a limitation the verifier reports, never a failure (§5.5, §5.9).
fn single_use_anchor_value(anchor: Option<&SealConsumptionProofRecord>) -> serde_json::Value {
    match anchor {
        Some(record) => serde_json::json!({
            "seal_id_hex": record.seal_id_hex,
            "nullifier_hex": record.nullifier_hex,
            "commitment_hex": record.commitment_hex,
            "anchor_backend": record.anchor_backend,
        }),
        None => serde_json::Value::Null,
    }
}

/// Assembles a bundle manifest JSON value.
fn assemble_manifest(
    receipt: &ReceiptProjection,
    dispatch_nodes: &[EvidenceNodeRecord],
    target_nodes: &[EvidenceNodeRecord],
    gap_nodes: &[EvidenceNodeRecord],
    single_use_anchor: Option<&SealConsumptionProofRecord>,
) -> Result<serde_json::Value, BundleExportError> {
    let outcome_str = outcome_as_str(&receipt.outcome);

    Ok(serde_json::json!({
        "single_use_anchor": single_use_anchor_value(single_use_anchor),
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
