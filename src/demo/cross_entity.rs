//! DEMO-06: portable evidence handoff across an organizational trust boundary.
//!
//! Piteka assembles and transports the package. The receiving organization
//! validates Parwana canonical bytes and invokes Parwana's three-state
//! evaluator locally; no sender-supplied verdict is accepted.

use piteka_parwana::protocol::{
    ACCOUNTABILITY_OBJECT_VERSION, ACCOUNTABILITY_PROTOCOL_VERSION,
    AUTHORITY_RECONSTRUCTION_REGISTRY_ID, AuthorityAuthenticity, AuthorityConclusion,
    AuthorityLink, AuthorityReconstruction, AuthoritySourceCompleteness, DisclosedObject,
    DisputeBundle, EvidenceKind, EvidenceNode, MandateId, SourceLocator, WithheldObject,
    bundle_object_digest, evaluate_authority_reconstruction, validate_evidence_graph,
};
use serde::Serialize;

const EVALUATION_TIME: u64 = 1_800_000_000;
const SCOPE: [u8; 32] = [0x61; 32];

/// Receiver-local result. `Compatible` is historical compatibility, never authorization.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct HandoffTrace {
    pub sender_tenant: &'static str,
    pub receiver_tenant: &'static str,
    pub conclusion: &'static str,
    pub bundle_id: String,
    pub custody_node_id: String,
    pub withheld_branches: usize,
    pub limitation: &'static str,
}

/// Deterministic cross-entity evidence package.
pub struct CrossEntityHandoff {
    bundle: DisputeBundle,
}

impl CrossEntityHandoff {
    /// Build a purpose-limited package from Org A for independent Org B.
    pub fn disclosed() -> Result<Self, &'static str> {
        Self::build(false)
    }

    /// Build a package that commits to, but does not reveal, one authority branch.
    pub fn with_withheld_branch() -> Result<Self, &'static str> {
        Self::build(true)
    }

    fn build(withheld: bool) -> Result<Self, &'static str> {
        let reconstruction = reconstruction(if withheld {
            AuthoritySourceCompleteness::Withheld
        } else {
            AuthoritySourceCompleteness::Complete
        });
        let reconstruction_bytes = reconstruction
            .canonical_bytes()
            .map_err(|_| "canonical reconstruction failed")?;
        let reconstruction_id = reconstruction
            .id()
            .map_err(|_| "reconstruction id failed")?;

        let claim = EvidenceNode {
            kind: EvidenceKind::Claim {
                proposition_digest: *reconstruction_id.as_bytes(),
            },
            producer_identity: b"sub-agent:org-a:payment".to_vec(),
            collected_at: EVALUATION_TIME,
            asserted_event_at: Some(EVALUATION_TIME - 1),
            content_digest: bundle_object_digest(&reconstruction_bytes),
            media_type: "application/vnd.diewan.authority-reconstruction+csv-binary".into(),
            source_locator: SourceLocator::Disclosed("org-a:vault:evidence-42".into()),
            authenticity: None,
            disclosure_classification: "counterparty-shared".into(),
            relationships: vec![],
        };
        let claim_id = claim.id().map_err(|_| "claim id failed")?;
        let custody = EvidenceNode {
            kind: EvidenceKind::CustodyRecord {
                subject_evidence_id: claim_id,
                previous_custody_id: None,
                custodian_identity: b"merchant:org-b".to_vec(),
            },
            producer_identity: b"gateway:org-b".to_vec(),
            collected_at: EVALUATION_TIME + 1,
            asserted_event_at: Some(EVALUATION_TIME + 1),
            content_digest: bundle_object_digest(claim_id.as_bytes()),
            media_type: "application/vnd.diewan.custody-record+csv-binary".into(),
            source_locator: SourceLocator::Disclosed("org-b:vault:handoff-42".into()),
            authenticity: None,
            disclosure_classification: "counterparty-shared".into(),
            relationships: vec![claim_id],
        };
        let custody_id = custody.id().map_err(|_| "custody id failed")?;
        validate_evidence_graph(&[(claim_id, claim.clone()), (custody_id, custody.clone())])
            .map_err(|_| "invalid custody graph")?;

        let mut disclosed_objects = vec![
            disclosed(AUTHORITY_RECONSTRUCTION_REGISTRY_ID, reconstruction_bytes),
            disclosed(
                claim.kind.registry_id(),
                claim
                    .canonical_bytes()
                    .map_err(|_| "claim encoding failed")?,
            ),
            disclosed(
                custody.kind.registry_id(),
                custody
                    .canonical_bytes()
                    .map_err(|_| "custody encoding failed")?,
            ),
        ];
        disclosed_objects.sort_by(|left, right| {
            (&left.registry_id, left.content_digest)
                .cmp(&(&right.registry_id, right.content_digest))
        });
        let withheld_objects = if withheld {
            vec![WithheldObject {
                registry_id: "org.diewan.evidence.delegation-source.v1".into(),
                content_digest: [0x77; 32],
                reason_code: "purpose-limited-third-party-identity".into(),
            }]
        } else {
            vec![]
        };
        let bundle = DisputeBundle {
            protocol_version: ACCOUNTABILITY_PROTOCOL_VERSION,
            bundle_version: ACCOUNTABILITY_OBJECT_VERSION,
            case_id: Some("handoff:org-a:org-b:42".into()),
            subject_intent_id: piteka_parwana::protocol::IntentId::from_digest([0x42; 32]),
            disclosed_objects,
            withheld_objects,
            recommended_context: None,
            producer_identity: b"org-a:evidence-exporter".to_vec(),
            producer_signature: vec![0x55; 64],
        };
        bundle.validate().map_err(|_| "invalid handoff bundle")?;
        Ok(Self { bundle })
    }

    /// Serialize the exact package transported across the boundary.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, &'static str> {
        self.bundle
            .canonical_bytes()
            .map_err(|_| "canonical bundle failed")
    }

    /// Verify using only the received package and the receiver's linked Parwana SDK.
    pub fn verify_at_receiver(&self) -> Result<HandoffTrace, &'static str> {
        self.bundle
            .validate()
            .map_err(|_| "bundle validation failed")?;
        let disclosed = self
            .bundle
            .disclosed_objects
            .iter()
            .find(|object| object.registry_id == AUTHORITY_RECONSTRUCTION_REGISTRY_ID)
            .ok_or("authority evidence absent")?;
        let reconstruction = AuthorityReconstruction::from_canonical_bytes(&disclosed.bytes)
            .map_err(|_| "authority evidence malformed")?;
        let evaluation = evaluate_authority_reconstruction(&reconstruction);
        let conclusion = match evaluation.conclusion {
            AuthorityConclusion::Compatible => "Compatible",
            AuthorityConclusion::Incompatible => "Incompatible",
            AuthorityConclusion::Indeterminate => "Indeterminate",
        };
        let custody = self
            .bundle
            .disclosed_objects
            .iter()
            .find(|object| object.registry_id == "org.diewan.evidence.custody-record.v1")
            .ok_or("custody evidence absent")?;
        let custody_node = EvidenceNode::from_canonical_bytes(&custody.bytes)
            .map_err(|_| "custody evidence malformed")?;
        let custody_id = custody_node.id().map_err(|_| "custody id failed")?;
        Ok(HandoffTrace {
            sender_tenant: "org-a",
            receiver_tenant: "org-b",
            conclusion,
            bundle_id: hex::encode(self.bundle.id().map_err(|_| "bundle id failed")?.as_bytes()),
            custody_node_id: hex::encode(custody_id.as_bytes()),
            withheld_branches: self.bundle.withheld_objects.len(),
            limitation: "Compatible reconstructed authority is not a mandate or authorization.",
        })
    }

    /// Exposes the package for transport tests without granting mutation.
    pub fn bundle(&self) -> &DisputeBundle {
        &self.bundle
    }
}

fn disclosed(registry_id: &str, bytes: Vec<u8>) -> DisclosedObject {
    DisclosedObject {
        registry_id: registry_id.into(),
        media_type: "application/vnd.diewan.canonical+octet-stream".into(),
        content_digest: bundle_object_digest(&bytes),
        bytes,
    }
}

fn reconstruction(completeness: AuthoritySourceCompleteness) -> AuthorityReconstruction {
    let first = MandateId::from_digest([1; 32]);
    let second = MandateId::from_digest([2; 32]);
    AuthorityReconstruction {
        registry_id: AUTHORITY_RECONSTRUCTION_REGISTRY_ID.into(),
        evaluation_time: EVALUATION_TIME,
        source_snapshot_digest: [3; 32],
        snapshot_authenticity: AuthorityAuthenticity::Verified,
        source_completeness: completeness,
        inference_method: "org.diewan.cross-entity-handoff.v1".into(),
        links: vec![
            AuthorityLink {
                mandate_id: first,
                parent_mandate_id: None,
                issuer_identity: b"org:org-a".to_vec(),
                subject_identity: b"agent:org-a".to_vec(),
                authority_domain: b"payment:evidence-handoff".to_vec(),
                effective_from: 1_700_000_000,
                effective_until: 1_900_000_000,
                scope_digest: SCOPE,
                authenticity: AuthorityAuthenticity::Verified,
            },
            AuthorityLink {
                mandate_id: second,
                parent_mandate_id: Some(first),
                issuer_identity: b"agent:org-a".to_vec(),
                subject_identity: b"sub-agent:org-a:payment".to_vec(),
                authority_domain: b"payment:evidence-handoff".to_vec(),
                effective_from: 1_700_000_000,
                effective_until: 1_900_000_000,
                scope_digest: SCOPE,
                authenticity: AuthorityAuthenticity::Verified,
            },
        ],
        contradiction_refs: vec![],
    }
}
