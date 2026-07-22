//! DEMO-04: deterministic delegated-authority scenario.
//!
//! Authority meaning remains entirely in Parwana. This module only assembles
//! disclosed scenario evidence, invokes the pinned verifier, and exports the
//! canonical reconstruction bytes for offline verification and Hemion tracing.

use piteka_parwana::protocol::{
    AUTHORITY_RECONSTRUCTION_REGISTRY_ID, AuthorityAuthenticity, AuthorityConclusion,
    AuthorityLink, AuthorityReason, AuthorityReconstruction, AuthoritySourceCompleteness,
    MandateId, evaluate_authority_reconstruction,
};
use serde::Serialize;
use std::sync::Arc;

use piteka_application::{
    CaseUseCase, Clock, SessionAuthority, SessionSigner, Signature, SignatureAlgorithm,
};
use piteka_domain::{ConfiguredOrganization, SessionId, UserId};
use piteka_storage::{EvidenceObjectStore, InMemoryEvidenceStore, InMemoryInvestigatorCaseStore};

const EVALUATION_TIME: u64 = 1_800_000_000;
const SCOPE: [u8; 32] = [0x5a; 32];

/// Machine-readable result exported by the runnable scenario.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DelegationTrace {
    pub scenario: &'static str,
    pub conclusion: &'static str,
    pub reason_code: &'static str,
    pub reconstruction_id: String,
    pub canonical_evidence_hex: String,
    pub identities: [&'static str; 4],
    pub hemion_route: String,
    pub limitation: &'static str,
}

/// Append-only investigator-case projection created from exported evidence.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DelegationCaseTrace {
    pub case_id: &'static str,
    pub tenant_id: String,
    pub version: i64,
    pub evidence_digest: String,
    pub event_kinds: Vec<String>,
}

/// A one-shot runner: a valid delegated action may be consumed once.
#[derive(Default)]
pub struct DelegatedAuthorityDemo {
    consumed: bool,
}

impl DelegatedAuthorityDemo {
    /// Evaluate and consume the valid org → team → agent → sub-agent chain.
    pub fn execute_valid_once(&mut self) -> Result<DelegationTrace, &'static str> {
        if self.consumed {
            return Err("delegated mandate already consumed");
        }
        let trace = trace(
            "valid",
            reconstruction(AuthoritySourceCompleteness::Complete, false),
        )?;
        if trace.conclusion != "Compatible" {
            return Err("valid delegation did not verify as compatible");
        }
        self.consumed = true;
        Ok(trace)
    }

    /// Evaluate a child whose scope differs from its parent.
    pub fn overreach(&self) -> Result<DelegationTrace, &'static str> {
        trace(
            "overreach",
            reconstruction(AuthoritySourceCompleteness::Complete, true),
        )
    }

    /// Evaluate the same chain with a deliberately withheld source link.
    pub fn withheld_link(&self) -> Result<DelegationTrace, &'static str> {
        trace(
            "withheld-link",
            reconstruction(AuthoritySourceCompleteness::Withheld, false),
        )
    }

    /// Store canonical evidence and exercise Piteka's append-only case use case.
    pub async fn investigate(
        &self,
        trace: &DelegationTrace,
    ) -> Result<DelegationCaseTrace, String> {
        let evidence = Arc::new(InMemoryEvidenceStore::default());
        let cases = Arc::new(InMemoryInvestigatorCaseStore::default());
        let bytes =
            hex::decode(&trace.canonical_evidence_hex).map_err(|error| error.to_string())?;
        let digest = evidence
            .put(&bytes)
            .await
            .map_err(|error| error.to_string())?;
        let use_case = CaseUseCase::new(cases, evidence, DemoClock);
        let session = auditor_session()?;
        let case_id = "case-delegation-overreach";
        let opened = use_case
            .open(&session, case_id, "Delegated authority review")
            .await
            .map_err(|error| error.to_string())?;
        let version = use_case
            .attach_evidence(
                &session,
                case_id,
                0,
                "event-delegation-evidence",
                &digest.to_hex(),
                "Canonical Parwana authority reconstruction",
            )
            .await
            .map_err(|error| error.to_string())?;
        let version = use_case
            .record_finding(
                &session,
                case_id,
                version,
                "event-delegation-finding",
                &digest.to_hex(),
                trace.reason_code,
            )
            .await
            .map_err(|error| error.to_string())?;
        let history = use_case
            .history(&session, case_id)
            .await
            .map_err(|error| error.to_string())?;
        Ok(DelegationCaseTrace {
            case_id,
            tenant_id: opened.tenant_id,
            version,
            evidence_digest: digest.to_hex(),
            event_kinds: history.into_iter().map(|event| event.kind).collect(),
        })
    }
}

struct DemoSigner;

impl SessionSigner for DemoSigner {
    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::DemoLocalV1
    }

    fn sign(&self, message: &[u8]) -> Signature {
        Signature::new(
            self.algorithm(),
            vec![
                message
                    .iter()
                    .fold(0_u8, |accumulator, byte| accumulator ^ byte),
            ],
        )
    }

    fn verify(&self, message: &[u8], signature: &Signature) -> bool {
        self.sign(message) == *signature
    }
}

#[derive(Clone, Copy)]
struct DemoClock;

impl Clock for DemoClock {
    fn unix_seconds(&self) -> u64 {
        EVALUATION_TIME
    }
}

fn auditor_session() -> Result<piteka_application::AuthenticatedSession, String> {
    let authority = SessionAuthority::new(DemoSigner, DemoClock, ConfiguredOrganization::demo());
    let signed = authority
        .issue(
            &UserId::new("auditor").map_err(|error| error.to_string())?,
            SessionId::from_bytes([0x44; 16]),
            300,
        )
        .map_err(|error| error.to_string())?;
    authority
        .authenticate(&signed)
        .map_err(|error| error.to_string())
}

fn reconstruction(
    completeness: AuthoritySourceCompleteness,
    overreach: bool,
) -> AuthorityReconstruction {
    let ids = [
        MandateId::from_digest([1; 32]),
        MandateId::from_digest([2; 32]),
        MandateId::from_digest([3; 32]),
    ];
    let identities: [&[u8]; 4] = [
        b"org:diewan",
        b"team:platform",
        b"agent:deploy",
        b"sub-agent:runner",
    ];
    let mut links = Vec::new();
    for index in 0..3 {
        links.push(AuthorityLink {
            mandate_id: ids[index],
            parent_mandate_id: index.checked_sub(1).map(|parent| ids[parent]),
            issuer_identity: identities[index].to_vec(),
            subject_identity: identities[index + 1].to_vec(),
            authority_domain: b"deployment:production".to_vec(),
            effective_from: 1_700_000_000,
            effective_until: 1_900_000_000,
            scope_digest: if overreach && index == 2 {
                [0xa5; 32]
            } else {
                SCOPE
            },
            authenticity: AuthorityAuthenticity::Verified,
        });
    }
    AuthorityReconstruction {
        registry_id: AUTHORITY_RECONSTRUCTION_REGISTRY_ID.into(),
        evaluation_time: EVALUATION_TIME,
        source_snapshot_digest: [0x33; 32],
        snapshot_authenticity: AuthorityAuthenticity::Verified,
        source_completeness: completeness,
        inference_method: "org.diewan.delegation-chain.v1".into(),
        links,
        contradiction_refs: Vec::new(),
    }
}

fn trace(
    scenario: &'static str,
    value: AuthorityReconstruction,
) -> Result<DelegationTrace, &'static str> {
    let evaluation = evaluate_authority_reconstruction(&value);
    let conclusion = match evaluation.conclusion {
        AuthorityConclusion::Compatible => "Compatible",
        AuthorityConclusion::Incompatible => "Incompatible",
        AuthorityConclusion::Indeterminate => "Indeterminate",
    };
    let bytes = value
        .canonical_bytes()
        .map_err(|_| "canonical reconstruction failed")?;
    let id = value.id().map_err(|_| "reconstruction id failed")?;
    Ok(DelegationTrace {
        scenario,
        conclusion,
        reason_code: AuthorityReason::registry_id(evaluation.reason),
        reconstruction_id: hex::encode(id.as_bytes()),
        canonical_evidence_hex: hex::encode(bytes),
        identities: [
            "org:diewan",
            "team:platform",
            "agent:deploy",
            "sub-agent:runner",
        ],
        hemion_route: format!("/responsibility/{}", hex::encode(id.as_bytes())),
        limitation: "Compatible historical evidence is not an authorization or a mandate.",
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_chain_succeeds_once_and_exports_canonical_evidence() {
        let mut demo = DelegatedAuthorityDemo::default();
        let trace = demo.execute_valid_once().unwrap();
        assert_eq!(trace.conclusion, "Compatible");
        assert!(!trace.canonical_evidence_hex.is_empty());
        assert_eq!(
            demo.execute_valid_once(),
            Err("delegated mandate already consumed")
        );
    }

    #[test]
    fn overreach_fails_closed_at_the_parwana_verifier() {
        let trace = DelegatedAuthorityDemo::default().overreach().unwrap();
        assert_eq!(trace.conclusion, "Incompatible");
        assert_eq!(
            trace.reason_code,
            "ACCOUNTABILITY.AUTHORITY_RECONSTRUCTION.DELEGATION_MISMATCH"
        );
    }

    #[test]
    fn withheld_link_is_indeterminate_never_authorized() {
        let trace = DelegatedAuthorityDemo::default().withheld_link().unwrap();
        assert_eq!(trace.conclusion, "Indeterminate");
        assert_eq!(
            trace.reason_code,
            "ACCOUNTABILITY.AUTHORITY_RECONSTRUCTION.SOURCE_INCOMPLETE"
        );
        assert!(
            !serde_json::to_string(&trace)
                .unwrap()
                .contains("Authorized")
        );
    }

    #[tokio::test]
    async fn overreach_opens_append_only_case_bound_to_canonical_evidence() {
        let demo = DelegatedAuthorityDemo::default();
        let trace = demo.overreach().unwrap();
        let case = demo.investigate(&trace).await.unwrap();
        assert_eq!(case.version, 2);
        assert_eq!(case.event_kinds, ["evidence_attached", "finding_recorded"]);
        assert_eq!(case.evidence_digest.len(), 64);
        assert!(trace.hemion_route.starts_with("/responsibility/"));
    }
}
