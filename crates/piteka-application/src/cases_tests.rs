use crate::{
    CaseUseCase, CaseUseCaseError, Clock, SessionAuthority, SessionSigner, Signature,
    SignatureAlgorithm,
};
use piteka_domain::{ConfiguredOrganization, SessionId, UserId};
use piteka_storage::{EvidenceObjectStore, InMemoryEvidenceStore, InMemoryInvestigatorCaseStore};
use std::sync::Arc;

struct Signer;
impl SessionSigner for Signer {
    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::DemoLocalV1
    }
    fn sign(&self, message: &[u8]) -> Signature {
        Signature::new(self.algorithm(), vec![message.iter().fold(0, |a, b| a ^ b)])
    }
    fn verify(&self, message: &[u8], signature: &Signature) -> bool {
        self.sign(message) == *signature
    }
}
#[derive(Clone, Copy)]
struct FixedClock;
impl Clock for FixedClock {
    fn unix_seconds(&self) -> u64 {
        42
    }
}

fn session(user: &str) -> crate::AuthenticatedSession {
    let authority = SessionAuthority::new(Signer, FixedClock, ConfiguredOrganization::demo());
    let signed = authority
        .issue(
            &UserId::new(user).unwrap(),
            SessionId::from_bytes([7; 16]),
            60,
        )
        .unwrap();
    authority.authenticate(&signed).unwrap()
}

#[tokio::test]
async fn investigator_case_is_tenant_scoped_append_only_and_conflict_safe() {
    let cases = Arc::new(InMemoryInvestigatorCaseStore::default());
    let evidence = Arc::new(InMemoryEvidenceStore::default());
    let digest = evidence.put(b"immutable evidence").await.unwrap();
    let use_case = CaseUseCase::new(cases, evidence, FixedClock);
    let auditor = session("auditor");

    use_case
        .open(&auditor, "case-1", "Suspicious deployment")
        .await
        .unwrap();
    assert_eq!(
        use_case
            .attach_evidence(
                &auditor,
                "case-1",
                0,
                "event-1",
                &digest.to_hex(),
                "provider log"
            )
            .await
            .unwrap(),
        1
    );
    assert!(matches!(
        use_case
            .record_finding(
                &auditor,
                "case-1",
                0,
                "event-2",
                &digest.to_hex(),
                "mismatch"
            )
            .await,
        Err(CaseUseCaseError::Conflict { current_version: 1 })
    ));
    assert_eq!(
        use_case
            .record_finding(
                &auditor,
                "case-1",
                1,
                "event-2",
                &digest.to_hex(),
                "mismatch"
            )
            .await
            .unwrap(),
        2
    );
    let history = use_case.history(&auditor, "case-1").await.unwrap();
    assert_eq!(history.len(), 2);
    assert_eq!(history[0].detail, "provider log");
}

#[tokio::test]
async fn privilege_escalation_and_missing_evidence_fail_closed() {
    let cases = Arc::new(InMemoryInvestigatorCaseStore::default());
    let evidence = Arc::new(InMemoryEvidenceStore::default());
    let use_case = CaseUseCase::new(cases, evidence, FixedClock);
    assert!(matches!(
        use_case.open(&session("requester"), "case-1", "x").await,
        Err(CaseUseCaseError::Unauthorized)
    ));
    let auditor = session("auditor");
    use_case.open(&auditor, "case-1", "x").await.unwrap();
    assert!(matches!(
        use_case
            .attach_evidence(
                &auditor,
                "case-1",
                0,
                "event-1",
                &piteka_storage::ContentDigest::of(b"missing").to_hex(),
                "x"
            )
            .await,
        Err(CaseUseCaseError::MissingEvidence)
    ));
    assert!(
        use_case
            .history(&auditor, "case-1")
            .await
            .unwrap()
            .is_empty()
    );
}
