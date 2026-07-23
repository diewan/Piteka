//! Tenant-scoped, append-only investigator case use case.

use crate::{AuthenticatedSession, Clock};
use piteka_domain::Capability;
use piteka_storage::{
    CaseAppendOutcome, CaseEvent, ContentDigest, EvidenceObjectStore, InvestigatorCase,
    InvestigatorCaseStore, StorageError, TenantScope,
};
use thiserror::Error;

pub const EVIDENCE_ATTACHED: &str = "evidence_attached";
pub const FINDING_RECORDED: &str = "finding_recorded";

#[derive(Debug, Error)]
pub enum CaseUseCaseError {
    #[error("authenticated role cannot manage investigator cases")]
    Unauthorized,
    #[error("field `{0}` must not be empty")]
    EmptyField(&'static str),
    #[error("evidence digest is not canonical lower-case SHA-256 hex")]
    InvalidEvidenceDigest,
    #[error("referenced evidence object is missing")]
    MissingEvidence,
    #[error("investigator case does not exist")]
    MissingCase,
    #[error("case version conflict; current version is {current_version}")]
    Conflict { current_version: i64 },
    #[error("case storage failed: {0}")]
    Storage(#[from] StorageError),
}

pub struct CaseUseCase<S, E, C> {
    cases: S,
    evidence: E,
    clock: C,
}

impl<S: InvestigatorCaseStore, E: EvidenceObjectStore, C: Clock> CaseUseCase<S, E, C> {
    pub const fn new(cases: S, evidence: E, clock: C) -> Self {
        Self {
            cases,
            evidence,
            clock,
        }
    }

    pub async fn open(
        &self,
        session: &AuthenticatedSession,
        case_id: &str,
        title: &str,
    ) -> Result<InvestigatorCase, CaseUseCaseError> {
        authorize(session)?;
        nonempty("case_id", case_id)?;
        nonempty("title", title)?;
        let case = InvestigatorCase {
            tenant_id: session.identity().organization().as_str().into(),
            case_id: case_id.into(),
            version: 0,
            title: title.into(),
            opened_by: session.identity().user_id().as_str().into(),
            created_at_unix_seconds: now(&self.clock),
        };
        let tenant = tenant_scope(session)?;
        self.cases.create(&tenant, case.clone()).await?;
        Ok(case)
    }

    pub async fn list(
        &self,
        session: &AuthenticatedSession,
    ) -> Result<Vec<InvestigatorCase>, CaseUseCaseError> {
        authorize(session)?;
        Ok(self.cases.list(&tenant_scope(session)?).await?)
    }

    pub async fn history(
        &self,
        session: &AuthenticatedSession,
        case_id: &str,
    ) -> Result<Vec<CaseEvent>, CaseUseCaseError> {
        authorize(session)?;
        nonempty("case_id", case_id)?;
        let tenant = tenant_scope(session)?;
        if self.cases.get(&tenant, case_id).await?.is_none() {
            return Err(CaseUseCaseError::MissingCase);
        }
        Ok(self.cases.history(&tenant, case_id).await?)
    }

    pub async fn attach_evidence(
        &self,
        session: &AuthenticatedSession,
        case_id: &str,
        expected_version: i64,
        event_id: &str,
        evidence_digest_hex: &str,
        detail: &str,
    ) -> Result<i64, CaseUseCaseError> {
        self.append_evidence_event(
            session,
            case_id,
            expected_version,
            event_id,
            evidence_digest_hex,
            detail,
            EVIDENCE_ATTACHED,
        )
        .await
    }

    pub async fn record_finding(
        &self,
        session: &AuthenticatedSession,
        case_id: &str,
        expected_version: i64,
        event_id: &str,
        evidence_digest_hex: &str,
        finding: &str,
    ) -> Result<i64, CaseUseCaseError> {
        self.append_evidence_event(
            session,
            case_id,
            expected_version,
            event_id,
            evidence_digest_hex,
            finding,
            FINDING_RECORDED,
        )
        .await
    }

    async fn append_evidence_event(
        &self,
        session: &AuthenticatedSession,
        case_id: &str,
        expected_version: i64,
        event_id: &str,
        digest_hex: &str,
        detail: &str,
        kind: &str,
    ) -> Result<i64, CaseUseCaseError> {
        authorize(session)?;
        nonempty("case_id", case_id)?;
        nonempty("event_id", event_id)?;
        nonempty("detail", detail)?;
        let digest =
            ContentDigest::from_hex(digest_hex).ok_or(CaseUseCaseError::InvalidEvidenceDigest)?;
        let tenant = tenant_scope(session)?;
        if self.evidence.get(&tenant, &digest).await?.is_none() {
            return Err(CaseUseCaseError::MissingEvidence);
        }
        let event = CaseEvent {
            event_id: event_id.into(),
            tenant_id: tenant.as_str().into(),
            case_id: case_id.into(),
            sequence: 0,
            actor: session.identity().user_id().as_str().into(),
            kind: kind.into(),
            detail: detail.into(),
            evidence_digest_hex: Some(digest_hex.into()),
            occurred_at_unix_seconds: now(&self.clock),
        };
        match self
            .cases
            .append(&tenant, case_id, expected_version, event)
            .await?
        {
            CaseAppendOutcome::Applied { new_version } => Ok(new_version),
            CaseAppendOutcome::Conflict { current_version } => {
                Err(CaseUseCaseError::Conflict { current_version })
            }
            CaseAppendOutcome::Missing => Err(CaseUseCaseError::MissingCase),
        }
    }
}

fn tenant_scope(session: &AuthenticatedSession) -> Result<TenantScope, CaseUseCaseError> {
    Ok(TenantScope::new(
        session.identity().organization().as_str(),
    )?)
}

fn authorize(session: &AuthenticatedSession) -> Result<(), CaseUseCaseError> {
    session
        .can(Capability::ManageInvestigatorCases)
        .then_some(())
        .ok_or(CaseUseCaseError::Unauthorized)
}
fn nonempty(field: &'static str, value: &str) -> Result<(), CaseUseCaseError> {
    (!value.trim().is_empty())
        .then_some(())
        .ok_or(CaseUseCaseError::EmptyField(field))
}
fn now(clock: &impl Clock) -> i64 {
    i64::try_from(clock.unix_seconds()).unwrap_or(i64::MAX)
}
