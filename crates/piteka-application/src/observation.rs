//! Read-only observation integration boundary (Master Plan F-08).
//!
//! Tuppira is an observation plane, not an authorization authority.  This
//! use case therefore preserves unavailable or incomplete indexed evidence as
//! explicit gaps.  Neither a successful query nor an empty/error response can
//! authorize, retry, or otherwise mutate an execution.

use async_trait::async_trait;
use std::collections::BTreeMap;

/// A normalized, tenant-visible observation returned by the Tuppira observation
/// plane.
///
/// The `Tuppira` qualifier names the vocabulary owner: Tuppira produces and defines
/// these observations, Piteka only reads them. It earns the reserved `Observation`
/// role because it carries source identity (`source_id`, `source_event_id`),
/// acquisition provenance (`observed_at`, `collection_run_id`), and explicit
/// uncertainty (`retraction_status`, `supersedes`). It is evidence, never authority:
/// see [`ObservationQueryResult::permits_execution`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TuppiraObservation {
    pub observation_id: String,
    pub source_id: String,
    pub source_event_id: String,
    pub source_event_type: String,
    pub subject_refs: Vec<String>,
    pub asserted_event_time: Option<i64>,
    pub observed_at: i64,
    pub normalized_profile_id: String,
    pub normalized_profile_version: u16,
    pub normalized_payload_digest_hex: String,
    pub authenticity_material_refs: Vec<String>,
    pub collection_run_id: String,
    pub supersedes: Option<String>,
    pub retraction_status: String,
    pub visibility_scope: String,
}

/// Collection progress reported for one observation source.
///
/// Qualified by `Observation` to separate it from `piteka_domain::Health`, which
/// reports this service's own readiness. This one reports how far an external
/// collector has got, which is what turns missing evidence into an explicit gap
/// rather than a conclusion.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObservationSourceHealth {
    pub source_id: String,
    pub connector_kind: String,
    pub display_name: String,
    pub last_run_started_at: Option<i64>,
    pub last_run_completed_at: Option<i64>,
    pub cursor_observed_at: Option<i64>,
}

/// Stable categories exposed by an observation adapter.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ObservationError {
    #[error("observation service unavailable")]
    Unavailable,
    #[error("observation credentials were rejected")]
    Unauthenticated,
    #[error("observation was not visible to the tenant")]
    NotVisible,
    #[error("observation response was malformed: {0}")]
    Malformed(String),
    #[error("observation query is unsupported: {0}")]
    Unsupported(String),
}

/// Port through which the application queries the source-neutral observation plane.
#[async_trait]
pub trait ObservationPort: Send + Sync {
    async fn lineage(
        &self,
        tenant_id: &str,
        observation_id: &str,
    ) -> Result<Vec<TuppiraObservation>, ObservationError>;

    async fn source_health(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<ObservationSourceHealth>, ObservationError>;
}

/// Tenant-scoped observation query.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObservationQuery {
    pub tenant_id: String,
    pub observation_id: String,
}

/// An explicit statement that required observation evidence was not available.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvidenceGap {
    pub code: &'static str,
    pub detail: String,
}

/// Read result suitable for investigation and evidence collection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObservationQueryResult {
    pub lineage: Vec<TuppiraObservation>,
    pub source_health: Vec<ObservationSourceHealth>,
    pub evidence_gaps: Vec<EvidenceGap>,
}

impl ObservationQueryResult {
    /// Whether all observation evidence requested by this query was available.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.evidence_gaps.is_empty()
    }

    /// Observation data is evidence, never permission to execute an action.
    #[must_use]
    pub const fn permits_execution(&self) -> bool {
        false
    }
}

/// Queries Tuppira through a port and converts absence/outages into evidence gaps.
pub struct ObservationUseCase<P> {
    port: P,
}

impl<P: ObservationPort> ObservationUseCase<P> {
    #[must_use]
    pub const fn new(port: P) -> Self {
        Self { port }
    }

    pub async fn query(&self, query: &ObservationQuery) -> ObservationQueryResult {
        if !valid_identifier(&query.tenant_id) || !valid_identifier(&query.observation_id) {
            return gap(
                "invalid_observation_query",
                "tenant or observation identifier is invalid",
            );
        }

        let lineage = match self
            .port
            .lineage(&query.tenant_id, &query.observation_id)
            .await
        {
            Ok(lineage) => lineage,
            Err(error) => return gap_for_error("observation_lineage_unavailable", error),
        };
        if lineage.is_empty() {
            return gap(
                "observation_not_found",
                "no tenant-visible observation lineage was returned",
            );
        }

        let source_health = match self.port.source_health(&query.tenant_id).await {
            Ok(health) => health,
            Err(error) => return gap_for_error("observation_source_health_unavailable", error),
        };

        let health_by_source: BTreeMap<&str, &ObservationSourceHealth> = source_health
            .iter()
            .map(|health| (health.source_id.as_str(), health))
            .collect();
        let mut evidence_gaps = Vec::new();
        for observation in &lineage {
            match health_by_source.get(observation.source_id.as_str()) {
                Some(health)
                    if health.last_run_completed_at.is_some()
                        && health.cursor_observed_at.is_some() => {}
                Some(_) => evidence_gaps.push(EvidenceGap {
                    code: "observation_source_incomplete",
                    detail: format!(
                        "source `{}` has no completed collection cursor",
                        observation.source_id
                    ),
                }),
                None => evidence_gaps.push(EvidenceGap {
                    code: "observation_source_health_missing",
                    detail: format!("source `{}` has no health record", observation.source_id),
                }),
            }
            if observation.retraction_status != "active" {
                evidence_gaps.push(EvidenceGap {
                    code: "observation_retracted",
                    detail: format!(
                        "observation `{}` has status `{}`",
                        observation.observation_id, observation.retraction_status
                    ),
                });
            }
        }

        ObservationQueryResult {
            lineage,
            source_health,
            evidence_gaps,
        }
    }
}

fn valid_identifier(value: &str) -> bool {
    !value.trim().is_empty() && value.len() <= 512 && !value.contains(['\0', ',', '='])
}

fn gap(code: &'static str, detail: impl Into<String>) -> ObservationQueryResult {
    ObservationQueryResult {
        lineage: Vec::new(),
        source_health: Vec::new(),
        evidence_gaps: vec![EvidenceGap {
            code,
            detail: detail.into(),
        }],
    }
}

fn gap_for_error(code: &'static str, error: ObservationError) -> ObservationQueryResult {
    gap(code, error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Stub {
        lineage: Result<Vec<TuppiraObservation>, ObservationError>,
        health: Result<Vec<ObservationSourceHealth>, ObservationError>,
    }

    #[async_trait]
    impl ObservationPort for Stub {
        async fn lineage(
            &self,
            _: &str,
            _: &str,
        ) -> Result<Vec<TuppiraObservation>, ObservationError> {
            self.lineage.clone()
        }

        async fn source_health(
            &self,
            _: &str,
        ) -> Result<Vec<ObservationSourceHealth>, ObservationError> {
            self.health.clone()
        }
    }

    fn observation() -> TuppiraObservation {
        TuppiraObservation {
            observation_id: "obs-1".into(),
            source_id: "github".into(),
            source_event_id: "deployment-1".into(),
            source_event_type: "deployment_status".into(),
            subject_refs: vec!["mandate-1".into()],
            asserted_event_time: Some(10),
            observed_at: 11,
            normalized_profile_id: "github.deployment.v1".into(),
            normalized_profile_version: 1,
            normalized_payload_digest_hex: "ab".repeat(32),
            authenticity_material_refs: vec![],
            collection_run_id: "run-1".into(),
            supersedes: None,
            retraction_status: "active".into(),
            visibility_scope: "tenant".into(),
        }
    }

    fn health() -> ObservationSourceHealth {
        ObservationSourceHealth {
            source_id: "github".into(),
            connector_kind: "github".into(),
            display_name: "GitHub".into(),
            last_run_started_at: Some(9),
            last_run_completed_at: Some(12),
            cursor_observed_at: Some(11),
        }
    }

    #[tokio::test]
    async fn complete_query_preserves_non_authoritative_observations() {
        let result = ObservationUseCase::new(Stub {
            lineage: Ok(vec![observation()]),
            health: Ok(vec![health()]),
        })
        .query(&ObservationQuery {
            tenant_id: "tenant-a".into(),
            observation_id: "obs-1".into(),
        })
        .await;
        assert!(result.is_complete());
        assert!(!result.permits_execution());
    }

    #[tokio::test]
    async fn unavailable_tuppira_becomes_gap_and_never_permission() {
        let result = ObservationUseCase::new(Stub {
            lineage: Err(ObservationError::Unavailable),
            health: Ok(vec![]),
        })
        .query(&ObservationQuery {
            tenant_id: "tenant-a".into(),
            observation_id: "obs-1".into(),
        })
        .await;
        assert_eq!(
            result.evidence_gaps[0].code,
            "observation_lineage_unavailable"
        );
        assert!(!result.permits_execution());
    }

    #[tokio::test]
    async fn missing_health_and_retraction_are_explicit_gaps() {
        let mut retracted = observation();
        retracted.retraction_status = "retracted".into();
        let result = ObservationUseCase::new(Stub {
            lineage: Ok(vec![retracted]),
            health: Ok(vec![]),
        })
        .query(&ObservationQuery {
            tenant_id: "tenant-a".into(),
            observation_id: "obs-1".into(),
        })
        .await;
        assert_eq!(result.evidence_gaps.len(), 2);
        assert!(!result.is_complete());
    }

    #[tokio::test]
    async fn ambiguous_tenant_identifier_is_rejected_before_port_call() {
        let result = ObservationUseCase::new(Stub {
            lineage: Ok(vec![observation()]),
            health: Ok(vec![health()]),
        })
        .query(&ObservationQuery {
            tenant_id: "tenant=a".into(),
            observation_id: "obs-1".into(),
        })
        .await;
        assert_eq!(result.evidence_gaps[0].code, "invalid_observation_query");
    }
}
