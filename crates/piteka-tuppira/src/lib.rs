#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! Tenant-authenticated REST adapter for Tuppira observation queries.

use async_trait::async_trait;
use piteka_application::{
    ObservationError, ObservationPort, ObservationSourceHealth, TuppiraObservation,
};
use reqwest::{StatusCode, header};
use serde::Deserialize;
use std::time::Duration;
use url::Url;

const MAX_RESPONSE_BYTES: usize = 1024 * 1024;

/// Validated adapter configuration. The bearer token is intentionally not debug-printable.
#[derive(Clone)]
pub struct TuppiraConfig {
    base_url: Url,
    bearer_token: String,
    timeout: Duration,
}

impl TuppiraConfig {
    /// Creates configuration for the versioned Tuppira REST API.
    pub fn new(base_url: &str, bearer_token: impl Into<String>) -> Result<Self, ObservationError> {
        let mut base_url = Url::parse(base_url)
            .map_err(|_| ObservationError::Unsupported("invalid Tuppira base URL".into()))?;
        if !matches!(base_url.scheme(), "http" | "https")
            || base_url.host_str().is_none()
            || !base_url.username().is_empty()
            || base_url.password().is_some()
            || base_url.query().is_some()
            || base_url.fragment().is_some()
        {
            return Err(ObservationError::Unsupported(
                "Tuppira URL must be an HTTP(S) origin without credentials, query, or fragment"
                    .into(),
            ));
        }
        if !base_url.path().ends_with('/') {
            base_url.set_path(&format!("{}/", base_url.path()));
        }
        let bearer_token = bearer_token.into();
        if bearer_token.is_empty() || bearer_token.contains(['\r', '\n']) {
            return Err(ObservationError::Unsupported(
                "invalid Tuppira bearer token".into(),
            ));
        }
        Ok(Self {
            base_url,
            bearer_token,
            timeout: Duration::from_secs(5),
        })
    }

    /// Overrides the network timeout.
    #[must_use]
    pub const fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
}

/// HTTP implementation of Piteka's read-only observation port.
#[derive(Clone)]
pub struct TuppiraObservationAdapter {
    client: reqwest::Client,
    config: TuppiraConfig,
}

impl TuppiraObservationAdapter {
    /// Builds an adapter with redirects disabled so credentials cannot be forwarded.
    pub fn new(config: TuppiraConfig) -> Result<Self, ObservationError> {
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(config.timeout)
            .build()
            .map_err(|_| ObservationError::Unavailable)?;
        Ok(Self { client, config })
    }

    async fn get<T: for<'de> Deserialize<'de>>(
        &self,
        tenant_id: &str,
        path: &str,
    ) -> Result<T, ObservationError> {
        validate_identifier(tenant_id, "tenant")?;
        let url = self
            .config
            .base_url
            .join(path)
            .map_err(|_| ObservationError::Unsupported("invalid observation path".into()))?;
        let response = self
            .client
            .get(url)
            .header("x-tuppira-tenant-id", tenant_id)
            .header(
                header::AUTHORIZATION,
                format!("Bearer {}", self.config.bearer_token),
            )
            .header(header::ACCEPT, "application/json")
            .send()
            .await
            .map_err(|_| ObservationError::Unavailable)?;
        match response.status() {
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => {
                return Err(ObservationError::Unauthenticated);
            }
            StatusCode::NOT_FOUND => return Err(ObservationError::NotVisible),
            status if !status.is_success() => return Err(ObservationError::Unavailable),
            _ => {}
        }
        if response
            .content_length()
            .is_some_and(|length| length > MAX_RESPONSE_BYTES as u64)
        {
            return Err(ObservationError::Malformed(
                "response exceeds size limit".into(),
            ));
        }
        let bytes = response
            .bytes()
            .await
            .map_err(|_| ObservationError::Unavailable)?;
        if bytes.len() > MAX_RESPONSE_BYTES {
            return Err(ObservationError::Malformed(
                "response exceeds size limit".into(),
            ));
        }
        let envelope: ApiResponse<T> = serde_json::from_slice(&bytes)
            .map_err(|_| ObservationError::Malformed("invalid JSON response".into()))?;
        if !envelope.success {
            return Err(ObservationError::Malformed(
                "unsuccessful response used a success status".into(),
            ));
        }
        Ok(envelope.data)
    }
}

#[async_trait]
impl ObservationPort for TuppiraObservationAdapter {
    async fn lineage(
        &self,
        tenant_id: &str,
        observation_id: &str,
    ) -> Result<Vec<TuppiraObservation>, ObservationError> {
        validate_identifier(observation_id, "observation")?;
        let encoded: String =
            url::form_urlencoded::byte_serialize(observation_id.as_bytes()).collect();
        let rows: Vec<ObservationDto> = self
            .get(tenant_id, &format!("api/v1/observations/{encoded}/lineage"))
            .await?;
        rows.into_iter().map(TuppiraObservation::try_from).collect()
    }

    async fn source_health(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<ObservationSourceHealth>, ObservationError> {
        let rows: Vec<SourceHealthDto> = self
            .get(tenant_id, "api/v1/observation-sources/health")
            .await?;
        rows.into_iter()
            .map(ObservationSourceHealth::try_from)
            .collect()
    }
}

#[derive(Deserialize)]
struct ApiResponse<T> {
    data: T,
    success: bool,
}

#[derive(Deserialize)]
struct ObservationDto {
    observation_id: String,
    source_id: String,
    source_event_id: String,
    source_event_type: String,
    subject_refs: Vec<String>,
    asserted_event_time: Option<i64>,
    observed_at: i64,
    normalized_profile_id: String,
    normalized_profile_version: u16,
    normalized_payload_digest: String,
    authenticity_material_refs: Vec<String>,
    collection_run_id: String,
    supersedes: Option<String>,
    retraction_status: String,
    visibility_scope: String,
}

impl TryFrom<ObservationDto> for TuppiraObservation {
    type Error = ObservationError;
    fn try_from(value: ObservationDto) -> Result<Self, Self::Error> {
        for (name, item) in [
            ("observation", value.observation_id.as_str()),
            ("source", value.source_id.as_str()),
            ("source event", value.source_event_id.as_str()),
            ("profile", value.normalized_profile_id.as_str()),
            ("collection run", value.collection_run_id.as_str()),
        ] {
            validate_identifier(item, name)?;
        }
        if value.normalized_profile_version == 0
            || !is_digest(&value.normalized_payload_digest)
            || !matches!(value.visibility_scope.as_str(), "public" | "tenant")
            || !matches!(
                value.retraction_status.as_str(),
                "active" | "retracted" | "superseded"
            )
        {
            return Err(ObservationError::Malformed(
                "invalid observation fields".into(),
            ));
        }
        Ok(Self {
            observation_id: value.observation_id,
            source_id: value.source_id,
            source_event_id: value.source_event_id,
            source_event_type: value.source_event_type,
            subject_refs: value.subject_refs,
            asserted_event_time: value.asserted_event_time,
            observed_at: value.observed_at,
            normalized_profile_id: value.normalized_profile_id,
            normalized_profile_version: value.normalized_profile_version,
            normalized_payload_digest_hex: value.normalized_payload_digest,
            authenticity_material_refs: value.authenticity_material_refs,
            collection_run_id: value.collection_run_id,
            supersedes: value.supersedes,
            retraction_status: value.retraction_status,
            visibility_scope: value.visibility_scope,
        })
    }
}

#[derive(Deserialize)]
struct SourceHealthDto {
    source_id: String,
    connector_kind: String,
    display_name: String,
    last_run_started_at: Option<i64>,
    last_run_completed_at: Option<i64>,
    cursor_observed_at: Option<i64>,
}

impl TryFrom<SourceHealthDto> for ObservationSourceHealth {
    type Error = ObservationError;
    fn try_from(value: SourceHealthDto) -> Result<Self, Self::Error> {
        validate_identifier(&value.source_id, "source")?;
        if value.connector_kind.trim().is_empty() || value.display_name.trim().is_empty() {
            return Err(ObservationError::Malformed(
                "invalid source health fields".into(),
            ));
        }
        Ok(Self {
            source_id: value.source_id,
            connector_kind: value.connector_kind,
            display_name: value.display_name,
            last_run_started_at: value.last_run_started_at,
            last_run_completed_at: value.last_run_completed_at,
            cursor_observed_at: value.cursor_observed_at,
        })
    }
}

fn validate_identifier(value: &str, kind: &str) -> Result<(), ObservationError> {
    if value.trim().is_empty() || value.len() > 512 || value.contains(['\0', ',', '=']) {
        return Err(ObservationError::Malformed(format!(
            "invalid {kind} identifier"
        )));
    }
    Ok(())
}

fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        Json, Router,
        extract::Path,
        http::{HeaderMap, StatusCode},
        routing::get,
    };
    use serde_json::{Value, json};

    async fn spawn() -> String {
        async fn lineage(
            Path(id): Path<String>,
            headers: HeaderMap,
        ) -> Result<Json<Value>, StatusCode> {
            if headers
                .get("x-tuppira-tenant-id")
                .and_then(|v| v.to_str().ok())
                != Some("tenant-a")
                || headers
                    .get(header::AUTHORIZATION)
                    .and_then(|v| v.to_str().ok())
                    != Some("Bearer secret")
            {
                return Err(StatusCode::FORBIDDEN);
            }
            Ok(Json(
                json!({"success": true, "data": [{"observation_id": id,
                "source_id":"github", "source_event_id":"deployment-1", "source_event_type":"deployment_status",
                "subject_refs":["mandate-1"], "asserted_event_time":10, "observed_at":11,
                "normalized_profile_id":"github.deployment.v1", "normalized_profile_version":1,
                "normalized_payload_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "authenticity_material_refs":[], "collection_run_id":"run-1", "supersedes":null,
                "retraction_status":"active", "visibility_scope":"tenant"}]}),
            ))
        }
        async fn health() -> Json<Value> {
            Json(json!({"success":true,"data":[{"source_id":"github",
            "connector_kind":"github","display_name":"GitHub","last_run_started_at":9,
            "last_run_completed_at":12,"cursor_observed_at":11}]}))
        }
        let app = Router::new()
            .route("/api/v1/observations/{id}/lineage", get(lineage))
            .route("/api/v1/observation-sources/health", get(health));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        format!("http://{address}/")
    }

    #[tokio::test]
    async fn queries_tenant_scoped_rest_contract() {
        let adapter =
            TuppiraObservationAdapter::new(TuppiraConfig::new(&spawn().await, "secret").unwrap())
                .unwrap();
        let lineage = adapter.lineage("tenant-a", "obs-1").await.unwrap();
        assert_eq!(lineage[0].observation_id, "obs-1");
        assert_eq!(
            adapter.source_health("tenant-a").await.unwrap()[0].source_id,
            "github"
        );
    }

    #[tokio::test]
    async fn cross_tenant_credentials_fail_closed() {
        let adapter =
            TuppiraObservationAdapter::new(TuppiraConfig::new(&spawn().await, "secret").unwrap())
                .unwrap();
        assert_eq!(
            adapter.lineage("tenant-b", "obs-1").await,
            Err(ObservationError::Unauthenticated)
        );
    }

    #[test]
    fn configuration_rejects_credential_bearing_and_non_http_urls() {
        assert!(TuppiraConfig::new("file:///tmp/tuppira", "secret").is_err());
        assert!(TuppiraConfig::new("https://user@example.test", "secret").is_err());
        assert!(TuppiraConfig::new("https://example.test", "bad\nvalue").is_err());
    }

    #[test]
    fn malformed_observation_digest_is_rejected() {
        let dto: ObservationDto = serde_json::from_value(json!({
            "observation_id":"obs-1", "source_id":"github",
            "source_event_id":"deployment-1", "source_event_type":"deployment_status",
            "subject_refs":[], "asserted_event_time":null, "observed_at":11,
            "normalized_profile_id":"github.deployment.v1", "normalized_profile_version":1,
            "normalized_payload_digest":"not-a-digest", "authenticity_material_refs":[],
            "collection_run_id":"run-1", "supersedes":null,
            "retraction_status":"active", "visibility_scope":"tenant"
        }))
        .unwrap();
        assert!(matches!(
            TuppiraObservation::try_from(dto),
            Err(ObservationError::Malformed(_))
        ));
    }
}
