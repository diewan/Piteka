//! Application boundary used by the Piteka MCP transport.
//!
//! The transport supplies an authenticated service identity. It cannot select
//! a tenant or actor through tool arguments. Implementations delegate to the
//! existing Piteka use cases; this module deliberately owns no live state and
//! implements no Parwana serialization or verification semantics.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const MAX_ARGUMENT_BYTES: usize = 32 * 1024;
pub const MAX_RESPONSE_BYTES: usize = 256 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct McpIdentity {
    service_identity: String,
    tenant_id: String,
}

impl McpIdentity {
    pub fn new(
        service_identity: impl Into<String>,
        tenant_id: impl Into<String>,
    ) -> Result<Self, McpError> {
        let value = Self {
            service_identity: service_identity.into(),
            tenant_id: tenant_id.into(),
        };
        if value.service_identity.trim().is_empty() || value.tenant_id.trim().is_empty() {
            return Err(McpError::new(
                "UNAUTHENTICATED",
                "An authenticated service identity and tenant are required",
            ));
        }
        Ok(value)
    }

    #[must_use]
    pub fn service_identity(&self) -> &str {
        &self.service_identity
    }

    #[must_use]
    pub fn tenant_id(&self) -> &str {
        &self.tenant_id
    }
}

#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct McpError {
    pub code: &'static str,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<Value>,
}

impl McpError {
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            details: None,
        }
    }
}

impl From<crate::dispatch::ReplayRejection> for McpError {
    fn from(rejection: crate::dispatch::ReplayRejection) -> Self {
        Self {
            code: rejection.reason_code,
            message: rejection.message,
            details: Some(serde_json::json!({
                "mandate_id": rejection.mandate_id_hex,
                "request_id": rejection.request_id,
                "mandate_state": rejection.mandate_state,
                "provider_dispatch_suppressed": true
            })),
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestDeployment {
    pub request_id: String,
    pub repository_id: u64,
    pub commit_sha: String,
    pub environment_id: u64,
    pub intent_id: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectRef {
    pub id: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecuteDeployment {
    pub request_id: String,
    pub mandate_id: String,
    pub repository_id: u64,
    pub commit_sha: String,
    pub environment_id: u64,
    pub intent_id: String,
}

#[async_trait]
pub trait AccountabilityTools: Send + Sync {
    async fn recompute_intent_id(
        &self,
        tenant: &str,
        repository_id: u64,
        commit_sha: &str,
        environment_id: u64,
    ) -> Result<String, McpError>;
    async fn request_deployment(
        &self,
        identity: &McpIdentity,
        input: RequestDeployment,
    ) -> Result<Value, McpError>;
    async fn get_action_status(&self, identity: &McpIdentity, id: &str) -> Result<Value, McpError>;
    async fn execute_approved_deployment(
        &self,
        identity: &McpIdentity,
        input: ExecuteDeployment,
    ) -> Result<Value, McpError>;
    async fn get_receipt(&self, identity: &McpIdentity, id: &str) -> Result<Value, McpError>;
    async fn export_dispute_bundle(
        &self,
        identity: &McpIdentity,
        id: &str,
    ) -> Result<Value, McpError>;
    async fn verify_bundle(&self, identity: &McpIdentity, id: &str) -> Result<Value, McpError>;
}

pub async fn call_tool<B: AccountabilityTools>(
    backend: &B,
    identity: &McpIdentity,
    name: &str,
    arguments: Value,
) -> Result<Value, McpError> {
    let size = serde_json::to_vec(&arguments)
        .map_err(|_| McpError::new("MALFORMED_ARGUMENTS", "Arguments must be valid JSON"))?
        .len();
    if size > MAX_ARGUMENT_BYTES {
        return Err(McpError::new(
            "ARGUMENTS_TOO_LARGE",
            "Tool arguments exceed the 32 KiB limit",
        ));
    }
    let response = match name {
        "piteka_request_deployment" => {
            let input: RequestDeployment = decode(arguments)?;
            validate_deployment_fields(
                &input.request_id,
                input.repository_id,
                &input.commit_sha,
                input.environment_id,
            )?;
            validate_intent(
                backend,
                identity,
                input.repository_id,
                &input.commit_sha,
                input.environment_id,
                &input.intent_id,
            )
            .await?;
            backend.request_deployment(identity, input).await
        }
        "piteka_get_action_status" => {
            let input: ObjectRef = decode(arguments)?;
            validate_object_id(&input.id)?;
            backend.get_action_status(identity, &input.id).await
        }
        "piteka_execute_approved_deployment" => {
            let input: ExecuteDeployment = decode(arguments)?;
            validate_deployment_fields(
                &input.request_id,
                input.repository_id,
                &input.commit_sha,
                input.environment_id,
            )?;
            if input.mandate_id.trim().is_empty() {
                return Err(McpError::new(
                    "MALFORMED_ARGUMENTS",
                    "mandate_id must not be empty",
                ));
            }
            validate_intent(
                backend,
                identity,
                input.repository_id,
                &input.commit_sha,
                input.environment_id,
                &input.intent_id,
            )
            .await?;
            backend.execute_approved_deployment(identity, input).await
        }
        "piteka_get_receipt" => {
            let input: ObjectRef = decode(arguments)?;
            validate_object_id(&input.id)?;
            backend.get_receipt(identity, &input.id).await
        }
        "piteka_export_dispute_bundle" => {
            let input: ObjectRef = decode(arguments)?;
            validate_object_id(&input.id)?;
            backend.export_dispute_bundle(identity, &input.id).await
        }
        "piteka_verify_bundle" => {
            let input: ObjectRef = decode(arguments)?;
            validate_object_id(&input.id)?;
            backend.verify_bundle(identity, &input.id).await
        }
        _ => Err(McpError::new("TOOL_NOT_FOUND", "Unknown Piteka tool")),
    }?;
    bound_response(response)
}

fn validate_object_id(id: &str) -> Result<(), McpError> {
    if id.trim().is_empty() {
        return Err(McpError::new("MALFORMED_ARGUMENTS", "id must not be empty"));
    }
    Ok(())
}

fn bound_response(response: Value) -> Result<Value, McpError> {
    let size = serde_json::to_vec(&response)
        .map_err(|_| McpError::new("INTERNAL_ERROR", "Tool response could not be encoded"))?
        .len();
    if size > MAX_RESPONSE_BYTES {
        return Err(McpError::new(
            "RESPONSE_TOO_LARGE",
            "Tool response exceeds the 256 KiB limit",
        ));
    }
    Ok(response)
}

fn decode<T: for<'de> Deserialize<'de>>(value: Value) -> Result<T, McpError> {
    serde_json::from_value(value).map_err(|e| {
        McpError::new(
            "MALFORMED_ARGUMENTS",
            format!("Invalid tool arguments: {e}"),
        )
    })
}

fn validate_deployment_fields(
    request_id: &str,
    repository_id: u64,
    commit_sha: &str,
    environment_id: u64,
) -> Result<(), McpError> {
    let valid_sha = commit_sha.len() == 40
        && commit_sha
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
    if request_id.trim().is_empty() || repository_id == 0 || environment_id == 0 || !valid_sha {
        return Err(McpError::new(
            "MALFORMED_ARGUMENTS",
            "request_id, stable provider IDs, and a lower-case 40-character commit SHA are required",
        ));
    }
    Ok(())
}

async fn validate_intent<B: AccountabilityTools>(
    backend: &B,
    identity: &McpIdentity,
    repository_id: u64,
    commit_sha: &str,
    environment_id: u64,
    supplied: &str,
) -> Result<(), McpError> {
    let computed = backend
        .recompute_intent_id(
            identity.tenant_id(),
            repository_id,
            commit_sha,
            environment_id,
        )
        .await?;
    if computed != supplied {
        let mut error = McpError::new(
            "INTENT_MISMATCH",
            "Deployment parameters do not match the authorized intent",
        );
        error.details = Some(
            serde_json::json!({"supplied_intent_id": supplied, "computed_intent_id": computed}),
        );
        return Err(error);
    }
    Ok(())
}
