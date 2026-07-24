//! The autonomous agent client (DEMO-01, Scenario A).
//!
//! [`AgentActor`] drives the deployment purely through the Piteka MCP tools via
//! [`piteka_mcp::handle`]. It constructs JSON-RPC `tools/call` requests, inspects
//! structured responses, and never reaches past the constrained MCP surface. The
//! human approval step is not one of its capabilities — an orchestrator performs
//! it out of band between [`AgentActor::request_deployment`] and
//! [`AgentActor::execute`].

use std::fmt;

use serde_json::{Value, json};

use piteka_application::mcp::{AccountabilityTools, McpIdentity};

use super::demo_intent_id;

/// An error surfaced to the agent by an MCP tool call, or a protocol framing
/// error. The agent treats structured tool errors as first-class outcomes.
#[derive(Debug, Clone)]
pub struct AgentError {
    /// Stable reason code from the tool (or an agent-side framing code).
    pub code: String,
    /// Human-readable message.
    pub message: String,
    /// Optional structured details echoed from the tool.
    pub details: Option<Value>,
}

impl fmt::Display for AgentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}", self.code, self.message)
    }
}

impl std::error::Error for AgentError {}

/// The exact deployment the agent intends to propose and execute.
#[derive(Clone, Debug)]
pub struct DeploymentPlan {
    /// Client-chosen action request id.
    pub request_id: String,
    /// Stable GitHub repository id.
    pub repository_id: u64,
    /// Stable GitHub environment id.
    pub environment_id: u64,
    /// Exact lower-case 40-hex commit sha.
    pub commit_sha: String,
}

impl DeploymentPlan {
    /// The intent digest the agent supplies. The server independently recomputes
    /// this from the same parameters and rejects a mismatch.
    #[must_use]
    pub fn intent_id(&self, tenant: &str) -> String {
        demo_intent_id(
            tenant,
            self.repository_id,
            &self.commit_sha,
            self.environment_id,
        )
    }
}

/// An autonomous MCP agent bound to a single service identity/tenant.
pub struct AgentActor<'a, B: AccountabilityTools> {
    backend: &'a B,
    identity: McpIdentity,
    next_id: u64,
}

impl<'a, B: AccountabilityTools> AgentActor<'a, B> {
    /// Creates an agent that will call `backend` under `identity`.
    pub fn new(backend: &'a B, identity: McpIdentity) -> Self {
        Self {
            backend,
            identity,
            next_id: 1,
        }
    }

    async fn call(&mut self, name: &str, arguments: Value) -> Result<Value, AgentError> {
        let id = self.next_id;
        self.next_id += 1;
        let request = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments},
        });
        let response = piteka_mcp::handle(self.backend, &self.identity, request)
            .await
            .ok_or_else(|| AgentError {
                code: "NO_RESPONSE".into(),
                message: format!("MCP transport returned no response for {name}"),
                details: None,
            })?;
        let result = &response["result"];
        if result["isError"] == Value::Bool(true) {
            let error = &result["structuredContent"]["error"];
            return Err(AgentError {
                code: error["code"].as_str().unwrap_or("UNKNOWN").to_string(),
                message: error["message"].as_str().unwrap_or_default().to_string(),
                details: error.get("details").cloned(),
            });
        }
        Ok(result["structuredContent"].clone())
    }

    /// Step 1 — propose the deployment for human review.
    pub async fn request_deployment(&mut self, plan: &DeploymentPlan) -> Result<Value, AgentError> {
        let intent_id = plan.intent_id(self.identity.tenant_id());
        self.call(
            "piteka_request_deployment",
            json!({
                "request_id": plan.request_id,
                "repository_id": plan.repository_id,
                "commit_sha": plan.commit_sha,
                "environment_id": plan.environment_id,
                "intent_id": intent_id,
            }),
        )
        .await
    }

    /// Reads the current status of the action request.
    pub async fn action_status(&mut self, request_id: &str) -> Result<Value, AgentError> {
        self.call("piteka_get_action_status", json!({"id": request_id}))
            .await
    }

    /// Step 2 — poll status until the human approves and the mandate id appears,
    /// then return that mandate id. `attempts` bounds the polling.
    pub async fn wait_for_mandate(
        &mut self,
        request_id: &str,
        attempts: usize,
    ) -> Result<String, AgentError> {
        for _ in 0..attempts.max(1) {
            let status = self.action_status(request_id).await?;
            if let Some(mandate_id) = status.get("mandate_id").and_then(Value::as_str) {
                return Ok(mandate_id.to_string());
            }
        }
        Err(AgentError {
            code: "NOT_APPROVED".into(),
            message: "Action was not approved within the polling budget".into(),
            details: None,
        })
    }

    /// Step 3 — execute the approved single-use mandate. The `plan` supplies the
    /// parameters; passing a plan whose parameters differ from the approved ones
    /// makes the server's recompute reject the call before any dispatch.
    pub async fn execute(
        &mut self,
        plan: &DeploymentPlan,
        mandate_id: &str,
    ) -> Result<Value, AgentError> {
        let intent_id = plan.intent_id(self.identity.tenant_id());
        self.call(
            "piteka_execute_approved_deployment",
            json!({
                "request_id": plan.request_id,
                "mandate_id": mandate_id,
                "repository_id": plan.repository_id,
                "commit_sha": plan.commit_sha,
                "environment_id": plan.environment_id,
                "intent_id": intent_id,
            }),
        )
        .await
    }

    /// Executes with explicitly supplied fields, bypassing the plan-derived
    /// intent computation. This models a tampering agent that keeps the approved
    /// `intent_id`/`mandate_id` but presents changed deployment parameters — the
    /// server's independent recompute must reject it before any dispatch.
    #[allow(clippy::too_many_arguments)]
    pub async fn execute_raw(
        &mut self,
        request_id: &str,
        mandate_id: &str,
        repository_id: u64,
        commit_sha: &str,
        environment_id: u64,
        intent_id: &str,
    ) -> Result<Value, AgentError> {
        self.call(
            "piteka_execute_approved_deployment",
            json!({
                "request_id": request_id,
                "mandate_id": mandate_id,
                "repository_id": repository_id,
                "commit_sha": commit_sha,
                "environment_id": environment_id,
                "intent_id": intent_id,
            }),
        )
        .await
    }

    /// Step 4 — read the execution receipt (the demo attempt journal).
    pub async fn get_receipt(&mut self, id: &str) -> Result<Value, AgentError> {
        self.call("piteka_get_receipt", json!({"id": id})).await
    }
}
