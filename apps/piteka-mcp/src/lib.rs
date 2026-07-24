#![forbid(unsafe_code)]

use piteka_application::mcp::{AccountabilityTools, McpIdentity, call_tool};
use serde_json::{Value, json};

pub const PROTOCOL_VERSION: &str = "2025-06-18";

pub fn tool_catalog() -> Value {
    json!([
        tool(
            "piteka_request_deployment",
            "Requests review of an exact deployment. Creates a pending action request; it does not approve or execute it.",
            deployment_schema(false)
        ),
        tool(
            "piteka_get_action_status",
            "Reads the current status of a tenant-scoped action. No side effects.",
            object_schema()
        ),
        tool(
            "piteka_execute_approved_deployment",
            "SIDE EFFECT: reserves a single-use mandate and may create a GitHub deployment. Requires an exact valid mandate and rejects changed parameters.",
            deployment_schema(true)
        ),
        tool(
            "piteka_get_receipt",
            "Reads a tenant-scoped execution receipt. No side effects.",
            object_schema()
        ),
        tool(
            "piteka_export_dispute_bundle",
            "SIDE EFFECT: creates an auditable export of disclosed evidence for a receipt.",
            object_schema()
        ),
        tool(
            "piteka_verify_bundle",
            "Verifies a bundle with the pinned Parwana verifier and returns structured assurance. No provider side effects.",
            object_schema()
        )
    ])
}

fn tool(name: &str, description: &str, input_schema: Value) -> Value {
    json!({"name":name,"description":description,"inputSchema":input_schema})
}
fn object_schema() -> Value {
    json!({"type":"object","properties":{"id":{"type":"string","minLength":1}},"required":["id"],"additionalProperties":false})
}
fn deployment_schema(execute: bool) -> Value {
    let mut properties = json!({"request_id":{"type":"string","minLength":1},"repository_id":{"type":"integer","minimum":1},"commit_sha":{"type":"string","pattern":"^[0-9a-f]{40}$"},"environment_id":{"type":"integer","minimum":1},"intent_id":{"type":"string","minLength":1}});
    let mut required = vec![
        "request_id",
        "repository_id",
        "commit_sha",
        "environment_id",
        "intent_id",
    ];
    if execute {
        properties
            .as_object_mut()
            .unwrap()
            .insert("mandate_id".into(), json!({"type":"string","minLength":1}));
        required.push("mandate_id");
    }
    json!({"type":"object","properties":properties,"required":required,"additionalProperties":false})
}

pub async fn handle<B: AccountabilityTools>(
    backend: &B,
    identity: &McpIdentity,
    request: Value,
) -> Option<Value> {
    let id = request.get("id").cloned();
    let method = request.get("method").and_then(Value::as_str)?;
    id.as_ref()?;
    let result = match method {
        "initialize" => Ok(
            json!({"protocolVersion":PROTOCOL_VERSION,"capabilities":{"tools":{"listChanged":false}},"serverInfo":{"name":"piteka-mcp","version":env!("CARGO_PKG_VERSION")}}),
        ),
        "tools/list" => Ok(json!({"tools":tool_catalog()})),
        "tools/call" => {
            let params = request.get("params").cloned().unwrap_or(Value::Null);
            let name = params.get("name").and_then(Value::as_str).unwrap_or("");
            let args = params
                .get("arguments")
                .cloned()
                .unwrap_or_else(|| json!({}));
            call_tool(backend, identity, name, args).await.map(|value| json!({"content":[{"type":"text","text":value.to_string()}],"structuredContent":value,"isError":false}))
        }
        _ => Err(piteka_application::mcp::McpError::new(
            "METHOD_NOT_FOUND",
            "Unknown JSON-RPC method",
        )),
    };
    Some(match result {
        Ok(value) => json!({"jsonrpc":"2.0","id":id,"result":value}),
        Err(error) => {
            json!({"jsonrpc":"2.0","id":id,"result":{"content":[{"type":"text","text":error.message}],"structuredContent":{"error":error},"isError":true}})
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use piteka_application::mcp::{ExecuteDeploymentInput, McpError, RequestDeploymentInput};

    struct Backend;
    #[async_trait]
    impl AccountabilityTools for Backend {
        async fn recompute_intent_id(
            &self,
            tenant: &str,
            _: u64,
            sha: &str,
            _: u64,
        ) -> Result<String, McpError> {
            Ok(format!("{tenant}:{sha}"))
        }
        async fn request_deployment(
            &self,
            identity: &McpIdentity,
            _: RequestDeploymentInput,
        ) -> Result<Value, McpError> {
            Ok(json!({"status":"pending","tenant":identity.tenant_id()}))
        }
        async fn get_action_status(
            &self,
            identity: &McpIdentity,
            id: &str,
        ) -> Result<Value, McpError> {
            Ok(json!({"id":id,"tenant":identity.tenant_id()}))
        }
        async fn execute_approved_deployment(
            &self,
            _: &McpIdentity,
            _: ExecuteDeploymentInput,
        ) -> Result<Value, McpError> {
            Ok(json!({"dispatched":true}))
        }
        async fn get_receipt(&self, _: &McpIdentity, id: &str) -> Result<Value, McpError> {
            Ok(json!({"id":id}))
        }
        async fn export_dispute_bundle(
            &self,
            _: &McpIdentity,
            id: &str,
        ) -> Result<Value, McpError> {
            Ok(json!({"id":id}))
        }
        async fn verify_bundle(&self, _: &McpIdentity, id: &str) -> Result<Value, McpError> {
            Ok(json!({"id":id}))
        }
    }

    fn identity() -> McpIdentity {
        McpIdentity::new("svc:agent", "tenant-a").unwrap()
    }

    #[tokio::test]
    async fn lists_all_six_tools_with_explicit_execution_side_effect() {
        let response = handle(
            &Backend,
            &identity(),
            json!({"jsonrpc":"2.0","id":1,"method":"tools/list"}),
        )
        .await
        .unwrap();
        let tools = response["result"]["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 6);
        let execute = tools
            .iter()
            .find(|v| v["name"] == "piteka_execute_approved_deployment")
            .unwrap();
        assert!(
            execute["description"]
                .as_str()
                .unwrap()
                .contains("SIDE EFFECT")
        );
    }

    #[tokio::test]
    async fn binds_tenant_from_transport_identity() {
        let response = handle(&Backend, &identity(), json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"piteka_get_action_status","arguments":{"id":"action-1"}}})).await.unwrap();
        assert_eq!(
            response["result"]["structuredContent"]["tenant"],
            "tenant-a"
        );
    }

    #[tokio::test]
    async fn rejects_changed_parameters_before_dispatch() {
        let response = handle(&Backend, &identity(), json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"piteka_execute_approved_deployment","arguments":{"request_id":"r","mandate_id":"m","repository_id":1,"commit_sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","environment_id":2,"intent_id":"different"}}})).await.unwrap();
        assert_eq!(
            response["result"]["structuredContent"]["error"]["code"],
            "INTENT_MISMATCH"
        );
        assert_eq!(response["result"]["isError"], true);
    }

    #[tokio::test]
    async fn rejects_unknown_fields_and_unknown_tools_structurally() {
        let bad = handle(&Backend, &identity(), json!({"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"piteka_get_receipt","arguments":{"id":"x","tenant_id":"other"}}})).await.unwrap();
        assert_eq!(
            bad["result"]["structuredContent"]["error"]["code"],
            "MALFORMED_ARGUMENTS"
        );
        let unknown = handle(&Backend, &identity(), json!({"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"piteka_destroy","arguments":{}}})).await.unwrap();
        assert_eq!(
            unknown["result"]["structuredContent"]["error"]["code"],
            "TOOL_NOT_FOUND"
        );
    }

    #[tokio::test]
    async fn rejects_empty_object_references() {
        let response = handle(&Backend, &identity(), json!({"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"piteka_get_receipt","arguments":{"id":"   "}}})).await.unwrap();
        assert_eq!(
            response["result"]["structuredContent"]["error"]["code"],
            "MALFORMED_ARGUMENTS"
        );
        assert_eq!(response["result"]["isError"], true);
    }

    struct OversizedBackend;

    #[async_trait]
    impl AccountabilityTools for OversizedBackend {
        async fn recompute_intent_id(
            &self,
            _: &str,
            _: u64,
            _: &str,
            _: u64,
        ) -> Result<String, McpError> {
            unreachable!()
        }
        async fn request_deployment(
            &self,
            _: &McpIdentity,
            _: RequestDeploymentInput,
        ) -> Result<Value, McpError> {
            unreachable!()
        }
        async fn get_action_status(&self, _: &McpIdentity, _: &str) -> Result<Value, McpError> {
            unreachable!()
        }
        async fn execute_approved_deployment(
            &self,
            _: &McpIdentity,
            _: ExecuteDeploymentInput,
        ) -> Result<Value, McpError> {
            unreachable!()
        }
        async fn get_receipt(&self, _: &McpIdentity, _: &str) -> Result<Value, McpError> {
            Ok(json!({"payload":"x".repeat(piteka_application::mcp::MAX_RESPONSE_BYTES)}))
        }
        async fn export_dispute_bundle(&self, _: &McpIdentity, _: &str) -> Result<Value, McpError> {
            unreachable!()
        }
        async fn verify_bundle(&self, _: &McpIdentity, _: &str) -> Result<Value, McpError> {
            unreachable!()
        }
    }

    #[tokio::test]
    async fn rejects_oversized_backend_responses() {
        let response = handle(&OversizedBackend, &identity(), json!({"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"piteka_get_receipt","arguments":{"id":"receipt-1"}}})).await.unwrap();
        assert_eq!(
            response["result"]["structuredContent"]["error"]["code"],
            "RESPONSE_TOO_LARGE"
        );
        assert_eq!(response["result"]["isError"], true);
    }
}
