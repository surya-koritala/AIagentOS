//! MCP (Model Context Protocol) Client — connect to any MCP tool server.
//!
//! Implements the MCP client protocol (JSON-RPC over stdio) to discover
//! and call tools from external MCP servers.

use std::collections::HashMap;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Child;
use tokio::sync::Mutex;

use crate::resources::ResourceType;
use crate::tools::{ToolBinding, ToolRegistry, ToolSecurity};

/// MCP server configuration.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpServerConfig {
    pub name: String,
    pub command: String,
    pub args: Vec<String>,
    #[serde(default)]
    pub env: HashMap<String, String>,
}

impl std::fmt::Debug for McpServerConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let redacted_env = self
            .env
            .keys()
            .map(|key| (key, "[REDACTED]"))
            .collect::<std::collections::BTreeMap<_, _>>();
        formatter
            .debug_struct("McpServerConfig")
            .field("name", &self.name)
            .field("command", &self.command)
            .field("args", &"[REDACTED]")
            .field("env", &redacted_env)
            .finish()
    }
}

/// A connected MCP server instance.
pub struct McpServer {
    pub config: McpServerConfig,
    process: Child,
    stdin: Arc<Mutex<tokio::process::ChildStdin>>,
    stdout: Arc<Mutex<BufReader<tokio::process::ChildStdout>>>,
    tools: Vec<McpTool>,
    next_id: u64,
}

/// A tool discovered from an MCP server.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpTool {
    pub name: String,
    pub description: String,
    pub input_schema: serde_json::Value,
    /// AgentOS extension supplied by the local operator/MCP server. Remote MCP
    /// descriptions without this declaration are discoverable but not executable.
    #[serde(rename = "agentosSecurity")]
    pub security: Option<ToolSecurity>,
    /// AgentOS extension naming the provider class. Remote data cannot choose
    /// an implicit process-execution fallback by omitting this field.
    #[serde(rename = "agentosResourceType")]
    pub resource_type: Option<ResourceType>,
    /// AgentOS extension naming the provider operation.
    #[serde(rename = "agentosOperation")]
    pub operation: Option<String>,
}

impl McpTool {
    fn to_binding(&self, server_name: &str) -> Result<ToolBinding, String> {
        let prefixed_name = format!("mcp_{server_name}_{}", self.name);
        let security = self.security.clone().ok_or_else(|| {
            format!("MCP tool '{prefixed_name}' omitted required agentosSecurity")
        })?;
        let resource_type = self.resource_type.clone().ok_or_else(|| {
            format!("MCP tool '{prefixed_name}' omitted required agentosResourceType")
        })?;
        let operation = self
            .operation
            .clone()
            .filter(|operation| !operation.trim().is_empty())
            .ok_or_else(|| {
                format!("MCP tool '{prefixed_name}' omitted required agentosOperation")
            })?;
        Ok(ToolBinding {
            name: prefixed_name,
            description: format!("[MCP:{server_name}] {}", self.description),
            parameters_schema: self.input_schema.clone(),
            resource_type,
            operation,
            security,
        })
    }
}

/// JSON-RPC request.
#[derive(Serialize)]
struct JsonRpcRequest {
    jsonrpc: &'static str,
    id: u64,
    method: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    params: Option<serde_json::Value>,
}

/// JSON-RPC response.
#[derive(Deserialize)]
struct JsonRpcResponse {
    #[allow(dead_code)]
    id: Option<u64>,
    result: Option<serde_json::Value>,
    error: Option<serde_json::Value>,
}

impl McpServer {
    /// Direct host-process MCP launch is disabled. Outbound MCP servers must be
    /// attached to an agent's qualified container backend before this API can
    /// be enabled; otherwise the MCP child would inherit the kernel's ambient
    /// filesystem, process, network, and credential authority.
    pub async fn connect(_config: McpServerConfig) -> Result<Self, String> {
        Err("direct host MCP launch is disabled; an isolated MCP backend is required".into())
    }

    /// Get discovered tools.
    pub fn tools(&self) -> &[McpTool] {
        &self.tools
    }

    /// Call a tool on this MCP server.
    pub async fn call_tool(
        &mut self,
        name: &str,
        arguments: serde_json::Value,
    ) -> Result<String, String> {
        let result = self
            .send_request(
                "tools/call",
                Some(serde_json::json!({
                    "name": name,
                    "arguments": arguments
                })),
            )
            .await?;

        // Extract text content from result
        if let Some(content) = result.get("content").and_then(|c| c.as_array()) {
            let text: Vec<String> = content
                .iter()
                .filter_map(|item| {
                    if item.get("type")?.as_str()? == "text" {
                        Some(item.get("text")?.as_str()?.to_string())
                    } else {
                        None
                    }
                })
                .collect();
            Ok(text.join("\n"))
        } else {
            Ok(serde_json::to_string(&result).unwrap_or_default())
        }
    }

    /// Register this server's tools as one all-or-nothing batch.
    ///
    /// The exclusive registry borrow makes the short publication loop
    /// unobservable to safe concurrent callers. Every declaration is converted,
    /// validated, and checked for conflicts first; an unexpected late registry
    /// failure rolls back only names inserted by this batch.
    pub fn register_tools(&self, registry: &mut ToolRegistry) -> Result<usize, Vec<String>> {
        register_mcp_tools(registry, &self.config.name, &self.tools)
    }

    async fn send_request(
        &mut self,
        method: &str,
        params: Option<serde_json::Value>,
    ) -> Result<serde_json::Value, String> {
        let id = self.next_id;
        self.next_id += 1;

        let request = JsonRpcRequest {
            jsonrpc: "2.0",
            id,
            method: method.to_string(),
            params,
        };
        let mut payload = serde_json::to_string(&request).map_err(|e| e.to_string())?;
        payload.push('\n');

        let mut stdin = self.stdin.lock().await;
        stdin
            .write_all(payload.as_bytes())
            .await
            .map_err(|e| e.to_string())?;
        stdin.flush().await.map_err(|e| e.to_string())?;
        drop(stdin);

        // Read response
        let mut stdout = self.stdout.lock().await;
        let mut line = String::new();
        stdout
            .read_line(&mut line)
            .await
            .map_err(|e| e.to_string())?;

        let response: JsonRpcResponse = serde_json::from_str(&line)
            .map_err(|e| format!("Invalid JSON-RPC response: {} (raw: {})", e, line.trim()))?;

        if let Some(error) = response.error {
            return Err(format!("MCP error: {}", error));
        }

        Ok(response.result.unwrap_or(serde_json::Value::Null))
    }
}

fn register_mcp_tools(
    registry: &mut ToolRegistry,
    server_name: &str,
    tools: &[McpTool],
) -> Result<usize, Vec<String>> {
    let existing = registry.security_catalog();
    let mut batch_names = std::collections::HashSet::new();
    let mut bindings = Vec::with_capacity(tools.len());
    let mut errors = Vec::new();

    // Convert and validate the complete discovery result before publishing any
    // binding. MCP metadata is untrusted, and a late invalid declaration must
    // not leave an executable prefix of the server's catalog installed.
    for tool in tools {
        match tool.to_binding(server_name) {
            Ok(binding) => {
                if !batch_names.insert(binding.name.clone()) {
                    errors.push(format!(
                        "MCP server '{server_name}' returned duplicate tool '{}'",
                        binding.name
                    ));
                } else if existing.contains_key(&binding.name) {
                    errors.push(format!(
                        "MCP tool '{}' conflicts with an existing registry binding",
                        binding.name
                    ));
                } else if let Err(error) = ToolRegistry::validate_binding(&binding) {
                    errors.push(format!("MCP tool '{}': {error}", binding.name));
                }
                bindings.push(binding);
            }
            Err(error) => errors.push(error),
        }
    }
    if !errors.is_empty() {
        return Err(errors);
    }

    register_validated_bindings_atomically(registry, bindings)
}

fn register_validated_bindings_atomically(
    registry: &mut ToolRegistry,
    bindings: Vec<ToolBinding>,
) -> Result<usize, Vec<String>> {
    let expected = bindings.len();
    let mut installed: Vec<String> = Vec::with_capacity(expected);
    for binding in bindings {
        let name = binding.name.clone();
        if let Err(error) = registry.register(binding) {
            for installed_name in installed.iter().rev() {
                registry.unregister(installed_name);
            }
            return Err(vec![format!(
                "MCP tool '{name}' could not be published; rolled back the batch: {error}"
            )]);
        }
        installed.push(name);
    }
    Ok(expected)
}

impl Drop for McpServer {
    fn drop(&mut self) {
        let _ = self.process.start_kill();
    }
}

/// Load MCP server configs from the config directory.
pub fn load_mcp_configs() -> Vec<McpServerConfig> {
    let config_path = dirs::config_dir()
        .unwrap_or_default()
        .join("ai-agent-os/mcp_servers.json");

    std::fs::read_to_string(&config_path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tools::{SecurityAction, ToolRegistrationError, ToolSecurity};

    fn declared_tool() -> McpTool {
        McpTool {
            name: "fetch".into(),
            description: "fetch a URL".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {"url": {"type": "string"}},
                "required": ["url"]
            }),
            security: Some(ToolSecurity::argument(SecurityAction::Network, "url")),
            resource_type: Some(ResourceType::Network),
            operation: Some("get".into()),
        }
    }

    #[tokio::test]
    async fn direct_host_mcp_launch_is_fail_closed() {
        let result = McpServer::connect(McpServerConfig {
            name: "unsafe-host-child".into(),
            command: "/bin/echo".into(),
            args: vec!["must-not-run".into()],
            env: HashMap::new(),
        })
        .await;
        let Err(error) = result else {
            panic!("direct host MCP launch unexpectedly succeeded");
        };
        assert!(error.contains("isolated MCP backend"));
    }

    #[test]
    fn mcp_binding_requires_every_local_security_extension() {
        let mut tool = declared_tool();
        assert!(tool.to_binding("remote").is_ok());

        tool.resource_type = None;
        assert!(tool
            .to_binding("remote")
            .unwrap_err()
            .contains("agentosResourceType"));
        tool = declared_tool();
        tool.operation = None;
        assert!(tool
            .to_binding("remote")
            .unwrap_err()
            .contains("agentosOperation"));
        tool = declared_tool();
        tool.security = None;
        assert!(tool
            .to_binding("remote")
            .unwrap_err()
            .contains("agentosSecurity"));
    }

    #[test]
    fn mcp_binding_cannot_disguise_network_as_filesystem_read() {
        let mut tool = declared_tool();
        tool.resource_type = Some(ResourceType::Application);
        tool.security = Some(ToolSecurity::argument(SecurityAction::Read, "url"));
        let registry = ToolRegistry::new();
        let error = registry
            .register(tool.to_binding("remote").unwrap())
            .unwrap_err();
        match error {
            ToolRegistrationError::ProviderTargetMismatch { .. }
            | ToolRegistrationError::ResourceActionMismatch { .. }
            | ToolRegistrationError::OperationActionMismatch { .. }
            | ToolRegistrationError::UnsupportedOperation { .. } => {}
            other => panic!("unexpected registration verdict: {other:?}"),
        }
    }

    #[test]
    fn mcp_registration_is_all_or_nothing_when_any_declaration_is_invalid() {
        let mut registry = ToolRegistry::new();
        let before = registry.security_catalog();
        let mut invalid = declared_tool();
        invalid.name = "invalid".into();
        invalid.security = None;

        let errors =
            register_mcp_tools(&mut registry, "remote", &[declared_tool(), invalid]).unwrap_err();
        assert!(errors
            .iter()
            .any(|error| error.contains("omitted required agentosSecurity")));
        assert_eq!(registry.security_catalog(), before);
        assert!(!registry.security_catalog().contains_key("mcp_remote_fetch"));
    }

    #[test]
    fn mcp_registration_rejects_duplicate_discovery_without_publishing() {
        let mut registry = ToolRegistry::new();
        let before = registry.security_catalog();

        let errors =
            register_mcp_tools(&mut registry, "remote", &[declared_tool(), declared_tool()])
                .unwrap_err();
        assert!(errors.iter().any(|error| error.contains("duplicate tool")));
        assert_eq!(registry.security_catalog(), before);
    }

    #[test]
    fn mcp_registration_rolls_back_a_late_registry_failure() {
        let mut registry = ToolRegistry::new();
        let before = registry.security_catalog();
        let fresh = {
            let mut tool = declared_tool();
            tool.name = "fresh".into();
            tool.to_binding("remote").unwrap()
        };
        let existing = declared_tool().to_binding("remote").unwrap();
        registry.register(existing.clone()).unwrap();

        let errors = register_validated_bindings_atomically(&mut registry, vec![fresh, existing])
            .unwrap_err();
        assert!(errors.iter().any(|error| error.contains("rolled back")));
        assert!(!registry.security_catalog().contains_key("mcp_remote_fresh"));
        assert!(registry.security_catalog().contains_key("mcp_remote_fetch"));
        assert_eq!(registry.security_catalog().len(), before.len() + 1);
    }

    #[test]
    fn valid_mcp_catalog_is_published_as_one_complete_batch() {
        let mut registry = ToolRegistry::new();
        let before = registry.security_catalog().len();
        let mut second = declared_tool();
        second.name = "post".into();
        second.operation = Some("post".into());

        assert_eq!(
            register_mcp_tools(&mut registry, "remote", &[declared_tool(), second]).unwrap(),
            2
        );
        let catalog = registry.security_catalog();
        assert_eq!(catalog.len(), before + 2);
        assert!(catalog.contains_key("mcp_remote_fetch"));
        assert!(catalog.contains_key("mcp_remote_post"));
    }

    #[test]
    fn mcp_config_debug_redacts_environment_and_arguments() {
        let config = McpServerConfig {
            name: "remote".into(),
            command: "server".into(),
            args: vec!["--token=argument-secret".into()],
            env: HashMap::from([("API_KEY".into(), "environment-secret".into())]),
        };
        let rendered = format!("{config:?}");
        assert!(!rendered.contains("argument-secret"));
        assert!(!rendered.contains("environment-secret"));
        assert!(rendered.contains("API_KEY"));
    }
}
