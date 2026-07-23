//! MCP (Model Context Protocol) Client — connect to any MCP tool server.
//!
//! Implements the MCP client protocol (JSON-RPC over stdio) to discover
//! and call tools from external MCP servers.

use std::collections::HashMap;
use std::process::Stdio;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::Mutex;

use crate::resources::ResourceType;
use crate::tools::{ToolBinding, ToolRegistry, ToolSecurity};

/// MCP server configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpServerConfig {
    pub name: String,
    pub command: String,
    pub args: Vec<String>,
    #[serde(default)]
    pub env: HashMap<String, String>,
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
    /// Start an MCP server process and initialize the connection.
    pub async fn connect(config: McpServerConfig) -> Result<Self, String> {
        let mut cmd = Command::new(&config.command);
        cmd.args(&config.args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());

        for (k, v) in &config.env {
            cmd.env(k, v);
        }

        let mut process = cmd
            .spawn()
            .map_err(|e| format!("Failed to start MCP server '{}': {}", config.name, e))?;

        let stdin = process.stdin.take().ok_or("No stdin")?;
        let stdout = process.stdout.take().ok_or("No stdout")?;

        let mut server = Self {
            config,
            process,
            stdin: Arc::new(Mutex::new(stdin)),
            stdout: Arc::new(Mutex::new(BufReader::new(stdout))),
            tools: Vec::new(),
            next_id: 1,
        };

        // Initialize
        server
            .send_request(
                "initialize",
                Some(serde_json::json!({
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {"name": "ai-agent-os", "version": "0.1.0"}
                })),
            )
            .await?;

        // Send initialized notification
        server
            .send_notification("notifications/initialized")
            .await?;

        // Discover tools
        let tools_response = server.send_request("tools/list", None).await?;
        if let Some(tools_arr) = tools_response.get("tools").and_then(|t| t.as_array()) {
            server.tools = tools_arr
                .iter()
                .filter_map(|t| {
                    Some(McpTool {
                        name: t.get("name")?.as_str()?.to_string(),
                        description: t
                            .get("description")
                            .and_then(|d| d.as_str())
                            .unwrap_or("")
                            .to_string(),
                        input_schema: t
                            .get("inputSchema")
                            .cloned()
                            .unwrap_or(serde_json::json!({})),
                        security: t
                            .get("agentosSecurity")
                            .cloned()
                            .and_then(|value| serde_json::from_value(value).ok()),
                        resource_type: t
                            .get("agentosResourceType")
                            .cloned()
                            .and_then(|value| serde_json::from_value(value).ok()),
                        operation: t
                            .get("agentosOperation")
                            .and_then(|value| value.as_str())
                            .map(str::to_string),
                    })
                })
                .collect();
        }

        Ok(server)
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

    /// Register this server's tools in a ToolRegistry.
    pub fn register_tools(&self, registry: &mut ToolRegistry) -> Result<usize, Vec<String>> {
        let mut bindings = Vec::new();
        let mut errors = Vec::new();
        for tool in &self.tools {
            match tool.to_binding(&self.config.name) {
                Ok(binding) => bindings.push(binding),
                Err(error) => errors.push(error),
            }
        }
        if !errors.is_empty() {
            return Err(errors);
        }
        for binding in bindings {
            if let Err(error) = registry.register(binding) {
                errors.push(error.to_string());
            }
        }
        if errors.is_empty() {
            Ok(self.tools.len())
        } else {
            Err(errors)
        }
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

    async fn send_notification(&mut self, method: &str) -> Result<(), String> {
        let notification = serde_json::json!({"jsonrpc": "2.0", "method": method});
        let mut payload = serde_json::to_string(&notification).map_err(|e| e.to_string())?;
        payload.push('\n');

        let mut stdin = self.stdin.lock().await;
        stdin
            .write_all(payload.as_bytes())
            .await
            .map_err(|e| e.to_string())?;
        stdin.flush().await.map_err(|e| e.to_string())?;
        Ok(())
    }
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
    use crate::tools::{SecurityAction, ToolSecurity};

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
        assert!(error.to_string().contains("contradicts resource type"));
    }
}
