//! Tool Registry — maps tool names to ResourceBroker operations.

use std::collections::HashMap;

use crate::connector::{ToolCall, ToolDefinition};
use crate::resources::{ResourceRequest, ResourceType};
use crate::AgentId;

/// Binding between a tool name and a resource operation.
#[derive(Debug, Clone)]
pub struct ToolBinding {
    pub name: String,
    pub description: String,
    pub parameters_schema: serde_json::Value,
    pub resource_type: ResourceType,
    pub operation: String,
}

/// Registry of available tools that agents can use.
pub struct ToolRegistry {
    tools: HashMap<String, ToolBinding>,
    /// Command templates for custom tools: name -> (command, args_template)
    command_templates: HashMap<String, (String, Vec<String>)>,
}

impl ToolRegistry {
    pub fn new() -> Self {
        let mut registry = Self { tools: HashMap::new(), command_templates: HashMap::new() };
        registry.register_builtins();
        registry
    }

    /// Register a tool binding.
    pub fn register(&mut self, binding: ToolBinding) {
        self.tools.insert(binding.name.clone(), binding);
    }

    /// Unregister a tool by name.
    pub fn unregister(&mut self, name: &str) {
        self.tools.remove(name);
        self.command_templates.remove(name);
    }

    /// Register a command template for a custom tool.
    pub fn register_command_template(&mut self, name: &str, command: &str, args_template: &[String]) {
        self.command_templates.insert(name.to_string(), (command.to_string(), args_template.to_vec()));
    }

    /// Generate LLM-compatible tool definitions.
    pub fn definitions(&self) -> Vec<ToolDefinition> {
        self.tools.values().map(|b| ToolDefinition {
            name: b.name.clone(),
            description: b.description.clone(),
            parameters: b.parameters_schema.clone(),
        }).collect()
    }

    /// Resolve a tool call into a ResourceRequest.
    pub fn resolve(&self, agent_id: AgentId, tool_call: &ToolCall) -> Option<ResourceRequest> {
        let binding = self.tools.get(&tool_call.name)?;

        // Check if this is a custom tool with a command template
        if let Some((command, args_template)) = self.command_templates.get(&tool_call.name) {
            let args: Vec<String> = args_template.iter().map(|tmpl| {
                let mut result = tmpl.clone();
                if let Some(obj) = tool_call.arguments.as_object() {
                    for (key, val) in obj {
                        let placeholder = format!("{{{}}}", key);
                        let value = match val.as_str() {
                            Some(s) => s.to_string(),
                            None => val.to_string(),
                        };
                        result = result.replace(&placeholder, &value);
                    }
                }
                result
            }).collect();
            return Some(ResourceRequest {
                agent_id,
                resource_type: ResourceType::Application,
                operation: "launch".into(),
                parameters: serde_json::json!({"command": command, "args": args}),
                sandbox_context: None,
            });
        }

        // Built-in tool resolution with special mappings
        let parameters = match tool_call.name.as_str() {
            "search_files" => {
                let dir = tool_call.arguments.get("directory").and_then(|v| v.as_str()).unwrap_or(".");
                let pattern = tool_call.arguments.get("pattern").and_then(|v| v.as_str()).unwrap_or("*");
                serde_json::json!({"command": "find", "args": [dir, "-name", pattern, "-type", "f"]})
            }
            "git_status" => {
                let dir = tool_call.arguments.get("directory").and_then(|v| v.as_str()).unwrap_or(".");
                serde_json::json!({"command": "git", "args": ["-C", dir, "status", "--short"]})
            }
            "create_directory" => {
                let path = tool_call.arguments.get("path").and_then(|v| v.as_str()).unwrap_or("");
                serde_json::json!({"command": "mkdir", "args": ["-p", path]})
            }
            _ => tool_call.arguments.clone(),
        };

        // create_directory uses Application provider (mkdir -p)
        let (resource_type, operation) = match tool_call.name.as_str() {
            "create_directory" => (ResourceType::Application, "launch".to_string()),
            _ => (binding.resource_type.clone(), binding.operation.clone()),
        };

        Some(ResourceRequest {
            agent_id,
            resource_type,
            operation,
            parameters,
            sandbox_context: None,
        })
    }

    /// Check if a tool exists.
    pub fn has_tool(&self, name: &str) -> bool {
        self.tools.contains_key(name)
    }

    fn register_builtins(&mut self) {
        self.register(ToolBinding {
            name: "read_file".into(),
            description: "Read the contents of a file at the given path".into(),
            parameters_schema: serde_json::json!({
                "type": "object",
                "properties": {"path": {"type": "string", "description": "File path to read"}},
                "required": ["path"]
            }),
            resource_type: ResourceType::Filesystem,
            operation: "read".into(),
        });

        self.register(ToolBinding {
            name: "write_file".into(),
            description: "Write content to a file at the given path".into(),
            parameters_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "File path to write"},
                    "content": {"type": "string", "description": "Content to write"}
                },
                "required": ["path", "content"]
            }),
            resource_type: ResourceType::Filesystem,
            operation: "write".into(),
        });

        self.register(ToolBinding {
            name: "list_directory".into(),
            description: "List files and directories at the given path".into(),
            parameters_schema: serde_json::json!({
                "type": "object",
                "properties": {"path": {"type": "string", "description": "Directory path to list"}},
                "required": ["path"]
            }),
            resource_type: ResourceType::Filesystem,
            operation: "list".into(),
        });

        self.register(ToolBinding {
            name: "http_get".into(),
            description: "Make an HTTP GET request to a URL".into(),
            parameters_schema: serde_json::json!({
                "type": "object",
                "properties": {"url": {"type": "string", "description": "URL to fetch"}},
                "required": ["url"]
            }),
            resource_type: ResourceType::Network,
            operation: "get".into(),
        });

        self.register(ToolBinding {
            name: "run_command".into(),
            description: "Run a shell command and return its output".into(),
            parameters_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "command": {"type": "string", "description": "Command to execute"},
                    "args": {"type": "array", "items": {"type": "string"}, "description": "Command arguments"}
                },
                "required": ["command"]
            }),
            resource_type: ResourceType::Application,
            operation: "launch".into(),
        });

        self.register(ToolBinding {
            name: "search_files".into(),
            description: "Search for files matching a pattern recursively in a directory".into(),
            parameters_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "directory": {"type": "string", "description": "Directory to search in"},
                    "pattern": {"type": "string", "description": "Filename pattern to match (e.g., '*.rs', 'test*')"}
                },
                "required": ["directory", "pattern"]
            }),
            resource_type: ResourceType::Application,
            operation: "launch".into(),
        });

        self.register(ToolBinding {
            name: "git_status".into(),
            description: "Get the git status of a repository".into(),
            parameters_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "directory": {"type": "string", "description": "Path to the git repository"}
                },
                "required": ["directory"]
            }),
            resource_type: ResourceType::Application,
            operation: "launch".into(),
        });

        self.register(ToolBinding {
            name: "create_directory".into(),
            description: "Create a directory (and parent directories if needed)".into(),
            parameters_schema: serde_json::json!({
                "type": "object",
                "properties": {"path": {"type": "string", "description": "Directory path to create"}},
                "required": ["path"]
            }),
            resource_type: ResourceType::Filesystem,
            operation: "create_dir".into(),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_has_builtins() {
        let reg = ToolRegistry::new();
        assert!(reg.has_tool("read_file"));
        assert!(reg.has_tool("write_file"));
        assert!(reg.has_tool("list_directory"));
        assert!(reg.has_tool("http_get"));
        assert!(reg.has_tool("run_command"));
    }

    #[test]
    fn definitions_generates_valid_tools() {
        let reg = ToolRegistry::new();
        let defs = reg.definitions();
        assert!(defs.len() >= 5);
        let read = defs.iter().find(|d| d.name == "read_file").unwrap();
        assert!(read.description.contains("Read"));
        assert!(read.parameters["properties"]["path"].is_object());
    }

    #[test]
    fn resolve_maps_tool_call_to_request() {
        let reg = ToolRegistry::new();
        let agent_id = uuid::Uuid::new_v4();
        let tool_call = ToolCall {
            id: "call_1".into(),
            name: "read_file".into(),
            arguments: serde_json::json!({"path": "/tmp/test.txt"}),
        };

        let req = reg.resolve(agent_id, &tool_call).unwrap();
        assert_eq!(req.resource_type, ResourceType::Filesystem);
        assert_eq!(req.operation, "read");
        assert_eq!(req.parameters["path"], "/tmp/test.txt");
        assert_eq!(req.agent_id, agent_id);
    }

    #[test]
    fn resolve_unknown_tool_returns_none() {
        let reg = ToolRegistry::new();
        let tool_call = ToolCall { id: "x".into(), name: "nonexistent".into(), arguments: serde_json::json!({}) };
        assert!(reg.resolve(uuid::Uuid::new_v4(), &tool_call).is_none());
    }

    #[test]
    fn register_and_unregister_custom_tool() {
        let mut reg = ToolRegistry::new();
        reg.register(ToolBinding {
            name: "custom_tool".into(),
            description: "A custom tool".into(),
            parameters_schema: serde_json::json!({}),
            resource_type: ResourceType::Browser,
            operation: "navigate".into(),
        });
        assert!(reg.has_tool("custom_tool"));
        reg.unregister("custom_tool");
        assert!(!reg.has_tool("custom_tool"));
    }
}
