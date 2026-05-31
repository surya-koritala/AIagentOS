//! Tool Registry — maps tool names to ResourceBroker operations.

use dashmap::DashMap;

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
///
/// Uses interior mutability (`DashMap`) so tools can be registered on a shared
/// `Arc<ToolRegistry>` at runtime: the kernel registers built-ins, then the
/// advanced/git/edit tool sets, and later subsystems (MCP, custom tools) can
/// extend the same registry without rebuilding it.
pub struct ToolRegistry {
    tools: DashMap<String, ToolBinding>,
    /// Command templates for custom tools: name -> (command, args_template)
    command_templates: DashMap<String, (String, Vec<String>)>,
}

impl Default for ToolRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ToolRegistry {
    pub fn new() -> Self {
        let registry = Self {
            tools: DashMap::new(),
            command_templates: DashMap::new(),
        };
        registry.register_builtins();
        registry
    }

    /// Register a tool binding.
    pub fn register(&self, binding: ToolBinding) {
        self.tools.insert(binding.name.clone(), binding);
    }

    /// Unregister a tool by name.
    pub fn unregister(&self, name: &str) {
        self.tools.remove(name);
        self.command_templates.remove(name);
    }

    /// Register a command template for a custom tool.
    pub fn register_command_template(&self, name: &str, command: &str, args_template: &[String]) {
        self.command_templates.insert(
            name.to_string(),
            (command.to_string(), args_template.to_vec()),
        );
    }

    /// Generate LLM-compatible tool definitions.
    pub fn definitions(&self) -> Vec<ToolDefinition> {
        self.tools
            .iter()
            .map(|b| ToolDefinition {
                name: b.name.clone(),
                description: b.description.clone(),
                parameters: b.parameters_schema.clone(),
            })
            .collect()
    }

    /// Resolve a tool call into a ResourceRequest.
    pub fn resolve(&self, agent_id: AgentId, tool_call: &ToolCall) -> Option<ResourceRequest> {
        // Read out what we need and drop the `tools` shard read-lock immediately,
        // so resolution (and the command-template lookup below) doesn't hold it
        // and block a concurrent register/unregister on the same shard.
        let (binding_rt, binding_op) = {
            let binding = self.tools.get(&tool_call.name)?;
            (binding.resource_type.clone(), binding.operation.clone())
        };

        // Check if this is a custom tool with a command template
        if let Some(entry) = self.command_templates.get(&tool_call.name) {
            let (command, args_template) = entry.value();
            let args: Vec<String> = args_template
                .iter()
                .map(|tmpl| {
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
                })
                .collect();
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
                let dir = tool_call
                    .arguments
                    .get("directory")
                    .and_then(|v| v.as_str())
                    .unwrap_or(".");
                let pattern = tool_call
                    .arguments
                    .get("pattern")
                    .and_then(|v| v.as_str())
                    .unwrap_or("*");
                serde_json::json!({"command": "find", "args": [dir, "-name", pattern, "-type", "f"]})
            }
            "git_status" => {
                let dir = tool_call
                    .arguments
                    .get("directory")
                    .and_then(|v| v.as_str())
                    .unwrap_or(".");
                serde_json::json!({"command": "git", "args": ["-C", dir, "status", "--short"]})
            }
            "create_directory" => {
                let path = tool_call
                    .arguments
                    .get("path")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                serde_json::json!({"command": "mkdir", "args": ["-p", path]})
            }
            // IPC tools: inject the caller's id as the sender (the LLM only
            // supplies the recipient / nothing). Recipient is addressed by id.
            "send_agent_message" => serde_json::json!({
                "from": agent_id.to_string(),
                "to": tool_call.arguments.get("to").and_then(|v| v.as_str()).unwrap_or(""),
                "payload": tool_call
                    .arguments
                    .get("message")
                    .cloned()
                    .unwrap_or(serde_json::Value::Null),
            }),
            "check_inbox" => serde_json::json!({"agent": agent_id.to_string()}),
            "discover_agents" => serde_json::json!({"viewer": agent_id.to_string()}),
            // Delegation: inject the caller as the delegator; recipient + task
            // come from the args. (status/complete pass {task_id} through.)
            "delegate_task" => serde_json::json!({
                "from": agent_id.to_string(),
                "to": tool_call.arguments.get("to").and_then(|v| v.as_str()).unwrap_or(""),
                "description": tool_call.arguments.get("task").and_then(|v| v.as_str()).unwrap_or(""),
            }),
            _ => tool_call.arguments.clone(),
        };

        // create_directory uses Application provider (mkdir -p)
        let (resource_type, operation) = match tool_call.name.as_str() {
            "create_directory" => (ResourceType::Application, "launch".to_string()),
            _ => (binding_rt, binding_op),
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

    fn register_builtins(&self) {
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
        let tool_call = ToolCall {
            id: "x".into(),
            name: "nonexistent".into(),
            arguments: serde_json::json!({}),
        };
        assert!(reg.resolve(uuid::Uuid::new_v4(), &tool_call).is_none());
    }

    #[test]
    fn register_and_unregister_custom_tool() {
        let reg = ToolRegistry::new();
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

    #[test]
    fn registry_is_runtime_extensible_via_shared_ref() {
        // #10 keystone: register_* take &self, so tools can be added to a
        // shared Arc<ToolRegistry> after construction (the path the kernel and
        // future MCP/custom-tool registration use).
        let reg = std::sync::Arc::new(ToolRegistry::new());
        assert!(!reg.has_tool("git_commit"));
        reg.register_advanced_tools();
        reg.register_git_tools();
        crate::editing::register_edit_tools(&reg);
        for t in [
            "browse_url",
            "git_commit",
            "git_diff",
            "edit_file",
            "create_file",
            "delete_file",
        ] {
            assert!(reg.has_tool(t), "expected tool {t} after registration");
        }
    }

    #[test]
    fn edit_file_resolves_to_filesystem_edit() {
        let reg = ToolRegistry::new();
        crate::editing::register_edit_tools(&reg);
        let tc = ToolCall {
            id: "e".into(),
            name: "edit_file".into(),
            arguments: serde_json::json!({"path": "/tmp/x", "search": "a", "replace": "b"}),
        };
        let req = reg.resolve(uuid::Uuid::new_v4(), &tc).unwrap();
        assert_eq!(req.resource_type, ResourceType::Filesystem);
        assert_eq!(req.operation, "edit");
    }

    #[test]
    fn ipc_tools_register_and_inject_sender() {
        let reg = ToolRegistry::new();
        reg.register_ipc_tools();
        assert!(reg.has_tool("send_agent_message"));
        assert!(reg.has_tool("check_inbox"));

        let from = uuid::Uuid::new_v4();
        let to = uuid::Uuid::new_v4();
        let req = reg
            .resolve(
                from,
                &ToolCall {
                    id: "s".into(),
                    name: "send_agent_message".into(),
                    arguments: serde_json::json!({"to": to.to_string(), "message": {"hi": 1}}),
                },
            )
            .unwrap();
        assert_eq!(req.resource_type, ResourceType::Ipc);
        assert_eq!(req.operation, "send");
        // Caller id is injected as the sender; recipient comes from the args.
        assert_eq!(req.parameters["from"], from.to_string());
        assert_eq!(req.parameters["to"], to.to_string());
        assert_eq!(req.parameters["payload"]["hi"], 1);

        let inbox = reg
            .resolve(
                from,
                &ToolCall {
                    id: "c".into(),
                    name: "check_inbox".into(),
                    arguments: serde_json::json!({}),
                },
            )
            .unwrap();
        assert_eq!(inbox.operation, "receive");
        assert_eq!(inbox.parameters["agent"], from.to_string());
    }
}

// Sprint 3 tools are registered separately via register_advanced_tools()
impl ToolRegistry {
    /// Register advanced tools (delegation, web browsing).
    pub fn register_advanced_tools(&self) {
        self.register(ToolBinding {
            name: "browse_url".into(),
            description: "Fetch a URL and extract readable text content (HTML stripped)".into(),
            parameters_schema: serde_json::json!({
                "type": "object",
                "properties": {"url": {"type": "string", "description": "URL to browse"}},
                "required": ["url"]
            }),
            resource_type: ResourceType::Network,
            operation: "browse".into(),
        });
    }
}

// Git tools registered via register_git_tools()
impl ToolRegistry {
    pub fn register_git_tools(&self) {
        self.register(ToolBinding {
            name: "git_commit".into(),
            description: "Commit tracked changes with the given message (git commit -a -m)".into(),
            parameters_schema: serde_json::json!({
                "type": "object",
                "properties": {"message": {"type": "string", "description": "Commit message"}},
                "required": ["message"]
            }),
            resource_type: ResourceType::Application,
            operation: "launch".into(),
        });
        // `-a -m {message}` so the tool actually commits (the previous template
        // was `git add -A`, which only staged and never created a commit).
        self.register_command_template(
            "git_commit",
            "git",
            &[
                "commit".into(),
                "-a".into(),
                "-m".into(),
                "{message}".into(),
            ],
        );

        self.register(ToolBinding {
            name: "git_diff".into(),
            description: "Show the current git diff (unstaged changes)".into(),
            parameters_schema: serde_json::json!({"type": "object", "properties": {}}),
            resource_type: ResourceType::Application,
            operation: "launch".into(),
        });
        self.register_command_template("git_diff", "git", &["diff".into()]);
    }
}

// Inter-agent messaging tools registered via register_ipc_tools()
impl ToolRegistry {
    pub fn register_ipc_tools(&self) {
        self.register(ToolBinding {
            name: "send_agent_message".into(),
            description:
                "Send a JSON message to another agent by its agent id. Delivery requires sharing \
                 a namespace with the recipient."
                    .into(),
            parameters_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "to": {"type": "string", "description": "Recipient agent name or id (UUID)"},
                    "message": {"description": "JSON payload to deliver"}
                },
                "required": ["to", "message"]
            }),
            resource_type: ResourceType::Ipc,
            operation: "send".into(),
        });
        self.register(ToolBinding {
            name: "check_inbox".into(),
            description: "Receive the next pending message from your agent inbox (empty if none)."
                .into(),
            parameters_schema: serde_json::json!({"type": "object", "properties": {}}),
            resource_type: ResourceType::Ipc,
            operation: "receive".into(),
        });
        self.register(ToolBinding {
            name: "delegate_task".into(),
            description: "Delegate a task to another agent by id; returns a task_id you can poll \
                          with delegation_status. The recipient must share a namespace with you."
                .into(),
            parameters_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "to": {"type": "string", "description": "Delegate-to agent name or id (UUID)"},
                    "task": {"type": "string", "description": "Task description"}
                },
                "required": ["to", "task"]
            }),
            resource_type: ResourceType::Ipc,
            operation: "delegate".into(),
        });
        self.register(ToolBinding {
            name: "delegation_status".into(),
            description: "Check a delegated task's status by task_id \
                          (pending/in_progress/completed/failed/unknown)."
                .into(),
            parameters_schema: serde_json::json!({
                "type": "object",
                "properties": {"task_id": {"type": "string", "description": "Id from delegate_task"}},
                "required": ["task_id"]
            }),
            resource_type: ResourceType::Ipc,
            operation: "delegation_status".into(),
        });
        self.register(ToolBinding {
            name: "complete_delegation".into(),
            description: "Mark a task delegated to you (by its task_id) as completed.".into(),
            parameters_schema: serde_json::json!({
                "type": "object",
                "properties": {"task_id": {"type": "string", "description": "Task id to complete"}},
                "required": ["task_id"]
            }),
            resource_type: ResourceType::Ipc,
            operation: "complete_delegation".into(),
        });
        self.register(ToolBinding {
            name: "discover_agents".into(),
            description: "List the other agents you can address (name, id, state) so you can \
                          send_agent_message or delegate_task to them by name or id."
                .into(),
            parameters_schema: serde_json::json!({"type": "object", "properties": {}}),
            resource_type: ResourceType::Ipc,
            operation: "discover".into(),
        });
    }
}
