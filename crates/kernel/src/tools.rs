//! Tool Registry — maps tool names to ResourceBroker operations.

use dashmap::DashMap;
use std::collections::HashMap;

use crate::agent_struct::CapabilitySet;
use crate::connector::{ToolCall, ToolDefinition};
use crate::resources::{ResourceRequest, ResourceType};
use crate::AgentId;

/// Security action enforced for a tool. This typed value is the declaration
/// used for both capability and MAC decisions; callers must not infer it from
/// a tool's name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SecurityAction {
    Read,
    Write,
    Delete,
    Network,
    Execute,
    Ipc,
    BrowserAutomation,
    CredentialAccess,
    PackageInstall,
}

impl SecurityAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::Delete => "delete",
            Self::Network => "net",
            Self::Execute => "exec",
            Self::Ipc => "ipc",
            Self::BrowserAutomation => "browser",
            Self::CredentialAccess => "credential",
            Self::PackageInstall => "package-install",
        }
    }

    fn mandatory_capabilities(self) -> Vec<u64> {
        match self {
            Self::Read | Self::Ipc => Vec::new(),
            Self::Write => vec![CapabilitySet::CAP_FILE_WRITE],
            Self::Delete => vec![CapabilitySet::CAP_FILE_DELETE],
            Self::Network | Self::BrowserAutomation => vec![CapabilitySet::CAP_NET_ACCESS],
            Self::Execute => vec![CapabilitySet::CAP_EXEC],
            Self::CredentialAccess => vec![CapabilitySet::CAP_ADMIN],
            Self::PackageInstall => vec![CapabilitySet::CAP_EXEC, CapabilitySet::CAP_ADMIN],
        }
    }

    fn supports_resource(self, resource_type: &ResourceType) -> bool {
        match resource_type {
            ResourceType::Filesystem => matches!(self, Self::Read | Self::Write | Self::Delete),
            ResourceType::Network => self == Self::Network,
            ResourceType::Browser => self == Self::BrowserAutomation,
            ResourceType::Application => matches!(
                self,
                Self::Execute | Self::CredentialAccess | Self::PackageInstall
            ),
            ResourceType::Ipc => self == Self::Ipc,
            // Peripheral tools can read device state, write device state, or
            // access a protected credential/device. Their provider still
            // supplies the concrete operation and sandbox classification.
            ResourceType::Peripheral => {
                matches!(self, Self::Read | Self::Write | Self::CredentialAccess)
            }
        }
    }
}

/// How the MAC resource string is obtained from untrusted tool arguments.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "kebab-case")]
pub enum ResourceExtractor {
    Argument(String),
    Constant(String),
}

/// Visibility of a declaration before any concrete namespace id is assigned.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NamespaceVisibility {
    Global,
    CallerNamespace,
}

/// Human approval required before a high-risk provider invocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ApprovalPolicy {
    None,
    User,
    Administrator,
}

impl ApprovalPolicy {
    pub(crate) fn satisfies(self, required: Self) -> bool {
        matches!(
            (self, required),
            (Self::Administrator, Self::Administrator | Self::User)
                | (Self::User, Self::User)
                | (_, Self::None)
        )
    }
}

/// Whether provider execution must run inside a configured sandbox boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SandboxRequirement {
    NotRequired,
    Required,
}

/// Complete authorization contract carried by every executable tool.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolSecurity {
    pub action: SecurityAction,
    pub required_capabilities: Vec<u64>,
    pub resource_extractor: ResourceExtractor,
    pub namespace_visibility: NamespaceVisibility,
    pub approval_policy: ApprovalPolicy,
    pub sandbox_requirement: SandboxRequirement,
}

impl ToolSecurity {
    pub fn new(action: SecurityAction, resource_extractor: ResourceExtractor) -> Self {
        Self {
            action,
            required_capabilities: action.mandatory_capabilities(),
            resource_extractor,
            namespace_visibility: NamespaceVisibility::Global,
            approval_policy: ApprovalPolicy::None,
            sandbox_requirement: SandboxRequirement::NotRequired,
        }
    }

    pub fn argument(action: SecurityAction, argument: &str) -> Self {
        Self::new(action, ResourceExtractor::Argument(argument.to_string()))
    }

    pub fn constant(action: SecurityAction, resource: &str) -> Self {
        Self::new(action, ResourceExtractor::Constant(resource.to_string()))
    }

    pub fn with_approval(mut self, approval: ApprovalPolicy) -> Self {
        self.approval_policy = approval;
        self
    }

    pub fn with_capability(mut self, capability: u64) -> Self {
        if !self.required_capabilities.contains(&capability) {
            self.required_capabilities.push(capability);
        }
        self
    }

    pub fn sandboxed(mut self) -> Self {
        self.sandbox_requirement = SandboxRequirement::Required;
        self
    }

    pub fn caller_namespace(mut self) -> Self {
        self.namespace_visibility = NamespaceVisibility::CallerNamespace;
        self
    }

    pub fn extract_resource(&self, arguments: &serde_json::Value) -> Result<String, String> {
        match &self.resource_extractor {
            ResourceExtractor::Constant(value) if !value.trim().is_empty() => Ok(value.clone()),
            ResourceExtractor::Constant(_) => Err("constant resource cannot be empty".into()),
            ResourceExtractor::Argument(name) => arguments
                .get(name)
                .and_then(|value| value.as_str())
                .filter(|value| !value.trim().is_empty())
                .map(str::to_string)
                .ok_or_else(|| format!("resource argument '{name}' must be a non-empty string")),
        }
    }

    fn summary(&self) -> String {
        let capabilities = if self.required_capabilities.is_empty() {
            "none".to_string()
        } else {
            self.required_capabilities
                .iter()
                .map(|cap| format!("0x{cap:x}"))
                .collect::<Vec<_>>()
                .join(",")
        };
        format!(
            "action={}; capabilities={capabilities}; approval={:?}; sandbox={:?}; visibility={:?}",
            self.action.as_str(),
            self.approval_policy,
            self.sandbox_requirement,
            self.namespace_visibility
        )
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ToolRegistrationError {
    #[error("tool name and description are required")]
    MissingIdentity,
    #[error("tool '{0}' is already registered; unregister it explicitly before replacement")]
    DuplicateName(String),
    #[error("tool parameters must be an object JSON schema")]
    InvalidSchema,
    #[error("tool resource operation is required")]
    MissingOperation,
    #[error("resource extractor argument '{0}' is not declared in the parameter schema")]
    MissingResourceArgument(String),
    #[error("resource extractor argument '{0}' must be a required string parameter")]
    InvalidResourceArgument(String),
    #[error("constant resource cannot be empty")]
    EmptyConstantResource,
    #[error("capability 0x{0:x} is unknown, combined, or duplicated")]
    InvalidCapability(u64),
    #[error("security action {action} contradicts resource type {resource_type:?}")]
    ResourceActionMismatch {
        action: &'static str,
        resource_type: ResourceType,
    },
    #[error("caller-namespace visibility requires an IPC provider or a concrete kernel namespace binding")]
    UnboundNamespace,
    #[error("security action {action} requires capability 0x{capability:x}")]
    MissingCapability {
        action: &'static str,
        capability: u64,
    },
    #[error("{0} requires explicit user or administrator approval")]
    MissingApproval(&'static str),
    #[error("{0} requires administrator approval")]
    MissingAdministratorApproval(&'static str),
    #[error("{0} must execute in a sandbox")]
    MissingSandbox(&'static str),
}

/// Binding between a tool name and a resource operation.
#[derive(Debug, Clone)]
pub struct ToolBinding {
    pub name: String,
    pub description: String,
    pub parameters_schema: serde_json::Value,
    pub resource_type: ResourceType,
    pub operation: String,
    pub security: ToolSecurity,
}

/// Security inputs prepared once for every public execution entry point.
/// Keeping estimation and resource extraction here prevents the executor,
/// JSON syscall wire, MCP server, and SDK-backed wire client from drifting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedToolCall {
    pub security: ToolSecurity,
    pub resource: String,
    pub estimated_tokens: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToolAuthorizationError {
    InvalidDeclaration(String),
    Denied(crate::syscall_gate::GateDenial),
}

impl std::fmt::Display for ToolAuthorizationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidDeclaration(error) => formatter.write_str(error),
            Self::Denied(denial) => formatter.write_str(&denial.message()),
        }
    }
}

impl std::error::Error for ToolAuthorizationError {}

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

    /// Validate and register a tool binding. Untrusted/custom declarations are
    /// rejected before they become visible to an LLM or executable provider.
    pub fn register(&self, binding: ToolBinding) -> Result<(), ToolRegistrationError> {
        Self::validate_binding_with_scope(&binding, false)?;
        let name = binding.name.clone();
        match self.tools.entry(name.clone()) {
            dashmap::mapref::entry::Entry::Vacant(entry) => {
                entry.insert(binding);
                Ok(())
            }
            dashmap::mapref::entry::Entry::Occupied(_) => {
                Err(ToolRegistrationError::DuplicateName(name))
            }
        }
    }

    pub fn validate_binding(binding: &ToolBinding) -> Result<(), ToolRegistrationError> {
        Self::validate_binding_with_scope(binding, false)
    }

    /// Kernel-only half of atomic namespace registration. The caller must tag
    /// the same tool name in `SyscallGate` before publishing this binding.
    pub(crate) fn register_namespace_scoped(
        &self,
        binding: ToolBinding,
    ) -> Result<(), ToolRegistrationError> {
        Self::validate_binding_with_scope(&binding, true)?;
        let name = binding.name.clone();
        match self.tools.entry(name.clone()) {
            dashmap::mapref::entry::Entry::Vacant(entry) => {
                entry.insert(binding);
                Ok(())
            }
            dashmap::mapref::entry::Entry::Occupied(_) => {
                Err(ToolRegistrationError::DuplicateName(name))
            }
        }
    }

    fn validate_binding_with_scope(
        binding: &ToolBinding,
        has_concrete_namespace: bool,
    ) -> Result<(), ToolRegistrationError> {
        if binding.name.trim().is_empty() || binding.description.trim().is_empty() {
            return Err(ToolRegistrationError::MissingIdentity);
        }
        if binding.operation.trim().is_empty() {
            return Err(ToolRegistrationError::MissingOperation);
        }
        let schema = binding
            .parameters_schema
            .as_object()
            .filter(|schema| {
                schema.get("type").and_then(serde_json::Value::as_str) == Some("object")
            })
            .ok_or(ToolRegistrationError::InvalidSchema)?;
        let properties = schema
            .get("properties")
            .and_then(serde_json::Value::as_object)
            .ok_or(ToolRegistrationError::InvalidSchema)?;
        match &binding.security.resource_extractor {
            ResourceExtractor::Argument(argument) => {
                let Some(property) = properties.get(argument) else {
                    return Err(ToolRegistrationError::MissingResourceArgument(
                        argument.clone(),
                    ));
                };
                let required = schema
                    .get("required")
                    .and_then(serde_json::Value::as_array)
                    .is_some_and(|required| {
                        required
                            .iter()
                            .any(|value| value.as_str() == Some(argument.as_str()))
                    });
                if argument.trim().is_empty()
                    || property.get("type").and_then(serde_json::Value::as_str) != Some("string")
                    || !required
                {
                    return Err(ToolRegistrationError::InvalidResourceArgument(
                        argument.clone(),
                    ));
                }
            }
            ResourceExtractor::Constant(resource) if resource.trim().is_empty() => {
                return Err(ToolRegistrationError::EmptyConstantResource);
            }
            ResourceExtractor::Constant(_) => {}
        }
        if !binding
            .security
            .action
            .supports_resource(&binding.resource_type)
        {
            return Err(ToolRegistrationError::ResourceActionMismatch {
                action: binding.security.action.as_str(),
                resource_type: binding.resource_type.clone(),
            });
        }
        if binding.security.namespace_visibility == NamespaceVisibility::CallerNamespace
            && binding.resource_type != ResourceType::Ipc
            && !has_concrete_namespace
        {
            return Err(ToolRegistrationError::UnboundNamespace);
        }
        let known_capabilities = [
            CapabilitySet::CAP_TOOL_MOUNT,
            CapabilitySet::CAP_AGENT_CREATE,
            CapabilitySet::CAP_AGENT_KILL,
            CapabilitySet::CAP_NET_ACCESS,
            CapabilitySet::CAP_FILE_WRITE,
            CapabilitySet::CAP_FILE_DELETE,
            CapabilitySet::CAP_EXEC,
            CapabilitySet::CAP_ADMIN,
            CapabilitySet::CAP_SYS_RESOURCE,
        ];
        let mut seen_capabilities = std::collections::HashSet::new();
        for capability in &binding.security.required_capabilities {
            if !known_capabilities.contains(capability) || !seen_capabilities.insert(*capability) {
                return Err(ToolRegistrationError::InvalidCapability(*capability));
            }
        }
        for required in binding.security.action.mandatory_capabilities() {
            if !binding.security.required_capabilities.contains(&required) {
                return Err(ToolRegistrationError::MissingCapability {
                    action: binding.security.action.as_str(),
                    capability: required,
                });
            }
        }
        if matches!(
            binding.security.action,
            SecurityAction::CredentialAccess | SecurityAction::PackageInstall
        ) && binding.security.approval_policy != ApprovalPolicy::Administrator
        {
            return Err(ToolRegistrationError::MissingAdministratorApproval(
                binding.security.action.as_str(),
            ));
        }
        if matches!(
            binding.security.action,
            SecurityAction::Delete | SecurityAction::BrowserAutomation
        ) && binding.security.approval_policy == ApprovalPolicy::None
        {
            return Err(ToolRegistrationError::MissingApproval(
                binding.security.action.as_str(),
            ));
        }
        if matches!(
            binding.security.action,
            SecurityAction::Execute
                | SecurityAction::PackageInstall
                | SecurityAction::BrowserAutomation
                | SecurityAction::CredentialAccess
        ) && binding.security.sandbox_requirement != SandboxRequirement::Required
        {
            return Err(ToolRegistrationError::MissingSandbox(
                binding.security.action.as_str(),
            ));
        }
        Ok(())
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
                description: format!(
                    "{}\nSecurity constraints: resource={:?}; operation={}; {}",
                    b.description,
                    b.resource_type,
                    b.operation,
                    b.security.summary()
                ),
                parameters: b.parameters_schema.clone(),
            })
            .collect()
    }

    /// Return the validated security contract for a registered tool.
    pub fn security(&self, name: &str) -> Option<ToolSecurity> {
        self.tools.get(name).map(|binding| binding.security.clone())
    }

    /// Resolve the exact validated security contract and MAC resource for an
    /// untrusted call. All public call paths share this extraction logic.
    pub fn security_context(
        &self,
        name: &str,
        arguments: &serde_json::Value,
    ) -> Result<(ToolSecurity, String), String> {
        let security = self
            .security(name)
            .ok_or_else(|| format!("unknown tool '{name}'"))?;
        let resource = security.extract_resource(arguments)?;
        Ok((security, resource))
    }

    /// Prepare the authorization inputs shared by every live tool-call path.
    pub fn prepare_call(
        &self,
        name: &str,
        arguments: &serde_json::Value,
    ) -> Result<PreparedToolCall, String> {
        let (security, resource) = self.security_context(name, arguments)?;
        let estimated_tokens = (arguments.to_string().len() as u64 / 4)
            .saturating_add(name.len() as u64 / 4)
            .saturating_add(10);
        Ok(PreparedToolCall {
            security,
            resource,
            estimated_tokens,
        })
    }

    /// Canonical authorization entry used by executor, syscall/MCP wire, and
    /// therefore SDK clients. A new public tool path should call this method,
    /// not reproduce declaration extraction or gate ordering.
    pub async fn authorize_call(
        &self,
        gate: &crate::syscall_gate::SyscallGate,
        agent_id: AgentId,
        name: &str,
        arguments: &serde_json::Value,
    ) -> Result<PreparedToolCall, ToolAuthorizationError> {
        let prepared = self
            .prepare_call(name, arguments)
            .map_err(ToolAuthorizationError::InvalidDeclaration)?;
        gate.check_tool_call_declared(
            agent_id,
            name,
            &prepared.resource,
            prepared.estimated_tokens,
            &prepared.security,
        )
        .await
        .map_err(ToolAuthorizationError::Denied)?;
        Ok(prepared)
    }

    /// Build the validated security catalog shipped by the kernel. This is
    /// also consumed by the legacy direct-gate compatibility API, ensuring its
    /// built-in classifications are generated from the same bindings.
    pub fn default_security_catalog() -> HashMap<String, ToolSecurity> {
        let registry = Self::new();
        registry.register_advanced_tools();
        registry.register_git_tools();
        registry.register_ipc_tools();
        crate::editing::register_edit_tools(&registry);
        registry.security_catalog()
    }

    /// Snapshot every currently registered validated declaration. Policy
    /// tooling uses the live registry variant so dynamically installed package,
    /// MCP, and custom tools cannot disappear from coverage checks.
    pub fn security_catalog(&self) -> HashMap<String, ToolSecurity> {
        self.tools
            .iter()
            .map(|binding| (binding.name.clone(), binding.security.clone()))
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
            // come from the args.
            "delegate_task" => serde_json::json!({
                "from": agent_id.to_string(),
                "to": tool_call.arguments.get("to").and_then(|v| v.as_str()).unwrap_or(""),
                "description": tool_call.arguments.get("task").and_then(|v| v.as_str()).unwrap_or(""),
            }),
            // Delegation status/complete: inject the caller as `from` so the
            // IpcManager can authorize (only parties may read; only the assignee
            // may complete). The LLM supplies just the task_id.
            "delegation_status" | "complete_delegation" => serde_json::json!({
                "from": agent_id.to_string(),
                "task_id": tool_call.arguments.get("task_id").and_then(|v| v.as_str()).unwrap_or(""),
            }),
            _ => tool_call.arguments.clone(),
        };

        Some(ResourceRequest {
            agent_id,
            resource_type: binding_rt,
            operation: binding_op,
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
            security: ToolSecurity::argument(SecurityAction::Read, "path"),
        })
        .expect("built-in read_file security declaration must be valid");

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
            security: ToolSecurity::argument(SecurityAction::Write, "path").sandboxed(),
        })
        .expect("built-in write_file security declaration must be valid");

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
            security: ToolSecurity::argument(SecurityAction::Read, "path"),
        })
        .expect("built-in list_directory security declaration must be valid");

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
            security: ToolSecurity::argument(SecurityAction::Network, "url"),
        })
        .expect("built-in http_get security declaration must be valid");

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
            security: ToolSecurity::argument(SecurityAction::Execute, "command")
                .with_approval(ApprovalPolicy::User)
                .sandboxed(),
        })
        .expect("built-in run_command security declaration must be valid");

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
            security: ToolSecurity::argument(SecurityAction::Execute, "directory").sandboxed(),
        })
        .expect("built-in search_files security declaration must be valid");

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
            security: ToolSecurity::argument(SecurityAction::Execute, "directory").sandboxed(),
        })
        .expect("built-in git_status security declaration must be valid");

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
            security: ToolSecurity::argument(SecurityAction::Write, "path").sandboxed(),
        })
        .expect("built-in create_directory security declaration must be valid");
    }
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
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
    fn duplicate_name_cannot_replace_a_validated_builtin() {
        let reg = ToolRegistry::new();
        let original = reg.security("read_file").unwrap();
        let error = reg
            .register(ToolBinding {
                name: "read_file".into(),
                description: "attempted replacement".into(),
                parameters_schema: serde_json::json!({
                    "type": "object",
                    "properties": {"command": {"type": "string"}},
                    "required": ["command"]
                }),
                resource_type: ResourceType::Application,
                operation: "launch".into(),
                security: ToolSecurity::argument(SecurityAction::Execute, "command").sandboxed(),
            })
            .unwrap_err();
        assert_eq!(
            error,
            ToolRegistrationError::DuplicateName("read_file".into())
        );
        assert_eq!(reg.security("read_file").unwrap(), original);
    }

    #[test]
    fn definitions_generates_valid_tools() {
        let reg = ToolRegistry::new();
        let defs = reg.definitions();
        assert!(defs.len() >= 5);
        let read = defs.iter().find(|d| d.name == "read_file").unwrap();
        assert!(read.description.contains("Read"));
        assert!(read.description.contains("Security constraints:"));
        assert!(read.description.contains("resource=Filesystem"));
        assert!(read.description.contains("operation=read"));
        assert!(read.description.contains("action=read"));
        assert!(read.parameters["properties"]["path"].is_object());
    }

    #[test]
    fn llm_security_summary_never_exposes_constant_resource_values() {
        let reg = ToolRegistry::new();
        reg.register(ToolBinding {
            name: "secret_target".into(),
            description: "execute a locally configured target".into(),
            parameters_schema: serde_json::json!({"type": "object", "properties": {}}),
            resource_type: ResourceType::Application,
            operation: "launch".into(),
            security: ToolSecurity::constant(
                SecurityAction::Execute,
                "credential://must-not-reach-the-model",
            )
            .sandboxed(),
        })
        .unwrap();

        let definition = reg
            .definitions()
            .into_iter()
            .find(|definition| definition.name == "secret_target")
            .unwrap();
        assert!(definition.description.contains("action=exec"));
        assert!(!definition.description.contains("must-not-reach-the-model"));
    }

    #[test]
    fn registration_rejects_incomplete_or_contradictory_security() {
        let reg = ToolRegistry::new();
        let mut missing_capability = ToolSecurity::argument(SecurityAction::Network, "url");
        missing_capability.required_capabilities.clear();
        let error = reg
            .register(ToolBinding {
                name: "unsafe_custom".into(),
                description: "must not register".into(),
                parameters_schema: serde_json::json!({
                    "type": "object",
                    "properties": {"url": {"type": "string"}},
                    "required": ["url"]
                }),
                resource_type: ResourceType::Network,
                operation: "get".into(),
                security: missing_capability,
            })
            .unwrap_err();
        assert!(matches!(
            error,
            ToolRegistrationError::MissingCapability { .. }
        ));
        assert!(!reg.has_tool("unsafe_custom"));

        let error = reg
            .register(ToolBinding {
                name: "bad_extractor".into(),
                description: "must not register".into(),
                parameters_schema: serde_json::json!({
                    "type": "object",
                    "properties": {"path": {"type": "string"}}
                }),
                resource_type: ResourceType::Filesystem,
                operation: "read".into(),
                security: ToolSecurity::argument(SecurityAction::Read, "undeclared"),
            })
            .unwrap_err();
        assert_eq!(
            error,
            ToolRegistrationError::MissingResourceArgument("undeclared".into())
        );

        let error = reg
            .register(ToolBinding {
                name: "disguised_exec".into(),
                description: "must not register".into(),
                parameters_schema: serde_json::json!({
                    "type": "object",
                    "properties": {"path": {"type": "string"}},
                    "required": ["path"]
                }),
                resource_type: ResourceType::Application,
                operation: "launch".into(),
                security: ToolSecurity::argument(SecurityAction::Read, "path"),
            })
            .unwrap_err();
        assert!(matches!(
            error,
            ToolRegistrationError::ResourceActionMismatch { .. }
        ));

        let error = reg
            .register(ToolBinding {
                name: "combined_capability".into(),
                description: "must not register".into(),
                parameters_schema: serde_json::json!({
                    "type": "object",
                    "properties": {"url": {"type": "string"}},
                    "required": ["url"]
                }),
                resource_type: ResourceType::Network,
                operation: "get".into(),
                security: ToolSecurity {
                    required_capabilities: vec![
                        CapabilitySet::CAP_NET_ACCESS | CapabilitySet::CAP_EXEC,
                    ],
                    ..ToolSecurity::argument(SecurityAction::Network, "url")
                },
            })
            .unwrap_err();
        assert!(matches!(error, ToolRegistrationError::InvalidCapability(_)));

        let error = reg
            .register(ToolBinding {
                name: "unbound_scoped_tool".into(),
                description: "must not register globally".into(),
                parameters_schema: serde_json::json!({
                    "type": "object",
                    "properties": {"path": {"type": "string"}},
                    "required": ["path"]
                }),
                resource_type: ResourceType::Filesystem,
                operation: "read".into(),
                security: ToolSecurity::argument(SecurityAction::Read, "path").caller_namespace(),
            })
            .unwrap_err();
        assert_eq!(error, ToolRegistrationError::UnboundNamespace);

        let package_security = ToolSecurity::constant(SecurityAction::PackageInstall, "pkg:test")
            .with_approval(ApprovalPolicy::Administrator)
            .sandboxed();
        assert!(package_security
            .required_capabilities
            .contains(&CapabilitySet::CAP_EXEC));
        assert!(package_security
            .required_capabilities
            .contains(&CapabilitySet::CAP_ADMIN));
    }

    #[test]
    fn resource_extraction_is_typed_and_fail_closed() {
        let reg = ToolRegistry::new();
        assert!(reg
            .security_context("http_get", &serde_json::json!({"url": 7}))
            .unwrap_err()
            .contains("non-empty string"));
        assert!(reg
            .security_context("http_get", &serde_json::json!({"path": "https://bypass"}))
            .unwrap_err()
            .contains("resource argument 'url'"));
        let (_, resource) = reg
            .security_context(
                "http_get",
                &serde_json::json!({"url": "https://example.com/a/../b?path=/etc/passwd"}),
            )
            .unwrap();
        assert_eq!(
            resource, "https://example.com/a/../b?path=/etc/passwd",
            "the declared URL field is preserved exactly for MAC matching"
        );
    }

    #[test]
    fn prepare_call_is_the_single_security_input_for_public_entry_points() {
        let reg = ToolRegistry::new();
        let arguments = serde_json::json!({"url": "https://example.com/x"});
        let prepared = reg.prepare_call("http_get", &arguments).unwrap();
        let (security, resource) = reg.security_context("http_get", &arguments).unwrap();
        assert_eq!(prepared.security, security);
        assert_eq!(prepared.resource, resource);
        assert_eq!(prepared.security.action, SecurityAction::Network);
        assert_eq!(prepared.resource, "https://example.com/x");
        assert!(prepared.estimated_tokens >= 10);
    }

    #[tokio::test]
    async fn authorize_call_is_the_single_gate_decision_for_public_entry_points() {
        let reg = ToolRegistry::new();
        let gate = crate::syscall_gate::SyscallGate::with_mac(
            std::sync::Arc::new(crate::cgroups::CgroupManager::new()),
            false,
            Vec::new(),
        );
        let agent = uuid::Uuid::new_v4();
        gate.register_agent(agent, CapabilitySet::none(), None);
        let denied = reg
            .authorize_call(
                &gate,
                agent,
                "http_get",
                &serde_json::json!({"url": "https://example.com"}),
            )
            .await;
        assert!(matches!(
            denied,
            Err(ToolAuthorizationError::Denied(
                crate::syscall_gate::GateDenial::MissingCapability(CapabilitySet::CAP_NET_ACCESS)
            ))
        ));
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
    fn create_directory_keeps_declared_filesystem_provider_and_operation() {
        let reg = ToolRegistry::new();
        let req = reg
            .resolve(
                uuid::Uuid::new_v4(),
                &ToolCall {
                    id: "mkdir".into(),
                    name: "create_directory".into(),
                    arguments: serde_json::json!({"path": "nested"}),
                },
            )
            .unwrap();
        assert_eq!(req.resource_type, ResourceType::Filesystem);
        assert_eq!(req.operation, "create_dir");
        assert_eq!(req.parameters["path"], "nested");
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
            parameters_schema: serde_json::json!({"type": "object", "properties": {}}),
            resource_type: ResourceType::Browser,
            operation: "navigate".into(),
            security: ToolSecurity::constant(SecurityAction::BrowserAutomation, "browser")
                .with_approval(ApprovalPolicy::User)
                .sandboxed(),
        })
        .unwrap();
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
            security: ToolSecurity::argument(SecurityAction::Network, "url"),
        })
        .expect("built-in browse_url security declaration must be valid");
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
            security: ToolSecurity::constant(SecurityAction::Execute, "git:working-tree")
                .with_capability(CapabilitySet::CAP_FILE_WRITE)
                .with_approval(ApprovalPolicy::User)
                .sandboxed(),
        })
        .expect("built-in git_commit security declaration must be valid");
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
            security: ToolSecurity::constant(SecurityAction::Execute, "git:working-tree")
                .sandboxed(),
        })
        .expect("built-in git_diff security declaration must be valid");
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
            security: ToolSecurity::argument(SecurityAction::Ipc, "to").caller_namespace(),
        })
        .expect("built-in send_agent_message security declaration must be valid");
        self.register(ToolBinding {
            name: "check_inbox".into(),
            description: "Receive the next pending message from your agent inbox (empty if none)."
                .into(),
            parameters_schema: serde_json::json!({"type": "object", "properties": {}}),
            resource_type: ResourceType::Ipc,
            operation: "receive".into(),
            security: ToolSecurity::constant(SecurityAction::Ipc, "ipc:self").caller_namespace(),
        })
        .expect("built-in check_inbox security declaration must be valid");
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
            security: ToolSecurity::argument(SecurityAction::Ipc, "to").caller_namespace(),
        })
        .expect("built-in delegate_task security declaration must be valid");
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
            security: ToolSecurity::argument(SecurityAction::Ipc, "task_id").caller_namespace(),
        })
        .expect("built-in delegation_status security declaration must be valid");
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
            security: ToolSecurity::argument(SecurityAction::Ipc, "task_id").caller_namespace(),
        })
        .expect("built-in complete_delegation security declaration must be valid");
        self.register(ToolBinding {
            name: "discover_agents".into(),
            description: "List the other agents you can address (name, id, state) so you can \
                          send_agent_message or delegate_task to them by name or id."
                .into(),
            parameters_schema: serde_json::json!({"type": "object", "properties": {}}),
            resource_type: ResourceType::Ipc,
            operation: "discover".into(),
            security: ToolSecurity::constant(SecurityAction::Ipc, "ipc:namespace")
                .caller_namespace(),
        })
        .expect("built-in discover_agents security declaration must be valid");
    }
}
