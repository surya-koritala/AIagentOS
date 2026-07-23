//! Tool Registry — maps tool names to ResourceBroker operations.

use dashmap::DashMap;
use std::collections::HashMap;

use crate::agent_struct::CapabilitySet;
use crate::connector::{ToolCall, ToolDefinition};
use crate::resources::{ProviderTargetSpec, ResourceRequest, ResourceType};
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
    pub const ALL: [Self; 9] = [
        Self::Read,
        Self::Write,
        Self::Delete,
        Self::Network,
        Self::Execute,
        Self::Ipc,
        Self::BrowserAutomation,
        Self::CredentialAccess,
        Self::PackageInstall,
    ];

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

    /// Return the one security action that a built-in provider operation is
    /// allowed to carry. Keeping this mapping beside the action declaration
    /// prevents a binding from authorizing a harmless action and dispatching a
    /// more privileged operation (for example, `Read` + filesystem `delete`).
    fn for_provider_operation(resource_type: &ResourceType, operation: &str) -> Option<Self> {
        match (resource_type, operation) {
            (ResourceType::Filesystem, "read" | "list") => Some(Self::Read),
            (ResourceType::Filesystem, "write" | "create" | "create_dir" | "edit") => {
                Some(Self::Write)
            }
            (ResourceType::Filesystem, "delete") => Some(Self::Delete),
            (ResourceType::Network, "get" | "post" | "put" | "delete" | "browse") => {
                Some(Self::Network)
            }
            (ResourceType::Application, "launch" | "close" | "send_input" | "read_output") => {
                Some(Self::Execute)
            }
            (ResourceType::Application, "install" | "uninstall") => Some(Self::PackageInstall),
            (ResourceType::Application, "credential" | "credential_access" | "read_credential") => {
                Some(Self::CredentialAccess)
            }
            (ResourceType::Browser, "navigate" | "click" | "type" | "read") => {
                Some(Self::BrowserAutomation)
            }
            (
                ResourceType::Ipc,
                "send"
                | "receive"
                | "delegate"
                | "delegation_status"
                | "complete_delegation"
                | "discover",
            ) => Some(Self::Ipc),
            (ResourceType::Peripheral, "capture_image" | "record_audio") => Some(Self::Read),
            (ResourceType::Peripheral, "play_audio" | "print") => Some(Self::Write),
            (ResourceType::Peripheral, "credential" | "credential_access" | "read_credential") => {
                Some(Self::CredentialAccess)
            }
            _ => None,
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
    #[error("operation '{operation}' is not supported for resource type {resource_type:?}")]
    UnsupportedOperation {
        resource_type: ResourceType,
        operation: String,
    },
    #[error(
        "operation '{operation}' on {resource_type:?} requires security action {expected}, not {actual}"
    )]
    OperationActionMismatch {
        resource_type: ResourceType,
        operation: String,
        expected: &'static str,
        actual: &'static str,
    },
    #[error("operation '{operation}' on {resource_type:?} requires resource extractor {expected}")]
    ProviderTargetMismatch {
        resource_type: ResourceType,
        operation: String,
        expected: String,
    },
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
    #[error("command templates require a non-empty command")]
    InvalidCommandTemplate,
    #[error(
        "command templates require a sandboxed Execute/Application/launch declaration with CAP_EXEC"
    )]
    CommandTemplateBindingMismatch,
    #[error("tool '{0}' already has a command template")]
    DuplicateCommandTemplate(String),
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
/// Resource extraction is authoritative. `estimated_tokens` is retained only
/// for source compatibility and diagnostics; authorization deliberately ignores
/// it because serialized tool payload is not provider usage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedToolCall {
    pub security: ToolSecurity,
    pub resource: String,
    /// Compatibility-only serialized-payload estimate. Never charged to
    /// provider or cgroup token quota.
    pub estimated_tokens: u64,
}

/// Immutable agent request and exact approval identity prepared from one
/// coherent registry snapshot. Live execution paths must execute `request`
/// directly after gate admission instead of resolving the mutable registry a
/// second time. The trusted broker may resolve normalized filesystem paths
/// inside the sandbox before provider dispatch.
#[derive(Debug)]
pub struct PreparedToolExecution {
    pub authorization: PreparedToolCall,
    pub request: ResourceRequest,
    /// SHA-256 identity of the immutable agent request. Raw parameters may
    /// contain secrets and are never retained in the approval-map key.
    pub approval_contract_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToolAuthorizationError {
    InvalidDeclaration(String),
    Denied(crate::syscall_gate::GateDenial),
}

/// Public execution paths deliberately collapse missing and namespace-hidden
/// declarations to one non-reflective result. Detailed namespace denials remain
/// available inside the gate for trusted diagnostics, but are not an agent
/// catalog oracle.
pub(crate) const TOOL_NOT_FOUND_ERROR: &str = "tool not found";

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
    /// Publishes a binding and its optional provider template as one snapshot.
    /// Readers hold the shared side while resolving or exposing declarations,
    /// so they cannot observe half of a command-backed registration.
    publication: std::sync::RwLock<()>,
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
            publication: std::sync::RwLock::new(()),
            tools: DashMap::new(),
            command_templates: DashMap::new(),
        };
        registry.register_builtins();
        registry
    }

    /// Validate and register a tool binding. Untrusted/custom declarations are
    /// rejected before they become visible to an LLM or executable provider.
    pub fn register(&self, binding: ToolBinding) -> Result<(), ToolRegistrationError> {
        let _publication = self
            .publication
            .write()
            .expect("tool registry publication lock poisoned");
        self.register_locked(binding, false, None)
    }

    fn register_locked(
        &self,
        binding: ToolBinding,
        has_concrete_namespace: bool,
        fixed_provider_target: Option<&str>,
    ) -> Result<(), ToolRegistrationError> {
        Self::validate_binding_with_scope(&binding, has_concrete_namespace, fixed_provider_target)?;
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
        Self::validate_binding_with_scope(binding, false, None)
    }

    /// Kernel-only half of atomic namespace registration. The caller must tag
    /// the same tool name in `SyscallGate` before publishing this binding.
    pub(crate) fn register_namespace_scoped(
        &self,
        binding: ToolBinding,
    ) -> Result<(), ToolRegistrationError> {
        let _publication = self
            .publication
            .write()
            .expect("tool registry publication lock poisoned");
        self.register_locked(binding, true, None)
    }

    fn validate_binding_with_scope(
        binding: &ToolBinding,
        has_concrete_namespace: bool,
        fixed_provider_target: Option<&str>,
    ) -> Result<(), ToolRegistrationError> {
        if binding.name.trim().is_empty() || binding.description.trim().is_empty() {
            return Err(ToolRegistrationError::MissingIdentity);
        }
        if binding.operation.trim().is_empty() {
            return Err(ToolRegistrationError::MissingOperation);
        }
        let expected_target =
            crate::resources::provider_target_spec(&binding.resource_type, &binding.operation)
                .ok_or_else(|| ToolRegistrationError::UnsupportedOperation {
                    resource_type: binding.resource_type.clone(),
                    operation: binding.operation.clone(),
                })?;
        let extractor_matches_target = match (
            fixed_provider_target,
            expected_target,
            &binding.security.resource_extractor,
        ) {
            (
                Some(fixed),
                ProviderTargetSpec::Argument("command"),
                ResourceExtractor::Constant(actual),
            ) => actual == fixed,
            (None, ProviderTargetSpec::Argument(expected), ResourceExtractor::Argument(actual)) => {
                actual == expected
            }
            (None, ProviderTargetSpec::Constant(expected), ResourceExtractor::Constant(actual)) => {
                actual == expected
            }
            _ => false,
        };
        if !extractor_matches_target {
            let expected = match fixed_provider_target {
                Some(target) => format!("constant '{target}'"),
                None => match expected_target {
                    ProviderTargetSpec::Argument(argument) => {
                        format!("required string argument '{argument}'")
                    }
                    ProviderTargetSpec::Constant(target) => format!("constant '{target}'"),
                },
            };
            return Err(ToolRegistrationError::ProviderTargetMismatch {
                resource_type: binding.resource_type.clone(),
                operation: binding.operation.clone(),
                expected,
            });
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
        let expected_action =
            SecurityAction::for_provider_operation(&binding.resource_type, &binding.operation)
                .expect("provider target and action tables cover the same operations");
        if binding.security.action != expected_action {
            return Err(ToolRegistrationError::OperationActionMismatch {
                resource_type: binding.resource_type.clone(),
                operation: binding.operation.clone(),
                expected: expected_action.as_str(),
                actual: binding.security.action.as_str(),
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
                | SecurityAction::Delete
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
        let _publication = self
            .publication
            .write()
            .expect("tool registry publication lock poisoned");
        self.unregister_locked(name);
    }

    fn unregister_locked(&self, name: &str) {
        self.tools.remove(name);
        self.command_templates.remove(name);
    }

    /// Register a command template for a custom tool.
    pub fn register_command_template(&self, name: &str, command: &str, args_template: &[String]) {
        let _publication = self
            .publication
            .write()
            .expect("tool registry publication lock poisoned");
        if let Err(error) = self.try_register_command_template_locked(name, command, args_template)
        {
            tracing::warn!(
                tool = name,
                %error,
                "command template rejected"
            );
        }
    }

    fn validate_command_template_binding(
        binding: &ToolBinding,
        command: &str,
    ) -> Result<(), ToolRegistrationError> {
        if command.trim().is_empty() {
            return Err(ToolRegistrationError::InvalidCommandTemplate);
        }
        if binding.resource_type != ResourceType::Application
            || binding.operation != "launch"
            || binding.security.action != SecurityAction::Execute
            || !binding
                .security
                .required_capabilities
                .contains(&CapabilitySet::CAP_EXEC)
            || binding.security.sandbox_requirement != SandboxRequirement::Required
            || binding.security.resource_extractor
                != ResourceExtractor::Constant(command.to_string())
        {
            return Err(ToolRegistrationError::CommandTemplateBindingMismatch);
        }
        Ok(())
    }

    fn try_register_command_template_locked(
        &self,
        name: &str,
        command: &str,
        args_template: &[String],
    ) -> Result<(), ToolRegistrationError> {
        {
            let binding = self
                .tools
                .get(name)
                .ok_or(ToolRegistrationError::CommandTemplateBindingMismatch)?;
            Self::validate_command_template_binding(&binding, command)?;
        }
        match self.command_templates.entry(name.to_string()) {
            dashmap::mapref::entry::Entry::Vacant(entry) => {
                entry.insert((command.to_string(), args_template.to_vec()));
                Ok(())
            }
            dashmap::mapref::entry::Entry::Occupied(_) => Err(
                ToolRegistrationError::DuplicateCommandTemplate(name.to_string()),
            ),
        }
    }

    /// Transactionally register a process-backed tool after both its security
    /// binding and command template have passed validation. If template
    /// attachment fails, the just-registered binding is removed again; the
    /// brief pre-attachment state has no command and therefore cannot execute.
    pub fn register_command_tool(
        &self,
        binding: ToolBinding,
        command: &str,
        args_template: &[String],
    ) -> Result<(), ToolRegistrationError> {
        let _publication = self
            .publication
            .write()
            .expect("tool registry publication lock poisoned");
        Self::validate_binding_with_scope(&binding, false, Some(command))?;
        Self::validate_command_template_binding(&binding, command)?;
        let name = binding.name.clone();
        self.register_locked(binding, false, Some(command))?;
        if let Err(error) = self.try_register_command_template_locked(&name, command, args_template)
        {
            // The binding did not exist before `register_locked` succeeded, so
            // only our new binding is rolled back. Preserve any unexpected
            // template entry for fail-closed diagnostics.
            self.tools.remove(&name);
            return Err(error);
        }
        Ok(())
    }

    /// Generate LLM-compatible tool definitions.
    pub fn definitions(&self) -> Vec<ToolDefinition> {
        let _publication = self
            .publication
            .read()
            .expect("tool registry publication lock poisoned");
        self.tools
            .iter()
            .map(|binding| Self::definition(binding.value()))
            .collect()
    }

    /// Generate only the tool definitions visible to `agent_id`.
    ///
    /// A namespace-scoped declaration is itself sensitive capability metadata:
    /// callers outside that namespace must not learn its name or schema from an
    /// LLM prompt or remote `tools/list` response.
    pub fn definitions_for_agent(
        &self,
        gate: &crate::syscall_gate::SyscallGate,
        agent_id: AgentId,
    ) -> Vec<ToolDefinition> {
        let _publication = self
            .publication
            .read()
            .expect("tool registry publication lock poisoned");
        self.tools
            .iter()
            .filter(|binding| gate.tool_visible_to_agent(agent_id, binding.key()))
            .map(|binding| Self::definition(binding.value()))
            .collect()
    }

    fn definition(binding: &ToolBinding) -> ToolDefinition {
        ToolDefinition {
            name: binding.name.clone(),
            description: format!(
                "{}\nSecurity constraints: resource={:?}; operation={}; {}",
                binding.description,
                binding.resource_type,
                binding.operation,
                binding.security.summary()
            ),
            parameters: binding.parameters_schema.clone(),
        }
    }

    /// Return the validated security contract for a registered tool.
    pub fn security(&self, name: &str) -> Option<ToolSecurity> {
        let _publication = self
            .publication
            .read()
            .expect("tool registry publication lock poisoned");
        self.tools.get(name).map(|binding| binding.security.clone())
    }

    /// Resolve the exact validated security contract and MAC resource for an
    /// untrusted call. All public call paths share this extraction logic.
    pub fn security_context(
        &self,
        name: &str,
        arguments: &serde_json::Value,
    ) -> Result<(ToolSecurity, String), String> {
        let _publication = self
            .publication
            .read()
            .expect("tool registry publication lock poisoned");
        self.security_context_locked(name, arguments)
    }

    fn security_context_locked(
        &self,
        name: &str,
        arguments: &serde_json::Value,
    ) -> Result<(ToolSecurity, String), String> {
        let (security, resource_type) = self
            .tools
            .get(name)
            .map(|binding| (binding.security.clone(), binding.resource_type.clone()))
            .ok_or_else(|| format!("unknown tool '{name}'"))?;
        let mut resource = security.extract_resource(arguments)?;
        if resource_type == ResourceType::Filesystem {
            resource =
                crate::resources::normalize_filesystem_target(&resource).map_err(|error| {
                    format!("tool '{name}' has an invalid filesystem target: {error}")
                })?;
        }
        Ok((security, resource))
    }

    /// Prepare the authorization inputs shared by every live tool-call path.
    pub fn prepare_call(
        &self,
        name: &str,
        arguments: &serde_json::Value,
    ) -> Result<PreparedToolCall, String> {
        let _publication = self
            .publication
            .read()
            .expect("tool registry publication lock poisoned");
        self.prepare_call_locked(name, arguments)
    }

    fn prepare_call_locked(
        &self,
        name: &str,
        arguments: &serde_json::Value,
    ) -> Result<PreparedToolCall, String> {
        let (security, resource) = self.security_context_locked(name, arguments)?;
        let estimated_tokens = (arguments.to_string().len() as u64 / 4)
            .saturating_add(name.len() as u64 / 4)
            .saturating_add(10);
        Ok(PreparedToolCall {
            security,
            resource,
            estimated_tokens,
        })
    }

    /// Prepare the immutable agent request and approval identity from one
    /// registry snapshot. This closes unregister/re-register TOCTOU: callers
    /// execute the returned immutable request after authorization.
    pub fn prepare_execution(
        &self,
        agent_id: AgentId,
        name: &str,
        arguments: &serde_json::Value,
    ) -> Result<PreparedToolExecution, String> {
        let _publication = self
            .publication
            .read()
            .expect("tool registry publication lock poisoned");
        let authorization = self.prepare_call_locked(name, arguments)?;
        let call = ToolCall {
            id: "prepared".into(),
            name: name.to_string(),
            arguments: arguments.clone(),
        };
        let mut request = self
            .resolve_locked(agent_id, &call)
            .ok_or_else(|| format!("tool '{name}' has no executable provider binding"))?;
        if request.resource_type == ResourceType::Filesystem {
            let target = crate::resources::provider_target(
                &request.resource_type,
                &request.operation,
                &request.parameters,
            )
            .map_err(|error| format!("tool '{name}' has an invalid provider target: {error}"))?;
            let normalized =
                crate::resources::normalize_filesystem_target(&target).map_err(|error| {
                    format!("tool '{name}' has an invalid filesystem target: {error}")
                })?;
            let parameters = request
                .parameters
                .as_object_mut()
                .ok_or_else(|| format!("tool '{name}' filesystem parameters must be an object"))?;
            parameters.insert("path".into(), serde_json::Value::String(normalized));
        }
        let provider_target = crate::resources::provider_target(
            &request.resource_type,
            &request.operation,
            &request.parameters,
        )
        .map_err(|error| format!("tool '{name}' has an invalid provider target: {error}"))?;
        if provider_target != authorization.resource {
            return Err(format!(
                "tool '{name}' authorization target does not match provider target"
            ));
        }
        let approval_contract = serde_json::to_vec(&serde_json::json!({
            "version": 1,
            "security": &authorization.security,
            "resource_type": &request.resource_type,
            "operation": &request.operation,
            "parameters": &request.parameters,
        }))
        .map_err(|error| format!("tool '{name}' contract serialization failed: {error}"))?;
        let digest = ring::digest::digest(&ring::digest::SHA256, &approval_contract);
        let mut approval_contract_digest = String::with_capacity(7 + digest.as_ref().len() * 2);
        approval_contract_digest.push_str("sha256:");
        use std::fmt::Write as _;
        for byte in digest.as_ref() {
            write!(&mut approval_contract_digest, "{byte:02x}")
                .expect("writing a digest into a String cannot fail");
        }
        Ok(PreparedToolExecution {
            authorization,
            request,
            approval_contract_digest,
        })
    }

    /// Authorization-only compatibility entry.
    ///
    /// This validates declarations and policy but does **not** reserve a
    /// concurrent cgroup tool slot. New execution paths must call
    /// [`authorize_and_acquire_call`](Self::authorize_and_acquire_call) and
    /// hold its guard through binding execution.
    #[deprecated(
        since = "0.3.0",
        note = "authorization only; use authorize_and_acquire_call for execution"
    )]
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

    /// Canonical live tool admission: validate the declaration, authorize the
    /// exact resource, and reserve hierarchical concurrent-tool capacity as one
    /// counted gate verdict. The returned guard must live through binding
    /// execution.
    pub async fn authorize_and_acquire_call(
        &self,
        gate: &crate::syscall_gate::SyscallGate,
        agent_id: AgentId,
        name: &str,
        arguments: &serde_json::Value,
    ) -> Result<(PreparedToolExecution, crate::cgroups::ToolCallGuard), ToolAuthorizationError>
    {
        // Visibility is sensitive declaration metadata. For a registered
        // caller, reject a namespace-hidden name before consulting the global
        // registry so an exact guess is indistinguishable from a missing name.
        // Preserve UnknownAgent for unregistered callers.
        if gate.pid_of(agent_id).is_some() && !gate.tool_visible_to_agent(agent_id, name) {
            return Err(ToolAuthorizationError::InvalidDeclaration(
                TOOL_NOT_FOUND_ERROR.to_string(),
            ));
        }
        let mut prepared = self
            .prepare_execution(agent_id, name, arguments)
            .map_err(|error| {
                if error.starts_with("unknown tool '") {
                    ToolAuthorizationError::InvalidDeclaration(TOOL_NOT_FOUND_ERROR.to_string())
                } else {
                    ToolAuthorizationError::InvalidDeclaration(error)
                }
            })?;
        let request_identity = crate::resources::request_identity(
            prepared.request.agent_id,
            &prepared.request.resource_type,
            &prepared.request.operation,
            &prepared.request.parameters,
        )
        .map_err(ToolAuthorizationError::InvalidDeclaration)?;
        let (_, guard, proof) = gate
            .authorize_and_acquire_tool_call_declared_contract(
                agent_id,
                name,
                &prepared.authorization.resource,
                &prepared.authorization.security,
                &prepared.approval_contract_digest,
                &request_identity,
            )
            .await
            .map_err(ToolAuthorizationError::Denied)?;
        prepared.request.gate_admission = Some(proof);
        Ok((prepared, guard))
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
        let _publication = self
            .publication
            .read()
            .expect("tool registry publication lock poisoned");
        self.tools
            .iter()
            .map(|binding| (binding.name.clone(), binding.security.clone()))
            .collect()
    }

    /// Snapshot every complete, validated tool declaration from one coherent
    /// registry publication. Policy analysis uses provider class and operation
    /// as well as the security contract.
    pub fn binding_catalog(&self) -> HashMap<String, ToolBinding> {
        let _publication = self
            .publication
            .read()
            .expect("tool registry publication lock poisoned");
        self.tools
            .iter()
            .map(|binding| (binding.name.clone(), binding.value().clone()))
            .collect()
    }

    /// Resolve a tool call into a ResourceRequest.
    pub fn resolve(&self, agent_id: AgentId, tool_call: &ToolCall) -> Option<ResourceRequest> {
        let _publication = self
            .publication
            .read()
            .expect("tool registry publication lock poisoned");
        self.resolve_locked(agent_id, tool_call)
    }

    fn resolve_locked(&self, agent_id: AgentId, tool_call: &ToolCall) -> Option<ResourceRequest> {
        // Read out what we need and drop the `tools` shard read-lock immediately.
        // The publication read guard intentionally remains held until the
        // provider request is fully materialized, keeping the binding/template
        // snapshot coherent.
        let (binding_rt, binding_op, binding_security) = {
            let binding = self.tools.get(&tool_call.name)?;
            (
                binding.resource_type.clone(),
                binding.operation.clone(),
                binding.security.clone(),
            )
        };

        // Check if this is a custom tool with a command template
        if let Some(entry) = self.command_templates.get(&tool_call.name) {
            if binding_rt != ResourceType::Application
                || binding_op != "launch"
                || binding_security.action != SecurityAction::Execute
                || !binding_security
                    .required_capabilities
                    .contains(&CapabilitySet::CAP_EXEC)
                || binding_security.sandbox_requirement != SandboxRequirement::Required
            {
                return None;
            }
            let (command, args_template) = entry.value();
            if binding_security.resource_extractor != ResourceExtractor::Constant(command.clone()) {
                return None;
            }
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
                gate_admission: None,
            });
        }

        // IPC provider identity is injected by operation, not inferred from a
        // trusted built-in name. Dynamically shared/package tools therefore
        // cannot select another agent as sender, inbox owner, or namespace
        // viewer while authorizing a harmless constant.
        let parameters = match (&binding_rt, binding_op.as_str()) {
            (ResourceType::Ipc, "send") => serde_json::json!({
                "from": agent_id.to_string(),
                "to": tool_call.arguments.get("to").and_then(|v| v.as_str()).unwrap_or(""),
                "payload": tool_call
                    .arguments
                    .get("payload")
                    .or_else(|| tool_call.arguments.get("message"))
                    .cloned()
                    .unwrap_or(serde_json::Value::Null),
            }),
            (ResourceType::Ipc, "receive") => {
                serde_json::json!({"agent": agent_id.to_string()})
            }
            (ResourceType::Ipc, "discover") => {
                serde_json::json!({"viewer": agent_id.to_string()})
            }
            (ResourceType::Ipc, "delegate") => serde_json::json!({
                "from": agent_id.to_string(),
                "to": tool_call.arguments.get("to").and_then(|v| v.as_str()).unwrap_or(""),
                "description": tool_call
                    .arguments
                    .get("description")
                    .or_else(|| tool_call.arguments.get("task"))
                    .and_then(|v| v.as_str())
                    .unwrap_or(""),
            }),
            (ResourceType::Ipc, "delegation_status" | "complete_delegation") => serde_json::json!({
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
            gate_admission: None,
        })
    }

    /// Check if a tool exists.
    pub fn has_tool(&self, name: &str) -> bool {
        let _publication = self
            .publication
            .read()
            .expect("tool registry publication lock poisoned");
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

        self.register_command_tool(
            ToolBinding {
                name: "search_files".into(),
                description: "Search for files matching a pattern recursively in a directory"
                    .into(),
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
                security: ToolSecurity::constant(SecurityAction::Execute, "find").sandboxed(),
            },
            "find",
            &[
                "{directory}".into(),
                "-name".into(),
                "{pattern}".into(),
                "-type".into(),
                "f".into(),
            ],
        )
        .expect("built-in search_files security declaration must be valid");

        self.register_command_tool(
            ToolBinding {
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
                security: ToolSecurity::constant(SecurityAction::Execute, "git").sandboxed(),
            },
            "git",
            &[
                "-C".into(),
                "{directory}".into(),
                "status".into(),
                "--short".into(),
            ],
        )
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

    fn complete_security(security: ToolSecurity) -> ToolSecurity {
        let action = security.action;
        match action {
            SecurityAction::Delete | SecurityAction::BrowserAutomation => {
                security.with_approval(ApprovalPolicy::User).sandboxed()
            }
            SecurityAction::CredentialAccess | SecurityAction::PackageInstall => security
                .with_approval(ApprovalPolicy::Administrator)
                .sandboxed(),
            SecurityAction::Execute => security.sandboxed(),
            _ => security,
        }
    }

    fn operation_binding(
        resource_type: ResourceType,
        operation: &str,
        action: SecurityAction,
    ) -> ToolBinding {
        let target = crate::resources::provider_target_spec(&resource_type, operation);
        let (parameters_schema, security) = match target {
            Some(ProviderTargetSpec::Argument(argument)) => (
                serde_json::json!({
                    "type": "object",
                    "properties": {argument: {"type": "string"}},
                    "required": [argument],
                }),
                ToolSecurity::argument(action, argument),
            ),
            Some(ProviderTargetSpec::Constant(resource)) => (
                serde_json::json!({"type": "object", "properties": {}}),
                ToolSecurity::constant(action, resource),
            ),
            None => (
                serde_json::json!({
                    "type": "object",
                    "properties": {"resource": {"type": "string"}},
                    "required": ["resource"],
                }),
                ToolSecurity::argument(action, "resource"),
            ),
        };
        ToolBinding {
            name: format!("{resource_type:?}-{operation}-{}", action.as_str()),
            description: "operation/action validation fixture".into(),
            parameters_schema,
            resource_type,
            operation: operation.into(),
            security: complete_security(security),
        }
    }

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
    fn definitions_for_agent_hide_foreign_namespace_tools() {
        let registry = ToolRegistry::new();
        let gate = crate::syscall_gate::SyscallGate::with_mac(
            std::sync::Arc::new(crate::cgroups::CgroupManager::new()),
            false,
            Vec::new(),
        );
        let member = uuid::Uuid::new_v4();
        let foreign = uuid::Uuid::new_v4();
        gate.register_agent(member, CapabilitySet::none(), None);
        gate.register_agent(foreign, CapabilitySet::none(), None);
        gate.set_agent_namespaces(member, vec![42]);
        gate.register_tool_namespace("read_file", 42);

        let member_tools = registry.definitions_for_agent(&gate, member);
        let foreign_tools = registry.definitions_for_agent(&gate, foreign);
        let unknown_tools = registry.definitions_for_agent(&gate, uuid::Uuid::new_v4());

        assert!(member_tools.iter().any(|tool| tool.name == "read_file"));
        assert!(!foreign_tools.iter().any(|tool| tool.name == "read_file"));
        assert!(
            member_tools.iter().any(|tool| tool.name == "write_file")
                && foreign_tools.iter().any(|tool| tool.name == "write_file"),
            "untagged tools remain globally discoverable to registered agents"
        );
        assert!(
            unknown_tools.is_empty(),
            "unknown agents must not discover any tools"
        );
    }

    #[test]
    fn llm_security_summary_never_exposes_constant_resource_values() {
        let reg = ToolRegistry::new();
        reg.register_command_tool(
            ToolBinding {
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
            },
            "credential://must-not-reach-the-model",
            &[],
        )
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
        assert!(matches!(
            error,
            ToolRegistrationError::ProviderTargetMismatch { .. }
        ));

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
            ToolRegistrationError::ProviderTargetMismatch { .. }
                | ToolRegistrationError::ResourceActionMismatch { .. }
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
    fn every_builtin_provider_operation_has_one_exact_security_action() {
        let expected = [
            (ResourceType::Filesystem, "read", SecurityAction::Read),
            (ResourceType::Filesystem, "list", SecurityAction::Read),
            (ResourceType::Filesystem, "write", SecurityAction::Write),
            (ResourceType::Filesystem, "create", SecurityAction::Write),
            (
                ResourceType::Filesystem,
                "create_dir",
                SecurityAction::Write,
            ),
            (ResourceType::Filesystem, "edit", SecurityAction::Write),
            (ResourceType::Filesystem, "delete", SecurityAction::Delete),
            (ResourceType::Network, "get", SecurityAction::Network),
            (ResourceType::Network, "post", SecurityAction::Network),
            (ResourceType::Network, "put", SecurityAction::Network),
            (ResourceType::Network, "delete", SecurityAction::Network),
            (ResourceType::Network, "browse", SecurityAction::Network),
            (ResourceType::Application, "launch", SecurityAction::Execute),
            (ResourceType::Application, "close", SecurityAction::Execute),
            (
                ResourceType::Application,
                "send_input",
                SecurityAction::Execute,
            ),
            (
                ResourceType::Application,
                "read_output",
                SecurityAction::Execute,
            ),
            (
                ResourceType::Application,
                "install",
                SecurityAction::PackageInstall,
            ),
            (
                ResourceType::Application,
                "uninstall",
                SecurityAction::PackageInstall,
            ),
            (
                ResourceType::Application,
                "credential",
                SecurityAction::CredentialAccess,
            ),
            (
                ResourceType::Application,
                "credential_access",
                SecurityAction::CredentialAccess,
            ),
            (
                ResourceType::Application,
                "read_credential",
                SecurityAction::CredentialAccess,
            ),
            (
                ResourceType::Browser,
                "navigate",
                SecurityAction::BrowserAutomation,
            ),
            (
                ResourceType::Browser,
                "click",
                SecurityAction::BrowserAutomation,
            ),
            (
                ResourceType::Browser,
                "type",
                SecurityAction::BrowserAutomation,
            ),
            (
                ResourceType::Browser,
                "read",
                SecurityAction::BrowserAutomation,
            ),
            (ResourceType::Ipc, "send", SecurityAction::Ipc),
            (ResourceType::Ipc, "receive", SecurityAction::Ipc),
            (ResourceType::Ipc, "delegate", SecurityAction::Ipc),
            (ResourceType::Ipc, "delegation_status", SecurityAction::Ipc),
            (
                ResourceType::Ipc,
                "complete_delegation",
                SecurityAction::Ipc,
            ),
            (ResourceType::Ipc, "discover", SecurityAction::Ipc),
            (
                ResourceType::Peripheral,
                "capture_image",
                SecurityAction::Read,
            ),
            (
                ResourceType::Peripheral,
                "record_audio",
                SecurityAction::Read,
            ),
            (
                ResourceType::Peripheral,
                "play_audio",
                SecurityAction::Write,
            ),
            (ResourceType::Peripheral, "print", SecurityAction::Write),
            (
                ResourceType::Peripheral,
                "credential",
                SecurityAction::CredentialAccess,
            ),
            (
                ResourceType::Peripheral,
                "credential_access",
                SecurityAction::CredentialAccess,
            ),
            (
                ResourceType::Peripheral,
                "read_credential",
                SecurityAction::CredentialAccess,
            ),
        ];

        for (resource_type, operation, action) in expected {
            let binding = operation_binding(resource_type.clone(), operation, action);
            ToolRegistry::validate_binding(&binding)
                .unwrap_or_else(|error| panic!("{operation}/{action:?} rejected: {error}"));

            let mut mismatched = binding.clone();
            match crate::resources::provider_target_spec(&resource_type, operation)
                .expect("fixture operation is supported")
            {
                ProviderTargetSpec::Argument(_) => {
                    mismatched.security.resource_extractor =
                        ResourceExtractor::Argument("benign_decoy".into());
                    assert!(matches!(
                        ToolRegistry::validate_binding(&mismatched),
                        Err(ToolRegistrationError::ProviderTargetMismatch { .. })
                    ));
                    mismatched.security.resource_extractor =
                        ResourceExtractor::Constant("benign:constant".into());
                }
                ProviderTargetSpec::Constant(_) => {
                    mismatched.security.resource_extractor =
                        ResourceExtractor::Constant("wrong:constant".into());
                }
            }
            assert!(matches!(
                ToolRegistry::validate_binding(&mismatched),
                Err(ToolRegistrationError::ProviderTargetMismatch { .. })
            ));
        }
    }

    #[test]
    fn operation_aliases_cannot_disguise_or_overstate_security_actions() {
        let mismatches = [
            (ResourceType::Filesystem, "delete", SecurityAction::Read),
            (ResourceType::Filesystem, "read", SecurityAction::Delete),
            (
                ResourceType::Application,
                "launch",
                SecurityAction::PackageInstall,
            ),
            (
                ResourceType::Application,
                "install",
                SecurityAction::Execute,
            ),
            (ResourceType::Network, "get", SecurityAction::Read),
            (ResourceType::Browser, "navigate", SecurityAction::Network),
            (ResourceType::Peripheral, "print", SecurityAction::Read),
            (ResourceType::Ipc, "send", SecurityAction::Execute),
        ];

        for (resource_type, operation, action) in mismatches {
            assert!(
                ToolRegistry::validate_binding(&operation_binding(
                    resource_type,
                    operation,
                    action
                ))
                .is_err(),
                "{operation}/{action:?} must not be accepted"
            );
        }

        let unsupported =
            operation_binding(ResourceType::Filesystem, "remove", SecurityAction::Delete);
        assert!(matches!(
            ToolRegistry::validate_binding(&unsupported),
            Err(ToolRegistrationError::UnsupportedOperation { .. })
        ));
    }

    #[test]
    fn delete_operation_cannot_opt_out_of_sandboxing() {
        let mut binding =
            operation_binding(ResourceType::Filesystem, "delete", SecurityAction::Delete);
        binding.security.sandbox_requirement = SandboxRequirement::NotRequired;
        assert_eq!(
            ToolRegistry::validate_binding(&binding),
            Err(ToolRegistrationError::MissingSandbox("delete"))
        );
    }

    #[test]
    fn command_templates_cannot_reclassify_tools_or_replace_existing_commands() {
        let registry = ToolRegistry::new();
        registry.register_command_template("read_file", "rm", &["-f".into(), "{path}".into()]);
        let read = registry
            .resolve(
                uuid::Uuid::new_v4(),
                &ToolCall {
                    id: "read".into(),
                    name: "read_file".into(),
                    arguments: serde_json::json!({"path": "/tmp/target"}),
                },
            )
            .unwrap();
        assert_eq!(read.resource_type, ResourceType::Filesystem);
        assert_eq!(read.operation, "read");
        assert_eq!(read.parameters["path"], "/tmp/target");

        registry
            .register_command_tool(
                {
                    let mut binding = operation_binding(
                        ResourceType::Application,
                        "launch",
                        SecurityAction::Execute,
                    );
                    binding.security.resource_extractor =
                        ResourceExtractor::Constant("echo".into());
                    binding
                },
                "echo",
                &["safe".into()],
            )
            .unwrap();
        let name = format!(
            "{:?}-{}-{}",
            ResourceType::Application,
            "launch",
            SecurityAction::Execute.as_str()
        );
        registry.register_command_template(&name, "rm", &["-rf".into(), "/".into()]);
        let process = registry
            .resolve(
                uuid::Uuid::new_v4(),
                &ToolCall {
                    id: "process".into(),
                    name,
                    arguments: serde_json::json!({"command": "attacker-controlled"}),
                },
            )
            .unwrap();
        assert_eq!(process.parameters["command"], "echo");
        assert_eq!(process.parameters["args"], serde_json::json!(["safe"]));
    }

    #[test]
    fn resolver_cannot_observe_a_half_published_command_tool() {
        let registry = std::sync::Arc::new(ToolRegistry::new());
        let mut binding =
            operation_binding(ResourceType::Application, "launch", SecurityAction::Execute);
        binding.security.resource_extractor = ResourceExtractor::Constant("echo".into());
        let name = binding.name.clone();

        let publication = registry
            .publication
            .write()
            .expect("tool registry publication lock poisoned");
        registry.tools.insert(name.clone(), binding);

        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let (sender, receiver) = std::sync::mpsc::channel();
        let reader_registry = registry.clone();
        let reader_barrier = barrier.clone();
        let reader_name = name.clone();
        let reader = std::thread::spawn(move || {
            reader_barrier.wait();
            let resolved = reader_registry.resolve(
                uuid::Uuid::new_v4(),
                &ToolCall {
                    id: "concurrent".into(),
                    name: reader_name,
                    arguments: serde_json::json!({
                        "command": "attacker-controlled"
                    }),
                },
            );
            sender.send(resolved).unwrap();
        });

        barrier.wait();
        assert!(
            receiver
                .recv_timeout(std::time::Duration::from_millis(100))
                .is_err(),
            "resolve must block while a binding/template snapshot is being published"
        );
        registry
            .command_templates
            .insert(name, ("echo".into(), vec!["fixed".into()]));
        drop(publication);

        let resolved = receiver
            .recv_timeout(std::time::Duration::from_secs(1))
            .unwrap()
            .unwrap();
        reader.join().unwrap();
        assert_eq!(resolved.parameters["command"], "echo");
        assert_eq!(resolved.parameters["args"], serde_json::json!(["fixed"]));
    }

    #[tokio::test]
    async fn authorized_request_is_immutable_and_stale_approval_cannot_cross_a_swap() {
        let registry = ToolRegistry::new();
        let mut binding =
            operation_binding(ResourceType::Application, "launch", SecurityAction::Execute);
        binding.name = "swappable_process".into();
        binding.security.approval_policy = ApprovalPolicy::User;
        binding.security.resource_extractor = ResourceExtractor::Constant("echo".into());
        registry
            .register_command_tool(binding.clone(), "echo", &["approved".into()])
            .unwrap();

        let gate = crate::syscall_gate::SyscallGate::with_mac(
            std::sync::Arc::new(crate::cgroups::CgroupManager::new()),
            false,
            Vec::new(),
        );
        let agent = uuid::Uuid::new_v4();
        let mut capabilities = CapabilitySet::none();
        capabilities.grant(CapabilitySet::CAP_EXEC);
        gate.register_agent(agent, capabilities, None);
        let arguments = serde_json::json!({"command": "attacker-controlled"});
        let approved = registry
            .prepare_execution(agent, "swappable_process", &arguments)
            .unwrap();
        assert!(gate.grant_tool_approval_contract(
            agent,
            "swappable_process",
            approved.authorization.resource.clone(),
            &approved.approval_contract_digest,
            ApprovalPolicy::User,
        ));

        registry.unregister("swappable_process");
        registry
            .register_command_tool(binding, "echo", &["different".into()])
            .unwrap();

        let denied = registry
            .authorize_and_acquire_call(&gate, agent, "swappable_process", &arguments)
            .await;
        assert!(matches!(
            denied,
            Err(ToolAuthorizationError::Denied(
                crate::syscall_gate::GateDenial::ApprovalRequired { .. }
            ))
        ));
        assert_eq!(approved.request.parameters["command"], "echo");
        assert_eq!(
            approved.request.parameters["args"],
            serde_json::json!(["approved"])
        );
    }

    #[test]
    fn approval_identity_is_a_digest_and_does_not_retain_sensitive_parameters() {
        let registry = ToolRegistry::new();
        let mut binding =
            operation_binding(ResourceType::Application, "launch", SecurityAction::Execute);
        binding.name = "secret_process".into();
        binding.security.resource_extractor = ResourceExtractor::Constant("helper".into());
        binding.parameters_schema = serde_json::json!({
            "type": "object",
            "properties": {
                "secret": {"type": "string"}
            },
            "required": ["secret"]
        });
        registry
            .register_command_tool(binding, "helper", &["{secret}".into()])
            .unwrap();
        let secret = "credential-value-that-must-not-be-retained";
        let prepared = registry
            .prepare_execution(
                uuid::Uuid::new_v4(),
                "secret_process",
                &serde_json::json!({"secret": secret}),
            )
            .unwrap();

        assert!(prepared.approval_contract_digest.starts_with("sha256:"));
        assert_eq!(prepared.approval_contract_digest.len(), 71);
        assert!(!prepared.approval_contract_digest.contains(secret));
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

    #[tokio::test]
    async fn filesystem_aliases_are_normalized_before_live_mac_admission() {
        let registry = ToolRegistry::new();
        let gate = crate::syscall_gate::SyscallGate::with_mac(
            std::sync::Arc::new(crate::cgroups::CgroupManager::new()),
            true,
            vec![crate::mac::PolicyRule {
                subject: "*".into(),
                action: "read".into(),
                object: "/workspace/allowed/**".into(),
                decision: "allow".into(),
            }],
        );
        let agent = uuid::Uuid::new_v4();
        gate.register_agent(agent, CapabilitySet::none(), None);

        let (prepared, slot) = registry
            .authorize_and_acquire_call(
                &gate,
                agent,
                "read_file",
                &serde_json::json!({"path": "/workspace//allowed/./note.txt"}),
            )
            .await
            .expect("normalized allowed path must pass the live MAC gate");
        assert_eq!(
            prepared.authorization.resource,
            "/workspace/allowed/note.txt"
        );
        assert_eq!(
            prepared.request.parameters["path"],
            "/workspace/allowed/note.txt"
        );
        drop(slot);

        let traversal = registry
            .authorize_and_acquire_call(
                &gate,
                agent,
                "read_file",
                &serde_json::json!({
                    "path": "/workspace/allowed/../denied/secret.txt"
                }),
            )
            .await;
        assert!(matches!(
            traversal,
            Err(ToolAuthorizationError::InvalidDeclaration(error))
                if error.contains("parent traversal")
        ));
    }

    #[test]
    fn filesystem_compatibility_preparation_uses_the_same_lexical_identity() {
        let registry = ToolRegistry::new();
        let canonical = registry
            .prepare_execution(
                uuid::Uuid::nil(),
                "read_file",
                &serde_json::json!({"path": "workspace/allowed/note.txt"}),
            )
            .unwrap();
        let aliased = registry
            .prepare_execution(
                uuid::Uuid::nil(),
                "read_file",
                &serde_json::json!({"path": "workspace//allowed/./note.txt"}),
            )
            .unwrap();
        let compatibility = registry
            .prepare_call(
                "read_file",
                &serde_json::json!({"path": "workspace//allowed/./note.txt"}),
            )
            .unwrap();

        assert_eq!(canonical.authorization.resource, compatibility.resource);
        assert_eq!(
            canonical.request.parameters, aliased.request.parameters,
            "approval and proof inputs must collapse lexical aliases"
        );
        assert_eq!(
            canonical.approval_contract_digest,
            aliased.approval_contract_digest
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
    async fn combined_admission_is_the_single_gate_decision_for_public_entry_points() {
        let reg = ToolRegistry::new();
        let gate = crate::syscall_gate::SyscallGate::with_mac(
            std::sync::Arc::new(crate::cgroups::CgroupManager::new()),
            false,
            Vec::new(),
        );
        let agent = uuid::Uuid::new_v4();
        gate.register_agent(agent, CapabilitySet::none(), None);
        let denied = reg
            .authorize_and_acquire_call(
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
            parameters_schema: serde_json::json!({
                "type": "object",
                "properties": {"url": {"type": "string"}},
                "required": ["url"]
            }),
            resource_type: ResourceType::Browser,
            operation: "navigate".into(),
            security: ToolSecurity::argument(SecurityAction::BrowserAutomation, "url")
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
        // `-a -m {message}` so the tool actually commits (the previous template
        // was `git add -A`, which only staged and never created a commit).
        self.register_command_tool(
            ToolBinding {
                name: "git_commit".into(),
                description: "Commit tracked changes with the given message (git commit -a -m)"
                    .into(),
                parameters_schema: serde_json::json!({
                    "type": "object",
                    "properties": {"message": {"type": "string", "description": "Commit message"}},
                    "required": ["message"]
                }),
                resource_type: ResourceType::Application,
                operation: "launch".into(),
                security: ToolSecurity::constant(SecurityAction::Execute, "git")
                    .with_capability(CapabilitySet::CAP_FILE_WRITE)
                    .with_approval(ApprovalPolicy::User)
                    .sandboxed(),
            },
            "git",
            &[
                "commit".into(),
                "-a".into(),
                "-m".into(),
                "{message}".into(),
            ],
        )
        .expect("built-in git_commit security declaration must be valid");

        self.register_command_tool(
            ToolBinding {
                name: "git_diff".into(),
                description: "Show the current git diff (unstaged changes)".into(),
                parameters_schema: serde_json::json!({"type": "object", "properties": {}}),
                resource_type: ResourceType::Application,
                operation: "launch".into(),
                security: ToolSecurity::constant(SecurityAction::Execute, "git").sandboxed(),
            },
            "git",
            &["diff".into()],
        )
        .expect("built-in git_diff security declaration must be valid");
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
