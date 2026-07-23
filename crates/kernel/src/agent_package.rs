//! Agent package format — a declarative, loadable description of an agent.
//!
//! In the Linux mental model an agent is a process; an **agent package** is the
//! unit file / package descriptor that tells the kernel how to bring that
//! process up. Because the platform is Rust-only with no dynamic code loading,
//! the loadable artifact is *data* — a TOML manifest (`agent.toml`) — not a
//! shared object. The loader maps the manifest onto the same `create_agent_full`
//! admission path the CLI and syscall server use, so a packaged agent is
//! admitted, gated, and scheduled identically to one created by hand.
//!
//! `tools` is the agent's declared tool set: every name must exist and be
//! visible in the package tenant's tool namespace before creation. It does not
//! grant authority; actual access is independently enforced by namespace and
//! capability checks at the syscall gate.
//!
//! See `docs/AGENT_PACKAGE.md` for the manifest schema and a worked example.

use serde::{Deserialize, Serialize};

use crate::context::{ContextManager, Fact, FactCategory};
use crate::execution::AgentOutput;
use crate::{AgentConfig, AgentHandle, AgentKernelImpl, Priority};

fn default_provider() -> String {
    "stub".to_string()
}
fn default_profile() -> String {
    "standard".to_string()
}
fn default_priority() -> u8 {
    3
}

/// A loadable agent package manifest (e.g. `agent.toml`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentManifest {
    /// Unique, human-readable package name.
    pub name: String,
    /// What the agent is for.
    #[serde(default)]
    pub description: String,
    /// The agent's standing task (its purpose / system intent).
    pub task: String,
    /// Optional entry prompt run once when the package is *run* (the runner
    /// drives a single turn with this message). `None` ⇒ load only.
    #[serde(default)]
    pub entry: Option<String>,
    /// LLM provider id the agent is created against.
    #[serde(default = "default_provider")]
    pub provider: String,
    /// Permission profile — decides the agent's capabilities at the gate.
    #[serde(default = "default_profile")]
    pub profile: String,
    /// Scheduling priority (1 = highest .. 5 = lowest); defaults to 3.
    #[serde(default = "default_priority")]
    pub priority: u8,
    /// Optional CFS nice value (-20..=19); applied after creation when set.
    #[serde(default)]
    pub nice: Option<i8>,
    /// Declared tool set (intent/documentation; access is gate-enforced).
    #[serde(default)]
    pub tools: Vec<String>,
    /// Seed facts written to the agent's long-term memory on load.
    #[serde(default)]
    pub memory: Vec<String>,
}

/// Errors from parsing, validating, loading, or running an agent package.
#[derive(Debug, thiserror::Error)]
pub enum AgentPackageError {
    /// The TOML did not parse, or a required field was absent.
    #[error("manifest parse error: {0}")]
    Parse(String),
    /// The manifest parsed but failed validation (empty field, out-of-range).
    #[error("invalid manifest: {0}")]
    Invalid(String),
    /// Reading the manifest file failed.
    #[error("io error: {0}")]
    Io(String),
    /// The kernel rejected the load/run (e.g. admission or connector failure).
    #[error("kernel error: {0}")]
    Kernel(String),
}

impl AgentManifest {
    /// Parse and validate a manifest from a TOML string.
    pub fn from_toml_str(s: &str) -> Result<Self, AgentPackageError> {
        if s.len() > 1_048_576 {
            return Err(AgentPackageError::Invalid(
                "manifest exceeds the 1 MiB input limit".into(),
            ));
        }
        let manifest: AgentManifest =
            toml::from_str(s).map_err(|e| AgentPackageError::Parse(e.to_string()))?;
        manifest.validate()?;
        Ok(manifest)
    }

    /// Load, parse, and validate a manifest from a file on disk.
    pub fn from_path(path: impl AsRef<std::path::Path>) -> Result<Self, AgentPackageError> {
        let s = std::fs::read_to_string(path).map_err(|e| AgentPackageError::Io(e.to_string()))?;
        Self::from_toml_str(&s)
    }

    /// Validate required fields and value ranges.
    pub fn validate(&self) -> Result<(), AgentPackageError> {
        if self.name.trim().is_empty() {
            return Err(AgentPackageError::Invalid(
                "`name` must not be empty".into(),
            ));
        }
        if self.name.len() > 128
            || self
                .name
                .chars()
                .any(|character| !(character.is_ascii_alphanumeric() || "-_.".contains(character)))
        {
            return Err(AgentPackageError::Invalid(
                "`name` must be at most 128 ASCII letters/digits/dot/dash/underscore characters"
                    .into(),
            ));
        }
        if self.task.trim().is_empty() {
            return Err(AgentPackageError::Invalid(
                "`task` must not be empty".into(),
            ));
        }
        if self.task.len() > 65_536
            || self.description.len() > 65_536
            || self
                .entry
                .as_ref()
                .is_some_and(|entry| entry.len() > 65_536)
        {
            return Err(AgentPackageError::Invalid(
                "description, task, and entry are each limited to 64 KiB".into(),
            ));
        }
        if self.provider.trim().is_empty() || self.provider.len() > 128 {
            return Err(AgentPackageError::Invalid(
                "`provider` must be non-empty and at most 128 bytes".into(),
            ));
        }
        if !matches!(
            self.profile.as_str(),
            "read-only" | "standard" | "elevated" | "full-access"
        ) {
            return Err(AgentPackageError::Invalid(format!(
                "unknown permission profile '{}'",
                self.profile
            )));
        }
        if !(1..=5).contains(&self.priority) {
            return Err(AgentPackageError::Invalid(format!(
                "`priority` must be 1..=5, got {}",
                self.priority
            )));
        }
        if let Some(n) = self.nice {
            if !(-20..=19).contains(&n) {
                return Err(AgentPackageError::Invalid(format!(
                    "`nice` must be -20..=19, got {n}"
                )));
            }
        }
        if self.tools.len() > 256 {
            return Err(AgentPackageError::Invalid(
                "at most 256 tools may be declared".into(),
            ));
        }
        let mut unique_tools = std::collections::HashSet::new();
        for tool in &self.tools {
            if tool.is_empty()
                || tool.len() > 128
                || tool.chars().any(|character| {
                    !(character.is_ascii_alphanumeric() || "-_.".contains(character))
                })
            {
                return Err(AgentPackageError::Invalid(format!(
                    "invalid tool name '{tool}'"
                )));
            }
            if !unique_tools.insert(tool) {
                return Err(AgentPackageError::Invalid(format!(
                    "duplicate tool declaration '{tool}'"
                )));
            }
        }
        if self.memory.len() > 128
            || self.memory.iter().any(|memory| memory.len() > 65_536)
            || self.memory.iter().map(String::len).sum::<usize>() > 1_048_576
        {
            return Err(AgentPackageError::Invalid(
                "memory seeds are limited to 128 items, 64 KiB each, and 1 MiB total".into(),
            ));
        }
        Ok(())
    }

    /// Resolve this manifest's declared `tools` against a shared tool registry,
    /// returning the matching [`SharedToolDef`]s in declaration order.
    ///
    /// This lets a packaged agent reference reusable tool definitions by name:
    /// the names in `tools` are looked up in the [`SharedToolRegistry`], and any
    /// that aren't published surface as
    /// [`crate::tool_registry_share::ShareError::Unresolved`].
    ///
    /// [`SharedToolDef`]: crate::tool_registry_share::SharedToolDef
    /// [`SharedToolRegistry`]: crate::tool_registry_share::SharedToolRegistry
    pub fn resolve_tools(
        &self,
        registry: &crate::tool_registry_share::SharedToolRegistry,
    ) -> Result<Vec<crate::tool_registry_share::SharedToolDef>, AgentPackageError> {
        registry
            .resolve_names(&self.tools)
            .map_err(|e| AgentPackageError::Invalid(e.to_string()))
    }

    /// Build the kernel [`AgentConfig`] this manifest describes.
    pub fn to_agent_config(&self) -> AgentConfig {
        AgentConfig {
            name: self.name.clone(),
            task: self.task.clone(),
            llm_provider: self.provider.clone(),
            permission_profile: self.profile.clone(),
            priority: Priority::new(self.priority).unwrap_or_else(|| Priority::new(3).unwrap()),
            sandbox_config: None,
        }
    }
}

/// Load a packaged agent onto the kernel: create it through the full admission
/// path, apply its nice value, and seed its long-term memory. Does **not** run
/// the entry prompt (use [`run_package`] for that). Returns the new agent.
pub async fn load_package(
    kernel: &AgentKernelImpl,
    manifest: &AgentManifest,
) -> Result<AgentHandle, AgentPackageError> {
    load_package_scoped(kernel, manifest, None).await
}

/// Load a packaged agent into an authenticated tenant boundary. This is the
/// wire-server path: package creation must not fall back to the un-tenanted
/// registry merely because the agent came from a manifest.
pub async fn load_package_for_tenant(
    kernel: &AgentKernelImpl,
    tenant_id: &str,
    manifest: &AgentManifest,
) -> Result<AgentHandle, AgentPackageError> {
    if manifest.profile == "full-access" {
        return Err(AgentPackageError::Invalid(
            "tenant package manifests cannot request the system-only full-access profile".into(),
        ));
    }
    load_package_scoped(kernel, manifest, Some(tenant_id)).await
}

async fn load_package_scoped(
    kernel: &AgentKernelImpl,
    manifest: &AgentManifest,
    tenant_id: Option<&str>,
) -> Result<AgentHandle, AgentPackageError> {
    manifest.validate()?;
    let namespace_group =
        tenant_id.filter(|tenant_id| *tenant_id != crate::context::DEFAULT_TENANT);
    for tool in &manifest.tools {
        if !kernel.tool_visible_to_group(namespace_group, tool) {
            return Err(AgentPackageError::Invalid(
                "one or more declared tools are unavailable in this namespace".into(),
            ));
        }
    }
    let config = manifest.to_agent_config();
    let handle = match tenant_id {
        Some(tenant_id) => kernel.create_agent_for_tenant(tenant_id, config).await,
        None => kernel.create_agent_full(config).await,
    }
    .map_err(|e| AgentPackageError::Kernel(e.to_string()))?;

    if let Some(nice) = manifest.nice {
        if let Err(error) = kernel.set_nice(handle.id, nice).await {
            kernel.rollback_created_agent(handle.id).await;
            return Err(AgentPackageError::Kernel(error.to_string()));
        }
    }

    for content in &manifest.memory {
        let now = chrono::Utc::now();
        let fact = Fact {
            id: uuid::Uuid::new_v4(),
            content: content.clone(),
            category: FactCategory::Fact,
            created_at: now,
            last_accessed_at: now,
            embedding: None,
        };
        if let Err(error) = kernel.context_manager.store_fact(handle.id, fact).await {
            kernel.rollback_created_agent(handle.id).await;
            return Err(AgentPackageError::Kernel(error.to_string()));
        }
    }

    Ok(handle)
}

/// Load a packaged agent and, if it declares an `entry`, drive one turn with it.
/// Returns the agent and the entry turn's output (when an entry was present).
pub async fn run_package(
    kernel: &AgentKernelImpl,
    manifest: &AgentManifest,
) -> Result<(AgentHandle, Option<AgentOutput>), AgentPackageError> {
    let handle = load_package(kernel, manifest).await?;
    let output = match &manifest.entry {
        Some(entry) => Some(
            kernel
                .send_message(handle.id, entry)
                .await
                .map_err(|e| AgentPackageError::Kernel(e.to_string()))?,
        ),
        None => None,
    };
    Ok((handle, output))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::AgentKernel;

    const SAMPLE: &str = r#"
name = "researcher"
description = "Reads and summarizes."
task = "Research and summarize topics."
entry = "Summarize the project README."
provider = "stub"
profile = "read-only"
priority = 2
nice = -5
tools = ["read_file", "http_get"]
memory = ["Prefer primary sources.", "Cite everything."]
"#;

    #[test]
    fn parses_full_manifest() {
        let m = AgentManifest::from_toml_str(SAMPLE).unwrap();
        assert_eq!(m.name, "researcher");
        assert_eq!(m.profile, "read-only");
        assert_eq!(m.priority, 2);
        assert_eq!(m.nice, Some(-5));
        assert_eq!(m.tools, vec!["read_file", "http_get"]);
        assert_eq!(m.memory.len(), 2);
        assert_eq!(m.entry.as_deref(), Some("Summarize the project README."));
    }

    #[test]
    fn applies_defaults_for_minimal_manifest() {
        let m = AgentManifest::from_toml_str("name = \"x\"\ntask = \"do x\"\n").unwrap();
        assert_eq!(m.provider, "stub");
        assert_eq!(m.profile, "standard");
        assert_eq!(m.priority, 3);
        assert!(m.nice.is_none());
        assert!(m.tools.is_empty());
        assert!(m.entry.is_none());
    }

    #[test]
    fn rejects_missing_fields_and_bad_ranges() {
        // No `name` field at all ⇒ TOML parse failure (required, no default).
        assert!(matches!(
            AgentManifest::from_toml_str("task = \"t\""),
            Err(AgentPackageError::Parse(_))
        ));
        // Present but empty ⇒ validation failure.
        assert!(matches!(
            AgentManifest::from_toml_str("name = \"\"\ntask = \"t\""),
            Err(AgentPackageError::Invalid(_))
        ));
        assert!(matches!(
            AgentManifest::from_toml_str("name = \"a\"\ntask = \"t\"\npriority = 9"),
            Err(AgentPackageError::Invalid(_))
        ));
        assert!(matches!(
            AgentManifest::from_toml_str("name = \"a\"\ntask = \"t\"\nnice = 50"),
            Err(AgentPackageError::Invalid(_))
        ));
    }

    #[test]
    fn rejects_unknown_fields_and_unsafe_manifest_shapes() {
        assert!(matches!(
            AgentManifest::from_toml_str("name = \"a\"\ntask = \"t\"\nprivileged = true"),
            Err(AgentPackageError::Parse(_))
        ));
        for source in [
            "name = \"not/a/name\"\ntask = \"t\"",
            "name = \"a\"\ntask = \"t\"\nprofile = \"root\"",
            "name = \"a\"\ntask = \"t\"\ntools = [\"read_file\", \"read_file\"]",
            "name = \"a\"\ntask = \"t\"\ntools = [\"bad/tool\"]",
        ] {
            assert!(matches!(
                AgentManifest::from_toml_str(source),
                Err(AgentPackageError::Invalid(_))
            ));
        }
    }

    #[test]
    fn rejects_manifest_larger_than_one_mibibyte() {
        let oversized = format!("name = \"a\"\ntask = \"{}\"", "x".repeat(1_048_576));
        assert!(matches!(
            AgentManifest::from_toml_str(&oversized),
            Err(AgentPackageError::Invalid(_))
        ));
    }

    #[test]
    fn resolve_tools_against_shared_registry() {
        use crate::tool_registry_share::{SharedToolDef, SharedToolRegistry};

        let mut registry = SharedToolRegistry::new();
        registry
            .publish(
                SharedToolDef::new(
                    "read_file",
                    "read a file",
                    crate::resources::ResourceType::Filesystem,
                    "read",
                    crate::tools::ToolSecurity::argument(
                        crate::tools::SecurityAction::Read,
                        "path",
                    ),
                )
                .with_parameters(serde_json::json!({
                    "type": "object",
                    "properties": {"path": {"type": "string"}},
                    "required": ["path"]
                })),
            )
            .unwrap();
        registry
            .publish(
                SharedToolDef::new(
                    "http_get",
                    "fetch a url",
                    crate::resources::ResourceType::Network,
                    "get",
                    crate::tools::ToolSecurity::argument(
                        crate::tools::SecurityAction::Network,
                        "url",
                    ),
                )
                .with_parameters(serde_json::json!({
                    "type": "object",
                    "properties": {"url": {"type": "string"}},
                    "required": ["url"]
                })),
            )
            .unwrap();

        let m = AgentManifest::from_toml_str(SAMPLE).unwrap();
        let resolved = m.resolve_tools(&registry).unwrap();
        assert_eq!(resolved.len(), 2);
        assert_eq!(resolved[0].name, "read_file");
        assert_eq!(resolved[1].name, "http_get");
        assert_eq!(
            resolved[0].security.action,
            crate::tools::SecurityAction::Read
        );
        assert_eq!(
            resolved[1].security.action,
            crate::tools::SecurityAction::Network
        );
        assert_eq!(
            resolved[0].resource_type,
            crate::resources::ResourceType::Filesystem
        );
        assert_eq!(resolved[0].operation, "read");

        // A manifest declaring an unpublished tool fails to resolve.
        let bad = AgentManifest::from_toml_str("name = \"x\"\ntask = \"t\"\ntools = [\"ghost\"]\n")
            .unwrap();
        assert!(matches!(
            bad.resolve_tools(&registry),
            Err(AgentPackageError::Invalid(_))
        ));
    }

    #[tokio::test]
    async fn load_package_creates_agent_seeds_memory_and_honors_profile() {
        let kernel = AgentKernelImpl::new().unwrap();
        let manifest = AgentManifest::from_toml_str(SAMPLE).unwrap();
        let handle = load_package(&kernel, &manifest).await.unwrap();

        // The agent exists under the package name.
        let agents = kernel.agent_manager.list_agents(None);
        assert!(agents
            .iter()
            .any(|a| a.id == handle.id && a.name == "researcher"));

        // The read-only profile is load-bearing: no write capability at the gate.
        let info = kernel.syscall_gate.agent_info(handle.id).unwrap();
        assert!(
            !info.capabilities.contains(&"CAP_FILE_WRITE".to_string()),
            "read-only package must not grant CAP_FILE_WRITE: {:?}",
            info.capabilities
        );

        // Seed facts are queryable from long-term memory.
        let facts = kernel
            .context_manager
            .query_memory(handle.id, "primary sources")
            .await
            .unwrap();
        assert!(facts.iter().any(|f| f.content.contains("primary sources")));
    }

    #[tokio::test]
    async fn tenant_load_rejects_system_profile_without_creating_an_agent() {
        let kernel = AgentKernelImpl::new().unwrap();
        let manifest = AgentManifest::from_toml_str(
            "name = \"rootish\"\ntask = \"t\"\nprofile = \"full-access\"",
        )
        .unwrap();

        let error = load_package_for_tenant(&kernel, "tenant-a", &manifest)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("system-only"));
        assert!(kernel.agent_manager.list_agents(None).is_empty());
    }

    #[tokio::test]
    async fn unknown_declared_tool_is_rejected_before_creation() {
        let kernel = AgentKernelImpl::new().unwrap();
        let manifest = AgentManifest::from_toml_str(
            "name = \"ghost-user\"\ntask = \"t\"\ntools = [\"definitely_missing\"]",
        )
        .unwrap();

        let error = load_package(&kernel, &manifest).await.unwrap_err();
        assert!(error.to_string().contains("unavailable in this namespace"));
        assert!(!error.to_string().contains("definitely_missing"));
        assert!(kernel.agent_manager.list_agents(None).is_empty());
    }

    #[tokio::test]
    async fn tenant_package_tools_are_resolved_only_inside_their_namespace() {
        let kernel = AgentKernelImpl::new().unwrap();
        let tenant_a = kernel.create_tenant("package-a").await.unwrap();
        let tenant_b = kernel.create_tenant("package-b").await.unwrap();
        kernel
            .register_group_tool(
                &tenant_a,
                crate::tools::ToolBinding {
                    name: "tenant_a_package_notes".into(),
                    description: "Read tenant A package notes".into(),
                    parameters_schema: serde_json::json!({
                        "type": "object",
                        "properties": {"path": {"type": "string"}},
                        "required": ["path"]
                    }),
                    resource_type: crate::resources::ResourceType::Filesystem,
                    operation: "read".into(),
                    security: crate::tools::ToolSecurity::argument(
                        crate::tools::SecurityAction::Read,
                        "path",
                    ),
                },
            )
            .unwrap();
        let scoped_manifest = AgentManifest::from_toml_str(
            "name = \"scoped-package\"\ntask = \"t\"\ntools = [\"tenant_a_package_notes\"]",
        )
        .unwrap();

        let missing_manifest = AgentManifest::from_toml_str(
            "name = \"missing-package\"\ntask = \"t\"\ntools = [\"missing_package_tool\"]",
        )
        .unwrap();
        let missing_error = load_package_for_tenant(&kernel, &tenant_b, &missing_manifest)
            .await
            .unwrap_err();
        assert!(
            kernel.group_namespaces.contains_key(&tenant_b),
            "missing and foreign tool probes must perform the same namespace resolution"
        );

        let foreign_error = load_package_for_tenant(&kernel, &tenant_b, &scoped_manifest)
            .await
            .unwrap_err();
        assert_eq!(
            foreign_error.to_string(),
            "invalid manifest: one or more declared tools are unavailable in this namespace"
        );
        assert!(
            !foreign_error.to_string().contains("tenant_a_package_notes"),
            "foreign namespace validation must not confirm the scoped tool name"
        );
        assert!(
            kernel.agent_manager.list_agents(None).is_empty(),
            "foreign tool validation must happen before agent creation"
        );

        assert_eq!(
            foreign_error.to_string(),
            missing_error.to_string(),
            "missing and foreign-scoped tools must be indistinguishable"
        );
        assert!(kernel.agent_manager.list_agents(None).is_empty());

        let owned = load_package_for_tenant(&kernel, &tenant_a, &scoped_manifest)
            .await
            .expect("the owning namespace must resolve its scoped tool");
        assert_eq!(
            kernel.context_manager.agent_tenant(owned.id).unwrap(),
            Some(tenant_a)
        );
        assert!(kernel
            .tool_registry
            .definitions_for_agent(&kernel.syscall_gate, owned.id)
            .iter()
            .any(|tool| tool.name == "tenant_a_package_notes"));
    }

    #[tokio::test]
    async fn creation_rollback_erases_live_and_durable_partial_state() {
        let kernel = AgentKernelImpl::new().unwrap();
        let manifest = AgentManifest::from_toml_str(
            "name = \"rollback-me\"\ntask = \"t\"\nprofile = \"standard\"",
        )
        .unwrap();
        let handle = load_package(&kernel, &manifest).await.unwrap();

        kernel.rollback_created_agent(handle.id).await;

        assert!(kernel.get_agent_status(handle.id).is_err());
        assert!(!kernel
            .agent_manager
            .list_agents(None)
            .iter()
            .any(|agent| agent.id == handle.id));
        assert_eq!(
            kernel.context_manager.agent_tenant(handle.id).unwrap(),
            None
        );
        assert!(kernel.syscall_gate.agent_info(handle.id).is_none());
    }
}
