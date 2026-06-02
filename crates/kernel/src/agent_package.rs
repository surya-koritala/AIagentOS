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
//! `tools` is the agent's *declared* tool set (intent + documentation); actual
//! tool access is enforced at runtime by the agent's permission profile through
//! the syscall gate's capability checks, not by this list.
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
        if self.task.trim().is_empty() {
            return Err(AgentPackageError::Invalid(
                "`task` must not be empty".into(),
            ));
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
        Ok(())
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
    manifest.validate()?;
    let handle = kernel
        .create_agent_full(manifest.to_agent_config())
        .await
        .map_err(|e| AgentPackageError::Kernel(e.to_string()))?;

    if let Some(nice) = manifest.nice {
        kernel
            .set_nice(handle.id, nice)
            .await
            .map_err(|e| AgentPackageError::Kernel(e.to_string()))?;
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
        kernel
            .context_manager
            .store_fact(handle.id, fact)
            .await
            .map_err(|e| AgentPackageError::Kernel(e.to_string()))?;
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
}
