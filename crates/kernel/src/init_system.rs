//! Init System — service management, dependencies, restart policies.
//!
//! Like systemd for AI agents. Manages agent lifecycle declaratively.

use std::collections::HashMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::AgentId;

/// Agent service definition (like a systemd unit file).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceDef {
    pub name: String,
    pub description: Option<String>,

    #[serde(default)]
    pub exec: ExecConfig,

    #[serde(default)]
    pub service: ServiceConfig,

    #[serde(default)]
    pub dependencies: DependencyConfig,

    #[serde(default)]
    pub resources: ResourceConfig,

    #[serde(default)]
    pub policy: ServicePolicyConfig,

    #[serde(default)]
    pub health: HealthConfig,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecConfig {
    pub provider: String,
    pub system_prompt: String,
    #[serde(default)]
    pub tools: Vec<String>,
    #[serde(default)]
    pub model: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceConfig {
    pub restart: RestartPolicy,
    #[serde(default = "default_restart_delay")]
    pub restart_delay_ms: u64,
    #[serde(default = "default_restart_max_delay")]
    pub restart_max_delay_ms: u64,
    #[serde(default = "default_restart_jitter")]
    pub restart_jitter_ms: u64,
    #[serde(default = "default_restart_window")]
    pub restart_window_ms: u64,
    #[serde(default = "default_max_restarts")]
    pub max_restarts: u32,
    #[serde(default)]
    pub service_type: ServiceType,
}

impl Default for ServiceConfig {
    fn default() -> Self {
        Self {
            restart: RestartPolicy::OnFailure,
            restart_delay_ms: 5000,
            restart_max_delay_ms: 60_000,
            restart_jitter_ms: 250,
            restart_window_ms: 60_000,
            max_restarts: 3,
            service_type: ServiceType::Simple,
        }
    }
}

fn default_restart_delay() -> u64 {
    5000
}
fn default_restart_max_delay() -> u64 {
    60_000
}
fn default_restart_jitter() -> u64 {
    250
}
fn default_restart_window() -> u64 {
    60_000
}
fn default_max_restarts() -> u32 {
    3
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RestartPolicy {
    Always,
    OnFailure,
    Never,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum ServiceType {
    #[default]
    Simple,
    Oneshot,
    Notify,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DependencyConfig {
    #[serde(default)]
    pub requires: Vec<String>,
    #[serde(default)]
    pub wants: Vec<String>,
    #[serde(default)]
    pub after: Vec<String>,
    #[serde(default)]
    pub before: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceConfig {
    /// Backwards-compatible human-readable provider budget (`1000/minute`,
    /// `60000/hour`, or a plain per-minute integer).
    pub token_budget: Option<String>,
    pub max_context: Option<u64>,
    pub max_concurrent_tool_calls: Option<u32>,
    pub nice: Option<i8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServicePolicyConfig {
    #[serde(default = "default_tenant")]
    pub tenant_id: String,
    #[serde(default = "default_profile")]
    pub profile: String,
    #[serde(default)]
    pub namespace: Option<String>,
    #[serde(default)]
    pub sandbox: Option<crate::SandboxConfig>,
    /// Names of operator-configured provider credentials. Values are never
    /// copied into the service definition or durable runtime state.
    #[serde(default)]
    pub secret_refs: Vec<String>,
}

impl Default for ServicePolicyConfig {
    fn default() -> Self {
        Self {
            tenant_id: default_tenant(),
            profile: default_profile(),
            namespace: None,
            sandbox: None,
            secret_refs: Vec::new(),
        }
    }
}

fn default_tenant() -> String {
    crate::context::DEFAULT_TENANT.to_string()
}

fn default_profile() -> String {
    "standard".to_string()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HealthConfig {
    #[serde(default = "default_startup_timeout")]
    pub startup_timeout_ms: u64,
    /// Minimum stable-running period before the service becomes ready.
    #[serde(default)]
    pub readiness_delay_ms: u64,
    #[serde(default = "default_liveness_interval")]
    pub liveness_interval_ms: u64,
    #[serde(default = "default_shutdown_timeout")]
    pub shutdown_timeout_ms: u64,
}

impl Default for HealthConfig {
    fn default() -> Self {
        Self {
            startup_timeout_ms: default_startup_timeout(),
            readiness_delay_ms: 0,
            liveness_interval_ms: default_liveness_interval(),
            shutdown_timeout_ms: default_shutdown_timeout(),
        }
    }
}

fn default_startup_timeout() -> u64 {
    30_000
}

fn default_liveness_interval() -> u64 {
    1_000
}

fn default_shutdown_timeout() -> u64 {
    30_000
}

/// Runtime state of a service.
#[derive(Debug, Clone)]
pub struct ServiceState {
    pub def: ServiceDef,
    pub status: ServiceStatus,
    pub agent_id: Option<AgentId>,
    /// Attempts in the active restart window. This may reset when the window
    /// expires or an operator explicitly starts/restarts the service.
    pub restart_count: u32,
    /// Monotonic lifetime restart attempts, persisted for counter metrics.
    pub restart_attempts_total: u64,
    pub last_exit_code: Option<i32>,
    pub desired_running: bool,
    pub ready: bool,
    pub healthy: bool,
    pub restart_exhausted: bool,
    pub last_failure: Option<String>,
    pub next_restart_at: Option<String>,
    pub restart_window_started_at: Option<String>,
    pub last_transition_at: String,
    pub dependency_blocks: u64,
    pub definition_revision: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct ServiceRuntimeInfo {
    pub name: String,
    pub status: ServiceStatus,
    pub agent_id: Option<AgentId>,
    pub restart_count: u32,
    pub restart_attempts_total: u64,
    pub last_exit_code: Option<i32>,
    pub desired_running: bool,
    pub ready: bool,
    pub healthy: bool,
    pub restart_exhausted: bool,
    pub last_failure: Option<String>,
    pub next_restart_at: Option<String>,
    pub restart_window_started_at: Option<String>,
    pub last_transition_at: String,
    pub dependency_blocks: u64,
    pub definition_revision: String,
}

impl Default for ServiceRuntimeInfo {
    fn default() -> Self {
        Self {
            name: String::new(),
            status: ServiceStatus::Inactive,
            agent_id: None,
            restart_count: 0,
            restart_attempts_total: 0,
            last_exit_code: None,
            desired_running: false,
            ready: false,
            healthy: false,
            restart_exhausted: false,
            last_failure: None,
            next_restart_at: None,
            restart_window_started_at: None,
            last_transition_at: String::new(),
            dependency_blocks: 0,
            definition_revision: String::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ServiceStatus {
    Inactive,
    Starting,
    Running,
    Stopping,
    Failed,
    Restarting,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServiceHistoryEntry {
    pub id: u64,
    pub name: String,
    pub event: String,
    pub status: ServiceStatus,
    pub agent_id: Option<AgentId>,
    pub reason: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ServiceMetrics {
    pub configured: u64,
    pub desired: u64,
    pub running: u64,
    pub ready: u64,
    pub healthy: u64,
    pub failed: u64,
    pub restarts_total: u64,
    pub dependency_blocks_total: u64,
}

/// The init system — manages all services.
pub struct InitSystem {
    services: HashMap<String, ServiceState>,
    boot_order: Vec<String>,
    allowed_secret_refs: std::collections::HashSet<String>,
}

impl Default for InitSystem {
    fn default() -> Self {
        Self::new()
    }
}

impl InitSystem {
    pub fn new() -> Self {
        Self {
            services: HashMap::new(),
            boot_order: Vec::new(),
            allowed_secret_refs: std::collections::HashSet::new(),
        }
    }

    /// Install one already-validated definition into a replacement graph.
    fn load_service(&mut self, def: ServiceDef) {
        let name = def.name.clone();
        let now = chrono::Utc::now().to_rfc3339();
        let definition_revision = definition_revision(&def);
        self.services.insert(
            name.clone(),
            ServiceState {
                def,
                status: ServiceStatus::Inactive,
                agent_id: None,
                restart_count: 0,
                restart_attempts_total: 0,
                last_exit_code: None,
                desired_running: false,
                ready: false,
                healthy: false,
                restart_exhausted: false,
                last_failure: None,
                next_restart_at: None,
                restart_window_started_at: None,
                last_transition_at: now,
                dependency_blocks: 0,
                definition_revision,
            },
        );
    }

    /// Parse and validate a service directory as one atomic configuration. A
    /// malformed file, duplicate name, missing required dependency, or cycle
    /// rejects the entire reload and leaves the current supervisor unchanged.
    pub fn load_directory_checked(&mut self, dir: &Path) -> Result<Vec<String>, String> {
        self.replace_definitions(Self::read_directory_checked(dir)?)
    }

    /// Parse a complete directory without changing live supervisor state.
    pub fn read_directory_checked(dir: &Path) -> Result<Vec<ServiceDef>, String> {
        let entries = std::fs::read_dir(dir)
            .map_err(|error| format!("cannot read service directory {}: {error}", dir.display()))?;
        let mut paths = entries
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| {
                path.extension()
                    .is_some_and(|extension| extension == "toml")
            })
            .collect::<Vec<_>>();
        paths.sort();
        let mut definitions = Vec::with_capacity(paths.len());
        for path in paths {
            let content = std::fs::read_to_string(&path)
                .map_err(|error| format!("cannot read service file {}: {error}", path.display()))?;
            let definition = toml::from_str::<ServiceDef>(&content)
                .map_err(|error| format!("invalid service file {}: {error}", path.display()))?;
            definitions.push(definition);
        }
        Ok(definitions)
    }

    /// Atomically replace definitions after validating the complete dependency
    /// graph. Runtime state is retained for services with the same name.
    pub fn replace_definitions(
        &mut self,
        definitions: Vec<ServiceDef>,
    ) -> Result<Vec<String>, String> {
        let mut replacement = InitSystem::new();
        replacement.allowed_secret_refs = self.allowed_secret_refs.clone();
        for definition in definitions {
            replacement.validate_definition(&definition)?;
            if replacement.services.contains_key(&definition.name) {
                return Err(format!("duplicate service '{}'", definition.name));
            }
            replacement.load_service(definition);
        }
        replacement.resolve_boot_order()?;
        for (name, state) in &mut replacement.services {
            if let Some(existing) = self.services.get(name) {
                state.status = existing.status;
                state.agent_id = existing.agent_id;
                state.restart_count = existing.restart_count;
                state.last_exit_code = existing.last_exit_code;
                state.desired_running = existing.desired_running;
                state.ready = existing.ready;
                state.healthy = existing.healthy;
                state.restart_exhausted = existing.restart_exhausted;
                state.last_failure = existing.last_failure.clone();
                state.next_restart_at = existing.next_restart_at.clone();
                state.restart_window_started_at = existing.restart_window_started_at.clone();
                state.last_transition_at = existing.last_transition_at.clone();
                state.dependency_blocks = existing.dependency_blocks;
            }
        }
        let order = replacement.boot_order.clone();
        *self = replacement;
        Ok(order)
    }

    pub fn validate_replacement(
        &self,
        definitions: Vec<ServiceDef>,
    ) -> Result<Vec<String>, String> {
        let mut preview = InitSystem::new();
        preview.allowed_secret_refs = self.allowed_secret_refs.clone();
        preview.replace_definitions(definitions)
    }

    pub fn set_allowed_secret_refs(
        &mut self,
        refs: impl IntoIterator<Item = String>,
    ) -> Result<(), String> {
        let refs = refs.into_iter().collect::<std::collections::HashSet<_>>();
        for state in self.services.values() {
            for reference in &state.def.policy.secret_refs {
                if !refs.contains(reference) {
                    return Err(format!(
                        "service '{}' references unavailable secret '{}'",
                        state.def.name, reference
                    ));
                }
            }
        }
        self.allowed_secret_refs = refs;
        Ok(())
    }

    fn validate_definition(&self, definition: &ServiceDef) -> Result<(), String> {
        if definition.name.trim().is_empty()
            || definition.name.len() > 128
            || definition
                .name
                .chars()
                .any(|character| !(character.is_ascii_alphanumeric() || "-_.".contains(character)))
        {
            return Err(format!("invalid service name '{}'", definition.name));
        }
        if !matches!(
            definition.policy.profile.as_str(),
            "read-only" | "standard" | "elevated" | "full-access"
        ) {
            return Err(format!(
                "service '{}' uses unsupported permission profile '{}'",
                definition.name, definition.policy.profile
            ));
        }
        if definition.exec.model.is_some() {
            return Err(format!(
                "service '{}' requests an unsupported per-service model override; configure the model on its provider",
                definition.name
            ));
        }
        if !definition.exec.tools.is_empty() {
            return Err(format!(
                "service '{}' requests an unsupported per-service tool allow-list; use its permission profile and MAC policy",
                definition.name
            ));
        }
        if definition.service.service_type != ServiceType::Simple {
            return Err(format!(
                "service '{}' uses unsupported service type {:?}; only Simple is currently supported",
                definition.name, definition.service.service_type
            ));
        }
        if definition.policy.tenant_id.trim().is_empty()
            || definition.policy.tenant_id.len() > 128
            || definition
                .policy
                .tenant_id
                .chars()
                .any(|character| !(character.is_ascii_alphanumeric() || "-_.".contains(character)))
        {
            return Err(format!(
                "service '{}' has an invalid tenant id",
                definition.name
            ));
        }
        if let Some(namespace) = &definition.policy.namespace {
            if namespace.trim().is_empty()
                || namespace.len() > 128
                || namespace.chars().any(|character| {
                    !(character.is_ascii_alphanumeric() || "-_.".contains(character))
                })
            {
                return Err(format!(
                    "service '{}' has invalid namespace '{}'",
                    definition.name, namespace
                ));
            }
        }
        if definition
            .policy
            .sandbox
            .as_ref()
            .is_some_and(|sandbox| sandbox.isolation_level == crate::IsolationLevel::Trusted)
        {
            return Err(format!(
                "service '{}' cannot request trusted host isolation",
                definition.name
            ));
        }
        if definition.health.startup_timeout_ms == 0
            || definition.health.startup_timeout_ms > 300_000
            || definition.health.liveness_interval_ms < 50
            || definition.health.liveness_interval_ms > 60_000
            || definition.health.shutdown_timeout_ms == 0
            || definition.health.shutdown_timeout_ms > 300_000
        {
            return Err(format!(
                "service '{}' has health timing outside supported bounds",
                definition.name
            ));
        }
        if definition.service.restart_delay_ms > definition.service.restart_max_delay_ms
            || definition.service.restart_max_delay_ms > 300_000
            || definition.service.restart_window_ms < definition.service.restart_delay_ms
            || definition.service.restart_window_ms > 3_600_000
            || definition.service.restart_jitter_ms > definition.service.restart_max_delay_ms
            || definition.service.max_restarts > 1_000
        {
            return Err(format!(
                "service '{}' has invalid restart/backoff bounds",
                definition.name
            ));
        }
        if let Some(nice) = definition.resources.nice {
            if !(-20..=19).contains(&nice) {
                return Err(format!(
                    "service '{}' nice value must be in -20..=19",
                    definition.name
                ));
            }
        }
        if definition.resources.max_context == Some(0)
            || definition.resources.max_concurrent_tool_calls == Some(0)
        {
            return Err(format!(
                "service '{}' resource overrides must be positive when present",
                definition.name
            ));
        }
        let _ = definition.token_budget_per_minute()?;
        for reference in &definition.policy.secret_refs {
            if reference.trim().is_empty()
                || reference.len() > 128
                || reference.contains('\0')
                || !self.allowed_secret_refs.contains(reference)
            {
                return Err(format!(
                    "service '{}' references unavailable secret '{}'",
                    definition.name, reference
                ));
            }
        }
        Ok(())
    }

    /// Resolve boot order (topological sort of dependencies).
    pub fn resolve_boot_order(&mut self) -> Result<(), String> {
        let mut order = Vec::new();
        let mut visited = std::collections::HashSet::new();
        let mut visiting = std::collections::HashSet::new();

        for (name, state) in &self.services {
            for required in &state.def.dependencies.requires {
                if !self.services.contains_key(required) {
                    return Err(format!(
                        "service '{name}' requires missing service '{required}'"
                    ));
                }
            }
        }
        let mut names: Vec<String> = self.services.keys().cloned().collect();
        names.sort();
        for name in &names {
            self.topo_sort(name, &mut order, &mut visited, &mut visiting)?;
        }

        self.boot_order = order;
        Ok(())
    }

    fn topo_sort(
        &self,
        name: &str,
        order: &mut Vec<String>,
        visited: &mut std::collections::HashSet<String>,
        visiting: &mut std::collections::HashSet<String>,
    ) -> Result<(), String> {
        if visited.contains(name) {
            return Ok(());
        }
        if visiting.contains(name) {
            return Err(format!("Circular dependency: {}", name));
        }

        visiting.insert(name.to_string());

        if let Some(state) = self.services.get(name) {
            let mut dependencies = state.def.dependencies.requires.clone();
            dependencies.extend(state.def.dependencies.wants.clone());
            dependencies.extend(state.def.dependencies.after.clone());
            for (candidate, candidate_state) in &self.services {
                if candidate_state
                    .def
                    .dependencies
                    .before
                    .iter()
                    .any(|before| before == name)
                {
                    dependencies.push(candidate.clone());
                }
            }
            dependencies.sort();
            dependencies.dedup();
            for dep in &dependencies {
                if self.services.contains_key(dep) {
                    self.topo_sort(dep, order, visited, visiting)?;
                }
            }
        }

        visiting.remove(name);
        visited.insert(name.to_string());
        order.push(name.to_string());
        Ok(())
    }

    /// Get the boot order.
    pub fn boot_order(&self) -> &[String] {
        &self.boot_order
    }

    pub fn reverse_boot_order(&self) -> Vec<String> {
        self.boot_order.iter().rev().cloned().collect()
    }

    pub fn dependents_of(&self, name: &str) -> Vec<String> {
        let mut affected = std::collections::HashSet::from([name.to_string()]);
        loop {
            let before = affected.len();
            for (candidate, state) in &self.services {
                if state
                    .def
                    .dependencies
                    .requires
                    .iter()
                    .any(|required| affected.contains(required))
                {
                    affected.insert(candidate.clone());
                }
            }
            if affected.len() == before {
                break;
            }
        }
        self.reverse_boot_order()
            .into_iter()
            .filter(|candidate| affected.contains(candidate))
            .collect()
    }

    pub fn state(&self, name: &str) -> Option<ServiceState> {
        self.services.get(name).cloned()
    }

    pub fn definitions(&self) -> Vec<ServiceDef> {
        let mut definitions = self
            .services
            .values()
            .map(|state| state.def.clone())
            .collect::<Vec<_>>();
        definitions.sort_by(|left, right| left.name.cmp(&right.name));
        definitions
    }

    pub fn definition(&self, name: &str) -> Option<ServiceDef> {
        self.services.get(name).map(|state| state.def.clone())
    }

    pub fn mark_starting(&mut self, name: &str) -> bool {
        if let Some(state) = self.services.get_mut(name) {
            state.status = ServiceStatus::Starting;
            state.desired_running = true;
            state.ready = false;
            state.healthy = false;
            state.restart_exhausted = false;
            state.last_transition_at = chrono::Utc::now().to_rfc3339();
            true
        } else {
            false
        }
    }

    /// Get service status.
    pub fn status(&self, name: &str) -> Option<ServiceStatus> {
        self.services.get(name).map(|s| s.status)
    }

    /// Mark service as started.
    pub fn mark_started(&mut self, name: &str, agent_id: AgentId) {
        if let Some(state) = self.services.get_mut(name) {
            state.status = ServiceStatus::Running;
            state.agent_id = Some(agent_id);
            state.desired_running = true;
            state.ready = false;
            state.healthy = true;
            state.restart_exhausted = false;
            state.last_failure = None;
            state.next_restart_at = None;
            state.last_exit_code = None;
            state.last_transition_at = chrono::Utc::now().to_rfc3339();
        }
    }

    pub fn mark_ready(&mut self, name: &str) -> bool {
        if let Some(state) = self.services.get_mut(name) {
            if state.status != ServiceStatus::Running {
                return false;
            }
            state.ready = true;
            state.healthy = true;
            state.last_transition_at = chrono::Utc::now().to_rfc3339();
            true
        } else {
            false
        }
    }

    /// Mark service as failed.
    pub fn mark_failed(&mut self, name: &str, exit_code: i32) {
        self.mark_failed_reason(name, exit_code, "service failed".into());
    }

    pub fn mark_failed_reason(&mut self, name: &str, exit_code: i32, reason: String) {
        if let Some(state) = self.services.get_mut(name) {
            state.status = ServiceStatus::Failed;
            state.last_exit_code = Some(exit_code);
            state.ready = false;
            state.healthy = false;
            state.last_failure = Some(reason);
            state.last_transition_at = chrono::Utc::now().to_rfc3339();
        }
    }

    pub fn mark_stopping(&mut self, name: &str) -> bool {
        if let Some(state) = self.services.get_mut(name) {
            state.status = ServiceStatus::Stopping;
            state.ready = false;
            state.last_transition_at = chrono::Utc::now().to_rfc3339();
            true
        } else {
            false
        }
    }

    pub fn mark_stopped(&mut self, name: &str) -> bool {
        self.mark_stopped_with_desired(name, false)
    }

    pub fn mark_stopped_with_desired(&mut self, name: &str, desired_running: bool) -> bool {
        if let Some(state) = self.services.get_mut(name) {
            state.status = ServiceStatus::Inactive;
            state.agent_id = None;
            state.last_exit_code = Some(0);
            state.desired_running = desired_running;
            state.ready = false;
            state.healthy = false;
            state.next_restart_at = None;
            state.restart_exhausted = false;
            state.last_transition_at = chrono::Utc::now().to_rfc3339();
            true
        } else {
            false
        }
    }

    /// Check if service should restart.
    pub fn should_restart(&self, name: &str) -> bool {
        if let Some(state) = self.services.get(name) {
            if !state.desired_running
                || state.restart_exhausted
                || state.restart_count >= state.def.service.max_restarts
            {
                return false;
            }
            match state.def.service.restart {
                RestartPolicy::Always => true,
                RestartPolicy::OnFailure => state.last_exit_code.map(|c| c != 0).unwrap_or(false),
                RestartPolicy::Never => false,
            }
        } else {
            false
        }
    }

    /// Increment restart count.
    pub fn record_restart(&mut self, name: &str) {
        if let Some(state) = self.services.get_mut(name) {
            state.restart_count = state.restart_count.saturating_add(1);
            state.restart_attempts_total = state.restart_attempts_total.saturating_add(1);
            state.status = ServiceStatus::Restarting;
            state.ready = false;
            state.healthy = false;
            state.next_restart_at = None;
            state.last_transition_at = chrono::Utc::now().to_rfc3339();
        }
    }

    pub fn reset_restart_budget(&mut self, name: &str) {
        if let Some(state) = self.services.get_mut(name) {
            state.restart_count = 0;
            state.restart_exhausted = false;
            state.next_restart_at = None;
            state.restart_window_started_at = None;
            state.last_exit_code = None;
            state.last_transition_at = chrono::Utc::now().to_rfc3339();
        }
    }

    pub fn clear_instance_for_restart(&mut self, name: &str) {
        if let Some(state) = self.services.get_mut(name) {
            state.status = ServiceStatus::Restarting;
            state.agent_id = None;
            state.ready = false;
            state.healthy = false;
            state.last_transition_at = chrono::Utc::now().to_rfc3339();
        }
    }

    pub fn clear_instance(&mut self, name: &str) {
        if let Some(state) = self.services.get_mut(name) {
            state.agent_id = None;
            state.ready = false;
            state.healthy = false;
            state.last_transition_at = chrono::Utc::now().to_rfc3339();
        }
    }

    pub fn defer_restart(&mut self, name: &str, delay: std::time::Duration, reason: String) {
        if let Some(state) = self.services.get_mut(name) {
            state.status = ServiceStatus::Restarting;
            state.next_restart_at = Some(
                (chrono::Utc::now()
                    + chrono::Duration::milliseconds(
                        i64::try_from(delay.as_millis()).unwrap_or(i64::MAX),
                    ))
                .to_rfc3339(),
            );
            state.last_failure = Some(reason);
            state.last_transition_at = chrono::Utc::now().to_rfc3339();
        }
    }

    /// Schedule a bounded exponential restart in the current restart window.
    /// Returns the selected delay, or `None` when policy/retry bounds are
    /// exhausted. Jitter is deterministic for a service/attempt pair so tests
    /// and crash recovery remain reproducible.
    pub fn schedule_restart(
        &mut self,
        name: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Option<std::time::Duration> {
        let state = self.services.get_mut(name)?;
        if !state.desired_running {
            return None;
        }
        let should_restart = match state.def.service.restart {
            RestartPolicy::Always => true,
            RestartPolicy::OnFailure => state.last_exit_code.is_some_and(|code| code != 0),
            RestartPolicy::Never => false,
        };
        if !should_restart {
            return None;
        }
        let window = chrono::Duration::milliseconds(
            i64::try_from(state.def.service.restart_window_ms).unwrap_or(i64::MAX),
        );
        let reset_window = state
            .restart_window_started_at
            .as_deref()
            .and_then(|timestamp| chrono::DateTime::parse_from_rfc3339(timestamp).ok())
            .map(|started| now.signed_duration_since(started.with_timezone(&chrono::Utc)) > window)
            .unwrap_or(true);
        if reset_window {
            state.restart_window_started_at = Some(now.to_rfc3339());
            state.restart_count = 0;
            state.restart_exhausted = false;
        }
        if state.restart_count >= state.def.service.max_restarts {
            state.restart_exhausted = true;
            state.next_restart_at = None;
            state.last_failure = Some(format!(
                "restart limit exhausted: {} attempts within {}ms",
                state.def.service.max_restarts, state.def.service.restart_window_ms
            ));
            state.last_transition_at = now.to_rfc3339();
            return None;
        }
        let exponent = state.restart_count.min(31);
        let base = state
            .def
            .service
            .restart_delay_ms
            .saturating_mul(1u64 << exponent)
            .min(state.def.service.restart_max_delay_ms);
        let jitter = if state.def.service.restart_jitter_ms == 0 {
            0
        } else {
            deterministic_jitter(name, state.restart_count)
                % state.def.service.restart_jitter_ms.saturating_add(1)
        };
        let delay_ms = base
            .saturating_add(jitter)
            .min(state.def.service.restart_max_delay_ms);
        state.status = ServiceStatus::Restarting;
        state.next_restart_at = Some(
            (now + chrono::Duration::milliseconds(i64::try_from(delay_ms).unwrap_or(i64::MAX)))
                .to_rfc3339(),
        );
        state.last_transition_at = now.to_rfc3339();
        Some(std::time::Duration::from_millis(delay_ms))
    }

    pub fn restart_due(&self, name: &str, now: chrono::DateTime<chrono::Utc>) -> bool {
        self.services
            .get(name)
            .and_then(|state| state.next_restart_at.as_deref())
            .and_then(|timestamp| chrono::DateTime::parse_from_rfc3339(timestamp).ok())
            .is_some_and(|timestamp| timestamp.with_timezone(&chrono::Utc) <= now)
    }

    pub fn record_dependency_block(&mut self, name: &str, reason: String) {
        if let Some(state) = self.services.get_mut(name) {
            state.dependency_blocks = state.dependency_blocks.saturating_add(1);
            state.last_failure = Some(reason);
            state.ready = false;
            state.healthy = false;
            state.last_transition_at = chrono::Utc::now().to_rfc3339();
        }
    }

    pub fn restore_runtime(&mut self, runtime: &[ServiceRuntimeInfo]) {
        for restored in runtime {
            let Some(state) = self.services.get_mut(&restored.name) else {
                continue;
            };
            if !restored.definition_revision.is_empty()
                && restored.definition_revision != state.definition_revision
            {
                state.status = ServiceStatus::Failed;
                state.agent_id = restored.agent_id;
                state.desired_running = restored.desired_running;
                state.ready = false;
                state.healthy = false;
                state.restart_count = restored.restart_count;
                state.last_failure = Some(
                    "configuration changed while the supervisor was offline; rolling restart required"
                        .into(),
                );
                continue;
            }
            state.status = restored.status;
            state.agent_id = restored.agent_id;
            state.restart_count = restored.restart_count;
            state.restart_attempts_total = restored.restart_attempts_total;
            state.last_exit_code = restored.last_exit_code;
            state.desired_running = restored.desired_running;
            state.ready = restored.ready;
            state.healthy = restored.healthy;
            state.restart_exhausted = restored.restart_exhausted;
            state.last_failure = restored.last_failure.clone();
            state.next_restart_at = restored.next_restart_at.clone();
            state.restart_window_started_at = restored.restart_window_started_at.clone();
            state.last_transition_at = restored.last_transition_at.clone();
            state.dependency_blocks = restored.dependency_blocks;
        }
    }

    pub fn metrics(&self) -> ServiceMetrics {
        let mut metrics = ServiceMetrics {
            configured: self.services.len() as u64,
            ..ServiceMetrics::default()
        };
        for state in self.services.values() {
            metrics.desired += u64::from(state.desired_running);
            metrics.running += u64::from(state.status == ServiceStatus::Running);
            metrics.ready += u64::from(state.ready);
            metrics.healthy += u64::from(state.healthy);
            metrics.failed += u64::from(state.status == ServiceStatus::Failed);
            metrics.restarts_total = metrics
                .restarts_total
                .saturating_add(state.restart_attempts_total);
            metrics.dependency_blocks_total = metrics
                .dependency_blocks_total
                .saturating_add(state.dependency_blocks);
        }
        metrics
    }

    /// List all services.
    pub fn list(&self) -> Vec<(&str, ServiceStatus)> {
        self.services
            .iter()
            .map(|(k, v)| (k.as_str(), v.status))
            .collect()
    }

    pub fn list_runtime(&self) -> Vec<ServiceRuntimeInfo> {
        let mut services = self
            .services
            .iter()
            .map(|(name, state)| ServiceRuntimeInfo {
                name: name.clone(),
                status: state.status,
                agent_id: state.agent_id,
                restart_count: state.restart_count,
                restart_attempts_total: state.restart_attempts_total,
                last_exit_code: state.last_exit_code,
                desired_running: state.desired_running,
                ready: state.ready,
                healthy: state.healthy,
                restart_exhausted: state.restart_exhausted,
                last_failure: state.last_failure.clone(),
                next_restart_at: state.next_restart_at.clone(),
                restart_window_started_at: state.restart_window_started_at.clone(),
                last_transition_at: state.last_transition_at.clone(),
                dependency_blocks: state.dependency_blocks,
                definition_revision: state.definition_revision.clone(),
            })
            .collect::<Vec<_>>();
        services.sort_by(|a, b| a.name.cmp(&b.name));
        services
    }
}

impl ServiceDef {
    pub fn token_budget_per_minute(&self) -> Result<Option<u64>, String> {
        let Some(raw) = self.resources.token_budget.as_deref() else {
            return Ok(None);
        };
        let raw = raw.trim();
        if raw.is_empty() {
            return Err(format!("service '{}' has an empty token budget", self.name));
        }
        let (amount, unit) = raw
            .split_once('/')
            .map_or((raw, "minute"), |(amount, unit)| {
                (amount.trim(), unit.trim())
            });
        let amount = amount.parse::<u64>().map_err(|_| {
            format!(
                "service '{}' token budget must start with an integer",
                self.name
            )
        })?;
        if amount == 0 {
            return Err(format!(
                "service '{}' token budget must be positive",
                self.name
            ));
        }
        let per_minute = match unit {
            "minute" | "min" => amount,
            "hour" | "hr" => amount.saturating_add(59) / 60,
            _ => {
                return Err(format!(
                    "service '{}' token budget unit must be minute/min/hour/hr",
                    self.name
                ))
            }
        };
        Ok(Some(per_minute.max(1)))
    }
}

fn definition_revision(definition: &ServiceDef) -> String {
    use ring::digest::{digest, SHA256};

    let encoded = serde_json::to_vec(definition).unwrap_or_default();
    digest(&SHA256, &encoded)
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn deterministic_jitter(name: &str, attempt: u32) -> u64 {
    use ring::digest::{digest, SHA256};

    let material = format!("{name}:{attempt}");
    let bytes = digest(&SHA256, material.as_bytes());
    let mut value = [0u8; 8];
    value.copy_from_slice(&bytes.as_ref()[..8]);
    u64::from_be_bytes(value)
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod tests {
    use super::*;

    fn test_service(name: &str) -> ServiceDef {
        ServiceDef {
            name: name.into(),
            description: None,
            exec: ExecConfig {
                provider: "test".into(),
                system_prompt: "test".into(),
                tools: vec![],
                model: None,
            },
            service: ServiceConfig::default(),
            dependencies: DependencyConfig::default(),
            resources: ResourceConfig::default(),
            policy: ServicePolicyConfig::default(),
            health: HealthConfig::default(),
        }
    }

    #[test]
    fn load_and_list_services() {
        let mut init = InitSystem::new();
        init.load_service(test_service("agent-a"));
        init.load_service(test_service("agent-b"));
        assert_eq!(init.list().len(), 2);
    }

    #[test]
    fn resolve_boot_order_simple() {
        let mut init = InitSystem::new();
        let mut b = test_service("b");
        b.dependencies.requires = vec!["a".into()];
        init.load_service(test_service("a"));
        init.load_service(b);
        init.resolve_boot_order().unwrap();
        let order = init.boot_order();
        let pos_a = order.iter().position(|x| x == "a").unwrap();
        let pos_b = order.iter().position(|x| x == "b").unwrap();
        assert!(pos_a < pos_b); // a before b
    }

    #[test]
    fn circular_dependency_detected() {
        let mut init = InitSystem::new();
        let mut a = test_service("a");
        a.dependencies.requires = vec!["b".into()];
        let mut b = test_service("b");
        b.dependencies.requires = vec!["a".into()];
        init.load_service(a);
        init.load_service(b);
        let result = init.resolve_boot_order();
        assert!(result.is_err());
    }

    #[test]
    fn missing_required_dependency_is_rejected_without_mutating_live_config() {
        let mut init = InitSystem::new();
        init.load_service(test_service("stable"));
        init.resolve_boot_order().unwrap();
        let mut broken = test_service("broken");
        broken.dependencies.requires = vec!["absent".into()];
        assert!(init.replace_definitions(vec![broken]).is_err());
        assert!(init.status("stable").is_some());
        assert!(init.status("broken").is_none());
    }

    #[test]
    fn before_and_after_constraints_are_deterministic() {
        let mut init = InitSystem::new();
        let mut database = test_service("database");
        database.dependencies.before = vec!["api".into()];
        let mut worker = test_service("worker");
        worker.dependencies.after = vec!["api".into()];
        init.replace_definitions(vec![worker, test_service("api"), database])
            .unwrap();
        assert_eq!(init.boot_order(), &["database", "api", "worker"]);
        assert_eq!(init.reverse_boot_order(), vec!["worker", "api", "database"]);
    }

    #[test]
    fn wanted_services_order_when_present_but_are_not_required() {
        let mut init = InitSystem::new();
        let mut api = test_service("api");
        api.dependencies.wants = vec!["cache".into(), "optional-missing".into()];
        init.replace_definitions(vec![api, test_service("cache")])
            .unwrap();
        assert_eq!(init.boot_order(), &["cache", "api"]);
    }

    #[test]
    fn restart_policy_on_failure() {
        let mut init = InitSystem::new();
        init.load_service(test_service("svc"));
        init.mark_starting("svc");
        init.mark_failed("svc", 1);
        assert!(init.should_restart("svc")); // exit code 1 = failure
    }

    #[test]
    fn restart_policy_max_reached() {
        let mut init = InitSystem::new();
        let mut svc = test_service("svc");
        svc.service.max_restarts = 2;
        init.load_service(svc);
        init.mark_failed("svc", 1);
        init.record_restart("svc");
        init.record_restart("svc");
        assert!(!init.should_restart("svc")); // max reached
    }

    #[test]
    fn service_file_parse() {
        let toml = r#"
name = "researcher"
description = "Research agent"

[exec]
provider = "azure-openai"
system_prompt = "You are a researcher"
tools = ["http_get", "browse_url"]

[service]
restart = "OnFailure"
restart_delay_ms = 3000
max_restarts = 5

[dependencies]
requires = ["database"]
after = ["database"]

[resources]
token_budget = "10000/hour"
nice = -5
"#;
        let def: ServiceDef = toml::from_str(toml).unwrap();
        assert_eq!(def.name, "researcher");
        assert_eq!(def.exec.tools.len(), 2);
        assert_eq!(def.dependencies.requires, vec!["database"]);
        assert_eq!(def.resources.nice, Some(-5));
        assert_eq!(def.token_budget_per_minute().unwrap(), Some(167));
    }

    #[test]
    fn invalid_security_and_health_policy_is_rejected_atomically() {
        let mut init = InitSystem::new();
        init.replace_definitions(vec![test_service("stable")])
            .unwrap();
        let mut malicious = test_service("malicious");
        malicious.policy.profile = "host-root".into();
        malicious.policy.tenant_id = "../foreign".into();
        malicious.health.startup_timeout_ms = 0;
        assert!(init.replace_definitions(vec![malicious]).is_err());
        assert!(init.status("stable").is_some());

        let mut trusted = test_service("trusted");
        trusted.policy.sandbox = Some(crate::SandboxConfig {
            workspace_dir: std::path::PathBuf::from("/tmp/agentos-trusted-rejected"),
            allowed_network_hosts: None,
            max_disk_usage_bytes: None,
            max_memory_bytes: None,
            isolation_level: crate::IsolationLevel::Trusted,
            container_image: None,
        });
        assert!(init
            .validate_replacement(vec![trusted])
            .unwrap_err()
            .contains("trusted host isolation"));
    }

    #[test]
    fn secret_references_are_names_only_and_must_be_operator_configured() {
        let mut init = InitSystem::new();
        let mut service = test_service("credentialed");
        service.policy.secret_refs = vec!["openai".into()];
        assert!(init
            .replace_definitions(vec![service.clone()])
            .unwrap_err()
            .contains("unavailable secret"));
        init.set_allowed_secret_refs(["openai".to_string()])
            .unwrap();
        init.replace_definitions(vec![service]).unwrap();
        let serialized = serde_json::to_string(&init.definition("credentialed").unwrap()).unwrap();
        assert!(serialized.contains("openai"));
        assert!(!serialized.contains("secret-value"));
    }

    #[test]
    fn unenforced_service_features_fail_validation_instead_of_being_ignored() {
        let init = InitSystem::new();
        let mut model = test_service("model-override");
        model.exec.model = Some("custom-model".into());
        assert!(init
            .validate_replacement(vec![model])
            .unwrap_err()
            .contains("model override"));

        let mut tools = test_service("tool-list");
        tools.exec.tools = vec!["http_get".into()];
        assert!(init
            .validate_replacement(vec![tools])
            .unwrap_err()
            .contains("tool allow-list"));

        let mut notify = test_service("notify");
        notify.service.service_type = ServiceType::Notify;
        assert!(init
            .validate_replacement(vec![notify])
            .unwrap_err()
            .contains("only Simple"));
    }

    #[test]
    fn restart_backoff_exhausts_within_window_and_resets_after_window() {
        let mut init = InitSystem::new();
        let mut service = test_service("crashy");
        service.service.restart_delay_ms = 10;
        service.service.restart_max_delay_ms = 100;
        service.service.restart_jitter_ms = 0;
        service.service.restart_window_ms = 1_000;
        service.service.max_restarts = 2;
        init.replace_definitions(vec![service]).unwrap();
        init.mark_starting("crashy");
        init.mark_failed_reason("crashy", 1, "crash".into());
        let now = chrono::Utc::now();
        assert_eq!(
            init.schedule_restart("crashy", now),
            Some(std::time::Duration::from_millis(10))
        );
        init.record_restart("crashy");
        init.mark_failed_reason("crashy", 1, "crash again".into());
        assert_eq!(
            init.schedule_restart("crashy", now),
            Some(std::time::Duration::from_millis(20))
        );
        init.record_restart("crashy");
        init.mark_failed_reason("crashy", 1, "crash loop".into());
        assert_eq!(init.schedule_restart("crashy", now), None);
        let exhausted = init.state("crashy").unwrap();
        assert!(exhausted.restart_exhausted);
        assert_eq!(exhausted.restart_count, 2);
        assert_eq!(exhausted.restart_attempts_total, 2);

        let after_window = now + chrono::Duration::milliseconds(1_001);
        assert_eq!(
            init.schedule_restart("crashy", after_window),
            Some(std::time::Duration::from_millis(10))
        );
        let reset_window = init.state("crashy").unwrap();
        assert_eq!(reset_window.restart_count, 0);
        assert_eq!(reset_window.restart_attempts_total, 2);
        assert_eq!(init.metrics().restarts_total, 2);
    }
}
