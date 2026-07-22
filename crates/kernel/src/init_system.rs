//! Init System — service management, dependencies, restart policies.
//!
//! Like systemd for AI agents. Manages agent lifecycle declaratively.

use std::collections::HashMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::AgentId;

/// Agent service definition (like a systemd unit file).
#[derive(Debug, Clone, Serialize, Deserialize)]
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
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExecConfig {
    pub provider: String,
    pub system_prompt: String,
    #[serde(default)]
    pub tools: Vec<String>,
    #[serde(default)]
    pub model: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceConfig {
    pub restart: RestartPolicy,
    #[serde(default = "default_restart_delay")]
    pub restart_delay_ms: u64,
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
            max_restarts: 3,
            service_type: ServiceType::Simple,
        }
    }
}

fn default_restart_delay() -> u64 {
    5000
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

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResourceConfig {
    pub token_budget: Option<String>,
    pub max_context: Option<u64>,
    pub nice: Option<i8>,
}

/// Runtime state of a service.
#[derive(Debug, Clone)]
pub struct ServiceState {
    pub def: ServiceDef,
    pub status: ServiceStatus,
    pub agent_id: Option<AgentId>,
    pub restart_count: u32,
    pub last_exit_code: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServiceRuntimeInfo {
    pub name: String,
    pub status: ServiceStatus,
    pub agent_id: Option<AgentId>,
    pub restart_count: u32,
    pub last_exit_code: Option<i32>,
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

/// The init system — manages all services.
pub struct InitSystem {
    services: HashMap<String, ServiceState>,
    boot_order: Vec<String>,
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
        }
    }

    /// Load a service definition.
    pub fn load_service(&mut self, def: ServiceDef) {
        let name = def.name.clone();
        self.services.insert(
            name.clone(),
            ServiceState {
                def,
                status: ServiceStatus::Inactive,
                agent_id: None,
                restart_count: 0,
                last_exit_code: None,
            },
        );
    }

    /// Load all service files from a directory.
    pub fn load_directory(&mut self, dir: &Path) {
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.filter_map(|e| e.ok()) {
                if entry
                    .path()
                    .extension()
                    .map(|e| e == "toml")
                    .unwrap_or(false)
                {
                    if let Ok(content) = std::fs::read_to_string(entry.path()) {
                        if let Ok(def) = toml::from_str::<ServiceDef>(&content) {
                            self.load_service(def);
                        }
                    }
                }
            }
        }
    }

    /// Parse and validate a service directory as one atomic configuration. A
    /// malformed file, duplicate name, missing required dependency, or cycle
    /// rejects the entire reload and leaves the current supervisor unchanged.
    pub fn load_directory_checked(&mut self, dir: &Path) -> Result<Vec<String>, String> {
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
        self.replace_definitions(definitions)
    }

    /// Atomically replace definitions after validating the complete dependency
    /// graph. Runtime state is retained for services with the same name.
    pub fn replace_definitions(
        &mut self,
        definitions: Vec<ServiceDef>,
    ) -> Result<Vec<String>, String> {
        let mut replacement = InitSystem::new();
        for definition in definitions {
            if definition.name.trim().is_empty()
                || definition.name.chars().any(|character| {
                    !(character.is_ascii_alphanumeric() || "-_.".contains(character))
                })
            {
                return Err(format!("invalid service name '{}'", definition.name));
            }
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
            }
        }
        let order = replacement.boot_order.clone();
        *self = replacement;
        Ok(order)
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

    pub fn state(&self, name: &str) -> Option<ServiceState> {
        self.services.get(name).cloned()
    }

    pub fn mark_starting(&mut self, name: &str) -> bool {
        if let Some(state) = self.services.get_mut(name) {
            state.status = ServiceStatus::Starting;
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
        }
    }

    /// Mark service as failed.
    pub fn mark_failed(&mut self, name: &str, exit_code: i32) {
        if let Some(state) = self.services.get_mut(name) {
            state.status = ServiceStatus::Failed;
            state.last_exit_code = Some(exit_code);
        }
    }

    pub fn mark_stopping(&mut self, name: &str) -> bool {
        if let Some(state) = self.services.get_mut(name) {
            state.status = ServiceStatus::Stopping;
            true
        } else {
            false
        }
    }

    pub fn mark_stopped(&mut self, name: &str) -> bool {
        if let Some(state) = self.services.get_mut(name) {
            state.status = ServiceStatus::Inactive;
            state.agent_id = None;
            state.last_exit_code = Some(0);
            true
        } else {
            false
        }
    }

    /// Check if service should restart.
    pub fn should_restart(&self, name: &str) -> bool {
        if let Some(state) = self.services.get(name) {
            if state.restart_count >= state.def.service.max_restarts {
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
            state.restart_count += 1;
            state.status = ServiceStatus::Restarting;
        }
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
                last_exit_code: state.last_exit_code,
            })
            .collect::<Vec<_>>();
        services.sort_by(|a, b| a.name.cmp(&b.name));
        services
    }
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
    fn restart_policy_on_failure() {
        let mut init = InitSystem::new();
        init.load_service(test_service("svc"));
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
    }
}

// ─── Socket Activation ───────────────────────────────────────────────────────

impl InitSystem {
    /// Check if a service should be socket-activated (started on first connection).
    pub fn is_socket_activated(&self, name: &str) -> bool {
        self.services
            .get(name)
            .map(|s| {
                s.def.service.service_type == ServiceType::Notify
                    && s.status == ServiceStatus::Inactive
            })
            .unwrap_or(false)
    }

    /// Trigger socket activation for a service.
    pub fn socket_activate(&mut self, name: &str) -> bool {
        if let Some(state) = self.services.get_mut(name) {
            if state.status == ServiceStatus::Inactive {
                state.status = ServiceStatus::Starting;
                return true;
            }
        }
        false
    }
}
