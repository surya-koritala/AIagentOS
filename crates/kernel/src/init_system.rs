//! Init System — service management, dependencies, restart policies.
//!
//! Like systemd for AI agents. Manages agent lifecycle declaratively.

use std::collections::HashMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::agent_struct::AgentId;

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

fn default_restart_delay() -> u64 { 5000 }
fn default_max_restarts() -> u32 { 3 }

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

impl InitSystem {
    pub fn new() -> Self {
        Self { services: HashMap::new(), boot_order: Vec::new() }
    }

    /// Load a service definition.
    pub fn load_service(&mut self, def: ServiceDef) {
        let name = def.name.clone();
        self.services.insert(name.clone(), ServiceState {
            def,
            status: ServiceStatus::Inactive,
            agent_id: None,
            restart_count: 0,
            last_exit_code: None,
        });
    }

    /// Load all service files from a directory.
    pub fn load_directory(&mut self, dir: &Path) {
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.filter_map(|e| e.ok()) {
                if entry.path().extension().map(|e| e == "toml").unwrap_or(false) {
                    if let Ok(content) = std::fs::read_to_string(entry.path()) {
                        if let Ok(def) = toml::from_str::<ServiceDef>(&content) {
                            self.load_service(def);
                        }
                    }
                }
            }
        }
    }

    /// Resolve boot order (topological sort of dependencies).
    pub fn resolve_boot_order(&mut self) -> Result<(), String> {
        let mut order = Vec::new();
        let mut visited = std::collections::HashSet::new();
        let mut visiting = std::collections::HashSet::new();

        let names: Vec<String> = self.services.keys().cloned().collect();
        for name in &names {
            self.topo_sort(name, &mut order, &mut visited, &mut visiting)?;
        }

        self.boot_order = order;
        Ok(())
    }

    fn topo_sort(
        &self, name: &str, order: &mut Vec<String>,
        visited: &mut std::collections::HashSet<String>,
        visiting: &mut std::collections::HashSet<String>,
    ) -> Result<(), String> {
        if visited.contains(name) { return Ok(()); }
        if visiting.contains(name) { return Err(format!("Circular dependency: {}", name)); }

        visiting.insert(name.to_string());

        if let Some(state) = self.services.get(name) {
            for dep in &state.def.dependencies.requires {
                self.topo_sort(dep, order, visited, visiting)?;
            }
            for dep in &state.def.dependencies.after {
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

    /// Check if service should restart.
    pub fn should_restart(&self, name: &str) -> bool {
        if let Some(state) = self.services.get(name) {
            if state.restart_count >= state.def.service.max_restarts { return false; }
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
        self.services.iter().map(|(k, v)| (k.as_str(), v.status)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_service(name: &str) -> ServiceDef {
        ServiceDef {
            name: name.into(),
            description: None,
            exec: ExecConfig { provider: "test".into(), system_prompt: "test".into(), tools: vec![], model: None },
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
        self.services.get(name).map(|s| s.def.service.service_type == ServiceType::Notify && s.status == ServiceStatus::Inactive).unwrap_or(false)
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
