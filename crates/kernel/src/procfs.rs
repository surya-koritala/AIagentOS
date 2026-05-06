//! ProcFS — virtual filesystem for agent introspection.
//!
//! Like Linux /proc. Exposes agent state, system info, and metrics
//! through a path-based interface.

use std::collections::HashMap;

use crate::agent_struct::AgentId;

/// A procfs entry (file or directory).
#[derive(Debug, Clone)]
pub enum ProcEntry {
    File(String),
    Directory(Vec<String>),
}

/// The proc filesystem.
pub struct ProcFs {
    /// Static system entries.
    system_info: HashMap<String, String>,
    /// Per-agent info generators.
    agent_info: HashMap<AgentId, HashMap<String, String>>,
}

impl ProcFs {
    pub fn new() -> Self {
        let mut system_info = HashMap::new();
        system_info.insert("version".into(), env!("CARGO_PKG_VERSION").to_string());
        system_info.insert("kernel".into(), "ai-agent-os".into());
        Self { system_info, agent_info: HashMap::new() }
    }

    /// Read a proc path.
    pub fn read(&self, path: &str) -> Option<ProcEntry> {
        let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();

        match parts.as_slice() {
            // /system/*
            ["system"] => Some(ProcEntry::Directory(self.system_info.keys().cloned().collect())),
            ["system", key] => self.system_info.get(*key).map(|v| ProcEntry::File(v.clone())),

            // /agents
            ["agents"] => Some(ProcEntry::Directory(self.agent_info.keys().map(|id| id.to_string()).collect())),

            // /agents/<id>
            ["agents", id_str] => {
                let id: AgentId = id_str.parse().ok()?;
                self.agent_info.get(&id).map(|info| ProcEntry::Directory(info.keys().cloned().collect()))
            }

            // /agents/<id>/<key>
            ["agents", id_str, key] => {
                let id: AgentId = id_str.parse().ok()?;
                self.agent_info.get(&id)?.get(*key).map(|v| ProcEntry::File(v.clone()))
            }

            _ => None,
        }
    }

    /// Update system info.
    pub fn set_system(&mut self, key: String, value: String) {
        self.system_info.insert(key, value);
    }

    /// Update agent info.
    pub fn set_agent_info(&mut self, agent_id: AgentId, key: String, value: String) {
        self.agent_info.entry(agent_id).or_default().insert(key, value);
    }

    /// Remove agent (on exit).
    pub fn remove_agent(&mut self, agent_id: AgentId) {
        self.agent_info.remove(&agent_id);
    }

    /// Set load average.
    pub fn update_loadavg(&mut self, running: usize, total: usize) {
        self.system_info.insert("loadavg".into(), format!("{}/{}", running, total));
    }

    /// Set token usage.
    pub fn update_tokeninfo(&mut self, used: u64, budget: u64) {
        self.system_info.insert("tokeninfo".into(), format!("{}/{}", used, budget));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_system_version() {
        let proc = ProcFs::new();
        let entry = proc.read("/system/version").unwrap();
        assert!(matches!(entry, ProcEntry::File(_)));
    }

    #[test]
    fn read_system_directory() {
        let proc = ProcFs::new();
        let entry = proc.read("/system").unwrap();
        assert!(matches!(entry, ProcEntry::Directory(_)));
    }

    #[test]
    fn agent_info() {
        let mut proc = ProcFs::new();
        proc.set_agent_info(1, "state".into(), "running".into());
        proc.set_agent_info(1, "tokens".into(), "5000".into());
        let entry = proc.read("/agents/1/state").unwrap();
        assert!(matches!(entry, ProcEntry::File(ref s) if s == "running"));
    }

    #[test]
    fn list_agents() {
        let mut proc = ProcFs::new();
        proc.set_agent_info(1, "state".into(), "running".into());
        proc.set_agent_info(2, "state".into(), "stopped".into());
        let entry = proc.read("/agents").unwrap();
        if let ProcEntry::Directory(entries) = entry {
            assert_eq!(entries.len(), 2);
        }
    }

    #[test]
    fn nonexistent_path() {
        let proc = ProcFs::new();
        assert!(proc.read("/nonexistent").is_none());
    }

    #[test]
    fn remove_agent() {
        let mut proc = ProcFs::new();
        proc.set_agent_info(1, "state".into(), "running".into());
        proc.remove_agent(1);
        assert!(proc.read("/agents/1/state").is_none());
    }
}
