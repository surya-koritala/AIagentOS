//! Multi-workspace management — isolated project environments.

use std::collections::HashMap;
use crate::agent_struct::AgentId;

/// A workspace (isolated project environment).
#[derive(Debug, Clone)]
pub struct Workspace {
    pub id: String,
    pub name: String,
    pub owner: String, // user_id
    pub agents: Vec<AgentId>,
    pub config: WorkspaceConfig,
    pub created_at: String,
}

/// Per-workspace configuration.
#[derive(Debug, Clone, Default)]
pub struct WorkspaceConfig {
    pub default_provider: String,
    pub token_budget: u64,
    pub max_agents: u32,
    pub tools_enabled: Vec<String>,
}

/// Workspace manager.
pub struct WorkspaceManager {
    workspaces: HashMap<String, Workspace>,
    user_workspaces: HashMap<String, Vec<String>>, // user_id → workspace_ids
    active: HashMap<String, String>, // user_id → active workspace_id
}

impl WorkspaceManager {
    pub fn new() -> Self {
        Self { workspaces: HashMap::new(), user_workspaces: HashMap::new(), active: HashMap::new() }
    }

    /// Create a workspace.
    pub fn create(&mut self, name: String, owner: String, config: WorkspaceConfig) -> String {
        let id = uuid::Uuid::new_v4().to_string();
        self.workspaces.insert(id.clone(), Workspace {
            id: id.clone(), name, owner: owner.clone(), agents: Vec::new(),
            config, created_at: chrono::Utc::now().to_rfc3339(),
        });
        self.user_workspaces.entry(owner.clone()).or_default().push(id.clone());
        self.active.insert(owner, id.clone());
        id
    }

    /// Switch active workspace for a user.
    pub fn switch(&mut self, user_id: &str, workspace_id: &str) -> Result<(), &'static str> {
        if !self.workspaces.contains_key(workspace_id) { return Err("workspace not found"); }
        let user_ws = self.user_workspaces.get(user_id).ok_or("user has no workspaces")?;
        if !user_ws.contains(&workspace_id.to_string()) { return Err("not your workspace"); }
        self.active.insert(user_id.into(), workspace_id.into());
        Ok(())
    }

    /// Get active workspace for a user.
    pub fn active_workspace(&self, user_id: &str) -> Option<&Workspace> {
        let ws_id = self.active.get(user_id)?;
        self.workspaces.get(ws_id)
    }

    /// List workspaces for a user.
    pub fn list_for_user(&self, user_id: &str) -> Vec<&Workspace> {
        self.user_workspaces.get(user_id)
            .map(|ids| ids.iter().filter_map(|id| self.workspaces.get(id)).collect())
            .unwrap_or_default()
    }

    /// Add agent to workspace.
    pub fn add_agent(&mut self, workspace_id: &str, agent_id: AgentId) -> Result<(), &'static str> {
        let ws = self.workspaces.get_mut(workspace_id).ok_or("workspace not found")?;
        if ws.config.max_agents > 0 && ws.agents.len() as u32 >= ws.config.max_agents {
            return Err("workspace agent limit reached");
        }
        ws.agents.push(agent_id);
        Ok(())
    }

    /// Delete a workspace.
    pub fn delete(&mut self, workspace_id: &str) -> Result<(), &'static str> {
        let ws = self.workspaces.remove(workspace_id).ok_or("workspace not found")?;
        if let Some(user_ws) = self.user_workspaces.get_mut(&ws.owner) {
            user_ws.retain(|id| id != workspace_id);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_and_switch() {
        let mut mgr = WorkspaceManager::new();
        let ws1 = mgr.create("project-a".into(), "user1".into(), WorkspaceConfig::default());
        let ws2 = mgr.create("project-b".into(), "user1".into(), WorkspaceConfig::default());
        assert_eq!(mgr.list_for_user("user1").len(), 2);
        mgr.switch("user1", &ws1).unwrap();
        assert_eq!(mgr.active_workspace("user1").unwrap().id, ws1);
    }

    #[test]
    fn agent_limit() {
        let mut mgr = WorkspaceManager::new();
        let ws = mgr.create("limited".into(), "u".into(), WorkspaceConfig { max_agents: 2, ..Default::default() });
        mgr.add_agent(&ws, 1).unwrap();
        mgr.add_agent(&ws, 2).unwrap();
        assert!(mgr.add_agent(&ws, 3).is_err());
    }

    #[test]
    fn delete_workspace() {
        let mut mgr = WorkspaceManager::new();
        let ws = mgr.create("temp".into(), "u".into(), WorkspaceConfig::default());
        mgr.delete(&ws).unwrap();
        assert_eq!(mgr.list_for_user("u").len(), 0);
    }
}
