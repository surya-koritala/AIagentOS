//! Permission System — enforces access control with role-based profiles.
//!
//! Provides predefined profiles (read-only, standard, elevated, full-access),
//! glob-based rule matching, elevation requests, and append-only audit logging.

use std::sync::Mutex;

use chrono::{DateTime, Utc};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};

use crate::resources::ResourceType;
use crate::{AgentId, PermissionError, PermissionProfileId};

/// Access decision for a resource request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AccessDecision {
    Allowed,
    Denied,
    RequiresApproval,
}

/// A single permission rule within a profile.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionRule {
    pub resource_type: ResourceType,
    pub operations: Vec<String>,
    pub targets: Option<Vec<String>>,
    pub decision: AccessDecision,
}

/// A named permission profile containing a set of rules.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionProfile {
    pub id: PermissionProfileId,
    pub name: String,
    pub rules: Vec<PermissionRule>,
}

/// Outcome of an action after the access decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ActionOutcome {
    Success,
    Failure,
    Pending,
    Timeout,
}

/// An entry in the audit log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub timestamp: DateTime<Utc>,
    pub agent_id: AgentId,
    pub action: String,
    pub resource: String,
    pub decision: AccessDecision,
    pub outcome: ActionOutcome,
}

/// Filter criteria for querying the audit log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditFilter {
    pub agent_id: Option<AgentId>,
    pub resource: Option<String>,
    pub decision: Option<AccessDecision>,
    pub from: Option<DateTime<Utc>>,
    pub to: Option<DateTime<Utc>>,
}

/// The Permission System trait.
#[async_trait::async_trait]
pub trait PermissionSystem: Send + Sync {
    fn check_access(
        &self,
        agent_id: AgentId,
        resource: &ResourceType,
        operation: &str,
        target: Option<&str>,
    ) -> AccessDecision;
    async fn request_elevation(
        &self,
        agent_id: AgentId,
        action: &str,
    ) -> Result<AccessDecision, PermissionError>;
    fn assign_profile(&self, agent_id: AgentId, profile_id: &PermissionProfileId);
    fn get_audit_log(&self, filter: Option<&AuditFilter>) -> Vec<AuditEntry>;
    fn log_action(
        &self,
        agent_id: AgentId,
        action: &str,
        resource: &str,
        decision: AccessDecision,
        outcome: ActionOutcome,
    );
}

/// Operations considered high-risk that always require approval (except full-access).
const HIGH_RISK_OPS: &[&str] = &[
    "delete",
    "execute",
    "install",
    "uninstall",
    "format",
    "sudo",
];

/// Concrete permission system implementation.
pub struct PermissionManager {
    /// Predefined and custom profiles.
    profiles: DashMap<PermissionProfileId, PermissionProfile>,
    /// Agent-to-profile assignments.
    agent_profiles: DashMap<AgentId, PermissionProfileId>,
    /// Append-only audit log.
    audit_log: Mutex<Vec<AuditEntry>>,
}

impl Default for PermissionManager {
    fn default() -> Self {
        Self::new()
    }
}

impl PermissionManager {
    pub fn new() -> Self {
        let mgr = Self {
            profiles: DashMap::new(),
            agent_profiles: DashMap::new(),
            audit_log: Mutex::new(Vec::new()),
        };
        mgr.register_predefined_profiles();
        mgr
    }

    fn register_predefined_profiles(&self) {
        // Read-only: only read operations allowed
        self.profiles.insert(
            "read-only".to_string(),
            PermissionProfile {
                id: "read-only".to_string(),
                name: "Read Only".to_string(),
                rules: vec![
                    PermissionRule {
                        resource_type: ResourceType::Filesystem,
                        operations: vec!["read".to_string(), "list".to_string()],
                        targets: None,
                        decision: AccessDecision::Allowed,
                    },
                    PermissionRule {
                        resource_type: ResourceType::Network,
                        operations: vec!["get".to_string()],
                        targets: None,
                        decision: AccessDecision::Allowed,
                    },
                ],
            },
        );

        // Standard: read/write but no destructive ops
        self.profiles.insert(
            "standard".to_string(),
            PermissionProfile {
                id: "standard".to_string(),
                name: "Standard".to_string(),
                rules: vec![
                    PermissionRule {
                        resource_type: ResourceType::Filesystem,
                        operations: vec![
                            "read".to_string(),
                            "write".to_string(),
                            "create".to_string(),
                            "create_dir".to_string(),
                            "edit".to_string(),
                            "list".to_string(),
                        ],
                        targets: None,
                        decision: AccessDecision::Allowed,
                    },
                    PermissionRule {
                        resource_type: ResourceType::Network,
                        operations: vec!["get".to_string(), "post".to_string()],
                        targets: None,
                        decision: AccessDecision::Allowed,
                    },
                    PermissionRule {
                        resource_type: ResourceType::Application,
                        operations: vec!["launch".to_string(), "read_output".to_string()],
                        targets: None,
                        decision: AccessDecision::Allowed,
                    },
                    PermissionRule {
                        resource_type: ResourceType::Ipc,
                        operations: vec![
                            "send".to_string(),
                            "receive".to_string(),
                            "delegate".to_string(),
                            "delegation_status".to_string(),
                            "complete_delegation".to_string(),
                            "discover".to_string(),
                        ],
                        targets: None,
                        decision: AccessDecision::Allowed,
                    },
                ],
            },
        );

        // Elevated: most operations allowed, destructive require approval
        self.profiles.insert(
            "elevated".to_string(),
            PermissionProfile {
                id: "elevated".to_string(),
                name: "Elevated".to_string(),
                rules: vec![
                    PermissionRule {
                        resource_type: ResourceType::Filesystem,
                        operations: vec![
                            "read".to_string(),
                            "write".to_string(),
                            "create".to_string(),
                            "create_dir".to_string(),
                            "edit".to_string(),
                            "list".to_string(),
                            "delete".to_string(),
                        ],
                        targets: None,
                        decision: AccessDecision::Allowed,
                    },
                    PermissionRule {
                        resource_type: ResourceType::Network,
                        operations: vec![
                            "get".to_string(),
                            "post".to_string(),
                            "put".to_string(),
                            "delete".to_string(),
                        ],
                        targets: None,
                        decision: AccessDecision::Allowed,
                    },
                    PermissionRule {
                        resource_type: ResourceType::Application,
                        operations: vec![
                            "launch".to_string(),
                            "close".to_string(),
                            "send_input".to_string(),
                            "read_output".to_string(),
                        ],
                        targets: None,
                        decision: AccessDecision::Allowed,
                    },
                    PermissionRule {
                        resource_type: ResourceType::Browser,
                        operations: vec![
                            "navigate".to_string(),
                            "click".to_string(),
                            "type".to_string(),
                            "read".to_string(),
                        ],
                        targets: None,
                        decision: AccessDecision::Allowed,
                    },
                    PermissionRule {
                        resource_type: ResourceType::Ipc,
                        operations: vec![
                            "send".to_string(),
                            "receive".to_string(),
                            "delegate".to_string(),
                            "delegation_status".to_string(),
                            "complete_delegation".to_string(),
                            "discover".to_string(),
                        ],
                        targets: None,
                        decision: AccessDecision::Allowed,
                    },
                ],
            },
        );

        // Full-access: everything allowed, no approval needed
        self.profiles.insert(
            "full-access".to_string(),
            PermissionProfile {
                id: "full-access".to_string(),
                name: "Full Access".to_string(),
                rules: vec![], // Empty rules = allow everything
            },
        );
    }

    fn matches_glob(pattern: &str, target: &str) -> bool {
        if pattern == "*" {
            return true;
        }
        if let Some(prefix) = pattern.strip_suffix('*') {
            return target.starts_with(prefix);
        }
        if let Some(suffix) = pattern.strip_prefix('*') {
            return target.ends_with(suffix);
        }
        pattern == target
    }

    fn find_matching_rule(
        &self,
        profile: &PermissionProfile,
        resource: &ResourceType,
        operation: &str,
        target: Option<&str>,
    ) -> Option<AccessDecision> {
        for rule in &profile.rules {
            if &rule.resource_type != resource {
                continue;
            }
            if !rule
                .operations
                .iter()
                .any(|op| op == operation || op == "*")
            {
                continue;
            }
            // Check target patterns if specified
            if let (Some(patterns), Some(t)) = (&rule.targets, target) {
                if !patterns.iter().any(|p| Self::matches_glob(p, t)) {
                    continue;
                }
            }
            return Some(rule.decision.clone());
        }
        None
    }
}

#[async_trait::async_trait]
impl PermissionSystem for PermissionManager {
    fn check_access(
        &self,
        agent_id: AgentId,
        resource: &ResourceType,
        operation: &str,
        target: Option<&str>,
    ) -> AccessDecision {
        let profile_id = self
            .agent_profiles
            .get(&agent_id)
            .map(|r| r.value().clone())
            .unwrap_or_else(|| "standard".to_string());

        // Full-access bypasses all checks including high-risk
        if profile_id == "full-access" {
            return AccessDecision::Allowed;
        }

        // High-risk operations always require approval (except full-access)
        if HIGH_RISK_OPS.contains(&operation) {
            return AccessDecision::RequiresApproval;
        }

        let profile = match self.profiles.get(&profile_id) {
            Some(p) => p.clone(),
            None => return AccessDecision::Denied,
        };

        self.find_matching_rule(&profile, resource, operation, target)
            .unwrap_or(AccessDecision::Denied)
    }

    async fn request_elevation(
        &self,
        _agent_id: AgentId,
        _action: &str,
    ) -> Result<AccessDecision, PermissionError> {
        // In a real implementation, this would prompt the user via the UI.
        // For now, return RequiresApproval to indicate the request was registered.
        Ok(AccessDecision::RequiresApproval)
    }

    fn assign_profile(&self, agent_id: AgentId, profile_id: &PermissionProfileId) {
        self.agent_profiles.insert(agent_id, profile_id.clone());
    }

    fn get_audit_log(&self, filter: Option<&AuditFilter>) -> Vec<AuditEntry> {
        let log = self.audit_log.lock().unwrap();
        match filter {
            None => log.clone(),
            Some(f) => log
                .iter()
                .filter(|entry| {
                    if let Some(aid) = f.agent_id {
                        if entry.agent_id != aid {
                            return false;
                        }
                    }
                    if let Some(ref res) = f.resource {
                        if &entry.resource != res {
                            return false;
                        }
                    }
                    if let Some(ref dec) = f.decision {
                        if &entry.decision != dec {
                            return false;
                        }
                    }
                    if let Some(from) = f.from {
                        if entry.timestamp < from {
                            return false;
                        }
                    }
                    if let Some(to) = f.to {
                        if entry.timestamp > to {
                            return false;
                        }
                    }
                    true
                })
                .cloned()
                .collect(),
        }
    }

    fn log_action(
        &self,
        agent_id: AgentId,
        action: &str,
        resource: &str,
        decision: AccessDecision,
        outcome: ActionOutcome,
    ) {
        let entry = AuditEntry {
            timestamp: Utc::now(),
            agent_id,
            action: action.to_string(),
            resource: resource.to_string(),
            decision,
            outcome,
        };
        self.audit_log.lock().unwrap().push(entry);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_only_allows_read() {
        let mgr = PermissionManager::new();
        let id = uuid::Uuid::new_v4();
        mgr.assign_profile(id, &"read-only".to_string());
        assert_eq!(
            mgr.check_access(id, &ResourceType::Filesystem, "read", None),
            AccessDecision::Allowed
        );
    }

    #[test]
    fn read_only_denies_write() {
        let mgr = PermissionManager::new();
        let id = uuid::Uuid::new_v4();
        mgr.assign_profile(id, &"read-only".to_string());
        assert_eq!(
            mgr.check_access(id, &ResourceType::Filesystem, "write", None),
            AccessDecision::Denied
        );
    }

    #[test]
    fn standard_allows_write() {
        let mgr = PermissionManager::new();
        let id = uuid::Uuid::new_v4();
        mgr.assign_profile(id, &"standard".to_string());
        assert_eq!(
            mgr.check_access(id, &ResourceType::Filesystem, "write", None),
            AccessDecision::Allowed
        );
    }

    #[test]
    fn high_risk_requires_approval() {
        let mgr = PermissionManager::new();
        let id = uuid::Uuid::new_v4();
        mgr.assign_profile(id, &"standard".to_string());
        assert_eq!(
            mgr.check_access(id, &ResourceType::Filesystem, "delete", None),
            AccessDecision::RequiresApproval
        );
    }

    #[test]
    fn full_access_allows_high_risk() {
        let mgr = PermissionManager::new();
        let id = uuid::Uuid::new_v4();
        mgr.assign_profile(id, &"full-access".to_string());
        assert_eq!(
            mgr.check_access(id, &ResourceType::Filesystem, "delete", None),
            AccessDecision::Allowed
        );
    }

    #[test]
    fn audit_log_records_actions() {
        let mgr = PermissionManager::new();
        let id = uuid::Uuid::new_v4();
        mgr.log_action(
            id,
            "read file",
            "filesystem",
            AccessDecision::Allowed,
            ActionOutcome::Success,
        );
        let log = mgr.get_audit_log(None);
        assert_eq!(log.len(), 1);
        assert_eq!(log[0].action, "read file");
    }

    #[test]
    fn audit_log_filters() {
        let mgr = PermissionManager::new();
        let id1 = uuid::Uuid::new_v4();
        let id2 = uuid::Uuid::new_v4();
        mgr.log_action(
            id1,
            "read",
            "fs",
            AccessDecision::Allowed,
            ActionOutcome::Success,
        );
        mgr.log_action(
            id2,
            "write",
            "fs",
            AccessDecision::Denied,
            ActionOutcome::Failure,
        );

        let filter = AuditFilter {
            agent_id: Some(id1),
            resource: None,
            decision: None,
            from: None,
            to: None,
        };
        let log = mgr.get_audit_log(Some(&filter));
        assert_eq!(log.len(), 1);
        assert_eq!(log[0].agent_id, id1);
    }

    #[test]
    fn default_profile_is_standard() {
        let mgr = PermissionManager::new();
        let id = uuid::Uuid::new_v4();
        // No profile assigned — defaults to standard
        assert_eq!(
            mgr.check_access(id, &ResourceType::Filesystem, "read", None),
            AccessDecision::Allowed
        );
        assert_eq!(
            mgr.check_access(id, &ResourceType::Filesystem, "write", None),
            AccessDecision::Allowed
        );
    }

    #[test]
    fn glob_matching() {
        assert!(PermissionManager::matches_glob("*", "/any/path"));
        assert!(PermissionManager::matches_glob("/home/*", "/home/user"));
        assert!(PermissionManager::matches_glob("*.txt", "file.txt"));
        assert!(!PermissionManager::matches_glob("/home/*", "/etc/passwd"));
    }
}
