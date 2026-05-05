//! Core data model structs for the AI Agent OS.
//!
//! These structs represent the persisted entities in the system:
//! sessions, agents, context snapshots, memory entries, module manifests,
//! and audit log entries.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::context::{FactCategory, Message, Task, TaskResult};
use crate::modules::ResourceRequirements;
use crate::observability::Metrics;
use crate::permissions::{AccessDecision, ActionOutcome, PermissionRule};
use crate::{AgentConfig, AgentId, AgentState, ModuleId, SandboxId, SessionId};

// ─── Session ─────────────────────────────────────────────────────────────────

/// Session — top-level execution context grouping agents together.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    /// Unique session identifier.
    pub id: SessionId,
    /// The user who owns this session.
    pub user_id: String,
    /// Agents active within this session.
    pub agents: Vec<AgentId>,
    /// When the session was created.
    pub created_at: DateTime<Utc>,
    /// When the session was last active.
    pub last_active_at: DateTime<Utc>,
    /// Current session status.
    pub status: SessionStatus,
    /// Arbitrary metadata associated with the session.
    pub metadata: serde_json::Value,
}

/// Status of a session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionStatus {
    /// Session is currently active.
    Active,
    /// Session is paused.
    Paused,
    /// Session has been archived.
    Archived,
}

// ─── Agent ───────────────────────────────────────────────────────────────────

/// Agent instance — the persisted representation of a running agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Agent {
    /// Unique agent identifier.
    pub id: AgentId,
    /// The session this agent belongs to.
    pub session_id: SessionId,
    /// Human-readable agent name.
    pub name: String,
    /// Current lifecycle state.
    pub state: AgentState,
    /// Configuration used to create this agent.
    pub config: AgentConfig,
    /// Sandbox assigned to this agent (if any).
    pub sandbox_id: Option<SandboxId>,
    /// When the agent was created.
    pub created_at: DateTime<Utc>,
    /// When the agent last performed an action.
    pub last_activity_at: DateTime<Utc>,
    /// Aggregated metrics for this agent.
    pub metrics: Metrics,
}

// ─── Context Snapshot ────────────────────────────────────────────────────────

/// A summary of a previously summarized conversation segment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Summary {
    /// The summarized text content.
    pub content: String,
    /// Number of original messages that were summarized.
    pub original_message_count: usize,
    /// Token count of the summary.
    pub token_count: u32,
    /// When the summary was created.
    pub created_at: DateTime<Utc>,
}

/// Persisted context snapshot — captures the full state of an agent's context
/// at a point in time for persistence and restoration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextSnapshot {
    /// The agent this snapshot belongs to.
    pub agent_id: AgentId,
    /// The session this snapshot belongs to.
    pub session_id: SessionId,
    /// Full conversation history at snapshot time.
    pub conversation_history: Vec<Message>,
    /// Arbitrary working state (JSON).
    pub working_state: serde_json::Value,
    /// Active tasks at snapshot time.
    pub active_tasks: Vec<Task>,
    /// Intermediate results from completed sub-tasks.
    pub intermediate_results: Vec<TaskResult>,
    /// Previously summarized conversation segments.
    pub summarized_segments: Vec<Summary>,
    /// Total token count of the context.
    pub token_count: u32,
    /// When this snapshot was taken.
    pub snapshot_at: DateTime<Utc>,
}

// ─── Memory Entry ────────────────────────────────────────────────────────────

/// Long-term memory entry — a fact stored for semantic retrieval.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryEntry {
    /// Unique memory entry identifier.
    pub id: uuid::Uuid,
    /// The agent this memory belongs to.
    pub agent_id: AgentId,
    /// The content of the memory entry.
    pub content: String,
    /// Category of the memory entry.
    pub category: FactCategory,
    /// Tags for filtering and organization.
    pub tags: Vec<String>,
    /// Embedding vector for semantic search.
    pub embedding: Vec<f32>,
    /// When this entry was created.
    pub created_at: DateTime<Utc>,
    /// When this entry was last accessed.
    pub last_accessed_at: DateTime<Utc>,
    /// Number of times this entry has been accessed.
    pub access_count: u32,
}

// ─── Module Manifest ─────────────────────────────────────────────────────────

/// A dependency declared by a module.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleDependency {
    /// The module ID of the dependency.
    pub module_id: ModuleId,
    /// Required version (semver range).
    pub version_requirement: String,
}

/// Module manifest — metadata loaded from a module's manifest file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleManifest {
    /// Unique module identifier.
    pub id: ModuleId,
    /// Human-readable module name.
    pub name: String,
    /// Module version string.
    pub version: String,
    /// Module author.
    pub author: String,
    /// Description of what the module does.
    pub description: String,
    /// Path to the .wasm entry point file.
    pub entry_point: String,
    /// Permissions the module requires.
    pub permissions: Vec<PermissionRule>,
    /// Capabilities the module provides.
    pub capabilities: Vec<String>,
    /// Other modules this module depends on.
    pub dependencies: Vec<ModuleDependency>,
    /// Resource requirements for running this module.
    pub resource_requirements: ResourceRequirements,
}

// ─── Audit Log Entry ─────────────────────────────────────────────────────────

/// Audit log entry — records an agent action for compliance and transparency.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLogEntry {
    /// Unique entry identifier.
    pub id: uuid::Uuid,
    /// When the action occurred.
    pub timestamp: DateTime<Utc>,
    /// The agent that performed the action.
    pub agent_id: AgentId,
    /// The session the action occurred in.
    pub session_id: SessionId,
    /// Type of action (e.g., "resource_access", "tool_call").
    pub action_type: String,
    /// The resource that was accessed.
    pub resource: String,
    /// The operation performed on the resource.
    pub operation: String,
    /// Optional target (path, URL, etc.).
    pub target: Option<String>,
    /// The access decision that was made.
    pub decision: AccessDecision,
    /// The outcome of the action.
    pub outcome: ActionOutcome,
    /// Optional additional metadata.
    pub metadata: Option<serde_json::Value>,
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_serialization_round_trip() {
        let session = Session {
            id: uuid::Uuid::new_v4(),
            user_id: "user-123".to_string(),
            agents: vec![uuid::Uuid::new_v4()],
            created_at: Utc::now(),
            last_active_at: Utc::now(),
            status: SessionStatus::Active,
            metadata: serde_json::json!({"theme": "dark"}),
        };

        let json = serde_json::to_string(&session).unwrap();
        let deserialized: Session = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.id, session.id);
        assert_eq!(deserialized.user_id, session.user_id);
        assert_eq!(deserialized.status, session.status);
    }

    #[test]
    fn session_status_variants() {
        let statuses = vec![
            SessionStatus::Active,
            SessionStatus::Paused,
            SessionStatus::Archived,
        ];
        for status in &statuses {
            let json = serde_json::to_string(status).unwrap();
            let deserialized: SessionStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(&deserialized, status);
        }
    }

    #[test]
    fn agent_model_construction() {
        use crate::Priority;

        let agent = Agent {
            id: uuid::Uuid::new_v4(),
            session_id: uuid::Uuid::new_v4(),
            name: "test-agent".to_string(),
            state: AgentState::Running,
            config: AgentConfig {
                name: "test-agent".to_string(),
                task: "organize files".to_string(),
                llm_provider: "openai".to_string(),
                permission_profile: "standard".to_string(),
                priority: Priority::new(2).unwrap(),
                sandbox_config: None,
            },
            sandbox_id: Some(uuid::Uuid::new_v4()),
            created_at: Utc::now(),
            last_activity_at: Utc::now(),
            metrics: Metrics::default(),
        };

        assert_eq!(agent.name, "test-agent");
        assert_eq!(agent.state, AgentState::Running);
        assert!(agent.sandbox_id.is_some());
    }

    #[test]
    fn context_snapshot_construction() {
        let snapshot = ContextSnapshot {
            agent_id: uuid::Uuid::new_v4(),
            session_id: uuid::Uuid::new_v4(),
            conversation_history: vec![Message {
                role: "user".to_string(),
                content: "Hello".to_string(),
                timestamp: Utc::now(),
            }],
            working_state: serde_json::json!({}),
            active_tasks: vec![],
            intermediate_results: vec![],
            summarized_segments: vec![Summary {
                content: "Previous conversation summary".to_string(),
                original_message_count: 10,
                token_count: 50,
                created_at: Utc::now(),
            }],
            token_count: 100,
            snapshot_at: Utc::now(),
        };

        assert_eq!(snapshot.conversation_history.len(), 1);
        assert_eq!(snapshot.summarized_segments.len(), 1);
        assert_eq!(snapshot.token_count, 100);
    }

    #[test]
    fn memory_entry_construction() {
        let entry = MemoryEntry {
            id: uuid::Uuid::new_v4(),
            agent_id: uuid::Uuid::new_v4(),
            content: "User prefers dark mode".to_string(),
            category: FactCategory::Preference,
            tags: vec!["ui".to_string(), "preference".to_string()],
            embedding: vec![0.1, 0.2, 0.3],
            created_at: Utc::now(),
            last_accessed_at: Utc::now(),
            access_count: 5,
        };

        assert_eq!(entry.content, "User prefers dark mode");
        assert_eq!(entry.category, FactCategory::Preference);
        assert_eq!(entry.tags.len(), 2);
        assert_eq!(entry.access_count, 5);
    }

    #[test]
    fn module_manifest_construction() {
        let manifest = ModuleManifest {
            id: "my-module".to_string(),
            name: "My Module".to_string(),
            version: "1.0.0".to_string(),
            author: "Test Author".to_string(),
            description: "A test module".to_string(),
            entry_point: "module.wasm".to_string(),
            permissions: vec![],
            capabilities: vec!["file-search".to_string()],
            dependencies: vec![ModuleDependency {
                module_id: "base-module".to_string(),
                version_requirement: ">=0.5.0".to_string(),
            }],
            resource_requirements: ResourceRequirements {
                max_memory_bytes: Some(64 * 1024 * 1024),
                max_cpu_time_ms: Some(5000),
                network_access: false,
                filesystem_access: vec!["/tmp/*".to_string()],
            },
        };

        assert_eq!(manifest.id, "my-module");
        assert_eq!(manifest.capabilities.len(), 1);
        assert_eq!(manifest.dependencies.len(), 1);
    }

    #[test]
    fn audit_log_entry_construction() {
        let entry = AuditLogEntry {
            id: uuid::Uuid::new_v4(),
            timestamp: Utc::now(),
            agent_id: uuid::Uuid::new_v4(),
            session_id: uuid::Uuid::new_v4(),
            action_type: "resource_access".to_string(),
            resource: "filesystem".to_string(),
            operation: "read".to_string(),
            target: Some("/home/user/docs".to_string()),
            decision: AccessDecision::Allowed,
            outcome: ActionOutcome::Success,
            metadata: Some(serde_json::json!({"bytes_read": 1024})),
        };

        assert_eq!(entry.action_type, "resource_access");
        assert_eq!(entry.decision, AccessDecision::Allowed);
        assert_eq!(entry.outcome, ActionOutcome::Success);
        assert!(entry.target.is_some());
        assert!(entry.metadata.is_some());
    }

    #[test]
    fn audit_log_entry_serialization_round_trip() {
        let entry = AuditLogEntry {
            id: uuid::Uuid::new_v4(),
            timestamp: Utc::now(),
            agent_id: uuid::Uuid::new_v4(),
            session_id: uuid::Uuid::new_v4(),
            action_type: "tool_call".to_string(),
            resource: "network".to_string(),
            operation: "http_get".to_string(),
            target: None,
            decision: AccessDecision::Denied,
            outcome: ActionOutcome::Failure,
            metadata: None,
        };

        let json = serde_json::to_string(&entry).unwrap();
        let deserialized: AuditLogEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.id, entry.id);
        assert_eq!(deserialized.action_type, entry.action_type);
        assert_eq!(deserialized.decision, AccessDecision::Denied);
        assert_eq!(deserialized.outcome, ActionOutcome::Failure);
    }

    #[test]
    fn module_dependency_serialization() {
        let dep = ModuleDependency {
            module_id: "core-utils".to_string(),
            version_requirement: "^1.0".to_string(),
        };

        let json = serde_json::to_string(&dep).unwrap();
        let deserialized: ModuleDependency = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.module_id, "core-utils");
        assert_eq!(deserialized.version_requirement, "^1.0");
    }

    #[test]
    fn summary_serialization() {
        let summary = Summary {
            content: "The user discussed file organization preferences.".to_string(),
            original_message_count: 15,
            token_count: 42,
            created_at: Utc::now(),
        };

        let json = serde_json::to_string(&summary).unwrap();
        let deserialized: Summary = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.content, summary.content);
        assert_eq!(deserialized.original_message_count, 15);
        assert_eq!(deserialized.token_count, 42);
    }
}
