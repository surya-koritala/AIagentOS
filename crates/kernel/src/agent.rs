//! Agent Kernel trait and implementation.
//!
//! Defines the core orchestrator interface for managing agent lifecycle,
//! state queries, and event subscriptions. Provides a concrete `AgentManager`
//! implementation with state machine validation and lock-free concurrent agent
//! storage. The wired kernel runtime owns watchdog termination so every timeout
//! flows through the coordinated cleanup path.

use chrono::{DateTime, Utc};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;

use crate::models::Agent;
use crate::observability::Metrics;
use crate::{
    AgentConfig, AgentError, AgentHandle, AgentId, AgentState, KernelError, KernelEvent, Priority,
    SessionId,
};

/// Summary information about a running agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentInfo {
    /// Unique agent identifier.
    pub id: AgentId,
    /// Human-readable agent name.
    pub name: String,
    /// Current lifecycle state.
    pub state: AgentState,
    /// Scheduling priority.
    pub priority: Priority,
    /// Session this agent belongs to.
    pub session_id: Option<SessionId>,
    /// When the agent was created.
    pub created_at: DateTime<Utc>,
}

// ─── State Transition Validation ─────────────────────────────────────────────

/// Validates whether a state transition is allowed per the agent state machine.
///
/// Valid transitions:
/// - Initializing → Running (context ready)
/// - Initializing → Error (init failed)
/// - Running → Paused (pause_agent)
/// - Running → Stopping (stop_agent)
/// - Running → Error (unresponsive 30s)
/// - Paused → Running (resume_agent)
/// - Paused → Stopping (stop_agent)
/// - Stopping → Stopped (cleanup complete)
/// - Error → Stopped (resources released)
pub fn is_valid_transition(from: &AgentState, to: &AgentState) -> bool {
    matches!(
        (from, to),
        (AgentState::Initializing, AgentState::Running)
            | (AgentState::Initializing, AgentState::Error(_))
            | (AgentState::Running, AgentState::Paused)
            | (AgentState::Running, AgentState::Stopping)
            | (AgentState::Running, AgentState::Error(_))
            | (AgentState::Paused, AgentState::Running)
            | (AgentState::Paused, AgentState::Stopping)
            | (AgentState::Stopping, AgentState::Stopped)
            | (AgentState::Error(_), AgentState::Stopped)
    )
}

// ─── AgentKernel Trait ───────────────────────────────────────────────────────

/// The Agent Kernel trait — central coordinator for agent lifecycle management.
///
/// Manages creation, pausing, resuming, and stopping of agents, as well as
/// state queries and event broadcasting.
#[async_trait::async_trait]
pub trait AgentKernel: Send + Sync {
    /// Create a new agent with the given configuration.
    ///
    /// Initializes context, assigns a sandbox (if configured), and transitions
    /// the agent to the Running state.
    async fn create_agent(&self, config: AgentConfig) -> Result<AgentHandle, KernelError>;

    /// Pause a running agent, persisting its context.
    async fn pause_agent(&self, agent_id: AgentId) -> Result<(), KernelError>;

    /// Resume a paused agent, restoring its context.
    async fn resume_agent(&self, agent_id: AgentId) -> Result<(), KernelError>;

    /// Stop an agent, releasing all resources and archiving the session.
    async fn stop_agent(&self, agent_id: AgentId) -> Result<(), KernelError>;

    /// Get the current lifecycle state of an agent.
    fn get_agent_state(&self, agent_id: AgentId) -> Option<AgentState>;

    /// List agents, optionally filtered by session.
    fn list_agents(&self, session_id: Option<SessionId>) -> Vec<AgentInfo>;

    /// Subscribe to kernel events broadcast channel.
    fn subscribe_events(&self) -> broadcast::Receiver<KernelEvent>;
}

// ─── AgentManager Implementation ────────────────────────────────────────────

/// Duration allowed for agent initialization before timeout.
const INIT_TIMEOUT_SECS: u64 = 5;

/// Concrete implementation of the AgentKernel trait.
///
/// Uses `DashMap` for lock-free concurrent agent storage and
/// `tokio::sync::broadcast` for event distribution.
pub struct AgentManager {
    /// Lock-free concurrent map of agent ID to agent data.
    agents: DashMap<AgentId, Agent>,
    /// Broadcast channel sender for kernel events.
    event_tx: broadcast::Sender<KernelEvent>,
}

impl AgentManager {
    /// Create a new AgentManager with the given event channel capacity.
    pub fn new(event_channel_capacity: usize) -> Self {
        let (event_tx, _) = broadcast::channel(event_channel_capacity);
        Self {
            agents: DashMap::new(),
            event_tx,
        }
    }

    /// Transition an agent's state, validating the transition is allowed.
    ///
    /// Returns the old state on success, or an error if the transition is invalid.
    pub fn transition_state(
        &self,
        agent_id: AgentId,
        new_state: AgentState,
    ) -> Result<AgentState, KernelError> {
        let mut agent = self
            .agents
            .get_mut(&agent_id)
            .ok_or(AgentError::NotFound(agent_id))?;

        let old_state = agent.state.clone();

        if !is_valid_transition(&old_state, &new_state) {
            return Err(AgentError::InvalidTransition {
                from: old_state,
                to: new_state,
            }
            .into());
        }

        agent.state = new_state.clone();
        agent.last_activity_at = Utc::now();

        // Broadcast state change event (ignore send errors if no receivers)
        let _ = self.event_tx.send(KernelEvent::AgentStateChanged {
            agent_id,
            old: old_state.clone(),
            new: new_state,
        });

        Ok(old_state)
    }

    /// Record activity for an agent (resets the watchdog timer effectively).
    pub fn record_activity(&self, agent_id: AgentId) {
        if let Some(mut agent) = self.agents.get_mut(&agent_id) {
            agent.last_activity_at = Utc::now();
        }
    }

    /// Whether a running agent has recorded no progress since `cutoff`.
    /// Kernel watchdog code combines this with active-turn membership so an
    /// intentionally idle runnable agent is never treated as hung.
    pub(crate) fn is_unresponsive_since(&self, agent_id: AgentId, cutoff: DateTime<Utc>) -> bool {
        self.agents.get(&agent_id).is_some_and(|agent| {
            agent.state == AgentState::Running && agent.last_activity_at <= cutoff
        })
    }

    #[cfg(test)]
    pub(crate) fn set_last_activity_for_test(
        &self,
        agent_id: AgentId,
        last_activity_at: DateTime<Utc>,
    ) {
        if let Some(mut agent) = self.agents.get_mut(&agent_id) {
            agent.last_activity_at = last_activity_at;
        }
    }

    /// Permanently remove a partially-created agent from the in-memory
    /// registry. Normal stop/kill deliberately retain terminal history; this
    /// narrower operation is reserved for transactional creation rollback.
    pub(crate) fn purge_agent(&self, agent_id: AgentId) -> bool {
        self.agents.remove(&agent_id).is_some()
    }

    /// Get the LLM provider ID configured for an agent.
    pub fn get_agent_provider(&self, agent_id: AgentId) -> Option<String> {
        self.agents
            .get(&agent_id)
            .map(|a| a.config.llm_provider.clone())
    }

    /// Get an agent's task description (the prompt it was created for).
    pub fn get_agent_task(&self, agent_id: AgentId) -> Option<String> {
        self.agents.get(&agent_id).map(|a| a.config.task.clone())
    }

    pub fn get_agent_config(&self, agent_id: AgentId) -> Option<AgentConfig> {
        self.agents.get(&agent_id).map(|agent| agent.config.clone())
    }

    /// Enter the non-runnable cleanup state from any non-terminal state. Forced
    /// kill uses this after durably staging `Stopping`, before revoking live
    /// subsystem state.
    pub(crate) fn force_stopping(&self, agent_id: AgentId) -> Result<(), KernelError> {
        let mut agent = self
            .agents
            .get_mut(&agent_id)
            .ok_or(AgentError::NotFound(agent_id))?;
        let old = agent.state.clone();
        if matches!(old, AgentState::Stopping | AgentState::Stopped) {
            return Ok(());
        }
        agent.state = AgentState::Stopping;
        agent.last_activity_at = Utc::now();
        let _ = self.event_tx.send(KernelEvent::AgentStateChanged {
            agent_id,
            old,
            new: AgentState::Stopping,
        });
        Ok(())
    }

    /// Forced terminal transition used only by the kernel lifecycle coordinator
    /// after every mandatory subsystem cleanup step has completed.
    pub fn force_stopped(&self, agent_id: AgentId) -> Result<(), KernelError> {
        let mut agent = self
            .agents
            .get_mut(&agent_id)
            .ok_or(AgentError::NotFound(agent_id))?;
        let old = agent.state.clone();
        if old == AgentState::Stopped {
            return Ok(());
        }
        agent.state = AgentState::Stopped;
        agent.last_activity_at = Utc::now();
        let _ = self.event_tx.send(KernelEvent::AgentStateChanged {
            agent_id,
            old,
            new: AgentState::Stopped,
        });
        Ok(())
    }

    /// Rehydrate a previously-persisted agent directly into the in-memory map,
    /// bypassing the create/init state machine (the agent already existed across
    /// the restart). Used by the kernel's boot-time registry rehydration to bring
    /// agents back with their original id, session, config, and timestamps. A
    /// The caller must resolve interrupted transitional states before invoking
    /// this method. The supplied state is restored exactly so this low-level
    /// primitive can never turn an incomplete initialization or shutdown into
    /// runnable work.
    pub fn restore_agent(
        &self,
        id: AgentId,
        session_id: SessionId,
        config: AgentConfig,
        state: AgentState,
        created_at: DateTime<Utc>,
        last_activity_at: DateTime<Utc>,
    ) {
        let sandbox_id = config.sandbox_config.as_ref().map(|_| uuid::Uuid::new_v4());
        let agent = Agent {
            id,
            session_id,
            name: config.name.clone(),
            state,
            config,
            sandbox_id,
            created_at,
            last_activity_at,
            metrics: Metrics::default(),
        };
        self.agents.insert(id, agent);
    }
}

#[async_trait::async_trait]
impl AgentKernel for AgentManager {
    async fn create_agent(&self, config: AgentConfig) -> Result<AgentHandle, KernelError> {
        let agent_id = uuid::Uuid::new_v4();
        let session_id = uuid::Uuid::new_v4();
        let now = Utc::now();

        // Create agent in Initializing state
        let agent = Agent {
            id: agent_id,
            session_id,
            name: config.name.clone(),
            state: AgentState::Initializing,
            config: config.clone(),
            sandbox_id: None,
            created_at: now,
            last_activity_at: now,
            metrics: Metrics::default(),
        };

        self.agents.insert(agent_id, agent);

        // Broadcast creation event
        let _ = self.event_tx.send(KernelEvent::AgentCreated(agent_id));

        // Perform initialization with a 5-second timeout.
        // Context initialization and sandbox assignment are stubbed for now
        // (will be implemented in later tasks).
        let init_result = tokio::time::timeout(
            tokio::time::Duration::from_secs(INIT_TIMEOUT_SECS),
            self.initialize_agent(agent_id, &config),
        )
        .await;

        match init_result {
            Ok(Ok(())) => {
                // Transition to Running
                self.transition_state(agent_id, AgentState::Running)?;
            }
            Ok(Err(e)) => {
                // Initialization failed — transition to Error
                let _ = self
                    .transition_state(agent_id, AgentState::Error(format!("Init failed: {}", e)));
                return Err(e);
            }
            Err(_elapsed) => {
                // Timeout — transition to Error
                let _ = self.transition_state(
                    agent_id,
                    AgentState::Error("Initialization timed out".to_string()),
                );
                return Err(AgentError::CreationTimeout.into());
            }
        }

        // Create command channel for the agent handle
        let (cmd_tx, _cmd_rx) = tokio::sync::mpsc::channel(32);

        let handle = AgentHandle {
            id: agent_id,
            state: AgentState::Running,
            cmd_tx,
        };

        Ok(handle)
    }

    async fn pause_agent(&self, agent_id: AgentId) -> Result<(), KernelError> {
        // Validate agent exists and is in Running state
        {
            let agent = self
                .agents
                .get(&agent_id)
                .ok_or(AgentError::NotFound(agent_id))?;
            if agent.state != AgentState::Running {
                return Err(AgentError::InvalidTransition {
                    from: agent.state.clone(),
                    to: AgentState::Paused,
                }
                .into());
            }
        }

        // Persist context (stubbed — will be implemented in context manager task)
        // In a full implementation, this would call context_manager.persist_context(agent_id)

        // Transition to Paused
        self.transition_state(agent_id, AgentState::Paused)?;

        Ok(())
    }

    async fn resume_agent(&self, agent_id: AgentId) -> Result<(), KernelError> {
        // Validate agent exists and is in Paused state
        {
            let agent = self
                .agents
                .get(&agent_id)
                .ok_or(AgentError::NotFound(agent_id))?;
            if agent.state != AgentState::Paused {
                return Err(AgentError::InvalidTransition {
                    from: agent.state.clone(),
                    to: AgentState::Running,
                }
                .into());
            }
        }

        // Restore context (stubbed — will be implemented in context manager task)
        // In a full implementation, this would call context_manager.restore_context(agent_id)

        // Transition to Running
        self.transition_state(agent_id, AgentState::Running)?;

        Ok(())
    }

    async fn stop_agent(&self, agent_id: AgentId) -> Result<(), KernelError> {
        // Validate agent exists
        let current_state = {
            let agent = self
                .agents
                .get(&agent_id)
                .ok_or(AgentError::NotFound(agent_id))?;
            agent.state.clone()
        };

        // Can stop from Running, Paused, or Error states
        match &current_state {
            AgentState::Running | AgentState::Paused => {
                // Transition to Stopping
                self.transition_state(agent_id, AgentState::Stopping)?;
            }
            AgentState::Error(_) => {
                // Error → Stopped directly (resources released)
                self.transition_state(agent_id, AgentState::Stopped)?;
                return Ok(());
            }
            _ => {
                return Err(AgentError::InvalidTransition {
                    from: current_state,
                    to: AgentState::Stopping,
                }
                .into());
            }
        }

        // Release resources (stubbed — will be implemented in later tasks)
        // In a full implementation:
        // - Release sandbox
        // - Archive session history
        // - Clean up any held resources

        // Transition to Stopped (cleanup complete)
        self.transition_state(agent_id, AgentState::Stopped)?;

        Ok(())
    }

    fn get_agent_state(&self, agent_id: AgentId) -> Option<AgentState> {
        self.agents.get(&agent_id).map(|a| a.state.clone())
    }

    fn list_agents(&self, session_id: Option<SessionId>) -> Vec<AgentInfo> {
        self.agents
            .iter()
            .filter(|entry| {
                if let Some(sid) = &session_id {
                    entry.value().session_id == *sid
                } else {
                    true
                }
            })
            .map(|entry| {
                let agent = entry.value();
                AgentInfo {
                    id: agent.id,
                    name: agent.name.clone(),
                    state: agent.state.clone(),
                    priority: agent.config.priority,
                    session_id: Some(agent.session_id),
                    created_at: agent.created_at,
                }
            })
            .collect()
    }

    fn subscribe_events(&self) -> broadcast::Receiver<KernelEvent> {
        self.event_tx.subscribe()
    }
}

impl AgentManager {
    /// Internal initialization routine for a new agent.
    /// Initializes context and assigns sandbox. Currently stubbed.
    async fn initialize_agent(
        &self,
        agent_id: AgentId,
        config: &AgentConfig,
    ) -> Result<(), KernelError> {
        // Stub: In later tasks, this will:
        // 1. Create context via ContextManager
        // 2. Assign sandbox via SandboxManager (if config.sandbox_config is Some)
        // 3. Register with scheduler

        // Assign sandbox_id if sandbox config is provided
        if config.sandbox_config.is_some() {
            if let Some(mut agent) = self.agents.get_mut(&agent_id) {
                agent.sandbox_id = Some(uuid::Uuid::new_v4());
            }
        }

        Ok(())
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ─── State Transition Tests ──────────────────────────────────────────────

    #[test]
    fn valid_transitions_from_initializing() {
        assert!(is_valid_transition(
            &AgentState::Initializing,
            &AgentState::Running
        ));
        assert!(is_valid_transition(
            &AgentState::Initializing,
            &AgentState::Error("failed".to_string())
        ));
    }

    #[test]
    fn valid_transitions_from_running() {
        assert!(is_valid_transition(
            &AgentState::Running,
            &AgentState::Paused
        ));
        assert!(is_valid_transition(
            &AgentState::Running,
            &AgentState::Stopping
        ));
        assert!(is_valid_transition(
            &AgentState::Running,
            &AgentState::Error("unresponsive".to_string())
        ));
    }

    #[test]
    fn valid_transitions_from_paused() {
        assert!(is_valid_transition(
            &AgentState::Paused,
            &AgentState::Running
        ));
        assert!(is_valid_transition(
            &AgentState::Paused,
            &AgentState::Stopping
        ));
    }

    #[test]
    fn valid_transitions_from_stopping() {
        assert!(is_valid_transition(
            &AgentState::Stopping,
            &AgentState::Stopped
        ));
    }

    #[test]
    fn valid_transitions_from_error() {
        assert!(is_valid_transition(
            &AgentState::Error("some error".to_string()),
            &AgentState::Stopped
        ));
    }

    #[test]
    fn invalid_transitions() {
        // Cannot go from Initializing to Paused
        assert!(!is_valid_transition(
            &AgentState::Initializing,
            &AgentState::Paused
        ));
        // Cannot go from Stopped to anything
        assert!(!is_valid_transition(
            &AgentState::Stopped,
            &AgentState::Running
        ));
        // Cannot go from Paused to Error directly
        assert!(!is_valid_transition(
            &AgentState::Paused,
            &AgentState::Error("err".to_string())
        ));
        // Cannot go from Running to Initializing
        assert!(!is_valid_transition(
            &AgentState::Running,
            &AgentState::Initializing
        ));
        // Cannot go from Stopping to Running
        assert!(!is_valid_transition(
            &AgentState::Stopping,
            &AgentState::Running
        ));
    }

    // ─── AgentManager Lifecycle Tests ────────────────────────────────────────

    fn test_config() -> AgentConfig {
        AgentConfig {
            name: "test-agent".to_string(),
            task: "test task".to_string(),
            llm_provider: "openai".to_string(),
            permission_profile: "standard".to_string(),
            priority: Priority::new(3).unwrap(),
            sandbox_config: None,
        }
    }

    #[tokio::test]
    async fn create_agent_transitions_to_running() {
        let manager = AgentManager::new(16);
        let handle = manager.create_agent(test_config()).await.unwrap();

        assert_eq!(handle.state, AgentState::Running);
        assert_eq!(
            manager.get_agent_state(handle.id),
            Some(AgentState::Running)
        );
    }

    #[tokio::test]
    async fn create_agent_broadcasts_events() {
        let manager = AgentManager::new(16);
        let mut rx = manager.subscribe_events();

        let handle = manager.create_agent(test_config()).await.unwrap();

        // Should receive AgentCreated event
        let event = rx.try_recv().unwrap();
        assert!(matches!(event, KernelEvent::AgentCreated(id) if id == handle.id));

        // Should receive state change from Initializing to Running
        let event = rx.try_recv().unwrap();
        assert!(matches!(
            event,
            KernelEvent::AgentStateChanged {
                agent_id,
                old: AgentState::Initializing,
                new: AgentState::Running,
            } if agent_id == handle.id
        ));
    }

    #[tokio::test]
    async fn pause_agent_from_running() {
        let manager = AgentManager::new(16);
        let handle = manager.create_agent(test_config()).await.unwrap();

        manager.pause_agent(handle.id).await.unwrap();
        assert_eq!(manager.get_agent_state(handle.id), Some(AgentState::Paused));
    }

    #[tokio::test]
    async fn pause_agent_not_running_fails() {
        let manager = AgentManager::new(16);
        let handle = manager.create_agent(test_config()).await.unwrap();

        // Pause first
        manager.pause_agent(handle.id).await.unwrap();

        // Try to pause again — should fail
        let result = manager.pause_agent(handle.id).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn resume_agent_from_paused() {
        let manager = AgentManager::new(16);
        let handle = manager.create_agent(test_config()).await.unwrap();

        manager.pause_agent(handle.id).await.unwrap();
        manager.resume_agent(handle.id).await.unwrap();

        assert_eq!(
            manager.get_agent_state(handle.id),
            Some(AgentState::Running)
        );
    }

    #[tokio::test]
    async fn resume_agent_not_paused_fails() {
        let manager = AgentManager::new(16);
        let handle = manager.create_agent(test_config()).await.unwrap();

        // Agent is Running, not Paused
        let result = manager.resume_agent(handle.id).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn stop_agent_from_running() {
        let manager = AgentManager::new(16);
        let handle = manager.create_agent(test_config()).await.unwrap();

        manager.stop_agent(handle.id).await.unwrap();
        assert_eq!(
            manager.get_agent_state(handle.id),
            Some(AgentState::Stopped)
        );
    }

    #[tokio::test]
    async fn stop_agent_from_paused() {
        let manager = AgentManager::new(16);
        let handle = manager.create_agent(test_config()).await.unwrap();

        manager.pause_agent(handle.id).await.unwrap();
        manager.stop_agent(handle.id).await.unwrap();

        assert_eq!(
            manager.get_agent_state(handle.id),
            Some(AgentState::Stopped)
        );
    }

    #[tokio::test]
    async fn stop_agent_from_error() {
        let manager = AgentManager::new(16);
        let handle = manager.create_agent(test_config()).await.unwrap();

        // Force into Error state via internal transition
        manager
            .transition_state(handle.id, AgentState::Error("test error".to_string()))
            .unwrap();

        manager.stop_agent(handle.id).await.unwrap();
        assert_eq!(
            manager.get_agent_state(handle.id),
            Some(AgentState::Stopped)
        );
    }

    #[tokio::test]
    async fn stop_agent_already_stopped_fails() {
        let manager = AgentManager::new(16);
        let handle = manager.create_agent(test_config()).await.unwrap();

        manager.stop_agent(handle.id).await.unwrap();

        // Try to stop again
        let result = manager.stop_agent(handle.id).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn get_agent_state_nonexistent_returns_none() {
        let manager = AgentManager::new(16);
        let fake_id = uuid::Uuid::new_v4();
        assert_eq!(manager.get_agent_state(fake_id), None);
    }

    #[tokio::test]
    async fn list_agents_returns_all() {
        let manager = AgentManager::new(16);
        manager.create_agent(test_config()).await.unwrap();
        manager.create_agent(test_config()).await.unwrap();

        let agents = manager.list_agents(None);
        assert_eq!(agents.len(), 2);
    }

    #[tokio::test]
    async fn list_agents_filters_by_session() {
        let manager = AgentManager::new(16);
        let handle1 = manager.create_agent(test_config()).await.unwrap();

        // Get the session_id of the first agent
        let session_id = manager.agents.get(&handle1.id).unwrap().session_id;

        // Create another agent (will have a different session_id)
        manager.create_agent(test_config()).await.unwrap();

        let agents = manager.list_agents(Some(session_id));
        assert_eq!(agents.len(), 1);
        assert_eq!(agents[0].id, handle1.id);
    }

    #[tokio::test]
    async fn agent_not_found_error() {
        let manager = AgentManager::new(16);
        let fake_id = uuid::Uuid::new_v4();

        let result = manager.pause_agent(fake_id).await;
        assert!(matches!(
            result,
            Err(KernelError::Agent(AgentError::NotFound(_)))
        ));
    }

    #[tokio::test]
    async fn create_agent_with_sandbox_config() {
        let mut config = test_config();
        config.sandbox_config = Some(crate::SandboxConfig {
            workspace_dir: std::path::PathBuf::from("/tmp/sandbox"),
            allowed_network_hosts: None,
            max_disk_usage_bytes: None,
            max_memory_bytes: None,
            isolation_level: crate::IsolationLevel::Filesystem,
            container_image: None,
        });

        let manager = AgentManager::new(16);
        let handle = manager.create_agent(config).await.unwrap();

        let agent = manager.agents.get(&handle.id).unwrap();
        assert!(agent.sandbox_id.is_some());
    }

    #[tokio::test]
    async fn watchdog_detection_requires_running_state_older_than_cutoff() {
        let manager = AgentManager::new(16);
        let handle = manager.create_agent(test_config()).await.unwrap();
        let now = Utc::now();
        manager.set_last_activity_for_test(handle.id, now - chrono::Duration::seconds(31));
        assert!(manager.is_unresponsive_since(handle.id, now - chrono::Duration::seconds(30)));
        manager.pause_agent(handle.id).await.unwrap();
        assert!(!manager.is_unresponsive_since(handle.id, now - chrono::Duration::seconds(30)));
    }

    #[tokio::test]
    async fn record_activity_updates_timestamp() {
        let manager = AgentManager::new(16);
        let handle = manager.create_agent(test_config()).await.unwrap();

        let before = manager.agents.get(&handle.id).unwrap().last_activity_at;
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
        manager.record_activity(handle.id);
        let after = manager.agents.get(&handle.id).unwrap().last_activity_at;

        assert!(after > before);
    }
}
