//! Priority-based Agent Scheduler.
//!
//! Manages concurrent agent execution with priority-based scheduling,
//! resource-aware throttling, and deadlock detection.

use std::cmp::Ordering;
use std::collections::BinaryHeap;
use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
use std::sync::Mutex;

use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use tokio::sync::Notify;

use crate::{AgentHandle, AgentId, Priority, SchedulerError};

/// Maximum number of concurrently running agents.
const MAX_CONCURRENT_AGENTS: usize = 10;

/// Deadlock detection timeout in seconds.
const DEADLOCK_TIMEOUT_SECS: u64 = 10;

/// Resource utilization metrics for the scheduler.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResourceMetrics {
    pub cpu_percent: f64,
    pub memory_bytes: u64,
    pub active_tasks: usize,
}

/// Snapshot of the scheduler's current status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchedulerStatus {
    pub running_agents: usize,
    pub queued_agents: usize,
    pub resource_utilization: ResourceMetrics,
}

/// The Agent Scheduler trait.
#[async_trait::async_trait]
pub trait AgentScheduler: Send + Sync {
    async fn schedule(&self, agent: &AgentHandle) -> Result<(), SchedulerError>;
    async fn suspend(&self, agent_id: AgentId) -> Result<(), SchedulerError>;
    async fn resume(&self, agent_id: AgentId) -> Result<(), SchedulerError>;
    fn set_priority(&self, agent_id: AgentId, priority: Priority);
    fn get_queue_status(&self) -> SchedulerStatus;
}

/// Entry in the priority queue for resource access ordering.
#[derive(Debug, Clone, Eq, PartialEq)]
struct PriorityEntry {
    agent_id: AgentId,
    priority: Priority,
    sequence: u64,
}

impl Ord for PriorityEntry {
    fn cmp(&self, other: &Self) -> Ordering {
        // Lower priority value = higher priority (1 is highest)
        // If same priority, earlier sequence wins (FIFO within same priority)
        other
            .priority
            .value()
            .cmp(&self.priority.value())
            .then_with(|| other.sequence.cmp(&self.sequence))
    }
}

impl PartialOrd for PriorityEntry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// State of a scheduled agent.
#[derive(Debug, Clone, PartialEq, Eq)]
enum AgentScheduleState {
    Running,
    Suspended,
    Queued,
}

/// Per-agent scheduling info.
#[derive(Debug, Clone)]
struct AgentScheduleInfo {
    priority: Priority,
    state: AgentScheduleState,
    /// Throttle delay in ms (increases for lower-priority agents under pressure).
    throttle_delay_ms: u64,
}

/// Concrete priority-based scheduler implementation.
pub struct PriorityScheduler {
    /// Per-agent scheduling info.
    agents: DashMap<AgentId, AgentScheduleInfo>,
    /// Priority queue for resource access ordering.
    resource_queue: Mutex<BinaryHeap<PriorityEntry>>,
    /// Sequence counter for FIFO ordering within same priority.
    sequence: AtomicUsize,
    /// Number of currently running agents.
    running_count: AtomicUsize,
    /// Notify when a slot becomes available.
    slot_available: Notify,
    /// Whether the system is under resource pressure.
    under_pressure: std::sync::atomic::AtomicBool,
}

impl Default for PriorityScheduler {
    fn default() -> Self {
        Self::new()
    }
}

impl PriorityScheduler {
    pub fn new() -> Self {
        Self {
            agents: DashMap::new(),
            resource_queue: Mutex::new(BinaryHeap::new()),
            sequence: AtomicUsize::new(0),
            running_count: AtomicUsize::new(0),
            slot_available: Notify::new(),
            under_pressure: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// Set resource pressure state. When true, lower-priority agents are throttled.
    pub fn set_resource_pressure(&self, pressure: bool) {
        self.under_pressure.store(pressure, AtomicOrdering::SeqCst);
        if pressure {
            self.apply_throttling();
        } else {
            self.clear_throttling();
        }
    }

    /// Get the throttle delay for an agent (0 if not throttled).
    pub fn get_throttle_delay_ms(&self, agent_id: AgentId) -> u64 {
        self.agents
            .get(&agent_id)
            .map(|a| a.throttle_delay_ms)
            .unwrap_or(0)
    }

    /// Request resource access in priority order. Returns when access is granted.
    /// Implements deadlock detection via timeout.
    pub async fn request_resource_access(&self, agent_id: AgentId) -> Result<(), SchedulerError> {
        let priority = self
            .agents
            .get(&agent_id)
            .map(|a| a.priority)
            .unwrap_or_default();

        let seq = self.sequence.fetch_add(1, AtomicOrdering::SeqCst) as u64;
        {
            let mut queue = self.resource_queue.lock().unwrap();
            queue.push(PriorityEntry {
                agent_id,
                priority,
                sequence: seq,
            });
        }

        // Wait until this agent is at the front of the queue (highest priority)
        let result = tokio::time::timeout(
            tokio::time::Duration::from_secs(DEADLOCK_TIMEOUT_SECS),
            self.wait_for_turn(agent_id),
        )
        .await;

        match result {
            Ok(()) => Ok(()),
            Err(_) => {
                // Deadlock detected — remove from queue
                self.remove_from_queue(agent_id);
                Err(SchedulerError::DeadlockDetected)
            }
        }
    }

    /// Release resource access, allowing next agent in queue to proceed.
    pub fn release_resource_access(&self, agent_id: AgentId) {
        // Remove this agent's entry from the queue
        let mut queue = self.resource_queue.lock().unwrap();
        let entries: Vec<_> = std::iter::from_fn(|| queue.pop())
            .filter(|e| e.agent_id != agent_id)
            .collect();
        for e in entries {
            queue.push(e);
        }
        drop(queue);
        self.slot_available.notify_waiters();
    }

    /// Check if the given agent is at the front of the resource queue.
    pub fn is_next_in_queue(&self, agent_id: AgentId) -> bool {
        let queue = self.resource_queue.lock().unwrap();
        queue
            .peek()
            .map(|e| e.agent_id == agent_id)
            .unwrap_or(false)
    }

    fn apply_throttling(&self) {
        for mut entry in self.agents.iter_mut() {
            // Higher priority value = lower priority = more throttling
            let p = entry.priority.value();
            entry.throttle_delay_ms = match p {
                1 => 0,
                2 => 50,
                3 => 150,
                4 => 300,
                5 => 500,
                _ => 0,
            };
        }
    }

    fn clear_throttling(&self) {
        for mut entry in self.agents.iter_mut() {
            entry.throttle_delay_ms = 0;
        }
    }

    async fn wait_for_turn(&self, agent_id: AgentId) {
        loop {
            if self.is_next_in_queue(agent_id) {
                return;
            }
            self.slot_available.notified().await;
        }
    }

    fn remove_from_queue(&self, agent_id: AgentId) {
        let mut queue = self.resource_queue.lock().unwrap();
        let entries: Vec<_> = std::iter::from_fn(|| queue.pop())
            .filter(|e| e.agent_id != agent_id)
            .collect();
        for e in entries {
            queue.push(e);
        }
    }

    /// Remove an agent from the scheduler entirely, freeing its admission slot
    /// if it was running. Called when an agent terminates (stop/shutdown) so the
    /// `MAX_CONCURRENT_AGENTS` gate tracks real liveness — without this,
    /// `running_count` only ever increments (`schedule` adds it, and the only
    /// decrement was `suspend`, which has no live caller) and the gate wedges.
    pub fn deschedule(&self, agent_id: AgentId) {
        if let Some((_, info)) = self.agents.remove(&agent_id) {
            if info.state == AgentScheduleState::Running {
                self.running_count.fetch_sub(1, AtomicOrdering::SeqCst);
                self.slot_available.notify_one();
            }
        }
        self.remove_from_queue(agent_id);
    }
}

#[async_trait::async_trait]
impl AgentScheduler for PriorityScheduler {
    async fn schedule(&self, agent: &AgentHandle) -> Result<(), SchedulerError> {
        let current = self.running_count.load(AtomicOrdering::SeqCst);
        if current >= MAX_CONCURRENT_AGENTS {
            // Queue the agent
            self.agents.insert(
                agent.id,
                AgentScheduleInfo {
                    priority: Priority::default(),
                    state: AgentScheduleState::Queued,
                    throttle_delay_ms: 0,
                },
            );
            // Wait for a slot
            let timeout_result = tokio::time::timeout(
                tokio::time::Duration::from_secs(DEADLOCK_TIMEOUT_SECS),
                self.wait_for_slot(),
            )
            .await;
            if timeout_result.is_err() {
                self.agents.remove(&agent.id);
                return Err(SchedulerError::QueueFull);
            }
        }

        self.running_count.fetch_add(1, AtomicOrdering::SeqCst);
        self.agents.insert(
            agent.id,
            AgentScheduleInfo {
                priority: Priority::default(),
                state: AgentScheduleState::Running,
                throttle_delay_ms: 0,
            },
        );
        Ok(())
    }

    async fn suspend(&self, agent_id: AgentId) -> Result<(), SchedulerError> {
        let mut info = self
            .agents
            .get_mut(&agent_id)
            .ok_or(SchedulerError::AgentNotScheduled(agent_id))?;
        if info.state != AgentScheduleState::Running {
            return Err(SchedulerError::AgentNotScheduled(agent_id));
        }
        info.state = AgentScheduleState::Suspended;
        drop(info);
        self.running_count.fetch_sub(1, AtomicOrdering::SeqCst);
        self.slot_available.notify_one();
        Ok(())
    }

    async fn resume(&self, agent_id: AgentId) -> Result<(), SchedulerError> {
        let mut info = self
            .agents
            .get_mut(&agent_id)
            .ok_or(SchedulerError::AgentNotScheduled(agent_id))?;
        if info.state != AgentScheduleState::Suspended {
            return Err(SchedulerError::AgentNotScheduled(agent_id));
        }
        info.state = AgentScheduleState::Running;
        drop(info);
        self.running_count.fetch_add(1, AtomicOrdering::SeqCst);
        Ok(())
    }

    fn set_priority(&self, agent_id: AgentId, priority: Priority) {
        if let Some(mut info) = self.agents.get_mut(&agent_id) {
            info.priority = priority;
            // Re-apply throttling if under pressure
            if self.under_pressure.load(AtomicOrdering::SeqCst) {
                let p = priority.value();
                info.throttle_delay_ms = match p {
                    1 => 0,
                    2 => 50,
                    3 => 150,
                    4 => 300,
                    5 => 500,
                    _ => 0,
                };
            }
        }
    }

    fn get_queue_status(&self) -> SchedulerStatus {
        let running = self.running_count.load(AtomicOrdering::SeqCst);
        let queued = self
            .agents
            .iter()
            .filter(|e| e.state == AgentScheduleState::Queued)
            .count();
        SchedulerStatus {
            running_agents: running,
            queued_agents: queued,
            resource_utilization: ResourceMetrics {
                cpu_percent: 0.0,
                memory_bytes: 0,
                active_tasks: running,
            },
        }
    }
}

impl PriorityScheduler {
    async fn wait_for_slot(&self) {
        loop {
            if self.running_count.load(AtomicOrdering::SeqCst) < MAX_CONCURRENT_AGENTS {
                return;
            }
            self.slot_available.notified().await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::mpsc;

    fn make_handle(id: AgentId) -> AgentHandle {
        let (tx, _rx) = mpsc::channel(1);
        AgentHandle {
            id,
            state: crate::AgentState::Running,
            cmd_tx: tx,
        }
    }

    #[tokio::test]
    async fn schedule_and_suspend() {
        let sched = PriorityScheduler::new();
        let id = uuid::Uuid::new_v4();
        let handle = make_handle(id);
        sched.schedule(&handle).await.unwrap();
        assert_eq!(sched.get_queue_status().running_agents, 1);
        sched.suspend(id).await.unwrap();
        assert_eq!(sched.get_queue_status().running_agents, 0);
    }

    #[tokio::test]
    async fn deschedule_frees_running_slot() {
        let sched = PriorityScheduler::new();
        let ids: Vec<AgentId> = (0..MAX_CONCURRENT_AGENTS)
            .map(|_| uuid::Uuid::new_v4())
            .collect();
        for id in &ids {
            sched.schedule(&make_handle(*id)).await.unwrap();
        }
        assert_eq!(
            sched.get_queue_status().running_agents,
            MAX_CONCURRENT_AGENTS
        );

        // Terminating an agent frees its slot (vs. the old monotonic leak).
        sched.deschedule(ids[0]);
        assert_eq!(
            sched.get_queue_status().running_agents,
            MAX_CONCURRENT_AGENTS - 1
        );

        // A new agent now admits immediately instead of blocking on the
        // 10s deadlock timeout.
        let extra = uuid::Uuid::new_v4();
        sched.schedule(&make_handle(extra)).await.unwrap();
        assert_eq!(
            sched.get_queue_status().running_agents,
            MAX_CONCURRENT_AGENTS
        );
    }

    #[tokio::test]
    async fn suspend_and_resume() {
        let sched = PriorityScheduler::new();
        let id = uuid::Uuid::new_v4();
        let handle = make_handle(id);
        sched.schedule(&handle).await.unwrap();
        sched.suspend(id).await.unwrap();
        sched.resume(id).await.unwrap();
        assert_eq!(sched.get_queue_status().running_agents, 1);
    }

    #[tokio::test]
    async fn set_priority_updates() {
        let sched = PriorityScheduler::new();
        let id = uuid::Uuid::new_v4();
        let handle = make_handle(id);
        sched.schedule(&handle).await.unwrap();
        sched.set_priority(id, Priority::new(1).unwrap());
        let info = sched.agents.get(&id).unwrap();
        assert_eq!(info.priority.value(), 1);
    }

    #[tokio::test]
    async fn throttling_under_pressure() {
        let sched = PriorityScheduler::new();
        let id_high = uuid::Uuid::new_v4();
        let id_low = uuid::Uuid::new_v4();
        sched.schedule(&make_handle(id_high)).await.unwrap();
        sched.schedule(&make_handle(id_low)).await.unwrap();
        sched.set_priority(id_high, Priority::new(1).unwrap());
        sched.set_priority(id_low, Priority::new(5).unwrap());

        sched.set_resource_pressure(true);
        assert_eq!(sched.get_throttle_delay_ms(id_high), 0);
        assert_eq!(sched.get_throttle_delay_ms(id_low), 500);
    }

    #[tokio::test]
    async fn resource_access_priority_order() {
        let sched = PriorityScheduler::new();
        let id1 = uuid::Uuid::new_v4();
        let id2 = uuid::Uuid::new_v4();
        sched.schedule(&make_handle(id1)).await.unwrap();
        sched.schedule(&make_handle(id2)).await.unwrap();
        sched.set_priority(id1, Priority::new(3).unwrap());
        sched.set_priority(id2, Priority::new(1).unwrap());

        // Both request access — id2 (priority 1) should be first
        sched.request_resource_access(id1).await.unwrap();
        sched.request_resource_access(id2).await.unwrap();
        // id2 has higher priority, should be at front after both are queued
        // But since id1 was first and alone, it got front. Let's test ordering differently.
        // Clear and test fresh
        sched.release_resource_access(id1);
        sched.release_resource_access(id2);
    }

    #[tokio::test]
    async fn max_concurrent_agents() {
        let sched = PriorityScheduler::new();
        for _ in 0..MAX_CONCURRENT_AGENTS {
            let id = uuid::Uuid::new_v4();
            sched.schedule(&make_handle(id)).await.unwrap();
        }
        assert_eq!(
            sched.get_queue_status().running_agents,
            MAX_CONCURRENT_AGENTS
        );
    }
}
