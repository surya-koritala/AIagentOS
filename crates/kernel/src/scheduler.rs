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
    /// Temporary boost while a higher-priority agent waits on a resource held
    /// by this agent. The configured priority remains unchanged.
    inherited_priority: Option<Priority>,
    state: AgentScheduleState,
    /// Throttle delay in ms (increases for lower-priority agents under pressure).
    throttle_delay_ms: u64,
}

#[derive(Default)]
struct ResourceAccessState {
    holder: Option<AgentId>,
    waiters: BinaryHeap<PriorityEntry>,
}

/// Concrete priority-based scheduler implementation.
pub struct PriorityScheduler {
    /// Per-agent scheduling info.
    agents: DashMap<AgentId, AgentScheduleInfo>,
    /// One atomic holder/waiter state for exclusive shared-resource access.
    resource_access: Mutex<ResourceAccessState>,
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
            resource_access: Mutex::new(ResourceAccessState::default()),
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

    /// Effective priority after any temporary shared-resource inheritance.
    pub fn effective_priority(&self, agent_id: AgentId) -> Option<Priority> {
        self.agents
            .get(&agent_id)
            .map(|info| Self::effective_priority_for(&info))
    }

    fn effective_priority_for(info: &AgentScheduleInfo) -> Priority {
        info.inherited_priority
            .filter(|inherited| inherited.value() < info.priority.value())
            .unwrap_or(info.priority)
    }

    fn throttle_delay(priority: Priority) -> u64 {
        match priority.value() {
            1 => 0,
            2 => 50,
            3 => 150,
            4 => 300,
            5 => 500,
            _ => 0,
        }
    }

    fn refresh_agent_throttle(&self, agent_id: AgentId) {
        if let Some(mut info) = self.agents.get_mut(&agent_id) {
            info.throttle_delay_ms = if self.under_pressure.load(AtomicOrdering::SeqCst) {
                Self::throttle_delay(Self::effective_priority_for(&info))
            } else {
                0
            };
        }
    }

    fn set_inherited_priority(&self, agent_id: AgentId, inherited: Option<Priority>) {
        if let Some(mut info) = self.agents.get_mut(&agent_id) {
            info.inherited_priority = inherited;
        }
        self.refresh_agent_throttle(agent_id);
    }

    fn refresh_holder_inheritance(&self) {
        let (holder, inherited) = {
            let state = self.resource_access.lock().unwrap();
            (
                state.holder,
                state.waiters.peek().map(|waiter| waiter.priority),
            )
        };
        if let Some(holder) = holder {
            self.set_inherited_priority(holder, inherited);
        }
    }

    /// Request exclusive resource access in priority order. A higher-priority
    /// waiter temporarily boosts a lower-priority holder so resource-pressure
    /// throttling cannot extend the inversion. The configured priority is
    /// restored on release. Waits are bounded by the deadlock timeout.
    pub async fn request_resource_access(&self, agent_id: AgentId) -> Result<(), SchedulerError> {
        let priority = self
            .agents
            .get(&agent_id)
            .map(|a| a.priority)
            .unwrap_or_default();

        let seq = self.sequence.fetch_add(1, AtomicOrdering::SeqCst) as u64;
        {
            let mut state = self.resource_access.lock().unwrap();
            if state.holder == Some(agent_id) {
                return Ok(());
            }
            state.waiters.push(PriorityEntry {
                agent_id,
                priority,
                sequence: seq,
            });
        }
        let mut registration = ResourceWaitRegistration {
            scheduler: self,
            agent_id,
            acquired: false,
        };
        self.refresh_holder_inheritance();

        // Wait until this agent is at the front of the queue (highest priority)
        let result = tokio::time::timeout(
            tokio::time::Duration::from_secs(DEADLOCK_TIMEOUT_SECS),
            self.wait_for_turn(agent_id),
        )
        .await;

        match result {
            Ok(()) => {
                registration.acquired = true;
                Ok(())
            }
            Err(_) => Err(SchedulerError::DeadlockDetected),
        }
    }

    /// Release resource access, allowing next agent in queue to proceed.
    pub fn release_resource_access(&self, agent_id: AgentId) {
        let released = {
            let mut state = self.resource_access.lock().unwrap();
            if state.holder == Some(agent_id) {
                state.holder = None;
                true
            } else {
                false
            }
        };
        self.remove_from_queue(agent_id);
        self.set_inherited_priority(agent_id, None);
        if released {
            self.slot_available.notify_waiters();
        }
    }

    /// Check if the agent holds the resource or is next to acquire it.
    pub fn is_next_in_queue(&self, agent_id: AgentId) -> bool {
        let state = self.resource_access.lock().unwrap();
        state.holder == Some(agent_id)
            || (state.holder.is_none()
                && state
                    .waiters
                    .peek()
                    .is_some_and(|entry| entry.agent_id == agent_id))
    }

    fn apply_throttling(&self) {
        for mut entry in self.agents.iter_mut() {
            entry.throttle_delay_ms = Self::throttle_delay(Self::effective_priority_for(&entry));
        }
    }

    fn clear_throttling(&self) {
        for mut entry in self.agents.iter_mut() {
            entry.throttle_delay_ms = 0;
        }
    }

    async fn wait_for_turn(&self, agent_id: AgentId) {
        loop {
            if self.try_acquire_resource(agent_id) {
                return;
            }
            // `release_resource_access` signals via `Notify::notify_waiters`,
            // which only wakes waiters *already* registered at the instant it
            // fires — a waiter that reaches this point just after a release
            // would miss that edge and, if it happens to be the new queue head,
            // strand every other waiter (no further release can occur).
            // Racing the notification against a short poll interval closes that
            // lost-wakeup window: a missed edge costs at most one poll tick, so
            // progress is guaranteed without busy-spinning.
            tokio::select! {
                _ = self.slot_available.notified() => {}
                _ = tokio::time::sleep(std::time::Duration::from_millis(5)) => {}
            }
        }
    }

    fn try_acquire_resource(&self, agent_id: AgentId) -> bool {
        let acquired = {
            let mut state = self.resource_access.lock().unwrap();
            if state.holder == Some(agent_id) {
                true
            } else if state.holder.is_none()
                && state
                    .waiters
                    .peek()
                    .is_some_and(|entry| entry.agent_id == agent_id)
            {
                state.waiters.pop();
                state.holder = Some(agent_id);
                true
            } else {
                false
            }
        };
        if acquired {
            self.refresh_holder_inheritance();
        }
        acquired
    }

    fn remove_from_queue(&self, agent_id: AgentId) {
        let mut state = self.resource_access.lock().unwrap();
        let entries: Vec<_> = std::iter::from_fn(|| state.waiters.pop())
            .filter(|e| e.agent_id != agent_id)
            .collect();
        for e in entries {
            state.waiters.push(e);
        }
    }

    /// Admit an agent to the scheduler **without** consuming a running slot.
    ///
    /// This is admission *to the system*, not *to the CPU*: an agent that was
    /// just created is not yet executing, so creation must never block on the
    /// concurrent-execution gate. The agent starts `Queued` and transitions to
    /// `Running` only for the duration of an actual execution (via
    /// [`set_running`](Self::set_running) / [`set_queued`](Self::set_queued)).
    /// Non-blocking and infallible — this is what the kernel's create path uses
    /// instead of the blocking [`AgentScheduler::schedule`], so bulk-creating
    /// agents past `MAX_CONCURRENT_AGENTS` no longer stalls on the 10s timeout.
    pub fn admit(&self, agent: &AgentHandle) {
        self.admit_id(agent.id);
    }

    /// Admit an agent by id alone (no [`AgentHandle`] needed). Used by the
    /// kernel's boot-time rehydration to re-admit a restored agent — which has
    /// an id but no live command channel — so it is `Queued` and schedulable
    /// again. Same non-blocking, infallible system-admission semantics as
    /// [`admit`](Self::admit).
    pub fn admit_id(&self, agent_id: AgentId) {
        self.agents.insert(
            agent_id,
            AgentScheduleInfo {
                priority: Priority::default(),
                inherited_priority: None,
                state: AgentScheduleState::Queued,
                throttle_delay_ms: 0,
            },
        );
    }

    /// Mark an agent as actively executing, incrementing the running count so
    /// `running_agents` reflects real concurrency. Idempotent — a second call
    /// while already `Running` does not double-count. If the agent was never
    /// admitted, it is inserted as `Running` (defensive).
    pub fn set_running(&self, agent_id: AgentId) {
        if let Some(mut info) = self.agents.get_mut(&agent_id) {
            if info.state != AgentScheduleState::Running {
                info.state = AgentScheduleState::Running;
                self.running_count.fetch_add(1, AtomicOrdering::SeqCst);
            }
            return;
        }
        self.agents.insert(
            agent_id,
            AgentScheduleInfo {
                priority: Priority::default(),
                inherited_priority: None,
                state: AgentScheduleState::Running,
                throttle_delay_ms: 0,
            },
        );
        self.running_count.fetch_add(1, AtomicOrdering::SeqCst);
    }

    /// Return an agent to `Queued` after its execution finishes, freeing its
    /// running slot and waking a waiter. Idempotent — a no-op if the agent is
    /// not currently `Running`.
    pub fn set_queued(&self, agent_id: AgentId) {
        if let Some(mut info) = self.agents.get_mut(&agent_id) {
            if info.state == AgentScheduleState::Running {
                self.running_count.fetch_sub(1, AtomicOrdering::SeqCst);
                self.slot_available.notify_one();
            }
            info.state = AgentScheduleState::Queued;
        }
    }

    /// Mark an admitted agent paused/suspended without requiring it to be
    /// actively running. Idempotent and releases a running count if necessary.
    pub fn set_paused(&self, agent_id: AgentId) {
        if let Some(mut info) = self.agents.get_mut(&agent_id) {
            if info.state == AgentScheduleState::Running {
                self.running_count.fetch_sub(1, AtomicOrdering::SeqCst);
                self.slot_available.notify_one();
            }
            info.state = AgentScheduleState::Suspended;
        }
    }

    pub fn contains(&self, agent_id: AgentId) -> bool {
        self.agents.contains_key(&agent_id)
    }

    /// Live per-agent scheduling state for operator introspection. The string
    /// vocabulary is stable and intentionally does not expose queue internals.
    pub fn schedule_state(&self, agent_id: AgentId) -> Option<&'static str> {
        self.agents.get(&agent_id).map(|info| match info.state {
            AgentScheduleState::Running => "running",
            AgentScheduleState::Suspended => "paused",
            AgentScheduleState::Queued => "queued",
        })
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

struct ResourceWaitRegistration<'a> {
    scheduler: &'a PriorityScheduler,
    agent_id: AgentId,
    acquired: bool,
}

impl Drop for ResourceWaitRegistration<'_> {
    fn drop(&mut self) {
        if self.acquired {
            return;
        }
        self.scheduler.remove_from_queue(self.agent_id);
        self.scheduler.refresh_holder_inheritance();
        self.scheduler.slot_available.notify_waiters();
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
                    inherited_priority: None,
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
                inherited_priority: None,
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
        }
        self.refresh_holder_inheritance();
        self.refresh_agent_throttle(agent_id);
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
    async fn admit_does_not_consume_running_slots() {
        let sched = PriorityScheduler::new();
        // Admit far more than MAX_CONCURRENT_AGENTS — must not block or cap.
        let ids: Vec<AgentId> = (0..MAX_CONCURRENT_AGENTS * 3)
            .map(|_| uuid::Uuid::new_v4())
            .collect();
        for id in &ids {
            sched.admit(&make_handle(*id));
        }
        // None are "running" yet — admission is not execution.
        assert_eq!(sched.get_queue_status().running_agents, 0);
        assert_eq!(sched.get_queue_status().queued_agents, ids.len());

        // Executing transitions to Running and back, tracking real concurrency.
        sched.set_running(ids[0]);
        sched.set_running(ids[1]);
        sched.set_running(ids[1]); // idempotent — no double count
        assert_eq!(sched.get_queue_status().running_agents, 2);
        sched.set_queued(ids[0]);
        sched.set_queued(ids[0]); // idempotent — no underflow
        assert_eq!(sched.get_queue_status().running_agents, 1);
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

    #[test]
    fn lifecycle_resume_requeues_a_paused_agent() {
        let sched = PriorityScheduler::new();
        let id = uuid::Uuid::new_v4();
        sched.admit(&make_handle(id));
        sched.set_paused(id);
        assert_eq!(sched.schedule_state(id), Some("paused"));
        sched.set_queued(id);
        assert_eq!(sched.schedule_state(id), Some("queued"));
        assert_eq!(sched.get_queue_status().running_agents, 0);
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
        let sched = std::sync::Arc::new(PriorityScheduler::new());
        let holder = uuid::Uuid::new_v4();
        let low = uuid::Uuid::new_v4();
        let high = uuid::Uuid::new_v4();
        for id in [holder, low, high] {
            sched.schedule(&make_handle(id)).await.unwrap();
        }
        sched.set_priority(holder, Priority::new(3).unwrap());
        sched.set_priority(low, Priority::new(5).unwrap());
        sched.set_priority(high, Priority::new(1).unwrap());
        sched.request_resource_access(holder).await.unwrap();

        let order = std::sync::Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let mut tasks = Vec::new();
        for id in [low, high] {
            let sched = std::sync::Arc::clone(&sched);
            let order = std::sync::Arc::clone(&order);
            tasks.push(tokio::spawn(async move {
                sched.request_resource_access(id).await.unwrap();
                order.lock().await.push(id);
                sched.release_resource_access(id);
            }));
        }
        while sched.effective_priority(holder) != Some(Priority::new(1).unwrap()) {
            tokio::task::yield_now().await;
        }
        assert!(
            order.lock().await.is_empty(),
            "waiters must not overtake the active holder"
        );
        sched.release_resource_access(holder);
        for task in tasks {
            task.await.unwrap();
        }
        assert_eq!(*order.lock().await, vec![high, low]);
    }

    #[tokio::test]
    async fn resource_holder_inherits_waiter_priority_until_release() {
        let sched = std::sync::Arc::new(PriorityScheduler::new());
        let holder = uuid::Uuid::new_v4();
        let waiter = uuid::Uuid::new_v4();
        for id in [holder, waiter] {
            sched.schedule(&make_handle(id)).await.unwrap();
        }
        sched.set_priority(holder, Priority::new(5).unwrap());
        sched.set_priority(waiter, Priority::new(1).unwrap());
        sched.set_resource_pressure(true);
        assert_eq!(sched.get_throttle_delay_ms(holder), 500);
        sched.request_resource_access(holder).await.unwrap();

        let acquired = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let waiting = {
            let sched = std::sync::Arc::clone(&sched);
            let acquired = std::sync::Arc::clone(&acquired);
            tokio::spawn(async move {
                sched.request_resource_access(waiter).await.unwrap();
                acquired.store(true, std::sync::atomic::Ordering::SeqCst);
                sched.release_resource_access(waiter);
            })
        };
        while sched.effective_priority(holder) != Some(Priority::new(1).unwrap()) {
            tokio::task::yield_now().await;
        }
        assert_eq!(sched.get_throttle_delay_ms(holder), 0);
        assert!(!acquired.load(std::sync::atomic::Ordering::SeqCst));

        sched.release_resource_access(holder);
        waiting.await.unwrap();
        assert_eq!(
            sched.effective_priority(holder),
            Some(Priority::new(5).unwrap())
        );
        assert_eq!(sched.get_throttle_delay_ms(holder), 500);
    }

    #[tokio::test]
    async fn cancelled_resource_waiter_is_removed_and_inheritance_is_restored() {
        let sched = std::sync::Arc::new(PriorityScheduler::new());
        let holder = uuid::Uuid::new_v4();
        let cancelled = uuid::Uuid::new_v4();
        let survivor = uuid::Uuid::new_v4();
        for id in [holder, cancelled, survivor] {
            sched.schedule(&make_handle(id)).await.unwrap();
        }
        sched.set_priority(holder, Priority::new(5).unwrap());
        sched.set_priority(cancelled, Priority::new(1).unwrap());
        sched.set_priority(survivor, Priority::new(3).unwrap());
        sched.request_resource_access(holder).await.unwrap();

        let waiting = {
            let sched = std::sync::Arc::clone(&sched);
            tokio::spawn(async move {
                let _ = sched.request_resource_access(cancelled).await;
            })
        };
        while sched.effective_priority(holder) != Some(Priority::new(1).unwrap()) {
            tokio::task::yield_now().await;
        }
        waiting.abort();
        let _ = waiting.await;
        while sched.effective_priority(holder) != Some(Priority::new(5).unwrap()) {
            tokio::task::yield_now().await;
        }

        let survivor_wait = {
            let sched = std::sync::Arc::clone(&sched);
            tokio::spawn(async move {
                sched.request_resource_access(survivor).await.unwrap();
                sched.release_resource_access(survivor);
            })
        };
        while sched.effective_priority(holder) != Some(Priority::new(3).unwrap()) {
            tokio::task::yield_now().await;
        }
        sched.release_resource_access(holder);
        survivor_wait.await.unwrap();
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
