//! Agent Struct — the core data structure of AI Agent OS.
//!
//! Equivalent to Linux's task_struct. Every agent in the system is represented
//! by one AgentStruct. Contains all state needed to manage the agent.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use chrono::{DateTime, Utc};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

/// Global agent ID counter (monotonically increasing, like PIDs).
static NEXT_AGENT_ID: AtomicU64 = AtomicU64::new(1);

/// Agent ID (like PID in Linux).
pub type AgentId = u64;

/// Special agent IDs.
pub const INIT_AGENT_ID: AgentId = 1;
pub const KERNEL_AGENT_ID: AgentId = 0;

/// Agent state machine (like process states in Linux).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgentState {
    /// Just created, not yet scheduled.
    Created,
    /// Ready to run, waiting for scheduler.
    Ready,
    /// Currently executing (has a time slice).
    Running,
    /// Blocked waiting for something (tool call, IPC, signal).
    Blocked(BlockReason),
    /// Stopped by signal (SIGSTOP).
    Stopped,
    /// Exited but parent hasn't waited (zombie).
    Zombie,
    /// Fully dead and reaped.
    Dead,
}

/// Why an agent is blocked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BlockReason {
    ToolCall,
    IpcWait,
    SignalWait,
    Sleep,
    ChildWait,
}

/// Agent credentials (like uid/gid in Linux).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentCredentials {
    pub uid: u64,
    pub gid: u64,
    pub groups: Vec<u64>,
    pub capabilities: CapabilitySet,
}

/// Capability set (fine-grained permissions).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CapabilitySet {
    bits: u64,
}

impl CapabilitySet {
    pub const CAP_TOOL_MOUNT: u64 = 1 << 0;
    pub const CAP_AGENT_CREATE: u64 = 1 << 1;
    pub const CAP_AGENT_KILL: u64 = 1 << 2;
    pub const CAP_NET_ACCESS: u64 = 1 << 3;
    pub const CAP_FILE_WRITE: u64 = 1 << 4;
    pub const CAP_FILE_DELETE: u64 = 1 << 5;
    pub const CAP_EXEC: u64 = 1 << 6;
    pub const CAP_ADMIN: u64 = 1 << 7;
    pub const CAP_SYS_RESOURCE: u64 = 1 << 8;

    pub fn new(bits: u64) -> Self {
        Self { bits }
    }
    pub fn all() -> Self {
        Self { bits: u64::MAX }
    }
    pub fn none() -> Self {
        Self { bits: 0 }
    }
    pub fn has(&self, cap: u64) -> bool {
        self.bits & cap != 0
    }
    pub fn grant(&mut self, cap: u64) {
        self.bits |= cap;
    }
    pub fn revoke(&mut self, cap: u64) {
        self.bits &= !cap;
    }
    pub fn drop_cap(&mut self, cap: u64) {
        self.revoke(cap);
    }
}

/// Scheduling information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchedInfo {
    /// Nice value (-20 to +19, lower = higher priority).
    pub nice: i8,
    /// Virtual runtime (for CFS — lower means deserves more CPU).
    pub vruntime: u64,
    /// Scheduling class.
    pub class: SchedClass,
    /// Tokens used in current time slice.
    pub tokens_this_slice: u64,
    /// Total tokens ever used.
    pub tokens_total: u64,
    /// Total tool calls made.
    pub tool_calls_total: u64,
}

/// Scheduling class (like Linux sched classes).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SchedClass {
    /// Always runs first (for critical system agents).
    RealTime,
    /// Normal fair scheduling (CFS).
    Normal,
    /// Only runs when system is idle.
    Background,
    /// Must complete by deadline.
    Deadline { deadline_ms: u64 },
}

/// Signal information.
pub struct SignalInfo {
    /// Pending signals (bitmask).
    pub pending: u64,
    /// Blocked signals (bitmask).
    pub mask: u64,
    /// Signal handlers.
    pub handlers: HashMap<u8, SignalHandler>,
}

/// What to do when a signal arrives.

#[derive(Clone)]
pub enum SignalHandler {
    Default,
    Ignore,
    Custom(Arc<dyn Fn(u8) + Send + Sync>),
}
impl std::fmt::Debug for SignalHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::Default => write!(f, "Default"),
            Self::Ignore => write!(f, "Ignore"),
            Self::Custom(_) => write!(f, "Custom(...)"),
        }
    }
}

/// Signal types.
pub mod signals {
    pub const SIGSTOP: u8 = 1;
    pub const SIGCONT: u8 = 2;
    pub const SIGKILL: u8 = 3;
    pub const SIGTERM: u8 = 4;
    pub const SIGUSR1: u8 = 5;
    pub const SIGUSR2: u8 = 6;
    pub const SIGCHLD: u8 = 7;
    pub const SIGALRM: u8 = 8;
}

/// Resource pointers (what this agent has access to).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourcePointers {
    /// Context (memory) namespace ID.
    pub context_ns: u64,
    /// Tool namespace ID.
    pub tool_ns: u64,
    /// Agent namespace ID (which agents are visible).
    pub agent_ns: u64,
    /// Network namespace ID.
    pub net_ns: u64,
    /// Cgroup ID (resource limits).
    pub cgroup: u64,
}

/// Exit information (set when agent exits).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExitInfo {
    pub code: i32,
    pub signal: Option<u8>,
    pub exited_at: DateTime<Utc>,
}

/// The core agent descriptor. Every agent has exactly one.
pub struct AgentStruct {
    // ─── Identity ────────────────────────────────────────
    /// Unique agent ID (like PID).
    pub id: AgentId,
    /// Human-readable name.
    pub name: String,
    /// Parent agent ID (0 = no parent / kernel).
    pub parent: AgentId,
    /// Child agent IDs.
    pub children: Vec<AgentId>,
    /// Process group ID.
    pub pgid: AgentId,
    /// Session ID.
    pub sid: AgentId,

    // ─── State ───────────────────────────────────────────
    /// Current state.
    pub state: AgentState,
    /// Exit info (set on exit).
    pub exit_info: Option<ExitInfo>,

    // ─── Security ────────────────────────────────────────
    /// Credentials (uid, gid, capabilities).
    pub creds: AgentCredentials,

    // ─── Resources ───────────────────────────────────────
    /// Namespace and resource pointers.
    pub resources: ResourcePointers,

    // ─── Scheduling ──────────────────────────────────────
    /// Scheduling info.
    pub sched: SchedInfo,

    // ─── Signals ─────────────────────────────────────────
    /// Signal state.
    pub signals: SignalInfo,

    // ─── Timestamps ──────────────────────────────────────
    pub created_at: DateTime<Utc>,
    pub started_at: Option<DateTime<Utc>>,
    pub last_active_at: DateTime<Utc>,
}

impl AgentStruct {
    /// Create a new agent with the next available ID.
    pub fn new(name: String, parent: AgentId) -> Self {
        let id = NEXT_AGENT_ID.fetch_add(1, Ordering::SeqCst);
        let now = Utc::now();
        Self {
            id,
            name,
            parent,
            children: Vec::new(),
            pgid: id, // own process group by default
            sid: id,  // own session by default
            state: AgentState::Created,
            exit_info: None,
            creds: AgentCredentials {
                uid: 1000,
                gid: 1000,
                groups: vec![1000],
                capabilities: CapabilitySet::none(),
            },
            resources: ResourcePointers {
                context_ns: 0,
                tool_ns: 0,
                agent_ns: 0,
                net_ns: 0,
                cgroup: 0,
            },
            sched: SchedInfo {
                nice: 0,
                vruntime: 0,
                class: SchedClass::Normal,
                tokens_this_slice: 0,
                tokens_total: 0,
                tool_calls_total: 0,
            },
            signals: SignalInfo {
                pending: 0,
                mask: 0,
                handlers: HashMap::new(),
            },
            created_at: now,
            started_at: None,
            last_active_at: now,
        }
    }

    /// Check if agent has a specific capability.
    pub fn has_cap(&self, cap: u64) -> bool {
        self.creds.capabilities.has(cap)
    }

    /// Check if agent is alive (not zombie or dead).
    pub fn is_alive(&self) -> bool {
        !matches!(self.state, AgentState::Zombie | AgentState::Dead)
    }

    /// Send a signal to this agent.
    pub fn send_signal(&mut self, sig: u8) {
        // SIGKILL and SIGSTOP can't be blocked
        if sig == signals::SIGKILL || sig == signals::SIGSTOP {
            self.pending_signal(sig);
            return;
        }
        // Check if signal is masked
        if self.signals.mask & (1 << sig) != 0 {
            return; // Signal blocked
        }
        self.pending_signal(sig);
    }

    fn pending_signal(&mut self, sig: u8) {
        self.signals.pending |= 1 << sig;
    }

    /// Deliver pending signals (called by scheduler).
    pub fn deliver_signals(&mut self) {
        if self.signals.pending == 0 {
            return;
        }

        for sig in 0..64u8 {
            if self.signals.pending & (1 << sig) == 0 {
                continue;
            }
            self.signals.pending &= !(1 << sig);

            match sig {
                signals::SIGKILL => {
                    self.state = AgentState::Dead;
                    return;
                }
                signals::SIGSTOP => {
                    self.state = AgentState::Stopped;
                    return;
                }
                signals::SIGCONT => {
                    if self.state == AgentState::Stopped {
                        self.state = AgentState::Ready;
                    }
                }
                signals::SIGTERM => {
                    match self.signals.handlers.get(&sig) {
                        Some(SignalHandler::Ignore) => {}
                        Some(SignalHandler::Custom(_)) => {} // handler will be called by runtime
                        _ => {
                            self.state = AgentState::Dead;
                        } // default: terminate
                    }
                }
                _ => {
                    // Custom signals — invoke handler if registered
                }
            }
        }
    }
}

/// Global agent table (like the process table).
pub struct AgentTable {
    agents: DashMap<AgentId, RwLock<AgentStruct>>,
}

impl Default for AgentTable {
    fn default() -> Self {
        Self::new()
    }
}

impl AgentTable {
    pub fn new() -> Self {
        Self {
            agents: DashMap::new(),
        }
    }

    /// Insert a new agent.
    pub fn insert(&self, agent: AgentStruct) -> AgentId {
        let id = agent.id;
        self.agents.insert(id, RwLock::new(agent));
        id
    }

    /// Get agent by ID (read lock).
    pub fn get(
        &self,
        id: AgentId,
    ) -> Option<dashmap::mapref::one::Ref<'_, AgentId, RwLock<AgentStruct>>> {
        self.agents.get(&id)
    }

    /// Remove agent (reap).
    pub fn remove(&self, id: AgentId) -> bool {
        self.agents.remove(&id).is_some()
    }

    /// Count of all agents.
    pub fn count(&self) -> usize {
        self.agents.len()
    }

    /// List all agent IDs.
    pub fn list_ids(&self) -> Vec<AgentId> {
        self.agents.iter().map(|e| *e.key()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_agent() {
        let agent = AgentStruct::new("test".into(), 0);
        assert_eq!(agent.state, AgentState::Created);
        assert!(agent.is_alive());
        assert_eq!(agent.parent, 0);
    }

    #[test]
    fn agent_ids_increment() {
        let a1 = AgentStruct::new("a".into(), 0);
        let a2 = AgentStruct::new("b".into(), 0);
        assert!(a2.id > a1.id);
    }

    #[test]
    fn signal_kill() {
        let mut agent = AgentStruct::new("test".into(), 0);
        agent.state = AgentState::Running;
        agent.send_signal(signals::SIGKILL);
        agent.deliver_signals();
        assert_eq!(agent.state, AgentState::Dead);
    }

    #[test]
    fn signal_stop_cont() {
        let mut agent = AgentStruct::new("test".into(), 0);
        agent.state = AgentState::Running;
        agent.send_signal(signals::SIGSTOP);
        agent.deliver_signals();
        assert_eq!(agent.state, AgentState::Stopped);
        agent.send_signal(signals::SIGCONT);
        agent.deliver_signals();
        assert_eq!(agent.state, AgentState::Ready);
    }

    #[test]
    fn signal_masking() {
        let mut agent = AgentStruct::new("test".into(), 0);
        agent.state = AgentState::Running;
        agent.signals.mask = 1 << signals::SIGTERM; // block SIGTERM
        agent.send_signal(signals::SIGTERM);
        agent.deliver_signals();
        assert_eq!(agent.state, AgentState::Running); // not killed
    }

    #[test]
    fn signal_kill_cant_be_masked() {
        let mut agent = AgentStruct::new("test".into(), 0);
        agent.state = AgentState::Running;
        agent.signals.mask = u64::MAX; // block everything
        agent.send_signal(signals::SIGKILL);
        agent.deliver_signals();
        assert_eq!(agent.state, AgentState::Dead); // SIGKILL can't be blocked
    }

    #[test]
    fn capabilities() {
        let mut caps = CapabilitySet::none();
        assert!(!caps.has(CapabilitySet::CAP_NET_ACCESS));
        caps.grant(CapabilitySet::CAP_NET_ACCESS);
        assert!(caps.has(CapabilitySet::CAP_NET_ACCESS));
        caps.revoke(CapabilitySet::CAP_NET_ACCESS);
        assert!(!caps.has(CapabilitySet::CAP_NET_ACCESS));
    }

    #[test]
    fn agent_table() {
        let table = AgentTable::new();
        let a1 = AgentStruct::new("agent1".into(), 0);
        let a2 = AgentStruct::new("agent2".into(), 0);
        let id1 = a1.id;
        let id2 = a2.id;
        table.insert(a1);
        table.insert(a2);
        assert_eq!(table.count(), 2);
        assert!(table.get(id1).is_some());
        table.remove(id1);
        assert_eq!(table.count(), 1);
        assert!(table.get(id1).is_none());
    }

    #[test]
    fn sched_classes() {
        let agent = AgentStruct::new("rt".into(), 0);
        assert_eq!(agent.sched.class, SchedClass::Normal);
        assert_eq!(agent.sched.nice, 0);
    }
}
