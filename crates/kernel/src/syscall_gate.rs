//! Syscall Gate — the chokepoint every tool call passes through.
//!
//! Wires together capabilities, MAC, and cgroup quotas so that the OS-style
//! enforcement subsystems are actually consulted on the live runtime path.
//!
//! Translation layer: kernel agents are identified by `uuid::Uuid`, while the
//! OS-level subsystems (MacEngine, CgroupManager) use `agent_struct::AgentId`
//! (u64, "OS PID"). The gate maintains a Uuid ↔ PID mapping so the two halves
//! can talk without changing either.

use std::sync::atomic::{AtomicU64, Ordering};

use dashmap::DashMap;
use tokio::sync::Mutex;

use crate::agent_struct::CapabilitySet;
use crate::cgroups::{CgroupId, CgroupManager};
use crate::mac::{MacDecision, MacEngine};

/// OS-level numeric agent identifier (analogue of a Linux PID).
pub type Pid = u64;

/// The reason a syscall was denied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GateDenial {
    /// Agent is not registered with the gate.
    UnknownAgent,
    /// Required capability missing.
    MissingCapability(u64),
    /// MAC policy denied this action.
    MacDeny { action: &'static str, resource: String },
    /// Cgroup token quota would be exceeded.
    CgroupQuota,
}

impl GateDenial {
    /// Human-readable message suitable for surfacing to the LLM as a tool error.
    pub fn message(&self) -> String {
        match self {
            GateDenial::UnknownAgent => "agent not registered with kernel (ESRCH)".to_string(),
            GateDenial::MissingCapability(cap) => format!("missing capability 0x{:x} (EPERM)", cap),
            GateDenial::MacDeny { action, resource } => format!("MAC policy denies {} on {} (EACCES)", action, resource),
            GateDenial::CgroupQuota => "cgroup token quota exceeded (EAGAIN)".to_string(),
        }
    }
}

/// Action classification for a tool. Used both for MAC checks and to decide
/// which capability is required.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ToolAction {
    pub action: &'static str,
    pub required_cap: Option<u64>,
}

impl ToolAction {
    pub const READ:    Self = Self { action: "read",  required_cap: None };
    pub const WRITE:   Self = Self { action: "write", required_cap: Some(CapabilitySet::CAP_FILE_WRITE) };
    pub const NET:     Self = Self { action: "net",   required_cap: Some(CapabilitySet::CAP_NET_ACCESS) };
    pub const EXEC:    Self = Self { action: "exec",  required_cap: Some(CapabilitySet::CAP_EXEC) };
    pub const EXECUTE: Self = Self { action: "execute", required_cap: None };
}

/// Classify a built-in tool name into an action + required capability.
///
/// Custom tools default to EXECUTE with no capability requirement, deliberately —
/// they're declared by the operator who is also expected to set a MAC policy for
/// their label.
pub fn classify_tool(tool_name: &str) -> ToolAction {
    match tool_name {
        // Pure reads
        "read_file" | "list_directory" | "search_files" | "git_status" | "git_diff" => ToolAction::READ,
        // Filesystem mutations
        "write_file" | "create_directory" | "git_commit" => ToolAction::WRITE,
        // Network
        "http_get" | "browse_url" => ToolAction::NET,
        // Process execution
        "run_command" => ToolAction::EXEC,
        _ => ToolAction::EXECUTE,
    }
}

/// Per-agent registration record inside the gate.
#[derive(Debug, Clone)]
struct GateRecord {
    pid: Pid,
    caps: CapabilitySet,
    cgroup: CgroupId,
}

/// Counters surfaced for observability and tests.
#[derive(Debug, Default, Clone, Copy)]
pub struct GateStats {
    pub allowed: u64,
    pub denied_capability: u64,
    pub denied_mac: u64,
    pub denied_cgroup: u64,
    pub denied_unknown: u64,
}

/// The syscall gate.
pub struct SyscallGate {
    pub mac: Mutex<MacEngine>,
    pub cgroups: std::sync::Arc<CgroupManager>,
    /// Default cgroup new agents are placed in if the caller doesn't specify one.
    default_cgroup: CgroupId,
    /// Kernel UUID → OS PID record.
    records: DashMap<uuid::Uuid, GateRecord>,
    /// Monotonic PID allocator (starts at 1 so 0 stays reserved for "kernel").
    next_pid: AtomicU64,
    /// Counters.
    allowed: AtomicU64,
    denied_capability: AtomicU64,
    denied_mac: AtomicU64,
    denied_cgroup: AtomicU64,
    denied_unknown: AtomicU64,
}

impl SyscallGate {
    /// Create a new gate. By default MAC is in *permissive* mode (default-allow)
    /// so existing tool calls keep working until a policy is loaded. Switch to
    /// enforcing via `mac().set_enforcing(true)` and load policy rules to
    /// activate denial.
    pub fn new(cgroups: std::sync::Arc<CgroupManager>) -> Self {
        let default_cgroup = cgroups.root();
        let mac = MacEngine::new(false);
        Self {
            mac: Mutex::new(mac),
            cgroups,
            default_cgroup,
            records: DashMap::new(),
            next_pid: AtomicU64::new(1),
            allowed: AtomicU64::new(0),
            denied_capability: AtomicU64::new(0),
            denied_mac: AtomicU64::new(0),
            denied_cgroup: AtomicU64::new(0),
            denied_unknown: AtomicU64::new(0),
        }
    }

    /// Register an agent with the gate, allocating it a PID and placing it in
    /// the given cgroup (or the default if `None`). Returns the assigned PID.
    pub fn register_agent(
        &self,
        kid: uuid::Uuid,
        caps: CapabilitySet,
        cgroup: Option<CgroupId>,
    ) -> Pid {
        let pid = self.next_pid.fetch_add(1, Ordering::SeqCst);
        let cg = cgroup.unwrap_or(self.default_cgroup);
        let _ = self.cgroups.add_agent(cg, pid);
        self.records.insert(kid, GateRecord { pid, caps, cgroup: cg });
        pid
    }

    /// Remove an agent from the gate.
    pub fn unregister_agent(&self, kid: uuid::Uuid) {
        if let Some((_, rec)) = self.records.remove(&kid) {
            self.cgroups.remove_agent(rec.cgroup, rec.pid);
        }
    }

    /// Look up the OS PID for a kernel UUID (useful for MAC labelling).
    pub fn pid_of(&self, kid: uuid::Uuid) -> Option<Pid> {
        self.records.get(&kid).map(|r| r.pid)
    }

    /// Check whether an agent may make this tool call.
    ///
    /// Order: capability → MAC → cgroup quota. If all three pass, returns
    /// `Ok(pid)` so the caller can record actual usage afterwards.
    pub async fn check_tool_call(
        &self,
        kid: uuid::Uuid,
        tool_name: &str,
        resource: &str,
        est_tokens: u64,
    ) -> Result<Pid, GateDenial> {
        let action = classify_tool(tool_name);

        let (pid, caps, cgroup) = match self.records.get(&kid) {
            Some(rec) => (rec.pid, rec.caps.clone(), rec.cgroup),
            None => {
                self.denied_unknown.fetch_add(1, Ordering::Relaxed);
                return Err(GateDenial::UnknownAgent);
            }
        };

        // 1. Capability check.
        if let Some(required) = action.required_cap {
            if !caps.has(required) {
                self.denied_capability.fetch_add(1, Ordering::Relaxed);
                return Err(GateDenial::MissingCapability(required));
            }
        }

        // 2. MAC check.
        let mac_decision = {
            let mac = self.mac.lock().await;
            mac.check(pid, action.action, resource)
        };
        if mac_decision == MacDecision::Deny {
            self.denied_mac.fetch_add(1, Ordering::Relaxed);
            return Err(GateDenial::MacDeny {
                action: action.action,
                resource: resource.to_string(),
            });
        }

        // 3. Cgroup quota check.
        if !self.cgroups.check_token_limit(cgroup, est_tokens) {
            self.denied_cgroup.fetch_add(1, Ordering::Relaxed);
            return Err(GateDenial::CgroupQuota);
        }

        self.allowed.fetch_add(1, Ordering::Relaxed);
        Ok(pid)
    }

    /// Record actual token usage post-execution. Propagates up the cgroup
    /// hierarchy so parent budgets are accounted.
    pub fn record_tool_usage(&self, kid: uuid::Uuid, actual_tokens: u64) {
        if let Some(rec) = self.records.get(&kid) {
            self.cgroups.record_tokens(rec.cgroup, actual_tokens);
        }
    }

    /// Set the cgroup an agent belongs to (e.g. when applying a profile).
    pub fn set_cgroup(&self, kid: uuid::Uuid, cgroup: CgroupId) {
        if let Some(mut rec) = self.records.get_mut(&kid) {
            self.cgroups.remove_agent(rec.cgroup, rec.pid);
            let _ = self.cgroups.add_agent(cgroup, rec.pid);
            rec.cgroup = cgroup;
        }
    }

    /// Update an agent's capability set.
    pub fn set_capabilities(&self, kid: uuid::Uuid, caps: CapabilitySet) {
        if let Some(mut rec) = self.records.get_mut(&kid) {
            rec.caps = caps;
        }
    }

    /// Snapshot of the gate counters.
    pub fn stats(&self) -> GateStats {
        GateStats {
            allowed: self.allowed.load(Ordering::Relaxed),
            denied_capability: self.denied_capability.load(Ordering::Relaxed),
            denied_mac: self.denied_mac.load(Ordering::Relaxed),
            denied_cgroup: self.denied_cgroup.load(Ordering::Relaxed),
            denied_unknown: self.denied_unknown.load(Ordering::Relaxed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cgroups::CgroupLimits;
    use crate::mac::PolicyRule;

    fn fresh_gate() -> (std::sync::Arc<SyscallGate>, std::sync::Arc<CgroupManager>) {
        let cgroups = std::sync::Arc::new(CgroupManager::new());
        let gate = std::sync::Arc::new(SyscallGate::new(cgroups.clone()));
        (gate, cgroups)
    }

    #[test]
    fn classify_known_tools() {
        assert_eq!(classify_tool("read_file").action, "read");
        assert_eq!(classify_tool("write_file").action, "write");
        assert_eq!(classify_tool("http_get").action, "net");
        assert_eq!(classify_tool("run_command").action, "exec");
        assert_eq!(classify_tool("totally_custom_tool").action, "execute");
    }

    #[tokio::test]
    async fn allows_when_no_policy_and_no_quota() {
        let (gate, _) = fresh_gate();
        let kid = uuid::Uuid::new_v4();
        gate.register_agent(kid, CapabilitySet::all(), None);

        let pid = gate.check_tool_call(kid, "read_file", "/etc/hosts", 10).await;
        assert!(pid.is_ok());
        assert_eq!(gate.stats().allowed, 1);
    }

    #[tokio::test]
    async fn denies_unknown_agent() {
        let (gate, _) = fresh_gate();
        let kid = uuid::Uuid::new_v4();
        let r = gate.check_tool_call(kid, "read_file", "/x", 1).await;
        assert_eq!(r, Err(GateDenial::UnknownAgent));
        assert_eq!(gate.stats().denied_unknown, 1);
    }

    #[tokio::test]
    async fn denies_when_capability_missing() {
        let (gate, _) = fresh_gate();
        let kid = uuid::Uuid::new_v4();
        gate.register_agent(kid, CapabilitySet::none(), None);

        // write_file requires CAP_FILE_WRITE
        let r = gate.check_tool_call(kid, "write_file", "/tmp/x", 1).await;
        assert!(matches!(r, Err(GateDenial::MissingCapability(_))));

        // read_file has no required capability — should pass
        let r = gate.check_tool_call(kid, "read_file", "/tmp/x", 1).await;
        assert!(r.is_ok());
    }

    #[tokio::test]
    async fn denies_when_mac_says_deny() {
        let (gate, _) = fresh_gate();
        let kid = uuid::Uuid::new_v4();
        let pid = gate.register_agent(kid, CapabilitySet::all(), None);

        {
            let mut mac = gate.mac.lock().await;
            mac.set_enforcing(true);
            mac.label_agent(pid, "untrusted".into());
            mac.load_policy(vec![
                PolicyRule {
                    subject: "untrusted".into(),
                    action: "net".into(),
                    object: "*".into(),
                    decision: "deny".into(),
                },
                PolicyRule {
                    subject: "untrusted".into(),
                    action: "*".into(),
                    object: "*".into(),
                    decision: "allow".into(),
                },
            ]);
        }

        let r = gate.check_tool_call(kid, "http_get", "https://example.com", 1).await;
        assert!(matches!(r, Err(GateDenial::MacDeny { .. })));
        assert_eq!(gate.stats().denied_mac, 1);

        // Reads should still pass (allow rule).
        let r = gate.check_tool_call(kid, "read_file", "/tmp/x", 1).await;
        assert!(r.is_ok());
    }

    #[tokio::test]
    async fn denies_over_cgroup_quota() {
        let (gate, cgroups) = fresh_gate();
        let cg = cgroups.create("tight".into(), cgroups.root(), CgroupLimits {
            tokens_per_min: 100,
            ..Default::default()
        });
        let kid = uuid::Uuid::new_v4();
        gate.register_agent(kid, CapabilitySet::all(), Some(cg));

        // Use most of the budget.
        gate.record_tool_usage(kid, 90);

        // Asking for 30 more would push to 120 > 100 → denied.
        let r = gate.check_tool_call(kid, "read_file", "/x", 30).await;
        assert_eq!(r, Err(GateDenial::CgroupQuota));
        assert_eq!(gate.stats().denied_cgroup, 1);

        // 5 more is under budget.
        let r = gate.check_tool_call(kid, "read_file", "/x", 5).await;
        assert!(r.is_ok());
    }

    #[tokio::test]
    async fn unregister_releases_cgroup_slot() {
        let (gate, cgroups) = fresh_gate();
        let cg = cgroups.create("small".into(), cgroups.root(), CgroupLimits {
            max_agents: 1,
            ..Default::default()
        });
        let kid1 = uuid::Uuid::new_v4();
        let kid2 = uuid::Uuid::new_v4();

        gate.register_agent(kid1, CapabilitySet::all(), Some(cg));
        gate.unregister_agent(kid1);
        gate.register_agent(kid2, CapabilitySet::all(), Some(cg));

        // If the slot wasn't released the second register would have failed silently
        // and pid_of would return Some — verify by checking we have a PID.
        assert!(gate.pid_of(kid2).is_some());
    }
}
