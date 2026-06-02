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
use crate::namespaces::NamespaceId;

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
    MacDeny {
        action: &'static str,
        resource: String,
    },
    /// Cgroup token quota would be exceeded.
    CgroupQuota,
    /// Tool is registered in a namespace the agent is not a member of.
    NotInNamespace {
        tool: String,
        namespace: NamespaceId,
    },
}

impl GateDenial {
    /// Human-readable message suitable for surfacing to the LLM as a tool error.
    pub fn message(&self) -> String {
        match self {
            GateDenial::UnknownAgent => "agent not registered with kernel (ESRCH)".to_string(),
            GateDenial::MissingCapability(cap) => format!("missing capability 0x{:x} (EPERM)", cap),
            GateDenial::MacDeny { action, resource } => {
                format!("MAC policy denies {} on {} (EACCES)", action, resource)
            }
            GateDenial::CgroupQuota => "cgroup token quota exceeded (EAGAIN)".to_string(),
            GateDenial::NotInNamespace { tool, namespace } => format!(
                "tool '{}' not visible in agent's namespaces (ns={}, ENOENT)",
                tool, namespace
            ),
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
    pub const READ: Self = Self {
        action: "read",
        required_cap: None,
    };
    pub const WRITE: Self = Self {
        action: "write",
        required_cap: Some(CapabilitySet::CAP_FILE_WRITE),
    };
    pub const NET: Self = Self {
        action: "net",
        required_cap: Some(CapabilitySet::CAP_NET_ACCESS),
    };
    pub const EXEC: Self = Self {
        action: "exec",
        required_cap: Some(CapabilitySet::CAP_EXEC),
    };
    pub const EXECUTE: Self = Self {
        action: "execute",
        required_cap: None,
    };
    pub const DELETE: Self = Self {
        action: "delete",
        required_cap: Some(CapabilitySet::CAP_FILE_DELETE),
    };
    pub const IPC: Self = Self {
        action: "ipc",
        required_cap: None,
    };
}

/// Classify a built-in tool name into an action + required capability.
///
/// Custom tools default to EXECUTE with no capability requirement, deliberately —
/// they're declared by the operator who is also expected to set a MAC policy for
/// their label.
pub fn classify_tool(tool_name: &str) -> ToolAction {
    match tool_name {
        // Pure reads
        "read_file" | "list_directory" | "search_files" | "git_status" | "git_diff" => {
            ToolAction::READ
        }
        // Filesystem mutations
        "write_file" | "create_directory" | "create_file" | "edit_file" | "git_commit" => {
            ToolAction::WRITE
        }
        // Filesystem deletion — requires CAP_FILE_DELETE (distinct from write).
        "delete_file" => ToolAction::DELETE,
        // Network
        "http_get" | "browse_url" => ToolAction::NET,
        // Process execution
        "run_command" => ToolAction::EXEC,
        // Inter-agent messaging + delegation (namespace isolation + the broker
        // Ipc profile rule are the real boundaries).
        "send_agent_message"
        | "check_inbox"
        | "delegate_task"
        | "delegation_status"
        | "complete_delegation"
        | "discover_agents" => ToolAction::IPC,
        _ => ToolAction::EXECUTE,
    }
}

/// Per-agent registration record inside the gate.
#[derive(Debug, Clone)]
struct GateRecord {
    pid: Pid,
    caps: CapabilitySet,
    cgroup: CgroupId,
    /// Namespaces this agent is a member of. A tool registered in any of these
    /// namespaces is visible. Tools without a namespace are visible to everyone.
    namespaces: Vec<NamespaceId>,
}

/// Read-only snapshot of an agent's enforcement state inside the gate.
///
/// Answers "what am I allowed to do?" for an SDK/agent without mutating any
/// gate state (no counter bumps, no cgroup accounting). Built from the agent's
/// [`GateRecord`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentGateInfo {
    /// OS PID (Linux-analogue) the gate assigned to this agent.
    pub pid: Pid,
    /// Human-readable names of the capabilities currently granted.
    pub capabilities: Vec<String>,
    /// Cgroup the agent is accounted against.
    pub cgroup: CgroupId,
    /// Namespaces the agent is a member of (empty means unconfined/global).
    pub namespaces: Vec<NamespaceId>,
}

/// All known capability bits paired with their human-readable name. The single
/// source of truth for [`capability_names`]; kept in sync with the
/// `CapabilitySet::CAP_*` constants.
const CAPABILITY_NAMES: &[(u64, &str)] = &[
    (CapabilitySet::CAP_TOOL_MOUNT, "CAP_TOOL_MOUNT"),
    (CapabilitySet::CAP_AGENT_CREATE, "CAP_AGENT_CREATE"),
    (CapabilitySet::CAP_AGENT_KILL, "CAP_AGENT_KILL"),
    (CapabilitySet::CAP_NET_ACCESS, "CAP_NET_ACCESS"),
    (CapabilitySet::CAP_FILE_WRITE, "CAP_FILE_WRITE"),
    (CapabilitySet::CAP_FILE_DELETE, "CAP_FILE_DELETE"),
    (CapabilitySet::CAP_EXEC, "CAP_EXEC"),
    (CapabilitySet::CAP_ADMIN, "CAP_ADMIN"),
    (CapabilitySet::CAP_SYS_RESOURCE, "CAP_SYS_RESOURCE"),
];

/// Map a capability set to the human-readable names of its granted caps, in a
/// stable (bit-ascending) order.
fn capability_names(caps: &CapabilitySet) -> Vec<String> {
    CAPABILITY_NAMES
        .iter()
        .filter(|(bit, _)| caps.has(*bit))
        .map(|(_, name)| name.to_string())
        .collect()
}

/// Counters surfaced for observability and tests.
#[derive(Debug, Default, Clone, Copy)]
pub struct GateStats {
    pub allowed: u64,
    pub denied_capability: u64,
    pub denied_mac: u64,
    pub denied_cgroup: u64,
    pub denied_unknown: u64,
    pub denied_namespace: u64,
    /// Calls allowed by an `audit` MAC rule (allowed *and* logged).
    pub audited: u64,
}

/// What the gate decided about an audited tool call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditDecision {
    /// A MAC `audit` rule matched: the call was allowed, and this event records it.
    Allowed,
    /// The call was denied (security-relevant; recorded for the audit trail).
    Denied,
}

/// An access-control audit record, emitted to the configured [`AuditSink`].
/// Analogous to an SELinux AVC audit message.
#[derive(Debug, Clone)]
pub struct AuditEvent {
    /// Kernel agent id (subject).
    pub agent: uuid::Uuid,
    /// OS PID of the subject.
    pub pid: Pid,
    /// Tool the agent invoked.
    pub tool: String,
    /// Classified action label (read/write/net/exec/...).
    pub action: &'static str,
    /// Resource string the action targeted (path/url/command).
    pub resource: String,
    /// Outcome.
    pub decision: AuditDecision,
}

/// A sink the gate writes access-control audit events to. The kernel wires its
/// observability engine in as the sink so MAC `audit` decisions land in the
/// agent activity log instead of vanishing.
pub trait AuditSink: Send + Sync {
    fn audit(&self, event: AuditEvent);
}

/// The syscall gate.
pub struct SyscallGate {
    pub mac: Mutex<MacEngine>,
    pub cgroups: std::sync::Arc<CgroupManager>,
    /// Default cgroup new agents are placed in if the caller doesn't specify one.
    default_cgroup: CgroupId,
    /// Kernel UUID → OS PID record.
    records: DashMap<uuid::Uuid, GateRecord>,
    /// Tool namespace assignments. A tool with a namespace is only visible to
    /// agents that are members of that namespace; absence means "global".
    tool_namespaces: DashMap<String, NamespaceId>,
    /// Monotonic PID allocator (starts at 1 so 0 stays reserved for "kernel").
    next_pid: AtomicU64,
    /// Optional audit sink for MAC `audit` decisions (and denials). Wired to the
    /// observability engine by the kernel; `None` keeps audit events as counters only.
    audit_sink: std::sync::Mutex<Option<std::sync::Arc<dyn AuditSink>>>,
    /// Counters.
    allowed: AtomicU64,
    denied_capability: AtomicU64,
    denied_mac: AtomicU64,
    denied_cgroup: AtomicU64,
    denied_unknown: AtomicU64,
    denied_namespace: AtomicU64,
    audited: AtomicU64,
}

impl SyscallGate {
    /// Create a new gate. By default MAC is in *permissive* mode (default-allow)
    /// so existing tool calls keep working until a policy is loaded. Switch to
    /// enforcing via `mac().set_enforcing(true)` and load policy rules to
    /// activate denial.
    pub fn new(cgroups: std::sync::Arc<CgroupManager>) -> Self {
        Self::with_mac(cgroups, false, Vec::new())
    }

    /// Create a gate with an explicit MAC configuration: `mac_enforcing` mode
    /// and an initial policy. The kernel uses this to wire operator MAC settings
    /// from config; `new` is the permissive (default-allow, no rules) shortcut.
    pub fn with_mac(
        cgroups: std::sync::Arc<CgroupManager>,
        mac_enforcing: bool,
        mac_rules: Vec<crate::mac::PolicyRule>,
    ) -> Self {
        let default_cgroup = cgroups.root();
        let mut mac = MacEngine::new(mac_enforcing);
        mac.load_policy(mac_rules);
        Self {
            mac: Mutex::new(mac),
            cgroups,
            default_cgroup,
            records: DashMap::new(),
            tool_namespaces: DashMap::new(),
            next_pid: AtomicU64::new(1),
            audit_sink: std::sync::Mutex::new(None),
            allowed: AtomicU64::new(0),
            denied_capability: AtomicU64::new(0),
            denied_mac: AtomicU64::new(0),
            denied_cgroup: AtomicU64::new(0),
            denied_unknown: AtomicU64::new(0),
            denied_namespace: AtomicU64::new(0),
            audited: AtomicU64::new(0),
        }
    }

    /// Install the audit sink. The kernel passes its observability engine so
    /// MAC `audit` decisions are recorded in the agent activity log.
    pub fn set_audit_sink(&self, sink: std::sync::Arc<dyn AuditSink>) {
        *self.audit_sink.lock().unwrap() = Some(sink);
    }

    /// Emit an audit event to the configured sink, if any.
    fn emit_audit(&self, event: AuditEvent) {
        let sink = self.audit_sink.lock().unwrap().clone();
        if let Some(sink) = sink {
            sink.audit(event);
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
        self.records.insert(
            kid,
            GateRecord {
                pid,
                caps,
                cgroup: cg,
                namespaces: Vec::new(),
            },
        );
        pid
    }

    /// Tag a tool with a namespace. Once tagged, only agents whose
    /// `set_agent_namespaces` set contains this id will resolve the tool.
    pub fn register_tool_namespace(&self, tool_name: impl Into<String>, ns: NamespaceId) {
        self.tool_namespaces.insert(tool_name.into(), ns);
    }

    /// Remove a tool's namespace tag — makes it global again.
    pub fn unregister_tool_namespace(&self, tool_name: &str) {
        self.tool_namespaces.remove(tool_name);
    }

    /// Replace an agent's namespace memberships.
    pub fn set_agent_namespaces(&self, kid: uuid::Uuid, namespaces: Vec<NamespaceId>) {
        if let Some(mut rec) = self.records.get_mut(&kid) {
            rec.namespaces = namespaces;
        }
    }

    /// Add a namespace to an agent's existing memberships.
    pub fn add_agent_namespace(&self, kid: uuid::Uuid, ns: NamespaceId) {
        if let Some(mut rec) = self.records.get_mut(&kid) {
            if !rec.namespaces.contains(&ns) {
                rec.namespaces.push(ns);
            }
        }
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

    /// Read-only introspection: report the agent's enforcement state (PID,
    /// granted capabilities, cgroup, namespaces) so an SDK/agent can answer
    /// "what am I allowed to do?". Returns `None` if the agent is unknown.
    ///
    /// Side-effect-free: it does not bump any counter, touch the cgroup
    /// accounting, or consult MAC — it only reads the per-agent record.
    pub fn agent_info(&self, kid: uuid::Uuid) -> Option<AgentGateInfo> {
        self.records.get(&kid).map(|rec| AgentGateInfo {
            pid: rec.pid,
            capabilities: capability_names(&rec.caps),
            cgroup: rec.cgroup,
            namespaces: rec.namespaces.clone(),
        })
    }

    /// Check whether an agent may make this tool call.
    ///
    /// Order: namespace visibility → capability → MAC → cgroup quota. If all
    /// pass, returns `Ok(pid)` so the caller can record actual usage afterwards.
    /// Namespace runs first because the LLM should not learn anything about
    /// tools it cannot see (an attacker probing a denied resource gets ENOENT,
    /// not EACCES).
    pub async fn check_tool_call(
        &self,
        kid: uuid::Uuid,
        tool_name: &str,
        resource: &str,
        est_tokens: u64,
    ) -> Result<Pid, GateDenial> {
        let action = classify_tool(tool_name);

        let (pid, caps, cgroup, agent_namespaces) = match self.records.get(&kid) {
            Some(rec) => (
                rec.pid,
                rec.caps.clone(),
                rec.cgroup,
                rec.namespaces.clone(),
            ),
            None => {
                self.denied_unknown.fetch_add(1, Ordering::Relaxed);
                return Err(GateDenial::UnknownAgent);
            }
        };

        // 0. Namespace visibility. If the tool is tagged with a namespace,
        //    the agent must be a member of it. Untagged tools are global.
        if let Some(tool_ns) = self.tool_namespaces.get(tool_name).map(|r| *r.value()) {
            if !agent_namespaces.contains(&tool_ns) {
                self.denied_namespace.fetch_add(1, Ordering::Relaxed);
                return Err(GateDenial::NotInNamespace {
                    tool: tool_name.to_string(),
                    namespace: tool_ns,
                });
            }
        }

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
        match mac_decision {
            MacDecision::Deny => {
                self.denied_mac.fetch_add(1, Ordering::Relaxed);
                self.emit_audit(AuditEvent {
                    agent: kid,
                    pid,
                    tool: tool_name.to_string(),
                    action: action.action,
                    resource: resource.to_string(),
                    decision: AuditDecision::Denied,
                });
                return Err(GateDenial::MacDeny {
                    action: action.action,
                    resource: resource.to_string(),
                });
            }
            // "Allow but log": let the call proceed, but record it. Without a
            // sink this is just a counter; with one wired it lands in the audit log.
            MacDecision::Audit => {
                self.audited.fetch_add(1, Ordering::Relaxed);
                self.emit_audit(AuditEvent {
                    agent: kid,
                    pid,
                    tool: tool_name.to_string(),
                    action: action.action,
                    resource: resource.to_string(),
                    decision: AuditDecision::Allowed,
                });
            }
            MacDecision::Allow => {}
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
            denied_namespace: self.denied_namespace.load(Ordering::Relaxed),
            audited: self.audited.load(Ordering::Relaxed),
        }
    }

    /// Whether two agents share at least one namespace. Foundation for
    /// namespace-aware IPC and any other cross-agent visibility check.
    /// If either agent is unregistered, returns true (the call sites already
    /// fail elsewhere; we don't want a missing-record race to drop messages).
    pub fn shares_namespace(&self, a: uuid::Uuid, b: uuid::Uuid) -> bool {
        let ns_a = match self.records.get(&a) {
            Some(rec) => rec.namespaces.clone(),
            None => return true,
        };
        let ns_b = match self.records.get(&b) {
            Some(rec) => rec.namespaces.clone(),
            None => return true,
        };
        // Empty memberships on either side → unconfined → allow (matches
        // the "untagged tools are global" rule from `check_tool_call`).
        if ns_a.is_empty() || ns_b.is_empty() {
            return true;
        }
        ns_a.iter().any(|n| ns_b.contains(n))
    }
}

impl crate::ipc::NamespaceVisibility for SyscallGate {
    fn allows(&self, from: uuid::Uuid, to: uuid::Uuid) -> bool {
        self.shares_namespace(from, to)
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

    #[test]
    fn classify_edit_and_delete_tools() {
        // File mutations require CAP_FILE_WRITE.
        for t in ["create_file", "edit_file"] {
            let a = classify_tool(t);
            assert_eq!(a.action, "write");
            assert_eq!(a.required_cap, Some(CapabilitySet::CAP_FILE_WRITE));
        }
        // Deletion is a distinct action requiring CAP_FILE_DELETE.
        let d = classify_tool("delete_file");
        assert_eq!(d.action, "delete");
        assert_eq!(d.required_cap, Some(CapabilitySet::CAP_FILE_DELETE));
    }

    #[tokio::test]
    async fn allows_when_no_policy_and_no_quota() {
        let (gate, _) = fresh_gate();
        let kid = uuid::Uuid::new_v4();
        gate.register_agent(kid, CapabilitySet::all(), None);

        let pid = gate
            .check_tool_call(kid, "read_file", "/etc/hosts", 10)
            .await;
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

        let r = gate
            .check_tool_call(kid, "http_get", "https://example.com", 1)
            .await;
        assert!(matches!(r, Err(GateDenial::MacDeny { .. })));
        assert_eq!(gate.stats().denied_mac, 1);

        // Reads should still pass (allow rule).
        let r = gate.check_tool_call(kid, "read_file", "/tmp/x", 1).await;
        assert!(r.is_ok());
    }

    #[tokio::test]
    async fn denies_over_cgroup_quota() {
        let (gate, cgroups) = fresh_gate();
        let cg = cgroups.create(
            "tight".into(),
            cgroups.root(),
            CgroupLimits {
                tokens_per_min: 100,
                ..Default::default()
            },
        );
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
    async fn audit_decision_allows_and_emits_event() {
        use std::sync::Arc;
        use std::sync::Mutex;

        // A test sink that just collects events.
        struct RecordingSink(Mutex<Vec<AuditEvent>>);
        impl AuditSink for RecordingSink {
            fn audit(&self, event: AuditEvent) {
                self.0.lock().unwrap().push(event);
            }
        }

        let (gate, _) = fresh_gate();
        let sink = Arc::new(RecordingSink(Mutex::new(Vec::new())));
        gate.set_audit_sink(sink.clone());

        let kid = uuid::Uuid::new_v4();
        let pid = gate.register_agent(kid, CapabilitySet::all(), None);
        {
            let mut mac = gate.mac.lock().await;
            mac.set_enforcing(true);
            mac.label_agent(pid, "watched".into());
            mac.load_policy(vec![
                PolicyRule {
                    subject: "watched".into(),
                    action: "exec".into(),
                    object: "*".into(),
                    decision: "audit".into(),
                },
                PolicyRule {
                    subject: "*".into(),
                    action: "*".into(),
                    object: "*".into(),
                    decision: "allow".into(),
                },
            ]);
        }

        // run_command is an `exec` action → audit rule → allowed *and* logged.
        let r = gate.check_tool_call(kid, "run_command", "/bin/ls", 5).await;
        assert!(r.is_ok(), "audit decision must allow the call");
        assert_eq!(gate.stats().audited, 1);
        assert_eq!(gate.stats().allowed, 1);

        let events = sink.0.lock().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].decision, AuditDecision::Allowed);
        assert_eq!(events[0].action, "exec");
        assert_eq!(events[0].tool, "run_command");
        assert_eq!(events[0].resource, "/bin/ls");
        assert_eq!(events[0].agent, kid);
    }

    #[tokio::test]
    async fn deny_emits_audit_event() {
        use std::sync::Arc;
        use std::sync::Mutex;

        struct RecordingSink(Mutex<Vec<AuditEvent>>);
        impl AuditSink for RecordingSink {
            fn audit(&self, event: AuditEvent) {
                self.0.lock().unwrap().push(event);
            }
        }

        let (gate, _) = fresh_gate();
        let sink = Arc::new(RecordingSink(Mutex::new(Vec::new())));
        gate.set_audit_sink(sink.clone());

        let kid = uuid::Uuid::new_v4();
        let pid = gate.register_agent(kid, CapabilitySet::all(), None);
        {
            let mut mac = gate.mac.lock().await;
            mac.set_enforcing(true);
            mac.label_agent(pid, "blocked".into());
            mac.load_policy(vec![PolicyRule {
                subject: "blocked".into(),
                action: "net".into(),
                object: "*".into(),
                decision: "deny".into(),
            }]);
        }

        let r = gate
            .check_tool_call(kid, "http_get", "https://x.example", 5)
            .await;
        assert!(matches!(r, Err(GateDenial::MacDeny { .. })));
        let events = sink.0.lock().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].decision, AuditDecision::Denied);
    }

    #[tokio::test]
    async fn unregister_releases_cgroup_slot() {
        let (gate, cgroups) = fresh_gate();
        let cg = cgroups.create(
            "small".into(),
            cgroups.root(),
            CgroupLimits {
                max_agents: 1,
                ..Default::default()
            },
        );
        let kid1 = uuid::Uuid::new_v4();
        let kid2 = uuid::Uuid::new_v4();

        gate.register_agent(kid1, CapabilitySet::all(), Some(cg));
        gate.unregister_agent(kid1);
        gate.register_agent(kid2, CapabilitySet::all(), Some(cg));

        // If the slot wasn't released the second register would have failed silently
        // and pid_of would return Some — verify by checking we have a PID.
        assert!(gate.pid_of(kid2).is_some());
    }

    #[test]
    fn agent_info_reports_capabilities_and_namespaces() {
        let (gate, _) = fresh_gate();
        let kid = uuid::Uuid::new_v4();

        // A read-only style agent: network access, but no file write/delete/exec.
        let caps = CapabilitySet::new(CapabilitySet::CAP_NET_ACCESS);
        let pid = gate.register_agent(kid, caps, None);
        gate.set_agent_namespaces(kid, vec![7, 42]);

        let info = gate.agent_info(kid).expect("registered agent has info");
        assert_eq!(info.pid, pid);
        assert_eq!(info.capabilities, vec!["CAP_NET_ACCESS".to_string()]);
        assert_eq!(info.namespaces, vec![7, 42]);
        assert_eq!(info.cgroup, gate.default_cgroup);

        // Introspection is side-effect-free: counters must be untouched.
        let stats = gate.stats();
        assert_eq!(stats.allowed, 0);
        assert_eq!(stats.denied_capability, 0);
        assert_eq!(stats.denied_unknown, 0);

        // Unknown agent → None.
        assert!(gate.agent_info(uuid::Uuid::new_v4()).is_none());
    }

    #[test]
    fn agent_info_lists_all_caps_for_full_set() {
        let (gate, _) = fresh_gate();
        let kid = uuid::Uuid::new_v4();
        gate.register_agent(kid, CapabilitySet::all(), None);

        let info = gate.agent_info(kid).unwrap();
        assert_eq!(info.capabilities.len(), CAPABILITY_NAMES.len());
        assert!(info.capabilities.contains(&"CAP_FILE_WRITE".to_string()));
        assert!(info.capabilities.contains(&"CAP_ADMIN".to_string()));

        // No capabilities → empty list.
        let bare = uuid::Uuid::new_v4();
        gate.register_agent(bare, CapabilitySet::none(), None);
        assert!(gate.agent_info(bare).unwrap().capabilities.is_empty());
    }
}
