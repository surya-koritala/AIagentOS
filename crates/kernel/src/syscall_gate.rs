//! Syscall Gate — the chokepoint every tool call passes through.
//!
//! Wires together namespace visibility, capabilities, MAC, approvals, cgroup
//! membership, and concurrent-tool limits on the live runtime path. Provider
//! token quota uses a separate durable snapshot/reservation handshake exposed
//! by this gate.
//!
//! Translation layer: kernel agents are identified by `uuid::Uuid`, while the
//! OS-level subsystems (MacEngine, CgroupManager) use `agent_struct::AgentId`
//! (u64, "OS PID"). The gate maintains a Uuid ↔ PID mapping so the two halves
//! can talk without changing either.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;

use dashmap::DashMap;
use tokio::sync::{watch, Mutex};

use crate::agent_struct::CapabilitySet;
use crate::cgroups::{CgroupError, CgroupId, CgroupManager};
use crate::mac::{MacDecision, MacEngine};
use crate::namespaces::NamespaceId;

/// OS-level numeric agent identifier (analogue of a Linux PID).
pub type Pid = u64;

/// The reason a syscall was denied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GateDenial {
    /// Agent is not registered with the gate.
    UnknownAgent,
    /// Tool name has no validated built-in declaration on the compatibility
    /// path. Live registries reject it even earlier.
    UnknownTool(String),
    /// A validated tool declaration requires an exact, one-shot local
    /// operator approval that has not been granted.
    ApprovalRequired {
        tool: String,
        policy: crate::tools::ApprovalPolicy,
    },
    /// Required capability missing.
    MissingCapability(u64),
    /// MAC policy denied this action.
    MacDeny {
        action: &'static str,
        resource: String,
    },
    /// Legacy token-quota denial. Tool payload size no longer consumes provider
    /// quota, so current authorization paths do not emit this variant.
    CgroupQuota,
    /// Cgroup hierarchy or membership state is unavailable/corrupt.
    CgroupUnavailable(String),
    /// Membership changed after provider quota was reserved. The reservation
    /// must be refunded and admission retried against a fresh snapshot.
    CgroupMembershipChanged,
    /// Cgroup concurrent tool-call limit is full.
    CgroupToolLimit,
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
            GateDenial::UnknownTool(tool) => {
                format!("tool '{tool}' has no validated security declaration (ENOENT)")
            }
            GateDenial::ApprovalRequired { tool, policy } => {
                format!("tool '{tool}' requires {policy:?} approval (EACCES)")
            }
            GateDenial::MissingCapability(cap) => format!("missing capability 0x{:x} (EPERM)", cap),
            GateDenial::MacDeny { action, resource } => {
                format!("MAC policy denies {} on {} (EACCES)", action, resource)
            }
            GateDenial::CgroupQuota => "cgroup token quota exceeded (EAGAIN)".to_string(),
            GateDenial::CgroupUnavailable(reason) => {
                format!("cgroup enforcement unavailable: {reason} (EIO)")
            }
            GateDenial::CgroupMembershipChanged => {
                "cgroup membership changed during provider admission (EAGAIN)".to_string()
            }
            GateDenial::CgroupToolLimit => {
                "cgroup concurrent tool-call limit exceeded (EAGAIN)".to_string()
            }
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

struct ToolCallContract<'a> {
    tool_name: &'a str,
    resource: &'a str,
    action: &'static str,
    required_capabilities: &'a [u64],
    approval_policy: crate::tools::ApprovalPolicy,
    approval_contract: Option<&'a str>,
}

struct AuthorizedToolCall {
    pid: Pid,
    audited: bool,
}

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum GateMutationError {
    #[error("agent {0} is already registered with the syscall gate")]
    AlreadyRegistered(uuid::Uuid),

    #[error("agent {0} is not registered with the syscall gate")]
    UnknownAgent(uuid::Uuid),

    #[error(
        "kernel-managed agent {0} cannot be reassigned through the raw syscall-gate cgroup API"
    )]
    ManagedCgroupImmutable(uuid::Uuid),

    #[error(transparent)]
    Cgroup(#[from] CgroupError),
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
/// This informational classifier returns the conservative `EXEC` class for an
/// unknown name. Authorization does not use that fallback: `check_tool_call`
/// rejects names missing from the built-in catalog, and live registries pass a
/// validated declaration to `check_tool_call_declared`.
fn default_security_catalog(
) -> &'static std::collections::HashMap<String, crate::tools::ToolSecurity> {
    static CATALOG: OnceLock<std::collections::HashMap<String, crate::tools::ToolSecurity>> =
        OnceLock::new();
    CATALOG.get_or_init(crate::tools::ToolRegistry::default_security_catalog)
}

pub fn classify_tool(tool_name: &str) -> ToolAction {
    default_security_catalog()
        .get(tool_name)
        .map_or(ToolAction::EXEC, |security| ToolAction {
            action: security.action.as_str(),
            // Direct legacy callers support one capability. Live public paths use
            // `check_tool_call_declared`, which enforces the complete vector.
            required_cap: security.required_capabilities.first().copied(),
        })
}

/// Per-agent registration record inside the gate.
#[derive(Debug, Clone)]
struct GateRecord {
    pid: Pid,
    caps: CapabilitySet,
    cgroup: CgroupId,
    /// Kernel-created agents are pinned to their managed
    /// root→tenant→profile→private-agent hierarchy. A raw gate reassignment
    /// must not discard those durable quota scopes.
    managed_cgroup: bool,
    cgroup_revision: u64,
    /// Per-agent revision notifier. A provider request waiting on capacity for
    /// an old hierarchy subscribes to this channel and resnapshots immediately
    /// after a successful move instead of sleeping until the epoch boundary.
    cgroup_changes: watch::Sender<u64>,
    accepting_tool_calls: bool,
    /// Namespaces this agent is a member of. A tool registered in any of these
    /// namespaces is visible. Tools without a namespace are visible to everyone.
    namespaces: Vec<NamespaceId>,
}

/// Durable quota constraints paired with the membership revision they were
/// derived from. Execution re-verifies the revision immediately before provider
/// I/O and refunds/retries if reassignment raced admission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CgroupQuotaSnapshot {
    pub constraints: Vec<crate::context::CgroupQuotaConstraint>,
    pub membership_revision: u64,
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
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct GateStats {
    pub allowed: u64,
    pub denied_capability: u64,
    pub denied_mac: u64,
    pub denied_approval: u64,
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
    /// When `true`, `check_tool_call` short-circuits to `Allow` for every call.
    /// This is the **single, explicit, greppable** way to run ungoverned — built
    /// only via [`SyscallGate::unconfined`]. Enforcement is otherwise mandatory:
    /// an executor cannot exist without a gate (it is a required constructor
    /// argument), so there is no "forgot to enable the gate" failure mode.
    unconfined: bool,
    /// Default cgroup new agents are placed in if the caller doesn't specify one.
    default_cgroup: CgroupId,
    /// Kernel UUID → OS PID record.
    records: DashMap<uuid::Uuid, GateRecord>,
    /// Serializes multi-map registration and reassignment transactions.
    mutation_lock: std::sync::Mutex<()>,
    /// Tool namespace assignments. A tool with a namespace is only visible to
    /// agents that are members of that namespace; absence means "global".
    tool_namespaces: DashMap<String, NamespaceId>,
    /// Exact, single-use local approvals keyed by
    /// (agent, tool, resource, serialized validated security contract).
    /// No wire/package/MCP deserialization path can populate this map.
    approvals: DashMap<(uuid::Uuid, String, String, String), crate::tools::ApprovalPolicy>,
    /// Monotonic PID allocator (starts at 1 so 0 stays reserved for "kernel").
    next_pid: AtomicU64,
    /// Global monotonic cgroup-membership revision allocator. Global ordering
    /// prevents unregister/re-register ABA for the same kernel UUID.
    next_cgroup_revision: AtomicU64,
    /// Optional audit sink for MAC `audit` decisions (and denials). Wired to the
    /// observability engine by the kernel; `None` keeps audit events as counters only.
    audit_sink: std::sync::Mutex<Option<std::sync::Arc<dyn AuditSink>>>,
    /// Counters.
    allowed: AtomicU64,
    denied_capability: AtomicU64,
    denied_mac: AtomicU64,
    denied_approval: AtomicU64,
    denied_cgroup: AtomicU64,
    denied_unknown: AtomicU64,
    denied_namespace: AtomicU64,
    audited: AtomicU64,
}

impl SyscallGate {
    /// Reserve one cgroup tool-call slot for a previously authorized agent.
    /// The returned guard must be held until tool execution finishes.
    pub fn acquire_tool_call(
        &self,
        kid: uuid::Uuid,
    ) -> Result<crate::cgroups::ToolCallGuard, GateDenial> {
        let _mutation = self.mutation_lock.lock().unwrap();
        let (cgroup, pid, accepting_tool_calls) = self
            .records
            .get(&kid)
            .map(|record| (record.cgroup, record.pid, record.accepting_tool_calls))
            .ok_or(GateDenial::UnknownAgent)?;
        if !accepting_tool_calls {
            self.denied_cgroup.fetch_add(1, Ordering::Relaxed);
            return Err(GateDenial::CgroupUnavailable(
                "agent tool admission is closed for lifecycle cleanup".into(),
            ));
        }
        self.cgroups
            .acquire_tool_call_for_agent(cgroup, pid)
            .map_err(|error| {
                self.denied_cgroup.fetch_add(1, Ordering::Relaxed);
                match error {
                    CgroupError::ToolCallLimit { .. } => GateDenial::CgroupToolLimit,
                    other => GateDenial::CgroupUnavailable(other.to_string()),
                }
            })
    }
    /// Create a gate with the production baseline: enforcing MAC, profile-based
    /// allow rules, and a default-deny fallthrough. Tests that intentionally
    /// need permissive MAC must say so through [`Self::with_mac`].
    pub fn new(cgroups: std::sync::Arc<CgroupManager>) -> Self {
        let config = crate::config::Config::default();
        Self::with_mac(cgroups, config.mac_enforcing, config.mac_rules)
    }

    /// Create a gate with an explicit MAC configuration: `mac_enforcing` mode
    /// and an initial policy. The kernel uses this to wire operator MAC settings
    /// from config. Disabling enforcement is an explicit local escape hatch and
    /// emits a security warning.
    pub fn with_mac(
        cgroups: std::sync::Arc<CgroupManager>,
        mac_enforcing: bool,
        mac_rules: Vec<crate::mac::PolicyRule>,
    ) -> Self {
        if !mac_enforcing {
            tracing::warn!(
                target: "agentos::security",
                "constructing a syscall gate with MAC enforcement DISABLED"
            );
        }
        let default_cgroup = cgroups.root();
        let mut mac = MacEngine::new(mac_enforcing);
        mac.load_policy(mac_rules);
        Self {
            mac: Mutex::new(mac),
            cgroups,
            unconfined: false,
            default_cgroup,
            records: DashMap::new(),
            mutation_lock: std::sync::Mutex::new(()),
            tool_namespaces: DashMap::new(),
            approvals: DashMap::new(),
            next_pid: AtomicU64::new(1),
            next_cgroup_revision: AtomicU64::new(1),
            audit_sink: std::sync::Mutex::new(None),
            allowed: AtomicU64::new(0),
            denied_capability: AtomicU64::new(0),
            denied_mac: AtomicU64::new(0),
            denied_approval: AtomicU64::new(0),
            denied_cgroup: AtomicU64::new(0),
            denied_unknown: AtomicU64::new(0),
            denied_namespace: AtomicU64::new(0),
            audited: AtomicU64::new(0),
        }
    }

    /// Build an **explicitly ungoverned** gate: `check_tool_call` allows every
    /// call without consulting capabilities, MAC, namespaces, or quotas.
    ///
    /// This exists so that tests and non-OS contexts that genuinely don't want
    /// enforcement must *say so by name* — `SyscallGate::unconfined()` is greppable
    /// and unmistakable. It replaces the old footgun where an executor simply
    /// having no gate ran unconfined by default: enforcement is now mandatory by
    /// construction (the gate is a required executor dependency), and bypassing it
    /// is possible only through this one clearly-labelled door.
    #[cfg(any(test, doc))]
    pub fn unconfined() -> Self {
        tracing::warn!(
            target: "agentos::security",
            "constructing an UNCONFINED syscall gate; all tool security checks are bypassed"
        );
        let mut gate = Self::new(std::sync::Arc::new(CgroupManager::new()));
        gate.unconfined = true;
        gate
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

    /// Fallibly register an agent and its cgroup membership as one serialized
    /// mutation. No gate record is published unless membership succeeds.
    pub fn try_register_agent(
        &self,
        kid: uuid::Uuid,
        caps: CapabilitySet,
        cgroup: Option<CgroupId>,
    ) -> Result<Pid, GateMutationError> {
        self.try_register_agent_with_cgroup_policy(kid, caps, cgroup, false)
    }

    /// Register a kernel-owned agent whose durable quota hierarchy must remain
    /// intact for its lifetime.
    pub(crate) fn try_register_managed_agent(
        &self,
        kid: uuid::Uuid,
        caps: CapabilitySet,
        cgroup: CgroupId,
    ) -> Result<Pid, GateMutationError> {
        self.try_register_agent_with_cgroup_policy(kid, caps, Some(cgroup), true)
    }

    fn try_register_agent_with_cgroup_policy(
        &self,
        kid: uuid::Uuid,
        caps: CapabilitySet,
        cgroup: Option<CgroupId>,
        managed_cgroup: bool,
    ) -> Result<Pid, GateMutationError> {
        let _mutation = self.mutation_lock.lock().unwrap();
        if self.records.contains_key(&kid) {
            return Err(GateMutationError::AlreadyRegistered(kid));
        }
        let pid = self.next_pid.fetch_add(1, Ordering::SeqCst);
        let cg = cgroup.unwrap_or(self.default_cgroup);
        self.cgroups.add_agent(cg, pid)?;
        let cgroup_revision = self.next_cgroup_revision.fetch_add(1, Ordering::SeqCst);
        let (cgroup_changes, _) = watch::channel(cgroup_revision);
        self.records.insert(
            kid,
            GateRecord {
                pid,
                caps,
                cgroup: cg,
                managed_cgroup,
                cgroup_revision,
                cgroup_changes,
                accepting_tool_calls: true,
                namespaces: Vec::new(),
            },
        );
        Ok(pid)
    }

    /// Backwards-compatible registration. Invalid cgroup state fails closed
    /// instead of publishing an unenforced agent record.
    pub fn register_agent(
        &self,
        kid: uuid::Uuid,
        caps: CapabilitySet,
        cgroup: Option<CgroupId>,
    ) -> Pid {
        self.try_register_agent(kid, caps, cgroup)
            .expect("syscall-gate registration failed")
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

    pub fn try_unregister_agent(&self, kid: uuid::Uuid) -> Result<(), GateMutationError> {
        let _mutation = self.mutation_lock.lock().unwrap();
        let rec = self
            .records
            .get(&kid)
            .map(|record| record.clone())
            .ok_or(GateMutationError::UnknownAgent(kid))?;
        self.cgroups.try_remove_agent(rec.cgroup, rec.pid)?;
        self.records.remove(&kid);
        self.approvals.retain(|(agent, _, _, _), _| *agent != kid);
        Ok(())
    }

    /// Close the lifecycle admission gate and wait for already-admitted tool
    /// bindings to release their per-agent cgroup guards. Closing and tool-slot
    /// acquisition share `mutation_lock`, so no new guard can appear after the
    /// close becomes visible.
    pub(crate) async fn close_tool_admission_and_wait(
        &self,
        kid: uuid::Uuid,
    ) -> Result<(), GateMutationError> {
        let pid = {
            let _mutation = self.mutation_lock.lock().unwrap();
            let mut record = self
                .records
                .get_mut(&kid)
                .ok_or(GateMutationError::UnknownAgent(kid))?;
            record.accepting_tool_calls = false;
            record.pid
        };
        self.cgroups.wait_for_agent_tool_calls(pid).await;
        Ok(())
    }

    pub(crate) fn reopen_tool_admission(&self, kid: uuid::Uuid) -> Result<(), GateMutationError> {
        let _mutation = self.mutation_lock.lock().unwrap();
        let mut record = self
            .records
            .get_mut(&kid)
            .ok_or(GateMutationError::UnknownAgent(kid))?;
        record.accepting_tool_calls = true;
        Ok(())
    }

    /// Backwards-compatible fail-closed removal.
    pub fn unregister_agent(&self, kid: uuid::Uuid) {
        self.try_unregister_agent(kid)
            .expect("syscall-gate unregistration failed");
    }

    /// Grant one exact tool call for a local trusted operator/UI. The grant is
    /// bound to agent + tool + extracted resource and consumed only after
    /// capability and MAC checks succeed. Returning `false` means the agent is
    /// not currently registered.
    pub(crate) fn grant_tool_approval(
        &self,
        kid: uuid::Uuid,
        tool_name: impl Into<String>,
        resource: impl Into<String>,
        security: &crate::tools::ToolSecurity,
        approval: crate::tools::ApprovalPolicy,
    ) -> bool {
        if approval == crate::tools::ApprovalPolicy::None || !self.records.contains_key(&kid) {
            return false;
        }
        let Ok(contract) = serde_json::to_string(security) else {
            return false;
        };
        self.approvals
            .insert((kid, tool_name.into(), resource.into(), contract), approval);
        true
    }

    /// Look up the OS PID for a kernel UUID (useful for MAC labelling).
    pub fn pid_of(&self, kid: uuid::Uuid) -> Option<Pid> {
        self.records.get(&kid).map(|r| r.pid)
    }

    /// Snapshot the agent's stable root-to-leaf durable quota constraints.
    pub(crate) fn cgroup_quota_constraints(
        &self,
        kid: uuid::Uuid,
    ) -> Result<CgroupQuotaSnapshot, GateDenial> {
        let _mutation = self.mutation_lock.lock().unwrap();
        let record = self.records.get(&kid).ok_or(GateDenial::UnknownAgent)?;
        let constraints = self
            .cgroups
            .quota_constraints_for_agent(record.cgroup, record.pid)
            .map_err(|error| GateDenial::CgroupUnavailable(error.to_string()))?;
        Ok(CgroupQuotaSnapshot {
            constraints,
            membership_revision: record.cgroup_revision,
        })
    }

    /// Subscribe to this agent's cgroup-membership revision before taking a
    /// quota snapshot. The receiver's value is the exact membership revision,
    /// so subscribe-then-snapshot is race-safe: a move on either side of the
    /// snapshot is either incorporated or observed as a changed value.
    pub(crate) fn cgroup_quota_changes(
        &self,
        kid: uuid::Uuid,
    ) -> Result<watch::Receiver<u64>, GateDenial> {
        self.records
            .get(&kid)
            .map(|record| record.cgroup_changes.subscribe())
            .ok_or(GateDenial::UnknownAgent)
    }

    /// Verify that a previously reserved quota snapshot still describes the
    /// agent immediately before provider invocation.
    #[cfg(test)]
    pub(crate) fn verify_cgroup_quota_snapshot(
        &self,
        kid: uuid::Uuid,
        membership_revision: u64,
    ) -> Result<(), GateDenial> {
        let _mutation = self.mutation_lock.lock().unwrap();
        let record = self.records.get(&kid).ok_or(GateDenial::UnknownAgent)?;
        if record.cgroup_revision != membership_revision {
            return Err(GateDenial::CgroupMembershipChanged);
        }
        self.cgroups
            .quota_constraints_for_agent(record.cgroup, record.pid)
            .map(|_| ())
            .map_err(|error| GateDenial::CgroupUnavailable(error.to_string()))
    }

    /// Run the final synchronous provider-admission transition while cgroup
    /// membership mutations are excluded.
    ///
    /// A separate `verify` followed by marking the durable receipt in flight
    /// would leave a small reassignment race between those two operations.
    /// Keeping the mutation lock through the callback makes the snapshot check
    /// and caller-supplied linearization point one atomic handshake.
    pub(crate) fn with_verified_cgroup_quota_snapshot<T, E>(
        &self,
        kid: uuid::Uuid,
        membership_revision: u64,
        operation: impl FnOnce() -> Result<T, E>,
    ) -> Result<Result<T, E>, GateDenial> {
        let _mutation = self.mutation_lock.lock().unwrap();
        let record = self.records.get(&kid).ok_or(GateDenial::UnknownAgent)?;
        if record.cgroup_revision != membership_revision {
            return Err(GateDenial::CgroupMembershipChanged);
        }
        self.cgroups
            .quota_constraints_for_agent(record.cgroup, record.pid)
            .map_err(|error| GateDenial::CgroupUnavailable(error.to_string()))?;
        Ok(operation())
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
    /// Order: namespace visibility → capability → MAC → approval. Tool payload
    /// size is not provider token usage and is never charged here.
    /// Namespace runs first because the LLM should not learn anything about
    /// tools it cannot see (an attacker probing a denied resource gets ENOENT,
    /// not EACCES).
    ///
    /// This is an authorization-only compatibility/introspection precheck. It
    /// does not reserve a concurrent tool slot and is therefore not a safe
    /// execution entry point. Execute through
    /// [`ToolRegistry::authorize_and_acquire_call`](crate::tools::ToolRegistry::authorize_and_acquire_call).
    pub async fn check_tool_call(
        &self,
        kid: uuid::Uuid,
        tool_name: &str,
        resource: &str,
        _est_tokens: u64,
    ) -> Result<Pid, GateDenial> {
        if !self.unconfined {
            let Some(security) = default_security_catalog().get(tool_name) else {
                self.denied_unknown.fetch_add(1, Ordering::Relaxed);
                return Err(GateDenial::UnknownTool(tool_name.to_string()));
            };
            return self
                .check_tool_call_declared(kid, tool_name, resource, _est_tokens, security)
                .await;
        }

        let action = classify_tool(tool_name);
        let required_capabilities: Vec<u64> = action.required_cap.into_iter().collect();
        self.check_tool_call_contract(
            kid,
            ToolCallContract {
                tool_name,
                resource,
                action: action.action,
                required_capabilities: &required_capabilities,
                approval_policy: crate::tools::ApprovalPolicy::None,
                approval_contract: None,
            },
            true,
        )
        .await
        .map(|authorized| authorized.pid)
    }

    /// Enforce the validated security declaration carried by the live tool
    /// registry without acquiring a tool slot. This remains public for
    /// compatibility and policy introspection; execution paths must use
    /// [`ToolRegistry::authorize_and_acquire_call`](crate::tools::ToolRegistry::authorize_and_acquire_call)
    /// so admission and authorization are one operation.
    pub async fn check_tool_call_declared(
        &self,
        kid: uuid::Uuid,
        tool_name: &str,
        resource: &str,
        _est_tokens: u64,
        security: &crate::tools::ToolSecurity,
    ) -> Result<Pid, GateDenial> {
        let contract = serde_json::to_string(security)
            .expect("validated ToolSecurity serialization is infallible");
        self.check_tool_call_contract(
            kid,
            ToolCallContract {
                tool_name,
                resource,
                action: security.action.as_str(),
                required_capabilities: &security.required_capabilities,
                approval_policy: security.approval_policy,
                approval_contract: Some(&contract),
            },
            true,
        )
        .await
        .map(|authorized| authorized.pid)
    }

    /// Perform declaration-backed authorization and concurrent-tool admission
    /// as one counted gate verdict. Authorization failures increment their
    /// specific bucket; slot failures increment cgroup denial; only a fully
    /// admitted call increments `allowed`.
    pub(crate) async fn authorize_and_acquire_tool_call_declared(
        &self,
        kid: uuid::Uuid,
        tool_name: &str,
        resource: &str,
        security: &crate::tools::ToolSecurity,
    ) -> Result<(Pid, crate::cgroups::ToolCallGuard), GateDenial> {
        let approval_contract = serde_json::to_string(security)
            .expect("validated ToolSecurity serialization is infallible");
        let authorized = self
            .check_tool_call_contract(
                kid,
                ToolCallContract {
                    tool_name,
                    resource,
                    action: security.action.as_str(),
                    required_capabilities: &security.required_capabilities,
                    approval_policy: security.approval_policy,
                    approval_contract: Some(&approval_contract),
                },
                false,
            )
            .await?;
        let guard = if self.unconfined {
            self.cgroups
                .acquire_tool_call_checked(self.cgroups.root())
                .map_err(|error| GateDenial::CgroupUnavailable(error.to_string()))?
        } else {
            self.acquire_tool_call(kid)?
        };
        self.allowed.fetch_add(1, Ordering::Relaxed);
        if authorized.audited {
            self.audited.fetch_add(1, Ordering::Relaxed);
            self.emit_audit(AuditEvent {
                agent: kid,
                pid: authorized.pid,
                tool: tool_name.to_string(),
                action: security.action.as_str(),
                resource: resource.to_string(),
                decision: AuditDecision::Allowed,
            });
        }
        Ok((authorized.pid, guard))
    }

    async fn check_tool_call_contract(
        &self,
        kid: uuid::Uuid,
        contract: ToolCallContract<'_>,
        count_success: bool,
    ) -> Result<AuthorizedToolCall, GateDenial> {
        let ToolCallContract {
            tool_name,
            resource,
            action,
            required_capabilities,
            approval_policy,
            approval_contract,
        } = contract;
        // Explicitly-ungoverned gate (test / non-OS contexts only — see
        // `SyscallGate::unconfined`): allow everything without registration.
        if self.unconfined {
            if count_success {
                self.allowed.fetch_add(1, Ordering::Relaxed);
            }
            return Ok(AuthorizedToolCall {
                pid: 0,
                audited: false,
            });
        }
        let (pid, caps, cgroup, accepting_tool_calls, agent_namespaces) =
            match self.records.get(&kid) {
                Some(rec) => (
                    rec.pid,
                    rec.caps.clone(),
                    rec.cgroup,
                    rec.accepting_tool_calls,
                    rec.namespaces.clone(),
                ),
                None => {
                    self.denied_unknown.fetch_add(1, Ordering::Relaxed);
                    return Err(GateDenial::UnknownAgent);
                }
            };
        if !accepting_tool_calls {
            self.denied_cgroup.fetch_add(1, Ordering::Relaxed);
            return Err(GateDenial::CgroupUnavailable(
                "agent tool admission is closed for lifecycle cleanup".into(),
            ));
        }

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
        for &required in required_capabilities {
            if !caps.has(required) {
                self.denied_capability.fetch_add(1, Ordering::Relaxed);
                return Err(GateDenial::MissingCapability(required));
            }
        }

        // 2. MAC check.
        let mac_decision = {
            let mac = self.mac.lock().await;
            mac.check(pid, action, resource)
        };
        let audited = match mac_decision {
            MacDecision::Deny => {
                self.denied_mac.fetch_add(1, Ordering::Relaxed);
                self.emit_audit(AuditEvent {
                    agent: kid,
                    pid,
                    tool: tool_name.to_string(),
                    action,
                    resource: resource.to_string(),
                    decision: AuditDecision::Denied,
                });
                return Err(GateDenial::MacDeny {
                    action,
                    resource: resource.to_string(),
                });
            }
            // "Allow but log": let the call proceed, but record it. Without a
            // sink this is just a counter; with one wired it lands in the audit log.
            MacDecision::Audit => {
                if count_success {
                    self.audited.fetch_add(1, Ordering::Relaxed);
                    self.emit_audit(AuditEvent {
                        agent: kid,
                        pid,
                        tool: tool_name.to_string(),
                        action,
                        resource: resource.to_string(),
                        decision: AuditDecision::Allowed,
                    });
                }
                true
            }
            MacDecision::Allow => false,
        };

        // 3. Approval is exact and single-use. It is checked after capability
        // and MAC so a denied request cannot consume a legitimate grant.
        if approval_policy != crate::tools::ApprovalPolicy::None {
            let contract = approval_contract
                .expect("declared approval always carries its validated security contract");
            let key = (
                kid,
                tool_name.to_string(),
                resource.to_string(),
                contract.to_string(),
            );
            let approved = match self.approvals.entry(key) {
                dashmap::mapref::entry::Entry::Occupied(entry)
                    if (*entry.get()).satisfies(approval_policy) =>
                {
                    entry.remove();
                    true
                }
                _ => false,
            };
            if !approved {
                self.denied_approval.fetch_add(1, Ordering::Relaxed);
                self.emit_audit(AuditEvent {
                    agent: kid,
                    pid,
                    tool: tool_name.to_string(),
                    action,
                    resource: resource.to_string(),
                    decision: AuditDecision::Denied,
                });
                return Err(GateDenial::ApprovalRequired {
                    tool: tool_name.to_string(),
                    policy: approval_policy,
                });
            }
        }

        // 4. Validate, but do not charge, cgroup membership and hierarchy.
        // Provider admission consumes the returned stable constraints later.
        self.cgroups
            .quota_constraints_for_agent(cgroup, pid)
            .map_err(|error| {
                self.denied_cgroup.fetch_add(1, Ordering::Relaxed);
                GateDenial::CgroupUnavailable(error.to_string())
            })?;

        if count_success {
            self.allowed.fetch_add(1, Ordering::Relaxed);
        }
        Ok(AuthorizedToolCall { pid, audited })
    }

    /// Compatibility no-op. Provider usage is reserved/reconciled by the
    /// durable rate limiter; tool argument length must never burn that quota.
    pub fn record_tool_usage(&self, _kid: uuid::Uuid, _actual_tokens: u64) {}

    /// Atomically reassign a low-level gate registration's cgroup. A failed
    /// destination admission leaves the old membership and revision unchanged.
    ///
    /// Kernel-created agents are deliberately immutable here: moving them
    /// directly would drop their tenant/profile/private-agent durable quota
    /// scopes. A future managed reassignment API must rebuild and validate that
    /// complete hierarchy instead.
    pub fn try_set_cgroup(
        &self,
        kid: uuid::Uuid,
        cgroup: CgroupId,
    ) -> Result<(), GateMutationError> {
        let _mutation = self.mutation_lock.lock().unwrap();
        let current = self
            .records
            .get(&kid)
            .map(|record| record.clone())
            .ok_or(GateMutationError::UnknownAgent(kid))?;
        if current.cgroup == cgroup {
            self.cgroups
                .quota_constraints_for_agent(cgroup, current.pid)?;
            return Ok(());
        }
        if current.managed_cgroup {
            return Err(GateMutationError::ManagedCgroupImmutable(kid));
        }

        self.cgroups
            .try_move_agent(current.cgroup, cgroup, current.pid)?;
        let revision = self.next_cgroup_revision.fetch_add(1, Ordering::SeqCst);
        let mut record = self
            .records
            .get_mut(&kid)
            .expect("mutation lock keeps registered agent stable");
        record.cgroup = cgroup;
        record.cgroup_revision = revision;
        record.cgroup_changes.send_replace(revision);
        Ok(())
    }

    /// Backwards-compatible fail-closed reassignment.
    pub fn set_cgroup(&self, kid: uuid::Uuid, cgroup: CgroupId) {
        self.try_set_cgroup(kid, cgroup)
            .expect("syscall-gate cgroup reassignment failed");
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
            denied_approval: self.denied_approval.load(Ordering::Relaxed),
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
        let gate = std::sync::Arc::new(SyscallGate::with_mac(cgroups.clone(), false, Vec::new()));
        (gate, cgroups)
    }

    #[test]
    fn classify_known_tools() {
        assert_eq!(classify_tool("read_file").action, "read");
        assert_eq!(classify_tool("write_file").action, "write");
        assert_eq!(classify_tool("http_get").action, "net");
        assert_eq!(classify_tool("run_command").action, "exec");
        let custom = classify_tool("totally_custom_tool");
        assert_eq!(custom.action, "exec");
        assert_eq!(custom.required_cap, Some(CapabilitySet::CAP_EXEC));
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
    async fn default_gate_is_enforcing_and_unknown_tools_fail_closed() {
        let cgroups = std::sync::Arc::new(CgroupManager::new());
        let gate = SyscallGate::new(cgroups);
        let kid = uuid::Uuid::new_v4();
        gate.register_agent(kid, CapabilitySet::all(), None);

        assert!(matches!(
            gate.check_tool_call(kid, "read_file", "/tmp/x", 1).await,
            Err(GateDenial::MacDeny { .. })
        ));
        assert_eq!(
            gate.check_tool_call(kid, "not_registered", "/tmp/x", 1)
                .await,
            Err(GateDenial::UnknownTool("not_registered".into()))
        );
    }

    #[tokio::test]
    async fn declared_security_overrides_name_and_enforces_every_capability() {
        let (gate, _) = fresh_gate();
        let kid = uuid::Uuid::new_v4();
        let mut caps = CapabilitySet::none();
        caps.grant(CapabilitySet::CAP_EXEC);
        gate.register_agent(kid, caps, None);

        let security = crate::tools::ToolSecurity::constant(
            crate::tools::SecurityAction::Execute,
            "declared:test",
        )
        .with_capability(CapabilitySet::CAP_FILE_WRITE)
        .sandboxed();

        // The deliberately misleading name would be classified as a harmless
        // read by the compatibility API. The live declared path still requires
        // both EXEC and FILE_WRITE, proving name matching cannot weaken it.
        let denial = gate
            .check_tool_call_declared(kid, "read_file", "declared:test", 1, &security)
            .await
            .unwrap_err();
        assert_eq!(
            denial,
            GateDenial::MissingCapability(CapabilitySet::CAP_FILE_WRITE)
        );
    }

    #[tokio::test]
    async fn declared_approval_is_exact_local_and_single_use() {
        use crate::tools::{ApprovalPolicy, SecurityAction, ToolSecurity};

        let (gate, _) = fresh_gate();
        let kid = uuid::Uuid::new_v4();
        let mut caps = CapabilitySet::none();
        caps.grant(CapabilitySet::CAP_EXEC);
        gate.register_agent(kid, caps, None);
        let security = ToolSecurity::constant(SecurityAction::Execute, "command:deploy")
            .with_approval(ApprovalPolicy::User)
            .sandboxed();

        let denied = gate
            .check_tool_call_declared(kid, "deploy", "command:deploy", 1, &security)
            .await;
        assert!(matches!(denied, Err(GateDenial::ApprovalRequired { .. })));

        assert!(gate.grant_tool_approval(
            kid,
            "deploy",
            "command:deploy",
            &security,
            ApprovalPolicy::User
        ));
        assert!(gate
            .check_tool_call_declared(kid, "deploy", "command:other", 1, &security)
            .await
            .is_err());
        let changed_contract = security.clone().caller_namespace();
        assert!(matches!(
            gate.check_tool_call_declared(kid, "deploy", "command:deploy", 1, &changed_contract,)
                .await,
            Err(GateDenial::ApprovalRequired { .. })
        ));
        assert!(gate
            .check_tool_call_declared(kid, "deploy", "command:deploy", 1, &security)
            .await
            .is_ok());
        assert!(matches!(
            gate.check_tool_call_declared(kid, "deploy", "command:deploy", 1, &security)
                .await,
            Err(GateDenial::ApprovalRequired { .. })
        ));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn one_shot_approval_cannot_be_replayed_concurrently() {
        use crate::tools::{ApprovalPolicy, SecurityAction, ToolSecurity};

        let (gate, _) = fresh_gate();
        let kid = uuid::Uuid::new_v4();
        let mut caps = CapabilitySet::none();
        caps.grant(CapabilitySet::CAP_EXEC);
        gate.register_agent(kid, caps, None);
        let security = ToolSecurity::constant(SecurityAction::Execute, "command:deploy")
            .with_approval(ApprovalPolicy::User)
            .sandboxed();
        assert!(gate.grant_tool_approval(
            kid,
            "deploy",
            "command:deploy",
            &security,
            ApprovalPolicy::User
        ));

        let mut calls = Vec::new();
        for _ in 0..16 {
            let gate = gate.clone();
            let security = security.clone();
            calls.push(tokio::spawn(async move {
                gate.check_tool_call_declared(kid, "deploy", "command:deploy", 1, &security)
                    .await
            }));
        }
        let mut allowed = 0;
        let mut approval_denied = 0;
        for call in calls {
            match call.await.unwrap() {
                Ok(_) => allowed += 1,
                Err(GateDenial::ApprovalRequired { .. }) => approval_denied += 1,
                other => panic!("unexpected approval result: {other:?}"),
            }
        }
        assert_eq!(allowed, 1);
        assert_eq!(approval_denied, 15);
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
    async fn tool_payload_size_never_burns_provider_quota() {
        let (gate, cgroups) = fresh_gate();
        let cg = cgroups.create(
            "tight".into(),
            cgroups.root(),
            CgroupLimits {
                tokens_per_min: 1,
                ..Default::default()
            },
        );
        let kid = uuid::Uuid::new_v4();
        gate.register_agent(kid, CapabilitySet::all(), Some(cg));

        for payload_size in [1, 1_000_000, u64::MAX] {
            assert!(gate
                .check_tool_call(kid, "read_file", "/x", payload_size)
                .await
                .is_ok());
            gate.record_tool_usage(kid, payload_size);
        }
        let snapshot = gate.cgroup_quota_constraints(kid).unwrap();
        assert_eq!(snapshot.constraints.last().unwrap().token_limit, 1);
        assert_eq!(cgroups.get(cg).unwrap().usage.tokens_this_min, 0);
        assert_eq!(gate.stats().denied_cgroup, 0);
    }

    #[test]
    fn quota_snapshot_revision_detects_successful_move_only() {
        let (gate, cgroups) = fresh_gate();
        let first = cgroups.create("first".into(), cgroups.root(), CgroupLimits::default());
        let second = cgroups.create("second".into(), cgroups.root(), CgroupLimits::default());
        let kid = uuid::Uuid::new_v4();
        gate.try_register_agent(kid, CapabilitySet::all(), Some(first))
            .unwrap();
        let before = gate.cgroup_quota_constraints(kid).unwrap();
        gate.verify_cgroup_quota_snapshot(kid, before.membership_revision)
            .unwrap();

        gate.try_set_cgroup(kid, second).unwrap();
        assert_eq!(
            gate.verify_cgroup_quota_snapshot(kid, before.membership_revision),
            Err(GateDenial::CgroupMembershipChanged)
        );
        let after = gate.cgroup_quota_constraints(kid).unwrap();
        assert_ne!(after.membership_revision, before.membership_revision);
        assert_eq!(after.constraints.last().unwrap().scope_id, "/second");

        let full = cgroups.create(
            "full".into(),
            cgroups.root(),
            CgroupLimits {
                max_agents: 1,
                ..Default::default()
            },
        );
        gate.try_register_agent(uuid::Uuid::new_v4(), CapabilitySet::all(), Some(full))
            .unwrap();
        assert!(matches!(
            gate.try_set_cgroup(kid, full),
            Err(GateMutationError::Cgroup(CgroupError::MaxAgentsReached(_)))
        ));
        gate.verify_cgroup_quota_snapshot(kid, after.membership_revision)
            .unwrap();
        assert_eq!(
            gate.cgroup_quota_constraints(kid)
                .unwrap()
                .constraints
                .last()
                .unwrap()
                .scope_id,
            "/second"
        );
    }

    #[test]
    fn active_tool_guard_rejects_gate_move_without_membership_or_revision_change() {
        let (gate, cgroups) = fresh_gate();
        let source = cgroups.create(
            "move-source".into(),
            cgroups.root(),
            CgroupLimits {
                max_concurrent_tool_calls: 1,
                ..Default::default()
            },
        );
        let destination = cgroups.create(
            "move-destination".into(),
            cgroups.root(),
            CgroupLimits::default(),
        );
        let kid = uuid::Uuid::new_v4();
        gate.try_register_agent(kid, CapabilitySet::all(), Some(source))
            .unwrap();
        let before = gate.cgroup_quota_constraints(kid).unwrap();
        let guard = gate.acquire_tool_call(kid).unwrap();

        assert!(matches!(
            gate.try_set_cgroup(kid, destination),
            Err(GateMutationError::Cgroup(
                CgroupError::ActiveToolReservations(_)
            ))
        ));
        let unchanged = gate.cgroup_quota_constraints(kid).unwrap();
        assert_eq!(unchanged, before);
        assert_eq!(gate.agent_info(kid).unwrap().cgroup, source);
        assert!(matches!(
            gate.acquire_tool_call(kid),
            Err(GateDenial::CgroupToolLimit)
        ));

        drop(guard);
        gate.try_set_cgroup(kid, destination).unwrap();
        assert_eq!(gate.agent_info(kid).unwrap().cgroup, destination);
        assert_ne!(
            gate.cgroup_quota_constraints(kid)
                .unwrap()
                .membership_revision,
            before.membership_revision
        );
    }

    #[tokio::test]
    async fn combined_tool_admission_records_exactly_one_outcome_per_attempt() {
        let (gate, cgroups) = fresh_gate();
        let group = cgroups.create(
            "counted-admission".into(),
            cgroups.root(),
            CgroupLimits {
                max_concurrent_tool_calls: 1,
                ..Default::default()
            },
        );
        let kid = uuid::Uuid::new_v4();
        gate.try_register_agent(kid, CapabilitySet::all(), Some(group))
            .unwrap();
        let security = crate::tools::ToolRegistry::default_security_catalog()
            .remove("read_file")
            .unwrap();

        let (_, first) = gate
            .authorize_and_acquire_tool_call_declared(kid, "read_file", "/x", &security)
            .await
            .unwrap();
        assert_eq!(gate.stats().allowed, 1);
        assert!(matches!(
            gate.authorize_and_acquire_tool_call_declared(kid, "read_file", "/x", &security)
                .await,
            Err(GateDenial::CgroupToolLimit)
        ));
        let denied = gate.stats();
        assert_eq!(denied.allowed, 1);
        assert_eq!(denied.denied_cgroup, 1);

        drop(first);
        let (_, second) = gate
            .authorize_and_acquire_tool_call_declared(kid, "read_file", "/x", &security)
            .await
            .unwrap();
        drop(second);
        let final_stats = gate.stats();
        assert_eq!(final_stats.allowed, 2);
        assert_eq!(final_stats.denied_cgroup, 1);
    }

    #[tokio::test]
    async fn lifecycle_close_blocks_new_calls_and_waits_for_existing_guard() {
        let (gate, _) = fresh_gate();
        let kid = uuid::Uuid::new_v4();
        gate.try_register_agent(kid, CapabilitySet::all(), None)
            .unwrap();
        let guard = gate.acquire_tool_call(kid).unwrap();
        assert!(matches!(
            gate.try_unregister_agent(kid),
            Err(GateMutationError::Cgroup(
                CgroupError::ActiveToolReservations(_)
            ))
        ));

        let waiting_gate = gate.clone();
        let waiter =
            tokio::spawn(async move { waiting_gate.close_tool_admission_and_wait(kid).await });
        tokio::task::yield_now().await;
        assert!(matches!(
            gate.acquire_tool_call(kid),
            Err(GateDenial::CgroupUnavailable(_))
        ));
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        assert!(
            !waiter.is_finished(),
            "cleanup must wait while the admitted binding is active"
        );

        drop(guard);
        tokio::time::timeout(std::time::Duration::from_secs(1), waiter)
            .await
            .expect("final guard drop must wake cleanup")
            .unwrap()
            .unwrap();
        gate.try_unregister_agent(kid).unwrap();
    }

    #[tokio::test]
    async fn missing_membership_fails_closed_without_tool_slot_bump() {
        let (gate, cgroups) = fresh_gate();
        let group = cgroups.create("member".into(), cgroups.root(), CgroupLimits::default());
        let kid = uuid::Uuid::new_v4();
        let pid = gate.register_agent(kid, CapabilitySet::all(), Some(group));
        cgroups.try_remove_agent(group, pid).unwrap();

        assert!(matches!(
            gate.check_tool_call(kid, "read_file", "/x", 1).await,
            Err(GateDenial::CgroupUnavailable(_))
        ));
        assert!(matches!(
            gate.cgroup_quota_constraints(kid),
            Err(GateDenial::CgroupUnavailable(_))
        ));
        assert!(matches!(
            gate.acquire_tool_call(kid),
            Err(GateDenial::CgroupUnavailable(_))
        ));
        assert_eq!(cgroups.get(group).unwrap().usage.active_tool_calls, 0);
    }

    #[test]
    fn gate_concurrent_tool_slots_are_raii_scoped() {
        let (gate, cgroups) = fresh_gate();
        let group = cgroups.create(
            "tool-limit".into(),
            cgroups.root(),
            CgroupLimits {
                max_concurrent_tool_calls: 1,
                ..Default::default()
            },
        );
        let kid = uuid::Uuid::new_v4();
        gate.register_agent(kid, CapabilitySet::all(), Some(group));
        let first = gate.acquire_tool_call(kid).unwrap();
        assert!(matches!(
            gate.acquire_tool_call(kid),
            Err(GateDenial::CgroupToolLimit)
        ));
        drop(first);
        assert!(gate.acquire_tool_call(kid).is_ok());
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

        // run_command is an `exec` action → audit rule → approval → allowed
        // and logged.
        let security = default_security_catalog().get("run_command").unwrap();
        assert!(gate.grant_tool_approval(
            kid,
            "run_command",
            "/bin/ls",
            security,
            crate::tools::ApprovalPolicy::User,
        ));
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
    async fn audited_call_is_not_logged_as_allowed_when_slot_admission_fails() {
        use std::sync::{Arc, Mutex};

        struct RecordingSink(Mutex<Vec<AuditEvent>>);
        impl AuditSink for RecordingSink {
            fn audit(&self, event: AuditEvent) {
                self.0.lock().unwrap().push(event);
            }
        }

        let (gate, cgroups) = fresh_gate();
        let group = cgroups.create(
            "audited-limit".into(),
            cgroups.root(),
            CgroupLimits {
                max_concurrent_tool_calls: 1,
                ..Default::default()
            },
        );
        let sink = Arc::new(RecordingSink(Mutex::new(Vec::new())));
        gate.set_audit_sink(sink.clone());
        let kid = uuid::Uuid::new_v4();
        let pid = gate.register_agent(kid, CapabilitySet::all(), Some(group));
        {
            let mut mac = gate.mac.lock().await;
            mac.set_enforcing(true);
            mac.label_agent(pid, "watched".into());
            mac.load_policy(vec![PolicyRule {
                subject: "watched".into(),
                action: "read".into(),
                object: "*".into(),
                decision: "audit".into(),
            }]);
        }
        let occupied = gate.acquire_tool_call(kid).unwrap();
        let security = default_security_catalog().get("read_file").unwrap();

        assert!(matches!(
            gate.authorize_and_acquire_tool_call_declared(kid, "read_file", "/x", security)
                .await,
            Err(GateDenial::CgroupToolLimit)
        ));
        let stats = gate.stats();
        assert_eq!(stats.allowed, 0);
        assert_eq!(stats.audited, 0);
        assert_eq!(stats.denied_cgroup, 1);
        assert!(sink.0.lock().unwrap().is_empty());
        drop(occupied);
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

    // A real gate denies an unregistered agent (no silent allow). This is the
    // default posture that makes enforcement mandatory: absence of registration
    // is a denial, not a bypass.
    #[tokio::test]
    async fn default_gate_denies_unregistered_agent() {
        let (gate, _) = fresh_gate();
        let res = gate
            .check_tool_call(uuid::Uuid::new_v4(), "read_file", "/tmp/x", 10)
            .await;
        assert!(matches!(res, Err(GateDenial::UnknownAgent)));
    }

    // The explicit escape hatch allows everything, even for an unregistered
    // agent, and bumps the `allowed` counter — the one sanctioned ungoverned path.
    #[tokio::test]
    async fn unconfined_gate_allows_any_call() {
        let gate = SyscallGate::unconfined();
        // A privileged action for an agent that was never registered: allowed.
        let res = gate
            .check_tool_call(uuid::Uuid::new_v4(), "write_file", "/etc/passwd", 10)
            .await;
        assert_eq!(res, Ok(0));
        assert_eq!(gate.stats().allowed, 1);
        assert_eq!(gate.stats().denied_unknown, 0);

        let security = default_security_catalog().get("write_file").unwrap();
        let (_, guard) = gate
            .authorize_and_acquire_tool_call_declared(
                uuid::Uuid::new_v4(),
                "write_file",
                "/etc/passwd",
                security,
            )
            .await
            .expect("combined unconfined admission must not require registration");
        drop(guard);
        assert_eq!(gate.stats().allowed, 2);
    }
}
