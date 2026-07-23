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
    /// Capabilities, namespaces, cgroup/lifecycle state, tool visibility, or the
    /// registered PID changed between policy evaluation and final tool-slot
    /// admission. The caller must retry authorization from a fresh snapshot.
    AuthorizationStateChanged,
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
            GateDenial::AuthorizationStateChanged => {
                "authorization state changed during tool admission (EAGAIN)".to_string()
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
    pending_approval: Option<(ApprovalKey, crate::tools::ApprovalPolicy)>,
    snapshot: Option<ToolAuthorizationSnapshot>,
}

type ApprovalKey = (uuid::Uuid, u64, String, String, String);

#[derive(Debug, Clone, PartialEq, Eq)]
struct AgentAuthorizationSnapshot {
    pid: Pid,
    caps: CapabilitySet,
    cgroup: CgroupId,
    cgroup_revision: u64,
    accepting_tool_calls: bool,
    namespaces: Vec<NamespaceId>,
    registration_revision: u64,
    authorization_revision: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ToolNamespaceState {
    namespace: Option<NamespaceId>,
    revision: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ToolAuthorizationSnapshot {
    agent: AgentAuthorizationSnapshot,
    tool_namespace: ToolNamespaceState,
    mac_revision: u64,
}

#[cfg(test)]
#[derive(Clone)]
struct ApprovalGrantHook {
    entered: std::sync::Arc<std::sync::Barrier>,
    release: std::sync::Arc<std::sync::Barrier>,
}

#[cfg(test)]
#[derive(Clone)]
struct MacCheckedHook {
    entered: tokio::sync::mpsc::UnboundedSender<()>,
    release: std::sync::Arc<tokio::sync::Notify>,
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
    /// Immutable registration generation. Unlike the mutable authorization
    /// generation below, this binds approvals to one UUID→PID lifetime and
    /// prevents unregister/re-register ABA from inheriting a stale grant.
    registration_revision: u64,
    accepting_tool_calls: bool,
    /// Namespaces this agent is a member of. A tool registered in any of these
    /// namespaces is visible. Tools without a namespace are visible to everyone.
    namespaces: Vec<NamespaceId>,
    /// Monotonic generation for capability, namespace, and lifecycle-admission
    /// mutations. Exact field comparison catches mismatches; this generation
    /// additionally catches change-then-restore ABA.
    authorization_revision: u64,
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
    /// Opaque SHA-256 identity of the targeted path/url/command. Authorization
    /// still compares the raw target, but audit sinks never receive it.
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
    /// Mutable MAC state is private so every production mutation must advance
    /// `mac_revision`; otherwise a policy/label/enforcing change could race the
    /// final tool-slot admission and leave an old allow verdict usable.
    mac: Mutex<MacEngine>,
    mac_revision: AtomicU64,
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
    /// Global generation for tool namespace assignments. This intentionally
    /// makes an unrelated retag conservatively stale an in-flight call, avoiding
    /// unbounded per-tool tombstones while still detecting tag→global→same-tag
    /// ABA for removed dynamic tool names.
    tool_namespace_revision: AtomicU64,
    /// Exact, single-use local approvals keyed by
    /// (agent, registration generation, tool, opaque resource digest, exact
    /// contract identity/digest).
    /// No wire/package/MCP deserialization path can populate this map.
    approvals: DashMap<ApprovalKey, crate::tools::ApprovalPolicy>,
    /// Monotonic PID allocator (starts at 1 so 0 stays reserved for "kernel").
    next_pid: AtomicU64,
    /// Global monotonic cgroup-membership revision allocator. Global ordering
    /// prevents unregister/re-register ABA for the same kernel UUID.
    next_cgroup_revision: AtomicU64,
    /// Global allocator for per-agent and per-tool authorization generations.
    /// Values are stored on the affected object, so unrelated mutations do not
    /// invalidate an in-flight authorization snapshot.
    next_authorization_revision: AtomicU64,
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
    #[cfg(test)]
    authorization_snapshot_hook: std::sync::Mutex<Option<tokio::sync::mpsc::UnboundedSender<()>>>,
    #[cfg(test)]
    approval_grant_hook: std::sync::Mutex<Option<ApprovalGrantHook>>,
    #[cfg(test)]
    mac_checked_hook: std::sync::Mutex<Option<MacCheckedHook>>,
}

impl SyscallGate {
    fn tool_namespace_state(&self, tool_name: &str) -> ToolNamespaceState {
        ToolNamespaceState {
            namespace: self.tool_namespaces.get(tool_name).map(|state| *state),
            revision: self.tool_namespace_revision.load(Ordering::SeqCst),
        }
    }

    /// Capture one coherent authorization snapshot while relevant mutations are
    /// excluded by `mutation_lock`.
    fn authorization_snapshot_locked(
        &self,
        kid: uuid::Uuid,
        tool_name: &str,
    ) -> Result<ToolAuthorizationSnapshot, GateDenial> {
        let record = self.records.get(&kid).ok_or(GateDenial::UnknownAgent)?;
        Ok(ToolAuthorizationSnapshot {
            agent: AgentAuthorizationSnapshot {
                pid: record.pid,
                caps: record.caps.clone(),
                cgroup: record.cgroup,
                cgroup_revision: record.cgroup_revision,
                accepting_tool_calls: record.accepting_tool_calls,
                namespaces: record.namespaces.clone(),
                registration_revision: record.registration_revision,
                authorization_revision: record.authorization_revision,
            },
            tool_namespace: self.tool_namespace_state(tool_name),
            mac_revision: self.mac_revision.load(Ordering::SeqCst),
        })
    }

    fn acquire_tool_call_for_record(
        &self,
        cgroup: CgroupId,
        pid: Pid,
        accepting_tool_calls: bool,
    ) -> Result<crate::cgroups::ToolCallGuard, GateDenial> {
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

    /// Revalidate the exact pre-MAC agent/tool snapshot and reserve the cgroup
    /// slot at the same mutation boundary. Any intervening mutation, including a
    /// change-then-restore or UUID unregister/re-register ABA, fails closed.
    ///
    /// MAC mutators do not take `mutation_lock`: they advance `mac_revision`
    /// before changing protected state. This final sequentially-consistent
    /// revision read is their authorization linearization boundary. An update
    /// ordered before it makes the snapshot stale; an update ordered after it
    /// begins after this call's final admission.
    fn acquire_tool_call_if_unchanged(
        &self,
        kid: uuid::Uuid,
        tool_name: &str,
        expected: &ToolAuthorizationSnapshot,
    ) -> Result<crate::cgroups::ToolCallGuard, GateDenial> {
        let _mutation = self.mutation_lock.lock().unwrap();
        let current = self.authorization_snapshot_locked(kid, tool_name)?;
        if current != *expected {
            return Err(GateDenial::AuthorizationStateChanged);
        }
        self.acquire_tool_call_for_record(
            current.agent.cgroup,
            current.agent.pid,
            current.agent.accepting_tool_calls,
        )
    }

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
        self.acquire_tool_call_for_record(cgroup, pid, accepting_tool_calls)
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
            mac_revision: AtomicU64::new(1),
            cgroups,
            unconfined: false,
            default_cgroup,
            records: DashMap::new(),
            mutation_lock: std::sync::Mutex::new(()),
            tool_namespaces: DashMap::new(),
            tool_namespace_revision: AtomicU64::new(1),
            approvals: DashMap::new(),
            next_pid: AtomicU64::new(1),
            next_cgroup_revision: AtomicU64::new(1),
            next_authorization_revision: AtomicU64::new(1),
            audit_sink: std::sync::Mutex::new(None),
            allowed: AtomicU64::new(0),
            denied_capability: AtomicU64::new(0),
            denied_mac: AtomicU64::new(0),
            denied_approval: AtomicU64::new(0),
            denied_cgroup: AtomicU64::new(0),
            denied_unknown: AtomicU64::new(0),
            denied_namespace: AtomicU64::new(0),
            audited: AtomicU64::new(0),
            #[cfg(test)]
            authorization_snapshot_hook: std::sync::Mutex::new(None),
            #[cfg(test)]
            approval_grant_hook: std::sync::Mutex::new(None),
            #[cfg(test)]
            mac_checked_hook: std::sync::Mutex::new(None),
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

    /// Return whether mandatory access control is currently enforcing.
    pub async fn mac_is_enforcing(&self) -> bool {
        self.mac.lock().await.is_enforcing()
    }

    /// Replace the live MAC policy and invalidate every authorization snapshot
    /// evaluated against the previous rules. The revision is advanced before
    /// mutating state, making that increment the linearization point: a final
    /// admission that read the old revision is ordered before this update, and
    /// every later admission observes either a mismatch or the new policy.
    pub async fn load_mac_policy(&self, rules: Vec<crate::mac::PolicyRule>) {
        let mut mac = self.mac.lock().await;
        self.mac_revision.fetch_add(1, Ordering::SeqCst);
        mac.load_policy(rules);
    }

    /// Parse and replace the live MAC policy while preserving the previous
    /// rules on malformed input. Successful replacement invalidates all
    /// authorization snapshots evaluated against the old policy.
    pub async fn load_mac_policy_toml(&self, source: &str) -> Result<(), String> {
        // Parse into a temporary engine first so invalid input cannot advance
        // the live generation or partially change enforcement state.
        let mut parsed = MacEngine::new(true);
        parsed.load_policy_toml(source)?;
        let mut mac = self.mac.lock().await;
        self.mac_revision.fetch_add(1, Ordering::SeqCst);
        mac.load_policy_toml(source)
    }

    /// Change an agent's MAC subject label and invalidate in-flight verdicts.
    pub async fn label_mac_agent(&self, pid: Pid, label: crate::mac::SecurityLabel) {
        let mut mac = self.mac.lock().await;
        self.mac_revision.fetch_add(1, Ordering::SeqCst);
        mac.label_agent(pid, label);
    }

    /// Change a resource's MAC object label and invalidate in-flight verdicts.
    pub async fn label_mac_resource(&self, resource: String, label: crate::mac::SecurityLabel) {
        let mut mac = self.mac.lock().await;
        self.mac_revision.fetch_add(1, Ordering::SeqCst);
        mac.label_resource(resource, label);
    }

    /// Toggle MAC enforcement and invalidate in-flight verdicts evaluated
    /// under the previous mode.
    pub async fn set_mac_enforcing(&self, enforcing: bool) {
        if !enforcing {
            tracing::warn!(
                target: "agentos::security",
                "disabling MAC enforcement on a live syscall gate"
            );
        }
        let mut mac = self.mac.lock().await;
        self.mac_revision.fetch_add(1, Ordering::SeqCst);
        mac.set_enforcing(enforcing);
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
        let authorization_revision = self
            .next_authorization_revision
            .fetch_add(1, Ordering::SeqCst);
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
                registration_revision: authorization_revision,
                accepting_tool_calls: true,
                namespaces: Vec::new(),
                authorization_revision,
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
        let _mutation = self.mutation_lock.lock().unwrap();
        self.tool_namespaces.insert(tool_name.into(), ns);
        self.tool_namespace_revision.fetch_add(1, Ordering::SeqCst);
    }

    /// Remove a tool's namespace tag — makes it global again.
    pub fn unregister_tool_namespace(&self, tool_name: &str) {
        let _mutation = self.mutation_lock.lock().unwrap();
        self.tool_namespaces.remove(tool_name);
        self.tool_namespace_revision.fetch_add(1, Ordering::SeqCst);
    }

    /// Return whether a registered agent may discover a tool declaration.
    ///
    /// Namespace-scoped tools must be hidden before an LLM or remote client can
    /// select them, not merely rejected at execution time. Unknown agents fail
    /// closed. The explicitly unconfined test gate remains fully visible.
    pub fn tool_visible_to_agent(&self, kid: uuid::Uuid, tool_name: &str) -> bool {
        if self.unconfined {
            return true;
        }
        let Some(record) = self.records.get(&kid) else {
            return false;
        };
        self.tool_namespaces
            .get(tool_name)
            .is_none_or(|namespace| record.namespaces.contains(namespace.value()))
    }

    /// Return whether a tool is global or belongs to the supplied tool
    /// namespace. This supports fail-closed package preflight before an agent
    /// record exists, without exposing the namespace assignment itself.
    pub fn tool_visible_in_namespace(&self, tool_name: &str, namespace: NamespaceId) -> bool {
        self.tool_namespaces
            .get(tool_name)
            .is_none_or(|tool_namespace| *tool_namespace.value() == namespace)
    }

    /// Replace an agent's namespace memberships.
    pub fn set_agent_namespaces(&self, kid: uuid::Uuid, namespaces: Vec<NamespaceId>) {
        let _mutation = self.mutation_lock.lock().unwrap();
        if let Some(mut rec) = self.records.get_mut(&kid) {
            rec.namespaces = namespaces;
            rec.authorization_revision = self
                .next_authorization_revision
                .fetch_add(1, Ordering::SeqCst);
        }
    }

    /// Add a namespace to an agent's existing memberships.
    pub fn add_agent_namespace(&self, kid: uuid::Uuid, ns: NamespaceId) {
        let _mutation = self.mutation_lock.lock().unwrap();
        if let Some(mut rec) = self.records.get_mut(&kid) {
            if !rec.namespaces.contains(&ns) {
                rec.namespaces.push(ns);
                rec.authorization_revision = self
                    .next_authorization_revision
                    .fetch_add(1, Ordering::SeqCst);
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
        self.approvals
            .retain(|(agent, _, _, _, _), _| *agent != kid);
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
            record.authorization_revision = self
                .next_authorization_revision
                .fetch_add(1, Ordering::SeqCst);
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
        record.authorization_revision = self
            .next_authorization_revision
            .fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    /// Backwards-compatible fail-closed removal.
    pub fn unregister_agent(&self, kid: uuid::Uuid) {
        self.try_unregister_agent(kid)
            .expect("syscall-gate unregistration failed");
    }

    /// Grant one exact tool call for a local trusted operator/UI. The grant is
    /// bound to agent + tool + extracted resource and consumed only after
    /// capability, MAC, cgroup hierarchy, and live slot admission all succeed.
    /// Returning `false` means the agent is not currently registered.
    #[cfg(test)]
    pub(crate) fn grant_tool_approval(
        &self,
        kid: uuid::Uuid,
        tool_name: impl Into<String>,
        resource: impl Into<String>,
        security: &crate::tools::ToolSecurity,
        approval: crate::tools::ApprovalPolicy,
    ) -> bool {
        let Ok(contract) = serde_json::to_string(security) else {
            return false;
        };
        self.grant_tool_approval_contract(kid, tool_name, resource, &contract, approval)
    }

    /// Grant approval for a fully materialized registry contract identity. Live
    /// registry callers pass a SHA-256 digest that covers provider class,
    /// operation, parameters, and `ToolSecurity`, so secrets are not retained
    /// in this map and a registry swap cannot reuse an older approval.
    pub(crate) fn grant_tool_approval_contract(
        &self,
        kid: uuid::Uuid,
        tool_name: impl Into<String>,
        resource: impl Into<String>,
        contract: &str,
        approval: crate::tools::ApprovalPolicy,
    ) -> bool {
        if approval == crate::tools::ApprovalPolicy::None {
            return false;
        }
        let _mutation = self.mutation_lock.lock().unwrap();
        let Some(registration_revision) = self
            .records
            .get(&kid)
            .map(|record| record.registration_revision)
        else {
            return false;
        };
        #[cfg(test)]
        if let Some(hook) = self.approval_grant_hook.lock().unwrap().clone() {
            hook.entered.wait();
            hook.release.wait();
        }
        self.approvals.insert(
            (
                kid,
                registration_revision,
                tool_name.into(),
                crate::resources::opaque_identity(resource.into().as_bytes()),
                contract.to_string(),
            ),
            approval,
        );
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
    #[cfg(test)]
    pub(crate) async fn authorize_and_acquire_tool_call_declared(
        &self,
        kid: uuid::Uuid,
        tool_name: &str,
        resource: &str,
        security: &crate::tools::ToolSecurity,
    ) -> Result<(Pid, crate::cgroups::ToolCallGuard), GateDenial> {
        let approval_contract = serde_json::to_string(security)
            .expect("validated ToolSecurity serialization is infallible");
        let (pid, guard, _) = self
            .authorize_and_acquire_tool_call_declared_contract(
                kid,
                tool_name,
                resource,
                security,
                &approval_contract,
                "legacy-test-request",
            )
            .await?;
        Ok((pid, guard))
    }

    /// Declaration-backed admission using an exact, caller-prepared provider
    /// contract for approval matching.
    pub(crate) async fn authorize_and_acquire_tool_call_declared_contract(
        &self,
        kid: uuid::Uuid,
        tool_name: &str,
        resource: &str,
        security: &crate::tools::ToolSecurity,
        approval_contract: &str,
        request_identity: &str,
    ) -> Result<
        (
            Pid,
            crate::cgroups::ToolCallGuard,
            crate::resources::GateAdmissionProof,
        ),
        GateDenial,
    > {
        let authorized = self
            .check_tool_call_contract(
                kid,
                ToolCallContract {
                    tool_name,
                    resource,
                    action: security.action.as_str(),
                    required_capabilities: &security.required_capabilities,
                    approval_policy: security.approval_policy,
                    approval_contract: Some(approval_contract),
                },
                false,
            )
            .await?;
        let guard = if self.unconfined {
            self.cgroups
                .acquire_tool_call_checked(self.cgroups.root())
                .map_err(|error| GateDenial::CgroupUnavailable(error.to_string()))?
        } else {
            self.acquire_tool_call_if_unchanged(
                kid,
                tool_name,
                authorized
                    .snapshot
                    .as_ref()
                    .expect("governed authorization carries a state snapshot"),
            )?
        };
        let approval_satisfied = if self.unconfined {
            true
        } else if let Some((key, required)) = authorized.pending_approval {
            let consumed = match self.approvals.entry(key) {
                dashmap::mapref::entry::Entry::Occupied(entry)
                    if (*entry.get()).satisfies(required) =>
                {
                    entry.remove();
                    true
                }
                _ => false,
            };
            if !consumed {
                self.denied_approval.fetch_add(1, Ordering::Relaxed);
                self.emit_audit(AuditEvent {
                    agent: kid,
                    pid: authorized.pid,
                    tool: tool_name.to_string(),
                    action: security.action.as_str(),
                    resource: crate::resources::opaque_identity(resource.as_bytes()),
                    decision: AuditDecision::Denied,
                });
                return Err(GateDenial::ApprovalRequired {
                    tool: tool_name.to_string(),
                    policy: required,
                });
            }
            true
        } else {
            false
        };
        self.allowed.fetch_add(1, Ordering::Relaxed);
        if authorized.audited {
            self.audited.fetch_add(1, Ordering::Relaxed);
            self.emit_audit(AuditEvent {
                agent: kid,
                pid: authorized.pid,
                tool: tool_name.to_string(),
                action: security.action.as_str(),
                resource: crate::resources::opaque_identity(resource.as_bytes()),
                decision: AuditDecision::Allowed,
            });
        }
        let proof = crate::resources::GateAdmissionProof::new(
            kid,
            request_identity.to_string(),
            approval_satisfied,
        );
        Ok((authorized.pid, guard, proof))
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
                pending_approval: None,
                snapshot: None,
            });
        }
        let snapshot = {
            let _mutation = self.mutation_lock.lock().unwrap();
            match self.authorization_snapshot_locked(kid, tool_name) {
                Ok(snapshot) => snapshot,
                Err(GateDenial::UnknownAgent) => {
                    self.denied_unknown.fetch_add(1, Ordering::Relaxed);
                    return Err(GateDenial::UnknownAgent);
                }
                Err(other) => return Err(other),
            }
        };
        let agent = &snapshot.agent;
        if !agent.accepting_tool_calls {
            self.denied_cgroup.fetch_add(1, Ordering::Relaxed);
            return Err(GateDenial::CgroupUnavailable(
                "agent tool admission is closed for lifecycle cleanup".into(),
            ));
        }

        // 0. Namespace visibility. If the tool is tagged with a namespace,
        //    the agent must be a member of it. Untagged tools are global.
        if let Some(tool_ns) = snapshot.tool_namespace.namespace {
            if !agent.namespaces.contains(&tool_ns) {
                self.denied_namespace.fetch_add(1, Ordering::Relaxed);
                return Err(GateDenial::NotInNamespace {
                    tool: tool_name.to_string(),
                    namespace: tool_ns,
                });
            }
        }

        // 1. Capability check.
        for &required in required_capabilities {
            if !agent.caps.has(required) {
                self.denied_capability.fetch_add(1, Ordering::Relaxed);
                return Err(GateDenial::MissingCapability(required));
            }
        }

        // 2. MAC check.
        #[cfg(test)]
        if let Some(hook) = self.authorization_snapshot_hook.lock().unwrap().clone() {
            let _ = hook.send(());
        }
        let mac_decision = {
            let mac = self.mac.lock().await;
            mac.check(agent.pid, action, resource)
        };
        let audited = match mac_decision {
            MacDecision::Deny => {
                let resource_identity = crate::resources::opaque_identity(resource.as_bytes());
                self.denied_mac.fetch_add(1, Ordering::Relaxed);
                self.emit_audit(AuditEvent {
                    agent: kid,
                    pid: agent.pid,
                    tool: tool_name.to_string(),
                    action,
                    resource: resource_identity.clone(),
                    decision: AuditDecision::Denied,
                });
                return Err(GateDenial::MacDeny {
                    action,
                    resource: resource_identity,
                });
            }
            // "Allow but log": let the call proceed, but record it. Without a
            // sink this is just a counter; with one wired it lands in the audit log.
            MacDecision::Audit => {
                if count_success {
                    self.audited.fetch_add(1, Ordering::Relaxed);
                    self.emit_audit(AuditEvent {
                        agent: kid,
                        pid: agent.pid,
                        tool: tool_name.to_string(),
                        action,
                        resource: crate::resources::opaque_identity(resource.as_bytes()),
                        decision: AuditDecision::Allowed,
                    });
                }
                true
            }
            MacDecision::Allow => false,
        };

        #[cfg(test)]
        let mac_checked_hook = { self.mac_checked_hook.lock().unwrap().clone() };
        #[cfg(test)]
        if let Some(hook) = mac_checked_hook {
            let _ = hook.entered.send(());
            hook.release.notified().await;
        }

        // 3. Approval is exact and single-use. Presence is checked after
        // capability and MAC, but the grant is not consumed until hierarchy
        // validation and live cgroup slot acquisition both succeed.
        let pending_approval = if approval_policy != crate::tools::ApprovalPolicy::None {
            let contract = approval_contract
                .expect("declared approval always carries its validated security contract");
            let key = (
                kid,
                agent.registration_revision,
                tool_name.to_string(),
                crate::resources::opaque_identity(resource.as_bytes()),
                contract.to_string(),
            );
            let approved = self
                .approvals
                .get(&key)
                .is_some_and(|entry| (*entry).satisfies(approval_policy));
            if !approved {
                self.denied_approval.fetch_add(1, Ordering::Relaxed);
                self.emit_audit(AuditEvent {
                    agent: kid,
                    pid: agent.pid,
                    tool: tool_name.to_string(),
                    action,
                    resource: crate::resources::opaque_identity(resource.as_bytes()),
                    decision: AuditDecision::Denied,
                });
                return Err(GateDenial::ApprovalRequired {
                    tool: tool_name.to_string(),
                    policy: approval_policy,
                });
            }
            Some((key, approval_policy))
        } else {
            None
        };

        // 4. Authorization-only callers still need a live cgroup membership
        // check. Executing callers validate the exact snapshot and reserve their
        // slot atomically in `acquire_tool_call_if_unchanged`; checking the old
        // PID here first would obscure unregister/re-register ABA as a generic
        // hierarchy error.
        if count_success {
            self.cgroups
                .quota_constraints_for_agent(agent.cgroup, agent.pid)
                .map_err(|error| {
                    self.denied_cgroup.fetch_add(1, Ordering::Relaxed);
                    GateDenial::CgroupUnavailable(error.to_string())
                })?;
        }

        if count_success {
            self.allowed.fetch_add(1, Ordering::Relaxed);
        }
        Ok(AuthorizedToolCall {
            pid: agent.pid,
            audited,
            pending_approval,
            snapshot: Some(snapshot),
        })
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
        let _mutation = self.mutation_lock.lock().unwrap();
        if let Some(mut rec) = self.records.get_mut(&kid) {
            rec.caps = caps;
            rec.authorization_revision = self
                .next_authorization_revision
                .fetch_add(1, Ordering::SeqCst);
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

    fn install_authorization_snapshot_hook(
        gate: &SyscallGate,
    ) -> tokio::sync::mpsc::UnboundedReceiver<()> {
        let (sender, receiver) = tokio::sync::mpsc::unbounded_channel();
        *gate.authorization_snapshot_hook.lock().unwrap() = Some(sender);
        receiver
    }

    fn clear_authorization_snapshot_hook(gate: &SyscallGate) {
        *gate.authorization_snapshot_hook.lock().unwrap() = None;
    }

    fn install_mac_checked_hook(
        gate: &SyscallGate,
    ) -> (
        tokio::sync::mpsc::UnboundedReceiver<()>,
        std::sync::Arc<tokio::sync::Notify>,
    ) {
        let (entered, receiver) = tokio::sync::mpsc::unbounded_channel();
        let release = std::sync::Arc::new(tokio::sync::Notify::new());
        *gate.mac_checked_hook.lock().unwrap() = Some(MacCheckedHook {
            entered,
            release: release.clone(),
        });
        (receiver, release)
    }

    fn clear_mac_checked_hook(gate: &SyscallGate) {
        *gate.mac_checked_hook.lock().unwrap() = None;
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
            .authorize_and_acquire_tool_call_declared(kid, "deploy", "command:other", &security,)
            .await
            .is_err());
        let changed_contract = security.clone().caller_namespace();
        assert!(matches!(
            gate.authorize_and_acquire_tool_call_declared(
                kid,
                "deploy",
                "command:deploy",
                &changed_contract,
            )
            .await,
            Err(GateDenial::ApprovalRequired { .. })
        ));
        let (_, guard) = gate
            .authorize_and_acquire_tool_call_declared(kid, "deploy", "command:deploy", &security)
            .await
            .unwrap();
        drop(guard);
        assert!(matches!(
            gate.authorize_and_acquire_tool_call_declared(
                kid,
                "deploy",
                "command:deploy",
                &security,
            )
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
                gate.authorize_and_acquire_tool_call_declared(
                    kid,
                    "deploy",
                    "command:deploy",
                    &security,
                )
                .await
            }));
        }
        let mut allowed = 0;
        let mut approval_denied = 0;
        for call in calls {
            match call.await.unwrap() {
                Ok((_pid, _guard)) => allowed += 1,
                Err(GateDenial::ApprovalRequired { .. }) => approval_denied += 1,
                Err(other) => panic!("unexpected approval denial: {other:?}"),
            }
        }
        assert_eq!(allowed, 1);
        assert_eq!(approval_denied, 15);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn capability_revoke_during_mac_fails_stale_admission_without_consuming_approval() {
        use crate::tools::{ApprovalPolicy, SecurityAction, ToolSecurity};

        let (gate, cgroups) = fresh_gate();
        let kid = uuid::Uuid::new_v4();
        let mut granted_caps = CapabilitySet::none();
        granted_caps.grant(CapabilitySet::CAP_FILE_DELETE);
        gate.register_agent(kid, granted_caps.clone(), None);
        let security = ToolSecurity::constant(SecurityAction::Delete, "file:/tmp/stale")
            .with_capability(CapabilitySet::CAP_FILE_DELETE)
            .with_approval(ApprovalPolicy::User)
            .sandboxed();
        assert!(gate.grant_tool_approval(
            kid,
            "delete_stale",
            "file:/tmp/stale",
            &security,
            ApprovalPolicy::User,
        ));

        let mac_guard = gate.mac.lock().await;
        let mut snapshot_ready = install_authorization_snapshot_hook(&gate);
        let pending_gate = gate.clone();
        let pending_security = security.clone();
        let pending = tokio::spawn(async move {
            pending_gate
                .authorize_and_acquire_tool_call_declared(
                    kid,
                    "delete_stale",
                    "file:/tmp/stale",
                    &pending_security,
                )
                .await
        });
        snapshot_ready
            .recv()
            .await
            .expect("authorization must reach the blocked MAC boundary");

        gate.set_capabilities(kid, CapabilitySet::none());
        drop(mac_guard);
        assert!(matches!(
            pending.await.unwrap(),
            Err(GateDenial::AuthorizationStateChanged)
        ));
        assert_eq!(
            cgroups.get(cgroups.root()).unwrap().usage.active_tool_calls,
            0,
            "stale authorization must not reserve a tool slot"
        );

        clear_authorization_snapshot_hook(&gate);
        gate.set_capabilities(kid, granted_caps);
        let (_, guard) = gate
            .authorize_and_acquire_tool_call_declared(
                kid,
                "delete_stale",
                "file:/tmp/stale",
                &security,
            )
            .await
            .expect("stale-state failure must leave the one-shot approval unconsumed");
        drop(guard);
        assert!(gate.approvals.is_empty());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn mac_policy_aba_after_allow_fails_final_registry_admission() {
        let (gate, cgroups) = fresh_gate();
        let kid = uuid::Uuid::new_v4();
        gate.register_agent(kid, CapabilitySet::all(), None);
        gate.set_mac_enforcing(true).await;
        let allow = vec![PolicyRule {
            subject: "*".into(),
            action: "*".into(),
            object: "*".into(),
            decision: "allow".into(),
        }];
        gate.load_mac_policy(allow.clone()).await;
        let registry = std::sync::Arc::new(crate::tools::ToolRegistry::new());
        let (mut mac_checked, release) = install_mac_checked_hook(&gate);
        let pending_gate = gate.clone();
        let pending_registry = registry.clone();
        let pending = tokio::spawn(async move {
            pending_registry
                .authorize_and_acquire_call(
                    &pending_gate,
                    kid,
                    "read_file",
                    &serde_json::json!({"path": "/tmp/mac-policy-aba"}),
                )
                .await
        });
        mac_checked
            .recv()
            .await
            .expect("authorization must finish its original MAC allow");

        gate.load_mac_policy(vec![PolicyRule {
            subject: "*".into(),
            action: "*".into(),
            object: "*".into(),
            decision: "deny".into(),
        }])
        .await;
        gate.load_mac_policy(allow).await;
        release.notify_one();

        assert!(matches!(
            pending.await.unwrap(),
            Err(crate::tools::ToolAuthorizationError::Denied(
                GateDenial::AuthorizationStateChanged
            ))
        ));
        assert_eq!(
            cgroups.get(cgroups.root()).unwrap().usage.active_tool_calls,
            0
        );
        clear_mac_checked_hook(&gate);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn mac_agent_label_aba_after_allow_fails_final_registry_admission() {
        let (gate, cgroups) = fresh_gate();
        let kid = uuid::Uuid::new_v4();
        let pid = gate.register_agent(kid, CapabilitySet::all(), None);
        gate.set_mac_enforcing(true).await;
        gate.load_mac_policy(vec![
            PolicyRule {
                subject: "trusted".into(),
                action: "*".into(),
                object: "*".into(),
                decision: "allow".into(),
            },
            PolicyRule {
                subject: "*".into(),
                action: "*".into(),
                object: "*".into(),
                decision: "deny".into(),
            },
        ])
        .await;
        gate.label_mac_agent(pid, "trusted".into()).await;
        let registry = std::sync::Arc::new(crate::tools::ToolRegistry::new());
        let (mut mac_checked, release) = install_mac_checked_hook(&gate);
        let pending_gate = gate.clone();
        let pending_registry = registry.clone();
        let pending = tokio::spawn(async move {
            pending_registry
                .authorize_and_acquire_call(
                    &pending_gate,
                    kid,
                    "read_file",
                    &serde_json::json!({"path": "/tmp/mac-label-aba"}),
                )
                .await
        });
        mac_checked
            .recv()
            .await
            .expect("authorization must finish its original MAC allow");

        gate.label_mac_agent(pid, "blocked".into()).await;
        gate.label_mac_agent(pid, "trusted".into()).await;
        release.notify_one();

        assert!(matches!(
            pending.await.unwrap(),
            Err(crate::tools::ToolAuthorizationError::Denied(
                GateDenial::AuthorizationStateChanged
            ))
        ));
        assert_eq!(
            cgroups.get(cgroups.root()).unwrap().usage.active_tool_calls,
            0
        );
        clear_mac_checked_hook(&gate);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn mac_enforcing_aba_after_allow_fails_final_registry_admission() {
        let (gate, cgroups) = fresh_gate();
        let kid = uuid::Uuid::new_v4();
        gate.register_agent(kid, CapabilitySet::all(), None);
        gate.load_mac_policy(vec![PolicyRule {
            subject: "*".into(),
            action: "*".into(),
            object: "*".into(),
            decision: "deny".into(),
        }])
        .await;
        let registry = std::sync::Arc::new(crate::tools::ToolRegistry::new());
        let (mut mac_checked, release) = install_mac_checked_hook(&gate);
        let pending_gate = gate.clone();
        let pending_registry = registry.clone();
        let pending = tokio::spawn(async move {
            pending_registry
                .authorize_and_acquire_call(
                    &pending_gate,
                    kid,
                    "read_file",
                    &serde_json::json!({"path": "/tmp/mac-enforcing-aba"}),
                )
                .await
        });
        mac_checked
            .recv()
            .await
            .expect("permissive MAC must initially allow the call");

        gate.set_mac_enforcing(true).await;
        gate.set_mac_enforcing(false).await;
        release.notify_one();

        assert!(matches!(
            pending.await.unwrap(),
            Err(crate::tools::ToolAuthorizationError::Denied(
                GateDenial::AuthorizationStateChanged
            ))
        ));
        assert_eq!(
            cgroups.get(cgroups.root()).unwrap().usage.active_tool_calls,
            0
        );
        clear_mac_checked_hook(&gate);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn agent_namespace_revoke_during_mac_fails_public_registry_admission() {
        let (gate, cgroups) = fresh_gate();
        let kid = uuid::Uuid::new_v4();
        gate.register_agent(kid, CapabilitySet::all(), None);
        gate.set_agent_namespaces(kid, vec![41]);
        gate.register_tool_namespace("read_file", 41);
        let registry = std::sync::Arc::new(crate::tools::ToolRegistry::new());

        let mac_guard = gate.mac.lock().await;
        let mut snapshot_ready = install_authorization_snapshot_hook(&gate);
        let pending_gate = gate.clone();
        let pending_registry = registry.clone();
        let pending = tokio::spawn(async move {
            pending_registry
                .authorize_and_acquire_call(
                    &pending_gate,
                    kid,
                    "read_file",
                    &serde_json::json!({"path": "/tmp/stale"}),
                )
                .await
        });
        snapshot_ready
            .recv()
            .await
            .expect("authorization must reach the blocked MAC boundary");

        gate.set_agent_namespaces(kid, Vec::new());
        drop(mac_guard);
        assert!(matches!(
            pending.await.unwrap(),
            Err(crate::tools::ToolAuthorizationError::Denied(
                GateDenial::AuthorizationStateChanged
            ))
        ));
        assert_eq!(
            cgroups.get(cgroups.root()).unwrap().usage.active_tool_calls,
            0
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn tool_namespace_tag_aba_during_mac_fails_public_registry_admission() {
        let (gate, cgroups) = fresh_gate();
        let kid = uuid::Uuid::new_v4();
        gate.register_agent(kid, CapabilitySet::all(), None);
        gate.set_agent_namespaces(kid, vec![41]);
        gate.register_tool_namespace("read_file", 41);
        let registry = std::sync::Arc::new(crate::tools::ToolRegistry::new());

        let mac_guard = gate.mac.lock().await;
        let mut snapshot_ready = install_authorization_snapshot_hook(&gate);
        let pending_gate = gate.clone();
        let pending_registry = registry.clone();
        let pending = tokio::spawn(async move {
            pending_registry
                .authorize_and_acquire_call(
                    &pending_gate,
                    kid,
                    "read_file",
                    &serde_json::json!({"path": "/tmp/stale"}),
                )
                .await
        });
        snapshot_ready
            .recv()
            .await
            .expect("authorization must reach the blocked MAC boundary");

        // A global generation detects this tag→global→same-tag ABA without
        // retaining an unbounded tombstone for every dynamic tool name.
        gate.unregister_tool_namespace("read_file");
        gate.register_tool_namespace("read_file", 41);
        drop(mac_guard);
        assert!(matches!(
            pending.await.unwrap(),
            Err(crate::tools::ToolAuthorizationError::Denied(
                GateDenial::AuthorizationStateChanged
            ))
        ));
        assert_eq!(
            cgroups.get(cgroups.root()).unwrap().usage.active_tool_calls,
            0
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn unregister_reregister_same_uuid_during_mac_fails_public_registry_admission() {
        let (gate, cgroups) = fresh_gate();
        let kid = uuid::Uuid::new_v4();
        let original_pid = gate.register_agent(kid, CapabilitySet::all(), None);
        let registry = std::sync::Arc::new(crate::tools::ToolRegistry::new());

        let mac_guard = gate.mac.lock().await;
        let mut snapshot_ready = install_authorization_snapshot_hook(&gate);
        let pending_gate = gate.clone();
        let pending_registry = registry.clone();
        let pending = tokio::spawn(async move {
            pending_registry
                .authorize_and_acquire_call(
                    &pending_gate,
                    kid,
                    "read_file",
                    &serde_json::json!({"path": "/tmp/stale"}),
                )
                .await
        });
        snapshot_ready
            .recv()
            .await
            .expect("authorization must reach the blocked MAC boundary");

        gate.try_unregister_agent(kid).unwrap();
        let replacement_pid = gate.register_agent(kid, CapabilitySet::all(), None);
        assert_ne!(replacement_pid, original_pid);
        drop(mac_guard);
        assert!(matches!(
            pending.await.unwrap(),
            Err(crate::tools::ToolAuthorizationError::Denied(
                GateDenial::AuthorizationStateChanged
            ))
        ));
        assert_eq!(
            cgroups.get(cgroups.root()).unwrap().usage.active_tool_calls,
            0
        );
    }

    #[test]
    fn approval_grant_is_serialized_with_unregister_and_bound_to_registration() {
        use crate::tools::{ApprovalPolicy, SecurityAction, ToolSecurity};

        let (gate, _) = fresh_gate();
        let kid = uuid::Uuid::new_v4();
        gate.register_agent(kid, CapabilitySet::all(), None);
        let security = ToolSecurity::constant(SecurityAction::Execute, "command:deploy")
            .with_approval(ApprovalPolicy::User)
            .sandboxed();
        let entered = std::sync::Arc::new(std::sync::Barrier::new(2));
        let release = std::sync::Arc::new(std::sync::Barrier::new(2));
        *gate.approval_grant_hook.lock().unwrap() = Some(ApprovalGrantHook {
            entered: entered.clone(),
            release: release.clone(),
        });

        let grant_gate = gate.clone();
        let grant_security = security.clone();
        let grant = std::thread::spawn(move || {
            grant_gate.grant_tool_approval(
                kid,
                "deploy",
                "command:deploy",
                &grant_security,
                ApprovalPolicy::User,
            )
        });
        entered.wait();

        let replace_gate = gate.clone();
        let (replaced, replacement_done) = std::sync::mpsc::channel();
        let replacement = std::thread::spawn(move || {
            replace_gate.try_unregister_agent(kid).unwrap();
            replace_gate.register_agent(kid, CapabilitySet::all(), None);
            replaced.send(()).unwrap();
        });
        assert!(
            replacement_done
                .recv_timeout(std::time::Duration::from_millis(25))
                .is_err(),
            "unregister must wait while approval record-check and insert hold mutation_lock"
        );

        release.wait();
        assert!(grant.join().unwrap());
        replacement.join().unwrap();
        assert!(
            gate.approvals.is_empty(),
            "unregister must purge the old registration's newly inserted grant"
        );
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
        assert_eq!(
            events[0].resource,
            crate::resources::opaque_identity(b"/bin/ls")
        );
        assert!(!events[0].resource.contains("/bin/ls"));
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
    async fn cgroup_slot_failure_does_not_consume_one_shot_approval() {
        let (gate, cgroups) = fresh_gate();
        let group = cgroups.create(
            "approval-slot".into(),
            cgroups.root(),
            CgroupLimits {
                max_concurrent_tool_calls: 1,
                ..Default::default()
            },
        );
        let kid = uuid::Uuid::new_v4();
        gate.register_agent(kid, CapabilitySet::all(), Some(group));
        let occupied = gate.acquire_tool_call(kid).unwrap();
        let security = default_security_catalog().get("run_command").unwrap();
        assert!(gate.grant_tool_approval(
            kid,
            "run_command",
            "echo",
            security,
            crate::tools::ApprovalPolicy::User,
        ));

        assert!(matches!(
            gate.authorize_and_acquire_tool_call_declared(kid, "run_command", "echo", security)
                .await,
            Err(GateDenial::CgroupToolLimit)
        ));
        assert_eq!(
            gate.approvals.len(),
            1,
            "failed slot acquisition must leave the exact grant available"
        );

        drop(occupied);
        let (_pid, guard) = gate
            .authorize_and_acquire_tool_call_declared(kid, "run_command", "echo", security)
            .await
            .expect("the retained approval must authorize the retried admission");
        drop(guard);
        assert!(gate.approvals.is_empty());
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

        let secret = "https://x.example/private?credential=must-not-leak";
        let denial = gate.check_tool_call(kid, "http_get", secret, 5).await;
        let Err(GateDenial::MacDeny { resource, .. }) = denial else {
            panic!("MAC must deny the secret-bearing URL")
        };
        assert_eq!(
            resource,
            crate::resources::opaque_identity(secret.as_bytes())
        );
        assert!(!resource.contains("credential"));
        let events = sink.0.lock().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].decision, AuditDecision::Denied);
        assert_eq!(events[0].resource, resource);
        assert!(!events[0].resource.contains(secret));
    }

    #[tokio::test]
    async fn approval_keys_hash_secret_bearing_resources_but_match_raw_targets() {
        let (gate, _) = fresh_gate();
        let kid = uuid::Uuid::new_v4();
        gate.register_agent(kid, CapabilitySet::all(), None);
        let security = default_security_catalog().get("run_command").unwrap();
        let secret = "credential://operator-token-that-must-not-be-retained";

        assert!(gate.grant_tool_approval(
            kid,
            "run_command",
            secret,
            security,
            crate::tools::ApprovalPolicy::User,
        ));
        let stored = gate.approvals.iter().next().unwrap();
        assert_eq!(
            stored.key().3,
            crate::resources::opaque_identity(secret.as_bytes())
        );
        assert!(!stored.key().3.contains(secret));
        drop(stored);

        let (_pid, guard) = gate
            .authorize_and_acquire_tool_call_declared(kid, "run_command", secret, security)
            .await
            .expect("authorization must still compare the caller's raw target");
        drop(guard);
        assert!(gate.approvals.is_empty(), "approval remains single-use");
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
