//! Adversarial property/fuzz suite for the syscall gate.
//!
//! The syscall gate (`kernel::syscall_gate::SyscallGate::check_tool_call`) is
//! the load-bearing enforcement chokepoint of the OS: every tool call from the
//! executor and the syscall server passes through it. The hand-written contract
//! tests in `os_enforcement.rs` lock specific cases; this suite turns "we have
//! enforcement" into "we can *prove* enforcement" by asserting the gate's
//! invariants hold across a large, randomized input space.
//!
//! Strategy: for each generated case we build a *fresh* gate, register one
//! agent with a chosen capability profile / cgroup / namespace state, optionally
//! tag the tool to a namespace, and load a simple-but-real MAC policy. We then
//! compute the *expected* verdict from an **independent oracle** (re-deriving the
//! four-layer decision from the inputs, not from the gate) and compare it to the
//! gate's actual return value. The oracle deliberately mirrors the documented
//! ordering — namespace → capability → MAC → cgroup, first-failure-wins — so any
//! divergence (a bypass, a reordering, a miscounted denial) fails the property.
//!
//! Everything is deterministic: no wall-clock, no sleeps, fresh gate per case,
//! proptest's own seeded RNG drives the input space.

use std::sync::Arc;

use proptest::prelude::*;
use tokio::runtime::Runtime;

use kernel::agent_struct::CapabilitySet;
use kernel::cgroups::{CgroupLimits, CgroupManager};
use kernel::mac::{MacEngine, PolicyRule};
use kernel::namespaces::NamespaceId;
use kernel::syscall_gate::{classify_tool, GateDenial, GateStats, SyscallGate};

// ---------------------------------------------------------------------------
// Input model
// ---------------------------------------------------------------------------

/// A permission profile, mapped to an *exact* capability set the oracle knows.
/// We define the sets locally (rather than going through the kernel's
/// `caps_for_profile`) precisely so the oracle is an independent source of truth.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Profile {
    /// No capabilities at all (stricter than the shipped "read-only").
    NoCaps,
    /// Reads + network only (no write/delete/exec).
    ReadOnly,
    /// Write + delete + net, but no exec — a typical "standard" shape.
    Standard,
    /// Every capability bit set.
    FullAccess,
}

impl Profile {
    fn caps(self) -> CapabilitySet {
        match self {
            Profile::NoCaps => CapabilitySet::none(),
            Profile::ReadOnly => CapabilitySet::new(CapabilitySet::CAP_NET_ACCESS),
            Profile::Standard => CapabilitySet::new(
                CapabilitySet::CAP_NET_ACCESS
                    | CapabilitySet::CAP_FILE_WRITE
                    | CapabilitySet::CAP_FILE_DELETE,
            ),
            Profile::FullAccess => CapabilitySet::all(),
        }
    }
}

/// The MAC posture for the case. Kept simple so the oracle is exact: we either
/// run permissive (default-allow) or enforcing with a single subject-scoped rule
/// (action exact-match or `*`) on top of a catch-all allow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MacPosture {
    /// Permissive: MAC never denies.
    Permissive,
    /// Enforcing, catch-all allow only: MAC never denies.
    EnforcingAllowAll,
    /// Enforcing: deny the given action label for this agent, allow the rest.
    EnforcingDenyAction(&'static str),
}

/// One fully-specified adversarial case.
#[derive(Debug, Clone)]
struct Case {
    profile: Profile,
    tool: &'static str,
    resource: String,
    est_tokens: u64,
    /// `tokens_per_min` for the agent's cgroup. 0 == unlimited (root, no child).
    cgroup_budget: u64,
    /// Tokens already consumed in this minute before the call.
    preused_tokens: u64,
    mac: MacPosture,
    /// If `Some`, the tool is tagged to this namespace.
    tool_namespace: Option<NamespaceId>,
    /// Whether the agent is a member of `tool_namespace` (only meaningful when
    /// the tool is tagged).
    member_of_tool_ns: bool,
}

/// The set of tool names the gate knows how to classify, plus an unknown custom
/// tool name. Chosen to span every `ToolAction` branch.
const TOOLS: &[&str] = &[
    "read_file",          // READ, no cap
    "list_directory",     // READ, no cap
    "git_status",         // READ, no cap
    "write_file",         // WRITE, CAP_FILE_WRITE
    "edit_file",          // WRITE, CAP_FILE_WRITE
    "create_file",        // WRITE, CAP_FILE_WRITE
    "delete_file",        // DELETE, CAP_FILE_DELETE
    "http_get",           // NET, CAP_NET_ACCESS
    "browse_url",         // NET, CAP_NET_ACCESS
    "run_command",        // EXEC, CAP_EXEC
    "send_agent_message", // IPC, no cap
    "discover_agents",    // IPC, no cap
    "totally_custom",     // EXECUTE, no cap (default branch)
];

fn arb_profile() -> impl Strategy<Value = Profile> {
    prop_oneof![
        Just(Profile::NoCaps),
        Just(Profile::ReadOnly),
        Just(Profile::Standard),
        Just(Profile::FullAccess),
    ]
}

fn arb_tool() -> impl Strategy<Value = &'static str> {
    proptest::sample::select(TOOLS.to_vec())
}

fn arb_resource() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("/etc/hosts".to_string()),
        Just("/tmp/scratch".to_string()),
        Just("/home/u/file".to_string()),
        Just("https://example.com/api".to_string()),
        Just("/bin/ls".to_string()),
        "[a-z/]{1,20}".prop_map(|s| format!("/{s}")),
    ]
}

fn arb_mac(action: &'static str) -> impl Strategy<Value = MacPosture> {
    // Action labels the gate may classify a tool into. We pick the *actual*
    // action for this tool sometimes (so the deny rule bites) and an unrelated
    // one other times (so it does not), exercising both paths.
    let other_actions = ["read", "write", "net", "exec", "delete", "execute", "ipc"];
    let other: Vec<&'static str> = other_actions.to_vec();
    prop_oneof![
        2 => Just(MacPosture::Permissive),
        2 => Just(MacPosture::EnforcingAllowAll),
        3 => Just(MacPosture::EnforcingDenyAction(action)),
        2 => proptest::sample::select(other).prop_map(MacPosture::EnforcingDenyAction),
    ]
}

fn arb_case() -> impl Strategy<Value = Case> {
    (arb_profile(), arb_tool(), arb_resource()).prop_flat_map(|(profile, tool, resource)| {
        let action = classify_tool(tool).action;
        (
            Just(profile),
            Just(tool),
            Just(resource),
            0u64..2_000u64,                            // est_tokens
            prop_oneof![Just(0u64), 100u64..5_000u64], // cgroup_budget (0 = unlimited)
            0u64..4_000u64,                            // preused_tokens
            arb_mac(action),
            prop_oneof![Just(None), (1u64..50u64).prop_map(Some)], // tool_namespace
            any::<bool>(),                                         // member_of_tool_ns
        )
            .prop_map(
                |(
                    profile,
                    tool,
                    resource,
                    est_tokens,
                    cgroup_budget,
                    preused_tokens,
                    mac,
                    tool_namespace,
                    member_of_tool_ns,
                )| Case {
                    profile,
                    tool,
                    resource,
                    est_tokens,
                    cgroup_budget,
                    preused_tokens,
                    mac,
                    tool_namespace,
                    member_of_tool_ns,
                },
            )
    })
}

// ---------------------------------------------------------------------------
// Independent oracle
// ---------------------------------------------------------------------------

/// The expected verdict, computed independently of the gate. `Allowed` means the
/// call should be allowed; the other variants name the highest-priority failing
/// check.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Expected {
    Allowed,
    Namespace,
    Capability(u64),
    Mac,
    Cgroup,
}

impl Case {
    /// Re-derive the four-layer decision from the raw inputs, in the documented
    /// first-failure-wins order: namespace → capability → MAC → cgroup.
    fn oracle(&self) -> Expected {
        let action = classify_tool(self.tool);

        // 0. Namespace visibility. Tagged tool + non-member → denied.
        if self.tool_namespace.is_some() && !self.member_of_tool_ns {
            return Expected::Namespace;
        }

        // 1. Capability.
        if let Some(required) = action.required_cap {
            if !self.profile.caps().has(required) {
                return Expected::Capability(required);
            }
        }

        // 2. MAC.
        let mac_denies = match self.mac {
            MacPosture::Permissive | MacPosture::EnforcingAllowAll => false,
            MacPosture::EnforcingDenyAction(denied) => denied == action.action,
        };
        if mac_denies {
            return Expected::Mac;
        }

        // 3. Cgroup quota. 0 budget == unlimited (the agent stays in root).
        if self.cgroup_budget > 0 && self.preused_tokens + self.est_tokens > self.cgroup_budget {
            return Expected::Cgroup;
        }

        Expected::Allowed
    }
}

// ---------------------------------------------------------------------------
// Gate construction from a case
// ---------------------------------------------------------------------------

struct Built {
    gate: Arc<SyscallGate>,
    kid: uuid::Uuid,
}

impl Case {
    /// Materialize this case into a live gate with the agent registered exactly
    /// as the oracle assumes. MAC labelling and cgroup pre-usage are applied in
    /// the async body of [`run_case`] (the engine sits behind an async mutex).
    fn build(&self) -> Built {
        let cgroups = Arc::new(CgroupManager::new());

        // Choose the cgroup: a bounded child when a budget is set, else root.
        let cg = if self.cgroup_budget > 0 {
            Some(cgroups.create(
                "case".into(),
                cgroups.root(),
                CgroupLimits {
                    tokens_per_min: self.cgroup_budget,
                    ..Default::default()
                },
            ))
        } else {
            None
        };

        // MAC: build the policy up front and hand it to the gate via `with_mac`
        // so there is no permissive window.
        let (enforcing, rules): (bool, Vec<PolicyRule>) = match self.mac {
            MacPosture::Permissive => (false, Vec::new()),
            MacPosture::EnforcingAllowAll => (
                true,
                vec![PolicyRule {
                    subject: "*".into(),
                    action: "*".into(),
                    object: "*".into(),
                    decision: "allow".into(),
                }],
            ),
            MacPosture::EnforcingDenyAction(denied) => (
                true,
                vec![
                    PolicyRule {
                        subject: "subject".into(),
                        action: denied.into(),
                        object: "*".into(),
                        decision: "deny".into(),
                    },
                    PolicyRule {
                        subject: "*".into(),
                        action: "*".into(),
                        object: "*".into(),
                        decision: "allow".into(),
                    },
                ],
            ),
        };

        let gate = Arc::new(SyscallGate::with_mac(cgroups, enforcing, rules));
        let kid = uuid::Uuid::new_v4();
        gate.register_agent(kid, self.profile.caps(), cg);

        // Namespaces: tag the tool and set membership per the case.
        if let Some(ns) = self.tool_namespace {
            gate.register_tool_namespace(self.tool, ns);
            if self.member_of_tool_ns {
                gate.set_agent_namespaces(kid, vec![ns]);
            } else {
                // Member of *some other* namespace, never the tool's — proves a
                // non-member is denied even when confined to a different ns.
                gate.set_agent_namespaces(kid, vec![ns.wrapping_add(1)]);
            }
        }

        Built { gate, kid }
    }
}

/// Convert the gate's actual result into the oracle's vocabulary so the two can
/// be compared directly.
fn classify_result(r: &Result<u64, GateDenial>) -> Expected {
    match r {
        Ok(_) => Expected::Allowed,
        Err(GateDenial::NotInNamespace { .. }) => Expected::Namespace,
        Err(GateDenial::MissingCapability(cap)) => Expected::Capability(*cap),
        Err(GateDenial::MacDeny { .. }) => Expected::Mac,
        Err(GateDenial::CgroupQuota) => Expected::Cgroup,
        Err(GateDenial::UnknownAgent) => {
            // Never expected in this suite — the agent is always registered.
            panic!("unexpected UnknownAgent denial for a registered agent");
        }
    }
}

/// Run a case end-to-end on the given runtime: build the gate, apply the MAC
/// label (async), preload cgroup usage, then check the call.
fn run_case(rt: &Runtime, case: &Case) -> (Result<u64, GateDenial>, GateStats) {
    let built = case.build();
    rt.block_on(async {
        // Apply the subject label so EnforcingDenyAction rules bind to the agent.
        if let MacPosture::EnforcingDenyAction(_) = case.mac {
            let pid = built.gate.pid_of(built.kid).expect("registered");
            let mut mac = built.gate.mac.lock().await;
            mac.label_agent(pid, "subject".into());
        }
        // Preload cgroup usage *before* the call (only meaningful with a budget).
        if case.cgroup_budget > 0 && case.preused_tokens > 0 {
            built.gate.record_tool_usage(built.kid, case.preused_tokens);
        }
        let r = built
            .gate
            .check_tool_call(built.kid, case.tool, &case.resource, case.est_tokens)
            .await;
        (r, built.gate.stats())
    })
}

// ---------------------------------------------------------------------------
// Properties
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig { cases: 512, .. ProptestConfig::default() })]

    /// INVARIANT 1 + 2 (no bypass + first-failure-wins): for every generated
    /// case, the gate's verdict equals the independent oracle's verdict — both
    /// the allow/deny outcome AND, on denial, the *specific* highest-priority
    /// reason. This single equality simultaneously proves there is no bypass
    /// (the gate never returns Ok when the oracle says some check fails) and
    /// that the documented ordering holds (the winning reason is the right one).
    #[test]
    fn gate_matches_oracle(case in arb_case()) {
        let rt = Runtime::new().unwrap();
        let (result, _stats) = run_case(&rt, &case);
        let expected = case.oracle();
        let actual = classify_result(&result);
        prop_assert_eq!(
            actual.clone(), expected.clone(),
            "gate verdict {:?} != oracle {:?} for case {:?}",
            actual, expected, case
        );
    }

    /// INVARIANT 6 (counter consistency): exactly one counter moves per call,
    /// and it is the bucket matching the verdict. (`audited` is not exercised
    /// here — these MAC postures never produce an `audit` decision.)
    #[test]
    fn counters_match_verdict(case in arb_case()) {
        let rt = Runtime::new().unwrap();
        let (result, stats) = run_case(&rt, &case);
        let actual = classify_result(&result);
        let total = stats.allowed
            + stats.denied_capability
            + stats.denied_mac
            + stats.denied_cgroup
            + stats.denied_unknown
            + stats.denied_namespace
            + stats.audited;
        prop_assert_eq!(total, 1, "exactly one counter must move per call: {:?}", stats);
        match actual {
            Expected::Allowed => prop_assert_eq!(stats.allowed, 1),
            Expected::Namespace => prop_assert_eq!(stats.denied_namespace, 1),
            Expected::Capability(_) => prop_assert_eq!(stats.denied_capability, 1),
            Expected::Mac => prop_assert_eq!(stats.denied_mac, 1),
            Expected::Cgroup => prop_assert_eq!(stats.denied_cgroup, 1),
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 256, .. ProptestConfig::default() })]

    /// INVARIANT 3 (capability monotonicity, deny side): a no-caps agent is
    /// NEVER granted any tool whose action carries a required capability —
    /// regardless of MAC posture or cgroup budget. The only way such a tool
    /// passes is if it requires no capability.
    #[test]
    fn no_caps_agent_never_gets_privileged_tool(
        tool in arb_tool(),
        resource in arb_resource(),
        budget in prop_oneof![Just(0u64), 100u64..5_000u64],
        mac in prop_oneof![
            Just(MacPosture::Permissive),
            Just(MacPosture::EnforcingAllowAll),
        ],
    ) {
        let case = Case {
            profile: Profile::NoCaps,
            tool,
            resource,
            est_tokens: 1,
            cgroup_budget: budget,
            preused_tokens: 0,
            mac,
            // Make the tool globally visible (untagged) so namespace can never be
            // the reason — capability must stand alone.
            tool_namespace: None,
            member_of_tool_ns: true,
        };
        let rt = Runtime::new().unwrap();
        let (result, _stats) = run_case(&rt, &case);
        let required = classify_tool(tool).required_cap;
        match required {
            Some(cap) => prop_assert_eq!(
                classify_result(&result),
                Expected::Capability(cap),
                "no-caps agent must be denied {} on capability grounds", tool
            ),
            None => prop_assert!(
                result.is_ok(),
                "tool {} requires no cap so a no-caps agent must pass it", tool
            ),
        }
    }

    /// INVARIANT 3 (capability monotonicity, grant side): a full-access agent is
    /// NEVER denied on *capability* grounds — it holds every bit. Under a
    /// permissive/allow-all MAC and an unlimited cgroup with the tool global, a
    /// full-access agent is always allowed.
    #[test]
    fn full_access_agent_never_capability_denied(
        tool in arb_tool(),
        resource in arb_resource(),
    ) {
        let case = Case {
            profile: Profile::FullAccess,
            tool,
            resource,
            est_tokens: 1,
            cgroup_budget: 0,      // unlimited
            preused_tokens: 0,
            mac: MacPosture::EnforcingAllowAll,
            tool_namespace: None,
            member_of_tool_ns: true,
        };
        let rt = Runtime::new().unwrap();
        let (result, _stats) = run_case(&rt, &case);
        prop_assert!(
            !matches!(result, Err(GateDenial::MissingCapability(_))),
            "full-access agent must never be capability-denied for {}: {:?}",
            tool, result
        );
        prop_assert!(result.is_ok(), "expected allow, got {:?}", result);
    }

    /// INVARIANT 4 (cgroup quota): with namespace/cap/MAC all satisfied, an
    /// under-budget call passes the cgroup check and an over-budget call is
    /// ALWAYS denied with the quota reason. Uses a no-cap tool (read_file) so
    /// capability never interferes.
    #[test]
    fn cgroup_quota_boundary(
        budget in 100u64..5_000u64,
        preused in 0u64..6_000u64,
        est in 0u64..6_000u64,
    ) {
        let case = Case {
            profile: Profile::FullAccess,
            tool: "read_file",
            resource: "/etc/hosts".to_string(),
            est_tokens: est,
            cgroup_budget: budget,
            preused_tokens: preused,
            mac: MacPosture::Permissive,
            tool_namespace: None,
            member_of_tool_ns: true,
        };
        let rt = Runtime::new().unwrap();
        let (result, _stats) = run_case(&rt, &case);
        let over = preused + est > budget;
        if over {
            prop_assert_eq!(
                classify_result(&result), Expected::Cgroup,
                "over-budget ({}+{}>{}) must be CgroupQuota", preused, est, budget
            );
        } else {
            prop_assert!(
                result.is_ok(),
                "under-budget ({}+{}<={}) must pass, got {:?}",
                preused, est, budget, result
            );
        }
    }

    /// INVARIANT 4 (accounting moves the needle): recording usage that crosses
    /// the budget flips an otherwise-allowed call into a CgroupQuota denial.
    #[test]
    fn record_usage_changes_verdict(
        (budget, est) in (100u64..2_000u64)
            .prop_flat_map(|b| (Just(b), 1u64..=b)),
    ) {
        let rt = Runtime::new().unwrap();
        let cgroups = Arc::new(CgroupManager::new());
        let cg = cgroups.create(
            "acct".into(),
            cgroups.root(),
            CgroupLimits { tokens_per_min: budget, ..Default::default() },
        );
        let gate = Arc::new(SyscallGate::new(cgroups));
        let kid = uuid::Uuid::new_v4();
        gate.register_agent(kid, CapabilitySet::all(), Some(cg));

        rt.block_on(async {
            // Fresh budget: a small call is allowed.
            let r0 = gate.check_tool_call(kid, "read_file", "/x", est).await;
            prop_assert!(r0.is_ok(), "initial under-budget call should pass: {:?}", r0);
            // Burn the whole budget.
            gate.record_tool_usage(kid, budget);
            // Now even a 1-token call exceeds it.
            let r1 = gate.check_tool_call(kid, "read_file", "/x", 1).await;
            prop_assert_eq!(
                classify_result(&r1), Expected::Cgroup,
                "after recording the full budget, the next call must be denied"
            );
            Ok(())
        })?;
    }

    /// INVARIANT 5 (namespace visibility): an untagged tool is globally visible
    /// (never NotInNamespace); a tool tagged to ns N is denied for a non-member
    /// and — other checks permitting — allowed for a member.
    #[test]
    fn namespace_visibility(
        tool in proptest::sample::select(vec!["read_file", "list_directory", "discover_agents"]),
        ns in 1u64..1_000u64,
        member in any::<bool>(),
        tagged in any::<bool>(),
    ) {
        // Use no-cap tools + full-access + permissive MAC + unlimited cgroup so
        // the *only* thing that can deny is the namespace layer.
        let rt = Runtime::new().unwrap();
        let cgroups = Arc::new(CgroupManager::new());
        let gate = Arc::new(SyscallGate::new(cgroups));
        let kid = uuid::Uuid::new_v4();
        gate.register_agent(kid, CapabilitySet::all(), None);

        if tagged {
            gate.register_tool_namespace(tool, ns);
            if member {
                gate.set_agent_namespaces(kid, vec![ns]);
            } else {
                gate.set_agent_namespaces(kid, vec![ns + 1]); // some other ns
            }
        }

        let result = rt.block_on(gate.check_tool_call(kid, tool, "/x", 1));
        if tagged && !member {
            match result {
                Err(GateDenial::NotInNamespace { tool: t, namespace }) => {
                    prop_assert_eq!(t, tool.to_string());
                    prop_assert_eq!(namespace, ns);
                }
                other => prop_assert!(false, "expected NotInNamespace, got {:?}", other),
            }
        } else {
            prop_assert!(
                result.is_ok(),
                "untagged-or-member call must pass (tagged={}, member={}): {:?}",
                tagged, member, result
            );
        }
    }

    /// INVARIANT 2 (ordering, focused): when BOTH the namespace check and the
    /// capability check would fail, the gate reports namespace (the higher
    /// priority). A privileged tool tagged to a namespace the no-cap agent is
    /// not in must yield NotInNamespace, never MissingCapability.
    #[test]
    fn namespace_wins_over_capability(
        tool in proptest::sample::select(vec!["write_file", "delete_file", "http_get", "run_command"]),
        ns in 1u64..1_000u64,
    ) {
        let rt = Runtime::new().unwrap();
        let cgroups = Arc::new(CgroupManager::new());
        let gate = Arc::new(SyscallGate::new(cgroups));
        let kid = uuid::Uuid::new_v4();
        gate.register_agent(kid, CapabilitySet::none(), None); // lacks the cap
        gate.register_tool_namespace(tool, ns);                // tag the tool
        gate.set_agent_namespaces(kid, vec![ns + 1]);          // NOT in `ns`

        let result = rt.block_on(gate.check_tool_call(kid, tool, "/x", 1));
        prop_assert!(
            matches!(result, Err(GateDenial::NotInNamespace { .. })),
            "namespace must precede capability, got {:?}", result
        );
    }

    /// INVARIANT 2 (ordering, focused): capability precedes MAC. A no-cap agent
    /// calling a privileged tool that MAC would *also* deny must be reported as
    /// MissingCapability (capability fires first), never MacDeny.
    #[test]
    fn capability_wins_over_mac(
        tool in proptest::sample::select(vec!["write_file", "delete_file", "http_get", "run_command"]),
    ) {
        let action = classify_tool(tool).action;
        let case = Case {
            profile: Profile::NoCaps,
            tool,
            resource: "/x".to_string(),
            est_tokens: 1,
            cgroup_budget: 0,
            preused_tokens: 0,
            mac: MacPosture::EnforcingDenyAction(action), // MAC would also deny
            tool_namespace: None,
            member_of_tool_ns: true,
        };
        let rt = Runtime::new().unwrap();
        let (result, _stats) = run_case(&rt, &case);
        prop_assert!(
            matches!(result, Err(GateDenial::MissingCapability(_))),
            "capability must precede MAC, got {:?}", result
        );
    }

    /// INVARIANT 2 (ordering, focused): MAC precedes cgroup. A capable agent
    /// whose action MAC denies, in a cgroup that is ALSO over budget, must be
    /// reported as MacDeny (MAC fires before the quota check).
    #[test]
    fn mac_wins_over_cgroup(_seed in 0u64..64u64) {
        // read_file needs no cap, so capability never interferes; MAC denies
        // "read" while the cgroup is simultaneously exhausted.
        let case = Case {
            profile: Profile::FullAccess,
            tool: "read_file",
            resource: "/x".to_string(),
            est_tokens: 1_000,
            cgroup_budget: 100,  // tiny budget
            preused_tokens: 100, // already at the cap → cgroup would deny
            mac: MacPosture::EnforcingDenyAction("read"),
            tool_namespace: None,
            member_of_tool_ns: true,
        };
        let rt = Runtime::new().unwrap();
        let (result, _stats) = run_case(&rt, &case);
        prop_assert!(
            matches!(result, Err(GateDenial::MacDeny { .. })),
            "MAC must precede cgroup, got {:?}", result
        );
    }
}

// ---------------------------------------------------------------------------
// Meta-property: the oracle's MAC mirror agrees with the real MacEngine for the
// postures we generate. This guards against the oracle silently drifting from
// the engine it claims to mirror.
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig { cases: 256, .. ProptestConfig::default() })]

    #[test]
    fn oracle_mac_mirror_agrees_with_engine(
        denied in proptest::sample::select(vec!["read", "write", "net", "exec", "delete", "execute", "ipc"]),
        queried in proptest::sample::select(vec!["read", "write", "net", "exec", "delete", "execute", "ipc"]),
    ) {
        use kernel::mac::MacDecision;
        let mut engine = MacEngine::new(true);
        engine.label_agent(1, "subject".into());
        engine.load_policy(vec![
            PolicyRule {
                subject: "subject".into(),
                action: denied.to_string(),
                object: "*".into(),
                decision: "deny".into(),
            },
            PolicyRule {
                subject: "*".into(),
                action: "*".into(),
                object: "*".into(),
                decision: "allow".into(),
            },
        ]);
        let engine_denies = matches!(engine.check(1, queried, "/whatever"), MacDecision::Deny);
        let oracle_denies = denied == queried;
        prop_assert_eq!(
            engine_denies, oracle_denies,
            "oracle MAC mirror disagrees with MacEngine for denied={}, queried={}",
            denied, queried
        );
    }
}
