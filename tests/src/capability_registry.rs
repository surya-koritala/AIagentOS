//! Regression tests for the canonical capability/maturity registry (#106).

use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

const MATURITY_MODEL: [&str; 5] = [
    "scaffolded",
    "unit-tested",
    "integrated",
    "public-api-e2e",
    "production-qualified",
];

#[derive(Debug, Deserialize)]
struct Registry {
    schema_version: u32,
    updated: String,
    model: Vec<String>,
    maturity_approvers: Vec<String>,
    verification_commands: Vec<String>,
    capability: Vec<Capability>,
}

#[derive(Debug, Deserialize)]
struct Capability {
    id: String,
    title: String,
    owner: String,
    maturity: String,
    release: String,
    tracking_issue: u64,
    qualification_issue: Option<u64>,
    v1_disposition: Option<String>,
    kernel_modules: Vec<String>,
    source_paths: Vec<String>,
    public_entry_points: Vec<String>,
    runtime_call_paths: Vec<String>,
    test_evidence: Vec<String>,
    platforms: Vec<String>,
    limitations: Vec<String>,
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("tests crate must live below the workspace root")
        .to_path_buf()
}

fn load_registry() -> Registry {
    let path = workspace_root().join("docs/capabilities.toml");
    let source = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
    toml::from_str(&source)
        .unwrap_or_else(|error| panic!("invalid capability registry {}: {error}", path.display()))
}

fn read_workspace_file(relative: &str) -> String {
    let path = workspace_root().join(relative);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()))
}

fn evidence_path(reference: &str) -> &str {
    reference.split("::").next().unwrap_or(reference)
}

fn validate_capability(capability: &Capability, root: &Path) -> Vec<String> {
    let mut errors = Vec::new();
    let level = MATURITY_MODEL
        .iter()
        .position(|candidate| *candidate == capability.maturity);

    if capability.id.trim().is_empty() || capability.title.trim().is_empty() {
        errors.push("id and title are required".to_string());
    }
    if capability.owner.trim().is_empty() {
        errors.push("owner is required".to_string());
    }
    if level.is_none() {
        errors.push(format!("unknown maturity level {:?}", capability.maturity));
    }
    if !matches!(
        capability.release.as_str(),
        "v0.4" | "v0.5" | "v0.6" | "v0.9" | "v1.0"
    ) {
        errors.push(format!("unknown release train {:?}", capability.release));
    }
    if capability.tracking_issue < 105 {
        errors.push("pending capabilities must link to the evidence-gated roadmap".to_string());
    }
    if capability
        .qualification_issue
        .is_some_and(|issue| issue < 105)
    {
        errors.push("qualification issues must link to the evidence-gated roadmap".to_string());
    }
    let disposition = capability.v1_disposition.as_deref().unwrap_or("retained");
    if !matches!(disposition, "retained" | "excluded-from-v1") {
        errors.push(format!("unknown v1 disposition {disposition:?}"));
    }
    if disposition == "excluded-from-v1"
        && !capability
            .limitations
            .iter()
            .any(|item| item.to_ascii_lowercase().contains("excluded from v1"))
    {
        errors.push("v1 exclusions must be explained in limitations".to_string());
    }
    if capability.source_paths.is_empty() {
        errors.push("at least one source path is required".to_string());
    }
    if capability.platforms.is_empty()
        || capability
            .platforms
            .iter()
            .any(|platform| !matches!(platform.as_str(), "linux" | "macos" | "windows"))
    {
        errors.push("platforms must be a non-empty subset of linux/macos/windows".to_string());
    }
    if capability.limitations.is_empty()
        || capability
            .limitations
            .iter()
            .any(|limitation| limitation.trim().is_empty())
    {
        errors.push("current limitations must be explicit".to_string());
    }

    for reference in capability
        .source_paths
        .iter()
        .chain(capability.public_entry_points.iter())
        .chain(capability.runtime_call_paths.iter())
        .chain(capability.test_evidence.iter())
    {
        let relative = evidence_path(reference);
        if !root.join(relative).exists() {
            errors.push(format!("evidence path does not exist: {relative}"));
        }
    }

    if let Some(level) = level {
        if level >= 2 && capability.runtime_call_paths.is_empty() {
            errors.push("integrated capabilities require a primary runtime call path".to_string());
        }
        if level >= 3 {
            if capability.public_entry_points.is_empty() {
                errors.push("public-api-e2e capabilities require a public entry point".to_string());
            }
            if capability.test_evidence.is_empty() {
                errors.push("public-api-e2e capabilities require test evidence".to_string());
            }
        }
        if level == 4
            && capability.limitations.iter().any(|item| {
                let lower = item.to_ascii_lowercase();
                lower.contains("pending")
                    || lower.contains("incomplete")
                    || lower.contains("not yet")
            })
        {
            errors
                .push("production-qualified capabilities cannot describe pending work".to_string());
        }
    }

    errors
}

#[test]
fn registry_is_complete_and_honest() {
    let root = workspace_root();
    let registry = load_registry();
    assert_eq!(registry.schema_version, 1);
    assert!(!registry.updated.trim().is_empty());
    assert_eq!(
        registry.model,
        MATURITY_MODEL.map(str::to_string),
        "the documented maturity model is a compatibility contract"
    );
    assert_eq!(
        registry.maturity_approvers.len(),
        3,
        "maturity promotion requires an owner, release reviewer, and conditional security review"
    );
    assert!(registry
        .maturity_approvers
        .iter()
        .any(|approver| approver.contains("security reviewer")));
    for command in &registry.verification_commands {
        assert!(
            command.starts_with("cargo "),
            "verification commands must be reproducible cargo commands: {command}"
        );
    }
    assert_eq!(
        registry.capability.len(),
        23,
        "every roadmap child issue must have a capability decision"
    );

    let mut ids = BTreeSet::new();
    let mut issues = BTreeSet::new();
    let mut validation_errors = BTreeMap::new();
    let mut registered_modules = BTreeSet::new();

    for capability in &registry.capability {
        assert!(
            ids.insert(capability.id.clone()),
            "duplicate id {}",
            capability.id
        );
        assert!(
            issues.insert(capability.tracking_issue),
            "issue #{} is assigned to more than one capability",
            capability.tracking_issue
        );
        for module in &capability.kernel_modules {
            assert!(
                registered_modules.insert(module.clone()),
                "kernel module {module} is assigned to multiple capabilities"
            );
        }
        let errors = validate_capability(capability, &root);
        if !errors.is_empty() {
            validation_errors.insert(capability.id.clone(), errors);
        }
    }
    assert!(
        validation_errors.is_empty(),
        "invalid capability claims: {validation_errors:#?}"
    );

    let lib = std::fs::read_to_string(root.join("crates/kernel/src/lib.rs")).unwrap();
    let declared_modules: BTreeSet<String> = lib
        .lines()
        .filter_map(|line| {
            line.trim()
                .strip_prefix("pub mod ")
                .and_then(|value| value.strip_suffix(';'))
                .map(str::to_string)
        })
        .collect();
    assert_eq!(
        registered_modules, declared_modules,
        "adding or removing a public kernel module requires a capability classification"
    );

    let expected_issues: BTreeSet<u64> = (106..=128).collect();
    assert_eq!(
        issues, expected_issues,
        "every child roadmap issue must be represented exactly once"
    );
}

#[test]
fn provider_matrix_names_every_resource_provider_status_and_platform_contract() {
    let matrix = read_workspace_file("docs/PROVIDER_MATRIX.md");
    let summary = read_workspace_file("docs/src/SUMMARY.md");
    assert!(summary.contains("./provider-matrix.md"));
    for status in ["Experimental", "E2E verified", "Production-qualified"] {
        assert!(
            matrix.contains(status),
            "provider matrix must define the required {status} status"
        );
    }
    let expected_platform_rows = [
        ("`BuiltinFilesystemProvider`", "Linux; macOS; Windows"),
        ("`BuiltinNetworkProvider`", "Linux; macOS; Windows"),
        (
            "`BuiltinAppProvider`",
            "Linux host; digest-pinned Alpine container",
        ),
        ("`IpcResourceProvider`", "Linux; macOS; Windows"),
        ("Kernel browser provider", "None — unavailable"),
        ("Kernel peripheral provider", "None — unavailable"),
        ("Kernel computer-use provider", "None — unavailable"),
        (
            "`FilesystemProvider` (`resources` crate)",
            "None — unavailable",
        ),
        (
            "`NetworkProvider` (`resources` crate)",
            "None — unavailable",
        ),
        (
            "`ApplicationProvider` (`resources` crate)",
            "None — unavailable",
        ),
        (
            "`PeripheralProvider` (`resources` crate)",
            "None — unavailable",
        ),
        (
            "Feature-gated HTML/playwright helpers",
            "Trusted operator process; feature-dependent",
        ),
    ];
    for (provider, expected_platforms) in expected_platform_rows {
        let row = matrix
            .lines()
            .find(|line| line.contains(provider))
            .unwrap_or_else(|| panic!("provider matrix does not name {provider}"));
        let cells = row
            .split('|')
            .map(str::trim)
            .filter(|cell| !cell.is_empty())
            .collect::<Vec<_>>();
        assert_eq!(
            cells.len(),
            5,
            "provider matrix row for {provider} must have five columns: {row}"
        );
        assert_eq!(
            cells[3].trim_matches('*'),
            expected_platforms,
            "provider matrix row for {provider} has a stale or ambiguous platform contract"
        );
    }

    let ci = read_workspace_file(".github/workflows/ci.yml");
    for runner in ["ubuntu-latest", "macos-latest", "windows-latest"] {
        assert!(
            ci.contains(runner),
            "CI must exercise provider contracts on {runner}"
        );
    }

    let root = workspace_root();
    let provider_sources = [
        "crates/kernel/src/lib.rs",
        "crates/resources/src/application.rs",
        "crates/resources/src/filesystem.rs",
        "crates/resources/src/network.rs",
        "crates/resources/src/peripheral.rs",
    ];
    let mut implementations = BTreeMap::<String, BTreeSet<String>>::new();
    for relative in provider_sources {
        let source = std::fs::read_to_string(root.join(relative)).unwrap();
        let mut implementation = None;
        let mut operations = false;
        for line in source.lines() {
            if let Some(name) = line
                .trim()
                .strip_prefix("impl ResourceProvider for ")
                .and_then(|value| value.strip_suffix(" {"))
            {
                implementation = Some(name.to_string());
                implementations.entry(name.to_string()).or_default();
                operations = false;
                continue;
            }
            if implementation.is_some() && line.contains("fn supported_operations(") {
                operations = true;
                continue;
            }
            if operations && line.contains("async fn execute(") {
                operations = false;
                continue;
            }
            if operations {
                let Some(name) = implementation.as_ref() else {
                    continue;
                };
                for (index, value) in line.split('"').enumerate() {
                    if index % 2 == 1 {
                        implementations
                            .get_mut(name)
                            .expect("provider implementation was registered")
                            .insert(value.to_string());
                    }
                }
            }
        }
    }
    assert!(!implementations.is_empty());
    for (implementation, operations) in implementations {
        let row = matrix
            .lines()
            .find(|line| line.contains(&format!("`{implementation}`")))
            .unwrap_or_else(|| {
                panic!("provider matrix does not name ResourceProvider implementation {implementation}")
            });
        for operation in operations {
            assert!(
                row.contains(&format!("`{operation}`")),
                "provider matrix row for {implementation} omits advertised operation {operation}"
            );
        }
        assert!(
            row.contains("Experimental")
                || row.contains("E2E verified")
                || row.contains("Production-qualified"),
            "provider matrix row for {implementation} has no recognized status"
        );
        assert!(
            expected_platform_rows
                .iter()
                .any(|(provider, _)| row.contains(provider)),
            "provider matrix row for {implementation} has no validated platform contract"
        );
    }
}

#[test]
fn distributed_consistency_contract_is_published_and_fail_closed() {
    let contract = read_workspace_file("docs/DISTRIBUTED_CONTROL_PLANE.md");
    let summary = read_workspace_file("docs/src/SUMMARY.md");
    let architecture = read_workspace_file("docs/ARCHITECTURE.md");
    let protocol = read_workspace_file("docs/PROTOCOL.md");

    assert!(summary.contains("./distributed-control-plane.md"));
    assert!(architecture.contains("DISTRIBUTED_CONTROL_PLANE.md"));
    assert!(protocol.contains("DISTRIBUTED_CONTROL_PLANE.md"));

    for object in [
        "Cluster identity and membership",
        "Agent identity",
        "Agent ownership and routing",
        "Agent state and checkpoints",
        "Package metadata and trust roots",
        "Authorization policy",
        "Quotas and accounting",
        "Audit",
        "IPC and delegation",
    ] {
        assert!(
            contract.contains(object),
            "distributed consistency contract must classify {object}"
        );
    }

    for failure in [
        "Membership authority loss",
        "Workload node loss",
        "Network partition",
        "Duplicate agent ownership",
        "Stale route",
        "Clock skew",
        "Unknown outcomes are not successes",
    ] {
        assert!(
            contract.contains(failure),
            "distributed consistency contract must define {failure}"
        );
    }

    for honest_boundary in [
        "isolated former leader cannot commit or locally apply",
        "separate generation-fenced transport-trust",
        "every fresh RPC checks that",
        "peer removed only from voting remains a replicated learner",
        "Startup compares the immutable seed and complete application catalog",
        "retained peers must preserve an application identity",
        "Configured Raft peers can no longer forward a bare external command",
        "proof delegates a system-node principal rather than",
        "host compromise that exposes both the",
        "records the OpenRaft leader term",
        "stops admitting new mutations at the exact expiry",
        "not a self-contained offline quorum certificate",
        "Expiry is checked at admission",
        "does not cancel or",
        "not atomic across databases",
        "not fully partition tolerant",
        "production distributed kernel",
        "every mutable agent operation must be rejected",
        "Lease expiry alone is insufficient",
    ] {
        assert!(
            contract.contains(honest_boundary),
            "distributed consistency contract lost boundary: {honest_boundary}"
        );
    }
}

#[test]
fn trusted_browser_helpers_remain_isolated_bounded_and_outside_runtime_discovery() {
    let automation = read_workspace_file("crates/resources/src/playwright.rs");
    for contract in [
        ".respect_https_errors()",
        ".user_data_dir(profile.path())",
        "SetDownloadBehaviorBehavior::Deny",
        "browser.wait()",
        "profile.close()",
        "MAX_SCREENSHOT_BYTES",
        "MAX_INPUT_BYTES",
        "browser URL is invalid or too large",
        "live_browser_denies_downloads_isolates_sessions_and_removes_profiles",
    ] {
        assert!(
            automation.contains(contract),
            "trusted Chromium helper lost security contract {contract:?}"
        );
    }

    let html = read_workspace_file("crates/resources/src/browser.rs");
    for contract in [
        ".no_proxy()",
        ".redirect(reqwest::redirect::Policy::none())",
        "MAX_HTML_BYTES",
        "MAX_CONTENT_CHARS",
        "String::from_utf8(bytes)",
        "project_document_link",
        "trusted_web_fetch_is_bounded_strict_and_does_not_follow_redirects",
    ] {
        assert!(
            html.contains(contract),
            "trusted HTML helper lost security contract {contract:?}"
        );
    }

    let matrix = read_workspace_file("docs/PROVIDER_MATRIX.md");
    let helper_row = matrix
        .lines()
        .find(|line| line.contains("Feature-gated HTML/playwright helpers"))
        .expect("provider matrix must retain the trusted helper row");
    assert!(helper_row.contains("**Experimental**"));
    assert!(helper_row.contains("Trusted operator process"));
    assert!(helper_row.contains("not `ResourceProvider` implementations"));

    let browser_row = matrix
        .lines()
        .find(|line| line.contains("Kernel browser provider"))
        .expect("provider matrix must retain the kernel browser row");
    assert!(browser_row.contains("Experimental — unavailable"));
    assert!(browser_row.contains("None — unavailable"));
    assert!(
        !read_workspace_file("crates/kernel/src/lib.rs")
            .contains("register_provider(ResourceType::Browser"),
        "trusted helper work must not silently publish an unqualified kernel browser provider"
    );

    let qualification = read_workspace_file(".github/workflows/extended-security.yml");
    for contract in [
        "flags=(unconfined)",
        "userns,",
        "apparmor_parser -r",
        "browser_sandbox=userns_apparmor_profile",
        "browser_userns_profile_sha256",
    ] {
        assert!(
            qualification.contains(contract),
            "live Chromium qualification lost sandbox contract {contract:?}"
        );
    }
    assert!(
        !qualification.contains("--no-sandbox")
            && !qualification.contains("--disable-setuid-sandbox")
            && !qualification.contains("apparmor_restrict_unprivileged_userns=0")
            && !qualification.contains("chmod 4755")
            && !qualification.contains("CHROME_DEVEL_SANDBOX"),
        "live Chromium qualification must use a scoped userns profile, not disable \
         Chromium's sandbox, weaken the runner globally, or elevate a downloaded helper"
    );
}

#[test]
fn peripheral_access_stays_unavailable_and_requires_a_revocable_local_grant() {
    let tools = read_workspace_file("crates/kernel/src/tools.rs");
    for contract in [
        "binding.resource_type == ResourceType::Peripheral",
        "binding.security.approval_policy == ApprovalPolicy::None",
        "binding.security.sandbox_requirement != SandboxRequirement::Required",
        "ResourceType::Peripheral,\n                \"capture_image\"",
        "ResourceType::Peripheral,\n                \"record_audio\"",
        "ResourceType::Peripheral,\n                \"play_audio\"",
        "(ResourceType::Peripheral, \"print\", SecurityAction::Write)",
    ] {
        assert!(
            tools.contains(contract),
            "peripheral registration guard lost {contract:?}"
        );
    }

    let kernel = read_workspace_file("crates/kernel/src/lib.rs");
    for contract in [
        "pub struct PeripheralCallState",
        "pub struct PeripheralRevocation",
        "pub fn approve_peripheral_call(",
        "pub fn peripheral_call_state(",
        "pub fn revoke_peripheral_call(",
        "grant_pending",
        "active_uses",
        "resource_identity",
        "peripheral_grant_has_visible_active_state_and_revokes_exact_use",
        "admitted_peripheral_use_is_revocable_before_provider_dispatch",
        "agent_kill_revokes_active_peripheral_use",
    ] {
        assert!(
            kernel.contains(contract),
            "trusted local approval surface lost {contract:?}"
        );
    }

    let resources = read_workspace_file("crates/kernel/src/resources.rs");
    for contract in [
        "pub(crate) struct PeripheralActivityLease",
        "peripheral_activity: Option<PeripheralActivityLease>",
        "peripheral gate admission lease required",
    ] {
        assert!(
            resources.contains(contract),
            "peripheral active-use contract lost {contract:?}"
        );
    }

    let sandbox = read_workspace_file("crates/kernel/src/sandbox.rs");
    for contract in [
        "fn intercept_action_with_operator_grant(",
        "peripheral access requires an exact trusted operator grant",
        "peripheral_access_requires_the_gate_bound_operator_grant",
    ] {
        assert!(
            sandbox.contains(contract),
            "peripheral sandbox contract lost {contract:?}"
        );
    }

    let gate = read_workspace_file("crates/kernel/src/syscall_gate.rs");
    for contract in [
        "tool_approval_granted_contract",
        "revoke_tool_approval_contract",
        "self.approvals.remove(&key)",
        "self.approvals",
        ".retain(|(agent, _, _, _, _), _| *agent != kid)",
        "peripheral_call_state_contract",
        "revoke_peripheral_call_contract",
        "cancel_peripheral_for_agent",
        "never in an uncancellable gap",
    ] {
        assert!(
            gate.contains(contract),
            "single-use approval lifecycle lost {contract:?}"
        );
    }

    let matrix = read_workspace_file("docs/PROVIDER_MATRIX.md");
    let row = matrix
        .lines()
        .find(|line| line.contains("Kernel peripheral provider"))
        .expect("provider matrix must retain the kernel peripheral row");
    for contract in [
        "Experimental — unavailable",
        "None — unavailable",
        "explicit local human approval",
        "pending-grant and active-use counts",
        "cooperatively cancels every active exact-match use",
        "No remote, SDK, package, or MCP surface can create, inspect, or revoke grants",
    ] {
        assert!(
            row.contains(contract),
            "peripheral matrix row lost honest contract {contract:?}"
        );
    }
}

#[test]
fn false_production_claim_is_rejected() {
    let root = workspace_root();
    let false_claim = Capability {
        id: "false-live-claim".into(),
        title: "False live claim".into(),
        owner: "nobody".into(),
        maturity: "production-qualified".into(),
        release: "v1.0".into(),
        tracking_issue: 999,
        qualification_issue: None,
        v1_disposition: None,
        kernel_modules: Vec::new(),
        source_paths: vec!["README.md".into()],
        public_entry_points: Vec::new(),
        runtime_call_paths: Vec::new(),
        test_evidence: Vec::new(),
        platforms: vec!["linux".into()],
        limitations: vec!["Critical work is still pending.".into()],
    };

    let errors = validate_capability(&false_claim, &root);
    assert!(errors
        .iter()
        .any(|error| error.contains("runtime call path")));
    assert!(errors
        .iter()
        .any(|error| error.contains("public entry point")));
    assert!(errors.iter().any(|error| error.contains("test evidence")));
    assert!(errors.iter().any(|error| error.contains("pending work")));
}

#[test]
fn user_facing_status_docs_defer_to_the_registry() {
    let root = workspace_root();
    for relative in [
        "README.md",
        "docs/ARCHITECTURE.md",
        "docs/PLATFORM_ROADMAP.md",
    ] {
        let text = std::fs::read_to_string(root.join(relative)).unwrap();
        assert!(
            text.contains("capabilities.toml"),
            "{relative} must identify docs/capabilities.toml as the maturity authority"
        );
    }

    let roadmap = std::fs::read_to_string(root.join("ROADMAP.md")).unwrap();
    assert!(
        roadmap.contains("issues/105"),
        "the historical roadmap must hand remaining work to the live issue tracker"
    );

    let readme = std::fs::read_to_string(root.join("README.md")).unwrap();
    for command in &load_registry().verification_commands {
        if command.contains("os-benchmark --bin os-benchmark") {
            assert!(
                readme.contains(command),
                "README benchmark command must be copied from the canonical registry"
            );
        }
    }
    assert!(
        !readme.contains("tests passing"),
        "volatile test counts must come from CI instead of a hand-maintained README claim"
    );
}

#[test]
fn canonical_client_contract_is_explicit_and_honest() {
    let protocol = read_workspace_file("docs/PROTOCOL.md");
    for required in [
        "There is one canonical operator client: **`agentctl`**",
        "There is one canonical programmatic client: **`agent_sdk::KernelClient`**",
        "| `agentctl` | Canonical headless operator client |",
        "| `agent-tui` | Focused interactive operator view |",
        "| Tauri/Svelte desktop | Focused end-user/operator application |",
        "| `agent` | Embedded single-agent developer shell |",
        "Not an operator client and not a feature-parity target.",
        "“Parity” means behavioral parity for an operation a surface exposes",
        "Missing breadth is not called parity.",
    ] {
        assert!(
            protocol.contains(required),
            "canonical client contract lost {required:?}"
        );
    }

    let interactive = read_workspace_file("crates/cli/src/main.rs");
    assert!(
        interactive.contains("AgentKernelImpl::from_config"),
        "embedded agent shell changed shape; revisit its documented client role"
    );
    let agentctl = read_workspace_file("crates/cli/src/bin/agentctl.rs");
    assert!(
        agentctl.contains("OperatorClient::connect_profile"),
        "canonical operator client no longer uses the shared public client"
    );
    for command in [
        "policy-validate POLICY_FILE",
        "policy-explain POLICY_FILE",
        "gate-stats",
        "node-control-audit [LIMIT]",
        "cluster-membership-audit [LIMIT]",
        "cluster-certificate-rollout-audit [LIMIT]",
    ] {
        assert!(
            agentctl.contains(command),
            "canonical operator client lost policy/audit command {command:?}"
        );
    }
    assert!(
        agentctl.contains("policy::explain_file")
            && agentctl.contains(".gate_stats()")
            && agentctl.contains(".node_control_audit(limit)")
            && agentctl.contains(".cluster_membership_audit(limit)")
            && agentctl.contains(".cluster_certificate_rollout_audit(limit)"),
        "canonical policy/audit commands must use the shared policy and SDK paths"
    );
    for surface in ["crates/tui/src/lib.rs", "crates/tauri-app/src/lib.rs"] {
        assert!(
            read_workspace_file(surface).contains("ConnectionProfile"),
            "{surface} no longer exposes the shared public connection boundary"
        );
    }
}

#[test]
fn high_risk_client_actions_keep_target_bound_confirmation() {
    let agentctl = read_workspace_file("crates/cli/src/bin/agentctl.rs");
    for contract in [
        "kill AGENT_ID --confirm AGENT_ID",
        "erase-agent AGENT_ID --confirm AGENT_ID",
        "erase-user USER_ID --confirm USER_ID",
        "erase-tenant TENANT_ID --confirm TENANT_ID",
        "require_target_confirmation(&mut args, &agent_id)",
        "require_target_confirmation(&mut args, &target)",
        "require_target_confirmation(&mut args, &user_id)",
        "require_target_confirmation(&mut args, &tenant_id)",
    ] {
        assert!(
            agentctl.contains(contract),
            "canonical CLI lost target-bound destructive contract {contract:?}"
        );
    }

    let tui = read_workspace_file("crates/tui/src/app.rs");
    for contract in [
        "Mode::ConfirmKill",
        "self.pending_kill = Some((agent.id.clone(), agent.name.clone()))",
        "will be force-stopped",
        "self.pending_kill.take()",
        "Mode::ConfirmServiceControl",
        "self.pending_service_control = Some(PendingServiceControl",
        "confirmation must exactly match",
        "may block dependent services",
        "can interrupt in-flight work",
    ] {
        assert!(
            tui.contains(contract),
            "TUI lost target-bound destructive contract {contract:?}"
        );
    }
}

#[test]
fn tui_tunable_controls_stay_revision_bound_on_the_public_wire_boundary() {
    let app = read_workspace_file("crates/tui/src/app.rs");
    for contract in [
        "Mode::SetTunable",
        "Mode::ConfirmTunableRollback",
        "expected_revision: target.revision",
        "target-revision|exact-name",
        "confirmation must exactly match",
        "value must be within",
    ] {
        assert!(
            app.contains(contract),
            "TUI tunable state lost revision/target contract {contract:?}"
        );
    }

    let binary = read_workspace_file("crates/tui/src/main.rs");
    for contract in [
        "client.set_operator_tunable(",
        "client.operator_tunable_audit(",
        "client.rollback_operator_tunable(",
        "app.set_tunable_audit(",
    ] {
        assert!(
            binary.contains(contract),
            "TUI tunable I/O lost public KernelClient contract {contract:?}"
        );
    }

    let integration = read_workspace_file("crates/tui/tests/refresh.rs");
    for contract in [
        "tunable_update_audit_and_rollback_use_the_public_tui_client",
        "stale TUI revision must fail closed",
        "revision-checked TUI rollback",
    ] {
        assert!(
            integration.contains(contract),
            "TUI tunable integration lost evidence {contract:?}"
        );
    }
}

#[test]
fn tui_package_controls_stay_exact_on_the_public_wire_boundary() {
    let app = read_workspace_file("crates/tui/src/app.rs");
    for contract in [
        "Mode::InstallPackage",
        "Mode::ConfirmPackageMutation",
        "expected_version: target.version",
        "expected_digest: target.digest",
        "confirmation must exactly match",
        "prevents new package runs",
    ] {
        assert!(
            app.contains(contract),
            "TUI package state lost exact-target contract {contract:?}"
        );
    }

    let binary = read_workspace_file("crates/tui/src/main.rs");
    for contract in [
        "client.install_package(",
        "client.run_installed_package(",
        "client.rollback_package_exact(",
        "client.remove_package_exact(",
    ] {
        assert!(
            binary.contains(contract),
            "TUI package I/O lost public KernelClient contract {contract:?}"
        );
    }

    let sdk = read_workspace_file("crates/sdk/src/lib.rs");
    let server = read_workspace_file("crates/kernel/src/syscall_server.rs");
    let registry = read_workspace_file("crates/kernel/src/package.rs");
    for contract in ["RollbackPackageExact", "RemovePackageExact"] {
        assert!(
            sdk.contains(contract) && server.contains(contract),
            "exact package mutation lost wire/SDK operation {contract:?}"
        );
    }
    for contract in [
        "rollback_exact",
        "remove_exact",
        "PackageError::Stale",
        "transaction_with_behavior(TransactionBehavior::Immediate)",
    ] {
        assert!(
            registry.contains(contract),
            "exact package mutation lost transactional contract {contract:?}"
        );
    }

    let integration = read_workspace_file("crates/tui/tests/refresh.rs");
    for contract in [
        "package_lifecycle_and_stale_confirmation_use_the_public_tui_client",
        "stale TUI confirmation must fail closed",
    ] {
        assert!(
            integration.contains(contract),
            "TUI package integration lost evidence {contract:?}"
        );
    }
}

#[test]
fn desktop_tunable_controls_stay_revision_bound_on_the_public_wire_boundary() {
    let protocol = read_workspace_file("docs/PROTOCOL.md");
    let normalized_protocol = protocol.split_whitespace().collect::<Vec<_>>().join(" ");
    for contract in [
        "freeze the displayed name and expected revision",
        "compare-and-set revision check",
        "requires the exact frozen tunable name",
    ] {
        assert!(
            normalized_protocol.contains(contract),
            "desktop tunable protocol lost {contract:?}"
        );
    }

    let backend = read_workspace_file("crates/tauri-app/src/lib.rs");
    for contract in [
        ".set_operator_tunable(name, value, expected_revision)",
        ".rollback_operator_tunable(name, target_revision, expected_revision)",
        ".operator_tunable_audit(name, limit)",
        "desktop_tunable_controls_and_audit_use_the_public_wire_client",
    ] {
        assert!(
            backend.contains(contract),
            "desktop tunable backend lost public client contract {contract:?}"
        );
    }

    let commands = read_workspace_file("crates/tauri-app/src/commands.rs");
    for contract in [
        "pub async fn set_operator_tunable",
        "pub async fn rollback_operator_tunable",
        "pub async fn operator_tunable_audit",
        "validate_tunable_rollback_confirmation(",
    ] {
        assert!(
            commands.contains(contract),
            "desktop tunable command surface lost {contract:?}"
        );
    }

    let main = read_workspace_file("crates/tauri-app/src/main.rs");
    for contract in [
        "commands::set_operator_tunable",
        "commands::rollback_operator_tunable",
        "commands::operator_tunable_audit",
    ] {
        assert!(
            main.contains(contract),
            "desktop shell stopped registering tunable command {contract:?}"
        );
    }

    let ui = read_workspace_file("crates/tauri-app/ui/src/lib/AgentStatus.svelte");
    for contract in [
        "expectedRevision: frozenTarget.revision",
        "confirmTunableName: frozenTarget.name",
        "Target revision|exact tunable name",
        "another operator changes the revision first",
    ] {
        assert!(
            ui.contains(contract),
            "desktop tunable UI lost frozen target contract {contract:?}"
        );
    }
}

#[test]
fn desktop_package_controls_stay_exact_on_the_public_wire_boundary() {
    let backend = read_workspace_file("crates/tauri-app/src/lib.rs");
    for contract in [
        ".install_package(name, requirement)",
        ".run_installed_package(name)",
        ".rollback_package_exact(name, expected_version, expected_digest)",
        ".remove_package_exact(name, expected_version, expected_digest)",
        "desktop_package_controls_use_exact_public_wire_mutations",
        "stale desktop package confirmation must fail closed",
    ] {
        assert!(
            backend.contains(contract),
            "desktop package backend lost public client contract {contract:?}"
        );
    }

    let commands = read_workspace_file("crates/tauri-app/src/commands.rs");
    let main = read_workspace_file("crates/tauri-app/src/main.rs");
    for command in [
        "list_installed_packages",
        "install_package",
        "run_installed_package",
        "rollback_installed_package",
        "remove_installed_package",
    ] {
        assert!(
            commands.contains(&format!("pub async fn {command}")),
            "desktop command surface lost {command:?}"
        );
        assert!(
            main.contains(&format!("commands::{command}")),
            "desktop shell stopped registering package command {command:?}"
        );
    }
    for contract in [
        "validate_exact_package_mutation(",
        "package mutation confirmation must exactly match version|package-name",
        "expected package digest must be a lowercase SHA-256 hex value",
    ] {
        assert!(
            commands.contains(contract),
            "desktop package IPC validation lost {contract:?}"
        );
    }

    let ui = read_workspace_file("crates/tauri-app/ui/src/lib/AgentStatus.svelte");
    for contract in [
        "expectedVersion: frozenTarget.version",
        "expectedDigest: frozenTarget.digest",
        "confirmPackageTarget: packageConfirmation",
        "Version|exact package name",
        "rejects a concurrent change",
        "prevents new runs from this package",
    ] {
        assert!(
            ui.contains(contract),
            "desktop package UI lost frozen target contract {contract:?}"
        );
    }
}

#[test]
fn reconnect_contract_is_bounded_and_fail_closed() {
    let protocol = read_workspace_file("docs/PROTOCOL.md");
    for contract in [
        "may then be replayed once.",
        "non-replayable by default",
        "Side-effecting requests are never replayed automatically.",
        "`SdkError::IndeterminateMutation`",
        "it does not resubmit the earlier mutation.",
    ] {
        assert!(
            protocol.contains(contract),
            "reconnect protocol lost fail-closed contract {contract:?}"
        );
    }

    let sdk = read_workspace_file("crates/sdk/src/lib.rs");
    for contract in [
        "fn safe_to_replay_after_reconnect",
        "Err(SdkError::IndeterminateMutation { operation, source })",
        "self.reconnect().await?",
    ] {
        assert!(
            sdk.contains(contract),
            "SDK reconnect implementation lost {contract:?}"
        );
    }
    assert!(
        read_workspace_file("crates/sdk/tests/reconnect.rs")
            .contains("reconnect_replays_reads_but_never_package_lifecycle_or_tool_mutations"),
        "response-loss duplicate-prevention regression was removed"
    );
}

#[test]
fn operator_ui_state_contract_is_visible_and_regressed() {
    let protocol = read_workspace_file("docs/PROTOCOL.md");
    for contract in [
        "**stale** with the transport error",
        "**partial**, not stale",
        "reconnected state",
        "renders the exact operation as in",
        "stable endpoint switching",
    ] {
        assert!(
            protocol.contains(contract),
            "operator UI protocol lost {contract:?}"
        );
    }

    let tui = read_workspace_file("crates/tui/src/app.rs");
    for contract in [
        "pub enum DataFreshness",
        "DataFreshness::Partial",
        "DataFreshness::Stale",
        "RECONNECTED #",
        "WORKING:",
    ] {
        assert!(
            tui.contains(contract),
            "TUI freshness state lost {contract:?}"
        );
    }
    let frontend = read_workspace_file("crates/tauri-app/ui/src/lib/operatorState.js");
    for contract in [
        "phase: 'stale'",
        "phase: warnings.length > 0 ? 'partial' : 'fresh'",
        "generation > state.reconnectGeneration",
        "operation: String(label)",
    ] {
        assert!(
            frontend.contains(contract),
            "desktop operator reducer lost {contract:?}"
        );
    }
    assert!(
        read_workspace_file("crates/tauri-app/ui/src/App.svelte")
            .contains("invoke('get_operator_view')"),
        "desktop UI no longer consumes the atomic operator view"
    );
    assert!(
        read_workspace_file("crates/tauri-app/tests/operator_reconnect.rs")
            .contains("desktop_operator_view_recovers_after_server_replacement"),
        "server-replacement UI regression was removed"
    );
    assert!(
        read_workspace_file(".github/workflows/ci.yml").contains("run: npm test"),
        "frontend operator state regressions are no longer blocking CI"
    );
}

#[test]
fn tui_stream_controls_stay_bounded_exact_and_on_the_public_wire_boundary() {
    let protocol = read_workspace_file("docs/PROTOCOL.md");
    for contract in [
        "The desktop and TUI use separate authenticated public-wire connections",
        "256-entry UI queue",
        "retains at most 64 KiB of UTF-8 turn text",
        "queues cancellation until registration is acknowledged",
        "frozen request/agent pair on the third connection",
    ] {
        assert!(
            protocol.contains(contract),
            "TUI stream protocol lost {contract:?}"
        );
    }

    let client = read_workspace_file("crates/tui/src/lib.rs");
    for contract in [
        "pub struct TuiMessageClient",
        "stream: Arc<Mutex<KernelClient>>",
        "cancellation: Arc<Mutex<KernelClient>>",
        ".send_message_stream(request_id, agent_id, message, on_event)",
        ".cancel_request(request_id, agent_id)",
    ] {
        assert!(
            client.contains(contract),
            "TUI message client lost public-wire contract {contract:?}"
        );
    }

    let app = read_workspace_file("crates/tui/src/app.rs");
    for contract in [
        "pub const MAX_MESSAGE_PREVIEW_BYTES: usize = 64 * 1024",
        "CancelMessageStream",
        "one agent turn is already active",
        "cancellation queued until the exact stream starts",
        "active_stream_matches",
        "EventsOmitted",
    ] {
        assert!(
            app.contains(contract),
            "TUI stream state lost bounded/exact contract {contract:?}"
        );
    }

    let binary = read_workspace_file("crates/tui/src/main.rs");
    for contract in [
        "const MAX_PENDING_MESSAGE_EVENTS: usize = 256",
        "message_client.cancel_request",
        "event_updates.try_send(update)",
        "updates.send(terminal).await",
        "Duration::from_millis(50)",
    ] {
        assert!(
            binary.contains(contract),
            "TUI stream event loop lost responsive/bounded contract {contract:?}"
        );
    }

    let integration = read_workspace_file("crates/tui/tests/streaming.rs");
    for contract in [
        "tui_stream_keeps_refresh_live_and_cancels_on_an_exact_dedicated_connection",
        "ordinary operator connection was blocked by stream",
        "wrong cancellation must not stop the live stream",
        "WireErrorCode::Cancelled",
    ] {
        assert!(
            integration.contains(contract),
            "TUI live stream regression lost evidence {contract:?}"
        );
    }
}

#[test]
fn tui_checkpoint_controls_stay_agent_bound_and_on_the_public_wire_boundary() {
    let protocol = read_workspace_file("docs/PROTOCOL.md");
    for contract in [
        "Desktop and TUI checkpoint list, explicit resume, and explicit delete",
        "rejects any cross-agent entry before rendering it",
        "clears the projection when agent selection changes",
        "requires the full checkpoint identifier",
    ] {
        assert!(
            protocol.contains(contract),
            "TUI checkpoint protocol lost {contract:?}"
        );
    }

    let app = read_workspace_file("crates/tui/src/app.rs");
    for contract in [
        "LoadGenerationCheckpoints",
        "ResumeGenerationCheckpoint",
        "DeleteGenerationCheckpoint",
        "checkpoint.agent_id == agent_id",
        "clear_checkpoint_projection_if_selection_changed",
        "confirmation must exactly match",
        "MAX_MESSAGE_PREVIEW_BYTES",
    ] {
        assert!(
            app.contains(contract),
            "TUI checkpoint state lost agent-bound/exact contract {contract:?}"
        );
    }

    let binary = read_workspace_file("crates/tui/src/main.rs");
    for contract in [
        "client.list_generation_checkpoints",
        "client.resume_generation_checkpoint",
        "client.delete_generation_checkpoint",
        "app.checkpoint_resumed",
        "app.checkpoint_deleted",
    ] {
        assert!(
            binary.contains(contract),
            "TUI checkpoint event loop lost public-client contract {contract:?}"
        );
    }

    let integration = read_workspace_file("crates/tui/tests/checkpoints.rs");
    for contract in [
        "tui_checkpoint_list_resume_and_exact_delete_use_the_authenticated_public_client",
        "pause through public TUI client",
        "explicit public checkpoint resume",
        "exact public checkpoint delete",
    ] {
        assert!(
            integration.contains(contract),
            "TUI live checkpoint regression lost evidence {contract:?}"
        );
    }
}

#[test]
fn desktop_stream_and_checkpoint_controls_stay_on_the_public_wire_boundary() {
    let protocol = read_workspace_file("docs/PROTOCOL.md");
    for contract in [
        "separate authenticated public-wire connections",
        "cannot hold the operator snapshot path",
        "freezes the request and agent identifiers",
        "requires the full checkpoint identifier",
    ] {
        assert!(
            protocol.contains(contract),
            "desktop stream/checkpoint protocol lost {contract:?}"
        );
    }

    let backend = read_workspace_file("crates/tauri-app/src/lib.rs");
    for contract in [
        "stream: Mutex<KernelClient>",
        "cancellation: Mutex<KernelClient>",
        ".send_message_stream(request_id, agent_id, message, on_event)",
        ".cancel_request(request_id, agent_id)",
        ".list_generation_checkpoints(agent_id)",
        ".resume_generation_checkpoint(agent_id, checkpoint_id)",
        ".delete_generation_checkpoint(agent_id, checkpoint_id)",
        "desktop_stream_keeps_refresh_live_and_cancels_on_a_dedicated_connection",
    ] {
        assert!(
            backend.contains(contract),
            "desktop public-wire backend lost {contract:?}"
        );
    }

    let commands = read_workspace_file("crates/tauri-app/src/commands.rs");
    for contract in [
        "Channel<agent_sdk::MessageStreamEvent>",
        "pub async fn cancel_message",
        "pub async fn list_checkpoints",
        "pub async fn resume_checkpoint",
        "pub async fn delete_checkpoint",
        "validate_checkpoint_deletion_confirmation(&checkpoint_id, &confirm_checkpoint_id)",
    ] {
        assert!(
            commands.contains(contract),
            "desktop command surface lost {contract:?}"
        );
    }

    let chat = read_workspace_file("crates/tauri-app/ui/src/lib/ChatPanel.svelte");
    assert!(chat.contains("invoke('stream_message'"));
    assert!(chat.contains("invoke('cancel_message'"));
    assert!(chat.contains("requestId: target.requestId"));
    assert!(chat.contains("agentId: target.agentId"));

    let detail = read_workspace_file("crates/tauri-app/ui/src/lib/AgentDetail.svelte");
    assert!(detail.contains("pendingCheckpointDelete.agentId"));
    assert!(detail.contains("pendingCheckpointDelete.checkpointId"));
    assert!(
        detail.contains("checkpointDeleteConfirmation !== pendingCheckpointDelete.checkpointId")
    );
}

#[test]
fn tui_and_desktop_system_audits_stay_bounded_and_on_the_public_wire_boundary() {
    let protocol = read_workspace_file("docs/PROTOCOL.md");
    let normalized_protocol = protocol.split_whitespace().collect::<Vec<_>>().join(" ");
    for contract in [
        "System audit views",
        "three bounded sequential public-API reads",
        "not an atomic cross-ledger snapshot",
        "retain the last successfully loaded projection",
    ] {
        assert!(
            normalized_protocol.contains(contract),
            "operator system-audit protocol lost {contract:?}"
        );
    }

    let tui_app = read_workspace_file("crates/tui/src/app.rs");
    for contract in [
        "LoadSystemAudit",
        "set_system_audits(",
        "system_audit_loaded",
        "cluster_certificate_rollout_audit_loaded",
        "sequential, not atomic",
    ] {
        assert!(
            tui_app.contains(contract),
            "TUI system-audit state lost {contract:?}"
        );
    }
    let tui_binary = read_workspace_file("crates/tui/src/main.rs");
    for contract in [
        ".node_control_audit(SYSTEM_AUDIT_LIMIT)",
        ".cluster_membership_audit(SYSTEM_AUDIT_LIMIT)",
        ".cluster_certificate_rollout_audit(SYSTEM_AUDIT_LIMIT)",
        "app.set_system_audits(",
        ".map_err(|error| error.to_string())",
    ] {
        assert!(
            tui_binary.contains(contract),
            "TUI system-audit I/O lost public-client contract {contract:?}"
        );
    }
    let tui_integration = read_workspace_file("crates/tui/tests/system_audit.rs");
    for contract in [
        "tui_system_audits_use_the_authenticated_public_client",
        "TUI system-audit regression",
        "tenant admin cannot read global node audit",
        "WireErrorCode::AuthorizationDenied",
    ] {
        assert!(
            tui_integration.contains(contract),
            "TUI live system-audit regression lost {contract:?}"
        );
    }

    let desktop_backend = read_workspace_file("crates/tauri-app/src/lib.rs");
    for contract in [
        "pub struct DesktopSystemAuditView",
        "pub async fn system_audit(&self, limit: usize)",
        ".node_control_audit(limit)",
        ".cluster_membership_audit(limit)",
        ".cluster_certificate_rollout_audit(limit)",
        "desktop_system_audits_use_the_public_wire_client_and_preserve_authorization",
    ] {
        assert!(
            desktop_backend.contains(contract),
            "desktop system-audit backend lost {contract:?}"
        );
    }
    let commands = read_workspace_file("crates/tauri-app/src/commands.rs");
    assert!(commands.contains("pub async fn get_system_audit"));
    assert!(commands.contains("validate_system_audit_limit(limit)?"));
    assert!(commands.contains("system audit limit must be between 1 and 200"));
    let main = read_workspace_file("crates/tauri-app/src/main.rs");
    assert!(main.contains("commands::get_system_audit"));
    let ui = read_workspace_file("crates/tauri-app/ui/src/lib/AgentStatus.svelte");
    for contract in [
        "invoke('get_system_audit', { limit: 50 })",
        "bounded sequential public-API reads, not an atomic cross-ledger",
        "showing the last successfully loaded audit",
        "Certificate-rollout history",
    ] {
        assert!(
            ui.contains(contract),
            "desktop system-audit UI lost {contract:?}"
        );
    }
}

#[test]
fn desktop_service_controls_stay_target_bound_on_the_public_wire_boundary() {
    let protocol = read_workspace_file("docs/PROTOCOL.md");
    let normalized_protocol = protocol.split_whitespace().collect::<Vec<_>>().join(" ");
    for contract in [
        "desktop service controls",
        "authenticated public-wire connection",
        "require the exact service name",
        "cannot retarget an open confirmation",
    ] {
        assert!(
            normalized_protocol.contains(contract),
            "desktop service protocol lost {contract:?}"
        );
    }

    let backend = read_workspace_file("crates/tauri-app/src/lib.rs");
    for contract in [
        ".start_service(name)",
        ".stop_service(name)",
        ".restart_service(name)",
        ".service_history(name, limit)",
        "desktop_service_controls_and_history_use_the_public_wire_client",
    ] {
        assert!(
            backend.contains(contract),
            "desktop service backend lost {contract:?}"
        );
    }

    let commands = read_workspace_file("crates/tauri-app/src/commands.rs");
    for contract in [
        "pub async fn start_service",
        "pub async fn stop_service",
        "pub async fn restart_service",
        "pub async fn service_history",
        "validate_service_control_confirmation(&service_name, &confirm_service_name)",
    ] {
        assert!(
            commands.contains(contract),
            "desktop service command surface lost {contract:?}"
        );
    }

    let status = read_workspace_file("crates/tauri-app/ui/src/lib/AgentStatus.svelte");
    for contract in [
        "const frozenTarget = { ...target }",
        "confirmServiceName = serviceConfirmation",
        "serviceConfirmation !== pendingServiceControl.name",
        "may block dependent services",
        "can interrupt in-flight work",
    ] {
        assert!(
            status.contains(contract),
            "desktop service UI lost {contract:?}"
        );
    }
}

#[test]
fn desktop_accessibility_baseline_is_explicit_and_honest() {
    let qualification = read_workspace_file("docs/ACCESSIBILITY.md");
    let normalized_qualification = qualification
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    for contract in [
        "targets **WCAG 2.2 Level AA**",
        "not a completed certification claim",
        "`svelte-check --fail-on-warnings`",
        "Playwright Chromium",
        "`@axe-core/playwright`",
        "320 CSS-pixel viewport",
        "exact native-webview testing",
        "do not replace assistive-technology testing",
        "Narrator on Windows",
        "VoiceOver on macOS",
        "remains below Production-qualified",
    ] {
        assert!(
            normalized_qualification.contains(contract),
            "desktop accessibility qualification lost {contract:?}"
        );
    }

    let app = read_workspace_file("crates/tauri-app/ui/src/App.svelte");
    for contract in [
        "Skip to main content",
        ":global(:focus-visible)",
        "@media (prefers-reduced-motion: reduce)",
    ] {
        assert!(
            app.contains(contract),
            "desktop shell lost accessibility contract {contract:?}"
        );
    }

    let status = read_workspace_file("crates/tauri-app/ui/src/lib/AgentStatus.svelte");
    assert!(
        status.contains("This view is not an event history."),
        "desktop agent-status view must disclose its snapshot scope"
    );
    for fabricated in ["Simulated activity feed", "time: 'now'", "Activity Feed"] {
        assert!(
            !status.contains(fabricated),
            "desktop must not present fabricated activity contract {fabricated:?}"
        );
    }

    let frontend_test = read_workspace_file("crates/tauri-app/ui/src/lib/accessibility.test.js");
    assert!(
        frontend_test.contains("no fabricated activity"),
        "frontend accessibility source-contract regression was removed"
    );
    assert!(
        read_workspace_file(".github/workflows/ci.yml")
            .contains("Svelte types and accessibility warnings are errors"),
        "Svelte accessibility diagnostics are no longer blocking CI"
    );
    let rendered = read_workspace_file("crates/tauri-app/ui/tests/rendered/accessibility.spec.js");
    for contract in [
        "AxeBuilder",
        "Skip to main content",
        "setup dialog is named, axe-clean, and contains keyboard focus",
        "width: 320",
        "reducedMotion: 'reduce'",
    ] {
        assert!(
            rendered.contains(contract),
            "rendered desktop accessibility regression lost {contract:?}"
        );
    }
    let workflow = read_workspace_file(".github/workflows/ci.yml");
    for contract in [
        "npx playwright install --with-deps chromium",
        "npm run test:a11y",
    ] {
        assert!(
            workflow.contains(contract),
            "rendered desktop accessibility gate is no longer blocking CI: {contract:?}"
        );
    }
}

#[test]
fn desktop_release_foundation_is_versioned_and_fail_closed() {
    let distribution = read_workspace_file("docs/DESKTOP_DISTRIBUTION.md");
    let normalized_distribution = distribution
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    for contract in [
        "**qualification artifacts only**",
        "Production requirement still open",
        "do not replace native platform signing",
        "signed-updater foundation",
        "TAURI_SIGNING_PRIVATE_KEY",
        "automatic downgrade is not enabled",
        "public `v*` tag is deliberately rejected",
        "failed-update, and operator-led rollback evidence",
    ] {
        assert!(
            normalized_distribution.contains(contract),
            "desktop distribution contract lost {contract:?}"
        );
    }

    let release = read_workspace_file(".github/workflows/release.yml");
    for contract in [
        "desktop-release-contract:",
        "python3 scripts/verify_desktop_release.py",
        "if: startsWith(github.ref, 'refs/tags/v')",
        "exit 1",
        "bundles: deb,appimage",
        "bundles: app,dmg",
        "bundles: msi,nsis",
        "OPENSSL_SRC_PERL: ${{ matrix.perl }}",
        "perl: C:/Strawberry/perl/bin/perl.exe",
        "CARGO_TARGET_DIR=target-repro cargo build",
        "mv target-repro target-a",
        "TAURI_SIGNING_PRIVATE_KEY: ${{ secrets.TAURI_SIGNING_PRIVATE_KEY }}",
        "TAURI_SIGNING_PRIVATE_KEY_PASSWORD: ${{ secrets.TAURI_SIGNING_PRIVATE_KEY_PASSWORD }}",
        "Require the protected updater signing identity",
        "cargo tauri build --ci --bundles",
        "scripts/build_desktop_update_manifest.py",
        "--output dist/latest.json",
        "release-desktop-${{ matrix.platform }}",
    ] {
        assert!(
            release.contains(contract),
            "desktop release workflow lost {contract:?}"
        );
    }
    assert!(
        !release.contains("CARGO_TARGET_DIR=target-b"),
        "release builds must not embed a different target path in the second binary"
    );
    assert!(
        !release.contains("cargo tauri build --ci --no-sign"),
        "desktop release qualification must never suppress updater signatures"
    );

    let verifier = read_workspace_file("scripts/verify_desktop_release.py");
    for contract in [
        "member_versions",
        "release tag",
        "REQUIRED_PNGS",
        "icon.ico",
        "icon.icns",
        "createUpdaterArtifacts",
        "updater public key",
        "dangerousInsecureTransportProtocol",
        "desktop updater plugin must remain exactly pinned",
    ] {
        assert!(
            verifier.contains(contract),
            "desktop release verifier lost {contract:?}"
        );
    }

    let tauri_config = read_workspace_file("crates/tauri-app/tauri.conf.json");
    for contract in [
        "\"createUpdaterArtifacts\": true",
        "https://github.com/surya-koritala/AIagentOS/releases/latest/download/latest.json",
        "\"installMode\": \"passive\"",
    ] {
        assert!(
            tauri_config.contains(contract),
            "desktop updater configuration lost {contract:?}"
        );
    }

    let updater_test = read_workspace_file("crates/tauri-app/tests/updater_signature.rs");
    for contract in [
        "checked_in_updater_identity_verifies_a_real_tauri_signature",
        "tampered updater bytes must fail signature verification",
    ] {
        assert!(
            updater_test.contains(contract),
            "desktop updater signature regression lost {contract:?}"
        );
    }

    let commands = read_workspace_file("crates/tauri-app/src/commands.rs");
    for contract in [
        "expected_version",
        "the available update changed",
        "download_and_install",
        "signed update verification or installation failed",
    ] {
        assert!(
            commands.contains(contract),
            "desktop updater IPC contract lost {contract:?}"
        );
    }

    let settings = read_workspace_file("crates/tauri-app/ui/src/lib/Settings.svelte");
    for contract in [
        "Confirm update {availableUpdate.version}",
        "invoke('install_update', { expectedVersion })",
        "Automatic downgrade is not available",
    ] {
        assert!(
            settings.contains(contract),
            "desktop updater review flow lost {contract:?}"
        );
    }

    let ci = read_workspace_file(".github/workflows/ci.yml");
    assert!(
        ci.contains("cargo test -p tauri-app --all-targets --locked"),
        "desktop updater signature regression is no longer exercised on platform CI"
    );
}

#[test]
fn restricted_linux_cli_rc_release_contract_is_fail_closed() {
    let stable = read_workspace_file(".github/workflows/release.yml");
    assert!(
        stable.contains("- \"!v*-rc.*\""),
        "stable all-platform publication must not consume restricted RC tags"
    );

    let workflow = read_workspace_file(".github/workflows/linux-cli-rc.yml");
    for contract in [
        "- \"v*-rc.*\"",
        "uses: ./.github/workflows/ci.yml",
        "governance:",
        "reproducible-linux:",
        "cmp -s",
        "python3 scripts/build_cli_archive.py",
        "sign-runtime:",
        "cosign sign-blob",
        "attest-build-provenance@",
        "fresh-host:",
        "scripts/linux_cli_rc_qualification.py qualify",
        "--released-schema-tag v0.3.0",
        "finalize:",
        "scripts/linux_cli_rc_qualification.py validate-report",
        "Signed candidate bundle awaiting Phase 1 promotion",
        "qualified-linux-cli-rc-bundle",
    ] {
        assert!(
            workflow.contains(contract),
            "restricted Linux CLI RC workflow lost {contract:?}"
        );
    }
    for forbidden in [
        "pull_request_target",
        "self-hosted",
        "continue-on-error: true",
        "AGENT_SERVER_ALLOW_INSECURE_REMOTE",
        "gh release create",
    ] {
        assert!(
            !workflow.contains(forbidden),
            "restricted Linux CLI RC workflow contains unsafe {forbidden:?}"
        );
    }

    let qualifier = read_workspace_file("scripts/linux_cli_rc_qualification.py");
    for contract in [
        "vX.Y.Z-rc.N",
        "EXPECTED_ARCHIVE_NAMES",
        "archive contains duplicate entries",
        "storage-encrypt",
        "AGENT_SERVER_TLS_CERT",
        "AGENTOS_TLS_CA",
        "wrong-token",
        "backup-anchor-create",
        "tampered-backup",
        "missing-storage-key.json",
        "backup-disaster-recover",
        "\"enforcement_rearmed\": True",
        "\"production_claim_allowed\": False",
        "deny-self-hosted-runners",
    ] {
        assert!(
            qualifier.contains(contract),
            "restricted Linux CLI qualifier lost {contract:?}"
        );
    }

    let guide = read_workspace_file("docs/LINUX_CLI_RC.md");
    for contract in [
        "Ubuntu 22.04 x86_64",
        "sha256sum --check SHA256SUMS",
        "--certificate-identity \"$identity\"",
        "production_claim_allowed",
        "backup-disaster-recover",
        "\"enforcement_rearmed\": true",
        "remote immutable-backup or measured RPO/RTO",
    ] {
        assert!(
            guide.contains(contract),
            "restricted Linux CLI operator guide lost {contract:?}"
        );
    }
}

#[test]
fn phase1_promotion_contract_is_exact_reviewed_and_fail_closed() {
    let tag_workflow = read_workspace_file(".github/workflows/linux-cli-rc.yml");
    assert!(
        !tag_workflow.contains("gh release create"),
        "tag workflow must retain the signed candidate without publishing it"
    );

    let workflow = read_workspace_file(".github/workflows/phase1-promotion-qualification.yml");
    for contract in [
        "workflow_dispatch:",
        "release_candidate:",
        "linux_cli_rc_run_id:",
        "phase1_campaign_run_id:",
        "phase1_review_run_id:",
        "environment_id:",
        "profile: phase1-promotion",
        "enabled: ${{ vars.AGENTOS_CAPACITY_QUALIFICATION_ENABLED }}",
        "runs-on: [self-hosted, linux, x64, agentos-capacity]",
        "environment: capacity-qualification",
        "PHASE1_CAMPAIGN_RUN_ID: ${{ inputs.phase1_campaign_run_id }}",
        "test \"$GITHUB_REF\" = \"refs/tags/${AGENTOS_RELEASE_CANDIDATE}\"",
        ".github/workflows/linux-cli-rc.yml",
        "test \"$(jq -r .conclusion <<<\"$metadata\")\" = \"success\"",
        "name: qualified-linux-cli-rc-bundle",
        "cmp \"$report\" \"$evidence_report\"",
        "scripts/linux_cli_rc_qualification.py validate-report",
        "scripts/phase1_campaign_provenance.py",
        "scripts/phase1_promotion_qualification.py",
        "scripts/phase1_workflow_provenance.py",
        "scripts/phase1_review_provenance.py",
        "actions/runs/${run_id}/attempts/${run_attempt}",
        "gh run download \"$run_id\"",
        "--campaign-provenance",
        "--workflow-provenance",
        "--review-provenance",
        "phase1-campaign-provenance.json",
        "phase1-workflow-provenance.json",
        "phase1-review-provenance.json",
        "github_campaign_workflow_provenance_verified",
        "keyless_campaign_signature_verified",
        "github_workflow_provenance_verified",
        "github_artifact_bytes_verified",
        "reviewer_identity_authenticated",
        "keyless_review_signature_verified",
        "phase1-independent-review/phase1-review.json",
        "--require-eligible",
        "phase1_release_candidate_ready",
        "production_claim_allowed",
        "needs: exact-release-candidate-promotion",
        "cosign verify-blob",
        "cosign sign-blob",
        "attest-build-provenance@",
        "gh release create",
        "--prerelease",
        "--verify-tag",
    ] {
        assert!(
            workflow.contains(contract),
            "Phase 1 promotion workflow lost {contract:?}"
        );
    }
    let publish = workflow
        .split_once("  publish:")
        .expect("Phase 1 workflow lost gated publish job")
        .1;
    assert!(
        publish.contains("needs: exact-release-candidate-promotion")
            && publish.contains("gh release create"),
        "publication must remain downstream of the exact Phase 1 decision"
    );

    let qualifier = read_workspace_file("scripts/phase1_promotion_qualification.py");
    for contract in [
        "restricted_phase1_evidence_campaign",
        "independent_restricted_phase1_promotion_review",
        "restricted_phase1_promotion_decision",
        "single-node-linux-rootless-container-cli",
        "Phase 1 promotion requires both Ollama and vLLM",
        "Phase 1 promotion requires at least one hosted provider",
        "live provider plan and provider reports must come from one run",
        "release SLO does not bind the retained resource soak",
        "review does not bind the exact campaign bytes",
        "review provenance does not bind the exact review bytes",
        "campaign provenance does not bind the exact campaign bytes",
        "\"phase1_release_candidate_ready\": ready",
        "\"production_claim_allowed\": False",
    ] {
        assert!(
            qualifier.contains(contract),
            "Phase 1 promotion evaluator lost {contract:?}"
        );
    }

    let campaign_workflow = read_workspace_file(".github/workflows/phase1-campaign-assembly.yml");
    for contract in [
        "run_ids_json:",
        "promoted_providers_json:",
        "test \"$GITHUB_RUN_ATTEMPT\" = \"1\"",
        "scripts/phase1_campaign_assembly.py",
        "scripts/phase1_campaign_provenance.py",
        "actions/runs/${run_id}/attempts/${run_attempt}",
        "gh run download \"$run_id\"",
        "cosign sign-blob --yes",
        "actions/attest-build-provenance@",
        "phase1-campaign-${{ inputs.release_candidate }}-${{ github.sha }}",
    ] {
        assert!(
            campaign_workflow.contains(contract),
            "Phase 1 campaign workflow lost {contract:?}"
        );
    }
    assert!(
        !campaign_workflow.contains("self-hosted")
            && !campaign_workflow.contains("contents: write"),
        "campaign assembly must remain hosted and read-only"
    );

    let campaign_builder = read_workspace_file("scripts/phase1_campaign_assembly.py");
    for contract in [
        "restricted_phase1_campaign_assembly_request",
        "campaign request run IDs must be unique",
        "workflow did not complete successfully",
        "does not match trusted repository",
        "downloaded artifact inventory differs from assembly plan",
        "\"operator_ids\": operators",
    ] {
        assert!(
            campaign_builder.contains(contract),
            "Phase 1 campaign builder lost {contract:?}"
        );
    }

    let campaign_provenance = read_workspace_file("scripts/phase1_campaign_provenance.py");
    for contract in [
        "restricted_phase1_campaign_provenance",
        "campaign assembly must use a fresh workflow dispatch",
        "is absent from campaign operators",
        "downloaded campaign artifact inventory differs from contract",
        "keyless campaign signature verification failed",
        "\"github_campaign_workflow_provenance_verified\": True",
        "\"github_campaign_artifact_bytes_verified\": True",
        "\"keyless_campaign_signature_verified\": True",
    ] {
        assert!(
            campaign_provenance.contains(contract),
            "Phase 1 campaign provenance verifier lost {contract:?}"
        );
    }

    let provenance = read_workspace_file("scripts/phase1_workflow_provenance.py");
    for contract in [
        "restricted_phase1_github_provenance_plan",
        "restricted_phase1_github_provenance",
        "campaign Linux CLI run does not match the downloaded signed bundle run",
        "GitHub run attempt does not match the campaign",
        "GitHub workflow path does not match the campaign",
        "GitHub workflow head SHA does not match the campaign",
        "GitHub workflow updated_at does not match the campaign",
        "does not match the trusted repository",
        "downloaded and protected bytes differ",
        "\"github_workflow_provenance_verified\": True",
        "\"github_artifact_bytes_verified\": True",
        "\"production_claim_allowed\": False",
    ] {
        assert!(
            provenance.contains(contract),
            "Phase 1 provenance verifier lost {contract:?}"
        );
    }

    let review_workflow = read_workspace_file(".github/workflows/phase1-independent-review.yml");
    for contract in [
        "profile: phase1-independent-review",
        "runs-on: [self-hosted, linux, x64, agentos-review]",
        "environment: phase1-review",
        "phase1_campaign_run_id:",
        "scripts/phase1_campaign_provenance.py",
        "test \"$GITHUB_RUN_ATTEMPT\" = \"1\"",
        "--actor \"$GITHUB_ACTOR\"",
        "scripts/phase1_independent_review.py",
        "cosign sign-blob --yes",
        "actions/attest-build-provenance@",
        "phase1-independent-review-${{ inputs.release_candidate }}-${{ github.sha }}",
    ] {
        assert!(
            review_workflow.contains(contract),
            "Phase 1 independent-review workflow lost {contract:?}"
        );
    }

    let review_builder = read_workspace_file("scripts/phase1_independent_review.py");
    for contract in [
        "independent_restricted_phase1_review_observation",
        "review observation reviewer does not match authenticated GitHub actor",
        "authenticated GitHub reviewer is not independent",
        "independent review must use a fresh workflow dispatch",
        "\"review_attestation_sha256\": observation_sha",
    ] {
        assert!(
            review_builder.contains(contract),
            "Phase 1 independent-review builder lost {contract:?}"
        );
    }

    let review_provenance = read_workspace_file("scripts/phase1_review_provenance.py");
    for contract in [
        "restricted_phase1_independent_review_provenance",
        "for field in (\"actor\", \"triggering_actor\")",
        "does not match signed reviewer",
        "downloaded independent review bytes differ",
        "cosign",
        "\"reviewer_identity_authenticated\": True",
        "\"github_review_workflow_provenance_verified\": True",
        "\"github_review_artifact_bytes_verified\": True",
        "\"keyless_review_signature_verified\": True",
    ] {
        assert!(
            review_provenance.contains(contract),
            "Phase 1 independent-review provenance verifier lost {contract:?}"
        );
    }
}

#[test]
fn release_blocking_workflows_keep_their_security_contract() {
    let ci = read_workspace_file(".github/workflows/ci.yml");
    for os in ["ubuntu-latest", "macos-latest", "windows-latest"] {
        assert!(ci.contains(os), "blocking CI must retain the {os} runner");
    }
    for required_job in [
        "- quality",
        "- capability-governance",
        "- rust-platforms",
        "- desktop-platforms",
        "- frontend",
        "- rust-supply-chain",
        "- coverage",
        "- container-smoke",
    ] {
        assert!(
            ci.contains(required_job),
            "required release gate lost {required_job}"
        );
    }

    // Capability-ownership governance queries the live GitHub issue API, so it
    // must never gate the jobs that produce compile and cross-platform test
    // evidence: a closed tracking issue (or a transient API failure) previously
    // skipped the whole macOS/Windows matrix and left a release candidate with
    // no platform evidence at all.
    assert!(
        ci.contains("  capability-governance:\n"),
        "capability-ownership governance must stay an independent job"
    );
    let platform_matrix = ci
        .split_once("  rust-platforms:\n")
        .expect("blocking CI must retain the rust-platforms matrix")
        .1
        .split_once("  desktop-platforms:")
        .expect("blocking CI must retain the desktop-platforms matrix")
        .0;
    assert!(
        !platform_matrix.contains("needs:"),
        "the cross-platform test matrix must not depend on any other job"
    );
    for command in [
        "cargo fmt --all -- --check",
        "cargo clippy --workspace --exclude tauri-app --all-targets -- -D warnings",
        "RUSTDOCFLAGS: -D warnings",
        "mdbook build docs",
        "npm ci",
        "npm audit --audit-level=high",
        "npm run check",
        "advisories bans licenses sources",
        "verify_workflow_action_pins.py --remote",
        "check_critical_coverage.py lcov.info",
        "\"storage_get\"",
    ] {
        assert!(
            ci.contains(command),
            "blocking CI lost required command or proof {command:?}"
        );
    }

    let extended = read_workspace_file(".github/workflows/extended-security.yml");
    for proof in [
        "schedule:",
        "RUSTUP_TOOLCHAIN: nightly-2026-07-20",
        "Exact-commit deterministic fault matrix",
        "RUSTUP_TOOLCHAIN: 1.97.1",
        "--bin resilience-qualification -- --validate",
        "--all --output target/qualification/deterministic-fault-matrix.json",
        "deterministic-fault-matrix-${{ github.sha }}",
        "all(.scenarios[].checks[]; . == true)",
        "rootless-sandbox-crash-${{ github.sha }}",
        "literal_argv_no_implicit_shell",
        "stdout_limit_enforced",
        "hung_process_cleanup",
        "Provider core live-path security controls",
        "Install the lockfile-pinned Chromium qualification runtime",
        "live_browser_denies_downloads_isolates_sessions_and_removes_profiles",
        "browser_profiles_isolated_and_cleaned",
        "browser_sha256=",
        "Google Chrome for Testing|Chromium",
        "kernel_browser_provider_unavailable",
        "live_linux_provider_security_core",
        "scripts/provider_core_qualification.py",
        "provider-core-${{ github.sha }}",
        "Live network SSRF and DNS-rebinding controls",
        "--features qualification",
        "sandbox::tests::live_network_egress_blocks_ssrf_redirects_and_dns_rebinding",
        "network-egress-${{ github.sha }}",
        "live_linux_network_egress",
        "Aggregate exact-commit provider security suite",
        "provider-security-suite-${{ github.sha }}",
        "combined_live_linux_provider_security",
        "MIRIFLAGS: -Zmiri-disable-isolation",
        "cargo miri test",
        "-Zsanitizer=address",
        "cargo fuzz build --target x86_64-unknown-linux-gnu",
        "cargo fuzz run wire_syscall --target x86_64-unknown-linux-gnu",
        "cargo fuzz run wire_transport --target x86_64-unknown-linux-gnu",
        "-max_len=262144",
        "timeout-minutes: 25",
    ] {
        assert!(
            extended.contains(proof),
            "extended security workflow lost {proof:?}"
        );
    }

    let incident = read_workspace_file(".github/workflows/incident-drill-qualification.yml");
    for proof in [
        "pull_request:",
        "QUALIFICATION_SHA: ${{ github.event.pull_request.head.sha || github.sha }}",
        "ref: ${{ env.QUALIFICATION_SHA }}",
        "Exact-commit automated incident technical controls",
        "python3 scripts/incident_drill_qualification.py --validate",
        "--output target/qualification/incident-drill.json",
        "automated_incident_drill_fixture",
        "automated_technical_controls_only",
        "human_game_day_completed",
        "game_day_proof_eligible",
        "incident-drill-${{ env.QUALIFICATION_SHA }}",
        "retention-days: 90",
    ] {
        assert!(
            incident.contains(proof),
            "incident qualification workflow lost {proof:?}"
        );
    }
    for scenario in [
        "credential-compromise",
        "tenant-leak",
        "malicious-package",
        "node-loss",
        "corrupt-database",
        "provider-outage",
    ] {
        assert!(
            incident.contains(scenario),
            "incident qualification workflow lost scenario {scenario:?}"
        );
    }

    let protected_plan = read_workspace_file("scripts/protected_qualification_plan.py");
    let protected_preflight =
        read_workspace_file(".github/workflows/protected-qualification-plan.yml");
    for proof in [
        "protected_external_dispatch_plan",
        "dispatch_configuration_only",
        "\"infrastructure_verified\": False",
        "\"production_claim_allowed\": False",
        "AGENTOS_CAPACITY_QUALIFICATION_ENABLED",
        "AGENTOS_MODEL_QUALIFICATION_ENABLED",
        "AGENTOS_DESTRUCTIVE_STORAGE_QUALIFICATION_ENABLED",
        "AGENTOS_EXTERNAL_DATA_QUALIFICATION_ENABLED",
        "AGENTOS_PHASE1_REVIEW_ENABLED",
        "capacity-qualification",
        "model-qualification",
        "destructive-storage-qualification",
        "external-data-qualification",
        "phase1-review",
        "agentos-capacity",
        "agentos-model",
        "agentos-destructive-storage",
        "agentos-external-data",
        "agentos-review",
    ] {
        assert!(
            protected_plan.contains(proof),
            "protected qualification plan lost {proof:?}"
        );
    }
    for proof in [
        "workflow_call:",
        "runs-on: ubuntu-latest",
        "protected_qualification_plan.py",
        "protected-qualification-plan-${{ inputs.profile }}-${{ github.sha }}",
        "retention-days: 30",
        "Require explicit protected dispatch enablement",
    ] {
        assert!(
            protected_preflight.contains(proof),
            "protected qualification preflight lost {proof:?}"
        );
    }
    assert!(
        !protected_preflight.contains("secrets.") && !protected_preflight.contains("vars."),
        "hosted preflight must receive only the caller's non-secret enable input"
    );
    for (workflow, profile, enable_variable) in [
        (
            ".github/workflows/capacity-qualification.yml",
            "capacity-baseline",
            "AGENTOS_CAPACITY_QUALIFICATION_ENABLED",
        ),
        (
            ".github/workflows/resource-soak-qualification.yml",
            "resource-soak",
            "AGENTOS_CAPACITY_QUALIFICATION_ENABLED",
        ),
        (
            ".github/workflows/target-remote-backup-qualification.yml",
            "target-remote-backup",
            "AGENTOS_CAPACITY_QUALIFICATION_ENABLED",
        ),
        (
            ".github/workflows/release-slo-qualification.yml",
            "release-slo",
            "AGENTOS_CAPACITY_QUALIFICATION_ENABLED",
        ),
        (
            ".github/workflows/game-day-qualification.yml",
            "game-day",
            "AGENTOS_CAPACITY_QUALIFICATION_ENABLED",
        ),
        (
            ".github/workflows/on-device-qualification.yml",
            "on-device",
            "AGENTOS_MODEL_QUALIFICATION_ENABLED",
        ),
        (
            ".github/workflows/phase1-independent-review.yml",
            "phase1-independent-review",
            "AGENTOS_PHASE1_REVIEW_ENABLED",
        ),
        (
            ".github/workflows/storage-profile-qualification.yml",
            "storage-profile",
            "AGENTOS_DESTRUCTIVE_STORAGE_QUALIFICATION_ENABLED",
        ),
        (
            ".github/workflows/external-deletion-qualification.yml",
            "external-deletion",
            "AGENTOS_EXTERNAL_DATA_QUALIFICATION_ENABLED",
        ),
    ] {
        let contents = read_workspace_file(workflow);
        for proof in [
            "uses: ./.github/workflows/protected-qualification-plan.yml",
            "needs: qualification-plan",
            "if: needs.qualification-plan.outputs.ready == 'true'",
            profile,
            enable_variable,
        ] {
            assert!(
                contents.contains(proof),
                "{workflow} lost protected preflight contract {proof:?}"
            );
        }
    }

    let target_remote =
        read_workspace_file(".github/workflows/target-remote-backup-qualification.yml");
    let target_remote_protected_job = target_remote
        .split_once("  exact-release-candidate-target-recovery:")
        .expect("target remote workflow lost protected job")
        .1;
    assert!(
        target_remote.contains("workflow_dispatch:")
            && !target_remote.contains("pull_request:")
            && !target_remote.contains("schedule:"),
        "target remote-backup qualification must remain an explicit protected gate"
    );
    for proof in [
        "runs-on: [self-hosted, linux, x64, agentos-capacity]",
        "environment: capacity-qualification",
        "refs/tags/${AGENTOS_RELEASE_CANDIDATE}^{commit}",
        "AGENTOS_TARGET_REMOTE_ENDPOINT: ${{ vars.AGENTOS_TARGET_REMOTE_ENDPOINT }}",
        "AWS_ACCESS_KEY_ID: ${{ secrets.AGENTOS_TARGET_REMOTE_ACCESS_KEY_ID }}",
        "--mode target-service",
        "--expected-commit \"$GITHUB_SHA\"",
        "target_remote_object_store_recovery",
        "target_remote_recovery_proof_eligible",
        "public_recovery_fixture",
        "production_claim_allowed",
        "retention-days: 90",
    ] {
        assert!(
            target_remote.contains(proof),
            "target remote-backup workflow lost {proof:?}"
        );
    }
    assert!(
        target_remote_protected_job
            .contains("AWS_ACCESS_KEY_ID: ${{ secrets.AGENTOS_TARGET_REMOTE_ACCESS_KEY_ID }}"),
        "target remote credentials must remain scoped to the protected self-hosted job"
    );

    let storage_profile =
        read_workspace_file(".github/workflows/storage-profile-qualification.yml");
    assert!(
        storage_profile.contains("workflow_dispatch:")
            && !storage_profile.contains("pull_request:")
            && !storage_profile.contains("schedule:"),
        "destructive storage qualification must remain an explicit protected gate"
    );
    for proof in [
        "runs-on: [self-hosted, linux, x64, agentos-destructive-storage]",
        "environment: destructive-storage-qualification",
        "AGENTOS_STORAGE_PROFILE_EVIDENCE_DIR: ${{ vars.AGENTOS_STORAGE_PROFILE_EVIDENCE_DIR }}",
        "single-node-linux-rootless-container-cli",
        "refs/tags/${AGENTOS_RELEASE_CANDIDATE}^{commit}",
        "scripts/storage_profile_qualification.py --validate",
        "--expected-commit \"$GITHUB_SHA\"",
        "--require-eligible",
        "exact_release_candidate_destructive_storage_profile",
        "out_of_band_power_cut",
        "block_level_torn_write",
        "storage_device_detached",
        "storage_profile_proof_eligible",
        "production_claim_allowed",
        "retention-days: 90",
    ] {
        assert!(
            storage_profile.contains(proof),
            "destructive storage workflow lost {proof:?}"
        );
    }

    let external_deletion =
        read_workspace_file(".github/workflows/external-deletion-qualification.yml");
    assert!(
        external_deletion.contains("workflow_dispatch:")
            && !external_deletion.contains("pull_request:")
            && !external_deletion.contains("schedule:"),
        "external deletion qualification must remain an explicit protected gate"
    );
    for proof in [
        "runs-on: [self-hosted, linux, x64, agentos-external-data]",
        "environment: external-data-qualification",
        "AGENTOS_EXTERNAL_DELETION_EVIDENCE_DIR: ${{ vars.AGENTOS_EXTERNAL_DELETION_EVIDENCE_DIR }}",
        "single-node-linux-rootless-container-cli",
        "refs/tags/${AGENTOS_RELEASE_CANDIDATE}^{commit}",
        "scripts/external_deletion_qualification.py --validate",
        "--expected-commit \"$GITHUB_SHA\"",
        "--require-eligible",
        "exact_release_candidate_external_deletion_retention",
        "external/remote-backup-copies",
        "immutable-retention-then-delete",
        "external_deletion_retention_proof_eligible",
        "production_claim_allowed",
        "retention-days: 90",
    ] {
        assert!(
            external_deletion.contains(proof),
            "external deletion workflow lost {proof:?}"
        );
    }

    let live = read_workspace_file(".github/workflows/live-provider-qualification.yml");
    let live_plan = read_workspace_file("scripts/live_provider_qualification_plan.py");
    assert!(
        live.contains("workflow_dispatch:") && !live.contains("pull_request:"),
        "secret-backed qualification must be explicit and separate from deterministic PR CI"
    );
    for proof in [
        "environment: provider-qualification",
        "QUALIFICATION_MODEL: ${{ vars[matrix.model_variable] }}",
        "QUALIFICATION_API_KEY: ${{ secrets[matrix.credential_secret] }}",
        "QUALIFICATION_ENDPOINT: ${{ secrets[matrix.endpoint_secret] }}",
        "AGENTOS_LIVE_PROVIDER_SET",
        "live_provider_qualification_plan.py",
        "fromJSON(needs.qualification-plan.outputs.matrix)",
        "cancel-in-progress: true",
        "test \"$status\" = \"passed\"",
        "Execute one governed live turn",
    ] {
        assert!(
            live.contains(proof),
            "live-provider qualification lost {proof:?}"
        );
    }
    for secret in [
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "AZURE_OPENAI_API_KEY",
        "GROQ_API_KEY",
        "DEEPSEEK_API_KEY",
        "GEMINI_API_KEY",
        "HUGGINGFACE_API_KEY",
        "VLLM_API_KEY",
    ] {
        assert!(
            live_plan.contains(&format!("\"credential_secret\": \"{secret}\"")),
            "live-provider plan lost matrix credential {secret:?}"
        );
        assert!(
            !live.contains(&format!("${{{{ secrets.{secret} }}}}")),
            "live-provider jobs must not receive unrelated credential {secret:?}"
        );
    }
    assert_eq!(
        live.matches("secrets[").count(),
        2,
        "live-provider jobs must select only their credential and endpoint secrets"
    );
    assert!(
        !live.contains("test \"$status\" = \"passed\" || test \"$status\" = \"not_run\""),
        "an explicitly enabled live provider must never report not_run as a passing job"
    );

    let on_device = read_workspace_file(".github/workflows/on-device-qualification.yml");
    assert!(
        on_device.contains("workflow_dispatch:") && !on_device.contains("pull_request:"),
        "provisioned model qualification must remain a protected explicit gate"
    );
    for proof in [
        "environment: model-qualification",
        "ref: ${{ github.sha }}",
        "AGENTOS_GGUF_MODEL: ${{ vars.AGENTOS_GGUF_MODEL }}",
        "AGENTOS_TOKENIZER: ${{ vars.AGENTOS_TOKENIZER }}",
        "AGENTOS_ON_DEVICE_HARDWARE_ID",
        "refs/tags/$RELEASE_CANDIDATE^{commit}",
        "--example on_device_qualification",
        "--expected-commit \"$GITHUB_SHA\"",
        "exact_release_candidate_on_device_gguf",
        "model_sha256",
        "tokenizer_sha256",
        "cancellation_worker_drained",
        "on_device_proof_eligible",
        "production_claim_allowed == false",
        "retention-days: 90",
    ] {
        assert!(
            on_device.contains(proof),
            "on-device qualification workflow lost {proof:?}"
        );
    }
    for forbidden in [
        "inputs.model_path",
        "inputs.tokenizer_path",
        "on-device-resources.txt",
    ] {
        assert!(
            !on_device.contains(forbidden),
            "on-device qualification must not retain or dispatch sensitive input {forbidden:?}"
        );
    }

    let release = read_workspace_file(".github/workflows/release.yml");
    for proof in [
        "workflow_dispatch:",
        "uses: ./.github/workflows/ci.yml",
        "macos-15-intel",
        "-C link-arg=/Brepro",
        "byte-for-byte reproducible",
        "cyclonedx-json",
        "spdx-json",
        "SHA256SUMS",
        "cosign sign-blob",
        "attest-build-provenance@",
        "\"storage_get\"",
    ] {
        assert!(
            release.contains(proof),
            "release qualification workflow lost {proof:?}"
        );
    }

    let dockerfile = read_workspace_file("Dockerfile");
    for image in ["FROM rust:", "FROM debian:"] {
        let line = dockerfile
            .lines()
            .find(|line| line.starts_with(image))
            .unwrap_or_else(|| panic!("Dockerfile lost {image} base"));
        assert!(
            line.contains("@sha256:"),
            "release image bases must be digest-pinned: {line}"
        );
    }

    let windows_icon = std::fs::read(workspace_root().join("crates/tauri-app/icons/icon.ico"))
        .expect("the Tauri Windows build requires icons/icon.ico");
    assert!(
        windows_icon.starts_with(&[0, 0, 1, 0]) && windows_icon.len() > 6,
        "the Tauri Windows icon must be a non-empty ICO image"
    );

    for workflow in [
        ".github/workflows/ci.yml",
        ".github/workflows/extended-security.yml",
        ".github/workflows/external-deletion-qualification.yml",
        ".github/workflows/live-provider-qualification.yml",
        ".github/workflows/linux-cli-rc.yml",
        ".github/workflows/on-device-qualification.yml",
        ".github/workflows/protected-qualification-plan.yml",
        ".github/workflows/release.yml",
    ] {
        for line in read_workspace_file(workflow).lines() {
            let Some(action) = line.trim().strip_prefix("- uses: ") else {
                continue;
            };
            if action.starts_with("./") {
                continue;
            }
            let revision = action
                .split_once('@')
                .unwrap_or_else(|| panic!("{workflow} action has no revision: {action}"))
                .1
                .split_whitespace()
                .next()
                .unwrap();
            assert!(
                revision.len() == 40 && revision.chars().all(|ch| ch.is_ascii_hexdigit()),
                "{workflow} action must be pinned to a full commit SHA: {action}"
            );
        }
    }
}
