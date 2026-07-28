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
    ] {
        assert!(
            tui.contains(contract),
            "TUI lost target-bound destructive contract {contract:?}"
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
        "public `v*` tag is deliberately rejected",
        "failed-update, and rollback tests",
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
        "cargo tauri build --ci --no-sign",
        "release-desktop-${{ matrix.platform }}",
    ] {
        assert!(
            release.contains(contract),
            "desktop release workflow lost {contract:?}"
        );
    }

    let verifier = read_workspace_file("scripts/verify_desktop_release.py");
    for contract in [
        "member_versions",
        "release tag",
        "REQUIRED_PNGS",
        "icon.ico",
        "icon.icns",
    ] {
        assert!(
            verifier.contains(contract),
            "desktop release verifier lost {contract:?}"
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

    let target_remote =
        read_workspace_file(".github/workflows/target-remote-backup-qualification.yml");
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
    assert!(
        live.contains("workflow_dispatch:") && !live.contains("pull_request:"),
        "secret-backed qualification must be explicit and separate from deterministic PR CI"
    );
    for proof in [
        "environment: provider-qualification",
        "QUALIFICATION_MODEL: ${{ vars[matrix.model_variable] }}",
        "QUALIFICATION_API_KEY: ${{ secrets[matrix.credential_secret] }}",
        "QUALIFICATION_ENDPOINT: ${{ secrets[matrix.endpoint_secret] }}",
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
            live.contains(&format!("credential_secret: {secret}")),
            "live-provider qualification lost matrix credential {secret:?}"
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
        ".github/workflows/on-device-qualification.yml",
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
