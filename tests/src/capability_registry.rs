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
