//! Declarative policy documents — the operator-authored security surface.
//!
//! Linux analogue: SELinux policy modules (the `.te` source an operator writes
//! and `checkpolicy` validates) plus `sesearch`/`audit2why` for explaining why
//! a decision was reached. This module is the *authoring* layer that sits above
//! the [`MacEngine`]: operators write a `PolicyDocument`
//! (TOML), it is **validated and linted** at load, then **lowered** (`compile`)
//! to the flat rules the engine already enforces. The engine stays unchanged —
//! this layer is purely about making policy authorable, checkable, and
//! explainable without editing Rust or hand-writing engine rules.
//!
//! Three things the inline `mac_rules` form could not do, and this can:
//!   1. **Typed decisions** — `decision = "alow"` is rejected at parse time
//!      instead of silently collapsing to `Deny`.
//!   2. **An explicit default** — a policy declares `default = "deny"` (or
//!      `allow`) up front rather than relying on an implicit engine fallback.
//!   3. **Explain / dry-run** — given (subject, action, object) the document
//!      reports *which rule decided and why*, the feedback loop authoring needs.

use serde::{Deserialize, Serialize};

use crate::mac::{MacDecision, MacEngine, PolicyRule};

/// A policy decision, parsed strictly: an unknown value is a hard error rather
/// than a silent fallback. This is the typed counterpart to the engine's
/// stringly-typed `decision` field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Decision {
    /// Permit the action.
    Allow,
    /// Refuse the action.
    Deny,
    /// Permit but record the access in the audit log.
    Audit,
}

impl Decision {
    fn as_engine_str(self) -> &'static str {
        match self {
            Decision::Allow => "allow",
            Decision::Deny => "deny",
            Decision::Audit => "audit",
        }
    }

    /// The runtime decision this lowers to (ignoring enforcing/permissive mode).
    pub fn to_mac(self) -> MacDecision {
        match self {
            Decision::Allow => MacDecision::Allow,
            Decision::Deny => MacDecision::Deny,
            Decision::Audit => MacDecision::Audit,
        }
    }
}

/// One authored rule. `name`/`description` are documentation only — they carry
/// no semantics but make a policy self-explaining (and let `explain` name the
/// rule that fired).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    /// Optional short identifier, surfaced by `explain`.
    #[serde(default)]
    pub name: Option<String>,
    /// Optional human description of intent.
    #[serde(default)]
    pub description: Option<String>,
    /// Subject label (agent type), `profile:<name>`, or `*`.
    pub subject: String,
    /// Action label, or `*`.
    pub action: String,
    /// Object: a resource label, a path/URL glob, or `*`.
    pub object: String,
    /// The decision when this rule matches.
    pub decision: Decision,
}

/// A complete, authorable policy document.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyDocument {
    /// Document format version (operator-facing; currently always 1).
    #[serde(default = "default_version")]
    pub version: u32,
    /// Free-text description of what this policy is for.
    #[serde(default)]
    pub description: Option<String>,
    /// Whether the engine enforces (true) or runs permissive/log-only (false).
    #[serde(default = "default_enforcing")]
    pub enforcing: bool,
    /// Decision applied when no rule matches. Declared explicitly so a reader
    /// never has to guess the fallthrough behaviour.
    #[serde(default = "default_default")]
    pub default: Decision,
    /// The ordered rule list; first match wins.
    #[serde(default, rename = "rule")]
    pub rules: Vec<Rule>,
}

fn default_version() -> u32 {
    1
}
fn default_enforcing() -> bool {
    true
}
fn default_default() -> Decision {
    Decision::Deny
}

const SUPPORTED_POLICY_PROFILES: [&str; 4] = [
    "profile:read-only",
    "profile:standard",
    "profile:elevated",
    "profile:full-access",
];

fn canonical_action_labels() -> Vec<&'static str> {
    crate::tools::SecurityAction::ALL
        .into_iter()
        .map(crate::tools::SecurityAction::as_str)
        .collect()
}

fn validate_action_label(index: usize, name: Option<&str>, action: &str) -> Result<(), String> {
    if action == "*"
        || crate::tools::SecurityAction::ALL
            .into_iter()
            .any(|candidate| candidate.as_str() == action)
    {
        return Ok(());
    }
    Err(format!(
        "rule #{index}{} uses unknown action label '{action}'; expected one of: {} (labels come from ToolSecurity, for example `exec`, not `execute`)",
        name.map(|name| format!(" ({name})")).unwrap_or_default(),
        canonical_action_labels().join(", ")
    ))
}

/// Validate the legacy inline MAC-rule representation before it reaches the
/// engine. Policy documents get typed decisions from [`Decision`]; inline
/// configuration is stringly typed and must receive the same fail-loud action
/// and terminal-decision checks.
pub(crate) fn validate_engine_rules(rules: &[PolicyRule]) -> Result<(), String> {
    for (index, rule) in rules.iter().enumerate() {
        if rule.subject.trim().is_empty()
            || rule.action.trim().is_empty()
            || rule.object.trim().is_empty()
        {
            return Err(format!(
                "inline MAC rule #{index} has an empty subject/action/object field"
            ));
        }
        validate_action_label(index, None, &rule.action)?;
        if !matches!(rule.decision.as_str(), "allow" | "deny" | "audit") {
            return Err(format!(
                "inline MAC rule #{index} uses unknown decision '{}'; expected allow, deny, or audit",
                rule.decision
            ));
        }
    }
    Ok(())
}

/// A non-fatal authoring concern surfaced by [`PolicyDocument::lint`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lint {
    /// The rule index the lint concerns, if any (`None` = document-level).
    pub rule_index: Option<usize>,
    /// Human-readable message.
    pub message: String,
}

/// The result of explaining a single (subject, action, object) query against a
/// document — the authoring feedback loop.
#[derive(Debug, Clone)]
pub struct Explanation {
    /// The effective decision.
    pub decision: MacDecision,
    /// Index of the rule that matched, or `None` if the default was used.
    pub matched_rule: Option<usize>,
    /// The matched rule's `name` (if it had one), for human-friendly output.
    pub matched_name: Option<String>,
    /// True when no rule matched and the document `default` decided.
    pub used_default: bool,
}

impl PolicyDocument {
    /// Parse and validate a policy document from TOML. Returns a clear error on
    /// malformed input (including an unknown `decision`/`default` value, thanks
    /// to the typed [`Decision`] enum).
    pub fn from_toml(toml_str: &str) -> Result<Self, String> {
        let raw: toml::Value = toml::from_str(toml_str).map_err(|e| e.to_string())?;
        if raw.get("default").is_none() {
            return Err(
                "policy must declare an explicit terminal `default = \"deny\"|\"allow\"|\"audit\"`"
                    .to_string(),
            );
        }
        let doc: PolicyDocument = toml::from_str(toml_str).map_err(|e| e.to_string())?;
        doc.validate()?;
        Ok(doc)
    }

    /// Hard validation — conditions that make a policy unusable. Soft authoring
    /// concerns go through [`lint`](Self::lint) instead.
    pub fn validate(&self) -> Result<(), String> {
        if self.version != 1 {
            return Err(format!(
                "unsupported policy version {} (this build understands version 1)",
                self.version
            ));
        }
        for (i, r) in self.rules.iter().enumerate() {
            if r.subject.trim().is_empty()
                || r.action.trim().is_empty()
                || r.object.trim().is_empty()
            {
                return Err(format!(
                    "rule #{i}{} has an empty subject/action/object field",
                    r.name
                        .as_ref()
                        .map(|n| format!(" ({n})"))
                        .unwrap_or_default()
                ));
            }
            validate_action_label(i, r.name.as_deref(), &r.action)?;
        }
        Ok(())
    }

    /// Soft authoring lints — things that are legal but probably mistakes.
    /// Returns an empty vec for a clean policy. Surfaced by `agent policy
    /// validate` so operators get feedback before deploying a policy.
    pub fn lint(&self) -> Vec<Lint> {
        let mut lints = Vec::new();

        if !self.enforcing {
            lints.push(Lint {
                rule_index: None,
                message: "SECURITY: policy is permissive; deny/audit decisions are logged but \
                          not enforced"
                    .to_string(),
            });
        }

        if self.default != Decision::Deny {
            lints.push(Lint {
                rule_index: None,
                message: format!(
                    "SECURITY: terminal default is {:?}; every otherwise-unmatched action is permitted",
                    self.default
                ),
            });
        }

        // Enforcing + no rules + default-deny denies *everything* for confined
        // agents — almost never intended.
        if self.enforcing && self.rules.is_empty() && self.default == Decision::Deny {
            lints.push(Lint {
                rule_index: None,
                message: "enforcing policy has no rules and default = deny: every confined \
                          action will be denied"
                    .to_string(),
            });
        }

        // First-match wins. An earlier selector that is at least as broad on all
        // three axes makes the later rule unreachable. This deliberately proves
        // only exact/catch-all subsumption; it does not guess whether two
        // different object globs contain one another.
        for (i, r) in self.rules.iter().enumerate() {
            if let Some(shadowing) = self.rules[..i]
                .iter()
                .position(|earlier| rule_selector_covers(earlier, r))
            {
                lints.push(Lint {
                    rule_index: Some(i),
                    message: format!(
                        "rule #{i} is unreachable: earlier rule #{shadowing} matches every subject/action/object it can match"
                    ),
                });
            }

            if r.decision != Decision::Deny && r.action == "*" {
                lints.push(Lint {
                    rule_index: Some(i),
                    message: "overbroad wildcard allows or audits every action for the matched \
                              subject and resource"
                        .to_string(),
                });
            }
        }

        lints
    }

    /// Extend authoring lints with coverage of every tool action in the
    /// kernel's validated default catalog. An uncovered action falls directly
    /// to the terminal default and is usually an accidental outage or grant.
    pub fn lint_with_tool_catalog(&self) -> Vec<Lint> {
        let registry = crate::tools::ToolRegistry::new();
        registry.register_advanced_tools();
        registry.register_git_tools();
        registry.register_ipc_tools();
        crate::editing::register_edit_tools(&registry);
        self.lint_with_tool_registry(&registry)
    }

    /// Lint policy coverage against the actual live registry, including
    /// dynamically installed package, custom, and MCP declarations.
    pub fn lint_with_tool_registry(&self, registry: &crate::tools::ToolRegistry) -> Vec<Lint> {
        let mut lints = self.lint();
        let engine = self.to_engine();
        let tools: std::collections::BTreeMap<String, crate::tools::ToolBinding> =
            registry.binding_catalog().into_iter().collect();
        for (tool, binding) in tools {
            let action = binding.security.action.as_str();
            let resource_label = canonical_resource_label(&binding.resource_type);
            let resource = representative_resource(&binding);
            let uncovered_profiles: Vec<&str> = SUPPORTED_POLICY_PROFILES
                .iter()
                .copied()
                .filter(|profile| {
                    // Check both the current unlabeled-resource behavior and the
                    // canonical type label. A synthetic terminal rule does not
                    // count: coverage means an authored rule explicitly handles
                    // this profile/action/resource class.
                    ["unconfined", resource_label]
                        .into_iter()
                        .all(|object_label| {
                            !engine
                                .evaluate(profile, action, object_label, &resource)
                                .1
                                .is_some_and(|index| index < self.rules.len())
                        })
                })
                .collect();
            if !uncovered_profiles.is_empty() {
                lints.push(Lint {
                    rule_index: None,
                    message: format!(
                        "tool '{tool}' action '{action}' resource class '{resource_label}' is uncovered for supported profiles [{}] and falls directly to default {:?}",
                        uncovered_profiles.join(", "),
                        self.default,
                    ),
                });
            }
        }
        lints
    }

    /// Lower this document to the flat rules the [`MacEngine`] enforces.
    ///
    /// The engine is default-deny, so a `default = deny` document needs no
    /// terminal rule; a `default = allow`/`audit` document compiles to an
    /// explicit trailing catch-all rule carrying that decision. This keeps the
    /// engine untouched while honouring the document's declared default.
    pub fn compile(&self) -> Vec<PolicyRule> {
        let mut rules: Vec<PolicyRule> = self
            .rules
            .iter()
            .map(|r| PolicyRule {
                subject: r.subject.clone(),
                action: r.action.clone(),
                object: r.object.clone(),
                decision: r.decision.as_engine_str().to_string(),
            })
            .collect();
        if self.default != Decision::Deny {
            rules.push(PolicyRule {
                subject: "*".to_string(),
                action: "*".to_string(),
                object: "*".to_string(),
                decision: self.default.as_engine_str().to_string(),
            });
        }
        rules
    }

    /// Build a standalone [`MacEngine`] loaded with this document's compiled
    /// rules and enforcing flag — used by `explain` and by callers that want to
    /// evaluate the policy in isolation.
    pub fn to_engine(&self) -> MacEngine {
        let mut engine = MacEngine::new(self.enforcing);
        engine.load_policy(self.compile());
        engine
    }

    /// Explain how this policy decides a single (subject, action, object)
    /// query. `object` is matched both as a resource *label* and as a raw
    /// path/URL glob, mirroring the engine's object semantics, so an operator
    /// can pass either a label (`filesystem`) or a concrete target (`/etc/x`).
    pub fn explain(&self, subject: &str, action: &str, object: &str) -> Explanation {
        let engine = self.to_engine();
        // Pass `object` as both the object label and the raw resource so either
        // interpretation can match — exactly what the engine does internally.
        let (decision, matched) = engine.evaluate(subject, action, object, object);
        let matched_name = matched
            .and_then(|i| self.rules.get(i))
            .and_then(|r| r.name.clone());
        Explanation {
            decision,
            matched_rule: matched,
            matched_name,
            used_default: matched.is_none(),
        }
    }
}

fn selector_covers(earlier: &str, later: &str) -> bool {
    earlier == "*" || earlier == later
}

fn canonical_resource_label(resource_type: &crate::resources::ResourceType) -> &'static str {
    use crate::resources::ResourceType;
    match resource_type {
        ResourceType::Filesystem => "filesystem",
        ResourceType::Network => "network",
        ResourceType::Application => "application",
        ResourceType::Browser => "browser",
        ResourceType::Peripheral => "peripheral",
        ResourceType::Ipc => "ipc",
    }
}

fn representative_resource(binding: &crate::tools::ToolBinding) -> String {
    if let crate::tools::ResourceExtractor::Constant(resource) =
        &binding.security.resource_extractor
    {
        return resource.clone();
    }
    use crate::resources::ResourceType;
    match &binding.resource_type {
        ResourceType::Filesystem => "/__agentos_policy_probe__".to_string(),
        ResourceType::Network | ResourceType::Browser => {
            "https://policy-probe.invalid/".to_string()
        }
        ResourceType::Application => "__agentos_policy_probe_command__".to_string(),
        ResourceType::Peripheral => "__agentos_policy_probe_device__".to_string(),
        ResourceType::Ipc => "__agentos_policy_probe_agent__".to_string(),
    }
}

fn object_selector_covers(earlier: &str, later: &str) -> bool {
    // `*` is the MAC engine's object-label catch-all and also matches every
    // single-segment raw resource. `**` is the raw-resource universal glob.
    // Equal patterns trivially cover one another.
    if earlier == "*" || earlier == "**" || earlier == later {
        return true;
    }
    // If the later selector is a literal, it can match only that exact label or
    // resource. Ask the real MAC matcher whether the earlier glob matches that
    // literal, avoiding a second policy-matching implementation here. Two
    // different glob languages still require a containment proof and are left
    // unclassified.
    if later.contains('*') || later.contains('?') {
        return false;
    }
    let mut engine = MacEngine::new(true);
    engine.load_policy(vec![PolicyRule {
        subject: "*".to_string(),
        action: "*".to_string(),
        object: earlier.to_string(),
        decision: "allow".to_string(),
    }]);
    engine.evaluate("*", "*", later, later).1.is_some()
}

fn rule_selector_covers(earlier: &Rule, later: &Rule) -> bool {
    selector_covers(&earlier.subject, &later.subject)
        && selector_covers(&earlier.action, &later.action)
        && object_selector_covers(&earlier.object, &later.object)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
version = 1
description = "test policy"
enforcing = true
default = "deny"

[[rule]]
name = "readers-read"
description = "the reader profile may read anything"
subject = "profile:read-only"
action = "read"
object = "*"
decision = "allow"

[[rule]]
name = "no-etc-writes"
subject = "*"
action = "write"
object = "/etc/**"
decision = "deny"

[[rule]]
name = "audit-exec"
subject = "*"
action = "exec"
object = "*"
decision = "audit"
"#;

    #[test]
    fn parses_a_valid_document() {
        let doc = PolicyDocument::from_toml(SAMPLE).unwrap();
        assert_eq!(doc.version, 1);
        assert!(doc.enforcing);
        assert_eq!(doc.default, Decision::Deny);
        assert_eq!(doc.rules.len(), 3);
        assert_eq!(doc.rules[0].name.as_deref(), Some("readers-read"));
    }

    #[test]
    fn rejects_unknown_decision() {
        let bad = r#"
default = "deny"
[[rule]]
subject = "x"
action = "read"
object = "*"
decision = "alow"
"#;
        let err = PolicyDocument::from_toml(bad).unwrap_err();
        assert!(err.contains("alow") || err.to_lowercase().contains("decision"));
    }

    #[test]
    fn rejects_unknown_default() {
        let bad = r#"default = "maybe""#;
        assert!(PolicyDocument::from_toml(bad).is_err());
    }

    #[test]
    fn rejects_noncanonical_action_labels() {
        let error = PolicyDocument::from_toml(
            r#"
default = "deny"
[[rule]]
subject = "*"
action = "execute"
object = "*"
decision = "allow"
"#,
        )
        .unwrap_err();
        assert!(error.contains("unknown action label 'execute'"), "{error}");
        assert!(error.contains("`exec`, not `execute`"), "{error}");
        assert!(canonical_action_labels().contains(&"exec"));
        assert!(!canonical_action_labels().contains(&"execute"));
    }

    #[test]
    fn rejects_unsupported_version() {
        let bad = "version = 99\ndefault = \"deny\"";
        assert!(PolicyDocument::from_toml(bad).is_err());
    }

    #[test]
    fn rejects_unknown_document_and_rule_fields() {
        let unknown_document = "default = \"deny\"\nenforcng = true\n";
        assert!(PolicyDocument::from_toml(unknown_document)
            .unwrap_err()
            .contains("unknown field"));

        let unknown_rule = r#"
default = "deny"
[[rule]]
subject = "*"
action = "read"
object = "*"
decision = "allow"
sandox = true
"#;
        assert!(PolicyDocument::from_toml(unknown_rule)
            .unwrap_err()
            .contains("unknown field"));
    }

    #[test]
    fn missing_terminal_default_is_rejected() {
        let error = PolicyDocument::from_toml("").unwrap_err();
        assert!(error.contains("explicit terminal"));
    }

    #[test]
    fn whitespace_only_rule_selectors_are_rejected() {
        let error = PolicyDocument::from_toml(
            r#"
default = "deny"
[[rule]]
subject = " "
action = "read"
object = "*"
decision = "allow"
"#,
        )
        .unwrap_err();
        assert!(error.contains("empty subject/action/object"));
    }

    #[test]
    fn lint_flags_empty_enforcing_deny() {
        let doc = PolicyDocument::from_toml("enforcing = true\ndefault = \"deny\"").unwrap();
        let lints = doc.lint();
        assert_eq!(lints.len(), 1);
        assert!(lints[0].message.contains("denied"));
    }

    #[test]
    fn lint_flags_unreachable_rule_after_catch_all() {
        let doc = PolicyDocument::from_toml(
            r#"
default = "deny"
[[rule]]
subject = "*"
action = "*"
object = "*"
decision = "allow"

[[rule]]
name = "shadowed"
subject = "profile:read-only"
action = "read"
object = "*"
decision = "deny"
"#,
        )
        .unwrap();
        let lints = doc.lint();
        assert!(lints
            .iter()
            .any(|lint| lint.rule_index == Some(1) && lint.message.contains("unreachable")));
        assert!(lints
            .iter()
            .any(|lint| lint.message.contains("overbroad wildcard")));
    }

    #[test]
    fn lint_flags_partially_shadowed_rules() {
        let doc = PolicyDocument::from_toml(
            r#"
default = "deny"
[[rule]]
subject = "*"
action = "write"
object = "*"
decision = "deny"

[[rule]]
subject = "profile:standard"
action = "write"
object = "/tmp/**"
decision = "allow"
"#,
        )
        .unwrap();
        assert!(doc.lint().iter().any(|lint| {
            lint.rule_index == Some(1)
                && lint.message.contains("unreachable")
                && lint.message.contains("rule #0")
        }));
    }

    #[test]
    fn lint_uses_runtime_glob_semantics_to_find_shadowed_literal_resources() {
        let doc = PolicyDocument::from_toml(
            r#"
default = "deny"
[[rule]]
subject = "*"
action = "write"
object = "/etc/**"
decision = "deny"

[[rule]]
subject = "profile:standard"
action = "write"
object = "/etc/ssl/key"
decision = "allow"
"#,
        )
        .unwrap();
        assert!(doc.lint().iter().any(|lint| {
            lint.rule_index == Some(1)
                && lint.message.contains("unreachable")
                && lint.message.contains("rule #0")
        }));
    }

    #[test]
    fn lint_flags_subject_scoped_all_action_grant_as_overbroad() {
        let doc = PolicyDocument::from_toml(
            r#"
default = "deny"
[[rule]]
subject = "profile:full-access"
action = "*"
object = "*"
decision = "allow"
"#,
        )
        .unwrap();
        assert!(doc
            .lint()
            .iter()
            .any(|lint| lint.message.contains("overbroad wildcard")));
    }

    #[test]
    fn lint_makes_permissive_and_non_deny_terminal_modes_noisy() {
        let doc = PolicyDocument::from_toml("enforcing = false\ndefault = \"audit\"").unwrap();
        let lints = doc.lint();
        assert!(lints
            .iter()
            .any(|lint| lint.message.contains("policy is permissive")));
        assert!(lints
            .iter()
            .any(|lint| lint.message.contains("terminal default is Audit")));
    }

    #[test]
    fn clean_policy_has_no_lints() {
        let doc = PolicyDocument::from_toml(SAMPLE).unwrap();
        assert!(doc.lint().is_empty());
    }

    #[test]
    fn tool_coverage_lint_detects_uncovered_actions() {
        let doc = PolicyDocument::from_toml(
            "default = \"deny\"\n[[rule]]\nsubject=\"*\"\naction=\"read\"\nobject=\"*\"\ndecision=\"allow\"\n",
        )
        .unwrap();
        let lints = doc.lint_with_tool_catalog();
        assert!(lints.iter().any(
            |lint| lint.message.contains("action 'net'") && lint.message.contains("uncovered")
        ));
        assert!(lints
            .iter()
            .any(|lint| lint.message.contains("action 'delete'")
                && lint.message.contains("uncovered")));
    }

    #[test]
    fn live_registry_coverage_includes_dynamic_tool_actions() {
        use crate::resources::ResourceType;
        use crate::tools::{
            ApprovalPolicy, SecurityAction, ToolBinding, ToolRegistry, ToolSecurity,
        };

        let registry = ToolRegistry::new();
        registry
            .register(ToolBinding {
                name: "dynamic_browser".into(),
                description: "browser extension".into(),
                parameters_schema: serde_json::json!({
                    "type": "object",
                    "properties": {"url": {"type": "string"}},
                    "required": ["url"]
                }),
                resource_type: ResourceType::Browser,
                operation: "navigate".into(),
                security: ToolSecurity::argument(SecurityAction::BrowserAutomation, "url")
                    .with_approval(ApprovalPolicy::User)
                    .sandboxed(),
            })
            .unwrap();
        let doc = PolicyDocument::from_toml(
            "default = \"deny\"\n[[rule]]\nsubject=\"*\"\naction=\"read\"\nobject=\"*\"\ndecision=\"allow\"\n",
        )
        .unwrap();

        assert!(doc
            .lint_with_tool_registry(&registry)
            .iter()
            .any(|lint| lint.message.contains("tool 'dynamic_browser'")
                && lint.message.contains("action 'browser'")
                && lint.message.contains("resource class 'browser'")
                && lint.message.contains("uncovered")));
    }

    #[test]
    fn every_registered_default_tool_has_non_vacuous_policy_coverage() {
        let registry = crate::tools::ToolRegistry::new();
        registry.register_advanced_tools();
        registry.register_git_tools();
        registry.register_ipc_tools();
        crate::editing::register_edit_tools(&registry);
        let bindings = registry.binding_catalog();
        let pairs: std::collections::BTreeSet<(String, String)> = bindings
            .values()
            .map(|binding| {
                (
                    binding.security.action.as_str().to_string(),
                    canonical_resource_label(&binding.resource_type).to_string(),
                )
            })
            .collect();
        let doc = PolicyDocument {
            version: 1,
            description: Some("explicit action/resource coverage fixture".into()),
            enforcing: true,
            default: Decision::Deny,
            rules: pairs
                .into_iter()
                .map(|(action, object)| Rule {
                    name: Some(format!("{action}-{object}")),
                    description: None,
                    subject: "*".into(),
                    action,
                    object,
                    decision: Decision::Deny,
                })
                .collect(),
        };
        doc.validate().unwrap();
        assert!(
            doc.rules.len() > 3,
            "fixture must exercise multiple classes"
        );
        assert!(doc
            .rules
            .iter()
            .all(|rule| rule.action != "*" && rule.object != "*"));
        let lints = doc.lint_with_tool_registry(&registry);
        assert!(
            !lints.iter().any(|lint| lint.message.contains("uncovered")),
            "all registered tools should be covered: {lints:?}"
        );

        // Prove the test is sensitive to subject and resource coverage, not just
        // action-string coincidence.
        let read_file = bindings.get("read_file").expect("built-in read_file");
        let mut broken = doc.clone();
        let rule = broken
            .rules
            .iter_mut()
            .find(|rule| {
                rule.action == read_file.security.action.as_str()
                    && rule.object == canonical_resource_label(&read_file.resource_type)
            })
            .expect("read/filesystem coverage rule");
        rule.subject = "profile:not-supported".into();
        let broken_lints = broken.lint_with_tool_registry(&registry);
        assert!(broken_lints.iter().any(|lint| {
            lint.message.contains("tool 'read_file'")
                && lint.message.contains("resource class 'filesystem'")
                && lint.message.contains("profile:read-only")
        }));

        let mut wrong_resource = doc.clone();
        let rule = wrong_resource
            .rules
            .iter_mut()
            .find(|rule| {
                rule.action == read_file.security.action.as_str()
                    && rule.object == canonical_resource_label(&read_file.resource_type)
            })
            .expect("read/filesystem coverage rule");
        rule.object = "network".into();
        assert!(wrong_resource
            .lint_with_tool_registry(&registry)
            .iter()
            .any(|lint| lint.message.contains("tool 'read_file'")
                && lint.message.contains("resource class 'filesystem'")
                && lint.message.contains("uncovered")));
    }

    #[test]
    fn default_allow_compiles_to_terminal_catch_all() {
        let doc = PolicyDocument::from_toml(
            r#"
default = "allow"

[[rule]]
subject = "*"
action = "write"
object = "/etc/**"
decision = "deny"
"#,
        )
        .unwrap();
        let compiled = doc.compile();
        assert_eq!(compiled.len(), 2);
        let last = compiled.last().unwrap();
        assert_eq!(last.subject, "*");
        assert_eq!(last.action, "*");
        assert_eq!(last.object, "*");
        assert_eq!(last.decision, "allow");
    }

    #[test]
    fn default_deny_compiles_without_terminal_rule() {
        let doc = PolicyDocument::from_toml(SAMPLE).unwrap();
        // 3 authored rules, no synthetic catch-all (engine is default-deny).
        assert_eq!(doc.compile().len(), 3);
    }

    #[test]
    fn explain_reports_the_matching_rule() {
        let doc = PolicyDocument::from_toml(SAMPLE).unwrap();

        // reader reading => first rule allows.
        let e = doc.explain("profile:read-only", "read", "/some/file");
        assert_eq!(e.decision, MacDecision::Allow);
        assert_eq!(e.matched_rule, Some(0));
        assert_eq!(e.matched_name.as_deref(), Some("readers-read"));
        assert!(!e.used_default);

        // anyone writing under /etc => deny rule.
        let e = doc.explain("profile:standard", "write", "/etc/ssl/key");
        assert_eq!(e.decision, MacDecision::Deny);
        assert_eq!(e.matched_rule, Some(1));

        // exec => audit rule.
        let e = doc.explain("profile:standard", "exec", "/bin/ls");
        assert_eq!(e.decision, MacDecision::Audit);
        assert_eq!(e.matched_rule, Some(2));

        // nothing matches => default deny.
        let e = doc.explain("profile:standard", "write", "/home/u/file");
        assert_eq!(e.decision, MacDecision::Deny);
        assert!(e.used_default);
        assert_eq!(e.matched_rule, None);
    }

    #[test]
    fn explain_default_allow_falls_through_to_catch_all() {
        let doc = PolicyDocument::from_toml(
            r#"
default = "allow"

[[rule]]
subject = "*"
action = "write"
object = "/etc/**"
decision = "deny"
"#,
        )
        .unwrap();
        // Unmatched action falls through to the synthetic catch-all (allow).
        let e = doc.explain("profile:standard", "read", "/home/u/file");
        assert_eq!(e.decision, MacDecision::Allow);
        // It *did* match the synthetic terminal rule rather than the engine
        // default, so used_default is false and the matched index is the last.
        assert_eq!(e.matched_rule, Some(1));
    }
}
