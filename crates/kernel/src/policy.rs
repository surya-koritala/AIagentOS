//! Declarative policy documents — the operator-authored security surface.
//!
//! Linux analogue: SELinux policy modules (the `.te` source an operator writes
//! and `checkpolicy` validates) plus `sesearch`/`audit2why` for explaining why
//! a decision was reached. This module is the *authoring* layer that sits above
//! the [`MacEngine`](crate::mac::MacEngine): operators write a `PolicyDocument`
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
            if r.subject.is_empty() || r.action.is_empty() || r.object.is_empty() {
                return Err(format!(
                    "rule #{i}{} has an empty subject/action/object field",
                    r.name
                        .as_ref()
                        .map(|n| format!(" ({n})"))
                        .unwrap_or_default()
                ));
            }
        }
        Ok(())
    }

    /// Soft authoring lints — things that are legal but probably mistakes.
    /// Returns an empty vec for a clean policy. Surfaced by `agent policy
    /// validate` so operators get feedback before deploying a policy.
    pub fn lint(&self) -> Vec<Lint> {
        let mut lints = Vec::new();

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

        // A `*/*/*` catch-all shadows every rule after it — first match wins,
        // so anything below it is unreachable.
        let mut catch_all: Option<usize> = None;
        for (i, r) in self.rules.iter().enumerate() {
            if let Some(ci) = catch_all {
                lints.push(Lint {
                    rule_index: Some(i),
                    message: format!(
                        "rule #{i} is unreachable: catch-all rule #{ci} (*/*/*) matches everything before it"
                    ),
                });
            } else if r.subject == "*" && r.action == "*" && r.object == "*" {
                catch_all = Some(i);
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
action = "execute"
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
    fn rejects_unsupported_version() {
        let bad = r#"version = 99"#;
        assert!(PolicyDocument::from_toml(bad).is_err());
    }

    #[test]
    fn defaults_fill_in_when_omitted() {
        // Empty doc => version 1, enforcing true, default deny, no rules.
        let doc = PolicyDocument::from_toml("").unwrap();
        assert_eq!(doc.version, 1);
        assert!(doc.enforcing);
        assert_eq!(doc.default, Decision::Deny);
        assert!(doc.rules.is_empty());
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
        assert_eq!(lints.len(), 1);
        assert_eq!(lints[0].rule_index, Some(1));
        assert!(lints[0].message.contains("unreachable"));
    }

    #[test]
    fn clean_policy_has_no_lints() {
        let doc = PolicyDocument::from_toml(SAMPLE).unwrap();
        assert!(doc.lint().is_empty());
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

        // execute => audit rule.
        let e = doc.explain("profile:standard", "execute", "/bin/ls");
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
