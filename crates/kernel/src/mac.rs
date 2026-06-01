//! Mandatory Access Control (MAC) — policy-based security enforcement.
//!
//! Like SELinux. Policies define what each agent type can do.
//! Cannot be overridden by the agent itself.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::agent_struct::AgentId;

/// A security label (type) assigned to an agent or resource.
pub type SecurityLabel = String;

/// Access decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MacDecision {
    Allow,
    Deny,
    Audit, // Allow but log
}

/// A MAC policy rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    /// Subject label (agent type).
    pub subject: String,
    /// Action being performed.
    pub action: String,
    /// Object label (resource type).
    pub object: String,
    /// Decision.
    pub decision: String, // "allow", "deny", "audit"
}

/// The MAC policy engine.
pub struct MacEngine {
    /// Agent label assignments: agent_id → label.
    labels: HashMap<AgentId, SecurityLabel>,
    /// Resource labels: resource_path → label.
    resource_labels: HashMap<String, SecurityLabel>,
    /// Policy rules.
    rules: Vec<PolicyRule>,
    /// Default decision when no rule matches.
    default: MacDecision,
    /// Enforcing mode (true = enforce, false = permissive/log only).
    enforcing: bool,
}

impl MacEngine {
    pub fn new(enforcing: bool) -> Self {
        Self {
            labels: HashMap::new(),
            resource_labels: HashMap::new(),
            rules: Vec::new(),
            default: MacDecision::Deny,
            enforcing,
        }
    }

    /// Assign a security label to an agent.
    pub fn label_agent(&mut self, agent_id: AgentId, label: SecurityLabel) {
        self.labels.insert(agent_id, label);
    }

    /// Assign a security label to a resource.
    pub fn label_resource(&mut self, path: String, label: SecurityLabel) {
        self.resource_labels.insert(path, label);
    }

    /// Load policy rules.
    pub fn load_policy(&mut self, rules: Vec<PolicyRule>) {
        self.rules = rules;
    }

    /// Load policy from TOML string.
    pub fn load_policy_toml(&mut self, toml_str: &str) -> Result<(), String> {
        #[derive(Deserialize)]
        struct PolicyFile {
            rule: Vec<PolicyRule>,
        }
        let policy: PolicyFile = toml::from_str(toml_str).map_err(|e| e.to_string())?;
        self.rules = policy.rule;
        Ok(())
    }

    /// Check if an agent can perform an action on a resource.
    pub fn check(&self, agent_id: AgentId, action: &str, resource: &str) -> MacDecision {
        let subject_label = self
            .labels
            .get(&agent_id)
            .map(|s| s.as_str())
            .unwrap_or("unconfined");
        let object_label = self
            .resource_labels
            .get(resource)
            .map(|s| s.as_str())
            .unwrap_or("unconfined");

        // Find matching rule
        for rule in &self.rules {
            if Self::matches(&rule.subject, subject_label)
                && Self::matches(&rule.action, action)
                && Self::object_matches(&rule.object, object_label, resource)
            {
                let decision = match rule.decision.as_str() {
                    "allow" => MacDecision::Allow,
                    "deny" => MacDecision::Deny,
                    "audit" => MacDecision::Audit,
                    _ => MacDecision::Deny,
                };
                return if self.enforcing {
                    decision
                } else {
                    MacDecision::Allow
                };
            }
        }

        // No rule matched — use default
        if self.enforcing {
            self.default
        } else {
            MacDecision::Allow
        }
    }

    /// Label matching (supports the bare `*` catch-all and exact equality).
    /// Used for subject and action fields, which are always labels.
    fn matches(pattern: &str, value: &str) -> bool {
        pattern == "*" || pattern == value
    }

    /// Object matching. A rule's `object` field may target *either* the
    /// resource's assigned security label (e.g. `filesystem`, like SELinux
    /// types) *or* the raw resource path/URL via a glob (e.g. `/etc/**`,
    /// `https://*.internal/*`). The match succeeds if either interpretation
    /// holds, so existing label-based policies keep working unchanged while
    /// operators can now write rules that point at concrete paths and URLs.
    fn object_matches(pattern: &str, object_label: &str, resource: &str) -> bool {
        Self::matches(pattern, object_label)
            || Self::glob_match(pattern.as_bytes(), resource.as_bytes())
    }

    /// Glob matcher with path-segment awareness, used for matching rule
    /// objects against raw resource strings:
    ///
    /// - `?`  — exactly one character, except the `/` separator.
    /// - `*`  — any run of characters within a single path segment (stops at `/`).
    /// - `**` — any run of characters including `/` (spans path segments).
    ///
    /// So `/etc/*` matches `/etc/passwd` but not `/etc/ssl/key`, while
    /// `/etc/**` matches both. Patterns are operator-authored, so the
    /// worst-case backtracking cost is not attacker-controlled.
    fn glob_match(pattern: &[u8], value: &[u8]) -> bool {
        // `**` — match any sequence, including separators.
        if let [b'*', b'*', rest @ ..] = pattern {
            if Self::glob_match(rest, value) {
                return true;
            }
            return match value {
                [] => false,
                [_, v_rest @ ..] => Self::glob_match(pattern, v_rest),
            };
        }
        match pattern {
            // `*` — match any run of non-`/` characters (incl. empty).
            [b'*', rest @ ..] => {
                if Self::glob_match(rest, value) {
                    return true;
                }
                match value {
                    [c, v_rest @ ..] if *c != b'/' => Self::glob_match(pattern, v_rest),
                    _ => false,
                }
            }
            // `?` — exactly one non-`/` character.
            [b'?', rest @ ..] => match value {
                [c, v_rest @ ..] if *c != b'/' => Self::glob_match(rest, v_rest),
                _ => false,
            },
            // Literal character.
            [pc, rest @ ..] => match value {
                [vc, v_rest @ ..] if vc == pc => Self::glob_match(rest, v_rest),
                _ => false,
            },
            // Pattern exhausted — match iff value is too.
            [] => value.is_empty(),
        }
    }

    /// Check if engine is in enforcing mode.
    pub fn is_enforcing(&self) -> bool {
        self.enforcing
    }

    /// Set enforcing mode.
    pub fn set_enforcing(&mut self, enforcing: bool) {
        self.enforcing = enforcing;
    }

    /// Get agent's label.
    pub fn get_label(&self, agent_id: AgentId) -> Option<&str> {
        self.labels.get(&agent_id).map(|s| s.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup() -> MacEngine {
        let mut engine = MacEngine::new(true);
        engine.load_policy(vec![
            PolicyRule {
                subject: "researcher".into(),
                action: "read".into(),
                object: "*".into(),
                decision: "allow".into(),
            },
            PolicyRule {
                subject: "researcher".into(),
                action: "write".into(),
                object: "filesystem".into(),
                decision: "deny".into(),
            },
            PolicyRule {
                subject: "admin".into(),
                action: "*".into(),
                object: "*".into(),
                decision: "allow".into(),
            },
            PolicyRule {
                subject: "worker".into(),
                action: "execute".into(),
                object: "commands".into(),
                decision: "audit".into(),
            },
        ]);
        engine.label_agent(1, "researcher".into());
        engine.label_agent(2, "admin".into());
        engine.label_agent(3, "worker".into());
        engine.label_resource("/files".into(), "filesystem".into());
        engine.label_resource("/bin".into(), "commands".into());
        engine
    }

    #[test]
    fn researcher_can_read() {
        let engine = setup();
        assert_eq!(engine.check(1, "read", "/anything"), MacDecision::Allow);
    }

    #[test]
    fn researcher_cant_write_filesystem() {
        let engine = setup();
        assert_eq!(engine.check(1, "write", "/files"), MacDecision::Deny);
    }

    #[test]
    fn admin_can_do_anything() {
        let engine = setup();
        assert_eq!(engine.check(2, "write", "/files"), MacDecision::Allow);
        assert_eq!(engine.check(2, "delete", "/anything"), MacDecision::Allow);
    }

    #[test]
    fn worker_execute_audited() {
        let engine = setup();
        assert_eq!(engine.check(3, "execute", "/bin"), MacDecision::Audit);
    }

    #[test]
    fn unknown_agent_denied_by_default() {
        let engine = setup();
        assert_eq!(engine.check(99, "read", "/secret"), MacDecision::Deny);
    }

    #[test]
    fn permissive_mode_allows_all() {
        let mut engine = setup();
        engine.set_enforcing(false);
        assert_eq!(engine.check(1, "write", "/files"), MacDecision::Allow); // would be denied in enforcing
    }

    #[test]
    fn glob_matcher_segment_and_recursive() {
        // `*` stays within a path segment.
        assert!(MacEngine::glob_match(b"/etc/*", b"/etc/passwd"));
        assert!(!MacEngine::glob_match(b"/etc/*", b"/etc/ssl/key"));
        // `**` spans separators.
        assert!(MacEngine::glob_match(b"/etc/**", b"/etc/ssl/key"));
        assert!(MacEngine::glob_match(b"/etc/**", b"/etc/passwd"));
        // `?` is a single non-separator char.
        assert!(MacEngine::glob_match(b"/tmp/?", b"/tmp/a"));
        assert!(!MacEngine::glob_match(b"/tmp/?", b"/tmp/ab"));
        assert!(!MacEngine::glob_match(b"/tmp/?", b"/tmp//"));
        // Suffix / URL globs.
        assert!(MacEngine::glob_match(b"*.txt", b"notes.txt"));
        assert!(!MacEngine::glob_match(b"*.txt", b"dir/notes.txt"));
        assert!(MacEngine::glob_match(
            b"https://*.internal/**",
            b"https://api.internal/v1/x"
        ));
        // Exact and empty.
        assert!(MacEngine::glob_match(b"/a", b"/a"));
        assert!(!MacEngine::glob_match(b"/a", b"/b"));
        assert!(MacEngine::glob_match(b"**", b"anything/at/all"));
    }

    #[test]
    fn policy_targets_raw_paths_by_glob() {
        let mut engine = MacEngine::new(true);
        engine.load_policy(vec![
            // Deny writes anywhere under /etc, regardless of label.
            PolicyRule {
                subject: "*".into(),
                action: "write".into(),
                object: "/etc/**".into(),
                decision: "deny".into(),
            },
            // Allow everything else.
            PolicyRule {
                subject: "*".into(),
                action: "*".into(),
                object: "*".into(),
                decision: "allow".into(),
            },
        ]);
        engine.label_agent(1, "worker".into());

        // No resource was ever labelled — matching is purely on the raw path.
        assert_eq!(engine.check(1, "write", "/etc/ssl/key"), MacDecision::Deny);
        assert_eq!(engine.check(1, "write", "/etc/passwd"), MacDecision::Deny);
        assert_eq!(engine.check(1, "write", "/home/u/file"), MacDecision::Allow);
        assert_eq!(engine.check(1, "read", "/etc/passwd"), MacDecision::Allow);
    }

    #[test]
    fn label_rules_still_match_after_glob_change() {
        // Regression: a label-based object (the pre-#20 style) keeps working
        // even though the rule's object string isn't a glob over the resource.
        let engine = setup();
        // researcher write filesystem → deny; /files is labelled "filesystem".
        assert_eq!(engine.check(1, "write", "/files"), MacDecision::Deny);
    }

    #[test]
    fn url_policy_by_glob() {
        let mut engine = MacEngine::new(true);
        engine.load_policy(vec![
            PolicyRule {
                subject: "scraper".into(),
                action: "net".into(),
                object: "https://*.public.example/**".into(),
                decision: "allow".into(),
            },
            // Default-deny: no catch-all, so anything else falls through.
        ]);
        engine.label_agent(7, "scraper".into());
        assert_eq!(
            engine.check(7, "net", "https://cdn.public.example/img/a.png"),
            MacDecision::Allow
        );
        // Different host → no rule matches → default deny (enforcing).
        assert_eq!(
            engine.check(7, "net", "https://evil.example/x"),
            MacDecision::Deny
        );
    }

    #[test]
    fn load_policy_from_toml() {
        let mut engine = MacEngine::new(true);
        let toml = r#"
[[rule]]
subject = "bot"
action = "read"
object = "public"
decision = "allow"

[[rule]]
subject = "bot"
action = "write"
object = "public"
decision = "deny"
"#;
        engine.load_policy_toml(toml).unwrap();
        engine.label_agent(1, "bot".into());
        engine.label_resource("/data".into(), "public".into());
        assert_eq!(engine.check(1, "read", "/data"), MacDecision::Allow);
        assert_eq!(engine.check(1, "write", "/data"), MacDecision::Deny);
    }
}
