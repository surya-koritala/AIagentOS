//! Shared policy authoring reports for first-party command-line surfaces.
//!
//! The reports are deliberately machine-readable and evaluate through
//! [`kernel::policy::PolicyDocument`], the same document and MAC engine used at
//! runtime. Loading is bounded so an operator command cannot accidentally read
//! an arbitrarily large file into memory.

use std::io::Read;
use std::path::Path;

use kernel::mac::MacDecision;
use kernel::policy::{Decision, PolicyDocument};
use serde::Serialize;

/// Largest policy document accepted by the operator authoring commands.
pub const MAX_POLICY_BYTES: usize = 1024 * 1024;

/// A non-fatal policy-authoring concern.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PolicyWarning {
    /// Zero-based authored rule index, or `None` for a document-level warning.
    pub rule_index: Option<usize>,
    /// Human-readable warning text.
    pub message: String,
}

/// Machine-readable result of validating one policy document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PolicyValidation {
    /// Policy document format version.
    pub version: u32,
    /// Whether the policy enforces decisions.
    pub enforcing: bool,
    /// Explicit terminal decision.
    pub default: Decision,
    /// Number of authored rules.
    pub rule_count: usize,
    /// Legal but potentially unsafe or surprising authoring choices.
    pub warnings: Vec<PolicyWarning>,
}

/// Machine-readable explanation of one policy decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PolicyExplanation {
    pub subject: String,
    pub action: String,
    pub object: String,
    /// Effective runtime decision: `allow`, `deny`, or `audit`.
    pub decision: String,
    /// Zero-based authored rule index, or `None` when the default decided.
    pub matched_rule: Option<usize>,
    /// Optional name of the authored matching rule.
    pub matched_name: Option<String>,
    /// True when no authored rule matched.
    pub used_default: bool,
    /// Explicit terminal decision from the document.
    pub default: Decision,
}

/// Load and validate a bounded UTF-8 TOML policy document.
pub fn load_policy(path: impl AsRef<Path>) -> Result<PolicyDocument, String> {
    let path = path.as_ref();
    let file = std::fs::File::open(path)
        .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    let limit = u64::try_from(MAX_POLICY_BYTES)
        .unwrap_or(u64::MAX)
        .saturating_add(1);
    let mut bytes = Vec::new();
    file.take(limit)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    if bytes.len() > MAX_POLICY_BYTES {
        return Err(format!(
            "policy {} exceeds the {} byte limit",
            path.display(),
            MAX_POLICY_BYTES
        ));
    }
    let content = String::from_utf8(bytes)
        .map_err(|_| format!("policy {} is not valid UTF-8", path.display()))?;
    PolicyDocument::from_toml(&content)
        .map_err(|error| format!("invalid policy {}: {error}", path.display()))
}

/// Build the validation report for an already parsed policy document.
pub fn validate_document(document: &PolicyDocument) -> PolicyValidation {
    PolicyValidation {
        version: document.version,
        enforcing: document.enforcing,
        default: document.default,
        rule_count: document.rules.len(),
        warnings: document
            .lint_with_tool_catalog()
            .into_iter()
            .map(|warning| PolicyWarning {
                rule_index: warning.rule_index,
                message: warning.message,
            })
            .collect(),
    }
}

/// Load a policy file and return its machine-readable validation report.
pub fn validate_file(path: impl AsRef<Path>) -> Result<PolicyValidation, String> {
    let document = load_policy(path)?;
    Ok(validate_document(&document))
}

/// Explain a query through the document's real MAC evaluation engine.
pub fn explain_document(
    document: &PolicyDocument,
    subject: impl Into<String>,
    action: impl Into<String>,
    object: impl Into<String>,
) -> PolicyExplanation {
    let subject = subject.into();
    let action = action.into();
    let object = object.into();
    let explanation = document.explain(&subject, &action, &object);
    PolicyExplanation {
        subject,
        action,
        object,
        decision: decision_name(explanation.decision).into(),
        matched_rule: explanation.matched_rule,
        matched_name: explanation.matched_name,
        used_default: explanation.used_default,
        default: document.default,
    }
}

/// Load a policy file and explain one query through its real MAC engine.
pub fn explain_file(
    path: impl AsRef<Path>,
    subject: impl Into<String>,
    action: impl Into<String>,
    object: impl Into<String>,
) -> Result<PolicyExplanation, String> {
    let document = load_policy(path)?;
    Ok(explain_document(&document, subject, action, object))
}

fn decision_name(decision: MacDecision) -> &'static str {
    match decision {
        MacDecision::Allow => "allow",
        MacDecision::Deny => "deny",
        MacDecision::Audit => "audit",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const POLICY: &str = r#"
version = 1
enforcing = true
default = "deny"

[[rule]]
name = "reader"
subject = "profile:read-only"
action = "read"
object = "/workspace/**"
decision = "allow"
"#;

    #[test]
    fn validation_and_explanation_share_the_runtime_document() {
        let document = PolicyDocument::from_toml(POLICY).expect("policy");
        let validation = validate_document(&document);
        assert_eq!(validation.version, 1);
        assert!(validation.enforcing);
        assert_eq!(validation.default, Decision::Deny);
        assert_eq!(validation.rule_count, 1);

        let allowed = explain_document(&document, "profile:read-only", "read", "/workspace/notes");
        assert_eq!(allowed.decision, "allow");
        assert_eq!(allowed.matched_rule, Some(0));
        assert_eq!(allowed.matched_name.as_deref(), Some("reader"));
        assert!(!allowed.used_default);

        let denied = explain_document(&document, "profile:read-only", "write", "/workspace/notes");
        assert_eq!(denied.decision, "deny");
        assert_eq!(denied.matched_rule, None);
        assert!(denied.used_default);
    }

    #[test]
    fn policy_file_loading_rejects_oversized_and_non_utf8_input() {
        let oversized =
            std::env::temp_dir().join(format!("agentctl-policy-{}.toml", uuid::Uuid::new_v4()));
        std::fs::write(&oversized, vec![b'x'; MAX_POLICY_BYTES + 1])
            .expect("write oversized policy");
        let oversized_error = load_policy(&oversized).expect_err("oversized policy must fail");
        let _ = std::fs::remove_file(&oversized);
        assert!(oversized_error.contains("exceeds"));

        let non_utf8 =
            std::env::temp_dir().join(format!("agentctl-policy-{}.toml", uuid::Uuid::new_v4()));
        std::fs::write(&non_utf8, [0xff, 0xfe]).expect("write non-UTF-8 policy");
        let utf8_error = load_policy(&non_utf8).expect_err("non-UTF-8 policy must fail");
        let _ = std::fs::remove_file(&non_utf8);
        assert!(utf8_error.contains("not valid UTF-8"));
    }
}
