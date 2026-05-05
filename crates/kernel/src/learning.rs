//! Learning from corrections — agents improve based on user feedback.
//!
//! Users can correct agent behavior, and corrections are stored as rules
//! that apply to future interactions.

use std::path::Path;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use crate::AgentId;

/// A learned rule from user correction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrectionRule {
    pub id: String,
    pub trigger: String,       // When this pattern is detected
    pub correction: String,    // Apply this correction
    pub scope: RuleScope,
    pub created_at: String,
    pub times_applied: u32,
}

/// Scope of a correction rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RuleScope {
    Global,
    Agent(String),
    Project(String),
}

/// Manages learned correction rules.
pub struct RuleStore {
    rules: Mutex<Vec<CorrectionRule>>,
    file_path: Option<std::path::PathBuf>,
}

impl RuleStore {
    pub fn new() -> Self {
        Self { rules: Mutex::new(Vec::new()), file_path: None }
    }

    /// Load rules from a file.
    pub fn from_file(path: &Path) -> Self {
        let rules = std::fs::read_to_string(path).ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();
        Self { rules: Mutex::new(rules), file_path: Some(path.to_path_buf()) }
    }

    /// Add a correction rule.
    pub fn add_rule(&self, trigger: String, correction: String, scope: RuleScope) -> String {
        let id = uuid::Uuid::new_v4().to_string();
        let rule = CorrectionRule {
            id: id.clone(),
            trigger,
            correction,
            scope,
            created_at: chrono::Utc::now().to_rfc3339(),
            times_applied: 0,
        };
        self.rules.lock().unwrap().push(rule);
        self.save();
        id
    }

    /// Remove a rule by ID.
    pub fn remove_rule(&self, id: &str) -> bool {
        let mut rules = self.rules.lock().unwrap();
        let len_before = rules.len();
        rules.retain(|r| r.id != id);
        let removed = rules.len() < len_before;
        drop(rules);
        if removed { self.save(); }
        removed
    }

    /// Get all rules (optionally filtered by scope).
    pub fn get_rules(&self, scope: Option<&RuleScope>) -> Vec<CorrectionRule> {
        let rules = self.rules.lock().unwrap();
        match scope {
            None => rules.clone(),
            Some(s) => rules.iter().filter(|r| &r.scope == s || r.scope == RuleScope::Global).cloned().collect(),
        }
    }

    /// Find applicable rules for a given context.
    pub fn find_applicable(&self, context: &str) -> Vec<CorrectionRule> {
        let rules = self.rules.lock().unwrap();
        rules.iter()
            .filter(|r| context.to_lowercase().contains(&r.trigger.to_lowercase()))
            .cloned()
            .collect()
    }

    /// Generate a system prompt addition from applicable rules.
    pub fn rules_as_prompt(&self, context: &str) -> Option<String> {
        let applicable = self.find_applicable(context);
        if applicable.is_empty() { return None; }
        let rules_text: Vec<String> = applicable.iter()
            .map(|r| format!("- When you encounter '{}': {}", r.trigger, r.correction))
            .collect();
        Some(format!("IMPORTANT RULES (learned from previous corrections):\n{}", rules_text.join("\n")))
    }

    fn save(&self) {
        if let Some(ref path) = self.file_path {
            let rules = self.rules.lock().unwrap();
            if let Ok(json) = serde_json::to_string_pretty(&*rules) {
                let _ = std::fs::write(path, json);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_and_find_rules() {
        let store = RuleStore::new();
        store.add_rule("python".into(), "Always use type hints".into(), RuleScope::Global);
        store.add_rule("rust".into(), "Prefer &str over String in function params".into(), RuleScope::Global);

        let found = store.find_applicable("Write a python function");
        assert_eq!(found.len(), 1);
        assert!(found[0].correction.contains("type hints"));
    }

    #[test]
    fn rules_as_prompt_works() {
        let store = RuleStore::new();
        store.add_rule("code".into(), "Add comments to all functions".into(), RuleScope::Global);

        let prompt = store.rules_as_prompt("Write some code");
        assert!(prompt.is_some());
        assert!(prompt.unwrap().contains("Add comments"));
    }

    #[test]
    fn remove_rule() {
        let store = RuleStore::new();
        let id = store.add_rule("test".into(), "correction".into(), RuleScope::Global);
        assert_eq!(store.get_rules(None).len(), 1);
        store.remove_rule(&id);
        assert_eq!(store.get_rules(None).len(), 0);
    }

    #[test]
    fn scope_filtering() {
        let store = RuleStore::new();
        store.add_rule("global".into(), "applies everywhere".into(), RuleScope::Global);
        store.add_rule("project".into(), "only this project".into(), RuleScope::Project("myproject".into()));

        let global_only = store.get_rules(Some(&RuleScope::Global));
        assert_eq!(global_only.len(), 1);

        let project_rules = store.get_rules(Some(&RuleScope::Project("myproject".into())));
        assert_eq!(project_rules.len(), 2); // global + project-specific
    }
}
