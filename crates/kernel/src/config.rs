//! Configuration management — TOML-based persistent config.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::ProviderId;

/// Application configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub llm_provider: String,
    pub default_model: String,
    pub api_keys: HashMap<ProviderId, String>,
    pub data_dir: PathBuf,
    #[serde(default)]
    pub setup_complete: bool,
    /// Azure OpenAI specific settings.
    #[serde(default)]
    pub azure_endpoint: Option<String>,
    #[serde(default)]
    pub azure_deployment: Option<String>,
    #[serde(default)]
    pub azure_api_version: Option<String>,
    /// Max characters to return from browse_url (default 16000).
    #[serde(default = "default_max_browse_chars")]
    pub max_browse_chars: usize,
    /// Permission profile assigned to agents created by the CLI. Drives both
    /// the syscall-gate capability set (`caps_for_profile`) and the resource
    /// broker's MAC-style access rules. Defaults to "standard" (read/write/
    /// create/list + network + process launch; destructive ops gated). Set to
    /// "read-only", "elevated", or "full-access" to widen/narrow.
    #[serde(default = "default_permission_profile")]
    pub permission_profile: String,
    /// Resource budgets (cgroup token quotas + rate limiter) applied to agents.
    #[serde(default)]
    pub budgets: BudgetConfig,
    /// Mandatory Access Control: when true, the syscall gate's MAC stage
    /// enforces `mac_rules` (default-deny on no match). When false (default) the
    /// MAC stage is permissive, preserving prior behavior. Agents are labelled
    /// `profile:<permission_profile>` at creation so rules can target them.
    #[serde(default)]
    pub mac_enforcing: bool,
    /// MAC policy rules (subject/action/object/decision strings), consulted only
    /// when `mac_enforcing` is true. Operator notes:
    /// - Matching is default-DENY on no match, so include a trailing catch-all
    ///   `{subject="*", action="*", object="*", decision="allow"}` unless you
    ///   intend strict whitelist semantics. Enforcing with an empty `mac_rules`
    ///   denies everything for confined agents.
    /// - Subjects are `profile:<name>` where name is one of
    ///   read-only/standard/elevated/full-access.
    /// - Object matching is exact-or-`*` against a resource's label; until
    ///   per-path resource labels are wired, every resource is `unconfined`, so
    ///   use `object = "*"` (or `"unconfined"`).
    #[serde(default)]
    pub mac_rules: Vec<crate::mac::PolicyRule>,
    /// Path to a declarative policy document (see `docs/POLICY.md`). When set,
    /// it is the source of truth and **supersedes** the inline
    /// `mac_enforcing`/`mac_rules`: the document's `enforcing` flag and its
    /// compiled rules are used instead. An unreadable or malformed policy file
    /// is a hard startup error (clear message + non-zero exit, never a silent
    /// fallback to permissive) — see [`Config::resolve_mac`].
    #[serde(default)]
    pub policy_file: Option<PathBuf>,
}

/// Resource budgets applied at agent creation and to the shared rate limiter.
///
/// `agent_tokens_per_min` bounds a non-`full-access` agent's per-minute token
/// spend via its cgroup (0 = unlimited); `full-access` agents are unlimited and
/// `elevated` gets a wider budget. `rpm`/`tpm`/`max_concurrent` configure the
/// shared `RateLimiter`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BudgetConfig {
    #[serde(default = "default_agent_tokens_per_min")]
    pub agent_tokens_per_min: u64,
    #[serde(default)]
    pub max_tool_calls: u32,
    #[serde(default)]
    pub max_context_tokens: u64,
    #[serde(default = "default_rpm")]
    pub rpm: u32,
    #[serde(default = "default_tpm")]
    pub tpm: u64,
    #[serde(default = "default_max_concurrent")]
    pub max_concurrent: u32,
    /// Hard cumulative USD spend ceiling across all agents (0.0 = unlimited).
    /// Enforced by [`crate::budget::BudgetEnforcer`] on the LLM path.
    #[serde(default)]
    pub max_usd: f64,
    /// Hard cumulative USD ceiling per agent (0.0 = unlimited).
    #[serde(default)]
    pub per_agent_max_usd: f64,
    /// Default blended price in USD per 1000 tokens, used to cost LLM responses
    /// (0.0 = free → the USD ceilings never trigger). Per-provider overrides go
    /// in `provider_pricing`.
    #[serde(default)]
    pub usd_per_1k_tokens: f64,
    /// Per-provider price overrides (provider id → USD per 1000 tokens).
    #[serde(default)]
    pub provider_pricing: HashMap<ProviderId, f64>,
}

impl Default for BudgetConfig {
    fn default() -> Self {
        Self {
            agent_tokens_per_min: default_agent_tokens_per_min(),
            max_tool_calls: 0,
            max_context_tokens: 0,
            rpm: default_rpm(),
            tpm: default_tpm(),
            max_concurrent: default_max_concurrent(),
            max_usd: 0.0,
            per_agent_max_usd: 0.0,
            usd_per_1k_tokens: 0.0,
            provider_pricing: HashMap::new(),
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            llm_provider: "azure-openai".to_string(),
            default_model: "gpt-4o".to_string(),
            api_keys: HashMap::new(),
            data_dir: default_data_dir(),
            setup_complete: false,
            azure_endpoint: None,
            azure_deployment: None,
            azure_api_version: None,
            max_browse_chars: default_max_browse_chars(),
            permission_profile: default_permission_profile(),
            budgets: BudgetConfig::default(),
            mac_enforcing: false,
            mac_rules: Vec::new(),
            policy_file: None,
        }
    }
}

fn default_max_browse_chars() -> usize {
    16000
}

fn default_permission_profile() -> String {
    "standard".to_string()
}

fn default_agent_tokens_per_min() -> u64 {
    50_000
}

fn default_rpm() -> u32 {
    60
}

fn default_tpm() -> u64 {
    100_000
}

fn default_max_concurrent() -> u32 {
    3
}

impl Config {
    /// Resolve the effective MAC configuration `(enforcing, rules)`.
    ///
    /// When `policy_file` is set it is the source of truth: the file is read,
    /// parsed/validated as a [`crate::policy::PolicyDocument`], and its
    /// `enforcing` flag + compiled rules are returned — superseding the inline
    /// `mac_enforcing`/`mac_rules`. An unreadable or malformed policy file is a
    /// hard error so startup fails loudly with a clear message rather than
    /// silently dropping to permissive mode. With no `policy_file`, the inline
    /// fields are returned unchanged.
    pub fn resolve_mac(&self) -> Result<(bool, Vec<crate::mac::PolicyRule>), String> {
        match &self.policy_file {
            Some(path) => {
                let content = std::fs::read_to_string(path)
                    .map_err(|e| format!("cannot read policy file {}: {e}", path.display()))?;
                let doc = crate::policy::PolicyDocument::from_toml(&content)
                    .map_err(|e| format!("invalid policy file {}: {e}", path.display()))?;
                Ok((doc.enforcing, doc.compile()))
            }
            None => Ok((self.mac_enforcing, self.mac_rules.clone())),
        }
    }

    /// Load config from the default path, or create default if missing.
    pub fn load() -> Self {
        let path = config_file_path();
        Self::load_from(&path)
    }

    /// Load config from a specific path.
    pub fn load_from(path: &Path) -> Self {
        match std::fs::read_to_string(path) {
            // A malformed config is degraded to defaults rather than aborting,
            // but we warn loudly: silently running with the wrong provider/keys
            // because of a typo is worse than a visible fallback.
            Ok(content) => match toml::from_str(&content) {
                Ok(cfg) => cfg,
                Err(e) => {
                    tracing::warn!(
                        path = %path.display(),
                        error = %e,
                        "config file is malformed; falling back to defaults"
                    );
                    Self::default()
                }
            },
            Err(_) => Self::default(),
        }
    }

    /// Save config to the default path.
    pub fn save(&self) -> Result<(), std::io::Error> {
        let path = config_file_path();
        self.save_to(&path)
    }

    /// Save config to a specific path.
    pub fn save_to(&self, path: &Path) -> Result<(), std::io::Error> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let content = toml::to_string_pretty(self).map_err(std::io::Error::other)?;
        std::fs::write(path, content)
    }

    /// Get API key for a provider.
    pub fn get_api_key(&self, provider: &str) -> Option<&str> {
        self.api_keys.get(provider).map(|s| s.as_str())
    }

    /// Set API key for a provider.
    pub fn set_api_key(&mut self, provider: &str, key: String) {
        self.api_keys.insert(provider.to_string(), key);
    }
}

/// Get the platform-appropriate config directory.
pub fn config_dir() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("ai-agent-os")
}

/// Get the config file path.
pub fn config_file_path() -> PathBuf {
    config_dir().join("config.toml")
}

/// Get the default data directory.
fn default_data_dir() -> PathBuf {
    dirs::data_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("ai-agent-os")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config() {
        let cfg = Config::default();
        assert_eq!(cfg.llm_provider, "azure-openai");
        assert!(!cfg.setup_complete);
        assert!(cfg.api_keys.is_empty());
    }

    #[test]
    fn save_and_load_config() {
        let dir = std::env::temp_dir().join(format!("cfg_test_{}", uuid::Uuid::new_v4()));
        let path = dir.join("config.toml");

        let mut cfg = Config::default();
        cfg.set_api_key("openai", "sk-test-123".to_string());
        cfg.setup_complete = true;
        cfg.save_to(&path).unwrap();

        let loaded = Config::load_from(&path);
        assert_eq!(loaded.get_api_key("openai"), Some("sk-test-123"));
        assert!(loaded.setup_complete);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn load_missing_file_returns_default() {
        let cfg = Config::load_from(Path::new("/nonexistent/path/config.toml"));
        assert_eq!(cfg.llm_provider, "azure-openai");
    }

    #[test]
    fn load_malformed_file_degrades_to_default() {
        // A corrupt config must not abort startup — it falls back to defaults
        // (and warns). This pins the graceful-degradation contract.
        let dir = std::env::temp_dir().join(format!("cfg_bad_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.toml");
        std::fs::write(&path, "this is = not valid toml ][").unwrap();

        let cfg = Config::load_from(&path);
        assert_eq!(cfg.llm_provider, "azure-openai");
        assert!(!cfg.setup_complete);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn config_roundtrip_toml() {
        let mut cfg = Config::default();
        cfg.set_api_key("anthropic", "sk-ant-xxx".to_string());
        cfg.default_model = "claude-3".to_string();

        let toml_str = toml::to_string_pretty(&cfg).unwrap();
        let parsed: Config = toml::from_str(&toml_str).unwrap();
        assert_eq!(parsed.default_model, "claude-3");
        assert_eq!(parsed.get_api_key("anthropic"), Some("sk-ant-xxx"));
    }

    #[test]
    fn budgets_default_when_absent_and_roundtrip() {
        // A config file with no [budgets] section still loads (serde default).
        let toml =
            "llm_provider = \"local\"\ndefault_model = \"m\"\ndata_dir = \"/tmp/x\"\n[api_keys]\n";
        let cfg: Config = toml::from_str(toml).unwrap();
        assert_eq!(cfg.budgets.agent_tokens_per_min, 50_000);
        assert_eq!(cfg.budgets.rpm, 60);

        // And an explicit budget round-trips through TOML.
        let mut cfg = Config::default();
        cfg.budgets.agent_tokens_per_min = 12_345;
        let s = toml::to_string_pretty(&cfg).unwrap();
        let parsed: Config = toml::from_str(&s).unwrap();
        assert_eq!(parsed.budgets.agent_tokens_per_min, 12_345);
    }

    #[test]
    fn mac_fields_default_and_roundtrip() {
        // MAC is off and rule-less by default; a config without the fields loads.
        let toml =
            "llm_provider = \"local\"\ndefault_model = \"m\"\ndata_dir = \"/tmp/x\"\n[api_keys]\n";
        let cfg: Config = toml::from_str(toml).unwrap();
        assert!(!cfg.mac_enforcing);
        assert!(cfg.mac_rules.is_empty());

        // Enforcing + a rule round-trips through TOML.
        let mut cfg = Config::default();
        cfg.mac_enforcing = true;
        cfg.mac_rules = vec![crate::mac::PolicyRule {
            subject: "profile:standard".into(),
            action: "write".into(),
            object: "*".into(),
            decision: "deny".into(),
        }];
        let s = toml::to_string_pretty(&cfg).unwrap();
        let parsed: Config = toml::from_str(&s).unwrap();
        assert!(parsed.mac_enforcing);
        assert_eq!(parsed.mac_rules.len(), 1);
        assert_eq!(parsed.mac_rules[0].decision, "deny");
    }

    #[test]
    fn resolve_mac_uses_inline_when_no_policy_file() {
        let mut cfg = Config::default();
        cfg.mac_enforcing = true;
        cfg.mac_rules = vec![crate::mac::PolicyRule {
            subject: "*".into(),
            action: "read".into(),
            object: "*".into(),
            decision: "allow".into(),
        }];
        let (enforcing, rules) = cfg.resolve_mac().unwrap();
        assert!(enforcing);
        assert_eq!(rules.len(), 1);
    }

    #[test]
    fn resolve_mac_policy_file_supersedes_inline() {
        let dir = std::env::temp_dir();
        let path = dir.join("agentos-test-policy-supersede.toml");
        std::fs::write(
            &path,
            r#"
enforcing = true
default = "deny"

[[rule]]
subject = "*"
action = "write"
object = "/etc/**"
decision = "deny"
"#,
        )
        .unwrap();

        let mut cfg = Config::default();
        // Inline says enforcing=false with no rules; the file must win.
        cfg.mac_enforcing = false;
        cfg.mac_rules.clear();
        cfg.policy_file = Some(path.clone());

        let (enforcing, rules) = cfg.resolve_mac().unwrap();
        assert!(
            enforcing,
            "policy file's enforcing flag should supersede inline"
        );
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].object, "/etc/**");

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn resolve_mac_malformed_policy_file_is_an_error() {
        let dir = std::env::temp_dir();
        let path = dir.join("agentos-test-policy-bad.toml");
        // Unknown decision value — typed parse rejects it.
        std::fs::write(
            &path,
            "[[rule]]\nsubject = \"*\"\naction = \"read\"\nobject = \"*\"\ndecision = \"alow\"\n",
        )
        .unwrap();

        let mut cfg = Config::default();
        cfg.policy_file = Some(path.clone());
        let err = cfg.resolve_mac().unwrap_err();
        assert!(err.contains("invalid policy file"), "got: {err}");

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn resolve_mac_missing_policy_file_is_an_error() {
        let mut cfg = Config::default();
        cfg.policy_file = Some(std::path::PathBuf::from(
            "/nonexistent/agentos/policy/does-not-exist.toml",
        ));
        let err = cfg.resolve_mac().unwrap_err();
        assert!(err.contains("cannot read policy file"), "got: {err}");
    }
}
