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
        }
    }
}

fn default_max_browse_chars() -> usize {
    16000
}

impl Config {
    /// Load config from the default path, or create default if missing.
    pub fn load() -> Self {
        let path = config_file_path();
        Self::load_from(&path)
    }

    /// Load config from a specific path.
    pub fn load_from(path: &Path) -> Self {
        match std::fs::read_to_string(path) {
            Ok(content) => toml::from_str(&content).unwrap_or_default(),
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
        let content = toml::to_string_pretty(self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
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
    use std::io::Write;

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
    fn config_roundtrip_toml() {
        let mut cfg = Config::default();
        cfg.set_api_key("anthropic", "sk-ant-xxx".to_string());
        cfg.default_model = "claude-3".to_string();

        let toml_str = toml::to_string_pretty(&cfg).unwrap();
        let parsed: Config = toml::from_str(&toml_str).unwrap();
        assert_eq!(parsed.default_model, "claude-3");
        assert_eq!(parsed.get_api_key("anthropic"), Some("sk-ant-xxx"));
    }
}
