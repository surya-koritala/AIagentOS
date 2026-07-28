//! Tauri command handlers for the AI Agent OS desktop app.

use crate::AppState;
use kernel::config::Config;
use serde::Serialize;
use std::path::PathBuf;
use tauri::State;

const SUPPORTED_PROVIDERS: [&str; 4] = ["azure-openai", "openai", "anthropic", "local"];

/// Non-secret configuration that may cross the desktop IPC boundary.
///
/// `Config` intentionally cannot be serialized directly here because it owns
/// provider credentials. The UI receives only provider names for which some
/// external credential source is configured, never the credential value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DesktopConfigView {
    pub llm_provider: String,
    pub default_model: String,
    pub data_dir: PathBuf,
    pub setup_complete: bool,
    pub azure_endpoint: Option<String>,
    pub azure_deployment: Option<String>,
    pub local_endpoint: String,
    pub configured_providers: Vec<String>,
}

impl DesktopConfigView {
    fn from_config_with_env(config: &Config, env_value: impl Fn(&str) -> Option<String>) -> Self {
        let configured_providers = SUPPORTED_PROVIDERS
            .iter()
            .filter(|provider| provider_is_configured(config, provider, &env_value))
            .map(|provider| (*provider).to_string())
            .collect();
        Self {
            llm_provider: config.llm_provider.clone(),
            default_model: config.default_model.clone(),
            data_dir: config.data_dir.clone(),
            setup_complete: config.setup_complete,
            azure_endpoint: config.azure_endpoint.clone(),
            azure_deployment: config.azure_deployment.clone(),
            local_endpoint: config
                .get_api_key("local")
                .unwrap_or("http://localhost:11434")
                .to_string(),
            configured_providers,
        }
    }
}

fn credential_environment_variable(provider: &str) -> Option<&'static str> {
    match provider {
        "azure-openai" => Some("AZURE_OPENAI_API_KEY"),
        "openai" => Some("OPENAI_API_KEY"),
        "anthropic" => Some("ANTHROPIC_API_KEY"),
        "local" => None,
        _ => None,
    }
}

fn provider_is_configured(
    config: &Config,
    provider: &str,
    env_value: &impl Fn(&str) -> Option<String>,
) -> bool {
    if provider == "local" {
        return true;
    }
    let in_legacy_config = config
        .get_api_key(provider)
        .is_some_and(|value| !value.trim().is_empty());
    let in_environment = credential_environment_variable(provider)
        .and_then(env_value)
        .is_some_and(|value| !value.trim().is_empty());
    in_legacy_config || in_environment
}

#[tauri::command]
pub async fn create_agent(
    state: State<'_, AppState>,
    name: String,
    task: String,
    provider: Option<String>,
) -> Result<String, String> {
    state
        .client
        .create_agent(name, task, provider)
        .await
        .map_err(|error| error.to_string())
}

#[tauri::command]
pub async fn send_message(
    state: State<'_, AppState>,
    agent_id: String,
    message: String,
) -> Result<serde_json::Value, String> {
    let output = state
        .client
        .send_message(agent_id, message)
        .await
        .map_err(|error| error.to_string())?;
    Ok(serde_json::json!({
        "content": output.content,
        "tool_calls_made": output.tool_calls,
        "tokens_used": output.tokens,
    }))
}

#[tauri::command]
pub async fn pause_agent(state: State<'_, AppState>, agent_id: String) -> Result<(), String> {
    state
        .client
        .pause_agent(agent_id)
        .await
        .map_err(|error| error.to_string())
}

#[tauri::command]
pub async fn resume_agent(state: State<'_, AppState>, agent_id: String) -> Result<(), String> {
    state
        .client
        .resume_agent(agent_id)
        .await
        .map_err(|error| error.to_string())
}

#[tauri::command]
pub async fn stop_agent(state: State<'_, AppState>, agent_id: String) -> Result<(), String> {
    state
        .client
        .stop_agent(agent_id)
        .await
        .map_err(|error| error.to_string())
}

#[tauri::command]
pub async fn list_agents(state: State<'_, AppState>) -> Result<serde_json::Value, String> {
    let agents = state
        .client
        .list_agents()
        .await
        .map_err(|error| error.to_string())?;
    serde_json::to_value(agents).map_err(|error| error.to_string())
}

#[tauri::command]
pub async fn get_metrics(state: State<'_, AppState>) -> Result<serde_json::Value, String> {
    let snapshot = state
        .client
        .operator_snapshot()
        .await
        .map_err(|error| error.to_string())?;
    let metrics = snapshot.system_metrics.unwrap_or_default();
    Ok(serde_json::json!({
        "tokens_consumed": metrics.tokens_consumed,
        "api_calls_made": metrics.api_calls_made,
        "time_elapsed_ms": metrics.uptime_seconds.saturating_mul(1_000),
    }))
}

#[tauri::command]
pub fn load_config() -> Result<DesktopConfigView, String> {
    let config = Config::try_load().map_err(|error| error.to_string())?;
    Ok(DesktopConfigView::from_config_with_env(&config, |name| {
        std::env::var(name).ok()
    }))
}

#[tauri::command]
pub fn save_config(
    llm_provider: String,
    default_model: Option<String>,
    azure_endpoint: Option<String>,
    azure_deployment: Option<String>,
    local_endpoint: Option<String>,
) -> Result<(), String> {
    if !SUPPORTED_PROVIDERS.contains(&llm_provider.as_str()) {
        return Err("unsupported provider".to_string());
    }
    let mut config = Config::try_load().map_err(|error| error.to_string())?;
    config.llm_provider = llm_provider.clone();
    if let Some(model) = default_model.filter(|value| !value.trim().is_empty()) {
        config.default_model = model;
    }
    if llm_provider == "azure-openai" {
        config.azure_endpoint = azure_endpoint.filter(|value| !value.trim().is_empty());
        config.azure_deployment = azure_deployment.filter(|value| !value.trim().is_empty());
    }
    if llm_provider == "local" {
        let endpoint = local_endpoint
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| "http://localhost:11434".to_string());
        config.set_api_key("local", endpoint);
    }
    if !provider_is_configured(&config, &llm_provider, &|name| std::env::var(name).ok()) {
        let variable = credential_environment_variable(&llm_provider)
            .expect("cloud providers have a credential environment variable");
        return Err(format!(
            "{llm_provider} is not configured; set {variable} before starting the desktop app"
        ));
    }
    config.setup_complete = true;
    config.save().map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn desktop_config_view_never_serializes_provider_credentials() {
        let mut config = Config::default();
        config.set_api_key("openai", "openai-secret-value".to_string());
        config.set_api_key("anthropic", "anthropic-secret-value".to_string());
        config.set_api_key("local", "http://localhost:11434".to_string());

        let view = DesktopConfigView::from_config_with_env(&config, |name| {
            (name == "AZURE_OPENAI_API_KEY").then(|| "azure-secret-value".to_string())
        });
        let serialized = serde_json::to_string(&view).expect("serialize desktop config view");

        assert!(!serialized.contains("openai-secret-value"));
        assert!(!serialized.contains("anthropic-secret-value"));
        assert!(!serialized.contains("azure-secret-value"));
        assert!(!serialized.contains("api_keys"));
        assert!(view.configured_providers.contains(&"openai".to_string()));
        assert!(view.configured_providers.contains(&"anthropic".to_string()));
        assert!(view
            .configured_providers
            .contains(&"azure-openai".to_string()));
        assert!(view.configured_providers.contains(&"local".to_string()));
    }

    #[test]
    fn blank_external_credentials_are_not_treated_as_configured() {
        let config = Config::default();
        assert!(!provider_is_configured(&config, "openai", &|_| {
            Some("   ".to_string())
        }));
        assert!(provider_is_configured(&config, "local", &|_| None));
    }

    #[test]
    fn production_manifest_does_not_enable_tauri_devtools() {
        let manifest = include_str!("../Cargo.toml");
        assert!(
            !manifest.contains("\"devtools\""),
            "production desktop builds must not enable Tauri devtools"
        );
    }
}
