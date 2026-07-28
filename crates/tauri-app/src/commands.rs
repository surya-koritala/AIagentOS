//! Tauri command handlers for the AI Agent OS desktop app.

use crate::{
    credentials::{
        validate_cloud_provider, NativeProviderCredentialStore, ProviderCredentialStore,
        CLOUD_DESKTOP_PROVIDERS, SUPPORTED_DESKTOP_PROVIDERS,
    },
    AppState,
};
use kernel::config::Config;
use serde::Serialize;
use std::path::PathBuf;
use tauri::State;
use zeroize::Zeroizing;

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
    pub credential_store_available: bool,
}

impl DesktopConfigView {
    fn from_config_with_sources(
        config: &Config,
        env_value: impl Fn(&str) -> Option<String>,
        keychain_contains: impl Fn(&str) -> Result<bool, String>,
    ) -> Self {
        let mut credential_store_available = true;
        let mut configured_providers = Vec::new();
        for provider in SUPPORTED_DESKTOP_PROVIDERS {
            let keychain_configured = if CLOUD_DESKTOP_PROVIDERS.contains(&provider) {
                match keychain_contains(provider) {
                    Ok(configured) => configured,
                    Err(_) => {
                        credential_store_available = false;
                        false
                    }
                }
            } else {
                false
            };
            if provider_is_configured(config, provider, &env_value, keychain_configured) {
                configured_providers.push(provider.to_string());
            }
        }
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
            credential_store_available,
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
    keychain_configured: bool,
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
    keychain_configured || in_legacy_config || in_environment
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
    let store = NativeProviderCredentialStore::default();
    Ok(DesktopConfigView::from_config_with_sources(
        &config,
        |name| std::env::var(name).ok(),
        |provider| store.contains(provider).map_err(|error| error.to_string()),
    ))
}

struct ProviderSettings {
    llm_provider: String,
    provider_credential: Option<String>,
    default_model: Option<String>,
    azure_endpoint: Option<String>,
    azure_deployment: Option<String>,
    local_endpoint: Option<String>,
}

fn apply_provider_settings(
    config: &mut Config,
    store: &impl ProviderCredentialStore,
    env_value: &impl Fn(&str) -> Option<String>,
    settings: ProviderSettings,
) -> Result<(), String> {
    let ProviderSettings {
        llm_provider,
        provider_credential,
        default_model,
        azure_endpoint,
        azure_deployment,
        local_endpoint,
    } = settings;
    if !SUPPORTED_DESKTOP_PROVIDERS.contains(&llm_provider.as_str()) {
        return Err("unsupported provider".to_string());
    }
    config.llm_provider = llm_provider.clone();
    if let Some(model) = default_model.filter(|value| !value.trim().is_empty()) {
        config.default_model = model;
    }
    if llm_provider == "azure-openai" {
        config.azure_endpoint = azure_endpoint.filter(|value| !value.trim().is_empty());
        config.azure_deployment = azure_deployment.filter(|value| !value.trim().is_empty());
    }
    if llm_provider == "local" {
        if provider_credential.is_some() {
            return Err("the local provider does not accept a credential".to_string());
        }
        let endpoint = local_endpoint
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| "http://localhost:11434".to_string());
        config.set_api_key("local", endpoint);
    }
    let mut keychain_configured = false;
    if CLOUD_DESKTOP_PROVIDERS.contains(&llm_provider.as_str()) {
        validate_cloud_provider(&llm_provider).map_err(|error| error.to_string())?;
        if let Some(secret) = provider_credential {
            let secret = Zeroizing::new(secret);
            store
                .store(&llm_provider, secret.as_str())
                .map_err(|error| error.to_string())?;
            config.api_keys.remove(&llm_provider);
            keychain_configured = true;
        } else {
            match store.contains(&llm_provider) {
                Ok(true) => {
                    config.api_keys.remove(&llm_provider);
                    keychain_configured = true;
                }
                Ok(false) => {
                    if let Some(legacy_secret) = config
                        .get_api_key(&llm_provider)
                        .filter(|value| !value.trim().is_empty())
                        .map(ToOwned::to_owned)
                    {
                        if store.store(&llm_provider, &legacy_secret).is_ok() {
                            config.api_keys.remove(&llm_provider);
                            keychain_configured = true;
                        }
                    }
                }
                Err(_) => {}
            }
        }
    }
    if !provider_is_configured(config, &llm_provider, env_value, keychain_configured) {
        let variable = credential_environment_variable(&llm_provider)
            .expect("cloud providers have a credential environment variable");
        return Err(format!(
            "{llm_provider} is not configured; store a credential or set {variable} before starting the desktop app"
        ));
    }
    config.setup_complete = true;
    Ok(())
}

#[tauri::command]
pub fn save_config(
    llm_provider: String,
    provider_credential: Option<String>,
    default_model: Option<String>,
    azure_endpoint: Option<String>,
    azure_deployment: Option<String>,
    local_endpoint: Option<String>,
) -> Result<(), String> {
    let mut config = Config::try_load().map_err(|error| error.to_string())?;
    apply_provider_settings(
        &mut config,
        &NativeProviderCredentialStore::default(),
        &|name| std::env::var(name).ok(),
        ProviderSettings {
            llm_provider,
            provider_credential,
            default_model,
            azure_endpoint,
            azure_deployment,
            local_endpoint,
        },
    )?;
    config.save().map_err(|e| e.to_string())
}

#[tauri::command]
pub fn delete_provider_credential(provider: String) -> Result<bool, String> {
    NativeProviderCredentialStore::default()
        .delete(&provider)
        .map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credentials::tests::MemoryCredentialStore;

    #[test]
    fn desktop_config_view_never_serializes_provider_credentials() {
        let mut config = Config::default();
        config.set_api_key("openai", "openai-secret-value".to_string());
        config.set_api_key("anthropic", "anthropic-secret-value".to_string());
        config.set_api_key("local", "http://localhost:11434".to_string());

        let store = MemoryCredentialStore::default();
        store.store("openai", "keychain-secret-value").unwrap();
        let view = DesktopConfigView::from_config_with_sources(
            &config,
            |name| (name == "AZURE_OPENAI_API_KEY").then(|| "azure-secret-value".to_string()),
            |provider| store.contains(provider).map_err(|error| error.to_string()),
        );
        let serialized = serde_json::to_string(&view).expect("serialize desktop config view");

        assert!(!serialized.contains("openai-secret-value"));
        assert!(!serialized.contains("anthropic-secret-value"));
        assert!(!serialized.contains("azure-secret-value"));
        assert!(!serialized.contains("keychain-secret-value"));
        assert!(!serialized.contains("api_keys"));
        assert!(view.configured_providers.contains(&"openai".to_string()));
        assert!(view.configured_providers.contains(&"anthropic".to_string()));
        assert!(view
            .configured_providers
            .contains(&"azure-openai".to_string()));
        assert!(view.configured_providers.contains(&"local".to_string()));
        assert!(view.credential_store_available);
    }

    #[test]
    fn blank_external_credentials_are_not_treated_as_configured() {
        let config = Config::default();
        assert!(!provider_is_configured(
            &config,
            "openai",
            &|_| Some("   ".to_string()),
            false
        ));
        assert!(provider_is_configured(&config, "local", &|_| None, false));
    }

    #[test]
    fn save_rotates_into_keychain_and_removes_legacy_plaintext() {
        let store = MemoryCredentialStore::default();
        let mut config = Config::default();
        config.set_api_key("openai", "legacy-secret".to_string());

        apply_provider_settings(
            &mut config,
            &store,
            &|_| None,
            ProviderSettings {
                llm_provider: "openai".to_string(),
                provider_credential: Some("rotated-secret".to_string()),
                default_model: Some("gpt-5".to_string()),
                azure_endpoint: None,
                azure_deployment: None,
                local_endpoint: None,
            },
        )
        .unwrap();

        assert!(config.get_api_key("openai").is_none());
        assert_eq!(
            store
                .load("openai")
                .unwrap()
                .as_ref()
                .map(|secret| secret.as_str()),
            Some("rotated-secret")
        );
        assert!(config.setup_complete);
        assert_eq!(config.default_model, "gpt-5");
    }

    #[test]
    fn save_migrates_legacy_secret_and_fails_closed_without_any_source() {
        let store = MemoryCredentialStore::default();
        let mut legacy = Config::default();
        legacy.set_api_key("anthropic", "legacy-secret".to_string());
        apply_provider_settings(
            &mut legacy,
            &store,
            &|_| None,
            ProviderSettings {
                llm_provider: "anthropic".to_string(),
                provider_credential: None,
                default_model: None,
                azure_endpoint: None,
                azure_deployment: None,
                local_endpoint: None,
            },
        )
        .unwrap();
        assert!(legacy.get_api_key("anthropic").is_none());
        assert_eq!(
            store
                .load("anthropic")
                .unwrap()
                .as_ref()
                .map(|secret| secret.as_str()),
            Some("legacy-secret")
        );

        let mut missing = Config::default();
        let error = apply_provider_settings(
            &mut missing,
            &MemoryCredentialStore::default(),
            &|_| None,
            ProviderSettings {
                llm_provider: "openai".to_string(),
                provider_credential: None,
                default_model: None,
                azure_endpoint: None,
                azure_deployment: None,
                local_endpoint: None,
            },
        )
        .unwrap_err();
        assert_eq!(
            error,
            "openai is not configured; store a credential or set OPENAI_API_KEY before starting the desktop app"
        );
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
