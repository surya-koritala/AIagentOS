//! Tauri command handlers for the AI Agent OS desktop app.

use crate::{
    credentials::{
        validate_cloud_provider, NativeProviderCredentialStore, ProviderCredentialStore,
        CLOUD_DESKTOP_PROVIDERS, SUPPORTED_DESKTOP_PROVIDERS,
    },
    AppState, DesktopInstalledPackage, DesktopMetricsView, DesktopOperatorView, DesktopService,
    DesktopServiceHistory, DesktopTunable, DesktopTunableAudit, DesktopUpdateState,
};
use kernel::config::Config;
use serde::Serialize;
use std::path::PathBuf;
use tauri::{ipc::Channel, AppHandle, State};
use tauri_plugin_updater::{Update, UpdaterExt};
use zeroize::Zeroizing;

const MAX_UPDATE_VERSION_BYTES: usize = 128;
const MAX_UPDATE_TARGET_BYTES: usize = 128;
const MAX_UPDATE_NOTES_BYTES: usize = 64 * 1024;

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

/// Bounded, non-secret update metadata that may cross the desktop IPC boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DesktopUpdateView {
    pub current_version: String,
    pub version: String,
    pub target: String,
    pub published_at: Option<String>,
    pub notes: Option<String>,
}

impl DesktopUpdateView {
    fn try_from_update(update: &Update) -> Result<Self, String> {
        validate_update_field(
            "current update version",
            &update.current_version,
            MAX_UPDATE_VERSION_BYTES,
        )?;
        validate_update_field("update version", &update.version, MAX_UPDATE_VERSION_BYTES)?;
        validate_update_field("update target", &update.target, MAX_UPDATE_TARGET_BYTES)?;
        if update
            .body
            .as_ref()
            .is_some_and(|notes| notes.len() > MAX_UPDATE_NOTES_BYTES)
        {
            return Err(format!(
                "update notes exceed the {MAX_UPDATE_NOTES_BYTES}-byte limit"
            ));
        }
        Ok(Self {
            current_version: update.current_version.clone(),
            version: update.version.clone(),
            target: update.target.clone(),
            published_at: update.date.map(|date| date.to_string()),
            notes: update.body.clone(),
        })
    }
}

fn validate_update_field(label: &str, value: &str, maximum: usize) -> Result<(), String> {
    if value.is_empty() || value.len() > maximum || value.chars().any(char::is_control) {
        return Err(format!(
            "{label} is empty, oversized, or contains control characters"
        ));
    }
    Ok(())
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
pub async fn stream_message(
    state: State<'_, AppState>,
    request_id: String,
    agent_id: String,
    message: String,
    on_event: Channel<agent_sdk::MessageStreamEvent>,
) -> Result<serde_json::Value, String> {
    let output = state
        .client
        .send_message_stream(request_id, agent_id, message, |event| {
            let _ = on_event.send(event.clone());
        })
        .await
        .map_err(|error| error.to_string())?;
    Ok(serde_json::json!({
        "content": output.content,
        "tool_calls_made": output.tool_calls,
        "tokens_used": output.tokens,
    }))
}

#[tauri::command]
pub async fn cancel_message(
    state: State<'_, AppState>,
    request_id: String,
    agent_id: String,
) -> Result<bool, String> {
    state
        .client
        .cancel_request(request_id, agent_id)
        .await
        .map_err(|error| error.to_string())
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
pub async fn list_checkpoints(
    state: State<'_, AppState>,
    agent_id: String,
) -> Result<serde_json::Value, String> {
    let checkpoints = state
        .client
        .list_generation_checkpoints(agent_id)
        .await
        .map_err(|error| error.to_string())?;
    serde_json::to_value(checkpoints).map_err(|error| error.to_string())
}

#[tauri::command]
pub async fn resume_checkpoint(
    state: State<'_, AppState>,
    agent_id: String,
    checkpoint_id: String,
) -> Result<serde_json::Value, String> {
    let result = state
        .client
        .resume_generation_checkpoint(agent_id, checkpoint_id)
        .await
        .map_err(|error| error.to_string())?;
    serde_json::to_value(result).map_err(|error| error.to_string())
}

#[tauri::command]
pub async fn delete_checkpoint(
    state: State<'_, AppState>,
    agent_id: String,
    checkpoint_id: String,
    confirm_checkpoint_id: String,
) -> Result<bool, String> {
    validate_checkpoint_deletion_confirmation(&checkpoint_id, &confirm_checkpoint_id)?;
    state
        .client
        .delete_generation_checkpoint(agent_id, checkpoint_id)
        .await
        .map_err(|error| error.to_string())
}

fn validate_checkpoint_deletion_confirmation(
    checkpoint_id: &str,
    confirmation: &str,
) -> Result<(), String> {
    if checkpoint_id != confirmation {
        return Err("checkpoint deletion confirmation must exactly match the checkpoint ID".into());
    }
    Ok(())
}

#[tauri::command]
pub async fn start_service(
    state: State<'_, AppState>,
    service_name: String,
) -> Result<DesktopService, String> {
    validate_service_name(&service_name)?;
    state
        .client
        .start_service(service_name)
        .await
        .map_err(|error| error.to_string())
}

#[tauri::command]
pub async fn stop_service(
    state: State<'_, AppState>,
    service_name: String,
    confirm_service_name: String,
) -> Result<DesktopService, String> {
    validate_service_control_confirmation(&service_name, &confirm_service_name)?;
    state
        .client
        .stop_service(service_name)
        .await
        .map_err(|error| error.to_string())
}

#[tauri::command]
pub async fn restart_service(
    state: State<'_, AppState>,
    service_name: String,
    confirm_service_name: String,
) -> Result<DesktopService, String> {
    validate_service_control_confirmation(&service_name, &confirm_service_name)?;
    state
        .client
        .restart_service(service_name)
        .await
        .map_err(|error| error.to_string())
}

#[tauri::command]
pub async fn service_history(
    state: State<'_, AppState>,
    service_name: Option<String>,
    limit: usize,
) -> Result<Vec<DesktopServiceHistory>, String> {
    if let Some(name) = service_name.as_deref() {
        validate_service_name(name)?;
    }
    if !(1..=200).contains(&limit) {
        return Err("service history limit must be between 1 and 200".into());
    }
    state
        .client
        .service_history(service_name, limit)
        .await
        .map_err(|error| error.to_string())
}

fn validate_service_name(service_name: &str) -> Result<(), String> {
    if service_name.is_empty() || service_name.trim() != service_name {
        return Err("service name must be a non-empty exact target".into());
    }
    Ok(())
}

fn validate_service_control_confirmation(
    service_name: &str,
    confirmation: &str,
) -> Result<(), String> {
    validate_service_name(service_name)?;
    if service_name != confirmation {
        return Err("service control confirmation must exactly match the service name".into());
    }
    Ok(())
}

#[tauri::command]
pub async fn set_operator_tunable(
    state: State<'_, AppState>,
    tunable_name: String,
    value: u64,
    expected_revision: u64,
) -> Result<DesktopTunable, String> {
    validate_tunable_target(&tunable_name, expected_revision)?;
    state
        .client
        .set_operator_tunable(tunable_name, value, expected_revision)
        .await
        .map_err(|error| error.to_string())
}

#[tauri::command]
pub async fn rollback_operator_tunable(
    state: State<'_, AppState>,
    tunable_name: String,
    target_revision: u64,
    expected_revision: u64,
    confirm_tunable_name: String,
) -> Result<DesktopTunable, String> {
    validate_tunable_rollback_confirmation(
        &tunable_name,
        target_revision,
        expected_revision,
        &confirm_tunable_name,
    )?;
    state
        .client
        .rollback_operator_tunable(tunable_name, target_revision, expected_revision)
        .await
        .map_err(|error| error.to_string())
}

#[tauri::command]
pub async fn operator_tunable_audit(
    state: State<'_, AppState>,
    tunable_name: Option<String>,
    limit: usize,
) -> Result<Vec<DesktopTunableAudit>, String> {
    if let Some(name) = tunable_name.as_deref() {
        validate_tunable_name(name)?;
    }
    if !(1..=200).contains(&limit) {
        return Err("operator tunable audit limit must be between 1 and 200".into());
    }
    state
        .client
        .operator_tunable_audit(tunable_name, limit)
        .await
        .map_err(|error| error.to_string())
}

fn validate_tunable_name(name: &str) -> Result<(), String> {
    if name.is_empty() || name.trim() != name || name.len() > 128 {
        return Err("operator tunable name must be a bounded non-empty exact target".into());
    }
    Ok(())
}

fn validate_tunable_target(name: &str, expected_revision: u64) -> Result<(), String> {
    validate_tunable_name(name)?;
    if expected_revision == 0 {
        return Err("operator tunable expected revision must be positive".into());
    }
    Ok(())
}

fn validate_tunable_rollback_confirmation(
    name: &str,
    target_revision: u64,
    expected_revision: u64,
    confirmation: &str,
) -> Result<(), String> {
    validate_tunable_target(name, expected_revision)?;
    if name != confirmation {
        return Err(
            "operator tunable rollback confirmation must exactly match the tunable name".into(),
        );
    }
    if target_revision == 0 || target_revision >= expected_revision {
        return Err(
            "operator tunable rollback revision must be positive and older than the current revision"
                .into(),
        );
    }
    Ok(())
}

#[tauri::command]
pub async fn list_installed_packages(
    state: State<'_, AppState>,
) -> Result<Vec<DesktopInstalledPackage>, String> {
    state
        .client
        .list_installed_packages()
        .await
        .map_err(|error| error.to_string())
}

#[tauri::command]
pub async fn install_package(
    state: State<'_, AppState>,
    package_name: String,
    requirement: String,
) -> Result<DesktopInstalledPackage, String> {
    validate_package_target(&package_name, &requirement)?;
    state
        .client
        .install_package(package_name, requirement)
        .await
        .map_err(|error| error.to_string())
}

#[tauri::command]
pub async fn run_installed_package(
    state: State<'_, AppState>,
    package_name: String,
) -> Result<String, String> {
    validate_package_name(&package_name)?;
    state
        .client
        .run_installed_package(package_name)
        .await
        .map_err(|error| error.to_string())
}

#[tauri::command]
pub async fn rollback_installed_package(
    state: State<'_, AppState>,
    package_name: String,
    expected_version: String,
    expected_digest: String,
    confirm_package_target: String,
) -> Result<DesktopInstalledPackage, String> {
    validate_exact_package_mutation(
        &package_name,
        &expected_version,
        &expected_digest,
        &confirm_package_target,
    )?;
    state
        .client
        .rollback_installed_package_exact(package_name, expected_version, expected_digest)
        .await
        .map_err(|error| error.to_string())
}

#[tauri::command]
pub async fn remove_installed_package(
    state: State<'_, AppState>,
    package_name: String,
    expected_version: String,
    expected_digest: String,
    confirm_package_target: String,
) -> Result<(), String> {
    validate_exact_package_mutation(
        &package_name,
        &expected_version,
        &expected_digest,
        &confirm_package_target,
    )?;
    state
        .client
        .remove_installed_package_exact(package_name, expected_version, expected_digest)
        .await
        .map_err(|error| error.to_string())
}

fn validate_package_name(name: &str) -> Result<(), String> {
    if name.is_empty() || name.trim() != name || name.len() > 128 || name.contains('\0') {
        return Err("package name must be a bounded non-empty exact target".into());
    }
    Ok(())
}

fn validate_package_target(name: &str, requirement: &str) -> Result<(), String> {
    validate_package_name(name)?;
    if requirement.is_empty()
        || requirement.trim() != requirement
        || requirement.len() > 128
        || requirement.contains('\0')
    {
        return Err("package requirement must be a bounded non-empty exact value".into());
    }
    Ok(())
}

fn validate_exact_package_mutation(
    name: &str,
    expected_version: &str,
    expected_digest: &str,
    confirmation: &str,
) -> Result<(), String> {
    validate_package_name(name)?;
    if expected_version.is_empty()
        || expected_version.trim() != expected_version
        || expected_version.len() > 128
        || expected_version.contains('\0')
    {
        return Err("expected package version must be a bounded non-empty exact value".into());
    }
    if expected_digest.len() != 64
        || !expected_digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("expected package digest must be a lowercase SHA-256 hex value".into());
    }
    if confirmation != format!("{expected_version}|{name}") {
        return Err("package mutation confirmation must exactly match version|package-name".into());
    }
    Ok(())
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
pub async fn get_metrics(state: State<'_, AppState>) -> Result<DesktopMetricsView, String> {
    let snapshot = state
        .client
        .operator_snapshot()
        .await
        .map_err(|error| error.to_string())?;
    DesktopMetricsView::try_from_operator_snapshot(&snapshot).map_err(str::to_string)
}

#[tauri::command]
pub async fn get_operator_view(state: State<'_, AppState>) -> Result<DesktopOperatorView, String> {
    state
        .client
        .operator_view()
        .await
        .map_err(|error| error.to_string())
}

#[tauri::command]
pub async fn check_for_update(app: AppHandle) -> Result<Option<DesktopUpdateView>, String> {
    let update = app
        .updater()
        .map_err(|error| format!("updater configuration is invalid: {error}"))?
        .check()
        .await
        .map_err(|error| format!("signed update check failed: {error}"))?;
    update
        .as_ref()
        .map(DesktopUpdateView::try_from_update)
        .transpose()
}

#[tauri::command]
pub async fn install_update(
    app: AppHandle,
    update_state: State<'_, DesktopUpdateState>,
    expected_version: String,
) -> Result<(), String> {
    validate_update_field(
        "expected update version",
        &expected_version,
        MAX_UPDATE_VERSION_BYTES,
    )?;
    let _install_guard = update_state.begin_install().map_err(str::to_string)?;
    let update = app
        .updater()
        .map_err(|error| format!("updater configuration is invalid: {error}"))?
        .check()
        .await
        .map_err(|error| format!("signed update check failed: {error}"))?
        .ok_or_else(|| "the reviewed update is no longer available".to_string())?;
    DesktopUpdateView::try_from_update(&update)?;
    if update.version != expected_version {
        return Err(format!(
            "the available update changed from {expected_version} to {}; review it before installing",
            update.version
        ));
    }
    update
        .download_and_install(|_, _| {}, || {})
        .await
        .map_err(|error| format!("signed update verification or installation failed: {error}"))?;
    app.restart()
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

    #[test]
    fn checkpoint_deletion_requires_the_exact_target_in_the_backend() {
        assert!(validate_checkpoint_deletion_confirmation(
            "11111111-2222-4333-8444-555555555555",
            "11111111-2222-4333-8444-555555555555"
        )
        .is_ok());
        assert_eq!(
            validate_checkpoint_deletion_confirmation(
                "11111111-2222-4333-8444-555555555555",
                "11111111-2222-4333-8444-555555555556"
            )
            .unwrap_err(),
            "checkpoint deletion confirmation must exactly match the checkpoint ID"
        );
    }

    #[test]
    fn disruptive_service_controls_require_the_exact_target_in_the_backend() {
        assert!(validate_service_control_confirmation("worker", "worker").is_ok());
        assert_eq!(
            validate_service_control_confirmation("worker", "worker-2").unwrap_err(),
            "service control confirmation must exactly match the service name"
        );
        assert_eq!(
            validate_service_control_confirmation(" worker", " worker").unwrap_err(),
            "service name must be a non-empty exact target"
        );
    }

    #[test]
    fn update_metadata_fields_are_bounded_before_crossing_ipc() {
        assert!(validate_update_field("version", "1.2.3", 128).is_ok());
        assert!(validate_update_field("version", "", 128).is_err());
        assert!(validate_update_field("version", "1.2.3\nforged", 128).is_err());
        assert!(validate_update_field("version", &"a".repeat(129), 128).is_err());
    }

    #[test]
    fn tunable_mutations_require_frozen_positive_revisions_and_exact_rollback_target() {
        assert!(validate_tunable_target("kernel.max_agents", 2).is_ok());
        assert_eq!(
            validate_tunable_target(" kernel.max_agents", 2).unwrap_err(),
            "operator tunable name must be a bounded non-empty exact target"
        );
        assert_eq!(
            validate_tunable_target("kernel.max_agents", 0).unwrap_err(),
            "operator tunable expected revision must be positive"
        );
        assert!(validate_tunable_rollback_confirmation(
            "kernel.max_agents",
            1,
            2,
            "kernel.max_agents"
        )
        .is_ok());
        assert_eq!(
            validate_tunable_rollback_confirmation(
                "kernel.max_agents",
                1,
                2,
                "kernel.max_agents.other"
            )
            .unwrap_err(),
            "operator tunable rollback confirmation must exactly match the tunable name"
        );
        assert_eq!(
            validate_tunable_rollback_confirmation(
                "kernel.max_agents",
                2,
                2,
                "kernel.max_agents"
            )
            .unwrap_err(),
            "operator tunable rollback revision must be positive and older than the current revision"
        );
    }

    #[test]
    fn package_mutations_require_frozen_version_digest_and_exact_target() {
        let digest = "a".repeat(64);
        assert!(
            validate_exact_package_mutation("reviewer", "1.2.3", &digest, "1.2.3|reviewer").is_ok()
        );
        assert_eq!(
            validate_exact_package_mutation("reviewer", "1.2.3", &digest, "1.2.3|planner")
                .unwrap_err(),
            "package mutation confirmation must exactly match version|package-name"
        );
        assert_eq!(
            validate_exact_package_mutation("reviewer", "1.2.3", &"A".repeat(64), "1.2.3|reviewer")
                .unwrap_err(),
            "expected package digest must be a lowercase SHA-256 hex value"
        );
        assert_eq!(
            validate_package_target(" reviewer", "^1").unwrap_err(),
            "package name must be a bounded non-empty exact target"
        );
        assert_eq!(
            validate_package_target("reviewer\0shadow", "^1").unwrap_err(),
            "package name must be a bounded non-empty exact target"
        );
    }
}
