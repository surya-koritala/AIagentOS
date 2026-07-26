//! Tauri command handlers for the AI Agent OS desktop app.

use crate::AppState;
use kernel::config::Config;
use tauri::State;

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
pub fn load_config() -> Result<serde_json::Value, String> {
    let config = Config::try_load().map_err(|error| error.to_string())?;
    serde_json::to_value(&config).map_err(|e| e.to_string())
}

#[tauri::command]
pub fn save_config(
    llm_provider: String,
    api_key: String,
    default_model: Option<String>,
) -> Result<(), String> {
    let mut config = Config::try_load().map_err(|error| error.to_string())?;
    config.llm_provider = llm_provider.clone();
    config.set_api_key(&llm_provider, api_key);
    if let Some(model) = default_model {
        config.default_model = model;
    }
    config.setup_complete = true;
    config.save().map_err(|e| e.to_string())
}
