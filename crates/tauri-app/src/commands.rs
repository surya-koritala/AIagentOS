//! Tauri command handlers for the AI Agent OS desktop app.

use tauri::State;
use kernel::{
    AgentConfig, AgentKernelImpl, Priority,
    agent::{AgentKernel, AgentInfo},
    config::Config,
    observability::{ObservabilityEngine, MetricScope},
};
use crate::AppState;

#[tauri::command]
pub async fn create_agent(
    state: State<'_, AppState>,
    name: String,
    task: String,
    provider: Option<String>,
) -> Result<String, String> {
    let config = AgentConfig {
        name,
        task,
        llm_provider: provider.unwrap_or_else(|| "openai".to_string()),
        permission_profile: "standard".to_string(),
        priority: Priority::default(),
        sandbox_config: None,
    };
    let handle = state.kernel.create_agent_full(config).await
        .map_err(|e| e.to_string())?;
    Ok(handle.id.to_string())
}

#[tauri::command]
pub async fn send_message(
    state: State<'_, AppState>,
    agent_id: String,
    message: String,
) -> Result<serde_json::Value, String> {
    let id = uuid::Uuid::parse_str(&agent_id).map_err(|e| e.to_string())?;
    let output = state.kernel.send_message(id, &message).await
        .map_err(|e| e.to_string())?;
    Ok(serde_json::json!({
        "content": output.content,
        "tool_calls_made": output.tool_calls_made,
        "tokens_used": output.tokens_used,
    }))
}

#[tauri::command]
pub async fn pause_agent(state: State<'_, AppState>, agent_id: String) -> Result<(), String> {
    let id = uuid::Uuid::parse_str(&agent_id).map_err(|e| e.to_string())?;
    state.kernel.agent_manager.pause_agent(id).await.map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn resume_agent(state: State<'_, AppState>, agent_id: String) -> Result<(), String> {
    let id = uuid::Uuid::parse_str(&agent_id).map_err(|e| e.to_string())?;
    state.kernel.agent_manager.resume_agent(id).await.map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn stop_agent(state: State<'_, AppState>, agent_id: String) -> Result<(), String> {
    let id = uuid::Uuid::parse_str(&agent_id).map_err(|e| e.to_string())?;
    state.kernel.agent_manager.stop_agent(id).await.map_err(|e| e.to_string())
}

#[tauri::command]
pub fn list_agents(state: State<'_, AppState>) -> Vec<serde_json::Value> {
    state.kernel.agent_manager.list_agents(None)
        .iter()
        .map(|info| serde_json::json!({
            "id": info.id.to_string(),
            "name": info.name,
            "state": format!("{:?}", info.state),
            "priority": info.priority.value(),
        }))
        .collect()
}

#[tauri::command]
pub fn get_metrics(state: State<'_, AppState>) -> serde_json::Value {
    let m = state.kernel.observability.get_metrics(MetricScope::System);
    serde_json::json!({
        "tokens_consumed": m.tokens_consumed,
        "api_calls_made": m.api_calls_made,
        "time_elapsed_ms": m.time_elapsed_ms,
    })
}

#[tauri::command]
pub fn load_config() -> Result<serde_json::Value, String> {
    let config = Config::load();
    serde_json::to_value(&config).map_err(|e| e.to_string())
}

#[tauri::command]
pub fn save_config(
    llm_provider: String,
    api_key: String,
    default_model: Option<String>,
) -> Result<(), String> {
    let mut config = Config::load();
    config.llm_provider = llm_provider.clone();
    config.set_api_key(&llm_provider, api_key);
    if let Some(model) = default_model {
        config.default_model = model;
    }
    config.setup_complete = true;
    config.save().map_err(|e| e.to_string())
}
