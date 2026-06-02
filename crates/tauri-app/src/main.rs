//! AI Agent OS — Tauri Desktop Application

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod commands;

use adapters::anthropic::AnthropicAdapter;
use adapters::azure_openai::AzureOpenAiAdapter;
use adapters::local::LocalLlmAdapter;
use adapters::openai::OpenAiAdapter;
use kernel::{config::Config, AgentKernelImpl};
use std::sync::Arc;

pub struct AppState {
    pub kernel: Arc<AgentKernelImpl>,
}

fn register_providers(kernel: &AgentKernelImpl, config: &Config) {
    match config.llm_provider.as_str() {
        "azure-openai" => {
            if let (Some(endpoint), Some(ref key)) =
                (&config.azure_endpoint, config.get_api_key("azure-openai"))
            {
                let deployment = config.azure_deployment.as_deref().unwrap_or("gpt-4o");
                let adapter = AzureOpenAiAdapter::new(
                    endpoint.clone(),
                    deployment.to_string(),
                    key.to_string(),
                );
                let _ = kernel.register_provider(Arc::new(adapter));
            }
        }
        "openai" => {
            if let Some(key) = config.get_api_key("openai") {
                let adapter = OpenAiAdapter::new(key.to_string());
                let _ = kernel.register_provider(Arc::new(adapter));
            }
        }
        "anthropic" => {
            if let Some(key) = config.get_api_key("anthropic") {
                let adapter = AnthropicAdapter::new(key.to_string());
                let _ = kernel.register_provider(Arc::new(adapter));
            }
        }
        "local" => {
            let url = config
                .get_api_key("local")
                .unwrap_or("http://localhost:11434");
            let model = config.default_model.clone();
            let adapter = LocalLlmAdapter::new(url.to_string(), model);
            let _ = kernel.register_provider(Arc::new(adapter));
        }
        _ => {}
    }
}

fn main() {
    let config = Config::load();
    let kernel =
        Arc::new(AgentKernelImpl::from_config(&config).expect("Failed to initialize kernel"));

    register_providers(&kernel, &config);

    // Start the kernel's background tasks (scheduler observer publishing the CFS
    // pick into procfs + the per-minute cgroup counter reset), matching the CLI
    // and agent-server. Held for the app's lifetime; dropped at shutdown.
    let _runtime = kernel.start_runtime();

    tauri::Builder::default()
        .manage(AppState {
            kernel: Arc::clone(&kernel),
        })
        .invoke_handler(tauri::generate_handler![
            commands::create_agent,
            commands::send_message,
            commands::pause_agent,
            commands::resume_agent,
            commands::stop_agent,
            commands::list_agents,
            commands::get_metrics,
            commands::load_config,
            commands::save_config,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
