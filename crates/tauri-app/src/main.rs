//! AI Agent OS — Tauri Desktop Application

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use agent_cli::providers::register_providers;
use kernel::{config::Config, AgentKernelImpl};
use std::sync::Arc;
use tauri_app::{commands, credentials::hydrate_provider_credentials, AppState, DesktopClient};

fn main() {
    let mut config = match Config::try_load() {
        Ok(config) => config,
        Err(error) => {
            eprintln!("Failed to load configuration: {error}");
            std::process::exit(1);
        }
    };
    let kernel =
        Arc::new(AgentKernelImpl::from_config(&config).expect("Failed to initialize kernel"));

    // Hydration happens only after kernel construction. The in-memory values
    // are used to register providers and are never saved back to Config.
    hydrate_provider_credentials(&mut config);
    register_providers(&kernel, &config);

    // Start the scheduler observer that publishes the CFS pick into procfs,
    // matching the CLI and agent-server. Durable quota uses fixed SQLite epochs
    // and needs no reset task. Held for the app's lifetime.
    let _runtime = kernel.start_runtime();
    let client =
        tauri::async_runtime::block_on(DesktopClient::connect_embedded(Arc::clone(&kernel)))
            .expect("Failed to start authenticated desktop kernel client");

    tauri::Builder::default()
        .manage(AppState { client })
        .invoke_handler(tauri::generate_handler![
            commands::create_agent,
            commands::send_message,
            commands::stream_message,
            commands::cancel_message,
            commands::pause_agent,
            commands::resume_agent,
            commands::stop_agent,
            commands::list_checkpoints,
            commands::resume_checkpoint,
            commands::delete_checkpoint,
            commands::start_service,
            commands::stop_service,
            commands::restart_service,
            commands::service_history,
            commands::set_operator_tunable,
            commands::rollback_operator_tunable,
            commands::operator_tunable_audit,
            commands::list_agents,
            commands::get_metrics,
            commands::get_operator_view,
            commands::load_config,
            commands::save_config,
            commands::delete_provider_credential,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
