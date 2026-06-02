//! `agent-server` — run the kernel as a long-lived syscall server.
//!
//! Boots the kernel from config, registers the configured LLM provider, and
//! serves the JSON syscall API (see `kernel::syscall_server`): agent lifecycle,
//! the `SendMessage` LLM turn, memory store/query, tool calls, and enforcement
//! introspection. Once a provider is registered, `SendMessage` reaches a real
//! backend; with none, the non-LLM syscalls still work (keyless boot).
//!
//! Usage:
//!   agent-server [ADDR]                 # TCP, default 127.0.0.1:7777
//!   AGENT_SERVER_UNIX=/path.sock agent-server   # Unix-domain socket instead
//!   AGENT_SERVER_TOKEN=secret agent-server      # require auth before any syscall

#[path = "../providers.rs"]
mod providers;

use std::sync::Arc;

use kernel::config::Config;
use kernel::syscall_server::SyscallServer;
use kernel::AgentKernelImpl;
use providers::register_providers;

#[tokio::main]
async fn main() {
    let addr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:7777".to_string());
    let unix_path = std::env::var("AGENT_SERVER_UNIX").ok();
    let token = std::env::var("AGENT_SERVER_TOKEN")
        .ok()
        .filter(|t| !t.is_empty());

    let config = Config::load();
    let kernel = Arc::new(AgentKernelImpl::from_config(&config).expect("failed to init kernel"));
    // Make SendMessage syscalls functional against the configured backend.
    register_providers(&kernel, &config);
    // Background tasks (scheduler observer + cgroup minute-reset).
    let _runtime = kernel.start_runtime();

    // Unix socket if requested, else TCP.
    let mut server = match &unix_path {
        #[cfg(unix)]
        Some(path) => {
            let _ = std::fs::remove_file(path);
            SyscallServer::bind_unix(kernel, path)
                .await
                .unwrap_or_else(|e| {
                    eprintln!("agent-server: failed to bind unix socket {path}: {e}");
                    std::process::exit(1);
                })
        }
        #[cfg(not(unix))]
        Some(_) => {
            eprintln!("agent-server: AGENT_SERVER_UNIX is only supported on Unix platforms");
            std::process::exit(1);
        }
        None => SyscallServer::bind(kernel, addr.as_str())
            .await
            .unwrap_or_else(|e| {
                eprintln!("agent-server: failed to bind {addr}: {e}");
                std::process::exit(1);
            }),
    };

    if let Some(token) = token {
        server = server.with_auth_token(token);
        eprintln!("agent-server: authentication required (AGENT_SERVER_TOKEN set)");
    }

    match &unix_path {
        Some(path) => eprintln!("agent-server listening on unix:{path}"),
        None => {
            let bound = server.local_addr().expect("local addr");
            eprintln!("agent-server listening on {bound}");
        }
    }

    if let Err(e) = server.serve().await {
        eprintln!("agent-server: serve error: {e}");
        std::process::exit(1);
    }
}
