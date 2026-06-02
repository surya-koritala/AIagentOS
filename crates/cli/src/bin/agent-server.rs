//! `agent-server` — run the kernel as a long-lived syscall server.
//!
//! Boots the kernel from config and serves the JSON syscall API (see
//! `kernel::syscall_server`). Agent-lifecycle and tool syscalls work out of the
//! box; LLM syscalls additionally require provider registration, which lands
//! with the LLM syscalls in a later increment.
//!
//! Usage: `agent-server [ADDR]` (default `127.0.0.1:7777`).

use std::sync::Arc;

use kernel::config::Config;
use kernel::syscall_server::SyscallServer;
use kernel::AgentKernelImpl;

#[tokio::main]
async fn main() {
    let addr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:7777".to_string());

    let config = Config::load();
    let kernel = Arc::new(AgentKernelImpl::from_config(&config).expect("failed to init kernel"));
    // Background tasks (scheduler observer + cgroup minute-reset).
    let _runtime = kernel.start_runtime();

    let server = SyscallServer::bind(kernel, addr.as_str())
        .await
        .unwrap_or_else(|e| {
            eprintln!("agent-server: failed to bind {addr}: {e}");
            std::process::exit(1);
        });
    let bound = server.local_addr().expect("local addr");
    eprintln!("agent-server listening on {bound}");

    if let Err(e) = server.serve().await {
        eprintln!("agent-server: serve error: {e}");
        std::process::exit(1);
    }
}
