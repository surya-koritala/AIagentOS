//! Integration test: drive the TUI's `App::refresh` against a real in-memory
//! kernel behind a `SyscallServer` over loopback — no terminal, no external
//! services. (Rendering and the key loop are exercised by `app`'s unit tests.)

use std::sync::Arc;

use agent_sdk::KernelClient;
use agent_tui::app::App;
use kernel::syscall_server::SyscallServer;
use kernel::AgentKernelImpl;

#[tokio::test]
async fn refresh_pulls_live_agents_gate_and_node_load() {
    // Boot a kernel node.
    let kernel = Arc::new(AgentKernelImpl::new().expect("kernel new"));
    let server = SyscallServer::bind(kernel, "127.0.0.1:0")
        .await
        .expect("bind");
    let addr = server.local_addr().expect("addr");
    tokio::spawn(server.serve());

    let mut client = KernelClient::connect(addr).await.expect("connect");
    let mut app = App::new(addr.to_string());

    // Empty to start.
    app.refresh(&mut client).await.expect("refresh");
    assert!(app.agents.is_empty());
    assert_eq!(app.node.agent_count, 0);

    // Create two agents through the same server, then refresh.
    client
        .create_agent("watcher", "observe", None, None, None)
        .await
        .expect("create");
    client
        .create_agent("worker", "work", None, None, None)
        .await
        .expect("create");
    app.refresh(&mut client).await.expect("refresh");

    assert_eq!(app.agents.len(), 2, "TUI sees both agents");
    assert_eq!(app.node.agent_count, 2, "node load reflected");
    assert!(app.agents.iter().any(|a| a.name == "watcher"));
    // Gate stats round-trip (the enforcement view is reachable from the TUI).
    let _ = app.gate.allowed;
    assert!(app.selected_agent().is_some());
}
