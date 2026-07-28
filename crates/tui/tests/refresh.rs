//! Integration test: drive the TUI's `App::refresh` against a real in-memory
//! kernel behind a `SyscallServer` over loopback — no terminal, no external
//! services. (Rendering and the key loop are exercised by `app`'s unit tests.)

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use agent_sdk::{ConnectionProfile, KernelClient};
use agent_tui::app::{App, DataFreshness};
use agent_tui::TuiClient;
use kernel::syscall_server::SyscallServer;
use kernel::AgentKernelImpl;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

async fn proxy_connection(
    client: TcpStream,
    backend: std::net::SocketAddr,
    drop_snapshot_reply: Arc<AtomicBool>,
) -> std::io::Result<()> {
    let backend = TcpStream::connect(backend).await?;
    let (client_read, mut client_write) = client.into_split();
    let (backend_read, mut backend_write) = backend.into_split();
    let mut client_read = BufReader::new(client_read);
    let mut backend_read = BufReader::new(backend_read);
    let mut request = String::new();
    let mut reply = String::new();

    loop {
        request.clear();
        if client_read.read_line(&mut request).await? == 0 {
            return Ok(());
        }
        backend_write.write_all(request.as_bytes()).await?;
        backend_write.flush().await?;
        reply.clear();
        if backend_read.read_line(&mut reply).await? == 0 {
            return Ok(());
        }
        let drop_reply = serde_json::from_str::<serde_json::Value>(&request)
            .ok()
            .and_then(|value| value["op"].as_str().map(|op| op == "operator_snapshot"))
            .unwrap_or(false)
            && drop_snapshot_reply.swap(false, Ordering::SeqCst);
        if drop_reply {
            return Ok(());
        }
        client_write.write_all(reply.as_bytes()).await?;
        client_write.flush().await?;
    }
}

async fn spawn_drop_proxy(
    backend: std::net::SocketAddr,
) -> (
    std::net::SocketAddr,
    Arc<AtomicBool>,
    tokio::task::JoinHandle<()>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let drop_snapshot_reply = Arc::new(AtomicBool::new(false));
    let task_flag = Arc::clone(&drop_snapshot_reply);
    let task = tokio::spawn(async move {
        while let Ok((client, _)) = listener.accept().await {
            let flag = Arc::clone(&task_flag);
            tokio::spawn(async move {
                let _ = proxy_connection(client, backend, flag).await;
            });
        }
    });
    (address, drop_snapshot_reply, task)
}

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

#[tokio::test]
async fn failed_refresh_keeps_last_known_data_and_marks_it_stale() {
    let kernel = Arc::new(AgentKernelImpl::new().expect("kernel new"));
    let server = SyscallServer::bind(kernel, "127.0.0.1:0")
        .await
        .expect("bind");
    let backend = server.local_addr().expect("addr");
    let server_task = tokio::spawn(server.serve());
    let (proxy, drop_snapshot_reply, proxy_task) = spawn_drop_proxy(backend).await;

    let mut client = KernelClient::connect(proxy).await.expect("connect");
    client
        .create_agent("cached", "remain visible", None, None, None)
        .await
        .expect("create");
    let mut app = App::new(proxy.to_string());
    app.refresh(&mut client).await.expect("initial refresh");
    let cached: Vec<_> = app
        .agents
        .iter()
        .map(|agent| (agent.id.clone(), agent.name.clone(), agent.state.clone()))
        .collect();

    drop_snapshot_reply.store(true, Ordering::SeqCst);
    app.refresh(&mut client)
        .await
        .expect_err("direct clients surface the lost response");

    assert_eq!(app.operator_state.freshness, DataFreshness::Stale);
    assert!(app.operator_state.last_error.is_some());
    let retained: Vec<_> = app
        .agents
        .iter()
        .map(|agent| (agent.id.clone(), agent.name.clone(), agent.state.clone()))
        .collect();
    assert_eq!(
        retained, cached,
        "stale data must not be cleared or replaced"
    );
    proxy_task.abort();
    server_task.abort();
}

#[tokio::test]
async fn profile_refresh_recovers_once_and_reports_the_reconnect_generation() {
    let kernel = Arc::new(AgentKernelImpl::new().expect("kernel new"));
    let server = SyscallServer::bind(kernel, "127.0.0.1:0")
        .await
        .expect("bind");
    let backend = server.local_addr().expect("addr");
    let server_task = tokio::spawn(server.serve());
    let (proxy, drop_snapshot_reply, proxy_task) = spawn_drop_proxy(backend).await;
    let profile = ConnectionProfile::plaintext(proxy.to_string());
    let mut client = TuiClient::connect_profile(&profile, None)
        .await
        .expect("profile connect");
    let mut app = App::new(proxy.to_string());
    app.refresh(&mut client).await.expect("initial refresh");

    drop_snapshot_reply.store(true, Ordering::SeqCst);
    app.refresh(&mut client)
        .await
        .expect("read-only refresh reconnects and replays once");

    assert_eq!(app.operator_state.freshness, DataFreshness::Fresh);
    assert!(app.operator_state.reconnected);
    assert_eq!(app.operator_state.reconnect_generation, 1);
    assert!(app.operator_state.label().contains("RECONNECTED #1"));
    proxy_task.abort();
    server_task.abort();
}
