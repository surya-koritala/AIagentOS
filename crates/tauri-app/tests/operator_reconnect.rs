use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use agent_sdk::KernelClient;
use kernel::syscall_server::SyscallServer;
use kernel::AgentKernelImpl;
use tauri_app::DesktopClient;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;

async fn proxy_connection(
    client: TcpStream,
    backend: Arc<RwLock<std::net::SocketAddr>>,
    drop_snapshot_reply: Arc<AtomicBool>,
) -> std::io::Result<()> {
    let backend = TcpStream::connect(*backend.read().await).await?;
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

async fn spawn_switching_proxy(
    initial_backend: std::net::SocketAddr,
) -> (
    std::net::SocketAddr,
    Arc<RwLock<std::net::SocketAddr>>,
    Arc<AtomicBool>,
    tokio::task::JoinHandle<()>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let backend = Arc::new(RwLock::new(initial_backend));
    let drop_snapshot_reply = Arc::new(AtomicBool::new(false));
    let task_backend = Arc::clone(&backend);
    let task_drop = Arc::clone(&drop_snapshot_reply);
    let task = tokio::spawn(async move {
        while let Ok((client, _)) = listener.accept().await {
            let backend = Arc::clone(&task_backend);
            let drop_snapshot_reply = Arc::clone(&task_drop);
            tokio::spawn(async move {
                let _ = proxy_connection(client, backend, drop_snapshot_reply).await;
            });
        }
    });
    (address, backend, drop_snapshot_reply, task)
}

#[tokio::test]
async fn desktop_operator_view_recovers_after_server_replacement() {
    let first_kernel = Arc::new(AgentKernelImpl::new().expect("first kernel"));
    let first_server = SyscallServer::bind(first_kernel, "127.0.0.1:0")
        .await
        .expect("first bind");
    let first_backend = first_server.local_addr().expect("first address");
    let first_task = tokio::spawn(first_server.serve());

    let second_kernel = Arc::new(AgentKernelImpl::new().expect("second kernel"));
    let second_server = SyscallServer::bind(second_kernel, "127.0.0.1:0")
        .await
        .expect("second bind");
    let second_backend = second_server.local_addr().expect("second address");
    let second_task = tokio::spawn(second_server.serve());
    let mut second_client = KernelClient::connect(second_backend)
        .await
        .expect("second server client");
    second_client
        .create_agent("after-restart", "prove replacement", None, None, None)
        .await
        .expect("seed replacement");

    let (stable_address, backend, drop_snapshot_reply, proxy_task) =
        spawn_switching_proxy(first_backend).await;
    let client = DesktopClient::connect(&stable_address.to_string(), None)
        .await
        .expect("desktop connect");
    let before = client.operator_view().await.expect("initial view");
    assert!(before.agents.is_empty());
    assert_eq!(before.reconnect_generation, 0);

    *backend.write().await = second_backend;
    drop_snapshot_reply.store(true, Ordering::SeqCst);
    let after = client
        .operator_view()
        .await
        .expect("read recovers against replacement server");

    assert_eq!(after.reconnect_generation, 1);
    assert!(
        after
            .agents
            .iter()
            .any(|agent| agent.name == "after-restart"),
        "the recovered view must come from the replacement server"
    );

    proxy_task.abort();
    first_task.abort();
    second_task.abort();
}
