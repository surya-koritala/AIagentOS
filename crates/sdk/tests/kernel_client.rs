//! Integration tests: drive a real in-memory kernel through the SDK over a
//! `SyscallServer`. No external services — the kernel is `AgentKernelImpl::new()`
//! (in-memory SQLite) and the transport is loopback TCP on an ephemeral port.

use std::sync::Arc;

use agent_sdk::{Agent, KernelClient, SdkError};
use kernel::syscall_server::SyscallServer;
use kernel::AgentKernelImpl;

/// Boot an in-memory kernel + syscall server on 127.0.0.1:0 and return its addr.
async fn spawn_server() -> std::net::SocketAddr {
    let kernel = Arc::new(AgentKernelImpl::new().expect("kernel new"));
    let server = SyscallServer::bind(kernel, "127.0.0.1:0")
        .await
        .expect("bind");
    let addr = server.local_addr().expect("local_addr");
    tokio::spawn(server.serve());
    addr
}

#[tokio::test]
async fn create_lists_and_gate_stats_via_kernel_client() {
    let addr = spawn_server().await;
    let mut client = KernelClient::connect(addr).await.expect("connect");

    // create_agent → typed id back.
    let id = client
        .create_agent("alpha", "demo task", None, None, None)
        .await
        .expect("create_agent");

    // list_agents reflects the new agent.
    let agents = client.list_agents().await.expect("list_agents");
    assert!(
        agents.iter().any(|a| a.id == id && a.name == "alpha"),
        "created agent should appear in list: {agents:?}"
    );

    // gate_stats round-trips through the typed mapping.
    let stats = client.gate_stats().await.expect("gate_stats");
    // The create path admits the agent without a tool denial.
    assert_eq!(stats.denied_capability, 0);
}

#[tokio::test]
async fn agent_builder_creates_and_lists() {
    let addr = spawn_server().await;

    let mut agent = Agent::builder()
        .name("beta")
        .task("builder task")
        .profile("standard")
        .priority(2)
        .connect(addr)
        .await
        .expect("builder connect");

    let id = agent.id().to_string();
    assert!(!id.is_empty());

    // The same connection can issue non-agent-specific syscalls.
    let agents = agent.client().list_agents().await.expect("list_agents");
    assert!(agents.iter().any(|a| a.id == id && a.name == "beta"));
}

#[tokio::test]
async fn builder_requires_name_and_task() {
    let addr = spawn_server().await;
    let client = KernelClient::connect(addr).await.expect("connect");

    let result = Agent::builder()
        .name("missing-task")
        .create_with(client)
        .await;
    match result {
        Ok(_) => panic!("should require task"),
        Err(SdkError::Kernel(msg)) => {
            assert!(msg.contains("name and task are required"), "{msg}")
        }
        Err(other) => panic!("expected Kernel error, got {other:?}"),
    }
}

#[tokio::test]
async fn read_only_agent_tool_call_is_denied() {
    let addr = spawn_server().await;

    // A read-only agent lacks CAP_FILE_WRITE, so write_file is gate-denied.
    let mut agent = Agent::builder()
        .name("ro")
        .task("t")
        .profile("read-only")
        .connect(addr)
        .await
        .expect("builder connect");

    let err = agent
        .call_tool(
            "write_file",
            serde_json::json!({"path": "/tmp/x", "content": "y"}),
        )
        .await
        .expect_err("write should be denied for a read-only agent");
    match err {
        SdkError::Kernel(msg) => assert!(
            msg.contains("denied by kernel"),
            "expected a kernel denial, got: {msg}"
        ),
        other => panic!("expected Kernel denial, got {other:?}"),
    }

    // The denial is reflected in the gate counters over the same connection.
    let stats = agent.client().gate_stats().await.expect("gate_stats");
    assert!(
        stats.denied_capability >= 1,
        "gate should record the capability denial: {stats:?}"
    );
}
