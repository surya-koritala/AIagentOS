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
async fn memory_store_query_and_list_providers_via_sdk() {
    let addr = spawn_server().await;
    let mut client = KernelClient::connect(addr).await.expect("connect");

    let id = client
        .create_agent("mem", "t", None, None, None)
        .await
        .expect("create_agent");

    // Store a fact, then retrieve it by substring.
    let fact_id = client
        .memory_store(&id, "api token rotates monthly", Some("instruction".into()))
        .await
        .expect("memory_store");
    assert!(!fact_id.is_empty());

    let facts = client
        .memory_query(&id, "token rotates")
        .await
        .expect("memory_query");
    assert!(
        facts.iter().any(|f| f.content.contains("api token")),
        "stored fact should be retrievable: {facts:?}"
    );

    // No providers registered in the bare test kernel, but the call round-trips.
    let providers = client.list_providers().await.expect("list_providers");
    assert!(providers.is_empty());
}

#[tokio::test]
async fn storage_put_get_list_delete_via_sdk() {
    let addr = spawn_server().await;
    let mut client = KernelClient::connect(addr).await.expect("connect");

    let id = client
        .create_agent("kv", "t", None, None, None)
        .await
        .expect("create_agent");

    // Missing key → None.
    assert_eq!(
        client.storage_get(&id, "color").await.expect("storage_get"),
        None
    );

    // Put then get.
    client
        .storage_put(&id, "color", "blue")
        .await
        .expect("storage_put");
    assert_eq!(
        client
            .storage_get(&id, "color")
            .await
            .expect("storage_get")
            .as_deref(),
        Some("blue")
    );

    // Overwrite, then list.
    client
        .storage_put(&id, "color", "green")
        .await
        .expect("storage_put overwrite");
    assert_eq!(
        client.storage_list(&id).await.expect("storage_list"),
        vec!["color".to_string()]
    );

    // Delete returns true; deleting again returns false.
    assert!(client
        .storage_delete(&id, "color")
        .await
        .expect("storage_delete"));
    assert!(!client
        .storage_delete(&id, "color")
        .await
        .expect("storage_delete again"));
    assert_eq!(
        client.storage_get(&id, "color").await.expect("storage_get"),
        None
    );
}

#[tokio::test]
async fn snapshot_context_via_sdk() {
    let addr = spawn_server().await;
    let mut client = KernelClient::connect(addr).await.expect("connect");

    // create_agent seeds an initial (default) context, snapshottable immediately.
    let id = client
        .create_agent("snap", "t", None, None, None)
        .await
        .expect("create_agent");

    // Capture, list, restore, delete round-trip through the typed methods.
    client
        .snapshot_context(&id, "start")
        .await
        .expect("snapshot_context");

    let labels = client.list_snapshots(&id).await.expect("list_snapshots");
    assert_eq!(labels, vec!["start".to_string()]);

    let tokens = client
        .restore_snapshot(&id, "start")
        .await
        .expect("restore_snapshot");
    assert_eq!(tokens, 0, "fresh context has zero tokens");

    assert!(client
        .delete_snapshot(&id, "start")
        .await
        .expect("delete_snapshot"));
    assert!(!client
        .delete_snapshot(&id, "start")
        .await
        .expect("delete_snapshot again"));
    assert!(client
        .list_snapshots(&id)
        .await
        .expect("list_snapshots")
        .is_empty());

    // Restoring a missing snapshot is a kernel error, not a panic.
    let err = client
        .restore_snapshot(&id, "missing")
        .await
        .expect_err("missing snapshot should fail");
    match err {
        SdkError::Kernel(msg) => assert!(msg.contains("restore snapshot failed"), "{msg}"),
        other => panic!("expected Kernel error, got {other:?}"),
    }
}

#[tokio::test]
async fn load_package_via_sdk() {
    let addr = spawn_server().await;
    let mut client = KernelClient::connect(addr).await.expect("connect");

    let id = client
        .load_package(
            r#"
name = "sdk-pkg"
task = "packaged via sdk"
profile = "read-only"
priority = 3
memory = ["seeded by package"]
"#,
        )
        .await
        .expect("load_package");

    // The packaged agent is live and queryable for its seeded memory.
    let agents = client.list_agents().await.expect("list_agents");
    assert!(agents.iter().any(|a| a.id == id && a.name == "sdk-pkg"));

    let facts = client
        .memory_query(&id, "seeded")
        .await
        .expect("memory_query");
    assert!(facts
        .iter()
        .any(|f| f.content.contains("seeded by package")));

    // A malformed manifest comes back as a kernel error, not a panic.
    let err = client
        .load_package("name = \"x\"")
        .await
        .expect_err("missing task should fail");
    match err {
        SdkError::Kernel(msg) => assert!(msg.contains("invalid package"), "{msg}"),
        other => panic!("expected Kernel error, got {other:?}"),
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
