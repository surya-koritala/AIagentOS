//! Integration tests: drive several in-memory kernel nodes as one cluster.
//!
//! Each node is a real `AgentKernelImpl` behind its own `SyscallServer` on an
//! ephemeral loopback port. No external services. Exercises placement,
//! cross-node aggregation, and per-agent routing through `ClusterClient`.

use std::sync::Arc;

use agent_sdk::{ClusterClient, Placement, SdkError};
use kernel::syscall_server::SyscallServer;
use kernel::AgentKernelImpl;

/// Spawn `n` independent in-memory kernel nodes; return their dialable addresses.
async fn spawn_cluster(n: usize) -> Vec<String> {
    let mut addrs = Vec::with_capacity(n);
    for _ in 0..n {
        let kernel = Arc::new(AgentKernelImpl::new().expect("kernel new"));
        let server = SyscallServer::bind(kernel, "127.0.0.1:0")
            .await
            .expect("bind");
        let addr = server.local_addr().expect("local_addr");
        tokio::spawn(server.serve());
        addrs.push(addr.to_string());
    }
    addrs
}

#[tokio::test]
async fn least_loaded_placement_spreads_agents() {
    let addrs = spawn_cluster(3).await;
    let mut cluster = ClusterClient::connect(&addrs).await.expect("connect");
    assert_eq!(cluster.node_count(), 3);

    // Three agents, least-loaded placement → one per node.
    let mut placed = Vec::new();
    for i in 0..3 {
        let p = cluster
            .create_agent(
                format!("agent-{i}"),
                "t",
                None,
                None,
                None,
                Placement::LeastLoaded,
            )
            .await
            .expect("create");
        placed.push(p);
    }

    // Every node ended up with exactly one agent.
    let loads = cluster.nodes_load().await.expect("loads");
    assert_eq!(loads.len(), 3);
    for (node, load) in &loads {
        assert_eq!(load.agent_count, 1, "node {node} should host one agent");
    }

    // The three agents landed on three distinct nodes.
    let mut nodes: Vec<_> = placed.iter().map(|p| p.node_id.clone()).collect();
    nodes.sort();
    nodes.dedup();
    assert_eq!(nodes.len(), 3, "agents spread across distinct nodes");
}

#[tokio::test]
async fn list_agents_aggregates_and_attributes_by_node() {
    let addrs = spawn_cluster(2).await;
    let mut cluster = ClusterClient::connect(&addrs).await.expect("connect");

    let a = cluster
        .create_agent("alpha", "t", None, None, None, Placement::RoundRobin)
        .await
        .expect("create a");
    let b = cluster
        .create_agent("beta", "t", None, None, None, Placement::RoundRobin)
        .await
        .expect("create b");
    // Round-robin over two nodes → different nodes.
    assert_ne!(a.node_id, b.node_id);

    let all = cluster.list_agents().await.expect("list");
    assert_eq!(all.len(), 2, "both agents listed across the cluster");

    // Each agent is attributed to the node it was placed on.
    let find = |id: &str| -> String {
        all.iter()
            .find(|(_, s)| s.id == id)
            .map(|(node, _)| node.clone())
            .expect("agent present in aggregated list")
    };
    assert_eq!(find(&a.agent_id), a.node_id);
    assert_eq!(find(&b.agent_id), b.node_id);
    assert_eq!(cluster.owner_of(&a.agent_id), Some(a.node_id.as_str()));
}

#[tokio::test]
async fn routing_reaches_owning_node_and_unknown_agent_errors() {
    let addrs = spawn_cluster(2).await;
    let mut cluster = ClusterClient::connect(&addrs).await.expect("connect");

    // A read-only agent placed somewhere in the cluster.
    let placed = cluster
        .create_agent(
            "ro",
            "t",
            None,
            Some("read-only".into()),
            None,
            Placement::LeastLoaded,
        )
        .await
        .expect("create");

    // call_tool routes to the owning node; write is gate-denied *there* — proving
    // the call reached the right node and enforcement held across the cluster.
    let err = cluster
        .call_tool(
            &placed.agent_id,
            "write_file",
            serde_json::json!({"path": "/tmp/x", "content": "y"}),
        )
        .await
        .expect_err("write must be denied for a read-only agent");
    match err {
        SdkError::Kernel(msg) => assert!(msg.contains("denied by kernel"), "{msg}"),
        other => panic!("expected kernel denial, got {other:?}"),
    }

    // An agent the cluster never placed has no owning node → routing error.
    let err = cluster
        .send_message("00000000-0000-0000-0000-000000000000", "hi")
        .await
        .expect_err("unknown agent should not route");
    match err {
        SdkError::Kernel(msg) => assert!(msg.contains("no cluster node owns"), "{msg}"),
        other => panic!("expected ownership error, got {other:?}"),
    }
}
