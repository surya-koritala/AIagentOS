//! Integration tests: drive several in-memory kernel nodes as one cluster.
//!
//! Each node is a real `AgentKernelImpl` behind its own `SyscallServer` on an
//! ephemeral loopback port. No external services. Exercises placement,
//! cross-node aggregation, and per-agent routing through `ClusterClient`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use agent_sdk::{
    ClusterClient, NodeAvailability, NodeProfile, Placement, PlacementConstraints, SdkError,
    WireErrorCode,
};
use kernel::syscall_server::SyscallServer;
use kernel::AgentKernelImpl;
use tokio::task::JoinHandle;

struct TempDb(PathBuf);

impl TempDb {
    fn new(label: &str) -> Self {
        Self(std::env::temp_dir().join(format!(
            "agentos-cluster-{label}-{}.sqlite",
            uuid::Uuid::new_v4()
        )))
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDb {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
        let _ = std::fs::remove_file(format!("{}-wal", self.0.display()));
        let _ = std::fs::remove_file(format!("{}-shm", self.0.display()));
    }
}

async fn serve_kernel(kernel: Arc<AgentKernelImpl>) -> (String, JoinHandle<std::io::Result<()>>) {
    let server = SyscallServer::bind(kernel, "127.0.0.1:0")
        .await
        .expect("bind");
    let address = server.local_addr().expect("local_addr").to_string();
    (address, tokio::spawn(server.serve()))
}

fn mutual_tls_configs() -> (
    rustls::ServerConfig,
    rustls::ClientConfig,
    rustls::ClientConfig,
) {
    use rcgen::{
        BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair,
        KeyUsagePurpose,
    };

    let _ = rustls::crypto::ring::default_provider().install_default();
    let ca_key = KeyPair::generate().expect("generate CA key");
    let mut ca_params = CertificateParams::default();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
    ];
    let ca_cert = ca_params.self_signed(&ca_key).expect("self-sign CA");

    let server_key = KeyPair::generate().expect("generate server key");
    let mut server_params =
        CertificateParams::new(vec!["localhost".to_string()]).expect("server params");
    server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let server_cert = server_params
        .signed_by(&server_key, &ca_cert, &ca_key)
        .expect("sign server certificate");

    let client_key = KeyPair::generate().expect("generate client key");
    let mut client_params = CertificateParams::new(Vec::<String>::new()).expect("client params");
    client_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let client_cert = client_params
        .signed_by(&client_key, &ca_cert, &ca_key)
        .expect("sign client certificate");

    let server = kernel::syscall_server::server_config_from_pem_with_client_ca(
        server_cert.pem().as_bytes(),
        server_key.serialize_pem().as_bytes(),
        ca_cert.pem().as_bytes(),
    )
    .expect("mutual TLS server config");
    let mut roots = rustls::RootCertStore::empty();
    roots.add(ca_cert.der().clone()).expect("trust cluster CA");
    let anonymous = rustls::ClientConfig::builder()
        .with_root_certificates(roots.clone())
        .with_no_client_auth();
    let authenticated = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_client_auth_cert(
            vec![client_cert.der().clone()],
            rustls::pki_types::PrivateKeyDer::try_from(client_key.serialize_der())
                .expect("client private key"),
        )
        .expect("mutual TLS client config");
    (server, anonymous, authenticated)
}

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

async fn spawn_authenticated_cluster(n: usize, token: &str) -> Vec<String> {
    let mut addrs = Vec::with_capacity(n);
    for _ in 0..n {
        let kernel = Arc::new(AgentKernelImpl::new().expect("kernel new"));
        let server = SyscallServer::bind(kernel, "127.0.0.1:0")
            .await
            .expect("bind")
            .with_auth_token(token);
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
    let message = err
        .kernel_message()
        .unwrap_or_else(|| panic!("expected kernel denial, got {err:?}"));
    assert!(message.contains("denied by kernel"), "{message}");

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

#[tokio::test]
async fn authenticated_cluster_construction_is_all_or_nothing() {
    let addrs = spawn_authenticated_cluster(2, "cluster-secret").await;

    let error = match ClusterClient::connect_authenticated(&addrs, "wrong-secret").await {
        Err(error) => error,
        Ok(_) => panic!("wrong credential must fail cluster construction"),
    };
    assert_eq!(
        error.wire_code(),
        Some(agent_sdk::WireErrorCode::AuthenticationFailed)
    );

    let mut cluster = ClusterClient::connect_authenticated(&addrs, "cluster-secret")
        .await
        .expect("authenticated cluster");
    assert_eq!(cluster.node_count(), 2);
    assert!(cluster.list_agents().await.expect("list").is_empty());
}

#[tokio::test]
async fn durable_identity_and_agent_ownership_survive_node_and_client_restart() {
    let database = TempDb::new("restart");
    let first_kernel =
        Arc::new(AgentKernelImpl::with_db_path(database.path()).expect("create persistent kernel"));
    let (first_address, first_server) = serve_kernel(first_kernel).await;
    let mut first_cluster = ClusterClient::connect(std::slice::from_ref(&first_address))
        .await
        .expect("connect first cluster client");
    let node_id = first_cluster.node_ids().remove(0);
    let placed = first_cluster
        .create_agent(
            "durable",
            "survive restart",
            None,
            None,
            None,
            Placement::LeastLoaded,
        )
        .await
        .expect("create durable agent");
    assert_eq!(placed.node_id, node_id);
    drop(first_cluster);
    first_server.abort();
    let _ = first_server.await;

    let restarted_kernel = Arc::new(
        AgentKernelImpl::with_db_path(database.path()).expect("restart persistent kernel"),
    );
    let (restarted_address, restarted_server) = serve_kernel(restarted_kernel).await;
    let mut restarted_cluster = ClusterClient::connect(&[restarted_address])
        .await
        .expect("connect after restart");
    assert_eq!(restarted_cluster.node_ids(), vec![node_id.clone()]);
    assert_eq!(
        restarted_cluster.owner_of(&placed.agent_id),
        Some(node_id.as_str()),
        "cluster construction must rebuild routing from durable node state"
    );
    assert!(restarted_cluster
        .list_agents()
        .await
        .expect("list after restart")
        .iter()
        .any(|(_, agent)| agent.id == placed.agent_id));

    restarted_server.abort();
    let _ = restarted_server.await;
}

#[tokio::test]
async fn duplicate_durable_node_identity_fails_closed() {
    let database = TempDb::new("duplicate-identity");
    let first = Arc::new(
        AgentKernelImpl::with_db_path(database.path()).expect("create first persistent kernel"),
    );
    let second = Arc::new(
        AgentKernelImpl::with_db_path(database.path()).expect("create duplicate persistent kernel"),
    );
    let (first_address, first_server) = serve_kernel(first).await;
    let (second_address, second_server) = serve_kernel(second).await;

    let error = match ClusterClient::connect(&[first_address, second_address]).await {
        Err(error) => error,
        Ok(_) => panic!("duplicate durable identities must be rejected"),
    };
    assert_eq!(error.wire_code(), Some(WireErrorCode::Conflict));
    assert!(error
        .kernel_message()
        .is_some_and(|message| message.contains("duplicate cluster node identity")));

    first_server.abort();
    second_server.abort();
    let _ = first_server.await;
    let _ = second_server.await;
}

#[tokio::test]
async fn draining_and_placement_constraints_fail_closed() {
    let addrs = spawn_cluster(2).await;
    let mut cluster = ClusterClient::connect(&addrs).await.expect("connect");
    let node_ids = cluster.node_ids();

    let first_profile = NodeProfile {
        region: Some("ca-central".into()),
        data_residency: Some("ca".into()),
        models: ["local-model".to_string()].into_iter().collect(),
        sandbox_profiles: ["hardened".to_string()].into_iter().collect(),
        labels: BTreeMap::from([("accelerator".into(), "cpu".into())]),
    };
    let second_profile = NodeProfile {
        region: Some("us-east".into()),
        data_residency: Some("us".into()),
        models: ["hosted-model".to_string()].into_iter().collect(),
        sandbox_profiles: ["standard".to_string()].into_iter().collect(),
        labels: BTreeMap::from([("accelerator".into(), "gpu".into())]),
    };

    let first = cluster.node(&node_ids[0]).expect("first node");
    let first_control = first
        .client()
        .set_node_profile(first_profile, 0, "configure Canadian node")
        .await
        .expect("set first profile");
    let drained = first
        .client()
        .set_node_availability(
            NodeAvailability::Draining,
            first_control.generation,
            "rolling maintenance",
        )
        .await
        .expect("drain first node");
    assert_eq!(drained.availability, NodeAvailability::Draining);
    let stale = first
        .client()
        .set_node_availability(NodeAvailability::Active, 0, "stale operator")
        .await
        .expect_err("stale generation must fail");
    assert_eq!(stale.wire_code(), Some(WireErrorCode::Conflict));

    let second = cluster.node(&node_ids[1]).expect("second node");
    second
        .client()
        .set_node_profile(second_profile, 0, "configure US node")
        .await
        .expect("set second profile");

    let unavailable = cluster
        .create_agent(
            "canada-only",
            "must stay in Canada",
            None,
            None,
            None,
            Placement::Constrained(PlacementConstraints {
                region: Some("ca-central".into()),
                data_residency: Some("ca".into()),
                model: Some("local-model".into()),
                sandbox_profile: Some("hardened".into()),
                labels: BTreeMap::new(),
            }),
        )
        .await
        .expect_err("a draining match must not receive new work");
    assert_eq!(unavailable.wire_code(), Some(WireErrorCode::Unavailable));

    let placed = cluster
        .create_agent(
            "gpu",
            "US hosted workload",
            None,
            None,
            None,
            Placement::Constrained(PlacementConstraints {
                region: Some("us-east".into()),
                data_residency: Some("us".into()),
                model: Some("hosted-model".into()),
                sandbox_profile: Some("standard".into()),
                labels: BTreeMap::from([("accelerator".into(), "gpu".into())]),
            }),
        )
        .await
        .expect("matching active node should accept placement");
    assert_eq!(placed.node_id, node_ids[1]);

    let round_robin = cluster
        .create_agent(
            "skip-draining",
            "unconstrained",
            None,
            None,
            None,
            Placement::RoundRobin,
        )
        .await
        .expect("round robin should skip draining nodes");
    assert_eq!(round_robin.node_id, node_ids[1]);
}

#[tokio::test]
async fn cluster_requires_mutual_tls_before_identity_discovery() {
    let (server_config, anonymous_config, authenticated_config) = mutual_tls_configs();
    let kernel = Arc::new(AgentKernelImpl::new().expect("kernel new"));
    let server = SyscallServer::bind_tls(kernel, "127.0.0.1:0", server_config)
        .await
        .expect("bind mutual TLS");
    let address = server.local_addr().expect("local_addr").to_string();
    let task = tokio::spawn(server.serve());

    let anonymous_error = match ClusterClient::connect_tls(
        std::slice::from_ref(&address),
        "localhost",
        anonymous_config,
    )
    .await
    {
        Err(error) => error,
        Ok(_) => panic!("a client without a trusted certificate must fail the TLS handshake"),
    };
    assert!(
        matches!(anonymous_error, SdkError::Transport(_)),
        "mTLS rejection must occur at the transport boundary: {anonymous_error:?}"
    );

    let mut cluster = ClusterClient::connect_tls(
        std::slice::from_ref(&address),
        "localhost",
        authenticated_config,
    )
    .await
    .expect("trusted mTLS client should connect");
    let node_id = cluster.node_ids().remove(0);
    let node = cluster.node(&node_id).expect("connected node");
    assert!(
        node.fingerprint().is_some(),
        "mTLS transport must still prove the durable application identity"
    );

    task.abort();
    let _ = task.await;
}
