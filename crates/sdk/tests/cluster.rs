//! Integration tests: drive several in-memory kernel nodes as one cluster.
//!
//! Each node is a real `AgentKernelImpl` behind its own `SyscallServer` on an
//! ephemeral loopback port. No external services. Exercises placement,
//! cross-node aggregation, and per-agent routing through `ClusterClient`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use agent_sdk::{
    AgentMutationFenceProof, AgentMutationFenceState, ClusterClient, ClusterMaintenanceConfig,
    ClusterMemberState, ClusterOwnershipState, KernelClient, NodeAvailability, NodeProfile,
    Placement, PlacementConstraints, ReservedAgentIdentity, SdkError, WireErrorCode,
};
use kernel::syscall_server::SyscallServer;
use kernel::{AgentConfig, AgentKernelImpl, Priority};
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
        let _ = std::fs::remove_file(format!("{}.lock", self.0.display()));
    }
}

async fn serve_kernel(kernel: Arc<AgentKernelImpl>) -> (String, JoinHandle<std::io::Result<()>>) {
    let server = SyscallServer::bind(kernel, "127.0.0.1:0")
        .await
        .expect("bind");
    let address = server.local_addr().expect("local_addr").to_string();
    (address, tokio::spawn(server.serve()))
}

async fn reopen_persistent_kernel(path: &Path, label: &str) -> AgentKernelImpl {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(2);
    loop {
        match AgentKernelImpl::with_db_path(path) {
            Ok(kernel) => return kernel,
            Err(error)
                if error.to_string().contains("already owned")
                    && tokio::time::Instant::now() < deadline =>
            {
                // An aborted in-process test server can have a detached
                // connection task release its final Arc one scheduler tick
                // later. A real process exit releases the OS lock immediately.
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
            Err(error) => panic!("{label}: {error}"),
        }
    }
}

fn mutual_tls_configs() -> (
    rustls::ServerConfig,
    rustls::ClientConfig,
    rustls::ClientConfig,
) {
    use rcgen::{
        BasicConstraints, CertificateParams, CertifiedIssuer, ExtendedKeyUsagePurpose, IsCa,
        KeyPair, KeyUsagePurpose,
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
    let ca_cert = CertifiedIssuer::self_signed(ca_params, ca_key).expect("self-sign CA");

    let server_key = KeyPair::generate().expect("generate server key");
    let mut server_params =
        CertificateParams::new(vec!["localhost".to_string()]).expect("server params");
    server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let server_cert = server_params
        .signed_by(&server_key, &ca_cert)
        .expect("sign server certificate");

    let client_key = KeyPair::generate().expect("generate client key");
    let mut client_params = CertificateParams::new(Vec::<String>::new()).expect("client params");
    client_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let client_cert = client_params
        .signed_by(&client_key, &ca_cert)
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

fn shared_mutual_tls_configs(
    server_count: usize,
) -> (Vec<rustls::ServerConfig>, rustls::ClientConfig, Vec<String>) {
    use rcgen::{
        BasicConstraints, CertificateParams, CertifiedIssuer, ExtendedKeyUsagePurpose, IsCa,
        KeyPair, KeyUsagePurpose,
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
    let ca = CertifiedIssuer::self_signed(ca_params, ca_key).expect("self-sign CA");

    let mut servers = Vec::with_capacity(server_count);
    let mut fingerprints = Vec::with_capacity(server_count);
    for _ in 0..server_count {
        let key = KeyPair::generate().expect("generate server key");
        let mut params =
            CertificateParams::new(vec!["localhost".to_string()]).expect("server params");
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let certificate = params
            .signed_by(&key, &ca)
            .expect("sign server certificate");
        fingerprints.push(
            ring::digest::digest(&ring::digest::SHA256, certificate.der().as_ref())
                .as_ref()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect(),
        );
        servers.push(
            kernel::syscall_server::server_config_from_pem_with_client_ca(
                certificate.pem().as_bytes(),
                key.serialize_pem().as_bytes(),
                ca.pem().as_bytes(),
            )
            .expect("mutual TLS server config"),
        );
    }

    let client_key = KeyPair::generate().expect("generate client key");
    let mut client_params = CertificateParams::new(Vec::<String>::new()).expect("client params");
    client_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let client_certificate = client_params
        .signed_by(&client_key, &ca)
        .expect("sign client certificate");
    let mut roots = rustls::RootCertStore::empty();
    roots.add(ca.der().clone()).expect("trust cluster CA");
    let client = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_client_auth_cert(
            vec![client_certificate.der().clone()],
            rustls::pki_types::PrivateKeyDer::try_from(client_key.serialize_der())
                .expect("client private key"),
        )
        .expect("mutual TLS client config");
    (servers, client, fingerprints)
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

struct ManagedCluster {
    authority_address: String,
    member_id: String,
    member_kernel: Arc<AgentKernelImpl>,
    authority: KernelClient,
    member: KernelClient,
    authority_task: JoinHandle<std::io::Result<()>>,
    member_task: JoinHandle<std::io::Result<()>>,
}

impl Drop for ManagedCluster {
    fn drop(&mut self) {
        self.authority_task.abort();
        self.member_task.abort();
    }
}

async fn spawn_managed_cluster(token: &str) -> ManagedCluster {
    let authority_kernel = Arc::new(AgentKernelImpl::new().expect("authority kernel"));
    let authority_server = SyscallServer::bind(authority_kernel, "127.0.0.1:0")
        .await
        .expect("bind authority")
        .with_auth_token(token);
    let authority_address = authority_server.local_addr().unwrap().to_string();
    let authority_task = tokio::spawn(authority_server.serve());

    let member_kernel = Arc::new(AgentKernelImpl::new().expect("member kernel"));
    let member_server = SyscallServer::bind(member_kernel.clone(), "127.0.0.1:0")
        .await
        .expect("bind member")
        .with_auth_token(token);
    let member_address = member_server.local_addr().unwrap().to_string();
    let member_task = tokio::spawn(member_server.serve());

    let mut authority = KernelClient::connect(&authority_address)
        .await
        .expect("connect authority");
    authority.authenticate(token).await.expect("auth authority");
    let mut member = KernelClient::connect(&member_address)
        .await
        .expect("connect member");
    member.authenticate(token).await.expect("auth member");
    let joined = ClusterClient::admit_node(
        &mut authority,
        &mut member,
        &member_address,
        None,
        "managed test member",
    )
    .await
    .expect("admit member");

    ManagedCluster {
        authority_address,
        member_id: joined.node_id,
        member_kernel,
        authority,
        member,
        authority_task,
        member_task,
    }
}

#[tokio::test]
async fn least_loaded_placement_spreads_agents() {
    let addrs = spawn_cluster(3).await;
    let mut cluster = ClusterClient::connect(&addrs).await.expect("connect");
    assert_eq!(cluster.node_count(), 3);
    assert!(!cluster.is_authority_managed());

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

    let restarted_kernel =
        Arc::new(reopen_persistent_kernel(database.path(), "restart persistent kernel").await);
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
    let database = TempDb::new("duplicate-identity-source");
    let first = Arc::new(
        AgentKernelImpl::with_db_path(database.path()).expect("create first persistent kernel"),
    );
    // Clone one verified offline snapshot to a different database path. Two
    // live kernels may never own one database path, but restoring the same
    // durable node identity onto two hosts must still be rejected by cluster
    // discovery.
    let backup_root = std::env::temp_dir().join(format!(
        "agentos-cluster-duplicate-backup-{}",
        uuid::Uuid::new_v4()
    ));
    first
        .context_manager
        .create_backup(&backup_root, "identity")
        .expect("back up durable identity");
    let duplicate_database = TempDb::new("duplicate-identity-restored");
    kernel::storage::restore_backup(&backup_root.join("identity"), duplicate_database.path())
        .expect("restore duplicate durable identity");
    let second = Arc::new(
        AgentKernelImpl::with_db_path(duplicate_database.path())
            .expect("create duplicate persistent kernel"),
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
    let _ = std::fs::remove_dir_all(backup_root);
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

#[tokio::test]
async fn membership_binds_rotated_tls_certificate_and_rejects_downgrade_or_old_leaf() {
    let token = "certificate-binding-system-secret";
    let (mut server_configs, client_config, fingerprints) = shared_mutual_tls_configs(3);
    let member_new_config = server_configs.pop().expect("new member config");
    let member_old_config = server_configs.pop().expect("old member config");
    let authority_config = server_configs.pop().expect("authority config");
    let member_old_fingerprint = &fingerprints[1];
    let member_new_fingerprint = &fingerprints[2];

    let authority_kernel = Arc::new(AgentKernelImpl::new().expect("authority kernel"));
    let authority_server =
        SyscallServer::bind_tls(authority_kernel, "127.0.0.1:0", authority_config)
            .await
            .expect("bind TLS authority")
            .with_auth_token(token);
    let authority_address = authority_server.local_addr().expect("authority address");
    let authority_task = tokio::spawn(authority_server.serve());

    let member_kernel = Arc::new(AgentKernelImpl::new().expect("member kernel"));
    let member_server = SyscallServer::bind_tls(
        Arc::clone(&member_kernel),
        "127.0.0.1:0",
        member_old_config.clone(),
    )
    .await
    .expect("bind old TLS member")
    .with_auth_token(token);
    let member_address = member_server.local_addr().expect("member address");
    let member_task = tokio::spawn(member_server.serve());

    let mut authority =
        KernelClient::connect_tls(authority_address, "localhost", client_config.clone())
            .await
            .expect("connect authority");
    authority.authenticate(token).await.expect("auth authority");
    let mut member = KernelClient::connect_tls(member_address, "localhost", client_config.clone())
        .await
        .expect("connect old member");
    member.authenticate(token).await.expect("auth old member");
    assert_eq!(
        member.tls_peer_certificate_fingerprint(),
        Some(member_old_fingerprint.as_str())
    );
    let joined = ClusterClient::admit_node(
        &mut authority,
        &mut member,
        member_address.to_string(),
        None,
        "initial TLS-bound membership",
    )
    .await
    .expect("admit TLS-bound member");
    assert_eq!(
        joined.tls_server_certificate_fingerprint.as_deref(),
        Some(member_old_fingerprint.as_str())
    );

    let plaintext_server = SyscallServer::bind(Arc::clone(&member_kernel), "127.0.0.1:0")
        .await
        .expect("bind plaintext downgrade")
        .with_auth_token(token);
    let plaintext_address = plaintext_server
        .local_addr()
        .expect("plaintext downgrade address");
    let plaintext_task = tokio::spawn(plaintext_server.serve());
    let mut plaintext_member = KernelClient::connect(plaintext_address)
        .await
        .expect("connect plaintext downgrade");
    plaintext_member
        .authenticate(token)
        .await
        .expect("auth plaintext downgrade");
    let downgrade = ClusterClient::admit_node(
        &mut authority,
        &mut plaintext_member,
        plaintext_address.to_string(),
        Some(joined.generation),
        "attempt transport downgrade",
    )
    .await
    .expect_err("a TLS-bound identity cannot rejoin without its certificate binding");
    assert!(
        downgrade
            .to_string()
            .contains("TLS certificate binding cannot be removed"),
        "unexpected downgrade error: {downgrade}"
    );
    plaintext_task.abort();
    let _ = plaintext_task.await;

    member_task.abort();
    let _ = member_task.await;
    drop(member);
    let member_server = SyscallServer::bind_tls(
        Arc::clone(&member_kernel),
        member_address,
        member_new_config.clone(),
    )
    .await
    .expect("bind rotated TLS member")
    .with_auth_token(token);
    let member_task = tokio::spawn(member_server.serve());
    let mut rotated = KernelClient::connect_tls(member_address, "localhost", client_config.clone())
        .await
        .expect("connect rotated member");
    rotated
        .authenticate(token)
        .await
        .expect("auth rotated member");
    let rotated_record = ClusterClient::admit_node(
        &mut authority,
        &mut rotated,
        member_address.to_string(),
        Some(joined.generation),
        "rotate server certificate",
    )
    .await
    .expect("re-admit rotated member");
    assert_eq!(
        rotated_record.tls_server_certificate_fingerprint.as_deref(),
        Some(member_new_fingerprint.as_str())
    );
    assert_eq!(rotated_record.generation, joined.generation + 1);
    let rotation_audit = authority
        .cluster_membership_audit(1)
        .await
        .expect("certificate rotation audit");
    assert_eq!(
        rotation_audit[0]
            .previous_tls_server_certificate_fingerprint
            .as_deref(),
        Some(member_old_fingerprint.as_str())
    );
    assert_eq!(
        rotation_audit[0]
            .current_tls_server_certificate_fingerprint
            .as_deref(),
        Some(member_new_fingerprint.as_str())
    );

    member_task.abort();
    let _ = member_task.await;
    drop(rotated);
    let stale_server = SyscallServer::bind_tls(
        Arc::clone(&member_kernel),
        member_address,
        member_old_config,
    )
    .await
    .expect("bind stale certificate at authorized endpoint")
    .with_auth_token(token);
    let stale_task = tokio::spawn(stale_server.serve());
    let stale = match ClusterClient::connect_discovered_tls_authenticated(
        authority_address.to_string(),
        "localhost",
        client_config.clone(),
        token,
    )
    .await
    {
        Err(error) => error,
        Ok(_) => panic!("the superseded leaf certificate must not satisfy membership"),
    };
    assert_eq!(stale.wire_code(), Some(WireErrorCode::Conflict));
    stale_task.abort();
    let _ = stale_task.await;

    let current_server = SyscallServer::bind_tls(member_kernel, member_address, member_new_config)
        .await
        .expect("restore current certificate")
        .with_auth_token(token);
    let current_task = tokio::spawn(current_server.serve());
    let current = ClusterClient::connect_discovered_tls_authenticated(
        authority_address.to_string(),
        "localhost",
        client_config,
        token,
    )
    .await
    .expect("current certificate and durable identity satisfy membership");
    assert_eq!(current.node_count(), 1);

    current_task.abort();
    let _ = current_task.await;
    authority_task.abort();
    let _ = authority_task.await;
}

#[tokio::test]
async fn authorized_membership_drives_discovery_leave_and_revocation() {
    let token = "membership-system-secret";
    let authority_kernel = Arc::new(AgentKernelImpl::new().expect("authority kernel"));
    let authority_server = SyscallServer::bind(authority_kernel, "127.0.0.1:0")
        .await
        .expect("bind authority")
        .with_auth_token(token);
    let authority_address = authority_server.local_addr().unwrap().to_string();
    let authority_task = tokio::spawn(authority_server.serve());

    let mut member_tasks = Vec::new();
    let mut member_addresses = Vec::new();
    for _ in 0..2 {
        let kernel = Arc::new(AgentKernelImpl::new().expect("member kernel"));
        let server = SyscallServer::bind(kernel, "127.0.0.1:0")
            .await
            .expect("bind member")
            .with_auth_token(token);
        member_addresses.push(server.local_addr().unwrap().to_string());
        member_tasks.push(tokio::spawn(server.serve()));
    }

    let mut authority = KernelClient::connect(&authority_address)
        .await
        .expect("connect authority");
    authority.authenticate(token).await.expect("auth authority");
    let mut joined = Vec::new();
    for endpoint in &member_addresses {
        let mut member = KernelClient::connect(endpoint)
            .await
            .expect("connect member");
        member.authenticate(token).await.expect("auth member");
        joined.push(
            ClusterClient::admit_node(
                &mut authority,
                &mut member,
                endpoint,
                None,
                "initial membership",
            )
            .await
            .expect("admit node"),
        );
    }

    let snapshot = authority
        .cluster_membership()
        .await
        .expect("membership snapshot");
    assert_eq!(snapshot.generation, 2);
    assert_eq!(snapshot.members.len(), 2);
    assert!(snapshot
        .members
        .iter()
        .all(|member| member.state == ClusterMemberState::Active));

    let discovered = ClusterClient::connect_discovered_authenticated(&authority_address, token)
        .await
        .expect("authorized discovery");
    assert_eq!(discovered.node_count(), 2);
    drop(discovered);

    let left = authority
        .set_cluster_member_state(
            &joined[0].node_id,
            ClusterMemberState::Left,
            joined[0].generation,
            "rolling maintenance",
        )
        .await
        .expect("leave member");
    assert_eq!(left.state, ClusterMemberState::Left);
    let stale = authority
        .set_cluster_member_state(
            &joined[0].node_id,
            ClusterMemberState::Revoked,
            joined[0].generation,
            "stale operator",
        )
        .await
        .expect_err("stale generation must fail");
    assert_eq!(stale.wire_code(), Some(WireErrorCode::Conflict));

    let discovered = ClusterClient::connect_discovered_authenticated(&authority_address, token)
        .await
        .expect("discovery skips left member");
    assert_eq!(discovered.node_count(), 1);
    assert_eq!(discovered.node_ids(), vec![joined[1].node_id.clone()]);
    drop(discovered);

    let revoked = authority
        .set_cluster_member_state(
            &joined[1].node_id,
            ClusterMemberState::Revoked,
            joined[1].generation,
            "identity compromise",
        )
        .await
        .expect("revoke member");
    assert_eq!(revoked.state, ClusterMemberState::Revoked);
    let unavailable =
        match ClusterClient::connect_discovered_authenticated(&authority_address, token).await {
            Err(error) => error,
            Ok(_) => panic!("no inactive or revoked member may be discovered"),
        };
    assert_eq!(unavailable.wire_code(), Some(WireErrorCode::Unavailable));

    let audit = authority
        .cluster_membership_audit(10)
        .await
        .expect("membership audit");
    assert_eq!(audit.len(), 4);
    assert_eq!(audit[0].current, ClusterMemberState::Revoked);

    authority_task.abort();
    let _ = authority_task.await;
    for task in member_tasks {
        task.abort();
        let _ = task.await;
    }
}

#[tokio::test]
async fn discovered_cluster_publishes_renews_rebuilds_and_enforces_fenced_routes() {
    let token = "managed-routing-system-secret";
    let authority_kernel = Arc::new(AgentKernelImpl::new().expect("authority kernel"));
    let authority_server = SyscallServer::bind(authority_kernel, "127.0.0.1:0")
        .await
        .expect("bind authority")
        .with_auth_token(token);
    let authority_address = authority_server.local_addr().unwrap().to_string();
    let authority_task = tokio::spawn(authority_server.serve());

    let member_kernel = Arc::new(AgentKernelImpl::new().expect("member kernel"));
    let member_server = SyscallServer::bind(member_kernel, "127.0.0.1:0")
        .await
        .expect("bind member")
        .with_auth_token(token);
    let member_address = member_server.local_addr().unwrap().to_string();
    let member_task = tokio::spawn(member_server.serve());

    let mut authority = KernelClient::connect(&authority_address)
        .await
        .expect("connect authority");
    authority.authenticate(token).await.expect("auth authority");
    let mut member = KernelClient::connect(&member_address)
        .await
        .expect("connect member");
    member.authenticate(token).await.expect("auth member");
    let joined = ClusterClient::admit_node(
        &mut authority,
        &mut member,
        &member_address,
        None,
        "managed routing member",
    )
    .await
    .expect("admit member");
    let cluster_id = authority
        .cluster_membership()
        .await
        .expect("membership")
        .cluster_id;

    let mut cluster = ClusterClient::connect_discovered_authenticated(&authority_address, token)
        .await
        .expect("discover managed cluster");
    assert!(cluster.is_authority_managed());
    let placed = cluster
        .create_agent(
            "managed",
            "authority fenced",
            None,
            None,
            None,
            Placement::LeastLoaded,
        )
        .await
        .expect("create managed agent");
    assert_eq!(placed.node_id, joined.node_id);

    let claimed = authority
        .cluster_agent_ownership(&placed.agent_id)
        .await
        .expect("read ownership")
        .expect("ownership published");
    assert_eq!(claimed.owner_node_id, joined.node_id);
    assert_eq!(claimed.state, ClusterOwnershipState::Active);
    let installed = member
        .agent_mutation_fence(&placed.agent_id)
        .await
        .expect("read destination fence")
        .expect("destination fence published");
    assert_eq!(installed.cluster_id, cluster_id);
    assert_eq!(installed.owner_node_id, joined.node_id);
    assert_eq!(installed.authority_generation, claimed.generation);
    assert_eq!(installed.fencing_token, claimed.fencing_token);
    assert_eq!(installed.state, AgentMutationFenceState::Active);

    assert_eq!(
        member
            .send_message(&placed.agent_id, "ordinary path must fail")
            .await
            .expect_err("managed agent rejects ordinary mutation")
            .wire_code(),
        Some(WireErrorCode::Conflict)
    );
    assert_eq!(
        cluster
            .send_message(&placed.agent_id, "managed fenced turn")
            .await
            .expect_err("stub provider remains unavailable after fence admission")
            .wire_code(),
        Some(WireErrorCode::Unavailable)
    );
    let mut streamed = Vec::new();
    assert_eq!(
        cluster
            .send_message_stream(
                "managed-stream",
                &placed.agent_id,
                "managed fenced stream",
                |event| streamed.push(event.clone()),
            )
            .await
            .expect_err("fenced stream reaches unavailable stub provider")
            .wire_code(),
        Some(WireErrorCode::Unavailable)
    );
    assert!(streamed.is_empty());

    let externally_renewed = authority
        .renew_cluster_agent_ownership(
            &placed.agent_id,
            &joined.node_id,
            claimed.fencing_token,
            60,
            "external authority renewal",
        )
        .await
        .expect("renew outside cluster client");
    assert_eq!(
        cluster
            .send_message(&placed.agent_id, "refresh renewed authority route")
            .await
            .expect_err("refreshed route reaches unavailable stub provider")
            .wire_code(),
        Some(WireErrorCode::Unavailable)
    );
    assert_eq!(
        member
            .agent_mutation_fence(&placed.agent_id)
            .await
            .expect("read refreshed fence")
            .expect("refreshed fence")
            .authority_generation,
        externally_renewed.generation
    );

    assert_eq!(
        cluster
            .renew_all_agent_ownerships(60)
            .await
            .expect("renew and publish every route"),
        1
    );
    let renewed = authority
        .cluster_agent_ownership(&placed.agent_id)
        .await
        .expect("read renewed ownership")
        .expect("renewed ownership");
    assert!(renewed.generation > externally_renewed.generation);
    assert_eq!(renewed.fencing_token, claimed.fencing_token);
    let renewed_fence = member
        .agent_mutation_fence(&placed.agent_id)
        .await
        .expect("read renewed fence")
        .expect("renewed fence");
    assert_eq!(renewed_fence.authority_generation, renewed.generation);

    drop(cluster);
    let mut rebuilt = ClusterClient::connect_discovered_authenticated(&authority_address, token)
        .await
        .expect("rebuild exact managed route");
    assert_eq!(
        rebuilt.owner_of(&placed.agent_id),
        Some(joined.node_id.as_str())
    );
    assert_eq!(
        rebuilt
            .send_message(&placed.agent_id, "rebuilt fenced route")
            .await
            .expect_err("rebuilt route reaches unavailable stub provider")
            .wire_code(),
        Some(WireErrorCode::Unavailable)
    );

    authority
        .release_cluster_agent_ownership(
            &placed.agent_id,
            &joined.node_id,
            renewed.fencing_token,
            "invalidate stale cluster client",
        )
        .await
        .expect("release ownership");
    assert_eq!(
        rebuilt
            .send_message(&placed.agent_id, "stale route must fail closed")
            .await
            .expect_err("released route rejected")
            .wire_code(),
        Some(WireErrorCode::Conflict)
    );
    assert_eq!(rebuilt.owner_of(&placed.agent_id), None);
    assert_eq!(
        rebuilt
            .rebuild_owners()
            .await
            .expect_err("released authority evidence cannot rebuild a route")
            .wire_code(),
        Some(WireErrorCode::Conflict)
    );
    assert_eq!(rebuilt.owner_of(&placed.agent_id), None);

    authority_task.abort();
    let _ = authority_task.await;
    member_task.abort();
    let _ = member_task.await;
}

#[tokio::test]
async fn failed_managed_destination_creation_retains_a_reconcilable_reservation() {
    let token = "managed-publication-failure-secret";
    let mut managed = spawn_managed_cluster(token).await;
    let mut cluster =
        ClusterClient::connect_discovered_authenticated(&managed.authority_address, token)
            .await
            .expect("discover managed cluster");
    cluster
        .create_agent(
            "quota-fill",
            "consume the single destination slot",
            None,
            None,
            None,
            Placement::LeastLoaded,
        )
        .await
        .expect("create first managed agent");
    let max_agents = managed
        .member
        .list_operator_tunables()
        .await
        .expect("list destination tunables")
        .into_iter()
        .find(|tunable| tunable.name == kernel::operator_control::MAX_AGENTS)
        .expect("max-agents tunable");
    managed
        .member
        .set_operator_tunable(&max_agents.name, 1, max_agents.revision)
        .await
        .expect("limit destination to its current agent");

    let error = cluster
        .create_agent(
            "publication-failure",
            "return exact reconciliation identity",
            None,
            None,
            None,
            Placement::LeastLoaded,
        )
        .await
        .expect_err("destination quota must fail after authority reservation");
    assert!(
        !error.is_retryable(),
        "partial publication requires reconciliation, never blind replay"
    );
    let SdkError::ClusterRoutePublication {
        agent_id,
        stage,
        source,
    } = error
    else {
        panic!("expected route publication error, got {error:?}");
    };
    assert_eq!(stage, "destination agent creation");
    assert!(source
        .kernel_message()
        .is_some_and(|message| message.contains("kernel.max_agents")));
    assert_eq!(cluster.owner_of(&agent_id), None);
    let reservation = managed
        .authority
        .cluster_agent_ownership(&agent_id)
        .await
        .expect("inspect authority")
        .expect("reservation remains durable");
    assert_eq!(reservation.owner_node_id, managed.member_id);
    assert_eq!(reservation.state, ClusterOwnershipState::Active);
    assert_eq!(
        reservation.reason,
        "cluster client pre-creation reservation"
    );
    assert!(!managed
        .member
        .list_agents()
        .await
        .expect("inspect destination")
        .iter()
        .any(|agent| agent.id == agent_id));
    let report = cluster
        .reconcile_routes()
        .await
        .expect("unexpired reservation remains pending");
    assert_eq!(report.pending_reservations, 1);
    assert_eq!(cluster.owner_of(&agent_id), None);
}

#[tokio::test]
async fn reconciliation_recovers_an_expired_lease_and_missing_destination_fence() {
    let token = "managed-reconciliation-secret";
    let mut managed = spawn_managed_cluster(token).await;
    let agent_id = uuid::Uuid::new_v4().to_string();
    let reserved = managed
        .authority
        .claim_cluster_agent_ownership(
            &agent_id,
            &managed.member_id,
            5,
            None,
            "cluster client pre-creation reservation",
        )
        .await
        .expect("reserve exact agent identity");
    assert_eq!(
        managed
            .member_kernel
            .create_agent_full_with_id(
                uuid::Uuid::parse_str(&agent_id).unwrap(),
                AgentConfig {
                    name: "crash-recovery".into(),
                    task: "created before the publisher crashed".into(),
                    llm_provider: "stub".into(),
                    permission_profile: "standard".into(),
                    priority: Priority::new(3).unwrap(),
                    sandbox_config: None,
                },
            )
            .await
            .expect("create exact destination agent")
            .id
            .to_string(),
        agent_id
    );
    assert!(managed
        .member
        .agent_mutation_fence(&agent_id)
        .await
        .expect("inspect pre-recovery fence")
        .is_none());

    let expiry_deadline = tokio::time::Instant::now() + Duration::from_secs(7);
    loop {
        match managed
            .authority
            .active_cluster_agent_ownership(&agent_id)
            .await
        {
            Err(error) if error.wire_code() == Some(WireErrorCode::Conflict) => break,
            Ok(_) if tokio::time::Instant::now() < expiry_deadline => {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Ok(_) => panic!("ownership lease did not expire"),
            Err(error) => panic!("unexpected ownership read failure: {error}"),
        }
    }

    let cluster =
        ClusterClient::connect_discovered_authenticated(&managed.authority_address, token)
            .await
            .expect("reconcile durable route after publisher crash");
    assert_eq!(
        cluster.owner_of(&agent_id),
        Some(managed.member_id.as_str())
    );
    let recovered = managed
        .authority
        .active_cluster_agent_ownership(&agent_id)
        .await
        .expect("recovered ownership is active");
    assert!(recovered.fencing_token > reserved.fencing_token);
    assert!(recovered.generation > reserved.generation);
    let installed = managed
        .member
        .agent_mutation_fence(&agent_id)
        .await
        .expect("inspect recovered fence")
        .expect("reconciliation installs destination fence");
    assert_eq!(installed.owner_node_id, managed.member_id);
    assert_eq!(installed.fencing_token, recovered.fencing_token);
    assert_eq!(installed.authority_generation, recovered.generation);

    let duplicate = managed
        .member
        .create_agent_with_id(
            ReservedAgentIdentity {
                agent_id: agent_id.clone(),
                ownership_proof: AgentMutationFenceProof {
                    cluster_id: installed.cluster_id.clone(),
                    owner_node_id: installed.owner_node_id.clone(),
                    authority_generation: installed.authority_generation,
                    fencing_token: installed.fencing_token,
                },
            },
            "duplicate",
            "must not overwrite recovered state",
            None,
            None,
            None,
        )
        .await
        .expect_err("exact-id retry cannot overwrite an existing agent");
    assert_eq!(duplicate.wire_code(), Some(WireErrorCode::Conflict));
    assert!(!duplicate.is_retryable());
    assert!(duplicate
        .kernel_message()
        .is_some_and(|message| message.contains("already exists")));
}

#[tokio::test]
async fn reconciliation_releases_an_expired_reservation_without_a_local_agent() {
    let token = "managed-reservation-cleanup-secret";
    let mut managed = spawn_managed_cluster(token).await;
    let agent_id = uuid::Uuid::new_v4().to_string();
    let cluster_id = managed
        .authority
        .cluster_membership()
        .await
        .expect("read cluster identity")
        .cluster_id;
    let reserved = managed
        .authority
        .claim_cluster_agent_ownership(
            &agent_id,
            &managed.member_id,
            5,
            None,
            "cluster client pre-creation reservation",
        )
        .await
        .expect("reserve exact agent identity");
    let stale_proof = AgentMutationFenceProof {
        cluster_id,
        owner_node_id: reserved.owner_node_id.clone(),
        authority_generation: reserved.generation,
        fencing_token: reserved.fencing_token,
    };

    let expiry_deadline = tokio::time::Instant::now() + Duration::from_secs(7);
    loop {
        match managed
            .authority
            .active_cluster_agent_ownership(&agent_id)
            .await
        {
            Err(error) if error.wire_code() == Some(WireErrorCode::Conflict) => break,
            Ok(_) if tokio::time::Instant::now() < expiry_deadline => {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Ok(_) => panic!("ownership lease did not expire"),
            Err(error) => panic!("unexpected ownership read failure: {error}"),
        }
    }

    let mut cluster =
        ClusterClient::connect_discovered_authenticated(&managed.authority_address, token)
            .await
            .expect("expired incomplete reservation is reconciled");
    assert_eq!(cluster.owner_of(&agent_id), None);
    let released = managed
        .authority
        .cluster_agent_ownership(&agent_id)
        .await
        .expect("read reconciled ownership")
        .expect("released tombstone remains durable");
    assert_eq!(released.state, ClusterOwnershipState::Released);
    assert!(released.fencing_token > reserved.fencing_token);
    assert_eq!(
        released.reason,
        "release expired incomplete cluster creation"
    );
    assert!(!managed
        .member
        .list_agents()
        .await
        .expect("inspect destination")
        .iter()
        .any(|agent| agent.id == agent_id));
    let retired = managed
        .member
        .agent_mutation_fence(&agent_id)
        .await
        .expect("inspect reservation fence")
        .expect("cleanup retains a destination tombstone");
    assert_eq!(retired.state, AgentMutationFenceState::Retired);
    assert_eq!(retired.fencing_token, released.fencing_token);
    let delayed = managed
        .member
        .create_agent_with_id(
            ReservedAgentIdentity {
                agent_id: agent_id.clone(),
                ownership_proof: stale_proof,
            },
            "delayed-creator",
            "must not cross cleanup",
            None,
            None,
            None,
        )
        .await
        .expect_err("stale creator must be fenced after cleanup");
    assert_eq!(delayed.wire_code(), Some(WireErrorCode::Conflict));
    assert!(!managed
        .member
        .list_agents()
        .await
        .expect("inspect destination after delayed create")
        .iter()
        .any(|agent| agent.id == agent_id));
    let report = cluster
        .reconcile_routes()
        .await
        .expect("released tombstone is stable on repeated reconciliation");
    assert_eq!(report, Default::default());
}

#[tokio::test]
async fn explicit_automatic_maintenance_renews_idle_routes_and_stops_on_drop() {
    let token = "managed-automatic-maintenance-secret";
    let mut managed = spawn_managed_cluster(token).await;
    let mut cluster = ClusterClient::connect_discovered_authenticated_with_maintenance(
        &managed.authority_address,
        token,
        ClusterMaintenanceConfig {
            lease_ttl_seconds: 5,
            renew_interval: Duration::from_secs(1),
        },
    )
    .await
    .expect("discover with explicit maintenance");
    let placed = cluster
        .create_agent(
            "idle-maintained",
            "remain fenced while the control plane is idle",
            None,
            None,
            None,
            Placement::LeastLoaded,
        )
        .await
        .expect("create maintained route");
    let initial = managed
        .authority
        .active_cluster_agent_ownership(&placed.agent_id)
        .await
        .expect("initial ownership");

    let renewal_deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let status = cluster
            .maintenance_status()
            .expect("maintenance status is exposed");
        if status.successful_renewals > 0 {
            assert!(status.running);
            assert_eq!(status.tracked_routes, 1);
            assert_eq!(status.failed_renewals, 0);
            assert!(status.last_error.is_none());
            break;
        }
        assert!(
            tokio::time::Instant::now() < renewal_deadline,
            "automatic ownership renewal did not complete: {status:?}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    let renewed = managed
        .authority
        .active_cluster_agent_ownership(&placed.agent_id)
        .await
        .expect("idle ownership remains active");
    assert!(renewed.generation > initial.generation);
    let renewed_fence = managed
        .member
        .agent_mutation_fence(&placed.agent_id)
        .await
        .expect("inspect maintained fence")
        .expect("maintained fence exists");
    assert_eq!(renewed_fence.authority_generation, renewed.generation);
    assert_eq!(renewed_fence.fencing_token, renewed.fencing_token);

    drop(cluster);
    let stop_deadline = tokio::time::Instant::now() + Duration::from_secs(7);
    loop {
        match managed
            .authority
            .active_cluster_agent_ownership(&placed.agent_id)
            .await
        {
            Err(error) if error.wire_code() == Some(WireErrorCode::Conflict) => break,
            Ok(_) if tokio::time::Instant::now() < stop_deadline => {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Ok(_) => panic!("maintenance continued renewing after ClusterClient drop"),
            Err(error) => panic!("unexpected ownership read failure: {error}"),
        }
    }
}

#[tokio::test]
async fn membership_authority_and_discovery_survive_authority_restart() {
    let token = "persistent-membership-secret";
    let database = TempDb::new("membership-authority");
    let authority_kernel = Arc::new(
        AgentKernelImpl::with_db_path(database.path()).expect("persistent authority kernel"),
    );
    let authority_server = SyscallServer::bind(authority_kernel, "127.0.0.1:0")
        .await
        .expect("bind authority")
        .with_auth_token(token);
    let first_authority_address = authority_server.local_addr().unwrap().to_string();
    let first_authority_task = tokio::spawn(authority_server.serve());

    let member_kernel = Arc::new(AgentKernelImpl::new().expect("member kernel"));
    let member_server = SyscallServer::bind(member_kernel, "127.0.0.1:0")
        .await
        .expect("bind member")
        .with_auth_token(token);
    let member_address = member_server.local_addr().unwrap().to_string();
    let member_task = tokio::spawn(member_server.serve());

    let mut authority = KernelClient::connect(&first_authority_address)
        .await
        .expect("connect authority");
    authority.authenticate(token).await.expect("auth authority");
    let mut member = KernelClient::connect(&member_address)
        .await
        .expect("connect member");
    member.authenticate(token).await.expect("auth member");
    let joined = ClusterClient::admit_node(
        &mut authority,
        &mut member,
        &member_address,
        None,
        "persistent admission",
    )
    .await
    .expect("admit member");
    let before = authority.cluster_membership().await.expect("snapshot");
    assert_eq!(before.members, vec![joined]);
    drop(authority);
    first_authority_task.abort();
    let _ = first_authority_task.await;

    let restarted_kernel =
        Arc::new(reopen_persistent_kernel(database.path(), "restart authority kernel").await);
    let restarted_server = SyscallServer::bind(restarted_kernel, "127.0.0.1:0")
        .await
        .expect("bind restarted authority")
        .with_auth_token(token);
    let restarted_address = restarted_server.local_addr().unwrap().to_string();
    let restarted_task = tokio::spawn(restarted_server.serve());
    let mut restarted = KernelClient::connect(&restarted_address)
        .await
        .expect("connect restarted authority");
    restarted
        .authenticate(token)
        .await
        .expect("auth restarted authority");
    assert_eq!(
        restarted
            .cluster_membership()
            .await
            .expect("persisted membership"),
        before
    );
    assert_eq!(
        restarted
            .cluster_membership_audit(10)
            .await
            .expect("persisted audit")
            .len(),
        1
    );

    let discovered = ClusterClient::connect_discovered_authenticated(&restarted_address, token)
        .await
        .expect("discover after authority restart");
    assert_eq!(discovered.node_count(), 1);
    assert_eq!(
        discovered.node_ids(),
        vec![before.members[0].node_id.clone()]
    );

    restarted_task.abort();
    let _ = restarted_task.await;
    member_task.abort();
    let _ = member_task.await;
}
