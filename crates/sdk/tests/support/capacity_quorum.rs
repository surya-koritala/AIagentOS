use agent_sdk::{
    AuthorityCommandClass, AuthorityPrincipal, AuthorityPrincipalKind, AuthoritySigner,
};
use kernel::agent::AgentKernel;
use kernel::cluster_runtime::{ClusterRaftRuntime, ClusterRaftRuntimeConfig};
use kernel::config::{ClusterRaftConfig, ClusterRaftMemberConfig};
use kernel::syscall_server::SyscallServer;
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose,
};
use ring::signature::{Ed25519KeyPair, KeyPair as _};
use std::collections::BTreeSet;
use std::sync::Arc;

pub struct CapacityQuorum {
    pub addresses: Vec<String>,
    pub kernels: Vec<Arc<kernel::AgentKernelImpl>>,
    pub signer: AuthoritySigner,
    root: tempfile::TempDir,
    runtimes: Vec<ClusterRaftRuntime>,
    publishers: Vec<kernel::cluster_capacity::CapacityPublisher>,
    servers: Vec<tokio::task::JoinHandle<std::io::Result<()>>>,
}

impl CapacityQuorum {
    pub async fn start(count: usize, token: &str, workers_only: bool) -> Self {
        let root = tempfile::tempdir().unwrap();
        let operator = Arc::new(
            Ed25519KeyPair::from_pkcs8(
                Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new())
                    .unwrap()
                    .as_ref(),
            )
            .unwrap(),
        );
        let cluster_id = uuid::Uuid::new_v4().to_string();
        let principal_id = uuid::Uuid::new_v4().to_string();
        let principal = AuthorityPrincipal {
            principal_id: principal_id.clone(),
            public_key: hex(operator.public_key().as_ref()),
            kind: AuthorityPrincipalKind::Operator,
            tenant_id: None,
            allowed_command_classes: BTreeSet::from([
                AuthorityCommandClass::PrincipalAdmin,
                AuthorityCommandClass::Membership,
                AuthorityCommandClass::Ownership,
            ]),
            generation: 1,
            revoked: false,
            expires_at: None,
        };
        let mut ca_params = CertificateParams::default();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let ca = CertifiedIssuer::self_signed(ca_params, KeyPair::generate().unwrap()).unwrap();
        let ca_path = root.path().join("ca.pem");
        kernel::config::write_owner_only_atomic(&ca_path, ca.pem().as_bytes()).unwrap();
        let mut addresses = Vec::new();
        let mut kernels = Vec::new();
        let mut servers = Vec::new();
        let mut materials = Vec::new();
        let mut members = Vec::new();
        let mut bound = Vec::new();
        for index in 0..count {
            let kernel = Arc::new(
                kernel::AgentKernelImpl::with_db_path(
                    &root.path().join(format!("node-{index}.db")),
                )
                .unwrap(),
            );
            let server = SyscallServer::bind(kernel.clone(), "127.0.0.1:0")
                .await
                .unwrap()
                .with_auth_token(token);
            let address = server.local_addr().unwrap().to_string();
            addresses.push(address.clone());
            servers.push(tokio::spawn(server.serve()));
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let endpoint = listener.local_addr().unwrap().to_string();
            bound.push(listener);
            let key = KeyPair::generate().unwrap();
            let hostname = format!("capacity-{index}.example");
            let mut params = CertificateParams::new(vec![hostname.clone()]).unwrap();
            params.extended_key_usages = vec![
                ExtendedKeyUsagePurpose::ServerAuth,
                ExtendedKeyUsagePurpose::ClientAuth,
            ];
            let certificate = params.signed_by(&key, &ca).unwrap();
            let tls = kernel::cluster_runtime::ClusterRaftTls::from_pem(
                certificate.pem().as_bytes(),
                key.serialize_pem().as_bytes(),
                certificate.pem().as_bytes(),
                key.serialize_pem().as_bytes(),
                ca.pem().as_bytes(),
            )
            .unwrap();
            let cert_path = root.path().join(format!("node-{index}.pem"));
            let key_path = root.path().join(format!("node-{index}.key"));
            kernel::config::write_owner_only_atomic(&cert_path, certificate.pem().as_bytes())
                .unwrap();
            kernel::config::write_owner_only_atomic(&key_path, key.serialize_pem().as_bytes())
                .unwrap();
            materials.push((cert_path, key_path));
            let identity = kernel.cluster_control.identity();
            members.push(ClusterRaftMemberConfig {
                node_id: index as u64 + 1,
                application_node_id: identity.node_id.clone(),
                application_endpoint: address,
                application_tls_server_certificate_sha256: None,
                endpoint,
                server_name: hostname,
                tls_certificate_sha256: tls.server_certificate_sha256().into(),
                tls_client_certificate_sha256: tls.client_certificate_sha256().into(),
                tls_certificate_sha256_overlap: Vec::new(),
                tls_client_certificate_sha256_overlap: Vec::new(),
                identity_public_key: identity.public_key.clone(),
            });
            kernels.push(kernel);
        }
        let mut runtimes = Vec::new();
        for (index, listener) in bound.into_iter().enumerate() {
            let (cert, key) = &materials[index];
            let config = ClusterRaftConfig {
                enabled: true,
                bootstrap: true,
                node_id: index as u64 + 1,
                authority_cluster_id: cluster_id.clone(),
                authority_genesis_principals: vec![principal.clone()],
                listen_addr: listener.local_addr().unwrap().to_string(),
                cluster_name: "owned-capacity-quorum".into(),
                members: members.clone(),
                server_certificate_path: Some(cert.clone()),
                server_private_key_path: Some(key.clone()),
                client_certificate_path: Some(cert.clone()),
                client_private_key_path: Some(key.clone()),
                peer_ca_path: Some(ca_path.clone()),
                heartbeat_interval_ms: 100,
                election_timeout_min_ms: 500,
                election_timeout_max_ms: 1000,
                ..Default::default()
            };
            let config = ClusterRaftRuntimeConfig::from_operator_config(&config)
                .unwrap()
                .unwrap();
            drop(listener);
            runtimes.push(
                ClusterRaftRuntime::start(kernels[index].context_manager.clone(), config)
                    .await
                    .unwrap(),
            );
        }
        for runtime in &runtimes {
            runtime.ensure_configured_membership(true).await.unwrap();
        }
        // Every node must enter initialization concurrently: a follower waits
        // for the leader's command and cannot prevent that leader from starting.
        match runtimes.as_slice() {
            [one, two] => {
                let (one, two) = tokio::join!(
                    one.ensure_authority_initialized(),
                    two.ensure_authority_initialized()
                );
                one.unwrap();
                two.unwrap();
            }
            [one, two, three] => {
                let (one, two, three) = tokio::join!(
                    one.ensure_authority_initialized(),
                    two.ensure_authority_initialized(),
                    three.ensure_authority_initialized()
                );
                one.unwrap();
                two.unwrap();
                three.unwrap();
            }
            _ => panic!("owned capacity fixture requires two or three real nodes"),
        }
        let mut publishers = Vec::new();
        for (index, (kernel, runtime)) in kernels.iter().zip(&runtimes).enumerate() {
            kernel
                .install_cluster_authority(runtime.authority_handle())
                .unwrap();
            if workers_only && index == 0 {
                kernel
                    .cluster_control
                    .transition(
                        kernel::cluster_control::NodeAvailability::Draining,
                        0,
                        "fixture",
                        "authority voter does not host workload",
                    )
                    .unwrap();
            }
            assert!(matches!(
                runtime
                    .authority_handle()
                    .publish_kernel_capacity(kernel)
                    .await
                    .unwrap(),
                kernel::cluster_consensus::AuthorityResponse::NodeCapacityReported { .. }
            ));
            publishers.push(runtime.authority_handle().start_capacity_publisher(kernel));
        }
        let signer = AuthoritySigner::new(cluster_id, principal_id, 1, move |payload| {
            Ok(operator.sign(payload).as_ref().to_vec())
        });
        Self {
            addresses,
            kernels,
            signer,
            root,
            runtimes,
            publishers,
            servers,
        }
    }

    pub async fn refresh(&self) {
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        for (kernel, runtime) in self.kernels.iter().zip(&self.runtimes) {
            let _ = runtime
                .authority_handle()
                .publish_kernel_capacity(kernel)
                .await
                .unwrap();
        }
    }

    pub async fn close(mut self) {
        for publisher in self.publishers.drain(..) {
            publisher.shutdown().await;
        }
        for kernel in &self.kernels {
            for agent in kernel.agent_manager.list_agents(None) {
                kernel.stop_agent(agent.id).await.unwrap();
            }
        }
        for runtime in self.runtimes.drain(..) {
            runtime.shutdown().await.unwrap();
        }
        for server in self.servers.drain(..) {
            server.abort();
            let _ = server.await;
        }
        let weak = self.kernels.iter().map(Arc::downgrade).collect::<Vec<_>>();
        self.kernels.clear();
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while weak.iter().any(|kernel| kernel.upgrade().is_some()) {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        self.root.close().unwrap();
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
