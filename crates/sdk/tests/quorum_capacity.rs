//! Actual signed capacity on a three-node mutual-TLS Raft authority.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use agent_sdk::{
    AuthorityCommandClass, AuthorityPrincipal, AuthorityPrincipalKind, AuthoritySigner,
    ClusterClient, KernelClient, Placement, SdkError, WireErrorCode,
};
use kernel::cluster_runtime::{ClusterRaftRuntime, ClusterRaftRuntimeConfig, ClusterRaftTls};
use kernel::config::{ClusterRaftConfig, ClusterRaftMemberConfig};
use kernel::syscall_server::SyscallServer;
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose,
};
use ring::signature::{Ed25519KeyPair, KeyPair as _};
use uuid::Uuid;

const TOKEN: &str = "live-reconfiguration-controlled-ci";

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stale_capacity_makes_a_node_ineligible_and_the_error_is_retryable() {
    tokio::time::timeout(Duration::from_secs(120), async {
        let root = tempfile::tempdir().unwrap();
        let operator_document =
            Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new()).unwrap();
        let operator = Arc::new(Ed25519KeyPair::from_pkcs8(operator_document.as_ref()).unwrap());
        let principal_id = Uuid::new_v4().to_string();
        let cluster_id = Uuid::new_v4().to_string();
        let principal = AuthorityPrincipal {
            principal_id: principal_id.clone(),
            public_key: hex(operator.public_key().as_ref()),
            kind: AuthorityPrincipalKind::Operator,
            tenant_id: None,
            allowed_command_classes: BTreeSet::from([
                AuthorityCommandClass::PrincipalAdmin,
                AuthorityCommandClass::TransportAdmin,
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
        let ca_path = root.path().join("peer-ca.pem");
        kernel::config::write_owner_only_atomic(&ca_path, ca.pem().as_bytes()).unwrap();
        let mut kernels = Vec::new();
        let mut addresses = Vec::new();
        let mut serving = Vec::new();
        let mut listeners = Vec::new();
        let mut materials = Vec::new();
        let mut members = Vec::new();
        for id in 1..=3 {
            let kernel = Arc::new(
                kernel::AgentKernelImpl::with_db_path(&root.path().join(format!("node-{id}.db")))
                    .unwrap(),
            );
            let server = SyscallServer::bind(kernel.clone(), "127.0.0.1:0")
                .await
                .unwrap()
                .with_auth_token(TOKEN);
            let address = server.local_addr().unwrap();
            addresses.push(address);
            serving.push(tokio::spawn(server.serve()));
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let raft_address = listener.local_addr().unwrap();
            listeners.push(listener);
            let hostname = format!("raft-{id}.example");
            let key = KeyPair::generate().unwrap();
            let mut params = CertificateParams::new(vec![hostname.clone()]).unwrap();
            params.extended_key_usages = vec![
                ExtendedKeyUsagePurpose::ServerAuth,
                ExtendedKeyUsagePurpose::ClientAuth,
            ];
            let certificate = params.signed_by(&key, &ca).unwrap();
            let tls = ClusterRaftTls::from_pem(
                certificate.pem().as_bytes(),
                key.serialize_pem().as_bytes(),
                certificate.pem().as_bytes(),
                key.serialize_pem().as_bytes(),
                ca.pem().as_bytes(),
            )
            .unwrap();
            let cert_path = root.path().join(format!("node-{id}-cert.pem"));
            let key_path = root.path().join(format!("node-{id}-key.pem"));
            kernel::config::write_owner_only_atomic(&cert_path, certificate.pem().as_bytes())
                .unwrap();
            kernel::config::write_owner_only_atomic(&key_path, key.serialize_pem().as_bytes())
                .unwrap();
            materials.push((cert_path, key_path));
            let identity = kernel.cluster_control.identity();
            members.push(ClusterRaftMemberConfig {
                node_id: id,
                application_node_id: identity.node_id.clone(),
                application_endpoint: address.to_string(),
                application_tls_server_certificate_sha256: None,
                endpoint: raft_address.to_string(),
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
        for (index, listener) in listeners.into_iter().enumerate() {
            let (cert, key) = &materials[index];
            let config = ClusterRaftConfig {
                enabled: true,
                bootstrap: true,
                node_id: index as u64 + 1,
                authority_cluster_id: cluster_id.clone(),
                authority_genesis_principals: vec![principal.clone()],
                listen_addr: listener.local_addr().unwrap().to_string(),
                cluster_name: "public-sdk-signed-capacity".into(),
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
        let (a, b, c) = tokio::join!(
            runtimes[0].ensure_configured_membership(true),
            runtimes[1].ensure_configured_membership(true),
            runtimes[2].ensure_configured_membership(true)
        );
        a.unwrap();
        b.unwrap();
        c.unwrap();
        let (a, b, c) = tokio::join!(
            runtimes[0].ensure_authority_initialized(),
            runtimes[1].ensure_authority_initialized(),
            runtimes[2].ensure_authority_initialized()
        );
        a.unwrap();
        b.unwrap();
        c.unwrap();
        for (kernel, runtime) in kernels.iter().zip(&runtimes) {
            kernel
                .install_cluster_authority(runtime.authority_handle())
                .unwrap();
        }
        for (kernel, runtime) in kernels.iter().zip(&runtimes) {
            assert!(matches!(
                runtime
                    .authority_handle()
                    .publish_kernel_capacity(kernel)
                    .await
                    .unwrap(),
                kernel::cluster_consensus::AuthorityResponse::NodeCapacityReported { .. }
            ));
        }
        let mut clients = Vec::new();
        for address in &addresses {
            let mut client = KernelClient::connect(*address).await.unwrap();
            client.authenticate(TOKEN).await.unwrap();
            let snapshot = client.cluster_capacity().await.unwrap();
            assert_eq!(snapshot.cluster_id, cluster_id);
            assert_eq!(
                snapshot.reports.len(),
                3,
                "a client connected to any member reads every quorum sample"
            );
            for capacity in &snapshot.reports {
                let member = snapshot
                    .members
                    .iter()
                    .find(|member| member.node_id == capacity.report.node_id)
                    .unwrap();
                capacity
                    .report
                    .verify_current(member, &snapshot.cluster_id, snapshot.authority_time)
                    .unwrap();
                assert_eq!(capacity.report.counters.agent_count, 0);
                assert_eq!(capacity.report.counters.active_turns, 0);
                assert!(capacity.report.counters.turn_capacity > 0);
            }
            let info = client.node_info().await.unwrap();
            assert!(
                info.observed_at.is_some()
                    && info.signature_hex.is_some()
                    && info.signed_capacity.is_some()
            );
            clients.push(client);
        }
        let own_key = operator.clone();
        let signer = AuthoritySigner::new(
            cluster_id.clone(),
            principal_id.clone(),
            1,
            move |payload| Ok(own_key.sign(payload).as_ref().to_vec()),
        );
        let mut placement =
            ClusterClient::connect_discovered_with_signer(addresses[0].to_string(), TOKEN, signer)
                .await
                .unwrap();
        assert!(placement.is_authority_managed());
        let fresh = placement
            .create_agent(
                "fresh signed placement",
                "capacity fixture",
                None,
                None,
                None,
                Placement::LeastLoaded,
            )
            .await
            .unwrap();
        assert!(kernels
            .iter()
            .any(|kernel| kernel.cluster_control.identity().node_id == fresh.node_id));
        let ownership = clients[1]
            .active_cluster_agent_ownership(&fresh.agent_id)
            .await
            .unwrap();
        assert_eq!(ownership.owner_node_id, fresh.node_id);
        let owner_index = kernels
            .iter()
            .position(|kernel| kernel.cluster_control.identity().node_id == fresh.node_id)
            .unwrap();
        let fence = clients[owner_index]
            .agent_mutation_fence(&fresh.agent_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(fence.fencing_token, ownership.fencing_token);
        assert_eq!(fence.authority_generation, ownership.generation);
        let audit = clients[2]
            .cluster_agent_ownership_audit(Some(fresh.agent_id.clone()), 10)
            .await
            .unwrap();
        assert_eq!(audit[0].actor, format!("principal:{principal_id}"));
        placement
            .renew_agent_ownership(&fresh.agent_id, 60)
            .await
            .unwrap();
        let owner = kernels
            .iter()
            .position(|kernel| kernel.cluster_control.identity().node_id == fresh.node_id)
            .unwrap();
        let renewed = clients[1]
            .active_cluster_agent_ownership(&fresh.agent_id)
            .await
            .unwrap();
        let paused_proof = agent_sdk::AgentMutationFenceProof {
            cluster_id: cluster_id.clone(),
            owner_node_id: renewed.owner_node_id.clone(),
            authority_term: renewed.authority_term,
            authority_generation: renewed.generation,
            fencing_token: renewed.fencing_token,
            proof_expires_at: renewed.lease_expires_at,
        };
        clients[owner]
            .pause_agent_fenced(&fresh.agent_id, paused_proof)
            .await
            .unwrap();
        // No reporters run here. A new any-member quorum barrier must advance time
        // independently; the client's clock is never consulted for eligibility.
        tokio::time::sleep(Duration::from_secs(16)).await;
        let snapshot = clients[2].cluster_capacity().await.unwrap();
        for capacity in &snapshot.reports {
            let member = snapshot
                .members
                .iter()
                .find(|member| member.node_id == capacity.report.node_id)
                .unwrap();
            assert_eq!(
                capacity.report.verify_current(
                    member,
                    &snapshot.cluster_id,
                    snapshot.authority_time
                ),
                Err(kernel::cluster_capacity::CapacityRejection::Stale)
            );
        }
        let error = placement
            .create_agent(
                "stale must fail",
                "capacity fixture",
                None,
                None,
                None,
                Placement::RoundRobin,
            )
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            SdkError::Wire {
                code: WireErrorCode::Unavailable,
                retryable: true,
                ..
            }
        ));
        // The actual bounded automatic publisher restores current samples.
        let publishers = kernels
            .iter()
            .zip(&runtimes)
            .map(|(kernel, runtime)| runtime.authority_handle().start_capacity_publisher(kernel))
            .collect::<Vec<_>>();
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        loop {
            let snapshot = clients[1].cluster_capacity().await.unwrap();
            if snapshot.reports.iter().all(|capacity| {
                snapshot
                    .members
                    .iter()
                    .find(|member| member.node_id == capacity.report.node_id)
                    .is_some_and(|member| {
                        capacity
                            .report
                            .verify_current(member, &snapshot.cluster_id, snapshot.authority_time)
                            .is_ok()
                    })
            }) {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "automatic publishers never restored current quorum samples"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let active = placement
            .create_agent(
                "automatic capacity",
                "capacity fixture",
                None,
                None,
                None,
                Placement::LeastLoaded,
            )
            .await
            .unwrap();
        assert!(kernels
            .iter()
            .any(|kernel| kernel.cluster_control.identity().node_id == active.node_id));
        for publisher in publishers {
            publisher.shutdown().await;
        }
        // A later exact sample includes actual lifecycle changes and every
        // production counter, rather than accepting only the zero-load shape.
        tokio::time::sleep(Duration::from_secs(5)).await;
        for (kernel, runtime) in kernels.iter().zip(&runtimes) {
            assert!(matches!(
                runtime
                    .authority_handle()
                    .publish_kernel_capacity(kernel)
                    .await
                    .unwrap(),
                kernel::cluster_consensus::AuthorityResponse::NodeCapacityReported { .. }
            ));
        }
        let loaded = clients[2].cluster_capacity().await.unwrap();
        for capacity in &loaded.reports {
            let kernel = kernels
                .iter()
                .find(|kernel| kernel.cluster_control.identity().node_id == capacity.report.node_id)
                .unwrap();
            let actual = kernel::metrics::MetricsSnapshot::collect(kernel);
            let c = &capacity.report.counters;
            assert_eq!(c.agent_count, actual.agent_count);
            assert_eq!(c.running_agents, actual.running_agents);
            assert_eq!(c.live_agents, actual.live_agents);
            assert_eq!(c.queued_agents, actual.queued_agents);
            assert_eq!(c.paused_agents, actual.paused_agents);
            assert_eq!(c.stopped_agents, actual.stopped_agents);
            assert_eq!(c.active_turns, actual.active_turns);
            assert_eq!(c.waiting_turns, actual.waiting_turns);
            assert_eq!(c.turn_capacity, actual.turn_capacity);
            assert_eq!(c.llm_requests_in_flight, actual.llm_requests_in_flight);
            assert_eq!(c.llm_requests_waiting, actual.llm_requests_waiting);
            assert_eq!(c.llm_core_capacity, actual.llm_core_capacity);
        }
        assert!(loaded
            .reports
            .iter()
            .any(|capacity| capacity.report.counters.paused_agents > 0));
        for agent in [&fresh, &active] {
            let owner = kernels
                .iter()
                .position(|kernel| kernel.cluster_control.identity().node_id == agent.node_id)
                .unwrap();
            let owned = clients[1]
                .active_cluster_agent_ownership(&agent.agent_id)
                .await
                .unwrap();
            let proof = agent_sdk::AgentMutationFenceProof {
                cluster_id: cluster_id.clone(),
                owner_node_id: owned.owner_node_id,
                authority_term: owned.authority_term,
                authority_generation: owned.generation,
                fencing_token: owned.fencing_token,
                proof_expires_at: owned.lease_expires_at,
            };
            clients[owner]
                .stop_agent_fenced(&agent.agent_id, proof)
                .await
                .unwrap();
        }
        for client in &mut clients {
            client.close().await.unwrap();
        }
        drop(clients);
        drop(placement);
        for runtime in runtimes {
            runtime.shutdown().await.unwrap();
        }
        let weak = kernels.iter().map(Arc::downgrade).collect::<Vec<_>>();
        for task in serving {
            task.abort();
            let _ = task.await;
        }
        drop(kernels);
        tokio::time::timeout(Duration::from_secs(5), async {
            while weak.iter().any(|kernel| kernel.upgrade().is_some()) {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("public handlers release native database owners");
        root.close().unwrap();
    })
    .await
    .expect("actual signed capacity and placement fixture is bounded");
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
