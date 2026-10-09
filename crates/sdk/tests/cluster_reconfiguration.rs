//! Real public-wire proposals on a three-node mutual-TLS Raft authority.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use agent_sdk::{
    sign_authority_principal, AuthorityCommand, AuthorityCommandClass, AuthorityPrincipal,
    AuthorityPrincipalKind, KernelClient, SdkError, WireErrorCode,
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
async fn public_sdk_live_voter_proposal_replays_and_denies_token_only_authority() {
    tokio::time::timeout(Duration::from_secs(120), async {
        let root = tempfile::tempdir().unwrap();
        let operator_document =
            Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new()).unwrap();
        let operator = Ed25519KeyPair::from_pkcs8(operator_document.as_ref()).unwrap();
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
                cluster_name: "public-sdk-live-voter".into(),
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
        let mut client = KernelClient::connect(addresses[0]).await.unwrap();
        client.authenticate(TOKEN).await.unwrap();
        let status = client.cluster_reconfiguration_status().await.unwrap();
        assert!(status.settled);
        let operation_id = Uuid::new_v4().to_string();
        let inner = AuthorityCommand::ProposeClusterVoterChange {
            operation_id: operation_id.clone(),
            prior: status.current,
            target_voter_ids: BTreeSet::from([1, 2]),
            expected_generation: 0,
            target_generation: 1,
            actor: format!(
                "system-node:{}",
                kernels[0].cluster_control.identity().node_id
            ),
            reason: "actual public SDK live voter fixture".into(),
            proposed_at: chrono::Utc::now(),
        };
        assert!(matches!(
            client
                .propose_cluster_voter_change_with_operation_id(&operation_id, inner.clone())
                .await,
            Err(SdkError::Configuration(_))
        ));
        let sign = |command| {
            sign_authority_principal(
                command,
                &cluster_id,
                &principal_id,
                1,
                chrono::Utc::now(),
                |payload| Ok(operator.sign(payload).as_ref().to_vec()),
            )
            .unwrap()
        };
        let signed = sign(inner.clone());
        assert!(matches!(
            client
                .propose_cluster_voter_change_with_operation_id(
                    &Uuid::new_v4().to_string(),
                    signed.clone()
                )
                .await,
            Err(SdkError::Configuration(_))
        ));
        let plan = client
            .propose_cluster_voter_change_with_operation_id(&operation_id, signed)
            .await
            .unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(25);
        loop {
            let status = client.cluster_reconfiguration_status().await.unwrap();
            if status.settled && status.quorum_verified && status.current == plan.target {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "public status never reached the authorized target"
            );
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
        assert_eq!(
            client
                .propose_cluster_voter_change_with_operation_id(&operation_id, sign(inner.clone()))
                .await
                .unwrap(),
            plan
        );
        let unknown_document =
            Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new()).unwrap();
        let unknown = Ed25519KeyPair::from_pkcs8(unknown_document.as_ref()).unwrap();
        let forged = sign_authority_principal(
            inner,
            &cluster_id,
            &principal_id,
            1,
            chrono::Utc::now(),
            |payload| Ok(unknown.sign(payload).as_ref().to_vec()),
        )
        .unwrap();
        assert!(
            matches!(
                client
                    .propose_cluster_voter_change_with_operation_id(&operation_id, forged)
                    .await,
                Err(SdkError::Wire {
                    code: WireErrorCode::AuthorizationDenied,
                    ..
                })
            ),
            "an invalid current signature must not retrieve a cached plan"
        );
        let first = runtimes.remove(0);
        for runtime in runtimes {
            runtime.shutdown().await.unwrap();
        }
        let local = tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                let status = client.cluster_reconfiguration_status().await.unwrap();
                if !status.quorum_verified {
                    break status;
                }
                tokio::time::sleep(Duration::from_millis(30)).await;
            }
        })
        .await
        .expect("no-quorum local progress observation is bounded");
        assert_eq!(
            local.observation,
            agent_sdk::ClusterReconfigurationObservation::LocalApplied
        );
        assert_eq!(local.operation_id.as_deref(), Some(operation_id.as_str()));
        assert_eq!(local.current, plan.target);
        assert!(local.applied_frontier.is_some());
        client.close().await.unwrap();
        first.shutdown().await.unwrap();
        let weak = kernels.iter().map(Arc::downgrade).collect::<Vec<_>>();
        let stores = kernels.iter().map(|kernel| Arc::downgrade(&kernel.context_manager)).collect::<Vec<_>>();
        for task in serving {
            task.abort();
            let _ = task.await;
        }
        drop(kernels);
        tokio::time::timeout(Duration::from_secs(5), async {
            while weak.iter().any(|kernel| kernel.upgrade().is_some()) || stores.iter().any(|store| store.upgrade().is_some()) {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("public handlers and Raft storage tasks release all kernel and durable context references");
        root.close().unwrap();
    })
    .await
    .expect("actual SDK three-node fixture is bounded");
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
