//! Challenged node admission through the public SDK and real syscall servers.

use std::sync::Arc;
use std::time::Duration;

use agent_sdk::{ClusterAdmissionOperationIds, ClusterClient, KernelClient, WireErrorCode};
use kernel::syscall_server::SyscallServer;
use kernel::AgentKernelImpl;

const TOKEN: &str = "cluster-admission-offline-ci";

struct Server {
    address: String,
    task: tokio::task::JoinHandle<Result<(), std::io::Error>>,
}

impl Server {
    async fn start() -> Self {
        let kernel = Arc::new(AgentKernelImpl::new().unwrap());
        let server = SyscallServer::bind(kernel, "127.0.0.1:0")
            .await
            .unwrap()
            .with_auth_token(TOKEN);
        let address = server.local_addr().unwrap().to_string();
        Self {
            address,
            task: tokio::spawn(server.serve()),
        }
    }

    async fn client(&self) -> KernelClient {
        let mut client = KernelClient::connect(&self.address).await.unwrap();
        client.authenticate(TOKEN).await.unwrap();
        client
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[tokio::test]
async fn challenged_admission_forms_three_distinct_members_through_public_clients() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let authority = Server::start().await;
        let peers = [Server::start().await, Server::start().await];
        let mut authority_client = authority.client().await;
        let mut identities = std::collections::BTreeSet::new();
        for server in [&authority, &peers[0], &peers[1]] {
            let mut node_client = server.client().await;
            let identity = node_client
                .node_info()
                .await
                .unwrap()
                .control
                .unwrap()
                .identity;
            let member = ClusterClient::admit_node_with_operation_ids(
                &mut authority_client,
                &mut node_client,
                &server.address,
                None,
                "three-node challenged admission fixture",
                ClusterAdmissionOperationIds::default(),
            )
            .await
            .unwrap();
            assert_eq!(member.node_id, identity.node_id);
            assert_eq!(member.fingerprint, identity.fingerprint);
            assert_eq!(member.public_key, identity.public_key);
            assert_eq!(member.endpoint, server.address);
            assert_eq!(member.state, agent_sdk::ClusterMemberState::Active);
            assert!(identities.insert(member.node_id));
            node_client.close().await.unwrap();
        }
        let membership = authority_client.cluster_membership().await.unwrap();
        assert_eq!(membership.members.len(), 3);
        assert_eq!(
            membership
                .members
                .iter()
                .map(|member| member.node_id.clone())
                .collect::<std::collections::BTreeSet<_>>(),
            identities
        );
        authority_client.close().await.unwrap();
    })
    .await
    .expect("bounded public cluster admission");
}

#[tokio::test]
async fn duplicate_challenge_and_mutation_ids_refuse_before_either_endpoint_receives_a_request() {
    use kernel::syscall_server::{Syscall, SyscallReply};
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
    let mut clients = Vec::new();
    let mut endpoints = Vec::new();
    for _ in 0..2 {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        endpoints.push(tokio::spawn(async move {
            tokio::time::timeout(Duration::from_secs(10), async move {
                let (socket, _) = listener.accept().await.unwrap();
                let (read, mut write) = socket.into_split();
                let mut read = BufReader::new(read);
                let mut greeting = String::new();
                read.read_line(&mut greeting).await.unwrap();
                assert!(matches!(
                    serde_json::from_str::<Syscall>(&greeting).unwrap(),
                    Syscall::Hello { .. }
                ));
                let mut response = serde_json::to_vec(&SyscallReply::Hello {
                    protocol_version: agent_sdk::PROTOCOL_VERSION,
                    min_protocol_version: 1,
                    server_version: "cluster-admission-fixture".into(),
                    features: Vec::new(),
                })
                .unwrap();
                response.push(b'\n');
                write.write_all(&response).await.unwrap();
                let mut after_greeting = Vec::new();
                read.read_to_end(&mut after_greeting).await.unwrap();
                write.shutdown().await.unwrap();
                after_greeting
            })
            .await
            .expect("bounded endpoint request capture")
        }));
        clients.push(KernelClient::connect(address).await.unwrap());
    }
    let id = uuid::Uuid::new_v4();
    let operation_ids = ClusterAdmissionOperationIds {
        challenge: id,
        mutation: id,
    };
    let mut node = clients.pop().unwrap();
    let mut authority = clients.pop().unwrap();
    let error = ClusterClient::admit_node_with_operation_ids(
        &mut authority,
        &mut node,
        "127.0.0.1:7443",
        None,
        "duplicate operation receipt rejection",
        operation_ids,
    )
    .await
    .unwrap_err();
    assert_eq!(error.wire_code(), Some(WireErrorCode::InvalidArgument));
    let error = ClusterClient::prepare_node_certificate_rollout_with_operation_ids(
        &mut authority,
        &mut node,
        "127.0.0.1:7443",
        "11".repeat(32),
        1,
        30,
        5,
        "duplicate certificate receipt rejection",
        operation_ids,
    )
    .await
    .unwrap_err();
    assert_eq!(error.wire_code(), Some(WireErrorCode::InvalidArgument));
    authority.close().await.unwrap();
    node.close().await.unwrap();
    for endpoint in endpoints {
        assert!(
            endpoint.await.unwrap().is_empty(),
            "a refused admission wrote a request after the opening handshake"
        );
    }
}
