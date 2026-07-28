use std::collections::HashSet;
use std::sync::Arc;

use agent_sdk::{
    ConnectionProfile, PackageArchive, PackageFile, PackageFileKind, PackageManifest,
    PackagePayload, PackageSbom, PackageSigningKey, SbomComponent, SdkError,
};
use kernel::agent_package::AgentManifest;
use kernel::auth::Role;
use kernel::syscall_server::SyscallServer;
use kernel::AgentKernelImpl;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

fn package(name: &str, publisher: &str) -> PackagePayload {
    PackagePayload {
        schema_version: 1,
        package: PackageManifest {
            name: name.into(),
            version: "1.0.0".parse().unwrap(),
            description: "Reconnect duplicate-prevention fixture".into(),
            publisher: publisher.into(),
            license: Some("AGPL-3.0-only".into()),
            dependencies: Vec::new(),
            capabilities_required: vec!["CAP_FILE_READ".into()],
            tools_required: Vec::new(),
        },
        agent: AgentManifest {
            name: name.into(),
            description: "Reconnect duplicate-prevention fixture".into(),
            task: "remain deterministic".into(),
            entry: Some("start".into()),
            provider: "stub".into(),
            profile: "read-only".into(),
            priority: 3,
            nice: None,
            tools: Vec::new(),
            memory: Vec::new(),
        },
        files: vec![PackageFile {
            path: "prompts/entry.txt".into(),
            kind: PackageFileKind::Prompt,
            bytes: b"start".to_vec(),
            checksum_sha256: String::new(),
        }],
        sbom: PackageSbom {
            format: "SPDX-2.3".into(),
            components: vec![SbomComponent {
                name: "agentos-kernel-api".into(),
                version: "1".into(),
                license: Some("AGPL-3.0-only".into()),
                checksum_sha256: None,
            }],
        },
    }
}

async fn proxy_connection(
    client: TcpStream,
    backend: std::net::SocketAddr,
    faults: Arc<Mutex<HashSet<String>>>,
) -> std::io::Result<()> {
    let backend = TcpStream::connect(backend).await?;
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
        let operation = serde_json::from_str::<serde_json::Value>(&request)
            .ok()
            .and_then(|value| value["op"].as_str().map(ToOwned::to_owned));
        if let Some(operation) = operation {
            if faults.lock().await.remove(&operation) {
                // The backend completed the operation and produced a reply, but
                // the client never receives it. This is the ambiguous window
                // where automatically replaying a mutation would duplicate it.
                return Ok(());
            }
        }
        client_write.write_all(reply.as_bytes()).await?;
        client_write.flush().await?;
    }
}

async fn spawn_fault_proxy(
    backend: std::net::SocketAddr,
    operations: &[&str],
) -> (
    std::net::SocketAddr,
    Arc<Mutex<HashSet<String>>>,
    tokio::task::JoinHandle<()>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let faults = Arc::new(Mutex::new(
        operations.iter().map(|value| value.to_string()).collect(),
    ));
    let task_faults = Arc::clone(&faults);
    let task = tokio::spawn(async move {
        while let Ok((client, _)) = listener.accept().await {
            let faults = Arc::clone(&task_faults);
            tokio::spawn(async move {
                let _ = proxy_connection(client, backend, faults).await;
            });
        }
    });
    (address, faults, task)
}

fn assert_indeterminate(error: SdkError, operation: &str) {
    match error {
        SdkError::IndeterminateMutation {
            operation: actual, ..
        } => assert_eq!(actual, operation),
        other => panic!("expected indeterminate {operation}, got {other:?}"),
    }
}

#[tokio::test]
async fn reconnect_replays_reads_but_never_package_lifecycle_or_tool_mutations() {
    let kernel = Arc::new(AgentKernelImpl::new().expect("kernel"));
    let tenant = kernel.create_tenant("reconnect-tenant").await.unwrap();
    let admin = kernel
        .register_user(
            &tenant,
            "reconnect-admin",
            "reconnect@example.invalid",
            Role::Admin,
        )
        .await
        .unwrap();
    let api_key = kernel
        .issue_api_key(&admin, "reconnect-test")
        .await
        .unwrap();

    let server = SyscallServer::bind(Arc::clone(&kernel), "127.0.0.1:0")
        .await
        .unwrap();
    let backend = server.local_addr().unwrap();
    let server_task = tokio::spawn(server.serve());
    let (proxy, pending_faults, proxy_task) = spawn_fault_proxy(
        backend,
        &["install_package", "list_agents", "pause_agent", "call_tool"],
    )
    .await;

    let profile = ConnectionProfile::plaintext(proxy.to_string());
    let mut client = profile.connect(Some(&api_key)).await.unwrap();
    let sender = client
        .create_agent(
            "sender",
            "send exactly once",
            Some("stub".into()),
            None,
            None,
        )
        .await
        .unwrap();
    let receiver = client
        .create_agent(
            "receiver",
            "receive exactly once",
            Some("stub".into()),
            None,
            None,
        )
        .await
        .unwrap();

    let (signer, _) = PackageSigningKey::generate(&admin, "reconnect-release").unwrap();
    client
        .trust_package_key(
            &admin,
            signer.key_id(),
            &signer.public_key(),
            "2020-01-01T00:00:00Z",
            None,
            None,
        )
        .await
        .unwrap();
    let archive = PackageArchive::sign(package("reconnect-package", &admin), &signer).unwrap();
    client.publish_package(&archive).await.unwrap();

    let install_error = client
        .install_package("reconnect-package", "=1.0.0")
        .await
        .expect_err("lost install reply must be indeterminate");
    assert_indeterminate(install_error, "package installation");

    // The pending reconnect happens before this read. Its first reply is also
    // dropped, so the SDK reconnects and replays the explicitly safe read once.
    let agents = client.list_agents().await.expect("read-only replay");
    assert_eq!(agents.len(), 2);
    assert_eq!(client.reconnect_generation(), 2);
    assert_eq!(client.list_installed_packages().await.unwrap().len(), 1);
    assert!(
        client.rollback_package("reconnect-package").await.is_err(),
        "one install has no previous non-null snapshot; replay would create one"
    );

    let pause_error = client
        .pause_agent(&sender)
        .await
        .expect_err("lost pause reply must be indeterminate");
    assert_indeterminate(pause_error, "agent pause");
    assert_eq!(client.agent_status(&sender).await.unwrap(), "Paused");
    let lifecycle = kernel::metrics::MetricsSnapshot::collect(&kernel);
    assert_eq!(
        lifecycle.lifecycle.pause.requested, 1,
        "the lifecycle mutation must not be replayed"
    );

    let tool_error = client
        .call_tool(
            &sender,
            "send_agent_message",
            serde_json::json!({"to": receiver, "message": {"once": true}}),
        )
        .await
        .expect_err("lost tool reply must be indeterminate");
    assert_indeterminate(tool_error, "tool call");
    let first = client
        .call_tool(&receiver, "check_inbox", serde_json::json!({}))
        .await
        .unwrap();
    assert_eq!(first["from"], sender);
    assert_eq!(first["payload"]["once"], true);
    let second = client
        .call_tool(&receiver, "check_inbox", serde_json::json!({}))
        .await
        .unwrap();
    assert_eq!(
        second["empty"], true,
        "automatic replay would have delivered a duplicate message"
    );

    assert!(
        pending_faults.lock().await.is_empty(),
        "every response-loss fault must have executed"
    );
    proxy_task.abort();
    server_task.abort();
}
