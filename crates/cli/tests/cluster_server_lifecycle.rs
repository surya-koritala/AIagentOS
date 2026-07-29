#![cfg(unix)]

use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use kernel::cluster_runtime::ClusterRaftTls;
use kernel::config::{ClusterRaftConfig, ClusterRaftMemberConfig, Config};
use kernel::syscall_server::{Syscall, SyscallReply, PROTOCOL_VERSION};
use kernel::AgentKernelImpl;
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose,
};

struct TestRoot(PathBuf);

impl TestRoot {
    fn new() -> Self {
        let path =
            std::env::temp_dir().join(format!("agentos-server-raft-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&path).expect("create test root");
        Self(path)
    }
}

impl Drop for TestRoot {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn test_ca() -> CertifiedIssuer<'static, KeyPair> {
    let key = KeyPair::generate().expect("generate CA key");
    let mut params = CertificateParams::default();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
    ];
    CertifiedIssuer::self_signed(params, key).expect("self-sign CA")
}

fn write_private(path: &Path, contents: &str) {
    std::fs::write(path, contents).expect("write private key");
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .expect("set owner-only permissions");
}

fn write_cluster_config(
    root: &Path,
    listen_addr: std::net::SocketAddr,
    application_addr: std::net::SocketAddr,
) -> PathBuf {
    let ca = test_ca();
    let server_name = "node-1.agentos.test";
    let server_key = KeyPair::generate().expect("generate server key");
    let mut server_params =
        CertificateParams::new(vec![server_name.into()]).expect("server params");
    server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let server_certificate = server_params
        .signed_by(&server_key, &ca)
        .expect("sign server certificate");
    let client_key = KeyPair::generate().expect("generate client key");
    let mut client_params = CertificateParams::new(Vec::<String>::new()).expect("client params");
    client_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let client_certificate = client_params
        .signed_by(&client_key, &ca)
        .expect("sign client certificate");

    let server_certificate_path = root.join("server.pem");
    let server_private_key_path = root.join("server-key.pem");
    let client_certificate_path = root.join("client.pem");
    let client_private_key_path = root.join("client-key.pem");
    let peer_ca_path = root.join("ca.pem");
    std::fs::write(&server_certificate_path, server_certificate.pem())
        .expect("write server certificate");
    write_private(&server_private_key_path, &server_key.serialize_pem());
    std::fs::write(&client_certificate_path, client_certificate.pem())
        .expect("write client certificate");
    write_private(&client_private_key_path, &client_key.serialize_pem());
    std::fs::write(&peer_ca_path, ca.pem()).expect("write CA");
    let tls = ClusterRaftTls::from_pem(
        server_certificate.pem().as_bytes(),
        server_key.serialize_pem().as_bytes(),
        client_certificate.pem().as_bytes(),
        client_key.serialize_pem().as_bytes(),
        ca.pem().as_bytes(),
    )
    .expect("build test TLS");
    let data_dir = root.join("data");
    let identity = {
        let kernel = AgentKernelImpl::with_db_path(&data_dir.join("agent_os.db"))
            .expect("initialize durable application identity");
        kernel.cluster_control.identity().clone()
    };

    let config = Config {
        data_dir,
        cluster_raft: ClusterRaftConfig {
            enabled: true,
            bootstrap: true,
            node_id: 1,
            authority_cluster_id: "00000000-0000-0000-0000-000000000100".into(),
            listen_addr: listen_addr.to_string(),
            cluster_name: "agent-server-lifecycle-test".into(),
            members: vec![ClusterRaftMemberConfig {
                node_id: 1,
                application_node_id: identity.node_id,
                application_endpoint: application_addr.to_string(),
                application_tls_server_certificate_sha256: None,
                endpoint: listen_addr.to_string(),
                server_name: server_name.into(),
                tls_certificate_sha256: tls.server_certificate_sha256().into(),
                tls_client_certificate_sha256: tls.client_certificate_sha256().into(),
                identity_public_key: identity.public_key,
            }],
            server_certificate_path: Some(server_certificate_path),
            server_private_key_path: Some(server_private_key_path),
            client_certificate_path: Some(client_certificate_path),
            client_private_key_path: Some(client_private_key_path),
            peer_ca_path: Some(peer_ca_path),
            heartbeat_interval_ms: 50,
            election_timeout_min_ms: 200,
            election_timeout_max_ms: 400,
            ..Default::default()
        },
        ..Default::default()
    };
    let path = root.join("config.toml");
    config.save_to(&path).expect("save test config");
    path
}

#[test]
fn agent_server_owns_configured_raft_startup_and_sigterm_shutdown() {
    let root = TestRoot::new();
    let reserved = TcpListener::bind("127.0.0.1:0").expect("reserve Raft port");
    let raft_addr = reserved.local_addr().expect("Raft address");
    drop(reserved);
    let application_reserved = TcpListener::bind("127.0.0.1:0").expect("reserve application port");
    let application_addr = application_reserved
        .local_addr()
        .expect("application address");
    drop(application_reserved);
    let config_path = write_cluster_config(&root.0, raft_addr, application_addr);

    let mut child = Command::new(env!("CARGO_BIN_EXE_agent-server"))
        .arg(application_addr.to_string())
        .env("AGENT_SERVER_CONFIG", &config_path)
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn agent-server");
    let stderr = child.stderr.take().expect("server stderr");
    let (lines_tx, lines_rx) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stderr).lines().map_while(Result::ok) {
            let _ = lines_tx.send(line);
        }
    });

    let deadline = Instant::now() + Duration::from_secs(10);
    let mut output = Vec::new();
    let listening = loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break false;
        }
        match lines_rx.recv_timeout(remaining.min(Duration::from_millis(250))) {
            Ok(line) => {
                let ready = line.contains("agent-server listening on tcp:");
                output.push(line);
                if ready {
                    break true;
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                if let Some(status) = child.try_wait().expect("poll child") {
                    output.push(format!("agent-server exited early with {status}"));
                    break false;
                }
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => break false,
        }
    };
    if !listening {
        let _ = child.kill();
        let _ = child.wait();
        panic!("agent-server did not become ready:\n{}", output.join("\n"));
    }

    let mut stream =
        std::net::TcpStream::connect(application_addr).expect("connect application listener");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("set read timeout");
    let mut reader = BufReader::new(stream.try_clone().expect("clone application socket"));
    let mut call = |request: &Syscall| {
        serde_json::to_writer(&mut stream, request).expect("write syscall request");
        stream.write_all(b"\n").expect("terminate syscall request");
        stream.flush().expect("flush syscall request");
        let mut line = String::new();
        reader.read_line(&mut line).expect("read syscall reply");
        serde_json::from_str::<SyscallReply>(&line).expect("decode syscall reply")
    };
    assert!(matches!(
        call(&Syscall::Hello {
            protocol_version: PROTOCOL_VERSION,
        }),
        SyscallReply::Hello { .. }
    ));
    let membership = match call(&Syscall::GetClusterMembership) {
        SyscallReply::ClusterMembership { membership } => membership,
        other => panic!("unexpected membership reply: {other:?}"),
    };
    assert_eq!(
        membership.cluster_id,
        "00000000-0000-0000-0000-000000000100"
    );
    assert_eq!(membership.members.len(), 1);
    let operation_id = uuid::Uuid::new_v4().to_string();
    let agent_id = uuid::Uuid::new_v4().to_string();
    let claim = Syscall::ClaimClusterAgentOwnership {
        operation_id: Some(operation_id),
        agent_id: agent_id.clone(),
        owner_node_id: membership.members[0].node_id.clone(),
        ttl_seconds: 60,
        expected_fencing_token: None,
        reason: "daemon quorum lifecycle test".into(),
    };
    let first_claim = call(&claim);
    let replayed_claim = call(&claim);
    assert_eq!(
        serde_json::to_value(&first_claim).unwrap(),
        serde_json::to_value(&replayed_claim).unwrap(),
        "same operation id must replay the exact committed ownership result"
    );
    assert!(matches!(
        first_claim,
        SyscallReply::ClusterAgentOwnership {
            ownership: Some(ref ownership)
        } if ownership.agent_id == agent_id && ownership.fencing_token == 1
    ));

    let signal_result = unsafe { libc::kill(child.id() as i32, libc::SIGTERM) };
    assert_eq!(signal_result, 0, "send SIGTERM");
    let shutdown_deadline = Instant::now() + Duration::from_secs(10);
    let status = loop {
        if let Some(status) = child.try_wait().expect("poll shutdown") {
            break status;
        }
        if Instant::now() >= shutdown_deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!(
                "agent-server did not shut down after SIGTERM:\n{}",
                output.join("\n")
            );
        }
        std::thread::sleep(Duration::from_millis(25));
    };
    assert!(
        status.success(),
        "agent-server shutdown failed with {status}:\n{}",
        output.join("\n")
    );
}
