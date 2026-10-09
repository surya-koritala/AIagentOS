//! Actual shipped CLI formation, secure endpoint selection and receipt replay.

use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use kernel::auth::Role;
use kernel::syscall_server::{Syscall, SyscallReply, SyscallServer};
use kernel::AgentKernelImpl;
use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair, KeyUsagePurpose};
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::process::Command;
use uuid::Uuid;

const TOKEN: &str = "offline-cluster-operator-fixture";

struct Server {
    address: String,
    hostname: String,
    kernel: Arc<AgentKernelImpl>,
    task: tokio::task::JoinHandle<Result<(), std::io::Error>>,
    reload: Option<kernel::syscall_server::TlsReloadHandle>,
    fingerprint: Option<String>,
}

fn ca() -> CertifiedIssuer<'static, KeyPair> {
    let mut params = CertificateParams::default();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
    ];
    CertifiedIssuer::self_signed(params, KeyPair::generate().unwrap()).unwrap()
}

fn certificate_config(
    ca: &CertifiedIssuer<'static, KeyPair>,
    hostname: &str,
) -> (rustls::ServerConfig, String) {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let key = KeyPair::generate().unwrap();
    let certificate = CertificateParams::new(vec![hostname.into()])
        .unwrap()
        .signed_by(&key, ca)
        .unwrap();
    let fingerprint = ring::digest::digest(&ring::digest::SHA256, certificate.der().as_ref()).as_ref().iter().map(|byte| format!("{byte:02x}")).collect();
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![certificate.der().clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
        )
        .unwrap();
    (config, fingerprint)
}

fn tls_config(ca: &CertifiedIssuer<'static, KeyPair>, hostname: &str) -> rustls::ServerConfig {
    certificate_config(ca, hostname).0
}

impl Server {
    async fn start(
        path: &std::path::Path,
        hostname: &str,
        ca: &CertifiedIssuer<'static, KeyPair>,
    ) -> Self {
        let kernel = Arc::new(AgentKernelImpl::with_db_path(path).unwrap());
        let (config, fingerprint) = certificate_config(ca, hostname);
        let server = SyscallServer::bind_tls(kernel.clone(), "127.0.0.1:0", config)
            .await
            .unwrap()
            .with_auth_token(TOKEN);
        let address = server.local_addr().unwrap().to_string();
        let reload = server.tls_reload_handle();
        Self {
            address,
            hostname: hostname.into(),
            kernel,
            task: tokio::spawn(server.serve()),
            reload,
            fingerprint: Some(fingerprint),
        }
    }

    async fn close(self) {
        let weak = Arc::downgrade(&self.kernel);
        self.task.abort();
        let stopped = tokio::time::timeout(Duration::from_secs(5), self.task)
            .await
            .unwrap();
        assert!(
            stopped.err().is_some_and(|error| error.is_cancelled()),
            "fixture listener must remain live until stopped"
        );
        drop(self.kernel);
        tokio::time::timeout(Duration::from_secs(5), async {
            while weak.upgrade().is_some() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("all listener handlers must release their kernel refs");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn lost_real_mutation_reply_is_replayed_after_server_restart_without_a_second_audit_row() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("ambiguous.db");
    let kernel = Arc::new(AgentKernelImpl::with_db_path(&path).unwrap());
    let server = SyscallServer::bind(kernel.clone(), "127.0.0.1:0")
        .await
        .unwrap()
        .with_auth_token(TOKEN);
    let backend = server.local_addr().unwrap().to_string();
    let task = tokio::spawn(server.serve());
    let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = proxy.local_addr().unwrap().to_string();
    let target = backend.clone();
    let proxy_task = tokio::spawn(async move {
        tokio::time::timeout(Duration::from_secs(15), async {
            let (front, _) = proxy.accept().await.unwrap();
            let back = TcpStream::connect(target).await.unwrap();
            let (front_read, mut front_write) = front.into_split();
            let (back_read, mut back_write) = back.into_split();
            let mut front_read = BufReader::new(front_read);
            let mut back_read = BufReader::new(back_read);
            loop {
                let mut request = String::new();
                assert!(front_read.read_line(&mut request).await.unwrap() > 0);
                let mutation = matches!(
                    serde_json::from_str::<Syscall>(&request).unwrap(),
                    Syscall::SetNodeAvailability { .. }
                );
                back_write.write_all(request.as_bytes()).await.unwrap();
                let mut response = String::new();
                assert!(back_read.read_line(&mut response).await.unwrap() > 0);
                if mutation {
                    assert!(matches!(
                        serde_json::from_str::<SyscallReply>(&response).unwrap(),
                        SyscallReply::NodeControlUpdated { .. }
                    ));
                    front_write.shutdown().await.unwrap();
                    break;
                }
                front_write.write_all(response.as_bytes()).await.unwrap();
            }
        })
        .await
        .expect("bounded response-loss proxy");
    });
    let id = Uuid::new_v4().to_string();
    let write = args(&[
        "cluster",
        "node-availability",
        "draining",
        "lost committed reply",
        "--generation",
        "0",
        "--operation-id",
        &id,
    ]);
    let lost = binary(&address, TOKEN, None, None, &write).await;
    assert!(!lost.success);
    assert!(lost.stdout.is_empty());
    assert!(String::from_utf8_lossy(&lost.stderr).contains(&id));
    proxy_task.await.unwrap();
    let audit = binary(
        &backend,
        TOKEN,
        None,
        None,
        &args(&["node-control-audit", "10"]),
    )
    .await;
    assert!(audit.success);
    assert_eq!(
        serde_json::from_slice::<Value>(&audit.stdout)
            .unwrap()
            .as_array()
            .unwrap()
            .len(),
        1
    );
    let original = Server {
        address: backend,
        hostname: String::new(),
        kernel,
        task,
        reload: None,
        fingerprint: None,
    };
    original.close().await;
    let kernel = Arc::new(AgentKernelImpl::with_db_path(&path).unwrap());
    let server = SyscallServer::bind(kernel.clone(), "127.0.0.1:0")
        .await
        .unwrap()
        .with_auth_token(TOKEN);
    let address = server.local_addr().unwrap().to_string();
    let task = tokio::spawn(server.serve());
    let replayed = binary(&address, TOKEN, None, None, &write).await;
    assert!(
        replayed.success,
        "{}",
        String::from_utf8_lossy(&replayed.stderr)
    );
    let record: Value = serde_json::from_slice(&replayed.stdout).unwrap();
    assert_eq!(record["operation_id"], id);
    assert_eq!(record["record"]["generation"], 1);
    let audit = binary(
        &address,
        TOKEN,
        None,
        None,
        &args(&["node-control-audit", "10"]),
    )
    .await;
    assert!(audit.success);
    assert_eq!(
        serde_json::from_slice::<Value>(&audit.stdout)
            .unwrap()
            .as_array()
            .unwrap()
            .len(),
        1
    );
    Server {
        address,
        hostname: String::new(),
        kernel,
        task,
        reload: None,
        fingerprint: None,
    }
    .close()
    .await;
    root.close().unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn actual_cli_distinguishes_identity_change_and_never_registers_the_changed_node() {
    let root = tempfile::tempdir().unwrap();
    let issuer = ca();
    let ca_path = root.path().join("ca.pem");
    std::fs::write(&ca_path, issuer.pem()).unwrap();
    let authority = Server::start(
        &root.path().join("authority.db"),
        "authority.agentos.test",
        &issuer,
    )
    .await;
    let old = Arc::new(AgentKernelImpl::with_db_path(&root.path().join("old.db")).unwrap());
    let changed = Arc::new(AgentKernelImpl::with_db_path(&root.path().join("changed.db")).unwrap());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let node_addr = listener.local_addr().unwrap().to_string();
    let config = tls_config(&issuer, "changing.agentos.test");
    let node_task = tokio::spawn(async move {
        tokio::time::timeout(Duration::from_secs(15), async {
            let (socket, _) = listener.accept().await.unwrap();
            let socket = tokio_rustls::TlsAcceptor::from(Arc::new(config))
                .accept(socket)
                .await
                .unwrap();
            let (read, mut write) = tokio::io::split(socket);
            let mut read = BufReader::new(read);
            let mut authenticated = false;
            loop {
                let mut frame = String::new();
                if read.read_line(&mut frame).await.unwrap() == 0 {
                    break;
                }
                let call: Syscall = serde_json::from_str(&frame).unwrap();
                let reply = match call {
                    Syscall::Authenticate { token } => {
                        assert_eq!(token, TOKEN);
                        authenticated = true;
                        SyscallReply::Authenticated
                    }
                    Syscall::Hello { .. } => kernel::syscall_server::dispatch(&old, call).await,
                    Syscall::NodeInfo => {
                        assert!(authenticated);
                        kernel::syscall_server::dispatch(&old, call).await
                    }
                    Syscall::ProveNodeIdentity { .. } => {
                        assert!(authenticated);
                        kernel::syscall_server::dispatch(&changed, call).await
                    }
                    _ => panic!("unexpected node mutation during identity-change fixture"),
                };
                let mut reply = serde_json::to_vec(&reply).unwrap();
                reply.push(b'\n');
                write.write_all(&reply).await.unwrap();
            }
            write.shutdown().await.unwrap();
        })
        .await
        .expect("bounded identity-change endpoint");
    });
    let denied = binary(
        &authority.address,
        TOKEN,
        Some(&ca_path),
        Some(&authority.hostname),
        &args(&[
            "cluster",
            "join",
            "--authority",
            &authority.address,
            "--node",
            &node_addr,
            "--node-server-name",
            "changing.agentos.test",
            "--reason",
            "identity changes must fail closed",
        ]),
    )
    .await;
    assert!(!denied.success);
    assert!(denied.stdout.is_empty());
    assert!(String::from_utf8_lossy(&denied.stderr)
        .contains("node identity changed while completing cluster admission"));
    node_task.await.unwrap();
    let membership = run(&authority, &ca_path, &args(&["cluster", "members"])).await;
    assert!(membership["members"].as_array().unwrap().is_empty());
    authority.close().await;
    root.close().unwrap();
}

struct Output {
    success: bool,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

async fn binary(
    address: &str,
    token: &str,
    ca: Option<&std::path::Path>,
    name: Option<&str>,
    args: &[String],
) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_agentctl"));
    command
        .args(["--addr", address, "--token", token])
        .args(args)
        .env_remove("AGENT_SERVER_TOKEN")
        .env_remove("AGENTOS_ADDR")
        .env_remove("AGENTOS_TLS_CA")
        .env_remove("AGENTOS_TLS_SERVER_NAME")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true);
    if let Some(ca) = ca {
        command.env("AGENTOS_TLS_CA", ca);
    }
    if let Some(name) = name {
        command.env("AGENTOS_TLS_SERVER_NAME", name);
    }
    let mut child = command.spawn().unwrap();
    let stdout = child.stdout.take().unwrap();
    let stderr = child.stderr.take().unwrap();
    let result = tokio::time::timeout(Duration::from_secs(20), async {
        let mut stdout = stdout.take(1024 * 1024 + 1);
        let mut stderr = stderr.take(1024 * 1024 + 1);
        let mut out = Vec::new();
        let mut err = Vec::new();
        let (status, captured_out, captured_err) = tokio::join!(
            child.wait(),
            stdout.read_to_end(&mut out),
            stderr.read_to_end(&mut err)
        );
        captured_out.unwrap();
        captured_err.unwrap();
        let status = status.unwrap();
        assert!(
            out.len() <= 1024 * 1024 && err.len() <= 1024 * 1024,
            "bounded CLI output"
        );
        Output {
            success: status.success(),
            stdout: out,
            stderr: err,
        }
    })
    .await;
    match result {
        Ok(output) => output,
        Err(_) => {
            child.start_kill().unwrap();
            tokio::time::timeout(Duration::from_secs(5), child.wait())
                .await
                .expect("bounded killed process reclamation")
                .unwrap();
            panic!("agentctl exceeded its bounded fixture deadline");
        }
    }
}

fn args(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| value.to_string()).collect()
}

async fn replicated_authority(
    root: &std::path::Path,
    server: &Server,
    issuer: &CertifiedIssuer<'static, KeyPair>,
) -> kernel::cluster_runtime::ClusterRaftRuntime {
    use kernel::cluster_runtime::{start_configured_cluster_runtime, ClusterRaftTls};
    use kernel::config::{ClusterRaftConfig, ClusterRaftMemberConfig};
    use rcgen::ExtendedKeyUsagePurpose;
    let reserved = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = reserved.local_addr().unwrap();
    drop(reserved);
    let hostname = "raft-authority.agentos.test";
    let server_key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(vec![hostname.into()]).unwrap();
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let certificate = params.signed_by(&server_key, issuer).unwrap();
    let client_key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::default();
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let client = params.signed_by(&client_key, issuer).unwrap();
    let tls = ClusterRaftTls::from_pem(
        certificate.pem().as_bytes(),
        server_key.serialize_pem().as_bytes(),
        client.pem().as_bytes(),
        client_key.serialize_pem().as_bytes(),
        issuer.pem().as_bytes(),
    )
    .unwrap();
    let server_cert = root.join("raft-server.pem");
    let server_private = root.join("raft-server-key.pem");
    let client_cert = root.join("raft-client.pem");
    let client_private = root.join("raft-client-key.pem");
    let peer_ca = root.join("raft-ca.pem");
    for (path, material) in [
        (&server_cert, certificate.pem()),
        (&server_private, server_key.serialize_pem()),
        (&client_cert, client.pem()),
        (&client_private, client_key.serialize_pem()),
        (&peer_ca, issuer.pem()),
    ] {
        kernel::config::write_owner_only_atomic(path, material.as_bytes()).unwrap();
    }
    let identity = server.kernel.cluster_control.identity();
    let config = ClusterRaftConfig {
        enabled: true,
        bootstrap: true,
        node_id: 1,
        authority_cluster_id: Uuid::new_v4().to_string(),
        listen_addr: address.to_string(),
        cluster_name: "offline-cli-certificate-proof".into(),
        members: vec![ClusterRaftMemberConfig {
            node_id: 1,
            application_node_id: identity.node_id.clone(),
            application_endpoint: server.address.clone(),
            application_tls_server_certificate_sha256: server.fingerprint.clone(),
            endpoint: address.to_string(),
            server_name: hostname.into(),
            tls_certificate_sha256: tls.server_certificate_sha256().into(),
            tls_certificate_sha256_overlap: Vec::new(),
            tls_client_certificate_sha256: tls.client_certificate_sha256().into(),
            tls_client_certificate_sha256_overlap: Vec::new(),
            identity_public_key: identity.public_key.clone(),
        }],
        server_certificate_path: Some(server_cert),
        server_private_key_path: Some(server_private),
        client_certificate_path: Some(client_cert),
        client_private_key_path: Some(client_private),
        peer_ca_path: Some(peer_ca),
        heartbeat_interval_ms: 50,
        election_timeout_min_ms: 200,
        election_timeout_max_ms: 400,
        ..Default::default()
    };
    let runtime = tokio::time::timeout(
        Duration::from_secs(15),
        start_configured_cluster_runtime(server.kernel.context_manager.clone(), &config),
    )
    .await
    .unwrap()
    .unwrap()
    .unwrap();
    server
        .kernel
        .install_cluster_authority(runtime.authority_handle())
        .unwrap();
    runtime
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn actual_cli_drives_certificate_prepare_abort_activate_and_finalize_on_live_replicated_authority(
) {
    let root = tempfile::tempdir().unwrap();
    let issuer = ca();
    let ca_path = root.path().join("ca.pem");
    std::fs::write(&ca_path, issuer.pem()).unwrap();
    let authority = Server::start(
        &root.path().join("authority.db"),
        "authority.agentos.test",
        &issuer,
    )
    .await;
    let node = Server::start(
        &root.path().join("workload.db"),
        "workload.agentos.test",
        &issuer,
    )
    .await;
    let runtime = replicated_authority(root.path(), &authority, &issuer).await;
    let admitted = run(
        &authority,
        &ca_path,
        &args(&[
            "cluster",
            "join",
            "--authority",
            &authority.address,
            "--node",
            &node.address,
            "--node-server-name",
            &node.hostname,
            "--reason",
            "certificate fixture membership",
        ]),
    )
    .await;
    let node_id = admitted["record"]["member"]["node_id"].as_str().unwrap();
    let generation = admitted["record"]["member"]["generation"]
        .as_u64()
        .unwrap()
        .to_string();
    let (_, candidate_fingerprint) = certificate_config(&issuer, &node.hostname);
    let first_id = Uuid::new_v4().to_string();
    let prepare = args(&[
        "cluster",
        "cert-prepare",
        "--authority",
        &authority.address,
        "--node",
        &node.address,
        "--node-server-name",
        &node.hostname,
        "--candidate-fingerprint",
        &candidate_fingerprint,
        "--generation",
        &generation,
        "--prepare-ttl",
        "30",
        "--minimum-overlap",
        "5",
        "--reason",
        "staged candidate proof",
        "--operation-id",
        &first_id,
    ]);
    let prepared = run(&authority, &ca_path, &prepare).await;
    assert_eq!(prepared["record"]["rollout"]["phase"], "prepared");
    assert_eq!(run(&authority, &ca_path, &prepare).await, prepared);
    let generation = prepared["record"]["member"]["generation"]
        .as_u64()
        .unwrap()
        .to_string();
    let abort_id = Uuid::new_v4().to_string();
    let abort = args(&[
        "cluster",
        "cert-abort",
        node_id,
        "--generation",
        &generation,
        "--reason",
        "candidate abort proof",
        "--operation-id",
        &abort_id,
    ]);
    let aborted = run(&authority, &ca_path, &abort).await;
    assert_eq!(aborted["record"].as_object().unwrap().len(), 1);
    let after_abort = run(&authority, &ca_path, &args(&["cluster", "members"])).await;
    assert!(after_abort.get("certificate_rollouts").is_none_or(|rollouts| rollouts.as_array().unwrap().is_empty()));
    assert_eq!(run(&authority, &ca_path, &abort).await, aborted);
    let previous_candidate = candidate_fingerprint;
    let (candidate_config, candidate_fingerprint) = certificate_config(&issuer, &node.hostname);
    assert_ne!(
        candidate_fingerprint, previous_candidate,
        "an aborted leaf remains in the immutable rollout history"
    );
    let generation = aborted["record"]["member"]["generation"]
        .as_u64()
        .unwrap()
        .to_string();
    let second_id = Uuid::new_v4().to_string();
    let prepare = args(&[
        "cluster",
        "cert-prepare",
        "--authority",
        &authority.address,
        "--node",
        &node.address,
        "--node-server-name",
        &node.hostname,
        "--candidate-fingerprint",
        &candidate_fingerprint,
        "--generation",
        &generation,
        "--prepare-ttl",
        "30",
        "--minimum-overlap",
        "5",
        "--reason",
        "fresh candidate proof",
        "--operation-id",
        &second_id,
    ]);
    let prepared = run(&authority, &ca_path, &prepare).await;
    node.reload
        .as_ref()
        .unwrap()
        .reload(candidate_config)
        .unwrap();
    let generation = prepared["record"]["member"]["generation"]
        .as_u64()
        .unwrap()
        .to_string();
    let activate_id = Uuid::new_v4().to_string();
    let activate = args(&[
        "cluster",
        "cert-activate",
        "--authority",
        &authority.address,
        "--node",
        &node.address,
        "--node-server-name",
        &node.hostname,
        "--generation",
        &generation,
        "--reason",
        "verified candidate activation",
        "--operation-id",
        &activate_id,
    ]);
    let activated = run(&authority, &ca_path, &activate).await;
    assert_eq!(
        activated["record"]["member"]["tls_server_certificate_fingerprint"],
        candidate_fingerprint
    );
    assert_eq!(run(&authority, &ca_path, &activate).await, activated);
    let membership = run(&authority, &ca_path, &args(&["cluster", "members"])).await;
    let rollout = membership["certificate_rollouts"]
        .as_array()
        .unwrap()
        .iter()
        .find(|rollout| rollout["node_id"] == node_id)
        .unwrap();
    assert_eq!(rollout["phase"], "activated");
    let deadline =
        chrono::DateTime::parse_from_rfc3339(rollout["retire_previous_after"].as_str().unwrap())
            .unwrap()
            .with_timezone(&Utc);
    let remaining =
        (deadline - Utc::now()).to_std().unwrap_or_default() + Duration::from_millis(500);
    assert!(
        remaining <= Duration::from_secs(8),
        "real minimum overlap remains bounded"
    );
    tokio::time::sleep(remaining).await;
    let generation = activated["record"]["member"]["generation"]
        .as_u64()
        .unwrap()
        .to_string();
    let finalize_id = Uuid::new_v4().to_string();
    let finalize = args(&[
        "cluster",
        "cert-finalize",
        node_id,
        "--generation",
        &generation,
        "--reason",
        "expired overlap finalized",
        "--operation-id",
        &finalize_id,
    ]);
    let finalized = run(&authority, &ca_path, &finalize).await;
    assert_eq!(finalized["record"].as_object().unwrap().len(), 1);
    let after_finalize = run(&authority, &ca_path, &args(&["cluster", "members"])).await;
    assert!(after_finalize.get("certificate_rollouts").is_none_or(|rollouts| rollouts.as_array().unwrap().is_empty()));
    assert_eq!(run(&authority, &ca_path, &finalize).await, finalized);
    tokio::time::timeout(Duration::from_secs(10), runtime.shutdown())
        .await
        .unwrap()
        .unwrap();
    node.close().await;
    authority.close().await;
    root.close().unwrap();
}

async fn run(server: &Server, ca: &std::path::Path, values: &[String]) -> Value {
    let output = binary(
        &server.address,
        TOKEN,
        Some(ca),
        Some(&server.hostname),
        values,
    )
    .await;
    assert!(
        output.success,
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!String::from_utf8_lossy(&output.stdout).contains(TOKEN));
    serde_json::from_slice(&output.stdout).unwrap()
}

#[tokio::test]
async fn cluster_help_and_dependency_failures_are_offline_and_honest() {
    let help = binary(
        "127.0.0.1:1",
        TOKEN,
        None,
        None,
        &args(&["cluster", "--help"]),
    )
    .await;
    assert!(help.success);
    let text = String::from_utf8(help.stdout).unwrap();
    for name in [
        "node-availability",
        "node-profile",
        "join",
        "members",
        "member-state",
        "cert-prepare",
        "cert-activate",
        "cert-abort",
        "cert-finalize",
        "ownerships",
        "fence-install",
        "fence-retire",
        "fence-show",
        "reconfigure-voters",
        "reconfigure-trust",
        "reconfiguration-status",
        "drain-node",
        "upgrade-node",
        "remove-node",
        "migrate-agent",
    ] {
        assert!(text.contains(name), "missing help command {name}");
    }
    for (name, dependency) in [
        ("reconfigure-voters", "#306"),
        ("drain-node", "#314"),
        ("migrate-agent", "#310"),
    ] {
        let output = binary("127.0.0.1:1", TOKEN, None, None, &args(&["cluster", name])).await;
        assert!(!output.success);
        assert!(output.stdout.is_empty());
        assert!(String::from_utf8_lossy(&output.stderr).contains(dependency));
        assert!(!String::from_utf8_lossy(&output.stderr).contains("could not connect"));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn older_server_without_receipts_is_refused_before_any_mutation() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let server = tokio::spawn(async move {
        tokio::time::timeout(Duration::from_secs(15), async {
            let (socket, _) = listener.accept().await.unwrap();
            let (read, mut write) = socket.into_split();
            let mut read = BufReader::new(read);
            let mut operations = Vec::new();
            loop {
                let mut frame = String::new();
                if read.read_line(&mut frame).await.unwrap() == 0 {
                    break;
                }
                let call: Syscall = serde_json::from_str(&frame).unwrap();
                let reply = match call {
                    Syscall::Hello { .. } => {
                        operations.push("hello");
                        SyscallReply::Hello {
                            protocol_version: agent_sdk::PROTOCOL_VERSION,
                            min_protocol_version: 1,
                            server_version: "older-receiptless-fixture".into(),
                            features: Vec::new(),
                        }
                    }
                    Syscall::Authenticate { token } => {
                        assert_eq!(token, TOKEN);
                        operations.push("authenticate");
                        SyscallReply::Authenticated
                    }
                    _ => panic!("a receiptless server must receive no mutation"),
                };
                let mut reply = serde_json::to_vec(&reply).unwrap();
                reply.push(b'\n');
                write.write_all(&reply).await.unwrap();
            }
            write.shutdown().await.unwrap();
            operations
        })
        .await
        .expect("bounded receiptless endpoint capture")
    });
    let id = Uuid::new_v4().to_string();
    let output = binary(
        &address,
        TOKEN,
        None,
        None,
        &args(&[
            "cluster",
            "node-availability",
            "draining",
            "must refuse ignored ids",
            "--generation",
            "0",
            "--operation-id",
            &id,
        ]),
    )
    .await;
    assert!(!output.success);
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("refusing ignored operation IDs"));
    assert_eq!(server.await.unwrap(), ["hello", "authenticate", "hello"]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn actual_cli_forms_three_signed_tls_members_and_replays_durable_node_member_and_fence_writes(
) {
    let root = tempfile::tempdir().unwrap();
    let issuer = ca();
    let ca_path = root.path().join("ca.pem");
    std::fs::write(&ca_path, issuer.pem()).unwrap();
    let authority = Server::start(
        &root.path().join("authority.db"),
        "authority.agentos.test",
        &issuer,
    )
    .await;
    let node_two = Server::start(&root.path().join("two.db"), "two.agentos.test", &issuer).await;
    let node_three =
        Server::start(&root.path().join("three.db"), "three.agentos.test", &issuer).await;
    let mut members = Vec::new();
    for node in [&authority, &node_two, &node_three] {
        let id = Uuid::new_v4().to_string();
        let join = args(&[
            "cluster",
            "join",
            "--authority",
            &authority.address,
            "--node",
            &node.address,
            "--node-server-name",
            &node.hostname,
            "--reason",
            "CLI formation proof",
            "--operation-id",
            &id,
        ]);
        let record = run(&authority, &ca_path, &join).await;
        assert_eq!(record["operation_id"], id);
        assert_ne!(record["record"]["challenge_operation_id"], id);
        let member = record["record"]["member"].clone();
        assert_eq!(member["endpoint"], node.address);
        assert_eq!(member["state"], "active");
        assert!(member["tls_server_certificate_fingerprint"]
            .as_str()
            .is_some());
        assert_eq!(
            run(&authority, &ca_path, &join).await,
            record,
            "same ID and payload must replay without another registration"
        );
        members.push(member);
    }
    let formed = run(&authority, &ca_path, &args(&["cluster", "members"])).await;
    assert_eq!(formed["members"].as_array().unwrap().len(), 3);
    let ids = formed["members"]
        .as_array()
        .unwrap()
        .iter()
        .map(|member| member["node_id"].as_str().unwrap())
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(ids.len(), 3);
    assert_eq!(formed["generation"], 3);

    let generation_id = Uuid::new_v4().to_string();
    let availability = args(&[
        "cluster",
        "node-availability",
        "draining",
        "CLI generation proof",
        "--generation",
        "0",
        "--operation-id",
        &generation_id,
    ]);
    let changed = run(&node_two, &ca_path, &availability).await;
    assert_eq!(changed["record"]["generation"], 1);
    assert_eq!(run(&node_two, &ca_path, &availability).await, changed);
    let conflict = args(&[
        "cluster",
        "node-availability",
        "quarantined",
        "CLI generation proof",
        "--generation",
        "0",
        "--operation-id",
        &generation_id,
    ]);
    let denied = binary(
        &node_two.address,
        TOKEN,
        Some(&ca_path),
        Some(&node_two.hostname),
        &conflict,
    )
    .await;
    assert!(!denied.success);
    assert!(denied.stdout.is_empty());
    assert!(String::from_utf8_lossy(&denied.stderr).contains("conflict"));

    let profile_id = Uuid::new_v4().to_string();
    let profile = args(&[
        "cluster",
        "node-profile",
        "{\"region\":\"offline-ci\"}",
        "--generation",
        "1",
        "--reason",
        "placement proof",
        "--operation-id",
        &profile_id,
    ]);
    let profiled = run(&node_two, &ca_path, &profile).await;
    assert_eq!(profiled["record"]["generation"], 2);
    assert_eq!(run(&node_two, &ca_path, &profile).await, profiled);

    let member_id = members[2]["node_id"].as_str().unwrap();
    let state_id = Uuid::new_v4().to_string();
    let left = args(&[
        "cluster",
        "member-state",
        member_id,
        "left",
        "CLI member state proof",
        "--generation",
        "1",
        "--operation-id",
        &state_id,
    ]);
    let state = run(&authority, &ca_path, &left).await;
    assert_eq!(state["record"]["generation"], 2);
    assert_eq!(run(&authority, &ca_path, &left).await, state);
    let empty = run(
        &authority,
        &ca_path,
        &args(&["cluster", "ownerships", "--limit", "10"]),
    )
    .await;
    assert_eq!(empty, json!([]));

    let agent_id = Uuid::new_v4().to_string();
    let proof = json!({"cluster_id":formed["cluster_id"], "owner_node_id":members[0]["node_id"], "authority_term":1, "authority_generation":1, "fencing_token":1, "proof_expires_at":(Utc::now()+chrono::Duration::seconds(120)).to_rfc3339()}).to_string();
    let install_id = Uuid::new_v4().to_string();
    let install = args(&[
        "cluster",
        "fence-install",
        &agent_id,
        &proof,
        "--reason",
        "exact fence proof",
        "--operation-id",
        &install_id,
    ]);
    let installed = run(&authority, &ca_path, &install).await;
    assert_eq!(run(&authority, &ca_path, &install).await, installed);
    let retire_id = Uuid::new_v4().to_string();
    let retire = args(&[
        "cluster",
        "fence-retire",
        &agent_id,
        &proof,
        "--reason",
        "exact retirement proof",
        "--operation-id",
        &retire_id,
    ]);
    let retired = run(&authority, &ca_path, &retire).await;
    assert_eq!(retired["record"]["state"], "retired");
    assert_eq!(run(&authority, &ca_path, &retire).await, retired);
    assert_eq!(
        run(&authority, &ca_path, &install).await,
        installed,
        "receipt returns original outcome without reactivating a retired fence"
    );
    assert_eq!(
        run(
            &authority,
            &ca_path,
            &args(&["cluster", "fence-show", &agent_id])
        )
        .await["state"],
        "retired"
    );

    let tenant = authority
        .kernel
        .create_tenant("foreign-receipt-reader")
        .await
        .unwrap();
    let user = authority
        .kernel
        .register_user(&tenant, "admin", "admin@foreign.test", Role::Admin)
        .await
        .unwrap();
    let tenant_token = authority
        .kernel
        .issue_api_key(&user, "denied-cluster-receipt")
        .await
        .unwrap();
    for token in [&tenant_token, "incorrect-operator-token"] {
        let denied = binary(
            &authority.address,
            token,
            Some(&ca_path),
            Some(&authority.hostname),
            &install,
        )
        .await;
        assert!(!denied.success);
        assert!(denied.stdout.is_empty());
        assert!(!String::from_utf8_lossy(&denied.stderr).contains("exact fence proof"));
        assert!(!String::from_utf8_lossy(&denied.stderr).contains(&proof));
    }

    node_two.close().await;
    node_three.close().await;
    authority.close().await;
    let restarted = Server::start(
        &root.path().join("authority.db"),
        "authority.agentos.test",
        &issuer,
    )
    .await;
    assert_eq!(run(&restarted, &ca_path, &left).await, state);
    assert_eq!(
        run(
            &restarted,
            &ca_path,
            &args(&["cluster", "fence-show", &agent_id])
        )
        .await["state"],
        "retired"
    );
    restarted.close().await;
    root.close().unwrap();
}
