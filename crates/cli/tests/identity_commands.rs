use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

use agent_sdk::{KernelClient, SdkError, WireErrorCode};
use kernel::config::Config;

const BOOTSTRAP_TOKEN: &str = "fixture-system-operator-not-a-live-secret";

struct TestRoot(PathBuf);

impl TestRoot {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("agentctl-identity-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}

impl Drop for TestRoot {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct ServerProcess {
    child: Child,
    address: String,
    log: PathBuf,
}

impl ServerProcess {
    fn start(config: &Path, root: &Path, generation: u8) -> Self {
        let log = root.join(format!("server-{generation}.log"));
        let file = std::fs::File::create(&log).unwrap();
        let child = Command::new(env!("CARGO_BIN_EXE_agent-server"))
            .arg("127.0.0.1:0")
            .env("AGENT_SERVER_CONFIG", config)
            .env("AGENT_SERVER_TOKEN", BOOTSTRAP_TOKEN)
            .env("RUST_LOG", "info")
            .env("LOG_FORMAT", "json")
            .env_remove("AGENT_SERVER_UNIX")
            .env_remove("AGENT_SERVER_TLS_CERT")
            .env_remove("AGENT_SERVER_TLS_KEY")
            .stdout(Stdio::from(file.try_clone().unwrap()))
            .stderr(Stdio::from(file))
            .spawn()
            .unwrap();
        let mut process = Self {
            child,
            address: String::new(),
            log,
        };
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            let lines = process.logs();
            if let Some(address) = lines
                .lines()
                .find_map(|line| line.strip_prefix("agent-server listening on tcp:"))
            {
                process.address = address.to_string();
                return process;
            }
            assert!(
                process.child.try_wait().unwrap().is_none(),
                "fixture server exited before listening"
            );
            assert!(
                Instant::now() < deadline,
                "fixture server did not become ready"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn logs(&self) -> String {
        let mut text = String::new();
        std::fs::File::open(&self.log)
            .unwrap()
            .read_to_string(&mut text)
            .unwrap();
        text
    }

    fn stop(&mut self) {
        if self.child.try_wait().unwrap().is_none() {
            self.child.kill().unwrap();
            self.child.wait().unwrap();
        }
    }
}

impl Drop for ServerProcess {
    fn drop(&mut self) {
        self.stop();
    }
}

fn agentctl(address: &str, token: &str, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_agentctl"))
        .args(["--addr", address])
        .env("AGENT_SERVER_TOKEN", token)
        .env("RUST_LOG", "trace")
        .args(args)
        .output()
        .unwrap()
}

fn json_success(output: Output) -> serde_json::Value {
    assert!(
        output.status.success(),
        "operator command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

fn issued_key(output: Output) -> String {
    assert!(output.status.success(), "key issuance failed");
    let stdout = String::from_utf8(output.stdout).unwrap();
    let key = stdout.trim().to_string();
    assert!(key.starts_with("ak_"));
    assert_eq!(stdout.lines().count(), 1);
    assert_eq!(stdout.matches(&key).count(), 1);
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(!stderr.contains(&key));
    assert!(stderr.contains("shown once") && stderr.contains("cannot be recovered"));
    key
}

async fn tenant_client(address: &str, key: &str) -> KernelClient {
    let mut client = KernelClient::connect(address).await.unwrap();
    client.authenticate(key).await.unwrap();
    client
}

fn authorization_denied<T>(result: Result<T, SdkError>) {
    assert!(matches!(
        result,
        Err(SdkError::Wire {
            code: WireErrorCode::AuthorizationDenied,
            ..
        })
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn first_operator_bootstrap_two_tenants_multiple_agents_and_crash_restart_use_shipped_binaries(
) {
    let root = TestRoot::new();
    let config_path = root.0.join("config.toml");
    let mut config = Config {
        data_dir: root.0.join("data"),
        llm_provider: "local".into(),
        ..Config::default()
    };
    config.budgets.max_context_storage_bytes = 32 * 1024;
    config.budgets.tenant_max_context_storage_bytes = 64 * 1024;
    config.budgets.global_max_context_storage_bytes = 128 * 1024;
    config.save_to(&config_path).unwrap();
    let mut server = ServerProcess::start(&config_path, &root.0, 1);
    let tenant_a = json_success(agentctl(
        &server.address,
        BOOTSTRAP_TOKEN,
        &["tenant-create", "alpha"],
    ))["id"]
        .as_str()
        .unwrap()
        .to_string();
    let tenant_b = json_success(agentctl(
        &server.address,
        BOOTSTRAP_TOKEN,
        &["tenant-create", "beta"],
    ))["id"]
        .as_str()
        .unwrap()
        .to_string();
    let admin_a = json_success(agentctl(
        &server.address,
        BOOTSTRAP_TOKEN,
        &[
            "--tenant",
            &tenant_a,
            "user-create",
            "alpha-admin",
            "alpha@example.test",
            "admin",
        ],
    ))["id"]
        .as_str()
        .unwrap()
        .to_string();
    let admin_b = json_success(agentctl(
        &server.address,
        BOOTSTRAP_TOKEN,
        &[
            "--tenant",
            &tenant_b,
            "user-create",
            "beta-admin",
            "beta@example.test",
            "admin",
        ],
    ))["id"]
        .as_str()
        .unwrap()
        .to_string();
    let key_a = issued_key(agentctl(
        &server.address,
        BOOTSTRAP_TOKEN,
        &[
            "--tenant",
            &tenant_a,
            "api-key-issue",
            &admin_a,
            "alpha-operator",
        ],
    ));
    let key_b = issued_key(agentctl(
        &server.address,
        BOOTSTRAP_TOKEN,
        &[
            "--tenant",
            &tenant_b,
            "api-key-issue",
            &admin_b,
            "beta-operator",
        ],
    ));
    let first = json_success(agentctl(
        &server.address,
        &key_a,
        &[
            "create",
            "researcher",
            "read project evidence",
            "stub",
            "read-only",
            "3",
        ],
    ))["id"]
        .as_str()
        .unwrap()
        .to_string();
    let second = json_success(agentctl(
        &server.address,
        &key_a,
        &[
            "create",
            "reviewer",
            "review project evidence",
            "stub",
            "standard",
            "3",
        ],
    ))["id"]
        .as_str()
        .unwrap()
        .to_string();
    let foreign = json_success(agentctl(
        &server.address,
        &key_b,
        &[
            "create",
            "beta-worker",
            "private work",
            "stub",
            "standard",
            "3",
        ],
    ))["id"]
        .as_str()
        .unwrap()
        .to_string();
    let list = agentctl(&server.address, &key_a, &["list"]);
    assert!(list.status.success());
    let list = String::from_utf8(list.stdout).unwrap();
    assert!(list.contains(&first) && list.contains(&second) && !list.contains(&foreign));
    let denied_bootstrap = agentctl(&server.address, &key_a, &["tenant-create", "forbidden"]);
    assert!(!denied_bootstrap.status.success());
    assert!(String::from_utf8_lossy(&denied_bootstrap.stderr).contains("access denied"));
    let denied_scope = agentctl(&server.address, &key_a, &["--tenant", &tenant_b, "users"]);
    assert!(!denied_scope.status.success());
    let mut a = tenant_client(&server.address, &key_a).await;
    let mut b = tenant_client(&server.address, &key_b).await;
    let invalid_revoke = a
        .revoke_api_key(&key_a, agent_sdk::CONFIRM_IDENTITY_REVOCATION)
        .await;
    assert!(matches!(invalid_revoke, Err(SdkError::Configuration(_))));
    authorization_denied(a.issue_api_key(&admin_b, "forbidden").await);
    authorization_denied(a.storage_get(&foreign, "proof").await);
    authorization_denied(b.storage_get(&first, "proof").await);
    a.storage_put(&first, "proof", "alpha-survives-restart")
        .await
        .unwrap();
    b.storage_put(&foreign, "proof", "beta-survives-restart")
        .await
        .unwrap();
    let quota = a.memory_store(&first, "q".repeat(64 * 1024), None).await;
    assert!(matches!(
        quota,
        Err(SdkError::Wire {
            code: WireErrorCode::QuotaExceeded,
            ..
        })
    ));
    let write = a
        .call_tool(
            &first,
            "write_file",
            serde_json::json!({ "path": "forbidden.txt", "content": "denied" }),
        )
        .await;
    assert!(matches!(
        write,
        Err(SdkError::Wire {
            code: WireErrorCode::PermissionDenied,
            ..
        })
    ));
    let inventory = json_success(agentctl(&server.address, &key_a, &["api-keys"]));
    let key_id = inventory[0]["key_id"].as_str().unwrap().to_string();
    assert!(!inventory.to_string().contains(&key_a));
    drop(a);
    drop(b);
    server.stop();
    let logs = server.logs();
    for secret in [&key_a, &key_b, BOOTSTRAP_TOKEN] {
        assert!(!logs.contains(secret));
    }
    for action in [
        "auth.tenant.create",
        "auth.user.create",
        "auth.api_key.issue",
    ] {
        assert!(logs
            .lines()
            .any(|line| line.contains("agentos::auth_audit") && line.contains(action)));
    }
    assert!(
        logs.contains("actor_tenant") && logs.contains("actor_user") && logs.contains("actor_role")
    );
    let server = ServerProcess::start(&config_path, &root.0, 2);
    let mut a = tenant_client(&server.address, &key_a).await;
    let mut b = tenant_client(&server.address, &key_b).await;
    assert_eq!(
        a.storage_get(&first, "proof").await.unwrap().as_deref(),
        Some("alpha-survives-restart")
    );
    assert_eq!(
        b.storage_get(&foreign, "proof").await.unwrap().as_deref(),
        Some("beta-survives-restart")
    );
    authorization_denied(a.storage_get(&foreign, "proof").await);
    assert_eq!(a.list_agents().await.unwrap().len(), 2);
    let revoked = json_success(agentctl(
        &server.address,
        &key_a,
        &["api-key-revoke", &key_id, "--confirm", &key_id],
    ));
    assert_eq!(revoked["revoked"], true);
    assert!(matches!(
        a.list_agents().await,
        Err(SdkError::Wire {
            code: WireErrorCode::AuthenticationRequired,
            ..
        })
    ));
    let fresh = agentctl(&server.address, &key_a, &["list"]);
    assert!(!fresh.status.success());
    assert_eq!(b.list_agents().await.unwrap().len(), 1);
    for secret in [&key_a, &key_b, BOOTSTRAP_TOKEN] {
        assert!(!server.logs().contains(secret));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn identity_cli_help_roles_and_exact_confirmation_are_unambiguous() {
    let invalid_without_server = agentctl(
        "127.0.0.1:1",
        BOOTSTRAP_TOKEN,
        &["user-create", "bad", "bad@example.test", "superuser"],
    );
    assert_eq!(invalid_without_server.status.code(), Some(2));
    let kernel = std::sync::Arc::new(kernel::AgentKernelImpl::new().unwrap());
    let server = kernel::syscall_server::SyscallServer::bind(kernel, "127.0.0.1:0")
        .await
        .unwrap()
        .with_auth_token(BOOTSTRAP_TOKEN);
    let address = server.local_addr().unwrap().to_string();
    let server_task = tokio::spawn(server.serve());
    let help = Command::new(env!("CARGO_BIN_EXE_agentctl"))
        .arg("--help")
        .output()
        .unwrap();
    let text = String::from_utf8(help.stdout).unwrap();
    for command in [
        "tenant-create",
        "tenants",
        "tenant-revoke",
        "user-create",
        "users",
        "user-revoke",
        "api-key-issue",
        "api-keys",
        "api-key-revoke",
    ] {
        assert!(text.contains(command));
    }
    let tenant = json_success(agentctl(
        &address,
        BOOTSTRAP_TOKEN,
        &["tenant-create", "confirmation"],
    ))["id"]
        .as_str()
        .unwrap()
        .to_string();
    let user = json_success(agentctl(
        &address,
        BOOTSTRAP_TOKEN,
        &[
            "--tenant",
            &tenant,
            "user-create",
            "operator",
            "operator@example.test",
            "operator",
        ],
    ))["id"]
        .as_str()
        .unwrap()
        .to_string();
    let invalid = agentctl(
        &address,
        BOOTSTRAP_TOKEN,
        &[
            "--tenant",
            &tenant,
            "user-create",
            "bad",
            "bad@example.test",
            "superuser",
        ],
    );
    assert_eq!(invalid.status.code(), Some(2));
    let key = issued_key(agentctl(
        &address,
        BOOTSTRAP_TOKEN,
        &["--tenant", &tenant, "api-key-issue", &user, "fixture"],
    ));
    let id = kernel::auth::hash_secret(&key);
    for (command, target) in [
        ("tenant-revoke", tenant.as_str()),
        ("user-revoke", user.as_str()),
        ("api-key-revoke", id.as_str()),
    ] {
        for args in [
            vec![command, target],
            vec![command, target, "--confirm", "wrong-target"],
        ] {
            let result = agentctl(&address, BOOTSTRAP_TOKEN, &args);
            assert_eq!(result.status.code(), Some(2));
        }
    }
    let users = json_success(agentctl(
        &address,
        BOOTSTRAP_TOKEN,
        &["--tenant", &tenant, "users"],
    ));
    assert_eq!(users[0]["role"], "read_only");
    let revoked = json_success(agentctl(
        &address,
        BOOTSTRAP_TOKEN,
        &["api-key-revoke", &id, "--confirm", &id],
    ));
    assert_eq!(revoked["revoked"], true);
    let revoked = json_success(agentctl(
        &address,
        BOOTSTRAP_TOKEN,
        &["user-revoke", &user, "--confirm", &user],
    ));
    assert_eq!(revoked["revoked"], true);
    let revoked = json_success(agentctl(
        &address,
        BOOTSTRAP_TOKEN,
        &["tenant-revoke", &tenant, "--confirm", &tenant],
    ));
    assert_eq!(revoked["revoked"], true);
    server_task.abort();
}
