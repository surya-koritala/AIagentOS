use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::Arc;

use kernel::auth::Role;
use kernel::mac::MacDecision;
use kernel::policy::PolicyDocument;
use kernel::AgentKernelImpl;

struct TempDirectory {
    path: PathBuf,
}

impl TempDirectory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("agentctl-policy-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&path).expect("create temporary policy directory");
        Self { path }
    }

    fn join(&self, name: &str) -> PathBuf {
        self.path.join(name)
    }
}

impl Drop for TempDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

fn path(path: &Path) -> &str {
    path.to_str().expect("UTF-8 test path")
}

fn agentctl(addr: &str, token: Option<&str>, arguments: &[&str]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_agentctl"));
    command.arg("--addr").arg(addr);
    if let Some(token) = token {
        command.arg("--token").arg(token);
    }
    command
        .args(arguments)
        .output()
        .expect("run agentctl command")
}

fn json(output: &Output) -> serde_json::Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "invalid JSON output: {error}\nstdout={}\nstderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

fn assert_success(output: &Output, command: &str) {
    assert!(
        output.status.success(),
        "{command} failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn canonical_agentctl_validates_and_explains_policy_without_connecting() {
    let root = TempDirectory::new();
    let policy_path = root.join("policy.toml");
    let policy = r#"
version = 1
enforcing = true
default = "deny"

[[rule]]
name = "reader-workspace"
subject = "profile:read-only"
action = "read"
object = "/workspace/**"
decision = "allow"
"#;
    std::fs::write(&policy_path, policy).expect("write policy");

    // An unreachable address proves both commands complete on the bounded
    // offline authoring path rather than booting or contacting a kernel. An
    // invalid live-profile variable also proves offline dispatch happens
    // before connection-profile parsing.
    let unreachable = "127.0.0.1:1";
    let validated = Command::new(env!("CARGO_BIN_EXE_agentctl"))
        .env("AGENTOS_CONNECT_TIMEOUT_MS", "invalid-live-profile")
        .args(["--addr", unreachable, "policy-validate", path(&policy_path)])
        .output()
        .expect("run offline policy validation");
    assert_success(&validated, "policy-validate");
    let validation = json(&validated);
    assert_eq!(validation["version"], 1);
    assert_eq!(validation["enforcing"], true);
    assert_eq!(validation["default"], "deny");
    assert_eq!(validation["rule_count"], 1);
    assert!(validation["warnings"].is_array());

    let explained = agentctl(
        unreachable,
        None,
        &[
            "policy-explain",
            path(&policy_path),
            "--subject",
            "profile:read-only",
            "--action",
            "read",
            "--object",
            "/workspace/notes",
        ],
    );
    assert_success(&explained, "policy-explain");
    let explanation = json(&explained);
    let document = PolicyDocument::from_toml(policy).expect("parse policy in test");
    let engine_explanation = document.explain("profile:read-only", "read", "/workspace/notes");
    let engine_decision = match engine_explanation.decision {
        MacDecision::Allow => "allow",
        MacDecision::Deny => "deny",
        MacDecision::Audit => "audit",
    };
    assert_eq!(explanation["decision"], engine_decision);
    assert_eq!(
        explanation["matched_rule"].as_u64(),
        engine_explanation
            .matched_rule
            .and_then(|index| u64::try_from(index).ok())
    );
    assert_eq!(explanation["matched_name"], "reader-workspace");
    assert_eq!(explanation["used_default"], false);

    let default_denied = agentctl(
        unreachable,
        None,
        &[
            "policy-explain",
            path(&policy_path),
            "--subject",
            "profile:read-only",
            "--action",
            "write",
            "--object",
            "/workspace/notes",
        ],
    );
    assert_success(&default_denied, "policy-explain default");
    let default_explanation = json(&default_denied);
    assert_eq!(default_explanation["decision"], "deny");
    assert_eq!(default_explanation["matched_rule"], serde_json::Value::Null);
    assert_eq!(default_explanation["used_default"], true);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn canonical_agentctl_system_audits_are_live_and_tenant_credentials_are_denied() {
    let kernel = Arc::new(AgentKernelImpl::new().expect("kernel"));
    let tenant = kernel
        .create_tenant("agentctl-audit")
        .await
        .expect("tenant");
    let admin = kernel
        .register_user(
            &tenant,
            "audit-admin",
            "admin@agentctl-audit.invalid",
            Role::Admin,
        )
        .await
        .expect("admin");
    let admin_token = kernel
        .issue_api_key(&admin, "agentctl-audit-admin")
        .await
        .expect("admin API key");
    let reader = kernel
        .register_user(
            &tenant,
            "audit-reader",
            "reader@agentctl-audit.invalid",
            Role::ReadOnly,
        )
        .await
        .expect("reader");
    let reader_token = kernel
        .issue_api_key(&reader, "agentctl-audit-reader")
        .await
        .expect("reader API key");

    let system_token = "agentctl-system-audit-secret";
    let server = kernel::syscall_server::SyscallServer::bind(Arc::clone(&kernel), "127.0.0.1:0")
        .await
        .expect("bind audit command server")
        .with_auth_token(system_token);
    let address = server.local_addr().expect("server address").to_string();
    let server_task = tokio::spawn(server.serve());

    let gate = agentctl(&address, Some(system_token), &["gate-stats"]);
    assert_success(&gate, "gate-stats");
    let gate = json(&gate);
    for field in [
        "allowed",
        "denied_capability",
        "denied_mac",
        "denied_approval",
        "denied_cgroup",
        "denied_namespace",
        "denied_unknown",
        "audited",
    ] {
        assert!(gate[field].is_u64(), "missing numeric gate field {field}");
    }

    for (command, label) in [
        (["node-control-audit", "25"], "node-control-audit"),
        (
            ["cluster-membership-audit", "25"],
            "cluster-membership-audit",
        ),
    ] {
        let output = agentctl(&address, Some(system_token), &command);
        assert_success(&output, label);
        assert!(json(&output).is_array(), "{label} must return a JSON array");
    }

    for invalid_limit in ["0", "1001", "not-a-number"] {
        let output = agentctl(
            &address,
            Some(system_token),
            &["node-control-audit", invalid_limit],
        );
        assert_eq!(
            output.status.code(),
            Some(2),
            "invalid audit limit {invalid_limit} must be a usage error"
        );
        assert!(output.stdout.is_empty());
        assert!(String::from_utf8_lossy(&output.stderr).contains("usage: agentctl"));
    }

    for (token, role) in [
        (admin_token.as_str(), "tenant Admin"),
        (reader_token.as_str(), "tenant ReadOnly"),
    ] {
        for command in [
            vec!["gate-stats"],
            vec!["node-control-audit", "25"],
            vec!["cluster-membership-audit", "25"],
        ] {
            let output = agentctl(&address, Some(token), &command);
            assert!(
                !output.status.success(),
                "{role} unexpectedly accessed {}",
                command[0]
            );
            assert!(
                output.stdout.is_empty(),
                "{role} denial leaked audit output for {}",
                command[0]
            );
            assert!(
                String::from_utf8_lossy(&output.stderr)
                    .contains("resource not found or access denied"),
                "{role} received the wrong denial for {}: {}",
                command[0],
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }

    server_task.abort();
    let _ = server_task.await;
}
