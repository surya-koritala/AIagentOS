use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::Arc;

use agent_sdk::{
    PackageArchive, PackageFile, PackageFileKind, PackageManifest, PackagePayload, PackageSbom,
    PackageSigningKey, SbomComponent,
};
use kernel::agent_package::AgentManifest;
use kernel::auth::Role;
use kernel::AgentKernelImpl;

struct TempDirectory(PathBuf);

impl TempDirectory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("agentctl-packages-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&path).expect("create package command temp directory");
        Self(path)
    }

    fn join(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for TempDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn package(name: &str, version: &str, publisher: &str) -> PackagePayload {
    PackagePayload {
        schema_version: 1,
        package: PackageManifest {
            name: name.into(),
            version: version.parse().expect("package version"),
            description: format!("{name} {version} command regression"),
            publisher: publisher.into(),
            license: Some("AGPL-3.0-only".into()),
            dependencies: Vec::new(),
            capabilities_required: vec!["CAP_FILE_READ".into()],
            tools_required: Vec::new(),
        },
        agent: AgentManifest {
            name: name.into(),
            description: "agentctl package command regression".into(),
            task: format!("run the signed {name} {version} task"),
            entry: None,
            provider: "stub".into(),
            profile: "read-only".into(),
            priority: 3,
            nice: None,
            tools: Vec::new(),
            memory: vec![format!("installed version {version}")],
        },
        files: vec![PackageFile {
            path: "prompts/system.txt".into(),
            kind: PackageFileKind::Prompt,
            bytes: format!("signed package {name} {version}").into_bytes(),
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

fn agentctl(address: &str, token: &str, arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_agentctl"))
        .args(["--addr", address, "--token", token])
        .args(arguments)
        .output()
        .expect("run agentctl")
}

fn assert_success(output: &Output, command: &str) {
    assert!(
        output.status.success(),
        "{command} failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

fn json(output: &Output) -> serde_json::Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "invalid JSON output ({error}): {}",
            String::from_utf8_lossy(&output.stdout)
        )
    })
}

fn path(path: &Path) -> &str {
    path.to_str().expect("UTF-8 test path")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn canonical_agentctl_manages_signed_packages_end_to_end() {
    let root = TempDirectory::new();
    let public_key_file = root.join("publisher.ed25519.pub");
    let archive_v1_file = root.join("cli-package-1.0.0.agent");
    let archive_v2_file = root.join("cli-package-2.0.0.agent");
    let fetched_file = root.join("fetched.agent");

    let kernel = Arc::new(AgentKernelImpl::new().expect("kernel"));
    let tenant = kernel
        .create_tenant("agentctl-packages")
        .await
        .expect("tenant");
    let admin = kernel
        .register_user(
            &tenant,
            "package-admin",
            "package-admin@example.invalid",
            Role::Admin,
        )
        .await
        .expect("package admin");
    let token = kernel
        .issue_api_key(&admin, "agentctl-packages")
        .await
        .expect("admin API key");
    let reader = kernel
        .register_user(
            &tenant,
            "package-reader",
            "package-reader@example.invalid",
            Role::ReadOnly,
        )
        .await
        .expect("package reader");
    let reader_token = kernel
        .issue_api_key(&reader, "agentctl-package-reader")
        .await
        .expect("reader API key");
    let other_tenant = kernel
        .create_tenant("agentctl-packages-other")
        .await
        .expect("other tenant");
    let other_admin = kernel
        .register_user(
            &other_tenant,
            "other-package-admin",
            "other-package-admin@example.invalid",
            Role::Admin,
        )
        .await
        .expect("other package admin");
    let other_token = kernel
        .issue_api_key(&other_admin, "agentctl-packages-other")
        .await
        .expect("other admin API key");

    let server = kernel::syscall_server::SyscallServer::bind(Arc::clone(&kernel), "127.0.0.1:0")
        .await
        .expect("bind package command server");
    let address = server.local_addr().expect("server address").to_string();
    let server_task = tokio::spawn(server.serve());

    let publisher = admin.as_str();
    let (signer, _) =
        PackageSigningKey::generate(publisher, "package-release-1").expect("signing key");
    std::fs::write(&public_key_file, signer.public_key()).expect("write public key");
    let archive_v1 =
        PackageArchive::sign(package("cli-package", "1.0.0", publisher), &signer).expect("sign v1");
    let archive_v2 =
        PackageArchive::sign(package("cli-package", "2.0.0", publisher), &signer).expect("sign v2");
    std::fs::write(&archive_v1_file, &archive_v1).expect("write v1 archive");
    std::fs::write(&archive_v2_file, &archive_v2).expect("write v2 archive");

    let trusted = agentctl(
        &address,
        &token,
        &[
            "package-trust-key",
            publisher,
            signer.key_id(),
            path(&public_key_file),
            "2020-01-01T00:00:00Z",
        ],
    );
    assert_success(&trusted, "package-trust-key");
    assert_eq!(json(&trusted)["status"], "trusted");

    let published_v1 = agentctl(
        &address,
        &token,
        &["package-publish", path(&archive_v1_file)],
    );
    assert_success(&published_v1, "package-publish v1");
    assert_eq!(json(&published_v1)["version"], "1.0.0");

    let search = agentctl(&address, &token, &["package-search", "cli-package"]);
    assert_success(&search, "package-search");
    assert_eq!(json(&search).as_array().expect("search array").len(), 1);
    let reader_search = agentctl(&address, &reader_token, &["package-search", "cli-package"]);
    assert_success(&reader_search, "read-only package-search");
    let reader_install = agentctl(
        &address,
        &reader_token,
        &["package-install", "cli-package", "=1.0.0"],
    );
    assert!(!reader_install.status.success());
    assert!(String::from_utf8_lossy(&reader_install.stderr).contains("AuthorizationDenied"));
    let isolated_search = agentctl(&address, &other_token, &["package-search", "cli-package"]);
    assert_success(&isolated_search, "tenant-isolated package-search");
    assert_eq!(json(&isolated_search), serde_json::json!([]));

    let fetched = agentctl(
        &address,
        &token,
        &["package-fetch", "cli-package", "1.0.0", path(&fetched_file)],
    );
    assert_success(&fetched, "package-fetch");
    assert_eq!(
        std::fs::read(&fetched_file).expect("read fetched archive"),
        archive_v1
    );
    let overwrite_refused = agentctl(
        &address,
        &token,
        &["package-fetch", "cli-package", "1.0.0", path(&fetched_file)],
    );
    assert!(!overwrite_refused.status.success());
    assert!(String::from_utf8_lossy(&overwrite_refused.stderr)
        .contains("without overwriting an existing file"));

    let installed_v1 = agentctl(
        &address,
        &token,
        &["package-install", "cli-package", "=1.0.0"],
    );
    assert_success(&installed_v1, "package-install v1");
    assert_eq!(json(&installed_v1)["version"], "1.0.0");
    let listed = agentctl(&address, &token, &["packages"]);
    assert_success(&listed, "packages");
    assert_eq!(json(&listed)[0]["name"], "cli-package");

    let run = agentctl(&address, &token, &["package-run", "cli-package"]);
    assert_success(&run, "package-run");
    let agent_id = json(&run)["agent_id"]
        .as_str()
        .expect("run agent id")
        .parse()
        .expect("agent UUID");
    assert_eq!(
        kernel
            .context_manager
            .agent_tenant(agent_id)
            .expect("agent tenant lookup"),
        Some(tenant.clone())
    );

    let published_v2 = agentctl(
        &address,
        &token,
        &["package-publish", path(&archive_v2_file)],
    );
    assert_success(&published_v2, "package-publish v2");
    let installed_v2 = agentctl(
        &address,
        &token,
        &["package-install", "cli-package", "=2.0.0"],
    );
    assert_success(&installed_v2, "package-install v2");
    assert_eq!(json(&installed_v2)["version"], "2.0.0");

    let unconfirmed_rollback = agentctl(&address, &token, &["package-rollback", "cli-package"]);
    assert_eq!(unconfirmed_rollback.status.code(), Some(2));
    let rolled_back = agentctl(
        &address,
        &token,
        &[
            "package-rollback",
            "cli-package",
            "--confirm",
            "cli-package",
        ],
    );
    assert_success(&rolled_back, "package-rollback");
    assert_eq!(json(&rolled_back)["version"], "1.0.0");

    let mismatched_yank = agentctl(
        &address,
        &token,
        &[
            "package-yank",
            "cli-package",
            "2.0.0",
            "--confirm",
            "cli-package@1.0.0",
        ],
    );
    assert_eq!(mismatched_yank.status.code(), Some(2));
    let yanked = agentctl(
        &address,
        &token,
        &[
            "package-yank",
            "cli-package",
            "2.0.0",
            "--confirm",
            "cli-package@2.0.0",
        ],
    );
    assert_success(&yanked, "package-yank");
    assert_eq!(json(&yanked)["yanked"], true);

    let unconfirmed_remove = agentctl(&address, &token, &["package-remove", "cli-package"]);
    assert_eq!(unconfirmed_remove.status.code(), Some(2));
    let removed = agentctl(
        &address,
        &token,
        &["package-remove", "cli-package", "--confirm", "cli-package"],
    );
    assert_success(&removed, "package-remove");
    assert_eq!(json(&removed)["removed"], true);
    let listed_after_remove = agentctl(&address, &token, &["packages"]);
    assert_success(&listed_after_remove, "packages after remove");
    assert_eq!(json(&listed_after_remove), serde_json::json!([]));

    let unconfirmed_revoke = agentctl(&address, &token, &["package-revoke-key", signer.key_id()]);
    assert_eq!(unconfirmed_revoke.status.code(), Some(2));
    let revoked = agentctl(
        &address,
        &token,
        &[
            "package-revoke-key",
            signer.key_id(),
            "--confirm",
            signer.key_id(),
        ],
    );
    assert_success(&revoked, "package-revoke-key");
    assert_eq!(json(&revoked)["status"], "revoked");

    server_task.abort();
    let _ = server_task.await;
}
