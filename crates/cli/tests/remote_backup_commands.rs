use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use chrono::{SecondsFormat, Timelike, Utc};
use kernel::context::SqliteContextManager;
use kernel::storage::{
    generate_backup_recovery_anchor, generate_backup_signing_key_files, load_backup_signing_key,
    verify_backup_with_recovery_anchor,
};
use wiremock::matchers::{header, header_exists, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

struct TempDirectory(PathBuf);

impl TempDirectory {
    fn new() -> Self {
        let path =
            std::env::temp_dir().join(format!("agentctl-remote-backup-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}

impl Drop for TempDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

async fn mount_upload(
    server: &MockServer,
    path_value: &str,
    bytes: &[u8],
    sha256: &str,
    retain_until: &str,
) {
    Mock::given(method("PUT"))
        .and(path(path_value))
        .and(header_exists("authorization"))
        .and(header("x-amz-object-lock-mode", "COMPLIANCE"))
        .and(header_exists("x-amz-checksum-sha256"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(server)
        .await;
    Mock::given(method("HEAD"))
        .and(path(path_value))
        .and(header_exists("authorization"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-length", bytes.len().to_string())
                .insert_header("x-amz-meta-agentos-sha256", sha256)
                .insert_header("x-amz-object-lock-mode", "COMPLIANCE")
                .insert_header("x-amz-object-lock-retain-until-date", retain_until)
                .insert_header("x-amz-version-id", "cli-immutable-version-1"),
        )
        .expect(2)
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path(path_value))
        .and(header_exists("authorization"))
        .and(query_param("versionId", "cli-immutable-version-1"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(bytes))
        .expect(1)
        .mount(server)
        .await;
}

fn agentctl() -> &'static Path {
    Path::new(env!("CARGO_BIN_EXE_agentctl"))
}

#[tokio::test(flavor = "multi_thread")]
async fn cli_publishes_only_a_verified_compliance_locked_backup() {
    let root = TempDirectory::new();
    let database = root.0.join("source.sqlite3");
    let manager = SqliteContextManager::new(&database).unwrap();
    manager
        .kv_put(kernel::AgentId::new_v4(), "cli-proof", "survived")
        .unwrap();

    let private_key = root.0.join("backup-signing.pk8");
    let trust_path = root.0.join("backup-trust.json");
    let trust =
        generate_backup_signing_key_files("cli-remote-test", &private_key, &trust_path).unwrap();
    let signer = load_backup_signing_key(&private_key, "cli-remote-test").unwrap();
    let backup_root = root.0.join("backups");
    let manifest = manager
        .create_signed_backup(&backup_root, "qualified", &signer)
        .unwrap();
    let backup_dir = backup_root.join("qualified");
    let anchor_path = root.0.join("recovery-anchor.json");
    let anchor = generate_backup_recovery_anchor(&backup_dir, None, &trust, &anchor_path).unwrap();
    let manifest_bytes = fs::read(backup_dir.join("manifest.json")).unwrap();
    let database_bytes = fs::read(backup_dir.join("agent_os.db")).unwrap();

    let server = MockServer::start().await;
    let retain_until = (Utc::now() + chrono::Duration::days(2))
        .with_nanosecond(0)
        .unwrap()
        .to_rfc3339_opts(SecondsFormat::Secs, true);
    mount_upload(
        &server,
        "/qualified-backups/install-1/backup-1/agent_os.db",
        &database_bytes,
        &manifest.sha256,
        &retain_until,
    )
    .await;
    mount_upload(
        &server,
        "/qualified-backups/install-1/backup-1/manifest.json",
        &manifest_bytes,
        &anchor.manifest_sha256,
        &retain_until,
    )
    .await;

    let output = Command::new(agentctl())
        .args([
            "backup-remote-publish",
            backup_dir.to_str().unwrap(),
            trust_path.to_str().unwrap(),
            anchor_path.to_str().unwrap(),
            &server.uri(),
            "qualified-backups",
            "install-1/backup-1",
            &retain_until,
            "--region",
            "us-east-1",
            "--allow-loopback-http",
            "--confirm-compliance-lock",
        ])
        .env("AWS_ACCESS_KEY_ID", "cli-access")
        .env("AWS_SECRET_ACCESS_KEY", "cli-super-secret")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "agentctl failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        report["qualification_class"],
        "immutable_remote_backup_publication"
    );
    assert_eq!(report["objects"].as_array().unwrap().len(), 2);
    assert_eq!(report["production_claim_allowed"], false);
    let output_text = String::from_utf8_lossy(&output.stdout);
    assert!(!output_text.contains("cli-access"));
    assert!(!output_text.contains("cli-super-secret"));

    let publication_path = root.0.join("remote-publication.json");
    fs::write(&publication_path, &output.stdout).unwrap();
    let fetched = root.0.join("fresh-host-backup");
    let fetch_output = Command::new(agentctl())
        .args([
            "backup-remote-fetch",
            &server.uri(),
            "qualified-backups",
            "install-1/backup-1",
            publication_path.to_str().unwrap(),
            fetched.to_str().unwrap(),
            trust_path.to_str().unwrap(),
            anchor_path.to_str().unwrap(),
            "--region",
            "us-east-1",
            "--allow-loopback-http",
        ])
        .env("AWS_ACCESS_KEY_ID", "cli-access")
        .env("AWS_SECRET_ACCESS_KEY", "cli-super-secret")
        .output()
        .unwrap();
    assert!(
        fetch_output.status.success(),
        "agentctl fetch failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&fetch_output.stdout),
        String::from_utf8_lossy(&fetch_output.stderr)
    );
    let recovery: serde_json::Value = serde_json::from_slice(&fetch_output.stdout).unwrap();
    assert_eq!(
        recovery["qualification_class"],
        "immutable_remote_backup_recovery"
    );
    assert_eq!(
        recovery["downloaded_bytes"],
        (database_bytes.len() + manifest_bytes.len()) as u64
    );
    assert_eq!(recovery["production_claim_allowed"], false);
    assert!(!String::from_utf8_lossy(&fetch_output.stdout).contains("cli-super-secret"));
    verify_backup_with_recovery_anchor(&fetched, None, &trust, &anchor).unwrap();
}

#[test]
fn cli_requires_explicit_compliance_lock_confirmation() {
    let output = Command::new(agentctl())
        .args([
            "backup-remote-publish",
            "/backup",
            "/trust",
            "/anchor",
            "http://127.0.0.1:9000",
            "qualified-backups",
            "install-1/backup-1",
            "2030-01-01T00:00:00Z",
            "--allow-loopback-http",
        ])
        .env("AWS_ACCESS_KEY_ID", "cli-access")
        .env("AWS_SECRET_ACCESS_KEY", "cli-secret")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("usage: agentctl"));
}
