//! Real S3-compatible object-lock publication and recovery qualification.
//!
//! This suite deliberately keeps `production_claim_allowed` false: a
//! disposable MinIO instance proves protocol behavior and operator-path
//! regression, not the required independent remote recovery run.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use chrono::{SecondsFormat, Utc};
use kernel::context::SqliteContextManager;
use kernel::remote_backup::{
    fetch_remote_backup, publish_remote_backup, qualification_create_delete_markers,
    RemoteBackupConfig, RemoteBackupPublicationReport, RemoteBackupRecoveryReport, S3Credentials,
};
use kernel::storage::{
    generate_backup_recovery_anchor, restore_backup_with_recovery_anchor, BackupSigningKey,
};
use kernel::AgentId;
use serde::Serialize;

const SCHEMA_VERSION: u32 = 1;
const QUALIFICATION_CLASS: &str = "disposable_s3_object_lock_recovery";

#[derive(Default)]
struct Cli {
    endpoint: Option<String>,
    bucket: Option<String>,
    prefix: Option<String>,
    state_dir: Option<PathBuf>,
    output: Option<PathBuf>,
    server_image_digest: Option<String>,
    client_image_digest: Option<String>,
    validate_only: bool,
}

#[derive(Debug, Serialize)]
struct SourceMetadata {
    commit: String,
    dirty: Option<bool>,
    rustc: String,
}

#[derive(Debug, Serialize)]
struct EnvironmentMetadata {
    os: &'static str,
    architecture: &'static str,
    endpoint_origin: String,
    bucket: String,
    server_image_digest: String,
    client_image_digest: String,
}

#[derive(Debug, Serialize)]
struct QualificationReport {
    schema_version: u32,
    suite: &'static str,
    generated_at: String,
    qualification_class: &'static str,
    proof_scope: &'static str,
    production_claim_allowed: bool,
    build_profile: &'static str,
    source: SourceMetadata,
    environment: EnvironmentMetadata,
    publication: RemoteBackupPublicationReport,
    delete_marker_version_ids: Vec<String>,
    recovery: RemoteBackupRecoveryReport,
    checks: BTreeMap<&'static str, bool>,
    passed: bool,
    caveats: Vec<&'static str>,
}

fn parse_cli() -> Result<Cli, String> {
    let mut parsed = Cli::default();
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--endpoint" => parsed.endpoint = args.next(),
            "--bucket" => parsed.bucket = args.next(),
            "--prefix" => parsed.prefix = args.next(),
            "--state-dir" => parsed.state_dir = args.next().map(PathBuf::from),
            "--output" => parsed.output = args.next().map(PathBuf::from),
            "--server-image-digest" => parsed.server_image_digest = args.next(),
            "--client-image-digest" => parsed.client_image_digest = args.next(),
            "--validate" => parsed.validate_only = true,
            "-h" | "--help" => {
                println!(
                    "remote-backup-qualification --validate | \\\n                     --endpoint LOOPBACK_URL --bucket NAME --prefix PREFIX \\\n                     --state-dir PATH --output PATH \\\n                     --server-image-digest sha256:HEX --client-image-digest sha256:HEX"
                );
                std::process::exit(0);
            }
            other => return Err(format!("unknown argument {other:?}")),
        }
    }
    if parsed.validate_only {
        if parsed.endpoint.is_some()
            || parsed.bucket.is_some()
            || parsed.prefix.is_some()
            || parsed.state_dir.is_some()
            || parsed.output.is_some()
            || parsed.server_image_digest.is_some()
            || parsed.client_image_digest.is_some()
        {
            return Err("--validate cannot be combined with execution arguments".into());
        }
        return Ok(parsed);
    }
    if parsed.endpoint.is_none()
        || parsed.bucket.is_none()
        || parsed.prefix.is_none()
        || parsed.state_dir.is_none()
        || parsed.output.is_none()
        || parsed.server_image_digest.is_none()
        || parsed.client_image_digest.is_none()
    {
        return Err("qualification execution requires every documented argument".into());
    }
    Ok(parsed)
}

fn validate_image_digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn validate_contract() -> Result<(), String> {
    if SCHEMA_VERSION != 1 || QUALIFICATION_CLASS != "disposable_s3_object_lock_recovery" {
        return Err("remote backup qualification constants are invalid".into());
    }
    Ok(())
}

fn command_output(program: &str, args: &[&str]) -> Option<String> {
    Command::new(program)
        .args(args)
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|output| output.trim().to_string())
        .filter(|output| !output.is_empty())
}

fn source_metadata() -> SourceMetadata {
    SourceMetadata {
        commit: command_output("git", &["rev-parse", "HEAD"]).unwrap_or_else(|| "unknown".into()),
        dirty: Command::new("git")
            .args(["status", "--porcelain"])
            .output()
            .ok()
            .filter(|output| output.status.success())
            .map(|output| !output.stdout.is_empty()),
        rustc: command_output("rustc", &["--version"]).unwrap_or_else(|| "unknown".into()),
    }
}

fn prepare_state_dir(path: &Path) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(_) => return Err(format!("state directory {} already exists", path.display())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(format!(
                "inspect state directory {}: {error}",
                path.display()
            ))
        }
    }
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    if !fs::symlink_metadata(parent)
        .map_err(|error| format!("inspect state parent {}: {error}", parent.display()))?
        .file_type()
        .is_dir()
    {
        return Err("state parent must be a real directory".into());
    }
    fs::create_dir(path).map_err(|error| format!("create state directory: {error}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .map_err(|error| format!("protect state directory: {error}"))?;
    }
    Ok(())
}

async fn execute(cli: Cli) -> Result<(), String> {
    validate_contract()?;
    if cli.validate_only {
        println!(
            "validated remote backup qualification schema v{SCHEMA_VERSION}: {QUALIFICATION_CLASS}"
        );
        return Ok(());
    }
    if cfg!(debug_assertions) {
        return Err("qualification execution requires a --release build".into());
    }
    let endpoint = cli.endpoint.unwrap();
    let bucket = cli.bucket.unwrap();
    let prefix = cli.prefix.unwrap();
    let state_dir = cli.state_dir.unwrap();
    let output = cli.output.unwrap();
    let server_image_digest = cli.server_image_digest.unwrap();
    let client_image_digest = cli.client_image_digest.unwrap();
    if !validate_image_digest(&server_image_digest) || !validate_image_digest(&client_image_digest)
    {
        return Err("qualification image identities must be immutable sha256 digests".into());
    }
    if output.starts_with(&state_dir) {
        return Err("qualification report must be retained outside the disposable state".into());
    }
    prepare_state_dir(&state_dir)?;

    let config = RemoteBackupConfig::new(&endpoint, &bucket, &prefix, "us-east-1", true)
        .map_err(|error| error.to_string())?;
    if !config.endpoint_origin().starts_with("http://127.0.0.1:")
        && !config.endpoint_origin().starts_with("http://[::1]:")
        && !config.endpoint_origin().starts_with("http://localhost:")
    {
        return Err("qualification endpoint must be explicit loopback HTTP".into());
    }
    let credentials = S3Credentials::from_env().map_err(|error| error.to_string())?;

    let database = state_dir.join("source.sqlite3");
    let manager = SqliteContextManager::new(&database).map_err(|error| error.to_string())?;
    let agent_id = AgentId::new_v4();
    manager
        .kv_put(agent_id, "remote-qualification", "survived")
        .map_err(|error| error.to_string())?;
    let (signer, _) =
        BackupSigningKey::generate("remote-qualification").map_err(|error| error.to_string())?;
    let trust = signer.trust_root();
    let backup_root = state_dir.join("local-backups");
    let manifest = manager
        .create_signed_backup(&backup_root, "source", &signer)
        .map_err(|error| error.to_string())?;
    let backup_dir = backup_root.join("source");
    let anchor = generate_backup_recovery_anchor(
        &backup_dir,
        None,
        &trust,
        &state_dir.join("independent-anchor.json"),
    )
    .map_err(|error| error.to_string())?;

    let retain_until = Utc::now() + chrono::Duration::days(2);
    let publication = publish_remote_backup(
        &backup_dir,
        None,
        &trust,
        &anchor,
        &config,
        &credentials,
        retain_until,
    )
    .await
    .map_err(|error| error.to_string())?;
    let delete_marker_version_ids = qualification_create_delete_markers(&config, &credentials)
        .await
        .map_err(|error| error.to_string())?;
    let fetched_dir = state_dir.join("fetched");
    let recovery = fetch_remote_backup(
        &fetched_dir,
        None,
        &trust,
        &anchor,
        &publication,
        &config,
        &credentials,
    )
    .await
    .map_err(|error| error.to_string())?;

    drop(manager);
    let restored_database = state_dir.join("restored.sqlite3");
    let restore = restore_backup_with_recovery_anchor(
        &fetched_dir,
        &restored_database,
        None,
        &trust,
        &anchor,
    )
    .map_err(|error| error.to_string())?;
    let restored =
        SqliteContextManager::new(&restored_database).map_err(|error| error.to_string())?;
    let restored_value = restored
        .kv_get(agent_id, "remote-qualification")
        .map_err(|error| error.to_string())?;

    let source = source_metadata();
    let mut checks = BTreeMap::new();
    checks.insert("clean_exact_source", source.dirty == Some(false));
    checks.insert(
        "signed_anchor_bound_backup",
        manifest == publication.manifest,
    );
    checks.insert(
        "compliance_retention_reported",
        publication
            .objects
            .iter()
            .all(|object| object.retention_mode == "COMPLIANCE"),
    );
    checks.insert(
        "immutable_version_ids_retained",
        publication
            .objects
            .iter()
            .all(|object| !object.version_id.is_empty() && object.version_id != "null"),
    );
    checks.insert(
        "exact_versions_recovered",
        publication.objects.iter().all(|published| {
            recovery
                .objects
                .iter()
                .any(|recovered| recovered == published)
        }),
    );
    checks.insert(
        "delete_markers_cannot_hide_retained_versions",
        delete_marker_version_ids.len() == 2
            && delete_marker_version_ids
                .iter()
                .all(|version| !version.is_empty() && version != "null"),
    );
    checks.insert(
        "authenticated_restore_completed",
        restore.manifest == manifest,
    );
    checks.insert(
        "restored_enforcement_data_matches",
        restored_value.as_deref() == Some("survived"),
    );
    checks.insert(
        "recovery_metrics_recorded",
        recovery.downloaded_bytes > 0 && recovery.recovery_point_age_seconds < 24 * 60 * 60,
    );
    let passed = checks.values().all(|passed| *passed);
    let report = QualificationReport {
        schema_version: SCHEMA_VERSION,
        suite: "remote-backup-qualification",
        generated_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
        qualification_class: QUALIFICATION_CLASS,
        proof_scope: "disposable_minio_s3_api_compliance_lock_and_exact_version_recovery",
        production_claim_allowed: false,
        build_profile: "release",
        source,
        environment: EnvironmentMetadata {
            os: std::env::consts::OS,
            architecture: std::env::consts::ARCH,
            endpoint_origin: config.endpoint_origin().to_string(),
            bucket,
            server_image_digest,
            client_image_digest,
        },
        publication,
        delete_marker_version_ids,
        recovery,
        checks,
        passed,
        caveats: vec![
            "Disposable MinIO proves S3-compatible protocol behavior, not an independent remote failure domain.",
            "Production qualification still requires retained trust fixtures and a measured operator recovery on the supported remote service.",
            "Deleting the disposable container is cleanup outside the object-store API and is not evidence that COMPLIANCE mode can be bypassed.",
        ],
    };
    let parent = output
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).map_err(|error| format!("create report parent: {error}"))?;
    let mut encoded =
        serde_json::to_vec_pretty(&report).map_err(|error| format!("encode report: {error}"))?;
    encoded.push(b'\n');
    fs::write(&output, encoded).map_err(|error| format!("write report: {error}"))?;
    if !passed {
        return Err("remote backup qualification checks failed".into());
    }
    println!(
        "qualified immutable remote backup publication and exact-version recovery in {} ms",
        report.recovery.recovery_elapsed_ms
    );
    Ok(())
}

#[tokio::main]
async fn main() -> ExitCode {
    let result = match parse_cli() {
        Ok(cli) => execute(cli).await,
        Err(error) => Err(error),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("remote backup qualification failed: {error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn image_digest_validation_is_exact() {
        assert!(validate_image_digest(&format!("sha256:{}", "a".repeat(64))));
        assert!(!validate_image_digest("latest"));
        assert!(!validate_image_digest(&format!(
            "sha256:{}",
            "A".repeat(64)
        )));
        assert!(!validate_image_digest(&format!(
            "sha256:{}",
            "a".repeat(63)
        )));
    }
}
