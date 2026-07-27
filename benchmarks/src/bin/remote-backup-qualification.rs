//! Real S3-compatible object-lock publication and recovery qualification.
//!
//! This suite deliberately keeps `production_claim_allowed` false. Disposable
//! MinIO mode proves protocol behavior. Target-service mode produces exact-RC
//! measurements and replayable public trust fixtures for independent review;
//! it does not review or promote itself.

use std::collections::BTreeMap;
use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use chrono::{SecondsFormat, Utc};
use kernel::context::SqliteContextManager;
use kernel::remote_backup::{
    fetch_remote_backup, publish_remote_backup, qualification_create_delete_markers,
    RemoteBackupConfig, RemoteBackupPublicationReport, RemoteBackupRecoveryReport, S3Credentials,
};
use kernel::storage::{
    generate_backup_recovery_anchor, restore_backup_with_recovery_anchor, BackupRecoveryAnchor,
    BackupSigningKey, BackupTrustRoot,
};
use kernel::AgentId;
use semver::Version;
use serde::Serialize;

const SCHEMA_VERSION: u32 = 1;
const DISPOSABLE_QUALIFICATION_CLASS: &str = "disposable_s3_object_lock_recovery";
const TARGET_QUALIFICATION_CLASS: &str = "target_remote_object_store_recovery";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum QualificationMode {
    DisposableMinio,
    TargetService,
}

impl QualificationMode {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "disposable-minio" => Ok(Self::DisposableMinio),
            "target-service" => Ok(Self::TargetService),
            _ => Err("qualification mode must be disposable-minio or target-service".into()),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::DisposableMinio => "disposable-minio",
            Self::TargetService => "target-service",
        }
    }
}

#[derive(Default)]
struct Cli {
    mode: Option<String>,
    endpoint: Option<String>,
    bucket: Option<String>,
    prefix: Option<String>,
    region: Option<String>,
    state_dir: Option<PathBuf>,
    output: Option<PathBuf>,
    server_image_digest: Option<String>,
    client_image_digest: Option<String>,
    expected_commit: Option<String>,
    release_candidate: Option<String>,
    environment_id: Option<String>,
    service_id: Option<String>,
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
    qualification_mode: &'static str,
    os: &'static str,
    architecture: &'static str,
    endpoint_origin: String,
    bucket: String,
    region: String,
    environment_id: Option<String>,
    service_id: Option<String>,
    server_image_digest: Option<String>,
    client_image_digest: Option<String>,
}

#[derive(Debug, Serialize)]
struct PublicRecoveryFixture {
    trust_root: BackupTrustRoot,
    recovery_anchor: BackupRecoveryAnchor,
}

#[derive(Debug, Serialize)]
struct QualificationReport {
    schema_version: u32,
    suite: &'static str,
    generated_at: String,
    qualification_class: &'static str,
    proof_scope: &'static str,
    release_candidate: Option<String>,
    production_claim_allowed: bool,
    target_remote_recovery_proof_eligible: bool,
    build_profile: &'static str,
    source: SourceMetadata,
    environment: EnvironmentMetadata,
    public_recovery_fixture: PublicRecoveryFixture,
    publication: RemoteBackupPublicationReport,
    delete_marker_version_ids: Vec<String>,
    recovery: RemoteBackupRecoveryReport,
    checks: BTreeMap<&'static str, bool>,
    passed: bool,
    caveats: Vec<&'static str>,
}

fn parse_cli_from(args: impl IntoIterator<Item = String>) -> Result<Cli, String> {
    let mut parsed = Cli::default();
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--mode" => parsed.mode = args.next(),
            "--endpoint" => parsed.endpoint = args.next(),
            "--bucket" => parsed.bucket = args.next(),
            "--prefix" => parsed.prefix = args.next(),
            "--region" => parsed.region = args.next(),
            "--state-dir" => parsed.state_dir = args.next().map(PathBuf::from),
            "--output" => parsed.output = args.next().map(PathBuf::from),
            "--server-image-digest" => parsed.server_image_digest = args.next(),
            "--client-image-digest" => parsed.client_image_digest = args.next(),
            "--expected-commit" => parsed.expected_commit = args.next(),
            "--release-candidate" => parsed.release_candidate = args.next(),
            "--environment-id" => parsed.environment_id = args.next(),
            "--service-id" => parsed.service_id = args.next(),
            "--validate" => parsed.validate_only = true,
            "-h" | "--help" => {
                println!(
                    "remote-backup-qualification --validate | \\\n+                     --mode <disposable-minio|target-service> --endpoint URL \\\n+                     --bucket NAME --prefix PREFIX --region REGION \\\n+                     --state-dir PATH --output PATH \\\n+                     [--server-image-digest sha256:HEX --client-image-digest sha256:HEX] \\\n+                     [--expected-commit SHA --release-candidate vX.Y.Z-rc.N \\\n+                      --environment-id ID --service-id ID]"
                );
                std::process::exit(0);
            }
            other => return Err(format!("unknown argument {other:?}")),
        }
    }
    if parsed.validate_only {
        if parsed.mode.is_some()
            || parsed.endpoint.is_some()
            || parsed.bucket.is_some()
            || parsed.prefix.is_some()
            || parsed.region.is_some()
            || parsed.state_dir.is_some()
            || parsed.output.is_some()
            || parsed.server_image_digest.is_some()
            || parsed.client_image_digest.is_some()
            || parsed.expected_commit.is_some()
            || parsed.release_candidate.is_some()
            || parsed.environment_id.is_some()
            || parsed.service_id.is_some()
        {
            return Err("--validate cannot be combined with execution arguments".into());
        }
        return Ok(parsed);
    }
    if parsed.mode.is_none()
        || parsed.endpoint.is_none()
        || parsed.bucket.is_none()
        || parsed.prefix.is_none()
        || parsed.region.is_none()
        || parsed.state_dir.is_none()
        || parsed.output.is_none()
    {
        return Err("qualification execution requires every common argument".into());
    }
    match QualificationMode::parse(parsed.mode.as_deref().unwrap())? {
        QualificationMode::DisposableMinio => {
            if parsed.server_image_digest.is_none()
                || parsed.client_image_digest.is_none()
                || parsed.expected_commit.is_some()
                || parsed.release_candidate.is_some()
                || parsed.environment_id.is_some()
                || parsed.service_id.is_some()
            {
                return Err(
                    "disposable-minio mode requires both image digests and forbids target arguments"
                        .into(),
                );
            }
        }
        QualificationMode::TargetService => {
            if parsed.server_image_digest.is_some()
                || parsed.client_image_digest.is_some()
                || parsed.expected_commit.is_none()
                || parsed.release_candidate.is_none()
                || parsed.environment_id.is_none()
                || parsed.service_id.is_none()
            {
                return Err(
                    "target-service mode requires exact commit, release candidate, environment, and service identifiers and forbids fixture image digests"
                        .into(),
                );
            }
        }
    }
    Ok(parsed)
}

fn parse_cli() -> Result<Cli, String> {
    parse_cli_from(std::env::args().skip(1))
}

fn validate_image_digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn validate_contract() -> Result<(), String> {
    if SCHEMA_VERSION != 1
        || DISPOSABLE_QUALIFICATION_CLASS != "disposable_s3_object_lock_recovery"
        || TARGET_QUALIFICATION_CLASS != "target_remote_object_store_recovery"
    {
        return Err("remote backup qualification constants are invalid".into());
    }
    Ok(())
}

fn validate_full_commit(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn validate_release_candidate(value: &str) -> bool {
    let Some(value) = value.strip_prefix('v') else {
        return false;
    };
    Version::parse(value).is_ok_and(|version| {
        version.build.is_empty()
            && (version.pre.is_empty()
                || version
                    .pre
                    .as_str()
                    .strip_prefix("rc.")
                    .is_some_and(|number| {
                        !number.is_empty()
                            && !number.starts_with('0')
                            && number.bytes().all(|byte| byte.is_ascii_digit())
                    }))
    })
}

fn validate_stable_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 100
        && !matches!(
            value.to_ascii_lowercase().as_str(),
            "local" | "fixture" | "test" | "dev" | "development"
        )
        && value.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_alphanumeric() || (index > 0 && matches!(byte, b'-' | b'_' | b'.'))
        })
}

fn endpoint_origin_is_loopback(origin: &str) -> bool {
    let Some(authority) = origin
        .strip_prefix("https://")
        .or_else(|| origin.strip_prefix("http://"))
    else {
        return false;
    };
    let host = if let Some(bracketed) = authority.strip_prefix('[') {
        let Some((host, remainder)) = bracketed.split_once(']') else {
            return false;
        };
        if !remainder.is_empty() && !remainder.starts_with(':') {
            return false;
        }
        host
    } else {
        authority
            .split_once(':')
            .map_or(authority, |(host, _)| host)
    };
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<IpAddr>()
            .is_ok_and(|address| address.is_loopback())
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
            "validated remote backup qualification schema v{SCHEMA_VERSION}: \
             {DISPOSABLE_QUALIFICATION_CLASS}, {TARGET_QUALIFICATION_CLASS}"
        );
        return Ok(());
    }
    if cfg!(debug_assertions) {
        return Err("qualification execution requires a --release build".into());
    }
    let mode = QualificationMode::parse(cli.mode.as_deref().unwrap())?;
    let endpoint = cli.endpoint.unwrap();
    let bucket = cli.bucket.unwrap();
    let prefix = cli.prefix.unwrap();
    let region = cli.region.unwrap();
    let state_dir = cli.state_dir.unwrap();
    let output = cli.output.unwrap();
    let expected_commit = cli.expected_commit;
    let release_candidate = cli.release_candidate;
    let environment_id = cli.environment_id;
    let service_id = cli.service_id;
    if mode == QualificationMode::DisposableMinio
        && (!validate_image_digest(cli.server_image_digest.as_deref().unwrap())
            || !validate_image_digest(cli.client_image_digest.as_deref().unwrap()))
    {
        return Err("qualification image identities must be immutable sha256 digests".into());
    }
    if mode == QualificationMode::TargetService {
        if !validate_full_commit(expected_commit.as_deref().unwrap()) {
            return Err("target expected commit must be a full lowercase Git SHA".into());
        }
        if !validate_release_candidate(release_candidate.as_deref().unwrap()) {
            return Err("target release candidate must be vX.Y.Z or vX.Y.Z-rc.N".into());
        }
        if !validate_stable_identifier(environment_id.as_deref().unwrap())
            || !validate_stable_identifier(service_id.as_deref().unwrap())
        {
            return Err(
                "target environment and service identifiers must be stable non-fixture identifiers"
                    .into(),
            );
        }
    }
    let source = source_metadata();
    if mode == QualificationMode::TargetService
        && (source.commit != expected_commit.as_deref().unwrap() || source.dirty != Some(false))
    {
        return Err("target qualification must run from the exact clean requested commit".into());
    }
    if output.starts_with(&state_dir) {
        return Err("qualification report must be retained outside qualification state".into());
    }
    prepare_state_dir(&state_dir)?;

    let config = RemoteBackupConfig::new(
        &endpoint,
        &bucket,
        &prefix,
        &region,
        mode == QualificationMode::DisposableMinio,
    )
    .map_err(|error| error.to_string())?;
    match mode {
        QualificationMode::DisposableMinio => {
            if !config.endpoint_origin().starts_with("http://127.0.0.1:")
                && !config.endpoint_origin().starts_with("http://[::1]:")
                && !config.endpoint_origin().starts_with("http://localhost:")
            {
                return Err("disposable qualification endpoint must be loopback HTTP".into());
            }
        }
        QualificationMode::TargetService => {
            if !config.endpoint_origin().starts_with("https://")
                || endpoint_origin_is_loopback(config.endpoint_origin())
            {
                return Err("target qualification endpoint must be non-loopback HTTPS".into());
            }
        }
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

    let mut checks = BTreeMap::new();
    checks.insert("clean_exact_source", source.dirty == Some(false));
    checks.insert(
        "exact_release_candidate_source",
        mode == QualificationMode::DisposableMinio
            || source.commit == expected_commit.as_deref().unwrap(),
    );
    checks.insert(
        "target_non_loopback_https",
        mode == QualificationMode::DisposableMinio
            || (config.endpoint_origin().starts_with("https://")
                && !endpoint_origin_is_loopback(config.endpoint_origin())),
    );
    checks.insert(
        "target_profile_bound",
        mode == QualificationMode::DisposableMinio
            || (validate_release_candidate(release_candidate.as_deref().unwrap())
                && validate_stable_identifier(environment_id.as_deref().unwrap())
                && validate_stable_identifier(service_id.as_deref().unwrap())),
    );
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
    checks.insert(
        "public_recovery_fixture_retained",
        trust.key_id == anchor.signing_key_id
            && manifest.authenticity.as_ref().is_some_and(|authenticity| {
                authenticity.key_id == trust.key_id
                    && authenticity.public_key_sha256 == anchor.signing_public_key_sha256
            }),
    );
    let passed = checks.values().all(|passed| *passed);
    let target_remote_recovery_proof_eligible = mode == QualificationMode::TargetService && passed;
    let report = QualificationReport {
        schema_version: SCHEMA_VERSION,
        suite: "remote-backup-qualification",
        generated_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
        qualification_class: match mode {
            QualificationMode::DisposableMinio => DISPOSABLE_QUALIFICATION_CLASS,
            QualificationMode::TargetService => TARGET_QUALIFICATION_CLASS,
        },
        proof_scope: match mode {
            QualificationMode::DisposableMinio => {
                "disposable_minio_s3_api_compliance_lock_and_exact_version_recovery"
            }
            QualificationMode::TargetService => {
                "exact_release_candidate_target_service_compliance_lock_and_measured_recovery"
            }
        },
        release_candidate,
        production_claim_allowed: false,
        target_remote_recovery_proof_eligible,
        build_profile: "release",
        source,
        environment: EnvironmentMetadata {
            qualification_mode: mode.as_str(),
            os: std::env::consts::OS,
            architecture: std::env::consts::ARCH,
            endpoint_origin: config.endpoint_origin().to_string(),
            bucket,
            region,
            environment_id,
            service_id,
            server_image_digest: cli.server_image_digest,
            client_image_digest: cli.client_image_digest,
        },
        public_recovery_fixture: PublicRecoveryFixture {
            trust_root: trust,
            recovery_anchor: anchor,
        },
        publication,
        delete_marker_version_ids,
        recovery,
        checks,
        passed,
        caveats: match mode {
            QualificationMode::DisposableMinio => vec![
                "Disposable MinIO proves S3-compatible protocol behavior, not an independent remote failure domain.",
                "Production qualification still requires the protected target-service run and independent evidence review.",
                "Deleting the disposable container is cleanup outside the object-store API and is not evidence that COMPLIANCE mode can be bypassed.",
            ],
            QualificationMode::TargetService => vec![
                "This exact-RC report contains replayable non-secret public trust and recovery-anchor fixtures; private signing keys, storage keys, and object-store credentials are never retained.",
                "target_remote_recovery_proof_eligible means the measured target-service contract passed; production_claim_allowed remains false pending independent review and the remaining durability/release gates.",
                "The dedicated object prefix and its COMPLIANCE-locked versions remain retained until the server-reported dates; lifecycle cleanup must follow the reviewed bucket policy.",
            ],
        },
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

    #[test]
    fn mode_specific_cli_contract_fails_closed() {
        let common = [
            "--endpoint",
            "https://s3.example.test",
            "--bucket",
            "agentos-backups",
            "--prefix",
            "v1/recovery",
            "--region",
            "ca-central-1",
            "--state-dir",
            "target/state",
            "--output",
            "target/report.json",
        ];
        let target = common
            .iter()
            .map(ToString::to_string)
            .chain(
                [
                    "--mode",
                    "target-service",
                    "--expected-commit",
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "--release-candidate",
                    "v1.0.0-rc.1",
                    "--environment-id",
                    "production-ca",
                    "--service-id",
                    "object-store-ca",
                ]
                .iter()
                .map(ToString::to_string),
            )
            .collect::<Vec<_>>();
        let parsed = parse_cli_from(target).unwrap();
        assert_eq!(
            QualificationMode::parse(parsed.mode.as_deref().unwrap()).unwrap(),
            QualificationMode::TargetService
        );

        let disposable = common
            .iter()
            .map(ToString::to_string)
            .chain(
                [
                    "--mode",
                    "disposable-minio",
                    "--server-image-digest",
                    &format!("sha256:{}", "a".repeat(64)),
                    "--client-image-digest",
                    &format!("sha256:{}", "b".repeat(64)),
                ]
                .iter()
                .map(ToString::to_string),
            )
            .collect::<Vec<_>>();
        assert!(parse_cli_from(disposable).is_ok());

        let mut mixed = common
            .iter()
            .map(ToString::to_string)
            .chain(
                [
                    "--mode",
                    "target-service",
                    "--expected-commit",
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "--release-candidate",
                    "v1.0.0-rc.1",
                    "--environment-id",
                    "production-ca",
                    "--service-id",
                    "object-store-ca",
                    "--server-image-digest",
                    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                ]
                .iter()
                .map(ToString::to_string),
            )
            .collect::<Vec<_>>();
        assert!(parse_cli_from(mixed.clone()).is_err());
        mixed[1] = "invented-mode".into();
        assert!(parse_cli_from(mixed).is_err());
    }

    #[test]
    fn target_identity_contract_is_strict() {
        assert!(validate_full_commit(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        ));
        assert!(!validate_full_commit(
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        ));
        assert!(validate_release_candidate("v1.0.0"));
        assert!(validate_release_candidate("v1.0.0-rc.1"));
        assert!(!validate_release_candidate("main"));
        assert!(!validate_release_candidate("v1.0.0-rc.0"));
        assert!(!validate_release_candidate("v1.0.0-beta.1"));
        assert!(validate_stable_identifier("production-ca"));
        assert!(!validate_stable_identifier("fixture"));
        assert!(!validate_stable_identifier("../unsafe"));
    }

    #[test]
    fn target_endpoint_loopback_detection_is_strict() {
        assert!(endpoint_origin_is_loopback("https://localhost"));
        assert!(endpoint_origin_is_loopback("https://localhost:443"));
        assert!(endpoint_origin_is_loopback("https://127.0.0.1:9000"));
        assert!(endpoint_origin_is_loopback("https://[::1]:9000"));
        assert!(!endpoint_origin_is_loopback(
            "https://object-store.example.test"
        ));
        assert!(!endpoint_origin_is_loopback(
            "https://object-store.example.test:9443"
        ));
        assert!(!endpoint_origin_is_loopback(
            "https://127.0.0.1.example.test"
        ));
    }
}
