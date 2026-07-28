//! Small operator CLI for the public agent lifecycle API.

use std::io::{Read, Write};
use std::time::Duration;

use agent_cli::OperatorClient;
use agent_sdk::ConnectionProfile;

fn usage() -> ! {
    eprintln!(
        "usage: agentctl [--addr HOST:PORT] [--token TOKEN] \
         <create|list|inspect|message|stream|cancel|checkpoints|checkpoint-resume|checkpoint-delete|capabilities|providers|metrics|protocol|package-trust-key|package-revoke-key|package-publish|package-yank|package-fetch|package-search|package-install|package-rollback|package-remove|packages|package-run|pressure|tunables|tunable-set|tunable-rollback|tunable-history|status|pause|resume|stop|kill|wait|services|service-start|service-stop|service-restart|service-reload|service-history|backup-create|backup-retention|backup-status|data-inventory|backup-key-generate|backup-anchor-create|backup-verify|backup-restore|backup-disaster-recover|backup-corruption-recover|backup-remote-publish|backup-remote-fetch|storage-key-generate|storage-encrypt|storage-encrypt-recover|storage-key-rotate|storage-portable-export|storage-portable-verify|storage-portable-import|erase-agent|erase-user|erase-tenant> [ARGS...]\n\
         \n\
         public runtime commands:\n\
           agentctl [SERVER OPTIONS] create NAME TASK [PROVIDER [PROFILE [PRIORITY]]]\n\
           agentctl [SERVER OPTIONS] message AGENT_ID MESSAGE\n\
           agentctl [SERVER OPTIONS] stream REQUEST_ID AGENT_ID MESSAGE\n\
           agentctl [SERVER OPTIONS] cancel REQUEST_ID AGENT_ID\n\
           agentctl [SERVER OPTIONS] checkpoints AGENT_ID\n\
           agentctl [SERVER OPTIONS] checkpoint-resume AGENT_ID CHECKPOINT_ID\n\
           agentctl [SERVER OPTIONS] checkpoint-delete AGENT_ID CHECKPOINT_ID\n\
           agentctl [SERVER OPTIONS] capabilities AGENT_ID\n\
           agentctl [SERVER OPTIONS] providers\n\
           agentctl [SERVER OPTIONS] metrics\n\
           agentctl [SERVER OPTIONS] protocol\n\
         \n\
         signed package commands:\n\
           agentctl [SERVER OPTIONS] package-trust-key PUBLISHER KEY_ID PUBLIC_KEY_FILE VALID_FROM [--valid-until RFC3339] [--supersedes KEY_ID]\n\
           agentctl [SERVER OPTIONS] package-revoke-key KEY_ID --confirm KEY_ID\n\
           agentctl [SERVER OPTIONS] package-publish ARCHIVE_FILE\n\
           agentctl [SERVER OPTIONS] package-yank NAME VERSION --confirm NAME@VERSION\n\
           agentctl [SERVER OPTIONS] package-fetch NAME VERSION OUTPUT_FILE\n\
           agentctl [SERVER OPTIONS] package-search QUERY\n\
           agentctl [SERVER OPTIONS] package-install NAME [REQUIREMENT]\n\
           agentctl [SERVER OPTIONS] package-rollback NAME --confirm NAME\n\
           agentctl [SERVER OPTIONS] package-remove NAME --confirm NAME\n\
           agentctl [SERVER OPTIONS] packages\n\
           agentctl [SERVER OPTIONS] package-run NAME\n\
         \n\
         storage commands:\n\
           agentctl [SERVER OPTIONS] backup-create BACKUP_ROOT NAME\n\
           agentctl [SERVER OPTIONS] backup-retention BACKUP_ROOT KEEP_LATEST MAX_AGE_SECONDS <--dry-run|--confirm>\n\
           agentctl [SERVER OPTIONS] backup-status\n\
           agentctl [SERVER OPTIONS] data-inventory\n\
           agentctl backup-key-generate KEY_ID PRIVATE_KEY_FILE PUBLIC_TRUST_FILE\n\
           agentctl backup-anchor-create BACKUP_DIR PUBLIC_TRUST_FILE ANCHOR_FILE [--storage-key KEY_FILE]\n\
           agentctl backup-verify BACKUP_DIR [--storage-key KEY_FILE] [--require-signature PUBLIC_TRUST_FILE] [--require-anchor ANCHOR_FILE]\n\
           agentctl backup-restore BACKUP_DIR DATABASE [--storage-key KEY_FILE] [--require-signature PUBLIC_TRUST_FILE] [--require-anchor ANCHOR_FILE] --confirm-offline\n\
           agentctl backup-disaster-recover BACKUP_DIR CONFIG_FILE PUBLIC_TRUST_FILE ANCHOR_FILE --confirm-offline\n\
           agentctl backup-corruption-recover BACKUP_DIR CONFIG_FILE PUBLIC_TRUST_FILE ANCHOR_FILE EXPECTED_INSTALLATION_ID --confirm-offline\n\
           agentctl backup-remote-publish BACKUP_DIR PUBLIC_TRUST_FILE ANCHOR_FILE ENDPOINT BUCKET PREFIX RETAIN_UNTIL [--region REGION] [--storage-key KEY_FILE] [--allow-loopback-http] --confirm-compliance-lock\n\
           agentctl backup-remote-fetch ENDPOINT BUCKET PREFIX PUBLICATION_REPORT DEST_BACKUP_DIR PUBLIC_TRUST_FILE ANCHOR_FILE [--region REGION] [--storage-key KEY_FILE] [--allow-loopback-http]\n\
           agentctl storage-key-generate KEY_ID KEY_FILE\n\
           agentctl storage-encrypt DATABASE KEY_FILE --confirm-offline\n\
           agentctl storage-encrypt-recover DATABASE KEY_FILE --confirm-offline\n\
           agentctl storage-key-rotate DATABASE CURRENT_KEY_FILE NEXT_KEY_FILE --confirm-offline\n\
           agentctl storage-portable-export DATABASE BUNDLE_DIR [--storage-key KEY_FILE] --confirm-offline\n\
           agentctl storage-portable-verify BUNDLE_DIR\n\
           agentctl storage-portable-import BUNDLE_DIR DATABASE [--storage-key KEY_FILE] --confirm-offline\n\
           agentctl [SERVER OPTIONS] kill AGENT_ID --confirm AGENT_ID\n\
           agentctl [SERVER OPTIONS] erase-agent AGENT_ID --confirm AGENT_ID\n\
           agentctl [SERVER OPTIONS] erase-user USER_ID --confirm USER_ID\n\
           agentctl [SERVER OPTIONS] erase-tenant TENANT_ID --confirm TENANT_ID"
    );
    std::process::exit(2);
}

#[derive(Default)]
struct BackupFileOptions {
    storage_key: Option<String>,
    trust_root: Option<String>,
    recovery_anchor: Option<String>,
    confirmed_offline: bool,
}

struct RemoteBackupOptions {
    region: String,
    storage_key: Option<String>,
    allow_loopback_http: bool,
    confirmed_compliance_lock: bool,
}

#[derive(Default)]
struct PackageTrustOptions {
    valid_until: Option<String>,
    supersedes: Option<String>,
}

fn parse_package_trust_options(values: impl IntoIterator<Item = String>) -> PackageTrustOptions {
    let mut values = values.into_iter();
    let mut parsed = PackageTrustOptions::default();
    while let Some(value) = values.next() {
        match value.as_str() {
            "--valid-until" if parsed.valid_until.is_none() => {
                parsed.valid_until = Some(values.next().unwrap_or_else(|| usage()));
            }
            "--supersedes" if parsed.supersedes.is_none() => {
                parsed.supersedes = Some(values.next().unwrap_or_else(|| usage()));
            }
            _ => usage(),
        }
    }
    parsed
}

impl Default for RemoteBackupOptions {
    fn default() -> Self {
        Self {
            region: std::env::var("AWS_REGION")
                .or_else(|_| std::env::var("AWS_DEFAULT_REGION"))
                .unwrap_or_else(|_| "us-east-1".into()),
            storage_key: None,
            allow_loopback_http: false,
            confirmed_compliance_lock: false,
        }
    }
}

fn parse_remote_backup_options(
    values: impl IntoIterator<Item = String>,
    compliance_confirmation_required: bool,
) -> RemoteBackupOptions {
    let mut values = values.into_iter();
    let mut parsed = RemoteBackupOptions::default();
    let mut region_set = false;
    while let Some(value) = values.next() {
        match value.as_str() {
            "--region" if !region_set => {
                parsed.region = values.next().unwrap_or_else(|| usage());
                region_set = true;
            }
            "--storage-key" if parsed.storage_key.is_none() => {
                parsed.storage_key = Some(values.next().unwrap_or_else(|| usage()));
            }
            "--allow-loopback-http" if !parsed.allow_loopback_http => {
                parsed.allow_loopback_http = true;
            }
            "--confirm-compliance-lock"
                if compliance_confirmation_required && !parsed.confirmed_compliance_lock =>
            {
                parsed.confirmed_compliance_lock = true;
            }
            _ => usage(),
        }
    }
    if compliance_confirmation_required && !parsed.confirmed_compliance_lock {
        usage();
    }
    parsed
}

fn parse_backup_file_options(
    values: impl IntoIterator<Item = String>,
    confirmation_required: bool,
) -> BackupFileOptions {
    let mut values = values.into_iter();
    let mut parsed = BackupFileOptions::default();
    while let Some(value) = values.next() {
        match value.as_str() {
            "--storage-key" if parsed.storage_key.is_none() => {
                parsed.storage_key = Some(values.next().unwrap_or_else(|| usage()));
            }
            "--require-signature" if parsed.trust_root.is_none() => {
                parsed.trust_root = Some(values.next().unwrap_or_else(|| usage()));
            }
            "--require-anchor" if parsed.recovery_anchor.is_none() => {
                parsed.recovery_anchor = Some(values.next().unwrap_or_else(|| usage()));
            }
            "--confirm-offline" if confirmation_required && !parsed.confirmed_offline => {
                parsed.confirmed_offline = true;
            }
            _ => usage(),
        }
    }
    if confirmation_required && !parsed.confirmed_offline {
        usage();
    }
    parsed
}

fn parse_portable_file_options(
    values: impl IntoIterator<Item = String>,
    confirmation_required: bool,
) -> BackupFileOptions {
    let mut values = values.into_iter();
    let mut parsed = BackupFileOptions::default();
    while let Some(value) = values.next() {
        match value.as_str() {
            "--storage-key" if parsed.storage_key.is_none() => {
                parsed.storage_key = Some(values.next().unwrap_or_else(|| usage()));
            }
            "--confirm-offline" if confirmation_required && !parsed.confirmed_offline => {
                parsed.confirmed_offline = true;
            }
            _ => usage(),
        }
    }
    if confirmation_required && !parsed.confirmed_offline {
        usage();
    }
    parsed
}

#[tokio::main]
async fn main() {
    let mut args = std::env::args().skip(1).peekable();
    let mut profile = ConnectionProfile::from_env().unwrap_or_else(|error| {
        eprintln!("agentctl: {error}");
        std::process::exit(2);
    });
    let mut token = std::env::var("AGENT_SERVER_TOKEN").ok();

    while matches!(args.peek().map(String::as_str), Some("--addr" | "--token")) {
        match args.next().as_deref() {
            Some("--addr") => profile.address = args.next().unwrap_or_else(|| usage()),
            Some("--token") => token = Some(args.next().unwrap_or_else(|| usage())),
            _ => unreachable!(),
        }
    }

    let command = args.next().unwrap_or_else(|| usage());

    // Verification and restore operate directly on local files. Restore must
    // remain offline: the storage lease rejects replacement while a kernel
    // owns the destination database.
    match command.as_str() {
        "backup-key-generate" => {
            let key_id = args.next().unwrap_or_else(|| usage());
            let private_key = args.next().unwrap_or_else(|| usage());
            let public_trust = args.next().unwrap_or_else(|| usage());
            if args.next().is_some() {
                usage();
            }
            let trust = kernel::storage::generate_backup_signing_key_files(
                &key_id,
                std::path::Path::new(&private_key),
                std::path::Path::new(&public_trust),
            )
            .unwrap_or_else(|error| fail_storage(error));
            print_json(&trust, "backup trust root");
            return;
        }
        "backup-anchor-create" => {
            let backup_dir = args.next().unwrap_or_else(|| usage());
            let public_trust = args.next().unwrap_or_else(|| usage());
            let anchor_file = args.next().unwrap_or_else(|| usage());
            let options = parse_portable_file_options(args.collect::<Vec<_>>(), false);
            let storage_key = options.storage_key.as_deref().map(|path| {
                kernel::storage_encryption::load_storage_encryption_key(std::path::Path::new(path))
                    .unwrap_or_else(|error| fail_storage(error))
            });
            let trust =
                kernel::storage::load_backup_trust_root(std::path::Path::new(&public_trust))
                    .unwrap_or_else(|error| fail_storage(error));
            let anchor = kernel::storage::generate_backup_recovery_anchor(
                std::path::Path::new(&backup_dir),
                storage_key.as_ref(),
                &trust,
                std::path::Path::new(&anchor_file),
            )
            .unwrap_or_else(|error| fail_storage(error));
            print_json(&anchor, "backup recovery anchor");
            return;
        }
        "backup-verify" => {
            let backup_dir = args.next().unwrap_or_else(|| usage());
            let options = parse_backup_file_options(args.collect::<Vec<_>>(), false);
            let storage_key = options.storage_key.as_deref().map(|path| {
                kernel::storage_encryption::load_storage_encryption_key(std::path::Path::new(path))
                    .unwrap_or_else(|error| fail_storage(error))
            });
            let trust = options.trust_root.as_deref().map(|path| {
                kernel::storage::load_backup_trust_root(std::path::Path::new(path))
                    .unwrap_or_else(|error| fail_storage(error))
            });
            let anchor = options.recovery_anchor.as_deref().map(|path| {
                kernel::storage::load_independent_backup_recovery_anchor(
                    std::path::Path::new(&backup_dir),
                    std::path::Path::new(path),
                )
                .unwrap_or_else(|error| fail_storage(error))
            });
            if anchor.is_some() && trust.is_none() {
                fail_operator("--require-anchor also requires --require-signature".into());
            }
            if let (Some(trust), Some(anchor)) = (trust.as_ref(), anchor.as_ref()) {
                let manifest = kernel::storage::verify_backup_with_recovery_anchor(
                    std::path::Path::new(&backup_dir),
                    storage_key.as_ref(),
                    trust,
                    anchor,
                )
                .unwrap_or_else(|error| fail_storage(error));
                print_json(&manifest, "backup manifest");
                return;
            }
            let manifest = match (storage_key.as_ref(), trust.as_ref()) {
                (None, None) => kernel::storage::verify_backup(std::path::Path::new(&backup_dir)),
                (None, Some(trust)) => kernel::storage::verify_backup_authenticity(
                    std::path::Path::new(&backup_dir),
                    trust,
                ),
                (Some(key), None) => kernel::storage::verify_backup_with_storage_key(
                    std::path::Path::new(&backup_dir),
                    key,
                ),
                (Some(key), Some(trust)) => {
                    kernel::storage::verify_backup_with_storage_key_and_trust(
                        std::path::Path::new(&backup_dir),
                        key,
                        trust,
                    )
                }
            }
            .unwrap_or_else(|error| fail_storage(error));
            print_json(&manifest, "backup manifest");
            return;
        }
        "backup-restore" => {
            let backup_dir = args.next().unwrap_or_else(|| usage());
            let database = args.next().unwrap_or_else(|| usage());
            let options = parse_backup_file_options(args.collect::<Vec<_>>(), true);
            let storage_key = options.storage_key.as_deref().map(|path| {
                kernel::storage_encryption::load_storage_encryption_key(std::path::Path::new(path))
                    .unwrap_or_else(|error| fail_storage(error))
            });
            let trust = options.trust_root.as_deref().map(|path| {
                kernel::storage::load_backup_trust_root(std::path::Path::new(path))
                    .unwrap_or_else(|error| fail_storage(error))
            });
            let anchor = options.recovery_anchor.as_deref().map(|path| {
                kernel::storage::load_independent_backup_recovery_anchor(
                    std::path::Path::new(&backup_dir),
                    std::path::Path::new(path),
                )
                .unwrap_or_else(|error| fail_storage(error))
            });
            if anchor.is_some() && trust.is_none() {
                fail_operator("--require-anchor also requires --require-signature".into());
            }
            if let (Some(trust), Some(anchor)) = (trust.as_ref(), anchor.as_ref()) {
                let report = kernel::storage::restore_backup_with_recovery_anchor(
                    std::path::Path::new(&backup_dir),
                    std::path::Path::new(&database),
                    storage_key.as_ref(),
                    trust,
                    anchor,
                )
                .unwrap_or_else(|error| fail_storage(error));
                print_json(&report, "restore report");
                return;
            }
            let report = match (storage_key.as_ref(), trust.as_ref()) {
                (None, None) => kernel::storage::restore_backup(
                    std::path::Path::new(&backup_dir),
                    std::path::Path::new(&database),
                ),
                (None, Some(trust)) => kernel::storage::restore_backup_with_trust(
                    std::path::Path::new(&backup_dir),
                    std::path::Path::new(&database),
                    trust,
                ),
                (Some(key), None) => kernel::storage::restore_backup_with_storage_key(
                    std::path::Path::new(&backup_dir),
                    std::path::Path::new(&database),
                    key,
                ),
                (Some(key), Some(trust)) => {
                    kernel::storage::restore_backup_with_storage_key_and_trust(
                        std::path::Path::new(&backup_dir),
                        std::path::Path::new(&database),
                        key,
                        trust,
                    )
                }
            }
            .unwrap_or_else(|error| fail_storage(error));
            print_json(&report, "restore report");
            return;
        }
        "backup-disaster-recover" => {
            let backup_dir = args.next().unwrap_or_else(|| usage());
            let config_file = args.next().unwrap_or_else(|| usage());
            let public_trust = args.next().unwrap_or_else(|| usage());
            let anchor_file = args.next().unwrap_or_else(|| usage());
            if args.next().as_deref() != Some("--confirm-offline") || args.next().is_some() {
                usage();
            }
            let config_path = std::path::Path::new(&config_file);
            let metadata = std::fs::symlink_metadata(config_path).unwrap_or_else(|error| {
                fail_operator(format!(
                    "failed to inspect recovery configuration {config_file}: {error}"
                ))
            });
            if !metadata.is_file() {
                fail_operator(format!(
                    "recovery configuration {config_file} must be an existing file"
                ));
            }
            let config =
                kernel::config::Config::try_load_from(config_path).unwrap_or_else(|error| {
                    fail_operator(format!("failed to load recovery configuration: {error}"))
                });
            let trust =
                kernel::storage::load_backup_trust_root(std::path::Path::new(&public_trust))
                    .unwrap_or_else(|error| fail_storage(error));
            let anchor = kernel::storage::load_independent_backup_recovery_anchor(
                std::path::Path::new(&backup_dir),
                std::path::Path::new(&anchor_file),
            )
            .unwrap_or_else(|error| fail_storage(error));
            let report = kernel::storage::recover_backup_from_config_with_anchor(
                std::path::Path::new(&backup_dir),
                &config,
                &trust,
                &anchor,
            )
            .unwrap_or_else(|error| fail_storage(error));
            print_json(&report, "disaster recovery report");
            return;
        }
        "backup-corruption-recover" => {
            let backup_dir = args.next().unwrap_or_else(|| usage());
            let config_file = args.next().unwrap_or_else(|| usage());
            let public_trust = args.next().unwrap_or_else(|| usage());
            let anchor_file = args.next().unwrap_or_else(|| usage());
            let expected_installation_id = args.next().unwrap_or_else(|| usage());
            if args.next().as_deref() != Some("--confirm-offline") || args.next().is_some() {
                usage();
            }
            let config_path = std::path::Path::new(&config_file);
            let metadata = std::fs::symlink_metadata(config_path).unwrap_or_else(|error| {
                fail_operator(format!(
                    "failed to inspect recovery configuration {config_file}: {error}"
                ))
            });
            if !metadata.is_file() {
                fail_operator(format!(
                    "recovery configuration {config_file} must be an existing file"
                ));
            }
            let config =
                kernel::config::Config::try_load_from(config_path).unwrap_or_else(|error| {
                    fail_operator(format!("failed to load recovery configuration: {error}"))
                });
            let trust =
                kernel::storage::load_backup_trust_root(std::path::Path::new(&public_trust))
                    .unwrap_or_else(|error| fail_storage(error));
            let anchor = kernel::storage::load_independent_backup_recovery_anchor(
                std::path::Path::new(&backup_dir),
                std::path::Path::new(&anchor_file),
            )
            .unwrap_or_else(|error| fail_storage(error));
            let report = kernel::storage::recover_corrupt_storage_from_config_with_anchor(
                std::path::Path::new(&backup_dir),
                &config,
                &trust,
                &anchor,
                &expected_installation_id,
            )
            .unwrap_or_else(|error| fail_storage(error));
            print_json(&report, "corrupt storage recovery report");
            return;
        }
        "backup-remote-publish" => {
            let backup_dir = args.next().unwrap_or_else(|| usage());
            let public_trust = args.next().unwrap_or_else(|| usage());
            let anchor_file = args.next().unwrap_or_else(|| usage());
            let endpoint = args.next().unwrap_or_else(|| usage());
            let bucket = args.next().unwrap_or_else(|| usage());
            let prefix = args.next().unwrap_or_else(|| usage());
            let retain_until = args.next().unwrap_or_else(|| usage());
            let options = parse_remote_backup_options(args.collect::<Vec<_>>(), true);
            let retain_until = chrono::DateTime::parse_from_rfc3339(&retain_until)
                .map(|value| value.with_timezone(&chrono::Utc))
                .unwrap_or_else(|error| {
                    fail_operator(format!(
                        "RETAIN_UNTIL must be an RFC3339 timestamp: {error}"
                    ))
                });
            let storage_key = options.storage_key.as_deref().map(|path| {
                kernel::storage_encryption::load_storage_encryption_key(std::path::Path::new(path))
                    .unwrap_or_else(|error| fail_storage(error))
            });
            let trust =
                kernel::storage::load_backup_trust_root(std::path::Path::new(&public_trust))
                    .unwrap_or_else(|error| fail_storage(error));
            let anchor = kernel::storage::load_independent_backup_recovery_anchor(
                std::path::Path::new(&backup_dir),
                std::path::Path::new(&anchor_file),
            )
            .unwrap_or_else(|error| fail_storage(error));
            let config = kernel::remote_backup::RemoteBackupConfig::new(
                &endpoint,
                &bucket,
                &prefix,
                &options.region,
                options.allow_loopback_http,
            )
            .unwrap_or_else(|error| fail_storage(error));
            let credentials = kernel::remote_backup::S3Credentials::from_env()
                .unwrap_or_else(|error| fail_storage(error));
            let report = kernel::remote_backup::publish_remote_backup(
                std::path::Path::new(&backup_dir),
                storage_key.as_ref(),
                &trust,
                &anchor,
                &config,
                &credentials,
                retain_until,
            )
            .await
            .unwrap_or_else(|error| fail_storage(error));
            print_json(&report, "remote backup publication report");
            return;
        }
        "backup-remote-fetch" => {
            let endpoint = args.next().unwrap_or_else(|| usage());
            let bucket = args.next().unwrap_or_else(|| usage());
            let prefix = args.next().unwrap_or_else(|| usage());
            let publication_report = args.next().unwrap_or_else(|| usage());
            let destination = args.next().unwrap_or_else(|| usage());
            let public_trust = args.next().unwrap_or_else(|| usage());
            let anchor_file = args.next().unwrap_or_else(|| usage());
            let options = parse_remote_backup_options(args.collect::<Vec<_>>(), false);
            let storage_key = options.storage_key.as_deref().map(|path| {
                kernel::storage_encryption::load_storage_encryption_key(std::path::Path::new(path))
                    .unwrap_or_else(|error| fail_storage(error))
            });
            let trust =
                kernel::storage::load_backup_trust_root(std::path::Path::new(&public_trust))
                    .unwrap_or_else(|error| fail_storage(error));
            let anchor =
                kernel::storage::load_backup_recovery_anchor(std::path::Path::new(&anchor_file))
                    .unwrap_or_else(|error| fail_storage(error));
            let publication = kernel::remote_backup::load_remote_backup_publication_report(
                std::path::Path::new(&publication_report),
            )
            .unwrap_or_else(|error| fail_storage(error));
            let config = kernel::remote_backup::RemoteBackupConfig::new(
                &endpoint,
                &bucket,
                &prefix,
                &options.region,
                options.allow_loopback_http,
            )
            .unwrap_or_else(|error| fail_storage(error));
            let credentials = kernel::remote_backup::S3Credentials::from_env()
                .unwrap_or_else(|error| fail_storage(error));
            let report = kernel::remote_backup::fetch_remote_backup(
                std::path::Path::new(&destination),
                storage_key.as_ref(),
                &trust,
                &anchor,
                &publication,
                &config,
                &credentials,
            )
            .await
            .unwrap_or_else(|error| fail_storage(error));
            print_json(&report, "remote backup recovery report");
            return;
        }
        "storage-portable-export" => {
            let database = args.next().unwrap_or_else(|| usage());
            let bundle_dir = args.next().unwrap_or_else(|| usage());
            let options = parse_portable_file_options(args.collect::<Vec<_>>(), true);
            let storage_key = options.storage_key.as_deref().map(|path| {
                kernel::storage_encryption::load_storage_encryption_key(std::path::Path::new(path))
                    .unwrap_or_else(|error| fail_storage(error))
            });
            let report = kernel::storage::export_portable_storage(
                std::path::Path::new(&database),
                std::path::Path::new(&bundle_dir),
                storage_key.as_ref(),
            )
            .unwrap_or_else(|error| fail_storage(error));
            print_json(&report, "portable storage export report");
            return;
        }
        "storage-portable-verify" => {
            let bundle_dir = args.next().unwrap_or_else(|| usage());
            if args.next().is_some() {
                usage();
            }
            let manifest =
                kernel::storage::verify_portable_storage(std::path::Path::new(&bundle_dir))
                    .unwrap_or_else(|error| fail_storage(error));
            print_json(&manifest, "portable storage manifest");
            return;
        }
        "storage-portable-import" => {
            let bundle_dir = args.next().unwrap_or_else(|| usage());
            let database = args.next().unwrap_or_else(|| usage());
            let options = parse_portable_file_options(args.collect::<Vec<_>>(), true);
            let storage_key = options.storage_key.as_deref().map(|path| {
                kernel::storage_encryption::load_storage_encryption_key(std::path::Path::new(path))
                    .unwrap_or_else(|error| fail_storage(error))
            });
            let report = kernel::storage::import_portable_storage(
                std::path::Path::new(&bundle_dir),
                std::path::Path::new(&database),
                storage_key.as_ref(),
            )
            .unwrap_or_else(|error| fail_storage(error));
            print_json(&report, "portable storage import report");
            return;
        }
        "storage-key-generate" => {
            let key_id = args.next().unwrap_or_else(|| usage());
            let key_file = args.next().unwrap_or_else(|| usage());
            if args.next().is_some() {
                usage();
            }
            kernel::storage_encryption::generate_storage_encryption_key_file(
                &key_id,
                std::path::Path::new(&key_file),
            )
            .unwrap_or_else(|error| fail_storage(error));
            print_json(
                &serde_json::json!({"key_id": key_id, "key_file": key_file}),
                "storage key",
            );
            return;
        }
        "storage-encrypt" => {
            let database = args.next().unwrap_or_else(|| usage());
            let key_file = args.next().unwrap_or_else(|| usage());
            if args.next().as_deref() != Some("--confirm-offline") || args.next().is_some() {
                usage();
            }
            let key = kernel::storage_encryption::load_storage_encryption_key(
                std::path::Path::new(&key_file),
            )
            .unwrap_or_else(|error| fail_storage(error));
            let report = kernel::storage_encryption::encrypt_existing_database(
                std::path::Path::new(&database),
                &key,
            )
            .unwrap_or_else(|error| fail_storage(error));
            print_json(&report, "storage encryption migration report");
            return;
        }
        "storage-encrypt-recover" => {
            let database = args.next().unwrap_or_else(|| usage());
            let key_file = args.next().unwrap_or_else(|| usage());
            if args.next().as_deref() != Some("--confirm-offline") || args.next().is_some() {
                usage();
            }
            let key = kernel::storage_encryption::load_storage_encryption_key(
                std::path::Path::new(&key_file),
            )
            .unwrap_or_else(|error| fail_storage(error));
            let report = kernel::storage_encryption::recover_interrupted_encryption_migration(
                std::path::Path::new(&database),
                &key,
            )
            .unwrap_or_else(|error| fail_storage(error));
            print_json(&report, "storage encryption recovery report");
            return;
        }
        "storage-key-rotate" => {
            let database = args.next().unwrap_or_else(|| usage());
            let current_key_file = args.next().unwrap_or_else(|| usage());
            let next_key_file = args.next().unwrap_or_else(|| usage());
            if args.next().as_deref() != Some("--confirm-offline") || args.next().is_some() {
                usage();
            }
            let current_key = kernel::storage_encryption::load_storage_encryption_key(
                std::path::Path::new(&current_key_file),
            )
            .unwrap_or_else(|error| fail_storage(error));
            let next_key = kernel::storage_encryption::load_storage_encryption_key(
                std::path::Path::new(&next_key_file),
            )
            .unwrap_or_else(|error| fail_storage(error));
            let report = kernel::storage_encryption::rotate_database_encryption_key(
                std::path::Path::new(&database),
                &current_key,
                &next_key,
            )
            .unwrap_or_else(|error| fail_storage(error));
            print_json(&report, "storage key rotation report");
            return;
        }
        _ => {}
    }

    let mut client = OperatorClient::connect_profile(&profile, token.as_deref())
        .await
        .unwrap_or_else(|error| {
            eprintln!(
                "agentctl: could not connect to {}: {error}",
                profile.address
            );
            std::process::exit(1);
        });

    let result = match command.as_str() {
        "create" => {
            let name = args.next().unwrap_or_else(|| usage());
            let task = args.next().unwrap_or_else(|| usage());
            let provider = args.next();
            let profile = args.next();
            let priority = args
                .next()
                .map(|value| value.parse::<u8>().unwrap_or_else(|_| usage()));
            if args.next().is_some() {
                usage();
            }
            let id = client
                .create_agent(name, task, provider, profile, priority)
                .await
                .unwrap_or_else(|error| fail(error));
            print_json(&serde_json::json!({ "id": id }), "created agent");
            return;
        }
        "list" => {
            if args.next().is_some() {
                usage();
            }
            let agents = client
                .list_agents()
                .await
                .unwrap_or_else(|error| fail(error));
            for agent in agents {
                println!("{}\t{}\t{}", agent.id, agent.state, agent.name);
            }
            return;
        }
        "inspect" => {
            let snapshot = client
                .operator_snapshot()
                .await
                .unwrap_or_else(|error| fail(error));
            println!(
                "{}",
                serde_json::to_string_pretty(&snapshot).unwrap_or_else(|error| {
                    fail(agent_sdk::SdkError::Kernel(format!(
                        "snapshot encoding failed: {error}"
                    )))
                })
            );
            return;
        }
        "message" => {
            let agent_id = args.next().unwrap_or_else(|| usage());
            let message = args.next().unwrap_or_else(|| usage());
            if args.next().is_some() {
                usage();
            }
            let result = client
                .send_message(agent_id, message)
                .await
                .unwrap_or_else(|error| fail(error));
            print_json(&result, "message result");
            return;
        }
        "stream" => {
            let request_id = args.next().unwrap_or_else(|| usage());
            let agent_id = args.next().unwrap_or_else(|| usage());
            let message = args.next().unwrap_or_else(|| usage());
            if args.next().is_some() {
                usage();
            }
            let result = client
                .send_message_stream(request_id.clone(), agent_id, message, |event| {
                    println!(
                        "{}",
                        serde_json::json!({
                            "type": "event",
                            "request_id": request_id,
                            "event": event,
                        })
                    );
                    let _ = std::io::stdout().flush();
                })
                .await
                .unwrap_or_else(|error| fail(error));
            println!(
                "{}",
                serde_json::json!({
                    "type": "completed",
                    "request_id": request_id,
                    "result": result,
                })
            );
            return;
        }
        "cancel" => {
            let request_id = args.next().unwrap_or_else(|| usage());
            let agent_id = args.next().unwrap_or_else(|| usage());
            if args.next().is_some() {
                usage();
            }
            let accepted = client
                .cancel_request(request_id.clone(), agent_id)
                .await
                .unwrap_or_else(|error| fail(error));
            print_json(
                &serde_json::json!({
                    "request_id": request_id,
                    "accepted": accepted,
                }),
                "cancellation result",
            );
            return;
        }
        "checkpoints" => {
            let agent_id = args.next().unwrap_or_else(|| usage());
            if args.next().is_some() {
                usage();
            }
            let checkpoints = client
                .list_generation_checkpoints(agent_id)
                .await
                .unwrap_or_else(|error| fail(error));
            print_json(&checkpoints, "generation checkpoints");
            return;
        }
        "checkpoint-resume" => {
            let agent_id = args.next().unwrap_or_else(|| usage());
            let checkpoint_id = args.next().unwrap_or_else(|| usage());
            if args.next().is_some() {
                usage();
            }
            let result = client
                .resume_generation_checkpoint(agent_id, checkpoint_id)
                .await
                .unwrap_or_else(|error| fail(error));
            print_json(&result, "checkpoint resume result");
            return;
        }
        "checkpoint-delete" => {
            let agent_id = args.next().unwrap_or_else(|| usage());
            let checkpoint_id = args.next().unwrap_or_else(|| usage());
            if args.next().is_some() {
                usage();
            }
            let existed = client
                .delete_generation_checkpoint(agent_id, checkpoint_id)
                .await
                .unwrap_or_else(|error| fail(error));
            print_json(
                &serde_json::json!({ "deleted": existed }),
                "checkpoint deletion result",
            );
            return;
        }
        "capabilities" => {
            let agent_id = args.next().unwrap_or_else(|| usage());
            if args.next().is_some() {
                usage();
            }
            let info = client
                .agent_info(agent_id)
                .await
                .unwrap_or_else(|error| fail(error));
            print_json(&info, "agent capabilities");
            return;
        }
        "providers" => {
            if args.next().is_some() {
                usage();
            }
            let providers = client
                .list_providers()
                .await
                .unwrap_or_else(|error| fail(error));
            print_json(&providers, "provider health");
            return;
        }
        "metrics" => {
            if args.next().is_some() {
                usage();
            }
            let metrics = client.metrics().await.unwrap_or_else(|error| fail(error));
            print!("{}", metrics.prometheus);
            return;
        }
        "protocol" => {
            if args.next().is_some() {
                usage();
            }
            let protocol = client.hello().await.unwrap_or_else(|error| fail(error));
            print_json(&protocol, "protocol description");
            return;
        }
        "package-trust-key" => {
            let publisher = args.next().unwrap_or_else(|| usage());
            let key_id = args.next().unwrap_or_else(|| usage());
            let public_key_file = args.next().unwrap_or_else(|| usage());
            let valid_from = args.next().unwrap_or_else(|| usage());
            let options = parse_package_trust_options(args.collect::<Vec<_>>());
            let public_key = read_bounded_file(&public_key_file, 4 * 1024, "package public key");
            client
                .trust_package_key(
                    publisher,
                    &key_id,
                    &public_key,
                    valid_from,
                    options.valid_until,
                    options.supersedes,
                )
                .await
                .unwrap_or_else(|error| fail(error));
            print_json(
                &serde_json::json!({ "key_id": key_id, "status": "trusted" }),
                "package trust result",
            );
            return;
        }
        "package-revoke-key" => {
            let key_id = args.next().unwrap_or_else(|| usage());
            require_target_confirmation(&mut args, &key_id);
            client
                .revoke_package_key(&key_id)
                .await
                .unwrap_or_else(|error| fail(error));
            print_json(
                &serde_json::json!({ "key_id": key_id, "status": "revoked" }),
                "package key revocation result",
            );
            return;
        }
        "package-publish" => {
            let archive_file = args.next().unwrap_or_else(|| usage());
            if args.next().is_some() {
                usage();
            }
            let archive = read_bounded_file(
                &archive_file,
                kernel::package::MAX_ARCHIVE_BYTES,
                "signed package archive",
            );
            let package = client
                .publish_package(&archive)
                .await
                .unwrap_or_else(|error| fail(error));
            print_json(&package, "published package");
            return;
        }
        "package-yank" => {
            let name = args.next().unwrap_or_else(|| usage());
            let version = args.next().unwrap_or_else(|| usage());
            let target = format!("{name}@{version}");
            require_target_confirmation(&mut args, &target);
            client
                .yank_package(&name, &version)
                .await
                .unwrap_or_else(|error| fail(error));
            print_json(
                &serde_json::json!({ "package": name, "version": version, "yanked": true }),
                "package yank result",
            );
            return;
        }
        "package-fetch" => {
            let name = args.next().unwrap_or_else(|| usage());
            let version = args.next().unwrap_or_else(|| usage());
            let output_file = args.next().unwrap_or_else(|| usage());
            if args.next().is_some() {
                usage();
            }
            let archive = client
                .fetch_package(&name, &version)
                .await
                .unwrap_or_else(|error| fail(error));
            write_new_file(&output_file, &archive, "fetched package archive");
            print_json(
                &serde_json::json!({
                    "package": name,
                    "version": version,
                    "output": output_file,
                    "bytes": archive.len(),
                }),
                "package fetch result",
            );
            return;
        }
        "package-search" => {
            let query = args.next().unwrap_or_else(|| usage());
            if args.next().is_some() {
                usage();
            }
            let packages = client
                .search_packages(query)
                .await
                .unwrap_or_else(|error| fail(error));
            print_json(&packages, "package search results");
            return;
        }
        "package-install" => {
            let name = args.next().unwrap_or_else(|| usage());
            let requirement = args.next().unwrap_or_else(|| "*".into());
            if args.next().is_some() {
                usage();
            }
            let package = client
                .install_package(name, requirement)
                .await
                .unwrap_or_else(|error| fail(error));
            print_json(&package, "installed package");
            return;
        }
        "package-rollback" => {
            let name = args.next().unwrap_or_else(|| usage());
            require_target_confirmation(&mut args, &name);
            let package = client
                .rollback_package(name)
                .await
                .unwrap_or_else(|error| fail(error));
            print_json(&package, "rolled-back package");
            return;
        }
        "package-remove" => {
            let name = args.next().unwrap_or_else(|| usage());
            require_target_confirmation(&mut args, &name);
            client
                .remove_package(&name)
                .await
                .unwrap_or_else(|error| fail(error));
            print_json(
                &serde_json::json!({ "package": name, "removed": true }),
                "package removal result",
            );
            return;
        }
        "packages" => {
            if args.next().is_some() {
                usage();
            }
            let packages = client
                .list_installed_packages()
                .await
                .unwrap_or_else(|error| fail(error));
            print_json(&packages, "installed packages");
            return;
        }
        "package-run" => {
            let name = args.next().unwrap_or_else(|| usage());
            if args.next().is_some() {
                usage();
            }
            let id = client
                .run_installed_package(&name)
                .await
                .unwrap_or_else(|error| fail(error));
            print_json(
                &serde_json::json!({ "package": name, "agent_id": id }),
                "package run result",
            );
            return;
        }
        "pressure" => {
            let stats = client
                .context_pressure(args.next().unwrap_or_else(|| usage()))
                .await
                .unwrap_or_else(|error| fail(error));
            println!(
                "{}",
                serde_json::to_string_pretty(&stats).unwrap_or_else(|error| {
                    fail(agent_sdk::SdkError::Kernel(format!(
                        "pressure encoding failed: {error}"
                    )))
                })
            );
            return;
        }
        "tunables" => {
            let tunables = client
                .list_operator_tunables()
                .await
                .unwrap_or_else(|error| fail(error));
            println!(
                "{}",
                serde_json::to_string_pretty(&tunables).unwrap_or_else(|error| {
                    fail(agent_sdk::SdkError::Kernel(format!(
                        "tunable encoding failed: {error}"
                    )))
                })
            );
            return;
        }
        "tunable-set" => {
            let name = args.next().unwrap_or_else(|| usage());
            let value = args
                .next()
                .unwrap_or_else(|| usage())
                .parse::<u64>()
                .unwrap_or_else(|_| usage());
            let expected_revision = args
                .next()
                .unwrap_or_else(|| usage())
                .parse::<u64>()
                .unwrap_or_else(|_| usage());
            let tunable = client
                .set_operator_tunable(name, value, expected_revision)
                .await
                .unwrap_or_else(|error| fail(error));
            println!(
                "{}",
                serde_json::to_string_pretty(&tunable).unwrap_or_else(|error| {
                    fail(agent_sdk::SdkError::Kernel(format!(
                        "tunable encoding failed: {error}"
                    )))
                })
            );
            return;
        }
        "tunable-rollback" => {
            let name = args.next().unwrap_or_else(|| usage());
            let target_revision = args
                .next()
                .unwrap_or_else(|| usage())
                .parse::<u64>()
                .unwrap_or_else(|_| usage());
            let expected_revision = args
                .next()
                .unwrap_or_else(|| usage())
                .parse::<u64>()
                .unwrap_or_else(|_| usage());
            let tunable = client
                .rollback_operator_tunable(name, target_revision, expected_revision)
                .await
                .unwrap_or_else(|error| fail(error));
            println!(
                "{}",
                serde_json::to_string_pretty(&tunable).unwrap_or_else(|error| {
                    fail(agent_sdk::SdkError::Kernel(format!(
                        "tunable encoding failed: {error}"
                    )))
                })
            );
            return;
        }
        "tunable-history" => {
            let name = args.next();
            let limit = args
                .next()
                .as_deref()
                .unwrap_or("100")
                .parse::<usize>()
                .unwrap_or_else(|_| usage());
            let entries = client
                .operator_tunable_audit(name, limit)
                .await
                .unwrap_or_else(|error| fail(error));
            println!(
                "{}",
                serde_json::to_string_pretty(&entries).unwrap_or_else(|error| {
                    fail(agent_sdk::SdkError::Kernel(format!(
                        "tunable audit encoding failed: {error}"
                    )))
                })
            );
            return;
        }
        "backup-create" => {
            let backup_root = args.next().unwrap_or_else(|| usage());
            let name = args.next().unwrap_or_else(|| usage());
            if args.next().is_some() {
                usage();
            }
            let manifest = client
                .create_storage_backup(backup_root, name)
                .await
                .unwrap_or_else(|error| fail(error));
            print_json(&manifest, "backup manifest");
            return;
        }
        "backup-retention" => {
            let backup_root = args.next().unwrap_or_else(|| usage());
            let keep_latest = args
                .next()
                .unwrap_or_else(|| usage())
                .parse::<usize>()
                .unwrap_or_else(|_| usage());
            let max_age_seconds = args
                .next()
                .unwrap_or_else(|| usage())
                .parse::<u64>()
                .unwrap_or_else(|_| usage());
            let mode = args.next().unwrap_or_else(|| usage());
            if args.next().is_some() {
                usage();
            }
            let report = match mode.as_str() {
                "--dry-run" => {
                    client
                        .preview_storage_backup_retention(backup_root, keep_latest, max_age_seconds)
                        .await
                }
                "--confirm" => {
                    client
                        .enforce_storage_backup_retention(
                            backup_root,
                            keep_latest,
                            max_age_seconds,
                            agent_sdk::CONFIRM_BACKUP_RETENTION,
                        )
                        .await
                }
                _ => usage(),
            }
            .unwrap_or_else(|error| fail(error));
            print_json(&report, "backup retention report");
            return;
        }
        "backup-status" => {
            if args.next().is_some() {
                usage();
            }
            let status = client
                .storage_backup_status()
                .await
                .unwrap_or_else(|error| fail(error));
            print_json(&status, "backup maintenance status");
            return;
        }
        "data-inventory" => {
            if args.next().is_some() {
                usage();
            }
            let inventory = client
                .storage_data_inventory()
                .await
                .unwrap_or_else(|error| fail(error));
            print_json(&inventory, "storage data inventory");
            return;
        }
        "erase-agent" => {
            let target = args.next().unwrap_or_else(|| usage());
            let agent_id = target
                .parse::<kernel::AgentId>()
                .unwrap_or_else(|_| usage());
            require_target_confirmation(&mut args, &target);
            let receipt = client
                .erase_agent_data(agent_id, agent_sdk::CONFIRM_DATA_ERASURE)
                .await
                .unwrap_or_else(|error| fail(error));
            print_json(&receipt, "deletion receipt");
            return;
        }
        "erase-user" => {
            let user_id = args.next().unwrap_or_else(|| usage());
            require_target_confirmation(&mut args, &user_id);
            let receipt = client
                .erase_user_data(user_id, agent_sdk::CONFIRM_DATA_ERASURE)
                .await
                .unwrap_or_else(|error| fail(error));
            print_json(&receipt, "deletion receipt");
            return;
        }
        "erase-tenant" => {
            let tenant_id = args.next().unwrap_or_else(|| usage());
            require_target_confirmation(&mut args, &tenant_id);
            let receipt = client
                .erase_tenant_data(tenant_id, agent_sdk::CONFIRM_DATA_ERASURE)
                .await
                .unwrap_or_else(|error| fail(error));
            print_json(&receipt, "deletion receipt");
            return;
        }
        "services" => {
            for service in client
                .list_services()
                .await
                .unwrap_or_else(|error| fail(error))
            {
                println!(
                    "{}\t{:?}\t{}\tready={}\thealthy={}\trestarts={}\tdesired={}",
                    service.name,
                    service.status,
                    service
                        .agent_id
                        .map(|id| id.to_string())
                        .unwrap_or_else(|| "-".into()),
                    service.ready,
                    service.healthy,
                    service.restart_count,
                    service.desired_running,
                );
            }
            return;
        }
        "service-start" => {
            let service = client
                .start_service(args.next().unwrap_or_else(|| usage()))
                .await
                .unwrap_or_else(|error| fail(error));
            println!("{}\t{:?}", service.name, service.status);
            return;
        }
        "service-stop" => {
            let service = client
                .stop_service(args.next().unwrap_or_else(|| usage()))
                .await
                .unwrap_or_else(|error| fail(error));
            println!("{}\t{:?}", service.name, service.status);
            return;
        }
        "service-restart" => {
            let service = client
                .restart_service(args.next().unwrap_or_else(|| usage()))
                .await
                .unwrap_or_else(|error| fail(error));
            println!("{}\t{:?}", service.name, service.status);
            return;
        }
        "service-reload" => {
            let order = client
                .reload_services()
                .await
                .unwrap_or_else(|error| fail(error));
            println!("{}", order.join("\n"));
            return;
        }
        "service-history" => {
            let name = args.next();
            let limit = args
                .next()
                .as_deref()
                .unwrap_or("100")
                .parse::<usize>()
                .unwrap_or_else(|_| usage());
            let history = client
                .service_history(name, limit)
                .await
                .unwrap_or_else(|error| fail(error));
            println!(
                "{}",
                serde_json::to_string_pretty(&history).unwrap_or_else(|error| {
                    fail(agent_sdk::SdkError::Kernel(format!(
                        "service history encoding failed: {error}"
                    )))
                })
            );
            return;
        }
        "status" => {
            client
                .agent_status(args.next().unwrap_or_else(|| usage()))
                .await
        }
        "pause" => {
            client
                .pause_agent(args.next().unwrap_or_else(|| usage()))
                .await
        }
        "resume" => {
            client
                .resume_agent(args.next().unwrap_or_else(|| usage()))
                .await
        }
        "stop" => {
            client
                .stop_agent(args.next().unwrap_or_else(|| usage()))
                .await
        }
        "kill" => {
            let agent_id = args.next().unwrap_or_else(|| usage());
            require_target_confirmation(&mut args, &agent_id);
            client.kill_agent(agent_id).await
        }
        "wait" => {
            let id = args.next().unwrap_or_else(|| usage());
            let timeout_ms = args
                .next()
                .as_deref()
                .unwrap_or("30000")
                .parse::<u64>()
                .unwrap_or_else(|_| usage());
            client
                .wait_agent(id, Duration::from_millis(timeout_ms))
                .await
        }
        _ => usage(),
    };

    println!("{}", result.unwrap_or_else(|error| fail(error)));
}

fn fail(error: agent_sdk::SdkError) -> ! {
    eprintln!("agentctl: {error}");
    std::process::exit(1);
}

fn fail_storage(error: kernel::ContextError) -> ! {
    eprintln!("agentctl: {error}");
    std::process::exit(1);
}

fn fail_operator(message: String) -> ! {
    eprintln!("agentctl: {message}");
    std::process::exit(1);
}

fn print_json(value: &impl serde::Serialize, label: &str) {
    println!(
        "{}",
        serde_json::to_string_pretty(value).unwrap_or_else(|error| fail(
            agent_sdk::SdkError::Kernel(format!("{label} encoding failed: {error}"))
        ))
    );
}

fn read_bounded_file(path: &str, max_bytes: usize, label: &str) -> Vec<u8> {
    let file = std::fs::File::open(path)
        .unwrap_or_else(|error| fail_operator(format!("failed to open {label} {path}: {error}")));
    let limit = u64::try_from(max_bytes)
        .unwrap_or(u64::MAX)
        .saturating_add(1);
    let mut bytes = Vec::new();
    file.take(limit)
        .read_to_end(&mut bytes)
        .unwrap_or_else(|error| fail_operator(format!("failed to read {label} {path}: {error}")));
    if bytes.len() > max_bytes {
        fail_operator(format!("{label} {path} exceeds the {max_bytes}-byte limit"));
    }
    bytes
}

fn write_new_file(path: &str, bytes: &[u8], label: &str) {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .unwrap_or_else(|error| {
            fail_operator(format!(
                "failed to create {label} {path} without overwriting an existing file: {error}"
            ))
        });
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .unwrap_or_else(|error| fail_operator(format!("failed to write {label} {path}: {error}")));
}

fn require_target_confirmation<I>(args: &mut std::iter::Peekable<I>, target: &str)
where
    I: Iterator<Item = String>,
{
    if args.next().as_deref() != Some("--confirm")
        || args.next().as_deref() != Some(target)
        || args.next().is_some()
    {
        usage();
    }
}
