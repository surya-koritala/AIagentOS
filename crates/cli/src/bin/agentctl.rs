//! Small operator CLI for the public agent lifecycle API.

use std::io::{Read, Write};
use std::time::Duration;

use agent_cli::{policy, OperatorClient};
use agent_sdk::ConnectionProfile;

/// Canonical `agentctl` usage text, shared by the usage-error and
/// explicit-help paths so the two can never drift apart.
const USAGE: &str = "usage: agentctl [--addr HOST:PORT] [--token TOKEN] [--tenant TENANT_ID] \
         <tenant-create|tenants|tenant-revoke|user-create|users|user-revoke|api-key-issue|api-keys|api-key-revoke|create|clone|list|inspect|message|stream|cancel|checkpoints|checkpoint-resume|checkpoint-delete|capabilities|vfs-mounts|vfs-open|vfs-invoke|vfs-close|vfs-data-open|vfs-kv-open|vfs-data-dup|vfs-data-read|vfs-data-write|vfs-data-list|vfs-data-stat|vfs-namespace-mounts|vfs-mount-entries|vfs-mount|vfs-unmount|vfs-workspace-mounts|vfs-workspace-open|vfs-open-at|vfs-dup|vfs-read|vfs-write|vfs-list|vfs-stat|providers|metrics|protocol|policy-validate|policy-explain|gate-stats|node-control-audit|cluster-membership-audit|cluster-certificate-rollout-audit|package-trust-key|package-revoke-key|package-publish|package-yank|package-fetch|package-search|package-install|package-rollback|package-remove|packages|package-run|pressure|tunables|tunable-set|tunable-rollback|tunable-history|status|pause|resume|stop|kill|wait|services|service-start|service-stop|service-restart|service-reload|service-history|backup-create|backup-retention|backup-status|data-inventory|backup-key-generate|backup-anchor-create|backup-verify|backup-restore|backup-disaster-recover|backup-corruption-recover|backup-remote-publish|backup-remote-fetch|storage-key-generate|storage-encrypt|storage-encrypt-recover|storage-key-rotate|storage-portable-export|storage-portable-verify|storage-portable-import|erase-agent|erase-user|erase-tenant> [ARGS...]\n\
         \n\
         public runtime commands:\n\
           agentctl [SERVER OPTIONS] tenant-create NAME\n\
           agentctl [SERVER OPTIONS] tenants\n\
           agentctl [SERVER OPTIONS] tenant-revoke TENANT_ID --confirm TENANT_ID\n\
           agentctl [SERVER OPTIONS] [--tenant TENANT_ID] user-create USERNAME EMAIL ROLE\n\
           agentctl [SERVER OPTIONS] [--tenant TENANT_ID] users\n\
           agentctl [SERVER OPTIONS] user-revoke USER_ID --confirm USER_ID\n\
           agentctl [SERVER OPTIONS] [--tenant TENANT_ID] api-key-issue USER_ID NAME\n\
           agentctl [SERVER OPTIONS] [--tenant TENANT_ID] api-keys\n\
           agentctl [SERVER OPTIONS] api-key-revoke KEY_ID --confirm KEY_ID\n\
           --tenant is only for trusted-system bootstrap and inventory.\n\
           ROLE is admin, user, read_only, or operator (read_only alias).\n\
           agentctl [SERVER OPTIONS] vfs-mounts AGENT_ID\n\
           agentctl [SERVER OPTIONS] vfs-open AGENT_ID /tools/NAME\n\
           agentctl [SERVER OPTIONS] vfs-invoke AGENT_ID HANDLE ARGUMENTS_JSON\n\
           agentctl [SERVER OPTIONS] vfs-close AGENT_ID HANDLE\n\
           agentctl [SERVER OPTIONS] vfs-data-open AGENT_ID MOUNT_PATH RIGHTS\n\
           agentctl [SERVER OPTIONS] vfs-kv-open AGENT_ID KV_MOUNT KEY RIGHTS\n\
           agentctl [SERVER OPTIONS] vfs-data-dup AGENT_ID HANDLE RIGHTS\n\
           agentctl [SERVER OPTIONS] vfs-data-read AGENT_ID HANDLE [ARGUMENTS_JSON]\n\
           agentctl [SERVER OPTIONS] vfs-data-write AGENT_ID HANDLE ARGUMENTS_JSON\n\
           agentctl [SERVER OPTIONS] vfs-data-list AGENT_ID HANDLE\n\
           agentctl [SERVER OPTIONS] vfs-data-stat AGENT_ID HANDLE\n\
           agentctl [SERVER OPTIONS] vfs-namespace-mounts AGENT_ID\n\
           agentctl [SERVER OPTIONS] vfs-mount-entries AGENT_ID MOUNT_PATH\n\
           agentctl [SERVER OPTIONS] vfs-mount AGENT_ID TABLE_ID TABLE_GENERATION MOUNT_PATH <tools|workspace|memory|kv|ipc>\n\
           agentctl [SERVER OPTIONS] vfs-unmount AGENT_ID TABLE_ID TABLE_GENERATION MOUNT_PATH MOUNT_ID\n\
           agentctl [SERVER OPTIONS] vfs-workspace-mounts AGENT_ID\n\
           agentctl [SERVER OPTIONS] vfs-workspace-open AGENT_ID PATH <file|directory> RIGHTS [--allow-missing]\n\
           agentctl [SERVER OPTIONS] vfs-open-at AGENT_ID DIRECTORY_HANDLE RELATIVE_PATH <file|directory> RIGHTS [--allow-missing]\n\
           agentctl [SERVER OPTIONS] vfs-dup AGENT_ID HANDLE RIGHTS\n\
           agentctl [SERVER OPTIONS] vfs-read AGENT_ID HANDLE [OFFSET [MAX_BYTES]]\n\
           agentctl [SERVER OPTIONS] vfs-write AGENT_ID HANDLE SOURCE_FILE_OR_DASH\n\
           agentctl [SERVER OPTIONS] vfs-list AGENT_ID DIRECTORY_HANDLE\n\
           agentctl [SERVER OPTIONS] vfs-stat AGENT_ID HANDLE\n\
           agentctl [SERVER OPTIONS] create NAME TASK [PROVIDER [PROFILE [PRIORITY]]]\n\
           agentctl [SERVER OPTIONS] clone PARENT_ID CHILD_UUID NAME [CAPABILITY_DROP_CSV]\n\
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
         policy authoring commands (offline, machine-readable):\n\
           agentctl policy-validate POLICY_FILE\n\
           agentctl policy-explain POLICY_FILE --subject SUBJECT --action ACTION --object OBJECT\n\
         \n\
         system audit commands:\n\
           agentctl [SERVER OPTIONS] gate-stats\n\
           agentctl [SERVER OPTIONS] node-control-audit [LIMIT]\n\
           agentctl [SERVER OPTIONS] cluster-membership-audit [LIMIT]\n\
           agentctl [SERVER OPTIONS] cluster-certificate-rollout-audit [LIMIT]\n\
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
           agentctl workspace-ownership CONFIG_FILE list\n\
           agentctl workspace-ownership CONFIG_FILE retain AGENT_UUID --confirm-offline\n\
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
           agentctl [SERVER OPTIONS] erase-tenant TENANT_ID --confirm TENANT_ID";

/// Usage error. Diagnostics go to stderr with a non-zero exit so a mistyped
/// command can never be mistaken for success by a script.
fn usage() -> ! {
    eprintln!("{USAGE}");
    std::process::exit(2);
}

fn workspace_rights(value: &str) -> Vec<agent_sdk::WorkspaceRight> {
    value
        .split(',')
        .map(|right| match right {
            "read" => agent_sdk::WorkspaceRight::Read,
            "write" => agent_sdk::WorkspaceRight::Write,
            "list" => agent_sdk::WorkspaceRight::List,
            "stat" => agent_sdk::WorkspaceRight::Stat,
            _ => usage(),
        })
        .collect()
}

fn workspace_request(
    path: String,
    args: &mut impl Iterator<Item = String>,
) -> agent_sdk::WorkspaceOpenRequest {
    let kind = match args.next().as_deref() {
        Some("file") => agent_sdk::WorkspaceKind::File,
        Some("directory") => agent_sdk::WorkspaceKind::Directory,
        _ => usage(),
    };
    let rights = workspace_rights(&args.next().unwrap_or_else(|| usage()));
    let allow_missing = match args.next().as_deref() {
        None => false,
        Some("--allow-missing") if args.next().is_none() => true,
        _ => usage(),
    };
    agent_sdk::WorkspaceOpenRequest {
        path,
        kind,
        rights,
        allow_missing,
    }
}

/// Explicit `--help`. The same text on stdout with a zero exit, so it pipes
/// cleanly and does not read as a failure.
fn help() -> ! {
    println!("{USAGE}");
    std::process::exit(0);
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

#[derive(Default)]
struct PolicyExplainOptions {
    subject: Option<String>,
    action: Option<String>,
    object: Option<String>,
}

fn parse_policy_explain_options(values: impl IntoIterator<Item = String>) -> PolicyExplainOptions {
    let mut values = values.into_iter();
    let mut parsed = PolicyExplainOptions::default();
    while let Some(value) = values.next() {
        match value.as_str() {
            "--subject" if parsed.subject.is_none() => {
                parsed.subject = Some(values.next().unwrap_or_else(|| usage()));
            }
            "--action" if parsed.action.is_none() => {
                parsed.action = Some(values.next().unwrap_or_else(|| usage()));
            }
            "--object" if parsed.object.is_none() => {
                parsed.object = Some(values.next().unwrap_or_else(|| usage()));
            }
            _ => usage(),
        }
    }
    if parsed.subject.is_none() || parsed.action.is_none() || parsed.object.is_none() {
        usage();
    }
    parsed
}

fn parse_audit_limit(values: impl IntoIterator<Item = String>) -> usize {
    let mut values = values.into_iter();
    let limit = values
        .next()
        .as_deref()
        .unwrap_or("100")
        .parse::<usize>()
        .unwrap_or_else(|_| usage());
    if !(1..=1_000).contains(&limit) || values.next().is_some() {
        usage();
    }
    limit
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
    // Keep the command state machine off the small Windows main-thread stack.
    // Offline recovery can construct a complete kernel beneath this frame.
    Box::pin(run()).await;
}

async fn run() {
    let argv: Vec<String> = std::env::args().collect();
    if argv.len() == 2 && matches!(argv[1].as_str(), "--version" | "-V") {
        println!("agentctl {}", env!("CARGO_PKG_VERSION"));
        return;
    }
    // Help must be answered before the connection profile is resolved. Reaching
    // `OperatorClient::connect_profile` first made `agentctl --help` fail with a
    // transport error against a server the caller never asked to reach.
    if argv[1..]
        .iter()
        .any(|argument| matches!(argument.as_str(), "--help" | "-h" | "help"))
    {
        help();
    }

    let mut args = argv.into_iter().skip(1).peekable();
    let mut address_override = None;
    let mut token = std::env::var("AGENT_SERVER_TOKEN").ok();
    let mut tenant_override = None;

    while matches!(
        args.peek().map(String::as_str),
        Some("--addr" | "--token" | "--tenant")
    ) {
        match args.next().as_deref() {
            Some("--addr") => address_override = Some(args.next().unwrap_or_else(|| usage())),
            Some("--token") => token = Some(args.next().unwrap_or_else(|| usage())),
            Some("--tenant") => tenant_override = Some(args.next().unwrap_or_else(|| usage())),
            _ => unreachable!(),
        }
    }

    let command = args.next().unwrap_or_else(|| usage());
    if tenant_override.is_some()
        && !matches!(
            command.as_str(),
            "user-create" | "users" | "api-key-issue" | "api-keys"
        )
    {
        usage();
    }

    // No command begins with `-`, so an option in command position is always a
    // usage error. Rejecting it here keeps unknown flags from being carried all
    // the way to `connect_profile`, which would report a transport failure for
    // what is really a typo.
    if command.starts_with('-') {
        eprintln!("agentctl: unrecognized option '{command}'\n");
        usage();
    }

    if command == "user-create" {
        let role = args.clone().nth(2).unwrap_or_else(|| usage());
        if agent_sdk::Role::parse(&role).is_none() {
            usage();
        }
    }

    // Keep recovery's kernel construction outside the wire-command frame.
    if Box::pin(run_offline(&command, &mut args)).await {
        return;
    }

    let mut profile = ConnectionProfile::from_env().unwrap_or_else(|error| {
        eprintln!("agentctl: {error}");
        std::process::exit(2);
    });
    if let Some(address) = address_override {
        profile.address = address;
    }
    let client = OperatorClient::connect_profile(&profile, token.as_deref())
        .await
        .unwrap_or_else(|error| {
            eprintln!(
                "agentctl: could not connect to {}: {error}",
                profile.address
            );
            std::process::exit(1);
        });

    Box::pin(run_online(&command, args, client, tenant_override)).await;
}

type CommandArgs = std::iter::Peekable<std::iter::Skip<std::vec::IntoIter<String>>>;

async fn run_offline(command: &str, args: &mut CommandArgs) -> bool {
    match command {
        "workspace-ownership" => {
            let config_file = args.next().unwrap_or_else(|| usage());
            let action = args.next().unwrap_or_else(|| usage());
            let target = match action.as_str() {
                "list" if args.next().is_none() => None,
                "retain" => {
                    let id = args.next().unwrap_or_else(|| usage());
                    let id = id.parse::<kernel::AgentId>().unwrap_or_else(|_| {
                        fail_operator("workspace ownership requires a recorded agent UUID".into())
                    });
                    if args.next().as_deref() != Some("--confirm-offline") || args.next().is_some()
                    {
                        usage();
                    }
                    Some(id)
                }
                _ => usage(),
            };
            let path = std::path::Path::new(&config_file);
            if !std::fs::symlink_metadata(path).is_ok_and(|metadata| metadata.is_file()) {
                fail_operator("workspace ownership requires an existing configuration file".into());
            }
            let config = kernel::config::Config::try_load_from(path).unwrap_or_else(|error| {
                fail_operator(format!("invalid local configuration: {error}"))
            });
            // Startup acquires the existing exclusive database lease; a live
            // runtime cannot race this purely local maintenance command.
            let kernel = kernel::AgentKernelImpl::from_config_for_workspace_maintenance(&config).unwrap_or_else(|error| {
                fail_operator(format!(
                    "local workspace ownership maintenance failed: {error}"
                ))
            });
            kernel
                .rehydrate_agents()
                .await
                .unwrap_or_else(|error| fail_operator(error.to_string()));
            if let Some(id) = target {
                kernel
                    .retain_legacy_workspace_as_operator(id)
                    .await
                    .unwrap_or_else(|error| fail_operator(error.to_string()));
                print_json(
                    &serde_json::json!({"agent_id":id,"resolution":"retain_as_operator_workspace","automatic_deletion":false}),
                    "workspace ownership resolution",
                );
            } else {
                let status = kernel
                    .workspace_ownership_status()
                    .unwrap_or_else(|error| fail_operator(error.to_string()));
                print_json(&status, "workspace ownership status");
            }
            true
        }
        "policy-validate" => {
            let path = args.next().unwrap_or_else(|| usage());
            if args.next().is_some() {
                usage();
            }
            let report = policy::validate_file(path).unwrap_or_else(|error| fail_operator(error));
            print_json(&report, "policy validation report");
            true
        }
        "policy-explain" => {
            let path = args.next().unwrap_or_else(|| usage());
            let options = parse_policy_explain_options(args.collect::<Vec<_>>());
            let report = policy::explain_file(
                path,
                options.subject.expect("validated subject"),
                options.action.expect("validated action"),
                options.object.expect("validated object"),
            )
            .unwrap_or_else(|error| fail_operator(error));
            print_json(&report, "policy explanation report");
            true
        }
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
            true
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
            true
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
                return true;
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
            true
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
                return true;
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
            true
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
            true
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
            true
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
            true
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
            true
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
            true
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
            true
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
            true
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
            true
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
            true
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
            true
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
            true
        }
        _ => false,
    }
}

async fn run_online(
    command: &str,
    mut args: CommandArgs,
    mut client: OperatorClient,
    tenant_override: Option<String>,
) {
    let result = match command {
        "tenant-create" => {
            let name = args.next().unwrap_or_else(|| usage());
            if args.next().is_some() {
                usage();
            }
            let id = client
                .create_tenant(name)
                .await
                .unwrap_or_else(|error| fail(error));
            print_json(&serde_json::json!({ "id": id }), "tenant");
            return;
        }
        "tenants" => {
            if args.next().is_some() {
                usage();
            }
            let tenants = client
                .list_tenants()
                .await
                .unwrap_or_else(|error| fail(error));
            print_json(&tenants, "tenants");
            return;
        }
        "tenant-revoke" => {
            let target = args.next().unwrap_or_else(|| usage());
            require_target_confirmation(&mut args, &target);
            let revoked = client
                .revoke_tenant(target, agent_sdk::CONFIRM_IDENTITY_REVOCATION)
                .await
                .unwrap_or_else(|error| fail(error));
            print_json(
                &serde_json::json!({ "revoked": revoked }),
                "tenant revocation",
            );
            return;
        }
        "user-create" => {
            let username = args.next().unwrap_or_else(|| usage());
            let email = args.next().unwrap_or_else(|| usage());
            let role = agent_sdk::Role::parse(&args.next().unwrap_or_else(|| usage()))
                .unwrap_or_else(|| usage());
            if args.next().is_some() {
                usage();
            }
            let result = match tenant_override {
                Some(tenant) => {
                    client
                        .create_user_for_tenant(tenant, username, email, role)
                        .await
                }
                None => client.create_user(username, email, role).await,
            };
            let id = result.unwrap_or_else(|error| fail(error));
            print_json(&serde_json::json!({ "id": id }), "user");
            return;
        }
        "users" => {
            if args.next().is_some() {
                usage();
            }
            let result = match tenant_override {
                Some(tenant) => client.list_users_for_tenant(tenant).await,
                None => client.list_users().await,
            };
            print_json(&result.unwrap_or_else(|error| fail(error)), "users");
            return;
        }
        "user-revoke" => {
            let target = args.next().unwrap_or_else(|| usage());
            require_target_confirmation(&mut args, &target);
            let revoked = client
                .revoke_user(target, agent_sdk::CONFIRM_IDENTITY_REVOCATION)
                .await
                .unwrap_or_else(|error| fail(error));
            print_json(
                &serde_json::json!({ "revoked": revoked }),
                "user revocation",
            );
            return;
        }
        "api-key-issue" => {
            let user = args.next().unwrap_or_else(|| usage());
            let name = args.next().unwrap_or_else(|| usage());
            if args.next().is_some() {
                usage();
            }
            let result = match tenant_override {
                Some(tenant) => client.issue_api_key_for_tenant(tenant, user, name).await,
                None => client.issue_api_key(user, name).await,
            };
            let issued = result.unwrap_or_else(|error| fail(error));
            eprintln!(
                "Store this API key securely; it is shown once and cannot be recovered. Key ID: {}",
                issued.key_id
            );
            println!("{}", issued.key);
            return;
        }
        "api-keys" => {
            if args.next().is_some() {
                usage();
            }
            let result = match tenant_override {
                Some(tenant) => client.list_api_keys_for_tenant(tenant).await,
                None => client.list_api_keys().await,
            };
            print_json(&result.unwrap_or_else(|error| fail(error)), "API keys");
            return;
        }
        "api-key-revoke" => {
            let target = args.next().unwrap_or_else(|| usage());
            require_target_confirmation(&mut args, &target);
            let revoked = client
                .revoke_api_key(target, agent_sdk::CONFIRM_IDENTITY_REVOCATION)
                .await
                .unwrap_or_else(|error| fail(error));
            print_json(
                &serde_json::json!({ "revoked": revoked }),
                "API-key revocation",
            );
            return;
        }
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
        "clone" => {
            let parent = args.next().unwrap_or_else(|| usage());
            let child = args
                .next()
                .unwrap_or_else(|| usage())
                .parse::<kernel::AgentId>()
                .unwrap_or_else(|_| usage());
            let name = args.next().unwrap_or_else(|| usage());
            let dropped = args
                .next()
                .map(|value| value.split(',').map(str::to_string).collect())
                .unwrap_or_default();
            if args.next().is_some() {
                usage();
            }
            let result = client
                .clone_agent(parent, child, name, dropped)
                .await
                .unwrap_or_else(|error| fail(error));
            print_json(&result, "cloned agent");
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
        "vfs-mounts" => {
            let agent = args.next().unwrap_or_else(|| usage());
            if args.next().is_some() {
                usage();
            }
            let view = client
                .vfs_mounts(agent)
                .await
                .unwrap_or_else(|error| fail(error));
            print_json(&view, "VFS mounts");
            return;
        }
        "vfs-open" => {
            let agent = args.next().unwrap_or_else(|| usage());
            let path = args.next().unwrap_or_else(|| usage());
            if args.next().is_some() {
                usage();
            }
            let handle = client
                .vfs_open(agent, path)
                .await
                .unwrap_or_else(|error| fail(error));
            print_json(&handle, "VFS handle");
            return;
        }
        "vfs-invoke" => {
            let agent = args.next().unwrap_or_else(|| usage());
            let handle = args.next().unwrap_or_else(|| usage());
            let arguments = args.next().unwrap_or_else(|| usage());
            if args.next().is_some() {
                usage();
            }
            let arguments = serde_json::from_str(&arguments).unwrap_or_else(|_| usage());
            let result = client
                .vfs_invoke(agent, handle, arguments)
                .await
                .unwrap_or_else(|error| fail(error));
            print_json(&result, "VFS tool result");
            return;
        }
        "vfs-close" => {
            let agent = args.next().unwrap_or_else(|| usage());
            let handle = args.next().unwrap_or_else(|| usage());
            if args.next().is_some() {
                usage();
            }
            client
                .vfs_close(agent, handle)
                .await
                .unwrap_or_else(|error| fail(error));
            print_json(&serde_json::json!({"closed": true}), "VFS close");
            return;
        }
        "vfs-workspace-mounts" => {
            let agent = args.next().unwrap_or_else(|| usage());
            if args.next().is_some() {
                usage();
            }
            let view = client
                .vfs_workspace_mounts(agent)
                .await
                .unwrap_or_else(|error| fail(error));
            print_json(&view, "workspace mount");
            return;
        }
        "vfs-data-open" | "vfs-kv-open" => {
            let agent = args.next().unwrap_or_else(|| usage());
            let path = args.next().unwrap_or_else(|| usage());
            let key = if command == "vfs-kv-open" {
                Some(args.next().unwrap_or_else(|| usage()))
            } else {
                None
            };
            let rights = workspace_rights(&args.next().unwrap_or_else(|| usage()));
            if args.next().is_some() {
                usage();
            }
            let handle = if let Some(key) = key {
                client.vfs_open_kv(agent, &path, &key, rights).await
            } else {
                client.vfs_open_data(agent, path, rights).await
            }
            .unwrap_or_else(|error| fail(error));
            print_json(&handle, "data handle");
            return;
        }
        "vfs-data-dup" => {
            let agent = args.next().unwrap_or_else(|| usage());
            let handle = args.next().unwrap_or_else(|| usage());
            let rights = workspace_rights(&args.next().unwrap_or_else(|| usage()));
            if args.next().is_some() {
                usage();
            }
            let handle = client
                .vfs_dup_data(agent, handle, rights)
                .await
                .unwrap_or_else(|error| fail(error));
            print_json(&handle, "data handle");
            return;
        }
        "vfs-data-read" | "vfs-data-write" => {
            let agent = args.next().unwrap_or_else(|| usage());
            let handle = args.next().unwrap_or_else(|| usage());
            let value = args.next().unwrap_or_else(|| "{}".into());
            let value = serde_json::from_str(&value).unwrap_or_else(|_| usage());
            if args.next().is_some() {
                usage();
            }
            let value = if command == "vfs-data-read" {
                client.vfs_read_data(agent, handle, value).await
            } else {
                client.vfs_write_data(agent, handle, value).await
            }
            .unwrap_or_else(|error| fail(error));
            print_json(&value, "data result");
            return;
        }
        "vfs-data-list" | "vfs-data-stat" => {
            let agent = args.next().unwrap_or_else(|| usage());
            let handle = args.next().unwrap_or_else(|| usage());
            if args.next().is_some() {
                usage();
            }
            let value = if command == "vfs-data-list" {
                client.vfs_list_data(agent, handle).await
            } else {
                client.vfs_stat_data(agent, handle).await
            }
            .unwrap_or_else(|error| fail(error));
            print_json(&value, "data result");
            return;
        }
        "vfs-namespace-mounts" => {
            let agent = args.next().unwrap_or_else(|| usage());
            if args.next().is_some() {
                usage();
            }
            let view = client
                .vfs_namespace_mounts(agent)
                .await
                .unwrap_or_else(|error| fail(error));
            print_json(&view, "namespace mounts");
            return;
        }
        "vfs-mount-entries" => {
            let agent = args.next().unwrap_or_else(|| usage());
            let path = args.next().unwrap_or_else(|| usage());
            if args.next().is_some() {
                usage();
            }
            let view = client
                .vfs_mount_entries(agent, path)
                .await
                .unwrap_or_else(|error| fail(error));
            print_json(&view, "mount entries");
            return;
        }
        "vfs-mount" => {
            let agent = args.next().unwrap_or_else(|| usage());
            let table_id = args.next().unwrap_or_else(|| usage());
            let generation = args
                .next()
                .unwrap_or_else(|| usage())
                .parse::<u64>()
                .unwrap_or_else(|_| usage());
            let path = args.next().unwrap_or_else(|| usage());
            let kind = match args.next().unwrap_or_else(|| usage()).as_str() {
                "tools" => agent_sdk::MountKind::Tools,
                "workspace" => agent_sdk::MountKind::Workspace,
                "memory" => agent_sdk::MountKind::Memory,
                "kv" => agent_sdk::MountKind::Kv,
                "ipc" => agent_sdk::MountKind::Ipc,
                _ => usage(),
            };
            if args.next().is_some() {
                usage();
            }
            let view = client
                .vfs_mount(agent, table_id, generation, path, kind)
                .await
                .unwrap_or_else(|error| fail(error));
            print_json(&view, "namespace mounts");
            return;
        }
        "vfs-unmount" => {
            let agent = args.next().unwrap_or_else(|| usage());
            let table_id = args.next().unwrap_or_else(|| usage());
            let generation = args
                .next()
                .unwrap_or_else(|| usage())
                .parse::<u64>()
                .unwrap_or_else(|_| usage());
            let path = args.next().unwrap_or_else(|| usage());
            let mount = args.next().unwrap_or_else(|| usage());
            if args.next().is_some() {
                usage();
            }
            let view = client
                .vfs_unmount(agent, table_id, generation, path, mount)
                .await
                .unwrap_or_else(|error| fail(error));
            print_json(&view, "namespace mounts");
            return;
        }
        "vfs-workspace-open" => {
            let agent = args.next().unwrap_or_else(|| usage());
            let path = args.next().unwrap_or_else(|| usage());
            let request = workspace_request(path, &mut args);
            let handle = client
                .vfs_open_workspace(agent, request)
                .await
                .unwrap_or_else(|error| fail(error));
            print_json(&handle, "workspace handle");
            return;
        }
        "vfs-open-at" => {
            let agent = args.next().unwrap_or_else(|| usage());
            let parent = args.next().unwrap_or_else(|| usage());
            let path = args.next().unwrap_or_else(|| usage());
            let request = workspace_request(path, &mut args);
            let handle = client
                .vfs_open_at(agent, parent, request)
                .await
                .unwrap_or_else(|error| fail(error));
            print_json(&handle, "workspace child handle");
            return;
        }
        "vfs-dup" => {
            let agent = args.next().unwrap_or_else(|| usage());
            let handle = args.next().unwrap_or_else(|| usage());
            let rights = workspace_rights(&args.next().unwrap_or_else(|| usage()));
            if args.next().is_some() {
                usage();
            }
            let duplicate = client
                .vfs_dup_workspace(agent, handle, rights)
                .await
                .unwrap_or_else(|error| fail(error));
            print_json(&duplicate, "workspace duplicate");
            return;
        }
        "vfs-read" => {
            let agent = args.next().unwrap_or_else(|| usage());
            let handle = args.next().unwrap_or_else(|| usage());
            let offset = args
                .next()
                .map(|value| value.parse().unwrap_or_else(|_| usage()))
                .unwrap_or(0);
            let max_bytes = args
                .next()
                .map(|value| value.parse().unwrap_or_else(|_| usage()))
                .unwrap_or(64 * 1024);
            if args.next().is_some() {
                usage();
            }
            let chunk = client
                .vfs_read_workspace(agent, handle, offset, max_bytes)
                .await
                .unwrap_or_else(|error| fail(error));
            print_json(&chunk, "workspace read");
            return;
        }
        "vfs-write" => {
            let agent = args.next().unwrap_or_else(|| usage());
            let handle = args.next().unwrap_or_else(|| usage());
            let source = args.next().unwrap_or_else(|| usage());
            if args.next().is_some() {
                usage();
            }
            let mut bytes = Vec::new();
            let limit = kernel::vfs::workspace::MAX_WORKSPACE_TRANSFER_BYTES as u64 + 1;
            if source == "-" {
                std::io::stdin()
                    .take(limit)
                    .read_to_end(&mut bytes)
                    .unwrap_or_else(|error| fail(agent_sdk::SdkError::Transport(error)));
            } else {
                std::fs::File::open(source)
                    .unwrap_or_else(|error| fail(agent_sdk::SdkError::Transport(error)))
                    .take(limit)
                    .read_to_end(&mut bytes)
                    .unwrap_or_else(|error| fail(agent_sdk::SdkError::Transport(error)));
            }
            let written_bytes = client
                .vfs_write_bytes(agent, handle, &bytes)
                .await
                .unwrap_or_else(|error| fail(error));
            print_json(
                &serde_json::json!({"written_bytes":written_bytes}),
                "workspace write",
            );
            return;
        }
        "vfs-list" | "vfs-stat" => {
            let agent = args.next().unwrap_or_else(|| usage());
            let handle = args.next().unwrap_or_else(|| usage());
            if args.next().is_some() {
                usage();
            }
            if command == "vfs-list" {
                let entries = client
                    .vfs_list_workspace(agent, handle)
                    .await
                    .unwrap_or_else(|error| fail(error));
                print_json(&entries, "workspace directory");
            } else {
                let metadata = client
                    .vfs_stat_workspace(agent, handle)
                    .await
                    .unwrap_or_else(|error| fail(error));
                print_json(&metadata, "workspace metadata");
            }
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
        "gate-stats" => {
            if args.next().is_some() {
                usage();
            }
            let stats = client
                .gate_stats()
                .await
                .unwrap_or_else(|error| fail(error));
            print_json(&stats, "gate enforcement counters");
            return;
        }
        "node-control-audit" => {
            let limit = parse_audit_limit(args.collect::<Vec<_>>());
            let entries = client
                .node_control_audit(limit)
                .await
                .unwrap_or_else(|error| fail(error));
            print_json(&entries, "node control audit");
            return;
        }
        "cluster-membership-audit" => {
            let limit = parse_audit_limit(args.collect::<Vec<_>>());
            let entries = client
                .cluster_membership_audit(limit)
                .await
                .unwrap_or_else(|error| fail(error));
            print_json(&entries, "cluster membership audit");
            return;
        }
        "cluster-certificate-rollout-audit" => {
            let limit = parse_audit_limit(args.collect::<Vec<_>>());
            let entries = client
                .cluster_certificate_rollout_audit(limit)
                .await
                .unwrap_or_else(|error| fail(error));
            print_json(&entries, "cluster certificate rollout audit");
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
