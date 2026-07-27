//! Destructive host-filesystem exhaustion qualification.
//!
//! The caller must provide a small, explicitly marked disposable filesystem.
//! This binary fills that filesystem to a real host `ENOSPC`, exercises a
//! SQLite mutation, restores capacity, and proves rollback, recovery,
//! integrity, and reopen behavior. It never turns fixture evidence into a
//! whole-product production claim.

use std::collections::BTreeMap;
#[cfg(unix)]
use std::ffi::CString;
use std::fs::{self, OpenOptions};
use std::io::{Error as IoError, Write};
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use chrono::Utc;
use kernel::context::SqliteContextManager;
use kernel::AgentId;
use serde::Serialize;

const SCHEMA_VERSION: u32 = 1;
const QUALIFICATION_CLASS: &str = "destructive_host_filesystem_enospc";
const CONFIRMATION_ENV: &str = "AGENTOS_DESTRUCTIVE_STORAGE_QUALIFICATION";
const CONFIRMATION_VALUE: &str = "I_UNDERSTAND_THIS_DISPOSABLE_FILESYSTEM_WILL_BE_FILLED";
const MARKER_NAME: &str = ".agentos-disposable-storage";
const MARKER_VALUE: &str = "AIAGENTOS_DISPOSABLE_STORAGE_QUALIFICATION_V1\n";
const MIN_FILESYSTEM_BYTES: u64 = 32 * 1024 * 1024;
const MAX_FILESYSTEM_BYTES: u64 = 128 * 1024 * 1024;
const FILL_CHUNK_BYTES: usize = 256 * 1024;
const ENOSPC_RAW_OS_ERROR: i32 = 28;

#[derive(Debug, Default)]
struct Cli {
    root: Option<PathBuf>,
    output: Option<PathBuf>,
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
    filesystem_total_bytes: u64,
    filesystem_available_before_bytes: u64,
    filesystem_available_exhausted_bytes: u64,
    filesystem_available_recovered_bytes: u64,
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
    checks: BTreeMap<&'static str, bool>,
    observations: BTreeMap<&'static str, u64>,
    passed: bool,
    caveats: Vec<&'static str>,
}

#[derive(Debug, Clone, Copy)]
struct FilesystemSpace {
    total: u64,
    available: u64,
}

fn parse_cli() -> Result<Cli, String> {
    parse_args(std::env::args().skip(1))
}

fn parse_args<I>(args: I) -> Result<Cli, String>
where
    I: IntoIterator<Item = String>,
{
    let mut cli = Cli::default();
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--root" => {
                cli.root = Some(PathBuf::from(args.next().ok_or("--root requires a path")?));
            }
            "--output" => {
                cli.output = Some(PathBuf::from(
                    args.next().ok_or("--output requires a path")?,
                ));
            }
            "--validate" => cli.validate_only = true,
            "-h" | "--help" => {
                println!(
                    "host-storage-qualification --validate | \\\n                     --root DISPOSABLE_MOUNT --output REPORT"
                );
                std::process::exit(0);
            }
            other => return Err(format!("unknown argument {other:?}")),
        }
    }
    if cli.validate_only {
        if cli.root.is_some() || cli.output.is_some() {
            return Err("--validate cannot be combined with --root or --output".into());
        }
    } else if cli.root.is_none() || cli.output.is_none() {
        return Err("qualification requires --root and --output".into());
    }
    Ok(cli)
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

#[cfg(unix)]
fn filesystem_space(path: &Path) -> Result<FilesystemSpace, String> {
    let bytes = path.as_os_str().as_bytes();
    let c_path = CString::new(bytes)
        .map_err(|_| format!("filesystem path contains NUL: {}", path.display()))?;
    let mut stat = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    // SAFETY: `c_path` is NUL-terminated and valid for this call; `statvfs`
    // initializes the output structure on success.
    let result = unsafe { libc::statvfs(c_path.as_ptr(), stat.as_mut_ptr()) };
    if result != 0 {
        return Err(format!(
            "statvfs {}: {}",
            path.display(),
            IoError::last_os_error()
        ));
    }
    // SAFETY: `statvfs` returned success and initialized `stat`.
    let stat = unsafe { stat.assume_init() };
    let fragment_size = u128::from(stat.f_frsize);
    let total = u128::from(stat.f_blocks).saturating_mul(fragment_size);
    let available = u128::from(stat.f_bavail).saturating_mul(fragment_size);
    Ok(FilesystemSpace {
        total: u64::try_from(total).unwrap_or(u64::MAX),
        available: u64::try_from(available).unwrap_or(u64::MAX),
    })
}

#[cfg(not(unix))]
fn filesystem_space(_path: &Path) -> Result<FilesystemSpace, String> {
    Err("filesystem space inspection requires Unix".into())
}

fn require_regular_non_symlink(path: &Path, label: &str) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("{label} {}: {error}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(format!("{label} must be a regular non-symlink file"));
    }
    Ok(())
}

fn validate_disposable_root(
    root: &Path,
    output: &Path,
) -> Result<(PathBuf, FilesystemSpace), String> {
    if std::env::consts::OS != "linux" {
        return Err("destructive host storage qualification requires Linux".into());
    }
    if std::env::var(CONFIRMATION_ENV).ok().as_deref() != Some(CONFIRMATION_VALUE) {
        return Err(format!(
            "{CONFIRMATION_ENV} must contain the exact destructive-test confirmation"
        ));
    }
    let root_metadata = fs::symlink_metadata(root)
        .map_err(|error| format!("inspect qualification root {}: {error}", root.display()))?;
    if root_metadata.file_type().is_symlink() || !root_metadata.is_dir() {
        return Err("qualification root must be a real directory".into());
    }
    let root = fs::canonicalize(root)
        .map_err(|error| format!("canonicalize qualification root: {error}"))?;
    if root == Path::new("/") {
        return Err("refusing to use the host root filesystem".into());
    }
    let marker = root.join(MARKER_NAME);
    require_regular_non_symlink(&marker, "qualification marker")?;
    let marker_value = fs::read_to_string(&marker)
        .map_err(|error| format!("read qualification marker: {error}"))?;
    if marker_value != MARKER_VALUE {
        return Err("qualification marker has the wrong exact value".into());
    }
    let output_parent = output
        .parent()
        .ok_or("output must have a parent directory")?;
    fs::create_dir_all(output_parent)
        .map_err(|error| format!("create output parent {}: {error}", output_parent.display()))?;
    let output_parent = fs::canonicalize(output_parent)
        .map_err(|error| format!("canonicalize output parent: {error}"))?;
    if output_parent.starts_with(&root) {
        return Err("report output must be outside the disposable filesystem".into());
    }
    let space = filesystem_space(&root)?;
    if !(MIN_FILESYSTEM_BYTES..=MAX_FILESYSTEM_BYTES).contains(&space.total) {
        return Err(format!(
            "disposable filesystem is {} bytes; required range is {}..={} bytes",
            space.total, MIN_FILESYSTEM_BYTES, MAX_FILESYSTEM_BYTES
        ));
    }
    Ok((root, space))
}

fn is_enospc(error: &IoError) -> bool {
    error.raw_os_error() == Some(ENOSPC_RAW_OS_ERROR)
}

fn fill_until_enospc(path: &Path) -> Result<(u64, bool), String> {
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .map_err(|error| format!("create filler {}: {error}", path.display()))?;
    let block = vec![0xA5_u8; FILL_CHUNK_BYTES];
    let mut written = 0_u64;
    loop {
        match file.write_all(&block) {
            Ok(()) => {
                written = written.saturating_add(block.len() as u64);
                if let Err(error) = file.sync_data() {
                    if is_enospc(&error) {
                        return Ok((written, true));
                    }
                    return Err(format!("sync filler: {error}"));
                }
            }
            Err(error) if is_enospc(&error) => return Ok((written, true)),
            Err(error) => return Err(format!("write filler: {error}")),
        }
    }
}

fn write_report(path: &Path, report: &QualificationReport) -> Result<(), String> {
    let json =
        serde_json::to_string_pretty(report).map_err(|error| format!("encode report: {error}"))?;
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .map_err(|error| format!("create report {}: {error}", path.display()))?;
    file.write_all(format!("{json}\n").as_bytes())
        .and_then(|()| file.sync_all())
        .map_err(|error| format!("write report {}: {error}", path.display()))
}

fn qualify(root: &Path, output: &Path) -> Result<(), String> {
    if cfg!(debug_assertions) {
        return Err("host storage qualification requires a --release build".into());
    }
    let (root, before) = validate_disposable_root(root, output)?;
    let work = root.join("agentos-host-storage");
    fs::create_dir(&work).map_err(|error| format!("create work directory: {error}"))?;
    let database = work.join("state.db");
    let filler = work.join("capacity-filler.bin");
    let agent_id = AgentId::new_v4();

    let manager = SqliteContextManager::new(&database)
        .map_err(|error| format!("create context manager: {error}"))?;
    manager
        .kv_put(agent_id, "baseline", "committed-before-host-enospc")
        .map_err(|error| format!("write baseline: {error}"))?;
    manager
        .checkpoint()
        .map_err(|error| format!("checkpoint baseline: {error}"))?;

    let (filler_bytes, filler_observed_enospc) = fill_until_enospc(&filler)?;
    let exhausted = filesystem_space(&root)?;
    let failed_write = manager.kv_put(agent_id, "must-rollback", &"x".repeat(1024 * 1024));
    let failed_write_is_full = failed_write
        .as_ref()
        .err()
        .map(ToString::to_string)
        .is_some_and(|message| {
            let message = message.to_ascii_lowercase();
            message.contains("database or disk is full")
                || message.contains("disk full")
                || message.contains("database is full")
        });

    fs::remove_file(&filler).map_err(|error| format!("remove filler: {error}"))?;
    let recovered_space = filesystem_space(&root)?;
    let baseline_preserved = manager
        .kv_get(agent_id, "baseline")
        .map_err(|error| format!("read baseline after recovery: {error}"))?
        .as_deref()
        == Some("committed-before-host-enospc");
    let failed_value_absent = manager
        .kv_get(agent_id, "must-rollback")
        .map_err(|error| format!("read rolled-back value: {error}"))?
        .is_none();
    let retry_succeeded = manager
        .kv_put(agent_id, "recovered", "committed-after-capacity-restored")
        .is_ok();
    manager
        .checkpoint()
        .map_err(|error| format!("checkpoint recovered database: {error}"))?;
    drop(manager);

    let connection = rusqlite::Connection::open(&database)
        .map_err(|error| format!("open for quick_check: {error}"))?;
    let quick_check: String = connection
        .query_row("PRAGMA quick_check", [], |row| row.get(0))
        .map_err(|error| format!("quick_check: {error}"))?;
    drop(connection);

    let reopened = SqliteContextManager::new(&database)
        .map_err(|error| format!("reopen context manager: {error}"))?;
    let reopen_preserved_both_commits = reopened
        .kv_get(agent_id, "baseline")
        .map_err(|error| format!("reopen baseline: {error}"))?
        .as_deref()
        == Some("committed-before-host-enospc")
        && reopened
            .kv_get(agent_id, "recovered")
            .map_err(|error| format!("reopen recovered value: {error}"))?
            .as_deref()
            == Some("committed-after-capacity-restored")
        && reopened
            .kv_get(agent_id, "must-rollback")
            .map_err(|error| format!("reopen rolled-back value: {error}"))?
            .is_none();

    let checks = BTreeMap::from([
        ("filler_observed_real_enospc", filler_observed_enospc),
        (
            "filesystem_capacity_was_exhausted",
            exhausted.available < FILL_CHUNK_BYTES as u64,
        ),
        ("sqlite_write_failed_with_disk_full", failed_write_is_full),
        ("previous_commit_preserved", baseline_preserved),
        ("failed_mutation_rolled_back", failed_value_absent),
        (
            "capacity_restoration_freed_space",
            recovered_space.available > exhausted.available,
        ),
        ("retry_succeeded_after_capacity_restored", retry_succeeded),
        ("database_quick_check_passed", quick_check == "ok"),
        (
            "reopen_preserved_exact_commits",
            reopen_preserved_both_commits,
        ),
    ]);
    let passed = checks.values().all(|value| *value);
    let report = QualificationReport {
        schema_version: SCHEMA_VERSION,
        suite: "host-storage-fault-qualification",
        generated_at: Utc::now().to_rfc3339(),
        qualification_class: QUALIFICATION_CLASS,
        proof_scope: "small_disposable_linux_filesystem_enospc_only",
        production_claim_allowed: false,
        build_profile: "release",
        source: source_metadata(),
        environment: EnvironmentMetadata {
            os: std::env::consts::OS,
            architecture: std::env::consts::ARCH,
            filesystem_total_bytes: before.total,
            filesystem_available_before_bytes: before.available,
            filesystem_available_exhausted_bytes: exhausted.available,
            filesystem_available_recovered_bytes: recovered_space.available,
        },
        checks,
        observations: BTreeMap::from([
            ("filler_bytes_written", filler_bytes),
            ("failed_payload_bytes", 1024 * 1024),
        ]),
        passed,
        caveats: vec![
            "This proves one real Linux host-filesystem ENOSPC and recovery path on a disposable ext4 image.",
            "It does not prove power-loss, torn writes, device loss, remote object storage, or every supported deployment filesystem.",
            "Production readiness still requires target-host qualification, measured RPO/RTO, and independent review.",
        ],
    };
    write_report(output, &report)?;
    if !passed {
        return Err("one or more host storage qualification checks failed".into());
    }
    Ok(())
}

fn run() -> Result<(), String> {
    let cli = parse_cli()?;
    if cli.validate_only {
        println!(
            "validated host storage qualification schema v{SCHEMA_VERSION}: {QUALIFICATION_CLASS}"
        );
        return Ok(());
    }
    qualify(
        cli.root.as_deref().expect("validated root"),
        cli.output.as_deref().expect("validated output"),
    )
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("host storage qualification failed: {error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_requires_explicit_root_and_external_report() {
        assert!(parse_args(["--root".into(), "/tmp/example".into()]).is_err());
        assert!(parse_args(["--output".into(), "/tmp/report.json".into()]).is_err());
        let cli = parse_args([
            "--root".into(),
            "/tmp/example".into(),
            "--output".into(),
            "/tmp/report.json".into(),
        ])
        .unwrap();
        assert_eq!(cli.root.as_deref(), Some(Path::new("/tmp/example")));
        assert_eq!(cli.output.as_deref(), Some(Path::new("/tmp/report.json")));
    }

    #[test]
    fn validate_is_isolated_from_destructive_arguments() {
        assert!(parse_args(["--validate".into()]).unwrap().validate_only);
        assert!(parse_args(["--validate".into(), "--root".into(), "/tmp/example".into()]).is_err());
    }

    #[test]
    fn enospc_detection_is_exact() {
        assert!(is_enospc(&IoError::from_raw_os_error(ENOSPC_RAW_OS_ERROR)));
        assert!(!is_enospc(&IoError::from_raw_os_error(5)));
    }
}
