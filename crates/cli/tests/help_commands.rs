//! `--help` must be answerable without a kernel, a database, or a server.
//!
//! Both shipped operator binaries previously reached initialization before
//! looking at the flag: `agent --help` booted the kernel, created the data
//! directory, persisted a `cli-agent` row, and then failed on an unreachable
//! provider, while `agentctl --help` opened a TCP connection and reported a
//! transport error. Documentation requests must stay free of side effects, and
//! argument errors must stay distinguishable from operational failures.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// A disposable directory removed on drop, so a failing assertion still cleans
/// up. `uuid` is already a dev-dependency here; this avoids pinning a third
/// copy of `tempfile` outside the workspace dependency table.
struct IsolatedHome(PathBuf);

impl IsolatedHome {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("agentos-help-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&path).expect("isolated home");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for IsolatedHome {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Run `binary` with `args` against an isolated, empty home so any durable
/// side effect lands inside `home` where the caller can detect it.
fn run_isolated(path: &str, args: &[&str], home: &Path) -> Output {
    let mut command = Command::new(path);
    command.args(args);
    // `dirs` resolves the data/config directories from these; covering the
    // Unix and Windows variants keeps the isolation valid on every platform
    // the release matrix builds.
    for key in [
        "HOME",
        "XDG_DATA_HOME",
        "XDG_CONFIG_HOME",
        "APPDATA",
        "LOCALAPPDATA",
    ] {
        command.env(key, home);
    }
    // A developer shell may export these; the help path must not consult them.
    for key in ["AGENT_SERVER_TOKEN", "AGENT_SERVER_ADDR"] {
        command.env_remove(key);
    }
    command
        .output()
        .unwrap_or_else(|error| panic!("run {path} {args:?}: {error}"))
}

fn entries(directory: &Path) -> Vec<String> {
    let Ok(read) = std::fs::read_dir(directory) else {
        return Vec::new();
    };
    read.filter_map(Result::ok)
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect()
}

fn assert_help_is_clean(binary: &str, path: &str) {
    for flag in ["--help", "-h"] {
        let home = IsolatedHome::new();
        let output = run_isolated(path, &[flag], home.path());

        assert!(
            output.status.success(),
            "{binary} {flag} must exit zero, got {:?}: {}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8(output.stdout).expect("help output is UTF-8");
        assert!(
            stdout.contains("USAGE") || stdout.starts_with("usage:"),
            "{binary} {flag} did not print usage: {stdout}"
        );
        assert!(
            output.stderr.is_empty(),
            "{binary} {flag} wrote to stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            entries(home.path()).is_empty(),
            "{binary} {flag} created durable state: {:?}",
            entries(home.path())
        );
    }
}

fn assert_unknown_flag_is_a_usage_error(binary: &str, path: &str) {
    let home = IsolatedHome::new();
    let output = run_isolated(path, &["--definitely-not-a-flag"], home.path());

    assert_eq!(
        output.status.code(),
        Some(2),
        "{binary} must reject an unknown option with the usage exit code, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8(output.stderr).expect("diagnostic is UTF-8");
    assert!(
        stderr.contains("unrecognized option '--definitely-not-a-flag'"),
        "{binary} did not name the offending option: {stderr}"
    );
    assert!(
        entries(home.path()).is_empty(),
        "{binary} created durable state while rejecting an unknown option: {:?}",
        entries(home.path())
    );
}

#[test]
fn shipped_operator_binaries_print_help_without_side_effects() {
    assert_help_is_clean("agent", env!("CARGO_BIN_EXE_agent"));
    assert_help_is_clean("agentctl", env!("CARGO_BIN_EXE_agentctl"));
}

#[test]
fn shipped_operator_binaries_reject_unknown_options_before_doing_work() {
    assert_unknown_flag_is_a_usage_error("agent", env!("CARGO_BIN_EXE_agent"));
    assert_unknown_flag_is_a_usage_error("agentctl", env!("CARGO_BIN_EXE_agentctl"));
}
