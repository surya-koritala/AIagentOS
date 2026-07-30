use std::process::Command;

fn assert_exact_version(binary: &str, path: &str) {
    for flag in ["--version", "-V"] {
        let output = Command::new(path)
            .arg(flag)
            .output()
            .unwrap_or_else(|error| panic!("run {binary} {flag}: {error}"));
        assert!(
            output.status.success(),
            "{binary} {flag} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            String::from_utf8(output.stdout).expect("version output is UTF-8"),
            format!("{binary} {}\n", env!("CARGO_PKG_VERSION"))
        );
        assert!(
            output.stderr.is_empty(),
            "{binary} {flag} wrote unexpected stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn shipped_cli_binaries_report_the_exact_build_version_without_side_effects() {
    assert_exact_version("agent", env!("CARGO_BIN_EXE_agent"));
    assert_exact_version("agent-server", env!("CARGO_BIN_EXE_agent-server"));
    assert_exact_version("agentctl", env!("CARGO_BIN_EXE_agentctl"));
}
