use std::process::Command;

#[test]
fn shipped_tui_reports_the_exact_build_version_without_connecting() {
    for flag in ["--version", "-V"] {
        let output = Command::new(env!("CARGO_BIN_EXE_agent-tui"))
            .arg(flag)
            .output()
            .unwrap_or_else(|error| panic!("run agent-tui {flag}: {error}"));
        assert!(
            output.status.success(),
            "agent-tui {flag} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            String::from_utf8(output.stdout).expect("version output is UTF-8"),
            format!("agent-tui {}\n", env!("CARGO_PKG_VERSION"))
        );
        assert!(
            output.stderr.is_empty(),
            "agent-tui {flag} wrote unexpected stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
