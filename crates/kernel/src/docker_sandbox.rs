//! Hardened rootless OCI execution for container-isolated agents.
//!
//! This backend deliberately supports one narrow contract: a digest-pinned
//! image, no network, one agent workspace mount, bounded resources, no added
//! capabilities, and no shell interpretation. It refuses to run against a
//! rootful Docker daemon.

use std::path::Path;
use std::process::Stdio;

use tokio::io::AsyncReadExt;

use crate::AgentId;

const SANDBOX_LABEL: &str = "aiagentos.sandbox=true";
const MAX_OUTPUT_BYTES: u64 = 1024 * 1024;
const DEFAULT_MEMORY_BYTES: u64 = 256 * 1024 * 1024;
const DEFAULT_PIDS_LIMIT: u32 = 64;

pub fn validate_digest_image(image: &str) -> Result<(), String> {
    let Some((name, digest)) = image.rsplit_once("@sha256:") else {
        return Err("container image must be pinned by sha256 digest".into());
    };
    if name.trim().is_empty()
        || digest.len() != 64
        || !digest.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err("container image must be pinned by a valid sha256 digest".into());
    }
    Ok(())
}

fn container_name(agent_id: AgentId) -> String {
    format!(
        "aiagentos-{}-{}",
        agent_id.simple(),
        uuid::Uuid::new_v4().simple()
    )
}

fn hardened_run_args(
    name: &str,
    agent_id: AgentId,
    workspace: &Path,
    image: &str,
    memory_bytes: Option<u64>,
    program: &str,
    arguments: &[String],
) -> Result<Vec<String>, String> {
    validate_digest_image(image)?;
    if program.trim().is_empty() || program.contains('\0') {
        return Err("container program is invalid".into());
    }
    if arguments.iter().any(|argument| argument.contains('\0')) {
        return Err("container argument is invalid".into());
    }
    let workspace = workspace
        .to_str()
        .ok_or_else(|| "container workspace must be valid UTF-8".to_string())?;
    let memory = memory_bytes
        .unwrap_or(DEFAULT_MEMORY_BYTES)
        .max(16 * 1024 * 1024);

    let mut args = vec![
        "run".into(),
        "--rm".into(),
        "--name".into(),
        name.into(),
        "--label".into(),
        SANDBOX_LABEL.into(),
        "--label".into(),
        format!("aiagentos.agent={agent_id}"),
        "--network".into(),
        "none".into(),
        "--read-only".into(),
        "--cap-drop".into(),
        "ALL".into(),
        "--security-opt".into(),
        "no-new-privileges=true".into(),
        "--pids-limit".into(),
        DEFAULT_PIDS_LIMIT.to_string(),
        "--memory".into(),
        memory.to_string(),
        "--memory-swap".into(),
        memory.to_string(),
        "--cpus".into(),
        "1.0".into(),
        "--ulimit".into(),
        "nofile=1024:1024".into(),
        "--ipc".into(),
        "none".into(),
        "--init".into(),
        // Docker root is mapped to the unprivileged service user by the
        // mandatory rootless daemon. This keeps a mode-0700 host workspace
        // usable without granting any host-root identity.
        "--user".into(),
        "0:0".into(),
        "--workdir".into(),
        "/workspace".into(),
        "--mount".into(),
        // Bind mounts are read-write by default. Docker's structured
        // `--mount` syntax rejects a standalone `rw` field.
        format!("type=bind,src={workspace},dst=/workspace"),
        "--tmpfs".into(),
        "/tmp:rw,noexec,nosuid,nodev,size=67108864,mode=700".into(),
        image.into(),
        program.into(),
    ];
    args.extend(arguments.iter().cloned());
    Ok(args)
}

async fn docker_is_rootless() -> Result<(), String> {
    let output = tokio::process::Command::new("docker")
        .args(["info", "--format", "{{json .SecurityOptions}}"])
        .output()
        .await
        .map_err(|_| "rootless Docker is unavailable".to_string())?;
    if !output.status.success()
        || !String::from_utf8_lossy(&output.stdout)
            .to_ascii_lowercase()
            .contains("rootless")
    {
        return Err("container isolation requires a rootless Docker daemon".into());
    }
    Ok(())
}

async fn verify_local_image(image: &str) -> Result<(), String> {
    validate_digest_image(image)?;
    let expected_digest = image
        .rsplit_once('@')
        .map(|(_, digest)| digest)
        .ok_or_else(|| "container image digest is missing".to_string())?;
    let output = tokio::process::Command::new("docker")
        .args([
            "image",
            "inspect",
            "--format",
            "{{json .RepoDigests}}",
            image,
        ])
        .output()
        .await
        .map_err(|_| "pinned container image is unavailable".to_string())?;
    let repo_digests = String::from_utf8_lossy(&output.stdout);
    if !output.status.success() || !repo_digests.contains(expected_digest) {
        return Err(
            "pinned container image is unavailable or its digest could not be verified".into(),
        );
    }
    Ok(())
}

struct CleanupGuard {
    name: String,
    armed: bool,
}

impl CleanupGuard {
    async fn cleanup(mut self) -> Result<(), String> {
        let _ = tokio::process::Command::new("docker")
            .args(["rm", "-f", &self.name])
            .output()
            .await;
        let inspection = tokio::process::Command::new("docker")
            .args(["container", "inspect", &self.name])
            .output()
            .await
            .map_err(|_| "container cleanup could not be verified".to_string())?;
        if inspection.status.success() {
            return Err("container cleanup did not remove the sandbox".into());
        }
        let inspection_error = String::from_utf8_lossy(&inspection.stderr).to_ascii_lowercase();
        if !inspection_error.contains("no such object")
            && !inspection_error.contains("no such container")
        {
            return Err("container cleanup could not be verified".into());
        }
        self.armed = false;
        Ok(())
    }
}

impl Drop for CleanupGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        // Cancellation may drop this future while a lifecycle/tool guard is
        // unwinding. Remove the exact, unguessable container synchronously so
        // that guard cannot drain before the process, mount, and network
        // namespace have been torn down. A process crash is handled by the
        // label-scoped startup reconciliation below.
        let _ = std::process::Command::new("docker")
            .args(["rm", "-f", &self.name])
            .output();
    }
}

/// Execute one command inside a fresh hardened rootless container.
pub async fn execute_hardened(
    agent_id: AgentId,
    workspace: &Path,
    image: &str,
    memory_bytes: Option<u64>,
    program: &str,
    arguments: &[String],
) -> Result<serde_json::Value, String> {
    docker_is_rootless().await?;
    verify_local_image(image).await?;

    let name = container_name(agent_id);
    let args = hardened_run_args(
        &name,
        agent_id,
        workspace,
        image,
        memory_bytes,
        program,
        arguments,
    )?;
    let mut child = tokio::process::Command::new("docker");
    child
        .args(&args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let mut child = child
        .spawn()
        .map_err(|_| "failed to start hardened container".to_string())?;
    let cleanup = CleanupGuard { name, armed: true };

    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| "container stdout unavailable".to_string())?
        .take(MAX_OUTPUT_BYTES + 1);
    let mut stderr = child
        .stderr
        .take()
        .ok_or_else(|| "container stderr unavailable".to_string())?
        .take(MAX_OUTPUT_BYTES + 1);
    let stdout_read = tokio::spawn(async move {
        let mut output = Vec::new();
        stdout.read_to_end(&mut output).await.map(|_| output)
    });
    let stderr_read = tokio::spawn(async move {
        let mut output = Vec::new();
        stderr.read_to_end(&mut output).await.map(|_| output)
    });
    let status = child
        .wait()
        .await
        .map_err(|_| "container execution failed".to_string())?;
    let stdout = stdout_read
        .await
        .map_err(|_| "container stdout task failed".to_string())?
        .map_err(|_| "container stdout read failed".to_string())?;
    let stderr = stderr_read
        .await
        .map_err(|_| "container stderr task failed".to_string())?
        .map_err(|_| "container stderr read failed".to_string())?;
    cleanup.cleanup().await?;

    if stdout.len() as u64 > MAX_OUTPUT_BYTES || stderr.len() as u64 > MAX_OUTPUT_BYTES {
        return Err("container output exceeded sandbox limit".into());
    }
    Ok(serde_json::json!({
        "stdout": String::from_utf8_lossy(&stdout),
        "stderr": String::from_utf8_lossy(&stderr),
        "exit_code": status.code(),
    }))
}

/// Remove containers left by an abruptly terminated AgentOS process. This is
/// intentionally label-scoped and runs only against a verified rootless daemon.
#[cfg(target_os = "linux")]
fn cleanup_filter_best_effort(filter: &str) {
    let info = std::process::Command::new("docker")
        .args(["info", "--format", "{{json .SecurityOptions}}"])
        .output();
    let Ok(info) = info else {
        return;
    };
    if !info.status.success()
        || !String::from_utf8_lossy(&info.stdout)
            .to_ascii_lowercase()
            .contains("rootless")
    {
        return;
    }
    let output = std::process::Command::new("docker")
        .args(["ps", "-aq", "--filter", filter])
        .output();
    let Ok(output) = output else {
        return;
    };
    for id in String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter(|id| !id.trim().is_empty())
    {
        let _ = std::process::Command::new("docker")
            .args(["rm", "-f", id])
            .output();
    }
}

#[cfg(target_os = "linux")]
pub fn cleanup_orphans_best_effort() {
    cleanup_filter_best_effort(&format!("label={SANDBOX_LABEL}"));
}

#[cfg(target_os = "linux")]
pub fn cleanup_agent_best_effort(agent_id: AgentId) {
    cleanup_filter_best_effort(&format!("label=aiagentos.agent={agent_id}"));
}

#[cfg(test)]
mod tests {
    use super::*;

    const PINNED: &str =
        "registry.example/agent@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn mutable_or_malformed_images_are_rejected() {
        assert!(validate_digest_image("ubuntu:22.04").is_err());
        assert!(validate_digest_image("ubuntu@sha256:abc").is_err());
        assert!(validate_digest_image(PINNED).is_ok());
    }

    #[test]
    fn run_contract_is_rootless_hardened_and_has_no_shell() {
        let agent = uuid::Uuid::new_v4();
        let args = hardened_run_args(
            "test-container",
            agent,
            Path::new("/private/workspace"),
            PINNED,
            Some(64 * 1024 * 1024),
            "/bin/echo",
            &["hello; touch /escaped".into()],
        )
        .unwrap();
        let joined = args.join(" ");
        for required in [
            "--network none",
            "--read-only",
            "--cap-drop ALL",
            "--security-opt no-new-privileges=true",
            "--pids-limit 64",
            "--memory 67108864",
            "--memory-swap 67108864",
            "--cpus 1.0",
            "--ulimit nofile=1024:1024",
            "--ipc none",
            "--init",
            "--user 0:0",
            "--workdir /workspace",
            "type=bind,src=/private/workspace,dst=/workspace",
            "/tmp:rw,noexec,nosuid,nodev",
            PINNED,
            "/bin/echo",
        ] {
            assert!(
                joined.contains(required),
                "missing hardened argument: {required}"
            );
        }
        assert!(!args
            .iter()
            .any(|argument| argument == "sh" || argument == "-c"));
        assert!(
            !args
                .iter()
                .any(|argument| argument == "-e" || argument == "--env"),
            "host credentials and environment variables must not be inherited"
        );
        assert_eq!(args.last().unwrap(), "hello; touch /escaped");
    }

    #[cfg(target_os = "linux")]
    async fn listed_containers(filter: &str) -> Vec<String> {
        let output = tokio::process::Command::new("docker")
            .args(["ps", "-aq", "--filter", filter])
            .output()
            .await
            .expect("query rootless Docker containers");
        assert!(output.status.success());
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(str::to_string)
            .collect()
    }

    /// Live qualification is kept out of ordinary cross-platform unit tests
    /// because it requires a Linux host with a rootless Docker daemon and a
    /// pre-pulled digest-pinned image. The extended-security workflow supplies
    /// both and runs this test explicitly.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    #[ignore = "requires a rootless Docker daemon and AGENTOS_SANDBOX_TEST_IMAGE"]
    async fn live_rootless_container_blocks_escape_and_cleans_cancellation_and_crash() {
        let image = std::env::var("AGENTOS_SANDBOX_TEST_IMAGE")
            .expect("AGENTOS_SANDBOX_TEST_IMAGE must name a pulled digest-pinned image");
        docker_is_rootless().await.expect("rootless Docker");
        verify_local_image(&image)
            .await
            .expect("pinned local image");

        let workspace =
            std::env::temp_dir().join(format!("aiagentos-live-container-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&workspace).unwrap();
        let agent = uuid::Uuid::new_v4();
        let script = concat!(
            "set -eu; ",
            "test \"$(id -u)\" = 0; ",
            "grep -Eq '^NoNewPrivs:[[:space:]]+1$' /proc/self/status; ",
            "grep -Eq '^CapEff:[[:space:]]+0+$' /proc/self/status; ",
            "! touch /etc/aiagentos-root-write; ",
            "test ! -e /workspace/foreign-agent-secret; ",
            "printf qualified > /workspace/qualification.txt; ",
            "! wget -q -T 2 -O- http://1.1.1.1"
        );
        let result = execute_hardened(
            agent,
            &workspace,
            &image,
            Some(64 * 1024 * 1024),
            "/bin/sh",
            &["-c".into(), script.into()],
        )
        .await
        .expect("hardened container execution");
        assert_eq!(
            result["exit_code"], 0,
            "qualification command failed: stdout={} stderr={}",
            result["stdout"], result["stderr"]
        );
        assert_eq!(
            std::fs::read_to_string(workspace.join("qualification.txt")).unwrap(),
            "qualified"
        );
        assert!(listed_containers(&format!("label=aiagentos.agent={agent}"))
            .await
            .is_empty());

        let cancelled_agent = uuid::Uuid::new_v4();
        let cancelled = tokio::time::timeout(
            std::time::Duration::from_millis(750),
            execute_hardened(
                cancelled_agent,
                &workspace,
                &image,
                Some(64 * 1024 * 1024),
                "/bin/sh",
                &["-c".into(), "sleep 300".into()],
            ),
        )
        .await;
        assert!(
            cancelled.is_err(),
            "the qualification command must be cancelled"
        );
        assert!(
            listed_containers(&format!("label=aiagentos.agent={cancelled_agent}"))
                .await
                .is_empty(),
            "cancellation must synchronously remove the container"
        );

        let orphan_agent = uuid::Uuid::new_v4();
        let orphan_name = container_name(orphan_agent);
        let started = tokio::process::Command::new("docker")
            .args([
                "run",
                "-d",
                "--name",
                &orphan_name,
                "--label",
                SANDBOX_LABEL,
                "--label",
                &format!("aiagentos.agent={orphan_agent}"),
                "--network",
                "none",
                &image,
                "/bin/sh",
                "-c",
                "sleep 300",
            ])
            .output()
            .await
            .expect("start simulated crash orphan");
        assert!(
            started.status.success(),
            "{}",
            String::from_utf8_lossy(&started.stderr)
        );
        assert!(!listed_containers(&format!("name={orphan_name}"))
            .await
            .is_empty());
        cleanup_orphans_best_effort();
        assert!(
            listed_containers(&format!("name={orphan_name}"))
                .await
                .is_empty(),
            "startup reconciliation must remove crash-orphaned sandboxes"
        );

        std::fs::remove_dir_all(workspace).unwrap();
    }
}
