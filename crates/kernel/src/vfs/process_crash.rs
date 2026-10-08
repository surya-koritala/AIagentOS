//! Abrupt-process evidence for ephemeral descriptors and atomic VFS writes.
//! Cut points cover a synced stage and completed rename before acknowledgement.
//! Process termination does not exercise physical power loss.

use super::workspace::{WorkspaceKind, WorkspaceOpenRequest, WorkspaceRight};
use crate::sandbox::{SandboxManager, WriteCrashBoundary, WRITE_CRASH_EXIT_CODE};
use crate::syscall_server::{Syscall, SyscallClient, SyscallReply, SyscallServer, WireErrorCode};
use crate::{AgentConfig, AgentKernelImpl, AgentState, IsolationLevel, Priority, SandboxConfig};
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::Path;
use std::process::Stdio;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};

const CHILD_TEST: &str = "vfs::process_crash::vfs_crash_child_process";
const READY_PREFIX: &str = "VFS_CRASH_READY ";
const ORIGINAL: &[u8] = b"original\0workspace bytes";
const REPLACEMENT: &[u8] = b"committed\0replacement bytes";
const KV_PATH: &str = "/kv/63726173682d6b6579";

#[derive(Debug, Serialize, Deserialize)]
struct Ready {
    address: std::net::SocketAddr,
    agent: String,
    tool: String,
    workspace: String,
    data: String,
}

fn file_request(path: &str, allow_missing: bool) -> WorkspaceOpenRequest {
    WorkspaceOpenRequest {
        path: path.into(),
        kind: WorkspaceKind::File,
        rights: vec![WorkspaceRight::Read, WorkspaceRight::Write],
        allow_missing,
    }
}

async fn connect(address: std::net::SocketAddr) -> SyscallClient {
    let mut client = SyscallClient::connect(address).await.unwrap();
    assert!(matches!(
        client
            .call(Syscall::Hello {
                protocol_version: 2
            })
            .await
            .unwrap(),
        SyscallReply::Hello { .. }
    ));
    client
}

async fn start_child(root: &Path, mode: &str) -> (Child, Ready) {
    let child_temporary = root.join("child-tmp");
    std::fs::create_dir_all(&child_temporary).unwrap();
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", CHILD_TEST, "--nocapture", "--test-threads=1"])
        .env("AGENTOS_VFS_CRASH_ROOT", root)
        .env("AGENTOS_VFS_CRASH_MODE", mode)
        .env("TMPDIR", &child_temporary)
        .env("TMP", &child_temporary)
        .env("TEMP", &child_temporary)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
    let ready = tokio::time::timeout(Duration::from_secs(30), async {
        while let Some(line) = lines.next_line().await.unwrap() {
            if let Some((_, payload)) = line.split_once(READY_PREFIX) {
                return serde_json::from_str::<Ready>(payload).unwrap();
            }
        }
        panic!("VFS child exited before reporting its actual crash boundary");
    })
    .await
    .expect("VFS child did not reach its crash boundary within 30 seconds");
    (child, ready)
}

async fn crash(mut child: Child) {
    child.start_kill().unwrap();
    let status = tokio::time::timeout(Duration::from_secs(10), child.wait())
        .await
        .expect("abrupt VFS child termination did not finish")
        .unwrap();
    assert!(
        !status.success(),
        "the child must die without graceful teardown"
    );
}

fn report_ready(ready: &Ready) {
    println!("{READY_PREFIX}{}", serde_json::to_string(ready).unwrap());
    std::io::stdout().flush().unwrap();
}

async fn wait_write_boundary(mut child: Child) {
    let status = tokio::time::timeout(Duration::from_secs(15), child.wait())
        .await
        .expect("write child did not exit at the armed boundary")
        .unwrap();
    assert_eq!(status.code(), Some(WRITE_CRASH_EXIT_CODE));
}

fn staged_files(root: &Path) -> Vec<std::path::PathBuf> {
    std::fs::read_dir(root.join("workspace"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.file_name().unwrap().to_string_lossy().starts_with(".aiagentos-write-"))
        .collect()
}

/// Invoked in a fresh OS process by the acceptance test below. Normal suite
/// discovery returns immediately; the parent test owns each process and root.
#[tokio::test]
async fn vfs_crash_child_process() {
    let Some(root) = std::env::var_os("AGENTOS_VFS_CRASH_ROOT") else {
        return;
    };
    let root = std::path::PathBuf::from(root);
    let mode = std::env::var("AGENTOS_VFS_CRASH_MODE").unwrap();
    let kernel = Arc::new(AgentKernelImpl::with_db_path(&root.join("state.db")).unwrap());
    let agent = if mode == "recover" {
        let agent: crate::AgentId = std::fs::read_to_string(root.join("agent-id"))
            .unwrap()
            .parse()
            .unwrap();
        assert_eq!(kernel.get_agent_status(agent).unwrap(), AgentState::Running);
        agent
    } else {
        let agent = kernel
            .create_agent_full(AgentConfig {
                name: "crash-boundary".into(),
                task: "VFS process-crash fixture".into(),
                llm_provider: "stub".into(),
                permission_profile: "standard".into(),
                priority: Priority::default(),
                sandbox_config: Some(SandboxConfig {
                    workspace_dir: root.join("workspace"),
                    isolation_level: IsolationLevel::Filesystem,
                    allowed_network_hosts: Some(Vec::new()),
                    max_disk_usage_bytes: Some(1024 * 1024),
                    max_memory_bytes: None,
                    container_image: None,
                }),
            })
            .await
            .unwrap()
            .id;
        std::fs::write(root.join("agent-id"), agent.to_string()).unwrap();
        agent
    };
    let server = SyscallServer::bind(kernel.clone(), "127.0.0.1:0")
        .await
        .unwrap();
    let address = server.local_addr().unwrap();
    tokio::spawn(server.serve());
    let mut client = connect(address).await;
    let mut ready = Ready {
        address,
        agent: agent.to_string(),
        tool: String::new(),
        workspace: String::new(),
        data: String::new(),
    };
    if mode == "recover" {
        assert_eq!(kernel.get_agent_status(agent).unwrap(), AgentState::Running);
        assert_eq!(kernel.vfs_mounts(agent).unwrap().open_handles, 0);
    } else {
        ready.tool = match client
            .call(Syscall::VfsOpen {
                agent_id: ready.agent.clone(),
                path: "/tools/read_file".into(),
            })
            .await
            .unwrap()
        {
            SyscallReply::VfsOpened { handle } => handle.id,
            other => panic!("tool open failed: {other:?}"),
        };
        ready.workspace = match client
            .call(Syscall::VfsOpenWorkspace {
                agent_id: ready.agent.clone(),
                request: file_request("/workspace/proof.bin", false),
            })
            .await
            .unwrap()
        {
            SyscallReply::WorkspaceOpened { handle } => handle.id,
            other => panic!("workspace open failed: {other:?}"),
        };
        ready.data = match client
            .call(Syscall::VfsOpenData {
                agent_id: ready.agent.clone(),
                path: KV_PATH.into(),
                rights: vec![WorkspaceRight::Read, WorkspaceRight::Write],
            })
            .await
            .unwrap()
        {
            SyscallReply::VfsDataOpened { handle } => handle.id,
            other => panic!("KV open failed: {other:?}"),
        };
        assert!(matches!(
            client
                .call(Syscall::VfsWriteData {
                    agent_id: ready.agent.clone(),
                    handle: ready.data.clone(),
                    args: serde_json::json!({"value":"committed before crash"}),
                })
                .await
                .unwrap(),
            SyscallReply::ToolResult { .. }
        ));
        if matches!(mode.as_str(), "after-stage-sync" | "after-rename") {
            let sandbox = kernel.sandbox_manager.get_sandbox_for_agent(agent).unwrap();
            let boundary = if mode == "after-stage-sync" {
                WriteCrashBoundary::AfterStageSync
            } else {
                WriteCrashBoundary::AfterRename
            };
            kernel.sandbox_manager.crash_next_write_for_test(sandbox, boundary);
            // The parent owns the handle identities before the syscall reaches
            // its cut point; exit code 73 proves the actual boundary was reached.
            report_ready(&ready);
            let reply = client.call(Syscall::VfsWriteWorkspace {
                agent_id: ready.agent.clone(),
                handle: ready.workspace.clone(),
                data_base64: base64::engine::general_purpose::STANDARD.encode(REPLACEMENT),
            }).await;
            panic!("armed write boundary did not terminate the child: {reply:?}");
        } else if mode == "committed-write" {
            assert!(matches!(client.call(Syscall::VfsWriteWorkspace {
                agent_id: ready.agent.clone(), handle: ready.workspace.clone(),
                data_base64: base64::engine::general_purpose::STANDARD.encode(REPLACEMENT),
            }).await.unwrap(), SyscallReply::WorkspaceWritten { written_bytes } if written_bytes == REPLACEMENT.len() as u64));
        } else {
            let (entered, _release, _) = kernel.sandbox_manager.pause_next_filesystem_for_test();
            let request = if mode == "pending-open" {
                Syscall::VfsOpenWorkspace {
                    agent_id: ready.agent.clone(),
                    request: file_request("/workspace/pending.bin", true),
                }
            } else {
                assert_eq!(mode, "pending-write");
                Syscall::VfsWriteWorkspace {
                    agent_id: ready.agent.clone(),
                    handle: ready.workspace.clone(),
                    data_base64: base64::engine::general_purpose::STANDARD.encode(REPLACEMENT),
                }
            };
            tokio::spawn(async move { client.call(request).await.unwrap() });
            tokio::time::timeout(Duration::from_secs(10), async {
                while !entered.load(Ordering::Acquire) {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
            })
            .await
            .expect("the public VFS operation was not admitted into its controlled worker");
        }
    }
    report_ready(&ready);
    std::future::pending::<()>().await;
}

#[tokio::test]
async fn abrupt_process_crash_revokes_handles_and_reopens_committed_vfs_data() {
    for mode in ["pending-open", "pending-write", "after-stage-sync", "after-rename", "committed-write"] {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join("workspace")).unwrap();
        std::fs::write(root.path().join("workspace/proof.bin"), ORIGINAL).unwrap();
        #[cfg(unix)]
        let original_permissions = {
            use std::os::unix::fs::PermissionsExt;
            std::fs::metadata(root.path().join("workspace/proof.bin"))
                .unwrap()
                .permissions()
                .mode() & 0o777
        };
        let (child, old) = start_child(root.path(), mode).await;
        if matches!(mode, "after-stage-sync" | "after-rename") {
            wait_write_boundary(child).await;
        } else {
            crash(child).await;
        }
        let expected = if matches!(mode, "after-rename" | "committed-write") {
            REPLACEMENT
        } else {
            ORIGINAL
        };
        assert_eq!(
            std::fs::read(root.path().join("workspace/proof.bin")).unwrap(),
            expected
        );
        assert!(!root.path().join("workspace/pending.bin").exists());
        let stages = staged_files(root.path());
        if mode == "after-stage-sync" {
            assert_eq!(stages.len(), 1, "cut point must leave the synced uncommitted stage");
            assert_eq!(std::fs::read(&stages[0]).unwrap(), REPLACEMENT);
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                assert_eq!(std::fs::metadata(&stages[0]).unwrap().permissions().mode() & 0o777, original_permissions);
            }
        } else {
            assert!(stages.is_empty());
        }
        assert_eq!(
            std::fs::read_dir(root.path().join("workspace"))
                .unwrap()
                .count(),
            1 + stages.len()
        );

        let (recovered, fresh) = start_child(root.path(), "recover").await;
        let retained_stages = staged_files(root.path());
        assert!(retained_stages.iter().all(|path| stages.contains(path)), "recovery must not create additional staging files");
        for path in &retained_stages {
            assert_eq!(std::fs::read(path).unwrap(), REPLACEMENT);
        }
        println!("VFS_WRITE_CRASH {}", serde_json::json!({
            "boundary": mode,
            "stage_files_before_restart": stages.len(),
            "stage_files_after_restart": retained_stages.len(),
            "power_loss_exercised": false,
        }));
        assert_eq!(fresh.agent, old.agent);
        let mut client = connect(fresh.address).await;
        for request in [
            Syscall::VfsInvoke {
                agent_id: old.agent.clone(),
                handle: old.tool,
                args: serde_json::json!({"path":"proof.bin"}),
            },
            Syscall::VfsReadWorkspace {
                agent_id: old.agent.clone(),
                handle: old.workspace,
                offset: 0,
                max_bytes: 256,
            },
            Syscall::VfsReadData {
                agent_id: old.agent.clone(),
                handle: old.data,
                args: serde_json::json!({}),
            },
        ] {
            assert!(matches!(
                client.call(request).await.unwrap(),
                SyscallReply::TypedError {
                    code: WireErrorCode::NotFound,
                    ..
                }
            ));
        }
        let handle = match client
            .call(Syscall::VfsOpenWorkspace {
                agent_id: fresh.agent.clone(),
                request: file_request("/workspace/proof.bin", false),
            })
            .await
            .unwrap()
        {
            SyscallReply::WorkspaceOpened { handle } => handle.id,
            other => panic!("fresh authorized workspace open failed: {other:?}"),
        };
        match client
            .call(Syscall::VfsReadWorkspace {
                agent_id: fresh.agent.clone(),
                handle,
                offset: 0,
                max_bytes: 256,
            })
            .await
            .unwrap()
        {
            SyscallReply::WorkspaceRead { chunk } => {
                assert!(chunk.eof);
                assert_eq!(
                    base64::engine::general_purpose::STANDARD
                        .decode(chunk.data_base64)
                        .unwrap(),
                    expected
                );
            }
            other => panic!("fresh workspace read failed: {other:?}"),
        }
        let handle = match client
            .call(Syscall::VfsOpenData {
                agent_id: fresh.agent.clone(),
                path: KV_PATH.into(),
                rights: vec![WorkspaceRight::Read],
            })
            .await
            .unwrap()
        {
            SyscallReply::VfsDataOpened { handle } => handle.id,
            other => panic!("fresh authorized KV open failed: {other:?}"),
        };
        match client
            .call(Syscall::VfsReadData {
                agent_id: fresh.agent,
                handle,
                args: serde_json::json!({}),
            })
            .await
            .unwrap()
        {
            SyscallReply::ToolResult { data } => {
                assert_eq!(data["value"], "committed before crash")
            }
            other => panic!("fresh committed KV read failed: {other:?}"),
        }
        client.close().await.unwrap();
        crash(recovered).await;
        // Actual OS process death must release every directory and SQLite handle.
        root.close().unwrap();
    }
}
