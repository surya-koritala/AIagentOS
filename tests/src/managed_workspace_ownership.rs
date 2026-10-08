//! Real processes and durable stores sharing one OS user and temporary root.

use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::sync::Arc;
use std::time::Duration;

use agent_sdk::KernelClient;
use kernel::syscall_server::SyscallServer;
use kernel::{AgentConfig, AgentKernelImpl, Priority, SandboxConfig};
use serde_json::{json, Value};

const TOKEN: &str = "workspace-ownership-ci";
const SENTINEL: &str = "first store remains owned and available";

struct ProbeRoot(PathBuf);
impl ProbeRoot {
    fn new() -> Self {
        let root =
            std::env::temp_dir().join(format!("managed-store-proof-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&root).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        std::fs::create_dir(root.join("shared-temp")).unwrap();
        Self(root)
    }
}
impl Drop for ProbeRoot {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
struct Process(Child);
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn process(root: &Path, role: &str) -> Process {
    let temporary = root.join("shared-temp");
    let mut child = Command::new(std::env::current_exe().unwrap());
    child
        .args([
            "--ignored",
            "--exact",
            "managed_workspace_ownership::ownership_process_child",
            "--nocapture",
        ])
        .env("AIAGENTOS_MANAGED_STORE_PROBE_ROOT", root)
        .env("AIAGENTOS_MANAGED_STORE_PROBE_ROLE", role);
    for name in ["TMPDIR", "TMP", "TEMP"] {
        child.env(name, &temporary);
    }
    match role {
        "cut-manifest" => { child.env("AIAGENTOS_TEST_WORKSPACE_ALLOCATION_EXIT", "manifest_published"); },
        "cut-directory" => { child.env("AIAGENTOS_TEST_WORKSPACE_ALLOCATION_EXIT", "directory_created"); },
        _ => {},
    }
    Process(child.spawn().unwrap())
}
async fn report(path: &Path, process: &mut Process) -> Value {
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            match std::fs::read(path) {
                Ok(bytes) => break serde_json::from_slice(&bytes).unwrap(),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => panic!("read isolated probe report: {error}"),
            }
            assert!(
                process.0.try_wait().unwrap().is_none(),
                "probe process exited before its report"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("bounded ownership probe readiness")
}
fn publish(path: &Path, value: Value) {
    let stage = path.with_extension("stage");
    std::fs::write(&stage, serde_json::to_vec(&value).unwrap()).unwrap();
    std::fs::rename(stage, path).unwrap();
}
fn config(root: &Path, role: &str) -> kernel::config::Config {
    kernel::config::Config {
        data_dir: root.join(if role == "a" { "store-a" } else { "store-b" }),
        ..Default::default()
    }
}
fn agent() -> AgentConfig {
    AgentConfig {
        name: "managed store owner".into(),
        task: "offline namespace ownership proof".into(),
        llm_provider: "offline-ci-fixture".into(),
        permission_profile: "full-access".into(),
        priority: Priority::default(),
        sandbox_config: None,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_live_stores_do_not_reconcile_each_others_workspace() {
    let root = ProbeRoot::new();
    let mut first = process(&root.0, "a");
    let a = report(&root.0.join("a.json"), &mut first).await;
    assert_eq!(a["reconciled"], true);
    let mut client = KernelClient::connect(a["address"].as_str().unwrap())
        .await
        .unwrap();
    client.authenticate(TOKEN).await.unwrap();
    let id = a["agent_id"].as_str().unwrap().to_string();
    client
        .call_tool(
            id.clone(),
            "write_file",
            json!({"path":"sentinel.txt", "content":SENTINEL}),
        )
        .await
        .unwrap();
    let workspace = PathBuf::from(a["workspace"].as_str().unwrap());
    assert_eq!(
        std::fs::read_to_string(workspace.join("sentinel.txt")).unwrap(),
        SENTINEL
    );
    let control = workspace.parent().unwrap().parent().unwrap().join("control");
    let owner_manifest = control.join(format!("{}.json", workspace.file_name().unwrap().to_str().unwrap()));
    let manifest = std::fs::read(&owner_manifest).unwrap();
    for path in [owner_manifest.to_string_lossy().into_owned(), format!("../../control/{}.json", workspace.file_name().unwrap().to_str().unwrap())] {
        assert!(client.call_tool(id.clone(), "write_file", json!({"path":path,"content":"forged store owner"})).await.is_err());
        assert_eq!(std::fs::read(&owner_manifest).unwrap(), manifest, "an agent changed its control-plane owner manifest");
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        // Native DELETE access, exclusive sharing, directory semantics. A live
        // directory capability must continue to prevent deletion on Windows.
        let probe = std::fs::OpenOptions::new()
            .access_mode(0x0001_0000)
            .share_mode(0)
            .custom_flags(0x0200_0000)
            .open(&workspace);
        assert_eq!(probe.unwrap_err().raw_os_error(), Some(32));
    }
    let mut second = process(&root.0, "b");
    let b = report(&root.0.join("b.json"), &mut second).await;
    assert_eq!(
        a["operator"], b["operator"],
        "both runtimes must use the same real OS user"
    );
    assert_eq!(
        a["temporary"], b["temporary"],
        "fixture must share TEMP, not avoid the production boundary"
    );
    let intact = std::fs::read_to_string(workspace.join("sentinel.txt"))
        .ok()
        .as_deref()
        == Some(SENTINEL);
    println!(
        "ownership_probe={}",
        json!({"same_user":true,"shared_temp":true,"second_reconciled":b["reconciled"],"first_sentinel_intact":intact})
    );
    assert_eq!(
        b["reconciled"], true,
        "independent store boot/reconciliation failed: {b}"
    );
    assert!(
        intact,
        "another store removed the first live store's workspace bytes"
    );
    let read = client
        .call_tool(id, "read_file", json!({"path":"sentinel.txt"}))
        .await
        .unwrap();
    assert!(
        read.to_string().contains(SENTINEL),
        "fresh authorized I/O lost the first store's sentinel"
    );
    let mut b_client = KernelClient::connect(b["address"].as_str().unwrap()).await.unwrap();
    b_client.authenticate(TOKEN).await.unwrap();
    let b_id = b["agent_id"].as_str().unwrap().to_string();
    b_client.call_tool(b_id.clone(), "write_file", json!({"path":"restart.txt","content":"second store restart identity"})).await.unwrap();
    b_client.close().await.unwrap();
    second.0.kill().unwrap();
    second.0.wait().unwrap();
    let mut restarted = process(&root.0, "b-restart");
    let resumed = report(&root.0.join("b-restart.json"), &mut restarted).await;
    assert_eq!(resumed["reconciled"], true);
    assert_eq!(resumed["agent_id"], b["agent_id"]);
    assert_eq!(resumed["workspace"], b["workspace"]);
    assert_eq!(resumed["store"], b["store"], "store ownership changed on real process restart");
    let mut resumed_client = KernelClient::connect(resumed["address"].as_str().unwrap()).await.unwrap();
    resumed_client.authenticate(TOKEN).await.unwrap();
    let restored = resumed_client.call_tool(b_id, "read_file", json!({"path":"restart.txt"})).await.unwrap();
    assert!(restored.to_string().contains("second store restart identity"));
    resumed_client.close().await.unwrap();
    let read = client.call_tool(a["agent_id"].as_str().unwrap(), "read_file", json!({"path":"sentinel.txt"})).await.unwrap();
    assert!(read.to_string().contains(SENTINEL), "B restart corrupted A's fresh authorized I/O");
    client.close().await.unwrap();
    std::fs::write(root.0.join("release"), []).unwrap();
    assert!(first.0.wait().unwrap().success());
    assert!(restarted.0.wait().unwrap().success());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "helper invoked by the actual two-process store test"]
async fn ownership_process_child() {
    let Some(root) = std::env::var_os("AIAGENTOS_MANAGED_STORE_PROBE_ROOT") else {
        return;
    };
    let root = PathBuf::from(root);
    let role = std::env::var("AIAGENTOS_MANAGED_STORE_PROBE_ROLE").unwrap();
    assert!(matches!(role.as_str(), "a" | "b" | "b-restart" | "cut-manifest" | "cut-directory" | "repair"));
    let kernel = Arc::new(AgentKernelImpl::from_config(&config(&root, &role)).unwrap());
    let reconciled = kernel.rehydrate_agents().await;
    if let Err(error) = reconciled {
        publish(
            &root.join(format!("{role}.json")),
            json!({
                "reconciled":false,"error":error.to_string(),
                "operator":kernel::config::local_operator_identity().unwrap(),"temporary":std::env::temp_dir(),
            }),
        );
    } else {
        let id = if role == "b-restart" {
            let record = kernel.context_manager.load_all_agents().unwrap().into_iter().find(|record| record.name == "managed store owner").unwrap();
            assert!(kernel.agent_manager.get_agent_state(record.id).is_some());
            record.id
        } else { kernel.create_agent_full(agent()).await.unwrap().id };
        let record = kernel
            .context_manager
            .load_all_agents()
            .unwrap()
            .into_iter()
            .find(|record| record.id == id)
            .unwrap();
        let sandbox: SandboxConfig =
            serde_json::from_str(record.sandbox_config_json.as_deref().unwrap()).unwrap();
        let server = SyscallServer::bind(kernel.clone(), "127.0.0.1:0")
            .await
            .unwrap()
            .with_auth_token(TOKEN);
        let address = server.local_addr().unwrap().to_string();
        let serving = tokio::spawn(server.serve());
        publish(
            &root.join(format!("{role}.json")),
            json!({
            "reconciled":true,"agent_id":id,"workspace":sandbox.workspace_dir,"address":address,
            "store":serde_json::from_slice::<Value>(&std::fs::read(sandbox.workspace_dir.parent().unwrap().parent().unwrap().join("control/store.json")).unwrap()).unwrap()["store"],
                "operator":kernel::config::local_operator_identity().unwrap(),"temporary":std::env::temp_dir(),
            }),
        );
        tokio::time::timeout(Duration::from_secs(30), async {
            while !root.join("release").exists() {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap();
        serving.abort();
        let _ = serving.await;
        kernel.stop_agent(id).await.unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn allocation_crash_retires_only_verified_current_store_orphan_pairs() {
    for role in ["cut-manifest", "cut-directory"] {
        let root = ProbeRoot::new();
        let mut allocation = process(&root.0, role);
        let status = tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                if let Some(status) = allocation.0.try_wait().unwrap() { break status; }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }).await.unwrap();
        assert_eq!(status.code(), Some(89), "allocation did not reach its real durability cutpoint");
        let prefix = root.0.join("store-b/.aiagentos-workspace-stores");
        let stores = std::fs::read_dir(&prefix).unwrap().map(|entry| entry.unwrap().path()).collect::<Vec<_>>();
        assert_eq!(stores.len(), 1);
        let namespace = &stores[0];
        let control = namespace.join("control");
        let orphans = std::fs::read_dir(&control).unwrap().filter_map(|entry| {
            let path = entry.unwrap().path();
            path.file_stem().and_then(|stem| stem.to_str()).and_then(|stem| uuid::Uuid::parse_str(stem).ok())
        }).collect::<Vec<_>>();
        assert_eq!(orphans.len(), 1, "verified ownership was not durably published before the cutpoint");
        let owned_data = namespace.join("data").join(orphans[0].to_string());
        assert_eq!(owned_data.exists(), role == "cut-directory");
        let unknown = namespace.join("data").join(uuid::Uuid::new_v4().to_string());
        std::fs::create_dir(&unknown).unwrap();
        std::fs::write(unknown.join(".aiagentos-managed"), []).unwrap();
        std::fs::write(unknown.join("sentinel.txt"), "unverified ownership is never cleanup authority").unwrap();
        let mut recovered = process(&root.0, "repair");
        let restored = report(&root.0.join("repair.json"), &mut recovered).await;
        assert_eq!(restored["reconciled"], true);
        assert!(!control.join(format!("{}.json", orphans[0])).exists());
        assert!(!owned_data.exists(), "verified allocation orphan survived current-store recovery");
        assert_eq!(std::fs::read_to_string(unknown.join("sentinel.txt")).unwrap(), "unverified ownership is never cleanup authority");
        std::fs::write(root.0.join("release"), []).unwrap();
        assert!(recovered.0.wait().unwrap().success());
    }
}
