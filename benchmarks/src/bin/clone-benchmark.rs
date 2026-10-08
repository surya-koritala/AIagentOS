//! Isolated-process fixture comparison of public cloning and eager history copy.

use std::path::Path;
use std::process::Command;
use std::sync::Arc;
use std::time::Instant;

use agent_sdk::KernelClient;
use kernel::connector::StandardMessage;
use kernel::syscall_server::SyscallServer;
use kernel::{AgentConfig, AgentKernelImpl, Priority};

fn resident_bytes() -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        std::fs::read_to_string("/proc/self/status")
            .ok()?
            .lines()
            .find_map(|line| line.strip_prefix("VmRSS:"))?
            .split_whitespace()
            .next()?
            .parse::<u64>()
            .ok()?
            .checked_mul(1024)
    }
    #[cfg(target_os = "macos")]
    {
        let output = Command::new("ps")
            .args(["-o", "rss=", "-p", &std::process::id().to_string()])
            .output()
            .ok()?;
        String::from_utf8(output.stdout)
            .ok()?
            .trim()
            .parse::<u64>()
            .ok()?
            .checked_mul(1024)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    None
}

fn database_bytes(kernel: &AgentKernelImpl, path: &Path) -> u64 {
    kernel
        .context_manager
        .checkpoint()
        .expect("checkpoint fixture store");
    std::fs::metadata(path).expect("fixture database").len()
}

fn history(messages: usize) -> Vec<StandardMessage> {
    let paragraph = "Inspected repository files and tests. The task requires preserving tenant ownership, validating changes, and recording a result that can be reviewed. ";
    (0..messages)
        .map(|index| {
            let content = format!("Turn {index:06}: {}", paragraph.repeat(6));
            if index % 2 == 0 {
                StandardMessage::user(content)
            } else {
                StandardMessage::assistant(content)
            }
        })
        .collect()
}

async fn worker(strategy: &str, messages: usize, branches: usize) -> serde_json::Value {
    let root = std::env::temp_dir().join(format!("agentos-clone-bench-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&root).unwrap();
    let path = root.join("store.db");
    let kernel = Arc::new(AgentKernelImpl::with_db_path(&path).unwrap());
    let parent = kernel
        .create_agent_full(AgentConfig {
            name: "fixture parent".into(),
            task: "fixture branching".into(),
            llm_provider: "stub".into(),
            permission_profile: "standard".into(),
            priority: Priority::default(),
            sandbox_config: None,
        })
        .await
        .unwrap()
        .id;
    let history = history(messages);
    let history_bytes = serde_json::to_vec(&history).unwrap().len();
    kernel
        .context_manager
        .save_conversation("source", parent, &history)
        .unwrap();
    drop(history);
    let server = SyscallServer::bind(kernel.clone(), "127.0.0.1:0")
        .await
        .unwrap();
    let address = server.local_addr().unwrap();
    let task = tokio::spawn(server.serve());
    let mut client = KernelClient::connect(address).await.unwrap();
    let before_storage = database_bytes(&kernel, &path);
    let before_rss = resident_bytes();
    let mut samples = Vec::new();
    let mut children = Vec::new();
    for index in 0..branches {
        let started = Instant::now();
        let child = if strategy == "cow" {
            let child = uuid::Uuid::new_v4();
            client
                .clone_agent(parent.to_string(), child, format!("branch {index}"), vec![])
                .await
                .unwrap();
            child
        } else {
            // Baseline performs the same public fresh-agent admission, then
            // materializes and persists a complete independent history.
            let copied = kernel.context_manager.load_conversation("source").unwrap();
            let child = client
                .create_agent(
                    format!("branch {index}"),
                    "fixture branching",
                    None,
                    None,
                    None,
                )
                .await
                .unwrap()
                .parse()
                .unwrap();
            kernel
                .context_manager
                .save_conversation(&format!("eager:{child}"), child, &copied)
                .unwrap();
            child
        };
        let latency_us = started.elapsed().as_micros();
        let storage = database_bytes(&kernel, &path);
        samples.push(serde_json::json!({
            "branch":index + 1, "latency_us":latency_us,
            "retained_database_growth_bytes":storage as i128 - before_storage as i128,
            "resident_growth_bytes": resident_bytes().zip(before_rss).map(|(after, before)| after as i128 - before as i128),
        }));
        children.push(child);
    }
    let report = serde_json::json!({"strategy":strategy,"messages":messages,"history_bytes":history_bytes,"branches":branches,"samples":samples});
    for child in children {
        kernel.stop_agent(child).await.unwrap();
    }
    kernel.stop_agent(parent).await.unwrap();
    client.close().await.unwrap();
    task.abort();
    let _ = task.await;
    drop(kernel);
    std::fs::remove_dir_all(root).unwrap();
    report
}

#[tokio::main]
async fn main() {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if let [mode, strategy, messages, branches] = args.as_slice() {
        assert_eq!(mode, "--worker");
        assert!(matches!(strategy.as_str(), "cow" | "eager"));
        let messages = messages.parse::<usize>().unwrap();
        let branches = branches.parse::<usize>().unwrap();
        assert!((1..=32768).contains(&messages) && (1..=32).contains(&branches));
        println!("{}", worker(strategy, messages, branches).await);
        return;
    }
    assert!(args.is_empty(), "usage: clone-benchmark");
    let executable = std::env::current_exe().unwrap();
    let mut results = Vec::new();
    for messages in [256, 4096, 16384] {
        for strategy in ["cow", "eager"] {
            let output = Command::new(&executable)
                .args(["--worker", strategy, &messages.to_string(), "8"])
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "fixture worker failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            results.push(serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap());
        }
    }
    println!("{}", serde_json::to_string_pretty(&serde_json::json!({
        "schema_version":1,"evidence_class":"deterministic_fixture",
        "platform":std::env::consts::OS,"architecture":std::env::consts::ARCH,
        "latency_scope":"public child admission plus history publication, excludes store checkpoint and RSS sampling",
        "storage_scope":"checkpointed allocated SQLite database bytes; includes indexes, metadata and freelist",
        "rss_scope":"current process resident bytes after each branch minus before first branch; each strategy and history uses a fresh process",
        "provider_calls":0,"results":results,
    })).unwrap());
}
