//! Actual-wire memory-provider cancellation before durable fact publication.

use super::{SqliteContextManager, WorkspaceRight};
use crate::memory_manager::{Embedder, EmbeddingError, FeatureHashEmbedder, EMBED_DIM};
use crate::resources::ResourceType;
use crate::syscall_server::{Syscall, SyscallClient, SyscallReply, SyscallServer, WireErrorCode};
use crate::{AgentConfig, AgentKernelImpl, IsolationLevel, Priority, SandboxConfig};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

#[derive(Default)]
struct EmbeddingDelay {
    armed: AtomicBool,
    entered: AtomicBool,
    returned: AtomicBool,
    released: Mutex<bool>,
    changed: Condvar,
}

impl EmbeddingDelay {
    fn release(&self) {
        *self.released.lock().unwrap() = true;
        self.changed.notify_all();
    }
}

struct ReleaseOnDrop(Arc<EmbeddingDelay>);

impl Drop for ReleaseOnDrop {
    fn drop(&mut self) {
        self.0.release();
    }
}

struct ControlledEmbedder(Arc<EmbeddingDelay>);

impl Embedder for ControlledEmbedder {
    fn embed(&self, text: &str) -> Result<Vec<f32>, EmbeddingError> {
        if self.0.armed.swap(false, Ordering::AcqRel) {
            self.0.entered.store(true, Ordering::Release);
            let (_released, timeout) = self.0.changed.wait_timeout_while(
                self.0.released.lock().unwrap(),
                Duration::from_secs(45),
                |released| !*released,
            ).unwrap();
            if timeout.timed_out() {
                return Err(EmbeddingError::Timeout);
            }
            let vector = FeatureHashEmbedder.embed(text);
            self.0.returned.store(true, Ordering::Release);
            vector
        } else {
            FeatureHashEmbedder.embed(text)
        }
    }

    fn dim(&self) -> usize {
        EMBED_DIM
    }

    fn is_remote(&self) -> bool {
        // Exercise the same offloaded path as an optional remote embedder.
        // This deterministic fixture makes no HTTP or model calls.
        true
    }

    fn model_id(&self) -> &str {
        "vfs-controlled-embedding"
    }
}

async fn observe(predicate: impl Fn() -> bool, limit: Duration, description: &str) {
    tokio::time::timeout(limit, async {
        while !predicate() {
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    }).await.expect(description);
}

async fn connect(address: std::net::SocketAddr) -> SyscallClient {
    let mut client = SyscallClient::connect(address).await.unwrap();
    assert!(matches!(client.call(Syscall::Hello { protocol_version: 2 }).await.unwrap(), SyscallReply::Hello { .. }));
    client
}

#[tokio::test]
async fn public_wire_memory_deadline_and_disconnect_cannot_publish_a_late_fact() {
    for disconnect in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let workspace = root.path().join("workspace");
        std::fs::create_dir(&workspace).unwrap();
        let delay = Arc::new(EmbeddingDelay::default());
        let _release_on_failure = ReleaseOnDrop(delay.clone());
        let context = Arc::new(SqliteContextManager::new(&root.path().join("state.db")).unwrap()
            .with_embedder(Arc::new(ControlledEmbedder(delay.clone()))));
        let security = crate::config::Config::default();
        let kernel = Arc::new(AgentKernelImpl::with_context_manager(
            context.clone(), &security.budgets, security.mac_enforcing, &security.mac_rules,
        ).unwrap());
        let agent = kernel.create_agent_full(AgentConfig {
            name: "memory-deadline".into(), task: "controlled memory publication".into(),
            llm_provider: "stub".into(), permission_profile: "standard".into(),
            priority: Priority::default(), sandbox_config: Some(SandboxConfig {
                workspace_dir: workspace, isolation_level: IsolationLevel::Filesystem,
                allowed_network_hosts: Some(Vec::new()), max_disk_usage_bytes: Some(100000),
                max_memory_bytes: None, container_image: None,
            }),
        }).await.unwrap().id;
        let server = SyscallServer::bind(kernel.clone(), "127.0.0.1:0").await.unwrap();
        let address = server.local_addr().unwrap();
        let server = tokio::spawn(server.serve());
        let mut reader = connect(address).await;
        let handle = match reader.call(Syscall::VfsOpenData {
            agent_id: agent.to_string(), path: "/memory".into(),
            rights: vec![WorkspaceRight::Read, WorkspaceRight::Write],
        }).await.unwrap() {
            SyscallReply::VfsDataOpened { handle } => handle,
            other => panic!("authorized memory open failed: {other:?}"),
        };
        assert!(matches!(reader.call(Syscall::VfsWriteData {
            agent_id: agent.to_string(), handle: handle.id.clone(),
            args: serde_json::json!({"content":"committed baseline","category":"Fact"}),
        }).await.unwrap(), SyscallReply::ToolResult { .. }));
        assert_eq!(context.fact_count(agent).unwrap(), 1);
        assert_eq!(kernel.resource_broker.available_resource_permits_for_test(ResourceType::Memory), 32);

        let mut writer = connect(address).await;
        delay.armed.store(true, Ordering::Release);
        writer.send(&Syscall::VfsWriteData {
            agent_id: agent.to_string(), handle: handle.id.clone(),
            args: serde_json::json!({"content":"late fact must never publish","category":"Fact"}),
        }).await.unwrap();
        observe(|| delay.entered.load(Ordering::Acquire), Duration::from_secs(3), "memory provider did not enter its actual embedding worker").await;
        assert_eq!(kernel.resource_broker.available_resource_permits_for_test(ResourceType::Memory), 31);
        let writer = if disconnect { drop(writer); None } else { Some(writer) };
        // Keep the actual 30-second provider and 130-second wire deadlines.
        observe(|| kernel.resource_broker.available_resource_permits_for_test(ResourceType::Memory) == 32,
            Duration::from_secs(40), "memory deadline did not drain its provider admission").await;
        if let Some(mut writer) = writer {
            assert!(matches!(writer.read_reply().await.unwrap(), SyscallReply::TypedError {
                code: WireErrorCode::Timeout, ..
            }));
            writer.close().await.unwrap();
        }
        assert_eq!(context.fact_count(agent).unwrap(), 1);
        assert!(!delay.returned.load(Ordering::Acquire));
        delay.release();
        observe(|| delay.returned.load(Ordering::Acquire), Duration::from_secs(3), "offloaded embedding worker did not return after release").await;
        assert_eq!(context.fact_count(agent).unwrap(), 1, "cancelled continuation must not publish even after delayed embedding completes");
        match reader.call(Syscall::VfsReadData {
            agent_id: agent.to_string(), handle: handle.id.clone(), args: serde_json::json!({"query":"baseline"}),
        }).await.unwrap() {
            SyscallReply::ToolResult { data } => {
                let facts = data["facts"].as_array().unwrap();
                assert_eq!(facts.len(), 1);
                assert_eq!(facts[0]["content"], "committed baseline");
            }
            other => panic!("fresh public memory read after drain failed: {other:?}"),
        }
        assert!(matches!(reader.call(Syscall::VfsWriteData {
            agent_id: agent.to_string(), handle: handle.id.clone(),
            args: serde_json::json!({"content":"fresh authorized fact","category":"Fact"}),
        }).await.unwrap(), SyscallReply::ToolResult { .. }));
        assert_eq!(context.fact_count(agent).unwrap(), 2);
        assert!(matches!(reader.call(Syscall::VfsClose {
            agent_id: agent.to_string(), handle: handle.id,
        }).await.unwrap(), SyscallReply::VfsClosed));
        assert_eq!(kernel.vfs_mounts(agent).unwrap().open_handles, 0);
        reader.close().await.unwrap();
        kernel.stop_agent(agent).await.unwrap();
        server.abort();
        let _ = server.await;
        drop(kernel);
        drop(context);
        let reopened = SqliteContextManager::new(&root.path().join("state.db")).unwrap();
        assert_eq!(reopened.fact_count(agent).unwrap(), 2);
        drop(reopened);
        root.close().unwrap();
        println!("VFS_MEMORY_DEADLINE {}", serde_json::json!({"client_disconnected":disconnect,"provider_permits_reclaimed":32,"late_fact_published":false,"durable_facts":2}));
    }
}
