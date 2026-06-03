//! Durable-restart tests for the kernel's persistence story.
//!
//! These prove the headline guarantee: kill the process, restart from the same
//! data dir, and **agents + conversations + long-term memory + KV storage +
//! context snapshots all come back intact** — with enforcement re-armed for the
//! restored agents.
//!
//! Two restart flavors are covered:
//! - **Crash recovery** — the kernel is dropped WITHOUT calling `shutdown()`
//!   (simulated abrupt stop). SQLite's committed transactions are durable, so a
//!   fresh kernel on the same file recovers everything.
//! - **Graceful shutdown** — `shutdown()` checkpoints the WAL into the main DB
//!   file; a restart afterward recovers everything just the same.
//!
//! All state flows through the single `SqliteContextManager` handle owned by the
//! kernel (`kernel.context_manager`) — no second SQLite handle is opened.

use kernel::agent::AgentKernel;
use kernel::connector::StandardMessage;
use kernel::context::{ContextManager, Fact, FactCategory};
use kernel::syscall_gate::GateDenial;
use kernel::{AgentConfig, AgentId, AgentKernelImpl};

/// A unique temp DB path for one test (mirrors the repo's existing
/// `std::env::temp_dir() + uuid` pattern — no new dependency).
fn temp_db_path(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("persist_{tag}_{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    dir.join("agent_os.db")
}

fn agent_cfg(name: &str, profile: &str) -> AgentConfig {
    AgentConfig {
        name: name.into(),
        task: format!("task for {name}"),
        llm_provider: "stub".into(),
        permission_profile: profile.into(),
        priority: kernel::Priority::new(2).unwrap(),
        sandbox_config: None,
    }
}

/// Populate a fresh persistent kernel with the full spread of durable state and
/// return the ids we'll assert on after restart.
struct Seeded {
    read_only_id: AgentId,
    full_access_id: AgentId,
    conversation_id: String,
    fact_id: uuid::Uuid,
}

async fn seed(kernel: &AgentKernelImpl) -> Seeded {
    // Two agents with DIFFERENT permission profiles so we can prove the restored
    // capability set (and thus gate enforcement) is profile-correct.
    let read_only = kernel
        .create_agent_full(agent_cfg("ro-agent", "read-only"))
        .await
        .expect("create read-only agent");
    let full_access = kernel
        .create_agent_full(agent_cfg("fa-agent", "full-access"))
        .await
        .expect("create full-access agent");

    // Conversation messages (durable conversation history).
    let conversation_id = uuid::Uuid::new_v4().to_string();
    let messages = vec![
        StandardMessage::user("remember the launch code is 1234"),
        StandardMessage::assistant("noted, stored the launch code"),
    ];
    kernel
        .context_manager
        .save_conversation(&conversation_id, read_only.id, &messages)
        .expect("save conversation");

    // A long-term-memory fact (with embedding computed on store).
    let fact_id = uuid::Uuid::new_v4();
    let fact = Fact {
        id: fact_id,
        content: "user prefers dark mode".into(),
        category: FactCategory::Preference,
        created_at: chrono::Utc::now(),
        last_accessed_at: chrono::Utc::now(),
        embedding: None,
    };
    ContextManager::store_fact(&*kernel.context_manager, full_access.id, fact)
        .await
        .expect("store fact");

    // A per-agent KV entry.
    kernel
        .context_manager
        .kv_put(read_only.id, "favorite_color", "blue")
        .expect("kv put");

    // A named context snapshot — first persist a context to snapshot from.
    let mut ctx = kernel
        .context_manager
        .get_context(full_access.id)
        .await
        .expect("get context");
    ctx.token_count = 42;
    ctx.working_state = serde_json::json!({"phase": "mid-flight"});
    ContextManager::persist_context(&*kernel.context_manager, full_access.id, &ctx)
        .await
        .expect("persist context");
    kernel
        .context_manager
        .snapshot_context(full_access.id, "checkpoint-1")
        .expect("snapshot");

    Seeded {
        read_only_id: read_only.id,
        full_access_id: full_access.id,
        conversation_id,
        fact_id,
    }
}

/// Assert that a freshly-booted kernel on the same DB recovered everything.
async fn assert_recovered(kernel: &AgentKernelImpl, seeded: &Seeded) {
    // 1. Both agents are back in the registry with the right names/profiles.
    let agents = kernel.agent_manager.list_agents(None);
    assert_eq!(agents.len(), 2, "both agents should rehydrate");
    let ro = agents
        .iter()
        .find(|a| a.id == seeded.read_only_id)
        .expect("read-only agent rehydrated");
    let fa = agents
        .iter()
        .find(|a| a.id == seeded.full_access_id)
        .expect("full-access agent rehydrated");
    assert_eq!(ro.name, "ro-agent");
    assert_eq!(fa.name, "fa-agent");
    // Priority survived.
    assert_eq!(ro.priority.value(), 2);

    // Task survived (config rehydration).
    assert_eq!(
        kernel.agent_manager.get_agent_task(seeded.read_only_id),
        Some("task for ro-agent".to_string())
    );

    // 2. Enforcement is re-armed and profile-correct for restored agents. The
    //    read-only agent must NOT be able to write a file; the full-access agent
    //    must be allowed. This proves the gate translation table + cgroup +
    //    capability set were rebuilt from the persisted profile.
    let ro_write = kernel
        .syscall_gate
        .check_tool_call(seeded.read_only_id, "write_file", "/tmp/x", 1)
        .await;
    assert!(
        matches!(ro_write, Err(GateDenial::MissingCapability(_))),
        "restored read-only agent must be denied write_file, got {ro_write:?}"
    );
    let fa_write = kernel
        .syscall_gate
        .check_tool_call(seeded.full_access_id, "write_file", "/tmp/x", 1)
        .await;
    assert!(
        fa_write.is_ok(),
        "restored full-access agent must be allowed write_file, got {fa_write:?}"
    );

    // 3. Conversation history is intact.
    let msgs = kernel
        .context_manager
        .load_conversation(&seeded.conversation_id)
        .expect("conversation recovered");
    assert_eq!(msgs.len(), 2);
    assert_eq!(msgs[0].content, "remember the launch code is 1234");

    // 4. Long-term memory fact is intact (queryable + correct content/category).
    let facts = ContextManager::query_memory(
        &*kernel.context_manager,
        seeded.full_access_id,
        "appearance preferences",
    )
    .await
    .expect("query memory");
    let found = facts
        .iter()
        .find(|f| f.id == seeded.fact_id)
        .expect("fact recovered");
    assert_eq!(found.content, "user prefers dark mode");
    assert_eq!(found.category, FactCategory::Preference);

    // 5. KV entry is intact.
    let color = kernel
        .context_manager
        .kv_get(seeded.read_only_id, "favorite_color")
        .expect("kv get");
    assert_eq!(color, Some("blue".to_string()));

    // 6. Context snapshot is intact and restores the captured working state.
    let labels = kernel
        .context_manager
        .list_snapshots(seeded.full_access_id)
        .expect("list snapshots");
    assert!(
        labels.contains(&"checkpoint-1".to_string()),
        "snapshot label recovered"
    );
    let restored_ctx = kernel
        .context_manager
        .restore_snapshot(seeded.full_access_id, "checkpoint-1")
        .expect("restore snapshot");
    assert_eq!(restored_ctx.token_count, 42);
    assert_eq!(
        restored_ctx.working_state,
        serde_json::json!({"phase": "mid-flight"})
    );
}

/// CRASH RECOVERY: seed a persistent kernel, then DROP it without calling
/// `shutdown()` (simulated abrupt process stop). A fresh kernel on the same DB
/// file must recover all committed state.
#[tokio::test(flavor = "multi_thread")]
async fn crash_recovery_restores_everything() {
    let db_path = temp_db_path("crash");

    let seeded = {
        let kernel = AgentKernelImpl::with_db_path(&db_path).expect("boot persistent kernel");
        let seeded = seed(&kernel).await;
        // Simulate a crash: drop the kernel WITHOUT graceful shutdown. No
        // checkpoint, no flush — relying purely on SQLite commit durability.
        drop(kernel);
        seeded
    };

    // Fresh kernel from the SAME path — this triggers boot-time rehydration.
    let kernel2 = AgentKernelImpl::with_db_path(&db_path).expect("reboot persistent kernel");
    assert_recovered(&kernel2, &seeded).await;

    std::fs::remove_dir_all(db_path.parent().unwrap()).ok();
}

/// GRACEFUL SHUTDOWN + RESTART: same seed, but call `shutdown()` (which
/// checkpoints the WAL) before dropping, then reboot from the same DB.
#[tokio::test(flavor = "multi_thread")]
async fn graceful_shutdown_then_restart_restores_everything() {
    let db_path = temp_db_path("graceful");

    let seeded = {
        let kernel = AgentKernelImpl::with_db_path(&db_path).expect("boot persistent kernel");
        let seeded = seed(&kernel).await;
        // Graceful: flush via shutdown (WAL checkpoint) before drop.
        kernel.shutdown().await.expect("graceful shutdown");
        drop(kernel);
        seeded
    };

    let kernel2 = AgentKernelImpl::with_db_path(&db_path).expect("reboot persistent kernel");
    assert_recovered(&kernel2, &seeded).await;

    std::fs::remove_dir_all(db_path.parent().unwrap()).ok();
}

/// A fresh DB with no prior agents must boot cleanly and rehydrate nothing
/// (backwards-compatible empty/new-schema case).
#[tokio::test(flavor = "multi_thread")]
async fn fresh_db_rehydrates_no_agents() {
    let db_path = temp_db_path("fresh");
    let kernel = AgentKernelImpl::with_db_path(&db_path).expect("boot fresh kernel");
    assert!(kernel.agent_manager.list_agents(None).is_empty());
    std::fs::remove_dir_all(db_path.parent().unwrap()).ok();
}

/// An explicit second `rehydrate_agents()` after agents already exist must be
/// idempotent (no duplicate registry rows / agents).
#[tokio::test(flavor = "multi_thread")]
async fn rehydrate_is_idempotent() {
    let db_path = temp_db_path("idem");
    let kernel = AgentKernelImpl::with_db_path(&db_path).expect("boot");
    kernel
        .create_agent_full(agent_cfg("solo", "standard"))
        .await
        .expect("create");
    assert_eq!(kernel.agent_manager.list_agents(None).len(), 1);
    // Re-run rehydration explicitly; must not duplicate the agent.
    let restored = kernel.rehydrate_agents().await.expect("rehydrate");
    assert_eq!(restored.len(), 1);
    assert_eq!(kernel.agent_manager.list_agents(None).len(), 1);
    std::fs::remove_dir_all(db_path.parent().unwrap()).ok();
}
