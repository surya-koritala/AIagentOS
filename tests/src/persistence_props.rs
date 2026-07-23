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

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use kernel::agent::AgentKernel;
use kernel::config::Config;
use kernel::connector::{
    LlmProviderAdapter, LlmResponse, LlmSession, LlmUsage, ProviderType, StandardMessage,
    ToolDefinition,
};
use kernel::context::{ContextManager, Fact, FactCategory, DEFAULT_TENANT};
use kernel::syscall_gate::GateDenial;
use kernel::{AgentConfig, AgentId, AgentKernelImpl, ConnectorError, Priority, ProviderId};

/// A deterministic provider used by the restart-accounting regressions. It
/// reports provider-native token counts so the production executor, durable
/// usage ledger, and boot-time budget rehydration all participate in the test.
struct FixedUsageAdapter {
    id: ProviderId,
    input_tokens: u32,
    output_tokens: u32,
    calls: Arc<AtomicUsize>,
}

struct FixedUsageSession {
    id: ProviderId,
    input_tokens: u32,
    output_tokens: u32,
    calls: Arc<AtomicUsize>,
}

#[async_trait]
impl LlmSession for FixedUsageSession {
    async fn send(&self, messages: Vec<StandardMessage>) -> Result<LlmResponse, ConnectorError> {
        self.send_with_tools(messages, &[]).await
    }

    async fn send_with_tools(
        &self,
        _messages: Vec<StandardMessage>,
        _tools: &[ToolDefinition],
    ) -> Result<LlmResponse, ConnectorError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(LlmResponse {
            content: "deterministic accounting response".into(),
            finish_reason: Some("stop".into()),
            tokens_used: self.input_tokens.saturating_add(self.output_tokens),
            usage: LlmUsage::reported(self.input_tokens, self.output_tokens, 0),
            tool_calls: Vec::new(),
        })
    }

    fn provider_id(&self) -> &ProviderId {
        &self.id
    }

    fn model_id(&self) -> &str {
        "fixed-accounting-v1"
    }
}

#[async_trait]
impl LlmProviderAdapter for FixedUsageAdapter {
    fn id(&self) -> &ProviderId {
        &self.id
    }

    fn name(&self) -> &str {
        "fixed-usage"
    }

    fn provider_type(&self) -> ProviderType {
        ProviderType::Local
    }

    async fn is_available(&self) -> bool {
        true
    }

    async fn create_session(&self) -> Result<Box<dyn LlmSession>, ConnectorError> {
        Ok(Box::new(FixedUsageSession {
            id: self.id.clone(),
            input_tokens: self.input_tokens,
            output_tokens: self.output_tokens,
            calls: Arc::clone(&self.calls),
        }))
    }

    fn translate_to_provider(&self, message: &StandardMessage) -> serde_json::Value {
        serde_json::json!({"role": message.role, "content": message.content})
    }

    fn translate_from_provider(&self, value: &serde_json::Value) -> Option<StandardMessage> {
        Some(StandardMessage::assistant(value.get("content")?.as_str()?))
    }
}

fn fixed_usage_adapter(
    provider: &str,
    input_tokens: u32,
    output_tokens: u32,
) -> (Arc<FixedUsageAdapter>, Arc<AtomicUsize>) {
    let calls = Arc::new(AtomicUsize::new(0));
    (
        Arc::new(FixedUsageAdapter {
            id: provider.into(),
            input_tokens,
            output_tokens,
            calls: Arc::clone(&calls),
        }),
        calls,
    )
}

pub(super) fn register_fixed_usage_provider(
    kernel: &AgentKernelImpl,
    provider: &str,
    input_tokens: u32,
    output_tokens: u32,
) -> Arc<AtomicUsize> {
    let (adapter, calls) = fixed_usage_adapter(provider, input_tokens, output_tokens);
    kernel
        .register_provider(adapter)
        .expect("register deterministic usage provider");
    calls
}

fn accounting_config(data_dir: &std::path::Path, price_per_1k: f64, global_ceiling: f64) -> Config {
    let mut config = Config {
        data_dir: data_dir.to_path_buf(),
        ..Config::default()
    };
    config.budgets.usd_per_1k_tokens = price_per_1k;
    config.budgets.max_usd = global_ceiling;
    config.budgets.per_agent_max_usd = 0.0;
    config.budgets.per_tenant_max_usd = 0.0;
    config
}

fn accounting_agent_cfg(name: &str, provider: &str) -> AgentConfig {
    AgentConfig {
        name: name.into(),
        task: "exercise durable accounting".into(),
        llm_provider: provider.into(),
        permission_profile: "standard".into(),
        priority: Priority::default(),
        sandbox_config: None,
    }
}

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
async fn assert_recovered(kernel: &AgentKernelImpl, seeded: &Seeded, expect_live: bool) {
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
    let fa_write = kernel
        .syscall_gate
        .check_tool_call(seeded.full_access_id, "write_file", "/tmp/x", 1)
        .await;
    if expect_live {
        assert!(
            matches!(ro_write, Err(GateDenial::MissingCapability(_))),
            "crash-restored read-only agent must be denied write_file, got {ro_write:?}"
        );
        assert!(
            fa_write.is_ok(),
            "crash-restored full-access agent must be allowed write_file, got {fa_write:?}"
        );
    } else {
        assert!(matches!(ro_write, Err(GateDenial::UnknownAgent)));
        assert!(matches!(fa_write, Err(GateDenial::UnknownAgent)));
        assert_eq!(
            kernel.get_agent_status(seeded.read_only_id).unwrap(),
            kernel::AgentState::Stopped
        );
        assert_eq!(
            kernel.get_agent_status(seeded.full_access_id).unwrap(),
            kernel::AgentState::Stopped
        );
    }

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
    assert_recovered(&kernel2, &seeded, true).await;

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
    // Coordinated shutdown persists agents as terminal history. Their durable
    // context remains available, but live gate/scheduler/sandbox state is not
    // re-armed on restart.
    assert_recovered(&kernel2, &seeded, false).await;

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

/// A committed usage charge must survive an abrupt process stop in the exact
/// fixed-point unit used by enforcement. A later pricing change must not
/// reprice that historical row, and a ceiling reached before the stop must
/// reject the next provider request after boot.
#[tokio::test(flavor = "multi_thread")]
async fn abrupt_restart_restores_exact_spend_without_repricing_and_blocks_next_request() {
    const PROVIDER: &str = "fixed-abrupt-accounting";
    const CHARGE_MICROS: u64 = 50_000;

    let db_path = temp_db_path("budget_abrupt");
    let data_dir = db_path.parent().unwrap();
    let first_config = accounting_config(data_dir, 2.0, 1.0);
    let agent_id = {
        let kernel = AgentKernelImpl::from_config(&first_config).expect("first boot");
        let (adapter, calls) = fixed_usage_adapter(PROVIDER, 20, 5);
        kernel
            .register_provider(adapter)
            .expect("register provider");
        let agent = kernel
            .create_agent_full(accounting_agent_cfg("abrupt-accounting", PROVIDER))
            .await
            .expect("create agent");

        let output = kernel
            .send_message(agent.id, "charge the durable budget")
            .await
            .expect("first provider request");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(output.usage.charged_cost_micros, CHARGE_MICROS);
        assert_eq!(
            kernel
                .context_manager
                .latest_usage(agent.id)
                .expect("durable usage row")
                .cost_micros,
            CHARGE_MICROS
        );

        // No shutdown/WAL checkpoint: this is the abrupt-restart path.
        drop(kernel);
        agent.id
    };

    // Change the live price by 50x. Rehydration must read the immutable exact
    // charge stored with the historical row, not recalculate from its tokens.
    let restart_config = accounting_config(data_dir, 100.0, 0.05);
    let kernel = AgentKernelImpl::from_config(&restart_config).expect("restart");
    let snapshot = kernel
        .context_manager
        .load_budget_usage_snapshot()
        .expect("load exact usage snapshot");
    assert_eq!(snapshot.global_micros, CHARGE_MICROS);
    assert_eq!(
        snapshot.per_agent_micros.get(&agent_id),
        Some(&CHARGE_MICROS)
    );
    assert_eq!(
        snapshot.per_tenant_micros.get(DEFAULT_TENANT),
        Some(&CHARGE_MICROS)
    );
    assert_eq!(kernel.budget_enforcer.global_spent_usd(), 0.05);
    assert_eq!(kernel.budget_enforcer.agent_spent_usd(agent_id), 0.05);
    assert_eq!(
        kernel.budget_enforcer.tenant_spent_usd(DEFAULT_TENANT),
        0.05
    );

    let (adapter, calls) = fixed_usage_adapter(PROVIDER, 20, 5);
    kernel
        .register_provider(adapter)
        .expect("register after restart");
    let blocked = kernel
        .send_message(agent_id, "must be rejected before provider I/O")
        .await
        .expect("budget stop is a completed, non-provider turn");
    assert!(
        blocked.content.contains("global budget exhausted"),
        "restored ceiling should stop the request, got {:?}",
        blocked.content
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "provider must not be called after the restored ceiling is reached"
    );
    assert_eq!(
        kernel
            .context_manager
            .load_budget_usage_snapshot()
            .unwrap()
            .global_micros,
        CHARGE_MICROS,
        "a blocked request must not create or alter a charge"
    );

    drop(kernel);
    std::fs::remove_dir_all(data_dir).ok();
}

/// Graceful shutdown follows a different lifecycle path (agents become
/// terminal history), but its accounting state must restore with the same
/// exact global, per-agent, and per-tenant totals.
#[tokio::test(flavor = "multi_thread")]
async fn graceful_restart_restores_exact_global_agent_and_tenant_spend() {
    const PROVIDER: &str = "fixed-graceful-accounting";
    const PER_AGENT_MICROS: u64 = 37_000;

    let db_path = temp_db_path("budget_graceful");
    let data_dir = db_path.parent().unwrap();
    let first_config = accounting_config(data_dir, 1.0, 1.0);
    let (first_agent, second_agent) = {
        let kernel = AgentKernelImpl::from_config(&first_config).expect("first boot");
        let (adapter, calls) = fixed_usage_adapter(PROVIDER, 30, 7);
        kernel
            .register_provider(adapter)
            .expect("register provider");
        let first = kernel
            .create_agent_full(accounting_agent_cfg("graceful-one", PROVIDER))
            .await
            .expect("create first agent");
        let second = kernel
            .create_agent_full(accounting_agent_cfg("graceful-two", PROVIDER))
            .await
            .expect("create second agent");

        for agent in [first.id, second.id] {
            let output = kernel
                .send_message(agent, "record one exact charge")
                .await
                .expect("provider request");
            assert_eq!(output.usage.charged_cost_micros, PER_AGENT_MICROS);
        }
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        kernel.shutdown().await.expect("graceful shutdown");
        drop(kernel);
        (first.id, second.id)
    };

    // A different price on boot cannot alter the charges committed above.
    let restart_config = accounting_config(data_dir, 9.0, 1.0);
    let kernel = AgentKernelImpl::from_config(&restart_config).expect("restart");
    let snapshot = kernel
        .context_manager
        .load_budget_usage_snapshot()
        .expect("load exact usage snapshot");
    assert_eq!(snapshot.global_micros, PER_AGENT_MICROS * 2);
    assert_eq!(
        snapshot.per_agent_micros.get(&first_agent),
        Some(&PER_AGENT_MICROS)
    );
    assert_eq!(
        snapshot.per_agent_micros.get(&second_agent),
        Some(&PER_AGENT_MICROS)
    );
    assert_eq!(
        snapshot.per_tenant_micros.get(DEFAULT_TENANT),
        Some(&(PER_AGENT_MICROS * 2))
    );
    assert_eq!(kernel.budget_enforcer.global_spent_usd(), 0.074);
    assert_eq!(kernel.budget_enforcer.agent_spent_usd(first_agent), 0.037);
    assert_eq!(kernel.budget_enforcer.agent_spent_usd(second_agent), 0.037);
    assert_eq!(
        kernel.budget_enforcer.tenant_spent_usd(DEFAULT_TENANT),
        0.074
    );

    drop(kernel);
    std::fs::remove_dir_all(data_dir).ok();
}
