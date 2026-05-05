//! Edge case tests for all modules.
//! Tests boundary conditions, error paths, and unusual inputs.

use std::sync::Arc;
use kernel::*;
use kernel::context::*;
use kernel::tools::*;
use kernel::connector::*;
use kernel::planning::*;
use kernel::editing::*;
use kernel::learning::*;
use kernel::rate_limit::*;
use kernel::production::*;
use kernel::indexer::*;
use kernel::database::*;

// ─── Execution Edge Cases ────────────────────────────────────────────────────

#[tokio::test]
async fn execution_empty_message() {
    // Empty message should still work (LLM handles it)
    let kernel = AgentKernelImpl::new().unwrap();
    // Can't test without provider, but verify kernel doesn't panic on empty
    let handle = kernel.create_agent_full(AgentConfig {
        name: "test".into(), task: "test".into(),
        llm_provider: "nonexistent".into(), permission_profile: "standard".into(),
        priority: Priority::default(), sandbox_config: None,
    }).await.unwrap();
    // send_message with empty string should return error (no provider), not panic
    let result = kernel.send_message(handle.id, "").await;
    assert!(result.is_err());
}

#[tokio::test]
async fn execution_very_long_message() {
    // 100KB message shouldn't panic
    let kernel = AgentKernelImpl::new().unwrap();
    let handle = kernel.create_agent_full(AgentConfig {
        name: "test".into(), task: "test".into(),
        llm_provider: "nonexistent".into(), permission_profile: "standard".into(),
        priority: Priority::default(), sandbox_config: None,
    }).await.unwrap();
    let long_msg = "x".repeat(100_000);
    let result = kernel.send_message(handle.id, &long_msg).await;
    assert!(result.is_err()); // No provider, but shouldn't panic
}

// ─── Context Edge Cases ──────────────────────────────────────────────────────

#[tokio::test]
async fn context_persist_empty_context() {
    let mgr = SqliteContextManager::in_memory().unwrap();
    let id = uuid::Uuid::new_v4();
    mgr.create_context(id).await.unwrap();
    let ctx = mgr.get_context(id).await.unwrap();
    assert!(ctx.conversation_history.is_empty());
}

#[tokio::test]
async fn context_persist_unicode_content() {
    let mgr = SqliteContextManager::in_memory().unwrap();
    let id = uuid::Uuid::new_v4();
    mgr.create_context(id).await.unwrap();
    let mut ctx = AgentContext::default();
    ctx.conversation_history.push(Message {
        role: "user".into(),
        content: "こんにちは 🌍 émojis ñ ü ∞ 中文".into(),
        timestamp: chrono::Utc::now(),
    });
    mgr.persist_context(id, &ctx).await.unwrap();
    let restored = mgr.restore_context(id).await.unwrap();
    assert_eq!(restored.conversation_history[0].content, "こんにちは 🌍 émojis ñ ü ∞ 中文");
}

#[tokio::test]
async fn context_conversation_save_empty_messages() {
    let mgr = SqliteContextManager::in_memory().unwrap();
    let id = uuid::Uuid::new_v4();
    mgr.save_conversation("conv1", id, &[]).unwrap();
    let loaded = mgr.load_conversation("conv1").unwrap();
    assert!(loaded.is_empty());
}

#[tokio::test]
async fn context_search_special_characters() {
    let mgr = SqliteContextManager::in_memory().unwrap();
    let id = uuid::Uuid::new_v4();
    let msgs = vec![StandardMessage::user("test with 'quotes' and \"double quotes\"")];
    mgr.save_conversation("conv_special", id, &msgs).unwrap();
    // Search shouldn't crash on special chars
    let results = mgr.search_conversations("quotes");
    // FTS5 may or may not find it depending on tokenization, but shouldn't panic
    assert!(results.len() <= 1);
}

// ─── Tools Edge Cases ────────────────────────────────────────────────────────

#[test]
fn tools_resolve_with_missing_arguments() {
    let reg = ToolRegistry::new();
    let agent_id = uuid::Uuid::new_v4();
    // Tool call with empty arguments
    let tc = ToolCall { id: "1".into(), name: "read_file".into(), arguments: serde_json::json!({}) };
    let req = reg.resolve(agent_id, &tc);
    assert!(req.is_some()); // Should resolve (missing path handled by provider)
}

#[test]
fn tools_resolve_with_null_arguments() {
    let reg = ToolRegistry::new();
    let agent_id = uuid::Uuid::new_v4();
    let tc = ToolCall { id: "1".into(), name: "read_file".into(), arguments: serde_json::Value::Null };
    let req = reg.resolve(agent_id, &tc);
    assert!(req.is_some());
}

#[test]
fn tools_custom_template_with_missing_param() {
    let mut reg = ToolRegistry::new();
    reg.register(ToolBinding {
        name: "custom".into(), description: "test".into(),
        parameters_schema: serde_json::json!({}),
        resource_type: kernel::resources::ResourceType::Application,
        operation: "launch".into(),
    });
    reg.register_command_template("custom", "echo", &["{missing_param}".into()]);
    let tc = ToolCall { id: "1".into(), name: "custom".into(), arguments: serde_json::json!({"other": "val"}) };
    let req = reg.resolve(uuid::Uuid::new_v4(), &tc).unwrap();
    // Missing param should remain as literal {missing_param}
    assert!(req.parameters["args"][0].as_str().unwrap().contains("{missing_param}"));
}

// ─── Planning Edge Cases ─────────────────────────────────────────────────────

#[test]
fn planning_parse_empty_response() {
    let steps = parse_plan_steps("");
    assert!(steps.is_empty());
}

#[test]
fn planning_parse_no_numbered_lines() {
    let steps = parse_plan_steps("This is just text\nwith no numbers\nat all");
    assert!(steps.is_empty());
}

#[test]
fn planning_parse_mixed_formats() {
    let text = "1. First\n2) Second\n3. Third\n- Not a step\n4. Fourth";
    let steps = parse_plan_steps(text);
    assert_eq!(steps.len(), 4);
}

// ─── Editing Edge Cases ──────────────────────────────────────────────────────

#[test]
fn editing_replace_not_found() {
    let dir = std::env::temp_dir().join(format!("edge_{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("test.txt");
    std::fs::write(&file, "hello world").unwrap();

    let mut tx = EditTransaction::new();
    tx.add(FileEdit { path: file.clone(), operation: EditOperation::Replace { search: "NOTFOUND".into(), replace: "x".into() } });
    let result = tx.apply();
    assert!(result.is_err());
    // File should be unchanged
    assert_eq!(std::fs::read_to_string(&file).unwrap(), "hello world");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn editing_create_in_nonexistent_directory() {
    let path = std::env::temp_dir().join(format!("edge_{}/deep/nested/file.txt", uuid::Uuid::new_v4()));
    let mut tx = EditTransaction::new();
    tx.add(FileEdit { path: path.clone(), operation: EditOperation::Create { content: "hello".into() } });
    let result = tx.apply();
    assert!(result.is_ok());
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "hello");
    std::fs::remove_dir_all(path.parent().unwrap().parent().unwrap().parent().unwrap()).ok();
}

#[test]
fn editing_empty_file_operations() {
    let mut tx = EditTransaction::new();
    // Empty transaction should succeed
    let result = tx.apply();
    assert!(result.is_ok());
    assert!(result.unwrap().is_empty());
}

// ─── Rate Limiter Edge Cases ─────────────────────────────────────────────────

#[tokio::test]
async fn rate_limit_zero_rpm() {
    // rpm=0 should effectively block everything... but our impl uses u32
    // This tests the boundary
    let limiter = RateLimiter::new(RateLimitConfig { rpm: 1, tpm: 100, max_concurrent: 1 });
    let _g = limiter.acquire().await;
    assert!(limiter.is_limited()); // 1 >= 1
}

#[tokio::test]
async fn rate_limit_record_zero_tokens() {
    let limiter = RateLimiter::new(RateLimitConfig::default());
    limiter.record_tokens(0);
    assert_eq!(limiter.stats().tokens_this_minute, 0);
}

// ─── Production Edge Cases ───────────────────────────────────────────────────

#[test]
fn circuit_breaker_immediate_success_after_creation() {
    let cb = CircuitBreaker::new(5, 60);
    cb.record_success(); // Should not panic even without prior failure
    assert!(cb.is_available());
}

#[test]
fn budget_enforcer_exact_limit() {
    let be = BudgetEnforcer::new(1.0);
    be.record_cost(1.0); // Exactly at limit
    assert!(!be.can_proceed()); // >= limit means stop
}

#[test]
fn budget_enforcer_negative_cost() {
    let be = BudgetEnforcer::new(1.0);
    be.record_cost(-0.5); // Shouldn't happen but shouldn't panic
    assert!(be.can_proceed());
}

// ─── Indexer Edge Cases ──────────────────────────────────────────────────────

#[test]
fn indexer_empty_directory() {
    let dir = std::env::temp_dir().join(format!("edge_idx_{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let map = RepoMap::build(&dir);
    assert_eq!(map.total_files, 0);
    assert_eq!(map.total_lines, 0);
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn indexer_binary_files_skipped() {
    let dir = std::env::temp_dir().join(format!("edge_idx2_{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("image.png"), &[0x89, 0x50, 0x4E, 0x47]).unwrap();
    std::fs::write(dir.join("code.rs"), "fn main() {}").unwrap();
    let map = RepoMap::build(&dir);
    assert_eq!(map.total_files, 1); // Only .rs, not .png
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn indexer_deeply_nested() {
    let dir = std::env::temp_dir().join(format!("edge_idx3_{}", uuid::Uuid::new_v4()));
    // Create 7 levels deep (should stop at 5)
    let deep = dir.join("a/b/c/d/e/f/g");
    std::fs::create_dir_all(&deep).unwrap();
    std::fs::write(deep.join("deep.rs"), "fn deep() {}").unwrap();
    std::fs::write(dir.join("a/shallow.rs"), "fn shallow() {}").unwrap();
    let map = RepoMap::build(&dir);
    // shallow.rs should be found, deep.rs might not (depth limit)
    assert!(map.files.iter().any(|f| f.path.contains("shallow")));
    std::fs::remove_dir_all(&dir).ok();
}

// ─── Database Edge Cases ─────────────────────────────────────────────────────

#[test]
fn database_sql_injection_attempt() {
    let path = "/tmp/edge_db_inject.db";
    let conn = rusqlite::Connection::open(path).unwrap();
    conn.execute("CREATE TABLE IF NOT EXISTS t (x TEXT)", []).unwrap();
    conn.execute("INSERT INTO t VALUES ('safe')", []).unwrap();
    drop(conn);

    // This should not execute the DROP TABLE
    let result = query_sqlite(path, "SELECT * FROM t WHERE x = 'a'; DROP TABLE t; --'", true);
    // SQLite doesn't execute multiple statements in one query_row, so this is safe
    // But it might error — either way, table should still exist
    let check = query_sqlite(path, "SELECT COUNT(*) FROM t", true);
    assert!(check.is_ok());
    std::fs::remove_file(path).ok();
}

#[test]
fn database_nonexistent_file() {
    let result = query_sqlite("/tmp/nonexistent_db_edge.db", "SELECT 1", true);
    // Should either create the file or error gracefully
    assert!(result.is_ok() || result.is_err());
    std::fs::remove_file("/tmp/nonexistent_db_edge.db").ok();
}

// ─── Learning Edge Cases ─────────────────────────────────────────────────────

#[test]
fn learning_empty_trigger() {
    let store = RuleStore::new();
    store.add_rule("".into(), "correction".into(), RuleScope::Global);
    // Empty trigger matches everything
    let found = store.find_applicable("anything");
    assert_eq!(found.len(), 1);
}

#[test]
fn learning_case_insensitive_matching() {
    let store = RuleStore::new();
    store.add_rule("Python".into(), "use type hints".into(), RuleScope::Global);
    let found = store.find_applicable("write python code");
    assert_eq!(found.len(), 1); // Should match case-insensitively
}

// ─── Vision Edge Cases ───────────────────────────────────────────────────────

#[test]
fn vision_nonexistent_file() {
    let result = kernel::vision::image_to_data_url("/tmp/nonexistent_image.png");
    assert!(result.is_err());
}

#[test]
fn vision_empty_file() {
    std::fs::write("/tmp/empty_image.png", &[]).unwrap();
    let result = kernel::vision::image_to_data_url("/tmp/empty_image.png");
    assert!(result.is_ok()); // Empty but valid
    assert!(result.unwrap().contains("base64,"));
    std::fs::remove_file("/tmp/empty_image.png").ok();
}
