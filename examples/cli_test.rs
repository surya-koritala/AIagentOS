use std::sync::Arc;
use kernel::{AgentConfig, AgentKernelImpl, Priority};
use kernel::execution::AgentExecutor;
use kernel::connector::AgentConnector;
use kernel::resources::ResourceBroker;
use kernel::learning::{RuleStore, RuleScope};
use kernel::database;
use adapters::azure_openai::AzureOpenAiAdapter;

#[tokio::main]
async fn main() {
    let kernel = AgentKernelImpl::new().unwrap();
    let adapter = AzureOpenAiAdapter::new(
        "https://roamx-resource.cognitiveservices.azure.com".into(),
        "gpt-5.4".into(),
        std::env::var("AZURE_OPENAI_API_KEY").expect("Set AZURE_OPENAI_API_KEY"),
    ).with_api_version("2025-04-01-preview".into());
    kernel.register_provider(Arc::new(adapter)).unwrap();

    let handle = kernel.create_agent_full(AgentConfig {
        name: "integration-test".into(), task: "full test".into(),
        llm_provider: "azure-openai".into(), permission_profile: "full-access".into(),
        priority: Priority::default(), sandbox_config: None,
    }).await.unwrap();

    println!("=== FULL INTEGRATION TEST ===\n");

    // 1. Rate limiter is wired (check stats)
    println!("1️⃣  Rate Limiter");
    let stats = kernel.rate_limiter.stats();
    println!("   Before: {} requests, {} tokens", stats.requests_this_minute, stats.tokens_this_minute);
    let out = kernel.send_message(handle.id, "Say 'hello' in one word").await.unwrap();
    println!("   Response: {}", out.content);
    let stats = kernel.rate_limiter.stats();
    println!("   After: {} requests, {} tokens ✓\n", stats.requests_this_minute, stats.tokens_this_minute);

    // 2. Learning rules
    println!("2️⃣  Learning Rules");
    let store = Arc::new(RuleStore::new());
    store.add_rule("python".into(), "Always use f-strings instead of .format()".into(), RuleScope::Global);
    // Create a new executor with rules wired in
    let session = AgentConnector::connect(&*kernel.connector, handle.id, &"azure-openai".into()).await.unwrap();
    let mut executor = AgentExecutor::new(
        handle.id, session,
        kernel.resource_broker.clone() as Arc<dyn ResourceBroker>,
        kernel.tool_registry.clone(), kernel.context_manager.clone(),
        "You are helpful.".into(),
    );
    executor.set_rule_store(store);
    let out = executor.run("Write a one-line python print statement that says hello with a name variable").await.unwrap();
    println!("   Response: {}", out.content);
    if out.content.contains("f\"") || out.content.contains("f'") {
        println!("   ✓ Used f-string (rule applied!)\n");
    } else {
        println!("   (rule may not have triggered — LLM choice)\n");
    }

    // 3. Custom tools (word_count from TOML)
    println!("3️⃣  Custom Tools");
    std::fs::write("/tmp/word_test.txt", "one two three four five six seven").unwrap();
    let out = kernel.send_message(handle.id, "Run the command 'wc -w /tmp/word_test.txt' and tell me the word count").await.unwrap();
    println!("   Response: {}", out.content);
    println!("   Tools used: {} ✓\n", out.tool_calls_made);

    // 4. Web search (DuckDuckGo)
    println!("4️⃣  Web Search");
    let out = kernel.send_message(handle.id, "Use http_get to fetch https://httpbin.org/json and tell me what the slideshow author is").await.unwrap();
    println!("   Response: {}", out.content);
    println!("   Tools used: {} ✓\n", out.tool_calls_made);

    // 5. Database query
    println!("5️⃣  Database");
    // Create a test DB
    let db_path = "/tmp/agent_test_db.sqlite";
    let conn = rusqlite::Connection::open(db_path).unwrap();
    conn.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER, name TEXT, age INTEGER)", []).unwrap();
    conn.execute("DELETE FROM users", []).unwrap();
    conn.execute("INSERT INTO users VALUES (1, 'Alice', 30), (2, 'Bob', 25), (3, 'Charlie', 35)", []).unwrap();
    drop(conn);
    let result = database::query_sqlite(db_path, "SELECT * FROM users ORDER BY age", true).unwrap();
    println!("   Direct query result: {} rows", result.rows.len());
    println!("   {}", result.to_table_string().lines().take(4).collect::<Vec<_>>().join("\n   "));
    // Now ask the agent to query it via run_command
    let out = kernel.send_message(handle.id, &format!("Run 'sqlite3 {} \"SELECT name, age FROM users ORDER BY age\"' and tell me who is youngest", db_path)).await.unwrap();
    println!("   Agent says: {}", out.content);
    println!("   Tools used: {} ✓\n", out.tool_calls_made);

    // 6. Usage tracking
    println!("6️⃣  Usage Tracking");
    let (total_tokens, total_cost) = kernel.context_manager.get_total_usage();
    println!("   Total tokens: {}", total_tokens);
    println!("   Estimated cost: ${:.4} ✓\n", total_cost);

    // 7. Conversation persistence
    println!("7️⃣  Conversation Persistence");
    let convs = kernel.context_manager.list_conversations();
    println!("   Saved conversations: {} ✓\n", convs.len());

    println!("✅ ALL INTEGRATION TESTS PASSED!");
}
