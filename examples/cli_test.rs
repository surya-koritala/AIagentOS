use std::sync::Arc;
use kernel::{AgentConfig, AgentKernelImpl, Priority};
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
        name: "editor".into(), task: "code editing".into(),
        llm_provider: "azure-openai".into(), permission_profile: "full-access".into(),
        priority: Priority::default(), sandbox_config: None,
    }).await.unwrap();

    // Setup: create test files
    std::fs::create_dir_all("/tmp/edit_test").unwrap();
    std::fs::write("/tmp/edit_test/main.rs", "fn main() {\n    println!(\"hello\");\n}\n").unwrap();
    std::fs::write("/tmp/edit_test/lib.rs", "pub fn greet() -> &'static str {\n    \"hello\"\n}\n").unwrap();

    println!("=== Multi-File Editing E2E ===\n");
    let out = kernel.send_message(handle.id,
        "In /tmp/edit_test/, change the greeting from 'hello' to 'hello world' in BOTH main.rs and lib.rs. Read each file first, then write the updated versions."
    ).await.unwrap();
    println!("Response: {}", out.content);
    println!("Tools: {}\n", out.tool_calls_made);

    // Verify
    let main = std::fs::read_to_string("/tmp/edit_test/main.rs").unwrap();
    let lib = std::fs::read_to_string("/tmp/edit_test/lib.rs").unwrap();
    println!("main.rs: {}", main.trim());
    println!("lib.rs: {}", lib.trim());

    if main.contains("hello world") && lib.contains("hello world") {
        println!("\n✅ Both files updated correctly!");
    } else {
        println!("\n❌ Files not updated as expected");
    }
}
