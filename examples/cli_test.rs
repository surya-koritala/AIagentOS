use std::sync::Arc;
use kernel::{AgentConfig, AgentKernelImpl, Priority};
use adapters::azure_openai::AzureOpenAiAdapter;

#[tokio::main]
async fn main() {
    let endpoint = std::env::var("AZURE_OPENAI_ENDPOINT")
        .expect("Set AZURE_OPENAI_ENDPOINT env var");
    let deployment = std::env::var("AZURE_OPENAI_DEPLOYMENT")
        .unwrap_or_else(|_| "gpt-4o".to_string());
    let api_key = std::env::var("AZURE_OPENAI_API_KEY")
        .expect("Set AZURE_OPENAI_API_KEY env var");
    let api_version = std::env::var("AZURE_OPENAI_API_VERSION")
        .unwrap_or_else(|_| "2024-08-01-preview".to_string());

    let kernel = AgentKernelImpl::new().unwrap();
    let adapter = AzureOpenAiAdapter::new(endpoint, deployment, api_key)
        .with_api_version(api_version);
    kernel.register_provider(Arc::new(adapter)).unwrap();

    let handle = kernel.create_agent_full(AgentConfig {
        name: "cli-agent".into(),
        task: "general assistant".into(),
        llm_provider: "azure-openai".into(),
        permission_profile: "full-access".into(),
        priority: Priority::default(),
        sandbox_config: None,
    }).await.unwrap();

    println!("Agent ready! Testing...\n");

    // Simple chat
    let out = kernel.send_message(handle.id, "What is 2+2? One word.").await.unwrap();
    println!("[Chat] {}", out.content);

    // Tool use
    let out = kernel.send_message(handle.id, "List files in /tmp and tell me how many there are").await.unwrap();
    println!("[Tools: {}] {}", out.tool_calls_made, out.content);

    println!("\n✅ Done! Tokens used: {}", out.tokens_used);
}
