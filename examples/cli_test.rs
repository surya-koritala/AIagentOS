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
        name: "web-agent".into(), task: "browsing".into(),
        llm_provider: "azure-openai".into(), permission_profile: "full-access".into(),
        priority: Priority::default(), sandbox_config: None,
    }).await.unwrap();

    println!("=== Web Browsing Test ===");
    let out = kernel.send_message(handle.id, "Browse https://httpbin.org/html and tell me what the page is about in one sentence").await.unwrap();
    println!("Response: {}", out.content);
    println!("Tools: {}", out.tool_calls_made);
    println!("\n✅ Done!");
}
