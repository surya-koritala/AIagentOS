use std::sync::Arc;
use kernel::{AgentConfig, AgentKernelImpl, Priority};
use kernel::custom_tools::load_custom_tools;
use kernel::tools::ToolRegistry;
use adapters::azure_openai::AzureOpenAiAdapter;

#[tokio::main]
async fn main() {
    // Load custom tools
    let mut registry = ToolRegistry::new();
    let tools_path = dirs::config_dir().unwrap().join("ai-agent-os/tools.toml");
    load_custom_tools(&mut registry, &tools_path);
    println!("Tools loaded: {}", registry.definitions().len());
    for d in registry.definitions() {
        println!("  - {}: {}", d.name, d.description);
    }

    // Test with real LLM
    let kernel = AgentKernelImpl::new().unwrap();
    let adapter = AzureOpenAiAdapter::new(
        "https://roamx-resource.cognitiveservices.azure.com".into(),
        "gpt-5.4".into(),
        std::env::var("AZURE_OPENAI_API_KEY").expect("Set AZURE_OPENAI_API_KEY"),
    ).with_api_version("2025-04-01-preview".into());
    kernel.register_provider(Arc::new(adapter)).unwrap();

    // Register custom tools in the kernel's registry (need mutable access)
    // For now test that they load correctly - the kernel integration will use from_config
    println!("\n✅ Custom tools loaded from TOML successfully!");
}
