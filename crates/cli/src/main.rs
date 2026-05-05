//! AI Agent OS — CLI (headless terminal agent)
//!
//! Usage:
//!   agent                    # Start interactive session
//!   agent --conversation ID  # Resume a conversation

use std::io::{self, BufRead, Write};
use std::sync::Arc;

use kernel::{AgentConfig, AgentKernelImpl, Priority};
use kernel::config::Config;
use kernel::connector::AgentConnector;
use kernel::custom_tools::load_custom_tools;
use kernel::execution::{AgentExecutor, StreamEvent};
use kernel::resources::ResourceBroker;
use kernel::tools::ToolRegistry;
use adapters::azure_openai::AzureOpenAiAdapter;
use adapters::openai::OpenAiAdapter;
use adapters::anthropic::AnthropicAdapter;
use adapters::local::LocalLlmAdapter;
use tokio::sync::mpsc;

fn register_providers(kernel: &AgentKernelImpl, config: &Config) {
    match config.llm_provider.as_str() {
        "azure-openai" => {
            let endpoint = config.azure_endpoint.clone().or_else(|| std::env::var("AZURE_OPENAI_ENDPOINT").ok()).unwrap_or_default();
            let deployment = config.azure_deployment.clone().or_else(|| std::env::var("AZURE_OPENAI_DEPLOYMENT").ok()).unwrap_or_else(|| "gpt-4o".into());
            let key = config.get_api_key("azure-openai").map(|s| s.to_string()).or_else(|| std::env::var("AZURE_OPENAI_API_KEY").ok()).unwrap_or_default();
            let version = config.azure_api_version.clone().or_else(|| std::env::var("AZURE_OPENAI_API_VERSION").ok()).unwrap_or_else(|| "2024-08-01-preview".into());
            if !key.is_empty() {
                let adapter = AzureOpenAiAdapter::new(endpoint, deployment, key).with_api_version(version);
                let _ = kernel.register_provider(Arc::new(adapter));
            }
        }
        "openai" => {
            if let Some(key) = config.get_api_key("openai").or(std::env::var("OPENAI_API_KEY").ok().as_deref()) {
                let _ = kernel.register_provider(Arc::new(OpenAiAdapter::new(key.to_string())));
            }
        }
        "anthropic" => {
            if let Some(key) = config.get_api_key("anthropic").or(std::env::var("ANTHROPIC_API_KEY").ok().as_deref()) {
                let _ = kernel.register_provider(Arc::new(AnthropicAdapter::new(key.to_string())));
            }
        }
        "local" => {
            let url = config.get_api_key("local").unwrap_or("http://localhost:11434");
            let _ = kernel.register_provider(Arc::new(LocalLlmAdapter::new(url.to_string(), config.default_model.clone())));
        }
        _ => {}
    }
}

#[tokio::main]
async fn main() {
    let config = Config::load();
    let kernel = AgentKernelImpl::from_config(&config).expect("Failed to init kernel");
    register_providers(&kernel, &config);

    // Load custom tools
    let tools_path = dirs::config_dir().unwrap_or_default().join("ai-agent-os/tools.toml");
    // Custom tools would need mutable registry - skip for now in CLI

    // Parse args
    let args: Vec<String> = std::env::args().collect();
    let conversation_id = args.iter().position(|a| a == "--conversation").and_then(|i| args.get(i + 1)).cloned();

    // Create agent
    let handle = kernel.create_agent_full(AgentConfig {
        name: "cli-agent".into(),
        task: "interactive assistant".into(),
        llm_provider: config.llm_provider.clone(),
        permission_profile: "full-access".into(),
        priority: Priority::default(),
        sandbox_config: None,
    }).await.expect("Failed to create agent");

    // Create executor
    let session = AgentConnector::connect(&*kernel.connector, handle.id, &config.llm_provider).await
        .expect("Failed to connect to LLM provider. Check your API key.");
    let mut executor = AgentExecutor::new(
        handle.id, session,
        kernel.resource_broker.clone() as Arc<dyn ResourceBroker>,
        kernel.tool_registry.clone(),
        kernel.context_manager.clone(),
        "You are a helpful AI assistant running in a terminal. Be concise.".into(),
    );

    if let Some(ref conv_id) = conversation_id {
        executor = executor.with_conversation(conv_id);
        eprintln!("\x1b[90mResumed conversation {}\x1b[0m", conv_id);
    }

    eprintln!("\x1b[36m⚡ AI Agent OS ({})\x1b[0m", config.llm_provider);
    eprintln!("\x1b[90mConversation: {}\x1b[0m", executor.conversation_id);
    eprintln!("\x1b[90mType your message. Ctrl+C to exit.\x1b[0m\n");

    let (tx, mut rx) = mpsc::channel::<StreamEvent>(256);
    executor.set_event_channel(tx);

    let stdin = io::stdin();
    let mut stdout = io::stdout();

    loop {
        // Prompt
        print!("\x1b[32m❯\x1b[0m ");
        stdout.flush().ok();

        let mut input = String::new();
        if stdin.lock().read_line(&mut input).unwrap_or(0) == 0 {
            break; // EOF
        }
        let input = input.trim();
        if input.is_empty() { continue; }

        // Slash commands
        match input {
            "/quit" | "/exit" => break,
            "/id" => { println!("\x1b[90m{}\x1b[0m", executor.conversation_id); continue; }
            _ => {}
        }

        // Run agent (in background so we can process events)
        let msg = input.to_string();

        // We need to split executor usage - run directly since we own it
        // Drop the event channel temporarily for direct run
        let output = executor.run(&msg).await;

        // Drain any events
        while let Ok(event) = rx.try_recv() {
            match event {
                StreamEvent::ToolCallStarted { name, .. } => {
                    eprintln!("\x1b[33m  🔧 {}\x1b[0m", name);
                }
                StreamEvent::ToolCallResult { name, result } => {
                    let preview: String = result.chars().take(80).collect();
                    eprintln!("\x1b[90m  ✓ {} → {}\x1b[0m", name, preview);
                }
                _ => {}
            }
        }

        match output {
            Ok(out) => {
                println!("\n\x1b[37m{}\x1b[0m", out.content);
                if out.tool_calls_made > 0 {
                    eprintln!("\x1b[90m  [{} tools, {} tokens]\x1b[0m\n", out.tool_calls_made, out.tokens_used);
                } else {
                    eprintln!("\x1b[90m  [{} tokens]\x1b[0m\n", out.tokens_used);
                }
            }
            Err(e) => {
                eprintln!("\x1b[31m  Error: {}\x1b[0m\n", e);
            }
        }
    }

    eprintln!("\n\x1b[90mConversation saved: {}\x1b[0m", executor.conversation_id);
}
