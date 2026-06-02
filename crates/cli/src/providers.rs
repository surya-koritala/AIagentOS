//! LLM provider registration shared by the interactive `agent` CLI and the
//! `agent-server` syscall daemon. Reads `config.llm_provider` (and the matching
//! API-key/env vars) and registers the corresponding `LlmProviderAdapter` with
//! the kernel connector, so `SendMessage` syscalls reach a real backend.

use std::sync::Arc;

use adapters::anthropic::AnthropicAdapter;
use adapters::azure_openai::AzureOpenAiAdapter;
use adapters::deepseek::DeepseekAdapter;
use adapters::groq::GroqAdapter;
use adapters::local::LocalLlmAdapter;
use adapters::openai::OpenAiAdapter;
use kernel::config::Config;
use kernel::AgentKernelImpl;

/// Register the LLM provider selected by `config.llm_provider` with the kernel.
/// A no-op for an unknown provider or a missing API key, so a keyless boot still
/// serves the non-LLM syscalls.
pub fn register_providers(kernel: &AgentKernelImpl, config: &Config) {
    match config.llm_provider.as_str() {
        "azure-openai" => {
            let endpoint = config
                .azure_endpoint
                .clone()
                .or_else(|| std::env::var("AZURE_OPENAI_ENDPOINT").ok())
                .unwrap_or_default();
            let deployment = config
                .azure_deployment
                .clone()
                .or_else(|| std::env::var("AZURE_OPENAI_DEPLOYMENT").ok())
                .unwrap_or_else(|| "gpt-4o".into());
            let key = config
                .get_api_key("azure-openai")
                .map(|s| s.to_string())
                .or_else(|| std::env::var("AZURE_OPENAI_API_KEY").ok())
                .unwrap_or_default();
            let version = config
                .azure_api_version
                .clone()
                .or_else(|| std::env::var("AZURE_OPENAI_API_VERSION").ok())
                .unwrap_or_else(|| "2024-08-01-preview".into());
            if !key.is_empty() {
                let adapter =
                    AzureOpenAiAdapter::new(endpoint, deployment, key).with_api_version(version);
                let _ = kernel.register_provider(Arc::new(adapter));
            }
        }
        "openai" => {
            if let Some(key) = config
                .get_api_key("openai")
                .map(|s| s.to_string())
                .or_else(|| std::env::var("OPENAI_API_KEY").ok())
            {
                let _ = kernel.register_provider(Arc::new(OpenAiAdapter::new(key)));
            }
        }
        "anthropic" => {
            if let Some(key) = config
                .get_api_key("anthropic")
                .map(|s| s.to_string())
                .or_else(|| std::env::var("ANTHROPIC_API_KEY").ok())
            {
                let _ = kernel.register_provider(Arc::new(AnthropicAdapter::new(key)));
            }
        }
        "groq" => {
            if let Some(key) = config
                .get_api_key("groq")
                .map(|s| s.to_string())
                .or_else(|| std::env::var("GROQ_API_KEY").ok())
            {
                let adapter = GroqAdapter::new(key).with_model(config.default_model.clone());
                let _ = kernel.register_provider(Arc::new(adapter));
            }
        }
        "deepseek" => {
            if let Some(key) = config
                .get_api_key("deepseek")
                .map(|s| s.to_string())
                .or_else(|| std::env::var("DEEPSEEK_API_KEY").ok())
            {
                let adapter = DeepseekAdapter::new(key).with_model(config.default_model.clone());
                let _ = kernel.register_provider(Arc::new(adapter));
            }
        }
        "local" => {
            let url = config
                .get_api_key("local")
                .unwrap_or("http://localhost:11434")
                .to_string();
            let _ = kernel.register_provider(Arc::new(LocalLlmAdapter::new(
                url,
                config.default_model.clone(),
            )));
        }
        _ => {}
    }
}
