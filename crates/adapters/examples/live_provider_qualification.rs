//! Secret-backed provider contract probe used only by the protected workflow.
//!
//! The probe never prints credentials, prompts, or model output. A missing
//! credential/endpoint is recorded as `not_run`; an attempted but failed
//! contract exits non-zero.

use std::time::Duration;

use adapters::anthropic::AnthropicAdapter;
use adapters::azure_openai::AzureOpenAiAdapter;
use adapters::deepseek::DeepseekAdapter;
use adapters::gemini::GeminiAdapter;
use adapters::groq::GroqAdapter;
use adapters::huggingface::HuggingFaceAdapter;
use adapters::local::LocalLlmAdapter;
use adapters::openai::OpenAiAdapter;
use adapters::vllm::VllmAdapter;
use kernel::connector::{LlmProviderAdapter, LlmRequestOptions, StandardMessage, ToolDefinition};

fn environment(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
}

fn not_run(provider: &str, reason: &str) -> ! {
    println!(
        "{}",
        serde_json::json!({
            "schema_version": 1,
            "provider": provider,
            "status": "not_run",
            "reason": reason,
        })
    );
    std::process::exit(0);
}

fn credential(provider: &str) -> String {
    environment("QUALIFICATION_API_KEY")
        .unwrap_or_else(|| not_run(provider, "protected credential is not configured"))
}

fn model_or(default: &str) -> String {
    environment("QUALIFICATION_MODEL").unwrap_or_else(|| default.into())
}

fn adapter(provider: &str) -> Box<dyn LlmProviderAdapter> {
    match provider {
        "openai" => {
            Box::new(OpenAiAdapter::new(credential(provider)).with_model(model_or("gpt-4o-mini")))
        }
        "anthropic" => Box::new(
            AnthropicAdapter::new(credential(provider))
                .with_model(model_or("claude-3-5-haiku-latest")),
        ),
        "groq" => Box::new(
            GroqAdapter::new(credential(provider)).with_model(model_or("llama-3.1-8b-instant")),
        ),
        "deepseek" => Box::new(
            DeepseekAdapter::new(credential(provider)).with_model(model_or("deepseek-chat")),
        ),
        "gemini" => Box::new(
            GeminiAdapter::new(credential(provider)).with_model(model_or("gemini-1.5-flash")),
        ),
        "huggingface" => Box::new(
            HuggingFaceAdapter::new(credential(provider))
                .with_model(model_or("meta-llama/Llama-3.1-8B-Instruct")),
        ),
        "azure-openai" => Box::new(
            AzureOpenAiAdapter::new(
                environment("QUALIFICATION_ENDPOINT")
                    .unwrap_or_else(|| not_run(provider, "protected endpoint is not configured")),
                environment("QUALIFICATION_DEPLOYMENT")
                    .unwrap_or_else(|| not_run(provider, "deployment is not configured")),
                credential(provider),
            )
            .with_api_version(
                environment("QUALIFICATION_API_VERSION")
                    .unwrap_or_else(|| "2024-08-01-preview".into()),
            ),
        ),
        "ollama" => Box::new(LocalLlmAdapter::new(
            environment("QUALIFICATION_ENDPOINT")
                .unwrap_or_else(|| not_run(provider, "qualification endpoint is not configured")),
            model_or("qwen2.5:0.5b"),
        )),
        "vllm" => Box::new(
            VllmAdapter::new(environment("QUALIFICATION_API_KEY").unwrap_or_default())
                .with_base_url(environment("QUALIFICATION_ENDPOINT").unwrap_or_else(|| {
                    not_run(provider, "qualification endpoint is not configured")
                }))
                .with_model(model_or("Qwen/Qwen2.5-0.5B-Instruct")),
        ),
        other => not_run(other, "provider is not part of the qualification matrix"),
    }
}

#[tokio::main]
async fn main() {
    let provider = environment("QUALIFICATION_PROVIDER")
        .unwrap_or_else(|| not_run("unknown", "QUALIFICATION_PROVIDER is unset"));
    let adapter = adapter(&provider);
    let capabilities = adapter.capabilities();
    let session = match adapter.create_session().await {
        Ok(session) => session,
        Err(error) => {
            println!(
                "{}",
                serde_json::json!({
                    "schema_version": 1,
                    "provider": provider,
                    "status": "failed",
                    "stage": "create_session",
                    "error": error.to_string(),
                })
            );
            std::process::exit(1);
        }
    };
    let tools = capabilities.tool_calls.then(|| {
        vec![ToolDefinition {
            name: "qualification_echo".into(),
            description: "Return the supplied short text.".into(),
            parameters: serde_json::json!({
                "type": "object",
                "properties": {"text": {"type": "string"}},
                "required": ["text"],
                "additionalProperties": false
            }),
        }]
    });
    let cancellation = tokio_util::sync::CancellationToken::new();
    let response = match session
        .send_controlled(
            vec![
                StandardMessage::system(
                    "This is a provider contract probe. Reply with the word ready.",
                ),
                StandardMessage::user("ready"),
            ],
            tools.as_deref().unwrap_or_default(),
            LlmRequestOptions {
                max_output_tokens: Some(32),
                timeout: Some(Duration::from_secs(90)),
            },
            &cancellation,
        )
        .await
    {
        Ok(response) => response,
        Err(error) => {
            println!(
                "{}",
                serde_json::json!({
                    "schema_version": 1,
                    "provider": provider,
                    "status": "failed",
                    "stage": "send",
                    "error": error.to_string(),
                    "request_id": error.request_id(),
                })
            );
            std::process::exit(1);
        }
    };
    let passed = !response.content.trim().is_empty() || !response.tool_calls.is_empty();
    println!(
        "{}",
        serde_json::json!({
            "schema_version": 1,
            "provider": provider,
            "model": session.model_id(),
            "status": if passed { "passed" } else { "failed" },
            "capabilities": capabilities,
            "response": {
                "content_nonempty": !response.content.trim().is_empty(),
                "content_bytes": response.content.len(),
                "tool_call_count": response.tool_calls.len(),
                "finish_reason": response.finish_reason,
                "tokens_used": response.tokens_used,
                "usage": response.usage,
            }
        })
    );
    if !passed {
        std::process::exit(1);
    }
}
