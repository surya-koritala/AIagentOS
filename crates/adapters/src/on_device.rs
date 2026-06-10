//! On-device LLM inference (pure-Rust, CPU) via `candle`.
//!
//! This is the in-process counterpart to [`crate::local::LocalLlmAdapter`]:
//! where `local` is an HTTP client to an external Ollama/llama.cpp server, this
//! adapter loads a quantized **GGUF** model and runs the forward pass *inside
//! the kernel process* — no network, no sidecar, no Python, no C++ FFI. The
//! whole inference stack (`candle-core`, `candle-transformers`, `gemm`,
//! `tokenizers`) is Rust, so it cross-compiles to `aarch64`/`armv7` and runs on
//! a Raspberry Pi or any headless edge box.
//!
//! It plugs into the unchanged [`LlmProviderAdapter`] seam, so the kernel,
//! syscall gate, scheduler and persistence treat it exactly like any cloud
//! provider — the only difference is where the tokens are produced.
//!
//! ## Scope (this is a spike)
//! - Greedy / temperature sampling of a single GGUF model on CPU.
//! - A model-agnostic instruct prompt format (see [`build_prompt`]). Production
//!   use should apply the model's real chat template.
//! - No native tool-calling: small on-device models emit tool calls as plain
//!   text, which the executor's plaintext shim recovers — so we return an empty
//!   `tool_calls` vec, same as the Ollama adapter.
//! - KV-cache is re-primed from the full prompt on every `send` (the executor
//!   passes the whole history each turn), so turns don't share cache state.
//!
//! ## Running it
//! Build with the feature and point it at a local GGUF + tokenizer:
//! ```text
//! cargo build -p adapters --features candle
//! AGENTOS_GGUF_MODEL=/models/qwen2.5-0.5b-instruct-q4_k_m.gguf \
//! AGENTOS_TOKENIZER=/models/qwen2.5-0.5b-tokenizer.json \
//! RAYON_NUM_THREADS=4   # cap CPU threads on small boards
//! ```

use std::sync::Mutex;

use candle_core::quantized::gguf_file;
use candle_core::{Device, Tensor};
use candle_transformers::generation::LogitsProcessor;
use candle_transformers::models::quantized_llama::ModelWeights;
use tokenizers::Tokenizer;

use kernel::connector::*;
use kernel::{ConnectorError, ProviderId};

/// Configuration for the on-device adapter.
#[derive(Debug, Clone)]
pub struct OnDeviceConfig {
    /// Path to the quantized GGUF model file.
    pub model_path: String,
    /// Path to the matching `tokenizer.json`.
    pub tokenizer_path: String,
    /// Provider id surfaced to the kernel (defaults to `on-device`).
    pub provider_id: ProviderId,
    /// Max tokens to generate per turn.
    pub max_new_tokens: usize,
    /// Sampling temperature; `<= 0.0` means greedy (deterministic).
    pub temperature: f64,
    /// RNG seed for sampling (kept fixed so spikes are reproducible).
    pub seed: u64,
}

impl OnDeviceConfig {
    /// Build a config from explicit model + tokenizer paths, with defaults for
    /// the rest.
    pub fn new(model_path: impl Into<String>, tokenizer_path: impl Into<String>) -> Self {
        Self {
            model_path: model_path.into(),
            tokenizer_path: tokenizer_path.into(),
            provider_id: "on-device".to_string(),
            max_new_tokens: 256,
            temperature: 0.0,
            seed: 42,
        }
    }

    /// Read configuration from the environment. Returns `None` when the model
    /// path is unset, so callers can register the adapter only when an operator
    /// has actually provisioned a model on the box.
    pub fn from_env() -> Option<Self> {
        let model_path = std::env::var("AGENTOS_GGUF_MODEL").ok()?;
        let tokenizer_path = std::env::var("AGENTOS_TOKENIZER").ok()?;
        let mut cfg = Self::new(model_path, tokenizer_path);
        if let Ok(id) = std::env::var("AGENTOS_MODEL_ID") {
            cfg.provider_id = id;
        }
        if let Some(n) = std::env::var("AGENTOS_MAX_NEW_TOKENS")
            .ok()
            .and_then(|s| s.parse().ok())
        {
            cfg.max_new_tokens = n;
        }
        if let Some(t) = std::env::var("AGENTOS_TEMPERATURE")
            .ok()
            .and_then(|s| s.parse().ok())
        {
            cfg.temperature = t;
        }
        Some(cfg)
    }
}

/// The loaded model + tokenizer. Inference is CPU-bound and `&mut`-on-forward
/// (KV cache), so the weights sit behind a `Mutex` and a turn is serialized.
struct Engine {
    model: Mutex<ModelWeights>,
    tokenizer: Tokenizer,
    device: Device,
    eos_ids: Vec<u32>,
    max_new_tokens: usize,
    temperature: f64,
    seed: u64,
}

impl Engine {
    /// Load a GGUF model and its tokenizer into memory. This is the expensive,
    /// one-time step (reads + maps all tensors), done eagerly at construction.
    fn load(cfg: &OnDeviceConfig) -> Result<Self, ConnectorError> {
        let device = Device::Cpu;

        let mut file = std::fs::File::open(&cfg.model_path).map_err(|e| {
            ConnectorError::ConnectionFailed(format!("open GGUF model '{}': {e}", cfg.model_path))
        })?;
        let content = gguf_file::Content::read(&mut file)
            .map_err(|e| ConnectorError::ProtocolError(format!("read GGUF: {e}")))?;
        let model = ModelWeights::from_gguf(content, &mut file, &device)
            .map_err(|e| ConnectorError::ProtocolError(format!("load weights: {e}")))?;

        let tokenizer = Tokenizer::from_file(&cfg.tokenizer_path).map_err(|e| {
            ConnectorError::ConnectionFailed(format!(
                "load tokenizer '{}': {e}",
                cfg.tokenizer_path
            ))
        })?;

        // Collect any end-of-turn tokens the tokenizer knows about; generation
        // stops on the first one it emits.
        let eos_ids = ["</s>", "<|im_end|>", "<|eot_id|>", "<|endoftext|>"]
            .iter()
            .filter_map(|t| tokenizer.token_to_id(t))
            .collect::<Vec<_>>();

        Ok(Self {
            model: Mutex::new(model),
            tokenizer,
            device,
            eos_ids,
            max_new_tokens: cfg.max_new_tokens,
            temperature: cfg.temperature,
            seed: cfg.seed,
        })
    }

    /// Run a full prompt → completion pass. Returns the decoded text and the
    /// number of tokens generated. Synchronous and CPU-heavy — callers run it
    /// on a blocking thread.
    fn generate(&self, prompt: &str) -> Result<(String, u32), ConnectorError> {
        let encoding = self
            .tokenizer
            .encode(prompt, true)
            .map_err(|e| ConnectorError::ProtocolError(format!("tokenize: {e}")))?;
        let prompt_tokens = encoding.get_ids().to_vec();
        if prompt_tokens.is_empty() {
            return Ok((String::new(), 0));
        }

        let temperature = if self.temperature <= 0.0 {
            None
        } else {
            Some(self.temperature)
        };
        let mut logits_processor = LogitsProcessor::new(self.seed, temperature, None);

        let mut model = self
            .model
            .lock()
            .map_err(|_| ConnectorError::ConnectionFailed("model lock poisoned".into()))?;

        // Prime the cache with the full prompt (index_pos = 0), then sample.
        let input = Tensor::new(prompt_tokens.as_slice(), &self.device)
            .and_then(|t| t.unsqueeze(0))
            .map_err(|e| ConnectorError::ProtocolError(format!("input tensor: {e}")))?;
        let logits = model
            .forward(&input, 0)
            .and_then(|l| l.squeeze(0))
            .map_err(|e| ConnectorError::ProtocolError(format!("forward(prompt): {e}")))?;
        let mut next = logits_processor
            .sample(&logits)
            .map_err(|e| ConnectorError::ProtocolError(format!("sample: {e}")))?;

        let mut generated = Vec::new();
        for step in 0..self.max_new_tokens {
            if self.eos_ids.contains(&next) {
                break;
            }
            generated.push(next);
            let input = Tensor::new(&[next], &self.device)
                .and_then(|t| t.unsqueeze(0))
                .map_err(|e| ConnectorError::ProtocolError(format!("step tensor: {e}")))?;
            let logits = model
                .forward(&input, prompt_tokens.len() + step)
                .and_then(|l| l.squeeze(0))
                .map_err(|e| ConnectorError::ProtocolError(format!("forward(decode): {e}")))?;
            next = logits_processor
                .sample(&logits)
                .map_err(|e| ConnectorError::ProtocolError(format!("sample: {e}")))?;
        }

        let text = self
            .tokenizer
            .decode(&generated, true)
            .map_err(|e| ConnectorError::ProtocolError(format!("detokenize: {e}")))?;
        Ok((text, generated.len() as u32))
    }
}

/// Render a chat history into a single prompt string.
///
/// Model-agnostic and deliberately simple — enough to drive a quantized
/// instruct model in a spike. Production use should switch on the model family
/// and apply its real chat template (ChatML, Llama-3, etc.).
pub fn build_prompt(messages: &[StandardMessage]) -> String {
    let mut out = String::new();
    for m in messages {
        match m.role.as_str() {
            "system" => out.push_str(&format!("{}\n\n", m.content)),
            "user" => out.push_str(&format!("User: {}\n", m.content)),
            "assistant" => out.push_str(&format!("Assistant: {}\n", m.content)),
            "tool" => out.push_str(&format!("Tool result: {}\n", m.content)),
            other => out.push_str(&format!("{}: {}\n", other, m.content)),
        }
    }
    out.push_str("Assistant:");
    out
}

/// On-device, in-process LLM provider backed by a quantized GGUF model.
pub struct OnDeviceLlmAdapter {
    id: ProviderId,
    engine: std::sync::Arc<Engine>,
}

impl OnDeviceLlmAdapter {
    /// Load the model described by `cfg`. The (expensive) load happens here, so
    /// a successful return means the box can actually serve inference.
    pub fn load(cfg: OnDeviceConfig) -> Result<Self, ConnectorError> {
        let engine = Engine::load(&cfg)?;
        Ok(Self {
            id: cfg.provider_id,
            engine: std::sync::Arc::new(engine),
        })
    }
}

struct OnDeviceSession {
    provider_id: ProviderId,
    engine: std::sync::Arc<Engine>,
}

#[async_trait::async_trait]
impl LlmSession for OnDeviceSession {
    async fn send(&self, messages: Vec<StandardMessage>) -> Result<LlmResponse, ConnectorError> {
        self.send_with_tools(messages, &[]).await
    }

    async fn send_with_tools(
        &self,
        messages: Vec<StandardMessage>,
        _tools: &[ToolDefinition],
    ) -> Result<LlmResponse, ConnectorError> {
        let prompt = build_prompt(&messages);
        let engine = self.engine.clone();
        // Inference is a long, blocking, CPU-bound computation — keep it off the
        // async runtime's worker threads.
        let (content, tokens) = tokio::task::spawn_blocking(move || engine.generate(&prompt))
            .await
            .map_err(|e| ConnectorError::ConnectionFailed(format!("inference task: {e}")))??;

        Ok(LlmResponse {
            content,
            finish_reason: Some("stop".to_string()),
            tokens_used: tokens,
            tool_calls: vec![],
        })
    }

    fn provider_id(&self) -> &ProviderId {
        &self.provider_id
    }
}

#[async_trait::async_trait]
impl LlmProviderAdapter for OnDeviceLlmAdapter {
    fn id(&self) -> &ProviderId {
        &self.id
    }
    fn name(&self) -> &str {
        "On-device (candle GGUF)"
    }
    fn provider_type(&self) -> ProviderType {
        // It runs locally, so it is a Local provider from the kernel's view.
        ProviderType::Local
    }

    async fn is_available(&self) -> bool {
        // If we hold an Engine, the weights are loaded and resident.
        true
    }

    async fn create_session(&self) -> Result<Box<dyn LlmSession>, ConnectorError> {
        Ok(Box::new(OnDeviceSession {
            provider_id: self.id.clone(),
            engine: self.engine.clone(),
        }))
    }

    fn translate_to_provider(&self, msg: &StandardMessage) -> serde_json::Value {
        serde_json::json!({"role": msg.role, "content": msg.content})
    }

    fn translate_from_provider(&self, value: &serde_json::Value) -> Option<StandardMessage> {
        Some(StandardMessage {
            role: value.get("role")?.as_str()?.to_string(),
            content: value.get("content")?.as_str().unwrap_or("").to_string(),
            tool_call_id: None,
            tool_calls: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_prompt_renders_roles_and_ends_on_assistant() {
        let msgs = vec![
            StandardMessage::system("You are helpful."),
            StandardMessage::user("hi"),
            StandardMessage::assistant("hello"),
            StandardMessage::user("write a file"),
        ];
        let p = build_prompt(&msgs);
        assert!(p.starts_with("You are helpful.\n\n"));
        assert!(p.contains("User: hi\n"));
        assert!(p.contains("Assistant: hello\n"));
        assert!(p.contains("User: write a file\n"));
        assert!(p.ends_with("Assistant:"));
    }

    #[test]
    fn build_prompt_empty_history_still_prompts_assistant() {
        assert_eq!(build_prompt(&[]), "Assistant:");
    }

    #[test]
    fn config_new_has_sane_defaults() {
        let c = OnDeviceConfig::new("/m.gguf", "/t.json");
        assert_eq!(c.provider_id, "on-device");
        assert_eq!(c.max_new_tokens, 256);
        assert_eq!(c.temperature, 0.0);
        assert_eq!(c.model_path, "/m.gguf");
    }

    #[test]
    fn load_missing_model_is_clean_error_not_panic() {
        let cfg = OnDeviceConfig::new("/nonexistent/model.gguf", "/nonexistent/tok.json");
        // An operator error (missing file) surfaces as a typed ConnectorError,
        // not a panic — consistent with graceful-degradation discipline.
        match OnDeviceLlmAdapter::load(cfg) {
            Err(ConnectorError::ConnectionFailed(_)) => {}
            Err(other) => panic!("expected ConnectionFailed, got {other:?}"),
            Ok(_) => panic!("loading a nonexistent model should fail"),
        }
    }

    /// Real end-to-end generation. Skipped unless a model is provisioned on the
    /// box via env vars — so CI (which has no weights) never runs it, but it is
    /// a one-command smoke test on a Pi:
    ///   AGENTOS_GGUF_MODEL=… AGENTOS_TOKENIZER=… cargo test -p adapters \
    ///     --features candle on_device_generates -- --ignored --nocapture
    #[tokio::test]
    #[ignore = "requires a local GGUF model; set AGENTOS_GGUF_MODEL + AGENTOS_TOKENIZER"]
    async fn on_device_generates_tokens() {
        let cfg = OnDeviceConfig::from_env()
            .expect("set AGENTOS_GGUF_MODEL and AGENTOS_TOKENIZER to run this test");
        let adapter = OnDeviceLlmAdapter::load(cfg).expect("model should load");
        assert!(adapter.is_available().await);
        let session = adapter.create_session().await.expect("session");
        let resp = session
            .send(vec![StandardMessage::user("Say hello in one word.")])
            .await
            .expect("generation should succeed");
        println!("on-device output: {:?}", resp.content);
        assert!(resp.tokens_used > 0, "model should emit at least one token");
    }
}
