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
//! It plugs into the unchanged [`kernel::connector::LlmProviderAdapter`] seam, so the kernel,
//! syscall gate, scheduler and persistence treat it exactly like any cloud
//! provider — the only difference is where the tokens are produced.
//!
//! ## Supported boundary
//! - Greedy / temperature sampling of a single GGUF model on CPU.
//! - Explicit Simple, ChatML, and Llama 3 prompt templates selected by the
//!   operator for the provisioned tokenizer/model family.
//! - No native tool-calling: small on-device models emit tool calls as plain
//!   text, which the executor's plaintext shim recovers — so we return an empty
//!   `tool_calls` vec, same as the Ollama adapter.
//! - KV-cache is re-primed from the full prompt on every `send` (the executor
//!   passes the whole history each turn), so turns don't share cache state.
//! - Model bytes, total context tokens, output tokens, timeout, and cooperative
//!   cancellation are bounded. GPU and non-Llama-family loaders are unsupported.
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
use std::time::Duration;

use candle_core::quantized::gguf_file;
use candle_core::{Device, Tensor};
use candle_transformers::generation::LogitsProcessor;
use candle_transformers::models::quantized_llama::ModelWeights;
use tokenizers::{
    DecoderWrapper, ModelWrapper, NormalizerWrapper, PostProcessorWrapper, PreTokenizerWrapper,
    Tokenizer,
};

use kernel::connector::*;
use kernel::{ConnectorError, ProviderId};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ChatTemplate {
    #[default]
    Simple,
    ChatMl,
    Llama3,
}

/// Configuration for the on-device adapter.
#[derive(Debug, Clone)]
pub struct OnDeviceConfig {
    /// Path to the quantized GGUF model file.
    pub model_path: String,
    /// Path to the matching `tokenizer.json`.
    pub tokenizer_path: String,
    /// Provider id surfaced to the kernel (defaults to `on-device`).
    pub provider_id: ProviderId,
    /// Stable model identifier surfaced in usage and checkpoint attribution.
    pub model_id: String,
    /// Max tokens to generate per turn.
    pub max_new_tokens: usize,
    /// Sampling temperature; `<= 0.0` means greedy (deterministic).
    pub temperature: f64,
    /// RNG seed for sampling (kept fixed so spikes are reproducible).
    pub seed: u64,
    /// Reject unexpectedly large model files before parsing or allocation.
    pub max_model_bytes: u64,
    /// Hard prompt + completion context ceiling.
    pub max_context_tokens: usize,
    /// Chat serialization required by the provisioned model family.
    pub chat_template: ChatTemplate,
}

impl OnDeviceConfig {
    /// Build a config from explicit model + tokenizer paths, with defaults for
    /// the rest.
    pub fn new(model_path: impl Into<String>, tokenizer_path: impl Into<String>) -> Self {
        Self {
            model_path: model_path.into(),
            tokenizer_path: tokenizer_path.into(),
            provider_id: "on-device".to_string(),
            model_id: "on-device-gguf".to_string(),
            max_new_tokens: 256,
            temperature: 0.0,
            seed: 42,
            max_model_bytes: 16 * 1024 * 1024 * 1024,
            max_context_tokens: 4096,
            chat_template: ChatTemplate::Simple,
        }
    }

    /// Read configuration from the environment. Returns `None` when the model
    /// path is unset, so callers can register the adapter only when an operator
    /// has actually provisioned a model on the box.
    pub fn from_env() -> Option<Self> {
        let model_path = std::env::var("AGENTOS_GGUF_MODEL").ok()?;
        let tokenizer_path = std::env::var("AGENTOS_TOKENIZER").ok()?;
        let mut cfg = Self::new(model_path, tokenizer_path);
        if let Ok(id) = std::env::var("AGENTOS_PROVIDER_ID") {
            cfg.provider_id = id;
        }
        if let Ok(id) = std::env::var("AGENTOS_MODEL_ID") {
            cfg.model_id = id;
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
        if let Some(n) = std::env::var("AGENTOS_MAX_CONTEXT_TOKENS")
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
        {
            cfg.max_context_tokens = n.clamp(1, 1_048_576);
        }
        if let Some(n) = std::env::var("AGENTOS_MAX_MODEL_BYTES")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
        {
            cfg.max_model_bytes = n.max(1);
        }
        if let Ok(template) = std::env::var("AGENTOS_CHAT_TEMPLATE") {
            cfg.chat_template = match template.to_ascii_lowercase().as_str() {
                "chatml" => ChatTemplate::ChatMl,
                "llama3" | "llama-3" => ChatTemplate::Llama3,
                _ => ChatTemplate::Simple,
            };
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
    model_id: String,
    max_context_tokens: usize,
    chat_template: ChatTemplate,
}

type InferenceResult = Result<(String, u32), ConnectorError>;
const MAX_DECODED_BYTES: usize = 64 * 1024;
const PROGRESS_BUFFER: usize = 4;

trait InferenceBackend: Send + Sync {
    fn model_id(&self) -> &str;
    fn chat_template(&self) -> ChatTemplate;
    fn generate(
        &self,
        prompt: &str,
        max_output_tokens: Option<usize>,
        provider: &ProviderId,
        cancellation: &tokio_util::sync::CancellationToken,
        progress: Option<&BlockingProgress>,
    ) -> InferenceResult;
}

struct BlockingProgress {
    sender: tokio::sync::mpsc::Sender<String>,
    cancellation: tokio_util::sync::CancellationToken,
    provider: ProviderId,
}

impl BlockingProgress {
    fn emit(&self, delta: String) -> Result<(), ConnectorError> {
        if self.cancellation.is_cancelled() {
            return Err(ConnectorError::cancelled(self.provider.clone(), None));
        }
        self.sender
            .blocking_send(delta)
            .map_err(|_| ConnectorError::cancelled(self.provider.clone(), None))
    }
}

type Decoder<'a> = tokenizers::tokenizer::DecodeStream<
    'a,
    ModelWrapper,
    NormalizerWrapper,
    PreTokenizerWrapper,
    PostProcessorWrapper,
    DecoderWrapper,
>;

struct TokenProgress<'a> {
    tokenizer: &'a Tokenizer,
    decoder: Decoder<'a>,
    generated: Vec<u32>,
    emitted: String,
    sink: Option<&'a BlockingProgress>,
}

impl<'a> TokenProgress<'a> {
    fn new(tokenizer: &'a Tokenizer, sink: Option<&'a BlockingProgress>) -> Self {
        Self {
            tokenizer,
            decoder: tokenizer.decode_stream(true),
            generated: Vec::new(),
            emitted: String::new(),
            sink,
        }
    }
    fn step(&mut self, token: u32) -> Result<(), ConnectorError> {
        self.generated.push(token);
        if let Some(sink) = self.sink {
            if let Some(delta) = self.decoder.step(token).map_err(|_| {
                ConnectorError::ProtocolError(
                    "on-device streaming detokenizer rejected its prefix".into(),
                )
            })? {
                if self.emitted.len().saturating_add(delta.len()) > MAX_DECODED_BYTES {
                    return Err(ConnectorError::ProtocolError(
                        "on-device output exceeded the byte ceiling".into(),
                    ));
                }
                self.emitted.push_str(&delta);
                if !delta.is_empty() {
                    sink.emit(delta)?;
                }
            }
        }
        Ok(())
    }
    fn finish(self) -> InferenceResult {
        let text = self.tokenizer.decode(&self.generated, true).map_err(|_| {
            ConnectorError::ProtocolError("on-device batch detokenization failed".into())
        })?;
        if text.len() > MAX_DECODED_BYTES {
            return Err(ConnectorError::ProtocolError(
                "on-device output exceeded the byte ceiling".into(),
            ));
        }
        if let Some(sink) = self.sink {
            let tail = text.strip_prefix(&self.emitted).ok_or_else(|| {
                ConnectorError::ProtocolError(
                    "on-device stream differs from batch detokenization".into(),
                )
            })?;
            if !tail.is_empty() {
                sink.emit(tail.to_string())?;
            }
        }
        Ok((
            text,
            u32::try_from(self.generated.len()).unwrap_or(u32::MAX),
        ))
    }
}

impl Engine {
    /// Load a GGUF model and its tokenizer into memory. This is the expensive,
    /// one-time step (reads + maps all tensors), done eagerly at construction.
    fn load(cfg: &OnDeviceConfig) -> Result<Self, ConnectorError> {
        let device = Device::Cpu;

        let metadata = std::fs::metadata(&cfg.model_path).map_err(|e| {
            ConnectorError::ConnectionFailed(format!("open GGUF model '{}': {e}", cfg.model_path))
        })?;
        if metadata.len() > cfg.max_model_bytes {
            return Err(ConnectorError::invalid_request(
                cfg.provider_id.clone(),
                format!(
                    "GGUF model is {} bytes, above configured {} byte limit",
                    metadata.len(),
                    cfg.max_model_bytes
                ),
                None,
            ));
        }
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
            model_id: cfg.model_id.clone(),
            max_context_tokens: cfg.max_context_tokens,
            chat_template: cfg.chat_template,
        })
    }

    /// Run a full prompt → completion pass. Returns the decoded text and the
    /// number of tokens generated. Synchronous and CPU-heavy — callers run it
    /// on a blocking thread.
    fn generate(
        &self,
        prompt: &str,
        max_output_tokens: Option<usize>,
        provider_id: &ProviderId,
        cancellation: &tokio_util::sync::CancellationToken,
        progress: Option<&BlockingProgress>,
    ) -> Result<(String, u32), ConnectorError> {
        if cancellation.is_cancelled() {
            return Err(ConnectorError::cancelled(provider_id.clone(), None));
        }

        let encoding = self
            .tokenizer
            .encode(prompt, true)
            .map_err(|e| ConnectorError::ProtocolError(format!("tokenize: {e}")))?;
        let prompt_tokens = encoding.get_ids().to_vec();
        if prompt_tokens.is_empty() {
            return Ok((String::new(), 0));
        }
        if prompt_tokens.len() > self.max_context_tokens {
            return Err(ConnectorError::invalid_request(
                provider_id.clone(),
                format!(
                    "prompt has {} tokens, above configured {} token on-device context limit",
                    prompt_tokens.len(),
                    self.max_context_tokens
                ),
                None,
            ));
        }

        let temperature = if self.temperature <= 0.0 {
            None
        } else {
            Some(self.temperature)
        };
        let mut logits_processor = LogitsProcessor::new(self.seed, temperature, None);

        let mut model = loop {
            if cancellation.is_cancelled() {
                return Err(ConnectorError::cancelled(provider_id.clone(), None));
            }
            match self.model.try_lock() {
                Ok(model) => break model,
                Err(std::sync::TryLockError::WouldBlock) => {
                    std::thread::sleep(Duration::from_millis(1))
                }
                Err(std::sync::TryLockError::Poisoned(_)) => {
                    return Err(ConnectorError::ConnectionFailed(
                        "model lock poisoned".into(),
                    ))
                }
            }
        };
        model.clear_kv_cache();

        const PROMPT_CHUNK_TOKENS: usize = 64;
        let mut logits = None;
        let mut index_pos = 0usize;
        for chunk in prompt_tokens.chunks(PROMPT_CHUNK_TOKENS) {
            if cancellation.is_cancelled() {
                return Err(ConnectorError::cancelled(provider_id.clone(), None));
            }
            let input = Tensor::new(chunk, &self.device)
                .and_then(|tensor| tensor.unsqueeze(0))
                .map_err(|error| ConnectorError::ProtocolError(format!("input tensor: {error}")))?;
            let chunk_logits = model
                .forward(&input, index_pos)
                .and_then(|tensor| tensor.squeeze(0))
                .map_err(|error| {
                    ConnectorError::ProtocolError(format!("forward(prompt): {error}"))
                })?;
            logits = Some(chunk_logits);
            index_pos = index_pos.saturating_add(chunk.len());
        }
        let logits = logits.expect("non-empty prompts produce at least one chunk");
        let mut next = logits_processor
            .sample(&logits)
            .map_err(|e| ConnectorError::ProtocolError(format!("sample: {e}")))?;

        let mut generated = TokenProgress::new(&self.tokenizer, progress);
        let max_new_tokens = max_output_tokens
            .unwrap_or(self.max_new_tokens)
            .min(self.max_new_tokens)
            .min(self.max_context_tokens.saturating_sub(prompt_tokens.len()));
        for step in 0..max_new_tokens {
            if cancellation.is_cancelled() {
                return Err(ConnectorError::cancelled(provider_id.clone(), None));
            }
            if self.eos_ids.contains(&next) {
                break;
            }
            generated.step(next)?;
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

        generated.finish()
    }
}

impl InferenceBackend for Engine {
    fn model_id(&self) -> &str {
        &self.model_id
    }
    fn chat_template(&self) -> ChatTemplate {
        self.chat_template
    }
    fn generate(
        &self,
        prompt: &str,
        max: Option<usize>,
        provider: &ProviderId,
        cancellation: &tokio_util::sync::CancellationToken,
        progress: Option<&BlockingProgress>,
    ) -> InferenceResult {
        Engine::generate(self, prompt, max, provider, cancellation, progress)
    }
}

/// Render a chat history into a single prompt string.
///
/// The no-argument compatibility helper uses the Simple template. Production
/// configuration should select the model's actual template through
/// [`OnDeviceConfig::chat_template`].
pub fn build_prompt(messages: &[StandardMessage]) -> String {
    build_prompt_with_template(messages, ChatTemplate::Simple)
}

pub fn build_prompt_with_template(messages: &[StandardMessage], template: ChatTemplate) -> String {
    match template {
        ChatTemplate::ChatMl => {
            let mut out = String::new();
            for message in messages {
                out.push_str("<|im_start|>");
                out.push_str(&message.role);
                out.push('\n');
                out.push_str(&message.content.text_projection());
                out.push_str("<|im_end|>\n");
            }
            out.push_str("<|im_start|>assistant\n");
            return out;
        }
        ChatTemplate::Llama3 => {
            let mut out = "<|begin_of_text|>".to_string();
            for message in messages {
                out.push_str("<|start_header_id|>");
                out.push_str(&message.role);
                out.push_str("<|end_header_id|>\n\n");
                out.push_str(&message.content.text_projection());
                out.push_str("<|eot_id|>");
            }
            out.push_str("<|start_header_id|>assistant<|end_header_id|>\n\n");
            return out;
        }
        ChatTemplate::Simple => {}
    }
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
    engine: std::sync::Arc<dyn InferenceBackend>,
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
    engine: std::sync::Arc<dyn InferenceBackend>,
}

#[cfg(test)]
struct ControlledDecode {
    tokenizer: Tokenizer,
    tokens: Vec<u32>,
    hold_until_cancel: bool,
    cleaned: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

#[cfg(test)]
impl InferenceBackend for ControlledDecode {
    fn model_id(&self) -> &str {
        "controlled-token-fixture"
    }
    fn chat_template(&self) -> ChatTemplate {
        ChatTemplate::Simple
    }
    fn generate(
        &self,
        _prompt: &str,
        max: Option<usize>,
        provider: &ProviderId,
        cancellation: &tokio_util::sync::CancellationToken,
        sink: Option<&BlockingProgress>,
    ) -> InferenceResult {
        let result = (|| {
            let mut progress = TokenProgress::new(&self.tokenizer, sink);
            for &token in self.tokens.iter().take(max.unwrap_or(self.tokens.len())) {
                if cancellation.is_cancelled() {
                    return Err(ConnectorError::cancelled(provider.clone(), None));
                }
                progress.step(token)?;
            }
            if self.hold_until_cancel {
                while !cancellation.is_cancelled() {
                    std::thread::sleep(Duration::from_millis(1));
                }
                return Err(ConnectorError::cancelled(provider.clone(), None));
            }
            progress.finish()
        })();
        self.cleaned
            .store(true, std::sync::atomic::Ordering::Release);
        result
    }
}

#[cfg(test)]
fn controlled_tokenizer() -> Tokenizer {
    Tokenizer::from_bytes(br#"{"version":"1.0","truncation":null,"padding":null,"added_tokens":[],"normalizer":null,"pre_tokenizer":null,"post_processor":null,"decoder":null,"model":{"type":"WordLevel","vocab":{"one":0,"two":1,"three":2},"unk_token":"one"}}"#).expect("controlled tokenizer fixture")
}

#[cfg(test)]
pub(crate) fn controlled_streaming_fixture() -> OnDeviceLlmAdapter {
    OnDeviceLlmAdapter {
        id: "on-device-fixture".into(),
        engine: std::sync::Arc::new(ControlledDecode {
            tokenizer: controlled_tokenizer(),
            tokens: vec![0, 1, 2],
            hold_until_cancel: false,
            cleaned: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }),
    }
}

const INFERENCE_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

async fn drain_inference_worker(
    worker: &mut tokio::task::JoinHandle<InferenceResult>,
    provider_id: &ProviderId,
    timeout: Duration,
) -> Result<(), ConnectorError> {
    match tokio::time::timeout(timeout, &mut *worker).await {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(error)) => Err(ConnectorError::ConnectionFailed(format!(
            "on-device inference cleanup task failed: {error}"
        ))),
        Err(_) => Err(ConnectorError::timeout(
            provider_id.clone(),
            format!(
                "on-device inference worker did not drain within {} ms",
                timeout.as_millis()
            ),
            None,
        )),
    }
}

struct WorkerCancellation(tokio_util::sync::CancellationToken);
impl Drop for WorkerCancellation {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

impl OnDeviceSession {
    async fn run(
        &self,
        messages: Vec<StandardMessage>,
        options: LlmRequestOptions,
        cancellation: &tokio_util::sync::CancellationToken,
        events: Option<ProviderEventSink>,
        streaming: bool,
    ) -> Result<LlmResponse, ConnectorError> {
        if cancellation.is_cancelled() {
            return Err(ConnectorError::cancelled(self.provider_id.clone(), None));
        }
        let prompt = build_prompt_with_template(&messages, self.engine.chat_template());
        let engine = self.engine.clone();
        let provider = self.provider_id.clone();
        let worker_provider = provider.clone();
        let max = options.max_output_tokens.map(|limit| limit as usize);
        let worker_cancel = tokio_util::sync::CancellationToken::new();
        let _cancel_on_drop = WorkerCancellation(worker_cancel.clone());
        let worker_token = worker_cancel.clone();
        let (sender, mut receiver) = tokio::sync::mpsc::channel(PROGRESS_BUFFER);
        let mut worker = tokio::task::spawn_blocking(move || {
            let progress = BlockingProgress {
                sender,
                cancellation: worker_token.clone(),
                provider: worker_provider.clone(),
            };
            engine.generate(
                &prompt,
                max,
                &worker_provider,
                &worker_token,
                streaming.then_some(&progress),
            )
        });
        let (interrupted, result) = {
            let collect = async {
                let mut open = true;
                loop {
                    tokio::select! {
                        biased;
                        delta = receiver.recv(), if open => match delta {
                            Some(delta) => if let Some(sink) = &events { sink.emit(ProviderStreamEvent::TextDelta(delta)).await; },
                            None => open = false,
                        },
                        result = &mut worker => break result.map_err(|error| ConnectorError::ConnectionFailed(format!("inference task: {error}")))?,
                    }
                }
            };
            tokio::pin!(collect);
            match options.timeout {
                Some(timeout) => tokio::select! {
                    biased;
                    _ = cancellation.cancelled() => (true, None),
                    _ = tokio::time::sleep(timeout) => (true, Some(Err(ConnectorError::timeout(provider.clone(), "on-device inference exceeded its deadline", None)))),
                    result = &mut collect => (false, Some(result)),
                },
                None => tokio::select! {
                    biased;
                    _ = cancellation.cancelled() => (true, None),
                    result = &mut collect => (false, Some(result)),
                },
            }
        };
        if interrupted {
            worker_cancel.cancel();
            receiver.close();
            drop(receiver);
            drain_inference_worker(&mut worker, &provider, INFERENCE_DRAIN_TIMEOUT).await?;
            return match result {
                Some(result) => result.map(|_| unreachable!()),
                None => Err(ConnectorError::cancelled(provider, None)),
            };
        }
        let (content, tokens) = result.expect("completed worker result")?;
        Ok(LlmResponse {
            content,
            finish_reason: Some("stop".to_string()),
            tokens_used: tokens,
            usage: Default::default(),
            tool_calls: vec![],
            provider_metadata: None,
        })
    }
}

#[async_trait::async_trait]
impl LlmSession for OnDeviceSession {
    async fn send(&self, messages: Vec<StandardMessage>) -> Result<LlmResponse, ConnectorError> {
        self.send_with_tools(messages, &[]).await
    }

    async fn send_with_tools(
        &self,
        messages: Vec<StandardMessage>,
        tools: &[ToolDefinition],
    ) -> Result<LlmResponse, ConnectorError> {
        self.send_with_options(messages, tools, LlmRequestOptions::default())
            .await
    }

    async fn send_with_options(
        &self,
        messages: Vec<StandardMessage>,
        _tools: &[ToolDefinition],
        options: LlmRequestOptions,
    ) -> Result<LlmResponse, ConnectorError> {
        self.validate_content(&messages)?;
        let cancellation = tokio_util::sync::CancellationToken::new();
        self.send_controlled(messages, _tools, options, &cancellation)
            .await
    }

    async fn send_controlled(
        &self,
        messages: Vec<StandardMessage>,
        _tools: &[ToolDefinition],
        options: LlmRequestOptions,
        cancellation: &tokio_util::sync::CancellationToken,
    ) -> Result<LlmResponse, ConnectorError> {
        self.run(messages, options, cancellation, None, false).await
    }
    async fn send_streaming(
        &self,
        messages: Vec<StandardMessage>,
        tools: &[ToolDefinition],
    ) -> Result<LlmResponse, ConnectorError> {
        self.send_streaming_with_options(messages, tools, LlmRequestOptions::default())
            .await
    }
    async fn send_streaming_with_options(
        &self,
        messages: Vec<StandardMessage>,
        _tools: &[ToolDefinition],
        options: LlmRequestOptions,
    ) -> Result<LlmResponse, ConnectorError> {
        self.run(
            messages,
            options,
            &tokio_util::sync::CancellationToken::new(),
            None,
            true,
        )
        .await
    }
    async fn send_streaming_controlled(
        &self,
        messages: Vec<StandardMessage>,
        _tools: &[ToolDefinition],
        options: LlmRequestOptions,
        cancellation: &tokio_util::sync::CancellationToken,
    ) -> Result<LlmResponse, ConnectorError> {
        self.validate_content(&messages)?;
        self.run(messages, options, cancellation, None, true).await
    }
    async fn send_streaming_events_controlled(
        &self,
        messages: Vec<StandardMessage>,
        _tools: &[ToolDefinition],
        options: LlmRequestOptions,
        cancellation: &tokio_util::sync::CancellationToken,
        events: ProviderEventSink,
    ) -> Result<LlmResponse, ConnectorError> {
        self.validate_content(&messages)?;
        self.run(messages, options, cancellation, Some(events), true)
            .await
    }

    fn enforces_max_output_tokens(&self) -> bool {
        true
    }

    fn provider_id(&self) -> &ProviderId {
        &self.provider_id
    }

    fn model_id(&self) -> &str {
        self.engine.model_id()
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
    fn capabilities(&self) -> ProviderCapabilities {
        ProviderCapabilities {
            native_streaming: true,
            prompt_cancellation: true,
            api_family: "candle-gguf".into(),
            ..Default::default()
        }
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
            provider_metadata: None,
            role: value.get("role")?.as_str()?.to_string(),
            content: value.get("content")?.as_str().unwrap_or("").into(),
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
        assert_eq!(c.max_context_tokens, 4096);
        assert_eq!(c.max_model_bytes, 16 * 1024 * 1024 * 1024);
    }

    #[test]
    fn supported_chat_templates_render_explicit_assistant_boundary() {
        let messages = [StandardMessage::user("hello")];
        let chatml = build_prompt_with_template(&messages, ChatTemplate::ChatMl);
        assert!(chatml.ends_with("<|im_start|>assistant\n"));
        let llama3 = build_prompt_with_template(&messages, ChatTemplate::Llama3);
        assert!(llama3.ends_with("<|start_header_id|>assistant<|end_header_id|>\n\n"));
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

    #[test]
    fn corrupt_or_oversized_gguf_fails_cleanly_before_inference() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("agentos-invalid-{unique}.gguf"));
        std::fs::write(&path, b"not a gguf").unwrap();

        let mut oversized =
            OnDeviceConfig::new(path.to_string_lossy(), "/nonexistent/tokenizer.json");
        oversized.max_model_bytes = 1;
        assert!(matches!(
            OnDeviceLlmAdapter::load(oversized),
            Err(ConnectorError::InvalidRequest(_))
        ));

        let corrupt = OnDeviceConfig::new(path.to_string_lossy(), "/nonexistent/tokenizer.json");
        assert!(matches!(
            OnDeviceLlmAdapter::load(corrupt),
            Err(ConnectorError::ProtocolError(_))
        ));
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn cancellation_drain_waits_for_blocking_worker_cleanup() {
        let provider_id = "on-device".to_string();
        let cancellation = tokio_util::sync::CancellationToken::new();
        let worker_token = cancellation.clone();
        let cleaned = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let worker_cleaned = cleaned.clone();
        let mut worker = tokio::task::spawn_blocking(move || {
            while !worker_token.is_cancelled() {
                std::thread::sleep(Duration::from_millis(1));
            }
            worker_cleaned.store(true, std::sync::atomic::Ordering::SeqCst);
            Err(ConnectorError::cancelled("on-device".into(), None))
        });

        cancellation.cancel();
        drain_inference_worker(&mut worker, &provider_id, Duration::from_secs(1))
            .await
            .expect("cooperative worker should drain");
        assert!(
            cleaned.load(std::sync::atomic::Ordering::SeqCst),
            "cancellation must not return before the blocking worker cleans up"
        );
    }

    #[tokio::test]
    async fn cancellation_drain_timeout_fails_closed() {
        let provider_id = "on-device".to_string();
        let mut worker = tokio::task::spawn_blocking(move || {
            std::thread::sleep(Duration::from_millis(50));
            Ok(("completed after cleanup deadline".to_string(), 1))
        });

        assert!(matches!(
            drain_inference_worker(&mut worker, &provider_id, Duration::from_millis(1)).await,
            Err(ConnectorError::Timeout(_))
        ));
        worker
            .await
            .expect("test worker should remain joinable after the timeout")
            .expect("test worker should complete cleanly");
    }

    #[tokio::test]
    async fn controlled_decode_cancellation_closes_backpressure_and_drains_worker() {
        let cleaned = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let adapter = OnDeviceLlmAdapter {
            id: "controlled-cancel".into(),
            engine: std::sync::Arc::new(ControlledDecode {
                tokenizer: controlled_tokenizer(),
                tokens: (0..10_000).map(|value| value % 3).collect(),
                hold_until_cancel: false,
                cleaned: cleaned.clone(),
            }),
        };
        let session = adapter.create_session().await.unwrap();
        let cancellation = tokio_util::sync::CancellationToken::new();
        let cancel = cancellation.clone();
        let (sender, mut receiver) = tokio::sync::mpsc::channel(1);
        let task = tokio::spawn(async move {
            session
                .send_streaming_events_controlled(
                    vec![StandardMessage::user("fixture")],
                    &[],
                    LlmRequestOptions {
                        max_output_tokens: Some(10_000),
                        timeout: Some(Duration::from_secs(5)),
                    },
                    &cancellation,
                    ProviderEventSink::new(sender),
                )
                .await
        });
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), receiver.recv())
                .await
                .unwrap(),
            Some(ProviderStreamEvent::TextDelta("one".into()))
        );
        assert!(!task.is_finished());
        cancel.cancel();
        assert!(matches!(
            tokio::time::timeout(Duration::from_secs(2), task)
                .await
                .unwrap()
                .unwrap()
                .unwrap_err(),
            ConnectorError::Cancelled(_)
        ));
        assert!(cleaned.load(std::sync::atomic::Ordering::Acquire));
        // Any remaining event was accepted before cancellation. Once drained,
        // the closed channel proves no producer survives the returned error.
        while receiver.recv().await.is_some() {}
        assert_eq!(receiver.recv().await, None);
    }

    #[tokio::test]
    async fn controlled_decode_deadline_also_drains_a_blocked_progress_worker() {
        let cleaned = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let adapter = OnDeviceLlmAdapter {
            id: "controlled-timeout".into(),
            engine: std::sync::Arc::new(ControlledDecode {
                tokenizer: controlled_tokenizer(),
                tokens: vec![0, 1, 2],
                hold_until_cancel: true,
                cleaned: cleaned.clone(),
            }),
        };
        let session = adapter.create_session().await.unwrap();
        let (sender, _receiver) = tokio::sync::mpsc::channel(1);
        let result = session
            .send_streaming_events_controlled(
                vec![StandardMessage::user("fixture")],
                &[],
                LlmRequestOptions {
                    timeout: Some(Duration::from_millis(100)),
                    ..Default::default()
                },
                &tokio_util::sync::CancellationToken::new(),
                ProviderEventSink::new(sender),
            )
            .await;
        assert!(matches!(result, Err(ConnectorError::Timeout(_))));
        assert!(cleaned.load(std::sync::atomic::Ordering::Acquire));
    }

    #[test]
    fn byte_fallback_progress_waits_for_utf8_and_flushes_exact_batch_tail() {
        let vocab = [
            ("<0x20>".to_string(), 0),
            ("<0xC3>".to_string(), 1),
            ("<0xA9>".to_string(), 2),
        ];
        let model = tokenizers::models::bpe::BPE::builder()
            .vocab_and_merges(vocab, vec![])
            .byte_fallback(true)
            .build()
            .unwrap();
        let mut tokenizer = Tokenizer::new(model);
        tokenizer.with_decoder(Some(
            tokenizers::decoders::byte_fallback::ByteFallback::default(),
        ));
        let (sender, mut receiver) = tokio::sync::mpsc::channel(8);
        let sink = BlockingProgress {
            sender,
            cancellation: tokio_util::sync::CancellationToken::new(),
            provider: "controlled-bytes".into(),
        };
        let mut progress = TokenProgress::new(&tokenizer, Some(&sink));
        progress.step(0).unwrap();
        assert_eq!(receiver.try_recv().unwrap(), " ");
        progress.step(1).unwrap();
        assert!(receiver.try_recv().is_err());
        progress.step(2).unwrap();
        assert_eq!(receiver.try_recv().unwrap(), "é");
        let (text, count) = progress.finish().unwrap();
        assert_eq!(text, tokenizer.decode(&[0, 1, 2], true).unwrap());
        assert_eq!(count, 3);
        let mut incomplete = TokenProgress::new(&tokenizer, Some(&sink));
        incomplete.step(1).unwrap();
        let (text, count) = incomplete.finish().unwrap();
        assert_eq!(receiver.try_recv().unwrap(), text);
        assert_eq!(text, tokenizer.decode(&[1], true).unwrap());
        assert_eq!(count, 1);
    }

    #[test]
    fn progress_never_returns_a_terminal_response_with_changed_published_prefix() {
        let tokenizer = controlled_tokenizer();
        let (sender, _receiver) = tokio::sync::mpsc::channel(4);
        let sink = BlockingProgress {
            sender,
            cancellation: tokio_util::sync::CancellationToken::new(),
            provider: "controlled-prefix".into(),
        };
        let mut progress = TokenProgress::new(&tokenizer, Some(&sink));
        progress.step(0).unwrap();
        progress.emitted.push_str("changed");
        assert!(matches!(
            progress.finish(),
            Err(ConnectorError::ProtocolError(_))
        ));
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
        println!(
            "on-device generation completed: tokens={}, output_bytes={}",
            resp.tokens_used,
            resp.content.len()
        );
        assert!(resp.tokens_used > 0, "model should emit at least one token");
        let messages = vec![StandardMessage::user(
            "Write the numbers one through twelve separated by spaces.",
        )];
        let batch = session
            .send(messages.clone())
            .await
            .expect("batch parity reference");
        let (sender, mut receiver) = tokio::sync::mpsc::channel(4);
        let cancellation = tokio_util::sync::CancellationToken::new();
        let send = session.send_streaming_events_controlled(
            messages,
            &[],
            LlmRequestOptions::default(),
            &cancellation,
            ProviderEventSink::new(sender),
        );
        let collect = async {
            let mut deltas = Vec::new();
            while let Some(ProviderStreamEvent::TextDelta(text)) = receiver.recv().await {
                deltas.push(text);
            }
            deltas
        };
        let (streamed, deltas) = tokio::join!(send, collect);
        let streamed = streamed.expect("real native stream");
        assert!(adapter.capabilities().native_streaming);
        assert!(
            deltas.len() >= 2,
            "native decode must produce incremental text"
        );
        assert_eq!(deltas.concat(), streamed.content);
        assert_eq!(streamed.content, batch.content);
        assert_eq!(streamed.tokens_used, batch.tokens_used);
    }
}
