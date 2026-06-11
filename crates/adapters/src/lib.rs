//! LLM Provider Adapters for the AI Agent OS.

pub mod anthropic;
pub mod azure_openai;
pub mod deepseek;
pub mod gemini;
pub mod groq;
pub mod huggingface;
pub mod local;
/// In-process, pure-Rust GGUF inference. Heavy; only compiled with `--features
/// candle`. The on-device counterpart to [`local`].
#[cfg(feature = "candle")]
pub mod on_device;
pub mod openai;
pub mod streaming;
pub mod vllm;

#[cfg(test)]
mod openai_tests;

#[cfg(test)]
mod anthropic_tests;

#[cfg(test)]
mod groq_tests;

#[cfg(test)]
mod deepseek_tests;

#[cfg(test)]
mod gemini_tests;

#[cfg(test)]
mod vllm_tests;

#[cfg(test)]
mod huggingface_tests;
