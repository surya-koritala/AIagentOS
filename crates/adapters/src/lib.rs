//! LLM Provider Adapters for the AI Agent OS.

pub mod openai;
pub mod azure_openai;
pub mod anthropic;
pub mod local;
pub mod streaming;

#[cfg(test)]
mod openai_tests;

#[cfg(test)]
mod anthropic_tests;
