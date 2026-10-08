//! Bounded repository maintenance through the public kernel client.

pub mod fixture;
pub mod io;
pub mod provider;
pub mod types;
pub mod workflow;

pub use types::*;
pub use workflow::{run_job, ProcessRunner, TestRunner};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("task contract: {0}")]
    Contract(String),
    #[error("task budget exhausted: {0}")]
    Budget(String),
    #[error("task cancelled")]
    Cancelled,
    #[error("task paused at a durable boundary")]
    Paused,
    #[error("uncertain {0}; explicit retry approval is required")]
    Uncertain(String),
    #[error(transparent)]
    Sdk(#[from] agent_sdk::SdkError),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Kernel(#[from] kernel::KernelError),
}

pub fn hash(bytes: &[u8]) -> String {
    ring::digest::digest(&ring::digest::SHA256, bytes)
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
