//! Reusable client plumbing for the command-line operator surfaces.
//!
//! `agentctl` intentionally owns no alternate kernel path: it connects and,
//! when configured, authenticates through the same [`agent_sdk::KernelClient`]
//! used by the SDK and TUI.

use std::ops::{Deref, DerefMut};

use agent_sdk::{KernelClient, SdkError};

/// An authenticated (or deliberately unauthenticated) `agentctl` session.
///
/// Deref access keeps the binary's command handlers on the typed SDK without
/// copying that API into this crate. Tests use the same constructor, so command
/// line authentication cannot drift from the other public clients.
pub struct OperatorClient {
    inner: KernelClient,
}

impl OperatorClient {
    /// Connect to `addr` and optionally authenticate before returning.
    pub async fn connect(addr: &str, token: Option<&str>) -> Result<Self, SdkError> {
        let mut inner = KernelClient::connect(addr).await?;
        if let Some(token) = token {
            inner.authenticate(token).await?;
        }
        Ok(Self { inner })
    }
}

impl Deref for OperatorClient {
    type Target = KernelClient;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for OperatorClient {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}
