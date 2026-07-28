//! `agent-tui` — Rust terminal UI for AI Agent OS.
//!
//! The library exposes the render-free [`app`] state machine (so it can be
//! unit/integration tested); the `agent-tui` binary (`src/main.rs`) wires it to
//! a terminal and the kernel syscall server.

use std::ops::{Deref, DerefMut};

use agent_sdk::{ConnectionProfile, KernelClient, SdkError};

pub mod app;

/// The TUI's typed connection to the public syscall service.
///
/// Keeping connection and authentication here makes the render-free UI usable
/// against protected servers and gives conformance tests the exact same entry
/// path as the binary.
pub struct TuiClient {
    inner: KernelClient,
}

impl TuiClient {
    /// Connect to `addr` and optionally authenticate before the first refresh.
    pub async fn connect(addr: &str, token: Option<&str>) -> Result<Self, SdkError> {
        Self::connect_profile(&ConnectionProfile::plaintext(addr), token).await
    }

    pub async fn connect_profile(
        profile: &ConnectionProfile,
        token: Option<&str>,
    ) -> Result<Self, SdkError> {
        let inner = profile.connect(token).await?;
        Ok(Self { inner })
    }

    pub async fn rotate_auth(&mut self, token: impl Into<String>) -> Result<(), SdkError> {
        self.inner.authenticate(token).await
    }
}

impl Deref for TuiClient {
    type Target = KernelClient;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for TuiClient {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}
