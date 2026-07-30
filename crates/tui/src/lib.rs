//! `agent-tui` — Rust terminal UI for AI Agent OS.
//!
//! The library exposes the render-free [`app`] state machine (so it can be
//! unit/integration tested); the `agent-tui` binary (`src/main.rs`) wires it to
//! a terminal and the kernel syscall server.

use std::ops::{Deref, DerefMut};
use std::sync::Arc;

use agent_sdk::{ConnectionProfile, KernelClient, MessageResult, MessageStreamEvent, SdkError};
use tokio::sync::Mutex;

pub mod app;

/// The TUI's typed connection to the public syscall service.
///
/// Keeping connection and authentication here makes the render-free UI usable
/// against protected servers and gives conformance tests the exact same entry
/// path as the binary.
pub struct TuiClient {
    inner: KernelClient,
    messages: TuiMessageClient,
}

/// Cloneable message-stream handle backed by two dedicated public-wire
/// connections: one for the ordered stream and one for exact cancellation.
///
/// The ordinary [`TuiClient`] connection therefore remains available for
/// refreshes and lifecycle/operator actions while one turn is active.
#[derive(Clone)]
pub struct TuiMessageClient {
    stream: Arc<Mutex<KernelClient>>,
    cancellation: Arc<Mutex<KernelClient>>,
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
        let (inner, stream, cancellation) = tokio::try_join!(
            profile.connect(token),
            profile.connect(token),
            profile.connect(token)
        )?;
        Ok(Self {
            inner,
            messages: TuiMessageClient {
                stream: Arc::new(Mutex::new(stream)),
                cancellation: Arc::new(Mutex::new(cancellation)),
            },
        })
    }

    pub async fn rotate_auth(&mut self, token: impl Into<String>) -> Result<(), SdkError> {
        let token = token.into();
        self.inner.authenticate(token.clone()).await?;
        self.messages
            .stream
            .lock()
            .await
            .authenticate(token.clone())
            .await?;
        self.messages
            .cancellation
            .lock()
            .await
            .authenticate(token)
            .await
    }

    pub fn message_client(&self) -> TuiMessageClient {
        self.messages.clone()
    }
}

impl TuiMessageClient {
    /// Drive one ordered turn on the dedicated stream connection.
    pub async fn send_message_stream<F>(
        &self,
        request_id: impl Into<String>,
        agent_id: impl Into<String>,
        message: impl Into<String>,
        on_event: F,
    ) -> Result<MessageResult, SdkError>
    where
        F: FnMut(&MessageStreamEvent),
    {
        self.stream
            .lock()
            .await
            .send_message_stream(request_id, agent_id, message, on_event)
            .await
    }

    /// Cooperatively cancel one exact stream without taking the stream lock.
    pub async fn cancel_request(
        &self,
        request_id: impl Into<String>,
        agent_id: impl Into<String>,
    ) -> Result<bool, SdkError> {
        self.cancellation
            .lock()
            .await
            .cancel_request(request_id, agent_id)
            .await
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
