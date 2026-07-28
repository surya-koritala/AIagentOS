//! # agent-sdk — embeddable Rust SDK for the AI Agent OS kernel
//!
//! This crate is the ergonomic, **Rust-only** face of the kernel's syscall
//! server ([`kernel::syscall_server`]). A developer building an agent connects
//! to a running [`SyscallServer`](kernel::syscall_server::SyscallServer) over
//! TCP and drives the kernel through typed async methods instead of hand-rolling
//! newline-delimited JSON.
//!
//! The SDK deliberately **reuses the kernel's wire types** ([`Syscall`] /
//! [`SyscallReply`]) and its [`SyscallClient`] transport rather than redefining
//! the protocol — there is exactly one source of truth for the boundary. What
//! this crate adds on top is:
//!
//! * [`KernelClient`] — a typed wrapper that maps each [`Syscall`] variant to an
//!   async method and preserves stable [`WireErrorCode`] categories from typed
//!   server errors.
//! * [`Agent`] — a builder (`Agent::builder()`) that creates an agent on the
//!   kernel and exposes `.send(..)` / `.call_tool(..)`.
//!
//! ## Example
//!
//! ```no_run
//! use agent_sdk::Agent;
//!
//! # async fn run() -> Result<(), agent_sdk::SdkError> {
//! let mut agent = Agent::builder()
//!     .name("alpha")
//!     .task("summarize the docs")
//!     .profile("standard")
//!     .connect("127.0.0.1:7777")
//!     .await?;
//!
//! let reply = agent.send("hello").await?;
//! println!("{}", reply.content);
//! # Ok(())
//! # }
//! ```

use kernel::syscall_server::{DataErasureTarget, Syscall, SyscallClient, SyscallReply};
use std::{path::PathBuf, time::Duration};
use tokio::net::ToSocketAddrs;

// Re-export the kernel wire types that appear in this crate's public API, so
// SDK consumers can name them without depending on the kernel directly.
pub use kernel::cluster_control::{
    ClusterJoinChallenge, ClusterMember, ClusterMemberRegistration, ClusterMemberState,
    ClusterMembershipAudit, ClusterMembershipSnapshot, NodeAvailability, NodeControlAudit,
    NodeControlStatus, NodeIdentity, NodeProfile,
};
pub use kernel::context::{ContextPressureStats, DeletionReceipt};
pub use kernel::data_inventory::{DataInventoryEntry, StorageDataInventory};
pub use kernel::init_system::{ServiceHistoryEntry, ServiceRuntimeInfo};
pub use kernel::operator_control::{OperatorTunable, OperatorTunableAudit};
pub use kernel::package::{
    InstallPolicy, InstalledPackage, LockedPackage, PackageArchive, PackageDep, PackageFile,
    PackageFileKind, PackageLock, PackageManifest, PackagePayload, PackageSbom, PackageSigningKey,
    PackageSummary, PackageTrustInput, PackageTrustKey, SbomComponent, VerifiedPackage,
};
pub use kernel::storage::{
    BackupAuthenticity, BackupMaintenanceStatus, BackupManifest, BackupRecoveryAnchor,
    BackupRetentionEntry, BackupRetentionIssue, BackupRetentionPolicy, BackupRetentionReport,
    BackupTrustRoot, CorruptStorageRecoveryReport, RestoreReport,
};
pub use kernel::syscall_server::{
    AgentSummary, FactSummary, GenerationCheckpointSummary, MessageStreamEvent,
    OperatorAgentSnapshot, OperatorCgroupSnapshot, OperatorNamespaceSnapshot,
    OperatorPackageSnapshot, OperatorServiceSnapshot, OperatorSnapshot, ProviderSummary,
    WireErrorCode,
};
pub use kernel::wire_contract::{ProtocolDescription, TransportDescription};

/// The wire-protocol version this SDK build was compiled against. A client
/// announces it via [`KernelClient::hello`]; a server outside its support
/// window is reported as [`SdkError::IncompatibleProtocol`] rather than failing
/// later with a confusing parse error.
pub use kernel::syscall_server::PROTOCOL_VERSION;

/// Deliberate proof-of-intent required by every typed SDK erasure method.
///
/// Callers must pass [`CONFIRM_DATA_ERASURE`] explicitly; there is no default
/// or boolean conversion that can be toggled accidentally by configuration.
#[derive(Debug, Clone, Copy)]
pub struct ConfirmDataErasure(());

pub const CONFIRM_DATA_ERASURE: ConfirmDataErasure = ConfirmDataErasure(());

/// Deliberate proof-of-intent required by confirmed backup expiration.
#[derive(Debug, Clone, Copy)]
pub struct ConfirmBackupRetention(());

pub const CONFIRM_BACKUP_RETENTION: ConfirmBackupRetention = ConfirmBackupRetention(());

pub mod cluster;
pub mod patterns;

pub use cluster::{ClusterClient, NodeHandle, PlacedAgent, Placement, PlacementConstraints};
pub use patterns::{
    Decision, DirectiveReasoner, FnPlanner, PlanRun, Planner, PlannerExecutor, ReActLoop,
    ReActOutcome, ReActStep, Reasoner, Step, StepResult, ToolInvocation,
};

/// Errors surfaced by the SDK.
///
/// [`SdkError::Wire`] carries the stable code, retry hint, and safe message from
/// protocol-v2 servers. [`SdkError::Kernel`] remains the compatibility form for
/// legacy-v1 replies and local SDK validation.
/// [`SdkError::Transport`] wraps I/O / connection failures, and
/// [`SdkError::UnexpectedReply`] guards the typed methods against a reply
/// variant that doesn't match the syscall that was sent.
#[derive(Debug, thiserror::Error)]
pub enum SdkError {
    /// Invalid local client configuration, before any network request is made.
    #[error("client configuration error: {0}")]
    Configuration(String),

    /// The kernel answered with [`SyscallReply::Error`] — e.g. a gate denial,
    /// an unknown tool, or an invalid agent id.
    #[error("kernel error: {0}")]
    Kernel(String),

    /// A protocol-v2 kernel error with a stable machine-readable category.
    #[error("kernel {code:?} error: {message}")]
    Wire {
        /// Stable public error category.
        code: WireErrorCode,
        /// Human-readable, redacted diagnostic.
        message: String,
        /// Whether retrying after backoff or an external state change can help.
        retryable: bool,
    },

    /// A transport / connection failure talking to the syscall server.
    #[error("transport error: {0}")]
    Transport(#[from] std::io::Error),

    /// The request was side-effecting and the transport failed after dispatch
    /// may have begun. The client deliberately does not replay it: callers must
    /// reconnect, inspect authoritative state, and reconcile explicitly.
    #[error(
        "{operation} outcome is indeterminate after a transport failure; the request was not replayed: {source}"
    )]
    IndeterminateMutation {
        operation: &'static str,
        #[source]
        source: std::io::Error,
    },

    /// The kernel replied with a variant that doesn't correspond to the
    /// syscall that was issued. Indicates a protocol mismatch.
    #[error("unexpected reply for {expected}: {got}")]
    UnexpectedReply {
        /// The reply variant the caller expected.
        expected: &'static str,
        /// A debug rendering of the variant actually received.
        got: String,
    },

    /// The server's wire-protocol support window doesn't include the version
    /// this SDK speaks ([`PROTOCOL_VERSION`]). Either the server is too old to
    /// understand the [`Hello`](Syscall::Hello) handshake at all (it predates
    /// protocol versioning), or its `[min, max]` window excludes us. Surfaced by
    /// [`KernelClient::hello`] so a version skew fails clearly up front rather
    /// than as a confusing error on a later syscall.
    #[error("incompatible wire protocol: this client speaks v{client}, server supports {server}")]
    IncompatibleProtocol {
        /// The protocol version this SDK build speaks.
        client: u32,
        /// A human description of the server's support (its window, or that it
        /// predates protocol versioning).
        server: String,
    },
}

impl SdkError {
    /// Stable wire category when the server supplied one.
    pub fn wire_code(&self) -> Option<WireErrorCode> {
        match self {
            Self::Wire { code, .. } => Some(*code),
            _ => None,
        }
    }

    /// The kernel/local validation message without transport formatting.
    pub fn kernel_message(&self) -> Option<&str> {
        match self {
            Self::Kernel(message) | Self::Wire { message, .. } => Some(message),
            _ => None,
        }
    }

    /// Whether the server explicitly classified the failure as retryable.
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::Wire {
                retryable: true,
                ..
            }
        )
    }
}

/// Transport settings shared by every first-party operator client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionTransport {
    /// Plain TCP, intended for loopback or an otherwise secured local path.
    Plaintext,
    /// TLS with an explicit PEM trust bundle and verified DNS server name.
    Tls {
        server_name: String,
        ca_certificates: PathBuf,
    },
}

/// A non-secret, reusable connection profile.
///
/// Tokens are supplied only when connecting or rotating authentication, so a
/// profile is safe to log and persist.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionProfile {
    pub address: String,
    pub transport: ConnectionTransport,
    pub connect_timeout: Duration,
}

impl ConnectionProfile {
    pub const DEFAULT_ADDRESS: &'static str = "127.0.0.1:7777";
    pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
    pub const MAX_CONNECT_TIMEOUT: Duration = Duration::from_secs(60);

    pub fn plaintext(address: impl Into<String>) -> Self {
        Self {
            address: address.into(),
            transport: ConnectionTransport::Plaintext,
            connect_timeout: Self::DEFAULT_CONNECT_TIMEOUT,
        }
    }

    /// Load the common first-party profile from environment variables.
    ///
    /// `AGENTOS_TLS_CA` enables verified TLS and requires
    /// `AGENTOS_TLS_SERVER_NAME`. Authentication remains separate in
    /// `AGENT_SERVER_TOKEN`, preventing accidental token rendering.
    pub fn from_env() -> Result<Self, SdkError> {
        let address =
            std::env::var("AGENTOS_ADDR").unwrap_or_else(|_| Self::DEFAULT_ADDRESS.to_string());
        let connect_timeout = match std::env::var("AGENTOS_CONNECT_TIMEOUT_MS") {
            Ok(raw) => {
                let millis = raw.parse::<u64>().map_err(|_| {
                    SdkError::Configuration(
                        "AGENTOS_CONNECT_TIMEOUT_MS must be a positive integer".into(),
                    )
                })?;
                let timeout = Duration::from_millis(millis);
                if timeout.is_zero() || timeout > Self::MAX_CONNECT_TIMEOUT {
                    return Err(SdkError::Configuration(
                        "AGENTOS_CONNECT_TIMEOUT_MS must be between 1 and 60000".into(),
                    ));
                }
                timeout
            }
            Err(_) => Self::DEFAULT_CONNECT_TIMEOUT,
        };
        let transport = match std::env::var("AGENTOS_TLS_CA") {
            Ok(path) if !path.trim().is_empty() => {
                let server_name = std::env::var("AGENTOS_TLS_SERVER_NAME").map_err(|_| {
                    SdkError::Configuration(
                        "AGENTOS_TLS_SERVER_NAME is required when AGENTOS_TLS_CA is set".into(),
                    )
                })?;
                if server_name.trim().is_empty() {
                    return Err(SdkError::Configuration(
                        "AGENTOS_TLS_SERVER_NAME cannot be empty".into(),
                    ));
                }
                ConnectionTransport::Tls {
                    server_name,
                    ca_certificates: PathBuf::from(path),
                }
            }
            _ => {
                if std::env::var_os("AGENTOS_TLS_SERVER_NAME").is_some() {
                    return Err(SdkError::Configuration(
                        "AGENTOS_TLS_CA is required when AGENTOS_TLS_SERVER_NAME is set".into(),
                    ));
                }
                ConnectionTransport::Plaintext
            }
        };
        Ok(Self {
            address,
            transport,
            connect_timeout,
        })
    }

    /// Connect, negotiate protocol compatibility, and optionally authenticate.
    pub async fn connect(&self, token: Option<&str>) -> Result<KernelClient, SdkError> {
        let mut client = self.connect_once(token).await?;
        client.reconnect = Some(ReconnectSettings {
            profile: self.clone(),
            token: token.map(ToOwned::to_owned),
        });
        Ok(client)
    }

    async fn connect_once(&self, token: Option<&str>) -> Result<KernelClient, SdkError> {
        let connect = async {
            let mut client = match &self.transport {
                ConnectionTransport::Plaintext => KernelClient::connect(&self.address).await?,
                ConnectionTransport::Tls {
                    server_name,
                    ca_certificates,
                } => {
                    use rustls::pki_types::{pem::PemObject, CertificateDer};

                    let _ = rustls::crypto::ring::default_provider().install_default();
                    let mut roots = rustls::RootCertStore::empty();
                    let certificates = CertificateDer::pem_file_iter(ca_certificates)
                        .map_err(|error| {
                            SdkError::Configuration(format!(
                                "failed to open TLS CA bundle {}: {error}",
                                ca_certificates.display()
                            ))
                        })?
                        .collect::<Result<Vec<_>, _>>()
                        .map_err(|error| {
                            SdkError::Configuration(format!(
                                "failed to parse TLS CA bundle {}: {error}",
                                ca_certificates.display()
                            ))
                        })?;
                    if certificates.is_empty() {
                        return Err(SdkError::Configuration(format!(
                            "TLS CA bundle {} contains no certificates",
                            ca_certificates.display()
                        )));
                    }
                    roots.add_parsable_certificates(certificates);
                    if roots.is_empty() {
                        return Err(SdkError::Configuration(format!(
                            "TLS CA bundle {} contains no trusted certificates",
                            ca_certificates.display()
                        )));
                    }
                    let config = rustls::ClientConfig::builder()
                        .with_root_certificates(roots)
                        .with_no_client_auth();
                    KernelClient::connect_tls(&self.address, server_name.clone(), config).await?
                }
            };
            if let Some(token) = token {
                client.authenticate_once(token).await?;
            }
            Ok(client)
        };
        tokio::time::timeout(self.connect_timeout, connect)
            .await
            .map_err(|_| {
                SdkError::Transport(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    format!(
                        "connection profile timed out after {} ms",
                        self.connect_timeout.as_millis()
                    ),
                ))
            })?
    }

    /// Replace the authenticated credential on an existing connection.
    pub async fn rotate_auth(
        &self,
        client: &mut KernelClient,
        token: impl Into<String>,
    ) -> Result<(), SdkError> {
        client.authenticate(token).await
    }
}

/// Result of a [`KernelClient::send_message`] / [`Agent::send`] turn.
#[derive(Debug, Clone, serde::Serialize)]
pub struct MessageResult {
    /// The agent's textual output for the turn.
    pub content: String,
    /// How many tool calls the agent made during the turn.
    pub tool_calls: usize,
    /// Tokens consumed by the turn.
    pub tokens: u32,
}

/// Result of a durable lifecycle operation. `checkpoint_id` is present when a
/// pause captured resumable work (or a resumed turn paused again).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct LifecycleResult {
    pub state: String,
    pub checkpoint_id: Option<String>,
    pub resumed_content: Option<String>,
    pub resumed_tool_calls: Option<usize>,
    pub resumed_tokens: Option<u32>,
}

/// Snapshot of the syscall gate's enforcement counters.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct GateStats {
    pub allowed: u64,
    pub denied_capability: u64,
    pub denied_mac: u64,
    pub denied_approval: u64,
    pub denied_cgroup: u64,
    pub denied_namespace: u64,
    pub denied_unknown: u64,
    pub audited: u64,
}

/// One agent's gate-enforced process identity and granted namespaces.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct AgentEnforcementInfo {
    pub pid: u64,
    pub capabilities: Vec<String>,
    pub namespaces: Vec<u64>,
}

/// A kernel node's load/health snapshot (reply to `node_info`).
#[derive(Debug, Clone, Default)]
pub struct NodeLoad {
    /// Durable identity, admission state, and placement constraints. Older
    /// compatible servers may omit this additive field.
    pub control: Option<NodeControlStatus>,
    /// Total agents the node hosts.
    pub agent_count: usize,
    /// Agents currently executing a turn.
    pub running_agents: usize,
    pub live_agents: usize,
    pub queued_agents: usize,
    pub paused_agents: usize,
    pub stopped_agents: usize,
    pub active_turns: usize,
    pub waiting_turns: usize,
    pub turn_capacity: usize,
    pub llm_requests_in_flight: usize,
    pub llm_requests_waiting: usize,
    pub llm_core_capacity: usize,
}

/// Signed response to a discovery nonce.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeIdentityProof {
    pub node_id: String,
    pub fingerprint: String,
    pub public_key: String,
    pub signature_hex: String,
}

/// The server's wire-protocol support window (reply to `hello`).
#[derive(Debug, Clone, serde::Serialize)]
pub struct ProtocolInfo {
    /// The newest wire-protocol version the server speaks.
    pub protocol_version: u32,
    /// The oldest wire-protocol version the server still accepts.
    pub min_protocol_version: u32,
    /// The server's crate version (informational).
    pub server_version: String,
    /// Fine-grained stable features advertised by this server.
    pub features: Vec<String>,
}

/// The kernel's operational metrics (reply to `metrics`). Carries the rendered
/// Prometheus text exposition plus a couple of the headline numbers as typed
/// fields.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct Metrics {
    /// The full `text/plain; version=0.0.4` Prometheus exposition.
    pub prometheus: String,
    /// Total agents the kernel hosts.
    pub agent_count: usize,
    /// System-wide tokens consumed.
    pub tokens_consumed: u64,
}

/// A typed, async client over the kernel's syscall protocol.
///
/// Wraps [`SyscallClient`]: each method serializes the matching [`Syscall`],
/// awaits the [`SyscallReply`], and maps [`SyscallReply::Error`] into
/// [`SdkError::Kernel`]. One [`KernelClient`] owns one connection; clone the
/// address and [`connect`](Self::connect) again for concurrent callers.
pub struct KernelClient {
    inner: SyscallClient,
    reconnect: Option<ReconnectSettings>,
    needs_reconnect: bool,
    reconnect_generation: u64,
}

#[derive(Clone)]
struct ReconnectSettings {
    profile: ConnectionProfile,
    token: Option<String>,
}

impl KernelClient {
    /// Connect to a running syscall server at `addr` (e.g. `"127.0.0.1:7777"`).
    pub async fn connect(addr: impl ToSocketAddrs) -> Result<Self, SdkError> {
        let mut client = Self {
            inner: SyscallClient::connect(addr).await?,
            reconnect: None,
            needs_reconnect: false,
            reconnect_generation: 0,
        };
        client.hello().await?;
        Ok(client)
    }

    /// Connect to a running syscall server over TLS. Mirrors [`connect`](Self::connect)
    /// but performs a rustls handshake first: the server's certificate is verified
    /// against `config`'s root store and must present `server_name` (e.g.
    /// `"localhost"`). Lets SDK / cluster users dial a TLS-terminated kernel node.
    pub async fn connect_tls(
        addr: impl ToSocketAddrs,
        server_name: impl Into<String>,
        config: rustls::ClientConfig,
    ) -> Result<Self, SdkError> {
        let mut client = Self {
            inner: SyscallClient::connect_tls(addr, server_name, config).await?,
            reconnect: None,
            needs_reconnect: false,
            reconnect_generation: 0,
        };
        client.hello().await?;
        Ok(client)
    }

    /// Build a [`KernelClient`] from an already-connected [`SyscallClient`].
    pub fn from_client(inner: SyscallClient) -> Self {
        Self {
            inner,
            reconnect: None,
            needs_reconnect: false,
            reconnect_generation: 0,
        }
    }

    /// Number of successful transport recoveries performed by a connection
    /// profile. Direct `KernelClient::connect` sessions remain at zero.
    pub fn reconnect_generation(&self) -> u64 {
        self.reconnect_generation
    }

    /// Re-establish a profile-backed connection, renegotiate the protocol, and
    /// restore the latest successfully authenticated credential.
    pub async fn reconnect(&mut self) -> Result<(), SdkError> {
        let settings = self.reconnect.clone().ok_or_else(|| {
            SdkError::Configuration(
                "this client was not created from a reconnectable connection profile".into(),
            )
        })?;
        let replacement = settings
            .profile
            .connect_once(settings.token.as_deref())
            .await?;
        self.inner = replacement.inner;
        self.needs_reconnect = false;
        self.reconnect_generation = self.reconnect_generation.saturating_add(1);
        Ok(())
    }

    async fn ensure_connected(&mut self) -> Result<(), SdkError> {
        if self.needs_reconnect {
            self.reconnect().await?;
        }
        Ok(())
    }

    async fn authenticate_once(&mut self, token: &str) -> Result<(), SdkError> {
        match self
            .inner
            .call(Syscall::Authenticate {
                token: token.to_string(),
            })
            .await?
        {
            SyscallReply::Authenticated => Ok(()),
            SyscallReply::Error { message } => Err(SdkError::Kernel(message)),
            SyscallReply::TypedError {
                code,
                message,
                retryable,
            } => Err(SdkError::Wire {
                code,
                message,
                retryable,
            }),
            other => Err(unexpected("Authenticated", &other)),
        }
    }

    /// Create an agent through the full kernel path (gate registration, cgroup,
    /// namespaces, scheduler admission, procfs). Returns the new agent's id.
    ///
    /// `provider`/`profile` default to `"stub"`/`"standard"` and `priority` to
    /// `3` when passed as [`None`] — matching the kernel's wire defaults.
    pub async fn create_agent(
        &mut self,
        name: impl Into<String>,
        task: impl Into<String>,
        provider: Option<String>,
        profile: Option<String>,
        priority: Option<u8>,
    ) -> Result<String, SdkError> {
        let call = Syscall::CreateAgent {
            name: name.into(),
            task: task.into(),
            provider: provider.unwrap_or_else(|| "stub".to_string()),
            profile: profile.unwrap_or_else(|| "standard".to_string()),
            priority: priority.unwrap_or(3),
        };
        match self.call(call).await? {
            SyscallReply::AgentCreated { id } => Ok(id),
            other => Err(unexpected("AgentCreated", &other)),
        }
    }

    /// List all agents the kernel knows about.
    pub async fn list_agents(&mut self) -> Result<Vec<AgentSummary>, SdkError> {
        match self.call(Syscall::ListAgents).await? {
            SyscallReply::Agents { agents } => Ok(agents),
            other => Err(unexpected("Agents", &other)),
        }
    }

    async fn lifecycle_call(&mut self, call: Syscall) -> Result<LifecycleResult, SdkError> {
        match self.call(call).await? {
            SyscallReply::AgentStatus {
                state,
                checkpoint_id,
                resumed_content,
                resumed_tool_calls,
                resumed_tokens,
            } => Ok(LifecycleResult {
                state,
                checkpoint_id,
                resumed_content,
                resumed_tool_calls,
                resumed_tokens,
            }),
            other => Err(unexpected("AgentStatus", &other)),
        }
    }

    /// Durable pause result, including the checkpoint id when an active turn
    /// reached its cooperative boundary.
    pub async fn pause_agent_durable(
        &mut self,
        agent_id: impl Into<String>,
    ) -> Result<LifecycleResult, SdkError> {
        self.lifecycle_call(Syscall::PauseAgent {
            agent_id: agent_id.into(),
        })
        .await
    }

    /// Pause admission for an agent and cooperatively cancel an active turn.
    pub async fn pause_agent(&mut self, agent_id: impl Into<String>) -> Result<String, SdkError> {
        Ok(self.pause_agent_durable(agent_id).await?.state)
    }

    /// Durable resume result, including completed continuation output.
    pub async fn resume_agent_durable(
        &mut self,
        agent_id: impl Into<String>,
    ) -> Result<LifecycleResult, SdkError> {
        self.lifecycle_call(Syscall::ResumeAgent {
            agent_id: agent_id.into(),
        })
        .await
    }

    /// Resume a paused agent.
    pub async fn resume_agent(&mut self, agent_id: impl Into<String>) -> Result<String, SdkError> {
        Ok(self.resume_agent_durable(agent_id).await?.state)
    }

    /// Gracefully stop an agent and clean up its live resources.
    pub async fn stop_agent(&mut self, agent_id: impl Into<String>) -> Result<String, SdkError> {
        Ok(self
            .lifecycle_call(Syscall::StopAgent {
                agent_id: agent_id.into(),
            })
            .await?
            .state)
    }

    /// Force an agent into its terminal state and clean up live resources.
    pub async fn kill_agent(&mut self, agent_id: impl Into<String>) -> Result<String, SdkError> {
        Ok(self
            .lifecycle_call(Syscall::KillAgent {
                agent_id: agent_id.into(),
            })
            .await?
            .state)
    }

    /// Return an agent's current lifecycle state.
    pub async fn agent_status(&mut self, agent_id: impl Into<String>) -> Result<String, SdkError> {
        Ok(self
            .lifecycle_call(Syscall::GetAgentStatus {
                agent_id: agent_id.into(),
            })
            .await?
            .state)
    }

    /// Wait for an agent to become terminal, bounded by `timeout`.
    pub async fn wait_agent(
        &mut self,
        agent_id: impl Into<String>,
        timeout: std::time::Duration,
    ) -> Result<String, SdkError> {
        let timeout_ms = u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX);
        Ok(self
            .lifecycle_call(Syscall::WaitAgent {
                agent_id: agent_id.into(),
                timeout_ms,
            })
            .await?
            .state)
    }

    pub async fn list_generation_checkpoints(
        &mut self,
        agent_id: impl Into<String>,
    ) -> Result<Vec<GenerationCheckpointSummary>, SdkError> {
        match self
            .call(Syscall::ListGenerationCheckpoints {
                agent_id: agent_id.into(),
            })
            .await?
        {
            SyscallReply::GenerationCheckpoints { checkpoints } => Ok(checkpoints),
            other => Err(unexpected("GenerationCheckpoints", &other)),
        }
    }

    pub async fn resume_generation_checkpoint(
        &mut self,
        agent_id: impl Into<String>,
        checkpoint_id: impl Into<String>,
    ) -> Result<LifecycleResult, SdkError> {
        self.lifecycle_call(Syscall::ResumeGenerationCheckpoint {
            agent_id: agent_id.into(),
            checkpoint_id: checkpoint_id.into(),
        })
        .await
    }

    pub async fn delete_generation_checkpoint(
        &mut self,
        agent_id: impl Into<String>,
        checkpoint_id: impl Into<String>,
    ) -> Result<bool, SdkError> {
        match self
            .call(Syscall::DeleteGenerationCheckpoint {
                agent_id: agent_id.into(),
                checkpoint_id: checkpoint_id.into(),
            })
            .await?
        {
            SyscallReply::GenerationCheckpointDeleted { existed } => Ok(existed),
            other => Err(unexpected("GenerationCheckpointDeleted", &other)),
        }
    }

    /// Drive one think→act→observe turn for an agent.
    pub async fn send_message(
        &mut self,
        agent_id: impl Into<String>,
        message: impl Into<String>,
    ) -> Result<MessageResult, SdkError> {
        let call = Syscall::SendMessage {
            agent_id: agent_id.into(),
            message: message.into(),
        };
        match self.call(call).await? {
            SyscallReply::Message {
                content,
                tool_calls,
                tokens,
            } => Ok(MessageResult {
                content,
                tool_calls,
                tokens,
            }),
            other => Err(unexpected("Message", &other)),
        }
    }

    /// Drive one turn and deliver ordered stream events as they arrive.
    ///
    /// `request_id` must be unique among active streams for this agent and is
    /// used by [`cancel_request`](Self::cancel_request) from a second
    /// authenticated client. The callback is synchronous and should return
    /// quickly so it does not become the stream's backpressure bottleneck.
    pub async fn send_message_stream<F>(
        &mut self,
        request_id: impl Into<String>,
        agent_id: impl Into<String>,
        message: impl Into<String>,
        mut on_event: F,
    ) -> Result<MessageResult, SdkError>
    where
        F: FnMut(&MessageStreamEvent),
    {
        let request_id = request_id.into();
        self.ensure_connected().await?;
        if let Err(source) = self
            .inner
            .send(&Syscall::SendMessageStream {
                request_id: request_id.clone(),
                agent_id: agent_id.into(),
                message: message.into(),
            })
            .await
        {
            if self.reconnect.is_some() {
                self.needs_reconnect = true;
                return Err(SdkError::IndeterminateMutation {
                    operation: "streaming agent turn",
                    source,
                });
            }
            return Err(SdkError::Transport(source));
        }
        let mut next_sequence = 0_u64;
        loop {
            let reply = match self.inner.read_reply().await {
                Ok(reply) => reply,
                Err(source) if self.reconnect.is_some() => {
                    self.needs_reconnect = true;
                    return Err(SdkError::IndeterminateMutation {
                        operation: "streaming agent turn",
                        source,
                    });
                }
                Err(source) => return Err(SdkError::Transport(source)),
            };
            match reply {
                SyscallReply::StreamEvent {
                    request_id: reply_id,
                    sequence,
                    event,
                } if reply_id == request_id && sequence == next_sequence => {
                    next_sequence = next_sequence.saturating_add(1);
                    on_event(&event);
                }
                SyscallReply::StreamCompleted {
                    request_id: reply_id,
                    content,
                    tool_calls,
                    tokens,
                } if reply_id == request_id => {
                    return Ok(MessageResult {
                        content,
                        tool_calls,
                        tokens,
                    });
                }
                SyscallReply::StreamFailed {
                    request_id: reply_id,
                    code,
                    message,
                    retryable,
                } if reply_id == request_id => {
                    return Err(SdkError::Wire {
                        code,
                        message,
                        retryable,
                    });
                }
                SyscallReply::Error { message } => return Err(SdkError::Kernel(message)),
                SyscallReply::TypedError {
                    code,
                    message,
                    retryable,
                } => {
                    return Err(SdkError::Wire {
                        code,
                        message,
                        retryable,
                    });
                }
                other => return Err(unexpected("ordered message stream frame", &other)),
            }
        }
    }

    /// Cooperatively cancel one exact active stream. This must normally be
    /// called from a second authenticated client because the streaming client
    /// owns its connection until the terminal frame.
    pub async fn cancel_request(
        &mut self,
        request_id: impl Into<String>,
        agent_id: impl Into<String>,
    ) -> Result<bool, SdkError> {
        let request_id = request_id.into();
        match self
            .call(Syscall::CancelRequest {
                request_id: request_id.clone(),
                agent_id: agent_id.into(),
            })
            .await?
        {
            SyscallReply::RequestCancellation {
                request_id: reply_id,
                accepted,
            } if reply_id == request_id => Ok(accepted),
            other => Err(unexpected("RequestCancellation", &other)),
        }
    }

    /// Invoke a single tool as an agent. The call goes through the syscall gate
    /// (capability / MAC / cgroup / namespace) on the kernel side, so a denial
    /// comes back as [`SdkError::Kernel`].
    pub async fn call_tool(
        &mut self,
        agent_id: impl Into<String>,
        tool: impl Into<String>,
        args: serde_json::Value,
    ) -> Result<serde_json::Value, SdkError> {
        let call = Syscall::CallTool {
            agent_id: agent_id.into(),
            tool: tool.into(),
            args,
        };
        match self.call(call).await? {
            SyscallReply::ToolResult { data } => Ok(data),
            other => Err(unexpected("ToolResult", &other)),
        }
    }

    /// Snapshot the syscall gate's enforcement counters.
    pub async fn gate_stats(&mut self) -> Result<GateStats, SdkError> {
        match self.call(Syscall::GateStats).await? {
            SyscallReply::GateStats {
                allowed,
                denied_capability,
                denied_mac,
                denied_approval,
                denied_cgroup,
                denied_namespace,
                denied_unknown,
                audited,
            } => Ok(GateStats {
                allowed,
                denied_capability,
                denied_mac,
                denied_approval,
                denied_cgroup,
                denied_namespace,
                denied_unknown,
                audited,
            }),
            other => Err(unexpected("GateStats", &other)),
        }
    }

    /// Read one agent's effective capability and namespace grants.
    pub async fn agent_info(
        &mut self,
        agent_id: impl Into<String>,
    ) -> Result<AgentEnforcementInfo, SdkError> {
        match self
            .call(Syscall::AgentInfo {
                agent_id: agent_id.into(),
            })
            .await?
        {
            SyscallReply::AgentInfo {
                pid,
                capabilities,
                namespaces,
            } => Ok(AgentEnforcementInfo {
                pid,
                capabilities,
                namespaces,
            }),
            other => Err(unexpected("AgentInfo", &other)),
        }
    }

    /// Negotiate the wire protocol with the server.
    ///
    /// Sends [`Syscall::Hello`] with this SDK's [`PROTOCOL_VERSION`] and verifies
    /// the version is inside the server's `[min, max]` support window. Returns
    /// the server's [`ProtocolInfo`] on success, or [`SdkError::IncompatibleProtocol`]
    /// when the windows don't overlap — including the case where the server is too
    /// old to understand `Hello` at all (it answers with an error, which predates
    /// protocol versioning). Call this once right after connecting to fail fast on
    /// a version skew instead of hitting a confusing error on a later syscall.
    pub async fn hello(&mut self) -> Result<ProtocolInfo, SdkError> {
        // Use the raw transport, not `self.call`: the latter folds
        // `SyscallReply::Error` into `SdkError::Kernel`, but here an Error reply
        // is itself a meaningful signal (an old server rejecting the handshake).
        match self
            .inner
            .call(Syscall::Hello {
                protocol_version: PROTOCOL_VERSION,
            })
            .await?
        {
            SyscallReply::Hello {
                protocol_version,
                min_protocol_version,
                server_version,
                features,
            } => {
                if (min_protocol_version..=protocol_version).contains(&PROTOCOL_VERSION) {
                    Ok(ProtocolInfo {
                        protocol_version,
                        min_protocol_version,
                        server_version,
                        features,
                    })
                } else {
                    Err(SdkError::IncompatibleProtocol {
                        client: PROTOCOL_VERSION,
                        server: format!(
                            "v{min_protocol_version}..=v{protocol_version} ({server_version})"
                        ),
                    })
                }
            }
            // A server that predates protocol versioning can't parse `hello` and
            // answers with an error — that itself is the incompatibility signal.
            SyscallReply::Error { message } => Err(SdkError::IncompatibleProtocol {
                client: PROTOCOL_VERSION,
                server: format!("rejected handshake: {message}"),
            }),
            SyscallReply::TypedError { message, .. } => Err(SdkError::IncompatibleProtocol {
                client: PROTOCOL_VERSION,
                server: format!("rejected handshake: {message}"),
            }),
            other => Err(unexpected("Hello", &other)),
        }
    }

    /// Fetch the server's versioned machine-readable schemas and transport
    /// contract. This remains available before authentication.
    pub async fn describe_protocol(&mut self) -> Result<ProtocolDescription, SdkError> {
        match self.call(Syscall::DescribeProtocol).await? {
            SyscallReply::ProtocolDescription { description } => Ok(description),
            other => Err(unexpected("ProtocolDescription", &other)),
        }
    }

    /// Verify that this protocol-v2 connection is responsive and reset the
    /// server's established idle deadline.
    pub async fn ping(&mut self) -> Result<(), SdkError> {
        match self.call(Syscall::Ping).await? {
            SyscallReply::Pong => Ok(()),
            other => Err(unexpected("Pong", &other)),
        }
    }

    /// Read a kernel node's load/health (agent counts) — used by
    /// [`ClusterClient`] for placement.
    pub async fn node_info(&mut self) -> Result<NodeLoad, SdkError> {
        match self.call(Syscall::NodeInfo).await? {
            SyscallReply::NodeInfo {
                control,
                agent_count,
                running_agents,
                live_agents,
                queued_agents,
                paused_agents,
                stopped_agents,
                active_turns,
                waiting_turns,
                turn_capacity,
                llm_requests_in_flight,
                llm_requests_waiting,
                llm_core_capacity,
            } => Ok(NodeLoad {
                control,
                agent_count,
                running_agents,
                live_agents,
                queued_agents,
                paused_agents,
                stopped_agents,
                active_turns,
                waiting_turns,
                turn_capacity,
                llm_requests_in_flight,
                llm_requests_waiting,
                llm_core_capacity,
            }),
            other => Err(unexpected("NodeInfo", &other)),
        }
    }

    /// Sign a nonce with the node's durable Ed25519 identity.
    pub async fn prove_node_identity(
        &mut self,
        challenge_hex: impl Into<String>,
    ) -> Result<NodeIdentityProof, SdkError> {
        match self
            .call(Syscall::ProveNodeIdentity {
                challenge_hex: challenge_hex.into(),
            })
            .await?
        {
            SyscallReply::NodeIdentityProof {
                node_id,
                fingerprint,
                public_key,
                signature_hex,
            } => Ok(NodeIdentityProof {
                node_id,
                fingerprint,
                public_key,
                signature_hex,
            }),
            other => Err(unexpected("NodeIdentityProof", &other)),
        }
    }

    pub async fn set_node_availability(
        &mut self,
        availability: NodeAvailability,
        expected_generation: u64,
        reason: impl Into<String>,
    ) -> Result<NodeControlStatus, SdkError> {
        match self
            .call(Syscall::SetNodeAvailability {
                availability,
                expected_generation,
                reason: reason.into(),
            })
            .await?
        {
            SyscallReply::NodeControlUpdated { control } => Ok(control),
            other => Err(unexpected("NodeControlUpdated", &other)),
        }
    }

    pub async fn set_node_profile(
        &mut self,
        profile: NodeProfile,
        expected_generation: u64,
        reason: impl Into<String>,
    ) -> Result<NodeControlStatus, SdkError> {
        match self
            .call(Syscall::SetNodeProfile {
                profile,
                expected_generation,
                reason: reason.into(),
            })
            .await?
        {
            SyscallReply::NodeControlUpdated { control } => Ok(control),
            other => Err(unexpected("NodeControlUpdated", &other)),
        }
    }

    pub async fn node_control_audit(
        &mut self,
        limit: usize,
    ) -> Result<Vec<NodeControlAudit>, SdkError> {
        match self.call(Syscall::ListNodeControlAudit { limit }).await? {
            SyscallReply::NodeControlAudit { entries } => Ok(entries),
            other => Err(unexpected("NodeControlAudit", &other)),
        }
    }

    pub async fn issue_cluster_join_challenge(
        &mut self,
        ttl_seconds: u64,
    ) -> Result<ClusterJoinChallenge, SdkError> {
        match self
            .call(Syscall::IssueClusterJoinChallenge { ttl_seconds })
            .await?
        {
            SyscallReply::ClusterJoinChallenge { challenge } => Ok(challenge),
            other => Err(unexpected("ClusterJoinChallenge", &other)),
        }
    }

    pub async fn register_cluster_member(
        &mut self,
        registration: ClusterMemberRegistration,
        challenge_hex: impl Into<String>,
        signature_hex: impl Into<String>,
        expected_generation: Option<u64>,
        reason: impl Into<String>,
    ) -> Result<ClusterMember, SdkError> {
        match self
            .call(Syscall::RegisterClusterMember {
                registration,
                challenge_hex: challenge_hex.into(),
                signature_hex: signature_hex.into(),
                expected_generation,
                reason: reason.into(),
            })
            .await?
        {
            SyscallReply::ClusterMemberUpdated { member } => Ok(member),
            other => Err(unexpected("ClusterMemberUpdated", &other)),
        }
    }

    pub async fn set_cluster_member_state(
        &mut self,
        node_id: impl Into<String>,
        state: ClusterMemberState,
        expected_generation: u64,
        reason: impl Into<String>,
    ) -> Result<ClusterMember, SdkError> {
        match self
            .call(Syscall::SetClusterMemberState {
                node_id: node_id.into(),
                state,
                expected_generation,
                reason: reason.into(),
            })
            .await?
        {
            SyscallReply::ClusterMemberUpdated { member } => Ok(member),
            other => Err(unexpected("ClusterMemberUpdated", &other)),
        }
    }

    pub async fn cluster_membership(&mut self) -> Result<ClusterMembershipSnapshot, SdkError> {
        match self.call(Syscall::GetClusterMembership).await? {
            SyscallReply::ClusterMembership { membership } => Ok(membership),
            other => Err(unexpected("ClusterMembership", &other)),
        }
    }

    pub async fn cluster_membership_audit(
        &mut self,
        limit: usize,
    ) -> Result<Vec<ClusterMembershipAudit>, SdkError> {
        match self
            .call(Syscall::ListClusterMembershipAudit { limit })
            .await?
        {
            SyscallReply::ClusterMembershipAudit { entries } => Ok(entries),
            other => Err(unexpected("ClusterMembershipAudit", &other)),
        }
    }

    /// Pull the kernel's operational metrics as a Prometheus text exposition
    /// (gate enforcement counters, agent counts, token/api totals, uptime). Lets
    /// a client scrape metrics over the syscall protocol without an HTTP port.
    pub async fn metrics(&mut self) -> Result<Metrics, SdkError> {
        match self.call(Syscall::Metrics).await? {
            SyscallReply::Metrics {
                prometheus,
                agent_count,
                tokens_consumed,
            } => Ok(Metrics {
                prometheus,
                agent_count,
                tokens_consumed,
            }),
            other => Err(unexpected("Metrics", &other)),
        }
    }

    /// List the LLM providers registered with the kernel.
    pub async fn list_providers(&mut self) -> Result<Vec<ProviderSummary>, SdkError> {
        match self.call(Syscall::ListProviders).await? {
            SyscallReply::Providers { providers } => Ok(providers),
            other => Err(unexpected("Providers", &other)),
        }
    }

    /// Store a fact in an agent's long-term memory. `category` is one of
    /// `preference` / `learned_pattern` / `fact` / `instruction` (defaults to
    /// `fact` when `None`). Returns the new fact's id.
    pub async fn memory_store(
        &mut self,
        agent_id: impl Into<String>,
        content: impl Into<String>,
        category: Option<String>,
    ) -> Result<String, SdkError> {
        let call = Syscall::MemoryStore {
            agent_id: agent_id.into(),
            content: content.into(),
            category,
        };
        match self.call(call).await? {
            SyscallReply::MemoryStored { id } => Ok(id),
            other => Err(unexpected("MemoryStored", &other)),
        }
    }

    /// Query an agent's long-term memory using the configured semantic index.
    pub async fn memory_query(
        &mut self,
        agent_id: impl Into<String>,
        query: impl Into<String>,
    ) -> Result<Vec<FactSummary>, SdkError> {
        let call = Syscall::MemoryQuery {
            agent_id: agent_id.into(),
            query: query.into(),
        };
        match self.call(call).await? {
            SyscallReply::Memory { facts } => Ok(facts),
            other => Err(unexpected("Memory", &other)),
        }
    }

    /// Replace one agent-owned fact and regenerate its embedding.
    pub async fn memory_update(
        &mut self,
        agent_id: impl Into<String>,
        fact_id: impl Into<String>,
        content: impl Into<String>,
    ) -> Result<bool, SdkError> {
        let call = Syscall::MemoryUpdate {
            agent_id: agent_id.into(),
            fact_id: fact_id.into(),
            content: content.into(),
        };
        match self.call(call).await? {
            SyscallReply::MemoryUpdated { updated } => Ok(updated),
            other => Err(unexpected("MemoryUpdated", &other)),
        }
    }

    /// Delete one agent-owned fact.
    pub async fn memory_delete(
        &mut self,
        agent_id: impl Into<String>,
        fact_id: impl Into<String>,
    ) -> Result<bool, SdkError> {
        let call = Syscall::MemoryDelete {
            agent_id: agent_id.into(),
            fact_id: fact_id.into(),
        };
        match self.call(call).await? {
            SyscallReply::MemoryDeleted { deleted } => Ok(deleted),
            other => Err(unexpected("MemoryDeleted", &other)),
        }
    }

    /// Rebuild all of an agent's embeddings with the active embedding model.
    pub async fn memory_reindex(&mut self, agent_id: impl Into<String>) -> Result<usize, SdkError> {
        match self
            .call(Syscall::MemoryReindex {
                agent_id: agent_id.into(),
            })
            .await?
        {
            SyscallReply::MemoryReindexed { count } => Ok(count),
            other => Err(unexpected("MemoryReindexed", &other)),
        }
    }

    /// Put (insert-or-overwrite) a value into an agent's durable key/value store
    /// (the per-agent `agent_kv` table, distinct from long-term memory). `value`
    /// is an opaque string — JSON-encode structured data on the caller side.
    pub async fn storage_put(
        &mut self,
        agent_id: impl Into<String>,
        key: impl Into<String>,
        value: impl Into<String>,
    ) -> Result<(), SdkError> {
        let call = Syscall::StoragePut {
            agent_id: agent_id.into(),
            key: key.into(),
            value: value.into(),
        };
        match self.call(call).await? {
            SyscallReply::StorageOk => Ok(()),
            other => Err(unexpected("StorageOk", &other)),
        }
    }

    /// Get a value from an agent's key/value store. Returns `None` when the key
    /// is absent.
    pub async fn storage_get(
        &mut self,
        agent_id: impl Into<String>,
        key: impl Into<String>,
    ) -> Result<Option<String>, SdkError> {
        let call = Syscall::StorageGet {
            agent_id: agent_id.into(),
            key: key.into(),
        };
        match self.call(call).await? {
            SyscallReply::StorageValue { value } => Ok(value),
            other => Err(unexpected("StorageValue", &other)),
        }
    }

    /// List the keys in an agent's key/value store.
    pub async fn storage_list(
        &mut self,
        agent_id: impl Into<String>,
    ) -> Result<Vec<String>, SdkError> {
        let call = Syscall::StorageList {
            agent_id: agent_id.into(),
        };
        match self.call(call).await? {
            SyscallReply::StorageKeys { keys } => Ok(keys),
            other => Err(unexpected("StorageKeys", &other)),
        }
    }

    /// Inspect an agent's active context budget, durable spill usage, and
    /// fail-closed pressure errors without returning prompt content.
    pub async fn context_pressure(
        &mut self,
        agent_id: impl Into<String>,
    ) -> Result<ContextPressureStats, SdkError> {
        let call = Syscall::ContextPressure {
            agent_id: agent_id.into(),
        };
        match self.call(call).await? {
            SyscallReply::ContextPressure { stats } => Ok(stats),
            other => Err(unexpected("ContextPressure", &other)),
        }
    }

    /// Capture the live, timestamped operations view. Tenant-authenticated
    /// connections receive only tenant-owned agents and omit global counters.
    pub async fn operator_snapshot(&mut self) -> Result<OperatorSnapshot, SdkError> {
        match self.call(Syscall::OperatorSnapshot).await? {
            SyscallReply::OperatorSnapshot { snapshot } => Ok(*snapshot),
            other => Err(unexpected("OperatorSnapshot", &other)),
        }
    }

    pub async fn list_operator_tunables(&mut self) -> Result<Vec<OperatorTunable>, SdkError> {
        match self.call(Syscall::ListOperatorTunables).await? {
            SyscallReply::OperatorTunables { tunables } => Ok(tunables),
            other => Err(unexpected("OperatorTunables", &other)),
        }
    }

    pub async fn set_operator_tunable(
        &mut self,
        name: impl Into<String>,
        value: u64,
        expected_revision: u64,
    ) -> Result<OperatorTunable, SdkError> {
        match self
            .call(Syscall::SetOperatorTunable {
                name: name.into(),
                value,
                expected_revision,
            })
            .await?
        {
            SyscallReply::OperatorTunable { tunable } => Ok(tunable),
            other => Err(unexpected("OperatorTunable", &other)),
        }
    }

    pub async fn rollback_operator_tunable(
        &mut self,
        name: impl Into<String>,
        target_revision: u64,
        expected_revision: u64,
    ) -> Result<OperatorTunable, SdkError> {
        match self
            .call(Syscall::RollbackOperatorTunable {
                name: name.into(),
                target_revision,
                expected_revision,
            })
            .await?
        {
            SyscallReply::OperatorTunable { tunable } => Ok(tunable),
            other => Err(unexpected("OperatorTunable", &other)),
        }
    }

    pub async fn operator_tunable_audit(
        &mut self,
        name: Option<String>,
        limit: usize,
    ) -> Result<Vec<OperatorTunableAudit>, SdkError> {
        match self
            .call(Syscall::ListOperatorTunableAudit { name, limit })
            .await?
        {
            SyscallReply::OperatorTunableAudit { entries } => Ok(entries),
            other => Err(unexpected("OperatorTunableAudit", &other)),
        }
    }

    /// Ask the running kernel to create and atomically publish a verified
    /// online backup on the server host.
    pub async fn create_storage_backup(
        &mut self,
        backup_root: impl Into<String>,
        name: impl Into<String>,
    ) -> Result<BackupManifest, SdkError> {
        match self
            .call(Syscall::CreateStorageBackup {
                backup_root: backup_root.into(),
                name: name.into(),
            })
            .await?
        {
            SyscallReply::StorageBackupCreated { manifest } => Ok(manifest),
            other => Err(unexpected("StorageBackupCreated", &other)),
        }
    }

    /// Preview the verified current-installation backups a retention policy
    /// would expire without deleting anything.
    pub async fn preview_storage_backup_retention(
        &mut self,
        backup_root: impl Into<String>,
        keep_latest: usize,
        max_age_seconds: u64,
    ) -> Result<BackupRetentionReport, SdkError> {
        self.storage_backup_retention(
            backup_root.into(),
            keep_latest,
            max_age_seconds,
            true,
            false,
        )
        .await
    }

    /// Enforce backup retention after explicit typed confirmation.
    pub async fn enforce_storage_backup_retention(
        &mut self,
        backup_root: impl Into<String>,
        keep_latest: usize,
        max_age_seconds: u64,
        _confirmation: ConfirmBackupRetention,
    ) -> Result<BackupRetentionReport, SdkError> {
        self.storage_backup_retention(
            backup_root.into(),
            keep_latest,
            max_age_seconds,
            false,
            true,
        )
        .await
    }

    async fn storage_backup_retention(
        &mut self,
        backup_root: String,
        keep_latest: usize,
        max_age_seconds: u64,
        dry_run: bool,
        confirm: bool,
    ) -> Result<BackupRetentionReport, SdkError> {
        match self
            .call(Syscall::EnforceStorageBackupRetention {
                backup_root,
                keep_latest,
                max_age_seconds,
                dry_run,
                confirm,
            })
            .await?
        {
            SyscallReply::StorageBackupRetention { report } => Ok(report),
            other => Err(unexpected("StorageBackupRetention", &other)),
        }
    }

    /// Read the configured automatic-backup policy and bounded live health.
    pub async fn storage_backup_status(
        &mut self,
    ) -> Result<kernel::storage::BackupMaintenanceStatus, SdkError> {
        match self.call(Syscall::StorageBackupStatus).await? {
            SyscallReply::StorageBackupStatus { maintenance } => Ok(maintenance),
            other => Err(unexpected("StorageBackupStatus", &other)),
        }
    }

    /// Read the versioned, non-secret policy inventory for every supported
    /// durable, ephemeral, and external data boundary.
    pub async fn storage_data_inventory(&mut self) -> Result<StorageDataInventory, SdkError> {
        match self.call(Syscall::StorageDataInventory).await? {
            SyscallReply::StorageDataInventory { inventory } => Ok(inventory),
            other => Err(unexpected("StorageDataInventory", &other)),
        }
    }

    /// Irreversibly erase one agent after the kernel drains its tenant requests
    /// and live runtime resources.
    pub async fn erase_agent_data(
        &mut self,
        agent_id: uuid::Uuid,
        _confirmation: ConfirmDataErasure,
    ) -> Result<Option<DeletionReceipt>, SdkError> {
        self.erase_data(DataErasureTarget::Agent {
            agent_id: agent_id.to_string(),
        })
        .await
    }

    /// Irreversibly erase one user identity and every credential after its
    /// already-admitted requests drain.
    pub async fn erase_user_data(
        &mut self,
        user_id: impl Into<String>,
        _confirmation: ConfirmDataErasure,
    ) -> Result<Option<DeletionReceipt>, SdkError> {
        self.erase_data(DataErasureTarget::User {
            user_id: user_id.into(),
        })
        .await
    }

    /// Irreversibly erase a tenant, its credentials, services' live owners,
    /// agents, and all classified tenant-owned durable state.
    pub async fn erase_tenant_data(
        &mut self,
        tenant_id: impl Into<String>,
        _confirmation: ConfirmDataErasure,
    ) -> Result<Option<DeletionReceipt>, SdkError> {
        self.erase_data(DataErasureTarget::Tenant {
            tenant_id: tenant_id.into(),
        })
        .await
    }

    async fn erase_data(
        &mut self,
        target: DataErasureTarget,
    ) -> Result<Option<DeletionReceipt>, SdkError> {
        match self
            .call(Syscall::EraseData {
                target,
                confirm: true,
            })
            .await?
        {
            SyscallReply::DataErased { receipt } => Ok(receipt),
            other => Err(unexpected("DataErased", &other)),
        }
    }

    pub async fn list_services(&mut self) -> Result<Vec<ServiceRuntimeInfo>, SdkError> {
        match self.call(Syscall::ListServices).await? {
            SyscallReply::Services { services } => Ok(services),
            other => Err(unexpected("Services", &other)),
        }
    }

    pub async fn start_service(
        &mut self,
        name: impl Into<String>,
    ) -> Result<ServiceRuntimeInfo, SdkError> {
        match self
            .call(Syscall::StartService { name: name.into() })
            .await?
        {
            SyscallReply::Service { service } => Ok(service),
            other => Err(unexpected("Service", &other)),
        }
    }

    pub async fn stop_service(
        &mut self,
        name: impl Into<String>,
    ) -> Result<ServiceRuntimeInfo, SdkError> {
        match self
            .call(Syscall::StopService { name: name.into() })
            .await?
        {
            SyscallReply::Service { service } => Ok(service),
            other => Err(unexpected("Service", &other)),
        }
    }

    pub async fn restart_service(
        &mut self,
        name: impl Into<String>,
    ) -> Result<ServiceRuntimeInfo, SdkError> {
        match self
            .call(Syscall::RestartService { name: name.into() })
            .await?
        {
            SyscallReply::Service { service } => Ok(service),
            other => Err(unexpected("Service", &other)),
        }
    }

    pub async fn reload_services(&mut self) -> Result<Vec<String>, SdkError> {
        match self.call(Syscall::ReloadServices).await? {
            SyscallReply::ServiceConfigurationReloaded { boot_order } => Ok(boot_order),
            other => Err(unexpected("ServiceConfigurationReloaded", &other)),
        }
    }

    pub async fn service_history(
        &mut self,
        name: Option<String>,
        limit: usize,
    ) -> Result<Vec<ServiceHistoryEntry>, SdkError> {
        match self
            .call(Syscall::ListServiceHistory { name, limit })
            .await?
        {
            SyscallReply::ServiceHistory { entries } => Ok(entries),
            other => Err(unexpected("ServiceHistory", &other)),
        }
    }

    /// Delete a key from an agent's key/value store. Returns `true` if the key
    /// existed, `false` otherwise.
    pub async fn storage_delete(
        &mut self,
        agent_id: impl Into<String>,
        key: impl Into<String>,
    ) -> Result<bool, SdkError> {
        let call = Syscall::StorageDelete {
            agent_id: agent_id.into(),
            key: key.into(),
        };
        match self.call(call).await? {
            SyscallReply::StorageDeleted { existed } => Ok(existed),
            other => Err(unexpected("StorageDeleted", &other)),
        }
    }

    /// Capture an agent's current working context under `label` (a point-in-time
    /// snapshot). Overwrites an existing snapshot with the same label.
    pub async fn snapshot_context(
        &mut self,
        agent_id: impl Into<String>,
        label: impl Into<String>,
    ) -> Result<(), SdkError> {
        let call = Syscall::SnapshotContext {
            agent_id: agent_id.into(),
            label: label.into(),
        };
        match self.call(call).await? {
            SyscallReply::SnapshotSaved => Ok(()),
            other => Err(unexpected("SnapshotSaved", &other)),
        }
    }

    /// Restore a previously captured snapshot, making it the agent's current
    /// context. Returns the restored context's token count.
    pub async fn restore_snapshot(
        &mut self,
        agent_id: impl Into<String>,
        label: impl Into<String>,
    ) -> Result<u32, SdkError> {
        let call = Syscall::RestoreSnapshot {
            agent_id: agent_id.into(),
            label: label.into(),
        };
        match self.call(call).await? {
            SyscallReply::SnapshotRestored { tokens } => Ok(tokens),
            other => Err(unexpected("SnapshotRestored", &other)),
        }
    }

    /// List the snapshot labels stored for an agent, newest first.
    pub async fn list_snapshots(
        &mut self,
        agent_id: impl Into<String>,
    ) -> Result<Vec<String>, SdkError> {
        let call = Syscall::ListSnapshots {
            agent_id: agent_id.into(),
        };
        match self.call(call).await? {
            SyscallReply::Snapshots { labels } => Ok(labels),
            other => Err(unexpected("Snapshots", &other)),
        }
    }

    /// Delete a snapshot by label. Returns `true` if the snapshot existed,
    /// `false` otherwise.
    pub async fn delete_snapshot(
        &mut self,
        agent_id: impl Into<String>,
        label: impl Into<String>,
    ) -> Result<bool, SdkError> {
        let call = Syscall::DeleteSnapshot {
            agent_id: agent_id.into(),
            label: label.into(),
        };
        match self.call(call).await? {
            SyscallReply::SnapshotDeleted { existed } => Ok(existed),
            other => Err(unexpected("SnapshotDeleted", &other)),
        }
    }

    /// Load an agent package from a TOML manifest. The kernel parses and
    /// validates it, then creates the agent through the full admission path and
    /// seeds its memory. Returns the new agent's id.
    pub async fn load_package(
        &mut self,
        manifest_toml: impl Into<String>,
    ) -> Result<String, SdkError> {
        let call = Syscall::LoadPackage {
            manifest_toml: manifest_toml.into(),
        };
        match self.call(call).await? {
            SyscallReply::AgentCreated { id } => Ok(id),
            other => Err(unexpected("AgentCreated", &other)),
        }
    }

    /// Add or rotate an Ed25519 package trust root in this connection's tenant.
    #[allow(clippy::too_many_arguments)]
    pub async fn trust_package_key(
        &mut self,
        publisher: impl Into<String>,
        key_id: impl Into<String>,
        public_key: &[u8],
        valid_from: impl Into<String>,
        valid_until: Option<String>,
        supersedes: Option<String>,
    ) -> Result<(), SdkError> {
        let call = Syscall::TrustPackageKey {
            publisher: publisher.into(),
            key_id: key_id.into(),
            public_key_hex: kernel::package::archive_to_hex(public_key),
            valid_from: valid_from.into(),
            valid_until,
            supersedes,
        };
        match self.call(call).await? {
            SyscallReply::PackageKeyUpdated => Ok(()),
            other => Err(unexpected("PackageKeyUpdated", &other)),
        }
    }

    /// Revoke a package publisher key for this tenant.
    pub async fn revoke_package_key(&mut self, key_id: impl Into<String>) -> Result<(), SdkError> {
        match self
            .call(Syscall::RevokePackageKey {
                key_id: key_id.into(),
            })
            .await?
        {
            SyscallReply::PackageKeyUpdated => Ok(()),
            other => Err(unexpected("PackageKeyUpdated", &other)),
        }
    }

    /// Publish a signed `.agent` archive.
    pub async fn publish_package(&mut self, archive: &[u8]) -> Result<PackageSummary, SdkError> {
        match self
            .call(Syscall::PublishPackage {
                archive_hex: kernel::package::archive_to_hex(archive),
            })
            .await?
        {
            SyscallReply::PackagePublished { package } => Ok(package),
            other => Err(unexpected("PackagePublished", &other)),
        }
    }

    /// Yank a package version from future fetch and dependency resolution.
    pub async fn yank_package(
        &mut self,
        name: impl Into<String>,
        version: impl Into<String>,
    ) -> Result<(), SdkError> {
        match self
            .call(Syscall::YankPackage {
                name: name.into(),
                version: version.into(),
            })
            .await?
        {
            SyscallReply::PackageMutationComplete => Ok(()),
            other => Err(unexpected("PackageMutationComplete", &other)),
        }
    }

    /// Fetch and re-verify a non-yanked package archive.
    pub async fn fetch_package(
        &mut self,
        name: impl Into<String>,
        version: impl Into<String>,
    ) -> Result<Vec<u8>, SdkError> {
        match self
            .call(Syscall::FetchPackage {
                name: name.into(),
                version: version.into(),
            })
            .await?
        {
            SyscallReply::PackageArchive { archive_hex } => {
                kernel::package::archive_from_hex(&archive_hex)
                    .map_err(|error| SdkError::Kernel(error.to_string()))
            }
            other => Err(unexpected("PackageArchive", &other)),
        }
    }

    /// Search signed package metadata inside the authenticated tenant.
    pub async fn search_packages(
        &mut self,
        query: impl Into<String>,
    ) -> Result<Vec<PackageSummary>, SdkError> {
        match self
            .call(Syscall::SearchPackages {
                query: query.into(),
            })
            .await?
        {
            SyscallReply::Packages { packages } => Ok(packages),
            other => Err(unexpected("Packages", &other)),
        }
    }

    /// Resolve and atomically install or upgrade a package.
    pub async fn install_package(
        &mut self,
        name: impl Into<String>,
        requirement: impl Into<String>,
    ) -> Result<InstalledPackage, SdkError> {
        match self
            .call(Syscall::InstallPackage {
                name: name.into(),
                requirement: requirement.into(),
            })
            .await?
        {
            SyscallReply::PackageInstalled { package } => Ok(package),
            other => Err(unexpected("PackageInstalled", &other)),
        }
    }

    /// Roll an installed package back to its previous committed version.
    pub async fn rollback_package(
        &mut self,
        name: impl Into<String>,
    ) -> Result<InstalledPackage, SdkError> {
        match self
            .call(Syscall::RollbackPackage { name: name.into() })
            .await?
        {
            SyscallReply::PackageInstalled { package } => Ok(package),
            other => Err(unexpected("PackageInstalled", &other)),
        }
    }

    /// Remove an installed package if it has no installed dependents.
    pub async fn remove_package(&mut self, name: impl Into<String>) -> Result<(), SdkError> {
        match self
            .call(Syscall::RemovePackage { name: name.into() })
            .await?
        {
            SyscallReply::PackageMutationComplete => Ok(()),
            other => Err(unexpected("PackageMutationComplete", &other)),
        }
    }

    /// List exact installed versions and lockfile digests.
    pub async fn list_installed_packages(&mut self) -> Result<Vec<InstalledPackage>, SdkError> {
        match self.call(Syscall::ListInstalledPackages).await? {
            SyscallReply::InstalledPackages { packages } => Ok(packages),
            other => Err(unexpected("InstalledPackages", &other)),
        }
    }

    /// Re-verify and load an installed package as a tenant-owned agent.
    pub async fn run_installed_package(
        &mut self,
        name: impl Into<String>,
    ) -> Result<String, SdkError> {
        match self
            .call(Syscall::RunInstalledPackage { name: name.into() })
            .await?
        {
            SyscallReply::AgentCreated { id } => Ok(id),
            other => Err(unexpected("AgentCreated", &other)),
        }
    }

    /// Authenticate the connection with the server's shared secret. Required
    /// before any other syscall when the server is configured with a token.
    pub async fn authenticate(&mut self, token: impl Into<String>) -> Result<(), SdkError> {
        let token = token.into();
        match self
            .call(Syscall::Authenticate {
                token: token.clone(),
            })
            .await?
        {
            SyscallReply::Authenticated => {
                if let Some(reconnect) = self.reconnect.as_mut() {
                    reconnect.token = Some(token);
                }
                Ok(())
            }
            other => Err(unexpected("Authenticated", &other)),
        }
    }

    /// Gracefully close this idle client connection.
    ///
    /// The method consumes the client, half-closes its output, and waits for
    /// bounded peer EOF. Finish every request or message stream before calling
    /// it; an unread frame is reported as a transport error.
    pub async fn close(self) -> Result<(), SdkError> {
        self.inner.close().await?;
        Ok(())
    }

    /// Issue a raw syscall and fold [`SyscallReply::Error`] into [`SdkError`].
    /// Lower-level escape hatch behind every typed method above.
    pub async fn call(&mut self, call: Syscall) -> Result<SyscallReply, SdkError> {
        self.ensure_connected().await?;
        let replay_safe = safe_to_replay_after_reconnect(&call);
        let operation = mutation_operation_name(&call);
        let reply = match self.inner.call(call.clone()).await {
            Ok(reply) => reply,
            Err(source) if self.reconnect.is_none() => return Err(SdkError::Transport(source)),
            Err(source) if !replay_safe => {
                self.needs_reconnect = true;
                return Err(SdkError::IndeterminateMutation { operation, source });
            }
            Err(_) => {
                self.needs_reconnect = true;
                self.reconnect().await?;
                match self.inner.call(call).await {
                    Ok(reply) => reply,
                    Err(source) => {
                        self.needs_reconnect = true;
                        return Err(SdkError::Transport(source));
                    }
                }
            }
        };
        match reply {
            SyscallReply::Error { message } => Err(SdkError::Kernel(message)),
            SyscallReply::TypedError {
                code,
                message,
                retryable,
            } => Err(SdkError::Wire {
                code,
                message,
                retryable,
            }),
            reply => Ok(reply),
        }
    }
}

fn safe_to_replay_after_reconnect(call: &Syscall) -> bool {
    matches!(
        call,
        Syscall::ListAgents
            | Syscall::GetAgentStatus { .. }
            | Syscall::WaitAgent { .. }
            | Syscall::ListGenerationCheckpoints { .. }
            | Syscall::GateStats
            | Syscall::AgentInfo { .. }
            | Syscall::ListProviders
            | Syscall::MemoryQuery { .. }
            | Syscall::StorageGet { .. }
            | Syscall::StorageList { .. }
            | Syscall::ContextPressure { .. }
            | Syscall::ListSnapshots { .. }
            | Syscall::Hello { .. }
            | Syscall::Authenticate { .. }
            | Syscall::DescribeProtocol
            | Syscall::Ping
            | Syscall::FetchPackage { .. }
            | Syscall::SearchPackages { .. }
            | Syscall::ListInstalledPackages
            | Syscall::NodeInfo
            | Syscall::ProveNodeIdentity { .. }
            | Syscall::ListNodeControlAudit { .. }
            | Syscall::GetClusterMembership
            | Syscall::ListClusterMembershipAudit { .. }
            | Syscall::Metrics
            | Syscall::OperatorSnapshot
            | Syscall::ListOperatorTunables
            | Syscall::ListOperatorTunableAudit { .. }
            | Syscall::StorageBackupStatus
            | Syscall::StorageDataInventory
            | Syscall::ListServices
            | Syscall::ListServiceHistory { .. }
            | Syscall::EnforceStorageBackupRetention { dry_run: true, .. }
    )
}

fn mutation_operation_name(call: &Syscall) -> &'static str {
    match call {
        Syscall::InstallPackage { .. } => "package installation",
        Syscall::RollbackPackage { .. } => "package rollback",
        Syscall::RemovePackage { .. } => "package removal",
        Syscall::PauseAgent { .. } => "agent pause",
        Syscall::ResumeAgent { .. } => "agent resume",
        Syscall::StopAgent { .. } => "agent stop",
        Syscall::KillAgent { .. } => "agent kill",
        Syscall::CallTool { .. } => "tool call",
        Syscall::SendMessage { .. } | Syscall::SendMessageStream { .. } => "agent turn",
        _ => "side-effecting syscall",
    }
}

fn unexpected(expected: &'static str, got: &SyscallReply) -> SdkError {
    SdkError::UnexpectedReply {
        expected,
        got: format!("{got:?}"),
    }
}

/// Builder for an [`Agent`]. Obtain one with [`Agent::builder`].
///
/// `name` and `task` are required; `provider` / `profile` / `priority` fall back
/// to the kernel wire defaults (`"stub"` / `"standard"` / `3`) when unset.
#[derive(Debug, Default, Clone)]
pub struct AgentBuilder {
    name: Option<String>,
    task: Option<String>,
    provider: Option<String>,
    profile: Option<String>,
    priority: Option<u8>,
}

impl AgentBuilder {
    /// Set the agent's name (required).
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Set the agent's task / system prompt (required).
    pub fn task(mut self, task: impl Into<String>) -> Self {
        self.task = Some(task.into());
        self
    }

    /// Set the LLM provider (defaults to `"stub"`).
    pub fn provider(mut self, provider: impl Into<String>) -> Self {
        self.provider = Some(provider.into());
        self
    }

    /// Set the permission profile (defaults to `"standard"`). Determines the
    /// agent's capabilities at the syscall gate (e.g. `"read-only"`).
    pub fn profile(mut self, profile: impl Into<String>) -> Self {
        self.profile = Some(profile.into());
        self
    }

    /// Set the scheduling priority 0..=5 (defaults to `3`).
    pub fn priority(mut self, priority: u8) -> Self {
        self.priority = Some(priority);
        self
    }

    /// Connect to the syscall server at `addr`, create the agent, and return a
    /// live [`Agent`] handle.
    ///
    /// # Errors
    /// Returns [`SdkError::Kernel`] with `"name and task are required"` if either
    /// required field is unset, or any transport / kernel error from creation.
    pub async fn connect(self, addr: impl ToSocketAddrs) -> Result<Agent, SdkError> {
        let client = KernelClient::connect(addr).await?;
        self.create_with(client).await
    }

    /// Create the agent over an already-connected [`KernelClient`], returning a
    /// live [`Agent`] handle that owns the client.
    pub async fn create_with(self, mut client: KernelClient) -> Result<Agent, SdkError> {
        let (name, task) = match (self.name, self.task) {
            (Some(name), Some(task)) => (name, task),
            _ => return Err(SdkError::Kernel("name and task are required".to_string())),
        };
        let id = client
            .create_agent(name, task, self.provider, self.profile, self.priority)
            .await?;
        Ok(Agent { id, client })
    }
}

/// A live agent handle bound to a kernel connection.
///
/// Created via [`Agent::builder`]. Owns its [`KernelClient`], so calls are
/// serialized over the single connection; create a second handle for
/// concurrency.
pub struct Agent {
    id: String,
    client: KernelClient,
}

impl Agent {
    /// Start building an agent.
    pub fn builder() -> AgentBuilder {
        AgentBuilder::default()
    }

    /// This agent's kernel id (a UUID string).
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Borrow the underlying typed client for syscalls not specific to this
    /// agent (e.g. [`KernelClient::gate_stats`] / [`KernelClient::list_agents`]).
    pub fn client(&mut self) -> &mut KernelClient {
        &mut self.client
    }

    /// Drive one think→act→observe turn for this agent.
    pub async fn send(&mut self, message: impl Into<String>) -> Result<MessageResult, SdkError> {
        let id = self.id.clone();
        self.client.send_message(id, message).await
    }

    /// Drive one turn with ordered stream events. Use a second
    /// [`KernelClient`] to cancel by `request_id` while this call owns the
    /// agent's connection.
    pub async fn send_stream<F>(
        &mut self,
        request_id: impl Into<String>,
        message: impl Into<String>,
        on_event: F,
    ) -> Result<MessageResult, SdkError>
    where
        F: FnMut(&MessageStreamEvent),
    {
        self.client
            .send_message_stream(request_id, self.id.clone(), message, on_event)
            .await
    }

    /// Invoke a tool as this agent (subject to the kernel's syscall gate).
    pub async fn call_tool(
        &mut self,
        tool: impl Into<String>,
        args: serde_json::Value,
    ) -> Result<serde_json::Value, SdkError> {
        let id = self.id.clone();
        self.client.call_tool(id, tool, args).await
    }

    /// Pause this agent and cooperatively cancel an active turn.
    pub async fn pause(&mut self) -> Result<String, SdkError> {
        self.client.pause_agent(self.id.clone()).await
    }

    /// Resume this agent after a pause.
    pub async fn resume(&mut self) -> Result<String, SdkError> {
        self.client.resume_agent(self.id.clone()).await
    }

    /// Gracefully stop this agent.
    pub async fn stop(&mut self) -> Result<String, SdkError> {
        self.client.stop_agent(self.id.clone()).await
    }

    /// Force this agent into the terminal state.
    pub async fn kill(&mut self) -> Result<String, SdkError> {
        self.client.kill_agent(self.id.clone()).await
    }

    /// Return this agent's current lifecycle state.
    pub async fn status(&mut self) -> Result<String, SdkError> {
        self.client.agent_status(self.id.clone()).await
    }

    /// Wait for this agent to become terminal.
    pub async fn wait(&mut self, timeout: std::time::Duration) -> Result<String, SdkError> {
        self.client.wait_agent(self.id.clone(), timeout).await
    }
}

#[cfg(test)]
mod protocol_tests {
    use super::*;
    use async_trait::async_trait;
    use kernel::connector::{
        LlmProviderAdapter, LlmResponse, LlmSession, ProviderCapabilities, ProviderType,
        StandardMessage, ToolDefinition,
    };
    use kernel::syscall_server::SyscallServer;
    use kernel::{AgentKernelImpl, ConnectorError};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    struct PausableAdapter {
        id: String,
        calls: Arc<AtomicUsize>,
        started: Arc<tokio::sync::Notify>,
    }

    struct PausableSession {
        id: String,
        calls: Arc<AtomicUsize>,
        started: Arc<tokio::sync::Notify>,
    }

    #[async_trait]
    impl LlmSession for PausableSession {
        async fn send(
            &self,
            messages: Vec<StandardMessage>,
        ) -> Result<LlmResponse, ConnectorError> {
            self.send_with_tools(messages, &[]).await
        }

        async fn send_with_tools(
            &self,
            _messages: Vec<StandardMessage>,
            _tools: &[ToolDefinition],
        ) -> Result<LlmResponse, ConnectorError> {
            if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
                self.started.notify_waiters();
                std::future::pending::<()>().await;
            }
            Ok(LlmResponse {
                content: "wire resume complete".into(),
                finish_reason: Some("stop".into()),
                tokens_used: 5,
                usage: kernel::connector::LlmUsage::reported(3, 2, 0),
                tool_calls: Vec::new(),
            })
        }

        async fn send_with_options(
            &self,
            messages: Vec<StandardMessage>,
            tools: &[ToolDefinition],
            options: kernel::connector::LlmRequestOptions,
        ) -> Result<LlmResponse, ConnectorError> {
            assert!(
                options.max_output_tokens.is_some_and(|limit| limit > 0),
                "production kernel execution must forward a positive output bound"
            );
            self.send_with_tools(messages, tools).await
        }

        fn provider_id(&self) -> &String {
            &self.id
        }

        fn model_id(&self) -> &str {
            "wire-checkpoint-model"
        }

        fn enforces_max_output_tokens(&self) -> bool {
            true
        }
    }

    #[async_trait]
    impl LlmProviderAdapter for PausableAdapter {
        fn id(&self) -> &String {
            &self.id
        }
        fn name(&self) -> &str {
            "pausable"
        }
        fn provider_type(&self) -> ProviderType {
            ProviderType::Cloud
        }
        async fn is_available(&self) -> bool {
            true
        }
        async fn create_session(&self) -> Result<Box<dyn LlmSession>, ConnectorError> {
            Ok(Box::new(PausableSession {
                id: self.id.clone(),
                calls: Arc::clone(&self.calls),
                started: Arc::clone(&self.started),
            }))
        }
        fn capabilities(&self) -> ProviderCapabilities {
            ProviderCapabilities {
                tool_calls: true,
                prompt_cancellation: true,
                ..ProviderCapabilities::default()
            }
        }
        fn translate_to_provider(&self, message: &StandardMessage) -> serde_json::Value {
            serde_json::json!({"role": message.role, "content": message.content})
        }
        fn translate_from_provider(&self, value: &serde_json::Value) -> Option<StandardMessage> {
            Some(StandardMessage::assistant(value.get("content")?.as_str()?))
        }
    }

    pub(super) async fn assert_public_lifecycle_contract(client: &mut KernelClient, prefix: &str) {
        fn assert_kernel_error(error: SdkError, expected: &str) {
            let message = error.kernel_message().unwrap_or_else(|| {
                panic!("expected kernel error containing {expected:?}, got {error:?}")
            });
            assert!(
                message.contains(expected),
                "expected kernel error containing {expected:?}, got {message:?}"
            );
        }

        // Running, Paused, and Stopped are the stable states exposed by the
        // public protocol. Exercise every valid operation/state pairing plus
        // the invalid terminal transitions over the caller's real transport.
        let paused_stop = client
            .create_agent(
                format!("{prefix}-paused-stop"),
                "public lifecycle matrix",
                None,
                None,
                None,
            )
            .await
            .unwrap();
        assert_eq!(
            client.agent_status(paused_stop.clone()).await.unwrap(),
            "Running"
        );
        assert_eq!(
            client.resume_agent(paused_stop.clone()).await.unwrap(),
            "Running"
        );
        assert_kernel_error(
            client
                .wait_agent(paused_stop.clone(), std::time::Duration::from_millis(20))
                .await
                .unwrap_err(),
            "timed out",
        );
        assert_eq!(
            client.pause_agent(paused_stop.clone()).await.unwrap(),
            "Paused"
        );
        assert_eq!(
            client.agent_status(paused_stop.clone()).await.unwrap(),
            "Paused"
        );
        assert_eq!(
            client.pause_agent(paused_stop.clone()).await.unwrap(),
            "Paused"
        );
        assert!(client
            .send_message(paused_stop.clone(), "must not run while paused")
            .await
            .is_err());
        assert_eq!(
            client.resume_agent(paused_stop.clone()).await.unwrap(),
            "Running"
        );
        assert_eq!(
            client.pause_agent(paused_stop.clone()).await.unwrap(),
            "Paused"
        );
        assert_eq!(
            client.stop_agent(paused_stop.clone()).await.unwrap(),
            "Stopped"
        );
        assert_eq!(
            client.stop_agent(paused_stop.clone()).await.unwrap(),
            "Stopped"
        );
        assert_eq!(
            client.kill_agent(paused_stop.clone()).await.unwrap(),
            "Stopped"
        );
        assert_eq!(
            client
                .wait_agent(paused_stop.clone(), std::time::Duration::from_secs(1),)
                .await
                .unwrap(),
            "Stopped"
        );
        assert_kernel_error(
            client.pause_agent(paused_stop.clone()).await.unwrap_err(),
            "Invalid state transition",
        );
        assert_kernel_error(
            client.resume_agent(paused_stop.clone()).await.unwrap_err(),
            "Invalid state transition",
        );
        assert!(client
            .send_message(paused_stop, "must not run after stop")
            .await
            .is_err());

        let running_stop = client
            .create_agent(
                format!("{prefix}-running-stop"),
                "stop from running",
                None,
                None,
                None,
            )
            .await
            .unwrap();
        assert_eq!(client.stop_agent(running_stop).await.unwrap(), "Stopped");

        let running_kill = client
            .create_agent(
                format!("{prefix}-running-kill"),
                "kill from running",
                None,
                None,
                None,
            )
            .await
            .unwrap();
        assert_eq!(client.kill_agent(running_kill).await.unwrap(), "Stopped");

        let paused_kill = client
            .create_agent(
                format!("{prefix}-paused-kill"),
                "kill from paused",
                None,
                None,
                None,
            )
            .await
            .unwrap();
        assert_eq!(
            client.pause_agent(paused_kill.clone()).await.unwrap(),
            "Paused"
        );
        assert_eq!(client.kill_agent(paused_kill).await.unwrap(), "Stopped");
    }

    /// `hello()` negotiates against a current server and returns its window.
    #[tokio::test]
    async fn sdk_hello_negotiates_current_server() {
        let kernel = Arc::new(AgentKernelImpl::new().expect("kernel new"));
        let server = SyscallServer::bind(kernel, "127.0.0.1:0").await.unwrap();
        let addr = server.local_addr().unwrap();
        tokio::spawn(server.serve());

        let mut client = KernelClient::connect(addr).await.expect("connect");
        let info = client.hello().await.expect("hello should negotiate");
        assert_eq!(info.protocol_version, PROTOCOL_VERSION);
        assert!(info.min_protocol_version <= PROTOCOL_VERSION);
        assert!(!info.server_version.is_empty());
    }

    #[tokio::test]
    async fn sdk_lifecycle_roundtrip_is_typed_idempotent_and_terminal() {
        let kernel = Arc::new(AgentKernelImpl::new().expect("kernel new"));
        let server = SyscallServer::bind(kernel, "127.0.0.1:0").await.unwrap();
        let addr = server.local_addr().unwrap();
        tokio::spawn(server.serve());

        let mut client = KernelClient::connect(addr).await.expect("connect");
        assert_public_lifecycle_contract(&mut client, "tcp").await;
    }

    #[tokio::test]
    async fn sdk_context_pressure_inspection_is_typed_and_content_free() {
        let kernel = Arc::new(AgentKernelImpl::new().expect("kernel new"));
        let server = SyscallServer::bind(Arc::clone(&kernel), "127.0.0.1:0")
            .await
            .unwrap();
        let addr = server.local_addr().unwrap();
        tokio::spawn(server.serve());

        let mut client = KernelClient::connect(addr).await.expect("connect");
        let id = client
            .create_agent("pressure-sdk", "inspect pressure", None, None, None)
            .await
            .unwrap();
        let uuid = id.parse::<kernel::AgentId>().unwrap();
        kernel
            .context_manager
            .store_context_spill(
                uuid,
                "context_spill:test:1",
                "sensitive prompt content",
                "d53a2e0e81dc3fddd58698ee6aaa79e0e885f0e52d510b91ecd127ddc91e1058",
            )
            .unwrap();
        kernel
            .context_manager
            .record_context_pressure(uuid, 80, 100, 4, None)
            .unwrap();

        let stats = client.context_pressure(id).await.unwrap();
        assert_eq!(stats.active_tokens, 80);
        assert_eq!(stats.budget_tokens, 100);
        assert_eq!(stats.evicted_messages, 4);
        assert_eq!(stats.stored_spills, 1);
        assert_eq!(stats.stored_spill_bytes, 24);
        let encoded = serde_json::to_string(&stats).unwrap();
        assert!(!encoded.contains("sensitive prompt content"));

        let operations = client.operator_snapshot().await.unwrap();
        assert_eq!(operations.scope, "system");
        assert!(operations
            .agents
            .iter()
            .any(|agent| agent.id == uuid.to_string()));
        assert!(operations.system_metrics.is_some());
        assert!(!serde_json::to_string(&operations)
            .unwrap()
            .contains("sensitive prompt content"));
    }

    #[tokio::test]
    async fn sdk_memory_lifecycle_roundtrip_is_typed() {
        let kernel = Arc::new(AgentKernelImpl::new().expect("kernel new"));
        let server = SyscallServer::bind(kernel, "127.0.0.1:0").await.unwrap();
        let address = server.local_addr().unwrap();
        tokio::spawn(server.serve());
        let mut client = KernelClient::connect(address).await.unwrap();
        let agent_id = client
            .create_agent("sdk-memory", "remember", None, None, None)
            .await
            .unwrap();

        let fact_id = client
            .memory_store(
                agent_id.clone(),
                "deploy key is in staging",
                Some("instruction".into()),
            )
            .await
            .unwrap();
        assert!(client
            .memory_update(
                agent_id.clone(),
                fact_id.clone(),
                "production deploy key is in vault",
            )
            .await
            .unwrap());
        assert_eq!(client.memory_reindex(agent_id.clone()).await.unwrap(), 1);
        let facts = client
            .memory_query(agent_id.clone(), "production deploy key")
            .await
            .unwrap();
        assert_eq!(facts.len(), 1);
        assert_eq!(facts[0].id, fact_id);
        assert!(client
            .memory_delete(agent_id.clone(), fact_id)
            .await
            .unwrap());
        assert!(client
            .memory_query(agent_id, "production deploy key")
            .await
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    async fn sdk_service_supervisor_uses_public_coordinated_lifecycle() {
        use kernel::init_system::ServiceStatus;

        let kernel = Arc::new(AgentKernelImpl::new().expect("kernel new"));
        let directory =
            std::env::temp_dir().join(format!("agentos-sdk-service-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&directory).unwrap();
        let definition_path = directory.join("public-service.toml");
        std::fs::write(
            &definition_path,
            "name = \"public-service\"\ndescription = \"public service test\"\n\
             [exec]\nprovider = \"stub\"\nsystem_prompt = \"run\"\n",
        )
        .unwrap();
        kernel.reload_service_directory(&directory).await.unwrap();
        let server = SyscallServer::bind(Arc::clone(&kernel), "127.0.0.1:0")
            .await
            .unwrap();
        let addr = server.local_addr().unwrap();
        tokio::spawn(server.serve());
        let mut client = KernelClient::connect(addr).await.unwrap();

        assert_eq!(client.list_services().await.unwrap().len(), 1);
        let started = client.start_service("public-service").await.unwrap();
        assert_eq!(started.status, ServiceStatus::Running);
        let first_agent = started.agent_id.unwrap();

        std::fs::write(
            &definition_path,
            "name = \"public-service\"\ndescription = \"reloaded public service\"\n\
             [exec]\nprovider = \"stub\"\nsystem_prompt = \"run\"\n",
        )
        .unwrap();
        assert_eq!(
            client.reload_services().await.unwrap(),
            vec!["public-service"]
        );
        let reloaded = client.list_services().await.unwrap().remove(0);
        assert_ne!(reloaded.agent_id, Some(first_agent));
        let reloaded_agent = reloaded.agent_id.unwrap();
        assert_eq!(
            client.agent_status(first_agent.to_string()).await.unwrap(),
            "Stopped"
        );

        let restarted = client.restart_service("public-service").await.unwrap();
        assert_eq!(restarted.status, ServiceStatus::Running);
        assert_ne!(restarted.agent_id, Some(reloaded_agent));
        assert_eq!(
            client
                .agent_status(reloaded_agent.to_string())
                .await
                .unwrap(),
            "Stopped"
        );

        let stopped = client.stop_service("public-service").await.unwrap();
        assert_eq!(stopped.status, ServiceStatus::Inactive);
        assert!(stopped.agent_id.is_none());
        let history = client
            .service_history(Some("public-service".into()), 100)
            .await
            .unwrap();
        assert!(history.iter().any(|entry| entry.event == "ready"));
        assert!(history.iter().any(|entry| entry.event == "manual_restart"));
        assert!(history
            .iter()
            .any(|entry| entry.event == "configuration_reloaded"));
        assert!(history.iter().any(|entry| entry.event == "stopped"));
        let _ = std::fs::remove_dir_all(directory);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn sdk_public_pause_returns_durable_id_and_resume_returns_output() {
        let kernel = Arc::new(AgentKernelImpl::new().expect("kernel new"));
        let calls = Arc::new(AtomicUsize::new(0));
        let started = Arc::new(tokio::sync::Notify::new());
        kernel
            .register_provider(Arc::new(PausableAdapter {
                id: "wire-checkpoint".into(),
                calls: Arc::clone(&calls),
                started: Arc::clone(&started),
            }))
            .unwrap();
        let server = SyscallServer::bind(Arc::clone(&kernel), "127.0.0.1:0")
            .await
            .unwrap();
        let addr = server.local_addr().unwrap();
        tokio::spawn(server.serve());

        let mut control = KernelClient::connect(addr).await.unwrap();
        let provider = control
            .list_providers()
            .await
            .unwrap()
            .into_iter()
            .find(|provider| provider.id == "wire-checkpoint")
            .expect("registered provider is publicly discoverable");
        assert!(provider.capabilities.tool_calls);
        assert!(provider.capabilities.prompt_cancellation);
        assert!(!provider.circuit_open);
        let id = control
            .create_agent(
                "public-checkpoint",
                "pause me",
                Some("wire-checkpoint".into()),
                None,
                None,
            )
            .await
            .unwrap();
        let mut sender = KernelClient::connect(addr).await.unwrap();
        let started_wait = started.notified();
        let sending_id = id.clone();
        let sending =
            tokio::spawn(
                async move { sender.send_message(sending_id, "long hosted request").await },
            );
        started_wait.await;

        let paused = control.pause_agent_durable(id.clone()).await.unwrap();
        let checkpoint_id = paused.checkpoint_id.expect("public checkpoint id");
        assert_eq!(paused.state, "Paused");
        assert!(sending
            .await
            .unwrap()
            .unwrap()
            .content
            .contains(&checkpoint_id));
        assert_eq!(
            control
                .list_generation_checkpoints(id.clone())
                .await
                .unwrap()
                .len(),
            1
        );

        let resumed = control
            .resume_generation_checkpoint(id.clone(), checkpoint_id.clone())
            .await
            .unwrap();
        assert_eq!(resumed.state, "Running");
        assert_eq!(
            resumed.resumed_content.as_deref(),
            Some("wire resume complete")
        );
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert!(control
            .list_generation_checkpoints(id.clone())
            .await
            .unwrap()
            .is_empty());
        assert!(control
            .delete_generation_checkpoint(id, checkpoint_id)
            .await
            .unwrap());
    }
}

#[cfg(test)]
mod tls_tests {
    use super::*;
    use kernel::auth::Role;
    use kernel::syscall_server::SyscallServer;
    use kernel::AgentKernelImpl;
    use std::sync::Arc;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    /// The SDK's `connect_tls` dials a TLS-terminated kernel node and drives it
    /// through the typed client over the encrypted transport.
    #[tokio::test]
    async fn sdk_connect_tls_roundtrip() {
        let _ = rustls::crypto::ring::default_provider().install_default();

        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .expect("generate self-signed cert");
        let cert_der = cert.cert.der().clone();
        let key_der = rustls::pki_types::PrivateKeyDer::try_from(cert.signing_key.serialize_der())
            .expect("private key der");

        let server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der.clone()], key_der)
            .expect("server config");

        let kernel = Arc::new(AgentKernelImpl::new().expect("kernel new"));
        let server = SyscallServer::bind_tls(kernel, "127.0.0.1:0", server_config)
            .await
            .expect("bind_tls");
        let addr = server.local_addr().unwrap();
        tokio::spawn(server.serve());

        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert_der).expect("trust cert");
        let client_config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();

        let mut client = KernelClient::connect_tls(addr, "localhost", client_config)
            .await
            .expect("sdk connect_tls");

        let id = client
            .create_agent("tls-sdk", "demo", None, None, None)
            .await
            .expect("create agent over TLS");
        let agents = client.list_agents().await.expect("list over TLS");
        assert!(
            agents.iter().any(|a| a.id == id && a.name == "tls-sdk"),
            "agent created over the SDK TLS client should be listed: {agents:?}"
        );
        crate::protocol_tests::assert_public_lifecycle_contract(&mut client, "tls").await;
    }

    #[tokio::test]
    async fn secure_profile_verifies_tls_and_supports_auth_refresh() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .expect("generate self-signed cert");
        let cert_der = cert.cert.der().clone();
        let key_der = rustls::pki_types::PrivateKeyDer::try_from(cert.signing_key.serialize_der())
            .expect("private key der");
        let server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .expect("server config");
        let kernel = Arc::new(AgentKernelImpl::new().expect("kernel new"));
        let tenant = kernel
            .create_tenant("profile-tenant")
            .await
            .expect("tenant");
        let user = kernel
            .register_user(
                &tenant,
                "profile-reader",
                "profile-reader@example.invalid",
                Role::ReadOnly,
            )
            .await
            .expect("user");
        let first_key = kernel
            .issue_api_key(&user, "first")
            .await
            .expect("first key");
        let rotated_key = kernel
            .issue_api_key(&user, "rotated")
            .await
            .expect("rotated key");
        let server = SyscallServer::bind_tls(Arc::clone(&kernel), "127.0.0.1:0", server_config)
            .await
            .expect("bind TLS");
        let address = server.local_addr().expect("server address");
        tokio::spawn(server.serve());

        let directory =
            std::env::temp_dir().join(format!("agentos-profile-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&directory).expect("profile fixture directory");
        let ca = directory.join("ca.pem");
        std::fs::write(&ca, cert.cert.pem()).expect("write CA");
        let profile = ConnectionProfile {
            address: address.to_string(),
            transport: ConnectionTransport::Tls {
                server_name: "localhost".into(),
                ca_certificates: ca,
            },
            connect_timeout: Duration::from_secs(5),
        };

        let mut client = profile
            .connect(Some(&first_key))
            .await
            .expect("verified authenticated profile");
        client.list_agents().await.expect("authenticated read");
        profile
            .rotate_auth(&mut client, rotated_key)
            .await
            .expect("refresh credential");
        assert!(kernel
            .revoke_api_key(&first_key)
            .await
            .expect("revoke old key"));
        client
            .list_agents()
            .await
            .expect("read after old credential revocation");

        let wrong_name = ConnectionProfile {
            transport: ConnectionTransport::Tls {
                server_name: "wrong.example".into(),
                ca_certificates: directory.join("ca.pem"),
            },
            ..profile
        };
        let error = match wrong_name.connect(Some(&first_key)).await {
            Ok(_) => panic!("hostname mismatch must fail closed"),
            Err(error) => error,
        };
        assert!(matches!(error, SdkError::Transport(_)));
        let _ = std::fs::remove_dir_all(directory);
    }

    #[tokio::test]
    async fn profile_timeout_and_protocol_skew_fail_clearly() {
        let silent = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind silent peer");
        let silent_address = silent.local_addr().expect("silent address");
        tokio::spawn(async move {
            let _connection = silent.accept().await.expect("accept silent client");
            tokio::time::sleep(Duration::from_secs(1)).await;
        });
        let timeout_profile = ConnectionProfile {
            address: silent_address.to_string(),
            transport: ConnectionTransport::Plaintext,
            connect_timeout: Duration::from_millis(25),
        };
        let timeout = match timeout_profile.connect(None).await {
            Ok(_) => panic!("silent peer must time out"),
            Err(error) => error,
        };
        assert!(matches!(timeout, SdkError::Transport(_)));
        assert!(timeout.to_string().contains("25 ms"));

        let future = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind future peer");
        let future_address = future.local_addr().expect("future address");
        tokio::spawn(async move {
            let (stream, _) = future.accept().await.expect("accept future client");
            let (read, mut write) = stream.into_split();
            let mut request = String::new();
            BufReader::new(read)
                .read_line(&mut request)
                .await
                .expect("read hello");
            let reply = SyscallReply::Hello {
                protocol_version: PROTOCOL_VERSION + 2,
                min_protocol_version: PROTOCOL_VERSION + 1,
                server_version: "future-test".into(),
                features: Vec::new(),
            };
            write
                .write_all(format!("{}\n", serde_json::to_string(&reply).unwrap()).as_bytes())
                .await
                .expect("write future hello");
        });
        let skew = match ConnectionProfile::plaintext(future_address.to_string())
            .connect(None)
            .await
        {
            Ok(_) => panic!("future protocol must be rejected"),
            Err(error) => error,
        };
        assert!(matches!(skew, SdkError::IncompatibleProtocol { .. }));
        assert!(skew.to_string().contains("future-test"));
    }
}
