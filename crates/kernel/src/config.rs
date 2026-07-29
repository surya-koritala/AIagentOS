//! Configuration management — TOML-based persistent config.

use std::collections::{BTreeSet, HashMap};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::ProviderId;

/// Per-token-class pricing in USD per 1,000 tokens.
///
/// `cached_input_usd_per_1k_tokens` applies only to the cached subset of
/// provider-reported input tokens. The remaining input tokens use
/// `input_usd_per_1k_tokens`, and completion tokens use
/// `output_usd_per_1k_tokens`.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct TokenPricing {
    pub input_usd_per_1k_tokens: f64,
    pub cached_input_usd_per_1k_tokens: f64,
    pub output_usd_per_1k_tokens: f64,
}

impl TokenPricing {
    pub(crate) fn blended(usd_per_1k_tokens: f64) -> Self {
        Self {
            input_usd_per_1k_tokens: usd_per_1k_tokens,
            cached_input_usd_per_1k_tokens: usd_per_1k_tokens,
            output_usd_per_1k_tokens: usd_per_1k_tokens,
        }
    }

    pub(crate) fn validate(self, location: &str) -> Result<(), String> {
        for (name, value) in [
            ("input_usd_per_1k_tokens", self.input_usd_per_1k_tokens),
            (
                "cached_input_usd_per_1k_tokens",
                self.cached_input_usd_per_1k_tokens,
            ),
            ("output_usd_per_1k_tokens", self.output_usd_per_1k_tokens),
        ] {
            if !value.is_finite() || value < 0.0 {
                return Err(format!(
                    "{location}.{name} must be a finite, non-negative USD price (got {value})"
                ));
            }
        }
        Ok(())
    }
}

/// Failure to read or validate an operator configuration.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ConfigLoadError {
    #[error("cannot read config file {path}: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("invalid config file {path}: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: Box<toml::de::Error>,
    },
    #[error("invalid budget configuration in {path}: {message}")]
    Budget { path: PathBuf, message: String },
    #[error("invalid scheduled-backup configuration in {path}: {message}")]
    Backup { path: PathBuf, message: String },
    #[error("invalid storage-encryption configuration in {path}: {message}")]
    StorageEncryption { path: PathBuf, message: String },
    #[error("invalid cluster-Raft configuration in {path}: {message}")]
    ClusterRaft { path: PathBuf, message: String },
}

/// Whole-database encryption policy for the kernel-owned SQLite store.
///
/// The key file is operator-custodied and deliberately lives outside the data
/// directory and database backups. `required` prevents an omitted key path
/// from silently starting a production instance with plaintext persistence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct StorageEncryptionConfig {
    pub required: bool,
    pub key_path: Option<PathBuf>,
    /// Previous generations retained only for older encrypted backups.
    pub retired_key_paths: Vec<PathBuf>,
}

impl StorageEncryptionConfig {
    pub fn validate(&self) -> Result<(), String> {
        match self.key_path.as_deref() {
            Some(path) if !path.is_absolute() => Err(format!(
                "storage_encryption.key_path must be an absolute path (got {})",
                path.display()
            )),
            Some(path) => {
                let mut seen = std::collections::BTreeSet::new();
                seen.insert(path);
                for retired in &self.retired_key_paths {
                    if !retired.is_absolute() {
                        return Err(format!(
                            "storage_encryption.retired_key_paths entries must be absolute (got {})",
                            retired.display()
                        ));
                    }
                    if !seen.insert(retired) {
                        return Err(format!(
                            "storage encryption key path is configured more than once: {}",
                            retired.display()
                        ));
                    }
                }
                Ok(())
            }
            None if self.required => {
                Err("storage_encryption.key_path is required when encryption is required".into())
            }
            None if !self.retired_key_paths.is_empty() => {
                Err("storage_encryption.retired_key_paths require a current key_path".into())
            }
            None => Ok(()),
        }
    }

    pub fn enabled(&self) -> bool {
        self.key_path.is_some()
    }
}

/// Operator policy for automatic, verified local backups.
///
/// The scheduler is disabled unless explicitly enabled. A configured root must
/// be absolute so daemon startup never makes backup placement depend on its
/// working directory. Remote replication remains an operator responsibility.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BackupScheduleConfig {
    pub enabled: bool,
    pub root: Option<PathBuf>,
    pub interval_seconds: u64,
    pub run_on_start: bool,
    pub keep_latest: usize,
    pub max_age_seconds: u64,
    /// Optional owner-only Ed25519 PKCS#8 key used by both scheduled and
    /// system-operator-created backups.
    pub signing_key_path: Option<PathBuf>,
    /// Stable public identifier recorded in signed manifests.
    pub signing_key_id: Option<String>,
}

impl Default for BackupScheduleConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            root: None,
            interval_seconds: 60 * 60,
            run_on_start: true,
            keep_latest: 24,
            max_age_seconds: 7 * 24 * 60 * 60,
            signing_key_path: None,
            signing_key_id: None,
        }
    }
}

impl BackupScheduleConfig {
    pub fn validate(&self) -> Result<(), String> {
        match (&self.signing_key_path, &self.signing_key_id) {
            (None, None) => {}
            (Some(path), Some(key_id)) => {
                if !path.is_absolute() {
                    return Err(format!(
                        "backup.signing_key_path must be an absolute path (got {})",
                        path.display()
                    ));
                }
                if key_id.is_empty()
                    || key_id.len() > 96
                    || !key_id.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')
                    })
                {
                    return Err(
                        "backup.signing_key_id must be 1-96 ASCII letters, digits, '-', '_' or '.'"
                            .into(),
                    );
                }
            }
            _ => {
                return Err(
                    "backup.signing_key_path and backup.signing_key_id must be configured together"
                        .into(),
                )
            }
        }
        if let Some(root) = self.root.as_deref() {
            if !root.is_absolute() {
                return Err(format!(
                    "backup.root must be an absolute path (got {})",
                    root.display()
                ));
            }
        }
        if !self.enabled {
            return Ok(());
        }
        if self.root.is_none() {
            return Err("backup.root is required when scheduled backups are enabled".to_string());
        }
        if self.interval_seconds == 0 {
            return Err("backup.interval_seconds must be greater than zero".into());
        }
        if self.keep_latest == 0 {
            return Err("backup.keep_latest must be at least one".into());
        }
        if self.max_age_seconds == 0 {
            return Err("backup.max_age_seconds must be greater than zero".into());
        }
        if self.max_age_seconds < self.interval_seconds {
            return Err("backup.max_age_seconds must be at least backup.interval_seconds".into());
        }
        Ok(())
    }
}

/// One statically trusted peer in the initial Raft membership.
///
/// These values are copied into the quorum-versioned OpenRaft membership.
/// Exact server and client certificate fingerprints bind every transport role
/// to one node id in addition to the normal CA-backed TLS validation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClusterRaftMemberConfig {
    pub node_id: u64,
    pub endpoint: String,
    pub server_name: String,
    pub tls_certificate_sha256: String,
    pub tls_client_certificate_sha256: String,
    pub identity_public_key: String,
}

/// Production daemon configuration for the authenticated OpenRaft runtime.
///
/// The runtime is disabled by default so existing single-node installations
/// remain compatible. Enabling it requires an exact static membership and five
/// absolute PEM paths. `bootstrap` may be used for a pristine cluster; on
/// restart it verifies the durable membership instead of creating a second
/// cluster.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ClusterRaftConfig {
    pub enabled: bool,
    pub bootstrap: bool,
    pub node_id: u64,
    pub listen_addr: String,
    pub cluster_name: String,
    pub members: Vec<ClusterRaftMemberConfig>,
    pub server_certificate_path: Option<PathBuf>,
    pub server_private_key_path: Option<PathBuf>,
    pub client_certificate_path: Option<PathBuf>,
    pub client_private_key_path: Option<PathBuf>,
    pub peer_ca_path: Option<PathBuf>,
    pub handshake_timeout_ms: u64,
    pub inbound_request_timeout_ms: u64,
    pub max_frame_bytes: usize,
    pub max_in_flight_connections: usize,
    pub heartbeat_interval_ms: u64,
    pub election_timeout_min_ms: u64,
    pub election_timeout_max_ms: u64,
    pub install_snapshot_timeout_ms: u64,
    pub max_payload_entries: u64,
}

impl Default for ClusterRaftConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            bootstrap: false,
            node_id: 0,
            listen_addr: "127.0.0.1:8788".into(),
            cluster_name: "ai-agent-os".into(),
            members: Vec::new(),
            server_certificate_path: None,
            server_private_key_path: None,
            client_certificate_path: None,
            client_private_key_path: None,
            peer_ca_path: None,
            handshake_timeout_ms: 5_000,
            inbound_request_timeout_ms: 15_000,
            max_frame_bytes: 8 * 1024 * 1024,
            max_in_flight_connections: 128,
            heartbeat_interval_ms: 100,
            election_timeout_min_ms: 500,
            election_timeout_max_ms: 1_000,
            install_snapshot_timeout_ms: 10_000,
            max_payload_entries: 300,
        }
    }
}

impl ClusterRaftConfig {
    pub fn validate(&self) -> Result<(), String> {
        if self.bootstrap && !self.enabled {
            return Err("cluster_raft.bootstrap requires cluster_raft.enabled = true".into());
        }
        if !self.enabled {
            return Ok(());
        }
        if self.node_id == 0 {
            return Err("cluster_raft.node_id 0 is reserved".into());
        }
        let listen_addr = self
            .listen_addr
            .parse::<SocketAddr>()
            .map_err(|_| "cluster_raft.listen_addr must be a numeric IP:port value".to_string())?;
        if listen_addr.port() == 0 {
            return Err("cluster_raft.listen_addr port cannot be zero".into());
        }
        if self.cluster_name.trim().is_empty() || self.cluster_name.len() > 128 {
            return Err("cluster_raft.cluster_name must contain 1 to 128 bytes".into());
        }
        if self.members.is_empty() || self.members.len() > 31 {
            return Err("cluster_raft.members must contain 1 to 31 nodes".into());
        }

        for (name, value, maximum) in [
            ("handshake_timeout_ms", self.handshake_timeout_ms, 300_000),
            (
                "inbound_request_timeout_ms",
                self.inbound_request_timeout_ms,
                300_000,
            ),
            ("heartbeat_interval_ms", self.heartbeat_interval_ms, 60_000),
            (
                "election_timeout_min_ms",
                self.election_timeout_min_ms,
                600_000,
            ),
            (
                "election_timeout_max_ms",
                self.election_timeout_max_ms,
                600_000,
            ),
            (
                "install_snapshot_timeout_ms",
                self.install_snapshot_timeout_ms,
                3_600_000,
            ),
        ] {
            if value == 0 || value > maximum {
                return Err(format!(
                    "cluster_raft.{name} must be between 1 and {maximum}"
                ));
            }
        }
        if self.election_timeout_min_ms <= self.heartbeat_interval_ms {
            return Err(
                "cluster_raft.election_timeout_min_ms must exceed heartbeat_interval_ms".into(),
            );
        }
        if self.election_timeout_max_ms <= self.election_timeout_min_ms {
            return Err(
                "cluster_raft.election_timeout_max_ms must exceed election_timeout_min_ms".into(),
            );
        }
        if !(64 * 1024..=64 * 1024 * 1024).contains(&self.max_frame_bytes) {
            return Err("cluster_raft.max_frame_bytes must be between 65536 and 67108864".into());
        }
        if !(1..=16_384).contains(&self.max_in_flight_connections) {
            return Err(
                "cluster_raft.max_in_flight_connections must be between 1 and 16384".into(),
            );
        }
        if self.max_payload_entries == 0 || self.max_payload_entries > 1_000_000 {
            return Err("cluster_raft.max_payload_entries must be between 1 and 1000000".into());
        }

        for (name, path) in [
            (
                "server_certificate_path",
                self.server_certificate_path.as_deref(),
            ),
            (
                "server_private_key_path",
                self.server_private_key_path.as_deref(),
            ),
            (
                "client_certificate_path",
                self.client_certificate_path.as_deref(),
            ),
            (
                "client_private_key_path",
                self.client_private_key_path.as_deref(),
            ),
            ("peer_ca_path", self.peer_ca_path.as_deref()),
        ] {
            let path =
                path.ok_or_else(|| format!("cluster_raft.{name} is required when enabled"))?;
            if !path.is_absolute() {
                return Err(format!(
                    "cluster_raft.{name} must be an absolute path (got {})",
                    path.display()
                ));
            }
        }

        let mut node_ids = BTreeSet::new();
        let mut endpoints = BTreeSet::new();
        let mut server_fingerprints = BTreeSet::new();
        let mut client_fingerprints = BTreeSet::new();
        let mut certificate_owners = HashMap::new();
        let mut identity_keys = BTreeSet::new();
        for member in &self.members {
            if member.node_id == 0 {
                return Err("cluster_raft member node_id 0 is reserved".into());
            }
            if !node_ids.insert(member.node_id) {
                return Err("cluster_raft contains a duplicate member node_id".into());
            }
            validate_cluster_endpoint(&member.endpoint)?;
            validate_cluster_server_name(&member.server_name)?;
            validate_cluster_fingerprint(&member.tls_certificate_sha256, "tls_certificate_sha256")?;
            validate_cluster_fingerprint(
                &member.tls_client_certificate_sha256,
                "tls_client_certificate_sha256",
            )?;
            if member.identity_public_key.is_empty() || member.identity_public_key.len() > 8_192 {
                return Err(
                    "cluster_raft member identity_public_key must contain 1 to 8192 bytes".into(),
                );
            }
            if !endpoints.insert(member.endpoint.as_str()) {
                return Err("cluster_raft contains a duplicate member endpoint".into());
            }
            if !server_fingerprints.insert(member.tls_certificate_sha256.as_str()) {
                return Err(
                    "cluster_raft contains a duplicate server certificate fingerprint".into(),
                );
            }
            if !client_fingerprints.insert(member.tls_client_certificate_sha256.as_str()) {
                return Err(
                    "cluster_raft contains a duplicate client certificate fingerprint".into(),
                );
            }
            for fingerprint in [
                member.tls_certificate_sha256.as_str(),
                member.tls_client_certificate_sha256.as_str(),
            ] {
                if certificate_owners
                    .insert(fingerprint, member.node_id)
                    .is_some_and(|owner| owner != member.node_id)
                {
                    return Err(
                        "cluster_raft certificate fingerprint is assigned to multiple node ids"
                            .into(),
                    );
                }
            }
            if !identity_keys.insert(member.identity_public_key.as_str()) {
                return Err("cluster_raft contains a duplicate member identity key".into());
            }
        }
        if !node_ids.contains(&self.node_id) {
            return Err("cluster_raft local node_id is absent from members".into());
        }
        Ok(())
    }
}

fn validate_cluster_endpoint(endpoint: &str) -> Result<(), String> {
    if endpoint.is_empty()
        || endpoint.len() > 512
        || endpoint.chars().any(char::is_whitespace)
        || endpoint.contains("://")
        || endpoint.contains('/')
    {
        return Err(
            "cluster_raft member endpoint must be a bounded host:port without a URL scheme".into(),
        );
    }
    let (_, port) = endpoint
        .rsplit_once(':')
        .ok_or_else(|| "cluster_raft member endpoint must include a port".to_string())?;
    if port.parse::<u16>().ok().is_none_or(|parsed| parsed == 0) {
        return Err("cluster_raft member endpoint port must be between 1 and 65535".into());
    }
    Ok(())
}

fn validate_cluster_server_name(server_name: &str) -> Result<(), String> {
    if server_name.is_empty()
        || server_name.len() > 253
        || server_name.chars().any(char::is_whitespace)
        || server_name.contains("://")
        || server_name.contains('/')
    {
        return Err("cluster_raft member server_name is invalid".into());
    }
    Ok(())
}

fn validate_cluster_fingerprint(value: &str, field: &str) -> Result<(), String> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(format!(
            "cluster_raft member {field} must be 64 lowercase hexadecimal characters"
        ))
    }
}

/// Application configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub llm_provider: String,
    pub default_model: String,
    pub api_keys: HashMap<ProviderId, String>,
    pub data_dir: PathBuf,
    #[serde(default)]
    pub setup_complete: bool,
    /// Azure OpenAI specific settings.
    #[serde(default)]
    pub azure_endpoint: Option<String>,
    #[serde(default)]
    pub azure_deployment: Option<String>,
    #[serde(default)]
    pub azure_api_version: Option<String>,
    /// Max characters to return from browse_url (default 16000).
    #[serde(default = "default_max_browse_chars")]
    pub max_browse_chars: usize,
    /// Permission profile assigned to agents created by the CLI. Drives both
    /// the syscall-gate capability set (`caps_for_profile`) and the resource
    /// broker's MAC-style access rules. Defaults to "standard" (read/write/
    /// create/list + network + process launch; destructive ops gated). Set to
    /// "read-only", "elevated", or "full-access" to widen/narrow.
    #[serde(default = "default_permission_profile")]
    pub permission_profile: String,
    /// Resource budgets (cgroup token quotas + rate limiter) applied to agents.
    #[serde(default)]
    pub budgets: BudgetConfig,
    /// Mandatory Access Control: when true (the production default), the
    /// syscall gate's MAC stage enforces `mac_rules` (default-deny on no match).
    /// Setting this false is an explicit local-operator escape hatch and emits
    /// a startup warning. Agents are labelled
    /// `profile:<permission_profile>` at creation so rules can target them.
    #[serde(default = "default_mac_enforcing")]
    pub mac_enforcing: bool,
    /// MAC policy rules (subject/action/object/decision strings), consulted only
    /// when `mac_enforcing` is true. Operator notes:
    /// - Matching is default-DENY on no match, so include a trailing catch-all
    ///   `{subject="*", action="*", object="*", decision="allow"}` unless you
    ///   intend strict whitelist semantics. Enforcing with an empty `mac_rules`
    ///   denies everything for confined agents.
    /// - Subjects are `profile:<name>` where name is one of
    ///   read-only/standard/elevated/full-access.
    /// - Object matching is exact-or-`*` against a resource's label; until
    ///   per-path resource labels are wired, every resource is `unconfined`, so
    ///   use `object = "*"` (or `"unconfined"`).
    #[serde(default = "default_mac_rules")]
    pub mac_rules: Vec<crate::mac::PolicyRule>,
    /// Path to a declarative policy document (see `docs/POLICY.md`). When set,
    /// it is the source of truth and **supersedes** the inline
    /// `mac_enforcing`/`mac_rules`: the document's `enforcing` flag and its
    /// compiled rules are used instead. An unreadable or malformed policy file
    /// is a hard startup error (clear message + non-zero exit, never a silent
    /// fallback to permissive) — see [`Config::resolve_mac`].
    #[serde(default)]
    pub policy_file: Option<PathBuf>,
    /// Optional directory of declarative `*.toml` agent services. Definitions
    /// are parsed and dependency-validated atomically during kernel creation;
    /// the server starts them after provider registration.
    #[serde(default)]
    pub service_dir: Option<PathBuf>,
    /// Disabled-by-default automatic local backup and retention policy.
    #[serde(default)]
    pub backup: BackupScheduleConfig,
    /// Optional whole-database SQLCipher encryption. Production profiles set
    /// `required = true` so missing key custody fails startup closed.
    #[serde(default)]
    pub storage_encryption: StorageEncryptionConfig,
    /// Disabled-by-default authenticated OpenRaft peer runtime.
    #[serde(default)]
    pub cluster_raft: ClusterRaftConfig,
}

/// Resource budgets applied at agent creation and to the shared rate limiter.
///
/// `agent_tokens_per_min` bounds a non-`full-access` agent's per-minute provider
/// token spend (0 = unlimited); `full-access` agents are unlimited and
/// `elevated` gets a wider budget. `tenant_tokens_per_min` independently bounds
/// each tenant. `rpm`/`tpm`/`max_concurrent` configure provider-wide limits,
/// while `max_waiting_turns` bounds queued turns before overload is rejected.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BudgetConfig {
    #[serde(default = "default_agent_tokens_per_min")]
    pub agent_tokens_per_min: u64,
    /// Maximum provider tokens charged to one tenant in a fixed Unix-minute
    /// epoch. `0` means unlimited. Kept separate from provider-wide `tpm` so
    /// tenant isolation remains meaningful when several tenants share a
    /// kernel.
    #[serde(default)]
    pub tenant_tokens_per_min: u64,
    /// Maximum cumulative tool calls in one logical agent turn. This count is
    /// carried through pause/resume checkpoints and resets for the next user
    /// turn. `0` means unlimited.
    #[serde(default)]
    pub max_tool_calls: u32,
    /// Maximum tool calls that may execute concurrently for one agent's
    /// cgroup. This is independent from the cumulative per-turn limit above;
    /// `0` means unlimited.
    #[serde(default)]
    pub max_concurrent_tool_calls: u32,
    #[serde(default = "default_max_context_tokens")]
    pub max_context_tokens: u64,
    /// Maximum concurrently admitted active-prompt tokens for one tenant.
    /// This is independent from the durable per-agent prompt compaction bound.
    /// `0` means unlimited.
    #[serde(default = "default_tenant_max_context_tokens")]
    pub tenant_max_context_tokens: u64,
    /// Maximum concurrently admitted active-prompt tokens across the kernel.
    /// `0` means unlimited.
    #[serde(default = "default_global_max_context_tokens")]
    pub global_max_context_tokens: u64,
    /// Maximum durable context bytes owned by one agent across conversations,
    /// spills, embeddings, snapshots, and generation checkpoints.
    #[serde(default = "default_max_context_storage_bytes")]
    pub max_context_storage_bytes: u64,
    /// Maximum durable context bytes owned by one tenant. `0` means unlimited.
    #[serde(default = "default_tenant_max_context_storage_bytes")]
    pub tenant_max_context_storage_bytes: u64,
    /// Maximum durable context bytes across the kernel. `0` means unlimited.
    #[serde(default = "default_global_max_context_storage_bytes")]
    pub global_max_context_storage_bytes: u64,
    /// Retention window for durable context spills. Expired spills are removed
    /// before quota accounting and cannot be paged in.
    #[serde(default = "default_context_spill_retention_seconds")]
    pub context_spill_retention_seconds: u64,
    /// Provider-enforced maximum completion/new tokens for each LLM attempt.
    /// The kernel reserves this allowance together with the complete prompt
    /// estimate before I/O, preventing a conforming built-in provider response
    /// from crossing a bounded RPM/TPM/cgroup admission ceiling.
    #[serde(default = "default_max_output_tokens_per_request")]
    pub max_output_tokens_per_request: u32,
    #[serde(default = "default_rpm")]
    pub rpm: u32,
    #[serde(default = "default_tpm")]
    pub tpm: u64,
    #[serde(default = "default_max_concurrent")]
    pub max_concurrent: u32,
    /// Maximum turns allowed to wait behind `max_concurrent` active turns.
    /// `0` uses the compatibility default: 64 waiters per active turn, with a
    /// minimum of 64. Configure an explicit finite value in production so the
    /// overload envelope is intentional and can be qualified.
    #[serde(default)]
    pub max_waiting_turns: u32,
    /// Hard cumulative USD spend ceiling across all agents (0.0 = unlimited).
    /// Enforced by [`crate::budget::BudgetEnforcer`] on the LLM path.
    #[serde(default)]
    pub max_usd: f64,
    /// Hard cumulative USD ceiling per agent (0.0 = unlimited).
    #[serde(default)]
    pub per_agent_max_usd: f64,
    /// Hard cumulative USD ceiling per tenant (0.0 = unlimited). Tenant spend
    /// remains cumulative when an individual agent is deleted or restarted.
    #[serde(default)]
    pub per_tenant_max_usd: f64,
    /// Default blended price in USD per 1000 tokens, used to cost LLM responses
    /// (0.0 = free → the USD ceilings never trigger). Per-provider overrides go
    /// in `provider_pricing`.
    #[serde(default)]
    pub usd_per_1k_tokens: f64,
    /// Per-provider price overrides (provider id → USD per 1000 tokens).
    #[serde(default)]
    pub provider_pricing: HashMap<ProviderId, f64>,
    /// Detailed fallback pricing used when no provider/model or legacy
    /// provider-specific price exists.
    #[serde(default)]
    pub default_token_pricing: Option<TokenPricing>,
    /// Detailed per-provider prices.
    #[serde(default)]
    pub provider_token_pricing: HashMap<ProviderId, TokenPricing>,
    /// Detailed per-provider, per-model prices. The outer key is the provider
    /// id and the inner key is the model id reported by its LLM session.
    #[serde(default)]
    pub provider_model_token_pricing: HashMap<ProviderId, HashMap<String, TokenPricing>>,
}

impl Default for BudgetConfig {
    fn default() -> Self {
        Self {
            agent_tokens_per_min: default_agent_tokens_per_min(),
            tenant_tokens_per_min: 0,
            max_tool_calls: 0,
            max_concurrent_tool_calls: 0,
            max_context_tokens: default_max_context_tokens(),
            tenant_max_context_tokens: default_tenant_max_context_tokens(),
            global_max_context_tokens: default_global_max_context_tokens(),
            max_context_storage_bytes: default_max_context_storage_bytes(),
            tenant_max_context_storage_bytes: default_tenant_max_context_storage_bytes(),
            global_max_context_storage_bytes: default_global_max_context_storage_bytes(),
            context_spill_retention_seconds: default_context_spill_retention_seconds(),
            max_output_tokens_per_request: default_max_output_tokens_per_request(),
            rpm: default_rpm(),
            tpm: default_tpm(),
            max_concurrent: default_max_concurrent(),
            max_waiting_turns: 0,
            max_usd: 0.0,
            per_agent_max_usd: 0.0,
            per_tenant_max_usd: 0.0,
            usd_per_1k_tokens: 0.0,
            provider_pricing: HashMap::new(),
            default_token_pricing: None,
            provider_token_pricing: HashMap::new(),
            provider_model_token_pricing: HashMap::new(),
        }
    }
}

impl BudgetConfig {
    /// Validate detailed pricing before a kernel can admit work.
    ///
    /// All monetary configuration is strict because accepting a malformed
    /// entry and treating it as free or unlimited could silently bypass a
    /// configured USD ceiling. Low-level legacy constructors retain their
    /// historical clamping behavior, but config-backed startup never does.
    pub fn validate(&self) -> Result<(), String> {
        if self.max_output_tokens_per_request == 0 {
            return Err(
                "max_output_tokens_per_request must be greater than zero so bounded token quotas can reserve a provider-enforced completion allowance"
                    .into(),
            );
        }
        if self.context_spill_retention_seconds == 0 {
            return Err(
                "context_spill_retention_seconds must be greater than zero; use storage limits and explicit deletion instead of disabling retention"
                    .into(),
            );
        }
        for (name, value) in [
            ("max_usd", self.max_usd),
            ("per_agent_max_usd", self.per_agent_max_usd),
            ("per_tenant_max_usd", self.per_tenant_max_usd),
            ("usd_per_1k_tokens", self.usd_per_1k_tokens),
        ] {
            if !value.is_finite() || value < 0.0 {
                return Err(format!(
                    "{name} must be a finite, non-negative USD value (got {value})"
                ));
            }
        }
        for (provider, price) in &self.provider_pricing {
            if provider.trim().is_empty() {
                return Err("provider_pricing contains an empty provider id".to_string());
            }
            if !price.is_finite() || *price < 0.0 {
                return Err(format!(
                    "provider_pricing.{provider} must be a finite, non-negative USD price (got {price})"
                ));
            }
        }
        if let Some(pricing) = self.default_token_pricing {
            pricing.validate("default_token_pricing")?;
        }
        for (provider, pricing) in &self.provider_token_pricing {
            if provider.trim().is_empty() {
                return Err("provider_token_pricing contains an empty provider id".to_string());
            }
            pricing.validate(&format!("provider_token_pricing.{provider}"))?;
        }
        for (provider, models) in &self.provider_model_token_pricing {
            if provider.trim().is_empty() {
                return Err(
                    "provider_model_token_pricing contains an empty provider id".to_string()
                );
            }
            for (model, pricing) in models {
                if model.trim().is_empty() {
                    return Err(format!(
                        "provider_model_token_pricing.{provider} contains an empty model id"
                    ));
                }
                pricing.validate(&format!("provider_model_token_pricing.{provider}.{model}"))?;
            }
        }
        Ok(())
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            llm_provider: "azure-openai".to_string(),
            default_model: "gpt-4o".to_string(),
            api_keys: HashMap::new(),
            data_dir: default_data_dir(),
            setup_complete: false,
            azure_endpoint: None,
            azure_deployment: None,
            azure_api_version: None,
            max_browse_chars: default_max_browse_chars(),
            permission_profile: default_permission_profile(),
            budgets: BudgetConfig::default(),
            mac_enforcing: default_mac_enforcing(),
            mac_rules: default_mac_rules(),
            policy_file: None,
            service_dir: None,
            backup: BackupScheduleConfig::default(),
            storage_encryption: StorageEncryptionConfig::default(),
            cluster_raft: ClusterRaftConfig::default(),
        }
    }
}

fn default_max_browse_chars() -> usize {
    16000
}

fn default_permission_profile() -> String {
    "standard".to_string()
}

fn default_mac_enforcing() -> bool {
    true
}

/// Baseline enforcing policy. Capabilities remain the first authorization
/// stage; this MAC policy adds a second, profile-labelled allow-list with a
/// default-deny fallthrough. Destructive deletion is deliberately limited to
/// elevated/full-access, and unknown profiles match no rule.
fn default_mac_rules() -> Vec<crate::mac::PolicyRule> {
    use crate::mac::PolicyRule;

    let mut rules = Vec::new();
    for action in ["read", "ipc"] {
        rules.push(PolicyRule {
            subject: "profile:read-only".into(),
            action: action.into(),
            object: "*".into(),
            decision: "allow".into(),
        });
    }
    for profile in ["standard", "elevated"] {
        for action in ["read", "write", "net", "exec", "ipc"] {
            rules.push(PolicyRule {
                subject: format!("profile:{profile}"),
                action: action.into(),
                object: "*".into(),
                decision: "allow".into(),
            });
        }
    }
    rules.push(PolicyRule {
        subject: "profile:elevated".into(),
        action: "delete".into(),
        object: "*".into(),
        decision: "allow".into(),
    });
    rules.push(PolicyRule {
        subject: "profile:full-access".into(),
        action: "*".into(),
        object: "*".into(),
        decision: "allow".into(),
    });
    rules
}

fn default_agent_tokens_per_min() -> u64 {
    50_000
}

fn default_max_context_tokens() -> u64 {
    65_536
}

fn default_tenant_max_context_tokens() -> u64 {
    262_144
}

fn default_global_max_context_tokens() -> u64 {
    1_048_576
}

fn default_max_context_storage_bytes() -> u64 {
    64 * 1024 * 1024
}

fn default_tenant_max_context_storage_bytes() -> u64 {
    512 * 1024 * 1024
}

fn default_global_max_context_storage_bytes() -> u64 {
    2 * 1024 * 1024 * 1024
}

fn default_context_spill_retention_seconds() -> u64 {
    30 * 24 * 60 * 60
}

fn default_rpm() -> u32 {
    60
}

fn default_tpm() -> u64 {
    100_000
}

fn default_max_concurrent() -> u32 {
    3
}

fn default_max_output_tokens_per_request() -> u32 {
    4_096
}

impl Config {
    /// Resolve the effective MAC configuration `(enforcing, rules)`.
    ///
    /// When `policy_file` is set it is the source of truth: the file is read,
    /// parsed/validated as a [`crate::policy::PolicyDocument`], and its
    /// `enforcing` flag + compiled rules are returned — superseding the inline
    /// `mac_enforcing`/`mac_rules`. An unreadable or malformed policy file is a
    /// hard error so startup fails loudly with a clear message rather than
    /// silently dropping to permissive mode. With no `policy_file`, inline rules
    /// are validated for canonical action/decision labels and non-empty
    /// selectors before they are returned.
    pub fn resolve_mac(&self) -> Result<(bool, Vec<crate::mac::PolicyRule>), String> {
        match &self.policy_file {
            Some(path) => {
                let content = std::fs::read_to_string(path)
                    .map_err(|e| format!("cannot read policy file {}: {e}", path.display()))?;
                let doc = crate::policy::PolicyDocument::from_toml(&content)
                    .map_err(|e| format!("invalid policy file {}: {e}", path.display()))?;
                Ok((doc.enforcing, doc.compile()))
            }
            None => {
                crate::policy::validate_engine_rules(&self.mac_rules)?;
                Ok((self.mac_enforcing, self.mac_rules.clone()))
            }
        }
    }

    /// Load config from the default path, or create default if missing.
    ///
    /// # Panics
    ///
    /// Panics when an existing config cannot be read, parsed, or validated.
    /// Production entry points should prefer [`Config::try_load`] to surface a
    /// clean startup error.
    pub fn load() -> Self {
        let path = config_file_path();
        Self::load_from(&path)
    }

    /// Strictly load config from the default path.
    ///
    /// A missing file still means first-run defaults. Other I/O failures,
    /// malformed TOML, and invalid detailed budget pricing are returned to the
    /// caller so production startup cannot silently fall back to free pricing.
    pub fn try_load() -> Result<Self, ConfigLoadError> {
        let path = config_file_path();
        Self::try_load_from(&path)
    }

    /// Load config from a specific path.
    pub fn load_from(path: &Path) -> Self {
        Self::try_load_from(path)
            .unwrap_or_else(|error| panic!("configuration must be valid: {error}"))
    }

    /// Parse and validate TOML supplied by an API caller.
    pub fn from_toml(content: &str) -> Result<Self, ConfigLoadError> {
        Self::from_toml_at(content, Path::new("<inline>"))
    }

    /// Strictly load config from `path`; see [`Config::try_load`].
    pub fn try_load_from(path: &Path) -> Result<Self, ConfigLoadError> {
        let content = match std::fs::read_to_string(path) {
            Ok(content) => content,
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self::default());
            }
            Err(source) => {
                return Err(ConfigLoadError::Read {
                    path: path.to_path_buf(),
                    source,
                });
            }
        };
        Self::from_toml_at(&content, path)
    }

    fn from_toml_at(content: &str, path: &Path) -> Result<Self, ConfigLoadError> {
        let config: Self = toml::from_str(content).map_err(|source| ConfigLoadError::Parse {
            path: path.to_path_buf(),
            source: Box::new(source),
        })?;
        config
            .budgets
            .validate()
            .map_err(|message| ConfigLoadError::Budget {
                path: path.to_path_buf(),
                message,
            })?;
        config
            .backup
            .validate()
            .map_err(|message| ConfigLoadError::Backup {
                path: path.to_path_buf(),
                message,
            })?;
        config.storage_encryption.validate().map_err(|message| {
            ConfigLoadError::StorageEncryption {
                path: path.to_path_buf(),
                message,
            }
        })?;
        config
            .cluster_raft
            .validate()
            .map_err(|message| ConfigLoadError::ClusterRaft {
                path: path.to_path_buf(),
                message,
            })?;
        Ok(config)
    }

    /// Save config to the default path.
    pub fn save(&self) -> Result<(), std::io::Error> {
        let path = config_file_path();
        self.save_to(&path)
    }

    /// Save config to a specific path.
    pub fn save_to(&self, path: &Path) -> Result<(), std::io::Error> {
        self.budgets.validate().map_err(|error| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("invalid budget configuration: {error}"),
            )
        })?;
        self.backup.validate().map_err(|error| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("invalid scheduled-backup configuration: {error}"),
            )
        })?;
        self.storage_encryption.validate().map_err(|error| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("invalid storage-encryption configuration: {error}"),
            )
        })?;
        self.cluster_raft.validate().map_err(|error| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("invalid cluster-Raft configuration: {error}"),
            )
        })?;
        let content = toml::to_string_pretty(self).map_err(std::io::Error::other)?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, content)
    }

    /// Get API key for a provider.
    pub fn get_api_key(&self, provider: &str) -> Option<&str> {
        self.api_keys.get(provider).map(|s| s.as_str())
    }

    /// Set API key for a provider.
    pub fn set_api_key(&mut self, provider: &str, key: String) {
        self.api_keys.insert(provider.to_string(), key);
    }
}

/// Get the platform-appropriate config directory.
pub fn config_dir() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("ai-agent-os")
}

/// Get the config file path.
pub fn config_file_path() -> PathBuf {
    config_dir().join("config.toml")
}

/// Get the default data directory.
fn default_data_dir() -> PathBuf {
    dirs::data_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("ai-agent-os")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config() {
        let cfg = Config::default();
        assert_eq!(cfg.llm_provider, "azure-openai");
        assert!(!cfg.setup_complete);
        assert!(cfg.api_keys.is_empty());
        assert!(!cfg.cluster_raft.enabled);
        assert!(!cfg.cluster_raft.bootstrap);
    }

    fn valid_cluster_raft_config() -> ClusterRaftConfig {
        let root =
            std::env::temp_dir().join(format!("agentos-raft-config-{}", uuid::Uuid::new_v4()));
        ClusterRaftConfig {
            enabled: true,
            bootstrap: true,
            node_id: 1,
            members: vec![ClusterRaftMemberConfig {
                node_id: 1,
                endpoint: "127.0.0.1:8788".into(),
                server_name: "node-1.agentos.test".into(),
                tls_certificate_sha256: "a".repeat(64),
                tls_client_certificate_sha256: "b".repeat(64),
                identity_public_key: "test-node-1-identity".into(),
            }],
            server_certificate_path: Some(root.join("server.pem")),
            server_private_key_path: Some(root.join("server-key.pem")),
            client_certificate_path: Some(root.join("client.pem")),
            client_private_key_path: Some(root.join("client-key.pem")),
            peer_ca_path: Some(root.join("ca.pem")),
            ..Default::default()
        }
    }

    #[test]
    fn cluster_raft_defaults_off_and_enabled_configuration_is_strict() {
        let legacy =
            "llm_provider = \"local\"\ndefault_model = \"m\"\ndata_dir = \"/tmp/x\"\n[api_keys]\n";
        let config = Config::from_toml(legacy).unwrap();
        assert!(!config.cluster_raft.enabled);

        let configured = valid_cluster_raft_config();
        configured.validate().expect("valid cluster config");
        let config = Config {
            cluster_raft: configured.clone(),
            ..Default::default()
        };
        let serialized = toml::to_string_pretty(&config).expect("serialize config");
        let parsed = Config::from_toml(&serialized).expect("parse config");
        assert_eq!(parsed.cluster_raft, configured);

        let unknown = serialized.replace(
            "[cluster_raft]",
            "[cluster_raft]\nunknown_cluster_option = true",
        );
        assert!(matches!(
            Config::from_toml(&unknown),
            Err(ConfigLoadError::Parse { .. })
        ));
    }

    #[test]
    fn cluster_raft_configuration_rejects_partial_and_ambiguous_identity() {
        let mut config = valid_cluster_raft_config();
        config.enabled = false;
        assert!(config.validate().unwrap_err().contains("bootstrap"));

        let mut config = valid_cluster_raft_config();
        config.server_private_key_path = Some(PathBuf::from("relative-key.pem"));
        assert!(config.validate().unwrap_err().contains("absolute"));

        let mut config = valid_cluster_raft_config();
        config.members[0].tls_certificate_sha256 = "uppercase".into();
        assert!(config
            .validate()
            .unwrap_err()
            .contains("lowercase hexadecimal"));

        let mut config = valid_cluster_raft_config();
        let mut second = config.members[0].clone();
        second.node_id = 2;
        second.endpoint = "127.0.0.1:8789".into();
        second.tls_client_certificate_sha256 = "c".repeat(64);
        second.identity_public_key = "test-node-2-identity".into();
        config.members.push(second);
        assert!(config
            .validate()
            .unwrap_err()
            .contains("duplicate server certificate"));
    }

    #[test]
    fn config_load_error_stays_compact_and_preserves_parse_details() {
        assert!(
            std::mem::size_of::<ConfigLoadError>() <= 64,
            "configuration errors must stay cheap to return on every supported platform"
        );

        let error = Config::from_toml("this is = not valid toml ][").unwrap_err();
        match error {
            ConfigLoadError::Parse { path, source } => {
                assert_eq!(path, Path::new("<inline>"));
                assert!(!source.to_string().is_empty());
            }
            other => panic!("expected a parse error, got {other}"),
        }
    }

    #[test]
    fn save_and_load_config() {
        let dir = std::env::temp_dir().join(format!("cfg_test_{}", uuid::Uuid::new_v4()));
        let path = dir.join("config.toml");

        let mut cfg = Config::default();
        cfg.set_api_key("openai", "sk-test-123".to_string());
        cfg.setup_complete = true;
        cfg.save_to(&path).unwrap();

        let loaded = Config::load_from(&path);
        assert_eq!(loaded.get_api_key("openai"), Some("sk-test-123"));
        assert!(loaded.setup_complete);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn load_missing_file_returns_default() {
        let cfg = Config::load_from(Path::new("/nonexistent/path/config.toml"));
        assert_eq!(cfg.llm_provider, "azure-openai");
    }

    #[test]
    fn compatibility_loader_fails_closed_on_malformed_file() {
        let dir = std::env::temp_dir().join(format!("cfg_bad_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.toml");
        std::fs::write(&path, "this is = not valid toml ][").unwrap();

        let result = std::panic::catch_unwind(|| Config::load_from(&path));
        std::fs::remove_dir_all(&dir).ok();
        let panic = result.expect_err("compatibility loader must fail closed");
        let message = panic
            .downcast_ref::<String>()
            .map(String::as_str)
            .or_else(|| panic.downcast_ref::<&str>().copied())
            .unwrap_or_default();
        assert!(message.contains("configuration must be valid"), "{message}");
    }

    #[test]
    fn config_roundtrip_toml() {
        let mut cfg = Config::default();
        cfg.set_api_key("anthropic", "sk-ant-xxx".to_string());
        cfg.default_model = "claude-3".to_string();

        let toml_str = toml::to_string_pretty(&cfg).unwrap();
        let parsed: Config = toml::from_str(&toml_str).unwrap();
        assert_eq!(parsed.default_model, "claude-3");
        assert_eq!(parsed.get_api_key("anthropic"), Some("sk-ant-xxx"));
    }

    #[test]
    fn budgets_default_when_absent_and_roundtrip() {
        // A config file with no [budgets] section still loads (serde default).
        let toml =
            "llm_provider = \"local\"\ndefault_model = \"m\"\ndata_dir = \"/tmp/x\"\n[api_keys]\n";
        let cfg: Config = toml::from_str(toml).unwrap();
        assert_eq!(cfg.budgets.agent_tokens_per_min, 50_000);
        assert_eq!(cfg.budgets.tenant_tokens_per_min, 0);
        assert_eq!(cfg.budgets.rpm, 60);
        assert_eq!(cfg.budgets.max_tool_calls, 0);
        assert_eq!(cfg.budgets.max_concurrent_tool_calls, 0);
        assert_eq!(cfg.budgets.max_output_tokens_per_request, 4_096);

        // And an explicit budget round-trips through TOML.
        let mut cfg = Config::default();
        cfg.budgets.agent_tokens_per_min = 12_345;
        cfg.budgets.tenant_tokens_per_min = 54_321;
        cfg.budgets.max_tool_calls = 7;
        cfg.budgets.max_concurrent_tool_calls = 2;
        cfg.budgets.max_output_tokens_per_request = 2_048;
        let s = toml::to_string_pretty(&cfg).unwrap();
        let parsed: Config = toml::from_str(&s).unwrap();
        assert_eq!(parsed.budgets.agent_tokens_per_min, 12_345);
        assert_eq!(parsed.budgets.tenant_tokens_per_min, 54_321);
        assert_eq!(parsed.budgets.max_output_tokens_per_request, 2_048);
        assert_eq!(parsed.budgets.max_tool_calls, 7);
        assert_eq!(parsed.budgets.max_concurrent_tool_calls, 2);
    }

    #[test]
    fn scheduled_backups_default_off_and_validate_production_policy() {
        let legacy =
            "llm_provider = \"local\"\ndefault_model = \"m\"\ndata_dir = \"/tmp/x\"\n[api_keys]\n";
        let config = Config::from_toml(legacy).unwrap();
        assert!(!config.backup.enabled);
        assert!(config.backup.root.is_none());

        let root = std::env::temp_dir().join(format!("agentos-backups-{}", uuid::Uuid::new_v4()));
        // Let the TOML serializer escape platform-specific separators (notably
        // Windows backslashes) instead of interpolating a raw path into a
        // basic TOML string.
        let root_toml = toml::Value::String(root.to_string_lossy().into_owned()).to_string();
        let configured = format!(
            r#"
llm_provider = "local"
default_model = "m"
data_dir = "/tmp/x"
[api_keys]
[backup]
enabled = true
root = {}
interval_seconds = 60
run_on_start = false
keep_latest = 3
max_age_seconds = 3600
"#,
            root_toml
        );
        let config = Config::from_toml(&configured).unwrap();
        assert!(config.backup.enabled);
        assert_eq!(config.backup.root.as_deref(), Some(root.as_path()));
        assert_eq!(config.backup.keep_latest, 3);
        assert!(!config.backup.run_on_start);
    }

    #[test]
    fn scheduled_backup_config_fails_closed_when_unsafe_or_incomplete() {
        let mut config = Config::default();
        config.backup.signing_key_path =
            Some(std::env::temp_dir().join("agentos-backup-signing.pk8"));
        assert!(config
            .backup
            .validate()
            .unwrap_err()
            .contains("configured together"));

        config.backup.signing_key_id = Some("release\ninjection".into());
        assert!(config
            .backup
            .validate()
            .unwrap_err()
            .contains("ASCII letters"));

        config.backup.signing_key_id = Some("release-2026.1".into());
        config.backup.signing_key_path = Some(PathBuf::from("relative/backup.pk8"));
        assert!(config.backup.validate().unwrap_err().contains("absolute"));

        config.backup.signing_key_path = None;
        config.backup.signing_key_id = None;
        config.backup.enabled = true;
        assert!(config.backup.validate().unwrap_err().contains("root"));

        config.backup.root = Some(PathBuf::from("relative/backups"));
        assert!(config.backup.validate().unwrap_err().contains("absolute"));

        config.backup.root = Some(std::env::temp_dir().join("agentos-backups"));
        config.backup.interval_seconds = 0;
        assert!(config
            .backup
            .validate()
            .unwrap_err()
            .contains("interval_seconds"));

        config.backup.interval_seconds = 60;
        config.backup.keep_latest = 0;
        assert!(config
            .backup
            .validate()
            .unwrap_err()
            .contains("keep_latest"));

        config.backup.keep_latest = 1;
        config.backup.max_age_seconds = 30;
        assert!(config
            .backup
            .validate()
            .unwrap_err()
            .contains("at least backup.interval_seconds"));
    }

    #[test]
    fn storage_encryption_defaults_off_and_required_policy_fails_closed() {
        let legacy =
            "llm_provider = \"local\"\ndefault_model = \"m\"\ndata_dir = \"/tmp/x\"\n[api_keys]\n";
        let config = Config::from_toml(legacy).unwrap();
        assert!(!config.storage_encryption.required);
        assert!(!config.storage_encryption.enabled());

        let required_without_key = r#"
llm_provider = "local"
default_model = "m"
data_dir = "/tmp/x"
[api_keys]
[storage_encryption]
required = true
"#;
        let error = Config::from_toml(required_without_key)
            .unwrap_err()
            .to_string();
        assert!(error.contains("key_path is required"), "{error}");

        let relative_key = r#"
llm_provider = "local"
default_model = "m"
data_dir = "/tmp/x"
[api_keys]
[storage_encryption]
required = true
key_path = "keys/storage.json"
"#;
        let error = Config::from_toml(relative_key).unwrap_err().to_string();
        assert!(error.contains("absolute path"), "{error}");

        let configured = Config {
            storage_encryption: StorageEncryptionConfig {
                required: true,
                key_path: Some(std::env::temp_dir().join("agentos-storage-key.json")),
                retired_key_paths: vec![
                    std::env::temp_dir().join("agentos-storage-key-retired.json")
                ],
            },
            ..Config::default()
        };
        let encoded = toml::to_string_pretty(&configured).unwrap();
        let parsed = Config::from_toml(&encoded).unwrap();
        assert!(parsed.storage_encryption.required);
        assert!(parsed.storage_encryption.enabled());
        assert_eq!(
            parsed.storage_encryption.key_path,
            configured.storage_encryption.key_path
        );
        assert_eq!(
            parsed.storage_encryption.retired_key_paths,
            configured.storage_encryption.retired_key_paths
        );

        let mut invalid = configured.clone();
        invalid.storage_encryption.retired_key_paths = vec![PathBuf::from("relative/retired.json")];
        assert!(invalid
            .storage_encryption
            .validate()
            .unwrap_err()
            .contains("must be absolute"));
        invalid.storage_encryption.retired_key_paths =
            vec![invalid.storage_encryption.key_path.clone().unwrap()];
        assert!(invalid
            .storage_encryption
            .validate()
            .unwrap_err()
            .contains("more than once"));
        invalid.storage_encryption.key_path = None;
        invalid.storage_encryption.required = false;
        assert!(invalid
            .storage_encryption
            .validate()
            .unwrap_err()
            .contains("require a current"));
    }

    #[test]
    fn backup_signing_identity_roundtrips_without_becoming_enabled_by_default() {
        let mut config = Config::default();
        let signing_key_path = std::env::temp_dir().join("agentos-backup-signing.pk8");
        config.backup.signing_key_path = Some(signing_key_path.clone());
        config.backup.signing_key_id = Some("release-2026.1".into());

        let encoded = toml::to_string_pretty(&config).unwrap();
        let parsed = Config::from_toml(&encoded).unwrap();
        assert!(!parsed.backup.enabled);
        assert_eq!(
            parsed.backup.signing_key_path.as_deref(),
            Some(signing_key_path.as_path())
        );
        assert_eq!(
            parsed.backup.signing_key_id.as_deref(),
            Some("release-2026.1")
        );
    }

    #[test]
    fn detailed_token_pricing_roundtrips_and_legacy_toml_stays_compatible() {
        let mut cfg = Config::default();
        cfg.budgets.default_token_pricing = Some(TokenPricing {
            input_usd_per_1k_tokens: 1.0,
            cached_input_usd_per_1k_tokens: 0.1,
            output_usd_per_1k_tokens: 2.0,
        });
        cfg.budgets.provider_token_pricing.insert(
            "openai".into(),
            TokenPricing {
                input_usd_per_1k_tokens: 3.0,
                cached_input_usd_per_1k_tokens: 0.3,
                output_usd_per_1k_tokens: 6.0,
            },
        );
        cfg.budgets
            .provider_model_token_pricing
            .entry("openai".into())
            .or_default()
            .insert(
                "gpt-4o".into(),
                TokenPricing {
                    input_usd_per_1k_tokens: 4.0,
                    cached_input_usd_per_1k_tokens: 0.4,
                    output_usd_per_1k_tokens: 8.0,
                },
            );

        let encoded = toml::to_string_pretty(&cfg).unwrap();
        let parsed: Config = toml::from_str(&encoded).unwrap();
        assert_eq!(
            parsed.budgets.default_token_pricing,
            cfg.budgets.default_token_pricing
        );
        assert_eq!(
            parsed.budgets.provider_token_pricing,
            cfg.budgets.provider_token_pricing
        );
        assert_eq!(
            parsed.budgets.provider_model_token_pricing,
            cfg.budgets.provider_model_token_pricing
        );

        let legacy = r#"
llm_provider = "local"
default_model = "m"
data_dir = "/tmp/x"
[api_keys]
[budgets]
usd_per_1k_tokens = 2.5
[budgets.provider_pricing]
openai = 3.5
"#;
        let parsed: Config = toml::from_str(legacy).unwrap();
        assert_eq!(parsed.budgets.usd_per_1k_tokens, 2.5);
        assert_eq!(parsed.budgets.provider_pricing["openai"], 3.5);
        assert!(parsed.budgets.default_token_pricing.is_none());
        assert!(parsed.budgets.provider_token_pricing.is_empty());
        assert!(parsed.budgets.provider_model_token_pricing.is_empty());
    }

    #[test]
    fn detailed_token_pricing_rejects_invalid_values_and_empty_keys() {
        let missing_output_bound = BudgetConfig {
            max_output_tokens_per_request: 0,
            ..BudgetConfig::default()
        };
        assert!(missing_output_bound
            .validate()
            .unwrap_err()
            .contains("max_output_tokens_per_request"));

        let mut budgets = BudgetConfig {
            default_token_pricing: Some(TokenPricing {
                input_usd_per_1k_tokens: f64::NAN,
                cached_input_usd_per_1k_tokens: 0.0,
                output_usd_per_1k_tokens: 0.0,
            }),
            ..BudgetConfig::default()
        };
        assert!(budgets.validate().unwrap_err().contains("finite"));

        budgets.default_token_pricing = Some(TokenPricing {
            input_usd_per_1k_tokens: 0.0,
            cached_input_usd_per_1k_tokens: -0.01,
            output_usd_per_1k_tokens: 0.0,
        });
        assert!(budgets.validate().unwrap_err().contains("non-negative"));

        budgets.default_token_pricing = None;
        budgets.provider_token_pricing.insert(
            " ".into(),
            TokenPricing {
                input_usd_per_1k_tokens: 0.0,
                cached_input_usd_per_1k_tokens: 0.0,
                output_usd_per_1k_tokens: 0.0,
            },
        );
        assert!(budgets.validate().unwrap_err().contains("empty provider"));

        let mut budgets = BudgetConfig {
            max_usd: f64::INFINITY,
            ..BudgetConfig::default()
        };
        assert!(budgets.validate().unwrap_err().contains("max_usd"));
        budgets.max_usd = 0.0;
        budgets.provider_pricing.insert("legacy".into(), -1.0);
        assert!(budgets
            .validate()
            .unwrap_err()
            .contains("provider_pricing.legacy"));
        budgets.provider_pricing.clear();
        budgets.provider_model_token_pricing.insert(
            "provider".into(),
            HashMap::from([(
                " ".into(),
                TokenPricing {
                    input_usd_per_1k_tokens: 0.0,
                    cached_input_usd_per_1k_tokens: 0.0,
                    output_usd_per_1k_tokens: 0.0,
                },
            )]),
        );
        assert!(budgets.validate().unwrap_err().contains("empty model"));
    }

    #[test]
    fn strict_loader_rejects_malformed_or_invalid_detailed_pricing() {
        let dir = std::env::temp_dir().join(format!("cfg_pricing_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.toml");
        std::fs::write(
            &path,
            r#"
llm_provider = "local"
default_model = "m"
data_dir = "/tmp/x"
[api_keys]
[budgets.default_token_pricing]
input_usd_per_1k_tokens = -1.0
cached_input_usd_per_1k_tokens = 0.1
output_usd_per_1k_tokens = 2.0
"#,
        )
        .unwrap();
        let error = Config::try_load_from(&path).unwrap_err().to_string();
        assert!(error.contains("invalid budget configuration"), "{error}");

        std::fs::write(
            &path,
            r#"
llm_provider = "local"
default_model = "m"
data_dir = "/tmp/x"
[api_keys]
[budgets.default_token_pricing]
input_usd_per_1k_tokens = 1.0
"#,
        )
        .unwrap();
        let error = Config::try_load_from(&path).unwrap_err().to_string();
        assert!(error.contains("invalid config file"), "{error}");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn strict_loader_defaults_only_for_missing_file_and_rejects_unknown_or_infinite_prices() {
        let missing =
            std::env::temp_dir().join(format!("cfg_missing_{}/config.toml", uuid::Uuid::new_v4()));
        let cfg = Config::try_load_from(&missing).unwrap();
        assert_eq!(cfg.llm_provider, Config::default().llm_provider);

        let unknown = r#"
llm_provider = "local"
default_model = "m"
data_dir = "/tmp/x"
[api_keys]
[budgets]
usd_per_1k_toknes = 1.0
"#;
        let error = Config::from_toml(unknown).unwrap_err().to_string();
        assert!(error.contains("unknown field"), "{error}");

        let unknown_detailed = r#"
llm_provider = "local"
default_model = "m"
data_dir = "/tmp/x"
[api_keys]
[budgets.default_token_pricing]
input_usd_per_1k_tokens = 1.0
cached_input_usd_per_1k_tokens = 0.1
output_usd_per_1k_tokens = 2.0
output_usd_per_million_tokens = 2000.0
"#;
        let error = Config::from_toml(unknown_detailed).unwrap_err().to_string();
        assert!(error.contains("unknown field"), "{error}");

        let infinite = r#"
llm_provider = "local"
default_model = "m"
data_dir = "/tmp/x"
[api_keys]
[budgets]
usd_per_1k_tokens = inf
"#;
        let error = Config::from_toml(infinite).unwrap_err().to_string();
        assert!(error.contains("finite"), "{error}");
    }

    #[test]
    fn invalid_budget_config_cannot_overwrite_an_existing_file() {
        let dir = std::env::temp_dir().join(format!("cfg_save_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.toml");
        std::fs::write(&path, "keep me").unwrap();
        let mut cfg = Config::default();
        cfg.budgets.max_usd = f64::NAN;

        let error = cfg.save_to(&path).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "keep me");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn mac_fields_default_and_roundtrip() {
        // A config without MAC fields loads the enforcing, default-deny
        // baseline policy rather than silently becoming permissive.
        let toml =
            "llm_provider = \"local\"\ndefault_model = \"m\"\ndata_dir = \"/tmp/x\"\n[api_keys]\n";
        let cfg: Config = toml::from_str(toml).unwrap();
        assert!(cfg.mac_enforcing);
        assert!(!cfg.mac_rules.is_empty());

        // Enforcing + a rule round-trips through TOML.
        let cfg = Config {
            mac_enforcing: true,
            mac_rules: vec![crate::mac::PolicyRule {
                subject: "profile:standard".into(),
                action: "write".into(),
                object: "*".into(),
                decision: "deny".into(),
            }],
            ..Config::default()
        };
        let s = toml::to_string_pretty(&cfg).unwrap();
        let parsed: Config = toml::from_str(&s).unwrap();
        assert!(parsed.mac_enforcing);
        assert_eq!(parsed.mac_rules.len(), 1);
        assert_eq!(parsed.mac_rules[0].decision, "deny");
    }

    #[test]
    fn resolve_mac_uses_inline_when_no_policy_file() {
        let cfg = Config {
            mac_enforcing: true,
            mac_rules: vec![crate::mac::PolicyRule {
                subject: "*".into(),
                action: "read".into(),
                object: "*".into(),
                decision: "allow".into(),
            }],
            ..Config::default()
        };
        let (enforcing, rules) = cfg.resolve_mac().unwrap();
        assert!(enforcing);
        assert_eq!(rules.len(), 1);
    }

    #[test]
    fn resolve_mac_rejects_noncanonical_inline_action_and_decision_labels() {
        let mut cfg = Config {
            mac_rules: vec![crate::mac::PolicyRule {
                subject: "*".into(),
                action: "execute".into(),
                object: "*".into(),
                decision: "allow".into(),
            }],
            ..Config::default()
        };
        let action_error = cfg.resolve_mac().unwrap_err();
        assert!(
            action_error.contains("unknown action label 'execute'"),
            "{action_error}"
        );
        assert!(
            action_error.contains("`exec`, not `execute`"),
            "{action_error}"
        );

        cfg.mac_rules[0].action = "exec".into();
        cfg.mac_rules[0].decision = "alow".into();
        let decision_error = cfg.resolve_mac().unwrap_err();
        assert!(
            decision_error.contains("unknown decision 'alow'"),
            "{decision_error}"
        );
    }

    #[test]
    fn resolve_mac_policy_file_supersedes_inline() {
        let dir = std::env::temp_dir();
        let path = dir.join("agentos-test-policy-supersede.toml");
        std::fs::write(
            &path,
            r#"
enforcing = true
default = "deny"

[[rule]]
subject = "*"
action = "write"
object = "/etc/**"
decision = "deny"
"#,
        )
        .unwrap();

        // Inline says enforcing=false with no rules; the file must win.
        let cfg = Config {
            mac_enforcing: false,
            mac_rules: Vec::new(),
            policy_file: Some(path.clone()),
            ..Config::default()
        };

        let (enforcing, rules) = cfg.resolve_mac().unwrap();
        assert!(
            enforcing,
            "policy file's enforcing flag should supersede inline"
        );
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].object, "/etc/**");

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn resolve_mac_malformed_policy_file_is_an_error() {
        let dir = std::env::temp_dir();
        let path = dir.join("agentos-test-policy-bad.toml");
        // Unknown decision value — typed parse rejects it.
        std::fs::write(
            &path,
            "[[rule]]\nsubject = \"*\"\naction = \"read\"\nobject = \"*\"\ndecision = \"alow\"\n",
        )
        .unwrap();

        let cfg = Config {
            policy_file: Some(path.clone()),
            ..Config::default()
        };
        let err = cfg.resolve_mac().unwrap_err();
        assert!(err.contains("invalid policy file"), "got: {err}");

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn resolve_mac_missing_policy_file_is_an_error() {
        let cfg = Config {
            policy_file: Some(std::path::PathBuf::from(
                "/nonexistent/agentos/policy/does-not-exist.toml",
            )),
            ..Config::default()
        };
        let err = cfg.resolve_mac().unwrap_err();
        assert!(err.contains("cannot read policy file"), "got: {err}");
    }
}
