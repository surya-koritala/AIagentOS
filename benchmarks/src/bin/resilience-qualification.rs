//! Deterministic overload and graceful-degradation qualification.
//!
//! This suite drives public TCP/SDK paths and records bounded admission,
//! recovery, and leak checks. It is a release-regression artifact, not
//! production proof: real-provider, target-host, long-duration, and independent
//! evidence remain mandatory before a production claim.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use agent_sdk::{KernelClient, MessageStreamEvent, SdkError, WireErrorCode};
use chrono::Utc;
use kernel::config::{BudgetConfig, Config};
use kernel::connector::{
    LlmProviderAdapter, LlmRequestOptions, LlmResponse, LlmSession, ProviderCapabilities,
    ProviderEventSink, ProviderStreamEvent, ProviderType, StandardMessage, ToolDefinition,
};
use kernel::context::SqliteContextManager;
use kernel::metrics::MetricsSnapshot;
use kernel::syscall_server::{SyscallServer, WireConnectionSnapshot};
use kernel::{AgentKernelImpl, ConnectorError, ProviderId};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Barrier;
use tokio::task::{JoinHandle, JoinSet};

const DEFAULT_CONFIG: &str = include_str!("../../resilience-profiles.toml");
const SCENARIOS: [&str; 7] = [
    "turn-overload",
    "slow-clients",
    "provider-outage",
    "cancellation-storm",
    "disk-full",
    "database-lock",
    "network-partition",
];
const MAX_CONFIGURED_RSS_GROWTH_BYTES: u64 = 256 * 1024 * 1024;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SuiteConfig {
    schema_version: u32,
    suite: String,
    turn_overload: TurnOverloadConfig,
    slow_clients: SlowClientsConfig,
    provider_outage: ProviderOutageConfig,
    cancellation_storm: CancellationStormConfig,
    disk_full: DiskFullConfig,
    database_lock: DatabaseLockConfig,
    network_partition: NetworkPartitionConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct TurnOverloadConfig {
    operations: usize,
    max_concurrent: u32,
    max_waiting: u32,
    provider_delay_ms: u64,
    memory_waves: usize,
    max_rss_growth_bytes: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SlowClientsConfig {
    connection_limit: usize,
    excess_connections: usize,
    idle_timeout_ms: u64,
    memory_waves: usize,
    max_rss_growth_bytes: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ProviderOutageConfig {
    operations: usize,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CancellationStormConfig {
    operations: usize,
    max_concurrent: u32,
    max_waiting: u32,
    start_timeout_ms: u64,
    settle_timeout_ms: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DiskFullConfig {
    payload_bytes: usize,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DatabaseLockConfig {
    busy_timeout_ms: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct NetworkPartitionConfig {
    operations: usize,
    recovery_wait_ms: u64,
}

#[derive(Debug, Serialize)]
struct SourceMetadata {
    commit: String,
    dirty: Option<bool>,
    rustc: String,
}

#[derive(Debug, Serialize)]
struct ScenarioResult {
    name: &'static str,
    elapsed_ms: f64,
    passed: bool,
    checks: BTreeMap<String, bool>,
    observed: BTreeMap<String, u64>,
    notes: Vec<String>,
}

#[derive(Debug, Serialize)]
struct QualificationReport {
    schema_version: u32,
    suite: String,
    generated_at: String,
    qualification_class: &'static str,
    production_claim_allowed: bool,
    build_profile: &'static str,
    smoke_scaled: bool,
    source: SourceMetadata,
    configuration: SuiteConfig,
    scenarios: Vec<ScenarioResult>,
    passed: bool,
    caveats: Vec<&'static str>,
}

#[derive(Default)]
struct Cli {
    config: Option<PathBuf>,
    output: Option<PathBuf>,
    selected: Vec<String>,
    run_all: bool,
    validate_only: bool,
    smoke: bool,
    allow_debug: bool,
}

fn parse_cli() -> Result<Cli, String> {
    let mut cli = Cli::default();
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--config" => {
                cli.config = Some(PathBuf::from(
                    args.next().ok_or("--config requires a path")?,
                ));
            }
            "--output" => {
                cli.output = Some(PathBuf::from(
                    args.next().ok_or("--output requires a path")?,
                ));
            }
            "--scenario" => cli
                .selected
                .push(args.next().ok_or("--scenario requires a name")?),
            "--all" => cli.run_all = true,
            "--validate" => cli.validate_only = true,
            "--smoke" => cli.smoke = true,
            "--allow-debug" => cli.allow_debug = true,
            "-h" | "--help" => {
                println!(
                    "resilience-qualification [--config PATH] [--validate] \\\n+                     [--all | --scenario NAME ...] [--output PATH] [--smoke] [--allow-debug]"
                );
                std::process::exit(0);
            }
            other => return Err(format!("unknown argument {other:?}")),
        }
    }
    if cli.run_all && !cli.selected.is_empty() {
        return Err("--all and --scenario cannot be combined".into());
    }
    Ok(cli)
}

fn read_config(path: Option<&Path>) -> Result<SuiteConfig, String> {
    let source = match path {
        Some(path) => std::fs::read_to_string(path)
            .map_err(|error| format!("read {}: {error}", path.display()))?,
        None => DEFAULT_CONFIG.to_string(),
    };
    toml::from_str(&source).map_err(|error| format!("parse resilience config: {error}"))
}

fn validate_config(config: &SuiteConfig) -> Result<(), String> {
    if config.schema_version != 1 {
        return Err(format!(
            "unsupported suite schema version {}",
            config.schema_version
        ));
    }
    if config.suite.trim().is_empty() {
        return Err("suite name cannot be empty".into());
    }
    let overload = &config.turn_overload;
    if overload.max_concurrent == 0 || overload.max_waiting == 0 {
        return Err("turn overload requires finite non-zero active and waiting limits".into());
    }
    if overload.operations <= overload.max_concurrent as usize + overload.max_waiting as usize {
        return Err("turn overload operations must exceed active plus waiting capacity".into());
    }
    if overload.provider_delay_ms == 0
        || overload.memory_waves < 2
        || overload.max_rss_growth_bytes == 0
        || overload.max_rss_growth_bytes > MAX_CONFIGURED_RSS_GROWTH_BYTES
    {
        return Err(
            "turn overload requires a non-zero delay, at least two memory waves, and a finite RSS growth limit"
                .into(),
        );
    }
    let clients = &config.slow_clients;
    if clients.connection_limit == 0
        || clients.excess_connections == 0
        || clients.idle_timeout_ms == 0
        || clients.memory_waves < 2
        || clients.max_rss_growth_bytes == 0
        || clients.max_rss_growth_bytes > MAX_CONFIGURED_RSS_GROWTH_BYTES
    {
        return Err(
            "slow clients requires finite non-zero limits, a timeout, at least two memory waves, and an RSS growth limit"
                .into(),
        );
    }
    if config.provider_outage.operations == 0 {
        return Err("provider outage operations must be non-zero".into());
    }
    let cancellations = &config.cancellation_storm;
    if cancellations.operations == 0
        || cancellations.max_concurrent == 0
        || cancellations.max_waiting < cancellations.operations as u32
        || cancellations.start_timeout_ms == 0
        || cancellations.settle_timeout_ms == 0
    {
        return Err(
            "cancellation storm requires non-zero operations/timeouts and waiting capacity for every operation"
                .into(),
        );
    }
    if config.disk_full.payload_bytes < 64 * 1024 || config.disk_full.payload_bytes > 900 * 1024 {
        return Err("disk full payload_bytes must be between 65536 and 921600".into());
    }
    if config.database_lock.busy_timeout_ms < 5_500 || config.database_lock.busy_timeout_ms > 30_000
    {
        return Err("database lock busy_timeout_ms must be between 5500 and 30000".into());
    }
    if config.network_partition.operations != 1
        || config.network_partition.recovery_wait_ms < 30_000
        || config.network_partition.recovery_wait_ms > 60_000
    {
        return Err(
            "network partition requires one operation and a 30000-60000ms circuit recovery wait"
                .into(),
        );
    }
    Ok(())
}

fn smoke_scale(config: &SuiteConfig) -> SuiteConfig {
    let mut scaled = config.clone();
    scaled.turn_overload.provider_delay_ms = 50;
    scaled.turn_overload.memory_waves = 2;
    scaled.slow_clients.memory_waves = 2;
    scaled.provider_outage.operations = scaled.provider_outage.operations.min(2);
    scaled.cancellation_storm.operations = scaled.cancellation_storm.operations.min(4);
    scaled.cancellation_storm.max_concurrent = scaled.cancellation_storm.max_concurrent.min(2);
    scaled.cancellation_storm.max_waiting = scaled.cancellation_storm.operations as u32;
    scaled
}

fn selected_scenarios(cli: &Cli) -> Result<Vec<&'static str>, String> {
    if cli.run_all {
        return Ok(SCENARIOS.to_vec());
    }
    if cli.selected.is_empty() {
        return Ok(Vec::new());
    }
    let unknown = cli
        .selected
        .iter()
        .filter(|name| !SCENARIOS.contains(&name.as_str()))
        .cloned()
        .collect::<Vec<_>>();
    if !unknown.is_empty() {
        return Err(format!("unknown scenarios: {}", unknown.join(", ")));
    }
    Ok(SCENARIOS
        .iter()
        .copied()
        .filter(|name| cli.selected.iter().any(|selected| selected == name))
        .collect())
}

struct DelayedProvider {
    id: ProviderId,
    delay: Duration,
}

struct DelayedSession {
    id: ProviderId,
    delay: Duration,
}

#[async_trait::async_trait]
impl LlmSession for DelayedSession {
    async fn send(&self, messages: Vec<StandardMessage>) -> Result<LlmResponse, ConnectorError> {
        tokio::time::sleep(self.delay).await;
        let input = messages
            .iter()
            .map(|message| message.content.len().div_ceil(4))
            .sum::<usize>()
            .min(u32::MAX as usize) as u32;
        Ok(LlmResponse {
            content: "resilience response".into(),
            finish_reason: Some("stop".into()),
            tokens_used: input.saturating_add(4),
            usage: kernel::connector::LlmUsage::reported(input, 4, 0),
            tool_calls: Vec::new(),
        })
    }

    async fn send_with_tools(
        &self,
        messages: Vec<StandardMessage>,
        _tools: &[ToolDefinition],
    ) -> Result<LlmResponse, ConnectorError> {
        self.send(messages).await
    }

    async fn send_with_options(
        &self,
        messages: Vec<StandardMessage>,
        _tools: &[ToolDefinition],
        _options: LlmRequestOptions,
    ) -> Result<LlmResponse, ConnectorError> {
        self.send(messages).await
    }

    fn provider_id(&self) -> &ProviderId {
        &self.id
    }

    fn model_id(&self) -> &str {
        "deterministic-resilience-v1"
    }

    fn enforces_max_output_tokens(&self) -> bool {
        true
    }
}

#[async_trait::async_trait]
impl LlmProviderAdapter for DelayedProvider {
    fn id(&self) -> &ProviderId {
        &self.id
    }

    fn name(&self) -> &str {
        "resilience-delayed-provider"
    }

    fn provider_type(&self) -> ProviderType {
        ProviderType::Local
    }

    async fn is_available(&self) -> bool {
        true
    }

    async fn create_session(&self) -> Result<Box<dyn LlmSession>, ConnectorError> {
        Ok(Box::new(DelayedSession {
            id: self.id.clone(),
            delay: self.delay,
        }))
    }

    fn translate_to_provider(&self, message: &StandardMessage) -> serde_json::Value {
        serde_json::json!({"role": message.role, "content": message.content})
    }

    fn translate_from_provider(&self, value: &serde_json::Value) -> Option<StandardMessage> {
        Some(StandardMessage::assistant(value.get("content")?.as_str()?))
    }
}

struct OutageProvider {
    id: ProviderId,
}

struct OutageSession {
    id: ProviderId,
}

#[async_trait::async_trait]
impl LlmSession for OutageSession {
    async fn send(&self, _messages: Vec<StandardMessage>) -> Result<LlmResponse, ConnectorError> {
        Err(ConnectorError::service_unavailable(
            self.id.clone(),
            "injected provider outage",
            None,
        ))
    }

    async fn send_with_tools(
        &self,
        _messages: Vec<StandardMessage>,
        _tools: &[ToolDefinition],
    ) -> Result<LlmResponse, ConnectorError> {
        self.send(Vec::new()).await
    }

    fn provider_id(&self) -> &ProviderId {
        &self.id
    }

    fn model_id(&self) -> &str {
        "injected-outage-v1"
    }

    fn enforces_max_output_tokens(&self) -> bool {
        true
    }
}

#[async_trait::async_trait]
impl LlmProviderAdapter for OutageProvider {
    fn id(&self) -> &ProviderId {
        &self.id
    }

    fn name(&self) -> &str {
        "resilience-outage-provider"
    }

    fn provider_type(&self) -> ProviderType {
        ProviderType::Local
    }

    async fn is_available(&self) -> bool {
        true
    }

    async fn create_session(&self) -> Result<Box<dyn LlmSession>, ConnectorError> {
        Ok(Box::new(OutageSession {
            id: self.id.clone(),
        }))
    }

    fn translate_to_provider(&self, message: &StandardMessage) -> serde_json::Value {
        serde_json::json!({"role": message.role, "content": message.content})
    }

    fn translate_from_provider(&self, value: &serde_json::Value) -> Option<StandardMessage> {
        Some(StandardMessage::assistant(value.get("content")?.as_str()?))
    }
}

struct CancellationProvider {
    id: ProviderId,
    started: Arc<AtomicU64>,
    cancelled: Arc<AtomicU64>,
}

struct CancellationSession {
    id: ProviderId,
    started: Arc<AtomicU64>,
    cancelled: Arc<AtomicU64>,
}

#[async_trait::async_trait]
impl LlmSession for CancellationSession {
    async fn send(&self, messages: Vec<StandardMessage>) -> Result<LlmResponse, ConnectorError> {
        self.send_with_tools(messages, &[]).await
    }

    async fn send_with_tools(
        &self,
        _messages: Vec<StandardMessage>,
        _tools: &[ToolDefinition],
    ) -> Result<LlmResponse, ConnectorError> {
        std::future::pending::<Result<LlmResponse, ConnectorError>>().await
    }

    async fn send_streaming_events_controlled(
        &self,
        _messages: Vec<StandardMessage>,
        _tools: &[ToolDefinition],
        _options: LlmRequestOptions,
        cancellation: &tokio_util::sync::CancellationToken,
        events: ProviderEventSink,
    ) -> Result<LlmResponse, ConnectorError> {
        self.started.fetch_add(1, Ordering::Relaxed);
        events
            .emit(ProviderStreamEvent::TextDelta(
                "provider-active-before-cancel".into(),
            ))
            .await;
        cancellation.cancelled().await;
        self.cancelled.fetch_add(1, Ordering::Relaxed);
        Err(ConnectorError::cancelled(self.id.clone(), None))
    }

    fn provider_id(&self) -> &ProviderId {
        &self.id
    }

    fn model_id(&self) -> &str {
        "injected-cancellation-v1"
    }

    fn enforces_max_output_tokens(&self) -> bool {
        true
    }
}

#[async_trait::async_trait]
impl LlmProviderAdapter for CancellationProvider {
    fn id(&self) -> &ProviderId {
        &self.id
    }

    fn name(&self) -> &str {
        "resilience-cancellation-provider"
    }

    fn provider_type(&self) -> ProviderType {
        ProviderType::Local
    }

    async fn is_available(&self) -> bool {
        true
    }

    async fn create_session(&self) -> Result<Box<dyn LlmSession>, ConnectorError> {
        Ok(Box::new(CancellationSession {
            id: self.id.clone(),
            started: Arc::clone(&self.started),
            cancelled: Arc::clone(&self.cancelled),
        }))
    }

    fn capabilities(&self) -> ProviderCapabilities {
        ProviderCapabilities {
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

struct NetworkPartitionProvider {
    id: ProviderId,
    endpoint: std::net::SocketAddr,
}

struct NetworkPartitionSession {
    id: ProviderId,
    endpoint: std::net::SocketAddr,
}

#[async_trait::async_trait]
impl LlmSession for NetworkPartitionSession {
    async fn send(&self, messages: Vec<StandardMessage>) -> Result<LlmResponse, ConnectorError> {
        self.send_with_tools(messages, &[]).await
    }

    async fn send_with_tools(
        &self,
        messages: Vec<StandardMessage>,
        _tools: &[ToolDefinition],
    ) -> Result<LlmResponse, ConnectorError> {
        let mut stream = tokio::net::TcpStream::connect(self.endpoint)
            .await
            .map_err(|error| {
                ConnectorError::ConnectionFailed(format!(
                    "provider network partition connect failed: {error}"
                ))
            })?;
        stream.write_all(b"agentos").await.map_err(|error| {
            ConnectorError::ConnectionFailed(format!(
                "provider network partition write failed: {error}"
            ))
        })?;
        let mut response = [0_u8; 2];
        stream.read_exact(&mut response).await.map_err(|error| {
            ConnectorError::ConnectionFailed(format!(
                "provider network partition response failed: {error}"
            ))
        })?;
        if response != *b"ok" {
            return Err(ConnectorError::ProtocolError(
                "network fixture returned an invalid provider response".into(),
            ));
        }
        let input = messages
            .iter()
            .map(|message| message.content.len().div_ceil(4))
            .sum::<usize>()
            .min(u32::MAX as usize) as u32;
        Ok(LlmResponse {
            content: "network recovered".into(),
            finish_reason: Some("stop".into()),
            tokens_used: input.saturating_add(4),
            usage: kernel::connector::LlmUsage::reported(input, 4, 0),
            tool_calls: Vec::new(),
        })
    }

    fn provider_id(&self) -> &ProviderId {
        &self.id
    }

    fn model_id(&self) -> &str {
        "loopback-network-partition-v1"
    }

    fn enforces_max_output_tokens(&self) -> bool {
        true
    }
}

#[async_trait::async_trait]
impl LlmProviderAdapter for NetworkPartitionProvider {
    fn id(&self) -> &ProviderId {
        &self.id
    }

    fn name(&self) -> &str {
        "resilience-network-partition-provider"
    }

    fn provider_type(&self) -> ProviderType {
        ProviderType::Local
    }

    async fn is_available(&self) -> bool {
        true
    }

    async fn create_session(&self) -> Result<Box<dyn LlmSession>, ConnectorError> {
        Ok(Box::new(NetworkPartitionSession {
            id: self.id.clone(),
            endpoint: self.endpoint,
        }))
    }

    fn translate_to_provider(&self, message: &StandardMessage) -> serde_json::Value {
        serde_json::json!({"role": message.role, "content": message.content})
    }

    fn translate_from_provider(&self, value: &serde_json::Value) -> Option<StandardMessage> {
        Some(StandardMessage::assistant(value.get("content")?.as_str()?))
    }
}

struct TemporaryState {
    directory: PathBuf,
}

impl TemporaryState {
    fn new(label: &str) -> Result<Self, String> {
        let directory = std::env::temp_dir().join(format!(
            "aiagentos-resilience-{label}-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir(&directory)
            .map_err(|error| format!("create {}: {error}", directory.display()))?;
        Ok(Self { directory })
    }

    fn database(&self) -> PathBuf {
        self.directory.join("agent_os.db")
    }
}

impl Drop for TemporaryState {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

fn qualification_kernel(budgets: &BudgetConfig) -> Result<AgentKernelImpl, String> {
    let context = Arc::new(SqliteContextManager::in_memory().map_err(|error| error.to_string())?);
    let config = Config::default();
    AgentKernelImpl::with_context_manager(context, budgets, config.mac_enforcing, &config.mac_rules)
        .map_err(|error| error.to_string())
}

async fn start_server(
    kernel: Arc<AgentKernelImpl>,
    connection_limit: usize,
    idle_timeout: Duration,
) -> Result<
    (
        std::net::SocketAddr,
        kernel::syscall_server::WireConnectionMetrics,
        JoinHandle<std::io::Result<()>>,
    ),
    String,
> {
    let server = SyscallServer::bind(kernel, "127.0.0.1:0")
        .await
        .map_err(|error| error.to_string())?
        .with_connection_limit(connection_limit)
        .with_idle_timeout(idle_timeout);
    let address = server.local_addr().map_err(|error| error.to_string())?;
    let metrics = server.connection_metrics();
    Ok((address, metrics, tokio::spawn(server.serve())))
}

async fn stop_server(task: JoinHandle<std::io::Result<()>>) {
    task.abort();
    let _ = task.await;
}

fn result(
    name: &'static str,
    started: Instant,
    checks: BTreeMap<String, bool>,
    observed: BTreeMap<String, u64>,
    notes: Vec<String>,
) -> ScenarioResult {
    ScenarioResult {
        name,
        elapsed_ms: started.elapsed().as_secs_f64() * 1_000.0,
        passed: checks.values().all(|passed| *passed),
        checks,
        observed,
        notes,
    }
}

#[cfg(target_os = "linux")]
fn process_rss_bytes() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let line = status.lines().find(|line| line.starts_with("VmRSS:"))?;
    line.split_whitespace()
        .nth(1)?
        .parse::<u64>()
        .ok()
        .map(|kilobytes| kilobytes.saturating_mul(1024))
}

#[cfg(target_os = "macos")]
fn process_rss_bytes() -> Option<u64> {
    let pid = std::process::id().to_string();
    command_output("ps", &["-o", "rss=", "-p", &pid])
        .and_then(|value| value.trim().parse::<u64>().ok())
        .map(|kilobytes| kilobytes.saturating_mul(1024))
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn process_rss_bytes() -> Option<u64> {
    None
}

fn retain_peak(peak: &mut Option<u64>, sample: Option<u64>) {
    if let Some(sample) = sample {
        *peak = Some(peak.unwrap_or(0).max(sample));
    }
}

fn rss_deltas(
    baseline: Option<u64>,
    peak: Option<u64>,
    settled_samples: &[u64],
) -> (Option<u64>, Option<u64>) {
    let peak_delta = peak
        .zip(baseline)
        .map(|(peak, baseline)| peak.saturating_sub(baseline));
    let steady_growth = settled_samples
        .last()
        .zip(settled_samples.first())
        .map(|(last, first)| last.saturating_sub(*first));
    (peak_delta, steady_growth)
}

async fn turn_overload(config: &TurnOverloadConfig) -> Result<ScenarioResult, String> {
    let mut budgets = BudgetConfig {
        max_concurrent: config.max_concurrent,
        max_waiting_turns: config.max_waiting,
        rpm: 10_000,
        tpm: 100_000_000,
        ..BudgetConfig::default()
    };
    budgets.agent_tokens_per_min = budgets.tpm;
    let kernel = Arc::new(qualification_kernel(&budgets)?);
    let provider = "resilience-delay";
    kernel
        .register_provider(Arc::new(DelayedProvider {
            id: provider.into(),
            delay: Duration::from_millis(config.provider_delay_ms),
        }))
        .map_err(|error| error.to_string())?;
    let (address, _, task) = start_server(
        Arc::clone(&kernel),
        config.operations + 4,
        Duration::from_secs(30),
    )
    .await?;
    let mut setup = KernelClient::connect(address)
        .await
        .map_err(|error| error.to_string())?;
    let mut agents = Vec::with_capacity(config.operations);
    for operation in 0..config.operations {
        agents.push(
            setup
                .create_agent(
                    format!("overload-{operation}"),
                    "bounded turn overload qualification",
                    Some(provider.into()),
                    Some("read-only".into()),
                    Some(3),
                )
                .await
                .map_err(|error| error.to_string())?,
        );
    }
    setup.close().await.map_err(|error| error.to_string())?;

    let baseline_rss = process_rss_bytes();
    let done = Arc::new(AtomicBool::new(false));
    let monitor_kernel = Arc::clone(&kernel);
    let monitor_done = Arc::clone(&done);
    let monitor = tokio::spawn(async move {
        let mut peak_active = 0;
        let mut peak_waiting = 0;
        let mut peak_rss = process_rss_bytes();
        while !monitor_done.load(Ordering::Relaxed) {
            let snapshot = MetricsSnapshot::collect(&monitor_kernel);
            peak_active = peak_active.max(snapshot.active_turns);
            peak_waiting = peak_waiting.max(snapshot.waiting_turns);
            retain_peak(&mut peak_rss, process_rss_bytes());
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        retain_peak(&mut peak_rss, process_rss_bytes());
        (peak_active, peak_waiting, peak_rss)
    });

    let started = Instant::now();
    let mut successes = 0_u64;
    let mut overload_rejections = 0_u64;
    let mut unexpected_failures = 0_u64;
    let mut notes = Vec::new();
    let mut settled_rss = Vec::with_capacity(config.memory_waves);
    for _ in 0..config.memory_waves {
        let mut clients = Vec::with_capacity(config.operations);
        for _ in 0..config.operations {
            clients.push(
                KernelClient::connect(address)
                    .await
                    .map_err(|error| error.to_string())?,
            );
        }
        let barrier = Arc::new(Barrier::new(config.operations + 1));
        let mut workers = JoinSet::new();
        for (mut client, agent_id) in clients.into_iter().zip(agents.iter().cloned()) {
            let barrier = Arc::clone(&barrier);
            workers.spawn(async move {
                barrier.wait().await;
                let outcome = client
                    .send_message(agent_id, "overload qualification")
                    .await
                    .map(|_| ())
                    .map_err(|error| error.to_string());
                let _ = client.close().await;
                outcome
            });
        }
        barrier.wait().await;
        while let Some(joined) = workers.join_next().await {
            match joined.map_err(|error| error.to_string())? {
                Ok(()) => successes += 1,
                Err(error) if error.contains("Turn admission queue is full") => {
                    overload_rejections += 1;
                }
                Err(error) => {
                    unexpected_failures += 1;
                    if notes.len() < 5 {
                        notes.push(error);
                    }
                }
            }
        }
        if let Some(rss) = process_rss_bytes() {
            settled_rss.push(rss);
        }
    }
    done.store(true, Ordering::Relaxed);
    let (peak_active, peak_waiting, peak_rss) = monitor.await.map_err(|error| error.to_string())?;
    let (peak_rss_delta, steady_rss_growth) = rss_deltas(baseline_rss, peak_rss, &settled_rss);
    let final_metrics = MetricsSnapshot::collect(&kernel);
    let mut recovery = KernelClient::connect(address)
        .await
        .map_err(|error| error.to_string())?;
    let recovery_ok = recovery.ping().await.is_ok() && recovery.close().await.is_ok();

    let expected = (config.operations as u64).saturating_mul(config.memory_waves as u64);
    let mut checks = BTreeMap::new();
    checks.insert(
        "all_requests_accounted".into(),
        successes + overload_rejections + unexpected_failures == expected,
    );
    checks.insert("overload_rejected".into(), overload_rejections > 0);
    checks.insert("no_unexpected_failures".into(), unexpected_failures == 0);
    checks.insert(
        "active_turns_bounded".into(),
        peak_active <= u64::from(config.max_concurrent),
    );
    checks.insert(
        "waiting_turns_bounded".into(),
        peak_waiting <= u64::from(config.max_waiting),
    );
    checks.insert(
        "turn_gauges_drained".into(),
        final_metrics.active_turns == 0 && final_metrics.waiting_turns == 0,
    );
    checks.insert(
        "quota_receipts_drained".into(),
        final_metrics.quota_reserved_receipts == 0 && final_metrics.quota_in_flight_receipts == 0,
    );
    checks.insert("server_recovers".into(), recovery_ok);
    if let Some(growth) = peak_rss_delta {
        checks.insert(
            "provider_backpressure_peak_rss_bounded".into(),
            growth <= config.max_rss_growth_bytes,
        );
    } else {
        notes.push("process RSS is unavailable on this operating system".into());
    }
    if let Some(growth) = steady_rss_growth {
        checks.insert(
            "provider_backpressure_steady_rss_bounded".into(),
            growth <= config.max_rss_growth_bytes,
        );
    }
    let observed = BTreeMap::from([
        ("successful_requests".into(), successes),
        ("overload_rejections".into(), overload_rejections),
        ("unexpected_failures".into(), unexpected_failures),
        ("peak_active_turns".into(), peak_active),
        ("peak_waiting_turns".into(), peak_waiting),
        (
            "configured_active_turn_limit".into(),
            u64::from(config.max_concurrent),
        ),
        (
            "configured_waiting_turn_limit".into(),
            u64::from(config.max_waiting),
        ),
        ("memory_waves".into(), config.memory_waves as u64),
        (
            "rss_samples".into(),
            settled_rss
                .len()
                .saturating_add(usize::from(baseline_rss.is_some())) as u64,
        ),
        (
            "baseline_rss_bytes".into(),
            baseline_rss.unwrap_or(u64::MAX),
        ),
        ("peak_rss_bytes".into(), peak_rss.unwrap_or(u64::MAX)),
        (
            "first_settled_rss_bytes".into(),
            settled_rss.first().copied().unwrap_or(u64::MAX),
        ),
        (
            "last_settled_rss_bytes".into(),
            settled_rss.last().copied().unwrap_or(u64::MAX),
        ),
        (
            "peak_rss_growth_bytes".into(),
            peak_rss_delta.unwrap_or(u64::MAX),
        ),
        (
            "steady_rss_growth_bytes".into(),
            steady_rss_growth.unwrap_or(u64::MAX),
        ),
        ("max_rss_growth_bytes".into(), config.max_rss_growth_bytes),
    ]);
    stop_server(task).await;
    kernel.shutdown().await.map_err(|error| error.to_string())?;
    Ok(result("turn-overload", started, checks, observed, notes))
}

async fn wait_for_wire(
    metrics: &kernel::syscall_server::WireConnectionMetrics,
    timeout: Duration,
    predicate: impl Fn(WireConnectionSnapshot) -> bool,
) -> bool {
    tokio::time::timeout(timeout, async {
        loop {
            if predicate(metrics.snapshot()) {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .is_ok()
}

async fn slow_clients(config: &SlowClientsConfig) -> Result<ScenarioResult, String> {
    let kernel = Arc::new(qualification_kernel(&BudgetConfig::default())?);
    let (address, metrics, task) = start_server(
        Arc::clone(&kernel),
        config.connection_limit,
        Duration::from_millis(config.idle_timeout_ms),
    )
    .await?;
    let started = Instant::now();
    let baseline_rss = process_rss_bytes();
    let mut peak_rss = baseline_rss;
    let mut settled_rss = Vec::with_capacity(config.memory_waves);
    let mut all_saturated = true;
    let mut all_reaped = true;
    let mut excess_rejected = 0_u64;
    for wave in 0..config.memory_waves {
        let mut holders = Vec::with_capacity(config.connection_limit);
        for _ in 0..config.connection_limit {
            holders.push(
                KernelClient::connect(address)
                    .await
                    .map_err(|error| error.to_string())?,
            );
        }
        all_saturated &= wait_for_wire(&metrics, Duration::from_secs(2), |snapshot| {
            snapshot.active == config.connection_limit
        })
        .await;
        retain_peak(&mut peak_rss, process_rss_bytes());
        for _ in 0..config.excess_connections {
            match KernelClient::connect(address).await {
                Ok(mut client) => {
                    if client.ping().await.is_err() {
                        excess_rejected += 1;
                    }
                }
                Err(_) => excess_rejected += 1,
            }
        }
        retain_peak(&mut peak_rss, process_rss_bytes());
        let expected_timeouts = (wave + 1).saturating_mul(config.connection_limit) as u64;
        all_reaped &= wait_for_wire(&metrics, Duration::from_secs(5), |snapshot| {
            snapshot.active == 0 && snapshot.idle_timeouts_total >= expected_timeouts
        })
        .await;
        drop(holders);
        if let Some(rss) = process_rss_bytes() {
            settled_rss.push(rss);
        }
    }
    let (peak_rss_delta, steady_rss_growth) = rss_deltas(baseline_rss, peak_rss, &settled_rss);
    let mut recovery = KernelClient::connect(address)
        .await
        .map_err(|error| error.to_string())?;
    let recovery_ok = recovery.ping().await.is_ok() && recovery.close().await.is_ok();
    let drained = wait_for_wire(&metrics, Duration::from_secs(2), |snapshot| {
        snapshot.active == 0
    })
    .await;
    let final_metrics = metrics.snapshot();

    let mut checks = BTreeMap::new();
    checks.insert("connection_limit_reached_each_wave".into(), all_saturated);
    checks.insert(
        "all_excess_connections_rejected".into(),
        excess_rejected
            == (config.excess_connections as u64).saturating_mul(config.memory_waves as u64),
    );
    checks.insert(
        "active_connections_bounded".into(),
        final_metrics.peak_active <= config.connection_limit,
    );
    checks.insert("slow_connections_reaped_each_wave".into(), all_reaped);
    checks.insert("permits_drained".into(), drained);
    checks.insert("server_recovers".into(), recovery_ok);
    let mut notes = Vec::new();
    if let Some(growth) = peak_rss_delta {
        checks.insert(
            "slow_client_peak_rss_bounded".into(),
            growth <= config.max_rss_growth_bytes,
        );
    } else {
        notes.push("process RSS is unavailable on this operating system".into());
    }
    if let Some(growth) = steady_rss_growth {
        checks.insert(
            "slow_client_steady_rss_bounded".into(),
            growth <= config.max_rss_growth_bytes,
        );
    }
    let observed = BTreeMap::from([
        ("connection_capacity".into(), final_metrics.capacity as u64),
        (
            "peak_active_connections".into(),
            final_metrics.peak_active as u64,
        ),
        ("admitted_connections".into(), final_metrics.admitted_total),
        ("rejected_connections".into(), final_metrics.rejected_total),
        ("observed_excess_rejections".into(), excess_rejected),
        ("idle_timeouts".into(), final_metrics.idle_timeouts_total),
        (
            "final_active_connections".into(),
            final_metrics.active as u64,
        ),
        ("memory_waves".into(), config.memory_waves as u64),
        (
            "rss_samples".into(),
            settled_rss
                .len()
                .saturating_add(usize::from(baseline_rss.is_some())) as u64,
        ),
        (
            "baseline_rss_bytes".into(),
            baseline_rss.unwrap_or(u64::MAX),
        ),
        ("peak_rss_bytes".into(), peak_rss.unwrap_or(u64::MAX)),
        (
            "first_settled_rss_bytes".into(),
            settled_rss.first().copied().unwrap_or(u64::MAX),
        ),
        (
            "last_settled_rss_bytes".into(),
            settled_rss.last().copied().unwrap_or(u64::MAX),
        ),
        (
            "peak_rss_growth_bytes".into(),
            peak_rss_delta.unwrap_or(u64::MAX),
        ),
        (
            "steady_rss_growth_bytes".into(),
            steady_rss_growth.unwrap_or(u64::MAX),
        ),
        ("max_rss_growth_bytes".into(), config.max_rss_growth_bytes),
    ]);
    stop_server(task).await;
    kernel.shutdown().await.map_err(|error| error.to_string())?;
    Ok(result("slow-clients", started, checks, observed, notes))
}

async fn provider_outage(config: &ProviderOutageConfig) -> Result<ScenarioResult, String> {
    let mut budgets = BudgetConfig {
        rpm: 10_000,
        tpm: 100_000_000,
        ..BudgetConfig::default()
    };
    budgets.agent_tokens_per_min = budgets.tpm;
    let kernel = Arc::new(qualification_kernel(&budgets)?);
    let provider = "resilience-outage";
    kernel
        .register_provider(Arc::new(OutageProvider {
            id: provider.into(),
        }))
        .map_err(|error| error.to_string())?;
    let (address, _, task) = start_server(Arc::clone(&kernel), 8, Duration::from_secs(30)).await?;
    let mut client = KernelClient::connect(address)
        .await
        .map_err(|error| error.to_string())?;
    let agent = client
        .create_agent(
            "provider-outage",
            "provider outage graceful degradation qualification",
            Some(provider.into()),
            Some("read-only".into()),
            Some(3),
        )
        .await
        .map_err(|error| error.to_string())?;
    let started = Instant::now();
    let mut classified_failures = 0_u64;
    let mut unexpected = 0_u64;
    let mut notes = Vec::new();
    for _ in 0..config.operations {
        match client.send_message(&agent, "injected outage").await {
            Err(SdkError::Wire {
                code: kernel::syscall_server::WireErrorCode::Unavailable,
                ..
            }) => classified_failures += 1,
            Err(error) => {
                unexpected += 1;
                if notes.len() < 5 {
                    notes.push(error.to_string());
                }
            }
            Ok(_) => {
                unexpected += 1;
                notes.push("provider outage unexpectedly returned success".into());
            }
        }
    }
    let recovery_ok = client.ping().await.is_ok();
    let final_metrics = MetricsSnapshot::collect(&kernel);
    let close_ok = client.close().await.is_ok();
    let mut checks = BTreeMap::new();
    checks.insert(
        "outage_failures_classified".into(),
        classified_failures == config.operations as u64,
    );
    checks.insert("no_unexpected_outcome".into(), unexpected == 0);
    checks.insert("control_plane_responsive".into(), recovery_ok && close_ok);
    checks.insert(
        "turn_and_llm_gauges_drained".into(),
        final_metrics.active_turns == 0
            && final_metrics.waiting_turns == 0
            && final_metrics.llm_requests_in_flight == 0
            && final_metrics.llm_requests_waiting == 0,
    );
    checks.insert(
        "quota_receipts_drained".into(),
        final_metrics.quota_reserved_receipts == 0 && final_metrics.quota_in_flight_receipts == 0,
    );
    let observed = BTreeMap::from([
        ("attempted_requests".into(), config.operations as u64),
        ("classified_outage_failures".into(), classified_failures),
        ("unexpected_outcomes".into(), unexpected),
        ("final_active_turns".into(), final_metrics.active_turns),
        (
            "final_llm_requests_in_flight".into(),
            final_metrics.llm_requests_in_flight,
        ),
        (
            "final_quota_receipts".into(),
            final_metrics
                .quota_reserved_receipts
                .saturating_add(final_metrics.quota_in_flight_receipts),
        ),
    ]);
    stop_server(task).await;
    kernel.shutdown().await.map_err(|error| error.to_string())?;
    Ok(result("provider-outage", started, checks, observed, notes))
}

async fn cancellation_storm(config: &CancellationStormConfig) -> Result<ScenarioResult, String> {
    let mut budgets = BudgetConfig {
        max_concurrent: config.max_concurrent,
        max_waiting_turns: config.max_waiting,
        rpm: 10_000,
        tpm: 100_000_000,
        ..BudgetConfig::default()
    };
    budgets.agent_tokens_per_min = budgets.tpm;
    let kernel = Arc::new(qualification_kernel(&budgets)?);
    let provider = "resilience-cancellation";
    let provider_started = Arc::new(AtomicU64::new(0));
    let provider_cancelled = Arc::new(AtomicU64::new(0));
    kernel
        .register_provider(Arc::new(CancellationProvider {
            id: provider.into(),
            started: Arc::clone(&provider_started),
            cancelled: Arc::clone(&provider_cancelled),
        }))
        .map_err(|error| error.to_string())?;
    let (address, wire, task) = start_server(
        Arc::clone(&kernel),
        config.operations + 4,
        Duration::from_secs(30),
    )
    .await?;
    let mut setup = KernelClient::connect(address)
        .await
        .map_err(|error| error.to_string())?;
    let mut agents = Vec::with_capacity(config.operations);
    for operation in 0..config.operations {
        agents.push(
            setup
                .create_agent(
                    format!("cancel-{operation}"),
                    "public request cancellation storm qualification",
                    Some(provider.into()),
                    Some("read-only".into()),
                    Some(3),
                )
                .await
                .map_err(|error| error.to_string())?,
        );
    }
    setup.close().await.map_err(|error| error.to_string())?;

    let mut stream_clients = Vec::with_capacity(config.operations);
    for _ in 0..config.operations {
        stream_clients.push(
            KernelClient::connect(address)
                .await
                .map_err(|error| error.to_string())?,
        );
    }
    let mut control = KernelClient::connect(address)
        .await
        .map_err(|error| error.to_string())?;
    let (started_tx, mut started_rx) = tokio::sync::mpsc::unbounded_channel();
    let started = Instant::now();
    let mut streams = JoinSet::new();
    let mut request_keys = Vec::with_capacity(config.operations);
    for (operation, (mut client, agent_id)) in stream_clients.into_iter().zip(agents).enumerate() {
        let request_id = format!("cancellation-storm-{operation}");
        request_keys.push((request_id.clone(), agent_id.clone()));
        let started_tx = started_tx.clone();
        streams.spawn(async move {
            let result = client
                .send_message_stream(
                    request_id,
                    agent_id,
                    "block until the exact public request is cancelled",
                    |event| {
                        if matches!(event, MessageStreamEvent::Started) {
                            let _ = started_tx.send(());
                        }
                    },
                )
                .await
                .map(|_| ());
            let close_ok = client.close().await.is_ok();
            (result, close_ok)
        });
    }
    drop(started_tx);

    let all_streams_started =
        tokio::time::timeout(Duration::from_millis(config.start_timeout_ms), async {
            for _ in 0..config.operations {
                started_rx
                    .recv()
                    .await
                    .ok_or("stream start channel closed early")?;
            }
            Ok::<(), &str>(())
        })
        .await
        .is_ok_and(|result| result.is_ok());

    let mut accepted = 0_u64;
    let mut cancel_errors = 0_u64;
    let mut notes = Vec::new();
    for (request_id, agent_id) in &request_keys {
        match control.cancel_request(request_id, agent_id).await {
            Ok(true) => accepted += 1,
            Ok(false) => {
                cancel_errors += 1;
                if notes.len() < 5 {
                    notes.push(format!("request {request_id} was not active"));
                }
            }
            Err(error) => {
                cancel_errors += 1;
                if notes.len() < 5 {
                    notes.push(error.to_string());
                }
            }
        }
    }

    let settled = tokio::time::timeout(Duration::from_millis(config.settle_timeout_ms), async {
        let mut terminal_cancelled = 0_u64;
        let mut unexpected = 0_u64;
        let mut connections_closed = 0_u64;
        while let Some(joined) = streams.join_next().await {
            match joined {
                Ok((
                    Err(SdkError::Wire {
                        code: WireErrorCode::Cancelled,
                        ..
                    }),
                    close_ok,
                )) => {
                    terminal_cancelled += 1;
                    connections_closed += u64::from(close_ok);
                }
                Ok((result, close_ok)) => {
                    unexpected += 1;
                    connections_closed += u64::from(close_ok);
                    if notes.len() < 5 {
                        notes.push(format!("unexpected stream result: {result:?}"));
                    }
                }
                Err(error) => {
                    unexpected += 1;
                    if notes.len() < 5 {
                        notes.push(error.to_string());
                    }
                }
            }
        }
        (terminal_cancelled, unexpected, connections_closed)
    })
    .await;
    let (terminal_cancelled, unexpected, connections_closed, settled_in_time) = match settled {
        Ok((terminal_cancelled, unexpected, connections_closed)) => {
            (terminal_cancelled, unexpected, connections_closed, true)
        }
        Err(_) => {
            streams.abort_all();
            while streams.join_next().await.is_some() {}
            notes.push("cancellation storm did not settle before the configured timeout".into());
            (0, config.operations as u64, 0, false)
        }
    };

    let mut inactive_after_settle = 0_u64;
    for (request_id, agent_id) in &request_keys {
        if matches!(
            control.cancel_request(request_id, agent_id).await,
            Ok(false)
        ) {
            inactive_after_settle += 1;
        }
    }
    let control_plane_responsive = control.ping().await.is_ok();
    let control_closed = control.close().await.is_ok();
    let wire_drained = wait_for_wire(&wire, Duration::from_secs(2), |snapshot| {
        snapshot.active == 0
    })
    .await;
    let final_wire = wire.snapshot();
    let final_metrics = MetricsSnapshot::collect(&kernel);
    let observed_provider_started = provider_started.load(Ordering::Relaxed);
    let observed_provider_cancelled = provider_cancelled.load(Ordering::Relaxed);

    let mut checks = BTreeMap::new();
    checks.insert("all_streams_started".into(), all_streams_started);
    checks.insert(
        "all_cancellations_accepted".into(),
        accepted == config.operations as u64 && cancel_errors == 0,
    );
    checks.insert("settled_before_deadline".into(), settled_in_time);
    checks.insert(
        "all_streams_terminated_cancelled".into(),
        terminal_cancelled == config.operations as u64 && unexpected == 0,
    );
    checks.insert(
        "stream_connections_closed".into(),
        connections_closed == config.operations as u64 && control_closed,
    );
    checks.insert(
        "request_registry_drained".into(),
        inactive_after_settle == config.operations as u64,
    );
    checks.insert(
        "active_provider_work_cancelled".into(),
        observed_provider_started > 0 && observed_provider_started == observed_provider_cancelled,
    );
    checks.insert(
        "turn_llm_and_quota_gauges_drained".into(),
        final_metrics.active_turns == 0
            && final_metrics.waiting_turns == 0
            && final_metrics.llm_requests_in_flight == 0
            && final_metrics.llm_requests_waiting == 0
            && final_metrics.quota_reserved_receipts == 0
            && final_metrics.quota_in_flight_receipts == 0,
    );
    checks.insert(
        "wire_permits_drained".into(),
        wire_drained && final_wire.active == 0,
    );
    checks.insert("control_plane_responsive".into(), control_plane_responsive);
    let observed = BTreeMap::from([
        ("attempted_streams".into(), config.operations as u64),
        ("accepted_cancellations".into(), accepted),
        ("cancellation_errors".into(), cancel_errors),
        ("terminal_cancelled_streams".into(), terminal_cancelled),
        ("unexpected_stream_outcomes".into(), unexpected),
        (
            "inactive_request_ids_after_settle".into(),
            inactive_after_settle,
        ),
        (
            "provider_requests_started".into(),
            observed_provider_started,
        ),
        (
            "provider_requests_cancelled".into(),
            observed_provider_cancelled,
        ),
        ("final_active_turns".into(), final_metrics.active_turns),
        (
            "final_llm_requests_in_flight".into(),
            final_metrics.llm_requests_in_flight,
        ),
        (
            "final_quota_receipts".into(),
            final_metrics
                .quota_reserved_receipts
                .saturating_add(final_metrics.quota_in_flight_receipts),
        ),
        (
            "peak_active_connections".into(),
            final_wire.peak_active as u64,
        ),
        ("final_active_connections".into(), final_wire.active as u64),
    ]);
    stop_server(task).await;
    kernel.shutdown().await.map_err(|error| error.to_string())?;
    Ok(result(
        "cancellation-storm",
        started,
        checks,
        observed,
        notes,
    ))
}

async fn restart_and_read(
    database: &Path,
    agent_id: &str,
    key: &str,
) -> Result<Option<String>, String> {
    let kernel = Arc::new(
        AgentKernelImpl::with_db_path(database)
            .map_err(|error| format!("restart kernel: {error}"))?,
    );
    let (address, _, task) = start_server(Arc::clone(&kernel), 4, Duration::from_secs(30)).await?;
    let mut client = KernelClient::connect(address)
        .await
        .map_err(|error| format!("restart client: {error}"))?;
    let value = client
        .storage_get(agent_id, key)
        .await
        .map_err(|error| format!("restart storage read: {error}"))?;
    client
        .close()
        .await
        .map_err(|error| format!("restart client close: {error}"))?;
    stop_server(task).await;
    kernel
        .shutdown()
        .await
        .map_err(|error| format!("restart shutdown: {error}"))?;
    Ok(value)
}

async fn disk_full(config: &DiskFullConfig) -> Result<ScenarioResult, String> {
    let state = TemporaryState::new("disk-full")?;
    let database = state.database();
    let kernel = Arc::new(
        AgentKernelImpl::with_db_path(&database)
            .map_err(|error| format!("create durable kernel: {error}"))?,
    );
    let (address, wire, task) =
        start_server(Arc::clone(&kernel), 4, Duration::from_secs(30)).await?;
    let mut client = KernelClient::connect(address)
        .await
        .map_err(|error| error.to_string())?;
    let agent_id = client
        .create_agent(
            "disk-full",
            "public durable storage capacity failure qualification",
            None,
            Some("read-only".into()),
            Some(3),
        )
        .await
        .map_err(|error| error.to_string())?;
    client
        .storage_put(&agent_id, "baseline", "committed-before-disk-full")
        .await
        .map_err(|error| error.to_string())?;
    let (page_count, free_pages) = kernel
        .context_manager
        .qualification_exhaust_storage()
        .map_err(|error| error.to_string())?;

    let started = Instant::now();
    let payload = "x".repeat(config.payload_bytes);
    let failure = client
        .storage_put(&agent_id, "must-rollback", payload)
        .await;
    let failure_is_typed = matches!(
        failure,
        Err(SdkError::Wire {
            code: WireErrorCode::Unavailable,
            retryable: true,
            ..
        })
    );
    let baseline_during_pressure = client
        .storage_get(&agent_id, "baseline")
        .await
        .map_err(|error| error.to_string())?;
    let failed_value_absent = client
        .storage_get(&agent_id, "must-rollback")
        .await
        .map_err(|error| error.to_string())?
        .is_none();
    kernel
        .context_manager
        .qualification_restore_storage_capacity()
        .map_err(|error| error.to_string())?;
    client
        .storage_put(&agent_id, "recovered", "written-after-capacity-restored")
        .await
        .map_err(|error| format!("post-capacity retry: {error}"))?;
    let recovered_value = client
        .storage_get(&agent_id, "recovered")
        .await
        .map_err(|error| error.to_string())?;
    let control_plane_responsive = client.ping().await.is_ok();
    let client_closed = client.close().await.is_ok();
    let wire_drained = wait_for_wire(&wire, Duration::from_secs(2), |snapshot| {
        snapshot.active == 0
    })
    .await;
    let final_wire = wire.snapshot();
    stop_server(task).await;
    kernel.shutdown().await.map_err(|error| error.to_string())?;
    drop(kernel);

    let connection = rusqlite::Connection::open(&database).map_err(|error| error.to_string())?;
    let quick_check: String = connection
        .query_row("PRAGMA quick_check", [], |row| row.get(0))
        .map_err(|error| format!("database quick_check: {error}"))?;
    drop(connection);

    let baseline_after_restart = restart_and_read(&database, &agent_id, "baseline").await?;
    let recovered_after_restart = restart_and_read(&database, &agent_id, "recovered").await?;

    let mut checks = BTreeMap::new();
    checks.insert("fixture_has_no_free_pages".into(), free_pages == 0);
    checks.insert("disk_full_is_typed_retryable".into(), failure_is_typed);
    checks.insert(
        "previous_commit_preserved".into(),
        baseline_during_pressure.as_deref() == Some("committed-before-disk-full"),
    );
    checks.insert("failed_transaction_rolled_back".into(), failed_value_absent);
    checks.insert(
        "retry_succeeds_after_capacity_restored".into(),
        recovered_value.as_deref() == Some("written-after-capacity-restored"),
    );
    checks.insert("database_integrity_preserved".into(), quick_check == "ok");
    checks.insert(
        "restart_preserves_commits".into(),
        baseline_after_restart.as_deref() == Some("committed-before-disk-full")
            && recovered_after_restart.as_deref() == Some("written-after-capacity-restored"),
    );
    checks.insert(
        "control_and_wire_recover".into(),
        control_plane_responsive && client_closed && wire_drained && final_wire.active == 0,
    );
    let observed = BTreeMap::from([
        ("database_page_count".into(), page_count.max(0) as u64),
        ("database_free_pages".into(), free_pages.max(0) as u64),
        ("injected_payload_bytes".into(), config.payload_bytes as u64),
        ("final_active_connections".into(), final_wire.active as u64),
    ]);
    Ok(result("disk-full", started, checks, observed, Vec::new()))
}

async fn database_lock(config: &DatabaseLockConfig) -> Result<ScenarioResult, String> {
    let state = TemporaryState::new("database-lock")?;
    let database = state.database();
    let kernel = Arc::new(
        AgentKernelImpl::with_db_path(&database)
            .map_err(|error| format!("create durable kernel: {error}"))?,
    );
    let (address, wire, task) =
        start_server(Arc::clone(&kernel), 6, Duration::from_secs(30)).await?;
    let mut control = KernelClient::connect(address)
        .await
        .map_err(|error| error.to_string())?;
    let agent_id = control
        .create_agent(
            "database-lock",
            "public durable database lock qualification",
            None,
            Some("read-only".into()),
            Some(3),
        )
        .await
        .map_err(|error| error.to_string())?;
    control
        .storage_put(&agent_id, "baseline", "committed-before-lock")
        .await
        .map_err(|error| error.to_string())?;

    let connection = rusqlite::Connection::open(&database).map_err(|error| error.to_string())?;
    connection
        .execute_batch("PRAGMA busy_timeout=0; BEGIN IMMEDIATE;")
        .map_err(|error| format!("hold database writer lock: {error}"))?;
    let mut writer = KernelClient::connect(address)
        .await
        .map_err(|error| error.to_string())?;
    let writer_agent = agent_id.clone();
    let started = Instant::now();
    let mut blocked_write = tokio::spawn(async move {
        let result = writer
            .storage_put(writer_agent, "blocked-write", "must-time-out")
            .await;
        let closed = writer.close().await.is_ok();
        (result, closed)
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    let ping_started = Instant::now();
    let control_plane_responsive = control.ping().await.is_ok();
    let ping_latency_ms = ping_started.elapsed().as_millis() as u64;

    let (write_result, writer_closed, settled) = match tokio::time::timeout(
        Duration::from_millis(config.busy_timeout_ms),
        &mut blocked_write,
    )
    .await
    {
        Ok(Ok((result, closed))) => (Some(result), closed, true),
        Ok(Err(error)) => {
            return Err(format!("database lock writer task failed: {error}"));
        }
        Err(_) => {
            blocked_write.abort();
            let _ = blocked_write.await;
            (None, false, false)
        }
    };
    let lock_is_typed = matches!(
        write_result,
        Some(Err(SdkError::Wire {
            code: WireErrorCode::Conflict,
            retryable: true,
            ..
        }))
    );
    connection
        .execute_batch("ROLLBACK;")
        .map_err(|error| format!("release database writer lock: {error}"))?;

    control
        .storage_put(&agent_id, "recovered", "written-after-lock-release")
        .await
        .map_err(|error| format!("post-lock retry: {error}"))?;
    let baseline = control
        .storage_get(&agent_id, "baseline")
        .await
        .map_err(|error| error.to_string())?;
    let blocked_absent = control
        .storage_get(&agent_id, "blocked-write")
        .await
        .map_err(|error| error.to_string())?
        .is_none();
    let recovered = control
        .storage_get(&agent_id, "recovered")
        .await
        .map_err(|error| error.to_string())?;
    let control_closed = control.close().await.is_ok();
    let wire_drained = wait_for_wire(&wire, Duration::from_secs(2), |snapshot| {
        snapshot.active == 0
    })
    .await;
    let final_wire = wire.snapshot();
    let quick_check: String = connection
        .query_row("PRAGMA quick_check", [], |row| row.get(0))
        .map_err(|error| format!("database quick_check: {error}"))?;
    drop(connection);
    stop_server(task).await;
    kernel.shutdown().await.map_err(|error| error.to_string())?;
    drop(kernel);
    let baseline_after_restart = restart_and_read(&database, &agent_id, "baseline").await?;
    let recovered_after_restart = restart_and_read(&database, &agent_id, "recovered").await?;

    let mut checks = BTreeMap::new();
    checks.insert("lock_failure_settles_before_deadline".into(), settled);
    checks.insert("lock_is_typed_retryable_conflict".into(), lock_is_typed);
    checks.insert(
        "control_plane_stays_responsive".into(),
        control_plane_responsive && ping_latency_ms < 2_000,
    );
    checks.insert("blocked_client_closes".into(), writer_closed);
    checks.insert(
        "previous_commit_preserved".into(),
        baseline.as_deref() == Some("committed-before-lock"),
    );
    checks.insert("timed_out_write_absent".into(), blocked_absent);
    checks.insert(
        "retry_succeeds_after_lock_release".into(),
        recovered.as_deref() == Some("written-after-lock-release"),
    );
    checks.insert("database_integrity_preserved".into(), quick_check == "ok");
    checks.insert(
        "restart_preserves_commits".into(),
        baseline_after_restart.as_deref() == Some("committed-before-lock")
            && recovered_after_restart.as_deref() == Some("written-after-lock-release"),
    );
    checks.insert(
        "wire_permits_drained".into(),
        control_closed && wire_drained && final_wire.active == 0,
    );
    let observed = BTreeMap::from([
        ("configured_deadline_ms".into(), config.busy_timeout_ms),
        ("control_ping_latency_ms".into(), ping_latency_ms),
        ("final_active_connections".into(), final_wire.active as u64),
    ]);
    Ok(result(
        "database-lock",
        started,
        checks,
        observed,
        Vec::new(),
    ))
}

async fn network_partition(config: &NetworkPartitionConfig) -> Result<ScenarioResult, String> {
    let partitioned = Arc::new(AtomicBool::new(true));
    let accepted = Arc::new(AtomicU64::new(0));
    let dropped = Arc::new(AtomicU64::new(0));
    let replied = Arc::new(AtomicU64::new(0));
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|error| error.to_string())?;
    let endpoint = listener.local_addr().map_err(|error| error.to_string())?;
    let fixture_partitioned = Arc::clone(&partitioned);
    let fixture_accepted = Arc::clone(&accepted);
    let fixture_dropped = Arc::clone(&dropped);
    let fixture_replied = Arc::clone(&replied);
    let fixture = tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await?;
            fixture_accepted.fetch_add(1, Ordering::Relaxed);
            if fixture_partitioned.load(Ordering::Acquire) {
                fixture_dropped.fetch_add(1, Ordering::Relaxed);
                drop(stream);
                continue;
            }
            let mut request = [0_u8; 7];
            stream.read_exact(&mut request).await?;
            if request == *b"agentos" {
                stream.write_all(b"ok").await?;
                fixture_replied.fetch_add(1, Ordering::Relaxed);
            }
        }
        #[allow(unreachable_code)]
        Ok::<(), std::io::Error>(())
    });

    let mut budgets = BudgetConfig {
        rpm: 10_000,
        tpm: 100_000_000,
        ..BudgetConfig::default()
    };
    budgets.agent_tokens_per_min = budgets.tpm;
    let kernel = Arc::new(qualification_kernel(&budgets)?);
    let provider = "resilience-network-partition";
    kernel
        .register_provider(Arc::new(NetworkPartitionProvider {
            id: provider.into(),
            endpoint,
        }))
        .map_err(|error| error.to_string())?;
    // Keep the public connection alive beyond the 30-second provider circuit
    // cooldown so the recovery attempt proves the same SDK session remains
    // usable; slow-client reaping is qualified separately.
    let (address, wire, task) =
        start_server(Arc::clone(&kernel), 4, Duration::from_secs(90)).await?;
    let mut client = KernelClient::connect(address)
        .await
        .map_err(|error| error.to_string())?;
    let agent_id = client
        .create_agent(
            "network-partition",
            "provider transport partition and recovery qualification",
            Some(provider.into()),
            Some("read-only".into()),
            Some(3),
        )
        .await
        .map_err(|error| error.to_string())?;
    let started = Instant::now();
    let mut typed_failures = 0_u64;
    let mut unexpected = 0_u64;
    let mut notes = Vec::new();
    for _ in 0..config.operations {
        match client
            .send_message(&agent_id, "request across a partitioned provider socket")
            .await
        {
            Err(SdkError::Wire {
                code: WireErrorCode::Provider,
                retryable: true,
                ..
            }) => typed_failures += 1,
            outcome => {
                unexpected += 1;
                if notes.len() < 5 {
                    notes.push(format!("unexpected partition outcome: {outcome:?}"));
                }
            }
        }
    }
    partitioned.store(false, Ordering::Release);
    tokio::time::sleep(Duration::from_millis(config.recovery_wait_ms)).await;
    let recovered = client
        .send_message(&agent_id, "provider network has recovered")
        .await
        .is_ok();
    let control_plane_responsive = client.ping().await.is_ok();
    let final_metrics = MetricsSnapshot::collect(&kernel);
    let client_closed = client.close().await.is_ok();
    let wire_drained = wait_for_wire(&wire, Duration::from_secs(2), |snapshot| {
        snapshot.active == 0
    })
    .await;
    let final_wire = wire.snapshot();
    stop_server(task).await;
    kernel.shutdown().await.map_err(|error| error.to_string())?;
    fixture.abort();
    let _ = fixture.await;

    let observed_accepted = accepted.load(Ordering::Relaxed);
    let observed_dropped = dropped.load(Ordering::Relaxed);
    let observed_replied = replied.load(Ordering::Relaxed);
    let mut checks = BTreeMap::new();
    checks.insert(
        "partition_failures_are_typed_retryable".into(),
        typed_failures == config.operations as u64 && unexpected == 0,
    );
    checks.insert(
        "real_socket_connections_were_dropped".into(),
        observed_dropped >= config.operations as u64,
    );
    checks.insert("provider_recovers_without_restart".into(), recovered);
    checks.insert(
        "recovery_crossed_same_socket_fixture".into(),
        observed_replied >= 1 && observed_accepted == observed_dropped + observed_replied,
    );
    checks.insert("control_plane_responsive".into(), control_plane_responsive);
    checks.insert(
        "turn_llm_and_quota_gauges_drained".into(),
        final_metrics.active_turns == 0
            && final_metrics.waiting_turns == 0
            && final_metrics.llm_requests_in_flight == 0
            && final_metrics.llm_requests_waiting == 0
            && final_metrics.quota_reserved_receipts == 0
            && final_metrics.quota_in_flight_receipts == 0,
    );
    checks.insert(
        "wire_permits_drained".into(),
        client_closed && wire_drained && final_wire.active == 0,
    );
    let observed = BTreeMap::from([
        (
            "logical_partition_requests".into(),
            config.operations as u64,
        ),
        ("circuit_recovery_wait_ms".into(), config.recovery_wait_ms),
        ("typed_partition_failures".into(), typed_failures),
        ("unexpected_outcomes".into(), unexpected),
        ("fixture_connections_accepted".into(), observed_accepted),
        ("fixture_connections_dropped".into(), observed_dropped),
        ("fixture_responses_sent".into(), observed_replied),
        ("final_active_connections".into(), final_wire.active as u64),
    ]);
    Ok(result(
        "network-partition",
        started,
        checks,
        observed,
        notes,
    ))
}

fn command_output(program: &str, args: &[&str]) -> Option<String> {
    Command::new(program)
        .args(args)
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|output| output.trim().to_string())
        .filter(|output| !output.is_empty())
}

fn source_metadata() -> SourceMetadata {
    SourceMetadata {
        commit: command_output("git", &["rev-parse", "HEAD"]).unwrap_or_else(|| "unknown".into()),
        dirty: Command::new("git")
            .args(["status", "--porcelain"])
            .output()
            .ok()
            .filter(|output| output.status.success())
            .map(|output| !output.stdout.is_empty()),
        rustc: command_output("rustc", &["--version"]).unwrap_or_else(|| "unknown".into()),
    }
}

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("resilience qualification failed: {error}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), String> {
    let cli = parse_cli()?;
    let mut config = read_config(cli.config.as_deref())?;
    validate_config(&config)?;
    let scenarios = selected_scenarios(&cli)?;
    if cli.validate_only || scenarios.is_empty() {
        println!(
            "validated {} schema v{} scenarios: {}",
            config.suite,
            config.schema_version,
            SCENARIOS.join(", ")
        );
        return Ok(());
    }
    if cfg!(debug_assertions) && !cli.allow_debug && !cli.smoke {
        return Err(
            "resilience runs require a --release build; use --allow-debug only for development"
                .into(),
        );
    }
    if cli.smoke {
        config = smoke_scale(&config);
    }

    let mut results = Vec::with_capacity(scenarios.len());
    for scenario in scenarios {
        eprintln!("running {scenario}");
        results.push(match scenario {
            "turn-overload" => turn_overload(&config.turn_overload).await?,
            "slow-clients" => slow_clients(&config.slow_clients).await?,
            "provider-outage" => provider_outage(&config.provider_outage).await?,
            "cancellation-storm" => cancellation_storm(&config.cancellation_storm).await?,
            "disk-full" => disk_full(&config.disk_full).await?,
            "database-lock" => database_lock(&config.database_lock).await?,
            "network-partition" => network_partition(&config.network_partition).await?,
            _ => unreachable!("selected scenario is validated"),
        });
    }
    let passed = results.iter().all(|result| result.passed);
    let report = QualificationReport {
        schema_version: 1,
        suite: config.suite.clone(),
        generated_at: Utc::now().to_rfc3339(),
        qualification_class: "deterministic_resilience_fixture",
        production_claim_allowed: false,
        build_profile: if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        },
        smoke_scaled: cli.smoke,
        source: source_metadata(),
        configuration: config,
        scenarios: results,
        passed,
        caveats: vec![
            "Deterministic fault fixtures validate AgentOS behavior, not an external provider, target network, or target filesystem.",
            "A smoke or local artifact is regression evidence, not the required 24-hour production soak.",
            "Sandbox crash recovery is qualified separately on a live rootless Linux runner.",
            "Production readiness still requires target-host resources, SLO evaluation, alert delivery, and independent game-day review.",
        ],
    };
    let json =
        serde_json::to_string_pretty(&report).map_err(|error| format!("encode report: {error}"))?;
    if let Some(path) = cli.output {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|error| format!("create {}: {error}", parent.display()))?;
        }
        std::fs::write(&path, format!("{json}\n"))
            .map_err(|error| format!("write {}: {error}", path.display()))?;
        println!("{}", path.display());
    } else {
        println!("{json}");
    }
    if !passed {
        return Err("one or more resilience scenarios failed".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checked_in_suite_is_complete_and_valid() {
        let config: SuiteConfig = toml::from_str(DEFAULT_CONFIG).unwrap();
        validate_config(&config).unwrap();
        assert_eq!(SCENARIOS.len(), 7);
    }

    #[test]
    fn validator_rejects_unbounded_overload_shape() {
        let mut config: SuiteConfig = toml::from_str(DEFAULT_CONFIG).unwrap();
        config.turn_overload.max_waiting = 0;
        assert!(validate_config(&config)
            .unwrap_err()
            .contains("finite non-zero"));
    }

    #[test]
    fn validator_rejects_missing_or_extreme_memory_proof() {
        let mut config: SuiteConfig = toml::from_str(DEFAULT_CONFIG).unwrap();
        config.turn_overload.memory_waves = 1;
        assert!(validate_config(&config)
            .unwrap_err()
            .contains("at least two memory waves"));

        let mut config: SuiteConfig = toml::from_str(DEFAULT_CONFIG).unwrap();
        config.slow_clients.max_rss_growth_bytes = MAX_CONFIGURED_RSS_GROWTH_BYTES + 1;
        assert!(validate_config(&config)
            .unwrap_err()
            .contains("RSS growth limit"));
    }

    #[tokio::test]
    async fn every_scenario_completes_at_smoke_scale() {
        let config: SuiteConfig = smoke_scale(&toml::from_str(DEFAULT_CONFIG).unwrap());
        for result in [
            turn_overload(&config.turn_overload).await.unwrap(),
            slow_clients(&config.slow_clients).await.unwrap(),
            provider_outage(&config.provider_outage).await.unwrap(),
            cancellation_storm(&config.cancellation_storm)
                .await
                .unwrap(),
            disk_full(&config.disk_full).await.unwrap(),
            database_lock(&config.database_lock).await.unwrap(),
            network_partition(&config.network_partition).await.unwrap(),
        ] {
            assert!(result.passed, "{} failed: {:?}", result.name, result);
        }
    }
}
