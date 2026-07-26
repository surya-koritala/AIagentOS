//! Deterministic overload and graceful-degradation qualification.
//!
//! This suite drives public TCP/SDK paths and records bounded admission,
//! recovery, and leak checks. It is a release-regression artifact, not
//! production proof: real-provider, target-host, long-duration, and independent
//! evidence remain mandatory before a production claim.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use agent_sdk::{KernelClient, SdkError};
use chrono::Utc;
use kernel::config::{BudgetConfig, Config};
use kernel::connector::{
    LlmProviderAdapter, LlmRequestOptions, LlmResponse, LlmSession, ProviderType, StandardMessage,
    ToolDefinition,
};
use kernel::context::SqliteContextManager;
use kernel::metrics::MetricsSnapshot;
use kernel::syscall_server::{SyscallServer, WireConnectionSnapshot};
use kernel::{AgentKernelImpl, ConnectorError, ProviderId};
use serde::{Deserialize, Serialize};
use tokio::sync::Barrier;
use tokio::task::{JoinHandle, JoinSet};

const DEFAULT_CONFIG: &str = include_str!("../../resilience-profiles.toml");
const SCENARIOS: [&str; 3] = ["turn-overload", "slow-clients", "provider-outage"];

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SuiteConfig {
    schema_version: u32,
    suite: String,
    turn_overload: TurnOverloadConfig,
    slow_clients: SlowClientsConfig,
    provider_outage: ProviderOutageConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct TurnOverloadConfig {
    operations: usize,
    max_concurrent: u32,
    max_waiting: u32,
    provider_delay_ms: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SlowClientsConfig {
    connection_limit: usize,
    excess_connections: usize,
    idle_timeout_ms: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ProviderOutageConfig {
    operations: usize,
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
    if overload.provider_delay_ms == 0 {
        return Err("turn overload provider_delay_ms must be non-zero".into());
    }
    let clients = &config.slow_clients;
    if clients.connection_limit == 0
        || clients.excess_connections == 0
        || clients.idle_timeout_ms == 0
    {
        return Err("slow clients requires finite non-zero limits and timeout".into());
    }
    if config.provider_outage.operations == 0 {
        return Err("provider outage operations must be non-zero".into());
    }
    Ok(())
}

fn smoke_scale(config: &SuiteConfig) -> SuiteConfig {
    let mut scaled = config.clone();
    scaled.turn_overload.provider_delay_ms = 50;
    scaled.provider_outage.operations = scaled.provider_outage.operations.min(2);
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

    let mut clients = Vec::with_capacity(config.operations);
    for _ in 0..config.operations {
        clients.push(
            KernelClient::connect(address)
                .await
                .map_err(|error| error.to_string())?,
        );
    }
    let barrier = Arc::new(Barrier::new(config.operations + 1));
    let done = Arc::new(AtomicBool::new(false));
    let monitor_kernel = Arc::clone(&kernel);
    let monitor_done = Arc::clone(&done);
    let monitor = tokio::spawn(async move {
        let mut peak_active = 0;
        let mut peak_waiting = 0;
        while !monitor_done.load(Ordering::Relaxed) {
            let snapshot = MetricsSnapshot::collect(&monitor_kernel);
            peak_active = peak_active.max(snapshot.active_turns);
            peak_waiting = peak_waiting.max(snapshot.waiting_turns);
            tokio::task::yield_now().await;
        }
        (peak_active, peak_waiting)
    });

    let started = Instant::now();
    let mut workers = JoinSet::new();
    for (mut client, agent_id) in clients.into_iter().zip(agents) {
        let barrier = Arc::clone(&barrier);
        workers.spawn(async move {
            barrier.wait().await;
            client
                .send_message(agent_id, "overload qualification")
                .await
                .map(|_| ())
                .map_err(|error| error.to_string())
        });
    }
    barrier.wait().await;
    let mut successes = 0_u64;
    let mut overload_rejections = 0_u64;
    let mut unexpected_failures = 0_u64;
    let mut notes = Vec::new();
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
    done.store(true, Ordering::Relaxed);
    let (peak_active, peak_waiting) = monitor.await.map_err(|error| error.to_string())?;
    let final_metrics = MetricsSnapshot::collect(&kernel);
    let mut recovery = KernelClient::connect(address)
        .await
        .map_err(|error| error.to_string())?;
    let recovery_ok = recovery.ping().await.is_ok() && recovery.close().await.is_ok();

    let expected = config.operations as u64;
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
    let mut holders = Vec::with_capacity(config.connection_limit);
    for _ in 0..config.connection_limit {
        holders.push(
            KernelClient::connect(address)
                .await
                .map_err(|error| error.to_string())?,
        );
    }
    let saturated = wait_for_wire(&metrics, Duration::from_secs(2), |snapshot| {
        snapshot.active == config.connection_limit
    })
    .await;
    let mut excess_rejected = 0_u64;
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
    let reaped = wait_for_wire(&metrics, Duration::from_secs(5), |snapshot| {
        snapshot.active == 0 && snapshot.idle_timeouts_total >= config.connection_limit as u64
    })
    .await;
    drop(holders);
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
    checks.insert("connection_limit_reached".into(), saturated);
    checks.insert(
        "all_excess_connections_rejected".into(),
        excess_rejected == config.excess_connections as u64,
    );
    checks.insert(
        "active_connections_bounded".into(),
        final_metrics.peak_active <= config.connection_limit,
    );
    checks.insert("slow_connections_reaped".into(), reaped);
    checks.insert("permits_drained".into(), drained);
    checks.insert("server_recovers".into(), recovery_ok);
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
    ]);
    stop_server(task).await;
    kernel.shutdown().await.map_err(|error| error.to_string())?;
    Ok(result(
        "slow-clients",
        started,
        checks,
        observed,
        Vec::new(),
    ))
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
            "Deterministic fault fixtures validate AgentOS behavior, not an external provider or network.",
            "A smoke or local artifact is regression evidence, not the required 24-hour production soak.",
            "Production readiness still requires the full fault matrix, target-host resources, SLO evaluation, and independent game-day review.",
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
        assert_eq!(SCENARIOS.len(), 3);
    }

    #[test]
    fn validator_rejects_unbounded_overload_shape() {
        let mut config: SuiteConfig = toml::from_str(DEFAULT_CONFIG).unwrap();
        config.turn_overload.max_waiting = 0;
        assert!(validate_config(&config)
            .unwrap_err()
            .contains("finite non-zero"));
    }

    #[tokio::test]
    async fn every_scenario_completes_at_smoke_scale() {
        let config: SuiteConfig = smoke_scale(&toml::from_str(DEFAULT_CONFIG).unwrap());
        for result in [
            turn_overload(&config.turn_overload).await.unwrap(),
            slow_clients(&config.slow_clients).await.unwrap(),
            provider_outage(&config.provider_outage).await.unwrap(),
        ] {
            assert!(result.passed, "{} failed: {:?}", result.name, result);
        }
    }
}
