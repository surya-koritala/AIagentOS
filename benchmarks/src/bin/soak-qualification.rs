//! Target-host resource and leak soak qualification.
//!
//! The checked-in configuration is a real 24-hour workload. `--smoke` scales
//! it down for regression testing but can never make an evidence-eligible
//! artifact. The report binds exact source, environment, resource samples,
//! admission gauges, and conservative growth checks.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, Instant};

use agent_sdk::KernelClient;
use chrono::Utc;
use kernel::config::{BudgetConfig, Config};
use kernel::connector::{
    LlmProviderAdapter, LlmRequestOptions, LlmResponse, LlmSession, LlmUsage, ProviderType,
    StandardMessage, ToolDefinition,
};
use kernel::context::SqliteContextManager;
use kernel::metrics::MetricsSnapshot;
use kernel::syscall_server::{SyscallServer, WireConnectionMetrics};
use kernel::{AgentKernelImpl, ConnectorError, ProviderId};
use serde::{Deserialize, Serialize};
use tokio::task::{JoinHandle, JoinSet};

const DEFAULT_CONFIG: &str = include_str!("../../soak-profiles.toml");

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SoakConfig {
    schema_version: u32,
    suite: String,
    minimum_proof_duration_seconds: u64,
    duration_seconds: u64,
    warmup_seconds: u64,
    sample_interval_seconds: u64,
    workload_interval_ms: u64,
    agent_count: usize,
    operations_per_cycle: usize,
    max_concurrent: u32,
    max_waiting: u32,
    provider_delay_ms: u64,
    minimum_samples: usize,
    thresholds: GrowthThresholds,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct GrowthThresholds {
    max_rss_growth_bytes: u64,
    max_descriptor_growth: u64,
    max_task_growth: u64,
    max_state_growth_bytes_per_operation: u64,
}

#[derive(Debug, Serialize)]
struct SourceMetadata {
    commit: String,
    dirty: Option<bool>,
    rustc: String,
}

#[derive(Debug, Serialize)]
struct EnvironmentMetadata {
    environment_id: String,
    os: &'static str,
    architecture: &'static str,
}

#[derive(Debug, Clone, Serialize)]
struct ResourceSample {
    elapsed_seconds: f64,
    completed_operations: u64,
    rss_bytes: Option<u64>,
    tasks: Option<u64>,
    descriptors: Option<u64>,
    state_bytes: u64,
    active_turns: u64,
    waiting_turns: u64,
    llm_requests_in_flight: u64,
    llm_requests_waiting: u64,
    quota_receipts: u64,
    active_connections: u64,
}

#[derive(Debug, Serialize)]
struct SoakResult {
    elapsed_seconds: f64,
    attempted_operations: u64,
    successful_operations: u64,
    unexpected_failures: u64,
    checks: BTreeMap<String, bool>,
    observed: BTreeMap<String, u64>,
    samples: Vec<ResourceSample>,
    notes: Vec<String>,
    passed: bool,
}

#[derive(Debug, Serialize)]
struct SoakReport {
    schema_version: u32,
    suite: String,
    generated_at: String,
    qualification_class: &'static str,
    proof_scope: &'static str,
    resource_soak_proof_eligible: bool,
    production_claim_allowed: bool,
    build_profile: &'static str,
    smoke_scaled: bool,
    source: SourceMetadata,
    environment: EnvironmentMetadata,
    configuration: SoakConfig,
    result: SoakResult,
    caveats: Vec<&'static str>,
}

#[derive(Default)]
struct Cli {
    config: Option<PathBuf>,
    output: Option<PathBuf>,
    state_dir: Option<PathBuf>,
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
            "--state-dir" => {
                cli.state_dir = Some(PathBuf::from(
                    args.next().ok_or("--state-dir requires a path")?,
                ));
            }
            "--validate" => cli.validate_only = true,
            "--smoke" => cli.smoke = true,
            "--allow-debug" => cli.allow_debug = true,
            "-h" | "--help" => {
                println!(
                    "soak-qualification [--config PATH] [--validate] \\\n+                     [--state-dir PATH --output PATH] [--smoke] [--allow-debug]"
                );
                std::process::exit(0);
            }
            other => return Err(format!("unknown argument {other:?}")),
        }
    }
    Ok(cli)
}

fn read_config(path: Option<&Path>) -> Result<SoakConfig, String> {
    let source = match path {
        Some(path) => std::fs::read_to_string(path)
            .map_err(|error| format!("read {}: {error}", path.display()))?,
        None => DEFAULT_CONFIG.to_string(),
    };
    toml::from_str(&source).map_err(|error| format!("parse soak config: {error}"))
}

fn validate_config(config: &SoakConfig) -> Result<(), String> {
    if config.schema_version != 1 {
        return Err(format!(
            "unsupported soak schema version {}",
            config.schema_version
        ));
    }
    if config.suite.trim().is_empty() {
        return Err("suite name cannot be empty".into());
    }
    if config.minimum_proof_duration_seconds < 24 * 60 * 60 {
        return Err("minimum proof duration cannot be less than 24 hours".into());
    }
    if config.duration_seconds == 0
        || config.sample_interval_seconds == 0
        || config.workload_interval_ms == 0
        || config.agent_count == 0
        || config.operations_per_cycle == 0
        || config.max_concurrent == 0
        || config.max_waiting == 0
        || config.provider_delay_ms == 0
        || config.minimum_samples < 3
    {
        return Err("soak workload fields must be finite and non-zero".into());
    }
    if config.warmup_seconds >= config.duration_seconds {
        return Err("warmup must end before the configured duration".into());
    }
    if config.thresholds.max_rss_growth_bytes == 0
        || config.thresholds.max_descriptor_growth == 0
        || config.thresholds.max_task_growth == 0
        || config.thresholds.max_state_growth_bytes_per_operation == 0
    {
        return Err("growth thresholds must be finite and non-zero".into());
    }
    Ok(())
}

fn smoke_scale(config: &SoakConfig) -> SoakConfig {
    let mut scaled = config.clone();
    scaled.duration_seconds = 5;
    scaled.warmup_seconds = 1;
    scaled.sample_interval_seconds = 1;
    scaled.workload_interval_ms = 100;
    scaled.agent_count = scaled.agent_count.min(2);
    scaled.operations_per_cycle = scaled.operations_per_cycle.min(2);
    scaled.max_concurrent = scaled.max_concurrent.min(2);
    scaled.max_waiting = scaled.max_waiting.min(4);
    scaled.provider_delay_ms = scaled.provider_delay_ms.min(10);
    scaled.minimum_samples = 4;
    scaled
}

struct SoakProvider {
    id: ProviderId,
    delay: Duration,
}

struct SoakSession {
    id: ProviderId,
    delay: Duration,
}

#[async_trait::async_trait]
impl LlmSession for SoakSession {
    async fn send(&self, messages: Vec<StandardMessage>) -> Result<LlmResponse, ConnectorError> {
        tokio::time::sleep(self.delay).await;
        let input = messages
            .iter()
            .map(|message| message.content.len().div_ceil(4))
            .sum::<usize>()
            .min(u32::MAX as usize) as u32;
        Ok(LlmResponse {
            content: "soak-response".into(),
            finish_reason: Some("stop".into()),
            tokens_used: input.saturating_add(3),
            usage: LlmUsage::reported(input, 3, 0),
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
        "deterministic-soak-v1"
    }

    fn enforces_max_output_tokens(&self) -> bool {
        true
    }
}

#[async_trait::async_trait]
impl LlmProviderAdapter for SoakProvider {
    fn id(&self) -> &ProviderId {
        &self.id
    }

    fn name(&self) -> &str {
        "target-resource-soak-provider"
    }

    fn provider_type(&self) -> ProviderType {
        ProviderType::Local
    }

    async fn is_available(&self) -> bool {
        true
    }

    async fn create_session(&self) -> Result<Box<dyn LlmSession>, ConnectorError> {
        Ok(Box::new(SoakSession {
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

async fn start_server(
    kernel: Arc<AgentKernelImpl>,
    connection_limit: usize,
) -> Result<
    (
        std::net::SocketAddr,
        WireConnectionMetrics,
        JoinHandle<std::io::Result<()>>,
    ),
    String,
> {
    let server = SyscallServer::bind(kernel, "127.0.0.1:0")
        .await
        .map_err(|error| error.to_string())?
        .with_connection_limit(connection_limit)
        .with_idle_timeout(Duration::from_secs(30));
    let address = server.local_addr().map_err(|error| error.to_string())?;
    let metrics = server.connection_metrics();
    Ok((address, metrics, tokio::spawn(server.serve())))
}

async fn stop_server(task: JoinHandle<std::io::Result<()>>) {
    task.abort();
    let _ = task.await;
}

fn prepare_state_dir(path: &Path) -> Result<(), String> {
    if path.exists() {
        let metadata = std::fs::symlink_metadata(path)
            .map_err(|error| format!("inspect {}: {error}", path.display()))?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(format!(
                "state path {} must be a real directory",
                path.display()
            ));
        }
        let mut entries = std::fs::read_dir(path)
            .map_err(|error| format!("inspect {}: {error}", path.display()))?;
        if entries
            .next()
            .transpose()
            .map_err(|error| error.to_string())?
            .is_some()
        {
            return Err(format!(
                "state directory {} must be empty so evidence cannot mix runs",
                path.display()
            ));
        }
    } else {
        std::fs::create_dir_all(path)
            .map_err(|error| format!("create {}: {error}", path.display()))?;
    }
    Ok(())
}

fn state_bytes(path: &Path) -> Result<u64, String> {
    let entries = std::fs::read_dir(path)
        .map_err(|error| format!("read state directory {}: {error}", path.display()))?;
    let mut bytes = 0_u64;
    for entry in entries {
        let entry = entry.map_err(|error| format!("read entry in {}: {error}", path.display()))?;
        let file_type = entry
            .file_type()
            .map_err(|error| format!("inspect {}: {error}", entry.path().display()))?;
        if file_type.is_symlink() {
            return Err(format!(
                "state evidence cannot include symlink {}",
                entry.path().display()
            ));
        }
        let metadata = entry
            .metadata()
            .map_err(|error| format!("inspect {}: {error}", entry.path().display()))?;
        if metadata.is_file() {
            bytes = bytes.saturating_add(metadata.len());
        }
    }
    Ok(bytes)
}

#[cfg(target_os = "linux")]
fn linux_status_value(name: &str) -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let line = status.lines().find(|line| line.starts_with(name))?;
    line.split_whitespace().nth(1)?.parse().ok()
}

#[cfg(target_os = "linux")]
fn process_resources() -> (Option<u64>, Option<u64>, Option<u64>) {
    let rss = linux_status_value("VmRSS:").map(|kilobytes| kilobytes.saturating_mul(1024));
    let tasks = linux_status_value("Threads:");
    let descriptors = std::fs::read_dir("/proc/self/fd")
        .ok()
        .map(|entries| entries.filter_map(Result::ok).count() as u64);
    (rss, tasks, descriptors)
}

#[cfg(target_os = "macos")]
fn process_resources() -> (Option<u64>, Option<u64>, Option<u64>) {
    let pid = std::process::id().to_string();
    let rss = command_output("ps", &["-o", "rss=", "-p", &pid])
        .and_then(|value| value.trim().parse::<u64>().ok())
        .map(|kilobytes| kilobytes.saturating_mul(1024));
    let tasks = command_output("ps", &["-M", "-o", "pid=", "-p", &pid])
        .map(|value| value.lines().filter(|line| !line.trim().is_empty()).count() as u64);
    let descriptors = std::fs::read_dir("/dev/fd")
        .ok()
        .map(|entries| entries.filter_map(Result::ok).count() as u64);
    (rss, tasks, descriptors)
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn process_resources() -> (Option<u64>, Option<u64>, Option<u64>) {
    (None, None, None)
}

fn collect_sample(
    started: Instant,
    completed_operations: u64,
    state_dir: &Path,
    kernel: &AgentKernelImpl,
    wire: &WireConnectionMetrics,
) -> Result<ResourceSample, String> {
    let (rss_bytes, tasks, descriptors) = process_resources();
    let metrics = MetricsSnapshot::collect(kernel);
    Ok(ResourceSample {
        elapsed_seconds: started.elapsed().as_secs_f64(),
        completed_operations,
        rss_bytes,
        tasks,
        descriptors,
        state_bytes: state_bytes(state_dir)?,
        active_turns: metrics.active_turns,
        waiting_turns: metrics.waiting_turns,
        llm_requests_in_flight: metrics.llm_requests_in_flight,
        llm_requests_waiting: metrics.llm_requests_waiting,
        quota_receipts: metrics
            .quota_reserved_receipts
            .saturating_add(metrics.quota_in_flight_receipts),
        active_connections: wire.snapshot().active as u64,
    })
}

fn growth(first: Option<u64>, last: Option<u64>) -> Option<u64> {
    Some(last?.saturating_sub(first?))
}

fn evaluate_samples(
    config: &SoakConfig,
    samples: &[ResourceSample],
) -> (BTreeMap<String, bool>, BTreeMap<String, u64>) {
    let steady = samples
        .iter()
        .filter(|sample| sample.elapsed_seconds >= config.warmup_seconds as f64)
        .collect::<Vec<_>>();
    let first = steady.first().copied();
    let last = steady.last().copied();
    let rss_growth = growth(
        first.and_then(|sample| sample.rss_bytes),
        last.and_then(|sample| sample.rss_bytes),
    );
    let descriptor_growth = growth(
        first.and_then(|sample| sample.descriptors),
        last.and_then(|sample| sample.descriptors),
    );
    let task_growth = growth(
        first.and_then(|sample| sample.tasks),
        last.and_then(|sample| sample.tasks),
    );
    let state_growth = match (first, last) {
        (Some(first), Some(last)) => Some(last.state_bytes.saturating_sub(first.state_bytes)),
        _ => None,
    };
    let operation_growth = match (first, last) {
        (Some(first), Some(last)) => Some(
            last.completed_operations
                .saturating_sub(first.completed_operations),
        ),
        _ => None,
    };
    let state_bytes_per_operation = match (state_growth, operation_growth) {
        (Some(bytes), Some(operations)) if operations > 0 => {
            Some(bytes.saturating_add(operations - 1) / operations)
        }
        _ => None,
    };

    let counters_available = samples.iter().all(|sample| {
        sample.rss_bytes.is_some() && sample.tasks.is_some() && sample.descriptors.is_some()
    });
    let checks = BTreeMap::from([
        (
            "minimum_samples_collected".into(),
            samples.len() >= config.minimum_samples,
        ),
        (
            "steady_state_samples_available".into(),
            steady.len() >= 2 && counters_available,
        ),
        (
            "rss_growth_bounded".into(),
            rss_growth.is_some_and(|growth| growth <= config.thresholds.max_rss_growth_bytes),
        ),
        (
            "descriptor_growth_bounded".into(),
            descriptor_growth
                .is_some_and(|growth| growth <= config.thresholds.max_descriptor_growth),
        ),
        (
            "task_growth_bounded".into(),
            task_growth.is_some_and(|growth| growth <= config.thresholds.max_task_growth),
        ),
        (
            "state_growth_per_operation_bounded".into(),
            state_bytes_per_operation.is_some_and(|growth| {
                growth <= config.thresholds.max_state_growth_bytes_per_operation
            }),
        ),
    ]);
    let observed = BTreeMap::from([
        ("samples".into(), samples.len() as u64),
        ("steady_state_samples".into(), steady.len() as u64),
        ("rss_growth_bytes".into(), rss_growth.unwrap_or(u64::MAX)),
        (
            "descriptor_growth".into(),
            descriptor_growth.unwrap_or(u64::MAX),
        ),
        ("task_growth".into(), task_growth.unwrap_or(u64::MAX)),
        (
            "state_growth_bytes".into(),
            state_growth.unwrap_or(u64::MAX),
        ),
        (
            "state_growth_bytes_per_operation".into(),
            state_bytes_per_operation.unwrap_or(u64::MAX),
        ),
    ]);
    (checks, observed)
}

async fn wait_for_wire_drain(metrics: &WireConnectionMetrics) -> bool {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if metrics.snapshot().active == 0 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .is_ok()
}

async fn run_soak(config: &SoakConfig, state_dir: &Path) -> Result<SoakResult, String> {
    prepare_state_dir(state_dir)?;
    let database = state_dir.join("agentos-soak.sqlite3");
    let context =
        Arc::new(SqliteContextManager::new(&database).map_err(|error| error.to_string())?);
    let mut budgets = BudgetConfig {
        max_concurrent: config.max_concurrent,
        max_waiting_turns: config.max_waiting,
        rpm: 60_000,
        tpm: 1_000_000_000,
        ..BudgetConfig::default()
    };
    budgets.agent_tokens_per_min = budgets.tpm;
    let kernel_config = Config::default();
    let kernel = Arc::new(
        AgentKernelImpl::with_context_manager(
            context,
            &budgets,
            kernel_config.mac_enforcing,
            &kernel_config.mac_rules,
        )
        .map_err(|error| error.to_string())?,
    );
    let provider = "resource-soak";
    kernel
        .register_provider(Arc::new(SoakProvider {
            id: provider.into(),
            delay: Duration::from_millis(config.provider_delay_ms),
        }))
        .map_err(|error| error.to_string())?;
    let connection_limit = config.operations_per_cycle.saturating_add(8);
    let (address, wire, server_task) = start_server(Arc::clone(&kernel), connection_limit).await?;

    let mut setup = KernelClient::connect(address)
        .await
        .map_err(|error| error.to_string())?;
    let mut agents = Vec::with_capacity(config.agent_count);
    for index in 0..config.agent_count {
        agents.push(
            setup
                .create_agent(
                    format!("soak-{index}"),
                    "target-host resource and leak soak",
                    Some(provider.into()),
                    Some("read-only".into()),
                    Some(3),
                )
                .await
                .map_err(|error| error.to_string())?,
        );
    }
    setup.close().await.map_err(|error| error.to_string())?;
    let initial_wire_drained = wait_for_wire_drain(&wire).await;

    let started = Instant::now();
    let duration = Duration::from_secs(config.duration_seconds);
    let sample_interval = Duration::from_secs(config.sample_interval_seconds);
    let workload_interval = Duration::from_millis(config.workload_interval_ms);
    let mut next_sample = Duration::ZERO;
    let mut attempted = 0_u64;
    let mut successful = 0_u64;
    let mut unexpected = 0_u64;
    let mut notes = Vec::new();
    let mut samples = Vec::new();

    while started.elapsed() < duration {
        if started.elapsed() >= next_sample {
            samples.push(collect_sample(
                started, successful, state_dir, &kernel, &wire,
            )?);
            next_sample = started.elapsed().saturating_add(sample_interval);
        }

        let mut cycle = JoinSet::new();
        for operation in 0..config.operations_per_cycle {
            let agent = agents[(attempted as usize + operation) % agents.len()].clone();
            cycle.spawn(async move {
                let mut client = KernelClient::connect(address).await?;
                let result = client
                    .send_message(agent, "bounded target-host soak operation")
                    .await
                    .map(|_| ());
                let close_result = client.close().await;
                result.and(close_result)
            });
        }
        attempted = attempted.saturating_add(config.operations_per_cycle as u64);
        while let Some(joined) = cycle.join_next().await {
            match joined {
                Ok(Ok(())) => successful += 1,
                Ok(Err(error)) => {
                    unexpected += 1;
                    if notes.len() < 10 {
                        notes.push(error.to_string());
                    }
                }
                Err(error) => {
                    unexpected += 1;
                    if notes.len() < 10 {
                        notes.push(error.to_string());
                    }
                }
            }
        }

        let remaining = duration.saturating_sub(started.elapsed());
        if !remaining.is_zero() {
            tokio::time::sleep(workload_interval.min(remaining)).await;
        }
    }
    let wire_drained = wait_for_wire_drain(&wire).await;
    samples.push(collect_sample(
        started, successful, state_dir, &kernel, &wire,
    )?);

    let mut recovery = KernelClient::connect(address)
        .await
        .map_err(|error| error.to_string())?;
    let recovery_ok = recovery.ping().await.is_ok() && recovery.close().await.is_ok();
    let recovery_drained = wait_for_wire_drain(&wire).await;
    let final_metrics = MetricsSnapshot::collect(&kernel);
    let final_wire = wire.snapshot();
    let elapsed_seconds = started.elapsed().as_secs_f64();
    let (mut checks, mut observed) = evaluate_samples(config, &samples);
    checks.insert(
        "configured_duration_completed".into(),
        elapsed_seconds + 0.001 >= config.duration_seconds as f64,
    );
    checks.insert(
        "all_operations_succeeded".into(),
        attempted > 0 && successful == attempted && unexpected == 0,
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
        initial_wire_drained && wire_drained && recovery_drained && final_wire.active == 0,
    );
    checks.insert(
        "quota_storage_healthy".into(),
        final_metrics.quota_storage_healthy,
    );
    checks.insert("server_recovers".into(), recovery_ok);
    observed.insert("attempted_operations".into(), attempted);
    observed.insert("successful_operations".into(), successful);
    observed.insert("unexpected_failures".into(), unexpected);
    observed.insert(
        "elapsed_milliseconds".into(),
        started.elapsed().as_millis().try_into().unwrap_or(u64::MAX),
    );
    observed.insert(
        "peak_active_connections".into(),
        final_wire.peak_active as u64,
    );
    observed.insert("final_active_turns".into(), final_metrics.active_turns);
    observed.insert(
        "final_llm_requests_in_flight".into(),
        final_metrics.llm_requests_in_flight,
    );
    observed.insert(
        "final_quota_receipts".into(),
        final_metrics
            .quota_reserved_receipts
            .saturating_add(final_metrics.quota_in_flight_receipts),
    );
    observed.insert("final_active_connections".into(), final_wire.active as u64);
    let passed = checks.values().all(|passed| *passed);

    stop_server(server_task).await;
    kernel.shutdown().await.map_err(|error| error.to_string())?;
    Ok(SoakResult {
        elapsed_seconds,
        attempted_operations: attempted,
        successful_operations: successful,
        unexpected_failures: unexpected,
        checks,
        observed,
        samples,
        notes,
        passed,
    })
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

fn environment_metadata() -> EnvironmentMetadata {
    EnvironmentMetadata {
        environment_id: std::env::var("AGENTOS_QUALIFICATION_ENVIRONMENT")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| "unspecified".into()),
        os: std::env::consts::OS,
        architecture: std::env::consts::ARCH,
    }
}

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("soak qualification failed: {error}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), String> {
    let cli = parse_cli()?;
    let mut config = read_config(cli.config.as_deref())?;
    validate_config(&config)?;
    if cli.validate_only {
        println!(
            "validated {} schema v{}: {} second target soak",
            config.suite, config.schema_version, config.duration_seconds
        );
        return Ok(());
    }
    if cfg!(debug_assertions) && !cli.allow_debug && !cli.smoke {
        return Err(
            "soak runs require a --release build; use --allow-debug only for development".into(),
        );
    }
    let state_dir = cli
        .state_dir
        .as_deref()
        .ok_or("--state-dir is required for an evidence run")?;
    if cli.smoke {
        config = smoke_scale(&config);
    }
    let source = source_metadata();
    let environment = environment_metadata();
    let result = run_soak(&config, state_dir).await?;
    let build_profile = if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    };
    let resource_soak_proof_eligible = result.passed
        && !cli.smoke
        && build_profile == "release"
        && source.dirty == Some(false)
        && environment.os == "linux"
        && environment.environment_id != "unspecified"
        && config.duration_seconds >= config.minimum_proof_duration_seconds
        && result.elapsed_seconds >= config.minimum_proof_duration_seconds as f64;
    let report = SoakReport {
        schema_version: 1,
        suite: config.suite.clone(),
        generated_at: Utc::now().to_rfc3339(),
        qualification_class: "target_resource_soak",
        proof_scope: "resource_and_leak_soak_only",
        resource_soak_proof_eligible,
        production_claim_allowed: false,
        build_profile,
        smoke_scaled: cli.smoke,
        source,
        environment,
        configuration: config,
        result,
        caveats: vec![
            "Eligibility covers only the resource/leak soak proof required by issue #125.",
            "Deterministic local provider work does not qualify live external providers or network paths.",
            "The remaining fault matrix, exact-release SLO report, game day, and independent review are separate gates.",
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
    if !report.result.passed {
        return Err("resource soak checks failed".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(
        elapsed_seconds: f64,
        completed_operations: u64,
        rss_bytes: u64,
        tasks: u64,
        descriptors: u64,
        state_bytes: u64,
    ) -> ResourceSample {
        ResourceSample {
            elapsed_seconds,
            completed_operations,
            rss_bytes: Some(rss_bytes),
            tasks: Some(tasks),
            descriptors: Some(descriptors),
            state_bytes,
            active_turns: 0,
            waiting_turns: 0,
            llm_requests_in_flight: 0,
            llm_requests_waiting: 0,
            quota_receipts: 0,
            active_connections: 0,
        }
    }

    #[test]
    fn checked_in_target_soak_is_a_full_day_and_valid() {
        let config: SoakConfig = toml::from_str(DEFAULT_CONFIG).unwrap();
        validate_config(&config).unwrap();
        assert_eq!(config.duration_seconds, 24 * 60 * 60);
        assert!(config.duration_seconds >= config.minimum_proof_duration_seconds);
    }

    #[test]
    fn smoke_scaling_cannot_reduce_the_proof_minimum() {
        let config: SoakConfig = toml::from_str(DEFAULT_CONFIG).unwrap();
        let smoke = smoke_scale(&config);
        assert_eq!(smoke.duration_seconds, 5);
        assert_eq!(smoke.minimum_proof_duration_seconds, 24 * 60 * 60);
    }

    #[test]
    fn growth_evaluation_uses_only_post_warmup_samples() {
        let mut config: SoakConfig = toml::from_str(DEFAULT_CONFIG).unwrap();
        config.warmup_seconds = 10;
        config.minimum_samples = 3;
        let samples = vec![
            sample(0.0, 0, 1, 1, 1, 1),
            sample(10.0, 10, 100, 5, 10, 1_000),
            sample(20.0, 20, 110, 5, 11, 2_000),
        ];
        let (checks, observed) = evaluate_samples(&config, &samples);
        assert!(checks.values().all(|passed| *passed));
        assert_eq!(observed["rss_growth_bytes"], 10);
        assert_eq!(observed["state_growth_bytes_per_operation"], 100);
    }

    #[test]
    fn growth_evaluation_rejects_leaks_and_missing_counters() {
        let mut config: SoakConfig = toml::from_str(DEFAULT_CONFIG).unwrap();
        config.warmup_seconds = 0;
        config.minimum_samples = 3;
        config.thresholds.max_rss_growth_bytes = 10;
        let mut samples = vec![
            sample(0.0, 0, 100, 5, 10, 1_000),
            sample(1.0, 1, 120, 5, 10, 2_000),
            sample(2.0, 2, 140, 5, 10, 3_000),
        ];
        samples[1].descriptors = None;
        let (checks, _) = evaluate_samples(&config, &samples);
        assert!(!checks["steady_state_samples_available"]);
        assert!(!checks["rss_growth_bounded"]);
    }
}
