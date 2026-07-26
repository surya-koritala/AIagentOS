//! Reproducible workload and capacity qualification harness.
//!
//! The checked-in suite exercises the public TCP/SDK boundary against a real
//! kernel with a deterministic local provider. Its output is a machine-readable
//! baseline, not a universal production-capacity claim. Operators must run the
//! release build on the intended deployment shape and retain the JSON artifact.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use agent_sdk::{
    KernelClient, PackageArchive, PackageFile, PackageFileKind, PackageManifest, PackagePayload,
    PackageSbom, PackageSigningKey, SbomComponent,
};
use chrono::Utc;
use kernel::agent_package::AgentManifest;
use kernel::auth::Role;
use kernel::config::{BudgetConfig, Config};
use kernel::connector::{
    LlmProviderAdapter, LlmRequestOptions, LlmResponse, LlmSession, LlmUsage, ProviderType,
    StandardMessage, ToolDefinition,
};
use kernel::context::SqliteContextManager;
use kernel::syscall_server::SyscallServer;
use kernel::{AgentKernelImpl, ConnectorError, ProviderId};
use semver::Version;
use serde::{Deserialize, Serialize};
use tokio::task::{JoinHandle, JoinSet};

const DEFAULT_CONFIG: &str = include_str!("../../capacity-profiles.toml");
const REQUIRED_PROFILES: [(&str, WorkloadKind); 8] = [
    ("idle", WorkloadKind::Idle),
    ("many-agents", WorkloadKind::ManyAgents),
    ("long-context", WorkloadKind::LongContext),
    ("tool-heavy", WorkloadKind::ToolHeavy),
    ("provider-latency", WorkloadKind::ProviderLatency),
    ("tenant-contention", WorkloadKind::TenantContention),
    ("package-install", WorkloadKind::PackageInstall),
    ("restart", WorkloadKind::Restart),
];

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SuiteConfig {
    schema_version: u32,
    suite: String,
    profiles: Vec<ProfileConfig>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ProfileConfig {
    name: String,
    kind: WorkloadKind,
    operations: usize,
    concurrency: usize,
    duration_ms: u64,
    payload_bytes: usize,
    provider_delay_ms: u64,
    tenants: usize,
    agents_per_tenant: usize,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
enum WorkloadKind {
    Idle,
    ManyAgents,
    LongContext,
    ToolHeavy,
    ProviderLatency,
    TenantContention,
    PackageInstall,
    Restart,
}

#[derive(Debug, Serialize)]
struct HostMetadata {
    os: &'static str,
    arch: &'static str,
    logical_cpus: usize,
    cpu_model: Option<String>,
    memory_bytes: Option<u64>,
    qualification_environment: Option<String>,
}

#[derive(Debug, Serialize)]
struct SourceMetadata {
    commit: String,
    dirty: Option<bool>,
    rustc: String,
}

#[derive(Debug, Serialize)]
struct ProfileResult {
    name: String,
    kind: WorkloadKind,
    configuration: ProfileConfig,
    kernel_limits: KernelLimits,
    expected_operations: usize,
    successful_operations: usize,
    failed_operations: usize,
    elapsed_ms: f64,
    throughput_per_second: f64,
    latency_ms_p50: f64,
    latency_ms_p95: f64,
    latency_ms_p99: f64,
    observed_max_prompt_bytes: usize,
    passed: bool,
    notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
struct KernelLimits {
    provider_requests_per_minute: u32,
    provider_tokens_per_minute: u64,
    concurrent_turns: u32,
    agent_tokens_per_minute: u64,
    agent_context_tokens: u64,
    tenant_context_tokens: u64,
    global_context_tokens: u64,
}

#[derive(Debug, Serialize)]
struct QualificationReport {
    schema_version: u32,
    suite: String,
    generated_at: String,
    qualification_class: &'static str,
    capacity_claim_allowed: bool,
    build_profile: &'static str,
    smoke_scaled: bool,
    host: HostMetadata,
    source: SourceMetadata,
    profiles: Vec<ProfileResult>,
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
            "--profile" => cli
                .selected
                .push(args.next().ok_or("--profile requires a profile name")?),
            "--all" => cli.run_all = true,
            "--validate" => cli.validate_only = true,
            "--smoke" => cli.smoke = true,
            "--allow-debug" => cli.allow_debug = true,
            "-h" | "--help" => {
                println!(
                    "capacity-qualification [--config PATH] [--validate] \\\n+                     [--all | --profile NAME ...] [--output PATH] [--smoke] [--allow-debug]\n\n\
                     Full qualification must use --release. --smoke scales every profile down and \
                     always produces a non-publishable fixture artifact."
                );
                std::process::exit(0);
            }
            other => return Err(format!("unknown argument {other:?}")),
        }
    }
    if cli.run_all && !cli.selected.is_empty() {
        return Err("--all and --profile cannot be combined".into());
    }
    Ok(cli)
}

fn read_config(path: Option<&Path>) -> Result<SuiteConfig, String> {
    let source = match path {
        Some(path) => std::fs::read_to_string(path)
            .map_err(|error| format!("read {}: {error}", path.display()))?,
        None => DEFAULT_CONFIG.to_string(),
    };
    toml::from_str(&source).map_err(|error| format!("parse workload config: {error}"))
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
    let mut seen = BTreeMap::new();
    for profile in &config.profiles {
        if profile.name.trim().is_empty() {
            return Err("profile name cannot be empty".into());
        }
        if seen.insert(profile.name.clone(), profile.kind).is_some() {
            return Err(format!("duplicate profile {:?}", profile.name));
        }
        if profile.operations == 0 {
            return Err(format!("{} must have operations > 0", profile.name));
        }
        if profile.concurrency == 0 || profile.concurrency > profile.operations {
            return Err(format!(
                "{} concurrency must be in 1..=operations",
                profile.name
            ));
        }
        match profile.kind {
            WorkloadKind::Idle if profile.duration_ms == 0 => {
                return Err("idle duration_ms must be > 0".into());
            }
            WorkloadKind::LongContext
            | WorkloadKind::ProviderLatency
            | WorkloadKind::TenantContention
                if profile.payload_bytes == 0 =>
            {
                return Err(format!("{} payload_bytes must be > 0", profile.name));
            }
            WorkloadKind::ProviderLatency if profile.provider_delay_ms == 0 => {
                return Err("provider-latency provider_delay_ms must be > 0".into());
            }
            WorkloadKind::TenantContention
                if profile.tenants < 2 || profile.agents_per_tenant == 0 =>
            {
                return Err(
                    "tenant-contention requires at least two tenants and one agent each".into(),
                );
            }
            WorkloadKind::PackageInstall if profile.payload_bytes == 0 => {
                return Err("package-install payload_bytes must be > 0".into());
            }
            WorkloadKind::Restart if profile.agents_per_tenant == 0 => {
                return Err("restart agents_per_tenant must be > 0".into());
            }
            _ => {}
        }
    }
    let expected = REQUIRED_PROFILES
        .iter()
        .map(|(name, kind)| ((*name).to_string(), *kind))
        .collect::<BTreeMap<_, _>>();
    if seen != expected {
        return Err(format!(
            "suite must contain exactly the required profile map {expected:?}, got {seen:?}"
        ));
    }
    Ok(())
}

fn smoke_scale(profile: &ProfileConfig) -> ProfileConfig {
    let operations = match profile.kind {
        WorkloadKind::Idle | WorkloadKind::Restart => 1,
        WorkloadKind::ManyAgents | WorkloadKind::ToolHeavy => 4,
        WorkloadKind::TenantContention => 4,
        _ => 2,
    };
    ProfileConfig {
        operations,
        concurrency: profile.concurrency.min(operations).min(2),
        duration_ms: profile.duration_ms.min(5),
        payload_bytes: profile.payload_bytes.min(1024),
        provider_delay_ms: profile.provider_delay_ms.min(5),
        tenants: if profile.kind == WorkloadKind::TenantContention {
            2
        } else {
            1
        },
        agents_per_tenant: profile.agents_per_tenant.clamp(1, 2),
        ..profile.clone()
    }
}

struct DelayedProvider {
    id: ProviderId,
    delay: Duration,
    max_prompt_bytes: Arc<AtomicUsize>,
}

struct DelayedSession {
    id: ProviderId,
    delay: Duration,
    max_prompt_bytes: Arc<AtomicUsize>,
}

type TimedOperation<E> = (f64, Result<(), E>);
type WorkerOutput<E> = Result<Vec<TimedOperation<E>>, String>;

impl DelayedSession {
    async fn respond(&self, messages: Vec<StandardMessage>) -> Result<LlmResponse, ConnectorError> {
        let bytes = messages.iter().map(|message| message.content.len()).sum();
        self.max_prompt_bytes.fetch_max(bytes, Ordering::SeqCst);
        tokio::time::sleep(self.delay).await;
        let input_tokens = u32::try_from(bytes.div_ceil(4)).unwrap_or(u32::MAX);
        Ok(LlmResponse {
            content: "deterministic qualification response".into(),
            finish_reason: Some("stop".into()),
            tokens_used: input_tokens.saturating_add(8),
            usage: LlmUsage::reported(input_tokens, 8, 0),
            tool_calls: Vec::new(),
        })
    }
}

#[async_trait::async_trait]
impl LlmSession for DelayedSession {
    async fn send(&self, messages: Vec<StandardMessage>) -> Result<LlmResponse, ConnectorError> {
        self.respond(messages).await
    }

    async fn send_with_tools(
        &self,
        messages: Vec<StandardMessage>,
        _tools: &[ToolDefinition],
    ) -> Result<LlmResponse, ConnectorError> {
        self.respond(messages).await
    }

    async fn send_with_options(
        &self,
        messages: Vec<StandardMessage>,
        _tools: &[ToolDefinition],
        _options: LlmRequestOptions,
    ) -> Result<LlmResponse, ConnectorError> {
        self.respond(messages).await
    }

    fn enforces_max_output_tokens(&self) -> bool {
        true
    }

    fn provider_id(&self) -> &ProviderId {
        &self.id
    }

    fn model_id(&self) -> &str {
        "deterministic-capacity-v1"
    }

    fn estimate_prompt_tokens(&self, messages: &[StandardMessage]) -> Option<u32> {
        let bytes: usize = messages.iter().map(|message| message.content.len()).sum();
        Some(u32::try_from(bytes.div_ceil(4)).unwrap_or(u32::MAX))
    }
}

#[async_trait::async_trait]
impl LlmProviderAdapter for DelayedProvider {
    fn id(&self) -> &ProviderId {
        &self.id
    }

    fn name(&self) -> &str {
        "deterministic-capacity-provider"
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
            max_prompt_bytes: Arc::clone(&self.max_prompt_bytes),
        }))
    }

    fn translate_to_provider(&self, message: &StandardMessage) -> serde_json::Value {
        serde_json::json!({"role": message.role, "content": message.content})
    }

    fn translate_from_provider(&self, value: &serde_json::Value) -> Option<StandardMessage> {
        Some(StandardMessage::assistant(value.get("content")?.as_str()?))
    }
}

fn register_delayed_provider(
    kernel: &AgentKernelImpl,
    id: &str,
    delay_ms: u64,
) -> Result<Arc<AtomicUsize>, String> {
    let max_prompt_bytes = Arc::new(AtomicUsize::new(0));
    kernel
        .register_provider(Arc::new(DelayedProvider {
            id: id.into(),
            delay: Duration::from_millis(delay_ms),
            max_prompt_bytes: Arc::clone(&max_prompt_bytes),
        }))
        .map_err(|error| error.to_string())?;
    Ok(max_prompt_bytes)
}

fn budget_for_profile(profile: &ProfileConfig) -> BudgetConfig {
    let mut budgets = BudgetConfig::default();
    if matches!(
        profile.kind,
        WorkloadKind::LongContext | WorkloadKind::ProviderLatency | WorkloadKind::TenantContention
    ) {
        let output_allowance = u64::from(budgets.max_output_tokens_per_request);
        let prompt_tokens = u64::try_from(profile.payload_bytes.div_ceil(4)).unwrap_or(u64::MAX);
        let tokens_per_operation = prompt_tokens
            .saturating_add(output_allowance)
            // The production executor also presents the tool catalogue,
            // standing task, and accumulated conversation to the provider.
            // Keep the fixture quota out of the measured path even for later
            // turns whose context contains every earlier large prompt.
            .saturating_add(65_536);
        let operation_count = u64::try_from(profile.operations).unwrap_or(u64::MAX);
        let operations_per_agent = profile
            .operations
            .div_ceil(profile.concurrency.max(1))
            .max(1);
        budgets.rpm = u32::try_from(profile.operations.saturating_mul(2))
            .unwrap_or(u32::MAX)
            .max(60);
        budgets.tpm = tokens_per_operation
            .saturating_mul(operation_count)
            .saturating_mul(operation_count)
            .saturating_mul(2);
        budgets.max_concurrent = u32::try_from(profile.concurrency)
            .unwrap_or(u32::MAX)
            .max(1);
        budgets.agent_tokens_per_min = budgets.tpm;
        budgets.max_context_tokens = tokens_per_operation
            .saturating_mul(u64::try_from(operations_per_agent).unwrap_or(u64::MAX))
            .saturating_add(8_192);
        budgets.tenant_max_context_tokens = budgets
            .max_context_tokens
            .saturating_mul(u64::try_from(profile.agents_per_tenant.max(1)).unwrap_or(u64::MAX));
        budgets.global_max_context_tokens = budgets
            .tenant_max_context_tokens
            .saturating_mul(u64::try_from(profile.tenants.max(1)).unwrap_or(u64::MAX));
    }
    budgets
}

fn reported_limits(profile: &ProfileConfig) -> KernelLimits {
    let budgets = budget_for_profile(profile);
    KernelLimits {
        provider_requests_per_minute: budgets.rpm,
        provider_tokens_per_minute: budgets.tpm,
        concurrent_turns: budgets.max_concurrent,
        agent_tokens_per_minute: budgets.agent_tokens_per_min,
        agent_context_tokens: budgets.max_context_tokens,
        tenant_context_tokens: budgets.tenant_max_context_tokens,
        global_context_tokens: budgets.global_max_context_tokens,
    }
}

fn qualification_kernel(profile: &ProfileConfig) -> Result<AgentKernelImpl, String> {
    let context = Arc::new(SqliteContextManager::in_memory().map_err(|error| error.to_string())?);
    let config = Config::default();
    AgentKernelImpl::with_context_manager(
        context,
        &budget_for_profile(profile),
        config.mac_enforcing,
        &config.mac_rules,
    )
    .map_err(|error| error.to_string())
}

async fn start_server(
    kernel: Arc<AgentKernelImpl>,
) -> Result<(std::net::SocketAddr, JoinHandle<std::io::Result<()>>), String> {
    let server = SyscallServer::bind(kernel, "127.0.0.1:0")
        .await
        .map_err(|error| error.to_string())?;
    let address = server.local_addr().map_err(|error| error.to_string())?;
    Ok((address, tokio::spawn(server.serve())))
}

async fn stop_server(task: JoinHandle<std::io::Result<()>>) {
    task.abort();
    let _ = task.await;
}

fn split_work(total: usize, workers: usize, worker: usize) -> usize {
    total / workers + usize::from(worker < total % workers)
}

fn push_error(notes: &mut Vec<String>, error: impl ToString) {
    if notes.len() < 5 {
        notes.push(error.to_string());
    }
}

fn percentile(samples: &[f64], percentile: f64) -> f64 {
    if samples.is_empty() {
        return 0.0;
    }
    let mut sorted = samples.to_vec();
    sorted.sort_by(f64::total_cmp);
    let index = ((sorted.len() - 1) as f64 * percentile).round() as usize;
    sorted[index.min(sorted.len() - 1)]
}

fn finish_result(
    profile: &ProfileConfig,
    started: Instant,
    successes: usize,
    failures: usize,
    latencies: Vec<f64>,
    observed_max_prompt_bytes: usize,
    notes: Vec<String>,
) -> ProfileResult {
    let elapsed_ms = started.elapsed().as_secs_f64() * 1_000.0;
    let attempted = successes + failures;
    ProfileResult {
        name: profile.name.clone(),
        kind: profile.kind,
        configuration: profile.clone(),
        kernel_limits: reported_limits(profile),
        expected_operations: profile.operations,
        successful_operations: successes,
        failed_operations: failures,
        elapsed_ms,
        throughput_per_second: if elapsed_ms > 0.0 {
            attempted as f64 / (elapsed_ms / 1_000.0)
        } else {
            0.0
        },
        latency_ms_p50: percentile(&latencies, 0.50),
        latency_ms_p95: percentile(&latencies, 0.95),
        latency_ms_p99: percentile(&latencies, 0.99),
        observed_max_prompt_bytes,
        passed: successes == profile.operations && failures == 0,
        notes,
    }
}

async fn idle_profile(profile: &ProfileConfig) -> Result<ProfileResult, String> {
    let kernel = Arc::new(qualification_kernel(profile)?);
    let (address, task) = start_server(Arc::clone(&kernel)).await?;
    let mut client = KernelClient::connect(address)
        .await
        .map_err(|error| error.to_string())?;
    let started = Instant::now();
    let interval = Duration::from_millis(profile.duration_ms / profile.operations as u64);
    let mut successes = 0;
    let mut failures = 0;
    let mut latencies = Vec::new();
    let mut notes = Vec::new();
    for operation in 0..profile.operations {
        let call = Instant::now();
        match client.ping().await {
            Ok(()) => successes += 1,
            Err(error) => {
                failures += 1;
                push_error(&mut notes, error);
            }
        }
        latencies.push(call.elapsed().as_secs_f64() * 1_000.0);
        if operation + 1 < profile.operations {
            tokio::time::sleep(interval).await;
        }
    }
    stop_server(task).await;
    kernel.shutdown().await.map_err(|error| error.to_string())?;
    Ok(finish_result(
        profile, started, successes, failures, latencies, 0, notes,
    ))
}

async fn many_agents_profile(profile: &ProfileConfig) -> Result<ProfileResult, String> {
    let kernel = Arc::new(qualification_kernel(profile)?);
    let (address, task) = start_server(Arc::clone(&kernel)).await?;
    let started = Instant::now();
    let mut workers = JoinSet::new();
    for worker in 0..profile.concurrency {
        let count = split_work(profile.operations, profile.concurrency, worker);
        workers.spawn(async move {
            let mut client = KernelClient::connect(address)
                .await
                .map_err(|error| error.to_string())?;
            let mut output = Vec::with_capacity(count);
            for operation in 0..count {
                let call = Instant::now();
                let result = client
                    .create_agent(
                        format!("capacity-agent-{worker}-{operation}"),
                        "many-agent public admission profile",
                        None,
                        Some("read-only".into()),
                        Some(3),
                    )
                    .await
                    .map(|_| ());
                output.push((call.elapsed().as_secs_f64() * 1_000.0, result));
            }
            Ok::<_, String>(output)
        });
    }
    let (successes, failures, latencies, notes) = collect_workers(workers).await?;
    stop_server(task).await;
    kernel.shutdown().await.map_err(|error| error.to_string())?;
    Ok(finish_result(
        profile, started, successes, failures, latencies, 0, notes,
    ))
}

async fn provider_profile(profile: &ProfileConfig) -> Result<ProfileResult, String> {
    let provider = format!("capacity-{}", profile.name);
    let kernel = Arc::new(qualification_kernel(profile)?);
    let observed = register_delayed_provider(&kernel, &provider, profile.provider_delay_ms)?;
    let (address, task) = start_server(Arc::clone(&kernel)).await?;
    let payload = "x".repeat(profile.payload_bytes);
    let started = Instant::now();
    let mut workers = JoinSet::new();
    for worker in 0..profile.concurrency {
        let count = split_work(profile.operations, profile.concurrency, worker);
        let provider = provider.clone();
        let payload = payload.clone();
        workers.spawn(async move {
            let mut client = KernelClient::connect(address)
                .await
                .map_err(|error| error.to_string())?;
            let agent = client
                .create_agent(
                    format!("{}-{worker}", provider),
                    "provider and context capacity profile",
                    Some(provider),
                    Some("read-only".into()),
                    Some(3),
                )
                .await
                .map_err(|error| error.to_string())?;
            let mut output = Vec::with_capacity(count);
            for _ in 0..count {
                let call = Instant::now();
                let result = client
                    .send_message(&agent, payload.clone())
                    .await
                    .map(|_| ());
                output.push((call.elapsed().as_secs_f64() * 1_000.0, result));
            }
            Ok::<_, String>(output)
        });
    }
    let (successes, failures, latencies, notes) = collect_workers(workers).await?;
    let observed_max_prompt_bytes = observed.load(Ordering::SeqCst);
    stop_server(task).await;
    kernel.shutdown().await.map_err(|error| error.to_string())?;
    Ok(finish_result(
        profile,
        started,
        successes,
        failures,
        latencies,
        observed_max_prompt_bytes,
        notes,
    ))
}

async fn tool_heavy_profile(profile: &ProfileConfig) -> Result<ProfileResult, String> {
    let kernel = Arc::new(qualification_kernel(profile)?);
    let (address, task) = start_server(Arc::clone(&kernel)).await?;
    let started = Instant::now();
    let mut workers = JoinSet::new();
    for worker in 0..profile.concurrency {
        let count = split_work(profile.operations, profile.concurrency, worker);
        workers.spawn(async move {
            let mut client = KernelClient::connect(address)
                .await
                .map_err(|error| error.to_string())?;
            let agent = client
                .create_agent(
                    format!("tool-capacity-{worker}"),
                    "tool-heavy public execution profile",
                    None,
                    Some("full-access".into()),
                    Some(3),
                )
                .await
                .map_err(|error| error.to_string())?;
            let mut output = Vec::with_capacity(count);
            for _ in 0..count {
                let call = Instant::now();
                let result = client
                    .call_tool(&agent, "list_directory", serde_json::json!({"path": "."}))
                    .await
                    .map(|_| ());
                output.push((call.elapsed().as_secs_f64() * 1_000.0, result));
            }
            Ok::<_, String>(output)
        });
    }
    let (successes, failures, latencies, notes) = collect_workers(workers).await?;
    stop_server(task).await;
    kernel.shutdown().await.map_err(|error| error.to_string())?;
    Ok(finish_result(
        profile, started, successes, failures, latencies, 0, notes,
    ))
}

async fn tenant_contention_profile(profile: &ProfileConfig) -> Result<ProfileResult, String> {
    let provider = "capacity-tenant-provider";
    let kernel = Arc::new(qualification_kernel(profile)?);
    let observed = register_delayed_provider(&kernel, provider, profile.provider_delay_ms)?;
    let mut credentials = Vec::with_capacity(profile.tenants);
    for tenant_index in 0..profile.tenants {
        let tenant = kernel
            .create_tenant(&format!("capacity-tenant-{tenant_index}"))
            .await
            .map_err(|error| error.to_string())?;
        let user = kernel
            .register_user(
                &tenant,
                &format!("capacity-user-{tenant_index}"),
                &format!("capacity-{tenant_index}@example.invalid"),
                Role::Admin,
            )
            .await
            .map_err(|error| error.to_string())?;
        let key = kernel
            .issue_api_key(&user, "capacity-qualification")
            .await
            .map_err(|error| error.to_string())?;
        credentials.push(key);
    }
    let (address, task) = start_server(Arc::clone(&kernel)).await?;
    let payload = "t".repeat(profile.payload_bytes);
    let started = Instant::now();
    let mut workers = JoinSet::new();
    for (tenant_index, key) in credentials.into_iter().enumerate() {
        let operations = split_work(profile.operations, profile.tenants, tenant_index);
        let agents = profile.agents_per_tenant;
        let payload = payload.clone();
        workers.spawn(async move {
            let mut client = KernelClient::connect(address)
                .await
                .map_err(|error| error.to_string())?;
            client
                .authenticate(key)
                .await
                .map_err(|error| error.to_string())?;
            let mut agent_ids = Vec::with_capacity(agents);
            for agent_index in 0..agents {
                agent_ids.push(
                    client
                        .create_agent(
                            format!("tenant-{tenant_index}-agent-{agent_index}"),
                            "tenant contention profile",
                            Some(provider.into()),
                            Some("read-only".into()),
                            Some(3),
                        )
                        .await
                        .map_err(|error| error.to_string())?,
                );
            }
            let mut output = Vec::with_capacity(operations);
            for operation in 0..operations {
                let call = Instant::now();
                let result = client
                    .send_message(&agent_ids[operation % agent_ids.len()], payload.clone())
                    .await
                    .map(|_| ());
                output.push((call.elapsed().as_secs_f64() * 1_000.0, result));
            }
            Ok::<_, String>(output)
        });
    }
    let (successes, failures, latencies, notes) = collect_workers(workers).await?;
    let observed_max_prompt_bytes = observed.load(Ordering::SeqCst);
    stop_server(task).await;
    kernel.shutdown().await.map_err(|error| error.to_string())?;
    Ok(finish_result(
        profile,
        started,
        successes,
        failures,
        latencies,
        observed_max_prompt_bytes,
        notes,
    ))
}

fn capacity_package(name: &str, publisher: &str, payload_bytes: usize) -> PackagePayload {
    PackagePayload {
        schema_version: 1,
        package: PackageManifest {
            name: name.into(),
            version: Version::new(1, 0, 0),
            description: "Capacity qualification package".into(),
            publisher: publisher.into(),
            license: Some("AGPL-3.0-only".into()),
            dependencies: Vec::new(),
            capabilities_required: vec!["CAP_FILE_READ".into()],
            tools_required: Vec::new(),
        },
        agent: AgentManifest {
            name: name.into(),
            description: "Signed package install workload".into(),
            task: "measure verified transactional package installation".into(),
            entry: None,
            provider: "stub".into(),
            profile: "read-only".into(),
            priority: 3,
            nice: None,
            tools: Vec::new(),
            memory: Vec::new(),
        },
        files: vec![PackageFile {
            path: "assets/payload.bin".into(),
            kind: PackageFileKind::Asset,
            bytes: vec![0x5a; payload_bytes],
            checksum_sha256: String::new(),
        }],
        sbom: PackageSbom {
            format: "SPDX-2.3".into(),
            components: vec![SbomComponent {
                name: "agentos-kernel-api".into(),
                version: "1".into(),
                license: Some("AGPL-3.0-only".into()),
                checksum_sha256: None,
            }],
        },
    }
}

async fn package_install_profile(profile: &ProfileConfig) -> Result<ProfileResult, String> {
    let kernel = Arc::new(qualification_kernel(profile)?);
    let tenant = kernel
        .create_tenant("capacity-package-tenant")
        .await
        .map_err(|error| error.to_string())?;
    let admin = kernel
        .register_user(
            &tenant,
            "capacity-package-publisher",
            "capacity-package@example.invalid",
            Role::Admin,
        )
        .await
        .map_err(|error| error.to_string())?;
    let api_key = kernel
        .issue_api_key(&admin, "capacity-package")
        .await
        .map_err(|error| error.to_string())?;
    let (address, task) = start_server(Arc::clone(&kernel)).await?;
    let mut client = KernelClient::connect(address)
        .await
        .map_err(|error| error.to_string())?;
    client
        .authenticate(api_key)
        .await
        .map_err(|error| error.to_string())?;
    let (signer, _) =
        PackageSigningKey::generate(&admin, "capacity-v1").map_err(|error| error.to_string())?;
    client
        .trust_package_key(
            &admin,
            signer.key_id(),
            &signer.public_key(),
            (Utc::now() - chrono::Duration::minutes(1)).to_rfc3339(),
            None,
            None,
        )
        .await
        .map_err(|error| error.to_string())?;
    let package_name = "capacity-package";
    let archive = PackageArchive::sign(
        capacity_package(package_name, &admin, profile.payload_bytes),
        &signer,
    )
    .map_err(|error| error.to_string())?;
    client
        .publish_package(&archive)
        .await
        .map_err(|error| error.to_string())?;

    let started = Instant::now();
    let mut successes = 0;
    let mut failures = 0;
    let mut latencies = Vec::with_capacity(profile.operations);
    let mut notes = Vec::new();
    for _ in 0..profile.operations {
        let call = Instant::now();
        let result = async {
            client.install_package(package_name, "=1.0.0").await?;
            client.remove_package(package_name).await
        }
        .await;
        latencies.push(call.elapsed().as_secs_f64() * 1_000.0);
        match result {
            Ok(()) => successes += 1,
            Err(error) => {
                failures += 1;
                push_error(&mut notes, error);
            }
        }
    }
    stop_server(task).await;
    kernel.shutdown().await.map_err(|error| error.to_string())?;
    Ok(finish_result(
        profile, started, successes, failures, latencies, 0, notes,
    ))
}

async fn restart_profile(profile: &ProfileConfig) -> Result<ProfileResult, String> {
    let root =
        std::env::temp_dir().join(format!("agentos-capacity-restart-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&root).map_err(|error| error.to_string())?;
    let mut kernel_config = Config {
        data_dir: root.clone(),
        ..Config::default()
    };
    kernel_config.budgets = budget_for_profile(profile);
    let started = Instant::now();
    let mut successes = 0;
    let mut failures = 0;
    let mut latencies = Vec::with_capacity(profile.operations);
    let mut notes = Vec::new();
    let mut expected_agents = Vec::new();
    for cycle in 0..profile.operations {
        let call = Instant::now();
        let result = async {
            let kernel = Arc::new(
                AgentKernelImpl::from_config(&kernel_config).map_err(|error| error.to_string())?,
            );
            let (address, task) = start_server(Arc::clone(&kernel)).await?;
            let mut client = KernelClient::connect(address)
                .await
                .map_err(|error| error.to_string())?;
            if cycle == 0 {
                for agent_index in 0..profile.agents_per_tenant {
                    let id = client
                        .create_agent(
                            format!("restart-agent-{agent_index}"),
                            "durable restart qualification",
                            None,
                            Some("read-only".into()),
                            Some(3),
                        )
                        .await
                        .map_err(|error| error.to_string())?;
                    client
                        .storage_put(&id, "capacity-sentinel", "durable-value")
                        .await
                        .map_err(|error| error.to_string())?;
                    expected_agents.push(id);
                }
            } else {
                let listed = client
                    .list_agents()
                    .await
                    .map_err(|error| error.to_string())?;
                if listed.len() != expected_agents.len() {
                    return Err(format!(
                        "restart restored {} agents, expected {}",
                        listed.len(),
                        expected_agents.len()
                    ));
                }
                for id in &expected_agents {
                    let value = client
                        .storage_get(id, "capacity-sentinel")
                        .await
                        .map_err(|error| error.to_string())?;
                    if value.as_deref() != Some("durable-value") {
                        return Err(format!("restart lost storage sentinel for {id}"));
                    }
                }
            }
            client
                .close()
                .await
                .map_err(|error| format!("graceful client close failed: {error}"))?;
            stop_server(task).await;
            drop(kernel);
            Ok::<_, String>(())
        }
        .await;
        latencies.push(call.elapsed().as_secs_f64() * 1_000.0);
        match result {
            Ok(()) => successes += 1,
            Err(error) => {
                failures += 1;
                push_error(&mut notes, error);
                break;
            }
        }
    }
    if let Err(error) = std::fs::remove_dir_all(&root) {
        push_error(
            &mut notes,
            format!("cleanup {} failed: {error}", root.display()),
        );
    }
    Ok(finish_result(
        profile, started, successes, failures, latencies, 0, notes,
    ))
}

async fn collect_workers<E>(
    mut workers: JoinSet<WorkerOutput<E>>,
) -> Result<(usize, usize, Vec<f64>, Vec<String>), String>
where
    E: ToString + 'static,
{
    let mut successes = 0;
    let mut failures = 0;
    let mut latencies = Vec::new();
    let mut notes = Vec::new();
    while let Some(joined) = workers.join_next().await {
        let output = joined.map_err(|error| format!("workload worker failed: {error}"))??;
        for (latency, result) in output {
            latencies.push(latency);
            match result {
                Ok(()) => successes += 1,
                Err(error) => {
                    failures += 1;
                    push_error(&mut notes, error);
                }
            }
        }
    }
    Ok((successes, failures, latencies, notes))
}

async fn run_profile(profile: &ProfileConfig) -> Result<ProfileResult, String> {
    match profile.kind {
        WorkloadKind::Idle => idle_profile(profile).await,
        WorkloadKind::ManyAgents => many_agents_profile(profile).await,
        WorkloadKind::LongContext | WorkloadKind::ProviderLatency => {
            provider_profile(profile).await
        }
        WorkloadKind::ToolHeavy => tool_heavy_profile(profile).await,
        WorkloadKind::TenantContention => tenant_contention_profile(profile).await,
        WorkloadKind::PackageInstall => package_install_profile(profile).await,
        WorkloadKind::Restart => restart_profile(profile).await,
    }
}

fn source_metadata() -> SourceMetadata {
    let commit = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|output| output.trim().to_string())
        .filter(|output| !output.is_empty())
        .unwrap_or_else(|| "unknown".into());
    let dirty = Command::new("git")
        .args(["status", "--porcelain"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| !output.stdout.is_empty());
    let rustc = Command::new("rustc")
        .arg("--version")
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|output| output.trim().to_string())
        .filter(|output| !output.is_empty())
        .unwrap_or_else(|| "unknown".into());
    SourceMetadata {
        commit,
        dirty,
        rustc,
    }
}

fn host_cpu_model() -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        return std::fs::read_to_string("/proc/cpuinfo")
            .ok()?
            .lines()
            .find_map(|line| line.strip_prefix("model name"))
            .and_then(|line| line.split_once(':'))
            .map(|(_, value)| value.trim().to_string());
    }
    #[cfg(target_os = "macos")]
    {
        return Command::new("sysctl")
            .args(["-n", "machdep.cpu.brand_string"])
            .output()
            .ok()
            .filter(|output| output.status.success())
            .and_then(|output| String::from_utf8(output.stdout).ok())
            .map(|output| output.trim().to_string())
            .filter(|output| !output.is_empty());
    }
    #[allow(unreachable_code)]
    None
}

fn host_memory_bytes() -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        return std::fs::read_to_string("/proc/meminfo")
            .ok()?
            .lines()
            .find_map(|line| line.strip_prefix("MemTotal:"))
            .and_then(|value| value.split_whitespace().next())
            .and_then(|value| value.parse::<u64>().ok())
            .and_then(|kibibytes| kibibytes.checked_mul(1024));
    }
    #[cfg(target_os = "macos")]
    {
        return Command::new("sysctl")
            .args(["-n", "hw.memsize"])
            .output()
            .ok()
            .filter(|output| output.status.success())
            .and_then(|output| String::from_utf8(output.stdout).ok())
            .and_then(|output| output.trim().parse::<u64>().ok());
    }
    #[allow(unreachable_code)]
    None
}

fn selected_profiles(config: &SuiteConfig, cli: &Cli) -> Result<Vec<ProfileConfig>, String> {
    if cli.run_all {
        return Ok(config.profiles.clone());
    }
    if cli.selected.is_empty() {
        return Ok(Vec::new());
    }
    let selected = cli.selected.iter().cloned().collect::<BTreeSet<_>>();
    let known = config
        .profiles
        .iter()
        .map(|profile| profile.name.clone())
        .collect::<BTreeSet<_>>();
    let unknown = selected.difference(&known).cloned().collect::<Vec<_>>();
    if !unknown.is_empty() {
        return Err(format!("unknown profiles: {}", unknown.join(", ")));
    }
    Ok(config
        .profiles
        .iter()
        .filter(|profile| selected.contains(&profile.name))
        .cloned()
        .collect())
}

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("capacity qualification failed: {error}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), String> {
    let cli = parse_cli()?;
    let config = read_config(cli.config.as_deref())?;
    validate_config(&config)?;
    let mut profiles = selected_profiles(&config, &cli)?;
    if cli.validate_only || profiles.is_empty() {
        println!(
            "validated {} schema v{} profiles: {}",
            config.suite,
            config.schema_version,
            config
                .profiles
                .iter()
                .map(|profile| profile.name.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        );
        return Ok(());
    }
    if cfg!(debug_assertions) && !cli.allow_debug && !cli.smoke {
        return Err(
            "capacity runs require a --release build; use --allow-debug only for development"
                .into(),
        );
    }
    if cli.smoke {
        profiles = profiles.iter().map(smoke_scale).collect();
    }

    let mut results = Vec::with_capacity(profiles.len());
    for profile in &profiles {
        eprintln!(
            "running {} ({:?}, {} operations, concurrency {})",
            profile.name, profile.kind, profile.operations, profile.concurrency
        );
        results.push(run_profile(profile).await?);
    }
    let passed = results.iter().all(|result| result.passed);
    let report = QualificationReport {
        schema_version: 1,
        suite: config.suite,
        generated_at: Utc::now().to_rfc3339(),
        qualification_class: "deterministic_fixture_baseline",
        capacity_claim_allowed: false,
        build_profile: if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        },
        smoke_scaled: cli.smoke,
        host: HostMetadata {
            os: std::env::consts::OS,
            arch: std::env::consts::ARCH,
            logical_cpus: std::thread::available_parallelism()
                .map(usize::from)
                .unwrap_or(1),
            cpu_model: host_cpu_model(),
            memory_bytes: host_memory_bytes(),
            qualification_environment: std::env::var("AGENTOS_QUALIFICATION_ENVIRONMENT").ok(),
        },
        source: source_metadata(),
        profiles: results,
        passed,
        caveats: vec![
            "The deterministic local provider isolates AgentOS overhead; it does not represent a hosted provider SLA.",
            "The in-process loopback server is a reproducible baseline, not a multi-node or internet deployment.",
            "Production capacity requires a clean exact-commit release run on the intended deployment shape plus SLO evaluation.",
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
        return Err("one or more workload profiles failed".into());
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
        assert_eq!(config.profiles.len(), REQUIRED_PROFILES.len());
    }

    #[test]
    fn validator_rejects_missing_profile() {
        let mut config: SuiteConfig = toml::from_str(DEFAULT_CONFIG).unwrap();
        config.profiles.pop();
        assert!(validate_config(&config)
            .unwrap_err()
            .contains("must contain exactly"));
    }

    #[test]
    fn percentile_is_stable_and_bounded() {
        let samples = [1.0, 4.0, 2.0, 3.0, 5.0];
        assert_eq!(percentile(&samples, 0.0), 1.0);
        assert_eq!(percentile(&samples, 0.5), 3.0);
        assert_eq!(percentile(&samples, 0.99), 5.0);
        assert_eq!(percentile(&[], 0.95), 0.0);
    }

    #[tokio::test]
    async fn every_profile_completes_at_smoke_scale() {
        let config: SuiteConfig = toml::from_str(DEFAULT_CONFIG).unwrap();
        for profile in &config.profiles {
            let scaled = smoke_scale(profile);
            let result = run_profile(&scaled)
                .await
                .unwrap_or_else(|error| panic!("{} setup failed: {error}", profile.name));
            assert!(result.passed, "{} failed: {:?}", result.name, result.notes);
        }
    }
}
