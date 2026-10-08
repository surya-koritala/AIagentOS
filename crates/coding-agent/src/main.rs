use agent_sdk::KernelClient;
use coding_agent::io::JobIo;
use coding_agent::provider::ProposalProvider;
use coding_agent::types::*;
use coding_agent::workflow::{register_test_tool, run_job, ProcessRunner};
use coding_agent::{hash, Error};
use kernel::config::{Config, TokenPricing};
use kernel::sandbox::SandboxManagerImpl;
use kernel::tools::{ApprovalPolicy, SecurityAction, ToolBinding, ToolSecurity};
use kernel::{AgentConfig, AgentKernelImpl, IsolationLevel, Priority};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

const USAGE: &str = "agent-code fixture --image NAME@sha256:DIGEST --data-dir DIRECTORY [--pause-after-branch]\nagent-code run --repo DIRECTORY --manifest TASK.json --model MODEL --input-price-per-1k USD --output-price-per-1k USD --image NAME@sha256:DIGEST --data-dir DIRECTORY\nagent-code resume --data-dir DIRECTORY [--retry-uncertain] [--pause-after-branch]\nSupported execution target: Linux with a rootless Docker daemon and the pinned Rust image already installed. Results remain in isolated workspaces; the original repository is never patched.";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Locator {
    version: u32,
    id: Uuid,
    parent: Uuid,
    spec: TaskSpec,
    image: String,
    mode: String,
    model: Option<String>,
    pricing: TokenPricing,
}
fn bounded_config(path: &Path) -> Result<String, Error> {
    let file = std::fs::File::open(path)
        .map_err(|_| Error::Contract("configuration file is unavailable".into()))?;
    let mut text = String::new();
    file.take(16 * 1024 + 1)
        .read_to_string(&mut text)
        .map_err(|_| Error::Contract("configuration must be UTF-8".into()))?;
    if text.len() > 16 * 1024 {
        return Err(Error::Contract("configuration exceeds 16 KiB".into()));
    }
    Ok(text)
}
fn options(args: &[String]) -> Result<(BTreeMap<String, String>, bool, bool), Error> {
    let mut values = BTreeMap::new();
    let mut pause = false;
    let mut retry = false;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--pause-after-branch" if !pause => pause = true,
            "--retry-uncertain" if !retry => retry = true,
            flag @ ("--repo"
            | "--manifest"
            | "--model"
            | "--image"
            | "--data-dir"
            | "--input-price-per-1k"
            | "--output-price-per-1k") => {
                index += 1;
                let value = args
                    .get(index)
                    .filter(|value| !value.starts_with("--"))
                    .ok_or_else(|| Error::Contract(format!("{flag} requires a value")))?;
                if values.insert(flag.into(), value.clone()).is_some() {
                    return Err(Error::Contract("duplicate option".into()));
                }
            }
            _ => return Err(Error::Contract("unknown option".into())),
        }
        index += 1;
    }
    Ok((values, pause, retry))
}
fn required<'a>(values: &'a BTreeMap<String, String>, name: &str) -> Result<&'a str, Error> {
    values
        .get(name)
        .map(String::as_str)
        .ok_or_else(|| Error::Contract(format!("{name} is required")))
}
fn fixture_spec() -> TaskSpec {
    TaskSpec {
        instruction: "Fix bounded_prefix to return the maximal borrowed UTF-8 prefix within a byte budget, preserving its signature and all integration tests.".into(),
        files: vec!["Cargo.toml".into(), "Cargo.lock".into(), "src/lib.rs".into(), "tests/utf8_budget.rs".into()],
        editable: vec!["src/lib.rs".into()], test_target: "utf8_budget".into(), max_branches: 2,
        max_steps: 1024, deadline_seconds: 600, max_usd: 0.01, max_output_tokens: 2048,
    }
}
fn fixture_files() -> BTreeMap<String, String> {
    [
        (
            "Cargo.toml",
            include_str!("../../../fixtures/coding-agent/utf8-budget/Cargo.toml"),
        ),
        (
            "Cargo.lock",
            include_str!("../../../fixtures/coding-agent/utf8-budget/Cargo.lock"),
        ),
        (
            "src/lib.rs",
            include_str!("../../../fixtures/coding-agent/utf8-budget/src/lib.rs"),
        ),
        (
            "tests/utf8_budget.rs",
            include_str!("../../../fixtures/coding-agent/utf8-budget/tests/utf8_budget.rs"),
        ),
    ]
    .into_iter()
    .map(|(path, text)| (path.into(), text.into()))
    .collect()
}
fn agent_config(name: &str) -> AgentConfig {
    AgentConfig {
        name: name.into(),
        task: "bounded repository maintenance".into(),
        llm_provider: "coding".into(),
        permission_profile: "standard".into(),
        priority: Priority::default(),
        sandbox_config: None,
    }
}
async fn connect(addr: std::net::SocketAddr, token: &str) -> Result<KernelClient, Error> {
    let mut client = KernelClient::connect(addr).await?;
    client.authenticate(token.to_string()).await?;
    Ok(client)
}
async fn probe(
    kernel: &AgentKernelImpl,
    client: &mut KernelClient,
    agent: Uuid,
) -> Result<(), Error> {
    kernel.tool_registry.register_command_tool(ToolBinding {
        name: "coding_probe".into(), description: "Verify the preinstalled isolated Rust toolchain".into(),
        parameters_schema: serde_json::json!({"type":"object","properties":{},"additionalProperties":false}),
        resource_type: kernel::resources::ResourceType::Application, operation: "launch".into(),
        security: ToolSecurity::constant(SecurityAction::Execute, "cargo").sandboxed().with_approval(ApprovalPolicy::User),
    }, "cargo", &["--version".into()]).map_err(|error| Error::Contract(error.to_string()))?;
    kernel.approve_tool_call(
        agent,
        "coding_probe",
        &serde_json::json!({}),
        ApprovalPolicy::User,
    )?;
    let handle = client
        .vfs_open(agent.to_string(), "/tools/coding_probe")
        .await?;
    let result = client
        .vfs_invoke(agent.to_string(), &handle.id, serde_json::json!({}))
        .await;
    let _ = client.vfs_close(agent.to_string(), &handle.id).await;
    if result?["exit_code"] != 0 {
        return Err(Error::Contract(
            "isolated Rust toolchain preflight failed".into(),
        ));
    }
    Ok(())
}
async fn seed(io: &mut JobIo, parent: Uuid, files: &BTreeMap<String, String>) -> Result<(), Error> {
    let mut directories = std::collections::BTreeSet::new();
    for path in files.keys() {
        let pieces = path.split('/').collect::<Vec<_>>();
        for depth in 1..pieces.len() {
            directories.insert(pieces[..depth].join("/"));
        }
    }
    for directory in directories {
        io.mkdir(parent, &directory).await?;
    }
    for (path, contents) in files {
        io.write_file(parent, path, contents).await?;
    }
    Ok(())
}
async fn execute(args: Vec<String>) -> Result<(), Error> {
    let mode = args.first().map(String::as_str).unwrap_or("--help");
    if matches!(mode, "--version" | "-V") {
        println!("agent-code {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    if matches!(mode, "--help" | "-h") {
        println!("{USAGE}");
        return Ok(());
    }
    if !matches!(mode, "fixture" | "run" | "resume") {
        return Err(Error::Contract("unknown command".into()));
    }
    if !cfg!(target_os = "linux") {
        return Err(Error::Contract(
            "process execution requires the supported Linux/rootless-container target".into(),
        ));
    }
    let (values, pause, retry) = options(&args[1..])?;
    let allowed: &[&str] = match mode {
        "fixture" => &["--image", "--data-dir"],
        "run" => &[
            "--repo",
            "--manifest",
            "--model",
            "--image",
            "--data-dir",
            "--input-price-per-1k",
            "--output-price-per-1k",
        ],
        _ => &["--data-dir"],
    };
    if values.keys().any(|key| !allowed.contains(&key.as_str())) || (retry && mode != "resume") {
        return Err(Error::Contract(
            "option is not valid for this command".into(),
        ));
    }
    let data = PathBuf::from(required(&values, "--data-dir")?);
    let locator_path = data.join("coding-job.json");
    let mut locator = if mode == "resume" {
        let locator: Locator = serde_json::from_str(&bounded_config(&locator_path)?)?;
        if locator.version != 1 {
            return Err(Error::Contract("unsupported job locator".into()));
        }
        locator
    } else {
        if locator_path.exists() {
            return Err(Error::Contract(
                "data directory already owns a job; use resume".into(),
            ));
        }
        let image = required(&values, "--image")?.to_string();
        kernel::docker_sandbox::validate_digest_image(&image).map_err(Error::Contract)?;
        let spec = if mode == "fixture" {
            fixture_spec()
        } else {
            serde_json::from_str(&bounded_config(Path::new(required(
                &values,
                "--manifest",
            )?))?)?
        };
        let model = if mode == "run" {
            Some(required(&values, "--model")?.to_string())
        } else {
            None
        };
        let pricing = if mode == "run" {
            let input = required(&values, "--input-price-per-1k")?
                .parse::<f64>()
                .map_err(|_| Error::Contract("invalid configured input price".into()))?;
            let output = required(&values, "--output-price-per-1k")?
                .parse::<f64>()
                .map_err(|_| Error::Contract("invalid configured output price".into()))?;
            if !input.is_finite() || !output.is_finite() || input <= 0.0 || output <= 0.0 {
                return Err(Error::Contract(
                    "real provider prices must be finite and positive".into(),
                ));
            }
            TokenPricing {
                input_usd_per_1k_tokens: input,
                cached_input_usd_per_1k_tokens: input,
                output_usd_per_1k_tokens: output,
            }
        } else {
            TokenPricing {
                input_usd_per_1k_tokens: 0.0,
                cached_input_usd_per_1k_tokens: 0.0,
                output_usd_per_1k_tokens: 0.0,
            }
        };
        Locator {
            version: 1,
            id: Uuid::new_v4(),
            parent: Uuid::nil(),
            spec,
            image,
            mode: mode.into(),
            model,
            pricing,
        }
    };
    locator.spec.validate()?;
    let mut config = Config {
        data_dir: data.clone(),
        llm_provider: "coding".into(),
        ..Default::default()
    };
    config.budgets.max_usd = locator.spec.max_usd;
    config.budgets.max_output_tokens_per_request = locator.spec.max_output_tokens;
    config.budgets.agent_tokens_per_min = 200_000;
    config.budgets.tpm = 200_000;
    config.budgets.max_context_tokens = 65_536;
    config.budgets.max_concurrent = 1;
    config
        .budgets
        .provider_token_pricing
        .insert("coding".into(), locator.pricing);
    let kernel = Arc::new(AgentKernelImpl::from_config(&config)?);
    let _runtime = kernel.start_runtime();
    let provider = if locator.mode == "fixture" {
        ProposalProvider::fixture()
    } else {
        let key = std::env::var("OPENAI_API_KEY").map_err(|_| {
            Error::Contract("OPENAI_API_KEY is required for real-provider mode".into())
        })?;
        ProposalProvider::real(
            Arc::new(
                adapters::openai::OpenAiAdapter::new(key).with_model(
                    locator
                        .model
                        .clone()
                        .ok_or_else(|| Error::Contract("model missing".into()))?,
                ),
            ),
            kernel.budget_enforcer.clone(),
        )
    };
    kernel.register_provider(Arc::new(provider))?;
    register_test_tool(&kernel, &locator.spec.test_target)?;
    let token = format!("{}{}", Uuid::new_v4(), Uuid::new_v4());
    let server = kernel::syscall_server::SyscallServer::bind(kernel.clone(), "127.0.0.1:0")
        .await
        .map_err(|_| Error::Contract("local kernel server unavailable".into()))?
        .with_auth_token(token.clone());
    let addr = server
        .local_addr()
        .map_err(|_| Error::Contract("local kernel address unavailable".into()))?;
    let server_task = tokio::spawn(server.serve());
    let main = connect(addr, &token).await?;
    let control = connect(addr, &token).await?;
    let cancel = CancellationToken::new();
    let signal = cancel.clone();
    let signal_task = tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            signal.cancel();
        }
    });
    let mut journal = if mode == "resume" {
        let mut reader = connect(addr, &token).await?;
        let journal = JobIo::load(&mut reader, locator.parent, locator.id).await?;
        reader.close().await?;
        if journal.spec != locator.spec
            || journal.image != locator.image
            || journal.mode != locator.mode
            || journal.model != locator.model
        {
            return Err(Error::Contract(
                "locator disagrees with durable job policy".into(),
            ));
        }
        journal
    } else {
        let mut sandbox = SandboxManagerImpl::default_config();
        sandbox.isolation_level = IsolationLevel::Container;
        sandbox.container_image = Some(locator.image.clone());
        sandbox.max_memory_bytes = Some(1024 * 1024 * 1024);
        let parent = kernel
            .create_agent_with_managed_sandbox(agent_config("coding coordinator"), sandbox)
            .await?
            .id;
        locator.parent = parent;
        Journal {
            version: JOURNAL_VERSION,
            id: locator.id,
            parent,
            spec: locator.spec.clone(),
            image: locator.image.clone(),
            mode: locator.mode.clone(),
            model: locator.model.clone(),
            created: chrono::Utc::now(),
            files: BTreeMap::new(),
            branches: vec![],
            events: vec![],
            steps: 0,
            provider_tokens: 0,
            selected: None,
            status: "captured".into(),
        }
    };
    let mut io = JobIo::new(main, control, &journal, cancel);
    let mut locator_created = false;
    let initialization = async {
        if mode != "resume" {
            // Check the actual rootless/pinned backend before incurring provider cost.
            probe(&kernel, &mut io.control, journal.parent).await?;
            journal.files = if mode == "fixture" {
                fixture_files()
            } else {
                let repo = std::fs::canonicalize(required(&values, "--repo")?)
                    .map_err(|_| Error::Contract("repository directory unavailable".into()))?;
                let mut sandbox = SandboxManagerImpl::default_config();
                sandbox.workspace_dir = repo;
                sandbox.isolation_level = IsolationLevel::Trusted;
                let mut config = agent_config("read-only repository import");
                config.permission_profile = "read-only".into();
                config.sandbox_config = Some(sandbox);
                let source = kernel.create_agent_full(config).await?.id;
                let mut files = BTreeMap::new();
                let captured = async {
                    for path in &journal.spec.files {
                        files.insert(path.clone(), io.read_file(source, path).await?);
                    }
                    Ok::<_, Error>(())
                }
                .await;
                io.control.kill_agent(source.to_string()).await?;
                io.control
                    .erase_agent_data(source, agent_sdk::CONFIRM_DATA_ERASURE)
                    .await?;
                captured?;
                files
            };
            journal.validate()?;
            seed(&mut io, journal.parent, &journal.files).await?;
            io.persist(&mut journal).await?;
            std::fs::create_dir_all(&data)
                .map_err(|_| Error::Contract("job directory unavailable".into()))?;
            let mut file_options = std::fs::OpenOptions::new();
            file_options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                file_options.mode(0o600);
            }
            let mut file = file_options
                .open(&locator_path)
                .map_err(|_| Error::Contract("job locator could not be created".into()))?;
            locator_created = true;
            use std::io::Write;
            file.write_all(serde_json::to_string_pretty(&locator)?.as_bytes())
                .map_err(|_| Error::Contract("job locator write failed".into()))?;
            file.sync_all()
                .map_err(|_| Error::Contract("job locator sync failed".into()))?;
        }
        Ok::<_, Error>(())
    }
    .await;
    if let Err(error) = initialization {
        if mode != "resume" {
            let _ = io.control.kill_agent(journal.parent.to_string()).await;
            let _ = io
                .control
                .erase_agent_data(journal.parent, agent_sdk::CONFIRM_DATA_ERASURE)
                .await;
            if locator_created {
                let _ = std::fs::remove_file(&locator_path);
            }
        }
        let _ = io.client.close().await;
        let _ = io.control.close().await;
        signal_task.abort();
        server_task.abort();
        let _ = server_task.await;
        return Err(error);
    }
    let result = run_job(
        &mut io,
        &mut journal,
        &ProcessRunner {
            kernel: kernel.clone(),
        },
        retry,
        pause,
    )
    .await;
    let changed = journal.branches.iter().find(|branch| Some(branch.id) == journal.selected)
        .and_then(|branch| branch.proposal.as_ref()).map(|proposal| proposal.edits.iter().map(|edit| serde_json::json!({"path":edit.path,"before_sha256":edit.expected_sha256,"after_sha256":hash(edit.replacement.as_bytes()),"replacement":edit.replacement})).collect::<Vec<_>>()).unwrap_or_default();
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "job_id":journal.id,"status":journal.status,"selected_agent":journal.selected,"changed_files":changed,
            "branches":journal.branches,"events":journal.events,"provider_tokens":journal.provider_tokens,
            "configured_cost_usd":kernel.budget_enforcer.global_spent_usd(),"original_repository_written":false,
            "isolation":"linux_rootless_container","model":journal.model,"mode":journal.mode,
        }))?
    );
    let _ = io.client.close().await;
    let _ = io.control.close().await;
    signal_task.abort();
    server_task.abort();
    let _ = server_task.await;
    result
}

#[tokio::main]
async fn main() {
    match execute(std::env::args().skip(1).collect()).await {
        Ok(()) | Err(Error::Paused) => {}
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(1);
        }
    }
}
