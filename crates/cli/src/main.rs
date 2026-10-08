//! AI Agent OS — CLI (headless terminal agent)
//!
//! Usage:
//!   agent                        # Interactive session
//!   agent --version              # Print the exact build version and exit
//!   agent --conversation ID      # Resume conversation
//!   agent -c "do something"      # One-shot command
//!   echo "text" | agent "prompt" # Pipe mode

use std::io::{self, BufRead, Read, Write};
use std::sync::Arc;

use agent_cli::providers::register_providers;
use agent_cli::slash::{handle_slash, SlashOutcome};
use kernel::config::Config;
use kernel::execution::StreamEvent;
use kernel::learning::{RuleScope, RuleStore};
use kernel::{AgentConfig, AgentKernelImpl, Priority};

mod logging;
mod policy_cmd;
/// Read project context (README, Cargo.toml) for the system prompt.
fn project_context() -> String {
    let mut ctx = String::new();
    if let Ok(readme) = std::fs::read_to_string("README.md") {
        let preview: String = readme.chars().take(500).collect();
        ctx.push_str(&format!(
            "Project README (first 500 chars):\n{}\n\n",
            preview
        ));
    }
    if let Ok(cargo) = std::fs::read_to_string("Cargo.toml") {
        let preview: String = cargo.chars().take(300).collect();
        ctx.push_str(&format!("Cargo.toml:\n{}\n", preview));
    }
    ctx
}

/// Canonical `agent` usage text, mirroring the module documentation above.
const USAGE: &str = "\
AI Agent OS — headless terminal agent.

USAGE:
  agent                          Interactive session
  agent \"prompt\"                 One-shot prompt (also reads piped stdin)
  agent -c \"do something\"        One-shot command
  agent --conversation ID        Resume a registered local conversation
  agent policy <ARGS...>         Validate or dry-run a policy document (offline)

OPTIONS:
  -c <COMMAND>                   Run one command and exit
  --conversation <ID>            Resume a registered local conversation <ID>
  --config <PATH>                Use a private configuration file
  -h, --help                     Print this help and exit
  -V, --version                  Print the exact build version and exit

Provider, data directory, and permission profile come from the environment and
configuration file; see .env.example and docs/PROVIDERS.md. `agentctl` is the
canonical operator client for an already-running kernel.";

/// Options `agent` understands. Anything else beginning with `-` is a usage
/// error: without this the argument fell through and was treated as a prompt,
/// so a typo booted the kernel and persisted an agent row.
const KNOWN_FLAGS: [&str; 7] = ["-c", "--conversation", "--config", "-h", "--help", "-V", "--version"];

/// First unrecognized option in `argv`, if any. `-c` and `--conversation`
/// consume the following value, which may itself begin with `-`.
fn unrecognized_flag(argv: &[String]) -> Option<&str> {
    let mut index = 1;
    while index < argv.len() {
        let argument = argv[index].as_str();
        if argument == "--" {
            return None;
        }
        if argument.starts_with('-') && argument != "-" {
            if !KNOWN_FLAGS.contains(&argument) {
                return Some(argument);
            }
            if matches!(argument, "-c" | "--conversation" | "--config") {
                index += 1;
            }
        }
        index += 1;
    }
    None
}

#[tokio::main]
async fn main() {
    // Offline subcommands that don't need a kernel/DB are dispatched before any
    // initialization. `agent policy …` validates/dry-runs a declarative policy
    // document (the SELinux checkpolicy/sesearch analogue) — see docs/POLICY.md.
    let argv: Vec<String> = std::env::args().collect();
    if argv.len() == 2 && matches!(argv[1].as_str(), "--version" | "-V") {
        println!("agent {}", env!("CARGO_PKG_VERSION"));
        return;
    }
    // `policy` claims its own arguments first, so `agent policy --help` reaches
    // the policy usage rather than this one.
    if argv.get(1).map(String::as_str) == Some("policy") {
        std::process::exit(policy_cmd::run(&argv));
    }
    // Help and argument errors are answered before any initialization. Falling
    // through to `AgentKernelImpl::from_config` created the data directory,
    // opened the database, and persisted a `cli-agent` row before failing on an
    // unreachable provider — durable side effects for a documentation request.
    if argv[1..]
        .iter()
        .any(|argument| matches!(argument.as_str(), "--help" | "-h"))
    {
        println!("{USAGE}");
        return;
    }
    if let Some(unknown) = unrecognized_flag(&argv) {
        eprintln!("agent: unrecognized option '{unknown}'\n\n{USAGE}");
        std::process::exit(2);
    }

    let config_path = argv.iter().position(|argument| argument == "--config").map(|index| {
        argv.get(index + 1).filter(|path| !path.trim().is_empty())
            .unwrap_or_else(|| {
                eprintln!("agent: --config requires a path\n\n{USAGE}");
                std::process::exit(2);
            })
    });

    // Install structured logging first so kernel init (persistence/auth) logs emit.
    logging::init_logging();
    let config = match config_path {
        Some(path) => {
            let path = std::path::Path::new(path);
            if !path.is_file() { fail(format!("explicit configuration file is missing or is not a file: {}", path.display())); }
            Config::try_load_from(path)
        }
        None => Config::try_load(),
    }
        .unwrap_or_else(|error| fail(format!("failed to load configuration: {error}")));
    // Startup failures (unwritable data dir, corrupt DB, unreachable provider)
    // degrade to a clear message + non-zero exit rather than a panic backtrace.
    let kernel = match AgentKernelImpl::from_config(&config) {
        Ok(k) => Arc::new(k),
        Err(e) => fail(format!(
            "failed to initialize kernel: {e}\n  (is the data dir writable? {})",
            config.data_dir.display()
        )),
    };
    // Start the scheduler observer that publishes the CFS pick into procfs
    // `current_agent`. Fixed-epoch provider/cgroup quotas are durable and need
    // no background reset task. Held for the process lifetime.
    let _runtime = kernel.start_runtime();
    register_providers(&kernel, &config);

    // Parse args
    let args: Vec<String> = std::env::args().collect();
    let conversation_id = args
        .iter()
        .position(|a| a == "--conversation")
        .and_then(|i| args.get(i + 1))
        .cloned();
    let one_shot = args
        .iter()
        .position(|a| a == "-c")
        .and_then(|i| args.get(i + 1))
        .cloned();

    // Check for piped input
    let piped_input = if !atty_is_terminal() {
        let mut buf = String::new();
        io::stdin().read_to_string(&mut buf).ok();
        Some(buf)
    } else {
        None
    };

    let operator = kernel::config::local_operator_identity()
        .unwrap_or_else(|error| fail(format!("failed to determine local operator: {error}")));
    let rules = Arc::new(
        RuleStore::from_file(
            &config.data_dir.join("rules.json"),
            RuleScope::local_cli(),
            &operator,
        )
        .unwrap_or_else(|error| fail(format!("failed to load local correction rules: {error}"))),
    );
    // Restore the original registered owner through the existing kernel
    // lifecycle, rather than copying another agent's history into a new one.
    kernel
        .rehydrate_agents()
        .await
        .unwrap_or_else(|error| fail(format!("failed to restore kernel agents: {error}")));
    let agent_id = if let Some(id) = conversation_id.as_deref() {
        let binding = rules
            .cli_conversation(id)
            .unwrap_or_else(|error| {
                fail(format!(
                    "failed to read local conversation binding: {error}"
                ))
            })
            .unwrap_or_else(|| fail("conversation is not registered to this local operator"));
        let restored = kernel
            .agent_manager
            .get_agent_config(binding.agent_id)
            .unwrap_or_else(|| fail("registered conversation owner is missing or was erased"));
        if restored.llm_provider != config.llm_provider
            || restored.permission_profile != config.permission_profile
        {
            fail("registered conversation provider or permission profile differs from the current CLI configuration");
        }
        binding.agent_id
    } else {
        kernel
            .create_agent_full(AgentConfig {
                name: "cli-agent".into(),
                task: "interactive assistant".into(),
                llm_provider: config.llm_provider.clone(),
                permission_profile: config.permission_profile.clone(),
                priority: Priority::default(),
                sandbox_config: None,
            })
            .await
            .unwrap_or_else(|error| fail(format!("failed to create agent: {error}")))
            .id
    };
    let project_ctx = project_context();
    let system_prompt = format!("You are a helpful AI assistant running in a terminal. Be concise and use tools when needed.\n\n{}", project_ctx);

    let conversation = kernel
        .configure_local_cli_agent(
            agent_id,
            rules.clone(),
            system_prompt,
            conversation_id.as_deref(),
        )
        .await
        .unwrap_or_else(|error| fail(format!("failed to configure CLI agent: {error}")));

    // One-shot mode
    if let Some(cmd) = one_shot {
        match cancellable_cli_operation(
            &kernel,
            agent_id,
            handle_slash(&cmd, &kernel, agent_id, &conversation, &rules),
        )
        .await
        {
            Ok(SlashOutcome::Output(output)) => {
                println!("{output}");
                return;
            }
            Ok(SlashOutcome::Quit) => return,
            Ok(SlashOutcome::NotSlash) => {}
            Err(error) => fail(error),
        }
        let msg = if let Some(ref piped) = piped_input {
            format!("{}\n\nInput:\n{}", cmd, piped)
        } else {
            cmd
        };
        let output = run_cli_turn(&kernel, agent_id, &msg)
            .await
            .unwrap_or_else(|e| fail(format!("run failed: {e}")));
        println!("{}", output.content);
        return;
    }

    // Pipe mode (no prompt, just process)
    if let Some(piped) = piped_input {
        let prompt = args
            .get(1)
            .map(|s| s.as_str())
            .unwrap_or("Process this input");
        let msg = format!("{}\n\nInput:\n{}", prompt, piped);
        let output = run_cli_turn(&kernel, agent_id, &msg)
            .await
            .unwrap_or_else(|e| fail(format!("run failed: {e}")));
        println!("{}", output.content);
        return;
    }

    // Interactive mode
    eprintln!(
        "\x1b[36m⚡ AI Agent OS\x1b[0m \x1b[90m({})\x1b[0m",
        config.llm_provider
    );
    eprintln!(
        "\x1b[90mConversation: {} | /help for commands\x1b[0m\n",
        &conversation
    );

    let stdin = io::stdin();
    let mut stdout = io::stdout();

    loop {
        print!("\x1b[32m❯\x1b[0m ");
        stdout.flush().ok();

        let mut input = String::new();
        if stdin.lock().read_line(&mut input).unwrap_or(0) == 0 {
            break;
        }
        let input = input.trim();
        if input.is_empty() {
            continue;
        }

        match cancellable_cli_operation(
            &kernel,
            agent_id,
            handle_slash(input, &kernel, agent_id, &conversation, &rules),
        )
        .await
        {
            Ok(SlashOutcome::Output(output)) => {
                println!("{output}");
                continue;
            }
            Ok(SlashOutcome::Quit) => break,
            Ok(SlashOutcome::NotSlash) => {}
            Err(error) => {
                eprintln!("Error: {error}");
                continue;
            }
        }
        let output = run_cli_turn(&kernel, agent_id, input).await;

        match output {
            Ok(out) => {
                println!("\n\x1b[37m{}\x1b[0m", out.content);
                if out.tool_calls_made > 0 {
                    eprintln!(
                        "\x1b[90m  [{} tools, {} tokens, ${:.4}]\x1b[0m\n",
                        out.tool_calls_made, out.tokens_used, out.estimated_cost_usd
                    );
                } else {
                    eprintln!("\x1b[90m  [{} tokens]\x1b[0m\n", out.tokens_used);
                }
            }
            Err(e) => eprintln!("\x1b[31m  Error: {}\x1b[0m\n", e),
        }
    }
    if kernel
        .context_manager
        .conversation_owner(&conversation)
        .ok()
        == Some(agent_id)
    {
        eprintln!("\n\x1b[90mSaved: {}\x1b[0m", conversation);
    } else {
        eprintln!(
            "\n\x1b[90mNo messages saved. Conversation: {}\x1b[0m",
            conversation
        );
    }
}

fn atty_is_terminal() -> bool {
    unsafe { libc::isatty(0) != 0 }
}

async fn cancellable_cli_operation<T>(
    kernel: &AgentKernelImpl,
    agent: kernel::AgentId,
    operation: impl std::future::Future<Output = Result<T, String>>,
) -> Result<T, String> {
    tokio::pin!(operation);
    tokio::select! {
        result = &mut operation => result,
        interrupted = tokio::signal::ctrl_c() => {
            interrupted.map_err(|error| format!("failed to receive terminal interrupt: {error}"))?;
            kernel.cancel_local_turn(agent);
            let _ = operation.await;
            Err("Operation cancelled by terminal interrupt.".into())
        }
    }
}

async fn run_cli_turn(
    kernel: &AgentKernelImpl,
    agent: kernel::AgentId,
    message: &str,
) -> Result<kernel::execution::AgentOutput, String> {
    let (events, mut receiver) = tokio::sync::mpsc::channel(256);
    let display = tokio::spawn(async move {
        while let Some(event) = receiver.recv().await {
            match event {
                StreamEvent::ToolCallStarted { name, .. } => eprint!("\x1b[33m  🔧 {name}\x1b[0m"),
                StreamEvent::ToolCallResult { .. } => eprintln!(" ✓"),
                _ => {}
            }
        }
    });
    let request = kernel::AgentId::new_v4().to_string();
    let output = cancellable_cli_operation(kernel, agent, async {
        kernel
            .send_message_stream(agent, message, &request, events)
            .await
            .map_err(|error| error.to_string())
    })
    .await;
    display
        .await
        .map_err(|error| format!("terminal event display failed: {error}"))?;
    output
}

/// Print a clean, user-facing startup error and exit non-zero.
///
/// Startup failures (config, persistence, provider) are operator errors, not
/// bugs — surface them as a readable message instead of a panic backtrace.
/// Returns `!` so it can stand in for any value at a `?`-less call site.
fn fail(msg: impl std::fmt::Display) -> ! {
    tracing::error!("{msg}");
    eprintln!("\x1b[31magent: {msg}\x1b[0m");
    std::process::exit(1);
}
