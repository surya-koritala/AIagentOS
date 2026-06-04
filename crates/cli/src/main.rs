//! AI Agent OS — CLI (headless terminal agent)
//!
//! Usage:
//!   agent                        # Interactive session
//!   agent --conversation ID      # Resume conversation
//!   agent -c "do something"      # One-shot command
//!   echo "text" | agent "prompt" # Pipe mode

use std::io::{self, BufRead, Read, Write};
use std::sync::Arc;

use kernel::config::Config;
use kernel::connector::AgentConnector;
use kernel::execution::{AgentExecutor, StreamEvent};
use kernel::resources::ResourceBroker;
use kernel::{AgentConfig, AgentKernelImpl, Priority};
use tokio::sync::mpsc;

mod logging;
mod providers;
use providers::register_providers;

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

/// Handle slash commands. Returns true if handled.
fn handle_slash(cmd: &str, executor: &AgentExecutor, kernel: &AgentKernelImpl) -> bool {
    match cmd.split_whitespace().next().unwrap_or("") {
        "/quit" | "/exit" => std::process::exit(0),
        "/id" => {
            println!("\x1b[90m{}\x1b[0m", executor.conversation_id);
            true
        }
        "/history" => {
            let convs = kernel.context_manager.list_conversations();
            println!("\x1b[90mConversations ({}):\x1b[0m", convs.len());
            for (id, _, updated) in convs.iter().take(10) {
                println!("  {} ({})", &id[..8], updated);
            }
            true
        }
        "/usage" => {
            let (tokens, cost) = kernel.context_manager.get_total_usage();
            let stats = kernel.rate_limiter.stats();
            println!(
                "\x1b[90mTokens: {} | Cost: ${:.4} | RPM: {}/{}\x1b[0m",
                tokens, cost, stats.requests_this_minute, stats.rpm_limit
            );
            true
        }
        "/plan" => {
            println!("\x1b[90mUse: /plan <task description> to generate a plan\x1b[0m");
            true
        }
        "/learn" => {
            let parts: Vec<&str> = cmd.splitn(3, ' ').collect();
            if parts.len() == 3 {
                println!(
                    "\x1b[90mRule added: when '{}' → '{}'\x1b[0m",
                    parts[1], parts[2]
                );
            } else {
                println!("\x1b[90mUse: /learn <trigger> <correction>\x1b[0m");
            }
            true
        }
        "/help" => {
            println!("\x1b[90mCommands:");
            println!("  /quit        Exit");
            println!("  /id          Show conversation ID");
            println!("  /history     List saved conversations");
            println!("  /usage       Show token usage and cost");
            println!("  /learn T C   Add correction rule (trigger → correction)");
            println!("  /help        This message\x1b[0m");
            true
        }
        _ if cmd.starts_with('/') => {
            println!("\x1b[90mUnknown command. Type /help\x1b[0m");
            true
        }
        _ => false,
    }
}

#[tokio::main]
async fn main() {
    // Install structured logging first so kernel init (persistence/auth) logs emit.
    logging::init_logging();
    let config = Config::load();
    // Startup failures (unwritable data dir, corrupt DB, unreachable provider)
    // degrade to a clear message + non-zero exit rather than a panic backtrace.
    let kernel = match AgentKernelImpl::from_config(&config) {
        Ok(k) => Arc::new(k),
        Err(e) => fail(format!(
            "failed to initialize kernel: {e}\n  (is the data dir writable? {})",
            config.data_dir.display()
        )),
    };
    // Start the kernel's background runtime on the live path: the scheduler
    // observer (publishes the CFS pick into procfs `current_agent`) and the
    // per-minute cgroup-counter reset that regenerates token quotas. Held for
    // the process lifetime; graceful stop()/signal handling is a follow-up.
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

    // Create agent
    let handle = kernel
        .create_agent_full(AgentConfig {
            name: "cli-agent".into(),
            task: "interactive assistant".into(),
            llm_provider: config.llm_provider.clone(),
            permission_profile: config.permission_profile.clone(),
            priority: Priority::default(),
            sandbox_config: None,
        })
        .await
        .unwrap_or_else(|e| fail(format!("failed to create agent: {e}")));

    // Create executor with project context
    let project_ctx = project_context();
    let system_prompt = format!("You are a helpful AI assistant running in a terminal. Be concise and use tools when needed.\n\n{}", project_ctx);

    let session = AgentConnector::connect(&*kernel.connector, handle.id, &config.llm_provider)
        .await
        .unwrap_or_else(|e| {
            fail(format!(
                "failed to connect to LLM provider '{}': {e}\n  (check the API key and provider settings in your config/env)",
                config.llm_provider
            ))
        });
    let mut executor = AgentExecutor::new(
        handle.id,
        session,
        kernel.resource_broker.clone() as Arc<dyn ResourceBroker>,
        kernel.tool_registry.clone(),
        kernel.context_manager.clone(),
        system_prompt,
    );
    // Route every tool call through the kernel's syscall gate (capability /
    // MAC / cgroup / namespace enforcement). The agent was registered with the
    // gate in `create_agent_full` using `config.permission_profile`'s caps, so
    // tool calls are now enforced instead of running unconfined.
    executor.set_syscall_gate(kernel.syscall_gate.clone());

    if let Some(ref conv_id) = conversation_id {
        executor = executor.with_conversation(conv_id);
        eprintln!("\x1b[90mResumed: {}\x1b[0m", conv_id);
    }

    // Set up event channel
    let (tx, mut rx) = mpsc::channel::<StreamEvent>(256);
    executor.set_event_channel(tx);

    // One-shot mode
    if let Some(cmd) = one_shot {
        let msg = if let Some(ref piped) = piped_input {
            format!("{}\n\nInput:\n{}", cmd, piped)
        } else {
            cmd
        };
        let output = executor
            .run(&msg)
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
        let output = executor
            .run(&msg)
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
        &executor.conversation_id[..8]
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

        if handle_slash(input, &executor, &kernel) {
            continue;
        }

        let output = executor.run(input).await;

        // Drain events
        while let Ok(event) = rx.try_recv() {
            match event {
                StreamEvent::ToolCallStarted { name, .. } => {
                    eprint!("\x1b[33m  🔧 {}\x1b[0m", name)
                }
                StreamEvent::ToolCallResult { .. } => eprintln!(" ✓"),
                _ => {}
            }
        }

        match output {
            Ok(out) => {
                println!("\n\x1b[37m{}\x1b[0m", out.content);
                if out.tool_calls_made > 0 {
                    eprintln!(
                        "\x1b[90m  [{} tools, {} tokens, ${:.4}]\x1b[0m\n",
                        out.tool_calls_made,
                        out.tokens_used,
                        out.tokens_used as f64 * 0.00001
                    );
                } else {
                    eprintln!("\x1b[90m  [{} tokens]\x1b[0m\n", out.tokens_used);
                }
            }
            Err(e) => eprintln!("\x1b[31m  Error: {}\x1b[0m\n", e),
        }
    }
    eprintln!("\n\x1b[90mSaved: {}\x1b[0m", executor.conversation_id);
}

fn atty_is_terminal() -> bool {
    unsafe { libc::isatty(0) != 0 }
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
