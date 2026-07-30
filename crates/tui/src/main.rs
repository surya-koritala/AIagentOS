//! `agent-tui` — a Rust terminal UI for observing and driving AI Agent OS.
//!
//! Connects to a running kernel syscall server (the same boundary the SDK uses)
//! and shows live agents, gate-enforcement counters, and node load; you can
//! create agents and send turns without leaving the terminal. Rust-native
//! (ratatui + crossterm) — no web stack.
//!
//! Usage: `agent-tui [--addr ADDR] [--token TOKEN]` (default
//! `127.0.0.1:7777`). `AGENTOS_ADDR` and `AGENT_SERVER_TOKEN` provide the same
//! settings without exposing a token in shell history. Start a server first
//! with `agent-server`. Use `agent-tui --version` to print the exact build
//! version without connecting.
//!
//! Keys: `j`/`k` (or arrows) move · `r` refresh · `c` create (`name|task`) ·
//! `m` message · `C` cancel active turn · `p` pause/resume · `s` stop · `X`
//! kill · `g` load checkpoints · `(`/`)` select · `e` resume · `K` delete with
//! exact-ID confirmation · `[`/`]` select service · `u` start · `d` stop · `R`
//! restart
//! with exact-name confirmation · `L` reload · `,`/`.` select tunable · `v`
//! set · `a` audit · `B` rollback with exact target confirmation · `A` load
//! bounded system audit · `q` quit.
//! `{`/`}` select installed package · `i` install/upgrade · `P` run · `b`
//! rollback · `D` remove, with exact artifact confirmation for destructive
//! mutations.

use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use agent_sdk::{ClusterCertificateRolloutPhase, ConnectionProfile};
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEventKind};
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap};
use ratatui::Frame;

use agent_tui::{
    app::{App, Key, MessageStreamUpdate, Mode, UiAction},
    TuiClient, TuiMessageClient,
};
use tokio::sync::mpsc;

const MAX_PENDING_MESSAGE_EVENTS: usize = 256;
const SYSTEM_AUDIT_LIMIT: usize = 50;

fn main() -> io::Result<()> {
    let argv: Vec<String> = std::env::args().collect();
    if argv.len() == 2 && matches!(argv[1].as_str(), "--version" | "-V") {
        println!("agent-tui {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }

    let (profile, token) = connection_options();
    let addr = profile.address.clone();

    let rt = tokio::runtime::Runtime::new()?;
    let mut client = match rt.block_on(TuiClient::connect_profile(&profile, token.as_deref())) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("agent-tui: could not connect to {addr}: {e}");
            eprintln!("hint: start a kernel first with `agent-server [ADDR]`.");
            std::process::exit(1);
        }
    };

    let mut app = App::new(addr);
    if let Err(e) = rt.block_on(app.refresh(&mut client)) {
        app.status = format!("initial refresh failed: {e}");
    }
    let message_client = client.message_client();

    let mut terminal = ratatui::init();
    let result = run(&mut terminal, &mut app, &mut client, &message_client, &rt);
    ratatui::restore();
    result
}

fn connection_options() -> (ConnectionProfile, Option<String>) {
    let mut profile = ConnectionProfile::from_env().unwrap_or_else(|error| {
        eprintln!("agent-tui: {error}");
        std::process::exit(2);
    });
    let mut token = std::env::var("AGENT_SERVER_TOKEN").ok();
    let mut positional_addr = false;
    let mut args = std::env::args().skip(1);
    while let Some(argument) = args.next() {
        match argument.as_str() {
            "--addr" => profile.address = args.next().unwrap_or_else(|| usage()),
            "--token" => token = Some(args.next().unwrap_or_else(|| usage())),
            value if !value.starts_with('-') && !positional_addr => {
                profile.address = value.to_string();
                positional_addr = true;
            }
            _ => usage(),
        }
    }
    (profile, token)
}

fn usage() -> ! {
    eprintln!("usage: agent-tui [--addr HOST:PORT] [--token TOKEN] [HOST:PORT]");
    std::process::exit(2);
}

fn run(
    terminal: &mut ratatui::DefaultTerminal,
    app: &mut App,
    client: &mut TuiClient,
    message_client: &TuiMessageClient,
    rt: &tokio::runtime::Runtime,
) -> io::Result<()> {
    let (stream_updates_tx, mut stream_updates_rx) = mpsc::channel(MAX_PENDING_MESSAGE_EVENTS);
    loop {
        drain_stream_updates(app, client, message_client, rt, &mut stream_updates_rx);
        terminal.draw(|f| ui(f, app))?;

        let poll_interval = if app.has_active_message_stream() {
            Duration::from_millis(50)
        } else {
            Duration::from_millis(500)
        };
        if event::poll(poll_interval)? {
            if let Event::Key(key) = event::read()? {
                if key.kind != KeyEventKind::Press {
                    continue;
                }
                if let Some(k) = map_key(key.code) {
                    if let Some(action) = app.on_key(k) {
                        if action != UiAction::Quit {
                            app.begin_operation(action.operation_label());
                            terminal.draw(|f| ui(f, app))?;
                        }
                        perform(action, app, client, message_client, &stream_updates_tx, rt);
                        app.finish_operation();
                    }
                }
            }
        }
        if app.should_quit {
            return Ok(());
        }
    }
}

/// Run an action's async I/O against the kernel, folding results into status.
fn perform(
    action: UiAction,
    app: &mut App,
    client: &mut TuiClient,
    message_client: &TuiMessageClient,
    stream_updates: &mpsc::Sender<MessageStreamUpdate>,
    rt: &tokio::runtime::Runtime,
) {
    match action {
        UiAction::Quit => {
            if let Some(stream) = app.active_message_stream() {
                let _ = rt
                    .block_on(message_client.cancel_request(&stream.request_id, &stream.agent_id));
            }
            app.should_quit = true;
        }
        UiAction::Refresh => match rt.block_on(app.refresh(client)) {
            Ok(()) => app.status = "refreshed".into(),
            Err(e) => app.status = format!("refresh failed: {e}"),
        },
        UiAction::CreateAgent { name, task } => {
            match rt.block_on(client.create_agent(name.clone(), task, None, None, None)) {
                Ok(id) => app.status = format!("created {name} ({id})"),
                Err(e) => app.status = format!("create failed: {e}"),
            }
            refresh_after_action(app, client, rt);
        }
        UiAction::SendMessage { agent_id, message } => {
            let request_id = format!("tui-{}", uuid::Uuid::new_v4());
            if app
                .start_message_stream(request_id.clone(), agent_id.clone())
                .is_err()
            {
                return;
            }
            let messages = message_client.clone();
            let updates = stream_updates.clone();
            let event_updates = updates.clone();
            let event_request_id = request_id.clone();
            let event_agent_id = agent_id.clone();
            let omitted = Arc::new(AtomicU64::new(0));
            let omitted_events = Arc::clone(&omitted);
            rt.spawn(async move {
                let outcome = messages
                    .send_message_stream(
                        request_id.clone(),
                        agent_id.clone(),
                        message,
                        move |event| {
                            let update = MessageStreamUpdate::Event {
                                request_id: event_request_id.clone(),
                                agent_id: event_agent_id.clone(),
                                event: event.clone(),
                            };
                            match event_updates.try_send(update) {
                                Ok(()) => {}
                                Err(mpsc::error::TrySendError::Full(_)) => {
                                    omitted_events.fetch_add(1, Ordering::Relaxed);
                                }
                                Err(mpsc::error::TrySendError::Closed(_)) => {}
                            }
                        },
                    )
                    .await;
                let omitted_count = omitted.load(Ordering::Relaxed);
                if omitted_count > 0
                    && updates
                        .send(MessageStreamUpdate::EventsOmitted {
                            request_id: request_id.clone(),
                            agent_id: agent_id.clone(),
                            count: omitted_count,
                        })
                        .await
                        .is_err()
                {
                    return;
                }
                let terminal = match outcome {
                    Ok(result) => MessageStreamUpdate::Completed {
                        request_id,
                        agent_id,
                        content: result.content,
                        tool_calls: result.tool_calls,
                        tokens: result.tokens,
                    },
                    Err(error) => MessageStreamUpdate::Failed {
                        request_id,
                        agent_id,
                        error: error.to_string(),
                    },
                };
                let _ = updates.send(terminal).await;
            });
        }
        UiAction::CancelMessageStream {
            request_id,
            agent_id,
        } => {
            perform_message_stream_cancellation(app, message_client, rt, &request_id, &agent_id);
        }
        UiAction::PauseAgent { agent_id } => {
            app.status = match rt.block_on(client.pause_agent(agent_id)) {
                Ok(state) => format!("agent state: {state}"),
                Err(error) => format!("pause failed: {error}"),
            };
            refresh_after_action(app, client, rt);
        }
        UiAction::ResumeAgent { agent_id } => {
            app.status = match rt.block_on(client.resume_agent(agent_id)) {
                Ok(state) => format!("agent state: {state}"),
                Err(error) => format!("resume failed: {error}"),
            };
            refresh_after_action(app, client, rt);
        }
        UiAction::StopAgent { agent_id } => {
            app.status = match rt.block_on(client.stop_agent(agent_id)) {
                Ok(state) => format!("agent state: {state}"),
                Err(error) => format!("stop failed: {error}"),
            };
            refresh_after_action(app, client, rt);
        }
        UiAction::KillAgent { agent_id } => {
            app.status = match rt.block_on(client.kill_agent(agent_id)) {
                Ok(state) => format!("agent state: {state}"),
                Err(error) => format!("kill failed: {error}"),
            };
            refresh_after_action(app, client, rt);
        }
        UiAction::LoadGenerationCheckpoints { agent_id } => {
            match rt.block_on(client.list_generation_checkpoints(agent_id.clone())) {
                Ok(checkpoints) => app.set_generation_checkpoints(agent_id, checkpoints),
                Err(error) => {
                    app.status = format!("checkpoint list failed for {agent_id}: {error}");
                }
            }
        }
        UiAction::ResumeGenerationCheckpoint {
            agent_id,
            checkpoint_id,
        } => {
            match rt.block_on(
                client.resume_generation_checkpoint(agent_id.clone(), checkpoint_id.clone()),
            ) {
                Ok(result) => app.checkpoint_resumed(&agent_id, &checkpoint_id, result),
                Err(error) => {
                    app.status = format!(
                        "checkpoint resume failed for agent {agent_id}, checkpoint {checkpoint_id}: {error}"
                    );
                }
            }
            refresh_after_action(app, client, rt);
        }
        UiAction::DeleteGenerationCheckpoint {
            agent_id,
            checkpoint_id,
        } => {
            match rt.block_on(
                client.delete_generation_checkpoint(agent_id.clone(), checkpoint_id.clone()),
            ) {
                Ok(existed) => app.checkpoint_deleted(&agent_id, &checkpoint_id, existed),
                Err(error) => {
                    app.status = format!(
                        "checkpoint deletion failed for agent {agent_id}, checkpoint {checkpoint_id}: {error}"
                    );
                }
            }
            refresh_after_action(app, client, rt);
        }
        UiAction::StartService { name } => {
            app.status = match rt.block_on(client.start_service(name.clone())) {
                Ok(service) => format!("service {}: {:?}", service.name, service.status),
                Err(error) => format!("service start failed: {error}"),
            };
            refresh_after_action(app, client, rt);
        }
        UiAction::StopService { name } => {
            app.status = match rt.block_on(client.stop_service(name.clone())) {
                Ok(service) => format!("service {}: {:?}", service.name, service.status),
                Err(error) => format!("service stop failed: {error}"),
            };
            refresh_after_action(app, client, rt);
        }
        UiAction::RestartService { name } => {
            app.status = match rt.block_on(client.restart_service(name.clone())) {
                Ok(service) => format!("service {}: {:?}", service.name, service.status),
                Err(error) => format!("service restart failed: {error}"),
            };
            refresh_after_action(app, client, rt);
        }
        UiAction::ReloadServices => {
            app.status = match rt.block_on(client.reload_services()) {
                Ok(order) => format!("services reloaded: {}", order.join(" → ")),
                Err(error) => format!("service reload failed: {error}"),
            };
            refresh_after_action(app, client, rt);
        }
        UiAction::SetOperatorTunable {
            name,
            value,
            expected_revision,
        } => {
            app.status = match rt.block_on(client.set_operator_tunable(
                name.clone(),
                value,
                expected_revision,
            )) {
                Ok(tunable) => {
                    app.clear_tunable_audit();
                    format!(
                        "tunable {}={} applied at revision {}; reload audit with `a`",
                        tunable.name, tunable.value, tunable.revision
                    )
                }
                Err(error) => {
                    format!("tunable update failed for {name}@r{expected_revision}: {error}")
                }
            };
            refresh_after_action(app, client, rt);
        }
        UiAction::LoadOperatorTunableAudit { name } => {
            match rt.block_on(client.operator_tunable_audit(Some(name.clone()), 20)) {
                Ok(entries) => {
                    let count = entries.len();
                    app.set_tunable_audit(name.clone(), entries);
                    app.status = format!("loaded {count} audit entries for {name}");
                }
                Err(error) => {
                    app.status = format!("tunable audit failed for {name}: {error}");
                }
            }
        }
        UiAction::LoadSystemAudit => {
            let (node_control, cluster_membership, cluster_certificate_rollout) =
                rt.block_on(async {
                    let node_control = client
                        .node_control_audit(SYSTEM_AUDIT_LIMIT)
                        .await
                        .map_err(|error| error.to_string());
                    let cluster_membership = client
                        .cluster_membership_audit(SYSTEM_AUDIT_LIMIT)
                        .await
                        .map_err(|error| error.to_string());
                    let cluster_certificate_rollout = client
                        .cluster_certificate_rollout_audit(SYSTEM_AUDIT_LIMIT)
                        .await
                        .map_err(|error| error.to_string());
                    (
                        node_control,
                        cluster_membership,
                        cluster_certificate_rollout,
                    )
                });
            app.set_system_audits(
                node_control,
                cluster_membership,
                cluster_certificate_rollout,
            );
        }
        UiAction::RollbackOperatorTunable {
            name,
            target_revision,
            expected_revision,
        } => {
            app.status = match rt.block_on(client.rollback_operator_tunable(
                name.clone(),
                target_revision,
                expected_revision,
            )) {
                Ok(tunable) => {
                    app.clear_tunable_audit();
                    format!(
                        "tunable {} rolled back to value {} at revision {}; reload audit with `a`",
                        tunable.name, tunable.value, tunable.revision
                    )
                }
                Err(error) => format!(
                    "tunable rollback failed for {name} from r{expected_revision} to r{target_revision}: {error}"
                ),
            };
            refresh_after_action(app, client, rt);
        }
        UiAction::InstallPackage { name, requirement } => {
            app.status = match rt.block_on(client.install_package(&name, &requirement)) {
                Ok(package) => format!(
                    "installed {}@{} ({})",
                    package.name,
                    package.version,
                    short_digest(&package.digest)
                ),
                Err(error) => {
                    format!("package install failed for {name}|{requirement}: {error}")
                }
            };
            refresh_after_action(app, client, rt);
        }
        UiAction::RunInstalledPackage { name } => {
            app.status = match rt.block_on(client.run_installed_package(&name)) {
                Ok(agent_id) => format!("started package {name} as agent {agent_id}"),
                Err(error) => format!("package run failed for {name}: {error}"),
            };
            refresh_after_action(app, client, rt);
        }
        UiAction::RollbackInstalledPackage {
            name,
            expected_version,
            expected_digest,
        } => {
            app.status = match rt.block_on(client.rollback_package_exact(
                &name,
                &expected_version,
                &expected_digest,
            )) {
                Ok(package) => format!(
                    "rolled back {} from {} to {} ({})",
                    package.name,
                    expected_version,
                    package.version,
                    short_digest(&package.digest)
                ),
                Err(error) => {
                    format!("package rollback failed for {name}@{expected_version}: {error}")
                }
            };
            refresh_after_action(app, client, rt);
        }
        UiAction::RemoveInstalledPackage {
            name,
            expected_version,
            expected_digest,
        } => {
            app.status = match rt.block_on(client.remove_package_exact(
                &name,
                &expected_version,
                &expected_digest,
            )) {
                Ok(()) => format!("removed {name}@{expected_version}"),
                Err(error) => {
                    format!("package removal failed for {name}@{expected_version}: {error}")
                }
            };
            refresh_after_action(app, client, rt);
        }
    }
}

fn drain_stream_updates(
    app: &mut App,
    client: &mut TuiClient,
    message_client: &TuiMessageClient,
    rt: &tokio::runtime::Runtime,
    updates: &mut mpsc::Receiver<MessageStreamUpdate>,
) {
    while let Ok(update) = updates.try_recv() {
        let terminal = matches!(
            update,
            MessageStreamUpdate::Completed { .. } | MessageStreamUpdate::Failed { .. }
        );
        if let Some(UiAction::CancelMessageStream {
            request_id,
            agent_id,
        }) = app.apply_message_stream_update(update)
        {
            app.begin_operation("cancelling agent turn");
            perform_message_stream_cancellation(app, message_client, rt, &request_id, &agent_id);
            app.finish_operation();
        }
        if terminal {
            refresh_after_action(app, client, rt);
        }
    }
}

fn perform_message_stream_cancellation(
    app: &mut App,
    message_client: &TuiMessageClient,
    rt: &tokio::runtime::Runtime,
    request_id: &str,
    agent_id: &str,
) {
    match rt.block_on(message_client.cancel_request(request_id, agent_id)) {
        Ok(true) => app.message_stream_cancellation_accepted(request_id, agent_id),
        Ok(false) => app.message_stream_cancellation_not_active(request_id, agent_id),
        Err(error) => {
            app.message_stream_cancellation_failed(request_id, agent_id, &error.to_string())
        }
    }
}

fn refresh_after_action(app: &mut App, client: &mut TuiClient, rt: &tokio::runtime::Runtime) {
    let outcome = app.status.clone();
    app.status = match rt.block_on(app.refresh(client)) {
        Ok(()) => outcome,
        Err(error) => {
            format!("{outcome}; refresh failed, showing last known data: {error}")
        }
    };
}

fn map_key(code: KeyCode) -> Option<Key> {
    match code {
        KeyCode::Char(c) => Some(Key::Char(c)),
        KeyCode::Enter => Some(Key::Enter),
        KeyCode::Esc => Some(Key::Esc),
        KeyCode::Backspace => Some(Key::Backspace),
        KeyCode::Up => Some(Key::Up),
        KeyCode::Down => Some(Key::Down),
        _ => None,
    }
}

fn ui(f: &mut Frame, app: &App) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // header
            Constraint::Min(5),    // body
            Constraint::Length(3), // footer / input
        ])
        .split(f.area());

    render_header(f, rows[0], app);
    render_body(f, rows[1], app);
    render_footer(f, rows[2], app);
}

fn render_header(f: &mut Frame, area: Rect, app: &App) {
    let operator_style = if app.operator_state.operation.is_some() {
        Style::default().fg(Color::Cyan)
    } else {
        match app.operator_state.freshness {
            agent_tui::app::DataFreshness::Loading => Style::default().fg(Color::Yellow),
            agent_tui::app::DataFreshness::Fresh => Style::default().fg(Color::Green),
            agent_tui::app::DataFreshness::Partial => Style::default().fg(Color::Yellow),
            agent_tui::app::DataFreshness::Stale => Style::default().fg(Color::Red),
        }
    }
    .add_modifier(Modifier::BOLD);
    let line = Line::from(vec![
        Span::styled("AI Agent OS", Style::default().add_modifier(Modifier::BOLD)),
        Span::raw(format!("  @ {}   ", app.addr)),
        Span::styled(format!("{}   ", app.operator_state.label()), operator_style),
        Span::styled(
            format!(
                "agents:{} running:{}",
                app.node.agent_count, app.node.running_agents
            ),
            Style::default().fg(Color::Cyan),
        ),
        Span::raw("   "),
        Span::styled(
            format!(
                "services:{} ready:{} failed:{}",
                app.services.len(),
                app.services
                    .iter()
                    .filter(|service| service.ready && service.healthy)
                    .count(),
                app.services
                    .iter()
                    .filter(|service| service.state == "Failed")
                    .count()
            ),
            Style::default().fg(Color::Magenta),
        ),
        Span::raw("   "),
        Span::styled(
            format!(
                "providers:{} available:{} packages:{}/{}",
                app.providers.len(),
                app.providers
                    .iter()
                    .filter(|provider| provider.available && !provider.circuit_open)
                    .count(),
                app.installed_packages.len(),
                app.packages.len()
            ),
            Style::default().fg(Color::Blue),
        ),
        Span::raw("   "),
        Span::styled(
            format!(
                "gate allowed:{} denied:{}",
                app.gate.allowed,
                app.gate.denied_capability
                    + app.gate.denied_mac
                    + app.gate.denied_approval
                    + app.gate.denied_cgroup
                    + app.gate.denied_namespace
                    + app.gate.denied_unknown
            ),
            Style::default().fg(Color::Green),
        ),
    ]);
    f.render_widget(
        Paragraph::new(line).block(Block::default().borders(Borders::ALL)),
        area,
    );
}

fn render_body(f: &mut Frame, area: Rect, app: &App) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(45), Constraint::Percentage(55)])
        .split(area);

    let items: Vec<ListItem> = app
        .agents
        .iter()
        .map(|a| {
            ListItem::new(format!(
                "{:<16} {:<10} {}",
                trunc(&a.name, 16),
                a.state,
                short(&a.id)
            ))
        })
        .collect();
    let mut state = ListState::default();
    if !app.agents.is_empty() {
        state.select(Some(app.selected));
    }
    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(format!(" agents ({}) ", app.agents.len())),
        )
        .highlight_style(
            Style::default()
                .bg(Color::Blue)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("› ");
    f.render_stateful_widget(list, cols[0], &mut state);

    let mut detail = match app.selected_agent() {
        Some(a) => {
            let mut lines = vec![
                Line::from(vec![
                    Span::styled("name: ", Style::default().fg(Color::Yellow)),
                    Span::raw(a.name.clone()),
                ]),
                Line::from(vec![
                    Span::styled("state: ", Style::default().fg(Color::Yellow)),
                    Span::raw(a.state.clone()),
                ]),
                Line::from(vec![
                    Span::styled("id: ", Style::default().fg(Color::Yellow)),
                    Span::raw(a.id.clone()),
                ]),
                Line::from(""),
            ];
            if let Some(agent) = app.selected_agent_detail() {
                lines.push(Line::from(format!(
                    "scheduler={} sandbox={} priority={} checkpoints={}",
                    agent.scheduler_state,
                    agent.sandbox_active,
                    agent.priority,
                    agent.checkpoint_count
                )));
                lines.push(Line::from(format!(
                    "capabilities: {}",
                    if agent.capabilities.is_empty() {
                        "none".into()
                    } else {
                        agent.capabilities.join(", ")
                    }
                )));
                lines.push(Line::from(format!(
                    "namespaces={} context={}/{} tokens spills={} bytes",
                    agent.namespace_details.len().max(agent.namespaces.len()),
                    agent.context_pressure.active_tokens,
                    agent.context_pressure.budget_tokens,
                    agent.context_pressure.stored_spill_bytes
                )));
                lines.push(Line::from(format!(
                    "gate allowed={} denied={} audited={}",
                    agent.gate_decisions.allowed,
                    agent.gate_decisions.denied_capability
                        + agent.gate_decisions.denied_mac
                        + agent.gate_decisions.denied_approval
                        + agent.gate_decisions.denied_cgroup
                        + agent.gate_decisions.denied_namespace
                        + agent.gate_decisions.denied_unknown,
                    agent.gate_decisions.audited
                )));
                if let Some(cgroup) = &agent.cgroup {
                    lines.push(Line::from(format!(
                        "cgroup {} ({}) tpm={}/context={} tools={}/{} agents={}/{}",
                        cgroup.id,
                        cgroup.scope,
                        cgroup.tokens_per_minute_limit,
                        cgroup.context_token_limit,
                        cgroup.active_tool_calls,
                        cgroup.concurrent_tool_limit,
                        cgroup.agent_count,
                        cgroup.agent_limit
                    )));
                }
                if let Some(package) = app
                    .packages
                    .iter()
                    .find(|package| package.agent_id == agent.id)
                {
                    lines.push(Line::from(format!(
                        "package: {} · provider={} · profile={}",
                        package.name, package.provider, package.profile
                    )));
                }
                if app.checkpoint_agent_id.as_deref() == Some(agent.id.as_str()) {
                    if let Some(checkpoint) = app.selected_checkpoint() {
                        lines.push(Line::from(format!(
                            "checkpoint [{}/{}]: {} · schema={} · {}/{}",
                            app.selected_checkpoint + 1,
                            app.checkpoints.len(),
                            checkpoint.id,
                            checkpoint.version,
                            checkpoint.provider_id,
                            checkpoint.model_id
                        )));
                        lines.push(Line::from(format!(
                            "created={} · expires={} · e resume · K exact delete",
                            checkpoint.created_at, checkpoint.expires_at
                        )));
                    } else {
                        lines.push(Line::from(
                            "loaded checkpoints: none · g reload for this agent",
                        ));
                    }
                }
                lines.push(Line::from(""));
            }
            if let Some(stream) = app.active_message_stream() {
                lines.push(Line::from(Span::styled(
                    format!(
                        "active turn: request={} agent={} · events={} omitted={} · tools={}/{}{}",
                        short(&stream.request_id),
                        short(&stream.agent_id),
                        stream.events_seen,
                        stream.omitted_events,
                        stream.tool_calls_completed,
                        stream.tool_calls_started,
                        if stream.cancellation_requested {
                            " · cancellation requested"
                        } else {
                            " · C cancel"
                        }
                    ),
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                )));
                if let Some(pressure) = &stream.context_pressure {
                    lines.push(Line::from(format!(
                        "context pressure: {}/{} tokens · evicted={} · spill={}",
                        pressure.active_tokens,
                        pressure.budget_tokens,
                        pressure.evicted_messages,
                        pressure.has_spill
                    )));
                }
            }
            if let Some(out) = &app.last_output {
                lines.push(Line::from(Span::styled(
                    format!(
                        "{}turn output{}:",
                        if app.has_active_message_stream() {
                            "active "
                        } else {
                            "last "
                        },
                        match &app.last_output_agent_id {
                            Some(agent_id) => format!(" for {}", short(agent_id)),
                            None => String::new(),
                        }
                    ),
                    Style::default().add_modifier(Modifier::BOLD),
                )));
                lines.push(Line::from(out.clone()));
                if app.last_output_truncated {
                    lines.push(Line::from(Span::styled(
                        "output truncated to the TUI retention limit",
                        Style::default().fg(Color::Yellow),
                    )));
                }
            }
            if let Some(service) = app.selected_service() {
                lines.push(Line::from(""));
                lines.push(Line::from(Span::styled(
                    format!(
                        "service [{}/{}]",
                        app.selected_service + 1,
                        app.services.len()
                    ),
                    Style::default().add_modifier(Modifier::BOLD),
                )));
                lines.push(Line::from(format!(
                    "{} · {} · ready={} · healthy={} · restarts={}",
                    service.name,
                    service.state,
                    service.ready,
                    service.healthy,
                    service.restart_count
                )));
                if let Some(failure) = &service.last_failure {
                    lines.push(Line::from(format!("last failure: {failure}")));
                }
            }
            lines
        }
        None => {
            let mut lines = vec![Line::from("no agents — press `c` to create one")];
            if let Some(service) = app.selected_service() {
                lines.push(Line::from(""));
                lines.push(Line::from(format!(
                    "service [{}/{}] {} · {} · ready={} · healthy={}",
                    app.selected_service + 1,
                    app.services.len(),
                    service.name,
                    service.state,
                    service.ready,
                    service.healthy
                )));
            }
            lines
        }
    };
    append_operator_summary(&mut detail, app);
    f.render_widget(
        Paragraph::new(detail)
            .block(Block::default().borders(Borders::ALL).title(" detail "))
            .wrap(Wrap { trim: true }),
        cols[1],
    );
}

fn append_operator_summary(lines: &mut Vec<Line<'static>>, app: &App) {
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        format!(
            "operator · scope={} · kernel={} · protocol={} · agents={}/{}{}",
            app.snapshot_scope,
            app.kernel_version,
            app.protocol_version,
            app.agents.len(),
            app.total_visible_agents,
            if app.agents_truncated {
                " (truncated)"
            } else {
                ""
            }
        ),
        Style::default().add_modifier(Modifier::BOLD),
    )));
    let providers = app
        .providers
        .iter()
        .map(|provider| {
            let state = if provider.probe_timed_out {
                "timeout"
            } else if provider.circuit_open {
                "circuit-open"
            } else if provider.available {
                "available"
            } else {
                "unavailable"
            };
            format!("{}={state}", provider.id)
        })
        .collect::<Vec<_>>()
        .join(", ");
    lines.push(Line::from(format!(
        "providers: {}",
        if providers.is_empty() {
            "none registered"
        } else {
            providers.as_str()
        }
    )));
    let tunables = app
        .tunables
        .iter()
        .map(|tunable| format!("{}={}@r{}", tunable.name, tunable.value, tunable.revision))
        .collect::<Vec<_>>()
        .join(", ");
    lines.push(Line::from(format!(
        "tunables: {}",
        if tunables.is_empty() {
            "unavailable"
        } else {
            tunables.as_str()
        }
    )));
    if let Some(tunable) = app.selected_tunable() {
        lines.push(Line::from(format!(
            "selected tunable [{}/{}]: {}={}@r{} · allowed {}..={} · {}",
            app.selected_tunable + 1,
            app.tunables.len(),
            tunable.name,
            tunable.value,
            tunable.revision,
            tunable.minimum,
            tunable.maximum,
            if tunable.persisted {
                "persisted"
            } else {
                "runtime only"
            }
        )));
        lines.push(Line::from(format!(
            "updated by {} at {} · {}",
            tunable.updated_by, tunable.updated_at, tunable.description
        )));
    }
    if let Some(name) = &app.tunable_audit_name {
        lines.push(Line::from(format!(
            "audit for {name}: {} entr{}",
            app.tunable_audit.len(),
            if app.tunable_audit.len() == 1 {
                "y"
            } else {
                "ies"
            }
        )));
        for entry in app.tunable_audit.iter().take(3) {
            lines.push(Line::from(format!(
                "  #{} {} {} r{} value={} actor={}",
                entry.id,
                entry.action,
                entry.outcome,
                entry
                    .revision
                    .map(|revision| revision.to_string())
                    .unwrap_or_else(|| "-".into()),
                entry
                    .effective_value
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "-".into()),
                entry.actor
            )));
        }
    }
    if let Some(package) = app.selected_package() {
        lines.push(Line::from(format!(
            "installed package [{}/{}]: {}@{} · {}",
            app.selected_package + 1,
            app.installed_packages.len(),
            package.name,
            package.version,
            short_digest(&package.digest)
        )));
        lines.push(Line::from(format!(
            "publisher={} · lock entries={} · installed {}",
            package.manifest.publisher,
            package.lock.packages.len(),
            package.installed_at
        )));
    } else {
        lines.push(Line::from("installed packages: none"));
    }
    for error in &app.system_audit_errors {
        lines.push(Line::from(format!("system audit warning: {error}")));
    }
    if app.system_audit_loaded {
        let node_count = if app.node_control_audit_loaded {
            app.node_control_audit.len().to_string()
        } else {
            "unavailable".into()
        };
        let membership_count = if app.cluster_membership_audit_loaded {
            app.cluster_membership_audit.len().to_string()
        } else {
            "unavailable".into()
        };
        let certificate_count = if app.cluster_certificate_rollout_audit_loaded {
            app.cluster_certificate_rollout_audit.len().to_string()
        } else {
            "unavailable".into()
        };
        lines.push(Line::from(format!(
            "system audit (bounded sequential reads, not atomic): node={} · membership={} · certificate-rollout={}",
            node_count, membership_count, certificate_count
        )));
        for entry in app.node_control_audit.iter().take(2) {
            lines.push(Line::from(format!(
                "  node r{} {}→{} actor={} at {} · {}",
                entry.generation,
                entry.previous.as_str(),
                entry.current.as_str(),
                entry.actor,
                entry.changed_at,
                entry.reason
            )));
        }
        for entry in app.cluster_membership_audit.iter().take(2) {
            lines.push(Line::from(format!(
                "  member g{} {} r{} {}→{} actor={} at {} · {}",
                entry.membership_generation,
                entry.node_id,
                entry.member_generation,
                entry.previous.map_or("none", |state| state.as_str()),
                entry.current.as_str(),
                entry.actor,
                entry.changed_at,
                entry.reason
            )));
        }
        for entry in app.cluster_certificate_rollout_audit.iter().take(2) {
            lines.push(Line::from(format!(
                "  certificate g{} {} r{} {}→{} actor={} at {} · {}",
                entry.trust_generation,
                entry.node_id,
                entry.member_generation,
                certificate_phase_label(entry.previous_phase),
                certificate_phase_label(entry.current_phase),
                entry.actor,
                entry.changed_at,
                entry.reason
            )));
        }
    } else {
        lines.push(Line::from(
            "system audit: not loaded · press A for bounded public-API history",
        ));
    }
}

fn certificate_phase_label(phase: Option<ClusterCertificateRolloutPhase>) -> &'static str {
    match phase {
        Some(ClusterCertificateRolloutPhase::Prepared) => "prepared",
        Some(ClusterCertificateRolloutPhase::Activated) => "activated",
        None => "none",
    }
}

fn render_footer(f: &mut Frame, area: Rect, app: &App) {
    let content = match app.mode {
        Mode::Normal => Line::from(app.status.clone()),
        Mode::CreateAgent => Line::from(vec![
            Span::styled("create> ", Style::default().fg(Color::Magenta)),
            Span::raw(app.input.clone()),
            Span::styled("▏", Style::default().add_modifier(Modifier::SLOW_BLINK)),
        ]),
        Mode::SendMessage => Line::from(vec![
            Span::styled("message> ", Style::default().fg(Color::Magenta)),
            Span::raw(app.input.clone()),
            Span::styled("▏", Style::default().add_modifier(Modifier::SLOW_BLINK)),
        ]),
        Mode::ConfirmKill => {
            let (agent_id, name) = app.pending_kill().unwrap_or(("missing target", "unknown"));
            Line::from(vec![
                Span::styled(
                    "CONFIRM FORCE-STOP ",
                    Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                ),
                Span::raw(format!("{name} ({agent_id}) · X confirm · Esc cancel")),
            ])
        }
        Mode::ConfirmServiceControl => {
            let (action, name, agent_id) =
                app.pending_service_control()
                    .unwrap_or(("control", "missing target", None));
            Line::from(vec![
                Span::styled(
                    format!("CONFIRM SERVICE {} ", action.to_uppercase()),
                    Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                ),
                Span::raw(format!(
                    "{name} (owner {}) · exact name> {}▏ · Enter confirm · Esc cancel",
                    agent_id.unwrap_or("none"),
                    app.input
                )),
            ])
        }
        Mode::SetTunable => {
            let (name, value, revision, minimum, maximum) = app
                .pending_tunable_control()
                .unwrap_or(("missing target", 0, 0, 0, 0));
            Line::from(vec![
                Span::styled(
                    "SET TUNABLE ",
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw(format!(
                    "{name}={value}@r{revision} · range {minimum}..={maximum} · value> {}▏ · Enter submit · Esc cancel",
                    app.input
                )),
            ])
        }
        Mode::ConfirmTunableRollback => {
            let (name, value, revision, _, _) =
                app.pending_tunable_control()
                    .unwrap_or(("missing target", 0, 0, 0, 0));
            Line::from(vec![
                Span::styled(
                    "CONFIRM TUNABLE ROLLBACK ",
                    Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                ),
                Span::raw(format!(
                    "{name}={value}@r{revision} · target-revision|exact-name> {}▏ · Enter submit · Esc cancel",
                    app.input
                )),
            ])
        }
        Mode::InstallPackage => Line::from(vec![
            Span::styled("INSTALL PACKAGE ", Style::default().fg(Color::Magenta)),
            Span::raw(app.input.clone()),
            Span::styled("▏", Style::default().add_modifier(Modifier::SLOW_BLINK)),
            Span::raw(" · name|semver-requirement · Enter submit · Esc cancel"),
        ]),
        Mode::ConfirmPackageMutation => {
            let (action, name, version, digest) = app.pending_package_mutation().unwrap_or((
                "mutate",
                "missing target",
                "unknown",
                "unknown",
            ));
            Line::from(vec![
                Span::styled(
                    format!("CONFIRM PACKAGE {} ", action.to_uppercase()),
                    Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                ),
                Span::raw(format!(
                    "{name}@{version} ({}) · {version}|{name}> {}▏ · Enter confirm · Esc cancel",
                    short_digest(digest),
                    app.input
                )),
            ])
        }
        Mode::ConfirmCheckpointDelete => {
            let (agent_id, checkpoint_id) = app
                .pending_checkpoint_delete()
                .unwrap_or(("missing agent", "missing checkpoint"));
            Line::from(vec![
                Span::styled(
                    "CONFIRM CHECKPOINT DELETE ",
                    Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                ),
                Span::raw(format!(
                    "agent {agent_id} · checkpoint {checkpoint_id} · full checkpoint ID> {}▏ · Enter confirm · Esc cancel",
                    app.input
                )),
            ])
        }
    };
    f.render_widget(
        Paragraph::new(content).block(Block::default().borders(Borders::ALL)),
        area,
    );
}

fn trunc(s: &str, n: usize) -> String {
    if s.len() <= n {
        s.to_string()
    } else {
        format!("{}…", &s[..n.saturating_sub(1)])
    }
}

fn short(id: &str) -> &str {
    id.get(..8).unwrap_or(id)
}

fn short_digest(digest: &str) -> &str {
    digest.get(..19).unwrap_or(digest)
}
