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
//! with `agent-server`.
//!
//! Keys: `j`/`k` (or arrows) move · `r` refresh · `c` create (`name|task`) ·
//! `m` message · `p` pause/resume · `s` stop · `X` kill · `[`/`]` select
//! service · `u` start · `d` stop · `R` restart · `L` reload · `q` quit.

use std::io;
use std::time::Duration;

use agent_sdk::ConnectionProfile;
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEventKind};
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap};
use ratatui::Frame;

use agent_tui::{
    app::{App, Key, Mode, UiAction},
    TuiClient,
};

fn main() -> io::Result<()> {
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

    let mut terminal = ratatui::init();
    let result = run(&mut terminal, &mut app, &mut client, &rt);
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
    rt: &tokio::runtime::Runtime,
) -> io::Result<()> {
    loop {
        terminal.draw(|f| ui(f, app))?;

        if event::poll(Duration::from_millis(500))? {
            if let Event::Key(key) = event::read()? {
                if key.kind != KeyEventKind::Press {
                    continue;
                }
                if let Some(k) = map_key(key.code) {
                    if let Some(action) = app.on_key(k) {
                        perform(action, app, client, rt);
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
fn perform(action: UiAction, app: &mut App, client: &mut TuiClient, rt: &tokio::runtime::Runtime) {
    match action {
        UiAction::Quit => app.should_quit = true,
        UiAction::Refresh => match rt.block_on(app.refresh(client)) {
            Ok(()) => app.status = "refreshed".into(),
            Err(e) => app.status = format!("refresh failed: {e}"),
        },
        UiAction::CreateAgent { name, task } => {
            match rt.block_on(client.create_agent(name.clone(), task, None, None, None)) {
                Ok(id) => app.status = format!("created {name} ({id})"),
                Err(e) => app.status = format!("create failed: {e}"),
            }
            let _ = rt.block_on(app.refresh(client));
        }
        UiAction::SendMessage { agent_id, message } => {
            match rt.block_on(client.send_message(agent_id, message)) {
                Ok(out) => {
                    app.status = format!("turn ok ({} tool calls)", out.tool_calls);
                    app.last_output = Some(out.content);
                }
                Err(e) => app.status = format!("send failed: {e}"),
            }
            let _ = rt.block_on(app.refresh(client));
        }
        UiAction::PauseAgent { agent_id } => {
            app.status = match rt.block_on(client.pause_agent(agent_id)) {
                Ok(state) => format!("agent state: {state}"),
                Err(error) => format!("pause failed: {error}"),
            };
            let _ = rt.block_on(app.refresh(client));
        }
        UiAction::ResumeAgent { agent_id } => {
            app.status = match rt.block_on(client.resume_agent(agent_id)) {
                Ok(state) => format!("agent state: {state}"),
                Err(error) => format!("resume failed: {error}"),
            };
            let _ = rt.block_on(app.refresh(client));
        }
        UiAction::StopAgent { agent_id } => {
            app.status = match rt.block_on(client.stop_agent(agent_id)) {
                Ok(state) => format!("agent state: {state}"),
                Err(error) => format!("stop failed: {error}"),
            };
            let _ = rt.block_on(app.refresh(client));
        }
        UiAction::KillAgent { agent_id } => {
            app.status = match rt.block_on(client.kill_agent(agent_id)) {
                Ok(state) => format!("agent state: {state}"),
                Err(error) => format!("kill failed: {error}"),
            };
            let _ = rt.block_on(app.refresh(client));
        }
        UiAction::StartService { name } => {
            app.status = match rt.block_on(client.start_service(name.clone())) {
                Ok(service) => format!("service {}: {:?}", service.name, service.status),
                Err(error) => format!("service start failed: {error}"),
            };
            let _ = rt.block_on(app.refresh(client));
        }
        UiAction::StopService { name } => {
            app.status = match rt.block_on(client.stop_service(name.clone())) {
                Ok(service) => format!("service {}: {:?}", service.name, service.status),
                Err(error) => format!("service stop failed: {error}"),
            };
            let _ = rt.block_on(app.refresh(client));
        }
        UiAction::RestartService { name } => {
            app.status = match rt.block_on(client.restart_service(name.clone())) {
                Ok(service) => format!("service {}: {:?}", service.name, service.status),
                Err(error) => format!("service restart failed: {error}"),
            };
            let _ = rt.block_on(app.refresh(client));
        }
        UiAction::ReloadServices => {
            app.status = match rt.block_on(client.reload_services()) {
                Ok(order) => format!("services reloaded: {}", order.join(" → ")),
                Err(error) => format!("service reload failed: {error}"),
            };
            let _ = rt.block_on(app.refresh(client));
        }
    }
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
    let line = Line::from(vec![
        Span::styled("AI Agent OS", Style::default().add_modifier(Modifier::BOLD)),
        Span::raw(format!("  @ {}   ", app.addr)),
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

    let detail = match app.selected_agent() {
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
            if let Some(out) = &app.last_output {
                lines.push(Line::from(Span::styled(
                    "last turn output:",
                    Style::default().add_modifier(Modifier::BOLD),
                )));
                lines.push(Line::from(out.clone()));
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
    f.render_widget(
        Paragraph::new(detail)
            .block(Block::default().borders(Borders::ALL).title(" detail "))
            .wrap(Wrap { trim: true }),
        cols[1],
    );
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
