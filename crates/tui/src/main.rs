//! `agent-tui` — a Rust terminal UI for observing and driving AI Agent OS.
//!
//! Connects to a running kernel syscall server (the same boundary the SDK uses)
//! and shows live agents, gate-enforcement counters, and node load; you can
//! create agents and send turns without leaving the terminal. Rust-native
//! (ratatui + crossterm) — no web stack.
//!
//! Usage: `agent-tui [ADDR]` (default `127.0.0.1:7777`). Start a server first
//! with `agent-server`.
//!
//! Keys: `j`/`k` (or arrows) move · `r` refresh · `c` create (`name|task`) ·
//! `m` message the selected agent · `q` quit.

use std::io;
use std::time::Duration;

use agent_sdk::KernelClient;
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEventKind};
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap};
use ratatui::Frame;

use agent_tui::app::{App, Key, Mode, UiAction};

fn main() -> io::Result<()> {
    let addr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:7777".to_string());

    let rt = tokio::runtime::Runtime::new()?;
    let mut client = match rt.block_on(KernelClient::connect(addr.clone())) {
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

fn run(
    terminal: &mut ratatui::DefaultTerminal,
    app: &mut App,
    client: &mut KernelClient,
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
fn perform(
    action: UiAction,
    app: &mut App,
    client: &mut KernelClient,
    rt: &tokio::runtime::Runtime,
) {
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
                "gate allowed:{} denied:{}",
                app.gate.allowed,
                app.gate.denied_capability
                    + app.gate.denied_mac
                    + app.gate.denied_cgroup
                    + app.gate.denied_namespace
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
            lines
        }
        None => vec![Line::from("no agents — press `c` to create one")],
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
