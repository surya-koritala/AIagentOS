//! TUI application state and input logic, kept free of rendering and async I/O
//! so it can be unit-tested directly. `main.rs` owns the terminal, the event
//! loop, and the [`KernelClient`] calls; this module owns *what the UI shows and
//! how keys mutate it*.

use agent_sdk::{AgentSummary, GateStats, KernelClient, NodeLoad, SdkError};

/// Input modes — the UI is modal (vim-ish): Normal navigates, the others edit a
/// single-line buffer until Enter (submit) or Esc (cancel).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Normal,
    /// Typing `name|task` for a new agent.
    CreateAgent,
    /// Typing a message to send to the selected agent.
    SendMessage,
}

/// An action the event loop should perform asynchronously (the pure key handler
/// can't do I/O itself). `None` from [`App::on_key`] means "handled, no I/O".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UiAction {
    Quit,
    Refresh,
    CreateAgent { name: String, task: String },
    SendMessage { agent_id: String, message: String },
}

/// All UI state.
pub struct App {
    pub addr: String,
    pub agents: Vec<AgentSummary>,
    pub gate: GateStats,
    pub node: NodeLoad,
    pub selected: usize,
    pub mode: Mode,
    pub input: String,
    pub status: String,
    pub last_output: Option<String>,
    pub should_quit: bool,
}

impl App {
    pub fn new(addr: impl Into<String>) -> Self {
        Self {
            addr: addr.into(),
            agents: Vec::new(),
            gate: GateStats::default(),
            node: NodeLoad::default(),
            selected: 0,
            mode: Mode::Normal,
            input: String::new(),
            status: "r: refresh  c: create  m: message  j/k: move  q: quit".into(),
            last_output: None,
            should_quit: false,
        }
    }

    /// Pull fresh state from the kernel: agent list, gate counters, node load.
    pub async fn refresh(&mut self, client: &mut KernelClient) -> Result<(), SdkError> {
        self.agents = client.list_agents().await?;
        self.gate = client.gate_stats().await?;
        self.node = client.node_info().await?;
        if self.selected >= self.agents.len() {
            self.selected = self.agents.len().saturating_sub(1);
        }
        Ok(())
    }

    pub fn selected_agent(&self) -> Option<&AgentSummary> {
        self.agents.get(self.selected)
    }

    fn move_selection(&mut self, delta: isize) {
        if self.agents.is_empty() {
            return;
        }
        let len = self.agents.len() as isize;
        let next = (self.selected as isize + delta).clamp(0, len - 1);
        self.selected = next as usize;
    }

    /// Handle a key press. Returns an action for the event loop to run, or
    /// `None` when the key only mutated local state. `key` is the character/name
    /// of the key; `enter`/`esc`/`backspace` are signalled via [`Key`].
    pub fn on_key(&mut self, key: Key) -> Option<UiAction> {
        match self.mode {
            Mode::Normal => self.on_key_normal(key),
            Mode::CreateAgent | Mode::SendMessage => self.on_key_editing(key),
        }
    }

    fn on_key_normal(&mut self, key: Key) -> Option<UiAction> {
        match key {
            Key::Char('q') => {
                self.should_quit = true;
                Some(UiAction::Quit)
            }
            Key::Char('r') => Some(UiAction::Refresh),
            Key::Char('j') | Key::Down => {
                self.move_selection(1);
                None
            }
            Key::Char('k') | Key::Up => {
                self.move_selection(-1);
                None
            }
            Key::Char('c') => {
                self.mode = Mode::CreateAgent;
                self.input.clear();
                self.status = "create — type `name|task`, Enter to submit, Esc to cancel".into();
                None
            }
            Key::Char('m') => {
                if self.selected_agent().is_some() {
                    self.mode = Mode::SendMessage;
                    self.input.clear();
                    self.status = "message — type text, Enter to send, Esc to cancel".into();
                } else {
                    self.status = "no agent selected".into();
                }
                None
            }
            _ => None,
        }
    }

    fn on_key_editing(&mut self, key: Key) -> Option<UiAction> {
        match key {
            Key::Esc => {
                self.mode = Mode::Normal;
                self.input.clear();
                self.status = "cancelled".into();
                None
            }
            Key::Char(c) => {
                self.input.push(c);
                None
            }
            Key::Backspace => {
                self.input.pop();
                None
            }
            Key::Enter => self.submit(),
            _ => None,
        }
    }

    fn submit(&mut self) -> Option<UiAction> {
        let action = match self.mode {
            Mode::CreateAgent => {
                let (name, task) = match self.input.split_once('|') {
                    Some((n, t)) => (n.trim().to_string(), t.trim().to_string()),
                    None => (self.input.trim().to_string(), "interactive".to_string()),
                };
                if name.is_empty() {
                    self.status = "name required (`name|task`)".into();
                    return None;
                }
                UiAction::CreateAgent { name, task }
            }
            Mode::SendMessage => {
                let message = self.input.trim().to_string();
                let agent_id = match self.selected_agent() {
                    Some(a) => a.id.clone(),
                    None => {
                        self.status = "no agent selected".into();
                        self.mode = Mode::Normal;
                        return None;
                    }
                };
                if message.is_empty() {
                    self.status = "message empty".into();
                    return None;
                }
                UiAction::SendMessage { agent_id, message }
            }
            Mode::Normal => return None,
        };
        self.mode = Mode::Normal;
        self.input.clear();
        Some(action)
    }
}

/// A keypress abstracted away from any specific backend, so [`App::on_key`] is
/// testable without a terminal. `main.rs` maps crossterm events onto this.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Key {
    Char(char),
    Enter,
    Esc,
    Backspace,
    Up,
    Down,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn app() -> App {
        App::new("127.0.0.1:7777")
    }

    fn dummy_agent(id: &str, name: &str) -> AgentSummary {
        AgentSummary {
            id: id.into(),
            name: name.into(),
            state: "Queued".into(),
        }
    }

    #[test]
    fn quit_key_sets_flag_and_action() {
        let mut a = app();
        assert_eq!(a.on_key(Key::Char('q')), Some(UiAction::Quit));
        assert!(a.should_quit);
    }

    #[test]
    fn refresh_key_requests_refresh() {
        let mut a = app();
        assert_eq!(a.on_key(Key::Char('r')), Some(UiAction::Refresh));
    }

    #[test]
    fn navigation_is_clamped() {
        let mut a = app();
        a.agents = vec![dummy_agent("1", "a"), dummy_agent("2", "b")];
        assert_eq!(a.selected, 0);
        a.on_key(Key::Char('k')); // up at top — stays
        assert_eq!(a.selected, 0);
        a.on_key(Key::Char('j'));
        assert_eq!(a.selected, 1);
        a.on_key(Key::Down); // down at bottom — stays
        assert_eq!(a.selected, 1);
        a.on_key(Key::Up);
        assert_eq!(a.selected, 0);
    }

    #[test]
    fn create_agent_flow_parses_name_and_task() {
        let mut a = app();
        assert_eq!(a.on_key(Key::Char('c')), None);
        assert_eq!(a.mode, Mode::CreateAgent);
        for ch in "bot|do things".chars() {
            a.on_key(Key::Char(ch));
        }
        let action = a.on_key(Key::Enter);
        assert_eq!(
            action,
            Some(UiAction::CreateAgent {
                name: "bot".into(),
                task: "do things".into()
            })
        );
        assert_eq!(a.mode, Mode::Normal, "submit returns to normal mode");
        assert!(a.input.is_empty());
    }

    #[test]
    fn create_agent_without_pipe_defaults_task() {
        let mut a = app();
        a.on_key(Key::Char('c'));
        for ch in "solo".chars() {
            a.on_key(Key::Char(ch));
        }
        assert_eq!(
            a.on_key(Key::Enter),
            Some(UiAction::CreateAgent {
                name: "solo".into(),
                task: "interactive".into()
            })
        );
    }

    #[test]
    fn esc_cancels_edit_mode() {
        let mut a = app();
        a.on_key(Key::Char('c'));
        a.on_key(Key::Char('x'));
        assert_eq!(a.on_key(Key::Esc), None);
        assert_eq!(a.mode, Mode::Normal);
        assert!(a.input.is_empty());
    }

    #[test]
    fn backspace_edits_buffer() {
        let mut a = app();
        a.on_key(Key::Char('c'));
        for ch in "abc".chars() {
            a.on_key(Key::Char(ch));
        }
        a.on_key(Key::Backspace);
        assert_eq!(a.input, "ab");
    }

    #[test]
    fn message_requires_a_selected_agent() {
        let mut a = app();
        // No agents → 'm' does nothing.
        assert_eq!(a.on_key(Key::Char('m')), None);
        assert_eq!(a.mode, Mode::Normal);
        // With an agent selected, 'm' enters message mode and Enter submits.
        a.agents = vec![dummy_agent("agent-1", "a")];
        a.on_key(Key::Char('m'));
        assert_eq!(a.mode, Mode::SendMessage);
        for ch in "hello".chars() {
            a.on_key(Key::Char(ch));
        }
        assert_eq!(
            a.on_key(Key::Enter),
            Some(UiAction::SendMessage {
                agent_id: "agent-1".into(),
                message: "hello".into()
            })
        );
    }

    #[test]
    fn empty_message_does_not_submit() {
        let mut a = app();
        a.agents = vec![dummy_agent("agent-1", "a")];
        a.on_key(Key::Char('m'));
        assert_eq!(a.on_key(Key::Enter), None, "empty message is not sent");
        assert_eq!(a.mode, Mode::SendMessage, "stays in edit mode");
    }
}
