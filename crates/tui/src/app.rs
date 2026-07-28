//! TUI application state and input logic, kept free of rendering and async I/O
//! so it can be unit-tested directly. `main.rs` owns the terminal, the event
//! loop, and the [`KernelClient`] calls; this module owns *what the UI shows and
//! how keys mutate it*.

use agent_sdk::{
    AgentSummary, GateStats, KernelClient, NodeLoad, OperatorAgentSnapshot,
    OperatorPackageSnapshot, OperatorServiceSnapshot, OperatorSnapshot, OperatorTunable,
    ProviderSummary, SdkError,
};

/// Input modes — the UI is modal (vim-ish): Normal navigates, the others edit a
/// single-line buffer until Enter (submit) or Esc (cancel).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Normal,
    /// Typing `name|task` for a new agent.
    CreateAgent,
    /// Typing a message to send to the selected agent.
    SendMessage,
    /// Waiting for a second uppercase `X` for one exact selected agent.
    ConfirmKill,
}

/// An action the event loop should perform asynchronously (the pure key handler
/// can't do I/O itself). `None` from [`App::on_key`] means "handled, no I/O".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UiAction {
    Quit,
    Refresh,
    CreateAgent { name: String, task: String },
    SendMessage { agent_id: String, message: String },
    PauseAgent { agent_id: String },
    ResumeAgent { agent_id: String },
    StopAgent { agent_id: String },
    KillAgent { agent_id: String },
    StartService { name: String },
    StopService { name: String },
    RestartService { name: String },
    ReloadServices,
}

impl UiAction {
    /// Stable, user-facing label rendered before the event loop begins an
    /// operation that may take long enough to be noticeable.
    pub fn operation_label(&self) -> &'static str {
        match self {
            Self::Quit => "quit",
            Self::Refresh => "refreshing operator data",
            Self::CreateAgent { .. } => "creating agent",
            Self::SendMessage { .. } => "waiting for agent turn",
            Self::PauseAgent { .. } => "pausing agent",
            Self::ResumeAgent { .. } => "resuming agent",
            Self::StopAgent { .. } => "stopping agent",
            Self::KillAgent { .. } => "force-stopping agent",
            Self::StartService { .. } => "starting service",
            Self::StopService { .. } => "stopping service",
            Self::RestartService { .. } => "restarting service",
            Self::ReloadServices => "reloading services",
        }
    }
}

/// Freshness of the last public operator snapshot retained by the TUI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataFreshness {
    Loading,
    Fresh,
    Partial,
    Stale,
}

/// Connection, freshness, and in-flight state rendered independently of the
/// current footer message. Last-known-good data remains in `App` when a refresh
/// fails; this metadata prevents cached values from looking current.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperatorUiState {
    pub freshness: DataFreshness,
    pub last_success_at: Option<String>,
    pub missing_sections: Vec<String>,
    pub last_error: Option<String>,
    pub reconnect_generation: u64,
    pub reconnected: bool,
    pub operation: Option<String>,
}

impl Default for OperatorUiState {
    fn default() -> Self {
        Self {
            freshness: DataFreshness::Loading,
            last_success_at: None,
            missing_sections: Vec::new(),
            last_error: None,
            reconnect_generation: 0,
            reconnected: false,
            operation: None,
        }
    }
}

impl OperatorUiState {
    pub fn label(&self) -> String {
        if let Some(operation) = &self.operation {
            return format!("WORKING: {operation}");
        }
        match self.freshness {
            DataFreshness::Loading => "LOADING".into(),
            DataFreshness::Fresh if self.reconnected => {
                format!("RECONNECTED #{}", self.reconnect_generation)
            }
            DataFreshness::Fresh => "FRESH".into(),
            DataFreshness::Partial if self.reconnected => format!(
                "RECONNECTED #{} · PARTIAL: {}",
                self.reconnect_generation,
                self.missing_sections.join(", ")
            ),
            DataFreshness::Partial => format!("PARTIAL: {}", self.missing_sections.join(", ")),
            DataFreshness::Stale => "STALE — showing last known data".into(),
        }
    }
}

/// All UI state.
pub struct App {
    pub addr: String,
    pub agents: Vec<AgentSummary>,
    pub agent_details: Vec<OperatorAgentSnapshot>,
    pub gate: GateStats,
    pub node: NodeLoad,
    pub providers: Vec<ProviderSummary>,
    pub packages: Vec<OperatorPackageSnapshot>,
    pub tunables: Vec<OperatorTunable>,
    pub services: Vec<OperatorServiceSnapshot>,
    pub snapshot_scope: String,
    pub kernel_version: String,
    pub protocol_version: u32,
    pub total_visible_agents: usize,
    pub agents_truncated: bool,
    pub selected: usize,
    pub selected_service: usize,
    pub mode: Mode,
    pub input: String,
    pub status: String,
    pending_kill: Option<(String, String)>,
    pub last_output: Option<String>,
    pub operator_state: OperatorUiState,
    pub should_quit: bool,
}

impl App {
    pub fn new(addr: impl Into<String>) -> Self {
        Self {
            addr: addr.into(),
            agents: Vec::new(),
            agent_details: Vec::new(),
            gate: GateStats::default(),
            node: NodeLoad::default(),
            providers: Vec::new(),
            packages: Vec::new(),
            tunables: Vec::new(),
            services: Vec::new(),
            snapshot_scope: "unknown".into(),
            kernel_version: "unknown".into(),
            protocol_version: 0,
            total_visible_agents: 0,
            agents_truncated: false,
            selected: 0,
            selected_service: 0,
            mode: Mode::Normal,
            input: String::new(),
            status: "r refresh · c/m/p/s/X agents · [/ ] service · u start · d stop · R restart · L reload · q quit".into(),
            pending_kill: None,
            last_output: None,
            operator_state: OperatorUiState::default(),
            should_quit: false,
        }
    }

    /// Pull fresh state from the kernel: agent list, gate counters, node load.
    pub async fn refresh(&mut self, client: &mut KernelClient) -> Result<(), SdkError> {
        let generation_before = client.reconnect_generation();
        match client.operator_snapshot().await {
            Ok(snapshot) => {
                let captured_at = snapshot.captured_at.clone();
                let mut missing_sections = Vec::new();
                if snapshot.system_metrics.is_none() {
                    missing_sections.push("global metrics".to_string());
                }
                if snapshot.services.is_none() {
                    missing_sections.push("services".to_string());
                }
                if snapshot.tunables.is_none() {
                    missing_sections.push("operator tunables".to_string());
                }
                if snapshot.agents_truncated {
                    missing_sections.push(format!(
                        "agent list truncated ({}/{})",
                        snapshot.agents.len(),
                        snapshot.total_visible_agents
                    ));
                }
                self.apply_operator_snapshot(snapshot);
                let reconnect_generation = client.reconnect_generation();
                self.operator_state = OperatorUiState {
                    freshness: if missing_sections.is_empty() {
                        DataFreshness::Fresh
                    } else {
                        DataFreshness::Partial
                    },
                    last_success_at: Some(captured_at),
                    missing_sections,
                    last_error: None,
                    reconnect_generation,
                    reconnected: reconnect_generation > generation_before,
                    operation: self.operator_state.operation.take(),
                };
                Ok(())
            }
            Err(error) => {
                self.operator_state.freshness = DataFreshness::Stale;
                self.operator_state.missing_sections.clear();
                self.operator_state.last_error = Some(error.to_string());
                self.operator_state.reconnected = false;
                Err(error)
            }
        }
    }

    pub fn begin_operation(&mut self, label: impl Into<String>) {
        self.operator_state.operation = Some(label.into());
    }

    pub fn finish_operation(&mut self) {
        self.operator_state.operation = None;
    }

    /// Apply one raw public operator snapshot to the render-free TUI model.
    ///
    /// Keeping this projection separate from transport lets conformance tests
    /// prove the displayed counters against the exact same wire fixture used
    /// by other clients.
    pub fn apply_operator_snapshot(&mut self, snapshot: OperatorSnapshot) {
        self.snapshot_scope = snapshot.scope.clone();
        self.kernel_version = snapshot.kernel_version.clone();
        self.protocol_version = snapshot.protocol_version;
        self.total_visible_agents = snapshot.total_visible_agents;
        self.agents_truncated = snapshot.agents_truncated;
        self.providers = snapshot.providers.clone();
        self.packages = snapshot.packages.clone();
        self.tunables = snapshot.tunables.clone().unwrap_or_default();
        self.services = snapshot.services.clone().unwrap_or_default();
        self.agent_details = snapshot.agents.clone();
        self.agents = snapshot
            .agents
            .into_iter()
            .map(|agent| AgentSummary {
                id: agent.id,
                name: agent.name,
                state: agent.state,
            })
            .collect();
        if let Some(metrics) = snapshot.system_metrics {
            self.gate = GateStats {
                allowed: metrics.gate.allowed,
                denied_capability: metrics.gate.denied_capability,
                denied_mac: metrics.gate.denied_mac,
                denied_approval: metrics.gate.denied_approval,
                denied_cgroup: metrics.gate.denied_cgroup,
                denied_namespace: metrics.gate.denied_namespace,
                denied_unknown: metrics.gate.denied_unknown,
                audited: metrics.gate.audited,
            };
            self.node = NodeLoad {
                control: None,
                agent_count: metrics.agent_count as usize,
                running_agents: metrics.running_agents as usize,
                live_agents: metrics.live_agents as usize,
                queued_agents: metrics.queued_agents as usize,
                paused_agents: metrics.paused_agents as usize,
                stopped_agents: metrics.stopped_agents as usize,
                active_turns: metrics.active_turns as usize,
                waiting_turns: metrics.waiting_turns as usize,
                turn_capacity: metrics.turn_capacity as usize,
                llm_requests_in_flight: metrics.llm_requests_in_flight as usize,
                llm_requests_waiting: metrics.llm_requests_waiting as usize,
                llm_core_capacity: metrics.llm_core_capacity as usize,
            };
        } else {
            // A tenant-scoped snapshot deliberately omits global counters.
            self.gate = GateStats::default();
            self.node = NodeLoad {
                agent_count: self.agents.len(),
                live_agents: self
                    .agents
                    .iter()
                    .filter(|agent| agent.state != "Stopped")
                    .count(),
                paused_agents: self
                    .agents
                    .iter()
                    .filter(|agent| agent.state == "Paused")
                    .count(),
                stopped_agents: self
                    .agents
                    .iter()
                    .filter(|agent| agent.state == "Stopped")
                    .count(),
                ..NodeLoad::default()
            };
        }
        if self.selected >= self.agents.len() {
            self.selected = self.agents.len().saturating_sub(1);
        }
        if self.selected_service >= self.services.len() {
            self.selected_service = self.services.len().saturating_sub(1);
        }
    }

    pub fn selected_agent(&self) -> Option<&AgentSummary> {
        self.agents.get(self.selected)
    }

    pub fn selected_agent_detail(&self) -> Option<&OperatorAgentSnapshot> {
        let id = &self.selected_agent()?.id;
        self.agent_details.iter().find(|agent| &agent.id == id)
    }

    pub fn selected_service(&self) -> Option<&OperatorServiceSnapshot> {
        self.services.get(self.selected_service)
    }

    fn move_selection(&mut self, delta: isize) {
        if self.agents.is_empty() {
            return;
        }
        let len = self.agents.len() as isize;
        let next = (self.selected as isize + delta).clamp(0, len - 1);
        self.selected = next as usize;
    }

    fn move_service_selection(&mut self, delta: isize) {
        if self.services.is_empty() {
            return;
        }
        let len = self.services.len() as isize;
        let next = (self.selected_service as isize + delta).clamp(0, len - 1);
        self.selected_service = next as usize;
    }

    /// Handle a key press. Returns an action for the event loop to run, or
    /// `None` when the key only mutated local state. `key` is the character/name
    /// of the key; `enter`/`esc`/`backspace` are signalled via [`Key`].
    pub fn on_key(&mut self, key: Key) -> Option<UiAction> {
        match self.mode {
            Mode::Normal => self.on_key_normal(key),
            Mode::CreateAgent | Mode::SendMessage => self.on_key_editing(key),
            Mode::ConfirmKill => self.on_key_confirm_kill(key),
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
            Key::Char('p') => self.selected_agent().map(|agent| {
                if agent.state == "Paused" {
                    UiAction::ResumeAgent {
                        agent_id: agent.id.clone(),
                    }
                } else {
                    UiAction::PauseAgent {
                        agent_id: agent.id.clone(),
                    }
                }
            }),
            Key::Char('s') => self.selected_agent().map(|agent| UiAction::StopAgent {
                agent_id: agent.id.clone(),
            }),
            Key::Char('X') => {
                if let Some(agent) = self.selected_agent().cloned() {
                    self.mode = Mode::ConfirmKill;
                    self.pending_kill = Some((agent.id.clone(), agent.name.clone()));
                    self.status = format!(
                        "confirm kill — {} ({}) will be force-stopped; press X again or Esc",
                        agent.name, agent.id
                    );
                } else {
                    self.status = "no agent selected".into();
                }
                None
            }
            Key::Char('[') => {
                self.move_service_selection(-1);
                None
            }
            Key::Char(']') => {
                self.move_service_selection(1);
                None
            }
            Key::Char('u') => self
                .selected_service()
                .map(|service| UiAction::StartService {
                    name: service.name.clone(),
                }),
            Key::Char('d') => self
                .selected_service()
                .map(|service| UiAction::StopService {
                    name: service.name.clone(),
                }),
            Key::Char('R') => self
                .selected_service()
                .map(|service| UiAction::RestartService {
                    name: service.name.clone(),
                }),
            Key::Char('L') => Some(UiAction::ReloadServices),
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

    fn on_key_confirm_kill(&mut self, key: Key) -> Option<UiAction> {
        match key {
            Key::Char('X') => {
                let target = self.pending_kill.take().map(|(agent_id, _)| agent_id);
                self.mode = Mode::Normal;
                self.status = "kill submitted".into();
                target.map(|agent_id| UiAction::KillAgent { agent_id })
            }
            Key::Esc => {
                self.pending_kill = None;
                self.mode = Mode::Normal;
                self.status = "kill cancelled".into();
                None
            }
            _ => {
                self.status = "kill not submitted — press X to confirm exact target or Esc".into();
                None
            }
        }
    }

    pub fn pending_kill(&self) -> Option<(&str, &str)> {
        self.pending_kill
            .as_ref()
            .map(|(agent_id, name)| (agent_id.as_str(), name.as_str()))
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
            Mode::Normal | Mode::ConfirmKill => return None,
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

    fn dummy_service(name: &str) -> OperatorServiceSnapshot {
        OperatorServiceSnapshot {
            name: name.into(),
            state: "Running".into(),
            agent_id: None,
            restart_count: 0,
            last_exit_code: None,
            desired_running: true,
            ready: true,
            healthy: true,
            restart_exhausted: false,
            last_failure: None,
            next_restart_at: None,
            last_transition_at: String::new(),
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
    fn long_running_operation_is_explicit_until_finished() {
        let mut a = app();
        assert_eq!(a.operator_state.freshness, DataFreshness::Loading);
        a.begin_operation(
            UiAction::SendMessage {
                agent_id: "agent-1".into(),
                message: "work".into(),
            }
            .operation_label(),
        );
        assert_eq!(a.operator_state.label(), "WORKING: waiting for agent turn");
        a.finish_operation();
        assert_eq!(a.operator_state.label(), "LOADING");
    }

    #[test]
    fn operator_snapshot_projection_keeps_public_scope_safe_sections() {
        let mut a = app();
        a.apply_operator_snapshot(OperatorSnapshot {
            captured_at: "2026-07-28T00:00:00Z".into(),
            consistency: "atomic".into(),
            scope: "global".into(),
            kernel_version: "0.3.0".into(),
            protocol_version: 2,
            agents: Vec::new(),
            total_visible_agents: 4,
            agents_truncated: true,
            providers: vec![ProviderSummary {
                id: "stub".into(),
                name: "Stub".into(),
                provider_type: "Local".into(),
                available: true,
                circuit_open: false,
                consecutive_failures: 0,
                capabilities: Default::default(),
                routing_policy: Default::default(),
                sampled_at: Some("2026-07-28T00:00:00Z".into()),
                probe_duration_ms: Some(2),
                probe_timed_out: false,
            }],
            packages: vec![OperatorPackageSnapshot {
                agent_id: "agent-1".into(),
                tenant_id: "tenant-1".into(),
                name: "reviewer".into(),
                provider: "stub".into(),
                profile: "safe".into(),
                loaded_at: "2026-07-28T00:00:00Z".into(),
                agent_state: "Running".into(),
            }],
            scoped_gate_decisions: Default::default(),
            tunables: Some(vec![OperatorTunable {
                name: "kernel.max_agents".into(),
                value: 10,
                revision: 2,
                minimum: 0,
                maximum: 100,
                persisted: true,
                updated_at: "2026-07-28T00:00:00Z".into(),
                updated_by: "operator".into(),
                description: "limit".into(),
            }]),
            services: Some(vec![dummy_service("worker")]),
            system_metrics: None,
            global_spend_usd: None,
        });

        assert_eq!(a.snapshot_scope, "global");
        assert_eq!(a.kernel_version, "0.3.0");
        assert_eq!(a.protocol_version, 2);
        assert_eq!(a.total_visible_agents, 4);
        assert!(a.agents_truncated);
        assert_eq!(a.providers[0].id, "stub");
        assert_eq!(a.packages[0].name, "reviewer");
        assert_eq!(a.tunables[0].name, "kernel.max_agents");
        assert_eq!(a.services[0].name, "worker");
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

    #[test]
    fn lifecycle_keys_target_the_selected_agent() {
        let mut a = app();
        a.agents = vec![dummy_agent("running", "a"), dummy_agent("paused", "b")];
        a.agents[1].state = "Paused".into();

        assert_eq!(
            a.on_key(Key::Char('p')),
            Some(UiAction::PauseAgent {
                agent_id: "running".into()
            })
        );
        assert_eq!(
            a.on_key(Key::Char('s')),
            Some(UiAction::StopAgent {
                agent_id: "running".into()
            })
        );
        a.selected = 1;
        assert_eq!(
            a.on_key(Key::Char('p')),
            Some(UiAction::ResumeAgent {
                agent_id: "paused".into()
            })
        );
        assert_eq!(a.on_key(Key::Char('X')), None);
        assert_eq!(a.mode, Mode::ConfirmKill);
        assert!(a.status.contains("paused"));
        assert_eq!(
            a.on_key(Key::Char('X')),
            Some(UiAction::KillAgent {
                agent_id: "paused".into()
            })
        );
        assert_eq!(a.mode, Mode::Normal);
    }

    #[test]
    fn kill_confirmation_is_target_bound_and_cancellable() {
        let mut a = app();
        a.agents = vec![
            dummy_agent("agent-exact", "critical-agent"),
            dummy_agent("agent-other", "other-agent"),
        ];

        assert_eq!(a.on_key(Key::Char('X')), None);
        assert_eq!(a.mode, Mode::ConfirmKill);
        assert!(a.status.contains("critical-agent"));
        assert!(a.status.contains("agent-exact"));
        a.selected = 1;
        assert_eq!(a.on_key(Key::Char('j')), None);
        assert_eq!(a.mode, Mode::ConfirmKill);
        assert_eq!(a.on_key(Key::Esc), None);
        assert_eq!(a.mode, Mode::Normal);
        a.selected = 0;
        assert_eq!(a.on_key(Key::Char('X')), None);
        a.selected = 1;
        assert_eq!(
            a.on_key(Key::Char('X')),
            Some(UiAction::KillAgent {
                agent_id: "agent-exact".into()
            })
        );
    }

    #[test]
    fn service_keys_target_the_selected_kernel_supervisor_service() {
        let mut a = app();
        a.services = vec![dummy_service("database"), dummy_service("worker")];
        a.on_key(Key::Char(']'));
        assert_eq!(a.selected_service, 1);
        assert_eq!(
            a.on_key(Key::Char('u')),
            Some(UiAction::StartService {
                name: "worker".into()
            })
        );
        assert_eq!(
            a.on_key(Key::Char('d')),
            Some(UiAction::StopService {
                name: "worker".into()
            })
        );
        assert_eq!(
            a.on_key(Key::Char('R')),
            Some(UiAction::RestartService {
                name: "worker".into()
            })
        );
        assert_eq!(a.on_key(Key::Char('L')), Some(UiAction::ReloadServices));
    }
}
