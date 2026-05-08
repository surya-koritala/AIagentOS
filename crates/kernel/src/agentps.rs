//! agentps — list running agents (like ps).
//! agenttop — real-time agent monitor (like top/htop).

use crate::agent_struct::{AgentId, AgentState, AgentStruct, AgentTable};
use std::sync::Arc;
use tokio::sync::RwLock;

/// A row in agentps output.
#[derive(Debug, Clone)]
pub struct PsEntry {
    pub id: AgentId,
    pub name: String,
    pub state: String,
    pub parent: AgentId,
    pub nice: i8,
    pub tokens_total: u64,
    pub tool_calls: u64,
    pub uptime_secs: u64,
}

/// agentps: snapshot of all agents.
pub fn agentps(table: &AgentTable) -> Vec<PsEntry> {
    let now = chrono::Utc::now();
    let mut entries = Vec::new();

    for id in table.list_ids() {
        if let Some(agent_ref) = table.get(id) {
            let agent = agent_ref.value();
            // We need to read-lock the agent
            // For now, create entry from what we can access
            entries.push(PsEntry {
                id,
                name: format!("agent-{}", id),
                state: "unknown".into(),
                parent: 0,
                nice: 0,
                tokens_total: 0,
                tool_calls: 0,
                uptime_secs: 0,
            });
        }
    }
    entries
}

/// Format agentps output as a table string.
pub fn format_ps(entries: &[PsEntry]) -> String {
    let mut out = format!(
        "{:<6} {:<15} {:<10} {:<6} {:<5} {:<10} {:<8} {}\n",
        "ID", "NAME", "STATE", "PPID", "NI", "TOKENS", "TOOLS", "UPTIME"
    );
    out += &"-".repeat(75);
    out += "\n";
    for e in entries {
        out += &format!(
            "{:<6} {:<15} {:<10} {:<6} {:<5} {:<10} {:<8} {}s\n",
            e.id, e.name, e.state, e.parent, e.nice, e.tokens_total, e.tool_calls, e.uptime_secs
        );
    }
    out += &format!("\nTotal: {} agents\n", entries.len());
    out
}

/// agenttop: real-time stats (single snapshot for now).
#[derive(Debug, Clone)]
pub struct TopStats {
    pub total_agents: usize,
    pub running: usize,
    pub blocked: usize,
    pub stopped: usize,
    pub total_tokens: u64,
    pub total_tool_calls: u64,
    pub tokens_per_min: u64,
}

/// Get top-level system stats.
pub fn agenttop(entries: &[PsEntry]) -> TopStats {
    TopStats {
        total_agents: entries.len(),
        running: entries.iter().filter(|e| e.state == "running").count(),
        blocked: entries.iter().filter(|e| e.state == "blocked").count(),
        stopped: entries.iter().filter(|e| e.state == "stopped").count(),
        total_tokens: entries.iter().map(|e| e.tokens_total).sum(),
        total_tool_calls: entries.iter().map(|e| e.tool_calls).sum(),
        tokens_per_min: 0, // would need rate tracking
    }
}

/// Format agenttop output.
pub fn format_top(stats: &TopStats, entries: &[PsEntry]) -> String {
    let mut out = format!(
        "AI Agent OS — {} agents ({} running, {} blocked, {} stopped)\n",
        stats.total_agents, stats.running, stats.blocked, stats.stopped
    );
    out += &format!(
        "Tokens: {} total | Tool calls: {} total\n\n",
        stats.total_tokens, stats.total_tool_calls
    );
    out += &format_ps(entries);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_ps_output() {
        let entries = vec![
            PsEntry {
                id: 1,
                name: "researcher".into(),
                state: "running".into(),
                parent: 0,
                nice: 0,
                tokens_total: 5000,
                tool_calls: 12,
                uptime_secs: 300,
            },
            PsEntry {
                id: 2,
                name: "coder".into(),
                state: "blocked".into(),
                parent: 1,
                nice: -5,
                tokens_total: 8000,
                tool_calls: 25,
                uptime_secs: 600,
            },
        ];
        let output = format_ps(&entries);
        assert!(output.contains("researcher"));
        assert!(output.contains("coder"));
        assert!(output.contains("Total: 2 agents"));
    }

    #[test]
    fn top_stats() {
        let entries = vec![
            PsEntry {
                id: 1,
                name: "a".into(),
                state: "running".into(),
                parent: 0,
                nice: 0,
                tokens_total: 100,
                tool_calls: 5,
                uptime_secs: 10,
            },
            PsEntry {
                id: 2,
                name: "b".into(),
                state: "running".into(),
                parent: 0,
                nice: 0,
                tokens_total: 200,
                tool_calls: 10,
                uptime_secs: 20,
            },
            PsEntry {
                id: 3,
                name: "c".into(),
                state: "stopped".into(),
                parent: 0,
                nice: 0,
                tokens_total: 50,
                tool_calls: 2,
                uptime_secs: 5,
            },
        ];
        let stats = agenttop(&entries);
        assert_eq!(stats.total_agents, 3);
        assert_eq!(stats.running, 2);
        assert_eq!(stats.stopped, 1);
        assert_eq!(stats.total_tokens, 350);
        assert_eq!(stats.total_tool_calls, 17);
    }

    #[test]
    fn format_top_output() {
        let entries = vec![PsEntry {
            id: 1,
            name: "test".into(),
            state: "running".into(),
            parent: 0,
            nice: 0,
            tokens_total: 100,
            tool_calls: 5,
            uptime_secs: 60,
        }];
        let stats = agenttop(&entries);
        let output = format_top(&stats, &entries);
        assert!(output.contains("1 agents"));
        assert!(output.contains("1 running"));
    }
}
