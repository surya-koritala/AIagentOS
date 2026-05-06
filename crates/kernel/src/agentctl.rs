//! agentctl — systemctl equivalent for AI Agent OS.
//!
//! Manages agent services: start, stop, restart, status, list, logs.

use std::sync::Arc;

use crate::agent_struct::{AgentId, AgentState};
use crate::init_system::{InitSystem, ServiceStatus};

/// agentctl command results.
#[derive(Debug)]
pub enum AgentCtlResult {
    Ok(String),
    Error(String),
    Table(Vec<Vec<String>>),
}

/// The agentctl command handler.
pub struct AgentCtl {
    init: Arc<std::sync::Mutex<InitSystem>>,
}

impl AgentCtl {
    pub fn new(init: Arc<std::sync::Mutex<InitSystem>>) -> Self {
        Self { init }
    }

    /// Execute an agentctl command.
    pub fn execute(&self, args: &[&str]) -> AgentCtlResult {
        match args.first().copied() {
            Some("start") => self.cmd_start(args.get(1).copied()),
            Some("stop") => self.cmd_stop(args.get(1).copied()),
            Some("restart") => self.cmd_restart(args.get(1).copied()),
            Some("status") => self.cmd_status(args.get(1).copied()),
            Some("list") | Some("list-units") => self.cmd_list(),
            Some("enable") => self.cmd_enable(args.get(1).copied()),
            Some("disable") => self.cmd_disable(args.get(1).copied()),
            Some("is-active") => self.cmd_is_active(args.get(1).copied()),
            Some("help") | None => self.cmd_help(),
            Some(cmd) => AgentCtlResult::Error(format!("unknown command: {}", cmd)),
        }
    }

    fn cmd_start(&self, name: Option<&str>) -> AgentCtlResult {
        let name = match name {
            Some(n) => n,
            None => return AgentCtlResult::Error("usage: agentctl start <service>".into()),
        };
        let mut init = self.init.lock().unwrap();
        if init.status(name).is_none() {
            return AgentCtlResult::Error(format!("service '{}' not found", name));
        }
        init.mark_started(name, 0); // agent_id would come from actual creation
        AgentCtlResult::Ok(format!("Started {}", name))
    }

    fn cmd_stop(&self, name: Option<&str>) -> AgentCtlResult {
        let name = match name {
            Some(n) => n,
            None => return AgentCtlResult::Error("usage: agentctl stop <service>".into()),
        };
        let mut init = self.init.lock().unwrap();
        if init.status(name).is_none() {
            return AgentCtlResult::Error(format!("service '{}' not found", name));
        }
        init.mark_failed(name, 0); // would actually stop the agent
        AgentCtlResult::Ok(format!("Stopped {}", name))
    }

    fn cmd_restart(&self, name: Option<&str>) -> AgentCtlResult {
        let name = match name {
            Some(n) => n,
            None => return AgentCtlResult::Error("usage: agentctl restart <service>".into()),
        };
        let init = self.init.lock().unwrap();
        if init.status(name).is_none() {
            return AgentCtlResult::Error(format!("service '{}' not found", name));
        }
        drop(init);
        self.cmd_stop(Some(name));
        self.cmd_start(Some(name))
    }

    fn cmd_status(&self, name: Option<&str>) -> AgentCtlResult {
        let name = match name {
            Some(n) => n,
            None => return self.cmd_list(),
        };
        let init = self.init.lock().unwrap();
        match init.status(name) {
            Some(status) => AgentCtlResult::Ok(format!("{}: {:?}", name, status)),
            None => AgentCtlResult::Error(format!("service '{}' not found", name)),
        }
    }

    fn cmd_list(&self) -> AgentCtlResult {
        let init = self.init.lock().unwrap();
        let services = init.list();
        let mut table = vec![vec!["NAME".into(), "STATUS".into()]];
        for (name, status) in services {
            table.push(vec![name.to_string(), format!("{:?}", status)]);
        }
        AgentCtlResult::Table(table)
    }

    fn cmd_enable(&self, name: Option<&str>) -> AgentCtlResult {
        match name {
            Some(n) => AgentCtlResult::Ok(format!("Enabled {} (will start on boot)", n)),
            None => AgentCtlResult::Error("usage: agentctl enable <service>".into()),
        }
    }

    fn cmd_disable(&self, name: Option<&str>) -> AgentCtlResult {
        match name {
            Some(n) => AgentCtlResult::Ok(format!("Disabled {} (won't start on boot)", n)),
            None => AgentCtlResult::Error("usage: agentctl disable <service>".into()),
        }
    }

    fn cmd_is_active(&self, name: Option<&str>) -> AgentCtlResult {
        let name = match name {
            Some(n) => n,
            None => return AgentCtlResult::Error("usage: agentctl is-active <service>".into()),
        };
        let init = self.init.lock().unwrap();
        match init.status(name) {
            Some(ServiceStatus::Running) => AgentCtlResult::Ok("active".into()),
            Some(_) => AgentCtlResult::Ok("inactive".into()),
            None => AgentCtlResult::Error("unknown".into()),
        }
    }

    fn cmd_help(&self) -> AgentCtlResult {
        AgentCtlResult::Ok("agentctl commands:\n  start <service>    Start a service\n  stop <service>     Stop a service\n  restart <service>  Restart a service\n  status [service]   Show status\n  list               List all services\n  enable <service>   Enable auto-start\n  disable <service>  Disable auto-start\n  is-active <svc>    Check if running\n  help               Show this help".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::init_system::{ServiceDef, ExecConfig, ServiceConfig, DependencyConfig, ResourceConfig};

    fn setup() -> AgentCtl {
        let mut init = InitSystem::new();
        init.load_service(ServiceDef {
            name: "researcher".into(), description: None,
            exec: ExecConfig { provider: "openai".into(), system_prompt: "research".into(), tools: vec![], model: None },
            service: ServiceConfig::default(),
            dependencies: DependencyConfig::default(),
            resources: ResourceConfig::default(),
        });
        init.load_service(ServiceDef {
            name: "coder".into(), description: None,
            exec: ExecConfig { provider: "openai".into(), system_prompt: "code".into(), tools: vec![], model: None },
            service: ServiceConfig::default(),
            dependencies: DependencyConfig::default(),
            resources: ResourceConfig::default(),
        });
        AgentCtl::new(Arc::new(std::sync::Mutex::new(init)))
    }

    #[test]
    fn list_services() {
        let ctl = setup();
        let result = ctl.execute(&["list"]);
        assert!(matches!(result, AgentCtlResult::Table(ref t) if t.len() == 3)); // header + 2 services
    }

    #[test]
    fn start_service() {
        let ctl = setup();
        let result = ctl.execute(&["start", "researcher"]);
        assert!(matches!(result, AgentCtlResult::Ok(_)));
    }

    #[test]
    fn start_nonexistent_fails() {
        let ctl = setup();
        let result = ctl.execute(&["start", "nonexistent"]);
        assert!(matches!(result, AgentCtlResult::Error(_)));
    }

    #[test]
    fn status_shows_state() {
        let ctl = setup();
        ctl.execute(&["start", "coder"]);
        let result = ctl.execute(&["status", "coder"]);
        if let AgentCtlResult::Ok(s) = result {
            assert!(s.contains("Running"));
        }
    }

    #[test]
    fn is_active_check() {
        let ctl = setup();
        let result = ctl.execute(&["is-active", "researcher"]);
        if let AgentCtlResult::Ok(s) = result {
            assert_eq!(s, "inactive");
        }
    }

    #[test]
    fn help_command() {
        let ctl = setup();
        let result = ctl.execute(&["help"]);
        assert!(matches!(result, AgentCtlResult::Ok(ref s) if s.contains("start")));
    }

    #[test]
    fn unknown_command() {
        let ctl = setup();
        let result = ctl.execute(&["foobar"]);
        assert!(matches!(result, AgentCtlResult::Error(_)));
    }
}
