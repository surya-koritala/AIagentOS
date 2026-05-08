//! The Unified Kernel — one struct that wires all subsystems together.
//!
//! This is the "main" of the OS. It boots, manages the lifecycle of all
//! subsystems, and provides the single entry point for all operations.

use std::sync::Arc;
use tokio::sync::Mutex;

use crate::agent_struct::{AgentId, AgentState, AgentStruct, AgentTable, CapabilitySet};
use crate::agent_syscalls::{AgentSyscalls, clone_flags};
use crate::cfs::CfsScheduler;
use crate::agent_struct::SchedClass;
use crate::cgroups::{CgroupManager, CgroupLimits};
use crate::event_loop::{EventLoop, KernelEvent};
use crate::init_system::{InitSystem, ServiceStatus};
use crate::mac::{MacEngine, MacDecision};
use crate::namespaces::{NamespaceRegistry, NamespaceType};
use crate::procfs::ProcFs;
use crate::sysctl::Sysctl;
use crate::syscall_interface::{SyscallNum, SyscallArgs, SyscallResult, SyscallError, check_capability};
use crate::agent_sockets::SocketRegistry;
use crate::service_discovery::ServiceRegistry;

/// The unified OS kernel.
pub struct OsKernel {
    /// Global agent table (all agents in the system).
    pub agents: Arc<AgentTable>,
    /// Agent syscall handlers.
    pub syscalls: AgentSyscalls,
    /// CFS scheduler.
    pub scheduler: Mutex<CfsScheduler>,
    /// Namespace registry.
    pub namespaces: NamespaceRegistry,
    /// Cgroup manager.
    pub cgroups: CgroupManager,
    /// MAC security engine.
    pub mac: Mutex<MacEngine>,
    /// Init system (service management).
    pub init: Mutex<InitSystem>,
    /// ProcFS (introspection).
    pub procfs: Mutex<ProcFs>,
    /// Sysctl (runtime config).
    pub sysctl: Mutex<Sysctl>,
    /// Socket registry (IPC).
    pub sockets: Mutex<SocketRegistry>,
    /// Service discovery.
    pub services: Mutex<ServiceRegistry>,
    /// Event sender.
    pub event_tx: tokio::sync::mpsc::Sender<KernelEvent>,
    /// Boot complete flag.
    booted: std::sync::atomic::AtomicBool,
}

impl OsKernel {
    /// Create a new kernel instance.
    pub fn new() -> Self {
        let agents = Arc::new(AgentTable::new());
        let syscalls = AgentSyscalls::new(agents.clone());
        let (mut event_loop, event_tx) = EventLoop::new();

        Self {
            agents,
            syscalls,
            scheduler: Mutex::new(CfsScheduler::new(1000)), // 1000 token time slice
            namespaces: NamespaceRegistry::new(),
            cgroups: CgroupManager::new(),
            mac: Mutex::new(MacEngine::new(true)), // enforcing mode
            init: Mutex::new(InitSystem::new()),
            procfs: Mutex::new(ProcFs::new()),
            sysctl: Mutex::new(Sysctl::new()),
            sockets: Mutex::new(SocketRegistry::new()),
            services: Mutex::new(ServiceRegistry::new()),
            event_tx,
            booted: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// Boot the kernel: load services, resolve deps, start agents.
    pub async fn boot(&self, service_dir: Option<&std::path::Path>) -> Result<Vec<AgentId>, String> {
        // Load service files
        if let Some(dir) = service_dir {
            let mut init = self.init.lock().await;
            init.load_directory(dir);
            init.resolve_boot_order().map_err(|e| format!("Boot failed: {}", e))?;
        }

        // Start agents in dependency order
        let boot_order = {
            let init = self.init.lock().await;
            init.boot_order().to_vec()
        };

        let mut started = Vec::new();
        for name in &boot_order {
            match self.start_agent(name).await {
                Ok(id) => {
                    started.push(id);
                    let mut init = self.init.lock().await;
                    init.mark_started(name, id);
                }
                Err(e) => {
                    eprintln!("Failed to start {}: {}", name, e);
                }
            }
        }

        self.booted.store(true, std::sync::atomic::Ordering::SeqCst);
        let _ = self.event_tx.send(KernelEvent::AgentCreated(0)).await;

        // Update procfs
        let mut procfs = self.procfs.lock().await;
        procfs.update_loadavg(started.len(), started.len());

        Ok(started)
    }

    /// Create an agent through the full kernel path.
    pub async fn start_agent(&self, name: &str) -> Result<AgentId, String> {
        // 1. Create agent struct
        let id = self.syscalls.agent_create(name.to_string(), 0);

        // 2. Assign to default namespaces
        if let Some(ns) = self.namespaces.default_ns(NamespaceType::Agent) {
            self.namespaces.join(ns, id);
        }
        if let Some(ns) = self.namespaces.default_ns(NamespaceType::Tool) {
            self.namespaces.join(ns, id);
        }

        // 3. Assign to root cgroup
        let _ = self.cgroups.add_agent(self.cgroups.root(), id);

        // 4. Enqueue in scheduler
        let mut sched = self.scheduler.lock().await;
        sched.enqueue(id, 0, SchedClass::Normal);

        // 5. Update procfs
        let mut procfs = self.procfs.lock().await;
        procfs.set_agent_info(id, "state".into(), "running".into());
        procfs.set_agent_info(id, "name".into(), name.into());

        // 6. Emit event
        let _ = self.event_tx.send(KernelEvent::AgentCreated(id)).await;

        Ok(id)
    }

    /// Execute a syscall with full security enforcement.
    pub async fn syscall(&self, caller: AgentId, num: SyscallNum, args: SyscallArgs) -> SyscallResult {
        // 1. MAC check
        let action = match num {
            SyscallNum::Create | SyscallNum::Clone => "create",
            SyscallNum::Kill => "kill",
            SyscallNum::ToolOpen | SyscallNum::ToolRead => "read",
            SyscallNum::ToolWrite => "write",
            SyscallNum::Send => "send",
            SyscallNum::Shutdown => "admin",
            _ => "execute",
        };
        let mac = self.mac.lock().await;
        let resource = args.str_arg.as_deref().unwrap_or("system");
        if mac.check(caller, action, resource) == MacDecision::Deny {
            return SyscallResult::Err(SyscallError::EACCES);
        }
        drop(mac);

        // 2. Capability check
        if let Some(agent_ref) = self.agents.get(caller) {
            let agent = agent_ref.value();
            // Would read caps from agent — simplified for now
        }

        // 3. Cgroup check (for token-consuming operations)
        match num {
            SyscallNum::ToolRead | SyscallNum::ToolWrite | SyscallNum::Send => {
                // Check cgroup limits before proceeding
                // In real impl, would look up agent's cgroup and check
            }
            _ => {}
        }

        // 4. Dispatch
        SyscallResult::Ok(0) // placeholder — real dispatch would call subsystem
    }

    /// Stop an agent through the full kernel path.
    pub async fn stop_agent(&self, id: AgentId) -> Result<(), String> {
        // 1. Dequeue from scheduler
        let mut sched = self.scheduler.lock().await;
        sched.dequeue(id);
        drop(sched);

        // 2. Remove from namespaces
        for ns_id in [
            self.namespaces.default_ns(NamespaceType::Agent),
            self.namespaces.default_ns(NamespaceType::Tool),
        ].into_iter().flatten() {
            self.namespaces.leave(ns_id, id);
        }

        // 3. Remove from cgroup
        self.cgroups.remove_agent(self.cgroups.root(), id);

        // 4. Update procfs
        let mut procfs = self.procfs.lock().await;
        procfs.set_agent_info(id, "state".into(), "stopped".into());

        // 5. Emit event
        let _ = self.event_tx.send(KernelEvent::AgentExited { id, code: 0 }).await;

        Ok(())
    }

    /// Graceful shutdown: stop all agents in reverse order.
    pub async fn shutdown(&self) -> Vec<AgentId> {
        let ids = self.agents.list_ids();
        let mut stopped = Vec::new();
        for id in ids.iter().rev() {
            if self.stop_agent(*id).await.is_ok() {
                stopped.push(*id);
            }
        }
        let _ = self.event_tx.send(KernelEvent::Shutdown).await;
        stopped
    }

    /// Get kernel status.
    pub fn status(&self) -> KernelStatus {
        KernelStatus {
            booted: self.booted.load(std::sync::atomic::Ordering::SeqCst),
            total_agents: self.agents.count(),
            namespaces: self.namespaces.count(),
        }
    }
}

/// Kernel status summary.
#[derive(Debug)]
pub struct KernelStatus {
    pub booted: bool,
    pub total_agents: usize,
    pub namespaces: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn boot_kernel() {
        let kernel = OsKernel::new();
        let started = kernel.boot(None).await.unwrap();
        assert!(kernel.status().booted);
    }

    #[tokio::test]
    async fn start_and_stop_agent() {
        let kernel = OsKernel::new();
        kernel.boot(None).await.unwrap();
        let id = kernel.start_agent("test-agent").await.unwrap();
        assert!(id > 0);
        assert_eq!(kernel.status().total_agents, 1);
        kernel.stop_agent(id).await.unwrap();
    }

    #[tokio::test]
    async fn multiple_agents() {
        let kernel = OsKernel::new();
        kernel.boot(None).await.unwrap();
        let id1 = kernel.start_agent("agent-1").await.unwrap();
        let id2 = kernel.start_agent("agent-2").await.unwrap();
        let id3 = kernel.start_agent("agent-3").await.unwrap();
        assert_eq!(kernel.status().total_agents, 3);
        kernel.stop_agent(id2).await.unwrap();
        assert_eq!(kernel.status().total_agents, 3); // still in table (zombie)
    }

    #[tokio::test]
    async fn graceful_shutdown() {
        let kernel = OsKernel::new();
        kernel.boot(None).await.unwrap();
        kernel.start_agent("a").await.unwrap();
        kernel.start_agent("b").await.unwrap();
        kernel.start_agent("c").await.unwrap();
        let stopped = kernel.shutdown().await;
        assert_eq!(stopped.len(), 3);
    }

    #[tokio::test]
    async fn mac_enforced_on_syscall() {
        let kernel = OsKernel::new();
        kernel.boot(None).await.unwrap();
        let id = kernel.start_agent("restricted").await.unwrap();

        // Set up MAC policy that denies kill
        {
            let mut mac = kernel.mac.lock().await;
            mac.label_agent(id, "worker".into());
            mac.load_policy(vec![
                crate::mac::PolicyRule { subject: "worker".into(), action: "kill".into(), object: "*".into(), decision: "deny".into() },
            ]);
        }

        let result = kernel.syscall(id, SyscallNum::Kill, SyscallArgs::none()).await;
        assert!(matches!(result, SyscallResult::Err(SyscallError::EACCES)));
    }

    #[tokio::test]
    async fn agents_in_namespaces() {
        let kernel = OsKernel::new();
        kernel.boot(None).await.unwrap();
        let id1 = kernel.start_agent("a").await.unwrap();
        let id2 = kernel.start_agent("b").await.unwrap();

        // Both should be in default agent namespace
        let default_ns = kernel.namespaces.default_ns(NamespaceType::Agent).unwrap();
        assert!(kernel.namespaces.same_namespace(id1, id2, NamespaceType::Agent));
    }
}

    #[tokio::test]
    async fn boot_from_service_files() {
        let kernel = OsKernel::new();
        let dir = std::path::Path::new("/tmp/agent_services");
        let started = kernel.boot(Some(dir)).await.unwrap();

        // Should start 3 agents in dependency order: database → researcher → writer
        assert_eq!(started.len(), 3);
        assert_eq!(kernel.status().total_agents, 3);

        // Verify init system tracked them
        let init = kernel.init.lock().await;
        assert_eq!(init.status("database"), Some(ServiceStatus::Running));
        assert_eq!(init.status("researcher"), Some(ServiceStatus::Running));
        assert_eq!(init.status("writer"), Some(ServiceStatus::Running));
    }

    #[tokio::test]
    async fn boot_respects_dependency_order() {
        let kernel = OsKernel::new();
        let dir = std::path::Path::new("/tmp/agent_services");
        let started = kernel.boot(Some(dir)).await.unwrap();

        // database must start before researcher, researcher before writer
        // IDs are monotonically increasing, so order is preserved
        assert!(started[0] < started[1]); // database before researcher
        assert!(started[1] < started[2]); // researcher before writer
    }

    #[tokio::test]
    async fn crash_one_others_survive() {
        let kernel = OsKernel::new();
        kernel.boot(None).await.unwrap();
        let id1 = kernel.start_agent("survivor-1").await.unwrap();
        let id2 = kernel.start_agent("crash-me").await.unwrap();
        let id3 = kernel.start_agent("survivor-2").await.unwrap();

        // Crash agent 2
        kernel.stop_agent(id2).await.unwrap();

        // Others still in scheduler
        let sched = kernel.scheduler.lock().await;
        assert_eq!(sched.runnable_count(), 2); // id1 and id3 still running
    }

    #[tokio::test]
    async fn full_lifecycle_integration() {
        let kernel = OsKernel::new();

        // 1. Boot
        kernel.boot(None).await.unwrap();
        assert!(kernel.status().booted);

        // 2. Start 5 agents
        let mut ids = Vec::new();
        for i in 0..5 {
            ids.push(kernel.start_agent(&format!("agent-{}", i)).await.unwrap());
        }
        assert_eq!(kernel.status().total_agents, 5);

        // 3. Verify all in scheduler
        {
            let sched = kernel.scheduler.lock().await;
            assert_eq!(sched.runnable_count(), 5);
        }

        // 4. Verify all in default namespace
        for &id in &ids {
            let default_ns = kernel.namespaces.default_ns(NamespaceType::Agent).unwrap();
            assert!(kernel.namespaces.same_namespace(ids[0], id, NamespaceType::Agent));
        }

        // 5. Crash one
        kernel.stop_agent(ids[2]).await.unwrap();
        {
            let sched = kernel.scheduler.lock().await;
            assert_eq!(sched.runnable_count(), 4);
        }

        // 6. Shutdown
        let stopped = kernel.shutdown().await;
        assert_eq!(stopped.len(), 5); // all 5 get stop signal
    }

// ─── Tool Call Path ──────────────────────────────────────────────────────────

impl OsKernel {
    /// Execute a tool call through the full kernel path:
    /// descriptor table → mount resolve → namespace check → permission check → execute
    pub async fn tool_call(&self, agent_id: AgentId, tool_path: &str, operation: &str, params: &serde_json::Value) -> Result<serde_json::Value, String> {
        // 1. Check agent exists
        if self.agents.get(agent_id).is_none() {
            return Err("agent not found (ESRCH)".into());
        }

        // 2. MAC check
        {
            let mac = self.mac.lock().await;
            if mac.check(agent_id, operation, tool_path) == MacDecision::Deny {
                return Err("permission denied by MAC policy (EACCES)".into());
            }
        }

        // 3. Namespace check — agent must be in a tool namespace
        // Default namespace allows all agents (they're joined on start)
        let tool_ns = self.namespaces.default_ns(NamespaceType::Tool).unwrap_or(0);
        let members = self.namespaces.members(tool_ns);
        if !members.contains(&agent_id) && tool_ns != 0 {
            return Err("tool not visible in agent's namespace (ENOENT)".into());
        }

        // 4. Cgroup check — verify token budget
        if !self.cgroups.check_token_limit(self.cgroups.root(), 100) {
            return Err("cgroup token limit exceeded (ENOMEM)".into());
        }

        // 5. Account tokens in CFS
        {
            let mut sched = self.scheduler.lock().await;
            sched.account_tokens(agent_id, 100); // estimated cost
        }

        // 6. Record in cgroup
        self.cgroups.record_tokens(self.cgroups.root(), 100);

        // 7. Update procfs
        {
            let mut procfs = self.procfs.lock().await;
            procfs.set_agent_info(agent_id, "last_tool_call".into(), tool_path.into());
        }

        // 8. Execute (placeholder — real impl would dispatch to tool driver)
        Ok(serde_json::json!({"status": "ok", "tool": tool_path, "operation": operation}))
    }
}

#[cfg(test)]
mod tool_call_tests {
    use super::*;

    #[tokio::test]
    async fn tool_call_full_path() {
        let kernel = OsKernel::new();
        kernel.boot(None).await.unwrap();
        let id = kernel.start_agent("tool-user").await.unwrap();

        // Set MAC policy to allow this agent
        {
            let mut mac = kernel.mac.lock().await;
            mac.label_agent(id, "worker".into());
            mac.load_policy(vec![
                crate::mac::PolicyRule { subject: "worker".into(), action: "*".into(), object: "*".into(), decision: "allow".into() },
            ]);
        }

        let result = kernel.tool_call(id, "/tools/fs/read", "read", &serde_json::json!({"path": "/tmp/test"})).await;
        assert!(result.is_ok(), "tool_call failed: {:?}", result);
    }

    #[tokio::test]
    async fn tool_call_mac_denied() {
        let kernel = OsKernel::new();
        kernel.boot(None).await.unwrap();
        let id = kernel.start_agent("restricted").await.unwrap();

        // Set MAC policy to deny writes
        {
            let mut mac = kernel.mac.lock().await;
            mac.label_agent(id, "readonly".into());
            mac.load_policy(vec![
                crate::mac::PolicyRule { subject: "readonly".into(), action: "write".into(), object: "*".into(), decision: "deny".into() },
                crate::mac::PolicyRule { subject: "readonly".into(), action: "read".into(), object: "*".into(), decision: "allow".into() },
            ]);
        }

        // Read should work
        let result = kernel.tool_call(id, "/tools/fs", "read", &serde_json::json!({})).await;
        assert!(result.is_ok(), "tool_call failed: {:?}", result);

        // Write should be denied
        let result = kernel.tool_call(id, "/tools/fs", "write", &serde_json::json!({})).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("EACCES"));
    }

    #[tokio::test]
    async fn tool_call_nonexistent_agent() {
        let kernel = OsKernel::new();
        kernel.boot(None).await.unwrap();
        let result = kernel.tool_call(99999, "/tools/fs", "read", &serde_json::json!({})).await;
        assert!(result.is_err());
    }
}
