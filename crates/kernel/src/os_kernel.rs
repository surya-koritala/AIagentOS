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
