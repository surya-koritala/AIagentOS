//! Durable, cancel-safe cloning of an idle agent's actual execution history.

use crate::agent::AgentKernel;
use crate::agent_struct::CapabilitySet;
use crate::context::{ExecutionSnapshotMetadata, PersistedAgent};
use crate::permissions::PermissionSystem;
use crate::sandbox::{SandboxManager, SandboxManagerImpl};
use crate::{AgentError, AgentId, AgentKernelImpl, AgentState, KernelError, KernelEvent};
use serde::{Deserialize, Serialize};

/// Permissions captured at clone creation and reapplied before restart admission.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct CloneSecurity {
    pub version: u32,
    pub profile: String,
    pub capabilities: CapabilitySet,
    pub mac_label: String,
    pub tokens_per_min: u64,
    pub max_concurrent_tool_calls: u32,
    pub max_context_tokens: u64,
    pub max_agents: u32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connector::StandardMessage;
    use crate::context::{ContextStorageLimits, DEFAULT_TENANT};
    use crate::Priority;
    use proptest::prelude::*;
    use std::sync::Arc;

    fn config() -> crate::AgentConfig {
        crate::AgentConfig {
            name: "clone parent".into(),
            task: "branch actual execution".into(),
            llm_provider: "stub".into(),
            permission_profile: "standard".into(),
            priority: Priority::default(),
            sandbox_config: None,
        }
    }

    fn absent(kernel: &AgentKernelImpl, child: AgentId) {
        assert!(kernel.agent_manager.get_agent_state(child).is_none());
        assert!(kernel
            .context_manager
            .agent_tenant(child)
            .unwrap()
            .is_none());
        assert!(kernel.syscall_gate.agent_info(child).is_none());
        assert!(kernel
            .sandbox_manager
            .get_sandbox_for_agent(child)
            .is_none());
        assert!(!kernel.agent_cgroups.contains_key(&child));
        assert!(kernel.permission_manager.profile_for_agent(child).is_none());
    }

    #[tokio::test]
    async fn clone_allocates_a_private_workspace_and_effective_security() {
        let kernel = AgentKernelImpl::new().unwrap();
        let parent = kernel
            .create_agent_in_namespace(config(), "private-team")
            .await
            .unwrap()
            .id;
        let sandbox = kernel
            .sandbox_manager
            .get_sandbox_for_agent(parent)
            .unwrap();
        let source = kernel.sandbox_manager.sandbox_config(sandbox).unwrap();
        std::fs::write(
            source.workspace_dir.join("parent-only.txt"),
            "private bytes",
        )
        .unwrap();
        let info = kernel.syscall_gate.agent_info(parent).unwrap();
        let caps = CapabilitySet::new(CapabilitySet::CAP_NET_ACCESS);
        kernel.syscall_gate.set_capabilities(parent, caps.clone());
        kernel
            .syscall_gate
            .label_mac_agent(info.pid, "restricted-label".into())
            .await;
        kernel
            .permission_manager
            .assign_profile(parent, &"read-only".into());
        let mut limits = kernel.cgroups.get(info.cgroup).unwrap().limits;
        limits.max_context_tokens = 1234;
        kernel
            .cgroups
            .update_limits(info.cgroup, limits.clone())
            .unwrap();
        let child = AgentId::new_v4();
        let result = kernel
            .clone_agent(parent, child, "private child".into(), vec![])
            .await
            .unwrap();
        assert!(result.snapshot.is_none());
        let child_sandbox = kernel.sandbox_manager.get_sandbox_for_agent(child).unwrap();
        let child_config = kernel
            .sandbox_manager
            .sandbox_config(child_sandbox)
            .unwrap();
        assert_ne!(source.workspace_dir, child_config.workspace_dir);
        assert!(!child_config.workspace_dir.join("parent-only.txt").exists());
        let child_info = kernel.syscall_gate.agent_info(child).unwrap();
        assert_eq!(child_info.namespaces, info.namespaces);
        assert_ne!(child_info.cgroup, info.cgroup);
        assert_eq!(
            kernel.cgroups.get(child_info.cgroup).unwrap().limits,
            limits
        );
        let inherited = kernel
            .syscall_gate
            .capture_clone_security(child)
            .await
            .unwrap();
        assert_eq!(inherited.capabilities, caps);
        assert_eq!(inherited.mac_label, "restricted-label");
        assert_eq!(
            kernel
                .permission_manager
                .profile_for_agent(child)
                .as_deref(),
            Some("read-only")
        );
        kernel.stop_agent(child).await.unwrap();
        assert!(
            source.workspace_dir.join("parent-only.txt").exists(),
            "stopping child must not erase parent workspace"
        );
        kernel.stop_agent(parent).await.unwrap();
    }

    #[tokio::test]
    async fn explicit_retry_reconciles_a_child_without_reanimating_it() {
        let kernel = AgentKernelImpl::new().unwrap();
        let parent = kernel.create_agent_full(config()).await.unwrap().id;
        let child = AgentId::new_v4();
        let first = kernel
            .clone_agent(parent, child, "child".into(), vec![])
            .await
            .unwrap();
        assert_eq!(
            first,
            kernel
                .clone_agent(parent, child, "child".into(), vec![])
                .await
                .unwrap()
        );
        assert!(kernel
            .clone_agent(parent, child, "different request".into(), vec![])
            .await
            .is_err());
        kernel.stop_agent(child).await.unwrap();
        kernel.stop_agent(parent).await.unwrap();
        assert_eq!(
            kernel
                .clone_agent(parent, child, "child".into(), vec![])
                .await
                .unwrap()
                .state,
            AgentState::Stopped
        );
        assert!(kernel.syscall_gate.agent_info(child).is_none());
    }

    #[tokio::test]
    async fn invalid_lifecycle_checkpoint_and_attenuation_leave_no_child() {
        let kernel = AgentKernelImpl::new().unwrap();
        let parent = kernel.create_agent_full(config()).await.unwrap().id;
        for drops in [
            vec!["CAP_UNKNOWN".into()],
            vec!["CAP_EXEC".into(), "CAP_EXEC".into()],
        ] {
            let child = AgentId::new_v4();
            assert!(kernel
                .clone_agent(parent, child, "child".into(), drops)
                .await
                .is_err());
            absent(&kernel, child);
        }
        let checkpoint = crate::execution::GenerationCheckpoint {
            agent_id: parent,
            conversation_id: "live-continuation".into(),
            user_message: "unfinished".into(),
            messages: vec![StandardMessage::user("unfinished")],
            partial_content: String::new(),
            tool_calls_made: 0,
            tokens_used: 0,
            usage: Default::default(),
        };
        kernel
            .context_manager
            .save_generation_checkpoint(
                DEFAULT_TENANT,
                "different-provider",
                "different-model",
                &checkpoint,
                std::time::Duration::from_secs(60),
            )
            .unwrap();
        let child = AgentId::new_v4();
        let error = kernel
            .clone_agent(parent, child, "child".into(), vec![])
            .await
            .unwrap_err();
        assert!(error.to_string().contains("checkpoint"));
        absent(&kernel, child);
        kernel.stop_agent(parent).await.unwrap();
        let child = AgentId::new_v4();
        assert!(kernel
            .clone_agent(parent, child, "child".into(), vec![])
            .await
            .is_err());
        absent(&kernel, child);
    }

    #[tokio::test]
    async fn live_tool_binding_denies_clone_and_idle_paused_parent_can_clone() {
        let kernel = AgentKernelImpl::new().unwrap();
        let parent = kernel.create_agent_full(config()).await.unwrap().id;
        let info = kernel.syscall_gate.agent_info(parent).unwrap();
        let binding = kernel
            .cgroups
            .acquire_tool_call_for_agent(info.cgroup, info.pid)
            .unwrap();
        let child = AgentId::new_v4();
        assert!(kernel
            .clone_agent(parent, child, "child".into(), vec![])
            .await
            .unwrap_err()
            .to_string()
            .contains("live tool execution"));
        absent(&kernel, child);
        drop(binding);
        kernel.pause_agent(parent).await.unwrap();
        kernel
            .clone_agent(parent, child, "child".into(), vec![])
            .await
            .unwrap();
        assert_eq!(kernel.get_agent_status(parent).unwrap(), AgentState::Paused);
        assert_eq!(kernel.get_agent_status(child).unwrap(), AgentState::Running);
        kernel.stop_agent(parent).await.unwrap();
        kernel.stop_agent(child).await.unwrap();
    }

    #[tokio::test]
    async fn logical_context_quota_rolls_back_runtime_and_snapshot_publication() {
        let kernel = AgentKernelImpl::new().unwrap();
        let parent = kernel.create_agent_full(config()).await.unwrap().id;
        let history = vec![StandardMessage::user("durable parent ".repeat(2048))];
        kernel
            .context_manager
            .save_conversation("source", parent, &history)
            .unwrap();
        kernel
            .context_manager
            .set_context_storage_limits(ContextStorageLimits {
                per_agent_bytes: 128,
                ..Default::default()
            })
            .unwrap();
        let child = AgentId::new_v4();
        assert!(kernel
            .clone_agent(parent, child, "child".into(), vec![])
            .await
            .is_err());
        absent(&kernel, child);
        assert_eq!(
            kernel.context_manager.load_conversation("source").unwrap(),
            history
        );
        kernel
            .context_manager
            .set_context_storage_limits(Default::default())
            .unwrap();
        kernel
            .clone_agent(parent, child, "child".into(), vec![])
            .await
            .unwrap();
        kernel.stop_agent(parent).await.unwrap();
        kernel.stop_agent(child).await.unwrap();
    }

    #[tokio::test]
    async fn canceled_staging_removes_identity_workspace_and_cgroup() {
        let kernel = Arc::new(AgentKernelImpl::new().unwrap());
        let parent = kernel.create_agent_full(config()).await.unwrap().id;
        let cfs = kernel.os.cfs.lock().await;
        let child = AgentId::new_v4();
        let cloned_kernel = kernel.clone();
        let task = tokio::spawn(async move {
            cloned_kernel
                .clone_agent(parent, child, "cancel me".into(), vec![])
                .await
        });
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while kernel.syscall_gate.agent_info(child).is_none() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let workspace = kernel
            .sandbox_manager
            .sandbox_config(kernel.sandbox_manager.get_sandbox_for_agent(child).unwrap())
            .unwrap()
            .workspace_dir;
        assert_eq!(
            kernel.get_agent_status(child).unwrap(),
            AgentState::Initializing
        );
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        absent(&kernel, child);
        assert!(!workspace.exists());
        drop(cfs);
        kernel
            .clone_agent(parent, child, "retry".into(), vec![])
            .await
            .unwrap();
        kernel.stop_agent(child).await.unwrap();
        kernel.stop_agent(parent).await.unwrap();
    }

    #[tokio::test]
    async fn policy_revocation_during_staging_aborts_the_clone() {
        let kernel = Arc::new(AgentKernelImpl::new().unwrap());
        let parent = kernel.create_agent_full(config()).await.unwrap().id;
        let cfs = kernel.os.cfs.lock().await;
        let child = AgentId::new_v4();
        let cloned_kernel = kernel.clone();
        let task = tokio::spawn(async move {
            cloned_kernel
                .clone_agent(parent, child, "revoked".into(), vec![])
                .await
        });
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while kernel.syscall_gate.agent_info(child).is_none() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        kernel
            .syscall_gate
            .set_capabilities(parent, CapabilitySet::none());
        drop(cfs);
        assert!(task
            .await
            .unwrap()
            .unwrap_err()
            .to_string()
            .contains("authorization changed"));
        absent(&kernel, child);
        kernel.stop_agent(parent).await.unwrap();
    }

    #[tokio::test]
    async fn agent_admission_quota_has_one_winner_for_concurrent_clones() {
        let kernel = AgentKernelImpl::new().unwrap();
        let parent = kernel.create_agent_full(config()).await.unwrap().id;
        kernel
            .operator_control
            .set(crate::operator_control::MAX_AGENTS, 2, 1, "fixture")
            .await
            .unwrap();
        let first = AgentId::new_v4();
        let second = AgentId::new_v4();
        let (left, right) = tokio::join!(
            kernel.clone_agent(parent, first, "first".into(), vec![]),
            kernel.clone_agent(parent, second, "second".into(), vec![])
        );
        assert_eq!(usize::from(left.is_ok()) + usize::from(right.is_ok()), 1);
        assert_eq!(kernel.context_manager.load_all_agents().unwrap().len(), 2);
        let winner = if left.is_ok() { first } else { second };
        absent(&kernel, if left.is_ok() { second } else { first });
        kernel.stop_agent(parent).await.unwrap();
        kernel.stop_agent(winner).await.unwrap();
    }

    #[tokio::test]
    async fn boot_purges_a_durable_pending_clone_before_agent_admission() {
        let root = std::env::temp_dir().join(format!("clone-pending-{}", AgentId::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("store.db");
        let (parent, child) = {
            let kernel = AgentKernelImpl::with_db_path(&path).unwrap();
            let parent = kernel.create_agent_full(config()).await.unwrap().id;
            let mut record = kernel.context_manager.load_all_agents().unwrap().remove(0);
            let child = AgentId::new_v4();
            record.id = child;
            record.session_id = AgentId::new_v4();
            record.status = serde_json::to_string(&AgentState::Initializing).unwrap();
            record.sandbox_config_json = None;
            let gate = kernel
                .syscall_gate
                .capture_clone_security(parent)
                .await
                .unwrap();
            let security = CloneSecurity {
                version: 1,
                profile: record.permission_profile.clone(),
                capabilities: gate.capabilities,
                mac_label: gate.mac_label,
                tokens_per_min: 1000,
                max_concurrent_tool_calls: 1,
                max_context_tokens: 1000,
                max_agents: 1,
            };
            kernel
                .context_manager
                .reserve_clone(&record, parent, "unfinished fixture", None, &security, 0)
                .unwrap();
            (parent, child)
        };
        let kernel = AgentKernelImpl::with_db_path(&path).unwrap();
        let restored = kernel.rehydrate_agents().await.unwrap();
        assert!(restored.contains(&parent));
        assert!(!restored.contains(&child));
        absent(&kernel, child);
        assert_eq!(kernel.context_manager.load_all_agents().unwrap().len(), 1);
        kernel.stop_agent(parent).await.unwrap();
        drop(kernel);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn restart_preserves_managed_clone_data_for_every_isolation_backend() {
        for level in [
            crate::IsolationLevel::Filesystem,
            crate::IsolationLevel::Trusted,
            crate::IsolationLevel::Container,
        ] {
            let root = std::env::temp_dir().join(format!("clone-backend-{}", AgentId::new_v4()));
            std::fs::create_dir_all(&root).unwrap();
            let path = root.join("store.db");
            let (parent, child, workspace) = {
                let kernel = AgentKernelImpl::with_db_path(&path).unwrap();
                let parent = kernel.create_agent_full(config()).await.unwrap().id;
                let child = AgentId::new_v4();
                kernel
                    .clone_agent(parent, child, "backend clone".into(), vec![])
                    .await
                    .unwrap();
                let mut record = kernel
                    .context_manager
                    .load_all_agents()
                    .unwrap()
                    .into_iter()
                    .find(|record| record.id == child)
                    .unwrap();
                let mut sandbox: crate::SandboxConfig =
                    serde_json::from_str(record.sandbox_config_json.as_deref().unwrap()).unwrap();
                let workspace = sandbox.workspace_dir.clone();
                std::fs::write(workspace.join("retained.txt"), "independent child data").unwrap();
                // This recovery fixture changes only the backend metadata. It
                // invokes no process and therefore requires no container image.
                sandbox.isolation_level = level.clone();
                sandbox.container_image = Some(format!("fixture@sha256:{}", "f".repeat(64)));
                record.sandbox_config_json = Some(serde_json::to_string(&sandbox).unwrap());
                kernel.context_manager.save_agent(&record).unwrap();
                (parent, child, workspace)
            };
            let kernel = AgentKernelImpl::with_db_path(&path).unwrap();
            assert_eq!(
                std::fs::read_to_string(workspace.join("retained.txt")).unwrap(),
                "independent child data"
            );
            if kernel.agent_manager.get_agent_state(child).is_some() {
                kernel.stop_agent(child).await.unwrap();
                assert!(
                    !workspace.exists(),
                    "restored managed ownership must reclaim its workspace"
                );
            } else {
                // An unsupported backend stays unadmitted while its owned
                // contents remain available for recovery on a supported host.
                std::fs::remove_dir_all(&workspace).unwrap();
            }
            kernel.stop_agent(parent).await.unwrap();
            drop(kernel);
            std::fs::remove_dir_all(root).unwrap();
        }
    }

    #[tokio::test]
    async fn stop_and_clone_serialize_without_a_dangling_child() {
        let kernel = AgentKernelImpl::new().unwrap();
        let parent = kernel.create_agent_full(config()).await.unwrap().id;
        let child = AgentId::new_v4();
        let (cloned, stopped) = tokio::join!(
            kernel.clone_agent(parent, child, "racing child".into(), vec![]),
            kernel.stop_agent(parent)
        );
        stopped.unwrap();
        if cloned.is_ok() {
            assert_eq!(kernel.get_agent_status(child).unwrap(), AgentState::Running);
            kernel.stop_agent(child).await.unwrap();
        } else {
            absent(&kernel, child);
        }
    }

    #[tokio::test]
    async fn conflicting_wire_child_does_not_wait_behind_a_queued_fence_writer() {
        use crate::syscall_server::{dispatch, Syscall, SyscallReply};
        let kernel = AgentKernelImpl::new().unwrap();
        let parent = kernel.create_agent_full(config()).await.unwrap().id;
        let unrelated = kernel.create_agent_full(config()).await.unwrap().id;
        let barrier = kernel.agent_mutation_fence_barrier(unrelated);
        let reader = barrier.clone().read_owned().await;
        let mut writer = Box::pin(barrier.write_owned());
        tokio::select! {
            biased;
            _ = &mut writer => panic!("writer cannot acquire while the reader is held"),
            _ = tokio::task::yield_now() => {}
        }
        let reply = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            dispatch(
                &kernel,
                Syscall::CloneAgent {
                    agent_id: parent.to_string(),
                    child_agent_id: unrelated.to_string(),
                    child_ownership_proof: None,
                    name: "conflicting child".into(),
                    drop_capabilities: vec![],
                },
            ),
        )
        .await
        .expect("an invalid child must not queue for another agent's fence");
        assert!(matches!(reply, SyscallReply::Error { message } if message.contains("conflicts")));
        drop(writer);
        drop(reader);
        assert_eq!(
            kernel.get_agent_status(parent).unwrap(),
            AgentState::Running
        );
        assert_eq!(
            kernel.get_agent_status(unrelated).unwrap(),
            AgentState::Running
        );
        kernel.stop_agent(parent).await.unwrap();
        kernel.stop_agent(unrelated).await.unwrap();
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(16))]
        #[test]
        fn clone_capability_attenuation_is_monotonic(mask in 0u16..512, drops in 0u16..512) {
            let runtime = tokio::runtime::Runtime::new().unwrap();
            runtime.block_on(async {
                let kernel = AgentKernelImpl::new().unwrap();
                let parent = kernel.create_agent_full(config()).await.unwrap().id;
                let names = ["CAP_TOOL_MOUNT", "CAP_AGENT_CREATE", "CAP_AGENT_KILL", "CAP_NET_ACCESS", "CAP_FILE_WRITE", "CAP_FILE_DELETE", "CAP_EXEC", "CAP_ADMIN", "CAP_SYS_RESOURCE"];
                let mut caps = CapabilitySet::none();
                let mut removed = Vec::new();
                for (index, name) in names.into_iter().enumerate() {
                    let bit = crate::syscall_gate::capability_bit(name).unwrap();
                    if mask & (1 << index) != 0 { caps.grant(bit); }
                    if drops & (1 << index) != 0 { removed.push(name.to_string()); }
                }
                kernel.syscall_gate.set_capabilities(parent, caps);
                let child = AgentId::new_v4();
                kernel.clone_agent(parent, child, "property child".into(), removed.clone()).await.unwrap();
                let parent_caps = kernel.syscall_gate.agent_info(parent).unwrap().capabilities;
                let child_caps = kernel.syscall_gate.agent_info(child).unwrap().capabilities;
                assert!(child_caps.iter().all(|name| parent_caps.contains(name) && !removed.contains(name)));
                assert_eq!(child_caps.len(), parent_caps.iter().filter(|name| !removed.contains(name)).count());
                kernel.stop_agent(parent).await.unwrap();
                kernel.stop_agent(child).await.unwrap();
            });
        }
    }
}
impl CloneSecurity {
    pub(crate) fn limits(&self) -> crate::cgroups::CgroupLimits {
        crate::cgroups::CgroupLimits {
            tokens_per_min: self.tokens_per_min,
            max_concurrent_tool_calls: self.max_concurrent_tool_calls,
            max_context_tokens: self.max_context_tokens,
            max_agents: self.max_agents,
        }
    }
}

/// Metadata returned after the child becomes independently runnable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloneResult {
    pub parent_id: AgentId,
    pub child_id: AgentId,
    pub state: AgentState,
    pub snapshot: Option<ExecutionSnapshotMetadata>,
    pub inherited_handles: usize,
}

fn policy(message: impl Into<String>) -> KernelError {
    KernelError::Policy(message.into())
}

pub(crate) fn clone_attenuation(
    names: &[String],
) -> Result<std::collections::BTreeSet<u64>, KernelError> {
    let mut dropped = std::collections::BTreeSet::new();
    for capability in names {
        let bit = crate::syscall_gate::capability_bit(capability)
            .ok_or_else(|| policy("invalid clone capability attenuation: unknown name"))?;
        if !dropped.insert(bit) {
            return Err(policy(
                "invalid clone capability attenuation: duplicate name",
            ));
        }
    }
    Ok(dropped)
}

// A dropped RPC must release every unpublished runtime resource. The durable
// pending marker handles abrupt process exit; the guard handles future drop.
struct AbortClone<'a> {
    kernel: &'a AgentKernelImpl,
    child: AgentId,
    armed: bool,
}
impl Drop for AbortClone<'_> {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let kernel = self.kernel;
        let info = kernel.syscall_gate.agent_info(self.child);
        let _ = kernel.syscall_gate.force_unregister_agent(self.child);
        kernel.tool_vfs.revoke_agent(self.child);
        kernel.scheduler.deschedule(self.child);
        kernel.scheduler.release_resource_access(self.child);
        kernel.ipc.unregister_agent(self.child);
        kernel.permission_manager.purge_agent(self.child);
        kernel.executors.remove(&self.child);
        kernel.active_cancellations.remove(&self.child);
        if let Some(sandbox) = kernel.sandbox_manager.get_sandbox_for_agent(self.child) {
            if let Err(error) = kernel.sandbox_manager.destroy_sandbox(sandbox) {
                tracing::error!("clone workspace rollback failed: {error}");
            }
        }
        kernel.agent_manager.purge_agent(self.child);
        kernel.budget_enforcer.unregister_agent(self.child);
        kernel.observability.purge_agent(self.child);
        kernel.syscall_gate.purge_agent_stats(self.child);
        if let Err(error) = kernel.reclaim_agent_cgroup(self.child) {
            tracing::error!("clone cgroup rollback failed: {error}");
        }
        if let Err(error) = kernel.context_manager.purge_agent_data(self.child) {
            tracing::error!("clone durable rollback failed: {error}");
        }
        if let Some(info) = info {
            for namespace in &info.namespaces {
                kernel.os.namespaces.leave(*namespace, info.pid);
            }
            let os = kernel.os.clone();
            if let Ok(runtime) = tokio::runtime::Handle::try_current() {
                runtime.spawn(async move {
                    os.cfs.lock().await.dequeue(info.pid);
                    os.procfs.lock().await.remove_agent(info.pid);
                });
            }
        }
        kernel.lifecycle_locks.remove(&self.child);
    }
}

impl AgentKernelImpl {
    /// Clone an idle Running or Paused agent. A live generation checkpoint is
    /// an incompatible continuation, so callers must finish or delete it first.
    /// The caller chooses the child UUID for explicit transport reconciliation.
    /// No descriptors, approvals, sessions, mailboxes or workspace bytes transfer.
    pub async fn clone_agent(
        &self,
        parent: AgentId,
        child: AgentId,
        name: String,
        drop_capabilities: Vec<String>,
    ) -> Result<CloneResult, KernelError> {
        if parent == child || child.is_nil() || name.is_empty() || name.len() > 256 {
            return Err(policy("invalid clone identity or name"));
        }
        let dropped = clone_attenuation(&drop_capabilities)?;
        let request_digest = crate::context::clone_request_digest(parent, &name, &dropped)?;
        let _operator = self.operator_control.mutation_guard().await;
        let parent_lock = self.lifecycle_lock(parent);
        let _parent_held = parent_lock.lock().await;
        if let Some(existing) =
            self.context_manager
                .completed_clone(parent, child, &request_digest)?
        {
            return Ok(existing);
        }
        let state = self.get_agent_status(parent)?;
        if !matches!(state, AgentState::Running | AgentState::Paused) {
            return Err(policy("clone requires an idle Running or Paused parent"));
        }
        let executor = self
            .executors
            .get(&parent)
            .map(|executor| executor.value().clone());
        let _idle = executor
            .as_ref()
            .map(|executor| executor.try_lock())
            .transpose()
            .map_err(|_| {
                policy("clone parent has an active or queued turn; pause it before cloning")
            })?;
        let tenant = self
            .context_manager
            .agent_tenant(parent)?
            .ok_or(AgentError::NotFound(parent))?;
        if !self
            .context_manager
            .list_generation_checkpoints(&tenant, Some(parent))?
            .is_empty()
        {
            return Err(policy(
                "clone does not inherit an active generation checkpoint",
            ));
        }
        let group = self.context_manager.agent_namespace_group(parent)?;
        let mut config = self
            .agent_manager
            .get_agent_config(parent)
            .ok_or(AgentError::NotFound(parent))?;
        let profile = self
            .permission_manager
            .profile_for_agent(parent)
            .ok_or_else(|| policy("clone parent permission profile is unavailable"))?;
        config.permission_profile = profile.clone();
        config.name = name;
        let gate = self
            .syscall_gate
            .capture_clone_security(parent)
            .await
            .map_err(|error| policy(error.to_string()))?;
        let owned_cgroup = self
            .agent_cgroups
            .get(&parent)
            .map(|group| *group)
            .ok_or_else(|| policy("clone parent cgroup is unavailable"))?;
        if gate.cgroup != owned_cgroup {
            return Err(policy("clone parent has an incompatible moved cgroup"));
        }
        let limits = self
            .cgroups
            .get(owned_cgroup)
            .ok_or_else(|| policy("clone parent cgroup disappeared"))?
            .limits;
        let expected_namespaces = self.namespaces_for_group(
            group
                .as_deref()
                .or_else(|| (tenant != crate::context::DEFAULT_TENANT).then_some(tenant.as_str())),
        );
        let mut expected = [
            expected_namespaces.0,
            expected_namespaces.1,
            expected_namespaces.2,
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
        let mut actual = gate.namespaces.clone();
        expected.sort();
        actual.sort();
        if actual != expected {
            return Err(policy(
                "clone parent has an incompatible transient namespace membership",
            ));
        }
        let mut capabilities = gate.capabilities.clone();
        for bit in &dropped {
            capabilities.drop_cap(*bit);
        }
        let security = CloneSecurity {
            version: 1,
            profile,
            capabilities,
            mac_label: gate.mac_label.clone(),
            tokens_per_min: limits.tokens_per_min,
            max_concurrent_tool_calls: limits.max_concurrent_tool_calls,
            max_context_tokens: limits.max_context_tokens,
            max_agents: limits.max_agents,
        };
        let source = self
            .context_manager
            .latest_execution_conversation_id(parent)?;
        if self.agent_manager.get_agent_state(child).is_some() {
            return Err(AgentError::AlreadyExists(child).into());
        }
        let now = chrono::Utc::now();
        let record = PersistedAgent {
            id: child,
            session_id: uuid::Uuid::new_v4(),
            tenant_id: tenant.clone(),
            name: config.name.clone(),
            task: config.task.clone(),
            llm_provider: config.llm_provider.clone(),
            permission_profile: config.permission_profile.clone(),
            priority: config.priority.value(),
            status: serde_json::to_string(&AgentState::Initializing)
                .map_err(|error| policy(error.to_string()))?,
            sandbox_config_json: None,
            created_at: now,
            last_activity_at: now,
        };
        let child_lock = self.lifecycle_lock(child);
        let _child_held = child_lock.lock().await;
        self.context_manager.reserve_clone(
            &record,
            parent,
            &request_digest,
            group.as_deref(),
            &security,
            self.operator_control.max_agents(),
        )?;
        let mut rollback = AbortClone {
            kernel: self,
            child,
            armed: true,
        };
        // Restore only an Initializing registry entry. Tool registration below
        // begins closed, so a discovered staging UUID cannot execute work.
        self.agent_manager.restore_agent(
            child,
            record.session_id,
            config.clone(),
            AgentState::Initializing,
            now,
            now,
        );
        self.permission_manager
            .assign_profile(child, &security.profile);
        let source_sandbox = self
            .sandbox_manager
            .get_sandbox_for_agent(parent)
            .ok_or_else(|| policy("clone parent sandbox is unavailable"))?;
        let mut sandbox_config = self
            .sandbox_manager
            .sandbox_config(source_sandbox)
            .ok_or_else(|| policy("clone parent sandbox policy is unavailable"))?;
        sandbox_config.workspace_dir = SandboxManagerImpl::default_config().workspace_dir;
        let sandbox = self
            .sandbox_manager
            .create_managed_sandbox(child, &sandbox_config)?;
        config.sandbox_config = Some(
            self.sandbox_manager
                .sandbox_config(sandbox)
                .ok_or_else(|| policy("clone workspace configuration unavailable"))?,
        );
        self.place_cloned_agent(child, &config, group.as_deref(), &tenant, &security)
            .await?;
        let pid = self
            .syscall_gate
            .pid_of(child)
            .ok_or_else(|| policy("clone enforcement registration disappeared"))?;
        self.os
            .procfs
            .lock()
            .await
            .set_agent_info(pid, "state".into(), "running".into());
        let snapshot = self
            .syscall_gate
            .with_clone_security(parent, &gate, || {
                self.permission_manager
                    .with_clone_profile(parent, &security.profile, || {
                        self.cgroups
                            .with_clone_limits(owned_cgroup, &limits, || {
                                self.context_manager.commit_clone(
                                    &record,
                                    &config,
                                    source.as_deref(),
                                    parent,
                                    child,
                                )
                            })
                            .map_err(policy)?
                            .map_err(KernelError::Context)
                    })
                    .map_err(policy)?
            })
            .await
            .map_err(|error| policy(error.to_string()))??;
        self.agent_manager.update_agent_config(child, config);
        self.agent_manager
            .transition_state(child, AgentState::Running)?;
        self.ipc.register_agent(child);
        self.scheduler.admit_id(child);
        self.syscall_gate
            .reopen_tool_admission(child)
            .map_err(|error| policy(error.to_string()))?;
        rollback.armed = false;
        let _ = self.event_tx.send(KernelEvent::AgentCreated(child));
        Ok(CloneResult {
            parent_id: parent,
            child_id: child,
            state: AgentState::Running,
            snapshot,
            inherited_handles: 0,
        })
    }

    pub(crate) async fn place_cloned_agent(
        &self,
        child: AgentId,
        config: &crate::AgentConfig,
        group: Option<&str>,
        tenant: &str,
        security: &CloneSecurity,
    ) -> Result<(), KernelError> {
        let cgroup = self.cgroup_for_agent(tenant, &security.profile, child)?;
        self.cgroups
            .update_limits(cgroup, security.limits())
            .map_err(|error| policy(error.to_string()))?;
        let pid = self
            .syscall_gate
            .try_register_managed_agent_closed(child, security.capabilities.clone(), cgroup)
            .map_err(|error| policy(error.to_string()))?;
        self.budget_enforcer.register_agent_tenant(child, tenant);
        self.syscall_gate
            .label_mac_agent(pid, security.mac_label.clone())
            .await;
        let (agent_ns, tool_ns, mount_ns) = self.namespaces_for_group(
            group.or_else(|| (tenant != crate::context::DEFAULT_TENANT).then_some(tenant)),
        );
        let namespaces = [agent_ns, tool_ns, mount_ns]
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();
        for namespace in &namespaces {
            self.os.namespaces.join(*namespace, pid);
        }
        self.syscall_gate.set_agent_namespaces(child, namespaces);
        self.os
            .cfs
            .lock()
            .await
            .enqueue(pid, 0, crate::agent_struct::SchedClass::Normal);
        let mut procfs = self.os.procfs.lock().await;
        procfs.set_agent_info(pid, "name".into(), config.name.clone());
        procfs.set_agent_info(pid, "uuid".into(), child.to_string());
        procfs.set_agent_info(pid, "state".into(), "initializing".into());
        Ok(())
    }
}
