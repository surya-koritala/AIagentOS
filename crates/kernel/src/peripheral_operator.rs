//! Process-local human approval handoff for exact peripheral contracts.

use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use serde::Serialize;
use tokio::sync::watch;

use crate::agent::AgentKernel;
use crate::syscall_gate::{LocalPeripheralAction, LocalPeripheralContract, SyscallGate};
use crate::tools::{ApprovalPolicy, PreparedToolExecution};
use crate::{AgentId, AgentKernelImpl, KernelError, PeripheralRevocation};

const MAX_REQUESTS: usize = 64;
const MAX_TARGET_BYTES: usize = 4096;
const APPROVAL_WAIT: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PeripheralRequestStatus {
    AwaitingApproval,
    Approved,
    Denied,
    Revoked,
    Cancelled,
    Expired,
    Finished,
}

/// Only this bounded, non-secret projection crosses native desktop IPC.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PeripheralOperatorRequest {
    pub request_id: uuid::Uuid,
    pub agent_id: AgentId,
    pub agent_name: String,
    pub tool_name: String,
    pub resource_identity: String,
    pub required_policy: ApprovalPolicy,
    pub status: PeripheralRequestStatus,
    pub grant_pending: bool,
    pub active_uses: usize,
}

// Raw targets remain private, bounded, and process-local. No Debug or Serialize
// implementation is provided for records or the human authority handle.
struct Request {
    id: uuid::Uuid,
    agent: AgentId,
    registration: u64,
    binding: uuid::Uuid,
    tool: String,
    resource: String,
    digest: String,
    activity: String,
    required: ApprovalPolicy,
    status: Mutex<PeripheralRequestStatus>,
    decision: watch::Sender<PeripheralRequestStatus>,
}

impl Request {
    fn contract(&self) -> LocalPeripheralContract<'_> {
        LocalPeripheralContract {
            agent_id: self.agent,
            registration: self.registration,
            tool_name: &self.tool,
            resource: &self.resource,
            contract: &self.digest,
            required: self.required,
            activity: &self.activity,
        }
    }

    fn cancel(&self, gate: &SyscallGate, reason: PeripheralRequestStatus) {
        let mut status = self.status.lock().unwrap();
        if matches!(*status, PeripheralRequestStatus::AwaitingApproval | PeripheralRequestStatus::Approved) {
            gate.local_peripheral_contract(self.contract(), LocalPeripheralAction::Revoke);
            *status = reason;
            self.decision.send_replace(reason);
        }
    }
}

pub(crate) struct PeripheralRequests {
    gate: Arc<SyscallGate>,
    records: Mutex<Vec<Arc<Request>>>,
    attached: AtomicBool,
}

impl PeripheralRequests {
    pub(crate) async fn wait_for_approval<'a>(
        &self,
        gate: &'a SyscallGate,
        name: &str,
        prepared: &PreparedToolExecution,
        identity: &str,
        registration: u64,
    ) -> Option<PendingPeripheralResume<'a>> {
        if !self.attached.load(Ordering::SeqCst) || prepared.authorization.resource.len() > MAX_TARGET_BYTES
            || name.len() > 128 || name.chars().any(char::is_control)
            || gate.peripheral_registration(prepared.request.agent_id) != Some(registration) {
            return None;
        }
        let (decision, mut receiver) = watch::channel(PeripheralRequestStatus::AwaitingApproval);
        let request = Arc::new(Request {
            id: uuid::Uuid::new_v4(), agent: prepared.request.agent_id,
            registration, binding: prepared.binding_identity, tool: name.to_string(),
            resource: prepared.authorization.resource.clone(), digest: prepared.approval_contract_digest.clone(),
            activity: crate::resources::peripheral_activity_identity(name, &prepared.approval_contract_digest, identity),
            required: prepared.authorization.security.approval_policy,
            status: Mutex::new(PeripheralRequestStatus::AwaitingApproval), decision,
        });
        {
            let mut records = self.records.lock().unwrap();
            if !self.attached.load(Ordering::SeqCst) { return None; }
            if records.len() == MAX_REQUESTS {
                // Never evict a waiter, an unconsumed grant, or an active use.
                if let Some(index) = records.iter().position(|record| {
                    *record.status.lock().unwrap() != PeripheralRequestStatus::AwaitingApproval
                        && self.gate.local_peripheral_contract(record.contract(), LocalPeripheralAction::Inspect).is_none_or(|(pending, active)| !pending && active == 0)
                }) { records.remove(index); } else { return None; }
            }
            records.push(Arc::clone(&request));
        }
        let waiting = PendingPeripheralResume { request: Arc::clone(&request), gate, admitted: false };
        let result = tokio::time::timeout(APPROVAL_WAIT, receiver.changed()).await;
        let approved = result.is_ok_and(|result| result.is_ok())
            && *receiver.borrow() == PeripheralRequestStatus::Approved;
        if approved { Some(waiting) } else {
            request.cancel(gate, PeripheralRequestStatus::Expired);
            None
        }
    }

    pub(crate) fn cancel_agent(&self, agent: AgentId) {
        let records = self.records.lock().unwrap().clone();
        for record in records.iter().filter(|record| record.agent == agent) {
            record.cancel(&self.gate, PeripheralRequestStatus::Cancelled);
        }
    }

    fn find(&self, id: uuid::Uuid) -> Result<Arc<Request>, KernelError> {
        self.records.lock().unwrap().iter().find(|record| record.id == id).cloned()
            .ok_or_else(|| KernelError::Policy("peripheral request is unavailable".into()))
    }
}

pub(crate) struct PendingPeripheralResume<'a> {
    request: Arc<Request>,
    gate: &'a SyscallGate,
    pub(crate) admitted: bool,
}

impl Drop for PendingPeripheralResume<'_> {
    fn drop(&mut self) {
        if !self.admitted { self.request.cancel(self.gate, PeripheralRequestStatus::Cancelled); }
    }
}

/// Native host authority. Creation and decisions require the in-process kernel;
/// remote DesktopClient instances, agentctl, SDK, MCP and packages have no route.
pub struct LocalPeripheralOperator {
    kernel: Arc<AgentKernelImpl>,
    requests: Arc<PeripheralRequests>,
}

impl LocalPeripheralOperator {
    pub(crate) fn attach(kernel: Arc<AgentKernelImpl>) -> Result<Self, KernelError> {
        let requests = Arc::new(PeripheralRequests { gate: Arc::clone(&kernel.syscall_gate), records: Mutex::new(Vec::new()), attached: AtomicBool::new(true) });
        {
            let mut local = kernel.tool_registry.local_peripheral.lock().unwrap();
            if local.upgrade().is_some() { return Err(KernelError::Policy("local peripheral operator already attached".into())); }
            *local = Arc::downgrade(&requests);
        }
        Ok(Self { kernel, requests })
    }

    pub fn requests(&self) -> Vec<PeripheralOperatorRequest> {
        let agents = self.kernel.agent_manager.list_agents(None);
        self.requests.records.lock().unwrap().iter().map(|record| {
            let recorded_status = record.status.lock().unwrap();
            let state = self.kernel.syscall_gate.local_peripheral_contract(record.contract(), LocalPeripheralAction::Inspect);
            let (grant_pending, active_uses) = state.unwrap_or((false, 0));
            let mut status = *recorded_status;
            if state.is_none() { status = PeripheralRequestStatus::Cancelled; }
            else if status == PeripheralRequestStatus::Approved && !grant_pending && active_uses == 0 { status = PeripheralRequestStatus::Finished; }
            let agent_name = agents.iter().find(|agent| agent.id == record.agent).map(|agent| agent.name.as_str()).unwrap_or("Stopped agent");
            PeripheralOperatorRequest {
                request_id: record.id, agent_id: record.agent,
                agent_name: agent_name.chars().filter(|character| !character.is_control()).take(128).collect(),
                tool_name: record.tool.clone(), resource_identity: crate::resources::opaque_identity(record.resource.as_bytes()),
                required_policy: record.required, status, grant_pending, active_uses,
            }
        }).collect()
    }

    /// One human decision issues the existing single-use gate grant. The
    /// original caller subsequently repeats canonical policy/slot admission.
    pub fn approve(&self, id: uuid::Uuid) -> Result<(), KernelError> {
        let request = self.requests.find(id)?;
        let mut status = request.status.lock().unwrap();
        if *status != PeripheralRequestStatus::AwaitingApproval { return Err(KernelError::Policy("peripheral request is no longer awaiting approval".into())); }
        let granted = self.kernel.tool_registry.with_peripheral_binding(&request.tool, request.binding, || {
            self.kernel.syscall_gate.local_peripheral_contract(request.contract(), LocalPeripheralAction::Approve)
        }).flatten();
        if granted.is_none() { return Err(KernelError::Policy("peripheral request authority changed".into())); }
        *status = PeripheralRequestStatus::Approved;
        request.decision.send_replace(*status);
        Ok(())
    }

    pub fn deny(&self, id: uuid::Uuid) -> Result<(), KernelError> {
        let request = self.requests.find(id)?;
        let mut status = request.status.lock().unwrap();
        if *status != PeripheralRequestStatus::AwaitingApproval { return Err(KernelError::Policy("peripheral request is no longer awaiting approval".into())); }
        *status = PeripheralRequestStatus::Denied;
        request.decision.send_replace(*status);
        Ok(())
    }

    /// Revocation uses the saved exact contract, including after a registry
    /// replacement. It never resolves new arguments or targets from the UI.
    pub fn revoke(&self, id: uuid::Uuid) -> Result<PeripheralRevocation, KernelError> {
        let request = self.requests.find(id)?;
        let mut status = request.status.lock().unwrap();
        let (pending_grant_revoked, active_uses_cancelled) = self.kernel.syscall_gate.local_peripheral_contract(request.contract(), LocalPeripheralAction::Revoke).unwrap_or((false, 0));
        *status = PeripheralRequestStatus::Revoked;
        request.decision.send_replace(*status);
        Ok(PeripheralRevocation { pending_grant_revoked, active_uses_cancelled })
    }
}

impl Drop for LocalPeripheralOperator {
    fn drop(&mut self) {
        self.requests.attached.store(false, Ordering::SeqCst);
        let records = self.requests.records.lock().unwrap().clone();
        for record in records { record.cancel(&self.kernel.syscall_gate, PeripheralRequestStatus::Cancelled); }
    }
}
