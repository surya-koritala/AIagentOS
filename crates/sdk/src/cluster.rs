//! Distributed orchestration — drive several kernel nodes as one cluster.
//!
//! Each kernel runs as its own [`SyscallServer`](kernel::syscall_server::SyscallServer)
//! (TCP or Unix socket, optionally authenticated). A [`ClusterClient`] holds a
//! [`KernelClient`] connection to each node, places new
//! agents across nodes by a [`Placement`] policy, aggregates listings, and
//! routes per-agent calls (turns, tool calls) back to the node that owns the
//! agent. Modern nodes publish a durable Ed25519 identity; dial addresses are
//! transport locations only and remain a compatibility fallback for older
//! servers.
//!
//! The wire boundary is unchanged: every call still flows through each node's
//! syscall gate, so enforcement holds across the cluster exactly as it does for
//! a single node.

use std::collections::{BTreeMap, HashMap, HashSet};

use crate::{
    AgentSummary, KernelClient, MessageResult, MessageStreamEvent, NodeAvailability, NodeLoad,
    SdkError, WireErrorCode,
};

/// One kernel node in the cluster: its stable id, transport address, and client.
pub struct NodeHandle {
    id: String,
    address: String,
    fingerprint: Option<String>,
    client: KernelClient,
}

impl NodeHandle {
    /// The node's durable identity (or an address fallback for an older node).
    pub fn id(&self) -> &str {
        &self.id
    }
    /// Current dial address; never use this as a trust identity.
    pub fn address(&self) -> &str {
        &self.address
    }
    /// Durable Ed25519 public-key fingerprint, when supported by the node.
    pub fn fingerprint(&self) -> Option<&str> {
        self.fingerprint.as_deref()
    }
    /// Mutable access to the node's typed client.
    pub fn client(&mut self) -> &mut KernelClient {
        &mut self.client
    }
}

/// Placement policy for new agents across cluster nodes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum Placement {
    /// Put the agent on the node with the lowest actual turn/LLM pressure,
    /// then fewest queued/live agents. Ties break toward the earliest node.
    #[default]
    LeastLoaded,
    /// Cycle through nodes in order, one after another.
    RoundRobin,
    /// Least-loaded placement restricted to nodes matching every requirement.
    Constrained(PlacementConstraints),
}

/// Fail-closed region/model/security requirements for new placement.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PlacementConstraints {
    pub region: Option<String>,
    pub data_residency: Option<String>,
    pub model: Option<String>,
    pub sandbox_profile: Option<String>,
    pub labels: BTreeMap<String, String>,
}

/// The result of placing an agent: its id and the node it landed on.
#[derive(Debug, Clone)]
pub struct PlacedAgent {
    pub agent_id: String,
    pub node_id: String,
}

/// A client that fans out across multiple kernel nodes.
pub struct ClusterClient {
    nodes: Vec<NodeHandle>,
    rr: usize,
    /// agent id → index into `nodes` (the node that owns the agent).
    owners: HashMap<String, usize>,
}

impl ClusterClient {
    /// Connect to every node, prove each durable identity, reject duplicates,
    /// and reconstruct the ownership directory from durable node listings.
    pub async fn connect(addrs: &[String]) -> Result<Self, SdkError> {
        Self::connect_with_token(addrs, None).await
    }

    /// Connect and authenticate every node with the same tenant/system token.
    ///
    /// Construction is all-or-nothing: a failed node authentication drops all
    /// earlier connections and never returns a partially authorized cluster.
    pub async fn connect_authenticated(
        addrs: &[String],
        token: impl Into<String>,
    ) -> Result<Self, SdkError> {
        Self::connect_with_token(addrs, Some(token.into())).await
    }

    /// Connect every node over TLS and prove its durable application identity.
    ///
    /// `config` may include a client certificate for mutual TLS. The same
    /// server name and trust/client-credential configuration is used for each
    /// address, which is appropriate for nodes issued from one cluster PKI.
    pub async fn connect_tls(
        addrs: &[String],
        server_name: impl Into<String>,
        config: rustls::ClientConfig,
    ) -> Result<Self, SdkError> {
        Self::connect_tls_with_token(addrs, server_name.into(), config, None).await
    }

    /// Connect every node over TLS, authenticate the syscall protocol, and
    /// prove its durable node identity.
    pub async fn connect_tls_authenticated(
        addrs: &[String],
        server_name: impl Into<String>,
        config: rustls::ClientConfig,
        token: impl Into<String>,
    ) -> Result<Self, SdkError> {
        Self::connect_tls_with_token(addrs, server_name.into(), config, Some(token.into())).await
    }

    async fn connect_with_token(addrs: &[String], token: Option<String>) -> Result<Self, SdkError> {
        if addrs.is_empty() {
            return Err(SdkError::Kernel("cluster needs at least one node".into()));
        }
        let mut connections = Vec::with_capacity(addrs.len());
        for addr in addrs {
            let mut client = KernelClient::connect(addr.as_str()).await?;
            if let Some(token) = token.as_deref() {
                client.authenticate(token).await?;
            }
            connections.push((addr.clone(), client));
        }
        Self::from_connections(connections).await
    }

    async fn connect_tls_with_token(
        addrs: &[String],
        server_name: String,
        config: rustls::ClientConfig,
        token: Option<String>,
    ) -> Result<Self, SdkError> {
        if addrs.is_empty() {
            return Err(SdkError::Kernel("cluster needs at least one node".into()));
        }
        let mut connections = Vec::with_capacity(addrs.len());
        for addr in addrs {
            let mut client =
                KernelClient::connect_tls(addr.as_str(), server_name.clone(), config.clone())
                    .await?;
            if let Some(token) = token.as_deref() {
                client.authenticate(token).await?;
            }
            connections.push((addr.clone(), client));
        }
        Self::from_connections(connections).await
    }

    async fn from_connections(connections: Vec<(String, KernelClient)>) -> Result<Self, SdkError> {
        let mut nodes = Vec::with_capacity(connections.len());
        let mut identities = HashSet::new();
        for (addr, mut client) in connections {
            let load = client.node_info().await?;
            let (id, fingerprint) = match load.control {
                Some(control) => {
                    let challenge = *uuid::Uuid::new_v4().as_bytes();
                    let proof = client.prove_node_identity(hex_encode(&challenge)).await?;
                    let signature = hex_decode(&proof.signature_hex).ok_or_else(|| {
                        SdkError::Kernel(format!(
                            "cluster node {} returned a malformed identity signature",
                            control.identity.node_id
                        ))
                    })?;
                    let consistent = proof.node_id == control.identity.node_id
                        && proof.fingerprint == control.identity.fingerprint
                        && proof.public_key == control.identity.public_key
                        && kernel::cluster_control::ClusterControl::verify_challenge(
                            &proof.public_key,
                            &challenge,
                            &signature,
                        );
                    if !consistent {
                        return Err(SdkError::Kernel(format!(
                            "cluster node at {addr} failed durable identity proof"
                        )));
                    }
                    (control.identity.node_id, Some(control.identity.fingerprint))
                }
                None => (addr.clone(), None),
            };
            if !identities.insert(id.clone()) {
                return Err(SdkError::Wire {
                    code: WireErrorCode::Conflict,
                    message: format!("duplicate cluster node identity {id}"),
                    retryable: false,
                });
            }
            nodes.push(NodeHandle {
                id,
                address: addr,
                fingerprint,
                client,
            });
        }
        let mut cluster = Self {
            nodes,
            rr: 0,
            owners: HashMap::new(),
        };
        cluster.rebuild_owners().await?;
        Ok(cluster)
    }

    /// Number of nodes in the cluster.
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// The node ids (dialed addresses).
    pub fn node_ids(&self) -> Vec<String> {
        self.nodes.iter().map(|n| n.id.clone()).collect()
    }

    /// Query every node's current load.
    pub async fn nodes_load(&mut self) -> Result<Vec<(String, NodeLoad)>, SdkError> {
        let mut out = Vec::with_capacity(self.nodes.len());
        for node in &mut self.nodes {
            let load = node.client.node_info().await?;
            out.push((node.id.clone(), load));
        }
        Ok(out)
    }

    /// Pick the target node index for the given placement policy.
    async fn pick_node(&mut self, placement: Placement) -> Result<usize, SdkError> {
        let loads = self.nodes_load().await?;
        let requirements = match &placement {
            Placement::Constrained(requirements) => Some(requirements),
            Placement::LeastLoaded | Placement::RoundRobin => None,
        };
        let candidates: Vec<usize> = loads
            .iter()
            .enumerate()
            .filter_map(|(index, (_, load))| node_accepts(load, requirements).then_some(index))
            .collect();
        if candidates.is_empty() {
            return Err(SdkError::Wire {
                code: WireErrorCode::Unavailable,
                message: "no active cluster node satisfies placement constraints".to_string(),
                retryable: true,
            });
        }
        match placement {
            Placement::RoundRobin => {
                let idx = candidates[self.rr % candidates.len()];
                self.rr = self.rr.wrapping_add(1);
                Ok(idx)
            }
            Placement::LeastLoaded | Placement::Constrained(_) => {
                let mut best = candidates[0];
                let mut best_load = (usize::MAX, usize::MAX, usize::MAX);
                for idx in candidates {
                    let load = &loads[idx].1;
                    let turn_pressure = load
                        .active_turns
                        .saturating_mul(1_000)
                        .checked_div(load.turn_capacity.max(1))
                        .unwrap_or(usize::MAX);
                    let llm_pressure = load
                        .llm_requests_in_flight
                        .saturating_mul(1_000)
                        .checked_div(load.llm_core_capacity.max(1))
                        .unwrap_or(usize::MAX);
                    let score = (
                        turn_pressure.max(llm_pressure),
                        load.queued_agents.saturating_add(load.waiting_turns),
                        load.live_agents,
                    );
                    if score < best_load {
                        best_load = score;
                        best = idx;
                    }
                }
                Ok(best)
            }
        }
    }

    /// Create an agent on the cluster, placed per `placement`. Records the
    /// owning node so later [`send_message`](Self::send_message) /
    /// [`call_tool`](Self::call_tool) route back to it.
    pub async fn create_agent(
        &mut self,
        name: impl Into<String>,
        task: impl Into<String>,
        provider: Option<String>,
        profile: Option<String>,
        priority: Option<u8>,
        placement: Placement,
    ) -> Result<PlacedAgent, SdkError> {
        let idx = self.pick_node(placement).await?;
        let node_id = self.nodes[idx].id.clone();
        let agent_id = self.nodes[idx]
            .client
            .create_agent(name, task, provider, profile, priority)
            .await?;
        self.owners.insert(agent_id.clone(), idx);
        Ok(PlacedAgent { agent_id, node_id })
    }

    /// The node id that owns an agent created through this cluster, if known.
    pub fn owner_of(&self, agent_id: &str) -> Option<&str> {
        self.owners
            .get(agent_id)
            .map(|&i| self.nodes[i].id.as_str())
    }

    /// Rebuild routing from durable node state. Duplicate agent ownership is a
    /// split-brain conflict and fails closed instead of selecting one owner.
    pub async fn rebuild_owners(&mut self) -> Result<(), SdkError> {
        let mut rebuilt: HashMap<String, usize> = HashMap::new();
        for index in 0..self.nodes.len() {
            let agents = self.nodes[index].client.list_agents().await?;
            for agent in agents {
                if let Some(previous) = rebuilt.insert(agent.id.clone(), index) {
                    return Err(SdkError::Wire {
                        code: WireErrorCode::Conflict,
                        message: format!(
                            "duplicate agent ownership for {} on nodes {} and {}",
                            agent.id, self.nodes[previous].id, self.nodes[index].id
                        ),
                        retryable: false,
                    });
                }
            }
        }
        self.owners = rebuilt;
        Ok(())
    }

    fn owner_index(&self, agent_id: &str) -> Result<usize, SdkError> {
        match self.owners.get(agent_id) {
            Some(&idx) => Ok(idx),
            None => Err(SdkError::Kernel(format!(
                "no cluster node owns agent {agent_id}"
            ))),
        }
    }

    /// Drive one turn for an agent, routed to its owning node.
    pub async fn send_message(
        &mut self,
        agent_id: &str,
        message: impl Into<String>,
    ) -> Result<MessageResult, SdkError> {
        let idx = self.owner_index(agent_id)?;
        self.nodes[idx].client.send_message(agent_id, message).await
    }

    /// Drive one streamed turn on the agent's owning node.
    pub async fn send_message_stream<F>(
        &mut self,
        request_id: impl Into<String>,
        agent_id: &str,
        message: impl Into<String>,
        on_event: F,
    ) -> Result<MessageResult, SdkError>
    where
        F: FnMut(&MessageStreamEvent),
    {
        let idx = self.owner_index(agent_id)?;
        self.nodes[idx]
            .client
            .send_message_stream(request_id, agent_id, message, on_event)
            .await
    }

    /// Cancel one exact active stream on the agent's owning node.
    ///
    /// The owning node needs a second connection while
    /// [`send_message_stream`](Self::send_message_stream) is active. Callers
    /// can obtain one with [`node`](Self::node), or use a separate
    /// [`KernelClient`] connected and authenticated to the same node.
    pub async fn cancel_request(
        &mut self,
        request_id: impl Into<String>,
        agent_id: &str,
    ) -> Result<bool, SdkError> {
        let idx = self.owner_index(agent_id)?;
        self.nodes[idx]
            .client
            .cancel_request(request_id, agent_id)
            .await
    }

    /// Invoke a tool as an agent, routed to its owning node (gate-enforced there).
    pub async fn call_tool(
        &mut self,
        agent_id: &str,
        tool: impl Into<String>,
        args: serde_json::Value,
    ) -> Result<serde_json::Value, SdkError> {
        let idx = self.owner_index(agent_id)?;
        self.nodes[idx].client.call_tool(agent_id, tool, args).await
    }

    /// List agents across the whole cluster, each tagged with its node id.
    pub async fn list_agents(&mut self) -> Result<Vec<(String, AgentSummary)>, SdkError> {
        let mut out = Vec::new();
        for node in &mut self.nodes {
            let id = node.id.clone();
            for a in node.client.list_agents().await? {
                out.push((id.clone(), a));
            }
        }
        Ok(out)
    }

    /// Mutable access to a node by id (for node-specific calls).
    pub fn node(&mut self, id: &str) -> Option<&mut NodeHandle> {
        self.nodes.iter_mut().find(|n| n.id == id)
    }
}

fn node_accepts(load: &NodeLoad, requirements: Option<&PlacementConstraints>) -> bool {
    let Some(control) = load.control.as_ref() else {
        return requirements.is_none();
    };
    if control.availability != NodeAvailability::Active {
        return false;
    }
    let Some(requirements) = requirements else {
        return true;
    };
    requirements
        .region
        .as_ref()
        .is_none_or(|region| control.profile.region.as_ref() == Some(region))
        && requirements
            .data_residency
            .as_ref()
            .is_none_or(|residency| control.profile.data_residency.as_ref() == Some(residency))
        && requirements
            .model
            .as_ref()
            .is_none_or(|model| control.profile.models.contains(model))
        && requirements
            .sandbox_profile
            .as_ref()
            .is_none_or(|profile| control.profile.sandbox_profiles.contains(profile))
        && requirements.labels.iter().all(|(key, value)| {
            control
                .profile
                .labels
                .get(key)
                .is_some_and(|actual| actual == value)
        })
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn hex_decode(value: &str) -> Option<Vec<u8>> {
    if !value.len().is_multiple_of(2) {
        return None;
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let pair = std::str::from_utf8(pair).ok()?;
            u8::from_str_radix(pair, 16).ok()
        })
        .collect()
}
