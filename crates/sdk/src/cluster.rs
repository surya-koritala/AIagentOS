//! Distributed orchestration — drive several kernel nodes as one cluster.
//!
//! Each kernel runs as its own [`SyscallServer`](kernel::syscall_server::SyscallServer)
//! (TCP or Unix socket, optionally authenticated). A [`ClusterClient`] holds a
//! [`KernelClient`](crate::KernelClient) connection to each node, places new
//! agents across nodes by a [`Placement`] policy, aggregates listings, and
//! routes per-agent calls (turns, tool calls) back to the node that owns the
//! agent. A node's identity is the address it was dialed at.
//!
//! The wire boundary is unchanged: every call still flows through each node's
//! syscall gate, so enforcement holds across the cluster exactly as it does for
//! a single node.

use std::collections::HashMap;

use crate::{AgentSummary, KernelClient, MessageResult, NodeLoad, SdkError};

/// One kernel node in the cluster: its address-derived id and a live client.
pub struct NodeHandle {
    id: String,
    client: KernelClient,
}

impl NodeHandle {
    /// The node's identity (the address it was connected at).
    pub fn id(&self) -> &str {
        &self.id
    }
    /// Mutable access to the node's typed client.
    pub fn client(&mut self) -> &mut KernelClient {
        &mut self.client
    }
}

/// Placement policy for new agents across cluster nodes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Placement {
    /// Put the agent on the node hosting the fewest agents (queries each node's
    /// load first). Ties break toward the earliest node.
    #[default]
    LeastLoaded,
    /// Cycle through nodes in order, one after another.
    RoundRobin,
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
    /// Connect to every node address. The address string becomes the node id.
    pub async fn connect(addrs: &[String]) -> Result<Self, SdkError> {
        if addrs.is_empty() {
            return Err(SdkError::Kernel("cluster needs at least one node".into()));
        }
        let mut nodes = Vec::with_capacity(addrs.len());
        for addr in addrs {
            let client = KernelClient::connect(addr.as_str()).await?;
            nodes.push(NodeHandle {
                id: addr.clone(),
                client,
            });
        }
        Ok(Self {
            nodes,
            rr: 0,
            owners: HashMap::new(),
        })
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
        match placement {
            Placement::RoundRobin => {
                let idx = self.rr % self.nodes.len();
                self.rr = self.rr.wrapping_add(1);
                Ok(idx)
            }
            Placement::LeastLoaded => {
                let mut best = 0usize;
                let mut best_load = usize::MAX;
                for (idx, node) in self.nodes.iter_mut().enumerate() {
                    let load = node.client.node_info().await?;
                    if load.agent_count < best_load {
                        best_load = load.agent_count;
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
