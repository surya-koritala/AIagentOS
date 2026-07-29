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
    AgentMutationFence, AgentMutationFenceProof, AgentMutationFenceState, AgentSummary,
    ClusterAgentOwnership, ClusterMember, ClusterMemberRegistration, ClusterMemberState,
    ClusterMembershipSnapshot, ClusterOwnershipState, KernelClient, MessageResult,
    MessageStreamEvent, NodeAvailability, NodeLoad, SdkError, WireErrorCode,
};

/// Initial authority lease used when a discovered cluster places an agent.
///
/// Long-lived clients must renew before this authority-clock deadline.
pub const DEFAULT_OWNERSHIP_LEASE_SECONDS: u64 = 30;

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
    /// Exact authority proof published for each managed route.
    ownership_proofs: HashMap<String, AgentMutationFenceProof>,
    /// Retained only by authority-discovered clients. Explicit-address clients
    /// remain legacy unmanaged clients and never manufacture authority state.
    authority: Option<ClusterAuthority>,
}

struct ClusterAuthority {
    client: KernelClient,
    cluster_id: String,
}

impl ClusterClient {
    /// Admit one connected node through an authority-issued, one-time challenge.
    ///
    /// The node signs a domain-separated payload covering its durable identity,
    /// endpoint, software version, and protocol window. A returning member must
    /// supply its current generation; new members pass `None`.
    pub async fn admit_node(
        authority: &mut KernelClient,
        node: &mut KernelClient,
        endpoint: impl Into<String>,
        expected_generation: Option<u64>,
        reason: impl Into<String>,
    ) -> Result<ClusterMember, SdkError> {
        let endpoint = endpoint.into();
        let challenge = authority.issue_cluster_join_challenge(30).await?;
        let load = node.node_info().await?;
        let control = load.control.ok_or_else(|| {
            SdkError::Kernel("cluster membership requires durable node identity support".into())
        })?;
        let protocol = node.hello().await?;
        let registration = ClusterMemberRegistration {
            node_id: control.identity.node_id,
            fingerprint: control.identity.fingerprint,
            public_key: control.identity.public_key,
            endpoint,
            server_version: protocol.server_version,
            min_protocol_version: protocol.min_protocol_version,
            protocol_version: protocol.protocol_version,
        };
        let payload = kernel::cluster_control::membership_join_payload(
            &challenge.cluster_id,
            &challenge.challenge_hex,
            &registration,
        )
        .map_err(|error| SdkError::Kernel(error.to_string()))?;
        let proof = node.prove_node_identity(hex_encode(&payload)).await?;
        if proof.node_id != registration.node_id
            || proof.fingerprint != registration.fingerprint
            || proof.public_key != registration.public_key
        {
            return Err(SdkError::Wire {
                code: WireErrorCode::Conflict,
                message: "node identity changed while completing cluster admission".into(),
                retryable: false,
            });
        }
        authority
            .register_cluster_member(
                registration,
                challenge.challenge_hex,
                proof.signature_hex,
                expected_generation,
                reason,
            )
            .await
    }

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

    /// Discover the active authority membership over authenticated connections.
    ///
    /// Construction validates every durable identity and endpoint against one
    /// atomic membership snapshot, then re-reads the authority generation. A
    /// concurrent membership change fails with a retryable conflict instead of
    /// returning a cluster assembled from mixed revisions.
    pub async fn connect_discovered_authenticated(
        authority_addr: impl AsRef<str>,
        token: impl Into<String>,
    ) -> Result<Self, SdkError> {
        let authority_addr = authority_addr.as_ref();
        let token = token.into();
        let mut authority = KernelClient::connect(authority_addr).await?;
        authority.authenticate(&token).await?;
        let snapshot = authority.cluster_membership().await?;
        let addrs = active_member_endpoints(&snapshot)?;
        let mut cluster = Self::connect_authenticated(&addrs, token).await?;
        cluster.validate_membership(&snapshot)?;
        let confirmed = authority.cluster_membership().await?;
        ensure_unchanged_membership(&snapshot, &confirmed)?;
        cluster.authority = Some(ClusterAuthority {
            client: authority,
            cluster_id: confirmed.cluster_id,
        });
        cluster.rebuild_owners().await?;
        Ok(cluster)
    }

    /// TLS/mTLS variant of [`connect_discovered_authenticated`](Self::connect_discovered_authenticated).
    pub async fn connect_discovered_tls_authenticated(
        authority_addr: impl AsRef<str>,
        server_name: impl Into<String>,
        config: rustls::ClientConfig,
        token: impl Into<String>,
    ) -> Result<Self, SdkError> {
        let authority_addr = authority_addr.as_ref();
        let server_name = server_name.into();
        let token = token.into();
        let mut authority =
            KernelClient::connect_tls(authority_addr, server_name.clone(), config.clone()).await?;
        authority.authenticate(&token).await?;
        let snapshot = authority.cluster_membership().await?;
        let addrs = active_member_endpoints(&snapshot)?;
        let mut cluster =
            Self::connect_tls_authenticated(&addrs, server_name, config, token).await?;
        cluster.validate_membership(&snapshot)?;
        let confirmed = authority.cluster_membership().await?;
        ensure_unchanged_membership(&snapshot, &confirmed)?;
        cluster.authority = Some(ClusterAuthority {
            client: authority,
            cluster_id: confirmed.cluster_id,
        });
        cluster.rebuild_owners().await?;
        Ok(cluster)
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
            ownership_proofs: HashMap::new(),
            authority: None,
        };
        cluster.rebuild_owners().await?;
        Ok(cluster)
    }

    /// Number of nodes in the cluster.
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Whether this client retains a designated authority and therefore
    /// publishes and enforces exact ownership-fenced routes.
    pub fn is_authority_managed(&self) -> bool {
        self.authority.is_some()
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
        if let Some(authority) = self.authority.as_mut() {
            let ownership = authority
                .client
                .claim_cluster_agent_ownership(
                    &agent_id,
                    &node_id,
                    DEFAULT_OWNERSHIP_LEASE_SECONDS,
                    None,
                    "cluster client placement",
                )
                .await
                .map_err(|source| {
                    route_publication_error(&agent_id, "authority ownership claim", source)
                })?;
            let proof = ownership_proof(&authority.cluster_id, &ownership);
            let fence = self.nodes[idx]
                .client
                .install_agent_mutation_fence(
                    &agent_id,
                    &proof.cluster_id,
                    &proof.owner_node_id,
                    proof.authority_generation,
                    proof.fencing_token,
                    "cluster client route publication",
                )
                .await
                .map_err(|source| {
                    route_publication_error(&agent_id, "destination fence installation", source)
                })?;
            validate_destination_fence(&agent_id, &proof, &fence).map_err(|source| {
                route_publication_error(&agent_id, "destination fence verification", source)
            })?;
            self.ownership_proofs.insert(agent_id.clone(), proof);
        }
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
        // Invalidate the published directory before any fallible read. A
        // caller that observes an error cannot keep using a previously valid
        // route after ownership or destination evidence changed.
        self.owners.clear();
        self.ownership_proofs.clear();
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
        let mut rebuilt_proofs = HashMap::new();
        if let Some(authority) = self.authority.as_mut() {
            for (agent_id, index) in &rebuilt {
                let ownership = authority
                    .client
                    .active_cluster_agent_ownership(agent_id)
                    .await?;
                validate_active_ownership(agent_id, &self.nodes[*index].id, &ownership)?;
                let proof = ownership_proof(&authority.cluster_id, &ownership);
                let fence = self.nodes[*index]
                    .client
                    .agent_mutation_fence(agent_id)
                    .await?
                    .ok_or_else(|| {
                        route_conflict(format!(
                            "destination {} has no mutation fence for agent {agent_id}",
                            self.nodes[*index].id
                        ))
                    })?;
                validate_destination_fence(agent_id, &proof, &fence)?;
                rebuilt_proofs.insert(agent_id.clone(), proof);
            }
        }
        self.owners = rebuilt;
        self.ownership_proofs = rebuilt_proofs;
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

    async fn current_mutation_proof(
        &mut self,
        agent_id: &str,
    ) -> Result<Option<AgentMutationFenceProof>, SdkError> {
        let result = self.validated_mutation_proof(agent_id).await;
        if result.is_err() {
            self.owners.remove(agent_id);
            self.ownership_proofs.remove(agent_id);
        }
        result
    }

    async fn validated_mutation_proof(
        &mut self,
        agent_id: &str,
    ) -> Result<Option<AgentMutationFenceProof>, SdkError> {
        let idx = self.owner_index(agent_id)?;
        let Some(authority) = self.authority.as_mut() else {
            return Ok(None);
        };
        let ownership = authority
            .client
            .active_cluster_agent_ownership(agent_id)
            .await?;
        validate_active_ownership(agent_id, &self.nodes[idx].id, &ownership)?;
        let proof = ownership_proof(&authority.cluster_id, &ownership);
        let current_fence = self.nodes[idx]
            .client
            .agent_mutation_fence(agent_id)
            .await?;
        match current_fence {
            Some(fence) if destination_fence_matches(agent_id, &proof, &fence) => {}
            Some(fence)
                if fence.fencing_token > proof.fencing_token
                    || (fence.fencing_token == proof.fencing_token
                        && fence.authority_generation > proof.authority_generation) =>
            {
                return Err(route_conflict(format!(
                    "destination {} has newer ownership evidence for agent {agent_id}",
                    self.nodes[idx].id
                )));
            }
            _ => {
                let installed = self.nodes[idx]
                    .client
                    .install_agent_mutation_fence(
                        agent_id,
                        &proof.cluster_id,
                        &proof.owner_node_id,
                        proof.authority_generation,
                        proof.fencing_token,
                        "cluster client route refresh",
                    )
                    .await?;
                validate_destination_fence(agent_id, &proof, &installed)?;
            }
        }
        self.ownership_proofs
            .insert(agent_id.to_string(), proof.clone());
        Ok(Some(proof))
    }

    /// Renew one managed route's exact ownership lease and publish the renewed
    /// authority generation to its destination before returning.
    pub async fn renew_agent_ownership(
        &mut self,
        agent_id: &str,
        ttl_seconds: u64,
    ) -> Result<(), SdkError> {
        let idx = self.owner_index(agent_id)?;
        let existing = self
            .current_mutation_proof(agent_id)
            .await?
            .ok_or_else(|| {
                SdkError::Configuration(
                    "ownership renewal requires an authority-discovered cluster".into(),
                )
            })?;
        let authority = self
            .authority
            .as_mut()
            .expect("managed proof requires retained authority");
        let ownership = authority
            .client
            .renew_cluster_agent_ownership(
                agent_id,
                &self.nodes[idx].id,
                existing.fencing_token,
                ttl_seconds,
                "cluster client lease renewal",
            )
            .await
            .map_err(|source| {
                route_publication_error(agent_id, "authority ownership renewal", source)
            })?;
        validate_active_ownership(agent_id, &self.nodes[idx].id, &ownership)?;
        let proof = ownership_proof(&authority.cluster_id, &ownership);
        let fence = self.nodes[idx]
            .client
            .install_agent_mutation_fence(
                agent_id,
                &proof.cluster_id,
                &proof.owner_node_id,
                proof.authority_generation,
                proof.fencing_token,
                "cluster client lease renewal",
            )
            .await
            .map_err(|source| {
                route_publication_error(agent_id, "renewed destination fence installation", source)
            })?;
        validate_destination_fence(agent_id, &proof, &fence).map_err(|source| {
            route_publication_error(agent_id, "renewed destination fence verification", source)
        })?;
        self.ownership_proofs.insert(agent_id.to_string(), proof);
        Ok(())
    }

    /// Renew and republish every currently routed managed agent.
    ///
    /// This is explicit rather than a hidden background task: callers choose
    /// their scheduling and failure policy, and any first failure is surfaced.
    pub async fn renew_all_agent_ownerships(
        &mut self,
        ttl_seconds: u64,
    ) -> Result<usize, SdkError> {
        if self.authority.is_none() {
            return Err(SdkError::Configuration(
                "ownership renewal requires an authority-discovered cluster".into(),
            ));
        }
        let agent_ids: Vec<String> = self.owners.keys().cloned().collect();
        for agent_id in &agent_ids {
            self.renew_agent_ownership(agent_id, ttl_seconds).await?;
        }
        Ok(agent_ids.len())
    }

    /// Drive one turn for an agent, routed to its owning node.
    pub async fn send_message(
        &mut self,
        agent_id: &str,
        message: impl Into<String>,
    ) -> Result<MessageResult, SdkError> {
        let idx = self.owner_index(agent_id)?;
        match self.current_mutation_proof(agent_id).await? {
            Some(proof) => {
                self.nodes[idx]
                    .client
                    .send_message_fenced(agent_id, proof, message)
                    .await
            }
            None => self.nodes[idx].client.send_message(agent_id, message).await,
        }
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
        match self.current_mutation_proof(agent_id).await? {
            Some(proof) => {
                self.nodes[idx]
                    .client
                    .send_message_stream_fenced(request_id, agent_id, proof, message, on_event)
                    .await
            }
            None => {
                self.nodes[idx]
                    .client
                    .send_message_stream(request_id, agent_id, message, on_event)
                    .await
            }
        }
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
        match self.current_mutation_proof(agent_id).await? {
            Some(proof) => {
                self.nodes[idx]
                    .client
                    .cancel_request_fenced(request_id, agent_id, proof)
                    .await
            }
            None => {
                self.nodes[idx]
                    .client
                    .cancel_request(request_id, agent_id)
                    .await
            }
        }
    }

    /// Invoke a tool as an agent, routed to its owning node (gate-enforced there).
    pub async fn call_tool(
        &mut self,
        agent_id: &str,
        tool: impl Into<String>,
        args: serde_json::Value,
    ) -> Result<serde_json::Value, SdkError> {
        let idx = self.owner_index(agent_id)?;
        match self.current_mutation_proof(agent_id).await? {
            Some(proof) => {
                self.nodes[idx]
                    .client
                    .call_tool_fenced(agent_id, proof, tool, args)
                    .await
            }
            None => self.nodes[idx].client.call_tool(agent_id, tool, args).await,
        }
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

    fn validate_membership(&self, snapshot: &ClusterMembershipSnapshot) -> Result<(), SdkError> {
        let active: HashMap<&str, &ClusterMember> = snapshot
            .members
            .iter()
            .filter(|member| member.state == ClusterMemberState::Active)
            .map(|member| (member.node_id.as_str(), member))
            .collect();
        if self.nodes.len() != active.len() {
            return Err(membership_conflict(
                format!(
                    "authority advertised {} active nodes but {} connected",
                    active.len(),
                    self.nodes.len()
                ),
                false,
            ));
        }
        for node in &self.nodes {
            let Some(member) = active.get(node.id.as_str()) else {
                return Err(membership_conflict(
                    format!(
                        "node {} is not active in authority generation {}",
                        node.id, snapshot.generation
                    ),
                    false,
                ));
            };
            if node.fingerprint.as_deref() != Some(member.fingerprint.as_str())
                || node.address != member.endpoint
            {
                return Err(membership_conflict(
                    format!(
                        "node {} does not match its authorized identity and endpoint",
                        node.id
                    ),
                    false,
                ));
            }
        }
        Ok(())
    }
}

fn active_member_endpoints(snapshot: &ClusterMembershipSnapshot) -> Result<Vec<String>, SdkError> {
    let endpoints: Vec<String> = snapshot
        .members
        .iter()
        .filter(|member| member.state == ClusterMemberState::Active)
        .map(|member| member.endpoint.clone())
        .collect();
    if endpoints.is_empty() {
        return Err(SdkError::Wire {
            code: WireErrorCode::Unavailable,
            message: "cluster authority has no active members".into(),
            retryable: true,
        });
    }
    Ok(endpoints)
}

fn ensure_unchanged_membership(
    initial: &ClusterMembershipSnapshot,
    confirmed: &ClusterMembershipSnapshot,
) -> Result<(), SdkError> {
    if initial.cluster_id != confirmed.cluster_id
        || initial.generation != confirmed.generation
        || initial.members != confirmed.members
    {
        return Err(membership_conflict(
            "cluster membership changed during discovery; retry from a fresh snapshot",
            true,
        ));
    }
    Ok(())
}

fn membership_conflict(message: impl Into<String>, retryable: bool) -> SdkError {
    SdkError::Wire {
        code: WireErrorCode::Conflict,
        message: message.into(),
        retryable,
    }
}

fn route_conflict(message: impl Into<String>) -> SdkError {
    membership_conflict(message, true)
}

fn route_publication_error(agent_id: &str, stage: &'static str, source: SdkError) -> SdkError {
    SdkError::ClusterRoutePublication {
        agent_id: agent_id.to_string(),
        stage,
        source: Box::new(source),
    }
}

fn validate_active_ownership(
    agent_id: &str,
    expected_owner: &str,
    ownership: &ClusterAgentOwnership,
) -> Result<(), SdkError> {
    if ownership.agent_id != agent_id
        || ownership.owner_node_id != expected_owner
        || ownership.state != ClusterOwnershipState::Active
    {
        return Err(route_conflict(format!(
            "authority ownership for agent {agent_id} does not match routed node {expected_owner}"
        )));
    }
    Ok(())
}

fn ownership_proof(cluster_id: &str, ownership: &ClusterAgentOwnership) -> AgentMutationFenceProof {
    AgentMutationFenceProof {
        cluster_id: cluster_id.to_string(),
        owner_node_id: ownership.owner_node_id.clone(),
        authority_generation: ownership.generation,
        fencing_token: ownership.fencing_token,
    }
}

fn destination_fence_matches(
    agent_id: &str,
    proof: &AgentMutationFenceProof,
    fence: &AgentMutationFence,
) -> bool {
    fence.agent_id == agent_id
        && fence.cluster_id == proof.cluster_id
        && fence.owner_node_id == proof.owner_node_id
        && fence.authority_generation == proof.authority_generation
        && fence.fencing_token == proof.fencing_token
        && fence.state == AgentMutationFenceState::Active
}

fn validate_destination_fence(
    agent_id: &str,
    proof: &AgentMutationFenceProof,
    fence: &AgentMutationFence,
) -> Result<(), SdkError> {
    if destination_fence_matches(agent_id, proof, fence) {
        Ok(())
    } else {
        Err(route_conflict(format!(
            "destination mutation fence does not match authority ownership for agent {agent_id}"
        )))
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
