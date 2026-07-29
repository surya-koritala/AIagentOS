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

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    sync::{Arc, Mutex},
    time::Duration,
};

use crate::{
    AgentMutationFence, AgentMutationFenceProof, AgentMutationFenceState, AgentSummary,
    ClusterAgentOwnership, ClusterMember, ClusterMemberRegistration, ClusterMemberState,
    ClusterMembershipSnapshot, ClusterOwnershipState, KernelClient, MessageResult,
    MessageStreamEvent, NodeAvailability, NodeLoad, ReservedAgentIdentity, SdkError, WireErrorCode,
};

/// Initial authority lease used when a discovered cluster places an agent.
///
/// Long-lived clients must renew before this authority-clock deadline, either
/// explicitly or through an opt-in maintenance constructor.
pub const DEFAULT_OWNERSHIP_LEASE_SECONDS: u64 = 30;
pub const DEFAULT_OWNERSHIP_RENEW_INTERVAL: Duration = Duration::from_secs(10);

/// One kernel node in the cluster: its stable id, transport address, and client.
pub struct NodeHandle {
    id: String,
    address: String,
    fingerprint: Option<String>,
    tls_server_certificate_fingerprint: Option<String>,
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
    /// SHA-256 of the TLS server leaf certificate verified for this connection.
    pub fn tls_server_certificate_fingerprint(&self) -> Option<&str> {
        self.tls_server_certificate_fingerprint.as_deref()
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

/// Result of rebuilding managed routes from durable authority, destination,
/// and local-agent evidence.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClusterReconciliationReport {
    pub published_routes: usize,
    pub recovered_expired_leases: usize,
    pub released_expired_reservations: usize,
    pub pending_reservations: usize,
}

/// Automatic managed-route renewal policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClusterMaintenanceConfig {
    pub lease_ttl_seconds: u64,
    pub renew_interval: Duration,
}

impl Default for ClusterMaintenanceConfig {
    fn default() -> Self {
        Self {
            lease_ttl_seconds: DEFAULT_OWNERSHIP_LEASE_SECONDS,
            renew_interval: DEFAULT_OWNERSHIP_RENEW_INTERVAL,
        }
    }
}

/// Bounded, non-secret health for the automatic managed-route worker.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClusterMaintenanceStatus {
    pub running: bool,
    pub tracked_routes: usize,
    pub successful_cycles: u64,
    pub failed_cycles: u64,
    pub successful_renewals: u64,
    pub failed_renewals: u64,
    pub consecutive_failed_cycles: u64,
    pub last_error: Option<String>,
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
    lease_ttl_seconds: u64,
    maintenance: Option<AutomaticMaintenance>,
}

struct AutomaticMaintenance {
    routes: Arc<Mutex<HashMap<String, MaintainedRoute>>>,
    status: Arc<Mutex<ClusterMaintenanceStatus>>,
    task: tokio::task::JoinHandle<()>,
}

#[derive(Clone)]
enum MaintenanceConnector {
    Plaintext {
        authority_address: String,
        token: String,
    },
    Tls {
        authority_address: String,
        server_name: String,
        config: Arc<rustls::ClientConfig>,
        token: String,
    },
}

#[derive(Clone)]
struct MaintainedRoute {
    agent_id: String,
    node_id: String,
    node_address: String,
    proof: AgentMutationFenceProof,
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
            tls_server_certificate_fingerprint: node
                .tls_peer_certificate_fingerprint()
                .map(str::to_string),
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

    /// Stage a replacement application-listener certificate while connected
    /// to the node through its currently authorized leaf.
    ///
    /// After this succeeds, reconnect to the candidate leaf and call
    /// [`Self::admit_node`] with the returned member generation to activate it.
    #[allow(clippy::too_many_arguments)]
    pub async fn prepare_node_certificate_rollout(
        authority: &mut KernelClient,
        node: &mut KernelClient,
        endpoint: impl Into<String>,
        next_tls_server_certificate_fingerprint: impl Into<String>,
        expected_generation: u64,
        prepare_ttl_seconds: u64,
        minimum_overlap_seconds: u64,
        reason: impl Into<String>,
    ) -> Result<(ClusterMember, crate::ClusterCertificateRollout), SdkError> {
        let challenge = authority.issue_cluster_join_challenge(30).await?;
        let load = node.node_info().await?;
        let control = load.control.ok_or_else(|| {
            SdkError::Kernel("certificate rollout requires durable node identity support".into())
        })?;
        let protocol = node.hello().await?;
        let registration = ClusterMemberRegistration {
            node_id: control.identity.node_id,
            fingerprint: control.identity.fingerprint,
            public_key: control.identity.public_key,
            tls_server_certificate_fingerprint: Some(
                next_tls_server_certificate_fingerprint.into(),
            ),
            endpoint: endpoint.into(),
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
                message: "node identity changed while preparing certificate rollout".into(),
                retryable: false,
            });
        }
        authority
            .prepare_cluster_member_certificate_rollout(
                registration,
                challenge.challenge_hex,
                proof.signature_hex,
                expected_generation,
                prepare_ttl_seconds,
                minimum_overlap_seconds,
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
        cluster.validate_membership(&confirmed)?;
        cluster.authority = Some(ClusterAuthority {
            client: authority,
            cluster_id: confirmed.cluster_id,
            lease_ttl_seconds: DEFAULT_OWNERSHIP_LEASE_SECONDS,
            maintenance: None,
        });
        cluster.rebuild_owners().await?;
        Ok(cluster)
    }

    /// Discover an authenticated cluster and explicitly opt into automatic
    /// idle lease renewal and destination-fence maintenance.
    pub async fn connect_discovered_authenticated_with_maintenance(
        authority_addr: impl AsRef<str>,
        token: impl Into<String>,
        maintenance: ClusterMaintenanceConfig,
    ) -> Result<Self, SdkError> {
        validate_maintenance_config(&maintenance)?;
        let authority_address = authority_addr.as_ref().to_string();
        let token = token.into();
        let connector = MaintenanceConnector::Plaintext {
            authority_address: authority_address.clone(),
            token: token.clone(),
        };
        let mut cluster = Self::connect_discovered_authenticated(&authority_address, token).await?;
        cluster
            .authority
            .as_mut()
            .expect("discovered cluster retains authority")
            .lease_ttl_seconds = maintenance.lease_ttl_seconds;
        cluster.start_automatic_maintenance(connector, maintenance)?;
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
        cluster.validate_membership(&confirmed)?;
        cluster.authority = Some(ClusterAuthority {
            client: authority,
            cluster_id: confirmed.cluster_id,
            lease_ttl_seconds: DEFAULT_OWNERSHIP_LEASE_SECONDS,
            maintenance: None,
        });
        cluster.rebuild_owners().await?;
        Ok(cluster)
    }

    /// TLS/mTLS discovery with explicit automatic idle lease and destination
    /// fence maintenance.
    pub async fn connect_discovered_tls_authenticated_with_maintenance(
        authority_addr: impl AsRef<str>,
        server_name: impl Into<String>,
        config: rustls::ClientConfig,
        token: impl Into<String>,
        maintenance: ClusterMaintenanceConfig,
    ) -> Result<Self, SdkError> {
        validate_maintenance_config(&maintenance)?;
        let authority_address = authority_addr.as_ref().to_string();
        let server_name = server_name.into();
        let token = token.into();
        let connector = MaintenanceConnector::Tls {
            authority_address: authority_address.clone(),
            server_name: server_name.clone(),
            config: Arc::new(config.clone()),
            token: token.clone(),
        };
        let mut cluster = Self::connect_discovered_tls_authenticated(
            &authority_address,
            server_name,
            config,
            token,
        )
        .await?;
        cluster
            .authority
            .as_mut()
            .expect("discovered cluster retains authority")
            .lease_ttl_seconds = maintenance.lease_ttl_seconds;
        cluster.start_automatic_maintenance(connector, maintenance)?;
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
            let tls_server_certificate_fingerprint = client
                .tls_peer_certificate_fingerprint()
                .map(str::to_string);
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
                tls_server_certificate_fingerprint,
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

    /// Snapshot automatic maintenance health, when the caller explicitly
    /// enabled it at discovery time.
    pub fn maintenance_status(&self) -> Option<ClusterMaintenanceStatus> {
        let maintenance = self.authority.as_ref()?.maintenance.as_ref()?;
        Some(
            maintenance
                .status
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone(),
        )
    }

    fn start_automatic_maintenance(
        &mut self,
        connector: MaintenanceConnector,
        config: ClusterMaintenanceConfig,
    ) -> Result<(), SdkError> {
        validate_maintenance_config(&config)?;
        let routes: HashMap<String, MaintainedRoute> = self
            .maintained_routes()
            .into_iter()
            .map(|route| (route.agent_id.clone(), route))
            .collect();
        let status = Arc::new(Mutex::new(ClusterMaintenanceStatus {
            running: true,
            tracked_routes: routes.len(),
            ..ClusterMaintenanceStatus::default()
        }));
        let routes = Arc::new(Mutex::new(routes));
        let worker_status = Arc::clone(&status);
        let worker_routes = Arc::clone(&routes);
        let cluster_id = self
            .authority
            .as_ref()
            .expect("automatic maintenance requires authority")
            .cluster_id
            .clone();
        let task = tokio::spawn(automatic_maintenance_loop(
            connector,
            cluster_id,
            config,
            worker_routes,
            worker_status,
        ));
        self.authority
            .as_mut()
            .expect("automatic maintenance requires authority")
            .maintenance = Some(AutomaticMaintenance {
            routes,
            status,
            task,
        });
        Ok(())
    }

    fn maintained_routes(&self) -> Vec<MaintainedRoute> {
        self.owners
            .iter()
            .filter_map(|(agent_id, index)| {
                self.ownership_proofs
                    .get(agent_id)
                    .map(|proof| MaintainedRoute {
                        agent_id: agent_id.clone(),
                        node_id: self.nodes[*index].id.clone(),
                        node_address: self.nodes[*index].address.clone(),
                        proof: proof.clone(),
                    })
            })
            .collect()
    }

    fn track_maintenance_route(&self, agent_id: &str) {
        let Some(index) = self.owners.get(agent_id).copied() else {
            return;
        };
        let Some(proof) = self.ownership_proofs.get(agent_id).cloned() else {
            return;
        };
        if let Some(maintenance) = self
            .authority
            .as_ref()
            .and_then(|authority| authority.maintenance.as_ref())
        {
            let mut routes = maintenance
                .routes
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            routes.insert(
                agent_id.to_string(),
                MaintainedRoute {
                    agent_id: agent_id.to_string(),
                    node_id: self.nodes[index].id.clone(),
                    node_address: self.nodes[index].address.clone(),
                    proof,
                },
            );
            maintenance
                .status
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .tracked_routes = routes.len();
        }
    }

    fn replace_maintenance_routes(&self) {
        if let Some(maintenance) = self
            .authority
            .as_ref()
            .and_then(|authority| authority.maintenance.as_ref())
        {
            let replacements = self
                .maintained_routes()
                .into_iter()
                .map(|route| (route.agent_id.clone(), route))
                .collect::<HashMap<_, _>>();
            let route_count = replacements.len();
            *maintenance
                .routes
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()) = replacements;
            maintenance
                .status
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .tracked_routes = route_count;
        }
    }

    fn untrack_maintenance_route(&self, agent_id: &str) {
        if let Some(maintenance) = self
            .authority
            .as_ref()
            .and_then(|authority| authority.maintenance.as_ref())
        {
            let mut routes = maintenance
                .routes
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            routes.remove(agent_id);
            maintenance
                .status
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .tracked_routes = routes.len();
        }
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
        let agent_id = if let Some(authority) = self.authority.as_mut() {
            let agent_id = uuid::Uuid::new_v4().to_string();
            let ownership = authority
                .client
                .claim_cluster_agent_ownership(
                    &agent_id,
                    &node_id,
                    authority.lease_ttl_seconds,
                    None,
                    "cluster client pre-creation reservation",
                )
                .await
                .map_err(|source| {
                    route_publication_error(&agent_id, "authority ownership claim", source)
                })?;
            let proof = ownership_proof(&authority.cluster_id, &ownership);
            let reservation_fence = self.nodes[idx]
                .client
                .install_agent_mutation_fence(
                    &agent_id,
                    &proof.cluster_id,
                    &proof.owner_node_id,
                    proof.authority_term,
                    proof.authority_generation,
                    proof.fencing_token,
                    proof.proof_expires_at,
                    "cluster client pre-creation reservation",
                )
                .await
                .map_err(|source| {
                    route_publication_error(
                        &agent_id,
                        "destination reservation fence installation",
                        source,
                    )
                })?;
            validate_destination_fence(&agent_id, &proof, &reservation_fence).map_err(
                |source| {
                    route_publication_error(
                        &agent_id,
                        "destination reservation fence verification",
                        source,
                    )
                },
            )?;
            let created_agent_id = self.nodes[idx]
                .client
                .create_agent_with_id(
                    ReservedAgentIdentity {
                        agent_id: agent_id.clone(),
                        ownership_proof: proof.clone(),
                    },
                    name,
                    task,
                    provider,
                    profile,
                    priority,
                )
                .await
                .map_err(|source| {
                    route_publication_error(&agent_id, "destination agent creation", source)
                })?;
            if created_agent_id != agent_id {
                return Err(route_publication_error(
                    &agent_id,
                    "destination agent identity verification",
                    route_conflict(format!(
                        "destination {} created unexpected agent {created_agent_id}",
                        self.nodes[idx].id
                    )),
                ));
            }
            self.ownership_proofs.insert(agent_id.clone(), proof);
            agent_id
        } else {
            self.nodes[idx]
                .client
                .create_agent(name, task, provider, profile, priority)
                .await?
        };
        self.owners.insert(agent_id.clone(), idx);
        self.track_maintenance_route(&agent_id);
        Ok(PlacedAgent { agent_id, node_id })
    }

    /// The node id that owns an agent created through this cluster, if known.
    pub fn owner_of(&self, agent_id: &str) -> Option<&str> {
        self.owners
            .get(agent_id)
            .map(|&i| self.nodes[i].id.as_str())
    }

    /// Reconcile managed routes from the authority directory and exact local
    /// node state.
    ///
    /// An unexpired pre-creation reservation is left pending so a concurrent
    /// creator cannot be raced. Once that reservation expires, absence of the
    /// exact agent on every node proves that it can be released. An expired
    /// lease with the exact agent on its recorded owner is recovered with the
    /// previous token, producing a strictly newer fence.
    pub async fn reconcile_routes(&mut self) -> Result<ClusterReconciliationReport, SdkError> {
        if self.authority.is_none() {
            return Err(SdkError::Configuration(
                "route reconciliation requires an authority-discovered cluster".into(),
            ));
        }
        self.owners.clear();
        self.ownership_proofs.clear();

        let mut local_agents: HashMap<String, usize> = HashMap::new();
        for index in 0..self.nodes.len() {
            for agent in self.nodes[index].client.list_agents().await? {
                if let Some(previous) = local_agents.insert(agent.id.clone(), index) {
                    return Err(route_conflict(format!(
                        "duplicate agent ownership for {} on nodes {} and {}",
                        agent.id, self.nodes[previous].id, self.nodes[index].id
                    )));
                }
            }
        }

        let ownerships = self.ownership_directory().await?;
        let directory_ids: HashSet<String> = ownerships
            .iter()
            .map(|ownership| ownership.agent_id.clone())
            .collect();
        let mut rebuilt = HashMap::new();
        let mut rebuilt_proofs = HashMap::new();
        let mut report = ClusterReconciliationReport::default();

        for listed in ownerships {
            let local_index = local_agents.get(&listed.agent_id).copied();
            if listed.state == ClusterOwnershipState::Released {
                if local_index.is_some() {
                    return Err(route_conflict(format!(
                        "local agent {} has a released authority ownership tombstone",
                        listed.agent_id
                    )));
                }
                continue;
            }

            let Some(index) = local_index else {
                if listed.reason != "cluster client pre-creation reservation" {
                    return Err(route_conflict(format!(
                        "authority owns agent {} but no cluster node contains it",
                        listed.agent_id
                    )));
                }
                let active_result = self
                    .authority
                    .as_mut()
                    .expect("managed reconciliation retains authority")
                    .client
                    .active_cluster_agent_ownership(&listed.agent_id)
                    .await;
                match active_result {
                    Ok(active) => {
                        validate_active_ownership(
                            &listed.agent_id,
                            &listed.owner_node_id,
                            &active,
                        )?;
                        report.pending_reservations += 1;
                    }
                    Err(error) if error.wire_code() == Some(WireErrorCode::Conflict) => {
                        let destination_index = self
                            .nodes
                            .iter()
                            .position(|node| node.id == listed.owner_node_id)
                            .ok_or_else(|| {
                                route_conflict(format!(
                                    "reservation {} names an unavailable destination {}",
                                    listed.agent_id, listed.owner_node_id
                                ))
                            })?;
                        let (recovered, cluster_id) = {
                            let authority = self
                                .authority
                                .as_mut()
                                .expect("managed reconciliation retains authority");
                            let current = authority
                                .client
                                .cluster_agent_ownership(&listed.agent_id)
                                .await?
                                .ok_or_else(|| {
                                    route_conflict(format!(
                                        "ownership {} disappeared during reconciliation",
                                        listed.agent_id
                                    ))
                                })?;
                            if current.state == ClusterOwnershipState::Released {
                                continue;
                            }
                            if current.owner_node_id != listed.owner_node_id
                                || current.fencing_token != listed.fencing_token
                                || current.reason != "cluster client pre-creation reservation"
                            {
                                return Err(route_conflict(format!(
                                    "ownership {} changed while reconciling a reservation",
                                    listed.agent_id
                                )));
                            }
                            let recovered = authority
                                .client
                                .claim_cluster_agent_ownership(
                                    &current.agent_id,
                                    &current.owner_node_id,
                                    authority.lease_ttl_seconds,
                                    Some(current.fencing_token),
                                    "cluster client pre-creation reservation",
                                )
                                .await?;
                            (recovered, authority.cluster_id.clone())
                        };
                        let proof = ownership_proof(&cluster_id, &recovered);
                        let fence = self.nodes[destination_index]
                            .client
                            .install_agent_mutation_fence(
                                &recovered.agent_id,
                                &proof.cluster_id,
                                &proof.owner_node_id,
                                proof.authority_term,
                                proof.authority_generation,
                                proof.fencing_token,
                                proof.proof_expires_at,
                                "fence expired incomplete cluster creation",
                            )
                            .await?;
                        validate_destination_fence(&recovered.agent_id, &proof, &fence)?;
                        let appeared = self.nodes[destination_index]
                            .client
                            .list_agents()
                            .await?
                            .iter()
                            .any(|agent| agent.id == recovered.agent_id);
                        if appeared {
                            rebuilt.insert(recovered.agent_id.clone(), destination_index);
                            rebuilt_proofs.insert(recovered.agent_id, proof);
                            report.recovered_expired_leases += 1;
                            report.published_routes += 1;
                        } else {
                            self.nodes[destination_index]
                                .client
                                .retire_agent_mutation_fence(
                                    &recovered.agent_id,
                                    &proof.cluster_id,
                                    &proof.owner_node_id,
                                    proof.authority_term,
                                    proof.authority_generation,
                                    proof.fencing_token,
                                    proof.proof_expires_at,
                                    "retire expired incomplete cluster creation",
                                )
                                .await?;
                            self.authority
                                .as_mut()
                                .expect("managed reconciliation retains authority")
                                .client
                                .release_cluster_agent_ownership(
                                    &recovered.agent_id,
                                    &recovered.owner_node_id,
                                    recovered.fencing_token,
                                    "release expired incomplete cluster creation",
                                )
                                .await?;
                            report.released_expired_reservations += 1;
                        }
                    }
                    Err(error) => return Err(error),
                }
                continue;
            };

            if self.nodes[index].id != listed.owner_node_id {
                return Err(route_conflict(format!(
                    "authority routes agent {} to {} but durable local state is on {}",
                    listed.agent_id, listed.owner_node_id, self.nodes[index].id
                )));
            }
            let authority = self
                .authority
                .as_mut()
                .expect("managed reconciliation retains authority");
            let (active, recovered) = active_or_recover_ownership(
                &mut authority.client,
                &listed,
                &self.nodes[index].id,
                authority.lease_ttl_seconds,
            )
            .await?;
            if recovered {
                report.recovered_expired_leases += 1;
            }
            let proof = ownership_proof(&authority.cluster_id, &active);
            let current_fence = self.nodes[index]
                .client
                .agent_mutation_fence(&listed.agent_id)
                .await?;
            match current_fence {
                Some(fence) if destination_fence_matches(&listed.agent_id, &proof, &fence) => {}
                Some(fence)
                    if fence.fencing_token > proof.fencing_token
                        || (fence.fencing_token == proof.fencing_token
                            && fence.authority_generation > proof.authority_generation) =>
                {
                    return Err(route_conflict(format!(
                        "destination {} has newer ownership evidence for agent {}",
                        self.nodes[index].id, listed.agent_id
                    )));
                }
                _ => {
                    let installed = self.nodes[index]
                        .client
                        .install_agent_mutation_fence(
                            &listed.agent_id,
                            &proof.cluster_id,
                            &proof.owner_node_id,
                            proof.authority_term,
                            proof.authority_generation,
                            proof.fencing_token,
                            proof.proof_expires_at,
                            "cluster client durable reconciliation",
                        )
                        .await?;
                    validate_destination_fence(&listed.agent_id, &proof, &installed)?;
                }
            }
            rebuilt.insert(listed.agent_id.clone(), index);
            rebuilt_proofs.insert(listed.agent_id, proof);
            report.published_routes += 1;
        }

        if let Some(agent_id) = local_agents
            .keys()
            .find(|agent_id| !directory_ids.contains(*agent_id))
        {
            return Err(route_conflict(format!(
                "local agent {agent_id} has no durable authority ownership record"
            )));
        }
        self.owners = rebuilt;
        self.ownership_proofs = rebuilt_proofs;
        self.replace_maintenance_routes();
        Ok(report)
    }

    async fn ownership_directory(&mut self) -> Result<Vec<ClusterAgentOwnership>, SdkError> {
        let authority = self
            .authority
            .as_mut()
            .expect("ownership directory requires managed authority");
        let mut ownerships = Vec::new();
        let mut after_agent_id = None;
        loop {
            let page = authority
                .client
                .cluster_agent_ownerships(after_agent_id.clone(), 1_000)
                .await?;
            if page.is_empty() {
                break;
            }
            if let Some(previous) = after_agent_id.as_deref() {
                if page
                    .first()
                    .is_some_and(|ownership| ownership.agent_id.as_str() <= previous)
                {
                    return Err(route_conflict(
                        "authority ownership directory did not advance its page cursor",
                    ));
                }
            }
            after_agent_id = page.last().map(|ownership| ownership.agent_id.clone());
            let full_page = page.len() == 1_000;
            ownerships.extend(page);
            if !full_page {
                break;
            }
        }
        Ok(ownerships)
    }

    /// Rebuild routing from durable node state. Duplicate agent ownership is a
    /// split-brain conflict and fails closed instead of selecting one owner.
    pub async fn rebuild_owners(&mut self) -> Result<(), SdkError> {
        if self.authority.is_some() {
            self.reconcile_routes().await?;
            return Ok(());
        }
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

    async fn current_mutation_proof(
        &mut self,
        agent_id: &str,
    ) -> Result<Option<AgentMutationFenceProof>, SdkError> {
        let result = self.validated_mutation_proof(agent_id).await;
        if result.is_err() {
            self.owners.remove(agent_id);
            self.ownership_proofs.remove(agent_id);
            self.untrack_maintenance_route(agent_id);
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
                        proof.authority_term,
                        proof.authority_generation,
                        proof.fencing_token,
                        proof.proof_expires_at,
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
                proof.authority_term,
                proof.authority_generation,
                proof.fencing_token,
                proof.proof_expires_at,
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
        self.track_maintenance_route(agent_id);
        Ok(())
    }

    /// Renew and republish every currently routed managed agent.
    ///
    /// This remains available to clients without automatic maintenance and to
    /// callers that need an explicit renewal boundary. Any first failure is
    /// surfaced.
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
        let mut rollouts = HashMap::new();
        for rollout in &snapshot.certificate_rollouts {
            if rollouts.insert(rollout.node_id.as_str(), rollout).is_some() {
                return Err(membership_conflict(
                    format!(
                        "authority advertised duplicate certificate rollouts for node {}",
                        rollout.node_id
                    ),
                    false,
                ));
            }
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
            let tls_matches = tls_binding_is_authorized(
                node.tls_server_certificate_fingerprint.as_deref(),
                member.tls_server_certificate_fingerprint.as_deref(),
                rollouts.get(node.id.as_str()).copied(),
                snapshot.authority_time,
            );
            if node.fingerprint.as_deref() != Some(member.fingerprint.as_str())
                || !tls_matches
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

impl Drop for ClusterClient {
    fn drop(&mut self) {
        if let Some(maintenance) = self
            .authority
            .as_mut()
            .and_then(|authority| authority.maintenance.take())
        {
            maintenance.task.abort();
            maintenance
                .status
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .running = false;
        }
    }
}

impl MaintenanceConnector {
    fn authority_address(&self) -> &str {
        match self {
            Self::Plaintext {
                authority_address, ..
            }
            | Self::Tls {
                authority_address, ..
            } => authority_address,
        }
    }

    async fn connect(&self, address: &str) -> Result<KernelClient, SdkError> {
        match self {
            Self::Plaintext { token, .. } => {
                let mut client = KernelClient::connect(address).await?;
                client.authenticate(token).await?;
                Ok(client)
            }
            Self::Tls {
                server_name,
                config,
                token,
                ..
            } => {
                let mut client = KernelClient::connect_tls(
                    address,
                    server_name.clone(),
                    config.as_ref().clone(),
                )
                .await?;
                client.authenticate(token).await?;
                Ok(client)
            }
        }
    }
}

fn validate_maintenance_config(config: &ClusterMaintenanceConfig) -> Result<(), SdkError> {
    if !(5..=300).contains(&config.lease_ttl_seconds) {
        return Err(SdkError::Configuration(
            "cluster maintenance lease TTL must be between 5 and 300 seconds".into(),
        ));
    }
    if config.renew_interval.is_zero()
        || config
            .renew_interval
            .checked_mul(2)
            .is_none_or(|retry_window| retry_window > Duration::from_secs(config.lease_ttl_seconds))
    {
        return Err(SdkError::Configuration(
            "cluster maintenance renewal interval must be positive and leave at least one retry before lease expiry"
                .into(),
        ));
    }
    Ok(())
}

async fn automatic_maintenance_loop(
    connector: MaintenanceConnector,
    cluster_id: String,
    config: ClusterMaintenanceConfig,
    routes: Arc<Mutex<HashMap<String, MaintainedRoute>>>,
    status: Arc<Mutex<ClusterMaintenanceStatus>>,
) {
    let mut interval = tokio::time::interval(config.renew_interval);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // Tokio intervals tick immediately once. Consume that tick so every newly
    // created route gets its full initial lease before the first renewal.
    interval.tick().await;

    loop {
        interval.tick().await;
        let route_snapshot = routes
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .values()
            .cloned()
            .collect::<Vec<_>>();
        if route_snapshot.is_empty() {
            continue;
        }
        let mut successful_renewals = 0_u64;
        let mut failed_renewals = 0_u64;
        let mut last_error = None;
        match connector.connect(connector.authority_address()).await {
            Ok(mut authority) => {
                for route in &route_snapshot {
                    match maintain_route(
                        &connector,
                        &cluster_id,
                        &mut authority,
                        route,
                        config.lease_ttl_seconds,
                    )
                    .await
                    {
                        Ok(proof) => {
                            let mut current_routes = routes
                                .lock()
                                .unwrap_or_else(|poisoned| poisoned.into_inner());
                            if let Some(current) = current_routes.get_mut(&route.agent_id) {
                                if current.node_id == route.node_id
                                    && current.node_address == route.node_address
                                    && current.proof.cluster_id == proof.cluster_id
                                    && current.proof.owner_node_id == proof.owner_node_id
                                    && proof_is_at_least_as_new(&proof, &current.proof)
                                {
                                    current.proof = proof;
                                }
                            }
                            successful_renewals = successful_renewals.saturating_add(1);
                        }
                        Err(error) => {
                            failed_renewals = failed_renewals.saturating_add(1);
                            last_error = Some(format!(
                                "automatic maintenance failed for agent {} on node {}: {error}",
                                route.agent_id, route.node_id
                            ));
                        }
                    }
                }
            }
            Err(error) => {
                failed_renewals = u64::try_from(route_snapshot.len()).unwrap_or(u64::MAX);
                last_error = Some(format!(
                    "automatic maintenance could not connect to the authority: {error}"
                ));
            }
        }
        let tracked_routes = routes
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .len();
        let mut current = status
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        current.tracked_routes = tracked_routes;
        current.successful_renewals = current
            .successful_renewals
            .saturating_add(successful_renewals);
        current.failed_renewals = current.failed_renewals.saturating_add(failed_renewals);
        if failed_renewals == 0 {
            current.successful_cycles = current.successful_cycles.saturating_add(1);
            current.consecutive_failed_cycles = 0;
            current.last_error = None;
        } else {
            current.failed_cycles = current.failed_cycles.saturating_add(1);
            current.consecutive_failed_cycles = current.consecutive_failed_cycles.saturating_add(1);
            current.last_error = last_error;
        }
    }
}

fn proof_is_at_least_as_new(
    candidate: &AgentMutationFenceProof,
    current: &AgentMutationFenceProof,
) -> bool {
    candidate.authority_term > current.authority_term
        || (candidate.authority_term == current.authority_term
            && (candidate.fencing_token > current.fencing_token
                || (candidate.fencing_token == current.fencing_token
                    && candidate.authority_generation >= current.authority_generation)))
}

async fn maintain_route(
    connector: &MaintenanceConnector,
    cluster_id: &str,
    authority: &mut KernelClient,
    route: &MaintainedRoute,
    ttl_seconds: u64,
) -> Result<AgentMutationFenceProof, SdkError> {
    if route.proof.cluster_id != cluster_id || route.proof.owner_node_id != route.node_id {
        return Err(route_conflict(format!(
            "tracked proof for agent {} does not match maintenance cluster/node",
            route.agent_id
        )));
    }
    let active = authority
        .active_cluster_agent_ownership(&route.agent_id)
        .await?;
    validate_active_ownership(&route.agent_id, &route.node_id, &active)?;
    let renewed = authority
        .renew_cluster_agent_ownership(
            &route.agent_id,
            &route.node_id,
            active.fencing_token,
            ttl_seconds,
            "cluster client automatic lease maintenance",
        )
        .await?;
    validate_active_ownership(&route.agent_id, &route.node_id, &renewed)?;
    let proof = ownership_proof(cluster_id, &renewed);
    let mut destination = connector.connect(&route.node_address).await?;
    let fence = destination
        .install_agent_mutation_fence(
            &route.agent_id,
            &proof.cluster_id,
            &proof.owner_node_id,
            proof.authority_term,
            proof.authority_generation,
            proof.fencing_token,
            proof.proof_expires_at,
            "cluster client automatic lease maintenance",
        )
        .await?;
    validate_destination_fence(&route.agent_id, &proof, &fence)?;
    Ok(proof)
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
        || initial.tls_trust_generation != confirmed.tls_trust_generation
        || initial.certificate_rollouts != confirmed.certificate_rollouts
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

async fn active_or_recover_ownership(
    authority: &mut KernelClient,
    listed: &ClusterAgentOwnership,
    expected_owner: &str,
    ttl_seconds: u64,
) -> Result<(ClusterAgentOwnership, bool), SdkError> {
    match authority
        .active_cluster_agent_ownership(&listed.agent_id)
        .await
    {
        Ok(active) => {
            validate_active_ownership(&listed.agent_id, expected_owner, &active)?;
            Ok((active, false))
        }
        Err(error) if error.wire_code() == Some(WireErrorCode::Conflict) => {
            let current = authority
                .cluster_agent_ownership(&listed.agent_id)
                .await?
                .ok_or_else(|| {
                    route_conflict(format!(
                        "ownership {} disappeared during lease recovery",
                        listed.agent_id
                    ))
                })?;
            if current.state != ClusterOwnershipState::Active
                || current.owner_node_id != expected_owner
            {
                return Err(route_conflict(format!(
                    "ownership {} was released or transferred during lease recovery",
                    listed.agent_id
                )));
            }
            match authority
                .claim_cluster_agent_ownership(
                    &current.agent_id,
                    expected_owner,
                    ttl_seconds,
                    Some(current.fencing_token),
                    "cluster client expired lease recovery",
                )
                .await
            {
                Ok(recovered) => {
                    validate_active_ownership(&listed.agent_id, expected_owner, &recovered)?;
                    Ok((recovered, true))
                }
                Err(claim_error) if claim_error.wire_code() == Some(WireErrorCode::Conflict) => {
                    let active = authority
                        .active_cluster_agent_ownership(&listed.agent_id)
                        .await?;
                    validate_active_ownership(&listed.agent_id, expected_owner, &active)?;
                    Ok((active, false))
                }
                Err(claim_error) => Err(claim_error),
            }
        }
        Err(error) => Err(error),
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
        authority_term: ownership.authority_term,
        authority_generation: ownership.generation,
        fencing_token: ownership.fencing_token,
        proof_expires_at: ownership.lease_expires_at,
    }
}

fn tls_binding_is_authorized(
    observed: Option<&str>,
    current: Option<&str>,
    rollout: Option<&crate::ClusterCertificateRollout>,
    authority_time: Option<chrono::DateTime<chrono::Utc>>,
) -> bool {
    observed == current
        || observed.zip(rollout).zip(authority_time).is_some_and(
            |((fingerprint, rollout), authority_time)| {
                rollout.accepts_fingerprint(fingerprint, authority_time)
            },
        )
}

fn destination_fence_matches(
    agent_id: &str,
    proof: &AgentMutationFenceProof,
    fence: &AgentMutationFence,
) -> bool {
    fence.agent_id == agent_id
        && fence.cluster_id == proof.cluster_id
        && fence.owner_node_id == proof.owner_node_id
        && fence.authority_term == proof.authority_term
        && fence.authority_generation == proof.authority_generation
        && fence.fencing_token == proof.fencing_token
        && fence.proof_expires_at == proof.proof_expires_at
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ClusterCertificateRollout, ClusterCertificateRolloutPhase};

    #[test]
    fn discovery_uses_replicated_time_and_fails_closed_outside_rollout_windows() {
        let now = chrono::Utc::now();
        let old_tls = "a".repeat(64);
        let next_tls = "b".repeat(64);
        let mut rollout = ClusterCertificateRollout {
            node_id: uuid::Uuid::new_v4().to_string(),
            trust_generation: 1,
            member_generation: 2,
            phase: ClusterCertificateRolloutPhase::Prepared,
            previous_tls_server_certificate_fingerprint: old_tls.clone(),
            next_tls_server_certificate_fingerprint: next_tls.clone(),
            minimum_overlap_seconds: 5,
            prepare_expires_at: now + chrono::TimeDelta::seconds(5),
            retire_previous_after: None,
            prepared_at: now,
            updated_at: now,
            reason: "test".into(),
        };
        assert!(tls_binding_is_authorized(
            Some(&next_tls),
            Some(&old_tls),
            Some(&rollout),
            Some(now)
        ));
        assert!(!tls_binding_is_authorized(
            Some(&next_tls),
            Some(&old_tls),
            Some(&rollout),
            None
        ));
        assert!(!tls_binding_is_authorized(
            Some(&next_tls),
            Some(&old_tls),
            Some(&rollout),
            Some(rollout.prepare_expires_at)
        ));
        assert!(tls_binding_is_authorized(
            Some(&old_tls),
            Some(&old_tls),
            Some(&rollout),
            Some(rollout.prepare_expires_at)
        ));

        rollout.phase = ClusterCertificateRolloutPhase::Activated;
        rollout.member_generation = 3;
        rollout.retire_previous_after = Some(now + chrono::TimeDelta::seconds(10));
        assert!(tls_binding_is_authorized(
            Some(&old_tls),
            Some(&next_tls),
            Some(&rollout),
            Some(now + chrono::TimeDelta::seconds(9))
        ));
        assert!(!tls_binding_is_authorized(
            Some(&old_tls),
            Some(&next_tls),
            Some(&rollout),
            rollout.retire_previous_after
        ));
        assert!(tls_binding_is_authorized(
            Some(&next_tls),
            Some(&next_tls),
            Some(&rollout),
            rollout.retire_previous_after
        ));
    }
}
