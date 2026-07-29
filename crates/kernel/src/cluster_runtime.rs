//! Authenticated peer transport and executable OpenRaft runtime.
//!
//! Every Raft RPC uses a fresh bounded connection authenticated in both
//! directions by rustls. The wire envelope binds the durable cluster name,
//! source node, target node, and embedded OpenRaft vote identity. The exact
//! server and client leaf fingerprints must match the statically trusted
//! membership supplied when the runtime starts.
//!
//! This module deliberately does not route public membership or ownership
//! syscalls through Raft yet. It makes election, replication, restart, and
//! failover executable so the next integration stage can switch those public
//! authority commands without pretending that the existing single-writer
//! paths are already quorum-backed.

#![allow(clippy::result_large_err)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use openraft::error::{
    ClientWriteError, InitializeError, NetworkError, RPCError, RaftError, RemoteError, Timeout,
    Unreachable,
};
use openraft::network::{RPCOption, RPCTypes, RaftNetwork, RaftNetworkFactory};
use openraft::raft::{
    AppendEntriesRequest, AppendEntriesResponse, ClientWriteResponse, InstallSnapshotRequest,
    InstallSnapshotResponse, VoteRequest, VoteResponse,
};
use openraft::{Config as OpenRaftConfig, Raft, RaftMetrics};
use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer, ServerName};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{watch, Semaphore};
use tokio::task::{JoinHandle, JoinSet};
use tokio_rustls::{TlsAcceptor, TlsConnector};

use crate::cluster_consensus::{
    open_cluster_raft_storage, AuthorityCommand, ClusterRaftNode, ClusterRaftNodeId,
    ClusterRaftTypeConfig,
};
use crate::context::SqliteContextManager;

const CLUSTER_RAFT_WIRE_VERSION: u16 = 1;
const MIN_FRAME_BYTES: usize = 64 * 1024;
const DEFAULT_MAX_FRAME_BYTES: usize = 8 * 1024 * 1024;
const ABSOLUTE_MAX_FRAME_BYTES: usize = 64 * 1024 * 1024;
const DEFAULT_MAX_IN_FLIGHT: usize = 128;
const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
const DEFAULT_INBOUND_TIMEOUT: Duration = Duration::from_secs(15);

/// Server and client TLS identities used by one Raft peer.
///
/// The two identities may be distinct. `server_certificate_sha256` is checked
/// by outbound peers and `client_certificate_sha256` is checked by inbound
/// peers after the CA-backed mTLS handshake succeeds.
#[derive(Clone)]
pub struct ClusterRaftTls {
    server_config: Arc<rustls::ServerConfig>,
    client_config: Arc<rustls::ClientConfig>,
    server_certificate_sha256: String,
    client_certificate_sha256: String,
}

impl fmt::Debug for ClusterRaftTls {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClusterRaftTls")
            .field("server_certificate_sha256", &self.server_certificate_sha256)
            .field("client_certificate_sha256", &self.client_certificate_sha256)
            .finish_non_exhaustive()
    }
}

impl ClusterRaftTls {
    /// Build separate server-auth and client-auth identities from PEM.
    ///
    /// The server requires client certificates chaining to `peer_ca_pem`; the
    /// client presents `client_cert_pem` and trusts servers chaining to the same
    /// CA. Exact leaf fingerprints remain mandatory in addition to CA trust.
    pub fn from_pem(
        server_cert_pem: &[u8],
        server_key_pem: &[u8],
        client_cert_pem: &[u8],
        client_key_pem: &[u8],
        peer_ca_pem: &[u8],
    ) -> io::Result<Self> {
        let server_config = crate::syscall_server::server_config_from_pem_with_client_ca(
            server_cert_pem,
            server_key_pem,
            peer_ca_pem,
        )?;
        let (client_config, client_certificate_sha256) =
            client_config_from_pem(client_cert_pem, client_key_pem, peer_ca_pem)?;
        let server_certificate_sha256 = first_pem_certificate_fingerprint(server_cert_pem)?;
        Ok(Self {
            server_config: Arc::new(server_config),
            client_config: Arc::new(client_config),
            server_certificate_sha256,
            client_certificate_sha256,
        })
    }

    /// Construct from already validated rustls configs and exact fingerprints.
    ///
    /// This is primarily useful for atomic config reload controllers. The live
    /// runtime still verifies the fingerprints against durable membership.
    pub fn from_configs(
        server_config: rustls::ServerConfig,
        client_config: rustls::ClientConfig,
        server_certificate_sha256: String,
        client_certificate_sha256: String,
    ) -> io::Result<Self> {
        validate_sha256(&server_certificate_sha256, "server certificate")?;
        validate_sha256(&client_certificate_sha256, "client certificate")?;
        Ok(Self {
            server_config: Arc::new(server_config),
            client_config: Arc::new(client_config),
            server_certificate_sha256,
            client_certificate_sha256,
        })
    }

    pub fn server_certificate_sha256(&self) -> &str {
        &self.server_certificate_sha256
    }

    pub fn client_certificate_sha256(&self) -> &str {
        &self.client_certificate_sha256
    }
}

fn client_config_from_pem(
    cert_pem: &[u8],
    key_pem: &[u8],
    server_ca_pem: &[u8],
) -> io::Result<(rustls::ClientConfig, String)> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let certs = CertificateDer::pem_slice_iter(cert_pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(invalid_input)?;
    let leaf = certs.first().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "no certificates found in client cert PEM",
        )
    })?;
    let fingerprint = certificate_fingerprint(leaf.as_ref());
    let key = PrivateKeyDer::pem_slice_iter(key_pem)
        .next()
        .transpose()
        .map_err(invalid_input)?
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "no private key found in client key PEM",
            )
        })?;
    let ca_certs = CertificateDer::pem_slice_iter(server_ca_pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(invalid_input)?;
    if ca_certs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "no certificates found in server CA PEM",
        ));
    }
    let mut roots = rustls::RootCertStore::empty();
    for certificate in ca_certs {
        roots.add(certificate).map_err(invalid_input)?;
    }
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_client_auth_cert(certs, key)
        .map_err(invalid_input)?;
    Ok((config, fingerprint))
}

fn first_pem_certificate_fingerprint(cert_pem: &[u8]) -> io::Result<String> {
    let certificate = CertificateDer::pem_slice_iter(cert_pem)
        .next()
        .transpose()
        .map_err(invalid_input)?
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "no certificates found in server cert PEM",
            )
        })?;
    Ok(certificate_fingerprint(certificate.as_ref()))
}

fn invalid_input(error: impl fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, error.to_string())
}

fn certificate_fingerprint(certificate: &[u8]) -> String {
    ring::digest::digest(&ring::digest::SHA256, certificate)
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn validate_sha256(value: &str, label: &str) -> io::Result<()> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{label} fingerprint must be 64 lowercase hexadecimal characters"),
        ))
    }
}

/// Resource and timeout limits for the Raft peer transport.
#[derive(Debug, Clone)]
pub struct ClusterRaftTransportLimits {
    pub handshake_timeout: Duration,
    pub inbound_request_timeout: Duration,
    pub max_frame_bytes: usize,
    pub max_in_flight_connections: usize,
}

impl Default for ClusterRaftTransportLimits {
    fn default() -> Self {
        Self {
            handshake_timeout: DEFAULT_HANDSHAKE_TIMEOUT,
            inbound_request_timeout: DEFAULT_INBOUND_TIMEOUT,
            max_frame_bytes: DEFAULT_MAX_FRAME_BYTES,
            max_in_flight_connections: DEFAULT_MAX_IN_FLIGHT,
        }
    }
}

/// Complete configuration for one executable Raft node.
#[derive(Clone)]
pub struct ClusterRaftRuntimeConfig {
    pub node_id: ClusterRaftNodeId,
    pub listen_addr: SocketAddr,
    pub members: BTreeMap<ClusterRaftNodeId, ClusterRaftNode>,
    pub tls: ClusterRaftTls,
    pub raft: OpenRaftConfig,
    pub transport: ClusterRaftTransportLimits,
}

impl fmt::Debug for ClusterRaftRuntimeConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClusterRaftRuntimeConfig")
            .field("node_id", &self.node_id)
            .field("listen_addr", &self.listen_addr)
            .field("members", &self.members)
            .field("tls", &self.tls)
            .field("raft", &self.raft)
            .field("transport", &self.transport)
            .finish()
    }
}

impl ClusterRaftRuntimeConfig {
    pub fn validate(&self) -> io::Result<()> {
        if self.node_id == 0 {
            return Err(invalid_input("Raft node id 0 is reserved"));
        }
        if self.members.is_empty() || self.members.len() > 31 {
            return Err(invalid_input("Raft membership must contain 1 to 31 nodes"));
        }
        let local = self
            .members
            .get(&self.node_id)
            .ok_or_else(|| invalid_input("local Raft node is absent from membership"))?;
        if local.tls_certificate_sha256 != self.tls.server_certificate_sha256 {
            return Err(invalid_input(
                "local server certificate fingerprint does not match membership",
            ));
        }
        if local.tls_client_certificate_sha256 != self.tls.client_certificate_sha256 {
            return Err(invalid_input(
                "local client certificate fingerprint does not match membership",
            ));
        }
        if self.transport.handshake_timeout.is_zero()
            || self.transport.inbound_request_timeout.is_zero()
        {
            return Err(invalid_input("Raft transport timeouts must be non-zero"));
        }
        if !(MIN_FRAME_BYTES..=ABSOLUTE_MAX_FRAME_BYTES).contains(&self.transport.max_frame_bytes) {
            return Err(invalid_input(format!(
                "Raft max frame bytes must be between {MIN_FRAME_BYTES} and {ABSOLUTE_MAX_FRAME_BYTES}"
            )));
        }
        if self.transport.max_in_flight_connections == 0
            || self.transport.max_in_flight_connections > 16_384
        {
            return Err(invalid_input(
                "Raft max in-flight connections must be between 1 and 16384",
            ));
        }
        self.raft.clone().validate().map_err(invalid_input)?;
        if self.raft.cluster_name.trim().is_empty() || self.raft.cluster_name.len() > 128 {
            return Err(invalid_input(
                "Raft cluster name must contain 1 to 128 bytes",
            ));
        }

        let mut endpoints = BTreeSet::new();
        let mut server_fingerprints = BTreeSet::new();
        let mut client_fingerprints = BTreeSet::new();
        let mut certificate_owners = BTreeMap::new();
        let mut identity_keys = BTreeSet::new();
        for (node_id, node) in &self.members {
            if *node_id == 0 {
                return Err(invalid_input("Raft node id 0 is reserved"));
            }
            validate_endpoint(&node.endpoint)?;
            ServerName::try_from(node.server_name.clone()).map_err(invalid_input)?;
            validate_sha256(&node.tls_certificate_sha256, "server certificate")?;
            validate_sha256(&node.tls_client_certificate_sha256, "client certificate")?;
            if node.identity_public_key.is_empty() || node.identity_public_key.len() > 8_192 {
                return Err(invalid_input(
                    "Raft member identity public key must contain 1 to 8192 bytes",
                ));
            }
            if !endpoints.insert(node.endpoint.clone()) {
                return Err(invalid_input("duplicate Raft peer endpoint"));
            }
            if !server_fingerprints.insert(node.tls_certificate_sha256.clone()) {
                return Err(invalid_input(
                    "duplicate Raft peer server certificate fingerprint",
                ));
            }
            if !client_fingerprints.insert(node.tls_client_certificate_sha256.clone()) {
                return Err(invalid_input(
                    "duplicate Raft peer client certificate fingerprint",
                ));
            }
            for fingerprint in [
                &node.tls_certificate_sha256,
                &node.tls_client_certificate_sha256,
            ] {
                if certificate_owners
                    .insert(fingerprint.clone(), *node_id)
                    .is_some_and(|owner| owner != *node_id)
                {
                    return Err(invalid_input(
                        "Raft certificate fingerprint is assigned to multiple node identities",
                    ));
                }
            }
            if !identity_keys.insert(node.identity_public_key.clone()) {
                return Err(invalid_input("duplicate Raft peer identity public key"));
            }
        }
        Ok(())
    }
}

fn validate_endpoint(endpoint: &str) -> io::Result<()> {
    if endpoint.is_empty()
        || endpoint.len() > 512
        || endpoint.chars().any(char::is_whitespace)
        || endpoint.contains("://")
        || endpoint.contains('/')
    {
        return Err(invalid_input(
            "Raft endpoint must be a bounded host:port value without a URL scheme",
        ));
    }
    let (_, port) = endpoint
        .rsplit_once(':')
        .ok_or_else(|| invalid_input("Raft endpoint must include a port"))?;
    let port = port.parse::<u16>().map_err(invalid_input)?;
    if port == 0 {
        return Err(invalid_input(
            "Raft advertised endpoint port cannot be zero",
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RpcEnvelope {
    version: u16,
    cluster_name: String,
    source: ClusterRaftNodeId,
    target: ClusterRaftNodeId,
    body: RpcRequest,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
enum RpcRequest {
    AppendEntries(AppendEntriesRequest<ClusterRaftTypeConfig>),
    Vote(VoteRequest<ClusterRaftNodeId>),
    InstallSnapshot(InstallSnapshotRequest<ClusterRaftTypeConfig>),
}

#[derive(Debug, Serialize, Deserialize)]
struct RpcResponseEnvelope {
    version: u16,
    cluster_name: String,
    source: ClusterRaftNodeId,
    target: ClusterRaftNodeId,
    body: RpcResponse,
}

#[derive(Debug, Serialize, Deserialize)]
enum RpcResponse {
    AppendEntries(Result<AppendEntriesResponse<ClusterRaftNodeId>, RaftError<ClusterRaftNodeId>>),
    Vote(Result<VoteResponse<ClusterRaftNodeId>, RaftError<ClusterRaftNodeId>>),
    InstallSnapshot(
        Result<
            InstallSnapshotResponse<ClusterRaftNodeId>,
            RaftError<ClusterRaftNodeId, openraft::error::InstallSnapshotError>,
        >,
    ),
}

impl RpcRequest {
    fn rpc_type(&self) -> RPCTypes {
        match self {
            Self::AppendEntries(_) => RPCTypes::AppendEntries,
            Self::Vote(_) => RPCTypes::Vote,
            Self::InstallSnapshot(_) => RPCTypes::InstallSnapshot,
        }
    }

    fn embedded_sender(&self) -> Option<ClusterRaftNodeId> {
        match self {
            Self::AppendEntries(request) => request.vote.leader_id.voted_for(),
            Self::Vote(request) => request.vote.leader_id.voted_for(),
            Self::InstallSnapshot(request) => request.vote.leader_id.voted_for(),
        }
    }
}

#[derive(Clone)]
struct ClusterNetworkFactory {
    source: ClusterRaftNodeId,
    cluster_name: Arc<str>,
    members: Arc<BTreeMap<ClusterRaftNodeId, ClusterRaftNode>>,
    client_config: Arc<rustls::ClientConfig>,
    handshake_timeout: Duration,
    max_frame_bytes: usize,
}

struct ClusterNetwork {
    source: ClusterRaftNodeId,
    target: ClusterRaftNodeId,
    target_node: ClusterRaftNode,
    cluster_name: Arc<str>,
    client_config: Arc<rustls::ClientConfig>,
    handshake_timeout: Duration,
    max_frame_bytes: usize,
    invalid_target: Option<String>,
}

impl RaftNetworkFactory<ClusterRaftTypeConfig> for ClusterNetworkFactory {
    type Network = ClusterNetwork;

    async fn new_client(
        &mut self,
        target: ClusterRaftNodeId,
        node: &ClusterRaftNode,
    ) -> Self::Network {
        let invalid_target = match self.members.get(&target) {
            Some(trusted) if trusted == node => None,
            Some(_) => Some("OpenRaft membership differs from trusted peer configuration".into()),
            None => Some("OpenRaft target is absent from trusted peer configuration".into()),
        };
        ClusterNetwork {
            source: self.source,
            target,
            target_node: node.clone(),
            cluster_name: self.cluster_name.clone(),
            client_config: self.client_config.clone(),
            handshake_timeout: self.handshake_timeout,
            max_frame_bytes: self.max_frame_bytes,
            invalid_target,
        }
    }
}

impl ClusterNetwork {
    async fn call(&self, body: RpcRequest, option: RPCOption) -> Result<RpcResponse, RpcCallError> {
        if let Some(error) = &self.invalid_target {
            return Err(RpcCallError::Unreachable(error.clone()));
        }
        let action = body.rpc_type();
        let timeout = option.hard_ttl();
        let future = self.call_inner(body);
        match tokio::time::timeout(timeout, future).await {
            Ok(result) => result,
            Err(_) => Err(RpcCallError::Timeout(Timeout {
                action,
                id: self.source,
                target: self.target,
                timeout,
            })),
        }
    }

    async fn call_inner(&self, body: RpcRequest) -> Result<RpcResponse, RpcCallError> {
        let tcp = tokio::time::timeout(
            self.handshake_timeout,
            TcpStream::connect(self.target_node.endpoint.as_str()),
        )
        .await
        .map_err(|_| RpcCallError::Unreachable("TCP connect timed out".into()))?
        .map_err(|error| RpcCallError::Unreachable(redacted_io("TCP connect", &error)))?;
        let server_name =
            ServerName::try_from(self.target_node.server_name.clone()).map_err(|_| {
                RpcCallError::Unreachable("trusted peer has an invalid TLS server name".into())
            })?;
        let connector = TlsConnector::from(self.client_config.clone());
        let mut tls =
            tokio::time::timeout(self.handshake_timeout, connector.connect(server_name, tcp))
                .await
                .map_err(|_| RpcCallError::Unreachable("TLS handshake timed out".into()))?
                .map_err(|error| RpcCallError::Unreachable(redacted_io("TLS handshake", &error)))?;
        let peer_certificate = tls
            .get_ref()
            .1
            .peer_certificates()
            .and_then(|certificates| certificates.first())
            .ok_or_else(|| {
                RpcCallError::Unreachable("TLS peer did not present a certificate".into())
            })?;
        let actual_fingerprint = certificate_fingerprint(peer_certificate.as_ref());
        if actual_fingerprint != self.target_node.tls_certificate_sha256 {
            return Err(RpcCallError::Unreachable(
                "TLS server leaf does not match trusted Raft membership".into(),
            ));
        }
        let request = RpcEnvelope {
            version: CLUSTER_RAFT_WIRE_VERSION,
            cluster_name: self.cluster_name.to_string(),
            source: self.source,
            target: self.target,
            body,
        };
        write_frame(&mut tls, &request, self.max_frame_bytes)
            .await
            .map_err(|error| RpcCallError::Network(redacted_io("write request", &error)))?;
        let response: RpcResponseEnvelope = read_frame(&mut tls, self.max_frame_bytes)
            .await
            .map_err(|error| RpcCallError::Network(redacted_io("read response", &error)))?;
        if response.version != CLUSTER_RAFT_WIRE_VERSION
            || response.cluster_name != self.cluster_name.as_ref()
            || response.source != self.target
            || response.target != self.source
        {
            return Err(RpcCallError::Network(
                "Raft response envelope identity mismatch".into(),
            ));
        }
        Ok(response.body)
    }
}

enum RpcCallError {
    Timeout(Timeout<ClusterRaftNodeId>),
    Unreachable(String),
    Network(String),
}

fn redacted_io(operation: &str, error: &impl fmt::Display) -> String {
    format!("{operation} failed: {error}")
}

fn rpc_error<E>(error: RpcCallError) -> RPCError<ClusterRaftNodeId, ClusterRaftNode, E>
where
    E: std::error::Error,
{
    match error {
        RpcCallError::Timeout(timeout) => RPCError::Timeout(timeout),
        RpcCallError::Unreachable(message) => {
            let error = io::Error::new(io::ErrorKind::ConnectionRefused, message);
            RPCError::Unreachable(Unreachable::new(&error))
        }
        RpcCallError::Network(message) => {
            let error = io::Error::new(io::ErrorKind::ConnectionAborted, message);
            RPCError::Network(NetworkError::new(&error))
        }
    }
}

impl RaftNetwork<ClusterRaftTypeConfig> for ClusterNetwork {
    async fn append_entries(
        &mut self,
        rpc: AppendEntriesRequest<ClusterRaftTypeConfig>,
        option: RPCOption,
    ) -> Result<
        AppendEntriesResponse<ClusterRaftNodeId>,
        RPCError<ClusterRaftNodeId, ClusterRaftNode, RaftError<ClusterRaftNodeId>>,
    > {
        match self
            .call(RpcRequest::AppendEntries(rpc), option)
            .await
            .map_err(rpc_error)?
        {
            RpcResponse::AppendEntries(Ok(response)) => Ok(response),
            RpcResponse::AppendEntries(Err(error)) => Err(RPCError::RemoteError(RemoteError {
                target: self.target,
                target_node: Some(self.target_node.clone()),
                source: error,
            })),
            _ => Err(rpc_error(RpcCallError::Network(
                "Raft response type mismatch".into(),
            ))),
        }
    }

    async fn install_snapshot(
        &mut self,
        rpc: InstallSnapshotRequest<ClusterRaftTypeConfig>,
        option: RPCOption,
    ) -> Result<
        InstallSnapshotResponse<ClusterRaftNodeId>,
        RPCError<
            ClusterRaftNodeId,
            ClusterRaftNode,
            RaftError<ClusterRaftNodeId, openraft::error::InstallSnapshotError>,
        >,
    > {
        match self
            .call(RpcRequest::InstallSnapshot(rpc), option)
            .await
            .map_err(rpc_error)?
        {
            RpcResponse::InstallSnapshot(Ok(response)) => Ok(response),
            RpcResponse::InstallSnapshot(Err(error)) => Err(RPCError::RemoteError(RemoteError {
                target: self.target,
                target_node: Some(self.target_node.clone()),
                source: error,
            })),
            _ => Err(rpc_error(RpcCallError::Network(
                "Raft response type mismatch".into(),
            ))),
        }
    }

    async fn vote(
        &mut self,
        rpc: VoteRequest<ClusterRaftNodeId>,
        option: RPCOption,
    ) -> Result<
        VoteResponse<ClusterRaftNodeId>,
        RPCError<ClusterRaftNodeId, ClusterRaftNode, RaftError<ClusterRaftNodeId>>,
    > {
        match self
            .call(RpcRequest::Vote(rpc), option)
            .await
            .map_err(rpc_error)?
        {
            RpcResponse::Vote(Ok(response)) => Ok(response),
            RpcResponse::Vote(Err(error)) => Err(RPCError::RemoteError(RemoteError {
                target: self.target,
                target_node: Some(self.target_node.clone()),
                source: error,
            })),
            _ => Err(rpc_error(RpcCallError::Network(
                "Raft response type mismatch".into(),
            ))),
        }
    }
}

/// Live OpenRaft node plus its authenticated peer listener.
pub struct ClusterRaftRuntime {
    node_id: ClusterRaftNodeId,
    local_addr: SocketAddr,
    members: BTreeMap<ClusterRaftNodeId, ClusterRaftNode>,
    raft: Raft<ClusterRaftTypeConfig>,
    shutdown_tx: watch::Sender<bool>,
    listener_task: Option<JoinHandle<io::Result<()>>>,
}

impl fmt::Debug for ClusterRaftRuntime {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClusterRaftRuntime")
            .field("node_id", &self.node_id)
            .field("local_addr", &self.local_addr)
            .field("members", &self.members)
            .finish_non_exhaustive()
    }
}

impl ClusterRaftRuntime {
    /// Bind and start one authenticated Raft node.
    pub async fn start(
        context: Arc<SqliteContextManager>,
        config: ClusterRaftRuntimeConfig,
    ) -> io::Result<Self> {
        config.validate()?;
        let listener = TcpListener::bind(config.listen_addr).await?;
        Self::start_on_listener(context, config, listener).await
    }

    async fn start_on_listener(
        context: Arc<SqliteContextManager>,
        config: ClusterRaftRuntimeConfig,
        listener: TcpListener,
    ) -> io::Result<Self> {
        config.validate()?;
        let local_addr = listener.local_addr()?;
        let members = Arc::new(config.members.clone());
        let network = ClusterNetworkFactory {
            source: config.node_id,
            cluster_name: Arc::from(config.raft.cluster_name.as_str()),
            members: members.clone(),
            client_config: config.tls.client_config.clone(),
            handshake_timeout: config.transport.handshake_timeout,
            max_frame_bytes: config.transport.max_frame_bytes,
        };
        let (log_store, state_machine) = open_cluster_raft_storage(context).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("open durable Raft storage: {error}"),
            )
        })?;
        let raft_config = Arc::new(config.raft.clone().validate().map_err(invalid_input)?);
        let raft = Raft::new(
            config.node_id,
            raft_config,
            network,
            log_store,
            state_machine,
        )
        .await
        .map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("start OpenRaft node: {error}"),
            )
        })?;
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let listener_task = tokio::spawn(serve_listener(
            listener,
            ListenerContext {
                local_node_id: config.node_id,
                cluster_name: Arc::from(config.raft.cluster_name.as_str()),
                members,
                server_config: config.tls.server_config.clone(),
                raft: raft.clone(),
                limits: config.transport,
            },
            shutdown_rx,
        ));
        Ok(Self {
            node_id: config.node_id,
            local_addr,
            members: config.members,
            raft,
            shutdown_tx,
            listener_task: Some(listener_task),
        })
    }

    pub fn node_id(&self) -> ClusterRaftNodeId {
        self.node_id
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub fn metrics(&self) -> watch::Receiver<RaftMetrics<ClusterRaftNodeId, ClusterRaftNode>> {
        self.raft.metrics()
    }

    /// Explicitly initialize the cluster with the exact trusted node map.
    ///
    /// More than one pristine node may call this with the same map. Operators
    /// must never call it with a different map, because OpenRaft documents that
    /// as a split-brain bootstrap error.
    pub async fn initialize(
        &self,
    ) -> Result<(), RaftError<ClusterRaftNodeId, InitializeError<ClusterRaftNodeId, ClusterRaftNode>>>
    {
        self.raft.initialize(self.members.clone()).await
    }

    pub async fn commit(
        &self,
        command: AuthorityCommand,
    ) -> Result<
        ClientWriteResponse<ClusterRaftTypeConfig>,
        RaftError<ClusterRaftNodeId, ClientWriteError<ClusterRaftNodeId, ClusterRaftNode>>,
    > {
        self.raft.client_write(command).await
    }

    pub async fn shutdown(mut self) -> io::Result<()> {
        let _ = self.shutdown_tx.send(true);
        if let Some(task) = self.listener_task.take() {
            match task.await {
                Ok(result) => result?,
                Err(error) if error.is_cancelled() => {}
                Err(error) => {
                    return Err(io::Error::other(format!(
                        "Raft listener task failed: {error}"
                    )));
                }
            }
        }
        self.raft
            .shutdown()
            .await
            .map_err(|error| io::Error::other(format!("Raft shutdown failed: {error}")))
    }
}

impl Drop for ClusterRaftRuntime {
    fn drop(&mut self) {
        let _ = self.shutdown_tx.send(true);
        if let Some(task) = &self.listener_task {
            task.abort();
        }
    }
}

struct ListenerContext {
    local_node_id: ClusterRaftNodeId,
    cluster_name: Arc<str>,
    members: Arc<BTreeMap<ClusterRaftNodeId, ClusterRaftNode>>,
    server_config: Arc<rustls::ServerConfig>,
    raft: Raft<ClusterRaftTypeConfig>,
    limits: ClusterRaftTransportLimits,
}

async fn serve_listener(
    listener: TcpListener,
    context: ListenerContext,
    mut shutdown: watch::Receiver<bool>,
) -> io::Result<()> {
    let acceptor = TlsAcceptor::from(context.server_config.clone());
    let semaphore = Arc::new(Semaphore::new(context.limits.max_in_flight_connections));
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            accepted = listener.accept() => {
                let (stream, _) = accepted?;
                let Ok(permit) = semaphore.clone().try_acquire_owned() else {
                    tracing::warn!(node_id = context.local_node_id, "dropping Raft peer connection at concurrency limit");
                    drop(stream);
                    continue;
                };
                let acceptor = acceptor.clone();
                let cluster_name = context.cluster_name.clone();
                let members = context.members.clone();
                let raft = context.raft.clone();
                let limits = context.limits.clone();
                let local_node_id = context.local_node_id;
                connections.spawn(async move {
                    let _permit = permit;
                    if let Err(error) = handle_connection(
                        stream,
                        local_node_id,
                        cluster_name,
                        members,
                        acceptor,
                        raft,
                        limits,
                    )
                    .await
                    {
                        tracing::warn!(
                            node_id = local_node_id,
                            error = %error,
                            "rejected Raft peer connection"
                        );
                    }
                });
            }
            Some(result) = connections.join_next(), if !connections.is_empty() => {
                if let Err(error) = result {
                    tracing::warn!(node_id = context.local_node_id, error = %error, "Raft connection task failed");
                }
            }
        }
    }
    connections.abort_all();
    while connections.join_next().await.is_some() {}
    Ok(())
}

async fn handle_connection(
    stream: TcpStream,
    local_node_id: ClusterRaftNodeId,
    cluster_name: Arc<str>,
    members: Arc<BTreeMap<ClusterRaftNodeId, ClusterRaftNode>>,
    acceptor: TlsAcceptor,
    raft: Raft<ClusterRaftTypeConfig>,
    limits: ClusterRaftTransportLimits,
) -> io::Result<()> {
    let mut tls = tokio::time::timeout(limits.handshake_timeout, acceptor.accept(stream))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "Raft TLS handshake timed out"))?
        .map_err(|error| io::Error::new(io::ErrorKind::PermissionDenied, error))?;
    let peer_certificate = tls
        .get_ref()
        .1
        .peer_certificates()
        .and_then(|certificates| certificates.first())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Raft TLS peer did not present a certificate",
            )
        })?;
    let peer_fingerprint = certificate_fingerprint(peer_certificate.as_ref());
    let request: RpcEnvelope = tokio::time::timeout(
        limits.inbound_request_timeout,
        read_frame(&mut tls, limits.max_frame_bytes),
    )
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "Raft request timed out"))??;
    if request.version != CLUSTER_RAFT_WIRE_VERSION
        || request.cluster_name != cluster_name.as_ref()
        || request.target != local_node_id
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Raft request envelope identity mismatch",
        ));
    }
    let source = members.get(&request.source).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Raft source is absent from trusted membership",
        )
    })?;
    if source.tls_client_certificate_sha256 != peer_fingerprint {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Raft client leaf does not match trusted membership",
        ));
    }
    if request.body.embedded_sender() != Some(request.source) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Raft embedded vote identity does not match authenticated source",
        ));
    }

    let body = match request.body {
        RpcRequest::AppendEntries(request) => {
            RpcResponse::AppendEntries(raft.append_entries(request).await)
        }
        RpcRequest::Vote(request) => RpcResponse::Vote(raft.vote(request).await),
        RpcRequest::InstallSnapshot(request) => {
            RpcResponse::InstallSnapshot(raft.install_snapshot(request).await)
        }
    };
    let response = RpcResponseEnvelope {
        version: CLUSTER_RAFT_WIRE_VERSION,
        cluster_name: cluster_name.to_string(),
        source: local_node_id,
        target: request.source,
        body,
    };
    tokio::time::timeout(
        limits.inbound_request_timeout,
        write_frame(&mut tls, &response, limits.max_frame_bytes),
    )
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "Raft response timed out"))??;
    tls.shutdown().await?;
    Ok(())
}

async fn write_frame<W, T>(writer: &mut W, value: &T, max_frame_bytes: usize) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
    T: Serialize,
{
    let bytes = serde_json::to_vec(value)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    if bytes.len() > max_frame_bytes || bytes.len() > u32::MAX as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Raft frame exceeds configured maximum",
        ));
    }
    writer.write_u32(bytes.len() as u32).await?;
    writer.write_all(&bytes).await?;
    writer.flush().await
}

async fn read_frame<R, T>(reader: &mut R, max_frame_bytes: usize) -> io::Result<T>
where
    R: AsyncRead + Unpin,
    T: DeserializeOwned,
{
    let length = reader.read_u32().await? as usize;
    if length == 0 || length > max_frame_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Raft frame length is outside configured bounds",
        ));
    }
    let mut bytes = vec![0; length];
    reader.read_exact(&mut bytes).await?;
    serde_json::from_slice(&bytes)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use openraft::network::{RPCOption, RaftNetwork, RaftNetworkFactory};
    use openraft::raft::{VoteRequest, VoteResponse};
    use openraft::Vote;
    use rcgen::{
        BasicConstraints, CertificateParams, CertifiedIssuer, ExtendedKeyUsagePurpose, IsCa,
        KeyPair, KeyUsagePurpose,
    };
    use tempfile::TempDir;
    use uuid::Uuid;

    use super::*;
    use crate::cluster_consensus::AuthorityResponse;

    struct TestPeer {
        node_id: ClusterRaftNodeId,
        server_name: String,
        tls: ClusterRaftTls,
    }

    fn test_ca() -> CertifiedIssuer<'static, KeyPair> {
        let key = KeyPair::generate().expect("generate CA key");
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
        ];
        CertifiedIssuer::self_signed(params, key).expect("self-sign CA")
    }

    fn test_peer(ca: &CertifiedIssuer<'_, KeyPair>, node_id: ClusterRaftNodeId) -> TestPeer {
        let server_name = format!("node-{node_id}.agentos.test");
        let server_key = KeyPair::generate().expect("generate server key");
        let mut server_params =
            CertificateParams::new(vec![server_name.clone()]).expect("server params");
        server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let server_certificate = server_params
            .signed_by(&server_key, ca)
            .expect("sign server certificate");

        let client_key = KeyPair::generate().expect("generate client key");
        let mut client_params =
            CertificateParams::new(Vec::<String>::new()).expect("client params");
        client_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        let client_certificate = client_params
            .signed_by(&client_key, ca)
            .expect("sign client certificate");

        let tls = ClusterRaftTls::from_pem(
            server_certificate.pem().as_bytes(),
            server_key.serialize_pem().as_bytes(),
            client_certificate.pem().as_bytes(),
            client_key.serialize_pem().as_bytes(),
            ca.pem().as_bytes(),
        )
        .expect("peer TLS");
        TestPeer {
            node_id,
            server_name,
            tls,
        }
    }

    async fn listeners(count: usize) -> Vec<TcpListener> {
        let mut listeners = Vec::with_capacity(count);
        for _ in 0..count {
            listeners.push(
                TcpListener::bind("127.0.0.1:0")
                    .await
                    .expect("bind test listener"),
            );
        }
        listeners
    }

    fn member_map(
        peers: &[TestPeer],
        listeners: &[TcpListener],
    ) -> BTreeMap<ClusterRaftNodeId, ClusterRaftNode> {
        peers
            .iter()
            .zip(listeners)
            .map(|(peer, listener)| {
                (
                    peer.node_id,
                    ClusterRaftNode {
                        endpoint: listener.local_addr().expect("listener address").to_string(),
                        server_name: peer.server_name.clone(),
                        tls_certificate_sha256: peer.tls.server_certificate_sha256().to_string(),
                        tls_client_certificate_sha256: peer
                            .tls
                            .client_certificate_sha256()
                            .to_string(),
                        identity_public_key: format!("test-identity-key-{}", peer.node_id),
                    },
                )
            })
            .collect()
    }

    fn runtime_config(
        peer: &TestPeer,
        listener: &TcpListener,
        members: &BTreeMap<ClusterRaftNodeId, ClusterRaftNode>,
        cluster_name: &str,
    ) -> ClusterRaftRuntimeConfig {
        ClusterRaftRuntimeConfig {
            node_id: peer.node_id,
            listen_addr: listener.local_addr().expect("listener address"),
            members: members.clone(),
            tls: peer.tls.clone(),
            raft: OpenRaftConfig {
                cluster_name: cluster_name.to_string(),
                heartbeat_interval: 100,
                election_timeout_min: 500,
                election_timeout_max: 1_000,
                install_snapshot_timeout: 3_000,
                max_payload_entries: 64,
                ..Default::default()
            },
            transport: ClusterRaftTransportLimits {
                handshake_timeout: Duration::from_secs(3),
                inbound_request_timeout: Duration::from_secs(5),
                ..Default::default()
            },
        }
    }

    fn context(tempdir: &TempDir, node_id: ClusterRaftNodeId) -> Arc<SqliteContextManager> {
        let path = tempdir.path().join(format!("node-{node_id}.db"));
        Arc::new(
            SqliteContextManager::new_without_storage_lease(&path).expect("create node database"),
        )
    }

    async fn wait_for_leader(
        runtimes: &[Option<ClusterRaftRuntime>],
        excluded: Option<ClusterRaftNodeId>,
    ) -> ClusterRaftNodeId {
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            let mut observations = BTreeMap::<ClusterRaftNodeId, usize>::new();
            for runtime in runtimes.iter().flatten() {
                if let Some(leader) = runtime.metrics().borrow().current_leader {
                    if Some(leader) != excluded {
                        *observations.entry(leader).or_default() += 1;
                    }
                }
            }
            if let Some((leader, count)) = observations.into_iter().max_by_key(|(_, count)| *count)
            {
                if count >= 2 || runtimes.iter().flatten().count() == 1 {
                    return leader;
                }
            }
            assert!(
                Instant::now() < deadline,
                "cluster did not converge on a leader"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    async fn wait_for_applied(
        runtimes: &[Option<ClusterRaftRuntime>],
        index: u64,
        required: usize,
    ) {
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            let applied = runtimes
                .iter()
                .flatten()
                .filter(|runtime| {
                    runtime
                        .metrics()
                        .borrow()
                        .last_applied
                        .is_some_and(|log_id| log_id.index >= index)
                })
                .count();
            if applied >= required {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "log index {index} did not reach {required} replicas"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn three_node_mtls_quorum_elects_replicates_fails_over_and_recovers() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let ca = test_ca();
        let peers = (1..=3)
            .map(|node_id| test_peer(&ca, node_id))
            .collect::<Vec<_>>();
        let initial_listeners = listeners(3).await;
        let members = member_map(&peers, &initial_listeners);
        let configs = peers
            .iter()
            .zip(&initial_listeners)
            .map(|(peer, listener)| runtime_config(peer, listener, &members, "mtls-quorum-test"))
            .collect::<Vec<_>>();
        let tempdir = TempDir::new().expect("tempdir");
        let contexts = (1..=3)
            .map(|node_id| context(&tempdir, node_id))
            .collect::<Vec<_>>();

        let mut runtimes = Vec::with_capacity(3);
        for ((config, listener), context) in configs
            .iter()
            .cloned()
            .zip(initial_listeners)
            .zip(&contexts)
        {
            runtimes.push(Some(
                ClusterRaftRuntime::start_on_listener(context.clone(), config, listener)
                    .await
                    .expect("start Raft runtime"),
            ));
        }
        let (first, second, third) = tokio::join!(
            runtimes[0].as_ref().expect("node 1").initialize(),
            runtimes[1].as_ref().expect("node 2").initialize(),
            runtimes[2].as_ref().expect("node 3").initialize(),
        );
        first.expect("initialize node 1");
        second.expect("initialize node 2");
        third.expect("initialize node 3");

        let first_leader = wait_for_leader(&runtimes, None).await;
        let first_leader_index = (first_leader - 1) as usize;
        let operation_id = Uuid::new_v4().to_string();
        let first_write = runtimes[first_leader_index]
            .as_ref()
            .expect("first leader runtime")
            .commit(AuthorityCommand::Barrier {
                operation_id: operation_id.clone(),
                expected_sequence: Some(0),
            })
            .await
            .expect("commit first barrier");
        assert!(matches!(
            first_write.data,
            AuthorityResponse::BarrierCommitted {
                operation_id: ref committed,
                sequence: 1,
                replayed: false,
                ..
            } if committed == &operation_id
        ));
        wait_for_applied(&runtimes, first_write.log_id.index, 3).await;

        runtimes[first_leader_index]
            .take()
            .expect("remove first leader")
            .shutdown()
            .await
            .expect("shutdown first leader");
        let second_leader = wait_for_leader(&runtimes, Some(first_leader)).await;
        assert_ne!(first_leader, second_leader);
        let second_write = runtimes[(second_leader - 1) as usize]
            .as_ref()
            .expect("second leader runtime")
            .commit(AuthorityCommand::Barrier {
                operation_id: Uuid::new_v4().to_string(),
                expected_sequence: Some(1),
            })
            .await
            .expect("commit after leader failover");
        assert!(matches!(
            second_write.data,
            AuthorityResponse::BarrierCommitted { sequence: 2, .. }
        ));
        wait_for_applied(&runtimes, second_write.log_id.index, 2).await;

        let restarted_listener = TcpListener::bind(configs[first_leader_index].listen_addr)
            .await
            .expect("rebind first leader address");
        runtimes[first_leader_index] = Some(
            ClusterRaftRuntime::start_on_listener(
                contexts[first_leader_index].clone(),
                configs[first_leader_index].clone(),
                restarted_listener,
            )
            .await
            .expect("restart old leader"),
        );
        wait_for_applied(&runtimes, second_write.log_id.index, 3).await;
        assert_eq!(
            wait_for_leader(&runtimes, None).await,
            second_leader,
            "restarted old leader must not revive its old term"
        );

        for runtime in runtimes.into_iter().flatten() {
            runtime.shutdown().await.expect("shutdown runtime");
        }
    }

    #[tokio::test]
    async fn authenticated_certificate_cannot_claim_another_raft_node_id() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let ca = test_ca();
        let peers = vec![test_peer(&ca, 1), test_peer(&ca, 2)];
        let bound = listeners(2).await;
        let members = member_map(&peers, &bound);
        let target_context_dir = TempDir::new().expect("tempdir");
        let target_context = context(&target_context_dir, 2);
        let mut bound = bound.into_iter();
        let source_listener = bound.next().expect("source listener");
        let target_listener = bound.next().expect("target listener");
        let target_config = runtime_config(&peers[1], &target_listener, &members, "spoof-test");
        let target_runtime =
            ClusterRaftRuntime::start_on_listener(target_context, target_config, target_listener)
                .await
                .expect("start target");

        let mut factory = ClusterNetworkFactory {
            source: 2,
            cluster_name: Arc::from("spoof-test"),
            members: Arc::new(members.clone()),
            client_config: peers[0].tls.client_config.clone(),
            handshake_timeout: Duration::from_secs(3),
            max_frame_bytes: DEFAULT_MAX_FRAME_BYTES,
        };
        let mut network = factory
            .new_client(2, members.get(&2).expect("node 2"))
            .await;
        let result: Result<
            VoteResponse<ClusterRaftNodeId>,
            RPCError<ClusterRaftNodeId, ClusterRaftNode, RaftError<ClusterRaftNodeId>>,
        > = network
            .vote(
                VoteRequest::new(Vote::new(1, 2), None),
                RPCOption::new(Duration::from_secs(3)),
            )
            .await;
        assert!(
            result.is_err(),
            "node 1 certificate must not authorize a source-node-2 envelope"
        );

        drop(source_listener);
        target_runtime.shutdown().await.expect("shutdown target");
    }

    #[tokio::test]
    async fn embedded_vote_cannot_disagree_with_authenticated_source() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let ca = test_ca();
        let peers = vec![test_peer(&ca, 1), test_peer(&ca, 2)];
        let bound = listeners(2).await;
        let members = member_map(&peers, &bound);
        let target_context_dir = TempDir::new().expect("tempdir");
        let target_context = context(&target_context_dir, 2);
        let mut bound = bound.into_iter();
        let source_listener = bound.next().expect("source listener");
        let target_listener = bound.next().expect("target listener");
        let target_config =
            runtime_config(&peers[1], &target_listener, &members, "embedded-vote-test");
        let target_runtime =
            ClusterRaftRuntime::start_on_listener(target_context, target_config, target_listener)
                .await
                .expect("start target");

        let mut factory = ClusterNetworkFactory {
            source: 1,
            cluster_name: Arc::from("embedded-vote-test"),
            members: Arc::new(members.clone()),
            client_config: peers[0].tls.client_config.clone(),
            handshake_timeout: Duration::from_secs(3),
            max_frame_bytes: DEFAULT_MAX_FRAME_BYTES,
        };
        let mut network = factory
            .new_client(2, members.get(&2).expect("node 2"))
            .await;
        let result: Result<
            VoteResponse<ClusterRaftNodeId>,
            RPCError<ClusterRaftNodeId, ClusterRaftNode, RaftError<ClusterRaftNodeId>>,
        > = network
            .vote(
                VoteRequest::new(Vote::new(1, 2), None),
                RPCOption::new(Duration::from_secs(3)),
            )
            .await;
        assert!(
            result.is_err(),
            "authenticated source node 1 must not send an embedded node 2 vote"
        );

        drop(source_listener);
        target_runtime.shutdown().await.expect("shutdown target");
    }

    #[tokio::test]
    async fn exact_server_leaf_mismatch_is_rejected_after_ca_validation() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let ca = test_ca();
        let peers = vec![test_peer(&ca, 1), test_peer(&ca, 2)];
        let bound = listeners(2).await;
        let members = member_map(&peers, &bound);
        let target_context_dir = TempDir::new().expect("tempdir");
        let target_context = context(&target_context_dir, 2);
        let target_listener = bound.into_iter().nth(1).expect("target listener");
        let target_config = runtime_config(&peers[1], &target_listener, &members, "leaf-test");
        let target_runtime =
            ClusterRaftRuntime::start_on_listener(target_context, target_config, target_listener)
                .await
                .expect("start target");

        let mut tampered_members = members.clone();
        tampered_members
            .get_mut(&2)
            .expect("node 2")
            .tls_certificate_sha256 = "0".repeat(64);
        let mut factory = ClusterNetworkFactory {
            source: 1,
            cluster_name: Arc::from("leaf-test"),
            members: Arc::new(tampered_members.clone()),
            client_config: peers[0].tls.client_config.clone(),
            handshake_timeout: Duration::from_secs(3),
            max_frame_bytes: DEFAULT_MAX_FRAME_BYTES,
        };
        let mut network = factory
            .new_client(2, tampered_members.get(&2).expect("node 2"))
            .await;
        let result: Result<
            VoteResponse<ClusterRaftNodeId>,
            RPCError<ClusterRaftNodeId, ClusterRaftNode, RaftError<ClusterRaftNodeId>>,
        > = network
            .vote(
                VoteRequest::new(Vote::new(1, 1), None),
                RPCOption::new(Duration::from_secs(3)),
            )
            .await;
        assert!(
            result.is_err(),
            "CA trust must not bypass the exact member leaf binding"
        );
        target_runtime.shutdown().await.expect("shutdown target");
    }

    #[tokio::test]
    async fn frame_and_configuration_bounds_fail_closed() {
        let (mut writer, reader) = tokio::io::duplex(128);
        let oversized = vec![7_u8; 512];
        let write = tokio::spawn(async move { write_frame(&mut writer, &oversized, 128).await });
        let error = write
            .await
            .expect("write task")
            .expect_err("oversized frame");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        drop(reader);

        let ca = test_ca();
        let peer = test_peer(&ca, 1);
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
        let mut members = member_map(std::slice::from_ref(&peer), std::slice::from_ref(&listener));
        members
            .get_mut(&1)
            .expect("local member")
            .tls_client_certificate_sha256 = String::new();
        let config = runtime_config(&peer, &listener, &members, "invalid-config");
        assert!(
            config.validate().is_err(),
            "empty client leaf binding must fail closed"
        );

        let peers = vec![test_peer(&ca, 2), test_peer(&ca, 3)];
        let listeners = listeners(2).await;
        let mut members = member_map(&peers, &listeners);
        let cross_node_fingerprint = members
            .get(&2)
            .expect("node 2")
            .tls_certificate_sha256
            .clone();
        members
            .get_mut(&3)
            .expect("node 3")
            .tls_client_certificate_sha256 = cross_node_fingerprint;
        let config = runtime_config(&peers[0], &listeners[0], &members, "invalid-role-collision");
        assert!(
            config.validate().is_err(),
            "one certificate fingerprint must not span two node identities"
        );
    }
}
