//! Agent Sockets — communication endpoints between agents.
//!
//! Like Unix sockets. Agents create sockets, bind to addresses,
//! connect to other agents, and send/receive messages.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

use tokio::sync::mpsc;

use crate::agent_struct::AgentId;

static NEXT_SOCKET_ID: AtomicU64 = AtomicU64::new(1);

/// Socket ID.
pub type SocketId = u64;

/// Socket address (agent_id + port).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SocketAddr {
    pub agent_id: AgentId,
    pub port: u16,
}

impl SocketAddr {
    pub fn new(agent_id: AgentId, port: u16) -> Self { Self { agent_id, port } }
}

/// Socket type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketType {
    /// Reliable ordered stream.
    Stream,
    /// Unreliable unordered datagrams.
    Datagram,
}

/// Socket state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketState {
    Created,
    Bound,
    Listening,
    Connected,
    Closed,
}

/// A message on a socket.
#[derive(Debug, Clone)]
pub struct SocketMessage {
    pub from: SocketAddr,
    pub data: Vec<u8>,
}

/// A socket instance.
pub struct Socket {
    pub id: SocketId,
    pub owner: AgentId,
    pub sock_type: SocketType,
    pub state: SocketState,
    pub local_addr: Option<SocketAddr>,
    pub remote_addr: Option<SocketAddr>,
    rx: mpsc::Receiver<SocketMessage>,
    tx: mpsc::Sender<SocketMessage>,
    pub buffer_size: usize,
}

/// Socket registry — manages all sockets in the system.
pub struct SocketRegistry {
    sockets: HashMap<SocketId, mpsc::Sender<SocketMessage>>,
    bindings: HashMap<SocketAddr, SocketId>,
}

impl SocketRegistry {
    pub fn new() -> Self {
        Self { sockets: HashMap::new(), bindings: HashMap::new() }
    }

    /// Create a new socket.
    pub fn create(&mut self, owner: AgentId, sock_type: SocketType, buffer_size: usize) -> Socket {
        let id = NEXT_SOCKET_ID.fetch_add(1, Ordering::SeqCst);
        let (tx, rx) = mpsc::channel(buffer_size);
        self.sockets.insert(id, tx.clone());
        Socket {
            id, owner, sock_type, state: SocketState::Created,
            local_addr: None, remote_addr: None, rx, tx, buffer_size,
        }
    }

    /// Bind a socket to an address.
    pub fn bind(&mut self, socket: &mut Socket, addr: SocketAddr) -> Result<(), &'static str> {
        if self.bindings.contains_key(&addr) {
            return Err("address already in use (EADDRINUSE)");
        }
        self.bindings.insert(addr.clone(), socket.id);
        socket.local_addr = Some(addr);
        socket.state = SocketState::Bound;
        Ok(())
    }

    /// Connect a socket to a remote address.
    pub fn connect(&mut self, socket: &mut Socket, remote: SocketAddr) -> Result<(), &'static str> {
        if !self.bindings.contains_key(&remote) {
            return Err("connection refused (ECONNREFUSED)");
        }
        socket.remote_addr = Some(remote);
        socket.state = SocketState::Connected;
        Ok(())
    }

    /// Send a message to a bound address.
    pub fn send_to(&self, from: &SocketAddr, to: &SocketAddr, data: Vec<u8>) -> Result<(), &'static str> {
        let target_id = self.bindings.get(to).ok_or("destination not found")?;
        let sender = self.sockets.get(target_id).ok_or("socket closed")?;
        let msg = SocketMessage { from: from.clone(), data };
        sender.try_send(msg).map_err(|_| "send buffer full (EAGAIN)")
    }

    /// Close a socket.
    pub fn close(&mut self, socket: &mut Socket) {
        if let Some(ref addr) = socket.local_addr {
            self.bindings.remove(addr);
        }
        self.sockets.remove(&socket.id);
        socket.state = SocketState::Closed;
    }

    /// Get number of active sockets.
    pub fn active_count(&self) -> usize { self.sockets.len() }

    /// Get number of bound addresses.
    pub fn bound_count(&self) -> usize { self.bindings.len() }
}

impl Socket {
    /// Receive a message (non-blocking).
    pub fn try_recv(&mut self) -> Option<SocketMessage> {
        self.rx.try_recv().ok()
    }

    /// Receive a message (blocking).
    pub async fn recv(&mut self) -> Option<SocketMessage> {
        self.rx.recv().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_and_bind() {
        let mut reg = SocketRegistry::new();
        let mut sock = reg.create(1, SocketType::Stream, 32);
        reg.bind(&mut sock, SocketAddr::new(1, 8080)).unwrap();
        assert_eq!(sock.state, SocketState::Bound);
        assert_eq!(reg.bound_count(), 1);
    }

    #[test]
    fn bind_duplicate_fails() {
        let mut reg = SocketRegistry::new();
        let mut s1 = reg.create(1, SocketType::Stream, 32);
        let mut s2 = reg.create(2, SocketType::Stream, 32);
        reg.bind(&mut s1, SocketAddr::new(1, 80)).unwrap();
        let result = reg.bind(&mut s2, SocketAddr::new(1, 80));
        assert!(result.is_err());
    }

    #[test]
    fn connect_to_bound() {
        let mut reg = SocketRegistry::new();
        let mut server = reg.create(1, SocketType::Stream, 32);
        let mut client = reg.create(2, SocketType::Stream, 32);
        let addr = SocketAddr::new(1, 9000);
        reg.bind(&mut server, addr.clone()).unwrap();
        reg.connect(&mut client, addr).unwrap();
        assert_eq!(client.state, SocketState::Connected);
    }

    #[test]
    fn connect_refused() {
        let mut reg = SocketRegistry::new();
        let mut client = reg.create(1, SocketType::Stream, 32);
        let result = reg.connect(&mut client, SocketAddr::new(99, 1234));
        assert!(result.is_err());
    }

    #[test]
    fn send_and_receive() {
        let mut reg = SocketRegistry::new();
        let mut server = reg.create(1, SocketType::Datagram, 32);
        let server_addr = SocketAddr::new(1, 5000);
        reg.bind(&mut server, server_addr.clone()).unwrap();

        let client_addr = SocketAddr::new(2, 6000);
        reg.send_to(&client_addr, &server_addr, b"hello".to_vec()).unwrap();

        let msg = server.try_recv().unwrap();
        assert_eq!(msg.data, b"hello");
        assert_eq!(msg.from, client_addr);
    }

    #[test]
    fn close_socket() {
        let mut reg = SocketRegistry::new();
        let mut sock = reg.create(1, SocketType::Stream, 32);
        reg.bind(&mut sock, SocketAddr::new(1, 7000)).unwrap();
        reg.close(&mut sock);
        assert_eq!(sock.state, SocketState::Closed);
        assert_eq!(reg.bound_count(), 0);
    }
}
