//! Remaining Linux kernel equivalents — interrupts, permissions, swap,
//! block devices, network protocol stack, futex, epoll, device tree,
//! power management, real-time clock, kernel modules.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::agent_struct::AgentId;

// ─── Interrupts (async event handling) ───────────────────────────────────────

/// Interrupt types for the AI Agent OS.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Interrupt {
    Timer,           // Scheduler tick
    ToolComplete,    // A tool call finished
    MessageArrived,  // IPC message received
    BudgetExceeded,  // Token budget hit
    AgentCrashed,    // An agent died unexpectedly
    ShutdownRequest, // System shutdown
    Custom(u32),     // User-defined
}

/// Interrupt handler registry.
#[allow(clippy::type_complexity)]
pub struct InterruptController {
    handlers: Mutex<HashMap<Interrupt, Vec<Box<dyn Fn(Interrupt) + Send + Sync>>>>,
    pending: Mutex<Vec<Interrupt>>,
    enabled: std::sync::atomic::AtomicBool,
}

impl Default for InterruptController {
    fn default() -> Self {
        Self::new()
    }
}

impl InterruptController {
    pub fn new() -> Self {
        Self {
            handlers: Mutex::new(HashMap::new()),
            pending: Mutex::new(Vec::new()),
            enabled: std::sync::atomic::AtomicBool::new(true),
        }
    }

    pub fn register(&self, irq: Interrupt, handler: impl Fn(Interrupt) + Send + Sync + 'static) {
        self.handlers
            .lock()
            .unwrap()
            .entry(irq)
            .or_default()
            .push(Box::new(handler));
    }

    pub fn raise(&self, irq: Interrupt) {
        if !self.enabled.load(Ordering::SeqCst) {
            self.pending.lock().unwrap().push(irq);
            return;
        }
        if let Some(handlers) = self.handlers.lock().unwrap().get(&irq) {
            for h in handlers {
                h(irq);
            }
        }
    }

    pub fn disable(&self) {
        self.enabled.store(false, Ordering::SeqCst);
    }
    pub fn enable(&self) {
        self.enabled.store(true, Ordering::SeqCst);
        let pending: Vec<_> = self.pending.lock().unwrap().drain(..).collect();
        for irq in pending {
            self.raise(irq);
        }
    }
}

// ─── File Permissions (chmod equivalent) ─────────────────────────────────────

/// Permission mode bits (like Unix rwxrwxrwx).
#[derive(Debug, Clone, Copy)]
pub struct FileMode {
    pub owner_read: bool,
    pub owner_write: bool,
    pub owner_exec: bool,
    pub group_read: bool,
    pub group_write: bool,
    pub group_exec: bool,
    pub other_read: bool,
    pub other_write: bool,
    pub other_exec: bool,
}

impl FileMode {
    pub fn from_octal(mode: u16) -> Self {
        Self {
            owner_read: mode & 0o400 != 0,
            owner_write: mode & 0o200 != 0,
            owner_exec: mode & 0o100 != 0,
            group_read: mode & 0o040 != 0,
            group_write: mode & 0o020 != 0,
            group_exec: mode & 0o010 != 0,
            other_read: mode & 0o004 != 0,
            other_write: mode & 0o002 != 0,
            other_exec: mode & 0o001 != 0,
        }
    }
    pub fn to_octal(&self) -> u16 {
        (if self.owner_read { 0o400 } else { 0 })
            | (if self.owner_write { 0o200 } else { 0 })
            | (if self.owner_exec { 0o100 } else { 0 })
            | (if self.group_read { 0o040 } else { 0 })
            | (if self.group_write { 0o020 } else { 0 })
            | (if self.group_exec { 0o010 } else { 0 })
            | (if self.other_read { 0o004 } else { 0 })
            | (if self.other_write { 0o002 } else { 0 })
            | (if self.other_exec { 0o001 } else { 0 })
    }
    pub fn check(&self, uid: u64, gid: u64, owner_uid: u64, owner_gid: u64, action: char) -> bool {
        let (r, w, x) = if uid == owner_uid {
            (self.owner_read, self.owner_write, self.owner_exec)
        } else if gid == owner_gid {
            (self.group_read, self.group_write, self.group_exec)
        } else {
            (self.other_read, self.other_write, self.other_exec)
        };
        match action {
            'r' => r,
            'w' => w,
            'x' => x,
            _ => false,
        }
    }
}

// ─── Process Credentials (setuid) ────────────────────────────────────────────

/// Runtime credential changes.
pub struct CredentialManager {
    overrides: Mutex<HashMap<AgentId, (u64, u64)>>, // agent → (effective_uid, effective_gid)
}

impl Default for CredentialManager {
    fn default() -> Self {
        Self::new()
    }
}

impl CredentialManager {
    pub fn new() -> Self {
        Self {
            overrides: Mutex::new(HashMap::new()),
        }
    }
    pub fn setuid(&self, agent_id: AgentId, new_uid: u64) {
        self.overrides
            .lock()
            .unwrap()
            .entry(agent_id)
            .or_insert((0, 0))
            .0 = new_uid;
    }
    pub fn setgid(&self, agent_id: AgentId, new_gid: u64) {
        self.overrides
            .lock()
            .unwrap()
            .entry(agent_id)
            .or_insert((0, 0))
            .1 = new_gid;
    }
    pub fn effective_uid(&self, agent_id: AgentId) -> Option<u64> {
        self.overrides.lock().unwrap().get(&agent_id).map(|c| c.0)
    }
    pub fn drop_privileges(&self, agent_id: AgentId) {
        self.overrides.lock().unwrap().remove(&agent_id);
    }
}

// ─── Swap ────────────────────────────────────────────────────────────────────

/// Swap space for evicted context pages.
pub struct SwapSpace {
    pages: Mutex<HashMap<u64, Vec<u8>>>, // page_id → serialized content
    total_bytes: AtomicU64,
    max_bytes: u64,
}

impl SwapSpace {
    pub fn new(max_bytes: u64) -> Self {
        Self {
            pages: Mutex::new(HashMap::new()),
            total_bytes: AtomicU64::new(0),
            max_bytes,
        }
    }
    pub fn write_page(&self, page_id: u64, data: Vec<u8>) -> Result<(), &'static str> {
        let size = data.len() as u64;
        if self.total_bytes.load(Ordering::SeqCst) + size > self.max_bytes {
            return Err("swap full");
        }
        self.total_bytes.fetch_add(size, Ordering::SeqCst);
        self.pages.lock().unwrap().insert(page_id, data);
        Ok(())
    }
    pub fn read_page(&self, page_id: u64) -> Option<Vec<u8>> {
        self.pages.lock().unwrap().remove(&page_id)
    }
    pub fn usage(&self) -> (u64, u64) {
        (self.total_bytes.load(Ordering::SeqCst), self.max_bytes)
    }
}

// ─── Block Device Layer ──────────────────────────────────────────────────────

/// Abstract block device (storage layer between tools and persistence).
pub trait BlockDevice: Send + Sync {
    fn read_block(&self, block_id: u64) -> Option<Vec<u8>>;
    fn write_block(&self, block_id: u64, data: Vec<u8>) -> Result<(), String>;
    fn block_count(&self) -> u64;
    fn block_size(&self) -> usize;
}

/// In-memory block device (for testing).
pub struct MemBlockDevice {
    blocks: Mutex<HashMap<u64, Vec<u8>>>,
    block_size: usize,
}
impl MemBlockDevice {
    pub fn new(block_size: usize) -> Self {
        Self {
            blocks: Mutex::new(HashMap::new()),
            block_size,
        }
    }
}
impl BlockDevice for MemBlockDevice {
    fn read_block(&self, block_id: u64) -> Option<Vec<u8>> {
        self.blocks.lock().unwrap().get(&block_id).cloned()
    }
    fn write_block(&self, block_id: u64, data: Vec<u8>) -> Result<(), String> {
        self.blocks.lock().unwrap().insert(block_id, data);
        Ok(())
    }
    fn block_count(&self) -> u64 {
        self.blocks.lock().unwrap().len() as u64
    }
    fn block_size(&self) -> usize {
        self.block_size
    }
}

// ─── Network Protocol Stack ──────────────────────────────────────────────────

/// Protocol layers for agent communication.
pub struct ProtocolStack {
    routing_table: Mutex<Vec<Route>>,
    congestion_window: AtomicU64,
}

#[derive(Debug, Clone)]
pub struct Route {
    pub destination: AgentId,
    pub gateway: Option<AgentId>,
    pub metric: u32,
}

impl Default for ProtocolStack {
    fn default() -> Self {
        Self::new()
    }
}

impl ProtocolStack {
    pub fn new() -> Self {
        Self {
            routing_table: Mutex::new(Vec::new()),
            congestion_window: AtomicU64::new(64),
        }
    }
    pub fn add_route(&self, dest: AgentId, gateway: Option<AgentId>, metric: u32) {
        self.routing_table.lock().unwrap().push(Route {
            destination: dest,
            gateway,
            metric,
        });
    }
    pub fn resolve_route(&self, dest: AgentId) -> Option<Route> {
        self.routing_table
            .lock()
            .unwrap()
            .iter()
            .find(|r| r.destination == dest)
            .cloned()
    }
    pub fn congestion_window(&self) -> u64 {
        self.congestion_window.load(Ordering::SeqCst)
    }
    pub fn reduce_window(&self) {
        let cw = self.congestion_window.load(Ordering::SeqCst);
        self.congestion_window.store(cw / 2, Ordering::SeqCst);
    }
    pub fn increase_window(&self) {
        self.congestion_window.fetch_add(1, Ordering::SeqCst);
    }
}

// ─── Futex (fast agent-to-agent mutex) ───────────────────────────────────────

/// Fast userspace mutex for agent synchronization.
pub struct Futex {
    value: AtomicU64,
    waiters: Mutex<Vec<tokio::sync::oneshot::Sender<()>>>,
}

impl Futex {
    pub fn new(initial: u64) -> Self {
        Self {
            value: AtomicU64::new(initial),
            waiters: Mutex::new(Vec::new()),
        }
    }
    pub fn load(&self) -> u64 {
        self.value.load(Ordering::SeqCst)
    }
    pub fn store(&self, val: u64) {
        self.value.store(val, Ordering::SeqCst);
    }
    pub fn compare_exchange(&self, expected: u64, new: u64) -> Result<u64, u64> {
        self.value
            .compare_exchange(expected, new, Ordering::SeqCst, Ordering::SeqCst)
    }
    pub async fn wait(&self, expected: u64) {
        if self.load() != expected {
            return;
        }
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.waiters.lock().unwrap().push(tx);
        let _ = rx.await;
    }
    pub fn wake_one(&self) -> bool {
        self.waiters
            .lock()
            .unwrap()
            .pop()
            .map(|tx| {
                let _ = tx.send(());
            })
            .is_some()
    }
    pub fn wake_all(&self) -> usize {
        let mut w = self.waiters.lock().unwrap();
        let n = w.len();
        for tx in w.drain(..) {
            let _ = tx.send(());
        }
        n
    }
}

// ─── Epoll (async I/O multiplexing) ──────────────────────────────────────────

/// Event types for epoll.
#[derive(Debug, Clone, Copy)]
pub enum EpollEvent {
    Readable,
    Writable,
    Error,
    HangUp,
}

/// Epoll instance — wait for events on multiple sources.
pub struct Epoll {
    interests: Mutex<HashMap<u64, Vec<EpollEvent>>>, // fd → events interested in
}

impl Default for Epoll {
    fn default() -> Self {
        Self::new()
    }
}

impl Epoll {
    pub fn new() -> Self {
        Self {
            interests: Mutex::new(HashMap::new()),
        }
    }
    pub fn add(&self, fd: u64, events: Vec<EpollEvent>) {
        self.interests.lock().unwrap().insert(fd, events);
    }
    pub fn remove(&self, fd: u64) {
        self.interests.lock().unwrap().remove(&fd);
    }
    pub fn watched_count(&self) -> usize {
        self.interests.lock().unwrap().len()
    }
}

// ─── Device Tree (auto-discovery) ────────────────────────────────────────────

/// Discovered device (LLM provider, tool, etc.).
#[derive(Debug, Clone)]
pub struct DeviceNode {
    pub name: String,
    pub device_type: String,
    pub properties: HashMap<String, String>,
    pub available: bool,
}

/// Device tree — auto-discovered resources.
pub struct DeviceTree {
    devices: Mutex<Vec<DeviceNode>>,
}
impl Default for DeviceTree {
    fn default() -> Self {
        Self::new()
    }
}

impl DeviceTree {
    pub fn new() -> Self {
        Self {
            devices: Mutex::new(Vec::new()),
        }
    }
    pub fn register(&self, node: DeviceNode) {
        self.devices.lock().unwrap().push(node);
    }
    pub fn find_by_type(&self, dtype: &str) -> Vec<DeviceNode> {
        self.devices
            .lock()
            .unwrap()
            .iter()
            .filter(|d| d.device_type == dtype && d.available)
            .cloned()
            .collect()
    }
    pub fn list(&self) -> Vec<DeviceNode> {
        self.devices.lock().unwrap().clone()
    }
    pub fn mark_unavailable(&self, name: &str) {
        for d in self.devices.lock().unwrap().iter_mut() {
            if d.name == name {
                d.available = false;
            }
        }
    }
}

// ─── Power Management ────────────────────────────────────────────────────────

/// Agent power states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PowerState {
    Active,
    Idle,
    Suspended,
    Hibernated,
}

/// Power manager.
pub struct PowerManager {
    states: Mutex<HashMap<AgentId, PowerState>>,
}
impl Default for PowerManager {
    fn default() -> Self {
        Self::new()
    }
}

impl PowerManager {
    pub fn new() -> Self {
        Self {
            states: Mutex::new(HashMap::new()),
        }
    }
    pub fn set_state(&self, id: AgentId, state: PowerState) {
        self.states.lock().unwrap().insert(id, state);
    }
    pub fn get_state(&self, id: AgentId) -> PowerState {
        self.states
            .lock()
            .unwrap()
            .get(&id)
            .copied()
            .unwrap_or(PowerState::Active)
    }
    pub fn suspend(&self, id: AgentId) {
        self.set_state(id, PowerState::Suspended);
    }
    pub fn hibernate(&self, id: AgentId) {
        self.set_state(id, PowerState::Hibernated);
    }
    pub fn resume(&self, id: AgentId) {
        self.set_state(id, PowerState::Active);
    }
    pub fn idle_agents(&self) -> Vec<AgentId> {
        self.states
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, s)| **s == PowerState::Idle)
            .map(|(id, _)| *id)
            .collect()
    }
}

// ─── Real-Time Clock ─────────────────────────────────────────────────────────

/// Per-agent time tracking.
pub struct AgentClock {
    clocks: Mutex<HashMap<AgentId, AgentTime>>,
}
struct AgentTime {
    started: Instant,
    cpu_time: Duration,
    #[allow(dead_code)]
    wall_time: Duration,
    last_active: Instant,
}

impl Default for AgentClock {
    fn default() -> Self {
        Self::new()
    }
}

impl AgentClock {
    pub fn new() -> Self {
        Self {
            clocks: Mutex::new(HashMap::new()),
        }
    }
    pub fn start(&self, id: AgentId) {
        self.clocks.lock().unwrap().insert(
            id,
            AgentTime {
                started: Instant::now(),
                cpu_time: Duration::ZERO,
                wall_time: Duration::ZERO,
                last_active: Instant::now(),
            },
        );
    }
    pub fn record_cpu_time(&self, id: AgentId, duration: Duration) {
        if let Some(t) = self.clocks.lock().unwrap().get_mut(&id) {
            t.cpu_time += duration;
            t.last_active = Instant::now();
        }
    }
    pub fn uptime(&self, id: AgentId) -> Duration {
        self.clocks
            .lock()
            .unwrap()
            .get(&id)
            .map(|t| t.started.elapsed())
            .unwrap_or(Duration::ZERO)
    }
    pub fn cpu_time(&self, id: AgentId) -> Duration {
        self.clocks
            .lock()
            .unwrap()
            .get(&id)
            .map(|t| t.cpu_time)
            .unwrap_or(Duration::ZERO)
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicU32;

    #[test]
    fn interrupt_handler() {
        let ic = InterruptController::new();
        let count = Arc::new(AtomicU32::new(0));
        let c = count.clone();
        ic.register(Interrupt::Timer, move |_| {
            c.fetch_add(1, Ordering::SeqCst);
        });
        ic.raise(Interrupt::Timer);
        ic.raise(Interrupt::Timer);
        assert_eq!(count.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn interrupt_disable_enable() {
        let ic = InterruptController::new();
        let count = Arc::new(AtomicU32::new(0));
        let c = count.clone();
        ic.register(Interrupt::Timer, move |_| {
            c.fetch_add(1, Ordering::SeqCst);
        });
        ic.disable();
        ic.raise(Interrupt::Timer); // queued
        assert_eq!(count.load(Ordering::SeqCst), 0);
        ic.enable(); // delivers pending
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn file_permissions() {
        let mode = FileMode::from_octal(0o750);
        assert!(mode.check(1, 1, 1, 1, 'r')); // owner can read
        assert!(mode.check(1, 1, 1, 1, 'x')); // owner can exec
        assert!(mode.check(2, 1, 1, 1, 'r')); // group can read
        assert!(!mode.check(2, 1, 1, 1, 'w')); // group can't write
        assert!(!mode.check(3, 3, 1, 1, 'r')); // others can't read
    }

    #[test]
    fn swap_space() {
        let swap = SwapSpace::new(1024);
        swap.write_page(1, vec![0u8; 100]).unwrap();
        assert_eq!(swap.usage().0, 100);
        let data = swap.read_page(1).unwrap();
        assert_eq!(data.len(), 100);
    }

    #[test]
    fn block_device() {
        let dev = MemBlockDevice::new(4096);
        dev.write_block(0, vec![1, 2, 3]).unwrap();
        assert_eq!(dev.read_block(0), Some(vec![1, 2, 3]));
        assert_eq!(dev.block_count(), 1);
    }

    #[test]
    fn routing() {
        let stack = ProtocolStack::new();
        stack.add_route(42, Some(10), 1);
        let route = stack.resolve_route(42).unwrap();
        assert_eq!(route.gateway, Some(10));
    }

    #[test]
    fn futex_compare_exchange() {
        let f = Futex::new(0);
        assert!(f.compare_exchange(0, 1).is_ok());
        assert_eq!(f.load(), 1);
        assert!(f.compare_exchange(0, 2).is_err()); // expected 0 but is 1
    }

    #[test]
    fn device_tree() {
        let dt = DeviceTree::new();
        dt.register(DeviceNode {
            name: "gpt-4o".into(),
            device_type: "llm".into(),
            properties: HashMap::new(),
            available: true,
        });
        dt.register(DeviceNode {
            name: "claude".into(),
            device_type: "llm".into(),
            properties: HashMap::new(),
            available: true,
        });
        assert_eq!(dt.find_by_type("llm").len(), 2);
        dt.mark_unavailable("claude");
        assert_eq!(dt.find_by_type("llm").len(), 1);
    }

    #[test]
    fn power_management() {
        let pm = PowerManager::new();
        pm.set_state(1, PowerState::Active);
        pm.suspend(1);
        assert_eq!(pm.get_state(1), PowerState::Suspended);
        pm.resume(1);
        assert_eq!(pm.get_state(1), PowerState::Active);
    }

    #[test]
    fn agent_clock() {
        let clock = AgentClock::new();
        clock.start(1);
        clock.record_cpu_time(1, Duration::from_millis(100));
        assert_eq!(clock.cpu_time(1), Duration::from_millis(100));
        assert!(clock.uptime(1) >= Duration::ZERO);
    }

    use std::sync::Arc;
}
