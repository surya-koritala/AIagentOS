//! Kernel Runtime — background loops, supervisor, kernel threads.
//!
//! This is what makes the OS actually RUN — not just respond to calls,
//! but actively manage agents in the background. Phase 2 cleanup: this
//! module now drives [`crate::AgentKernelImpl`] directly, not the legacy
//! `OsKernel`. Construct via `AgentKernelImpl::start_runtime()`.

use std::sync::Arc;
use std::time::Duration;

use tokio::time::interval;

use crate::agent_struct::AgentId;
use crate::AgentKernelImpl;

/// The kernel runtime — runs background tasks against an `AgentKernelImpl`.
pub struct KernelRuntime {
    kernel: Arc<AgentKernelImpl>,
    scheduler_interval_ms: u64,
    cgroup_reset_interval_secs: u64,
    running: Arc<std::sync::atomic::AtomicBool>,
}

impl KernelRuntime {
    pub fn new(kernel: Arc<AgentKernelImpl>) -> Self {
        Self {
            kernel,
            scheduler_interval_ms: 100,
            cgroup_reset_interval_secs: 60,
            running: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    /// Start all kernel background threads. Returns the join handles so the
    /// caller can await them on shutdown if desired.
    pub fn start(&self) -> Vec<tokio::task::JoinHandle<()>> {
        self.running
            .store(true, std::sync::atomic::Ordering::SeqCst);
        vec![
            self.spawn_scheduler_observer(),
            self.spawn_cgroup_reset_timer(),
        ]
    }

    /// Stop all background threads. Loops exit on next tick.
    pub fn stop(&self) {
        self.running
            .store(false, std::sync::atomic::Ordering::SeqCst);
    }

    #[allow(dead_code)]
    fn is_running(&self) -> bool {
        self.running.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Scheduler observer: every tick, ask CFS who would run next and
    /// publish that into procfs as `current_agent`. The actual turn execution
    /// is still driven by `send_message`; this loop just keeps procfs honest.
    fn spawn_scheduler_observer(&self) -> tokio::task::JoinHandle<()> {
        let kernel = self.kernel.clone();
        let running = self.running.clone();
        let interval_ms = self.scheduler_interval_ms;

        tokio::spawn(async move {
            let mut tick = interval(Duration::from_millis(interval_ms));
            while running.load(std::sync::atomic::Ordering::SeqCst) {
                tick.tick().await;
                let next = {
                    let mut sched = kernel.os.cfs.lock().await;
                    sched.pick_next()
                };
                if let Some(pid) = next {
                    let mut procfs = kernel.os.procfs.lock().await;
                    procfs.set_system("current_agent".into(), pid.to_string());
                }
            }
        })
    }

    /// Cgroup reset timer: every minute, reset per-minute token counters so
    /// `tokens_per_min` quotas regenerate. Without this, an agent that hits
    /// quota stays denied forever.
    fn spawn_cgroup_reset_timer(&self) -> tokio::task::JoinHandle<()> {
        let kernel = self.kernel.clone();
        let running = self.running.clone();
        let interval_secs = self.cgroup_reset_interval_secs;

        tokio::spawn(async move {
            let mut tick = interval(Duration::from_secs(interval_secs));
            // Skip first immediate tick.
            tick.tick().await;
            while running.load(std::sync::atomic::Ordering::SeqCst) {
                tick.tick().await;
                kernel.cgroups.reset_minute_counters();
            }
        })
    }
}

/// Wait queue — agents blocked waiting for a condition.
pub struct WaitQueue {
    waiters: std::sync::Mutex<Vec<(AgentId, tokio::sync::oneshot::Sender<()>)>>,
}

impl Default for WaitQueue {
    fn default() -> Self {
        Self::new()
    }
}

impl WaitQueue {
    pub fn new() -> Self {
        Self {
            waiters: std::sync::Mutex::new(Vec::new()),
        }
    }

    /// Block an agent until woken.
    pub async fn wait(&self, agent_id: AgentId) {
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.waiters.lock().unwrap().push((agent_id, tx));
        let _ = rx.await;
    }

    /// Wake one waiter.
    pub fn wake_one(&self) -> Option<AgentId> {
        let mut waiters = self.waiters.lock().unwrap();
        if let Some((id, tx)) = waiters.pop() {
            let _ = tx.send(());
            Some(id)
        } else {
            None
        }
    }

    /// Wake all waiters.
    pub fn wake_all(&self) -> usize {
        let mut waiters = self.waiters.lock().unwrap();
        let count = waiters.len();
        for (_, tx) in waiters.drain(..) {
            let _ = tx.send(());
        }
        count
    }

    /// Number of waiters.
    pub fn len(&self) -> usize {
        self.waiters.lock().unwrap().len()
    }

    /// Whether the wait queue has no waiters.
    pub fn is_empty(&self) -> bool {
        self.waiters.lock().unwrap().is_empty()
    }
}

/// Kernel page cache — caches tool call results.
pub struct PageCache {
    cache: std::sync::Mutex<std::collections::HashMap<String, CacheEntry>>,
    max_entries: usize,
}

struct CacheEntry {
    value: serde_json::Value,
    inserted_at: std::time::Instant,
    ttl: Duration,
    hits: u64,
}

impl PageCache {
    pub fn new(max_entries: usize) -> Self {
        Self {
            cache: std::sync::Mutex::new(std::collections::HashMap::new()),
            max_entries,
        }
    }

    /// Get from cache.
    pub fn get(&self, key: &str) -> Option<serde_json::Value> {
        let mut cache = self.cache.lock().unwrap();
        if let Some(entry) = cache.get_mut(key) {
            if entry.inserted_at.elapsed() < entry.ttl {
                entry.hits += 1;
                return Some(entry.value.clone());
            } else {
                cache.remove(key);
            }
        }
        None
    }

    /// Put into cache.
    pub fn put(&self, key: String, value: serde_json::Value, ttl: Duration) {
        let mut cache = self.cache.lock().unwrap();
        if cache.len() >= self.max_entries {
            // Evict oldest
            if let Some(oldest_key) = cache
                .iter()
                .min_by_key(|(_, e)| e.inserted_at)
                .map(|(k, _)| k.clone())
            {
                cache.remove(&oldest_key);
            }
        }
        cache.insert(
            key,
            CacheEntry {
                value,
                inserted_at: std::time::Instant::now(),
                ttl,
                hits: 0,
            },
        );
    }

    /// Invalidate a cache entry.
    pub fn invalidate(&self, key: &str) {
        self.cache.lock().unwrap().remove(key);
    }

    /// Cache stats.
    pub fn stats(&self) -> (usize, u64) {
        let cache = self.cache.lock().unwrap();
        let total_hits: u64 = cache.values().map(|e| e.hits).sum();
        (cache.len(), total_hits)
    }
}

/// Copy-on-write context for agent_clone.
#[derive(Debug, Clone)]
pub struct CowContext {
    /// Shared reference to original data.
    shared: Arc<Vec<String>>,
    /// Local modifications (None = still sharing).
    local: Option<Vec<String>>,
}

impl CowContext {
    pub fn new(data: Vec<String>) -> Self {
        Self {
            shared: Arc::new(data),
            local: None,
        }
    }

    /// Read (cheap — no copy).
    pub fn read(&self) -> &[String] {
        self.local.as_deref().unwrap_or(&self.shared)
    }

    /// Write (copies on first write).
    pub fn write(&mut self) -> &mut Vec<String> {
        if self.local.is_none() {
            self.local = Some((*self.shared).clone()); // COW copy happens here
        }
        self.local.as_mut().unwrap()
    }

    /// Check if this is still sharing (no writes yet).
    pub fn is_shared(&self) -> bool {
        self.local.is_none()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wait_queue_wake_one() {
        let wq = WaitQueue::new();
        // Can't easily test async wait in sync test, but test wake with no waiters
        assert_eq!(wq.wake_one(), None);
        assert_eq!(wq.len(), 0);
    }

    #[test]
    fn page_cache_put_get() {
        let cache = PageCache::new(10);
        cache.put(
            "key1".into(),
            serde_json::json!("value1"),
            Duration::from_secs(60),
        );
        assert_eq!(cache.get("key1"), Some(serde_json::json!("value1")));
    }

    #[test]
    fn page_cache_ttl_expiry() {
        let cache = PageCache::new(10);
        cache.put(
            "key".into(),
            serde_json::json!("val"),
            Duration::from_millis(1),
        );
        std::thread::sleep(Duration::from_millis(5));
        assert_eq!(cache.get("key"), None); // expired
    }

    #[test]
    fn page_cache_eviction() {
        let cache = PageCache::new(2);
        cache.put("a".into(), serde_json::json!(1), Duration::from_secs(60));
        cache.put("b".into(), serde_json::json!(2), Duration::from_secs(60));
        cache.put("c".into(), serde_json::json!(3), Duration::from_secs(60)); // evicts oldest
        assert_eq!(cache.stats().0, 2); // max 2
    }

    #[test]
    fn cow_context_no_copy_on_read() {
        let ctx = CowContext::new(vec!["hello".into(), "world".into()]);
        assert!(ctx.is_shared());
        assert_eq!(ctx.read().len(), 2);
        assert!(ctx.is_shared()); // still shared after read
    }

    #[test]
    fn cow_context_copies_on_write() {
        let original = CowContext::new(vec!["a".into(), "b".into()]);
        let mut clone = original.clone();
        assert!(clone.is_shared());
        clone.write().push("c".into()); // triggers copy
        assert!(!clone.is_shared());
        assert_eq!(clone.read().len(), 3);
        assert_eq!(original.read().len(), 2); // original unchanged
    }

    #[tokio::test]
    async fn kernel_runtime_starts_and_stops() {
        let kernel = Arc::new(crate::AgentKernelImpl::new().unwrap());
        let runtime = kernel.start_runtime();

        // Let the loops tick at least once so we exercise both the scheduler
        // observer and the cgroup reset timer's first iteration.
        tokio::time::sleep(Duration::from_millis(150)).await;

        runtime.stop();
        kernel.shutdown().await.unwrap();
    }
}
