//! LLM-request scheduler — a bounded pool of "LLM cores" with priority-ordered
//! admission.
//!
//! Where [`crate::cfs::TurnAdmission`] gates *agent turns*, this gates the
//! *LLM-request* step inside a turn: a fixed number of "cores" model the
//! concurrency a provider (or a budget) can sustain. When more LLM requests are
//! pending than there are cores, the next freed core is granted to the
//! **highest-priority waiter** (lowest nice value) rather than FIFO — mirroring
//! how CFS picks among contenders.
//!
//! Correctness mirrors `TurnAdmission`: the choice is made only among agents
//! currently waiting in [`LlmScheduler::acquire`] (the real contenders); the
//! preferred waiter is itself looping in `acquire`, so progress is always made.
//! No lock is held across an `await`, and the returned [`LlmCoreSlot`] is an
//! RAII guard that frees the core (and wakes the next waiter) on drop.

use crate::agent_struct::AgentId;

/// Default number of LLM cores when the caller doesn't specify one.
pub const DEFAULT_LLM_CORES: usize = 4;

/// A single waiting LLM request: which agent, and its scheduling priority
/// (nice — lower is higher priority, Linux semantics).
#[derive(Debug, Clone, Copy)]
struct Waiter {
    nice: i8,
    /// Monotonic sequence number — tie-breaks equal-nice waiters in FIFO order
    /// so admission is deterministic and starvation-free among equals.
    seq: u64,
    enqueued_at: std::time::Instant,
}

struct SchedInner {
    /// Cores currently handed out (in flight).
    in_flight: usize,
    /// Total cores in the pool.
    cores: usize,
    max_waiters: usize,
    /// Agents currently blocked in `acquire`.
    waiters: Vec<Waiter>,
    /// Next sequence number to hand to a waiter.
    next_seq: u64,
}

/// Priority-aware admission gate for LLM requests.
pub struct LlmScheduler {
    state: std::sync::Mutex<SchedInner>,
    notify: tokio::sync::Notify,
    admitted_total: std::sync::atomic::AtomicU64,
    cancelled_total: std::sync::atomic::AtomicU64,
    wait_ns_total: std::sync::atomic::AtomicU64,
    run_ns_total: std::sync::atomic::AtomicU64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LlmSchedulerMetrics {
    pub in_flight: usize,
    pub waiting: usize,
    pub cores: usize,
    pub queue_capacity: usize,
    pub admitted_total: u64,
    pub cancelled_total: u64,
    pub wait_ns_total: u64,
    pub run_ns_total: u64,
}

impl LlmScheduler {
    /// Create a scheduler with `cores` LLM cores (at least 1).
    pub fn new(cores: usize) -> Self {
        let cores = cores.max(1);
        Self::with_queue_limit(cores, cores.saturating_mul(64).max(64))
    }

    pub fn with_queue_limit(cores: usize, max_waiters: usize) -> Self {
        let cores = cores.max(1);
        Self {
            state: std::sync::Mutex::new(SchedInner {
                in_flight: 0,
                cores,
                max_waiters: max_waiters.max(1),
                waiters: Vec::new(),
                next_seq: 0,
            }),
            notify: tokio::sync::Notify::new(),
            admitted_total: std::sync::atomic::AtomicU64::new(0),
            cancelled_total: std::sync::atomic::AtomicU64::new(0),
            wait_ns_total: std::sync::atomic::AtomicU64::new(0),
            run_ns_total: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Total number of cores in the pool.
    pub fn cores(&self) -> usize {
        self.state.lock().unwrap().cores
    }

    /// Number of cores currently free.
    pub fn available(&self) -> usize {
        let st = self.state.lock().unwrap();
        st.cores.saturating_sub(st.in_flight)
    }

    /// Number of LLM requests currently executing (cores handed out).
    pub fn in_flight(&self) -> usize {
        self.state.lock().unwrap().in_flight
    }

    /// Provider requests currently waiting for an LLM core.
    pub fn waiting(&self) -> usize {
        self.state.lock().unwrap().waiters.len()
    }

    pub fn metrics(&self) -> LlmSchedulerMetrics {
        use std::sync::atomic::Ordering;
        let state = self.state.lock().unwrap();
        LlmSchedulerMetrics {
            in_flight: state.in_flight,
            waiting: state.waiters.len(),
            cores: state.cores,
            queue_capacity: state.max_waiters,
            admitted_total: self.admitted_total.load(Ordering::Relaxed),
            cancelled_total: self.cancelled_total.load(Ordering::Relaxed),
            wait_ns_total: self.wait_ns_total.load(Ordering::Relaxed),
            run_ns_total: self.run_ns_total.load(Ordering::Relaxed),
        }
    }

    /// Pick the preferred waiter by aged priority, then FIFO. Every full second
    /// of waiting improves effective nice by one until -20, so a low-priority
    /// request eventually ties new high-priority arrivals and its older
    /// sequence wins. This is bounded aging, not Linux priority inheritance.
    fn preferred(waiters: &[Waiter]) -> Option<Waiter> {
        waiters
            .iter()
            .min_by(|a, b| {
                let effective = |waiter: &Waiter| {
                    waiter
                        .nice
                        .saturating_sub(waiter.enqueued_at.elapsed().as_secs().min(39) as i8)
                        .max(-20)
                };
                effective(a).cmp(&effective(b)).then(a.seq.cmp(&b.seq))
            })
            .copied()
    }

    /// Acquire an LLM core for `agent_id`, blocking until a core is free and this
    /// agent is the highest-priority waiter. The returned [`LlmCoreSlot`] frees
    /// the core (and wakes the next waiter) on drop.
    ///
    /// `nice` follows Linux semantics: lower = higher priority. Uncontended
    /// requests admit immediately (no added latency when cores are free).
    pub async fn acquire(&self, agent_id: AgentId, nice: i8) -> LlmCoreSlot<'_> {
        self.acquire_inner(agent_id, nice, None)
            .await
            .expect("uncancelled LLM admission queue unexpectedly full")
    }

    pub async fn acquire_cancellable(
        &self,
        agent_id: AgentId,
        nice: i8,
        cancellation: &tokio_util::sync::CancellationToken,
    ) -> Result<LlmCoreSlot<'_>, crate::SchedulerError> {
        self.acquire_inner(agent_id, nice, Some(cancellation)).await
    }

    async fn acquire_inner(
        &self,
        agent_id: AgentId,
        nice: i8,
        cancellation: Option<&tokio_util::sync::CancellationToken>,
    ) -> Result<LlmCoreSlot<'_>, crate::SchedulerError> {
        // Register as a contender exactly once, with a monotonic sequence.
        let my_seq = {
            let mut st = self.state.lock().unwrap();
            if st.waiters.len() >= st.max_waiters {
                return Err(crate::SchedulerError::LlmQueueFull {
                    capacity: st.max_waiters,
                });
            }
            let seq = st.next_seq;
            st.next_seq = st.next_seq.wrapping_add(1);
            st.waiters.push(Waiter {
                nice,
                seq,
                enqueued_at: std::time::Instant::now(),
            });
            seq
        };
        let mut registration = LlmWaitRegistration {
            scheduler: self,
            seq: my_seq,
            admitted: false,
        };
        loop {
            // If a core is free, snapshot the preferred waiter without holding
            // the lock across the (async) wait below.
            let preferred = {
                let st = self.state.lock().unwrap();
                if st.in_flight < st.cores {
                    Self::preferred(&st.waiters)
                } else {
                    None
                }
            };
            if let Some(chosen) = preferred {
                if chosen.seq == my_seq {
                    let mut st = self.state.lock().unwrap();
                    // Re-check under the lock: a core is still free and we're
                    // still registered (a concurrent drop/admit may have raced).
                    let still_registered = st.waiters.iter().any(|w| w.seq == my_seq);
                    if st.in_flight < st.cores && still_registered {
                        let position = st
                            .waiters
                            .iter()
                            .position(|waiter| waiter.seq == my_seq)
                            .expect("registered waiter");
                        let waiter = st.waiters.remove(position);
                        st.in_flight += 1;
                        drop(st);
                        registration.admitted = true;
                        use std::sync::atomic::Ordering;
                        self.admitted_total.fetch_add(1, Ordering::Relaxed);
                        self.wait_ns_total.fetch_add(
                            waiter
                                .enqueued_at
                                .elapsed()
                                .as_nanos()
                                .min(u128::from(u64::MAX)) as u64,
                            Ordering::Relaxed,
                        );
                        return Ok(LlmCoreSlot {
                            sched: self,
                            started_at: std::time::Instant::now(),
                        });
                    }
                }
            }
            // Not admitted yet — wait for a core to free. The short timeout is a
            // safety net against a missed notification; releases notify directly.
            if let Some(cancellation) = cancellation {
                tokio::select! {
                    _ = cancellation.cancelled() => {
                        return Err(crate::SchedulerError::LlmAdmissionCancelled(agent_id));
                    }
                    _ = self.notify.notified() => {}
                    _ = tokio::time::sleep(std::time::Duration::from_millis(25)) => {}
                }
            } else {
                let _ = tokio::time::timeout(
                    std::time::Duration::from_millis(25),
                    self.notify.notified(),
                )
                .await;
            }
        }
    }
}

struct LlmWaitRegistration<'a> {
    scheduler: &'a LlmScheduler,
    seq: u64,
    admitted: bool,
}

impl Drop for LlmWaitRegistration<'_> {
    fn drop(&mut self) {
        if self.admitted {
            return;
        }
        let removed = {
            let mut state = self.scheduler.state.lock().unwrap();
            let before = state.waiters.len();
            state.waiters.retain(|waiter| waiter.seq != self.seq);
            state.waiters.len() != before
        };
        if removed {
            use std::sync::atomic::Ordering;
            self.scheduler
                .cancelled_total
                .fetch_add(1, Ordering::Relaxed);
            self.scheduler.notify.notify_waiters();
        }
    }
}

/// RAII LLM-core slot. Frees the core and wakes the next waiter on drop.
pub struct LlmCoreSlot<'a> {
    sched: &'a LlmScheduler,
    started_at: std::time::Instant,
}

impl Drop for LlmCoreSlot<'_> {
    fn drop(&mut self) {
        {
            let mut st = self.sched.state.lock().unwrap();
            st.in_flight = st.in_flight.saturating_sub(1);
        }
        use std::sync::atomic::Ordering;
        self.sched.run_ns_total.fetch_add(
            self.started_at
                .elapsed()
                .as_nanos()
                .min(u128::from(u64::MAX)) as u64,
            Ordering::Relaxed,
        );
        self.sched.notify.notify_waiters();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[tokio::test]
    async fn n_cores_admit_n_concurrent_immediately() {
        let sched = LlmScheduler::new(4);
        let s1 = sched.acquire(1, 0).await;
        let s2 = sched.acquire(2, 0).await;
        let s3 = sched.acquire(3, 0).await;
        let s4 = sched.acquire(4, 0).await;
        assert_eq!(sched.in_flight(), 4);
        assert_eq!(sched.available(), 0);
        assert_eq!(sched.cores(), 4);
        drop((s1, s2, s3, s4));
        assert_eq!(sched.in_flight(), 0);
        assert_eq!(sched.available(), 4);
    }

    #[tokio::test]
    async fn nplus_one_waits_until_release() {
        let sched = Arc::new(LlmScheduler::new(1));
        let held = sched.acquire(1, 0).await;
        assert_eq!(sched.in_flight(), 1);

        // The 2nd request must block while the single core is held.
        let waiter = {
            let sched = sched.clone();
            tokio::spawn(async move {
                let _slot = sched.acquire(2, 0).await;
                // Hold briefly so the test can observe in_flight from outside.
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            })
        };

        // Give the waiter time to register and confirm it is NOT admitted.
        tokio::time::sleep(std::time::Duration::from_millis(60)).await;
        assert_eq!(sched.in_flight(), 1, "waiter must not preempt held core");

        // Release the core; the waiter should now acquire it.
        drop(held);
        waiter.await.unwrap();
        assert_eq!(sched.in_flight(), 0);
    }

    #[tokio::test]
    async fn higher_priority_waiter_served_first_under_contention() {
        // Single core forces strict ordering. Two waiters contend; the
        // lower-nice (higher-priority) one must be admitted first. Ordering is
        // gated on explicit slot-release sequencing, not wall-clock races.
        let sched = Arc::new(LlmScheduler::new(1));
        let holder = sched.acquire(1, 0).await;

        let order = Arc::new(tokio::sync::Mutex::new(Vec::<AgentId>::new()));
        let mut tasks = Vec::new();
        // Spawn the low-priority (nice=10) waiter first, then the high-priority
        // (nice=-10) one — to prove ordering follows nice, not arrival order.
        for (id, nice) in [(2u64, 10i8), (3u64, -10i8)] {
            let (sched, order) = (sched.clone(), order.clone());
            tasks.push(tokio::spawn(async move {
                let _slot = sched.acquire(id, nice).await;
                order.lock().await.push(id);
                // Hold briefly so admissions are observably sequential.
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }));
            // Stagger spawns so the low-priority waiter registers first.
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        // Ensure both are registered as waiters before the core frees.
        tokio::time::sleep(std::time::Duration::from_millis(80)).await;
        drop(holder);

        for t in tasks {
            t.await.unwrap();
        }
        // Agent 3 (nice=-10) must be admitted before agent 2 (nice=10),
        // despite agent 2 having arrived first.
        assert_eq!(*order.lock().await, vec![3, 2]);
    }

    #[tokio::test]
    async fn equal_priority_is_fifo() {
        // Equal nice → FIFO by arrival (seq) so equals don't starve. Stagger
        // registration so arrival order is deterministic: 2 before 3.
        let sched = Arc::new(LlmScheduler::new(1));
        let holder = sched.acquire(1, 0).await;

        let order = Arc::new(tokio::sync::Mutex::new(Vec::<AgentId>::new()));
        let mut tasks = Vec::new();
        for id in [2u64, 3u64] {
            let (sched, order) = (sched.clone(), order.clone());
            tasks.push(tokio::spawn(async move {
                let _slot = sched.acquire(id, 0).await;
                order.lock().await.push(id);
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }));
            tokio::time::sleep(std::time::Duration::from_millis(15)).await;
        }
        tokio::time::sleep(std::time::Duration::from_millis(80)).await;
        drop(holder);
        for t in tasks {
            t.await.unwrap();
        }
        assert_eq!(*order.lock().await, vec![2, 3]);
    }

    #[tokio::test]
    async fn cancelled_llm_waiter_is_removed_and_metrics_update() {
        let sched = Arc::new(LlmScheduler::with_queue_limit(1, 2));
        let held = sched.acquire(1, 0).await;
        let cancellation = tokio_util::sync::CancellationToken::new();
        let waiter = {
            let sched = Arc::clone(&sched);
            let cancellation = cancellation.clone();
            tokio::spawn(async move {
                let _slot = sched.acquire_cancellable(2, 0, &cancellation).await?;
                Ok::<(), crate::SchedulerError>(())
            })
        };
        while sched.waiting() != 1 {
            tokio::task::yield_now().await;
        }
        cancellation.cancel();
        assert!(matches!(
            waiter.await.unwrap(),
            Err(crate::SchedulerError::LlmAdmissionCancelled(2))
        ));
        assert_eq!(sched.waiting(), 0);
        assert_eq!(sched.metrics().cancelled_total, 1);
        drop(held);
    }

    #[tokio::test]
    async fn cores_is_at_least_one() {
        let sched = LlmScheduler::new(0);
        assert_eq!(sched.cores(), 1);
    }
}
