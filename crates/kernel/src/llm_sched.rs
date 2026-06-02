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
    #[allow(dead_code)]
    agent_id: AgentId,
    nice: i8,
    /// Monotonic sequence number — tie-breaks equal-nice waiters in FIFO order
    /// so admission is deterministic and starvation-free among equals.
    seq: u64,
}

struct SchedInner {
    /// Cores currently handed out (in flight).
    in_flight: usize,
    /// Total cores in the pool.
    cores: usize,
    /// Agents currently blocked in `acquire`.
    waiters: Vec<Waiter>,
    /// Next sequence number to hand to a waiter.
    next_seq: u64,
}

/// Priority-aware admission gate for LLM requests.
pub struct LlmScheduler {
    state: std::sync::Mutex<SchedInner>,
    notify: tokio::sync::Notify,
}

impl LlmScheduler {
    /// Create a scheduler with `cores` LLM cores (at least 1).
    pub fn new(cores: usize) -> Self {
        Self {
            state: std::sync::Mutex::new(SchedInner {
                in_flight: 0,
                cores: cores.max(1),
                waiters: Vec::new(),
                next_seq: 0,
            }),
            notify: tokio::sync::Notify::new(),
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

    /// Pick the preferred waiter (lowest nice, then lowest seq) from a snapshot.
    fn preferred(waiters: &[Waiter]) -> Option<Waiter> {
        waiters
            .iter()
            .min_by(|a, b| a.nice.cmp(&b.nice).then(a.seq.cmp(&b.seq)))
            .copied()
    }

    /// Acquire an LLM core for `agent_id`, blocking until a core is free and this
    /// agent is the highest-priority waiter. The returned [`LlmCoreSlot`] frees
    /// the core (and wakes the next waiter) on drop.
    ///
    /// `nice` follows Linux semantics: lower = higher priority. Uncontended
    /// requests admit immediately (no added latency when cores are free).
    pub async fn acquire(&self, agent_id: AgentId, nice: i8) -> LlmCoreSlot<'_> {
        // Register as a contender exactly once, with a monotonic sequence.
        let my_seq = {
            let mut st = self.state.lock().unwrap();
            let seq = st.next_seq;
            st.next_seq += 1;
            st.waiters.push(Waiter {
                agent_id,
                nice,
                seq,
            });
            seq
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
                        st.in_flight += 1;
                        st.waiters.retain(|w| w.seq != my_seq);
                        return LlmCoreSlot { sched: self };
                    }
                }
            }
            // Not admitted yet — wait for a core to free. The short timeout is a
            // safety net against a missed notification; releases notify directly.
            let _ =
                tokio::time::timeout(std::time::Duration::from_millis(25), self.notify.notified())
                    .await;
        }
    }
}

/// RAII LLM-core slot. Frees the core and wakes the next waiter on drop.
pub struct LlmCoreSlot<'a> {
    sched: &'a LlmScheduler,
}

impl Drop for LlmCoreSlot<'_> {
    fn drop(&mut self) {
        {
            let mut st = self.sched.state.lock().unwrap();
            st.in_flight = st.in_flight.saturating_sub(1);
        }
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
    async fn cores_is_at_least_one() {
        let sched = LlmScheduler::new(0);
        assert_eq!(sched.cores(), 1);
    }
}
