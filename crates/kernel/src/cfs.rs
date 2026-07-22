//! CFS-inspired cooperative turn scheduler — fair token accounting for agents.
//!
//! This is not Linux's CPU scheduler and does not preempt model execution. It
//! uses Linux CFS weight values and virtual runtime to order *waiting turns* at
//! cooperative boundaries. Modern Linux uses EEVDF deadlines/lag and operates
//! on nanosecond CPU runtime; this module accounts model tokens and admits whole
//! turns. See `docs/SCHEDULER.md` for the precise contract.

use std::collections::BTreeMap;

use crate::agent_struct::{AgentId, SchedClass};

/// Weight derived from nice value (like Linux sched_prio_to_weight).
fn nice_to_weight(nice: i8) -> u64 {
    // Nice -20 = weight 88761, nice 0 = 1024, nice +19 = 15
    let clamped = nice.clamp(-20, 19);
    let idx = (clamped + 20) as usize;
    const WEIGHTS: [u64; 40] = [
        88761, 71755, 56483, 46273, 36291, 29154, 23254, 18705, 14949, 11916, 9548, 7620, 6100,
        4904, 3906, 3121, 2501, 1991, 1586, 1277, 1024, 820, 655, 526, 423, 335, 272, 215, 172,
        137, 110, 87, 70, 56, 45, 36, 29, 23, 18, 15,
    ];
    WEIGHTS[idx]
}

/// A runnable agent in the CFS tree.
#[derive(Debug, Clone)]
struct CfsEntry {
    agent_id: AgentId,
    vruntime: u64,
    weight: u64,
    nice: i8,
    #[allow(dead_code)]
    class: SchedClass,
    tokens_used: u64,
}

/// The CFS scheduler.
pub struct CfsScheduler {
    /// Red-black tree equivalent (BTreeMap keyed by vruntime).
    /// Key: (vruntime, agent_id) to handle equal vruntimes.
    runqueue: BTreeMap<(u64, AgentId), CfsEntry>,
    /// Real-time queue (always runs first).
    rt_queue: Vec<CfsEntry>,
    /// Background queue (only runs when normal queue is empty).
    bg_queue: Vec<CfsEntry>,
    /// Minimum vruntime (floor for new agents).
    min_vruntime: u64,
    /// Time slice in tokens (how many tokens per scheduling round).
    time_slice_tokens: u64,
    /// Total weight of all runnable agents.
    total_weight: u64,
}

impl CfsScheduler {
    pub fn new(time_slice_tokens: u64) -> Self {
        Self {
            runqueue: BTreeMap::new(),
            rt_queue: Vec::new(),
            bg_queue: Vec::new(),
            min_vruntime: 0,
            time_slice_tokens,
            total_weight: 0,
        }
    }

    /// Add an agent to the scheduler.
    pub fn enqueue(&mut self, agent_id: AgentId, nice: i8, class: SchedClass) {
        let weight = nice_to_weight(nice);
        let entry = CfsEntry {
            agent_id,
            vruntime: self.min_vruntime,
            weight,
            nice,
            class,
            tokens_used: 0,
        };

        match class {
            SchedClass::RealTime => self.rt_queue.push(entry),
            SchedClass::Background => self.bg_queue.push(entry),
            _ => {
                self.total_weight += weight;
                self.runqueue.insert((self.min_vruntime, agent_id), entry);
            }
        }
    }

    /// Remove an agent from the scheduler.
    pub fn dequeue(&mut self, agent_id: AgentId) {
        // Try normal queue
        let key = self.runqueue.keys().find(|k| k.1 == agent_id).cloned();
        if let Some(key) = key {
            if let Some(entry) = self.runqueue.remove(&key) {
                self.total_weight -= entry.weight;
            }
            return;
        }
        // Try RT queue
        self.rt_queue.retain(|e| e.agent_id != agent_id);
        // Try BG queue
        self.bg_queue.retain(|e| e.agent_id != agent_id);
    }

    /// Change an agent's nice value without erasing its vruntime or token debt.
    /// This is the only supported live-priority update path.
    pub fn update_nice(&mut self, agent_id: AgentId, nice: i8) -> bool {
        let nice = nice.clamp(-20, 19);
        let new_weight = nice_to_weight(nice);
        let key = self.runqueue.keys().find(|key| key.1 == agent_id).cloned();
        if let Some(key) = key {
            if let Some(mut entry) = self.runqueue.remove(&key) {
                self.total_weight = self.total_weight.saturating_sub(entry.weight);
                entry.nice = nice;
                entry.weight = new_weight;
                self.total_weight = self.total_weight.saturating_add(new_weight);
                self.runqueue.insert((entry.vruntime, agent_id), entry);
                return true;
            }
        }
        for entry in &mut self.rt_queue {
            if entry.agent_id == agent_id {
                entry.nice = nice;
                entry.weight = new_weight;
                return true;
            }
        }
        for entry in &mut self.bg_queue {
            if entry.agent_id == agent_id {
                entry.nice = nice;
                entry.weight = new_weight;
                return true;
            }
        }
        false
    }

    pub fn vruntime_of(&self, agent_id: AgentId) -> Option<u64> {
        self.runqueue
            .values()
            .find(|entry| entry.agent_id == agent_id)
            .map(|entry| entry.vruntime)
    }

    pub fn tokens_used_of(&self, agent_id: AgentId) -> Option<u64> {
        self.runqueue
            .values()
            .find(|entry| entry.agent_id == agent_id)
            .map(|entry| entry.tokens_used)
            .or_else(|| {
                self.rt_queue
                    .iter()
                    .chain(&self.bg_queue)
                    .find(|entry| entry.agent_id == agent_id)
                    .map(|entry| entry.tokens_used)
            })
    }

    /// Pick the next agent to run (lowest vruntime = most deserving).
    pub fn pick_next(&mut self) -> Option<AgentId> {
        // Real-time agents always go first
        if !self.rt_queue.is_empty() {
            return Some(self.rt_queue[0].agent_id);
        }
        // Normal CFS: pick lowest vruntime
        if let Some((&key, _)) = self.runqueue.iter().next() {
            return Some(key.1);
        }
        // Background: only if nothing else
        if !self.bg_queue.is_empty() {
            return Some(self.bg_queue[0].agent_id);
        }
        None
    }

    /// Pick the most-deserving agent **among `candidates`** (CFS order:
    /// RealTime first, then lowest vruntime in the normal runqueue, then
    /// Background). Returns `None` if none of the candidates are enqueued.
    ///
    /// Unlike [`pick_next`](Self::pick_next), this restricts the choice to a
    /// given set — the agents actually contending for a turn — so turn-admission
    /// ordering reflects who *wants* to run, not every enqueued agent.
    pub fn pick_among(&self, candidates: &[AgentId]) -> Option<AgentId> {
        if candidates.is_empty() {
            return None;
        }
        // RealTime candidates first (queue order).
        for e in &self.rt_queue {
            if candidates.contains(&e.agent_id) {
                return Some(e.agent_id);
            }
        }
        // Normal: the runqueue is ordered by (vruntime, id), so the first
        // candidate encountered is the lowest-vruntime one.
        for &(_, id) in self.runqueue.keys() {
            if candidates.contains(&id) {
                return Some(id);
            }
        }
        // Background last.
        for e in &self.bg_queue {
            if candidates.contains(&e.agent_id) {
                return Some(e.agent_id);
            }
        }
        None
    }

    /// Record that an agent used tokens (advances its vruntime).
    pub fn account_tokens(&mut self, agent_id: AgentId, tokens: u64) {
        let key = self.runqueue.keys().find(|k| k.1 == agent_id).cloned();
        if let Some(key) = key {
            if let Some(mut entry) = self.runqueue.remove(&key) {
                // vruntime advances inversely proportional to weight
                // Higher weight = slower vruntime growth = more CPU time
                let delta = (tokens * 1024) / entry.weight;
                entry.vruntime += delta;
                entry.tokens_used += tokens;
                // Update min_vruntime
                if entry.vruntime > self.min_vruntime {
                    self.min_vruntime = self
                        .runqueue
                        .keys()
                        .next()
                        .map(|k| k.0)
                        .unwrap_or(entry.vruntime);
                }
                self.runqueue.insert((entry.vruntime, agent_id), entry);
            }
        }
    }

    /// Check if current agent's time slice is expired.
    pub fn time_slice_expired(&self, agent_id: AgentId) -> bool {
        let key = self.runqueue.keys().find(|k| k.1 == agent_id);
        if let Some(key) = key {
            if let Some(entry) = self.runqueue.get(key) {
                return entry.tokens_used >= self.time_slice_tokens;
            }
        }
        false
    }

    /// Reset time slice for an agent (after preemption).
    pub fn reset_slice(&mut self, agent_id: AgentId) {
        let key = self.runqueue.keys().find(|k| k.1 == agent_id).cloned();
        if let Some(key) = key {
            if let Some(entry) = self.runqueue.get_mut(&key) {
                entry.tokens_used = 0;
            }
        }
    }

    /// Read an agent's current nice value (priority hint), if enqueued.
    /// Read-only; used by the LLM-request scheduler to order contenders by
    /// priority without duplicating nice bookkeeping.
    pub fn nice_of(&self, agent_id: AgentId) -> Option<i8> {
        for e in &self.rt_queue {
            if e.agent_id == agent_id {
                return Some(e.nice);
            }
        }
        for entry in self.runqueue.values() {
            if entry.agent_id == agent_id {
                return Some(entry.nice);
            }
        }
        for e in &self.bg_queue {
            if e.agent_id == agent_id {
                return Some(e.nice);
            }
        }
        None
    }

    /// Get the number of runnable agents.
    pub fn runnable_count(&self) -> usize {
        self.runqueue.len() + self.rt_queue.len() + self.bg_queue.len()
    }

    /// Calculate fair share for an agent (tokens per scheduling period).
    pub fn fair_share(&self, agent_id: AgentId) -> u64 {
        let key = self.runqueue.keys().find(|k| k.1 == agent_id);
        if let Some(key) = key {
            if let Some(entry) = self.runqueue.get(key) {
                if let Some(share) =
                    (self.time_slice_tokens * entry.weight).checked_div(self.total_weight)
                {
                    return share;
                }
            }
        }
        self.time_slice_tokens
    }
}

/// CFS-ordered turn admission.
///
/// Bounds concurrent agent turns to `max_concurrent`. When more agents contend
/// for a turn than there are slots, the next freed slot is granted to the
/// **CFS-preferred waiter** (RealTime, else lowest vruntime) rather than FIFO —
/// so nice values affect *who runs next* under contention, not just vruntime
/// bookkeeping. Uncontended turns are admitted immediately.
///
/// Correctness: the choice is made only among agents currently waiting in
/// [`acquire`](Self::acquire) (the real contenders). Whenever a slot is free
/// the preferred waiter — which is itself looping in `acquire` — admits, so
/// progress is always made (no waiting on an agent that isn't trying to run).
pub struct TurnAdmission {
    state: std::sync::Mutex<AdmissionInner>,
    notify: tokio::sync::Notify,
    admitted_total: std::sync::atomic::AtomicU64,
    cancelled_total: std::sync::atomic::AtomicU64,
    wait_ns_total: std::sync::atomic::AtomicU64,
    run_ns_total: std::sync::atomic::AtomicU64,
    starvation_total: std::sync::atomic::AtomicU64,
}

#[derive(Clone)]
struct TurnWaiter {
    agent_id: AgentId,
    seq: u64,
    enqueued_at: std::time::Instant,
}

struct AdmissionInner {
    running: usize,
    max_concurrent: usize,
    max_waiters: usize,
    next_seq: u64,
    waiters: Vec<TurnWaiter>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TurnAdmissionMetrics {
    pub running: usize,
    pub waiting: usize,
    pub capacity: usize,
    pub queue_capacity: usize,
    pub admitted_total: u64,
    pub cancelled_total: u64,
    pub wait_ns_total: u64,
    pub run_ns_total: u64,
    pub starvation_total: u64,
}

impl TurnAdmission {
    pub fn new(max_concurrent: usize) -> Self {
        let max_concurrent = max_concurrent.max(1);
        Self::with_queue_limit(max_concurrent, max_concurrent.saturating_mul(64).max(64))
    }

    pub fn with_queue_limit(max_concurrent: usize, max_waiters: usize) -> Self {
        let max_concurrent = max_concurrent.max(1);
        Self {
            state: std::sync::Mutex::new(AdmissionInner {
                running: 0,
                max_concurrent,
                max_waiters: max_waiters.max(1),
                next_seq: 0,
                waiters: Vec::new(),
            }),
            notify: tokio::sync::Notify::new(),
            admitted_total: std::sync::atomic::AtomicU64::new(0),
            cancelled_total: std::sync::atomic::AtomicU64::new(0),
            wait_ns_total: std::sync::atomic::AtomicU64::new(0),
            run_ns_total: std::sync::atomic::AtomicU64::new(0),
            starvation_total: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Number of turns currently admitted (running).
    pub fn running(&self) -> usize {
        self.state.lock().unwrap().running
    }

    /// Maximum turns this admission gate permits concurrently.
    pub fn capacity(&self) -> usize {
        self.state.lock().unwrap().max_concurrent
    }

    /// Turns currently waiting for admission.
    pub fn waiting(&self) -> usize {
        self.state.lock().unwrap().waiters.len()
    }

    pub fn metrics(&self) -> TurnAdmissionMetrics {
        use std::sync::atomic::Ordering;
        let state = self.state.lock().unwrap();
        TurnAdmissionMetrics {
            running: state.running,
            waiting: state.waiters.len(),
            capacity: state.max_concurrent,
            queue_capacity: state.max_waiters,
            admitted_total: self.admitted_total.load(Ordering::Relaxed),
            cancelled_total: self.cancelled_total.load(Ordering::Relaxed),
            wait_ns_total: self.wait_ns_total.load(Ordering::Relaxed),
            run_ns_total: self.run_ns_total.load(Ordering::Relaxed),
            starvation_total: self.starvation_total.load(Ordering::Relaxed),
        }
    }

    /// Acquire a turn slot for `agent_id`, blocking until a slot is free and
    /// this agent is the CFS-preferred waiter. The returned [`TurnSlot`] frees
    /// the slot (and wakes the next waiter) on drop. `cfs` is consulted only to
    /// order contenders; its lock is never held across the wait.
    pub async fn acquire<'a>(
        &'a self,
        agent_id: AgentId,
        cfs: &tokio::sync::Mutex<CfsScheduler>,
    ) -> Result<TurnSlot<'a>, crate::SchedulerError> {
        self.acquire_inner(agent_id, cfs, None).await
    }

    pub async fn acquire_cancellable<'a>(
        &'a self,
        agent_id: AgentId,
        cfs: &tokio::sync::Mutex<CfsScheduler>,
        cancellation: &tokio_util::sync::CancellationToken,
    ) -> Result<TurnSlot<'a>, crate::SchedulerError> {
        self.acquire_inner(agent_id, cfs, Some(cancellation)).await
    }

    async fn acquire_inner<'a>(
        &'a self,
        agent_id: AgentId,
        cfs: &tokio::sync::Mutex<CfsScheduler>,
        cancellation: Option<&tokio_util::sync::CancellationToken>,
    ) -> Result<TurnSlot<'a>, crate::SchedulerError> {
        // Register as a contender exactly once. The registration guard removes
        // it if this future is cancelled or dropped before admission.
        let seq = {
            let mut st = self.state.lock().unwrap();
            if st.waiters.len() >= st.max_waiters {
                return Err(crate::SchedulerError::AdmissionQueueFull {
                    capacity: st.max_waiters,
                });
            }
            let seq = st.next_seq;
            st.next_seq = st.next_seq.wrapping_add(1);
            st.waiters.push(TurnWaiter {
                agent_id,
                seq,
                enqueued_at: std::time::Instant::now(),
            });
            seq
        };
        let mut registration = TurnWaitRegistration {
            admission: self,
            seq,
            admitted: false,
        };
        loop {
            // Snapshot the waiter set if a slot is free — without holding the
            // state lock across the (async) cfs lock below.
            let waiters = {
                let st = self.state.lock().unwrap();
                (st.running < st.max_concurrent).then(|| st.waiters.clone())
            };
            if let Some(waiters) = waiters {
                let candidates: Vec<_> = waiters.iter().map(|waiter| waiter.agent_id).collect();
                let chosen = {
                    let cfs = cfs.lock().await;
                    cfs.pick_among(&candidates)
                };
                // For equal/unknown CFS rank, sequence gives deterministic FIFO
                // instead of a race-dependent fallback.
                let preferred_seq = chosen
                    .and_then(|chosen| {
                        waiters
                            .iter()
                            .filter(|waiter| waiter.agent_id == chosen)
                            .map(|waiter| waiter.seq)
                            .min()
                    })
                    .or_else(|| waiters.iter().map(|waiter| waiter.seq).min());
                if preferred_seq == Some(seq) {
                    let mut st = self.state.lock().unwrap();
                    if st.running < st.max_concurrent {
                        let Some(position) = st.waiters.iter().position(|waiter| waiter.seq == seq)
                        else {
                            return Err(crate::SchedulerError::AdmissionCancelled(agent_id));
                        };
                        let waiter = st.waiters.remove(position);
                        st.running += 1;
                        drop(st);
                        registration.admitted = true;
                        let waited = waiter.enqueued_at.elapsed();
                        use std::sync::atomic::Ordering;
                        self.admitted_total.fetch_add(1, Ordering::Relaxed);
                        self.wait_ns_total.fetch_add(
                            waited.as_nanos().min(u128::from(u64::MAX)) as u64,
                            Ordering::Relaxed,
                        );
                        if waited >= std::time::Duration::from_secs(30) {
                            self.starvation_total.fetch_add(1, Ordering::Relaxed);
                        }
                        return Ok(TurnSlot {
                            admission: self,
                            started_at: std::time::Instant::now(),
                        });
                    }
                }
            }
            // Not admitted yet — wait for a slot to free. The short timeout is a
            // safety net against a missed notification; releases notify directly.
            if let Some(cancellation) = cancellation {
                tokio::select! {
                    _ = cancellation.cancelled() => {
                        return Err(crate::SchedulerError::AdmissionCancelled(agent_id));
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

struct TurnWaitRegistration<'a> {
    admission: &'a TurnAdmission,
    seq: u64,
    admitted: bool,
}

impl Drop for TurnWaitRegistration<'_> {
    fn drop(&mut self) {
        if self.admitted {
            return;
        }
        let removed = {
            let mut state = self.admission.state.lock().unwrap();
            let before = state.waiters.len();
            state.waiters.retain(|waiter| waiter.seq != self.seq);
            state.waiters.len() != before
        };
        if removed {
            use std::sync::atomic::Ordering;
            self.admission
                .cancelled_total
                .fetch_add(1, Ordering::Relaxed);
            self.admission.notify.notify_waiters();
        }
    }
}

/// RAII turn slot. Frees the admission slot and wakes the next waiter on drop.
pub struct TurnSlot<'a> {
    admission: &'a TurnAdmission,
    started_at: std::time::Instant,
}

impl Drop for TurnSlot<'_> {
    fn drop(&mut self) {
        {
            let mut st = self.admission.state.lock().unwrap();
            st.running = st.running.saturating_sub(1);
        }
        use std::sync::atomic::Ordering;
        self.admission.run_ns_total.fetch_add(
            self.started_at
                .elapsed()
                .as_nanos()
                .min(u128::from(u64::MAX)) as u64,
            Ordering::Relaxed,
        );
        self.admission.notify.notify_waiters();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enqueue_and_pick() {
        let mut sched = CfsScheduler::new(100);
        sched.enqueue(1, 0, SchedClass::Normal);
        sched.enqueue(2, 0, SchedClass::Normal);
        let next = sched.pick_next();
        assert!(next.is_some());
    }

    #[test]
    fn rt_runs_first() {
        let mut sched = CfsScheduler::new(100);
        sched.enqueue(1, 0, SchedClass::Normal);
        sched.enqueue(2, 0, SchedClass::RealTime);
        assert_eq!(sched.pick_next(), Some(2)); // RT first
    }

    #[test]
    fn bg_runs_last() {
        let mut sched = CfsScheduler::new(100);
        sched.enqueue(1, 0, SchedClass::Background);
        sched.enqueue(2, 0, SchedClass::Normal);
        assert_eq!(sched.pick_next(), Some(2)); // Normal before BG
    }

    #[test]
    fn fair_share_proportional_to_weight() {
        let mut sched = CfsScheduler::new(1000);
        sched.enqueue(1, -10, SchedClass::Normal); // high priority
        sched.enqueue(2, 10, SchedClass::Normal); // low priority
        let share1 = sched.fair_share(1);
        let share2 = sched.fair_share(2);
        assert!(share1 > share2); // higher priority gets more
    }

    #[test]
    fn vruntime_advances_slower_for_high_weight() {
        let mut sched = CfsScheduler::new(1000);
        sched.enqueue(1, -10, SchedClass::Normal); // high weight
        sched.enqueue(2, 10, SchedClass::Normal); // low weight
        sched.account_tokens(1, 100);
        sched.account_tokens(2, 100);
        // Agent 1 (high weight) should still be picked next (lower vruntime)
        assert_eq!(sched.pick_next(), Some(1));
    }

    #[test]
    fn nice_change_preserves_vruntime_and_usage_debt() {
        let mut sched = CfsScheduler::new(1000);
        sched.enqueue(1, 0, SchedClass::Normal);
        sched.account_tokens(1, 4_096);
        let vruntime = sched.vruntime_of(1).unwrap();
        let tokens = sched.tokens_used_of(1).unwrap();

        assert!(sched.update_nice(1, -10));
        assert_eq!(sched.vruntime_of(1), Some(vruntime));
        assert_eq!(sched.tokens_used_of(1), Some(tokens));
        assert_eq!(sched.nice_of(1), Some(-10));
    }

    #[test]
    fn dequeue_removes() {
        let mut sched = CfsScheduler::new(100);
        sched.enqueue(1, 0, SchedClass::Normal);
        sched.enqueue(2, 0, SchedClass::Normal);
        sched.dequeue(1);
        assert_eq!(sched.runnable_count(), 1);
        assert_eq!(sched.pick_next(), Some(2));
    }

    #[test]
    fn pick_among_restricts_to_candidates_in_cfs_order() {
        let mut sched = CfsScheduler::new(1000);
        sched.enqueue(1, 0, SchedClass::Normal);
        sched.enqueue(2, 0, SchedClass::Normal);
        sched.enqueue(3, 0, SchedClass::Normal);
        // Advance agent 1's vruntime so 2 and 3 are more deserving.
        sched.account_tokens(1, 500);
        // pick_next would consider all; pick_among restricts to the set.
        assert_eq!(sched.pick_among(&[1]), Some(1)); // only candidate
        assert_eq!(sched.pick_among(&[2, 3]), Some(2)); // lowest vruntime among {2,3}
        assert_eq!(sched.pick_among(&[]), None);
        // A candidate not enqueued is ignored.
        assert_eq!(sched.pick_among(&[99]), None);
    }

    #[test]
    fn pick_among_respects_nice_under_contention() {
        let mut sched = CfsScheduler::new(10_000);
        sched.enqueue(1, -10, SchedClass::Normal); // high priority (heavy weight)
        sched.enqueue(2, 10, SchedClass::Normal); // low priority (light weight)
                                                  // Both do the same work; the light-weight agent's vruntime races ahead.
        sched.account_tokens(1, 1000);
        sched.account_tokens(2, 1000);
        // So under contention the nice=-10 agent is the preferred next turn.
        assert_eq!(sched.pick_among(&[1, 2]), Some(1));
    }

    #[test]
    fn pick_among_realtime_precedence() {
        let mut sched = CfsScheduler::new(1000);
        sched.enqueue(1, -20, SchedClass::Normal); // very light vruntime growth
        sched.enqueue(2, 0, SchedClass::RealTime);
        assert_eq!(sched.pick_among(&[1, 2]), Some(2)); // RT beats any normal
    }

    #[test]
    fn long_mixed_nice_workload_is_weighted_and_no_normal_agent_starves() {
        let mut sched = CfsScheduler::new(10_000);
        for (id, nice) in [(1, -10), (2, 0), (3, 10)] {
            sched.enqueue(id, nice, SchedClass::Normal);
        }
        let mut turns = [0u64; 3];
        for _ in 0..20_000 {
            let id = sched.pick_next().unwrap();
            turns[id as usize - 1] += 1;
            sched.account_tokens(id, 1_024);
        }
        assert!(turns[0] > turns[1] && turns[1] > turns[2], "{turns:?}");
        assert!(turns.iter().all(|turns| *turns > 0), "{turns:?}");
        // The observed turn ratios track the same monotonic ordering as the
        // Linux weight table without asserting an implementation-fragile exact
        // ratio after integer vruntime rounding.
        assert!(sched.vruntime_of(1).unwrap() <= sched.vruntime_of(3).unwrap());
    }

    #[tokio::test]
    async fn turn_admission_uncontended_admits_immediately() {
        let cfs = tokio::sync::Mutex::new(CfsScheduler::new(1000));
        cfs.lock().await.enqueue(1, 0, SchedClass::Normal);
        let adm = TurnAdmission::new(2);
        let slot = adm.acquire(1, &cfs).await.unwrap();
        assert_eq!(adm.running(), 1);
        drop(slot);
        assert_eq!(adm.running(), 0);
    }

    #[tokio::test]
    async fn turn_admission_grants_freed_slot_in_cfs_order() {
        use std::sync::Arc;

        let cfs = Arc::new(tokio::sync::Mutex::new(CfsScheduler::new(10_000)));
        {
            let mut c = cfs.lock().await;
            c.enqueue(1, 0, SchedClass::Normal); // holder
            c.enqueue(2, 0, SchedClass::Normal); // LOW vruntime contender
            c.enqueue(3, 0, SchedClass::Normal); // HIGH vruntime contender
            c.account_tokens(3, 5000); // push agent 3's vruntime far ahead
        }
        let adm = Arc::new(TurnAdmission::new(1)); // single slot → strict ordering

        // Holder takes the only slot.
        let holder = adm.acquire(1, &cfs).await.unwrap();

        let order = Arc::new(tokio::sync::Mutex::new(Vec::<u64>::new()));
        // Spawn the two contenders (3 = HIGH vruntime, 2 = LOW vruntime).
        let mut tasks = Vec::new();
        for id in [3u64, 2u64] {
            let (adm, cfs, order) = (adm.clone(), cfs.clone(), order.clone());
            tasks.push(tokio::spawn(async move {
                let _slot = adm.acquire(id, &cfs).await;
                order.lock().await.push(id);
                // Hold briefly so admissions are observably sequential.
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }));
        }
        // Ensure both are registered as waiters before the slot frees.
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        drop(holder);

        for t in tasks {
            t.await.unwrap();
        }
        // Agent 2 (lower vruntime) must be admitted before agent 3.
        assert_eq!(*order.lock().await, vec![2, 3]);
    }

    #[tokio::test]
    async fn cancelled_turn_waiter_is_removed_without_lost_wakeup() {
        use std::sync::Arc;

        let cfs = Arc::new(tokio::sync::Mutex::new(CfsScheduler::new(1000)));
        cfs.lock().await.enqueue(1, 0, SchedClass::Normal);
        cfs.lock().await.enqueue(2, 0, SchedClass::Normal);
        let admission = Arc::new(TurnAdmission::with_queue_limit(1, 2));
        let held = admission.acquire(1, &cfs).await.unwrap();
        let cancellation = tokio_util::sync::CancellationToken::new();
        let waiting = {
            let admission = Arc::clone(&admission);
            let cfs = Arc::clone(&cfs);
            let cancellation = cancellation.clone();
            tokio::spawn(async move {
                let _slot = admission
                    .acquire_cancellable(2, &cfs, &cancellation)
                    .await?;
                Ok::<(), crate::SchedulerError>(())
            })
        };
        while admission.waiting() != 1 {
            tokio::task::yield_now().await;
        }
        cancellation.cancel();
        assert!(matches!(
            waiting.await.unwrap(),
            Err(crate::SchedulerError::AdmissionCancelled(2))
        ));
        assert_eq!(admission.waiting(), 0);
        assert_eq!(admission.metrics().cancelled_total, 1);
        drop(held);
        assert_eq!(admission.running(), 0);
    }

    #[tokio::test]
    async fn turn_queue_limit_returns_stable_overload_error() {
        use std::sync::Arc;

        let cfs = Arc::new(tokio::sync::Mutex::new(CfsScheduler::new(1000)));
        for id in 1..=3 {
            cfs.lock().await.enqueue(id, 0, SchedClass::Normal);
        }
        let admission = Arc::new(TurnAdmission::with_queue_limit(1, 1));
        let held = admission.acquire(1, &cfs).await.unwrap();
        let first = {
            let admission = Arc::clone(&admission);
            let cfs = Arc::clone(&cfs);
            tokio::spawn(async move {
                let _slot = admission.acquire(2, &cfs).await?;
                std::future::pending::<()>().await;
                Ok::<(), crate::SchedulerError>(())
            })
        };
        while admission.waiting() != 1 {
            tokio::task::yield_now().await;
        }
        assert!(matches!(
            admission.acquire(3, &cfs).await,
            Err(crate::SchedulerError::AdmissionQueueFull { capacity: 1 })
        ));
        first.abort();
        let _ = first.await;
        drop(held);
        assert_eq!(admission.waiting(), 0);
    }

    #[test]
    fn time_slice_expiry() {
        let mut sched = CfsScheduler::new(50);
        sched.enqueue(1, 0, SchedClass::Normal);
        assert!(!sched.time_slice_expired(1));
        sched.account_tokens(1, 60);
        assert!(sched.time_slice_expired(1));
    }

    #[test]
    fn nice_to_weight_range() {
        assert!(nice_to_weight(-20) > nice_to_weight(0));
        assert!(nice_to_weight(0) > nice_to_weight(19));
        assert_eq!(nice_to_weight(0), 1024);
    }
}

// ─── CFS integration with execution ─────────────────────────────────────────

/// Check if an agent should be preempted (called after each tool call).
pub fn should_preempt(sched: &mut CfsScheduler, current: AgentId) -> bool {
    sched.time_slice_expired(current)
}

/// Account tokens and check preemption in one call.
pub fn account_and_check(sched: &mut CfsScheduler, agent_id: AgentId, tokens: u64) -> bool {
    sched.account_tokens(agent_id, tokens);
    should_preempt(sched, agent_id)
}

#[cfg(test)]
mod integration_tests {
    use super::*;

    #[test]
    fn preempt_after_time_slice() {
        let mut sched = CfsScheduler::new(50);
        sched.enqueue(1, 0, SchedClass::Normal);
        sched.enqueue(2, 0, SchedClass::Normal);
        // Agent 1 uses 60 tokens (exceeds 50 slice)
        let preempt = account_and_check(&mut sched, 1, 60);
        assert!(preempt);
    }

    #[test]
    fn no_preempt_within_slice() {
        let mut sched = CfsScheduler::new(100);
        sched.enqueue(1, 0, SchedClass::Normal);
        let preempt = account_and_check(&mut sched, 1, 30);
        assert!(!preempt);
    }
}
