//! Completely Fair Scheduler (CFS) — fair token allocation for agents.
//!
//! Like Linux CFS. Uses virtual runtime to ensure every agent gets
//! a fair share of tokens proportional to its weight (nice value).

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
    #[allow(dead_code)]
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
        for (&(_, id), _) in self.runqueue.iter() {
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
}

struct AdmissionInner {
    running: usize,
    max_concurrent: usize,
    waiters: Vec<AgentId>,
}

impl TurnAdmission {
    pub fn new(max_concurrent: usize) -> Self {
        Self {
            state: std::sync::Mutex::new(AdmissionInner {
                running: 0,
                max_concurrent: max_concurrent.max(1),
                waiters: Vec::new(),
            }),
            notify: tokio::sync::Notify::new(),
        }
    }

    /// Number of turns currently admitted (running).
    pub fn running(&self) -> usize {
        self.state.lock().unwrap().running
    }

    /// Acquire a turn slot for `agent_id`, blocking until a slot is free and
    /// this agent is the CFS-preferred waiter. The returned [`TurnSlot`] frees
    /// the slot (and wakes the next waiter) on drop. `cfs` is consulted only to
    /// order contenders; its lock is never held across the wait.
    pub async fn acquire<'a>(
        &'a self,
        agent_id: AgentId,
        cfs: &tokio::sync::Mutex<CfsScheduler>,
    ) -> TurnSlot<'a> {
        // Register as a contender exactly once.
        {
            let mut st = self.state.lock().unwrap();
            st.waiters.push(agent_id);
        }
        loop {
            // Snapshot the waiter set if a slot is free — without holding the
            // state lock across the (async) cfs lock below.
            let waiters = {
                let st = self.state.lock().unwrap();
                (st.running < st.max_concurrent).then(|| st.waiters.clone())
            };
            if let Some(waiters) = waiters {
                let chosen = {
                    let cfs = cfs.lock().await;
                    cfs.pick_among(&waiters)
                };
                // If CFS has no opinion (agent not enqueued), don't starve it.
                if chosen.map_or(true, |c| c == agent_id) {
                    let mut st = self.state.lock().unwrap();
                    if st.running < st.max_concurrent && st.waiters.contains(&agent_id) {
                        st.running += 1;
                        st.waiters.retain(|a| *a != agent_id);
                        return TurnSlot { admission: self };
                    }
                }
            }
            // Not admitted yet — wait for a slot to free. The short timeout is a
            // safety net against a missed notification; releases notify directly.
            let _ =
                tokio::time::timeout(std::time::Duration::from_millis(25), self.notify.notified())
                    .await;
        }
    }
}

/// RAII turn slot. Frees the admission slot and wakes the next waiter on drop.
pub struct TurnSlot<'a> {
    admission: &'a TurnAdmission,
}

impl Drop for TurnSlot<'_> {
    fn drop(&mut self) {
        {
            let mut st = self.admission.state.lock().unwrap();
            st.running = st.running.saturating_sub(1);
        }
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

    #[tokio::test]
    async fn turn_admission_uncontended_admits_immediately() {
        let cfs = tokio::sync::Mutex::new(CfsScheduler::new(1000));
        cfs.lock().await.enqueue(1, 0, SchedClass::Normal);
        let adm = TurnAdmission::new(2);
        let slot = adm.acquire(1, &cfs).await;
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
        let holder = adm.acquire(1, &cfs).await;

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
