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
