//! Property-based tests for Scheduler (Properties 6, 7).
//!
//! Property 6: Priority-ordered resource access without deadlock — For any set of
//! agents with distinct priorities competing for same resource, access granted in
//! priority order and all requests eventually complete.
//!
//! Property 7: Priority-based throttling under resource pressure — For any agents
//! with different priorities under constraints, lower-priority agents throttled
//! before higher-priority.

use std::sync::Arc;

use proptest::prelude::*;

use kernel::scheduler::{AgentScheduler, PriorityScheduler};
use kernel::{AgentHandle, AgentState, Priority};

fn make_handle(id: uuid::Uuid) -> AgentHandle {
    let (tx, _rx) = tokio::sync::mpsc::channel(1);
    AgentHandle { id, state: AgentState::Running, cmd_tx: tx }
}

/// Strategy for generating 2-5 priorities.
fn arb_priority_set() -> impl Strategy<Value = Vec<u8>> {
    proptest::collection::vec(1u8..=5u8, 2..=5)
}

proptest! {
    /// Property 6: For any set of agents with distinct priorities competing for
    /// the same resource, access is granted in priority order and all requests
    /// eventually complete (no deadlock).
    ///
    /// We verify:
    /// 1. Sequential resource access always completes (no deadlock)
    /// 2. The internal priority queue correctly orders by priority
    /// 3. Concurrent access with a holder results in priority-ordered waiting
    #[test]
    fn prop6_priority_ordered_resource_access(priorities in arb_priority_set()) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let sched = Arc::new(PriorityScheduler::new());

            let mut agents: Vec<(uuid::Uuid, u8)> = Vec::new();
            for &p in &priorities {
                let id = uuid::Uuid::new_v4();
                let handle = make_handle(id);
                sched.schedule(&handle).await.unwrap();
                sched.set_priority(id, Priority::new(p).unwrap());
                agents.push((id, p));
            }

            // Part 1: Sequential access — each agent requests and releases.
            // All must complete without deadlock.
            for &(id, _) in &agents {
                let result = tokio::time::timeout(
                    tokio::time::Duration::from_secs(2),
                    sched.request_resource_access(id),
                ).await;
                prop_assert!(result.is_ok(), "Should not timeout (no deadlock)");
                prop_assert!(result.unwrap().is_ok(), "Should succeed");
                sched.release_resource_access(id);
            }

            // Part 2: Verify priority queue ordering.
            // A "holder" agent grabs the resource first. Then other agents
            // queue up. When the holder releases, the highest-priority
            // waiting agent should be served next.
            let holder_id = uuid::Uuid::new_v4();
            let holder_handle = make_handle(holder_id);
            sched.schedule(&holder_handle).await.unwrap();
            sched.set_priority(holder_id, Priority::new(1).unwrap());

            // Holder grabs the resource
            sched.request_resource_access(holder_id).await.unwrap();
            prop_assert!(sched.is_next_in_queue(holder_id));

            // Other agents try to access concurrently — they will block
            let access_order = Arc::new(tokio::sync::Mutex::new(Vec::new()));
            let mut join_handles = Vec::new();

            for &(id, p) in &agents {
                let s = Arc::clone(&sched);
                let ao = Arc::clone(&access_order);
                join_handles.push(tokio::spawn(async move {
                    if s.request_resource_access(id).await.is_ok() {
                        ao.lock().await.push(p);
                        s.release_resource_access(id);
                    }
                }));
            }

            // Give spawned tasks time to queue up
            tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

            // Release the holder — this should trigger priority-ordered access
            sched.release_resource_access(holder_id);

            // Wait for all to complete
            let all_done = tokio::time::timeout(
                tokio::time::Duration::from_secs(5),
                futures::future::join_all(join_handles),
            ).await;
            prop_assert!(all_done.is_ok(), "All agents should complete (no deadlock)");

            let order = access_order.lock().await;
            prop_assert_eq!(order.len(), agents.len(), "All agents got access");

            // The order should be non-decreasing (priority-ordered)
            for i in 1..order.len() {
                prop_assert!(
                    order[i - 1] <= order[i],
                    "Access should be priority-ordered, got {:?}",
                    *order
                );
            }

            Ok(())
        })?;
    }

    /// Property 7: For any agents with different priorities under resource pressure,
    /// lower-priority agents are throttled more than higher-priority agents.
    #[test]
    fn prop7_priority_throttling_under_pressure(priorities in arb_priority_set()) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let sched = PriorityScheduler::new();

            let mut agents: Vec<(uuid::Uuid, u8)> = Vec::new();
            for &p in &priorities {
                let id = uuid::Uuid::new_v4();
                let handle = make_handle(id);
                sched.schedule(&handle).await.unwrap();
                sched.set_priority(id, Priority::new(p).unwrap());
                agents.push((id, p));
            }

            // Enable resource pressure
            sched.set_resource_pressure(true);

            // Verify: higher priority (lower value) => less or equal throttle delay
            for i in 0..agents.len() {
                for j in 0..agents.len() {
                    let (id_i, p_i) = agents[i];
                    let (id_j, p_j) = agents[j];
                    let delay_i = sched.get_throttle_delay_ms(id_i);
                    let delay_j = sched.get_throttle_delay_ms(id_j);

                    if p_i < p_j {
                        prop_assert!(
                            delay_i <= delay_j,
                            "Priority {} delay ({}) should be <= priority {} delay ({})",
                            p_i, delay_i, p_j, delay_j
                        );
                    }
                }
            }

            // Priority 1 should never be throttled
            for &(id, p) in &agents {
                if p == 1 {
                    prop_assert_eq!(sched.get_throttle_delay_ms(id), 0);
                }
            }

            // When pressure is off, no throttling for anyone
            sched.set_resource_pressure(false);
            for &(id, _) in &agents {
                prop_assert_eq!(sched.get_throttle_delay_ms(id), 0);
            }

            Ok(())
        })?;
    }
}
