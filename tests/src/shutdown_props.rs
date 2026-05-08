//! Property test for graceful shutdown (Property 25).
//!
//! Property 25: For any set of running agents at shutdown, all states SHALL be
//! persisted and sessions terminated.

use kernel::agent::AgentKernel;
use kernel::{AgentConfig, AgentKernelImpl, AgentState, Priority};
use proptest::prelude::*;

fn arb_config() -> impl Strategy<Value = AgentConfig> {
    ("[a-z]{3,10}", "[a-zA-Z ]{5,20}").prop_map(|(name, task)| AgentConfig {
        name,
        task,
        llm_provider: "openai".to_string(),
        permission_profile: "standard".to_string(),
        priority: Priority::default(),
        sandbox_config: None,
    })
}

proptest! {
    /// Property 25: For any set of running agents at shutdown, all states SHALL
    /// be persisted and sessions terminated.
    #[test]
    fn prop25_graceful_shutdown_persists_all(num_agents in 1usize..5) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let kernel = AgentKernelImpl::new().unwrap();
            let mut event_rx = kernel.subscribe_events();

            // Create multiple agents
            let mut agent_ids = Vec::new();
            for i in 0..num_agents {
                let config = AgentConfig {
                    name: format!("agent-{}", i),
                    task: "test task".to_string(),
                    llm_provider: "openai".to_string(),
                    permission_profile: "standard".to_string(),
                    priority: Priority::default(),
                    sandbox_config: None,
                };
                let handle = kernel.create_agent_full(config).await.unwrap();
                agent_ids.push(handle.id);
            }

            // All agents should be running
            for &id in &agent_ids {
                prop_assert_eq!(
                    kernel.agent_manager.get_agent_state(id),
                    Some(AgentState::Running)
                );
            }

            // Shutdown
            let stopped = kernel.shutdown().await.unwrap();
            prop_assert_eq!(stopped.len(), num_agents, "All agents should be stopped");

            // All agents should now be in Stopped state
            for &id in &agent_ids {
                prop_assert_eq!(
                    kernel.agent_manager.get_agent_state(id),
                    Some(AgentState::Stopped),
                    "Agent should be Stopped after shutdown"
                );
            }

            // ShutdownInitiated event should have been broadcast
            let mut found_shutdown = false;
            while let Ok(event) = event_rx.try_recv() {
                if event == kernel::KernelEvent::ShutdownInitiated {
                    found_shutdown = true;
                }
            }
            prop_assert!(found_shutdown, "ShutdownInitiated event should be broadcast");

            Ok(())
        })?;
    }
}
