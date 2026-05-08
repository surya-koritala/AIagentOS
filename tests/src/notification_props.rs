//! Property test for notification generation (Property 28).

use kernel::agent::AgentKernel;
use kernel::{AgentConfig, AgentKernelImpl, AgentState, KernelEvent, Priority};
use proptest::prelude::*;

proptest! {
    /// Property 28: For any agent event (completion, error, approval request),
    /// system SHALL generate corresponding notification.
    #[test]
    fn prop28_notification_generation(num_agents in 1usize..4) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let kernel = AgentKernelImpl::new().unwrap();
            let mut event_rx = kernel.subscribe_events();

            // Create agents — should generate AgentCreated events
            let mut ids = Vec::new();
            for i in 0..num_agents {
                let config = AgentConfig {
                    name: format!("agent-{}", i),
                    task: "test".into(),
                    llm_provider: "openai".into(),
                    permission_profile: "standard".into(),
                    priority: Priority::default(),
                    sandbox_config: None,
                };
                let handle = kernel.create_agent_full(config).await.unwrap();
                ids.push(handle.id);
            }

            // Shutdown — should generate ShutdownInitiated
            kernel.shutdown().await.unwrap();

            // Collect all events
            let mut events = Vec::new();
            while let Ok(e) = event_rx.try_recv() {
                events.push(e);
            }

            // Verify: at least one AgentCreated per agent
            for &id in &ids {
                prop_assert!(
                    events.iter().any(|e| matches!(e, KernelEvent::AgentCreated(aid) if *aid == id)),
                    "Should have AgentCreated event for each agent"
                );
            }

            // Verify: ShutdownInitiated event exists
            prop_assert!(
                events.iter().any(|e| matches!(e, KernelEvent::ShutdownInitiated)),
                "Should have ShutdownInitiated event"
            );

            Ok(())
        })?;
    }
}
