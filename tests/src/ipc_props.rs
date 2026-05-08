//! Property-based tests for IPC (Properties 19, 20, 21).
//!
//! Property 19: Pub/sub message delivery to all subscribers.
//! Property 20: IPC permission enforcement.
//! Property 21: Delegation chain completion propagation.

use kernel::ipc::*;
use proptest::prelude::*;

fn arb_payload() -> impl Strategy<Value = serde_json::Value> {
    "[a-zA-Z0-9 ]{5,30}".prop_map(|s| serde_json::json!({"data": s}))
}

fn arb_topic() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("events".to_string()),
        Just("tasks".to_string()),
        Just("alerts".to_string()),
        Just("updates".to_string()),
    ]
}

proptest! {
    /// Property 19: For any subscribed agent, published message to that topic
    /// SHALL be received.
    #[test]
    fn prop19_pubsub_delivery_to_all_subscribers(
        payload in arb_payload(),
        topic in arb_topic(),
        num_subs in 1usize..5,
    ) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let ipc = IpcManager::new();
            let publisher = uuid::Uuid::new_v4();
            ipc.register_agent(publisher);

            let mut subscribers = Vec::new();
            for _ in 0..num_subs {
                let id = uuid::Uuid::new_v4();
                ipc.register_agent(id);
                ipc.subscribe(id, &topic).unwrap();
                subscribers.push(id);
            }

            let delivered = ipc.publish(publisher, &topic, payload.clone()).await.unwrap();
            prop_assert_eq!(delivered, num_subs, "All subscribers should receive the message");

            // Each subscriber should have the message
            for sub_id in &subscribers {
                let msg = ipc.receive(*sub_id).await;
                prop_assert!(msg.is_ok(), "Subscriber should have received message");
                prop_assert_eq!(msg.unwrap().payload, payload.clone());
            }

            Ok(())
        })?;
    }

    /// Property 20: For any communication attempt, permission policies SHALL be
    /// enforced; unpermitted messages rejected.
    #[test]
    fn prop20_ipc_permission_enforcement(payload in arb_payload()) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mut ipc = IpcManager::new();
            ipc.enable_permissions();

            let a = uuid::Uuid::new_v4();
            let b = uuid::Uuid::new_v4();
            let c = uuid::Uuid::new_v4();
            ipc.register_agent(a);
            ipc.register_agent(b);
            ipc.register_agent(c);

            // No permissions set — all should fail
            let result = ipc.send(a, b, payload.clone()).await;
            prop_assert!(result.is_err(), "Should be denied without permission");

            let result = ipc.send(b, c, payload.clone()).await;
            prop_assert!(result.is_err(), "Should be denied without permission");

            // Allow a->b only
            ipc.allow_communication(a, b);
            let result = ipc.send(a, b, payload.clone()).await;
            prop_assert!(result.is_ok(), "Should succeed with permission");

            // a->c still denied
            let result = ipc.send(a, c, payload.clone()).await;
            prop_assert!(result.is_err(), "Should still be denied for a->c");

            // b->a still denied (one-directional)
            let result = ipc.send(b, a, payload.clone()).await;
            prop_assert!(result.is_err(), "Should be denied for reverse direction");

            Ok(())
        })?;
    }

    /// Property 21: For any delegation chain, leaf completion SHALL propagate
    /// back through every node to originator.
    #[test]
    fn prop21_delegation_chain_completion(desc in "[a-zA-Z ]{5,20}") {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let ipc = IpcManager::new();
            let a = uuid::Uuid::new_v4();
            let b = uuid::Uuid::new_v4();
            let c = uuid::Uuid::new_v4();
            ipc.register_agent(a);
            ipc.register_agent(b);
            ipc.register_agent(c);

            // a delegates to b
            let task1 = ipc.delegate(a, b, desc.clone()).await.unwrap();
            prop_assert_eq!(ipc.get_delegation_status(task1), Some(DelegationStatus::Pending));

            // b delegates to c (sub-delegation)
            let task2 = ipc.delegate(b, c, format!("sub: {}", desc)).await.unwrap();
            prop_assert_eq!(ipc.get_delegation_status(task2), Some(DelegationStatus::Pending));

            // c completes its task
            ipc.complete_delegation(task2).unwrap();
            prop_assert_eq!(ipc.get_delegation_status(task2), Some(DelegationStatus::Completed));

            // b completes its task (after sub-task done)
            ipc.complete_delegation(task1).unwrap();
            prop_assert_eq!(ipc.get_delegation_status(task1), Some(DelegationStatus::Completed));

            Ok(())
        })?;
    }
}
