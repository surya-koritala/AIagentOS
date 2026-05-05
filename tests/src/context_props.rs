//! Property-based tests for Context Management (Properties 1, 2).
//!
//! Property 1: Context persistence round-trip — For any agent context,
//! persist then restore SHALL produce equivalent context.
//!
//! Property 2: Context summarization respects token limit — For any context
//! exceeding token limit, summarization SHALL produce context within limit.

use proptest::prelude::*;

use chrono::Utc;
use kernel::context::*;

fn arb_message() -> impl Strategy<Value = Message> {
    ("[a-z]{3,10}", "[a-zA-Z0-9 ]{5,100}")
        .prop_map(|(role, content)| Message {
            role,
            content,
            timestamp: Utc::now(),
        })
}

fn arb_task() -> impl Strategy<Value = Task> {
    ("[a-zA-Z ]{5,30}", prop_oneof![Just("pending"), Just("done"), Just("in_progress")])
        .prop_map(|(desc, status)| Task {
            id: uuid::Uuid::new_v4(),
            description: desc,
            status: status.to_string(),
            created_at: Utc::now(),
        })
}

fn arb_task_result() -> impl Strategy<Value = TaskResult> {
    any::<bool>().prop_map(|success| TaskResult {
        task_id: uuid::Uuid::new_v4(),
        success,
        output: serde_json::json!({"result": "data"}),
        completed_at: Utc::now(),
    })
}

fn arb_context() -> impl Strategy<Value = AgentContext> {
    (
        proptest::collection::vec(arb_message(), 0..10),
        proptest::collection::vec(arb_task(), 0..5),
        proptest::collection::vec(arb_task_result(), 0..5),
        0u32..10000,
    ).prop_map(|(messages, tasks, results, token_count)| AgentContext {
        conversation_history: messages,
        working_state: serde_json::json!({"key": "value"}),
        active_tasks: tasks,
        intermediate_results: results,
        token_count,
    })
}

fn arb_large_context() -> impl Strategy<Value = AgentContext> {
    proptest::collection::vec(arb_message(), 20..50)
        .prop_map(|messages| {
            let token_count = messages.iter()
                .map(|m| (m.content.len() as u32) / 4 + 1)
                .sum::<u32>() + 5000; // ensure it exceeds any reasonable limit
            AgentContext {
                conversation_history: messages,
                working_state: serde_json::json!({}),
                active_tasks: Vec::new(),
                intermediate_results: Vec::new(),
                token_count,
            }
        })
}

proptest! {
    /// Property 1: For any agent context, persist then restore produces equivalent context.
    #[test]
    fn prop1_context_persistence_round_trip(ctx in arb_context()) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mgr = SqliteContextManager::in_memory().unwrap();
            let agent_id = uuid::Uuid::new_v4();

            mgr.create_context(agent_id).await.unwrap();
            mgr.persist_context(agent_id, &ctx).await.unwrap();
            let restored = mgr.restore_context(agent_id).await.unwrap();

            prop_assert_eq!(restored.conversation_history.len(), ctx.conversation_history.len());
            prop_assert_eq!(restored.active_tasks.len(), ctx.active_tasks.len());
            prop_assert_eq!(restored.intermediate_results.len(), ctx.intermediate_results.len());
            prop_assert_eq!(restored.token_count, ctx.token_count);
            prop_assert_eq!(restored.working_state, ctx.working_state);

            // Verify message content matches
            for (orig, rest) in ctx.conversation_history.iter().zip(restored.conversation_history.iter()) {
                prop_assert_eq!(&orig.role, &rest.role);
                prop_assert_eq!(&orig.content, &rest.content);
            }

            Ok(())
        })?;
    }

    /// Property 2: For any context exceeding token limit, summarization produces
    /// context within the limit.
    #[test]
    fn prop2_context_summarization_respects_token_limit(
        ctx in arb_large_context(),
        limit in 100u32..2000,
    ) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mgr = SqliteContextManager::in_memory().unwrap();

            if ctx.token_count > limit {
                let summarized = mgr.summarize_overflow(&ctx, limit).await.unwrap();

                // Summarized token count must be within limit
                prop_assert!(
                    summarized.token_count <= limit,
                    "Summarized tokens {} should be <= limit {}",
                    summarized.token_count, limit
                );

                // Summarized should have fewer or equal messages
                prop_assert!(
                    summarized.conversation_history.len() <= ctx.conversation_history.len() + 1,
                    "Summarized should not have more messages than original + summary"
                );
            }

            Ok(())
        })?;
    }
}
