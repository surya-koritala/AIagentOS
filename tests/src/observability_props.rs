//! Property-based tests for Observability (Properties 22, 23, 24).
//!
//! Property 22: Plan deviation detection.
//! Property 23: Resource metrics accuracy (monotonically non-decreasing).
//! Property 24: Reasoning chain retrieval.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use proptest::prelude::*;
use chrono::Utc;

use kernel::observability::*;

fn arb_action_type() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("tool_call".to_string()),
        Just("resource_access".to_string()),
        Just("llm_call".to_string()),
        Just("file_write".to_string()),
    ]
}

proptest! {
    /// Property 22: For any action not matching stated plan, system SHALL flag
    /// deviation and notify user.
    #[test]
    fn prop22_plan_deviation_detection(
        plan_desc in "[a-zA-Z ]{5,20}",
        action_desc in "[a-zA-Z ]{5,20}",
    ) {
        let engine = ObservabilityEngineImpl::new();
        let agent_id = uuid::Uuid::new_v4();

        // Set a plan
        engine.set_agent_plan(agent_id, vec![
            PlanStep { step_number: 1, description: plan_desc.clone(), status: PlanStepStatus::Pending },
        ]);

        let deviation_count = Arc::new(AtomicUsize::new(0));
        let dc = deviation_count.clone();
        engine.on_deviation(Box::new(move |_id, _action| {
            dc.fetch_add(1, Ordering::SeqCst);
        }));

        // Log an action
        engine.log_action(agent_id, AgentAction {
            id: uuid::Uuid::new_v4(),
            action_type: "tool_call".into(),
            description: action_desc.clone(),
            resources_accessed: vec![],
            reasoning: None,
            plan_context: None,
            timestamp: Utc::now(),
        });

        // If action doesn't match plan, deviation should be detected
        let matches = action_desc.to_lowercase().contains(&plan_desc.to_lowercase())
            || plan_desc.to_lowercase().contains(&"tool_call".to_lowercase());

        if !matches {
            prop_assert!(deviation_count.load(Ordering::SeqCst) > 0,
                "Deviation should be detected when action '{}' doesn't match plan '{}'",
                action_desc, plan_desc);
        }
        // If it matches, no deviation (or deviation — both are acceptable since
        // the matching heuristic is simple)
    }

    /// Property 23: For any activity sequence, metrics SHALL be monotonically
    /// non-decreasing and increment correctly.
    #[test]
    fn prop23_resource_metrics_accuracy(
        increments in proptest::collection::vec((1u64..1000, 1u64..10), 1..10),
    ) {
        let engine = ObservabilityEngineImpl::new();
        let agent_id = uuid::Uuid::new_v4();

        let mut expected_tokens: u64 = 0;
        let mut expected_calls: u64 = 0;
        let mut prev_tokens: u64 = 0;
        let mut prev_calls: u64 = 0;

        for (tokens, calls) in &increments {
            engine.record_metrics(agent_id, *tokens, *calls);
            expected_tokens += tokens;
            expected_calls += calls;

            let m = engine.get_metrics(MetricScope::Agent(agent_id));

            // Monotonically non-decreasing
            prop_assert!(m.tokens_consumed >= prev_tokens,
                "Tokens should be non-decreasing: {} >= {}", m.tokens_consumed, prev_tokens);
            prop_assert!(m.api_calls_made >= prev_calls,
                "API calls should be non-decreasing: {} >= {}", m.api_calls_made, prev_calls);

            // Correct totals
            prop_assert_eq!(m.tokens_consumed, expected_tokens);
            prop_assert_eq!(m.api_calls_made, expected_calls);

            prev_tokens = m.tokens_consumed;
            prev_calls = m.api_calls_made;
        }
    }

    /// Property 24: For any action with reasoning chain, explanation request
    /// SHALL return complete chain.
    #[test]
    fn prop24_reasoning_chain_retrieval(
        num_steps in 1usize..5,
        thought in "[a-zA-Z ]{5,30}",
    ) {
        let engine = ObservabilityEngineImpl::new();
        let agent_id = uuid::Uuid::new_v4();
        let action_id = uuid::Uuid::new_v4();

        // Add reasoning steps
        for i in 0..num_steps {
            engine.add_reasoning_step(agent_id, action_id, ReasoningStep {
                thought: format!("{} step {}", thought, i),
                evidence: Some(format!("evidence {}", i)),
                conclusion: if i == num_steps - 1 { Some("final conclusion".into()) } else { None },
                timestamp: Utc::now(),
            });
        }

        // Retrieve chain
        let chain = engine.get_reasoning_chain(agent_id, action_id);
        prop_assert!(chain.is_some(), "Chain should exist");
        let chain = chain.unwrap();
        prop_assert_eq!(chain.len(), num_steps, "Chain should have all steps");

        // Verify completeness
        for (i, step) in chain.iter().enumerate() {
            let expected = format!("step {}", i);
            prop_assert!(step.thought.contains(&expected), "Step should contain expected text");
            prop_assert!(step.evidence.is_some());
        }
        // Last step should have conclusion
        prop_assert!(chain.last().unwrap().conclusion.is_some());
    }
}
