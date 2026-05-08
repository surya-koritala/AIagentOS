//! Property-based test for Long-Term Memory (Property 3).
//!
//! Property 3: For any valid Fact, storing and querying SHALL return result
//! containing original content.

use chrono::Utc;
use proptest::prelude::*;

use kernel::context::*;

fn arb_category() -> impl Strategy<Value = FactCategory> {
    prop_oneof![
        Just(FactCategory::Preference),
        Just(FactCategory::LearnedPattern),
        Just(FactCategory::Fact),
        Just(FactCategory::Instruction),
    ]
}

fn arb_fact() -> impl Strategy<Value = Fact> {
    ("[a-zA-Z ]{5,50}", arb_category()).prop_map(|(content, category)| Fact {
        id: uuid::Uuid::new_v4(),
        content,
        category,
        created_at: Utc::now(),
        last_accessed_at: Utc::now(),
        embedding: None,
    })
}

proptest! {
    /// Property 3: For any valid Fact, storing and querying with a substring
    /// of the content SHALL return a result containing the original content.
    #[test]
    fn prop3_memory_store_retrieve_round_trip(fact in arb_fact()) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mgr = SqliteContextManager::in_memory().unwrap();
            let agent_id = uuid::Uuid::new_v4();

            mgr.store_fact(agent_id, fact.clone()).await.unwrap();

            // Query with a substring of the content (at least 3 chars)
            let query_term = if fact.content.len() >= 6 {
                &fact.content[1..6]
            } else {
                &fact.content
            };

            let results = mgr.query_memory(agent_id, query_term).await.unwrap();

            prop_assert!(
                results.iter().any(|f| f.content == fact.content),
                "Query '{}' should find fact with content '{}', got {:?}",
                query_term, fact.content, results.iter().map(|f| &f.content).collect::<Vec<_>>()
            );

            // Verify the returned fact has correct category
            let found = results.iter().find(|f| f.content == fact.content).unwrap();
            prop_assert_eq!(&found.category, &fact.category);

            Ok(())
        })?;
    }
}
