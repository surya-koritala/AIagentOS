//! Property-based test for Long-Term Memory (Property 3).
//!
//! Property 3: For any valid Fact, storing and querying SHALL return result
//! containing original content.
//!
//! Additional properties cover the pluggable embedding seam:
//! * (a) embedding is deterministic,
//! * (b) identical text → identical vector (a pure function),
//! * (c) more-similar text ranks higher than less-similar text (semantic order),
//! * (d) the seam is swappable (a trivial alternate `Embedder` works end-to-end).

use std::sync::Arc;

use chrono::Utc;
use proptest::prelude::*;

use kernel::context::*;
use kernel::memory_manager::{
    cosine_similarity, embed, BlendedEmbedder, Embedder, FeatureHashEmbedder, EMBED_DIM,
};

/// A trivial alternate embedder used to prove the seam is swappable: it maps
/// the (clamped) character count onto a single nonzero bucket. Deterministic,
/// offline, dependency-free, and obviously distinct from the default embedder.
#[derive(Debug, Default, Clone, Copy)]
struct LengthBucketEmbedder;

impl Embedder for LengthBucketEmbedder {
    fn embed(&self, text: &str) -> Vec<f32> {
        let mut v = vec![0.0f32; EMBED_DIM];
        let n = text.chars().count();
        if n > 0 {
            v[n % EMBED_DIM] = 1.0;
        }
        v
    }
    fn dim(&self) -> usize {
        EMBED_DIM
    }
}

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

/// Build a Fact from a content string with no precomputed embedding.
fn fact_with(content: &str) -> Fact {
    Fact {
        id: uuid::Uuid::new_v4(),
        content: content.to_string(),
        category: FactCategory::Fact,
        created_at: Utc::now(),
        last_accessed_at: Utc::now(),
        embedding: None,
    }
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

    /// (a) + (b): The default embedder is a deterministic pure function — the
    /// same text always yields the identical vector, of the fixed dimension.
    #[test]
    fn prop_embed_is_deterministic_and_pure(text in "[a-zA-Z ]{0,60}") {
        let v1 = embed(&text);
        let v2 = embed(&text);
        prop_assert_eq!(&v1, &v2, "embedding must be a pure function of its input");
        prop_assert_eq!(v1.len(), EMBED_DIM);

        // Holds for an explicit Embedder impl too, behind the trait object.
        let e: Arc<dyn Embedder> = Arc::new(BlendedEmbedder::default());
        prop_assert_eq!(e.embed(&text), e.embed(&text));
        prop_assert_eq!(e.dim(), EMBED_DIM);
    }

    /// (c) Semantic ordering: a query embeds closer to text that shares its
    /// tokens than to disjoint filler text. We build the "related" candidate by
    /// reusing the query's words and the "unrelated" one from a disjoint
    /// vocabulary, so the invariant holds regardless of the random word pick.
    #[test]
    fn prop_more_similar_ranks_higher(
        words in prop::collection::vec("[a-z]{3,8}", 2..6),
    ) {
        // Disjoint filler vocabulary (uppercase-derived tokens never collide
        // with the lowercase query words after tokenization-lowercasing? they
        // would — so use numeric-suffixed tokens guaranteed distinct).
        let query = words.join(" ");
        let related = format!("{} {}", query, words[0]); // same tokens, repeated
        let unrelated: String = (0..words.len())
            .map(|i| format!("zzqx{}", i))
            .collect::<Vec<_>>()
            .join(" ");

        let qv = embed(&query);
        let rv = embed(&related);
        let uv = embed(&unrelated);

        let s_related = cosine_similarity(&qv, &rv);
        let s_unrelated = cosine_similarity(&qv, &uv);
        prop_assert!(
            s_related > s_unrelated,
            "related '{}' ({}) should outrank unrelated '{}' ({}) for query '{}'",
            related, s_related, unrelated, s_unrelated, query
        );
    }

    /// (c) end-to-end through persistence: querying with text overlapping one
    /// stored fact and disjoint from another ranks the overlapping fact first.
    #[test]
    fn prop_query_ranks_overlapping_fact_first(
        words in prop::collection::vec("[a-z]{4,8}", 3..6),
    ) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let mgr = SqliteContextManager::in_memory().unwrap();
            let agent_id = uuid::Uuid::new_v4();

            let query = words.join(" ");
            let overlapping = query.clone();
            let disjoint: String = (0..words.len())
                .map(|i| format!("qqzx{}", i))
                .collect::<Vec<_>>()
                .join(" ");

            mgr.store_fact(agent_id, fact_with(&overlapping)).await.unwrap();
            mgr.store_fact(agent_id, fact_with(&disjoint)).await.unwrap();

            let results = mgr.query_memory(agent_id, &query).await.unwrap();
            prop_assert_eq!(results.len(), 2);
            prop_assert_eq!(
                &results[0].content, &overlapping,
                "fact sharing the query tokens should rank first"
            );
            Ok(())
        })?;
    }

    /// (d) The seam is swappable: injecting an alternate Embedder changes the
    /// stored embedding (vs. the default) while round-trip retrieval still
    /// works end-to-end through the same persistence path.
    #[test]
    fn prop_seam_is_swappable(content in "[a-zA-Z ]{5,40}") {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let agent_id = uuid::Uuid::new_v4();

            // Default-embedder manager.
            let default_mgr = SqliteContextManager::in_memory().unwrap();
            default_mgr.store_fact(agent_id, fact_with(&content)).await.unwrap();
            let default_hit = default_mgr.query_memory(agent_id, &content).await.unwrap();
            prop_assert_eq!(default_hit.len(), 1);
            let default_emb = default_hit[0].embedding.clone().unwrap();

            // Alternate-embedder manager via the injectable seam.
            let alt_mgr = SqliteContextManager::in_memory()
                .unwrap()
                .with_embedder(Arc::new(LengthBucketEmbedder));
            alt_mgr.store_fact(agent_id, fact_with(&content)).await.unwrap();
            let alt_hit = alt_mgr.query_memory(agent_id, &content).await.unwrap();
            prop_assert_eq!(alt_hit.len(), 1);
            prop_assert_eq!(&alt_hit[0].content, &content);
            let alt_emb = alt_hit[0].embedding.clone().unwrap();

            // The alternate embedder produced the LengthBucketEmbedder vector,
            // proving the injected seam is actually on the store path.
            prop_assert_eq!(&alt_emb, &LengthBucketEmbedder.embed(&content));

            // And it differs from the default embedder's vector for non-empty
            // input (the two embedders are genuinely distinct).
            if content.chars().any(|c| c.is_alphanumeric()) {
                prop_assert_ne!(
                    default_emb, alt_emb,
                    "swapping the embedder must change the stored vector"
                );
            }
            Ok(())
        })?;
    }
}

/// (d, fixed): a hand-checked swappability case independent of proptest input,
/// plus a check that the legacy FeatureHashEmbedder is still reachable and
/// produces the original-dimension vectors.
#[test]
fn legacy_embedder_still_usable_through_seam() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let agent_id = uuid::Uuid::new_v4();
        let mgr = SqliteContextManager::in_memory()
            .unwrap()
            .with_embedder(Arc::new(FeatureHashEmbedder));
        mgr.store_fact(agent_id, fact_with("the user prefers dark mode"))
            .await
            .unwrap();
        let hits = mgr.query_memory(agent_id, "dark mode").await.unwrap();
        assert_eq!(hits.len(), 1);
        let emb = hits[0].embedding.clone().unwrap();
        assert_eq!(emb.len(), EMBED_DIM);
        assert_eq!(emb, FeatureHashEmbedder.embed("the user prefers dark mode"));
    });
}
