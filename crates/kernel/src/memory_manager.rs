//! Memory Manager — deterministic, offline embeddings + vector (cosine) search.
//!
//! This module provides the retrieval backbone for the long-term memory `facts`
//! table in [`crate::context`]. The Linux analogue is a page-cache lookup keyed by
//! content similarity rather than address: facts are "paged in" by semantic
//! relevance to a query instead of a substring match.
//!
//! Everything here is **Rust-native, deterministic, and offline** — there are no
//! network or API calls, so it works identically in CI, tests, and production.
//! The embedder uses the classic *feature-hashing trick*: text is tokenized,
//! each token (and adjacent bigram) is hashed with a fixed-seed FNV-1a hasher
//! into a fixed-dimension vector, and the result is L2-normalized. Because the
//! vectors are unit-length, cosine similarity reduces to a dot product.

/// Dimensionality of the embedding space. Fixed so stored vectors stay
/// comparable across runs and process restarts.
pub const EMBED_DIM: usize = 256;

/// FNV-1a 64-bit offset basis (fixed seed — guarantees determinism, unlike
/// the standard library's randomly-seeded `RandomState`).
const FNV_OFFSET: u64 = 0xcbf29ce484222325;
/// FNV-1a 64-bit prime.
const FNV_PRIME: u64 = 0x100000001b3;

/// Hand-rolled FNV-1a hash over bytes with a fixed seed for reproducibility.
fn fnv1a(bytes: &[u8]) -> u64 {
    let mut hash = FNV_OFFSET;
    for &b in bytes {
        hash ^= b as u64;
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

/// Tokenize text: lowercase, split on any non-alphanumeric boundary, drop empties.
fn tokenize(text: &str) -> Vec<String> {
    text.split(|c: char| !c.is_alphanumeric())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_lowercase())
        .collect()
}

/// Fold a single hashed feature into the accumulator vector.
///
/// The low bits of the hash pick the bucket; one more bit picks the sign. This
/// keeps the expected dot product unbiased (the hashing trick).
fn add_feature(acc: &mut [f32; EMBED_DIM], hash: u64) {
    let bucket = (hash % EMBED_DIM as u64) as usize;
    // Use a distinct bit (not one of the bucket bits) to decide the sign.
    let sign = if (hash >> 63) & 1 == 1 { 1.0 } else { -1.0 };
    acc[bucket] += sign;
}

/// Compute a deterministic, L2-normalized feature-hash embedding for `text`.
///
/// Empty or token-free input yields an all-zero vector (norm 0), which scores 0
/// against everything under [`cosine_similarity`] — a safe neutral result.
pub fn embed(text: &str) -> Vec<f32> {
    let tokens = tokenize(text);
    let mut acc = [0.0f32; EMBED_DIM];

    for (i, tok) in tokens.iter().enumerate() {
        // Unigram feature.
        add_feature(&mut acc, fnv1a(tok.as_bytes()));
        // Adjacent bigram feature — captures a little word-order context.
        if i + 1 < tokens.len() {
            let bigram = format!("{} {}", tok, tokens[i + 1]);
            add_feature(&mut acc, fnv1a(bigram.as_bytes()));
        }
    }

    // L2-normalize so cosine similarity == dot product.
    let norm: f32 = acc.iter().map(|v| v * v).sum::<f32>().sqrt();
    if norm > 0.0 {
        for v in acc.iter_mut() {
            *v /= norm;
        }
    }
    acc.to_vec()
}

/// Cosine similarity between two vectors.
///
/// Returns 0.0 when either vector is empty, has mismatched length, or is the
/// zero vector. For already-normalized vectors (as produced by [`embed`]) this
/// is exactly their dot product, but the full formula is used so callers can
/// pass un-normalized vectors safely.
pub fn cosine_similarity(a: &[f32], b: &[f32]) -> f32 {
    if a.is_empty() || a.len() != b.len() {
        return 0.0;
    }
    let mut dot = 0.0f32;
    let mut na = 0.0f32;
    let mut nb = 0.0f32;
    for i in 0..a.len() {
        dot += a[i] * b[i];
        na += a[i] * a[i];
        nb += b[i] * b[i];
    }
    let denom = na.sqrt() * nb.sqrt();
    if denom > 0.0 {
        dot / denom
    } else {
        0.0
    }
}

/// Rank `(item, embedding)` pairs against a query embedding, best (highest
/// cosine similarity) first. Returns each item paired with its score.
///
/// The sort is stable and total (NaN scores are treated as the smallest),
/// so ranking is deterministic for a given input order.
pub fn rank<T>(query: &[f32], items: Vec<(T, Vec<f32>)>) -> Vec<(T, f32)> {
    let mut scored: Vec<(T, f32)> = items
        .into_iter()
        .map(|(item, emb)| {
            let score = cosine_similarity(query, &emb);
            (item, score)
        })
        .collect();
    scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    scored
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embed_is_deterministic() {
        let a = embed("the quick brown fox");
        let b = embed("the quick brown fox");
        assert_eq!(a, b);
    }

    #[test]
    fn embed_has_fixed_dimension() {
        assert_eq!(embed("hello world").len(), EMBED_DIM);
        assert_eq!(embed("").len(), EMBED_DIM);
    }

    #[test]
    fn embed_is_unit_length() {
        let v = embed("the user prefers dark mode in the editor");
        let norm: f32 = v.iter().map(|x| x * x).sum::<f32>().sqrt();
        assert!((norm - 1.0).abs() < 1e-5, "norm was {}", norm);
    }

    #[test]
    fn empty_embedding_is_zero() {
        let v = embed("");
        assert!(v.iter().all(|&x| x == 0.0));
        let norm: f32 = v.iter().map(|x| x * x).sum::<f32>().sqrt();
        assert_eq!(norm, 0.0);
    }

    #[test]
    fn case_insensitive() {
        assert_eq!(embed("Dark Mode"), embed("dark mode"));
    }

    #[test]
    fn self_similarity_is_one() {
        let v = embed("agents are processes");
        let sim = cosine_similarity(&v, &v);
        assert!((sim - 1.0).abs() < 1e-5, "sim was {}", sim);
    }

    #[test]
    fn related_scores_higher_than_unrelated() {
        let query = embed("the user prefers dark mode");
        let related = embed("dark mode is the user's preferred theme");
        let unrelated = embed("the spacecraft reached orbital velocity");

        let s_related = cosine_similarity(&query, &related);
        let s_unrelated = cosine_similarity(&query, &unrelated);
        assert!(
            s_related > s_unrelated,
            "related {} should beat unrelated {}",
            s_related,
            s_unrelated
        );
    }

    #[test]
    fn cosine_handles_zero_and_mismatch() {
        assert_eq!(cosine_similarity(&[], &[]), 0.0);
        assert_eq!(cosine_similarity(&[1.0, 2.0], &[1.0]), 0.0);
        assert_eq!(cosine_similarity(&[0.0, 0.0], &[1.0, 1.0]), 0.0);
    }

    #[test]
    fn rank_orders_best_first() {
        let query = embed("coffee in the morning");
        let items = vec![
            ("orbit", embed("rockets and orbital mechanics")),
            ("coffee", embed("i drink coffee every morning")),
            ("tea", embed("tea is a warm beverage")),
        ];
        let ranked = rank(&query, items);
        assert_eq!(ranked[0].0, "coffee");
        // Scores must be non-increasing.
        for w in ranked.windows(2) {
            assert!(w[0].1 >= w[1].1);
        }
    }
}
