//! Memory Manager — deterministic, offline embeddings + vector (cosine) search.
//!
//! This module provides the retrieval backbone for the long-term memory `facts`
//! table in [`crate::context`]. The Linux analogue is a page-cache lookup keyed by
//! content similarity rather than address: facts are "paged in" by semantic
//! relevance to a query instead of a substring match.
//!
//! Everything here is **Rust-native, deterministic, and offline** — there are no
//! network or API calls, so it works identically in CI, tests, and production.
//!
//! # Pluggable seam
//!
//! Embedding and nearest-neighbor lookup are expressed as two object-safe traits:
//!
//! * [`Embedder`] — turns text into a fixed-dimension vector. The default
//!   [`BlendedEmbedder`] blends word-token, character-n-gram, and word-bigram
//!   feature hashes with sublinear term weighting; the simpler
//!   [`FeatureHashEmbedder`] preserves the original FNV-1a behavior for callers
//!   that need bit-for-bit compatibility with previously-stored vectors.
//! * [`VectorIndex`] — accumulates `(id, vector)` pairs and answers top-`k`
//!   nearest-neighbor queries. The default [`BruteForceIndex`] does an exact
//!   cosine scan; this is the seam where a real ANN index could later drop in
//!   without touching callers.
//!
//! Both default impls are unit-length and L2-normalized, so cosine similarity
//! reduces to a dot product.

use std::sync::Arc;

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

/// Mix a small integer salt into a seed hash so different feature *kinds*
/// (unigram vs. char-trigram vs. bigram) land in independent hash subspaces
/// and don't collide systematically.
fn fnv1a_salted(salt: u8, bytes: &[u8]) -> u64 {
    let mut hash = FNV_OFFSET;
    hash ^= salt as u64;
    hash = hash.wrapping_mul(FNV_PRIME);
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

/// Fold a single hashed feature into the accumulator vector with the given
/// weight.
///
/// The low bits of the hash pick the bucket; the top bit picks the sign. This
/// keeps the expected dot product unbiased (the hashing trick).
fn add_feature(acc: &mut [f32; EMBED_DIM], hash: u64, weight: f32) {
    let bucket = (hash % EMBED_DIM as u64) as usize;
    // Use a distinct bit (not one of the bucket bits) to decide the sign.
    let sign = if (hash >> 63) & 1 == 1 { 1.0 } else { -1.0 };
    acc[bucket] += sign * weight;
}

/// L2-normalize an accumulator and return it as a `Vec`. A zero accumulator is
/// returned unchanged (norm 0), which scores 0 against everything under
/// [`cosine_similarity`] — a safe neutral result.
fn normalize(mut acc: [f32; EMBED_DIM]) -> Vec<f32> {
    let norm: f32 = acc.iter().map(|v| v * v).sum::<f32>().sqrt();
    if norm > 0.0 {
        for v in acc.iter_mut() {
            *v /= norm;
        }
    }
    acc.to_vec()
}

/// An object-safe text → vector embedder.
///
/// Implementations must be **deterministic**: the same input text always
/// produces the same vector, across runs and process restarts. They are used
/// behind `Arc<dyn Embedder>` so the embedding strategy is injectable.
pub trait Embedder: Send + Sync {
    /// Embed `text` into a vector of length [`Embedder::dim`].
    fn embed(&self, text: &str) -> Vec<f32>;
    /// The dimensionality of vectors produced by [`Embedder::embed`].
    fn dim(&self) -> usize;
}

/// The original feature-hash embedder: unigram + adjacent-bigram FNV-1a feature
/// hashing, L2-normalized. Kept as a stable, bit-for-bit-compatible impl for
/// callers that must match vectors stored by older builds.
#[derive(Debug, Default, Clone, Copy)]
pub struct FeatureHashEmbedder;

impl Embedder for FeatureHashEmbedder {
    fn embed(&self, text: &str) -> Vec<f32> {
        let tokens = tokenize(text);
        let mut acc = [0.0f32; EMBED_DIM];

        for (i, tok) in tokens.iter().enumerate() {
            // Unigram feature.
            add_feature(&mut acc, fnv1a(tok.as_bytes()), 1.0);
            // Adjacent bigram feature — captures a little word-order context.
            if i + 1 < tokens.len() {
                let bigram = format!("{} {}", tok, tokens[i + 1]);
                add_feature(&mut acc, fnv1a(bigram.as_bytes()), 1.0);
            }
        }

        normalize(acc)
    }

    fn dim(&self) -> usize {
        EMBED_DIM
    }
}

/// The stronger default embedder.
///
/// Blends three complementary feature families, each in its own hash subspace
/// (via a salt), then weights repeated terms sublinearly (`1 + ln(count)`,
/// a TF-style damping) so a word repeated ten times doesn't swamp the vector:
///
/// 1. **Word unigrams** — the core lexical signal.
/// 2. **Word bigrams** — a little word-order context.
/// 3. **Character trigrams** (with word-boundary padding) — robustness to
///    morphology and typos, e.g. "editor"/"editing" share trigrams. This is the
///    main lift over pure word hashing on the semantic-ordering tests.
///
/// Character features are down-weighted relative to word features so exact
/// lexical overlap still dominates, while sub-word overlap breaks ties toward
/// the semantically closer candidate. Output is L2-normalized.
#[derive(Debug, Clone, Copy)]
pub struct BlendedEmbedder {
    /// Weight applied to character-trigram features (word features are 1.0).
    char_weight: f32,
}

impl Default for BlendedEmbedder {
    fn default() -> Self {
        Self { char_weight: 0.45 }
    }
}

impl BlendedEmbedder {
    /// Salt namespaces so the three feature families don't systematically alias.
    const SALT_UNIGRAM: u8 = 1;
    const SALT_BIGRAM: u8 = 2;
    const SALT_TRIGRAM: u8 = 3;

    /// Sublinear term-frequency weight: `1 + ln(count)`. Damps repeated terms.
    fn tf_weight(count: u32) -> f32 {
        1.0 + (count as f32).ln()
    }
}

impl Embedder for BlendedEmbedder {
    fn embed(&self, text: &str) -> Vec<f32> {
        use std::collections::HashMap;

        let tokens = tokenize(text);
        let mut acc = [0.0f32; EMBED_DIM];

        // Count unigrams so we can apply sublinear TF weighting.
        let mut unigram_counts: HashMap<&str, u32> = HashMap::new();
        for tok in &tokens {
            *unigram_counts.entry(tok.as_str()).or_insert(0) += 1;
        }
        for (tok, count) in &unigram_counts {
            let w = Self::tf_weight(*count);
            add_feature(
                &mut acc,
                fnv1a_salted(Self::SALT_UNIGRAM, tok.as_bytes()),
                w,
            );
        }

        // Word bigrams (positional, not de-duplicated — order context is cheap).
        for pair in tokens.windows(2) {
            let bigram = format!("{} {}", pair[0], pair[1]);
            add_feature(
                &mut acc,
                fnv1a_salted(Self::SALT_BIGRAM, bigram.as_bytes()),
                1.0,
            );
        }

        // Character trigrams over each token, padded with boundary markers so
        // short tokens and word edges still contribute distinctive features.
        for tok in &tokens {
            let padded: Vec<char> = std::iter::once('^')
                .chain(tok.chars())
                .chain(std::iter::once('$'))
                .collect();
            if padded.len() >= 3 {
                for gram in padded.windows(3) {
                    let s: String = gram.iter().collect();
                    add_feature(
                        &mut acc,
                        fnv1a_salted(Self::SALT_TRIGRAM, s.as_bytes()),
                        self.char_weight,
                    );
                }
            }
        }

        normalize(acc)
    }

    fn dim(&self) -> usize {
        EMBED_DIM
    }
}

/// The process-wide default embedder used by the free functions and by
/// [`MemoryManager::default`]. Currently [`BlendedEmbedder`].
pub fn default_embedder() -> Arc<dyn Embedder> {
    Arc::new(BlendedEmbedder::default())
}

/// Compute a deterministic, L2-normalized embedding for `text` using the
/// default embedder.
///
/// Backwards-compatible free function: existing call sites in [`crate::context`]
/// keep working unchanged. Empty or token-free input yields an all-zero vector.
pub fn embed(text: &str) -> Vec<f32> {
    BlendedEmbedder::default().embed(text)
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

/// An object-safe nearest-neighbor index over embedding vectors.
///
/// This is the seam where a real approximate-nearest-neighbor (ANN) structure
/// could later replace the exact brute-force default without changing callers.
/// Implementations are keyed by an opaque `u64` id (callers map their own ids
/// in/out). All implementations must be deterministic for a given insert order.
pub trait VectorIndex: Send + Sync {
    /// Insert (or overwrite) the vector stored under `id`.
    fn add(&mut self, id: u64, vec: Vec<f32>);
    /// Return up to `k` ids most similar to `query`, best (highest score) first.
    fn search(&self, query: &[f32], k: usize) -> Vec<(u64, f32)>;
    /// Number of vectors currently stored.
    fn len(&self) -> usize;
    /// Whether the index holds no vectors.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Exact cosine nearest-neighbor index by brute-force scan.
///
/// Simple and dependency-free: correct for any vector dimension, deterministic,
/// and adequate for the fact-table sizes the memory subsystem deals with. Drop
/// in an ANN index behind [`VectorIndex`] when corpora grow.
#[derive(Debug, Default, Clone)]
pub struct BruteForceIndex {
    entries: Vec<(u64, Vec<f32>)>,
}

impl BruteForceIndex {
    /// Create an empty index.
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }
}

impl VectorIndex for BruteForceIndex {
    fn add(&mut self, id: u64, vec: Vec<f32>) {
        if let Some(slot) = self.entries.iter_mut().find(|(eid, _)| *eid == id) {
            slot.1 = vec;
        } else {
            self.entries.push((id, vec));
        }
    }

    fn search(&self, query: &[f32], k: usize) -> Vec<(u64, f32)> {
        let mut scored: Vec<(u64, f32)> = self
            .entries
            .iter()
            .map(|(id, v)| (*id, cosine_similarity(query, v)))
            .collect();
        scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        scored.truncate(k);
        scored
    }

    fn len(&self) -> usize {
        self.entries.len()
    }
}

/// A deterministic, dependency-free PRNG (SplitMix64) used to generate the
/// random hyperplanes for [`LshIndex`]. Seeded from a constant so the planes —
/// and therefore every signature and search result — are identical across runs
/// and process restarts, which the [`VectorIndex`] contract requires.
struct SplitMix64(u64);

impl SplitMix64 {
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Uniform f32 in [0, 1).
    fn next_f32(&mut self) -> f32 {
        // Top 24 bits → mantissa precision; divide into [0, 1).
        (self.next_u64() >> 40) as f32 / (1u32 << 24) as f32
    }

    /// Standard-normal sample via Box–Muller. Random hyperplanes with Gaussian
    /// components give an unbiased SimHash (each plane a uniformly-random
    /// direction), which is what makes sign-bit collisions track cosine angle.
    fn next_gaussian(&mut self) -> f32 {
        // Guard u1 away from 0 so ln() is finite.
        let u1 = self.next_f32().max(1e-7);
        let u2 = self.next_f32();
        (-2.0 * u1.ln()).sqrt() * (std::f32::consts::TAU * u2).cos()
    }
}

/// One LSH table: a fixed set of random hyperplanes plus the buckets they induce.
struct LshTable {
    /// `bits` hyperplanes, each a `dim`-length Gaussian vector.
    planes: Vec<Vec<f32>>,
    /// Signature → ids that hash to it in this table.
    buckets: std::collections::HashMap<u64, Vec<u64>>,
}

impl LshTable {
    /// The `bits`-bit SimHash signature of `vec` in this table: bit `i` = sign of
    /// `vec · plane[i]`.
    fn signature(&self, vec: &[f32]) -> u64 {
        let mut sig = 0u64;
        for (i, plane) in self.planes.iter().enumerate() {
            let mut dot = 0.0f32;
            for (a, b) in vec.iter().zip(plane.iter()) {
                dot += a * b;
            }
            if dot >= 0.0 {
                sig |= 1 << i;
            }
        }
        sig
    }
}

/// Approximate nearest-neighbor index via multi-table random-hyperplane LSH
/// (SimHash).
///
/// Each of `L` independent tables reduces a vector to a short sign-bit signature
/// (one bit per random hyperplane). Two vectors with a small cosine angle agree
/// on each bit with probability `1 - θ/π`, so they land in the same bucket of at
/// least one table with high probability — the more tables, the higher the
/// recall. A query gathers the union of its same-bucket ids across all tables
/// (cheap: one bucket lookup per table), then ranks those candidates *exactly* by
/// cosine. The approximation is only in *which* vectors get scored, never in how
/// they're scored.
///
/// This is the scale-oriented sibling of [`BruteForceIndex`]: same
/// [`VectorIndex`] contract, deterministic (hyperplanes come from a fixed-seed
/// PRNG), but a large corpus scores only the colliding candidates instead of
/// every vector. A safety net widens to single-bit-flipped buckets and finally a
/// full scan if the tables didn't surface at least `k` candidates, so recall
/// degrades gracefully rather than dropping results.
pub struct LshIndex {
    tables: Vec<LshTable>,
    /// Source of truth: id → vector. Survives bucket churn on overwrite.
    vectors: std::collections::HashMap<u64, Vec<f32>>,
}

impl LshIndex {
    /// Fixed seed → identical hyperplanes every run (determinism contract).
    const SEED: u64 = 0x5A17_C0DE_1DEA_2025;

    /// Build an index for `dim`-dimensional vectors with `num_tables` independent
    /// tables of `bits_per_table` hyperplanes each (bits clamped to 1..=64 so a
    /// signature fits a `u64`). More tables raise recall; more bits per table
    /// shrink buckets (faster, lower recall per table).
    pub fn new(dim: usize, num_tables: usize, bits_per_table: usize) -> Self {
        let num_tables = num_tables.max(1);
        let bits = bits_per_table.clamp(1, 64);
        let mut rng = SplitMix64(Self::SEED);
        let tables = (0..num_tables)
            .map(|_| LshTable {
                planes: (0..bits)
                    .map(|_| (0..dim).map(|_| rng.next_gaussian()).collect())
                    .collect(),
                buckets: std::collections::HashMap::new(),
            })
            .collect();
        Self {
            tables,
            vectors: std::collections::HashMap::new(),
        }
    }

    /// Sensible defaults for the kernel's [`EMBED_DIM`] vectors: many tables with
    /// short signatures, since text embeddings make even "similar" pairs only
    /// moderately cosine-close, so high recall needs several independent chances
    /// to collide (combined with the always-on radius-1 probe in `search`).
    pub fn with_dim(dim: usize) -> Self {
        Self::new(dim, 16, 8)
    }

    fn remove_id(&mut self, vec: &[f32], id: u64) {
        for table in &mut self.tables {
            let sig = table.signature(vec);
            if let Some(ids) = table.buckets.get_mut(&sig) {
                ids.retain(|&x| x != id);
                if ids.is_empty() {
                    table.buckets.remove(&sig);
                }
            }
        }
    }
}

impl VectorIndex for LshIndex {
    fn add(&mut self, id: u64, vec: Vec<f32>) {
        // Overwrite: drop the id from every table's old bucket first so no table
        // holds a stale signature for it.
        if let Some(old) = self.vectors.get(&id).cloned() {
            self.remove_id(&old, id);
        }
        for table in &mut self.tables {
            let sig = table.signature(&vec);
            table.buckets.entry(sig).or_default().push(id);
        }
        self.vectors.insert(id, vec);
    }

    fn search(&self, query: &[f32], k: usize) -> Vec<(u64, f32)> {
        if k == 0 || self.vectors.is_empty() {
            return Vec::new();
        }

        // Gather candidates from each table at Hamming radius 0 and 1: the
        // query's own bucket plus every single-bit-flipped neighbor. Probing
        // radius 1 (cheap: `bits` extra lookups per table) is what lifts recall
        // for the moderate-cosine pairs that text embeddings produce — a near
        // pair that misses on one bit per table still collides.
        let mut candidates: std::collections::HashSet<u64> = std::collections::HashSet::new();
        for table in &self.tables {
            let sig = table.signature(query);
            if let Some(ids) = table.buckets.get(&sig) {
                candidates.extend(ids.iter().copied());
            }
            for bit in 0..table.planes.len() {
                if let Some(ids) = table.buckets.get(&(sig ^ (1 << bit))) {
                    candidates.extend(ids.iter().copied());
                }
            }
        }

        // Safety net: still too few (sparse/unlucky) — score everything. Exact
        // and bounded by the corpus size, so results are never silently dropped.
        if candidates.len() < k {
            candidates = self.vectors.keys().copied().collect();
        }

        let mut scored: Vec<(u64, f32)> = candidates
            .into_iter()
            .filter_map(|id| {
                self.vectors
                    .get(&id)
                    .map(|v| (id, cosine_similarity(query, v)))
            })
            .collect();
        scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        scored.truncate(k);
        scored
    }

    fn len(&self) -> usize {
        self.vectors.len()
    }
}

/// Rank `(item, embedding)` pairs against a `query` embedding and return the top
/// `k`, best-first — choosing the index strategy by candidate-set size.
///
/// At or below `exact_threshold` items an exact [`BruteForceIndex`] scan is used
/// (cheap and exactly correct); above it, the approximate [`LshIndex`] bounds the
/// work by probing signature buckets instead of scoring every vector. The seam is
/// the same either way, so callers get exact results on the common small case and
/// graceful degradation to approximate on large corpora.
pub fn rank_topk<T>(
    query: &[f32],
    items: Vec<(T, Vec<f32>)>,
    k: usize,
    exact_threshold: usize,
) -> Vec<(T, f32)> {
    if items.is_empty() || k == 0 {
        return Vec::new();
    }
    let dim = query.len();
    let mut index: Box<dyn VectorIndex> = if items.len() > exact_threshold {
        Box::new(LshIndex::with_dim(dim))
    } else {
        Box::new(BruteForceIndex::new())
    };
    for (i, (_, emb)) in items.iter().enumerate() {
        index.add(i as u64, emb.clone());
    }
    let hits = index.search(query, k);
    // Map index positions back to items. Collect by position so we can move each
    // item out exactly once, preserving the index's best-first order.
    let mut slots: Vec<Option<T>> = items.into_iter().map(|(item, _)| Some(item)).collect();
    hits.into_iter()
        .filter_map(|(id, score)| slots[id as usize].take().map(|item| (item, score)))
        .collect()
}

/// Bundles a pluggable [`Embedder`] with ranking helpers.
///
/// This is the injectable entry point: construct it with [`MemoryManager::new`]
/// to swap in an alternate embedder, or [`MemoryManager::default`] for the
/// process default. Persistence still lives entirely in
/// [`crate::context::SqliteContextManager`]; this type only owns the embedding
/// and ranking policy.
#[derive(Clone)]
pub struct MemoryManager {
    embedder: Arc<dyn Embedder>,
}

impl Default for MemoryManager {
    fn default() -> Self {
        Self {
            embedder: default_embedder(),
        }
    }
}

impl MemoryManager {
    /// Construct with a specific embedder.
    pub fn new(embedder: Arc<dyn Embedder>) -> Self {
        Self { embedder }
    }

    /// The embedder backing this manager.
    pub fn embedder(&self) -> Arc<dyn Embedder> {
        Arc::clone(&self.embedder)
    }

    /// Embed `text` with this manager's embedder.
    pub fn embed(&self, text: &str) -> Vec<f32> {
        self.embedder.embed(text)
    }

    /// Rank `(item, embedding)` pairs by cosine similarity to `query` text,
    /// embedding the query with this manager's embedder. Best-first.
    pub fn rank_by_query<T>(&self, query: &str, items: Vec<(T, Vec<f32>)>) -> Vec<(T, f32)> {
        let q = self.embed(query);
        rank(&q, items)
    }
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

    #[test]
    fn feature_hash_embedder_matches_legacy_behavior() {
        // The FeatureHashEmbedder must reproduce the original unigram+bigram
        // FNV-1a vector so previously-stored embeddings still rank correctly.
        let e = FeatureHashEmbedder;
        let tokens = tokenize("the quick brown fox");
        let mut acc = [0.0f32; EMBED_DIM];
        for (i, tok) in tokens.iter().enumerate() {
            add_feature(&mut acc, fnv1a(tok.as_bytes()), 1.0);
            if i + 1 < tokens.len() {
                let bigram = format!("{} {}", tok, tokens[i + 1]);
                add_feature(&mut acc, fnv1a(bigram.as_bytes()), 1.0);
            }
        }
        assert_eq!(e.embed("the quick brown fox"), normalize(acc));
        assert_eq!(e.dim(), EMBED_DIM);
    }

    #[test]
    fn blended_embedder_is_subword_aware() {
        // Morphological variants ("editor"/"editing") share char-trigrams, so
        // the blended embedder should rate them more similar than the pure
        // word-hash embedder (which sees them as fully distinct tokens).
        let blended = BlendedEmbedder::default();
        let words = FeatureHashEmbedder;

        let a_b = blended.embed("editor settings");
        let b_b = blended.embed("editing settings");
        let a_w = words.embed("editor settings");
        let b_w = words.embed("editing settings");

        let sim_blended = cosine_similarity(&a_b, &b_b);
        let sim_words = cosine_similarity(&a_w, &b_w);
        assert!(
            sim_blended > sim_words,
            "blended {} should exceed word-only {}",
            sim_blended,
            sim_words
        );
    }

    #[test]
    fn brute_force_index_exact_search() {
        let mut idx = BruteForceIndex::new();
        idx.add(1, embed("rockets and orbital mechanics"));
        idx.add(2, embed("i drink coffee every morning"));
        idx.add(3, embed("tea is a warm beverage"));
        assert_eq!(idx.len(), 3);
        assert!(!idx.is_empty());

        let q = embed("coffee in the morning");
        let hits = idx.search(&q, 2);
        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0].0, 2, "coffee fact should rank first");
        // Non-increasing scores.
        assert!(hits[0].1 >= hits[1].1);
    }

    #[test]
    fn brute_force_index_add_overwrites() {
        let mut idx = BruteForceIndex::new();
        idx.add(7, embed("first"));
        idx.add(7, embed("second"));
        assert_eq!(idx.len(), 1, "same id should overwrite, not duplicate");
    }

    #[test]
    fn lsh_index_overwrites_and_counts() {
        let mut idx = LshIndex::with_dim(EMBED_DIM);
        idx.add(7, embed("first"));
        idx.add(7, embed("second"));
        assert_eq!(idx.len(), 1, "same id should overwrite, not duplicate");
        assert!(!idx.is_empty());
    }

    #[test]
    fn lsh_index_is_deterministic_across_instances() {
        // Two independently-built indexes must hash identically (fixed-seed
        // planes) — the VectorIndex determinism contract.
        let mut a = LshIndex::with_dim(EMBED_DIM);
        let mut b = LshIndex::with_dim(EMBED_DIM);
        for (i, t) in ["alpha beta", "gamma delta", "epsilon"].iter().enumerate() {
            a.add(i as u64, embed(t));
            b.add(i as u64, embed(t));
        }
        let q = embed("alpha beta");
        assert_eq!(a.search(&q, 3), b.search(&q, 3));
    }

    #[test]
    fn lsh_index_finds_planted_nearest_neighbor() {
        // A clearly-closest fact among many noise vectors must surface near the
        // top, even though search probes buckets rather than scanning everything.
        let mut idx = LshIndex::with_dim(EMBED_DIM);
        let target_text = "the user prefers dark mode in the editor";
        idx.add(1000, embed(target_text));
        for i in 0..200u64 {
            idx.add(
                i,
                embed(&format!("unrelated noise fact number {i} about rockets")),
            );
        }
        let q = embed("what editor theme does the user like, dark mode?");
        let hits = idx.search(&q, 5);
        assert!(!hits.is_empty());
        assert!(
            hits.iter().any(|h| h.0 == 1000),
            "planted dark-mode fact should be among the top-5 ANN hits"
        );
        // Scores are non-increasing.
        for w in hits.windows(2) {
            assert!(w[0].1 >= w[1].1);
        }
    }

    #[test]
    fn lsh_search_recall_matches_brute_force_topk() {
        // The LSH top-3 should recover most of the exact top-3 across queries.
        // This pins recall without demanding an approximate index match an exact
        // one perfectly. Deterministic (fixed-seed planes + fixed embeddings).
        let corpus = [
            "rust ownership and borrowing rules",
            "the spacecraft reached orbital velocity at dawn",
            "the user enjoys drinking coffee every morning",
            "dark mode is the preferred editor theme",
            "tokio async runtime and futures",
            "a recipe for sourdough bread starter",
            "linux kernel scheduler and cgroups",
            "the cat slept on the warm windowsill",
        ];
        let mut lsh = LshIndex::with_dim(EMBED_DIM);
        let mut brute = BruteForceIndex::new();
        for (i, t) in corpus.iter().enumerate() {
            lsh.add(i as u64, embed(t));
            brute.add(i as u64, embed(t));
        }
        let queries = [
            "borrow checker in rust",
            "morning coffee habit",
            "editor color theme dark",
            "async futures in tokio",
            "cgroup scheduling on linux",
        ];
        let mut top1_agree = 0;
        let mut overlap = 0usize;
        let mut total = 0usize;
        for q in queries {
            let qv = embed(q);
            let l = lsh.search(&qv, 3);
            let b = brute.search(&qv, 3);
            if l.first().map(|h| h.0) == b.first().map(|h| h.0) {
                top1_agree += 1;
            }
            let lset: std::collections::HashSet<u64> = l.iter().map(|h| h.0).collect();
            overlap += b.iter().filter(|h| lset.contains(&h.0)).count();
            total += b.len();
        }
        // Most queries get the exact best result, and most of the exact top-3 is
        // recovered overall.
        assert!(
            top1_agree >= 3,
            "LSH top-1 agreement too low: {top1_agree}/5"
        );
        assert!(
            overlap * 100 >= total * 80,
            "LSH top-3 recall too low: {overlap}/{total}"
        );
    }

    #[test]
    fn rank_topk_small_is_exact_and_truncates() {
        let items: Vec<(&str, Vec<f32>)> = vec![
            ("rockets", embed("rockets and orbital mechanics")),
            ("coffee", embed("i drink coffee every morning")),
            ("tea", embed("tea is a warm beverage")),
        ];
        let q = embed("coffee in the morning");
        let top = rank_topk(&q, items, 2, 64);
        assert_eq!(top.len(), 2);
        assert_eq!(top[0].0, "coffee", "closest item first");
    }

    #[test]
    fn rank_topk_large_uses_ann_and_finds_target() {
        // Above the exact threshold, rank_topk switches to LSH; the planted
        // closest item must still surface.
        let mut items: Vec<(u64, Vec<f32>)> = (0..300u64)
            .map(|i| (i, embed(&format!("noise document {i} concerning weather"))))
            .collect();
        items.push((9999, embed("the kernel syscall gate enforces capabilities")));
        let q = embed("how does the syscall gate enforce capability checks");
        let top = rank_topk(&q, items, 3, 64);
        assert!(
            top.iter().any(|(id, _)| *id == 9999),
            "ANN should surface the planted target"
        );
    }

    #[test]
    fn memory_manager_default_uses_blended() {
        let mm = MemoryManager::default();
        assert_eq!(mm.embed("hello world"), embed("hello world"));
        assert_eq!(mm.embedder().dim(), EMBED_DIM);
    }

    #[test]
    fn memory_manager_accepts_custom_embedder() {
        let mm = MemoryManager::new(Arc::new(FeatureHashEmbedder));
        assert_eq!(
            mm.embed("hello world"),
            FeatureHashEmbedder.embed("hello world")
        );
    }
}
