//! Deterministic memory-index qualification.
//!
//! Compares the production LSH index against exact cosine search over the same
//! corpus. CI fails closed when top-k recall or top-1 agreement regresses.

use std::collections::HashSet;
use std::time::{Duration, Instant};

use kernel::memory_manager::{
    BlendedEmbedder, BruteForceIndex, Embedder, LshIndex, VectorIndex, EMBED_DIM,
};

const DEFAULT_ITEMS: usize = 10_000;
const DEFAULT_QUERIES: usize = 100;
const TOP_K: usize = 10;
const MIN_RECALL: f64 = 0.80;
const MIN_TOP1_AGREEMENT: f64 = 0.99;

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(default)
}

fn corpus_item(id: usize) -> String {
    format!(
        "tenant t{:03} project p{:04} incident i{id:06} service s{:02} \
         observed timeout during deployment; remediation rotated credential \
         c{:05} and restarted worker w{:03}",
        id % 127,
        id % 997,
        id % 43,
        id % 8191,
        id % 251,
    )
}

fn percentile_95(samples: &mut [Duration]) -> u128 {
    if samples.is_empty() {
        return 0;
    }
    samples.sort_unstable();
    let index = (samples.len() - 1) * 95 / 100;
    samples[index].as_micros()
}

#[cfg(target_os = "linux")]
fn resident_memory_kib() -> Option<u64> {
    std::fs::read_to_string("/proc/self/status")
        .ok()?
        .lines()
        .find_map(|line| line.strip_prefix("VmRSS:"))
        .and_then(|value| value.split_whitespace().next())
        .and_then(|value| value.parse().ok())
}

#[cfg(not(target_os = "linux"))]
fn resident_memory_kib() -> Option<u64> {
    None
}

fn main() {
    let items = env_usize("MEMORY_BENCH_ITEMS", DEFAULT_ITEMS);
    let queries = env_usize("MEMORY_BENCH_QUERIES", DEFAULT_QUERIES).min(items);
    let embedder = BlendedEmbedder::default();
    let mut exact = BruteForceIndex::new();
    let mut approximate = LshIndex::with_dim(EMBED_DIM);

    let build_started = Instant::now();
    let mut query_vectors = Vec::with_capacity(queries);
    let selected: HashSet<usize> = (0..queries)
        .map(|query| query.saturating_mul(7_919) % items)
        .collect();
    for id in 0..items {
        let vector = embedder.embed(&corpus_item(id));
        if selected.contains(&id) {
            query_vectors.push((id, vector.clone()));
        }
        exact.add(id as u64, vector.clone());
        approximate.add(id as u64, vector);
    }
    query_vectors.sort_unstable_by_key(|(id, _)| *id);
    let build_ms = build_started.elapsed().as_millis();

    let mut exact_durations = Vec::with_capacity(query_vectors.len());
    let mut approximate_durations = Vec::with_capacity(query_vectors.len());
    let mut recall_sum = 0.0f64;
    let mut top1_matches = 0usize;
    for (_, query) in &query_vectors {
        let exact_started = Instant::now();
        let exact_hits = exact.search(query, TOP_K);
        exact_durations.push(exact_started.elapsed());

        let approximate_started = Instant::now();
        let approximate_hits = approximate.search(query, TOP_K);
        approximate_durations.push(approximate_started.elapsed());

        let expected: HashSet<u64> = exact_hits.iter().map(|(id, _)| *id).collect();
        let overlap = approximate_hits
            .iter()
            .filter(|(id, _)| expected.contains(id))
            .count();
        recall_sum += overlap as f64 / exact_hits.len().max(1) as f64;
        if exact_hits.first().map(|hit| hit.0) == approximate_hits.first().map(|hit| hit.0) {
            top1_matches += 1;
        }
    }

    let evaluated_queries = query_vectors.len().max(1);
    let recall_at_10 = recall_sum / evaluated_queries as f64;
    let top1_agreement = top1_matches as f64 / evaluated_queries as f64;
    let exact_p95_us = percentile_95(&mut exact_durations);
    let approximate_p95_us = percentile_95(&mut approximate_durations);
    let vector_bytes_estimate = items
        .saturating_mul(EMBED_DIM)
        .saturating_mul(std::mem::size_of::<f32>())
        .saturating_mul(2);

    let report = serde_json::json!({
        "schema_version": 1,
        "embedding": {
            "model": embedder.model_id(),
            "version": embedder.version(),
            "dimensions": embedder.dim()
        },
        "corpus_items": items,
        "queries": query_vectors.len(),
        "top_k": TOP_K,
        "recall_at_10": recall_at_10,
        "top1_agreement": top1_agreement,
        "thresholds": {
            "minimum_recall_at_10": MIN_RECALL,
            "minimum_top1_agreement": MIN_TOP1_AGREEMENT
        },
        "timing": {
            "build_ms": build_ms,
            "exact_query_p95_us": exact_p95_us,
            "ann_query_p95_us": approximate_p95_us
        },
        "memory": {
            "index_vector_bytes_estimate": vector_bytes_estimate,
            "resident_kib_linux": resident_memory_kib()
        },
        "passed": recall_at_10 >= MIN_RECALL && top1_agreement >= MIN_TOP1_AGREEMENT
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&report).expect("serialize benchmark report")
    );

    if recall_at_10 < MIN_RECALL || top1_agreement < MIN_TOP1_AGREEMENT {
        eprintln!(
            "memory qualification failed: recall@10={recall_at_10:.3}, \
             top1={top1_agreement:.3}"
        );
        std::process::exit(1);
    }
}
