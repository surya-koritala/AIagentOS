//! Production context-manager path with bounded concurrent mutation traffic.

use std::collections::{BTreeMap, HashSet};
use std::path::Path;
use std::process::Command;
use std::sync::{Arc, Barrier};
use std::time::{Duration, Instant};

use chrono::Utc;
use kernel::context::{ContextStorageLimits, PersistedAgent, SqliteContextManager};
use kernel::memory_manager::{BlendedEmbedder, BruteForceIndex, Embedder, VectorIndex};
use rusqlite::{params, Connection};
use serde_json::{json, Value};
use uuid::Uuid;

const FULL_ITEMS: usize = 100_000;
const MIN_SOAK_SECONDS: u64 = 60;
const MAX_PEAK_RSS_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_COLD_QUERY_MS: u64 = 60_000;
const MAX_WARM_P95_US: u128 = 500_000;
const MAX_SUSTAINED_P95_US: u128 = 1_000_000;
const READERS: usize = 2;
const WRITERS: usize = 2;
const MIN_FULL_READS: usize = 128;
const MIN_FULL_WRITES: usize = 20;
const OWNER: Uuid = Uuid::from_u128(1_u128 << 100);
const FOREIGN: Uuid = Uuid::from_u128((1_u128 << 100) + 1);
const TENANT: &str = "memory-fixture-a";
const LIMITS: ContextStorageLimits = ContextStorageLimits {
    per_agent_bytes: 512 * 1024 * 1024,
    per_tenant_bytes: 768 * 1024 * 1024,
    global_bytes: 1024 * 1024 * 1024,
    spill_retention_seconds: 30 * 24 * 60 * 60,
};

fn runtime() -> Result<tokio::runtime::Runtime, String> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| error.to_string())
}
fn hash(content: &str) -> String {
    ring::digest::digest(&ring::digest::SHA256, content.as_bytes())
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
fn fact_id(id: usize) -> Uuid {
    Uuid::from_u128(id as u128 + 1)
}
fn text(id: usize) -> String {
    super::corpus_item(id)
}
fn identity(id: Uuid, tenant: &str) -> PersistedAgent {
    let now = Utc::now();
    PersistedAgent {
        id,
        session_id: Uuid::new_v4(),
        tenant_id: tenant.into(),
        name: "memory fixture".into(),
        task: "retrieval qualification".into(),
        llm_provider: "offline".into(),
        permission_profile: "standard".into(),
        priority: 3,
        status: "\"Running\"".into(),
        sandbox_config_json: None,
        created_at: now,
        last_activity_at: now,
    }
}
fn percentile(samples: &[u128], p: usize) -> u128 {
    if samples.is_empty() {
        return 0;
    }
    let mut sorted = samples.to_vec();
    sorted.sort_unstable();
    sorted[(sorted.len() * p)
        .div_ceil(100)
        .saturating_sub(1)
        .min(sorted.len() - 1)]
}
fn latency(samples: &[u128]) -> Value {
    json!({"samples":samples.len(),"p50_us":percentile(samples,50),"p95_us":percentile(samples,95),"p99_us":percentile(samples,99),"max_us":samples.iter().copied().max().unwrap_or(0)})
}
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn peak_rss_bytes() -> Option<u64> {
    let mut usage = std::mem::MaybeUninit::<libc::rusage>::zeroed();
    // The kernel writes exactly one rusage record to this valid pointer.
    if unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) } != 0 {
        return None;
    }
    let usage = unsafe { usage.assume_init() };
    let maximum = u64::try_from(usage.ru_maxrss).ok()?;
    #[cfg(target_os = "linux")]
    {
        Some(maximum.saturating_mul(1024))
    }
    #[cfg(target_os = "macos")]
    {
        Some(maximum)
    }
}
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn peak_rss_bytes() -> Option<u64> {
    None
}

/// Offline fixture preparation uses one transaction before timing. The runtime
/// is closed while SQLite is populated, then reopened normally to migrate JSON
/// and verify its schema. No benchmark-owned index serves production queries.
fn prepare(path: &Path, items: usize) -> Result<BruteForceIndex, String> {
    let manager = SqliteContextManager::new(path).map_err(|e| e.to_string())?;
    manager
        .save_agent(&identity(OWNER, TENANT))
        .map_err(|e| e.to_string())?;
    manager
        .save_agent(&identity(FOREIGN, "memory-fixture-b"))
        .map_err(|e| e.to_string())?;
    drop(manager);
    let mut conn = Connection::open(path).map_err(|e| e.to_string())?;
    let tx = conn.transaction().map_err(|e| e.to_string())?;
    let embedder = BlendedEmbedder::default();
    let now = "2026-10-08T00:00:00+00:00";
    let mut exact = BruteForceIndex::new();
    {
        let mut statement=tx.prepare("INSERT INTO facts(id,agent_id,content,category,created_at,last_accessed_at,embedding_json,embedding_model,embedding_version,embedding_dim,content_hash) VALUES(?1,?2,?3,'\"Fact\"',?4,?4,?5,?6,?7,?8,?9)").map_err(|e|e.to_string())?;
        for id in 0..items {
            let content = text(id);
            let vector = embedder.embed(&content);
            statement
                .execute(params![
                    fact_id(id).to_string(),
                    OWNER.to_string(),
                    content,
                    now,
                    serde_json::to_string(&vector).map_err(|e| e.to_string())?,
                    embedder.model_id(),
                    embedder.version(),
                    embedder.dim() as i64,
                    hash(&content)
                ])
                .map_err(|e| e.to_string())?;
            exact.add(id as u64, vector);
        }
        let content = "foreign confidential memory marker";
        let vector = embedder.embed(content);
        statement
            .execute(params![
                Uuid::from_u128(u128::MAX).to_string(),
                FOREIGN.to_string(),
                content,
                now,
                serde_json::to_string(&vector).map_err(|e| e.to_string())?,
                embedder.model_id(),
                embedder.version(),
                embedder.dim() as i64,
                hash(content)
            ])
            .map_err(|e| e.to_string())?;
    }
    tx.commit().map_err(|e| e.to_string())?;
    Ok(exact)
}

struct WorkerResult {
    durations: Vec<u128>,
    updates: BTreeMap<usize, String>,
    errors: Vec<String>,
    isolation_failures: usize,
}
fn concurrent(
    manager: &Arc<SqliteContextManager>,
    items: usize,
    seconds: u64,
) -> Result<(WorkerResult, WorkerResult, f64), String> {
    let barrier = Arc::new(Barrier::new(READERS + WRITERS + 1));
    let started = Instant::now();
    let results = std::thread::scope(|scope| {
        let mut workers = Vec::new();
        for reader in 0..READERS {
            let manager = Arc::clone(manager);
            let barrier = Arc::clone(&barrier);
            workers.push(scope.spawn(move || {
                let mut result = WorkerResult {
                    durations: Vec::new(),
                    updates: BTreeMap::new(),
                    errors: Vec::new(),
                    isolation_failures: 0,
                };
                let rt = match runtime() {
                    Ok(rt) => rt,
                    Err(error) => {
                        barrier.wait();
                        result.errors.push(error);
                        return result;
                    }
                };
                barrier.wait();
                let started = Instant::now();
                let mut iteration = 0usize;
                while started.elapsed() < Duration::from_secs(seconds) {
                    let query = text((reader + iteration * 7919) % items);
                    let tick = Instant::now();
                    match rt.block_on(manager.query_memory_for_tenant(TENANT, OWNER, &query)) {
                        Ok(facts) => {
                            if facts.is_empty()
                                || facts
                                    .iter()
                                    .any(|fact| fact.id == Uuid::from_u128(u128::MAX))
                            {
                                result.isolation_failures += 1;
                            }
                        }
                        Err(error) => result.errors.push(error.to_string()),
                    }
                    result.durations.push(tick.elapsed().as_micros());
                    iteration += 1;
                    std::thread::sleep(Duration::from_millis(25));
                }
                result
            }));
        }
        for writer in 0..WRITERS {
            let manager = Arc::clone(manager);
            let barrier = Arc::clone(&barrier);
            workers.push(scope.spawn(move || {
                let mut result = WorkerResult {
                    durations: Vec::new(),
                    updates: BTreeMap::new(),
                    errors: Vec::new(),
                    isolation_failures: 0,
                };
                barrier.wait();
                let started = Instant::now();
                let mut iteration = 0usize;
                while started.elapsed() < Duration::from_secs(seconds) {
                    // Disjoint writer IDs make the final expected content exact,
                    // independent of thread scheduling or operation completion order.
                    let id = ((iteration * 47) % (items / WRITERS)) * WRITERS + writer;
                    let content =
                        format!("{} update writer {writer} sequence {iteration}", text(id));
                    let tick = Instant::now();
                    match manager.update_fact(OWNER, fact_id(id), &content) {
                        Ok(true) => {
                            result.updates.insert(id, content);
                        }
                        Ok(false) => result
                            .errors
                            .push("owned fact missing during update".into()),
                        Err(error) => result.errors.push(error.to_string()),
                    }
                    result.durations.push(tick.elapsed().as_micros());
                    iteration += 1;
                    std::thread::sleep(Duration::from_millis(100));
                }
                result
            }));
        }
        barrier.wait();
        workers
            .into_iter()
            .map(|handle| {
                handle
                    .join()
                    .map_err(|_| "memory traffic worker panicked".to_string())
            })
            .collect::<Result<Vec<_>, _>>()
    })?;
    let mut readers = WorkerResult {
        durations: Vec::new(),
        updates: BTreeMap::new(),
        errors: Vec::new(),
        isolation_failures: 0,
    };
    let mut writers = WorkerResult {
        durations: Vec::new(),
        updates: BTreeMap::new(),
        errors: Vec::new(),
        isolation_failures: 0,
    };
    for (position, result) in results.into_iter().enumerate() {
        let aggregate = if position < READERS {
            &mut readers
        } else {
            &mut writers
        };
        aggregate.durations.extend(result.durations);
        aggregate.updates.extend(result.updates);
        aggregate.errors.extend(result.errors);
        aggregate.isolation_failures += result.isolation_failures;
    }
    Ok((readers, writers, started.elapsed().as_secs_f64()))
}

fn verify_store(
    path: &Path,
    items: usize,
    updates: &BTreeMap<usize, String>,
) -> Result<Value, String> {
    let conn = Connection::open(path).map_err(|e| e.to_string())?;
    let embedder = BlendedEmbedder::default();
    let mut statement=conn.prepare("SELECT id,content,embedding_model,embedding_version,embedding_dim,content_hash FROM facts WHERE agent_id=?1 ORDER BY id").map_err(|e|e.to_string())?;
    let rows = statement
        .query_map([OWNER.to_string()], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, String>(5)?,
            ))
        })
        .map_err(|e| e.to_string())?;
    let mut seen = HashSet::new();
    let mut row_count = 0usize;
    let mut mismatches = 0usize;
    for row in rows {
        row_count += 1;
        let (id, content, model, version, dimension, stored_hash) =
            row.map_err(|e| e.to_string())?;
        let uuid = id.parse::<Uuid>().map_err(|e| e.to_string())?;
        let ordinal =
            usize::try_from(uuid.as_u128().saturating_sub(1)).map_err(|e| e.to_string())?;
        let expected = updates
            .get(&ordinal)
            .cloned()
            .unwrap_or_else(|| text(ordinal));
        if ordinal >= items
            || content != expected
            || stored_hash != hash(&content)
            || model != embedder.model_id()
            || version != i64::from(embedder.version())
            || dimension != embedder.dim() as i64
        {
            mismatches += 1;
        }
        seen.insert(uuid);
    }
    let expected = (0..items).map(fact_id).collect::<HashSet<_>>();
    let missing = expected.difference(&seen).count();
    let unexpected = seen.difference(&expected).count();
    let foreign: String = conn
        .query_row(
            "SELECT content FROM facts WHERE id=?1 AND agent_id=?2",
            params![Uuid::from_u128(u128::MAX).to_string(), FOREIGN.to_string()],
            |row| row.get(0),
        )
        .map_err(|e| e.to_string())?;
    Ok(
        json!({"expected_facts":items,"actual_distinct_facts":seen.len(),"actual_rows":row_count,"duplicate_ids":row_count.saturating_sub(seen.len()),"missing_facts":missing,"unexpected_facts":unexpected,"content_or_metadata_mismatches":mismatches,"foreign_fact_unchanged":foreign=="foreign confidential memory marker","passed":row_count==items&&missing==0&&unexpected==0&&mismatches==0&&foreign=="foreign confidential memory marker"}),
    )
}

fn quality_phase(
    rt: &tokio::runtime::Runtime,
    manager: &SqliteContextManager,
    exact: &BruteForceIndex,
    inputs: &[(usize, String)],
) -> Result<(Vec<u128>, Value), String> {
    let embedder = BlendedEmbedder::default();
    let mut durations = Vec::new();
    let mut overlap = 0_f64;
    let mut top1 = 0usize;
    for (_, query) in inputs {
        let expected = exact.search(&embedder.embed(query), 10);
        let expected_ids = expected
            .iter()
            .map(|(id, _)| fact_id(*id as usize))
            .collect::<HashSet<_>>();
        let tick = Instant::now();
        let actual = rt
            .block_on(manager.query_memory_for_tenant(TENANT, OWNER, query))
            .map_err(|e| e.to_string())?;
        durations.push(tick.elapsed().as_micros());
        overlap += actual
            .iter()
            .take(10)
            .filter(|fact| expected_ids.contains(&fact.id))
            .count() as f64
            / 10.;
        if actual.first().map(|fact| fact.id)
            == expected.first().map(|(id, _)| fact_id(*id as usize))
        {
            top1 += 1;
        }
    }
    let denominator = inputs.len().max(1) as f64;
    Ok((
        durations,
        json!({"queries":inputs.len(),"recall_at_10":overlap/denominator,"top1_agreement":top1 as f64/denominator}),
    ))
}

fn source() -> Value {
    let output = |arguments: &[&str]| {
        Command::new("git")
            .args(arguments)
            .output()
            .ok()
            .filter(|result| result.status.success())
            .map(|result| String::from_utf8_lossy(&result.stdout).trim().to_string())
    };
    json!({"commit":output(&["rev-parse","HEAD"]),"dirty":output(&["status","--porcelain"]).map(|status|!status.is_empty()),"os":std::env::consts::OS,"architecture":std::env::consts::ARCH,"build_profile":if cfg!(debug_assertions){"dev"}else{"release"}})
}

fn failures(report: &Value) -> Vec<&'static str> {
    let mut errors = Vec::new();
    if report["quality"]["recall_at_10"].as_f64().unwrap_or(0.) < 0.80 {
        errors.push("recall@10");
    }
    if report["quality"]["top1_agreement"].as_f64().unwrap_or(0.) < 0.99 {
        errors.push("top-one agreement");
    }
    if report["quality_post_mutation"]["recall_at_10"]
        .as_f64()
        .unwrap_or(0.)
        < 0.80
    {
        errors.push("post-mutation recall@10");
    }
    if report["quality_post_mutation"]["top1_agreement"]
        .as_f64()
        .unwrap_or(0.)
        < 0.99
    {
        errors.push("post-mutation top-one agreement");
    }
    if report["latency"]["cold_query_ms"]
        .as_u64()
        .unwrap_or(u64::MAX)
        > MAX_COLD_QUERY_MS
    {
        errors.push("cold query latency");
    }
    if report["latency"]["warm"]["p95_us"]
        .as_u64()
        .unwrap_or(u64::MAX) as u128
        > MAX_WARM_P95_US
    {
        errors.push("warm p95 latency");
    }
    if report["latency"]["sustained_read"]["p95_us"]
        .as_u64()
        .unwrap_or(u64::MAX) as u128
        > MAX_SUSTAINED_P95_US
    {
        errors.push("sustained p95 latency");
    }
    if report["memory"]["peak_rss_bytes"]
        .as_u64()
        .is_none_or(|rss| rss == 0 || rss > MAX_PEAK_RSS_BYTES)
    {
        errors.push("peak RSS");
    }
    if !report["integrity"]["passed"].as_bool().unwrap_or(false) {
        errors.push("fact integrity");
    }
    if !report["isolation_passed"].as_bool().unwrap_or(false) {
        errors.push("tenant isolation");
    }
    if report["traffic"]["errors"].as_u64().unwrap_or(u64::MAX) != 0 {
        errors.push("traffic error");
    }
    let full = report["corpus_items"].as_u64() == Some(FULL_ITEMS as u64);
    if full && report["queries"].as_u64().unwrap_or(0) < 100 {
        errors.push("insufficient quality queries");
    }
    if full
        && report["quality_post_mutation"]["queries"]
            .as_u64()
            .unwrap_or(0)
            < 20
    {
        errors.push("insufficient post-mutation quality queries");
    }
    if report["latency"]["warm"]["samples"].as_u64().unwrap_or(0)
        < report["queries"].as_u64().unwrap_or(1)
    {
        errors.push("missing warm latency samples");
    }
    let required_reads = if full { MIN_FULL_READS } else { 1 };
    let required_writes = if full { MIN_FULL_WRITES } else { 1 };
    if report["traffic"]["reads"].as_u64().unwrap_or(0) < required_reads as u64 {
        errors.push("insufficient read traffic");
    }
    if report["traffic"]["writes"].as_u64().unwrap_or(0) < required_writes as u64 {
        errors.push("insufficient write traffic");
    }
    if full && report["traffic"]["elapsed_seconds"].as_f64().unwrap_or(0.) < MIN_SOAK_SECONDS as f64
    {
        errors.push("insufficient sustained duration");
    }
    errors
}

pub(super) fn run(items: usize, queries: usize) -> Result<(), String> {
    if !(128..=FULL_ITEMS).contains(&items) || queries == 0 {
        return Err("production mode requires 128..=100000 facts and nonzero queries".into());
    }
    let seconds = match std::env::var("MEMORY_BENCH_SOAK_SECONDS") {
        Ok(value) => value.parse::<u64>().map_err(|_| "invalid soak duration")?,
        Err(_) => MIN_SOAK_SECONDS,
    };
    if !(1..=300).contains(&seconds) {
        return Err("soak duration must be 1..=300 seconds".into());
    }
    if items == FULL_ITEMS && seconds < MIN_SOAK_SECONDS {
        return Err("100k qualification requires at least 60 seconds of sustained traffic".into());
    }
    let directory = tempfile::tempdir().map_err(|e| e.to_string())?;
    let path = directory.path().join("memory.db");
    let prepare_started = Instant::now();
    let mut exact = prepare(&path, items)?;
    let fixture_ms = prepare_started.elapsed().as_millis();
    let reopen_started = Instant::now();
    let manager = Arc::new(SqliteContextManager::new(&path).map_err(|e| e.to_string())?);
    manager
        .set_context_storage_limits(LIMITS)
        .map_err(|e| e.to_string())?;
    let reopen_ms = reopen_started.elapsed().as_millis();
    let rt = runtime()?;
    let embedder = BlendedEmbedder::default();
    let cold_started = Instant::now();
    rt.block_on(manager.query_memory_for_tenant(TENANT, OWNER, &text(0)))
        .map_err(|e| e.to_string())?;
    let cold_query_ms = cold_started.elapsed().as_millis();
    let inputs = (0..queries)
        .map(|ordinal| {
            let id = ordinal.saturating_mul(7919) % items;
            (id, text(id))
        })
        .collect::<Vec<_>>();
    let (warm, quality) = quality_phase(&rt, &manager, &exact, &inputs)?;
    let wrong_tenant = rt
        .block_on(manager.query_memory_for_tenant("memory-fixture-b", OWNER, "incident"))
        .map_err(|e| e.to_string())?;
    let (reads, writes, elapsed) = concurrent(&manager, items, seconds)?;
    for (&id, content) in &writes.updates {
        exact.add(id as u64, embedder.embed(content));
    }
    let post_inputs = writes
        .updates
        .iter()
        .take(queries)
        .map(|(&id, content)| (id, content.clone()))
        .collect::<Vec<_>>();
    let (post_latencies, post_quality) = quality_phase(&rt, &manager, &exact, &post_inputs)?;
    drop(exact);
    manager.checkpoint().map_err(|e| e.to_string())?;
    let integrity = verify_store(&path, items, &writes.updates)?;
    let mut report = json!({"schema_version":3,"mode":"production-context","evidence_class":"synthetic-context-scale","production_claim_allowed":false,"corpus_items":items,"queries":queries,"source":source(),"provider_api_calls":0,"preparation":{"offline_fixture_ms":fixture_ms,"reopen_and_json_migration_ms":reopen_ms},"embedding":{"model":embedder.model_id(),"version":embedder.version(),"dimensions":embedder.dim()},"storage_limits":{"per_agent_bytes":LIMITS.per_agent_bytes,"per_tenant_bytes":LIMITS.per_tenant_bytes,"global_bytes":LIMITS.global_bytes},"quality":quality,"quality_post_mutation":post_quality,"latency":{"cold_query_ms":cold_query_ms,"warm":latency(&warm),"post_mutation":latency(&post_latencies),"sustained_read":latency(&reads.durations),"sustained_write":latency(&writes.durations)},"memory":{"peak_rss_bytes":peak_rss_bytes(),"measurement":"getrusage process-lifetime peak; includes preparation and exact oracle"},"traffic":{"readers":READERS,"writers":WRITERS,"read_interval_ms":25,"write_interval_ms":100,"requested_seconds":seconds,"elapsed_seconds":elapsed,"reads":reads.durations.len(),"writes":writes.durations.len(),"distinct_updated_facts":writes.updates.len(),"errors":reads.errors.len()+writes.errors.len(),"diagnostics":reads.errors.iter().chain(&writes.errors).take(16).collect::<Vec<_>>()},"integrity":integrity,"isolation_passed":wrong_tenant.is_empty()&&reads.isolation_failures==0,"thresholds":{"minimum_recall_at_10":0.8,"minimum_top1_agreement":0.99,"max_cold_query_ms":MAX_COLD_QUERY_MS,"max_warm_p95_us":MAX_WARM_P95_US,"max_sustained_p95_us":MAX_SUSTAINED_P95_US,"max_peak_rss_bytes":MAX_PEAK_RSS_BYTES,"minimum_full_seconds":MIN_SOAK_SECONDS,"minimum_full_reads":MIN_FULL_READS,"minimum_full_writes":MIN_FULL_WRITES}});
    let failed = failures(&report);
    report["passed"] = json!(failed.is_empty());
    report["failed_checks"] = json!(failed);
    report["scale_qualification_passed"] = json!(
        failed.is_empty()
            && items == FULL_ITEMS
            && std::env::consts::OS == "linux"
            && report["source"]["dirty"] == false
            && report["source"]["commit"].as_str().is_some_and(
                |commit| commit.len() == 40 && commit.bytes().all(|b| b.is_ascii_hexdigit())
            )
    );
    println!(
        "{}",
        serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?
    );
    if !failed.is_empty() {
        return Err(format!("failed checks: {}", failed.join(", ")));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn percentiles_include_the_tail_and_handle_empty_samples() {
        assert_eq!(percentile(&[8, 1, 6, 2, 3], 50), 3);
        assert_eq!(percentile(&[8, 1, 6, 2, 3], 95), 8);
        assert_eq!(percentile(&[], 99), 0);
    }
    #[test]
    fn gates_fail_closed_on_missing_or_bad_evidence() {
        let report = json!({});
        assert!(failures(&report).len() >= 9);
        let report = json!({"corpus_items":100000,"queries":100,"quality":{"recall_at_10":1.,"top1_agreement":1.},"quality_post_mutation":{"queries":20,"recall_at_10":1.,"top1_agreement":1.},"latency":{"cold_query_ms":1,"warm":{"p95_us":1,"samples":100},"sustained_read":{"p95_us":1}},"memory":{"peak_rss_bytes":1},"integrity":{"passed":true},"isolation_passed":true,"traffic":{"errors":0,"reads":128,"writes":20,"elapsed_seconds":60.}});
        assert!(failures(&report).is_empty());
        for (section, key, bad) in [
            ("quality", "recall_at_10", json!(0.79)),
            ("quality", "top1_agreement", json!(0.98)),
            ("memory", "peak_rss_bytes", json!(MAX_PEAK_RSS_BYTES + 1)),
            ("integrity", "passed", json!(false)),
            ("traffic", "errors", json!(1)),
            ("traffic", "reads", json!(127)),
            ("traffic", "writes", json!(19)),
            ("traffic", "elapsed_seconds", json!(59.9)),
        ] {
            let mut broken = report.clone();
            broken[section][key] = bad;
            assert!(!failures(&broken).is_empty(), "{section}.{key}");
        }
        for (key, limit) in [
            ("warm", MAX_WARM_P95_US),
            ("sustained_read", MAX_SUSTAINED_P95_US),
        ] {
            let mut broken = report.clone();
            broken["latency"][key]["p95_us"] = json!(limit + 1);
            assert!(!failures(&broken).is_empty());
        }
    }
}
