# Sustained context memory fixture

Issue #358 extends the index-only gate with the production
`SqliteContextManager::query_memory_for_tenant` path. The fixture is synthetic,
offline and single-process. It never authorizes deployment SLO, real-model or
24-hour soak claims; those remain in #125.

Run the full fixture with the pinned toolchain:

```bash
MEMORY_BENCH_ITEMS=100000 cargo run -p os-benchmark --bin memory-qualification --locked
```

The 10k default remains the existing blocking exact-versus-ANN index gate.
At 100k items the binary selects the context-manager mode automatically.
`MEMORY_BENCH_MODE=production` selects that mode for smaller smoke fixtures;
128..100000 items and 1..300 seconds are accepted. A full 100k run requires at
least 60 seconds. Smoke or non-Linux/dirty-source runs cannot report successful
scale qualification.

## Measurement and limits

Fixture preparation creates a normal versioned store and two durable owned
identities, closes the runtime and populates synthetic legacy JSON facts in one
offline transaction. The runtime reopens and performs its ordinary migration.
Preparation and reopen/migration are recorded separately. An independent exact
index is used only to judge retrieval quality; it never answers the timed queries.

The first cold query includes row loading, vector validation and index build.
The next 100 planted queries measure the full API, including SQLite locking,
ranking and last-access updates. Two readers and two disjoint-ID writers then
run concurrent query/update traffic for 60 seconds. All latency samples include
connection-mutex wait. Read/write arrivals have 25/100 ms intervals.

The report records p50/p95/p99/max for warm reads, sustained reads and sustained
writes. Process-lifetime peak RSS comes from getrusage and includes fixture
preparation, the exact oracle, runtime warming and final integrity verification.
The scope has finite logical-byte allowances: 512 MiB per agent, 768 MiB per
tenant and 1 GiB globally.

Fixed fail-closed thresholds are:

- Recall@10 >= 0.80 and top-one agreement >= 0.99.
- Cold query <= 60 seconds; warm-read p95 <= 500 ms.
- Concurrent-read p95 <= 1 second; process peak RSS <= 1 GiB.
- At least 128 reads and 20 writes during at least 60 seconds at 100k.
- No traffic errors, missing/unexpected/duplicated facts or content/hash/model
  metadata mismatches; the other tenant's sentinel remains unchanged.

After traffic, changed vectors are updated in the independent exact oracle and
up to 100 changed-fact queries must pass the same recall/top-one quality floors.
Every persisted owner row is compared with the exact original
or latest successful writer content. IDs and physical row counts are checked
separately. Cross-tenant queries must remain empty. Unknown peak memory and
missing measurements fail their checks.

Normal stores and updates reconcile one retained fact/index entry inside the
same transaction. External revision changes and full reindexing still warm the
store again. Deletion and subject erasure retain cache reclamation. A failed
commit cannot expose staged cached content because its durable generation differs.
Fact replacements and updates use the same UTF-8 content/binary-vector byte
accounting; update admission now enforces existing context limits atomically.

## Evidence workflow

`retrieval-scale.yml` runs the full fixture nightly, manually and separately on
relevant PR changes. It does not join the existing 10k required-release-gates
job. Each run retains JSON and exact source identity for 30 days, requires a
clean Linux checkout and explicitly checks that production claims remain false.
The report's development-profile timings describe that runner and this corpus.
The [retained Linux 100k run](../benchmarks/retrieval/2026-10-08-linux-100k/README.md)
passed all scale gates. The capability's fixture-scale gap is fulfilled; deployment
SLO and 24-hour soak requirements remain separate in #125.
