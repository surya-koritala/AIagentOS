# Retained semantic memory retrieval

The public MemoryStore/Query/Update/Delete/Reindex syscalls and SDK remain the
entry points. Query returns up to 16 owned facts ranked by cosine similarity.
Stores of at most 64 facts use exact search; larger stores use the same
16-table, 8-bit LSH signatures and radius-one probes as before. The offline
256-dimensional blended-feature-hash embedder remains the default.

The context manager warms fact rows and a private index on first query, then
retains them across unchanged queries. Immutable planes are shared by index
configuration. Vector norms are retained, candidate buckets use sparse bitsets,
and only the returned score prefix is sorted. These changes preserve the
candidate union, scores and insertion order. Score ties use durable last-access
order followed by row insertion order. LSH previously relied on unordered
hash-set traversal for ties; it now honors its deterministic insertion contract.

SQL triggers maintain each agent's durable revision for inserts, updates,
deletes, repairs, reindexing and access metadata. Normal stores/updates reconcile
one cached fact and vector inside their transaction. Unknown revision changes or
full reindexing force the next query to warm authoritative rows again. The query's own access updates
advance its cached revision without another reload. Trigger definitions are
checked exactly at restart alongside the existing accounting trigger checks.

The process cache retains at most 16 agents and an estimated 512 MiB, evicting
least-recently-used entries. A store above that allowance is searched transiently
without retaining its index. Fact deletion drops the agent's cached rows
immediately. Successful agent erasure drops that entry; successful tenant
erasure clears the cache. Other tenants' durable facts remain intact.

Schema 10 stores finite vectors as a versioned binary header, little-endian
length and float bits. Opening a legacy JSON database converts valid vectors
inside the existing atomic schema transaction. Model, version, dimension,
content hash and blob shape are checked when warming; stale/corrupt rows are
rebuilt with the configured embedder. Byte quotas count both legacy JSON and
binary representations. Encryption, backups and subject erasure cover the same
SQLite store. Binary embeddings were introduced in schema 10. The current store also retains
native assistant replay state; readers below schema 11 must not open it.

## Verification

Unit regressions prove no full row reload or fact embedding on a second query,
next-query mutation/repair visibility, exact JSON migration ordering, schema-nine
upgrade, late migration rollback, restart tie ordering, exact trigger refusal,
LRU eviction and agent/tenant erasure. Existing memory properties, cross-owner
checks and the 160-concurrent-write regression remain required.

`cargo run -p os-benchmark --bin memory-qualification --locked` compares both
indexes on the same corpus. At the default 10,000 items/100 planted queries,
recall@10 must be at least 0.80, top-one agreement at least 0.99, and ANN p95
must be below exact p95. Timings are specific to that host/build and measure
index searches; they exclude database warming and are not a deployment SLO.
The [100k context fixture](RETRIEVAL_SCALE.md) adds concurrent API traffic and
peak-memory checks. Actual deployment and 24-hour soak qualification remain #125.
