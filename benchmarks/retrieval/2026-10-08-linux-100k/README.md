# Sustained 100k context-manager fixture

Measured 2026-10-08 on GitHub-hosted Ubuntu 24.04 x86_64, Rust 1.97.1, default
development build. Source head 4afe08b12b410df9c298d07776188e9a17e1406c; tested
merge 35bc5ad0c2b4f85e25bb26dbf362de3dee139927 against the retrieval-cache branch.

[Run 37772086443](https://github.com/surya-koritala/AIagentOS/actions/runs/37772086443),
[job 113293880259](https://github.com/surya-koritala/AIagentOS/actions/runs/37772086443/job/113293880259),
artifact 11547899166. Raw [results](results.json), [job log](job.log), exact source
metadata and SHA-256 digests are retained together.

| Phase | Samples | p50 ms | p95 ms | p99 ms | Maximum ms |
| --- | --- | --- | --- | --- | --- |
| Warm full-API queries | 100 | 111.987 | 135.619 | 196.676 | 210.313 |
| Concurrent full-API reads | 189 | 603.677 | 839.088 | 926.674 | 937.069 |
| Concurrent API updates | 189 | 417.987 | 895.003 | 965.354 | 984.869 |
| Post-update quality queries | 100 | 111.501 | 142.871 | 214.061 | 265.469 |

The first cold query, including fact loading and index build, took 16.035
seconds. Both original and changed-fact query phases had recall@10 1.0 and
exact top-one agreement 1.0. Two readers and two writers ran for 60.446 seconds;
all 100,000 physical/distinct facts retained exact expected content/hash/model
metadata, with no missing/unexpected/duplicate facts, errors or tenant leakage.
The other tenant's sentinel remained unchanged.

Process-lifetime peak RSS was 398,667,776 bytes. getrusage includes fixture
preparation, the independent exact oracle, runtime warming and final integrity
checks; this is peak memory, not a settled/current sample. The fixed 1 GiB peak,
500 ms warm p95, 1 second concurrent p95, 60 second cold query, recall 0.80,
top-one 0.99 and minimum traffic/duration gates all passed unchanged.

Reproduce:

```bash
MEMORY_BENCH_ITEMS=100000 cargo run -p os-benchmark --bin memory-qualification --locked
```

Synthetic legacy JSON fixtures are prepared offline in a closed runtime, then
reopened and migrated normally. Timed queries and traffic use the actual context
manager with finite 512 MiB agent/768 MiB tenant/1 GiB global byte limits. Normal
mutations reconcile private cached entries; commit-failure and quota regressions
are separate required tests. The independent exact oracle judges results only.

This qualifies this bounded synthetic context-path fixture on this runner. It
is not target-deployment latency/capacity, wire-protocol overhead, provider
quality, or 24-hour resource/leak/SLO qualification. No provider API was called.
Those broader requirements remain #125 and the protected deployment workflows.
