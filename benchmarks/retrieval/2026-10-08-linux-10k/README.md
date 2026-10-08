# Retained-index qualification at 10,000 facts

GitHub-hosted Ubuntu 24.04 x86_64, Rust 1.97.1, default development build,
2026-10-08. Source head e47275e1d53ec926e733b01ba6abc4c38e9702b7; tested merge
23c49e8e13999340e939c98ccc642d52622cf36d against the cloning dependency.

[Run 37761904835](https://github.com/surya-koritala/AIagentOS/actions/runs/37761904835),
[successful job 113260105588](https://github.com/surya-koritala/AIagentOS/actions/runs/37761904835/job/113260105588),
artifact 11541994815 (`memory-qualification`). The exact checkout, toolchain,
invocation and successful upload are retained in [job.log](job.log). Raw results,
metadata and SHA-256 digests accompany this record.

| Corpus | Queries | Recall@10 | Top-one agreement | Exact p95 ms | ANN p95 ms | Combined build ms |
| --- | --- | --- | --- | --- | --- | --- |
| 10,000 | 100 | 1.0 | 1.0 | 17.851 | 15.228 | 2,336 |

The run passed the unchanged quality floors (recall >= 0.80, top-one >= 0.99)
and the new ANN-below-exact p95 gate. The same deterministic corpus was inserted
into both indexes and the same planted vectors queried. No provider API was
called. Reported Linux resident memory was 26,936 KiB after both indexes; this is
current RSS, not peak RSS.

Reproduce from the tested source:

```bash
cargo run -p os-benchmark --bin memory-qualification --locked > results.json
```

This measures retained index searches, excluding database warming, row parsing,
SQLite updates and the full context-manager query path. It is one fixture run on
one runner, not a deployment latency SLO. Production-path 100k facts, concurrent
mutation, sustained traffic and peak-memory qualification remain in #358/#125.
