# Public cloning fixture measurements

Measured on 2026-10-08, macOS arm64, Rust 1.97.1, optimized release build.
The fixture uses 256, 4,096 and 16,384 alternating user/assistant messages
with repository-task paragraphs. Each row creates eight children in a fresh
process. No model or provider API is called. These measurements establish
fixture behavior; they do not establish production agent quality or a general
performance guarantee.

Reproduce from this revision:

```bash
cargo run -p os-benchmark --bin clone-benchmark --release --locked > results.json
```

The COW path calls the public CloneAgent SDK operation. The eager baseline
uses public fresh-agent creation, materializes the saved history, and writes a
full independent copy through the same context store. Both allocate fresh
workspaces and normal agent enforcement. The timed interval includes child
admission and history publication; checkpoints and RSS sampling are outside it.

| Messages | Serialized history bytes | Strategy | First clone ms | Clones 2–8 median ms | Database growth after 8 bytes | RSS growth after 8 bytes |
| --- | --- | --- | --- | --- | --- | --- |
| 256 | 241,793 | cow | 6.749 | 1.661 | 475,136 | 2,703,360 |
| 256 | 241,793 | eager | 3.893 | 3.919 | 4,112,384 | 2,523,136 |
| 4,096 | 3,868,673 | cow | 79.927 | 5.209 | 7,614,464 | 14,467,072 |
| 4,096 | 3,868,673 | eager | 54.120 | 60.147 | 66,654,208 | 37,027,840 |
| 16,384 | 15,474,689 | cow | 313.507 | 16.125 | 30,474,240 | 112,787,456 |
| 16,384 | 15,474,689 | eager | 220.545 | 219.320 | 266,162,176 | 173,703,168 |

[Raw results](results.json) retain every branch's measured latency, storage and
RSS sample. Storage is allocated SQLite file size after a truncating WAL
checkpoint, including indexes, metadata and reusable free pages. RSS is current
process resident bytes sampled after each branch, relative to the pre-clone
sample. It includes allocator retention and SQLite memory; it is not a peak-RSS
measurement or a provider-memory estimate. The six workers use independent
processes, so the strategies do not inherit each other's allocator state.

First promotion copies and indexes a private saved tail inside SQLite and has
visible latency and memory cost. Later COW children reuse the immutable prefix.
Eager children each store and index a complete history. Provider execution still
materializes a branch's resolved history when it sends a request. No zero-copy
inference claim follows from these results.
