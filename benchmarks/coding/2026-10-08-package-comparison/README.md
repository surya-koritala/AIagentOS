# Downloaded candidate and coding strategy fixture

[Exact GitHub run](https://github.com/surya-koritala/AIagentOS/actions/runs/37750182669)
completed the real rootless task, comparison and separate-runner install checks.
[Source metadata](source.json) identifies the source/merge commits, artifact IDs
and SHA-256 digests. No provider API call or real-model outcome is claimed.

The canonical five-binary archive was built on Ubuntu 22.04, uploaded, downloaded
on a separate Ubuntu 22.04 runner with no source checkout, and verified against
its SHA-256. All five installed binaries reported version 0.4.0-rc.1. The installed
agent-code then rejected the wrong patch, resumed in a fresh process, selected
its correct patch after actual isolated tests, and returned identical JSON on a
second resume. [Install report](install-report.json) retains exact binary hashes
and the nonproduction evidence classification. This is a downloadable development
candidate; signatures/publication and independent release qualification remain.

The same UTF-8 task and task/candidate prompt templates were compared using COW
branches, sequential attempts in a single governed agent, and a direct benchmark
path. All paths retained the same strict proposal decoder, immutable test input
and rootless test containment. The direct path omitted kernel agent/gate/journal
services; it is not a product mode. Conversation/runtime context differs by
strategy, as intended. Every path produced the same source SHA-256 and two actual
Rust test exits: 101 for the wrong candidate, then 0 for the correct candidate.

| Strategy | Single-run elapsed ms | Synthetic fixture tokens | Test exits |
| --- | --- | --- | --- |
| governed_cow | 17,526 | 2,131 | 101, 0 |
| governed_sequential | 5,113 | 2,394 | 101, 0 |
| contained_direct | 893 | 2,294 | 101, 0 |

[Raw comparison](comparison.json) includes process receipts. Timings run serially,
include compilation and the governed path's journal/VFS work, and are single
fixture samples, not a performance guarantee. Token counters are deterministic
fixture estimates, not invoices. Real-provider reviewed tasks, costs and comparable
live runs remain required by #394. No fixture result promotes production readiness.
