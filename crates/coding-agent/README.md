# Bounded Rust coding agent

`agent-code` is a single-node repository-maintenance application on the kernel.
It captures declared UTF-8 files through workspace handles, saves an actual
governed provider conversation, and clones that history for speculative fixes.
Each child receives an explicitly seeded private workspace. A proposal can edit
only declared source files whose preimage hashes match. Tests and dependency
manifests are immutable. The first candidate passing the permitted test target
is selected; failed branches and their durable data are erased.

The original repository is never patched. The final JSON report contains the
selected workspace agent, replacement contents and hashes, recorded tests,
configured cost, provider tokens and a bounded per-agent event trail. Progress
events are emitted as JSON on stderr. Review the result before applying it to
the current original files; their hashes may have changed since capture.

## Keyless fixture

Execution requires Linux, a rootless Docker daemon, and a preinstalled immutable
Rust image. The fixture needs no API key and installs no dependencies. It uses
the Rust image already pinned in the repository's container build:

```bash
docker pull rust:1.99.0-slim-bookworm@sha256:452176c0cefca88c0b3184ce85a4eb03e3d4fa05d2afb5366abcba853221019e
cargo run -p coding-agent --bin agent-code --locked -- fixture \
  --image rust:1.99.0-slim-bookworm@sha256:452176c0cefca88c0b3184ce85a4eb03e3d4fa05d2afb5366abcba853221019e \
  --data-dir /tmp/coding-job-1
```

The UTF-8 task has a real failing baseline, a plausible character-count fix that
still violates byte limits, and a correct boundary-aware fix. The permitted
command is fixed at bootstrap: `cargo test --offline --locked --test utf8_budget
--jobs 1`. It is invoked through `/tools/coding_tests` with an exact local
approval and the existing hardened rootless backend. There is no ambient
process-launch fallback on unsupported hosts.

## Explicit real-provider mode

Provide `OPENAI_API_KEY` in the operator environment, an explicitly supported
Chat Completions model, and its current configured input/output prices in USD
per 1,000 tokens. No model or price is silently selected. Repository contents
declared in the manifest will be sent to that provider. The provider wrapper
forwards no tool declarations and rejects native calls, textual tool calls,
invalid JSON and oversized replies before the executor can perform effects.

An example manifest:

```json
{
  "instruction": "Fix the UTF-8 byte-budget bug without changing the tests",
  "files": ["Cargo.toml", "Cargo.lock", "src/lib.rs", "tests/utf8_budget.rs"],
  "editable": ["src/lib.rs"],
  "test_target": "utf8_budget",
  "max_branches": 2,
  "max_steps": 1024,
  "deadline_seconds": 600,
  "max_usd": 1.0,
  "max_output_tokens": 2048
}
```

```bash
agent-code run --repo /absolute/repository --manifest task.json \
  --model "$CODING_MODEL" --input-price-per-1k "$CODING_INPUT_PRICE" \
  --output-price-per-1k "$CODING_OUTPUT_PRICE" \
  --image "$CODING_RUST_IMAGE" --data-dir /tmp/coding-real-job
```

Import uses a read-only agent and the kernel's retained directory capability;
original contents and permissions are preserved. Dotfiles, credentials,
traversal, test edits, dependency changes, deletion and remote writes are denied
by this application. Supporting those operations requires a separately reviewed
explicit policy; a model response cannot authorize them. Test code runs only in
the child container with no network, no host secrets and bounded process resources.

Money limits use configured prices and durable kernel accounting. Admission
also checks a conservative input-byte/envelope estimate plus the completion
allowance before provider I/O. The report calls this `configured_cost_usd`;
invoice reconciliation and real-model quality require retained live evidence.

## Recovery and cancellation

One data directory owns one job and one live kernel process. `--pause-after-branch`
stops at a durable boundary. Continue with:

```bash
agent-code resume --data-dir /tmp/coding-job-1
```

Completed proposals, patch replacements and test receipts are not replayed.
A patch interrupted after replacement is reconciled by its content hash. The
journal records caller-known child UUIDs and verifies creation lineage before
discarding any branch. The private selected workspace is retained for review.

A started provider request or test without a durable receipt is uncertain.
Resume stops for an explicit decision; `--retry-uncertain` permits a deliberate
retry. A process can finish between its effect and receipt publication, so this
window is at least once when retried. Test operation IDs are retained, tests
must be idempotent and confined, and no exact-once external-effect claim is made.
Ctrl-C cancels the exact active provider request or kills the owned test branch,
then retains a failure journal and attempts branch reclamation. Cleanup failures
are reported as `cleanup_required`, never as successful disposal.

The task's absolute deadline, branch count, productive request count, source,
proposal, journal and output bounds remain explicit across resumes. A retained
completed job can be inspected without starting another model request.

## Evidence and remaining acceptance

Public-wire contract tests use the real kernel for VFS, history branching,
quotas, cancellation, cleanup and restart. Their scripted test runner is labelled
`contract_fixture`; it does not claim a process test. The Linux CLI fixture job
uses real Rust compilation through the rootless backend. Both remain scripted
fixtures, separate from real-provider outcomes and production qualification.

Reviewed real-provider tasks, same-agent comparisons, invoice/cost evidence,
clean-host downloadable package verification and independent review remain
required by #394/#127. This source package does not establish those missing gates.

The operator-only `coding-comparison` harness compares this same fixture with
COW branching, sequential attempts in one governed agent, and a direct contained
baseline. All strategies use the same task, prompts, proposal decoder, source
preimages, protected test input and immutable test image. The direct baseline
omits the kernel's agent/gate/journal path but retains the rootless process
boundary; it is not a product execution mode. The harness reports single-run
timings and synthetic fixture token counters, not real-model performance or bills.

```bash
cargo run -p os-benchmark --bin coding-comparison --locked -- \
  --image "$CODING_RUST_IMAGE"
```

The fixture workflow also builds a canonical five-binary candidate archive and
downloads it onto a separate Ubuntu 22.04 runner without a source checkout.
The install check validates its SHA-256, exact binary versions and quick-start
help before running the isolated task and two fresh-process resumes. Candidate
artifacts are downloadable from that workflow's run. They remain development
candidates; this check does not replace signed-release publication or the
independent qualification gates.

For a reviewed live comparison, `coding-comparison` additionally requires
`--model`, `--max-usd`, `--input-price-per-1k` and `--output-price-per-1k`, with
the operator's `OPENAI_API_KEY` environment credential. The single configured
campaign ceiling is divided equally among all three strategies. The kernel
accounts governed charges; the direct contained baseline retains the same
proposal admission guard and explicitly records returned usage. Upstream
attempts are counted. An uncertain direct outcome preserves unknown total cost
instead of reporting it as zero. Live outcomes may differ and remain recorded;
the fixture's identical-output assertion is not applied to real-model quality.

The reviewed pilot is manual only and uses the protected `provider-qualification`
environment. Its review checkbox covers the fixed task and three strategies,
each with up to two attempts. Missing credentials are retained as `not_run` and
fail the live-task gate. No scheduled or PR workflow can initiate those paid runs.
