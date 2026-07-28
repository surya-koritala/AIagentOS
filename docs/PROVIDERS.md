# Provider and memory qualification

This document is the evidence contract for
[issue #120](https://github.com/surya-koritala/AIagentOS/issues/120). It
distinguishes code, deterministic fixtures, and live service evidence:

- **Fixture** means a checked-in test against a local HTTP mock.
- **Implemented** means the public runtime path carries the behavior.
- **Live passed** means a protected workflow artifact exercised a real service.
- **Not run** is not a pass.

The current capability-registry maturity remains **Public-API E2E**. The
engineering path is substantially qualified, but this commit has not produced
the protected live-service and provisioned-model artifacts required for
production promotion.

## Provider matrix

`Cancel` means the runtime stops awaiting and drops the hosted request future.
It does not claim that every vendor can prove server-side compute termination.
`Tools` describes native provider request/response fields; the governed
plaintext tool shim is separate.

| Provider | Text fixture | Native stream | Tools / parallel | Usage parsed | Cancel / timeout | Vision / audio | Model/API selection | Live evidence for this commit |
|---|---:|---:|---:|---:|---:|---:|---|---|
| Azure OpenAI | Yes | Yes, SSE | Yes / yes | Input, output, cached | Yes / yes | Not in the standard message contract | Deployment + configured API version | **Not run** |
| OpenAI | Yes | No; bounded non-streaming fallback | Yes / yes | Input, output, cached | Yes / yes | Not in the standard message contract | Configured model; OpenAI v1 family | **Not run** |
| Anthropic | Yes | No; bounded non-streaming fallback | Yes / yes | Input, output, cache-read | Yes / yes | Not in the standard message contract | Configured model; Messages API family | **Not run** |
| Groq | Yes | No; bounded non-streaming fallback | Yes / yes | Prompt, completion, cached when present | Yes / yes | Unsupported | Configured model; OpenAI-compatible v1 | **Not run** |
| DeepSeek | Yes | No; bounded non-streaming fallback | Yes / yes | Prompt, completion, cache-hit when present | Yes / yes | Unsupported | Configured model; OpenAI-compatible v1 | **Not run** |
| Gemini | Yes | No; bounded non-streaming fallback | No / no | Prompt, candidate, cached | Yes / yes | Not in the standard message contract | Configured model; GenerateContent v1beta family | **Not run** |
| Hugging Face inference | Yes | No; bounded non-streaming fallback | No / no | Provider usage unavailable; runtime estimate | Yes / yes | Unsupported | Configured model endpoint | **Not run** |
| vLLM | Yes | No; bounded non-streaming fallback | Yes / yes | Prompt, completion, cached when present | Yes / yes | Unsupported | Configured model; OpenAI-compatible v1 | **Not run** |
| Ollama | Yes | No; bounded non-streaming fallback | No / no | Prompt/eval counts when present | Yes / yes | Unsupported | Configured endpoint and model | **Not run** |
| Candle/GGUF | Failure/template fixtures; gated real-model test | No | No / no | Generated-token count; no input usage | Cooperative decode cancellation / wall timeout | Unsupported | CPU, quantized Llama-family GGUF; Simple, ChatML, or Llama 3 template | **Not run** |

No adapter currently advertises vision, audio, or a supported model-discovery
API. Those fields default to false, so callers cannot infer support from a
provider name.

## Shared runtime contract

### Errors and diagnostics

Provider HTTP failures map to typed authentication, authorization, rate-limit,
service-unavailable, invalid-request, content-filter, and timeout errors.
Rate-limit errors preserve a bounded `Retry-After`; common request-ID headers
are retained up to 256 bytes. Diagnostic bodies are read through an 8 KiB
ceiling, structured credential/prompt fields are redacted recursively, and
unstructured bodies fail closed to a generic message. Tests cover retry
classification, content-filter handling, oversized usage counters, and secret
redaction.

### Retry, circuit breaking, and failover

The production executor owns bounded transient retry rounds and backoff. Inside
one round, the resilient connector owns at most one fresh attempt per compatible
provider in the ordered failover chain. This avoids stacked retry loops while
still producing actual provider/model/attempt attribution. Each round durably
reserves its worst-case failover request/token count before provider I/O and
reconciles the exact attempts after success, failure, or cancellation. A later
retry round requires a new durable admission.

Failover is compatibility-checked before any backup receives a prompt:

- a request carrying native tools never routes to an adapter without tool
  support;
- local prompts do not route to a cloud provider unless an operator explicitly
  enables it;
- a required processing region rejects adapters that do not declare that
  region;
- cancellation and content-filter decisions stop the whole chain.

Regression tests prove cancellation starts no backup request, incompatible tool
failover is skipped, local-to-cloud routing is denied by default, one half-open
circuit probe is admitted, and successful backup attribution records the
actual provider/model and exact attempt count.

Provider HTTP requests themselves remain at-least-once across a transient
network failure: a retry can repeat a request when the service processed it but
the response was lost. Tool side effects are not executed until a successful
model response reaches the governed executor. Executor retries are disabled for
sessions that explicitly declare their own retry loop.

### Usage and pricing

The executor prices the provider and concrete model that actually served the
successful response, including failover. Provider-reported input, output, and
cached usage stays distinct from conservative admission estimates. Missing
provider usage is explicitly marked as estimated; the runtime does not invent a
vendor invoice.

## On-device boundary

The feature-gated Candle adapter is a CPU-only, in-process GGUF path. It:

- validates file metadata against a configurable 16 GiB default before parsing;
- supports a configurable 4,096-token default context ceiling and output clamp;
- requires a matching tokenizer and explicit Simple, ChatML, or Llama 3
  template;
- checks cancellation before tokenization, between 64-token prefill chunks, and
  on every decode token;
- serializes inference per loaded model and reports the configured stable model
  identifier;
- cleanly rejects missing, corrupt, and oversized models.

It does not support GPU execution, arbitrary GGUF architectures, native tools,
multimodal input, batching, or provider-style input-token usage. A real model is
therefore qualified only by the protected
`on-device-qualification.yml` workflow on a repository-owned runner. Model
weights are never fetched by pull-request CI.

The workflow accepts only an existing `vX.Y.Z` or `vX.Y.Z-rc.N` tag that points
to its exact clean checkout. Protected environment variables supply absolute,
non-symlink model and tokenizer paths plus a stable hardware ID; paths, prompts,
generated text, and weights never enter dispatch history or the artifact. The
bounded report binds the source commit and release candidate to SHA-256 model,
tokenizer, and configuration identities. It records load, bounded generation,
peak RSS, and cancellation latency against explicit targets.

Cancellation qualification is stronger than observing an API error: the
adapter signals its blocking inference worker and waits for that worker to
finish before returning cancellation or timeout. Failure to drain within the
bounded cleanup interval fails closed. The retained report still sets
`production_claim_allowed` to false. It becomes usable on-device proof only
after the exact artifact and runner provenance are independently reviewed, and
whole-product promotion still requires every other release gate. This
repository has implemented and regression-tested the gate, but has not yet
published an independently approved real-model artifact.

## Durable retrieval memory

Facts persist the embedding model ID, version, dimension, content hash, and
vector. Query validates all five fields plus finite numeric values. A stale,
legacy, malformed, wrong-dimension, or content-mismatched vector is
deterministically rebuilt and persisted before ranking.

The public wire protocol and Rust SDK support store, semantic query, update,
delete, and full-agent reindex. Mutations are agent-owned; tests cover
cross-agent denial, 160 concurrent writes without loss, large top-k queries,
corrupt/stale rebuilds, and tenant purge that removes runtime/memory artifacts
without damaging another tenant or deleting durable agent identity history.

The default offline embedding is `blended-feature-hash` version 2 at 256
dimensions. It is deterministic and dependency-free; it is not a neural
embedding model and should not be described as equivalent to one.

### Exact-vs-ANN gate

`memory-qualification` builds the same corpus into exact cosine and deterministic
LSH indexes, runs planted queries, emits JSON evidence, and fails when:

- mean recall@10 is below `0.80`; or
- exact/ANN top-1 agreement is below `0.99`.

Run it with:

```bash
cargo run -p os-benchmark --bin memory-qualification --locked
```

The default corpus is 10,000 items and 100 queries. A local development-profile
run on 2026-07-25 produced recall@10 `1.0` and top-1 agreement `1.0`. Its ANN
p95 (`44.260 ms`) was slower than exact search (`25.052 ms`) on that host, so
this is quality evidence—not a performance SLO. The CI artifact records each
runner's build/query timing and Linux resident memory. Cached/persistent ANN
construction and sustained 100k+ latency/soak goals remain part of
[issue #125](https://github.com/surya-koritala/AIagentOS/issues/125).

## Protected evidence workflows

- `live-provider-qualification.yml` runs fixtures and then one bounded contract
  for each cloud/local service every night or on manual dispatch. Missing
  credentials/endpoints emit a `not_run` artifact.
- `on-device-qualification.yml` binds a provisioned real GGUF model and
  tokenizer to one exact tagged release candidate, verifies bounded load,
  generation, cancellation drain, and peak RSS on a repository-owned CPU
  runner, and retains only non-sensitive digest-bound evidence for 90 days.
- Pull-request CI runs adapter fixtures, memory correctness/concurrency tests,
  the exact-vs-ANN quality gate, Clippy, and the full workspace regressions.

Production promotion requires reviewed `passed` artifacts for every provider
and on-device configuration the release claims to support. Providers without
such evidence remain experimental even when their fixtures pass.
