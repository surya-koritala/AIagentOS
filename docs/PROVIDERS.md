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
| Azure OpenAI | Yes | Yes, SSE | Yes / yes | Input, output, cached | Yes / yes | Inline PNG/JPEG with an explicit deployment bound; no audio | Deployment + configured API version | **Not run** |
| OpenAI | Yes | Yes, SSE | Yes / yes | Input, output, cached | Yes / yes | Inline PNG/JPEG with an explicit model bound; no audio | Configured model; OpenAI v1 family | **Not run** |
| Anthropic | Yes | Yes, SSE | Yes / yes | Input, output, cache-read | Yes / yes | Inline PNG/JPEG with an explicit model bound; no audio | Configured model; Messages API family | **Not run** |
| Groq | Yes | Yes, SSE | Yes / yes | Prompt, completion, cached when present | Yes / yes | Unsupported | Configured model; OpenAI-compatible v1 | **Not run** |
| DeepSeek | Yes | Yes, SSE | Yes / yes | Prompt, completion, cache-hit when present | Yes / yes | Unsupported | Configured model; OpenAI-compatible v1 | **Not run** |
| Gemini | Yes | Yes, SSE | Yes / yes | Prompt, candidate + thought, cached | Yes / yes | Inline PNG/JPEG with an explicit model bound; no audio | Configured model; GenerateContent v1beta family | **Not run** |
| Hugging Face text generation (default) | Yes | No; bounded non-streaming fallback | No / no; explicit governed shim or reject | Estimated input/output bytes; not provider-reported | Yes / yes | Unsupported | Configured legacy model endpoint | **Not run** |
| Hugging Face chat router (opt-in) | Yes | Yes, SSE | Yes / yes; selected model/provider must support functions | Prompt, completion, cached when supplied | Yes / yes | Unsupported | Configured router endpoint and model:provider | **Not run** |
| vLLM | Yes | Yes, SSE | Yes / yes | Prompt, completion, cached when present | Yes / yes | Unsupported | Configured model; OpenAI-compatible v1 | **Not run** |
| Ollama | Yes | Yes, NDJSON | Yes / yes | Prompt/eval counts when present | Yes / yes | Unsupported | Configured endpoint and model | **Not run** |
| Candle/GGUF | Controlled decoder/drain fixtures; gated real-model test | Yes, token decode | No / no | Generated-token count; no input usage | Cooperative decode cancellation / wall timeout | Unsupported | CPU, quantized Llama-family GGUF; Simple, ChatML, or Llama 3 template | **Not run** |

Vision defaults to false. The four image compilers advertise it only with a
valid accounting profile matching the configured model or Azure deployment.
All other image modes and audio remain unsupported. Model discovery is
supported only by the adapters listed below; callers must inspect configured
capabilities.

## Bounded image input

`StandardMessage.content` retains its legacy JSON string form. Ordered user
parts accept text and inline `image/png` or `image/jpeg`, with explicit MIME
and standard base64 data. The reserved audio tag is rejected. Parts in system,
assistant and tool history are rejected; native provider replay metadata stays
separate. Images are limited to 1 MiB decoded bytes and 2048 pixels per dimension,
four images and 32 parts per message, and 6 MiB serialized multipart content.
An image-bearing request additionally has at most 16 images, 4 MiB decoded
image bytes and 8 MiB of serialized standardized history.
URLs, file paths, animation, image output and audio input are unavailable.
PNG validation checks chunk CRC, legal IHDR fields, palette constraints and
critical ordering. JPEG checks bounded 8-bit Huffman DCT containers, frame/scan
headers, table selectors and entropy framing. These checks do not decode or
qualify raster/model quality.

An operator must set an `image_input_profiles` entry for the exact selected
provider and model (Azure uses the deployment identity), with a nonzero bounded
`max_tokens_per_image`. This is an operator-declared input-token bound. It is
not a measured price or a provider-verified estimate. Select it from current
model-specific accounting documentation for the allowed dimensions and request
detail; there is no universal image-token cost. Unknown or mismatched profiles
fail before provider I/O. The executor adds the image bound to text/structure
admission, includes compatible failover bounds, and prevents reported usage
from refunding below that reservation floor. Unsupported failover candidates
are skipped without dropping content.

The serializers follow the primary [OpenAI chat image guide](https://developers.openai.com/api/docs/guides/images-vision),
[Azure vision guide](https://learn.microsoft.com/en-us/azure/foundry/openai/how-to/gpt-with-vision?view=foundry-classic),
[Anthropic image source contract](https://platform.claude.com/docs/en/build-with-claude/vision),
and [Gemini GenerateContent API](https://ai.google.dev/api/generate-content).
These endpoint shapes do not prove a configured model can interpret images.

Wire v2 adds `send_message_content` and `send_message_content_stream`; v1
strings and text convenience APIs remain unchanged. Rust SDK content methods,
desktop backend/TUI types and `agentctl message-content AGENT_ID INPUT.json`
or `agentctl stream-content REQUEST_ID AGENT_ID INPUT.json` use the same
authorization, admission, ownership fences, request identity and cancellation
paths. A dash reads bounded JSON from stdin. There is no desktop upload UI.
The CLI's stream frames retain the ordinary event/completion envelope.

Schema/min-reader 13 is established before conversation, snapshot, spill,
checkpoint or clone writes. Complete parts remain in private durable JSON and
survive replay; logs, debug, search indexes and checkpoint listings use redacted
projections. Image-bearing requests retain typed failures and retry hints while
discarding vendor diagnostic text and request IDs that could echo input bytes.
Keyless tests are hosted in `image-input.yml`. Live provider,
hardware and independent qualification remain open in #360/#120.

A green nightly run with an empty provider set retains a dated `not_run` plan
and skips live contracts. It verifies fixture contracts only; it is not live
provider evidence and never permits a production claim. Invalid provider sets
fail, and every explicitly selected live provider must still report `passed`.

## Native streaming conformance

Azure/OpenAI/Groq/DeepSeek/vLLM and Hugging Face chat mode use one bounded byte-safe SSE reader with
ordered native call assembly, usage, cancellation/backpressure and partial-output
retry suppression. Keyless conformance covers nine providers and both Hugging Face modes and remains distinct from live
provider qualification. See issue #351 and the hosted streaming fixtures.

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

### Explicit model discovery

`agentctl [SERVER OPTIONS] providers` displays configured providers and their
capability flags without enumerating a provider account. A trusted system
operator can explicitly request one catalog with
`agentctl [SERVER OPTIONS] models PROVIDER_ID`. The SDK method
`KernelClient::list_provider_models` uses the v2 `list_provider_models` syscall
and returns `{ "provider_id": "...", "models": ["..."] }`. Tenant API keys,
including tenant Admin keys, are denied before provider I/O because configured
credentials can expose account-specific model identifiers.

| Adapter | Configured endpoint suffix | Identifier and pagination contract |
|---|---|---|
| OpenAI | `/models` | [`data[].id`](https://developers.openai.com/api/reference/resources/models/methods/list) |
| Groq | `/models` | [`data[].id`](https://console.groq.com/docs/api-reference#models) |
| DeepSeek | `/models` | [`data[].id`](https://api-docs.deepseek.com/api/list-models/) |
| vLLM | `/models` | [`data[].id` from its OpenAI server](https://github.com/vllm-project/vllm/blob/main/vllm/entrypoints/openai/models/api_router.py) |
| Anthropic | `/models` | [`data[].id`, `has_more` and `after_id`](https://platform.claude.com/docs/en/api/models/list) |
| Gemini | `/v1beta/models` | [`models[].name`, `nextPageToken` and `pageToken`](https://ai.google.dev/api/models); remove the `models/` prefix for configured generation IDs |
| Ollama | `/api/tags` | [`models[].model`, with `name` compatibility](https://docs.ollama.com/api/tags) |

Azure deployment discovery, both Hugging Face endpoint modes, and
Candle have no implemented catalog endpoint. They retain
`model_discovery = false` and return `ConnectorError::UnsupportedFeature`;
the wire/SDK category is `unsupported`, not an empty success. A valid empty
provider catalog is a successful empty array. Listing does not prove a model
supports chat, tools, or a particular generation method, and does not load,
download, execute, select, or change a model.

Catalogs preserve identifier spelling, sort and deduplicate it, and include no
owners, account fields, endpoints, credentials, display metadata, or local
paths. IDs must be 1–256 ASCII bytes with a leading alphanumeric character and
only alphanumerics, `_`, `-`, `.`, `:`, `/`; URL schemes and empty/dot path
segments are rejected. The raw catalog is capped at 1024 entries, 1 MiB across
all response bodies, 16 pages, and a ten-second total deadline. Pagination is
same-endpoint only, cursors are bounded and repeated cursors fail. Exceeding a
bound or encountering malformed data fails the whole lookup, without a partial
or silently truncated catalog.

Built-in HTTP listing disables redirects, carries credentials only in headers,
and never echoes provider bodies, request IDs, URLs or cursor values in errors.
Diagnostics stay below the existing 8 KiB error ceiling. The connector applies
the public ID/count bounds again to third-party adapters; the wire maps even
their error prose to fixed typed messages. In-process callers can use
`list_models_controlled` with a cancellation token; cancellation drops the
transport future. Wire calls use the same total deadline and existing transport
limits. Listing has no inference retry/failover; the SDK retains its ordinary
bounded reconnect behavior for read operations. This does not prove vendor
server-side compute cancellation. Keyless catalog, capability, pagination,
authorization, SDK and actual CLI fixtures run in GitHub CI. Live listing
qualification remains **Not run**.

### Native streaming conformance

Azure OpenAI, OpenAI, Groq, DeepSeek, vLLM and Hugging Face chat mode use one SSE reader. Anthropic Messages and Gemini streamGenerateContent share its byte framing, wire ceilings, cancellation and bounded event sink through their typed decoders. It retains
UTF-8 across HTTP chunks, accepts SSE line endings and comments, reassembles
parallel function arguments by index, and preserves final prompt, completion
and cached usage (including DeepSeek cache-hit fields). The entire response,
including comments and incomplete events, is capped at 8 MiB. Tool-call count
and identities are bounded; malformed arguments, sparse indexes and duplicate
identities fail before any tool execution. A truncated stream is an error.

The reusable fixture checks all nine network adapters and both Hugging Face modes
independently of their capability flags: nine native modes publish multiple text
deltas; completion-only modes publish one completed delta. Concatenated text must equal the terminal
response. A paused chunked HTTP fixture proves delivery before completion and
split UTF-8 handling. Cancellation and deadlines cover channel backpressure;
visible-output failures suppress connector retry and failover. These tests run
in `provider-streaming.yml` and the platform/workspace CI suites without keys,
model downloads or live requests. They qualify the protocol implementation;
real provider evidence remains **Not run**.

### Anthropic and Gemini typed streams

Anthropic accumulates text, JSON tool fragments, cumulative output usage and
signed thinking blocks. Native calls become available only after the message
stops and all blocks close; fragments never execute. Its history compiler pairs
parallel tool results and replays complete signed blocks through later turns.

Gemini uses `streamGenerateContent?alt=sse` with `x-goog-api-key` in the header.
It preserves every streamed Content entry and exact part ordering, including a
late signature on empty text. Thought text is retained privately rather than
published as a text delta. The opaque replay payload retains chunk-part counts
and is capped at 256 KiB, 2048 chunks and 4096 parts; each chunk is at most 64
parts and terminal native calls are limited to 64. Schema/min-reader 13 prevents
older adapters from flattening even short signed histories. Usage includes
thought tokens; a blocking final finish reason returns a typed filter error.

Both protocols share the 8 MiB wire ceiling and enforce a 1 MiB event ceiling.
Clean EOF after complete text events can return that text with no finish reason.
EOF within a wire event, unfinished tool calls, transport failures, malformed
JSON and oversized replay state fail. Visible failures retain retry/failover
suppression; cancellation and deadlines cover event-sink backpressure.

These rules follow the [Anthropic streaming contract](https://platform.claude.com/docs/en/build-with-claude/streaming)
and [Gemini GenerateContent signature contract](https://ai.google.dev/gemini-api/docs/generate-content/thought-signatures).
The [official SDK history accumulator](https://github.com/googleapis/python-genai/blob/main/google/genai/chats.py)
retains streamed model Content entries separately. Keyless CI fixtures qualify
this implementation; protected real-service qualification remains **Not run**.

### Retry, circuit breaking, and failover

The production executor owns bounded transient retry rounds and backoff. Inside
one round, the resilient connector owns at most one fresh attempt per compatible
provider in the ordered failover chain. This avoids stacked retry loops while
still producing actual provider/model/attempt attribution. Each round durably
reserves its worst-case failover request/token count before provider I/O and
reconciles the exact attempts after success, failure, or cancellation. A later
retry round requires a new durable admission.

A tool-incompatible primary uses an explicit policy. The compatibility default
is `degraded-shim`: native definitions are omitted, the same declarations are
rendered as a plaintext tool protocol, and every recovered call still passes the
normal gate. The connector warns and records provider/model/dropped-definition
count once per logical session in the agent's bounded activity log. Turn usage
reports `degraded_requests`, `dropped_native_tool_definitions` and
`shim_recovered_tool_calls`; zero fields are omitted for older wire/checkpoint
compatibility. Audit retention remains the normal bounded observability policy.

An operator can require native support at boot:

```toml
[provider_routing.huggingface]
tool_incompatible_primary = "reject"
```

`reject` returns `ToolIncompatiblePrimary` before provider request or failover I/O;
it is permanent on the wire. Empty tool sets are accepted, and native primaries
produce no degradation event. Provider views expose this routing policy. The
rendered protocol's serialized bytes and native declarations are alternative
representations. Context/token admission reserves their maximum with the prompt,
so failover is covered without charging both representations. This is fixture-tested behavior;
real model quality remains not run.

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

## Hugging Face endpoint selection

Checked **2026-10-08**: the official [chat-completion API](https://huggingface.co/docs/inference-providers/en/tasks/chat-completion)
documents router tools, token usage and SSE. The [function-calling guide](https://huggingface.co/docs/inference-providers/en/guides/function-calling)
requires a compatible provider/model pair; streaming availability also varies.
The [supported-model table](https://huggingface.co/inference/models) lists
`Qwen/Qwen3.5-9B` with tool support on DeepInfra, Together and OVHcloud. The
adapter's older default, `meta-llama/Llama-3.1-8B-Instruct`, is listed with tools
on DeepInfra and without tools on Novita/Nscale. Provider mappings alone do not
establish function support. These are upstream declarations, not a live AIagentOS test.

Select chat mode explicitly and pin the provider:

```toml
llm_provider = "huggingface"
default_model = "Qwen/Qwen3.5-9B:deepinfra"
huggingface_api_mode = "chat-completions"
# Optional compatible gateway override; default is https://router.huggingface.co/v1.
# huggingface_base_url = "https://gateway.example/v1"
```

Credentials retain the existing configured key or `HUGGINGFACE_API_KEY` /
`HF_API_KEY` sources. Chat mode uses shared OpenAI-shaped request/response code
and the bounded SSE reader; it preserves native call IDs and tool-result turns.
Malformed calls fail the entire response before execution. Unsupported
model/provider requests surface typed upstream errors; there is no automatic
switch to the completion endpoint or hidden tool removal.

Omitting the mode keeps `text-generation`. Direct native tool requests now
return `ToolIncompatiblePrimary` before HTTP. The normal kernel path retains
the default governed plaintext shim, a once-per-session degradation audit and
turn counters. Legacy usage contains conservative UTF-8 byte estimates with
`provider_reported = false`; it is not a tokenizer measurement or an invoice.
Chat requests without returned usage are likewise marked unreported. Both
modes have deterministic CI fixtures; live provider quality remains **not run**.

## Gemini native history

The GenerateContent adapter sends JSON-schema function declarations and parses
all native function calls in response order. Tool results are paired by call ID
and returned as functionResponse parts in original call order in one user turn
for parallel calls, even when results arrive in reverse order.
Upstream IDs are retained when present; missing IDs receive a durable unique
synthetic ID. Synthetic IDs are never inserted into signed native response parts.
System instructions use the separate systemInstruction field.

Bounded provider/model-specific assistant metadata preserves native parts and
thought signatures exactly through saved conversations, checkpoints and cloning.
Thought-marked text is excluded from visible answer content. Native text is
returned as text even when a code example resembles the plaintext tool shim. Malformed parts,
non-object arguments, duplicate IDs, changed signed content, orphan results and
incompatible provider/model history fail closed. Native history cannot fail over
to a provider or model that cannot replay it. Signed history and its following
messages stay pinned under context pressure; insufficient context rejects the
request before provider I/O. Usage includes thought tokens in output accounting.

Responses are limited to 1 MiB, native messages to 64 parts, and opaque replay
payloads to 256 KiB. Replay state is not a tool permission. Tool calls still pass
through the declaration, namespace, capability, MAC, approval and cgroup gate.
The wiremock and kernel restart tests are fixtures; live Gemini evidence remains
**not run**. Schema 11 prevents an older reader from discarding replay state.
Custom Rust adapters constructing StandardMessage or LlmResponse literals must
initialize the new optional provider_metadata field, normally to None.

The contracts follow Google's [GenerateContent API reference](https://ai.google.dev/api/generate-content)
and [thinking state documentation](https://ai.google.dev/gemini-api/docs/thinking).

### Local-provider streaming

Ollama requests native NDJSON and emits each content fragment as its record
arrives. UTF-8 survives HTTP chunk boundaries; terminal `done` supplies prompt,
output and cached usage. The complete wire is capped at 8 MiB and each record at
1 MiB. Native function calls are bounded, ordered by their indexes, validated as
JSON objects and returned only with a terminal record. Unknown or truncated
records fail; visible failures cannot restart or fail over. Thinking fields are
not displayed; this change preserves the existing text/tool history contract.

A model without a tool template retains its one retry without tool definitions
and the existing governed plaintext recovery. Both sends are admitted through
the current durable request/token budget, and actual attempts are reconciled on
success, failure or cancellation. No extra tool execution path is introduced.

Candle publishes stateful tokenizer suffixes during actual sampled-token
decode, through a bounded four-item worker bridge. It buffers incomplete UTF-8,
flushes only the pending tokenizer tail, and refuses a terminal response if its
published prefix differs from the original batch decode. Output is capped at
64 KiB; a tokenizer that revises its published prefix fails closed. Cancellation,
deadlines and dropped futures signal the worker; cancellation/deadline close
the bridge before awaiting the existing five-second cleanup bound. Model cache
state resets between independent turns, and lock acquisition is cancellable.

CI uses a controlled token source with the same detokenizer/worker bridge and
shared capability conformance. This proves incremental transport and cleanup;
it is not real GGUF inference or model-quality evidence. The protected
on-device report is now schema 2 and must prove actual multi-delta decode,
byte-identical stream/batch output for the same prompt/seed, and cancellation
after a decoded delta. Older reports cannot authorize promotion. The gated
real-model test and protected artifact remain **Not run** on this source.

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
delete, and full-agent reindex. The context manager retains per-agent fact rows
and search indexes instead of rebuilding them for every query. Deterministic
planes are shared; vectors and buckets remain private. Mutations are agent-owned;
tests cover
cross-agent denial, 160 concurrent writes without loss, large top-k queries,
corrupt/stale rebuilds, and tenant purge that removes runtime/memory artifacts
without damaging another tenant or deleting durable agent identity history.

The default offline embedding is `blended-feature-hash` version 2 at 256
dimensions. It is deterministic and dependency-free; it is not a neural
embedding model and should not be described as equivalent to one. An
[opt-in HTTP embedding backend](HTTP_EMBEDDINGS.md) supports configured
OpenAI-compatible/Ollama services with typed failures, model/dimension repair and
same-corpus comparison. Actual neural-model quality remains not run.

### Exact-vs-ANN gate

`memory-qualification` builds the same corpus into exact cosine and deterministic
LSH indexes, runs planted queries, emits JSON evidence, and fails when:

- mean recall@10 is below `0.80`; or
- exact/ANN top-1 agreement is below `0.99`; or
- ANN query p95 is not below exact p95 at 10,000 or more items.

Run it with:

```bash
cargo run -p os-benchmark --bin memory-qualification --locked
```

The default corpus is 10,000 items and 100 queries. A local development-profile
run on 2026-07-25 produced recall@10 `1.0` and top-1 agreement `1.0`. Its ANN
p95 (`44.260 ms`) was slower than exact search (`25.052 ms`) on that host, so
this is quality evidence—not a performance SLO. The CI artifact records each
runner's build/query timing and Linux resident memory. The retained cache,
binary-embedding migration, deterministic ordering and revised performance gate
are described in [memory retrieval](MEMORY_RETRIEVAL.md). The
[2026-10-08 Linux fixture](../benchmarks/retrieval/2026-10-08-linux-10k/README.md)
passed with recall/top-one agreement 1.0 and ANN p95 15.228 ms versus exact
17.851 ms; it measures index searches and excludes database warming.
The [2026-10-08 100k context fixture](../benchmarks/retrieval/2026-10-08-linux-100k/README.md)
passes the actual API under 60 seconds of concurrent updates and queries: cold
16.035 seconds, warm p95 135.619 ms, concurrent-read p95 839.088 ms and process
peak RSS 398,667,776 bytes. Recall/top-one are 1.0 before and after mutation;
189 reads/189 writes preserve all facts and the foreign sentinel. These are
synthetic runner-specific results. Target deployment and 24-hour soak goals remain
[issue #125](https://github.com/surya-koritala/AIagentOS/issues/125).

## Protected evidence workflows

- `live-provider-qualification.yml` runs fixtures every night and executes
  bounded live contracts only for the comma-separated provider IDs in the
  repository variable `AGENTOS_LIVE_PROVIDER_SET` (or the explicit manual
  dispatch input). Use `all` only when every backend is deliberately
  provisioned. The checked-in planner rejects unknown/duplicate IDs, cancels a
  stale approval-bound run when newer source is scheduled, and retains an
  exact-commit readiness artifact.
- An empty provider set fails with explicit `not_run` evidence before entering
  the protected environment. Once a provider is selected, its job must report
  `passed`; a missing credential, endpoint, deployment, or model is retained as
  `not_run` but fails the workflow. Consequently neither an empty setup nor an
  approved-but-incomplete setup can create a green live-evidence claim.
- Keep credentials/endpoints in the `provider-qualification` environment and
  model/API selections in that environment's variables. The dynamic matrix
  contains only selected providers, so unselected jobs never request
  environment approval and never receive a credential expression.
- `on-device-qualification.yml` binds a provisioned real GGUF model and
  tokenizer to one exact tagged release candidate, verifies bounded load,
  generation, cancellation drain, and peak RSS on a repository-owned CPU
  runner, and retains only non-sensitive digest-bound evidence for 90 days.
- Pull-request CI runs adapter fixtures, memory correctness/concurrency tests,
  the exact-vs-ANN quality gate, Clippy, and the full workspace regressions.

Production promotion requires reviewed `passed` artifacts for every provider
and on-device configuration the release claims to support. Providers without
such evidence remain experimental even when their fixtures pass.
