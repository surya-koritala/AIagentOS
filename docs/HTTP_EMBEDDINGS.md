# Optional HTTP embedding services

The default remains `blended-feature-hash` version 2 at 256 dimensions. Omitting
`embeddings` starts no HTTP worker and makes no embedding request. Its algorithm
and serialized vectors are unchanged.

An operator may explicitly configure an OpenAI-compatible or Ollama embedding
service. Configuration uses a full endpoint, model name, expected dimensions and
version; it contains an optional credential environment reference, never a key.
For example, a local service configuration is:

```toml
[embeddings]
protocol = "ollama"
endpoint = "http://localhost:11434/api/embed"
model = "configured-embedding-model"
dimensions = 768
version = 1
request_dimensions = false
timeout_seconds = 15
batch_size = 32
```

`openai-compatible` selects the `/embeddings` response format at the explicitly
configured URL. It requests float encoding and reconstructs original input order
from unique response indexes. Ollama selects `/api/embed` and requests
`truncate = false`. Set `request_dimensions = true` only when the chosen service
supports dimension control. Every returned vector must match `dimensions`, be
finite, and have a valid nonzero norm. There is no clipping, zero-vector error
substitute, alternate-model fallback or retry.

The transports follow the [OpenAI embeddings reference](https://developers.openai.com/api/reference/resources/embeddings/methods/create)
and [Ollama embed reference](https://docs.ollama.com/api/embed). They require HTTPS
except explicit loopback HTTP, reject URL credentials/query/fragments, disable
redirects and ambient proxies, and bound input, batch and response sizes. A
bounded worker owns the HTTP client and its internal runtime. Queue wait counts
against the request deadline; capacity exhaustion and timeouts are typed errors.
Diagnostics omit input text, credentials, endpoint URLs and upstream bodies.

`api_key_env`, when present, identifies an existing operator-supplied service
credential. Missing/invalid references fail startup before opening the database.
No account or key is created by this feature. Enabling a paid endpoint can incur
embedding-service charges; the comparison reports unknown billing cost and does
not equate request counts with an invoice. Existing LLM token/cost accounting is
not an embedding-service billing record.

## Persistence, failure and dimension changes

Normal kernel boot selects this backend from `Config.embeddings`. Stored facts
retain endpoint/model-specific identity, explicit version, dimension and content
hash. A model, expected response identity or endpoint change triggers repair.
Dimension/version changes trigger repair or the existing `MemoryReindex` syscall.
An operator must change `version` when a service changes model weights under the
same name. `expected_response_model` explicitly permits a known provider alias;
an unexpected response model is rejected.

Store/query failures return `ContextError::Embedding` with a typed cause. A failed
call never saves a replacement vector under the declared model. Reindex batches
commit atomically, including partial upstream failure and byte-limit refusal.
Larger dimensions cannot bypass agent, tenant or global logical storage caps.
Cold async repair performs network batches outside the SQLite lock, then verifies
the captured fact revision before committing. Concurrent mutation returns a retry
error. Cancellation can abandon network work but cannot publish a background
repair. Warm retained indexes skip the repair scan. Synchronous update/reindex
callers may wait for the bounded service operation; remote deployment latency
must be measured independently.

The `Embedder` and `MemoryManager` Rust methods now return `Result` so callers
must propagate embedding failures. Custom implementations return `Ok(vector)`;
`embed_batch` has an ordered default implementation. The offline convenience
`memory_manager::embed` still returns its unchanged `Vec<f32>`. The wire/SDK fact
representation is unchanged.

## Comparison and evidence

The ordinary 10k index and 100k context fixtures stay offline. To compare a
configured service with the offline embedder, provide a JSON file with the same
embedding fields and explicitly select:

```bash
MEMORY_BENCH_EMBEDDING_CONFIG=/absolute/path/embedding-service.json \
  cargo run -p os-benchmark --bin memory-qualification --locked
```

This mode sends a bounded fixed corpus of 100 labelled documents and 20
paraphrase queries to the configured service. Both embedders rank the same
corpus against independent topic labels; JSON records semantic recall@10,
top-one relevance, per-query document IDs, model/version/dimensions, elapsed time
and actual HTTP attempts. A service failure yields incomplete/null HTTP results
and a failed command. Successful transport never implies an improvement, and the
report forbids production claims.

Local mock regressions cover both protocols, dimensions/index validation,
authentication/rate-limit/upstream errors, timeout/redirect refusal, startup,
byte limits, model/dimension migration, partial-batch rollback, mutation races,
cancellation, tenant isolation/purge and comparison accounting. Mock vectors are
protocol evidence. No live OpenAI/Ollama model-quality result is claimed.
