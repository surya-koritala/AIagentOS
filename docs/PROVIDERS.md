# LLM Provider Support Contract

This is the evidence-based provider matrix for
[issue #120](https://github.com/surya-koritala/AIagentOS/issues/120). “Fixture”
means the request/response behavior is verified against a local HTTP mock, not
the vendor's live service. No provider is production-qualified until the
secret-backed contract suite and operational requirements in #120 pass.

| Provider | Current evidence | Streaming | Tool calls | Usage | Vision / audio | Discovery / versioning | Current status |
|---|---|---|---|---|---|---|---|
| Azure OpenAI | Mock HTTP + SDK/integration E2E | Native SSE parser, including fragmented tool arguments; not live-qualified | Fixture-verified, including multiple calls | Prompt, completion, cached, total | Not represented by the standard message contract | Configured deployment/API version; no supported discovery contract | **Public-path E2E, experimental service support** |
| OpenAI | Mock HTTP contract | Non-streaming fallback | Fixture-verified, including multiple calls | Prompt, completion, cached, total | Not supported by this adapter contract | Availability probe only; model currently fixed by adapter | **Fixture-verified, experimental** |
| Anthropic | Mock HTTP contract | Non-streaming fallback | Fixture-verified | Input, output, cache-read | Not supported by this adapter contract | Fixed model/API header; no discovery contract | **Fixture-verified, experimental** |
| Groq | Mock HTTP contract | Non-streaming fallback | Fixture-verified | Prompt, completion, cached when reported | Not supported | Availability probe; configured model | **Fixture-verified, experimental** |
| DeepSeek | Mock HTTP contract | Non-streaming fallback | Fixture-verified | Prompt, completion, cache-hit when reported | Not supported | Availability probe; configured model | **Fixture-verified, experimental** |
| Gemini | Mock HTTP contract | Non-streaming fallback | Not implemented (`tools` are ignored) | Prompt, candidate, cached | Not supported by the standard message contract | Availability probe against v1beta; configured model | **Text fixture only, experimental** |
| vLLM | Mock OpenAI-compatible contract | Non-streaming fallback | Fixture-verified | Prompt, completion, cached when reported | Not supported | Availability probe; configured model | **Fixture-verified, experimental** |
| Hugging Face | Mock inference contract | Non-streaming fallback | Not implemented (`tools` are ignored) | Provider usage unavailable; conservative runtime fallback | Not supported | Configured model endpoint only | **Text fixture only, experimental** |
| Local Ollama | Unit/integration use of configured endpoint; no live nightly | Non-streaming fallback | Not implemented (`tools` are ignored; plaintext shim may recover model output) | Prompt/eval counts when reported | Not supported | Configured model; availability probe only | **Experimental local provider** |
| On-device Candle/GGUF | Feature-gated unit checks; real generation test is ignored unless a model is supplied | Non-streaming | No native tools; plaintext shim only | No provider usage record | Not supported | Only quantized Llama-family loader is implemented; generic prompt template | **Spike; unsupported for production** |

## Shared runtime behavior

- `AgentConnectorImpl` applies bounded retry/backoff and ordered failover. Its
  current error taxonomy is coarse (`unavailable`, `connection`, `protocol`,
  `stream`) and does not yet preserve vendor request IDs or distinguish auth,
  rate-limit, content-filter, and other permanent failures.
- The lifecycle coordinator cancels the awaiting provider future and prevents
  subsequent tool work. Prompt network/local-inference termination is not yet
  contract-tested independently for each adapter.
- Provider/model identity and detailed usage flow into durable usage records;
  when the provider omits usage, accounting records the documented conservative
  estimate. Pricing is operator-configured, not an invoice claim.
- Operator snapshots actively probe registered providers. There is no circuit
  breaker state, data-residency compatibility model, or automatic failover
  compatibility negotiation in that view yet.
- Parallel tool-call arrays can be parsed by the OpenAI-compatible/Azure paths,
  but the executor runs calls under its ordinary governed pipeline. Exactly-once
  side effects across failover are not promised.

## Qualification still required

Production promotion requires secret-backed nightly tests against each claimed
cloud API and supported Ollama/vLLM version, per-provider error/cancellation/rate
limit cases, model/API compatibility policy, real multimodal tests where
claimed, and on-device architecture/quantization/memory/CPU/GPU bounds. Memory
retrieval still needs persisted/rebuildable index versioning plus published
quality, latency, concurrency, deletion, and scale results.
