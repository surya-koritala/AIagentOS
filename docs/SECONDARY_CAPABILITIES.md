# Secondary Capability Disposition

This inventory is the v1 disposition for supporting modules tracked by
[issue #128](https://github.com/surya-koritala/AIagentOS/issues/128). A public
Rust module is not automatically a supported remote/runtime capability. Only a
row with a live path may be advertised as part of the governed runtime.

Maturity terms come from [`capabilities.toml`](capabilities.toml). “Deferred”
means excluded from v1 discovery and support even if an in-process Rust helper
remains available for experiments.

| Module | Owner | Surface and live path | Security boundary | Platforms | v1 disposition / limitation |
|---|---|---|---|---|---|
| `editing` | kernel | Integrated through `edit_file`, `create_file`, and `delete_file` → `ResourceBroker` | Tool declaration → gate → mandatory sandbox → bounded filesystem provider | Linux, macOS, Windows | **Integrated.** Atomic transaction/rollback is tested; filesystem race and platform semantics still block production qualification. |
| `function_calling` | runtime | Internal fallback from `AgentExecutor`; no standalone remote operation | Parsed calls re-enter normal named-tool resolution and the gate | Linux, macOS, Windows | **Integrated internal utility.** It grants no authority; malformed prose yields no call. Model/prompt robustness is not production-qualified. |
| `planning` | runtime | In-process `PlanExecutor`; SDK has separately tested `patterns` over the public API | Tool steps use `AgentExecutor`; no public plan lifecycle or durable idempotency contract | Linux, macOS, Windows | **Experimental/deferred.** Do not advertise the kernel planning module as a v1 public service. |
| `learning` | runtime | Optional in-process `RuleStore` attached to an executor | No tenant authorization, provenance, poisoning review, or durable governed ownership | Linux, macOS, Windows | **Experimental/deferred.** Not enabled by the default kernel and not public over the wire. |
| `indexer` | developer tooling | Standalone `RepoMap::build` helper only | Direct host filesystem traversal; no agent sandbox/tenant boundary | Linux, macOS, Windows | **Deferred.** Not an agent-accessible v1 provider; ignore/secret/symlink/scale policy remains incomplete. |
| `shell` | developer tooling | Parser and a few in-memory built-ins; no process-execution runtime path | No governed command executor | Linux, macOS, Windows | **Deferred.** It is not a supported agent shell and must not be used to execute untrusted commands. |
| `github` | integrations | Standalone in-process HTTP client; not registered as a kernel provider/tool | Caller supplies a token directly; no kernel egress, credential, approval, or audit pipeline | Linux, macOS, Windows | **Deferred.** Not exposed in v1 API discovery. Use a separately governed tool integration. |
| `database` | integrations | Standalone SQLite query/schema helper; not registered as a kernel provider/tool | Direct path/SQL access outside the agent gate and sandbox | Linux, macOS, Windows | **Deferred.** Read-only SQLite checks exist, but this is not the kernel's durable-state API or a supported agent database tool. |
| `mcp` (client) | integrations | Standalone stdio child-process client; not started by `AgentKernelImpl` | Discovered metadata is untrusted; callers must provide local security declarations before registry installation | Linux, macOS, Windows | **Experimental/deferred.** The gate-enforced `mcp_server` is distinct and remains classified under `wire-protocol`. |
| `vision` | multimodal | In-process data-URL helper; no public vision syscall | Direct file read, with no sandbox, size, retention, or MIME-validation contract | Linux, macOS, Windows | **Deferred.** Byte helper is experimental; not a supported v1 device/provider path. |
| `voice` | multimodal | Direct in-process OpenAI/Azure HTTP helpers using environment secrets | Bypasses kernel egress, accounting, redaction, peripheral grant, and tenant policy | Linux, macOS, Windows | **Deferred.** Not registered or advertised by the runtime. |
| `modules` | extensions | Standalone `WasmModuleSystem`; no boot/public syscall integration | Fuel is set, but inputs are unsigned and the experimental host file import is not capability/sandbox mediated | Linux, macOS, Windows | **Deferred from v1.** Never load untrusted modules; signed inputs, import capabilities, memory/time bounds, and cleanup require qualification. |
| `models` | data model | Rust data structures used by internal/tests | No executable capability by itself | Linux, macOS, Windows | **Internal model layer.** Presence is not model-serving or Wasm evidence. |
| `prerequisites` | quality | Optional host-check helper; CI unit coverage only | Read-only host inspection | Linux, macOS, Windows | **Unit-tested utility.** Not a security boundary or production installer check. Unknown measurements fail the requested threshold rather than silently pass. |
| `linux_compat` | architecture tests | Standalone analogy/test models only | Disconnected from `AgentKernelImpl` enforcement | Linux, macOS, Windows | **Explicitly outside v1 runtime.** It is not evidence of Linux ABI, kernel, device, network-stack, or filesystem compatibility. |

## Rules enforced by this disposition

- Deferred modules are absent from the supported JSON syscall API and are not
  registered as default tools/providers.
- A future promotion needs an owner, public entry point, live call path,
  security declaration, adversarial tests, and an updated capability-registry
  maturity record.
- Direct in-process helpers are trusted-application APIs. They must not be
  presented as substitutes for tenant authorization, the syscall gate, the
  sandbox, accounting, audit, or lifecycle coordination.
- `editing` and `function_calling` are retained because their live execution
  paths re-enter the same governed tool pipeline; the other executable helpers
  remain deferred until that invariant is proven.
