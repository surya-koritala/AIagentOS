# ADR 0001: JSON service protocol is the public ABI

- **Status:** Accepted
- **Date:** 2026-07-21
- **Decision owner:** Platform/runtime
- **Tracking:** [#116](https://github.com/surya-koritala/AIagentOS/issues/116)

## Context

The repository contained two syscall concepts: the newline-delimited JSON
service used by the SDK and clients, and a numbered `SyscallTable` used only by
unit tests. It also contained test-local `MountTable` and `ToolDescTable`
analogies that were not consulted by normal `ToolRegistry` / `ResourceBroker`
execution. Calling all of these a public VFS/ABI made the security boundary
ambiguous.

## Decision

The canonical public ABI is `syscall_server::Syscall` / `SyscallReply` over the
TCP, Unix, or TLS newline-JSON transport. The Rust SDK is a typed client for that
same ABI. In-process kernel methods are implementation interfaces, not a second
agent ABI.

The numbered `syscall_interface`, `MountTable`, and `ToolDescTable` are retained
only as experimental Linux-analogy prototypes. They are excluded from the v1
supported surface and must not be used by an entry point. An unregistered
numbered call deterministically returns `ENOSYS`, but registration does not make
that table a supported runtime boundary. Tool open/close/dup/inheritance,
mount/unmount, descriptor persistence, and a semantic filesystem are therefore
explicitly beyond the current v1 contract rather than falsely reported as
built.

Normal tool invocation has one route:

`Syscall::CallTool` or executor → validated `ToolRegistry` declaration →
namespace/capability/MAC/cgroup `SyscallGate` → sandboxed `ResourceBroker` →
provider → accounting/audit.

Direct tool-name lookup cannot bypass that route. Lifecycle, memory, storage,
checkpoint, and operator syscalls pass tenant/RBAC authorization in
`dispatch_scoped` before their single subsystem owner; sandbox/tool accounting
is not applicable when no external resource is invoked.

## Versioning and errors

`Hello` negotiates protocol versions 1 through 2. A connection that omits
`Hello` remains on v1. Version 1 receives the released legacy
`{"status":"error","message":...}` shape. Version 2 receives
`typed_error` with a stable `WireErrorCode`, human message, and retry hint. The
Rust SDK negotiates its compiled version on connect. Additive requests may be
introduced within a version; incompatible field/variant changes require a new
version and compatibility fixture.

Feature discovery is the negotiated version plus stable identifiers returned by
`Hello`. `DescribeProtocol` publishes machine-readable request/reply/MCP
schemas, compatibility behavior, and bounded transport controls. Protocol v2
also defines ordered message-stream event/terminal frames, bounded
backpressure, and exact request-id cancellation from a second authenticated
connection. Non-native backends emit one completed-response delta; Azure OpenAI
forwards native SSE deltas.

## Consequences

- Security and accounting reviews have one public call graph.
- The VFS analogy no longer creates a bypass obligation for production code.
- Code may keep experimental prototypes for research, but documentation and the
  capability registry must label them as disconnected/deferred.
- If descriptors are revived later, they require a new ADR and public E2E tests
  for canonical paths, tenant/namespace isolation, exhaustion, revocation,
  stop/restart behavior, and one-pass enforcement before promotion.
