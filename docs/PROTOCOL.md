# Public wire and client contract

AI Agent OS has one canonical remote ABI:
`kernel::syscall_server::Syscall` / `SyscallReply` as UTF-8,
newline-delimited JSON. The Rust SDK, CLI, TUI backend, and raw clients must use
that boundary. MCP tool calls enter the same authorization, tool-registry,
syscall-gate, sandbox, accounting, and audit path.

The numbered in-process syscall prototype is not part of this contract.

## Version and feature negotiation

The wire protocol is versioned independently from the crate. Protocol v2 serves
the compatibility window v1 through v2:

```json
{"op":"hello","protocol_version":2}
```

The `hello` reply reports:

- `protocol_version`: newest supported version;
- `min_protocol_version`: oldest supported version;
- `server_version`: informational crate version;
- `features`: stable fine-grained feature identifiers.

The Rust SDK performs this handshake during `KernelClient::connect`. A client
whose version is outside the server window fails before presenting credentials.
A legacy client that omits `hello` receives the v1 prose error shape. A v2
client receives `typed_error`.

`describe_protocol` is safe before authentication and returns the current
machine-readable JSON Schemas, MCP method schema, advertised features,
compatibility behavior, and transport limits:

```json
{"op":"describe_protocol"}
```

The schemas use JSON Schema draft 2020-12 and cover every top-level request,
reply, and stream-event tag. The authorization/schema regression constructs
all 61 current syscalls and rejects either a missing schema operation or an
undocumented extra. Deterministic golden request arrays cover all 58 v1
operations and all 61 v2 operations. Domain payload examples and
previous-version shapes are retained under `protocol/`.

## Compatibility policy

- Unknown fields on a known operation are ignored. This is the additive
  extension mechanism.
- An unknown `op`, a missing required field, or a wrong primitive type returns
  `invalid_request`; it does not panic and the connection remains usable.
- New optional operations, reply fields, error detail, and feature identifiers
  may be added within a protocol version.
- Removing or renaming an operation/field, changing a required field, or
  changing serialized meaning requires a protocol-version bump.
- A breaking version must retain the immediately previous released window and
  its golden fixtures unless release notes explicitly announce retirement.
- Deprecation is documented for at least one minor release before removal.
- Credentials and payload-bearing fields are redacted from Rust `Debug`
  renderings. Typed public errors contain only bounded, redacted diagnostics.

## Transport and backpressure

Both syscall and MCP servers share one bounded framing implementation:

| Control | Contract |
|---|---|
| Framing | One UTF-8 JSON value followed by `\n`; CRLF accepted |
| Maximum frame | 34,603,008 bytes (16 MiB package archive after hex encoding plus envelope allowance) |
| Default admitted connections | 256 per bound server |
| First-frame / TLS handshake deadline | 15 seconds |
| Established connection idle deadline | 300 seconds |
| Recommended keepalive interval | At most 150 seconds between complete frames |
| Graceful-close deadline | 5 seconds from client half-close to peer EOF |
| Per-request dispatch deadline | 130 seconds |
| Stream event buffers | 64 events at each provider/executor and executor/socket boundary |
| Ordering | One ordinary request/reply or one ordered stream at a time per connection |

Oversized or invalid UTF-8 input is rejected before an unbounded allocation.
An oversized response is replaced with a bounded typed/internal error.
Connection admission is semaphore-bounded; excess sockets are closed rather
than spawning unbounded tasks. A client-side ordinary-request timeout closes
the connection so a late reply cannot be mistaken for the next request. A
stream uses the same timeout between frames and can therefore outlast one
ordinary request without accepting a silent peer indefinitely.

### Connection liveness and graceful close

Protocol v2 provides an application-level liveness probe:

```json
{"op":"ping"}
{"status":"pong"}
```

`ping` is safe before authentication, performs no kernel work, and is rejected
on a negotiated v1 connection with `incompatible_version`. Every complete
frame starts a fresh established-idle window, so a quiet client should send a
ping no less often than the published 150-second recommendation. The Rust SDK
exposes this as `KernelClient::ping`.

MCP uses its standard parameterless JSON-RPC `ping` method and returns an empty
result. It is accepted before `initialize`, as required by the negotiated
2024-11-05 lifecycle. There is no private MCP shutdown method.

Graceful shutdown uses the transport for both protocols. After consuming every
ordinary reply or terminal stream frame, the client half-closes its write side
and waits up to five seconds for server EOF. The server stops admitting frames,
shuts down its write side, and releases the connection permit. An unread frame
during that handshake is a client protocol-state error. The Rust
`SyscallClient`, `KernelClient`, and in-tree `McpClient` expose consuming
`close` methods that enforce this sequence. If the 300-second idle deadline
expires instead, the server closes the write side without an application error;
the next client operation must reconnect. Closing a transport during an
in-flight request is not a cancellation signal—stream cancellation remains the
explicit request-id operation described below.

### Message streaming and request cancellation

Protocol v2 advertises `token_streaming` and `request_id_cancellation`. Start a
stream with an application-generated id:

```json
{"op":"send_message_stream","request_id":"turn-42","agent_id":"…","message":"hello"}
```

The server sends monotonically sequenced `stream_event` replies followed by
exactly one `stream_completed` or `stream_failed` terminal reply. Event kinds
are `started`, `token`, `tool_call_started`, `tool_call_completed`, and
`context_pressure`. The SDK rejects a skipped, duplicated, out-of-order, or
cross-request sequence.

The per-connection event channel is bounded to 64 entries. A slow reader
therefore backpressures the executor/provider rather than creating an unbounded
queue. Azure OpenAI SSE deltas are forwarded incrementally. A backend without
native deltas emits its completed response as one token event, which is honest
fallback behavior rather than a claim of provider token granularity.

Because one connection belongs to its stream until the terminal frame,
cancellation uses a second authenticated connection:

```json
{"op":"cancel_request","request_id":"turn-42","agent_id":"…"}
```

The agent id passes through the normal tenant-ownership authorization check; a
request id by itself is not a cancellation capability. The exact active
request token is signalled cooperatively. The original stream ends with
`stream_failed` and code `cancelled`, while the agent remains runnable. Once
any provider delta is visible, retry and failover are suppressed to prevent
duplicated output. A socket write failure drops the stream immediately; a
silent disconnected peer is bounded by the per-frame inactivity timeout.

## Errors

Protocol v2 errors have:

```json
{
  "status": "typed_error",
  "code": "authorization_denied",
  "message": "resource not found or access denied",
  "retryable": false
}
```

Stable codes cover authentication, authorization, invalid requests/arguments,
not found, permission, quota, sandbox, conflict, unavailable, timeout,
cancelled, incompatible version, provider, lifecycle, and internal failures.
`agent_sdk::SdkError::Wire` preserves the code and retry hint. The legacy
`SdkError::Kernel` form remains for v1 replies and local SDK validation.

## Authentication and transport variants

- Loopback TCP can be open for local trusted-system operation or protected by a
  shared token.
- AuthSystem API keys/session tokens bind a connection to a tenant and are
  revalidated for every request.
- TLS verifies the server certificate; shared/tenant authentication occurs
  inside the encrypted stream.
- Unix sockets rely on filesystem permissions and may additionally require a
  token.
- Plaintext MCP binds only to loopback. Remote MCP is not advertised until it
  has a TLS transport.
- `ClusterClient::connect_authenticated` authenticates every node
  all-or-nothing. It performs no hidden retry of side-effecting calls and does
  not infer ownership for an agent it did not place.

## Conformance evidence

Versioned fixtures:

- `protocol/v1/error.json`
- `protocol/v1/requests.json` (all 58 v1 operations)
- `protocol/v2/hello.json`
- `protocol/v2/typed-error.json`
- `protocol/v2/describe-protocol-request.json`
- `protocol/v2/requests.json` (all 61 v2 operations)
- `protocol/v2/send-message-stream.json`
- `protocol/v2/stream-event.json`
- `protocol/v2/stream-completed.json`
- `protocol/v2/stream-failed.json`
- `protocol/v2/cancel-request.json`
- `protocol/v2/request-cancellation.json`
- `protocol/v2/ping.json`
- `protocol/v2/pong.json`
- `protocol/mcp/initialize.json`
- `protocol/mcp/ping.json`
- `protocol/mcp/ping-response.json`

Regenerate a version after an intentional schema change:

```bash
cargo run -p kernel --example export-wire-fixtures --locked -- 1 > protocol/v1/requests.json
cargo run -p kernel --example export-wire-fixtures --locked -- 2 > protocol/v2/requests.json
python3 scripts/verify_wire_fixtures.py
```

Prospective non-Rust clients can check both version handshakes and validate
every fixture against a live server's `DescribeProtocol` schema without any
third-party Python dependency:

```bash
python3 scripts/verify_wire_fixtures.py --address tcp://127.0.0.1:7777
# Authenticated server:
AGENTOS_TOKEN=… python3 scripts/verify_wire_fixtures.py \
  --address tcp://127.0.0.1:7777 --token-env AGENTOS_TOKEN
```

The runner performs only `Hello`, optional `Authenticate`, and
`DescribeProtocol`; it never executes the mutating golden requests. Kernel
tests verify fixture parsing, complete per-version operation/schema parity,
typed error classification, authorization, bounds, redaction, TCP/Unix/TLS
behavior, ping idle-reset semantics, bounded half-close/EOF shutdown, stream
ordering/backpressure, and MCP parity. SDK tests exercise the same real server
boundary, preserve typed errors and enforcement introspection, and prove
second-connection request cancellation plus typed liveness and close APIs.
Adapter tests prove incremental Azure SSE deltas and bounded output.
