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

The schemas use JSON Schema draft 2020-12 and cover every top-level request and
reply tag. The authorization/schema regression constructs all 58 current
syscalls and rejects either a missing schema operation or an undocumented
extra. Domain payload examples and previous-version shapes are retained under
`protocol/`.

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
| Per-request dispatch deadline | 130 seconds |
| Ordering | One request and one reply at a time per connection |

Oversized or invalid UTF-8 input is rejected before an unbounded allocation.
An oversized response is replaced with a bounded typed/internal error.
Connection admission is semaphore-bounded; excess sockets are closed rather
than spawning unbounded tasks. A client-side request timeout closes the
connection so a late reply cannot be mistaken for the next request.

Protocol v2 does not advertise event or streaming frames. Hosted/local provider
work is cancellable through lifecycle pause/kill, including from a second
connection, but token streaming and request-id cancellation require a future
protocol feature and remain open in issue #121.

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
- `protocol/v2/hello.json`
- `protocol/v2/typed-error.json`
- `protocol/v2/describe-protocol-request.json`
- `protocol/mcp/initialize.json`

Kernel tests verify fixture parsing, complete operation/schema parity, typed
error classification, authorization, bounds, redaction, TCP/Unix/TLS behavior,
and MCP parity. SDK tests exercise the same real server boundary and preserve
typed errors and enforcement introspection.
