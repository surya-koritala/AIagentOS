# Public wire and client contract

AI Agent OS has one canonical remote ABI:
`kernel::syscall_server::Syscall` / `SyscallReply` as UTF-8,
newline-delimited JSON. The Rust SDK, CLI, TUI backend, and raw clients must use
that boundary. The desktop packages an ephemeral loopback server protected by a
random per-process secret and reaches its in-process kernel only through the
same typed client. MCP tool calls enter the same authorization, tool-registry,
syscall-gate, sandbox, accounting, and audit path.

The numbered in-process syscall prototype is not part of this contract.

## Canonical clients and parity

There is one canonical operator client: **`agentctl`**. It is the
non-interactive, scriptable reference for public administrative operations.
There is one canonical programmatic client: **`agent_sdk::KernelClient`**. The
wire schema remains the ultimate compatibility authority; neither client may
invent a privileged operation outside it.

| Surface | Intended role | Feature-parity expectation |
|---|---|---|
| `agentctl` | Canonical headless operator client | New public administrative operations land here first or declare an explicit tracked exception. It must preserve typed errors, authorization, confirmations, and machine-readable output. |
| Rust SDK (`KernelClient`) | Canonical typed programmatic client | Covers the public wire contract and is the shared implementation boundary for first-party remote clients. |
| `agent-tui` | Focused interactive operator view | May expose a deliberate subset, but shared operations must match `agentctl` authorization, target identity, state, errors, and metrics. Missing breadth is not called parity. |
| Tauri/Svelte desktop | Focused end-user/operator application | May expose a deliberate subset, but its backend must use `KernelClient`; shared operations follow the same security and state contract. |
| `agent` | Embedded single-agent developer shell | Not an operator client and not a feature-parity target. It hosts a kernel in-process for an interactive conversation. Administrative automation belongs in `agentctl`. |
| Raw JSON / MCP | Interoperability surfaces | Must match protocol authorization and typed failure semantics; they do not define first-party UX breadth. |

“Parity” means behavioral parity for an operation a surface exposes, not an
identical menu on every surface. Shared conformance tests therefore require
the CLI, TUI state model, desktop backend, SDK, raw protocol, and MCP adapter to
agree on authentication, tenant visibility, allowed owner behavior, foreign
denial, failed re-authentication, and read-only mutation denial. Metrics
projections are separately checked against the same raw snapshot. Feature
breadth, reconnect/idempotency, accessibility, and signed desktop distribution
remain release criteria rather than implied parity.

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
all 75 current syscalls and rejects either a missing schema operation or an
undocumented extra. Deterministic golden request arrays cover all 59 v1
operations and all 75 v2 operations. Domain payload examples and
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
- Setting `AGENT_SERVER_TLS_CLIENT_CA` makes the TLS handshake mutually
  authenticated. `ClusterClient::connect_tls` accepts a rustls client config
  carrying the client certificate and cluster trust roots.
- Unix sockets rely on filesystem permissions and may additionally require a
  token.
- Plaintext MCP binds only to loopback. Remote MCP is not advertised until it
  has a TLS transport.
- `ClusterClient::connect_authenticated` and its TLS variants connect every node
  all-or-nothing. They perform no hidden retry of side-effecting calls.

## Storage data inventory

Protocol v2 advertises `data_inventory`. A trusted system operator can read the
versioned policy classification for every supported SQLite, file, ephemeral,
and external data boundary:

```json
{"op":"storage_data_inventory"}
```

The `storage_data_inventory` reply carries an `inventory` object with the
inventory schema version, database schema version, and entries classified by
owner, tenant key, sensitivity, retention, encryption, backup, and deletion
policy. It is static policy metadata: it does not inspect or return live
content, credentials, tenant identifiers, configured paths, or secret material.
Tenant credentials are denied. The SQLite subset is checked against the live
logical schema, so adding a table or view without a complete classification
fails regression tests.

## Destructive data erasure

Protocol v2 advertises `data_erasure`. Only a trusted system principal can erase
data; tenant users and tenant administrators are denied. The request must carry
an explicit `confirm: true` and exactly one tagged agent, user, or tenant target:

```json
{
  "op": "erase_data",
  "target": {
    "kind": "agent",
    "agent_id": "00000000-0000-0000-0000-000000000001"
  },
  "confirm": true
}
```

The kernel closes affected credential admission and waits for already-admitted
requests to finish before taking a global erasure barrier. Agent and tenant
erasure also disables supervised owners, quiesces turns and external tool
calls, removes live scheduler, executor, sandbox, namespace, cgroup, gate, and
observability state, and only then commits the classified SQLite transaction.
When `backup.root` is configured, every subject scope also exclusively locks
that managed root, verifies and removes every current-installation backup, and
keeps publication fenced through the SQLite commit. Any unknown, corrupt,
foreign, unsafe, or unavailable-key entry fails the request before durable
erasure.

## Backup retention

Protocol v2 advertises `backup_retention`. A trusted system operator can preview
or enforce retention over verified backups owned by the running installation.
Tenant credentials are denied, and deletion requires `confirm: true`;
`dry_run: true` never deletes:

```json
{
  "op": "enforce_storage_backup_retention",
  "backup_root": "/var/lib/agentos/backups",
  "keep_latest": 7,
  "max_age_seconds": 2592000,
  "dry_run": true,
  "confirm": false
}
```

The server serializes retention with backup publication and returns an
auditable report of eligible, deleted, retained, and skipped entries.

Protocol v2 also advertises `scheduled_backups`. A trusted system operator can
read the configured policy and bounded process-local maintenance health:

```json
{"op":"storage_backup_status"}
```

The `storage_backup_status` reply carries a `maintenance` object with bounded
attempt/success/failure counters, consecutive failures, timestamps, the last
published name, configured signing key ID (never private key material), and a
bounded diagnostic. It also reports managed-erasure purge attempts, successes,
failures, and deleted-copy counts. When a signing identity is configured, both
scheduled backups and the system-only `create_storage_backup` operation return
manifests with Ed25519 authenticity metadata. That operation accepts only the
exact configured `backup.root`, preventing untracked server-side snapshots.
Verification still requires a separately retained public trust file; the
server never returns it as trusted material. Tenant credentials are denied. The
same bounded health values are available without filesystem-path labels in
Prometheus.
An agent-only erasure reopens the unaffected tenant credentials after the
operation. Successful user and tenant erasure leaves their credentials revoked.
Failure before the durable commit reopens still-valid credentials so the
operator can inspect and retry safely.

The reply is `data_erased` with a nullable `receipt`. `null` means no classified
data existed. A receipt is durable and contains no subject identifier, tenant,
actor, reason, prompt, path, or deleted value. The typed SDK requires the
explicit `CONFIRM_DATA_ERASURE` proof value; `agentctl` requires a trailing
`--confirm`.

## Distributed node contract

Protocol-v2 nodes publish a durable Ed25519 identity and local control state in
the optional `control` field of `node_info`. `prove_node_identity` signs a fresh
client challenge. Cluster construction verifies that proof, treats dial
addresses as transport locations rather than identities, and rejects duplicate
node identities. The private key and node-control revision are persisted in the
kernel SQLite database; filesystem permissions protect that database.

Node state is generation-fenced:

- `active` accepts placement and normal work;
- `draining` rejects new agents, resumed work, turns, tool calls, and installed
  package starts while allowing observation and cleanup;
- `quarantined` permits only diagnostics, control recovery, and cleanup.

Placement can require exact region, data-residency, model, sandbox-profile, and
label matches. A missing match is a retryable `unavailable` error. On
construction or explicit `rebuild_owners`, the cluster lists durable node state
and reconstructs agent routing. Duplicate agent ownership is a non-routable
`conflict`; the client never guesses an owner.

### Authorized membership and discovery

A designated protocol-v2 kernel can act as the durable membership authority.
Membership operations are system-scoped; production callers should use both a
system authentication token and mutual TLS.

1. The authority issues a random 32-byte challenge valid for 5–300 seconds.
2. The joining node signs a domain-separated payload covering the authority
   cluster ID, challenge, durable identity, endpoint, software version, and
   protocol support window.
3. The authority verifies and consumes the challenge exactly once, rejects
   incompatible versions and duplicate identities/endpoints, and commits the
   active member plus audit evidence in one SQLite transaction.
4. Clean leave and terminal identity revocation use per-member generation
   compare-and-set fences. A left node needs a fresh challenged join; a revoked
   identity cannot rejoin.

`get_cluster_membership` returns one atomic cluster ID/generation/member
snapshot. `ClusterClient::connect_discovered_authenticated` and its TLS variant
dial only active endpoints, prove every identity, require exact endpoint and
fingerprint matches, then re-read the authority. If membership changed while
connections were assembled, construction fails with a retryable `conflict`.
The authority identity, membership, generations, and audit survive authority
restart.

This is not yet a consensus, lease, or partition-tolerant membership protocol.
The designated authority is a single consistency point with no quorum failover;
there is no ownership lease/fencing token enforced by agent mutations,
automatic migration, partition fencing, cluster-wide quota transaction,
policy/package convergence, rolling-upgrade coordinator, or disaster-recovery
controller. Identity revocation is enforced by discovery, but live TLS client
certificate rotation/revocation still requires replacing trust configuration
and restarting affected listeners. Those requirements remain tracked by #122.

## Conformance evidence

Versioned fixtures:

- `protocol/v1/error.json`
- `protocol/v1/requests.json` (all 59 v1 operations)
- `protocol/v2/hello.json`
- `protocol/v2/typed-error.json`
- `protocol/v2/describe-protocol-request.json`
- `protocol/v2/requests.json` (all 75 v2 operations)
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
ordering/backpressure, and MCP parity. The production incremental frame decoder
also runs through 512-case ordered-fragment equivalence and shuffled-fragment
properties with explicit retained/allocation bounds; the protected
extended-security workflow fuzzes whole envelopes and fragmented/reordered
transport input independently. SDK tests exercise the same real server
boundary, preserve typed errors and enforcement introspection, and prove
second-connection request cancellation plus typed liveness and close APIs.
One shared scenario runner also drives the SDK, `agentctl`, TUI refresh,
desktop backend, raw protocol, and MCP client. Every surface must prove
pre-auth liveness, typed missing/invalid authentication, tenant-scoped
visibility, allowed owner behavior, identical foreign/absent denial,
failed-reauthentication reset, and read-only mutation denial.
Adapter tests prove incremental Azure SSE deltas and bounded output.
