# Memory, KV and IPC VFS mounts

`/memory`, `/kv` and `/ipc` expose real agent-owned persistent data and local
messaging through bounded VFS references. Servers advertise `data_vfs`.
The namespace table starts with these mounts plus `/tools` and `/workspace`;
a tenant Admin can create aliases and revoke exact bindings.

Opening a data reference validates its logical identity and captures the exact
backing tool registrations. It does not read data or grant authorization.
Every read, write, list or stat passes once through the ordinary tool gate and
resource broker, using the caller's agent identity, current policies, tenant,
namespace, sandbox identity, admission limits and ownership fences.

Rights are explicit and duplicates can only attenuate them. Close is independent
for each descriptor. Unmount, stop, binding replacement and namespace changes
invalidate new use; already admitted work may finish. Handles are ephemeral,
lost on restart and close on clone. Persistent KV values and facts retain the
existing context-store ownership, backup, encryption and deletion semantics.

## Objects and operations

| Object | Read | Write | List | Stat |
|---|---|---|---|---|
| Memory store | Semantic query | Store a fact | Unavailable | Fact count and bounds |
| KV mount root | Unavailable | Unavailable | Bounded sorted keys | Key count and listing bound |
| KV entry | Get optional UTF-8 value | Atomic insert/overwrite | Unavailable | Existence, byte length, update time |
| IPC mailbox/outbox | Receive one pending message | Send to a permitted peer | Discover permitted peers | Pending count and capacity |

KV keys are opaque UTF-8 strings up to 1,024 bytes. The SDK and CLI select a
canonical lowercase hex path component under the chosen mount. This preserves
keys containing slashes or Unicode without interpreting them as paths. Raw wire
clients must use the same canonical component. Internal `context_spill:` keys
are reserved and excluded from public VFS listings.

Values are bounded to 1 MiB, facts to 64 KiB and query strings to 4 KiB. KV reads
apply their bound in SQL before materializing the value. Listings return at most
256 keys and an explicit `truncated` flag. Directory stat reports a count,
without revealing names or granting listing rights.

Durable context quotas include ordinary KV data and measure UTF-8 bytes. KV
admission, replacement accounting and writes are one SQLite transaction, so
concurrent connections cannot overspend a tenant or global budget. Failed writes
preserve the previous value. Metadata key bytes are included in accounting.

IPC uses the existing local mailbox ordering and namespace authorization.
Payloads are bounded to 64 KiB of serialized JSON, each mailbox holds at most
256 messages, and the dead-letter buffer retains at most 256 failed deliveries.
Receiving an empty mailbox returns `empty: true`. Delivery/receive effects retain
the existing at-least-once crash window; an indeterminate transport outcome must
be reconciled explicitly.

## SDK and CLI

```bash
agentctl vfs-data-open AGENT_ID /memory read,write,stat
agentctl vfs-kv-open AGENT_ID /kv notes read,write,stat
agentctl vfs-data-write AGENT_ID HANDLE '{"value":"saved result"}'
agentctl vfs-data-read AGENT_ID HANDLE
agentctl vfs-data-stat AGENT_ID HANDLE
agentctl vfs-data-dup AGENT_ID HANDLE read
agentctl vfs-close AGENT_ID HANDLE
```

Memory writes use `content` and optional `category`; queries use `query`.
IPC writes use `to` and `payload`. Requests cannot substitute the KV key or
agent identity stored in a reference. Data arguments are redacted from syscall
Debug output, and SDK operations are not automatically replayed.

This completes additional delivery work in
[#392](https://github.com/surya-koritala/AIagentOS/issues/392); independent review
and full production qualification remain open. Cross-node IPC is tracked
separately.
