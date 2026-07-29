# Distributed control-plane consistency contract

This document is the normative consistency and failure contract for the
multi-node foundation tracked by issue #122. It describes the implementation
that exists now and the invariants a production distributed kernel must add.
It is not a production-readiness claim.

## Current maturity and authority model

The current implementation has one designated membership authority backed by
one kernel SQLite database. Membership changes are serialized by an immediate
SQLite transaction and published as an atomic, monotonically generated
snapshot. There is no replicated log, election, quorum, or automatic authority
failover. If the designated authority is unavailable, clients must fail closed
for joins, leaves, revocation, and fresh authenticated discovery.

Each workload node owns a separate SQLite database under the existing
single-process storage lease. Agent state is not replicated between nodes.
`ClusterClient` is a routing client, not a consensus participant: it reconstructs
an in-memory owner map by listing every connected node and refuses duplicate
agent identifiers, but no ownership lease or fencing token is enforced by
agent mutations yet.

Consequently, the current multi-node foundation is appropriate for controlled
development and qualification. It is not partition tolerant and must not be
advertised as a production distributed kernel.

## Consistency by object

| Object | System of record now | Current consistency | Production requirement |
|---|---|---|---|
| Cluster identity and membership | Designated authority SQLite database | Linearized on that one authority; atomic generation-fenced snapshots and audit | Quorum-committed authority term, failover, and read rules that cannot revive an old authority |
| Node identity | Node-local Ed25519 key in the node SQLite database | Stable across restart; proved by fresh challenge | Live certificate rotation/revocation bound to durable node identity |
| Node availability and placement profile | Node-local SQLite database | Generation-fenced on one node; discovery reads a point-in-time value | Signed or quorum-observed liveness/capacity with staleness bounds |
| Agent identity | Owning node SQLite database | Stable on one node; cluster-wide uniqueness is detected only while rebuilding connected nodes | Authority-allocated ownership record with an immutable agent identity |
| Agent ownership and routing | `ClusterClient` in-memory map rebuilt from node listings | Duplicate ownership fails closed; no durable lease, expiry, or mutation fence | Quorum-committed lease plus monotonically increasing fencing token checked by every mutable node path |
| Agent state and checkpoints | Owning node SQLite database | Transactional on one node; no cross-node replica or migration transaction | Checkpoint/handoff protocol with one committed owner, rollback point, and side-effect boundary |
| Package metadata and trust roots | Node-local package registry and policy | Transactional per node; no cluster convergence guarantee | Versioned trust epoch distributed atomically or by a documented monotonic convergence protocol |
| Authorization policy | Node-local kernel configuration and durable policy state | Enforced consistently across local entry points; not synchronized cluster-wide | Tenant policy epoch included in placement and mutation admission |
| Quotas and accounting | Node-local durable quota ledger | Restart-safe per node; the same tenant can consume limits independently on several nodes | Cluster-wide reservation/commit protocol or conservatively partitioned quota grants |
| Audit | Node-local audit stores; membership audit on the authority | Durable and ordered only within its store | Globally attributable event identity, node/authority terms, durable collection, and gap detection |
| IPC and delegation | Owning-node kernel | Authorized locally; no cross-node delivery protocol | End-to-end principal/namespace propagation, ordering scope, idempotency key, and delivery guarantee |

## Current operation semantics

- A challenged join, clean leave, or identity revocation succeeds only after
  the designated authority commits the member row, authority generation, and
  audit row in one transaction.
- Authenticated discovery reads one atomic membership snapshot, connects to
  every active endpoint, proves the advertised identity and fingerprint, and
  re-reads membership. Any change during assembly returns a retryable conflict.
- Placement considers the load and declared constraints reported by connected
  active nodes. Capacity is advisory and has no signed freshness guarantee.
- Agent creation commits on the selected node. The client records that node in
  memory only after creation succeeds.
- Agent turns, tool calls, cancellation, memory operations, storage operations,
  checkpoints, and lifecycle mutations are authorized and committed by the
  owning node. They do not currently carry an authority ownership fence.
- Rebuilding routing lists durable agents on every connected node. Missing
  nodes make the view incomplete; duplicate identifiers make it conflicted.
  The client never selects an arbitrary duplicate owner.

## Failure and retry semantics

| Event | Required current behavior | What remains before production |
|---|---|---|
| Membership authority loss | Existing node-local work can continue; membership mutation and fresh authoritative discovery fail closed | Elect a new term by quorum and fence every previous authority |
| Workload node loss | Calls to that node fail; another node must not recreate or resume its agents automatically | Expiring ownership lease, durable replica/checkpoint, and explicit recovery policy |
| Network partition | Each side may retain local state, so operators must prevent multi-side mutation; the system makes no availability promise | Majority ownership authority and node-side fencing of every mutation |
| Duplicate agent ownership | `rebuild_owners` returns a non-retryable conflict and routes neither copy | Durable ownership directory and repair procedure based on fencing evidence |
| Stale route | The routed node may return not-found/unavailable; callers rebuild explicitly and do not guess | Route revision and ownership token verified by the destination |
| Client retry before visible output | Safe only where the called local API already documents idempotency | Cluster request identity and durable deduplication at the authority and owner |
| Retry after a side effect or partial model/tool output | Must not happen automatically; the result is terminal unless the operation contract proves idempotency | Side-effect journal and explicit at-most-once or at-least-once contract per operation |
| Clock skew | Join challenge expiry uses authority time; workload leases do not exist yet | Authority term plus bounded lease clock assumptions or logical-expiry protocol |
| Authority restart | The same database restores cluster identity, membership generation, and audit | Quorum log recovery and disaster-recovery procedure |
| Workload restart | The same node database restores its agents and routing can be rebuilt | Ownership lease reacquisition that cannot overlap a previous owner |

Unknown outcomes are not successes. A timeout, broken connection, or authority
change must be surfaced as an explicit retryable or terminal error according to
whether replay can duplicate visible work.

## Production ownership invariant

The next control-plane stage must enforce this invariant:

> At most one non-expired authority term can grant the highest fencing token
> for an agent, and every mutable agent operation must be rejected by the
> destination node unless it presents that exact owner, term, and token.

An ownership transfer must:

1. stop new work under the old token and drain or explicitly cancel admitted
   work;
2. persist a recoverable checkpoint and side-effect boundary;
3. commit the new owner and a strictly greater fencing token through quorum;
4. make the destination durably reject every older token before resuming; and
5. publish the new route only after destination admission succeeds.

Lease expiry alone is insufficient: a paused or partitioned old owner can wake
up later, so the monotonically increasing token must reach every mutable
resource boundary. Operations that cannot propagate a fence must remain
non-migratable.

## Required implementation sequence

1. Replicated authority log, term election, quorum read/write rules, snapshot
   installation, and permanent fencing of old terms.
2. Durable agent ownership leases and destination-enforced mutation tokens.
3. Explicit node-loss, stale-route, retry, idempotency, and split-brain tests.
4. Checkpointed drain/migration with rollback and side-effect classifications.
5. Cross-node IPC/delegation with end-to-end authorization and audit.
6. Cluster quota reservations and monotonic policy/package trust epochs.
7. Live certificate rotation/revocation, rolling upgrades, partition/clock-skew
   chaos qualification, and disaster recovery.

The unchecked criteria in issue #122 remain unchecked until their implementation
and exact-commit evidence exist. Documentation, a client-side route map, or a
passing single-node test is never accepted as substitute evidence.

## Implementation references

- Membership, identity, generations, and audit:
  `crates/kernel/src/cluster_control.rs`
- Durable cluster tables and single-process storage lease:
  `crates/kernel/src/context.rs` and `crates/kernel/src/storage.rs`
- Authenticated discovery, placement, and owner reconstruction:
  `crates/sdk/src/cluster.rs`
- Node admission and all wire mutation paths:
  `crates/kernel/src/syscall_server.rs`
- Local quotas and accounting: `crates/kernel/src/cgroups.rs`,
  `crates/kernel/src/rate_limit.rs`, and `crates/kernel/src/context.rs`
