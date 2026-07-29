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
An explicitly addressed `ClusterClient` remains an unmanaged compatibility
client: it reconstructs an in-memory owner map by listing every connected node
and refuses duplicate agent identifiers. A client built through authenticated
authority discovery instead retains its authority connection. Creation reserves
a UUID at the authority, preinstalls its exact destination fence, creates only
while that proof remains active, and publishes the route last. Before every
managed mutation the client re-reads the authority record, rejects expired or
changed ownership, and installs a same-owner renewal generation before using
it. Managed routes can be renewed explicitly or by an opt-in maintenance worker
that uses fresh authenticated connections, republishes exact fences, and
exposes bounded health.

The designated authority remains a single database with no quorum term, and
agent creation plus authority/fence publication is not atomic across databases.
It is now durably reconcilable: the
authority exposes a stable paginated ownership directory, reserved-ID creation
cannot cross a retired fence, and discovery or `reconcile_routes` repairs an
expired lease/fence for an exact local agent. An incomplete expired reservation
is first advanced to a newer token, installed at the destination, checked again,
retired, and only then released. Unknown outcomes are reported with the exact
agent id and never blindly replayed.

Consequently, the current multi-node foundation is appropriate for controlled
development and qualification. It is not partition tolerant and must not be
advertised as a production distributed kernel.

## Consistency by object

| Object | System of record now | Current consistency | Production requirement |
|---|---|---|---|
| Cluster identity and membership | Designated authority SQLite database | Linearized on that one authority; atomic generation-fenced snapshots and audit | Quorum-committed authority term, failover, and read rules that cannot revive an old authority |
| Node identity | Node-local Ed25519 key plus authority membership certificate fingerprint | Stable across restart; fresh challenge signs the verified TLS server leaf; listener trust generations reload atomically and drain old sessions | Quorum-coordinated certificate/trust epochs and rollout order across partitions |
| Node availability and placement profile | Node-local SQLite database | Generation-fenced on one node; discovery reads a point-in-time value | Signed or quorum-observed liveness/capacity with staleness bounds |
| Agent identity | Authority reservation plus owning-node SQLite database | Managed creation reserves one UUID before exact destination creation; duplicates cannot overwrite a local agent | Quorum-allocated immutable identity and migration-aware placement record |
| Agent ownership and routing | Authority lease registry, destination fence tombstones, plus `ClusterClient` in-memory routes | Authority-discovered clients reserve, pre-fence, create, and publish exact routes; paginated reconciliation repairs or safely retires partial creation; every mutation revalidates authority/fence agreement; opt-in maintenance renews idle routes; a per-agent admission barrier prevents fence changes from crossing admitted work | Quorum-committed authority term, partition-safe renewal, and migration admission |
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
- Managed agent creation allocates a UUID, commits an expiring authority
  reservation for that UUID/node, preinstalls the exact destination fence,
  creates the local agent while holding a shared fence guard, verifies the
  returned UUID, and publishes the route. A delayed create with a stale or
  retired proof is rejected before local state is created.
- Agent turns, tool calls, cancellation, memory writes, storage writes,
  checkpoint writes, and lifecycle mutations are authorized and committed by
  the owning node. An operator/control-plane client can install a durable
  highest-token destination fence; after installation, unfenced calls and
  stale, retired, foreign-cluster, or cross-agent proofs fail closed. The
  verification and complete protected operation share one per-agent read
  barrier, while install and retirement take its exclusive side. A newer token
  therefore waits for an admitted operation instead of crossing a
  verify-to-execute gap. The typed SDK covers fenced lifecycle, turn, stream,
  cancellation, and tool calls. A fenced stream holds the same barrier for its
  complete lifetime; ordinary streams remain rejected after fence installation.
  Its cancellation registration is bound to the exact proof, so an old owner
  can drain its admitted stream even when a handoff writer is queued, but a
  delayed cancel cannot signal a later request-id reuse under a new fence.
- Ownership claims are system-scoped authority operations. A new record starts
  at token 1; renewal preserves the token; release retains a tombstone; and
  transfer after release or expiry requires the exact old token and allocates a
  strictly greater token. Unknown, inactive, or revoked owner nodes fail closed.
  Clean leave is blocked while an unexpired lease remains; terminal member
  revocation releases every owned record in the same authority transaction.
- Rebuilding routing lists durable agents on every connected node and pages the
  complete authority ownership directory in stable agent-id order. A managed
  rebuild requires each local agent to match one authority record. Exact local
  state can recover an expired lease and missing/stale fence; an unexpired
  pre-creation reservation remains pending; an expired reservation without a
  local agent is fenced with a newer token, rechecked, retired, and released.
  A released tombstone with local state, an unknown record, missing authority
  evidence, or a duplicate local identifier is a fail-closed conflict.
- Automatic maintenance is explicit opt-in because it retains an authenticated
  connector and performs background authority/destination mutations. Its TTL
  and interval are validated to leave a retry window. Each cycle renews known
  routes and republishes exact fences; per-route failures remain visible in
  `maintenance_status`. Dropping the `ClusterClient` aborts the worker.

## Failure and retry semantics

| Event | Required current behavior | What remains before production |
|---|---|---|
| Membership authority loss | Existing node-local work can continue; membership mutation and fresh authoritative discovery fail closed | Elect a new term by quorum and fence every previous authority |
| Workload node loss | Calls to that node fail; another node must not recreate or resume its agents automatically | Expiring ownership lease, durable replica/checkpoint, and explicit recovery policy |
| Network partition | A node with an installed destination fence rejects older or missing tokens, but the single authority can still be duplicated or revived without quorum | Majority ownership authority and an authority term incorporated into every destination proof |
| Duplicate agent ownership | Reconciliation compares every node with the durable authority directory, returns a conflict, and publishes neither arbitrary copy | Quorum-backed repair procedure and replicated workload evidence |
| Stale route | A managed client re-reads authority ownership before each mutation, rejects released/expired/different ownership, propagates same-owner renewal generations, and requires the destination fence before use; explicit reconciliation repairs exact same-owner evidence | Quorum-backed route reads, authority terms, and durable request identity |
| Client retry before visible output | Safe only where the called local API already documents idempotency | Cluster request identity and durable deduplication at the authority and owner |
| Retry after a side effect or partial model/tool output | Must not happen automatically; the result is terminal unless the operation contract proves idempotency | Side-effect journal and explicit at-most-once or at-least-once contract per operation |
| Clock skew | Join challenge and ownership expiry use authority time; workload nodes do not independently expire or enforce leases | Authority term plus bounded lease clock assumptions or logical-expiry protocol |
| Authority restart | The same database restores cluster identity, membership generation, and audit | Quorum log recovery and disaster-recovery procedure |
| Workload restart | The same node database restores its agents and highest-token/retired destination tombstones; managed reconstruction recovers exact same-owner leases/fences and rejects ambiguous evidence | Checkpoint replication and quorum takeover publication |

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
2. Checkpointed drain/migration with rollback and side-effect classifications.
3. Cross-node IPC/delegation with end-to-end authorization and audit.
4. Cluster quota reservations and monotonic policy/package trust epochs.
5. Quorum-coordinated certificate rollout, rolling upgrades,
   partition/clock-skew chaos qualification, and disaster recovery. The
   node-local live reload, session drain, and membership leaf binding primitives
   exist; cluster-wide sequencing does not.

The unchecked criteria in issue #122 remain unchecked until their implementation
and exact-commit evidence exist. Documentation, a client-side route map, or a
passing single-node test is never accepted as substitute evidence.

## Implementation references

- Membership, identity, ownership leases, generations, and audit:
  `crates/kernel/src/cluster_control.rs`
- Durable cluster tables and single-process storage lease:
  `crates/kernel/src/context.rs` and `crates/kernel/src/storage.rs`
- Authenticated discovery, placement, and owner reconstruction:
  `crates/sdk/src/cluster.rs`
- Node admission and all wire mutation paths:
  `crates/kernel/src/syscall_server.rs`
- Local quotas and accounting: `crates/kernel/src/cgroups.rs`,
  `crates/kernel/src/rate_limit.rs`, and `crates/kernel/src/context.rs`
