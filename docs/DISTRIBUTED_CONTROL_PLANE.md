# Distributed control-plane consistency contract

This document is the normative consistency and failure contract for the
multi-node foundation tracked by issue #122. It describes the implementation
that exists now and the invariants a production distributed kernel must add.
It is not a production-readiness claim.

## Current maturity and authority model

The default, single-node configuration retains the original designated
SQLite authority for compatibility. When the strict, default-off
`[cluster_raft]` mode is enabled, public membership and ownership mutations are
instead committed through an OpenRaft majority, and their reads pass an
OpenRaft linearizability barrier. A request received by a follower is forwarded
to the elected leader over the same identity-pinned mTLS transport. A minority
or isolated former leader cannot commit or locally apply an authority mutation.
This provides product authority election and failover for the operations moved
behind that mode; it does not make the whole distributed kernel production
ready.

The kernel now contains a durable OpenRaft storage-v2 substrate and an
executable, statically configured peer runtime for the next stage. Votes,
committed and purged pointers, consecutive log entries, deterministic
membership and ownership state, idempotency receipts, applied state and
membership, and current snapshots share the existing SQLCipher-capable SQLite
database, WAL,
`synchronous=FULL`, backup/restore, and process-lease boundary. Open validates
all serialized state and fails closed on corruption. The upstream OpenRaft
storage conformance suite plus restart, idempotency, and malformed-record
regressions qualify that storage contract.

`cluster_runtime` supplies bounded, versioned AppendEntries, Vote, and snapshot
RPCs over mutual TLS. CA validation is necessary but not sufficient: outbound
connections verify the exact member server leaf, inbound connections bind the
exact client leaf to the claimed stable node ID, and the authenticated source
must match the vote identity inside each RPC. Configuration rejects duplicate
endpoints, certificate fingerprints, and identity keys. The internal protocol
also carries authenticated authority writes and linearizable reads for
follower forwarding. The leader replaces a forwarded mutation's proposed
timestamp with its own clock and rejects internal initialization/barrier/clock
commands on that path, so a follower cannot force a future authority time. A
three-node regression proves election, application
state replication, majority failover, follower forwarding, durable restart
catch-up, old-term fencing, and that authority writes fail closed without a
quorum. Separate regressions reject
certificate/node spoofing, embedded vote spoofing, wrong-but-CA-valid server
leaves, oversized frames, and invalid bounds.

Configured Raft voters are still fully trusted forwarders. The forwarded
command records the authenticated actor selected by the receiving application
node, but it does not yet carry an end-to-end operator credential or delegated
principal proof that the leader can independently verify. A compromised voter
must therefore be treated as a control-plane trust breach; proving that a
compromised node cannot forge tenant/operator authority remains an unchecked
#122 requirement.

`agent-server` constructs and owns this runtime when `[cluster_raft].enabled`
is true. Startup reads bounded no-follow PEM inputs, requires owner-only private
keys on Unix, validates the local certificate fingerprints against the exact
member record, and fails if an existing durable membership differs from the
configured static map. A pristine store requires explicit `bootstrap = true`;
the same setting is restart-safe because an already initialized node is
verified instead of reinitialized. SIGINT/SIGTERM closes the peer listener and
OpenRaft task cleanly. Startup also verifies that the local application UUID
and Ed25519 public key match the durable node identity before the process can
join the quorum.

All voters supply one identical immutable application genesis document. The
replicated state machine owns challenged join, membership generation and audit,
leave/revocation, ownership claim/renew/release, a monotonic authority clock,
and exact caller-stable operation receipts. The SDK exposes explicit
operation-ID variants for safe replay after an ambiguous authority response.
An application endpoint certificate fingerprint is independent from the Raft
transport certificate and may be omitted only when that application listener
does not use TLS.

The OpenRaft voter map is still static and fixed for the lifetime of the
process. Application membership can change through the replicated state
machine, but adding/removing consensus voters, coordinating cluster-wide
certificate epochs, and rotating the Raft trust map safely are not implemented.
Destination mutation proofs also do not yet contain an authority term or a
proof expiry that a partitioned destination can independently validate.

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

In enabled mode the authority directory is quorum-replicated, but agent
creation plus authority/fence publication is not atomic across databases. It
is durably reconcilable: the
authority exposes a stable paginated ownership directory, reserved-ID creation
cannot cross a retired fence, and discovery or `reconcile_routes` repairs an
expired lease/fence for an exact local agent. An incomplete expired reservation
is first advanced to a newer token, installed at the destination, checked again,
retired, and only then released. Unknown outcomes are reported with the exact
agent id and never blindly replayed.

Consequently, the current multi-node foundation is appropriate for controlled
development and qualification. Authority writes are majority-safe, but
destination execution, placement, migration, trust rollout, quotas, and
workload state are not fully partition tolerant. This must not be advertised as
a production distributed kernel.

## Starting the internal Raft runtime

Each node uses the same exact member list and cluster name, while `node_id`,
`listen_addr`, and private-key paths identify that local process. Certificate
fingerprints are lowercase SHA-256 hex for the leaf certificate in the
corresponding PEM. Paths must be absolute; private keys must be regular,
owner-only files on Unix and no TLS input may be a symbolic link.

```toml
[cluster_raft]
enabled = true
bootstrap = true
node_id = 1
authority_cluster_id = "2d1b98c1-6caf-4ed4-b87f-55acde52d1ee"
listen_addr = "10.0.0.11:8788"
cluster_name = "production-agentos"
server_certificate_path = "/etc/agentos/raft/node-1-server.pem"
server_private_key_path = "/etc/agentos/raft/node-1-server-key.pem"
client_certificate_path = "/etc/agentos/raft/node-1-client.pem"
client_private_key_path = "/etc/agentos/raft/node-1-client-key.pem"
peer_ca_path = "/etc/agentos/raft/peer-ca.pem"

[[cluster_raft.members]]
node_id = 1
application_node_id = "558b5ce5-10a9-4274-9984-f209f0945c89"
application_endpoint = "10.0.0.11:7443"
application_tls_server_certificate_sha256 = "<64 lowercase hex characters>"
endpoint = "10.0.0.11:8788"
server_name = "node-1.internal.example"
tls_certificate_sha256 = "<64 lowercase hex characters>"
tls_client_certificate_sha256 = "<64 lowercase hex characters>"
identity_public_key = "<64 lowercase hex characters>"
```

Add one `[[cluster_raft.members]]` table for every voter. Set `bootstrap =
true` on the first start of every pristine node using the identical map. After
the membership is durable, operators may set it to `false`; a pristine or
mismatched store then fails startup rather than silently forming another
cluster. Every node must use the same `authority_cluster_id`, application
identity records, and voter records. Omit
`application_tls_server_certificate_sha256` only for a non-TLS application
listener; never substitute the Raft transport leaf for a different application
certificate. This configuration moves public membership and ownership
authority into the quorum, but does not replicate agent state or make all agent
operations partition-safe.

`agent-server` reads the platform config path by default. A service manager may
set `AGENT_SERVER_CONFIG` to an explicit absolute `config.toml` path; relative
paths are rejected.

## Consistency by object

| Object | System of record now | Current consistency | Production requirement |
|---|---|---|---|
| Cluster identity and membership | Replicated authority state when `[cluster_raft]` is enabled; designated SQLite authority otherwise | Enabled mode commits mutations through a majority, forwards followers to the leader, and uses linearizable reads; the voter map remains static | Safe voter membership changes and coordinated certificate/trust epochs |
| Node identity | Node-local Ed25519 key plus authority membership certificate fingerprint | Stable across restart; fresh challenge signs the verified TLS server leaf; listener trust generations reload atomically and drain old sessions | Quorum-coordinated certificate/trust epochs and rollout order across partitions |
| Node availability and placement profile | Node-local SQLite database | Generation-fenced on one node; discovery reads a point-in-time value | Signed or quorum-observed liveness/capacity with staleness bounds |
| Agent identity | Authority reservation plus owning-node SQLite database | Managed creation reserves one UUID before exact destination creation; duplicates cannot overwrite a local agent | Quorum-allocated immutable identity and migration-aware placement record |
| Agent ownership and routing | Quorum authority lease registry in enabled mode, destination fence tombstones, plus `ClusterClient` in-memory routes | Ownership mutations and reads are quorum-backed in enabled mode; authority-discovered clients reserve, pre-fence, create, and publish exact routes; paginated reconciliation repairs or safely retires partial creation; every mutation revalidates authority/fence agreement; opt-in maintenance renews idle routes; a per-agent admission barrier prevents fence changes from crossing admitted work | Authority term/expiry in destination-verifiable proofs, partition-safe execution, and migration admission |
| Agent state and checkpoints | Owning node SQLite database | Transactional on one node; no cross-node replica or migration transaction | Checkpoint/handoff protocol with one committed owner, rollback point, and side-effect boundary |
| Package metadata and trust roots | Node-local package registry and policy | Transactional per node; no cluster convergence guarantee | Versioned trust epoch distributed atomically or by a documented monotonic convergence protocol |
| Authorization policy | Node-local kernel configuration and durable policy state | Enforced consistently across local entry points; not synchronized cluster-wide | Tenant policy epoch included in placement and mutation admission |
| Quotas and accounting | Node-local durable quota ledger | Restart-safe per node; the same tenant can consume limits independently on several nodes | Cluster-wide reservation/commit protocol or conservatively partitioned quota grants |
| Audit | Node-local audit stores; membership audit on the authority | Durable and ordered only within its store | Globally attributable event identity, node/authority terms, durable collection, and gap detection |
| IPC and delegation | Owning-node kernel | Authorized locally; no cross-node delivery protocol | End-to-end principal/namespace propagation, ordering scope, idempotency key, and delivery guarantee |

## Current operation semantics

- In enabled mode, a challenged join, clean leave, or identity revocation
  succeeds only after a majority commits the member row, authority generation,
  and audit evidence. Disabled mode retains the single-node transaction path.
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
| Membership authority loss | Enabled mode elects a replacement while a majority remains; a minority or isolated old leader rejects authority writes and linearizable reads | Safe voter changes, cluster-wide trust rollout, and externally qualified partition/latency behavior |
| Workload node loss | Calls to that node fail; another node must not recreate or resume its agents automatically | Expiring ownership lease, durable replica/checkpoint, and explicit recovery policy |
| Network partition | Only the authority majority can mutate membership/ownership. A destination rejects older or missing installed tokens, but a previously installed proof has no independently verifiable authority term/expiry | Authority term and expiry incorporated into every destination proof, plus partition qualification |
| Duplicate agent ownership | Reconciliation compares every node with the durable authority directory, returns a conflict, and publishes neither arbitrary copy | Quorum-backed repair procedure and replicated workload evidence |
| Stale route | In enabled mode a managed client receives a linearizable authority ownership read before each mutation, rejects released/expired/different ownership, propagates same-owner renewal generations, and requires the destination fence before use; explicit reconciliation repairs exact same-owner evidence | Authority terms in destination proofs and durable owner request identity |
| Client retry before visible output | Authority mutations accept a caller-stable UUID and return the original retained successful quorum result for an exact retry; reusing that retained ID for a different command fails closed. Rejections are not retained and never count as success. Local workload APIs remain safe only where their contract documents idempotency | Durable request identity and deduplication at each workload owner |
| Retry after a side effect or partial model/tool output | Must not happen automatically; the result is terminal unless the operation contract proves idempotency | Side-effect journal and explicit at-most-once or at-least-once contract per operation |
| Clock skew | Join challenge and ownership expiry use authority time; workload nodes do not independently expire or enforce leases | Authority term plus bounded lease clock assumptions or logical-expiry protocol |
| Authority restart | Each voter restores its log, snapshots, immutable genesis, membership, ownership, receipts, and audit; a quorum elects a leader and catches up a restarted node | Cross-host disaster-recovery procedure and external qualification |
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

1. Add safe quorum-versioned voter membership changes; coordinate certificate
   and trust epochs; include the committed authority term/expiry in every
   destination proof; and permanently fence old terms.
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
- Durable OpenRaft storage-v2 log, replicated membership/ownership authority,
  operation receipts, and snapshots: `crates/kernel/src/cluster_consensus.rs`
- Strict operator configuration: `crates/kernel/src/config.rs`
- Bounded mTLS Raft peer RPCs, exact certificate/node binding, daemon
  lifecycle, and quorum regressions: `crates/kernel/src/cluster_runtime.rs` and
  `crates/cli/src/bin/agent-server.rs`
- Durable cluster tables and single-process storage lease:
  `crates/kernel/src/context.rs` and `crates/kernel/src/storage.rs`
- Authenticated discovery, placement, and owner reconstruction:
  `crates/sdk/src/cluster.rs`
- Node admission and all wire mutation paths:
  `crates/kernel/src/syscall_server.rs`
- Local quotas and accounting: `crates/kernel/src/cgroups.rs`,
  `crates/kernel/src/rate_limit.rs`, and `crates/kernel/src/context.rs`
