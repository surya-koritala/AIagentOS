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
executable peer runtime with separate generation-fenced transport-trust and
voter plans. Votes, committed and purged pointers,
consecutive log entries, deterministic
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
keys on Unix and validates the local certificate fingerprints against the
exact trusted peer record. A pristine store requires explicit `bootstrap =
true`; the same setting is restart-safe because an already initialized node is
verified instead of reinitialized. Omitting `voter_ids` at generation zero
preserves the original all-members-are-voters behavior; an explicit
generation-zero subset is also supported. Bootstrap commits the complete
transport catalog and its digest even when some trusted peers begin as
learners. A later voter change must advance the durable generation by one. The
current leader first commits the exact generation and target digest into
OpenRaft membership, catches up every incoming voter as a learner, and then
completes joint consensus while retaining non-voters as learners. Startup
resumes only the matching intent or joint configuration and rejects stale,
skipped, conflicting, foreign-node, transport-catalog, and transport-identity
state. A transport-trust change separately advances its own generation and
atomically replaces the complete peer map while preserving every current
voter. The target may add learners, remove only non-voters, change endpoints,
or rotate exact server/client leaves and accepted CA roots. A node accepts
OpenRaft metadata only from the complete digest-verified durable prior catalog
or the exact configured target. Multiple roots or old-leaf overlap require an
absolute expiration no more than 30 days away; every fresh RPC checks that
deadline before accepting an overlap leaf. SIGINT/SIGTERM closes the peer
listener and OpenRaft task cleanly.
Startup also verifies that the
local application UUID and Ed25519 public key match the durable node identity
before the process can join the quorum. When durable authority state already
exists, application endpoint/TLS validation waits for a linearizable quorum
read that advances the replicated clock; a restarted minority cannot use stale
persisted time to extend a rollout window.

All voters supply one identical immutable application genesis document on the
first bootstrap. Later transport changes continue to publish that exact seed
separately from the complete current challenged application membership and the
current Raft transport subset. The replicated state machine owns challenged
join, membership generation and audit, leave/revocation, bounded
application-listener certificate rollout and audit, ownership
claim/renew/release, a monotonic authority clock, and exact caller-stable
operation receipts. The SDK exposes explicit operation-ID variants for safe
replay after an ambiguous authority response. An application endpoint
certificate fingerprint is independent from the Raft transport certificate and
may be omitted only when that application listener does not use TLS.

Application-listener rotation is a replicated prepare/activate/finalize state
machine. Prepare authorizes a new challenged leaf only until a replicated
deadline while retaining the current leaf. Activation requires another fresh
challenged registration and retains the previous leaf only for a bounded
replicated overlap. Abort is prepared-only; finalize is rejected until the
overlap ends. Discovery and startup use replicated authority time, and retired
or aborted candidate fingerprints cannot be reused. Thus a stalled rollout
automatically narrows trust instead of leaving an unbounded extra leaf.

The OpenRaft voter set can remove or promote peers already present in the
current transport-trust catalog. Its target is generation-fenced, incoming
voters catch up as learners, OpenRaft performs joint consensus, and the pinned
catalog digest rejects additions or identity changes disguised as voter
updates. Separate trust generations replace the complete catalog, add learners,
remove only former non-voters, and rotate exact server/client leaves plus CA
roots through an expiring overlap. Exact restart,
stale/skipped/conflicting-generation, mixed voter/trust, catalog-drift,
addition/removal, and retired-credential regressions cover both transitions.
A peer removed only from voting remains a replicated learner and stays trusted
until a later transport generation explicitly removes it.

Every replicated ownership revision now records the OpenRaft leader term from
its committed log ID. The managed client copies that term and the lease's exact
expiry into the destination proof. A workload node durably binds
cluster/owner/term/generation/token/expiry, rejects lower terms and stale or
conflicting revisions, and stops admitting new mutations at the exact expiry
boundary. Proof installation also rejects an expiry more than the maximum
five-minute lease plus 30 seconds ahead of the destination clock, and mutation
admission fails if the clock moves behind the fence's installation time. This
gives a partitioned destination a bounded local stop condition and permanently
fences a term after a newer term is installed. Proof installation remains a
system-scoped authenticated control operation rather than a self-contained
authority signature, so compromising a trusted workload/control client remains
inside the current control-plane threat boundary.

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
destination execution, placement, migration, Raft trust rotation, quotas, and
workload state are not fully partition tolerant. This must not be advertised
as a production distributed kernel.

## Starting the internal Raft runtime

Each node uses the same exact current transport member list, complete
application-authority catalog, immutable genesis seed, and cluster name, while
`node_id`, `listen_addr`, and private-key paths identify that local process.
Certificate fingerprints are lowercase SHA-256 hex for the leaf certificate
in the corresponding PEM. Paths must be absolute; private keys must be regular,
owner-only files on Unix and no TLS input may be a symbolic link.

```toml
[cluster_raft]
enabled = true
bootstrap = true
node_id = 1
authority_cluster_id = "2d1b98c1-6caf-4ed4-b87f-55acde52d1ee"
listen_addr = "10.0.0.11:8788"
cluster_name = "production-agentos"
voter_ids = [1, 2, 3]
voter_set_generation = 0
transport_trust_generation = 0
# Required only during a bounded overlap generation:
# transport_trust_overlap_not_after = "2026-08-15T00:00:00Z"
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
# During rotation, the primary value above is the replacement leaf and the
# retired leaf is accepted only until transport_trust_overlap_not_after:
# tls_certificate_sha256_overlap = ["<old 64-character fingerprint>"]
tls_client_certificate_sha256 = "<64 lowercase hex characters>"
# tls_client_certificate_sha256_overlap = ["<old 64-character fingerprint>"]
identity_public_key = "<64 lowercase hex characters>"
```

Add one `[[cluster_raft.members]]` table for every trusted Raft transport peer
in the current generation. `voter_ids` must be a non-empty subset; omitting it
preserves the legacy behavior in which every trusted peer votes. Set `bootstrap = true`
on the first start of every pristine node using generation zero and the
identical catalog. After the membership is durable, operators may set it to
`false`; a pristine or mismatched store then fails startup rather than silently
forming another cluster. Every node must use the same
`authority_cluster_id`, application identity records, transport catalog, voter
target, voter generation, and transport-trust generation. Omit
`application_tls_server_certificate_sha256` only for a non-TLS application
listener; never substitute the Raft transport leaf for a different application
certificate. This configuration moves public membership and ownership
authority into the quorum, but does not replicate agent state or make all agent
operations partition-safe.

At bootstrap, leave `authority_genesis_members` and `authority_members` empty;
both are derived from the exact transport member list. Once challenged
application membership or the transport subset diverges, every node must
publish both catalogs explicitly:

```toml
[[cluster_raft.authority_genesis_members]]
application_node_id = "558b5ce5-10a9-4274-9984-f209f0945c89"
application_endpoint = "10.0.0.11:7443"
application_tls_server_certificate_sha256 = "<64 lowercase hex characters>"
identity_public_key = "<64 lowercase hex characters>"

[[cluster_raft.authority_members]]
application_node_id = "558b5ce5-10a9-4274-9984-f209f0945c89"
application_endpoint = "10.0.0.11:7443"
application_tls_server_certificate_sha256 = "<64 lowercase hex characters>"
identity_public_key = "<64 lowercase hex characters>"
```

Repeat the genesis table for every identity in the original immutable seed.
Its node id and public key remain immutable; its endpoint and TLS field must
track the current challenged binding accepted by the authority.
Repeat the authority-members table for every current durable challenged
identity, including an identity whose Raft transport entry was later removed.
Every current transport entry must exactly match its authority-members record.
Startup compares the immutable seed and complete application catalog with the
replicated quorum state before any Raft membership mutation; a missing, extra,
forged, or stale application identity fails closed.

To change voters inside the existing catalog, set the same target
`voter_ids` on every participating process and increment
`voter_set_generation` from the currently durable value by one. Restart enough
current voters with that identical configuration at the same time for one of
them to obtain leadership inside the bounded startup window. This slice is a
coordinated config-driven startup operation, not a zero-downtime live
administration endpoint; a sequential rolling edit can time out while only the
old-configuration leader is active. The target-configured leader persists the
intent before learner catch-up and joint consensus; a crash at either stage is
resumed only for that exact target. A removed voter remains a trusted learner
and continues receiving replicated authority state. Do not remove a peer from
`members` or change its endpoint, identity, certificate fingerprints, server
name, or CA in the same operation. Those require a separate transport-trust
generation.

To change transport trust, keep `voter_ids` and `voter_set_generation` exactly
at their durable values, set the same complete target `members` catalog on
every participating process, and increment `transport_trust_generation` by
one. Restart enough current voters with the exact target configuration for a
leader to form. The leader commits `ReplaceAllNodes`; OpenRaft rejects a target
that omits a current voter. A newly added node must not be in `voter_ids`; it
starts with an empty store, never bootstraps a second cluster, and waits for the
leader to replicate it as a learner. Before adding that transport peer, admit
its challenged application identity through the existing quorum, retain the
original seed in `authority_genesis_members`, and put the complete resulting
durable membership in `authority_members`; every non-pristine node preflights
those exact catalogs before changing Raft membership. Remove a node from voting
in a prior voter generation before removing it from the trust catalog. Keep its
durable application record in `authority_members` until a separate challenged
application-membership protocol has removed it from the replicated authority.

Rotate Raft leaves or CAs in two transport-trust generations:

1. Build `peer_ca_path` with the old and replacement roots. Put each
   replacement server/client leaf in the primary fingerprint field and each old
   leaf in the corresponding `_overlap` list. Set
   `transport_trust_overlap_not_after` to an absolute instant no more than 30
   days away. Nodes may temporarily run either listed leaf, but overlap leaves
   fail every new RPC after that instant.
2. Move every retained node to the replacement credentials. In the next
   transport-trust generation, remove the old leaves, old CA, overlap lists, and
   expiration. The exact final catalog then rejects the retired credentials.

Trust changes are coordinated config-driven startup operations, not a
zero-downtime administration API. Trust and voter generations cannot advance
together, generations cannot be skipped or reused for a different digest, and
retained peers must preserve an application identity, server/client leaf, and
(after generation zero) CA continuity bridge. An expired overlap configuration
cannot start. Successful daemon startup
prints the converged voter generation, transport-trust generation, optional
overlap expiration, exact voter IDs, and pinned catalog digest.

`agent-server` reads the platform config path by default. A service manager may
set `AGENT_SERVER_CONFIG` to an explicit absolute `config.toml` path; relative
paths are rejected.

## Consistency by object

| Object | System of record now | Current consistency | Production requirement |
|---|---|---|---|
| Cluster identity and membership | Replicated authority state when `[cluster_raft]` is enabled; designated SQLite authority otherwise | Enabled mode commits mutations through a majority, forwards followers to the leader, and uses linearizable reads; application leaves use bounded prepare/activate/finalize trust generations; voter changes use learner catch-up and joint consensus; separate digest-pinned transport-trust generations add/remove learners and rotate exact peer leaves/CA roots | End-to-end delegated operator/tenant proof, live administration, and external partition/clock qualification |
| Node identity | Node-local Ed25519 key plus authority membership certificate fingerprint | Stable across restart; fresh challenges sign application-listener prepare and activation; candidate and previous leaf acceptance expire against replicated time; Raft peer leaves and roots use separately bounded trust epochs | Independent compromised-node and multi-host partition/clock qualification |
| Node availability and placement profile | Node-local SQLite database | Generation-fenced on one node; discovery reads a point-in-time value | Signed or quorum-observed liveness/capacity with staleness bounds |
| Agent identity | Authority reservation plus owning-node SQLite database | Managed creation reserves one UUID before exact destination creation; duplicates cannot overwrite a local agent | Quorum-allocated immutable identity and migration-aware placement record |
| Agent ownership and routing | Quorum authority lease registry in enabled mode, destination fence tombstones, plus `ClusterClient` in-memory routes | Ownership mutations and reads are quorum-backed in enabled mode; authority-discovered clients reserve, pre-fence, create, and publish exact routes; paginated reconciliation repairs or safely retires partial creation; every mutation revalidates exact term/generation/token/expiry agreement; expiry stops new destination admission; opt-in maintenance renews idle routes; a per-agent admission barrier prevents fence changes or expiry checks from crossing admitted work | Self-contained authority authentication at the destination, externally qualified partition/clock bounds, and migration admission |
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
  highest-term/token destination fence; after installation, unfenced calls and
  stale, expired, retired, foreign-cluster, or cross-agent proofs fail closed.
  Term, generation, token, and expiry must all match the durable record.
  Verification and the complete protected operation share one per-agent read
  barrier, while install and retirement take its exclusive side. A newer fence
  therefore waits for an admitted operation instead of crossing a
  verify-to-execute gap. Expiry is checked at admission and does not cancel or
  roll back a side effect admitted before the deadline. The typed SDK covers
  fenced lifecycle, turn, stream, cancellation, and tool calls. A fenced stream
  holds the same barrier for its complete lifetime; ordinary streams remain
  rejected after fence installation. Its cancellation registration is bound to
  the exact proof, so an old owner can drain its admitted stream even when a
  handoff writer is queued, but a delayed cancel cannot signal a later
  request-id reuse under a new fence.
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
| Membership authority loss | Enabled mode elects a replacement while a majority remains; a minority or isolated old leader rejects authority writes and linearizable reads; exact voter and transport-trust changes are restart-safe | Live administration plus externally qualified partition/latency behavior |
| Workload node loss | Calls to that node fail; another node must not recreate or resume its agents automatically; authority leases expire but workload state stays on the failed node | Durable replica/checkpoint and explicit recovery policy |
| Network partition | Only the authority majority can mutate membership/ownership. A destination admits only its exact installed term/generation/token/expiry and stops new admission at expiry; an already-admitted operation retains its guard through completion | Self-contained authority authentication at the destination plus external partition, delay, and clock qualification |
| Duplicate agent ownership | Reconciliation compares every node with the durable authority directory, returns a conflict, and publishes neither arbitrary copy | Quorum-backed repair procedure and replicated workload evidence |
| Stale route | In enabled mode a managed client receives a linearizable authority ownership read before each mutation, rejects released/expired/different ownership, propagates the committed authority term and same-owner renewal generation/expiry, and requires exact destination agreement before use; explicit reconciliation repairs exact same-owner evidence | Durable owner request identity and external partition qualification |
| Client retry before visible output | Authority mutations accept a caller-stable UUID and return the original retained successful quorum result for an exact retry; reusing that retained ID for a different command fails closed. Rejections are not retained and never count as success. Local workload APIs remain safe only where their contract documents idempotency | Durable request identity and deduplication at each workload owner |
| Retry after a side effect or partial model/tool output | Must not happen automatically; the result is terminal unless the operation contract proves idempotency | Side-effect journal and explicit at-most-once or at-least-once contract per operation |
| Clock skew | Join challenge and ownership expiry use authority time. Destination installation permits at most the five-minute lease horizon plus 30 seconds, rejects already-expired proofs, fails on rollback behind installation, and stops admission at the exact stored expiry | Supported-host clock discipline, alerting, and external skew/jump qualification |
| Authority restart | Each voter restores its log, snapshots, immutable genesis, membership, ownership, receipts, and audit; a quorum elects a leader and catches up a restarted node | Cross-host disaster-recovery procedure and external qualification |
| Workload restart | The same node database restores its agents and highest-token/retired destination tombstones; managed reconstruction recovers exact same-owner leases/fences and rejects ambiguous evidence | Checkpoint replication and quorum takeover publication |

Unknown outcomes are not successes. A timeout, broken connection, or authority
change must be surfaced as an explicit retryable or terminal error according to
whether replay can duplicate visible work.

## Production ownership invariant

The current destination-admission subset enforces the term/token/expiry portion
of this invariant. Migration and every external side-effect boundary must still
carry it before the complete invariant is production-qualified:

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

1. Bind forwarded commands to end-to-end delegated principals and destination
   installation to self-contained authority authentication instead of only the
   trusted system control path. Quorum-versioned voter and transport-trust
   changes are implemented.
2. Checkpointed drain/migration with rollback and side-effect classifications.
3. Cross-node IPC/delegation with end-to-end authorization and audit.
4. Cluster quota reservations and monotonic policy/package trust epochs.
5. Rolling upgrades, partition/clock-skew chaos qualification, and disaster
   recovery. Application-listener and Raft peer trust rotation now have bounded
   generation-fenced sequencing.

The unchecked criteria in issue #122 remain unchecked until their implementation
and exact-commit evidence exist. Documentation, a client-side route map, or a
passing single-node test is never accepted as substitute evidence.

## Implementation references

- Membership, identity, ownership leases, generations, and audit:
  `crates/kernel/src/cluster_control.rs`
- Durable OpenRaft storage-v2 log, replicated membership/ownership authority,
  operation receipts, and snapshots: `crates/kernel/src/cluster_consensus.rs`
- Strict operator configuration: `crates/kernel/src/config.rs`
- Bounded mTLS Raft peer RPCs, exact certificate/node binding,
  generation-fenced voter changes, daemon lifecycle, and quorum regressions:
  `crates/kernel/src/cluster_runtime.rs` and
  `crates/cli/src/bin/agent-server.rs`
- Durable cluster tables and single-process storage lease:
  `crates/kernel/src/context.rs` and `crates/kernel/src/storage.rs`
- Authenticated discovery, placement, and owner reconstruction:
  `crates/sdk/src/cluster.rs`
- Node admission and all wire mutation paths:
  `crates/kernel/src/syscall_server.rs`
- Local quotas and accounting: `crates/kernel/src/cgroups.rs`,
  `crates/kernel/src/rate_limit.rs`, and `crates/kernel/src/context.rs`
