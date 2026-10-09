# Online quorum destination admission

This is the destination contract required by #432, coordinated with immutable
agent reservations in #434. The current branch implements the signature and
request-binding primitives. Configuration, dispatch, protocol discovery,
reservation persistence, clients and fault qualification remain in progress.
The feature is not yet advertised by `hello` and is not production-qualified.

## Mode and trust

The selected mode is `online_quorum_v1`. Enabled quorum installations must
explicitly configure `cluster_raft.destination_authority_mode`; missing and
unknown modes fail closed. Destinations must discover and verify the same mode
before a client supplies credentials or a signed mutation. An incompatible
destination cannot fall back to designated single-node authority.

The committed installation contract must retain the cluster identity and
required mode across restart and restore. Removing the configuration or disabling
quorum must not erase that requirement or permit legacy fence installation.
Mixed versions that cannot preserve the contract refuse managed work before
creation, mutation or receipt lookup. The disabled single-node compatibility
path does not satisfy this contract.

Each newly admitted destination mutation needs an independently signed caller
request and a fresh linearizable quorum view. mTLS identifies the transport peer;
node credentials and the trusted-system label do not replace the caller proof.
Current replicated principal enrollment, command class, generation, expiry and
revocation are checked before new effects or historical receipt replay.

## Exact binding

The signature binds the following fields:

| Field | Verification source |
| --- | --- |
| Mode and cluster UUID | Committed installation contract and current quorum genesis |
| Agent UUID, tenant and creator | Immutable committed reservation; exact local identity after creation |
| Principal UUID and generation | Current replicated public-key registry and authenticated tenant |
| Owner node UUID | Current ownership revision and the destination's durable identity |
| Authority term, generation and fencing token | Exact active quorum ownership revision |
| Lease expiration | Exact revision plus retained local expiry/clock checks |
| Operation UUID | Stable caller operation; conflict checks precede effects |
| Mutation digest | Canonical JSON derived from the actual request, including tool arguments |
| Proof issuance and expiration | At most 30 seconds, never beyond the lease |

Object key order cannot change the mutation digest. Mutation type, nested target,
tool arguments, creation identity or ownership fields cannot be substituted.
Unknown proof versions and fields are rejected. The caller retains its signing
key; neither the runtime nor the SDK owns that private key.

Tenant identity is explicit. Ordinary tenants use their canonical UUID. The
reserved `default` scope identifies system agents and requires an operator key
and an explicit immutable quorum binding. An absent legacy scope is unknown,
not evidence of system ownership. Tenant credentials cannot create or use a
foreign or system identity, even with another caller's proof.

## Admission, handoff and failure

A destination verifies current authority after acquiring its existing shared
mutation barrier. Install and retire use the matching exclusive barrier and
retain permanent retirement tombstones. Renewal, transfer, principal revocation
or removal rejects new admission under the previous revision. An already
admitted operation retains its exact owner and guard through completion; handoff
waits for that work rather than changing its identity underneath it.

When quorum confirmation fails, new installation, retirement, creation and
mutation return retryable unavailability before local effects. A local applied
projection cannot substitute for the fresh admission view. No cached lease is
extended because the quorum is unavailable, the clock moved backward, or a retry
arrived. Expired, future, retired, conflicting and wrong-cluster evidence fails
closed. Request timeout and lease limits remain unchanged.

Cancellation of already admitted work must remain available under quorum loss
without granting another operation. It is bound to the original admitted caller,
agent, request ID and captured ownership revision. It cannot signal a later
request that reused an ID. Independent credential revocation and expiry rules
must be explicit in the active-request registration and cancellation verifier.

Prepare, destination create, receipt and publication are separate durable
boundaries. A committed reservation is not an atomic cross-database transaction.
Unknown outcomes remain pending for exact reconciliation; retries cannot adopt
foreign rows, reuse deleted identities or replay completed effects. Current
authorization never derives from a saved success reply.

## Required proof

GitHub CI must cover the actual public SDK and wire path with three mTLS nodes,
independent operator and tenant keys, current and retired ownership, signature
and tenant negatives, exact retries, peer partitions, expired leases, clock
rollback, restart, authority failover and credential rotation. Creation and
publication cutpoints must retain one immutable identity and no unauthorized
admission. Each artifact records its source, mode, boundaries and actual result.

The current primitive tests and any pending preflight do not establish those
end-to-end guarantees. Multi-host, clock and disaster qualification remains
required by #315/#316; release and independent security qualification remain open.
