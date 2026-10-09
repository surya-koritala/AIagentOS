# Immutable cluster agent identity

An ownership lease grants a temporary placement revision. It does not allocate
an agent identity or prove that a destination created it. Managed creation uses
one immutable quorum reservation and a separate, exact destination receipt.

The reservation binds the cluster UUID, agent UUID, explicit `System` or
`Tenant { tenant_id }` scope, creator principal, stable creation operation,
creation argument digest, and initial node, authority term, generation,
fencing token and lease expiry. Missing legacy scope and the local default
tenant sentinel never select `System`. Ownership renewal or migration changes
current ownership while preserving every initial reservation field.

## Creation and publication

| Authority state | Evidence and permitted next steps |
|---|---|
| `Prepared` | A majority allocated identity and initial ownership in one log entry. The exact admitted destination may create the reserved ID. A receipt may advance it to `Created`; an abort leaves a permanent tombstone. Ordinary work and agent exposure remain denied. |
| `Created` | The majority retained the exact signed destination receipt. Publication requires that exact receipt digest and current destination ownership. An abort preserves the identity and receipt as a tombstone. Ordinary work remains denied. |
| `Published` | The majority published the identity. Destination exposure additionally requires the matching local journal and agent row. Current ownership, independent principal, tenant and credential admission remain necessary for each operation. |
| `Aborted` | Incomplete creation was terminated and current ownership released. The UUID, creator, scope, digest and any creation receipt remain retained. Late receipts, publication and new allocation of this UUID reject. |
| `Deleted` | A published identity was terminated and current ownership released. Its receipt and immutable identity remain retained after local data erasure. Ownership expiry, restart, migration and restore do not permit a replacement identity. |

Transitions use bounded, consecutive compare-and-set revisions. Operation UUIDs
are retained across indeterminate outcomes. A successful exact retry returns its
original committed response only after current independent authorization. A
different creator, scope, digest, placement or receipt fails closed. The current
forwarding node's audit actor is authenticated by its separate delegation; a
retry through another admitted origin does not change caller semantics.

The destination writes a retained preparation journal before creation. The
actual `agents` row and unsigned receipt payload commit in the same SQLite
transaction. The receipt binds the immutable reservation and its revision,
destination node and datastore installation, local receipt UUID, exact created
UUID and row digest, schema/reader/protocol versions and creation time. Node
signing follows that commit and is deterministic across receipt-loss retries.
A later majority publication and a matching destination publication marker
make the row visible. Unpublished rows are excluded from normal listings,
rehydration and runnable execution.

These are separate authority and destination database transactions. A committed
identity with safe reconciliation is not a distributed atomic destination
transaction. Interruption can leave an incomplete reservation or an unpublished
local row; those states remain explicit durable evidence.

## Reconciliation and restoration

Reconciliation compares the immutable authority record, current ownership,
exact signed destination receipt and retained local journal. A matching UUID or
tenant name alone never justifies adoption. Receipt inspection reports absence
only when there is no local agent row; a partial, foreign or mismatched row
returns a conflict. A valid receipt created before the initial lease expired can
be recovered under a newer same-destination ownership lease. An expired
reservation with no receipt cannot start a delayed creation.

`get_cluster_agent_identity` and `list_cluster_agent_identities` are majority
reads, scoped to the authenticated tenant when present. The destination receipt
read purpose, `get_destination_creation_receipt`, requires the signed online
destination contract and current creator, scope and credential admission.
Legacy unsigned dispatch always rejects it. Inspection of a `Prepared` or
`Created` identity returns evidence without publishing the agent.

Identity rows and destination journals remain bounded retained state. Abort and
delete tombstones survive local agent/tenant erasure. Database backups retain
the immutable reservation, exact receipt and journal; authority snapshots
validate independent signed history and cannot replace already committed
identity evidence. Restoring an older destination image must catch up with the
current online authority before exposure. An offline image or a UUID-matching
legacy row cannot prove current publication or authorization.

## Verification boundary

The `Immutable quorum agent identity` workflow checks the exact source in
GitHub CI. Its fixtures cover deterministic transition and receipt conflicts,
actual destination SQLite process exits, current principal revocation, lease
expiry, real mutual-TLS majority allocation and duplicate origins, leader loss
between receipt and publication, retained ownership migration evidence,
minority refusal, and database backup/restore with a later tombstone snapshot.
These fixtures are controlled CI evidence, not independent multi-host
qualification.

Full managed creation, receipt-loss reconciliation and ordinary destination
admission also require the served signed contract in
[#432](https://github.com/surya-koritala/AIagentOS/issues/432). Its discovery must
continue to report admission unsupported until the actual signed dispatcher,
current credential lease and these immutable identity checks are integrated and
verified. This allocation/storage layer alone does not close
[#434](https://github.com/surya-koritala/AIagentOS/issues/434),
[#122](https://github.com/surya-koritala/AIagentOS/issues/122), or the independent
fault qualification in #315/#316.
