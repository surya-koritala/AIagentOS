# Durable execution history

The kernel restores the latest conversation owned by an agent before creating
its next provider session. A corrupt private payload or shared prefix fails
closed. Restoring history preserves completed assistant/tool messages; it does
not replay those messages as fresh effects or copy historical provider charges.
New work uses the ordinary provider admission, accounting and tool gate.

The context store can branch an owned conversation over immutable prefixes.
Each conversation owns a reference and a private tail. The first fork promotes
its saved tail inside one SQLite transaction; later forks with no new writes
reuse the prefix. Appends store only the branch's new tail. Rewriting or
summarizing a history detaches that branch from its old prefix. Other branches
continue to read the original immutable history.

Prefixes use a versioned representation with payload and metadata digests.
Chains are bounded to 64 levels and a shared history to 64 MiB. Legacy payloads
are canonicalized once during promotion. Provider execution materializes its
resolved conversation when needed; this storage contract does not promise
shared provider memory or zero-copy inference.

Referenced context spills are promoted into immutable, snapshot-owned payloads
inside the same transaction. Spill dependencies preserve page-in through later
compaction; an unrelated parent spill is not inherited. Payloads and dependency
links are checked for integrity, and inherited keys cannot be overwritten.
Dependency depth is bounded to 64 and the graph to 1,024 nodes. Missing, expired,
corrupt or conflicting references fail cloning rather than losing detail.

`StorageGet` resolves a spill only through the calling agent's reachable
snapshot references. Shared spills remain available while a branch depends on
them, including after parent erasure. Garbage collection removes their payloads
and links when the last snapshot dependency disappears. Context-pressure views
include these retained spills, and context quotas charge their logical bytes
to each referencing conversation branch.

Agent, tenant and global context quotas charge each branch's entire logical
history, including shared prefixes. Sharing reduces retained payload copies;
it does not provide free logical context allowance. Quota admission, reference
publication and source-tail promotion are one write transaction. Failed forks
leave no new conversations, prefixes or references.

Search indexes retain the shared prefix once and resolve results to the owning
conversation branches. Deleting a conversation or agent drops its references.
Garbage collection removes a prefix and its index only after its last reachable
branch disappears. A same-tenant child can retain a shared history after parent
erasure; this retained ownership is reported in the deletion receipt. Tenant
erasure removes every branch and shared prefix owned by that tenant.
A child's creation metadata also retains its parent UUID as child-owned lineage.
Parent erasure preserves that lineage; child or tenant erasure removes it.

All payloads, references and search indexes remain in the kernel's single
SQLite store. Configured SQLCipher encryption, verified database backups and
transaction recovery cover them together. Database schema 11 requires a reader
that understands branch tails, durable clone security, binary fact embeddings
and native provider replay state;
older binaries must not open it. Cloning was introduced in schema 9.

## Public agent cloning

`CloneAgent`, `KernelClient::clone_agent`, and
`agentctl clone PARENT_ID CHILD_UUID NAME [CAPABILITY_DROP_CSV]` create a new
Running agent from an idle Running or Paused parent. An active or queued provider
turn, live tool binding, retained generation checkpoint, transient namespace
membership, or moved cgroup is incompatible. A checkpoint from another provider
or model is also rejected. A parent with no conversation produces a child with
no snapshot; its first turn starts normally. Provider/model selection and task
configuration stay the same.

The caller supplies the child UUID. Repeating the same parent, child, name and
capability-removal request explicitly reconciles the original result without
creating a second child or reviving a stopped child. Another creation using
that UUID fails. The SDK never automatically replays a clone after an uncertain
transport result. A deleted child identity is absent; reconciliation after
explicit deletion is a new creation, so callers must use a new UUID when they
intend a distinct branch.

A child retains its parent's tenant, named namespace group, actual permission
profile, effective capabilities, MAC label and private cgroup limits. Named
capabilities may only be removed. The parent policy is held stable during the
publication transaction. The child gets a new session identity, private cgroup,
empty managed workspace and mailbox. No VFS handles are inherited: a child must
open fresh descriptors through the ordinary gate. Approvals, credentials,
agent-private facts/KV, live provider/tool execution, and external side effects
do not transfer. Both branches use normal provider billing for actual new work.

Creation first reserves a durable pending identity under the node's agent quota.
Runtime registration starts with tool admission closed and an Initializing
registry state. One SQLite transaction publishes the child context, immutable
snapshot references, logical context quota charge, sandbox configuration and
Running identity. Cancellation before publication removes staged resources;
boot purges interrupted pending identities before admitting any agents and
reconciles orphan managed workspaces. A committed child restores its attenuated
security before reopening admission. Parent teardown and cloning serialize
through the lifecycle lock; public erasure and both destination ownership fences
remain held through the operation.

For fenced destinations, `KernelClient::clone_agent_fenced` accepts the exact
parent proof and an authority-reserved child identity with its own proof.
Stale, missing or mismatched ownership proofs fail before creation.

The in-process `fork_conversation` storage primitive remains available to kernel
callers that already serialize the parent against execution and teardown. The
public lifecycle path supplies those locks and durable reconciliation for
[#393](https://github.com/surya-koritala/AIagentOS/issues/393).

Latency, allocated database growth and sampled RSS are compared with eager
history copy in the retained [fixture measurement record](
../benchmarks/cloning/2026-10-08-macos-arm64/README.md). First promotion has a
visible cost; later clones reuse the shared prefix. The record reports actual
samples and does not imply a production performance or provider-memory guarantee.
