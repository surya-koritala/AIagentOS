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

All payloads, references and search indexes remain in the kernel's single
SQLite store. Configured SQLCipher encryption, verified database backups and
transaction recovery cover them together. Database schema 8 requires a reader
that understands branch tails; older binaries must not open it.

This is the storage and execution foundation for
[#393](https://github.com/surya-koritala/AIagentOS/issues/393). The in-process
`fork_conversation` operation requires callers to serialize the parent against
execution and teardown. It does not create an agent or transfer a sandbox,
permissions, handles, approvals, credentials or live work. The public
`CloneAgent` lifecycle transaction, SDK/CLI, idempotent recovery, eligibility
rules, spill ownership and performance measurements remain part of #393.
