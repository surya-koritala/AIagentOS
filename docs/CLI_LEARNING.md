# Terminal corrections and planning

The embedded `agent` terminal uses the kernel's ordinary governed executor.
`/help` enumerates all accepted slash commands, including `/exit`, `/plan`,
`/learn`, and `/unlearn`. The same commands work with `agent -c "/learn"`.

Use `/learn a b` to persist a correction whose one-word trigger is `a` and
whose correction text is `b`. `/learn` lists the current local operator's
rules and their UUIDs, operator identity, and creation times. `/unlearn UUID`
removes the rule. Both changes survive an ordinary quit and restart of
`agent`; no conversation flag is required. A missing rule or failed write
produces an error, never a success acknowledgment.
The existing platform configuration location remains the default. Optional
`agent --config PATH` selects a particular private configuration file; a
missing explicit file is an error before the kernel creates durable state.
Both paths require a current-owner-only regular file and reject symlinks or
Windows reparse objects. `agent --help` reports the native default location
without opening configuration or creating kernel state.
An uncertain durability failure fences further rule use until the process
reopens the store, so a failed acknowledgment cannot cause a later overwrite
from stale in-memory state.

Rules live in `rules.json` beside `agent_os.db` under `config.data_dir`.
The file is restricted to the current filesystem operator and replaced
atomically using the same private-file writer as configuration. Unix uses
owner-only mode `0600`; Windows uses the protected current-user DACL. A
store-wide process lock prevents concurrent writers from losing updates.
It uses the standard library's [exclusive file lock](https://doc.rust-lang.org/std/fs/struct.File.html#method.try_lock), held for the store's lifetime.
The operator identity is derived from the effective Unix UID or the Windows
TokenUser SID, rather than caller-supplied environment names.

The same private file holds at most 128 conversation ownership bindings,
registered only after the local executor saves its own conversation. Each
binding records only the conversation UUID, original agent UUID, default
tenant, and registration time. `agent --conversation UUID` selects that
original owner after kernel rehydration; it creates no replacement agent
and copies no permissions, approvals, credentials, or foreign messages.
The kernel rechecks private registration, SQL ownership, tenant, running
lifecycle, and current gate/cgroup admission before loading history. The
current CLI provider/profile must still match the restored owner's
configuration. Missing, erased, unregistered, foreign, terminal, or stale
bindings fail closed. An unfinished durable checkpoint requires the
existing checkpoint-resume route instead of discarding its pending work.
Conversation IDs from before this private registry existed are unregistered
and are rejected; they are never adopted automatically.

The `file/local-cli-corrections` data inventory entry includes the rules,
provenance, and registry. This file is plaintext under owner-only access and
is excluded from database backups and SQLCipher database encryption. The
local operator must protect and recover it separately. Retiring the file
clears corrections and local resume bindings; it does not erase SQLite
history. `/unlearn` removes correction text while preserving ownership
bindings. Erasing an agent's database state leaves an unusable stale ID in
the private registry, which cannot resurrect the erased agent.

The default correction scope belongs to the local embedded CLI operator and
the default tenant. The terminal explicitly attaches it to its executor.
Another kernel agent or tenant receives no rules automatically, and a
foreign-tenant executor cannot acquire the local CLI scope. Rules reach the
model as quoted user-level preference data with a warning that they grant
no tool, permission, approval, or authority. Every resulting tool call still
passes through the existing syscall gate. Removing a rule removes its
previous prompt injection before the next turn.
An explicit authorized conversation-history clone shares already-saved
user-level conversation data, including quoted prior corrections. Its exact
COW prefix remains intact. The child receives no live rule store, local CLI
binding, resume registry, approval, or credential; current or subsequently
added local rules are not automatically injected into it. Unrelated and
foreign-tenant agents cannot acquire the store or clone a foreign source.

Triggers contain 1–256 UTF-8 bytes and corrections 1–2048 bytes, without
control characters. A store holds at most 32 rules and its serialized file
is limited to 256 KiB. Exceeding a bound is an error. Corrupt, oversized,
insecure, incompatible, or foreign-operator files fail startup visibly;
they are never silently replaced with empty rules. These controls contain
input size and authority; they do not promise that a model follows a
correction or resists every semantic prompt attack.

`/plan refactor the parser` asks the connected provider for numbered steps
and prints the parsed descriptions and risk labels. Generation enters the
same turn admission, provider quotas, configured context/output limits,
timeout, retry, cancellation, and usage accounting as ordinary messages.
Task text is limited to 8 KiB, response text to 32 KiB, and plans to ten
steps of at most 1024 bytes each. A malformed plan is a visible error;
consumed provider usage is recorded even if parsing fails. Provider tool
calls in a plan response are rejected, and the terminal states:
`Plan execution is not wired. No plan steps were executed.` Risk labels are
model suggestions and string classification, not grants or approvals.

GitHub CI exercises the shipped binary through add/list/remove and process
restart, checks actual constructed kernel requests and rule isolation,
denies a poisoned correction's attempted write, verifies plan bounds and
quota denial before provider I/O, and drains cancellation. Providers in
these checks are deterministic local fixtures. Live model qualification
still requires explicit model/budget approval and secret-backed CI.
