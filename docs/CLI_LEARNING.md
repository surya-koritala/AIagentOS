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

The default correction scope belongs to the local embedded CLI operator and
the default tenant. The terminal explicitly attaches it to its executor.
Another kernel agent or tenant receives no rules automatically, and a
foreign-tenant executor cannot acquire the local CLI scope. Rules reach the
model as quoted user-level preference data with a warning that they grant
no tool, permission, approval, or authority. Every resulting tool call still
passes through the existing syscall gate. Removing a rule removes its
previous prompt injection before the next turn.

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
