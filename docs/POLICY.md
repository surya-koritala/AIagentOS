# Policy authoring

AI Agent OS governs what an agent may do through a Mandatory Access Control
(MAC) layer in the syscall gate — the same load-bearing chokepoint every tool
call passes through (see [ARCHITECTURE.md](ARCHITECTURE.md) and the syscall-gate
section of the project [CLAUDE.md](../CLAUDE.md)). This document describes the
**declarative policy surface**: how an operator writes, validates, and dry-runs
that policy without editing Rust.

The Linux analogue is SELinux: you author a policy module, a tool validates it
(`checkpolicy`), and another explains decisions (`sesearch` / `audit2why`). Here
the policy is a TOML document, `agent policy validate` checks it, and `agent
policy explain` answers "would this be allowed, and which rule decides?".

## The document format

A policy is a TOML file:

```toml
# Top-level metadata
version     = 1            # document format version (currently always 1)
description = "..."        # free text, optional
enforcing   = true         # true = enforce; false = permissive (log only)
default     = "deny"       # decision when no rule matches: allow | deny | audit

# Rules are evaluated top to bottom; first match wins.
[[rule]]
name        = "readers-read"      # optional, shown by `explain`
description = "the reader profile may read anything"   # optional
subject     = "profile:read-only" # agent label, or *
action      = "read"              # action label, or *
object      = "*"                 # resource label, a path/URL glob, or *
decision    = "allow"             # allow | deny | audit

[[rule]]
name     = "no-etc-writes"
subject  = "*"
action   = "write"
object   = "/etc/**"              # glob over the raw resource path
decision = "deny"

[[rule]]
name     = "audit-exec"
subject  = "*"
action   = "execute"
object   = "*"
decision = "audit"                # allowed, but recorded in the audit log
```

### Fields

| Field | Meaning |
|---|---|
| `version` | Document format version. This build understands `1`. |
| `description` | Human note; ignored by the engine. |
| `enforcing` | `true` enforces decisions; `false` is permissive (everything is allowed, decisions are still computable for logging). |
| `default` | The decision when **no** rule matches. Declared explicitly so fallthrough is never a guess. |
| `[[rule]].subject` | The agent's security label. CLI/kernel agents are labelled `profile:<name>` where `<name>` is `read-only` / `standard` / `elevated` / `full-access`. `*` matches any subject. |
| `[[rule]].action` | The action label (`read`, `write`, `execute`, `net`, …), or `*`. |
| `[[rule]].object` | Either a resource **label** (matched exactly, like SELinux types) **or** a path/URL **glob** matched against the raw resource. `*` matches any object. |
| `[[rule]].decision` | `allow`, `deny`, or `audit`. A misspelling is a parse error, not a silent deny. |
| `[[rule]].name` / `.description` | Documentation only; `name` is surfaced by `explain`. |

### Object globs

A rule's `object` is matched against both the resource's assigned label and the
raw resource string, so either interpretation can fire:

- `?` — exactly one character, except the `/` separator.
- `*` — any run of characters within a single path segment (stops at `/`).
- `**` — any run of characters including `/` (spans path segments).

So `/etc/*` matches `/etc/passwd` but not `/etc/ssl/key`, while `/etc/**`
matches both. URL globs work the same way: `https://*.internal/**`.

### Evaluation model

Rules are scanned top to bottom; the **first** matching rule decides. If none
matches, `default` decides. Because matching is first-match-wins:

- Put specific `deny` rules **above** broad `allow` rules.
- A `subject = "*"`, `action = "*"`, `object = "*"` rule is a catch-all — any
  rule below it is unreachable (the linter flags this).
- A `default = "allow"` policy compiles to an explicit trailing catch-all; a
  `default = "deny"` policy relies on the engine's default-deny. Either way the
  declared default is what happens.

## Validating a policy

```bash
agent policy validate path/to/policy.toml
```

Prints whether the document is valid, its mode and default, and any **lint
warnings** (legal but probably-mistaken policies):

```
[OK] policy is valid - version 1, enforcing, default = Deny, 3 rule(s)
```

Lints include an enforcing policy with no rules and `default = deny` (which
denies *everything* for confined agents) and rules made unreachable by an
earlier catch-all. Lints are warnings, not failures — a linted policy still
loads. A genuinely malformed document (bad TOML, unknown `decision`/`default`,
unsupported `version`, empty subject/action/object) is a hard error with a
pointed message and a non-zero exit.

## Explaining a decision (dry-run)

```bash
agent policy explain path/to/policy.toml \
  --subject profile:read-only --action read --object /home/u/notes
```

```
query: subject=profile:read-only action=read object=/home/u/notes
=> ALLOW
  decided by rule #0 (readers-read)
```

`explain` evaluates the document the same way the live engine will — they share
one matching implementation, so the explanation can never disagree with what
gets enforced (a property test pins this). When no rule matches it tells you the
default decided:

```
=> DENY
  decided by default (no rule matched) - default = Deny
```

## Deploying a policy

Point the kernel at a policy file from its config (`config.toml`):

```toml
policy_file = "/etc/agent-os/policy.toml"
```

When `policy_file` is set it is the **source of truth** and supersedes the
inline `mac_enforcing` / `mac_rules` fields: the document's `enforcing` flag and
compiled rules are used. An unreadable or malformed policy file is a **hard
startup error** — the kernel refuses to boot with a clear message rather than
silently falling back to permissive mode.

With no `policy_file`, the inline `mac_enforcing` / `mac_rules` config fields
are used unchanged, so existing deployments keep working.
