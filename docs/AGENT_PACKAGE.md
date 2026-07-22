# Agent Package Format

An **agent package** is a declarative, loadable description of an agent: a TOML
manifest (`agent.toml`) the kernel can parse, validate, and bring up as a live
agent process. It is closer to a systemd unit file than a trusted apt artifact:
the current format is an **unsigned manifest**, not a signed archive.

The platform is **Rust-only with no dynamic code loading**, so the loadable
artifact is *data* — the manifest — not a shared object. The loader maps the
manifest onto the same `create_agent_full` admission path the CLI and syscall
server use, so a packaged agent is admitted, capability-gated, and scheduled
exactly like one created by hand. Agent *behavior* (custom tools, ReAct loops,
planner/executor patterns) is compiled Rust shipped on the SDK; the package
selects and configures it.

## Schema

| Field | Type | Required | Default | Meaning |
|-------|------|----------|---------|---------|
| `name` | string | yes | — | Human-readable package name (maximum 128 canonical ASCII characters). |
| `task` | string | yes | — | The agent's standing task / purpose. |
| `description` | string | no | `""` | What the agent is for. |
| `entry` | string | no | _none_ | Entry prompt. The runner drives one turn with it on load; omit for load-only. |
| `provider` | string | no | `"stub"` | LLM provider id to create the agent against (must be a registered provider to actually run). |
| `profile` | string | no | `"standard"` | One of `read-only`, `standard`, `elevated`, or `full-access`. Tenant callers cannot request the system-only `full-access` profile. |
| `priority` | integer | no | `3` | Scheduling priority, `1` (highest) .. `5` (lowest). |
| `nice` | integer | no | _none_ | CFS nice value, `-20` (most favored) .. `19`; applied after creation. |
| `tools` | array<string> | no | `[]` | Declared tool set. Every name must resolve in the live registry before creation; actual access remains enforced by the permission profile through the gate. |
| `memory` | array<string> | no | `[]` | Seed facts written to the agent's long-term memory on load. |

Validation is fail-closed: unknown TOML fields, non-canonical names, unknown
profiles, duplicate/invalid/unregistered tools, invalid scheduling values, and
oversized input are rejected. The manifest is capped at 1 MiB; each text field
at 64 KiB; tools at 256 declarations; and memory at 128 items, 64 KiB per item,
and 1 MiB total. If post-creation setup fails, the kernel transactionally
removes the partial agent, its live subsystem registrations, and its durable
rows.

## Example

See [`examples/packages/researcher/agent.toml`](../examples/packages/researcher/agent.toml):

```toml
name = "researcher"
description = "Reads sources and summarizes topics with citations."
task = "Research a topic and produce a cited summary."
entry = "Summarize the project's README and list its key components."
provider = "stub"
profile = "read-only"
priority = 2
nice = -5
tools = ["read_file", "http_get"]
memory = [
  "Prefer primary sources over summaries.",
  "Always cite where a claim came from.",
]
```

## Loading and running

**In-process** (`kernel::agent_package`):

```rust
use kernel::agent_package::{AgentManifest, load_package, run_package};

let manifest = AgentManifest::from_path("examples/packages/researcher/agent.toml")?;

// Load only: create the agent, apply nice, seed memory.
let handle = load_package(&kernel, &manifest).await?;

// Load + run: also drive the `entry` turn (requires a registered provider).
let (handle, output) = run_package(&kernel, &manifest).await?;
```

**Over the wire / from the Rust SDK** — load a packaged agent through the
syscall server:

```rust
let toml = std::fs::read_to_string("examples/packages/researcher/agent.toml")?;
let agent_id = client.load_package(toml).await?; // KernelClient
```

The `LoadPackage` syscall parses, validates, and loads the agent (creating it
and seeding memory); driving the `entry` prompt is left to the in-process
`run_package` runner so the wire path has no implicit LLM dependency.

`LoadPackage` requires an authenticated administrator. Authentication and the
manifest's permission profile are the current trust boundary. This API does
**not** establish artifact provenance: package archives, cryptographic
signatures, publisher trust roots, key rotation/revocation, durable registries,
dependency lockfiles/solving, reproducible builds, and atomic upgrade/rollback
are still roadmap work under issue #119. Do not treat a raw manifest as a
production software-supply-chain equivalent to apt/rpm.
