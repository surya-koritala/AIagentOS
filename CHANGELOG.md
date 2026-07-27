# Changelog

All notable changes to this project will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/), and the
project uses [Semantic Versioning](https://semver.org/). While pre-1.0, a
**minor** bump (0.x.0) marks a shipped feature batch and a **patch** (0.x.y)
marks fixes. Every PR adds an entry under `## [Unreleased]`; cutting a release
moves it to a versioned, dated section. See [RELEASING.md](RELEASING.md).

## [Unreleased]

- Retained exact-commit deterministic fault evidence for #125. The extended
  security workflow now executes all seven public TCP/SDK resilience scenarios
  in release mode, rejects source/build/scenario/check mismatches, and uploads
  the fail-closed JSON report for 90 days. The artifact proves the controlled
  provider-outage, cancellation-storm, SQLite disk-full and writer-lock, and
  loopback network-partition fixtures; target-host/TLS/proxy/provider chaos is
  still a separate production gate. The fuzz job now reserves enough time for
  cold compilation plus both bounded two-minute wire fuzz cases.
- Completed the deterministic fault-injection matrix infrastructure for #125.
  The release resilience suite now drives real public TCP/SDK storage writes
  against a live SQLite page limit and a held writer lock, proving typed
  retryable failures, rollback, integrity, recovery, and restart persistence.
  A loopback provider transport drops real TCP connections, waits through the
  production circuit-breaker cooldown, and proves automatic reconnect plus
  complete turn/LLM/quota/wire drainage. The live rootless Linux sandbox test
  now emits and retains exact-commit JSON evidence for cancellation and
  crash-orphan cleanup. These deterministic and live-run artifacts still
  forbid a production claim; the target 24-hour run, exact-RC SLO evaluation,
  alert delivery, game day, and independent review remain open.
- Added cancellation-storm and target resource/leak qualification under #125.
  The public TCP/SDK resilience suite now cancels concurrent exact request IDs
  from separate control connections and proves active provider cancellation,
  request-registry cleanup, bounded settlement, control-plane recovery, and
  complete turn/LLM/quota/wire drainage. A separate strict 24-hour Linux soak
  profile retains RSS, task, descriptor, SQLite/WAL, operation, queue, permit,
  and connection samples; evaluates explicit post-warmup growth thresholds;
  and has a repository-owned manual workflow that rejects short, dirty,
  mismatched, unnamed, or failing artifacts. Smoke runs remain ineligible and
  the production claim remains false until the real run plus remaining fault,
  release-SLO, game-day, and independent-review gates are complete.
- Added the first deterministic resilience qualification suite under #125.
  Public TCP/SDK scenarios now prove explicit active-turn and waiting-turn
  bounds, stable overload rejection, slow-client connection admission and idle
  reaping, provider-outage classification, control-plane recovery, and complete
  turn/LLM/quota-permit drainage. `budgets.max_waiting_turns` makes the turn
  backlog an operator-controlled hard limit, while server-local bounded
  connection counters make rejection and recovery measurable. JSON artifacts
  bind source/configuration/results and explicitly forbid production claims;
  the long soak and remaining fault/game-day matrix stay open.
- Fixed file-backed kernel lease release across a concurrent Unix
  `fork`/`exec` window. Storage leases now share one process-local owner that
  explicitly unlocks when its final owner exits, so a briefly inherited file
  descriptor cannot keep an offline database fenced after shutdown. A
  deterministic inherited-descriptor regression and repeated parallel storage
  CLI coverage protect restart, restore, rekey, and portable-import paths.
- Added a strict schema-v1 capacity qualification harness under #125. Eight
  release-mode workload profiles exercise public idle health, concurrent agent
  admission, long prompts, tool-heavy calls, deterministic provider delay,
  authenticated tenant contention, signed package installation, and durable
  restart recovery. Reports bind the complete workload config to the exact Git
  source, dirty state, Rust build, host resources, pass/fail counts,
  throughput, and latency percentiles. Fixture and smoke artifacts explicitly
  forbid production capacity claims; target-deployment load, soak, fault, and
  independent qualification remain open.
- Added production observability contract v1 under #125. Every Prometheus
  family now has a machine-checked name, type, unit, and bounded label catalog;
  dispatched and streaming syscalls record fixed-subsystem outcomes and latency
  histograms while server-generated correlation IDs remain only in redacted
  structured spans. JSON logs include the wire→kernel→provider/tool/persistence
  span path, and checked-in release-candidate SLO targets, an importable
  Grafana dashboard, Prometheus alerts, and alert runbooks cover availability,
  timeout/latency, quota health, backup freshness, and queue saturation. The
  24-hour soak, chaos/fault/leak runs,
  alert-delivery validation, privacy export controls, game day, exact-RC
  report, and independent review remain open.
- Added independently retained exact backup recovery anchors under #123.
  `agentctl backup-anchor-create` fully verifies a signed plaintext or SQLCipher
  backup and publishes an owner-only, non-overwriting anchor outside the backup
  directory. Anchored verify/restore rejects another older-but-valid signed
  backup, and production disaster/corruption recovery now requires the exact
  anchor before destination mutation. Kernel and CLI regressions cover
  substitution, non-overwrite, co-location, encrypted restore, confirmation,
  and fresh-host configured recovery. Immutable remote custody, a monotonic
  newest-point policy, and measured recovery drills remain open.
- Added authenticated offline corruption recovery under #123.
  `agentctl backup-corruption-recover` refuses healthy databases, requires an
  independently trusted signed backup plus the operator-supplied expected
  installation UUID, acquires the normal storage lease, and preserves the
  corrupt database/WAL/SHM in an owner-only forensic quarantine. A durable
  secret-free journal resumes interrupted quarantine/publication; configured
  kernel boot and persisted-agent enforcement qualification must succeed
  before completion, while ordinary failures restore the original corrupt
  files and preserve the failed candidate. Plaintext, SQLCipher, wrong
  identity, healthy-destination, running-owner, exact-sidecar preservation,
  interruption-resume, qualification-rollback, and CLI regressions cover the
  recovery contract.
- Added versioned full-installation portability under #123. Confirmed offline
  `storage-portable-export`, `storage-portable-verify`, and
  `storage-portable-import` commands move every durable SQLite state class from
  plaintext or SQLCipher storage into an owner-only, integrity-checked
  plaintext transfer bundle, then atomically publish a fresh destination with
  optional re-encryption under a different key. Exact-format, schema,
  installation-identity, hash, symlink, unexpected-file, running-owner,
  tamper, no-overwrite, plaintext/encrypted round-trip, rekey, and CLI
  regressions fail closed without publishing partial destinations.
- Added authenticated usage and quota accounting under #123 with schema version
  3. Every usage row, quota aggregate, receipt, scope, refund tombstone, epoch
  floor, and migration fence contributes a keyed HMAC to one enforcement-state
  root. Persistent SQLite triggers update that root and append an authenticated
  mutation-chain entry in the same transaction as each accounting change;
  startup, backup qualification, and restore verification independently scan
  the protected rows and fail closed on mismatch. Regressions cover clean
  restart, offline usage/quota mutation, event-chain forgery and truncation,
  canonical-trigger enforcement, transaction rollback, migration, and
  two-handle quota contention. SQLCipher protects the database-resident
  integrity secret in production; plaintext development stores provide
  corruption detection rather than malicious-writer resistance.
- Added authenticated configured-host disaster recovery under #123.
  `agentctl backup-disaster-recover` now requires an independently retained
  public trust root and the exact destination `config.toml`, restores the
  matching signed/encrypted backup offline, boots the complete configured
  kernel, and proves every persisted agent was re-admitted to enforcement
  before discarding rollback state. Failed configured-kernel qualification
  removes a fresh destination or restores the previous database.
- Added atomic released-storage upgrade qualification under #123. One immediate
  transaction now covers schema DDL, backfills, reconciliation, quota fences,
  migration metadata, and final version publication, so a late failure rolls
  back the complete attempt. Reviewable digest-pinned fixtures reproduce
  representative databases from every published tag (`v0.1.0`, `v0.2.0`, and
  `v0.3.0`) and prove context, memory, FTS, usage-cost, tenant, and KV retention
  through upgrade and idempotent reopen. Version bumps must add the next
  fixture before release. Released public-trust fixtures remain open.
- Added journaled recovery for interrupted offline storage encryption under
  #123. `storage-encrypt` now durably records a secret-free migration identity
  before staging, and `agentctl storage-encrypt-recover ... --confirm-offline`
  authenticates every surviving file before completing encrypted publication
  or restoring plaintext. A separate-process exit regression covers the
  post-rename crash window, wrong keys prove non-mutation, and a deterministic
  `SQLITE_FULL` regression proves failed growth rolls back without losing
  committed data. Host-filesystem exhaustion, power-loss, arbitrary
  corruption repair, and broader disaster qualification remain open.
- Added SQLCipher whole-database encryption for #123. Operator-custodied
  256-bit key documents (created and validated as owner-only files on Unix) now
  protect SQLite pages, WAL state, and
  online backups without interpolating key bytes into SQL. Required production
  configuration fails closed for missing, unsafe, or wrong keys; manifests
  record only the non-secret key generation. `agentctl` now generates storage
  keys, performs confirmed offline plaintext export migration and key rotation,
  and verifies/restores encrypted and independently signed backups on a fresh
  host. The rootless Compose profile keeps keys in a separate volume and
  exposes encryption health through structured startup logs and a bounded
  Prometheus gauge. Restart, plaintext-page absence, wrong/missing/retired key,
  lease, migration, rotation, retention, signed recovery, CLI, and entrypoint
  regressions cover the slice. Remote immutable retention, key-vault/HSM
  integration, crash/power-loss qualification, and measured recovery drills
  remain open in #123.
- Added a versioned storage data inventory for #123. A schema-enforced catalog
  classifies every logical SQLite object plus supported file, ephemeral, and
  external boundary by owner, tenant key, sensitivity, retention, encryption,
  backup, and deletion policy. Trusted system operators can inspect the
  non-secret policy document through protocol v2, the typed SDK, or
  `agentctl data-inventory`; wire, authorization, schema, SDK, and CLI
  regressions prevent silent drift. The inventory explicitly exposes remaining
  encryption, external deletion, and remote-retention gaps rather than treating
  them as implemented.
- Added optional Ed25519 backup authenticity for #123. An owner-only
  operator-generated PKCS#8 key signs both scheduled and live operator backup
  manifests; verification and offline restore can require a matching,
  independently retained versioned public trust file. Configuration and the
  container entrypoint fail closed on incomplete or unsafe identities, status
  and Prometheus expose signing enablement without secret paths, and key
  generation never overwrites existing material. Tamper, wrong-key, unsigned,
  permissions, rotation/configuration, scheduled, SDK, CLI, restore, and
  container regressions cover the path. Remote immutable retention, encryption,
  automated recovery, and measured RPO/RTO remain open in #123.
- Added automatic verified local backups for #123. A fail-closed `[backup]`
  policy controls startup execution, interval, absolute backup root, and safe
  retention; blocking SQLite work runs off the async runtime and failures
  preserve prior backups while updating bounded health. A system-only protocol
  v2 status operation, typed SDK method, `agentctl backup-status`, structured
  logs, and stable Prometheus counters make maintenance observable. The
  rootless Compose profile uses a separate backup volume, and config,
  scheduler, retention/failure, authorization, SDK, CLI, entrypoint, metrics,
  and wire regressions cover the path. Remote replication, automated restore,
  encryption, and measured RPO/RTO remain open in #123.
- Added safe verified local-backup retention for #123. The kernel serializes
  retention with backup publication, bounds root scans, considers only verified
  backups from the current installation, always preserves a configured latest
  set, and expires only age-eligible backups. Unknown content, symlinks,
  corrupt/foreign backups, and future timestamps are reported but untouched;
  deletion never recursively removes arbitrary content. Protocol v2, the typed
  SDK, and `agentctl` support dry-run reports and explicitly confirmed
  enforcement, with kernel safety/concurrency and live SDK/CLI regressions.
  Scheduling, remote/object-store retention, encryption, and measured recovery
  qualification remain open in #123.
- Added the supported #123 hot-erasure workflow for agents, users, and tenants.
  The system-only wire operation requires explicit confirmation, closes and
  drains affected credential leases, disables supervised owners, quiesces
  turns and tool calls, removes kernel-owned live resources, and commits the
  classified SQLite deletion behind a global request barrier. The typed SDK
  requires an explicit proof-of-intent value and `agentctl` exposes confirmed
  commands for all three targets. Kernel concurrency/isolation tests plus live
  wire, SDK, CLI, schema, and golden-fixture regressions cover the workflow.
  Backup expiration, external-workspace/provider deletion, scheduled retention,
  encryption, and disaster qualification remain open in #123.
- Added the #123 storage-erasure foundation with schema version 2. Every logical
  durable table now has a test-enforced ownership/deletion classification.
  Agent, user, and tenant erasure runs in one immediate transaction, removes
  owned rows plus FTS/service/quota references, reconciles orphaned children,
  preserves explicitly shared accounting state, and publishes a durable
  non-identifying deletion receipt. Failure injection proves all-or-nothing
  rollback, file-backed restart tests prove erasure persistence, and a released
  v1 fixture proves the v2 migration.
- Added the supported #123 operator workflow for storage recovery. Trusted
  system operators can create WAL-consistent backups through the server and
  typed Rust SDK without blocking the async request runtime; `agentctl` can
  verify backup manifests locally and perform explicitly confirmed offline
  fresh-host or replacement restores. The public wire schema and versioned
  conformance fixtures include the new operation, tenant credentials remain
  denied, and SDK plus CLI end-to-end regressions cover publication,
  verification, restore, and reboot of the restored database.
- Added WAL-consistent online SQLite backup, bounded manifest parsing,
  SHA-256/size/schema/installation verification, and offline atomic restore.
  File-backed kernels now hold a process-lifetime storage lease so restore
  cannot race a running owner. Restore stages and verifies the snapshot,
  checkpoints and preserves an existing database, atomically publishes the
  replacement, and automatically rolls back any failed publication. Concurrent
  writer, WAL inclusion, tamper, future-schema, fresh-host, owner-exclusion, and
  injected rollback regressions cover the kernel primitive. System-authorized
  API/SDK/CLI workflows, retention, encryption, and complete deletion remain
  #123.
- Added the first #123 durability foundation: the kernel SQLite store now has
  an explicit AI Agent OS application ID, monotonic schema version, installation
  metadata, and migration ledger. Startup checks integrity and rejects corrupt,
  unrelated, or newer databases before schema mutation; legacy column upgrades
  no longer swallow arbitrary SQLite errors; cluster tables are part of the
  canonical schema; and version, retry, downgrade-fence, and ownership
  regressions document the forward-only compatibility contract. Consistent
  backup/restore, encryption, complete deletion, and disaster qualification
  remain open.
- Added a durable, system-scoped cluster membership authority. Nodes join by
  signing one-time expiring challenges that bind cluster ID, durable identity,
  endpoint, software version, and protocol window. Atomic membership snapshots,
  generation-fenced leave/revocation, compatibility and duplicate checks,
  durable audit, authenticated SDK discovery, mixed-revision rejection, and
  authority-restart recovery are covered by regressions. This is deliberately a
  single-authority model; quorum failover, ownership leases, live TLS
  certificate revocation, migration, and partition fencing remain #122.
- Added the first distributed-control-plane foundation: every kernel now owns
  a durable Ed25519 node identity and generation-fenced active/draining/
  quarantined state with placement metadata and audit history. `ClusterClient`
  proves node possession, rejects duplicate identities/agent ownership,
  rebuilds routing after restart, skips unavailable nodes, and supports
  fail-closed region/residency/model/sandbox/label placement. The server and
  SDK can require mutual TLS client certificates; multi-node restart, stale
  control, placement, duplicate identity, admission, and mTLS regressions are
  included. Membership consensus, ownership migration, global quotas, and
  policy/package convergence remain open in #122.
- Added pre-auth wire protocol discovery with exhaustive JSON Schemas, stable
  feature identifiers, v1/v2/MCP golden fixtures, typed SDK errors, agent
  enforcement introspection, credential-safe debug output, bounded
  syscall/MCP frames and connection admission, and transport/request deadlines
  as the first production-qualification slice of #121.
- Added ordered request-scoped message streams, bounded event backpressure,
  second-connection request-id cancellation, SDK stream callbacks, exact
  tenant/agent cancellation authorization, disconnect-safe cleanup, and
  incremental Azure OpenAI SSE deltas. Retry/failover now stops after visible
  partial output to prevent duplicate stream content.
- Added deterministic golden request sets for every v1 and v2 operation plus a
  dependency-free Python conformance runner that negotiates both supported
  versions and validates the fixtures against a live server's published schema.
- Added protocol-v2 `ping`/`pong`, standard MCP ping, published keepalive and
  graceful-close bounds, and SDK/raw/MCP half-close APIs that require bounded
  peer EOF after all replies are consumed.
- Reworked newline framing around one incremental bounded decoder and added
  deterministic fragmentation/shuffle properties plus a scheduled transport
  fuzz target that asserts retained and allocated frame memory never exceeds
  the selected limit.
- Added one shared authorization/behavior conformance suite for the Rust SDK,
  `agentctl`, TUI, desktop, raw JSON, and MCP clients. The TUI now supports
  protected servers, the desktop uses a random-secret authenticated loopback
  wire service instead of direct kernel calls, MCP distinguishes invalid
  credentials from missing authentication, and v2 preserves a stable
  `authorization_denied` code without exposing foreign-resource existence.

### Added

- **Provider and on-device qualification contract** — provider adapters expose
  conservative streaming/tool/parallel/cancellation/API-family capabilities;
  HTTP failures preserve typed auth, authorization, throttling, timeout,
  service, invalid-request, content-filter, retry-after, and bounded request-ID
  context through an 8 KiB redacted diagnostic path. The resilient connector
  adds exact half-open circuit probes, compatibility-checked regional and
  local-to-cloud failover, per-attempt timeouts/cancellation, actual
  provider/model attribution, and duplicate-retry ownership regressions.
  Nightly/manual protected workflows now emit explicit live `passed`, `failed`,
  or `not_run` evidence; real GGUF inference remains gated to a
  repository-owned model runner. (#120)
- **Versioned retrieval-memory lifecycle** — facts persist embedding
  model/version/dimension/content hashes, deterministically rebuild stale or
  corrupt vectors, and support agent-owned update, delete, and reindex over the
  wire and SDK. Concurrent writes, cross-agent mutations, tenant artifact
  purge, and large retrieval have regressions. A blocking exact-vs-LSH
  benchmark emits recall, agreement, latency, and memory evidence and enforces
  recall@10/top-1 floors. (#120)
- **Coordinated lifecycle and durable checkpoints** — public wire/SDK operations
  now coordinate pause, resume, stop, kill, cleanup, restart rehydration, and
  versioned generation checkpoints across kernel subsystems. Checkpoint
  retention, corruption/incompatibility handling, completion races, restart
  side-effect replay protection, multi-agent permit release, and lifecycle
  latency metrics are regression-qualified. (#112, #113)
- **Live operator and service APIs** — tenant-safe operator snapshots now expose
  barrier-consistent lifecycle/scheduler/sandbox/cgroup/namespace state,
  per-tenant gate-denial aggregates, bounded provider-health samples, and
  durable package-instance metadata to the SDK, `agentctl`, and TUI. Three
  range-validated live tunables use SQLite revision CAS, rollback, persistence,
  and durable applied/denied audit history. The kernel-owned service supervisor
  validates dependency order and coordinates startup, rollback, and shutdown.
  (#117, #118)
- **Durable init supervisor** — configured services now carry tenant, permission
  profile, namespace, sandbox, resource-budget, and secret-reference policy.
  Kernel health sweeps enforce readiness/startup deadlines, dependency failure
  propagation, bounded exponential restart with deterministic jitter/windows,
  exhaustion, and cleanup. SQLite ownership/history prevents duplicate agents
  after a process crash; validated rolling reload restarts the dependency
  closure atomically or restores the previous graph. SDK, `agentctl`, TUI, and
  Prometheus service views use that same kernel-owned state. (#118)
- **Context and admission controls** — bounded turn/LLM/tool admission,
  CFS-inspired fairness, exclusive shared-resource priority inheritance,
  starvation escape, and per-class/yield metrics. Context pressure now enforces
  per-agent/tenant/kernel active-prompt and durable-byte ceilings; retains and
  verifies lossless spill payloads; counts conversations, embeddings,
  snapshots, and checkpoints; and exposes content-free usage/rejection
  telemetry. Explicit backpressure replaces unsupported CPU-preemption,
  virtual-memory, and OOM-killer claims. (#114, #115)
- **Signed agent-package supply chain** — deterministic bounded `.agent`
  archives carry manifests, prompts/assets/policy files, dependencies, tool and
  capability declarations, and SPDX SBOM data. Ed25519 signatures are verified
  before payload parsing against durable tenant trust roots with rotation and
  revocation. The authenticated wire/SDK registry provides immutable publish,
  verified fetch/search, yanking, tenant-scoped deterministic semver lockfiles,
  policy admission, and atomic install/upgrade/rollback/remove. Registry,
  installed state, audit, rate limits, and hash-chained transparency records
  survive restart and backup/restore. Marketplace ratings/download counters are
  excluded from the v1 surface. (#119)
- **On-device GGUF adapter spike** — feature-gated Candle inference can run a
  provisioned quantized model locally; it remains experimental and is not part
  of the production support promise. (#104, #120)

### Security

- **Tenant authorization** — the wire server retains the authenticated
  principal and credential identity, centralizes ownership/RBAC checks, rejects
  unknown or inconsistent identities and roles, and durably closes sessions,
  API keys, users, and tenants before draining already-admitted requests.
  Overlapping credential/user/tenant revocations share that drain boundary;
  bounded waits return an explicit incomplete result without reopening access.
  Package-created agents are tenant-scoped, and denials are audited without
  leaking foreign resources. TCP and TLS regressions cover owner/foreign, role,
  unauthenticated, and revoked paths. Non-loopback listeners now fail closed
  unless authentication and TLS are configured. (#107, #108)
- **Fail-closed tools** — every registered tool needs a typed security contract;
  unknown tools/profiles, combined or unknown capabilities, optional/non-string
  resource extractors, provider/action contradictions, and mismatched or unknown
  provider operations are rejected. Shared package and MCP definitions now carry
  resource type + operation explicitly; custom command tools cannot disguise
  process execution as a read or become visible before their fixed command
  template is attached. Executor, syscall, MCP, and SDK-backed calls authorize
  and execute one immutable provider request, preventing a concurrent registry
  replacement from changing the side effect after admission. Approvals are
  contract-bound, exact-resource, local-operator, atomically consumed, and
  single-use. Policy validation now rejects unknown fields and missing terminal
  behavior and warns on permissive modes, non-deny defaults, overbroad action
  wildcards, uncovered tools, and shadowed rules. In-memory and low-level gate
  constructors default to enforcing MAC; explicit permissive construction is
  noisy and fully unconfined gates are test-only. Package-resolved tools have
  allow/deny parity regressions across executor, raw wire, MCP, and SDK paths.
  Final admission revalidates generation-bound agent, capability, cgroup,
  lifecycle, namespace, tool-tag, and MAC state, including change-and-restore
  races, before reserving the execution slot.
  (#103, #108)
- **Mandatory sandbox boundary** — resource calls require an unforgeable agent
  sandbox identity. Non-trusted filesystem I/O is capability-relative and
  regression-tested against traversal, symlink/rename races, quota escape, and
  cross-agent access. HTTP resolves and pins public-only answers with no proxy,
  redirects, credentials, or non-default ports. Digest-pinned Linux containers
  require a rootless daemon and enforce read-only root, no network, no
  capabilities, no-new-privileges, PID/CPU/memory/swap/file-descriptor/output
  limits, bounded temporary storage, and cancellation/crash cleanup. A protected
  live qualification job covers breakout prerequisites and teardown; raw wire,
  SDK, package, custom-tool, and MCP calls share the same fail-closed boundary.
  Native process mode, outbound host MCP, unisolated browser/peripheral access,
  and macOS/Windows process/container isolation are explicitly unsupported for
  untrusted agents. Independent penetration testing remains a v1 gate. (#111,
  #127)
- **Rust supply-chain repair** — upgraded Wasmtime, Tauri, `quick-xml`,
  `crossbeam-epoch`, Ratatui, and `memmap2`; replaced the discontinued direct
  PEM parser with rustls PKI parsing; and added valid AGPL SPDX metadata to
  every Rust package. RustSec reports zero vulnerabilities. Remaining
  unmaintained Tauri/Chromium transitive notices are exact, reviewed
  cargo-deny exceptions rather than vulnerability waivers. (#110)

### Governance

- **Evidence-backed capability registry** — one machine-readable inventory now
  records owners, maturity, runtime paths, tests, limitations, and tracking
  issues; CI rejects contradictory or unsupported public claims. (#106)
- **Secondary capability disposition** — disconnected and experimental modules
  are individually retained, deferred, or excluded from the v1 public runtime
  instead of being advertised as complete. (#128)
- **Issue-state governance** — completed milestone issues remain attached to
  their capability evidence while retained below-production work points to an
  open qualification issue; deliberate v1 exclusions are recorded explicitly.
- **Declarative policy authoring** — typed TOML policy documents, validation,
  linting, explain/dry-run, and explicit startup loading remain the supported MAC
  authoring path. (#102)

### Changed

- **Correct accounting and live metrics** — provider/model usage, retries,
  latency, provider/model-specific input, output, and cached-input pricing,
  backwards-compatible blended rates, hierarchical budgets/quotas, active
  execution, queue state, and node load now use runtime evidence with atomic
  concurrency tests. Invalid pricing and USD ceilings fail closed. Exact
  micro-dollar charges rehydrate global, tenant, and agent ceilings across
  restart without repricing history. Cumulative per-turn tool limits are now
  distinct from concurrent tool slots and persist across pause/resume. Existing
  TOML remains compatible; Rust callers with exhaustive `BudgetConfig` literals
  must add the detailed-pricing fields, `tenant_tokens_per_min`, and the
  per-turn/concurrent-tool fields, plus
  `max_output_tokens_per_request`, or use
  `..BudgetConfig::default()`.
  Existing but unreadable or malformed config files now stop startup; only a
  missing first-run config yields defaults. (#109)
- **Durable provider quota epochs** — RPM/TPM now use fixed UTC Unix-minute
  epochs with durable request receipts, restart recovery, monotonic clock-floor
  protection, pre-invocation cancellation refunds, conservative failed-attempt
  estimates, and original-admission-epoch usage reconciliation. Production
  SQLite quota commits require WAL, full synchronization, foreign-key
  enforcement, and a bounded busy timeout. Legacy non-empty databases are
  fenced for the unknowable remainder of their first upgraded epoch. (#109)
- **Atomic durable cgroup hierarchy** — every LLM attempt now reserves
  provider/global plus stable root → tenant → profile → agent token scopes in
  one SQLite transaction. The serialized prompt floor and a provider-enforced
  output allowance are reserved before I/O; successful calls reconcile every
  scope in the original epoch without replacing provider-reported invoice
  usage used for billing. Hosted adapters make one outbound request per
  connector attempt. The executor owns bounded retry rounds while the resilient
  connector owns one attempt per compatible failover provider inside a round,
  avoiding stacked retry loops. Each round durably reserves its worst-case
  failover count before I/O and reconciles exact attempts afterward, so RPM
  receipts still map one-to-one to provider attempts. Restart, cancellation,
  overflow, sibling
  races, tenant/per-agent isolation, low-level membership reassignment races,
  and managed-hierarchy immutability are covered.
  Exhausted execution-path quotas now return retryable epoch-boundary
  backpressure immediately instead of occupying global turn slots while they
  wait, preserving progress for independently funded scopes.
  Agent creation now fails and rolls back every live subsystem if its durable
  registry commit fails, so a returned identity cannot disappear on restart.
  Gate-time tool payload bytes no longer masquerade as model usage; structured
  tool-call JSON/results are charged when they become provider input. The
  obsolete timer reset is gone. `tenant_tokens_per_min` independently
  configures tenant capacity. Deprecated `CgroupManager` token/reset methods
  and `cgroups::enforce_limits` remain source shims but are explicitly
  non-authoritative; their token checks fail closed for any bounded hierarchy,
  and durable admission must use the kernel provider path.
  `add_agent` now returns typed
  `CgroupError`, a permitted pre-1.0 minor-version Rust API break. (#109)
- **Wire protocol v2** — typed error categories and retry hints are served while
  retaining the released v1 compatibility fixture; SDK negotiation is automatic.
  The complete v1 compatibility/conformance commitment remains tracked by #121.
  (#116, #121)
- **Provider claims** — documentation now distinguishes mock-fixture evidence,
  explicit live `not_run` evidence, unsupported multimodal/discovery/tool/usage
  behavior, local-to-cloud routing policy, and the bounded CPU-only on-device
  path. No fixture result is described as live production qualification.
  (#120)

### Quality

- CI now treats formatting, Clippy, tests, capability claims, rustdoc/mdBook,
  dependency policy, Svelte warnings/audit/build, global coverage, and explicit
  critical-subsystem floors as blocking. Linux, macOS, and Windows run both
  kernel and desktop checks; scheduled Miri, sanitizer, and fuzz jobs preserve
  evidence. Release qualification reuses full CI and produces byte-reproducible
  archives, CycloneDX/SPDX SBOMs, checksums, Sigstore bundles, provenance, and a
  non-root container restart proof using durable application data. Toolchains,
  Actions, and Docker bases are pinned, with weekly dependency updates.
  Protected-branch and remote qualification evidence are required before this
  capability is promoted. (#110)
- Regression coverage expanded across authorization, sandbox escapes, lifecycle
  cleanup, checkpoints, scheduling, context pressure, accounting, persistence,
  services, packages, providers, wire compatibility, CLI/TUI state, and claim
  integrity. Local line coverage is 78.79% with a 60% CI floor.
- Filesystem, SQLite, and vision fixtures now use unique platform-native
  temporary paths, so the same regression suite runs on Windows as well as
  Linux and macOS. (#110)

## [0.3.0] - 2026-06-04

**Production-shell hardening + toward a stable API.** 0.2.0 made the kernel a
reachable, multi-tenant service; 0.3.0 hardens it for operation and takes the
first concrete step toward a 1.0 stability promise. Startup degrades gracefully
instead of panicking, the wire protocol is now explicitly versioned with a
negotiation handshake, and long-term memory gets a real approximate-nearest-
neighbor index behind its existing seam — all pure-Rust and offline, with the
governance wedge unchanged and still proven by the release gate.

### Memory & retrieval

- **Approximate-nearest-neighbor index** — a real, dependency-free ANN behind the
  existing `VectorIndex` seam: multi-table random-hyperplane LSH (`LshIndex`),
  deterministic via a fixed-seed PRNG, with a radius-1 probe and a full-scan
  safety net so recall degrades gracefully. The live memory-query path now ranks
  through the seam (`rank_topk`) — exact `BruteForceIndex` at small fact counts,
  `LshIndex` above a threshold so a large fact store bounds the work instead of
  scoring every vector — and caps results to a top-K so the caller stops dumping
  the whole store into the prompt. Stays pure-Rust and fully offline (#100).

### Wire protocol (toward 1.0)

- **Versioned wire protocol** — the `Syscall`/`SyscallReply` schema now carries an
  explicit `PROTOCOL_VERSION` (1), versioned independently of the crate release.
  A new optional `Hello { protocol_version }` handshake lets a client negotiate:
  the server replies with its `[MIN_PROTOCOL_VERSION, PROTOCOL_VERSION]` support
  window, and an out-of-range (or pre-versioning) server surfaces as a clear
  `SdkError::IncompatibleProtocol` rather than a confusing later failure. The SDK
  pins the version it was built against and adds `KernelClient::hello()`. `Hello`
  is allowed before authentication so a client can check compatibility before
  presenting credentials. Foundation for the 1.0 stability promise (#99).

### Reliability

- **Graceful startup degradation** — `agent-server` and the `agent` CLI no longer
  panic on operator errors (unwritable/locked data dir, corrupt DB, unreachable
  LLM provider). Kernel init, agent creation, provider connect, and one-shot/pipe
  runs now exit non-zero with a clear, actionable message instead of a panic
  backtrace. A malformed `config.toml` warns and falls back to defaults rather
  than being silently swallowed (#98).

### Observability

- **Production logging** — `agent-server` and the CLI install a `tracing`
  subscriber driven by `RUST_LOG` (default `info`), with `LOG_FORMAT=json` for
  ingestion; the kernel's existing `tracing` lines now actually emit (#96).
- **Prometheus metrics** — hand-rendered `text/plain; version=0.0.4` exposition
  (gate counters, agent counts, token/api totals, uptime) readable two ways: a
  `Metrics` syscall + `KernelClient::metrics()`, and an optional dependency-free
  HTTP `/metrics` endpoint started via `AGENT_SERVER_METRICS_ADDR` (#96).

## [0.2.0] - 2026-06-03

**Platform + Governed Execution.** Since 0.1.0 made the syscall gate
load-bearing, 0.2.0 turns the kernel into a real, reachable, multi-tenant
service: a JSON wire API over TCP/Unix/TLS, an embeddable Rust SDK and clients,
nine LLM providers with a hardened send-path, durable state across restarts,
first-class tenancy, and a one-command container. The governance wedge — agents
governed like Linux processes — is now proven un-bypassable and demonstrated
end-to-end. (64 commits since 0.1.0.)

### Kernel as a service (wire API)

- **Syscall server** — expose the kernel over a newline-delimited JSON protocol,
  generic over the transport (#41, #43, #47).
- **Transports** — TCP, **Unix-domain socket**, and **TLS** (rustls/ring), with
  an optional shared-secret `Authenticate` (#47, #84).
- **Syscall surface** — `AgentInfo` introspection (#44), `CallTool` (#43),
  per-agent **storage** (`StoragePut/Get/List/Delete`) (#71), **context
  snapshot/restore** (#78), and **`NodeInfo`** node-load (#80).

### SDK & clients

- **Embeddable Rust SDK** (`KernelClient`) over the syscall server (#46).
- **Agent patterns** — `ReActLoop` and `PlannerExecutor` templates (#69).
- **Distributed `ClusterClient`** — N nodes, `LeastLoaded` / `RoundRobin`
  placement (#80).
- **Terminal UI** — a ratatui TUI for observing and driving agents (#82).

### LLM providers & path

- **Six new adapters** — Groq, Deepseek (#45), Gemini, vLLM, HuggingFace (#51),
  bringing the total to **nine** providers.
- **Function-calling shim** for models without native tool support (#53).
- **Hardened send-path** — provider **failover**, bounded **retry/backoff**, and
  **rate-limiting under concurrent load** (atomic RPM/TPM reserve) (#90).

### Scheduling

- **CFS-ordered turn admission** — nice decides who runs under contention (#33).
- **LLM-request scheduling** — priority-ordered LLM-core admission (#52).
- **Mid-generation context switch** — pause/resume a turn at a boundary (#85).
- **Non-blocking create-time admission** (#29) and a **lost-wakeup fix** in the
  resource-access scheduler (#75).

### Memory & context

- **Memory manager** — embeddings + vector search (#67).
- **Pluggable embedding seam** — object-safe `Embedder` + `VectorIndex` traits
  with a stronger pure-Rust default (#89).
- **ContextPager** wired to bound the active context by tokens (#32).

### Security, governance & tenancy

- **Namespace differentiation** — isolate agent groups; group-scoped tools make
  tool-namespace isolation load-bearing (#22, #30).
- **MAC** — enforceable gate stage (#17), allow-and-log `Audit` decisions (#25),
  glob object matching on raw paths/URLs (#24).
- **Budget** — hard cumulative USD spend ceiling on the LLM path (#26).
- **Adversarial gate fuzz** — ~2500 proptest cases per run with an independent
  oracle, proving the 4-layer gate has no bypass (#87).
- **First-class multi-tenancy** — a tenant model atop namespaces/cgroups/auth;
  cross-tenant tool/IPC/state access is denied at the gate (#93).

### Persistence

- **Durable agent registry** — agents (and conversations/memory/KV/snapshots)
  survive a process restart; enforcement is re-armed on rehydrate (#92).

### IPC & multi-agent

- Agent-to-agent **messaging** (#18), **delegation** tools with orphan-on-reject
  (#19), **discovery** + address-by-name (#21), namespace-scoped discovery (#23),
  and delegation authorized by caller identity (#31).

### Packages, hub & MCP

- **Agent package format** + loader/runner (#49).
- **Shareable tool registry** (#72) and an **agent hub** — publish/fetch/share
  packages (#77).
- **MCP server** exposing kernel tools over JSON-RPC, gate-enforced (#68).

### Tools

- Extensible tool **registry** + git/browse/edit tools (#16).

### Benchmarks, demos & distribution

- **Agent-task benchmark** + eval harness with a CI smoke test (#73).
- **Governed-execution scenario** + runnable keyless demo (#88); keyless
  `os-demo` + Docker/Ollama test harness (#13).
- **Container image + one-command bootstrap** — ships `agent-server`, keyless by
  default, with a real-syscall healthcheck and `scripts/quickstart.sh` (#94).

### CLI

- Enforce the syscall gate on CLI tool calls (#12).

## [0.1.0] - 2026-05-09

First tagged release. Marks the point at which the Linux-mapped subsystems
became *load-bearing* — capability checks, MAC policy, cgroup quotas, and
namespace isolation now enforce on every tool call and IPC send instead of
existing as scaffolding next to the runtime path.

### Added — OS contract

- **`SyscallGate`** chokepoint (`crates/kernel/src/syscall_gate.rs`). Every
  tool call from `AgentExecutor::execute_tool` runs:
  `namespace visibility → capability → MAC → cgroup quota` before reaching
  the resource broker. Denials surface to the LLM as structured tool errors
  so the model can recover without the kernel trusting it.
- **Capabilities** — 9 capability types; `http_get` requires
  `CAP_NET_ACCESS`, `write_file` requires `CAP_FILE_WRITE`, etc. Profiles
  (`read-only`/`standard`/`elevated`/`full-access`) translate to capability
  sets.
- **MAC policy enforcement** — `MacEngine` consulted on every tool call;
  `MacDeny` returned to the LLM.
- **Cgroup quotas reject** — `tokens_per_min` over-budget calls return
  `CgroupQuota` (≈ EAGAIN); the minute-counter resets via background timer.
- **Namespace-scoped tools** — `register_tool_namespace(name, ns)` plus
  per-agent `set_agent_namespaces` produces `NotInNamespace` (≈ ENOENT)
  for foreign tools. Check runs first so MAC information cannot leak.
- **Namespace-scoped IPC** — `IpcManager.send/publish` consults a
  `NamespaceVisibility` checker; cross-namespace sends look like
  `AgentNotFound`.
- **Scheduler observability** — every `send_message` accounts tokens against
  CFS vruntime; `set_nice` and `next_runnable_agent` make fairness queryable.

### Added — orchestration

- **Unified `AgentKernelImpl`** with `OsSubsystems` (CFS, namespaces, init,
  procfs, sysctl, service registry). The standalone `OsKernel` is removed.
- **`kernel::boot(config)`** as the documented top-level entry point;
  spawns `KernelRuntime` automatically. CLI and Tauri use this.
- **`KernelRuntime::start()`** — scheduler observer + cgroup minute reset
  timer running as background tasks driven by the unified kernel.
- **Bounded observability retention** (default 1000 entries/agent) plus
  `purge_agent` on shutdown so multi-hour runs don't leak.

### Added — distribution

- **Lean default build** — `chromiumoxide` (~50 MB) and `scraper` moved
  behind `browser` and `web` cargo features on the `resources` crate. CI
  exercises both lean (`cargo test`) and full (`--all-features`) modes.

### Added — quality

- `tests/src/os_enforcement.rs` — 8 e2e tests pinning every contract above.
- `cargo clippy --workspace --exclude tauri-app -- -D warnings` runs clean.
- CI (`cargo fmt --check` + `cargo test --workspace --exclude tauri-app`)
  green on `main`. Test count: 416 passing.
- `.gitattributes` enforces LF line endings to prevent CRLF drift on
  cross-platform contributions.

### Removed

- **`OsKernel`** — superseded by `AgentKernelImpl`. Functionality fully
  migrated; stress benchmark (`benchmarks/stress_test.rs`) now drives the
  unified kernel + `SyscallGate`.

### Documentation

- **`ROADMAP.md`** — 5-phase plan with exit criteria; tracks load-bearing
  status of each subsystem.
- **`CLAUDE.md`** — orientation for AI assistants working in the repo;
  documents the syscall-gate convention.
- **`README.md`** — honest "Live / Defined / Planned" status table
  replacing the prior all-✅ marketing.

## [Pre-audit baseline] - 2025-05-05

### Added

- **Core Kernel**
  - Agent lifecycle management (create, pause, resume, stop) with state machine validation
  - Priority-based scheduler (1-5, max 10 concurrent agents, deadlock detection)
  - SQLite-backed context persistence with auto-summarization
  - Long-term memory store with text-based retrieval
  - Permission system with 4 profiles (read-only, standard, elevated, full-access)
  - Sandbox isolation with path traversal prevention and network allowlists
  - Inter-agent communication (direct messaging, pub/sub, task delegation)
  - Observability engine (action logging, metrics, plan deviation detection)
  - WASM module system (Wasmtime-based, manifest validation, crash isolation)
  - System prerequisite validation (RAM, disk, internet)

- **Agent Execution**
  - Think→Act→Observe execution loop with tool calling
  - LLM retry with exponential backoff (3 attempts)
  - Tool failure recovery (errors sent back to LLM for self-correction)
  - Context window management (auto-summarize at 20+ messages)
  - Long-term memory integration (facts stored and queried across sessions)

- **LLM Adapters**
  - Azure OpenAI (with api-key auth, deployment URLs)
  - OpenAI (GPT-4, function calling)
  - Anthropic (Claude, tool_use content blocks)
  - Local (Ollama/llama.cpp via HTTP)

- **Built-in Tools**
  - `read_file` — Read file contents
  - `write_file` — Write/create files
  - `list_directory` — List directory contents
  - `http_get` — HTTP GET requests
  - `run_command` — Execute shell commands

- **Desktop Application**
  - Tauri 2 + Svelte frontend
  - Setup wizard (provider selection, API key entry)
  - Dashboard with agent cards and system metrics
  - Chat panel with tool call indicators
  - Configuration persistence (TOML)

- **Testing**
  - 160 tests (unit + property-based + integration)
  - 28 correctness properties validated via proptest
  - E2E pipeline tests with wiremock
  - Adapter-specific wiremock tests (OpenAI, Anthropic)
