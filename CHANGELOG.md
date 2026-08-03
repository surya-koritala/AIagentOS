# Changelog

All notable changes to this project will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/), and the
project uses [Semantic Versioning](https://semver.org/). While pre-1.0, a
**minor** bump (0.x.0) marks a shipped feature batch and a **patch** (0.x.y)
marks fixes. Every PR adds an entry under `## [Unreleased]`; cutting a release
moves it to a versioned, dated section. See [RELEASING.md](RELEASING.md).

## [Unreleased]

- Cut the build footprint, which had no bound at all. The workspace defined no
  `[profile.*]` anywhere, so every build used Cargo's default `debug = true` —
  full DWARF for this crate *and* all ~200 dependencies, inherited by
  `[profile.test]` — across ~47 separately linked units each statically
  embedding SQLCipher and a vendored OpenSSL. A development session reached a
  **533 GB** `target/` directory and filled a 926 GB disk. Dependencies now build
  with no debug info and workspace crates with line tables only, measured at
  **38.7% smaller** (1.93 GiB to 1.18 GiB for one lib build; larger for the
  linked test binaries that dominate). Panics and `RUST_BACKTRACE` still give
  exact file:line for workspace code. `split-debuginfo` and `strip` are
  deliberately not set — on macOS `packed` would build a `.dSYM` per executable,
  and `strip` destroys backtraces. `cargo llvm-cov` is unaffected, so the
  coverage floor and per-subsystem floors are unchanged.
- Stopped the GitHub Actions cache thrashing. The repository was holding 19
  caches totalling 13 GiB against GitHub's 10 GiB per-repository ceiling, so
  entries were evicted continuously and most jobs restored nothing. Every pull
  request also minted a fresh ~1 GB key per job and evicted `main`'s warm set.
  `ci.yml` now restores on every run but saves only on `main`, and the sixteen
  `rust-cache` steps in scheduled, manual, and tag-triggered workflows are
  restore-only. `ci.yml` also sets `CARGO_INCREMENTAL: 0`, matching `release.yml`
  and `linux-cli-rc.yml` — incremental artifacts are never reused on an
  ephemeral runner and only inflate the cache entry.
- Removed `tokio-tungstenite`, which had zero references in any source file.
- Added `target-a/` and `target-repro/` to `.gitignore` and `.dockerignore`. The
  reproducible-build check in `release.yml` and `linux-cli-rc.yml` creates both,
  and neither was ignored, so a contributor who ran it locally saw two
  multi-gigabyte untracked trees in `git status`.
- Documented the footprint and a prune cadence in CONTRIBUTING.md. Cargo never
  garbage-collects superseded artifact generations, and `cargo clean` does not
  reach `fuzz/target` — that retention, not per-set size, is what turns a large
  `target/` into a full disk.
- Gated the Wasm module system behind an off-by-default `wasm` feature on
  `kernel`, so no shipped binary links wasmtime or Cranelift. `WasmModuleSystem`
  has no production caller and the module is already deferred from v1, yet
  wasmtime was an unconditional dependency: the default `kernel` dependency
  graph drops from 274 crates to 195 — 79 removed, including all of Cranelift.
  It also removes a dead-code dependency from the advisory surface;
  RUSTSEC-2026-0222 and -0223 were both against wasmtime.
  **Breaking for library consumers:** `kernel::modules::ResourceRequirements`
  moved to `kernel::models::ResourceRequirements` (it was the only thing forcing
  an ungated module to depend on the gated one), and `kernel::modules` is
  unavailable without `--features wasm`. The crate is not published, so no
  released artifact is affected. `ROADMAP.md` framed this as a follow-up
  requiring structural work; it was one four-field struct. CI now exercises the
  module system explicitly under the feature, since the default
  `cargo test --workspace` no longer compiles it.
  Relates #128.
- Made the capability registry honest about Windows. Owner-only permission
  enforcement, open-time symlink rejection, and directory-entry durability are
  implemented on Unix only — the helpers in `storage.rs`,
  `storage_encryption.rs`, and `remote_backup.rs` return `Ok(())` on Windows —
  and every regression proving them is `#[cfg(unix)]`, so the passing
  `windows-latest` leg was compiled-out behavior rather than Windows evidence.
  `durable-state`, `resource-providers`, and `distributed-control-plane` still
  declared Windows with no such caveat. Each now carries an explicit
  platform-scope limitation, `sandbox-isolation`'s one-sentence Unix aside is
  expanded to cover managed-workspace hardening, and the registry header now
  defines `platforms` as where a capability is built and run rather than a claim
  that every guarantee holds on each one. `docs/DURABILITY.md` gains a matching
  Platform scope section, and its claim that the storage key loader rejects a
  symlinked key file is corrected — that comes from `O_NOFOLLOW`, which Windows
  does not have. No behavior changed; the claims now match the code.
  Relates #122, #123, #124, and #127.
- Stopped a panic under the shared SQLite connection guard from permanently
  bricking the kernel. Every durable subsystem shares one `Mutex<Connection>`,
  and the panic is reachable on the live path because `query_memory` calls the
  pluggable `Arc<dyn Embedder>` while holding the guard. Sixty `lock().unwrap()`
  sites in `context.rs` panicked on a poisoned mutex and the remaining sites
  returned "mutex is poisoned" for the rest of the process lifetime. All of them
  now go through `SqliteContextManager::locked_conn`, which takes the inner
  guard and *clears* the poison flag, so the error-returning sites recover too;
  the eleven quota-path sites that fed `RateLimiter::poison` are included, which
  removes a permanent `healthy = false` latch. Recovery is sound because every
  write path uses an RAII transaction that rolls back while unwinding. A
  regression panics with an open transaction under the guard and proves the
  store stays queryable, the aborted write rolled back, and the flag cleared.
  Relates #123.
- Stopped the online backup pacing itself while holding the writer mutex.
  `run_to_completion` sleeps between steps, so a 64-page step size spent roughly
  eight seconds asleep on a 1 GiB database — with the single connection mutex
  held, which every Tokio worker blocks on synchronously. The pacing existed to
  yield to concurrent writers who were locked out by that same mutex, so it
  bought nothing. The copy now runs in one step; the pause remains only as
  backoff on the `Busy`/`Locked` retry path.
  Relates #123 and #125.
- Restored blocking CI and separated capability governance from build evidence.
  `operator-clients` is still below production-qualified but its tracking issue
  #126 was auto-closed by PR #292, so the ownership gate failed and, because it
  ran inside the `quality` job that `rust-platforms` and `desktop-platforms`
  depend on, silently skipped the entire macOS/Windows matrix. The capability
  now declares `qualification_issue = 127`, the gate moved to its own
  `capability-governance` job, the cross-platform matrix no longer depends on
  any other job, and the gate distinguishes a closed issue from an unresolved
  GitHub API call instead of treating both as a governance verdict. A
  capability-registry regression pins the independence.
  Relates #126 and #127.
- Cleared the `cargo deny` advisories gate by taking wasmtime 47.0.3, which
  carries the fixes for RUSTSEC-2026-0222 and RUSTSEC-2026-0223. The dependency
  is not reachable from any shipped binary — the Wasm module system has no
  production caller and is deferred from v1 — but the advisory gate is required
  and blocks every subsequent push.
- Made `agent` and `agentctl` answer `--help` before doing any work. `agent`
  previously initialized the kernel, created its data directory, and persisted a
  `cli-agent` row before failing on an unreachable provider, and `agentctl`
  opened a TCP connection and reported a transport error; both now print usage
  on stdout and exit zero, and reject an unrecognized option with a named
  diagnostic on stderr and exit 2. `agentctl` usage text is shared between the
  help and usage-error paths so they cannot drift. New regressions assert both
  binaries leave an isolated home completely empty.
  Relates #126.
- Stopped the Gemini adapter putting its API key in the request URL: the key now
  travels in `x-goog-api-key`. `reqwest::Error` renders the request URL into its
  `Display`, so a query-string credential reached transport error text, logs,
  and wire clients verbatim, bypassing the response-body redaction. The shared
  adapter `transport_error` now also strips the URL so no future adapter can
  reintroduce the leak. Gemini was the only adapter affected; the other eight
  already use `Authorization: Bearer`.
  Relates #120 and #124.
- Made the saved configuration file owner-only. It carries cleartext provider
  API keys and was written with the default umask while every other secret file
  in the tree is forced to 0600. The mode is applied at create time so a new key
  is never briefly world-readable, and reapplied on save so a permissive file
  from an earlier release is repaired.
  Relates #124 and #127.
- Bounded the `/metrics` listener with a five-second read timeout and a
  sixteen-connection limit. A client that connected and never sent pinned a task
  indefinitely, with no cap on how many could do so, on a listener that
  `AGENT_SERVER_ALLOW_INSECURE_REMOTE=1` can expose unauthenticated. The wire
  server already had both protections.
  Relates #125.
- Added the missing regression for destination-fence retirement rejecting a
  foreign owner node. Installation was already covered; retirement carries the
  same guard and now has the same proof, which is what keeps a locally asserted
  fence retirable when no replicated authority is configured.
  Relates #122.
- Added bounded system-audit views to the TUI and desktop through the public
  `KernelClient`. Both clients read node-control, cluster-membership, and
  application-listener certificate-rollout ledgers sequentially, update only
  the ledgers whose reads succeed, retain previous projections on failure,
  expose cluster-only history as unavailable on the single-node profile, and
  preserve trusted-system authorization. Live loopback and capability
  regressions cover positive reads, standalone partial state, and tenant-admin
  denial.
  Relates #126.

## [0.4.0-rc.1] - 2026-07-30

- Finalized the restricted candidate change ledger and made the exact-tag
  verifier reject any release candidate while notes remain under
  `Unreleased`. This prevents the signed archive version and published release
  notes from silently describing different source scopes. The tag workflow now
  also binds the exact annotated tag object through GitHub's API and requires
  GitHub to report its cryptographic signature as verified. The preliminary
  workflow still retains a signed candidate bundle only; protected Phase 1
  evidence and independent review remain mandatory before prerelease
  publication. Relates #120, #123, and #125.
- Added durable checkpoint list, selection, explicit resume, and exact deletion
  to the TUI through the authenticated public `KernelClient`. The projection is
  bound to the selected agent, rejects cross-agent entries, and is cleared when
  selection changes. Permanent deletion freezes the agent/checkpoint pair and
  requires the complete checkpoint ID; resumed output is UTF-8 bounded like
  streamed output. State-model tests and a live authenticated loopback
  regression create real checkpoints and exercise resume and delete. Relates
  #126.
- Made TUI agent turns responsive and exactly cancellable over the public wire
  boundary. Ordinary operator calls, the one active ordered stream, and
  cancellation now use three authenticated connections, so streaming cannot
  freeze refreshes or hold the connection needed to cancel itself. `C` freezes
  the request/agent pair, queues pre-start cancellation until server
  registration, and suppresses duplicate cancellation. A 256-entry projection
  queue and 64 KiB UTF-8 display limit bound terminal memory; omitted live
  events are counted while the authoritative terminal result remains
  deliverable. State-machine and authenticated loopback regressions cover
  stale updates, target binding, bounded Unicode output, responsive refresh,
  wrong-request refusal, and terminal cancellation. Relates #126.
- Added the grant-aware kernel boundary required by future peripheral
  providers. Capture, recording, playback, and print bindings now have fixed
  device/printer target schemas and still require sandbox execution plus an
  exact, single-use local human approval. A trusted in-process UI can inspect
  non-secret pending and active-use counts, revoke an unconsumed grant, cancel
  every active exact-match use, and rely on agent stop/kill to cancel device
  work. The sandbox accepts peripheral dispatch only after the syscall gate
  consumes the exact grant; remote wire, SDK, package, and MCP paths receive no
  grant authority. No hardware backend is registered or advertised yet, so
  peripheral support remains unavailable rather than falsely promoted.
  Relates #124.
- Replaced hand-built Phase 1 campaign files and manual bounded-report copying
  with a GitHub-hosted exact-tag assembly workflow. It authenticates every
  selected evidence run and human actor, downloads deterministic artifacts,
  derives the operator inventory, copies only the expected JSON reports,
  computes exact digests, and keyless-signs the canonical campaign. Review,
  promotion, and the final hosted publisher independently re-download and
  verify the campaign workflow attempt, repository, actors, complete artifact
  inventory, report bytes, and Sigstore identity. The identity-private campaign
  provenance is hash-bound into the decision and shipped as the fifth signed
  qualification report. This automates evidence assembly; it does not claim
  that the external provider, GGUF, storage, deletion, soak, SLO, game-day, or
  review runs exist. Relates #120, #123, #125, and #127.
- Replaced the self-declared Phase 1 reviewer identity with a protected,
  exact-tag review workflow. A fresh authenticated GitHub actor distinct from
  every campaign operator must create and keyless-sign the hash-bound review;
  promotion now verifies the exact review run, attempt, repository, workflow,
  event, actor, triggering actor, downloaded bytes, and Sigstore signature.
  The bounded identity-private review provenance is hash-bound into the
  promotion decision and shipped as the fourth qualification report. Reruns,
  forked metadata, actor substitution, unsigned reviews, and tampered artifacts
  fail closed. Relates #120, #123, and #125.
- Hardened restricted Phase 1 publication so copied campaign metadata cannot
  impersonate successful qualification. The protected gate now queries
  GitHub's exact workflow-run-attempt API for every retained report, requires
  the latest attempt to match the campaign's repository, workflow, commit,
  conclusion, and update time, downloads every exact named artifact, and
  compares its report bytes with the protected evidence digest. The bounded
  provenance result is hash-bound into the promotion decision, signed,
  attested, and shipped as the third qualification report. Missing, expired,
  ambiguous, rerun, forked, or tampered evidence fails closed. (#284)

- Prepared the first restricted Linux CLI candidate with every workspace,
  desktop, UI, and internal dependency version locked to `0.4.0-rc.1`. All four
  shipped binaries now provide side-effect-free `--version` and `-V` probes,
  and the exact-tag workflow rejects an archive whose binaries do not report
  the tagged version. The candidate remains ineligible for a production claim
  until its signed per-tag qualification report and the separate roadmap
  evidence are complete. (#281)
- Added a separately scoped `vX.Y.Z-rc.N` release path for the restricted
  Ubuntu 22.04 x86_64 CLI profile. It builds all four CLI/server/TUI binaries
  twice, rejects byte drift, creates a canonical traversal-safe archive and
  exact-binary SBOM, keyless-signs and attests the artifacts, and then verifies
  the final archive on a fresh hosted runner. The runtime gate requires the
  released v0.3.0 schema to upgrade under required SQLCipher encryption, verified
  TLS and shared-secret authentication, wrong/absent-auth rejection, governed
  agent creation, clean restart persistence, signed and independently anchored
  encrypted backup, tamper and missing-key rejection, and fresh-host recovery
  with enforcement re-armed. A strict bounded report retains the restricted
  scope and remaining external qualification gaps, is revalidated, checksummed,
  signed, attested, and published only as a prerelease. Relates #120, #123, and
  #125. (#280)
- Bound every external replicated-authority write to a 30-second Ed25519
  delegation from the originating application node. The signed,
  domain-separated proof covers the caller-stable operation UUID, a semantic
  command digest, the canonical system-node actor, issuance, and expiration.
  Both the originating node and current leader require the signer to match the
  authenticated Raft source's separately pinned application identity and an
  active replicated member; stale, future, changed-command, changed-actor,
  foreign-source, and revoked-member proofs fail closed. Internal clock,
  barrier, and initialization commands remain unavailable to follower
  forwarding. Quorum-enabled destinations now also perform their own
  linearizable ownership read before installing or retiring a mutation fence
  and accept only the exact active cluster/owner/term/generation/token/expiry
  revision. The disabled standalone authority keeps its compatibility path.
  This establishes attributable system-node delegation and online destination
  verification; end-user credential delegation, offline quorum certificates,
  compromised-host isolation, migration, cross-node IPC, and broader
  qualification remain #122.
- Added generation-fenced OpenRaft transport trust epochs. A quorum can
  atomically replace the complete peer catalog while preserving every current
  voter, add a new peer as a learner, or remove a former non-voter. Peer server
  and client leaves plus the accepted CA bundle are digest-pinned in durable
  membership. Certificate/CA rotation uses an explicit overlap generation
  whose old leaves and multiple roots expire within 30 days and are checked on
  every fresh RPC connection, followed by a separate generation that removes
  the retired leaves and roots. Startup accepts only the complete
  digest-verified durable prior catalog or exact configured target, rejects
  stale/skipped/mixed voter-and-trust changes, requires retained peers to keep
  identity, leaf, and CA continuity, and preserves the legacy generation-zero
  catalog digest byte-for-byte. Immutable application genesis, the complete
  current challenged application membership, and the current transport subset
  are configured separately once those catalogs diverge; startup validates
  every durable identity before mutating Raft membership.
- Added generation-fenced OpenRaft voter changes within the versioned
  transport-trust catalog. Operators select a non-empty `voter_ids` subset and
  advance `voter_set_generation` by one through a coordinated config-driven
  startup. Before quorum changes, the target-configured leader
  persists the exact generation, target-set digest, and immutable transport
  catalog digest in every OpenRaft node record, catches up each incoming voter
  as a learner, and then completes joint consensus. Removed voters remain
  trusted learners so the catalog stays durable. Restart resumes the matching
  prepared or joint change; legacy configurations keep generation zero and
  default to every trusted member voting. Voter and transport-trust generations
  are separate and cannot advance in the same transition.
- Bound every destination mutation fence to the OpenRaft term that committed
  its ownership revision and to the authority lease's exact expiry. Workload
  nodes persist term/generation/token/expiry together, reject lower terms and
  conflicting replays, permanently retain retirement tombstones, refuse proof
  horizons beyond the five-minute authority lease plus 30 seconds of clock
  skew, and stop admitting mutations at the exact expiry boundary. A detected
  clock rollback behind fence installation also fails closed. Schema migration
  v7 backfills standalone and legacy authority terms to one and expires legacy
  destination proofs at their installation time, requiring an authenticated
  refresh before reuse. Replicated ownership and audit now retain the committed
  leader term across replay, snapshot, and restart. Typed v2/SDK operations,
  managed cluster routing, streams, and exact cancellation carry the complete
  proof. An operation admitted before expiry keeps the existing per-agent guard
  through completion; expiry prevents new admission rather than rolling back an
  already-started side effect.
- Added quorum-coordinated, time-bounded application-listener certificate
  rollout for `[cluster_raft]` authorities. A fresh challenged identity proof
  prepares a never-before-authorized candidate for 5–3600 seconds; activation
  requires another fresh challenged registration, then retains the previous
  leaf only for a replicated 5–3600 second overlap. Prepared rollouts can be
  aborted, activated rollouts can be finalized only after their retirement
  deadline, and retired leaves cannot be reused. Membership discovery and
  configured-authority startup evaluate both windows against replicated
  authority time. New typed v2/SDK prepare, abort, finalize, and audit controls
  preserve caller-stable retry IDs. Raft peer transport certificates and trust
  roots use the separate generation-fenced transport-trust protocol.
- Routed public membership and ownership authority through the optional
  production OpenRaft runtime. Identical voter genesis now seeds challenged
  application membership, generation/audit history, ownership
  leases/tombstones/audit, a monotonic replicated clock, and caller-stable
  idempotency receipts. Writes and linearizable reads received by followers
  forward to the elected leader over exact identity-pinned mTLS; an isolated
  leader cannot apply authority state. The production daemon verifies its
  configured application UUID/key against durable node identity, installs the
  authority handle only after genesis commits, and serves the public syscall
  endpoint through failover. SDK callers can supply stable operation UUIDs for
  exact retry. Application-listener TLS identity is configured independently
  from Raft transport TLS. State-machine, three-node failover/partition, and
  real daemon TCP lifecycle regressions cover deterministic replay, restart
  recovery, follower forwarding, no-quorum rejection, and clean shutdown.
  End-user credential delegation beyond the system-node principal, migration,
  cross-node IPC, global quotas/trust, rolling upgrades, and disaster recovery
  remain #122.
- Wired the authenticated OpenRaft runtime into the production `agent-server`
  lifecycle behind a default-off, strict `[cluster_raft]` configuration.
  Enabled nodes read bounded no-follow PEM files, require owner-only private
  keys on Unix, bind the configured peer listener, bootstrap only when
  explicitly requested, and reject restart if the durable membership differs
  from the configured node, endpoint, certificate, or identity map. The daemon
  owns clean Raft shutdown on SIGINT/SIGTERM. Restart and negative regressions
  cover exact durable membership, configuration drift, unsafe key permissions,
  and symlinked TLS material.
- Added a durable OpenRaft storage-v2 implementation and an executable internal
  quorum runtime for the cluster authority foundation. Votes, log and commit
  pointers, deterministic barrier state, membership, receipts, and snapshots
  share the encrypted SQLite durability/backup boundary and fail closed on
  corruption or safety-pointer regression. Bounded versioned Raft RPCs run over
  mutual TLS with exact server/client leaf binding to stable node IDs. A
  three-node regression proves election, replication, leader failover, durable
  restart catch-up, and old-term fencing; negative regressions cover identity
  spoofing, wrong-but-CA-valid leaves, invalid configuration, and oversized
  frames.
- Fixed service startup deadlines so a configured readiness delay that cannot
  finish inside the remaining startup budget fails closed deterministically,
  reclaims the created service agent, and records `startup_timeout`. This
  removes a timer-boundary race observed on protected macOS CI.
- Added restart-free TLS certificate and client-trust rotation for the syscall
  server. Operators atomically replace PEM material and then change a bounded
  trigger file; a fully validated configuration is published as one monotonic
  generation, while unreadable, partial, or mismatched updates leave the
  current generation active. Optional client CRLs provide fail-closed
  individual certificate revocation with expiry enforcement. New handshakes
  switch immediately and sessions admitted under the previous trust generation
  finish their current request before being closed. TLS clients retain only the
  verified server leaf's SHA-256 fingerprint. Cluster admission signs and persists that observed
  fingerprint, permits authenticated certificate rotation, forbids TLS-to-
  plaintext re-admission, records old/new leaf fingerprints in durable
  membership audit, and rejects a superseded leaf during discovery.
  Quorum application-listener rollout is implemented by the replicated
  authority; Raft peer transport rotation uses separate bounded trust epochs.
- Added durably reconcilable managed cluster creation. The authority now exposes
  a stable paginated ownership directory; managed placement reserves a UUID,
  preinstalls its exact destination fence, and creates only while that proof is
  active. Startup/manual reconciliation recovers expired exact-owner leases,
  repairs missing fences, leaves live reservations pending, and advances,
  rechecks, retires, then releases expired incomplete reservations so a delayed
  creator cannot cross cleanup. Duplicate exact IDs never overwrite state.
  New explicit maintenance constructors renew idle leases, republish destination
  fences through fresh authenticated connections, expose bounded health, and
  stop on client drop. These controls remain single-authority, not quorum.
- Added a system-scoped durable cluster ownership authority: active members can
  claim bounded leases, exact owner/token pairs can renew or release them, and
  transfer after release or expiry requires the old token and allocates a
  strictly greater fencing token. Records, tombstones, and audit survive
  restart; clean leave cannot strand an active lease, and identity revocation
  releases every owned record atomically. The controls are exposed through the
  typed v2 wire/SDK boundary, and schema migration v4 upgrades existing stores
  atomically. Authority records require explicit destination installation and
  are not automatically propagated, so this alone is not a partition fence.
- Added durable workload-node mutation fences and retirement tombstones.
  System-only v2/SDK controls install the highest accepted cluster/owner/
  generation/token record; every agent-targeted write path then rejects
  unfenced, stale, retired, cross-agent, and foreign-destination calls.
  Per-agent read/write admission barriers hold verification across the complete
  operation, serialize initial installation and handoff with in-flight work,
  and cover the dedicated ordinary-stream path.
  Fenced lifecycle, turn, and tool SDK calls reuse the existing authorization
  and resource gates. This is destination enforcement, not quorum: authority
  terms/failover and migration remain open in #122.
- Published the normative distributed control-plane consistency contract. It
  distinguishes single-authority membership, node-local state, reconstructed
  routing, and missing ownership fencing; defines fail-closed partition, retry,
  duplicate-owner, stale-route, and unknown-outcome behavior; and states the
  invariants required before the multi-node foundation can be production
  qualified.
- Added a revocable, visible local approval contract for future peripheral
  access without enabling any placeholder device operation. Peripheral tool
  bindings are registration-rejected unless they require sandbox execution and
  explicit human approval. The trusted in-process operator API can grant,
  inspect, or revoke one exact agent/tool/opaque-target/contract approval;
  grants are single-use, secrets never enter the status projection, and agent
  teardown purges them. Capture, audio, print, and every kernel peripheral
  provider remain unavailable until a platform backend supplies active-use
  indicators and qualification.
- The protected Linux browser qualification now installs an exact-path
  AppArmor profile granting only the `userns` permission Chromium needs for its
  native process sandbox. This fixes Ubuntu 24.04 hosted-runner launch failure
  without adding `--no-sandbox`; retained evidence records the browser and
  profile SHA-256 values.

- Expanded the protected exact-commit provider-security workflow from a
  browser-unavailable assertion to a real two-profile Chromium qualification.
  The lockfile-pinned browser fixture proves cookies do not cross isolated
  profiles, downloads cannot land, typed secrets do not enter errors, returned
  URLs omit query secrets, screenshots stay bounded in memory, both browser
  processes are reaped, and both private profiles are removed. The retained
  Linux report separately proves the kernel browser provider remains
  unavailable and does not promote the trusted helper into runtime discovery.
- Hardened the feature-gated trusted-process HTML and Chromium helpers without
  advertising them as kernel providers. HTML fetches now use strict HTTPS,
  ignore ambient proxies, refuse redirects, cap strict-UTF-8 bodies and output,
  bound extracted fields, and redact returned source URLs. Each Chromium launch
  uses a unique owner-only profile, denies downloads through CDP, applies fixed
  launch and operation deadlines, returns bounded in-memory screenshots, strips
  sensitive URL components, and explicitly reaps the process and profile.
  Focused regressions cover bounds, redaction, redirects, invalid/oversized
  responses, private unique profiles, and cleanup; an opt-in real Chromium
  fixture also proves download denial and profile removal. These trusted helpers
  remain Experimental: the unavailable kernel browser provider, agent egress and
  authorization boundary, supported-platform live matrix, and independent
  review remain open under #124/#127.
- Added signed-package install/upgrade, run, rollback, removal, and honest
  installed-state projection to the desktop Operations view over `KernelClient`.
  Rollback and removal freeze the displayed package name, version, digest, and
  publisher; require exact `version|name` confirmation; and submit the frozen
  version and digest to the transaction-bound wire operation. Backend loopback,
  IPC validation, reducer, source-contract, rendered interaction, axe, and
  capability-registry regressions retain the flow and stale-target refusal.
- Added signed-package install/upgrade, run, rollback, removal, and installed
  state to the TUI over `KernelClient`. Rollback and removal freeze the
  displayed name, version, and digest, require exact `version|name`
  confirmation, and use new transaction-bound exact mutation operations so a
  concurrent package change fails stale. State-machine, registry, and
  authenticated loopback regressions cover the complete flow.
- Added desktop operator-tunable update, rollback, and bounded audit history
  through the authenticated public `KernelClient`. The UI freezes the tunable
  name, value, revision, and advertised bounds; updates use compare-and-set
  revision enforcement, while rollback requires an older retained revision and
  the exact tunable name. Backend validation, system/tenant authorization,
  stale-revision refusal, production-bundle interaction, and axe regressions
  retain the contract.
- Added focused operator-tunable control to the TUI over the public
  `KernelClient` boundary. Operators can select a live tunable, submit a value
  only within its advertised bounds using the frozen expected revision, load
  bounded audit history, and roll back only after entering the older revision
  plus the exact frozen tunable name. Real loopback coverage proves successful
  update/audit/rollback, stale-revision refusal, and snapshot projection.
- Added frozen exact-name confirmation to TUI service stop and restart. The
  confirmation identifies the selected service and current owner, discloses
  dependent-service or in-flight-work impact, ignores later selection changes,
  and remains cancellable before the public SDK mutation is submitted.
- Added desktop service supervision over the authenticated public SDK/wire
  boundary. Operators can start inactive services, inspect bounded transition
  history, and stop or restart a frozen service target only after typing its
  exact name. The confirmation discloses the current owner and dependency or
  in-flight-work impact. A real embedded loopback regression exercises
  start/restart/history/stop plus unknown-service failure, while source and
  rendered axe tests retain target binding and keyboard-accessible controls.
- Added real ordered message streaming, exact-request cancellation, and durable
  checkpoint controls to the desktop client over the public SDK/wire boundary.
  Streaming, ordinary operator reads, and cancellation use separate
  authenticated connections so a live turn cannot freeze status refreshes or
  prevent its own cancellation. The desktop lists checkpoint metadata, resumes
  an exact checkpoint, and requires the full frozen checkpoint ID before
  permanent deletion. A loopback regression proves refresh remains responsive
  during a blocked stream and that cancellation terminates only the exact
  request. Source and rendered axe tests cover the cancellation and checkpoint
  controls. Dashboard selection now passes the real agent ID instead of a
  double-wrapped event payload that left the detail panel empty.
- Added the fail-closed Tauri 2 signed-updater foundation. The desktop embeds a
  real minisign public identity, checks only the canonical HTTPS GitHub Release
  manifest, bounds update metadata at IPC, requires exact-version review and
  confirmation, rechecks before install, rejects concurrent installs, and
  delegates mandatory artifact verification to the official updater plugin.
  Release qualification now requires protected updater key/password secrets,
  collects every installer signature, and can build strict tag-bound static
  metadata. Real-signature tamper tests, malformed/ambiguous manifest tests,
  frontend confirmation tests, and rendered axe coverage are blocking CI.
  Native signing/notarization and clean-host install, upgrade, failed-update,
  and operator-led rollback qualification remain open under #126.
- Added rendered accessibility regression coverage for the production desktop
  frontend bundle. Lockfile-pinned Playwright Chromium and axe now scan the
  dashboard, operations, settings, and setup states against WCAG A/AA rules and
  prove skip-link keyboard behavior, visible focus, modal focus containment,
  320 CSS-pixel page reflow, and reduced-motion suppression in blocking CI.
  Responsive shell, navigation, dashboard, and operator-card layouts now avoid
  page-level horizontal scrolling at the narrow regression viewport. Exact
  native-webview, text-scaling, signed-artifact, and platform screen-reader
  qualification remain open under #126.
- Added bounded, offline, machine-readable policy validation and explanation
  to the canonical `agentctl` surface, sharing the runtime `PolicyDocument` and
  MAC evaluator. Added live SDK-backed gate-counter, node-control-audit, and
  cluster-membership-audit commands with bounded limits. Real process/TCP
  regressions prove the offline commands never connect, explanations match the
  engine, trusted-system reads succeed, and tenant Admin and ReadOnly
  credentials receive the same payload-free authorization denial.
- Expanded the focused TUI and desktop Operations view without bypassing the
  public operator snapshot. Both now retain scope, version, truncation, agent
  enforcement/context/cgroup data, provider health, loaded-package instances,
  services, tunables, and scoped gate counters. Scope-protected services,
  tunables, and global metrics remain explicitly unavailable instead of being
  rendered as zero or empty evidence. Projection, stale-state, compiler
  accessibility, frontend-build, and Rust regression checks cover the new
  surface. Policy explanation/audit workflows, exact-artifact accessibility,
  and signed updater qualification remain open under #126.
- Added complete signed-package lifecycle coverage to the canonical `agentctl`
  public SDK/wire path: trust and revoke publisher keys, publish and yank
  signed archives, safely fetch without overwriting an existing file, search,
  install/upgrade, roll back, remove, list, and run installed packages.
  Destructive key, version, rollback, and removal operations require the exact
  target after `--confirm`. A real TCP, multi-process regression proves the
  end-to-end lifecycle, tenant-isolated discovery and execution, byte-identical
  fetches, transactional upgrade/rollback, and overwrite refusal.
- Expanded the canonical `agentctl` operator over the existing public SDK/wire
  boundary. It now supports tenant-scoped agent creation and messages, ordered
  NDJSON streaming, exact request cancellation from a second process,
  generation checkpoint list/resume/delete, enforcement capabilities,
  provider health, protocol features, and Prometheus metrics. A real TCP
  regression exercises those commands with a tenant credential, proves
  foreign-agent isolation and system-only metrics authorization, and cancels a
  live slow-provider stream. SDK result views used by scriptable clients are
  now serializable without redefining wire types. Policy explanation/audit
  views, rendered desktop/TUI breadth, exact-artifact accessibility, and signed
  updater qualification remain open under #126.
- Added a fail-closed desktop release foundation under #126. Workspace, Tauri,
  UI, lockfile, and release-tag versions must now agree; a code-rendered source
  SVG generates validated multi-resolution PNG, ICO, and ICNS assets; and the
  release workflow builds native Linux Debian/AppImage, macOS DMG, and Windows
  MSI/NSIS qualification installers with SBOM, checksums, Sigstore signatures,
  and provenance. Public tags remain deliberately blocked until native signing,
  macOS notarization, signed updater, clean-host upgrade/rollback evidence, and
  the supported platform matrix are complete. Windows release builds explicitly
  select the complete Strawberry Perl runtime so Git Bash cannot break vendored
  OpenSSL configuration by shadowing it with an incomplete Perl installation.
  Reproducibility builds now use two clean output trees through one stable
  logical target path, preventing Rust, ELF, Mach-O, and PE linker metadata from
  embedding the prior `target-a`/`target-b` test-harness difference.
- Established a WCAG 2.2 AA-oriented desktop accessibility baseline with a
  keyboard skip link, visible focus, semantic landmarks and current navigation,
  named controls, modal focus containment, live operation/conversation status,
  text-backed state, minimum control targets, and reduced-motion handling.
  Blocking Svelte diagnostics and source-contract regressions retain these
  behaviors. The former simulated activity feed now truthfully renders only the
  latest operator snapshot and discloses that it is not event history. Manual
  exact-artifact keyboard, contrast, zoom/reflow, and platform screen-reader
  qualification remains open under #126, so no completed accessibility claim
  is made. The desktop entry point now uses the Svelte 5 mount API instead of
  crashing at launch through the removed legacy component constructor.
- Made operator clients honest under degraded connections. The TUI and desktop
  now retain and label last-known-good data as stale, distinguish scoped
  partial views without inventing global zeroes, expose successful reconnect
  generations after server replacement, and render long-running agent,
  lifecycle, service, and refresh operations before blocking. Atomic desktop
  views, reducer tests, loopback response-loss tests, and a stable-endpoint
  server-replacement regression are blocking CI.
- Added bounded profile-backed reconnect for the SDK and first-party clients.
  Protocol and authentication negotiation are restored after transport loss;
  explicitly classified reads may be replayed once, while package, lifecycle,
  tool, turn, and every other mutation fail with an indeterminate-outcome error
  and are never replayed automatically. Real response-loss regressions prove
  package, lifecycle, and tool side effects occur exactly once.
- Required exact target-bound confirmation for CLI force-stop and agent, user,
  or tenant erasure operations. The TUI force-stop flow freezes the original
  agent selection and shows its name, full identifier, and force-stop impact
  before accepting the second confirmation.
- Hardened on-device GGUF qualification under #120 into a fail-closed exact-RC
  evidence gate. A strict runner binds a provisioned model, tokenizer, hardware
  profile, resource limits, existing release tag, and clean commit by digest;
  measures real load, bounded generation, peak RSS, and cancellation latency;
  and never records paths, prompts, generated text, or weights. Cancellation
  and timeout now wait for the blocking inference worker to drain before
  returning. Protected paths moved out of dispatch history, and the bounded
  report is retained for independent review. The gate and regressions are
  implemented, but no independently approved real-model artifact exists yet.
- Added a fail-closed exact-RC external deletion and retention evidence gate
  under #123. A versioned contract now covers all six external-system inventory
  boundaries, requires real immutable-retention-then-delete evidence for remote
  backup copies, and permits `not-configured` only for an exact hashed target
  configuration. The validator recalculates bounded lifecycle completion,
  requires fresh-principal absence, zero residual objects and cross-tenant
  access, and binds a separate eight-check review to the exact observation.
  The protected self-hosted workflow retains only a bounded non-secret report.
  The gate and regressions are implemented, but no eligible target exercise
  exists yet, so production qualification remains false.
- Added a fail-closed exact-RC destructive storage-profile evidence gate under
  #123 for the supported single-node Linux deployment. It accepts only bounded
  external observations of an out-of-band power cut, block-level torn write,
  and storage-device detachment, recalculates the 300-second RPO and
  3,600-second RTO targets, and requires a hash-bound independent review with
  no open findings. A protected self-hosted workflow retains only the
  non-secret report and never injects dangerous faults or substitutes SIGKILL,
  synthetic SQLite failure, or disposable CI storage. The gate and regressions
  are implemented, but no eligible target exercise exists yet, so production
  qualification remains false.
- Added the protected exact-RC target object-store qualification path under
  #123. It requires a non-loopback HTTPS service and dedicated protected
  credentials, binds the run to an existing release tag and clean commit,
  exercises compliance retention, delete-marker survival, exact-version
  download, authenticated restore, and enforcement-state recovery, and retains
  measured timings with replayable non-secret public trust/anchor fixtures.
  The disposable MinIO regression remains separately classified. The target
  workflow is implemented but has not yet produced an independently approved
  artifact, so no production claim is made.
- Added a fail-closed human incident game-day evidence contract under #125.
  The protected workflow validates a one-hour staffed exercise for all six
  runbooks against one exact release candidate and target environment,
  recalculates RPO/RTO, runbook, finding, and tenant-boundary outcomes, and
  requires a separate reviewer bound to the exact raw observation. Only a
  bounded hash-linked report is retained. Release-SLO qualification now
  requires and independently checks that exact report instead of trusting a
  `game_day_completed` flag. The tooling is regression-tested; a real target
  game day and eligible artifact have not yet been run.
- Added operator-triggered immutable remote backup publication and recovery
  under #123. `agentctl` now streams an independently signed and anchor-bound
  backup to an S3-compatible bucket using SigV4, requires server-reported
  `COMPLIANCE` Object Lock retention and immutable version IDs, retains a
  bounded publication receipt, and recovers those exact versions even after
  current-key delete markers. Recovery rechecks lock metadata, size, SHA-256,
  signature, encryption key, schema, installation identity, and independent
  anchor before atomically publishing a local backup, while reporting elapsed
  time and recovery-point age without credentials. Redirects, unsafe
  endpoints, missing confirmation, wrong/short retention, unversioned objects,
  receipt substitution, existing destinations, and databases above the
  documented 5 GiB single-object limit fail closed. A fixed-digest disposable
  MinIO workflow qualifies the exact-commit protocol path. Release archives now
  include the `agentctl` recovery binary and check it for reproducibility;
  independent target-service recovery, released trust fixtures, destructive
  device profiles, and supported-profile RPO/RTO remain open.
- Removed fabricated success behavior from placeholder resource operations
  under #124. Application providers advertise only implemented one-shot
  `launch`; `close`, `send_input`, and `read_output` now return a typed
  unsupported error. The peripheral placeholder advertises no operations and
  every call fails typed-unsupported. Empty providers are omitted from
  capability discovery, unsupported aliases cannot enter local or shared tool
  registries, and predefined permission profiles no longer grant nonexistent
  application operations. Peripheral/application-control support remains
  unavailable until real operator policy and platform implementations are
  qualified.
- Isolated resource-provider execution under #124. Generic provider operations
  now run in kernel-owned tasks with a cooperative cancellation token, a
  five-second drain window, forced-abort fallback, and admission-permit
  ownership that lasts until provider cleanup completes. Provider panics and
  panicking metadata are contained behind redacted errors instead of unwinding
  the kernel path, while cancellation of the broker future drains the provider
  rather than detaching its task. Runtime registration now refuses to replace
  an existing resource class; changing a built-in provider requires a reviewed
  restart/configuration change. Regressions prove panic containment, permit
  recovery, cancellation cleanup, process-tree cleanup, and replacement
  refusal. This contract does not make unaudited third-party detached side
  effects trustworthy, and browser/peripheral production qualification remains
  open.
- Added deterministic bounded-memory evidence for backpressure under #125.
  Delayed-provider overload and slow-client saturation now run in four
  independent waves, retain baseline/peak/settled process RSS observations,
  and fail when either peak footprint or post-warmup growth exceeds the
  reviewed 64 MiB ceiling. The exact-commit Linux workflow rejects missing RSS
  checks or undersized evidence. This proves the controlled regression
  fixture; the actual 24-hour target-host soak, real TLS/proxy/provider path,
  exact-RC SLO report, and human game day remain open.
- Added process-exit atomicity qualification for durable cluster control under
  #123. Twenty-one child-process exits cover first initialization, availability
  transition, profile update, initial join, rejoin, leave, and revocation
  across node identity/control/audit plus membership
  authority/challenge/member/audit state. Every statement boundary is inventory
  checked; an exit must restore the exact pre-transaction contents of all seven
  cluster tables. Clean retries verify complete generations, audits, challenge
  consumption, schema ownership, and `quick_check`. This completes the
  in-process multi-table statement-boundary matrix; power loss, torn writes,
  device loss, external side effects, and measured RPO/RTO remain open.
- Added process-exit atomicity qualification for the durable package registry
  under #123. Twenty-nine child-process exits cover initial and superseding
  trust roots, revocation, artifact publish/yank with transparency and audit
  chains, dependency installs and upgrades, rollback, and removal. Every
  boundary is inventory checked; an exit must retain the deliberately separate
  rate-limit admission while restoring the exact pre-transaction contents of
  every package mutation table. Clean retries verify terminal state, the full
  transparency hash chain, schema ownership, and `quick_check`. The
  cluster-control matrix is covered by the entry above; power loss and torn
  writes remain open.
- Added process-exit atomicity qualification for durable quota/accounting
  workflows under #123. Thirty-seven child-process exits cover hierarchical
  reservation, pre-invocation refund, actual-usage reconciliation, direct token
  charging, restart recovery, and completed-epoch pruning across the monotonic
  floor, receipts, ordered scopes, trusted aggregates, refund tombstones,
  migration fences, and trigger-maintained accounting integrity state. Every
  exit must reopen with the exact pre-transaction contents of every durable
  table; clean retries must publish complete state and pass schema verification
  plus `quick_check`. The cluster-control matrix is covered by the entry above;
  power loss and torn writes remain open.
- Added process-exit atomicity qualification for eleven high-value context
  mutations under #123. Twenty-six child-process exits cover conversation and
  search-index persistence, context-spill store/purge/delete, operator-tunable
  ensure/update/rollback with audit history, service runtime/history
  publication, and user/tenant identity revocation. Every exit must reopen with
  the exact pre-transaction contents of every durable table; clean retries must
  publish all related rows and pass schema verification plus `quick_check`.
  Conversation search-index failures now abort the transaction instead of
  being silently ignored. The quota/accounting, package-registry, and
  cluster-control matrices are covered by the entries above; power loss and
  torn writes remain open.
- Added fail-closed managed-backup erasure under #123. Every server-created
  backup is now constrained to the configured `backup.root`. Agent, user, and
  tenant hot deletion exclusively locks that root, preflights every entry,
  removes every verified backup for the current installation, and keeps backup
  publication fenced until the SQLite erasure commits. Unknown, corrupt,
  foreign, symlinked, augmented, or unavailable-key entries abort before live
  data is deleted. Privacy-safe receipts count removed managed backup copies,
  and bounded metrics expose purge attempts, successes, failures, and deleted
  backups. External replicas and operator-created offline copies remain under
  their independent lifecycle policy.
- Added real process-exit qualification around the supported hot-erasure
  coordinator under #123. Eighteen child-process crash points cover credential
  fencing, supervised-service shutdown, request/operator barriers, completion
  of the managed-backup purge, live-agent quiescence and cleanup, the SQLite
  commit handoff, and final auth revocation across agent, user, and tenant
  deletion. Every crash is followed by a file-backed configured-kernel restart
  and idempotent retry that must remove the subject, leave no live agent
  boundary or pre-erasure managed backup, and retain exactly one private
  receipt. This qualifies process-local erasure coordination; external
  providers/workspaces, interruption inside an opaque purge/cleanup call,
  power loss, and torn writes remain open.
- Added real process-exit fault injection at every statement boundary in all
  three schema-wide erasure transactions under #123: 17 agent, 5 user, and 28
  tenant boundaries. Fifty child-process crash points now prove that SQLite
  recovery preserves the canonical contents of every durable table, schema
  verification, and `quick_check`, followed by clean retries that commit each
  deletion and exactly one private receipt. This qualifies the SQLite erasure
  transactions only; the separate coordinator matrix covers the surrounding
  hot-erasure boundaries, while power loss, torn writes, backup copies, and
  external-system deletion remain open.
- Added destructive Linux host-filesystem exhaustion qualification under #123.
  A guarded release harness accepts only an explicitly marked 32–128 MiB
  disposable filesystem, fills it to a real host `ENOSPC`, proves the failed
  SQLite mutation rolls back without losing the prior commit, restores
  capacity, retries, runs `quick_check`, and reopens with the exact expected
  state. An exact-commit workflow retains the bounded report. The artifact
  explicitly does not prove power-loss, torn-write, device-loss, remote-store,
  or every deployment-filesystem behavior.
- Added a fail-closed exact-release-candidate SLO report under #125. A strict
  evaluator recalculates all nine documented SLOs from raw target counts and
  measurements, enforces 24-hour/30-day windows and minimum proof volumes, and
  rejects malformed, fixture, dirty, short, mixed-commit, mixed-environment,
  short-soak, incomplete-incident, and unresolved-alert evidence. A protected
  self-hosted workflow binds an existing release tag to the exact commit and
  retains only the bounded report plus input hashes. The implementation and its
  tests do not claim that a real target has supplied an eligible report.
- Fixed two queue-saturation alerts that could never match their `waiting` and
  `capacity` series because those series carry different `state` labels. A
  checksum-pinned Prometheus 3.13.1 suite now parses the production rules and
  proves all nine alerts remain inactive before their hold time, fire with the
  documented labels and runbook, and clear after recovery. This validates the
  checked-in rule engine behavior; target Alertmanager routing and receiver
  delivery remain open under #125.
- Added six incident-response playbooks and a fail-closed automated drill for
  #125 covering credential compromise, tenant leak, malicious package, abrupt
  node loss, corrupt database, and provider outage. The fixed command catalog
  rejects empty Cargo filters and invalid child fault evidence, retains only
  non-sensitive command results in an exact-commit workflow artifact, and
  explicitly remains ineligible as proof of alert delivery or a human game day.
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
