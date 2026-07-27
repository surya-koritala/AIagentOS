# Incident response

This runbook covers the six release-blocking incident classes in issue #125.
Its commands and technical controls apply to the supported single-node Linux
release candidate. Distributed failover, external alert delivery, provider
status APIs, legal notification duties, and organization-specific contacts
must be supplied by the deploying operator.

The priorities are always:

1. Protect people and prevent cross-tenant or credential misuse.
2. Stop unsafe writes and new admission without destroying evidence.
3. Preserve a UTC timeline, exact code SHA, configuration, audit data, database
   and sidecars, logs, relevant provider receipts, and host/runtime metadata.
4. Recover only from authenticated, independently anchored material.
5. Re-open admission only after the incident-specific verification passes.

Never paste credentials, prompts, tenant data, database contents, or signing
keys into a public issue or CI log. Use the deployment's restricted evidence
store and record hashes plus custody instead. Declare an incident commander,
scribe, operations lead, security lead, and communications owner. One person
may fill several roles on a small team, but the commander must authorize every
containment and recovery transition.

## Severity and common procedure

Treat a confirmed tenant boundary violation, active credential exploitation,
malicious signed package, unauthenticated recovery, or loss of storage
integrity as **SEV-1**. Treat a credible but unconfirmed version of those events,
complete node loss without a qualified recovery point, or sustained provider
failure with no safe route as **SEV-2**. Lower-impact contained degradation may
be **SEV-3**.

For every incident:

- Record detection time, declaration time, commander, affected deployment,
  exact SHA, tenant scope, and the evidence-store location.
- Freeze unrelated changes. Capture current metrics and redacted structured
  logs before restarting. Use `agentctl` storage and backup verification
  commands from [DURABILITY.md](DURABILITY.md); never edit SQLite directly.
- Prefer drain/revoke/deny controls over deleting state. Preserve originals
  before recovery. Do not weaken tenant authorization, package verification,
  storage integrity, or sandbox policy to restore service.
- State what is known, unknown, contained, and next due time. Notify affected
  parties and regulators according to the operator's jurisdiction and policy;
  this repository cannot decide those obligations.
- After recovery, retain the timeline, evidence hashes, actions, test results,
  residual risk, root cause, and corrective owners. A reviewer other than the
  incident commander must approve closure.

## Credential compromise

**Trigger:** a leaked token/key, unexpected authentication use, abnormal
authorization failures, provider notification, or evidence that a credential
was copied. Declare SEV-1 if misuse is confirmed or tenant/system authority may
be exposed.

**Containment**

1. Revoke the affected AgentOS credential immediately and block its identity.
   If scope is uncertain, stop new admission for the affected tenant or node.
2. Rotate external provider credentials at the provider, then update the
   deployment through its secret manager. Do not put replacement secrets in
   config files, shell history, logs, or tickets.
3. Preserve credential audit events, tenant authorization events, bounded
   request metrics, provider access records, and the last known-good config
   hash. Do not preserve plaintext secret values.

**Recovery and verification**

1. Issue a least-privilege replacement only after identifying the owning user,
   tenant, scopes, and suspected exposure window.
2. Prove that an already-connected revoked session loses authority and that
   revocation survives restart:

   ```bash
   cargo test -p kernel \
     syscall_server::tests::revoked_tenant_session_loses_authority_without_reconnect \
     --locked -- --exact
   cargo test -p integration-tests \
     tenancy_props::credential_revocation_survives_restart \
     --locked -- --exact
   ```

3. Review all actions during the exposure window for unexpected allows,
   package changes, storage access, and provider usage. Re-open only the
   verified scope. Record any downstream provider revocation separately.

## Tenant data leak

**Trigger:** a tenant reports foreign data, an authorization trace shows an
unexpected allow, an export contains another tenant, or storage/audit
reconciliation cannot establish ownership. Treat credible cross-tenant access
as SEV-1.

**Containment**

1. Stop new admission and exports for the suspected tenant boundary. If the
   affected boundary is unknown, drain the node.
2. Preserve the database/WAL/SHM, storage inventory, authorization and erasure
   audits, request correlation timeline, export hashes, and exact deployment
   configuration. Do not query or copy more tenant content than investigation
   requires.
3. Do not “test” the leak in production with another tenant's credentials and
   do not erase evidence before scope and notification duties are established.

**Recovery and verification**

1. Identify the first violating operation, affected ownership classes, tenants,
   duration, and whether content left the system. Rotate implicated credentials.
2. Patch the boundary and prove both durable state isolation and authorization
   of every ID-addressed foreign operation:

   ```bash
   cargo test -p integration-tests \
     tenancy_props::cross_tenant_state_reads_are_impossible \
     --locked -- --exact
   cargo test -p kernel \
     syscall_server::tests::tenant_authorizer_denies_every_foreign_agent_operation \
     --locked -- --exact
   ```

3. Run the complete tenant adversarial suite and reconcile affected exports.
   Restore service tenant by tenant only after zero unexpected allows. The
   communications owner handles customer and legal notifications.

## Malicious package

**Trigger:** signature/checksum failure, unexpected publisher key, dependency
confusion, package privilege escalation, transparency discrepancy, or a
package executing behavior outside its manifest. Confirmed execution is SEV-1.

**Containment**

1. Stop new package installs and agent admission for the package. Quarantine
   the exact package bytes, manifest, signature, publisher chain, dependency
   graph, install audit, hash, and affected agent IDs in restricted evidence.
2. Revoke the publisher/key and affected package version through the governed
   package controls. Do not delete the only sample or “fix” its manifest.
3. Inspect affected tenants, tool calls, storage writes, credentials, provider
   usage, and sandbox events. Rotate any credential the package could access.

**Recovery and verification**

1. Remove or roll back only through the package lifecycle, using a trusted
   signed version and verified dependency graph.
2. Prove recomputed checksums cannot bypass signatures and confusion/escalation
   fails closed:

   ```bash
   cargo test -p kernel \
     package::tests::recomputed_checksum_cannot_bypass_signature_verification \
     --locked -- --exact
   cargo test -p kernel \
     package::tests::dependency_confusion_and_privilege_escalation_fail_closed \
     --locked -- --exact
   ```

3. Re-run package supply-chain and sandbox qualification before admitting the
   replacement. Publish revocation/affected-version guidance without exposing
   tenant evidence.

## Node or process loss

**Trigger:** process crash, host loss, unavailable disk, unexpected reboot, or
loss of node identity/availability. Treat loss without an authenticated recent
recovery point as SEV-2 or higher.

**Containment**

1. Fence the failed node from traffic and prevent two kernels from owning the
   same database. Preserve host, volume, database/WAL/SHM, process, and audit
   evidence. Do not attach the same writable store to another live owner.
2. Establish the last confirmed write, backup status, independently retained
   recovery anchor, storage key availability, and external side effects.
3. For the single-node v1 candidate, recovery means restart or authenticated
   fresh-host restore; it does not claim automatic failover.

**Recovery and verification**

1. Prefer restart on intact storage. If the host/store is lost, follow the
   exact anchored fresh-host restore in [DURABILITY.md](DURABILITY.md).
2. Prove abrupt committed-state recovery and stable private-key possession:

   ```bash
   cargo test -p integration-tests \
     persistence_props::crash_recovery_restores_everything \
     --locked -- --exact
   cargo test -p kernel \
     cluster_control::tests::identity_is_stable_and_proves_private_key_possession \
     --locked -- --exact
   ```

3. Verify health, installation identity, persisted agents, enforcement,
   accounting integrity, backup status, and external side-effect reconciliation
   before clearing the fence. Record measured RPO/RTO; repository tests are not
   measured deployment recovery evidence.

## Corrupt database

**Trigger:** SQLite integrity failure, accounting-root mismatch, unreadable
page, invalid schema/migration state, corrupt key material, or startup refusing
storage integrity. Treat confirmed integrity loss as SEV-1.

**Containment**

1. Stop all writes and admission. Copy the exact database/WAL/SHM and relevant
   journal/key metadata to restricted forensic storage with hashes and custody.
2. Do not run manual SQL repair, discard sidecars, replace integrity roots, or
   repeatedly boot the only copy. Preserve the corrupt original even after a
   candidate restore.
3. Obtain the independently retained signing trust, exact recovery anchor,
   expected installation UUID, and storage key through separate custody.

**Recovery and verification**

1. Use confirmed offline `agentctl backup-corruption-recover` according to
   [DURABILITY.md](DURABILITY.md). It must quarantine originals, verify exact
   trusted backup identity, boot a candidate, and roll back on qualification
   failure.
2. Prove preservation, qualification, and rollback behavior:

   ```bash
   cargo test -p kernel \
     storage::tests::corrupt_recovery_preserves_original_files_and_qualifies_backup \
     --locked -- --exact
   cargo test -p kernel \
     storage::tests::corrupt_recovery_qualification_failure_restores_original_and_keeps_candidate \
     --locked -- --exact
   ```

3. Verify full storage integrity, installation identity, agents, authorization,
   quota/accounting state, backup status, and forensic quarantine before
   admission. Retain the failed and recovered hashes.

## Provider outage

**Trigger:** provider timeouts/5xx, circuit open, quota or authentication
failure, DNS/TLS/network failure, or materially degraded latency. Escalate if
all safe routes fail or external side effects cannot be reconciled.

**Containment**

1. Classify the failure before retrying. Stop retries for authentication,
   policy, quota, incompatible residency, partial visible output, or unknown
   side-effect state. Reduce admission when queues approach their qualified
   bounds.
2. Preserve bounded provider health/circuit/retry metrics, request correlation
   IDs, provider status and request IDs, configuration hash, and outage
   timeline. Never log prompts, provider credentials, or response content.
3. Fail over only to a preconfigured compatible provider whose model,
   residency, credential, budget, and cancellation policy is qualified.

**Recovery and verification**

1. Confirm provider health outside AgentOS, then allow the circuit's normal
   probe/recovery path. Reconcile duplicate or uncertain external side effects.
2. Exercise typed outage classification, bounded retries, drainage, and
   control-plane availability:

   ```bash
   cargo run --release --locked --package os-benchmark \
     --bin resilience-qualification -- \
     --scenario provider-outage \
     --output target/qualification/provider-outage.json
   ```

3. Restore normal admission gradually while watching waiting/active turns,
   permits, latency, error budget, quota receipts, and circuit state.

## Automated drill and evidence boundary

Validate or execute the fixed six-playbook technical-control catalog:

```bash
python3 scripts/incident_drill_qualification.py --validate
python3 scripts/incident_drill_qualification.py \
  --output target/qualification/incident-drill.json
```

The scheduled `Incident drill qualification` workflow runs the exact commands,
rejects empty test filters and malformed child evidence, binds the report to a
clean Git SHA, and retains it for 90 days. The report stores command IDs and
results, not raw command output.

Even a passing artifact has
`qualification_class = automated_incident_drill_fixture`,
`human_game_day_completed = false`, `game_day_proof_eligible = false`, and
`production_claim_allowed = false`. It does not prove alerts reached an
operator, roles were staffed, decisions and communications were correct, or
RPO/RTO targets were met. The
[human game-day qualification](GAME_DAY_QUALIFICATION.md) now defines and
validates that protected evidence, including exact-RC/environment binding,
staffed roles, UTC timelines, recalculated outcomes, and a separate review.
Issue #125's game-day proof remains open until people actually run that gate on
the target deployment and retain an eligible artifact; the checked-in
validator does not claim that exercise has happened.
