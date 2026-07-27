# Destructive storage profile qualification

AI Agent OS has deterministic SQLite, process-exit, disposable-filesystem
`ENOSPC`, and immutable remote-backup tests. Those tests cannot prove recovery
from real host power loss, block-level torn writes, or storage-device loss. The
destructive storage profile gate validates separately collected evidence for
those three events without pretending that a CI fixture is equivalent.

No eligible target exercise has been published yet. The gate and its
regressions are implemented; production qualification remains false until an
exact release-candidate exercise passes and receives independent review.

## Supported v1 profile and objectives

The first qualification contract is deliberately narrow:

- profile: `single-node-linux-rootless-container-cli`;
- target host: Linux x86_64;
- RPO: no more than 300 seconds;
- RTO: no more than 3,600 seconds; and
- recovery for torn-write and device-loss scenarios: an exact immutable remote
  backup, not a local copy in the same failure domain.

The report records the specific filesystem type, filesystem-configuration
digest, storage-stack identifier, object-store service identifier, and complete
non-secret configuration digest. A result applies only to that declared target
profile. Other filesystems and storage stacks require their own evidence.

## Safety and evidence custody

The workflow never injects a destructive fault. An operator-owned external
harness performs the exercise using the platform's out-of-band controller and
places two bounded JSON summaries in a protected evidence directory:

- `storage-observation.json`, produced after all three faults; and
- `storage-review.json`, produced by a reviewer who is not the operator or
  harness identity and is bound to the exact observation SHA-256.

Raw controller logs, device telemetry, installation secrets, storage keys,
operator identity records, and reviewer identity attestation stay in a
separately governed evidence store. The GitHub artifact contains only the
bounded hash-linked report. A JSON assertion cannot authenticate a person or
hardware by itself; protected runner access, environment approval, and external
attestation custody are part of the qualification control.

Never perform these scenarios on a production installation or shared storage.
Use an isolated, restorable target environment with an approved destructive
test plan.

## Required observation

Both evidence files use schema version 1, reject duplicate or unknown JSON
keys, must be regular non-symlink files, and may not exceed 512 KiB.

The observation contains:

- `qualification_class`:
  `destructive_storage_profile_observation`;
- the exact release tag and clean 40-character commit;
- target environment, profile, and exercise identities;
- exercise start/end time, operator identifier, and external harness
  identifier; and
- exactly these scenarios in order: `host-power-loss`, `torn-write`,
  `device-loss`.

Every scenario supplies the start, last acknowledged write, fault injection,
recovery start, newest recovered write, and healthy-service timestamps. The
validator recalculates:

```text
RPO = last acknowledged write - newest recovered write
RTO = service healthy - fault injected
```

It also requires the exact fault mechanism, recovery source, hashed pre/post
boot IDs, observed expected fault, SQLite `quick_check=ok`, installation
identity verification, recovery-artifact verification, re-armed enforcement,
zero unexpected tenant access, and a raw-evidence digest.

Eligible mechanisms are fixed:

| Scenario | Required mechanism | Eligible recovery |
|---|---|---|
| `host-power-loss` | `out_of_band_power_cut` | local journal or immutable remote backup; boot ID must change |
| `torn-write` | `block_level_torn_write` | immutable remote backup |
| `device-loss` | `storage_device_detached` | immutable remote backup |

SIGKILL, a synthetic SQLite failure, loopback storage, and a disposable CI
filesystem are not substitutes for these observations.

## Required independent review

The review uses qualification class
`independent_destructive_storage_review`. It repeats the exact release,
commit, environment, profile, and scenario inventory; binds the observation
SHA-256; records an external attestation digest; and must occur after the
exercise but within 30 days.

An eligible decision is `approved`, has no open findings, and affirms all seven
checks: the three physical fault mechanisms, recovery identity/integrity,
RPO/RTO calculations, exact target-profile match, and retained raw evidence.
The reviewer identifier must differ from both operator and harness identifiers.

## Protected workflow

Configure a protected GitHub environment named
`destructive-storage-qualification`, a dedicated self-hosted runner labeled
`agentos-destructive-storage`, and the environment variable
`AGENTOS_STORAGE_PROFILE_EVIDENCE_DIR`. The directory must be outside the
checkout and readable only by the qualification principal.

Dispatch `.github/workflows/storage-profile-qualification.yml` with:

- `release_candidate`: an existing `vX.Y.Z-rc.N` or `vX.Y.Z` tag that points
  exactly to the workflow commit; and
- `environment_id`: the same stable non-secret target identifier recorded in
  both evidence files.

The workflow validates the checked-in contract, tag/commit binding, clean
source, evidence bounds, exact scenario inventory, independently approved
review, and RPO/RTO objectives. It retains the non-secret report for 90 days
and deliberately sets `production_claim_allowed` to `false`; whole-product
approval still requires every independent release gate.

The portable non-destructive contract check is:

```bash
python3 scripts/storage_profile_qualification.py --validate
```

## What remains open

This gate makes a real target result reviewable; it does not create that result.
Issue #123 remains open until eligible evidence is actually collected for the
supported profile, independently reviewed, and accepted together with target
remote-backup qualification, external deletion/retention verification, and the
remaining release-level evidence.
