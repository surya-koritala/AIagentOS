# External deletion and retention qualification

AI Agent OS can erase its live SQLite state, kernel-owned resources, and every
verified backup in the configured managed backup root. It cannot directly
erase copies controlled by providers, infrastructure, registries, telemetry
services, or remote object stores. This gate makes the target deployment's
external boundary explicit and validates independently reviewed lifecycle
evidence for each configured system.

No eligible target exercise has been published yet. The contract, validator,
protected workflow, and regressions are implemented; this is not proof that a
provider or object store has deleted production data, and whole-product
production qualification remains false.

## Supported v1 profile

The first contract is intentionally narrow:

- profile: `single-node-linux-rootless-container-cli`;
- target: Linux x86_64;
- maximum claimed deletion or post-retention completion: 30 days; and
- remote backup copies: configured and exercised with
  `immutable-retention-then-delete`.

The canonical machine-readable contract is
`config/external-data-boundaries.json`. The observation binds its exact
SHA-256. A change to the inventory, eligible lifecycle modes, or maximum
completion bound changes that digest and invalidates older observations.

The contract requires one disposition for every external-system entry in the
kernel inventory:

| Boundary | Eligible dispositions |
|---|---|
| workspace copies and mounts | delete API, bounded retention, or not configured |
| provider requests and retained data | delete API, bounded retention, zero-data retention, or not configured |
| remote backup copies | immutable retention followed by final deletion |
| log, metric, and trace sinks | delete API, bounded retention, zero-data retention, or not configured |
| container, model, and package registries | delete API, bounded retention, or not configured |
| browser, peripheral, and tool services | delete API, bounded retention, zero-data retention, or not configured |

`not-configured` is evidence only for the exact hashed target configuration.
It is not a general product claim and must be replaced by a configured exercise
when that integration is enabled. Multiple configured services may be listed
under the same boundary; every one must pass.

## What a configured exercise proves

Use a unique canary containing no user or production data. For every configured
external system, the operator records:

- the stable non-secret system identifier and hashes of its exact
  configuration, lifecycle policy, and retained raw evidence;
- canary creation, lifecycle action, retention expiry when applicable,
  observed absence, and final verification timestamps;
- whether the canary was discoverable before action, whether an immutable
  early deletion was denied, and whether retention expiry was observed;
- accepted lifecycle action, absence after action, and absence reproduced by a
  fresh principal; and
- residual object count and unexpected cross-tenant access count.

The validator recalculates completion rather than trusting a `passed` field:

```text
delete API:                    absent - lifecycle action
zero-data retention:           absent - canary creation
bounded retention:             absent - retention expiry
immutable retention then delete: absent - retention expiry
```

Every completion must be within the system's declared target and the published
30-day maximum. Zero-data-retention canaries must never become discoverable.
Bounded-retention modes must demonstrate the expiry. Immutable remote backups
must additionally demonstrate that early deletion was denied and that final
deletion completed after expiry.

An exercise can establish service behavior only for the named target,
configuration, account, region, policy, and release candidate. Policy text,
screenshots, unit tests, a local emulator, or a successful API response without
fresh-principal absence verification are not substitutes.

## Evidence files and custody

The external harness places two bounded JSON files in a protected directory
outside the checkout:

- `external-deletion-observation.json`; and
- `external-deletion-review.json`.

Both use schema version 1, reject duplicate and unknown keys, must be regular
non-symlink files, and may not exceed 512 KiB. The observation is bound to:

- an existing release candidate and exact clean 40-character commit;
- the target environment and complete configuration digest;
- the profile and canonical boundary-contract digest;
- one bounded exercise, operator, and external harness identity; and
- a complete, fixed-order external-system inventory.

Raw provider responses, audit trails, lifecycle configuration exports, canary
queries, credential identities, and human identity attestations stay in the
operator's governed evidence store. GitHub retains only hashes and the bounded
report. Do not place credentials, user content, endpoint secrets, or direct
personal identifiers in either JSON file.

## Independent review

The review binds the exact observation SHA-256, commit, release candidate,
environment, profile, and complete record inventory. It must occur after the
exercise and within 30 days. Its reviewer identity must differ
case-insensitively from the operator and harness identities.

An eligible review is `approved`, has no open findings, and affirms all eight
checks:

1. target configuration matches the release candidate;
2. every configured external system was exercised;
3. deletion and retention timelines were recalculated;
4. absence was reproduced with a fresh principal;
5. immutable backup retention and final deletion were reviewed;
6. cross-tenant results were reviewed;
7. raw service evidence remains retained; and
8. external policy owners approved the result.

The JSON validator cannot authenticate people, cloud accounts, or raw provider
behavior by itself. Independent identity attestation, protected evidence
custody, and runner access are part of the control.

## Protected workflow

Configure:

- a GitHub environment named `external-data-qualification`;
- a dedicated self-hosted Linux x86_64 runner labeled
  `agentos-external-data`; and
- environment variable `AGENTOS_EXTERNAL_DELETION_EVIDENCE_DIR`, pointing to
  the protected external evidence directory.

Dispatch
`.github/workflows/external-deletion-qualification.yml` with:

- `release_candidate`: an existing `vX.Y.Z-rc.N` or `vX.Y.Z` tag pointing
  exactly to the workflow commit; and
- `environment_id`: the stable non-secret target identifier used in both
  evidence files.

The workflow only validates already collected evidence. It does not hold
service credentials or issue deletion requests. It requires exact tag/commit
binding, clean source, a complete boundary inventory, a configured immutable
remote-backup exercise, independently approved review, and all recalculated
checks. It retains the bounded non-secret report for 90 days and always sets
`production_claim_allowed` to `false`.

The portable contract check is:

```bash
python3 scripts/external_deletion_qualification.py --validate
```

The validator's execution interface is:

```bash
python3 scripts/external_deletion_qualification.py \
  --observation /protected/external-deletion-observation.json \
  --review /protected/external-deletion-review.json \
  --expected-commit FULL_GIT_SHA \
  --expected-environment TARGET_ID \
  --release-candidate v1.0.0-rc.1 \
  --output /new/path/external-deletion-report.json \
  --require-eligible
```

The output path must not already exist and is created owner-only on Unix.

## What remains open

The repository now defines how an external deletion result can be accepted
without confusing a fixture with proof. Issue #123 remains open until operators
run this gate against the supported target and every real configured external
service, retain the raw evidence, obtain independent approval, and accept the
result together with the other release-level durability gates.
