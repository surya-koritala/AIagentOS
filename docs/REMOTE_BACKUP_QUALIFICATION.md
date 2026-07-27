# Remote immutable backups

AI Agent OS can publish one already-signed local backup to an S3-compatible
object store and recover the exact locked object versions. The object store is
never trusted to identify a valid recovery point: publication and recovery both
require the independently retained public trust root and exact recovery anchor.

This is an operator-triggered CLI path for the supported single-node profile.
It does not silently replicate every scheduled backup.

## Object-store contract

Provision a dedicated bucket before publication:

- versioning and Object Lock must be enabled when the bucket is created;
- the publishing identity needs `PutObject`, checksum, retention, and
  `HeadObject`/retention-read permissions;
- the recovery identity needs `GetObject`, `HeadObject`, and retention-read
  permissions for exact versions;
- use a bucket policy that denies ordinary `DeleteObject` and
  `DeleteObjectVersion` access, with separately controlled break-glass
  administration. The dedicated target-qualification identity is the only
  exception: it needs `DeleteObject` on its unique `qualifications/` prefixes
  to create current-key delete markers, but must never receive
  `DeleteObjectVersion` or retention-bypass permission; and
- use TLS with a trusted certificate. Plain HTTP is accepted only with
  `--allow-loopback-http` and a syntactic loopback endpoint for disposable
  qualification.

Publication uses path-style S3 requests and SigV4 credentials from
`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, optional `AWS_SESSION_TOKEN`, and
`AWS_REGION`/`AWS_DEFAULT_REGION`. Credentials never appear in JSON reports or
error messages. Each request disables redirects so credentials cannot be
forwarded to another origin.

The current implementation uses one streaming `PutObject` per file and
therefore accepts backup databases up to 5 GiB. Larger installations are not
silently truncated; publication fails before network mutation.

## Publish a locked recovery point

First create and verify a signed backup and its recovery anchor as described in
[Durability and recovery](DURABILITY.md). Select a retain-until timestamp at
least 24 hours in the future. `COMPLIANCE` mode is intentionally irreversible
through the object API until that timestamp, so the command requires the exact
confirmation flag.

```bash
export AWS_ACCESS_KEY_ID='operator-supplied'
export AWS_SECRET_ACCESS_KEY='operator-supplied'
export AWS_REGION='ca-central-1'

agentctl backup-remote-publish \
  /var/lib/agentos/backups/nightly_2026_07_25 \
  /srv/recovery/agentos-trust/release-2026.1.json \
  /srv/recovery/agentos-anchors/nightly_2026_07_25.json \
  https://s3.ca-central-1.amazonaws.com \
  agentos-immutable-backups \
  installation-01/nightly_2026_07_25 \
  2026-08-27T00:00:00Z \
  --storage-key /etc/agentos/storage-keys/storage-generation-1.json \
  --confirm-compliance-lock \
  > /srv/recovery/agentos-receipts/nightly_2026_07_25.remote.json
```

The database is uploaded first and `manifest.json` last as the commit marker.
Existing keys are accepted only when their byte count, SHA-256, compliance
mode, retention timestamp, and immutable version match. The command then
performs version-specific `HeadObject` verification and returns a bounded
publication receipt containing the exact version IDs.

Retain the receipt with the non-secret trust root and recovery anchor in an
independent operator evidence store. The receipt is a locator, not a trust
root; changing it cannot make altered backup bytes pass signature and anchor
verification.

## Fetch and recover the exact versions

Current object keys can be hidden by a delete marker even though the locked
versions still exist. Recovery therefore requires the publication receipt and
always addresses its exact version IDs.

```bash
agentctl backup-remote-fetch \
  https://s3.ca-central-1.amazonaws.com \
  agentos-immutable-backups \
  installation-01/nightly_2026_07_25 \
  /srv/recovery/agentos-receipts/nightly_2026_07_25.remote.json \
  /var/lib/agentos/recovered/nightly_2026_07_25 \
  /srv/recovery/agentos-trust/release-2026.1.json \
  /srv/recovery/agentos-anchors/nightly_2026_07_25.json \
  --storage-key /etc/agentos/storage-keys/storage-generation-1.json
```

Fetch verifies the server-reported version ID, compliance retention, size, and
metadata hash before streaming each object to a new owner-only staging
directory. It then verifies the signed manifest, database hash, encryption key,
schema, installation identity, and exact recovery anchor before atomically
publishing the local backup directory. Existing destinations are never
overwritten.

The recovery report records downloaded bytes, elapsed milliseconds, and
recovery-point age. It deliberately keeps `production_claim_allowed: false`;
the report must be combined with target-environment, operator, RPO/RTO, and
independent-review evidence.

After fetch, keep the server stopped and run `backup-disaster-recover` with the
same trust root and anchor to replace and boot-qualify the configured database.

## Protected target-service qualification

The manual `Target remote backup qualification` workflow exercises this path
against the declared non-loopback HTTPS service for one exact existing release
candidate. It never substitutes the disposable MinIO fixture. Configure the
protected `capacity-qualification` environment with:

| Kind | Name | Meaning |
| --- | --- | --- |
| Variable | `AGENTOS_TARGET_REMOTE_ENDPOINT` | Origin-only HTTPS S3-compatible endpoint |
| Variable | `AGENTOS_TARGET_REMOTE_BUCKET` | Dedicated versioned Object Lock bucket |
| Variable | `AGENTOS_TARGET_REMOTE_REGION` | SigV4 region |
| Secret | `AGENTOS_TARGET_REMOTE_ACCESS_KEY_ID` | Dedicated qualification access key |
| Secret | `AGENTOS_TARGET_REMOTE_SECRET_ACCESS_KEY` | Dedicated qualification secret |
| Secret | `AGENTOS_TARGET_REMOTE_SESSION_TOKEN` | Optional short-lived session token |

Dispatch the workflow from the exact `vX.Y.Z-rc.N` or `vX.Y.Z` tag and provide
stable non-secret deployment and service-profile identifiers. The job proves
the tag resolves to its checked-out commit, requires a clean release build,
publishes a unique prefix with two days of compliance retention, creates
current-key delete markers, fetches the exact locked versions, restores and
opens the database, and records measured publication, download, recovery-point
age, and restore results.

The retained bounded JSON embeds the non-secret `BackupTrustRoot` and exact
`BackupRecoveryAnchor` under `public_recovery_fixture`. Those released fixtures
allow an independent reviewer to replay signature, installation, database, and
manifest identity checks without the private signing key, storage key, or
object-store credentials. The private signing key exists only in the
disposable runner state and is not uploaded.

`target_remote_recovery_proof_eligible: true` means the target-service
measurement contract passed. `production_claim_allowed` remains false until
the artifact, service separation, bucket policy, retention custody, and
remaining durability/release gates receive independent approval. If protected
credentials, the runner, or the target service are absent, the gate is
failed/not-run rather than passed.

## Checked-in qualification boundary

`.github/workflows/remote-backup-qualification.yml` runs the release-mode path
against fixed-digest MinIO server and client images. It creates an Object Lock
bucket, publishes both objects in compliance mode, creates current-key delete
markers, recovers the exact retained versions, restores the database, and
checks an application value. The retained JSON is exact-commit regression
evidence.

That disposable fixture is not an independent remote failure domain and cannot
complete issue #123 by itself. The protected target-service workflow and
released-fixture report contract are implemented, but production promotion
still requires an eligible exact-RC target run and independent review,
destructive supported-profile tests, external deletion/retention evidence, and
published RPO/RTO.
