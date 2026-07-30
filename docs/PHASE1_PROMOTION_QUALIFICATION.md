# Restricted Phase 1 promotion qualification

Phase 1 is not complete merely because one release workflow, provider, backup,
or benchmark is green. The restricted Linux CLI release candidate may be
published only after one decision binds every required result to the same
annotated release-candidate tag, clean commit, supported profile, reviewed
workflow run, and target environment.

The protected `Restricted Phase 1 promotion and publication` workflow is the
only workflow that publishes this prerelease. The tag-triggered
`Restricted Linux CLI release candidate` workflow builds, tests, keyless-signs,
and retains a candidate bundle, but deliberately does not create a GitHub
release.

## Required evidence

The protected evidence directory contains these bounded JSON files:

| Evidence ID | File | Required proof |
| --- | --- | --- |
| `linux-cli-rc` | `linux-cli-rc-qualification.json` | Reproducible signed CLI, governed runtime, restart, encrypted backup, fresh-host restore, and released-schema upgrade |
| `live-provider-plan` | `live-provider-plan.json` | Exact-source inventory of every promoted provider |
| `provider:<id>` | `provider-<id>.json` | Successful real contract probe for each promoted provider |
| `on-device` | `on-device.json` | Real provisioned GGUF CPU/resource/cancellation result |
| `target-remote-backup` | `target-remote-backup.json` | Immutable target object-store publication and measured recovery |
| `storage-profile` | `storage-profile.json` | Independently reviewed power-loss, torn-write, and device-loss profile |
| `external-deletion` | `external-deletion.json` | Independently reviewed external deletion and retention lifecycle |
| `resource-soak` | `resource-soak.json` | At least 24 hours of eligible resource/leak evidence |
| `release-slo` | `release-slo-report.json` | All nine exact-RC SLO targets passed |
| `game-day` | `game-day.json` | Independently reviewed human execution of all incident scenarios |

The promoted provider set must include Ollama, vLLM, and at least one hosted
provider. Providers not in that exact set remain below production-qualified
maturity and are not advertised by the restricted candidate.

The release SLO report must contain the SHA-256 digests of the exact retained
resource-soak and game-day reports. A report from another release, commit,
environment, workflow run, or run attempt is rejected.

## Campaign manifest

`campaign.json` is a bounded inventory, not an approval. It contains exactly:

```json
{
  "schema_version": 1,
  "qualification_class": "restricted_phase1_evidence_campaign",
  "release_candidate": "v0.4.0-rc.1",
  "source": {
    "commit": "0000000000000000000000000000000000000000",
    "dirty": false
  },
  "profile_id": "single-node-linux-rootless-container-cli",
  "target_environment_id": "target-linux-rootless-1",
  "on_device_environment_id": "gguf-cpu-runner-1",
  "promoted_providers": ["openai", "ollama", "vllm"],
  "operator_ids": ["operator-1"],
  "artifacts": []
}
```

`artifacts` is sorted by `evidence_id`. Every entry contains exactly:

```json
{
  "evidence_id": "linux-cli-rc",
  "path": "linux-cli-rc-qualification.json",
  "sha256": "0000000000000000000000000000000000000000000000000000000000000000",
  "workflow_path": ".github/workflows/linux-cli-rc.yml",
  "workflow_run_id": 1,
  "workflow_run_attempt": 1,
  "workflow_head_sha": "0000000000000000000000000000000000000000",
  "workflow_conclusion": "success",
  "workflow_completed_at": "2026-01-01T00:00:00Z"
}
```

The protected operator obtains run metadata from the GitHub Actions API, not
from job summaries or copied text. The live-provider plan and every promoted
provider result must have the same run ID, attempt, commit, and completion
time.

## Independent review

`phase1-review.json` is created only after every listed workflow completed. It
repeats the exact release candidate, source, profile, environments, and
operator inventory; binds the byte-for-byte SHA-256 of `campaign.json`; and
contains:

- an authenticated reviewer identity distinct from every operator and
  qualification harness identity;
- an `approved` decision no later than 30 days after the last workflow result;
- an empty `open_findings` list;
- a detached review-attestation SHA-256; and
- every required review check set to `true`.

The required checks are exported by
`scripts/phase1_promotion_qualification.py` as `REVIEW_CHECK_IDS`. They cover
workflow provenance, artifact digests, CLI signatures and fresh-host behavior,
provider/model evidence, target recovery, destructive storage, external
deletion, the 24-hour soak, SLOs, game day, and unresolved findings.

Raw observations, credentials, model weights, participant identities, and
reviewer identity proof stay in the operator-controlled evidence store. Only
the bounded decision and its digests are uploaded.

## Promotion sequence

1. Create one signed annotated `vX.Y.Z-rc.N` tag.
2. Let `linux-cli-rc.yml` finish successfully and retain its run ID. It does
   not publish a release.
3. Run every protected qualification against that exact tag/commit and target
   profile.
4. Copy only their bounded JSON reports into the protected evidence directory.
5. Construct `campaign.json` from authenticated GitHub run metadata and exact
   file digests.
6. Have an independent reviewer verify the raw evidence and write the
   hash-bound `phase1-review.json`.
7. Configure `AGENTOS_PHASE1_EVIDENCE_DIR` in the
   `capacity-qualification` environment and dispatch
   `phase1-promotion-qualification.yml` **using the RC tag as the workflow
   ref**, the originating Linux CLI run ID, and the target environment ID.
8. The workflow revalidates the signed CLI bundle, campaign, review, every
   report, cross-report hashes, and tag. Only then does it replace preliminary
   checksums/signatures, attest the complete bundle, and create the immutable
   GitHub prerelease.

Missing files, a disabled runner, an unapproved environment, mixed commits,
failed runs, stale review, unknown fields, duplicate JSON keys, symlinks,
digest mismatches, unsupported providers, or one false proof leave the
candidate unpublished.

## Local contract check

```bash
python3 scripts/phase1_promotion_qualification.py --validate
```

A passing Phase 1 decision sets `phase1_release_candidate_ready: true`, but
keeps `production_claim_allowed: false`. Provider/client qualification,
distributed control-plane completion, independent product security review,
and final v1 release governance remain separate gates.
