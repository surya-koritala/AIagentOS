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

## GitHub workflow, reviewer, and artifact authentication

The protected promotion job does not trust copied workflow fields in
`campaign.json`. It deterministically derives a request plan, queries GitHub's
specific workflow-run-attempt endpoint for every unique run/attempt pair, and
requires the API response to match the exact repository, workflow path, head
commit, successful conclusion, attempt number, and update time in the
campaign. The campaign's Linux CLI run must also equal the run ID used to
download the signed candidate bundle.

The job then downloads every report from its exact expected GitHub artifact
name. The downloaded JSON bytes and the protected evidence-store copy must
both match the campaign SHA-256. Missing, expired, ambiguous, renamed, or
tampered artifacts fail closed.

`scripts/phase1_workflow_provenance.py` retains a bounded
`phase1-workflow-provenance.json` containing only the authenticated run IDs,
attempts, workflow paths, artifact names, and report digests. The final Phase 1
decision hash-binds that report.

The independent review is authenticated separately. A reviewer-controlled
`phase1-review` environment and `agentos-review` runner execute
`phase1-independent-review.yml` from the exact annotated RC tag. The workflow:

- rejects reruns and accepts only attempt 1 from a fresh `workflow_dispatch`;
- requires the authenticated GitHub actor to match the reviewer record and to
  differ from every campaign operator;
- hash-binds the reviewer-controlled observation and exact campaign;
- creates and keyless-signs `phase1-review.json`; and
- retains the review and Sigstore bundle in one deterministic artifact.

Promotion receives that review workflow run ID, queries GitHub's specific
attempt API, and requires the trusted repository, workflow path, tag commit,
event, successful conclusion, actor, and triggering actor to match the signed
review. It downloads the exact named artifact and verifies its bytes and
keyless signature. `scripts/phase1_review_provenance.py` emits a bounded
`phase1-review-provenance.json` without the reviewer identity. The promotion
decision hash-binds both provenance reports, and the publisher signs and
attests the runtime report, both provenance reports, and the promotion report.
Before signing, the hosted publisher independently downloads the exact review
artifact again, rechecks the specific GitHub attempt and both actor identities,
recomputes its digest, and re-verifies the review workflow's keyless signature.

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

The live-provider plan and every promoted provider result must have the same
run ID, attempt, commit, and completion time. The protected promotion job
authenticates those values against GitHub before trusting the campaign.
`workflow_completed_at` records the specific completed attempt's GitHub API
`updated_at` value; the gate parses and compares those instants exactly.

## Independent review

The independent reviewer first writes
`phase1-review-observation.json` in the reviewer-controlled evidence store,
only after every listed workflow completed. It repeats the exact release
candidate, source, profile, environments, and operator inventory; binds the
byte-for-byte SHA-256 of `campaign.json`; and contains:

- the reviewer's GitHub login, which must equal the authenticated workflow
  actor and differ from every operator and reserved harness identity;
- an `approved` decision no later than 30 days after the last workflow result;
- an empty `open_findings` list;
- a detached review-attestation SHA-256; and
- every required review check set to `true`.

The required checks are exported by
`scripts/phase1_promotion_qualification.py` as `REVIEW_CHECK_IDS`. They cover
workflow provenance, artifact digests, CLI signatures and fresh-host behavior,
provider/model evidence, target recovery, destructive storage, external
deletion, the 24-hour soak, SLOs, game day, and unresolved findings.

The protected observation has exactly this shape. Replace the example values,
set `campaign_sha256` from the exact file bytes, and set a check to `true` only
after the reviewer has inspected its raw evidence:

```json
{
  "schema_version": 1,
  "qualification_class": "independent_restricted_phase1_review_observation",
  "release_candidate": "v0.4.0-rc.1",
  "source": {
    "commit": "0000000000000000000000000000000000000000",
    "dirty": false
  },
  "profile_id": "single-node-linux-rootless-container-cli",
  "target_environment_id": "target-linux-rootless-1",
  "on_device_environment_id": "gguf-cpu-runner-1",
  "campaign_sha256": "0000000000000000000000000000000000000000000000000000000000000000",
  "operator_ids": ["operator-1"],
  "reviewer_id": "independent-reviewer",
  "reviewed_at": "2026-01-01T00:00:00Z",
  "decision": "approved",
  "checks": {
    "exact_release_candidate_and_commit": true,
    "workflow_run_provenance_verified": true,
    "artifact_digests_verified": true,
    "linux_cli_signatures_and_fresh_host_reviewed": true,
    "promoted_provider_contracts_reviewed": true,
    "on_device_model_and_resource_limits_reviewed": true,
    "remote_backup_retention_and_recovery_reviewed": true,
    "destructive_storage_rpo_rto_reviewed": true,
    "external_deletion_and_retention_reviewed": true,
    "resource_soak_and_slo_reviewed": true,
    "human_game_day_reviewed": true,
    "no_open_findings": true
  },
  "open_findings": []
}
```

`scripts/phase1_independent_review.py` validates that observation and creates
schema-v2 `phase1-review.json` with the exact GitHub run identity. The review's
`review_attestation_sha256` is the digest of the protected observation. Raw
observations, credentials, model weights, participant identities, and reviewer
identity proof stay in the reviewer/operator-controlled stores. Only bounded
decisions and digests enter the final release bundle.

## Promotion sequence

1. Create one signed annotated `vX.Y.Z-rc.N` tag.
2. Let `linux-cli-rc.yml` finish successfully and retain its run ID. It does
   not publish a release.
3. Run every protected qualification against that exact tag/commit and target
   profile.
4. Copy only their bounded JSON reports into the protected evidence directory.
5. Construct `campaign.json` from GitHub run metadata and exact file digests.
6. Copy `campaign.json` into the separately controlled Phase 1 review store.
   Have an independent reviewer verify the raw evidence and write the
   hash-bound `phase1-review-observation.json`.
7. Configure the `phase1-review` environment and
   `AGENTOS_PHASE1_REVIEW_DIR`, then have that reviewer dispatch
   `phase1-independent-review.yml` using the RC tag as the workflow ref.
   Retain the successful fresh run ID; do not rerun it.
8. Configure `AGENTOS_PHASE1_EVIDENCE_DIR` in the
   `capacity-qualification` environment and dispatch
   `phase1-promotion-qualification.yml` **using the RC tag as the workflow
   ref**, the originating Linux CLI run ID, authenticated review run ID, and
   target environment ID.
9. The workflow authenticates and signature-verifies the exact independent
   review, then queries GitHub for every exact evidence workflow attempt,
   downloads every expected report artifact, and requires those bytes to match
   the protected evidence and campaign digests.
10. The workflow revalidates the signed CLI bundle, campaign, review, every
    report, both authenticated provenance reports, cross-report hashes, and
    tag. Only then does it replace preliminary checksums/signatures, attest the
    complete bundle, and create the immutable GitHub prerelease.

Missing files, a disabled runner, an unapproved environment, mixed commits,
failed runs, stale review, unknown fields, duplicate JSON keys, symlinks,
digest mismatches, unsupported providers, or one false proof leave the
candidate unpublished.

## Local contract check

```bash
python3 scripts/phase1_promotion_qualification.py --validate
python3 scripts/phase1_workflow_provenance.py --validate
python3 scripts/phase1_independent_review.py --validate
python3 scripts/phase1_review_provenance.py --validate
```

A passing Phase 1 decision sets `phase1_release_candidate_ready: true`, but
keeps `production_claim_allowed: false`. Provider/client qualification,
distributed control-plane completion, independent product security review,
and final v1 release governance remain separate gates.
