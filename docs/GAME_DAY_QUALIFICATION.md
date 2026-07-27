# Human incident game-day qualification

This gate records a real, staffed incident exercise against one exact release
candidate on the target single-node Linux deployment. It covers the six
incident runbooks, recalculates RPO/RTO and completion results from the UTC
timeline, binds an independent review to the exact observation bytes, and emits
a bounded report safe for CI retention.

The validator does **not** run the exercise, authenticate a person's identity,
or make the product production-ready by itself. Missing people, raw evidence,
or independent approval is a failed/not-run gate, never a synthetic pass.

## Protected inputs

Set `AGENTOS_GAME_DAY_EVIDENCE_DIR` on the `capacity-qualification`
environment to an operator-controlled directory containing two regular,
non-symlink files:

| File | Contents |
| --- | --- |
| `game-day-observation.json` | Exact-RC source/environment, exercise window and participants, plus the measured timeline and evidence digest for every scenario |
| `game-day-review.json` | A separate review bound to the observation SHA-256, with an externally retained attestation digest |

Keep actor identifiers, raw timelines, findings, communications, and the
detached review attestation in that protected store. The workflow uploads only
`game-day.json`, which contains summary measurements and hashes.

The observation must contain exactly:

```json
{
  "schema_version": 1,
  "qualification_class": "human_incident_game_day_observation",
  "release_candidate": "v1.0.0-rc.1",
  "source": {"commit": "<40 lowercase hex>", "dirty": false},
  "environment": {
    "environment_id": "staging-x64-8cpu-32g",
    "deployment_mode": "single-node",
    "os": "linux",
    "arch": "x86_64",
    "configuration_sha256": "<64 lowercase hex>"
  },
  "exercise": {
    "exercise_id": "gameday-2026-01",
    "started_at": "2026-01-31T12:00:00Z",
    "ended_at": "2026-01-31T18:00:00Z",
    "facilitator_id": "facilitator-01",
    "participants": [
      {"participant_id": "commander-01", "role": "incident_commander"},
      {"participant_id": "operator-01", "role": "operator"},
      {"participant_id": "observer-01", "role": "observer"}
    ]
  },
  "scenarios": []
}
```

The exercise must last at least one hour. Participant identifiers must be
unique, and the roles `incident_commander`, `operator`, and `observer` are
mandatory. The facilitator may not approve their own exercise.

`scenarios` must contain these entries in order:

1. `credential-compromise`
2. `tenant-leak`
3. `malicious-package`
4. `node-loss`
5. `corrupt-database`
6. `provider-outage`

Each scenario contains `scenario_id`, `started_at`, `detected_at`,
`mitigated_at`, `recovered_at`, `target_rto_seconds`, `target_rpo_seconds`,
`observed_data_loss_seconds`, `runbook_steps_total`,
`runbook_steps_completed`, `unexpected_tenant_accesses`,
`unresolved_findings`, and `evidence_sha256`. Timestamps must be ordered inside
the exercise window. Eligibility requires positive recovery time, observed RTO
and RPO within their targets, every runbook step complete, zero unexpected
tenant access, and zero unresolved findings.

The independent review must contain exactly:

```json
{
  "schema_version": 1,
  "qualification_class": "independent_human_game_day_review",
  "release_candidate": "v1.0.0-rc.1",
  "source": {"commit": "<same 40 lowercase hex>", "dirty": false},
  "environment_id": "staging-x64-8cpu-32g",
  "observation_sha256": "<SHA-256 of exact observation bytes>",
  "reviewer_id": "reviewer-01",
  "reviewed_at": "2026-02-01T00:00:00Z",
  "decision": "approved",
  "review_attestation_sha256": "<64 lowercase hex>",
  "scenario_ids": [
    "credential-compromise",
    "tenant-leak",
    "malicious-package",
    "node-loss",
    "corrupt-database",
    "provider-outage"
  ],
  "checks": {
    "exact_release_candidate_exercised": true,
    "timeline_and_measurements_reviewed": true,
    "runbook_steps_reviewed": true,
    "rpo_rto_results_reviewed": true,
    "tenant_boundaries_preserved": true,
    "raw_evidence_retained": true
  },
  "open_findings": []
}
```

The review must occur after the exercise and within 30 days. The reviewer ID
must differ from the facilitator and every participant. Protected environment
approval and the external attestation process remain responsible for verifying
that these identifiers belong to real, authorized people.

## Execute the gate

Dispatch `Human incident game-day qualification` from an existing
`vX.Y.Z-rc.N` or `vX.Y.Z` tag. The workflow proves the tag resolves to its exact
checked-out commit before reading the evidence.

An operator can validate an already controlled evidence drop locally:

```bash
python3 scripts/game_day_qualification.py \
  --observation /controlled/evidence/game-day-observation.json \
  --review /controlled/evidence/game-day-review.json \
  --expected-commit 0123456789abcdef0123456789abcdef01234567 \
  --expected-environment staging-x64-8cpu-32g \
  --release-candidate v1.0.0-rc.1 \
  --output target/qualification/game-day.json \
  --require-eligible
```

Copy the exact derived `game-day.json` into the protected release-SLO evidence
drop. Its SHA-256 must be stored in
`slo-observation.json.slis.tenant_isolation.game_day_evidence_sha256`. The
release-SLO evaluator independently checks its critical measurements and
requires the hashes to match.

Even an eligible game-day report sets `production_claim_allowed: false`.
Release SLOs, the 24-hour soak, security and deployment qualification, and
independent release approval are separate gates.
