# Release-candidate SLO qualification

Every release candidate gets a report; only complete target evidence gets an
eligible report. The evaluator recalculates all nine SLOs from raw counts and
measurements. It does not trust an input `passed` field, and it never turns a
fixture, smoke run, dirty checkout, short window, low-volume sample, mixed
commit, or mixed environment into production evidence.

## Required evidence drop

The protected `agentos-capacity` runner reads three regular, non-symlink JSON
files from the fixed directory configured by the
`AGENTOS_SLO_EVIDENCE_DIR` repository environment variable:

| File | Required origin |
| --- | --- |
| `slo-observation.json` | Export from the intended target deployment for the exact release-candidate commit |
| `resource-soak.json` | Eligible 24-hour `target_resource_soak` report for the same commit and environment |
| `incident-drill.json` | Passing automated incident-control report for the same clean commit |

The workflow never uploads these raw files. It retains only the bounded
calculated report and their SHA-256 digests. Keep the raw evidence in the
operator's controlled evidence store.

The observation has this top-level schema:

```json
{
  "schema_version": 1,
  "qualification_class": "target_release_candidate_slo_observation",
  "release_candidate": "v1.0.0-rc.1",
  "source": {"commit": "<40 lowercase hex>", "dirty": false},
  "environment": {
    "environment_id": "staging-x64-8cpu-32g",
    "deployment_mode": "single-node",
    "os": "linux",
    "arch": "x86_64",
    "hardware": "8cpu-32g-nvme",
    "provider": "operator-approved-provider",
    "model": "operator-approved-model",
    "configuration_sha256": "<64 lowercase hex>",
    "dataset_sha256": "<64 lowercase hex>"
  },
  "window": {
    "start": "2026-01-01T00:00:00Z",
    "end": "2026-01-31T00:00:00Z"
  },
  "alert_firings": [],
  "slis": {}
}
```

`slis` must contain exactly the nine identifiers below. Unknown and missing
fields are errors, all counters are non-negative integers, measurements must be
finite, timestamps must be UTC, and each claimed sub-window must fit inside the
30-day observation envelope.

| SLI object | Raw fields | Eligibility gate |
| --- | --- | --- |
| `availability` | `window_seconds`, `success`, `failed`, `timed_out`, `cancelled` | 30 days, at least 100,000 eligible requests, at least 99.5% success |
| `syscall_latency` | `window_seconds`, control/agent p95 seconds and request counts | 24 hours, at least 10,000 control and 1,000 agent requests, p95 below 1s/30s |
| `queue_wait` | `window_seconds`, `wait_seconds_delta`, `admissions_delta`, `starvation_delta` | 24 hours, at least 10,000 admissions, mean below 250ms, zero starvation |
| `llm_success` | `window_seconds`, `success`, `failed`, `timed_out`, `cancelled`, `policy_quota_rejected`, live-provider pass and artifact SHA-256 | 24 hours, at least 1,000 eligible requests, at least 99% success, live-provider qualification passes |
| `tool_success` | `window_seconds`, `success`, `failed`, `timed_out`, `cancelled`, `policy_quota_rejected` | 24 hours, at least 1,000 eligible requests, at least 99.5% success |
| `auth_sandbox_denial` | `adversarial_attempts`, `unexpected_allows` | at least 100 attempts, zero unexpected allows |
| `data_durability` | healthy/unhealthy ledger seconds, verified-backup age, restore result | 30 healthy days, zero unhealthy seconds, backup no older than 25h, restore passes |
| `checkpoint_recovery` | `attempted`, `recovered`, `safe_rejected`, cross-tenant recoveries | at least 100 fully accounted attempts, zero cross-tenant recovery |
| `tenant_isolation` | adversarial attempts, confirmed violations, game-day result and evidence SHA-256 | at least 100 attempts, zero violations, game day completed with bound evidence |

Policy and quota rejections are recorded but excluded from LLM/tool success
denominators. Every alert firing must be listed with its bounded name, severity,
UTC firing time, and UTC resolution time. An unresolved alert blocks
eligibility.

## Run and interpret

Dispatch `Release candidate SLO qualification` from the exact existing
`vX.Y.Z-rc.N` or `vX.Y.Z` tag. The workflow proves that the tag resolves to the
checked-out commit before it reads evidence.

For an offline review of an already controlled evidence drop:

```bash
python3 scripts/release_slo_qualification.py \
  --observation /controlled/evidence/slo-observation.json \
  --resource-soak /controlled/evidence/resource-soak.json \
  --incident-drill /controlled/evidence/incident-drill.json \
  --expected-commit 0123456789abcdef0123456789abcdef01234567 \
  --expected-environment staging-x64-8cpu-32g \
  --release-candidate v1.0.0-rc.1 \
  --output target/qualification/release-slo-report.json \
  --require-eligible
```

The output sets `report_generated: true` whenever all input schemas are valid.
Target failures produce a report with `release_slo_proof_eligible: false` and
named blockers; `--require-eligible` then exits non-zero. Malformed or
misclassified evidence fails before a report can be trusted.

Even an eligible SLO report keeps `production_claim_allowed: false`. Release
publication, supported-platform gates, external Alertmanager delivery, security
qualification, and independent reviewer approval remain separate requirements.
Missing target infrastructure or evidence is `not_run`/failed, never a pass.
