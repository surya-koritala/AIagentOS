# Release-candidate SLO qualification

Every release candidate gets a report; only complete target evidence gets an
eligible report. The evaluator recalculates all nine SLOs from raw counts and
measurements. It does not trust an input `passed` field, and it never turns a
fixture, smoke run, dirty checkout, short window, low-volume sample, mixed
commit, or mixed environment into production evidence.

## Required evidence drop

The protected `agentos-capacity` runner reads four regular, non-symlink JSON
files from the fixed directory configured by the
`AGENTOS_SLO_EVIDENCE_DIR` repository environment variable:

| File | Required origin |
| --- | --- |
| `slo-observation.json` | Export from the intended target deployment for the exact release-candidate commit |
| `resource-soak.json` | Eligible 24-hour `target_resource_soak` report for the same commit and environment |
| `incident-drill.json` | Passing automated incident-control report for the same clean commit |
| `game-day.json` | Eligible bounded human game-day report for the same exact release candidate, clean commit, and environment |

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
| `tenant_isolation` | adversarial attempts, confirmed violations, game-day result and evidence SHA-256 | at least 100 attempts, zero violations, eligible independently reviewed game day with an exact report-hash binding |

Policy and quota rejections are recorded but excluded from LLM/tool success
denominators. Every alert firing must be listed with its bounded name, severity,
UTC firing time, and UTC resolution time. An unresolved alert blocks
eligibility.

## Run and interpret

### Produce the observation

`scripts/slo_observation.py` reads raw range vectors from an existing Prometheus
deployment, or streams an already retained JSON-lines metrics archive. It emits
the exact nine-SLI schema without changing the evaluator or its eligibility
thresholds. Run its schema check in CI:

```bash
python3 scripts/slo_observation.py --validate
```

The printed zero-filled example is enclosed in an `example_only` envelope and
is never a target evidence file. All nine targets fail its eligibility checks.

On the configured qualification host, freeze the deployment manifest,
configuration and workload before the observation window. The deployment JSON
has exactly `schema_version: 1`, `release_candidate`, `source` (`commit`,
`dirty: false`), `environment` (the exact fields described above) and
`prometheus_target` (`job`, `instance`). The configuration and workload digest
fields must match the actual files. The exporter hashes both files before and
after reading measurements; it rejects mismatches. The manifest is the target
operator's retained configuration binding. Every sample must additionally
expose the runtime's compiled source identity as five fixed
`agentos_build_source_sha1{part}` gauges and
`agentos_build_source_verified: 1`. The exporter reconstructs the actual commit
and requires it to match the declared clean source throughout the window.
Missing Git build metadata, dirty tracked source, and mixed builds fail closed.
Provisioning and independent review also verify the installed artifact and
keep the deployment binding valid throughout the window.

```bash
python3 scripts/slo_observation.py \
  --deployment /controlled/evidence/deployment.json \
  --configuration /controlled/frozen/config.toml \
  --dataset /controlled/frozen/workload.json \
  --prometheus https://metrics.example.internal \
  --bearer-file /controlled/credentials/prometheus-read-token \
  --alert-history /controlled/evidence/alertmanager-history.json \
  --window-start 2026-06-01T00:00:00Z \
  --window-end 2026-07-02T00:00:00Z \
  --provider-report /controlled/evidence/provider-openai.json \
  --provider-binding /controlled/evidence/provider-binding.json \
  --restore-report /controlled/evidence/target-remote-backup.json \
  --game-day /controlled/evidence/game-day.json \
  --output /controlled/evidence/slo-observation.json
```

Use a 31-day requested interval to allow the actual scrape boundaries to leave
at least 30 measured days. The output window starts and ends at real retained
sample timestamps, with at most 120 seconds between samples. It rejects missing
sources, stale/duplicate/out-of-order samples, changed series, mixed targets,
counter decreases without a measured process restart and incomplete ledger
time. A restart discards the entire earlier prefix and starts a new baseline
at the first post-restart sample; this newly reported window must independently
cover at least 30 days. The exporter never treats unavailable terminal counters
or unobserved failures before a crash as zero. Availability and durability use
the whole resulting envelope; latency, queue, provider and tool outcomes use
its final daily interval, including at most a few minutes of boundary samples
to cover a full measured day. Counter increases are measured per series before
summation. The continuous healthy-ledger interval resets at every observed restart;
subsecond unhealthy time rounds upward. Histograms use the first finite bucket
covering 95% as a conservative upper bound, without interpolating a better p95.

Prometheus reads are paged into bounded one-hour raw range queries. This avoids
rounding the fractional extrapolation produced by
[Prometheus `increase`](https://prometheus.io/docs/prometheus/latest/querying/functions/#increase)
into supposedly exact event counts. The caller chooses one frozen `job` and
`instance`; extra labels and query warnings are rejected. Requests have bounded
responses/timeouts, redirects are refused, and bearer contents are never
retained or printed. Non-loopback HTTP requires the explicit `--allow-http`
option; HTTPS is the normal target path.

For offline metrics, replace `--prometheus` and `--bearer-file` with
`--metrics-archive /controlled/metrics/day-01.jsonl ...`. Each bounded line is
an object containing exactly `schema_version: 1`, `binding`, `collected_at`
(UTC `Z`) and `samples`. Each sample has exactly `name`, `labels` and `value`.
`binding` contains the manifest's `source`, `environment_id`,
`configuration_sha256` and `dataset_sha256`. Archive files must be regular,
non-symlink files ordered by actual sample time; at most 64 files are accepted,
with streaming reads rather than retaining the month in memory.

The alert-history input must retain notifications throughout the same interval.
It contains exactly `schema_version: 1`, the same `binding`, `coverage` and
`notifications`. Coverage has `start`, `end`, `notification_failures: 0` and
`truncated: false`; the timestamps must enclose the output window.
`notifications` contains the actual version-4 Alertmanager webhook payloads,
including resolved deliveries and fingerprints. Duplicate deliveries merge by
fingerprint plus firing timestamp, preserving distinct firings with the same
name. Truncated messages, failed delivery coverage, unsupported severity,
changed identity and unresolved firings overlapping from before the window
are rejected. Configure a durable history receiver with
[`send_resolved: true` and untruncated webhook notifications](https://prometheus.io/docs/alerting/latest/configuration/#webhook_config)
before the target campaign. A current `/api/v2/alerts` response is insufficient
to reconstruct a month of firing history. Receiver retention, delivery coverage
and archive custody remain part of the target deployment and review.

An unresolved firing inside the window is preserved as `resolved_at: null`.
The exporter writes the observation and exits nonzero with a diagnostic; the
existing evaluator then records `unresolved_alerts`. It never drops the firing
to obtain an eligible report. The output refuses to overwrite an existing file.

Provider, restore and game-day inputs are optional only when generating an
explicitly ineligible observation. Missing evidence leaves the corresponding
qualification field false. Provider evidence requires an additional binding
with exactly `schema_version: 1`,
`qualification_class: target_live_provider_evidence_binding`,
`release_candidate`, `source`, `environment_id`, `configuration_sha256`,
`dataset_sha256`, `provider`, `model` and `provider_report_sha256`. Produce and
retain that identity binding alongside the raw protected-workflow provider
report; it must identify this exact target and the digest of the report's bytes.
The exporter reuses the campaign's provider validation and checks the model.
Restore evidence must be the exact-RC target remote-backup report, including
all required checks and actual recovery measurements. Game-day eligibility is
recomputed by the existing release evaluator, with the exact report hash and
frozen configuration. No command-line switch can declare a prerequisite passed.

The producer and schema fixtures do not constitute a 30-day target run.
Infrastructure, recorded target/provider measurements, durable alert history,
restore and independent human review remain required for promotion.

Dispatch `Release candidate SLO qualification` from the exact existing
`vX.Y.Z-rc.N` or `vX.Y.Z` tag. The workflow proves that the tag resolves to the
checked-out commit before it reads evidence.

For an offline review of an already controlled evidence drop:

```bash
python3 scripts/release_slo_qualification.py \
  --observation /controlled/evidence/slo-observation.json \
  --resource-soak /controlled/evidence/resource-soak.json \
  --incident-drill /controlled/evidence/incident-drill.json \
  --game-day /controlled/evidence/game-day.json \
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

The human game-day prerequisite is independently rechecked for its exact
scenario inventory, one-hour minimum and staffed roles, RPO/RTO and runbook
measurements, tenant-boundary outcomes, separate approved review, child
evidence hashes, and zero findings. See
[Human incident game-day qualification](GAME_DAY_QUALIFICATION.md).

Even an eligible SLO report keeps `production_claim_allowed: false`. Release
publication, supported-platform gates, external Alertmanager delivery, security
qualification, and independent reviewer approval remain separate requirements.
Missing target infrastructure or evidence is `not_run`/failed, never a pass.
