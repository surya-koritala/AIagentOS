# Protected qualification infrastructure

The external qualification workflows use repository-owned runners, protected
environments, provisioned models, target object stores, or human evidence.
GitHub-hosted fixtures cannot substitute for those systems.

Every protected workflow starts with a GitHub-hosted dispatch preflight. The
preflight always retains a small exact-source JSON report and fails before a
self-hosted job is queued unless the corresponding repository variable is
exactly `true`.

`status: ready` means only that an operator explicitly enabled dispatch. It
does **not** prove that a runner is online, an environment is configured, a
secret exists, or a qualification passed. Every preflight report therefore
sets:

- `readiness_scope` to `dispatch_configuration_only`;
- `infrastructure_verified` to `false`; and
- `production_claim_allowed` to `false`.

The protected job remains responsible for validating its inputs, binding its
result to the exact source commit or release-candidate tag, and publishing
eligible evidence.

## Dispatch gates

| Profiles | Repository enable variable | Protected environment | Required runner label |
| --- | --- | --- | --- |
| Capacity baseline, resource soak, target remote backup, release SLO, game day, Phase 1 promotion | `AGENTOS_CAPACITY_QUALIFICATION_ENABLED` | `capacity-qualification` | `agentos-capacity` |
| Phase 1 independent review | `AGENTOS_PHASE1_REVIEW_ENABLED` | `phase1-review` | `agentos-review` |
| Real GGUF/on-device model | `AGENTOS_MODEL_QUALIFICATION_ENABLED` | `model-qualification` | `agentos-model` |
| Destructive target-storage profile | `AGENTOS_DESTRUCTIVE_STORAGE_QUALIFICATION_ENABLED` | `destructive-storage-qualification` | `agentos-destructive-storage` |
| External deletion and retention | `AGENTOS_EXTERNAL_DATA_QUALIFICATION_ENABLED` | `external-data-qualification` | `agentos-external-data` |

The retained preflight report lists the required environment variable and
secret **names** for its selected profile. It never reads, renders, or uploads
secret values, model paths, evidence-directory contents, or credentials.

## Provisioning order

1. Create the protected environment named in the table.
2. Register a repository-owned Linux x64 runner with every label listed in the
   selected profile's preflight report.
3. Configure the environment variables and secrets named in that report.
4. Apply required reviewers and deployment-branch restrictions to the
   environment.
5. Set the repository enable variable to the exact lowercase value `true`.
6. Dispatch the qualification for an immutable source commit or existing
   release-candidate tag and review the resulting protected artifact.
7. Set the enable variable back to `false` when the runner or protected inputs
   are intentionally unavailable.

The `phase1-review` environment and `agentos-review` runner are a separate
trust boundary. Set `AGENTOS_PHASE1_REVIEW_DIR` to a reviewer-controlled
directory containing only `phase1-review-observation.json`. The separately
authenticated campaign workflow supplies the signed `campaign.json` and its
bounded reports. The authenticated GitHub actor who dispatches the review must
be distinct from every `operator_id` derived from the campaign and underlying
evidence workflows. A rerun is deliberately rejected; a failed review must use
a fresh dispatch so the actor and attempt cannot become ambiguous.

Do not set an enable flag merely to make a workflow advance. If the protected
job then waits for a runner or approval, that is unverified external state, not
production evidence.

## Local contract checks

Validate the checked-in profile catalog:

```bash
python3 scripts/protected_qualification_plan.py --validate
```

Generate a disabled preflight example without contacting external systems:

```bash
python3 scripts/protected_qualification_plan.py \
  --profile capacity-baseline \
  --enabled false \
  --commit 0000000000000000000000000000000000000000 \
  --output /tmp/agentos-protected-qualification-plan.json
```

The example must report `not_run`; it is not qualification evidence.
