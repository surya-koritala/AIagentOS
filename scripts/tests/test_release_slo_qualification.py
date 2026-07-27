import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from release_slo_qualification import (  # noqa: E402
    QualificationError,
    TARGET_IDS,
    evaluate,
    validate_contract,
)


COMMIT = "a" * 40
ENVIRONMENT = "staging-x64-8cpu-32g"
RELEASE_CANDIDATE = "v1.0.0-rc.1"
START = "2026-01-01T00:00:00Z"
END = "2026-01-31T00:00:00Z"
SCENARIO_IDS = (
    "credential-compromise",
    "tenant-leak",
    "malicious-package",
    "node-loss",
    "corrupt-database",
    "provider-outage",
)
REVIEW_CHECK_IDS = (
    "exact_release_candidate_exercised",
    "timeline_and_measurements_reviewed",
    "runbook_steps_reviewed",
    "rpo_rto_results_reviewed",
    "tenant_boundaries_preserved",
    "raw_evidence_retained",
)


def valid_observation():
    return {
        "schema_version": 1,
        "qualification_class": "target_release_candidate_slo_observation",
        "release_candidate": RELEASE_CANDIDATE,
        "source": {"commit": COMMIT, "dirty": False},
        "environment": {
            "environment_id": ENVIRONMENT,
            "deployment_mode": "single-node",
            "os": "linux",
            "arch": "x86_64",
            "hardware": "8cpu-32g-nvme",
            "provider": "qualified-provider",
            "model": "qualified-model",
            "configuration_sha256": "b" * 64,
            "dataset_sha256": "c" * 64,
        },
        "window": {"start": START, "end": END},
        "alert_firings": [
            {
                "name": "AgentOSProviderQueueSaturated",
                "severity": "warning",
                "fired_at": "2026-01-15T00:00:00Z",
                "resolved_at": "2026-01-15T00:10:00Z",
            }
        ],
        "slis": {
            "availability": {
                "window_seconds": 2_592_000,
                "success": 199_100,
                "failed": 500,
                "timed_out": 200,
                "cancelled": 200,
            },
            "syscall_latency": {
                "window_seconds": 86_400,
                "control_p95_seconds": 0.25,
                "control_requests": 20_000,
                "agent_p95_seconds": 12.0,
                "agent_requests": 2_000,
            },
            "queue_wait": {
                "window_seconds": 86_400,
                "wait_seconds_delta": 1_000.0,
                "admissions_delta": 10_000,
                "starvation_delta": 0,
            },
            "llm_success": {
                "window_seconds": 86_400,
                "success": 1_990,
                "failed": 10,
                "timed_out": 0,
                "cancelled": 0,
                "policy_quota_rejected": 50,
                "live_provider_qualification_passed": True,
                "live_provider_evidence_sha256": "d" * 64,
            },
            "tool_success": {
                "window_seconds": 86_400,
                "success": 1_995,
                "failed": 5,
                "timed_out": 0,
                "cancelled": 0,
                "policy_quota_rejected": 25,
            },
            "auth_sandbox_denial": {
                "adversarial_attempts": 200,
                "unexpected_allows": 0,
            },
            "data_durability": {
                "continuous_ledger_healthy_seconds": 2_592_000,
                "ledger_unhealthy_seconds": 0,
                "latest_verified_backup_age_seconds": 3_600,
                "restore_drill_passed": True,
            },
            "checkpoint_recovery": {
                "attempted": 100,
                "recovered": 99,
                "safe_rejected": 1,
                "cross_tenant_recoveries": 0,
            },
            "tenant_isolation": {
                "adversarial_attempts": 200,
                "confirmed_violations": 0,
                "game_day_completed": True,
                "game_day_evidence_sha256": "e" * 64,
            },
        },
    }


def valid_soak():
    return {
        "schema_version": 1,
        "qualification_class": "target_resource_soak",
        "production_claim_allowed": False,
        "resource_soak_proof_eligible": True,
        "build_profile": "release",
        "smoke_scaled": False,
        "source": {
            "commit": COMMIT,
            "dirty": False,
            "rustc": "rustc 1.97.1 (fixture)",
        },
        "environment": {"environment_id": ENVIRONMENT, "os": "linux"},
        "configuration": {"duration_seconds": 86_400},
        "result": {
            "passed": True,
            "elapsed_seconds": 86_400,
            "checks": {"resources_bounded": True, "server_recovers": True},
            "samples": [{"sample": index} for index in range(1_000)],
        },
    }


def valid_incident():
    return {
        "schema_version": 1,
        "qualification_class": "automated_incident_drill_fixture",
        "proof_scope": "automated_technical_controls_only",
        "automated_drill_passed": True,
        "passed": True,
        "production_claim_allowed": False,
        "source": {"commit": COMMIT, "dirty": False},
        "scenarios": [
            {
                "scenario_id": scenario_id,
                "passed": True,
                "commands": [
                    {
                        "command_id": f"{scenario_id}.control",
                        "passed": True,
                        "evidence_valid": True,
                    }
                ],
            }
            for scenario_id in SCENARIO_IDS
        ],
    }


def valid_game_day():
    return {
        "schema_version": 1,
        "suite": "agentos-v1-human-game-day",
        "generated_at": "2026-02-01T00:00:00Z",
        "qualification_class": "exact_release_candidate_human_game_day",
        "proof_scope": "human_runbook_execution_and_independent_review",
        "release_candidate": RELEASE_CANDIDATE,
        "source": {"commit": COMMIT, "dirty": False},
        "environment": {
            "environment_id": ENVIRONMENT,
            "deployment_mode": "single-node",
            "os": "linux",
            "arch": "x86_64",
            "configuration_sha256": "3" * 64,
        },
        "exercise": {
            "exercise_id": "gameday-2026-01",
            "started_at": "2026-01-31T12:00:00Z",
            "ended_at": "2026-01-31T18:00:00Z",
            "duration_seconds": 21_600,
            "participant_count": 3,
            "participant_roles": [
                "incident_commander",
                "observer",
                "operator",
            ],
        },
        "evidence": {
            "observation_sha256": "4" * 64,
            "independent_review_sha256": "5" * 64,
            "review_attestation_sha256": "6" * 64,
        },
        "review": {
            "reviewed_at": "2026-02-01T00:00:00Z",
            "reviewer_independent": True,
            "decision": "approved",
            "reviewed_checks": {check_id: True for check_id in REVIEW_CHECK_IDS},
            "open_finding_count": 0,
            "checks": {
                "reviewer_independent": True,
                "review_approved": True,
                "every_review_check_passed": True,
                "zero_open_findings": True,
            },
            "passed": True,
        },
        "scenarios": [
            {
                "scenario_id": scenario_id,
                "elapsed_seconds": 2_100,
                "rto_seconds": 2_100,
                "target_rto_seconds": 3_600,
                "observed_data_loss_seconds": 0,
                "target_rpo_seconds": 300,
                "runbook_steps_total": 8,
                "runbook_steps_completed": 8,
                "unexpected_tenant_accesses": 0,
                "unresolved_findings": 0,
                "evidence_sha256": "7" * 64,
                "checks": {
                    "positive_recovery_interval": True,
                    "rto_met": True,
                    "rpo_met": True,
                    "all_runbook_steps_completed": True,
                    "zero_unexpected_tenant_accesses": True,
                    "zero_unresolved_findings": True,
                },
                "failed_checks": [],
                "passed": True,
            }
            for scenario_id in SCENARIO_IDS
        ],
        "failed_scenarios": [],
        "eligibility_blockers": [],
        "passed": True,
        "human_game_day_completed": True,
        "game_day_proof_eligible": True,
        "production_claim_allowed": False,
        "caveats": ["fixture for release SLO validator regression"],
    }


class EvidenceWorkspace:
    def __init__(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.observation = self.root / "observation.json"
        self.soak = self.root / "soak.json"
        self.incident = self.root / "incident.json"
        self.game_day = self.root / "game-day.json"
        self.write(
            valid_observation(), valid_soak(), valid_incident(), valid_game_day()
        )

    def write(self, observation, soak, incident, game_day=None, *, bind_game_day=True):
        if game_day is None:
            game_day = valid_game_day()
        game_day_bytes = json.dumps(
            game_day, sort_keys=True, separators=(",", ":")
        ).encode()
        self.game_day.write_bytes(game_day_bytes)
        if bind_game_day:
            observation["slis"]["tenant_isolation"][
                "game_day_evidence_sha256"
            ] = hashlib.sha256(game_day_bytes).hexdigest()
        self.observation.write_text(json.dumps(observation), encoding="utf-8")
        self.soak.write_text(json.dumps(soak), encoding="utf-8")
        self.incident.write_text(json.dumps(incident), encoding="utf-8")

    def evaluate(self):
        return evaluate(
            self.observation,
            self.soak,
            self.incident,
            self.game_day,
            expected_commit=COMMIT,
            expected_environment=ENVIRONMENT,
            release_candidate=RELEASE_CANDIDATE,
        )

    def close(self):
        self.temporary.cleanup()


class ReleaseSloQualificationTests(unittest.TestCase):
    def setUp(self):
        self.workspace = EvidenceWorkspace()

    def tearDown(self):
        self.workspace.close()

    def test_contract_has_exact_required_sli_inventory(self):
        validate_contract()
        self.assertEqual(
            TARGET_IDS,
            (
                "availability",
                "syscall_latency",
                "queue_wait",
                "llm_success",
                "tool_success",
                "auth_sandbox_denial",
                "data_durability",
                "checkpoint_recovery",
                "tenant_isolation",
            ),
        )

    def test_complete_exact_target_evidence_is_eligible(self):
        report = self.workspace.evaluate()
        self.assertTrue(report["report_generated"])
        self.assertTrue(report["release_slo_proof_eligible"])
        self.assertFalse(report["production_claim_allowed"])
        self.assertEqual(report["failed_targets"], [])
        self.assertEqual(report["eligibility_blockers"], [])
        self.assertEqual(
            [target["target_id"] for target in report["targets"]],
            list(TARGET_IDS),
        )
        self.assertTrue(report["evidence"]["same_clean_source_commit"])
        self.assertRegex(report["evidence"]["observation_sha256"], r"^[0-9a-f]{64}$")

    def test_threshold_failures_generate_an_ineligible_report(self):
        observation = valid_observation()
        observation["slis"]["availability"]["failed"] = 5_000
        observation["slis"]["queue_wait"]["starvation_delta"] = 1
        observation["slis"]["tenant_isolation"]["confirmed_violations"] = 1
        self.workspace.write(observation, valid_soak(), valid_incident())
        report = self.workspace.evaluate()
        self.assertFalse(report["release_slo_proof_eligible"])
        self.assertEqual(
            report["failed_targets"],
            ["availability", "queue_wait", "tenant_isolation"],
        )

    def test_every_target_fails_closed_for_low_volume_or_missing_proof(self):
        observation = valid_observation()
        observation["slis"]["availability"]["success"] = 1
        observation["slis"]["syscall_latency"]["control_requests"] = 1
        observation["slis"]["queue_wait"]["admissions_delta"] = 1
        observation["slis"]["llm_success"]["success"] = 1
        observation["slis"]["tool_success"]["success"] = 1
        observation["slis"]["auth_sandbox_denial"]["adversarial_attempts"] = 1
        observation["slis"]["data_durability"][
            "continuous_ledger_healthy_seconds"
        ] = 1
        observation["slis"]["checkpoint_recovery"] = {
            "attempted": 1,
            "recovered": 1,
            "safe_rejected": 0,
            "cross_tenant_recoveries": 0,
        }
        observation["slis"]["tenant_isolation"]["adversarial_attempts"] = 1
        observation["slis"]["tenant_isolation"]["game_day_completed"] = False
        observation["slis"]["tenant_isolation"]["game_day_evidence_sha256"] = None
        self.workspace.write(
            observation, valid_soak(), valid_incident(), bind_game_day=False
        )
        report = self.workspace.evaluate()
        self.assertEqual(report["failed_targets"], list(TARGET_IDS))

    def test_policy_and_quota_rejections_are_excluded_from_success_ratio(self):
        observation = valid_observation()
        observation["slis"]["llm_success"]["policy_quota_rejected"] = 1_000_000
        observation["slis"]["tool_success"]["policy_quota_rejected"] = 1_000_000
        self.workspace.write(observation, valid_soak(), valid_incident())
        report = self.workspace.evaluate()
        self.assertTrue(report["release_slo_proof_eligible"])

    def test_llm_target_requires_live_provider_evidence(self):
        observation = valid_observation()
        observation["slis"]["llm_success"][
            "live_provider_qualification_passed"
        ] = False
        self.workspace.write(observation, valid_soak(), valid_incident())
        report = self.workspace.evaluate()
        self.assertIn("llm_success", report["failed_targets"])

    def test_game_day_completion_requires_bound_evidence(self):
        observation = valid_observation()
        observation["slis"]["tenant_isolation"]["game_day_evidence_sha256"] = None
        self.workspace.write(
            observation, valid_soak(), valid_incident(), bind_game_day=False
        )
        with self.assertRaisesRegex(QualificationError, "must be a bounded"):
            self.workspace.evaluate()

        observation = valid_observation()
        observation["slis"]["tenant_isolation"]["game_day_completed"] = False
        self.workspace.write(
            observation, valid_soak(), valid_incident(), bind_game_day=False
        )
        with self.assertRaisesRegex(QualificationError, "cannot cite"):
            self.workspace.evaluate()

    def test_game_day_report_must_be_exactly_bound_and_eligible(self):
        game_day = valid_game_day()
        self.workspace.write(
            valid_observation(), valid_soak(), valid_incident(), game_day
        )
        game_day["review"]["decision"] = "rejected"
        self.workspace.game_day.write_text(json.dumps(game_day), encoding="utf-8")
        report = self.workspace.evaluate()
        self.assertIn(
            "human_game_day.exact_report_binding",
            report["eligibility_blockers"],
        )
        self.assertIn(
            "human_game_day.independent_review_passed",
            report["eligibility_blockers"],
        )

    def test_game_day_measurements_are_recalculated(self):
        game_day = valid_game_day()
        game_day["scenarios"][0]["rto_seconds"] = 7_200
        self.workspace.write(
            valid_observation(), valid_soak(), valid_incident(), game_day
        )
        report = self.workspace.evaluate()
        self.assertIn(
            "human_game_day.every_scenario_passed",
            report["eligibility_blockers"],
        )

    def test_game_day_requires_same_source_and_environment(self):
        for key, value, message in (
            ("source", {"commit": "9" * 40, "dirty": False}, "does not match"),
            (
                "environment",
                {
                    **valid_game_day()["environment"],
                    "environment_id": "other-target",
                },
                "does not match",
            ),
        ):
            with self.subTest(key=key):
                game_day = valid_game_day()
                game_day[key] = value
                self.workspace.write(
                    valid_observation(), valid_soak(), valid_incident(), game_day
                )
                with self.assertRaisesRegex(QualificationError, message):
                    self.workspace.evaluate()

    def test_checkpoint_outcomes_cannot_exceed_attempts(self):
        observation = valid_observation()
        observation["slis"]["checkpoint_recovery"]["recovered"] = 101
        self.workspace.write(observation, valid_soak(), valid_incident())
        with self.assertRaisesRegex(QualificationError, "outcomes exceed"):
            self.workspace.evaluate()

    def test_observation_rejects_unknown_or_missing_sli(self):
        observation = valid_observation()
        del observation["slis"]["queue_wait"]
        observation["slis"]["invented"] = {}
        self.workspace.write(observation, valid_soak(), valid_incident())
        with self.assertRaisesRegex(QualificationError, "keys differ"):
            self.workspace.evaluate()

    def test_observation_rejects_fixture_classification(self):
        observation = valid_observation()
        observation["qualification_class"] = "deterministic_fixture"
        self.workspace.write(observation, valid_soak(), valid_incident())
        with self.assertRaisesRegex(QualificationError, "not target"):
            self.workspace.evaluate()

    def test_observation_rejects_dirty_or_mixed_source(self):
        for source in (
            {"commit": COMMIT, "dirty": True},
            {"commit": "d" * 40, "dirty": False},
        ):
            with self.subTest(source=source):
                observation = valid_observation()
                observation["source"] = source
                self.workspace.write(observation, valid_soak(), valid_incident())
                with self.assertRaises(QualificationError):
                    self.workspace.evaluate()

    def test_observation_rejects_local_or_mismatched_environment(self):
        for environment in ("local", "different-target"):
            with self.subTest(environment=environment):
                observation = valid_observation()
                observation["environment"]["environment_id"] = environment
                self.workspace.write(observation, valid_soak(), valid_incident())
                with self.assertRaises(QualificationError):
                    self.workspace.evaluate()

    def test_observation_rejects_short_or_inflated_envelope(self):
        observation = valid_observation()
        observation["window"]["end"] = "2026-01-02T00:00:00Z"
        self.workspace.write(observation, valid_soak(), valid_incident())
        with self.assertRaisesRegex(QualificationError, "at least 30 days"):
            self.workspace.evaluate()

        observation = valid_observation()
        observation["slis"]["availability"]["window_seconds"] = 2_592_001
        self.workspace.write(observation, valid_soak(), valid_incident())
        with self.assertRaisesRegex(QualificationError, "exceeds"):
            self.workspace.evaluate()

    def test_alerts_must_be_bounded_and_inside_window(self):
        observation = valid_observation()
        observation["alert_firings"][0]["fired_at"] = "2025-12-01T00:00:00Z"
        self.workspace.write(observation, valid_soak(), valid_incident())
        with self.assertRaisesRegex(QualificationError, "outside"):
            self.workspace.evaluate()

    def test_unresolved_alert_blocks_eligibility(self):
        observation = valid_observation()
        observation["alert_firings"][0]["resolved_at"] = None
        self.workspace.write(observation, valid_soak(), valid_incident())
        report = self.workspace.evaluate()
        self.assertEqual(report["failed_targets"], [])
        self.assertEqual(report["eligibility_blockers"], ["unresolved_alerts"])
        self.assertFalse(report["release_slo_proof_eligible"])

    def test_numbers_reject_booleans_and_nonfinite_values(self):
        for bad_value in (True, float("nan"), float("inf")):
            with self.subTest(value=bad_value):
                observation = valid_observation()
                observation["slis"]["queue_wait"]["wait_seconds_delta"] = bad_value
                self.workspace.write(observation, valid_soak(), valid_incident())
                with self.assertRaisesRegex(QualificationError, "finite number"):
                    self.workspace.evaluate()

    def test_release_candidate_identifier_is_strict(self):
        with self.assertRaisesRegex(QualificationError, "release candidate"):
            evaluate(
                self.workspace.observation,
                self.workspace.soak,
                self.workspace.incident,
                self.workspace.game_day,
                expected_commit=COMMIT,
                expected_environment=ENVIRONMENT,
                release_candidate="main",
            )

    def test_resource_soak_must_be_full_target_exact_source(self):
        mutations = [
            ("smoke_scaled", True),
            ("resource_soak_proof_eligible", False),
            ("build_profile", "debug"),
        ]
        for key, value in mutations:
            with self.subTest(key=key):
                soak = valid_soak()
                soak[key] = value
                self.workspace.write(valid_observation(), soak, valid_incident())
                report = self.workspace.evaluate()
                self.assertFalse(report["release_slo_proof_eligible"])
                self.assertTrue(
                    any(
                        blocker.startswith("resource_soak.")
                        for blocker in report["eligibility_blockers"]
                    )
                )

    def test_resource_soak_requires_same_environment_and_sustained_samples(self):
        soak = valid_soak()
        soak["environment"]["environment_id"] = "other-target"
        self.workspace.write(valid_observation(), soak, valid_incident())
        with self.assertRaisesRegex(QualificationError, "does not match"):
            self.workspace.evaluate()

        soak = valid_soak()
        soak["result"]["samples"] = [{"sample": 1}]
        self.workspace.write(valid_observation(), soak, valid_incident())
        report = self.workspace.evaluate()
        self.assertIn(
            "resource_soak.sustained_sample_count", report["eligibility_blockers"]
        )

    def test_incident_drill_must_be_complete_and_same_source(self):
        incident = valid_incident()
        incident["scenarios"][2]["passed"] = False
        self.workspace.write(valid_observation(), valid_soak(), incident)
        report = self.workspace.evaluate()
        self.assertIn(
            "incident_drill.every_scenario_passed", report["eligibility_blockers"]
        )

        incident = valid_incident()
        incident["source"]["commit"] = "e" * 40
        self.workspace.write(valid_observation(), valid_soak(), incident)
        with self.assertRaisesRegex(QualificationError, "does not match"):
            self.workspace.evaluate()

    def test_duplicate_json_keys_are_rejected(self):
        self.workspace.observation.write_text(
            '{"schema_version":1,"schema_version":1}', encoding="utf-8"
        )
        with self.assertRaisesRegex(QualificationError, "duplicate JSON key"):
            self.workspace.evaluate()

    @unittest.skipUnless(hasattr(os, "symlink"), "symlinks unsupported")
    def test_symlink_evidence_is_rejected(self):
        real = self.workspace.root / "real-observation.json"
        self.workspace.observation.rename(real)
        os.symlink(real, self.workspace.observation)
        with self.assertRaisesRegex(QualificationError, "non-symlink"):
            self.workspace.evaluate()

    def test_cli_validate_and_require_eligible(self):
        script = Path(__file__).resolve().parents[1] / "release_slo_qualification.py"
        validated = subprocess.run(
            [sys.executable, str(script), "--validate"],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(validated.returncode, 0, validated.stderr)
        output = self.workspace.root / "report.json"
        command = [
            sys.executable,
            str(script),
            "--observation",
            str(self.workspace.observation),
            "--resource-soak",
            str(self.workspace.soak),
            "--incident-drill",
            str(self.workspace.incident),
            "--game-day",
            str(self.workspace.game_day),
            "--expected-commit",
            COMMIT,
            "--expected-environment",
            ENVIRONMENT,
            "--release-candidate",
            RELEASE_CANDIDATE,
            "--output",
            str(output),
            "--require-eligible",
        ]
        completed = subprocess.run(command, check=False, capture_output=True, text=True)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertTrue(json.loads(output.read_text())["release_slo_proof_eligible"])

        observation = valid_observation()
        observation["slis"]["availability"]["success"] = 1
        self.workspace.write(observation, valid_soak(), valid_incident())
        completed = subprocess.run(command, check=False, capture_output=True, text=True)
        self.assertEqual(completed.returncode, 1)
        self.assertFalse(json.loads(output.read_text())["release_slo_proof_eligible"])

    def test_workflow_is_exact_tag_protected_and_fail_closed(self):
        root = Path(__file__).resolve().parents[2]
        workflow = (
            root / ".github/workflows/release-slo-qualification.yml"
        ).read_text(encoding="utf-8")
        self.assertIn(
            "runs-on: [self-hosted, linux, x64, agentos-capacity]", workflow
        )
        self.assertIn('refs/tags/${AGENTOS_RELEASE_CANDIDATE}^{commit}', workflow)
        self.assertIn("--require-eligible", workflow)
        self.assertIn("--game-day", workflow)
        self.assertIn("game-day.json", workflow)
        self.assertIn('test ! -L "$path"', workflow)
        self.assertIn("production_claim_allowed", workflow)
        capabilities = (root / "docs/capabilities.toml").read_text(encoding="utf-8")
        self.assertIn("scripts/release_slo_qualification.py", capabilities)
        self.assertIn("scripts/tests/test_release_slo_qualification.py", capabilities)


if __name__ == "__main__":
    unittest.main()
