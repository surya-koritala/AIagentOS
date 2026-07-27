import hashlib
import json
import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from storage_profile_qualification import (  # noqa: E402
    MAX_EVIDENCE_BYTES,
    QualificationError,
    REVIEW_CHECK_IDS,
    SCENARIO_IDS,
    SUPPORTED_PROFILE_ID,
    TARGET_RPO_SECONDS,
    TARGET_RTO_SECONDS,
    evaluate,
    main,
    validate_contract,
)


COMMIT = "a" * 40
ENVIRONMENT = "prod-ca-east-1"
RELEASE_CANDIDATE = "v1.0.0-rc.1"
EXERCISE_START = datetime(2026, 7, 25, 9, 0, tzinfo=timezone.utc)
EXERCISE_END = datetime(2026, 7, 25, 12, 0, tzinfo=timezone.utc)


def timestamp(value):
    return value.isoformat().replace("+00:00", "Z")


def valid_observation():
    mechanisms = {
        "host-power-loss": "out_of_band_power_cut",
        "torn-write": "block_level_torn_write",
        "device-loss": "storage_device_detached",
    }
    scenarios = []
    for index, scenario_id in enumerate(SCENARIO_IDS):
        started = EXERCISE_START + timedelta(hours=index)
        newest = started + timedelta(minutes=2)
        last_ack = newest + timedelta(seconds=120)
        fault = last_ack + timedelta(seconds=30)
        recovery = fault + timedelta(seconds=15)
        healthy = fault + timedelta(seconds=900)
        scenarios.append(
            {
                "scenario_id": scenario_id,
                "started_at": timestamp(started),
                "last_acknowledged_write_at": timestamp(last_ack),
                "fault_injected_at": timestamp(fault),
                "recovery_started_at": timestamp(recovery),
                "newest_recovered_write_at": timestamp(newest),
                "service_healthy_at": timestamp(healthy),
                "fault_mechanism": mechanisms[scenario_id],
                "recovery_source": (
                    "local-journal"
                    if scenario_id == "host-power-loss"
                    else "immutable-remote-backup"
                ),
                "pre_fault_boot_id_sha256": format(index + 1, "064x"),
                "post_recovery_boot_id_sha256": format(index + 11, "064x"),
                "expected_fault_observed": True,
                "sqlite_quick_check": "ok",
                "installation_identity_verified": True,
                "recovery_artifact_verified": True,
                "enforcement_rearmed": True,
                "unexpected_tenant_accesses": 0,
                "evidence_sha256": format(index + 21, "064x"),
            }
        )
    return {
        "schema_version": 1,
        "qualification_class": "destructive_storage_profile_observation",
        "release_candidate": RELEASE_CANDIDATE,
        "source": {"commit": COMMIT, "dirty": False},
        "environment": {
            "environment_id": ENVIRONMENT,
            "deployment_mode": "single-node",
            "os": "linux",
            "arch": "x86_64",
            "filesystem_type": "ext4",
            "filesystem_configuration_sha256": "b" * 64,
            "storage_stack_id": "nvme-ebs-gp3",
            "object_store_service_id": "s3-object-lock-ca-east-1",
            "configuration_sha256": "c" * 64,
        },
        "profile": {
            "profile_id": SUPPORTED_PROFILE_ID,
            "target_rpo_seconds": TARGET_RPO_SECONDS,
            "target_rto_seconds": TARGET_RTO_SECONDS,
        },
        "exercise": {
            "exercise_id": "storage-drill-2026-07-25",
            "started_at": timestamp(EXERCISE_START),
            "ended_at": timestamp(EXERCISE_END),
            "operator_id": "operator-1",
            "harness_id": "destructive-rig-1",
        },
        "scenarios": scenarios,
    }


def valid_review(observation_sha256):
    return {
        "schema_version": 1,
        "qualification_class": "independent_destructive_storage_review",
        "release_candidate": RELEASE_CANDIDATE,
        "source": {"commit": COMMIT, "dirty": False},
        "environment_id": ENVIRONMENT,
        "profile_id": SUPPORTED_PROFILE_ID,
        "observation_sha256": observation_sha256,
        "reviewer_id": "independent-reviewer-1",
        "reviewed_at": "2026-07-26T09:00:00Z",
        "decision": "approved",
        "review_attestation_sha256": "d" * 64,
        "scenario_ids": list(SCENARIO_IDS),
        "checks": {check_id: True for check_id in REVIEW_CHECK_IDS},
        "open_findings": [],
    }


class EvidenceWorkspace:
    def __init__(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.observation = self.root / "storage-observation.json"
        self.review = self.root / "storage-review.json"
        self.write(valid_observation())

    def write(self, observation, review_mutator=None):
        observation_bytes = json.dumps(
            observation, sort_keys=True, separators=(",", ":")
        ).encode()
        self.observation.write_bytes(observation_bytes)
        review = valid_review(hashlib.sha256(observation_bytes).hexdigest())
        if review_mutator is not None:
            review_mutator(review)
        self.review.write_text(
            json.dumps(review, sort_keys=True, separators=(",", ":")),
            encoding="utf-8",
        )

    def evaluate(self):
        return evaluate(
            self.observation,
            self.review,
            expected_commit=COMMIT,
            expected_environment=ENVIRONMENT,
            release_candidate=RELEASE_CANDIDATE,
        )

    def close(self):
        self.temporary.cleanup()


class StorageProfileQualificationTests(unittest.TestCase):
    def setUp(self):
        self.workspace = EvidenceWorkspace()

    def tearDown(self):
        self.workspace.close()

    def test_contract_is_fixed_to_three_real_faults_and_published_targets(self):
        validate_contract()
        self.assertEqual(
            SCENARIO_IDS, ("host-power-loss", "torn-write", "device-loss")
        )
        self.assertEqual(TARGET_RPO_SECONDS, 300)
        self.assertEqual(TARGET_RTO_SECONDS, 3600)
        self.assertEqual(len(REVIEW_CHECK_IDS), 7)

    def test_complete_exact_rc_evidence_is_eligible_bounded_and_private(self):
        report = self.workspace.evaluate()
        self.assertTrue(report["passed"])
        self.assertTrue(report["destructive_storage_profile_completed"])
        self.assertTrue(report["storage_profile_proof_eligible"])
        self.assertFalse(report["production_claim_allowed"])
        self.assertEqual(report["failed_scenarios"], [])
        self.assertEqual(report["eligibility_blockers"], [])
        self.assertEqual(
            [scenario["rpo_seconds"] for scenario in report["scenarios"]],
            [120, 120, 120],
        )
        self.assertEqual(
            [scenario["rto_seconds"] for scenario in report["scenarios"]],
            [900, 900, 900],
        )
        encoded = json.dumps(report)
        self.assertNotIn("operator-1", encoded)
        self.assertNotIn("independent-reviewer-1", encoded)
        self.assertNotIn("replace suspect device", encoded)

    def test_scenario_outcomes_are_recalculated_not_trusted(self):
        observation = valid_observation()
        observation["scenarios"][0]["last_acknowledged_write_at"] = timestamp(
            EXERCISE_START + timedelta(minutes=8)
        )
        observation["scenarios"][0]["fault_injected_at"] = timestamp(
            EXERCISE_START + timedelta(minutes=9)
        )
        observation["scenarios"][0]["recovery_started_at"] = timestamp(
            EXERCISE_START + timedelta(minutes=10)
        )
        observation["scenarios"][1]["service_healthy_at"] = timestamp(
            EXERCISE_START + timedelta(hours=2, minutes=30)
        )
        observation["scenarios"][2]["expected_fault_observed"] = False
        self.workspace.write(observation)
        report = self.workspace.evaluate()
        self.assertFalse(report["storage_profile_proof_eligible"])
        self.assertEqual(report["failed_scenarios"], list(SCENARIO_IDS))

    def test_integrity_identity_enforcement_and_tenant_checks_fail_closed(self):
        field_values = (
            ("sqlite_quick_check", "corrupt"),
            ("installation_identity_verified", False),
            ("recovery_artifact_verified", False),
            ("enforcement_rearmed", False),
            ("unexpected_tenant_accesses", 1),
        )
        for field, value in field_values:
            with self.subTest(field=field):
                observation = valid_observation()
                observation["scenarios"][0][field] = value
                self.workspace.write(observation)
                report = self.workspace.evaluate()
                self.assertFalse(report["storage_profile_proof_eligible"])
                self.assertEqual(report["failed_scenarios"], ["host-power-loss"])

    def test_real_mechanisms_recovery_sources_and_boot_transition_are_required(self):
        observation = valid_observation()
        observation["scenarios"][0]["fault_mechanism"] = "sigkill"
        self.workspace.write(observation)
        with self.assertRaisesRegex(QualificationError, "wrong real fault mechanism"):
            self.workspace.evaluate()

        observation = valid_observation()
        observation["scenarios"][1]["recovery_source"] = "local-journal"
        self.workspace.write(observation)
        with self.assertRaisesRegex(QualificationError, "ineligible recovery source"):
            self.workspace.evaluate()

        observation = valid_observation()
        observation["scenarios"][0]["post_recovery_boot_id_sha256"] = observation[
            "scenarios"
        ][0]["pre_fault_boot_id_sha256"]
        self.workspace.write(observation)
        with self.assertRaisesRegex(QualificationError, "different pre-fault"):
            self.workspace.evaluate()

    def test_scenario_inventory_is_exact_and_ordered(self):
        observation = valid_observation()
        observation["scenarios"].reverse()
        self.workspace.write(observation)
        with self.assertRaisesRegex(QualificationError, "fixed contract order"):
            self.workspace.evaluate()

    def test_timeline_must_be_monotonic_and_inside_exercise(self):
        observation = valid_observation()
        observation["scenarios"][0]["recovery_started_at"] = timestamp(
            EXERCISE_START + timedelta(hours=2)
        )
        self.workspace.write(observation)
        with self.assertRaisesRegex(QualificationError, "timeline is not monotonic"):
            self.workspace.evaluate()

        observation = valid_observation()
        observation["scenarios"][-1]["service_healthy_at"] = timestamp(
            EXERCISE_END + timedelta(seconds=1)
        )
        self.workspace.write(observation)
        with self.assertRaisesRegex(QualificationError, "timeline is not monotonic"):
            self.workspace.evaluate()

    def test_exact_source_environment_profile_and_release_are_required(self):
        observations = []
        for path, value in (
            (("source", "commit"), "e" * 40),
            (("source", "dirty"), True),
            (("environment", "environment_id"), "other-prod"),
            (("profile", "profile_id"), "other-profile"),
            (("profile", "target_rpo_seconds"), 301),
            (("environment", "os"), "macos"),
        ):
            observation = valid_observation()
            observation[path[0]][path[1]] = value
            observations.append(observation)
        wrong_release = valid_observation()
        wrong_release["release_candidate"] = "v1.0.0-rc.2"
        observations.append(wrong_release)
        for index, observation in enumerate(observations):
            with self.subTest(index=index):
                self.workspace.write(observation)
                with self.assertRaises(QualificationError):
                    self.workspace.evaluate()

    def test_fixture_like_target_identifiers_are_rejected(self):
        for value in ("test", "test-target", "prod_mock_store", "local:ext4"):
            with self.subTest(value=value):
                observation = valid_observation()
                observation["environment"]["environment_id"] = value
                self.workspace.write(observation)
                with self.assertRaisesRegex(QualificationError, "non-fixture"):
                    evaluate(
                        self.workspace.observation,
                        self.workspace.review,
                        expected_commit=COMMIT,
                        expected_environment=value,
                        release_candidate=RELEASE_CANDIDATE,
                    )

    def test_review_binds_exact_observation_and_target(self):
        self.workspace.write(
            valid_observation(),
            lambda review: review.__setitem__("observation_sha256", "e" * 64),
        )
        with self.assertRaisesRegex(QualificationError, "exact observation bytes"):
            self.workspace.evaluate()

        self.workspace.write(
            valid_observation(),
            lambda review: review.__setitem__("profile_id", "other-profile"),
        )
        with self.assertRaisesRegex(QualificationError, "target identity"):
            self.workspace.evaluate()

    def test_review_must_follow_exercise_and_be_timely(self):
        self.workspace.write(
            valid_observation(),
            lambda review: review.__setitem__(
                "reviewed_at", timestamp(EXERCISE_END - timedelta(seconds=1))
            ),
        )
        with self.assertRaisesRegex(QualificationError, "derived durations"):
            self.workspace.evaluate()

        self.workspace.write(
            valid_observation(),
            lambda review: review.__setitem__(
                "reviewed_at", timestamp(EXERCISE_END + timedelta(days=31))
            ),
        )
        with self.assertRaisesRegex(QualificationError, "too long"):
            self.workspace.evaluate()

    def test_review_inventory_must_be_exact(self):
        self.workspace.write(
            valid_observation(),
            lambda review: review["scenario_ids"].reverse(),
        )
        with self.assertRaisesRegex(QualificationError, "incomplete or reordered"):
            self.workspace.evaluate()

    def test_reviewer_decision_checks_and_findings_control_eligibility(self):
        mutations = (
            lambda review: review.__setitem__("reviewer_id", "operator-1"),
            lambda review: review.__setitem__("reviewer_id", "Operator-1"),
            lambda review: review.__setitem__("reviewer_id", "destructive-rig-1"),
            lambda review: review.__setitem__("decision", "rejected"),
            lambda review: review["checks"].__setitem__(
                REVIEW_CHECK_IDS[0], False
            ),
            lambda review: review.__setitem__(
                "open_findings", ["replace suspect device"]
            ),
        )
        for index, mutation in enumerate(mutations):
            with self.subTest(index=index):
                self.workspace.write(valid_observation(), mutation)
                report = self.workspace.evaluate()
                self.assertFalse(report["storage_profile_proof_eligible"])
                self.assertTrue(report["eligibility_blockers"])

    def test_unknown_duplicate_and_oversized_json_are_rejected(self):
        observation = valid_observation()
        observation["unknown"] = True
        self.workspace.write(observation)
        with self.assertRaisesRegex(QualificationError, "keys differ"):
            self.workspace.evaluate()

        self.workspace.observation.write_text(
            '{"schema_version":1,"schema_version":1}', encoding="utf-8"
        )
        with self.assertRaisesRegex(QualificationError, "duplicate JSON key"):
            self.workspace.evaluate()

        self.workspace.observation.write_bytes(b" " * (MAX_EVIDENCE_BYTES + 1))
        with self.assertRaisesRegex(QualificationError, "invalid size"):
            self.workspace.evaluate()

    @unittest.skipUnless(hasattr(os, "symlink"), "symlinks unavailable")
    def test_symlink_evidence_is_rejected(self):
        real = self.workspace.root / "real-observation.json"
        self.workspace.observation.rename(real)
        self.workspace.observation.symlink_to(real)
        with self.assertRaisesRegex(QualificationError, "unavailable"):
            self.workspace.evaluate()

    def test_cli_validate_is_isolated_and_execution_requires_clean_exact_git(self):
        self.assertEqual(main(["--validate"]), 0)
        with self.assertRaises(SystemExit):
            main(["--validate", "--require-eligible"])
        with self.assertRaises(SystemExit):
            main([])
        with mock.patch(
            "storage_profile_qualification._local_source",
            return_value=("f" * 40, False),
        ):
            with self.assertRaisesRegex(QualificationError, "exact clean"):
                main(
                    [
                        "--observation",
                        str(self.workspace.observation),
                        "--review",
                        str(self.workspace.review),
                        "--expected-commit",
                        COMMIT,
                        "--expected-environment",
                        ENVIRONMENT,
                        "--release-candidate",
                        RELEASE_CANDIDATE,
                        "--output",
                        str(self.workspace.root / "report.json"),
                    ]
                )

    def test_cli_writes_new_owner_only_report_and_require_eligible_fails(self):
        output = self.workspace.root / "report.json"
        arguments = [
            "--observation",
            str(self.workspace.observation),
            "--review",
            str(self.workspace.review),
            "--expected-commit",
            COMMIT,
            "--expected-environment",
            ENVIRONMENT,
            "--release-candidate",
            RELEASE_CANDIDATE,
        ]
        with mock.patch(
            "storage_profile_qualification._local_source",
            return_value=(COMMIT, False),
        ):
            self.assertEqual(
                main(arguments + ["--output", str(output), "--require-eligible"]),
                0,
            )
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            with self.assertRaisesRegex(QualificationError, "new regular file"):
                main(arguments + ["--output", str(output)])

        observation = valid_observation()
        observation["scenarios"][0]["expected_fault_observed"] = False
        self.workspace.write(observation)
        ineligible_output = self.workspace.root / "ineligible.json"
        with mock.patch(
            "storage_profile_qualification._local_source",
            return_value=(COMMIT, False),
        ):
            with self.assertRaisesRegex(QualificationError, "not eligible"):
                main(
                    arguments
                    + [
                        "--output",
                        str(ineligible_output),
                        "--require-eligible",
                    ]
                )


if __name__ == "__main__":
    unittest.main()
