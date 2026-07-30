import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

from protected_qualification_plan import (  # noqa: E402
    PROFILE_BY_ID,
    PROFILES,
    QualificationPlanError,
    build_plan,
    main,
    parse_enablement,
    validate_catalog,
)


COMMIT = "b" * 40
WORKFLOW_PROFILES = {
    "capacity-qualification.yml": (
        "capacity-baseline",
        "AGENTOS_CAPACITY_QUALIFICATION_ENABLED",
        "deterministic-baseline",
    ),
    "resource-soak-qualification.yml": (
        "resource-soak",
        "AGENTOS_CAPACITY_QUALIFICATION_ENABLED",
        "target-resource-soak",
    ),
    "target-remote-backup-qualification.yml": (
        "target-remote-backup",
        "AGENTOS_CAPACITY_QUALIFICATION_ENABLED",
        "exact-release-candidate-target-recovery",
    ),
    "release-slo-qualification.yml": (
        "release-slo",
        "AGENTOS_CAPACITY_QUALIFICATION_ENABLED",
        "exact-release-candidate-slo",
    ),
    "game-day-qualification.yml": (
        "game-day",
        "AGENTOS_CAPACITY_QUALIFICATION_ENABLED",
        "exact-release-candidate-game-day",
    ),
    "phase1-promotion-qualification.yml": (
        "phase1-promotion",
        "AGENTOS_CAPACITY_QUALIFICATION_ENABLED",
        "exact-release-candidate-promotion",
    ),
    "on-device-qualification.yml": (
        "on-device",
        "AGENTOS_MODEL_QUALIFICATION_ENABLED",
        "exact-release-candidate",
    ),
    "storage-profile-qualification.yml": (
        "storage-profile",
        "AGENTOS_DESTRUCTIVE_STORAGE_QUALIFICATION_ENABLED",
        "exact-release-candidate-destructive-storage",
    ),
    "external-deletion-qualification.yml": (
        "external-deletion",
        "AGENTOS_EXTERNAL_DATA_QUALIFICATION_ENABLED",
        "exact-release-candidate-external-deletion",
    ),
}


class ProtectedQualificationPlanTests(unittest.TestCase):
    def test_catalog_is_complete_and_valid(self):
        validate_catalog()
        self.assertEqual(set(PROFILES), {value[0] for value in WORKFLOW_PROFILES.values()})
        self.assertEqual(len(PROFILE_BY_ID), len(PROFILES))

    def test_disabled_profile_is_explicit_not_run_evidence(self):
        report = build_plan("capacity-baseline", "", COMMIT)

        self.assertEqual(report["schema_version"], 1)
        self.assertEqual(
            report["qualification_class"], "protected_external_dispatch_plan"
        )
        self.assertEqual(report["status"], "not_run")
        self.assertEqual(report["source"], {"commit": COMMIT})
        self.assertFalse(report["configuration"]["explicitly_enabled"])
        self.assertTrue(report["configuration"]["enable_value_valid"])
        self.assertFalse(report["infrastructure_verified"])
        self.assertFalse(report["production_claim_allowed"])
        self.assertIn("AGENTOS_CAPACITY_QUALIFICATION_ENABLED", report["reason"])

    def test_enabled_profile_is_only_dispatch_ready(self):
        report = build_plan("on-device", "true", COMMIT)

        self.assertEqual(report["status"], "ready")
        self.assertEqual(report["readiness_scope"], "dispatch_configuration_only")
        self.assertFalse(report["infrastructure_verified"])
        self.assertFalse(report["production_claim_allowed"])
        self.assertEqual(report["required_environment"], "model-qualification")
        self.assertIn("agentos-model", report["required_runner_labels"])
        self.assertIn("AGENTOS_GGUF_MODEL", report["required_variables"])
        self.assertIn("must still prove", report["reason"])

    def test_enablement_is_exact_and_fail_closed(self):
        self.assertEqual(parse_enablement(""), (False, True))
        self.assertEqual(parse_enablement("false"), (False, True))
        self.assertEqual(parse_enablement(" true "), (True, True))
        for value in ("TRUE", "1", "yes", "false\ntrue"):
            with self.subTest(value=value):
                report = build_plan("capacity-baseline", value, COMMIT)
                self.assertEqual(report["status"], "not_run")
                self.assertFalse(report["configuration"]["enable_value_valid"])
                self.assertIn("must be exactly true or false", report["reason"])

    def test_unknown_profile_and_invalid_commit_fail_closed(self):
        with self.assertRaisesRegex(QualificationPlanError, "unsupported"):
            build_plan("unknown", "true", COMMIT)
        with self.assertRaisesRegex(QualificationPlanError, "SHA-1"):
            build_plan("capacity-baseline", "true", "not-a-commit")

    def test_cli_writes_bounded_report_and_outputs_without_raw_enablement(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report_path = root / "plan.json"
            github_output = root / "github-output.txt"
            result = main(
                [
                    "--profile",
                    "target-remote-backup",
                    "--enabled",
                    "true",
                    "--commit",
                    COMMIT,
                    "--output",
                    str(report_path),
                    "--github-output",
                    str(github_output),
                ]
            )

            self.assertEqual(result, 0)
            report_text = report_path.read_text()
            self.assertLessEqual(len(report_text.encode()), 32768)
            self.assertNotIn('"enabled": "true"', report_text)
            report = json.loads(report_text)
            self.assertEqual(report["status"], "ready")
            self.assertEqual(
                github_output.read_text().splitlines(),
                ["ready=true", "profile=target-remote-backup"],
            )

    def test_protected_workflows_use_the_hosted_preflight_before_self_hosted_jobs(self):
        for workflow_name, (
            profile,
            enable_variable,
            protected_job,
        ) in WORKFLOW_PROFILES.items():
            with self.subTest(workflow=workflow_name):
                workflow = (
                    ROOT / ".github/workflows" / workflow_name
                ).read_text()
                self.assertIn("qualification-plan:", workflow)
                self.assertIn(
                    "uses: ./.github/workflows/protected-qualification-plan.yml",
                    workflow,
                )
                self.assertIn(f"profile: {profile}", workflow)
                self.assertIn(f"enabled: ${{{{ vars.{enable_variable} }}}}", workflow)
                self.assertIn(f"  {protected_job}:", workflow)
                self.assertIn("needs: qualification-plan", workflow)
                self.assertIn(
                    "if: needs.qualification-plan.outputs.ready == 'true'",
                    workflow,
                )
                preflight_prefix = workflow.split(f"  {protected_job}:", 1)[0]
                self.assertNotIn("secrets.", preflight_prefix)

        target_remote = (
            ROOT
            / ".github/workflows/target-remote-backup-qualification.yml"
        ).read_text()
        protected_job = target_remote.split(
            "  exact-release-candidate-target-recovery:", 1
        )[1]
        self.assertIn(
            "AWS_ACCESS_KEY_ID: ${{ secrets.AGENTOS_TARGET_REMOTE_ACCESS_KEY_ID }}",
            protected_job,
        )


if __name__ == "__main__":
    unittest.main()
