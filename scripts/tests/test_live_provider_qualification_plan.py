import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

from live_provider_qualification_plan import (  # noqa: E402
    PROVIDERS,
    QualificationPlanError,
    build_plan,
    main,
    parse_provider_set,
)


COMMIT = "a" * 40


class LiveProviderQualificationPlanTests(unittest.TestCase):
    def test_empty_provider_set_is_explicit_not_run_evidence(self):
        report = build_plan("", COMMIT)

        self.assertEqual(report["schema_version"], 1)
        self.assertEqual(report["qualification_class"], "live_provider_dispatch_plan")
        self.assertEqual(report["status"], "not_run")
        self.assertFalse(report["production_claim_allowed"])
        self.assertEqual(report["source"], {"commit": COMMIT})
        self.assertEqual(report["selected_providers"], [])
        self.assertEqual(report["unselected_providers"], list(PROVIDERS))
        self.assertIn("AGENTOS_LIVE_PROVIDER_SET", report["reason"])

    def test_selected_providers_are_unique_and_canonically_ordered(self):
        selected = parse_provider_set(" vllm, openai ,ollama ")
        self.assertEqual(selected, ["openai", "ollama", "vllm"])

        report = build_plan("vllm,openai,ollama", COMMIT)
        self.assertEqual(report["status"], "ready")
        self.assertEqual(report["selected_providers"], selected)
        self.assertNotIn("reason", report)

    def test_all_expands_to_the_complete_checked_in_catalog(self):
        self.assertEqual(parse_provider_set("all"), list(PROVIDERS))

    def test_unknown_duplicate_and_malformed_provider_sets_fail_closed(self):
        for value, message in [
            ("openai,openai", "duplicate"),
            ("openai,unknown", "unsupported"),
            ("openai,,ollama", "comma-separated"),
            ("OpenAI", "comma-separated"),
        ]:
            with self.subTest(value=value):
                with self.assertRaisesRegex(QualificationPlanError, message):
                    parse_provider_set(value)

    def test_invalid_commit_fails_closed(self):
        with self.assertRaisesRegex(QualificationPlanError, "SHA-1"):
            build_plan("openai", "not-a-commit")

    def test_cli_writes_bounded_plan_and_github_outputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report_path = root / "plan.json"
            github_output = root / "github-output.txt"
            result = main(
                [
                    "--providers",
                    "ollama,openai",
                    "--commit",
                    COMMIT,
                    "--output",
                    str(report_path),
                    "--github-output",
                    str(github_output),
                ]
            )

            self.assertEqual(result, 0)
            report = json.loads(report_path.read_text())
            self.assertEqual(report["selected_providers"], ["openai", "ollama"])
            output_lines = github_output.read_text().splitlines()
            self.assertEqual(output_lines[0], 'providers=["openai","ollama"]')
            self.assertEqual(output_lines[2], "has_providers=true")
            matrix = json.loads(output_lines[1].removeprefix("matrix="))
            self.assertEqual(
                [entry["provider"] for entry in matrix["include"]],
                ["openai", "ollama"],
            )

    def test_workflow_skips_unselected_environments_and_requires_passed_evidence(self):
        workflow = (
            ROOT / ".github/workflows/live-provider-qualification.yml"
        ).read_text()

        for contract in [
            "cancel-in-progress: true",
            "AGENTOS_LIVE_PROVIDER_SET",
            "live_provider_qualification_plan.py",
            "fromJSON(needs.qualification-plan.outputs.matrix)",
            "environment: provider-qualification",
            'test "$status" = "passed"',
            "if: always()",
        ]:
            self.assertIn(contract, workflow)
        self.assertNotIn(
            'test "$status" = "passed" || test "$status" = "not_run"',
            workflow,
        )


if __name__ == "__main__":
    unittest.main()
