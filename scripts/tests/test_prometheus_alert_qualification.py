import re
import unittest
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
RULES = ROOT / "observability" / "prometheus-rules.yml"
RULE_TESTS = ROOT / "observability" / "prometheus-rule-tests.yml"
RUNNER = ROOT / "scripts" / "run_promtool_tests.sh"


class PrometheusAlertQualificationTests(unittest.TestCase):
    def test_every_production_alert_has_pre_fire_and_recovery_assertions(self):
        production_alerts = set(
            re.findall(r"^\s+- alert: (\S+)\s*$", RULES.read_text(), re.MULTILINE)
        )
        tested_alerts = re.findall(
            r"^\s+alertname: (\S+)\s*$", RULE_TESTS.read_text(), re.MULTILINE
        )

        self.assertEqual(set(tested_alerts), production_alerts)
        self.assertEqual(
            Counter(tested_alerts),
            Counter({alert: 3 for alert in production_alerts}),
            "each alert must be asserted before firing, while firing, and after recovery",
        )

    def test_cross_state_queue_comparisons_declare_vector_matching(self):
        rules = RULES.read_text()
        self.assertIn(
            'agentos_turn_admission{state="waiting"} > ignoring(state) '
            'agentos_turn_admission{state="capacity"}',
            rules,
        )
        self.assertIn(
            'agentos_llm_cores{state="waiting"} > ignoring(state) '
            'agentos_llm_cores{state="capacity"}',
            rules,
        )

    def test_runner_is_version_and_checksum_pinned_and_wired_into_gates(self):
        runner = RUNNER.read_text()
        self.assertIn('PROMETHEUS_VERSION="3.13.1"', runner)
        self.assertEqual(
            len(re.findall(r'expected_sha256="[0-9a-f]{64}"', runner)),
            4,
            "each supported host tuple must have an immutable checksum",
        )
        self.assertNotIn(":latest", runner)
        self.assertIn('"${promtool}" check rules', runner)
        self.assertIn('"${promtool}" test rules', runner)

        for gate in (ROOT / ".github/workflows/ci.yml", ROOT / "scripts/ci-local.sh"):
            self.assertIn("scripts/run_promtool_tests.sh", gate.read_text())


if __name__ == "__main__":
    unittest.main()
