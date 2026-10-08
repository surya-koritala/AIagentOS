import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


class CodingPilotPlanTests(unittest.TestCase):
    def workflow(self):
        return (ROOT / '.github/workflows/coding-agent-pilot.yml').read_text()

    def plan(self, values):
        source = re.search(r"python3 - <<'PY'\n(.*?)\n          PY", self.workflow(), re.S).group(1)
        source = '\n'.join(line[10:] for line in source.splitlines())
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'target/coding-pilot').mkdir(parents=True)
            env = os.environ.copy()
            env.update({'CODING_MODEL':'contract-model','CODING_MAX_USD':'1','CODING_INPUT_PRICE':'0.001','CODING_OUTPUT_PRICE':'0.002','GITHUB_OUTPUT':str(root/'output')})
            env.pop('OPENAI_API_KEY', None)
            env.update(values)
            result = subprocess.run([sys.executable, '-c', source], cwd=root, env=env, capture_output=True, text=True)
            plan = root/'target/coding-pilot/plan.json'
            return result, json.loads(plan.read_text()) if plan.exists() else None

    def test_live_spend_requires_manual_task_review_and_protected_environment(self):
        source = self.workflow()
        self.assertIn('workflow_dispatch:', source)
        self.assertNotIn('pull_request:', source)
        self.assertNotIn('schedule:', source)
        self.assertIn('if: inputs.reviewed_utf8_task == true', source)
        self.assertIn('environment: provider-qualification', source)
        self.assertIn('Missing provider credentials are not a passing task', source)

    def test_missing_credential_records_not_run_without_a_provider_call(self):
        result, plan = self.plan({})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(plan['status'], 'not_run')
        self.assertEqual(plan['provider_api_calls'], 0)
        self.assertFalse(plan['production_claim_allowed'])

    def test_invalid_reviewed_bounds_fail_before_a_plan_is_published(self):
        for values in [{'CODING_MAX_USD':'nan'}, {'CODING_MAX_USD':'0'}, {'CODING_MAX_USD':'0.000000001'}, {'CODING_MAX_USD':'101'}, {'CODING_MODEL':''}, {'CODING_INPUT_PRICE':'-1'}]:
            with self.subTest(values=values):
                result, plan = self.plan(values)
                self.assertNotEqual(result.returncode, 0)
                self.assertIsNone(plan)

    def test_one_authorized_ceiling_is_partitioned_across_the_entire_comparison(self):
        result, plan = self.plan({'OPENAI_API_KEY':'fixture-key','CODING_MAX_USD':'3'})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(plan['authorized_configured_max_usd'], 3)
        self.assertEqual(plan['configured_max_usd_per_strategy'], 1)
        self.assertEqual(plan['strategy_count'], 3)
        self.assertEqual(plan['max_attempts_per_strategy'], 2)


if __name__ == '__main__':
    unittest.main()
