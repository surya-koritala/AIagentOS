"""Check the narrowly approved workflow concurrency policy and its event matrix."""

import re
import unittest
from pathlib import Path
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = ("ci.yml", "coding-agent.yml", "integration-format.yml")
GROUP = (
    "${{ github.workflow }}-${{ github.event_name }}-"
    "${{ github.event_name == 'pull_request' && "
    "format('pr-{0}', github.event.pull_request.number) || "
    "format('run-{0}', github.run_id) }}"
)
CANCEL = "${{ github.event_name == 'pull_request' }}"


def policy(source):
    """Reject missing, duplicate, job-local or broadened concurrency rules."""
    blocks = re.findall(r"(?m)^concurrency:\n((?:[ \t]+[^\n]*\n)+)", source)
    if len(blocks) != 1:
        raise ValueError("exactly one workflow concurrency block is required")
    entries = re.findall(r"(?m)^  (group|cancel-in-progress): (.+)$", blocks[0])
    if len(entries) != 2 or dict(entries) != {"group": GROUP, "cancel-in-progress": CANCEL}:
        raise ValueError("concurrency may cancel only a matching pull request")
    return dict(entries)


def outcome(entries, workflow, event, run_id, number=None):
    """Evaluate only the approved expressions, with GitHub's and/or short circuit."""
    github = SimpleNamespace(
        workflow=workflow,
        event_name=event,
        run_id=run_id,
        event=SimpleNamespace(pull_request=SimpleNamespace(number=number)),
    )
    context = {"github": github, "format": lambda template, value: template.format(value)}

    def expression(match):
        code = match.group(1).replace("&&", " and ").replace("||", " or ")
        return eval(code, {"__builtins__": {}}, context)

    group = re.sub(r"\$\{\{\s*(.*?)\s*\}\}", lambda match: str(expression(match)), entries["group"])
    cancel = expression(re.fullmatch(r"\$\{\{\s*(.*?)\s*\}\}", entries["cancel-in-progress"]))
    return group, cancel


class PullRequestConcurrencyTests(unittest.TestCase):
    def test_committed_workflows_follow_the_approved_policy(self):
        for name in WORKFLOWS:
            with self.subTest(workflow=name):
                source = (ROOT / ".github/workflows" / name).read_text(encoding="utf-8")
                entries = policy(source)
                self.assertEqual(outcome(entries, name, "pull_request", "100", 419),
                                 (f"{name}-pull_request-pr-419", True))

    def test_successive_runs_cancel_only_the_same_workflow_and_pr(self):
        entries = {"group": GROUP, "cancel-in-progress": CANCEL}
        first = outcome(entries, "CI", "pull_request", "100", 419)
        updated = outcome(entries, "CI", "pull_request", "101", 419)
        other_pr = outcome(entries, "CI", "pull_request", "102", 420)
        other_workflow = outcome(entries, "Coding agent fixture", "pull_request", "100", 419)
        self.assertEqual(first, updated)
        self.assertTrue(first[1])
        self.assertNotEqual(first[0], other_pr[0])
        self.assertNotEqual(first[0], other_workflow[0])

    def test_non_pr_runs_are_unique_and_never_cancel(self):
        entries = {"group": GROUP, "cancel-in-progress": CANCEL}
        # Main and tag publication both arrive as push. A reusable workflow
        # inherits its caller's event; the release callers are push/dispatch.
        for event in ("push", "workflow_dispatch", "workflow_call", "schedule"):
            for workflow in ("CI", "Release qualification and publication",
                             "Restricted Linux CLI release candidate"):
                with self.subTest(event=event, workflow=workflow):
                    first = outcome(entries, workflow, event, "100")
                    second = outcome(entries, workflow, event, "101")
                    self.assertEqual(first, (f"{workflow}-{event}-run-100", False))
                    self.assertNotEqual(first[0], second[0])
                    self.assertFalse(second[1])

    def test_unsafe_policy_mutations_are_rejected(self):
        baseline = f"concurrency:\n  group: {GROUP}\n  cancel-in-progress: {CANCEL}\n"
        mutations = {
            "all events cancel": baseline.replace(CANCEL, "true"),
            "PRs never cancel": baseline.replace(CANCEL, "false"),
            "main or tags share a ref group": baseline.replace("github.run_id", "github.ref"),
            "PRs collide": baseline.replace("github.event.pull_request.number", "github.ref"),
            "workflows collide": baseline.replace("${{ github.workflow }}-", ""),
            "events collide": baseline.replace("${{ github.event_name }}-", ""),
            "missing block": "jobs:\n  example:\n    runs-on: ubuntu-latest\n",
            "duplicate block": baseline + baseline,
            "job-only block": "jobs:\n  example:\n" + "".join(f"    {line}\n" for line in baseline.splitlines()),
        }
        for name, source in mutations.items():
            with self.subTest(mutation=name), self.assertRaises(ValueError):
                policy(source)


if __name__ == "__main__":
    unittest.main()
