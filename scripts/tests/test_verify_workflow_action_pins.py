import sys
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from verify_workflow_action_pins import (
    ActionPin,
    discover_action_pins,
    remote_pin_failures,
)


class WorkflowActionPinTests(unittest.TestCase):
    def test_discovers_every_uses_key_and_skips_local_workflows(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            workflow = root / "release.yml"
            workflow.write_text(
                "\n".join(
                    [
                        "steps:",
                        "  - uses: owner/action/subpath@0123456789abcdef0123456789abcdef01234567",
                        "  - name: Named action step",
                        "    uses: second/action@123456789abcdef0123456789abcdef012345678",
                        "reusable-job:",
                        "  uses: third/workflows/.github/workflows/ci.yml@23456789abcdef0123456789abcdef0123456789",
                        "local-job:",
                        "  uses: ./.github/workflows/ci.yml",
                    ]
                ),
                encoding="utf-8",
            )
            pins, failures = discover_action_pins(root)
        self.assertEqual(failures, [])
        self.assertEqual(
            pins,
            [
                ActionPin(
                    repository="owner/action",
                    revision="0123456789abcdef0123456789abcdef01234567",
                    workflow=workflow,
                    line=2,
                ),
                ActionPin(
                    repository="second/action",
                    revision="123456789abcdef0123456789abcdef012345678",
                    workflow=workflow,
                    line=4,
                ),
                ActionPin(
                    repository="third/workflows",
                    revision="23456789abcdef0123456789abcdef0123456789",
                    workflow=workflow,
                    line=6,
                ),
            ],
        )

    def test_rejects_floating_or_missing_revisions(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "ci.yaml").write_text(
                "\n".join(
                    [
                        "steps:",
                        "  - uses: actions/checkout@v7",
                        "  - name: Setup",
                        "    uses: actions/setup-node",
                    ]
                ),
                encoding="utf-8",
            )
            pins, failures = discover_action_pins(root)
        self.assertEqual(pins, [])
        self.assertEqual(len(failures), 2)
        self.assertIn("40-character", failures[0])
        self.assertIn("no revision", failures[1])

    @mock.patch("verify_workflow_action_pins.urllib.request.urlopen")
    def test_remote_verifier_rejects_a_nonexistent_commit(self, urlopen):
        urlopen.side_effect = urllib.error.HTTPError(
            "https://api.github.test/repos/owner/action/commits/deadbeef",
            404,
            "Not Found",
            {},
            None,
        )
        pin = ActionPin(
            repository="owner/action",
            revision="0" * 40,
            workflow=Path("ci.yml"),
            line=3,
        )
        failures = remote_pin_failures(
            [pin],
            "test-token",
            "https://api.github.test",
        )
        self.assertEqual(len(failures), 1)
        self.assertIn("does not resolve", failures[0])


if __name__ == "__main__":
    unittest.main()
