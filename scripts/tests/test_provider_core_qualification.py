import hashlib
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from provider_core_qualification import (  # noqa: E402
    EvidenceSpec,
    QualificationError,
    build_report,
)


COMMIT = "a" * 40
TEST_NAME = "sandbox::tests::capability_io_rejects_cross_agent_workspace_access"


def passing_log(test_name=TEST_NAME):
    return (
        f"running 1 test\n"
        f"test {test_name} ... ok\n\n"
        "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; "
        "939 filtered out; finished in 0.01s\n"
    )


class ProviderCoreQualificationTests(unittest.TestCase):
    def test_exact_passing_event_builds_hashed_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "cross-agent.log"
            raw = passing_log().encode()
            log.write_bytes(raw)
            report = build_report(
                [EvidenceSpec("cross_agent_access_denied", TEST_NAME, log)],
                COMMIT,
                dirty=False,
                generated_at="2026-07-28T00:00:00Z",
            )

        self.assertTrue(report["passed"])
        self.assertFalse(report["production_claim_allowed"])
        self.assertEqual(report["source"], {"commit": COMMIT, "dirty": False})
        self.assertEqual(
            report["evidence"]["cross_agent_access_denied"]["sha256"],
            hashlib.sha256(raw).hexdigest(),
        )

    def test_missing_or_wrong_test_event_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "wrong.log"
            log.write_text(passing_log("sandbox::tests::another_test"))
            with self.assertRaisesRegex(QualificationError, "exact passing event"):
                build_report(
                    [EvidenceSpec("cross_agent_access_denied", TEST_NAME, log)],
                    COMMIT,
                    dirty=False,
                    generated_at="2026-07-28T00:00:00Z",
                )

    def test_failed_harness_or_dirty_source_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "failed.log"
            log.write_text(
                f"test {TEST_NAME} ... ok\n"
                "test result: FAILED. 0 passed; 1 failed; 0 ignored; "
                "0 measured; 0 filtered out; finished in 0.01s\n"
            )
            with self.assertRaisesRegex(QualificationError, "harness result"):
                build_report(
                    [EvidenceSpec("cross_agent_access_denied", TEST_NAME, log)],
                    COMMIT,
                    dirty=False,
                    generated_at="2026-07-28T00:00:00Z",
                )
            log.write_text(passing_log())
            with self.assertRaisesRegex(QualificationError, "clean source tree"):
                build_report(
                    [EvidenceSpec("cross_agent_access_denied", TEST_NAME, log)],
                    COMMIT,
                    dirty=True,
                    generated_at="2026-07-28T00:00:00Z",
                )

    def test_duplicate_checks_and_invalid_commit_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "valid.log"
            log.write_text(passing_log())
            duplicate = EvidenceSpec("same_check", TEST_NAME, log)
            with self.assertRaisesRegex(QualificationError, "duplicate"):
                build_report(
                    [duplicate, duplicate],
                    COMMIT,
                    dirty=False,
                    generated_at="2026-07-28T00:00:00Z",
                )
            with self.assertRaisesRegex(QualificationError, "SHA-1"):
                build_report(
                    [duplicate],
                    "not-a-commit",
                    dirty=False,
                    generated_at="2026-07-28T00:00:00Z",
                )


if __name__ == "__main__":
    unittest.main()
