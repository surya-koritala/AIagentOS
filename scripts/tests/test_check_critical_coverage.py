import contextlib
import io
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from check_critical_coverage import CoverageTarget, evaluate, parse_lcov


class CriticalCoverageTests(unittest.TestCase):
    def test_parses_unix_and_windows_source_paths(self):
        records = parse_lcov(
            "\n".join(
                [
                    "SF:/workspace/crates/kernel/src/auth.rs",
                    "LF:10",
                    "LH:9",
                    "end_of_record",
                    r"SF:D:\a\repo\crates\kernel\src\permissions.rs",
                    "LF:5",
                    "LH:5",
                    "end_of_record",
                ]
            )
        )
        self.assertEqual(records["/workspace/crates/kernel/src/auth.rs"], (9, 10))
        self.assertEqual(
            records["D:/a/repo/crates/kernel/src/permissions.rs"], (5, 5)
        )

    def test_rejects_missing_and_below_floor_records(self):
        target = CoverageTarget(
            "authorization",
            90.0,
            ("crates/kernel/src/auth.rs", "crates/kernel/src/permissions.rs"),
        )
        missing = evaluate(
            {"crates/kernel/src/auth.rs": (9, 10)},
            (target,),
        )
        self.assertIn("missing unique LCOV", missing[0])

        with contextlib.redirect_stdout(io.StringIO()):
            below = evaluate(
                {
                    "crates/kernel/src/auth.rs": (8, 10),
                    "crates/kernel/src/permissions.rs": (8, 10),
                },
                (target,),
            )
        self.assertIn("below", below[0])

    def test_accepts_aggregate_at_exact_floor(self):
        target = CoverageTarget(
            "sandbox",
            85.0,
            ("crates/kernel/src/sandbox.rs", "crates/kernel/src/resources.rs"),
        )
        with contextlib.redirect_stdout(io.StringIO()):
            failures = evaluate(
                {
                    "/repo/crates/kernel/src/sandbox.rs": (80, 100),
                    "/repo/crates/kernel/src/resources.rs": (90, 100),
                },
                (target,),
            )
        self.assertEqual(failures, [])


if __name__ == "__main__":
    unittest.main()
