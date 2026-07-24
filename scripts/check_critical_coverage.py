#!/usr/bin/env python3
"""Enforce line-coverage floors for the release-critical OS boundaries."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class CoverageTarget:
    name: str
    minimum: float
    paths: tuple[str, ...]


TARGETS = (
    CoverageTarget("syscall gate", 90.0, ("crates/kernel/src/syscall_gate.rs",)),
    CoverageTarget(
        "authorization",
        90.0,
        ("crates/kernel/src/auth.rs", "crates/kernel/src/permissions.rs"),
    ),
    CoverageTarget(
        "lifecycle",
        85.0,
        ("crates/kernel/src/agent.rs", "crates/kernel/src/lib.rs"),
    ),
    CoverageTarget(
        "sandbox",
        85.0,
        ("crates/kernel/src/sandbox.rs", "crates/kernel/src/resources.rs"),
    ),
    CoverageTarget("persistence", 80.0, ("crates/kernel/src/context.rs",)),
    CoverageTarget("wire API", 85.0, ("crates/kernel/src/syscall_server.rs",)),
)


def parse_lcov(source: str) -> dict[str, tuple[int, int]]:
    """Return normalized source path -> (lines hit, lines found)."""
    records: dict[str, tuple[int, int]] = {}
    current: str | None = None
    found: int | None = None
    hit: int | None = None

    def finish() -> None:
        nonlocal current, found, hit
        if current is not None and found is not None and hit is not None:
            records[current] = (hit, found)
        current = None
        found = None
        hit = None

    for raw_line in source.splitlines():
        line = raw_line.strip()
        if line.startswith("SF:"):
            finish()
            current = line[3:].replace("\\", "/")
        elif line.startswith("LF:"):
            found = int(line[3:])
        elif line.startswith("LH:"):
            hit = int(line[3:])
        elif line == "end_of_record":
            finish()
    finish()
    return records


def evaluate(
    records: dict[str, tuple[int, int]],
    targets: tuple[CoverageTarget, ...] = TARGETS,
) -> list[str]:
    failures: list[str] = []
    for target in targets:
        matched: list[tuple[int, int]] = []
        missing: list[str] = []
        for expected in target.paths:
            values = [
                counts
                for path, counts in records.items()
                if path == expected or path.endswith(f"/{expected}")
            ]
            if len(values) != 1:
                missing.append(expected)
            else:
                matched.append(values[0])
        if missing:
            failures.append(
                f"{target.name}: missing unique LCOV record(s): {', '.join(missing)}"
            )
            continue

        lines_hit = sum(value[0] for value in matched)
        lines_found = sum(value[1] for value in matched)
        percent = 100.0 if lines_found == 0 else 100.0 * lines_hit / lines_found
        print(
            f"{target.name}: {lines_hit}/{lines_found} lines "
            f"({percent:.2f}%, minimum {target.minimum:.2f}%)"
        )
        if percent + 1e-9 < target.minimum:
            failures.append(
                f"{target.name}: {percent:.2f}% is below {target.minimum:.2f}%"
            )
    return failures


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("lcov", type=Path, help="LCOV report produced by cargo llvm-cov")
    args = parser.parse_args()

    try:
        source = args.lcov.read_text(encoding="utf-8")
    except OSError as error:
        parser.error(str(error))
    failures = evaluate(parse_lcov(source))
    if failures:
        for failure in failures:
            print(f"ERROR: {failure}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
