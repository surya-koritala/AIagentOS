#!/usr/bin/env python3
"""Build exact-source provider qualification evidence from Rust test logs."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from typing import NamedTuple


MAX_LOG_BYTES = 4 * 1024 * 1024
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
CHECK_RE = re.compile(r"^[a-z][a-z0-9_]*$")


class QualificationError(ValueError):
    """The supplied evidence is incomplete, malformed, or not exact-source."""


class EvidenceSpec(NamedTuple):
    check: str
    test: str
    log: Path


def parse_evidence(value: str) -> EvidenceSpec:
    parts = value.split(",", 2)
    if len(parts) != 3:
        raise argparse.ArgumentTypeError(
            "evidence must use CHECK,RUST_TEST_NAME,LOG_PATH"
        )
    check, test, log = parts
    if CHECK_RE.fullmatch(check) is None:
        raise argparse.ArgumentTypeError(f"invalid check name: {check!r}")
    if not test or any(character.isspace() for character in test):
        raise argparse.ArgumentTypeError(f"invalid Rust test name: {test!r}")
    return EvidenceSpec(check, test, Path(log))


def _read_test_log(spec: EvidenceSpec) -> tuple[bytes, str]:
    try:
        raw = spec.log.read_bytes()
    except OSError as error:
        raise QualificationError(
            f"{spec.check}: cannot read test log {spec.log}: {error}"
        ) from error
    if not raw or len(raw) > MAX_LOG_BYTES:
        raise QualificationError(
            f"{spec.check}: test log must contain 1..{MAX_LOG_BYTES} bytes"
        )
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise QualificationError(f"{spec.check}: test log is not UTF-8") from error

    exact_pass = re.compile(
        rf"(?m)^test {re.escape(spec.test)} \.\.\. ok\r?$"
    )
    if exact_pass.search(text) is None:
        raise QualificationError(
            f"{spec.check}: exact passing event for {spec.test!r} is missing"
        )
    result = re.compile(
        r"(?m)^test result: ok\. 1 passed; 0 failed; "
        r"(?:0 ignored; )?\d+ measured; \d+ filtered out; finished in .+\r?$"
    )
    if result.search(text) is None:
        raise QualificationError(
            f"{spec.check}: an exact one-test successful harness result is missing"
        )
    return raw, text


def build_report(
    specs: list[EvidenceSpec],
    commit: str,
    *,
    dirty: bool,
    generated_at: str,
) -> dict[str, object]:
    if COMMIT_RE.fullmatch(commit) is None:
        raise QualificationError("source commit must be a lowercase 40-character SHA-1")
    if dirty:
        raise QualificationError("provider qualification requires a clean source tree")
    if not specs:
        raise QualificationError("at least one provider check is required")

    checks: dict[str, bool] = {}
    logs: dict[str, dict[str, object]] = {}
    for spec in specs:
        if spec.check in checks:
            raise QualificationError(f"duplicate provider check: {spec.check}")
        raw, _ = _read_test_log(spec)
        checks[spec.check] = True
        logs[spec.check] = {
            "test": spec.test,
            "path": spec.log.name,
            "bytes": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest(),
        }

    return {
        "schema_version": 1,
        "suite": "agentos-v1-provider-security-core",
        "generated_at": generated_at,
        "qualification_class": "live_linux_kernel_provider_core",
        "production_claim_allowed": False,
        "source": {"commit": commit, "dirty": False},
        "environment": {
            "operating_system": "linux",
            "provider_path": "kernel-gate-broker-sandbox",
        },
        "checks": checks,
        "evidence": logs,
        "passed": all(checks.values()),
    }


def source_is_dirty() -> bool:
    result = subprocess.run(
        ["git", "status", "--porcelain"],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return bool(result.stdout)


def write_report(path: Path, report: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    os.replace(temporary, path)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument(
        "--evidence",
        action="append",
        type=parse_evidence,
        default=[],
        metavar="CHECK,RUST_TEST_NAME,LOG_PATH",
    )
    args = parser.parse_args(argv)
    generated_at = dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")
    try:
        report = build_report(
            args.evidence,
            args.commit,
            dirty=source_is_dirty(),
            generated_at=generated_at,
        )
        write_report(args.output, report)
    except (QualificationError, OSError, subprocess.SubprocessError) as error:
        print(f"provider qualification failed: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
