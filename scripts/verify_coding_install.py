#!/usr/bin/env python3
"""Verify a downloaded candidate archive on a fresh supported rootless host."""

from __future__ import annotations

import argparse
import json
import os
import platform
import subprocess
from pathlib import Path

from linux_cli_rc_qualification import (
    QualificationError,
    extract_archive,
    sha256_file,
    validate_archive,
)


def execute(command: list[str], environment: dict[str, str]) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        command, env=environment, stdin=subprocess.DEVNULL, capture_output=True,
        text=True, timeout=900, check=False,
    )
    if result.returncode:
        raise QualificationError(
            f"{Path(command[0]).name} failed with exit {result.returncode}"
        )
    return result


def verify(archive: Path, expected_sha256: str, version: str, image: str, destination: Path) -> dict:
    if platform.system() != "Linux":
        raise QualificationError("coding installation execution requires Linux/rootless")
    validate_archive(archive)
    actual = sha256_file(archive)
    if actual != expected_sha256:
        raise QualificationError("downloaded archive checksum mismatch")
    destination.mkdir(mode=0o700, parents=True, exist_ok=False)
    (destination / "bin").mkdir(mode=0o700)
    binaries = extract_archive(archive, destination / "bin")
    environment = {
        name: value for name, value in os.environ.items()
        if not name.startswith(("AGENTOS_", "AGENT_SERVER_"))
        and name not in ("OPENAI_API_KEY", "AZURE_OPENAI_API_KEY", "ANTHROPIC_API_KEY")
    }
    environment["RUST_LOG"] = "warn"
    versions = {}
    for name, binary in binaries.items():
        observed = execute([str(binary), "--version"], environment).stdout.strip()
        if observed != f"{name} {version}":
            raise QualificationError(f"{name} installed version differs from candidate")
        versions[name] = observed
    binary = binaries["agent-code"]
    if "agent-code fixture" not in execute([str(binary), "--help"], environment).stdout:
        raise QualificationError("installed coding quick start is missing")
    reports = destination / "reports"
    reports.mkdir(mode=0o700)
    data = destination / "job"
    outputs = {}
    for name, command in [
        ("paused", [str(binary), "fixture", "--image", image, "--data-dir", str(data), "--pause-after-branch"]),
        ("completed", [str(binary), "resume", "--data-dir", str(data)]),
        ("repeated", [str(binary), "resume", "--data-dir", str(data)]),
    ]:
        result = execute(command, environment)
        try:
            document = json.loads(result.stdout)
        except json.JSONDecodeError as error:
            raise QualificationError("installed application did not report JSON") from error
        outputs[name] = document
        (reports / f"{name}.json").write_text(result.stdout, encoding="utf-8")
        (reports / f"{name}-events.jsonl").write_text(result.stderr, encoding="utf-8")
    paused, completed, repeated = (outputs[name] for name in ("paused", "completed", "repeated"))
    if not (
        paused.get("status") == "paused"
        and paused["branches"][0]["phase"] == "discarded"
        and completed.get("status") == "completed"
        and completed["branches"][0]["test"]["exit_code"] != 0
        and completed["branches"][1]["test"]["exit_code"] == 0
        and all(branch["test"]["kind"] == "isolated_process" for branch in completed["branches"])
        and completed.get("original_repository_written") is False
        and completed == repeated
    ):
        raise QualificationError("installed task, restart, or receipt contract failed")
    return {
        "schema_version": 1,
        "qualification_class": "coding_cli_clean_runner_fixture",
        "production_claim_allowed": False,
        "artifact_sha256": actual,
        "versions": versions,
        "binary_sha256": {name: sha256_file(binary) for name, binary in binaries.items()},
        "image": image,
        "environment": {"os": platform.system(), "architecture": platform.machine()},
        "task_completed": True,
        "fresh_process_resume": True,
        "completed_effects_replayed": False,
        "provider_api_calls": 0,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--image", required=True)
    parser.add_argument("--destination", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    try:
        report = verify(args.archive, args.sha256, args.version, args.image, args.destination)
    except (QualificationError, OSError, KeyError, IndexError, subprocess.TimeoutExpired) as error:
        parser.exit(1, f"coding install verification failed: {error}\n")
    args.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
