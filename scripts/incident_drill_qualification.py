#!/usr/bin/env python3
"""Run the deterministic technical controls behind the incident playbooks.

This runner deliberately executes only a fixed, reviewed command catalog. It
retains command identity and pass/fail metadata, never command output, prompts,
credentials, paths from test failures, or other potentially sensitive logs.
The resulting artifact is automated regression evidence; it is not evidence
that humans completed an incident game day.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import platform
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Sequence


class QualificationError(RuntimeError):
    """The drill catalog, command execution, or child evidence was invalid."""


@dataclass(frozen=True)
class CommandSpec:
    command_id: str
    argv: tuple[str, ...]
    expected_test: str | None = None
    evidence_kind: str = "cargo_test"
    timeout_seconds: int = 600


@dataclass(frozen=True)
class ScenarioSpec:
    scenario_id: str
    title: str
    runbook_anchor: str
    commands: tuple[CommandSpec, ...]


@dataclass(frozen=True)
class ProcessResult:
    return_code: int
    output: str


def cargo_test(package: str, test_name: str, command_id: str) -> CommandSpec:
    return CommandSpec(
        command_id=command_id,
        argv=(
            "cargo",
            "test",
            "-p",
            package,
            test_name,
            "--locked",
            "--",
            "--exact",
        ),
        expected_test=test_name,
    )


SCENARIOS = (
    ScenarioSpec(
        scenario_id="credential-compromise",
        title="Credential compromise",
        runbook_anchor="docs/INCIDENT_RESPONSE.md#credential-compromise",
        commands=(
            cargo_test(
                "kernel",
                "syscall_server::tests::revoked_tenant_session_loses_authority_without_reconnect",
                "credential.live-session-revocation",
            ),
            cargo_test(
                "integration-tests",
                "tenancy_props::credential_revocation_survives_restart",
                "credential.revocation-survives-restart",
            ),
        ),
    ),
    ScenarioSpec(
        scenario_id="tenant-leak",
        title="Suspected tenant data leak",
        runbook_anchor="docs/INCIDENT_RESPONSE.md#tenant-data-leak",
        commands=(
            cargo_test(
                "integration-tests",
                "tenancy_props::cross_tenant_state_reads_are_impossible",
                "tenant-leak.cross-tenant-state-denial",
            ),
            cargo_test(
                "kernel",
                "syscall_server::tests::tenant_authorizer_denies_every_foreign_agent_operation",
                "tenant-leak.foreign-operation-denial",
            ),
        ),
    ),
    ScenarioSpec(
        scenario_id="malicious-package",
        title="Malicious or compromised package",
        runbook_anchor="docs/INCIDENT_RESPONSE.md#malicious-package",
        commands=(
            cargo_test(
                "kernel",
                "package::tests::recomputed_checksum_cannot_bypass_signature_verification",
                "package.signature-bypass-denial",
            ),
            cargo_test(
                "kernel",
                "package::tests::dependency_confusion_and_privilege_escalation_fail_closed",
                "package.dependency-confusion-denial",
            ),
        ),
    ),
    ScenarioSpec(
        scenario_id="node-loss",
        title="Node or process loss",
        runbook_anchor="docs/INCIDENT_RESPONSE.md#node-or-process-loss",
        commands=(
            cargo_test(
                "integration-tests",
                "persistence_props::crash_recovery_restores_everything",
                "node-loss.committed-state-recovery",
            ),
            cargo_test(
                "kernel",
                "cluster_control::tests::identity_is_stable_and_proves_private_key_possession",
                "node-loss.durable-node-identity",
            ),
        ),
    ),
    ScenarioSpec(
        scenario_id="corrupt-database",
        title="Corrupt database",
        runbook_anchor="docs/INCIDENT_RESPONSE.md#corrupt-database",
        commands=(
            cargo_test(
                "kernel",
                "storage::tests::corrupt_recovery_preserves_original_files_and_qualifies_backup",
                "database.corrupt-recovery-qualification",
            ),
            cargo_test(
                "kernel",
                "storage::tests::corrupt_recovery_qualification_failure_restores_original_and_keeps_candidate",
                "database.failed-recovery-rollback",
            ),
        ),
    ),
    ScenarioSpec(
        scenario_id="provider-outage",
        title="Provider outage",
        runbook_anchor="docs/INCIDENT_RESPONSE.md#provider-outage",
        commands=(
            CommandSpec(
                command_id="provider.outage-graceful-degradation",
                argv=(
                    "cargo",
                    "run",
                    "--release",
                    "--locked",
                    "--package",
                    "os-benchmark",
                    "--bin",
                    "resilience-qualification",
                    "--",
                    "--scenario",
                    "provider-outage",
                ),
                evidence_kind="resilience_report",
                timeout_seconds=1200,
            ),
        ),
    ),
)

EXPECTED_SCENARIOS = (
    "credential-compromise",
    "tenant-leak",
    "malicious-package",
    "node-loss",
    "corrupt-database",
    "provider-outage",
)

Runner = Callable[[CommandSpec, Sequence[str], Path], ProcessResult]


def validate_catalog(repo_root: Path) -> None:
    scenario_ids = tuple(scenario.scenario_id for scenario in SCENARIOS)
    if scenario_ids != EXPECTED_SCENARIOS:
        raise QualificationError(
            f"incident catalog must contain exactly {EXPECTED_SCENARIOS}, got {scenario_ids}"
        )
    command_ids = [
        command.command_id
        for scenario in SCENARIOS
        for command in scenario.commands
    ]
    if len(command_ids) != len(set(command_ids)):
        raise QualificationError("incident command IDs must be unique")
    for scenario in SCENARIOS:
        if not scenario.commands:
            raise QualificationError(f"{scenario.scenario_id} has no technical control")
        relative, separator, anchor = scenario.runbook_anchor.partition("#")
        if not separator or not anchor or not (repo_root / relative).is_file():
            raise QualificationError(
                f"{scenario.scenario_id} has an invalid runbook anchor"
            )
        for command in scenario.commands:
            if not command.argv or command.argv[0] != "cargo":
                raise QualificationError(
                    f"{command.command_id} is not a fixed Cargo command"
                )
            if command.evidence_kind not in {"cargo_test", "resilience_report"}:
                raise QualificationError(
                    f"{command.command_id} has an unknown evidence kind"
                )
            if command.evidence_kind == "cargo_test" and not command.expected_test:
                raise QualificationError(
                    f"{command.command_id} must name its exact expected test"
                )


def run_process(
    command: CommandSpec, argv: Sequence[str], repo_root: Path
) -> ProcessResult:
    try:
        completed = subprocess.run(
            list(argv),
            cwd=repo_root,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=command.timeout_seconds,
            env={**os.environ, "CARGO_TERM_COLOR": "never"},
        )
        return ProcessResult(completed.returncode, completed.stdout)
    except subprocess.TimeoutExpired:
        return ProcessResult(124, "")
    except OSError:
        return ProcessResult(127, "")


def _git(repo_root: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", *args],
        cwd=repo_root,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=15,
    )
    if completed.returncode != 0:
        raise QualificationError(f"git {' '.join(args)} failed")
    return completed.stdout.strip()


def source_metadata(repo_root: Path) -> dict[str, object]:
    return {
        "commit": _git(repo_root, "rev-parse", "HEAD"),
        "dirty": bool(_git(repo_root, "status", "--porcelain", "--untracked-files=all")),
    }


def environment_metadata(repo_root: Path) -> dict[str, str]:
    rustc = subprocess.run(
        ["rustc", "--version"],
        cwd=repo_root,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=15,
    )
    return {
        "os": platform.system().lower(),
        "architecture": platform.machine().lower(),
        "python": platform.python_version(),
        "rustc": rustc.stdout.strip() if rustc.returncode == 0 else "unavailable",
    }


def _exact_test_passed(output: str, expected_test: str) -> bool:
    return (
        "running 1 test" in output
        and f"test {expected_test} ... ok" in output
        and "1 passed; 0 failed;" in output
    )


def _load_resilience_evidence(
    path: Path, expected_commit: str, expected_dirty: bool
) -> tuple[bool, dict[str, object]]:
    try:
        raw = path.read_bytes()
        report = json.loads(raw)
        scenarios = report["scenarios"]
        scenario = scenarios[0]
        checks = scenario["checks"]
        valid = (
            report["schema_version"] == 1
            and report["qualification_class"] == "deterministic_resilience_fixture"
            and report["production_claim_allowed"] is False
            and report["build_profile"] == "release"
            and report["smoke_scaled"] is False
            and report["source"]["commit"] == expected_commit
            and report["source"]["dirty"] is expected_dirty
            and report["passed"] is True
            and len(scenarios) == 1
            and scenario["name"] == "provider-outage"
            and scenario["passed"] is True
            and isinstance(checks, dict)
            and bool(checks)
            and all(value is True for value in checks.values())
        )
        summary = {
            "child_schema_version": report.get("schema_version"),
            "child_qualification_class": report.get("qualification_class"),
            "child_source_commit": report.get("source", {}).get("commit"),
            "child_scenario": scenario.get("name"),
            "child_check_count": len(checks) if isinstance(checks, dict) else 0,
            "child_sha256": hashlib.sha256(raw).hexdigest(),
        }
        return valid, summary
    except (OSError, json.JSONDecodeError, KeyError, IndexError, TypeError):
        return False, {
            "child_schema_version": None,
            "child_qualification_class": None,
            "child_source_commit": None,
            "child_scenario": None,
            "child_check_count": 0,
            "child_sha256": None,
        }


def run_qualification(
    repo_root: Path,
    output_path: Path,
    runner: Runner = run_process,
    *,
    source: dict[str, object] | None = None,
    environment: dict[str, str] | None = None,
) -> dict[str, object]:
    validate_catalog(repo_root)
    source = source or source_metadata(repo_root)
    environment = environment or environment_metadata(repo_root)
    commit = source.get("commit")
    if not isinstance(commit, str) or len(commit) != 40:
        raise QualificationError("source commit must be a full Git SHA")
    dirty = source.get("dirty")
    if not isinstance(dirty, bool):
        raise QualificationError("source dirty state must be a boolean")

    child_path = output_path.parent / ".incident-provider-outage.json"
    scenario_results: list[dict[str, object]] = []
    for scenario in SCENARIOS:
        command_results: list[dict[str, object]] = []
        for command in scenario.commands:
            argv = list(command.argv)
            if command.evidence_kind == "resilience_report":
                try:
                    child_path.unlink()
                except FileNotFoundError:
                    pass
                argv.extend(["--output", str(child_path)])
            started = time.monotonic()
            result = runner(command, argv, repo_root)
            elapsed_ms = round((time.monotonic() - started) * 1000, 3)
            details: dict[str, object] = {}
            if command.evidence_kind == "cargo_test":
                evidence_valid = bool(
                    command.expected_test
                    and _exact_test_passed(result.output, command.expected_test)
                )
            else:
                evidence_valid, details = _load_resilience_evidence(
                    child_path, commit, dirty
                )
                try:
                    child_path.unlink()
                except FileNotFoundError:
                    pass
            passed = result.return_code == 0 and evidence_valid
            command_results.append(
                {
                    "command_id": command.command_id,
                    "evidence_kind": command.evidence_kind,
                    "return_code": result.return_code,
                    "elapsed_ms": elapsed_ms,
                    "evidence_valid": evidence_valid,
                    "passed": passed,
                    **details,
                }
            )
        scenario_results.append(
            {
                "scenario_id": scenario.scenario_id,
                "title": scenario.title,
                "runbook_anchor": scenario.runbook_anchor,
                "commands": command_results,
                "passed": all(item["passed"] is True for item in command_results),
            }
        )

    passed = all(item["passed"] is True for item in scenario_results)
    return {
        "schema_version": 1,
        "suite": "agentos-v1-incident-response",
        "generated_at": dt.datetime.now(dt.timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z"),
        "qualification_class": "automated_incident_drill_fixture",
        "proof_scope": "automated_technical_controls_only",
        "automated_drill_passed": passed,
        "human_game_day_completed": False,
        "game_day_proof_eligible": False,
        "production_claim_allowed": False,
        "source": source,
        "environment": environment,
        "scenarios": scenario_results,
        "passed": passed,
        "caveats": [
            "This artifact proves deterministic technical regressions, not operator response time, alert delivery, communications, or human decisions.",
            "A real exact-release-candidate game day with retained timeline and reviewer sign-off remains required.",
            "The provider outage is a deterministic fixture, not an external provider incident.",
        ],
    }


def write_report(path: Path, report: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    temporary.replace(path)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
    )
    parser.add_argument("--validate", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    repo_root = args.repo_root.resolve()
    try:
        validate_catalog(repo_root)
        if args.validate:
            if args.output is not None:
                parser.error("--validate cannot be combined with --output")
            print(
                "validated incident response schema v1 scenarios: "
                + ", ".join(EXPECTED_SCENARIOS)
            )
            return 0
        if args.output is None:
            parser.error("--output is required unless --validate is used")
        output = args.output
        if not output.is_absolute():
            output = repo_root / output
        report = run_qualification(repo_root, output)
        write_report(output, report)
        print(output)
        return 0 if report["passed"] is True else 1
    except QualificationError as error:
        print(f"incident qualification failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
