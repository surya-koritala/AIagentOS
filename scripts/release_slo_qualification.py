#!/usr/bin/env python3
"""Evaluate exact-release-candidate SLO evidence without trusting pass flags.

The input observation contains raw counts and measurements exported from the
target deployment. This program recalculates every target, rejects incomplete,
low-volume, short-window, fixture, dirty, or mixed-source evidence, and emits a
bounded report that contains hashes rather than the raw observation.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import math
import os
import re
import stat
import sys
from pathlib import Path
from typing import Any, Callable, Sequence


class QualificationError(RuntimeError):
    """The evidence could not be parsed or did not satisfy the schema."""


SCHEMA_VERSION = 1
SUITE = "agentos-v1-release-slo"
QUALIFICATION_CLASS = "target_release_candidate_slo_observation"
MAX_EVIDENCE_BYTES = 2 * 1024 * 1024
FULL_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
RELEASE_CANDIDATE_RE = re.compile(
    r"^v[0-9]+\.[0-9]+\.[0-9]+(?:-rc\.[1-9][0-9]*)?$"
)
MIN_24H_SECONDS = 86_400
MIN_30D_SECONDS = 2_592_000

TARGET_IDS = (
    "availability",
    "syscall_latency",
    "queue_wait",
    "llm_success",
    "tool_success",
    "auth_sandbox_denial",
    "data_durability",
    "checkpoint_recovery",
    "tenant_isolation",
)
INCIDENT_SCENARIO_IDS = (
    "credential-compromise",
    "tenant-leak",
    "malicious-package",
    "node-loss",
    "corrupt-database",
    "provider-outage",
)

TARGET_CONTRACT = {
    "availability": {
        "target": ">= 99.5%",
        "window": "rolling 30 days",
        "minimum_volume": "100000 eligible requests",
    },
    "syscall_latency": {
        "target": "control p95 < 1s and agent p95 < 30s",
        "window": "rolling 24 hours",
        "minimum_volume": "10000 control and 1000 agent requests",
    },
    "queue_wait": {
        "target": "mean < 250ms and zero starvation increments",
        "window": "rolling 24 hours",
        "minimum_volume": "10000 admissions",
    },
    "llm_success": {
        "target": ">= 99%, excluding policy/quota rejection",
        "window": "rolling 24 hours",
        "minimum_volume": "1000 eligible requests",
    },
    "tool_success": {
        "target": ">= 99.5% after allowed admission",
        "window": "rolling 24 hours",
        "minimum_volume": "1000 eligible requests",
    },
    "auth_sandbox_denial": {
        "target": "zero unexpected allows",
        "window": "per release",
        "minimum_volume": "100 adversarial attempts",
    },
    "data_durability": {
        "target": "ledger continuously healthy, backup <= 25h, restore passes",
        "window": "rolling 30 days and per release",
        "minimum_volume": "30 days of ledger observation",
    },
    "checkpoint_recovery": {
        "target": "100% recovered or safe rejection; zero cross-tenant recovery",
        "window": "per release",
        "minimum_volume": "100 attempts",
    },
    "tenant_isolation": {
        "target": "zero confirmed violations and game day completed",
        "window": "per release",
        "minimum_volume": "100 adversarial attempts",
    },
}


def _duplicates_rejected(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise QualificationError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def _load_json(path: Path, label: str) -> tuple[dict[str, Any], str]:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise QualificationError(f"{label} is unavailable") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise QualificationError(f"{label} must be a regular non-symlink file")
    if metadata.st_size <= 0 or metadata.st_size > MAX_EVIDENCE_BYTES:
        raise QualificationError(f"{label} has an invalid size")
    try:
        raw = path.read_bytes()
        value = json.loads(raw, object_pairs_hook=_duplicates_rejected)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise QualificationError(f"{label} is not valid JSON") from error
    if not isinstance(value, dict):
        raise QualificationError(f"{label} must contain one JSON object")
    return value, hashlib.sha256(raw).hexdigest()


def _exact_keys(value: dict[str, Any], expected: set[str], path: str) -> None:
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        unknown = sorted(actual - expected)
        raise QualificationError(
            f"{path} keys differ: missing={missing}, unknown={unknown}"
        )


def _object(value: Any, path: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise QualificationError(f"{path} must be an object")
    return value


def _string(value: Any, path: str, *, max_length: int = 200) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > max_length
        or any(ord(character) < 0x20 for character in value)
    ):
        raise QualificationError(f"{path} must be a bounded non-empty string")
    return value


def _boolean(value: Any, path: str) -> bool:
    if not isinstance(value, bool):
        raise QualificationError(f"{path} must be a boolean")
    return value


def _integer(value: Any, path: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise QualificationError(f"{path} must be an integer >= {minimum}")
    return value


def _number(value: Any, path: str, *, minimum: float = 0.0) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise QualificationError(f"{path} must be a finite number")
    result = float(value)
    if not math.isfinite(result) or result < minimum:
        raise QualificationError(f"{path} must be a finite number >= {minimum}")
    return result


def _timestamp(value: Any, path: str) -> dt.datetime:
    text = _string(value, path, max_length=40)
    if not text.endswith("Z"):
        raise QualificationError(f"{path} must be an RFC3339 UTC timestamp")
    try:
        parsed = dt.datetime.fromisoformat(text[:-1] + "+00:00")
    except ValueError as error:
        raise QualificationError(f"{path} must be an RFC3339 UTC timestamp") from error
    if parsed.tzinfo != dt.timezone.utc:
        raise QualificationError(f"{path} must use UTC")
    return parsed


def _safe_identifier(value: Any, path: str) -> str:
    text = _string(value, path, max_length=100)
    if (
        text.lower() in {"local", "smoke", "fixture", "test", "development", "dev"}
        or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", text)
    ):
        raise QualificationError(f"{path} is not a stable target identifier")
    return text


def _validate_source(
    value: Any,
    expected_commit: str,
    path: str,
    *,
    allowed_extra: set[str] | None = None,
) -> dict[str, Any]:
    source = _object(value, path)
    _exact_keys(source, {"commit", "dirty"} | (allowed_extra or set()), path)
    commit = _string(source["commit"], f"{path}.commit", max_length=40)
    dirty = _boolean(source["dirty"], f"{path}.dirty")
    if not FULL_SHA_RE.fullmatch(commit):
        raise QualificationError(f"{path}.commit must be a full lowercase Git SHA")
    if commit != expected_commit:
        raise QualificationError(f"{path}.commit does not match the requested commit")
    if dirty:
        raise QualificationError(f"{path}.dirty must be false")
    for key in allowed_extra or set():
        _string(source[key], f"{path}.{key}")
    return {"commit": commit, "dirty": dirty}


def _validate_environment(
    value: Any, expected_environment: str
) -> dict[str, str]:
    environment = _object(value, "observation.environment")
    expected = {
        "environment_id",
        "deployment_mode",
        "os",
        "arch",
        "hardware",
        "provider",
        "model",
        "configuration_sha256",
        "dataset_sha256",
    }
    _exact_keys(environment, expected, "observation.environment")
    result = {
        key: _string(environment[key], f"observation.environment.{key}")
        for key in expected
    }
    result["environment_id"] = _safe_identifier(
        result["environment_id"], "observation.environment.environment_id"
    )
    if result["environment_id"] != expected_environment:
        raise QualificationError("observation environment does not match requested target")
    if result["os"] != "linux":
        raise QualificationError("release SLO evidence currently requires Linux")
    for digest_key in ("configuration_sha256", "dataset_sha256"):
        if not SHA256_RE.fullmatch(result[digest_key]):
            raise QualificationError(
                f"observation.environment.{digest_key} must be a SHA-256 digest"
            )
    return result


def _validate_alerts(
    value: Any, window_start: dt.datetime, window_end: dt.datetime
) -> dict[str, int]:
    if not isinstance(value, list) or len(value) > 1000:
        raise QualificationError("observation.alert_firings must be a bounded array")
    unresolved = 0
    critical = 0
    for index, item in enumerate(value):
        path = f"observation.alert_firings[{index}]"
        alert = _object(item, path)
        _exact_keys(alert, {"name", "severity", "fired_at", "resolved_at"}, path)
        _safe_identifier(alert["name"], f"{path}.name")
        severity = _string(alert["severity"], f"{path}.severity", max_length=20)
        if severity not in {"warning", "critical"}:
            raise QualificationError(f"{path}.severity is unsupported")
        if severity == "critical":
            critical += 1
        fired = _timestamp(alert["fired_at"], f"{path}.fired_at")
        resolved_raw = alert["resolved_at"]
        resolved = (
            None
            if resolved_raw is None
            else _timestamp(resolved_raw, f"{path}.resolved_at")
        )
        if fired < window_start or fired > window_end:
            raise QualificationError(f"{path}.fired_at is outside the observation window")
        if resolved is not None and (resolved < fired or resolved > window_end):
            raise QualificationError(f"{path}.resolved_at is invalid")
        if resolved is None:
            unresolved += 1
    return {
        "firing_count": len(value),
        "critical_firing_count": critical,
        "unresolved_firing_count": unresolved,
    }


def _ratio(success: int, total: int) -> float | None:
    return None if total == 0 else success / total


def _target(
    target_id: str,
    observed: dict[str, Any],
    checks: list[tuple[str, bool]],
) -> dict[str, Any]:
    failed = [check_id for check_id, passed in checks if not passed]
    return {
        "target_id": target_id,
        **TARGET_CONTRACT[target_id],
        "observed": observed,
        "passed": not failed,
        "failed_checks": failed,
    }


def _validate_sli_keys(
    slis: dict[str, Any], target_id: str, expected: set[str]
) -> dict[str, Any]:
    value = _object(slis[target_id], f"observation.slis.{target_id}")
    _exact_keys(value, expected, f"observation.slis.{target_id}")
    return value


def _evaluate_slis(slis_value: Any) -> list[dict[str, Any]]:
    slis = _object(slis_value, "observation.slis")
    _exact_keys(slis, set(TARGET_IDS), "observation.slis")
    results: list[dict[str, Any]] = []

    value = _validate_sli_keys(
        slis,
        "availability",
        {"window_seconds", "success", "failed", "timed_out", "cancelled"},
    )
    window = _integer(value["window_seconds"], "availability.window_seconds")
    success = _integer(value["success"], "availability.success")
    failed = _integer(value["failed"], "availability.failed")
    timed_out = _integer(value["timed_out"], "availability.timed_out")
    cancelled = _integer(value["cancelled"], "availability.cancelled")
    total = success + failed + timed_out + cancelled
    ratio = _ratio(success, total)
    results.append(
        _target(
            "availability",
            {
                "window_seconds": window,
                "eligible_requests": total,
                "success_ratio": ratio,
            },
            [
                ("window_at_least_30_days", window >= MIN_30D_SECONDS),
                ("minimum_volume", total >= 100_000),
                ("success_ratio", ratio is not None and ratio >= 0.995),
            ],
        )
    )

    value = _validate_sli_keys(
        slis,
        "syscall_latency",
        {
            "window_seconds",
            "control_p95_seconds",
            "control_requests",
            "agent_p95_seconds",
            "agent_requests",
        },
    )
    window = _integer(value["window_seconds"], "syscall_latency.window_seconds")
    control_p95 = _number(
        value["control_p95_seconds"], "syscall_latency.control_p95_seconds"
    )
    control_requests = _integer(
        value["control_requests"], "syscall_latency.control_requests"
    )
    agent_p95 = _number(
        value["agent_p95_seconds"], "syscall_latency.agent_p95_seconds"
    )
    agent_requests = _integer(
        value["agent_requests"], "syscall_latency.agent_requests"
    )
    results.append(
        _target(
            "syscall_latency",
            {
                "window_seconds": window,
                "control_p95_seconds": control_p95,
                "control_requests": control_requests,
                "agent_p95_seconds": agent_p95,
                "agent_requests": agent_requests,
            },
            [
                ("window_at_least_24_hours", window >= MIN_24H_SECONDS),
                ("minimum_control_volume", control_requests >= 10_000),
                ("minimum_agent_volume", agent_requests >= 1_000),
                ("control_p95_below_1_second", control_p95 < 1.0),
                ("agent_p95_below_30_seconds", agent_p95 < 30.0),
            ],
        )
    )

    value = _validate_sli_keys(
        slis,
        "queue_wait",
        {"window_seconds", "wait_seconds_delta", "admissions_delta", "starvation_delta"},
    )
    window = _integer(value["window_seconds"], "queue_wait.window_seconds")
    wait_seconds = _number(value["wait_seconds_delta"], "queue_wait.wait_seconds_delta")
    admissions = _integer(value["admissions_delta"], "queue_wait.admissions_delta")
    starvation = _integer(value["starvation_delta"], "queue_wait.starvation_delta")
    mean_wait = None if admissions == 0 else wait_seconds / admissions
    results.append(
        _target(
            "queue_wait",
            {
                "window_seconds": window,
                "admissions": admissions,
                "mean_wait_seconds": mean_wait,
                "starvation_delta": starvation,
            },
            [
                ("window_at_least_24_hours", window >= MIN_24H_SECONDS),
                ("minimum_volume", admissions >= 10_000),
                ("mean_wait_below_250ms", mean_wait is not None and mean_wait < 0.25),
                ("zero_starvation", starvation == 0),
            ],
        )
    )

    for target_id, threshold in (("llm_success", 0.99), ("tool_success", 0.995)):
        expected_fields = {
            "window_seconds",
            "success",
            "failed",
            "timed_out",
            "cancelled",
            "policy_quota_rejected",
        }
        if target_id == "llm_success":
            expected_fields.update(
                {
                    "live_provider_qualification_passed",
                    "live_provider_evidence_sha256",
                }
            )
        value = _validate_sli_keys(
            slis,
            target_id,
            expected_fields,
        )
        window = _integer(value["window_seconds"], f"{target_id}.window_seconds")
        success = _integer(value["success"], f"{target_id}.success")
        failed = _integer(value["failed"], f"{target_id}.failed")
        timed_out = _integer(value["timed_out"], f"{target_id}.timed_out")
        cancelled = _integer(value["cancelled"], f"{target_id}.cancelled")
        rejected = _integer(
            value["policy_quota_rejected"], f"{target_id}.policy_quota_rejected"
        )
        live_provider_passed = True
        live_provider_evidence_sha256: str | None = None
        if target_id == "llm_success":
            live_provider_passed = _boolean(
                value["live_provider_qualification_passed"],
                "llm_success.live_provider_qualification_passed",
            )
            live_provider_evidence_sha256 = _string(
                value["live_provider_evidence_sha256"],
                "llm_success.live_provider_evidence_sha256",
                max_length=64,
            )
            if not SHA256_RE.fullmatch(live_provider_evidence_sha256):
                raise QualificationError(
                    "llm_success.live_provider_evidence_sha256 must be a SHA-256 digest"
                )
        total = success + failed + timed_out + cancelled
        ratio = _ratio(success, total)
        results.append(
            _target(
                target_id,
                {
                    "window_seconds": window,
                    "eligible_requests": total,
                    "excluded_policy_quota_rejections": rejected,
                    "success_ratio": ratio,
                    **(
                        {
                            "live_provider_qualification_passed": live_provider_passed,
                            "live_provider_evidence_sha256": live_provider_evidence_sha256,
                        }
                        if target_id == "llm_success"
                        else {}
                    ),
                },
                [
                    ("window_at_least_24_hours", window >= MIN_24H_SECONDS),
                    ("minimum_volume", total >= 1_000),
                    (
                        "success_ratio",
                        ratio is not None and ratio >= threshold,
                    ),
                    *(
                        [
                            (
                                "live_provider_qualification_passed",
                                live_provider_passed,
                            )
                        ]
                        if target_id == "llm_success"
                        else []
                    ),
                ],
            )
        )

    value = _validate_sli_keys(
        slis,
        "auth_sandbox_denial",
        {"adversarial_attempts", "unexpected_allows"},
    )
    attempts = _integer(
        value["adversarial_attempts"], "auth_sandbox_denial.adversarial_attempts"
    )
    unexpected = _integer(
        value["unexpected_allows"], "auth_sandbox_denial.unexpected_allows"
    )
    results.append(
        _target(
            "auth_sandbox_denial",
            {"adversarial_attempts": attempts, "unexpected_allows": unexpected},
            [
                ("minimum_volume", attempts >= 100),
                ("zero_unexpected_allows", unexpected == 0),
            ],
        )
    )

    value = _validate_sli_keys(
        slis,
        "data_durability",
        {
            "continuous_ledger_healthy_seconds",
            "ledger_unhealthy_seconds",
            "latest_verified_backup_age_seconds",
            "restore_drill_passed",
        },
    )
    healthy_seconds = _integer(
        value["continuous_ledger_healthy_seconds"],
        "data_durability.continuous_ledger_healthy_seconds",
    )
    unhealthy_seconds = _integer(
        value["ledger_unhealthy_seconds"], "data_durability.ledger_unhealthy_seconds"
    )
    backup_age = _number(
        value["latest_verified_backup_age_seconds"],
        "data_durability.latest_verified_backup_age_seconds",
    )
    restore_passed = _boolean(
        value["restore_drill_passed"], "data_durability.restore_drill_passed"
    )
    results.append(
        _target(
            "data_durability",
            {
                "continuous_ledger_healthy_seconds": healthy_seconds,
                "ledger_unhealthy_seconds": unhealthy_seconds,
                "latest_verified_backup_age_seconds": backup_age,
                "restore_drill_passed": restore_passed,
            },
            [
                ("ledger_observed_for_30_days", healthy_seconds >= MIN_30D_SECONDS),
                ("ledger_continuously_healthy", unhealthy_seconds == 0),
                ("verified_backup_within_25_hours", backup_age <= 90_000),
                ("restore_drill_passed", restore_passed),
            ],
        )
    )

    value = _validate_sli_keys(
        slis,
        "checkpoint_recovery",
        {"attempted", "recovered", "safe_rejected", "cross_tenant_recoveries"},
    )
    attempted = _integer(value["attempted"], "checkpoint_recovery.attempted")
    recovered = _integer(value["recovered"], "checkpoint_recovery.recovered")
    safe_rejected = _integer(
        value["safe_rejected"], "checkpoint_recovery.safe_rejected"
    )
    cross_tenant = _integer(
        value["cross_tenant_recoveries"],
        "checkpoint_recovery.cross_tenant_recoveries",
    )
    if recovered + safe_rejected > attempted:
        raise QualificationError("checkpoint recovery outcomes exceed attempts")
    results.append(
        _target(
            "checkpoint_recovery",
            {
                "attempted": attempted,
                "recovered": recovered,
                "safe_rejected": safe_rejected,
                "cross_tenant_recoveries": cross_tenant,
            },
            [
                ("minimum_volume", attempted >= 100),
                ("every_attempt_accounted", recovered + safe_rejected == attempted),
                ("zero_cross_tenant_recovery", cross_tenant == 0),
            ],
        )
    )

    value = _validate_sli_keys(
        slis,
        "tenant_isolation",
        {
            "adversarial_attempts",
            "confirmed_violations",
            "game_day_completed",
            "game_day_evidence_sha256",
        },
    )
    attempts = _integer(
        value["adversarial_attempts"], "tenant_isolation.adversarial_attempts"
    )
    violations = _integer(
        value["confirmed_violations"], "tenant_isolation.confirmed_violations"
    )
    game_day = _boolean(
        value["game_day_completed"], "tenant_isolation.game_day_completed"
    )
    game_day_evidence = value["game_day_evidence_sha256"]
    if game_day:
        game_day_evidence = _string(
            game_day_evidence,
            "tenant_isolation.game_day_evidence_sha256",
            max_length=64,
        )
        if not SHA256_RE.fullmatch(game_day_evidence):
            raise QualificationError(
                "tenant_isolation.game_day_evidence_sha256 must be a SHA-256 digest"
            )
    elif game_day_evidence is not None:
        raise QualificationError(
            "tenant isolation cannot cite game-day evidence when completion is false"
        )
    results.append(
        _target(
            "tenant_isolation",
            {
                "adversarial_attempts": attempts,
                "confirmed_violations": violations,
                "game_day_completed": game_day,
                "game_day_evidence_sha256": game_day_evidence,
            },
            [
                ("minimum_volume", attempts >= 100),
                ("zero_confirmed_violations", violations == 0),
                ("game_day_completed", game_day),
            ],
        )
    )
    return results


def _validate_observation(
    report: dict[str, Any],
    expected_commit: str,
    expected_environment: str,
    release_candidate: str,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    _exact_keys(
        report,
        {
            "schema_version",
            "qualification_class",
            "release_candidate",
            "source",
            "environment",
            "window",
            "alert_firings",
            "slis",
        },
        "observation",
    )
    if _integer(report["schema_version"], "observation.schema_version") != SCHEMA_VERSION:
        raise QualificationError("observation schema version is unsupported")
    if report["qualification_class"] != QUALIFICATION_CLASS:
        raise QualificationError("observation is not target release-candidate evidence")
    observed_rc = _string(
        report["release_candidate"], "observation.release_candidate", max_length=50
    )
    if observed_rc != release_candidate:
        raise QualificationError("observation release candidate does not match request")
    source = _validate_source(report["source"], expected_commit, "observation.source")
    environment = _validate_environment(report["environment"], expected_environment)
    window = _object(report["window"], "observation.window")
    _exact_keys(window, {"start", "end"}, "observation.window")
    start = _timestamp(window["start"], "observation.window.start")
    end = _timestamp(window["end"], "observation.window.end")
    if end <= start:
        raise QualificationError("observation window end must be after start")
    window_seconds = int((end - start).total_seconds())
    if window_seconds < MIN_30D_SECONDS:
        raise QualificationError("observation window must cover at least 30 days")
    alert_summary = _validate_alerts(report["alert_firings"], start, end)
    targets = _evaluate_slis(report["slis"])
    for target in targets:
        target_window = target["observed"].get("window_seconds")
        if isinstance(target_window, (int, float)) and target_window > window_seconds:
            raise QualificationError(
                f"{target['target_id']} window exceeds the observation envelope"
            )
    durability = next(
        target for target in targets if target["target_id"] == "data_durability"
    )
    if (
        durability["observed"]["continuous_ledger_healthy_seconds"]
        > window_seconds
    ):
        raise QualificationError(
            "data durability observation exceeds the observation envelope"
        )
    metadata = {
        "source": source,
        "environment": environment,
        "window": {
            "start": window["start"],
            "end": window["end"],
            "duration_seconds": window_seconds,
        },
        "alert_summary": alert_summary,
    }
    return metadata, targets


def _validate_soak(
    report: dict[str, Any], expected_commit: str, expected_environment: str
) -> dict[str, Any]:
    _validate_source(
        report.get("source"),
        expected_commit,
        "soak.source",
        allowed_extra={"rustc"},
    )
    if report.get("schema_version") != 1:
        raise QualificationError("resource soak schema version is unsupported")
    if report.get("qualification_class") != "target_resource_soak":
        raise QualificationError("resource soak is not target evidence")
    environment = _object(report.get("environment"), "soak.environment")
    if environment.get("environment_id") != expected_environment:
        raise QualificationError("resource soak environment does not match target")
    build_profile = _string(report.get("build_profile"), "soak.build_profile")
    smoke_scaled = _boolean(report.get("smoke_scaled"), "soak.smoke_scaled")
    proof_eligible = _boolean(
        report.get("resource_soak_proof_eligible"),
        "soak.resource_soak_proof_eligible",
    )
    production_claim = _boolean(
        report.get("production_claim_allowed"), "soak.production_claim_allowed"
    )
    configuration = _object(report.get("configuration"), "soak.configuration")
    duration = _integer(
        configuration.get("duration_seconds"), "soak.configuration.duration_seconds"
    )
    result = _object(report.get("result"), "soak.result")
    result_passed = _boolean(result.get("passed"), "soak.result.passed")
    elapsed = _number(result.get("elapsed_seconds"), "soak.result.elapsed_seconds")
    samples = report["result"].get("samples")
    if not isinstance(samples, list):
        raise QualificationError("soak.result.samples must be an array")
    child_checks = _object(result.get("checks"), "soak.result.checks")
    if not child_checks or any(
        not isinstance(check_id, str) or not isinstance(passed, bool)
        for check_id, passed in child_checks.items()
    ):
        raise QualificationError("soak.result.checks must be a non-empty boolean map")
    checks = [
        ("release_build", build_profile == "release"),
        ("not_smoke_scaled", smoke_scaled is False),
        ("child_proof_eligible", proof_eligible is True),
        ("child_production_claim_false", production_claim is False),
        ("child_result_passed", result_passed is True),
        ("every_child_check_passed", all(child_checks.values())),
        ("configured_for_24_hours", duration >= MIN_24H_SECONDS),
        ("elapsed_for_24_hours", elapsed >= MIN_24H_SECONDS),
        ("sustained_sample_count", len(samples) >= 1_000),
    ]
    failed = [check_id for check_id, passed in checks if not passed]
    return {
        "passed": not failed,
        "failed_checks": failed,
        "duration_seconds": duration,
        "elapsed_seconds": elapsed,
        "sample_count": len(samples),
    }


def _validate_incident(
    report: dict[str, Any], expected_commit: str
) -> dict[str, Any]:
    _validate_source(report.get("source"), expected_commit, "incident.source")
    if report.get("schema_version") != 1:
        raise QualificationError("incident drill schema version is unsupported")
    if report.get("qualification_class") != "automated_incident_drill_fixture":
        raise QualificationError("incident drill classification is unsupported")
    scenarios = report.get("scenarios")
    if not isinstance(scenarios, list):
        raise QualificationError("incident.scenarios must be an array")
    scenario_ids: list[Any] = []
    scenario_passes: list[bool] = []
    command_passes: list[bool] = []
    for index, scenario_value in enumerate(scenarios):
        scenario = _object(scenario_value, f"incident.scenarios[{index}]")
        scenario_ids.append(scenario.get("scenario_id"))
        scenario_passes.append(scenario.get("passed") is True)
        commands = scenario.get("commands")
        if not isinstance(commands, list) or not commands:
            command_passes.append(False)
            continue
        command_passes.extend(
            isinstance(command, dict)
            and command.get("passed") is True
            and command.get("evidence_valid") is True
            for command in commands
        )
    checks = [
        (
            "automated_scope",
            report.get("proof_scope") == "automated_technical_controls_only",
        ),
        ("automated_drill_passed", report.get("automated_drill_passed") is True),
        ("child_report_passed", report.get("passed") is True),
        ("child_production_claim_false", report.get("production_claim_allowed") is False),
        ("exact_scenarios_present", tuple(scenario_ids) == INCIDENT_SCENARIO_IDS),
        ("every_scenario_passed", bool(scenarios) and all(scenario_passes)),
        ("every_command_evidence_passed", bool(command_passes) and all(command_passes)),
    ]
    failed = [check_id for check_id, passed in checks if not passed]
    return {
        "passed": not failed,
        "failed_checks": failed,
        "scenario_count": len(scenarios),
    }


def evaluate(
    observation_path: Path,
    soak_path: Path,
    incident_path: Path,
    *,
    expected_commit: str,
    expected_environment: str,
    release_candidate: str,
) -> dict[str, Any]:
    if not FULL_SHA_RE.fullmatch(expected_commit):
        raise QualificationError("expected commit must be a full lowercase Git SHA")
    expected_environment = _safe_identifier(
        expected_environment, "expected environment"
    )
    if not RELEASE_CANDIDATE_RE.fullmatch(release_candidate):
        raise QualificationError(
            "release candidate must look like v1.2.3 or v1.2.3-rc.1"
        )

    observation, observation_sha = _load_json(observation_path, "observation")
    soak, soak_sha = _load_json(soak_path, "resource soak")
    incident, incident_sha = _load_json(incident_path, "incident drill")
    metadata, targets = _validate_observation(
        observation, expected_commit, expected_environment, release_candidate
    )
    soak_result = _validate_soak(soak, expected_commit, expected_environment)
    incident_result = _validate_incident(incident, expected_commit)

    failed_targets = [
        result["target_id"] for result in targets if result["passed"] is not True
    ]
    eligibility_blockers = list(failed_targets)
    if metadata["alert_summary"]["unresolved_firing_count"] != 0:
        eligibility_blockers.append("unresolved_alerts")
    eligibility_blockers.extend(
        f"resource_soak.{check_id}" for check_id in soak_result["failed_checks"]
    )
    eligibility_blockers.extend(
        f"incident_drill.{check_id}"
        for check_id in incident_result["failed_checks"]
    )
    eligible = not eligibility_blockers
    return {
        "schema_version": SCHEMA_VERSION,
        "suite": SUITE,
        "generated_at": dt.datetime.now(dt.timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z"),
        "qualification_class": "exact_release_candidate_slo_report",
        "release_candidate": release_candidate,
        "report_generated": True,
        "release_slo_proof_eligible": eligible,
        "production_claim_allowed": False,
        **metadata,
        "evidence": {
            "observation_sha256": observation_sha,
            "resource_soak_sha256": soak_sha,
            "incident_drill_sha256": incident_sha,
            "same_clean_source_commit": True,
            "same_target_environment": True,
        },
        "prerequisites": {
            "resource_soak": soak_result,
            "incident_drill": incident_result,
        },
        "targets": targets,
        "failed_targets": failed_targets,
        "eligibility_blockers": eligibility_blockers,
        "caveats": [
            "This report recalculates release SLOs from target evidence; it does not independently attest that the source telemetry was collected correctly.",
            "production_claim_allowed remains false until the separate release, security, deployment, and independent-review gates are complete.",
            "External Alertmanager receiver delivery is a separate target-infrastructure qualification.",
        ],
    }


def write_report(path: Path, report: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    os.replace(temporary, path)


def validate_contract() -> None:
    if tuple(TARGET_CONTRACT) != TARGET_IDS:
        raise QualificationError("SLO target contract order or inventory changed")
    if len(set(TARGET_IDS)) != len(TARGET_IDS):
        raise QualificationError("SLO target identifiers must be unique")
    for target_id in TARGET_IDS:
        if set(TARGET_CONTRACT[target_id]) != {"target", "window", "minimum_volume"}:
            raise QualificationError(f"{target_id} contract is incomplete")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--validate", action="store_true")
    parser.add_argument("--observation", type=Path)
    parser.add_argument("--resource-soak", type=Path)
    parser.add_argument("--incident-drill", type=Path)
    parser.add_argument("--expected-commit")
    parser.add_argument("--expected-environment")
    parser.add_argument("--release-candidate")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--require-eligible", action="store_true")
    args = parser.parse_args(argv)
    try:
        validate_contract()
        if args.validate:
            supplied = [
                args.observation,
                args.resource_soak,
                args.incident_drill,
                args.expected_commit,
                args.expected_environment,
                args.release_candidate,
                args.output,
            ]
            if any(value is not None for value in supplied) or args.require_eligible:
                parser.error("--validate cannot be combined with report arguments")
            print(
                f"validated release SLO schema v{SCHEMA_VERSION} targets: "
                + ", ".join(TARGET_IDS)
            )
            return 0
        required = {
            "--observation": args.observation,
            "--resource-soak": args.resource_soak,
            "--incident-drill": args.incident_drill,
            "--expected-commit": args.expected_commit,
            "--expected-environment": args.expected_environment,
            "--release-candidate": args.release_candidate,
            "--output": args.output,
        }
        missing = [name for name, value in required.items() if value is None]
        if missing:
            parser.error("required arguments missing: " + ", ".join(missing))
        report = evaluate(
            args.observation,
            args.resource_soak,
            args.incident_drill,
            expected_commit=args.expected_commit,
            expected_environment=args.expected_environment,
            release_candidate=args.release_candidate,
        )
        write_report(args.output, report)
        print(args.output)
        if args.require_eligible and report["release_slo_proof_eligible"] is not True:
            return 1
        return 0
    except QualificationError as error:
        print(f"release SLO qualification failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
