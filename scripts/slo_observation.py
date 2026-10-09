#!/usr/bin/env python3
"""Produce all nine SLI observations from retained target measurements.

Read raw Prometheus range vectors or an archive of the same samples. Count
observed increases without extrapolating integer events. Alertmanager's current
API is never substituted for the required retained notification history.
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
import urllib.error
import urllib.parse
import urllib.request
from collections import defaultdict
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any, Iterable, Iterator

import release_slo_qualification as evaluator
import phase1_promotion_qualification as campaign


class ObservationError(RuntimeError):
    """Missing, inconsistent or unbounded target measurement input."""


MAX_JSON_BYTES = 16 * 1024 * 1024
MAX_ARCHIVE_BYTES = 128 * 1024 * 1024
MAX_LINE_BYTES = 128 * 1024
MAX_SERIES = 200
MAX_SAMPLES_PER_CHUNK = 200_000
MAX_WINDOW_SECONDS = 32 * 86_400
MAX_GAP_SECONDS = 120
OUTCOMES = ("success", "failed", "timed_out", "cancelled")
SUBSYSTEMS = frozenset(
    "agent auth checkpoint cluster memory operator package protocol service storage system tool".split()
)
BUCKETS = tuple(Decimal(value) for value in (
    "0.005", "0.010", "0.025", "0.050", "0.100", "0.250", "0.500",
    "1.000", "2.500", "5.000", "10.000", "30.000", "60.000", "Infinity",
))
SCALARS = (
    "agentos_turn_wait_nanoseconds_total",
    "agentos_turn_admitted_total",
    "agentos_turn_starvation_total",
    "agentos_adversarial_attempts_total",
    "agentos_unexpected_allows_total",
    "agentos_tenant_boundary_attempts_total",
    "agentos_confirmed_violations_total",
    "agentos_checkpoint_recovery_attempts_total",
    "agentos_checkpoint_cross_tenant_recoveries_total",
    "agentos_quota_storage_healthy_seconds_total",
    "agentos_quota_storage_unhealthy_seconds_total",
    "agentos_backup_last_success_unixtime_seconds",
    "agentos_process_uptime_seconds",
    "agentos_build_source_verified",
)
FAMILIES = SCALARS + (
    "agentos_requests_total", "agentos_request_class_total",
    "agentos_request_class_duration_seconds_bucket",
    "agentos_request_class_duration_seconds_count",
    "agentos_llm_requests_total", "agentos_checkpoint_recovery_total",
    "agentos_quota_denied_total", "agentos_telemetry_contract_info",
    "agentos_build_source_sha1",
)
GAUGES = frozenset((
    "agentos_process_uptime_seconds", "agentos_backup_last_success_unixtime_seconds",
    "agentos_telemetry_contract_info",
    "agentos_build_source_sha1", "agentos_build_source_verified",
))
FRACTIONAL_COUNTERS = frozenset((
    "agentos_quota_storage_healthy_seconds_total",
    "agentos_quota_storage_unhealthy_seconds_total",
))


def exact_keys(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise ObservationError(f"{label} keys differ")
    return value


def decode_json(raw: bytes, label: str) -> Any:
    try:
        return json.loads(raw, object_pairs_hook=evaluator._duplicates_rejected)
    except (UnicodeError, ValueError, evaluator.QualificationError) as error:
        raise ObservationError(f"{label} is not unique-key JSON") from error


def open_regular(path: Path):
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode):
        raise ObservationError("input must be a regular non-symlink file")
    descriptor = os.open(path, flags)
    after = os.fstat(descriptor)
    if not stat.S_ISREG(after.st_mode) or (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
        os.close(descriptor)
        raise ObservationError("input changed while opening")
    return os.fdopen(descriptor, "rb")


def read_json(path: Path) -> tuple[dict[str, Any], str]:
    with open_regular(path) as source:
        raw = source.read(MAX_JSON_BYTES + 1)
    if not raw or len(raw) > MAX_JSON_BYTES:
        raise ObservationError("JSON input exceeds its size bound")
    value = decode_json(raw, "input")
    if not isinstance(value, dict):
        raise ObservationError("JSON input must contain an object")
    return value, hashlib.sha256(raw).hexdigest()


def file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with open_regular(path) as source:
        while raw := source.read(1024 * 1024):
            digest.update(raw)
    return digest.hexdigest()


def timestamp(value: str) -> Decimal:
    try:
        return Decimal(str(evaluator._timestamp(value, "timestamp").timestamp()))
    except evaluator.QualificationError as error:
        raise ObservationError(str(error)) from error


def utc(value: Decimal) -> str:
    return dt.datetime.fromtimestamp(float(value), dt.timezone.utc).isoformat().replace("+00:00", "Z")


def number(value: Any, label: str, *, integer: bool = False) -> Decimal:
    if isinstance(value, bool) or not isinstance(value, (int, float, str, Decimal)):
        raise ObservationError(f"{label} is not numeric")
    try:
        result = Decimal(str(value))
    except InvalidOperation as error:
        raise ObservationError(f"{label} is not numeric") from error
    if not result.is_finite() or result < 0 or (integer and result != result.to_integral_value()):
        raise ObservationError(f"{label} must be finite and non-negative")
    if result > Decimal(2**64 - 1):
        raise ObservationError(f"{label} exceeds the runtime counter bound")
    return result


MetricKey = tuple[str, tuple[tuple[str, str], ...]]


def metric_key(name: str, labels: Any) -> MetricKey:
    if name not in FAMILIES or not isinstance(labels, dict):
        raise ObservationError("unknown metric or invalid labels")
    if any(not isinstance(key, str) or not isinstance(value, str) for key, value in labels.items()):
        raise ObservationError("metric labels must be strings")
    valid = False
    if name in SCALARS:
        valid = not labels
    elif name == "agentos_requests_total":
        valid = set(labels) == {"subsystem", "outcome"} and labels["subsystem"] in SUBSYSTEMS and labels["outcome"] in OUTCOMES + ("rejected",)
    elif name in {"agentos_request_class_total", "agentos_request_class_duration_seconds_count"}:
        valid = set(labels) == {"class"} and labels["class"] in {"agent", "control"}
    elif name == "agentos_request_class_duration_seconds_bucket":
        if set(labels) == {"class", "le"} and labels["class"] in {"agent", "control"}:
            try:
                boundary = Decimal(labels["le"])
                valid = boundary in BUCKETS
                labels = {**labels, "le": str(boundary)}
            except InvalidOperation:
                pass
    elif name == "agentos_llm_requests_total":
        valid = set(labels) == {"outcome"} and labels["outcome"] in OUTCOMES
    elif name == "agentos_checkpoint_recovery_total":
        valid = set(labels) == {"outcome"} and labels["outcome"] in {"recovered", "safe_rejected"}
    elif name == "agentos_quota_denied_total":
        valid = set(labels) == {"scope", "dimension"} and (labels["scope"], labels["dimension"]) in {
            ("provider", "requests"), ("provider", "tokens"),
            ("cgroup", "requests"), ("cgroup", "tokens"), ("provider", "migration_fence"),
        }
    elif name == "agentos_telemetry_contract_info":
        valid = labels == {"version": "2"}
    elif name == "agentos_build_source_sha1":
        valid = set(labels) == {"part"} and labels["part"] in {"0", "1", "2", "3", "4"}
    if not valid:
        raise ObservationError(f"{name} has undeclared metric labels")
    return name, tuple(sorted(labels.items()))


def parse_samples(samples: Any) -> dict[MetricKey, Decimal]:
    if not isinstance(samples, list) or not 1 <= len(samples) <= MAX_SERIES:
        raise ObservationError("snapshot has an invalid series count")
    result: dict[MetricKey, Decimal] = {}
    for sample in samples:
        exact_keys(sample, {"name", "labels", "value"}, "metric sample")
        key = metric_key(sample["name"], sample["labels"])
        if key in result:
            raise ObservationError("duplicate metric series")
        result[key] = number(sample["value"], key[0], integer=key[0] not in FRACTIONAL_COUNTERS)
    for name in SCALARS:
        if (name, ()) not in result:
            raise ObservationError(f"required metric absent: {name}")
    if result.get(metric_key("agentos_telemetry_contract_info", {"version": "2"})) != 1:
        raise ObservationError("telemetry contract v2 is required")
    for part in range(5):
        value = result.get(metric_key("agentos_build_source_sha1", {"part": str(part)}))
        if value is None or value > 2**32 - 1:
            raise ObservationError("compiled runtime source identity is incomplete")
    for outcome in OUTCOMES:
        if metric_key("agentos_llm_requests_total", {"outcome": outcome}) not in result:
            raise ObservationError("provider outcome source is incomplete")
    recovery = [result.get(metric_key("agentos_checkpoint_recovery_total", {"outcome": outcome})) for outcome in ("recovered", "safe_rejected")]
    if None in recovery or sum(recovery) != result[("agentos_checkpoint_recovery_attempts_total", ())]:
        raise ObservationError("checkpoint attempt/outcome snapshot is inconsistent")
    return result


def archive_frames(paths: list[Path], binding: dict[str, Any]) -> Iterator[tuple[Decimal, dict[MetricKey, Decimal]]]:
    if not 1 <= len(paths) <= 64:
        raise ObservationError("metrics archive requires one to 64 files")
    for path in paths:
        with open_regular(path) as source:
            consumed = 0
            while raw := source.readline(MAX_LINE_BYTES + 1):
                consumed += len(raw)
                if len(raw) > MAX_LINE_BYTES or consumed > MAX_ARCHIVE_BYTES:
                    raise ObservationError("metrics archive exceeds its bounds")
                frame = decode_json(raw, "metrics archive frame")
                exact_keys(frame, {"schema_version", "binding", "collected_at", "samples"}, "metrics archive frame")
                if frame["schema_version"] != 1 or frame["binding"] != binding:
                    raise ObservationError("metrics archive source/configuration binding differs")
                yield timestamp(frame["collected_at"]), parse_samples(frame["samples"])


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, newurl):
        raise ObservationError("telemetry redirects are not allowed")


def read_http_json(url: str, *, bearer: str | None = None) -> Any:
    headers = {"Accept": "application/json"}
    if bearer:
        headers["Authorization"] = f"Bearer {bearer}"
    request = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.build_opener(NoRedirect()).open(request, timeout=20) as response:
            raw = response.read(MAX_JSON_BYTES + 1)
    except (urllib.error.URLError, TimeoutError, OSError) as error:
        raise ObservationError("telemetry endpoint request failed") from error
    if not raw or len(raw) > MAX_JSON_BYTES:
        raise ObservationError("telemetry response exceeds its bound")
    return decode_json(raw, "telemetry response")


def endpoint(value: str, allow_http: bool) -> str:
    parsed = urllib.parse.urlsplit(value)
    if parsed.scheme not in {"https", "http"} or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ObservationError("telemetry URL must be an uncredentialed HTTP(S) origin/path")
    if parsed.scheme == "http" and not allow_http and parsed.hostname not in {"localhost", "127.0.0.1", "::1"}:
        raise ObservationError("remote plaintext telemetry requires --allow-http")
    return value.rstrip("/")


def prometheus_frames(base: str, job: str, instance: str, start: Decimal, end: Decimal, *, bearer: str | None = None) -> Iterator[tuple[Decimal, dict[MetricKey, Decimal]]]:
    selector = '{__name__=~' + json.dumps("|".join(FAMILIES)) + ',job=' + json.dumps(job) + ',instance=' + json.dumps(instance) + '}'
    cursor = start
    previous: tuple[Decimal, dict[MetricKey, Decimal]] | None = None
    while cursor <= end:
        stop = min(cursor + 3600, end)
        query = selector + f"[{int(stop - cursor) + 1}s]"
        encoded = urllib.parse.urlencode({"query": query, "time": str(stop), "timeout": "15s"})
        response = read_http_json(base + "/api/v1/query?" + encoded, bearer=bearer)
        if not isinstance(response, dict) or response.get("status") != "success" or response.get("warnings") or response.get("infos"):
            raise ObservationError("Prometheus query failed or returned incomplete annotations")
        data = response.get("data")
        if not isinstance(data, dict) or data.get("resultType") != "matrix" or not isinstance(data.get("result"), list) or not 1 <= len(data["result"]) <= MAX_SERIES:
            raise ObservationError("Prometheus must return a bounded raw range vector")
        frames: dict[Decimal, list[dict[str, Any]]] = defaultdict(list)
        sample_count = 0
        for series in data["result"]:
            exact_keys(series, {"metric", "values"}, "Prometheus series")
            labels = dict(series["metric"])
            if labels.pop("job", None) != job or labels.pop("instance", None) != instance:
                raise ObservationError("Prometheus target differs from the frozen deployment")
            name = labels.pop("__name__", None)
            metric_key(name, labels)
            if not isinstance(series["values"], list):
                raise ObservationError("Prometheus values must be an array")
            for pair in series["values"]:
                if not isinstance(pair, list) or len(pair) != 2:
                    raise ObservationError("Prometheus sample must be a timestamp/value pair")
                at = number(pair[0], "sample timestamp")
                if at < cursor or at > stop:
                    continue
                frames[at].append({"name": name, "labels": labels, "value": pair[1]})
                sample_count += 1
                if sample_count > MAX_SAMPLES_PER_CHUNK:
                    raise ObservationError("Prometheus chunk exceeds its sample bound")
        for at in sorted(frames):
            parsed = parse_samples(frames[at])
            if previous is not None and previous[0] == at:
                if previous[1] != parsed:
                    raise ObservationError("Prometheus boundary samples changed between queries")
                continue
            previous = at, parsed
            yield previous
        if stop == end:
            break
        cursor = stop


class Measurements:
    def __init__(self, requested_start: Decimal, requested_end: Decimal, expected_commit: str | None = None):
        if not evaluator.MIN_30D_SECONDS <= requested_end - requested_start <= MAX_WINDOW_SECONDS:
            raise ObservationError("requested window must span 30 to 32 days")
        self.requested_start = requested_start
        self.requested_end = requested_end
        self.expected_commit = expected_commit
        self.first: Decimal | None = None
        self.previous: tuple[Decimal, dict[MetricKey, Decimal]] | None = None
        self.deltas: dict[MetricKey, Decimal] = defaultdict(Decimal)
        self.daily_deltas: dict[MetricKey, Decimal] = defaultdict(Decimal)
        self.daily_first: Decimal | None = None
        self.restarts = 0
        self.healthy_period = Decimal(0)
        self.unhealthy = Decimal(0)
        self.frames = 0

    def consume(self, frames: Iterable[tuple[Decimal, dict[MetricKey, Decimal]]]) -> None:
        for at, samples in frames:
            if at < self.requested_start or at > self.requested_end:
                continue
            self.frames += 1
            if self.frames > 600_000:
                raise ObservationError("observation exceeds its frame bound")
            source = "".join(f"{int(samples[metric_key('agentos_build_source_sha1', {'part': str(part)})]):08x}" for part in range(5))
            if samples[("agentos_build_source_verified", ())] != 1 or (self.expected_commit is not None and source != self.expected_commit):
                raise ObservationError("runtime build identity is dirty, unknown or differs from the declared source")
            if self.expected_commit is None:
                self.expected_commit = source
            if self.first is None:
                if at - self.requested_start > MAX_GAP_SECONDS:
                    raise ObservationError("metrics archive does not cover the window start")
                self.first = at
            if self.previous is not None:
                prior_at, prior = self.previous
                elapsed = at - prior_at
                if not 0 < elapsed <= MAX_GAP_SECONDS:
                    raise ObservationError("duplicate/out-of-order samples or telemetry coverage gap")
                old_boot = prior_at - prior[("agentos_process_uptime_seconds", ())]
                new_boot = at - samples[("agentos_process_uptime_seconds", ())]
                restart = abs(new_boot - old_boot) > 3
                if restart:
                    self.restarts += 1
                    self.healthy_period = Decimal(0)
                    self.unhealthy = Decimal(0)
                    self.first = at
                    self.deltas.clear()
                    self.daily_deltas.clear()
                    self.daily_first = None
                    # The old process's terminal counters are unavailable.
                    # Make this actual sample the new baseline; never invent
                    # zero failures for the interval ending at its crash.
                    self.previous = at, samples
                    continue
                for key, value in prior.items():
                    if key not in samples:
                        raise ObservationError("a previously measured series disappeared")
                for key, value in samples.items():
                    if key[0] in GAUGES:
                        continue
                    old = prior.get(key, Decimal(0))
                    if value < old and not restart:
                        raise ObservationError("counter decreased without a measured process restart")
                    delta = value - old
                    self.deltas[key] += delta
                    if at > self.requested_end - 86_400 - MAX_GAP_SECONDS:
                        if self.daily_first is None:
                            self.daily_first = prior_at
                        self.daily_deltas[key] += delta
                healthy = samples[("agentos_quota_storage_healthy_seconds_total", ())]
                unhealthy = samples[("agentos_quota_storage_unhealthy_seconds_total", ())]
                healthy_delta = healthy - prior[("agentos_quota_storage_healthy_seconds_total", ())]
                unhealthy_delta = unhealthy - prior[("agentos_quota_storage_unhealthy_seconds_total", ())]
                if abs(healthy_delta + unhealthy_delta - elapsed) > 3:
                    raise ObservationError("ledger measurement interval does not cover elapsed target time")
                self.unhealthy += unhealthy_delta
                if unhealthy_delta > 0:
                    self.healthy_period = Decimal(0)
                else:
                    self.healthy_period += min(healthy_delta, elapsed)
            self.previous = at, samples
        if self.previous is None or self.first is None or self.requested_end - self.previous[0] > MAX_GAP_SECONDS:
            raise ObservationError("metrics archive does not cover the window end")
        if self.previous[0] - self.first < evaluator.MIN_30D_SECONDS:
            raise ObservationError("actual sampled window is shorter than 30 days")

    def delta(self, name: str, *, daily: bool = False, **labels: str) -> int:
        deltas = self.daily_deltas if daily else self.deltas
        return int(deltas[metric_key(name, labels)])

    def outcomes(self, name: str, **labels: str) -> dict[str, int]:
        return {outcome: self.delta(name, daily=True, **labels, outcome=outcome) for outcome in OUTCOMES}

    def p95(self, request_class: str) -> tuple[float, int]:
        total = self.delta("agentos_request_class_total", daily=True, **{"class": request_class})
        count = self.delta("agentos_request_class_duration_seconds_count", daily=True, **{"class": request_class})
        if total != count:
            raise ObservationError("latency histogram and class count disagree")
        previous = 0
        selected: Decimal | None = None
        for boundary in BUCKETS:
            bucket = self.delta("agentos_request_class_duration_seconds_bucket", daily=True, **{"class": request_class, "le": str(boundary)})
            if bucket < previous or bucket > count:
                raise ObservationError("latency histogram buckets are not coherent")
            if selected is None and count and Decimal(bucket) >= Decimal(count) * Decimal("0.95"):
                selected = boundary
            previous = bucket
        if previous != count:
            raise ObservationError("latency histogram +Inf bucket differs from count")
        if selected is not None and not selected.is_finite():
            raise ObservationError("p95 falls beyond the largest finite histogram bucket")
        return float(selected or 0), count

    def slis(self) -> dict[str, Any]:
        assert self.previous is not None and self.first is not None
        window = int(self.previous[0] - self.first)
        if self.daily_first is None:
            raise ObservationError("last-day measurement window is absent")
        daily_window = int(self.previous[0] - self.daily_first)
        availability = {outcome: sum(value for (name, labels), value in self.deltas.items() if name == "agentos_requests_total" and dict(labels)["outcome"] == outcome) for outcome in OUTCOMES}
        control_p95, control_count = self.p95("control")
        agent_p95, agent_count = self.p95("agent")
        backup = self.previous[1][("agentos_backup_last_success_unixtime_seconds", ())]
        if backup > self.previous[0]:
            raise ObservationError("last verified backup timestamp is in the future")
        return {
            "availability": {"window_seconds": window, **{key: int(value) for key, value in availability.items()}},
            "syscall_latency": {"window_seconds": daily_window, "control_p95_seconds": control_p95, "control_requests": control_count, "agent_p95_seconds": agent_p95, "agent_requests": agent_count},
            "queue_wait": {"window_seconds": daily_window, "wait_seconds_delta": self.delta("agentos_turn_wait_nanoseconds_total", daily=True) / 1_000_000_000, "admissions_delta": self.delta("agentos_turn_admitted_total", daily=True), "starvation_delta": self.delta("agentos_turn_starvation_total", daily=True)},
            "llm_success": {"window_seconds": daily_window, **self.outcomes("agentos_llm_requests_total"), "policy_quota_rejected": sum(int(value) for (name, _), value in self.daily_deltas.items() if name == "agentos_quota_denied_total"), "live_provider_qualification_passed": False, "live_provider_evidence_sha256": "0" * 64},
            "tool_success": {"window_seconds": daily_window, **self.outcomes("agentos_requests_total", subsystem="tool"), "policy_quota_rejected": self.delta("agentos_requests_total", daily=True, subsystem="tool", outcome="rejected")},
            "auth_sandbox_denial": {"adversarial_attempts": self.delta("agentos_adversarial_attempts_total"), "unexpected_allows": self.delta("agentos_unexpected_allows_total")},
            "data_durability": {"continuous_ledger_healthy_seconds": min(window, math.floor(self.healthy_period)), "ledger_unhealthy_seconds": math.ceil(self.unhealthy), "latest_verified_backup_age_seconds": float(self.previous[0] - backup), "restore_drill_passed": False},
            "checkpoint_recovery": {"attempted": self.delta("agentos_checkpoint_recovery_attempts_total"), "recovered": self.delta("agentos_checkpoint_recovery_total", outcome="recovered"), "safe_rejected": self.delta("agentos_checkpoint_recovery_total", outcome="safe_rejected"), "cross_tenant_recoveries": self.delta("agentos_checkpoint_cross_tenant_recoveries_total")},
            "tenant_isolation": {"adversarial_attempts": self.delta("agentos_tenant_boundary_attempts_total"), "confirmed_violations": self.delta("agentos_confirmed_violations_total"), "game_day_completed": False, "game_day_evidence_sha256": None},
        }


def alert_history(report: dict[str, Any], binding: dict[str, Any], start: Decimal, end: Decimal) -> list[dict[str, Any]]:
    exact_keys(report, {"schema_version", "binding", "coverage", "notifications"}, "Alertmanager history")
    if report["schema_version"] != 1 or report["binding"] != binding:
        raise ObservationError("Alertmanager history source/configuration binding differs")
    coverage = exact_keys(report["coverage"], {"start", "end", "notification_failures", "truncated"}, "alert coverage")
    if timestamp(coverage["start"]) > start or timestamp(coverage["end"]) < end or number(coverage["notification_failures"], "alert delivery failures", integer=True) != 0 or coverage["truncated"] is not False:
        raise ObservationError("retained Alertmanager notification history has incomplete coverage")
    notifications = report["notifications"]
    if not isinstance(notifications, list) or len(notifications) > 20_000:
        raise ObservationError("Alertmanager history notification count exceeds its bound")
    events: dict[tuple[str, str], dict[str, Any]] = {}
    for notification in notifications:
        if not isinstance(notification, dict) or notification.get("version") != "4" or notification.get("truncatedAlerts", 0) != 0 or not isinstance(notification.get("alerts"), list) or not 1 <= len(notification["alerts"]) <= 1000:
            raise ObservationError("invalid or truncated Alertmanager webhook notification")
        for alert in notification["alerts"]:
            if not isinstance(alert, dict) or alert.get("status") not in {"firing", "resolved"}:
                raise ObservationError("invalid Alertmanager alert status")
            labels = alert.get("labels")
            if not isinstance(labels, dict) or labels.get("severity") not in {"warning", "critical"}:
                raise ObservationError("Alertmanager alert lacks a supported severity")
            name = labels.get("alertname")
            try:
                evaluator._safe_identifier(name, "alert name")
            except evaluator.QualificationError as error:
                raise ObservationError(str(error)) from error
            fired = timestamp(alert.get("startsAt"))
            fingerprint = alert.get("fingerprint")
            if not isinstance(fingerprint, str) or not re.fullmatch(r"[0-9a-f]{16,64}", fingerprint):
                raise ObservationError("Alertmanager fingerprint is invalid")
            if not start <= fired <= end:
                # Earlier unresolved firings cannot be hidden by the window filter.
                if fired < start and (alert["status"] == "firing" or timestamp(alert.get("endsAt")) > start):
                    raise ObservationError("alert firing overlaps the window from before its start")
                continue
            key = fingerprint, utc(fired)
            projected = {"name": name, "severity": labels["severity"], "fired_at": utc(fired), "resolved_at": None}
            old = events.setdefault(key, projected)
            if len(events) > 1000:
                raise ObservationError("alert firing count exceeds the evaluator bound")
            if (old["name"], old["severity"]) != (name, labels["severity"]):
                raise ObservationError("alert identity changed across retained notifications")
            if alert["status"] == "resolved":
                resolved = timestamp(alert.get("endsAt"))
                if resolved < fired:
                    raise ObservationError("alert resolved before it fired")
                if resolved <= end:
                    if old["resolved_at"] not in {None, utc(resolved)}:
                        raise ObservationError("alert has inconsistent resolution timestamps")
                    old["resolved_at"] = utc(resolved)
    if len(events) > 1000:
        raise ObservationError("alert firing count exceeds the evaluator bound")
    return sorted(events.values(), key=lambda alert: (alert["fired_at"], alert["name"], alert["severity"]))


def build_observation(deployment: dict[str, Any], config: Path, dataset: Path, frames: Iterable[tuple[Decimal, dict[MetricKey, Decimal]]], history: dict[str, Any], requested_start: Decimal, requested_end: Decimal) -> dict[str, Any]:
    exact_keys(deployment, {"schema_version", "release_candidate", "source", "environment", "prometheus_target"}, "deployment manifest")
    if deployment["schema_version"] != 1:
        raise ObservationError("unsupported deployment manifest version")
    environment = deployment["environment"]
    exact_keys(environment, {"environment_id", "deployment_mode", "os", "arch", "hardware", "provider", "model", "configuration_sha256", "dataset_sha256"}, "deployment environment")
    evaluator._validate_source(deployment["source"], deployment["source"]["commit"], "deployment.source")
    evaluator._validate_environment(environment, environment["environment_id"])
    if not isinstance(deployment["release_candidate"], str) or not evaluator.RELEASE_CANDIDATE_RE.fullmatch(deployment["release_candidate"]):
        raise ObservationError("deployment release candidate is invalid")
    if environment["configuration_sha256"] != file_digest(config) or environment["dataset_sha256"] != file_digest(dataset):
        raise ObservationError("frozen configuration or workload digest differs from deployment")
    binding = {"source": deployment["source"], "environment_id": environment["environment_id"], "configuration_sha256": environment["configuration_sha256"], "dataset_sha256": environment["dataset_sha256"]}
    measurements = Measurements(requested_start, requested_end, deployment["source"]["commit"])
    measurements.consume(frames)
    assert measurements.first is not None and measurements.previous is not None
    report = {"schema_version": 1, "qualification_class": evaluator.QUALIFICATION_CLASS, "release_candidate": deployment["release_candidate"], "source": deployment["source"], "environment": environment, "window": {"start": utc(measurements.first), "end": utc(measurements.previous[0])}, "alert_firings": alert_history(history, binding, measurements.first, measurements.previous[0]), "slis": measurements.slis()}
    evaluator._validate_observation(report, deployment["source"]["commit"], environment["environment_id"], deployment["release_candidate"])
    # Re-read frozen files after streaming all measurements; no mixed-config report.
    if environment["configuration_sha256"] != file_digest(config) or environment["dataset_sha256"] != file_digest(dataset):
        raise ObservationError("frozen configuration or workload changed during export")
    return report


def apply_prerequisites(report: dict[str, Any], *, provider_report: Path | None = None, provider_binding: Path | None = None, restore_report: Path | None = None, game_day: Path | None = None) -> None:
    """Bind existing qualification reports; no CLI flag can assert a pass."""
    source = report["source"]
    environment = report["environment"]
    common = {"release_candidate": report["release_candidate"], "expected_commit": source["commit"], "target_environment": environment["environment_id"], "on_device_environment": "unused-on-device", "promoted_providers": [environment["provider"]]}
    if bool(provider_report) != bool(provider_binding):
        raise ObservationError("live provider evidence requires its exact target binding")
    if provider_report is not None and provider_binding is not None:
        provider, provider_sha = read_json(provider_report)
        binding, _ = read_json(provider_binding)
        exact_keys(binding, {"schema_version", "qualification_class", "release_candidate", "source", "environment_id", "configuration_sha256", "dataset_sha256", "provider", "model", "provider_report_sha256"}, "live provider binding")
        expected = {"schema_version": 1, "qualification_class": "target_live_provider_evidence_binding", "release_candidate": report["release_candidate"], "source": source, "environment_id": environment["environment_id"], "configuration_sha256": environment["configuration_sha256"], "dataset_sha256": environment["dataset_sha256"], "provider": environment["provider"], "model": environment["model"], "provider_report_sha256": provider_sha}
        if binding != expected or provider.get("model") != environment["model"]:
            raise ObservationError("live provider report differs from the target identity")
        blockers = campaign._validate_evidence("provider:" + environment["provider"], provider, **common)
        report["slis"]["llm_success"]["live_provider_qualification_passed"] = not blockers
        report["slis"]["llm_success"]["live_provider_evidence_sha256"] = provider_sha
    if restore_report is not None:
        restore, _ = read_json(restore_report)
        blockers = campaign._validate_evidence("target-remote-backup", restore, **common)
        required_checks = {
            "clean_exact_source", "exact_release_candidate_source", "target_non_loopback_https",
            "target_profile_bound", "signed_anchor_bound_backup", "compliance_retention_reported",
            "immutable_version_ids_retained", "exact_versions_recovered",
            "delete_markers_cannot_hide_retained_versions", "authenticated_restore_completed",
            "restored_enforcement_data_matches", "recovery_metrics_recorded", "public_recovery_fixture_retained",
        }
        checks = exact_keys(restore.get("checks"), required_checks, "target restore checks")
        recovery = restore.get("recovery")
        if not isinstance(recovery, dict):
            raise ObservationError("target restore measurement is absent")
        downloaded = number(recovery.get("downloaded_bytes"), "restored byte count", integer=True)
        age = number(recovery.get("recovery_point_age_seconds"), "restored recovery point age", integer=True)
        report["slis"]["data_durability"]["restore_drill_passed"] = not blockers and all(value is True for value in checks.values()) and downloaded > 0 and age < 86_400
    if game_day is not None:
        game, digest = read_json(game_day)
        if game.get("environment", {}).get("configuration_sha256") != environment["configuration_sha256"]:
            raise ObservationError("game day used a different frozen configuration")
        evaluated = evaluator._validate_game_day(game, source["commit"], environment["environment_id"], report["release_candidate"], report_sha256=digest, observed_evidence_sha256=digest)
        passed = evaluated["passed"]
        report["slis"]["tenant_isolation"]["game_day_completed"] = passed
        report["slis"]["tenant_isolation"]["game_day_evidence_sha256"] = digest if passed else None
    evaluator._validate_observation(report, source["commit"], environment["environment_id"], report["release_candidate"])


def write_new_json(path: Path, value: dict[str, Any]) -> None:
    raw = (json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n").encode()
    if len(raw) > evaluator.MAX_EVIDENCE_BYTES:
        raise ObservationError("observation exceeds the evaluator size bound")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        with os.fdopen(descriptor, "wb") as destination:
            destination.write(raw)
            destination.flush()
            os.fsync(destination.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def validation_example() -> dict[str, Any]:
    window = evaluator.MIN_30D_SECONDS
    report = {"schema_version": 1, "qualification_class": evaluator.QUALIFICATION_CLASS, "release_candidate": "v1.0.0-rc.1", "source": {"commit": "0" * 40, "dirty": False}, "environment": {"environment_id": "schema-validation-only", "deployment_mode": "single-node", "os": "linux", "arch": "x86_64", "hardware": "schema-only", "provider": "unqualified", "model": "unqualified", "configuration_sha256": "0" * 64, "dataset_sha256": "0" * 64}, "window": {"start": "2026-01-01T00:00:00Z", "end": "2026-01-31T00:00:00Z"}, "alert_firings": [], "slis": {}}
    report["slis"] = {
        "availability": {"window_seconds": window, **dict.fromkeys(OUTCOMES, 0)},
        "syscall_latency": {"window_seconds": window, "control_p95_seconds": 0, "control_requests": 0, "agent_p95_seconds": 0, "agent_requests": 0},
        "queue_wait": {"window_seconds": window, "wait_seconds_delta": 0, "admissions_delta": 0, "starvation_delta": 0},
        "llm_success": {"window_seconds": window, **dict.fromkeys(OUTCOMES, 0), "policy_quota_rejected": 0, "live_provider_qualification_passed": False, "live_provider_evidence_sha256": "0" * 64},
        "tool_success": {"window_seconds": window, **dict.fromkeys(OUTCOMES, 0), "policy_quota_rejected": 0},
        "auth_sandbox_denial": {"adversarial_attempts": 0, "unexpected_allows": 0},
        "data_durability": {"continuous_ledger_healthy_seconds": 0, "ledger_unhealthy_seconds": 0, "latest_verified_backup_age_seconds": window, "restore_drill_passed": False},
        "checkpoint_recovery": {"attempted": 0, "recovered": 0, "safe_rejected": 0, "cross_tenant_recoveries": 0},
        "tenant_isolation": {"adversarial_attempts": 0, "confirmed_violations": 0, "game_day_completed": False, "game_day_evidence_sha256": None},
    }
    _, targets = evaluator._validate_observation(report, "0" * 40, "schema-validation-only", "v1.0.0-rc.1")
    if len(targets) != 9 or any(target["passed"] for target in targets):
        raise ObservationError("zero-filled schema example unexpectedly qualifies")
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--validate", action="store_true")
    parser.add_argument("--deployment", type=Path)
    parser.add_argument("--configuration", type=Path)
    parser.add_argument("--dataset", type=Path)
    parser.add_argument("--alert-history", type=Path)
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--prometheus")
    source.add_argument("--metrics-archive", type=Path, nargs="+")
    parser.add_argument("--bearer-file", type=Path)
    parser.add_argument("--provider-report", type=Path)
    parser.add_argument("--provider-binding", type=Path)
    parser.add_argument("--restore-report", type=Path)
    parser.add_argument("--game-day", type=Path)
    parser.add_argument("--allow-http", action="store_true")
    parser.add_argument("--window-start")
    parser.add_argument("--window-end")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.validate:
            if any((args.deployment, args.configuration, args.dataset, args.alert_history, args.prometheus, args.metrics_archive, args.bearer_file, args.provider_report, args.provider_binding, args.restore_report, args.game_day, args.window_start, args.window_end, args.output)) or args.allow_http:
                raise ObservationError("--validate cannot consume target inputs or publish target evidence")
            print(json.dumps({"schema_valid": True, "example_only": True, "production_claim_allowed": False, "observation": validation_example()}, sort_keys=True))
            return 0
        if not all((args.deployment, args.configuration, args.dataset, args.alert_history, args.window_start, args.window_end, args.output)) or not (args.prometheus or args.metrics_archive):
            raise ObservationError("target export requires deployment, frozen files, history, window, telemetry and output")
        deployment, _ = read_json(args.deployment)
        history, _ = read_json(args.alert_history)
        environment = deployment["environment"]
        binding = {"source": deployment["source"], "environment_id": environment["environment_id"], "configuration_sha256": environment["configuration_sha256"], "dataset_sha256": environment["dataset_sha256"]}
        start, end = timestamp(args.window_start), timestamp(args.window_end)
        if args.prometheus:
            target = exact_keys(deployment["prometheus_target"], {"job", "instance"}, "Prometheus target")
            bearer = None
            if args.bearer_file:
                with open_regular(args.bearer_file) as token_file:
                    raw = token_file.read(8193)
                bearer = raw.decode().strip()
                if len(raw) > 8192 or not bearer or any(character.isspace() for character in bearer):
                    raise ObservationError("bearer file must contain one bounded token")
            frames = prometheus_frames(endpoint(args.prometheus, args.allow_http), target["job"], target["instance"], start, end, bearer=bearer)
        else:
            if args.bearer_file or args.allow_http:
                raise ObservationError("HTTP options cannot apply to an offline archive")
            frames = archive_frames(args.metrics_archive, binding)
        report = build_observation(deployment, args.configuration, args.dataset, frames, history, start, end)
        apply_prerequisites(report, provider_report=args.provider_report, provider_binding=args.provider_binding, restore_report=args.restore_report, game_day=args.game_day)
        write_new_json(args.output, report)
        unresolved = sum(alert["resolved_at"] is None for alert in report["alert_firings"])
        print(json.dumps({"observation_written": True, "production_claim_allowed": False, "unresolved_alerts": unresolved}, sort_keys=True))
        if unresolved:
            print("slo observation: unresolved alerts retained; evidence is ineligible", file=sys.stderr)
            return 1
        return 0
    except (ObservationError, evaluator.QualificationError, campaign.QualificationError, OSError, KeyError, TypeError, UnicodeError) as error:
        # Endpoint URLs and token contents never enter diagnostics.
        detail = str(error) if isinstance(error, ObservationError) else "target inputs could not be exported"
        print(f"slo observation: {type(error).__name__}: {detail}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
