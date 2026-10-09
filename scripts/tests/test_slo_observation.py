import hashlib
import http.server
import io
import json
import sys
import tempfile
import threading
import unittest
from contextlib import redirect_stderr, redirect_stdout
from decimal import Decimal
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import release_slo_qualification as evaluator
import slo_observation as producer


START = producer.timestamp("2026-01-01T00:00:00Z")
END = producer.timestamp("2026-01-31T00:00:00Z")


def snapshot(elapsed=0, *, reboot=False, unhealthy="0"):
    elapsed = Decimal(elapsed)
    runtime = elapsed if not reboot else elapsed % 86_400
    samples = [{"name": name, "labels": {}, "value": 0} for name in producer.SCALARS]
    samples.extend([
        {"name": "agentos_telemetry_contract_info", "labels": {"version": "2"}, "value": 1},
        *({"name": "agentos_build_source_sha1", "labels": {"part": str(part)}, "value": int("a" * 8, 16)} for part in range(5)),
        *({"name": "agentos_llm_requests_total", "labels": {"outcome": outcome}, "value": int(runtime) if outcome == "success" else 0} for outcome in producer.OUTCOMES),
        *({"name": "agentos_checkpoint_recovery_total", "labels": {"outcome": outcome}, "value": 0} for outcome in ("recovered", "safe_rejected")),
    ])
    for sample in samples:
        if sample["name"] == "agentos_process_uptime_seconds":
            sample["value"] = int(runtime)
        elif sample["name"] == "agentos_build_source_verified":
            sample["value"] = 1
        elif sample["name"] == "agentos_quota_storage_healthy_seconds_total":
            sample["value"] = str(runtime - Decimal(unhealthy))
        elif sample["name"] == "agentos_quota_storage_unhealthy_seconds_total":
            sample["value"] = unhealthy
        elif sample["name"] == "agentos_backup_last_success_unixtime_seconds":
            sample["value"] = int(START + elapsed - 3600)
    for request_class in ("control", "agent"):
        labels = {"class": request_class}
        count = int(runtime)
        samples.extend([
            {"name": "agentos_request_class_total", "labels": labels, "value": count},
            {"name": "agentos_request_class_duration_seconds_count", "labels": labels, "value": count},
        ])
        for boundary in producer.BUCKETS:
            samples.append({"name": "agentos_request_class_duration_seconds_bucket", "labels": {**labels, "le": str(boundary)}, "value": count if boundary >= Decimal("0.250") else 0})
    samples.append({"name": "agentos_requests_total", "labels": {"subsystem": "system", "outcome": "success"}, "value": int(runtime)})
    samples.append({"name": "agentos_quota_denied_total", "labels": {"scope": "provider", "dimension": "migration_fence"}, "value": 0})
    return samples


def frames(*, reboot=False):
    for elapsed in range(0, 2_592_001, 120):
        yield START + elapsed, producer.parse_samples(snapshot(elapsed, reboot=reboot))


def binding(environment):
    return {"source": {"commit": "a" * 40, "dirty": False}, "environment_id": environment["environment_id"], "configuration_sha256": environment["configuration_sha256"], "dataset_sha256": environment["dataset_sha256"]}


def history(identity, notifications=None):
    return {"schema_version": 1, "binding": identity, "coverage": {"start": producer.utc(START), "end": producer.utc(END), "notification_failures": 0, "truncated": False}, "notifications": notifications or []}


def notification(status="resolved", fingerprint="a" * 16):
    return {"version": "4", "truncatedAlerts": 0, "alerts": [{"status": status, "fingerprint": fingerprint, "labels": {"alertname": "AgentOSProviderQueueSaturated", "severity": "warning"}, "startsAt": "2026-01-15T00:00:00Z", "endsAt": "2026-01-15T00:10:00Z"}]}


class SloObservationTests(unittest.TestCase):
    def test_zero_schema_example_roundtrips_all_nine_fields_and_rejects_extra_key(self):
        report = producer.validation_example()
        _, targets = evaluator._validate_observation(report, "0" * 40, "schema-validation-only", "v1.0.0-rc.1")
        self.assertEqual(set(report["slis"]), set(evaluator.TARGET_IDS))
        self.assertFalse(any(target["passed"] for target in targets))
        report["slis"]["tool_success"]["invented"] = 0
        with self.assertRaisesRegex(evaluator.QualificationError, "keys differ"):
            evaluator._validate_observation(report, "0" * 40, "schema-validation-only", "v1.0.0-rc.1")

    def test_actual_counter_increases_and_conservative_histogram_upper_bounds(self):
        measured = producer.Measurements(START, END)
        measured.consume(frames())
        result = measured.slis()
        self.assertEqual(result["availability"]["success"], 2_592_000)
        self.assertEqual(result["llm_success"]["success"], 86_520)
        self.assertEqual(result["llm_success"]["window_seconds"], 86_520)
        self.assertEqual(result["syscall_latency"]["control_p95_seconds"], 0.25)
        self.assertEqual(result["data_durability"]["continuous_ledger_healthy_seconds"], 2_592_000)
        self.assertEqual(result["data_durability"]["latest_verified_backup_age_seconds"], 3600)
        self.assertFalse(result["data_durability"]["restore_drill_passed"])
        self.assertFalse(result["tenant_isolation"]["game_day_completed"])

    def test_restart_increases_do_not_claim_continuous_healthy_month(self):
        measured = producer.Measurements(START, END)
        with self.assertRaisesRegex(producer.ObservationError, "actual sampled window is shorter"):
            measured.consume(frames(reboot=True))
        self.assertEqual(measured.restarts, 30)

    def test_early_restart_discards_unknown_prefix_and_requires_full_new_month(self):
        requested_end = START + 32 * 86_400
        measured = producer.Measurements(START, requested_end, "a" * 40)

        def restarted_frames():
            for elapsed in range(0, 32 * 86_400 + 1, 120):
                samples = producer.parse_samples(snapshot(elapsed))
                if elapsed >= 86_400:
                    for key in list(samples):
                        if key[0] not in producer.GAUGES:
                            samples[key] = max(Decimal(0), samples[key] - (86_400 if samples[key] >= 86_400 else 0))
                    samples[("agentos_process_uptime_seconds", ())] -= 86_400
                yield START + elapsed, samples

        measured.consume(restarted_frames())
        self.assertEqual(measured.first, START + 86_400)
        self.assertEqual(measured.restarts, 1)
        self.assertEqual(measured.slis()["availability"]["success"], 31 * 86_400)
        self.assertEqual(measured.slis()["availability"]["window_seconds"], 31 * 86_400)

    def test_reused_instance_or_dirty_build_cannot_claim_manifest_source(self):
        for kind in ("different", "dirty"):
            samples = producer.parse_samples(snapshot())
            if kind == "dirty":
                samples[("agentos_build_source_verified", ())] = 0
            else:
                samples[producer.metric_key("agentos_build_source_sha1", {"part": "0"})] += 1
            with self.subTest(kind=kind), self.assertRaisesRegex(producer.ObservationError, "runtime build identity"):
                producer.Measurements(START, END, "a" * 40).consume([(START, samples)])

    def test_coverage_gap_reset_without_reboot_and_duplicate_fail(self):
        for bad_frames in (
            [(START, producer.parse_samples(snapshot())), (START + 121, producer.parse_samples(snapshot(121)))],
            [(START, producer.parse_samples(snapshot())), (START, producer.parse_samples(snapshot()))],
        ):
            with self.assertRaises(producer.ObservationError):
                producer.Measurements(START, END).consume(bad_frames)
        one = producer.parse_samples(snapshot(120))
        two = producer.parse_samples(snapshot(240))
        two[producer.metric_key("agentos_llm_requests_total", {"outcome": "success"})] = 0
        with self.assertRaisesRegex(producer.ObservationError, "without a measured process restart"):
            producer.Measurements(START, END).consume([(START, one), (START + 120, two)])

    def test_subsecond_unhealthy_interval_is_rounded_up(self):
        measured = producer.Measurements(START, END)
        measured.consume((START + elapsed, producer.parse_samples(snapshot(elapsed, unhealthy="0.000000001" if elapsed else "0"))) for elapsed in range(0, 2_592_001, 120))
        self.assertEqual(measured.slis()["data_durability"]["ledger_unhealthy_seconds"], 1)

    def test_missing_sources_invalid_labels_and_corrupt_checkpoint_are_refused(self):
        for edit in ("missing", "label", "checkpoint", "nonfinite", "fractional_count"):
            samples = snapshot()
            if edit == "missing":
                samples = [sample for sample in samples if sample["name"] != "agentos_adversarial_attempts_total"]
            elif edit == "label":
                samples[0]["labels"] = {"tenant": "private"}
            elif edit == "checkpoint":
                samples[0]["name"] = "agentos_checkpoint_recovery_attempts_total"
                samples[0]["value"] = 1
            elif edit == "nonfinite":
                samples[0]["value"] = "NaN"
            else:
                samples[0]["value"] = "0.1"
            with self.subTest(edit=edit), self.assertRaises(producer.ObservationError):
                producer.parse_samples(samples)

    def test_alert_retries_deduplicate_but_distinct_fingerprints_survive(self):
        identity = {"test": "binding"}
        result = producer.alert_history(history(identity, [notification("firing"), notification(), notification(), notification(fingerprint="b" * 16)]), identity, START, END)
        self.assertEqual(len(result), 2)
        self.assertTrue(all(alert["resolved_at"] for alert in result))

    def test_unresolved_alert_is_retained_and_evaluator_reports_it(self):
        identity = {"test": "binding"}
        result = producer.alert_history(history(identity, [notification("firing")]), identity, START, END)
        self.assertIsNone(result[0]["resolved_at"])
        summary = evaluator._validate_alerts(result, evaluator._timestamp(producer.utc(START), "start"), evaluator._timestamp(producer.utc(END), "end"))
        self.assertEqual(summary["unresolved_firing_count"], 1)

    def test_truncated_partial_or_failed_alert_history_is_not_empty_success(self):
        identity = {"test": "binding"}
        for key, value in (("truncated", True), ("notification_failures", 1), ("start", "2026-01-02T00:00:00Z")):
            report = history(identity)
            report["coverage"][key] = value
            with self.subTest(key=key), self.assertRaises(producer.ObservationError):
                producer.alert_history(report, identity, START, END)

    def test_producer_digest_binding_and_generated_schema(self):
        with tempfile.TemporaryDirectory() as directory:
            config, dataset = Path(directory) / "config", Path(directory) / "workload"
            config.write_bytes(b"frozen configuration")
            dataset.write_bytes(b"frozen workload")
            environment = {"environment_id": "target-rootless-1", "deployment_mode": "single-node", "os": "linux", "arch": "x86_64", "hardware": "eight-cores", "provider": "openai", "model": "qualified-target-model", "configuration_sha256": hashlib.sha256(config.read_bytes()).hexdigest(), "dataset_sha256": hashlib.sha256(dataset.read_bytes()).hexdigest()}
            deployment = {"schema_version": 1, "release_candidate": "v1.0.0-rc.1", "source": {"commit": "a" * 40, "dirty": False}, "environment": environment, "prometheus_target": {"job": "agentos", "instance": "target:9091"}}
            generated = producer.build_observation(deployment, config, dataset, frames(), history(binding(environment)), START, END)
            metadata, targets = evaluator._validate_observation(generated, "a" * 40, "target-rootless-1", "v1.0.0-rc.1")
            self.assertEqual(len(targets), 9)
            self.assertEqual(metadata["window"]["duration_seconds"], 2_592_000)
            from test_release_slo_qualification import valid_game_day, valid_incident, valid_soak
            soak, incident, game = valid_soak(), valid_incident(), valid_game_day()
            soak["environment"]["environment_id"] = environment["environment_id"]
            game["environment"]["environment_id"] = environment["environment_id"]
            game["environment"]["configuration_sha256"] = environment["configuration_sha256"]
            paths = [Path(directory) / name for name in ("observation.json", "soak.json", "incident.json", "game.json")]
            generated["alert_firings"] = producer.alert_history(history(binding(environment), [notification("firing")]), binding(environment), START, END)
            for path, report in zip(paths, (generated, soak, incident, game)):
                path.write_text(json.dumps(report))
            evaluated = evaluator.evaluate(*paths, expected_commit="a" * 40, expected_environment=environment["environment_id"], release_candidate="v1.0.0-rc.1")
            self.assertTrue(evaluated["report_generated"])
            self.assertIn("unresolved_alerts", evaluated["eligibility_blockers"])
            self.assertEqual(len(evaluated["targets"]), 9)
            config.write_bytes(b"changed configuration")
            with self.assertRaisesRegex(producer.ObservationError, "digest differs"):
                producer.build_observation(deployment, config, dataset, [], history(binding(environment)), START, END)

    def test_live_provider_pass_requires_model_source_config_and_report_hash(self):
        report = producer.validation_example()
        report["environment"]["provider"] = "openai"
        report["environment"]["model"] = "target-model"
        provider = {"schema_version": 1, "provider": "openai", "model": "target-model", "status": "passed", "response": {"content_nonempty": True, "tool_call_count": 0}, "capabilities": {}}
        with tempfile.TemporaryDirectory() as directory:
            path, bound = Path(directory) / "provider.json", Path(directory) / "binding.json"
            path.write_text(json.dumps(provider))
            identity = {"schema_version": 1, "qualification_class": "target_live_provider_evidence_binding", "release_candidate": report["release_candidate"], "source": report["source"], "environment_id": report["environment"]["environment_id"], "configuration_sha256": "0" * 64, "dataset_sha256": "0" * 64, "provider": "openai", "model": "target-model", "provider_report_sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
            bound.write_text(json.dumps(identity))
            producer.apply_prerequisites(report, provider_report=path, provider_binding=bound)
            self.assertTrue(report["slis"]["llm_success"]["live_provider_qualification_passed"])
            identity["source"] = {"commit": "b" * 40, "dirty": False}
            bound.write_text(json.dumps(identity))
            with self.assertRaises(producer.ObservationError):
                producer.apply_prerequisites(report, provider_report=path, provider_binding=bound)

    def test_bounded_archive_requires_exact_binding_and_unique_json_keys(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "samples.jsonl"
            identity = {"test": "binding"}
            frame = {"schema_version": 1, "binding": identity, "collected_at": producer.utc(START), "samples": snapshot()}
            path.write_text(json.dumps(frame) + "\n")
            self.assertEqual(len(list(producer.archive_frames([path], identity))), 1)
            with self.assertRaises(producer.ObservationError):
                list(producer.archive_frames([path], {"test": "wrong"}))
            path.write_text('{"schema_version":1,"schema_version":1}\n')
            with self.assertRaises(producer.ObservationError):
                list(producer.archive_frames([path], identity))

    def test_prometheus_reads_raw_range_vectors_and_rejects_wrong_targets(self):
        samples = snapshot()
        response = {"status": "success", "data": {"resultType": "matrix", "result": [{"metric": {"__name__": sample["name"], "job": "agentos", "instance": "target", **sample["labels"]}, "values": [[int(START), str(sample["value"])]]} for sample in samples]}}
        with mock.patch.object(producer, "read_http_json", return_value=response) as query:
            observed = list(producer.prometheus_frames("http://127.0.0.1", "agentos", "target", START, START))
            self.assertEqual(len(observed), 1)
            self.assertIn("%5B1s%5D", query.call_args.args[0])
            response["data"]["result"][0]["metric"]["instance"] = "wrong"
            with self.assertRaises(producer.ObservationError):
                list(producer.prometheus_frames("http://127.0.0.1", "agentos", "target", START, START))

    def test_real_http_prometheus_response_binding_and_redirect_denial(self):
        samples = snapshot()
        response = {"status": "success", "data": {"resultType": "matrix", "result": [{"metric": {"__name__": sample["name"], "job": "agentos", "instance": "target", **sample["labels"]}, "values": [[int(START), str(sample["value"])]]} for sample in samples]}}
        seen = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                seen.append((self.path, self.headers.get("Authorization")))
                if self.path.startswith("/redirect"):
                    self.send_response(302)
                    self.send_header("Location", "/api/v1/query")
                    self.end_headers()
                    return
                raw = json.dumps(response).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def log_message(self, *args):
                pass

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        base = f"http://127.0.0.1:{server.server_port}"
        try:
            observed = list(producer.prometheus_frames(base, "agentos", "target", START, START, bearer="ci-fixture-token"))
            self.assertEqual(len(observed), 1)
            self.assertEqual(seen[0][1], "Bearer ci-fixture-token")
            with self.assertRaisesRegex(producer.ObservationError, "redirects"):
                producer.read_http_json(base + "/redirect", bearer="ci-fixture-token")
            self.assertEqual(len(seen), 2)
        finally:
            server.shutdown()
            server.server_close()
            worker.join(timeout=2)
            self.assertFalse(worker.is_alive())

    def test_histogram_incoherence_and_overflow_are_not_fake_good_p95(self):
        measured = producer.Measurements(START, END)
        class_labels = {"class": "control"}
        measured.daily_deltas[producer.metric_key("agentos_request_class_total", class_labels)] = Decimal(10)
        measured.daily_deltas[producer.metric_key("agentos_request_class_duration_seconds_count", class_labels)] = Decimal(10)
        infinity = producer.metric_key("agentos_request_class_duration_seconds_bucket", {**class_labels, "le": "Infinity"})
        measured.daily_deltas[infinity] = Decimal(10)
        with self.assertRaisesRegex(producer.ObservationError, "largest finite"):
            measured.p95("control")
        measured.daily_deltas[infinity] = Decimal(11)
        with self.assertRaisesRegex(producer.ObservationError, "not coherent"):
            measured.p95("control")

    def test_provider_pass_flag_without_response_and_binding_is_refused(self):
        report = producer.validation_example()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "provider.json"
            path.write_text(json.dumps({"passed": True}))
            with self.assertRaisesRegex(producer.ObservationError, "requires its exact target binding"):
                producer.apply_prerequisites(report, provider_report=path)

    def test_wrong_game_day_configuration_is_rejected_before_pass_flag(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "game-day.json"
            path.write_text(json.dumps({"passed": True, "environment": {"configuration_sha256": "a" * 64}}))
            with self.assertRaisesRegex(producer.ObservationError, "different frozen configuration"):
                producer.apply_prerequisites(producer.validation_example(), game_day=path)

    def test_cli_validation_and_non_overwriting_output(self):
        with redirect_stdout(io.StringIO()) as output:
            self.assertEqual(producer.main(["--validate"]), 0)
        self.assertTrue(json.loads(output.getvalue())["example_only"])
        with redirect_stderr(io.StringIO()):
            self.assertEqual(producer.main(["--validate", "--output", "unused"]), 2)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "observation.json"
            producer.write_new_json(path, producer.validation_example())
            original = path.read_bytes()
            with self.assertRaises(FileExistsError):
                producer.write_new_json(path, {"overwritten": True})
            self.assertEqual(path.read_bytes(), original)


if __name__ == "__main__":
    unittest.main()
