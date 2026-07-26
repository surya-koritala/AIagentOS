import copy
import json
import socketserver
import sys
import threading
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from verify_wire_fixtures import (
    ConformanceError,
    V2_ONLY_OPERATIONS,
    discover_live_schema,
    fixture_operations,
    load_fixture_set,
    parse_address,
    schema_variants,
    validate_fixture_against_schema,
    validate_versioned_fixtures,
)


REPO_ROOT = Path(__file__).resolve().parents[2]


class _ContractHandler(socketserver.StreamRequestHandler):
    request_schema = {
        "oneOf": [
            {
                "type": "object",
                "properties": {"op": {"const": "describe_protocol"}},
                "required": ["op"],
                "additionalProperties": True,
            }
        ]
    }

    def handle(self):
        for line in self.rfile:
            request = json.loads(line)
            if request["op"] == "hello":
                reply = {
                    "status": "hello",
                    "protocol_version": 2,
                    "min_protocol_version": 1,
                    "server_version": "test",
                    "features": ["protocol_description"],
                }
            elif request["op"] == "describe_protocol":
                reply = {
                    "status": "protocol_description",
                    "description": {"request_schema": self.request_schema},
                }
            else:
                reply = {"status": "error", "message": "unexpected test request"}
            self.wfile.write(json.dumps(reply).encode("utf-8") + b"\n")
            self.wfile.flush()


class WireFixtureTests(unittest.TestCase):
    def test_repository_fixture_sets_are_complete_and_versioned(self):
        self.assertEqual(validate_versioned_fixtures(REPO_ROOT), {1: 59, 2: 72})
        v1 = fixture_operations(load_fixture_set(REPO_ROOT, 1), 1)
        v2 = fixture_operations(load_fixture_set(REPO_ROOT, 2), 2)
        self.assertEqual(v2 - v1, V2_ONLY_OPERATIONS)

    def test_duplicate_operation_is_rejected(self):
        fixtures = load_fixture_set(REPO_ROOT, 1)
        fixtures.append(copy.deepcopy(fixtures[0]))
        with self.assertRaisesRegex(ConformanceError, "duplicate operations"):
            fixture_operations(fixtures, 1)

    def test_tagged_union_schema_checks_required_fields_and_types(self):
        schema = {
            "oneOf": [
                {
                    "type": "object",
                    "properties": {
                        "op": {"const": "example"},
                        "name": {"type": "string"},
                        "count": {"type": ["integer", "null"]},
                    },
                    "required": ["op", "name"],
                    "additionalProperties": True,
                }
            ]
        }
        variant = schema_variants(schema)["example"]
        validate_fixture_against_schema(
            {"op": "example", "name": "fixture", "count": None}, variant, 2
        )
        with self.assertRaisesRegex(ConformanceError, "missing required"):
            validate_fixture_against_schema({"op": "example"}, variant, 2)
        with self.assertRaisesRegex(ConformanceError, "does not match"):
            validate_fixture_against_schema(
                {"op": "example", "name": 7}, variant, 2
            )

    def test_address_parser_accepts_explicit_and_implicit_tcp(self):
        self.assertEqual(parse_address("127.0.0.1:7777"), ("127.0.0.1", 7777))
        self.assertEqual(
            parse_address("tcp://localhost:9000"), ("localhost", 9000)
        )
        with self.assertRaises(ConformanceError):
            parse_address("https://localhost:9000")

    def test_live_discovery_negotiates_without_executing_fixtures(self):
        with socketserver.ThreadingTCPServer(
            ("127.0.0.1", 0), _ContractHandler
        ) as server:
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            host, port = server.server_address
            try:
                schema = discover_live_schema(f"{host}:{port}", 1, 2.0, None)
            finally:
                server.shutdown()
                thread.join(timeout=2)
        self.assertEqual(schema, _ContractHandler.request_schema)


if __name__ == "__main__":
    unittest.main()
