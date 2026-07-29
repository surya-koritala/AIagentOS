#!/usr/bin/env python3
"""Validate versioned wire fixtures, optionally against a live kernel.

The runner uses only Python's standard library so prospective non-Rust clients
can consume the contract without installing this workspace or a JSON Schema
package. It validates the tagged-union subset emitted by DescribeProtocol:
operation tags, required fields, and declared JSON primitive/container types.
It never executes the fixture operations because many are intentionally
mutating; a live run performs Hello negotiation and schema discovery only.
"""

from __future__ import annotations

import argparse
import json
import os
import socket
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

MAX_FRAME_BYTES = 8 * 1024 * 1024
SUPPORTED_VERSIONS = (1, 2)
V2_ONLY_OPERATIONS = {
    "cancel_request",
    "claim_cluster_agent_ownership",
    "enforce_storage_backup_retention",
    "erase_data",
    "get_cluster_agent_ownership",
    "get_cluster_membership",
    "issue_cluster_join_challenge",
    "list_cluster_agent_ownership_audit",
    "list_cluster_membership_audit",
    "list_node_control_audit",
    "ping",
    "prove_node_identity",
    "register_cluster_member",
    "release_cluster_agent_ownership",
    "renew_cluster_agent_ownership",
    "send_message_stream",
    "set_cluster_member_state",
    "set_node_availability",
    "set_node_profile",
    "storage_backup_status",
    "storage_data_inventory",
}


class ConformanceError(ValueError):
    """The fixture set or discovered contract is internally inconsistent."""


def load_fixture_set(repo_root: Path, version: int) -> list[dict[str, Any]]:
    path = repo_root / "protocol" / f"v{version}" / "requests.json"
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ConformanceError(f"cannot load {path}: {error}") from error
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise ConformanceError(f"{path} must contain an array of request objects")
    return value


def fixture_operations(fixtures: list[dict[str, Any]], version: int) -> set[str]:
    operations: list[str] = []
    for index, fixture in enumerate(fixtures):
        operation = fixture.get("op")
        if not isinstance(operation, str) or not operation:
            raise ConformanceError(f"v{version} fixture {index} has no string op")
        operations.append(operation)
    unique = set(operations)
    if len(unique) != len(operations):
        duplicates = sorted(
            operation for operation in unique if operations.count(operation) > 1
        )
        raise ConformanceError(f"v{version} has duplicate operations: {duplicates}")
    return unique


def schema_variants(schema: dict[str, Any]) -> dict[str, dict[str, Any]]:
    one_of = schema.get("oneOf")
    if not isinstance(one_of, list):
        raise ConformanceError("request schema has no oneOf variant list")
    variants: dict[str, dict[str, Any]] = {}
    for index, variant in enumerate(one_of):
        if not isinstance(variant, dict):
            raise ConformanceError(f"request schema variant {index} is not an object")
        properties = variant.get("properties")
        if not isinstance(properties, dict):
            raise ConformanceError(f"request schema variant {index} has no properties")
        operation_schema = properties.get("op")
        operation = (
            operation_schema.get("const")
            if isinstance(operation_schema, dict)
            else None
        )
        if not isinstance(operation, str) or not operation:
            raise ConformanceError(f"request schema variant {index} has no op const")
        if operation in variants:
            raise ConformanceError(f"request schema repeats operation {operation}")
        variants[operation] = variant
    return variants


def _matches_json_type(value: Any, declared: str) -> bool:
    if declared == "null":
        return value is None
    if declared == "boolean":
        return isinstance(value, bool)
    if declared == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if declared == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if declared == "string":
        return isinstance(value, str)
    if declared == "array":
        return isinstance(value, list)
    if declared == "object":
        return isinstance(value, dict)
    return False


def validate_fixture_against_schema(
    fixture: dict[str, Any],
    variant: dict[str, Any],
    version: int,
) -> None:
    operation = fixture["op"]
    required = variant.get("required", [])
    if not isinstance(required, list) or not all(
        isinstance(field, str) for field in required
    ):
        raise ConformanceError(f"schema required list is invalid for {operation}")
    missing = sorted(field for field in required if field not in fixture)
    if missing:
        raise ConformanceError(f"v{version} {operation} is missing required fields {missing}")
    properties = variant.get("properties", {})
    for field, value in fixture.items():
        declaration = properties.get(field)
        if not isinstance(declaration, dict) or "type" not in declaration:
            continue
        declared = declaration["type"]
        types = declared if isinstance(declared, list) else [declared]
        if not all(isinstance(item, str) for item in types) or not any(
            _matches_json_type(value, item) for item in types
        ):
            raise ConformanceError(
                f"v{version} {operation}.{field} does not match schema type {declared}"
            )


def validate_versioned_fixtures(
    repo_root: Path,
    request_schema: dict[str, Any] | None = None,
) -> dict[int, int]:
    fixtures = {
        version: load_fixture_set(repo_root, version)
        for version in SUPPORTED_VERSIONS
    }
    operations = {
        version: fixture_operations(values, version)
        for version, values in fixtures.items()
    }
    expected_v2 = operations[1] | V2_ONLY_OPERATIONS
    if expected_v2 != operations[2]:
        missing = sorted(expected_v2 - operations[2])
        extra = sorted(operations[2] - expected_v2)
        raise ConformanceError(
            "version operation sets drifted: "
            f"missing from v2={missing}, unexpected v2 additions={extra}"
        )
    if operations[1] & V2_ONLY_OPERATIONS:
        raise ConformanceError("v1 fixture set contains v2-only streaming operations")
    if request_schema is not None:
        variants = schema_variants(request_schema)
        if set(variants) != operations[2]:
            missing = sorted(set(variants) - operations[2])
            extra = sorted(operations[2] - set(variants))
            raise ConformanceError(
                f"v2 fixtures/schema differ: missing fixtures={missing}, unknown fixtures={extra}"
            )
        for version, values in fixtures.items():
            for fixture in values:
                validate_fixture_against_schema(
                    fixture, variants[fixture["op"]], version
                )
    return {version: len(values) for version, values in fixtures.items()}


def parse_address(address: str) -> tuple[str, int]:
    parsed = urlparse(address if "://" in address else f"tcp://{address}")
    if parsed.scheme != "tcp" or parsed.hostname is None or parsed.port is None:
        raise ConformanceError("address must be tcp://host:port or host:port")
    return parsed.hostname, parsed.port


def _read_reply(stream: Any) -> dict[str, Any]:
    line = stream.readline(MAX_FRAME_BYTES + 1)
    if not line:
        raise ConformanceError("server closed before replying")
    if len(line) > MAX_FRAME_BYTES:
        raise ConformanceError("server reply exceeds the public frame limit")
    try:
        reply = json.loads(line)
    except json.JSONDecodeError as error:
        raise ConformanceError(f"server returned invalid JSON: {error}") from error
    if not isinstance(reply, dict):
        raise ConformanceError("server reply is not an object")
    return reply


def _exchange(stream: Any, request: dict[str, Any]) -> dict[str, Any]:
    frame = json.dumps(request, separators=(",", ":")).encode("utf-8") + b"\n"
    if len(frame) > MAX_FRAME_BYTES:
        raise ConformanceError("client request exceeds the public frame limit")
    stream.write(frame)
    stream.flush()
    return _read_reply(stream)


def discover_live_schema(
    address: str,
    version: int,
    timeout: float,
    token: str | None,
) -> dict[str, Any]:
    host, port = parse_address(address)
    with socket.create_connection((host, port), timeout=timeout) as connection:
        connection.settimeout(timeout)
        with connection.makefile("rwb") as stream:
            hello = _exchange(stream, {"op": "hello", "protocol_version": version})
            if hello.get("status") != "hello":
                raise ConformanceError(f"v{version} Hello failed: {hello}")
            if token is not None:
                authenticated = _exchange(
                    stream, {"op": "authenticate", "token": token}
                )
                if authenticated.get("status") != "authenticated":
                    raise ConformanceError(
                        f"v{version} authentication failed: {authenticated}"
                    )
            description = _exchange(stream, {"op": "describe_protocol"})
    if description.get("status") != "protocol_description":
        raise ConformanceError(f"DescribeProtocol failed: {description}")
    contract = description.get("description")
    if not isinstance(contract, dict) or not isinstance(
        contract.get("request_schema"), dict
    ):
        raise ConformanceError("DescribeProtocol omitted request_schema")
    return contract["request_schema"]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
        help="AI Agent OS checkout containing protocol/v1 and protocol/v2",
    )
    parser.add_argument(
        "--address",
        help="optional live kernel address (tcp://host:port or host:port)",
    )
    parser.add_argument(
        "--token-env",
        help="environment variable containing a live server auth token",
    )
    parser.add_argument("--timeout", type=float, default=5.0)
    args = parser.parse_args()

    token = None
    if args.token_env:
        token = os.environ.get(args.token_env)
        if token is None:
            raise ConformanceError(
                f"authentication environment variable {args.token_env} is not set"
            )

    schema = None
    if args.address:
        discovered = [
            discover_live_schema(args.address, version, args.timeout, token)
            for version in SUPPORTED_VERSIONS
        ]
        if discovered[0] != discovered[1]:
            raise ConformanceError("v1 and v2 DescribeProtocol schemas differ")
        schema = discovered[1]
    counts = validate_versioned_fixtures(args.repo_root, schema)
    print(
        "wire fixture conformance passed: "
        + ", ".join(f"v{version}={counts[version]}" for version in SUPPORTED_VERSIONS)
        + (" (live schema verified)" if schema is not None else "")
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ConformanceError as error:
        print(f"wire fixture conformance failed: {error}")
        raise SystemExit(1) from error
