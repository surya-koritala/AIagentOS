#!/usr/bin/env python3
"""Exercise a downloaded native CLI archive on a fresh CI host without compiling."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import secrets
import socket
import subprocess
import tempfile
import time
from pathlib import Path

from linux_cli_rc_qualification import EXPECTED_BINARIES, extract_archive


TARGETS = {
    "aarch64-unknown-linux-gnu": ("Linux", "aarch64"),
    "aarch64-apple-darwin": ("Darwin", "arm64"),
}
MAX_FRAME = 1024 * 1024


class InstallationError(RuntimeError):
    """Downloaded candidate cannot run its native installation contract."""


def digest(path: Path) -> str:
    result = hashlib.sha256()
    with path.open("rb") as handle:
        while block := handle.read(1024 * 1024):
            result.update(block)
    return result.hexdigest()


def check_manifest(dist: Path, archive: Path) -> None:
    if archive.parent.resolve() != dist.resolve() or archive.is_symlink():
        raise InstallationError("archive must be a regular file in the downloaded distribution")
    manifest = dist / "SHA256SUMS"
    if manifest.is_symlink() or not manifest.is_file() or manifest.stat().st_size > 8192:
        raise InstallationError("checksum manifest is missing or unsafe")
    expected = {archive.name, f"{archive.stem}.cdx.json"}
    seen: set[str] = set()
    for row in manifest.read_text(encoding="utf-8").splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  (?:\./)?([A-Za-z0-9_.+-]+)", row)
        if match is None or match.group(2) not in expected or match.group(2) in seen:
            raise InstallationError("checksum manifest has an unexpected or duplicate file")
        name = match.group(2)
        path = dist / name
        if path.is_symlink() or not path.is_file() or digest(path) != match.group(1):
            raise InstallationError(f"downloaded checksum failed for {name}")
        seen.add(name)
    if seen != expected:
        raise InstallationError("checksum manifest does not cover both archive and SBOM")


def _reply(connection: socket.socket, request: dict) -> dict:
    connection.sendall(json.dumps(request).encode() + b"\n")
    payload = bytearray()
    while not payload.endswith(b"\n"):
        chunk = connection.recv(1)
        if not chunk or len(payload) >= MAX_FRAME:
            raise InstallationError("server closed or exceeded the reply frame bound")
        payload.extend(chunk)
    reply = json.loads(payload)
    if not isinstance(reply, dict):
        raise InstallationError("server reply is not an object")
    return reply


def request(port: int, token: str | None, operation: dict) -> dict:
    with socket.create_connection(("127.0.0.1", port), timeout=5) as connection:
        if token is not None:
            if _reply(connection, {"op": "authenticate", "token": token}).get("status") != "authenticated":
                raise InstallationError("installed server rejected the fixture authentication")
        return _reply(connection, operation)


def require_status(reply: dict, status: str) -> dict:
    if reply.get("status") != status:
        raise InstallationError(f"expected {status}, received {reply.get('status')}")
    return reply


def _start(binary: Path, port: int, environment: dict, log) -> subprocess.Popen:
    process = subprocess.Popen([str(binary), f"127.0.0.1:{port}"], env=environment, stdout=log, stderr=log)
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise InstallationError("installed server exited during boot")
        try:
            request(port, None, {"op": "hello", "protocol_version": 1})
            return process
        except (OSError, ValueError):
            time.sleep(0.1)
    _stop(process)
    raise InstallationError("installed server did not become ready before its boot deadline")


def _stop(process: subprocess.Popen | None) -> None:
    if process is None or process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def qualify(dist: Path, archive: Path, target: str, commit: str, output: Path) -> dict:
    if target not in TARGETS or re.fullmatch(r"[0-9a-f]{40}", commit) is None:
        raise InstallationError("unsupported native target or invalid source commit")
    if (platform.system(), platform.machine()) != TARGETS[target]:
        raise InstallationError("fresh runner CPU/OS does not match the archive target")
    check_manifest(dist, archive)
    report = {
        "schema_version": 1, "source_commit": commit, "target": target,
        "archive": {"name": archive.name, "sha256": digest(archive)},
        "platform": {"os": platform.system(), "release": platform.release(),
                     "machine": platform.machine(), "macos_version": platform.mac_ver()[0],
                     "libc": list(platform.libc_ver())},
        "checks": {}, "provider_requests": 0, "production_claim_allowed": False,
        "limitations": ["keyless CI candidate", "native desktop signing not exercised",
                        "published release and paid-provider qualification not exercised"],
    }
    process = None
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="agentos-installed-") as temporary:
        root = Path(temporary)
        binaries = extract_archive(archive, root)
        environment = {key: value for key, value in os.environ.items()
                       if not key.startswith(("AGENT", "AZURE", "OPENAI", "ANTHROPIC", "GEMINI"))}
        environment.update({"HOME": str(root), "AGENT_SERVER_TOKEN": secrets.token_hex(32)})
        version_replies = {}
        for name in EXPECTED_BINARIES:
            reply = subprocess.run([str(binaries[name]), "--version"], env=environment,
                                   capture_output=True, text=True, timeout=15, check=True)
            version_replies[name] = reply.stdout.strip()
            if not reply.stdout.strip().startswith(f"{name} "):
                raise InstallationError(f"installed {name} did not report its version")
        report["checks"]["version_entry_points"] = version_replies
        if target.endswith("apple-darwin"):
            for binary in binaries.values():
                result = subprocess.run(["lipo", "-archs", str(binary)], capture_output=True,
                                        text=True, timeout=15, check=True)
                if result.stdout.strip() != "arm64":
                    raise InstallationError("macOS archive contains a non-native or universal binary")
        config = root / "config.toml"
        config.write_text(
            'llm_provider = "offline-installation-fixture"\n'
            'default_model = "no-provider-call"\n'
            'api_keys = {}\n'
            f"data_dir = {json.dumps(str(root / 'data'))}\n"
            "setup_complete = true\n",
            encoding="utf-8",
        )
        environment["AGENT_SERVER_CONFIG"] = str(config)
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        token = environment["AGENT_SERVER_TOKEN"]
        with output.with_suffix(".server.log").open("wb") as log:
            try:
                process = _start(binaries["agent-server"], port, environment, log)
                for credential in (None, "wrong-fixture-token"):
                    reply = request(port, credential, {"op": "node_info"}) if credential is None else None
                    if credential is None:
                        require_status(reply, "error")
                    else:
                        with socket.create_connection(("127.0.0.1", port), timeout=5) as connection:
                            require_status(_reply(connection, {"op": "authenticate", "token": credential}), "error")
                report["checks"]["authentication_denials"] = True
                require_status(request(port, token, {"op": "node_info"}), "node_info")
                agents = []
                for index in range(3):
                    reply = require_status(request(port, token, {
                        "op": "create_agent", "name": f"installed-{index}", "task": "offline installation fixture",
                        "provider": "stub", "profile": "standard", "priority": 3,
                    }), "agent_created")
                    agents.append(reply["id"])
                    require_status(request(port, token, {
                        "op": "storage_put", "agent_id": reply["id"], "key": "same-key", "value": f"private-{index}",
                    }), "storage_ok")
                if len(set(agents)) != 3:
                    raise InstallationError("installed server did not create distinct agent identities")
                _stop(process)
                process = _start(binaries["agent-server"], port, environment, log)
                for index, agent in enumerate(agents):
                    reply = require_status(request(port, token, {"op": "storage_get", "agent_id": agent, "key": "same-key"}), "storage_value")
                    if reply.get("value") != f"private-{index}":
                        raise InstallationError("agent-private storage changed or leaked across restart")
                report["checks"]["multiple_agents"] = 3
                report["checks"]["private_storage_survives_restart"] = True
                report["installation_fixture_passed"] = True
            finally:
                _stop(process)
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dist", type=Path, required=True)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    qualify(args.dist, args.archive, args.target, args.commit, args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
