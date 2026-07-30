#!/usr/bin/env python3
"""Fresh-host qualification for a signed restricted Linux CLI release candidate."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import secrets
import shutil
import signal
import socket
import sqlite3
import stat
import subprocess
import sys
import tempfile
import time
import tomllib
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


RC_TAG_PATTERN = re.compile(r"^v([0-9]+)\.([0-9]+)\.([0-9]+)-rc\.([1-9][0-9]*)$")
COMMIT_PATTERN = re.compile(r"^[0-9a-f]{40}$")
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
REPOSITORY_PATTERN = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
EXPECTED_BINARIES = ("agent", "agent-server", "agent-tui", "agentctl")
EXPECTED_ARCHIVE_NAMES = frozenset(EXPECTED_BINARIES)
MAX_ARCHIVE_BYTES = 512 * 1024 * 1024
MAX_BINARY_BYTES = 256 * 1024 * 1024
MAX_TOTAL_UNCOMPRESSED_BYTES = 768 * 1024 * 1024
MAX_FIXTURE_REGISTRY_BYTES = 64 * 1024
MAX_FIXTURE_BYTES = 16 * 1024 * 1024
MAX_SIGSTORE_BUNDLE_BYTES = 8 * 1024 * 1024
MAX_COMMAND_OUTPUT_BYTES = 1024 * 1024
FIXTURE_AGENT_IDS = {
    "v0.1.0": "00000000-0000-0000-0000-000000000101",
    "v0.2.0": "00000000-0000-0000-0000-000000000201",
    "v0.3.0": "00000000-0000-0000-0000-000000000301",
}


class QualificationError(RuntimeError):
    """The candidate failed a production-promotion requirement."""


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _require_regular_file(path: Path, label: str, max_bytes: int) -> os.stat_result:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise QualificationError(f"cannot inspect {label}: {error}") from error
    if not stat.S_ISREG(metadata.st_mode):
        raise QualificationError(f"{label} must be a regular non-symlink file")
    if metadata.st_size <= 0 or metadata.st_size > max_bytes:
        raise QualificationError(f"{label} must contain 1..{max_bytes} bytes")
    return metadata


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while block := handle.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def validate_identity(release_candidate: str, commit: str) -> str:
    match = RC_TAG_PATTERN.fullmatch(release_candidate)
    if match is None:
        raise QualificationError("release candidate must be an exact vX.Y.Z-rc.N tag")
    if COMMIT_PATTERN.fullmatch(commit) is None:
        raise QualificationError("source commit must be exactly 40 lowercase hexadecimal characters")
    return release_candidate[1:]


def validate_archive(path: Path) -> dict[str, zipfile.ZipInfo]:
    metadata = _require_regular_file(path, "CLI archive", MAX_ARCHIVE_BYTES)
    try:
        with zipfile.ZipFile(path) as archive:
            infos = archive.infolist()
            names = [info.filename for info in infos]
            if len(names) != len(set(names)):
                raise QualificationError("CLI archive contains duplicate entries")
            if set(names) != EXPECTED_ARCHIVE_NAMES:
                missing = sorted(EXPECTED_ARCHIVE_NAMES - set(names))
                extra = sorted(set(names) - EXPECTED_ARCHIVE_NAMES)
                raise QualificationError(
                    f"CLI archive entries differ from the contract; missing={missing}, extra={extra}"
                )
            total = 0
            result: dict[str, zipfile.ZipInfo] = {}
            for info in infos:
                mode = info.external_attr >> 16
                if info.create_system != 3 or stat.S_IFMT(mode) != stat.S_IFREG:
                    raise QualificationError(
                        f"CLI archive entry {info.filename} is not a Unix regular file"
                    )
                if stat.S_IMODE(mode) != 0o755:
                    raise QualificationError(
                        f"CLI archive entry {info.filename} must have mode 0755"
                    )
                if info.date_time != (1980, 1, 1, 0, 0, 0):
                    raise QualificationError(
                        f"CLI archive entry {info.filename} has a non-canonical timestamp"
                    )
                if info.flag_bits & 0x1:
                    raise QualificationError(
                        f"CLI archive entry {info.filename} must not use ZIP encryption"
                    )
                if info.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
                    raise QualificationError(
                        f"CLI archive entry {info.filename} uses an unsupported compression method"
                    )
                if info.file_size <= 0 or info.file_size > MAX_BINARY_BYTES:
                    raise QualificationError(
                        f"CLI archive entry {info.filename} has an unsafe size"
                    )
                total += info.file_size
                result[info.filename] = info
            if total > MAX_TOTAL_UNCOMPRESSED_BYTES:
                raise QualificationError("CLI archive expands beyond the total size limit")
            corrupt = archive.testzip()
            if corrupt is not None:
                raise QualificationError(f"CLI archive CRC failed for {corrupt}")
            if archive.fp is None or metadata.st_size != path.stat().st_size:
                raise QualificationError("CLI archive changed while it was being validated")
            return result
    except (OSError, zipfile.BadZipFile, zipfile.LargeZipFile) as error:
        raise QualificationError(f"CLI archive is unreadable: {error}") from error


def extract_archive(path: Path, destination: Path) -> dict[str, Path]:
    infos = validate_archive(path)
    extracted: dict[str, Path] = {}
    with zipfile.ZipFile(path) as archive:
        for name in sorted(infos):
            output = destination / name
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            descriptor = os.open(output, flags, 0o700)
            written = 0
            try:
                with os.fdopen(descriptor, "wb") as target, archive.open(infos[name]) as source:
                    while block := source.read(1024 * 1024):
                        written += len(block)
                        if written > infos[name].file_size or written > MAX_BINARY_BYTES:
                            raise QualificationError(
                                f"CLI archive entry {name} expanded beyond its declared size"
                            )
                        target.write(block)
                    target.flush()
                    os.fsync(target.fileno())
            except Exception:
                try:
                    output.unlink()
                except OSError:
                    pass
                raise
            if written != infos[name].file_size:
                raise QualificationError(f"CLI archive entry {name} was truncated")
            os.chmod(output, 0o755)
            extracted[name] = output
    return extracted


def load_release_fixture(registry_path: Path, released_tag: str) -> tuple[Path, dict[str, Any]]:
    _require_regular_file(
        registry_path, "released-schema registry", MAX_FIXTURE_REGISTRY_BYTES
    )
    try:
        registry = tomllib.loads(registry_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        raise QualificationError(f"released-schema registry is invalid: {error}") from error
    if registry.get("format_version") != 1:
        raise QualificationError("released-schema registry format_version must be 1")
    matches = [
        release
        for release in registry.get("release", [])
        if isinstance(release, dict) and release.get("tag") == released_tag
    ]
    if len(matches) != 1:
        raise QualificationError(
            "released-schema registry must contain the requested tag exactly once"
        )
    release = matches[0]
    sql_file = release.get("sql_file")
    digest = release.get("sql_sha256")
    source_commit = release.get("source_commit")
    if (
        not isinstance(sql_file, str)
        or Path(sql_file).name != sql_file
        or not sql_file.endswith(".sql")
    ):
        raise QualificationError("released-schema fixture name is unsafe")
    if not isinstance(digest, str) or SHA256_PATTERN.fullmatch(digest) is None:
        raise QualificationError("released-schema fixture digest is invalid")
    if not isinstance(source_commit, str) or COMMIT_PATTERN.fullmatch(source_commit) is None:
        raise QualificationError("released-schema source commit is invalid")
    fixture = registry_path.parent / sql_file
    _require_regular_file(fixture, "released-schema fixture", MAX_FIXTURE_BYTES)
    if sha256_file(fixture) != digest:
        raise QualificationError("released-schema fixture digest does not match its registry")
    expected_agent_id = FIXTURE_AGENT_IDS.get(released_tag)
    if expected_agent_id is None or release.get("agent_id") != expected_agent_id:
        raise QualificationError("released-schema fixture agent identity is not trusted")
    return fixture, release


def _bounded_output(value: bytes, label: str) -> str:
    if len(value) > MAX_COMMAND_OUTPUT_BYTES:
        raise QualificationError(f"{label} exceeded the {MAX_COMMAND_OUTPUT_BYTES}-byte limit")
    return value.decode("utf-8", errors="replace")


def run_command(
    command: list[str],
    *,
    env: dict[str, str] | None = None,
    timeout: int = 60,
    expect_failure: bool = False,
    redactions: tuple[str, ...] = (),
) -> subprocess.CompletedProcess[bytes]:
    try:
        result = subprocess.run(
            command,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise QualificationError(f"{Path(command[0]).name} could not complete: {error}") from error
    stdout = _bounded_output(result.stdout, f"{Path(command[0]).name} stdout")
    stderr = _bounded_output(result.stderr, f"{Path(command[0]).name} stderr")
    failed = result.returncode != 0
    if failed != expect_failure:
        detail = (stderr or stdout).strip()[-2_000:]
        for secret in redactions:
            if secret:
                detail = detail.replace(secret, "<redacted>")
        expectation = "failure" if expect_failure else "success"
        raise QualificationError(
            f"{Path(command[0]).name} returned {result.returncode}; expected {expectation}: {detail}"
        )
    return result


def run_json(
    command: list[str],
    *,
    env: dict[str, str] | None = None,
    timeout: int = 60,
    redactions: tuple[str, ...] = (),
) -> Any:
    result = run_command(command, env=env, timeout=timeout, redactions=redactions)
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise QualificationError(
            f"{Path(command[0]).name} did not return one JSON document"
        ) from error


def _clean_environment() -> dict[str, str]:
    environment = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith("AGENTOS_") and not key.startswith("AGENT_SERVER_")
    }
    environment["RUST_LOG"] = "warn"
    return environment


def _toml_string(value: Path | str) -> str:
    return json.dumps(str(value))


def write_config(
    path: Path,
    *,
    data_dir: Path,
    backup_root: Path,
    storage_key: Path,
    signing_key: Path,
) -> None:
    document = f"""llm_provider = "local"
default_model = "qualification-no-provider-call"
data_dir = {_toml_string(data_dir)}
setup_complete = true
permission_profile = "standard"

[api_keys]
local = "http://127.0.0.1:9"

[backup]
enabled = true
root = {_toml_string(backup_root)}
interval_seconds = 86400
run_on_start = false
keep_latest = 2
max_age_seconds = 172800
signing_key_path = {_toml_string(signing_key)}
signing_key_id = "linux-cli-rc-backup-1"

[storage_encryption]
required = true
key_path = {_toml_string(storage_key)}
"""
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(document)
        handle.flush()
        os.fsync(handle.fileno())


def _generate_tls(root: Path) -> tuple[Path, Path, Path]:
    ca_key = root / "ca.key"
    ca_certificate = root / "ca.pem"
    server_key = root / "server.key"
    request = root / "server.csr"
    server_certificate = root / "server.pem"
    extensions = root / "server.ext"
    extensions.write_text(
        "subjectAltName=DNS:localhost,IP:127.0.0.1\n"
        "extendedKeyUsage=serverAuth\n"
        "keyUsage=digitalSignature,keyEncipherment\n",
        encoding="utf-8",
    )
    run_command(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-sha256",
            "-days",
            "1",
            "-subj",
            "/CN=AIagentOS Linux CLI RC CA",
            "-keyout",
            str(ca_key),
            "-out",
            str(ca_certificate),
        ]
    )
    run_command(
        [
            "openssl",
            "req",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-sha256",
            "-subj",
            "/CN=localhost",
            "-keyout",
            str(server_key),
            "-out",
            str(request),
        ]
    )
    run_command(
        [
            "openssl",
            "x509",
            "-req",
            "-in",
            str(request),
            "-CA",
            str(ca_certificate),
            "-CAkey",
            str(ca_key),
            "-CAcreateserial",
            "-days",
            "1",
            "-sha256",
            "-extfile",
            str(extensions),
            "-out",
            str(server_certificate),
        ]
    )
    os.chmod(ca_key, 0o600)
    os.chmod(server_key, 0o600)
    return ca_certificate, server_certificate, server_key


def _free_loopback_address() -> str:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return f"127.0.0.1:{listener.getsockname()[1]}"


class Server:
    def __init__(
        self,
        binary: Path,
        agentctl: Path,
        address: str,
        server_environment: dict[str, str],
        client_environment: dict[str, str],
        log_path: Path,
        token: str,
    ) -> None:
        self.binary = binary
        self.agentctl = agentctl
        self.address = address
        self.server_environment = server_environment
        self.client_environment = client_environment
        self.log_path = log_path
        self.token = token
        self.process: subprocess.Popen[bytes] | None = None
        self.log_handle: Any = None

    def start(self, expected_version: str) -> dict[str, Any]:
        if self.process is not None:
            raise QualificationError("server is already running")
        self.log_handle = self.log_path.open("ab", buffering=0)
        self.process = subprocess.Popen(
            [str(self.binary), self.address],
            env=self.server_environment,
            stdin=subprocess.DEVNULL,
            stdout=self.log_handle,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        deadline = time.monotonic() + 30
        last_error: Exception | None = None
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                break
            try:
                protocol = run_json(
                    [str(self.agentctl), "protocol"],
                    env=self.client_environment,
                    timeout=5,
                    redactions=(self.token,),
                )
                if protocol.get("server_version") != expected_version:
                    raise QualificationError(
                        "running server version does not match the release-candidate tag"
                    )
                return protocol
            except QualificationError as error:
                last_error = error
                time.sleep(0.25)
        exit_code = self.process.poll()
        self.stop(require_graceful=False)
        detail = ""
        try:
            detail = self.log_path.read_text(encoding="utf-8", errors="replace")[-2_000:]
        except OSError:
            pass
        detail = detail.replace(self.token, "<redacted>")
        raise QualificationError(
            f"server did not become ready (exit={exit_code}, last={last_error}): {detail}"
        )

    def stop(self, require_graceful: bool = True) -> None:
        process = self.process
        self.process = None
        if process is None:
            return
        try:
            if process.poll() is None:
                process.send_signal(signal.SIGTERM)
                try:
                    process.wait(timeout=20)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
                    if require_graceful:
                        raise QualificationError("server did not stop cleanly on SIGTERM")
            if require_graceful and process.returncode != 0:
                raise QualificationError(f"server stopped with status {process.returncode}")
        finally:
            if self.log_handle is not None:
                self.log_handle.close()
                self.log_handle = None


def _list_agent_ids(agentctl: Path, environment: dict[str, str], token: str) -> set[str]:
    result = run_command(
        [str(agentctl), "list"],
        env=environment,
        redactions=(token,),
    )
    lines = _bounded_output(result.stdout, "agent list").splitlines()
    return {line.split("\t", 1)[0] for line in lines if line.strip()}


def _assert_encrypted_database(path: Path) -> None:
    _require_regular_file(path, "encrypted database", MAX_ARCHIVE_BYTES)
    with path.open("rb") as handle:
        header = handle.read(16)
    if header == b"SQLite format 3\x00":
        raise QualificationError("database remained plaintext after encryption was required")


def _tamper_copy(source: Path, destination: Path) -> None:
    shutil.copytree(source, destination)
    database = destination / "agent_os.db"
    with database.open("r+b") as handle:
        size = database.stat().st_size
        if size < 128:
            raise QualificationError("backup database is unexpectedly small")
        offset = min(size - 1, max(64, size // 2))
        handle.seek(offset)
        original = handle.read(1)
        handle.seek(offset)
        handle.write(bytes([original[0] ^ 0x01]))
        handle.flush()
        os.fsync(handle.fileno())


def _linux_environment() -> dict[str, str]:
    if platform.system() != "Linux" or platform.machine().lower() not in {
        "x86_64",
        "amd64",
    }:
        raise QualificationError("restricted CLI qualification requires Linux x86_64")
    values: dict[str, str] = {}
    # /etc/os-release is commonly a symlink; read its fixed canonical location
    # so qualification does not relax the regular-file policy.
    path = Path("/usr/lib/os-release")
    _require_regular_file(path, "Linux OS release file", 64 * 1024)
    for line in path.read_text(encoding="utf-8").splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            values[key] = value.strip().strip('"')
    if values.get("ID") != "ubuntu" or values.get("VERSION_ID") != "22.04":
        raise QualificationError("restricted CLI qualification requires Ubuntu 22.04")
    return {
        "os": "ubuntu",
        "version": "22.04",
        "architecture": "x86_64",
    }


def verify_supply_chain(
    archive: Path,
    sigstore_bundle: Path,
    repository: str,
    release_candidate: str,
    commit: str,
) -> None:
    _require_regular_file(
        sigstore_bundle, "Sigstore bundle", MAX_SIGSTORE_BUNDLE_BYTES
    )
    if REPOSITORY_PATTERN.fullmatch(repository) is None:
        raise QualificationError("repository must be in owner/name form")
    workflow_identity = (
        f"https://github.com/{repository}/.github/workflows/"
        f"linux-cli-rc.yml@refs/tags/{release_candidate}"
    )
    run_command(
        [
            "cosign",
            "verify-blob",
            "--bundle",
            str(sigstore_bundle),
            "--certificate-identity",
            workflow_identity,
            "--certificate-oidc-issuer",
            "https://token.actions.githubusercontent.com",
            str(archive),
        ],
        timeout=60,
    )
    attestation_command = [
        "gh",
        "attestation",
        "verify",
        str(archive),
        "--repo",
        repository,
        "--signer-workflow",
        f"{repository}/.github/workflows/linux-cli-rc.yml",
        "--source-ref",
        f"refs/tags/{release_candidate}",
        "--source-digest",
        commit,
        "--cert-identity",
        workflow_identity,
        "--deny-self-hosted-runners",
    ]
    error: QualificationError | None = None
    for delay in (0, 2, 4, 8, 16):
        if delay:
            time.sleep(delay)
        try:
            run_command(attestation_command, timeout=60)
            return
        except QualificationError as current:
            error = current
    raise QualificationError(f"GitHub build provenance did not verify: {error}")


def _write_new_json(path: Path, value: dict[str, Any]) -> None:
    encoded = (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
        + b"\n"
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(encoded)
        handle.flush()
        os.fsync(handle.fileno())


def validate_report(
    report_path: Path,
    *,
    release_candidate: str,
    commit: str,
    archive: Path,
    release_registry: Path,
    released_schema_tag: str,
) -> dict[str, Any]:
    validate_identity(release_candidate, commit)
    _, fixture_record = load_release_fixture(release_registry, released_schema_tag)
    _require_regular_file(report_path, "qualification report", 1024 * 1024)
    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise QualificationError(f"qualification report is invalid: {error}") from error
    if not isinstance(report, dict) or set(report) != {
        "artifact",
        "completed_at",
        "durability",
        "limitations",
        "platform",
        "production_claim_allowed",
        "qualification_class",
        "release_candidate",
        "runtime",
        "schema_version",
        "source",
        "supply_chain",
        "upgrade",
    }:
        raise QualificationError("qualification report has an unexpected top-level schema")
    expected = {
        "schema_version": 1,
        "qualification_class": "restricted_linux_cli_release_candidate",
        "release_candidate": release_candidate,
        "production_claim_allowed": False,
    }
    for key, value in expected.items():
        if report.get(key) != value:
            raise QualificationError(f"qualification report has an invalid {key}")
    if report.get("source") != {"commit": commit, "dirty": False}:
        raise QualificationError("qualification report source identity is invalid")
    artifact = report.get("artifact")
    if not isinstance(artifact, dict) or set(artifact) != {
        "binaries",
        "byte_count",
        "name",
        "sha256",
    }:
        raise QualificationError("qualification report artifact schema is invalid")
    expected_name = (
        f"agentos-{release_candidate}-x86_64-unknown-linux-gnu.zip"
    )
    if artifact.get("name") != archive.name or artifact.get("name") != expected_name:
        raise QualificationError("qualification report archive name is invalid")
    if artifact.get("sha256") != sha256_file(archive):
        raise QualificationError("qualification report does not bind the exact archive")
    if artifact.get("byte_count") != archive.stat().st_size:
        raise QualificationError("qualification report archive size is invalid")
    if artifact.get("binaries") != list(EXPECTED_BINARIES):
        raise QualificationError("qualification report binary inventory is invalid")
    if report.get("platform") != {
        "architecture": "x86_64",
        "os": "ubuntu",
        "version": "22.04",
    }:
        raise QualificationError("qualification report platform is invalid")
    if report.get("supply_chain") != {
        "github_provenance_verified": True,
        "keyless_sigstore_verified": True,
    }:
        raise QualificationError("qualification report supply-chain proof is invalid")
    runtime = report.get("runtime")
    runtime_fields = {
        "authentication_required",
        "clean_restart_persisted_state",
        "exact_version_served",
        "gate_counters_observable",
        "governed_agent_created",
        "tls_verified",
        "wrong_authentication_rejected",
    }
    if (
        not isinstance(runtime, dict)
        or set(runtime) != runtime_fields
        or any(value is not True for value in runtime.values())
    ):
        raise QualificationError("qualification report runtime contains a failed proof")
    durability = report.get("durability")
    durability_boolean_fields = {
        "backup_encrypted",
        "backup_signed",
        "enforcement_rearmed",
        "fresh_host_restore_completed",
        "fresh_host_runtime_verified",
        "missing_key_failed_closed",
        "recovery_anchor_verified",
        "storage_encrypted",
        "tampered_backup_rejected",
    }
    if (
        not isinstance(durability, dict)
        or set(durability) != durability_boolean_fields | {"persisted_agent_count"}
        or any(durability.get(field) is not True for field in durability_boolean_fields)
        or not isinstance(durability.get("persisted_agent_count"), int)
        or durability["persisted_agent_count"] < 2
    ):
        raise QualificationError("qualification report durability contains a failed proof")
    upgrade = report.get("upgrade")
    upgrade_boolean_fields = {
        "released_agent_survived",
        "released_schema_encrypted",
        "released_schema_fixture_verified",
    }
    if (
        not isinstance(upgrade, dict)
        or set(upgrade)
        != upgrade_boolean_fields
        | {"released_schema_sha256", "released_schema_source_commit", "released_schema_tag"}
        or any(upgrade.get(field) is not True for field in upgrade_boolean_fields)
        or upgrade.get("released_schema_tag") != released_schema_tag
        or upgrade.get("released_schema_source_commit")
        != fixture_record["source_commit"]
        or upgrade.get("released_schema_sha256") != fixture_record["sql_sha256"]
    ):
        raise QualificationError("qualification report upgrade contains a failed proof")
    completed_at = report.get("completed_at")
    if not isinstance(completed_at, str) or not completed_at.endswith("Z"):
        raise QualificationError("qualification report completion timestamp is missing")
    try:
        datetime.fromisoformat(completed_at.replace("Z", "+00:00"))
    except ValueError as error:
        raise QualificationError("qualification report completion timestamp is invalid") from error
    limitations = report.get("limitations")
    if (
        not isinstance(limitations, list)
        or len(limitations) < 3
        or any(
            not isinstance(item, str) or not item or len(item.encode("utf-8")) > 512
            for item in limitations
        )
    ):
        raise QualificationError("qualification report must retain scoped limitations")
    return report


def qualify(
    *,
    archive: Path,
    sigstore_bundle: Path,
    release_candidate: str,
    commit: str,
    repository: str,
    release_registry: Path,
    released_schema_tag: str,
    output: Path,
) -> dict[str, Any]:
    expected_version = validate_identity(release_candidate, commit)
    linux = _linux_environment()
    validate_archive(archive)
    archive_digest = sha256_file(archive)
    verify_supply_chain(
        archive, sigstore_bundle, repository, release_candidate, commit
    )
    if sha256_file(archive) != archive_digest:
        raise QualificationError("CLI archive changed after supply-chain verification")
    fixture, fixture_record = load_release_fixture(
        release_registry, released_schema_tag
    )
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="agentos-linux-cli-rc-") as temporary:
        root = Path(temporary)
        bin_dir = root / "bin"
        bin_dir.mkdir(mode=0o700)
        binaries = extract_archive(archive, bin_dir)
        if sha256_file(archive) != archive_digest:
            raise QualificationError("CLI archive changed during extraction")
        data_dir = root / "upgraded-data"
        backup_root = root / "backups"
        fresh_data_dir = root / "fresh-data"
        fresh_backup_root = root / "fresh-backups"
        tls_dir = root / "tls"
        for directory in (
            data_dir,
            backup_root,
            fresh_data_dir,
            fresh_backup_root,
            tls_dir,
        ):
            directory.mkdir(mode=0o700)

        database = data_dir / "agent_os.db"
        connection = sqlite3.connect(database)
        try:
            connection.executescript(fixture.read_text(encoding="utf-8"))
            connection.commit()
        finally:
            connection.close()
        os.chmod(database, 0o600)

        storage_key = root / "storage.json"
        signing_key = root / "backup.pk8"
        trust_root = root / "backup-trust.json"
        anchor = root / "backup-anchor.json"
        agentctl = binaries["agentctl"]
        run_json(
            [
                str(agentctl),
                "storage-key-generate",
                "linux-cli-rc-storage-1",
                str(storage_key),
            ]
        )
        migration = run_json(
            [
                str(agentctl),
                "storage-encrypt",
                str(database),
                str(storage_key),
                "--confirm-offline",
            ]
        )
        if migration.get("operation") != "encrypt":
            raise QualificationError("released-schema encryption migration did not complete")
        _assert_encrypted_database(database)
        trust = run_json(
            [
                str(agentctl),
                "backup-key-generate",
                "linux-cli-rc-backup-1",
                str(signing_key),
                str(trust_root),
            ]
        )
        if trust.get("key_id") != "linux-cli-rc-backup-1":
            raise QualificationError("backup signing identity is not the configured identity")

        ca_certificate, server_certificate, server_key = _generate_tls(tls_dir)
        config = root / "config.toml"
        write_config(
            config,
            data_dir=data_dir,
            backup_root=backup_root,
            storage_key=storage_key,
            signing_key=signing_key,
        )
        token = secrets.token_urlsafe(32)
        address = _free_loopback_address()
        base_environment = _clean_environment()
        server_environment = {
            **base_environment,
            "AGENT_SERVER_CONFIG": str(config),
            "AGENT_SERVER_TOKEN": token,
            "AGENT_SERVER_TLS_CERT": str(server_certificate),
            "AGENT_SERVER_TLS_KEY": str(server_key),
        }
        client_environment = {
            **base_environment,
            "AGENTOS_ADDR": address,
            "AGENTOS_TLS_CA": str(ca_certificate),
            "AGENTOS_TLS_SERVER_NAME": "localhost",
            "AGENT_SERVER_TOKEN": token,
        }
        server = Server(
            binaries["agent-server"],
            agentctl,
            address,
            server_environment,
            client_environment,
            root / "server.log",
            token,
        )
        try:
            server.start(expected_version)
            unauthenticated = dict(client_environment)
            unauthenticated.pop("AGENT_SERVER_TOKEN")
            run_command(
                [str(agentctl), "list"],
                env=unauthenticated,
                timeout=15,
                expect_failure=True,
            )
            wrong_token = {**client_environment, "AGENT_SERVER_TOKEN": "wrong-token"}
            run_command(
                [str(agentctl), "list"],
                env=wrong_token,
                timeout=15,
                expect_failure=True,
            )
            upgraded_ids = _list_agent_ids(agentctl, client_environment, token)
            fixture_agent_id = str(fixture_record["agent_id"])
            if fixture_agent_id not in upgraded_ids:
                raise QualificationError("released-schema agent did not survive upgrade")
            created = run_json(
                [
                    str(agentctl),
                    "create",
                    "linux-cli-rc-agent",
                    "prove governed release operation",
                    "stub",
                    "standard",
                    "3",
                ],
                env=client_environment,
                redactions=(token,),
            )
            created_id = created.get("id")
            if not isinstance(created_id, str) or not created_id:
                raise QualificationError("agent creation did not return a stable identity")
            gates = run_json(
                [str(agentctl), "gate-stats"],
                env=client_environment,
                redactions=(token,),
            )
            if not isinstance(gates, dict):
                raise QualificationError("gate enforcement counters were not observable")
        finally:
            server.stop()
        _assert_encrypted_database(database)

        try:
            server.start(expected_version)
            restarted_ids = _list_agent_ids(agentctl, client_environment, token)
            if created_id not in restarted_ids or fixture_agent_id not in restarted_ids:
                raise QualificationError("agent state did not survive a clean server restart")
            manifest = run_json(
                [str(agentctl), "backup-create", str(backup_root), "rc-qualified"],
                env=client_environment,
                timeout=120,
                redactions=(token,),
            )
            if not isinstance(manifest.get("encryption"), dict):
                raise QualificationError("release backup is not encrypted")
            authenticity = manifest.get("authenticity")
            if (
                not isinstance(authenticity, dict)
                or authenticity.get("key_id") != "linux-cli-rc-backup-1"
            ):
                raise QualificationError("release backup is not signed by the configured identity")
        finally:
            server.stop()

        backup_dir = backup_root / "rc-qualified"
        run_json(
            [
                str(agentctl),
                "backup-anchor-create",
                str(backup_dir),
                str(trust_root),
                str(anchor),
                "--storage-key",
                str(storage_key),
            ]
        )
        run_json(
            [
                str(agentctl),
                "backup-verify",
                str(backup_dir),
                "--storage-key",
                str(storage_key),
                "--require-signature",
                str(trust_root),
                "--require-anchor",
                str(anchor),
            ]
        )
        tampered = root / "tampered-backup"
        _tamper_copy(backup_dir, tampered)
        run_command(
            [
                str(agentctl),
                "backup-verify",
                str(tampered),
                "--storage-key",
                str(storage_key),
                "--require-signature",
                str(trust_root),
            ],
            expect_failure=True,
        )

        missing_key_config = root / "missing-key.toml"
        write_config(
            missing_key_config,
            data_dir=fresh_data_dir,
            backup_root=fresh_backup_root,
            storage_key=root / "missing-storage-key.json",
            signing_key=signing_key,
        )
        run_command(
            [
                str(agentctl),
                "backup-disaster-recover",
                str(backup_dir),
                str(missing_key_config),
                str(trust_root),
                str(anchor),
                "--confirm-offline",
            ],
            expect_failure=True,
        )
        if (fresh_data_dir / "agent_os.db").exists():
            raise QualificationError("failed missing-key recovery mutated the fresh destination")

        fresh_config = root / "fresh-config.toml"
        write_config(
            fresh_config,
            data_dir=fresh_data_dir,
            backup_root=fresh_backup_root,
            storage_key=storage_key,
            signing_key=signing_key,
        )
        recovery = run_json(
            [
                str(agentctl),
                "backup-disaster-recover",
                str(backup_dir),
                str(fresh_config),
                str(trust_root),
                str(anchor),
                "--confirm-offline",
            ],
            timeout=120,
        )
        if recovery.get("enforcement_rearmed") is not True:
            raise QualificationError("fresh-host recovery did not re-arm enforcement")
        persisted_agent_count = recovery.get("persisted_agent_count")
        if not isinstance(persisted_agent_count, int) or persisted_agent_count < 2:
            raise QualificationError("fresh-host recovery lost persisted agents")
        fresh_database = fresh_data_dir / "agent_os.db"
        _assert_encrypted_database(fresh_database)

        fresh_server_environment = {
            **server_environment,
            "AGENT_SERVER_CONFIG": str(fresh_config),
        }
        fresh_server = Server(
            binaries["agent-server"],
            agentctl,
            address,
            fresh_server_environment,
            client_environment,
            root / "fresh-server.log",
            token,
        )
        try:
            fresh_server.start(expected_version)
            recovered_ids = _list_agent_ids(agentctl, client_environment, token)
            if created_id not in recovered_ids or fixture_agent_id not in recovered_ids:
                raise QualificationError("fresh-host runtime did not expose recovered agents")
            run_json(
                [str(agentctl), "gate-stats"],
                env=client_environment,
                redactions=(token,),
            )
        finally:
            fresh_server.stop()
        _assert_encrypted_database(fresh_database)

        report = {
            "schema_version": 1,
            "qualification_class": "restricted_linux_cli_release_candidate",
            "release_candidate": release_candidate,
            "source": {"commit": commit, "dirty": False},
            "artifact": {
                "name": archive.name,
                "sha256": archive_digest,
                "byte_count": archive.stat().st_size,
                "binaries": list(EXPECTED_BINARIES),
            },
            "platform": linux,
            "supply_chain": {
                "keyless_sigstore_verified": True,
                "github_provenance_verified": True,
            },
            "upgrade": {
                "released_schema_fixture_verified": True,
                "released_schema_encrypted": True,
                "released_agent_survived": True,
                "released_schema_tag": released_schema_tag,
                "released_schema_source_commit": fixture_record["source_commit"],
                "released_schema_sha256": fixture_record["sql_sha256"],
            },
            "runtime": {
                "exact_version_served": True,
                "tls_verified": True,
                "authentication_required": True,
                "wrong_authentication_rejected": True,
                "governed_agent_created": True,
                "gate_counters_observable": True,
                "clean_restart_persisted_state": True,
            },
            "durability": {
                "storage_encrypted": True,
                "backup_signed": True,
                "backup_encrypted": True,
                "recovery_anchor_verified": True,
                "tampered_backup_rejected": True,
                "missing_key_failed_closed": True,
                "fresh_host_restore_completed": True,
                "enforcement_rearmed": True,
                "fresh_host_runtime_verified": True,
                "persisted_agent_count": persisted_agent_count,
            },
            "completed_at": _utc_now(),
            "production_claim_allowed": False,
            "limitations": [
                "Qualification is restricted to single-node Ubuntu 22.04 x86_64 CLI operation.",
                "No cloud LLM, Ollama, vLLM, or on-device GGUF backend is promoted by this artifact.",
                "Remote immutable backup, destructive device-loss testing, 24-hour soak, and human game day require separate exact-RC evidence.",
                "Desktop, peripheral, distributed-control-plane, and independent-security-review gates remain open.",
            ],
        }
        if time.monotonic() - started > 15 * 60:
            raise QualificationError("fresh-host qualification exceeded its 15-minute budget")
        _write_new_json(output, report)
        validate_report(
            output,
            release_candidate=release_candidate,
            commit=commit,
            archive=archive,
            release_registry=release_registry,
            released_schema_tag=released_schema_tag,
        )
        return report


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    qualify_parser = subparsers.add_parser("qualify")
    qualify_parser.add_argument("--archive", type=Path, required=True)
    qualify_parser.add_argument("--sigstore-bundle", type=Path, required=True)
    qualify_parser.add_argument("--release-candidate", required=True)
    qualify_parser.add_argument("--commit", required=True)
    qualify_parser.add_argument("--repository", required=True)
    qualify_parser.add_argument("--release-registry", type=Path, required=True)
    qualify_parser.add_argument("--released-schema-tag", default="v0.3.0")
    qualify_parser.add_argument("--output", type=Path, required=True)
    report_parser = subparsers.add_parser("validate-report")
    report_parser.add_argument("--report", type=Path, required=True)
    report_parser.add_argument("--archive", type=Path, required=True)
    report_parser.add_argument("--release-candidate", required=True)
    report_parser.add_argument("--commit", required=True)
    report_parser.add_argument("--release-registry", type=Path, required=True)
    report_parser.add_argument("--released-schema-tag", default="v0.3.0")
    args = parser.parse_args()
    try:
        if args.command == "qualify":
            qualify(
                archive=args.archive.absolute(),
                sigstore_bundle=args.sigstore_bundle.absolute(),
                release_candidate=args.release_candidate,
                commit=args.commit,
                repository=args.repository,
                release_registry=args.release_registry.absolute(),
                released_schema_tag=args.released_schema_tag,
                output=args.output.absolute(),
            )
            print(f"restricted Linux CLI RC qualified: {args.output}")
        else:
            validate_report(
                args.report.absolute(),
                release_candidate=args.release_candidate,
                commit=args.commit,
                archive=args.archive.absolute(),
                release_registry=args.release_registry.absolute(),
                released_schema_tag=args.released_schema_tag,
            )
            print("restricted Linux CLI RC report is exact and complete")
    except QualificationError as error:
        print(f"Linux CLI RC qualification failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
