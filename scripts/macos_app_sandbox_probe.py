#!/usr/bin/env python3
"""Observe supported App Sandbox controls on disposable GitHub macOS runners.

This does not enable a runtime backend or implement custom Seatbelt profiles.
Ad-hoc fixture signatures are deliberately not distribution signing evidence.
"""

from __future__ import annotations

import argparse
import errno
import hashlib
import json
import os
from pathlib import Path
import platform
import plistlib
import socket
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
MAX_OUTPUT = 16 * 1024


def command(argv: list[str], *, cwd: Path | None = None, timeout: int = 15) -> subprocess.CompletedProcess:
    result = subprocess.run(
        argv, cwd=cwd, env={}, stdin=subprocess.DEVNULL,
        capture_output=True, timeout=timeout, check=False,
    )
    if len(result.stdout) > MAX_OUTPUT or len(result.stderr) > MAX_OUTPUT:
        raise ValueError("probe output exceeded its bound")
    result.stdout.decode("utf-8", "strict")
    result.stderr.decode("utf-8", "strict")
    return result


def observe(binary: Path, workspace: Path, operation: str, *args: str) -> dict:
    result = command([str(binary), operation, *args], cwd=workspace)
    if result.returncode:
        return {
            "observed": False, "exit_code": result.returncode,
            "diagnostic": result.stderr.decode("utf-8", "strict")[:4096],
        }
    payload = json.loads(result.stdout)
    if not isinstance(payload, dict):
        raise ValueError("fixture response was not an object")
    return {"observed": True, **payload}


def run(output: Path) -> None:
    if platform.system() != "Darwin" or os.environ.get("GITHUB_ACTIONS") != "true":
        raise ValueError("this live probe runs only on disposable GitHub macOS CI")
    source = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    dirty = bool(subprocess.check_output(
        ["git", "status", "--porcelain", "--untracked-files=no"], cwd=ROOT,
    ))
    if dirty:
        raise ValueError("probe requires unchanged tracked source")
    report = {
        "schema_version": 1,
        "qualification_class": "macos_app_sandbox_feasibility_probe",
        "source": {"commit": source, "dirty": False},
        "environment": {"os": "macos", "version": platform.mac_ver()[0], "architecture": platform.machine()},
        "signing": "disposable_ad_hoc_fixture_only",
        "backend_enabled": False,
        "production_claim_allowed": False,
        "native_process_contract_qualified": False,
        "process_deadlines_seconds": {"fixture_compilation": 120, "observation": 15},
        "fixture_parent_scope": "globally_traversable_disposable_tmp",
        "observations": {},
    }
    with tempfile.TemporaryDirectory(prefix="aiagentos-app-sandbox-", dir="/private/tmp") as temporary:
        root = Path(temporary).resolve()
        root.chmod(0o755)
        workspace, outside = root / "workspace", root / "outside"
        workspace.mkdir(mode=0o700)
        outside.mkdir(mode=0o755)
        public = outside / "public.txt"
        private = outside / "private.txt"
        inside = workspace / "inside.txt"
        for path, mode in [(public, 0o644), (private, 0o600), (inside, 0o600)]:
            path.write_text("fixture sentinel\n")
            path.chmod(mode)
        (workspace / "link-public").symlink_to(public)
        (workspace / "link-private").symlink_to(private)
        bundle = root / "SandboxProbe.app"
        executable_directory = bundle / "Contents/MacOS"
        executable_directory.mkdir(parents=True)
        binary = executable_directory / "sandbox-probe"
        (bundle / "Contents/Info.plist").write_bytes(plistlib.dumps({
            "CFBundleIdentifier": "dev.aiagentos.ci.sandboxprobe",
            "CFBundleExecutable": "sandbox-probe",
            "CFBundleName": "SandboxProbe",
            "CFBundlePackageType": "APPL",
            "CFBundleVersion": "1",
            "LSBackgroundOnly": True,
        }))
        # Cold SDK/compiler startup is preparation, separate from an agent's
        # observation deadline. Every sandbox observation retains the 15s cap.
        built = command([
            "/usr/bin/clang", "-std=c11", "-Wall", "-Wextra", "-Werror",
            str(ROOT / "scripts/fixtures/macos_app_sandbox_probe.c"), "-o", str(binary),
        ], timeout=120)
        if built.returncode:
            raise ValueError("probe compilation failed")
        report["unsigned_fixture_sha256"] = hashlib.sha256(binary.read_bytes()).hexdigest()
        baseline = observe(binary, workspace, "read", str(public))
        private_baseline = observe(binary, workspace, "read", str(private))
        if baseline.get("allowed") is not True or private_baseline.get("allowed") is not True:
            raise ValueError("controlled public-file positive baseline failed")
        entitlements = root / "probe.entitlements"
        entitlements.write_bytes(plistlib.dumps({
            "com.apple.security.app-sandbox": True,
            "com.apple.security.temporary-exception.files.absolute-path.read-write": [str(workspace) + "/"],
        }))
        signed = command([
            "/usr/bin/codesign", "--force", "--sign", "-", "--identifier",
            "dev.aiagentos.ci.sandboxprobe", "--entitlements", str(entitlements), str(bundle),
        ])
        if signed.returncode:
            raise ValueError("disposable ad-hoc fixture signing failed")
        verified = command(["/usr/bin/codesign", "--verify", "--strict", str(bundle)])
        if verified.returncode:
            raise ValueError("fixture code signature verification failed")
        report["signed_fixture_sha256"] = hashlib.sha256(binary.read_bytes()).hexdigest()
        identity = observe(binary, workspace, "identity")
        report["observations"]["identity"] = identity
        if identity.get("observed"):
            observed = report["observations"]
            for name, path in [
                ("workspace_read", inside),
                ("outside_public_read", public),
                ("outside_private_read", private),
                ("symlink_public_read", workspace / "link-public"),
                ("symlink_private_read", workspace / "link-private"),
                ("parent_traversal_public_read", workspace / "../outside/public.txt"),
            ]:
                observed[name] = observe(binary, workspace, "read", str(path))
            observed["workspace_write"] = observe(binary, workspace, "write", str(workspace / "created.txt"))
            observed["outside_write"] = observe(binary, workspace, "write", str(outside / "created.txt"))
            observed["runtime_temporary_write"] = observe(binary, workspace, "temporary", str(workspace))
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
                listener.bind(("127.0.0.1", 0))
                listener.listen(1)
                listener.settimeout(0.2)
                observed["network"] = observe(binary, workspace, "network", str(listener.getsockname()[1]))
                try:
                    connection, _ = listener.accept()
                    connection.close()
                    observed["network"]["listener_accepted"] = True
                except TimeoutError:
                    observed["network"]["listener_accepted"] = False
            for operation in ["detach", "exec", "files", "memory", "processes"]:
                observed[operation] = observe(binary, workspace, operation)
            report["observed_controls"] = {
                "workspace_read_write": observed["workspace_read"].get("allowed") is True and observed["workspace_write"].get("allowed") is True,
                "outside_public_read_denied": observed["outside_public_read"].get("allowed") is False,
                "outside_private_read_denied": observed["outside_private_read"].get("allowed") is False,
                "outside_write_denied": observed["outside_write"].get("allowed") is False,
                "outside_workspace_temporary_write_denied": observed["runtime_temporary_write"].get("path_resolved") is True and observed["runtime_temporary_write"].get("inside_workspace") is False and observed["runtime_temporary_write"].get("allowed") is False,
                "network_connection_denied": observed["network"].get("connected") is False and observed["network"].get("listener_accepted") is False and observed["network"].get("errno") in {errno.EPERM, errno.EACCES},
                "process_group_escape_denied": observed["detach"].get("allowed") is False,
                "undeclared_exec_denied": observed["exec"].get("allowed") is False,
                "file_limit_enforced": observed["files"].get("limit_applied") is True and observed["files"].get("errno") == errno.EMFILE,
                "requested_memory_limit_enforced": observed["memory"].get("limit_applied") is True and observed["memory"].get("allocated_above_limit") is False,
                "uid_process_limit_enforced": observed["processes"].get("limit_applied") is True and observed["processes"].get("forked") is False,
            }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parsed = parser.parse_args()
    run(parsed.output)
