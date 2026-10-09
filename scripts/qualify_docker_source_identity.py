#!/usr/bin/env python3
"""CI-only actual Docker keyless boot and native/source metric comparison."""

import argparse
import json
import re
from pathlib import Path
import subprocess
import time
import uuid


def command(*args, timeout=30):
    return subprocess.run(args, check=True, capture_output=True, text=True, timeout=timeout).stdout.strip()


def identity(text):
    parts = {}
    verified = None
    for line in text.splitlines():
        if line.startswith('agentos_build_source_sha1{part="'):
            label, value = line.rsplit(" ", 1)
            part = int(label.split('part="', 1)[1].split('"', 1)[0])
            if part in parts or not 0 <= part < 5:
                raise ValueError("duplicate/unknown source identity part")
            integer = int(value)
            if not 0 <= integer <= 0xFFFFFFFF:
                raise ValueError("source identity segment is outside its bound")
            parts[part] = integer
        elif line.startswith("agentos_build_source_verified "):
            if verified is not None:
                raise ValueError("duplicate source verification sample")
            verified = int(line.rsplit(" ", 1)[1])
    if set(parts) != set(range(5)) or verified != 1:
        raise ValueError("runtime source is missing or unverified")
    return "".join(f"{parts[part]:08x}" for part in range(5))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image-id-file", required=True, type=Path)
    parser.add_argument("--native-metrics", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    arguments = parser.parse_args()
    image = arguments.image_id_file.read_text().strip()
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", image):
        raise ValueError("image id file must contain an exact Docker SHA-256 image id")
    expected = identity(arguments.native_metrics.read_text())
    command("docker", "run", "--rm", "--network=none", image)
    command("docker", "run", "--rm", "--network=none", "--entrypoint", "/bin/sh", image,
            "-c", "test ! -e /build && test ! -e /.git && test ! -e /root/.gitconfig && ! command -v git")
    name = "source-proof-" + uuid.uuid4().hex
    try:
        command("docker", "run", "-d", "--name", name,
                "--network=none", "-e", "AGENT_SERVER_METRICS_ADDR=127.0.0.1:9101",
                "-e", "AGENTOS_MODEL=source-proof-ci-fixture",
                "-e", "OLLAMA_BASE_URL=http://127.0.0.1:9", image, "agent-server", "127.0.0.1:7777")
        deadline = time.monotonic() + 30
        while True:
            if time.monotonic() >= deadline:
                raise RuntimeError("actual image did not expose wire and metrics before bounded deadline")
            try:
                node_text = command("docker", "exec", name, "/bin/sh", "-c",
                    "printf '{\"op\":\"node_info\"}\\n' | timeout 2 nc -w2 -q1 127.0.0.1 7777",
                    timeout=min(3, max(0.1, deadline-time.monotonic())))
                node = json.loads(node_text)
                if not isinstance(node, dict) or node.get("status") != "node_info":
                    raise ValueError("running image did not return actual NodeInfo")
                for field in ("agent_count", "running_agents", "live_agents"):
                    if type(node.get(field)) is not int or node[field] < 0:
                        raise ValueError("actual NodeInfo omitted bounded node state")
                response = command("docker", "exec", name, "/bin/sh", "-c",
                    "printf 'GET /metrics HTTP/1.1\\r\\nHost: localhost\\r\\nConnection: close\\r\\n\\r\\n' | timeout 2 nc -w2 -q1 127.0.0.1 9101",
                    timeout=min(3, max(0.1, deadline-time.monotonic())))
                header, text = response.replace("\r\n", "\n").split("\n\n", 1)
                if not header.startswith("HTTP/1.1 200 "):
                    raise ValueError("running image metric endpoint did not return200")
                if len(text.encode()) > 1024 * 1024:
                    raise ValueError("actual image metric output exceeds bound")
                break
            except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired, json.JSONDecodeError):
                if time.monotonic() >= deadline:
                    raise RuntimeError("actual image did not expose metrics before bounded deadline")
                time.sleep(0.1)
        arguments.output.parent.mkdir(parents=True, exist_ok=True)
        arguments.output.with_suffix(".prom").write_text(text)
        arguments.output.with_suffix(".node.json").write_text(json.dumps(node, sort_keys=True, indent=2) + "\n")
        actual = identity(text)
        if actual != expected:
            raise ValueError("actual image source identity differs from native compiled source")
        arguments.output.write_text(json.dumps({
            "schema_version": 1, "source_commit": actual,
            "image_id": image, "native_and_image_identity_equal": True,
            "keyless_boot": True, "production_qualification": False,
            "node_info_received": True,
        }, sort_keys=True, indent=2) + "\n")
    finally:
        subprocess.run(["docker", "logs", name], capture_output=False, timeout=10, check=False)
        subprocess.run(["docker", "rm", "-f", "-v", name], capture_output=True, timeout=10, check=False)


if __name__ == "__main__":
    main()
