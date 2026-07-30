#!/usr/bin/env python3
"""Build the canonical deterministic AI Agent OS CLI release archive."""

from __future__ import annotations

import argparse
import os
import stat
import sys
import zipfile
from pathlib import Path


BINARIES = ("agent", "agent-server", "agent-tui", "agentctl")
MAX_BINARY_BYTES = 256 * 1024 * 1024


class ArchiveBuildError(ValueError):
    """The requested archive would violate the release contract."""


def _read_executable(path: Path) -> bytes:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise ArchiveBuildError(f"cannot inspect release binary {path.name}: {error}") from error
    if not stat.S_ISREG(metadata.st_mode):
        raise ArchiveBuildError(f"release binary {path.name} must be a regular non-symlink file")
    if metadata.st_size <= 0 or metadata.st_size > MAX_BINARY_BYTES:
        raise ArchiveBuildError(
            f"release binary {path.name} must contain 1..{MAX_BINARY_BYTES} bytes"
        )
    if metadata.st_mode & 0o111 == 0:
        raise ArchiveBuildError(f"release binary {path.name} must be executable")
    try:
        return path.read_bytes()
    except OSError as error:
        raise ArchiveBuildError(f"cannot read release binary {path.name}: {error}") from error


def build_archive(source: Path, output: Path) -> None:
    """Create one byte-stable zip with exactly the supported CLI binaries."""

    try:
        source_metadata = source.lstat()
    except OSError as error:
        raise ArchiveBuildError(f"cannot inspect source directory: {error}") from error
    if not stat.S_ISDIR(source_metadata.st_mode):
        raise ArchiveBuildError("source must be a real directory, not a symlink")
    try:
        output.parent.mkdir(parents=True, exist_ok=True)
        if output.exists() or output.is_symlink():
            raise ArchiveBuildError("output archive already exists")
    except OSError as error:
        raise ArchiveBuildError(f"cannot prepare output directory: {error}") from error

    payloads = {name: _read_executable(source / name) for name in BINARIES}
    try:
        with zipfile.ZipFile(
            output,
            mode="x",
            compression=zipfile.ZIP_DEFLATED,
            compresslevel=9,
        ) as archive:
            for name in sorted(payloads):
                info = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
                info.create_system = 3
                info.external_attr = (stat.S_IFREG | 0o755) << 16
                info.compress_type = zipfile.ZIP_DEFLATED
                archive.writestr(info, payloads[name])
    except (OSError, zipfile.BadZipFile) as error:
        try:
            output.unlink()
        except OSError:
            pass
        raise ArchiveBuildError(f"failed to create deterministic archive: {error}") from error


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        build_archive(args.source.resolve(), args.output.absolute())
    except ArchiveBuildError as error:
        print(f"CLI archive build failed: {error}", file=sys.stderr)
        return 1
    print(f"created deterministic CLI archive {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
