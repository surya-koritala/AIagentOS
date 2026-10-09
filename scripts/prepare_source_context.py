#!/usr/bin/env python3
"""Prepare an object-bound Docker source context from a clean Git commit."""

import argparse
import hashlib
import json
import stat
from pathlib import Path
import subprocess

PROOF_FILE = ".agentos-source-proof.json"
MAX_PROOF_BYTES = 4 * 1024 * 1024
MAX_SOURCE_BYTES = 128 * 1024 * 1024
MAX_FILES = 8192
MAX_TREES = 2048


def git(repository, *arguments):
    return subprocess.run(
        ["git", "-C", str(repository), *arguments], check=True, capture_output=True
    ).stdout


def object_hash(kind, data):
    return hashlib.sha1(f"{kind} {len(data)}\0".encode() + data).hexdigest()


def safe_component(name):
    folded = name.lower()
    return (
        bool(name) and len(name.encode()) <= 255
        and folded not in {
            ".", "..", ".git", ".ssh", ".aws", ".azure", ".gcloud", ".kube",
            ".docker", ".config", ".gnupg", ".codex", ".netrc", ".git-credentials",
            ".npmrc", ".pypirc", ".env", "credentials", "credentials.toml", "credentials.json",
            PROOF_FILE, "target", "node_modules",
        }
        and not any(character in name for character in "/\\\0\r\n")
        and (not folded.startswith(".env.") or folded == ".env.example")
        and not credential_file(folded)
        and not folded.endswith((".pk8", ".p12", ".pfx", ".key"))
    )

def credential_file(name):
    base = name.replace("-", "_")
    for extension in (".json", ".txt", ".toml", ".yaml", ".yml"):
        if base.endswith(extension):
            base = base.removesuffix(extension)
            break
    return base in {"api_key", "api_keys", "token", "tokens", "access_token", "refresh_token"}


def prepare(repository, output):
    repository = Path(git(repository, "rev-parse", "--show-toplevel").decode().strip()).resolve()
    output = output.absolute()
    for ancestor in (output, *output.parents):
        if ancestor.is_symlink():
            raise ValueError("source context output rejects symlink ancestors")
        if ancestor.exists() and getattr(ancestor.lstat(), "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0):
            raise ValueError("source context output rejects reparse ancestors")
    output = output.resolve(strict=False)
    if output.exists():
        raise ValueError("source context destination must not already exist")
    if repository == output or repository in output.parents:
        raise ValueError("source context must be outside the checkout")
    if git(repository, "rev-parse", "--show-object-format").strip() != b"sha1":
        raise ValueError("source proof requires Git SHA-1 object format")
    if git(repository, "status", "--porcelain=v1", "--untracked-files=no").strip():
        raise ValueError("tracked source must be clean before context generation")
    commit = git(repository, "rev-parse", "HEAD").decode().strip()
    commit_body = git(repository, "cat-file", "commit", commit)
    if len(commit_body) > 64 * 1024 or object_hash("commit", commit_body) != commit:
        raise ValueError("declared commit does not match its bounded Git object")
    tree = commit_body.split(b"\n", 1)[0].removeprefix(b"tree ").decode()
    trees = {}
    files = []
    total = 0

    def walk(oid, relative, depth=0):
        nonlocal total
        if depth > 64 or len(trees) >= MAX_TREES:
            raise ValueError("source tree inventory exceeds bounds")
        body = git(repository, "cat-file", "tree", oid)
        if len(body) > 1024 * 1024 or object_hash("tree", body) != oid:
            raise ValueError("source tree does not match its Git object")
        trees[oid] = body.hex()
        position = 0
        names = set()
        while position < len(body):
            end = body.index(b"\0", position)
            mode, name = body[position:end].decode().split(" ", 1)
            position = end + 1
            child_oid = body[position:position+20].hex()
            position += 20
            if len(child_oid) != 40 or not safe_component(name) or name in names:
                raise ValueError("source tree contains an unsafe or duplicated path")
            names.add(name)
            path = relative / name
            if mode == "40000":
                walk(child_oid, path, depth+1)
            elif mode in {"100644", "100755"}:
                data = git(repository, "cat-file", "blob", child_oid)
                total += len(data)
                if object_hash("blob", data) != child_oid or total > MAX_SOURCE_BYTES or len(files) >= MAX_FILES:
                    raise ValueError("source blob or byte inventory exceeds bounds")
                files.append((path, data, mode))
            else:
                raise ValueError("source proof refuses symlinks/submodules/unsupported modes")

    walk(tree, Path())
    proof = {"version": 1, "commit": commit, "commit_hex": commit_body.hex(), "trees": trees}
    encoded = (json.dumps(proof, sort_keys=True, separators=(",", ":")) + "\n").encode()
    if len(encoded) > MAX_PROOF_BYTES:
        raise ValueError("source proof exceeds metadata bound")
    # Freeze the declared object set across generation; never copy arbitrary
    # checkout files, .git configuration, untracked tokens or build artifacts.
    if git(repository, "rev-parse", "HEAD").decode().strip() != commit or git(
        repository, "status", "--porcelain=v1", "--untracked-files=no"
    ).strip():
        raise ValueError("source changed during context generation")
    output.mkdir(parents=True)
    for relative, data, mode in files:
        target = output / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        target.chmod(0o755 if mode == "100755" else 0o644)
    (output / PROOF_FILE).write_bytes(encoded)
    return {"commit": commit, "files": len(files), "source_bytes": total, "proof_bytes": len(encoded)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, default=Path.cwd())
    parser.add_argument("--output", required=True, type=Path)
    arguments = parser.parse_args()
    print(json.dumps(prepare(arguments.repository, arguments.output), sort_keys=True))


if __name__ == "__main__":
    main()
