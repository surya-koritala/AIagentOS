# Host storage fault qualification

AI Agent OS has deterministic SQLite page-exhaustion coverage and public-path
fault fixtures, but those seams do not prove how the process behaves when the
host filesystem itself returns `ENOSPC`. The host storage qualification closes
that narrower evidence gap on a disposable Linux filesystem.

## Safety contract

This suite is destructive by design. The binary refuses to start unless all of
these conditions hold:

- the operating system is Linux;
- `AGENTOS_DESTRUCTIVE_STORAGE_QUALIFICATION` contains the exact documented
  confirmation value;
- the supplied root is a real directory, not `/` or a symlink;
- the root contains a regular non-symlink
  `.agentos-disposable-storage` marker with the exact schema-v1 value;
- the filesystem is between 32 MiB and 128 MiB; and
- the report destination resolves outside the disposable filesystem.

The GitHub workflow creates a fresh 96 MiB ext4 image in the runner temporary
directory, mounts it with `nosuid,nodev,noexec`, marks it, runs the qualification
as the unprivileged runner user, and unmounts it on every exit path. Never point
the binary at a data volume, workspace, home directory, or production mount.

## Proof sequence

The release-mode binary:

1. creates a fresh file-backed `SqliteContextManager`;
2. writes and checkpoints a baseline KV commit;
3. writes and synchronizes a filler file until the host returns real
   `ENOSPC`;
4. attempts a one-MiB SQLite mutation and requires a disk-full failure;
5. removes the filler, verifies the baseline and absence of the failed value,
   and retries successfully;
6. checkpoints, runs SQLite `quick_check`, reopens the normal context manager,
   and verifies exactly the baseline and recovered commits; and
7. writes a bounded schema-v1 JSON report outside the disposable filesystem.

The workflow binds checkout and report source to the exact pull-request head or
push commit. It requires a clean source tree, release build, Linux x86_64,
bounded filesystem size, observed host `ENOSPC`, every check true, and
`production_claim_allowed: false`. The retained artifact expires after 90
days.

## Run the contract validator

The non-destructive validator is portable:

```bash
cargo run --release --locked --package os-benchmark \
  --bin host-storage-qualification -- --validate
```

The destructive path is intentionally owned by
`.github/workflows/host-storage-fault-qualification.yml`; local execution
requires constructing and confirming an equivalent disposable filesystem.

## Evidence boundary

Passing evidence proves one small ext4-hosted Linux `ENOSPC` transaction,
capacity restoration, integrity check, and reopen path. It does not prove:

- power loss, torn writes, kernel/device loss, or arbitrary media corruption;
- remote/object-store failure or immutable retention;
- behavior on every supported deployment filesystem;
- measured RPO/RTO or recovery-operator performance; or
- whole-product production readiness.

Those claims remain open under issue #123 and require target-environment and
independent recovery qualification.
