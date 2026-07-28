#!/usr/bin/env bash
# Reproduce the deterministic, host-compatible release gates from a clean checkout.
# Cross-platform matrices, GitHub action/issue-state checks, Sigstore,
# provenance, and container qualification remain GitHub-hosted gates.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

cargo fmt --all -- --check
python3 scripts/verify_workflow_action_pins.py
cargo clippy --workspace --exclude tauri-app --all-targets --locked -- -D warnings
cargo test -p integration-tests capability_registry --locked
python3 -m unittest discover -s scripts/tests -p "test_*.py"
scripts/run_promtool_tests.sh
cargo test --workspace --exclude tauri-app --doc --locked
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --exclude tauri-app --no-deps --locked
mdbook build docs
cargo build --workspace --exclude tauri-app --all-features --locked
cargo test --workspace --exclude tauri-app --locked
cargo deny check advisories bans licenses sources

(
  cd crates/tauri-app/ui
  npm ci
  npm audit --audit-level=high
  npm run check
  npm test
  npx playwright install chromium
  npm run test:a11y
)

cargo clippy -p tauri-app --all-targets --locked -- -D warnings
cargo llvm-cov --workspace --exclude tauri-app --all-targets --locked \
  --lcov --output-path lcov.info --fail-under-lines 60 -- --test-threads=1
python3 scripts/check_critical_coverage.py lcov.info
