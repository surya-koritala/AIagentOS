# Restricted Linux CLI release candidate

The restricted release candidate is the first public installation profile that
is qualified from its final downloadable binaries. It supports one
**Ubuntu 22.04 x86_64** host, one `agent-server`, and the first-party CLI/TUI.
It is a governed agent runtime on Linux, not a replacement for the Linux
kernel.

This profile is deliberately narrower than the eventual v1.0 promise. Its
Phase 1 decision promotes only the exact provider/model set named in that
report; desktop clients, peripherals, and the distributed control plane remain
outside the restricted promise. The signed qualification reports included in
the release keep those limitations machine-readable.

## What the release gate proves

An exact `vX.Y.Z-rc.N` tag first produces a retained signed candidate only
after:

1. full release-blocking CI and the governed-execution acceptance test pass;
2. `agent`, `agent-server`, `agentctl`, and `agent-tui` build twice with
   byte-for-byte identical output;
3. the deterministic archive and exact-binary SBOM receive keyless Sigstore
   signatures and GitHub build provenance;
4. a fresh Ubuntu 22.04 runner verifies that supply-chain evidence before
   executing the archive;
5. the released v0.3.0 database fixture upgrades and is encrypted in place;
6. the server starts with verified TLS, shared-secret authentication, required
   SQLCipher storage, and signed backups;
7. unauthenticated and wrong-token clients are rejected;
8. a governed agent survives a clean server restart;
9. an encrypted signed backup is independently anchored and verified, while a
   tampered copy and a recovery attempt without the storage key fail closed;
10. the backup restores onto a distinct empty host directory, the configured
    kernel re-arms enforcement, and both the upgraded and newly created agents
    remain visible after the recovered server starts.

The tag workflow signs and attests the bounded runtime report but does **not**
publish a GitHub release. The separate protected Phase 1 gate then requires
the exact same RC/commit to have eligible live-provider, real GGUF, target
remote-backup, destructive-storage, external-deletion, 24-hour soak,
release-SLO, and human game-day reports. One independent review must bind the
exact campaign and workflow provenance. Only that gate re-signs and attests the
complete bundle and publishes it as a GitHub **prerelease**. See
[Restricted Phase 1 promotion qualification](PHASE1_PROMOTION_QUALIFICATION.md).
Missing or mixed evidence prevents publication.

## Download and verify

Install `gh`, `cosign`, `sha256sum`, and `unzip`, then set the exact tag:

```bash
export AGENTOS_RC=vX.Y.Z-rc.N
mkdir "agentos-${AGENTOS_RC}"
cd "agentos-${AGENTOS_RC}"
gh release download "$AGENTOS_RC" \
  --repo surya-koritala/AIagentOS
sha256sum --check SHA256SUMS
```

Verify the final archive against the exact Phase 1 publication workflow
identity:

```bash
identity="https://github.com/surya-koritala/AIagentOS/.github/workflows/phase1-promotion-qualification.yml@refs/tags/${AGENTOS_RC}"
archive="agentos-${AGENTOS_RC}-x86_64-unknown-linux-gnu.zip"
for asset in \
  "$archive" \
  linux-cli-rc-qualification.json \
  phase1-campaign-provenance.json \
  phase1-workflow-provenance.json \
  phase1-review-provenance.json \
  phase1-promotion.json \
  SHA256SUMS; do
  cosign verify-blob \
    --bundle "${asset}.sigstore.json" \
    --certificate-identity "$identity" \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    "$asset"
  gh attestation verify "$asset" \
    --repo surya-koritala/AIagentOS \
    --signer-workflow surya-koritala/AIagentOS/.github/workflows/phase1-promotion-qualification.yml \
    --source-ref "refs/tags/${AGENTOS_RC}" \
    --cert-identity "$identity" \
    --deny-self-hosted-runners
done
```

Inspect all five reports before trusting the candidate:

```bash
jq '{
  release_candidate,
  source,
  artifact,
  platform,
  supply_chain,
  upgrade,
  runtime,
  durability,
  production_claim_allowed,
  limitations
}' linux-cli-rc-qualification.json
jq '{
  release_candidate,
  source,
  profile,
  promoted_providers,
  evidence,
  review,
  phase1_release_candidate_ready,
  production_claim_allowed,
  eligibility_blockers
}' phase1-promotion.json
jq '{
  repository,
  release_candidate,
  source,
  campaign_workflow,
  github_campaign_workflow_provenance_verified,
  github_campaign_artifact_bytes_verified,
  keyless_campaign_signature_verified,
  production_claim_allowed
}' phase1-campaign-provenance.json
jq '{
  repository,
  release_candidate,
  source,
  run_count,
  artifact_count,
  github_workflow_provenance_verified,
  github_artifact_bytes_verified,
  production_claim_allowed
}' phase1-workflow-provenance.json
jq '{
  repository,
  release_candidate,
  source,
  review_workflow,
  reviewer_identity_authenticated,
  github_review_workflow_provenance_verified,
  github_review_artifact_bytes_verified,
  keyless_review_signature_verified,
  production_claim_allowed
}' phase1-review-provenance.json
```

The restricted decision must set `phase1_release_candidate_ready` to `true`.
The campaign provenance report must set its workflow, artifact-byte, and
keyless-signature verification booleans to `true`, and its SHA-256 must match
`phase1-promotion.json.evidence.campaign_provenance_sha256`.
The GitHub provenance report must set both verification booleans to `true`,
and its SHA-256 must match
`phase1-promotion.json.evidence.workflow_provenance_sha256`.
The independent-review provenance report must set its identity, workflow,
artifact-byte, and keyless-signature verification booleans to `true`, and its
SHA-256 must match
`phase1-promotion.json.evidence.independent_review_provenance_sha256`.
`production_claim_allowed` remains `false` until the client, peripheral,
distributed-control-plane, independent-security, and final v1 governance gates
are satisfied.

## Install

Install without overwriting an existing binary:

```bash
install_root="$HOME/.local/lib/agentos/${AGENTOS_RC}"
mkdir -p "$install_root" "$HOME/.local/bin"
unzip "$archive" -d "$install_root"
for binary in agent agent-server agentctl agent-tui; do
  test ! -e "$HOME/.local/bin/$binary"
  ln -s "$install_root/$binary" "$HOME/.local/bin/$binary"
done
```

For an upgrade, retain the old version directory and atomically replace each
symlink only after the new candidate has been verified. This provides a binary
rollback path; never roll a migrated database back to an older reader unless
that release's compatibility statement explicitly permits it.

## Secure first boot

Use separate private directories for live data, backups, and key custody. The
storage key and backup signing key are intentionally absent from backups.

```bash
install -d -m 0700 "$HOME/.local/share/agentos" \
  "$HOME/.local/share/agentos/backups" \
  "$HOME/.config/agentos" \
  "$HOME/.config/agentos/keys"
agentctl storage-key-generate rc-storage-1 \
  "$HOME/.config/agentos/keys/storage.json"
agentctl backup-key-generate rc-backup-1 \
  "$HOME/.config/agentos/keys/backup.pk8" \
  "$HOME/.config/agentos/keys/backup-trust.json"
```

Create a CA and a localhost certificate whose private keys remain owner-only:

```bash
tls="$HOME/.config/agentos/keys"
openssl req -x509 -newkey rsa:3072 -nodes -sha256 -days 365 \
  -subj "/CN=AIagentOS local CA" \
  -keyout "$tls/ca.key" -out "$tls/ca.pem"
openssl req -newkey rsa:3072 -nodes -sha256 -subj "/CN=localhost" \
  -keyout "$tls/server.key" -out "$tls/server.csr"
printf '%s\n' \
  'subjectAltName=DNS:localhost,IP:127.0.0.1' \
  'extendedKeyUsage=serverAuth' \
  'keyUsage=digitalSignature,keyEncipherment' > "$tls/server.ext"
openssl x509 -req -in "$tls/server.csr" \
  -CA "$tls/ca.pem" -CAkey "$tls/ca.key" -CAcreateserial \
  -days 90 -sha256 -extfile "$tls/server.ext" -out "$tls/server.pem"
chmod 0600 "$tls/ca.key" "$tls/server.key"
```

Create `$HOME/.config/agentos/config.toml` using absolute paths:

```toml
llm_provider = "local"
default_model = "not-qualified"
data_dir = "/home/USER/.local/share/agentos"
setup_complete = true
permission_profile = "standard"

[api_keys]
local = "http://127.0.0.1:11434"

[backup]
enabled = true
root = "/home/USER/.local/share/agentos/backups"
interval_seconds = 3600
run_on_start = true
keep_latest = 24
max_age_seconds = 604800
signing_key_path = "/home/USER/.config/agentos/keys/backup.pk8"
signing_key_id = "rc-backup-1"

[storage_encryption]
required = true
key_path = "/home/USER/.config/agentos/keys/storage.json"
```

Generate a random token, retain it in a secret manager or owner-only runtime
file, and start the server:

```bash
export AGENT_SERVER_CONFIG="$HOME/.config/agentos/config.toml"
export AGENT_SERVER_TOKEN="$(openssl rand -base64 32)"
export AGENT_SERVER_TLS_CERT="$tls/server.pem"
export AGENT_SERVER_TLS_KEY="$tls/server.key"
agent-server 127.0.0.1:7777
```

In the operator shell, load the same token without printing it and configure
the verified client profile:

```bash
export AGENTOS_ADDR=127.0.0.1:7777
export AGENTOS_TLS_CA="$HOME/.config/agentos/keys/ca.pem"
export AGENTOS_TLS_SERVER_NAME=localhost
agentctl protocol
agentctl create first-agent "verify governed operation" stub standard 3
agentctl list
agentctl gate-stats
```

## Backup and fresh-host recovery

Create and authenticate a recovery point:

```bash
backup_root="$HOME/.local/share/agentos/backups"
agentctl backup-create "$backup_root" before-upgrade
agentctl backup-anchor-create \
  "$backup_root/before-upgrade" \
  "$HOME/.config/agentos/keys/backup-trust.json" \
  "$HOME/.config/agentos/keys/before-upgrade.anchor.json" \
  --storage-key "$HOME/.config/agentos/keys/storage.json"
agentctl backup-verify \
  "$backup_root/before-upgrade" \
  --storage-key "$HOME/.config/agentos/keys/storage.json" \
  --require-signature "$HOME/.config/agentos/keys/backup-trust.json" \
  --require-anchor "$HOME/.config/agentos/keys/before-upgrade.anchor.json"
```

Copy the backup, public trust root, anchor, and storage key through independent
protected channels. On a stopped fresh host, create a config that names an
empty absolute `data_dir`, then run:

```bash
agentctl backup-disaster-recover \
  /recovery/backups/before-upgrade \
  /recovery/config.toml \
  /recovery/backup-trust.json \
  /recovery/before-upgrade.anchor.json \
  --confirm-offline
```

Accept recovery only when the JSON report says
`"enforcement_rearmed": true`. Start the recovered server with the fresh-host
config and verify `agentctl list` plus `agentctl gate-stats`.

Local backups remain in the same host failure domain. They do not satisfy the
remote immutable-backup or measured RPO/RTO requirements in issue #123.
