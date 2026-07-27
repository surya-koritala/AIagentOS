#!/usr/bin/env bash
set -euo pipefail

readonly PROMETHEUS_VERSION="3.13.1"
readonly REPOSITORY_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

platform="$(uname -s | tr '[:upper:]' '[:lower:]')"
machine="$(uname -m)"
case "${machine}" in
  x86_64) architecture="amd64" ;;
  arm64 | aarch64) architecture="arm64" ;;
  *)
    echo "unsupported promtool architecture: ${machine}" >&2
    exit 2
    ;;
esac

case "${platform}-${architecture}" in
  linux-amd64)
    expected_sha256="962b812371aff838d152b6ff2d56fdb7a6396f5542f48ebf73421b9721f0d103"
    ;;
  linux-arm64)
    expected_sha256="fbd8e5e0f6ad2e7d053e717739186caee4fd0cab2cf9335bfc86c292fe2a2bfe"
    ;;
  darwin-amd64)
    expected_sha256="bc6cef4bdbeb3d0974ac161684dd2a0c4d4e341a13a4a634917b1c09d0f33fc5"
    ;;
  darwin-arm64)
    expected_sha256="28d1f1224b2a22f84c801487fad4b3bd58f94a8cb58cf9340557e787030c9703"
    ;;
  *)
    echo "unsupported promtool platform: ${platform}-${architecture}" >&2
    exit 2
    ;;
esac

archive_name="prometheus-${PROMETHEUS_VERSION}.${platform}-${architecture}.tar.gz"
download_url="https://github.com/prometheus/prometheus/releases/download/v${PROMETHEUS_VERSION}/${archive_name}"
temporary_directory="$(mktemp -d "${TMPDIR:-/tmp}/agentos-promtool.XXXXXX")"
trap 'rm -rf "${temporary_directory}"' EXIT

curl --fail --location --silent --show-error --retry 3 \
  "${download_url}" --output "${temporary_directory}/${archive_name}"

actual_sha256="$(shasum -a 256 "${temporary_directory}/${archive_name}" | awk '{print $1}')"
if [[ "${actual_sha256}" != "${expected_sha256}" ]]; then
  echo "promtool archive checksum mismatch" >&2
  exit 1
fi

tar -xzf "${temporary_directory}/${archive_name}" -C "${temporary_directory}"
promtool="${temporary_directory}/prometheus-${PROMETHEUS_VERSION}.${platform}-${architecture}/promtool"

"${promtool}" check rules "${REPOSITORY_ROOT}/observability/prometheus-rules.yml"
(
  cd "${REPOSITORY_ROOT}/observability"
  "${promtool}" test rules prometheus-rule-tests.yml
)
