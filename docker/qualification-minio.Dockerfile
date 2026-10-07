# Disposable CI fixtures built from exact upstream sources. These images are
# qualification infrastructure, not AI Agent OS release artifacts.
FROM golang:1.27.1-bookworm@sha256:8d48e12ec56735e9358640898b9d9b9fcca110612ed8a5567438c0a1baa24e66 AS builder
ARG MINIO_SOURCE_COMMIT
ARG MC_SOURCE_COMMIT
ENV CGO_ENABLED=0 GOTOOLCHAIN=local
RUN test "${#MINIO_SOURCE_COMMIT}" = 40 \
    && test "${#MC_SOURCE_COMMIT}" = 40 \
    && GOBIN=/out/server go install github.com/minio/minio@${MINIO_SOURCE_COMMIT} \
    && GOBIN=/out/client go install github.com/minio/mc@${MC_SOURCE_COMMIT}

FROM debian:bookworm-20260918-slim@sha256:3783cc01769c7b2b1b83a5c5ad96c815348e28ed7da68e2e3687004faa906251 AS runtime
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

FROM runtime AS minio-server
COPY --from=builder /out/server/minio /usr/local/bin/minio
ENTRYPOINT ["/usr/local/bin/minio"]

FROM runtime AS minio-client
COPY --from=builder /out/client/mc /usr/local/bin/mc
ENTRYPOINT ["/usr/local/bin/mc"]
