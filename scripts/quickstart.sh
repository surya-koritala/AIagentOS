#!/bin/sh
# AI Agent OS — one-command bootstrap of the wire server.
#
# Builds the image, starts the `agentos-server` service (the kernel exposing the
# JSON syscall protocol on tcp://localhost:7777), waits for it to become healthy
# (the healthcheck sends a real `node_info` syscall), then does its own
# round-trip and prints the reply.
#
# Usage:
#   ./scripts/quickstart.sh
#
# Boots keyless (provider `local`): comes up with NO API keys and WITHOUT Ollama
# for the enforcement / non-LLM syscalls.
set -eu

PORT="${AGENTOS_SERVER_PORT:-7777}"
SERVICE="agentos-server"

# docker compose (v2) vs legacy docker-compose.
if docker compose version >/dev/null 2>&1; then
    DC="docker compose"
elif command -v docker-compose >/dev/null 2>&1; then
    DC="docker-compose"
else
    echo "error: neither 'docker compose' nor 'docker-compose' is available" >&2
    exit 1
fi

echo "==> Building + starting the $SERVICE service..."
$DC up -d --build "$SERVICE"

echo "==> Waiting for $SERVICE to become healthy..."
cid="$($DC ps -q "$SERVICE")"
if [ -z "$cid" ]; then
    echo "error: could not resolve container id for $SERVICE" >&2
    exit 1
fi

i=0
while true; do
    status="$(docker inspect -f '{{.State.Health.Status}}' "$cid" 2>/dev/null || echo unknown)"
    case "$status" in
        healthy)
            break
            ;;
        unhealthy)
            echo "error: $SERVICE went unhealthy. Recent logs:" >&2
            $DC logs --tail 30 "$SERVICE" >&2 || true
            exit 1
            ;;
    esac
    i=$((i + 1))
    if [ "$i" -gt 60 ]; then
        echo "error: timed out waiting for $SERVICE to become healthy (last: $status)" >&2
        $DC logs --tail 30 "$SERVICE" >&2 || true
        exit 1
    fi
    sleep 2
done

echo "==> Server healthy. Sending a real NodeInfo syscall to localhost:$PORT ..."
# The Syscall enum is internally tagged (#[serde(tag = "op")]); the unit variant
# NodeInfo serializes to {"op":"node_info"}. The reply is tagged with "status".
reply=""
if command -v nc >/dev/null 2>&1; then
    reply="$(printf '{"op":"node_info"}\n' | nc -w2 127.0.0.1 "$PORT" | head -1 || true)"
fi
# Fallback to bash /dev/tcp if nc is unavailable on the host.
if [ -z "$reply" ] && [ -n "${BASH_VERSION:-}" ]; then
    reply="$(bash -c "exec 3<>/dev/tcp/127.0.0.1/$PORT; printf '{\"op\":\"node_info\"}\n' >&3; head -1 <&3" || true)"
fi

if [ -z "$reply" ]; then
    echo "warning: could not read a reply from the host (no nc / bash tcp);" >&2
    echo "         the container healthcheck already confirmed it answers." >&2
else
    echo "NodeInfo reply: $reply"
fi

echo
echo "server is up on tcp://localhost:$PORT — connect with the SDK/CLI"
