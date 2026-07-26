#!/bin/sh
# AI Agent OS container entrypoint.
#
# The CLI reads its provider/model/URL ONLY from config.toml (there is no env
# var that selects the provider, and the Ollama base URL is stored in the
# api_keys."local" field of the TOML). So before running any command we render
# a config.toml from environment variables into XDG_CONFIG_HOME.
#
# Env vars consumed here (set sensible defaults in the Dockerfile / compose):
#   AGENTOS_LLM_PROVIDER  -> config.llm_provider   (default: local)
#   AGENTOS_MODEL         -> config.default_model  (default: llama3.2)
#   OLLAMA_BASE_URL       -> api_keys."local"      (the Ollama URL field)
#   AGENTOS_BACKUP_*      -> config.backup          (disabled by default)
#
# Cloud-provider keys (AZURE_OPENAI_API_KEY / OPENAI_API_KEY /
# ANTHROPIC_API_KEY and friends) are read directly from the process
# environment by the CLI, so they are simply inherited — no TOML needed.
set -eu

: "${XDG_CONFIG_HOME:=$HOME/.config}"
: "${XDG_DATA_HOME:=$HOME/.local/share}"
: "${AGENTOS_LLM_PROVIDER:=local}"
: "${AGENTOS_MODEL:=llama3.2}"
: "${OLLAMA_BASE_URL:=http://localhost:11434}"
: "${AGENTOS_BACKUP_ENABLED:=false}"
: "${AGENTOS_BACKUP_ROOT:=/backups}"
: "${AGENTOS_BACKUP_INTERVAL_SECONDS:=3600}"
: "${AGENTOS_BACKUP_RUN_ON_START:=true}"
: "${AGENTOS_BACKUP_KEEP_LATEST:=24}"
: "${AGENTOS_BACKUP_MAX_AGE_SECONDS:=604800}"

case "$AGENTOS_BACKUP_ENABLED" in
    1|true|yes) BACKUP_ENABLED=true ;;
    0|false|no) BACKUP_ENABLED=false ;;
    *)
        echo "error: AGENTOS_BACKUP_ENABLED must be true or false" >&2
        exit 1
        ;;
esac
case "$AGENTOS_BACKUP_RUN_ON_START" in
    1|true|yes) BACKUP_RUN_ON_START=true ;;
    0|false|no) BACKUP_RUN_ON_START=false ;;
    *)
        echo "error: AGENTOS_BACKUP_RUN_ON_START must be true or false" >&2
        exit 1
        ;;
esac
case "$AGENTOS_BACKUP_ROOT" in
    /*) ;;
    *)
        echo "error: AGENTOS_BACKUP_ROOT must be an absolute path" >&2
        exit 1
        ;;
esac
case "$AGENTOS_BACKUP_ROOT" in
    *[!A-Za-z0-9._/-]*)
        echo "error: AGENTOS_BACKUP_ROOT contains unsupported characters" >&2
        exit 1
        ;;
esac
for value in \
    "$AGENTOS_BACKUP_INTERVAL_SECONDS" \
    "$AGENTOS_BACKUP_KEEP_LATEST" \
    "$AGENTOS_BACKUP_MAX_AGE_SECONDS"
do
    case "$value" in
        ''|*[!0-9]*)
            echo "error: scheduled-backup numeric settings must contain only digits" >&2
            exit 1
            ;;
    esac
done
if [ "$BACKUP_ENABLED" = true ]; then
    if [ -L "$AGENTOS_BACKUP_ROOT" ]; then
        echo "error: AGENTOS_BACKUP_ROOT must not be a symlink" >&2
        exit 1
    fi
    mkdir -p "$AGENTOS_BACKUP_ROOT"
    if [ ! -d "$AGENTOS_BACKUP_ROOT" ] || [ ! -w "$AGENTOS_BACKUP_ROOT" ]; then
        echo "error: AGENTOS_BACKUP_ROOT must be a writable directory" >&2
        exit 1
    fi
fi

CONFIG_DIR="$XDG_CONFIG_HOME/ai-agent-os"
DATA_DIR="$XDG_DATA_HOME/ai-agent-os"
CONFIG_FILE="$CONFIG_DIR/config.toml"

mkdir -p "$CONFIG_DIR" "$DATA_DIR"

# Render config.toml. For the keyless path AGENTOS_LLM_PROVIDER=local makes the
# CLI register the Ollama adapter (the only provider with no key gate); the URL
# lives in api_keys."local" and the model in default_model.
cat > "$CONFIG_FILE" <<EOF
llm_provider = "$AGENTOS_LLM_PROVIDER"
default_model = "$AGENTOS_MODEL"
data_dir = "$DATA_DIR"
setup_complete = true

[api_keys]
local = "$OLLAMA_BASE_URL"

[backup]
enabled = $BACKUP_ENABLED
root = "$AGENTOS_BACKUP_ROOT"
interval_seconds = $AGENTOS_BACKUP_INTERVAL_SECONDS
run_on_start = $BACKUP_RUN_ON_START
keep_latest = $AGENTOS_BACKUP_KEEP_LATEST
max_age_seconds = $AGENTOS_BACKUP_MAX_AGE_SECONDS
EOF

# Convenience: allow `docker run <image> agent ...`, `os-demo`, etc. to be
# passed as the bare binary name. Anything else is exec'd verbatim.
case "${1:-}" in
    agent|agent-server|os-demo|os-benchmark|stress-test)
        exec "$@"
        ;;
    "")
        exec os-demo
        ;;
    *)
        exec "$@"
        ;;
esac
