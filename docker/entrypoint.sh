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
EOF

# Convenience: allow `docker run <image> agent ...`, `os-demo`, etc. to be
# passed as the bare binary name. Anything else is exec'd verbatim.
case "${1:-}" in
    agent|os-demo|os-benchmark|stress-test)
        exec "$@"
        ;;
    "")
        exec os-demo
        ;;
    *)
        exec "$@"
        ;;
esac
