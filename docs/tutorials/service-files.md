# Writing Agent Service Files

Service files define agents declaratively (like systemd unit files).

## Format

Create a `.toml` file in your services directory:

```toml
name = "researcher"
description = "Research agent that finds information"

[exec]
provider = "azure-openai"
system_prompt = "You are a research specialist. Search the web and summarize findings."
tools = ["http_get", "browse_url", "search_web"]
model = "gpt-4o"

[service]
restart = "OnFailure"
restart_delay_ms = 5000
max_restarts = 3
service_type = "Simple"

[dependencies]
requires = ["database"]
after = ["database"]

[resources]
token_budget = "10000/hour"
max_context = 32000
nice = -5
```

## Fields

### [exec]
- `provider`: LLM provider (azure-openai, openai, anthropic, local)
- `system_prompt`: The agent's personality/instructions
- `tools`: List of tools the agent can use
- `model`: Specific model override

### [service]
- `restart`: Always | OnFailure | Never
- `restart_delay_ms`: Wait before restart
- `max_restarts`: Give up after N restarts
- `service_type`: Simple | Oneshot | Notify

### [dependencies]
- `requires`: Hard dependencies (must be running)
- `wants`: Soft dependencies (nice to have)
- `after`: Start after these (ordering only)
- `before`: Start before these

### [resources]
- `token_budget`: Token limit per time period
- `max_context`: Max context window size
- `nice`: Priority (-20 to +19, lower = higher priority)

## Managing Services

```bash
# Start
cargo run --package agent-cli -- -c "agentctl start researcher"

# Stop
cargo run --package agent-cli -- -c "agentctl stop researcher"

# Status
cargo run --package agent-cli -- -c "agentctl status"
```
