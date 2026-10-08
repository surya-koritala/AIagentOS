# Repository framing proposal

The current GitHub description calls the project an operating system kernel and
its topics include operating-system. That framing exceeds the user-space runtime
scope in README. This file proposes an exact replacement for review; it does not
change the external repository settings.

Proposed description:

> A governed user-space runtime and control plane for long-lived AI agents, with lifecycle, scheduling, durable context, tool authorization, quotas and operator interfaces.

Proposed topics:

```text
agent-runtime
control-plane
ai-agents
multi-agent
llm
rust
```

The acceptance item in [#373](https://github.com/surya-koritala/AIagentOS/issues/373)
remains open until an authorized repository administrator applies and verifies
these settings. Current qualification remains defined by
[capabilities.toml](capabilities.toml); this proposal promotes no capability tier.
