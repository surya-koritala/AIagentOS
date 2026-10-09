# Repository framing

The GitHub description and topics were updated and verified on 2026-10-08 to
match the user-space runtime scope in README. The previous kernel/operating-system
framing exceeded the implemented host-runtime boundary.

Verified description:

> A governed user-space runtime and control plane for long-lived AI agents, with lifecycle, scheduling, durable context, tool authorization, quotas and operator interfaces.

Verified topics:

```text
agent-runtime
control-plane
ai-agents
multi-agent
llm
rust
```

The external-framing acceptance item in
[#373](https://github.com/surya-koritala/AIagentOS/issues/373) has recorded evidence;
the issue remains open until the source audit and gates are reviewed and merged.
Current qualification remains defined by [capabilities.toml](capabilities.toml).
