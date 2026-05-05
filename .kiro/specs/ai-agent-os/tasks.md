# Implementation Plan: AI Agent OS

## Overview

This plan implements the AI Agent OS as a Rust Cargo workspace with four crates (kernel, adapters, resources, tauri-app) plus a WASM module example. The implementation proceeds bottom-up: core types and traits first, then subsystem implementations, then integration and wiring, and finally the Tauri desktop shell. Property-based tests validate correctness properties from the design throughout.

## Tasks

- [x] 1. Set up Cargo workspace and core types
  - [x] 1.1 Create workspace Cargo.toml with all crates and shared dependencies
    - Initialize `ai-agent-os/Cargo.toml` as workspace root
    - Define workspace members: `crates/kernel`, `crates/adapters`, `crates/resources`, `crates/tauri-app`, `tests`
    - Add all workspace dependencies from the design (tokio, serde, uuid, chrono, thiserror, async-trait, dashmap, wasmtime, rusqlite, reqwest, proptest, etc.)
    - Create each crate's `Cargo.toml` referencing workspace dependencies
    - _Requirements: 10.1_

  - [x] 1.2 Define core type definitions and error hierarchy in `crates/kernel/src/lib.rs`
    - Implement `AgentId`, `SessionId`, `ProviderId`, `PermissionProfileId`, `ModuleId`, `SandboxId` type aliases
    - Implement `AgentState` enum with all states (Initializing, Running, Paused, Stopping, Stopped, Error)
    - Implement `Priority` newtype constrained to 1..=5
    - Implement `AgentConfig`, `AgentHandle`, `KernelEvent` structs/enums
    - Implement full error hierarchy: `KernelError`, `AgentError`, `SchedulerError`, `ContextError`, `ResourceError`, `PermissionError`, `ConnectorError`, `ModuleError`, `IpcError`, `SandboxError` using `thiserror`
    - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5_

  - [x] 1.3 Define all trait interfaces as specified in the design
    - Implement `AgentKernel` trait with lifecycle and event methods
    - Implement `AgentScheduler` trait with schedule/suspend/resume/priority methods
    - Implement `ContextManager` trait with context CRUD and memory methods
    - Implement `ResourceBroker` trait and `ResourceProvider` trait
    - Implement `PermissionSystem` trait with check_access, request_elevation, assign_profile, get_audit_log
    - Implement `AgentConnector`, `LlmSession`, `LlmProviderAdapter` traits
    - Implement `ModuleSystem` trait with install/uninstall/load/unload
    - Implement `AgentIpc` trait with send/subscribe/publish/delegate
    - Implement `ObservabilityEngine` trait with logging and metrics methods
    - Implement `SandboxManager` trait with create/destroy/intercept
    - _Requirements: 1.1, 2.1, 3.1, 4.1, 5.1, 6.1, 7.1, 11.1, 12.1, 9.1_

  - [x] 1.4 Define data model structs (Session, Agent, ContextSnapshot, MemoryEntry, ModuleManifest, AuditLogEntry)
    - Implement all data model structs from the design's "Core Data Entities" section
    - Derive `Serialize`, `Deserialize`, `Debug`, `Clone` as specified
    - _Requirements: 3.1, 5.6, 7.5, 12.1_

- [ ] 2. Implement Agent Lifecycle and Scheduler
  - [x] 2.1 Implement agent state machine in `crates/kernel/src/agent.rs`
    - Implement state transition validation (only valid transitions allowed per state diagram)
    - Implement `create_agent` — initialize context, assign sandbox, transition to Running within 5 seconds (use `tokio::time::timeout`)
    - Implement `pause_agent` — suspend execution, persist context
    - Implement `resume_agent` — restore context, transition to Running
    - Implement `stop_agent` — terminate, release resources, archive session
    - Implement 30-second unresponsive watchdog using `tokio::time::timeout`
    - Store agents in `DashMap<AgentId, Agent>` for lock-free concurrent access
    - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5_

  - [-] 2.2 Write property tests for agent lifecycle (Properties 4, 5)
    - **Property 4: Agent stop releases all resources** — For any running agent holding resources, stopping SHALL result in zero held resources and archived session
    - **Property 5: Unresponsive agent termination and cleanup** — For any unresponsive agent, kernel SHALL terminate, release resources (count → 0), and generate notification
    - **Validates: Requirements 1.4, 1.5**

  - [~] 2.3 Implement priority-based scheduler in `crates/kernel/src/scheduler.rs`
    - Implement cooperative scheduling with Tokio tasks (agents yield between LLM calls)
    - Support at least 10 concurrent agents
    - Implement priority queue for resource access (highest priority first)
    - Implement resource-aware throttling (increase delay between LLM calls for lower-priority agents under pressure)
    - Implement default priority assignment for new agents
    - Implement deadlock detection via 10-second timeout with rollback of lowest-priority pending operation
    - _Requirements: 2.1, 2.2, 2.3, 2.4_

  - [~] 2.4 Write property tests for scheduler (Properties 6, 7)
    - **Property 6: Priority-ordered resource access without deadlock** — For any set of agents with distinct priorities competing for same resource, access granted in priority order and all requests eventually complete
    - **Property 7: Priority-based throttling under resource pressure** — For any agents with different priorities under constraints, lower-priority agents throttled before higher-priority
    - **Validates: Requirements 2.2, 2.3**

- [ ] 3. Implement Context and Memory Management
  - [~] 3.1 Implement context manager in `crates/kernel/src/context.rs`
    - Implement `create_context` — initialize empty context for new agent
    - Implement `get_context` / `persist_context` / `restore_context` — full round-trip persistence to SQLite
    - Implement context summarization when token count exceeds 80% of LLM limit
    - Implement retry logic for persistence failures (3 attempts) with user notification on failure
    - Set up SQLite database schema for conversation history and context snapshots using `rusqlite`
    - _Requirements: 3.1, 3.2, 3.3, 3.5_

  - [~] 3.2 Write property tests for context management (Properties 1, 2)
    - **Property 1: Context persistence round-trip** — For any agent context (history, working state, tasks, results), persist then restore SHALL produce equivalent context
    - **Property 2: Context summarization respects token limit** — For any context exceeding token limit, summarization SHALL produce context within limit
    - **Validates: Requirements 1.2, 1.3, 3.1, 3.2, 3.3**

  - [~] 3.3 Implement long-term memory store in `crates/kernel/src/context.rs`
    - Implement `store_fact` — persist facts with category, tags, and optional embeddings to SQLite
    - Implement `query_memory` — retrieve facts by semantic query (text matching initially, vector search as enhancement)
    - Create SQLite schema for memory entries with indexing on category and tags
    - _Requirements: 3.4_

  - [~] 3.4 Write property test for long-term memory (Property 3)
    - **Property 3: Long-term memory store/retrieve round-trip** — For any valid Fact, storing and querying SHALL return result containing original content
    - **Validates: Requirements 3.4**

- [~] 4. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 5. Implement Permission System and Sandbox
  - [~] 5.1 Implement permission system in `crates/kernel/src/permissions.rs`
    - Implement `check_access` — evaluate agent's permission profile rules against resource request
    - Implement rule matching with glob patterns for targets (paths, URLs)
    - Implement `request_elevation` — prompt user for approval on high-risk actions
    - Implement `assign_profile` — associate permission profile with agent
    - Implement predefined profiles: read-only, standard, elevated, full-access
    - Implement audit logging — record all actions with timestamp, agent ID, resource, decision, outcome
    - Store audit log as append-only JSON lines file
    - _Requirements: 5.1, 5.2, 5.3, 5.4, 5.5, 5.6_

  - [~] 5.2 Write property tests for permissions (Properties 8, 9, 12, 18)
    - **Property 8: Permission enforcement matches profile rules** — For any agent with profile and any request, decision SHALL match profile rules
    - **Property 9: High-risk actions require user approval** — For any high-risk action, SHALL return RequiresApproval regardless of profile (except full-access)
    - **Property 12: Resource access always validates permissions** — For any resource request, Permission_System check_access SHALL be invoked before execution
    - **Property 18: Agent action audit logging completeness** — For any agent action, a corresponding audit entry SHALL be created
    - **Validates: Requirements 5.1, 5.2, 5.3, 4.6, 5.6, 12.1**

  - [~] 5.3 Implement sandbox manager in `crates/kernel/src/sandbox.rs`
    - Implement `create` — create isolated workspace directory with platform-specific isolation
    - Implement `destroy` — clean up sandbox directory and release resources
    - Implement `intercept_action` — check resource requests against sandbox boundaries
    - Implement path canonicalization to prevent traversal attacks
    - Implement network allowlist checking for sandboxed agents
    - Implement default sandbox assignment for new agents
    - Platform-specific: Linux (namespaces/seccomp), macOS (sandbox-exec), Windows (Job Objects)
    - _Requirements: 9.1, 9.2, 9.3, 9.4, 9.5_

  - [~] 5.4 Write property tests for sandbox (Properties 10, 11, 27)
    - **Property 10: Sandbox boundary enforcement** — For any sandboxed agent, actions targeting resources outside boundary SHALL be intercepted
    - **Property 11: New agents are sandboxed by default** — For any new agent without explicit broader permissions, SHALL be assigned to Sandbox
    - **Property 27: Sandbox isolation between agents** — For any two agents in separate sandboxes, one's actions SHALL not modify other's visible state
    - **Validates: Requirements 5.5, 9.1, 9.2, 9.3, 9.4, 9.5**

- [ ] 6. Implement Resource Broker and Providers
  - [~] 6.1 Implement resource broker in `crates/kernel/src/resources.rs`
    - Implement `execute` — validate permissions via Permission_System, then dispatch to appropriate ResourceProvider
    - Implement `register_provider` — register pluggable resource providers
    - Implement `list_capabilities` — enumerate available resource types and operations
    - Wire permission check before every resource execution
    - _Requirements: 4.1, 4.6_

  - [~] 6.2 Implement built-in resource providers in `crates/resources/src/`
    - Implement `filesystem.rs` — read, write, create, delete, list operations using `std::fs` and `tokio::fs`
    - Implement `network.rs` — HTTP requests via `reqwest`, socket connections, DNS resolution
    - Implement `application.rs` — launch/close apps, send input, read output via `std::process::Command`
    - Implement `browser.rs` — navigate, click, type, read page content (stub with trait for future implementation)
    - Implement `peripheral.rs` — camera, microphone, speakers, printers (stub with trait for future implementation)
    - _Requirements: 4.1, 4.2, 4.3, 4.4, 4.5_

- [ ] 7. Implement Agent Connector and LLM Adapters
  - [~] 7.1 Implement agent connector in `crates/kernel/src/connector.rs`
    - Implement `register_provider` — validate adapter implements required trait methods, store in registry
    - Implement `connect` — create LLM session for agent using specified provider
    - Implement `list_providers` — enumerate registered providers with type (Cloud/Local)
    - Implement provider unavailability detection and user notification
    - Implement optional failover to backup provider
    - _Requirements: 6.1, 6.2, 6.3, 6.4, 6.5_

  - [~] 7.2 Implement LLM provider adapters in `crates/adapters/src/`
    - Implement `openai.rs` — OpenAI API adapter with streaming, tool calling translation
    - Implement `anthropic.rs` — Anthropic API adapter with streaming, tool calling translation
    - Implement `local.rs` — Local LLM adapter (Ollama/llama.cpp) via HTTP
    - Each adapter translates between StandardMessage and provider-specific formats
    - Implement retry with exponential backoff (1s, 2s, 4s) for transient failures
    - _Requirements: 6.1, 6.3, 6.5_

  - [~] 7.3 Write property tests for connector (Properties 13, 14)
    - **Property 13: Provider protocol validation** — For any adapter, acceptance iff all required trait methods implemented (compile-time via Rust traits)
    - **Property 14: Protocol message translation round-trip** — For any StandardMessage, translate to provider format and back SHALL produce semantically equivalent message
    - **Validates: Requirements 6.2, 6.5**

- [ ] 8. Implement Module System (WASM)
  - [~] 8.1 Implement WASM module system in `crates/kernel/src/modules.rs`
    - Implement `install` — load WASM binary, parse manifest, validate permissions and resource requirements
    - Implement `uninstall` — remove module from registry and clean up
    - Implement `load` — instantiate Wasmtime engine with resource limits (StoreLimits for memory/CPU)
    - Implement `unload` — terminate Wasmtime instance, clean up registered resources
    - Implement `list_modules` — return module registry with status, version, capabilities
    - Implement host functions exposed to WASM modules (kernel services API)
    - Implement crash isolation — catch Wasmtime Trap, log, unload module, continue kernel
    - Implement module registry as TOML config file
    - _Requirements: 7.1, 7.2, 7.3, 7.4, 7.5_

  - [~] 8.2 Write property tests for modules (Properties 15, 16, 17)
    - **Property 15: Module validation on install** — For any manifest, kernel SHALL validate permissions/resources before activation; invalid modules rejected
    - **Property 16: Module crash isolation** — For any set of modules where one traps, all others and all agents SHALL continue without corruption
    - **Property 17: Module registry accuracy** — For any installed modules, registry SHALL contain correct name, version, status, capabilities matching manifest
    - **Validates: Requirements 7.2, 7.4, 7.5**

  - [~] 8.3 Create example WASM module in `modules/example-tool/`
    - Create a simple tool module in Rust targeting `wasm32-wasi`
    - Implement module manifest (manifest.toml) with declared permissions and capabilities
    - Demonstrate calling kernel host functions from WASM
    - _Requirements: 7.3_

- [ ] 9. Implement Agent IPC and Observability
  - [~] 9.1 Implement inter-agent communication in `crates/kernel/src/ipc.rs`
    - Implement `send` — direct agent-to-agent messaging via Tokio mpsc channels
    - Implement `subscribe` / `unsubscribe` / `publish` — pub/sub via Tokio broadcast channels
    - Implement `delegate` — task delegation with completion tracking
    - Implement delegation chain tracking (tree structure with status propagation)
    - Implement permission enforcement on IPC (check communication policies before delivery)
    - Implement message delivery within 1 second under normal load
    - Implement dead-letter queue for failed deliveries
    - _Requirements: 11.1, 11.2, 11.3, 11.4, 11.5_

  - [~] 9.2 Write property tests for IPC (Properties 19, 20, 21)
    - **Property 19: Pub/sub message delivery to all subscribers** — For any subscribed agent, published message to that topic SHALL be received
    - **Property 20: IPC permission enforcement** — For any communication attempt, permission policies SHALL be enforced; unpermitted messages rejected
    - **Property 21: Delegation chain completion propagation** — For any delegation chain, leaf completion SHALL propagate back through every node to originator
    - **Validates: Requirements 11.3, 11.4, 11.5**

  - [~] 9.3 Implement observability engine in `crates/kernel/src/observability.rs`
    - Implement `log_action` — record agent actions with type, description, resources, reasoning, timestamp
    - Implement `get_activity_log` — retrieve filtered action history per agent
    - Implement `get_reasoning_chain` — retrieve reasoning steps for a specific action
    - Implement `get_agent_plan` — retrieve agent's current plan steps
    - Implement `get_metrics` — compute resource usage metrics (tokens, API calls, files, time)
    - Implement `on_deviation` — register handler for plan deviation detection
    - Implement plan deviation detection (compare action against expected next step)
    - Use `tracing` crate for structured logging
    - _Requirements: 12.1, 12.2, 12.3, 12.4, 12.5_

  - [~] 9.4 Write property tests for observability (Properties 22, 23, 24)
    - **Property 22: Plan deviation detection** — For any action not matching stated plan, system SHALL flag deviation and notify user
    - **Property 23: Resource metrics accuracy** — For any activity sequence, metrics SHALL be monotonically non-decreasing and increment correctly
    - **Property 24: Reasoning chain retrieval** — For any action with reasoning chain, explanation request SHALL return complete chain
    - **Validates: Requirements 12.2, 12.4, 12.5**

- [~] 10. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 11. Implement Kernel Orchestrator and System Integration
  - [~] 11.1 Wire kernel orchestrator in `crates/kernel/src/lib.rs`
    - Implement concrete `AgentKernelImpl` struct holding all subsystem instances (`Arc<dyn Trait>`)
    - Wire event bus using `tokio::sync::broadcast` channel for `KernelEvent` distribution
    - Implement `create_agent` flow: validate config → create sandbox → init context → schedule → broadcast event
    - Implement `pause_agent` / `resume_agent` / `stop_agent` flows with proper subsystem coordination
    - Implement `subscribe_events` for subsystem event consumption
    - Implement graceful shutdown — persist all agent states, terminate sessions, release resources
    - _Requirements: 1.1, 1.2, 1.3, 1.4, 10.4_

  - [~] 11.2 Write property test for graceful shutdown (Property 25)
    - **Property 25: Graceful shutdown persists all agent states** — For any set of running agents at shutdown, all states SHALL be persisted and sessions terminated
    - **Validates: Requirements 10.4**

  - [~] 11.3 Implement system prerequisite validation
    - Check minimum RAM (8GB), disk space (10GB), internet connectivity
    - Report specific deficiencies to user
    - Integrate with host OS notification system
    - Respect host OS security model and firewall rules
    - _Requirements: 10.2, 10.3, 10.5_

  - [~] 11.4 Write property test for prerequisite validation (Property 26)
    - **Property 26: System prerequisite validation** — For any system config, checker SHALL correctly identify all deficiencies; passing systems pass, failing systems report specific issue
    - **Validates: Requirements 10.2**

  - [~] 11.5 Write property test for notification generation (Property 28)
    - **Property 28: Notification generation for agent events** — For any agent event (completion, error, approval request), system SHALL generate corresponding notification
    - **Validates: Requirements 8.6**

- [ ] 12. Implement Tauri Desktop Application
  - [~] 12.1 Set up Tauri 2 application shell in `crates/tauri-app/`
    - Configure `tauri.conf.json` with app metadata, window settings, and permissions
    - Implement `main.rs` — Tauri entry point, initialize kernel, register commands
    - Set up Svelte frontend project in `crates/tauri-app/ui/` with Vite
    - Configure Tauri IPC bridge between Rust backend and Svelte frontend
    - _Requirements: 10.1, 10.3_

  - [~] 12.2 Implement Tauri command handlers in `crates/tauri-app/src/commands.rs`
    - Implement `create_agent` command — accept natural language task, create agent via kernel
    - Implement `pause_agent` / `resume_agent` / `stop_agent` commands
    - Implement `list_agents` command — return agent status for dashboard
    - Implement `get_activity_log` command — return agent actions for transparency view
    - Implement `get_agent_plan` command — return current plan steps
    - Implement `get_metrics` command — return resource usage metrics
    - Implement `approve_action` / `deny_action` commands — handle permission elevation requests
    - Implement `set_permissions` command — assign permission profiles
    - Implement `set_priority` command — adjust agent priority
    - _Requirements: 8.2, 8.3, 8.4, 8.5_

  - [~] 12.3 Implement Svelte frontend dashboard
    - Implement main dashboard view showing agent status, active tasks, recent actions
    - Implement natural language input for task assignment
    - Implement permission controls (buttons, toggles, sliders) for profiles, priority, resource limits
    - Implement approval dialog for high-risk actions with description, impact, approve/deny
    - Implement notification system for completions, errors, approval requests
    - Implement agent plan view showing next steps in human-readable format
    - Implement activity log view with reasoning chain drill-down
    - _Requirements: 8.1, 8.2, 8.3, 8.4, 8.5, 8.6_

  - [~] 12.4 Implement guided setup wizard
    - Implement first-run detection and wizard trigger
    - Implement LLM provider configuration step (API key entry, provider selection)
    - Implement first agent creation step with natural language task
    - Implement permission profile selection with visual explanations
    - Target completion within 10 minutes for non-technical users
    - _Requirements: 8.1_

- [ ] 13. Integration and Cross-Platform Wiring
  - [~] 13.1 Wire all subsystems together in kernel initialization
    - Initialize SQLite database with schema migrations
    - Initialize all subsystem implementations and inject dependencies
    - Start event bus and connect all subscribers
    - Register built-in resource providers (filesystem, network, application)
    - Load installed WASM modules from registry
    - Start unresponsive agent watchdog timer
    - _Requirements: 1.1, 4.1, 7.1, 10.1_

  - [~] 13.2 Implement host OS integration
    - Implement native notification integration (Windows toast, macOS NSUserNotification, Linux libnotify)
    - Implement graceful shutdown on OS shutdown signal (SIGTERM/SIGINT on Unix, WM_CLOSE on Windows)
    - Implement file system watcher for sandbox workspace directories
    - Implement application launcher integration per platform
    - _Requirements: 10.3, 10.4, 10.5_

  - [~] 13.3 Write integration tests
    - Test end-to-end agent task execution (create → run → tool call → permission check → complete)
    - Test LLM provider failover with mock HTTP server (wiremock)
    - Test context persistence under simulated storage errors
    - Test WASM module loading, execution, and crash recovery
    - Test cross-sandbox isolation
    - Test message delivery timing (< 1 second)
    - _Requirements: 1.1, 6.4, 3.5, 7.4, 9.5, 11.2_

- [~] 14. Final checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- Tasks marked with `*` are optional and can be skipped for faster MVP
- Each task references specific requirements for traceability
- Checkpoints ensure incremental validation
- Property tests validate the 28 universal correctness properties from the design
- Unit tests (co-located with source via `#[cfg(test)]`) validate specific examples and edge cases
- The Cargo workspace structure enables independent compilation and testing of each crate
- Platform-specific sandbox code should use conditional compilation (`#[cfg(target_os = "...")]`)

---

# Phase 2: Scaffolding → Deployable App

## Overview

The tasks above (1-14) built the kernel scaffolding with validated subsystem contracts. The tasks below wire everything into a working end-to-end application that can be deployed to users.

---

## Phase 1: MVP — Working Agent Loop with Tool Use

- [ ] 15. Configuration Management
  - [ ] 15.1 Create `crates/kernel/src/config.rs` with Config struct
    - Fields: llm_provider, api_keys (HashMap<ProviderId, String>), default_model, data_dir
    - Use `dirs` crate for platform-appropriate config directory (~/.config/ai-agent-os/)
    - Load from TOML file on startup, create default if missing
    - Serialize/deserialize with serde + toml
  - [ ] 15.2 Write unit tests for config load/save/defaults

- [ ] 16. Extend LLM Interface for Tool Calling
  - [ ] 16.1 Add ToolCall and ToolDefinition structs to `connector.rs`
    - ToolCall: id, name, arguments (serde_json::Value)
    - ToolDefinition: name, description, parameters (JSON Schema)
    - Extend LlmResponse with `tool_calls: Vec<ToolCall>`
    - Extend LlmSession::send() to accept `tools: &[ToolDefinition]`
    - Add StandardMessage variant for tool results (role="tool", tool_call_id, content)
  - [ ] 16.2 Write unit tests for ToolCall/ToolDefinition serialization

- [ ] 17. OpenAI Adapter — Real Function Calling
  - [ ] 17.1 Update `openai.rs` to send tools in API request body
    - Include `"tools"` array in request when tools are provided
    - Parse `response.choices[0].message.tool_calls` from JSON response
    - Map OpenAI tool call format to generic ToolCall struct
    - Support both content responses and tool_call responses
  - [ ] 17.2 Write wiremock integration tests for tool calling responses

- [ ] 18. Tool Registry
  - [ ] 18.1 Create `crates/kernel/src/tools.rs`
    - ToolRegistry struct with HashMap<String, ToolBinding>
    - ToolBinding: name, description, parameters_schema, resource_type, operation
    - `definitions() -> Vec<ToolDefinition>` — generates LLM-compatible tool list
    - `resolve(tool_call: &ToolCall) -> ResourceRequest` — converts tool call to resource request
    - Register built-in tools: read_file, write_file, list_directory, http_get, run_command
  - [ ] 18.2 Write unit tests for tool resolution and definition generation

- [ ] 19. Agent Execution Loop
  - [ ] 19.1 Create `crates/kernel/src/execution.rs`
    - AgentExecutor struct: connector, resource_broker, context_manager, tool_registry, agent_id
    - `run(user_message) -> AgentOutput` method implementing think→act→observe loop:
      1. Append user message to context
      2. Build messages from context history
      3. Send to LLM with tool definitions
      4. If response has tool_calls: execute each via ResourceBroker, append results, loop to step 2
      5. If response is plain content: return to user
      6. Cap at 10 tool call rounds to prevent infinite loops
    - Handle errors: if tool execution fails, send error back to LLM for recovery
  - [ ] 19.2 Write integration test with mock LLM returning tool calls
  - [ ] 19.3 Write test for max iteration cap (infinite loop prevention)

- [ ] 20. Wire Execution Loop into Kernel
  - [ ] 20.1 Add `send_message(agent_id, message) -> Result<String>` to AgentKernelImpl
    - Store active executors in DashMap<AgentId, Arc<AgentExecutor>>
    - Create executor on first message using agent's assigned LLM provider
    - Route messages through executor's run() method
  - [ ] 20.2 Write end-to-end test: create agent → send message → get response (mocked LLM)

- [ ] 21. SQLite Persistence to Disk
  - [ ] 21.1 Update SqliteContextManager to support file-based databases
    - `SqliteContextManager::from_path(path)` — open/create SQLite file at config data_dir
    - On startup, load existing agent contexts
    - On shutdown, persist all active contexts
    - Migrate AgentKernelImpl::new() to accept config with DB path
  - [ ] 21.2 Write test: create context, drop manager, reopen from same file, verify data persists

- [ ] 22. Tauri Chat Commands + Event Streaming
  - [ ] 22.1 Add `send_message` Tauri command
    - Accept agent_id and message string
    - Call kernel.send_message(), return response
    - Emit `agent-thinking` event when LLM call starts
    - Emit `agent-tool-call` event when tool is being executed
    - Emit `agent-response` event with final response
  - [ ] 22.2 Add `save_config` and `load_config` Tauri commands
  - [ ] 22.3 Wire config loading into Tauri app startup

- [ ] 23. Minimal Svelte Frontend
  - [ ] 23.1 Initialize Svelte + Vite project in `crates/tauri-app/ui/`
    - npm create vite@latest with svelte template
    - Configure Vite for Tauri (dev server port, build output to dist/)
  - [ ] 23.2 Implement ChatPanel component
    - Message list with user/assistant/tool-call bubbles
    - Text input with send button
    - Auto-scroll to bottom on new messages
    - Show "thinking..." indicator during LLM calls
    - Collapsible tool call blocks showing what the agent did
  - [ ] 23.3 Implement Sidebar component
    - Agent list with state indicators (running/paused/stopped)
    - "New Agent" button
    - Agent name and task display
  - [ ] 23.4 Implement SetupModal component
    - First-run detection (no API key in config)
    - Provider selection (OpenAI/Anthropic/Local)
    - API key input with "Test Connection" button
    - Save and dismiss
  - [ ] 23.5 Wire Tauri invoke/listen for commands and events

- [ ] 24. Checkpoint — MVP Demo
  - Launch app → enter API key → create agent → chat → agent uses file tools → responses display

---

## Phase 2: Robustness & Streaming

- [ ] 25. LLM Streaming Support
  - [ ] 25.1 Add `send_streaming()` to LlmSession trait
    - Returns `impl Stream<Item=StreamChunk>`
    - StreamChunk enum: Token(String), ToolCallStart(id, name), ToolCallArgs(id, delta), Done(LlmResponse)
  - [ ] 25.2 Implement streaming in OpenAI adapter (SSE parsing on reqwest response)
  - [ ] 25.3 Update AgentExecutor to use streaming, emit chunks via channel
  - [ ] 25.4 Forward stream chunks as Tauri events to frontend
  - [ ] 25.5 Update ChatPanel to render tokens incrementally

- [ ] 26. Anthropic Adapter with Tool Use
  - [ ] 26.1 Update `anthropic.rs` for Claude messages API with tool_use content blocks
    - Map Claude's tool_use format to generic ToolCall
    - Support streaming via Claude's SSE format
  - [ ] 26.2 Write wiremock tests for Anthropic tool calling responses

- [ ] 27. Agent-Level Error Recovery & Retry
  - [ ] 27.1 In AgentExecutor: retry LLM calls with backoff (3 attempts)
  - [ ] 27.2 On tool failure: send error context back to LLM for recovery
  - [ ] 27.3 On max retries exhausted: transition agent to Error state, notify user
  - [ ] 27.4 Circuit breaker: if provider fails 5x in a row, mark unavailable, trigger failover
  - [ ] 27.5 Write tests for retry and recovery scenarios

- [ ] 28. Context Window Management
  - [ ] 28.1 Track token count per message (estimate via word_count * 1.3 or tiktoken-rs)
  - [ ] 28.2 When context approaches 80% of model max, trigger summarization
    - Use LLM to summarize older messages
    - Store summary, replace old messages with summary message
  - [ ] 28.3 Write test: long conversation triggers summarization, stays within limit

- [ ] 29. Checkpoint — Production-Quality LLM Interaction
  - Streaming works, multi-provider, error recovery, long conversations handled

---

## Phase 3: Extensibility — WASM Modules

- [ ] 30. WASM Module Host Functions
  - [ ] 30.1 Define host function interface for WASM modules
    - `host_read_file(path_ptr, path_len) -> (ptr, len)` — read file contents
    - `host_write_file(path_ptr, path_len, content_ptr, content_len) -> status`
    - `host_http_get(url_ptr, url_len) -> (ptr, len)` — HTTP GET request
    - `host_log(msg_ptr, msg_len)` — log a message
  - [ ] 30.2 Implement host functions using Wasmtime linker
    - Route through ResourceBroker (permission-gated)
    - Use agent's sandbox context for isolation
  - [ ] 30.3 Compile example-tool to wasm32-wasi, test loading and execution
  - [ ] 30.4 Write integration test: load module, call exported function, verify host function calls work

- [ ] 31. Dynamic Tool Registration from Modules
  - [ ] 31.1 Extend module manifest with tool declarations
    - Each tool: name, description, parameters JSON schema, exported function name
  - [ ] 31.2 On module load: parse manifest, register tools in ToolRegistry
  - [ ] 31.3 On module unload: remove tools from ToolRegistry
  - [ ] 31.4 ToolBinding for module tools routes execution through WASM runtime
  - [ ] 31.5 Write test: load module → tools appear → agent can use them → unload → tools gone

- [ ] 32. Checkpoint — Plugin Ecosystem
  - Install a WASM module, agent immediately gains new tool capabilities

---

## Phase 4: Polish & Distribution

- [ ] 33. Guided Setup Wizard
  - [ ] 33.1 Svelte multi-step wizard component
    - Step 1: Welcome screen with brief explanation
    - Step 2: Provider selection (OpenAI / Anthropic / Local Ollama)
    - Step 3: API key entry (or Ollama URL for local)
    - Step 4: Test connection (make a simple API call, show success/failure)
    - Step 5: Create first agent with a sample task
    - Step 6: Done — redirect to main app
  - [ ] 33.2 First-run detection (check config file exists and has valid API key)
  - [ ] 33.3 Validate API key by making test call before saving
  - [ ] 33.4 Target completion within 2 minutes for non-technical users

- [ ] 34. Enhanced UI — Dashboard & Agent Management
  - [ ] 34.1 Dashboard view
    - Agent cards showing: name, state (color-coded), current task, last activity time
    - System metrics: total tokens used, active agents, uptime
    - Quick actions: pause all, resume all
  - [ ] 34.2 Agent detail view
    - Full conversation history with search
    - Reasoning chain drill-down (click action → see why agent did it)
    - Plan view showing next steps
    - Resource usage metrics (tokens, API calls, files modified)
  - [ ] 34.3 Create agent dialog
    - Natural language task input
    - Provider selection dropdown
    - Permission profile selector with visual explanations
    - Priority slider (1-5)
    - Optional sandbox configuration
  - [ ] 34.4 Settings page
    - Provider management (add/remove/test API keys)
    - Module management (install/uninstall/enable/disable)
    - Permission profile editor
    - Data management (export/import conversations, clear history)
  - [ ] 34.5 Notification system
    - Toast notifications for: agent completed task, agent error, approval request
    - Approval dialog for high-risk actions (show description, impact, approve/deny buttons)
    - Notification history panel
  - [ ] 34.6 Dark/light theme with system preference detection
  - [ ] 34.7 Keyboard shortcuts (Ctrl+N new agent, Ctrl+Enter send, Esc cancel)

- [ ] 35. Real-Time Activity Feed
  - [ ] 35.1 Live activity log showing all agent actions as they happen
    - Filterable by agent, action type, time range
    - Color-coded by action type (tool call, LLM call, error)
  - [ ] 35.2 Agent plan visualization
    - Show planned steps as a checklist
    - Highlight current step, mark completed steps
    - Flag deviations with warning icon
  - [ ] 35.3 Resource usage graphs (tokens over time, API calls per minute)

- [ ] 36. Multi-Agent Collaboration UI
  - [ ] 36.1 Agent-to-agent message visualization
    - Show IPC messages between agents as connecting lines
    - Delegation tree view (who delegated what to whom)
  - [ ] 36.2 Create agent group/team with shared context
  - [ ] 36.3 Drag-and-drop task delegation between agent cards

- [ ] 37. Packaging & Installers
  - [ ] 37.1 Configure Tauri bundler for all platforms
    - Linux: .deb and .AppImage
    - macOS: .dmg with code signing
    - Windows: .msi with code signing
  - [ ] 37.2 App icon and branding assets
    - App icon (multiple sizes: 16x16 to 1024x1024)
    - Splash screen
    - Tray icon
  - [ ] 37.3 Set up tauri-plugin-updater
    - GitHub Releases as update backend
    - Check for updates on startup (configurable)
    - Show update available notification with changelog
    - One-click update and restart

- [ ] 38. CI/CD Pipeline
  - [ ] 38.1 GitHub Actions workflow
    - On push to main: run all tests, build all platforms
    - On tag: build release artifacts, create GitHub Release, upload installers
    - Matrix build: ubuntu-latest, macos-latest, windows-latest
  - [ ] 38.2 Automated testing
    - Unit tests + property tests on every PR
    - Integration tests with mocked LLM APIs
    - Build verification (all platforms compile)
  - [ ] 38.3 Release automation
    - Semantic versioning from commit messages
    - Auto-generate changelog from PR titles
    - Upload artifacts to GitHub Releases
    - Trigger update server notification

- [ ] 39. Documentation & Onboarding
  - [ ] 39.1 User documentation
    - Getting started guide (install → first agent → first task)
    - Provider setup guides (OpenAI, Anthropic, Ollama)
    - Permission profiles explained
    - Module development guide
  - [ ] 39.2 Developer documentation
    - Architecture overview with diagrams
    - Contributing guide
    - API reference (generated from rustdoc)
    - Module SDK documentation
  - [ ] 39.3 In-app help
    - Tooltips on all UI elements
    - "What's this?" contextual help
    - Link to docs from settings/error messages

- [ ] 40. Final Checkpoint — Shippable Product
  - App installs cleanly on all platforms
  - Setup wizard guides new users
  - Agents work with OpenAI/Anthropic/Local
  - WASM modules extend capabilities
  - Auto-update works
  - Documentation is complete

---

## Phase 4 Summary

| Task | Deliverable | User Impact |
|------|-------------|-------------|
| 33 | Setup wizard | Non-technical users can configure the app in 2 minutes |
| 34 | Enhanced UI | Professional dashboard with full agent management |
| 35 | Activity feed | Real-time visibility into what agents are doing |
| 36 | Multi-agent UI | Visualize and manage agent collaboration |
| 37 | Installers | One-click install on Windows/macOS/Linux |
| 38 | CI/CD | Automated builds, tests, and releases |
| 39 | Documentation | Users and developers can self-serve |
| 40 | Final checkpoint | Everything works end-to-end |
