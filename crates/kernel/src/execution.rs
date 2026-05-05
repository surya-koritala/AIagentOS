//! Agent Execution Loop — the think→act→observe cycle.

use std::sync::Arc;

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::connector::{LlmSession, StandardMessage};
use crate::context::{ContextManager, Fact, FactCategory, SqliteContextManager};
use crate::resources::ResourceBroker;
use crate::tools::ToolRegistry;
use crate::{AgentId, KernelError};

/// Maximum tool call rounds before forcing termination.
const MAX_ITERATIONS: usize = 10;

/// Maximum LLM retry attempts on transient failures.
const LLM_RETRIES: usize = 3;

/// Message count threshold before triggering summarization.
const MESSAGE_OVERFLOW_THRESHOLD: usize = 20;

/// Events streamed during agent execution.
#[derive(Debug, Clone)]
pub enum StreamEvent {
    /// A text token from the LLM.
    Token(String),
    /// A tool call is starting.
    ToolCallStarted { name: String, arguments: String },
    /// A tool call completed.
    ToolCallResult { name: String, result: String },
    /// Execution complete.
    Done(AgentOutput),
    /// Execution was cancelled.
    Cancelled { tool_calls_made: usize },
    /// An error occurred.
    Error(String),
}

/// Output from the agent execution loop.
#[derive(Debug, Clone)]
pub struct AgentOutput {
    pub content: String,
    pub tool_calls_made: usize,
    pub tokens_used: u32,
}

/// The agent executor — drives the think→act→observe loop.
pub struct AgentExecutor {
    pub agent_id: AgentId,
    pub conversation_id: String,
    session: Box<dyn LlmSession>,
    resource_broker: Arc<dyn ResourceBroker>,
    tool_registry: Arc<ToolRegistry>,
    context_manager: Arc<SqliteContextManager>,
    rule_store: Option<Arc<crate::learning::RuleStore>>,
    messages: Vec<StandardMessage>,
    cancel_token: CancellationToken,
    event_tx: Option<mpsc::Sender<StreamEvent>>,
    #[allow(dead_code)]
    system_prompt: String,
}

impl AgentExecutor {
    pub fn new(
        agent_id: AgentId,
        session: Box<dyn LlmSession>,
        resource_broker: Arc<dyn ResourceBroker>,
        tool_registry: Arc<ToolRegistry>,
        context_manager: Arc<SqliteContextManager>,
        system_prompt: String,
    ) -> Self {
        Self {
            agent_id,
            conversation_id: uuid::Uuid::new_v4().to_string(),
            session,
            resource_broker,
            tool_registry,
            context_manager,
            rule_store: None,
            messages: vec![StandardMessage::system(&system_prompt)],
            cancel_token: CancellationToken::new(),
            event_tx: None,
            system_prompt,
        }
    }

    /// Resume from a saved conversation.
    pub fn with_conversation(mut self, conversation_id: &str) -> Self {
        self.conversation_id = conversation_id.to_string();
        if let Ok(messages) = self.context_manager.load_conversation(conversation_id) {
            self.messages = messages;
        }
        self
    }

    /// Set an event channel for streaming events to the caller.
    pub fn set_event_channel(&mut self, tx: mpsc::Sender<StreamEvent>) {
        self.event_tx = Some(tx);
    }

    /// Set a rule store for learning from corrections.
    pub fn set_rule_store(&mut self, store: Arc<crate::learning::RuleStore>) {
        self.rule_store = Some(store);
    }

    /// Get a cancellation token for this executor.
    pub fn cancel_token(&self) -> CancellationToken {
        self.cancel_token.clone()
    }

    /// Cancel the running execution.
    pub fn cancel(&self) {
        self.cancel_token.cancel();
    }

    async fn emit(&self, event: StreamEvent) {
        if let Some(ref tx) = self.event_tx {
            let _ = tx.send(event).await;
        }
    }

    /// Run the execution loop for a user message.
    pub async fn run(&mut self, user_message: &str) -> Result<AgentOutput, KernelError> {
        // Query long-term memory for relevant facts
        if let Ok(facts) = self.context_manager.query_memory(self.agent_id, user_message).await {
            if !facts.is_empty() {
                let memory_text = facts.iter().map(|f| f.content.as_str()).collect::<Vec<_>>().join("\n");
                self.messages.push(StandardMessage::system(format!("Relevant memories:\n{}", memory_text)));
            }
        }

        // Inject applicable correction rules
        if let Some(ref store) = self.rule_store {
            if let Some(rules_prompt) = store.rules_as_prompt(user_message) {
                self.messages.push(StandardMessage::system(rules_prompt));
            }
        }

        self.messages.push(StandardMessage::user(user_message));

        // Auto-summarize if messages exceed threshold
        if self.messages.len() > MESSAGE_OVERFLOW_THRESHOLD {
            let ctx = crate::context::AgentContext {
                conversation_history: self.messages.iter().map(|m| crate::context::Message {
                    role: m.role.clone(),
                    content: m.content.clone(),
                    timestamp: chrono::Utc::now(),
                }).collect(),
                token_count: self.messages.iter().map(|m| m.content.len() as u32 / 4 + 1).sum(),
                ..Default::default()
            };
            if let Ok(summarized) = self.context_manager.summarize_overflow(&ctx, ctx.token_count / 2).await {
                self.messages = summarized.conversation_history.iter().map(|m| {
                    StandardMessage { role: m.role.clone(), content: m.content.clone(), tool_call_id: None, tool_calls: None }
                }).collect();
            }
        }

        let tools = self.tool_registry.definitions();
        let mut total_tokens: u32 = 0;
        let mut tool_calls_made: usize = 0;

        for _ in 0..MAX_ITERATIONS {
            // Check cancellation
            if self.cancel_token.is_cancelled() {
                self.emit(StreamEvent::Cancelled { tool_calls_made }).await;
                return Ok(AgentOutput { content: "Cancelled.".into(), tool_calls_made, tokens_used: total_tokens });
            }

            // Think: send to LLM with retry
            let response = self.send_with_retry(&tools).await?;

            total_tokens += response.tokens_used;

            // If no tool calls, we're done — return content
            if response.tool_calls.is_empty() {
                self.messages.push(StandardMessage::assistant(&response.content));

                // Store as fact if response is substantial (>100 chars)
                if response.content.len() > 100 {
                    let fact = Fact {
                        id: uuid::Uuid::new_v4(),
                        content: response.content.clone(),
                        category: FactCategory::Fact,
                        created_at: chrono::Utc::now(),
                        last_accessed_at: chrono::Utc::now(),
                        embedding: None,
                    };
                    let _ = self.context_manager.store_fact(self.agent_id, fact).await;
                }

                let output = AgentOutput {
                    content: response.content,
                    tool_calls_made,
                    tokens_used: total_tokens,
                };
                self.emit(StreamEvent::Done(output.clone())).await;
                self.save_conversation();
                return Ok(output);
            }

            // Act: execute tool calls
            let mut assistant_msg = StandardMessage::assistant(&response.content);
            assistant_msg.tool_calls = Some(response.tool_calls.clone());
            self.messages.push(assistant_msg);

            for tool_call in &response.tool_calls {
                if self.cancel_token.is_cancelled() {
                    self.emit(StreamEvent::Cancelled { tool_calls_made }).await;
                    return Ok(AgentOutput { content: "Cancelled.".into(), tool_calls_made, tokens_used: total_tokens });
                }
                tool_calls_made += 1;
                self.emit(StreamEvent::ToolCallStarted {
                    name: tool_call.name.clone(),
                    arguments: tool_call.arguments.to_string(),
                }).await;
                let result = self.execute_tool(tool_call).await;
                self.emit(StreamEvent::ToolCallResult {
                    name: tool_call.name.clone(),
                    result: result.chars().take(200).collect(),
                }).await;
                self.messages.push(StandardMessage::tool_result(&tool_call.id, &result));
            }
        }

        // Max iterations reached
        Ok(AgentOutput {
            content: "I've reached the maximum number of tool call iterations. Here's what I've done so far.".to_string(),
            tool_calls_made,
            tokens_used: total_tokens,
        })
    }

    /// Send to LLM with retry (3 attempts, exponential backoff).
    async fn send_with_retry(&self, tools: &[crate::connector::ToolDefinition]) -> Result<crate::connector::LlmResponse, KernelError> {
        let mut last_err = None;
        for attempt in 0..LLM_RETRIES {
            if attempt > 0 {
                tokio::time::sleep(tokio::time::Duration::from_millis(500 * (1 << attempt))).await;
            }
            match self.session.send_streaming(self.messages.clone(), tools).await {
                Ok(response) => return Ok(response),
                Err(e) => { last_err = Some(e); }
            }
        }
        Err(KernelError::Connector(last_err.unwrap()))
    }

    /// Execute a tool call, returning the result string (or error message for LLM recovery).
    async fn execute_tool(&self, tool_call: &crate::connector::ToolCall) -> String {
        match self.tool_registry.resolve(self.agent_id, tool_call) {
            Some(request) => {
                match self.resource_broker.execute(request).await {
                    Ok(resp) if resp.success => {
                        serde_json::to_string(&resp.data).unwrap_or_default()
                    }
                    Ok(resp) => {
                        format!("Tool '{}' failed: {}. Try a different approach.", tool_call.name, resp.error.unwrap_or_default())
                    }
                    Err(e) => {
                        format!("Tool '{}' error: {}. Try a different approach or tool.", tool_call.name, e)
                    }
                }
            }
            None => format!("Unknown tool '{}'. Available tools: {}", tool_call.name,
                self.tool_registry.definitions().iter().map(|t| t.name.as_str()).collect::<Vec<_>>().join(", ")),
        }
    }

    /// Get the current message history.
    pub fn messages(&self) -> &[StandardMessage] {
        &self.messages
    }

    /// Save the current conversation to SQLite.
    fn save_conversation(&self) {
        let _ = self.context_manager.save_conversation(&self.conversation_id, self.agent_id, &self.messages);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connector::{LlmResponse, ToolCall, ToolDefinition};
    use crate::{ConnectorError, ResourceError};
    use crate::resources::{ResourceResponse, ResourceCapability, ResourceProvider};
    use crate::permissions::PermissionManager;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn mock_context_manager() -> Arc<SqliteContextManager> {
        Arc::new(SqliteContextManager::in_memory().unwrap())
    }

    /// Mock LLM session that returns tool calls on first call, then content.
    struct MockToolSession {
        call_count: AtomicUsize,
        id: String,
    }

    #[async_trait::async_trait]
    impl LlmSession for MockToolSession {
        async fn send(&self, messages: Vec<StandardMessage>) -> Result<LlmResponse, ConnectorError> {
            self.send_with_tools(messages, &[]).await
        }
        async fn send_with_tools(&self, _messages: Vec<StandardMessage>, _tools: &[ToolDefinition]) -> Result<LlmResponse, ConnectorError> {
            let count = self.call_count.fetch_add(1, Ordering::SeqCst);
            if count == 0 {
                Ok(LlmResponse {
                    content: "".into(),
                    finish_reason: Some("tool_calls".into()),
                    tokens_used: 20,
                    tool_calls: vec![ToolCall {
                        id: "call_1".into(),
                        name: "read_file".into(),
                        arguments: serde_json::json!({"path": "/tmp/test.txt"}),
                    }],
                })
            } else {
                Ok(LlmResponse {
                    content: "The file contains: hello world".into(),
                    finish_reason: Some("stop".into()),
                    tokens_used: 15,
                    tool_calls: vec![],
                })
            }
        }
        fn provider_id(&self) -> &crate::ProviderId { &self.id }
    }

    /// Mock session that always returns tool calls (for testing max iterations).
    struct InfiniteToolSession { id: String }

    #[async_trait::async_trait]
    impl LlmSession for InfiniteToolSession {
        async fn send(&self, messages: Vec<StandardMessage>) -> Result<LlmResponse, ConnectorError> {
            self.send_with_tools(messages, &[]).await
        }
        async fn send_with_tools(&self, _messages: Vec<StandardMessage>, _tools: &[ToolDefinition]) -> Result<LlmResponse, ConnectorError> {
            Ok(LlmResponse {
                content: "".into(),
                finish_reason: Some("tool_calls".into()),
                tokens_used: 5,
                tool_calls: vec![ToolCall { id: "call_x".into(), name: "read_file".into(), arguments: serde_json::json!({"path": "/x"}) }],
            })
        }
        fn provider_id(&self) -> &crate::ProviderId { &self.id }
    }

    fn mock_broker() -> Arc<dyn ResourceBroker> {
        use crate::resources::ResourceBrokerImpl;
        let perms = Arc::new(PermissionManager::new());
        let broker = ResourceBrokerImpl::new(perms.clone());
        // Register a mock filesystem provider
        struct MockFs;
        #[async_trait::async_trait]
        impl ResourceProvider for MockFs {
            fn resource_type(&self) -> crate::resources::ResourceType { crate::resources::ResourceType::Filesystem }
            fn supported_operations(&self) -> Vec<String> { vec!["read".into(), "write".into(), "list".into()] }
            async fn execute(&self, _op: &str, _params: &serde_json::Value) -> Result<serde_json::Value, ResourceError> {
                Ok(serde_json::json!({"content": "hello world"}))
            }
        }
        broker.register_provider(Box::new(MockFs));
        Arc::new(broker)
    }

    #[tokio::test]
    async fn execution_loop_with_tool_call() {
        let session = Box::new(MockToolSession { call_count: AtomicUsize::new(0), id: "mock".into() });
        let broker = mock_broker();
        let registry = Arc::new(ToolRegistry::new());

        let mut executor = AgentExecutor::new(
            uuid::Uuid::new_v4(), session, broker, registry, mock_context_manager(), "You are a helpful assistant.".into(),
        );

        let output = executor.run("Read /tmp/test.txt").await.unwrap();
        assert_eq!(output.content, "The file contains: hello world");
        assert_eq!(output.tool_calls_made, 1);
        assert_eq!(output.tokens_used, 35);
    }

    #[tokio::test]
    async fn execution_loop_caps_at_max_iterations() {
        let session = Box::new(InfiniteToolSession { id: "mock".into() });
        let broker = mock_broker();
        let registry = Arc::new(ToolRegistry::new());

        let mut executor = AgentExecutor::new(
            uuid::Uuid::new_v4(), session, broker, registry, mock_context_manager(), "You are a helpful assistant.".into(),
        );

        let output = executor.run("Do something forever").await.unwrap();
        assert_eq!(output.tool_calls_made, MAX_ITERATIONS);
        assert!(output.content.contains("maximum"));
    }

    /// Mock session that fails twice then succeeds (tests LLM retry).
    struct FailThenSucceedSession { call_count: AtomicUsize, id: String }

    #[async_trait::async_trait]
    impl LlmSession for FailThenSucceedSession {
        async fn send(&self, messages: Vec<StandardMessage>) -> Result<LlmResponse, ConnectorError> {
            self.send_with_tools(messages, &[]).await
        }
        async fn send_with_tools(&self, _messages: Vec<StandardMessage>, _tools: &[ToolDefinition]) -> Result<LlmResponse, ConnectorError> {
            let count = self.call_count.fetch_add(1, Ordering::SeqCst);
            if count < 2 {
                Err(ConnectorError::ConnectionFailed("server error".into()))
            } else {
                Ok(LlmResponse { content: "recovered!".into(), finish_reason: Some("stop".into()), tokens_used: 10, tool_calls: vec![] })
            }
        }
        fn provider_id(&self) -> &crate::ProviderId { &self.id }
    }

    #[tokio::test]
    async fn llm_retry_recovers_from_transient_failure() {
        let session = Box::new(FailThenSucceedSession { call_count: AtomicUsize::new(0), id: "mock".into() });
        let broker = mock_broker();
        let registry = Arc::new(ToolRegistry::new());

        let mut executor = AgentExecutor::new(
            uuid::Uuid::new_v4(), session, broker, registry, mock_context_manager(), "test".into(),
        );

        let output = executor.run("test").await.unwrap();
        assert_eq!(output.content, "recovered!");
    }

    /// Mock session that calls a nonexistent tool — tests error recovery message to LLM.
    struct BadToolSession { call_count: AtomicUsize, id: String }

    #[async_trait::async_trait]
    impl LlmSession for BadToolSession {
        async fn send(&self, messages: Vec<StandardMessage>) -> Result<LlmResponse, ConnectorError> {
            self.send_with_tools(messages, &[]).await
        }
        async fn send_with_tools(&self, messages: Vec<StandardMessage>, _tools: &[ToolDefinition]) -> Result<LlmResponse, ConnectorError> {
            let count = self.call_count.fetch_add(1, Ordering::SeqCst);
            if count == 0 {
                // First call: return a bad tool call
                Ok(LlmResponse {
                    content: "".into(), finish_reason: Some("tool_calls".into()), tokens_used: 10,
                    tool_calls: vec![ToolCall { id: "c1".into(), name: "nonexistent_tool".into(), arguments: serde_json::json!({}) }],
                })
            } else {
                // Second call: LLM sees the error and responds with content
                // Verify the error message was passed back
                let last_msg = messages.last().unwrap();
                assert!(last_msg.content.contains("Unknown tool"));
                assert!(last_msg.content.contains("read_file")); // suggests available tools
                Ok(LlmResponse { content: "Sorry, let me try differently.".into(), finish_reason: Some("stop".into()), tokens_used: 8, tool_calls: vec![] })
            }
        }
        fn provider_id(&self) -> &crate::ProviderId { &self.id }
    }

    #[tokio::test]
    async fn tool_failure_sends_error_back_to_llm() {
        let session = Box::new(BadToolSession { call_count: AtomicUsize::new(0), id: "mock".into() });
        let broker = mock_broker();
        let registry = Arc::new(ToolRegistry::new());

        let mut executor = AgentExecutor::new(
            uuid::Uuid::new_v4(), session, broker, registry, mock_context_manager(), "test".into(),
        );

        let output = executor.run("use a bad tool").await.unwrap();
        assert_eq!(output.content, "Sorry, let me try differently.");
        assert_eq!(output.tool_calls_made, 1);
    }

    #[tokio::test]
    async fn memory_stored_and_queried_across_runs() {
        let ctx_mgr = mock_context_manager();
        let agent_id = uuid::Uuid::new_v4();

        // Store a fact manually
        let fact = Fact {
            id: uuid::Uuid::new_v4(),
            content: "User prefers dark mode theme".to_string(),
            category: FactCategory::Preference,
            created_at: chrono::Utc::now(),
            last_accessed_at: chrono::Utc::now(),
            embedding: None,
        };
        ctx_mgr.store_fact(agent_id, fact).await.unwrap();

        // Query and verify it appears
        let results = ctx_mgr.query_memory(agent_id, "dark mode").await.unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].content.contains("dark mode"));
    }

    /// Mock session that returns a long response (>100 chars) to trigger fact storage.
    struct LongResponseSession { id: String }

    #[async_trait::async_trait]
    impl LlmSession for LongResponseSession {
        async fn send(&self, messages: Vec<StandardMessage>) -> Result<LlmResponse, ConnectorError> {
            self.send_with_tools(messages, &[]).await
        }
        async fn send_with_tools(&self, _messages: Vec<StandardMessage>, _tools: &[ToolDefinition]) -> Result<LlmResponse, ConnectorError> {
            Ok(LlmResponse {
                content: "This is a very long response that exceeds one hundred characters in length so it will be stored as a fact in long-term memory for future reference.".into(),
                finish_reason: Some("stop".into()),
                tokens_used: 30,
                tool_calls: vec![],
            })
        }
        fn provider_id(&self) -> &crate::ProviderId { &self.id }
    }

    #[tokio::test]
    async fn long_response_stored_as_fact() {
        let ctx_mgr = mock_context_manager();
        let agent_id = uuid::Uuid::new_v4();
        let session = Box::new(LongResponseSession { id: "mock".into() });
        let broker = mock_broker();
        let registry = Arc::new(ToolRegistry::new());

        let mut executor = AgentExecutor::new(
            agent_id, session, broker, registry, ctx_mgr.clone(), "test".into(),
        );

        executor.run("tell me something").await.unwrap();

        // Verify fact was stored
        let facts = ctx_mgr.query_memory(agent_id, "long-term memory").await.unwrap();
        assert_eq!(facts.len(), 1);
    }

    /// Mock session for summarization test — tracks messages received.
    struct SummarizationSession { id: String, msg_count: AtomicUsize }

    #[async_trait::async_trait]
    impl LlmSession for SummarizationSession {
        async fn send(&self, messages: Vec<StandardMessage>) -> Result<LlmResponse, ConnectorError> {
            self.send_with_tools(messages, &[]).await
        }
        async fn send_with_tools(&self, messages: Vec<StandardMessage>, _tools: &[ToolDefinition]) -> Result<LlmResponse, ConnectorError> {
            self.msg_count.store(messages.len(), Ordering::SeqCst);
            Ok(LlmResponse { content: "ok".into(), finish_reason: Some("stop".into()), tokens_used: 5, tool_calls: vec![] })
        }
        fn provider_id(&self) -> &crate::ProviderId { &self.id }
    }

    #[tokio::test]
    async fn summarization_triggers_when_messages_exceed_threshold() {
        let ctx_mgr = mock_context_manager();
        let agent_id = uuid::Uuid::new_v4();
        let session = Box::new(SummarizationSession { id: "mock".into(), msg_count: AtomicUsize::new(0) });
        let broker = mock_broker();
        let registry = Arc::new(ToolRegistry::new());

        let mut executor = AgentExecutor::new(
            agent_id, session, broker, registry, ctx_mgr, "test".into(),
        );

        // Manually fill messages to exceed threshold
        for i in 0..MESSAGE_OVERFLOW_THRESHOLD {
            executor.messages.push(StandardMessage::user(format!("message {}", i)));
        }

        // Run should trigger summarization
        executor.run("final message").await.unwrap();

        // After summarization, message count should be less than what we started with
        assert!(executor.messages().len() < MESSAGE_OVERFLOW_THRESHOLD + 3);
    }
}
