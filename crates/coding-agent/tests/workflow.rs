use agent_sdk::KernelClient;
use async_trait::async_trait;
use coding_agent::io::JobIo;
use coding_agent::provider::ProposalProvider;
use coding_agent::types::*;
use coding_agent::{run_job, Error, TestRunner};
use kernel::connector::{
    LlmProviderAdapter, LlmRequestOptions, LlmResponse, LlmSession, LlmUsage, ProviderCapabilities,
    ProviderType, StandardMessage, ToolDefinition,
};
use kernel::ConnectorError;
use kernel::{AgentConfig, AgentKernelImpl, Priority};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

fn files() -> BTreeMap<String, String> {
    [
        (
            "Cargo.toml",
            include_str!("../../../fixtures/coding-agent/utf8-budget/Cargo.toml"),
        ),
        (
            "Cargo.lock",
            include_str!("../../../fixtures/coding-agent/utf8-budget/Cargo.lock"),
        ),
        (
            "src/lib.rs",
            include_str!("../../../fixtures/coding-agent/utf8-budget/src/lib.rs"),
        ),
        (
            "tests/utf8_budget.rs",
            include_str!("../../../fixtures/coding-agent/utf8-budget/tests/utf8_budget.rs"),
        ),
    ]
    .into_iter()
    .map(|(path, text)| (path.into(), text.into()))
    .collect()
}
fn spec() -> TaskSpec {
    TaskSpec {
        instruction: "Fix UTF-8 byte budgeting".into(),
        files: files().into_keys().collect(),
        editable: vec!["src/lib.rs".into()],
        test_target: "utf8_budget".into(),
        max_branches: 2,
        max_steps: 1024,
        deadline_seconds: 600,
        max_usd: 0.01,
        max_output_tokens: 2048,
    }
}
struct Harness {
    kernel: Arc<AgentKernelImpl>,
    addr: std::net::SocketAddr,
    server: tokio::task::JoinHandle<std::io::Result<()>>,
}
impl Harness {
    async fn release_store(mut self) {
        let context = Arc::downgrade(&self.kernel.context_manager);
        self.server.abort();
        assert!((&mut self.server).await.unwrap_err().is_cancelled());
        drop(self);
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while context.strong_count() != 0 {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("server connection tasks must release the durable context");
    }

    async fn new(kernel: Arc<AgentKernelImpl>) -> Self {
        Self::with_provider(kernel, Arc::new(ProposalProvider::fixture())).await
    }

    async fn with_provider(
        kernel: Arc<AgentKernelImpl>,
        provider: Arc<dyn LlmProviderAdapter>,
    ) -> Self {
        kernel.register_provider(provider).unwrap();
        let server = kernel::syscall_server::SyscallServer::bind(kernel.clone(), "127.0.0.1:0")
            .await
            .unwrap();
        let addr = server.local_addr().unwrap();
        Self {
            kernel,
            addr,
            server: tokio::spawn(server.serve()),
        }
    }
    async fn clients(&self, journal: &Journal, cancel: CancellationToken) -> JobIo {
        JobIo::new(
            KernelClient::connect(self.addr).await.unwrap(),
            KernelClient::connect(self.addr).await.unwrap(),
            journal,
            cancel,
        )
    }
    async fn create_job(&self) -> (Journal, JobIo) {
        let parent = self
            .kernel
            .create_agent_full(AgentConfig {
                name: "coding coordinator".into(),
                task: "fix fixture".into(),
                llm_provider: "coding".into(),
                permission_profile: "standard".into(),
                priority: Priority::default(),
                sandbox_config: None,
            })
            .await
            .unwrap()
            .id;
        let mut journal = Journal {
            version: JOURNAL_VERSION,
            id: Uuid::new_v4(),
            parent,
            spec: spec(),
            image: "contract fixture; no process".into(),
            mode: "fixture".into(),
            model: None,
            created: chrono::Utc::now(),
            files: files(),
            branches: vec![],
            events: vec![],
            steps: 0,
            provider_tokens: 0,
            selected: None,
            status: "captured".into(),
        };
        let mut io = self.clients(&journal, CancellationToken::new()).await;
        for directory in ["src", "tests"] {
            io.mkdir(parent, directory).await.unwrap();
        }
        for (path, content) in &journal.files {
            io.write_file(parent, path, content).await.unwrap();
        }
        io.persist(&mut journal).await.unwrap();
        (journal, io)
    }
}
impl Drop for Harness {
    fn drop(&mut self) {
        self.server.abort();
    }
}

struct ContractRunner;

struct FailingProposalProvider {
    id: String,
    calls: Arc<AtomicUsize>,
}

#[async_trait]
impl LlmSession for FailingProposalProvider {
    async fn send(&self, messages: Vec<StandardMessage>) -> Result<LlmResponse, ConnectorError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if messages
            .iter()
            .any(|message| message.content.contains("candidate="))
        {
            return Err(ConnectorError::ProtocolError(
                "controlled proposal provider failure".into(),
            ));
        }
        Ok(LlmResponse {
            content: "{\"edits\":[]}".into(),
            finish_reason: Some("stop".into()),
            tokens_used: 3,
            usage: LlmUsage::reported(2, 1, 0),
            tool_calls: Vec::new(),
            provider_metadata: None,
        })
    }
    async fn send_with_tools(
        &self,
        messages: Vec<StandardMessage>,
        _: &[ToolDefinition],
    ) -> Result<LlmResponse, ConnectorError> {
        self.send(messages).await
    }
    async fn send_with_options(
        &self,
        messages: Vec<StandardMessage>,
        tools: &[ToolDefinition],
        options: LlmRequestOptions,
    ) -> Result<LlmResponse, ConnectorError> {
        assert!(options.max_output_tokens.is_some_and(|limit| limit >= 3));
        self.send_with_tools(messages, tools).await
    }
    fn provider_id(&self) -> &String {
        &self.id
    }
    fn model_id(&self) -> &str {
        "controlled-coding-failure"
    }
    fn enforces_max_output_tokens(&self) -> bool {
        true
    }
}

#[async_trait]
impl LlmProviderAdapter for FailingProposalProvider {
    fn id(&self) -> &String {
        &self.id
    }
    fn name(&self) -> &str {
        "controlled coding failure"
    }
    fn provider_type(&self) -> ProviderType {
        ProviderType::Local
    }
    fn capabilities(&self) -> ProviderCapabilities {
        ProviderCapabilities {
            tool_calls: true,
            ..Default::default()
        }
    }
    async fn is_available(&self) -> bool {
        true
    }
    async fn create_session(&self) -> Result<Box<dyn LlmSession>, ConnectorError> {
        Ok(Box::new(Self {
            id: self.id.clone(),
            calls: self.calls.clone(),
        }))
    }
    fn translate_to_provider(&self, message: &StandardMessage) -> serde_json::Value {
        serde_json::to_value(message).unwrap()
    }
    fn translate_from_provider(&self, value: &serde_json::Value) -> Option<StandardMessage> {
        serde_json::from_value(value.clone()).ok()
    }
}

struct MustNotRun(Arc<AtomicUsize>);

#[async_trait]
impl TestRunner for MustNotRun {
    async fn run(&self, _: &mut JobIo, _: Uuid, _: Uuid) -> Result<TestEvidence, Error> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Err(Error::Contract(
            "tests must not start after provider failure".into(),
        ))
    }
}

#[tokio::test]
async fn provider_failure_reclaims_speculative_branch_and_preserves_original_files() {
    let provider_calls = Arc::new(AtomicUsize::new(0));
    let runner_calls = Arc::new(AtomicUsize::new(0));
    let h = Harness::with_provider(
        Arc::new(AgentKernelImpl::new().unwrap()),
        Arc::new(FailingProposalProvider {
            id: "coding".into(),
            calls: provider_calls.clone(),
        }),
    )
    .await;
    let (mut journal, mut io) = h.create_job().await;
    let result = run_job(
        &mut io,
        &mut journal,
        &MustNotRun(runner_calls.clone()),
        false,
        false,
    )
    .await;
    assert!(result.is_err());
    assert_eq!(
        provider_calls.load(Ordering::SeqCst),
        2,
        "baseline and actual speculative provider failure must both execute"
    );
    assert_eq!(runner_calls.load(Ordering::SeqCst), 0);
    assert_eq!(journal.status, "failed");
    assert!(journal.selected.is_none());
    assert_eq!(journal.branches.len(), 1);
    let child = journal.branches[0].id;
    assert!(journal.branches[0].owned);
    assert_eq!(journal.branches[0].phase, Phase::Discarded);
    assert!(journal.branches[0].test.is_none());
    assert!(h
        .kernel
        .context_manager
        .agent_tenant(child)
        .unwrap()
        .is_none());
    assert_eq!(h.kernel.context_manager.load_all_agents().unwrap().len(), 1);
    for (path, original) in &journal.files {
        assert_eq!(io.read_file(journal.parent, path).await.unwrap(), *original);
    }
    let retained = JobIo::load(&mut io.control, journal.parent, journal.id)
        .await
        .unwrap();
    assert_eq!(retained.status, "failed");
    assert_eq!(retained.branches[0].phase, Phase::Discarded);
    assert!(retained
        .events
        .iter()
        .any(|event| event.agent == child && event.action == "failed"));
    assert!(retained
        .events
        .iter()
        .all(|event| event.action != "test_started" && event.action != "test_completed"));
    io.client.close().await.unwrap();
    io.control.close().await.unwrap();
    h.kernel.stop_agent(journal.parent).await.unwrap();
}
#[async_trait]
impl TestRunner for ContractRunner {
    async fn run(
        &self,
        io: &mut JobIo,
        agent: Uuid,
        operation_id: Uuid,
    ) -> Result<TestEvidence, Error> {
        let source = io.read_file(agent, "src/lib.rs").await?;
        let good: Proposal = serde_json::from_str(include_str!(
            "../../../fixtures/coding-agent/utf8-budget/good-utf8-boundaries.json"
        ))?;
        Ok(TestEvidence {
            operation_id,
            kind: "contract_fixture".into(),
            tool: "scripted contract; process not run".into(),
            exit_code: if source == good.edits[0].replacement {
                0
            } else {
                101
            },
            duration_ms: 0,
            stdout: String::new(),
            stderr: String::new(),
        })
    }
}

#[tokio::test]
async fn public_wire_selects_the_passing_branch_and_reclaims_the_failure() {
    let h = Harness::new(Arc::new(AgentKernelImpl::new().unwrap())).await;
    let (mut j, mut io) = h.create_job().await;
    run_job(&mut io, &mut j, &ContractRunner, false, false)
        .await
        .unwrap();
    assert_eq!(j.status, "completed");
    assert_eq!(j.branches.len(), 2);
    assert_eq!(j.branches[0].phase, Phase::Discarded);
    assert_eq!(j.branches[0].test.as_ref().unwrap().exit_code, 101);
    assert_eq!(j.selected, Some(j.branches[1].id));
    assert!(h
        .kernel
        .context_manager
        .agent_tenant(j.branches[0].id)
        .unwrap()
        .is_none());
    for (path, contents) in &j.files {
        assert_eq!(io.read_file(j.parent, path).await.unwrap(), *contents);
    }
    let stored = JobIo::load(&mut io.control, j.parent, j.id).await.unwrap();
    assert_eq!(stored.selected, j.selected);
    assert!(stored
        .events
        .iter()
        .any(|event| event.action == "discarded"));
    assert!(stored
        .branches
        .iter()
        .flat_map(|branch| branch.test.iter())
        .all(|test| test.kind == "contract_fixture"));
    let calls = stored.provider_tokens;
    run_job(&mut io, &mut j, &ContractRunner, false, false)
        .await
        .unwrap();
    assert_eq!(
        j.provider_tokens, calls,
        "completed effects must not replay"
    );
    io.client.close().await.unwrap();
    io.control.close().await.unwrap();
    h.kernel.stop_agent(j.parent).await.unwrap();
    h.kernel.stop_agent(j.selected.unwrap()).await.unwrap();
}

#[tokio::test]
async fn durable_pause_resumes_after_the_discarded_branch_without_repeating_it() {
    let h = Harness::new(Arc::new(AgentKernelImpl::new().unwrap())).await;
    let (mut j, mut io) = h.create_job().await;
    assert!(matches!(
        run_job(&mut io, &mut j, &ContractRunner, false, true).await,
        Err(Error::Paused)
    ));
    assert_eq!(j.branches[0].phase, Phase::Discarded);
    let discarded = j.branches[0].id;
    io.client.close().await.unwrap();
    io.control.close().await.unwrap();
    let mut reader = KernelClient::connect(h.addr).await.unwrap();
    let mut j = JobIo::load(&mut reader, j.parent, j.id).await.unwrap();
    reader.close().await.unwrap();
    let mut io = h.clients(&j, CancellationToken::new()).await;
    run_job(&mut io, &mut j, &ContractRunner, false, false)
        .await
        .unwrap();
    assert_eq!(j.branches[0].id, discarded);
    assert_eq!(j.branches.len(), 2);
    assert!(h
        .kernel
        .context_manager
        .agent_tenant(discarded)
        .unwrap()
        .is_none());
    io.client.close().await.unwrap();
    io.control.close().await.unwrap();
    h.kernel.stop_agent(j.parent).await.unwrap();
    h.kernel.stop_agent(j.selected.unwrap()).await.unwrap();
}

#[tokio::test]
async fn uncertain_tests_are_not_implicitly_reexecuted() {
    let h = Harness::new(Arc::new(AgentKernelImpl::new().unwrap())).await;
    let (mut j, mut io) = h.create_job().await;
    assert!(matches!(
        run_job(&mut io, &mut j, &ContractRunner, false, true).await,
        Err(Error::Paused)
    ));
    j.branches[0].phase = Phase::Testing;
    io.persist(&mut j).await.unwrap();
    assert!(matches!(
        run_job(&mut io, &mut j, &ContractRunner, false, false).await,
        Err(Error::Uncertain(_))
    ));
    assert_eq!(j.branches.len(), 1);
    io.client.close().await.unwrap();
    io.control.close().await.unwrap();
    h.kernel.stop_agent(j.parent).await.unwrap();
}

#[test]
fn proposals_cannot_change_tests_credentials_dependencies_or_unknown_files() {
    let task = spec();
    for path in [
        "../escape.rs",
        "/host.rs",
        ".env",
        "tests/utf8_budget.rs",
        "Cargo.toml",
        "unknown.rs",
    ] {
        let proposal = Proposal {
            edits: vec![FileEdit {
                path: path.into(),
                expected_sha256: "f".repeat(64),
                replacement: "modified".into(),
            }],
        };
        assert!(proposal.validate(&task, &files()).is_err());
    }
    let good: Proposal = serde_json::from_str(include_str!(
        "../../../fixtures/coding-agent/utf8-budget/good-utf8-boundaries.json"
    ))
    .unwrap();
    good.validate(&task, &files()).unwrap();
    let mut wrong = good;
    wrong.edits[0].expected_sha256 = "0".repeat(64);
    assert!(wrong.validate(&task, &files()).is_err());
}

#[test]
fn a_budget_that_rounds_to_the_unlimited_sentinel_is_rejected() {
    let mut task = spec();
    task.max_usd = 0.000000001;
    assert!(task.validate().is_err());
    task.max_usd = 0.000001;
    task.validate().unwrap();
}

#[tokio::test]
async fn managed_application_bootstrap_never_claims_the_supplied_operator_directory() {
    let original = std::env::temp_dir().join(format!("coding-original-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&original).unwrap();
    std::fs::write(original.join("untouched.txt"), "user changes").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&original, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let kernel = AgentKernelImpl::new().unwrap();
    let mut sandbox = kernel::sandbox::SandboxManagerImpl::default_config();
    sandbox.workspace_dir = original.clone();
    let id = kernel
        .create_agent_with_managed_sandbox(
            AgentConfig {
                name: "owned application".into(),
                task: "isolated task".into(),
                llm_provider: "coding".into(),
                permission_profile: "standard".into(),
                priority: Priority::default(),
                sandbox_config: None,
            },
            sandbox,
        )
        .await
        .unwrap()
        .id;
    let workspace = kernel
        .agent_manager
        .get_agent_config(id)
        .unwrap()
        .sandbox_config
        .unwrap()
        .workspace_dir;
    assert_ne!(workspace, original);
    assert!(!workspace.join("untouched.txt").exists());
    kernel.stop_agent(id).await.unwrap();
    assert!(!workspace.exists());
    assert_eq!(
        std::fs::read_to_string(original.join("untouched.txt")).unwrap(),
        "user changes"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&original).unwrap().permissions().mode() & 0o777,
            0o755
        );
    }
    std::fs::remove_dir_all(original).unwrap();
}

struct WaitingRunner {
    entered: Arc<tokio::sync::Notify>,
}
#[async_trait]
impl TestRunner for WaitingRunner {
    async fn run(
        &self,
        io: &mut JobIo,
        _agent: Uuid,
        _operation: Uuid,
    ) -> Result<TestEvidence, Error> {
        self.entered.notify_one();
        io.cancel.cancelled().await;
        Err(Error::Cancelled)
    }
}

#[tokio::test]
async fn cancellation_reclaims_the_active_owned_branch_and_retains_the_journal() {
    let h = Harness::new(Arc::new(AgentKernelImpl::new().unwrap())).await;
    let (mut j, mut io) = h.create_job().await;
    let cancel = io.cancel.clone();
    let entered = Arc::new(tokio::sync::Notify::new());
    let runner = WaitingRunner {
        entered: entered.clone(),
    };
    let preparation_deadline = std::time::Duration::from_secs(j.spec.deadline_seconds);
    let mut run = tokio::spawn(async move {
        let result = run_job(&mut io, &mut j, &runner, false, false).await;
        io.client.close().await.unwrap();
        io.control.close().await.unwrap();
        (result, j)
    });
    // Preparation includes durable cloning, provider admission and VFS writes;
    // its bound is the configured job deadline. Cancellation is measured only
    // after the controlled runner is active, with the original five-second cap.
    tokio::select! {
        _ = entered.notified() => {}
        result = &mut run => panic!("job completed before the controlled runner: {result:?}"),
        _ = tokio::time::sleep(preparation_deadline) => {
            cancel.cancel();
            run.abort();
            panic!("job preparation exceeded its configured deadline");
        }
    }
    cancel.cancel();
    let (result, j) = tokio::time::timeout(std::time::Duration::from_secs(5), run)
        .await
        .expect("active cancellation must reclaim the owned branch within five seconds")
        .unwrap();
    assert!(matches!(result, Err(Error::Cancelled)));
    assert_eq!(j.status, "cancelled");
    assert!(j
        .branches
        .iter()
        .all(|branch| branch.phase == Phase::Discarded));
    assert_eq!(h.kernel.context_manager.load_all_agents().unwrap().len(), 1);
    let mut reader = KernelClient::connect(h.addr).await.unwrap();
    assert_eq!(
        JobIo::load(&mut reader, j.parent, j.id)
            .await
            .unwrap()
            .status,
        "cancelled"
    );
    reader.close().await.unwrap();
    h.kernel.stop_agent(j.parent).await.unwrap();
}

#[tokio::test]
async fn request_budget_exhaustion_leaves_no_live_or_durable_child() {
    let h = Harness::new(Arc::new(AgentKernelImpl::new().unwrap())).await;
    let (mut j, old) = h.create_job().await;
    let primary = old.client;
    let control = old.control;
    primary.close().await.unwrap();
    control.close().await.unwrap();
    j.spec.max_steps = 32;
    let mut io = h.clients(&j, CancellationToken::new()).await;
    assert!(matches!(
        run_job(&mut io, &mut j, &ContractRunner, false, false).await,
        Err(Error::Budget(_))
    ));
    assert_eq!(h.kernel.context_manager.load_all_agents().unwrap().len(), 1);
    assert!(j.selected.is_none());
    for (path, original) in &j.files {
        let handle = io
            .control
            .vfs_open_workspace(
                j.parent.to_string(),
                agent_sdk::WorkspaceOpenRequest {
                    path: format!("/workspace/{path}"),
                    kind: agent_sdk::WorkspaceKind::File,
                    rights: vec![agent_sdk::WorkspaceRight::Read],
                    allow_missing: false,
                },
            )
            .await
            .unwrap();
        let bytes = io
            .control
            .vfs_read_bytes(j.parent.to_string(), &handle.id, 0, 32768)
            .await
            .unwrap();
        assert_eq!(bytes.bytes, original.as_bytes());
        io.control
            .vfs_close(j.parent.to_string(), &handle.id)
            .await
            .unwrap();
    }
    io.client.close().await.unwrap();
    io.control.close().await.unwrap();
    h.kernel.stop_agent(j.parent).await.unwrap();
}

#[tokio::test]
async fn optional_reads_distinguish_absence_from_existing_files_through_directory_handles() {
    let h = Harness::new(Arc::new(AgentKernelImpl::new().unwrap())).await;
    let (j, mut io) = h.create_job().await;
    assert_eq!(
        io.read_optional_file(j.parent, "src/lib.rs").await.unwrap(),
        Some(j.files["src/lib.rs"].clone())
    );
    assert_eq!(
        io.read_optional_file(j.parent, "src/absent.rs")
            .await
            .unwrap(),
        None
    );
    assert!(io
        .read_optional_file(j.parent, "../outside.rs")
        .await
        .is_err());
    io.client.close().await.unwrap();
    io.control.close().await.unwrap();
    h.kernel.stop_agent(j.parent).await.unwrap();
}

#[tokio::test]
async fn speculative_branch_cannot_gain_network_or_escape_workspace_authority() {
    let h = Harness::new(Arc::new(AgentKernelImpl::new().unwrap())).await;
    let (j, mut io) = h.create_job().await;
    let child = Uuid::new_v4();
    io.client
        .clone_agent(
            j.parent.to_string(),
            child,
            "denied probe",
            vec!["CAP_NET_ACCESS".into()],
        )
        .await
        .unwrap();
    let network = io
        .client
        .vfs_open(child.to_string(), "/tools/http_get")
        .await
        .unwrap();
    let denied = io
        .client
        .vfs_invoke(
            child.to_string(),
            &network.id,
            serde_json::json!({"url":"https://example.com"}),
        )
        .await
        .unwrap_err();
    assert_eq!(
        denied.wire_code(),
        Some(agent_sdk::WireErrorCode::PermissionDenied)
    );
    assert!(io
        .client
        .vfs_open_workspace(
            child.to_string(),
            agent_sdk::WorkspaceOpenRequest {
                path: "/workspace/../outside".into(),
                kind: agent_sdk::WorkspaceKind::File,
                rights: vec![agent_sdk::WorkspaceRight::Read],
                allow_missing: false,
            }
        )
        .await
        .is_err());
    io.client
        .vfs_close(child.to_string(), &network.id)
        .await
        .unwrap();
    io.control.kill_agent(child.to_string()).await.unwrap();
    io.control
        .erase_agent_data(child, agent_sdk::CONFIRM_DATA_ERASURE)
        .await
        .unwrap();
    io.client.close().await.unwrap();
    io.control.close().await.unwrap();
    h.kernel.stop_agent(j.parent).await.unwrap();
}

#[tokio::test]
async fn a_kernel_restart_resumes_after_a_completed_test_without_replaying_the_failure() {
    let root = std::env::temp_dir().join(format!("coding-restart-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&root).unwrap();
    let path = root.join("store.db");
    let (parent, id, discarded) = {
        let h = Harness::new(Arc::new(AgentKernelImpl::with_db_path(&path).unwrap())).await;
        let (mut j, mut io) = h.create_job().await;
        assert!(matches!(
            run_job(&mut io, &mut j, &ContractRunner, false, true).await,
            Err(Error::Paused)
        ));
        io.client.close().await.unwrap();
        io.control.close().await.unwrap();
        h.kernel.context_manager.checkpoint().unwrap();
        let continuation = (j.parent, j.id, j.branches[0].id);
        h.release_store().await;
        continuation
    };
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(2);
    let kernel = loop {
        match AgentKernelImpl::with_db_path(&path) {
            Ok(kernel) => break kernel,
            Err(error)
                if error.to_string().contains("already owned")
                    && tokio::time::Instant::now() < deadline =>
            {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await
            }
            Err(error) => panic!("restart failed: {error}"),
        }
    };
    let h = Harness::new(Arc::new(kernel)).await;
    let mut reader = KernelClient::connect(h.addr).await.unwrap();
    let mut j = JobIo::load(&mut reader, parent, id).await.unwrap();
    reader.close().await.unwrap();
    let mut io = h.clients(&j, CancellationToken::new()).await;
    assert_eq!(
        io.read_file(parent, "src/lib.rs").await.unwrap(),
        j.files["src/lib.rs"]
    );
    run_job(&mut io, &mut j, &ContractRunner, false, false)
        .await
        .unwrap();
    assert_eq!(j.branches[0].id, discarded);
    assert_eq!(j.branches.len(), 2);
    assert!(h
        .kernel
        .context_manager
        .agent_tenant(discarded)
        .unwrap()
        .is_none());
    io.client.close().await.unwrap();
    io.control.close().await.unwrap();
    h.kernel.stop_agent(parent).await.unwrap();
    h.kernel.stop_agent(j.selected.unwrap()).await.unwrap();
    h.release_store().await;
    std::fs::remove_dir_all(root).unwrap();
}
