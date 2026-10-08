use crate::io::JobIo;
use crate::types::*;
use crate::{hash, Error};
use async_trait::async_trait;
use kernel::tools::{ApprovalPolicy, SecurityAction, ToolBinding, ToolSecurity};
use kernel::AgentKernelImpl;
use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::{Duration, Instant};
use uuid::Uuid;

pub const TEST_TOOL: &str = "coding_tests";
fn branch_name(job: Uuid, index: u32) -> String {
    format!("coding-{job}-{index}")
}
fn drops() -> Vec<String> {
    vec!["CAP_NET_ACCESS".into()]
}

pub fn register_test_tool(kernel: &AgentKernelImpl, target: &str) -> Result<(), Error> {
    kernel.tool_registry.register_command_tool(ToolBinding {
        name: TEST_TOOL.into(), description: "Run the explicitly permitted offline, locked Rust test target".into(),
        parameters_schema: serde_json::json!({"type":"object","properties":{},"additionalProperties":false}),
        resource_type: kernel::resources::ResourceType::Application, operation: "launch".into(),
        security: ToolSecurity::constant(SecurityAction::Execute, "cargo").sandboxed().with_approval(ApprovalPolicy::User),
    }, "cargo", &["test".into(), "--offline".into(), "--locked".into(), "--test".into(), target.into(), "--jobs".into(), "1".into()])
    .map_err(|error| Error::Contract(error.to_string()))
}

#[async_trait]
pub trait TestRunner: Send + Sync {
    async fn run(
        &self,
        io: &mut JobIo,
        agent: Uuid,
        operation_id: Uuid,
    ) -> Result<TestEvidence, Error>;
}
pub struct ProcessRunner {
    pub kernel: Arc<AgentKernelImpl>,
}
#[async_trait]
impl TestRunner for ProcessRunner {
    async fn run(
        &self,
        io: &mut JobIo,
        agent: Uuid,
        operation_id: Uuid,
    ) -> Result<TestEvidence, Error> {
        self.kernel.approve_tool_call(
            agent,
            TEST_TOOL,
            &serde_json::json!({}),
            ApprovalPolicy::User,
        )?;
        let duration = io.step()?;
        let result = JobIo::wait(
            duration,
            io.cancel.clone(),
            io.client
                .vfs_open(agent.to_string(), format!("/tools/{TEST_TOOL}")),
        )
        .await;
        let handle = io.observe(result)?;
        let started = Instant::now();
        let result = async {
            let duration = io.step()?;
            let result = JobIo::wait(
                duration,
                io.cancel.clone(),
                io.client
                    .vfs_invoke(agent.to_string(), &handle.id, serde_json::json!({})),
            )
            .await;
            let value = io.observe(result)?;
            let exit = value["exit_code"]
                .as_i64()
                .and_then(|code| i32::try_from(code).ok())
                .ok_or_else(|| {
                    Error::Contract("test process returned no actual exit status".into())
                })?;
            let stdout = bounded_log(value["stdout"].as_str().unwrap_or(""));
            let stderr = bounded_log(value["stderr"].as_str().unwrap_or(""));
            Ok(TestEvidence {
                operation_id,
                kind: "isolated_process".into(),
                tool: format!("/tools/{TEST_TOOL}"),
                exit_code: exit,
                duration_ms: started.elapsed().as_millis() as u64,
                stdout,
                stderr,
            })
        }
        .await;
        let _ = io.control.vfs_close(agent.to_string(), &handle.id).await;
        if matches!(&result, Err(Error::Cancelled | Error::Budget(_))) {
            let _ = io.control.kill_agent(agent.to_string()).await;
        }
        result
    }
}
fn bounded_log(value: &str) -> String {
    let mut end = value.len().min(MAX_LOG_BYTES);
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].into()
}

async fn model(
    io: &mut JobIo,
    agent: Uuid,
    request: &str,
    prompt: String,
) -> Result<agent_sdk::MessageResult, Error> {
    let duration = io.step()?;
    let cancel = io.cancel.clone();
    let started = Arc::new(tokio::sync::Notify::new());
    let entered = started.clone();
    let mut send = Box::pin(io.client.send_message_stream(
        request.to_string(),
        agent.to_string(),
        prompt,
        move |event| {
            if matches!(event, agent_sdk::MessageStreamEvent::Started) {
                entered.notify_one();
            }
        },
    ));
    tokio::select! {
        result = &mut send => result.map_err(Error::Sdk),
        _ = cancel.cancelled() => {
            tokio::select! {
                result = &mut send => { let _ = result; },
                _ = started.notified() => {
                    let _ = io.control.cancel_request(request.to_string(), agent.to_string()).await;
                    let _ = tokio::time::timeout(Duration::from_secs(5), &mut send).await;
                },
                _ = tokio::time::sleep(Duration::from_secs(5)) => {}
            }
            Err(Error::Cancelled)
        },
        _ = tokio::time::sleep(duration) => {
            let _ = io.control.cancel_request(request.to_string(), agent.to_string()).await;
            let _ = tokio::time::timeout(Duration::from_secs(5), &mut send).await;
            Err(Error::Budget("provider deadline".into()))
        }
    }
}

async fn protected(io: &mut JobIo, j: &Journal, branch: &Branch) -> Result<(), Error> {
    for (path, original) in &j.files {
        if !j.spec.editable.contains(path) && io.read_file(branch.id, path).await? != *original {
            return Err(Error::Contract(
                "protected tests or manifests changed".into(),
            ));
        }
    }
    Ok(())
}
async fn save(io: &mut JobIo, j: &mut Journal, index: usize, branch: &Branch) -> Result<(), Error> {
    j.branches[index] = branch.clone();
    io.persist(j).await
}

async fn cleanup(io: &mut JobIo, j: &Journal, branch: &Branch) -> Result<(), Error> {
    if !branch.owned {
        return Err(Error::Uncertain("branch creation ownership".into()));
    }
    match io.control.agent_status(branch.id.to_string()).await {
        Err(error) if error.wire_code() == Some(agent_sdk::WireErrorCode::NotFound) => {
            return Ok(())
        }
        Err(error) => return Err(error.into()),
        Ok(_) => {}
    }
    // Creation lineage is verified through the public reconciliation API before
    // any erasure. A forged or conflicting child identity is never discarded.
    let result = io
        .control
        .clone_agent(
            j.parent.to_string(),
            branch.id,
            branch_name(j.id, branch.index),
            drops(),
        )
        .await?;
    if result.parent_id != j.parent || result.child_id != branch.id {
        return Err(Error::Contract("branch ownership mismatch".into()));
    }
    io.control.kill_agent(branch.id.to_string()).await?;
    io.control
        .erase_agent_data(branch.id, agent_sdk::CONFIRM_DATA_ERASURE)
        .await?;
    Ok(())
}

async fn candidate(
    io: &mut JobIo,
    j: &mut Journal,
    index: usize,
    runner: &dyn TestRunner,
    retry_uncertain: bool,
) -> Result<bool, Error> {
    let mut branch = j.branches[index].clone();
    if branch.phase == Phase::Discarded {
        return Ok(false);
    }
    if branch.phase == Phase::Selected {
        return Ok(true);
    }
    if matches!(branch.phase, Phase::Proposing | Phase::Testing) && !retry_uncertain {
        return Err(Error::Uncertain(format!(
            "{} operation",
            if branch.phase == Phase::Testing {
                "test"
            } else {
                "provider"
            }
        )));
    }
    if branch.phase == Phase::Preparing {
        let duration = io.step()?;
        let result = JobIo::wait(
            duration,
            io.cancel.clone(),
            io.client.clone_agent(
                j.parent.to_string(),
                branch.id,
                branch_name(j.id, branch.index),
                drops(),
            ),
        )
        .await;
        let cloned = io.observe(result)?;
        if cloned.parent_id != j.parent || cloned.child_id != branch.id {
            return Err(Error::Contract("clone identity mismatch".into()));
        }
        branch.owned = true;
        save(io, j, index, &branch).await?;
        let mut directories = BTreeSet::new();
        for path in j.files.keys() {
            let pieces = path.split('/').collect::<Vec<_>>();
            for depth in 1..pieces.len() {
                directories.insert(pieces[..depth].join("/"));
            }
        }
        for directory in directories {
            io.mkdir(branch.id, &directory).await?;
        }
        for (path, content) in j.files.clone() {
            if branch.seeded.contains(&path) {
                continue;
            }
            match io.read_optional_file(branch.id, &path).await? {
                Some(existing) if existing == content => {}
                None => io.write_file(branch.id, &path, &content).await?,
                Some(_) => {
                    return Err(Error::Contract(
                        "branch seed conflicts with existing data".into(),
                    ))
                }
            }
            branch.seeded.insert(path);
            save(io, j, index, &branch).await?;
        }
        branch.phase = Phase::Proposing;
        save(io, j, index, &branch).await?;
    }
    if branch.phase == Phase::Proposing {
        protected(io, j, &branch).await?;
        let output = model(io, branch.id, &branch.request_id, format!(
            "candidate={}\nPropose a different fix for the prepared task. Return only JSON {{\"edits\":[{{\"path\":\"...\",\"expected_sha256\":\"...\",\"replacement\":\"...\"}}]}}. Allowed editable paths: {:?}. No tools, test edits, dependency changes, deletes, credentials or remote writes.",
            branch.index, j.spec.editable)).await?;
        j.provider_tokens += output.tokens as u64;
        let proposal = Proposal::parse(&output.content)?;
        proposal.validate(&j.spec, &j.files)?;
        branch.proposal = Some(proposal);
        branch.phase = Phase::Proposed;
        j.event(
            branch.id,
            "proposal",
            "validated declared source scope and preimage",
        );
        save(io, j, index, &branch).await?;
    }
    if matches!(branch.phase, Phase::Proposed | Phase::Applying) {
        branch.phase = Phase::Applying;
        save(io, j, index, &branch).await?;
        for edit in branch
            .proposal
            .clone()
            .ok_or_else(|| Error::Contract("proposal missing".into()))?
            .edits
        {
            let existing = io.read_file(branch.id, &edit.path).await?;
            if hash(existing.as_bytes()) == hash(edit.replacement.as_bytes()) {
                // A crash after replacement but before the journal update does
                // not repeat the write. Other preimages fail closed.
            } else if hash(existing.as_bytes()) == edit.expected_sha256 {
                io.write_file(branch.id, &edit.path, &edit.replacement)
                    .await?;
            } else {
                return Err(Error::Contract(
                    "source preimage changed before patch".into(),
                ));
            }
            branch.applied.insert(edit.path.clone());
            j.event(branch.id, "patch", &edit.path);
            save(io, j, index, &branch).await?;
        }
        protected(io, j, &branch).await?;
        branch.phase = Phase::Testing;
        j.event(
            branch.id,
            "test_started",
            &branch.test_operation.to_string(),
        );
        save(io, j, index, &branch).await?;
    }
    if branch.phase == Phase::Testing {
        protected(io, j, &branch).await?;
        branch.test = Some(runner.run(io, branch.id, branch.test_operation).await?);
        protected(io, j, &branch).await?;
        branch.phase = Phase::Tested;
        j.event(
            branch.id,
            "test_completed",
            &branch
                .test
                .as_ref()
                .expect("assigned evidence")
                .exit_code
                .to_string(),
        );
        save(io, j, index, &branch).await?;
    }
    if branch.phase == Phase::Tested && branch.test.as_ref().is_some_and(|test| test.exit_code == 0)
    {
        branch.phase = Phase::Selected;
        j.selected = Some(branch.id);
        j.status = "completed".into();
        j.event(
            branch.id,
            "selected",
            "explicit first passing candidate policy",
        );
        save(io, j, index, &branch).await?;
        return Ok(true);
    }
    branch.phase = Phase::Discarding;
    save(io, j, index, &branch).await?;
    cleanup(io, j, &branch).await?;
    branch.phase = Phase::Discarded;
    j.event(
        branch.id,
        "discarded",
        "runtime and durable branch data reclaimed",
    );
    save(io, j, index, &branch).await?;
    Ok(false)
}

/// Resume only durable completed effects. A started test/provider operation
/// without its receipt requires deliberate retry approval; it is never replayed
/// implicitly. Passing candidates retain their isolated workspace for review.
pub async fn run_job(
    io: &mut JobIo,
    j: &mut Journal,
    runner: &dyn TestRunner,
    retry_uncertain: bool,
    pause_after_branch: bool,
) -> Result<(), Error> {
    j.validate()?;
    if j.selected.is_some() {
        return Ok(());
    }
    if matches!(j.status.as_str(), "captured" | "preparing_context") {
        if j.status == "preparing_context" && !retry_uncertain {
            return Err(Error::Uncertain("baseline provider request".into()));
        }
        j.status = "preparing_context".into();
        io.persist(j).await?;
        let corpus = j.files.iter().map(|(path, content)| serde_json::json!({"path":path,"sha256":hash(content.as_bytes()),"content":content})).collect::<Vec<_>>();
        let output = model(io, j.parent, &format!("coding-{}-base", j.id), format!(
            "Prepare coding task: {}\nRepository snapshot: {}\nRead this data only. Acknowledge preparation with exactly {{\"edits\":[]}}; do not call tools or change files. Next requests will ask for source edits.", j.spec.instruction, serde_json::to_string(&corpus)?)).await?;
        if !Proposal::parse(&output.content)?.edits.is_empty() {
            return Err(Error::Contract("baseline must not propose effects".into()));
        }
        j.provider_tokens += output.tokens as u64;
        j.status = "running".into();
        j.event(
            j.parent,
            "context_prepared",
            "normal governed provider history saved for branching",
        );
        io.persist(j).await?;
    }
    for index in 0..j.spec.max_branches as usize {
        if index == j.branches.len() {
            let id = Uuid::new_v4();
            j.branches.push(Branch {
                id,
                owned: false,
                index: index as u32,
                phase: Phase::Preparing,
                seeded: BTreeSet::new(),
                proposal: None,
                applied: BTreeSet::new(),
                test: None,
                request_id: format!("coding-{}-{index}", j.id),
                test_operation: Uuid::new_v4(),
                error: None,
            });
            j.event(
                id,
                "clone_intent",
                "caller-known identity reserved in job journal",
            );
            io.persist(j).await?;
        }
        let already_discarded = j.branches[index].phase == Phase::Discarded;
        let result = candidate(io, j, index, runner, retry_uncertain).await;
        match result {
            Ok(true) => return Ok(()),
            Ok(false) => {}
            Err(error @ Error::Uncertain(_)) => return Err(error),
            Err(error) => {
                j.branches[index].error = Some(error.to_string());
                j.status = if matches!(&error, Error::Cancelled) {
                    "cancelled"
                } else {
                    "failed"
                }
                .into();
                j.event(j.branches[index].id, "failed", &error.to_string());
                let _ = io.emergency_persist(j).await;
                if j.branches[index].owned {
                    if cleanup(io, j, &j.branches[index]).await.is_ok() {
                        j.branches[index].phase = Phase::Discarded;
                        let _ = io.emergency_persist(j).await;
                    } else {
                        j.status = "cleanup_required".into();
                        let _ = io.emergency_persist(j).await;
                    }
                }
                return Err(error);
            }
        }
        if pause_after_branch && !already_discarded {
            j.status = "paused".into();
            io.persist(j).await?;
            return Err(Error::Paused);
        }
    }
    j.status = "no_passing_candidate".into();
    io.persist(j).await?;
    Err(Error::Contract(
        "no candidate passed the permitted tests".into(),
    ))
}
