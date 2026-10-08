//! Operator-only comparison; every process strategy remains rootless-contained.

use agent_sdk::KernelClient;
use coding_agent::fixture;
use coding_agent::io::JobIo;
use coding_agent::provider::ProposalProvider;
use coding_agent::workflow::{candidate_prompt, preparation_prompt, register_test_tool};
use coding_agent::{
    hash, run_job, Error, Journal, ProcessRunner, Proposal, TestRunner, JOURNAL_VERSION,
};
use kernel::connector::{LlmProviderAdapter, LlmRequestOptions, StandardMessage};
use kernel::sandbox::SandboxManagerImpl;
use kernel::{AgentConfig, AgentKernelImpl, IsolationLevel, Priority};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

fn journal(parent: Uuid, image: &str) -> Journal {
    Journal {
        version: JOURNAL_VERSION,
        id: Uuid::new_v4(),
        parent,
        spec: fixture::spec(),
        image: image.into(),
        mode: "fixture".into(),
        model: None,
        created: chrono::Utc::now(),
        files: fixture::files(),
        branches: vec![],
        events: vec![],
        steps: 0,
        provider_tokens: 0,
        selected: None,
        status: "captured".into(),
    }
}
async fn seed(io: &mut JobIo, agent: Uuid, files: &BTreeMap<String, String>) -> Result<(), Error> {
    for directory in ["src", "tests"] {
        io.mkdir(agent, directory).await?;
    }
    for (path, content) in files {
        io.write_file(agent, path, content).await?;
    }
    Ok(())
}
async fn verify_protected(io: &mut JobIo, agent: Uuid, j: &Journal) -> Result<(), Error> {
    for (path, content) in &j.files {
        if !j.spec.editable.contains(path) && io.read_file(agent, path).await? != *content {
            return Err(Error::Contract("comparison changed protected input".into()));
        }
    }
    Ok(())
}
async fn governed(strategy: &str, image: &str) -> Result<Value, Error> {
    let security = kernel::config::Config::default();
    let budgets = coding_agent::task_budgets(
        &fixture::spec(),
        kernel::config::TokenPricing {
            input_usd_per_1k_tokens: 0.0,
            cached_input_usd_per_1k_tokens: 0.0,
            output_usd_per_1k_tokens: 0.0,
        },
    )?;
    let kernel = Arc::new(AgentKernelImpl::with_context_manager(
        Arc::new(
            kernel::context::SqliteContextManager::in_memory()
                .map_err(kernel::KernelError::Context)?,
        ),
        &budgets,
        security.mac_enforcing,
        &security.mac_rules,
    )?);
    let _runtime = kernel.start_runtime();
    kernel.register_provider(Arc::new(ProposalProvider::fixture()))?;
    register_test_tool(&kernel, "utf8_budget")?;
    let mut sandbox = SandboxManagerImpl::default_config();
    sandbox.isolation_level = IsolationLevel::Container;
    sandbox.container_image = Some(image.into());
    sandbox.max_memory_bytes = Some(1024 * 1024 * 1024);
    let parent = kernel
        .create_agent_with_managed_sandbox(
            AgentConfig {
                name: "comparison".into(),
                task: "same UTF-8 task".into(),
                llm_provider: "coding".into(),
                permission_profile: "standard".into(),
                priority: Priority::default(),
                sandbox_config: None,
            },
            sandbox,
        )
        .await?
        .id;
    let mut j = journal(parent, image);
    let server = kernel::syscall_server::SyscallServer::bind(kernel.clone(), "127.0.0.1:0")
        .await
        .map_err(|_| Error::Contract("comparison server unavailable".into()))?;
    let address = server
        .local_addr()
        .map_err(|_| Error::Contract("comparison server address unavailable".into()))?;
    let server_task = tokio::spawn(server.serve());
    let mut io = JobIo::new(
        KernelClient::connect(address).await?,
        KernelClient::connect(address).await?,
        &j,
        CancellationToken::new(),
    );
    seed(&mut io, parent, &j.files).await?;
    let runner = ProcessRunner {
        kernel: kernel.clone(),
    };
    let started = Instant::now();
    let result=async {
        if strategy=="governed_cow" {
            run_job(&mut io,&mut j,&runner,false,false).await?;
            let tests=j.branches.iter().filter_map(|branch|branch.test.as_ref()).collect::<Vec<_>>();
            Ok(json!({"strategy":strategy,"kernel_governance":true,"copy_on_write":true,
                "completed":j.selected.is_some(),"attempts":tests.len(),"tests":tests,"provider_tokens":j.provider_tokens,
                "duration_ms":started.elapsed().as_millis(),"changed_file_sha256":j.branches.last().and_then(|branch|branch.proposal.as_ref()).map(|proposal|hash(proposal.edits[0].replacement.as_bytes()))}))
        } else {
            let output=io.client.send_message(parent.to_string(),preparation_prompt(&j)?).await?;
            let mut tokens=u64::from(output.tokens);
            let mut tests=Vec::new();
            let mut selected_hash=None;
            for index in 0..j.spec.max_branches {
                // Reset only the operator-created private copy. The same agent
                // keeps its previous conversational attempts; no clone is used.
                for path in &j.spec.editable { io.write_file(parent,path,&j.files[path]).await?; }
                let output=io.client.send_message(parent.to_string(),candidate_prompt(index,&j.spec.editable)).await?;
                tokens+=u64::from(output.tokens);
                let proposal=Proposal::parse(&output.content)?;proposal.validate(&j.spec,&j.files)?;
                for edit in &proposal.edits { io.write_file(parent,&edit.path,&edit.replacement).await?; }
                verify_protected(&mut io,parent,&j).await?;
                let test=runner.run(&mut io,parent,Uuid::new_v4()).await?;
                verify_protected(&mut io,parent,&j).await?;
                let passed=test.exit_code==0;tests.push(test);
                if passed {selected_hash=Some(hash(proposal.edits[0].replacement.as_bytes()));break;}
            }
            Ok(json!({"strategy":strategy,"kernel_governance":true,"copy_on_write":false,
                "completed":selected_hash.is_some(),"attempts":tests.len(),"tests":tests,"provider_tokens":tokens,
                "duration_ms":started.elapsed().as_millis(),"changed_file_sha256":selected_hash}))
        }
    }.await;
    if let Some(selected) = j.selected {
        let _ = io.control.kill_agent(selected.to_string()).await;
        let _ = io
            .control
            .erase_agent_data(selected, agent_sdk::CONFIRM_DATA_ERASURE)
            .await;
    }
    let _ = io.control.kill_agent(parent.to_string()).await;
    let _ = io
        .control
        .erase_agent_data(parent, agent_sdk::CONFIRM_DATA_ERASURE)
        .await;
    let _ = io.client.close().await;
    let _ = io.control.close().await;
    server_task.abort();
    let _ = server_task.await;
    result
}

struct PrivateDirectory(PathBuf);
impl Drop for PrivateDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn direct_inputs(workspace: &Path, files: &BTreeMap<String, String>) -> Result<(), Error> {
    for (path, content) in files {
        let file = workspace.join(path);
        if let Some(parent) = file.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|_| Error::Contract("baseline directory creation failed".into()))?;
        }
        std::fs::write(file, content)
            .map_err(|_| Error::Contract("baseline seed failed".into()))?;
    }
    Ok(())
}
async fn direct(image: &str) -> Result<Value, Error> {
    let root = std::env::temp_dir().join(format!("coding-direct-baseline-{}", Uuid::new_v4()));
    std::fs::create_dir(&root).map_err(|_| Error::Contract("baseline root unavailable".into()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))
            .map_err(|_| Error::Contract("baseline permissions unavailable".into()))?;
    }
    let directory = PrivateDirectory(root);
    let j = journal(Uuid::new_v4(), image);
    direct_inputs(&directory.0, &j.files)?;
    let provider = ProposalProvider::fixture();
    let session = provider
        .create_session()
        .await
        .map_err(|_| Error::Contract("baseline provider unavailable".into()))?;
    let options = LlmRequestOptions {
        max_output_tokens: Some(j.spec.max_output_tokens),
        ..Default::default()
    };
    let mut messages = vec![
        StandardMessage::system(
            "You are a helpful AI assistant. Use the available tools to help the user.",
        ),
        StandardMessage::user(preparation_prompt(&j)?),
    ];
    let started = Instant::now();
    let response = session
        .send_with_options(messages.clone(), &[], options)
        .await
        .map_err(|_| Error::Contract("baseline preparation failed".into()))?;
    let mut tokens = u64::from(response.tokens_used);
    messages.push(StandardMessage::assistant(response.content));
    let mut tests = Vec::new();
    let mut selected_hash = None;
    for index in 0..j.spec.max_branches {
        for path in &j.spec.editable {
            std::fs::write(directory.0.join(path), &j.files[path])
                .map_err(|_| Error::Contract("baseline reset failed".into()))?;
        }
        messages.push(StandardMessage::user(candidate_prompt(
            index,
            &j.spec.editable,
        )));
        let response = session
            .send_with_options(messages.clone(), &[], options)
            .await
            .map_err(|_| Error::Contract("baseline proposal failed".into()))?;
        tokens += u64::from(response.tokens_used);
        let proposal = Proposal::parse(&response.content)?;
        proposal.validate(&j.spec, &j.files)?;
        messages.push(StandardMessage::assistant(response.content));
        for edit in &proposal.edits {
            std::fs::write(directory.0.join(&edit.path), &edit.replacement)
                .map_err(|_| Error::Contract("baseline patch failed".into()))?;
        }
        let test_started = Instant::now();
        // Even the benchmark-only non-kernel path retains the qualified
        // containment boundary. It never launches an ambient host test process.
        let test = kernel::docker_sandbox::execute_hardened(
            j.parent,
            &directory.0,
            image,
            Some(1024 * 1024 * 1024),
            "cargo",
            &[
                "test".into(),
                "--offline".into(),
                "--locked".into(),
                "--test".into(),
                j.spec.test_target.clone(),
                "--jobs".into(),
                "1".into(),
            ],
        )
        .await
        .map_err(Error::Contract)?;
        let exit = test["exit_code"]
            .as_i64()
            .ok_or_else(|| Error::Contract("baseline has no exit receipt".into()))?;
        for (path, content) in &j.files {
            if !j.spec.editable.contains(path)
                && std::fs::read(directory.0.join(path))
                    .map_err(|_| Error::Contract("baseline input disappeared".into()))?
                    != content.as_bytes()
            {
                return Err(Error::Contract("baseline protected input changed".into()));
            }
        }
        tests.push(json!({"kind":"isolated_process","exit_code":exit,"duration_ms":test_started.elapsed().as_millis()}));
        if exit == 0 {
            selected_hash = Some(hash(proposal.edits[0].replacement.as_bytes()));
            break;
        }
    }
    Ok(
        json!({"strategy":"contained_direct","kernel_governance":false,"copy_on_write":false,
        "completed":selected_hash.is_some(),"attempts":tests.len(),"tests":tests,"provider_tokens":tokens,
        "duration_ms":started.elapsed().as_millis(),"changed_file_sha256":selected_hash}),
    )
}

#[tokio::main]
async fn main() {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.len() != 2 || args[0] != "--image" || !cfg!(target_os = "linux") {
        eprintln!("usage on Linux/rootless: coding-comparison --image NAME@sha256:DIGEST");
        std::process::exit(2);
    }
    let image = &args[1];
    if let Err(error) = kernel::docker_sandbox::validate_digest_image(image) {
        eprintln!("{error}");
        std::process::exit(2);
    }
    let result=async {
        let cow=governed("governed_cow",image).await?;
        let sequential=governed("governed_sequential",image).await?;
        let baseline=direct(image).await?;
        let results=vec![cow,sequential,baseline];
        if results.iter().any(|row|row["completed"]!=true || row["attempts"]!=2)
            || results.iter().any(|row|row["changed_file_sha256"]!=results[0]["changed_file_sha256"])
        {return Err(Error::Contract("comparison outcomes differ or incomplete".into()));}
        Ok::<_,Error>(json!({"schema_version":1,"evidence_class":"deterministic_fixture","production_claim_allowed":false,
            "provider_api_calls":0,"task":"utf8_byte_budget","image":image,"same_prompts_and_proposal_decoder":true,
            "containment_in_every_strategy":true,"timing_scope":"prepared file snapshot through selection; single run, includes test compilation",
            "token_counter_scope":"synthetic fixture usage; not a billed-provider measurement","results":results}))
    }.await;
    match result {
        Ok(report) => println!(
            "{}",
            serde_json::to_string_pretty(&report).expect("report encoding")
        ),
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(1);
        }
    }
}
