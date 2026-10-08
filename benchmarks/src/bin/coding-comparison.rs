//! Operator-only comparison; every process strategy remains rootless-contained.

use agent_sdk::KernelClient;
use coding_agent::fixture;
use coding_agent::io::JobIo;
use coding_agent::provider::{ProposalProvider, ProviderAudit};
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

struct Campaign {
    image: String,
    model: Option<String>,
    max_usd: f64,
    pricing: kernel::config::TokenPricing,
}
impl Campaign {
    fn spec(&self) -> coding_agent::TaskSpec {
        let mut spec = fixture::spec();
        spec.max_usd = self.max_usd / 3.0;
        spec
    }
    fn provider(
        &self,
        budget: Arc<kernel::budget::BudgetEnforcer>,
        audit: Arc<ProviderAudit>,
    ) -> Result<ProposalProvider, Error> {
        let provider = if let Some(model) = &self.model {
            let key = std::env::var("OPENAI_API_KEY").map_err(|_| {
                Error::Contract("OPENAI_API_KEY is required for reviewed comparison".into())
            })?;
            ProposalProvider::real(
                Arc::new(adapters::openai::OpenAiAdapter::new(key).with_model(model.clone())),
                budget,
            )
        } else {
            ProposalProvider::fixture()
        };
        Ok(provider.with_audit(audit))
    }
    fn parse(args: &[String]) -> Result<Self, Error> {
        if !args.len().is_multiple_of(2) {
            return Err(Error::Contract("comparison options require values".into()));
        }
        let mut options = BTreeMap::new();
        for pair in args.chunks(2) {
            if !matches!(
                pair[0].as_str(),
                "--image"
                    | "--model"
                    | "--max-usd"
                    | "--input-price-per-1k"
                    | "--output-price-per-1k"
            ) || options.insert(pair[0].as_str(), pair[1].as_str()).is_some()
            {
                return Err(Error::Contract(
                    "unknown or duplicate comparison option".into(),
                ));
            }
        }
        let image = options
            .get("--image")
            .ok_or_else(|| Error::Contract("--image is required".into()))?
            .to_string();
        kernel::docker_sandbox::validate_digest_image(&image).map_err(Error::Contract)?;
        let model = options.get("--model").map(|value| value.to_string());
        let (max_usd, input, output) = if let Some(model) = &model {
            if model.is_empty() || model.len() > 256 {
                return Err(Error::Contract("invalid explicit comparison model".into()));
            }
            let number = |name| {
                options
                    .get(name)
                    .ok_or_else(|| Error::Contract(format!("{name} is required")))?
                    .parse::<f64>()
                    .map_err(|_| Error::Contract("invalid comparison financial bound".into()))
            };
            let values = (
                number("--max-usd")?,
                number("--input-price-per-1k")?,
                number("--output-price-per-1k")?,
            );
            if !values.0.is_finite()
                || values.0 < 0.000003
                || values.0 > 100.0
                || !values.1.is_finite()
                || values.1 <= 0.0
                || !values.2.is_finite()
                || values.2 <= 0.0
            {
                return Err(Error::Contract(
                    "comparison bounds must be finite and positive".into(),
                ));
            }
            values
        } else {
            if options.len() != 1 {
                return Err(Error::Contract(
                    "financial comparison options require an explicit model".into(),
                ));
            }
            (0.03, 0.0, 0.0)
        };
        Ok(Self {
            image,
            model,
            max_usd,
            pricing: kernel::config::TokenPricing {
                input_usd_per_1k_tokens: input,
                cached_input_usd_per_1k_tokens: input,
                output_usd_per_1k_tokens: output,
            },
        })
    }
}

fn journal(parent: Uuid, campaign: &Campaign) -> Journal {
    Journal {
        version: JOURNAL_VERSION,
        id: Uuid::new_v4(),
        parent,
        spec: campaign.spec(),
        image: campaign.image.clone(),
        mode: if campaign.model.is_some() {
            "run"
        } else {
            "fixture"
        }
        .into(),
        model: campaign.model.clone(),
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
async fn governed(strategy: &str, campaign: &Campaign) -> Result<Value, Error> {
    let security = kernel::config::Config::default();
    let budgets = coding_agent::task_budgets(&campaign.spec(), campaign.pricing)?;
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
    let audit = Arc::new(ProviderAudit::default());
    kernel.register_provider(Arc::new(
        campaign.provider(kernel.budget_enforcer.clone(), audit.clone())?,
    ))?;
    register_test_tool(&kernel, "utf8_budget")?;
    let mut sandbox = SandboxManagerImpl::default_config();
    sandbox.isolation_level = IsolationLevel::Container;
    sandbox.container_image = Some(campaign.image.clone());
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
    let mut j = journal(parent, campaign);
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
    let result: Result<Value, Error> = async {
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
    let mut outcome = result.unwrap_or_else(|error| json!({"strategy":strategy,"completed":false,"error":error.to_string(),"status":"failed_or_incomplete","duration_ms":started.elapsed().as_millis()}));
    outcome["provider_api_calls"] = json!(audit.api_calls());
    outcome["configured_cost_usd"] = json!(kernel.budget_enforcer.global_spent_usd());
    outcome["configured_max_usd"] = json!(campaign.spec().max_usd);
    Ok(outcome)
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
async fn direct(campaign: &Campaign) -> Result<Value, Error> {
    let root = std::env::temp_dir().join(format!("coding-direct-baseline-{}", Uuid::new_v4()));
    std::fs::create_dir(&root).map_err(|_| Error::Contract("baseline root unavailable".into()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))
            .map_err(|_| Error::Contract("baseline permissions unavailable".into()))?;
    }
    let directory = PrivateDirectory(root);
    let j = journal(Uuid::new_v4(), campaign);
    direct_inputs(&directory.0, &j.files)?;
    let budget = Arc::new(kernel::budget::BudgetEnforcer::with_pricing(
        0.0,
        campaign.spec().max_usd,
        0.0,
    ));
    budget
        .set_provider_token_pricing("coding", campaign.pricing)
        .map_err(Error::Contract)?;
    let audit = Arc::new(ProviderAudit::default());
    let provider = campaign.provider(budget.clone(), audit.clone())?;
    let session = provider
        .create_session()
        .await
        .map_err(|_| Error::Contract("baseline provider unavailable".into()))?;
    let options = LlmRequestOptions {
        max_output_tokens: Some(j.spec.max_output_tokens),
        timeout: Some(std::time::Duration::from_secs(120)),
    };
    let mut messages = vec![
        StandardMessage::system(
            "You are a helpful AI assistant. Use the available tools to help the user.",
        ),
        StandardMessage::user(preparation_prompt(&j)?),
    ];
    let started = Instant::now();
    let result = async {
    let response = session
        .send_with_options(messages.clone(), &[], options)
        .await
        .map_err(|_| Error::Contract("baseline preparation failed".into()))?;
    let mut tokens = u64::from(response.tokens_used);
    budget.record_usage_charge(j.parent, "coding", session.model_id(), response.usage);
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
        budget.record_usage_charge(j.parent, "coding", session.model_id(), response.usage);
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
            &campaign.image,
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
    Ok::<Value, Error>(
        json!({"strategy":"contained_direct","kernel_governance":false,"copy_on_write":false,
        "completed":selected_hash.is_some(),"attempts":tests.len(),"tests":tests,"provider_tokens":tokens,
        "duration_ms":started.elapsed().as_millis(),"changed_file_sha256":selected_hash,
        "provider_api_calls":audit.api_calls(),"configured_cost_usd":budget.global_spent_usd(),"configured_max_usd":campaign.spec().max_usd}),
    )
    }.await;
    let successful = result.is_ok();
    let mut outcome = result.unwrap_or_else(|error| incomplete("contained_direct", error));
    outcome["provider_api_calls"] = json!(audit.api_calls());
    outcome["configured_recorded_cost_usd"] = json!(budget.global_spent_usd());
    if !successful {
        outcome["configured_cost_usd"] = Value::Null;
    }
    outcome["configured_max_usd"] = json!(campaign.spec().max_usd);
    Ok(outcome)
}

fn comparison_report(campaign: &Campaign, results: Vec<Value>) -> Result<Value, Error> {
    let fixture = campaign.model.is_none();
    if fixture
        && (results
            .iter()
            .any(|row| row["completed"] != true || row["attempts"] != 2)
            || results
                .iter()
                .any(|row| row["changed_file_sha256"] != results[0]["changed_file_sha256"]))
    {
        return Err(Error::Contract(
            "fixture comparison outcomes differ or incomplete".into(),
        ));
    }
    let completed = results.len() == 3 && results.iter().all(|row| row["completed"] == true);
    let calls = results
        .iter()
        .map(|row| row["provider_api_calls"].as_u64())
        .collect::<Option<Vec<_>>>()
        .map(|counts| counts.iter().sum::<u64>());
    let cost = results
        .iter()
        .map(|row| row["configured_cost_usd"].as_f64())
        .collect::<Option<Vec<_>>>()
        .map(|values| values.iter().sum::<f64>());
    Ok(
        json!({"schema_version":1,"status":if completed {"completed"} else {"failed_or_incomplete"},
        "evidence_class":if fixture {"deterministic_fixture"} else {"reviewed_live_comparison"},"production_claim_allowed":false,
        "provider_api_calls":calls,"configured_cost_usd":cost,"authorized_configured_max_usd":campaign.max_usd,
        "budget_partition":"one third of the single authorized campaign ceiling per strategy",
        "task":"utf8_byte_budget","image":campaign.image,"model":campaign.model,"same_task_and_candidate_prompt_templates":true,
        "containment_in_every_strategy":true,"timing_scope":"prepared file snapshot through selection; single run, includes test compilation",
        "token_counter_scope":if fixture {"synthetic fixture usage; not a billed-provider measurement"} else {"provider-reported usage; configured costs require invoice reconciliation"},"results":results}),
    )
}
fn incomplete(strategy: &str, error: Error) -> Value {
    json!({"strategy":strategy,"completed":false,"status":"failed_or_incomplete","error":error.to_string(),
        "provider_api_calls":null,"configured_cost_usd":null})
}
#[tokio::main]
async fn main() {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if !cfg!(target_os = "linux") {
        eprintln!("coding comparison requires the Linux/rootless target");
        std::process::exit(2);
    }
    let campaign = match Campaign::parse(&args) {
        Ok(campaign) => campaign,
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(2);
        }
    };
    let cow = governed("governed_cow", &campaign)
        .await
        .unwrap_or_else(|error| incomplete("governed_cow", error));
    let sequential = governed("governed_sequential", &campaign)
        .await
        .unwrap_or_else(|error| incomplete("governed_sequential", error));
    let baseline = direct(&campaign)
        .await
        .unwrap_or_else(|error| incomplete("contained_direct", error));
    match comparison_report(&campaign, vec![cow, sequential, baseline]) {
        Ok(report) => {
            println!(
                "{}",
                serde_json::to_string_pretty(&report).expect("report encoding")
            );
            if report["status"] != "completed" {
                std::process::exit(1);
            }
        }
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| value.to_string()).collect()
    }
    fn image() -> String {
        format!("fixture@sha256:{}", "f".repeat(64))
    }
    #[test]
    fn reviewed_limits_are_explicit_and_shared_by_all_strategies() {
        let pin = image();
        let campaign = Campaign::parse(&args(&[
            "--image",
            &pin,
            "--model",
            "contract-model",
            "--max-usd",
            "3",
            "--input-price-per-1k",
            "0.001",
            "--output-price-per-1k",
            "0.002",
        ]))
        .unwrap();
        assert_eq!(campaign.spec().max_usd, 1.0);
        for invalid in ["0", "0.000000001", "nan", "101"] {
            assert!(Campaign::parse(&args(&[
                "--image",
                &pin,
                "--model",
                "contract-model",
                "--max-usd",
                invalid,
                "--input-price-per-1k",
                "0.001",
                "--output-price-per-1k",
                "0.002"
            ]))
            .is_err());
        }
        assert!(Campaign::parse(&args(&["--image", &pin, "--model", "contract-model"])).is_err());
    }
    #[test]
    fn a_live_failure_stays_incomplete_with_unknown_costs_preserved() {
        let pin = image();
        let campaign = Campaign::parse(&args(&[
            "--image",
            &pin,
            "--model",
            "contract-model",
            "--max-usd",
            "3",
            "--input-price-per-1k",
            "0.001",
            "--output-price-per-1k",
            "0.002",
        ]))
        .unwrap();
        let report = comparison_report(
            &campaign,
            vec![incomplete(
                "governed_cow",
                Error::Contract("provider outcome uncertain".into()),
            )],
        )
        .unwrap();
        assert_eq!(report["status"], "failed_or_incomplete");
        assert!(report["configured_cost_usd"].is_null());
        assert!(report["provider_api_calls"].is_null());
        assert_eq!(report["production_claim_allowed"], false);
    }
}
