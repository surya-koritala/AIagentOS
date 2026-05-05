use std::sync::Arc;
use kernel::{AgentConfig, AgentKernelImpl, Priority};
use kernel::planning::{generate_plan, PlanExecutor, PlanEvent, PlanStepStatus};
use kernel::execution::AgentExecutor;
use kernel::connector::AgentConnector;
use kernel::resources::ResourceBroker;
use adapters::azure_openai::AzureOpenAiAdapter;
use tokio::sync::mpsc;

#[tokio::main]
async fn main() {
    let kernel = AgentKernelImpl::new().unwrap();
    let adapter = AzureOpenAiAdapter::new(
        "https://roamx-resource.cognitiveservices.azure.com".into(),
        "gpt-5.4".into(),
        std::env::var("AZURE_OPENAI_API_KEY").expect("Set AZURE_OPENAI_API_KEY"),
    ).with_api_version("2025-04-01-preview".into());
    kernel.register_provider(Arc::new(adapter)).unwrap();

    let handle = kernel.create_agent_full(AgentConfig {
        name: "planner".into(), task: "planning test".into(),
        llm_provider: "azure-openai".into(), permission_profile: "full-access".into(),
        priority: Priority::default(), sandbox_config: None,
    }).await.unwrap();

    println!("=== Multi-Step Planning E2E Test ===\n");

    // Step 1: Generate a plan
    let session = AgentConnector::connect(&*kernel.connector, handle.id, &"azure-openai".into()).await.unwrap();
    let task = "Create a directory /tmp/plan_test, write a Python hello world script there, and run it";
    println!("Task: {}\n", task);

    let plan = generate_plan(&*session, task).await.unwrap();
    println!("Plan generated ({} steps, revision {}):", plan.steps.len(), plan.revision);
    for step in &plan.steps {
        println!("  {}. {} [{}]", step.number, step.description, 
            if step.risk_level == kernel::planning::RiskLevel::High { "HIGH" } else { "low" });
    }

    // Step 2: Execute the plan
    println!("\n--- Executing ---\n");
    let session2 = AgentConnector::connect(&*kernel.connector, handle.id, &"azure-openai".into()).await.unwrap();
    let executor = AgentExecutor::new(
        handle.id, session2,
        kernel.resource_broker.clone() as Arc<dyn ResourceBroker>,
        kernel.tool_registry.clone(),
        kernel.context_manager.clone(),
        "You are executing a plan step by step. Use tools to accomplish each step.".into(),
    );

    let (tx, mut rx) = mpsc::channel::<PlanEvent>(64);
    let mut plan_exec = PlanExecutor::new(plan, executor);
    plan_exec.set_event_channel(tx);
    plan_exec.disable_approval(); // auto-approve for testing

    let exec_handle = tokio::spawn(async move { plan_exec.execute().await });

    // Listen to events
    while let Some(event) = rx.recv().await {
        match event {
            PlanEvent::StepStarted { step, description } => println!("  ▶ Step {}: {}", step, description),
            PlanEvent::StepCompleted { step, output } => println!("  ✓ Step {}: {}...", step, &output[..output.len().min(60)]),
            PlanEvent::StepFailed { step, error } => println!("  ✗ Step {}: {}", step, error),
            PlanEvent::PlanRevised { revision, .. } => println!("  🔄 Plan revised (v{})", revision),
            PlanEvent::PlanCompleted { total_steps } => { println!("\n  ✅ Plan completed ({} steps)", total_steps); break; }
            _ => {}
        }
    }

    let result = exec_handle.await.unwrap().unwrap();
    println!("\nFinal status: {:?}", result.status);
    println!("Steps done: {}", result.steps.iter().filter(|s| s.status == PlanStepStatus::Done).count());

    // Verify the plan actually worked
    if std::path::Path::new("/tmp/plan_test").exists() {
        println!("\n✅ Directory created!");
    }
    if let Ok(files) = std::fs::read_dir("/tmp/plan_test") {
        for f in files { println!("  📄 {}", f.unwrap().file_name().to_string_lossy()); }
    }
}
