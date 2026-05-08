//! Stress test: 100 agents, measure kernel performance.

use std::time::Instant;
use kernel::os_kernel::OsKernel;
use kernel::agent_struct::AgentId;

#[tokio::main]
async fn main() {
    println!("=== AI Agent OS Stress Test ===\n");

    let kernel = OsKernel::new();
    kernel.boot(None).await.unwrap();

    // Test 1: Create 100 agents
    print!("Creating 100 agents... ");
    let start = Instant::now();
    let mut ids: Vec<AgentId> = Vec::new();
    for i in 0..100 {
        ids.push(kernel.start_agent(&format!("stress-{}", i)).await.unwrap());
    }
    let elapsed = start.elapsed();
    println!("{}ms ({:.1} agents/ms)", elapsed.as_millis(), 100.0 / elapsed.as_millis() as f64);

    // Test 2: 1000 tool calls
    print!("1000 tool calls... ");
    let start = Instant::now();
    // Set MAC policy to allow
    {
        let mut mac = kernel.mac.lock().await;
        for &id in &ids {
            mac.label_agent(id, "worker".into());
        }
        mac.load_policy(vec![
            kernel::mac::PolicyRule { subject: "worker".into(), action: "*".into(), object: "*".into(), decision: "allow".into() },
        ]);
    }
    for i in 0..1000 {
        let agent = ids[i % 100];
        kernel.tool_call(agent, "/tools/fs", "read", &serde_json::json!({})).await.ok();
    }
    let elapsed = start.elapsed();
    println!("{}ms ({:.0} calls/sec)", elapsed.as_millis(), 1000000.0 / elapsed.as_millis() as f64);

    // Test 3: Shutdown all
    print!("Shutting down 100 agents... ");
    let start = Instant::now();
    kernel.shutdown().await;
    let elapsed = start.elapsed();
    println!("{}ms", elapsed.as_millis());

    println!("\n✅ Stress test complete");
}
