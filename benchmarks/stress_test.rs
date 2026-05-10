//! Stress test: 100 agents, measure kernel performance through the unified
//! `AgentKernelImpl` and its `SyscallGate`. Replaces the legacy `OsKernel`
//! benchmark from before the Phase 2 unification.

use std::time::Instant;

use kernel::{AgentConfig, AgentKernelImpl, Priority};

#[tokio::main]
async fn main() {
    println!("=== AI Agent OS Stress Test ===\n");

    let kernel = AgentKernelImpl::new().expect("kernel new");

    // Test 1: Create 100 agents through the live path.
    print!("Creating 100 agents... ");
    let start = Instant::now();
    let mut handles = Vec::with_capacity(100);
    for i in 0..100 {
        let config = AgentConfig {
            name: format!("stress-{}", i),
            task: "stress".into(),
            llm_provider: "stub".into(),
            permission_profile: "full-access".into(),
            priority: Priority::default(),
            sandbox_config: None,
        };
        handles.push(kernel.create_agent_full(config).await.expect("create"));
    }
    let elapsed = start.elapsed();
    println!(
        "{}ms ({:.1} agents/ms)",
        elapsed.as_millis(),
        100.0 / elapsed.as_millis() as f64
    );

    // Test 2: 1000 syscall-gate tool checks. With "full-access" permission
    // profile every agent has all caps, MAC defaults to permissive, and each
    // call is well under the cgroup quota — so this measures gate throughput
    // on the hot path.
    print!("1000 tool calls through SyscallGate... ");
    let start = Instant::now();
    for i in 0..1000 {
        let agent = handles[i % 100].id;
        kernel
            .syscall_gate
            .check_tool_call(agent, "read_file", "/tmp/stress", 10)
            .await
            .ok();
    }
    let elapsed = start.elapsed();
    println!(
        "{}ms ({:.0} calls/sec)",
        elapsed.as_millis(),
        1_000_000.0 / elapsed.as_millis() as f64
    );

    // Test 3: Shutdown — gate + observability + executors all purge.
    print!("Shutting down 100 agents... ");
    let start = Instant::now();
    kernel.shutdown().await.expect("shutdown");
    let elapsed = start.elapsed();
    println!("{}ms", elapsed.as_millis());

    println!("\n✅ Stress test complete");
}
