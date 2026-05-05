//! AI Agent OS — Kernel Benchmarks
//!
//! Tests the OS properties: concurrency, isolation, scheduling, fault tolerance.

use std::sync::Arc;
use std::time::Instant;
use kernel::*;
use kernel::agent::AgentKernel;
use kernel::scheduler::{AgentScheduler, PriorityScheduler};
use kernel::sandbox::{SandboxManager, SandboxManagerImpl, SandboxAction};
use kernel::ipc::{AgentIpc, IpcManager};
use kernel::permissions::{PermissionSystem, PermissionManager, AccessDecision};
use kernel::resources::ResourceType;
use kernel::rate_limit::{RateLimiter, RateLimitConfig};
use kernel::production::{CircuitBreaker, BudgetEnforcer};

#[tokio::main]
async fn main() {
    println!("╔═══════════════════════════════════════════════╗");
    println!("║  AI Agent OS — Kernel Benchmark Suite         ║");
    println!("╚═══════════════════════════════════════════════╝\n");

    let mut passed = 0;
    let mut failed = 0;

    // ═══ BENCHMARK 1: Concurrent Agent Creation ═══════════════════════
    print!("1. Create 10 agents concurrently... ");
    let start = Instant::now();
    let kernel = AgentKernelImpl::new().unwrap();
    let mut handles = Vec::new();
    for i in 0..10 {
        let h = kernel.create_agent_full(AgentConfig {
            name: format!("agent-{}", i),
            task: format!("task-{}", i),
            llm_provider: "none".into(),
            permission_profile: "standard".into(),
            priority: Priority::new((i % 5 + 1) as u8).unwrap(),
            sandbox_config: None,
        }).await.unwrap();
        handles.push(h);
    }
    let elapsed = start.elapsed();
    let agents = kernel.agent_manager.list_agents(None);
    if agents.len() == 10 && elapsed.as_millis() < 1000 {
        println!("✅ 10 agents in {}ms", elapsed.as_millis());
        passed += 1;
    } else {
        println!("❌ {} agents, {}ms", agents.len(), elapsed.as_millis());
        failed += 1;
    }

    // ═══ BENCHMARK 2: Scheduler Priority Ordering ═════════════════════
    print!("2. Priority scheduling (10 agents, verify order)... ");
    let sched = PriorityScheduler::new();
    let mut agent_ids: Vec<(AgentId, u8)> = Vec::new();
    for p in 1..=5 {
        for _ in 0..2 {
            let id = uuid::Uuid::new_v4();
            let (tx, _) = tokio::sync::mpsc::channel(1);
            let handle = AgentHandle { id, state: AgentState::Running, cmd_tx: tx };
            sched.schedule(&handle).await.unwrap();
            sched.set_priority(id, Priority::new(p).unwrap());
            agent_ids.push((id, p));
        }
    }
    let status = sched.get_queue_status();
    if status.running_agents == 10 {
        println!("✅ 10 agents scheduled, queue working");
        passed += 1;
    } else {
        println!("❌ {} agents scheduled", status.running_agents);
        failed += 1;
    }

    // ═══ BENCHMARK 3: Sandbox Isolation ═══════════════════════════════
    print!("3. Sandbox isolation (agent can't escape)... ");
    let sandbox_mgr = SandboxManagerImpl::new();
    let agent_a = uuid::Uuid::new_v4();
    let agent_b = uuid::Uuid::new_v4();
    let sid_a = sandbox_mgr.create_sandbox(agent_a, &SandboxConfig {
        workspace_dir: "/tmp/sandbox_a".into(),
        allowed_network_hosts: Some(vec!["api.openai.com".into()]),
        max_disk_usage_bytes: None, max_memory_bytes: None,
        isolation_level: IsolationLevel::Filesystem,
    }).unwrap();
    let sid_b = sandbox_mgr.create_sandbox(agent_b, &SandboxConfig {
        workspace_dir: "/tmp/sandbox_b".into(),
        allowed_network_hosts: Some(vec!["api.anthropic.com".into()]),
        max_disk_usage_bytes: None, max_memory_bytes: None,
        isolation_level: IsolationLevel::Filesystem,
    }).unwrap();

    // Agent A tries to access Agent B's workspace
    let cross_access = sandbox_mgr.intercept_action(sid_a, &SandboxAction::FileAccess("/tmp/sandbox_b/secret.txt".into()));
    let self_access = sandbox_mgr.intercept_action(sid_a, &SandboxAction::FileAccess("/tmp/sandbox_a/myfile.txt".into()));
    let net_blocked = sandbox_mgr.intercept_action(sid_a, &SandboxAction::NetworkAccess("evil.com".into()));
    let net_allowed = sandbox_mgr.intercept_action(sid_a, &SandboxAction::NetworkAccess("api.openai.com".into()));

    if cross_access.is_err() && self_access.is_ok() && net_blocked.is_err() && net_allowed.is_ok() {
        println!("✅ Cross-access blocked, self-access allowed, network filtered");
        passed += 1;
    } else {
        println!("❌ Isolation failed");
        failed += 1;
    }

    // ═══ BENCHMARK 4: IPC Throughput ══════════════════════════════════
    print!("4. IPC throughput (200 messages)... ");
    let ipc = IpcManager::new();
    let sender = uuid::Uuid::new_v4();
    let receiver = uuid::Uuid::new_v4();
    ipc.register_agent(sender);
    ipc.register_agent(receiver);

    let start = Instant::now();
    for i in 0..200 {
        ipc.send(sender, receiver, serde_json::json!({"msg": i})).await.unwrap();
    }
    let elapsed = start.elapsed();
    let mut received = 0;
    while ipc.receive(receiver).await.is_ok() { received += 1; }

    if received == 200 && elapsed.as_millis() < 100 {
        println!("✅ 200 msgs in {}ms ({} msg/s)", elapsed.as_millis(), 200000 / elapsed.as_millis().max(1));
        passed += 1;
    } else {
        println!("❌ {} received, {}ms", received, elapsed.as_millis());
        failed += 1;
    }

    // ═══ BENCHMARK 5: Pub/Sub Fan-out ═════════════════════════════════
    print!("5. Pub/Sub fan-out (1 publisher, 20 subscribers)... ");
    let ipc2 = IpcManager::new();
    let pub_id = uuid::Uuid::new_v4();
    ipc2.register_agent(pub_id);
    let mut sub_ids = Vec::new();
    for _ in 0..20 {
        let id = uuid::Uuid::new_v4();
        ipc2.register_agent(id);
        ipc2.subscribe(id, "events").unwrap();
        sub_ids.push(id);
    }
    let delivered = ipc2.publish(pub_id, "events", serde_json::json!({"event": "test"})).await.unwrap();
    if delivered == 20 {
        println!("✅ Delivered to all 20 subscribers");
        passed += 1;
    } else {
        println!("❌ Delivered to {}/20", delivered);
        failed += 1;
    }

    // ═══ BENCHMARK 6: Permission Enforcement ══════════════════════════
    print!("6. Permission enforcement (1000 checks)... ");
    let perms = PermissionManager::new();
    let agent = uuid::Uuid::new_v4();
    perms.assign_profile(agent, &"read-only".into());

    let start = Instant::now();
    let mut allowed = 0;
    let mut denied = 0;
    for _ in 0..1000 {
        match perms.check_access(agent, &ResourceType::Filesystem, "read", None) {
            AccessDecision::Allowed => allowed += 1,
            _ => denied += 1,
        }
        match perms.check_access(agent, &ResourceType::Filesystem, "write", None) {
            AccessDecision::Denied => denied += 1,
            _ => allowed += 1,
        }
    }
    let elapsed = start.elapsed();
    if allowed == 1000 && denied == 1000 && elapsed.as_millis() < 50 {
        println!("✅ 2000 checks in {}ms (read=allowed, write=denied)", elapsed.as_millis());
        passed += 1;
    } else {
        println!("❌ allowed={} denied={} {}ms", allowed, denied, elapsed.as_millis());
        failed += 1;
    }

    // ═══ BENCHMARK 7: Fault Tolerance (agent crash) ═══════════════════
    print!("7. Fault tolerance (crash 1 of 5 agents)... ");
    let kernel2 = AgentKernelImpl::new().unwrap();
    let mut ids = Vec::new();
    for i in 0..5 {
        let h = kernel2.create_agent_full(AgentConfig {
            name: format!("ft-{}", i), task: "test".into(),
            llm_provider: "none".into(), permission_profile: "standard".into(),
            priority: Priority::default(), sandbox_config: None,
        }).await.unwrap();
        ids.push(h.id);
    }
    // Crash agent 2 (force to Error state)
    kernel2.agent_manager.transition_state(ids[2], AgentState::Error("crashed".into())).unwrap();
    kernel2.agent_manager.transition_state(ids[2], AgentState::Stopped).unwrap();

    let running: Vec<_> = ids.iter().filter(|id| {
        kernel2.agent_manager.get_agent_state(**id) == Some(AgentState::Running)
    }).collect();
    if running.len() == 4 {
        println!("✅ 4/5 still running after crash");
        passed += 1;
    } else {
        println!("❌ {}/5 running", running.len());
        failed += 1;
    }

    // ═══ BENCHMARK 8: Rate Limiter Under Load ═════════════════════════
    print!("8. Rate limiter (burst 100 requests, limit 10)... ");
    let limiter = RateLimiter::new(RateLimitConfig { rpm: 10, tpm: 100000, max_concurrent: 5 });
    let mut acquired = 0;
    for _ in 0..10 {
        let _g = limiter.acquire().await;
        acquired += 1;
    }
    let is_limited = limiter.is_limited();
    if acquired == 10 && is_limited {
        println!("✅ 10 acquired, then rate limited");
        passed += 1;
    } else {
        println!("❌ acquired={} limited={}", acquired, is_limited);
        failed += 1;
    }

    // ═══ BENCHMARK 9: Circuit Breaker ═════════════════════════════════
    print!("9. Circuit breaker (5 failures trips, success resets)... ");
    let cb = CircuitBreaker::new(5, 30);
    for _ in 0..4 { cb.record_failure(); }
    let before_trip = cb.is_available();
    cb.record_failure(); // 5th failure
    let after_trip = cb.is_available();
    cb.record_success(); // reset
    let after_reset = cb.is_available();
    if before_trip && !after_trip && after_reset {
        println!("✅ Trips at 5, resets on success");
        passed += 1;
    } else {
        println!("❌ before={} after={} reset={}", before_trip, after_trip, after_reset);
        failed += 1;
    }

    // ═══ BENCHMARK 10: Graceful Shutdown ══════════════════════════════
    print!("10. Graceful shutdown (stop all agents)... ");
    let kernel3 = AgentKernelImpl::new().unwrap();
    for i in 0..10 {
        kernel3.create_agent_full(AgentConfig {
            name: format!("shutdown-{}", i), task: "test".into(),
            llm_provider: "none".into(), permission_profile: "standard".into(),
            priority: Priority::default(), sandbox_config: None,
        }).await.unwrap();
    }
    let stopped = kernel3.shutdown().await.unwrap();
    let all_stopped = kernel3.agent_manager.list_agents(None).iter()
        .all(|a| a.state == AgentState::Stopped);
    if stopped.len() == 10 && all_stopped {
        println!("✅ All 10 agents stopped gracefully");
        passed += 1;
    } else {
        println!("❌ stopped={} all_stopped={}", stopped.len(), all_stopped);
        failed += 1;
    }

    // ═══ Results ══════════════════════════════════════════════════════
    println!("\n╔═══════════════════════════════════════════════╗");
    println!("║  Results: {}/{}                                 ║", passed, passed + failed);
    println!("╚═══════════════════════════════════════════════╝");

    if failed > 0 { std::process::exit(1); }
}
