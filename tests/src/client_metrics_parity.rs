//! TUI and desktop metric projections must agree with one exact raw-wire
//! operator snapshot. This prevents client-local recomputation or silent
//! substitution when the server intentionally omits global metrics.

use std::sync::Arc;

use agent_sdk::KernelClient;
use agent_tui::app::App;
use kernel::syscall_server::{
    Syscall, SyscallClient, SyscallReply, SyscallServer, PROTOCOL_VERSION,
};
use kernel::AgentKernelImpl;
use tauri_app::DesktopMetricsView;

#[tokio::test]
async fn tui_and_desktop_metrics_match_one_raw_operator_snapshot() {
    let kernel = Arc::new(AgentKernelImpl::new().expect("kernel"));
    let server = SyscallServer::bind(kernel, "127.0.0.1:0")
        .await
        .expect("bind");
    let addr = server.local_addr().expect("address");
    tokio::spawn(server.serve());

    let mut sdk = KernelClient::connect(addr).await.expect("SDK connect");
    sdk.create_agent("metrics-one", "observe", None, None, None)
        .await
        .expect("create first agent");
    sdk.create_agent("metrics-two", "observe", None, None, None)
        .await
        .expect("create second agent");

    let mut raw_client = SyscallClient::connect(addr).await.expect("raw connect");
    let hello = raw_client
        .call(Syscall::Hello {
            protocol_version: PROTOCOL_VERSION,
        })
        .await
        .expect("raw hello");
    assert!(matches!(hello, SyscallReply::Hello { .. }));
    let snapshot = match raw_client
        .call(Syscall::OperatorSnapshot)
        .await
        .expect("raw operator snapshot")
    {
        SyscallReply::OperatorSnapshot { snapshot } => *snapshot,
        other => panic!("unexpected raw operator reply: {other:?}"),
    };
    let raw_metrics = snapshot
        .system_metrics
        .clone()
        .expect("system-scoped raw snapshot includes global metrics");

    let desktop = DesktopMetricsView::try_from_operator_snapshot(&snapshot)
        .expect("desktop global metrics projection");
    assert_eq!(desktop.captured_at, snapshot.captured_at);
    assert_eq!(
        desktop.telemetry_contract_version,
        raw_metrics.telemetry_contract_version
    );
    assert_eq!(desktop.tokens_consumed, raw_metrics.tokens_consumed);
    assert_eq!(desktop.api_calls_made, raw_metrics.api_calls_made);
    assert_eq!(
        desktop.time_elapsed_ms,
        raw_metrics.uptime_seconds.saturating_mul(1_000)
    );

    let mut tui = App::new(addr.to_string());
    tui.apply_operator_snapshot(snapshot);
    assert_eq!(tui.node.agent_count as u64, raw_metrics.agent_count);
    assert_eq!(tui.node.running_agents as u64, raw_metrics.running_agents);
    assert_eq!(tui.node.live_agents as u64, raw_metrics.live_agents);
    assert_eq!(tui.node.queued_agents as u64, raw_metrics.queued_agents);
    assert_eq!(tui.node.paused_agents as u64, raw_metrics.paused_agents);
    assert_eq!(tui.node.stopped_agents as u64, raw_metrics.stopped_agents);
    assert_eq!(tui.node.active_turns as u64, raw_metrics.active_turns);
    assert_eq!(tui.node.waiting_turns as u64, raw_metrics.waiting_turns);
    assert_eq!(tui.node.turn_capacity as u64, raw_metrics.turn_capacity);
    assert_eq!(
        tui.node.llm_requests_in_flight as u64,
        raw_metrics.llm_requests_in_flight
    );
    assert_eq!(
        tui.node.llm_requests_waiting as u64,
        raw_metrics.llm_requests_waiting
    );
    assert_eq!(
        tui.node.llm_core_capacity as u64,
        raw_metrics.llm_core_capacity
    );
    assert_eq!(tui.gate.allowed, raw_metrics.gate.allowed);
    assert_eq!(
        tui.gate.denied_capability,
        raw_metrics.gate.denied_capability
    );
    assert_eq!(tui.gate.denied_mac, raw_metrics.gate.denied_mac);
    assert_eq!(tui.gate.denied_approval, raw_metrics.gate.denied_approval);
    assert_eq!(tui.gate.denied_cgroup, raw_metrics.gate.denied_cgroup);
    assert_eq!(tui.gate.denied_namespace, raw_metrics.gate.denied_namespace);
    assert_eq!(tui.gate.denied_unknown, raw_metrics.gate.denied_unknown);
    assert_eq!(tui.gate.audited, raw_metrics.gate.audited);
}

#[test]
fn desktop_does_not_turn_scoped_metric_omission_into_fake_zeroes() {
    let mut snapshot: kernel::syscall_server::OperatorSnapshot =
        serde_json::from_value(serde_json::json!({
            "captured_at": "2026-07-28T12:00:00Z",
            "consistency": "transactionally_consistent",
            "scope": "tenant",
            "kernel_version": "0.3.0",
            "protocol_version": PROTOCOL_VERSION,
            "agents": [],
            "providers": [],
            "services": null,
            "system_metrics": null,
            "global_spend_usd": null
        }))
        .expect("scoped fixture");
    snapshot.system_metrics = None;

    assert_eq!(
        DesktopMetricsView::try_from_operator_snapshot(&snapshot),
        Err("global metrics are unavailable for this caller scope")
    );
}
