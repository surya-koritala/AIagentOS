//! Live public-wire regression for the TUI's bounded global audit projection.

use std::sync::Arc;

use agent_sdk::{NodeAvailability, WireErrorCode};
use agent_tui::app::{App, Key, UiAction};
use agent_tui::TuiClient;
use kernel::auth::Role;
use kernel::syscall_server::SyscallServer;
use kernel::AgentKernelImpl;

#[tokio::test]
async fn tui_system_audits_use_the_authenticated_public_client() {
    let kernel = Arc::new(AgentKernelImpl::new().expect("kernel"));
    let tenant_id = kernel.create_tenant("tui-audit-tenant").await.unwrap();
    let tenant_admin = kernel
        .register_user(
            &tenant_id,
            "tui-audit-admin",
            "tui-audit-admin@example.invalid",
            Role::Admin,
        )
        .await
        .unwrap();
    let tenant_token = kernel
        .issue_api_key(&tenant_admin, "tui-audit-admin")
        .await
        .unwrap();
    let server = SyscallServer::bind(Arc::clone(&kernel), "127.0.0.1:0")
        .await
        .expect("bind audit server");
    let address = server.local_addr().expect("audit server address");
    let server_task = tokio::spawn(server.serve());

    let mut client = TuiClient::connect(&address.to_string(), None)
        .await
        .expect("system TUI public client");
    let generation = client
        .node_info()
        .await
        .expect("node info")
        .control
        .expect("node control")
        .generation;
    client
        .set_node_availability(
            NodeAvailability::Draining,
            generation,
            "TUI system-audit regression",
        )
        .await
        .expect("public node-control mutation");

    let node_control = client
        .node_control_audit(20)
        .await
        .expect("node audit through public TUI client");
    let cluster_membership = client
        .cluster_membership_audit(20)
        .await
        .expect("membership audit through public TUI client");
    let cluster_certificate_rollout = client
        .cluster_certificate_rollout_audit(20)
        .await
        .map_err(|error| error.to_string());
    assert!(
        cluster_certificate_rollout
            .as_ref()
            .is_err_and(|error| error.contains("requires the replicated cluster_raft authority")),
        "standalone mode must report the unavailable cluster ledger rather than inventing emptiness"
    );
    assert!(node_control.iter().any(|entry| {
        entry.current == NodeAvailability::Draining && entry.reason == "TUI system-audit regression"
    }));

    let mut app = App::new(address.to_string());
    assert_eq!(app.on_key(Key::Char('A')), Some(UiAction::LoadSystemAudit));
    app.set_system_audits(
        Ok(node_control),
        Ok(cluster_membership),
        cluster_certificate_rollout,
    );
    assert!(app.system_audit_loaded);
    assert!(app.node_control_audit_loaded);
    assert!(app.cluster_membership_audit_loaded);
    assert!(!app.cluster_certificate_rollout_audit_loaded);
    assert_eq!(app.system_audit_errors.len(), 1);
    assert!(app.status.contains("system audit partial"));

    let mut tenant_client = TuiClient::connect(&address.to_string(), Some(&tenant_token))
        .await
        .expect("tenant TUI public client");
    let denied = tenant_client
        .node_control_audit(20)
        .await
        .expect_err("tenant admin cannot read global node audit");
    assert_eq!(denied.wire_code(), Some(WireErrorCode::AuthorizationDenied));

    server_task.abort();
}
