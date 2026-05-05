//! Property-based tests for Sandbox (Properties 10, 11, 27).
//!
//! Property 10: Sandbox boundary enforcement — actions outside boundary intercepted.
//! Property 11: New agents are sandboxed by default.
//! Property 27: Sandbox isolation between agents — one agent can't affect another's state.

use std::path::PathBuf;

use proptest::prelude::*;

use kernel::sandbox::*;
use kernel::{IsolationLevel, SandboxConfig};

fn arb_workspace() -> impl Strategy<Value = PathBuf> {
    prop_oneof![
        Just(PathBuf::from("/tmp/sandbox/agent1")),
        Just(PathBuf::from("/home/user/workspace")),
        Just(PathBuf::from("/var/agents/sandbox")),
    ]
}

fn arb_path_outside(workspace: PathBuf) -> impl Strategy<Value = PathBuf> {
    prop_oneof![
        Just(PathBuf::from("/etc/passwd")),
        Just(PathBuf::from("/root/.ssh/id_rsa")),
        Just(workspace.join("../../etc/shadow")),
        Just(PathBuf::from("/tmp/other_agent/data")),
    ]
}

proptest! {
    /// Property 10: For any sandboxed agent, actions targeting resources outside
    /// the sandbox boundary SHALL be intercepted.
    #[test]
    fn prop10_sandbox_boundary_enforcement(workspace in arb_workspace()) {
        let mgr = SandboxManagerImpl::new();
        let agent_id = uuid::Uuid::new_v4();
        let config = SandboxConfig {
            workspace_dir: workspace.clone(),
            allowed_network_hosts: Some(vec!["allowed.com".to_string()]),
            max_disk_usage_bytes: None,
            max_memory_bytes: None,
            isolation_level: IsolationLevel::Filesystem,
        };
        let sid = mgr.create_sandbox(agent_id, &config).unwrap();

        // File access within boundary should succeed
        let inside = workspace.join("subdir/file.txt");
        prop_assert!(mgr.intercept_action(sid, &SandboxAction::FileAccess(inside)).is_ok());

        // File access outside boundary should be blocked
        let outside_paths = vec![
            PathBuf::from("/etc/passwd"),
            PathBuf::from("/root/.ssh/id_rsa"),
            workspace.join("../../etc/shadow"),
        ];
        for path in outside_paths {
            let result = mgr.intercept_action(sid, &SandboxAction::FileAccess(path.clone()));
            prop_assert!(result.is_err(), "Path {:?} should be blocked", path);
        }

        // Network access to disallowed host should be blocked
        let result = mgr.intercept_action(sid, &SandboxAction::NetworkAccess("evil.com".to_string()));
        prop_assert!(result.is_err());

        // Network access to allowed host should pass
        let result = mgr.intercept_action(sid, &SandboxAction::NetworkAccess("allowed.com".to_string()));
        prop_assert!(result.is_ok());
    }

    /// Property 11: For any new agent without explicit broader permissions,
    /// SHALL be assigned to a sandbox. We verify that create_sandbox always
    /// succeeds and the agent is tracked.
    #[test]
    fn prop11_new_agents_sandboxed_by_default(workspace in arb_workspace()) {
        let mgr = SandboxManagerImpl::new();
        let agent_id = uuid::Uuid::new_v4();
        let config = SandboxConfig {
            workspace_dir: workspace,
            allowed_network_hosts: None,
            max_disk_usage_bytes: None,
            max_memory_bytes: None,
            isolation_level: IsolationLevel::Filesystem,
        };

        // Creating a sandbox for a new agent should always succeed
        let sid = mgr.create_sandbox(agent_id, &config);
        prop_assert!(sid.is_ok(), "Sandbox creation should succeed for any new agent");

        // Agent should be tracked
        let found = mgr.get_sandbox_for_agent(agent_id);
        prop_assert!(found.is_some(), "Agent should have a sandbox assigned");
        prop_assert_eq!(found.unwrap(), sid.unwrap());
    }

    /// Property 27: For any two agents in separate sandboxes, one's actions
    /// SHALL not modify the other's visible state.
    #[test]
    fn prop27_sandbox_isolation_between_agents(
        ws1 in Just(PathBuf::from("/tmp/sandbox/agent1")),
        ws2 in Just(PathBuf::from("/tmp/sandbox/agent2")),
    ) {
        let mgr = SandboxManagerImpl::new();
        let agent1 = uuid::Uuid::new_v4();
        let agent2 = uuid::Uuid::new_v4();

        let config1 = SandboxConfig {
            workspace_dir: ws1.clone(),
            allowed_network_hosts: Some(vec!["api1.com".to_string()]),
            max_disk_usage_bytes: None,
            max_memory_bytes: None,
            isolation_level: IsolationLevel::Filesystem,
        };
        let config2 = SandboxConfig {
            workspace_dir: ws2.clone(),
            allowed_network_hosts: Some(vec!["api2.com".to_string()]),
            max_disk_usage_bytes: None,
            max_memory_bytes: None,
            isolation_level: IsolationLevel::Filesystem,
        };

        let sid1 = mgr.create_sandbox(agent1, &config1).unwrap();
        let sid2 = mgr.create_sandbox(agent2, &config2).unwrap();

        // Agent1 cannot access agent2's workspace
        let cross_access = mgr.intercept_action(sid1, &SandboxAction::FileAccess(ws2.join("secret.txt")));
        prop_assert!(cross_access.is_err(), "Agent1 should not access agent2's workspace");

        // Agent2 cannot access agent1's workspace
        let cross_access = mgr.intercept_action(sid2, &SandboxAction::FileAccess(ws1.join("data.txt")));
        prop_assert!(cross_access.is_err(), "Agent2 should not access agent1's workspace");

        // Agent1 cannot use agent2's allowed network hosts
        let net_cross = mgr.intercept_action(sid1, &SandboxAction::NetworkAccess("api2.com".to_string()));
        prop_assert!(net_cross.is_err(), "Agent1 should not access agent2's network hosts");

        // Each agent can access their own workspace
        prop_assert!(mgr.intercept_action(sid1, &SandboxAction::FileAccess(ws1.join("my_file.txt"))).is_ok());
        prop_assert!(mgr.intercept_action(sid2, &SandboxAction::FileAccess(ws2.join("my_file.txt"))).is_ok());
    }
}
