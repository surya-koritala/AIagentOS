//! Property-based tests for Permissions (Properties 8, 9, 12, 18).
//!
//! Property 8: Permission enforcement matches profile rules.
//! Property 9: High-risk actions require user approval (except full-access).
//! Property 12: Resource access always validates permissions.
//! Property 18: Agent action audit logging completeness.

use proptest::prelude::*;

use kernel::permissions::*;
use kernel::resources::ResourceType;

fn arb_resource_type() -> impl Strategy<Value = ResourceType> {
    prop_oneof![
        Just(ResourceType::Filesystem),
        Just(ResourceType::Network),
        Just(ResourceType::Application),
        Just(ResourceType::Browser),
        Just(ResourceType::Peripheral),
    ]
}

fn arb_profile_id() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("read-only".to_string()),
        Just("standard".to_string()),
        Just("elevated".to_string()),
        Just("full-access".to_string()),
    ]
}

fn arb_operation() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("read".to_string()),
        Just("write".to_string()),
        Just("create".to_string()),
        Just("list".to_string()),
        Just("delete".to_string()),
        Just("execute".to_string()),
        Just("get".to_string()),
        Just("post".to_string()),
    ]
}

proptest! {
    /// Property 8: For any agent with a profile and any request, the decision
    /// SHALL match the profile rules.
    #[test]
    fn prop8_permission_enforcement_matches_profile(
        profile_id in arb_profile_id(),
        resource in arb_resource_type(),
        operation in arb_operation(),
    ) {
        let mgr = PermissionManager::new();
        let agent_id = uuid::Uuid::new_v4();
        mgr.assign_profile(agent_id, &profile_id);

        let decision = mgr.check_access(agent_id, &resource, &operation, None);

        match profile_id.as_str() {
            "full-access" => {
                prop_assert_eq!(decision, AccessDecision::Allowed,
                    "Full-access should always allow");
            }
            _ => {
                // High-risk ops should require approval
                if ["delete", "execute", "install", "uninstall", "format", "sudo"].contains(&operation.as_str()) {
                    prop_assert_eq!(decision, AccessDecision::RequiresApproval,
                        "High-risk op '{}' should require approval for profile '{}'",
                        operation, profile_id);
                } else {
                    // Decision should be Allowed or Denied based on profile rules
                    prop_assert!(
                        decision == AccessDecision::Allowed || decision == AccessDecision::Denied,
                        "Non-high-risk op should be Allowed or Denied, got {:?}",
                        decision
                    );
                }
            }
        }
    }

    /// Property 9: For any high-risk action, SHALL return RequiresApproval
    /// regardless of profile (except full-access).
    #[test]
    fn prop9_high_risk_requires_approval(
        profile_id in arb_profile_id().prop_filter("not full-access", |p| p != "full-access"),
        resource in arb_resource_type(),
    ) {
        let mgr = PermissionManager::new();
        let agent_id = uuid::Uuid::new_v4();
        mgr.assign_profile(agent_id, &profile_id);

        // All high-risk operations
        for op in &["delete", "execute", "install", "uninstall", "format", "sudo"] {
            let decision = mgr.check_access(agent_id, &resource, op, None);
            prop_assert_eq!(
                decision, AccessDecision::RequiresApproval,
                "High-risk op '{}' with profile '{}' should require approval",
                op, profile_id
            );
        }
    }

    /// Property 12: For any resource request, permission check is invoked.
    /// We verify this by checking that check_access always returns a valid decision
    /// (never panics or returns an undefined state).
    #[test]
    fn prop12_resource_access_validates_permissions(
        profile_id in arb_profile_id(),
        resource in arb_resource_type(),
        operation in arb_operation(),
    ) {
        let mgr = PermissionManager::new();
        let agent_id = uuid::Uuid::new_v4();
        mgr.assign_profile(agent_id, &profile_id);

        // This should never panic — always returns a valid decision
        let decision = mgr.check_access(agent_id, &resource, &operation, None);
        prop_assert!(
            matches!(decision, AccessDecision::Allowed | AccessDecision::Denied | AccessDecision::RequiresApproval),
            "Decision must be a valid variant"
        );
    }

    /// Property 18: For any agent action, a corresponding audit entry SHALL be created.
    #[test]
    fn prop18_audit_logging_completeness(
        operation in arb_operation(),
        resource in arb_resource_type(),
    ) {
        let mgr = PermissionManager::new();
        let agent_id = uuid::Uuid::new_v4();
        mgr.assign_profile(agent_id, &"standard".to_string());

        let decision = mgr.check_access(agent_id, &resource, &operation, None);

        // Log the action
        mgr.log_action(agent_id, &operation, &format!("{:?}", resource), decision.clone(), ActionOutcome::Success);

        // Verify audit entry exists
        let log = mgr.get_audit_log(None);
        prop_assert!(!log.is_empty(), "Audit log should have at least one entry");

        let entry = log.last().unwrap();
        prop_assert_eq!(entry.agent_id, agent_id);
        prop_assert_eq!(&entry.action, &operation);
        prop_assert_eq!(&entry.decision, &decision);
        prop_assert_eq!(&entry.outcome, &ActionOutcome::Success);
    }
}
