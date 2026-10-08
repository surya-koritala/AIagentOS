use super::*;

const BOOTSTRAP_TOKEN: &str = "fixture-bootstrap-not-a-live-credential";

async fn connect(addr: std::net::SocketAddr, token: &str) -> SyscallClient {
    let mut client = SyscallClient::connect(addr).await.unwrap();
    assert!(matches!(
        client
            .call(Syscall::Hello {
                protocol_version: PROTOCOL_VERSION
            })
            .await
            .unwrap(),
        SyscallReply::Hello { .. }
    ));
    assert!(matches!(
        client.authenticate(token).await.unwrap(),
        SyscallReply::Authenticated
    ));
    client
}

async fn bootstrap(client: &mut SyscallClient, name: &str) -> (String, String, String, String) {
    let tenant = match client
        .call(Syscall::CreateTenant { name: name.into() })
        .await
        .unwrap()
    {
        SyscallReply::TenantCreated { id } => id,
        other => panic!("unexpected bootstrap reply: {other:?}"),
    };
    let user = match client
        .call(Syscall::CreateUserForTenant {
            tenant_id: tenant.clone(),
            username: "admin".into(),
            email: "admin@example.test".into(),
            role: Role::Admin,
        })
        .await
        .unwrap()
    {
        SyscallReply::UserCreated { id } => id,
        other => panic!("unexpected bootstrap reply: {other:?}"),
    };
    let (key_id, key) = match client
        .call(Syscall::IssueApiKeyForTenant {
            tenant_id: tenant.clone(),
            user_id: user.clone(),
            name: "operator".into(),
        })
        .await
        .unwrap()
    {
        SyscallReply::ApiKeyIssued { key_id, key } => (key_id, key),
        other => panic!("unexpected bootstrap reply: {other:?}"),
    };
    (tenant, user, key_id, key)
}

fn denied(reply: SyscallReply) {
    assert!(
        matches!(
            reply,
            SyscallReply::TypedError {
                code: WireErrorCode::AuthorizationDenied,
                ..
            }
        ),
        "expected authorization denial: {reply:?}"
    );
}

#[tokio::test]
async fn tenant_administration_bootstrap_roles_and_scope_are_enforced_over_wire() {
    let kernel = Arc::new(AgentKernelImpl::new().unwrap());
    let server = SyscallServer::bind(Arc::clone(&kernel), "127.0.0.1:0")
        .await
        .unwrap()
        .with_auth_token(BOOTSTRAP_TOKEN);
    let addr = server.local_addr().unwrap();
    let task = tokio::spawn(server.serve());
    let mut system = connect(addr, BOOTSTRAP_TOKEN).await;
    let (tenant_a, user_a, key_a_id, key_a) = bootstrap(&mut system, "alpha").await;
    let (tenant_b, user_b, key_b_id, key_b) = bootstrap(&mut system, "beta").await;
    let mut admin = connect(addr, &key_a).await;
    for call in [
        Syscall::CreateTenant {
            name: "forbidden".into(),
        },
        Syscall::ListTenants,
        Syscall::RevokeTenant {
            tenant_id: tenant_b.clone(),
            confirm: true,
        },
        Syscall::CreateUserForTenant {
            tenant_id: tenant_b.clone(),
            username: "intruder".into(),
            email: "intruder@example.test".into(),
            role: Role::Admin,
        },
        Syscall::ListUsersForTenant {
            tenant_id: tenant_b.clone(),
        },
        Syscall::IssueApiKeyForTenant {
            tenant_id: tenant_b.clone(),
            user_id: user_b.clone(),
            name: "intruder".into(),
        },
        Syscall::ListApiKeysForTenant {
            tenant_id: tenant_b.clone(),
        },
        Syscall::IssueApiKey {
            user_id: user_b.clone(),
            name: "foreign".into(),
        },
        Syscall::RevokeUser {
            user_id: user_b.clone(),
            confirm: true,
        },
        Syscall::RevokeApiKey {
            key_id: key_b_id.clone(),
            confirm: true,
        },
    ] {
        denied(admin.call(call).await.unwrap());
    }
    let users = match admin.call(Syscall::ListUsers).await.unwrap() {
        SyscallReply::Users { users } => users,
        other => panic!("unexpected reply: {other:?}"),
    };
    assert_eq!(users.len(), 1);
    assert_eq!(users[0].id, user_a);
    assert_eq!(users[0].tenant_id, tenant_a);
    let keys_reply = admin.call(Syscall::ListApiKeys).await.unwrap();
    let inventory = serde_json::to_string(&keys_reply).unwrap();
    assert!(!inventory.contains(&key_a) && !inventory.contains(&key_b));
    assert!(inventory.contains(&key_a_id) && !inventory.contains(&key_b_id));
    for role in [Role::User, Role::ReadOnly] {
        let user = match admin
            .call(Syscall::CreateUser {
                username: role.as_str().into(),
                email: "user@example.test".into(),
                role,
            })
            .await
            .unwrap()
        {
            SyscallReply::UserCreated { id } => id,
            other => panic!("unexpected reply: {other:?}"),
        };
        let key = match admin
            .call(Syscall::IssueApiKey {
                user_id: user.clone(),
                name: "worker".into(),
            })
            .await
            .unwrap()
        {
            SyscallReply::ApiKeyIssued { key, .. } => key,
            other => panic!("unexpected reply: {other:?}"),
        };
        let mut worker = connect(addr, &key).await;
        for call in [
            Syscall::CreateUser {
                username: "forbidden".into(),
                email: "user@example.test".into(),
                role: Role::User,
            },
            Syscall::ListUsers,
            Syscall::RevokeUser {
                user_id: user.clone(),
                confirm: true,
            },
            Syscall::IssueApiKey {
                user_id: user.clone(),
                name: "forbidden".into(),
            },
            Syscall::ListApiKeys,
            Syscall::RevokeApiKey {
                key_id: key_a_id.clone(),
                confirm: true,
            },
        ] {
            denied(worker.call(call).await.unwrap());
        }
    }
    task.abort();
}

#[tokio::test]
async fn identity_revocations_deny_new_and_live_connections_and_allow_self_revocation() {
    let kernel = Arc::new(AgentKernelImpl::new().unwrap());
    let server = SyscallServer::bind(Arc::clone(&kernel), "127.0.0.1:0")
        .await
        .unwrap()
        .with_auth_token(BOOTSTRAP_TOKEN);
    let addr = server.local_addr().unwrap();
    let task = tokio::spawn(server.serve());
    let mut system = connect(addr, BOOTSTRAP_TOKEN).await;
    let (tenant, user, id, key) = bootstrap(&mut system, "self-revoke").await;
    for call in [
        Syscall::RevokeTenant {
            tenant_id: key.clone(),
            confirm: true,
        },
        Syscall::RevokeUser {
            user_id: key.clone(),
            confirm: true,
        },
    ] {
        let reply = system.call(call).await.unwrap();
        assert!(matches!(
            reply,
            SyscallReply::TypedError {
                code: WireErrorCode::InvalidArgument,
                ..
            }
        ));
        assert!(!serde_json::to_string(&reply).unwrap().contains(&key));
    }
    let mut live = connect(addr, &key).await;
    let mut admin = connect(addr, &key).await;
    assert!(matches!(
        admin
            .call(Syscall::RevokeApiKey {
                key_id: id.clone(),
                confirm: false
            })
            .await
            .unwrap(),
        SyscallReply::TypedError { .. }
    ));
    let reply = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        admin.call(Syscall::RevokeApiKey {
            key_id: id,
            confirm: true,
        }),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(matches!(
        reply,
        SyscallReply::ApiKeyRevoked { existed: true }
    ));
    assert!(matches!(
        live.call(Syscall::ListUsers).await.unwrap(),
        SyscallReply::TypedError {
            code: WireErrorCode::AuthenticationRequired,
            ..
        }
    ));
    let mut fresh = SyscallClient::connect(addr).await.unwrap();
    assert!(matches!(
        fresh.authenticate(&key).await.unwrap(),
        SyscallReply::Error { .. }
    ));
    let replacement = match system
        .call(Syscall::IssueApiKeyForTenant {
            tenant_id: tenant.clone(),
            user_id: user.clone(),
            name: "replacement".into(),
        })
        .await
        .unwrap()
    {
        SyscallReply::ApiKeyIssued { key, .. } => key,
        other => panic!("unexpected reply: {other:?}"),
    };
    let mut self_admin = connect(addr, &replacement).await;
    let reply = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        self_admin.call(Syscall::RevokeUser {
            user_id: user,
            confirm: true,
        }),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(matches!(reply, SyscallReply::UserRevoked { existed: true }));
    assert!(matches!(
        system
            .call(Syscall::RevokeTenant {
                tenant_id: tenant.clone(),
                confirm: false
            })
            .await
            .unwrap(),
        SyscallReply::TypedError { .. }
    ));
    assert!(matches!(
        system
            .call(Syscall::RevokeTenant {
                tenant_id: tenant,
                confirm: true
            })
            .await
            .unwrap(),
        SyscallReply::TenantRevoked { existed: true }
    ));
    task.abort();
}

#[test]
fn identity_contract_and_debug_never_reuse_bearer_secrets_for_revocation() {
    assert_eq!(
        WireErrorCode::classify("memory store failed: context storage pressure").0,
        WireErrorCode::QuotaExceeded
    );
    let key = "ak_fixture_bearer_secret_never_a_key_id";
    let reply = SyscallReply::ApiKeyIssued {
        key_id: crate::auth::hash_secret(key),
        key: key.into(),
    };
    assert!(!format!("{reply:?}").contains(key));
    let issued = crate::auth::IssuedApiKey {
        key_id: crate::auth::hash_secret(key),
        key: key.into(),
    };
    assert!(!format!("{issued:?}").contains(key));
    let request = Syscall::RevokeApiKey {
        key_id: issued.key_id.clone(),
        confirm: true,
    };
    assert!(!serde_json::to_string(&request).unwrap().contains(key));
    assert!(!format!("{request:?}").contains(key));
    assert_eq!(
        serde_json::to_string(&reply).unwrap().matches(key).count(),
        1
    );
    let contract = crate::wire_contract::protocol_description();
    assert_eq!(contract.protocol_version, 2);
    assert!(contract
        .features
        .contains(&"tenant_identity_administration".into()));
    let tags: Vec<_> = contract.request_schema["oneOf"]
        .as_array()
        .unwrap()
        .iter()
        .map(|variant| variant["properties"]["op"]["const"].as_str().unwrap())
        .collect();
    for op in [
        "create_tenant",
        "list_tenants",
        "revoke_tenant",
        "create_user",
        "list_users",
        "revoke_user",
        "issue_api_key",
        "list_api_keys",
        "revoke_api_key",
    ] {
        assert!(tags.contains(&op));
    }
}
