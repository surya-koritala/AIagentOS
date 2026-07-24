//! Public-surface proof for the signed package lifecycle tracked by #119.

use std::sync::Arc;

use agent_sdk::{
    KernelClient, PackageArchive, PackageFile, PackageFileKind, PackageManifest, PackagePayload,
    PackageSbom, PackageSigningKey, SbomComponent,
};
use kernel::agent_package::AgentManifest;
use kernel::auth::Role;
use kernel::sandbox::SandboxManager;
use kernel::syscall_server::SyscallServer;
use kernel::AgentKernelImpl;
use semver::Version;

fn package(name: &str, version: &str, publisher: &str) -> PackagePayload {
    PackagePayload {
        schema_version: 1,
        package: PackageManifest {
            name: name.into(),
            version: Version::parse(version).unwrap(),
            description: "A fully signed public-surface package".into(),
            publisher: publisher.into(),
            license: Some("AGPL-3.0-only".into()),
            dependencies: Vec::new(),
            capabilities_required: vec!["CAP_FILE_READ".into()],
            tools_required: Vec::new(),
        },
        agent: AgentManifest {
            name: name.into(),
            description: "Runs through normal tenant admission".into(),
            task: "prove signed package lifecycle".into(),
            entry: Some("start".into()),
            provider: "stub".into(),
            profile: "read-only".into(),
            priority: 3,
            nice: None,
            tools: Vec::new(),
            memory: vec!["installed from a verified archive".into()],
        },
        files: vec![PackageFile {
            path: "prompts/entry.txt".into(),
            kind: PackageFileKind::Prompt,
            bytes: b"start".to_vec(),
            checksum_sha256: String::new(),
        }],
        sbom: PackageSbom {
            format: "SPDX-2.3".into(),
            components: vec![SbomComponent {
                name: "agentos-kernel-api".into(),
                version: "1".into(),
                license: Some("AGPL-3.0-only".into()),
                checksum_sha256: None,
            }],
        },
    }
}

#[tokio::test]
async fn publish_sign_fetch_install_run_upgrade_rollback_remove_over_sdk() {
    let kernel = Arc::new(AgentKernelImpl::new().expect("kernel"));
    let tenant = kernel.create_tenant("package-e2e").await.unwrap();
    let admin = kernel
        .register_user(
            &tenant,
            "package-publisher",
            "packages@example.invalid",
            Role::Admin,
        )
        .await
        .unwrap();
    let api_key = kernel.issue_api_key(&admin, "package-e2e").await.unwrap();

    let server = SyscallServer::bind(kernel.clone(), "127.0.0.1:0")
        .await
        .expect("bind package server");
    let address = server.local_addr().unwrap();
    let task = tokio::spawn(server.serve());
    let mut client = KernelClient::connect(address).await.unwrap();
    client.authenticate(api_key).await.unwrap();

    let (signer, _) = PackageSigningKey::generate(&admin, "release-2026").unwrap();
    client
        .trust_package_key(
            &admin,
            signer.key_id(),
            &signer.public_key(),
            (chrono::Utc::now() - chrono::Duration::minutes(1)).to_rfc3339(),
            None,
            None,
        )
        .await
        .unwrap();

    let archive_v1 = PackageArchive::sign(package("sdk-runner", "1.0.0", &admin), &signer).unwrap();
    let published_v1 = client.publish_package(&archive_v1).await.unwrap();
    assert_eq!(published_v1.version, Version::parse("1.0.0").unwrap());
    assert_eq!(
        client.fetch_package("sdk-runner", "1.0.0").await.unwrap(),
        archive_v1
    );
    assert_eq!(client.search_packages("sdk-runner").await.unwrap().len(), 1);

    let installed_v1 = client
        .install_package("sdk-runner", "=1.0.0")
        .await
        .unwrap();
    assert_eq!(installed_v1.version, Version::parse("1.0.0").unwrap());
    let agent_id = client.run_installed_package("sdk-runner").await.unwrap();
    let agent_uuid = uuid::Uuid::parse_str(&agent_id).unwrap();
    assert_eq!(
        kernel.context_manager.agent_tenant(agent_uuid).unwrap(),
        Some(tenant.clone())
    );
    assert!(kernel
        .sandbox_manager
        .get_sandbox_for_agent(agent_uuid)
        .is_some());
    let gate = kernel.syscall_gate.agent_info(agent_uuid).unwrap();
    assert!(!gate.namespaces.is_empty());
    assert_ne!(gate.cgroup, kernel.cgroups.root());
    assert!(!gate.capabilities.contains(&"CAP_FILE_WRITE".into()));
    let loaded = kernel
        .context_manager
        .list_loaded_package_instances(Some(&tenant))
        .unwrap();
    assert!(loaded
        .iter()
        .any(|instance| instance.agent_id == agent_id && instance.name == "sdk-runner"));

    let archive_v2 = PackageArchive::sign(package("sdk-runner", "2.0.0", &admin), &signer).unwrap();
    client.publish_package(&archive_v2).await.unwrap();
    let installed_v2 = client
        .install_package("sdk-runner", "=2.0.0")
        .await
        .unwrap();
    assert_eq!(installed_v2.version, Version::parse("2.0.0").unwrap());
    let restored = client.rollback_package("sdk-runner").await.unwrap();
    assert_eq!(restored.version, Version::parse("1.0.0").unwrap());
    assert_eq!(client.list_installed_packages().await.unwrap().len(), 1);
    client.remove_package("sdk-runner").await.unwrap();
    assert!(client.list_installed_packages().await.unwrap().is_empty());

    task.abort();
}
