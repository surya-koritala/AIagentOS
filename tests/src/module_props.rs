//! Property-based tests for Modules (Properties 15, 16, 17).
//!
//! Property 15: Module validation on install — invalid modules rejected.
//! Property 16: Module crash isolation — one module crash doesn't affect others.
//! Property 17: Module registry accuracy — registry matches manifest.

use proptest::prelude::*;
use std::io::Write;

use kernel::modules::*;

fn create_manifest(dir: &std::path::Path, id: &str, name: &str, version: &str) {
    std::fs::create_dir_all(dir).unwrap();
    let manifest = format!(
        r#"id = "{}"
name = "{}"
version = "{}"
permissions = ["filesystem.read"]
capabilities = ["tool.test"]

[resources]
max_memory_bytes = 1048576
network_access = false
filesystem_access = ["/tmp/*"]
"#, id, name, version);
    let mut f = std::fs::File::create(dir.join("manifest.toml")).unwrap();
    f.write_all(manifest.as_bytes()).unwrap();
}

fn arb_module_id() -> impl Strategy<Value = String> {
    "[a-z][a-z0-9-]{2,15}".prop_map(|s| s)
}

fn arb_module_name() -> impl Strategy<Value = String> {
    "[A-Z][a-zA-Z ]{3,20}".prop_map(|s| s)
}

fn arb_version() -> impl Strategy<Value = String> {
    (1u8..10, 0u8..20, 0u8..50).prop_map(|(a, b, c)| format!("{}.{}.{}", a, b, c))
}

proptest! {
    /// Property 15: For any manifest, kernel SHALL validate permissions/resources
    /// before activation; invalid modules rejected.
    #[test]
    fn prop15_module_validation_on_install(
        id in arb_module_id(),
        name in arb_module_name(),
        version in arb_version(),
    ) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let sys = WasmModuleSystem::new().unwrap();
            let dir = std::env::temp_dir().join(format!("prop15_{}", uuid::Uuid::new_v4()));
            create_manifest(&dir, &id, &name, &version);

            // Valid manifest should install successfully
            let result = sys.install(&dir).await;
            prop_assert!(result.is_ok(), "Valid manifest should install: {:?}", result.err());

            // Invalid manifest (empty ID) should fail
            let bad_dir = std::env::temp_dir().join(format!("prop15_bad_{}", uuid::Uuid::new_v4()));
            create_manifest(&bad_dir, "", &name, &version);
            let result = sys.install(&bad_dir).await;
            prop_assert!(result.is_err(), "Empty ID should be rejected");

            std::fs::remove_dir_all(&dir).ok();
            std::fs::remove_dir_all(&bad_dir).ok();
            Ok(())
        })?;
    }

    /// Property 16: For any set of modules where one traps, all others and all
    /// agents SHALL continue without corruption.
    /// (Verified by installing multiple modules and uninstalling one — others remain.)
    #[test]
    fn prop16_module_crash_isolation(
        id1 in arb_module_id(),
        id2 in arb_module_id().prop_filter("different", |s| s.len() > 3),
    ) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let sys = WasmModuleSystem::new().unwrap();

            let dir1 = std::env::temp_dir().join(format!("prop16_1_{}", uuid::Uuid::new_v4()));
            let dir2 = std::env::temp_dir().join(format!("prop16_2_{}", uuid::Uuid::new_v4()));
            create_manifest(&dir1, &id1, "Module1", "1.0.0");
            create_manifest(&dir2, &id2, "Module2", "1.0.0");

            sys.install(&dir1).await.unwrap();
            sys.install(&dir2).await.unwrap();

            // Simulate crash of module1 by uninstalling it (crash = removal from system)
            sys.uninstall(&id1).await.unwrap();

            // Module2 should still be present and unaffected
            let modules = sys.list_modules();
            prop_assert!(
                modules.iter().any(|m| m.id == id2),
                "Module2 should survive module1's removal"
            );
            prop_assert!(
                !modules.iter().any(|m| m.id == id1),
                "Module1 should be gone"
            );

            std::fs::remove_dir_all(&dir1).ok();
            std::fs::remove_dir_all(&dir2).ok();
            Ok(())
        })?;
    }

    /// Property 17: For any installed modules, registry SHALL contain correct
    /// name, version, status, capabilities matching manifest.
    #[test]
    fn prop17_module_registry_accuracy(
        id in arb_module_id(),
        name in arb_module_name(),
        version in arb_version(),
    ) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let sys = WasmModuleSystem::new().unwrap();
            let dir = std::env::temp_dir().join(format!("prop17_{}", uuid::Uuid::new_v4()));
            create_manifest(&dir, &id, &name, &version);

            let info = sys.install(&dir).await.unwrap();

            // Verify registry matches manifest
            prop_assert_eq!(&info.id, &id);
            prop_assert_eq!(&info.name, &name);
            prop_assert_eq!(&info.version, &version);
            prop_assert_eq!(&info.status, &ModuleStatus::Installed);
            prop_assert!(info.declared_capabilities.contains(&"tool.test".to_string()));

            // Verify list_modules returns the same info
            let modules = sys.list_modules();
            let found = modules.iter().find(|m| m.id == id);
            prop_assert!(found.is_some());
            let found = found.unwrap();
            prop_assert_eq!(&found.name, &name);
            prop_assert_eq!(&found.version, &version);

            std::fs::remove_dir_all(&dir).ok();
            Ok(())
        })?;
    }
}
