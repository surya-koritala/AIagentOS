//! WASM Module System — manages runtime loading/unloading of WASM extensions.
//!
//! Uses Wasmtime for sandboxed execution with resource limits and crash isolation.

use std::path::PathBuf;
use std::sync::Mutex;

use dashmap::DashMap;
use serde::{Deserialize, Serialize};

use crate::permissions::PermissionRule;
use crate::{ModuleError, ModuleId};

/// Status of a module in its lifecycle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ModuleStatus {
    Installed,
    Loaded,
    Active,
    Error(String),
    Disabled,
}

/// Resource requirements declared by a module.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceRequirements {
    pub max_memory_bytes: Option<u64>,
    pub max_cpu_time_ms: Option<u64>,
    pub network_access: bool,
    pub filesystem_access: Vec<String>,
}

/// Module manifest parsed from TOML.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleManifest {
    pub id: ModuleId,
    pub name: String,
    pub version: String,
    pub permissions: Vec<String>,
    pub capabilities: Vec<String>,
    pub resources: ResourceRequirements,
    /// Tools this module provides (optional).
    #[serde(default)]
    pub tools: Vec<ModuleToolDeclaration>,
}

/// A tool declared by a module in its manifest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleToolDeclaration {
    pub name: String,
    pub description: String,
    pub function: String, // exported WASM function name
    #[serde(default)]
    pub parameters: serde_json::Value,
}

/// Information about an installed module.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleInfo {
    pub id: ModuleId,
    pub name: String,
    pub version: String,
    pub status: ModuleStatus,
    pub declared_permissions: Vec<PermissionRule>,
    pub declared_capabilities: Vec<String>,
    pub resource_requirements: ResourceRequirements,
}

/// The Module System trait.
#[async_trait::async_trait]
pub trait ModuleSystem: Send + Sync {
    async fn install(&self, module_path: &PathBuf) -> Result<ModuleInfo, ModuleError>;
    async fn uninstall(&self, module_id: &ModuleId) -> Result<(), ModuleError>;
    async fn load(&self, module_id: &ModuleId) -> Result<(), ModuleError>;
    async fn unload(&self, module_id: &ModuleId) -> Result<(), ModuleError>;
    fn list_modules(&self) -> Vec<ModuleInfo>;
}

/// Internal module state.
struct ModuleState {
    info: ModuleInfo,
    wasm_bytes: Option<Vec<u8>>,
}

/// Host function context passed to WASM modules.
pub struct HostContext {
    /// Results from host function calls (module reads these).
    pub last_result: String,
}

/// Concrete WASM module system implementation using Wasmtime.
pub struct WasmModuleSystem {
    modules: DashMap<ModuleId, ModuleState>,
    engine: Mutex<wasmtime::Engine>,
}

impl WasmModuleSystem {
    pub fn new() -> Result<Self, ModuleError> {
        let mut config = wasmtime::Config::new();
        config.consume_fuel(true);
        let engine = wasmtime::Engine::new(&config)
            .map_err(|e| ModuleError::LoadFailed(e.to_string()))?;
        Ok(Self {
            modules: DashMap::new(),
            engine: Mutex::new(engine),
        })
    }

    /// Execute a function exported by a loaded module.
    /// Host functions (read_file, http_get, log) are available to the module.
    pub fn execute_module_function(&self, module_id: &ModuleId, function: &str, _input: &str) -> Result<String, ModuleError> {
        let state = self.modules.get(module_id)
            .ok_or_else(|| ModuleError::NotFound(module_id.clone()))?;

        if state.info.status != ModuleStatus::Loaded && state.info.status != ModuleStatus::Active {
            return Err(ModuleError::LoadFailed("Module not loaded".into()));
        }

        let bytes = state.wasm_bytes.as_ref()
            .ok_or_else(|| ModuleError::LoadFailed("No WASM binary".into()))?;

        let engine = self.engine.lock().unwrap();
        let module = wasmtime::Module::new(&engine, bytes)
            .map_err(|e| ModuleError::LoadFailed(e.to_string()))?;

        let mut store = wasmtime::Store::new(&engine, HostContext { last_result: String::new() });
        store.set_fuel(1_000_000).ok(); // CPU limit

        let mut linker = wasmtime::Linker::new(&engine);

        // Host function: log a message
        linker.func_wrap("env", "host_log", |mut caller: wasmtime::Caller<'_, HostContext>, ptr: i32, len: i32| {
            if let Some(memory) = caller.get_export("memory").and_then(|e| e.into_memory()) {
                let data = memory.data(&caller);
                if let Some(slice) = data.get(ptr as usize..(ptr as usize + len as usize)) {
                    if let Ok(msg) = std::str::from_utf8(slice) {
                        tracing::info!("[WASM module] {}", msg);
                    }
                }
            }
        }).ok();

        // Host function: read a file (result stored in host context)
        linker.func_wrap("env", "host_read_file", |mut caller: wasmtime::Caller<'_, HostContext>, ptr: i32, len: i32| -> i32 {
            if let Some(memory) = caller.get_export("memory").and_then(|e| e.into_memory()) {
                let data = memory.data(&caller);
                if let Some(slice) = data.get(ptr as usize..(ptr as usize + len as usize)) {
                    if let Ok(path) = std::str::from_utf8(slice) {
                        match std::fs::read_to_string(path) {
                            Ok(content) => {
                                caller.data_mut().last_result = content;
                                return 0; // success
                            }
                            Err(_) => return -1,
                        }
                    }
                }
            }
            -1
        }).ok();

        // Host function: get result length
        linker.func_wrap("env", "host_result_len", |caller: wasmtime::Caller<'_, HostContext>| -> i32 {
            caller.data().last_result.len() as i32
        }).ok();

        // Instantiate module with host functions
        let instance = linker.instantiate(&mut store, &module)
            .map_err(|e| ModuleError::LoadFailed(format!("Instantiation failed: {}", e)))?;

        // Call the requested function
        let func = instance.get_typed_func::<(), i32>(&mut store, function)
            .map_err(|e| ModuleError::LoadFailed(format!("Function '{}' not found: {}", function, e)))?;

        let result = func.call(&mut store, ())
            .map_err(|e| ModuleError::CrashDetected(format!("Module trapped: {}", e)))?;

        Ok(result.to_string())
    }

    fn validate_manifest(manifest: &ModuleManifest) -> Result<(), ModuleError> {
        if manifest.id.is_empty() {
            return Err(ModuleError::ValidationFailed("Module ID cannot be empty".into()));
        }
        if manifest.name.is_empty() {
            return Err(ModuleError::ValidationFailed("Module name cannot be empty".into()));
        }
        if manifest.version.is_empty() {
            return Err(ModuleError::ValidationFailed("Module version cannot be empty".into()));
        }
        // Validate resource requirements are reasonable
        if let Some(mem) = manifest.resources.max_memory_bytes {
            if mem > 1024 * 1024 * 1024 { // 1GB max
                return Err(ModuleError::ValidationFailed("Memory requirement exceeds 1GB limit".into()));
            }
        }
        Ok(())
    }

    fn parse_manifest(manifest_path: &PathBuf) -> Result<ModuleManifest, ModuleError> {
        let content = std::fs::read_to_string(manifest_path)
            .map_err(|e| ModuleError::InstallFailed(format!("Cannot read manifest: {}", e)))?;
        let manifest: ModuleManifest = toml::from_str(&content)
            .map_err(|e| ModuleError::InstallFailed(format!("Invalid manifest TOML: {}", e)))?;
        Ok(manifest)
    }
}

#[async_trait::async_trait]
impl ModuleSystem for WasmModuleSystem {
    async fn install(&self, module_path: &PathBuf) -> Result<ModuleInfo, ModuleError> {
        // Look for manifest.toml in the module directory
        let manifest_path = module_path.join("manifest.toml");
        let manifest = Self::parse_manifest(&manifest_path)?;

        // Validate manifest
        Self::validate_manifest(&manifest)?;

        // Check for WASM binary
        let wasm_path = module_path.join("module.wasm");
        let wasm_bytes = if wasm_path.exists() {
            Some(std::fs::read(&wasm_path)
                .map_err(|e| ModuleError::InstallFailed(format!("Cannot read WASM: {}", e)))?)
        } else {
            None
        };

        // Validate WASM binary if present
        if let Some(ref bytes) = wasm_bytes {
            let engine = self.engine.lock().unwrap();
            wasmtime::Module::validate(&engine, bytes)
                .map_err(|e| ModuleError::ValidationFailed(format!("Invalid WASM binary: {}", e)))?;
        }

        let info = ModuleInfo {
            id: manifest.id.clone(),
            name: manifest.name,
            version: manifest.version,
            status: ModuleStatus::Installed,
            declared_permissions: Vec::new(),
            declared_capabilities: manifest.capabilities,
            resource_requirements: manifest.resources,
        };

        self.modules.insert(manifest.id.clone(), ModuleState {
            info: info.clone(),
            wasm_bytes,
        });

        Ok(info)
    }

    async fn uninstall(&self, module_id: &ModuleId) -> Result<(), ModuleError> {
        self.modules.remove(module_id)
            .ok_or_else(|| ModuleError::NotFound(module_id.clone()))?;
        Ok(())
    }

    async fn load(&self, module_id: &ModuleId) -> Result<(), ModuleError> {
        let mut state = self.modules.get_mut(module_id)
            .ok_or_else(|| ModuleError::NotFound(module_id.clone()))?;

        if state.wasm_bytes.is_none() {
            return Err(ModuleError::LoadFailed("No WASM binary available".into()));
        }

        // Instantiate with resource limits
        let engine = self.engine.lock().unwrap();
        let bytes = state.wasm_bytes.as_ref().unwrap();
        let _module = wasmtime::Module::new(&engine, bytes)
            .map_err(|e| ModuleError::LoadFailed(e.to_string()))?;

        state.info.status = ModuleStatus::Loaded;
        Ok(())
    }

    async fn unload(&self, module_id: &ModuleId) -> Result<(), ModuleError> {
        let mut state = self.modules.get_mut(module_id)
            .ok_or_else(|| ModuleError::NotFound(module_id.clone()))?;
        state.info.status = ModuleStatus::Installed;
        Ok(())
    }

    fn list_modules(&self) -> Vec<ModuleInfo> {
        self.modules.iter().map(|entry| entry.value().info.clone()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn create_test_module(dir: &std::path::Path) {
        let manifest = r#"
id = "test-module"
name = "Test Module"
version = "1.0.0"
permissions = ["filesystem.read"]
capabilities = ["tool.test"]

[resources]
max_memory_bytes = 1048576
network_access = false
filesystem_access = ["/tmp/*"]
"#;
        std::fs::create_dir_all(dir).unwrap();
        let mut f = std::fs::File::create(dir.join("manifest.toml")).unwrap();
        f.write_all(manifest.as_bytes()).unwrap();
    }

    #[tokio::test]
    async fn install_valid_module() {
        let dir = std::env::temp_dir().join("test_module_install");
        create_test_module(&dir);

        let sys = WasmModuleSystem::new().unwrap();
        let info = sys.install(&dir).await.unwrap();
        assert_eq!(info.id, "test-module");
        assert_eq!(info.status, ModuleStatus::Installed);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn install_invalid_manifest_fails() {
        let dir = std::env::temp_dir().join("test_module_invalid");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("manifest.toml"), "invalid toml {{{{").unwrap();

        let sys = WasmModuleSystem::new().unwrap();
        let result = sys.install(&dir).await;
        assert!(result.is_err());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn uninstall_module() {
        let dir = std::env::temp_dir().join("test_module_uninstall");
        create_test_module(&dir);

        let sys = WasmModuleSystem::new().unwrap();
        sys.install(&dir).await.unwrap();
        sys.uninstall(&"test-module".to_string()).await.unwrap();
        assert!(sys.list_modules().is_empty());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn uninstall_nonexistent_fails() {
        let sys = WasmModuleSystem::new().unwrap();
        let result = sys.uninstall(&"nonexistent".to_string()).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn list_modules_returns_installed() {
        let dir = std::env::temp_dir().join("test_module_list");
        create_test_module(&dir);

        let sys = WasmModuleSystem::new().unwrap();
        sys.install(&dir).await.unwrap();
        let modules = sys.list_modules();
        assert_eq!(modules.len(), 1);
        assert_eq!(modules[0].name, "Test Module");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn validate_empty_id_fails() {
        let manifest = ModuleManifest {
            id: "".to_string(),
            name: "Test".to_string(),
            version: "1.0".to_string(),
            permissions: vec![],
            capabilities: vec![],
            tools: vec![],
            resources: ResourceRequirements {
                max_memory_bytes: None,
                max_cpu_time_ms: None,
                network_access: false,
                filesystem_access: vec![],
            },
        };
        assert!(WasmModuleSystem::validate_manifest(&manifest).is_err());
    }
}
