//! Agent Package System — .agent package format, install, versioning.

use std::path::Path;
use serde::{Deserialize, Serialize};

/// Package manifest (inside .agent file).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageManifest {
    pub name: String,
    pub version: String,
    pub description: String,
    pub author: Option<String>,
    pub license: Option<String>,
    #[serde(default)]
    pub dependencies: Vec<PackageDep>,
    #[serde(default)]
    pub capabilities_required: Vec<String>,
    #[serde(default)]
    pub tools_required: Vec<String>,
}

/// A package dependency.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageDep {
    pub name: String,
    pub version: String, // semver constraint e.g. ">=1.0.0"
    #[serde(default)]
    pub optional: bool,
}

/// An installed package.
#[derive(Debug, Clone)]
pub struct InstalledPackage {
    pub manifest: PackageManifest,
    pub install_path: String,
    pub installed_at: String,
}

/// Package registry (local database of installed packages).
pub struct PackageRegistry {
    packages: Vec<InstalledPackage>,
}

impl PackageRegistry {
    pub fn new() -> Self { Self { packages: Vec::new() } }

    /// Install a package from manifest.
    pub fn install(&mut self, manifest: PackageManifest, path: String) -> Result<(), String> {
        // Check if already installed
        if self.packages.iter().any(|p| p.manifest.name == manifest.name) {
            return Err(format!("package '{}' already installed", manifest.name));
        }
        // Check dependencies
        for dep in &manifest.dependencies {
            if !dep.optional && !self.is_installed(&dep.name) {
                return Err(format!("missing dependency: {} {}", dep.name, dep.version));
            }
        }
        self.packages.push(InstalledPackage {
            manifest, install_path: path,
            installed_at: chrono::Utc::now().to_rfc3339(),
        });
        Ok(())
    }

    /// Remove a package.
    pub fn remove(&mut self, name: &str) -> Result<(), String> {
        // Check if other packages depend on this
        for pkg in &self.packages {
            if pkg.manifest.dependencies.iter().any(|d| d.name == name && !d.optional) {
                return Err(format!("'{}' is required by '{}'", name, pkg.manifest.name));
            }
        }
        self.packages.retain(|p| p.manifest.name != name);
        Ok(())
    }

    /// Check if a package is installed.
    pub fn is_installed(&self, name: &str) -> bool {
        self.packages.iter().any(|p| p.manifest.name == name)
    }

    /// Get installed package info.
    pub fn get(&self, name: &str) -> Option<&InstalledPackage> {
        self.packages.iter().find(|p| p.manifest.name == name)
    }

    /// List all installed packages.
    pub fn list(&self) -> &[InstalledPackage] { &self.packages }

    /// Upgrade a package (remove old, install new).
    pub fn upgrade(&mut self, manifest: PackageManifest, path: String) -> Result<(), String> {
        self.packages.retain(|p| p.manifest.name != manifest.name);
        self.packages.push(InstalledPackage {
            manifest, install_path: path,
            installed_at: chrono::Utc::now().to_rfc3339(),
        });
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_manifest(name: &str) -> PackageManifest {
        PackageManifest {
            name: name.into(), version: "1.0.0".into(), description: "test".into(),
            author: None, license: None, dependencies: vec![], capabilities_required: vec![], tools_required: vec![],
        }
    }

    #[test]
    fn install_and_list() {
        let mut reg = PackageRegistry::new();
        reg.install(test_manifest("pkg-a"), "/agents/pkg-a".into()).unwrap();
        assert_eq!(reg.list().len(), 1);
        assert!(reg.is_installed("pkg-a"));
    }

    #[test]
    fn duplicate_install_fails() {
        let mut reg = PackageRegistry::new();
        reg.install(test_manifest("pkg"), "/a".into()).unwrap();
        assert!(reg.install(test_manifest("pkg"), "/b".into()).is_err());
    }

    #[test]
    fn missing_dep_fails() {
        let mut reg = PackageRegistry::new();
        let mut manifest = test_manifest("child");
        manifest.dependencies = vec![PackageDep { name: "parent".into(), version: ">=1.0".into(), optional: false }];
        assert!(reg.install(manifest, "/a".into()).is_err());
    }

    #[test]
    fn remove_with_dependents_fails() {
        let mut reg = PackageRegistry::new();
        reg.install(test_manifest("base"), "/a".into()).unwrap();
        let mut child = test_manifest("child");
        child.dependencies = vec![PackageDep { name: "base".into(), version: ">=1.0".into(), optional: false }];
        reg.install(child, "/b".into()).unwrap();
        assert!(reg.remove("base").is_err()); // child depends on it
    }

    #[test]
    fn upgrade_replaces() {
        let mut reg = PackageRegistry::new();
        reg.install(test_manifest("pkg"), "/a".into()).unwrap();
        let mut v2 = test_manifest("pkg");
        v2.version = "2.0.0".into();
        reg.upgrade(v2, "/a".into()).unwrap();
        assert_eq!(reg.get("pkg").unwrap().manifest.version, "2.0.0");
    }
}
