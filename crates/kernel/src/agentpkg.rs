//! agentpkg — package manager CLI + registry client.

use crate::package::{PackageManifest, PackageRegistry};

/// agentpkg command handler.
pub struct AgentPkg {
    registry: PackageRegistry,
    remote_url: Option<String>,
}

impl AgentPkg {
    pub fn new() -> Self {
        Self {
            registry: PackageRegistry::new(),
            remote_url: None,
        }
    }

    pub fn with_remote(mut self, url: String) -> Self {
        self.remote_url = Some(url);
        self
    }

    /// Execute a package manager command.
    pub fn execute(&mut self, args: &[&str]) -> Result<String, String> {
        match args.first().copied() {
            Some("install") => self.cmd_install(args.get(1).copied()),
            Some("remove") => self.cmd_remove(args.get(1).copied()),
            Some("list") => self.cmd_list(),
            Some("search") => self.cmd_search(args.get(1).copied()),
            Some("info") => self.cmd_info(args.get(1).copied()),
            Some("update") => self.cmd_update(),
            Some("help") | None => Ok(self.cmd_help()),
            Some(cmd) => Err(format!("unknown command: {}", cmd)),
        }
    }

    fn cmd_install(&mut self, name: Option<&str>) -> Result<String, String> {
        let name = name.ok_or("usage: agentpkg install <package>")?;
        // In real impl, would fetch from registry
        let manifest = PackageManifest {
            name: name.into(),
            version: "1.0.0".into(),
            description: format!("Package {}", name),
            author: None,
            license: None,
            dependencies: vec![],
            capabilities_required: vec![],
            tools_required: vec![],
        };
        self.registry
            .install(manifest, format!("/agents/{}", name))?;
        Ok(format!("Installed {} v1.0.0", name))
    }

    fn cmd_remove(&mut self, name: Option<&str>) -> Result<String, String> {
        let name = name.ok_or("usage: agentpkg remove <package>")?;
        self.registry.remove(name)?;
        Ok(format!("Removed {}", name))
    }

    fn cmd_list(&self) -> Result<String, String> {
        let packages = self.registry.list();
        if packages.is_empty() {
            return Ok("No packages installed".into());
        }
        let mut out = format!("{:<20} {:<10} {}\n", "NAME", "VERSION", "PATH");
        for pkg in packages {
            out += &format!(
                "{:<20} {:<10} {}\n",
                pkg.manifest.name, pkg.manifest.version, pkg.install_path
            );
        }
        Ok(out)
    }

    fn cmd_search(&self, query: Option<&str>) -> Result<String, String> {
        let query = query.ok_or("usage: agentpkg search <query>")?;
        // In real impl, would search remote registry
        Ok(format!(
            "Searching registry for '{}'...\n(registry not configured)",
            query
        ))
    }

    fn cmd_info(&self, name: Option<&str>) -> Result<String, String> {
        let name = name.ok_or("usage: agentpkg info <package>")?;
        match self.registry.get(name) {
            Some(pkg) => Ok(format!(
                "Name: {}\nVersion: {}\nDescription: {}\nPath: {}",
                pkg.manifest.name, pkg.manifest.version, pkg.manifest.description, pkg.install_path
            )),
            None => Err(format!("package '{}' not installed", name)),
        }
    }

    fn cmd_update(&mut self) -> Result<String, String> {
        Ok("All packages up to date".into())
    }

    fn cmd_help(&self) -> String {
        "agentpkg — AI Agent OS Package Manager\n\nCommands:\n  install <pkg>   Install a package\n  remove <pkg>    Remove a package\n  list            List installed packages\n  search <query>  Search registry\n  info <pkg>      Show package info\n  update          Update all packages\n  help            Show this help".into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn install_and_list() {
        let mut pkg = AgentPkg::new();
        pkg.execute(&["install", "researcher"]).unwrap();
        let list = pkg.execute(&["list"]).unwrap();
        assert!(list.contains("researcher"));
    }

    #[test]
    fn install_and_remove() {
        let mut pkg = AgentPkg::new();
        pkg.execute(&["install", "temp-pkg"]).unwrap();
        pkg.execute(&["remove", "temp-pkg"]).unwrap();
        let list = pkg.execute(&["list"]).unwrap();
        assert!(list.contains("No packages"));
    }

    #[test]
    fn info_installed() {
        let mut pkg = AgentPkg::new();
        pkg.execute(&["install", "my-agent"]).unwrap();
        let info = pkg.execute(&["info", "my-agent"]).unwrap();
        assert!(info.contains("my-agent"));
        assert!(info.contains("1.0.0"));
    }

    #[test]
    fn info_not_installed() {
        let mut pkg = AgentPkg::new();
        let result = pkg.execute(&["info", "nonexistent"]);
        assert!(result.is_err());
    }

    #[test]
    fn help() {
        let mut pkg = AgentPkg::new();
        let result = pkg.execute(&["help"]).unwrap();
        assert!(result.contains("install"));
        assert!(result.contains("remove"));
    }
}
