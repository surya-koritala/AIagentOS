//! `agentpkg` command adapter for the durable signed package registry.
//!
//! It never fabricates manifests. Installation succeeds only for a signed,
//! trusted artifact that has already been published to the selected tenant.

use semver::VersionReq;

use crate::context::DEFAULT_TENANT;
use crate::package::{InstallPolicy, PackageRegistry};

pub struct AgentPkg {
    registry: PackageRegistry,
    tenant_id: String,
    actor: String,
    install_policy: InstallPolicy,
}

impl Default for AgentPkg {
    fn default() -> Self {
        Self::new()
    }
}

impl AgentPkg {
    pub fn new() -> Self {
        Self {
            registry: PackageRegistry::new(),
            tenant_id: DEFAULT_TENANT.into(),
            actor: "local-operator".into(),
            install_policy: InstallPolicy::system_default(),
        }
    }

    pub fn with_registry(
        registry: PackageRegistry,
        tenant_id: impl Into<String>,
        actor: impl Into<String>,
        install_policy: InstallPolicy,
    ) -> Self {
        Self {
            registry,
            tenant_id: tenant_id.into(),
            actor: actor.into(),
            install_policy,
        }
    }

    /// Execute a package-manager command.
    pub fn execute(&self, args: &[&str]) -> Result<String, String> {
        match args.first().copied() {
            Some("install") => self.cmd_install(args.get(1).copied(), args.get(2).copied()),
            Some("remove") => self.cmd_remove(args.get(1).copied()),
            Some("list") => self.cmd_list(),
            Some("search") => self.cmd_search(args.get(1).copied()),
            Some("info") => self.cmd_info(args.get(1).copied()),
            Some("rollback") => self.cmd_rollback(args.get(1).copied()),
            Some("help") | None => Ok(self.cmd_help()),
            Some(command) => Err(format!("unknown command: {command}")),
        }
    }

    fn cmd_install(&self, name: Option<&str>, requirement: Option<&str>) -> Result<String, String> {
        let name = name.ok_or("usage: agentpkg install <package> [requirement]")?;
        let requirement =
            VersionReq::parse(requirement.unwrap_or("*")).map_err(|error| error.to_string())?;
        let installed = self
            .registry
            .install(
                &self.tenant_id,
                &self.actor,
                name,
                &requirement,
                &self.install_policy,
            )
            .map_err(|error| error.to_string())?;
        Ok(format!(
            "Installed {} v{} ({})",
            installed.name, installed.version, installed.digest
        ))
    }

    fn cmd_remove(&self, name: Option<&str>) -> Result<String, String> {
        let name = name.ok_or("usage: agentpkg remove <package>")?;
        self.registry
            .remove(&self.tenant_id, &self.actor, name)
            .map_err(|error| error.to_string())?;
        Ok(format!("Removed {name}"))
    }

    fn cmd_list(&self) -> Result<String, String> {
        let packages = self
            .registry
            .list_installed(&self.tenant_id)
            .map_err(|error| error.to_string())?;
        if packages.is_empty() {
            return Ok("No packages installed".into());
        }
        let mut output = format!("{:<24} {:<14} {}\n", "NAME", "VERSION", "DIGEST");
        for package in packages {
            output.push_str(&format!(
                "{:<24} {:<14} {}\n",
                package.name, package.version, package.digest
            ));
        }
        Ok(output)
    }

    fn cmd_search(&self, query: Option<&str>) -> Result<String, String> {
        let query = query.ok_or("usage: agentpkg search <query>")?;
        let packages = self
            .registry
            .search(&self.tenant_id, &self.actor, query)
            .map_err(|error| error.to_string())?;
        if packages.is_empty() {
            return Ok("No matching signed packages".into());
        }
        let mut output = String::new();
        for package in packages {
            output.push_str(&format!(
                "{} {} {}{}\n",
                package.name,
                package.version,
                package.publisher,
                if package.yanked { " [yanked]" } else { "" }
            ));
        }
        Ok(output)
    }

    fn cmd_info(&self, name: Option<&str>) -> Result<String, String> {
        let name = name.ok_or("usage: agentpkg info <package>")?;
        let package = self
            .registry
            .list_installed(&self.tenant_id)
            .map_err(|error| error.to_string())?
            .into_iter()
            .find(|package| package.name == name)
            .ok_or_else(|| format!("package '{name}' not installed"))?;
        Ok(format!(
            "Name: {}\nVersion: {}\nPublisher: {}\nDigest: {}\nInstalled: {}",
            package.name,
            package.version,
            package.manifest.publisher,
            package.digest,
            package.installed_at
        ))
    }

    fn cmd_rollback(&self, name: Option<&str>) -> Result<String, String> {
        let name = name.ok_or("usage: agentpkg rollback <package>")?;
        let restored = self
            .registry
            .rollback(&self.tenant_id, &self.actor, name)
            .map_err(|error| error.to_string())?;
        Ok(format!("Rolled back {name} to v{}", restored.version))
    }

    fn cmd_help(&self) -> String {
        "agentpkg — signed AI Agent OS package manager\n\nCommands:\n  install <pkg> [req]  Install/upgrade a trusted package\n  rollback <pkg>       Restore the previous installed version\n  remove <pkg>         Remove a package when no dependents need it\n  list                 List installed packages and digests\n  search <query>       Search the tenant registry\n  info <pkg>           Show installed package information\n  help                 Show this help"
            .into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_registry_is_honest() {
        let package_manager = AgentPkg::new();
        assert_eq!(
            package_manager.execute(&["list"]).unwrap(),
            "No packages installed"
        );
        assert!(package_manager
            .execute(&["install", "not-published"])
            .unwrap_err()
            .contains("dependency"));
        assert_eq!(
            package_manager.execute(&["search", "missing"]).unwrap(),
            "No matching signed packages"
        );
    }

    #[test]
    fn help_describes_transactional_commands() {
        let package_manager = AgentPkg::new();
        let help = package_manager.execute(&["help"]).unwrap();
        assert!(help.contains("install"));
        assert!(help.contains("rollback"));
        assert!(help.contains("remove"));
    }
}
