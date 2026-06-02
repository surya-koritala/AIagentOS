//! Agent hub — publish, fetch, list, and share agent packages.
//!
//! In the apt-like mental model (`agentpkg`, `package`, `marketplace`) the hub
//! is the **package registry**: a versioned catalog of [`AgentManifest`]s keyed
//! by package name. Whereas [`crate::marketplace`] lists *plugins* (rated,
//! download-counted listings), the hub's unit is the loadable agent *package*
//! itself — the same manifest that [`crate::agent_package::load_package`] and
//! [`crate::agent_package::run_package`] consume. So `publish → fetch → load`
//! is a real path: a manifest published here can be fetched and dropped straight
//! onto a running [`AgentKernelImpl`].
//!
//! The catalog is pure data: [`AgentHub`] is serde-serializable, so a hub's
//! contents can be snapshotted, written to a file, shipped, and restored
//! elsewhere — sharing agent packages without any network. Timestamps are
//! supplied by the caller (the library never reads the system clock), keeping
//! publish deterministic and testable.
//!
//! [`AgentKernelImpl`]: crate::AgentKernelImpl

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::agent_package::AgentManifest;

/// A single published version of an agent package in the hub.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HubEntry {
    /// The loadable manifest. Its `name` is the package's catalog key.
    pub manifest: AgentManifest,
    /// Semantic-ish version string for this published artifact (e.g. `1.2.0`).
    /// Versions are hub metadata — `AgentManifest` itself carries no version.
    pub version: String,
    /// Caller-supplied publish timestamp (e.g. an RFC-3339 string). The hub
    /// never calls the clock; whoever publishes decides what this means.
    pub published_at: String,
}

impl HubEntry {
    /// The package name (the manifest's `name`), the hub's primary key.
    pub fn name(&self) -> &str {
        &self.manifest.name
    }
}

/// Errors from hub operations.
#[derive(Debug, thiserror::Error, PartialEq)]
pub enum HubError {
    /// A package with this exact name + version is already published.
    #[error("package `{name}` version `{version}` already published")]
    DuplicateVersion {
        /// Package name that collided.
        name: String,
        /// Version that collided.
        version: String,
    },
    /// The manifest failed its own validation before it could be published.
    #[error("invalid manifest: {0}")]
    InvalidManifest(String),
}

/// A versioned registry of agent packages.
///
/// Keyed by package name; each name maps to one or more published
/// [`HubEntry`] versions in publish order. Fetching by name returns the
/// **latest** (most recently published) version.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AgentHub {
    /// name -> versions, in publish order (last = latest).
    packages: HashMap<String, Vec<HubEntry>>,
}

impl AgentHub {
    /// Create an empty hub.
    pub fn new() -> Self {
        Self::default()
    }

    /// Publish a manifest under `version`, stamped with `published_at`.
    ///
    /// The manifest is validated first (an invalid manifest is rejected the
    /// same way [`crate::agent_package::load_package`] would reject it). A
    /// duplicate name + version pair is rejected with
    /// [`HubError::DuplicateVersion`]; publishing a *new* version of an existing
    /// name appends to that package's version list.
    pub fn publish(
        &mut self,
        manifest: AgentManifest,
        version: impl Into<String>,
        published_at: impl Into<String>,
    ) -> Result<(), HubError> {
        manifest
            .validate()
            .map_err(|e| HubError::InvalidManifest(e.to_string()))?;

        let version = version.into();
        let name = manifest.name.clone();
        let entries = self.packages.entry(name.clone()).or_default();

        if entries.iter().any(|e| e.version == version) {
            return Err(HubError::DuplicateVersion { name, version });
        }

        entries.push(HubEntry {
            manifest,
            version,
            published_at: published_at.into(),
        });
        Ok(())
    }

    /// Fetch the latest published manifest for `name`, if any.
    pub fn fetch(&self, name: &str) -> Option<&AgentManifest> {
        self.latest(name).map(|e| &e.manifest)
    }

    /// Fetch a specific published manifest by `name` and exact `version`.
    pub fn fetch_version(&self, name: &str, version: &str) -> Option<&AgentManifest> {
        self.packages
            .get(name)
            .and_then(|entries| entries.iter().find(|e| e.version == version))
            .map(|e| &e.manifest)
    }

    /// The latest [`HubEntry`] for `name` (most recently published), if any.
    pub fn latest(&self, name: &str) -> Option<&HubEntry> {
        self.packages.get(name).and_then(|entries| entries.last())
    }

    /// All package versions known for `name`, in publish order.
    pub fn versions(&self, name: &str) -> Vec<&str> {
        match self.packages.get(name) {
            Some(entries) => entries.iter().map(|e| e.version.as_str()).collect(),
            None => Vec::new(),
        }
    }

    /// List the latest entry of every published package.
    pub fn list(&self) -> Vec<&HubEntry> {
        self.packages
            .values()
            .filter_map(|entries| entries.last())
            .collect()
    }

    /// Search the latest entry of each package by case-insensitive substring
    /// over the package name and description.
    pub fn search(&self, query: &str) -> Vec<&HubEntry> {
        let q = query.to_lowercase();
        self.packages
            .values()
            .filter_map(|entries| entries.last())
            .filter(|e| {
                e.manifest.name.to_lowercase().contains(&q)
                    || e.manifest.description.to_lowercase().contains(&q)
            })
            .collect()
    }

    /// Number of distinct packages (names) in the hub.
    pub fn count(&self) -> usize {
        self.packages.len()
    }

    /// Total number of published artifacts across all versions.
    pub fn total_versions(&self) -> usize {
        self.packages.values().map(Vec::len).sum()
    }

    /// Remove a package and all its versions. Returns `true` if it existed.
    pub fn remove(&mut self, name: &str) -> bool {
        self.packages.remove(name).is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::AgentKernel;
    use crate::agent_package::load_package;
    use crate::context::ContextManager;
    use crate::AgentKernelImpl;

    fn manifest(name: &str, description: &str) -> AgentManifest {
        AgentManifest {
            name: name.to_string(),
            description: description.to_string(),
            task: "do work".to_string(),
            entry: None,
            provider: "stub".to_string(),
            profile: "standard".to_string(),
            priority: 3,
            nice: None,
            tools: Vec::new(),
            memory: Vec::new(),
        }
    }

    #[test]
    fn publish_fetch_and_count() {
        let mut hub = AgentHub::new();
        assert_eq!(hub.count(), 0);
        hub.publish(manifest("researcher", "reads things"), "1.0.0", "t0")
            .unwrap();
        assert_eq!(hub.count(), 1);
        let m = hub.fetch("researcher").unwrap();
        assert_eq!(m.name, "researcher");
        assert!(hub.fetch("missing").is_none());
    }

    #[test]
    fn rejects_duplicate_name_and_version() {
        let mut hub = AgentHub::new();
        hub.publish(manifest("a", "x"), "1.0.0", "t0").unwrap();
        let err = hub.publish(manifest("a", "x"), "1.0.0", "t1").unwrap_err();
        assert_eq!(
            err,
            HubError::DuplicateVersion {
                name: "a".to_string(),
                version: "1.0.0".to_string(),
            }
        );
        // Still only the original artifact.
        assert_eq!(hub.total_versions(), 1);
    }

    #[test]
    fn rejects_invalid_manifest() {
        let mut hub = AgentHub::new();
        let mut bad = manifest("a", "x");
        bad.task = "  ".to_string();
        assert!(matches!(
            hub.publish(bad, "1.0.0", "t0"),
            Err(HubError::InvalidManifest(_))
        ));
        assert_eq!(hub.count(), 0);
    }

    #[test]
    fn fetch_returns_latest_version() {
        let mut hub = AgentHub::new();
        hub.publish(manifest("a", "v1 desc"), "1.0.0", "t0")
            .unwrap();
        hub.publish(manifest("a", "v2 desc"), "2.0.0", "t1")
            .unwrap();

        // count is per-name; versions accumulate.
        assert_eq!(hub.count(), 1);
        assert_eq!(hub.total_versions(), 2);
        assert_eq!(hub.versions("a"), vec!["1.0.0", "2.0.0"]);

        // fetch -> latest
        assert_eq!(hub.fetch("a").unwrap().description, "v2 desc");
        // explicit version fetch
        assert_eq!(
            hub.fetch_version("a", "1.0.0").unwrap().description,
            "v1 desc"
        );
        assert!(hub.fetch_version("a", "9.9.9").is_none());
        assert_eq!(hub.latest("a").unwrap().version, "2.0.0");
    }

    #[test]
    fn list_and_search() {
        let mut hub = AgentHub::new();
        hub.publish(
            manifest("code-reviewer", "Reviews code for bugs"),
            "1.0.0",
            "t0",
        )
        .unwrap();
        hub.publish(manifest("web-scraper", "Scrapes websites"), "1.0.0", "t0")
            .unwrap();

        assert_eq!(hub.list().len(), 2);

        // substring over name
        let by_name = hub.search("review");
        assert_eq!(by_name.len(), 1);
        assert_eq!(by_name[0].name(), "code-reviewer");

        // substring over description, case-insensitive
        let by_desc = hub.search("SCRAPE");
        assert_eq!(by_desc.len(), 1);
        assert_eq!(by_desc[0].name(), "web-scraper");

        assert!(hub.search("nonexistent").is_empty());
    }

    #[test]
    fn remove_package() {
        let mut hub = AgentHub::new();
        hub.publish(manifest("a", "x"), "1.0.0", "t0").unwrap();
        hub.publish(manifest("a", "x"), "2.0.0", "t1").unwrap();
        assert!(hub.remove("a"));
        assert_eq!(hub.count(), 0);
        assert!(hub.fetch("a").is_none());
        assert!(!hub.remove("a"));
    }

    #[test]
    fn serde_round_trip_preserves_catalog() {
        let mut hub = AgentHub::new();
        hub.publish(manifest("a", "alpha"), "1.0.0", "t0").unwrap();
        hub.publish(manifest("a", "alpha v2"), "2.0.0", "t1")
            .unwrap();
        hub.publish(manifest("b", "beta"), "1.0.0", "t0").unwrap();

        let json = serde_json::to_string(&hub).unwrap();
        let restored: AgentHub = serde_json::from_str(&json).unwrap();

        assert_eq!(restored.count(), 2);
        assert_eq!(restored.total_versions(), 3);
        assert_eq!(restored.versions("a"), vec!["1.0.0", "2.0.0"]);
        assert_eq!(restored.fetch("a").unwrap().description, "alpha v2");
        assert_eq!(restored.fetch("b").unwrap().description, "beta");
    }

    /// The load-bearing tie-in: a fetched package is the same manifest the
    /// kernel loader consumes. Publish -> fetch -> `load_package` onto a real
    /// in-memory kernel, and assert the agent was actually created.
    #[tokio::test]
    async fn publish_fetch_then_load_onto_kernel() {
        let mut hub = AgentHub::new();
        let mut m = manifest("packaged-agent", "loaded from the hub");
        m.memory = vec!["seeded from a hub package".to_string()];
        hub.publish(m, "1.0.0", "t0").unwrap();

        let fetched = hub.fetch("packaged-agent").expect("package present");

        let kernel = AgentKernelImpl::new().unwrap();
        let handle = load_package(&kernel, fetched).await.unwrap();

        let agents = kernel.agent_manager.list_agents(None);
        assert!(
            agents
                .iter()
                .any(|a| a.id == handle.id && a.name == "packaged-agent"),
            "fetched hub package must create a live agent"
        );

        // Seed memory carried through the package round-trip.
        let facts = kernel
            .context_manager
            .query_memory(handle.id, "hub package")
            .await
            .unwrap();
        assert!(facts.iter().any(|f| f.content.contains("hub package")));
    }
}
