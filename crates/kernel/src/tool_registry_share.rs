//! Shareable tool registry — publish/fetch reusable tool definitions by name.
//!
//! In the Linux mental model tools are files (VFS); a *shared* tool registry is
//! the package repository those files can be published to and pulled from. The
//! platform is Rust-only with no dynamic code loading, so the shareable artifact
//! is **data**: a [`SharedToolDef`] (name + description + JSON-Schema parameters)
//! that is `serde`-serializable, so a tool definition can be authored once,
//! stored, transported as plain JSON/TOML, and referenced by name from many
//! agent packages.
//!
//! The registry is load-bearing rather than an island: a published definition
//! converts directly into the kernel's own [`ToolBinding`] (via
//! [`SharedToolDef::to_binding`]) and can be installed into a live
//! [`ToolRegistry`] with [`SharedToolRegistry::install_into`]. Agent packages
//! resolve their declared `tools` against the registry with
//! [`SharedToolRegistry::resolve_names`], so a packaged agent can reference a
//! shared tool purely by name.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::resources::ResourceType;
use crate::tools::{ToolBinding, ToolRegistry};

/// A shareable, self-describing tool definition.
///
/// This is *data*: it serializes cleanly so a definition can be published, saved
/// to disk, or shipped alongside an agent package and re-registered elsewhere.
/// `parameters` is a JSON-Schema object describing the tool's arguments (the same
/// shape the kernel's [`ToolBinding::parameters_schema`] expects).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SharedToolDef {
    /// Unique tool name (the key it is published/fetched under).
    pub name: String,
    /// Human-readable description of what the tool does.
    #[serde(default)]
    pub description: String,
    /// JSON-Schema for the tool's parameters (an `{"type":"object", ...}` schema).
    #[serde(default = "empty_object_schema")]
    pub parameters: serde_json::Value,
    /// Monotonically increasing revision; bumped on each overwrite via
    /// [`SharedToolRegistry::publish_overwrite`]. Starts at 1.
    #[serde(default = "default_version")]
    pub version: u32,
}

fn empty_object_schema() -> serde_json::Value {
    serde_json::json!({ "type": "object", "properties": {} })
}

fn default_version() -> u32 {
    1
}

impl SharedToolDef {
    /// Build a definition with an empty-object parameter schema and version 1.
    pub fn new(name: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            parameters: empty_object_schema(),
            version: 1,
        }
    }

    /// Set the JSON-Schema parameter definition (builder style).
    pub fn with_parameters(mut self, parameters: serde_json::Value) -> Self {
        self.parameters = parameters;
        self
    }

    /// Convert this shared definition into a kernel-usable [`ToolBinding`].
    ///
    /// Shared tools are pure declarations, so they bind to the generic
    /// `Application`/`invoke` resource operation — the same surface custom tools
    /// use. The syscall gate still governs whether a given agent may call it.
    pub fn to_binding(&self) -> ToolBinding {
        ToolBinding {
            name: self.name.clone(),
            description: self.description.clone(),
            parameters_schema: self.parameters.clone(),
            resource_type: ResourceType::Application,
            operation: "invoke".to_string(),
        }
    }
}

/// Errors from publishing to or fetching from the shared registry.
#[derive(Debug, thiserror::Error, PartialEq)]
pub enum ShareError {
    /// A definition with this name already exists (use `publish_overwrite`).
    #[error("tool `{0}` already published")]
    DuplicateName(String),
    /// The definition failed validation (e.g. empty name).
    #[error("invalid tool definition: {0}")]
    Invalid(String),
    /// One or more declared tool names were not found in the registry.
    #[error("unknown shared tool(s): {0}")]
    Unresolved(String),
}

/// An in-memory registry of shareable tool definitions, keyed by tool name.
///
/// Publishing rejects duplicate names by default; use
/// [`Self::publish_overwrite`] to replace and bump the version explicitly.
#[derive(Debug, Default, Clone)]
pub struct SharedToolRegistry {
    defs: HashMap<String, SharedToolDef>,
}

impl SharedToolRegistry {
    /// Create an empty shared registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Publish a new definition. Rejects a duplicate name with
    /// [`ShareError::DuplicateName`].
    pub fn publish(&mut self, mut def: SharedToolDef) -> Result<(), ShareError> {
        if def.name.trim().is_empty() {
            return Err(ShareError::Invalid("`name` must not be empty".into()));
        }
        if self.defs.contains_key(&def.name) {
            return Err(ShareError::DuplicateName(def.name));
        }
        if def.version == 0 {
            def.version = 1;
        }
        self.defs.insert(def.name.clone(), def);
        Ok(())
    }

    /// Publish a definition, overwriting any existing one of the same name and
    /// bumping the stored `version` to `previous + 1`. Returns the new version.
    pub fn publish_overwrite(&mut self, mut def: SharedToolDef) -> Result<u32, ShareError> {
        if def.name.trim().is_empty() {
            return Err(ShareError::Invalid("`name` must not be empty".into()));
        }
        let next = match self.defs.get(&def.name) {
            Some(existing) => existing.version + 1,
            None => def.version.max(1),
        };
        def.version = next;
        self.defs.insert(def.name.clone(), def);
        Ok(next)
    }

    /// Fetch a published definition by name.
    pub fn fetch(&self, name: &str) -> Option<&SharedToolDef> {
        self.defs.get(name)
    }

    /// List all published definitions (order unspecified).
    pub fn list(&self) -> Vec<&SharedToolDef> {
        self.defs.values().collect()
    }

    /// Number of published definitions.
    pub fn count(&self) -> usize {
        self.defs.len()
    }

    /// Whether a definition with this name is published.
    pub fn contains(&self, name: &str) -> bool {
        self.defs.contains_key(name)
    }

    /// Remove a published definition, returning it if present.
    pub fn remove(&mut self, name: &str) -> Option<SharedToolDef> {
        self.defs.remove(name)
    }

    /// Resolve a set of declared tool names against the registry, returning the
    /// matching definitions in the requested order. Any name not published
    /// yields [`ShareError::Unresolved`] listing the missing names.
    ///
    /// This is the package-resolution path: an agent package's declared `tools`
    /// can be checked/expanded against the shared registry.
    pub fn resolve_names(&self, names: &[String]) -> Result<Vec<SharedToolDef>, ShareError> {
        let mut resolved = Vec::with_capacity(names.len());
        let mut missing = Vec::new();
        for name in names {
            match self.defs.get(name) {
                Some(def) => resolved.push(def.clone()),
                None => missing.push(name.clone()),
            }
        }
        if !missing.is_empty() {
            return Err(ShareError::Unresolved(missing.join(", ")));
        }
        Ok(resolved)
    }

    /// Install a single published definition into a live [`ToolRegistry`] as a
    /// real [`ToolBinding`]. Returns `false` if the name is not published.
    pub fn install_into(&self, name: &str, registry: &ToolRegistry) -> bool {
        match self.defs.get(name) {
            Some(def) => {
                registry.register(def.to_binding());
                true
            }
            None => false,
        }
    }

    /// Install every published definition into a live [`ToolRegistry`].
    /// Returns the number of tools installed.
    pub fn install_all_into(&self, registry: &ToolRegistry) -> usize {
        for def in self.defs.values() {
            registry.register(def.to_binding());
        }
        self.defs.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(name: &str) -> SharedToolDef {
        SharedToolDef::new(name, "does a thing").with_parameters(serde_json::json!({
            "type": "object",
            "properties": { "q": { "type": "string" } },
            "required": ["q"],
        }))
    }

    #[test]
    fn publish_fetch_list_count() {
        let mut reg = SharedToolRegistry::new();
        assert_eq!(reg.count(), 0);
        reg.publish(sample("web_search")).unwrap();
        reg.publish(sample("calc")).unwrap();
        assert_eq!(reg.count(), 2);
        assert!(reg.contains("web_search"));
        let fetched = reg.fetch("web_search").unwrap();
        assert_eq!(fetched.name, "web_search");
        assert_eq!(fetched.version, 1);
        assert_eq!(reg.list().len(), 2);
        assert!(reg.fetch("missing").is_none());
    }

    #[test]
    fn rejects_duplicate_and_empty_names() {
        let mut reg = SharedToolRegistry::new();
        reg.publish(sample("dup")).unwrap();
        assert_eq!(
            reg.publish(sample("dup")),
            Err(ShareError::DuplicateName("dup".into()))
        );
        assert!(matches!(
            reg.publish(SharedToolDef::new("", "x")),
            Err(ShareError::Invalid(_))
        ));
    }

    #[test]
    fn overwrite_bumps_version() {
        let mut reg = SharedToolRegistry::new();
        reg.publish(sample("t")).unwrap();
        assert_eq!(reg.fetch("t").unwrap().version, 1);
        let v = reg.publish_overwrite(sample("t")).unwrap();
        assert_eq!(v, 2);
        assert_eq!(reg.fetch("t").unwrap().version, 2);
        // Overwriting a brand-new name keeps version >= 1.
        let v = reg.publish_overwrite(sample("fresh")).unwrap();
        assert_eq!(v, 1);
    }

    #[test]
    fn remove_returns_def() {
        let mut reg = SharedToolRegistry::new();
        reg.publish(sample("gone")).unwrap();
        let removed = reg.remove("gone").unwrap();
        assert_eq!(removed.name, "gone");
        assert_eq!(reg.count(), 0);
        assert!(reg.remove("gone").is_none());
    }

    #[test]
    fn def_serializes_round_trip() {
        let def = sample("ser");
        let json = serde_json::to_string(&def).unwrap();
        let back: SharedToolDef = serde_json::from_str(&json).unwrap();
        assert_eq!(def, back);
    }

    #[test]
    fn published_def_converts_to_usable_tool_binding() {
        // Load-bearing path: a published definition becomes a tool the kernel's
        // ToolRegistry actually recognizes and exposes to the LLM.
        let mut share = SharedToolRegistry::new();
        share.publish(sample("shared_search")).unwrap();

        let registry = ToolRegistry::new();
        assert!(!registry.has_tool("shared_search"));

        assert!(share.install_into("shared_search", &registry));
        assert!(registry.has_tool("shared_search"));

        // It appears in the LLM-facing definitions with its schema preserved.
        let defs = registry.definitions();
        let def = defs.iter().find(|d| d.name == "shared_search").unwrap();
        assert_eq!(def.description, "does a thing");
        assert_eq!(def.parameters["required"][0], "q");

        // Installing an unknown name is a no-op that reports failure.
        assert!(!share.install_into("nope", &registry));
    }

    #[test]
    fn install_all_into_registers_everything() {
        let mut share = SharedToolRegistry::new();
        share.publish(sample("a")).unwrap();
        share.publish(sample("b")).unwrap();
        let registry = ToolRegistry::new();
        assert_eq!(share.install_all_into(&registry), 2);
        assert!(registry.has_tool("a"));
        assert!(registry.has_tool("b"));
    }

    #[test]
    fn resolve_names_matches_package_declared_tools() {
        // Package-resolution path: an agent package's declared `tools` resolve
        // against the shared registry by name.
        let mut share = SharedToolRegistry::new();
        share.publish(sample("read_file")).unwrap();
        share.publish(sample("http_get")).unwrap();

        let declared = vec!["http_get".to_string(), "read_file".to_string()];
        let resolved = share.resolve_names(&declared).unwrap();
        assert_eq!(resolved.len(), 2);
        // Order follows the declaration order.
        assert_eq!(resolved[0].name, "http_get");
        assert_eq!(resolved[1].name, "read_file");

        // A declared tool that isn't published is reported as unresolved.
        let bad = vec!["read_file".to_string(), "ghost".to_string()];
        assert_eq!(
            share.resolve_names(&bad),
            Err(ShareError::Unresolved("ghost".into()))
        );
    }
}
