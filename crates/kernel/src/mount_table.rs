//! Tool Mount System — mount tool providers at paths.
//!
//! Like Linux VFS mount. Tools are mounted at paths, agents access
//! them through the path hierarchy.

use std::collections::HashMap;

use crate::agent_struct::AgentId;

/// A mount entry.
#[derive(Debug, Clone)]
pub struct MountEntry {
    pub source: String,      // e.g., "mcp://github" or "builtin://filesystem"
    pub target: String,      // e.g., "/tools/github"
    pub fs_type: String,     // e.g., "mcp", "builtin", "wasm"
    pub flags: MountFlags,
    pub mounted_by: AgentId,
}

/// Mount flags.
#[derive(Debug, Clone, Copy, Default)]
pub struct MountFlags {
    pub read_only: bool,
    pub no_exec: bool,
    pub private: bool, // only visible to mounting agent's namespace
}

/// The mount table.
pub struct MountTable {
    mounts: Vec<MountEntry>,
}

impl MountTable {
    pub fn new() -> Self { Self { mounts: Vec::new() } }

    /// Mount a tool provider at a path.
    pub fn mount(&mut self, source: String, target: String, fs_type: String, flags: MountFlags, agent_id: AgentId) -> Result<(), &'static str> {
        // Check target not already mounted
        if self.mounts.iter().any(|m| m.target == target) {
            return Err("mount point busy (EBUSY)");
        }
        self.mounts.push(MountEntry { source, target, fs_type, flags, mounted_by: agent_id });
        Ok(())
    }

    /// Unmount a path.
    pub fn unmount(&mut self, target: &str) -> Result<(), &'static str> {
        let idx = self.mounts.iter().position(|m| m.target == target).ok_or("not mounted (EINVAL)")?;
        self.mounts.remove(idx);
        Ok(())
    }

    /// Resolve a tool path to its mount entry.
    pub fn resolve(&self, path: &str) -> Option<(&MountEntry, String)> {
        let mut best: Option<(&MountEntry, String)> = None;
        for mount in &self.mounts {
            if path.starts_with(&mount.target) {
                let remainder = &path[mount.target.len()..];
                let remainder = remainder.strip_prefix('/').unwrap_or(remainder).to_string();
                if best.is_none() || mount.target.len() > best.as_ref().unwrap().0.target.len() {
                    best = Some((mount, remainder));
                }
            }
        }
        best
    }

    /// List all mounts.
    pub fn list(&self) -> &[MountEntry] { &self.mounts }

    /// Count mounts.
    pub fn count(&self) -> usize { self.mounts.len() }

    /// Check if a path is mounted read-only.
    pub fn is_readonly(&self, path: &str) -> bool {
        self.resolve(path).map(|(m, _)| m.flags.read_only).unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mount_and_resolve() {
        let mut table = MountTable::new();
        table.mount("builtin://fs".into(), "/tools/fs".into(), "builtin".into(), MountFlags::default(), 1).unwrap();
        let (entry, remainder) = table.resolve("/tools/fs/read").unwrap();
        assert_eq!(entry.source, "builtin://fs");
        assert_eq!(remainder, "read");
    }

    #[test]
    fn longest_match() {
        let mut table = MountTable::new();
        table.mount("a".into(), "/tools".into(), "x".into(), MountFlags::default(), 1).unwrap();
        table.mount("b".into(), "/tools/github".into(), "mcp".into(), MountFlags::default(), 1).unwrap();
        let (entry, _) = table.resolve("/tools/github/issues").unwrap();
        assert_eq!(entry.source, "b");
    }

    #[test]
    fn unmount() {
        let mut table = MountTable::new();
        table.mount("x".into(), "/mnt".into(), "t".into(), MountFlags::default(), 1).unwrap();
        table.unmount("/mnt").unwrap();
        assert_eq!(table.count(), 0);
    }

    #[test]
    fn duplicate_mount_fails() {
        let mut table = MountTable::new();
        table.mount("a".into(), "/mnt".into(), "t".into(), MountFlags::default(), 1).unwrap();
        let result = table.mount("b".into(), "/mnt".into(), "t".into(), MountFlags::default(), 1);
        assert!(result.is_err());
    }

    #[test]
    fn readonly_check() {
        let mut table = MountTable::new();
        table.mount("x".into(), "/ro".into(), "t".into(), MountFlags { read_only: true, ..Default::default() }, 1).unwrap();
        assert!(table.is_readonly("/ro/file"));
    }
}
