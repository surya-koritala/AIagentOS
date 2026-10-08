//! Process-local mount tables for live agent mount namespaces.

use super::VfsError;
use crate::namespaces::NamespaceId;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashMap},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
};
use uuid::Uuid;

pub const MAX_MOUNTS_PER_NAMESPACE: usize = 32;
pub const MAX_MOUNT_NAMESPACES: usize = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MountKind {
    Tools,
    Workspace,
    Memory,
    Kv,
    Ipc,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MountInfo {
    pub id: String,
    pub path: String,
    pub kind: MountKind,
    pub generation: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NamespaceMountView {
    pub table_id: String,
    pub namespace: NamespaceId,
    pub generation: u64,
    pub mounts: Vec<MountInfo>,
    pub mount_limit: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct NamespaceKey {
    pub tenant: String,
    pub namespace: NamespaceId,
}

pub(crate) struct MountEntry {
    pub key: NamespaceKey,
    pub info: MountInfo,
    active: AtomicBool,
}

impl MountEntry {
    fn new(key: NamespaceKey, path: &str, kind: MountKind, generation: u64) -> Arc<Self> {
        Arc::new(Self {
            key,
            info: MountInfo {
                id: Uuid::new_v4().to_string(),
                path: path.into(),
                kind,
                generation,
            },
            active: AtomicBool::new(true),
        })
    }

    pub fn is_active(&self) -> bool {
        self.active.load(Ordering::SeqCst)
    }

    pub fn relative<'a>(&self, path: &'a str) -> Result<&'a str, VfsError> {
        if path == self.info.path {
            return Ok("");
        }
        path.strip_prefix(self.info.path.as_str())
            .and_then(|tail| tail.strip_prefix('/'))
            .ok_or(VfsError::InvalidPath)
    }

    pub fn workspace_path(&self, path: &str) -> String {
        let suffix = path
            .strip_prefix("/workspace")
            .expect("canonical workspace capability");
        format!("{}{suffix}", self.info.path)
    }
}

#[derive(Clone)]
pub(crate) struct MountBinding {
    pub entry: Arc<MountEntry>,
    pub namespace_revision: u64,
}

struct NamespaceTable {
    id: String,
    key: NamespaceKey,
    generation: u64,
    mounts: BTreeMap<String, Arc<MountEntry>>,
}

impl NamespaceTable {
    fn new(key: NamespaceKey) -> Self {
        let mut mounts = BTreeMap::new();
        for (path, kind, generation) in [
            ("/tools", MountKind::Tools, 1),
            ("/workspace", MountKind::Workspace, 2),
            ("/memory", MountKind::Memory, 3),
            ("/kv", MountKind::Kv, 4),
            ("/ipc", MountKind::Ipc, 5),
        ] {
            mounts.insert(
                path.into(),
                MountEntry::new(key.clone(), path, kind, generation),
            );
        }
        Self {
            id: Uuid::new_v4().to_string(),
            key,
            generation: 5,
            mounts,
        }
    }

    fn view(&self) -> NamespaceMountView {
        NamespaceMountView {
            table_id: self.id.clone(),
            namespace: self.key.namespace,
            generation: self.generation,
            mounts: self
                .mounts
                .values()
                .map(|entry| entry.info.clone())
                .collect(),
            mount_limit: MAX_MOUNTS_PER_NAMESPACE,
        }
    }

    fn next_generation(&self, expected_table_id: &str, expected: u64) -> Result<u64, VfsError> {
        if expected_table_id != self.id || expected != self.generation {
            return Err(VfsError::MountConflict);
        }
        self.generation.checked_add(1).ok_or(VfsError::Unavailable)
    }
}

#[derive(Default)]
pub(crate) struct MountRegistry {
    tables: Mutex<HashMap<NamespaceKey, NamespaceTable>>,
}

fn canonical_mount_path(path: &str) -> Result<(), VfsError> {
    let relative = path.strip_prefix('/').ok_or(VfsError::InvalidPath)?;
    super::workspace::canonical_relative(relative, false).map_err(|_| VfsError::InvalidPath)?;
    Ok(())
}

fn overlaps(a: &str, b: &str) -> bool {
    a == b
        || a.strip_prefix(b).is_some_and(|tail| tail.starts_with('/'))
        || b.strip_prefix(a).is_some_and(|tail| tail.starts_with('/'))
}

impl MountRegistry {
    fn with_table<T>(
        &self,
        key: &NamespaceKey,
        apply: impl FnOnce(&mut NamespaceTable) -> Result<T, VfsError>,
    ) -> Result<T, VfsError> {
        let mut tables = self.tables.lock().map_err(|_| VfsError::Unavailable)?;
        if !tables.contains_key(key) && tables.len() >= MAX_MOUNT_NAMESPACES {
            return Err(VfsError::Capacity);
        }
        apply(
            tables
                .entry(key.clone())
                .or_insert_with(|| NamespaceTable::new(key.clone())),
        )
    }

    pub fn view(&self, key: &NamespaceKey) -> Result<NamespaceMountView, VfsError> {
        self.with_table(key, |table| Ok(table.view()))
    }

    pub fn resolve(
        &self,
        key: &NamespaceKey,
        path: &str,
        kind: MountKind,
    ) -> Result<Arc<MountEntry>, VfsError> {
        canonical_mount_path(path)?;
        self.with_table(key, |table| {
            table
                .mounts
                .values()
                .find(|entry| {
                    entry.info.kind == kind && entry.relative(path).is_ok() && entry.is_active()
                })
                .cloned()
                .ok_or(VfsError::NotFound)
        })
    }

    pub fn mount(
        &self,
        key: &NamespaceKey,
        expected_table_id: &str,
        expected_generation: u64,
        path: &str,
        kind: MountKind,
    ) -> Result<NamespaceMountView, VfsError> {
        canonical_mount_path(path)?;
        self.with_table(key, |table| {
            let generation = table.next_generation(expected_table_id, expected_generation)?;
            if table.mounts.keys().any(|existing| overlaps(existing, path)) {
                return Err(VfsError::MountConflict);
            }
            if table.mounts.len() >= MAX_MOUNTS_PER_NAMESPACE {
                return Err(VfsError::Capacity);
            }
            table.mounts.insert(
                path.into(),
                MountEntry::new(key.clone(), path, kind, generation),
            );
            table.generation = generation;
            Ok(table.view())
        })
    }

    pub fn unmount(
        &self,
        key: &NamespaceKey,
        expected_table_id: &str,
        expected_generation: u64,
        path: &str,
        id: &str,
    ) -> Result<(NamespaceMountView, Arc<MountEntry>), VfsError> {
        canonical_mount_path(path)?;
        self.with_table(key, |table| {
            let generation = table.next_generation(expected_table_id, expected_generation)?;
            let entry = table
                .mounts
                .get(path)
                .filter(|entry| entry.info.id == id)
                .cloned()
                .ok_or(VfsError::NotFound)?;
            entry.active.store(false, Ordering::SeqCst);
            table.mounts.remove(path);
            table.generation = generation;
            Ok((table.view(), entry))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn key(namespace: u64) -> NamespaceKey {
        NamespaceKey {
            tenant: "test".into(),
            namespace,
        }
    }

    proptest! {
        #[test]
        fn component_collisions_are_symmetric(a in "[a-z]{1,16}", b in "[a-z]{1,16}") {
            let a = format!("/{a}");
            let b = format!("/{b}");
            let child = format!("{a}/child");
            let suffix = format!("{a}suffix");
            prop_assert_eq!(overlaps(&a, &b), overlaps(&b, &a));
            prop_assert!(overlaps(&a, &child));
            prop_assert!(!overlaps(&a, &suffix));
        }
    }

    #[test]
    fn generations_and_binding_identity_prevent_aba_and_stale_admin_writes() {
        let registry = MountRegistry::default();
        let key = key(1);
        let initial = registry.view(&key).unwrap();
        let old = registry
            .resolve(&key, "/tools/read_file", MountKind::Tools)
            .unwrap();
        let (removed, _) = registry
            .unmount(
                &key,
                &initial.table_id,
                initial.generation,
                "/tools",
                &old.info.id,
            )
            .unwrap();
        assert!(!old.is_active());
        assert!(registry
            .resolve(&key, "/tools/read_file", MountKind::Tools)
            .is_err());
        assert!(registry
            .mount(
                &key,
                &initial.table_id,
                initial.generation,
                "/tools",
                MountKind::Tools
            )
            .is_err());
        let recreated = registry
            .mount(
                &key,
                &removed.table_id,
                removed.generation,
                "/tools",
                MountKind::Tools,
            )
            .unwrap();
        let fresh = registry
            .resolve(&key, "/tools/read_file", MountKind::Tools)
            .unwrap();
        assert_ne!(old.info.id, fresh.info.id);
        assert!(fresh.info.generation > old.info.generation);
        assert!(registry
            .unmount(
                &key,
                &recreated.table_id,
                recreated.generation,
                "/tools",
                &old.info.id
            )
            .is_err());
        assert!(!old.is_active());
        assert!(fresh.is_active());
    }

    #[test]
    fn namespace_and_tenant_views_are_separate_and_capacity_is_bounded() {
        let registry = MountRegistry::default();
        let first = key(1);
        let mut second = first.clone();
        second.tenant = "other".into();
        let initial = registry.view(&first).unwrap();
        let mut view = initial;
        for i in 5..MAX_MOUNTS_PER_NAMESPACE {
            view = registry
                .mount(
                    &first,
                    &view.table_id,
                    view.generation,
                    &format!("/alias-{i}"),
                    MountKind::Tools,
                )
                .unwrap();
        }
        assert!(matches!(
            registry.mount(
                &first,
                &view.table_id,
                view.generation,
                "/overflow",
                MountKind::Tools
            ),
            Err(VfsError::Capacity)
        ));
        assert_eq!(registry.view(&second).unwrap().mounts.len(), 5);
        assert_eq!(registry.view(&key(2)).unwrap().mounts.len(), 5);
        for path in [
            "/tools",
            "/tools/child",
            "/",
            "/../root",
            "/a/",
            "/a//b",
            "/CON",
            "relative",
        ] {
            assert!(registry
                .mount(
                    &first,
                    &view.table_id,
                    view.generation,
                    path,
                    MountKind::Tools
                )
                .is_err());
        }
    }

    #[test]
    fn stale_table_identity_cannot_target_another_namespace_or_restarted_table() {
        let registry = MountRegistry::default();
        let original = registry.view(&key(1)).unwrap();
        let other = registry.view(&key(2)).unwrap();
        assert_eq!(original.generation, other.generation);
        assert!(matches!(
            registry.mount(
                &key(2),
                &original.table_id,
                original.generation,
                "/alias",
                MountKind::Tools
            ),
            Err(VfsError::MountConflict)
        ));
        assert_eq!(registry.view(&key(2)).unwrap(), other);
        let restarted = MountRegistry::default();
        let fresh = restarted.view(&key(1)).unwrap();
        assert_ne!(original.table_id, fresh.table_id);
        assert!(matches!(
            restarted.mount(
                &key(1),
                &original.table_id,
                original.generation,
                "/alias",
                MountKind::Tools
            ),
            Err(VfsError::MountConflict)
        ));
        assert_eq!(restarted.view(&key(1)).unwrap(), fresh);
    }

    #[test]
    fn namespace_capacity_is_finite_and_existing_tables_remain_accessible() {
        let registry = MountRegistry::default();
        for namespace in 0..MAX_MOUNT_NAMESPACES as u64 {
            registry.view(&key(namespace)).unwrap();
        }
        assert!(matches!(
            registry.view(&key(MAX_MOUNT_NAMESPACES as u64)),
            Err(VfsError::Capacity)
        ));
        assert_eq!(registry.view(&key(0)).unwrap().mounts.len(), 5);
    }
}
