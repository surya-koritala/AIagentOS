//! Autonomous multi-file code editing.
//!
//! Diff-based editing with atomic transactions and rollback support.

use std::collections::HashMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::resources::ResourceType;
use crate::tools::{ToolBinding, ToolRegistry};

// ─── Data Model ──────────────────────────────────────────────────────────────

/// A single file edit operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEdit {
    pub path: PathBuf,
    pub operation: EditOperation,
}

/// Types of edit operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EditOperation {
    /// Replace text in a file (search → replace).
    Replace { search: String, replace: String },
    /// Create a new file with content.
    Create { content: String },
    /// Append content to a file.
    Append { content: String },
    /// Insert content at a specific line number.
    InsertAt { line: usize, content: String },
    /// Delete a file.
    Delete,
    /// Rename/move a file.
    Rename { new_path: PathBuf },
}

/// A transaction of multiple file edits (atomic apply/rollback).
#[derive(Debug, Clone)]
pub struct EditTransaction {
    pub edits: Vec<FileEdit>,
    backups: HashMap<PathBuf, Option<String>>, // path → original content (None = didn't exist)
    applied: bool,
}

impl Default for EditTransaction {
    fn default() -> Self {
        Self::new()
    }
}

impl EditTransaction {
    pub fn new() -> Self {
        Self {
            edits: Vec::new(),
            backups: HashMap::new(),
            applied: false,
        }
    }

    /// Add an edit to the transaction.
    pub fn add(&mut self, edit: FileEdit) {
        self.edits.push(edit);
    }

    /// Apply all edits atomically. If any fails, rollback all.
    pub fn apply(&mut self) -> Result<Vec<String>, String> {
        let mut results = Vec::new();

        for (i, edit) in self.edits.iter().enumerate() {
            // Backup original state
            if !self.backups.contains_key(&edit.path) {
                let original = std::fs::read_to_string(&edit.path).ok();
                self.backups.insert(edit.path.clone(), original);
            }

            let path_display = edit.path.display().to_string();
            match self.apply_single(edit) {
                Ok(msg) => results.push(msg),
                Err(e) => {
                    self.rollback();
                    return Err(format!(
                        "Edit {} failed ({}), rolled back all changes: {}",
                        i + 1,
                        path_display,
                        e
                    ));
                }
            }
        }

        self.applied = true;
        Ok(results)
    }

    /// Rollback all applied edits to their original state.
    pub fn rollback(&mut self) {
        for (path, original) in &self.backups {
            match original {
                Some(content) => {
                    let _ = std::fs::write(path, content);
                }
                None => {
                    let _ = std::fs::remove_file(path);
                }
            }
        }
        self.applied = false;
    }

    fn apply_single(&self, edit: &FileEdit) -> Result<String, String> {
        match &edit.operation {
            EditOperation::Replace { search, replace } => {
                let content = std::fs::read_to_string(&edit.path)
                    .map_err(|e| format!("Can't read {}: {}", edit.path.display(), e))?;
                if !content.contains(search.as_str()) {
                    return Err(format!("Search text not found in {}", edit.path.display()));
                }
                let new_content = content.replacen(search.as_str(), replace.as_str(), 1);
                std::fs::write(&edit.path, &new_content)
                    .map_err(|e| format!("Can't write {}: {}", edit.path.display(), e))?;
                Ok(format!("Replaced in {}", edit.path.display()))
            }
            EditOperation::Create { content } => {
                if let Some(parent) = edit.path.parent() {
                    std::fs::create_dir_all(parent).ok();
                }
                std::fs::write(&edit.path, content)
                    .map_err(|e| format!("Can't create {}: {}", edit.path.display(), e))?;
                Ok(format!("Created {}", edit.path.display()))
            }
            EditOperation::Append { content } => {
                use std::io::Write;
                let mut file = std::fs::OpenOptions::new()
                    .append(true)
                    .create(true)
                    .open(&edit.path)
                    .map_err(|e| format!("Can't open {}: {}", edit.path.display(), e))?;
                file.write_all(content.as_bytes())
                    .map_err(|e| format!("Can't append to {}: {}", edit.path.display(), e))?;
                Ok(format!("Appended to {}", edit.path.display()))
            }
            EditOperation::InsertAt { line, content } => {
                let text = std::fs::read_to_string(&edit.path)
                    .map_err(|e| format!("Can't read {}: {}", edit.path.display(), e))?;
                let mut lines: Vec<&str> = text.lines().collect();
                let idx = (*line).min(lines.len());
                lines.insert(idx, content.as_str());
                std::fs::write(&edit.path, lines.join("\n"))
                    .map_err(|e| format!("Can't write {}: {}", edit.path.display(), e))?;
                Ok(format!(
                    "Inserted at line {} in {}",
                    line,
                    edit.path.display()
                ))
            }
            EditOperation::Delete => {
                std::fs::remove_file(&edit.path)
                    .map_err(|e| format!("Can't delete {}: {}", edit.path.display(), e))?;
                Ok(format!("Deleted {}", edit.path.display()))
            }
            EditOperation::Rename { new_path } => {
                if let Some(parent) = new_path.parent() {
                    std::fs::create_dir_all(parent).ok();
                }
                std::fs::rename(&edit.path, new_path).map_err(|e| {
                    format!(
                        "Can't rename {} → {}: {}",
                        edit.path.display(),
                        new_path.display(),
                        e
                    )
                })?;
                Ok(format!(
                    "Renamed {} → {}",
                    edit.path.display(),
                    new_path.display()
                ))
            }
        }
    }
}

// ─── Tool Registration ───────────────────────────────────────────────────────

/// Register file editing tools in the registry.
pub fn register_edit_tools(registry: &ToolRegistry) {
    registry.register(ToolBinding {
        name: "edit_file".into(),
        description: "Replace specific text in a file. Use this for precise edits.".into(),
        parameters_schema: serde_json::json!({
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "File path"},
                "search": {"type": "string", "description": "Exact text to find (must match exactly)"},
                "replace": {"type": "string", "description": "Text to replace it with"}
            },
            "required": ["path", "search", "replace"]
        }),
        resource_type: ResourceType::Filesystem,
        operation: "edit".into(),
    });

    registry.register(ToolBinding {
        name: "create_file".into(),
        description: "Create a new file with the given content.".into(),
        parameters_schema: serde_json::json!({
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "File path to create"},
                "content": {"type": "string", "description": "File content"}
            },
            "required": ["path", "content"]
        }),
        resource_type: ResourceType::Filesystem,
        operation: "create".into(),
    });

    registry.register(ToolBinding {
        name: "delete_file".into(),
        description: "Delete a file.".into(),
        parameters_schema: serde_json::json!({
            "type": "object",
            "properties": {"path": {"type": "string", "description": "File path to delete"}},
            "required": ["path"]
        }),
        resource_type: ResourceType::Filesystem,
        operation: "delete".into(),
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transaction_create_and_replace() {
        let dir = std::env::temp_dir().join(format!("edit_test_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("test.txt");
        std::fs::write(&file, "hello world").unwrap();

        let mut tx = EditTransaction::new();
        tx.add(FileEdit {
            path: file.clone(),
            operation: EditOperation::Replace {
                search: "world".into(),
                replace: "rust".into(),
            },
        });
        let results = tx.apply().unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(std::fs::read_to_string(&file).unwrap(), "hello rust");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn transaction_rollback_on_failure() {
        let dir = std::env::temp_dir().join(format!("edit_test_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let file1 = dir.join("a.txt");
        let file2 = dir.join("b.txt");
        std::fs::write(&file1, "original").unwrap();
        // file2 doesn't exist — edit will fail

        let mut tx = EditTransaction::new();
        tx.add(FileEdit {
            path: file1.clone(),
            operation: EditOperation::Replace {
                search: "original".into(),
                replace: "modified".into(),
            },
        });
        tx.add(FileEdit {
            path: file2.clone(),
            operation: EditOperation::Replace {
                search: "x".into(),
                replace: "y".into(),
            },
        });

        let result = tx.apply();
        assert!(result.is_err());
        // file1 should be rolled back to original
        assert_eq!(std::fs::read_to_string(&file1).unwrap(), "original");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn transaction_create_delete_rename() {
        let dir = std::env::temp_dir().join(format!("edit_test_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();

        let mut tx = EditTransaction::new();
        tx.add(FileEdit {
            path: dir.join("new.txt"),
            operation: EditOperation::Create {
                content: "new file".into(),
            },
        });
        tx.apply().unwrap();
        assert!(dir.join("new.txt").exists());

        let mut tx2 = EditTransaction::new();
        tx2.add(FileEdit {
            path: dir.join("new.txt"),
            operation: EditOperation::Rename {
                new_path: dir.join("renamed.txt"),
            },
        });
        tx2.apply().unwrap();
        assert!(!dir.join("new.txt").exists());
        assert!(dir.join("renamed.txt").exists());

        let mut tx3 = EditTransaction::new();
        tx3.add(FileEdit {
            path: dir.join("renamed.txt"),
            operation: EditOperation::Delete,
        });
        tx3.apply().unwrap();
        assert!(!dir.join("renamed.txt").exists());

        std::fs::remove_dir_all(&dir).ok();
    }
}
