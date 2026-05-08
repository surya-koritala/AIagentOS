//! Tool Descriptors — the file descriptor equivalent for AI agents.
//!
//! Each agent has a table of open tool descriptors. Tools are opened,
//! used, and closed through this interface.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};

use crate::agent_struct::AgentId;

/// Tool descriptor (like a file descriptor number).
pub type ToolDescriptor = u32;

/// Flags for tool_open().
pub mod open_flags {
    pub const O_RDONLY: u32 = 0b001;
    pub const O_WRONLY: u32 = 0b010;
    pub const O_RDWR: u32 = 0b011;
    pub const O_EXEC: u32 = 0b100;
}

/// A tool descriptor entry in the per-agent table.
#[derive(Debug, Clone)]
pub struct ToolDescEntry {
    pub td: ToolDescriptor,
    pub tool_path: String,
    pub flags: u32,
    pub position: u64,
    pub ref_count: u32,
}

/// Per-agent tool descriptor table (like fd table).
pub struct ToolDescTable {
    entries: HashMap<ToolDescriptor, ToolDescEntry>,
    next_td: AtomicU32,
    max_open: u32,
}

impl ToolDescTable {
    pub fn new(max_open: u32) -> Self {
        Self {
            entries: HashMap::new(),
            next_td: AtomicU32::new(0),
            max_open,
        }
    }

    /// Open a tool, get a descriptor.
    pub fn open(&mut self, path: String, flags: u32) -> Result<ToolDescriptor, &'static str> {
        if self.entries.len() as u32 >= self.max_open {
            return Err("too many open tools (EMFILE)");
        }
        let td = self.next_td.fetch_add(1, Ordering::SeqCst);
        self.entries.insert(
            td,
            ToolDescEntry {
                td,
                tool_path: path,
                flags,
                position: 0,
                ref_count: 1,
            },
        );
        Ok(td)
    }

    /// Close a tool descriptor.
    pub fn close(&mut self, td: ToolDescriptor) -> Result<(), &'static str> {
        if self.entries.remove(&td).is_some() {
            Ok(())
        } else {
            Err("bad tool descriptor (EBADF)")
        }
    }

    /// Get a descriptor entry.
    pub fn get(&self, td: ToolDescriptor) -> Option<&ToolDescEntry> {
        self.entries.get(&td)
    }

    /// Check if flags allow read.
    pub fn can_read(&self, td: ToolDescriptor) -> bool {
        self.entries
            .get(&td)
            .map(|e| (e.flags & open_flags::O_RDONLY) != 0)
            .unwrap_or(false)
    }

    /// Check if flags allow write.
    pub fn can_write(&self, td: ToolDescriptor) -> bool {
        self.entries
            .get(&td)
            .map(|e| (e.flags & open_flags::O_WRONLY) != 0)
            .unwrap_or(false)
    }

    /// Duplicate a descriptor (like dup()).
    pub fn dup(&mut self, td: ToolDescriptor) -> Result<ToolDescriptor, &'static str> {
        let entry = self.entries.get(&td).ok_or("bad tool descriptor")?.clone();
        let new_td = self.next_td.fetch_add(1, Ordering::SeqCst);
        self.entries.insert(
            new_td,
            ToolDescEntry {
                td: new_td,
                ..entry
            },
        );
        Ok(new_td)
    }

    /// Clone the entire table (for agent_clone with CLONE_TOOLS).
    pub fn clone_table(&self) -> Self {
        let mut new_table = Self::new(self.max_open);
        for (td, entry) in &self.entries {
            new_table.entries.insert(*td, entry.clone());
        }
        new_table.next_td = AtomicU32::new(self.next_td.load(Ordering::SeqCst));
        new_table
    }

    /// Count open descriptors.
    pub fn count(&self) -> usize {
        self.entries.len()
    }

    /// List all open tool paths.
    pub fn list(&self) -> Vec<(ToolDescriptor, &str)> {
        self.entries
            .iter()
            .map(|(td, e)| (*td, e.tool_path.as_str()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_and_close() {
        let mut table = ToolDescTable::new(256);
        let td = table
            .open("/tools/filesystem".into(), open_flags::O_RDWR)
            .unwrap();
        assert_eq!(table.count(), 1);
        table.close(td).unwrap();
        assert_eq!(table.count(), 0);
    }

    #[test]
    fn max_open_limit() {
        let mut table = ToolDescTable::new(2);
        table.open("a".into(), open_flags::O_RDONLY).unwrap();
        table.open("b".into(), open_flags::O_RDONLY).unwrap();
        let result = table.open("c".into(), open_flags::O_RDONLY);
        assert!(result.is_err());
    }

    #[test]
    fn permission_check() {
        let mut table = ToolDescTable::new(256);
        let td = table
            .open("/tools/fs".into(), open_flags::O_RDONLY)
            .unwrap();
        assert!(table.can_read(td));
        assert!(!table.can_write(td));
    }

    #[test]
    fn dup_descriptor() {
        let mut table = ToolDescTable::new(256);
        let td1 = table.open("/tools/net".into(), open_flags::O_RDWR).unwrap();
        let td2 = table.dup(td1).unwrap();
        assert_ne!(td1, td2);
        assert_eq!(table.get(td2).unwrap().tool_path, "/tools/net");
    }

    #[test]
    fn clone_table() {
        let mut table = ToolDescTable::new(256);
        table.open("/tools/a".into(), open_flags::O_RDONLY).unwrap();
        table.open("/tools/b".into(), open_flags::O_WRONLY).unwrap();
        let cloned = table.clone_table();
        assert_eq!(cloned.count(), 2);
    }

    #[test]
    fn close_bad_descriptor() {
        let mut table = ToolDescTable::new(256);
        let result = table.close(999);
        assert!(result.is_err());
    }
}
