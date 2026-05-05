//! Context Paging — virtual memory for AI agents.
//!
//! Like Linux's virtual memory system. Context is divided into pages that
//! can be paged in/out of active memory (the LLM context window).

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};

use chrono::{DateTime, Utc};

use crate::agent_struct::AgentId;

static NEXT_PAGE_ID: AtomicU64 = AtomicU64::new(1);

/// A page of context (like a memory page).
#[derive(Debug, Clone)]
pub struct ContextPage {
    pub id: u64,
    pub agent_id: AgentId,
    pub content: String,
    pub token_count: u32,
    pub created_at: DateTime<Utc>,
    pub last_accessed: DateTime<Utc>,
    pub pinned: bool, // pinned pages can't be evicted
}

/// Page location.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PageLocation {
    /// In active context (LLM can see it).
    Active,
    /// Paged out to storage (must be loaded before use).
    Swapped,
}

/// Page table entry.
#[derive(Debug, Clone)]
pub struct PageTableEntry {
    pub page_id: u64,
    pub location: PageLocation,
    pub dirty: bool,
}

/// The paging system for an agent's context.
pub struct ContextPager {
    /// Active pages (in LLM context window).
    active: VecDeque<ContextPage>,
    /// Swapped pages (on disk/SQLite).
    swapped: Vec<ContextPage>,
    /// Page table (maps page_id → location).
    page_table: Vec<PageTableEntry>,
    /// Max active tokens (context window size).
    max_active_tokens: u32,
    /// Current active token count.
    active_tokens: u32,
}

impl ContextPager {
    pub fn new(max_active_tokens: u32) -> Self {
        Self {
            active: VecDeque::new(),
            swapped: Vec::new(),
            page_table: Vec::new(),
            max_active_tokens,
            active_tokens: 0,
        }
    }

    /// Add a new page to active context.
    pub fn add_page(&mut self, agent_id: AgentId, content: String) -> u64 {
        let token_count = (content.len() as u32) / 4 + 1; // rough estimate
        let page_id = NEXT_PAGE_ID.fetch_add(1, Ordering::SeqCst);
        let now = Utc::now();

        // Evict if needed
        while self.active_tokens + token_count > self.max_active_tokens && !self.active.is_empty() {
            self.evict_lru();
        }

        let page = ContextPage {
            id: page_id, agent_id, content, token_count,
            created_at: now, last_accessed: now, pinned: false,
        };

        self.active_tokens += token_count;
        self.active.push_back(page);
        self.page_table.push(PageTableEntry { page_id, location: PageLocation::Active, dirty: false });

        page_id
    }

    /// Evict the least recently used non-pinned page.
    fn evict_lru(&mut self) {
        // Find oldest non-pinned page
        let idx = self.active.iter().position(|p| !p.pinned);
        if let Some(idx) = idx {
            let page = self.active.remove(idx).unwrap();
            self.active_tokens -= page.token_count;
            // Update page table
            if let Some(entry) = self.page_table.iter_mut().find(|e| e.page_id == page.id) {
                entry.location = PageLocation::Swapped;
            }
            self.swapped.push(page);
        }
    }

    /// Page in a swapped page (bring back to active).
    pub fn page_in(&mut self, page_id: u64) -> Option<&ContextPage> {
        let idx = self.swapped.iter().position(|p| p.id == page_id)?;
        let mut page = self.swapped.remove(idx);
        page.last_accessed = Utc::now();

        // Evict if needed to make room
        while self.active_tokens + page.token_count > self.max_active_tokens && !self.active.is_empty() {
            self.evict_lru();
        }

        self.active_tokens += page.token_count;
        if let Some(entry) = self.page_table.iter_mut().find(|e| e.page_id == page_id) {
            entry.location = PageLocation::Active;
        }
        self.active.push_back(page);
        self.active.back()
    }

    /// Pin a page (prevent eviction).
    pub fn pin(&mut self, page_id: u64) {
        if let Some(page) = self.active.iter_mut().find(|p| p.id == page_id) {
            page.pinned = true;
        }
    }

    /// Get all active pages (what the LLM sees).
    pub fn active_pages(&self) -> Vec<&ContextPage> {
        self.active.iter().collect()
    }

    /// Get active token count.
    pub fn active_token_count(&self) -> u32 { self.active_tokens }

    /// Get swapped page count.
    pub fn swapped_count(&self) -> usize { self.swapped.len() }

    /// Get total pages.
    pub fn total_pages(&self) -> usize { self.active.len() + self.swapped.len() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_pages_within_limit() {
        let mut pager = ContextPager::new(1000);
        pager.add_page(1, "hello world".into()); // ~3 tokens
        assert_eq!(pager.active_pages().len(), 1);
        assert_eq!(pager.swapped_count(), 0);
    }

    #[test]
    fn eviction_on_overflow() {
        let mut pager = ContextPager::new(20); // very small
        pager.add_page(1, "first page with some content that is long enough".into());
        pager.add_page(1, "second page also with content".into());
        // First page should be evicted
        assert!(pager.swapped_count() > 0);
    }

    #[test]
    fn page_in_swapped() {
        let mut pager = ContextPager::new(10); // tiny window
        let id1 = pager.add_page(1, "x".repeat(40)); // ~11 tokens, fills window
        let _id2 = pager.add_page(1, "y".repeat(40)); // forces eviction of id1
        assert!(pager.swapped_count() > 0);
        let result = pager.page_in(id1);
        assert!(result.is_some());
    }

    #[test]
    fn pinned_pages_not_evicted() {
        let mut pager = ContextPager::new(30);
        let id1 = pager.add_page(1, "pinned page content here".into());
        pager.pin(id1);
        pager.add_page(1, "second page tries to evict".into());
        pager.add_page(1, "third page also tries".into());
        // Pinned page should still be active
        assert!(pager.active_pages().iter().any(|p| p.id == id1));
    }

    #[test]
    fn token_accounting() {
        let mut pager = ContextPager::new(10000);
        pager.add_page(1, "x".repeat(100)); // ~26 tokens
        assert!(pager.active_token_count() > 0);
        assert!(pager.active_token_count() < 100);
    }
}
