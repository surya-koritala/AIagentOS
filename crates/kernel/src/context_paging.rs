//! Context-pressure admission and the legacy in-memory page model.
//!
//! The production contract is explicit backpressure for provider prompts. It is
//! not host virtual memory and never claims to preempt or kill a process.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use chrono::{DateTime, Utc};

use crate::agent_struct::AgentId as PageAgentId;
use crate::AgentId;

static NEXT_PAGE_ID: AtomicU64 = AtomicU64::new(1);

/// Concurrent active-prompt limits. Zero means unlimited at that scope.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ActiveContextLimits {
    pub per_agent_tokens: u64,
    pub per_tenant_tokens: u64,
    pub global_tokens: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ActiveContextUsage {
    pub agent_tokens: u64,
    pub tenant_tokens: u64,
    pub global_tokens: u64,
    pub per_agent_limit: u64,
    pub per_tenant_limit: u64,
    pub global_limit: u64,
    pub rejection_count: u64,
}

#[derive(Debug, Default)]
struct ActiveContextState {
    agents: HashMap<AgentId, u64>,
    tenants: HashMap<String, u64>,
    global: u64,
    rejections: HashMap<AgentId, u64>,
}

/// Atomic, process-wide active-prompt admission.
///
/// Admission is deliberately non-blocking. Callers receive stable retryable
/// backpressure instead of holding an LLM core or provider quota while waiting
/// for another prompt to leave the active set.
#[derive(Debug)]
pub struct ActiveContextManager {
    limits: ActiveContextLimits,
    state: Arc<Mutex<ActiveContextState>>,
}

impl ActiveContextManager {
    pub fn new(limits: ActiveContextLimits) -> Self {
        Self {
            limits,
            state: Arc::new(Mutex::new(ActiveContextState::default())),
        }
    }

    pub fn try_admit(
        &self,
        agent_id: AgentId,
        tenant_id: &str,
        tokens: u64,
    ) -> Result<ActiveContextAdmission, String> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| "context pressure state is unavailable; retry with backoff".to_string())?;
        let agent_used = state.agents.get(&agent_id).copied().unwrap_or(0);
        let tenant_used = state.tenants.get(tenant_id).copied().unwrap_or(0);
        let checks = [
            (
                "agent",
                agent_used,
                self.limits.per_agent_tokens,
                agent_id.to_string(),
            ),
            (
                "tenant",
                tenant_used,
                self.limits.per_tenant_tokens,
                tenant_id.to_string(),
            ),
            (
                "global",
                state.global,
                self.limits.global_tokens,
                "kernel".to_string(),
            ),
        ];
        if let Some((scope, used, limit, identity)) = checks
            .into_iter()
            .find(|(_, used, limit, _)| *limit > 0 && used.saturating_add(tokens) > *limit)
        {
            *state.rejections.entry(agent_id).or_default() = state
                .rejections
                .get(&agent_id)
                .copied()
                .unwrap_or(0)
                .saturating_add(1);
            return Err(format!(
                "context pressure: {scope} {identity} active prompt admission would use {} tokens above limit {limit}; retry with backoff",
                used.saturating_add(tokens)
            ));
        }

        state
            .agents
            .insert(agent_id, agent_used.saturating_add(tokens));
        state
            .tenants
            .insert(tenant_id.to_string(), tenant_used.saturating_add(tokens));
        state.global = state.global.saturating_add(tokens);
        Ok(ActiveContextAdmission {
            state: Arc::clone(&self.state),
            agent_id,
            tenant_id: tenant_id.to_string(),
            tokens,
        })
    }

    pub fn usage(&self, agent_id: AgentId, tenant_id: &str) -> ActiveContextUsage {
        let Ok(state) = self.state.lock() else {
            return ActiveContextUsage {
                per_agent_limit: self.limits.per_agent_tokens,
                per_tenant_limit: self.limits.per_tenant_tokens,
                global_limit: self.limits.global_tokens,
                ..ActiveContextUsage::default()
            };
        };
        ActiveContextUsage {
            agent_tokens: state.agents.get(&agent_id).copied().unwrap_or(0),
            tenant_tokens: state.tenants.get(tenant_id).copied().unwrap_or(0),
            global_tokens: state.global,
            per_agent_limit: self.limits.per_agent_tokens,
            per_tenant_limit: self.limits.per_tenant_tokens,
            global_limit: self.limits.global_tokens,
            rejection_count: state.rejections.get(&agent_id).copied().unwrap_or(0),
        }
    }
}

#[derive(Debug)]
pub struct ActiveContextAdmission {
    state: Arc<Mutex<ActiveContextState>>,
    agent_id: AgentId,
    tenant_id: String,
    tokens: u64,
}

impl Drop for ActiveContextAdmission {
    fn drop(&mut self) {
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        let agent_remaining = state
            .agents
            .get(&self.agent_id)
            .copied()
            .unwrap_or(0)
            .saturating_sub(self.tokens);
        if agent_remaining == 0 {
            state.agents.remove(&self.agent_id);
        } else {
            state.agents.insert(self.agent_id, agent_remaining);
        }
        let tenant_remaining = state
            .tenants
            .get(&self.tenant_id)
            .copied()
            .unwrap_or(0)
            .saturating_sub(self.tokens);
        if tenant_remaining == 0 {
            state.tenants.remove(&self.tenant_id);
        } else {
            state
                .tenants
                .insert(self.tenant_id.clone(), tenant_remaining);
        }
        state.global = state.global.saturating_sub(self.tokens);
    }
}

/// A page of context (like a memory page).
#[derive(Debug, Clone)]
pub struct ContextPage {
    pub id: u64,
    pub agent_id: PageAgentId,
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
    pub fn add_page(&mut self, agent_id: PageAgentId, content: String) -> u64 {
        let token_count = (content.len() as u32) / 4 + 1; // rough estimate
        let page_id = NEXT_PAGE_ID.fetch_add(1, Ordering::SeqCst);
        let now = Utc::now();

        // Evict if needed. Stop if there's nothing evictable (e.g. only pinned
        // pages remain) so an oversized/pinned working set can't spin forever.
        while self.active_tokens.saturating_add(token_count) > self.max_active_tokens {
            if !self.evict_lru() {
                break;
            }
        }

        let page = ContextPage {
            id: page_id,
            agent_id,
            content,
            token_count,
            created_at: now,
            last_accessed: now,
            pinned: false,
        };

        let location = if self.active_tokens.saturating_add(token_count) <= self.max_active_tokens {
            self.active_tokens = self.active_tokens.saturating_add(token_count);
            self.active.push_back(page);
            PageLocation::Active
        } else {
            self.swapped.push(page);
            PageLocation::Swapped
        };
        self.page_table.push(PageTableEntry {
            page_id,
            location,
            dirty: false,
        });

        page_id
    }

    /// Evict the least recently used non-pinned page. Returns `true` if a page
    /// was evicted, `false` if there is nothing evictable (no non-pinned page).
    fn evict_lru(&mut self) -> bool {
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
            true
        } else {
            false
        }
    }

    /// Page in a swapped page (bring back to active).
    pub fn page_in(&mut self, page_id: u64) -> Option<&ContextPage> {
        let idx = self.swapped.iter().position(|p| p.id == page_id)?;
        let page_tokens = self.swapped[idx].token_count;

        // Evict if needed to make room; stop if nothing is evictable.
        while self.active_tokens.saturating_add(page_tokens) > self.max_active_tokens {
            if !self.evict_lru() {
                break;
            }
        }
        if self.active_tokens.saturating_add(page_tokens) > self.max_active_tokens {
            return None;
        }

        let mut page = self.swapped.remove(idx);
        page.last_accessed = Utc::now();
        self.active_tokens = self.active_tokens.saturating_add(page.token_count);
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
    pub fn active_token_count(&self) -> u32 {
        self.active_tokens
    }

    /// Get swapped page count.
    pub fn swapped_count(&self) -> usize {
        self.swapped.len()
    }

    /// Get total pages.
    pub fn total_pages(&self) -> usize {
        self.active.len() + self.swapped.len()
    }
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
        let mut pager = ContextPager::new(15); // one page fits, two do not
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
    fn all_pinned_over_budget_does_not_hang() {
        // Regression: if every active page is pinned and we're over budget,
        // add_page must not spin forever trying to evict.
        let mut pager = ContextPager::new(25);
        let id1 = pager.add_page(1, "x".repeat(80)); // ~21 tokens, within budget
        pager.pin(id1);
        // Adding another page can't evict the pinned one — must return promptly.
        pager.add_page(1, "y".repeat(80));
        assert!(pager.active_pages().iter().any(|p| p.id == id1));
        assert_eq!(pager.total_pages(), 2);
        assert!(pager.active_token_count() <= 25);
    }

    #[test]
    fn token_accounting() {
        let mut pager = ContextPager::new(10000);
        pager.add_page(1, "x".repeat(100)); // ~26 tokens
        assert!(pager.active_token_count() > 0);
        assert!(pager.active_token_count() < 100);
    }

    #[test]
    fn active_admission_is_atomic_isolated_and_released_by_drop() {
        let manager = ActiveContextManager::new(ActiveContextLimits {
            per_agent_tokens: 80,
            per_tenant_tokens: 100,
            global_tokens: 140,
        });
        let a = uuid::Uuid::new_v4();
        let b = uuid::Uuid::new_v4();
        let c = uuid::Uuid::new_v4();
        let first = manager.try_admit(a, "tenant-a", 70).unwrap();
        let error = manager.try_admit(b, "tenant-a", 40).unwrap_err();
        assert!(error.contains("tenant tenant-a"));
        let other_tenant = manager.try_admit(c, "tenant-b", 60).unwrap();
        assert_eq!(manager.usage(a, "tenant-a").global_tokens, 130);
        drop(first);
        assert!(manager.try_admit(b, "tenant-a", 40).is_ok());
        drop(other_tenant);
        assert_eq!(manager.usage(c, "tenant-b").tenant_tokens, 0);
    }

    #[test]
    fn oversized_prompt_fails_without_leaking_usage() {
        let manager = ActiveContextManager::new(ActiveContextLimits {
            per_agent_tokens: 10,
            ..ActiveContextLimits::default()
        });
        let agent = uuid::Uuid::new_v4();
        assert!(manager.try_admit(agent, "tenant", 11).is_err());
        let usage = manager.usage(agent, "tenant");
        assert_eq!(usage.agent_tokens, 0);
        assert_eq!(usage.global_tokens, 0);
        assert_eq!(usage.rejection_count, 1);
    }
}
