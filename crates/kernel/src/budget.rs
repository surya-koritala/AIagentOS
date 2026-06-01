//! Budget Enforcer — a hard cumulative USD spend ceiling on the LLM path.
//!
//! The cgroup token quota (see [`crate::cgroups`] / [`crate::syscall_gate`])
//! bounds an agent's *per-minute* token throughput. It does **not** bound
//! lifetime cost: an agent can run for hours and spend unboundedly as long as
//! it stays under the per-minute rate. The `BudgetEnforcer` closes that gap by
//! pricing every LLM response in USD and refusing further LLM calls once a
//! cumulative ceiling is reached — globally and/or per agent.
//!
//! It is **inert by default**: with no price and no ceiling configured, cost is
//! always `$0` and `check` always passes, so existing behavior is unchanged.
//! An operator activates it by setting `usd_per_1k_tokens` (or per-provider
//! prices) and a `max_usd` / `per_agent_max_usd` ceiling in [`crate::config`].

use std::sync::atomic::{AtomicU64, Ordering};

use dashmap::DashMap;

use crate::AgentId;

/// Spend is accumulated in micro-dollars (1e-6 USD) as `u64` so the global
/// counter can be a lock-free atomic without floating-point atomics.
const MICROS_PER_USD: f64 = 1_000_000.0;

fn usd_to_micros(usd: f64) -> u64 {
    if usd <= 0.0 {
        0
    } else {
        (usd * MICROS_PER_USD).round() as u64
    }
}

fn micros_to_usd(micros: u64) -> f64 {
    micros as f64 / MICROS_PER_USD
}

/// Which ceiling a call would breach.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BudgetScope {
    Global,
    Agent,
}

/// Returned by [`BudgetEnforcer::check`] when a ceiling is already reached.
#[derive(Debug, Clone, PartialEq)]
pub struct BudgetExceeded {
    pub scope: BudgetScope,
    pub spent_usd: f64,
    pub limit_usd: f64,
}

impl BudgetExceeded {
    /// Human-readable message suitable for surfacing to the caller / LLM.
    pub fn message(&self) -> String {
        let scope = match self.scope {
            BudgetScope::Global => "global",
            BudgetScope::Agent => "per-agent",
        };
        format!(
            "{} budget exhausted: spent ${:.4} of ${:.4} ceiling",
            scope, self.spent_usd, self.limit_usd
        )
    }
}

/// Tracks cumulative USD spend and enforces hard ceilings.
pub struct BudgetEnforcer {
    /// Per-provider price in USD per 1000 tokens; falls back to `default_price_per_1k`.
    pricing: DashMap<String, f64>,
    /// Price used when a provider has no specific entry.
    default_price_per_1k: f64,
    /// Global ceiling in micro-USD; `0` = unlimited.
    max_micros: u64,
    /// Per-agent ceiling in micro-USD; `0` = unlimited.
    per_agent_max_micros: u64,
    /// Cumulative global spend (micro-USD).
    spent_micros: AtomicU64,
    /// Cumulative per-agent spend (micro-USD).
    per_agent_micros: DashMap<AgentId, u64>,
}

impl BudgetEnforcer {
    /// Simple constructor: a global USD ceiling only (`0.0` = unlimited), no
    /// token pricing. Pair with [`record_cost`](Self::record_cost) /
    /// [`can_proceed`](Self::can_proceed) when the caller computes USD itself.
    pub fn new(max_cost_usd: f64) -> Self {
        Self::with_pricing(0.0, max_cost_usd, 0.0)
    }

    /// Construct with a default blended price and global/per-agent ceilings (USD;
    /// `0.0` or negative = unlimited / inert).
    pub fn with_pricing(default_price_per_1k: f64, max_usd: f64, per_agent_max_usd: f64) -> Self {
        Self {
            pricing: DashMap::new(),
            default_price_per_1k: default_price_per_1k.max(0.0),
            max_micros: usd_to_micros(max_usd),
            per_agent_max_micros: usd_to_micros(per_agent_max_usd),
            spent_micros: AtomicU64::new(0),
            per_agent_micros: DashMap::new(),
        }
    }

    /// Build from the operator's budget config.
    pub fn from_config(cfg: &crate::config::BudgetConfig) -> Self {
        let enforcer =
            Self::with_pricing(cfg.usd_per_1k_tokens, cfg.max_usd, cfg.per_agent_max_usd);
        for (provider, price) in &cfg.provider_pricing {
            enforcer.set_provider_price(provider, *price);
        }
        enforcer
    }

    /// Set a per-provider price (USD per 1000 tokens).
    pub fn set_provider_price(&self, provider: impl Into<String>, usd_per_1k: f64) {
        self.pricing.insert(provider.into(), usd_per_1k.max(0.0));
    }

    /// Price (USD / 1000 tokens) for a provider.
    pub fn price_per_1k(&self, provider: &str) -> f64 {
        self.pricing
            .get(provider)
            .map(|p| *p.value())
            .unwrap_or(self.default_price_per_1k)
    }

    /// Cost in USD of `tokens` for a provider.
    pub fn cost_of(&self, provider: &str, tokens: u32) -> f64 {
        self.price_per_1k(provider) * (tokens as f64 / 1000.0)
    }

    /// Whether any ceiling is configured (otherwise the enforcer is inert).
    pub fn is_active(&self) -> bool {
        self.max_micros > 0 || self.per_agent_max_micros > 0
    }

    /// Check whether `agent` may make another LLM call. Returns `Err` when a
    /// cumulative ceiling has already been reached (hard stop). The global
    /// ceiling is checked before the per-agent one.
    pub fn check(&self, agent: AgentId) -> Result<(), BudgetExceeded> {
        if self.max_micros > 0 {
            let spent = self.spent_micros.load(Ordering::Relaxed);
            if spent >= self.max_micros {
                return Err(BudgetExceeded {
                    scope: BudgetScope::Global,
                    spent_usd: micros_to_usd(spent),
                    limit_usd: micros_to_usd(self.max_micros),
                });
            }
        }
        if self.per_agent_max_micros > 0 {
            let spent = self
                .per_agent_micros
                .get(&agent)
                .map(|v| *v.value())
                .unwrap_or(0);
            if spent >= self.per_agent_max_micros {
                return Err(BudgetExceeded {
                    scope: BudgetScope::Agent,
                    spent_usd: micros_to_usd(spent),
                    limit_usd: micros_to_usd(self.per_agent_max_micros),
                });
            }
        }
        Ok(())
    }

    /// Record actual spend for an LLM response and return the cost in USD.
    pub fn record(&self, agent: AgentId, provider: &str, tokens: u32) -> f64 {
        let cost_usd = self.cost_of(provider, tokens);
        let micros = usd_to_micros(cost_usd);
        if micros > 0 {
            self.spent_micros.fetch_add(micros, Ordering::Relaxed);
            *self.per_agent_micros.entry(agent).or_insert(0) += micros;
        }
        cost_usd
    }

    /// Cumulative global spend in USD.
    pub fn global_spent_usd(&self) -> f64 {
        micros_to_usd(self.spent_micros.load(Ordering::Relaxed))
    }

    /// Cumulative spend for one agent in USD.
    pub fn agent_spent_usd(&self, agent: AgentId) -> f64 {
        micros_to_usd(
            self.per_agent_micros
                .get(&agent)
                .map(|v| *v.value())
                .unwrap_or(0),
        )
    }

    /// Drop tracking for an agent (call on shutdown / unregister). Global spend
    /// is intentionally retained — the lifetime ceiling spans agents.
    pub fn purge_agent(&self, agent: AgentId) {
        self.per_agent_micros.remove(&agent);
    }

    // ── Agent-agnostic API (caller supplies USD directly) ────────────────────

    /// Whether the global ceiling permits another request. `true` when no
    /// ceiling is set or cumulative spend is still below it.
    pub fn can_proceed(&self) -> bool {
        self.max_micros == 0 || self.spent_micros.load(Ordering::Relaxed) < self.max_micros
    }

    /// Record a raw USD cost against the global total (no provider/agent). Used
    /// when the caller has already computed cost. Negative costs are ignored.
    pub fn record_cost(&self, cost_usd: f64) {
        let micros = usd_to_micros(cost_usd);
        if micros > 0 {
            self.spent_micros.fetch_add(micros, Ordering::Relaxed);
        }
    }

    /// Remaining global budget in USD (`f64::INFINITY` if unlimited).
    pub fn remaining(&self) -> f64 {
        if self.max_micros == 0 {
            f64::INFINITY
        } else {
            micros_to_usd(
                self.max_micros
                    .saturating_sub(self.spent_micros.load(Ordering::Relaxed)),
            )
        }
    }

    /// Current global spend in USD (alias of [`global_spent_usd`](Self::global_spent_usd)).
    pub fn current_spend(&self) -> f64 {
        self.global_spent_usd()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inert_when_no_ceiling() {
        let b = BudgetEnforcer::with_pricing(10.0, 0.0, 0.0);
        let a = uuid::Uuid::new_v4();
        assert!(!b.is_active());
        // Spend a lot; with no ceiling, check always passes.
        b.record(a, "openai", 1_000_000);
        assert!(b.check(a).is_ok());
        assert!(b.global_spent_usd() > 0.0);
    }

    #[test]
    fn pricing_default_and_per_provider() {
        let b = BudgetEnforcer::with_pricing(2.0, 0.0, 0.0);
        b.set_provider_price("anthropic", 15.0);
        // 1000 tokens at default $2/1k = $2.
        assert!((b.cost_of("openai", 1000) - 2.0).abs() < 1e-9);
        // 2000 tokens at $15/1k = $30.
        assert!((b.cost_of("anthropic", 2000) - 30.0).abs() < 1e-9);
    }

    #[test]
    fn global_ceiling_blocks_after_reached() {
        // $1/1k tokens, $0.10 global ceiling.
        let b = BudgetEnforcer::with_pricing(1.0, 0.10, 0.0);
        let a = uuid::Uuid::new_v4();
        assert!(b.check(a).is_ok());
        // 100 tokens = $0.10 → reaches the ceiling.
        b.record(a, "p", 100);
        let err = b.check(a).unwrap_err();
        assert_eq!(err.scope, BudgetScope::Global);
        assert!(err.spent_usd >= 0.10);
    }

    #[test]
    fn per_agent_ceiling_is_isolated() {
        // No global ceiling; $0.05 per-agent ceiling at $1/1k.
        let b = BudgetEnforcer::with_pricing(1.0, 0.0, 0.05);
        let a = uuid::Uuid::new_v4();
        let other = uuid::Uuid::new_v4();
        b.record(a, "p", 60); // $0.06 > $0.05
        assert_eq!(b.check(a).unwrap_err().scope, BudgetScope::Agent);
        // A different agent is unaffected.
        assert!(b.check(other).is_ok());
    }

    #[test]
    fn purge_agent_resets_agent_spend_not_global() {
        let b = BudgetEnforcer::with_pricing(1.0, 0.0, 0.05);
        let a = uuid::Uuid::new_v4();
        b.record(a, "p", 100); // $0.10
        let global_before = b.global_spent_usd();
        b.purge_agent(a);
        assert_eq!(b.agent_spent_usd(a), 0.0);
        assert_eq!(b.global_spent_usd(), global_before);
    }

    // ── Agent-agnostic simple API (absorbed from the former
    //    production::BudgetEnforcer; preserves its behavior) ──────────────────

    #[test]
    fn simple_api_blocks_at_limit() {
        let be = BudgetEnforcer::new(1.0);
        assert!(be.can_proceed());
        be.record_cost(0.5);
        assert!(be.can_proceed());
        be.record_cost(0.6);
        assert!(!be.can_proceed()); // $1.10 ≥ $1.00
    }

    #[test]
    fn simple_api_unlimited_and_negative() {
        let be = BudgetEnforcer::new(0.0); // 0 = unlimited
        be.record_cost(1000.0);
        assert!(be.can_proceed());
        assert_eq!(be.remaining(), f64::INFINITY);

        // Negative cost is ignored (defensive).
        let be2 = BudgetEnforcer::new(1.0);
        be2.record_cost(-0.5);
        assert!(be2.can_proceed());
        assert_eq!(be2.current_spend(), 0.0);
    }
}
