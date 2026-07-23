//! Budget Enforcer — a hard cumulative USD spend ceiling on the LLM path.
//!
//! The durable provider/cgroup quota (see [`crate::rate_limit`] and
//! [`crate::cgroups`]) bounds an agent's *per-minute* token throughput. It does
//! **not** bound lifetime cost: an agent can run for hours and spend unboundedly
//! as long as it stays under the per-minute rate. The `BudgetEnforcer` closes that gap by
//! pricing every LLM response in USD and refusing further LLM calls once a
//! cumulative ceiling is reached — globally and/or per agent.
//!
//! It is **inert by default**: with no price and no ceiling configured, cost is
//! always `$0` and `check` always passes, so existing behavior is unchanged.
//! An operator activates it by setting `usd_per_1k_tokens` (or per-provider
//! prices) and a `max_usd` / `per_agent_max_usd` ceiling in [`crate::config`].

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use dashmap::DashMap;

use crate::config::TokenPricing;
use crate::connector::LlmUsage;
use crate::context::BudgetUsageSnapshot;
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

fn atomic_saturating_add(counter: &AtomicU64, amount: u64) {
    let _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
        Some(current.saturating_add(amount))
    });
}

/// Which ceiling a call would breach.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BudgetScope {
    Global,
    Tenant,
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
            BudgetScope::Tenant => "per-tenant",
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
    /// Detailed fallback pricing, lower precedence than legacy per-provider
    /// scalar prices but higher precedence than the legacy global scalar.
    default_token_pricing: Option<TokenPricing>,
    /// Detailed provider pricing.
    provider_token_pricing: DashMap<String, TokenPricing>,
    /// Detailed provider+model pricing.
    provider_model_token_pricing: DashMap<String, std::collections::HashMap<String, TokenPricing>>,
    /// Global ceiling in micro-USD; `0` = unlimited.
    max_micros: u64,
    /// Per-agent ceiling in micro-USD; `0` = unlimited.
    per_agent_max_micros: u64,
    /// Per-tenant ceiling in micro-USD; `0` = unlimited.
    per_tenant_max_micros: u64,
    /// Cumulative global spend (micro-USD).
    spent_micros: AtomicU64,
    /// Cumulative per-agent spend (micro-USD).
    per_agent_micros: DashMap<AgentId, u64>,
    /// Durable tenant association for each live/rehydrated agent.
    agent_tenants: DashMap<AgentId, String>,
    /// Cumulative per-tenant spend (micro-USD).
    per_tenant_micros: DashMap<String, u64>,
    /// Admission locks make check→request→record atomic for every configured
    /// ceiling scope, preventing concurrent requests from racing past a limit.
    global_call_lock: Arc<tokio::sync::Mutex<()>>,
    tenant_call_locks: DashMap<String, Arc<tokio::sync::Mutex<()>>>,
    agent_call_locks: DashMap<AgentId, Arc<tokio::sync::Mutex<()>>>,
}

/// Holds configured budget-scope locks from admission until actual provider
/// usage has been recorded. The fields are intentionally unused except for
/// their drop behavior.
pub(crate) struct BudgetCallGuard {
    _global: Option<tokio::sync::OwnedMutexGuard<()>>,
    _tenant: Option<tokio::sync::OwnedMutexGuard<()>>,
    _agent: Option<tokio::sync::OwnedMutexGuard<()>>,
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
        Self::with_limits(default_price_per_1k, max_usd, per_agent_max_usd, 0.0)
    }

    /// Construct with global, per-agent, and per-tenant cumulative ceilings.
    pub fn with_limits(
        default_price_per_1k: f64,
        max_usd: f64,
        per_agent_max_usd: f64,
        per_tenant_max_usd: f64,
    ) -> Self {
        Self {
            pricing: DashMap::new(),
            default_price_per_1k: default_price_per_1k.max(0.0),
            default_token_pricing: None,
            provider_token_pricing: DashMap::new(),
            provider_model_token_pricing: DashMap::new(),
            max_micros: usd_to_micros(max_usd),
            per_agent_max_micros: usd_to_micros(per_agent_max_usd),
            per_tenant_max_micros: usd_to_micros(per_tenant_max_usd),
            spent_micros: AtomicU64::new(0),
            per_agent_micros: DashMap::new(),
            agent_tenants: DashMap::new(),
            per_tenant_micros: DashMap::new(),
            global_call_lock: Arc::new(tokio::sync::Mutex::new(())),
            tenant_call_locks: DashMap::new(),
            agent_call_locks: DashMap::new(),
        }
    }

    /// Build from the operator's budget config.
    pub fn from_config(cfg: &crate::config::BudgetConfig) -> Self {
        Self::try_from_config(cfg)
            .unwrap_or_else(|error| panic!("invalid budget configuration: {error}"))
    }

    /// Strictly build from operator budget config.
    ///
    /// Kernel startup uses this path so invalid detailed prices cannot be
    /// silently converted to free pricing.
    pub fn try_from_config(cfg: &crate::config::BudgetConfig) -> Result<Self, String> {
        cfg.validate()?;
        let mut enforcer = Self::with_limits(
            cfg.usd_per_1k_tokens,
            cfg.max_usd,
            cfg.per_agent_max_usd,
            cfg.per_tenant_max_usd,
        );
        enforcer.default_token_pricing = cfg.default_token_pricing;
        for (provider, price) in &cfg.provider_pricing {
            enforcer.set_provider_price(provider, *price);
        }
        for (provider, pricing) in &cfg.provider_token_pricing {
            enforcer.set_provider_token_pricing(provider, *pricing)?;
        }
        for (provider, models) in &cfg.provider_model_token_pricing {
            for (model, pricing) in models {
                enforcer.set_provider_model_token_pricing(provider, model, *pricing)?;
            }
        }
        Ok(enforcer)
    }

    /// Set a per-provider price (USD per 1000 tokens).
    pub fn set_provider_price(&self, provider: impl Into<String>, usd_per_1k: f64) {
        self.pricing.insert(provider.into(), usd_per_1k.max(0.0));
    }

    /// Set detailed prices for a provider.
    pub fn set_provider_token_pricing(
        &self,
        provider: impl Into<String>,
        pricing: TokenPricing,
    ) -> Result<(), String> {
        let provider = provider.into();
        if provider.trim().is_empty() {
            return Err("provider token pricing requires a non-empty provider id".to_string());
        }
        pricing.validate(&format!("provider_token_pricing.{provider}"))?;
        self.provider_token_pricing.insert(provider, pricing);
        Ok(())
    }

    /// Set detailed prices for one model exposed by a provider.
    pub fn set_provider_model_token_pricing(
        &self,
        provider: impl Into<String>,
        model: impl Into<String>,
        pricing: TokenPricing,
    ) -> Result<(), String> {
        let provider = provider.into();
        let model = model.into();
        if provider.trim().is_empty() {
            return Err(
                "provider+model token pricing requires a non-empty provider id".to_string(),
            );
        }
        if model.trim().is_empty() {
            return Err("provider+model token pricing requires a non-empty model id".to_string());
        }
        pricing.validate(&format!("provider_model_token_pricing.{provider}.{model}"))?;
        self.provider_model_token_pricing
            .entry(provider)
            .or_default()
            .insert(model, pricing);
        Ok(())
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

    /// Resolve detailed prices using the documented compatibility precedence:
    ///
    /// provider+model detailed → provider detailed → legacy provider scalar →
    /// detailed default → legacy global scalar.
    pub fn token_pricing_for(&self, provider: &str, model: &str) -> TokenPricing {
        if let Some(models) = self.provider_model_token_pricing.get(provider) {
            if let Some(pricing) = models.get(model) {
                return *pricing;
            }
        }
        if let Some(pricing) = self.provider_token_pricing.get(provider) {
            return *pricing.value();
        }
        if let Some(price) = self.pricing.get(provider) {
            return TokenPricing::blended(*price.value());
        }
        self.default_token_pricing
            .unwrap_or_else(|| TokenPricing::blended(self.default_price_per_1k))
    }

    /// Cost detailed provider usage, charging cached input only at its cached
    /// rate rather than also charging it as uncached input.
    pub fn cost_of_usage(&self, provider: &str, model: &str, usage: LlmUsage) -> f64 {
        let pricing = self.token_pricing_for(provider, model);
        let cached_input = usage.cached_tokens.min(usage.input_tokens);
        let uncached_input = usage.input_tokens.saturating_sub(cached_input);
        (f64::from(uncached_input) * pricing.input_usd_per_1k_tokens
            + f64::from(cached_input) * pricing.cached_input_usd_per_1k_tokens
            + f64::from(usage.output_tokens) * pricing.output_usd_per_1k_tokens)
            / 1000.0
    }

    /// Whether any ceiling is configured (otherwise the enforcer is inert).
    pub fn is_active(&self) -> bool {
        self.max_micros > 0 || self.per_agent_max_micros > 0 || self.per_tenant_max_micros > 0
    }

    /// Associate an agent with its tenant for tenant-scoped accounting. Calling
    /// this again after rehydration is idempotent.
    pub fn register_agent_tenant(&self, agent: AgentId, tenant: impl Into<String>) {
        self.agent_tenants.insert(agent, tenant.into());
    }

    /// Atomically admit one provider request against every configured USD
    /// scope. The returned guard must live until [`record`](Self::record) has
    /// charged the response. This prevents multiple executors from passing the
    /// same pre-call check concurrently.
    pub(crate) async fn begin_call(
        &self,
        agent: AgentId,
    ) -> Result<BudgetCallGuard, BudgetExceeded> {
        let global = if self.max_micros > 0 {
            Some(self.global_call_lock.clone().lock_owned().await)
        } else {
            None
        };

        let tenant_name = self
            .agent_tenants
            .get(&agent)
            .map(|tenant| tenant.value().clone());
        let tenant = if self.per_tenant_max_micros > 0 {
            if let Some(name) = tenant_name {
                let lock = self
                    .tenant_call_locks
                    .entry(name)
                    .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
                    .clone();
                Some(lock.lock_owned().await)
            } else {
                None
            }
        } else {
            None
        };

        let agent_guard = if self.per_agent_max_micros > 0 {
            let lock = self
                .agent_call_locks
                .entry(agent)
                .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
                .clone();
            Some(lock.lock_owned().await)
        } else {
            None
        };

        self.check(agent)?;
        Ok(BudgetCallGuard {
            _global: global,
            _tenant: tenant,
            _agent: agent_guard,
        })
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
        if self.per_tenant_max_micros > 0 {
            if let Some(tenant) = self.agent_tenants.get(&agent) {
                let spent = self
                    .per_tenant_micros
                    .get(tenant.value())
                    .map(|value| *value.value())
                    .unwrap_or(0);
                if spent >= self.per_tenant_max_micros {
                    return Err(BudgetExceeded {
                        scope: BudgetScope::Tenant,
                        spent_usd: micros_to_usd(spent),
                        limit_usd: micros_to_usd(self.per_tenant_max_micros),
                    });
                }
            }
        }
        Ok(())
    }

    /// Record actual spend for an LLM response and return both the display USD
    /// value and the exact integer micro-USD charge applied to every counter.
    ///
    /// Persist the returned `u64` alongside the usage row; recalculating it from
    /// a floating-point USD value after restart can otherwise drift by a micro.
    pub fn record_charge(&self, agent: AgentId, provider: &str, tokens: u32) -> (f64, u64) {
        let cost_usd = self.cost_of(provider, tokens);
        self.record_calculated_charge(agent, cost_usd)
    }

    /// Price and record detailed provider usage. The three token-class amounts
    /// are summed in USD and rounded exactly once to integer micro-USD.
    pub fn record_usage_charge(
        &self,
        agent: AgentId,
        provider: &str,
        model: &str,
        usage: LlmUsage,
    ) -> (f64, u64) {
        let cost_usd = self.cost_of_usage(provider, model, usage);
        self.record_calculated_charge(agent, cost_usd)
    }

    fn record_calculated_charge(&self, agent: AgentId, cost_usd: f64) -> (f64, u64) {
        let micros = usd_to_micros(cost_usd);
        if micros > 0 {
            atomic_saturating_add(&self.spent_micros, micros);
            let mut agent_spend = self.per_agent_micros.entry(agent).or_insert(0);
            *agent_spend = agent_spend.saturating_add(micros);
            if let Some(tenant) = self.agent_tenants.get(&agent) {
                let mut tenant_spend = self
                    .per_tenant_micros
                    .entry(tenant.value().clone())
                    .or_insert(0);
                *tenant_spend = tenant_spend.saturating_add(micros);
            }
        }
        (cost_usd, micros)
    }

    /// Compatibility wrapper returning only the USD display value.
    pub fn record(&self, agent: AgentId, provider: &str, tokens: u32) -> f64 {
        self.record_charge(agent, provider, tokens).0
    }

    /// Replace in-memory counters with a durable restart snapshot.
    ///
    /// Replacement rather than addition makes repeated startup/recovery calls
    /// idempotent. This is intended to run before request admission begins.
    pub fn rehydrate(&self, snapshot: &BudgetUsageSnapshot) {
        self.spent_micros
            .store(snapshot.global_micros, Ordering::Relaxed);

        self.per_agent_micros.clear();
        for (agent, micros) in &snapshot.per_agent_micros {
            self.per_agent_micros.insert(*agent, *micros);
        }

        self.per_tenant_micros.clear();
        for (tenant, micros) in &snapshot.per_tenant_micros {
            self.per_tenant_micros.insert(tenant.clone(), *micros);
        }

        self.agent_tenants.clear();
        for (agent, tenant) in &snapshot.agent_tenants {
            self.agent_tenants.insert(*agent, tenant.clone());
        }
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

    /// Cumulative spend for one tenant in USD.
    pub fn tenant_spent_usd(&self, tenant: &str) -> f64 {
        micros_to_usd(
            self.per_tenant_micros
                .get(tenant)
                .map(|value| *value.value())
                .unwrap_or(0),
        )
    }

    /// Drop only live admission state for an unregistered agent. Cumulative
    /// global, tenant, and per-agent spend is retained so stop/restart cannot
    /// reset a lifetime ceiling.
    pub fn unregister_agent(&self, agent: AgentId) {
        let tenant = self.agent_tenants.remove(&agent).map(|(_, tenant)| tenant);
        self.agent_call_locks.remove(&agent);
        if let Some(tenant) = tenant {
            let still_live = self
                .agent_tenants
                .iter()
                .any(|entry| entry.value() == &tenant);
            if !still_live {
                self.tenant_call_locks.remove(&tenant);
            }
        }
    }

    /// Compatibility wrapper for the historical unregister hook.
    pub fn purge_agent(&self, agent: AgentId) {
        self.unregister_agent(agent);
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
            atomic_saturating_add(&self.spent_micros, micros);
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

    fn token_pricing(input: f64, cached: f64, output: f64) -> TokenPricing {
        TokenPricing {
            input_usd_per_1k_tokens: input,
            cached_input_usd_per_1k_tokens: cached,
            output_usd_per_1k_tokens: output,
        }
    }

    #[test]
    fn detailed_pricing_uses_provider_model_legacy_and_default_precedence() {
        let mut cfg = crate::config::BudgetConfig {
            usd_per_1k_tokens: 1.0,
            default_token_pricing: Some(token_pricing(2.0, 3.0, 4.0)),
            ..crate::config::BudgetConfig::default()
        };
        cfg.provider_pricing.insert("legacy".into(), 5.0);
        cfg.provider_token_pricing
            .insert("detailed".into(), token_pricing(6.0, 7.0, 8.0));
        cfg.provider_token_pricing
            .insert("modeled".into(), token_pricing(6.0, 7.0, 8.0));
        cfg.provider_model_token_pricing
            .entry("modeled".into())
            .or_default()
            .insert("special".into(), token_pricing(9.0, 10.0, 11.0));
        let b = BudgetEnforcer::try_from_config(&cfg).unwrap();
        let usage = LlmUsage::reported(100, 50, 20);

        let expected = |input: f64, cached: f64, output: f64| {
            (80.0 * input + 20.0 * cached + 50.0 * output) / 1000.0
        };
        assert_eq!(
            b.cost_of_usage("modeled", "special", usage),
            expected(9.0, 10.0, 11.0)
        );
        assert_eq!(
            b.cost_of_usage("modeled", "other", usage),
            expected(6.0, 7.0, 8.0)
        );
        assert_eq!(
            b.cost_of_usage("detailed", "any", usage),
            expected(6.0, 7.0, 8.0)
        );
        assert_eq!(
            b.cost_of_usage("legacy", "any", usage),
            expected(5.0, 5.0, 5.0)
        );
        assert_eq!(
            b.cost_of_usage("unknown", "any", usage),
            expected(2.0, 3.0, 4.0)
        );

        let without_detailed_default =
            BudgetEnforcer::with_pricing(cfg.usd_per_1k_tokens, 0.0, 0.0);
        assert_eq!(
            without_detailed_default.cost_of_usage("unknown", "any", usage),
            expected(1.0, 1.0, 1.0)
        );
    }

    #[test]
    fn detailed_usage_prices_cached_input_separately_and_rounds_once() {
        let mut cfg = crate::config::BudgetConfig {
            default_token_pricing: Some(token_pricing(0.0004, 9.0, 0.0004)),
            ..crate::config::BudgetConfig::default()
        };
        let b = BudgetEnforcer::try_from_config(&cfg).unwrap();
        let agent = uuid::Uuid::new_v4();
        let usage = LlmUsage::reported(1, 1, 0);
        let (cost, micros) = b.record_usage_charge(agent, "p", "m", usage);
        assert!((cost - 0.0000008).abs() < f64::EPSILON);
        assert_eq!(micros, 1, "token classes must be summed before rounding");

        cfg.default_token_pricing = Some(token_pricing(4.0, 0.5, 8.0));
        let b = BudgetEnforcer::try_from_config(&cfg).unwrap();
        let cost = b.cost_of_usage("p", "m", LlmUsage::reported(100, 25, 40));
        assert_eq!(cost, (60.0 * 4.0 + 40.0 * 0.5 + 25.0 * 8.0) / 1000.0);
    }

    #[test]
    fn strict_constructor_rejects_invalid_detailed_pricing() {
        let cfg = crate::config::BudgetConfig {
            default_token_pricing: Some(token_pricing(f64::INFINITY, 0.0, 0.0)),
            ..crate::config::BudgetConfig::default()
        };
        assert!(BudgetEnforcer::try_from_config(&cfg).is_err());

        let b = BudgetEnforcer::new(1.0);
        assert!(b
            .set_provider_token_pricing("p", token_pricing(-1.0, 0.0, 0.0))
            .is_err());
        assert!(b
            .set_provider_model_token_pricing("p", "", token_pricing(1.0, 1.0, 1.0))
            .is_err());
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
    fn per_tenant_ceiling_is_shared_and_isolated() {
        let b = BudgetEnforcer::with_limits(1.0, 0.0, 0.0, 0.05);
        let a1 = uuid::Uuid::new_v4();
        let a2 = uuid::Uuid::new_v4();
        let other = uuid::Uuid::new_v4();
        b.register_agent_tenant(a1, "tenant-a");
        b.register_agent_tenant(a2, "tenant-a");
        b.register_agent_tenant(other, "tenant-b");

        b.record(a1, "p", 30);
        b.record(a2, "p", 20);
        assert_eq!(b.check(a1).unwrap_err().scope, BudgetScope::Tenant);
        assert_eq!(b.check(a2).unwrap_err().scope, BudgetScope::Tenant);
        assert!(b.check(other).is_ok());
        assert!((b.tenant_spent_usd("tenant-a") - 0.05).abs() < f64::EPSILON);
    }

    #[test]
    fn counters_saturate_instead_of_overflowing() {
        let b = BudgetEnforcer::new(0.0);
        b.record_cost(f64::MAX);
        let first = b.spent_micros.load(Ordering::Relaxed);
        b.record_cost(f64::MAX);
        assert_eq!(first, u64::MAX);
        assert_eq!(b.spent_micros.load(Ordering::Relaxed), u64::MAX);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_calls_cannot_race_past_global_ceiling() {
        let budget = Arc::new(BudgetEnforcer::with_pricing(1.0, 0.10, 0.0));
        let barrier = Arc::new(tokio::sync::Barrier::new(32));
        let mut tasks = Vec::new();
        for _ in 0..32 {
            let budget = budget.clone();
            let barrier = barrier.clone();
            tasks.push(tokio::spawn(async move {
                let agent = uuid::Uuid::new_v4();
                barrier.wait().await;
                match budget.begin_call(agent).await {
                    Ok(_guard) => {
                        budget.record(agent, "p", 100);
                        true
                    }
                    Err(_) => false,
                }
            }));
        }
        let mut admitted = 0;
        for task in tasks {
            admitted += usize::from(task.await.unwrap());
        }
        assert_eq!(admitted, 1);
        assert!((budget.global_spent_usd() - 0.10).abs() < f64::EPSILON);
    }

    #[test]
    fn unregister_agent_retains_cumulative_spend() {
        let b = BudgetEnforcer::with_pricing(1.0, 0.0, 0.05);
        let a = uuid::Uuid::new_v4();
        b.register_agent_tenant(a, "tenant-a");
        b.record(a, "p", 100); // $0.10
        let global_before = b.global_spent_usd();
        let agent_before = b.agent_spent_usd(a);
        let tenant_before = b.tenant_spent_usd("tenant-a");
        b.purge_agent(a);
        assert_eq!(b.global_spent_usd(), global_before);
        assert_eq!(b.agent_spent_usd(a), agent_before);
        assert_eq!(b.tenant_spent_usd("tenant-a"), tenant_before);
        assert!(!b.agent_tenants.contains_key(&a));
        assert!(!b.agent_call_locks.contains_key(&a));
        assert!(!b.tenant_call_locks.contains_key("tenant-a"));
    }

    #[test]
    fn record_charge_returns_exact_applied_micros() {
        let b = BudgetEnforcer::with_pricing(0.0015, 0.0, 0.0);
        let agent = uuid::Uuid::new_v4();
        let (usd, micros) = b.record_charge(agent, "p", 1);
        assert!((usd - 0.0000015).abs() < f64::EPSILON);
        assert_eq!(micros, 2);
        assert_eq!(b.spent_micros.load(Ordering::Relaxed), micros);
        assert_eq!(b.per_agent_micros.get(&agent).map(|v| *v), Some(micros));
    }

    #[test]
    fn rehydrate_is_idempotent_and_restores_enforcement() {
        let agent = uuid::Uuid::new_v4();
        let mut snapshot = BudgetUsageSnapshot {
            global_micros: 50_000,
            ..BudgetUsageSnapshot::default()
        };
        snapshot.per_agent_micros.insert(agent, 50_000);
        snapshot
            .per_tenant_micros
            .insert("tenant-a".to_string(), 50_000);
        snapshot.agent_tenants.insert(agent, "tenant-a".to_string());

        let b = BudgetEnforcer::with_limits(1.0, 0.05, 0.05, 0.05);
        b.rehydrate(&snapshot);
        b.rehydrate(&snapshot);

        assert_eq!(b.spent_micros.load(Ordering::Relaxed), 50_000);
        assert_eq!(b.agent_spent_usd(agent), 0.05);
        assert_eq!(b.tenant_spent_usd("tenant-a"), 0.05);
        assert_eq!(b.check(agent).unwrap_err().scope, BudgetScope::Global);
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
