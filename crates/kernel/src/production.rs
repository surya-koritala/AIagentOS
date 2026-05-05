//! Production hardening — circuit breaker, budget enforcement, structured logging.

use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Instant;

/// Circuit breaker — marks a provider as dead after N consecutive failures.
pub struct CircuitBreaker {
    failure_threshold: u32,
    consecutive_failures: AtomicU32,
    state: Mutex<BreakerState>,
    last_failure: Mutex<Option<Instant>>,
    /// Cooldown before retrying a tripped breaker (seconds).
    cooldown_secs: u64,
}

#[derive(Debug, Clone, PartialEq)]
enum BreakerState {
    Closed,    // Normal operation
    Open,      // Failing, reject requests
    HalfOpen,  // Testing if recovered
}

impl CircuitBreaker {
    pub fn new(failure_threshold: u32, cooldown_secs: u64) -> Self {
        Self {
            failure_threshold,
            consecutive_failures: AtomicU32::new(0),
            state: Mutex::new(BreakerState::Closed),
            last_failure: Mutex::new(None),
            cooldown_secs,
        }
    }

    /// Check if requests should be allowed.
    pub fn is_available(&self) -> bool {
        let state = self.state.lock().unwrap();
        match *state {
            BreakerState::Closed => true,
            BreakerState::Open => {
                // Check if cooldown has passed
                if let Some(last) = *self.last_failure.lock().unwrap() {
                    if last.elapsed().as_secs() >= self.cooldown_secs {
                        return true; // Allow one test request (half-open)
                    }
                }
                false
            }
            BreakerState::HalfOpen => true,
        }
    }

    /// Record a successful request.
    pub fn record_success(&self) {
        self.consecutive_failures.store(0, Ordering::SeqCst);
        *self.state.lock().unwrap() = BreakerState::Closed;
    }

    /// Record a failed request.
    pub fn record_failure(&self) {
        let failures = self.consecutive_failures.fetch_add(1, Ordering::SeqCst) + 1;
        *self.last_failure.lock().unwrap() = Some(Instant::now());
        if failures >= self.failure_threshold {
            *self.state.lock().unwrap() = BreakerState::Open;
        }
    }

    /// Get current state info.
    pub fn status(&self) -> (bool, u32) {
        (self.is_available(), self.consecutive_failures.load(Ordering::SeqCst))
    }
}

/// Budget enforcement — stop agent when cost exceeds limit.
pub struct BudgetEnforcer {
    /// Maximum cost in USD (0 = unlimited).
    max_cost_usd: f64,
    current_cost: Mutex<f64>,
}

impl BudgetEnforcer {
    pub fn new(max_cost_usd: f64) -> Self {
        Self { max_cost_usd, current_cost: Mutex::new(0.0) }
    }

    /// Check if budget allows another request.
    pub fn can_proceed(&self) -> bool {
        if self.max_cost_usd <= 0.0 { return true; } // Unlimited
        *self.current_cost.lock().unwrap() < self.max_cost_usd
    }

    /// Record cost from a request.
    pub fn record_cost(&self, cost: f64) {
        *self.current_cost.lock().unwrap() += cost;
    }

    /// Get remaining budget.
    pub fn remaining(&self) -> f64 {
        if self.max_cost_usd <= 0.0 { return f64::INFINITY; }
        self.max_cost_usd - *self.current_cost.lock().unwrap()
    }

    /// Get current spend.
    pub fn current_spend(&self) -> f64 {
        *self.current_cost.lock().unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn circuit_breaker_trips_after_threshold() {
        let cb = CircuitBreaker::new(3, 60);
        assert!(cb.is_available());
        cb.record_failure();
        cb.record_failure();
        assert!(cb.is_available()); // 2 < 3
        cb.record_failure();
        assert!(!cb.is_available()); // 3 >= 3, tripped
    }

    #[test]
    fn circuit_breaker_resets_on_success() {
        let cb = CircuitBreaker::new(3, 60);
        cb.record_failure();
        cb.record_failure();
        cb.record_success();
        assert!(cb.is_available());
        assert_eq!(cb.status().1, 0);
    }

    #[test]
    fn budget_enforcer_blocks_at_limit() {
        let be = BudgetEnforcer::new(1.0);
        assert!(be.can_proceed());
        be.record_cost(0.5);
        assert!(be.can_proceed());
        be.record_cost(0.6);
        assert!(!be.can_proceed()); // 1.1 > 1.0
    }

    #[test]
    fn budget_unlimited() {
        let be = BudgetEnforcer::new(0.0);
        be.record_cost(1000.0);
        assert!(be.can_proceed()); // 0 = unlimited
    }
}
