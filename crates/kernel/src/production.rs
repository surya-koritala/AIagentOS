//! Production hardening — circuit breaker, budget enforcement, structured logging.

use std::sync::atomic::{AtomicU32, Ordering};
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
#[allow(dead_code)]
enum BreakerState {
    Closed,   // Normal operation
    Open,     // Failing, reject requests
    HalfOpen, // Testing if recovered
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
        let mut state = self.state.lock().unwrap();
        match *state {
            BreakerState::Closed => true,
            BreakerState::Open => {
                if let Some(last) = *self.last_failure.lock().unwrap() {
                    if last.elapsed().as_secs() >= self.cooldown_secs {
                        // Only this caller owns the single recovery probe.
                        *state = BreakerState::HalfOpen;
                        return true;
                    }
                }
                false
            }
            BreakerState::HalfOpen => false,
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
        // Keep the same lock order as `is_available`: state, then timestamp.
        let mut state = self.state.lock().unwrap();
        *self.last_failure.lock().unwrap() = Some(Instant::now());
        if failures >= self.failure_threshold {
            *state = BreakerState::Open;
        }
    }

    /// Get current state info.
    pub fn status(&self) -> (bool, u32) {
        let state = self.state.lock().unwrap();
        let available = match *state {
            BreakerState::Closed => true,
            BreakerState::HalfOpen => false,
            BreakerState::Open => self
                .last_failure
                .lock()
                .unwrap()
                .is_some_and(|last| last.elapsed().as_secs() >= self.cooldown_secs),
        };
        (available, self.consecutive_failures.load(Ordering::SeqCst))
    }
}

// Budget enforcement lives in [`crate::budget::BudgetEnforcer`] — the live,
// token-priced, per-agent enforcer wired into the execution loop. The earlier
// global-only stub that lived here was consolidated into it (#44).

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
    fn circuit_breaker_allows_exactly_one_half_open_probe() {
        let cb = CircuitBreaker::new(1, 0);
        cb.record_failure();
        assert!(cb.is_available());
        assert!(!cb.is_available());
        cb.record_success();
        assert!(cb.is_available());
    }
}
