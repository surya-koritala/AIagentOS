//! Rate limiting — prevent API overuse and control costs.
//!
//! Three independent bounds, all enforced on [`RateLimiter::acquire`]:
//!
//! * **Concurrency** — a counting [`Semaphore`] caps simultaneous in-flight
//!   requests at `max_concurrent`. A permit is held for the lifetime of the
//!   returned [`RateLimitGuard`] and released on drop. Using a semaphore (not
//!   `Notify`) sidesteps lost-wakeup bugs: a permit returned before a waiter
//!   registers is still observed, because the permit count is durable state.
//! * **Requests / minute (RPM)** — a counter over a one-minute window.
//! * **Tokens / minute (TPM)** — a counter over the same window. Callers
//!   reserve an estimate up front during `acquire` and reconcile the true cost
//!   afterwards with [`RateLimiter::record_tokens`].
//!
//! The window counters and the window start instant live behind a single mutex
//! ([`WindowState`]) so the *check-and-reserve* step is atomic. This closes the
//! time-of-check/time-of-use race the previous lock-free version had, where two
//! callers could both observe `requests < rpm` and then both increment past the
//! cap. RPM/TPM waiting is a bounded poll loop (sleep then re-check) rather than
//! an edge-triggered notification, so a caller can never miss a window rollover.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::Semaphore;
use tokio::time::sleep;

/// Length of the rate-limit accounting window.
const WINDOW: Duration = Duration::from_secs(60);
/// Upper bound on any single poll-wait, so a caller re-checks the window
/// promptly after a rollover even when its computed wait was longer.
const MAX_POLL_WAIT: Duration = Duration::from_millis(250);

/// Rate limiter configuration.
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Max requests per minute.
    pub rpm: u32,
    /// Max tokens per minute.
    pub tpm: u64,
    /// Max concurrent agent executions.
    pub max_concurrent: u32,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            rpm: 60,
            tpm: 100_000,
            max_concurrent: 3,
        }
    }
}

/// Mutable per-window accounting, guarded as a single unit so reservation is
/// atomic with respect to the window rollover.
#[derive(Debug)]
struct WindowState {
    start: Instant,
    generation: u64,
    requests: u64,
    tokens: u64,
}

impl WindowState {
    /// Reset the window if it has expired. Returns the remaining time until the
    /// current window ends (zero if it just rolled over).
    fn roll_if_expired(&mut self) -> Duration {
        let elapsed = self.start.elapsed();
        if elapsed >= WINDOW {
            self.start = Instant::now();
            self.generation = self.generation.saturating_add(1);
            self.requests = 0;
            self.tokens = 0;
            WINDOW
        } else {
            WINDOW - elapsed
        }
    }
}

/// Production-grade rate limiter (token-bucket-style windowed counters plus a
/// concurrency semaphore).
pub struct RateLimiter {
    config: RateLimitConfig,
    /// Semaphore for the concurrent execution limit.
    concurrency: Arc<Semaphore>,
    /// Windowed request/token accounting (single mutex → atomic reserve).
    window: Arc<Mutex<WindowState>>,
}

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum RateLimitError {
    #[error("request estimate {requested} tokens exceeds configured TPM limit {limit}")]
    RequestExceedsTpm { requested: u64, limit: u64 },
}

impl RateLimiter {
    pub fn new(config: RateLimitConfig) -> Self {
        let permits = if config.max_concurrent == 0 {
            Semaphore::MAX_PERMITS
        } else {
            config.max_concurrent as usize
        };
        Self {
            concurrency: Arc::new(Semaphore::new(permits)),
            window: Arc::new(Mutex::new(WindowState {
                start: Instant::now(),
                generation: 0,
                requests: 0,
                tokens: 0,
            })),
            config,
        }
    }

    /// Acquire permission to make a request, reserving one request slot. Blocks
    /// until both the RPM bound has room and a concurrency permit is free.
    pub async fn acquire(&self) -> RateLimitGuard {
        self.acquire_tokens(0)
            .await
            .expect("a zero-token reservation always fits")
    }

    /// Like [`acquire`](Self::acquire) but also reserves `est_tokens` against
    /// the TPM bound up front. The reservation is corrected once the true cost
    /// is known via [`record_tokens`](Self::record_tokens).
    pub async fn acquire_tokens(&self, est_tokens: u64) -> Result<RateLimitGuard, RateLimitError> {
        if self.config.tpm > 0 && est_tokens > self.config.tpm {
            return Err(RateLimitError::RequestExceedsTpm {
                requested: est_tokens,
                limit: self.config.tpm,
            });
        }
        // Phase 1: reserve an RPM (and TPM) slot atomically, polling across
        // window rollovers. We loop because the reservation may have to wait
        // for the current window to expire.
        let generation = loop {
            let wait = {
                let mut w = self.window.lock().unwrap();
                let remaining = w.roll_if_expired();

                let rpm_ok = self.config.rpm == 0 || w.requests < self.config.rpm as u64;
                let tpm_ok =
                    self.config.tpm == 0 || w.tokens.saturating_add(est_tokens) <= self.config.tpm;

                if rpm_ok && tpm_ok {
                    w.requests = w.requests.saturating_add(1);
                    w.tokens = w.tokens.saturating_add(est_tokens);
                    Ok(w.generation)
                } else {
                    // Wait for the window to roll over, bounded so we re-poll
                    // soon after the rollover instant.
                    Err(remaining.min(MAX_POLL_WAIT))
                }
            };

            match wait {
                Ok(generation) => break generation,
                Err(d) if d > Duration::ZERO => sleep(d).await,
                Err(_) => {
                    // Window just expired but another caller may race us to the
                    // reset; yield and re-check immediately.
                    tokio::task::yield_now().await;
                }
            }
        };

        // Phase 2: acquire a concurrency permit. Held until the guard drops.
        let permit = self.concurrency.clone().acquire_owned().await.unwrap();
        Ok(RateLimitGuard {
            _permit: permit,
            window: self.window.clone(),
            generation,
            reserved_tokens: est_tokens,
        })
    }

    /// Record tokens actually used (call after the LLM response). This is the
    /// reconciliation against any up-front estimate reserved in `acquire_tokens`.
    pub fn record_tokens(&self, tokens: u64) {
        let mut w = self.window.lock().unwrap();
        w.roll_if_expired();
        w.tokens = w.tokens.saturating_add(tokens);
    }

    /// Check if currently at or above the RPM bound.
    pub fn is_limited(&self) -> bool {
        let w = self.window.lock().unwrap();
        w.requests >= self.config.rpm as u64
    }

    /// Get current usage stats.
    pub fn stats(&self) -> RateLimitStats {
        let w = self.window.lock().unwrap();
        RateLimitStats {
            requests_this_minute: w.requests,
            tokens_this_minute: w.tokens,
            rpm_limit: self.config.rpm,
            tpm_limit: self.config.tpm,
            concurrent_available: if self.config.max_concurrent == 0 {
                0
            } else {
                self.concurrency.available_permits() as u32
            },
            max_concurrent: self.config.max_concurrent,
        }
    }
}

/// Guard that releases the concurrency permit on drop.
pub struct RateLimitGuard {
    _permit: tokio::sync::OwnedSemaphorePermit,
    window: Arc<Mutex<WindowState>>,
    generation: u64,
    reserved_tokens: u64,
}

impl RateLimitGuard {
    /// Replace the up-front token estimate with provider-reported or
    /// conservatively estimated actual usage. If the minute rolled while the
    /// request was in flight, actual usage is charged to the new window.
    pub fn reconcile(self, actual_tokens: u64) {
        let mut window = self.window.lock().unwrap();
        window.roll_if_expired();
        if window.generation == self.generation {
            window.tokens = window
                .tokens
                .saturating_sub(self.reserved_tokens)
                .saturating_add(actual_tokens);
        } else {
            window.tokens = window.tokens.saturating_add(actual_tokens);
        }
    }
}

/// Current rate limit statistics.
#[derive(Debug, Clone)]
pub struct RateLimitStats {
    pub requests_this_minute: u64,
    pub tokens_this_minute: u64,
    pub rpm_limit: u32,
    pub tpm_limit: u64,
    pub concurrent_available: u32,
    pub max_concurrent: u32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    #[tokio::test]
    async fn acquire_within_limits() {
        let limiter = RateLimiter::new(RateLimitConfig {
            rpm: 10,
            tpm: 1000,
            max_concurrent: 3,
        });
        let _guard = limiter.acquire().await;
        assert_eq!(limiter.stats().requests_this_minute, 1);
        assert_eq!(limiter.stats().concurrent_available, 2);
    }

    #[tokio::test]
    async fn concurrency_limit() {
        let limiter = Arc::new(RateLimiter::new(RateLimitConfig {
            rpm: 100,
            tpm: 100000,
            max_concurrent: 2,
        }));
        let _g1 = limiter.acquire().await;
        let _g2 = limiter.acquire().await;
        assert_eq!(limiter.stats().concurrent_available, 0);
        // Third acquire would block — test that stats reflect it
        assert_eq!(limiter.stats().requests_this_minute, 2);
    }

    #[tokio::test]
    async fn record_tokens() {
        let limiter = RateLimiter::new(RateLimitConfig::default());
        limiter.record_tokens(500);
        limiter.record_tokens(300);
        assert_eq!(limiter.stats().tokens_this_minute, 800);
    }

    #[tokio::test]
    async fn is_limited_when_at_cap() {
        let limiter = RateLimiter::new(RateLimitConfig {
            rpm: 2,
            tpm: 1000,
            max_concurrent: 10,
        });
        let _g1 = limiter.acquire().await;
        let _g2 = limiter.acquire().await;
        assert!(limiter.is_limited());
    }

    /// The concurrency bound holds under many simultaneous callers: at no point
    /// may more than `max_concurrent` guards be live at once.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrency_bound_holds_under_load() {
        let max_concurrent = 3u32;
        let limiter = Arc::new(RateLimiter::new(RateLimitConfig {
            rpm: 10_000,
            tpm: 10_000_000,
            max_concurrent,
        }));
        let live = Arc::new(AtomicU32::new(0));
        let peak = Arc::new(AtomicU32::new(0));

        let mut handles = Vec::new();
        for _ in 0..64 {
            let limiter = limiter.clone();
            let live = live.clone();
            let peak = peak.clone();
            handles.push(tokio::spawn(async move {
                let _g = limiter.acquire().await;
                let now = live.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(now, Ordering::SeqCst);
                // Hold the slot briefly to force contention.
                tokio::time::sleep(Duration::from_millis(5)).await;
                live.fetch_sub(1, Ordering::SeqCst);
            }));
        }
        for h in handles {
            h.await.unwrap();
        }

        assert!(
            peak.load(Ordering::SeqCst) <= max_concurrent,
            "observed {} concurrent, bound was {}",
            peak.load(Ordering::SeqCst),
            max_concurrent
        );
        // All slots released.
        assert_eq!(limiter.stats().concurrent_available, max_concurrent);
    }

    /// The RPM bound holds under concurrent reservation: with rpm set below the
    /// number of callers, only `rpm` requests get admitted within the window.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn rpm_bound_holds_under_load() {
        let rpm = 5u32;
        let limiter = Arc::new(RateLimiter::new(RateLimitConfig {
            rpm,
            tpm: 10_000_000,
            max_concurrent: 32,
        }));

        // Spawn more callers than the RPM budget; the excess must block on the
        // window (and not get admitted within this short window).
        let mut handles = Vec::new();
        for _ in 0..20 {
            let limiter = limiter.clone();
            handles.push(tokio::spawn(async move {
                // Don't await admission to completion for the blocked ones —
                // race them against a short timeout. Admitted callers reserve a
                // slot synchronously inside acquire before returning.
                let _ = tokio::time::timeout(Duration::from_millis(50), limiter.acquire_tokens(1))
                    .await;
            }));
        }
        for h in handles {
            h.await.unwrap();
        }

        // Exactly `rpm` requests may have been admitted in this window.
        assert_eq!(
            limiter.stats().requests_this_minute,
            rpm as u64,
            "more than rpm requests admitted in one window"
        );
    }

    /// TPM reservation blocks once the token budget for the window is consumed.
    #[tokio::test]
    async fn tpm_bound_blocks_when_exhausted() {
        let limiter = Arc::new(RateLimiter::new(RateLimitConfig {
            rpm: 1000,
            tpm: 100,
            max_concurrent: 10,
        }));
        // Reserve the whole token budget.
        let _g = limiter.acquire_tokens(100).await.unwrap();
        assert_eq!(limiter.stats().tokens_this_minute, 100);

        // A further reservation that would exceed TPM must block (times out).
        let res = tokio::time::timeout(Duration::from_millis(50), limiter.acquire_tokens(1)).await;
        assert!(res.is_err(), "reservation should have blocked on TPM");
    }

    #[tokio::test]
    async fn oversized_request_is_rejected_instead_of_waiting_forever() {
        let limiter = RateLimiter::new(RateLimitConfig {
            rpm: 10,
            tpm: 100,
            max_concurrent: 1,
        });
        let error = match limiter.acquire_tokens(101).await {
            Ok(_) => panic!("oversized reservation unexpectedly admitted"),
            Err(error) => error,
        };
        assert_eq!(
            error,
            RateLimitError::RequestExceedsTpm {
                requested: 101,
                limit: 100
            }
        );
    }

    #[tokio::test]
    async fn zero_limits_are_explicitly_unlimited() {
        let limiter = RateLimiter::new(RateLimitConfig {
            rpm: 0,
            tpm: 0,
            max_concurrent: 0,
        });
        let guard = limiter.acquire_tokens(u64::MAX).await.unwrap();
        guard.reconcile(u64::MAX);
        let stats = limiter.stats();
        assert_eq!(stats.requests_this_minute, 1);
        assert_eq!(stats.tokens_this_minute, u64::MAX);
        assert_eq!(stats.rpm_limit, 0);
        assert_eq!(stats.tpm_limit, 0);
        assert_eq!(stats.max_concurrent, 0);
    }

    #[tokio::test]
    async fn provider_actual_usage_replaces_reservation() {
        let limiter = RateLimiter::new(RateLimitConfig {
            rpm: 10,
            tpm: 1_000,
            max_concurrent: 1,
        });
        let guard = limiter.acquire_tokens(300).await.unwrap();
        assert_eq!(limiter.stats().tokens_this_minute, 300);
        guard.reconcile(125);
        assert_eq!(limiter.stats().tokens_this_minute, 125);
    }
}
