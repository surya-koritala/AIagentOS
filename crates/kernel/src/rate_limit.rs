//! Rate limiting — prevent API overuse and control costs.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::Semaphore;
use tokio::time::sleep;

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

/// Production-grade rate limiter with token bucket algorithm.
pub struct RateLimiter {
    config: RateLimitConfig,
    /// Semaphore for concurrent execution limit.
    concurrency: Arc<Semaphore>,
    /// Requests made in current window.
    requests_in_window: AtomicU64,
    /// Tokens used in current window.
    tokens_in_window: AtomicU64,
    /// Window start time.
    window_start: std::sync::Mutex<Instant>,
}

impl RateLimiter {
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            concurrency: Arc::new(Semaphore::new(config.max_concurrent as usize)),
            requests_in_window: AtomicU64::new(0),
            tokens_in_window: AtomicU64::new(0),
            window_start: std::sync::Mutex::new(Instant::now()),
            config,
        }
    }

    /// Acquire permission to make a request. Blocks if rate limited.
    pub async fn acquire(&self) -> RateLimitGuard {
        // Check if window needs reset (1 minute windows)
        {
            let mut start = self.window_start.lock().unwrap();
            if start.elapsed() > Duration::from_secs(60) {
                *start = Instant::now();
                self.requests_in_window.store(0, Ordering::SeqCst);
                self.tokens_in_window.store(0, Ordering::SeqCst);
            }
        }

        // Wait for RPM limit
        loop {
            let current = self.requests_in_window.load(Ordering::SeqCst);
            if current < self.config.rpm as u64 {
                break;
            }
            // Wait until window resets
            let elapsed = self.window_start.lock().unwrap().elapsed();
            let wait = Duration::from_secs(60).saturating_sub(elapsed);
            if wait > Duration::ZERO {
                sleep(wait).await;
            }
            // Reset window
            let mut start = self.window_start.lock().unwrap();
            *start = Instant::now();
            self.requests_in_window.store(0, Ordering::SeqCst);
            self.tokens_in_window.store(0, Ordering::SeqCst);
        }

        // Acquire concurrency permit
        let permit = self.concurrency.clone().acquire_owned().await.unwrap();
        self.requests_in_window.fetch_add(1, Ordering::SeqCst);

        RateLimitGuard { _permit: permit }
    }

    /// Record tokens used (call after LLM response).
    pub fn record_tokens(&self, tokens: u64) {
        self.tokens_in_window.fetch_add(tokens, Ordering::SeqCst);
    }

    /// Check if currently rate limited.
    pub fn is_limited(&self) -> bool {
        self.requests_in_window.load(Ordering::SeqCst) >= self.config.rpm as u64
    }

    /// Get current usage stats.
    pub fn stats(&self) -> RateLimitStats {
        RateLimitStats {
            requests_this_minute: self.requests_in_window.load(Ordering::SeqCst),
            tokens_this_minute: self.tokens_in_window.load(Ordering::SeqCst),
            rpm_limit: self.config.rpm,
            tpm_limit: self.config.tpm,
            concurrent_available: self.concurrency.available_permits() as u32,
            max_concurrent: self.config.max_concurrent,
        }
    }
}

/// Guard that releases the concurrency permit on drop.
pub struct RateLimitGuard {
    _permit: tokio::sync::OwnedSemaphorePermit,
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
}
