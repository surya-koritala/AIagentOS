//! Clock primitives for fixed, durable quota epochs.
//!
//! Quota accounting uses half-open Unix-minute epochs: millisecond `0` through
//! `59_999` belong to epoch `0`, and millisecond `60_000` starts epoch `1`.
//! Keeping the clock behind this small trait makes boundary and clock-skew
//! behavior deterministic in tests.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::Notify;

/// Length of one fixed quota epoch in milliseconds.
pub const QUOTA_EPOCH_MILLIS: u64 = 60_000;

/// Return the fixed Unix-minute epoch containing `unix_millis`.
#[inline]
pub const fn quota_epoch(unix_millis: u64) -> u64 {
    unix_millis / QUOTA_EPOCH_MILLIS
}

/// Source of Unix time used to select a quota epoch.
#[async_trait::async_trait]
pub trait QuotaClock: Send + Sync {
    fn now_unix_millis(&self) -> u64;

    /// Wait until `deadline_unix_millis`.
    ///
    /// Production maps the wall-clock deadline to a Tokio duration. Manual
    /// clocks wake from [`ManualQuotaClock::set`] and
    /// [`ManualQuotaClock::advance`], keeping boundary tests free of real
    /// minute-long sleeps.
    async fn sleep_until(&self, deadline_unix_millis: u64);
}

/// Production wall clock that never moves backwards during this process.
///
/// Fixed Unix epochs need wall time so separate processes agree after a
/// restart. The atomic high-water mark protects a running process from an NTP
/// or administrator clock correction accidentally reopening an older epoch.
#[derive(Debug, Default)]
pub struct SystemQuotaClock {
    last_seen_millis: AtomicU64,
}

impl SystemQuotaClock {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait::async_trait]
impl QuotaClock for SystemQuotaClock {
    fn now_unix_millis(&self) -> u64 {
        let observed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
            .min(u128::from(u64::MAX)) as u64;

        self.last_seen_millis
            .fetch_max(observed, Ordering::AcqRel)
            .max(observed)
    }

    async fn sleep_until(&self, deadline_unix_millis: u64) {
        loop {
            let delay = deadline_unix_millis.saturating_sub(self.now_unix_millis());
            if delay == 0 {
                return;
            }
            // Recheck wall time promptly so an NTP/admin forward correction
            // does not make admissions wait for the old full duration.
            tokio::time::sleep(std::time::Duration::from_millis(delay.min(250))).await;
        }
    }
}

/// Deterministic clock for quota tests.
///
/// `set` intentionally permits backwards movement so tests can verify the
/// durable store's epoch high-water mark. Production code should use
/// [`SystemQuotaClock`].
#[derive(Debug)]
pub struct ManualQuotaClock {
    unix_millis: AtomicU64,
    changed: Notify,
}

impl ManualQuotaClock {
    pub fn new(unix_millis: u64) -> Self {
        Self {
            unix_millis: AtomicU64::new(unix_millis),
            changed: Notify::new(),
        }
    }

    pub fn set(&self, unix_millis: u64) {
        self.unix_millis.store(unix_millis, Ordering::Release);
        self.changed.notify_waiters();
    }

    pub fn advance(&self, millis: u64) -> u64 {
        let previous = self
            .unix_millis
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                Some(current.saturating_add(millis))
            })
            .unwrap_or_else(|current| current);
        let current = previous.saturating_add(millis);
        self.changed.notify_waiters();
        current
    }
}

#[async_trait::async_trait]
impl QuotaClock for ManualQuotaClock {
    fn now_unix_millis(&self) -> u64 {
        self.unix_millis.load(Ordering::Acquire)
    }

    async fn sleep_until(&self, deadline_unix_millis: u64) {
        loop {
            // Register before checking the time so a concurrent advance cannot
            // be lost between the condition check and awaiting notification.
            let changed = self.changed.notified();
            if self.now_unix_millis() >= deadline_unix_millis {
                return;
            }
            changed.await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unix_minute_epochs_are_half_open() {
        assert_eq!(quota_epoch(0), 0);
        assert_eq!(quota_epoch(59_999), 0);
        assert_eq!(quota_epoch(60_000), 1);
        assert_eq!(quota_epoch(119_999), 1);
        assert_eq!(quota_epoch(120_000), 2);
    }

    #[test]
    fn manual_clock_can_model_forward_and_backward_corrections() {
        let clock = ManualQuotaClock::new(59_999);
        assert_eq!(clock.now_unix_millis(), 59_999);
        assert_eq!(clock.advance(1), 60_000);
        clock.set(1_000);
        assert_eq!(clock.now_unix_millis(), 1_000);
    }

    #[tokio::test]
    async fn manual_sleep_wakes_at_exact_boundary() {
        let clock = std::sync::Arc::new(ManualQuotaClock::new(59_999));
        let waiter = {
            let clock = clock.clone();
            tokio::spawn(async move { clock.sleep_until(60_000).await })
        };
        tokio::task::yield_now().await;
        assert!(!waiter.is_finished());
        clock.advance(1);
        waiter.await.unwrap();
    }

    #[test]
    fn manual_advance_saturates_without_wrapping_storage() {
        let clock = ManualQuotaClock::new(u64::MAX - 1);
        assert_eq!(clock.advance(10), u64::MAX);
        assert_eq!(clock.now_unix_millis(), u64::MAX);
    }
}
