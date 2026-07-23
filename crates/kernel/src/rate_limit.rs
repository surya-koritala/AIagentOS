//! Durable provider rate limiting.
//!
//! RPM and TPM are committed atomically in the context store against fixed,
//! half-open Unix-minute epochs. A reservation has an explicit lifecycle:
//! before provider I/O it is refundable; immediately before I/O it is marked
//! invoked; after invocation, cancellation/failure retains the estimate; and a
//! successful response reconciles actual usage in the original admission
//! epoch. The concurrency permit is process-local and is always acquired before
//! a durable reservation, so cancellation while waiting cannot leak quota.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use tokio::sync::{watch, OwnedSemaphorePermit, Semaphore};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::context::{
    CgroupQuotaConstraint, ProviderRateLimitDimension, ProviderRateReceiptState,
    ProviderRateReservation, ProviderRateReserveOutcome, QuotaScopeKind, SqliteContextManager,
};
use crate::quota_clock::{quota_epoch, QuotaClock, SystemQuotaClock, QUOTA_EPOCH_MILLIS};
use crate::ContextError;

/// Rate limiter configuration.
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Maximum requests in one fixed Unix-minute epoch. Zero is unlimited.
    pub rpm: u32,
    /// Maximum estimated/actual tokens in one fixed Unix-minute epoch. Zero is
    /// unlimited.
    pub tpm: u64,
    /// Maximum simultaneous provider calls. Zero is unlimited.
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

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum RateLimitError {
    #[error("request estimate {requested} tokens exceeds configured TPM limit {limit}")]
    RequestExceedsTpm { requested: u64, limit: u64 },

    #[error(
        "request estimate {requested} tokens exceeds cgroup scope {scope_id:?} TPM limit {limit}"
    )]
    RequestExceedsCgroupTpm {
        scope_id: String,
        requested: u64,
        limit: u64,
    },

    #[error(
        "{scope_kind} quota exhausted for scope {scope_id:?} ({dimension}): used {used}, requested {requested}, limit {limit}; retry at Unix millisecond {retry_at_unix_ms}"
    )]
    QuotaExhausted {
        scope_kind: String,
        scope_id: String,
        dimension: String,
        used: u64,
        requested: u64,
        limit: u64,
        retry_at_unix_ms: u64,
    },

    #[error("provider rate-limit admission was cancelled")]
    Cancelled,

    #[error("cgroup membership changed during provider rate-limit admission")]
    CgroupMembershipChanged,

    #[error("provider rate-limit concurrency semaphore closed")]
    ConcurrencyClosed,

    #[error("durable provider rate-limit accounting is unavailable: {0}")]
    StorageUnavailable(String),

    #[error("provider rate-limit guard must be marked invoked before reconciliation")]
    NotInvoked,

    #[error("provider rate-limit reservation cannot be refunded after invocation")]
    AlreadyInvoked,
}

/// Durable fixed-epoch rate limiter plus a process-local concurrency bound.
pub struct RateLimiter {
    config: RateLimitConfig,
    concurrency: Arc<Semaphore>,
    store: Arc<SqliteContextManager>,
    clock: Arc<dyn QuotaClock>,
    healthy: Arc<AtomicBool>,
    capacity_changed: watch::Sender<u64>,
    last_pruned_epoch: AtomicU64,
    denied_provider_requests: AtomicU64,
    denied_provider_tokens: AtomicU64,
    denied_cgroup_requests: AtomicU64,
    denied_cgroup_tokens: AtomicU64,
    denied_migration_fence: AtomicU64,
}

impl RateLimiter {
    /// Construct a limiter with a private in-memory durable store.
    ///
    /// This preserves the historical convenience constructor for tests and
    /// embedders. Production kernels should use [`with_store`](Self::with_store)
    /// so quota survives restart.
    pub fn new(config: RateLimitConfig) -> Self {
        let store = Arc::new(
            SqliteContextManager::in_memory()
                .expect("creating the private in-memory rate-limit store must succeed"),
        );
        Self::with_store(config, store, Arc::new(SystemQuotaClock::new()))
            .expect("recovering a new in-memory rate-limit store must succeed")
    }

    /// Construct a limiter over the kernel's persistent context store.
    ///
    /// Recovery atomically refunds reservations for calls that provably never
    /// started and retains estimates for calls that may have reached a provider.
    pub fn with_store(
        config: RateLimitConfig,
        store: Arc<SqliteContextManager>,
        clock: Arc<dyn QuotaClock>,
    ) -> Result<Self, RateLimitError> {
        let requested_epoch = quota_epoch(clock.now_unix_millis());
        let recovery = store
            .recover_provider_rate_state(requested_epoch)
            .map_err(Self::storage_error)?;
        store
            .prune_provider_rate_epochs(recovery.effective_epoch)
            .map_err(Self::storage_error)?;

        let permits = if config.max_concurrent == 0 {
            Semaphore::MAX_PERMITS
        } else {
            config.max_concurrent as usize
        };
        let (capacity_changed, _) = watch::channel(0);
        Ok(Self {
            config,
            concurrency: Arc::new(Semaphore::new(permits)),
            store,
            clock,
            healthy: Arc::new(AtomicBool::new(true)),
            capacity_changed,
            last_pruned_epoch: AtomicU64::new(recovery.effective_epoch),
            denied_provider_requests: AtomicU64::new(0),
            denied_provider_tokens: AtomicU64::new(0),
            denied_cgroup_requests: AtomicU64::new(0),
            denied_cgroup_tokens: AtomicU64::new(0),
            denied_migration_fence: AtomicU64::new(0),
        })
    }

    fn storage_error(error: ContextError) -> RateLimitError {
        RateLimitError::StorageUnavailable(error.to_string())
    }

    fn poison(&self, error: ContextError) -> RateLimitError {
        self.healthy.store(false, Ordering::Release);
        Self::storage_error(error)
    }

    fn ensure_healthy(&self) -> Result<(), RateLimitError> {
        if self.healthy.load(Ordering::Acquire) {
            Ok(())
        } else {
            Err(RateLimitError::StorageUnavailable(
                "a prior persistence operation failed; restart and recover before admitting work"
                    .into(),
            ))
        }
    }

    fn prune_if_epoch_advanced(&self, effective_epoch: u64) -> Result<(), RateLimitError> {
        if effective_epoch <= self.last_pruned_epoch.load(Ordering::Acquire) {
            return Ok(());
        }
        self.store
            .prune_provider_rate_epochs(effective_epoch)
            .map_err(|error| self.poison(error))?;
        self.last_pruned_epoch
            .fetch_max(effective_epoch, Ordering::AcqRel);
        Ok(())
    }

    fn record_denial(&self, scope_kind: QuotaScopeKind, dimension: ProviderRateLimitDimension) {
        let counter = match (scope_kind, dimension) {
            (QuotaScopeKind::Provider, ProviderRateLimitDimension::Requests) => {
                &self.denied_provider_requests
            }
            (QuotaScopeKind::Provider, ProviderRateLimitDimension::Tokens) => {
                &self.denied_provider_tokens
            }
            (QuotaScopeKind::Cgroup, ProviderRateLimitDimension::Tokens) => {
                &self.denied_cgroup_tokens
            }
            (_, ProviderRateLimitDimension::MigrationFence) => &self.denied_migration_fence,
            (QuotaScopeKind::Cgroup, ProviderRateLimitDimension::Requests) => {
                &self.denied_cgroup_requests
            }
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    /// Backwards-compatible admitted request.
    ///
    /// Historical callers treated return from `acquire` as the attempted
    /// provider call. Therefore this wrapper marks the receipt invoked before
    /// returning. New execution code should use
    /// [`acquire_tokens_cancellable`](Self::acquire_tokens_cancellable) and mark
    /// the guard immediately before adapter I/O.
    pub async fn acquire(&self) -> RateLimitGuard {
        self.acquire_tokens(0)
            .await
            .expect("provider rate-limit admission failed")
    }

    /// Backwards-compatible admitted request with an up-front TPM estimate.
    pub async fn acquire_tokens(
        &self,
        estimated_tokens: u64,
    ) -> Result<RateLimitGuard, RateLimitError> {
        let cancellation = CancellationToken::new();
        let mut guard = self
            .acquire_tokens_cancellable(estimated_tokens, &cancellation)
            .await?;
        guard.mark_invoked()?;
        Ok(guard)
    }

    /// Reserve a request cancellably without yet declaring provider I/O.
    ///
    /// Callers must invoke [`RateLimitGuard::mark_invoked`] immediately before
    /// adapter use. Dropping before that point refunds RPM/TPM; dropping after
    /// it retains the estimate.
    pub async fn acquire_tokens_cancellable(
        &self,
        estimated_tokens: u64,
        cancellation: &CancellationToken,
    ) -> Result<RateLimitGuard, RateLimitError> {
        self.acquire_tokens_with_cgroups_cancellable(estimated_tokens, &[], None, cancellation)
            .await
    }

    /// Atomically reserve provider/global capacity and every stable root-to-leaf
    /// cgroup token scope for this provider attempt.
    ///
    /// A cgroup consumes tokens but not an additional request count. The
    /// returned affine guard refunds, retains, and reconciles all scopes as one
    /// durable receipt.
    pub(crate) async fn acquire_tokens_with_cgroups_cancellable(
        &self,
        estimated_tokens: u64,
        cgroups: &[CgroupQuotaConstraint],
        membership_changes: Option<(&mut watch::Receiver<u64>, u64)>,
        cancellation: &CancellationToken,
    ) -> Result<RateLimitGuard, RateLimitError> {
        self.acquire_tokens_with_cgroups_cancellable_inner(
            estimated_tokens,
            cgroups,
            membership_changes,
            cancellation,
            true,
        )
        .await
    }

    /// Attempt one execution-path admission without waiting for the next quota
    /// epoch. Exhaustion returns retryable structured backpressure immediately,
    /// so a quota-blocked turn cannot occupy global turn admission and starve
    /// an independently funded cgroup.
    pub(crate) async fn try_acquire_tokens_with_cgroups_cancellable(
        &self,
        estimated_tokens: u64,
        cgroups: &[CgroupQuotaConstraint],
        membership_changes: Option<(&mut watch::Receiver<u64>, u64)>,
        cancellation: &CancellationToken,
    ) -> Result<RateLimitGuard, RateLimitError> {
        self.acquire_tokens_with_cgroups_cancellable_inner(
            estimated_tokens,
            cgroups,
            membership_changes,
            cancellation,
            false,
        )
        .await
    }

    async fn acquire_tokens_with_cgroups_cancellable_inner(
        &self,
        estimated_tokens: u64,
        cgroups: &[CgroupQuotaConstraint],
        mut membership_changes: Option<(&mut watch::Receiver<u64>, u64)>,
        cancellation: &CancellationToken,
        wait_for_capacity: bool,
    ) -> Result<RateLimitGuard, RateLimitError> {
        if Self::cgroup_membership_changed(&membership_changes) {
            return Err(RateLimitError::CgroupMembershipChanged);
        }
        if self.config.tpm > 0 && estimated_tokens > self.config.tpm {
            self.denied_provider_tokens.fetch_add(1, Ordering::Relaxed);
            return Err(RateLimitError::RequestExceedsTpm {
                requested: estimated_tokens,
                limit: self.config.tpm,
            });
        }
        if let Some(constraint) = cgroups.iter().find(|constraint| {
            constraint.token_limit > 0 && estimated_tokens > constraint.token_limit
        }) {
            if Self::cgroup_membership_changed(&membership_changes) {
                return Err(RateLimitError::CgroupMembershipChanged);
            }
            self.denied_cgroup_tokens.fetch_add(1, Ordering::Relaxed);
            return Err(RateLimitError::RequestExceedsCgroupTpm {
                scope_id: constraint.scope_id.clone(),
                requested: estimated_tokens,
                limit: constraint.token_limit,
            });
        }
        if cancellation.is_cancelled() {
            return Err(RateLimitError::Cancelled);
        }

        // Subscribe before the first reservation attempt. A refund or lower
        // reconciliation between a denial and the wait below is retained as an
        // unseen watch version, so the wakeup cannot be lost.
        let mut capacity_changed = self.capacity_changed.subscribe();
        loop {
            self.ensure_healthy()?;
            if cancellation.is_cancelled() {
                return Err(RateLimitError::Cancelled);
            }
            if Self::cgroup_membership_changed(&membership_changes) {
                return Err(RateLimitError::CgroupMembershipChanged);
            }

            // Acquire concurrency first. If cancellation wins, no durable
            // receipt exists and therefore nothing can leak.
            let permit = if let Some((receiver, _)) = membership_changes.as_mut() {
                tokio::select! {
                    biased;
                    _ = cancellation.cancelled() => return Err(RateLimitError::Cancelled),
                    changed = receiver.changed() => {
                        let _ = changed;
                        return Err(RateLimitError::CgroupMembershipChanged);
                    }
                    permit = self.concurrency.clone().acquire_owned() => {
                        permit.map_err(|_| RateLimitError::ConcurrencyClosed)?
                    }
                }
            } else {
                tokio::select! {
                    biased;
                    _ = cancellation.cancelled() => return Err(RateLimitError::Cancelled),
                    permit = self.concurrency.clone().acquire_owned() => {
                        permit.map_err(|_| RateLimitError::ConcurrencyClosed)?
                    }
                }
            };
            if cancellation.is_cancelled() {
                drop(permit);
                return Err(RateLimitError::Cancelled);
            }
            if Self::cgroup_membership_changed(&membership_changes) {
                drop(permit);
                return Err(RateLimitError::CgroupMembershipChanged);
            }

            let requested_epoch = quota_epoch(self.clock.now_unix_millis());
            let receipt_id = Uuid::new_v4();
            let outcome = self
                .store
                .reserve_provider_rate_with_cgroups(
                    receipt_id,
                    requested_epoch,
                    self.config.rpm,
                    self.config.tpm,
                    estimated_tokens,
                    cgroups,
                )
                .map_err(|error| self.poison(error))?;

            match outcome {
                ProviderRateReserveOutcome::Reserved(reservation) => {
                    let guard = RateLimitGuard {
                        permit: Some(permit),
                        store: self.store.clone(),
                        healthy: self.healthy.clone(),
                        capacity_changed: self.capacity_changed.clone(),
                        reservation: Some(reservation),
                        invoked: false,
                    };
                    self.prune_if_epoch_advanced(guard.admission_epoch())?;
                    if cancellation.is_cancelled() {
                        guard.refund()?;
                        return Err(RateLimitError::Cancelled);
                    }
                    if Self::cgroup_membership_changed(&membership_changes) {
                        guard.refund()?;
                        return Err(RateLimitError::CgroupMembershipChanged);
                    }
                    return Ok(guard);
                }
                ProviderRateReserveOutcome::Denied {
                    epoch,
                    scope,
                    dimension,
                    used,
                    requested,
                    limit,
                } => {
                    self.record_denial(scope.kind.clone(), dimension);
                    self.prune_if_epoch_advanced(epoch)?;
                    // Quota denial has no receipt. Release concurrency while
                    // waiting so admitted work in other epochs cannot starve.
                    drop(permit);
                    let deadline = epoch.saturating_add(1).saturating_mul(QUOTA_EPOCH_MILLIS);
                    if !wait_for_capacity {
                        let scope_kind = match scope.kind {
                            QuotaScopeKind::Provider => "provider",
                            QuotaScopeKind::Cgroup => "cgroup",
                        };
                        let dimension = match dimension {
                            ProviderRateLimitDimension::Requests => "requests",
                            ProviderRateLimitDimension::Tokens => "tokens",
                            ProviderRateLimitDimension::MigrationFence => "migration_fence",
                        };
                        return Err(RateLimitError::QuotaExhausted {
                            scope_kind: scope_kind.into(),
                            scope_id: scope.id,
                            dimension: dimension.into(),
                            used,
                            requested,
                            limit,
                            retry_at_unix_ms: deadline,
                        });
                    }
                    if let Some((receiver, _)) = membership_changes.as_mut() {
                        tokio::select! {
                            biased;
                            _ = cancellation.cancelled() => {
                                return Err(RateLimitError::Cancelled);
                            }
                            changed = receiver.changed() => {
                                let _ = changed;
                                return Err(RateLimitError::CgroupMembershipChanged);
                            }
                            _ = self.clock.sleep_until(deadline) => {}
                            changed = capacity_changed.changed() => {
                                if changed.is_err() {
                                    return Err(RateLimitError::StorageUnavailable(
                                        "provider rate-limit capacity notifier closed".into(),
                                    ));
                                }
                            }
                        }
                    } else {
                        tokio::select! {
                            biased;
                            _ = cancellation.cancelled() => {
                                return Err(RateLimitError::Cancelled);
                            }
                            _ = self.clock.sleep_until(deadline) => {}
                            changed = capacity_changed.changed() => {
                                if changed.is_err() {
                                    return Err(RateLimitError::StorageUnavailable(
                                        "provider rate-limit capacity notifier closed".into(),
                                    ));
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    fn cgroup_membership_changed(
        membership_changes: &Option<(&mut watch::Receiver<u64>, u64)>,
    ) -> bool {
        membership_changes
            .as_ref()
            .is_some_and(|(receiver, expected)| {
                receiver.has_changed().is_err() || *receiver.borrow() != *expected
            })
    }

    /// Fallible current usage. The store rolls stale reads into the effective
    /// fixed epoch and clamps backwards wall-clock movement.
    pub fn try_stats(&self) -> Result<RateLimitStats, RateLimitError> {
        self.ensure_healthy()?;
        let requested_epoch = quota_epoch(self.clock.now_unix_millis());
        let usage = self
            .store
            .provider_rate_usage(requested_epoch)
            .map_err(|error| self.poison(error))?;
        self.prune_if_epoch_advanced(usage.epoch)?;
        Ok(RateLimitStats {
            epoch: usage.epoch,
            requests_this_minute: usage.requests,
            tokens_this_minute: usage.tokens,
            rpm_limit: self.config.rpm,
            tpm_limit: self.config.tpm,
            concurrent_available: if self.config.max_concurrent == 0 {
                0
            } else {
                self.concurrency.available_permits() as u32
            },
            max_concurrent: self.config.max_concurrent,
            reserved_receipts: usage.reserved_receipts,
            in_flight_receipts: usage.in_flight_receipts,
            estimated_receipts: usage.estimated_receipts,
            reconciled_receipts: usage.reconciled_receipts,
            denied_provider_requests: self.denied_provider_requests.load(Ordering::Relaxed),
            denied_provider_tokens: self.denied_provider_tokens.load(Ordering::Relaxed),
            denied_cgroup_requests: self.denied_cgroup_requests.load(Ordering::Relaxed),
            denied_cgroup_tokens: self.denied_cgroup_tokens.load(Ordering::Relaxed),
            denied_migration_fence: self.denied_migration_fence.load(Ordering::Relaxed),
            healthy: true,
        })
    }

    /// Compatibility status wrapper. Storage failure is represented as
    /// unhealthy and at-cap for configured dimensions, never as zero usage.
    pub fn stats(&self) -> RateLimitStats {
        self.try_stats().unwrap_or_else(|_| RateLimitStats {
            epoch: quota_epoch(self.clock.now_unix_millis()),
            requests_this_minute: u64::from(self.config.rpm),
            tokens_this_minute: self.config.tpm,
            rpm_limit: self.config.rpm,
            tpm_limit: self.config.tpm,
            concurrent_available: 0,
            max_concurrent: self.config.max_concurrent,
            reserved_receipts: 0,
            in_flight_receipts: 0,
            estimated_receipts: 0,
            reconciled_receipts: 0,
            denied_provider_requests: self.denied_provider_requests.load(Ordering::Relaxed),
            denied_provider_tokens: self.denied_provider_tokens.load(Ordering::Relaxed),
            denied_cgroup_requests: self.denied_cgroup_requests.load(Ordering::Relaxed),
            denied_cgroup_tokens: self.denied_cgroup_tokens.load(Ordering::Relaxed),
            denied_migration_fence: self.denied_migration_fence.load(Ordering::Relaxed),
            healthy: false,
        })
    }

    pub fn try_is_limited(&self) -> Result<bool, RateLimitError> {
        let stats = self.try_stats()?;
        Ok(
            (self.config.rpm > 0 && stats.requests_this_minute >= u64::from(self.config.rpm))
                || (self.config.tpm > 0 && stats.tokens_this_minute >= self.config.tpm),
        )
    }

    /// Safe compatibility wrapper. Configured zero RPM/TPM are always
    /// unlimited and never reported as limited.
    pub fn is_limited(&self) -> bool {
        if self.config.rpm == 0 && self.config.tpm == 0 {
            return false;
        }
        self.try_is_limited().unwrap_or(true)
    }

    /// Fallible compatibility token-only charge.
    pub fn try_record_tokens(&self, tokens: u64) -> Result<(), RateLimitError> {
        self.ensure_healthy()?;
        let requested_epoch = quota_epoch(self.clock.now_unix_millis());
        self.store
            .charge_provider_rate_tokens(Uuid::new_v4(), requested_epoch, tokens)
            .map_err(|error| self.poison(error))
    }

    /// Historical infallible token-only charge. On storage failure the limiter
    /// is poisoned and future admissions fail closed.
    pub fn record_tokens(&self, tokens: u64) {
        let _ = self.try_record_tokens(tokens);
    }
}

/// Affine reservation and concurrency permit.
///
/// The guard is intentionally not `Clone`: exactly one owner may transition,
/// refund, retain, or reconcile a receipt.
pub struct RateLimitGuard {
    permit: Option<OwnedSemaphorePermit>,
    store: Arc<SqliteContextManager>,
    healthy: Arc<AtomicBool>,
    capacity_changed: watch::Sender<u64>,
    reservation: Option<ProviderRateReservation>,
    invoked: bool,
}

impl RateLimitGuard {
    pub fn receipt_id(&self) -> Uuid {
        self.reservation
            .as_ref()
            .expect("live rate-limit guard has a receipt")
            .id
    }

    pub fn admission_epoch(&self) -> u64 {
        self.reservation
            .as_ref()
            .expect("live rate-limit guard has a receipt")
            .epoch
    }

    /// Persist that provider I/O is about to begin.
    pub fn mark_invoked(&mut self) -> Result<(), RateLimitError> {
        if self.invoked {
            return Ok(());
        }
        let receipt = self
            .reservation
            .as_ref()
            .expect("live rate-limit guard has a receipt");
        self.store
            .mark_provider_rate_invoked(receipt.id)
            .map_err(|error| {
                self.healthy.store(false, Ordering::Release);
                RateLimiter::storage_error(error)
            })?;
        self.invoked = true;
        Ok(())
    }

    /// Explicitly refund a reservation before provider I/O.
    pub fn refund(mut self) -> Result<(), RateLimitError> {
        if self.invoked {
            return Err(RateLimitError::AlreadyInvoked);
        }
        if let Some(receipt) = self.reservation.take() {
            self.store
                .refund_provider_rate_before_invocation(receipt.id)
                .map_err(|error| {
                    self.healthy.store(false, Ordering::Release);
                    RateLimiter::storage_error(error)
                })?;
            self.capacity_changed
                .send_modify(|generation| *generation = generation.wrapping_add(1));
        }
        self.permit.take();
        Ok(())
    }

    /// Replace the estimate with actual usage in the original admission epoch.
    pub fn reconcile(mut self, actual_tokens: u64) -> Result<(), RateLimitError> {
        if !self.invoked {
            return Err(RateLimitError::NotInvoked);
        }
        if let Some(receipt) = self.reservation.take() {
            self.store
                .reconcile_provider_rate(receipt.id, actual_tokens)
                .map_err(|error| {
                    self.healthy.store(false, Ordering::Release);
                    RateLimiter::storage_error(error)
                })?;
            self.capacity_changed
                .send_modify(|generation| *generation = generation.wrapping_add(1));
        }
        self.permit.take();
        Ok(())
    }

    /// Explicitly retain the estimate after provider error or cancellation.
    ///
    /// Consuming this guard exposes persistence failures to the execution path;
    /// [`Drop`] remains a conservative last-resort fallback for unwinding.
    pub fn retain_estimate(mut self) -> Result<(), RateLimitError> {
        if !self.invoked {
            return Err(RateLimitError::NotInvoked);
        }
        if let Some(receipt) = self.reservation.take() {
            self.store
                .retain_provider_rate_estimate(receipt.id)
                .map_err(|error| {
                    self.healthy.store(false, Ordering::Release);
                    RateLimiter::storage_error(error)
                })?;
        }
        self.permit.take();
        Ok(())
    }
}

impl Drop for RateLimitGuard {
    fn drop(&mut self) {
        let Some(receipt) = self.reservation.take() else {
            return;
        };
        let result = if self.invoked || receipt.state != ProviderRateReceiptState::Reserved {
            self.store.retain_provider_rate_estimate(receipt.id)
        } else {
            self.store
                .refund_provider_rate_before_invocation(receipt.id)
        };
        match result {
            Ok(()) if !self.invoked && receipt.state == ProviderRateReceiptState::Reserved => {
                self.capacity_changed
                    .send_modify(|generation| *generation = generation.wrapping_add(1));
            }
            Ok(()) => {}
            Err(_) => self.healthy.store(false, Ordering::Release),
        }
        self.permit.take();
    }
}

/// Current effective-epoch statistics.
#[derive(Debug, Clone)]
pub struct RateLimitStats {
    pub epoch: u64,
    pub requests_this_minute: u64,
    pub tokens_this_minute: u64,
    pub rpm_limit: u32,
    pub tpm_limit: u64,
    pub concurrent_available: u32,
    pub max_concurrent: u32,
    pub reserved_receipts: u64,
    pub in_flight_receipts: u64,
    pub estimated_receipts: u64,
    pub reconciled_receipts: u64,
    pub denied_provider_requests: u64,
    pub denied_provider_tokens: u64,
    pub denied_cgroup_requests: u64,
    pub denied_cgroup_tokens: u64,
    pub denied_migration_fence: u64,
    pub healthy: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::quota_clock::ManualQuotaClock;
    use std::sync::atomic::{AtomicU32, Ordering as AtomicOrdering};

    fn temporary_database_path(test_name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("aiagentos-{test_name}-{}.sqlite", Uuid::new_v4()))
    }

    fn deterministic_limiter(config: RateLimitConfig, clock: Arc<ManualQuotaClock>) -> RateLimiter {
        RateLimiter::with_store(
            config,
            Arc::new(SqliteContextManager::in_memory().unwrap()),
            clock,
        )
        .unwrap()
    }

    #[tokio::test]
    async fn exact_half_open_boundary_rolls_usage() {
        let clock = Arc::new(ManualQuotaClock::new(59_999));
        let limiter = deterministic_limiter(
            RateLimitConfig {
                rpm: 1,
                tpm: 100,
                max_concurrent: 2,
            },
            clock.clone(),
        );
        drop(limiter.acquire_tokens(10).await.unwrap());
        assert_eq!(limiter.stats().epoch, 0);
        assert!(limiter.is_limited());

        let cancellation = CancellationToken::new();
        let waiter_cancellation = cancellation.clone();
        let waiter = limiter.acquire_tokens_cancellable(10, &waiter_cancellation);
        tokio::pin!(waiter);
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(10), &mut waiter)
                .await
                .is_err()
        );
        clock.set(60_000);
        let guard = waiter.await.unwrap();
        assert_eq!(guard.admission_epoch(), 1);
        drop(guard);
        assert_eq!(limiter.stats().epoch, 1);
    }

    #[tokio::test]
    async fn skipped_epochs_and_stale_reads_start_empty() {
        let clock = Arc::new(ManualQuotaClock::new(10));
        let limiter = deterministic_limiter(RateLimitConfig::default(), clock.clone());
        drop(limiter.acquire_tokens(7).await.unwrap());
        assert_eq!(limiter.stats().requests_this_minute, 1);
        clock.set(180_000);
        let stats = limiter.stats();
        assert_eq!(stats.epoch, 3);
        assert_eq!(stats.requests_this_minute, 0);
        assert_eq!(stats.tokens_this_minute, 0);
    }

    #[tokio::test]
    async fn backward_clock_cannot_reopen_old_epoch() {
        let clock = Arc::new(ManualQuotaClock::new(120_000));
        let limiter = deterministic_limiter(RateLimitConfig::default(), clock.clone());
        drop(limiter.acquire_tokens(7).await.unwrap());
        assert_eq!(limiter.stats().epoch, 2);
        clock.set(1);
        let stats = limiter.stats();
        assert_eq!(stats.epoch, 2);
        assert_eq!(stats.requests_this_minute, 1);
    }

    #[tokio::test]
    async fn zero_limits_are_unlimited_and_never_report_limited() {
        let clock = Arc::new(ManualQuotaClock::new(0));
        let limiter = deterministic_limiter(
            RateLimitConfig {
                rpm: 0,
                tpm: 0,
                max_concurrent: 0,
            },
            clock,
        );
        let guard = limiter.acquire_tokens(u64::MAX).await.unwrap();
        guard.reconcile(u64::MAX).unwrap();
        let stats = limiter.stats();
        assert_eq!(stats.requests_this_minute, 1);
        assert_eq!(stats.tokens_this_minute, u64::MAX);
        assert!(!limiter.is_limited());
    }

    #[tokio::test]
    async fn request_larger_than_cgroup_limit_fails_without_waiting_or_receipt() {
        let clock = Arc::new(ManualQuotaClock::new(0));
        let limiter = deterministic_limiter(
            RateLimitConfig {
                rpm: 0,
                tpm: 1_000,
                max_concurrent: 1,
            },
            clock,
        );
        let cancellation = CancellationToken::new();
        let result = limiter
            .acquire_tokens_with_cgroups_cancellable(
                101,
                &[CgroupQuotaConstraint {
                    scope_id: "/tenant/tight".into(),
                    token_limit: 100,
                }],
                None,
                &cancellation,
            )
            .await;
        assert!(matches!(
            result,
            Err(RateLimitError::RequestExceedsCgroupTpm {
                ref scope_id,
                requested: 101,
                limit: 100,
            }) if scope_id == "/tenant/tight"
        ));
        let stats = limiter.try_stats().unwrap();
        assert_eq!(stats.requests_this_minute, 0);
        assert_eq!(stats.tokens_this_minute, 0);
        assert_eq!(stats.reserved_receipts, 0);
        assert_eq!(stats.denied_cgroup_tokens, 1);
    }

    #[tokio::test]
    async fn execution_admission_returns_retryable_backpressure_without_epoch_wait() {
        let clock = Arc::new(ManualQuotaClock::new(0));
        let limiter = deterministic_limiter(
            RateLimitConfig {
                rpm: 0,
                tpm: 1_000,
                max_concurrent: 1,
            },
            clock.clone(),
        );
        let scope = [CgroupQuotaConstraint {
            scope_id: "/tenant/funded/profile/standard/agent/exhausted".into(),
            token_limit: 5,
        }];
        let cancellation = CancellationToken::new();
        let mut fill = limiter
            .acquire_tokens_with_cgroups_cancellable(5, &scope, None, &cancellation)
            .await
            .unwrap();
        fill.mark_invoked().unwrap();
        fill.reconcile(5).unwrap();

        let result = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            limiter.try_acquire_tokens_with_cgroups_cancellable(1, &scope, None, &cancellation),
        )
        .await
        .expect("execution admission must not wait for an exhausted epoch");
        let Err(error) = result else {
            panic!("exhausted execution admission unexpectedly succeeded");
        };
        assert!(matches!(
            error,
            RateLimitError::QuotaExhausted {
                ref scope_kind,
                ref scope_id,
                ref dimension,
                used: 5,
                requested: 1,
                limit: 5,
                retry_at_unix_ms: QUOTA_EPOCH_MILLIS,
            } if scope_kind == "cgroup"
                && scope_id == "/tenant/funded/profile/standard/agent/exhausted"
                && dimension == "tokens"
        ));
        assert_eq!(clock.now_unix_millis(), 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrency_bound_holds_under_load() {
        let max_concurrent = 3;
        let limiter = Arc::new(RateLimiter::new(RateLimitConfig {
            rpm: 10_000,
            tpm: 10_000_000,
            max_concurrent,
        }));
        let live = Arc::new(AtomicU32::new(0));
        let peak = Arc::new(AtomicU32::new(0));
        let mut handles = Vec::new();
        for _ in 0..32 {
            let limiter = limiter.clone();
            let live = live.clone();
            let peak = peak.clone();
            handles.push(tokio::spawn(async move {
                let _guard = limiter.acquire_tokens(1).await.unwrap();
                let now = live.fetch_add(1, AtomicOrdering::SeqCst) + 1;
                peak.fetch_max(now, AtomicOrdering::SeqCst);
                tokio::task::yield_now().await;
                live.fetch_sub(1, AtomicOrdering::SeqCst);
            }));
        }
        for handle in handles {
            handle.await.unwrap();
        }
        assert!(peak.load(AtomicOrdering::SeqCst) <= max_concurrent);
    }

    #[tokio::test]
    async fn cancellation_waiting_for_concurrency_leaks_no_receipt() {
        let limiter = Arc::new(RateLimiter::new(RateLimitConfig {
            rpm: 10,
            tpm: 100,
            max_concurrent: 1,
        }));
        let _held = limiter.acquire_tokens(1).await.unwrap();
        let cancellation = CancellationToken::new();
        let waiter = {
            let limiter = limiter.clone();
            let cancellation = cancellation.clone();
            tokio::spawn(async move { limiter.acquire_tokens_cancellable(1, &cancellation).await })
        };
        tokio::task::yield_now().await;
        cancellation.cancel();
        assert!(matches!(
            waiter.await.unwrap(),
            Err(RateLimitError::Cancelled)
        ));
        assert_eq!(limiter.stats().requests_this_minute, 1);
    }

    #[tokio::test]
    async fn pre_cancelled_admission_never_reserves_quota() {
        let limiter = RateLimiter::new(RateLimitConfig {
            rpm: 10,
            tpm: 100,
            max_concurrent: 1,
        });
        let cancellation = CancellationToken::new();
        cancellation.cancel();

        assert!(matches!(
            limiter.acquire_tokens_cancellable(1, &cancellation).await,
            Err(RateLimitError::Cancelled)
        ));
        let stats = limiter.try_stats().unwrap();
        assert_eq!(stats.requests_this_minute, 0);
        assert_eq!(stats.tokens_this_minute, 0);
        assert_eq!(stats.reserved_receipts, 0);
    }

    #[tokio::test]
    async fn denied_old_cgroup_scope_wakes_immediately_on_membership_change() {
        let clock = Arc::new(ManualQuotaClock::new(0));
        let limiter = deterministic_limiter(
            RateLimitConfig {
                rpm: 100,
                tpm: 10_000,
                max_concurrent: 2,
            },
            clock.clone(),
        );
        let old_scope = [CgroupQuotaConstraint {
            scope_id: "/tenant/a/agent/old".into(),
            token_limit: 5,
        }];
        let cancellation = CancellationToken::new();
        let mut fill = limiter
            .acquire_tokens_with_cgroups_cancellable(5, &old_scope, None, &cancellation)
            .await
            .unwrap();
        fill.mark_invoked().unwrap();
        fill.reconcile(5).unwrap();

        let (membership, mut changes) = watch::channel(1u64);
        let waiter = limiter.acquire_tokens_with_cgroups_cancellable(
            1,
            &old_scope,
            Some((&mut changes, 1)),
            &cancellation,
        );
        tokio::pin!(waiter);
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(20), &mut waiter)
                .await
                .is_err(),
            "the exhausted old scope should initially wait"
        );

        membership.send_replace(2);
        assert!(matches!(
            tokio::time::timeout(std::time::Duration::from_secs(1), &mut waiter)
                .await
                .expect("membership notification must wake admission"),
            Err(RateLimitError::CgroupMembershipChanged)
        ));
        assert_eq!(clock.now_unix_millis(), 0, "the epoch did not advance");
        let stats = limiter.try_stats().unwrap();
        assert_eq!(stats.requests_this_minute, 1);
        assert_eq!(stats.reconciled_receipts, 1);
    }

    #[tokio::test]
    async fn cancellation_waiting_for_next_epoch_leaks_no_receipt() {
        let clock = Arc::new(ManualQuotaClock::new(1));
        let limiter = Arc::new(deterministic_limiter(
            RateLimitConfig {
                rpm: 1,
                tpm: 100,
                max_concurrent: 2,
            },
            clock,
        ));
        drop(limiter.acquire_tokens(1).await.unwrap());
        let cancellation = CancellationToken::new();
        let waiter = {
            let limiter = limiter.clone();
            let cancellation = cancellation.clone();
            tokio::spawn(async move { limiter.acquire_tokens_cancellable(1, &cancellation).await })
        };
        tokio::task::yield_now().await;
        cancellation.cancel();
        assert!(matches!(
            waiter.await.unwrap(),
            Err(RateLimitError::Cancelled)
        ));
        let stats = limiter.stats();
        assert_eq!(stats.requests_this_minute, 1);
        assert_eq!(stats.estimated_receipts, 1);
        assert_eq!(stats.reserved_receipts, 0);
    }

    #[tokio::test]
    async fn every_admission_has_a_unique_receipt() {
        let limiter = RateLimiter::new(RateLimitConfig {
            rpm: 10,
            tpm: 100,
            max_concurrent: 2,
        });
        let first = limiter.acquire_tokens(1).await.unwrap();
        let second = limiter.acquire_tokens(1).await.unwrap();
        assert_ne!(first.receipt_id(), second.receipt_id());
    }

    #[tokio::test]
    async fn pre_invocation_drop_and_explicit_refund_restore_quota() {
        let limiter = RateLimiter::new(RateLimitConfig {
            rpm: 10,
            tpm: 100,
            max_concurrent: 1,
        });
        let cancellation = CancellationToken::new();
        let guard = limiter
            .acquire_tokens_cancellable(10, &cancellation)
            .await
            .unwrap();
        drop(guard);
        assert_eq!(limiter.stats().requests_this_minute, 0);

        let guard = limiter
            .acquire_tokens_cancellable(10, &cancellation)
            .await
            .unwrap();
        guard.refund().unwrap();
        assert_eq!(limiter.stats().tokens_this_minute, 0);
    }

    #[tokio::test]
    async fn same_epoch_refund_wakes_denied_waiter() {
        let clock = Arc::new(ManualQuotaClock::new(1));
        let limiter = Arc::new(deterministic_limiter(
            RateLimitConfig {
                rpm: 0,
                tpm: 100,
                max_concurrent: 2,
            },
            clock,
        ));
        let cancellation = CancellationToken::new();
        let reservation = limiter
            .acquire_tokens_cancellable(100, &cancellation)
            .await
            .unwrap();
        let waiter = {
            let limiter = limiter.clone();
            tokio::spawn(async move { limiter.acquire_tokens(1).await })
        };
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        assert!(!waiter.is_finished(), "full TPM must initially deny");

        reservation.refund().unwrap();
        let guard = tokio::time::timeout(std::time::Duration::from_secs(1), waiter)
            .await
            .expect("refund must wake the same-epoch waiter")
            .unwrap()
            .unwrap();
        assert_eq!(guard.admission_epoch(), 0);
        guard.reconcile(1).unwrap();
    }

    #[tokio::test]
    async fn same_epoch_lower_reconciliation_wakes_denied_waiter() {
        let clock = Arc::new(ManualQuotaClock::new(1));
        let limiter = Arc::new(deterministic_limiter(
            RateLimitConfig {
                rpm: 0,
                tpm: 100,
                max_concurrent: 2,
            },
            clock,
        ));
        let reservation = limiter.acquire_tokens(100).await.unwrap();
        let waiter = {
            let limiter = limiter.clone();
            tokio::spawn(async move { limiter.acquire_tokens(1).await })
        };
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        assert!(!waiter.is_finished(), "full TPM must initially deny");

        reservation.reconcile(50).unwrap();
        let guard = tokio::time::timeout(std::time::Duration::from_secs(1), waiter)
            .await
            .expect("lower reconciliation must wake the same-epoch waiter")
            .unwrap()
            .unwrap();
        assert_eq!(guard.admission_epoch(), 0);
        guard.reconcile(1).unwrap();
        assert_eq!(limiter.stats().tokens_this_minute, 51);
    }

    #[tokio::test]
    async fn attempted_request_retains_estimate_on_drop() {
        let limiter = RateLimiter::new(RateLimitConfig {
            rpm: 10,
            tpm: 100,
            max_concurrent: 1,
        });
        let cancellation = CancellationToken::new();
        let mut guard = limiter
            .acquire_tokens_cancellable(10, &cancellation)
            .await
            .unwrap();
        guard.mark_invoked().unwrap();
        drop(guard);
        let stats = limiter.stats();
        assert_eq!(stats.requests_this_minute, 1);
        assert_eq!(stats.tokens_this_minute, 10);
        assert_eq!(stats.estimated_receipts, 1);
    }

    #[tokio::test]
    async fn attempted_request_can_explicitly_retain_estimate() {
        let limiter = RateLimiter::new(RateLimitConfig {
            rpm: 10,
            tpm: 100,
            max_concurrent: 1,
        });
        let cancellation = CancellationToken::new();
        let mut guard = limiter
            .acquire_tokens_cancellable(10, &cancellation)
            .await
            .unwrap();
        guard.mark_invoked().unwrap();
        guard.retain_estimate().unwrap();
        let stats = limiter.stats();
        assert_eq!(stats.requests_this_minute, 1);
        assert_eq!(stats.tokens_this_minute, 10);
        assert_eq!(stats.estimated_receipts, 1);
        assert_eq!(stats.in_flight_receipts, 0);
    }

    #[tokio::test]
    async fn same_epoch_reconciliation_replaces_estimate() {
        let limiter = RateLimiter::new(RateLimitConfig {
            rpm: 10,
            tpm: 1_000,
            max_concurrent: 1,
        });
        let guard = limiter.acquire_tokens(300).await.unwrap();
        guard.reconcile(125).unwrap();
        assert_eq!(limiter.stats().tokens_this_minute, 125);
    }

    #[tokio::test]
    async fn cross_epoch_reconciliation_does_not_charge_completion_epoch() {
        let path = temporary_database_path("cross-epoch-reconcile");
        let clock = Arc::new(ManualQuotaClock::new(59_999));
        let store = Arc::new(SqliteContextManager::new(&path).unwrap());
        let limiter = RateLimiter::with_store(
            RateLimitConfig {
                rpm: 10,
                tpm: 1_000,
                max_concurrent: 1,
            },
            store,
            clock.clone(),
        )
        .unwrap();
        let guard = limiter.acquire_tokens(300).await.unwrap();
        clock.set(60_000);
        guard.reconcile(125).unwrap();

        let inspection = rusqlite::Connection::open(&path).unwrap();
        let epoch = 0u64.to_be_bytes();
        let tokens: Vec<u8> = inspection
            .query_row(
                "SELECT tokens FROM quota_epochs
                 WHERE scope_kind = 'provider' AND scope_id = 'global' AND epoch = ?1",
                [epoch.as_slice()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            u64::from_be_bytes(tokens.try_into().unwrap()),
            125,
            "actual usage must replace the estimate in the admission epoch"
        );
        drop(inspection);
        let stats = limiter.stats();
        assert_eq!(stats.epoch, 1);
        assert_eq!(stats.tokens_this_minute, 0);
        drop(limiter);
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn record_tokens_uses_durable_token_only_charge() {
        let limiter = RateLimiter::new(RateLimitConfig::default());
        limiter.try_record_tokens(500).unwrap();
        limiter.try_record_tokens(300).unwrap();
        let stats = limiter.stats();
        assert_eq!(stats.requests_this_minute, 0);
        assert_eq!(stats.tokens_this_minute, 800);
    }

    #[tokio::test]
    async fn persistent_restart_in_same_epoch_preserves_usage() {
        let path = temporary_database_path("rate-restart");
        let clock = Arc::new(ManualQuotaClock::new(20_000));
        let config = RateLimitConfig {
            rpm: 1,
            tpm: 100,
            max_concurrent: 1,
        };
        {
            let store = Arc::new(SqliteContextManager::new(&path).unwrap());
            let limiter = RateLimiter::with_store(config.clone(), store, clock.clone()).unwrap();
            let guard = limiter.acquire_tokens(40).await.unwrap();
            drop(guard);
            assert_eq!(limiter.stats().estimated_receipts, 1);
        }

        {
            let store = Arc::new(SqliteContextManager::new(&path).unwrap());
            let limiter = RateLimiter::with_store(config.clone(), store, clock.clone()).unwrap();
            let stats = limiter.try_stats().unwrap();
            assert_eq!(stats.epoch, 0);
            assert_eq!(stats.requests_this_minute, 1);
            assert_eq!(stats.tokens_this_minute, 40);
            assert!(limiter.is_limited());
        }

        clock.set(60_000);
        {
            let store = Arc::new(SqliteContextManager::new(&path).unwrap());
            let limiter = RateLimiter::with_store(config, store, clock).unwrap();
            let stats = limiter.try_stats().unwrap();
            assert_eq!(stats.epoch, 1);
            assert_eq!(stats.requests_this_minute, 0);
            assert_eq!(stats.tokens_this_minute, 0);
        }
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn storage_failure_poisons_future_admission() {
        let path = temporary_database_path("rate-poison");
        let store = Arc::new(SqliteContextManager::new(&path).unwrap());
        let clock = Arc::new(ManualQuotaClock::new(0));
        let limiter = RateLimiter::with_store(RateLimitConfig::default(), store, clock).unwrap();

        let sabotage = rusqlite::Connection::open(&path).unwrap();
        sabotage
            .execute_batch("DROP TABLE quota_epoch_floor")
            .unwrap();
        drop(sabotage);

        let cancellation = CancellationToken::new();
        let first = match limiter.acquire_tokens_cancellable(1, &cancellation).await {
            Ok(_) => panic!("storage failure unexpectedly admitted a request"),
            Err(error) => error,
        };
        assert!(matches!(first, RateLimitError::StorageUnavailable(_)));

        let second = match limiter.acquire_tokens_cancellable(1, &cancellation).await {
            Ok(_) => panic!("poisoned limiter unexpectedly admitted a request"),
            Err(error) => error,
        };
        assert!(
            second
                .to_string()
                .contains("prior persistence operation failed"),
            "unexpected second error: {second}"
        );
        assert!(!limiter.stats().healthy);
        let _ = std::fs::remove_file(path);
    }
}
