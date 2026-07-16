//! Runtime conformance assertion for `LocalOnly` routes.
//!
//! An exercised operation must not increase its caller-supplied business-write, outbox, or
//! publish probes.
//! This observes only the runtime seams supplied by the caller and explicit typed-route exclusions;
//! it is not a process-wide filesystem, network, or global-state sandbox.
//! Run `cargo test -p testkit local_only` for the focused local check.
//! The Medium invariant carrier and its synthetic red/green evidence live in
//! `crates/testkit/tests/local_only.rs`, whose integration-test path is bound to verify and CI.
//!
//! ref: tokio-rs/axum examples/testing/src/main.rs@c59208c86fded335cd85e388030ad59347b0e5ae
//! (RSS keeps axum's complete `Router::oneshot` await lifecycle and samples observable effects
//! before and after that lifecycle.)

use std::future::Future;
use std::marker::PhantomData;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

/// Business-write effect observer dimension.
pub enum BusinessWrite {}

/// Outbox-effect observer dimension.
pub enum Outbox {}

/// Direct-publish observer dimension.
pub enum Publish {}

/// Provider-owned cumulative counter bound to one forbidden-effect dimension.
pub struct ProviderCounter<D> {
    count: Arc<AtomicU64>,
    dimension: PhantomData<fn() -> D>,
}

/// Cloneable read-only handle for one provider-owned counter.
pub struct ProviderCounterHandle<D> {
    count: Arc<AtomicU64>,
    dimension: PhantomData<fn() -> D>,
}

impl<D> Clone for ProviderCounter<D> {
    fn clone(&self) -> Self {
        Self {
            count: Arc::clone(&self.count),
            dimension: PhantomData,
        }
    }
}

impl<D> Clone for ProviderCounterHandle<D> {
    fn clone(&self) -> Self {
        Self {
            count: Arc::clone(&self.count),
            dimension: PhantomData,
        }
    }
}

impl ProviderCounter<BusinessWrite> {
    /// Creates a provider-owned business-write counter.
    pub fn business_write() -> Self {
        Self::new()
    }
}

impl ProviderCounter<Outbox> {
    /// Creates a provider-owned outbox counter.
    pub fn outbox() -> Self {
        Self::new()
    }
}

impl ProviderCounter<Publish> {
    /// Creates a provider-owned direct-publish counter.
    pub fn publish() -> Self {
        Self::new()
    }
}

impl<D> ProviderCounter<D> {
    fn new() -> Self {
        Self {
            count: Arc::new(AtomicU64::new(0)),
            dimension: PhantomData,
        }
    }

    /// Returns a read-only handle sharing this provider's cumulative state.
    pub fn handle(&self) -> ProviderCounterHandle<D> {
        ProviderCounterHandle {
            count: Arc::clone(&self.count),
            dimension: PhantomData,
        }
    }

    /// Records one effect produced by the owning provider.
    pub fn record(&self) {
        self.add(1);
    }

    /// Records `amount` effects produced by the owning provider.
    pub fn add(&self, amount: u64) {
        self.count.fetch_add(amount, Ordering::SeqCst);
    }
}

impl<D> ProviderCounterHandle<D> {
    fn sample(&self) -> u64 {
        self.count.load(Ordering::SeqCst)
    }
}

/// Explicit evidence that a dimension is statically absent from the exercised route.
///
/// This value does not claim to perform a cross-crate proof. Its call site must be adjacent to the
/// route/state proof that excludes the capability; repository consistency checks enforce the
/// cross-crate provenance. Runtime seams must use [`ProviderCounterHandle`] instead.
pub struct StaticExclusion<D> {
    dimension: PhantomData<fn() -> D>,
}

impl<D> StaticExclusion<D> {
    /// Adapts an owner-side typed route/state proof into Medium conformance evidence.
    ///
    /// The proof type is intentionally generic because testkit has no workspace dependencies.
    /// The repository provenance gate accepts only canonical httpserve proof constructors.
    pub const fn from_governed<Proof>(_proof: &Proof) -> Self {
        Self {
            dimension: PhantomData,
        }
    }
}

enum EffectEvidenceKind<D> {
    Runtime(ProviderCounterHandle<D>),
    Static(StaticExclusion<D>),
}

#[doc(hidden)]
pub struct EffectEvidence<D>(EffectEvidenceKind<D>);

impl<D> EffectEvidence<D> {
    fn sample(&mut self) -> u64 {
        match &mut self.0 {
            EffectEvidenceKind::Runtime(probe) => probe.sample(),
            EffectEvidenceKind::Static(_) => 0,
        }
    }
}

impl<D> From<ProviderCounterHandle<D>> for EffectEvidence<D> {
    fn from(handle: ProviderCounterHandle<D>) -> Self {
        Self(EffectEvidenceKind::Runtime(handle))
    }
}

impl<D> From<StaticExclusion<D>> for EffectEvidence<D> {
    fn from(exclusion: StaticExclusion<D>) -> Self {
        Self(EffectEvidenceKind::Static(exclusion))
    }
}

/// Mandatory evidence for the three forbidden `LocalOnly` effect dimensions.
///
/// The constructor requires all dimensions together so a conformance call cannot silently omit an
/// effect. Each runtime probe returns a monotonically non-decreasing cumulative count.
pub struct LocalOnlyObservers {
    business_write: EffectEvidence<BusinessWrite>,
    outbox: EffectEvidence<Outbox>,
    publish: EffectEvidence<Publish>,
}

impl LocalOnlyObservers {
    /// Creates a complete observer set for business-write, outbox, and publish effects.
    ///
    /// Dimension-specific probe types make swapped arguments fail to compile.
    ///
    /// ```compile_fail
    /// use testkit::local_only::{LocalOnlyObservers, ProviderCounter};
    /// LocalOnlyObservers::new(
    ///     ProviderCounter::outbox().handle(),
    ///     ProviderCounter::business_write().handle(),
    ///     ProviderCounter::publish().handle(),
    /// );
    /// ```
    ///
    /// ```compile_fail
    /// use testkit::local_only::RuntimeProbe;
    /// let _ = RuntimeProbe::write(|| 0);
    /// ```
    pub fn new(
        business_write: impl Into<EffectEvidence<BusinessWrite>>,
        outbox: impl Into<EffectEvidence<Outbox>>,
        publish: impl Into<EffectEvidence<Publish>>,
    ) -> Self {
        Self {
            business_write: business_write.into(),
            outbox: outbox.into(),
            publish: publish.into(),
        }
    }

    fn sample(&mut self) -> LocalOnlySideEffects {
        LocalOnlySideEffects {
            business_writes: self.business_write.sample(),
            outbox: self.outbox.sample(),
            publishes: self.publish.sample(),
        }
    }
}

/// A read-only cumulative snapshot of observable `LocalOnly` side effects.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[must_use]
pub struct LocalOnlySideEffects {
    business_writes: u64,
    outbox: u64,
    publishes: u64,
}

impl LocalOnlySideEffects {
    /// Returns the observed business-write count.
    pub const fn business_writes(self) -> u64 {
        self.business_writes
    }

    /// Returns the observed outbox count.
    pub const fn outbox(self) -> u64 {
        self.outbox
    }

    /// Returns the observed publish count.
    pub const fn publishes(self) -> u64 {
        self.publishes
    }
}

/// Opaque evidence that one route operation completed its `LocalOnly` post-check.
///
/// The receipt retains its generic marker and only [`assert_local_only_with_receipt`] can construct
/// it; callers cannot mint evidence independently. Because `testkit` deliberately has no workspace
/// dependency, the cross-crate relationship between that marker, a generated active `LocalOnly`
/// contract, and its mounted route is closed by the repository's Medium source-provenance gate.
///
/// ```compile_fail
/// use std::marker::PhantomData;
/// use testkit::local_only::LocalOnlyConformanceReceipt;
///
/// struct RouteMarker;
/// let _forged = LocalOnlyConformanceReceipt::<RouteMarker> {
///     contract_id: "example.route",
///     marker: PhantomData,
/// };
/// ```
#[must_use = "a LocalOnly conformance receipt is the evidence produced by the post-check"]
pub struct LocalOnlyConformanceReceipt<Marker> {
    contract_id: &'static str,
    marker: PhantomData<fn() -> Marker>,
}

impl<Marker> LocalOnlyConformanceReceipt<Marker> {
    /// Returns the generated contract ID bound to this receipt's canonical source site.
    pub const fn contract_id(&self) -> &'static str {
        self.contract_id
    }
}

/// Failure reported by [`assert_local_only`] and [`assert_local_only_with_receipt`].
///
/// Errors contain only observer names and counts. The operation output is never formatted or
/// retained, preventing request, tenant, subject, or payload data from entering diagnostics.
#[derive(Debug, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum LocalOnlyConformanceError {
    /// An observer violated its cumulative monotonicity contract.
    #[error("LocalOnly {effect} observation regressed from {before} to {after}")]
    ObservationRegressed {
        /// Stable effect dimension name.
        effect: &'static str,
        /// Count sampled before the operation.
        before: u64,
        /// Count sampled after the operation.
        after: u64,
    },
    /// At least one forbidden effect increased while the operation ran.
    #[error(
        "LocalOnly operation produced forbidden effects: business_writes={business_writes}, outbox={outbox}, publishes={publishes}"
    )]
    ForbiddenEffects {
        /// Business-write count increase.
        business_writes: u64,
        /// Outbox count increase.
        outbox: u64,
        /// Publish count increase.
        publishes: u64,
    },
}

/// Runs an operation and rejects observable business-write, outbox, or publish effects.
///
/// The baseline is sampled before `operation` is invoked, so both future construction and its
/// complete await lifecycle are inside the observation window. When conformance holds, the
/// operation output is returned unchanged, including a domain-level error value.
pub async fn assert_local_only<Operation, OperationFuture, T>(
    mut observers: LocalOnlyObservers,
    operation: Operation,
) -> Result<T, LocalOnlyConformanceError>
where
    Operation: FnOnce() -> OperationFuture,
    OperationFuture: Future<Output = T>,
{
    let before = observers.sample();
    let output = operation().await;
    let after = observers.sample();
    validate_observations(before, after)?;
    Ok(output)
}

/// Runs a route operation and returns opaque evidence only after its `LocalOnly` post-check.
///
/// The generated route marker and generated `contract_id` are intentionally supplied separately:
/// repository provenance checks require their canonical source forms and reject mismatches. A
/// domain-level error remains an operation output and therefore still receives a receipt when all
/// forbidden-effect observations remain clean.
pub async fn assert_local_only_with_receipt<Marker, Operation, OperationFuture, T>(
    contract_id: &'static str,
    observers: LocalOnlyObservers,
    operation: Operation,
) -> Result<(T, LocalOnlyConformanceReceipt<Marker>), LocalOnlyConformanceError>
where
    Operation: FnOnce() -> OperationFuture,
    OperationFuture: Future<Output = T>,
{
    let output = assert_local_only(observers, operation).await?;
    let receipt = LocalOnlyConformanceReceipt {
        contract_id,
        marker: PhantomData,
    };
    Ok((output, receipt))
}

fn validate_observations(
    before: LocalOnlySideEffects,
    after: LocalOnlySideEffects,
) -> Result<(), LocalOnlyConformanceError> {
    let business_writes = checked_delta(
        "business-write",
        before.business_writes(),
        after.business_writes(),
    )?;
    let outbox = checked_delta("outbox", before.outbox(), after.outbox())?;
    let publishes = checked_delta("publish", before.publishes(), after.publishes())?;

    if business_writes == 0 && outbox == 0 && publishes == 0 {
        return Ok(());
    }

    Err(LocalOnlyConformanceError::ForbiddenEffects {
        business_writes,
        outbox,
        publishes,
    })
}

fn checked_delta(
    effect: &'static str,
    before: u64,
    after: u64,
) -> Result<u64, LocalOnlyConformanceError> {
    after
        .checked_sub(before)
        .ok_or(LocalOnlyConformanceError::ObservationRegressed {
            effect,
            before,
            after,
        })
}

#[cfg(test)]
mod tests {
    use super::{
        BusinessWrite, LocalOnlyConformanceError, LocalOnlyObservers, Outbox, ProviderCounter,
        Publish, assert_local_only,
    };

    fn observers(
        business_writes: &ProviderCounter<BusinessWrite>,
        outbox: &ProviderCounter<Outbox>,
        publishes: &ProviderCounter<Publish>,
    ) -> LocalOnlyObservers {
        LocalOnlyObservers::new(
            business_writes.handle(),
            outbox.handle(),
            publishes.handle(),
        )
    }

    #[tokio::test]
    async fn operation_failure_is_returned_after_post_check() {
        let clean = assert_local_only(
            observers(
                &ProviderCounter::business_write(),
                &ProviderCounter::outbox(),
                &ProviderCounter::publish(),
            ),
            || async { Result::<(), &str>::Err("domain failure") },
        )
        .await;
        assert_eq!(clean, Ok(Err("domain failure")));

        let business_writes = ProviderCounter::business_write();
        let operation_business_writes = business_writes.clone();
        let violated = assert_local_only(
            observers(
                &business_writes,
                &ProviderCounter::outbox(),
                &ProviderCounter::publish(),
            ),
            move || async move {
                operation_business_writes.record();
                Result::<(), &str>::Err("must not appear in conformance error")
            },
        )
        .await;
        assert_eq!(
            violated,
            Err(LocalOnlyConformanceError::ForbiddenEffects {
                business_writes: 1,
                outbox: 0,
                publishes: 0,
            })
        );
    }

    #[tokio::test]
    async fn observer_regression_fails_loudly() {
        let business_writes = ProviderCounter::business_write();
        business_writes.add(u64::MAX);
        let operation_business_writes = business_writes.clone();
        let result = assert_local_only(
            observers(
                &business_writes,
                &ProviderCounter::outbox(),
                &ProviderCounter::publish(),
            ),
            move || async move { operation_business_writes.record() },
        )
        .await;

        assert_eq!(
            result,
            Err(LocalOnlyConformanceError::ObservationRegressed {
                effect: "business-write",
                before: u64::MAX,
                after: 0,
            })
        );
    }

    #[tokio::test]
    async fn operation_is_created_only_after_baseline_sampling() {
        let business_writes = ProviderCounter::business_write();
        let outbox = ProviderCounter::outbox();
        let publishes = ProviderCounter::publish();
        let operation_business_writes = business_writes.clone();

        let result = assert_local_only(
            observers(&business_writes, &outbox, &publishes),
            move || {
                operation_business_writes.record();
                async {}
            },
        )
        .await;

        assert_eq!(
            result,
            Err(LocalOnlyConformanceError::ForbiddenEffects {
                business_writes: 1,
                outbox: 0,
                publishes: 0,
            })
        );
    }
}
