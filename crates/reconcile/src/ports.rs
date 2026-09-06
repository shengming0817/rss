use crate::{Completion, Control, Error, ReconcileDiff, Scope, Target, Timer};
use std::{future::Future, time::Duration};
/// Provider-owned authority. Concrete claims must hide their token and cannot be cloned.
/// This trait reports metadata; only the provider's write path establishes fencing.
pub trait Claim: Send + Sync {
    /// Exact target owned by this claim.
    fn target(&self) -> &Target;
    /// Persisted failures at claim time.
    fn failures(&self) -> u32;
}
/// Provider-neutral durable schedule. Every mutation must enforce tenant and claim identity.
pub trait DurableStore: Send + Sync {
    /// Provider-minted, move-only write authority.
    type Claim: Claim;
    /// Persist wake before emitting any best-effort notification.
    fn wake<T: Timer>(
        &self,
        target: &Target,
        control: &Control<'_, T>,
    ) -> impl Future<Output = Result<(), Error>> + Send;
    /// Atomically claim due or expired unfinished work. Return at most limit unique targets
    /// within scope, mint a new epoch and capture wake version. Never claim a live lease.
    fn claim_due<T: Timer>(
        &self,
        scope: &Scope,
        limit: usize,
        lease: Duration,
        control: &Control<'_, T>,
    ) -> impl Future<Output = Result<Vec<Self::Claim>, Error>> + Send;
    /// Renew only an unexpired matching token and epoch; failure cancels its callback.
    fn renew<T: Timer>(
        &self,
        claim: &Self::Claim,
        lease: Duration,
        control: &Control<'_, T>,
    ) -> impl Future<Output = Result<(), Error>> + Send;
    /// Atomically settle and release while preserving a newer wake and monotonic epoch.
    fn finish<T: Timer>(
        &self,
        claim: &Self::Claim,
        completion: Completion,
        control: &Control<'_, T>,
    ) -> impl Future<Output = Result<(), Error>> + Send;
    /// Relinquish matching authority without deleting pending work; TTL is the recovery fallback.
    fn release<T: Timer>(
        &self,
        claim: &Self::Claim,
        control: &Control<'_, T>,
    ) -> impl Future<Output = Result<(), Error>> + Send;
}
/// Business comparison and effects. No generated commands or product policy belongs here.
pub trait Reconciler<C: Claim>: Send + Sync {
    /// Pure comparable business snapshots; Debug must not expose them.
    type State: PartialEq + Send;
    /// Re-read desired and actual on every attempt, including after uncertain effects.
    fn observe<T: Timer>(
        &self,
        claim: &C,
        control: &Control<'_, T>,
    ) -> impl Future<Output = Result<ReconcileDiff<Self::State>, Error>> + Send;
    /// Apply a drift. Success acknowledges submission, never convergence. Implementations
    /// must use stable business idempotency identities across attempts, and provider fencing
    /// for protected database writes. Remote effects remain at-least-once unless the remote
    /// independently enforces fencing; do not spawn work escaping the supplied control.
    fn apply<T: Timer>(
        &self,
        claim: &C,
        diff: ReconcileDiff<Self::State>,
        control: &Control<'_, T>,
    ) -> impl Future<Output = Result<(), Error>> + Send;
}
