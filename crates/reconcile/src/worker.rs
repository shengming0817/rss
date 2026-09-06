//! ref: kube-rs kube-runtime/src/controller/mod.rs@f2774b13d66910a8a0fe456cc8e6e52414eb1d0e
use crate::{
    Claim, Completion, Control, DriftKind, DurableStore, Error, ErrorKind, Policy, Reconciler,
    Scope, Target, Timer,
};
use futures::{StreamExt, future::BoxFuture, stream::FuturesUnordered};
use std::{collections::HashSet, time::Duration};
use tokio::sync::Notify;
/// The core operation that produced an observed target failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    Observe,
    Apply,
    Renew,
    Finish,
}
/// Owned failure diagnostics. Error sources remain redacted; no business snapshot is exposed.
#[derive(Debug, Clone)]
pub enum Observation {
    /// A target failure, including the original reason when Retry/Suspended was persisted.
    AttemptFailed {
        target: Target,
        stage: Stage,
        error: Error,
    },
    /// A scan operation failed; its scope is known, its possibly committed claim count is not.
    ScanFailed { scope: Scope, error: Error },
}
/// Counts of completed observations; these are not commit receipts for business effects.
#[derive(Debug, Default, Clone, Copy)]
pub struct Report {
    pub converged: u64,
    pub reobserve: u64,
    pub retried: u64,
    pub suspended: u64,
    pub fenced: u64,
    /// Target attempts with an execution/settlement failure, distinct from scheduled retries.
    pub execution_failed: u64,
    /// Failed scan operations, not target counts.
    pub scan_failed: u64,
    /// Batches with unconfirmed claim commit; their target count is unknown.
    pub claim_unknown_batches: u64,
}
struct Failure {
    stage: Stage,
    error: Error,
}
struct Outcome {
    result: Result<Completion, Failure>,
    prior: Option<Failure>,
}
impl Outcome {
    fn failed(stage: Stage, error: Error) -> Self {
        Self {
            result: Err(Failure { stage, error }),
            prior: None,
        }
    }
}
type Tasks<'a> = FuturesUnordered<BoxFuture<'a, (Target, Outcome)>>;
struct Active<'a, F> {
    tasks: Tasks<'a>,
    targets: HashSet<Target>,
    report: Report,
    observe: F,
}
impl<F: FnMut(Observation)> Active<'_, F> {
    fn record(&mut self, target: Target, outcome: Outcome) {
        self.targets.remove(&target);
        if let Some(failure) = outcome.prior {
            self.emit(&target, failure);
        }
        match outcome.result {
            Ok(Completion::Converged) => self.report.converged += 1,
            Ok(Completion::Reobserve(_)) => self.report.reobserve += 1,
            Ok(Completion::Retry { .. }) => self.report.retried += 1,
            Ok(Completion::Suspended { .. }) => self.report.suspended += 1,
            Err(failure) => {
                if failure.error.kind() == ErrorKind::Fenced {
                    self.report.fenced += 1;
                } else {
                    self.report.execution_failed += 1;
                }
                self.emit(&target, failure);
            }
        }
    }
    fn emit(&mut self, target: &Target, failure: Failure) {
        (self.observe)(Observation::AttemptFailed {
            target: target.clone(),
            stage: failure.stage,
            error: failure.error,
        });
    }
    fn scan_error(&mut self, scope: &Scope, error: Error) {
        if error.kind() == ErrorKind::CommitUnknown {
            self.report.claim_unknown_batches += 1;
        } else {
            self.report.scan_failed += 1;
        }
        (self.observe)(Observation::ScanFailed {
            scope: scope.clone(),
            error,
        });
    }
}
/// Run from durable startup/periodic scans until cancellation/deadline. No dummy Notify needed.
/// Diagnostics are delivered synchronously at attempt completion; keep the observer nonblocking.
/// Panic propagates unchanged to the caller. No detached tasks: drop cancels all in-flight work.
pub async fn run<
    S: DurableStore,
    R: Reconciler<S::Claim>,
    T: Timer,
    F: FnMut(Observation) + Send,
>(
    store: &S,
    reconciler: &R,
    scope: &Scope,
    policy: Policy,
    control: &Control<'_, T>,
    observe: F,
) -> Result<Report, Error> {
    run_inner(store, reconciler, scope, policy, control, None, observe).await
}
/// Additionally accept best-effort wake hints; durable scans remain the recovery authority.
pub async fn run_with_notify<
    S: DurableStore,
    R: Reconciler<S::Claim>,
    T: Timer,
    F: FnMut(Observation) + Send,
>(
    store: &S,
    reconciler: &R,
    scope: &Scope,
    policy: Policy,
    control: &Control<'_, T>,
    notify: &Notify,
    observe: F,
) -> Result<Report, Error> {
    run_inner(
        store,
        reconciler,
        scope,
        policy,
        control,
        Some(notify),
        observe,
    )
    .await
}
async fn run_inner<
    S: DurableStore,
    R: Reconciler<S::Claim>,
    T: Timer,
    F: FnMut(Observation) + Send,
>(
    store: &S,
    reconciler: &R,
    scope: &Scope,
    policy: Policy,
    control: &Control<'_, T>,
    notify: Option<&Notify>,
    observe: F,
) -> Result<Report, Error> {
    let mut active = Active {
        tasks: FuturesUnordered::new(),
        targets: HashSet::new(),
        report: Report::default(),
        observe,
    };
    loop {
        if control.check().is_err() {
            return Ok(active.report);
        }
        if active.tasks.len() < policy.concurrency {
            let before = active.tasks.len();
            let started = control.elapsed();
            let available = policy.concurrency - before;
            let batch = claim_round(store, scope, available, policy, control, &mut active).await;
            let freed = active.tasks.len() < before;
            match batch {
                Ok(claims) => {
                    if claims.len() > available {
                        return Err(Error::new(ErrorKind::Invariant));
                    }
                    for claim in claims {
                        let target = claim.target().clone();
                        if target.scope() != scope || !active.targets.insert(target.clone()) {
                            return Err(Error::new(ErrorKind::Invariant));
                        }
                        active.tasks.push(Box::pin(async move {
                            (
                                target,
                                execute(store, reconciler, claim, policy, control, started).await,
                            )
                        }));
                    }
                }
                Err(e)
                    if matches!(e.kind(), ErrorKind::Cancelled | ErrorKind::Deadline)
                        && control.check().is_err() =>
                {
                    return Ok(active.report);
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        ErrorKind::Transient | ErrorKind::Deadline | ErrorKind::CommitUnknown
                    ) =>
                {
                    active.scan_error(scope, e)
                }
                Err(e) => return Err(e),
            }
            if freed && active.tasks.len() < policy.concurrency {
                continue;
            }
        }
        let event = control
            .run(async {
                tokio::select! {
                    result=active.tasks.next(),if !active.tasks.is_empty()=>Ok(result),
                    ()=wake_hint(notify)=>Ok(None),
                    ()=control.sleep(policy.scan)=>Ok(None),
                }
            })
            .await;
        match event {
            Ok(Some((target, outcome))) => active.record(target, outcome),
            Ok(None) => {}
            Err(_) => return Ok(active.report),
        }
    }
}
async fn wake_hint(notify: Option<&Notify>) {
    // reason: timer-only runs have no optional wake source to poll.
    match notify {
        Some(notify) => notify.notified().await,
        None => std::future::pending().await,
    }
}
async fn claim_round<S: DurableStore, T: Timer, F: FnMut(Observation) + Send>(
    store: &S,
    scope: &Scope,
    available: usize,
    policy: Policy,
    control: &Control<'_, T>,
    active: &mut Active<'_, F>,
) -> Result<Vec<S::Claim>, Error> {
    let scan_control = control.child(policy.attempt);
    let scan = scan_control.run(store.claim_due(scope, available, policy.lease, &scan_control));
    tokio::pin!(scan);
    loop {
        tokio::select! {
            result=&mut scan=>return result,
            Some((target,outcome))=active.tasks.next(),if !active.tasks.is_empty()=>active.record(target,outcome),
        }
    }
}
async fn action<C: Claim, R: Reconciler<C>, T: Timer>(
    reconciler: &R,
    claim: &C,
    policy: Policy,
    control: &Control<'_, T>,
) -> Result<Completion, Failure> {
    let diff = control
        .run(reconciler.observe(claim, control))
        .await
        .map_err(|error| Failure {
            stage: Stage::Observe,
            error,
        })?;
    if diff.drift() == DriftKind::Converged {
        return Ok(Completion::Converged);
    }
    control
        .run(reconciler.apply(claim, diff, control))
        .await
        .map_err(|error| Failure {
            stage: Stage::Apply,
            error,
        })?;
    Ok(Completion::Reobserve(policy.scan))
}
async fn execute<S: DurableStore, R: Reconciler<S::Claim>, T: Timer>(
    store: &S,
    reconciler: &R,
    claim: S::Claim,
    policy: Policy,
    outer: &Control<'_, T>,
    claimed_at: Duration,
) -> Outcome {
    let mut renew_at = claimed_at.saturating_add(policy.lease / 3);
    if outer.elapsed() >= renew_at {
        match renew_lease(store, &claim, policy, outer).await {
            Ok(at) => renew_at = at,
            Err(e) => return Outcome::failed(Stage::Renew, e),
        }
    }
    let control = outer.child(policy.attempt);
    let action = action(reconciler, &claim, policy, &control);
    tokio::pin!(action);
    let outcome = loop {
        tokio::select! {
            result=&mut action=>break result,
            renewed=async {outer.sleep_until(renew_at).await;renew_lease(store,&claim,policy,outer).await}=>match renewed {Ok(at)=>renew_at=at,Err(e)=>return Outcome::failed(Stage::Renew,e)},
        }
    };
    settle(store, &claim, policy, outer, outcome).await
}
async fn settle<S: DurableStore, T: Timer>(
    store: &S,
    claim: &S::Claim,
    policy: Policy,
    control: &Control<'_, T>,
    outcome: Result<Completion, Failure>,
) -> Outcome {
    let (completion, prior) = match outcome {
        Ok(completion) => (completion, None),
        Err(failure)
            if matches!(
                failure.error.kind(),
                ErrorKind::Fenced
                    | ErrorKind::Cancelled
                    | ErrorKind::CommitUnknown
                    | ErrorKind::RollbackFailed
            ) =>
        {
            return Outcome {
                result: Err(failure),
                prior: None,
            };
        }
        Err(failure) => {
            let failures = claim.failures().saturating_add(1);
            let completion = if matches!(
                failure.error.kind(),
                ErrorKind::Permanent
                    | ErrorKind::Invariant
                    | ErrorKind::StorageContract
                    | ErrorKind::InvalidInput
            ) || failures >= policy.max_attempts
            {
                Completion::Suspended { failures }
            } else {
                Completion::Retry {
                    after: policy.backoff(failures),
                    failures,
                }
            };
            (completion, Some(failure))
        }
    };
    let result = control
        .run(store.finish(claim, completion, control))
        .await
        .map(|()| completion)
        .map_err(|error| Failure {
            stage: Stage::Finish,
            error,
        });
    Outcome { result, prior }
}
async fn renew_lease<S: DurableStore, T: Timer>(
    store: &S,
    claim: &S::Claim,
    policy: Policy,
    outer: &Control<'_, T>,
) -> Result<Duration, Error> {
    let started = outer.elapsed();
    let control = outer.child(policy.lease / 3);
    control
        .run(store.renew(claim, policy.lease, &control))
        .await?;
    Ok(started.saturating_add(policy.lease / 3))
}
