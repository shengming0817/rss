//! ref: kube-rs kube-runtime/src/controller/mod.rs@f2774b13d66910a8a0fe456cc8e6e52414eb1d0e
use crate::{
    Claim, ClaimBatch, Completion, Control, DriftKind, DurableStore, Error, ErrorKind, Policy,
    ReconcileStep, Reconciler, Scope, Target, Timer,
};
use futures::{StreamExt, future::BoxFuture, stream::FuturesUnordered};
use std::{
    collections::{BTreeSet, HashSet},
    time::Duration,
};
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;
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
    /// Normal waiting, emitted only after the deferred schedule is durably acknowledged.
    Deferred { target: Target },
    /// A scan operation failed; its scope is known, its possibly committed claim count is not.
    ScanFailed { scope: Scope, error: Error },
}
/// Counts of completed observations; these are not commit receipts for business effects.
#[derive(Debug, Default, Clone, Copy)]
pub struct Report {
    pub converged: u64,
    pub reobserve: u64,
    pub deferred: u64,
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
    prior: Vec<Failure>,
}
impl Outcome {
    fn failed(stage: Stage, error: Error) -> Self {
        Self {
            result: Err(Failure { stage, error }),
            prior: Vec::new(),
        }
    }
}
type Tasks<'a> = FuturesUnordered<BoxFuture<'a, (Target, Outcome)>>;
struct Active<'a, F> {
    tasks: Tasks<'a>,
    targets: HashSet<Target>,
    report: Report,
    observe: F,
    due: BTreeSet<Duration>,
    idle_scan: Duration,
}
impl<F: FnMut(Observation)> Active<'_, F> {
    async fn drain<T: Timer>(&mut self, control: &Control<'_, T>) -> Result<(), Error> {
        while !self.tasks.is_empty() {
            if let Some((target, outcome)) =
                control.run(async { Ok(self.tasks.next().await) }).await?
            {
                self.record(target, outcome, control.elapsed());
            }
        }
        Ok(())
    }
    fn record(&mut self, target: Target, outcome: Outcome, now: Duration) {
        if let Ok(
            Completion::Reobserve(after)
            | Completion::Deferred(after)
            | Completion::Retry { after, .. },
        ) = &outcome.result
        {
            self.schedule(now, *after);
        }
        self.targets.remove(&target);
        for failure in outcome.prior {
            self.emit(&target, failure);
        }
        match outcome.result {
            Ok(Completion::Converged) => self.report.converged += 1,
            Ok(Completion::Reobserve(_)) => self.report.reobserve += 1,
            Ok(Completion::Deferred(_)) => {
                self.report.deferred += 1;
                (self.observe)(Observation::Deferred { target });
            }
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
    fn schedule(&mut self, now: Duration, after: Duration) {
        // Longer deadlines are covered by the recovery scan. These hints carry no
        // claim authority and exist only after acknowledged settlement.
        if after < self.idle_scan {
            self.due.insert(now.saturating_add(after));
        }
    }
    fn scanned_through(&mut self, started: Duration) {
        // A deadline reached during a slow scan still needs a subsequent scan.
        while self.due.first().is_some_and(|due| *due <= started) {
            self.due.pop_first();
        }
    }
    fn delay(&self, now: Duration) -> Duration {
        self.due.first().map_or(self.idle_scan, |due| {
            due.saturating_sub(now).min(self.idle_scan)
        })
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
/// Run durable scans until `stop`, then await all acquired work and its settlement.
/// `control` remains the hard execution deadline/cancellation boundary. During draining,
/// interruption returns an error, never a successful drain. Dropping the future aborts work.
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
    stop: &CancellationToken,
    observe: F,
) -> Result<Report, Error> {
    run_inner(
        store, reconciler, scope, policy, control, stop, None, observe,
    )
    .await
}
/// Additionally accept best-effort wake hints; durable scans remain the recovery authority.
#[allow(
    clippy::too_many_arguments,
    reason = "stop admission and hard execution control are distinct caller-owned signals"
)]
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
    stop: &CancellationToken,
    notify: &Notify,
    observe: F,
) -> Result<Report, Error> {
    run_inner(
        store,
        reconciler,
        scope,
        policy,
        control,
        stop,
        Some(notify),
        observe,
    )
    .await
}
#[allow(
    clippy::too_many_arguments,
    reason = "one runner owns both admission and active execution"
)]
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
    stop: &CancellationToken,
    notify: Option<&Notify>,
    observe: F,
) -> Result<Report, Error> {
    let mut active = Active {
        tasks: FuturesUnordered::new(),
        targets: HashSet::new(),
        report: Report::default(),
        observe,
        due: BTreeSet::new(),
        idle_scan: policy.idle_scan,
    };
    loop {
        if stop.is_cancelled() {
            active.drain(control).await?;
            return Ok(active.report);
        }
        if control.check().is_err() {
            return Ok(active.report);
        }
        if active.tasks.len() < policy.concurrency {
            let before = active.tasks.len();
            let started = control.elapsed();
            let available = policy.concurrency - before;
            let batch = claim_round(store, scope, available, policy, control, &mut active).await;
            active.scanned_through(started);
            let freed = active.tasks.len() < before;
            let mut more = false;
            match batch {
                Ok(batch) => {
                    more = batch.more;
                    let claims = batch.claims;
                    if claims.len() > available {
                        active.drain(control).await?;
                        return Err(Error::new(ErrorKind::Invariant));
                    }
                    for claim in claims {
                        let target = claim.target().clone();
                        if target.scope() != scope || !active.targets.insert(target.clone()) {
                            active.drain(control).await?;
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
                    if stop.is_cancelled() {
                        return Err(e);
                    }
                    return Ok(active.report);
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        ErrorKind::Transient | ErrorKind::Deadline | ErrorKind::CommitUnknown
                    ) =>
                {
                    active.scan_error(scope, e);
                    active.schedule(control.elapsed(), policy.scan);
                }
                Err(e) => {
                    active.scan_error(scope, e.clone());
                    active.drain(control).await?;
                    return Err(e);
                }
            }
            if (freed || more) && active.tasks.len() < policy.concurrency {
                tokio::task::yield_now().await;
                continue;
            }
        }
        let delay = active.delay(control.elapsed());
        let available = active.tasks.len() < policy.concurrency;
        let event = control
            .run(async {
                tokio::select! {
                    ()=stop.cancelled()=>Ok(None),
                    result=active.tasks.next(),if !active.tasks.is_empty()=>Ok(result),
                    ()=wake_hint(notify),if available=>Ok(None),
                    ()=control.sleep(delay),if available=>Ok(None),
                }
            })
            .await;
        match event {
            Ok(Some((target, outcome))) => active.record(target, outcome, control.elapsed()),
            Ok(None) => {}
            Err(error) if stop.is_cancelled() => return Err(error),
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
) -> Result<ClaimBatch<S::Claim>, Error> {
    let scan_control = control.child(policy.attempt);
    let scan = scan_control.run(store.claim_due(scope, available, policy.lease, &scan_control));
    tokio::pin!(scan);
    loop {
        tokio::select! {
            result=&mut scan=>return result,
            Some((target,outcome))=active.tasks.next(),if !active.tasks.is_empty()=>active.record(target,outcome,control.elapsed()),
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
    let diff = match diff {
        ReconcileStep::Ready(diff) => diff,
        ReconcileStep::Deferred(after) => return Ok(Completion::Deferred(after)),
    };
    if diff.drift() == DriftKind::Converged {
        return Ok(Completion::Converged);
    }
    let applied = control
        .run(reconciler.apply(claim, diff, control))
        .await
        .map_err(|error| Failure {
            stage: Stage::Apply,
            error,
        })?;
    Ok(match applied {
        ReconcileStep::Ready(()) => Completion::Reobserve(policy.scan),
        ReconcileStep::Deferred(after) => Completion::Deferred(after),
    })
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
    let outcome =
        attempt_with_renewal(store, reconciler, &claim, policy, outer, &mut renew_at).await;
    if let Err(failure) = &outcome
        && failure.stage == Stage::Renew
    {
        return Outcome::failed(Stage::Renew, failure.error.clone());
    }
    let finish = settle(store, &claim, policy, outer, outcome);
    tokio::pin!(finish);
    loop {
        tokio::select! {
            biased;
            outcome = &mut finish => return outcome,
            renewed = async { outer.sleep_until(renew_at).await; renew_lease(store, &claim, policy, outer).await } => match renewed {
                Ok(at) => renew_at = at,
                Err(error) => {
                    // A committed finish releases its token before the receipt may arrive.
                    // Never discard that receipt in response to a concurrent renewal failure.
                    let mut outcome = finish.await;
                    if outcome.result.is_err() && error.kind() != ErrorKind::BindingChanged {
                        outcome.prior.push(Failure { stage: Stage::Renew, error });
                    }
                    return outcome;
                }
            },
        }
    }
}
async fn attempt_with_renewal<S: DurableStore, R: Reconciler<S::Claim>, T: Timer>(
    store: &S,
    reconciler: &R,
    claim: &S::Claim,
    policy: Policy,
    outer: &Control<'_, T>,
    renew_at: &mut Duration,
) -> Result<Completion, Failure> {
    if outer.elapsed() >= *renew_at {
        match renew_lease(store, claim, policy, outer).await {
            Ok(at) => *renew_at = at,
            Err(error) if error.kind() == ErrorKind::BindingChanged => {
                return Ok(Completion::Deferred(policy.scan));
            }
            Err(error) => {
                return Err(Failure {
                    stage: Stage::Renew,
                    error,
                });
            }
        }
    }
    let control = outer.child(policy.attempt);
    let action = action(reconciler, claim, policy, &control);
    tokio::pin!(action);
    loop {
        tokio::select! {
            result=&mut action=>return result,
            renewed=async {outer.sleep_until(*renew_at).await;renew_lease(store,claim,policy,outer).await}=>match renewed {
                Ok(at)=>*renew_at=at,
                Err(error) if error.kind()==ErrorKind::BindingChanged=>return Ok(Completion::Deferred(policy.scan)),
                Err(error)=>return Err(Failure { stage: Stage::Renew,error }),
            },
        }
    }
}
async fn settle<S: DurableStore, T: Timer>(
    store: &S,
    claim: &S::Claim,
    policy: Policy,
    control: &Control<'_, T>,
    outcome: Result<Completion, Failure>,
) -> Outcome {
    let (mut completion, prior) = match outcome {
        Ok(completion) => (completion, Vec::new()),
        Err(failure) if failure.error.kind() == ErrorKind::BindingChanged => {
            (Completion::Deferred(policy.scan), Vec::new())
        }
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
                prior: Vec::new(),
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
                    after: policy.retry_delay(claim.target(), failures),
                    failures,
                }
            };
            (completion, vec![failure])
        }
    };
    let settlement = control.child(policy.attempt);
    let mut result = settlement
        .run(store.finish(claim, completion, &settlement))
        .await
        .map_err(Error::uncertain);
    if result
        .as_ref()
        .is_err_and(|e| e.kind() == ErrorKind::BindingChanged)
    {
        completion = Completion::Deferred(policy.scan);
        result = settlement
            .run(store.finish(claim, completion, &settlement))
            .await
            .map_err(Error::uncertain);
    }
    let result = result.map(|()| completion).map_err(|error| Failure {
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
