//! One bounded driver for both new execution and durable recovery.
//! ref: oxidecomputer/steno src/saga_exec.rs@main
use crate::action::Registered;
use crate::{
    Control, Definition, EffectContext, EffectOutcome, Error, Event, EventKind, Lease, Mutation,
    Phase, ReceiptContext, ReceiptProtection, Registry, SagaReceiptProtector, Scope, Snapshot,
    Status, Store, Timer,
};

/// Why a bounded invocation stopped after acknowledged durable progress.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunStop {
    /// All effects succeeded or their compensation completed.
    Completed,
    /// A compensation requires an explicit revision-checked resume.
    Paused,
    /// The invocation yielded after its advance budget; it can be scheduled again.
    Yielded,
}
/// Closed cause associated with a failed step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureKind {
    /// Proven forward failures exhausted the pinned retry policy.
    ForwardRetriesExhausted,
    /// A compensation was proven not applied and needs an explicit retry.
    CompensationNotApplied,
}
/// Safe step-level failure information; never carries provider messages or receipt bytes.
#[derive(Debug, Clone)]
pub struct Failure {
    /// Definition-owned step name.
    pub step: String,
    /// Closed failure classification.
    pub kind: FailureKind,
}
/// Executor-issued reference to an acknowledged successful instance and exact definition.
#[derive(Debug, Clone)]
pub struct SuccessReference {
    scope: Scope,
    definition: Definition,
}
impl SuccessReference {
    /// Tenant and instance to which this result belongs.
    pub const fn scope(&self) -> Scope {
        self.scope
    }
    /// Exact definition whose last action produced the result.
    pub fn definition(&self) -> &Definition {
        &self.definition
    }
}
/// Acknowledged progress. Inspect `stop` and `status`; a yielded invocation is not Saga success.
#[derive(Debug)]
#[must_use]
pub struct Report {
    /// Durable status after this invocation's last acknowledged transition.
    pub status: Status,
    /// Revision used for explicit compensation resume CAS.
    pub revision: u64,
    /// Number of driver advances consumed by this invocation.
    pub advances: u32,
    /// Completion, pause, or ordinary budget yield.
    pub stop: RunStop,
    /// Failure information for compensation or a paused compensation attempt.
    pub failure: Option<Failure>,
    /// Present only for an acknowledged successful Saga.
    pub success: Option<SuccessReference>,
}
fn report(scope: Scope, snapshot: &Snapshot, advances: u32) -> Report {
    let status = snapshot.status();
    let stop = if status.is_terminal() {
        RunStop::Completed
    } else if status == Status::CompensationFailed {
        RunStop::Paused
    } else {
        RunStop::Yielded
    };
    let failed_kind = if status == Status::CompensationFailed {
        Some(EventKind::CompensationFailed)
    } else if matches!(status, Status::Compensating | Status::Compensated) {
        Some(EventKind::Abort)
    } else {
        None
    };
    let failure = failed_kind
        .and_then(|kind| snapshot.events().iter().rev().find(|e| e.kind == kind))
        .map(|event| Failure {
            step: snapshot.definition().steps()[event.step].name().into(),
            kind: if event.kind == EventKind::Abort {
                FailureKind::ForwardRetriesExhausted
            } else {
                FailureKind::CompensationNotApplied
            },
        });
    let success = (status == Status::Succeeded).then(|| SuccessReference {
        scope,
        definition: snapshot.definition().clone(),
    });
    Report {
        status,
        revision: snapshot.revision(),
        advances,
        stop,
        failure,
        success,
    }
}
/// Caller-driven execution and recovery with exact definitions and mandatory receipt protection.
pub struct Executor<S, P> {
    store: S,
    protection: ReceiptProtection<P>,
    registry: Registry,
    lease_policy: crate::LeasePolicy,
}
impl<S: Store, P: SagaReceiptProtector> Executor<S, P> {
    /// Construct an unstarted executor with mandatory store, protection and exact registry; default leases last 30 seconds.
    pub fn new(store: S, protection: ReceiptProtection<P>, registry: Registry) -> Self {
        Self {
            store,
            protection,
            registry,
            lease_policy: crate::LeasePolicy::default(),
        }
    }
    /// Select explicit operational lease timing before execution starts.
    pub fn with_lease_policy(mut self, policy: crate::LeasePolicy) -> Self {
        self.lease_policy = policy;
        self
    }
    /// Borrow the provider for explicit resource lifecycle and storage operations.
    pub fn store(&self) -> &S {
        &self.store
    }
    /// Persist an exact registered definition for this authorized scope; only acknowledged registration succeeds.
    pub async fn register<T: Timer>(
        &self,
        scope: Scope,
        definition: &Definition,
        control: &Control<'_, T>,
    ) -> Result<(), Error> {
        self.registry.resolve(definition)?;
        control
            .run(self.store.register(scope, definition, control))
            .await
    }
    /// Recover and advance within one total deadline and driver budget. Yielding is reported separately from Saga completion.
    pub async fn run<T: Timer>(
        &self,
        scope: Scope,
        budget: u32,
        control: &Control<'_, T>,
    ) -> Result<Report, Error> {
        self.enter(scope, None, budget, control).await
    }
    /// Explicitly authorize one retry of a paused compensation at an exact revision.
    pub async fn resume<T: Timer>(
        &self,
        scope: Scope,
        expected_revision: u64,
        budget: u32,
        control: &Control<'_, T>,
    ) -> Result<Report, Error> {
        self.enter(scope, Some(expected_revision), budget, control)
            .await
    }
    async fn enter<T: Timer>(
        &self,
        scope: Scope,
        resume: Option<u64>,
        budget: u32,
        control: &Control<'_, T>,
    ) -> Result<Report, Error> {
        if budget == 0 {
            return Err(Error::new(crate::ErrorKind::Budget));
        }
        control.check()?;
        let lease = control
            .run(self.store.claim(scope, self.lease_policy.ttl(), control))
            .await?;
        // Bound the size of the public future when a provider has large native async futures.
        // Two allocations per invocation also keep debug builds within ordinary worker stacks.
        let renewal = Box::pin(self.renew_until_done(&lease, control));
        let work = Box::pin(self.recover(&lease, resume, budget, control));
        let result = tokio::select! {
            biased;
            work = work => work,
            renewal = renewal => Err(renewal),
        };
        // Unknown/cancelled writes leave authority to expire: another write cannot prove settlement.
        if !matches!(
            result,
            Err(ref failure) if matches!(failure.kind(),crate::ErrorKind::CommitUnknown
                | crate::ErrorKind::RollbackUnknown
                | crate::ErrorKind::Cancelled
                | crate::ErrorKind::Deadline
                | crate::ErrorKind::Fenced)
        ) {
            control.run(self.store.release(&lease, control)).await?;
        }
        result
    }
    async fn renew_until_done<T: Timer>(&self, lease: &Lease, control: &Control<'_, T>) -> Error {
        loop {
            if let Err(error) = control.wait(self.lease_policy.renewal_interval()).await {
                return error;
            }
            if let Err(error) = control
                .run(self.store.renew(lease, self.lease_policy.ttl(), control))
                .await
            {
                return error;
            }
        }
    }
    async fn recover<T: Timer>(
        &self,
        lease: &Lease,
        resume: Option<u64>,
        budget: u32,
        control: &Control<'_, T>,
    ) -> Result<Report, Error> {
        let mut snapshot = control.run(self.store.snapshot(lease, control)).await?;
        let entry = self.registry.resolve(snapshot.definition())?;
        self.verify_receipts(lease.scope(), &snapshot, control)
            .await?;
        if let Some(revision) = resume {
            if revision != snapshot.revision() || snapshot.status() != Status::CompensationFailed {
                return Err(Error::new(crate::ErrorKind::Conflict));
            }
            let step = snapshot
                .progress()
                .completed
                .last()
                .ok_or(Error::new(crate::ErrorKind::Integrity))?
                .0;
            let event = Event {
                seq: revision,
                step,
                attempt: snapshot.progress().compensation_attempts[step],
                kind: EventKind::Resume,
                receipt: None,
            };
            snapshot = self.commit(lease, snapshot, event, control).await?;
        }
        for advances in 0..budget {
            control.check()?;
            if snapshot.status().is_terminal() || snapshot.status() == Status::CompensationFailed {
                return Ok(report(lease.scope(), &snapshot, advances));
            }
            snapshot = self.advance(lease, snapshot, &entry, control).await?;
        }
        Ok(report(lease.scope(), &snapshot, budget))
    }
    /// Resolve an acknowledged final receipt using the witness issued when its Step was registered.
    /// The stored row and actual registered Rust receipt type are rechecked before decoding.
    pub async fn success_receipt<R: serde::de::DeserializeOwned + 'static, T: Timer>(
        &self,
        reference: &SuccessReference,
        completion: &crate::Completion<R>,
        control: &Control<'_, T>,
    ) -> Result<R, Error> {
        if completion.definition != reference.definition {
            return Err(Error::new(crate::ErrorKind::ReceiptType));
        }
        let registered = self.registry.resolve(&reference.definition)?;
        if registered.actions[completion.step].receipt_type() != std::any::TypeId::of::<R>() {
            return Err(Error::new(crate::ErrorKind::ReceiptType));
        }
        let lease = control
            .run(
                self.store
                    .claim(reference.scope, self.lease_policy.ttl(), control),
            )
            .await?;
        let snapshot = control.run(self.store.snapshot(&lease, control)).await;
        let release = control.run(self.store.release(&lease, control)).await;
        // Preserve the read failure, but always attempt bounded cleanup after a successful claim.
        let snapshot = snapshot?;
        release?;
        if snapshot.status() != Status::Succeeded || snapshot.definition() != &reference.definition
        {
            return Err(Error::new(crate::ErrorKind::ReceiptUnavailable));
        }
        let event = snapshot
            .events()
            .iter()
            .find(|e| e.step == completion.step && e.kind == EventKind::ForwardApplied)
            .ok_or_else(|| Error::new(crate::ErrorKind::ReceiptUnavailable))?;
        let receipt = event
            .receipt
            .as_ref()
            .ok_or_else(|| Error::new(crate::ErrorKind::Integrity))?;
        let context = ReceiptContext::new(
            reference.scope,
            &reference.definition,
            completion.step,
            event.attempt,
            event.seq,
        )?;
        let plaintext = control.run(self.protection.open(receipt, &context)).await?;
        serde_json::from_slice(plaintext.expose())
            .map_err(|_| Error::new(crate::ErrorKind::ReceiptType))
    }
    async fn verify_receipts<T: Timer>(
        &self,
        scope: Scope,
        snapshot: &Snapshot,
        control: &Control<'_, T>,
    ) -> Result<(), Error> {
        for event in snapshot.events() {
            if let Some(receipt) = &event.receipt {
                let context = ReceiptContext::new(
                    scope,
                    snapshot.definition(),
                    event.step,
                    event.attempt,
                    event.seq,
                )?;
                control.run(self.protection.open(receipt, &context)).await?;
            }
        }
        Ok(())
    }
    async fn commit<T: Timer>(
        &self,
        lease: &Lease,
        snapshot: Snapshot,
        event: Event,
        control: &Control<'_, T>,
    ) -> Result<Snapshot, Error> {
        let mutation = Mutation::new(&snapshot, event.clone())?;
        control
            .run(self.store.commit(lease, mutation, control))
            .await
            .map_err(Error::uncertain)?;
        snapshot.apply(event)
    }
    async fn advance<T: Timer>(
        &self,
        lease: &Lease,
        mut snapshot: Snapshot,
        entry: &Registered,
        control: &Control<'_, T>,
    ) -> Result<Snapshot, Error> {
        let recovery = snapshot.progress().pending.is_some();
        let intent = if let Some(event) = snapshot.progress().pending.clone() {
            event
        } else {
            let p = snapshot.progress();
            let (step, attempt, kind) = if p.status == Status::Compensating {
                let step = p
                    .completed
                    .last()
                    .ok_or(Error::new(crate::ErrorKind::Integrity))?
                    .0;
                (
                    step,
                    p.compensation_attempts[step]
                        .checked_add(1)
                        .ok_or(Error::new(crate::ErrorKind::Integrity))?,
                    EventKind::CompensationIntent,
                )
            } else {
                let step = p.forward;
                let attempts = p.forward_attempts[step];
                if p.forward_failures[step] >= entry.definition.steps()[step].max_failures() {
                    let event = Event {
                        seq: snapshot.revision(),
                        step,
                        attempt: attempts,
                        kind: EventKind::Abort,
                        receipt: None,
                    };
                    return self.commit(lease, snapshot, event, control).await;
                }
                (
                    step,
                    attempts
                        .checked_add(1)
                        .ok_or(Error::new(crate::ErrorKind::Integrity))?,
                    EventKind::ForwardIntent,
                )
            };
            let event = Event {
                seq: snapshot.revision(),
                step,
                attempt,
                kind,
                receipt: None,
            };
            snapshot = self.commit(lease, snapshot, event.clone(), control).await?;
            event
        };
        let event = if intent.kind == EventKind::ForwardIntent {
            self.forward(lease.scope(), &snapshot, entry, &intent, recovery, control)
                .await?
        } else {
            self.compensate(lease.scope(), &snapshot, entry, &intent, recovery, control)
                .await?
        };
        self.commit(lease, snapshot, event, control).await
    }
    async fn forward<T: Timer>(
        &self,
        scope: Scope,
        snapshot: &Snapshot,
        entry: &Registered,
        intent: &Event,
        probe: bool,
        control: &Control<'_, T>,
    ) -> Result<Event, Error> {
        let context = EffectContext::new(scope, &entry.definition, intent.step, Phase::Forward)?;
        let outcome = control
            .run(entry.actions[intent.step].execute(context, probe))
            .await?;
        let (kind, receipt) = match outcome {
            EffectOutcome::Applied(plaintext) => {
                let context = ReceiptContext::new(
                    scope,
                    &entry.definition,
                    intent.step,
                    intent.attempt,
                    snapshot.revision(),
                )?;
                (
                    EventKind::ForwardApplied,
                    Some(
                        control
                            .run(self.protection.seal(plaintext, &context))
                            .await?,
                    ),
                )
            }
            EffectOutcome::NotApplied if probe => (EventKind::ForwardProbeNotApplied, None),
            EffectOutcome::NotApplied => (EventKind::ForwardNotApplied, None),
            EffectOutcome::Unknown => return Err(Error::new(crate::ErrorKind::EffectUnknown)),
        };
        Ok(Event {
            seq: snapshot.revision(),
            step: intent.step,
            attempt: intent.attempt,
            kind,
            receipt,
        })
    }
    async fn compensate<T: Timer>(
        &self,
        scope: Scope,
        snapshot: &Snapshot,
        entry: &Registered,
        intent: &Event,
        probe: bool,
        control: &Control<'_, T>,
    ) -> Result<Event, Error> {
        let (step, receipt) = snapshot
            .progress()
            .completed
            .last()
            .ok_or(Error::new(crate::ErrorKind::Integrity))?;
        if *step != intent.step {
            return Err(Error::new(crate::ErrorKind::Integrity));
        }
        let context = ReceiptContext::new(
            scope,
            &entry.definition,
            *step,
            receipt.attempt(),
            receipt.completed_seq(),
        )?;
        let plaintext = control.run(self.protection.open(receipt, &context)).await?;
        let effect_context =
            EffectContext::new(scope, &entry.definition, *step, Phase::Compensation)?;
        let outcome = control
            .run(entry.actions[*step].compensate(effect_context, plaintext, probe))
            .await?;
        // A negative probe authorizes a fresh attempt; it does not declare a failed compensation.
        let kind = match outcome {
            EffectOutcome::Applied(()) => EventKind::CompensationApplied,
            EffectOutcome::NotApplied if probe => EventKind::CompensationNotApplied,
            EffectOutcome::NotApplied => EventKind::CompensationFailed,
            EffectOutcome::Unknown => return Err(Error::new(crate::ErrorKind::EffectUnknown)),
        };
        Ok(Event {
            seq: snapshot.revision(),
            step: *step,
            attempt: intent.attempt,
            kind,
            receipt: None,
        })
    }
    /// Run one fair page. Pass back `next_cursor` on the next call; None restarts at the beginning.
    /// Each admitted instance receives at most one advance, including probes. Instance errors are
    /// retained in the report; cancellation/deadline returns all already observed progress.
    pub async fn run_once<T: Timer>(
        &self,
        tenant: rss_request_context::TenantId,
        cursor: Option<Scope>,
        budget: SweepBudget,
        control: &Control<'_, T>,
    ) -> Result<SweepReport, Error> {
        if cursor.is_some_and(|s| s.tenant() != tenant) {
            return Err(Error::new(crate::ErrorKind::Definition));
        }
        let limit = budget.instances.min(budget.advances);
        let candidates = control
            .run(
                self.store
                    .candidates(tenant, cursor.map(|s| s.id()), limit, control),
            )
            .await?;
        validate_candidates(&candidates, tenant, cursor, limit)?;
        let mut report = SweepReport {
            items: vec![],
            next_cursor: cursor,
            stop: SweepStop::PageComplete,
        };
        if candidates.is_empty() {
            report.next_cursor = None;
            return Ok(report);
        }
        for scope in candidates {
            if let Err(error) = control.check() {
                report.stop = sweep_stop(error.kind());
                break;
            }
            let result = self.run(scope, 1, control).await;
            let interrupted =
                result.as_ref().err().map(|e| e.kind()).filter(|k| {
                    matches!(k, crate::ErrorKind::Cancelled | crate::ErrorKind::Deadline)
                });
            report.items.push(InstanceResult { scope, result });
            report.next_cursor = Some(scope);
            if let Some(kind) = interrupted {
                report.stop = sweep_stop(kind);
                break;
            }
        }
        Ok(report)
    }
}
#[cfg(feature = "rss-runtime")]
impl<S: Store + 'static, P: SagaReceiptProtector + 'static> Executor<S, P> {
    /// Register a single bounded run from a caller-retained shared executor with its lifecycle slot. The receiver carries the
    /// execution result, including a paused compensation; task completion alone is not success.
    pub fn into_registration<T: Timer + 'static>(
        self: std::sync::Arc<Self>,
        start: rss_runtime::TaskStart,
        timer: T,
        scope: Scope,
        budget: u32,
        duration: std::time::Duration,
    ) -> (
        rss_runtime::ManagedTaskRegistration,
        tokio::sync::oneshot::Receiver<Result<Report, Error>>,
    ) {
        let (send, receive) = tokio::sync::oneshot::channel();
        let registration = start.into_registration(move |token| async move {
            let control = Control::new(&timer, timer.now().saturating_add(duration), &token);
            let result = self.run(scope, budget, &control).await;
            let failure = result.as_ref().err().cloned();
            let cancelled = token.is_cancelled()
                && failure
                    .as_ref()
                    .is_some_and(|e| e.kind() == crate::ErrorKind::Cancelled);
            let _ = send.send(result); // Dropping the receiver does not cancel lifecycle cleanup.
            if cancelled {
                return Ok(());
            }
            failure.map_or(Ok(()), |error| Err(rss_runtime::ShutdownError::new(error)))
        });
        (registration, receive)
    }
}

/// Upper bounds for one sweep; every instance admission consumes an advance allocation.
#[derive(Debug, Clone, Copy)]
pub struct SweepBudget {
    instances: u32,
    advances: u32,
}
impl SweepBudget {
    /// Require nonzero bounds and at most 10,000 candidate instances per sweep.
    pub fn new(instances: u32, advances: u32) -> Result<Self, Error> {
        if instances == 0 || instances > 10_000 || advances == 0 {
            return Err(Error::new(crate::ErrorKind::Budget));
        }
        Ok(Self {
            instances,
            advances,
        })
    }
}
/// A per-instance result; failure of one instance does not discard its peers' progress.
#[derive(Debug)]
pub struct InstanceResult {
    /// Tenant and instance that was admitted.
    pub scope: Scope,
    /// Acknowledged progress or the instance's recovery error.
    pub result: Result<Report, Error>,
}
/// Reason this bounded sweep stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SweepStop {
    /// The requested page was processed; continue from its cursor on the next sweep.
    PageComplete,
    /// The caller cancelled; earlier results remain available.
    Cancelled,
    /// The shared deadline expired; earlier results remain available.
    Deadline,
}
/// Fair bounded sweep progress. An empty final page resets the cursor for the next pass.
#[derive(Debug)]
#[must_use]
pub struct SweepReport {
    /// Results in candidate order, including expected per-instance failures.
    pub items: Vec<InstanceResult>,
    /// Pass back on the next sweep; scope binding prevents cross-tenant cursor reuse.
    pub next_cursor: Option<Scope>,
    /// Shared stop reason, independent of individual Saga outcomes.
    pub stop: SweepStop,
}
fn sweep_stop(kind: crate::ErrorKind) -> SweepStop {
    if kind == crate::ErrorKind::Cancelled {
        SweepStop::Cancelled
    } else {
        SweepStop::Deadline
    }
}
fn validate_candidates(
    candidates: &[Scope],
    tenant: rss_request_context::TenantId,
    cursor: Option<Scope>,
    limit: u32,
) -> Result<(), Error> {
    if candidates.len() > limit as usize {
        return Err(Error::new(crate::ErrorKind::Integrity));
    }
    let mut after = cursor.map(|s| s.id());
    for scope in candidates {
        if scope.tenant() != tenant || after.is_some_and(|id| scope.id() <= id) {
            return Err(Error::new(crate::ErrorKind::Integrity));
        }
        after = Some(scope.id());
    }
    Ok(())
}
