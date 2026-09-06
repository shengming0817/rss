mod support;
use rss_saga::*;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex, atomic::Ordering},
    time::Duration,
};
use support::*;
use tokio_util::sync::CancellationToken;

#[derive(Default, Clone)]
struct Memory(
    Arc<Mutex<HashMap<Scope, (Snapshot, Lease)>>>,
    Arc<std::sync::atomic::AtomicBool>,
    Arc<std::sync::atomic::AtomicU8>,
    Arc<std::sync::atomic::AtomicUsize>,
);
impl Store for Memory {
    async fn register<T: Timer>(
        &self,
        scope: Scope,
        d: &Definition,
        _: &Control<'_, T>,
    ) -> Result<(), Error> {
        let mut data = self
            .0
            .lock()
            .map_err(|_| Error::new(rss_saga::ErrorKind::Store))?;
        if let Some((snapshot, _)) = data.get(&scope) {
            if snapshot.definition() != d {
                return Err(Error::new(rss_saga::ErrorKind::Conflict));
            }
        } else {
            data.insert(
                scope,
                (
                    Snapshot::empty(d.clone()),
                    Lease::from_provider(scope, uuid::Uuid::new_v4(), 1)?,
                ),
            );
        }
        Ok(())
    }
    async fn claim<T: Timer>(
        &self,
        scope: Scope,
        _: Duration,
        _: &Control<'_, T>,
    ) -> Result<Lease, Error> {
        let mut data = self
            .0
            .lock()
            .map_err(|_| Error::new(rss_saga::ErrorKind::Store))?;
        let (_, lease) = data
            .get_mut(&scope)
            .ok_or(Error::new(rss_saga::ErrorKind::Store))?;
        // Deterministic test-only takeover substitutes for explicitly expired database leases.
        *lease = Lease::from_provider(scope, uuid::Uuid::new_v4(), lease.epoch() + 1)?;
        Ok(lease.clone())
    }
    async fn renew<T: Timer>(
        &self,
        _: &Lease,
        _: Duration,
        _: &Control<'_, T>,
    ) -> Result<(), Error> {
        Ok(())
    }
    async fn release<T: Timer>(&self, _: &Lease, _: &Control<'_, T>) -> Result<(), Error> {
        self.3.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    async fn snapshot<T: Timer>(&self, l: &Lease, _: &Control<'_, T>) -> Result<Snapshot, Error> {
        if self.2.load(Ordering::SeqCst) == 2 {
            return Err(Error::new(ErrorKind::Store));
        }
        self.0
            .lock()
            .map_err(|_| Error::new(rss_saga::ErrorKind::Store))?
            .get(&l.scope())
            .map(|(s, _)| s.clone())
            .ok_or(Error::new(rss_saga::ErrorKind::Store))
    }
    async fn commit<T: Timer>(
        &self,
        l: &Lease,
        m: Mutation,
        _: &Control<'_, T>,
    ) -> Result<(), Error> {
        if self.2.load(Ordering::SeqCst) == 1 {
            std::future::pending::<()>().await;
        }
        let mut data = self
            .0
            .lock()
            .map_err(|_| Error::new(rss_saga::ErrorKind::Store))?;
        let (s, lease) = data
            .get_mut(&l.scope())
            .ok_or(Error::new(rss_saga::ErrorKind::Store))?;
        if lease.token() != l.token() {
            return Err(Error::new(rss_saga::ErrorKind::Fenced));
        }
        *s = s.apply(m.event().clone())?;
        if m.event().kind == EventKind::ForwardIntent && self.1.swap(false, Ordering::SeqCst) {
            return Err(Error::new(ErrorKind::CommitUnknown));
        }
        Ok(())
    }
    async fn candidates<T: Timer>(
        &self,
        t: rss_request_context::TenantId,
        after: Option<uuid::Uuid>,
        n: u32,
        _: &Control<'_, T>,
    ) -> Result<Vec<Scope>, Error> {
        let mut scopes = self
            .0
            .lock()
            .map_err(|_| Error::new(rss_saga::ErrorKind::Store))?
            .keys()
            .filter(|s| s.tenant() == t && after.is_none_or(|id| s.id() > id))
            .copied()
            .collect::<Vec<_>>();
        scopes.sort_by_key(|s| s.id());
        scopes.truncate(n as usize);
        Ok(scopes)
    }
}
fn scope() -> anyhow::Result<Scope> {
    Ok(Scope::new(
        rss_request_context::TenantId::parse("11111111-2222-4333-8444-555555555555")?,
        uuid::Uuid::new_v4(),
    ))
}
#[tokio::test]
async fn effect_unknown_recovers_by_probe_without_reexecuting() -> anyhow::Result<()> {
    let d = definition(&["one", "two"])?;
    let effects = Arc::new(Effects::default());
    effects.unknown_once.store(true, Ordering::SeqCst);
    let memory = Memory::default();
    let s = scope()?;
    let clock = Clock::new();
    let cancel = CancellationToken::new();
    let control = Control::new(&clock, Duration::from_secs(10), &cancel);
    let e = Executor::new(
        memory.clone(),
        protection()?,
        registry(d.clone(), effects.clone(), false)?,
    );
    e.register(s, &d, &control).await?;
    assert!(matches!(
        e.run(s, 10, &control).await,
        Err(ref failure) if failure.kind()==rss_saga::ErrorKind::EffectUnknown
    ));
    drop(e);
    let recovered = Executor::new(memory, protection()?, registry(d, effects.clone(), false)?);
    assert_eq!(
        recovered.run(s, 10, &control).await?.status,
        Status::Succeeded
    );
    assert_eq!(
        *effects
            .calls
            .lock()
            .map_err(|_| Error::new(rss_saga::ErrorKind::Store))?,
        vec!["execute:one", "probe:one", "execute:two"]
    );
    Ok(())
}
#[tokio::test]
async fn failed_compensation_resumes_once_in_reverse_order() -> anyhow::Result<()> {
    let d = definition(&["one", "two", "three"])?;
    let effects = Arc::new(Effects::default());
    effects.fail_undo.store(true, Ordering::SeqCst);
    let memory = Memory::default();
    let s = scope()?;
    let clock = Clock::new();
    let cancel = CancellationToken::new();
    let control = Control::new(&clock, Duration::from_secs(10), &cancel);
    let e = Executor::new(
        memory.clone(),
        protection()?,
        registry(d.clone(), effects.clone(), true)?,
    );
    e.register(s, &d, &control).await?;
    let paused = e.run(s, 20, &control).await?;
    assert_eq!(paused.status, Status::CompensationFailed);
    assert!(matches!(
        e.resume(s, paused.revision - 1, 20, &control).await,
        Err(ref failure) if failure.kind()==rss_saga::ErrorKind::Conflict
    ));
    drop(e);
    let recovered = Executor::new(
        memory.clone(),
        protection()?,
        registry(d, effects.clone(), true)?,
    );
    assert_eq!(
        recovered
            .resume(s, paused.revision, 20, &control)
            .await?
            .status,
        Status::Compensated
    );
    assert_eq!(
        *effects
            .undo
            .lock()
            .map_err(|_| Error::new(rss_saga::ErrorKind::Store))?,
        vec!["two", "one"]
    );
    let data = memory
        .0
        .lock()
        .map_err(|_| Error::new(rss_saga::ErrorKind::Store))?;
    let events = data
        .get(&s)
        .ok_or(Error::new(rss_saga::ErrorKind::Store))?
        .0
        .events();
    assert_eq!(
        events
            .iter()
            .filter(|e| e.step == 1 && e.kind == EventKind::CompensationIntent)
            .map(|e| e.attempt)
            .collect::<Vec<_>>(),
        vec![1, 2]
    );
    Ok(())
}
#[tokio::test]
async fn changed_definition_and_cancel_never_admit_effects() -> anyhow::Result<()> {
    let d = definition(&["one"])?;
    let memory = Memory::default();
    let s = scope()?;
    let clock = Clock::new();
    let cancel = CancellationToken::new();
    let control = Control::new(&clock, Duration::from_secs(10), &cancel);
    let effects = Arc::new(Effects::default());
    let e = Executor::new(
        memory.clone(),
        protection()?,
        registry(d.clone(), effects.clone(), false)?,
    );
    e.register(s, &d, &control).await?;
    let wrong = Executor::new(
        memory,
        protection()?,
        registry(definition(&["one", "two"])?, effects.clone(), false)?,
    );
    assert!(matches!(
        wrong.run(s, 10, &control).await,
        Err(ref failure) if failure.kind()==rss_saga::ErrorKind::UnsupportedDefinition
    ));
    cancel.cancel();
    assert!(matches!(
        e.run(s, 10, &control).await,
        Err(ref failure) if failure.kind()==rss_saga::ErrorKind::Cancelled
    ));
    assert!(
        effects
            .calls
            .lock()
            .map_err(|_| Error::new(rss_saga::ErrorKind::Store))?
            .is_empty()
    );
    Ok(())
}
#[tokio::test]
async fn unknown_compensation_is_probed_after_restart() -> anyhow::Result<()> {
    let d = definition(&["one", "two", "three"])?;
    let effects = Arc::new(Effects::default());
    effects.unknown_undo_once.store(true, Ordering::SeqCst);
    let memory = Memory::default();
    let s = scope()?;
    let clock = Clock::new();
    let cancel = CancellationToken::new();
    let control = Control::new(&clock, Duration::from_secs(10), &cancel);
    let e = Executor::new(
        memory.clone(),
        protection()?,
        registry(d.clone(), effects.clone(), true)?,
    );
    e.register(s, &d, &control).await?;
    assert!(matches!(
        e.run(s, 20, &control).await,
        Err(ref failure) if failure.kind()==rss_saga::ErrorKind::EffectUnknown
    ));
    drop(e);
    let e = Executor::new(
        memory.clone(),
        protection()?,
        registry(d, effects.clone(), true)?,
    );
    assert_eq!(e.run(s, 20, &control).await?.status, Status::Compensated);
    let data = memory
        .0
        .lock()
        .map_err(|_| Error::new(rss_saga::ErrorKind::Store))?;
    let events = data
        .get(&s)
        .ok_or(Error::new(rss_saga::ErrorKind::Store))?
        .0
        .events();
    assert_eq!(
        events
            .iter()
            .filter(|e| e.step == 1 && e.kind == EventKind::CompensationIntent)
            .count(),
        1
    );
    Ok(())
}
#[tokio::test]
async fn negative_probe_after_intent_crash_does_not_exhaust_one_attempt() -> anyhow::Result<()> {
    let d = definition(&["one"])?;
    let effects = Arc::new(Effects::default());
    let memory = Memory::default();
    memory.1.store(true, Ordering::SeqCst);
    let s = scope()?;
    let clock = Clock::new();
    let cancel = CancellationToken::new();
    let control = Control::new(&clock, Duration::from_secs(10), &cancel);
    let e = Executor::new(
        memory.clone(),
        protection()?,
        registry(d, effects.clone(), false)?,
    );
    let d = definition(&["one"])?;
    e.register(s, &d, &control).await?;
    assert!(
        matches!(e.run(s,10,&control).await,Err(error) if error.kind()==ErrorKind::CommitUnknown)
    );
    assert_eq!(e.run(s, 10, &control).await?.status, Status::Succeeded);
    assert_eq!(
        *effects
            .calls
            .lock()
            .map_err(|_| Error::new(ErrorKind::Store))?,
        vec!["probe:one", "execute:one"]
    );
    let data = memory.0.lock().map_err(|_| Error::new(ErrorKind::Store))?;
    let events = data.get(&s).ok_or(Error::new(ErrorKind::Store))?.0.events();
    assert_eq!(
        events
            .iter()
            .filter(|e| e.kind == EventKind::ForwardIntent)
            .map(|e| e.attempt)
            .collect::<Vec<_>>(),
        vec![1, 2]
    );
    assert!(
        events
            .iter()
            .any(|e| e.kind == EventKind::ForwardProbeNotApplied)
    );
    Ok(())
}
#[tokio::test]
async fn successful_receipt_is_typed_and_bound_to_the_final_action() -> anyhow::Result<()> {
    let d = definition(&["one", "two"])?;
    let effects = Arc::new(Effects::default());
    let (builder, completion) = DefinitionBuilder::new(d.clone())?
        .step(Action {
            name: "one",
            fail: false,
            effects: effects.clone(),
        })?
        .last_step(Action {
            name: "two",
            fail: false,
            effects,
        })?;
    let e = Executor::new(
        Memory::default(),
        protection()?,
        Registry::builder().register(builder)?.finish(),
    );
    let clock = Clock::new();
    let cancel = CancellationToken::new();
    let control = Control::new(&clock, Duration::from_secs(10), &cancel);
    let s = scope()?;
    e.register(s, &d, &control).await?;
    let report = e.run(s, 10, &control).await?;
    let reference = report
        .success
        .ok_or(Error::new(ErrorKind::ReceiptUnavailable))?;
    assert_eq!(reference.scope(), s);
    assert_eq!(
        e.success_receipt(&reference, &completion, &control).await?,
        "two"
    );
    Ok(())
}
struct SelectiveStep;
impl Step for SelectiveStep {
    type Receipt = String;
    fn name(&self) -> &str {
        "one"
    }
    fn receipt_schema(&self) -> &str {
        "receipt.v1"
    }
    async fn execute(&self, c: EffectContext) -> EffectOutcome<String> {
        if c.scope().id() == uuid::Uuid::from_u128(1) {
            EffectOutcome::Unknown
        } else {
            EffectOutcome::Applied("one".into())
        }
    }
    async fn probe(&self, _: EffectContext) -> ProbeOutcome<String> {
        ProbeOutcome::Unknown
    }
    async fn compensate(&self, _: EffectContext, _: String) -> EffectOutcome<()> {
        EffectOutcome::Unknown
    }
    async fn probe_compensation(&self, _: EffectContext, _: String) -> ProbeOutcome<()> {
        ProbeOutcome::Unknown
    }
}
#[tokio::test]
async fn sweep_cursor_and_total_budget_prevent_unknown_instance_starvation() -> anyhow::Result<()> {
    let d = definition(&["one"])?;
    let registry = Registry::builder()
        .register(DefinitionBuilder::new(d.clone())?.step(SelectiveStep)?)?
        .finish();
    let e = Executor::new(Memory::default(), protection()?, registry);
    let tenant = scope()?.tenant();
    let a = Scope::new(tenant, uuid::Uuid::from_u128(1));
    let b = Scope::new(tenant, uuid::Uuid::from_u128(2));
    let clock = Clock::new();
    let cancel = CancellationToken::new();
    let control = Control::new(&clock, Duration::from_secs(10), &cancel);
    e.register(a, &d, &control).await?;
    e.register(b, &d, &control).await?;
    let first = e
        .run_once(tenant, None, SweepBudget::new(2, 1)?, &control)
        .await?;
    assert_eq!(first.items.len(), 1);
    assert!(matches!(&first.items[0].result,Err(error) if error.kind()==ErrorKind::EffectUnknown));
    let second = e
        .run_once(tenant, first.next_cursor, SweepBudget::new(2, 1)?, &control)
        .await?;
    assert_eq!(second.items[0].scope, b);
    assert_eq!(
        second.items[0]
            .result
            .as_ref()
            .map_err(Clone::clone)?
            .status,
        Status::Succeeded
    );
    Ok(())
}
#[cfg(feature = "rss-runtime")]
struct PendingStep(Arc<tokio::sync::Notify>);
#[cfg(feature = "rss-runtime")]
impl Step for PendingStep {
    type Receipt = String;
    fn name(&self) -> &str {
        "one"
    }
    fn receipt_schema(&self) -> &str {
        "receipt.v1"
    }
    async fn execute(&self, _: EffectContext) -> EffectOutcome<String> {
        self.0.notify_one();
        std::future::pending().await
    }
    async fn probe(&self, _: EffectContext) -> ProbeOutcome<String> {
        ProbeOutcome::Unknown
    }
    async fn compensate(&self, _: EffectContext, _: String) -> EffectOutcome<()> {
        EffectOutcome::Unknown
    }
    async fn probe_compensation(&self, _: EffectContext, _: String) -> ProbeOutcome<()> {
        ProbeOutcome::Unknown
    }
}
#[cfg(feature = "rss-runtime")]
#[tokio::test]
async fn managed_cancellation_is_a_clean_lifecycle_exit() -> anyhow::Result<()> {
    let d = definition(&["one"])?;
    let entered = Arc::new(tokio::sync::Notify::new());
    let registry = Registry::builder()
        .register(DefinitionBuilder::new(d.clone())?.step(PendingStep(entered.clone()))?)?
        .finish();
    let e = Executor::new(Memory::default(), protection()?, registry);
    let s = scope()?;
    let clock = Clock::new();
    let cancel = CancellationToken::new();
    let control = Control::new(&clock, Duration::from_secs(10), &cancel);
    e.register(s, &d, &control).await?;
    let (start, status) = rss_runtime::ManagedTask::prepare("saga-test", Duration::from_secs(1));
    let (registration, result) =
        Arc::new(e).into_registration(start, Clock::new(), s, 10, Duration::from_secs(60));
    let mut stack = rss_runtime::ShutdownStack::try_new(rss_runtime::TotalDrainBudget::new(
        Duration::from_secs(2),
    )?)?;
    let mut startup = stack.startup()?;
    startup.stage_task_with_token(registration);
    startup.commit().finish();
    tokio::time::timeout(Duration::from_secs(1), entered.notified()).await?;
    assert!(stack.shutdown().await?.is_clean());
    assert_eq!(
        status.current(),
        rss_runtime::TaskState::Stopped(rss_runtime::TaskExit::Cancelled)
    );
    assert!(matches!(result.await?,Err(error) if error.kind()==ErrorKind::Cancelled));
    Ok(())
}

#[tokio::test]
async fn interrupted_commit_is_unknown() -> anyhow::Result<()> {
    let d = definition(&["one"])?;
    let memory = Memory::default();
    let e = Executor::new(
        memory.clone(),
        protection()?,
        registry(d.clone(), Arc::new(Effects::default()), false)?,
    );
    let s = scope()?;
    let clock = Clock::new();
    let cancel = CancellationToken::new();
    let control = Control::new(&clock, Duration::from_millis(50), &cancel);
    e.register(s, &d, &control).await?;
    memory.2.store(1, Ordering::SeqCst);
    assert!(
        matches!(e.run(s,10,&control).await,Err(error) if error.kind()==ErrorKind::CommitUnknown)
    );
    assert_eq!(memory.3.load(Ordering::SeqCst), 0);
    Ok(())
}
#[tokio::test]
async fn receipt_snapshot_failure_releases_claim() -> anyhow::Result<()> {
    let d = definition(&["one"])?;
    let effects = Arc::new(Effects::default());
    let (builder, completion) = DefinitionBuilder::new(d.clone())?.last_step(Action {
        name: "one",
        effects,
        fail: false,
    })?;
    let memory = Memory::default();
    let e = Executor::new(
        memory.clone(),
        protection()?,
        Registry::builder().register(builder)?.finish(),
    );
    let s = scope()?;
    let clock = Clock::new();
    let cancel = CancellationToken::new();
    let control = Control::new(&clock, Duration::from_secs(10), &cancel);
    e.register(s, &d, &control).await?;
    let report = e.run(s, 10, &control).await?;
    let reference = report
        .success
        .ok_or_else(|| anyhow::anyhow!("missing result"))?;
    let releases = memory.3.load(Ordering::SeqCst);
    memory.2.store(2, Ordering::SeqCst);
    assert!(
        matches!(e.success_receipt(&reference,&completion,&control).await,Err(error) if error.kind()==ErrorKind::Store)
    );
    assert_eq!(memory.3.load(Ordering::SeqCst), releases + 1);
    Ok(())
}

#[cfg(feature = "rss-runtime")]
#[tokio::test]
async fn managed_yield_and_pause_preserve_continuation_owner() -> anyhow::Result<()> {
    let d = definition(&["one", "two", "three"])?;
    let effects = Arc::new(Effects::default());
    effects.fail_undo.store(true, Ordering::SeqCst);
    let e = Arc::new(Executor::new(
        Memory::default(),
        protection()?,
        registry(d.clone(), effects, true)?,
    ));
    let s = scope()?;
    let clock = Clock::new();
    let cancel = CancellationToken::new();
    let control = Control::new(&clock, Duration::from_secs(10), &cancel);
    e.register(s, &d, &control).await?;
    for (budget, expected) in [(1, RunStop::Yielded), (30, RunStop::Paused)] {
        let (start, _) =
            rss_runtime::ManagedTask::prepare("saga-continuation", Duration::from_secs(1));
        let (registration, result) =
            e.clone()
                .into_registration(start, Clock::new(), s, budget, Duration::from_secs(10));
        let mut stack = rss_runtime::ShutdownStack::try_new(rss_runtime::TotalDrainBudget::new(
            Duration::from_secs(1),
        )?)?;
        let mut startup = stack.startup()?;
        startup.stage_task_with_token(registration);
        startup.commit().finish();
        let report = result.await??;
        assert_eq!(report.stop, expected);
        assert!(stack.shutdown().await?.is_clean());
        if expected == RunStop::Paused {
            assert_eq!(
                e.resume(s, report.revision, 30, &control).await?.status,
                Status::Compensated
            );
        }
    }
    Ok(())
}
