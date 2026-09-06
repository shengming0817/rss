use rss_reconcile::*;
use rss_request_context::TenantId;
use std::{
    sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio_util::sync::CancellationToken;
struct Clock(tokio::time::Instant);
impl Clock {
    #[allow(clippy::disallowed_methods)]
    fn new() -> Self {
        Self(tokio::time::Instant::now())
    }
}
impl Timer for Clock {
    #[allow(clippy::disallowed_methods)]
    fn now(&self) -> Duration {
        self.0.elapsed()
    }
    async fn sleep_until(&self, d: Duration) {
        tokio::time::sleep(d.saturating_sub(self.now())).await;
    }
}
struct Row {
    target: Target,
    due: Duration,
    epoch: u64,
    leased: bool,
    wake: u64,
    failures: u32,
    suspended: bool,
}
struct Token {
    target: Target,
    epoch: u64,
    wake: u64,
    failures: u32,
}
impl Claim for Token {
    fn target(&self) -> &Target {
        &self.target
    }
    fn failures(&self) -> u32 {
        self.failures
    }
}
struct Store {
    rows: Mutex<Vec<Row>>,
    clock: Clock,
    lost: bool,
    scans: AtomicUsize,
    scan_delay: Option<(usize, Duration)>,
    scan_failure: Option<ErrorKind>,
    finishes: AtomicUsize,
    releases: AtomicUsize,
}
impl Store {
    fn lock(&self) -> std::sync::MutexGuard<'_, Vec<Row>> {
        self.rows.lock().unwrap_or_else(|e| e.into_inner())
    }
    fn check<'a>(rows: &'a mut [Row], claim: &Token) -> Result<&'a mut Row, Error> {
        rows.iter_mut()
            .find(|r| r.target == claim.target && r.epoch == claim.epoch && r.leased)
            .ok_or_else(|| Error::new(ErrorKind::Fenced))
    }
}
impl DurableStore for Store {
    type Claim = Token;
    async fn wake<T: Timer>(&self, target: &Target, _: &Control<'_, T>) -> Result<(), Error> {
        let mut rows = self.lock();
        if let Some(row) = rows.iter_mut().find(|r| r.target == *target) {
            row.wake += 1;
            row.due = self.clock.now();
            row.suspended = false;
            row.failures = 0;
        } else {
            rows.push(Row {
                target: target.clone(),
                due: self.clock.now(),
                epoch: 0,
                leased: false,
                wake: 0,
                failures: 0,
                suspended: false,
            });
        }
        Ok(())
    }
    async fn claim_due<T: Timer>(
        &self,
        scope: &Scope,
        limit: usize,
        _: Duration,
        _: &Control<'_, T>,
    ) -> Result<Vec<Token>, Error> {
        let scan = self.scans.fetch_add(1, Ordering::SeqCst);
        if let Some((at, delay)) = self.scan_delay
            && scan == at
        {
            tokio::time::sleep(delay).await;
        }
        if let Some(kind) = self.scan_failure {
            return Err(Error::new(kind));
        }
        let now = self.clock.now();
        Ok(self
            .lock()
            .iter_mut()
            .filter(|r| r.target.scope() == scope && !r.leased && !r.suspended && r.due <= now)
            .take(limit)
            .map(|r| {
                r.leased = true;
                r.epoch += 1;
                Token {
                    target: r.target.clone(),
                    epoch: r.epoch,
                    wake: r.wake,
                    failures: r.failures,
                }
            })
            .collect())
    }
    async fn renew<T: Timer>(
        &self,
        c: &Token,
        _: Duration,
        _: &Control<'_, T>,
    ) -> Result<(), Error> {
        if self.lost {
            return Err(Error::new(ErrorKind::Fenced));
        }
        Self::check(&mut self.lock(), c)?;
        Ok(())
    }
    async fn finish<T: Timer>(
        &self,
        c: &Token,
        out: Completion,
        _: &Control<'_, T>,
    ) -> Result<(), Error> {
        self.finishes.fetch_add(1, Ordering::SeqCst);
        let mut rows = self.lock();
        let r = Self::check(&mut rows, c)?;
        r.leased = false;
        if r.wake != c.wake {
            return Ok(());
        }
        match out {
            Completion::Converged => r.suspended = true,
            Completion::Reobserve(d) => {
                r.due = self.clock.now() + d;
                r.failures = 0;
            }
            Completion::Retry { after, failures } => {
                r.due = self.clock.now() + after;
                r.failures = failures;
            }
            Completion::Suspended { failures } => {
                r.suspended = true;
                r.failures = failures;
            }
        }
        Ok(())
    }
    async fn release<T: Timer>(&self, c: &Token, _: &Control<'_, T>) -> Result<(), Error> {
        self.releases.fetch_add(1, Ordering::SeqCst);
        Self::check(&mut self.lock(), c)?.leased = false;
        Ok(())
    }
}
struct Business {
    observed: AtomicUsize,
    applied: AtomicUsize,
    active: AtomicUsize,
    peak: AtomicUsize,
    behavior: u8,
}
struct Active<'a>(&'a AtomicUsize);
impl Drop for Active<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}
impl Reconciler<Token> for Business {
    type State = usize;
    async fn observe<T: Timer>(
        &self,
        _: &Token,
        _: &Control<'_, T>,
    ) -> Result<ReconcileDiff<usize>, Error> {
        let n = self.observed.fetch_add(1, Ordering::SeqCst);
        Ok(ReconcileDiff::between(
            DesiredState::present(1),
            ActualState::present(usize::from(n > 1)),
        ))
    }
    #[allow(clippy::panic)]
    async fn apply<T: Timer>(
        &self,
        _: &Token,
        _: ReconcileDiff<usize>,
        control: &Control<'_, T>,
    ) -> Result<(), Error> {
        self.applied.fetch_add(1, Ordering::SeqCst);
        let n = self.active.fetch_add(1, Ordering::SeqCst) + 1;
        self.peak.fetch_max(n, Ordering::SeqCst);
        let _guard = Active(&self.active);
        match self.behavior {
            1 => Err(Error::new(ErrorKind::Transient)),
            2 => {
                control.sleep(Duration::from_secs(20)).await;
                Ok(())
            }
            3 => panic!("callback panic"),
            4 => Err(Error::new(ErrorKind::CommitUnknown)),
            5 => Err(Error::new(ErrorKind::RollbackFailed)),
            6 => Err(Error::provider(
                ErrorKind::Transient,
                std::io::Error::other("private-business-detail"),
            )),
            _ => {
                control.sleep(Duration::from_millis(3)).await;
                Ok(())
            }
        }
    }
}
fn business(behavior: u8) -> Business {
    Business {
        observed: AtomicUsize::new(0),
        applied: AtomicUsize::new(0),
        active: AtomicUsize::new(0),
        peak: AtomicUsize::new(0),
        behavior,
    }
}
fn scope() -> anyhow::Result<Scope> {
    Ok(Scope::new(
        TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479")?,
        "test",
    )?)
}
fn policy() -> Result<Policy, Error> {
    policy_with_attempts(2)
}
fn policy_with_attempts(max_attempts: u32) -> Result<Policy, Error> {
    Policy::try_from(rss_reconcile::PolicyConfig {
        concurrency: 2,
        lease_ttl: Duration::from_millis(15),
        attempt_timeout: Duration::from_millis(100),
        scan_interval: Duration::from_millis(2),
        initial_backoff: Duration::from_millis(2),
        max_backoff: Duration::from_millis(8),
        max_attempts,
    })
}
#[tokio::test(start_paused = true)]
async fn successful_action_requires_another_observation_and_no_notification() -> anyhow::Result<()>
{
    let clock = Clock::new();
    let cancel = CancellationToken::new();
    let control = Control::new(&clock, Duration::from_millis(50), &cancel);
    let store = Store {
        rows: Mutex::new(vec![]),
        clock: Clock::new(),
        lost: false,
        scans: AtomicUsize::new(0),
        scan_delay: None,
        scan_failure: None,
        finishes: AtomicUsize::new(0),
        releases: AtomicUsize::new(0),
    };
    let scope = scope()?;
    store
        .wake(&Target::new(scope.clone(), "one")?, &control)
        .await?;
    let business = business(0);
    let report = run(&store, &business, &scope, policy()?, &control, |_| {}).await?;
    assert_eq!(report.converged, 1);
    assert!(report.reobserve >= 1);
    assert!(business.observed.load(Ordering::SeqCst) > business.applied.load(Ordering::SeqCst));
    Ok(())
}
#[tokio::test(start_paused = true)]
async fn bounded_concurrency_and_lease_loss_cancel_callbacks() -> anyhow::Result<()> {
    let clock = Clock::new();
    let cancel = CancellationToken::new();
    let control = Control::new(&clock, Duration::from_millis(35), &cancel);
    let store = Store {
        rows: Mutex::new(vec![]),
        clock: Clock::new(),
        lost: true,
        scans: AtomicUsize::new(0),
        scan_delay: None,
        scan_failure: None,
        finishes: AtomicUsize::new(0),
        releases: AtomicUsize::new(0),
    };
    let scope = scope()?;
    for i in 0..4 {
        store
            .wake(&Target::new(scope.clone(), format!("e{i}"))?, &control)
            .await?;
    }
    let business = business(2);
    let report = run(&store, &business, &scope, policy()?, &control, |_| {}).await?;
    assert!(report.fenced >= 2);
    assert!(business.peak.load(Ordering::SeqCst) <= 2);
    assert_eq!(business.active.load(Ordering::SeqCst), 0);
    Ok(())
}
#[tokio::test(start_paused = true)]
async fn newer_wake_survives_completion_and_stale_completion_is_rejected() -> anyhow::Result<()> {
    let clock = Clock::new();
    let cancel = CancellationToken::new();
    let control = Control::new(&clock, Duration::from_secs(1), &cancel);
    let store = Store {
        rows: Mutex::new(vec![]),
        clock: Clock::new(),
        lost: false,
        scans: AtomicUsize::new(0),
        scan_delay: None,
        scan_failure: None,
        finishes: AtomicUsize::new(0),
        releases: AtomicUsize::new(0),
    };
    let scope = scope()?;
    let target = Target::new(scope.clone(), "one")?;
    store.wake(&target, &control).await?;
    let c = store
        .claim_due(&scope, 1, policy()?.lease(), &control)
        .await?
        .remove(0);
    store.wake(&target, &control).await?;
    store.finish(&c, Completion::Converged, &control).await?;
    assert_eq!(
        store
            .claim_due(&scope, 1, policy()?.lease(), &control)
            .await?
            .len(),
        1
    );
    assert!(
        matches!(store.finish(&c,Completion::Converged,&control).await,Err(e) if e.kind()==ErrorKind::Fenced)
    );
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn transient_retry_is_bounded_and_persisted() -> anyhow::Result<()> {
    for max_attempts in [1, 2] {
        let clock = Clock::new();
        let cancel = CancellationToken::new();
        let control = Control::new(&clock, Duration::from_millis(35), &cancel);
        let store = Store {
            rows: Mutex::new(vec![]),
            clock: Clock::new(),
            lost: false,
            scans: AtomicUsize::new(0),
            scan_delay: None,
            scan_failure: None,
            finishes: AtomicUsize::new(0),
            releases: AtomicUsize::new(0),
        };
        let scope = scope()?;
        let t = Target::new(scope.clone(), "retry")?;
        store.wake(&t, &control).await?;
        let business = business(1);
        let report = run(
            &store,
            &business,
            &scope,
            policy_with_attempts(max_attempts)?,
            &control,
            |_| {},
        )
        .await?;
        assert_eq!(report.retried, u64::from(max_attempts - 1));
        assert_eq!(report.suspended, 1);
        assert_eq!(report.converged, 0);
        assert_eq!(store.lock()[0].failures, max_attempts);
    }
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn idle_worker_recovers_a_durable_wake_without_notification() -> anyhow::Result<()> {
    let clock = Clock::new();
    let cancel = CancellationToken::new();
    let c = Control::new(&clock, Duration::from_millis(55), &cancel);
    let store = Store {
        rows: Mutex::new(vec![]),
        clock: Clock::new(),
        lost: false,
        scans: AtomicUsize::new(0),
        scan_delay: None,
        scan_failure: None,
        finishes: AtomicUsize::new(0),
        releases: AtomicUsize::new(0),
    };
    let scope = scope()?;
    let target = Target::new(scope.clone(), "late")?;
    let business = business(0);
    let notify = tokio::sync::Notify::new();
    let producer = async {
        while store.scans.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
        store.wake(&target, &c).await
    };
    let (report, wake) = tokio::join!(
        run_with_notify(&store, &business, &scope, policy()?, &c, &notify, |_| {}),
        producer
    );
    wake?;
    assert_eq!(report?.converged, 1);
    assert!(store.scans.load(Ordering::SeqCst) >= 2);
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn delayed_claim_is_renewed_before_any_business_callback() -> anyhow::Result<()> {
    let clock = Clock::new();
    let cancel = CancellationToken::new();
    let c = Control::new(&clock, Duration::from_millis(35), &cancel);
    let store = Store {
        rows: Mutex::new(vec![]),
        clock: Clock::new(),
        lost: true,
        scans: AtomicUsize::new(0),
        scan_delay: Some((0, Duration::from_millis(12))),
        scan_failure: None,
        finishes: AtomicUsize::new(0),
        releases: AtomicUsize::new(0),
    };
    let scope = scope()?;
    store
        .wake(&Target::new(scope.clone(), "expired-on-return")?, &c)
        .await?;
    let business = business(0);
    let report = run(&store, &business, &scope, policy()?, &c, |_| {}).await?;
    assert_eq!(report.fenced, 1);
    assert_eq!(business.observed.load(Ordering::SeqCst), 0);
    assert_eq!(business.applied.load(Ordering::SeqCst), 0);
    Ok(())
}
#[tokio::test(start_paused = true)]
async fn scan_failures_have_operation_units_not_target_units() -> anyhow::Result<()> {
    for kind in [ErrorKind::Transient, ErrorKind::CommitUnknown] {
        let clock = Clock::new();
        let cancel = CancellationToken::new();
        let c = Control::new(&clock, Duration::from_millis(20), &cancel);
        let store = Store {
            rows: Mutex::new(vec![]),
            clock: Clock::new(),
            lost: false,
            scans: AtomicUsize::new(0),
            scan_delay: None,
            scan_failure: Some(kind),
            finishes: AtomicUsize::new(0),
            releases: AtomicUsize::new(0),
        };
        let report = run(&store, &business(0), &scope()?, policy()?, &c, |_| {}).await?;
        assert_eq!(report.execution_failed, 0);
        assert_eq!(report.scan_failed > 0, kind == ErrorKind::Transient);
        assert_eq!(
            report.claim_unknown_batches > 0,
            kind == ErrorKind::CommitUnknown
        );
    }
    Ok(())
}
struct AdmissionProbe(AtomicUsize);
impl Reconciler<Token> for AdmissionProbe {
    type State = usize;
    async fn observe<T: Timer>(
        &self,
        c: &Token,
        _: &Control<'_, T>,
    ) -> Result<ReconcileDiff<usize>, Error> {
        if c.target.entity() == "d" {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
        Ok(ReconcileDiff::between(
            DesiredState::present(1),
            ActualState::missing(),
        ))
    }
    async fn apply<T: Timer>(
        &self,
        c: &Token,
        _: ReconcileDiff<usize>,
        control: &Control<'_, T>,
    ) -> Result<(), Error> {
        match c.target.entity() {
            "a" => control.sleep(Duration::from_millis(10)).await,
            "b" => control.sleep(Duration::from_millis(20)).await,
            _ => std::future::pending().await,
        }
        Ok(())
    }
}
#[tokio::test(start_paused = true)]
async fn slots_freed_during_scan_are_refilled_without_waiting_for_poll_interval()
-> anyhow::Result<()> {
    let clock = Clock::new();
    let cancel = CancellationToken::new();
    let c = Control::new(&clock, Duration::from_millis(100), &cancel);
    let store = Store {
        rows: Mutex::new(vec![]),
        clock: Clock::new(),
        lost: false,
        scans: AtomicUsize::new(0),
        scan_delay: Some((1, Duration::from_millis(30))),
        scan_failure: None,
        finishes: AtomicUsize::new(0),
        releases: AtomicUsize::new(0),
    };
    let scope = scope()?;
    for id in ["a", "b", "c", "d"] {
        store.wake(&Target::new(scope.clone(), id)?, &c).await?;
    }
    let p = Policy::try_from(rss_reconcile::PolicyConfig {
        concurrency: 2,
        lease_ttl: Duration::from_secs(2),
        attempt_timeout: Duration::from_millis(500),
        scan_interval: Duration::from_secs(1),
        initial_backoff: Duration::from_millis(2),
        max_backoff: Duration::from_millis(10),
        max_attempts: 3,
    })?;
    let probe = AdmissionProbe(AtomicUsize::new(0));
    run(&store, &probe, &scope, p, &c, |_| {}).await?;
    assert_eq!(probe.0.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn panic_payload_escapes_run_without_settling_claim() -> anyhow::Result<()> {
    use futures::FutureExt;
    let clock = Clock::new();
    let cancel = CancellationToken::new();
    let c = Control::new(&clock, Duration::from_millis(40), &cancel);
    let store = Store {
        rows: Mutex::new(vec![]),
        clock: Clock::new(),
        lost: false,
        scans: AtomicUsize::new(0),
        scan_delay: None,
        scan_failure: None,
        finishes: AtomicUsize::new(0),
        releases: AtomicUsize::new(0),
    };
    let scope = scope()?;
    store
        .wake(&Target::new(scope.clone(), "panic")?, &c)
        .await?;
    let business = business(3);
    let result =
        std::panic::AssertUnwindSafe(run(&store, &business, &scope, policy()?, &c, |_| {}))
            .catch_unwind()
            .await;
    let payload = result
        .err()
        .ok_or_else(|| anyhow::anyhow!("panic was swallowed"))?;
    assert_eq!(payload.downcast_ref::<&str>(), Some(&"callback panic"));
    assert!(store.lock()[0].leased);
    assert_eq!(store.lock()[0].failures, 0);
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn uncertain_execution_preserves_claim_and_emits_target_failure() -> anyhow::Result<()> {
    for (behavior, kind) in [
        (4, ErrorKind::CommitUnknown),
        (5, ErrorKind::RollbackFailed),
    ] {
        let clock = Clock::new();
        let cancel = CancellationToken::new();
        let c = Control::new(&clock, Duration::from_millis(35), &cancel);
        let store = Store {
            rows: Mutex::new(vec![]),
            clock: Clock::new(),
            lost: false,
            scans: AtomicUsize::new(0),
            scan_delay: None,
            scan_failure: None,
            finishes: AtomicUsize::new(0),
            releases: AtomicUsize::new(0),
        };
        let scope = scope()?;
        let t = Target::new(scope.clone(), "unknown-action")?;
        store.wake(&t, &c).await?;
        let mut observations = vec![];
        let report = run(&store, &business(behavior), &scope, policy()?, &c, |o| {
            observations.push(o)
        })
        .await?;
        assert_eq!(report.execution_failed, 1);
        assert_eq!(report.retried + report.suspended, 0);
        assert_eq!(store.finishes.load(Ordering::SeqCst), 0);
        assert_eq!(store.releases.load(Ordering::SeqCst), 0);
        assert!(store.lock()[0].leased);
        assert!(
            matches!(observations.as_slice(),[Observation::AttemptFailed{target,stage:Stage::Apply,error}] if target==&t && error.kind()==kind)
        );
    }
    Ok(())
}
#[tokio::test(start_paused = true)]
async fn scheduled_retry_retains_typed_redacted_diagnostic() -> anyhow::Result<()> {
    let clock = Clock::new();
    let cancel = CancellationToken::new();
    let c = Control::new(&clock, Duration::from_millis(40), &cancel);
    let store = Store {
        rows: Mutex::new(vec![]),
        clock: Clock::new(),
        lost: false,
        scans: AtomicUsize::new(0),
        scan_delay: None,
        scan_failure: None,
        finishes: AtomicUsize::new(0),
        releases: AtomicUsize::new(0),
    };
    let scope = scope()?;
    let t = Target::new(scope.clone(), "diagnostic")?;
    store.wake(&t, &c).await?;
    let mut observations = vec![];
    let report = run(&store, &business(6), &scope, policy()?, &c, |o| {
        observations.push(o)
    })
    .await?;
    assert_eq!(report.retried, 1);
    assert_eq!(report.suspended, 1);
    assert_eq!(observations.len(), 2);
    for o in observations {
        assert!(!format!("{o:?}").contains("private-business-detail"));
        assert!(
            matches!(o,Observation::AttemptFailed{target,stage:Stage::Apply,error} if target==t && error.kind()==ErrorKind::Transient && std::error::Error::source(&error).is_some())
        );
    }
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn explicit_notification_wakes_before_the_periodic_scan() -> anyhow::Result<()> {
    let clock = Clock::new();
    let cancel = CancellationToken::new();
    let c = Control::new(&clock, Duration::from_millis(100), &cancel);
    let store = Store {
        rows: Mutex::new(vec![]),
        clock: Clock::new(),
        lost: false,
        scans: AtomicUsize::new(0),
        scan_delay: None,
        scan_failure: None,
        finishes: AtomicUsize::new(0),
        releases: AtomicUsize::new(0),
    };
    let scope = scope()?;
    let t = Target::new(scope.clone(), "hint")?;
    let notify = tokio::sync::Notify::new();
    let policy = Policy::try_from(PolicyConfig {
        concurrency: 1,
        lease_ttl: Duration::from_secs(2),
        attempt_timeout: Duration::from_millis(50),
        scan_interval: Duration::from_secs(1),
        initial_backoff: Duration::from_millis(2),
        max_backoff: Duration::from_millis(8),
        max_attempts: 2,
    })?;
    let producer = async {
        while store.scans.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
        store.wake(&t, &c).await?;
        notify.notify_one();
        Ok::<(), Error>(())
    };
    let behavior = business(0);
    let (report, wake) = tokio::join!(
        run_with_notify(&store, &behavior, &scope, policy, &c, &notify, |_| {}),
        producer
    );
    wake?;
    assert_eq!(report?.reobserve, 1);
    Ok(())
}
