use rss_reconcile::*;
struct Business;
impl<C: Claim> Reconciler<C> for Business {
    type State = u8;
    async fn observe<T: Timer>(
        &self,
        _: &C,
        _: &Control<'_, T>,
    ) -> Result<ReconcileStep<ReconcileDiff<u8>>, Error> {
        let observed = async {
            Ok(ReconcileDiff::between(
                DesiredState::present(1),
                ActualState::present(1),
            ))
        }
        .await;
        observed.map(ReconcileStep::Ready)
    }
    async fn apply<T: Timer>(
        &self,
        _: &C,
        _: ReconcileDiff<u8>,
        _: &Control<'_, T>,
    ) -> Result<ReconcileStep<()>, Error> {
        let applied: Result<(), Error> = async {
            // reason: already-converged core probe has no external effect provider.
            Ok(())
        }
        .await;
        applied.map(ReconcileStep::Ready)
    }
}
#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    let _implementation = Business;
    let diff = ReconcileDiff::between(DesiredState::present(1), ActualState::present(0));
    anyhow::ensure!(
        diff.drift() == DriftKind::Changed,
        "core drift classification"
    );
    anyhow::ensure!(
        diff.converge_action() == ConvergeAction::Update,
        "core action classification"
    );
    let scope = Scope::new(
        rss_request_context::TenantId::parse("00000000-0000-0000-0000-000000000001")?,
        "probe",
    )?;
    let store = Store {
        target: Target::new(scope.clone(), "one")?,
        claims: AtomicUsize::new(0),
        finishes: AtomicUsize::new(0),
    };
    let timer = Clock(tokio::time::Instant::now());
    let cancel = CancellationToken::new();
    let stop = CancellationToken::new();
    let control = Control::new(&timer, Duration::from_secs(5), &cancel);
    let policy = Policy::try_from(PolicyConfig {
        concurrency: 1,
        claim_batch_size: 1,
        scan_budget: 1,
        lease_ttl: Duration::from_secs(3),
        attempt_timeout: Duration::from_secs(1),
        scan_interval: Duration::from_millis(10),
        idle_scan_interval: Duration::from_secs(1),
        initial_backoff: Duration::from_millis(10),
        max_backoff: Duration::from_secs(1),
        max_attempts: 2,
    })?;
    let report = run_batch(&store, &Business, &scope, policy, &control, &stop, |_| {}).await?;
    anyhow::ensure!(
        report.converged == 1 && report.execution_failed == 0,
        "single batch settles"
    );
    anyhow::ensure!(
        store.claims.load(Ordering::SeqCst) == 1 && store.finishes.load(Ordering::SeqCst) == 1,
        "more hint does not rescan"
    );
    Ok(())
}

use std::{
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};
use tokio_util::sync::CancellationToken;
struct Clock(tokio::time::Instant);
impl Timer for Clock {
    fn now(&self) -> Duration {
        self.0.elapsed()
    }
    async fn sleep_until(&self, at: Duration) {
        tokio::time::sleep(at.saturating_sub(self.now())).await;
    }
}
struct Token(Target);
impl Claim for Token {
    fn target(&self) -> &Target {
        &self.0
    }
    fn failures(&self) -> u32 {
        0
    }
}
struct Store {
    target: Target,
    claims: AtomicUsize,
    finishes: AtomicUsize,
}
impl DurableStore for Store {
    type Claim = Token;
    async fn wake<T: Timer>(
        &self,
        _: &Target,
        _: &ResourceSet,
        _: &Control<'_, T>,
    ) -> Result<(), Error> {
        Ok(())
    }
    async fn bind_resources<T: Timer>(
        &self,
        _: &Target,
        _: &ResourceSet,
        _: &Control<'_, T>,
    ) -> Result<(), Error> {
        Ok(())
    }
    async fn claim_due<T: Timer>(
        &self,
        scope: &Scope,
        limit: usize,
        budget: u32,
        _: Duration,
        _: &Control<'_, T>,
    ) -> Result<ClaimBatch<Token>, Error> {
        check(scope == self.target.scope() && limit == 1 && budget == 1)?;
        self.claims.fetch_add(1, Ordering::SeqCst);
        Ok(ClaimBatch {
            claims: vec![Token(self.target.clone())],
            more: true,
        })
    }
    async fn renew<T: Timer>(
        &self,
        _: &Token,
        _: Duration,
        _: &Control<'_, T>,
    ) -> Result<(), Error> {
        Ok(())
    }
    async fn finish<T: Timer>(
        &self,
        _: &Token,
        completion: Completion,
        _: &Control<'_, T>,
    ) -> Result<(), Error> {
        check(matches!(completion, Completion::Converged))?;
        self.finishes.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    async fn release<T: Timer>(&self, _: &Token, _: &Control<'_, T>) -> Result<(), Error> {
        Ok(())
    }
}
fn check(valid: bool) -> Result<(), Error> {
    if valid {
        Ok(())
    } else {
        Err(Error::new(ErrorKind::Invariant))
    }
}
