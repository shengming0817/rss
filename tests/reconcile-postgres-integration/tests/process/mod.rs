use super::*;
use std::process::{Command, Stdio};
pub async fn run(
    store: &PgStore,
    owner: &PgPool,
    fixture: &testkit::PgTlsFixture,
    c: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    graceful_stop(store, owner, c).await?;
    for mode in [
        "claim",
        "staged",
        "applied",
        "finished",
        "retry-finished",
        "resource",
    ] {
        crash(mode, owner, fixture, c).await?;
    }
    Ok(())
}
async fn crash(
    mode: &str,
    owner: &PgPool,
    fixture: &testkit::PgTlsFixture,
    c: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    let root = std::env::temp_dir().join(format!("reconcile-crash-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&root)?;
    let marker = root.join("ready");
    let ca = root.join("ca.pem");
    std::fs::write(&ca, fixture.ca_pem())?;
    let params = fixture.params();
    let mut child = Command::new(std::env::current_exe()?)
        .args([
            "--exact",
            "process::worker_child",
            "--ignored",
            "--nocapture",
        ])
        .env("RECONCILE_TEST_HOST", &params.host)
        .env("RECONCILE_TEST_PORT", params.port.to_string())
        .env("RECONCILE_TEST_DB", &params.database)
        .env("RECONCILE_TEST_CA", &ca)
        .env("RECONCILE_TEST_MODE", mode)
        .env("RECONCILE_TEST_MARKER", &marker)
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()?;
    stop_child(&mut child, &marker, mode, fixture, c).await?;
    tokio::time::sleep(if mode == "resource" {
        Duration::from_millis(2100)
    } else {
        Duration::from_millis(180)
    })
    .await;
    let pool = PgPoolOptions::new()
        .max_connections(3)
        .connect_with(options(fixture))
        .await?;
    let store = Arc::new(PgStore::new(pool, c).await?);
    let t = target(&format!("crash-{mode}"), TENANT)?;
    if mode == "retry-finished" {
        let deadline: String = sqlx::query_scalar(
            "SELECT next_run::text FROM rss_reconcile.targets WHERE reconciler=$1",
        )
        .bind(t.scope().reconciler())
        .fetch_one(owner)
        .await?;
        assert_eq!(deadline, std::fs::read_to_string(&marker)?);
    }
    if mode == "resource" {
        // Keep both scopes progressing: an abandoned older waiter correctly blocks reobserve.
        let contender = Target::new(
            Scope::new(TenantId::parse(TENANT)?, "process-contender")?,
            "blocked",
        )?;
        let recovered = claim(&store, &contender, Duration::from_secs(2), c).await?;
        store.finish(&recovered, Completion::Converged, c).await?;
    }
    recover(mode, owner, c, &store, &t).await?;
    assert_eq!(store.close(c).await, CloseOutcome::Drained);
    std::fs::remove_dir_all(root)?;
    Ok(())
}
async fn stop_child(
    child: &mut std::process::Child,
    marker: &std::path::Path,
    mode: &str,
    fixture: &testkit::PgTlsFixture,
    c: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    let ready = tokio::time::timeout(Duration::from_secs(20), async {
        while !marker.exists() {
            anyhow::ensure!(
                child.try_wait()?.is_none(),
                "child exited before crash point"
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        Ok::<(), anyhow::Error>(())
    })
    .await;
    let resource_check = if ready.is_ok() && mode == "resource" {
        cross_process_blocked(fixture, c).await
    } else {
        Ok(())
    };
    if child.try_wait()?.is_none() {
        child.kill()?;
    }
    child.wait()?;
    ready??;
    resource_check?;
    Ok(())
}

async fn recover(
    mode: &str,
    owner: &PgPool,
    c: &Control<'_, Clock>,
    store: &Arc<PgStore>,
    t: &Target,
) -> anyhow::Result<()> {
    let expected = i64::from(matches!(mode, "applied" | "finished"));
    assert_eq!(count(owner, t.scope().reconciler()).await?, expected);
    if matches!(mode, "finished" | "retry-finished") {
        assert!(
            store
                .claim_due(t.scope(), 1, Duration::from_secs(1), c)
                .await?
                .claims
                .is_empty()
        );
    } else {
        let runner = Business {
            store: store.clone(),
            key: t.scope().reconciler().to_owned(),
        };
        let policy = Policy::try_from(rss_reconcile::PolicyConfig {
            concurrency: 1,
            lease_ttl: Duration::from_secs(1),
            attempt_timeout: Duration::from_millis(300),
            scan_interval: Duration::from_millis(3),
            idle_scan_interval: Duration::from_millis(3),
            initial_backoff: Duration::from_millis(2),
            max_backoff: Duration::from_millis(10),
            max_attempts: 3,
        })?;
        // Recovery is a durable-state assertion, not a 100ms performance assertion.
        // Keep the caller's existing budget, and stop the worker once finish has committed.
        let converged = async {
            loop {
                let finished = sqlx::query_scalar::<_, bool>(
                    "SELECT result='converged' FROM rss_reconcile.targets WHERE tenant_id=$1::uuid AND reconciler=$2 AND entity=$3",
                )
                .bind(t.scope().tenant().to_string())
                .bind(t.scope().reconciler())
                .bind(t.entity())
                .fetch_one(owner)
                .await?;
                if finished {
                    return Ok::<(), anyhow::Error>(());
                }
                c.sleep(Duration::from_millis(5)).await;
            }
        };
        let stop = CancellationToken::new();
        tokio::select! {
            result = rss_reconcile::run(store.as_ref(), &runner, t.scope(), policy, c, &stop, |_| {}) => {
                anyhow::bail!("{mode}: recovery stopped before durable convergence: {:?}", result?);
            }
            result = tokio::time::timeout(c.remaining(), converged) => { result??; }
        }
        assert_eq!(count(owner, t.scope().reconciler()).await?, 1);
    }
    Ok(())
}
fn options(fixture: &testkit::PgTlsFixture) -> PgConnectOptions {
    let p = fixture.params();
    PgConnectOptions::new()
        .host(&p.host)
        .port(p.port)
        .database(&p.database)
        .username("reconcile_runtime")
        .password("fixture-only")
        .ssl_mode(PgSslMode::VerifyFull)
        .ssl_root_cert_from_pem(fixture.ca_pem().as_bytes().to_vec())
}
struct Business {
    store: Arc<PgStore>,
    key: String,
}
impl Reconciler<PgClaim> for Business {
    type State = i64;
    async fn observe<T: Timer>(
        &self,
        claim: &PgClaim,
        c: &Control<'_, T>,
    ) -> Result<ReconcileStep<ReconcileDiff<i64>>, Error> {
        let observed = async {
            let id = claim.target().scope().reconciler().to_owned();
            let observed = self
                .store
                .local_tx(claim.target().scope(), c, move |tx| {
                    Box::pin(async move {
                        tx.with_connection(move |conn| {
                            Box::pin(async move {
                                sqlx::query_scalar::<_, i64>(
                                "SELECT coalesce(sum(n),0)::bigint FROM public.effects WHERE id=$1",
                            )
                            .bind(id)
                            .fetch_one(conn)
                            .await
                            })
                        })
                        .await
                    })
                })
                .await?;
            Ok(ReconcileDiff::between(
                DesiredState::present(1),
                ActualState::present(observed),
            ))
        }
        .await;
        observed.map(ReconcileStep::Ready)
    }
    async fn apply<T: Timer>(
        &self,
        claim: &PgClaim,
        _: ReconcileDiff<i64>,
        c: &Control<'_, T>,
    ) -> Result<ReconcileStep<()>, Error> {
        self.store
            .protect(claim, c, &self.key, |key, tx| {
                Box::pin(async move {
                    effect(tx, (*key).clone())
                        .await
                        .map(rss_reconcile_postgres::ProtectedStep::Ready)
                })
            })
            .await
    }
}
#[tokio::test]
#[ignore = "launched and killed by the component crash recovery suite"]
async fn worker_child() -> anyhow::Result<()> {
    let options = PgConnectOptions::new()
        .host(&std::env::var("RECONCILE_TEST_HOST")?)
        .port(std::env::var("RECONCILE_TEST_PORT")?.parse()?)
        .database(&std::env::var("RECONCILE_TEST_DB")?)
        .username("reconcile_runtime")
        .password("fixture-only")
        .ssl_mode(PgSslMode::VerifyFull)
        .ssl_root_cert_from_pem(std::fs::read(std::env::var("RECONCILE_TEST_CA")?)?);
    let clock = Clock::new();
    let cancel = CancellationToken::new();
    let control = Control::new(&clock, Duration::from_secs(25), &cancel);
    let store = PgStore::new(
        PgPoolOptions::new()
            .max_connections(2)
            .connect_with(options)
            .await?,
        &control,
    )
    .await?;
    let mode = std::env::var("RECONCILE_TEST_MODE")?;
    let marker = std::env::var("RECONCILE_TEST_MARKER")?;
    let t = target(&format!("crash-{mode}"), TENANT)?;
    store
        .wake(
            &t,
            &if mode == "resource" {
                ResourceSet::new(t.scope().tenant(), ["process:shared"])?
            } else {
                ResourceSet::empty(t.scope().tenant())
            },
            &control,
        )
        .await?;
    let claim = claim(
        &store,
        &t,
        if mode == "resource" {
            Duration::from_secs(2)
        } else {
            Duration::from_millis(150)
        },
        &control,
    )
    .await?;
    if matches!(mode.as_str(), "claim" | "resource") {
        std::fs::write(&marker, b"claimed")?;
        std::future::pending::<()>().await;
    }
    if mode == "retry-finished" {
        store
            .finish(
                &claim,
                Completion::Retry {
                    after: Duration::from_secs(60),
                    failures: 5,
                },
                &control,
            )
            .await?;
        let deadline = store.local_tx(t.scope(), &control, |tx| Box::pin(async move {
            tx.with_connection(|conn| Box::pin(async move {
                sqlx::query_scalar::<_, String>("SELECT next_run::text FROM rss_reconcile.targets WHERE reconciler='crash-retry-finished'").fetch_one(conn).await
            })).await
        })).await?;
        // The parent may kill us as soon as marker exists: publish complete contents.
        let pending = std::path::Path::new(&marker).with_extension("pending");
        std::fs::write(&pending, deadline)?;
        std::fs::rename(pending, &marker)?;
        std::future::pending::<()>().await;
    }
    let id = t.scope().reconciler().to_owned();
    let staged = mode == "staged";
    let inside = marker.clone();
    store
        .protect(&claim, &control, (), move |_, tx| {
            Box::pin(async move {
                (async move {
                    effect(tx, id).await?;
                    if staged {
                        std::fs::write(inside, b"staged").map_err(PgOperationError::unavailable)?;
                        std::future::pending::<()>().await;
                    }
                    Ok(())
                })
                .await
                .map(rss_reconcile_postgres::ProtectedStep::Ready)
            })
        })
        .await?;
    if mode == "finished" {
        store
            .finish(&claim, Completion::Converged, &control)
            .await?;
    }
    std::fs::write(marker, b"committed")?;
    std::future::pending::<()>().await;
    Ok(())
}

struct PausedTransaction<'a> {
    store: &'a PgStore,
    key: String,
    entered: tokio::sync::Notify,
    resume: tokio::sync::Notify,
}
impl Reconciler<PgClaim> for PausedTransaction<'_> {
    type State = bool;
    async fn observe<T: Timer>(
        &self,
        _: &PgClaim,
        _: &Control<'_, T>,
    ) -> Result<ReconcileStep<ReconcileDiff<bool>>, Error> {
        let observed = async {
            Ok(ReconcileDiff::between(
                DesiredState::present(true),
                ActualState::present(false),
            ))
        }
        .await;
        observed.map(ReconcileStep::Ready)
    }
    async fn apply<T: Timer>(
        &self,
        claim: &PgClaim,
        _: ReconcileDiff<bool>,
        control: &Control<'_, T>,
    ) -> Result<ReconcileStep<()>, Error> {
        self.store
            .protect(claim, control, self, |owner, tx| {
                Box::pin(async move {
                    (async move {
                        effect(tx, owner.key.clone()).await?;
                        owner.entered.notify_one();
                        owner.resume.notified().await;
                        Ok(())
                    })
                    .await
                    .map(rss_reconcile_postgres::ProtectedStep::Ready)
                })
            })
            .await
    }
}
async fn graceful_stop(
    store: &PgStore,
    owner: &PgPool,
    control: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    let target = target("graceful-stop", TENANT)?;
    store
        .wake(
            &target,
            &ResourceSet::empty(target.scope().tenant()),
            control,
        )
        .await?;
    let stop = CancellationToken::new();
    let business = PausedTransaction {
        store,
        key: target.scope().reconciler().into(),
        entered: Default::default(),
        resume: Default::default(),
    };
    let policy = Policy::try_from(PolicyConfig {
        concurrency: 1,
        lease_ttl: Duration::from_secs(1),
        attempt_timeout: Duration::from_secs(3),
        scan_interval: Duration::from_millis(5),
        idle_scan_interval: Duration::from_secs(1),
        initial_backoff: Duration::from_millis(5),
        max_backoff: Duration::from_millis(50),
        max_attempts: 3,
    })?;
    let settling = DelayedSettlement(store);
    let runner = rss_reconcile::run(
        &settling,
        &business,
        target.scope(),
        policy,
        control,
        &stop,
        |_| {},
    );
    tokio::pin!(runner);
    tokio::select! { result=&mut runner=>anyhow::bail!("premature runner exit: {result:?}"), ()=business.entered.notified()=>{} }
    stop.cancel();
    assert!(
        tokio::time::timeout(Duration::from_millis(50), &mut runner)
            .await
            .is_err()
    );
    assert_eq!(
        count(owner, target.scope().reconciler()).await?,
        0,
        "business write is still uncommitted"
    );
    business.resume.notify_one();
    let report = runner.await?;
    assert_eq!(report.reobserve, 1);
    assert_eq!(count(owner, target.scope().reconciler()).await?, 1);
    let settled: bool = sqlx::query_scalar("SELECT token IS NULL AND result='pending' FROM rss_reconcile.targets WHERE tenant_id=$1::uuid AND reconciler=$2 AND entity=$3")
        .bind(target.scope().tenant().to_string()).bind(target.scope().reconciler()).bind(target.entity()).fetch_one(owner).await?;
    assert!(settled, "runner returned before the real claim settlement");
    Ok(())
}

// Delay before acquiring the real PG finish transaction; renewal must keep its claim valid.
struct DelayedSettlement<'a>(&'a PgStore);
impl DurableStore for DelayedSettlement<'_> {
    type Claim = PgClaim;
    async fn wake<T: Timer>(
        &self,
        target: &Target,
        resources: &ResourceSet,
        c: &Control<'_, T>,
    ) -> Result<(), Error> {
        self.0.wake(target, resources, c).await
    }
    async fn bind_resources<T: Timer>(
        &self,
        target: &Target,
        resources: &ResourceSet,
        c: &Control<'_, T>,
    ) -> Result<(), Error> {
        self.0.bind_resources(target, resources, c).await
    }

    async fn claim_due<T: Timer>(
        &self,
        scope: &Scope,
        limit: usize,
        lease: Duration,
        c: &Control<'_, T>,
    ) -> Result<ClaimBatch<PgClaim>, Error> {
        self.0.claim_due(scope, limit, lease, c).await
    }
    async fn renew<T: Timer>(
        &self,
        claim: &PgClaim,
        lease: Duration,
        c: &Control<'_, T>,
    ) -> Result<(), Error> {
        self.0.renew(claim, lease, c).await
    }
    async fn release<T: Timer>(&self, claim: &PgClaim, c: &Control<'_, T>) -> Result<(), Error> {
        self.0.release(claim, c).await
    }
    async fn finish<T: Timer>(
        &self,
        claim: &PgClaim,
        completion: Completion,
        c: &Control<'_, T>,
    ) -> Result<(), Error> {
        c.sleep(Duration::from_millis(1200)).await;
        self.0.finish(claim, completion, c).await
    }
}

async fn cross_process_blocked(
    fixture: &testkit::PgTlsFixture,
    c: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect_with(options(fixture))
        .await?;
    let store = PgStore::new(pool, c).await?;
    let scope = Scope::new(TenantId::parse(TENANT)?, "process-contender")?;
    let blocked = Target::new(scope.clone(), "blocked")?;
    let independent = Target::new(scope.clone(), "independent")?;
    store
        .wake(
            &blocked,
            &ResourceSet::new(scope.tenant(), ["process:shared"])?,
            c,
        )
        .await?;
    store
        .wake(
            &independent,
            &ResourceSet::new(scope.tenant(), ["process:independent"])?,
            c,
        )
        .await?;
    let claims = store
        .claim_due(&scope, 2, Duration::from_secs(1), c)
        .await?
        .claims;
    assert_eq!(
        claims.len(),
        1,
        "another process still owns the shared resource"
    );
    assert_eq!(claims[0].target().entity(), "independent");
    store.finish(&claims[0], Completion::Converged, c).await?;
    assert_eq!(store.close(c).await, CloseOutcome::Drained);
    Ok(())
}
