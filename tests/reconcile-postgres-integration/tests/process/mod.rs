use super::*;
use std::process::{Command, Stdio};
pub async fn run(
    _: &PgStore,
    owner: &PgPool,
    fixture: &testkit::PgTlsFixture,
    c: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    for mode in ["claim", "staged", "applied", "finished"] {
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
    if child.try_wait()?.is_none() {
        child.kill()?;
    }
    child.wait()?;
    ready??;
    tokio::time::sleep(Duration::from_millis(180)).await;
    let pool = PgPoolOptions::new()
        .max_connections(3)
        .connect_with(options(fixture))
        .await?;
    let store = Arc::new(PgStore::new(pool, c).await?);
    let t = target(&format!("crash-{mode}"), TENANT)?;
    recover(mode, owner, c, &store, &t).await?;
    assert_eq!(store.close(c).await, CloseOutcome::Drained);
    std::fs::remove_dir_all(root)?;
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
    if mode == "finished" {
        assert!(
            store
                .claim_due(t.scope(), 1, Duration::from_secs(1), c)
                .await?
                .is_empty()
        );
    } else {
        let runner = Business {
            store: store.clone(),
            key: t.scope().reconciler().to_owned(),
        };
        let local = c.child(Duration::from_millis(100));
        let policy = Policy::try_from(rss_reconcile::PolicyConfig {
            concurrency: 1,
            lease_ttl: Duration::from_secs(1),
            attempt_timeout: Duration::from_millis(300),
            scan_interval: Duration::from_millis(3),
            initial_backoff: Duration::from_millis(2),
            max_backoff: Duration::from_millis(10),
            max_attempts: 3,
        })?;
        let report =
            rss_reconcile::run(store.as_ref(), &runner, t.scope(), policy, &local, |_| {}).await?;
        assert_eq!(report.converged, 1);
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
    ) -> Result<ReconcileDiff<i64>, Error> {
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
    async fn apply<T: Timer>(
        &self,
        claim: &PgClaim,
        _: ReconcileDiff<i64>,
        c: &Control<'_, T>,
    ) -> Result<(), Error> {
        self.store
            .protect(claim, c, &self.key, |key, tx| {
                Box::pin(async move { effect(tx, (*key).clone()).await })
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
    store.wake(&t, &control).await?;
    let claim = claim(&store, &t, Duration::from_millis(150), &control).await?;
    if mode == "claim" {
        std::fs::write(&marker, b"claimed")?;
        std::future::pending::<()>().await;
    }
    let id = t.scope().reconciler().to_owned();
    let staged = mode == "staged";
    let inside = marker.clone();
    store
        .protect(&claim, &control, (), move |_, tx| {
            Box::pin(async move {
                effect(tx, id).await?;
                if staged {
                    std::fs::write(inside, b"staged").map_err(PgOperationError::unavailable)?;
                    std::future::pending::<()>().await;
                }
                Ok(())
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
