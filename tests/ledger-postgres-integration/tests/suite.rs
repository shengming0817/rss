use rss_ledger::{AppendRequest, Authenticator, ChainId, KeyId, LedgerId, RecordId, Sequence};
use rss_ledger_postgres::*;
use rss_request_context::TenantId;
use sqlx::{
    PgPool,
    postgres::{PgConnectOptions, PgPoolOptions, PgSslMode},
};
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;
mod messaging;
mod scenarios;
struct Clock(Instant);
impl Clock {
    #[allow(clippy::disallowed_methods)]
    // reason: fixture clock owns the monotonic origin.
    fn new() -> Self {
        Self(Instant::now())
    }
}
impl Timer for Clock {
    #[allow(clippy::disallowed_methods)]
    // reason: concrete injected fixture clock.
    fn now(&self) -> Duration {
        self.0.elapsed()
    }
    async fn sleep_until(&self, t: Duration) {
        tokio::time::sleep(t.saturating_sub(self.now())).await;
    }
}
const TENANT: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";
fn auth() -> anyhow::Result<Authenticator> {
    Ok(Authenticator::new(
        KeyId::parse("fixture-key")?,
        vec![42; 32],
    )?)
}
fn request(chain: &str, id: &str, bytes: &[u8]) -> anyhow::Result<AppendRequest> {
    Ok(AppendRequest::new(
        LedgerId::new(TenantId::parse(TENANT)?, ChainId::parse(chain)?),
        RecordId::parse(id)?,
        bytes.to_vec(),
    )?)
}
use rss_transactional_messaging::transaction::{LocalTxAttempt, LocalTxDeadlineStage};
fn committed<T>(attempt: LocalTxAttempt<Committed<T>, Error>) -> anyhow::Result<T> {
    attempt.fold(
        |c| Ok(c.into_value()),
        |e| Err(e.into()),
        |e| Err(e.into()),
        |e| Err(e.into()),
        |e| Err(e.into()),
        |e| Err(e.into()),
    )
}
// Test-only observation, obtained by exhaustively consuming the canonical provider outcome.
enum Observed<T> {
    Committed(T),
    NotStarted(Error),
    RolledBack(Error),
    RollbackFailed(Error),
    CommitUnknown(Error),
    Fenced,
}
fn observe<T>(attempt: LocalTxAttempt<Committed<T>, Error>) -> Observed<T> {
    attempt.fold(
        |c| Observed::Committed(c.into_value()),
        Observed::NotStarted,
        Observed::RolledBack,
        Observed::RollbackFailed,
        Observed::CommitUnknown,
        |_| Observed::Fenced,
    )
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ledger_postgres_suite() -> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(180), run()).await??;
    Ok(())
}
#[allow(clippy::cognitive_complexity)]
// reason: bounded fixture lifecycle retains setup and teardown in one owner.
async fn run() -> anyhow::Result<()> {
    let network = testkit::bridge_network("ledger-pg").await?;
    let fixture = testkit::postgres_tls(
        testkit::NetworkAttachment {
            network: network.name(),
            dns_name: "ledger-pg",
        },
        testkit::PgTlsServerIdentity::MatchingHost,
    )
    .await?;
    let p = fixture.params();
    let base = PgConnectOptions::new()
        .host(&p.host)
        .port(p.port)
        .database(&p.database)
        .ssl_mode(PgSslMode::VerifyFull)
        .ssl_root_cert_from_pem(fixture.ca_pem().as_bytes().to_vec());
    let owner = PgPoolOptions::new()
        .max_connections(4)
        .connect_with(base.clone().username(&p.username).password(&p.password))
        .await?;
    sqlx::raw_sql("CREATE ROLE ledger_owner NOLOGIN NOSUPERUSER NOBYPASSRLS; CREATE ROLE ledger_runtime LOGIN PASSWORD 'fixture-only' NOSUPERUSER NOBYPASSRLS; GRANT CREATE ON DATABASE rss_test TO ledger_owner;").execute(&owner).await?;
    let mut c = owner.acquire().await?;
    sqlx::raw_sql("SET ROLE ledger_owner")
        .execute(&mut *c)
        .await?;
    sqlx::raw_sql(MIGRATION_SQL).execute(&mut *c).await?;
    sqlx::raw_sql("RESET ROLE; GRANT USAGE ON SCHEMA rss_ledger TO ledger_runtime; GRANT SELECT ON ALL TABLES IN SCHEMA rss_ledger TO ledger_runtime; GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA rss_ledger TO ledger_runtime;").execute(&mut *c).await?;
    drop(c);
    let pool = PgPoolOptions::new()
        .max_connections(8)
        .acquire_timeout(Duration::from_secs(3))
        .connect_with(base.username("ledger_runtime").password("fixture-only"))
        .await?;
    let clock = Clock::new();
    let cancel = CancellationToken::new();
    let control = Control::new(&clock, Duration::from_secs(150), &cancel);
    let store = PgLedger::new(pool.clone(), auth()?, &control).await?;
    scenarios::run(&store, &pool, &owner, &control).await?;
    scenarios::adversarial(&store, &pool, &owner, &control).await?;
    messaging::run(&store, &owner, &fixture).await?;
    admission(&store, &control).await?;
    owner.close().await;
    drop(fixture);
    drop(network);
    Ok(())
}

async fn admission(store: &PgLedger, control: &Control<'_, Clock>) -> anyhow::Result<()> {
    let clock = Clock::new();
    let cancel = CancellationToken::new();
    cancel.cancel();
    for (c, cancelled) in [
        (Control::new(&clock, Duration::from_secs(10), &cancel), true),
        (
            Control::new(&clock, Duration::ZERO, &CancellationToken::new()),
            false,
        ),
    ] {
        let ran = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = ran.clone();
        let result = store
            .local_tx(TenantId::parse(TENANT)?, &c, move |_| {
                Box::pin(async move {
                    flag.store(true, std::sync::atomic::Ordering::SeqCst);
                    Ok(())
                })
            })
            .await;
        assert!(!ran.load(std::sync::atomic::Ordering::SeqCst));
        match observe(result) {
            Observed::NotStarted(Error::Cancelled(LocalTxDeadlineStage::Acquire)) if cancelled => {}
            Observed::NotStarted(Error::Deadline(LocalTxDeadlineStage::Acquire)) if !cancelled => {}
            _ => anyhow::bail!("admission did not preserve its cause"),
        }
    }
    let clone = store.clone();
    store.close(control).await?;
    let ran = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let flag = ran.clone();
    let result = clone
        .local_tx(TenantId::parse(TENANT)?, control, move |_| {
            Box::pin(async move {
                flag.store(true, std::sync::atomic::Ordering::SeqCst);
                Err(Error::Rejected)
            })
        })
        .await;
    assert!(!ran.load(std::sync::atomic::Ordering::SeqCst));
    assert!(matches!(
        observe::<()>(result),
        Observed::NotStarted(Error::Storage(_))
    ));
    Ok(())
}
