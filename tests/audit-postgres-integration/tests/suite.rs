//! Real TLS PostgreSQL acceptance through the public adapter API.
use anyhow::Context as _;
use rss_audit_core::*;
use rss_audit_postgres::{
    Committed, Control, Cursor, Error, Integrity, PgAudit, ReadLimit, TransactionError,
};
use rss_contract::{ContractId, ContractVersion, SchemaDigest, Timepoint};
use rss_ledger::{Authenticator, KeyId};
use rss_request_context::{Clock, Deadline, ExecutionTimer, TenantId};
use rss_transactional_messaging::transaction::LocalTxAttempt;
use sqlx::{
    PgPool,
    postgres::{PgConnectOptions, PgPoolOptions, PgSslMode},
};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use tokio_util::sync::CancellationToken;
mod admission;
mod atomicity;
mod batch;
mod batch_cost;
mod composition;
mod ledger_index;
mod messaging;
mod page_transaction;
mod paging;
mod query_cost;
mod reader;
mod reads;
mod write_capacity;

fn write_budget() -> Result<rss_audit_postgres::WriteBudget, Error> {
    rss_audit_postgres::WriteBudget::new(1024, 8 * 1024 * 1024, 32 * 1024 * 1024)
}
struct TestClock;
impl Clock for TestClock {
    #[allow(
        clippy::disallowed_methods,
        reason = "real monotonic clock for PostgreSQL acceptance"
    )]
    fn now(&self) -> Instant {
        Instant::now()
    }
}
impl ExecutionTimer for TestClock {
    async fn sleep_until(&self, deadline: Deadline) {
        tokio::task::unconstrained(tokio::time::sleep_until(deadline.instant().into())).await;
    }
}
fn tenant() -> anyhow::Result<TenantId> {
    Ok(TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479")?)
}
fn auth() -> anyhow::Result<Arc<Authenticator>> {
    Ok(Arc::new(Authenticator::new(
        KeyId::parse("audit-fixture")?,
        vec![9; 32],
    )?))
}
fn event(
    tenant: TenantId,
    source: &str,
    id: &str,
    payload: Vec<u8>,
) -> anyhow::Result<AuditEventV1> {
    Ok(AuditEventV1::new(
        RecordIdentity::new(
            tenant,
            SourceIdentity::new(
                SourceId::parse(source)?,
                SourceContract::new(
                    ContractId::parse("fixture.operation")?,
                    ContractVersion::from_major(1)?,
                    SchemaDigest::parse(
                        "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
                    )?,
                ),
            ),
            EventId::parse(id)?,
        ),
        EventFacts::new(
            ActorRef::new(ActorKind::parse("user")?, ActorId::parse("actor")?),
            Action::parse("updated")?,
            ResourceRef::new(
                ResourceKind::parse("device")?,
                ResourceId::parse("resource")?,
            ),
            Outcome::Succeeded,
            Timepoint::try_from(123_i64)?,
        ),
        EventContext::new(
            Coordinates::new(None, None, None),
            AuditPayload::new(payload)?,
        ),
    ))
}
fn committed<R, E: std::error::Error + Send + Sync + 'static>(
    attempt: LocalTxAttempt<Committed<R>, E>,
) -> anyhow::Result<R> {
    attempt.fold(
        |v| Ok(v.into_value()),
        |e| Err(e.into()),
        |e| Err(e.into()),
        |e| Err(e.into()),
        |e| Err(e.into()),
        |e| Err(e.into()),
    )
}
fn rolled_back<R, E>(attempt: LocalTxAttempt<Committed<R>, E>, expected: fn(&E) -> bool) {
    assert!(attempt.fold(
        |_| false,
        |_| false,
        |e| expected(&e),
        |_| false,
        |_| false,
        |_| false
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn audit_postgres_suite() -> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(180), run(Workload::Acceptance)).await??;
    Ok(())
}
#[tokio::test]
#[ignore = "isolated release-mode concurrent write capacity"]
async fn audit_write_pressure() -> anyhow::Result<()> {
    run(Workload::Pressure).await
}
#[tokio::test]
#[ignore = "release-mode batch cost comparison"]
async fn audit_batch_cost() -> anyhow::Result<()> {
    run(Workload::BatchCost).await
}

enum Workload {
    BatchCost,
    Acceptance,
    Pressure,
}

async fn run(workload: Workload) -> anyhow::Result<()> {
    let network = testkit::bridge_network("audit-postgres").await?;
    let fixture = testkit::postgres_tls(
        testkit::NetworkAttachment {
            network: network.name(),
            dns_name: "audit-postgres",
        },
        testkit::PgTlsServerIdentity::MatchingHost,
    )
    .await?;
    let (admin, pool) = install_pools(&fixture).await?;
    let clock = TestClock;
    let cancel = CancellationToken::new();
    let cutoff = Deadline::from_timeout(&clock, Duration::from_secs(150))?;
    let control = Control::new(&clock, cutoff, cutoff, &cancel);
    let shared = write_budget()?;
    let plain = PgAudit::new(pool.clone(), Integrity::Plain, shared.clone(), &control)
        .await
        .context("plain startup")?;
    let ledger = PgAudit::new(pool.clone(), Integrity::Ledger(auth()?), shared, &control)
        .await
        .context("ledger startup")?;
    match workload {
        Workload::BatchCost => batch_cost::measure(&plain, &ledger, &pool, &control).await?,
        Workload::Pressure => write_capacity::measure(&pool, &control).await?,
        Workload::Acceptance => {
            exercise(&plain, &ledger, &pool, &admin, &fixture, &control).await?;
            storage_classification(&pool).await?;
        }
    }
    pool.close().await;
    admin.close().await;
    drop(fixture);
    drop(network);
    Ok(())
}
async fn exercise(
    plain: &PgAudit,
    ledger: &PgAudit,
    pool: &PgPool,
    admin: &PgPool,
    fixture: &testkit::PgTlsFixture,
    control: &Control<'_, TestClock>,
) -> anyhow::Result<()> {
    query_cost::run(ledger, pool, admin, control)
        .await
        .context("query_cost::run")?;
    batch::semantics(plain, ledger, pool, admin, control).await?;
    basic(plain, ledger, control).await.context("basic")?;
    atomicity::run(plain, ledger, admin, control)
        .await
        .context("atomicity::run")?;
    reads::run(plain, ledger, admin, control)
        .await
        .context("reads::run")?;
    paging::run(plain, admin, control)
        .await
        .context("paging::run")?;
    messaging::run(plain, ledger, admin, fixture, control)
        .await
        .context("messaging::run")?;
    page_transaction::run(plain, ledger, pool, admin, control)
        .await
        .context("audit page transaction")?;
    composition::run(plain, ledger, admin, control)
        .await
        .context("composition::run")?;
    composition::single_connection(pool)
        .await
        .context("composition::single_connection")?;
    reader::run(ledger, pool, admin, control)
        .await
        .context("reader::run")?;
    write_capacity::run(pool, admin, control)
        .await
        .context("write capacity")?;
    ledger_index::run(plain, ledger, pool, admin, control)
        .await
        .context("ledger_index::run")?;
    admission::run(pool, admin, control)
        .await
        .context("admission::run")?;
    Ok(())
}
async fn install(admin: &PgPool) -> anyhow::Result<()> {
    sqlx::raw_sql("CREATE ROLE audit_owner NOLOGIN NOSUPERUSER NOBYPASSRLS; CREATE ROLE audit_runtime LOGIN PASSWORD 'fixture-password' NOSUPERUSER NOBYPASSRLS; GRANT CREATE ON DATABASE rss_test TO audit_owner;").execute(admin).await?;
    let mut connection = admin.acquire().await?;
    sqlx::raw_sql("SET ROLE audit_owner")
        .execute(&mut *connection)
        .await?;
    sqlx::raw_sql(rss_audit_postgres::MIGRATION_SQL)
        .execute(&mut *connection)
        .await?;
    sqlx::raw_sql(rss_ledger_postgres::MIGRATION_SQL)
        .execute(&mut *connection)
        .await?;
    sqlx::raw_sql("RESET ROLE; GRANT USAGE ON SCHEMA rss_audit,rss_ledger TO audit_runtime; GRANT SELECT ON ALL TABLES IN SCHEMA rss_audit,rss_ledger TO audit_runtime; GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA rss_audit,rss_ledger TO audit_runtime;").execute(&mut *connection).await?;
    Ok(())
}
async fn basic(
    plain: &PgAudit,
    ledger: &PgAudit,
    control: &Control<'_, TestClock>,
) -> anyhow::Result<()> {
    let t = tenant()?;
    let request = plain
        .prepare(event(t, "first", "id-1", vec![1, 2])?, control)
        .await?;
    assert!(
        decode_untrusted(request.canonical_bytes())?
            .recorded_at()
            .unix_seconds()
            > 123
    );
    let first = committed(plain.append(&request, control).await)?;
    assert!(first.inserted());
    assert_eq!(first.record().ledger_sequence(), None);
    let replay = committed(plain.append(&request, control).await)?;
    assert!(!replay.inserted());
    assert_eq!(replay.record().position(), first.record().position());
    assert_eq!(
        replay.record().prepared().canonical_bytes(),
        request.canonical_bytes()
    );
    rolled_back(ledger.append(&request, control).await, conflict);
    conflicts_and_ledger(plain, ledger, control).await?;
    basic_pages(plain, control).await
}

async fn conflicts_and_ledger(
    plain: &PgAudit,
    ledger: &PgAudit,
    control: &Control<'_, TestClock>,
) -> anyhow::Result<()> {
    let t = tenant()?;
    let changed = plain
        .prepare(event(t, "first", "id-1", vec![8])?, control)
        .await?;
    rolled_back(plain.append(&changed, control).await, conflict);
    let second = ledger
        .prepare(event(t, "second", "id-1", vec![3])?, control)
        .await?;
    assert_eq!(
        committed(ledger.append(&second, control).await)?
            .record()
            .ledger_sequence(),
        Some(0)
    );
    Ok(())
}

fn conflict(error: &Error) -> bool {
    matches!(error, Error::Conflict)
}

async fn basic_pages(plain: &PgAudit, control: &Control<'_, TestClock>) -> anyhow::Result<()> {
    let t = tenant()?;
    let page = committed(
        plain
            .read_page(Cursor::start(t), ReadLimit::new(1, 10000)?, control)
            .await,
    )?;
    assert_eq!(page.records().len(), 1);
    rolled_back(
        plain
            .read_page(Cursor::start(t), ReadLimit::new(2, 1)?, control)
            .await,
        |e| matches!(e, Error::ReadBudgetExceeded),
    );
    let last = committed(
        plain
            .read_page(
                page.next()
                    .ok_or_else(|| anyhow::anyhow!("missing cursor"))?,
                ReadLimit::new(2, 10000)?,
                control,
            )
            .await,
    )?;
    assert_eq!(last.records().len(), 1);
    assert!(last.next().is_none());
    Ok(())
}

async fn storage_classification(pool: &PgPool) -> anyhow::Result<()> {
    use rss_audit_postgres::StorageFailure;
    for sql in [
        "SELECT private_missing_function_marker()",
        "SELECT * FROM pg_authid",
    ] {
        let original = sqlx::query(sql)
            .execute(pool)
            .await
            .err()
            .ok_or_else(|| anyhow::anyhow!("expected storage rejection"))?;
        let error = Error::from(original);
        assert!(matches!(
            error,
            Error::Storage {
                kind: StorageFailure::Permanent,
                ..
            }
        ));
        assert!(!format!("{error:?}").contains("private_missing_function_marker"));
        let messaging = rss_transactional_messaging_postgres::PgError::from(error);
        assert_eq!(
            messaging.kind(),
            rss_transactional_messaging::error::MessagingErrorKind::Permanent
        );
    }
    let mut tx = pool.begin().await?;
    sqlx::query("SET LOCAL statement_timeout='10ms'")
        .execute(&mut *tx)
        .await?;
    let original = sqlx::query("SELECT pg_sleep(1)")
        .execute(&mut *tx)
        .await
        .err()
        .ok_or_else(|| anyhow::anyhow!("expected timeout"))?;
    let error = Error::from(original);
    assert!(matches!(
        error,
        Error::Storage {
            kind: StorageFailure::Transient,
            ..
        }
    ));
    assert_eq!(
        rss_transactional_messaging_postgres::PgError::from(error).kind(),
        rss_transactional_messaging::error::MessagingErrorKind::Transient
    );
    tx.rollback().await?;
    Ok(())
}

async fn install_pools(fixture: &testkit::PgTlsFixture) -> anyhow::Result<(PgPool, PgPool)> {
    let p = fixture.params();
    let options = PgConnectOptions::new()
        .host(&p.host)
        .port(p.port)
        .database(&p.database)
        .ssl_mode(PgSslMode::VerifyFull)
        .ssl_root_cert_from_pem(fixture.ca_pem().as_bytes().to_vec());
    let admin = PgPoolOptions::new()
        .max_connections(3)
        .connect_with(options.clone().username(&p.username).password(&p.password))
        .await?;
    install(&admin).await?;
    let pool = PgPoolOptions::new()
        .max_connections(8)
        .connect_with(
            options
                .username("audit_runtime")
                .password("fixture-password"),
        )
        .await?;
    Ok((admin, pool))
}
