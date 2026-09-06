#[path = "support/boundaries.rs"]
mod boundaries;
#[path = "../../../crates/saga/tests/support/mod.rs"]
mod common;
mod process;
#[path = "support/redis_effect.rs"]
mod redis_effect;
use common::*;
use rss_request_context::TenantId;
use rss_saga::*;
use rss_saga_postgres::*;
use sqlx::{
    PgPool,
    postgres::{PgConnectOptions, PgPoolOptions, PgSslMode},
};
use std::{
    sync::{Arc, atomic::Ordering},
    time::Duration,
};
use tokio_util::sync::CancellationToken;

const TENANT: &str = "11111111-2222-4333-8444-555555555555";
const OTHER: &str = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
fn scope(tenant: &str) -> anyhow::Result<Scope> {
    Ok(Scope::new(TenantId::parse(tenant)?, uuid::Uuid::new_v4()))
}
async fn expire(owner: &PgPool, s: Scope) -> anyhow::Result<()> {
    sqlx::query("UPDATE rss_saga.instances SET expires_at=clock_timestamp()-interval '1 second' WHERE tenant_id=$1::text::uuid AND saga_id=$2 AND lease_token IS NOT NULL").bind(s.tenant().to_string()).bind(s.id()).execute(owner).await?;
    Ok(())
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn saga_postgres_suite() -> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(240), suite()).await??;
    Ok(())
}
async fn suite() -> anyhow::Result<()> {
    let network = testkit::bridge_network("saga-pg").await?;
    let fixture = testkit::postgres_tls(
        testkit::NetworkAttachment {
            network: network.name(),
            dns_name: "saga-pg",
        },
        testkit::PgTlsServerIdentity::MatchingHost,
    )
    .await?;
    let (owner, pool) = provision(&fixture).await?;
    let clock = Clock::new();
    let cancel = CancellationToken::new();
    let control = Control::new(&clock, Duration::from_secs(180), &cancel);
    assert!(matches!(
        PgStore::new(owner.clone(), &control).await,
        Err(ref failure) if failure.kind()==rss_saga::ErrorKind::StorageContract
    ));
    let store = PgStore::new(pool.clone(), &control).await?;
    let d = definition(&["one", "two", "three"])?;
    run_scenarios(&store, &owner, &pool, &fixture, &d, &control).await?;
    assert_eq!(store.close(&control).await, CloseOutcome::Drained);
    owner.close().await;
    drop(fixture);
    drop(network);
    Ok(())
}
async fn lease_and_isolation(
    store: &PgStore,
    owner: &PgPool,
    pool: &PgPool,
    d: &Definition,
    control: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    let a = scope(TENANT)?;
    register_tenants(store, a, d, control).await?;
    let stale = store.claim(a, Duration::from_secs(10), control).await?;
    assert_active_claim_rejected(store, a, control).await?;
    expire(owner, a).await?;
    let fresh = store.claim(a, Duration::from_secs(10), control).await?;
    assert!(fresh.epoch() > stale.epoch());
    assert_stale_rejected(store, &stale, control).await;
    assert_eq!(store.snapshot(&fresh, control).await?.revision(), 0);
    isolation_sql(pool).await?;
    store.release(&fresh, control).await?;
    Ok(())
}

async fn unresolved_restart(
    store: &PgStore,
    owner: &PgPool,
    d: &Definition,
    control: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    let s = scope(TENANT)?;
    let effects = Arc::new(Effects::default());
    effects.unknown_once.store(true, Ordering::SeqCst);
    let e = Executor::new(
        store.clone(),
        protection()?,
        registry(d.clone(), effects.clone(), false)?,
    );
    e.register(s, d, control).await?;
    assert!(matches!(
        e.run(s, 30, control).await,
        Err(ref failure) if failure.kind()==rss_saga::ErrorKind::EffectUnknown
    ));
    drop(e);
    expire(owner, s).await?;
    let e = Executor::new(
        store.clone(),
        protection()?,
        registry(d.clone(), effects.clone(), false)?,
    );
    assert_eq!(e.run(s, 30, control).await?.status, Status::Succeeded);
    assert_eq!(
        *effects
            .calls
            .lock()
            .map_err(|_| Error::new(rss_saga::ErrorKind::Store))?,
        vec!["execute:one", "probe:one", "execute:two", "execute:three"]
    );
    sqlx::query("UPDATE rss_saga.step_receipts SET protected=jsonb_set(protected,'{aad}','[]') WHERE saga_id=$1 AND step=0").bind(s.id()).execute(owner).await?;
    assert!(matches!(
        e.run(s, 30, control).await,
        Err(ref failure) if failure.kind()==rss_saga::ErrorKind::Protection
    ));
    Ok(())
}
async fn redis_effects() -> anyhow::Result<()> {
    use redis_effect::*;
    let redis = testkit::managed_redis().await?;
    let pool = deadpool_redis::Config::from_url(redis.url())
        .create_pool(Some(deadpool_redis::Runtime::Tokio1))?;
    let fixture = RedisSagaEffectFixture::new(pool.clone());
    let d = definition(&["one"])?;
    let s = scope(TENANT)?;
    let key = d.effect_key(s, 0, Phase::Forward)?;
    redis_dedup(&fixture, &key).await?;
    let reopened = RedisSagaEffectFixture::new(pool.clone());
    assert_eq!(
        reopened.probe(&key).await?,
        RedisSagaEffectProbeOutcome::Applied
    );
    let observation = fixture.observation();
    assert_eq!(observation.apply_count(), 3);
    assert_eq!(observation.write_count(), 1);
    assert_eq!(observation.duplicate_count(), 1);
    assert_eq!(observation.conflict_count(), 1);
    assert_eq!(observation.probe_count(), 1);
    pool.close();
    drop(redis);
    Ok(())
}
#[path = "support/transport.rs"]
mod transport;

async fn provision(fixture: &testkit::PgTlsFixture) -> anyhow::Result<(PgPool, PgPool)> {
    let params = fixture.params();
    let base = PgConnectOptions::new()
        .host(&params.host)
        .port(params.port)
        .database(&params.database)
        .ssl_mode(PgSslMode::VerifyFull)
        .ssl_root_cert_from_pem(fixture.ca_pem().as_bytes().to_vec());
    let owner = PgPoolOptions::new()
        .max_connections(5)
        .connect_with(
            base.clone()
                .username(&params.username)
                .password(&params.password),
        )
        .await?;
    sqlx::raw_sql("CREATE ROLE saga_owner NOLOGIN NOSUPERUSER NOBYPASSRLS; CREATE ROLE saga_runtime LOGIN PASSWORD 'fixture-only' NOSUPERUSER NOBYPASSRLS; GRANT CREATE ON DATABASE rss_test TO saga_owner;").execute(&owner).await?;
    let mut migration = owner.acquire().await?;
    sqlx::raw_sql("SET ROLE saga_owner")
        .execute(&mut *migration)
        .await?;
    sqlx::raw_sql(MIGRATION_SQL)
        .execute(&mut *migration)
        .await?;
    sqlx::raw_sql("RESET ROLE; GRANT USAGE ON SCHEMA rss_saga TO saga_runtime; GRANT SELECT ON ALL TABLES IN SCHEMA rss_saga TO saga_runtime; GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA rss_saga TO saga_runtime;").execute(&mut *migration).await?;
    drop(migration);
    let options = base.username("saga_runtime").password("fixture-only");
    let pool = PgPoolOptions::new()
        .max_connections(8)
        .connect_with(options.clone())
        .await?;
    Ok((owner, pool))
}

async fn compensation_roundtrip(
    store: &PgStore,
    owner: &PgPool,
    d: &Definition,
    control: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    let s = scope(TENANT)?;
    let effects = Arc::new(Effects::default());
    effects.fail_undo.store(true, Ordering::SeqCst);
    let executor = Executor::new(
        store.clone(),
        protection()?,
        registry(d.clone(), effects.clone(), true)?,
    );
    executor.register(s, d, control).await?;
    let report = executor.run(s, 30, control).await?;
    assert_eq!(report.status, Status::CompensationFailed);
    assert_eq!(
        executor
            .resume(s, report.revision, 30, control)
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
    let counts:(i64,i64)=sqlx::query_as("SELECT (SELECT count(*) FROM rss_saga.journal WHERE saga_id=$1 AND kind='ForwardApplied'),(SELECT count(*) FROM rss_saga.step_receipts WHERE saga_id=$1)").bind(s.id()).fetch_one(owner).await?;
    assert_eq!(counts, (2, 2));
    Ok(())
}

async fn isolation_sql(pool: &PgPool) -> anyhow::Result<()> {
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(TENANT)
        .execute(&mut *tx)
        .await?;
    let cross: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM rss_saga.instances WHERE tenant_id=$1::text::uuid",
    )
    .bind(OTHER)
    .fetch_one(&mut *tx)
    .await?;
    assert_eq!(cross, 0);
    let (id, epoch): (uuid::Uuid, i64) = sqlx::query_as(
        "SELECT saga_id,epoch FROM rss_saga.instances WHERE lease_token IS NULL LIMIT 1",
    )
    .fetch_one(&mut *tx)
    .await?;
    assert!(
        sqlx::query("SELECT rss_saga.lock_instance($1,NULL,$2)")
            .bind(id)
            .bind(epoch)
            .execute(&mut *tx)
            .await
            .is_err()
    );
    tx.rollback().await?;
    assert!(
        sqlx::query("DELETE FROM rss_saga.instances")
            .execute(pool)
            .await
            .is_err()
    );
    Ok(())
}

async fn redis_dedup(
    fixture: &redis_effect::RedisSagaEffectFixture,
    key: &EffectKey,
) -> anyhow::Result<()> {
    use redis_effect::*;
    assert_eq!(
        fixture.probe(key).await?,
        RedisSagaEffectProbeOutcome::Missing
    );
    assert_eq!(
        fixture.apply(key, b"effect").await?,
        RedisSagaEffectApplyOutcome::Applied
    );
    assert_eq!(
        fixture.apply(key, b"effect").await?,
        RedisSagaEffectApplyOutcome::ExactDuplicate
    );
    assert_eq!(
        fixture.apply(key, b"conflict").await?,
        RedisSagaEffectApplyOutcome::Conflict
    );
    Ok(())
}

async fn run_scenarios(
    store: &PgStore,
    owner: &PgPool,
    pool: &PgPool,
    fixture: &testkit::PgTlsFixture,
    d: &Definition,
    control: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    eprintln!("saga T2: compensation_roundtrip");
    compensation_roundtrip(store, owner, d, control).await?;
    typed_success_receipt(store, d, control).await?;
    eprintln!("saga T2: lease_and_isolation");
    lease_and_isolation(store, owner, pool, d, control).await?;
    eprintln!("saga T2: boundaries::fence_during_effect");
    boundaries::fence_during_effect(store, owner, d, control).await?;
    eprintln!("saga T2: boundaries::admission_drift");
    boundaries::admission_drift(pool, owner, control).await?;
    transport::verify(fixture, store, owner, d, control).await?;
    eprintln!("saga T2: unresolved_restart");
    unresolved_restart(store, owner, d, control).await?;
    eprintln!("saga T2: redis_effects");
    redis_effects().await?;
    eprintln!("saga T2: process::crash");
    process::crash(store, owner, fixture, d, control).await?;
    Ok(())
}

async fn register_tenants(
    store: &PgStore,
    a: Scope,
    d: &Definition,
    control: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    let b = Scope::new(TenantId::parse(OTHER)?, a.id());
    store.register(a, d, control).await?;
    store.register(b, d, control).await?;
    Ok(())
}

async fn assert_stale_rejected(store: &PgStore, stale: &Lease, control: &Control<'_, Clock>) {
    assert!(matches!(
        store.snapshot(stale, control).await,
        Err(ref failure) if failure.kind()==rss_saga::ErrorKind::Fenced
    ));
    assert!(matches!(
        store.renew(stale, Duration::from_secs(1), control).await,
        Err(ref failure) if failure.kind()==rss_saga::ErrorKind::Fenced
    ));
}

async fn assert_active_claim_rejected(
    store: &PgStore,
    scope: Scope,
    control: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    let error = store
        .claim(scope, Duration::from_secs(1), control)
        .await
        .err()
        .ok_or(Error::new(ErrorKind::Integrity))?;
    assert_eq!(error.kind(), ErrorKind::Fenced);
    assert_eq!(error.diagnostic().and_then(|d| d.sqlstate()), Some("RS001"));
    assert_eq!(
        error.diagnostic().map(|d| d.phase()),
        Some(DiagnosticPhase::Operation)
    );
    Ok(())
}

async fn typed_success_receipt(
    store: &PgStore,
    d: &Definition,
    control: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    let effects = Arc::new(Effects::default());
    let (builder, completion) = DefinitionBuilder::new(d.clone())?
        .step(Action {
            name: "one",
            fail: false,
            effects: effects.clone(),
        })?
        .step(Action {
            name: "two",
            fail: false,
            effects: effects.clone(),
        })?
        .last_step(Action {
            name: "three",
            fail: false,
            effects,
        })?;
    let e = Executor::new(
        store.clone(),
        protection()?,
        Registry::builder().register(builder)?.finish(),
    );
    let s = scope(TENANT)?;
    e.register(s, d, control).await?;
    let report = e.run(s, 30, control).await?;
    let reference = report
        .success
        .ok_or(Error::new(ErrorKind::ReceiptUnavailable))?;
    assert_eq!(
        e.success_receipt(&reference, &completion, control).await?,
        "three"
    );
    Ok(())
}
