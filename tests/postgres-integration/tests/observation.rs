use rss_contract::Timepoint;
use rss_observation::{
    Access, Authority, Batch, Body, Change, Clock, Coverage, Epoch, Error, ErrorKind, Id,
    LifecycleGrant, ObservationStore, Policy, ReadGrant, ReceiveOutcome, Registration, Scope,
    SyncOutcome, VerifiedBatch,
};
use rss_observation_postgres::{Fault, PgStore};
use rss_request_context::{Deadline, TenantId};
use sqlx::{
    PgPool,
    postgres::{PgConnectOptions, PgPoolOptions, PgSslMode},
};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
const TENANT: &str = "00000000-0000-0000-0000-000000000001";
struct Timer;
impl Clock for Timer {
    #[allow(clippy::disallowed_methods)]
    // reason: host-owned monotonic clock implementation for real provider tests.
    fn now(&self) -> Instant {
        Instant::now()
    }
}
fn deadline() -> Deadline {
    Deadline::at(Timer.now() + Duration::from_secs(20))
}
struct Trusted;
impl Authority for Trusted {
    fn authorize(&self, _: &Scope, _: Option<&Coverage>, _: Access) -> Result<(), Error> {
        Ok(())
    } // reason: fixture authority, never production authentication.
}
fn scope(tenant: &str, registration: &str, source: &str, epoch: &str) -> anyhow::Result<Scope> {
    Ok(Scope::new(
        TenantId::parse(tenant)?,
        Id::new("device")?,
        Registration::new(registration)?,
        Id::new(source)?,
        Id::new("inventory")?,
        Epoch::new(epoch)?,
    ))
}
fn policy() -> Result<Policy, Error> {
    Policy::new(1, 1, 2)
}
fn report(scope: &Scope, id: &str, seq: u64, body: Body) -> anyhow::Result<VerifiedBatch> {
    let coverage = Coverage::new(
        Id::new("all")?,
        Id::new("1")?,
        Id::new("catalog")?,
        Id::new("bytes-v1")?,
    );
    Ok(VerifiedBatch::verify(
        &Trusted,
        scope.clone(),
        Batch::new(Id::new(id)?, seq, Timepoint::try_from(100)?, coverage, body)?,
    )?)
}
fn snapshot(scope: &Scope, id: &str, seq: u64) -> anyhow::Result<VerifiedBatch> {
    report(
        scope,
        id,
        seq,
        Body::Snapshot(vec![Change::upsert(Id::new("item")?, vec![1, 2, 3])]),
    )
}
fn read_grant(scope: &Scope) -> Result<ReadGrant, Error> {
    ReadGrant::verify(&Trusted, scope.clone())
}
async fn activate(
    store: &PgStore<Timer>,
    scope: &Scope,
    expected: Option<u64>,
) -> anyhow::Result<u64> {
    Ok(store
        .activate(
            &LifecycleGrant::verify(&Trusted, scope.clone())?,
            expected,
            &policy()?,
            deadline(),
        )
        .await?)
}
async fn cursor(store: &PgStore<Timer>, scope: &Scope) -> anyhow::Result<Option<u64>> {
    Ok(store.state(&read_grant(scope)?, deadline()).await?.cursor())
}
async fn runtime_pool(params: &testkit::PgConnParams, ca: &str) -> anyhow::Result<PgPool> {
    Ok(PgPoolOptions::new()
        .max_connections(6)
        .connect_with(
            PgConnectOptions::new()
                .host(&params.host)
                .port(params.port)
                .database(&params.database)
                .username("obs_runtime")
                .password("fixture-only")
                .ssl_mode(PgSslMode::VerifyFull)
                .ssl_root_cert_from_pem(ca.as_bytes().to_vec()),
        )
        .await?)
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn observation_atomic_recovery() -> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(180), suite()).await??;
    Ok(())
}
async fn suite() -> anyhow::Result<()> {
    let network = testkit::bridge_network("obs-pg").await?;
    let fixture = testkit::postgres_tls(
        testkit::NetworkAttachment {
            network: network.name(),
            dns_name: "obs-pg",
        },
        testkit::PgTlsServerIdentity::MatchingHost,
    )
    .await?;
    let params = fixture.params();
    let (admin, owner, pool) = prepare(params, fixture.ca_pem()).await?;
    let store = Arc::new(PgStore::new(pool.clone(), Timer, deadline()).await?);
    let base = scope(TENANT, "registration-1", "agent", "epoch-1")?;
    receipt_identity(&store, &base).await?;
    delta_gap(&store, &base).await?;
    review_regressions(&admin, &pool, &store).await?;
    contract_checks(&store, &base, &admin, &pool).await?;
    new_regressions(params, fixture.ca_pem(), &admin, &pool, &store, &base).await?;
    recovery_process(&admin, params, fixture.ca_pem(), &store).await?;
    restart(params, fixture.ca_pem(), &store, &base).await?;
    owner.close().await;
    admin.close().await;
    Ok(())
}
async fn faults(store: &PgStore<Timer>, scope: &Scope) -> anyhow::Result<()> {
    for (fault, id, seq, expected) in [
        (Fault::BeforeCommit, "rollback", 4, ErrorKind::Storage),
        (
            Fault::RollbackAckLost,
            "rollback-unknown",
            5,
            ErrorKind::RollbackFailed,
        ),
    ] {
        store.inject_next_fault(fault);
        assert_eq!(
            store
                .receive(&snapshot(scope, id, seq)?, deadline())
                .await
                .err()
                .map(|e| e.kind()),
            Some(expected)
        );
        assert!(
            store
                .lookup(&read_grant(scope)?, &Id::new(id)?, deadline())
                .await?
                .is_none()
        );
        assert_eq!(cursor(store, scope).await?, Some(1));
    }
    commit_faults(store, scope).await
}
async fn commit_faults(store: &PgStore<Timer>, scope: &Scope) -> anyhow::Result<()> {
    store.inject_next_fault(Fault::CommitAckLost);
    let saved = store
        .receive(&snapshot(scope, "ack-lost", 6)?, deadline())
        .await?;
    assert!(matches!(saved, ReceiveOutcome::Replay(_)));
    store.inject_next_fault(Fault::CommitAckAndReadLost);
    let uncertain = snapshot(scope, "unknown", 7)?;
    assert_eq!(
        store
            .receive(&uncertain, deadline())
            .await
            .err()
            .map(|e| e.kind()),
        Some(ErrorKind::CommitUnknown)
    );
    store
        .receive(&snapshot(scope, "later", 8)?, deadline())
        .await?;
    // Exact receipt restoration must not compare its historical cursor to the current head.
    assert_eq!(
        store
            .receive(&uncertain, deadline())
            .await?
            .record()
            .decision()
            .state()
            .cursor(),
        Some(7)
    );
    assert_eq!(cursor(store, scope).await?, Some(8));
    store.inject_next_fault(Fault::CommitPending);
    let short = Deadline::at(Timer.now() + Duration::from_millis(100));
    assert_eq!(
        store
            .receive(&snapshot(scope, "timeout", 9)?, short)
            .await
            .err()
            .map(|e| e.kind()),
        Some(ErrorKind::CommitUnknown)
    );
    assert!(
        store
            .lookup(&read_grant(scope)?, &Id::new("timeout")?, deadline())
            .await?
            .is_none()
    );
    Ok(())
}
async fn isolation(store: &PgStore<Timer>, base: &Scope) -> anyhow::Result<()> {
    let other = scope(
        "00000000-0000-0000-0000-000000000002",
        "registration-1",
        "agent",
        "epoch-1",
    )?;
    assert_eq!(activate(store, &other, None).await?, 1);
    assert!(
        store
            .lookup(&read_grant(&other)?, &Id::new("s1")?, deadline())
            .await?
            .is_none()
    );
    store
        .receive(&snapshot(&other, "s1", 0)?, deadline())
        .await?;
    let source = scope(TENANT, "registration-1", "scanner", "epoch-1")?;
    assert_eq!(activate(store, &source, Some(1)).await?, 2);
    store
        .receive(&snapshot(&source, "s1", 0)?, deadline())
        .await?;
    epoch_replacement(store, base).await?;
    registration_replacement(store, &source).await
}
async fn epoch_replacement(store: &PgStore<Timer>, base: &Scope) -> anyhow::Result<()> {
    let epoch = scope(TENANT, "registration-1", "agent", "epoch-2")?;
    assert_eq!(activate(store, &epoch, Some(2)).await?, 3);
    assert_eq!(
        store
            .receive(&snapshot(base, "old-new", 100)?, deadline())
            .await
            .err()
            .map(|e| e.kind()),
        Some(ErrorKind::StaleEpoch)
    );
    assert!(matches!(
        store.receive(&snapshot(base, "s1", 0)?, deadline()).await?,
        ReceiveOutcome::Replay(_)
    ));
    assert_eq!(
        activate(store, base, Some(3))
            .await
            .err()
            .and_then(|e| e.downcast_ref::<Error>().map(Error::kind)),
        Some(ErrorKind::LifecycleConflict)
    );
    Ok(())
}
async fn registration_replacement(store: &PgStore<Timer>, source: &Scope) -> anyhow::Result<()> {
    let registration = scope(TENANT, "registration-2", "agent", "epoch-1")?;
    assert_eq!(activate(store, &registration, Some(3)).await?, 4);
    assert!(
        store
            .lookup(&read_grant(&registration)?, &Id::new("s1")?, deadline())
            .await?
            .is_none()
    );
    assert_eq!(
        store
            .receive(&snapshot(source, "late", 1)?, deadline())
            .await
            .err()
            .map(|e| e.kind()),
        Some(ErrorKind::StaleEpoch)
    );
    let resurrect = scope(TENANT, "registration-1", "agent", "epoch-3")?;
    assert!(activate(store, &resurrect, Some(4)).await.is_err());
    // A missing expected revision cannot bypass lifecycle CAS via SQL NULL semantics.
    assert!(
        activate(
            store,
            &scope(TENANT, "registration-3", "agent", "epoch-1")?,
            None
        )
        .await
        .is_err()
    );
    Ok(())
}
async fn expiry(store: &PgStore<Timer>) -> anyhow::Result<()> {
    let s = scope(
        "00000000-0000-0000-0000-000000000003",
        "registration",
        "source",
        "epoch",
    )?;
    activate(store, &s, None).await?;
    let first = snapshot(&s, "base", u64::MAX - 2)?;
    let original = store.receive(&first, deadline()).await?;
    tokio::time::sleep(Duration::from_secs(3)).await;
    let replayed = store.receive(&first, deadline()).await?;
    assert_eq!(
        replayed.record().received_at(),
        original.record().received_at()
    );
    let delta = report(
        &s,
        "expired",
        u64::MAX - 1,
        Body::Delta {
            baseline: Id::new("base")?,
            previous: u64::MAX - 2,
            changes: vec![],
        },
    )?;
    assert!(
        !store
            .receive(&delta, deadline())
            .await?
            .record()
            .decision()
            .outcome()
            .is_applicable()
    );
    assert_eq!(cursor(store, &s).await?, Some(u64::MAX - 2));
    assert_eq!(
        store
            .receive(&snapshot(&s, "full-u64", u64::MAX)?, deadline())
            .await?
            .record()
            .decision()
            .state()
            .cursor(),
        Some(u64::MAX)
    );
    Ok(())
}
async fn role_checks(admin: &PgPool, pool: &PgPool) -> anyhow::Result<()> {
    assert!(
        sqlx::query("DELETE FROM rss_observation.batches")
            .execute(pool)
            .await
            .is_err()
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM rss_observation.batches")
            .fetch_one(pool)
            .await?,
        0
    );
    sqlx::query("ALTER TABLE rss_observation.batches NO FORCE ROW LEVEL SECURITY")
        .execute(admin)
        .await?;
    assert!(PgStore::new(pool.clone(), Timer, deadline()).await.is_err());
    sqlx::query("ALTER TABLE rss_observation.batches FORCE ROW LEVEL SECURITY")
        .execute(admin)
        .await?;
    sqlx::query("GRANT UPDATE ON rss_observation.batches TO obs_runtime")
        .execute(admin)
        .await?;
    assert!(PgStore::new(pool.clone(), Timer, deadline()).await.is_err());
    sqlx::query("REVOKE UPDATE ON rss_observation.batches FROM obs_runtime")
        .execute(admin)
        .await?;
    schema_checks(admin, pool).await
}
async fn schema_checks(admin: &PgPool, pool: &PgPool) -> anyhow::Result<()> {
    sqlx::query("ALTER TABLE rss_observation.batches ALTER COLUMN sequence TYPE numeric(21,0)")
        .execute(admin)
        .await?;
    assert!(PgStore::new(pool.clone(), Timer, deadline()).await.is_err());
    sqlx::query("ALTER TABLE rss_observation.batches ALTER COLUMN sequence TYPE numeric(20,0)")
        .execute(admin)
        .await?;
    sqlx::query("COMMENT ON SCHEMA rss_observation IS 'unknown-version'")
        .execute(admin)
        .await?;
    assert!(PgStore::new(pool.clone(), Timer, deadline()).await.is_err());
    sqlx::query("COMMENT ON SCHEMA rss_observation IS 'rss-observation-postgres:1'")
        .execute(admin)
        .await?;
    assert!(PgStore::new(pool.clone(), Timer, deadline()).await.is_ok());
    Ok(())
}
async fn recovery_process(
    admin: &PgPool,
    params: &testkit::PgConnParams,
    ca: &str,
    store: &PgStore<Timer>,
) -> anyhow::Result<()> {
    let s = scope(
        "00000000-0000-0000-0000-000000000004",
        "registration",
        "source",
        "epoch",
    )?;
    activate(store, &s, None).await?;
    let mut config = tempfile::NamedTempFile::new()?;
    use std::io::Write;
    write!(
        config,
        "{}",
        serde_json::json!({"host":params.host,"port":params.port,"database":params.database,"ca":ca})
    )?;
    for mode in ["before", "after"] {
        let mut child = std::process::Command::new(std::env::current_exe()?)
            .args(["--exact", "observation_process_child", "--nocapture"])
            .env("OBS_FIXTURE_CONFIG", config.path())
            .env("OBS_FIXTURE_MODE", mode)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()?;
        let observed=tokio::time::timeout(Duration::from_secs(15),async{
            loop {
                if mode=="after" && store.lookup(&read_grant(&s)?,&Id::new(mode)?,deadline()).await?.is_some(){break;}
                if mode=="before"{
                    let ready:bool=sqlx::query_scalar("SELECT EXISTS(SELECT FROM pg_stat_activity WHERE application_name='observation-crash' AND state='idle in transaction' AND query LIKE '%commit_batch%')").fetch_one(admin).await?;
                    if ready{break;}
                }
                if child.try_wait()?.is_some(){anyhow::bail!("child exited before recovery checkpoint");}
                tokio::time::sleep(Duration::from_millis(25)).await;
            }Ok::<(),anyhow::Error>(())
        }).await;
        let killed = child.kill();
        let waited = child.wait();
        killed?;
        waited?;
        observed??;
        let record = store
            .lookup(&read_grant(&s)?, &Id::new(mode)?, deadline())
            .await?;
        assert_eq!(record.is_some(), mode == "after");
    }
    let input = snapshot(&s, "after", 1)?;
    assert!(matches!(
        store.receive(&input, deadline()).await?,
        ReceiveOutcome::Replay(_)
    ));
    Ok(())
}
#[test]
fn observation_process_child() -> anyhow::Result<()> {
    let Some(path) = std::env::var_os("OBS_FIXTURE_CONFIG") else {
        return Ok(());
    }; // reason: only parent invocation owns a database fixture.
    let config: serde_json::Value = serde_json::from_slice(&std::fs::read(path)?)?;
    let mode = std::env::var("OBS_FIXTURE_MODE")?;
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let host = config["host"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("host"))?;
            let database = config["database"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("database"))?;
            let port = u16::try_from(
                config["port"]
                    .as_u64()
                    .ok_or_else(|| anyhow::anyhow!("port"))?,
            )?;
            let ca = config["ca"].as_str().ok_or_else(|| anyhow::anyhow!("ca"))?;
            let pool = PgPoolOptions::new()
                .max_connections(1)
                .connect_with(
                    PgConnectOptions::new()
                        .host(host)
                        .port(port)
                        .database(database)
                        .username("obs_runtime")
                        .password("fixture-only")
                        .ssl_mode(PgSslMode::VerifyFull)
                        .ssl_root_cert_from_pem(ca.as_bytes().to_vec())
                        .application_name("observation-crash"),
                )
                .await?;
            let store = PgStore::new(pool, Timer, deadline()).await?;
            let s = scope(
                "00000000-0000-0000-0000-000000000004",
                "registration",
                "source",
                "epoch",
            )?;
            if mode == "before" {
                store.inject_next_fault(Fault::CommitPending);
            }
            store.receive(&snapshot(&s, &mode, 1)?, deadline()).await?;
            std::future::pending::<()>().await;
            Ok::<(), anyhow::Error>(())
        })
}

async fn activation_unknown(store: &PgStore<Timer>) -> anyhow::Result<()> {
    let s = scope(
        "00000000-0000-0000-0000-000000000005",
        "registration",
        "source",
        "epoch",
    )?;
    store.inject_next_fault(Fault::CommitAckLost);
    assert_eq!(activate(store, &s, None).await?, 1);
    let next = scope(
        "00000000-0000-0000-0000-000000000005",
        "registration",
        "source",
        "next",
    )?;
    store.inject_next_fault(Fault::CommitAckAndReadLost);
    assert!(activate(store, &next, Some(1)).await.is_err());
    assert_eq!(activate(store, &next, Some(1)).await?, 2);
    Ok(())
}
async fn evidence_corruption(
    admin: &PgPool,
    store: &PgStore<Timer>,
    scope: &Scope,
) -> anyhow::Result<()> {
    let raw: Vec<u8> = sqlx::query_scalar(
        "SELECT raw FROM rss_observation.batches WHERE scope=$1 AND batch_id='s1'",
    )
    .bind(scope.encode()?)
    .fetch_one(admin)
    .await?;
    sqlx::query("UPDATE rss_observation.batches SET raw=$1 WHERE scope=$2 AND batch_id='s1'")
        .bind(b"[]".as_slice())
        .bind(scope.encode()?)
        .execute(admin)
        .await?;
    assert_eq!(
        store
            .lookup(&read_grant(scope)?, &Id::new("s1")?, deadline())
            .await
            .err()
            .map(|e| e.kind()),
        Some(ErrorKind::Invariant)
    );
    sqlx::query("UPDATE rss_observation.batches SET raw=$1 WHERE scope=$2 AND batch_id='s1'")
        .bind(raw)
        .bind(scope.encode()?)
        .execute(admin)
        .await?;
    Ok(())
}

async fn prepare(
    params: &testkit::PgConnParams,
    ca: &str,
) -> anyhow::Result<(PgPool, PgPool, PgPool)> {
    let options = PgConnectOptions::new()
        .host(&params.host)
        .port(params.port)
        .database(&params.database)
        .username(&params.username)
        .password(&params.password)
        .ssl_mode(PgSslMode::VerifyFull)
        .ssl_root_cert_from_pem(ca.as_bytes().to_vec());
    let admin = PgPoolOptions::new()
        .max_connections(3)
        .connect_with(options.clone())
        .await?;
    sqlx::raw_sql("CREATE ROLE obs_owner LOGIN PASSWORD 'owner-fixture' NOSUPERUSER NOBYPASSRLS; CREATE ROLE obs_runtime LOGIN PASSWORD 'fixture-only' NOSUPERUSER NOBYPASSRLS; GRANT CREATE ON DATABASE rss_test TO obs_owner;").execute(&admin).await?;
    let owner = PgPoolOptions::new()
        .max_connections(2)
        .connect_with(options.username("obs_owner").password("owner-fixture"))
        .await?;
    sqlx::raw_sql(rss_observation_postgres::MIGRATION_SQL)
        .execute(&owner)
        .await?;
    sqlx::raw_sql("GRANT USAGE ON SCHEMA rss_observation TO obs_runtime; GRANT SELECT ON ALL TABLES IN SCHEMA rss_observation TO obs_runtime; GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA rss_observation TO obs_runtime;").execute(&owner).await?;
    let pool = runtime_pool(params, ca).await?;
    Ok((admin, owner, pool))
}

async fn receipt_identity(store: &PgStore<Timer>, base: &Scope) -> anyhow::Result<()> {
    assert_eq!(activate(store, base, None).await?, 1);
    assert_eq!(activate(store, base, None).await?, 1);
    let input = snapshot(base, "s1", 0)?;
    let (a, b) = tokio::join!(
        store.receive(&input, deadline()),
        store.receive(&input, deadline())
    );
    let a = a?;
    let b = b?;
    assert!(matches!(
        (&a, &b),
        (ReceiveOutcome::Accepted(_), ReceiveOutcome::Replay(_))
            | (ReceiveOutcome::Replay(_), ReceiveOutcome::Accepted(_))
    ));
    assert_eq!(a.record().received_at(), b.record().received_at());
    assert_eq!(a.record().decision(), b.record().decision());
    let changed = report(base, "s1", 0, Body::Snapshot(vec![]))?;
    assert_eq!(
        store
            .receive(&changed, deadline())
            .await
            .err()
            .map(|e| e.kind()),
        Some(ErrorKind::Conflict)
    );
    assert_eq!(
        store
            .receive(&snapshot(base, "same-seq", 0)?, deadline())
            .await
            .err()
            .map(|e| e.kind()),
        Some(ErrorKind::Conflict)
    );
    Ok(())
}

async fn delta_gap(store: &PgStore<Timer>, base: &Scope) -> anyhow::Result<()> {
    let delta = report(
        base,
        "d1",
        1,
        Body::Delta {
            baseline: Id::new("s1")?,
            previous: 0,
            changes: vec![Change::delete(Id::new("item")?)],
        },
    )?;
    assert_eq!(
        store
            .receive(&delta, deadline())
            .await?
            .record()
            .decision()
            .outcome(),
        &SyncOutcome::Delta
    );
    let gap = report(
        base,
        "gap",
        3,
        Body::Delta {
            baseline: Id::new("s1")?,
            previous: 2,
            changes: vec![],
        },
    )?;
    assert!(
        !store
            .receive(&gap, deadline())
            .await?
            .record()
            .decision()
            .outcome()
            .is_applicable()
    );
    assert_eq!(cursor(store, base).await?, Some(1));
    Ok(())
}

async fn restart(
    params: &testkit::PgConnParams,
    ca: &str,
    store: &PgStore<Timer>,
    base: &Scope,
) -> anyhow::Result<()> {
    // Re-adopt a fresh pool against the same database; no in-memory receipt or state is needed.
    store.close(deadline()).await?;
    assert!(store.is_closed());
    let restarted = PgStore::new(runtime_pool(params, ca).await?, Timer, deadline()).await?;
    assert!(
        restarted
            .lookup(&read_grant(base)?, &Id::new("s1")?, deadline())
            .await?
            .is_some()
    );
    assert!(matches!(
        restarted
            .receive(&snapshot(base, "s1", 0)?, deadline())
            .await?,
        ReceiveOutcome::Replay(_)
    ));
    restarted.close(deadline()).await?;
    Ok(())
}

async fn contract_checks(
    store: &PgStore<Timer>,
    base: &Scope,
    admin: &PgPool,
    pool: &PgPool,
) -> anyhow::Result<()> {
    faults(store, base).await?;
    isolation(store, base).await?;
    expiry(store).await?;
    role_checks(admin, pool).await?;
    activation_unknown(store).await?;
    evidence_corruption(admin, store, base).await?;
    Ok(())
}

async fn new_regressions(
    params: &testkit::PgConnParams,
    ca: &str,
    admin: &PgPool,
    pool: &PgPool,
    store: &PgStore<Timer>,
    base: &Scope,
) -> anyhow::Result<()> {
    public_acl(admin, pool).await?;
    default_function_acl(admin, pool).await?;
    acquire_timeout(pool, store, base).await?;
    rollback_pending(pool, store, base).await?;
    degraded_recovery(params, ca).await?;
    damaged_state(admin, store, base).await?;
    let missing = scope(TENANT, "unknown", "source", "epoch")?;
    assert_eq!(
        store
            .state(&read_grant(&missing)?, deadline())
            .await
            .err()
            .map(|e| e.kind()),
        Some(ErrorKind::UnknownStream)
    );
    Ok(())
}
async fn public_acl(admin: &PgPool, pool: &PgPool) -> anyhow::Result<()> {
    for (grant, revoke) in [
        (
            "GRANT USAGE ON SCHEMA rss_observation TO PUBLIC",
            "REVOKE USAGE ON SCHEMA rss_observation FROM PUBLIC",
        ),
        (
            "GRANT SELECT ON rss_observation.batches TO PUBLIC",
            "REVOKE SELECT ON rss_observation.batches FROM PUBLIC",
        ),
        (
            "GRANT SELECT(raw) ON rss_observation.batches TO PUBLIC",
            "REVOKE SELECT(raw) ON rss_observation.batches FROM PUBLIC",
        ),
    ] {
        sqlx::query(grant).execute(admin).await?;
        assert!(PgStore::new(pool.clone(), Timer, deadline()).await.is_err());
        sqlx::query(revoke).execute(admin).await?;
    }
    assert!(PgStore::new(pool.clone(), Timer, deadline()).await.is_ok());
    Ok(())
}
async fn acquire_timeout(
    pool: &PgPool,
    store: &PgStore<Timer>,
    scope: &Scope,
) -> anyhow::Result<()> {
    let mut held = Vec::new();
    for _ in 0..6 {
        held.push(pool.acquire().await?);
    }
    let short = Deadline::at(Timer.now() + Duration::from_millis(30));
    assert_eq!(
        store
            .receive(&snapshot(scope, "no-attempt", 100)?, short)
            .await
            .err()
            .map(|e| e.kind()),
        Some(ErrorKind::Deadline)
    );
    drop(held);
    Ok(())
}
async fn rollback_pending(
    pool: &PgPool,
    store: &PgStore<Timer>,
    scope: &Scope,
) -> anyhow::Result<()> {
    let short = || Deadline::at(Timer.now() + Duration::from_millis(100));
    store.inject_next_fault(Fault::RollbackPending);
    assert_eq!(
        store
            .lookup(&read_grant(scope)?, &Id::new("s1")?, short())
            .await
            .err()
            .map(|e| e.kind()),
        Some(ErrorKind::RollbackFailed)
    );
    store.inject_next_fault(Fault::RollbackPending);
    assert_eq!(
        store
            .receive(&snapshot(scope, "rollback-wait", 100)?, short())
            .await
            .err()
            .map(|e| e.kind()),
        Some(ErrorKind::RollbackFailed)
    );
    assert_eq!(
        PgStore::new_with_fault(pool.clone(), Timer, short(), Fault::RollbackPending)
            .await
            .err()
            .map(|e| e.kind()),
        Some(ErrorKind::RollbackFailed)
    );
    Ok(())
}
async fn degraded_recovery(params: &testkit::PgConnParams, ca: &str) -> anyhow::Result<()> {
    let store = PgStore::new(runtime_pool(params, ca).await?, Timer, deadline()).await?;
    let s = scope(
        "00000000-0000-0000-0000-000000000006",
        "registration",
        "source",
        "epoch",
    )?;
    activate(&store, &s, None).await?;
    store.receive(&snapshot(&s, "base", 1)?, deadline()).await?;
    let gap = report(
        &s,
        "gap",
        3,
        Body::Delta {
            baseline: Id::new("base")?,
            previous: 2,
            changes: vec![],
        },
    )?;
    store.receive(&gap, deadline()).await?;
    store.close(deadline()).await?;
    let restarted = PgStore::new(runtime_pool(params, ca).await?, Timer, deadline()).await?;
    assert_degraded(&restarted, &s).await?;
    restarted.close(deadline()).await?;
    Ok(())
}
async fn assert_degraded(store: &PgStore<Timer>, scope: &Scope) -> anyhow::Result<()> {
    let state = store.state(&read_grant(scope)?, deadline()).await?;
    assert_eq!(state.cursor(), Some(1));
    assert_eq!(
        state.needs_snapshot(),
        Some(&rss_observation::NeedSnapshot::Gap)
    );
    store
        .receive(&snapshot(scope, "recovery", 4)?, deadline())
        .await?;
    let state = store.state(&read_grant(scope)?, deadline()).await?;
    assert_eq!(state.cursor(), Some(4));
    assert_eq!(state.needs_snapshot(), None);
    Ok(())
}
async fn damaged_state(admin: &PgPool, store: &PgStore<Timer>, base: &Scope) -> anyhow::Result<()> {
    let s = scope(TENANT, "registration-2", "agent", "epoch-1")?;
    let saved: String =
        sqlx::query_scalar("SELECT state FROM rss_observation.streams WHERE scope=$1")
            .bind(s.encode()?)
            .fetch_one(admin)
            .await?;
    // Keep the generated revision readable while damaging the core-owned envelope version.
    let malformed = saved
        .replace("\"version\": 1", "\"version\": 2")
        .replace("\"version\":1", "\"version\":2");
    sqlx::query("UPDATE rss_observation.streams SET state=$1 WHERE scope=$2")
        .bind(&malformed)
        .bind(s.encode()?)
        .execute(admin)
        .await?;
    assert_eq!(
        store
            .receive(&snapshot(&s, "bad-state", 0)?, deadline())
            .await
            .err()
            .map(|e| e.kind()),
        Some(ErrorKind::Invariant)
    );
    sqlx::query("UPDATE rss_observation.streams SET state=$1 WHERE scope=$2")
        .bind(saved)
        .bind(s.encode()?)
        .execute(admin)
        .await?;
    assert!(
        store
            .lookup(&read_grant(base)?, &Id::new("s1")?, deadline())
            .await?
            .is_some()
    );
    Ok(())
}

async fn default_function_acl(admin: &PgPool, pool: &PgPool) -> anyhow::Result<()> {
    let definition:String=sqlx::query_scalar("SELECT pg_get_functiondef('rss_observation.activate(text,numeric,text,text)'::regprocedure)").fetch_one(admin).await?;
    let mut tx = admin.begin().await?;
    sqlx::query("SET LOCAL ROLE obs_owner")
        .execute(&mut *tx)
        .await?;
    sqlx::query("DROP FUNCTION rss_observation.activate(text,numeric,text,text)")
        .execute(&mut *tx)
        .await?;
    // The SQL comes solely from this fixture-owned component function, never from a caller.
    sqlx::raw_sql(sqlx::AssertSqlSafe(definition))
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    // A newly recreated function has implicit PUBLIC EXECUTE even when proacl is NULL.
    assert!(PgStore::new(pool.clone(), Timer, deadline()).await.is_err());
    sqlx::raw_sql("REVOKE ALL ON FUNCTION rss_observation.activate(text,numeric,text,text) FROM PUBLIC; GRANT EXECUTE ON FUNCTION rss_observation.activate(text,numeric,text,text) TO obs_runtime;").execute(admin).await?;
    assert!(PgStore::new(pool.clone(), Timer, deadline()).await.is_ok());
    Ok(())
}

async fn review_regressions(
    admin: &PgPool,
    pool: &PgPool,
    store: &PgStore<Timer>,
) -> anyhow::Result<()> {
    inherited_without_set(admin, pool).await?;
    pre_effect_lock_deadline(admin, store).await?;
    server_watchdogs(admin, store).await?;
    Ok(())
}
async fn inherited_without_set(admin: &PgPool, pool: &PgPool) -> anyhow::Result<()> {
    sqlx::raw_sql("CREATE ROLE obs_inherited NOLOGIN; GRANT obs_inherited TO obs_runtime WITH INHERIT TRUE, SET FALSE; GRANT UPDATE ON rss_observation.batches TO obs_inherited;").execute(admin).await?;
    let rights:(bool,bool,bool)=sqlx::query_as("SELECT pg_has_role(current_user,'obs_inherited','USAGE'),pg_has_role(current_user,'obs_inherited','SET'),has_table_privilege(current_user,'rss_observation.batches','UPDATE')").fetch_one(pool).await?;
    assert_eq!(rights, (true, false, true));
    assert_eq!(
        PgStore::new(pool.clone(), Timer, deadline())
            .await
            .err()
            .map(|e| e.kind()),
        Some(ErrorKind::Invariant)
    );
    sqlx::raw_sql("REVOKE UPDATE ON rss_observation.batches FROM obs_inherited; GRANT CREATE ON SCHEMA rss_observation TO obs_inherited;").execute(admin).await?;
    assert!(PgStore::new(pool.clone(), Timer, deadline()).await.is_err());
    sqlx::raw_sql("REVOKE CREATE ON SCHEMA rss_observation FROM obs_inherited; REVOKE obs_inherited FROM obs_runtime; DROP ROLE obs_inherited;").execute(admin).await?;
    assert!(PgStore::new(pool.clone(), Timer, deadline()).await.is_ok());
    Ok(())
}
async fn pre_effect_lock_deadline(admin: &PgPool, store: &PgStore<Timer>) -> anyhow::Result<()> {
    let s = scope(
        "00000000-0000-0000-0000-000000000007",
        "registration",
        "source",
        "epoch",
    )?;
    activate(store, &s, None).await?;
    store.receive(&snapshot(&s, "base", 1)?, deadline()).await?;
    let mut blocker = admin.begin().await?;
    sqlx::query("SELECT 1 FROM rss_observation.streams WHERE scope=$1 FOR UPDATE")
        .bind(s.encode()?)
        .execute(&mut *blocker)
        .await?;
    store.inject_next_fault(Fault::ClientDeadlineOnly);
    let result = store
        .receive(
            &snapshot(&s, "blocked", 2)?,
            Deadline::at(Timer.now() + Duration::from_millis(100)),
        )
        .await;
    blocker.rollback().await?;
    assert_eq!(result.err().map(|e| e.kind()), Some(ErrorKind::Deadline));
    assert!(
        store
            .lookup(&read_grant(&s)?, &Id::new("blocked")?, deadline())
            .await?
            .is_none()
    );
    assert_eq!(cursor(store, &s).await?, Some(1));
    Ok(())
}

async fn server_watchdogs(admin: &PgPool, store: &PgStore<Timer>) -> anyhow::Result<()> {
    let s = scope(
        "00000000-0000-0000-0000-000000000008",
        "registration",
        "source",
        "epoch",
    )?;
    activate(store, &s, None).await?;
    store.receive(&snapshot(&s, "base", 1)?, deadline()).await?;
    server_lock_wait(admin, store, &s, Fault::ShortStatementWatchdog).await?;
    server_lock_wait(admin, store, &s, Fault::ShortLockWatchdog).await?;
    store.inject_next_fault(Fault::StatementTimeoutAfterWrite);
    let result = store
        .receive(&snapshot(&s, "cancelled-write", 2)?, deadline())
        .await;
    assert_eq!(result.err().map(|e| e.kind()), Some(ErrorKind::Deadline));
    assert_eq!(cursor(store, &s).await?, Some(1));
    assert!(
        store
            .lookup(&read_grant(&s)?, &Id::new("cancelled-write")?, deadline())
            .await?
            .is_none()
    );
    Ok(())
}
async fn server_lock_wait(
    admin: &PgPool,
    store: &PgStore<Timer>,
    scope: &Scope,
    fault: Fault,
) -> anyhow::Result<()> {
    let mut blocker = admin.begin().await?;
    sqlx::query("SELECT 1 FROM rss_observation.streams WHERE scope=$1 FOR UPDATE")
        .bind(scope.encode()?)
        .execute(&mut *blocker)
        .await?;
    store.inject_next_fault(fault);
    let result = store
        .receive(&snapshot(scope, "blocked", 2)?, deadline())
        .await;
    blocker.rollback().await?;
    assert_eq!(result.err().map(|e| e.kind()), Some(ErrorKind::Deadline));
    Ok(())
}
