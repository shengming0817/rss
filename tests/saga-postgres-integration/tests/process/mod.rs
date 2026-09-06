use super::*;
use std::{path::PathBuf, process::Stdio};
use tokio::process::Command;

struct RedisStep {
    name: &'static str,
    pool: deadpool_redis::Pool,
    marker: Option<PathBuf>,
    before_effect: bool,
}
impl Step for RedisStep {
    type Receipt = String;
    fn name(&self) -> &str {
        self.name
    }
    fn receipt_schema(&self) -> &str {
        "receipt.v1"
    }
    async fn execute(&self, context: EffectContext) -> EffectOutcome<String> {
        if self.before_effect
            && let Some(marker) = &self.marker
        {
            if std::fs::write(marker, b"intent-durable-effect-absent").is_err() {
                return EffectOutcome::Unknown;
            }
            return std::future::pending().await;
        }
        let fixture = redis_effect::RedisSagaEffectFixture::new(self.pool.clone());
        match fixture
            .apply(context.idempotency_key(), self.name.as_bytes())
            .await
        {
            Ok(
                redis_effect::RedisSagaEffectApplyOutcome::Applied
                | redis_effect::RedisSagaEffectApplyOutcome::ExactDuplicate,
            ) => {
                if let Some(marker) = &self.marker {
                    if std::fs::write(marker, b"external-effect-durable").is_err() {
                        return EffectOutcome::Unknown;
                    }
                    return std::future::pending().await;
                }
                EffectOutcome::Applied(self.name.into())
            }
            Ok(redis_effect::RedisSagaEffectApplyOutcome::Conflict) => EffectOutcome::NotApplied,
            Err(_) => EffectOutcome::Unknown,
        }
    }
    async fn probe(&self, context: EffectContext) -> ProbeOutcome<String> {
        let fixture = redis_effect::RedisSagaEffectFixture::new(self.pool.clone());
        match fixture.probe(context.idempotency_key()).await {
            Ok(redis_effect::RedisSagaEffectProbeOutcome::Applied) => {
                ProbeOutcome::Applied(self.name.into())
            }
            Ok(redis_effect::RedisSagaEffectProbeOutcome::Missing) => ProbeOutcome::NotApplied,
            Err(_) => ProbeOutcome::Unknown,
        }
    }
    async fn compensate(&self, context: EffectContext, _: String) -> EffectOutcome<()> {
        let fixture = redis_effect::RedisSagaEffectFixture::new(self.pool.clone());
        match fixture.apply(context.idempotency_key(), b"undo").await {
            Ok(
                redis_effect::RedisSagaEffectApplyOutcome::Applied
                | redis_effect::RedisSagaEffectApplyOutcome::ExactDuplicate,
            ) => EffectOutcome::Applied(()),
            Ok(redis_effect::RedisSagaEffectApplyOutcome::Conflict) => EffectOutcome::NotApplied,
            Err(_) => EffectOutcome::Unknown,
        }
    }
    async fn probe_compensation(&self, context: EffectContext, _: String) -> ProbeOutcome<()> {
        let fixture = redis_effect::RedisSagaEffectFixture::new(self.pool.clone());
        match fixture.probe(context.idempotency_key()).await {
            Ok(redis_effect::RedisSagaEffectProbeOutcome::Applied) => ProbeOutcome::Applied(()),
            Ok(redis_effect::RedisSagaEffectProbeOutcome::Missing) => ProbeOutcome::NotApplied,
            Err(_) => ProbeOutcome::Unknown,
        }
    }
}
fn redis_registry(
    d: Definition,
    pool: deadpool_redis::Pool,
    marker: Option<PathBuf>,
    before_effect: bool,
) -> Result<Registry, Error> {
    let builder = DefinitionBuilder::new(d)?
        .step(RedisStep {
            name: "one",
            pool: pool.clone(),
            marker,
            before_effect,
        })?
        .step(RedisStep {
            name: "two",
            pool: pool.clone(),
            marker: None,
            before_effect: false,
        })?
        .step(RedisStep {
            name: "three",
            pool,
            marker: None,
            before_effect: false,
        })?;
    Ok(Registry::builder().register(builder)?.finish())
}
pub(super) async fn crash(
    store: &PgStore,
    owner: &PgPool,
    fixture: &testkit::PgTlsFixture,
    d: &Definition,
    control: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    crash_at(store, owner, fixture, d, control, false).await?;
    crash_at(store, owner, fixture, d, control, true).await
}
async fn crash_at(
    store: &PgStore,
    owner: &PgPool,
    fixture: &testkit::PgTlsFixture,
    d: &Definition,
    control: &Control<'_, Clock>,
    before_effect: bool,
) -> anyhow::Result<()> {
    let redis = testkit::managed_redis().await?;
    let pool = deadpool_redis::Config::from_url(redis.url())
        .create_pool(Some(deadpool_redis::Runtime::Tokio1))?;
    let s = scope(TENANT)?;
    store.register(s, d, control).await?;
    let root = std::env::temp_dir().join(format!("rss-saga-crash-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&root)?;
    let ca = root.join("ca.pem");
    std::fs::write(&ca, fixture.ca_pem())?;
    let marker = root.join("applied");
    let params = fixture.params();
    let mut child = Command::new(std::env::current_exe()?)
        .args([
            "--exact",
            "process::saga_worker_child",
            "--ignored",
            "--nocapture",
        ])
        .env("SAGA_TEST_HOST", &params.host)
        .env("SAGA_TEST_PORT", params.port.to_string())
        .env("SAGA_TEST_DB", &params.database)
        .env("SAGA_TEST_CA", &ca)
        .env("SAGA_TEST_MARKER", &marker)
        .env("SAGA_TEST_ID", s.id().to_string())
        .env("SAGA_TEST_REDIS", redis.url())
        .env(
            "SAGA_TEST_PHASE",
            if before_effect { "intent" } else { "effect" },
        )
        .kill_on_drop(true)
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()?;
    kill_at_marker(&mut child, &marker).await?;
    recover_after_crash(store, owner, &pool, d, s, control, before_effect).await?;
    pool.close();
    std::fs::remove_dir_all(root)?;
    drop(redis);
    Ok(())
}
#[tokio::test]
#[ignore = "spawned and killed after durable external effect by saga_postgres_suite"]
async fn saga_worker_child() -> anyhow::Result<()> {
    let ca = std::fs::read(std::env::var("SAGA_TEST_CA")?)?;
    let options = PgConnectOptions::new()
        .host(&std::env::var("SAGA_TEST_HOST")?)
        .port(std::env::var("SAGA_TEST_PORT")?.parse()?)
        .database(&std::env::var("SAGA_TEST_DB")?)
        .username("saga_runtime")
        .password("fixture-only")
        .ssl_mode(PgSslMode::VerifyFull)
        .ssl_root_cert_from_pem(ca);
    let clock = Clock::new();
    let cancel = CancellationToken::new();
    let control = Control::new(&clock, Duration::from_secs(60), &cancel);
    let store = PgStore::new(
        PgPoolOptions::new()
            .max_connections(2)
            .connect_with(options)
            .await?,
        &control,
    )
    .await?;
    let pool = deadpool_redis::Config::from_url(std::env::var("SAGA_TEST_REDIS")?)
        .create_pool(Some(deadpool_redis::Runtime::Tokio1))?;
    let d = definition(&["one", "two", "three"])?;
    let e = Executor::new(
        store,
        protection()?,
        redis_registry(
            d,
            pool,
            Some(std::env::var("SAGA_TEST_MARKER")?.into()),
            std::env::var("SAGA_TEST_PHASE")? == "intent",
        )?,
    );
    let e = e.with_lease_policy(LeasePolicy::new(Duration::from_millis(300))?);
    let s = Scope::new(
        TenantId::parse(TENANT)?,
        std::env::var("SAGA_TEST_ID")?.parse()?,
    );
    let _ = e.run(s, 30, &control).await?;
    Ok(())
}

async fn kill_at_marker(
    child: &mut tokio::process::Child,
    marker: &std::path::Path,
) -> anyhow::Result<()> {
    let ready = tokio::time::timeout(Duration::from_secs(20), async {
        while !marker.exists() {
            if child.try_wait()?.is_some() {
                return Err(anyhow::anyhow!("worker exited before effect"));
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        Ok::<(), anyhow::Error>(())
    })
    .await;
    child.kill().await?;
    child.wait().await?;
    ready??;
    Ok(())
}

async fn recover_after_crash(
    store: &PgStore,
    owner: &PgPool,
    pool: &deadpool_redis::Pool,
    d: &Definition,
    s: Scope,
    control: &Control<'_, Clock>,
    before_effect: bool,
) -> anyhow::Result<()> {
    let rows:(i64,i64)=sqlx::query_as("SELECT (SELECT count(*) FROM rss_saga.journal WHERE saga_id=$1),(SELECT count(*) FROM rss_saga.step_receipts WHERE saga_id=$1)").bind(s.id()).fetch_one(owner).await?;
    assert_eq!(rows, (1, 0));
    let remote_before = redis_effect::RedisSagaEffectFixture::new(pool.clone());
    let observed = remote_before
        .probe(&d.effect_key(s, 0, Phase::Forward)?)
        .await?;
    assert_eq!(
        observed,
        if before_effect {
            redis_effect::RedisSagaEffectProbeOutcome::Missing
        } else {
            redis_effect::RedisSagaEffectProbeOutcome::Applied
        }
    );
    tokio::time::sleep(Duration::from_millis(350)).await;
    let e = Executor::new(
        store.clone(),
        protection()?,
        redis_registry(d.clone(), pool.clone(), None, false)?,
    );
    assert_eq!(e.run(s, 30, control).await?.status, Status::Succeeded);
    let first_key = d.effect_key(s, 0, Phase::Forward)?;
    let remote = redis_effect::RedisSagaEffectFixture::new(pool.clone());
    assert_eq!(
        remote.apply(&first_key, b"one").await?,
        redis_effect::RedisSagaEffectApplyOutcome::ExactDuplicate
    );
    assert_restart_receipts(owner, s, before_effect).await?;
    Ok(())
}

async fn assert_restart_receipts(
    owner: &PgPool,
    s: Scope,
    before_effect: bool,
) -> anyhow::Result<()> {
    let receipts: i64 =
        sqlx::query_scalar("SELECT count(*) FROM rss_saga.step_receipts WHERE saga_id=$1")
            .bind(s.id())
            .fetch_one(owner)
            .await?;
    assert_eq!(receipts, 3);
    let attempts:Vec<i64>=sqlx::query_scalar("SELECT attempt FROM rss_saga.journal WHERE saga_id=$1 AND step=0 AND kind='ForwardIntent' ORDER BY seq").bind(s.id()).fetch_all(owner).await?;
    assert_eq!(attempts, if before_effect { vec![1, 2] } else { vec![1] });
    Ok(())
}
