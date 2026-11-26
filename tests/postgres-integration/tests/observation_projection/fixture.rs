use super::installer;
use rss_observation::*;
use rss_observation_postgres::{PgSource, PgStore};
use rss_request_context::{Deadline, TenantId};
use sqlx::{
    PgPool, Row,
    postgres::{PgConnectOptions, PgPoolOptions, PgSslMode},
};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
pub const TENANT: &str = "00000000-0000-0000-0000-000000000071";
pub const OTHER: &str = "00000000-0000-0000-0000-000000000072";
#[derive(Clone, Copy)]
pub struct Clock;
impl rss_observation::Clock for Clock {
    #[allow(clippy::disallowed_methods)] // reason: test host supplies the actual monotonic clock.
    fn now(&self) -> Instant {
        Instant::now()
    }
}
pub struct ProjectionClock(pub Instant);
impl rss_projection::Timer for ProjectionClock {
    #[allow(clippy::disallowed_methods)] // reason: injected host Timer owns its monotonic origin and elapsed-time calculation.
    fn now(&self) -> Duration {
        rss_observation::Clock::now(&Clock).duration_since(self.0)
    }
    async fn sleep_until(&self, end: Duration) {
        tokio::time::sleep(end.saturating_sub(rss_projection::Timer::now(self))).await;
    }
}
pub fn deadline() -> Deadline {
    Deadline::at(rss_observation::Clock::now(&Clock) + Duration::from_secs(20))
}
pub struct Trusted;
impl Authority for Trusted {
    fn authorize(&self, _: Access<'_>) -> Result<(), Error> {
        Ok(())
    } // reason: fixture-only authenticated host.
}
pub fn scope(
    tenant: &str,
    object: &str,
    registration: &str,
    source: &str,
    epoch: &str,
) -> anyhow::Result<Scope> {
    Ok(Scope::new(
        TenantId::parse(tenant)?,
        Id::new(object)?,
        Registration::new(registration)?,
        Id::new(source)?,
        Id::new("facts")?,
        Epoch::new(epoch)?,
    ))
}
pub fn batch(
    scope: &Scope,
    id: &str,
    sequence: u64,
    coverage: &str,
    body: Body,
) -> anyhow::Result<VerifiedBatch> {
    Ok(VerifiedBatch::verify(
        &Trusted,
        scope.clone(),
        Batch::new(
            Id::new(id)?,
            sequence,
            rss_contract::Timepoint::try_from(100)?,
            Coverage::new(
                Id::new(coverage)?,
                Id::new("v1")?,
                Id::new("catalog")?,
                Id::new("bytes")?,
            ),
            body,
        )?,
    )?)
}
pub async fn activate(
    store: &PgStore<Clock>,
    scope: &Scope,
    previous: Option<u64>,
) -> anyhow::Result<()> {
    store
        .activate(
            &LifecycleGrant::verify(&Trusted, scope.clone())?,
            previous,
            &Policy::new(86400, 3600, 3600)?,
            deadline(),
        )
        .await?;
    Ok(())
}
pub struct Fixture {
    pub admin: PgPool,
    pub owner: PgPool,
    pub pool: PgPool,
    pub options: PgConnectOptions,
    pub server: testkit::PgTlsFixture,
    _network: testkit::BridgeNetwork,
}
impl Fixture {
    pub async fn new() -> anyhow::Result<Self> {
        let network = testkit::bridge_network("obs-projection").await?;
        let server = testkit::postgres_tls(
            testkit::NetworkAttachment {
                network: network.name(),
                dns_name: network.name(),
            },
            testkit::PgTlsServerIdentity::MatchingHost,
        )
        .await?;
        let p = server.params();
        let options = PgConnectOptions::new()
            .host(&p.host)
            .port(p.port)
            .database(&p.database)
            .ssl_mode(PgSslMode::VerifyFull)
            .ssl_root_cert_from_pem(server.ca_pem().as_bytes().to_vec());
        let admin = PgPoolOptions::new()
            .max_connections(6)
            .connect_with(options.clone().username(&p.username).password(&p.password))
            .await?;
        sqlx::raw_sql("CREATE ROLE handoff_owner LOGIN PASSWORD 'owner-fixture' NOSUPERUSER NOBYPASSRLS; CREATE ROLE handoff_runtime LOGIN PASSWORD 'fixture-only' NOSUPERUSER NOBYPASSRLS; GRANT CREATE ON DATABASE rss_test TO handoff_owner; GRANT CREATE ON SCHEMA public TO handoff_owner;").execute(&admin).await?;
        let owner = PgPoolOptions::new()
            .max_connections(3)
            .connect_with(
                options
                    .clone()
                    .username("handoff_owner")
                    .password("owner-fixture"),
            )
            .await?;
        installer::install(&mut *owner.acquire().await?).await?;
        let options = options.username("handoff_runtime").password("fixture-only");
        let pool = PgPoolOptions::new()
            .max_connections(8)
            .connect_with(options.clone())
            .await?;
        Ok(Self {
            admin,
            owner,
            pool,
            options,
            server,
            _network: network,
        })
    }
    // Stage the actual receive write funnel and keep settlement under the test's control.
    pub async fn stage(
        &self,
        input: &VerifiedBatch,
    ) -> anyhow::Result<(sqlx::Transaction<'static, sqlx::Postgres>, i32)> {
        let mut tx = self.pool.begin().await?;
        let (pid, _): (i32, String) =
            sqlx::query_as("SELECT pg_backend_pid(), set_config('rss.tenant_id',$1,true)")
                .bind(input.scope().tenant().to_string())
                .fetch_one(&mut *tx)
                .await?;
        let row = sqlx::query("SELECT state,policy FROM rss_observation.lock_stream($1)")
            .bind(input.scope().encode()?)
            .fetch_one(&mut *tx)
            .await?;
        let state = rss_observation::State::decode(row.try_get("state")?)?;
        let policy = rss_observation::Policy::decode(row.try_get("policy")?)?;
        let decision = state.advance(input.batch(), 100, &policy)?;
        sqlx::query(
            "SELECT rss_observation.commit_batch($1,$2,$3::numeric,$4,$5,$6,$7,$8,$9::numeric,$10)",
        )
        .bind(input.scope().encode()?)
        .bind(input.batch().id().as_str())
        .bind(input.batch().sequence().to_string())
        .bind(input.batch().encode())
        .bind(input.fingerprint().as_slice())
        .bind(100_i64)
        .bind(policy.encode()?)
        .bind(decision.encode()?)
        .bind(state.revision().to_string())
        .bind(decision.outcome().is_applicable())
        .execute(&mut *tx)
        .await?;
        Ok((tx, pid))
    }
    pub async fn wait_for_blocked(&self, blocker: i32, count: i64) -> anyhow::Result<()> {
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let waiting: i64 = sqlx::query_scalar("SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND usename='handoff_runtime' AND $1=ANY(pg_blocking_pids(pid))")
                    .bind(blocker).fetch_one(&self.admin).await?;
                if waiting == count { return Ok::<_, sqlx::Error>(()); }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }).await.map_err(|_| anyhow::anyhow!("expected {count} receivers blocked by backend {blocker}"))??;
        Ok(())
    }
    pub async fn store(&self) -> anyhow::Result<Arc<PgStore<Clock>>> {
        Ok(Arc::new(
            PgStore::new(self.pool.clone(), Clock, deadline()).await?,
        ))
    }
    pub fn source(
        &self,
        store: Arc<PgStore<Clock>>,
        tenant: &str,
    ) -> anyhow::Result<Arc<PgSource<Clock, rss_observation_postgres::LocalPages>>> {
        Ok(Arc::new(
            PgSource::new(
                store,
                JournalReadGrant::verify(&Trusted, TenantId::parse(tenant)?)?,
                rss_projection::SourceScope::new(TenantId::parse(tenant)?, "rss.observation.v1")?,
                32 * 1024 * 1024,
            )?
            .into_local(),
        ))
    }
    pub async fn projection(
        &self,
        control: &rss_projection::Control<'_, ProjectionClock>,
    ) -> anyhow::Result<rss_projection_postgres::PgStore> {
        Ok(rss_projection_postgres::PgStore::new(
            PgPoolOptions::new()
                .max_connections(5)
                .connect_with(self.options.clone())
                .await?,
            control,
        )
        .await?)
    }
}

pub fn assert_same_record(actual: &Record, expected: &Record) {
    assert_eq!(actual.scope(), expected.scope());
    assert_eq!(actual.batch(), expected.batch());
    assert_eq!(actual.received_at(), expected.received_at());
    assert_eq!(actual.policy(), expected.policy());
    assert_eq!(actual.decision(), expected.decision());
}
