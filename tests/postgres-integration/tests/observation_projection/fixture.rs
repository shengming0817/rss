#[path = "../../../../crates/observation-postgres/examples/handoff/install.rs"]
mod installer;
use rss_observation::*;
use rss_observation_postgres::{PgSource, PgStore};
use rss_request_context::{Deadline, TenantId};
use sqlx::{
    PgPool,
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
    pub async fn new(v1: bool) -> anyhow::Result<Self> {
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
        if v1 {
            let sql = {
                include_str!(
                    "../../../../crates/observation-postgres/migrations/0001_create_observation.sql"
                )
            };
            sqlx::raw_sql(sql).execute(&owner).await?;
            sqlx::raw_sql(rss_projection_postgres::MIGRATION_SQL)
                .execute(&owner)
                .await?;
            sqlx::raw_sql("GRANT USAGE ON SCHEMA rss_observation,rss_projection TO handoff_runtime; GRANT SELECT ON ALL TABLES IN SCHEMA rss_observation,rss_projection TO handoff_runtime; GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA rss_observation,rss_projection TO handoff_runtime;").execute(&owner).await?;
            sqlx::raw_sql(include_str!(
                "../../../../crates/observation-postgres/examples/handoff/facts.sql"
            ))
            .execute(&owner)
            .await?;
            sqlx::raw_sql(
                "GRANT SELECT,INSERT,UPDATE,DELETE ON public.observation_facts TO handoff_runtime;",
            )
            .execute(&owner)
            .await?;
        } else {
            installer::install(&mut *owner.acquire().await?).await?;
        }
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
    pub async fn store(&self) -> anyhow::Result<Arc<PgStore<Clock>>> {
        Ok(Arc::new(
            PgStore::new(self.pool.clone(), Clock, deadline()).await?,
        ))
    }
    pub fn source(
        &self,
        store: Arc<PgStore<Clock>>,
        tenant: &str,
    ) -> anyhow::Result<Arc<PgSource<Clock>>> {
        Ok(Arc::new(PgSource::new(
            store,
            JournalReadGrant::verify(&Trusted, TenantId::parse(tenant)?)?,
        )?))
    }
    pub async fn projection(&self) -> anyhow::Result<rss_projection_postgres::PgStore> {
        Ok(rss_projection_postgres::PgStore::new(
            PgPoolOptions::new()
                .max_connections(5)
                .connect_with(self.options.clone())
                .await?,
        )
        .await?)
    }
}
