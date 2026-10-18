use rss_request_context::{Clock, Deadline, TenantId};
use rss_timeseries::*;
use rss_timeseries_postgres::{CursorKey, Fault, Limits, MIGRATION_SQL, PgStore};
use sqlx::{
    PgPool,
    postgres::{PgConnectOptions, PgPoolOptions, PgSslMode},
};
use std::{
    num::{NonZeroU32, NonZeroU64},
    time::{Duration, Instant},
};
mod aggregation;
mod crash;
mod examples;
mod lifecycle;
mod queries;
mod security;
mod writing;
const TENANT: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";
const OTHER: &str = "11111111-1111-4111-8111-111111111111";
struct Timer;
impl Clock for Timer {
    #[allow(clippy::disallowed_methods)] // reason: injected real fixture monotonic clock.
    fn now(&self) -> Instant {
        Instant::now()
    }
}
fn deadline() -> anyhow::Result<Deadline> {
    Ok(Deadline::from_timeout(&Timer, Duration::from_secs(15))?)
}
fn id(s: &str) -> anyhow::Result<Id> {
    Ok(Id::new(s)?)
}
fn limits() -> anyhow::Result<Limits> {
    Ok(Limits {
        max_points: NonZeroU32::new(100).ok_or_else(|| anyhow::anyhow!("positive"))?,
        max_series: NonZeroU32::new(20).ok_or_else(|| anyhow::anyhow!("positive"))?,
        max_bytes: NonZeroU32::new(1024 * 1024).ok_or_else(|| anyhow::anyhow!("positive"))?,
        replay_micros: NonZeroU64::new(60_000_000).ok_or_else(|| anyhow::anyhow!("positive"))?,
        cursor_micros: NonZeroU64::new(60_000_000).ok_or_else(|| anyhow::anyhow!("positive"))?,
    })
}
struct Product(TenantId);
impl Authority for Product {
    fn authorize(&self, a: Access<'_>) -> Result<(), Error> {
        let tenant = match a {
            Access::Write(v) => v.stream().scope().tenant(),
            Access::Receipt(v) => v.stream.scope().tenant(),
            Access::Query(v) => v.selection().scope().tenant(),
            Access::Aggregate(v) => v.spec().stream().scope().tenant(),
            Access::Maintain(v) => v.scope().tenant(),
            Access::DefinitionRead(v) => v.scope.tenant(),
            Access::Definition(DefinitionMutation::Register { definition, .. }) => {
                definition.spec().scope.tenant()
            }
            Access::Definition(DefinitionMutation::Retire { id, .. }) => id.scope.tenant(),
        };
        if tenant == self.0 {
            Ok(())
        } else {
            Err(Error::Unauthorized)
        }
    }
}
fn authority(tenant: &str) -> anyhow::Result<Product> {
    Ok(Product(TenantId::parse(tenant)?))
}
fn definition(tenant: &str) -> anyhow::Result<Definition> {
    Ok(Definition::new(DefinitionSpec {
        scope: Scope::new(TenantId::parse(tenant)?, id("metrics")?),
        key: id("temperature")?,
        version: 1,
        unit: id("units")?,
        metric: Metric::Gauge {
            number: NumberKind::U64,
        },
        dimensions: DimensionRules {
            allowed: Default::default(),
            required: Default::default(),
            max_count: 0,
            max_value_bytes: 256,
            max_total_bytes: 32768,
        },
    })?)
}
fn sample(d: &Definition, name: &str, time: i64, value: u64) -> anyhow::Result<Sample> {
    Ok(Sample::new(SampleInput {
        stream: Stream::new(d.spec().scope.clone(), id("sensor")?, id("generation")?),
        series: Series::new(
            d.clone(),
            id("device")?,
            id("resource")?,
            Default::default(),
        )?,
        id: id(name)?,
        sequence: value,
        observed_at: Timestamp::new(time)?,
        interval: None,
        reading: Reading::Valid(Value::Number(Number::U64(value))),
    })?)
}
fn batch(name: &str, samples: Vec<Sample>) -> anyhow::Result<Batch> {
    let stream = samples
        .first()
        .ok_or_else(|| anyhow::anyhow!("empty"))?
        .input()
        .stream
        .clone();
    Ok(Batch::new(stream, id(name)?, samples)?)
}
fn query(d: &Definition, mode: QueryMode, points: u32) -> anyhow::Result<Query> {
    Ok(Query::new(
        Selection::Resource {
            scope: d.spec().scope.clone(),
            subject: id("device")?,
            resource: id("resource")?,
            keys: Default::default(),
        },
        Interval::new(Timestamp::new(0)?, Timestamp::new(i64::MAX)?)?,
        QueryBudget {
            max_points: NonZeroU32::new(points).ok_or_else(|| anyhow::anyhow!("positive"))?,
            max_series: NonZeroU32::new(10).ok_or_else(|| anyhow::anyhow!("positive"))?,
        },
        mode,
    )?)
}
fn receipt_query(b: &Batch) -> anyhow::Result<ReceiptQuery> {
    Ok(ReceiptQuery {
        stream: b.stream().clone(),
        batch_id: b.id().clone(),
        digest: b.digest()?,
    })
}
fn confirmed<T>(v: Outcome<T>) -> anyhow::Result<T> {
    match v {
        Outcome::Accepted(v) | Outcome::Replay(v) => Ok(v),
        Outcome::Unknown => anyhow::bail!("unexpected unknown"),
    }
}
const ROLES: &str = "CREATE ROLE ts_owner NOLOGIN NOSUPERUSER NOBYPASSRLS; CREATE ROLE ts_runtime LOGIN PASSWORD 'fixture-only' NOSUPERUSER NOBYPASSRLS; CREATE ROLE ts_migrator LOGIN PASSWORD 'fixture-only' NOSUPERUSER NOBYPASSRLS; GRANT ts_owner TO ts_migrator; GRANT CREATE ON DATABASE rss_test TO ts_owner;";
const GRANTS: &str = "GRANT USAGE ON SCHEMA rss_timeseries TO ts_runtime; GRANT SELECT ON ALL TABLES IN SCHEMA rss_timeseries TO ts_runtime; GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA rss_timeseries TO ts_runtime; REVOKE EXECUTE ON FUNCTION rss_timeseries.create_partition(bigint,bigint) FROM ts_runtime;";
struct Fixture {
    admin: PgPool,
    pool: PgPool,
    store: PgStore<Timer>,
    pg: testkit::PgTlsFixture,
    _network: testkit::BridgeNetwork,
}
impl Fixture {
    async fn new(name: &str) -> anyhow::Result<Self> {
        Self::new_inner(name, false).await
    }
    async fn new_inner(name: &str, upgrade: bool) -> anyhow::Result<Self> {
        let network = testkit::bridge_network(name).await?;
        let pg = testkit::postgres_tls(
            testkit::NetworkAttachment {
                network: network.name(),
                dns_name: name,
            },
            testkit::PgTlsServerIdentity::MatchingHost,
        )
        .await?;
        let p = pg.params();
        let base = PgConnectOptions::new()
            .host(&p.host)
            .port(p.port)
            .database(&p.database)
            .ssl_mode(PgSslMode::VerifyFull)
            .ssl_root_cert_from_pem(pg.ca_pem().as_bytes().to_vec());
        let admin = PgPoolOptions::new()
            .max_connections(4)
            .connect_with(base.clone().username(&p.username).password(&p.password))
            .await?;
        install_schema(&admin, upgrade).await?;
        let pool = PgPoolOptions::new()
            .max_connections(6)
            .connect_with(base.username("ts_runtime").password("fixture-only"))
            .await?;
        if upgrade {
            upgrade_schema(&admin, &pool).await?;
        }
        let catalog: String = sqlx::query_scalar(include_str!(
            "../../../crates/timeseries-postgres/src/catalog.sql"
        ))
        .fetch_one(&pool)
        .await?;
        let store = PgStore::new(
            pool.clone(),
            Timer,
            limits()?,
            CursorKey::new([17; 32]),
            deadline()?,
        )
        .await
        .map_err(|e| anyhow::anyhow!("store admission: {e:?}; catalog={catalog}"))?;
        Ok(Self {
            admin,
            pool,
            store,
            pg,
            _network: network,
        })
    }
    async fn register(&self, d: &Definition) -> anyhow::Result<()> {
        confirmed(
            self.store
                .change(
                    &Authorized::<DefinitionMutation>::verify(
                        &authority(&d.spec().scope.tenant().to_string())?,
                        DefinitionMutation::Register {
                            definition: d.clone(),
                            expected_latest: None,
                        },
                    )?,
                    deadline()?,
                )
                .await?,
        )?;
        Ok(())
    }
    async fn write(&self, b: &Batch) -> Result<Outcome<Receipt>, Error> {
        let auth = Product(b.stream().scope().tenant());
        self.store
            .write(
                &Authorized::<Batch>::verify(&auth, b.clone())?,
                Deadline::from_timeout(&Timer, Duration::from_secs(15))
                    .map_err(|_| Error::InvalidInput)?,
            )
            .await
    }
    async fn count(&self) -> anyhow::Result<i64> {
        Ok(
            sqlx::query_scalar("SELECT count(*) FROM rss_timeseries.samples")
                .fetch_one(&self.admin)
                .await?,
        )
    }
}

async fn seed_v1(c: &mut sqlx::PgConnection) -> anyhow::Result<()> {
    let d = definition(TENANT)?;
    let s = sample(&d, "v1", 50, 7)?;
    let b = batch("v1", vec![s.clone()])?;
    sqlx::raw_sql("SET ROLE ts_owner").execute(&mut *c).await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,false)")
        .bind(TENANT)
        .execute(&mut *c)
        .await?;
    sqlx::query("SELECT rss_timeseries.put_definition($1::text::uuid,'metrics','temperature',1,$2,$3,false)").bind(TENANT).bind(serde_json::to_vec(&d)?).bind(d.digest()?.as_bytes().as_slice()).execute(&mut *c).await?;
    sqlx::query("SELECT rss_timeseries.put_sample($1,$2,$3,10)")
        .bind(serde_json::to_vec(&s)?)
        .bind(s.digest()?.as_bytes().as_slice())
        .bind(s.input().series.digest()?.as_bytes().as_slice())
        .execute(&mut *c)
        .await?;
    sqlx::query("SELECT rss_timeseries.put_batch($1::text::uuid,'metrics','sensor','generation','v1',$2,10,1,0,20)").bind(TENANT).bind(b.digest()?.as_bytes().as_slice()).execute(&mut *c).await?;
    sqlx::raw_sql("RESET ROLE; RESET rss.tenant_id")
        .execute(&mut *c)
        .await?;
    Ok(())
}

async fn install_schema(admin: &PgPool, upgrade: bool) -> anyhow::Result<()> {
    sqlx::raw_sql(ROLES).execute(admin).await?;
    let mut c = admin.acquire().await?;
    sqlx::raw_sql("SET ROLE ts_owner").execute(&mut *c).await?;
    let migration = if upgrade {
        include_str!("../../../crates/timeseries-postgres/migrations/0001_create_timeseries.sql")
    } else {
        MIGRATION_SQL
    };
    sqlx::raw_sql(migration).execute(&mut *c).await?;
    sqlx::raw_sql("SELECT rss_timeseries.create_partition(0,100); SELECT rss_timeseries.create_partition(100,9223372036854775807); RESET ROLE;").execute(&mut *c).await?;
    sqlx::raw_sql(GRANTS).execute(&mut *c).await?;
    if upgrade {
        seed_v1(&mut c).await?;
    }
    drop(c);
    Ok(())
}

async fn upgrade_schema(admin: &PgPool, pool: &PgPool) -> anyhow::Result<()> {
    assert!(
        PgStore::new(
            pool.clone(),
            Timer,
            limits()?,
            CursorKey::new([17; 32]),
            deadline()?
        )
        .await
        .is_err()
    );
    let mut owner = admin.acquire().await?;
    sqlx::raw_sql("SET ROLE ts_owner")
        .execute(&mut *owner)
        .await?;
    sqlx::raw_sql(rss_timeseries_postgres::UPGRADE_V2_SQL)
        .execute(&mut *owner)
        .await?;
    sqlx::raw_sql("RESET ROLE").execute(&mut *owner).await?;
    sqlx::raw_sql(GRANTS).execute(&mut *owner).await?;
    Ok(())
}
