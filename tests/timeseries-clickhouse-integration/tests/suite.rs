mod regressions;
mod transport;
use rss_request_context::{Clock, Deadline, TenantId};
use rss_timeseries::*;
use rss_timeseries_clickhouse::{ChStore, Connections, Credentials, CursorKey, Fault, Limits};
use sqlx::{
    PgPool,
    postgres::{PgConnectOptions, PgPoolOptions, PgSslMode},
};
use std::{
    num::{NonZeroU32, NonZeroU64},
    time::{Duration, Instant},
};
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
        max_scan_rows: NonZeroU64::new(100000).ok_or_else(|| anyhow::anyhow!("positive"))?,
        max_scan_bytes: NonZeroU64::new(16777216).ok_or_else(|| anyhow::anyhow!("positive"))?,
        max_memory_bytes: NonZeroU64::new(67108864).ok_or_else(|| anyhow::anyhow!("positive"))?,
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

const ROLES: &str = "CREATE ROLE ch_owner NOLOGIN NOSUPERUSER NOBYPASSRLS; CREATE ROLE ch_runtime LOGIN PASSWORD 'fixture-only' NOSUPERUSER NOBYPASSRLS; CREATE ROLE ch_guard LOGIN PASSWORD 'fixture-only' NOSUPERUSER NOBYPASSRLS; GRANT CREATE ON DATABASE rss_test TO ch_owner;";
const GRANTS: &str = "GRANT USAGE ON SCHEMA rss_ts_ch TO ch_runtime,ch_guard; GRANT SELECT ON rss_ts_ch.installation TO ch_runtime; GRANT SELECT,INSERT,UPDATE,DELETE ON rss_ts_ch.namespaces,rss_ts_ch.definitions,rss_ts_ch.streams,rss_ts_ch.batches,rss_ts_ch.identities,rss_ts_ch.attempts,rss_ts_ch.fences,rss_ts_ch.plans,rss_ts_ch.summaries,rss_ts_ch.ranges TO ch_runtime; GRANT SELECT ON rss_ts_ch.active_attempts,rss_ts_ch.guard_identity TO ch_guard;";
struct Fixture {
    admin: PgPool,
    pool: PgPool,
    store: ChStore<Timer>,
    ch: testkit::ClickHouseFixture,
    pg: testkit::PgTlsFixture,
    _network: testkit::BridgeNetwork,
}
impl Fixture {
    async fn new(name: &str) -> anyhow::Result<Self> {
        let network = testkit::bridge_network(name).await?;
        let pg_name = format!("{name}-pg");
        let pg = testkit::postgres_tls(
            testkit::NetworkAttachment {
                network: network.name(),
                dns_name: &pg_name,
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
        let instance: String = sqlx::query_scalar("SELECT gen_random_uuid()::text")
            .fetch_one(&admin)
            .await?;
        let installation = schema(&instance).await?;
        Self::install_control(&admin, &installation.control, &instance).await?;
        let ch = testkit::clickhouse_tls(
            testkit::NetworkAttachment {
                network: network.name(),
                dns_name: name,
            },
            &pg_name,
            pg.ca_pem(),
        )
        .await?;
        Self::install_data(&ch, &installation.clickhouse).await?;
        let pool = PgPoolOptions::new()
            .max_connections(6)
            .connect_with(base.username("ch_runtime").password("fixture-only"))
            .await?;
        let store = Self::connect(&ch, pool.clone(), TENANT, "ch_reader")
            .await
            .map_err(|e| e.context("fixture constructor"))?;
        Ok(Self {
            admin,
            pool,
            store,
            ch,
            pg,
            _network: network,
        })
    }
    async fn install_control(admin: &PgPool, control: &str, instance: &str) -> anyhow::Result<()> {
        sqlx::raw_sql(ROLES).execute(admin).await?;
        let mut owner = admin.acquire().await?;
        sqlx::query("SET ROLE ch_owner")
            .execute(&mut *owner)
            .await?;
        sqlx::raw_sql(sqlx::AssertSqlSafe(control))
            .execute(&mut *owner)
            .await?;
        // External fresh-install owner binds both stores before granting runtime access.
        sqlx::query("UPDATE rss_ts_ch.installation SET id=$1::text::uuid")
            .bind(instance)
            .execute(&mut *owner)
            .await?;
        sqlx::raw_sql(GRANTS).execute(&mut *owner).await?;
        sqlx::query("RESET ROLE").execute(&mut *owner).await?;
        drop(owner);
        Ok(())
    }
    async fn install_data(
        ch: &testkit::ClickHouseFixture,
        statements: &[String],
    ) -> anyhow::Result<()> {
        for sql in statements {
            ch.sql(sql).await?;
        }
        ch.sql("CREATE USER ch_reader IDENTIFIED WITH sha256_password BY 'fixture-only'; CREATE USER ch_other IDENTIFIED WITH sha256_password BY 'fixture-only'; CREATE USER ch_writer IDENTIFIED WITH sha256_password BY 'fixture-only'; CREATE USER ch_maint IDENTIFIED WITH sha256_password BY 'fixture-only'; GRANT SELECT ON rss_ts_ch.installation TO ch_reader,ch_other,ch_writer,ch_maint; GRANT SELECT ON rss_ts_ch.raw TO ch_reader,ch_other,ch_maint; GRANT SELECT ON rss_ts_ch.summaries TO ch_reader,ch_other,ch_maint; GRANT SELECT ON rss_ts_ch.active_attempts TO ch_writer; GRANT SELECT ON rss_ts_ch.guard_identity TO ch_writer; GRANT INSERT ON rss_ts_ch.raw TO ch_writer; GRANT INSERT ON rss_ts_ch.summaries TO ch_writer; GRANT CREATE TEMPORARY TABLE ON *.* TO ch_writer; GRANT ALTER DELETE ON rss_ts_ch.raw TO ch_maint; GRANT ALTER DELETE ON rss_ts_ch.summaries TO ch_maint; GRANT SELECT ON system.* TO ch_maint; GRANT SHOW ACCESS ON *.* TO ch_maint; GRANT SHOW COLUMNS ON rss_ts_ch.* TO ch_maint; GRANT KILL QUERY ON *.* TO ch_maint;").await?;
        for table in ["raw", "summaries"] {
            ch.sql(&format!("CREATE ROW POLICY tenant_{table} ON rss_ts_ch.{table} USING tenant='{TENANT}' TO ch_reader; CREATE ROW POLICY other_{table} ON rss_ts_ch.{table} USING tenant='{OTHER}' TO ch_other; CREATE ROW POLICY maintain_{table} ON rss_ts_ch.{table} USING 1 TO ch_maint,default;")).await?;
        }
        Ok(())
    }
    async fn connect(
        ch: &testkit::ClickHouseFixture,
        pool: PgPool,
        tenant: &str,
        reader: &str,
    ) -> anyhow::Result<ChStore<Timer>> {
        Self::connect_options(ch, pool, tenant, reader, "ch_writer", limits()?).await
    }
    async fn connect_options(
        ch: &testkit::ClickHouseFixture,
        pool: PgPool,
        tenant: &str,
        reader: &str,
        writer: &str,
        limits: Limits,
    ) -> anyhow::Result<ChStore<Timer>> {
        let c = |name: &str| Credentials::new(name.into(), "fixture-only".into());
        let connections = Connections::new(
            ch.endpoint(),
            ch.ca_pem().as_bytes(),
            c(reader)?,
            c(writer)?,
            c("ch_maint")?,
        )?;
        Ok(ChStore::new(
            TenantId::parse(tenant)?,
            pool,
            connections,
            Timer,
            limits,
            CursorKey::new([42; 32]),
            deadline()?,
        )
        .await?)
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
    async fn write(&self, b: &Batch) -> anyhow::Result<Outcome<Receipt>> {
        Ok(self
            .store
            .write(
                &Authorized::<Batch>::verify(&authority(TENANT)?, b.clone())?,
                deadline()?,
            )
            .await?)
    }
    async fn read(&self, d: &Definition) -> anyhow::Result<Page> {
        Ok(self
            .store
            .query(
                &Authorized::<Query>::verify(
                    &authority(TENANT)?,
                    query(d, QueryMode::History, 100)?,
                )?,
                None,
                deadline()?,
            )
            .await?)
    }
    async fn maintain(
        &self,
        name: &str,
        action: MaintenanceAction,
    ) -> anyhow::Result<MaintenanceProgress> {
        let r = Authorized::<MaintenanceRequest>::verify(
            &authority(TENANT)?,
            MaintenanceRequest::new(
                id(name)?,
                action,
                MaintenanceBudget {
                    rows: NonZeroU32::new(2).ok_or(Error::InvalidInput)?,
                    buckets: NonZeroU32::new(1).ok_or(Error::InvalidInput)?,
                },
            )?,
        )?;
        let mut next = None;
        for _ in 0..60 {
            match confirmed(self.store.step(&r, next.as_ref(), deadline()?).await?)? {
                MaintenanceProgress::More { next: n, .. } => next = Some(n),
                v => return Ok(v),
            }
        }
        anyhow::bail!("bounded maintenance did not finish")
    }
}

#[tokio::test]
async fn identity_conflict_visibility_and_restart_recovery() -> anyhow::Result<()> {
    let f = Fixture::new("ch-write").await?;
    let d = definition(TENANT)?;
    f.register(&d).await?;
    let b = batch(
        "batch",
        vec![
            sample(&d, "one", 10, u64::MAX)?,
            sample(&d, "two", 2592000000010, 7)?,
        ],
    )?;
    f.store.inject_next_fault(Fault::AfterPrepare);
    assert!(matches!(f.write(&b).await?, Outcome::Unknown));
    assert!(f.read(&d).await?.rows.is_empty());
    let q = Authorized::<ReceiptQuery>::verify(&authority(TENANT)?, receipt_query(&b)?)?;
    assert!(matches!(
        f.store.receipt(&q, deadline()?).await?,
        Lookup::NotVisible
    ));
    assert_eq!(
        f.store.progress(&q, deadline()?).await?,
        rss_timeseries_clickhouse::ProjectionProgress::Prepared
    );
    let r = confirmed(
        f.store
            .recover(b.stream().scope(), &authority(TENANT)?, deadline()?)
            .await?,
    )?
    .ok_or_else(|| anyhow::anyhow!("pending batch"))?;
    assert_eq!(r.new_samples(), 2);
    assert_eq!(f.read(&d).await?.rows.len(), 2);
    let replay = confirmed(f.write(&b).await?)?;
    assert_eq!(r.received_at(), replay.received_at());
    let conflict = batch("batch", vec![sample(&d, "one", 10, 99)?])?;
    assert!(
        matches!(f.write(&conflict).await,Err(e) if e.downcast_ref::<Error>()==Some(&Error::Conflict))
    );
    let cross = batch("cross", vec![sample(&d, "one", 10, u64::MAX)?])?;
    assert_eq!(confirmed(f.write(&cross).await?)?.replayed_samples(), 1);
    let other = batch(
        "other",
        vec![sample(&d, "one", 10, 3)?, sample(&d, "new", 12, 5)?],
    )?;
    assert!(f.write(&other).await.is_err());
    assert_eq!(f.read(&d).await?.rows.len(), 2);
    f.ch.restart().await?;
    assert!(matches!(f.write(&b).await?, Outcome::Replay(_)));
    Ok(())
}
#[tokio::test]
async fn lost_response_and_outside_window_replay_do_not_count_twice() -> anyhow::Result<()> {
    let f = Fixture::new("ch-replay").await?;
    let d = definition(TENANT)?;
    f.register(&d).await?;
    let b = batch("batch", vec![sample(&d, "one", 10, 7)?])?;
    f.store.inject_next_fault(Fault::AfterInsert);
    assert!(matches!(f.write(&b).await?, Outcome::Unknown));
    assert!(f.read(&d).await?.rows.is_empty());
    // Force eviction of the transport dedup history while retaining the domain identity.
    f.ch.sql("ALTER TABLE rss_ts_ch.raw MODIFY SETTING non_replicated_deduplication_window=1")
        .await?;
    f.ch.sql(&format!("INSERT INTO rss_ts_ch.raw VALUES ('{OTHER}','noise','s','g','noise','digest','d','r','m',1,1,1,1,'digest','{{}}')")).await?;
    assert_eq!(confirmed(f.write(&b).await?)?.new_samples(), 1);
    assert_eq!(f.read(&d).await?.rows.len(), 1);
    let spec = SummarySpec::new(
        b.stream().clone(),
        b.samples()[0].input().series.clone(),
        NonZeroU64::new(100).ok_or(Error::InvalidInput)?,
        CoveragePolicy::ObservedOnly,
        None,
    )?;
    let aq = AggregateQuery::new(
        spec,
        Interval::new(Timestamp::new(0)?, Timestamp::new(100)?)?,
        QueryBudget {
            max_points: NonZeroU32::new(10).ok_or(Error::InvalidInput)?,
            max_series: NonZeroU32::new(1).ok_or(Error::InvalidInput)?,
        },
        AggregateOp::Count,
    )?;
    let page = f
        .store
        .aggregate(
            &Authorized::<AggregateQuery>::verify(&authority(TENANT)?, aq)?,
            None,
            deadline()?,
        )
        .await?;
    assert!(matches!(page.buckets[0].value, AggregateValue::Count(1)));
    Ok(())
}
#[tokio::test]
async fn isolation_definition_retirement_and_cursors() -> anyhow::Result<()> {
    let f = Fixture::new("ch-read").await?;
    let d = definition(TENANT)?;
    f.register(&d).await?;
    let b = batch(
        "b",
        vec![
            sample(&d, "a", 10, 1)?,
            sample(&d, "b", 20, 2)?,
            sample(&d, "c", 30, 3)?,
        ],
    )?;
    confirmed(f.write(&b).await?)?;
    let q = Authorized::<Query>::verify(&authority(TENANT)?, query(&d, QueryMode::History, 1)?)?;
    let first = f.store.query(&q, None, deadline()?).await?;
    assert_eq!(first.rows.len(), 1);
    let second = f.store.query(&q, first.next.as_ref(), deadline()?).await?;
    assert_eq!(second.rows[0].sample.input().observed_at.micros(), 20);
    let different =
        Authorized::<Query>::verify(&authority(TENANT)?, query(&d, QueryMode::Latest, 1)?)?;
    assert!(matches!(
        f.store
            .query(&different, first.next.as_ref(), deadline()?)
            .await,
        Err(Error::InvalidCursor)
    ));
    let other = Fixture::connect(&f.ch, f.pool.clone(), OTHER, "ch_other").await?;
    let oq = Authorized::<Query>::verify(
        &authority(OTHER)?,
        query(&definition(OTHER)?, QueryMode::History, 10)?,
    )?;
    assert!(other.query(&oq, None, deadline()?).await?.rows.is_empty());
    assert!(matches!(
        other.query(&q, None, deadline()?).await,
        Err(Error::Unauthorized)
    ));
    let retire = Authorized::<DefinitionMutation>::verify(
        &authority(TENANT)?,
        DefinitionMutation::Retire {
            id: DefinitionId {
                scope: d.spec().scope.clone(),
                key: d.spec().key.clone(),
                version: NonZeroU64::new(1).ok_or(Error::InvalidInput)?,
            },
            expected: d.digest()?,
        },
    )?;
    confirmed(f.store.change(&retire, deadline()?).await?)?;
    assert!(matches!(f.write(&b).await?, Outcome::Replay(_)));
    assert!(
        f.write(&batch("new", vec![sample(&d, "new", 40, 4)?])?)
            .await
            .is_err()
    );
    Ok(())
}
#[tokio::test]
async fn recompute_late_delete_restore_and_retained_summary() -> anyhow::Result<()> {
    let f = Fixture::new("ch-life").await?;
    let d = definition(TENANT)?;
    f.register(&d).await?;
    let b = batch(
        "b",
        vec![sample(&d, "one", 10, 2)?, sample(&d, "two", 20, 4)?],
    )?;
    confirmed(f.write(&b).await?)?;
    let spec = SummarySpec::new(
        b.stream().clone(),
        b.samples()[0].input().series.clone(),
        NonZeroU64::new(100).ok_or(Error::InvalidInput)?,
        CoveragePolicy::ObservedOnly,
        None,
    )?;
    let window = Interval::new(Timestamp::new(0)?, Timestamp::new(100)?)?;
    assert!(matches!(
        f.maintain(
            "sum",
            MaintenanceAction::Recompute {
                spec: spec.clone(),
                window
            }
        )
        .await?,
        MaintenanceProgress::Complete { .. }
    ));
    let budget = QueryBudget {
        max_points: NonZeroU32::new(10).ok_or(Error::InvalidInput)?,
        max_series: NonZeroU32::new(1).ok_or(Error::InvalidInput)?,
    };
    let aq = Authorized::<AggregateQuery>::verify(
        &authority(TENANT)?,
        AggregateQuery::new(spec.clone(), window, budget, AggregateOp::Sum)?,
    )?;
    assert!(matches!(
        f.store.aggregate(&aq, None, deadline()?).await?.buckets[0].value,
        AggregateValue::Sum(Sum::U128(6))
    ));
    confirmed(
        f.write(&batch("late", vec![sample(&d, "late", 15, 3)?])?)
            .await?,
    )?;
    assert!(matches!(
        f.store.aggregate(&aq, None, deadline()?).await?.buckets[0].value,
        AggregateValue::Sum(Sum::U128(9))
    ));
    let time: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp())*1000000)::bigint")
            .fetch_one(&f.admin)
            .await?;
    let deleted = Interval::new(Timestamp::new(14)?, Timestamp::new(16)?)?;
    f.maintain(
        "delete",
        MaintenanceAction::Delete {
            selection: spec.selection(),
            window: deleted,
            restore_until: Timestamp::new(time + 60_000_000)?,
        },
    )
    .await?;
    assert_eq!(f.read(&d).await?.rows.len(), 2);
    f.maintain(
        "restore",
        MaintenanceAction::Restore {
            selection: spec.selection(),
            window: deleted,
            deletion_fence: id("delete")?,
        },
    )
    .await?;
    assert_eq!(f.read(&d).await?.rows.len(), 3);
    f.maintain(
        "sum2",
        MaintenanceAction::Recompute {
            spec: spec.clone(),
            window,
        },
    )
    .await?;
    f.maintain(
        "cutoff",
        MaintenanceAction::AdvanceCutoff {
            selection: spec.selection(),
            before: Timestamp::new(100)?,
        },
    )
    .await?;
    assert!(matches!(
        f.maintain(
            "prune",
            MaintenanceAction::Prune {
                selection: spec.selection(),
                raw_before: Timestamp::new(100)?,
                summaries_before: Timestamp::new(0)?
            }
        )
        .await?,
        MaintenanceProgress::Complete { .. }
    ));
    assert!(f.read(&d).await?.rows.is_empty());
    assert!(matches!(
        f.store.aggregate(&aq, None, deadline()?).await?.buckets[0].value,
        AggregateValue::Sum(Sum::U128(9))
    ));
    assert!(matches!(f.write(&b).await?, Outcome::Replay(_)));
    assert!(f.read(&d).await?.rows.is_empty());
    Ok(())
}
#[tokio::test]
async fn pending_write_blocks_maintenance_and_closed_stream_cannot_reopen() -> anyhow::Result<()> {
    let f = Fixture::new("ch-close").await?;
    let d = definition(TENANT)?;
    f.register(&d).await?;
    let b = batch("b", vec![sample(&d, "one", 10, 2)?])?;
    f.store.inject_next_fault(Fault::AfterPrepare);
    assert!(matches!(f.write(&b).await?, Outcome::Unknown));
    assert!(matches!(
        f.maintain(
            "close",
            MaintenanceAction::CloseStream {
                stream: b.stream().clone()
            }
        )
        .await?,
        MaintenanceProgress::Blocked {
            reason: MaintenanceBlock::PendingWrite
        }
    ));
    confirmed(f.write(&b).await?)?;
    f.maintain(
        "close",
        MaintenanceAction::CloseStream {
            stream: b.stream().clone(),
        },
    )
    .await?;
    assert!(
        f.write(&batch("new", vec![sample(&d, "new", 20, 3)?])?)
            .await
            .is_err()
    );
    assert!(matches!(f.write(&b).await?, Outcome::Replay(_)));
    Ok(())
}
#[tokio::test]
async fn rejects_unsafe_admission_and_tls_identity() -> anyhow::Result<()> {
    let f = Fixture::new("ch-probe").await?;
    f.ch.sql("GRANT INSERT ON rss_ts_ch.raw TO ch_reader")
        .await?;
    assert!(
        Fixture::connect(&f.ch, f.pool.clone(), TENANT, "ch_reader")
            .await
            .is_err()
    );
    f.ch.sql("REVOKE INSERT ON rss_ts_ch.raw FROM ch_reader")
        .await?;
    f.ch.sql("CREATE MATERIALIZED VIEW rss_ts_ch.unexpected ENGINE=MergeTree ORDER BY tenant AS SELECT tenant FROM rss_ts_ch.raw").await?;
    assert!(
        Fixture::connect(&f.ch, f.pool.clone(), TENANT, "ch_reader")
            .await
            .is_err()
    );
    let credentials = || Credentials::new("x".into(), "fixture-only".into());
    assert!(
        Connections::new(
            "http://localhost",
            f.ch.ca_pem().as_bytes(),
            credentials()?,
            credentials()?,
            credentials()?
        )
        .is_err()
    );
    Ok(())
}

#[derive(serde::Deserialize)]
struct Schema {
    control: String,
    clickhouse: Vec<String>,
}
async fn schema(instance: &str) -> anyhow::Result<Schema> {
    match std::env::var("RSS_CH_SCHEMA") {
        Ok(binary) => {
            use tokio::io::AsyncWriteExt;
            let mut child = tokio::process::Command::new(&binary)
                .kill_on_drop(true)
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::null())
                .spawn()?;
            let mut stdin = child.stdin.take().ok_or_else(|| anyhow::anyhow!("stdin"))?;
            stdin.write_all(&serde_json::to_vec(instance)?).await?;
            drop(stdin);
            let output =
                tokio::time::timeout(Duration::from_secs(30), child.wait_with_output()).await??;
            anyhow::ensure!(
                output.status.success() && output.stdout.len() < 131072,
                "schema consumer failed"
            );
            eprintln!("external-provider-consumer PASS {binary}");
            Ok(serde_json::from_slice(&output.stdout)?)
        }
        Err(std::env::VarError::NotPresent) => Ok(Schema {
            control: rss_timeseries_clickhouse::CONTROL_SQL.into(),
            clickhouse: rss_timeseries_clickhouse::installation_sql(instance)?,
        }),
        Err(e) => Err(e.into()),
    }
}
mod examples {
    use super::*;
    #[tokio::test]
    async fn example_consumer() -> anyhow::Result<()> {
        let f = Fixture::new("ch-example").await?;
        let mut input = testkit::example_process::pg_input(&f.pg, "ch_runtime", TENANT);
        input["endpoint"] = serde_json::json!(f.ch.endpoint());
        input["ch_ca"] = serde_json::json!(f.ch.ca_pem());
        input["reader"] = serde_json::json!("ch_reader");
        input["writer"] = serde_json::json!("ch_writer");
        input["maintenance"] = serde_json::json!("ch_maint");
        input["ch_password"] = serde_json::json!("fixture-only");
        input["cursor_key"] = serde_json::to_value([42; 32])?;
        match std::env::var("RSS_CH_EXAMPLE") {
            Ok(binary) => {
                testkit::example_process::run_binary(&binary, &input, Duration::from_secs(90))
                    .await?;
                eprintln!("external-provider-consumer PASS {binary}");
            }
            Err(std::env::VarError::NotPresent) => {
                rss_examples::timeseries_clickhouse::run(serde_json::from_value(input)?).await?
            }
            Err(e) => return Err(e.into()),
        }
        Ok(())
    }
}

#[tokio::test]
async fn revoked_guard_rejects_late_insert_after_prune() -> anyhow::Result<()> {
    let f = Fixture::new("ch-guard").await?;
    let d = definition(TENANT)?;
    f.register(&d).await?;
    let b = batch("b", vec![sample(&d, "one", 10, 2)?])?;
    confirmed(f.write(&b).await?)?;
    let old: (String,String,String,i64)=sqlx::query_as("SELECT id::text,query_id::text,digest,revision FROM rss_ts_ch.attempts ORDER BY id LIMIT 1").fetch_one(&f.admin).await?;
    // Persist exactly what an old network request would send, before physical cleanup.
    let captured =
        f.ch.sql("SELECT * FROM rss_ts_ch.raw FORMAT JSONEachRow")
            .await?;
    let spec = Selection::Exact {
        stream: b.stream().clone(),
        series: b.samples()[0].input().series.clone(),
    };
    f.maintain(
        "cutoff",
        MaintenanceAction::AdvanceCutoff {
            selection: spec.clone(),
            before: Timestamp::new(100)?,
        },
    )
    .await?;
    f.maintain(
        "prune",
        MaintenanceAction::Prune {
            selection: spec,
            raw_before: Timestamp::new(100)?,
            summaries_before: Timestamp::new(0)?,
        },
    )
    .await?;
    assert_eq!(
        f.ch.sql("SELECT count() FROM rss_ts_ch.raw").await?.trim(),
        "0"
    );
    // Replay a late INSERT in the server pipeline: the revoked/missing permit gives zero rows.
    assert!(
        !captured.trim().is_empty(),
        "captured a real stored row before cleanup"
    );
    let ddl = "tenant String,namespace String,source String,generation String,sample_id String,series String,subject String,resource String,metric_key String,observed_at Int64,sequence UInt64,received_at Int64,revision Int64,digest String,payload String";
    let query = format!(
        "INSERT INTO rss_ts_ch.raw SELECT i.* FROM input('{ddl}') i INNER JOIN rss_ts_ch.active_attempts a ON i.tenant=a.tenant AND i.namespace=a.namespace AND i.revision=a.revision WHERE a.attempt='{}' AND a.query_id='{}' AND a.digest='{}' FORMAT JSONEachRow\n{}",
        old.0, old.1, old.2, captured
    );
    f.ch.sql(&query).await?;
    assert_eq!(
        f.ch.sql("SELECT count() FROM rss_ts_ch.raw").await?.trim(),
        "0"
    );
    assert!(f.read(&d).await?.rows.is_empty());
    Ok(())
}
#[tokio::test]
async fn simultaneous_batches_and_confirmed_receipt_after_ack_loss() -> anyhow::Result<()> {
    let f = Fixture::new("ch-concurrent").await?;
    let d = definition(TENANT)?;
    f.register(&d).await?;
    let b = batch("b", vec![sample(&d, "one", 10, 2)?])?;
    let (left, right) = tokio::join!(f.write(&b), f.write(&b));
    // Racing callers may receive Unknown, but neither can publish divergent facts.
    let _ = (left?, right?);
    confirmed(f.write(&b).await?)?;
    assert_eq!(f.read(&d).await?.rows.len(), 1);
    let next = batch("next", vec![sample(&d, "two", 20, 3)?])?;
    f.store.inject_next_fault(Fault::AfterPublish);
    assert!(matches!(f.write(&next).await?, Outcome::Unknown));
    let q = Authorized::<ReceiptQuery>::verify(&authority(TENANT)?, receipt_query(&next)?)?;
    assert!(matches!(
        f.store.receipt(&q, deadline()?).await?,
        Lookup::Found(_)
    ));
    assert!(matches!(f.write(&next).await?, Outcome::Replay(_)));
    Ok(())
}

#[tokio::test]
async fn typed_values_and_custom_dimensions_roundtrip() -> anyhow::Result<()> {
    let f = Fixture::new("ch-values").await?;
    let cases = vec![
        (
            Metric::Gauge {
                number: NumberKind::I64,
            },
            Value::Number(Number::I64(i64::MIN)),
        ),
        (
            Metric::Gauge {
                number: NumberKind::F64,
            },
            Value::Number(Number::F64(FiniteF64::new(1.0000000000000002)?)),
        ),
        (
            Metric::Counter {
                number: NumberKind::U64,
                temporality: Temporality::Cumulative,
            },
            Value::Number(Number::U64(u64::MAX)),
        ),
        (
            Metric::Counter {
                number: NumberKind::I64,
                temporality: Temporality::Delta,
            },
            Value::Number(Number::I64(5)),
        ),
        (Metric::Bool, Value::Bool(true)),
        (
            Metric::State {
                members: [id("active")?, id("idle")?].into(),
            },
            Value::State(id("active")?),
        ),
    ];
    for (n, (metric, value)) in cases.into_iter().enumerate() {
        let mut spec = definition(TENANT)?.spec().clone();
        spec.key = id(&format!("typed.{n}"))?;
        spec.metric = metric;
        spec.dimensions.allowed.insert(id("channel")?);
        spec.dimensions.max_count = 1;
        let d = Definition::new(spec)?;
        f.register(&d).await?;
        let stream = Stream::new(d.spec().scope.clone(), id("s")?, id("g")?);
        let series = Series::new(
            d.clone(),
            id("device")?,
            id("resource")?,
            [(id("channel")?, id("温度'\\sensor")?)].into(),
        )?;
        let sample = Sample::new(SampleInput {
            stream: stream.clone(),
            series: series.clone(),
            id: id(&format!("sample.{n}"))?,
            sequence: u64::MAX,
            observed_at: Timestamp::new(100)?,
            interval: matches!(d.spec().metric, Metric::Counter { .. })
                .then(|| Interval::new(Timestamp::new(0)?, Timestamp::new(100)?))
                .transpose()?,
            reading: Reading::Valid(value),
        })?;
        let b = batch(&format!("typed.{n}"), vec![sample.clone()])?;
        confirmed(f.write(&b).await?)?;
        let q = Query::new(
            Selection::Exact { stream, series },
            Interval::new(Timestamp::new(0)?, Timestamp::new(101)?)?,
            QueryBudget {
                max_points: NonZeroU32::new(10).ok_or(Error::InvalidInput)?,
                max_series: NonZeroU32::new(1).ok_or(Error::InvalidInput)?,
            },
            QueryMode::History,
        )?;
        let page = f
            .store
            .query(
                &Authorized::<Query>::verify(&authority(TENANT)?, q)?,
                None,
                deadline()?,
            )
            .await?;
        assert_eq!(page.rows.len(), 1);
        assert_eq!(page.rows[0].sample, sample);
    }
    Ok(())
}
mod crash {
    use super::*;
    fn crash_definition() -> anyhow::Result<Definition> {
        let mut spec = definition(TENANT)?.spec().clone();
        spec.dimensions.allowed = (0..64)
            .map(|n| Id::new(format!("k{n:02}")))
            .collect::<Result<_, _>>()?;
        spec.dimensions.max_count = 64;
        Ok(Definition::new(spec)?)
    }
    #[tokio::test]
    async fn process_death_after_partial_publication_recovers() -> anyhow::Result<()> {
        use tokio::io::AsyncWriteExt;
        let f = Fixture::new("ch-crash").await?;
        let d = crash_definition()?;
        f.register(&d).await?;
        let root = std::env::temp_dir().join(format!("rss-ch-crash-{}", std::process::id()));
        std::fs::create_dir_all(&root)?;
        let marker = root.join("prepared");
        let p = f.pg.params();
        let input = serde_json::json!({"host":p.host,"port":p.port,"database":p.database,"pg_ca":f.pg.ca_pem(),"endpoint":f.ch.endpoint(),"ch_ca":f.ch.ca_pem(),"marker":marker});
        let mut child = tokio::process::Command::new(std::env::current_exe()?)
            .args(["--exact", "crash::child", "--ignored", "--nocapture"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::inherit())
            .kill_on_drop(true)
            .spawn()?;
        let mut stdin = child.stdin.take().ok_or_else(|| anyhow::anyhow!("stdin"))?;
        stdin.write_all(&serde_json::to_vec(&input)?).await?;
        drop(stdin);
        let ready = tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                if f.ch.sql("SELECT count() FROM system.processes WHERE query LIKE 'INSERT INTO rss_ts_ch.raw%'").await?.trim()!="0" {
                    break;
                }
                if child.try_wait()?.is_some() {
                    anyhow::bail!("child exited before the real storage boundary");
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            Ok::<_, anyhow::Error>(())
        })
        .await;
        child.kill().await?;
        child.wait().await?;
        ready??;
        assert!(f.read(&d).await?.rows.is_empty());
        let reopened = Fixture::connect(&f.ch, f.pool.clone(), TENANT, "ch_reader").await?;
        let result = confirmed(
            reopened
                .recover(&d.spec().scope, &authority(TENANT)?, deadline()?)
                .await?,
        )?;
        assert_eq!(
            result
                .ok_or_else(|| anyhow::anyhow!("recovered receipt"))?
                .new_samples(),
            24
        );
        assert_eq!(f.read(&d).await?.rows.len(), 24);
        std::fs::remove_dir_all(root)?;
        Ok(())
    }
    #[tokio::test]
    #[ignore = "subprocess killed at a real PG/CH publication boundary"]
    async fn child() -> anyhow::Result<()> {
        use std::io::Read;
        let mut data = Vec::new();
        std::io::stdin().take(65536).read_to_end(&mut data)?;
        let v: serde_json::Value = serde_json::from_slice(&data)?;
        let text = |key: &str| {
            v[key]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("child input"))
        };
        let pool = PgPoolOptions::new()
            .max_connections(3)
            .connect_with(
                PgConnectOptions::new()
                    .host(text("host")?)
                    .port(u16::try_from(
                        v["port"].as_u64().ok_or_else(|| anyhow::anyhow!("port"))?,
                    )?)
                    .database(text("database")?)
                    .username("ch_runtime")
                    .password("fixture-only")
                    .ssl_mode(PgSslMode::VerifyFull)
                    .ssl_root_cert_from_pem(text("pg_ca")?.as_bytes().to_vec()),
            )
            .await?;
        let c = |user: &str| Credentials::new(user.into(), "fixture-only".into());
        let connections = Connections::new(
            text("endpoint")?,
            text("ch_ca")?.as_bytes(),
            c("ch_reader")?,
            c("ch_writer")?,
            c("ch_maint")?,
        )?;
        let store = ChStore::new(
            TenantId::parse(TENANT)?,
            pool,
            connections,
            Timer,
            limits()?,
            CursorKey::new([42; 32]),
            deadline()?,
        )
        .await?;
        store.inject_next_fault(Fault::BeforeInsertEnd);
        let d = crash_definition()?;
        let dimensions = (0..64)
            .map(|n| Ok((Id::new(format!("k{n:02}"))?, Id::new("x".repeat(256))?)))
            .collect::<Result<std::collections::BTreeMap<_, _>, Error>>()?;
        let series = Series::new(d.clone(), id("device")?, id("resource")?, dimensions)?;
        let mut samples = Vec::new();
        for n in 0..24 {
            let mut input = sample(&d, &format!("crash.{n}"), 10, n)?.input().clone();
            input.series = series.clone();
            samples.push(Sample::new(input)?);
        }
        let b = batch("crash", samples)?;
        assert!(matches!(
            store
                .write(
                    &Authorized::<Batch>::verify(&authority(TENANT)?, b)?,
                    deadline()?
                )
                .await?,
            Outcome::Unknown
        ));
        std::fs::write(text("marker")?, b"projected-not-published")?;
        std::future::pending::<()>().await;
        Ok(())
    }
}

#[tokio::test]
async fn rejects_broad_policies_guard_drift_and_service_escalation() -> anyhow::Result<()> {
    let f = Fixture::new("ch-acl").await?;
    for (grant, revoke) in [
        (
            "CREATE ROW POLICY broad ON rss_ts_ch.raw USING 1 TO ALL",
            "DROP ROW POLICY broad ON rss_ts_ch.raw",
        ),
        (
            "GRANT ALTER DELETE ON rss_ts_ch.raw TO ch_writer",
            "REVOKE ALTER DELETE ON rss_ts_ch.raw FROM ch_writer",
        ),
        (
            "GRANT INSERT ON rss_ts_ch.raw TO ch_maint",
            "REVOKE INSERT ON rss_ts_ch.raw FROM ch_maint",
        ),
        (
            "GRANT SHOW NAMED COLLECTIONS, SHOW NAMED COLLECTIONS SECRETS ON * TO ch_maint",
            "REVOKE SHOW NAMED COLLECTIONS, SHOW NAMED COLLECTIONS SECRETS ON * FROM ch_maint",
        ),
    ] {
        f.ch.sql(grant).await?;
        assert!(
            Fixture::connect(&f.ch, f.pool.clone(), TENANT, "ch_reader")
                .await
                .is_err()
        );
        f.ch.sql(revoke).await?;
    }
    for (grant, revoke) in [
        (
            "ALTER POLICY tenant ON rss_ts_ch.batches USING(true) WITH CHECK(true)",
            "ALTER POLICY tenant ON rss_ts_ch.batches USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid)",
        ),
        (
            "CREATE POLICY broad ON rss_ts_ch.batches TO ch_runtime USING(true) WITH CHECK(true)",
            "DROP POLICY broad ON rss_ts_ch.batches",
        ),
        (
            "ALTER ROLE ch_guard SUPERUSER",
            "ALTER ROLE ch_guard NOSUPERUSER",
        ),
        (
            "GRANT SELECT ON rss_ts_ch.batches TO ch_guard",
            "REVOKE SELECT ON rss_ts_ch.batches FROM ch_guard",
        ),
        (
            "GRANT SELECT(payload) ON rss_ts_ch.batches TO ch_guard",
            "REVOKE SELECT(payload) ON rss_ts_ch.batches FROM ch_guard",
        ),
        (
            "GRANT INSERT(payload) ON rss_ts_ch.batches TO ch_guard",
            "REVOKE INSERT(payload) ON rss_ts_ch.batches FROM ch_guard",
        ),
        (
            "GRANT UPDATE(payload) ON rss_ts_ch.batches TO ch_guard",
            "REVOKE UPDATE(payload) ON rss_ts_ch.batches FROM ch_guard",
        ),
        (
            "GRANT REFERENCES(payload) ON rss_ts_ch.batches TO ch_guard",
            "REVOKE REFERENCES(payload) ON rss_ts_ch.batches FROM ch_guard",
        ),
        (
            "GRANT INSERT(attempt) ON rss_ts_ch.active_attempts TO ch_guard",
            "REVOKE INSERT(attempt) ON rss_ts_ch.active_attempts FROM ch_guard",
        ),
        (
            "GRANT UPDATE(attempt) ON rss_ts_ch.active_attempts TO ch_guard",
            "REVOKE UPDATE(attempt) ON rss_ts_ch.active_attempts FROM ch_guard",
        ),
        (
            "GRANT REFERENCES(attempt) ON rss_ts_ch.active_attempts TO ch_guard",
            "REVOKE REFERENCES(attempt) ON rss_ts_ch.active_attempts FROM ch_guard",
        ),
        (
            "GRANT INSERT(id) ON rss_ts_ch.installation TO ch_runtime",
            "REVOKE INSERT(id) ON rss_ts_ch.installation FROM ch_runtime",
        ),
        (
            "GRANT UPDATE(id) ON rss_ts_ch.installation TO ch_runtime",
            "REVOKE UPDATE(id) ON rss_ts_ch.installation FROM ch_runtime",
        ),
        (
            "GRANT REFERENCES(id) ON rss_ts_ch.installation TO ch_runtime",
            "REVOKE REFERENCES(id) ON rss_ts_ch.installation FROM ch_runtime",
        ),
        (
            "GRANT SELECT(attempt) ON rss_ts_ch.active_attempts TO ch_runtime",
            "REVOKE SELECT(attempt) ON rss_ts_ch.active_attempts FROM ch_runtime",
        ),
    ] {
        // Audited closed fixture statements; no producer input enters DDL.
        sqlx::raw_sql(sqlx::AssertSqlSafe(grant))
            .execute(&f.admin)
            .await?;
        assert!(
            Fixture::connect(&f.ch, f.pool.clone(), TENANT, "ch_reader")
                .await
                .is_err()
        );
        sqlx::raw_sql(sqlx::AssertSqlSafe(revoke))
            .execute(&f.admin)
            .await?;
    }
    Fixture::connect(&f.ch, f.pool.clone(), TENANT, "ch_reader").await?;
    sqlx::raw_sql("CREATE TABLE rss_ts_ch.cached_attempts AS SELECT * FROM rss_ts_ch.active_attempts; GRANT SELECT ON rss_ts_ch.cached_attempts TO ch_guard").execute(&f.admin).await?;
    f.ch.sql("DROP TABLE rss_ts_ch.active_attempts; CREATE TABLE rss_ts_ch.active_attempts (tenant String,namespace String,attempt String,query_id String,target String,digest String,revision Int64,installation String) ENGINE=PostgreSQL(rss_ts_ch_guard, table='cached_attempts',schema='rss_ts_ch')").await?;
    assert!(
        Fixture::connect(&f.ch, f.pool.clone(), TENANT, "ch_reader")
            .await
            .is_err()
    );
    Ok(())
}
#[tokio::test]
async fn receipt_expiry_reclaim_and_terminal_fences() -> anyhow::Result<()> {
    let f = Fixture::new("ch-expire").await?;
    let d = definition(TENANT)?;
    f.register(&d).await?;
    let b = batch("b", vec![sample(&d, "one", 10, 2)?])?;
    confirmed(f.write(&b).await?)?;
    let before = Timestamp::new(i64::MAX)?;
    assert!(matches!(
        f.maintain(
            "early",
            MaintenanceAction::ExpireReceipts {
                stream: b.stream().clone(),
                before
            }
        )
        .await?,
        MaintenanceProgress::Blocked {
            reason: MaintenanceBlock::ReplayGuarantee
        }
    ));
    // Advance only the fixture-owned durable acceptance clock to avoid wall-time sleeps.
    sqlx::query("UPDATE rss_ts_ch.batches SET received_at=1,replay_until=2")
        .execute(&f.admin)
        .await?;
    f.maintain(
        "expire",
        MaintenanceAction::ExpireReceipts {
            stream: b.stream().clone(),
            before,
        },
    )
    .await?;
    let rq = Authorized::<ReceiptQuery>::verify(&authority(TENANT)?, receipt_query(&b)?)?;
    assert!(matches!(
        f.store.receipt(&rq, deadline()?).await?,
        Lookup::Expired
    ));
    assert!(matches!(
        f.maintain(
            "reclaim-open",
            MaintenanceAction::Reclaim {
                stream: b.stream().clone()
            }
        )
        .await?,
        MaintenanceProgress::Blocked {
            reason: MaintenanceBlock::StreamOpen
        }
    ));
    f.maintain(
        "close",
        MaintenanceAction::CloseStream {
            stream: b.stream().clone(),
        },
    )
    .await?;
    assert!(matches!(
        f.maintain(
            "reclaim-retained",
            MaintenanceAction::Reclaim {
                stream: b.stream().clone()
            }
        )
        .await?,
        MaintenanceProgress::Blocked {
            reason: MaintenanceBlock::RetainedData
        }
    ));
    let selection = query(&d, QueryMode::History, 10)?.selection().clone();
    f.maintain(
        "cutoff",
        MaintenanceAction::AdvanceCutoff {
            selection: selection.clone(),
            before: Timestamp::new(100)?,
        },
    )
    .await?;
    f.maintain(
        "prune",
        MaintenanceAction::Prune {
            selection,
            raw_before: Timestamp::new(100)?,
            summaries_before: Timestamp::new(100)?,
        },
    )
    .await?;
    assert!(matches!(
        f.maintain(
            "reclaim",
            MaintenanceAction::Reclaim {
                stream: b.stream().clone()
            }
        )
        .await?,
        MaintenanceProgress::Complete { .. }
    ));
    assert!(matches!(
        f.store.receipt(&rq, deadline()?).await?,
        Lookup::Expired
    ));
    assert!(matches!(
        f.store
            .write(
                &Authorized::<Batch>::verify(&authority(TENANT)?, b)?,
                deadline()?
            )
            .await,
        Err(Error::HistoryExpired)
    ));
    Ok(())
}
#[tokio::test]
async fn repeated_recompute_mixed_resolutions_and_summary_only_prune() -> anyhow::Result<()> {
    let f = Fixture::new("ch-summary").await?;
    let d = definition(TENANT)?;
    f.register(&d).await?;
    let b = batch(
        "b",
        vec![sample(&d, "one", 10, 2)?, sample(&d, "two", 210, 3)?],
    )?;
    confirmed(f.write(&b).await?)?;
    let spec = |resolution| {
        SummarySpec::new(
            b.stream().clone(),
            b.samples()[0].input().series.clone(),
            NonZeroU64::new(resolution).ok_or(Error::InvalidInput)?,
            CoveragePolicy::ObservedOnly,
            None,
        )
    };
    let window = |end| Interval::new(Timestamp::new(0)?, Timestamp::new(end)?);
    f.maintain(
        "hundred",
        MaintenanceAction::Recompute {
            spec: spec(100)?,
            window: window(100)?,
        },
    )
    .await?;
    f.maintain(
        "hundred-again",
        MaintenanceAction::Recompute {
            spec: spec(100)?,
            window: window(100)?,
        },
    )
    .await?;
    f.maintain(
        "sixty",
        MaintenanceAction::Recompute {
            spec: spec(60)?,
            window: window(300)?,
        },
    )
    .await?;
    // No raw interval exists; retaining part of a registered range must not construct -1.
    f.maintain(
        "summary-only",
        MaintenanceAction::Prune {
            selection: spec(60)?.selection(),
            raw_before: Timestamp::new(0)?,
            summaries_before: Timestamp::new(0)?,
        },
    )
    .await?;
    f.maintain(
        "cutoff",
        MaintenanceAction::AdvanceCutoff {
            selection: spec(60)?.selection(),
            before: Timestamp::new(300)?,
        },
    )
    .await?;
    f.maintain(
        "prune",
        MaintenanceAction::Prune {
            selection: spec(60)?.selection(),
            raw_before: Timestamp::new(300)?,
            summaries_before: Timestamp::new(0)?,
        },
    )
    .await?;
    let q = AggregateQuery::new(
        spec(300)?,
        window(300)?,
        QueryBudget {
            max_points: NonZeroU32::new(10).ok_or(Error::InvalidInput)?,
            max_series: NonZeroU32::new(1).ok_or(Error::InvalidInput)?,
        },
        AggregateOp::Sum,
    )?;
    let page = f
        .store
        .aggregate(
            &Authorized::<AggregateQuery>::verify(&authority(TENANT)?, q)?,
            None,
            deadline()?,
        )
        .await?;
    assert!(matches!(
        page.buckets[0].value,
        AggregateValue::Sum(Sum::U128(5))
    ));
    Ok(())
}
