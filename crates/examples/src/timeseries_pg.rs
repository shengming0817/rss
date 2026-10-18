//! Minimal public provider consumer. Authentication and deployment remain host-owned.
use rss_request_context::{Clock, Deadline, TenantId};
use rss_timeseries::*;
use rss_timeseries_postgres::{CursorKey, Limits, MIGRATION_SQL, PgStore};
use std::{
    num::{NonZeroU32, NonZeroU64},
    time::{Duration, Instant},
};
#[derive(serde::Deserialize)]
pub struct Input {
    #[serde(flatten)]
    pub pg: crate::pg::Input,
    pub cursor_key: [u8; 32],
}
struct Timer;
impl Clock for Timer {
    #[allow(clippy::disallowed_methods)] // reason: concrete monotonic clock injected by this example host.
    fn now(&self) -> Instant {
        Instant::now()
    }
}
struct Operator(TenantId);
impl Authority for Operator {
    fn authorize(&self, access: Access<'_>) -> Result<(), Error> {
        let scope = match access {
            Access::Definition(DefinitionMutation::Register { definition, .. }) => {
                &definition.spec().scope
            }
            Access::Write(b) => b.stream().scope(),
            Access::Receipt(q) => q.stream.scope(),
            Access::Query(q) => q.selection().scope(),
            Access::Aggregate(v) => v.spec().stream().scope(),
            Access::Maintain(v) => v.scope(),
            _ => return Err(Error::Unauthorized),
        };
        if scope.tenant() == self.0 {
            Ok(())
        } else {
            Err(Error::Unauthorized)
        }
    }
}
fn budget() -> anyhow::Result<Deadline> {
    Ok(Deadline::from_timeout(&Timer, Duration::from_secs(15))?)
}
fn confirmed<T>(outcome: Outcome<T>) -> anyhow::Result<T> {
    match outcome {
        Outcome::Accepted(v) | Outcome::Replay(v) => Ok(v),
        Outcome::Unknown => anyhow::bail!("resolve original identity before retry"),
    }
}
pub async fn install(input: crate::pg::Input) -> anyhow::Result<()> {
    let pool = input.pool().await?;
    let mut c = pool.acquire().await?;
    sqlx::raw_sql("SET ROLE ts_owner").execute(&mut *c).await?;
    sqlx::raw_sql(MIGRATION_SQL).execute(&mut *c).await?;
    // The fixture explicitly chooses its admission interval; products choose their own partitions.
    sqlx::raw_sql("SELECT rss_timeseries.create_partition(0,100); SELECT rss_timeseries.create_partition(100,1000000); RESET ROLE").execute(&mut *c).await?;
    drop(c);
    pool.close().await;
    Ok(())
}
pub async fn run(input: Input) -> anyhow::Result<()> {
    let tenant = TenantId::parse(&input.pg.tenant)?;
    let operator = Operator(tenant);
    let scope = Scope::new(tenant, Id::new("example")?);
    let d = Definition::new(DefinitionSpec {
        scope: scope.clone(),
        key: Id::new("custom.gauge")?,
        version: 1,
        unit: Id::new("units")?,
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
    })?;
    let pool = input.pg.pool().await?;
    let limits = Limits {
        max_points: NonZeroU32::new(10).ok_or(Error::InvalidInput)?,
        max_series: NonZeroU32::new(10).ok_or(Error::InvalidInput)?,
        max_bytes: NonZeroU32::new(65536).ok_or(Error::InvalidInput)?,
        replay_micros: NonZeroU64::new(60_000_000).ok_or(Error::InvalidInput)?,
        cursor_micros: NonZeroU64::new(60_000_000).ok_or(Error::InvalidInput)?,
    };
    let store = PgStore::new(
        rss_timeseries_postgres::StorageProfile::PostgreSQL,
        pool.clone(),
        Timer,
        limits.clone(),
        CursorKey::new(input.cursor_key),
        budget()?,
    )
    .await?;
    confirmed(
        store
            .change(
                &Authorized::<DefinitionMutation>::verify(
                    &operator,
                    DefinitionMutation::Register {
                        definition: d.clone(),
                        expected_latest: None,
                    },
                )?,
                budget()?,
            )
            .await?,
    )?;
    let stream = Stream::new(scope, Id::new("source")?, Id::new("generation")?);
    let series = Series::new(
        d,
        Id::new("subject")?,
        Id::new("resource")?,
        Default::default(),
    )?;
    let sample = Sample::new(SampleInput {
        stream: stream.clone(),
        series: series.clone(),
        id: Id::new("sample")?,
        sequence: u64::MAX,
        observed_at: Timestamp::new(100)?,
        interval: None,
        reading: Reading::Valid(Value::Number(Number::U64(u64::MAX))),
    })?;
    let batch = Batch::new(stream.clone(), Id::new("batch")?, vec![sample.clone()])?;
    let write = Authorized::<Batch>::verify(&operator, batch.clone())?;
    let first = confirmed(store.write(&write, budget()?).await?)?;
    anyhow::ensure!(
        matches!(store.write(&write, budget()?).await?, Outcome::Replay(_)),
        "batch did not replay"
    );
    let reopened = PgStore::new(
        rss_timeseries_postgres::StorageProfile::PostgreSQL,
        pool.clone(),
        Timer,
        limits,
        CursorKey::new(input.cursor_key),
        budget()?,
    )
    .await?;
    let receipt = reopened
        .receipt(
            &Authorized::<ReceiptQuery>::verify(
                &operator,
                ReceiptQuery {
                    stream: stream.clone(),
                    batch_id: batch.id().clone(),
                    digest: batch.digest()?,
                },
            )?,
            budget()?,
        )
        .await?;
    let Lookup::Found(receipt) = receipt else {
        anyhow::bail!("durable receipt missing")
    };
    anyhow::ensure!(
        receipt.received_at() == first.received_at(),
        "receipt changed"
    );
    let q = Query::new(
        Selection::Exact { stream, series },
        Interval::new(Timestamp::new(0)?, Timestamp::new(101)?)?,
        QueryBudget {
            max_points: NonZeroU32::MIN,
            max_series: NonZeroU32::MIN,
        },
        QueryMode::Latest,
    )?;
    let result = reopened
        .query(&Authorized::<Query>::verify(&operator, q)?, None, budget()?)
        .await?;
    anyhow::ensure!(
        result.rows.len() == 1 && result.rows[0].sample == sample && result.next.is_none(),
        "query failed exact value preservation"
    );
    lifecycle(&reopened, &operator, &sample, &receipt).await?;
    store.close(budget()?).await?;
    Ok(())
}

async fn maintain(
    store: &PgStore<Timer>,
    operator: &Operator,
    id: &str,
    action: MaintenanceAction,
) -> anyhow::Result<()> {
    let request = Authorized::<MaintenanceRequest>::verify(
        operator,
        MaintenanceRequest::new(
            Id::new(id)?,
            action,
            MaintenanceBudget {
                rows: NonZeroU32::new(2).ok_or(Error::InvalidInput)?,
                buckets: NonZeroU32::new(2).ok_or(Error::InvalidInput)?,
            },
        )?,
    )?;
    let mut next = None;
    for _ in 0..100 {
        match confirmed(store.step(&request, next.as_ref(), budget()?).await?)? {
            MaintenanceProgress::Complete { .. } => return Ok(()),
            MaintenanceProgress::More { next: token, .. } => next = Some(token),
            MaintenanceProgress::Blocked { reason } => {
                anyhow::bail!("maintenance blocked: {reason:?}")
            }
        }
    }
    anyhow::bail!("example maintenance budget exhausted")
}

async fn lifecycle(
    reopened: &PgStore<Timer>,
    operator: &Operator,
    sample: &Sample,
    receipt: &Receipt,
) -> anyhow::Result<()> {
    let spec = SummarySpec::new(
        sample.input().stream.clone(),
        sample.input().series.clone(),
        NonZeroU64::new(100).ok_or(Error::InvalidInput)?,
        CoveragePolicy::ObservedOnly,
        None,
    )?;
    let window = Interval::new(Timestamp::new(0)?, Timestamp::new(200)?)?;
    maintain(
        reopened,
        operator,
        "refresh",
        MaintenanceAction::Recompute {
            spec: spec.clone(),
            window,
        },
    )
    .await?;
    maintain(
        reopened,
        operator,
        "delete",
        MaintenanceAction::Delete {
            selection: spec.selection(),
            window,
            restore_until: receipt.replay_until(),
        },
    )
    .await?;
    let hidden = Query::new(
        spec.selection(),
        window,
        QueryBudget {
            max_points: NonZeroU32::MIN,
            max_series: NonZeroU32::MIN,
        },
        QueryMode::Latest,
    )?;
    anyhow::ensure!(
        reopened
            .query(
                &Authorized::<Query>::verify(operator, hidden)?,
                None,
                budget()?
            )
            .await?
            .rows
            .is_empty(),
        "deleted data visible"
    );
    maintain(
        reopened,
        operator,
        "restore",
        MaintenanceAction::Restore {
            selection: spec.selection(),
            window,
            deletion_fence: Id::new("delete")?,
        },
    )
    .await?;
    maintain(
        reopened,
        operator,
        "refresh-restored",
        MaintenanceAction::Recompute {
            spec: spec.clone(),
            window,
        },
    )
    .await?;
    maintain(
        reopened,
        operator,
        "cutoff",
        MaintenanceAction::AdvanceCutoff {
            selection: spec.selection(),
            before: window.end(),
        },
    )
    .await?;
    maintain(
        reopened,
        operator,
        "prune",
        MaintenanceAction::Prune {
            selection: spec.selection(),
            raw_before: window.end(),
            summaries_before: Timestamp::new(0)?,
        },
    )
    .await?;
    let q = AggregateQuery::new(
        spec,
        window,
        QueryBudget {
            max_points: NonZeroU32::new(10).ok_or(Error::InvalidInput)?,
            max_series: NonZeroU32::MIN,
        },
        AggregateOp::Mean,
    )?;
    let aggregated = reopened
        .aggregate(
            &Authorized::<AggregateQuery>::verify(operator, q)?,
            None,
            budget()?,
        )
        .await?;
    anyhow::ensure!(
        aggregated.refreshed_through == Some(window.end())
            && aggregated
                .buckets
                .iter()
                .any(|b| matches!(b.value,AggregateValue::Mean {count,..} if count.get()==1)),
        "retained summary missing"
    );
    Ok(())
}
