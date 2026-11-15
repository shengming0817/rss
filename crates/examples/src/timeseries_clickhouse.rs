//! Public consumption of the single ClickHouse/PG profile; products own provisioning.
use rss_request_context::{Clock, Deadline, TenantId};
use rss_timeseries::*;
use rss_timeseries_clickhouse::{
    ChOwner, ChStore, ConnectionConfig, Credentials, CursorKey, Limits,
};
use std::{
    num::{NonZeroU32, NonZeroU64},
    time::{Duration, Instant},
};
#[derive(serde::Deserialize)]
pub struct Input {
    #[serde(flatten)]
    pub pg: crate::pg::Input,
    pub endpoint: String,
    pub ch_ca: String,
    pub reader: String,
    pub other_tenant: String,
    pub other_reader: String,
    pub writer: String,
    pub maintenance: String,
    pub ch_password: String,
    pub cursor_key: [u8; 32],
}
struct Timer;
impl Clock for Timer {
    #[allow(clippy::disallowed_methods)] // reason: explicit concrete clock supplied by the example host.
    fn now(&self) -> Instant {
        Instant::now()
    }
}
struct Product(TenantId);
impl Authority for Product {
    fn authorize(&self, a: Access<'_>) -> Result<(), Error> {
        let scope = match a {
            Access::Definition(DefinitionMutation::Register { definition, .. }) => {
                &definition.spec().scope
            }
            Access::Write(b) => b.stream().scope(),
            Access::Receipt(q) => q.stream.scope(),
            Access::Query(q) => q.selection().scope(),
            Access::Aggregate(q) => q.spec().stream().scope(),
            Access::Maintain(r) => r.scope(),
            _ => return Err(Error::Unauthorized),
        };
        if scope.tenant() == self.0 {
            Ok(())
        } else {
            Err(Error::Unauthorized)
        }
    }
}
fn deadline() -> anyhow::Result<Deadline> {
    Ok(Deadline::from_timeout(&Timer, Duration::from_secs(20))?)
}
pub async fn run(input: Input) -> anyhow::Result<()> {
    let tenant = TenantId::parse(&input.pg.tenant)?;
    let credentials = |user: String| Credentials::new(user, input.ch_password.clone());
    let config = ConnectionConfig::new(
        &input.endpoint,
        input.ch_ca.as_bytes(),
        credentials(input.writer)?,
        credentials(input.maintenance)?,
    )?;
    let n = |v| NonZeroU32::new(v).ok_or(Error::InvalidInput);
    let m = |v| NonZeroU64::new(v).ok_or(Error::InvalidInput);
    let limits = Limits {
        max_concurrent_operations: n(4)?,
        max_points: n(100)?,
        max_series: n(10)?,
        max_bytes: n(1048576)?,
        max_scan_rows: m(100000)?,
        max_scan_bytes: m(16777216)?,
        max_memory_bytes: m(67108864)?,
        replay_micros: m(60000000)?,
        cursor_micros: m(60000000)?,
    };
    let owner = ChOwner::new(input.pg.pool().await?, config, Timer, limits, deadline()?).await?;
    let store = owner
        .bind_tenant(
            tenant,
            credentials(input.reader)?,
            CursorKey::new(input.cursor_key),
            m(1)?,
            deadline()?,
        )
        .await?;
    let query = exercise(&store, tenant).await?;
    let other_tenant = TenantId::parse(&input.other_tenant)?;
    anyhow::ensure!(other_tenant != tenant, "two distinct tenant identities");
    let other = owner
        .bind_tenant(
            other_tenant,
            credentials(input.other_reader)?,
            CursorKey::new([43; 32]),
            m(1)?,
            deadline()?,
        )
        .await?;
    let other_query = exercise(&other, other_tenant).await?;
    anyhow::ensure!(
        matches!(
            store.query(&other_query, None, deadline()?).await,
            Err(Error::Unauthorized)
        ),
        "tenant capability mismatch"
    );
    other.retire(deadline()?).await?;
    anyhow::ensure!(
        store.query(&query, None, deadline()?).await?.rows.len() == 1,
        "retiring another tenant preserves the installation"
    );
    owner.close(deadline()?).await?;
    Ok(())
}
async fn exercise(store: &ChStore<Timer>, tenant: TenantId) -> anyhow::Result<Authorized<Query>> {
    let product = Product(tenant);
    let n = |v| NonZeroU32::new(v).ok_or(Error::InvalidInput);
    let d = Definition::new(DefinitionSpec {
        scope: Scope::new(tenant, Id::new("example")?),
        key: Id::new("custom.counter")?,
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
    let definition = Authorized::<DefinitionMutation>::verify(
        &product,
        DefinitionMutation::Register {
            definition: d.clone(),
            expected_latest: None,
        },
    )?;
    anyhow::ensure!(
        !matches!(
            store.change(&definition, deadline()?).await?,
            Outcome::Unknown
        ),
        "unknown definition"
    );
    let stream = Stream::new(
        d.spec().scope.clone(),
        Id::new("producer")?,
        Id::new("generation")?,
    );
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
        sequence: 1,
        observed_at: Timestamp::new(10)?,
        interval: None,
        reading: Reading::Valid(Value::Number(Number::U64(u64::MAX))),
    })?;
    let batch = Batch::new(stream.clone(), Id::new("batch")?, vec![sample])?;
    let batch = Authorized::<Batch>::verify(&product, batch)?;
    anyhow::ensure!(
        matches!(
            store.write(&batch, deadline()?).await?,
            Outcome::Accepted(_)
        ),
        "unconfirmed batch"
    );
    anyhow::ensure!(
        matches!(store.write(&batch, deadline()?).await?, Outcome::Replay(_)),
        "same-ID replay"
    );
    let query = Authorized::<Query>::verify(
        &product,
        Query::new(
            Selection::Exact { stream, series },
            Interval::new(Timestamp::new(0)?, Timestamp::new(100)?)?,
            QueryBudget {
                max_points: n(10)?,
                max_series: n(1)?,
            },
            QueryMode::History,
        )?,
    )?;
    let page = store.query(&query, None, deadline()?).await?;
    anyhow::ensure!(page.rows.len() == 1, "deduplicated raw visibility");
    anyhow::ensure!(
        matches!(
            page.rows[0].sample.input().reading,
            Reading::Valid(Value::Number(Number::U64(u64::MAX)))
        ),
        "exact unsigned integer roundtrip"
    );
    Ok(query)
}
