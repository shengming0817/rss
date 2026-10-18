//! The same public behavior runs in the workspace and isolated source/artifact consumers.
use rss_request_context::TenantId;
use rss_timeseries::*;
use std::collections::{BTreeMap, BTreeSet};

fn main() -> anyhow::Result<()> {
    run()?;
    println!("timeseries public behavior PASS");
    Ok(())
}
fn run() -> anyhow::Result<()> {
    let scope = Scope::new(
        TenantId::parse("11111111-1111-4111-8111-111111111111")?,
        Id::new("custom")?,
    );
    let definition = Definition::new(DefinitionSpec {
        scope: scope.clone(),
        key: Id::new("acme.bytes_processed")?,
        version: 1,
        unit: Id::new("By")?,
        metric: Metric::Counter {
            number: NumberKind::U64,
            temporality: Temporality::Cumulative,
        },
        dimensions: DimensionRules {
            allowed: BTreeSet::from([Id::new("volume")?]),
            required: BTreeSet::new(),
            max_count: 1,
            max_value_bytes: 64,
            max_total_bytes: 128,
        },
    })?;
    let stream = Stream::new(scope, Id::new("collector")?, Id::new("boot-42")?);
    let series = Series::new(
        definition.clone(),
        Id::new("subject")?,
        Id::new("resource")?,
        BTreeMap::from([(Id::new("volume")?, Id::new("data")?)]),
    )?;
    let sample = Sample::new(SampleInput {
        stream: stream.clone(),
        series,
        id: Id::new("sample-1")?,
        sequence: 1,
        observed_at: Timestamp::new(1_000_000)?,
        interval: Some(Interval::new(
            Timestamp::new(0)?,
            Timestamp::new(1_000_000)?,
        )?),
        reading: Reading::Valid(Value::Number(Number::U64(u64::MAX))),
    })?;
    let batch = Batch::new(stream.clone(), Id::new("batch-1")?, vec![sample.clone()])?;
    let decoded = Batch::decode(&batch.encode()?)?;
    anyhow::ensure!(decoded == batch && decoded.digest()? == batch.digest()?);
    anyhow::ensure!(batch.compare(&decoded)? == IdentityMatch::Replay);
    let another = Batch::new(stream, Id::new("batch-2")?, vec![sample.clone()])?;
    anyhow::ensure!(another.samples()[0].compare(&sample)? == IdentityMatch::Replay);
    let mut changed = sample.input().clone();
    changed.reading = Reading::Valid(Value::Number(Number::U64(0)));
    anyhow::ensure!(Sample::new(changed)?.compare(&sample) == Err(Error::Conflict));
    let mut next = definition.spec().clone();
    next.version = 2;
    next.unit = Id::new("KiBy")?;
    anyhow::ensure!(
        Definition::new(next)?.compare(&definition) == Err(Error::IncompatibleDefinition)
    );
    anyhow::ensure!(DefinitionState::Retired.admit(false) == Err(Error::Retired));
    DefinitionState::Retired.admit(true)?;
    anyhow::ensure!(
        AggregateOp::Sum.validate(&definition.spec().metric) == Err(Error::Unsupported)
    );
    Ok(())
}
#[test]
fn public_behavior() -> anyhow::Result<()> {
    run()
}
