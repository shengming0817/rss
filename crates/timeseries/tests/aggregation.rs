use rss_request_context::TenantId;
use rss_timeseries::*;
use std::num::NonZeroU64;
fn n(v: u64) -> anyhow::Result<NonZeroU64> {
    NonZeroU64::new(v).ok_or_else(|| anyhow::anyhow!("positive"))
}
fn t(v: i64) -> anyhow::Result<Timestamp> {
    Ok(Timestamp::new(v)?)
}
fn w(a: i64, b: i64) -> anyhow::Result<Interval> {
    Ok(Interval::new(t(a)?, t(b)?)?)
}
fn spec(metric: Metric, coverage: CoveragePolicy) -> anyhow::Result<SummarySpec> {
    let scope = Scope::new(
        TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479")?,
        Id::new("test")?,
    );
    let counter = matches!(metric, Metric::Counter { .. });
    let d = Definition::new(DefinitionSpec {
        scope: scope.clone(),
        key: Id::new("metric")?,
        version: 1,
        unit: Id::new("unit")?,
        metric,
        dimensions: DimensionRules {
            allowed: Default::default(),
            required: Default::default(),
            max_count: 0,
            max_value_bytes: 256,
            max_total_bytes: 32768,
        },
    })?;
    Ok(SummarySpec::new(
        Stream::new(scope, Id::new("source")?, Id::new("generation")?),
        Series::new(
            d,
            Id::new("device")?,
            Id::new("resource")?,
            Default::default(),
        )?,
        n(10)?,
        coverage,
        if counter { Some(n(10)?) } else { None },
    )?)
}
fn sample(
    s: &SummarySpec,
    at: i64,
    reading: Reading,
    start: Option<i64>,
) -> anyhow::Result<Sample> {
    Ok(Sample::new(SampleInput {
        stream: s.stream().clone(),
        series: s.series().clone(),
        id: Id::new(format!("p{at}"))?,
        sequence: at as u64,
        observed_at: t(at)?,
        interval: start.map(|a| w(a, at)).transpose()?,
        reading,
    })?)
}
fn value(v: u64) -> Reading {
    Reading::Valid(Value::Number(Number::U64(v)))
}
#[test]
fn unequal_bucket_means_and_large_integer_statistics() -> anyhow::Result<()> {
    let s = spec(
        Metric::Gauge {
            number: NumberKind::U64,
        },
        CoveragePolicy::ObservedOnly,
    )?;
    let input = [
        sample(&s, 1, value(u64::MAX), None)?,
        sample(&s, 2, value(1), None)?,
        sample(&s, 11, value(9), None)?,
    ];
    let a = Summary::compute(&s, w(0, 10)?, &input[..2], 10)?;
    let b = Summary::compute(&s, w(10, 20)?, &input[2..], 10)?;
    let merged = a.merge(b, 10)?.project(AggregateOp::Mean)?;
    let direct = Summary::compute(&s, w(0, 20)?, &input, 10)?.project(AggregateOp::Mean)?;
    for v in [merged.value, direct.value] {
        match v {
            AggregateValue::Mean {
                sum: Sum::U128(v),
                count,
            } => {
                assert_eq!(v, u128::from(u64::MAX) + 10);
                assert_eq!(count.get(), 3)
            }
            _ => anyhow::bail!("mean"),
        }
    }
    assert!(matches!(
        Summary::compute(&s, w(20, 30)?, &[], 10)?
            .project(AggregateOp::Count)?
            .value,
        AggregateValue::Missing
    ));
    Ok(())
}
#[test]
fn cumulative_reset_gap_and_boundary_rollup() -> anyhow::Result<()> {
    let s = spec(
        Metric::Counter {
            number: NumberKind::U64,
            temporality: Temporality::Cumulative,
        },
        CoveragePolicy::ObservedOnly,
    )?;
    let input = [
        sample(&s, 1, value(5), Some(0))?,
        sample(&s, 6, value(9), Some(0))?,
        sample(&s, 11, value(15), Some(0))?,
        sample(&s, 15, value(2), Some(15))?,
        sample(&s, 29, value(20), Some(15))?,
    ];
    let a = Summary::compute(&s, w(0, 10)?, &input[..2], 20)?;
    let b = Summary::compute(&s, w(10, 20)?, &input[1..4], 20)?;
    let v = a.merge(b, 20)?.project(AggregateOp::Rate)?;
    assert!(
        matches!(v.value,AggregateValue::Rate {increase:Sum::U128(10),duration_micros} if duration_micros.get()==10)
    );
    assert!(v.completeness.contains(&Completeness::ResetBoundary));
    let gap = Summary::compute(&s, w(20, 30)?, &input[3..], 20)?.project(AggregateOp::Increase)?;
    assert!(matches!(gap.value, AggregateValue::Missing));
    assert!(gap.completeness.contains(&Completeness::Gaps));
    Ok(())
}
#[test]
fn delta_overlap_is_not_a_plausible_rate() -> anyhow::Result<()> {
    let s = spec(
        Metric::Counter {
            number: NumberKind::U64,
            temporality: Temporality::Delta,
        },
        CoveragePolicy::ObservedOnly,
    )?;
    let input = [
        sample(&s, 5, value(10), Some(0))?,
        sample(&s, 9, value(12), Some(3))?,
    ];
    let v = Summary::compute(&s, w(0, 10)?, &input, 10)?.project(AggregateOp::Rate)?;
    assert!(matches!(v.value, AggregateValue::Missing));
    assert!(v.completeness.contains(&Completeness::Overlap));
    Ok(())
}
#[test]
fn state_hold_stops_at_missing_and_never_invents_online_time() -> anyhow::Result<()> {
    let s = spec(Metric::Bool, CoveragePolicy::HoldLast(n(5)?))?;
    let input = [
        sample(&s, 1, Reading::Valid(Value::Bool(true)), None)?,
        sample(&s, 3, Reading::Missing, None)?,
        sample(&s, 9, Reading::Valid(Value::Bool(false)), None)?,
    ];
    let v = Summary::compute(&s, w(0, 20)?, &input, 10)?.project(AggregateOp::Coverage)?;
    assert_eq!(v.covered_micros, 7);
    assert!(v.completeness.contains(&Completeness::Gaps));
    let AggregateValue::StateCoverage(d) = v.value else {
        anyhow::bail!("coverage")
    };
    assert_eq!(d[0].micros, 2);
    assert_eq!(d[1].micros, 5);
    assert!(
        matches!(Summary::compute(&s,w(0,20)?,&input,10)?.project(AggregateOp::Transitions)?.value,AggregateValue::Transitions(v) if v.is_empty())
    );
    Ok(())
}
#[test]
fn invalid_order_and_output_budget_fail_closed() -> anyhow::Result<()> {
    let s = spec(Metric::Bool, CoveragePolicy::ObservedOnly)?;
    let a = sample(&s, 1, Reading::Valid(Value::Bool(true)), None)?;
    let b = sample(&s, 2, Reading::Valid(Value::Bool(false)), None)?;
    assert!(Summary::compute(&s, w(0, 10)?, &[b.clone(), a.clone()], 10).is_err());
    assert!(Summary::compute(&s, w(0, 10)?, &[a, b], 2).is_err());
    Ok(())
}

#[test]
fn serialized_fold_resumes_large_gauge_and_same_time_state_without_recounting() -> anyhow::Result<()>
{
    let s = spec(
        Metric::Gauge {
            number: NumberKind::U64,
        },
        CoveragePolicy::ObservedOnly,
    )?;
    let mut fold = SummaryBuilder::new(s.clone(), w(0, 1000)?)?;
    for at in 0..1000 {
        fold.push(sample(&s, at, value(1), None)?, 2)?;
        if at % 17 == 0 {
            fold = serde_json::from_slice(&serde_json::to_vec(&fold)?)?;
        }
    }
    assert!(
        matches!(fold.finish(2)?.project(AggregateOp::Mean)?.value,AggregateValue::Mean {sum:Sum::U128(1000),count} if count.get()==1000)
    );
    let s = spec(Metric::Bool, CoveragePolicy::HoldLast(n(10)?))?;
    let a = sample(&s, 1, Reading::Valid(Value::Bool(true)), None)?;
    let mut changed = a.input().clone();
    changed.sequence += 1;
    changed.id = Id::new("replacement")?;
    changed.reading = Reading::Valid(Value::Bool(false));
    let mut fold = SummaryBuilder::new(s, w(0, 10)?)?;
    fold.push(a, 10)?;
    fold = serde_json::from_slice(&serde_json::to_vec(&fold)?)?;
    fold.push(Sample::new(changed)?, 10)?;
    let v = fold.finish(10)?.project(AggregateOp::Coverage)?;
    assert_eq!(v.valid_samples, 1);
    assert_eq!(v.covered_micros, 9);
    Ok(())
}
