use rss_request_context::TenantId;
use rss_timeseries::*;
use std::collections::{BTreeMap, BTreeSet};
use std::num::{NonZeroU32, NonZeroU64};
use std::time::{Duration, SystemTime};

type TestResult = anyhow::Result<()>;
fn id(s: &str) -> anyhow::Result<Id> {
    Ok(Id::new(s)?)
}
fn tenant() -> anyhow::Result<TenantId> {
    Ok(TenantId::parse("11111111-1111-4111-8111-111111111111")?)
}
fn scope() -> anyhow::Result<Scope> {
    Ok(Scope::new(tenant()?, id("telemetry")?))
}
fn stream() -> anyhow::Result<Stream> {
    Ok(Stream::new(scope()?, id("collector")?, id("boot-1")?))
}
fn ts(n: i64) -> anyhow::Result<Timestamp> {
    Ok(Timestamp::new(n)?)
}
fn definition(metric: Metric) -> anyhow::Result<Definition> {
    Ok(Definition::new(DefinitionSpec {
        scope: scope()?,
        key: id("custom.measurement")?,
        version: 1,
        unit: id("1")?,
        metric,
        dimensions: DimensionRules {
            allowed: BTreeSet::from([id("core")?]),
            required: BTreeSet::new(),
            max_count: 1,
            max_value_bytes: 16,
            max_total_bytes: 64,
        },
    })?)
}
fn sample(metric: Metric, reading: Reading, n: i64) -> anyhow::Result<Sample> {
    Ok(Sample::new(SampleInput {
        stream: stream()?,
        series: Series::new(
            definition(metric)?,
            id("subject")?,
            id("resource")?,
            BTreeMap::new(),
        )?,
        id: id("sample-1")?,
        sequence: 1,
        observed_at: ts(n)?,
        interval: Some(Interval::new(ts(0)?, ts(n)?)?),
        reading,
    })?)
}
fn gauge(n: i64) -> anyhow::Result<Sample> {
    sample(
        Metric::Gauge {
            number: NumberKind::U64,
        },
        Reading::Valid(Value::Number(Number::U64(u64::MAX))),
        n,
    )
}
fn batch(samples: Vec<Sample>) -> anyhow::Result<Batch> {
    Ok(Batch::new(stream()?, id("batch-1")?, samples)?)
}
fn nz(n: u64) -> anyhow::Result<NonZeroU64> {
    NonZeroU64::new(n).ok_or_else(|| anyhow::anyhow!("zero fixture"))
}
fn budget() -> anyhow::Result<QueryBudget> {
    let n = NonZeroU32::new(2).ok_or_else(|| anyhow::anyhow!("zero fixture"))?;
    Ok(QueryBudget {
        max_series: n,
        max_points: n,
    })
}
fn query(mode: QueryMode) -> anyhow::Result<Query> {
    Ok(Query::new(
        Selection::Exact {
            stream: stream()?,
            series: gauge(1)?.input().series.clone(),
        },
        Interval::new(ts(0)?, ts(10)?)?,
        budget()?,
        mode,
    )?)
}

#[test]
fn values_preserve_precision_and_reject_invalid_construction_and_decode() -> TestResult {
    for v in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
        assert_eq!(FiniteF64::new(v), Err(Error::NumericRange));
    }
    assert_eq!(FiniteF64::new(-0.0)?.get().to_bits(), 0.0f64.to_bits());
    assert!(Timestamp::new(-1).is_err());
    assert!(Timestamp::from_system_time(SystemTime::UNIX_EPOCH + Duration::from_nanos(1)).is_err());
    assert!(Timestamp::from_system_time(SystemTime::UNIX_EPOCH - Duration::from_secs(1)).is_err());
    assert_eq!(
        Timestamp::from_system_time(ts(1)?.to_system_time()?)?,
        ts(1)?
    );
    assert!(
        Timestamp::from_system_time(SystemTime::UNIX_EPOCH + Duration::from_secs(i64::MAX as u64))
            .is_err()
    );
    assert_eq!(Timestamp::new(i64::MAX)?.micros(), i64::MAX);
    Ok(())
}

#[test]
fn invalid_values_cannot_enter_through_decode() -> TestResult {
    for value in ["", "\n", &"x".repeat(257)] {
        assert!(Id::new(value).is_err());
    }
    assert!(serde_json::from_str::<Id>("\"\"").is_err());
    assert!(serde_json::from_str::<Timestamp>("-1").is_err());
    assert!(serde_json::from_str::<FiniteF64>("1e999").is_err());
    assert!(
        serde_json::from_str::<Number>(r#"{"type":"u64","value":18446744073709551616}"#).is_err()
    );
    Ok(())
}

#[test]
fn numeric_extremes_roundtrip_without_coercion() -> TestResult {
    for number in [
        Number::I64(i64::MIN),
        Number::I64(i64::MAX),
        Number::U64(u64::MAX),
        Number::F64(FiniteF64::new(f64::MAX)?),
    ] {
        let s = sample(
            Metric::Gauge {
                number: number.kind(),
            },
            Reading::Valid(Value::Number(number)),
            1,
        )?;
        let b = batch(vec![s])?;
        assert_eq!(Batch::decode(&b.encode()?)?, b);
    }
    Ok(())
}

#[test]
fn definitions_have_one_immutable_version_and_monotonic_extensions() -> TestResult {
    let d = definition(Metric::State {
        members: BTreeSet::from([id("on")?]),
    })?;
    assert_eq!(d.compare(&d)?, DefinitionChange::Replay);
    let mut spec = d.spec().clone();
    spec.unit = id("seconds")?;
    assert_eq!(
        Definition::new(spec.clone())?.compare(&d),
        Err(Error::Conflict)
    );
    spec.version = 2;
    assert_eq!(
        Definition::new(spec)?.compare(&d),
        Err(Error::IncompatibleDefinition)
    );
    let mut spec = d.spec().clone();
    spec.version = 2;
    spec.metric = Metric::State {
        members: BTreeSet::from([id("on")?, id("off")?]),
    };
    spec.dimensions.allowed.insert(id("socket")?);
    spec.dimensions.max_count = 2;
    let next = Definition::new(spec.clone())?;
    assert_eq!(next.compare(&d)?, DefinitionChange::CompatibleVersion);
    assert_ne!(d.digest()?, next.digest()?);
    assert_eq!(d.compare(&next), Err(Error::IncompatibleDefinition));
    spec.metric = Metric::State {
        members: BTreeSet::from([id("off")?]),
    };
    assert_eq!(
        Definition::new(spec)?.compare(&d),
        Err(Error::IncompatibleDefinition)
    );
    let mut spec = d.spec().clone();
    spec.version = 0;
    assert_eq!(Definition::new(spec), Err(Error::InvalidInput));
    assert!(
        definition(Metric::State {
            members: BTreeSet::new()
        })
        .is_err()
    );
    let mut spec = d.spec().clone();
    spec.key = id("different")?;
    assert_eq!(Definition::new(spec)?.compare(&d), Err(Error::InvalidInput));
    DefinitionState::Active.admit(false)?;
    DefinitionState::Retired.admit(true)?;
    assert_eq!(DefinitionState::Retired.admit(false), Err(Error::Retired));
    // Keeping the original exact definition needs no compatibility alias or upgrade.
    assert_eq!(
        serde_json::from_slice::<Definition>(&serde_json::to_vec(&d)?)?,
        d
    );
    Ok(())
}

#[test]
fn dimensions_are_whitelisted_bounded_and_canonical() -> TestResult {
    let d = definition(Metric::Bool)?;
    let mk = |m| Series::new(d.clone(), Id::new("s")?, Id::new("r")?, m);
    assert!(mk(BTreeMap::from([(id("unknown")?, id("v")?)])).is_err());
    assert_eq!(
        mk(BTreeMap::from([(id("core")?, id(&"v".repeat(17))?)])),
        Err(Error::BudgetExceeded)
    );
    let mut spec = d.spec().clone();
    spec.dimensions.required.insert(id("core")?);
    assert!(Series::new(Definition::new(spec)?, id("s")?, id("r")?, BTreeMap::new()).is_err());
    let mut spec = d.spec().clone();
    spec.dimensions.max_count = 65;
    assert!(Definition::new(spec).is_err());
    let mut spec = d.spec().clone();
    spec.dimensions.max_total_bytes = 4;
    assert!(
        Series::new(
            Definition::new(spec)?,
            id("s")?,
            id("r")?,
            BTreeMap::from([(id("core")?, id("1")?)])
        )
        .is_err()
    );
    let a = mk(BTreeMap::from([(id("core")?, id("1")?)]))?;
    assert_eq!(
        a.digest()?,
        serde_json::from_slice::<Series>(&serde_json::to_vec(&a)?)?.digest()?
    );
    Ok(())
}

#[test]
fn counter_and_state_semantics_cannot_be_bypassed() -> TestResult {
    let counter = Metric::Counter {
        number: NumberKind::I64,
        temporality: Temporality::Delta,
    };
    assert!(
        sample(
            counter.clone(),
            Reading::Valid(Value::Number(Number::I64(-1))),
            1
        )
        .is_err()
    );
    assert!(
        sample(
            counter.clone(),
            Reading::Valid(Value::Number(Number::U64(1))),
            1
        )
        .is_err()
    );
    assert!(sample(counter.clone(), Reading::Missing, 0).is_err());
    let mut input = sample(counter.clone(), Reading::Missing, 1)?
        .input()
        .clone();
    input.interval = None;
    assert!(Sample::new(input).is_err());
    sample(
        Metric::Counter {
            number: NumberKind::I64,
            temporality: Temporality::Cumulative,
        },
        Reading::Valid(Value::Number(Number::I64(0))),
        0,
    )?;
    assert!(
        sample(
            Metric::Bool,
            Reading::Valid(Value::Number(Number::I64(0))),
            1
        )
        .is_err()
    );
    assert!(
        sample(
            Metric::State {
                members: BTreeSet::from([id("on")?])
            },
            Reading::Valid(Value::State(id("unknown")?)),
            1
        )
        .is_err()
    );
    let zero = sample(Metric::Bool, Reading::Valid(Value::Bool(false)), 1)?;
    let missing = sample(Metric::Bool, Reading::Missing, 1)?;
    let failed = sample(Metric::Bool, Reading::Failed, 1)?;
    assert_ne!(zero.digest()?, missing.digest()?);
    assert_ne!(failed.digest()?, missing.digest()?);
    let b = batch(vec![sample(
        counter,
        Reading::Valid(Value::Number(Number::I64(1))),
        1,
    )?])?;
    let raw = String::from_utf8(b.encode()?)?.replace("\"value\":1", "\"value\":-1");
    assert!(Batch::decode(raw.as_bytes()).is_err());
    Ok(())
}

#[test]
fn stable_identity_and_batch_order_cover_cross_batch_conflicts() -> TestResult {
    let a = gauge(1)?;
    assert_eq!(a.compare(&a)?, IdentityMatch::Replay);
    assert_eq!(gauge(2)?.compare(&a), Err(Error::Conflict));
    let mut input = a.input().clone();
    input.id = id("sample-2")?;
    let b = Sample::new(input.clone())?;
    assert_eq!(a.compare(&b)?, IdentityMatch::Distinct);
    let first = batch(vec![a.clone(), b.clone()])?;
    let reversed = batch(vec![b.clone(), a.clone()])?;
    assert_eq!(first.compare(&reversed), Err(Error::Conflict));
    assert_ne!(first.digest()?, reversed.digest()?);
    assert_eq!(
        first.compare(&Batch::decode(&first.encode()?)?)?,
        IdentityMatch::Replay
    );
    assert!(batch(vec![a.clone(), a.clone()]).is_err());
    assert!(batch(Vec::new()).is_err());
    assert!(batch(vec![a.clone(); Batch::MAX_SAMPLES + 1]).is_err());
    assert!(Batch::decode(&vec![b' '; Batch::MAX_BYTES + 1]).is_err());
    Ok(())
}

#[test]
fn cross_batch_replay_and_stream_isolation() -> TestResult {
    let a = gauge(1)?;
    let first = batch(vec![a.clone()])?;
    let mut input = a.input().clone();
    input.id = id("sample-2")?;
    let b = Sample::new(input.clone())?;
    let other_batch = Batch::new(stream()?, id("batch-2")?, vec![a.clone()])?;
    assert_eq!(first.compare(&other_batch)?, IdentityMatch::Distinct);
    assert_eq!(other_batch.samples()[0].compare(&a)?, IdentityMatch::Replay);
    input.stream = Stream::new(scope()?, id("collector")?, id("boot-2")?);
    let different_generation = Sample::new(input)?;
    assert_eq!(different_generation.compare(&b)?, IdentityMatch::Distinct);
    assert!(batch(vec![different_generation]).is_err());
    let mut input = a.input().clone();
    input.stream = Stream::new(
        Scope::new(
            TenantId::parse("22222222-2222-4222-8222-222222222222")?,
            id("telemetry")?,
        ),
        id("collector")?,
        id("boot-1")?,
    );
    assert!(Sample::new(input).is_err());
    let mut input = a.input().clone();
    input.interval = Some(Interval::new(ts(0)?, ts(2)?)?);
    assert!(Sample::new(input).is_err());
    assert!(Interval::new(ts(2)?, ts(1)?).is_err());
    Ok(())
}

#[test]
fn query_bounds_order_latest_and_continuation_are_explicit() -> TestResult {
    let q = query(QueryMode::History)?;
    assert!(q.matches(&gauge(0)?));
    assert!(!q.matches(&gauge(10)?));
    let row = |n| -> anyhow::Result<ObservedSample> {
        Ok(ObservedSample {
            sample: gauge(n)?,
            received_at: ts(50)?,
        })
    };
    q.validate_page(&[row(1)?, row(2)?])?;
    assert!(q.validate_page(&[row(2)?, row(1)?]).is_err());
    assert!(q.validate_page(&[row(1)?, row(2)?, row(3)?]).is_err());
    assert!(q.validate_page(&[row(10)?]).is_err());
    assert!(
        query(QueryMode::Latest)?
            .validate_page(&[row(1)?, row(2)?])
            .is_err()
    );
    assert!(gauge(2)?.latest_cmp(&gauge(1)?)?.is_gt());
    assert!(
        gauge(1)?
            .latest_cmp(&sample(Metric::Bool, Reading::Missing, 1)?)
            .is_err()
    );
    let token = Continuation::new(q.binding()?, rss_contract::PageCursor::parse("YQ")?);
    token.verify(q.binding()?)?;
    assert!(token.verify(query(QueryMode::Latest)?.binding()?).is_err());
    let resource = Selection::Resource {
        scope: scope()?,
        subject: id("subject")?,
        resource: id("resource")?,
        keys: BTreeSet::from([id("custom.measurement")?]),
    };
    assert!(resource.matches(&gauge(1)?));
    Query::new(resource.clone(), q.window(), budget()?, QueryMode::History)?;
    assert!(
        Query::new(
            resource,
            Interval::new(ts(1)?, ts(1)?)?,
            budget()?,
            QueryMode::History
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn aggregate_matrix_and_exact_statistics() -> TestResult {
    let q = query(QueryMode::History)?;
    AggregateQuery::new(
        q.clone(),
        AggregateOp::Mean,
        nz(1)?,
        CoveragePolicy::ObservedOnly,
    )?;
    assert!(
        AggregateQuery::new(
            q.clone(),
            AggregateOp::Rate,
            nz(1)?,
            CoveragePolicy::ObservedOnly
        )
        .is_err()
    );
    assert!(
        AggregateQuery::new(
            q.clone(),
            AggregateOp::Mean,
            nz(11)?,
            CoveragePolicy::ObservedOnly
        )
        .is_err()
    );
    assert!(
        AggregateQuery::new(
            q,
            AggregateOp::Mean,
            nz(1)?,
            CoveragePolicy::HoldLast(nz(1)?)
        )
        .is_err()
    );
    let cumulative = Metric::Counter {
        number: NumberKind::U64,
        temporality: Temporality::Cumulative,
    };
    assert!(AggregateOp::Sum.validate(&cumulative).is_err());
    AggregateOp::Increase.validate(&cumulative)?;
    AggregateOp::Rate.validate(&cumulative)?;
    let delta = Metric::Counter {
        number: NumberKind::U64,
        temporality: Temporality::Delta,
    };
    AggregateOp::Sum.validate(&delta)?;
    AggregateOp::Rate.validate(&delta)?;
    assert!(AggregateOp::Mean.validate(&delta).is_err());
    for op in [
        AggregateOp::Timeline,
        AggregateOp::Transitions,
        AggregateOp::Coverage,
    ] {
        op.validate(&Metric::Bool)?;
    }
    assert!(AggregateOp::Mean.validate(&Metric::Bool).is_err());
    assert_eq!(
        Sum::U128(u64::MAX as u128).checked_add(Sum::U128(1))?,
        Sum::U128(u64::MAX as u128 + 1)
    );
    assert!(Sum::U128(u128::MAX).checked_add(Sum::U128(1)).is_err());
    assert!(Sum::I128(i128::MAX).checked_add(Sum::I128(1)).is_err());
    assert!(
        Sum::F64(FiniteF64::new(f64::MAX)?)
            .checked_add(Sum::F64(FiniteF64::new(f64::MAX)?))
            .is_err()
    );
    assert!(Sum::I128(0).checked_add(Sum::U128(0)).is_err());
    for kind in [NumberKind::I64, NumberKind::U64, NumberKind::F64] {
        Sum::zero(kind)?;
    }
    Ok(())
}

struct Deny;
impl Authority for Deny {
    fn authorize(&self, _: Access<'_>) -> Result<(), Error> {
        Err(Error::Unauthorized)
    }
}
struct Product;
impl Authority for Product {
    fn authorize(&self, access: Access<'_>) -> Result<(), Error> {
        match access {
            Access::Write(b) if b.stream().scope().namespace().as_str() == "telemetry" => Ok(()),
            _ => Err(Error::Unauthorized),
        }
    }
}
#[test]
fn authorization_receipt_and_maintenance_do_not_invent_guarantees() -> TestResult {
    let b = batch(vec![gauge(1)?])?;
    assert!(Authorized::<Batch>::verify(&Deny, b.clone()).is_err());
    let authorized = Authorized::<Batch>::verify(&Product, b.clone())?;
    assert_eq!(authorized.request().digest()?, b.digest()?);
    let snapshot = ReceiptSnapshot {
        identity: ReceiptQuery {
            stream: b.stream().clone(),
            batch_id: b.id().clone(),
            digest: b.digest()?,
        },
        received_at: ts(10)?,
        new_samples: 1,
        replayed_samples: 0,
        replay_until: ts(100)?,
    };
    let receipt = Receipt::from_durable(snapshot.clone())?;
    assert_eq!(receipt.identity().digest, b.digest()?);
    assert_eq!(receipt.received_at(), ts(10)?);
    assert_eq!(receipt.new_samples() + receipt.replayed_samples(), 1);
    assert_eq!(receipt.replay_until(), ts(100)?);
    for (new_samples, replayed_samples) in [(0, 0), (4097, 0), (u32::MAX, 1)] {
        assert!(
            Receipt::from_durable(ReceiptSnapshot {
                new_samples,
                replayed_samples,
                ..snapshot.clone()
            })
            .is_err()
        );
    }
    assert!(
        Receipt::from_durable(ReceiptSnapshot {
            replay_until: ts(10)?,
            ..snapshot
        })
        .is_err()
    );
    assert_eq!(b.digest()?, batch(vec![gauge(1)?])?.digest()?);
    let q = query(QueryMode::History)?;
    let m = MaintenanceRequest::new(
        id("plan")?,
        q.selection().clone(),
        q.window(),
        MaintenanceAction::Delete,
        budget()?.max_points,
    )?;
    let other = MaintenanceRequest::new(
        id("plan")?,
        q.selection().clone(),
        q.window(),
        MaintenanceAction::Restore {
            deletion_fence: id("fence")?,
        },
        budget()?.max_points,
    )?;
    let cursor = Continuation::new(m.binding()?, rss_contract::PageCursor::parse("YQ")?);
    assert!(cursor.verify(other.binding()?).is_err());
    assert!(Authorized::<MaintenanceRequest>::verify(&Product, m).is_err());
    assert!(
        MaintenanceRequest::new(
            id("plan")?,
            q.selection().clone(),
            q.window(),
            MaintenanceAction::Prune {
                raw_before: ts(20)?,
                summaries_before: ts(1)?,
                receipts_before: ts(1)?
            },
            budget()?.max_points
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn canonical_v1_golden_and_duplicate_dimensions() -> TestResult {
    let b = batch(vec![gauge(1)?])?;
    assert_eq!(
        b.digest()?.as_bytes(),
        &[
            57, 145, 91, 102, 29, 5, 123, 248, 95, 39, 87, 37, 155, 204, 64, 210, 224, 140, 58, 78,
            87, 13, 1, 48, 238, 137, 69, 245, 218, 221, 211, 75
        ]
    );
    let raw = String::from_utf8(b.encode()?)?.replace(
        "\"dimensions\":{}",
        "\"dimensions\":{\"core\":\"1\",\"core\":\"2\"}",
    );
    assert!(Batch::decode(raw.as_bytes()).is_err());
    Ok(())
}

#[test]
fn finite_float_roundtrip_keeps_exact_bits() -> TestResult {
    // This representable value was rounded down one ULP by the default JSON parser.
    let exact = f64::from_bits(3705789329577597224);
    let b = batch(vec![sample(
        Metric::Gauge {
            number: NumberKind::F64,
        },
        Reading::Valid(Value::Number(Number::F64(FiniteF64::new(exact)?))),
        1,
    )?])?;
    assert_eq!(Batch::decode(&b.encode()?)?.digest()?, b.digest()?);
    let mut bits = 17u64;
    for _ in 0..4096 {
        bits = bits.wrapping_mul(6364136223846793005).wrapping_add(1);
        let v = f64::from_bits(bits);
        if !v.is_finite() {
            continue;
        }
        let value = FiniteF64::new(v)?;
        let decoded: FiniteF64 = serde_json::from_slice(&serde_json::to_vec(&value)?)?;
        assert_eq!(
            decoded.get().to_bits(),
            value.get().to_bits(),
            "bits={bits}"
        );
    }
    Ok(())
}

#[test]
fn every_admitted_observation_has_a_representable_query_upper_bound() -> TestResult {
    let last = gauge(i64::MAX - 1)?;
    let window = Interval::new(ts(i64::MAX - 1)?, ts(i64::MAX)?)?;
    let selection = Selection::Exact {
        stream: stream()?,
        series: last.input().series.clone(),
    };
    for mode in [QueryMode::History, QueryMode::Latest] {
        let q = Query::new(selection.clone(), window, budget()?, mode)?;
        assert!(q.matches(&last));
        q.validate_page(&[ObservedSample {
            sample: last.clone(),
            received_at: ts(i64::MAX)?,
        }])?;
    }
    MaintenanceRequest::new(
        id("boundary-cleanup")?,
        selection,
        window,
        MaintenanceAction::Delete,
        budget()?.max_points,
    )?;
    let mut rejected = last.input().clone();
    rejected.observed_at = ts(i64::MAX)?;
    rejected.interval = Some(Interval::new(ts(0)?, ts(i64::MAX)?)?);
    assert_eq!(Sample::new(rejected.clone()), Err(Error::NumericRange));
    assert!(serde_json::from_slice::<Sample>(&serde_json::to_vec(&rejected)?).is_err());
    let encoded = String::from_utf8(batch(vec![last])?.encode()?)?;
    let malformed = encoded.replace("9223372036854775806", "9223372036854775807");
    assert!(Batch::decode(malformed.as_bytes()).is_err());
    Ok(())
}
