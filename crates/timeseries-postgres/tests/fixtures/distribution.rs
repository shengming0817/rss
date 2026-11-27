//! Matched preparation and transaction inputs. Only the order of the two series changes.
use rss_request_context::TenantId;
use rss_timeseries::*;

pub const LOADS: [&str; 4] = ["clustered", "alternating", "shuffled", "distinct"];
pub const COUNT: usize = 2048;
pub const TENANT: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";

pub fn batch(load: &str, run: usize) -> anyhow::Result<Batch> {
    let scope = Scope::new(TenantId::parse(TENANT)?, Id::new("metrics")?);
    let stream = Stream::new(scope.clone(), Id::new("sensor")?, Id::new("generation")?);
    let mut positions: Vec<_> = (0..COUNT).collect();
    match load {
        "clustered" | "distinct" => {}
        "alternating" => positions.sort_by_key(|n| (n % (COUNT / 2), *n)),
        "shuffled" => {
            let mut state = 3364u64;
            for i in (1..COUNT).rev() {
                state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
                positions.swap(i, ((state >> 32) as usize) % (i + 1));
            }
        }
        _ => anyhow::bail!("unknown distribution {load}"),
    }
    let samples = positions
        .into_iter()
        .map(|i| {
            let key = if load == "distinct" {
                i
            } else {
                i / (COUNT / 2)
            };
            let d = Definition::new(DefinitionSpec {
                scope: scope.clone(),
                key: Id::new(format!("metric-{key:04}"))?,
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
            Sample::new(SampleInput {
                stream: stream.clone(),
                series: Series::new(
                    d,
                    Id::new("device")?,
                    Id::new("resource")?,
                    Default::default(),
                )?,
                id: Id::new(format!("s-{run:03}-{i:04}"))?,
                sequence: i as u64,
                observed_at: Timestamp::new(i as i64)?,
                interval: None,
                reading: Reading::Valid(Value::Number(Number::U64(i as u64))),
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Batch::new(
        stream,
        Id::new(format!("b-{run:03}"))?,
        samples,
    )?)
}
