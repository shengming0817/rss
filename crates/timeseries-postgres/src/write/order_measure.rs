//! Run this ignored test alone in release mode, with default features disabled.
use super::*;
use crate::{Atomicity, CursorKey, Guarantees, Limits, StorageProfile};
use std::{
    num::{NonZeroU32, NonZeroU64},
    time::{Duration, Instant},
};

#[path = "../../tests/fixtures/distribution.rs"]
mod distribution;

struct Timer;
impl Clock for Timer {
    #[allow(clippy::disallowed_methods)] // reason: time the production encoder in isolation.
    fn now(&self) -> Instant {
        Instant::now()
    }
}

#[tokio::test]
#[ignore = "isolated release-mode preparation through SQLx binding"]
async fn preparation_by_order() -> anyhow::Result<()> {
    let limits = Limits {
        max_prepare_batches: NonZeroU32::MIN,
        max_prepare_bytes: NonZeroU32::new(Limits::MIN_PREPARE_BYTES).ok_or(Error::Invariant)?,
        max_prepare_waiters: 0,
        max_points: NonZeroU32::MIN,
        max_series: NonZeroU32::MIN,
        max_bytes: NonZeroU32::MIN,
        replay_micros: NonZeroU64::MIN,
        cursor_micros: NonZeroU64::MIN,
    };
    let store = PgStore {
        pool: sqlx::postgres::PgPoolOptions::new().connect_lazy_with(Default::default()),
        preparation: crate::prepare::Capacity::new(&limits)?,
        profile: StorageProfile::PostgreSQL,
        maintenance: None,
        clock: Timer,
        limits,
        key: CursorKey::new([1; 32]),
        instance: "offline".into(),
        guarantees: Guarantees {
            atomicity: Atomicity::AtomicBatch,
            replay_micros: NonZeroU64::MIN,
        },
        #[cfg(feature = "integration")]
        phases: Default::default(),
        #[cfg(feature = "integration")]
        fault: Default::default(),
    };
    let mut length = None;
    for load in distribution::LOADS {
        let batch = distribution::batch(load, 0)?;
        assert_eq!(
            *length.get_or_insert(batch.encoded_len()),
            batch.encoded_len()
        );
        let mut times = Vec::new();
        #[cfg(feature = "integration")]
        rss_timeseries::measurement::start(true);
        for i in 0..61 {
            let deadline = Deadline::from_timeout(&Timer, Duration::from_secs(60))?;
            let end = tokio::time::Instant::from_std(Timer.now() + Duration::from_secs(60));
            let budget = Budget::for_measurement(deadline, end);
            let permit = store.preparation.acquire(&batch).await?;
            let started = Timer.now();
            let prepared = prepare(&batch, &store, budget, permit).await?;
            let elapsed = Timer.now() - started;
            assert_eq!(prepared.count, distribution::COUNT);
            if i > 0 {
                times.push(elapsed.as_nanos());
            }
        }
        times.sort_unstable();
        println!(
            "prepare load={load} bytes={} median_ns={} p95_ns={}",
            batch.encoded_len(),
            (times[29] + times[30]) / 2,
            times[56]
        );
        #[cfg(feature = "integration")]
        {
            let r = rss_timeseries::measurement::finish();
            println!(
                "detail load={load} sha={} bindings={} sort=0 index_peak={} peak_bytes={} reserved={}",
                r.stages["series_sha"].calls / 61,
                r.definition_bindings / 61,
                r.index_peak_bytes,
                r.peak_live_bytes,
                r.peak_reserved_bytes
            );
            let unique = if load == "distinct" {
                distribution::COUNT
            } else {
                2
            };
            assert_eq!(r.stages["series_sha"].calls, (61 * unique) as u64);
            assert_eq!(r.definition_bindings, 61 * unique);
            assert!(r.peak_live_bytes <= r.peak_reserved_bytes);
        }
    }
    Ok(())
}

#[test]
fn repeats_only_reuse_the_complete_series() -> anyhow::Result<()> {
    let b = distribution::batch("alternating", 0)?;
    let first = &b.samples()[0].input().series;
    let other = &b.samples()[1].input().series;
    let mut spec = first.definition().spec().clone();
    spec.unit = Id::new("changed")?;
    let different = Series::new(
        Definition::new(spec)?,
        first.subject().clone(),
        first.resource().clone(),
        first.dimensions().clone(),
    )?;
    let input = [first, other, &different, other, first, &different];
    let mut cache = HashMap::with_hasher(RandomState::new());
    let mut output = Vec::new();
    for series in input {
        push_series(&mut cache, &mut output, series)?;
    }
    assert_eq!(cache.len(), 3);
    for (actual, expected) in output.iter().zip(input) {
        assert_eq!(actual, expected.digest()?.as_bytes());
    }
    Ok(())
}
