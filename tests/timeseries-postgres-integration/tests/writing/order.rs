use super::*;
#[path = "../../../../crates/timeseries-postgres/tests/fixtures/distribution.rs"]
mod distribution;

#[tokio::test]
#[ignore = "isolated release-mode fresh PostgreSQL transactions"]
async fn writes_by_order() -> anyhow::Result<()> {
    for load in distribution::LOADS {
        let f = Fixture::new("ts-order").await?;
        let seed = distribution::batch(load, 0)?;
        let mut keys = std::collections::BTreeSet::new();
        for sample in seed.samples() {
            let definition = sample.input().series.definition();
            if keys.insert(&definition.spec().key) {
                f.register(definition).await?;
            }
        }
        let a = authority(distribution::TENANT)?;
        let mut times = Vec::new();
        for run in 0..21 {
            let b = distribution::batch(load, run)?;
            let lookup = Authorized::<ReceiptQuery>::verify(&a, receipt_query(&b)?)?;
            let request = Authorized::<Batch>::verify(&a, b)?;
            let cutoff = deadline()?;
            let start = Timer.now();
            let receipt = confirmed(f.store.write(&request, cutoff).await?)?;
            let elapsed = Timer.now() - start;
            assert_eq!(receipt.new_samples() as usize, distribution::COUNT);
            assert!(matches!(
                f.store.receipt(&lookup, deadline()?).await?,
                Lookup::Found(_)
            ));
            if run > 0 {
                times.push(elapsed);
            }
        }
        times.sort_unstable();
        let seconds = times.iter().sum::<Duration>().as_secs_f64();
        println!(
            "write load={load} samples_s={:.0} median_us={} p95_us={}",
            (times.len() * distribution::COUNT) as f64 / seconds,
            (times[9] + times[10]).as_micros() / 2,
            times[18].as_micros()
        );
    }
    Ok(())
}
