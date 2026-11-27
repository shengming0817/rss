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

#[tokio::test]
async fn interleaved_last_definition_controls_atomic_rejection() -> anyhow::Result<()> {
    let f = Fixture::new("ts-last-definition").await?;
    let d = definition(TENANT)?;
    let mut changed = d.spec().clone();
    changed.unit = id("changed")?;
    let changed = Definition::new(changed)?;
    let mut other = d.spec().clone();
    other.key = id("other")?;
    let other = Definition::new(other)?;
    f.register(&d).await?;
    f.register(&other).await?;
    for (name, first, last, error) in [
        ("invalid", &changed, &d, Error::InvalidInput),
        ("conflict", &d, &changed, Error::Conflict),
    ] {
        let b = batch(
            name,
            vec![
                sample(first, "first", 10, 1)?,
                sample(&other, "other", 20, 2)?,
                sample(last, "last", 30, 3)?,
            ],
        )?;
        assert_eq!(f.write(&b).await.err(), Some(error));
        assert_eq!(f.count().await?, 0);
        let q = Authorized::<ReceiptQuery>::verify(&authority(TENANT)?, receipt_query(&b)?)?;
        assert!(matches!(
            f.store.receipt(&q, deadline()?).await?,
            Lookup::NotVisible
        ));
    }
    // The two registered definitions repeat out of order. Verify each stored digest
    // against the independent canonical digest for its original sample identity.
    let b = batch(
        "valid",
        vec![
            sample(&d, "first", 10, 1)?,
            sample(&other, "other", 20, 2)?,
            sample(&d, "last", 30, 3)?,
        ],
    )?;
    assert_eq!(confirmed(f.write(&b).await?)?.new_samples(), 3);
    let rows: Vec<(String, Vec<u8>)> = sqlx::query_as(
        "SELECT sample_id,series_digest FROM rss_timeseries.samples ORDER BY observed_at",
    )
    .fetch_all(&f.admin)
    .await?;
    assert_eq!(rows.len(), b.samples().len());
    for ((id, digest), sample) in rows.iter().zip(b.samples()) {
        assert_eq!(id, sample.input().id.as_str());
        assert_eq!(
            digest.as_slice(),
            sample.input().series.digest()?.as_bytes()
        );
    }
    Ok(())
}
