use super::*;

#[tokio::test]
async fn only_the_exact_complete_revision_can_publish_after_merge() -> anyhow::Result<()> {
    let f = Fixture::new("ch-revision-keys").await?;
    let proxy = transport::Proxy::new(&f.ch).await?;
    let store = proxy.store(f.pool.clone()).await?;
    sqlx::query("UPDATE rss_ts_ch.installation SET max_pending_batches=16")
        .execute(&f.admin)
        .await?;
    let d = definition(TENANT)?;
    f.register(&d).await?;
    for (name, change) in [
        (
            "duplicate",
            "INSERT INTO rss_ts_ch.raw SELECT * FROM rss_ts_ch.raw WHERE sample_id='duplicate' SETTINGS insert_deduplicate=0",
        ),
        (
            "missing",
            "ALTER TABLE rss_ts_ch.raw DELETE WHERE sample_id='missing' SETTINGS mutations_sync=2",
        ),
        (
            "extra",
            "INSERT INTO rss_ts_ch.raw SELECT * REPLACE (toInt64(2592000000001) AS observed_at) FROM rss_ts_ch.raw WHERE sample_id='extra'",
        ),
        (
            "digest",
            "INSERT INTO rss_ts_ch.raw SELECT * REPLACE (repeat('a',64) AS digest) FROM rss_ts_ch.raw WHERE sample_id='digest'",
        ),
        (
            "time",
            "INSERT INTO rss_ts_ch.raw SELECT * REPLACE (received_at+1 AS received_at) FROM rss_ts_ch.raw WHERE sample_id='time'",
        ),
    ] {
        let b = stream_batch(&d, name, name, 1)?;
        let auth = authority(TENANT)?;
        let request = Authorized::<Batch>::verify(&auth, b.clone())?;
        let receipt = Authorized::<ReceiptQuery>::verify(&auth, receipt_query(&b)?)?;
        proxy.arm(4);
        let write = store.write(&request, deadline()?);
        tokio::pin!(write);
        tokio::select! { _=&mut write=>anyhow::bail!("INSERT missed gate"), ready=proxy.wait_held()=>ready?, }
        f.ch.sql(change).await?;
        f.ch.sql("OPTIMIZE TABLE rss_ts_ch.raw FINAL").await?;
        proxy.release();
        let result = write.await?;
        if name == "duplicate" {
            confirmed(result)?;
        } else {
            assert!(matches!(result, Outcome::Unknown), "{name}");
            assert_eq!(
                store.progress(&receipt, deadline()?).await?,
                rss_timeseries_clickhouse::ProjectionProgress::Prepared
            );
            assert!(matches!(
                store.receipt(&receipt, deadline()?).await?,
                Lookup::NotVisible
            ));
        }
    }
    Ok(())
}
