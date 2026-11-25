//! Fixed provider workloads; counters are PostgreSQL backend execution facts.
use super::*;
#[path = "wire.rs"]
mod wire;
async fn calls(pool: &PgPool) -> anyhow::Result<(i64, i64)> {
    let mut leases = Vec::new();
    let mut totals = (0, 0);
    for _ in 0..pool.options().get_max_connections() {
        let mut c = pool.acquire().await?;
        let counts:(i64,i64)=sqlx::query_as("SELECT coalesce(sum(custom_plans+generic_plans),0)::bigint,coalesce(sum(custom_plans+generic_plans) FILTER(WHERE statement LIKE '%headers AS (%' OR statement LIKE 'SELECT observed_at,raw%'),0)::bigint FROM pg_prepared_statements WHERE statement NOT LIKE '%pg_prepared_statements%' AND (statement LIKE 'SELECT%' OR statement LIKE 'WITH%')")
            .fetch_one(&mut *c).await?;
        totals.0 += counts.0;
        totals.1 += counts.1;
        leases.push(c);
    }
    Ok(totals)
}
#[tokio::test]
async fn dense_and_sparse_bounded_io() -> anyhow::Result<()> {
    let f = Fixture::new("ts-aggregate-io").await?;
    let d = definition(TENANT)?;
    f.register(&d).await?;
    for offset in (0..4096).step_by(64) {
        let items = (offset..offset + 64)
            .map(|i| sample(&d, &format!("dense-{i}"), i, i as u64))
            .collect::<anyhow::Result<Vec<_>>>()?;
        f.write(&batch(&format!("dense-batch-{offset}"), items)?)
            .await?;
    }
    let mut caps = limits()?;
    caps.max_points = NonZeroU32::new(5000).ok_or(Error::InvalidInput)?;
    caps.max_bytes = NonZeroU32::new(16 * 1024 * 1024).ok_or(Error::InvalidInput)?;
    let wire = wire::Wire::new(f.pg.params().host.clone(), f.pg.params().port).await?;
    let measured = PgPoolOptions::new()
        .max_connections(1)
        .connect_with(f.pool.connect_options().as_ref().clone().port(wire.port))
        .await?;
    let store = PgStore::new(
        f.profile.clone(),
        rss_timeseries_postgres::StoreConnections::Runtime(measured.clone()),
        Timer,
        caps,
        CursorKey::new([17; 32]),
        deadline()?,
    )
    .await?;
    let bytes: i64 =
        sqlx::query_scalar("SELECT sum(octet_length(raw))::bigint FROM rss_timeseries.samples")
            .fetch_one(&f.admin)
            .await?;
    let before = calls(&measured).await?;
    let wire_before = wire.counts();
    let page = aggregate(&store, spec(&d, 4096)?, 0, 4096).await?;
    let wire_after = wire.counts();
    let after = calls(&measured).await?;
    assert_eq!(page.buckets.len(), 1);
    assert_eq!(page.buckets[0].valid_samples, 4096);
    println!(
        "aggregate-io dense rows=4096 logical_bytes={bytes} page_select={} scan_select={}",
        after.0 - before.0,
        after.1 - before.1
    );
    println!(
        "aggregate-io dense tls_sent={} tls_received={}",
        wire_after.0 - wire_before.0,
        wire_after.1 - wire_before.1
    );
    let before = calls(&measured).await?;
    let sparse = aggregate(&store, spec(&d, 4096)?, 0, 4096 * 64).await?;
    let after = calls(&measured).await?;
    assert_eq!(sparse.buckets.len(), 64);
    println!(
        "aggregate-io sparse buckets=64 page_select={} scan_select={}",
        after.0 - before.0,
        after.1 - before.1
    );
    let request = Authorized::<MaintenanceRequest>::verify(
        &authority(TENANT)?,
        plan(
            "dense-recompute",
            MaintenanceAction::Recompute {
                spec: spec(&d, 4096)?,
                window: window(0, 4096)?,
            },
            257,
        )?,
    )?;
    let mut next = None;
    let mut pages = 0;
    loop {
        let before = calls(&measured).await?;
        let progress = confirmed(store.step(&request, next.as_ref(), deadline()?).await?)?;
        let after = calls(&measured).await?;
        println!(
            "aggregate-io recompute page={pages} select={} scan_select={}",
            after.0 - before.0,
            after.1 - before.1
        );
        pages += 1;
        match progress {
            MaintenanceProgress::More { next: cursor, .. } => next = Some(cursor),
            MaintenanceProgress::Complete { .. } => break,
            _ => anyhow::bail!("unexpected block"),
        }
        assert!(pages < 30);
    }
    let cached = aggregate(&store, spec(&d, 4096)?, 0, 4096).await?;
    assert_eq!(cached.buckets[0].valid_samples, 4096);
    measured.close().await;
    Ok(())
}
