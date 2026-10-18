use super::*;
#[tokio::test]
async fn tenant_permissions_partitions_and_drift() -> anyhow::Result<()> {
    let f = Fixture::new("ts-security").await?;
    for tenant in [TENANT, OTHER] {
        let d = definition(tenant)?;
        f.register(&d).await?;
        confirmed(
            f.write(&batch(
                "same",
                vec![sample(&d, "same", 99, 1)?, sample(&d, "later", 101, 2)?],
            )?)
            .await?,
        )?;
    }
    let d = definition(TENANT)?;
    let other = definition(OTHER)?;
    assert!(
        Authorized::<Batch>::verify(
            &authority(TENANT)?,
            batch("x", vec![sample(&other, "x", 1, 1)?])?
        )
        .is_err()
    );
    assert!(
        Authorized::<Query>::verify(&authority(TENANT)?, query(&other, QueryMode::History, 10)?)
            .is_err()
    );
    let q = Authorized::<Query>::verify(&authority(TENANT)?, query(&d, QueryMode::History, 1)?)?;
    let p = f.store.query(&q, None, deadline()?).await?;
    assert_eq!(p.rows.len(), 1);
    let other_q =
        Authorized::<Query>::verify(&authority(OTHER)?, query(&other, QueryMode::History, 1)?)?;
    assert_eq!(
        f.store
            .query(&other_q, p.next.as_ref(), deadline()?)
            .await
            .err(),
        Some(Error::InvalidCursor)
    );
    let empty: i64 = sqlx::query_scalar("SELECT count(*) FROM rss_timeseries.samples")
        .fetch_one(&f.pool)
        .await?;
    assert_eq!(empty, 0);
    assert!(
        sqlx::query(
            "SELECT rss_timeseries.lock_stream($1::text::uuid,'metrics','sensor','generation')"
        )
        .bind(TENANT)
        .execute(&f.pool)
        .await
        .is_err()
    );
    for sql in [
        "DELETE FROM rss_timeseries.samples",
        "UPDATE rss_timeseries.batches SET received_at=0",
        "SELECT rss_timeseries.create_partition(200,300)",
        "SET ROLE ts_owner",
        "TRUNCATE rss_timeseries.sample_identities",
    ] {
        assert!(sqlx::raw_sql(sql).execute(&f.pool).await.is_err());
    }
    let parts: i64 =
        sqlx::query_scalar("SELECT count(DISTINCT tableoid) FROM rss_timeseries.samples")
            .fetch_one(&f.admin)
            .await?;
    assert_eq!(parts, 2);
    // A missing partition must roll back the earlier new sample and its identity as well.
    sqlx::raw_sql("ALTER TABLE rss_timeseries.samples DETACH PARTITION rss_timeseries.samples_100_9223372036854775807").execute(&f.admin).await?;
    let b = batch(
        "missing-part",
        vec![sample(&d, "staged", 3, 1)?, sample(&d, "no-part", 300, 1)?],
    )?;
    assert!(f.write(&b).await.is_err());
    let count:i64=sqlx::query_scalar("SELECT count(*) FROM rss_timeseries.sample_identities WHERE sample_id IN ('staged','no-part')").fetch_one(&f.admin).await?;
    assert_eq!(count, 0);
    assert!(
        PgStore::new(
            rss_timeseries_postgres::StorageProfile::PostgreSQL,
            f.pool.clone(),
            Timer,
            limits()?,
            CursorKey::new([17; 32]),
            deadline()?
        )
        .await
        .is_err()
    );
    sqlx::raw_sql("ALTER TABLE rss_timeseries.samples ATTACH PARTITION rss_timeseries.samples_100_9223372036854775807 FOR VALUES FROM (100) TO (9223372036854775807)").execute(&f.admin).await?;
    for (bad, undo) in [
        (
            "GRANT UPDATE ON rss_timeseries.samples TO ts_runtime",
            "REVOKE UPDATE ON rss_timeseries.samples FROM ts_runtime",
        ),
        (
            "ALTER TABLE rss_timeseries.samples_0_100 DISABLE ROW LEVEL SECURITY",
            "ALTER TABLE rss_timeseries.samples_0_100 ENABLE ROW LEVEL SECURITY",
        ),
        (
            "GRANT SELECT ON rss_timeseries.samples_0_100 TO PUBLIC",
            "REVOKE SELECT ON rss_timeseries.samples_0_100 FROM PUBLIC",
        ),
        (
            "ALTER ROLE ts_runtime BYPASSRLS",
            "ALTER ROLE ts_runtime NOBYPASSRLS",
        ),
        (
            "ALTER TABLE rss_timeseries.batches ADD COLUMN drift integer",
            "ALTER TABLE rss_timeseries.batches DROP COLUMN drift",
        ),
    ] {
        sqlx::raw_sql(bad).execute(&f.admin).await?;
        assert!(
            PgStore::new(
                rss_timeseries_postgres::StorageProfile::PostgreSQL,
                f.pool.clone(),
                Timer,
                limits()?,
                CursorKey::new([17; 32]),
                deadline()?
            )
            .await
            .is_err()
        );
        sqlx::raw_sql(undo).execute(&f.admin).await?;
    }
    PgStore::new(
        rss_timeseries_postgres::StorageProfile::PostgreSQL,
        f.pool.clone(),
        Timer,
        limits()?,
        CursorKey::new([17; 32]),
        deadline()?,
    )
    .await?;
    Ok(())
}
#[tokio::test]
async fn lock_budget_and_retirement_race() -> anyhow::Result<()> {
    let f = Fixture::new("ts-lock").await?;
    let d = definition(TENANT)?;
    f.register(&d).await?;
    let b = batch("lock", vec![sample(&d, "lock", 1, 1)?])?;
    let mut c = f.admin.acquire().await?;
    sqlx::raw_sql("BEGIN").execute(&mut *c).await?;
    sqlx::query(
        "SELECT 1 FROM rss_timeseries.definitions WHERE tenant_id=$1::text::uuid FOR UPDATE",
    )
    .bind(TENANT)
    .execute(&mut *c)
    .await?;
    let auth = Authorized::<Batch>::verify(&authority(TENANT)?, b.clone())?;
    let result = f
        .store
        .write(
            &auth,
            Deadline::from_timeout(&Timer, Duration::from_millis(150))?,
        )
        .await;
    assert!(matches!(
        result,
        Err(Error::Deadline) | Ok(Outcome::Unknown)
    ));
    sqlx::raw_sql("UPDATE rss_timeseries.definitions SET retired=true; COMMIT")
        .execute(&mut *c)
        .await?;
    assert_eq!(f.write(&b).await.err(), Some(Error::Retired));
    assert_eq!(f.count().await?, 0);
    Ok(())
}

struct ShiftClock(std::sync::Arc<std::sync::atomic::AtomicU64>);
impl Clock for ShiftClock {
    #[allow(clippy::disallowed_methods)] // reason: fixture independently advances the injected monotonic clock.
    fn now(&self) -> Instant {
        Instant::now() + Duration::from_secs(self.0.load(std::sync::atomic::Ordering::SeqCst))
    }
}
#[tokio::test]
async fn injected_deadline_is_checked_before_commit() -> anyhow::Result<()> {
    let f = Fixture::new("ts-clock").await?;
    let d = definition(TENANT)?;
    f.register(&d).await?;
    let offset = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    let store = PgStore::new(
        rss_timeseries_postgres::StorageProfile::PostgreSQL,
        f.pool.clone(),
        ShiftClock(offset.clone()),
        limits()?,
        CursorKey::new([17; 32]),
        deadline()?,
    )
    .await?;
    let mut c = f.admin.acquire().await?;
    sqlx::raw_sql("BEGIN; SELECT 1 FROM rss_timeseries.definition_heads FOR UPDATE")
        .execute(&mut *c)
        .await?;
    let mut spec = d.spec().clone();
    spec.version = 2;
    let request = Authorized::<DefinitionMutation>::verify(
        &authority(TENANT)?,
        DefinitionMutation::Register {
            definition: Definition::new(spec)?,
            expected_latest: Some(d.digest()?),
        },
    )?;
    let cutoff = deadline()?;
    let task = tokio::spawn(async move { store.change(&request, cutoff).await });
    tokio::time::timeout(Duration::from_secs(5),async {
        loop {
            let waiting:bool=sqlx::query_scalar("SELECT EXISTS(SELECT FROM pg_stat_activity WHERE usename='ts_runtime' AND wait_event_type='Lock' AND query LIKE '%lock_key%')").fetch_one(&f.admin).await?;
            if waiting {break;}
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        Ok::<_,anyhow::Error>(())
    }).await??;
    offset.store(60, std::sync::atomic::Ordering::SeqCst);
    sqlx::raw_sql("COMMIT").execute(&mut *c).await?;
    assert!(matches!(task.await??, Outcome::Unknown));
    // Serialize behind cleanup to observe the durable definition head after connection quarantine.
    sqlx::raw_sql("BEGIN; SELECT 1 FROM rss_timeseries.definition_heads FOR UPDATE; COMMIT")
        .execute(&mut *c)
        .await?;
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM rss_timeseries.definitions")
        .fetch_one(&f.admin)
        .await?;
    assert_eq!(count, 1);
    Ok(())
}
