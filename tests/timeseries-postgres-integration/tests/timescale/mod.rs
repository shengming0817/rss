use super::aggregation::{aggregate, complete, plan, spec, window};
use super::*;
use rss_timeseries_postgres::{
    StorageProfile, StoreConnections,
    timescale::{DedicatedTenant, Hypertable, StorageFormat},
};
fn shared() -> anyhow::Result<StorageProfile> {
    Ok(StorageProfile::TimescaleSharedRls(Hypertable::new(
        NonZeroU64::new(100).ok_or(Error::InvalidInput)?,
    )?))
}
fn dedicated() -> anyhow::Result<StorageProfile> {
    Ok(StorageProfile::TimescaleDedicatedTenant(
        DedicatedTenant::new(
            TenantId::parse(TENANT)?,
            Hypertable::new(NonZeroU64::new(100).ok_or(Error::InvalidInput)?)?,
            &[NonZeroU64::new(10).ok_or(Error::InvalidInput)?],
        )?,
    ))
}
async fn reopen(f: &Fixture) -> anyhow::Result<PgStore<Timer>> {
    Ok(PgStore::new(
        f.profile.clone(),
        match &f.maintenance {
            Some(pool) => StoreConnections::Native {
                runtime: f.pool.clone(),
                maintenance: pool.clone(),
            },
            None => StoreConnections::Runtime(f.pool.clone()),
        },
        Timer,
        limits()?,
        CursorKey::new([17; 32]),
        deadline()?,
    )
    .await?)
}
async fn refresh(f: &Fixture, d: &Definition, name: &str, hi: i64) -> anyhow::Result<()> {
    complete(
        &f.store,
        plan(
            name,
            MaintenanceAction::Recompute {
                spec: spec(d, 10)?,
                window: window(0, hi)?,
            },
            2,
        )?,
    )
    .await
}
#[tokio::test]
async fn shared_atomic_replay_isolation_and_catalog_readmission() -> anyhow::Result<()> {
    let f = Fixture::on_profile("ts-shared", shared()?).await?;
    let d = definition(TENANT)?;
    f.register(&d).await?;
    let b = batch(
        "cross-chunk",
        vec![sample(&d, "early", 1, 10)?, sample(&d, "later", 101, 20)?],
    )?;
    f.store.inject_next_fault(Fault::CommitAckLost);
    assert!(matches!(f.write(&b).await?, Outcome::Unknown));
    assert!(matches!(f.write(&b).await?, Outcome::Replay(_)));
    assert_eq!(f.count().await?, 2);
    let fresh = reopen(&f).await?;
    assert!(matches!(
        fresh
            .receipt(
                &Authorized::<ReceiptQuery>::verify(&authority(TENANT)?, receipt_query(&b)?)?,
                deadline()?
            )
            .await?,
        Lookup::Found(_)
    ));
    let conflict = batch(
        "conflict",
        vec![sample(&d, "new", 202, 1)?, sample(&d, "early", 1, 99)?],
    )?;
    assert_eq!(f.write(&conflict).await.err(), Some(Error::Conflict));
    assert_eq!(f.count().await?, 2);
    Ok(())
}
#[tokio::test]
async fn native_refresh_late_delete_restore_columnstore_and_retention() -> anyhow::Result<()> {
    let f = Fixture::on_profile("ts-native", dedicated()?).await?;
    let d = definition(TENANT)?;
    f.register(&d).await?;
    let b = batch(
        "initial",
        vec![sample(&d, "a", 1, 5)?, sample(&d, "b", 11, 8)?],
    )?;
    f.write(&b).await?;
    refresh(&f, &d, "initial-refresh", 20).await?;
    assert!(matches!(
        aggregate(&f.store, spec(&d, 10)?, 0, 10).await?.buckets[0].value,
        AggregateValue::Mean {
            sum: Sum::U128(5),
            ..
        }
    ));
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM rss_timeseries.gauge_10")
        .fetch_one(&f.admin)
        .await?;
    assert_eq!(n, 2);
    let cap = NonZeroU32::new(1).ok_or(Error::InvalidInput)?;
    assert_eq!(
        confirmed(
            f.store
                .convert_raw_chunks(
                    window(0, 100)?,
                    cap,
                    StorageFormat::Columnstore,
                    deadline()?
                )
                .await?
        )?,
        1
    );
    f.write(&batch("late", vec![sample(&d, "late", 2, 7)?])?)
        .await?;
    refresh(&f, &d, "late-refresh", 20).await?;
    let selection = spec(&d, 10)?.selection();
    let now: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp())*1000000)::bigint")
            .fetch_one(&f.admin)
            .await?;
    complete(
        &f.store,
        plan(
            "delete",
            MaintenanceAction::Delete {
                selection: selection.clone(),
                window: window(0, 10)?,
                restore_until: Timestamp::new(now + 60_000_000)?,
            },
            1,
        )?,
    )
    .await?;
    refresh(&f, &d, "deleted-refresh", 20).await?;
    assert!(matches!(
        aggregate(&f.store, spec(&d, 10)?, 0, 10).await?.buckets[0].value,
        AggregateValue::Missing
    ));
    complete(
        &f.store,
        plan(
            "restore",
            MaintenanceAction::Restore {
                selection: selection.clone(),
                window: window(0, 10)?,
                deletion_fence: id("delete")?,
            },
            1,
        )?,
    )
    .await?;
    refresh(&f, &d, "restored-refresh", 20).await?;
    assert!(
        matches!(aggregate(&f.store,spec(&d,10)?,0,10).await?.buckets[0].value,AggregateValue::Mean{sum:Sum::U128(12),count} if count.get()==2)
    );
    reopen(&f).await?;
    complete(
        &f.store,
        plan(
            "cutoff",
            MaintenanceAction::AdvanceCutoff {
                selection: selection.clone(),
                before: Timestamp::new(20)?,
            },
            1,
        )?,
    )
    .await?;
    complete(
        &f.store,
        plan(
            "prune",
            MaintenanceAction::Prune {
                selection,
                raw_before: Timestamp::new(20)?,
                summaries_before: Timestamp::new(0)?,
            },
            1,
        )?,
    )
    .await?;
    assert_eq!(f.count().await?, 0);
    assert!(matches!(f.write(&b).await?, Outcome::Replay(_)));
    assert_eq!(f.count().await?, 0);
    assert!(matches!(
        aggregate(&f.store, spec(&d, 10)?, 0, 10).await?.buckets[0].value,
        AggregateValue::Mean {
            sum: Sum::U128(12),
            ..
        }
    ));
    let expired = plan(
        "refresh-pruned",
        MaintenanceAction::Recompute {
            spec: spec(&d, 10)?,
            window: window(0, 20)?,
        },
        1,
    )?;
    assert_eq!(
        f.store
            .step(
                &Authorized::<MaintenanceRequest>::verify(&authority(TENANT)?, expired)?,
                None,
                deadline()?
            )
            .await
            .err(),
        Some(Error::HistoryExpired)
    );
    Ok(())
}
#[tokio::test]
async fn native_unknown_checkpoint_revision_and_fixed_tenant() -> anyhow::Result<()> {
    let f = Fixture::on_profile("ts-native-recovery", dedicated()?).await?;
    let d = definition(TENANT)?;
    f.register(&d).await?;
    f.write(&batch("initial", vec![sample(&d, "a", 1, u64::MAX)?])?)
        .await?;
    let r = plan(
        "recompute",
        MaintenanceAction::Recompute {
            spec: spec(&d, 10)?,
            window: window(0, 10)?,
        },
        1,
    )?;
    let authorized = Authorized::<MaintenanceRequest>::verify(&authority(TENANT)?, r.clone())?;
    f.store.inject_next_fault(Fault::CommitAckLost);
    assert!(matches!(
        f.store.step(&authorized, None, deadline()?).await?,
        Outcome::Unknown
    ));
    f.write(&batch("concurrent", vec![sample(&d, "b", 0, 1)?])?)
        .await?;
    let fresh = reopen(&f).await?;
    complete(&fresh, r).await?;
    assert!(
        matches!(aggregate(&fresh,spec(&d,10)?,0,10).await?.buckets[0].value,AggregateValue::Mean{sum:Sum::U128(v),count} if v==u128::from(u64::MAX)+1 && count.get()==2)
    );
    let other = definition("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")?;
    assert!(f.register(&other).await.is_err());
    assert!(
        PgStore::new(
            f.profile.clone(),
            StoreConnections::Runtime(f.pool.clone()),
            Timer,
            limits()?,
            CursorKey::new([17; 32]),
            deadline()?
        )
        .await
        .is_err()
    );
    sqlx::raw_sql("SET ROLE ts_owner; ALTER TABLE rss_timeseries.samples DROP CONSTRAINT installation_tenant; RESET ROLE").execute(&f.admin).await?;
    assert!(reopen(&f).await.is_err());
    Ok(())
}
#[tokio::test]
async fn native_missing_extension_and_capability_drift_rejected() -> anyhow::Result<()> {
    let f = Fixture::new("ts-no-extension").await?;
    assert!(
        PgStore::new(
            shared()?,
            StoreConnections::Runtime(f.pool.clone()),
            Timer,
            limits()?,
            CursorKey::new([17; 32]),
            deadline()?
        )
        .await
        .is_err()
    );
    let g = Fixture::on_profile("ts-native-drift", dedicated()?).await?;
    sqlx::raw_sql("DO $$ DECLARE r record; BEGIN FOR r IN SELECT materialization_hypertable_schema AS s,materialization_hypertable_name AS n FROM timescaledb_information.continuous_aggregates WHERE view_schema='rss_timeseries' LOOP EXECUTE format('GRANT UPDATE ON %I.%I TO ts_runtime',r.s,r.n); END LOOP; END $$").execute(&g.admin).await?;
    assert!(reopen(&g).await.is_err());
    sqlx::raw_sql("DO $$ DECLARE r record; BEGIN FOR r IN SELECT materialization_hypertable_schema AS s,materialization_hypertable_name AS n FROM timescaledb_information.continuous_aggregates WHERE view_schema='rss_timeseries' LOOP EXECUTE format('REVOKE UPDATE ON %I.%I FROM ts_runtime',r.s,r.n); END LOOP; END $$").execute(&g.admin).await?;
    reopen(&g).await?;
    sqlx::raw_sql("SET ROLE ts_owner; ALTER MATERIALIZED VIEW rss_timeseries.gauge_10 SET (timescaledb.materialized_only=false); RESET ROLE").execute(&g.admin).await?;
    assert!(reopen(&g).await.is_err());
    Ok(())
}

#[tokio::test]
async fn native_call_commit_before_publication_and_cleanup_rollback_recover() -> anyhow::Result<()>
{
    let f = Fixture::on_profile("ts-native-publish-fault", dedicated()?).await?;
    let d = definition(TENANT)?;
    f.register(&d).await?;
    f.write(&batch("one", vec![sample(&d, "one", 1, 11)?])?)
        .await?;
    let r = plan(
        "refresh",
        MaintenanceAction::Recompute {
            spec: spec(&d, 10)?,
            window: window(0, 10)?,
        },
        1,
    )?;
    let auth = Authorized::<MaintenanceRequest>::verify(&authority(TENANT)?, r.clone())?;
    for _ in 0..2 {
        assert!(matches!(
            confirmed(f.store.step(&auth, None, deadline()?).await?)?,
            MaintenanceProgress::More { .. }
        ));
    }
    f.store.inject_next_fault(Fault::BeforeCommit);
    assert_eq!(
        f.store.step(&auth, None, deadline()?).await.err(),
        Some(Error::Unavailable)
    );
    let native: i64 = sqlx::query_scalar("SELECT count(*) FROM rss_timeseries.gauge_10")
        .fetch_one(&f.admin)
        .await?;
    let published: i64 = sqlx::query_scalar("SELECT count(*) FROM rss_timeseries.summaries")
        .fetch_one(&f.admin)
        .await?;
    assert_eq!((native, published), (1, 0));
    let fresh = reopen(&f).await?;
    complete(&fresh, r).await?;
    assert!(matches!(
        aggregate(&fresh, spec(&d, 10)?, 0, 10).await?.buckets[0].value,
        AggregateValue::Mean {
            sum: Sum::U128(11),
            ..
        }
    ));
    let selection = spec(&d, 10)?.selection();
    complete(
        &fresh,
        plan(
            "cut",
            MaintenanceAction::AdvanceCutoff {
                selection: selection.clone(),
                before: Timestamp::new(10)?,
            },
            1,
        )?,
    )
    .await?;
    let prune = plan(
        "prune",
        MaintenanceAction::Prune {
            selection,
            raw_before: Timestamp::new(10)?,
            summaries_before: Timestamp::new(0)?,
        },
        1,
    )?;
    let auth = Authorized::<MaintenanceRequest>::verify(&authority(TENANT)?, prune.clone())?;
    for _ in 0..2 {
        assert!(matches!(
            confirmed(fresh.step(&auth, None, deadline()?).await?)?,
            MaintenanceProgress::More { .. }
        ));
    }
    fresh.inject_next_fault(Fault::BeforeCommit);
    assert_eq!(
        fresh.step(&auth, None, deadline()?).await.err(),
        Some(Error::Unavailable)
    );
    let cached: i64 = sqlx::query_scalar("SELECT count(*) FROM rss_timeseries.gauge_10")
        .fetch_one(&f.admin)
        .await?;
    assert_eq!(cached, 0);
    complete(&reopen(&f).await?, prune).await?;
    assert!(matches!(
        aggregate(&fresh, spec(&d, 10)?, 0, 10).await?.buckets[0].value,
        AggregateValue::Mean {
            sum: Sum::U128(11),
            ..
        }
    ));
    Ok(())
}
