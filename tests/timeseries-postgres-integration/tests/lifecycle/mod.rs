use super::aggregation::{aggregate, complete, plan, spec, window};
use super::*;
async fn run(store: &PgStore<Timer>, r: MaintenanceRequest) -> anyhow::Result<MaintenanceProgress> {
    confirmed(
        store
            .step(
                &Authorized::<MaintenanceRequest>::verify(&authority(TENANT)?, r)?,
                None,
                deadline()?,
            )
            .await?,
    )
}
async fn now(f: &Fixture) -> anyhow::Result<i64> {
    Ok(
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp())*1000000)::bigint")
            .fetch_one(&f.admin)
            .await?,
    )
}
async fn raw_page(f: &Fixture, d: &Definition) -> anyhow::Result<Page> {
    Ok(f.store
        .query(
            &Authorized::<Query>::verify(&authority(TENANT)?, query(d, QueryMode::History, 100)?)?,
            None,
            deadline()?,
        )
        .await?)
}
#[tokio::test]
async fn deletion_restore_retirement_and_overlapping_fences() -> anyhow::Result<()> {
    let f = Fixture::new("ts-delete").await?;
    let d = definition(TENANT)?;
    f.register(&d).await?;
    let b = batch(
        "initial",
        vec![sample(&d, "a", 1, 5)?, sample(&d, "b", 11, 8)?],
    )?;
    f.write(&b).await?;
    let sp = spec(&d, 10)?;
    let selection = sp.selection();
    let until = Timestamp::new(now(&f).await? + 60_000_000)?;
    complete(
        &f.store,
        plan(
            "refresh",
            MaintenanceAction::Recompute {
                spec: sp.clone(),
                window: window(0, 20)?,
            },
            1,
        )?,
    )
    .await?;
    complete(
        &f.store,
        plan(
            "delete",
            MaintenanceAction::Delete {
                selection: selection.clone(),
                window: window(0, 10)?,
                restore_until: until,
            },
            1,
        )?,
    )
    .await?;
    assert_eq!(raw_page(&f, &d).await?.rows.len(), 1);
    assert!(matches!(
        aggregate(&f.store, sp.clone(), 0, 10).await?.buckets[0].value,
        AggregateValue::Missing
    ));
    assert_eq!(
        f.write(&batch("old-new-id", vec![sample(&d, "new", 5, 4)?])?)
            .await
            .err(),
        Some(Error::HistoryExpired)
    );
    assert!(matches!(f.write(&b).await?, Outcome::Replay(_)));
    let wrong = plan(
        "bad-restore",
        MaintenanceAction::Restore {
            selection: selection.clone(),
            window: window(0, 10)?,
            deletion_fence: id("wrong")?,
        },
        1,
    )?;
    assert_eq!(
        f.store
            .step(
                &Authorized::<MaintenanceRequest>::verify(&authority(TENANT)?, wrong)?,
                None,
                deadline()?
            )
            .await
            .err(),
        Some(Error::HistoryExpired)
    );
    complete(
        &f.store,
        plan(
            "delete-overlap",
            MaintenanceAction::Delete {
                selection: selection.clone(),
                window: window(0, 20)?,
                restore_until: until,
            },
            1,
        )?,
    )
    .await?;
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
    assert_eq!(raw_page(&f, &d).await?.rows.len(), 0);
    confirmed(
        f.store
            .change(
                &Authorized::<DefinitionMutation>::verify(
                    &authority(TENANT)?,
                    DefinitionMutation::Retire {
                        id: DefinitionId {
                            scope: d.spec().scope.clone(),
                            key: d.spec().key.clone(),
                            version: NonZeroU64::new(1).ok_or(Error::InvalidInput)?,
                        },
                        expected: d.digest()?,
                    },
                )?,
                deadline()?,
            )
            .await?,
    )?;
    complete(
        &f.store,
        plan(
            "restore-overlap",
            MaintenanceAction::Restore {
                selection: selection.clone(),
                window: window(0, 20)?,
                deletion_fence: id("delete-overlap")?,
            },
            1,
        )?,
    )
    .await?;
    assert_eq!(raw_page(&f, &d).await?.rows.len(), 2);
    assert_eq!(
        f.write(&batch("still-fenced", vec![sample(&d, "new", 5, 4)?])?)
            .await
            .err(),
        Some(Error::HistoryExpired)
    );
    complete(
        &f.store,
        plan(
            "refresh-retired",
            MaintenanceAction::Recompute {
                spec: sp,
                window: window(0, 20)?,
            },
            1,
        )?,
    )
    .await?;
    Ok(())
}
#[tokio::test]
async fn layered_pruning_expiry_and_closed_stream_reclamation() -> anyhow::Result<()> {
    let f = Fixture::new("ts-prune").await?;
    let d = definition(TENANT)?;
    f.register(&d).await?;
    let b = batch(
        "initial",
        vec![sample(&d, "a", 1, 5)?, sample(&d, "b", 11, 15)?],
    )?;
    let mut short = limits()?;
    short.replay_micros = NonZeroU64::new(1).ok_or(Error::InvalidInput)?;
    let store = PgStore::new(
        f.pool.clone(),
        Timer,
        short,
        CursorKey::new([17; 32]),
        deadline()?,
    )
    .await?;
    confirmed(
        store
            .write(
                &Authorized::<Batch>::verify(&authority(TENANT)?, b.clone())?,
                deadline()?,
            )
            .await?,
    )?;
    let sp = spec(&d, 10)?;
    let selection = sp.selection();
    let zero = Timestamp::new(0)?;
    let prune = plan(
        "prune",
        MaintenanceAction::Prune {
            selection: selection.clone(),
            raw_before: Timestamp::new(20)?,
            summaries_before: zero,
        },
        1,
    )?;
    assert!(matches!(
        run(&store, prune.clone()).await?,
        MaintenanceProgress::Blocked {
            reason: MaintenanceBlock::Cutoff
        }
    ));
    complete(
        &store,
        plan(
            "refresh",
            MaintenanceAction::Recompute {
                spec: sp.clone(),
                window: window(0, 20)?,
            },
            1,
        )?,
    )
    .await?;
    complete(
        &store,
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
    complete(&store, prune).await?;
    assert_eq!(f.count().await?, 0);
    let coarse = aggregate(&store, spec(&d, 20)?, 0, 20).await?;
    assert!(
        matches!(coarse.buckets[0].value,AggregateValue::Mean {sum:Sum::U128(20),count} if count.get()==2)
    );
    assert!(matches!(
        store
            .write(
                &Authorized::<Batch>::verify(&authority(TENANT)?, b.clone())?,
                deadline()?
            )
            .await?,
        Outcome::Replay(_)
    ));
    complete(
        &store,
        plan(
            "expire",
            MaintenanceAction::ExpireReceipts {
                stream: b.stream().clone(),
                before: Timestamp::new(now(&f).await?)?,
            },
            1,
        )?,
    )
    .await?;
    assert!(matches!(
        store
            .receipt(
                &Authorized::<ReceiptQuery>::verify(&authority(TENANT)?, receipt_query(&b)?)?,
                deadline()?
            )
            .await?,
        Lookup::Expired
    ));
    assert_eq!(f.write(&b).await.err(), Some(Error::HistoryExpired));
    assert_eq!(
        f.write(&batch("new-batch", vec![sample(&d, "unknown-old", 1, 5)?])?)
            .await
            .err(),
        Some(Error::HistoryExpired)
    );
    complete(
        &store,
        plan(
            "close",
            MaintenanceAction::CloseStream {
                stream: b.stream().clone(),
            },
            1,
        )?,
    )
    .await?;
    assert!(matches!(
        run(
            &store,
            plan(
                "reclaim",
                MaintenanceAction::Reclaim {
                    stream: b.stream().clone()
                },
                1
            )?
        )
        .await?,
        MaintenanceProgress::Blocked {
            reason: MaintenanceBlock::RetainedData
        }
    ));
    complete(
        &store,
        plan(
            "prune-all",
            MaintenanceAction::Prune {
                selection,
                raw_before: Timestamp::new(20)?,
                summaries_before: Timestamp::new(20)?,
            },
            1,
        )?,
    )
    .await?;
    complete(
        &store,
        plan(
            "reclaim",
            MaintenanceAction::Reclaim {
                stream: b.stream().clone(),
            },
            1,
        )?,
    )
    .await?;
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM rss_timeseries.sample_identities")
        .fetch_one(&f.admin)
        .await?;
    assert_eq!(count, 0);
    assert_eq!(
        f.write(&batch("future", vec![sample(&d, "future", 21, 1)?])?)
            .await
            .err(),
        Some(Error::HistoryExpired)
    );
    let mut unknown = receipt_query(&b)?;
    unknown.batch_id = id("never-observed")?;
    assert!(matches!(
        store
            .receipt(
                &Authorized::<ReceiptQuery>::verify(&authority(TENANT)?, unknown)?,
                deadline()?
            )
            .await?,
        Lookup::Expired
    ));
    Ok(())
}
#[tokio::test]
async fn restore_and_receipt_guarantees_block_physical_cleanup() -> anyhow::Result<()> {
    let f = Fixture::new("ts-retention").await?;
    let d = definition(TENANT)?;
    f.register(&d).await?;
    let b = batch("initial", vec![sample(&d, "a", 1, 1)?])?;
    f.write(&b).await?;
    let selection = spec(&d, 10)?.selection();
    let expiry = plan(
        "expire",
        MaintenanceAction::ExpireReceipts {
            stream: b.stream().clone(),
            before: Timestamp::new(now(&f).await?)?,
        },
        1,
    )?;
    assert!(matches!(
        run(&f.store, expiry).await?,
        MaintenanceProgress::Blocked {
            reason: MaintenanceBlock::ReplayGuarantee
        }
    ));
    complete(
        &f.store,
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
    complete(
        &f.store,
        plan(
            "delete",
            MaintenanceAction::Delete {
                selection: selection.clone(),
                window: window(0, 10)?,
                restore_until: Timestamp::new(now(&f).await? + 60_000_000)?,
            },
            1,
        )?,
    )
    .await?;
    let prune = plan(
        "prune",
        MaintenanceAction::Prune {
            selection: selection.clone(),
            raw_before: Timestamp::new(10)?,
            summaries_before: Timestamp::new(10)?,
        },
        1,
    )?;
    assert!(matches!(
        run(&f.store, prune.clone()).await?,
        MaintenanceProgress::Blocked {
            reason: MaintenanceBlock::RestoreWindow
        }
    ));
    // Trusted fixture owner advances the persisted expiry boundary, without a timing sleep.
    sqlx::query("UPDATE rss_timeseries.fences SET restore_until=0 WHERE kind='delete'")
        .execute(&f.admin)
        .await?;
    complete(&f.store, prune).await?;
    assert_eq!(f.count().await?, 0);
    let restore = plan(
        "expired-restore",
        MaintenanceAction::Restore {
            selection,
            window: window(0, 10)?,
            deletion_fence: id("delete")?,
        },
        1,
    )?;
    assert_eq!(
        f.store
            .step(
                &Authorized::<MaintenanceRequest>::verify(&authority(TENANT)?, restore)?,
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
async fn v1_upgrade_requires_current_schema_and_protects_new_objects() -> anyhow::Result<()> {
    let f = Fixture::new_inner("ts-upgrade", true).await?;
    let old_sample = sample(&definition(TENANT)?, "v1", 50, 7)?;
    let old = batch("v1", vec![old_sample.clone()])?;
    let old_page = raw_page(&f, &definition(TENANT)?).await?;
    assert!(old_page.rows.iter().any(|r| r.sample == old_sample));
    let old_receipt = f
        .store
        .receipt(
            &Authorized::<ReceiptQuery>::verify(&authority(TENANT)?, receipt_query(&old)?)?,
            deadline()?,
        )
        .await?;
    assert!(
        matches!(old_receipt,Lookup::Found(ref receipt) if receipt.identity().digest==old.digest()? && receipt.received_at()==Timestamp::new(10)?)
    );
    assert!(matches!(f.write(&old).await?, Outcome::Replay(_)));
    let replay = confirmed(f.write(&batch("v1-new-batch", vec![old_sample])?).await?)?;
    assert_eq!((replay.new_samples(), replay.replayed_samples()), (0, 1));

    let d = definition(TENANT)?;
    f.register(&d).await?;
    f.write(&batch("upgraded", vec![sample(&d, "upgraded", 1, 1)?])?)
        .await?;
    let selection = spec(&d, 10)?.selection();
    complete(
        &f.store,
        plan(
            "cut",
            MaintenanceAction::AdvanceCutoff {
                selection,
                before: Timestamp::new(10)?,
            },
            1,
        )?,
    )
    .await?;
    for (delete, select) in [
        (
            "DELETE FROM rss_timeseries.namespaces",
            "SELECT count(*) FROM rss_timeseries.namespaces",
        ),
        (
            "DELETE FROM rss_timeseries.fences",
            "SELECT count(*) FROM rss_timeseries.fences",
        ),
        (
            "DELETE FROM rss_timeseries.plans",
            "SELECT count(*) FROM rss_timeseries.plans",
        ),
        (
            "DELETE FROM rss_timeseries.summaries",
            "SELECT count(*) FROM rss_timeseries.summaries",
        ),
        (
            "DELETE FROM rss_timeseries.summary_ranges",
            "SELECT count(*) FROM rss_timeseries.summary_ranges",
        ),
    ] {
        assert!(sqlx::query(delete).execute(&f.pool).await.is_err());
        let rows: i64 = sqlx::query_scalar(select).fetch_one(&f.pool).await?;
        assert_eq!(rows, 0);
    }
    sqlx::raw_sql("GRANT DELETE ON rss_timeseries.fences TO ts_runtime")
        .execute(&f.admin)
        .await?;
    assert!(
        PgStore::new(
            f.pool.clone(),
            Timer,
            limits()?,
            CursorKey::new([17; 32]),
            deadline()?
        )
        .await
        .is_err()
    );
    let wrong = Authorized::<MaintenanceRequest>::verify(
        &authority(OTHER)?,
        plan(
            "cross",
            MaintenanceAction::CloseStream {
                stream: sample(&d, "x", 0, 0)?.input().stream.clone(),
            },
            1,
        )?,
    );
    assert_eq!(wrong.err(), Some(Error::Unauthorized));
    Ok(())
}
#[tokio::test]
async fn namespace_fence_serializes_new_stream_and_write_first_cleanup() -> anyhow::Result<()> {
    let f = Fixture::new("ts-lifecycle-lock").await?;
    let d = definition(TENANT)?;
    f.register(&d).await?;
    // A committed write is visible to the subsequent cleanup before its fence is released.
    f.write(&batch("first", vec![sample(&d, "first", 1, 1)?])?)
        .await?;
    let resource = query(&d, QueryMode::History, 10)?.selection().clone();
    let mut owner = f.admin.acquire().await?;
    sqlx::raw_sql("BEGIN").execute(&mut *owner).await?;
    sqlx::query(
        "SELECT revision FROM rss_timeseries.namespaces WHERE tenant_id=$1::text::uuid FOR UPDATE",
    )
    .bind(TENANT)
    .execute(&mut *owner)
    .await?;
    let mut input = sample(&d, "racing", 2, 2)?.input().clone();
    input.stream = Stream::new(
        d.spec().scope.clone(),
        id("new-source")?,
        id("new-generation")?,
    );
    let b = batch("racing", vec![Sample::new(input)?])?;
    let deadline = Deadline::from_timeout(&Timer, Duration::from_millis(150))?;
    let outcome = f
        .store
        .write(
            &Authorized::<Batch>::verify(&authority(TENANT)?, b.clone())?,
            deadline,
        )
        .await;
    assert!(matches!(
        outcome,
        Err(Error::Deadline) | Ok(Outcome::Unknown)
    ));
    sqlx::raw_sql("ROLLBACK").execute(&mut *owner).await?;
    complete(
        &f.store,
        plan(
            "cut",
            MaintenanceAction::AdvanceCutoff {
                selection: resource.clone(),
                before: Timestamp::new(10)?,
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
                selection: resource,
                raw_before: Timestamp::new(10)?,
                summaries_before: Timestamp::new(10)?,
            },
            1,
        )?,
    )
    .await?;
    assert_eq!(f.write(&b).await.err(), Some(Error::HistoryExpired));
    assert_eq!(f.count().await?, 0);
    Ok(())
}

#[tokio::test]
async fn maintenance_survives_real_before_and_after_commit_process_death() -> anyhow::Result<()> {
    let f = Fixture::new("ts-maint-crash").await?;
    let d = definition(TENANT)?;
    f.register(&d).await?;
    f.write(&batch(
        "initial",
        vec![sample(&d, "a", 1, 1)?, sample(&d, "b", 11, 2)?],
    )?)
    .await?;
    let root = std::env::temp_dir().join(format!("rss-maint-crash-{}", std::process::id()));
    std::fs::create_dir_all(&root)?;
    let ca = root.join("ca.pem");
    std::fs::write(&ca, f.pg.ca_pem())?;
    for committed in [false, true] {
        let phase = if committed { "after" } else { "before" };
        let marker = root.join(phase);
        let p = f.pg.params();
        let mut child = tokio::process::Command::new(std::env::current_exe()?)
            .args([
                "--exact",
                "lifecycle::maintenance_child",
                "--ignored",
                "--nocapture",
            ])
            .env("TS_HOST", &p.host)
            .env("TS_PORT", p.port.to_string())
            .env("TS_DB", &p.database)
            .env("TS_CA", &ca)
            .env("TS_MARKER", &marker)
            .env("TS_PHASE", phase)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::inherit())
            .kill_on_drop(true)
            .spawn()?;
        let ready=tokio::time::timeout(Duration::from_secs(20),async {
   loop {
    if child.try_wait()?.is_some(){anyhow::bail!("child exited before maintenance boundary");}
    let staged:bool=sqlx::query_scalar("SELECT EXISTS(SELECT FROM pg_stat_activity a JOIN pg_locks l ON l.pid=a.pid WHERE a.application_name='timeseries-maintenance-crash' AND a.state='idle in transaction' AND a.query LIKE 'SELECT rss_timeseries.put_plan%' AND l.locktype='relation' AND l.relation='rss_timeseries.plans'::regclass AND l.mode='RowExclusiveLock' AND l.granted)").fetch_one(&f.admin).await?;
    if (committed&&marker.exists())||(!committed&&staged){break;}
    tokio::time::sleep(Duration::from_millis(20)).await;
   }Ok::<_,anyhow::Error>(())
  }).await;
        child.kill().await?;
        child.wait().await?;
        ready??;
        let reopened = PgStore::new(
            f.pool.clone(),
            Timer,
            limits()?,
            CursorKey::new([17; 32]),
            deadline()?,
        )
        .await?;
        let request = crash_plan(phase, &d)?;
        let outcome = reopened
            .step(
                &Authorized::<MaintenanceRequest>::verify(&authority(TENANT)?, request)?,
                None,
                deadline()?,
            )
            .await?;
        assert_eq!(matches!(outcome, Outcome::Replay(_)), committed);
    }
    assert!(raw_page(&f, &d).await?.rows.is_empty());
    std::fs::remove_dir_all(root)?;
    Ok(())
}
fn crash_plan(phase: &str, d: &Definition) -> anyhow::Result<MaintenanceRequest> {
    let (lo, hi) = if phase == "before" { (0, 5) } else { (10, 15) };
    plan(
        phase,
        MaintenanceAction::Delete {
            selection: spec(d, 10)?.selection(),
            window: window(lo, hi)?,
            restore_until: Timestamp::new(i64::MAX)?,
        },
        1,
    )
}
#[tokio::test]
#[ignore = "subprocess stopped at a real PostgreSQL maintenance commit boundary"]
async fn maintenance_child() -> anyhow::Result<()> {
    let phase = std::env::var("TS_PHASE")?;
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect_with(
            PgConnectOptions::new()
                .host(&std::env::var("TS_HOST")?)
                .port(std::env::var("TS_PORT")?.parse()?)
                .database(&std::env::var("TS_DB")?)
                .username("ts_runtime")
                .password("fixture-only")
                .application_name("timeseries-maintenance-crash")
                .ssl_mode(PgSslMode::VerifyFull)
                .ssl_root_cert_from_pem(std::fs::read(std::env::var("TS_CA")?)?),
        )
        .await?;
    let store = PgStore::new(
        pool,
        Timer,
        limits()?,
        CursorKey::new([17; 32]),
        deadline()?,
    )
    .await?;
    store.inject_next_fault(if phase == "before" {
        Fault::CommitPending
    } else {
        Fault::CommitAckLost
    });
    let outcome = store
        .step(
            &Authorized::<MaintenanceRequest>::verify(
                &authority(TENANT)?,
                crash_plan(&phase, &definition(TENANT)?)?,
            )?,
            None,
            Deadline::from_timeout(&Timer, Duration::from_secs(60))?,
        )
        .await?;
    anyhow::ensure!(
        matches!(outcome, Outcome::Unknown),
        "expected lost maintenance acknowledgment"
    );
    std::fs::write(std::env::var("TS_MARKER")?, b"committed")?;
    std::future::pending::<()>().await;
    Ok(())
}

#[tokio::test]
async fn repeated_prunes_compact_frontiers_and_unrelated_deletes_do_not_exhaust_reads()
-> anyhow::Result<()> {
    let f = Fixture::new("ts-fence-growth").await?;
    let d = definition(TENANT)?;
    f.register(&d).await?;
    f.write(&batch("initial", vec![sample(&d, "initial", 100, 1)?])?)
        .await?;
    let selection = spec(&d, 10)?.selection();
    let mut low = limits()?;
    low.max_points = NonZeroU32::new(2).ok_or(Error::InvalidInput)?;
    let store = PgStore::new(
        f.pool.clone(),
        Timer,
        low,
        CursorKey::new([17; 32]),
        deadline()?,
    )
    .await?;
    for i in 1..8 {
        complete(
            &store,
            plan(
                &format!("cut-{i}"),
                MaintenanceAction::AdvanceCutoff {
                    selection: selection.clone(),
                    before: Timestamp::new(i)?,
                },
                1,
            )?,
        )
        .await?;
        complete(
            &store,
            plan(
                &format!("prune-{i}"),
                MaintenanceAction::Prune {
                    selection: selection.clone(),
                    raw_before: Timestamp::new(i)?,
                    summaries_before: Timestamp::new(0)?,
                },
                1,
            )?,
        )
        .await?;
        let other = Selection::Resource {
            scope: d.spec().scope.clone(),
            subject: id("other-device")?,
            resource: id(&format!("resource-{i}"))?,
            keys: Default::default(),
        };
        complete(
            &store,
            plan(
                &format!("delete-{i}"),
                MaintenanceAction::Delete {
                    selection: other,
                    window: window(0, 10)?,
                    restore_until: Timestamp::new(i64::MAX)?,
                },
                1,
            )?,
        )
        .await?;
    }
    let q = Query::new(
        selection,
        window(90, 110)?,
        QueryBudget {
            max_points: NonZeroU32::MIN,
            max_series: NonZeroU32::MIN,
        },
        QueryMode::Latest,
    )?;
    let page = store
        .query(
            &Authorized::<Query>::verify(&authority(TENANT)?, q)?,
            None,
            deadline()?,
        )
        .await?;
    assert_eq!(page.rows.len(), 1);
    assert!(page.availability.excluded.is_empty());
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM rss_timeseries.fences WHERE kind='pruned'")
            .fetch_one(&f.admin)
            .await?;
    assert_eq!(count, 1);
    Ok(())
}
