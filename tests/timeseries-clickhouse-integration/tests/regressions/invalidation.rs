use super::*;

fn request(
    name: &str,
    action: &MaintenanceAction,
) -> anyhow::Result<Authorized<MaintenanceRequest>> {
    Ok(Authorized::<MaintenanceRequest>::verify(
        &authority(TENANT)?,
        MaintenanceRequest::new(
            id(name)?,
            action.clone(),
            MaintenanceBudget {
                rows: NonZeroU32::MIN,
                buckets: NonZeroU32::MIN,
            },
        )?,
    )?)
}

async fn namespace(f: &Fixture) -> anyhow::Result<(i64, i64, i64, i64)> {
    Ok(
        sqlx::query_as("SELECT revision,fence_epoch,allocated,published FROM rss_ts_ch.namespaces")
            .fetch_one(&f.admin)
            .await?,
    )
}

// Snapshot all control facts written by Delete/Restore, excluding unrelated fixture data.
async fn facts(f: &Fixture) -> anyhow::Result<String> {
    Ok(sqlx::query_scalar(
        "SELECT jsonb_build_array(
        (SELECT jsonb_agg(to_jsonb(n)) FROM rss_ts_ch.namespaces n),
        (SELECT jsonb_agg(to_jsonb(f) ORDER BY id) FROM rss_ts_ch.fences f),
        (SELECT jsonb_agg(to_jsonb(s) ORDER BY spec_digest,lo) FROM rss_ts_ch.summaries s),
        (SELECT jsonb_agg(to_jsonb(p) ORDER BY id) FROM rss_ts_ch.plans p))::text",
    )
    .fetch_one(&f.admin)
    .await?)
}

async fn wait_for_gate(f: &Fixture, writer: bool) -> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(8),async {
        loop {
            let waiting:bool=sqlx::query_scalar("SELECT EXISTS (
                SELECT FROM pg_locks gate WHERE gate.locktype='advisory' AND gate.objid=3296 AND NOT gate.granted
                  AND (NOT $1 OR EXISTS (SELECT FROM pg_stat_activity w
                     WHERE w.usename='ch_runtime' AND gate.pid=ANY(pg_blocking_pids(w.pid)))))")
                .bind(writer).fetch_one(&f.admin).await?;
            if waiting { return Ok::<_,anyhow::Error>(()); }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }).await?
}

async fn cancellation(f: &Fixture, req: &Authorized<MaintenanceRequest>) -> anyhow::Result<()> {
    let mut gate = f.admin.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(3296)")
        .execute(&mut *gate)
        .await?;
    let before = facts(f).await?;
    {
        let op = f.store.step(req, None, deadline()?);
        tokio::select! {
            result=op=>anyhow::bail!("operation passed the save gate: {result:?}"),
            ready=wait_for_gate(f,false)=>ready?,
        }
    }
    gate.rollback().await?;
    tokio::time::timeout(
        Duration::from_secs(8),
        sqlx::query("SELECT revision FROM rss_ts_ch.namespaces FOR UPDATE").execute(&f.admin),
    )
    .await??;
    assert_eq!(facts(f).await?, before);
    Ok(())
}

// Start the writer only after maintenance owns the namespace; release it only after PG
// observes this backend actually blocking the writer.
async fn commit_before_write(
    f: &Fixture,
    name: &str,
    action: MaintenanceAction,
    b: &Batch,
) -> anyhow::Result<()> {
    let mut gate = f.admin.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(3296)")
        .execute(&mut *gate)
        .await?;
    let writer = async {
        wait_for_gate(f, false).await?;
        let release = async {
            wait_for_gate(f, true).await?;
            gate.rollback().await?;
            Ok::<_, anyhow::Error>(())
        };
        let (result, released) = tokio::join!(f.write(b), release);
        released?;
        anyhow::ensure!(matches!(
            result.err().and_then(|e| e.downcast::<Error>().ok()),
            Some(Error::HistoryExpired)
        ));
        anyhow::Ok(())
    };
    let (progress, written) = tokio::join!(f.maintain(name, action), writer);
    assert!(matches!(progress?, MaintenanceProgress::Complete { .. }));
    written?;
    let lookup = Authorized::<ReceiptQuery>::verify(&authority(TENANT)?, receipt_query(b)?)?;
    assert!(matches!(
        f.store.receipt(&lookup, deadline()?).await?,
        Lookup::NotVisible
    ));
    Ok(())
}

async fn assert_rejected(
    f: &Fixture,
    store: &ChStore<Timer>,
    name: &str,
    action: &MaintenanceAction,
    expected: Error,
) -> anyhow::Result<()> {
    let before = facts(f).await?;
    let req = request(name, action)?;
    assert_eq!(
        store.step(&req, None, deadline()?).await.err(),
        Some(expected)
    );
    assert_eq!(facts(f).await?, before);
    Ok(())
}

async fn rejected_steps(
    f: &Fixture,
    small: &ChStore<Timer>,
    action: &MaintenanceAction,
) -> anyhow::Result<()> {
    let original = facts(f).await?;
    assert_rejected(f, small, "over", action, Error::BudgetExceeded).await?;
    assert_rejected(f, &f.store, "fail-save", action, Error::Invariant).await?;
    cancellation(f, &request("pause-save", action)?).await?;
    // Keep valid JSON and a matching selector so the typed SummarySpec decoder sees the corruption.
    let spec: Vec<u8> = sqlx::query_scalar("SELECT spec FROM rss_ts_ch.summaries WHERE lo=20")
        .fetch_one(&f.admin)
        .await?;
    sqlx::query("UPDATE rss_ts_ch.summaries SET spec=convert_to(jsonb_set(convert_from(spec,'UTF8')::jsonb,'{resolution}','0')::text,'UTF8') WHERE lo=20").execute(&f.admin).await?;
    assert_rejected(f, &f.store, "bad-spec", action, Error::Invariant).await?;
    sqlx::query("UPDATE rss_ts_ch.summaries SET spec=$1 WHERE lo=20")
        .bind(spec)
        .execute(&f.admin)
        .await?;
    assert_eq!(facts(f).await?, original);
    Ok(())
}

async fn dirty_keys(f: &Fixture) -> anyhow::Result<Vec<(Vec<u8>, i64, i64, i64, Option<i64>)>> {
    Ok(sqlx::query_as("SELECT spec_digest,lo,hi,dependency_start,dirty_from FROM rss_ts_ch.summaries ORDER BY spec_digest,lo").fetch_all(&f.admin).await?)
}

#[tokio::test]
async fn delete_and_restore_validate_every_key_and_roll_back_together() -> anyhow::Result<()> {
    let f = Fixture::new("ch-invalidation-tx").await?;
    let d = definition(TENANT)?;
    f.register(&d).await?;
    let b = batch(
        "seed",
        vec![sample(&d, "in", 15, 7)?, sample(&d, "outside", 1, 1)?],
    )?;
    confirmed(f.write(&b).await?)?;
    let spec = SummarySpec::new(
        b.stream().clone(),
        b.samples()[0].input().series.clone(),
        NonZeroU64::new(10).ok_or(Error::Invariant)?,
        CoveragePolicy::ObservedOnly,
        None,
    )?;
    let window = Interval::new(Timestamp::new(10)?, Timestamp::new(40)?)?;
    let select = spec.selection();
    let cache = MaintenanceAction::Recompute {
        spec,
        window: Interval::new(Timestamp::new(0)?, Timestamp::new(60)?)?,
    };
    let mut caps = limits()?;
    caps.max_points = NonZeroU32::new(2).ok_or(Error::Invariant)?;
    let small = Fixture::connect_options(
        &f.ch,
        f.pool.clone(),
        TENANT,
        "ch_reader",
        "ch_writer",
        caps,
    )
    .await?;
    sqlx::raw_sql("CREATE FUNCTION rss_ts_ch.gate_plan() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
        IF NEW.id='fail-save' THEN RAISE EXCEPTION 'fixture save failure' USING ERRCODE='23514'; END IF;
        IF NEW.id IN ('delete','restore','pause-save') THEN PERFORM pg_advisory_xact_lock(3296); END IF; RETURN NEW; END $$;
        CREATE TRIGGER gate_plan BEFORE INSERT ON rss_ts_ch.plans FOR EACH ROW EXECUTE FUNCTION rss_ts_ch.gate_plan();").execute(&f.admin).await?;
    let delete = MaintenanceAction::Delete {
        selection: select.clone(),
        window,
        restore_until: Timestamp::new(i64::MAX)?,
    };
    let restore = MaintenanceAction::Restore {
        selection: select,
        window,
        deletion_fence: id("delete")?,
    };
    for (name, action, delta, visible) in [("delete", delete, 2, 1), ("restore", restore, 1, 2)] {
        f.maintain(&format!("cache-{name}"), cache.clone()).await?;
        sqlx::query("UPDATE rss_ts_ch.summaries SET dependency_start=CASE WHEN lo=40 THEN 19 WHEN lo=50 THEN 40 ELSE lo END,
            dirty_from=CASE lo WHEN 20 THEN 9 WHEN 30 THEN 0 ELSE NULL END").execute(&f.admin).await?;
        rejected_steps(&f, &small, &action).await?;
        let mut expected = dirty_keys(&f).await?;
        assert_eq!(expected.len(), 6);
        for (_, lo, _, _, dirty) in &mut expected {
            if [10, 20, 30, 40].contains(lo) {
                *dirty = Some(0);
            }
        }
        let (rev, epoch, alloc, pub_watermark) = namespace(&f).await?;
        let blocked = batch(&format!("write-{name}"), vec![sample(&d, "fresh", 15, 1)?])?;
        commit_before_write(&f, name, action.clone(), &blocked).await?;
        assert_eq!(dirty_keys(&f).await?, expected);
        assert_eq!(
            namespace(&f).await?,
            (rev + delta, epoch + 1, alloc, pub_watermark)
        );
        assert_eq!(f.read(&d).await?.rows.len(), visible);
        let committed = facts(&f).await?;
        f.maintain(name, action).await?;
        assert_eq!(facts(&f).await?, committed);
    }
    Ok(())
}

#[tokio::test]
async fn update_pairs_each_digest_with_its_own_bucket_start() -> anyhow::Result<()> {
    let f = Fixture::new("ch-invalidate-pairs").await?;
    let d = definition(TENANT)?;
    f.register(&d).await?;
    let b = batch("seed", vec![sample(&d, "seed", 15, 1)?])?;
    confirmed(f.write(&b).await?)?;
    let spec = |resolution| {
        SummarySpec::new(
            b.stream().clone(),
            b.samples()[0].input().series.clone(),
            NonZeroU64::new(resolution).ok_or(Error::Invariant)?,
            CoveragePolicy::ObservedOnly,
            None,
        )
    };
    let fine = spec(10)?;
    let coarse = spec(20)?;
    let fine_id = fine.binding()?.as_bytes().to_vec();
    let coarse_id = coarse.binding()?.as_bytes().to_vec();
    assert_ne!(fine_id, coarse_id);
    let window = Interval::new(Timestamp::new(15)?, Timestamp::new(16)?)?;
    let selection = fine.selection();
    let delete = MaintenanceAction::Delete {
        selection: selection.clone(),
        window,
        restore_until: Timestamp::new(i64::MAX)?,
    };
    let restore = MaintenanceAction::Restore {
        selection,
        window,
        deletion_fence: id("delete")?,
    };
    for (name, action) in [("delete", delete), ("restore", restore)] {
        for s in [&fine, &coarse] {
            let cache = MaintenanceAction::Recompute {
                spec: s.clone(),
                window: Interval::new(Timestamp::new(0)?, Timestamp::new(60)?)?,
            };
            f.maintain(&format!("{name}-cache-{}", s.resolution_micros()), cache)
                .await?;
        }
        let mut want = dirty_keys(&f).await?;
        assert_eq!(want.len(), 9);
        for (digest, lo, _, _, dirty) in &mut want {
            assert!(dirty.is_none());
            if (digest == &fine_id && *lo == 10) || (digest == &coarse_id && *lo == 0) {
                *dirty = Some(0);
            }
        }
        assert_eq!(want.iter().filter(|r| r.4.is_some()).count(), 2);
        f.maintain(name, action).await?;
        assert_eq!(dirty_keys(&f).await?, want);
    }
    Ok(())
}
