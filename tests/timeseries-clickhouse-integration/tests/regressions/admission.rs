use super::*;

fn interval(lo: i64, hi: i64) -> Result<Interval, Error> {
    Interval::new(Timestamp::new(lo)?, Timestamp::new(hi)?)
}

fn deletion(selection: Selection, window: Interval) -> Result<MaintenanceAction, Error> {
    Ok(MaintenanceAction::Delete {
        selection,
        window,
        restore_until: Timestamp::new(i64::MAX)?,
    })
}

async fn watermarks(f: &Fixture) -> anyhow::Result<(i64, i64)> {
    Ok(sqlx::query_as("SELECT allocated,published FROM rss_ts_ch.namespaces WHERE tenant_id=$1::text::uuid AND namespace='metrics'")
       .bind(TENANT).fetch_one(&f.admin).await?)
}

async fn write_error(store: &ChStore<Timer>, b: Batch) -> anyhow::Result<Error> {
    let req = Authorized::<Batch>::verify(&authority(TENANT)?, b)?;
    store
        .write(&req, deadline()?)
        .await
        .err()
        .ok_or_else(|| anyhow::anyhow!("write succeeded"))
}

#[tokio::test]
async fn replay_precedence_and_namespace_fence_budget() -> anyhow::Result<()> {
    let f = Fixture::new("ch-admit-order").await?;
    let d = definition(TENANT)?;
    f.register(&d).await?;
    let seed = sample(&d, "original", 10, 1)?;
    let original = batch("original", vec![seed.clone()])?;
    let select = query(&d, QueryMode::History, 1)?.selection().clone();
    let hide = deletion(select.clone(), interval(10, 20)?)?;
    f.store.inject_next_fault(Fault::AfterPrepare);
    assert!(matches!(f.write(&original).await?, Outcome::Unknown));
    assert!(matches!(
        f.maintain("hide", hide.clone()).await?,
        MaintenanceProgress::Blocked {
            reason: MaintenanceBlock::PendingWrite
        }
    ));
    let saved = confirmed(f.write(&original).await?)?;
    f.maintain("hide", hide).await?;
    f.maintain(
        "restore",
        MaintenanceAction::Restore {
            selection: select,
            window: interval(10, 20)?,
            deletion_fence: id("hide")?,
        },
    )
    .await?;
    let replay = batch("replayed", vec![seed.clone()])?;
    let rr = confirmed(f.write(&replay).await?)?;
    assert_eq!((rr.new_samples(), rr.replayed_samples()), (0, 1));
    let point = sample(&d, "new", 10, 3)?;
    let altered = sample(&d, "original", 10, 2)?;
    let before = watermarks(&f).await?;
    assert_eq!(
        write_error(
            &f.store,
            batch("conflict", vec![altered.clone(), point.clone()])?
        )
        .await?,
        Error::Conflict
    );
    assert_eq!(
        write_error(&f.store, batch("expired", vec![point, altered])?).await?,
        Error::HistoryExpired
    );
    assert_eq!(watermarks(&f).await?, before);
    let mut limits = limits()?;
    limits.max_fences = NonZeroU32::MIN;
    let small = Fixture::connect_options(
        &f.ch,
        f.pool.clone(),
        TENANT,
        "ch_reader",
        "ch_writer",
        limits,
    )
    .await?;
    let safe = batch("at-cap", vec![sample(&d, "safe", 20, 1)?])?;
    confirmed(
        small
            .write(
                &Authorized::<Batch>::verify(&authority(TENANT)?, safe)?,
                deadline()?,
            )
            .await?,
    )?;
    let other = Selection::Resource {
        scope: d.spec().scope.clone(),
        subject: id("unused")?,
        resource: id("resource")?,
        keys: Default::default(),
    };
    f.maintain("extra", deletion(other, interval(40, 50)?)?)
        .await?;
    let before = watermarks(&f).await?;
    assert_eq!(
        write_error(&small, batch("over", vec![seed])?).await?,
        Error::BudgetExceeded
    );
    let lookup = Authorized::<Batch>::verify(&authority(TENANT)?, original)?;
    assert!(
        matches!(small.write(&lookup,deadline()?).await?,Outcome::Replay(r) if r.received_at()==saved.received_at() && r.identity().digest==saved.identity().digest && r.replay_until()==saved.replay_until())
    );
    assert_eq!(watermarks(&f).await?, before);
    Ok(())
}

#[tokio::test]
async fn ordered_windows_use_full_stream_series_and_resource_keys() -> anyhow::Result<()> {
    let f = Fixture::new("ch-admit-windows").await?;
    let basic = definition(TENANT)?;
    let mut spec = basic.spec().clone();
    spec.dimensions.allowed.insert(id("zone")?);
    spec.dimensions.max_count = 1;
    let d = Definition::new(spec)?;
    f.register(&d).await?;
    let point = sample(&d, "seed", 1, 1)?;
    let stream = &point.input().stream;
    let series = &point.input().series;
    let exact = |stream: &Stream, series: &Series| Selection::Exact {
        stream: stream.clone(),
        series: series.clone(),
    };
    let resource = |keys| Selection::Resource {
        scope: stream.scope().clone(),
        subject: series.subject().clone(),
        resource: series.resource().clone(),
        keys,
    };
    let zone = Series::new(
        d.clone(),
        series.subject().clone(),
        series.resource().clone(),
        [(id("zone")?, id("west")?)].into(),
    )?;
    let next = Definition::new(DefinitionSpec {
        version: 2,
        ..d.spec().clone()
    })?;
    let v2 = Series::new(
        next,
        series.subject().clone(),
        series.resource().clone(),
        Default::default(),
    )?;
    let other_stream = Stream::new(
        stream.scope().clone(),
        stream.source().clone(),
        id("new-generation")?,
    );
    for (i, (selector, lo, hi)) in [
        (exact(stream, series), 12, 15),
        (exact(stream, series), 10, 13),
        (exact(stream, series), 15, 20),
        (exact(stream, &zone), 20, 30),
        (exact(stream, &v2), 20, 30),
        (exact(&other_stream, series), 20, 30),
        (resource([id("absent")?].into()), 20, 30),
        (
            resource([id("absent")?, d.spec().key.clone()].into()),
            30,
            35,
        ),
        (resource(Default::default()), 40, 42),
    ]
    .into_iter()
    .enumerate()
    {
        f.maintain(&format!("hide-{i}"), deletion(selector, interval(lo, hi)?)?)
            .await?;
    }
    // Exercise the same resource and time under independent namespace/tenant RLS bindings.
    for (tenant, namespace, reader) in [
        (TENANT, "elsewhere", "ch_reader"),
        (OTHER, "metrics", "ch_other"),
    ] {
        let owner = bind(&f.store.owner, tenant, reader).await?;
        let select = Selection::Resource {
            scope: Scope::new(TenantId::parse(tenant)?, id(namespace)?),
            subject: series.subject().clone(),
            resource: series.resource().clone(),
            keys: Default::default(),
        };
        let request = Authorized::<MaintenanceRequest>::verify(
            &authority(tenant)?,
            MaintenanceRequest::new(
                id("foreign")?,
                deletion(select, interval(20, 30)?)?,
                MaintenanceBudget {
                    rows: NonZeroU32::MIN,
                    buckets: NonZeroU32::MIN,
                },
            )?,
        )?;
        confirmed(owner.step(&request, None, deadline()?).await?)?;
    }
    for (n, at, blocked) in [
        (0, 9, false),
        (1, 10, true),
        (2, 14, true),
        (3, 15, true),
        (4, 19, true),
        (5, 20, false),
        (6, 29, false),
        (7, 30, true),
        (8, 35, false),
        (9, 40, true),
        (10, 42, false),
    ] {
        let name = format!("probe-{n}");
        let b = batch(&name, vec![sample(&d, &name, at, 1)?])?;
        if blocked {
            assert_eq!(write_error(&f.store, b).await?, Error::HistoryExpired);
        } else {
            assert_eq!(confirmed(f.write(&b).await?)?.new_samples(), 1);
        }
    }
    cutoff_boundary(&f, &d, resource(Default::default())).await?;
    Ok(())
}

async fn cutoff_boundary(f: &Fixture, d: &Definition, selection: Selection) -> anyhow::Result<()> {
    f.maintain(
        "retain",
        MaintenanceAction::AdvanceCutoff {
            selection,
            before: Timestamp::new(50)?,
        },
    )
    .await?;
    let before = watermarks(f).await?;
    let blocked = batch("before-cutoff", vec![sample(d, "before-cutoff", 49, 1)?])?;
    let lookup = Authorized::<ReceiptQuery>::verify(&authority(TENANT)?, receipt_query(&blocked)?)?;
    assert_eq!(write_error(&f.store, blocked).await?, Error::HistoryExpired);
    assert!(matches!(
        f.store.receipt(&lookup, deadline()?).await?,
        Lookup::NotVisible
    ));
    assert_eq!(watermarks(f).await?, before);
    let at = batch("at-cutoff", vec![sample(d, "at-cutoff", 50, 1)?])?;
    let got = confirmed(f.write(&at).await?)?;
    assert_eq!(got.new_samples(), 1);
    let lookup = Authorized::<ReceiptQuery>::verify(&authority(TENANT)?, receipt_query(&at)?)?;
    assert!(
        matches!(f.store.receipt(&lookup,deadline()?).await?,Lookup::Found(r) if r.identity().digest==got.identity().digest)
    );
    assert_eq!(watermarks(f).await?, (before.0 + 1, before.1 + 1));
    Ok(())
}
