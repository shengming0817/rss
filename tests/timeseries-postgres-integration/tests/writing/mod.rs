mod measure;
use super::*;
#[tokio::test]
async fn atomic_replay_conflict_retirement_and_recovery() -> anyhow::Result<()> {
    let f = Fixture::new("ts-writing").await?;
    let d = definition(TENANT)?;
    f.register(&d).await?;
    let a = sample(&d, "a", 99, u64::MAX)?;
    let b = sample(&d, "b", 100, 2)?;
    let first = batch("first", vec![a.clone(), b.clone()])?;
    let r = confirmed(f.write(&first).await?)?;
    assert_eq!(r.new_samples(), 2);
    let replay = f.write(&first).await?;
    assert!(matches!(replay, Outcome::Replay(_)));
    let replay = confirmed(replay)?;
    assert_eq!(replay.received_at(), r.received_at());
    assert_eq!(replay.replay_until(), r.replay_until());
    assert_eq!(
        f.write(&batch("first", vec![a.clone()])?).await.err(),
        Some(Error::Conflict)
    );
    let cross = confirmed(f.write(&batch("cross", vec![a.clone()])?).await?)?;
    assert_eq!((cross.new_samples(), cross.replayed_samples()), (0, 1));
    let conflict = batch(
        "conflict",
        vec![sample(&d, "new", 101, 3)?, sample(&d, "a", 100, 9)?],
    )?;
    assert_eq!(f.write(&conflict).await.err(), Some(Error::Conflict));
    assert_eq!(f.count().await?, 2);
    let mut changed = a.input().clone();
    changed.series = Series::new(
        d.clone(),
        id("other-device")?,
        id("resource")?,
        Default::default(),
    )?;
    assert_eq!(
        f.write(&batch("changed-series", vec![Sample::new(changed)?])?)
            .await
            .err(),
        Some(Error::Conflict)
    );
    let next = batch("unknown", vec![sample(&d, "unknown", 101, 3)?])?;
    f.store.inject_next_fault(Fault::CommitAckLost);
    assert!(matches!(f.write(&next).await?, Outcome::Unknown));
    let fresh = PgStore::new(
        rss_timeseries_postgres::StorageProfile::PostgreSQL,
        rss_timeseries_postgres::StoreConnections::Runtime(f.pool.clone()),
        Timer,
        limits()?,
        CursorKey::new([17; 32]),
        deadline()?,
    )
    .await?;
    let lookup = fresh
        .receipt(
            &Authorized::<ReceiptQuery>::verify(&authority(TENANT)?, receipt_query(&next)?)?,
            deadline()?,
        )
        .await?;
    assert!(matches!(lookup, Lookup::Found(_)));
    assert!(matches!(f.write(&next).await?, Outcome::Replay(_)));
    assert_eq!(f.count().await?, 3);
    let failed = batch("rollback", vec![sample(&d, "rollback", 102, 3)?])?;
    f.store.inject_next_fault(Fault::BeforeCommit);
    assert_eq!(f.write(&failed).await.err(), Some(Error::Unavailable));
    assert_eq!(f.count().await?, 3);
    f.store.inject_next_fault(Fault::RollbackAckLost);
    assert!(matches!(f.write(&conflict).await?, Outcome::Unknown));
    assert_eq!(f.count().await?, 3);
    let expired = Deadline::from_timeout(&Timer, Duration::ZERO)?;
    assert_eq!(
        f.store
            .write(
                &Authorized::<Batch>::verify(&authority(TENANT)?, failed.clone())?,
                expired
            )
            .await
            .err(),
        Some(Error::Deadline)
    );
    f.store.inject_next_fault(Fault::CommitPending);
    let short = Deadline::from_timeout(&Timer, Duration::from_millis(150))?;
    assert!(matches!(
        f.store
            .write(
                &Authorized::<Batch>::verify(&authority(TENANT)?, failed.clone())?,
                short
            )
            .await?,
        Outcome::Unknown
    ));
    confirmed(f.write(&failed).await?)?;
    assert_eq!(f.count().await?, 4);
    let retirement = DefinitionMutation::Retire {
        id: DefinitionId {
            scope: d.spec().scope.clone(),
            key: d.spec().key.clone(),
            version: NonZeroU64::MIN,
        },
        expected: d.digest()?,
    };
    confirmed(
        f.store
            .change(
                &Authorized::<DefinitionMutation>::verify(&authority(TENANT)?, retirement)?,
                deadline()?,
            )
            .await?,
    )?;
    assert!(matches!(f.write(&first).await?, Outcome::Replay(_)));
    confirmed(f.write(&batch("retired-replay", vec![a])?).await?)?;
    assert_eq!(
        f.write(&batch("retired-new", vec![sample(&d, "retired", 2, 1)?])?)
            .await
            .err(),
        Some(Error::Retired)
    );
    assert_eq!(f.count().await?, 4);
    expanded_dimensions(&f).await?;
    Ok(())
}
#[tokio::test]
async fn concurrent_admission_and_definition_cas() -> anyhow::Result<()> {
    let f = Fixture::new("ts-concurrent").await?;
    let d = definition(TENANT)?;
    f.register(&d).await?;
    let b = batch("race", vec![sample(&d, "race", 42, 1)?])?;
    let (left, right) = tokio::join!(f.write(&b), f.write(&b));
    assert!(matches!(
        (&left, &right),
        (Ok(Outcome::Accepted(_)), Ok(Outcome::Replay(_)))
            | (Ok(Outcome::Replay(_)), Ok(Outcome::Accepted(_)))
    ));
    let x = batch("x", vec![sample(&d, "shared", 43, 2)?])?;
    let y = batch("y", vec![sample(&d, "shared", 43, 2)?])?;
    let (x, y) = tokio::join!(f.write(&x), f.write(&y));
    assert_eq!(
        confirmed(x?)?.new_samples() + confirmed(y?)?.new_samples(),
        1
    );
    let mut spec = d.spec().clone();
    spec.version = u64::MAX;
    let newer = Definition::new(spec)?;
    let req = Authorized::<DefinitionMutation>::verify(
        &authority(TENANT)?,
        DefinitionMutation::Register {
            definition: newer.clone(),
            expected_latest: Some(d.digest()?),
        },
    )?;
    let (l, r) = tokio::join!(
        f.store.change(&req, deadline()?),
        f.store.change(&req, deadline()?)
    );
    confirmed(l?)?;
    confirmed(r?)?;
    let mut bad = newer.spec().clone();
    bad.unit = id("different")?;
    assert_eq!(
        f.store
            .change(
                &Authorized::<DefinitionMutation>::verify(
                    &authority(TENANT)?,
                    DefinitionMutation::Register {
                        definition: Definition::new(bad)?,
                        expected_latest: None
                    }
                )?,
                deadline()?
            )
            .await
            .err(),
        Some(Error::Conflict)
    );
    let req = Authorized::<DefinitionMutation>::verify(
        &authority(TENANT)?,
        DefinitionMutation::Register {
            definition: d.clone(),
            expected_latest: None,
        },
    )?;
    assert!(matches!(
        f.store.change(&req, deadline()?).await?,
        Outcome::Replay(_)
    ));
    assert_eq!(f.count().await?, 2);
    Ok(())
}

pub(super) async fn expanded_dimensions(f: &Fixture) -> anyhow::Result<()> {
    let base = definition(TENANT)?;
    let mut spec = base.spec().clone();
    spec.key = id("capacity")?;
    let keys = (0..1024)
        .map(|i| id(&format!("d{i:04}")))
        .collect::<anyhow::Result<std::collections::BTreeSet<_>>>()?;
    spec.dimensions.allowed = keys.clone();
    spec.dimensions.max_count = 1024;
    spec.metric = Metric::State {
        members: keys.clone(),
    };
    let d = Definition::new(spec)?;
    f.register(&d).await?;
    let dimensions = keys
        .into_iter()
        .map(|k| Ok((k, id("v")?)))
        .collect::<anyhow::Result<_>>()?;
    let mut input = sample(&base, "capacity", 123, 1)?.input().clone();
    input.series = Series::new(d.clone(), id("device")?, id("resource")?, dimensions)?;
    input.reading = Reading::Valid(Value::State(id("d1023")?));
    let sample = Sample::new(input)?;
    let b = batch("capacity", vec![sample.clone()])?;
    confirmed(f.write(&b).await?)?;
    let query = Query::new(
        Selection::Exact {
            stream: sample.input().stream.clone(),
            series: sample.input().series.clone(),
        },
        query(&d, QueryMode::History, 1)?.window(),
        query(&d, QueryMode::History, 1)?.budget(),
        QueryMode::History,
    )?;
    let page = f
        .store
        .query(
            &Authorized::<Query>::verify(&authority(TENANT)?, query)?,
            None,
            deadline()?,
        )
        .await?;
    assert_eq!(page.rows.len(), 1);
    assert_eq!(page.rows[0].sample, sample);
    assert!(matches!(f.write(&b).await?, Outcome::Replay(_)));
    Ok(())
}

async fn stage_batch(c: &mut sqlx::PgConnection, batch: &Batch) -> anyhow::Result<()> {
    let s = batch.stream();
    let item = &batch.samples()[0];
    let series = &item.input().series;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(s.scope().tenant().to_string())
        .execute(&mut *c)
        .await?;
    sqlx::query(
        "SELECT * FROM rss_timeseries.admit_batch($1::text::uuid,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)",
    )
    .bind(s.scope().tenant().to_string())
    .bind(s.scope().namespace().as_str())
    .bind(s.source().as_str())
    .bind(s.generation().as_str())
    .bind(batch.id().as_str())
    .bind(batch.digest()?.as_bytes().as_slice())
    .bind(vec![serde_json::to_vec(item)?])
    .bind(vec![item.digest()?.as_bytes().to_vec()])
    .bind(vec![series.digest()?.as_bytes().to_vec()])
    .bind(vec![series.definition().digest()?.as_bytes().to_vec()])
    .bind(60_000_000i64)
    .fetch_one(c)
    .await?;
    Ok(())
}

#[tokio::test]
async fn independent_first_streams_commit_while_another_batch_is_staged() -> anyhow::Result<()> {
    let f = Fixture::new("ts-independent").await?;
    let d = definition(TENANT)?;
    f.register(&d).await?;
    for (name, commit) in [("commit", true), ("rollback", false)] {
        let mut input = sample(&d, name, 20, 1)?.input().clone();
        input.stream = Stream::new(d.spec().scope.clone(), id(name)?, id("generation")?);
        let held = batch(name, vec![Sample::new(input)?])?;
        let mut staged = f.pool.begin().await?;
        stage_batch(&mut staged, &held).await?;
        let other = batch(name, vec![sample(&d, name, 21, 2)?])?;
        assert!(matches!(f.write(&other).await?, Outcome::Accepted(_)));
        let auth = authority(TENANT)?;
        let lookup = Authorized::<ReceiptQuery>::verify(&auth, receipt_query(&held)?)?;
        assert!(matches!(
            f.store.receipt(&lookup, deadline()?).await?,
            Lookup::NotVisible
        ));
        if commit {
            staged.commit().await?;
            assert!(matches!(f.write(&held).await?, Outcome::Replay(_)));
        } else {
            staged.rollback().await?;
            assert!(matches!(f.write(&held).await?, Outcome::Accepted(_)));
        }
    }
    assert_eq!(f.count().await?, 4);
    Ok(())
}
