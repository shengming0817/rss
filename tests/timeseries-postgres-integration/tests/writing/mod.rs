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
        f.pool.clone(),
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
