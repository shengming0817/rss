use super::*;

async fn state(pool: &PgPool, s: &ProjectionScope) -> anyhow::Result<String> {
    Ok(sqlx::query_scalar("SELECT row_to_json(c)::text FROM rss_projection.checkpoints c WHERE tenant_id=$1::uuid AND source_id=$2 AND projection_id=$3 AND generation=$4")
        .bind(s.source().tenant().to_string()).bind(s.source().source()).bind(s.projection()).bind(s.generation()).fetch_one(pool).await?)
}

pub(crate) async fn binding(
    store: &PgStore,
    owner: &PgPool,
    control: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    let s = scope("definition", TENANT)?;
    let a = DefinitionIdentity::new([11; 32]);
    let b = DefinitionIdentity::new([22; 32]);
    store
        .initialize(
            &s,
            &a,
            GenerationStart::beginning(),
            ReplayBound::Live,
            control,
        )
        .await?;
    let claim = store.takeover(&s, &a, control).await?;
    assert_eq!(claim.definition_identity(), &a);
    let execution = store.projection(claim, Counter)?;
    assert_eq!(execution.definition_identity(), &a);
    rejected_changes(store, owner, &s, &a, &b, control).await?;
    // Rejected takeover leaves the existing claim usable.
    execution
        .execute(None, &event(&s, 0, "one", b"one")?, control)
        .await?;
    assert_eq!(count(owner, &s).await?, 1);
    resumed_checkpoint(store, &s, &a, &b, &execution, control).await?;
    identity_drift(store, owner, &s, &a, &b, control).await?;
    invalid_sql_identity(owner).await?;
    concurrency(store, owner, control).await
}

async fn concurrency(
    store: &PgStore,
    owner: &PgPool,
    control: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    let s = scope("definition-race", TENANT)?;
    let a = DefinitionIdentity::new([11; 32]);
    let b = DefinitionIdentity::new([22; 32]);
    let (left, right) = tokio::join!(
        store.initialize(
            &s,
            &a,
            GenerationStart::beginning(),
            ReplayBound::Live,
            control
        ),
        store.initialize(
            &s,
            &b,
            GenerationStart::beginning(),
            ReplayBound::Live,
            control
        )
    );
    let (winner, loser) = if left.is_ok() {
        assert_eq!(right, Err(Error::new(ErrorKind::Conflict)));
        (a, b)
    } else {
        assert_eq!(left, Err(Error::new(ErrorKind::Conflict)));
        right?;
        (b, a)
    };
    let (left, right) = tokio::join!(
        store.initialize(
            &s,
            &winner,
            GenerationStart::beginning(),
            ReplayBound::Live,
            control
        ),
        store.initialize(
            &s,
            &winner,
            GenerationStart::beginning(),
            ReplayBound::Live,
            control
        )
    );
    left?;
    right?;
    let (accepted, rejected) = tokio::join!(
        store.takeover(&s, &winner, control),
        store.takeover(&s, &loser, control)
    );
    assert!(matches!(rejected, Err(e) if e.kind() == ErrorKind::Conflict));
    let execution = store.projection(accepted?, Counter)?;
    execution
        .execute(None, &event(&s, 0, "one", b"one")?, control)
        .await?;
    assert_eq!(count(owner, &s).await?, 1);
    let epoch: i64 = sqlx::query_scalar(
        "SELECT epoch FROM rss_projection.checkpoints WHERE source_id='definition-race'",
    )
    .fetch_one(owner)
    .await?;
    assert_eq!(epoch, 1);
    Ok(())
}

async fn identity_drift(
    store: &PgStore,
    owner: &PgPool,
    s: &ProjectionScope,
    a: &DefinitionIdentity,
    b: &DefinitionIdentity,
    control: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    let execution = store.projection(store.takeover(s, a, control).await?, Counter)?;
    // Deliberate administrator corruption, impossible for the admitted runtime role.
    sqlx::query("UPDATE rss_projection.checkpoints SET definition_identity=$1 WHERE tenant_id=$2::uuid AND source_id='definition'").bind(b.as_bytes().as_slice()).bind(TENANT).execute(owner).await?;
    let before = state(owner, s).await?;
    assert_eq!(
        execution.checkpoint().await,
        Err(Error::new(ErrorKind::Conflict))
    );
    assert_eq!(
        execution
            .execute(
                Some(Position::new(0)?),
                &event(s, 1, "two", b"two")?,
                control
            )
            .await,
        Err(Error::new(ErrorKind::Conflict))
    );
    assert_eq!(before, state(owner, s).await?);
    assert_eq!(count(owner, s).await?, 1);
    sqlx::query("UPDATE rss_projection.checkpoints SET definition_identity=$1 WHERE tenant_id=$2::uuid AND source_id='definition'").bind(a.as_bytes().as_slice()).bind(TENANT).execute(owner).await?;
    Ok(())
}

async fn rejected_changes(
    store: &PgStore,
    owner: &PgPool,
    s: &ProjectionScope,
    a: &DefinitionIdentity,
    b: &DefinitionIdentity,
    control: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    let before = state(owner, s).await?;
    store
        .initialize(
            s,
            a,
            GenerationStart::beginning(),
            ReplayBound::Live,
            control,
        )
        .await?;
    assert_eq!(
        store
            .initialize(
                s,
                b,
                GenerationStart::beginning(),
                ReplayBound::Live,
                control
            )
            .await,
        Err(Error::new(ErrorKind::Conflict))
    );
    assert!(
        matches!(store.takeover(s, b, control).await, Err(e) if e.kind() == ErrorKind::Conflict)
    );
    assert_eq!(before, state(owner, s).await?);
    assert_eq!(count(owner, s).await?, 0);
    Ok(())
}

async fn resumed_checkpoint(
    store: &PgStore,
    s: &ProjectionScope,
    a: &DefinitionIdentity,
    b: &DefinitionIdentity,
    execution: &PgProjection<Counter>,
    control: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    let other = scope("definition", OTHER)?;
    store
        .initialize(
            &other,
            b,
            GenerationStart::beginning(),
            ReplayBound::Live,
            control,
        )
        .await?;
    let other = store.projection(store.takeover(&other, b, control).await?, Counter)?;
    assert_eq!(other.definition_identity(), b);
    let checkpoint = store.external_checkpoint(store.takeover(s, a, control).await?)?;
    assert_eq!(checkpoint.definition_identity(), a);
    assert_eq!(checkpoint.load().await?.position, Some(Position::new(0)?));
    assert_eq!(
        execution.checkpoint().await,
        Err(Error::new(ErrorKind::Fenced))
    );
    Ok(())
}

async fn invalid_sql_identity(owner: &PgPool) -> anyhow::Result<()> {
    for identity in [None, Some(vec![1_u8])] {
        for statement in [
            "SELECT rss_projection.initialize(tenant_id,source_id,projection_id,generation,NULL,false,NULL,ARRAY[]::text[],ARRAY[]::bytea[],$2) FROM rss_projection.checkpoints WHERE tenant_id=$1::uuid AND source_id='definition'",
            "SELECT rss_projection.takeover(tenant_id,source_id,projection_id,generation,worker_token,$2) FROM rss_projection.checkpoints WHERE tenant_id=$1::uuid AND source_id='definition'",
            "SELECT rss_projection.lock_event(tenant_id,source_id,projection_id,generation,epoch,worker_token,position,1,'two',decode(repeat('01',32),'hex'),$2) FROM rss_projection.checkpoints WHERE tenant_id=$1::uuid AND source_id='definition'",
            "SELECT rss_projection.finish_event(tenant_id,source_id,projection_id,generation,epoch,worker_token,position,1,'two',decode(repeat('01',32),'hex'),$2) FROM rss_projection.checkpoints WHERE tenant_id=$1::uuid AND source_id='definition'",
        ] {
            let mut tx = owner.begin().await?;
            sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
                .bind(TENANT)
                .execute(&mut *tx)
                .await?;
            let error = sqlx::query(statement)
                .bind(TENANT)
                .bind(&identity)
                .execute(&mut *tx)
                .await
                .err()
                .ok_or_else(|| anyhow::anyhow!("invalid identity accepted"))?;
            assert_eq!(
                error.as_database_error().and_then(|e| e.code()).as_deref(),
                Some("P1003")
            );
            tx.rollback().await?;
        }
    }
    Ok(())
}
