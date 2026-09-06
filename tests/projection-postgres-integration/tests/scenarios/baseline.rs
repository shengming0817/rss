use super::*;

pub(crate) async fn baseline_receipts_prevent_cross_start_duplicates(
    store: &PgStore,
    owner: &PgPool,
    control: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    let s = scope("baseline", TENANT)?;
    let original = event(&s, 0, "one", b"one")?;
    let baseline = GenerationStart::after(
        original.position(),
        vec![BaselineReceipt::from_event(&original)],
    )?;
    // The product prepares its read-model baseline; initialization imports matching fact receipts.
    let target = s.clone();
    store
        .local_tx(s.source(), control, move |tx| {
            Box::pin(async move { increment(tx, &target).await })
        })
        .await?;
    store
        .initialize(&s, baseline.clone(), ReplayBound::Live, control)
        .await?;
    let projection = store.projection(store.takeover(&s, control).await?, Counter)?;
    let repeated = event(&s, 1, "one", b"one")?;
    assert_eq!(
        projection
            .execute(Some(original.position()), &repeated, control)
            .await?,
        ApplyOutcome::Duplicate
    );
    assert_eq!(count(owner, &s).await?, 1);
    assert_eq!(
        projection.checkpoint().await?.position,
        Some(repeated.position())
    );
    store
        .initialize(&s, baseline, ReplayBound::Live, control)
        .await?;
    let changed = GenerationStart::after(
        original.position(),
        vec![BaselineReceipt::from_event(&event(
            &s, 0, "one", b"changed",
        )?)],
    )?;
    assert_eq!(
        store
            .initialize(&s, changed, ReplayBound::Live, control)
            .await,
        Err(Error::new(rss_projection::ErrorKind::Conflict))
    );
    Ok(())
}
pub(crate) async fn invalid_baselines_are_atomic(
    store: &PgStore,
    owner: &PgPool,
    control: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    let s = scope("baseline-invalid", TENANT)?;
    let other = scope("baseline-invalid", OTHER)?;
    let baseline = GenerationStart::after(
        Position::new(0)?,
        vec![BaselineReceipt::from_event(&event(
            &other, 0, "one", b"one",
        )?)],
    )?;
    assert_eq!(
        store
            .initialize(&s, baseline, ReplayBound::Live, control)
            .await,
        Err(Error::new(rss_projection::ErrorKind::ScopeMismatch))
    );
    let absent: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM rss_projection.checkpoints WHERE source_id='baseline-invalid'",
    )
    .fetch_one(owner)
    .await?;
    assert_eq!(absent, 0);
    // PostgreSQL rejects the same invalid partial initialization even when bypassing Rust values.
    let mut tx = owner.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(TENANT)
        .execute(&mut *tx)
        .await?;
    assert!(sqlx::query("SELECT rss_projection.initialize($1::uuid,'baseline-invalid','counter','v1',0,false,NULL,ARRAY['one'],ARRAY[NULL::bytea])").bind(TENANT).execute(&mut *tx).await.is_err());
    tx.rollback().await?;
    let absent: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM rss_projection.checkpoints WHERE source_id='baseline-invalid'",
    )
    .fetch_one(owner)
    .await?;
    assert_eq!(absent, 0);
    Ok(())
}
