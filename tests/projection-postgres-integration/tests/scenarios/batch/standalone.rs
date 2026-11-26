use super::*;

// The public write function must also fence a direct runtime caller that has
// never called lock_batch. Each rejected statement must undo its cursor CAS.
pub(super) async fn verify(
    store: &PgStore,
    owner: &PgPool,
    control: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    let s = scope("standalone", TENANT)?;
    let exec = worker(
        store,
        &s,
        ReplayBound::Through(Some(Position::new(9)?)),
        Arc::default(),
        control,
    )
    .await?;
    let first = event(&s, 1, "original", b"original")?;
    exec.execute_batch(None, vec![first.clone()], control)
        .await?;
    let cases = [
        (1, vec![2, 3], vec!["new", "original"], "P1003"),
        (1, vec![2, 3], vec!["within", "within"], "P1003"),
        (1, vec![3, 2], vec!["first", "second"], "P1004"),
        (1, vec![2, 10], vec!["first", "second"], "P1004"),
        (0, vec![2, 3], vec!["first", "second"], "P1002"),
    ];
    for (expected, positions, ids, code) in cases {
        let mut tx = owner.begin().await?;
        sqlx::raw_sql("SET LOCAL ROLE projection_runtime")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
            .bind(TENANT)
            .execute(&mut *tx)
            .await?;
        let error=sqlx::query("SELECT rss_projection.finish_batch(tenant_id,source_id,projection_id,generation,epoch,worker_token,$2,$3,$4,$5,definition_identity) FROM rss_projection.checkpoints WHERE tenant_id=$1::uuid AND source_id='standalone'")
            .bind(TENANT).bind(i64::from(expected)).bind(positions.iter().map(|&p|i64::from(p)).collect::<Vec<_>>())
            .bind(ids).bind(vec![[1_u8;32],[2_u8;32]]).execute(&mut *tx).await.unwrap_err();
        assert_eq!(
            error.as_database_error().and_then(|e| e.code()).as_deref(),
            Some(code)
        );
        tx.rollback().await?;
        assert_eq!(snapshot(owner, &s).await?, (Some(1), 1, vec![1], 1));
    }
    Ok(())
}
