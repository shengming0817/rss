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
    exec.execute_batch(None, vec![first], control).await?;
    let credentials = || {
        sqlx::query_as::<_,(i64,String)>("SELECT epoch,worker_token::text FROM rss_projection.checkpoints WHERE tenant_id=$1::uuid AND source_id='standalone'").bind(TENANT).fetch_one(owner)
    };
    let (old_epoch, old_token) = credentials().await?;
    store.takeover(&s, &DEFINITION, control).await?;
    let (epoch, token) = credentials().await?;
    let cases = [
        (
            1,
            vec![2, 3],
            vec!["new", "original"],
            epoch,
            &token,
            "P1003",
        ),
        (
            1,
            vec![2, 3],
            vec!["within", "within"],
            epoch,
            &token,
            "P1003",
        ),
        (
            1,
            vec![3, 2],
            vec!["first", "second"],
            epoch,
            &token,
            "P1004",
        ),
        (
            1,
            vec![2, 10],
            vec!["first", "second"],
            epoch,
            &token,
            "P1004",
        ),
        (
            0,
            vec![2, 3],
            vec!["first", "second"],
            epoch,
            &token,
            "P1002",
        ),
        (
            1,
            vec![2, 3],
            vec!["first", "second"],
            old_epoch,
            &token,
            "P1002",
        ),
        (
            1,
            vec![2, 3],
            vec!["first", "second"],
            epoch,
            &old_token,
            "P1002",
        ),
    ];
    for (expected, positions, ids, worker_epoch, worker_token, code) in cases {
        let mut tx = owner.begin().await?;
        sqlx::raw_sql("SET LOCAL ROLE projection_runtime")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
            .bind(TENANT)
            .execute(&mut *tx)
            .await?;
        let error=sqlx::query("SELECT rss_projection.finish_batch(tenant_id,source_id,projection_id,generation,$6,$7::uuid,$2,$3,$4,$5,definition_identity) FROM rss_projection.checkpoints WHERE tenant_id=$1::uuid AND source_id='standalone'")
            .bind(TENANT).bind(i64::from(expected)).bind(positions.iter().map(|&p|i64::from(p)).collect::<Vec<_>>())
            .bind(ids).bind(vec![[1_u8;32],[2_u8;32]]).bind(worker_epoch).bind(worker_token).execute(&mut *tx).await.err().ok_or_else(||anyhow::anyhow!("direct settlement unexpectedly succeeded for {code}"))?;
        assert_eq!(
            error.as_database_error().and_then(|e| e.code()).as_deref(),
            Some(code)
        );
        tx.rollback().await?;
        assert_eq!(snapshot(owner, &s).await?, (Some(1), 1, vec![1], 1));
    }
    Ok(())
}

// Even on a store admitted before DDL drift, an omitted settlement result
// must roll back the first page's already-staged business writes.
pub(super) async fn skips_settlement(
    store: &PgStore,
    owner: &PgPool,
    c: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    let s = scope("strict-page", TENANT)?;
    let rec = Arc::new(Recorder::default());
    let session = worker(store, &s, ReplayBound::Live, rec.clone(), c).await?;
    let page = vec![event(&s, 1, "first", b"work")?];
    sqlx::raw_sql("ALTER FUNCTION rss_projection.finish_batch(uuid,text,text,text,bigint,uuid,bigint,bigint[],text[],bytea[],bytea) STRICT").execute(owner).await?;
    let result = session.execute_batch(None, page, c).await;
    sqlx::raw_sql("ALTER FUNCTION rss_projection.finish_batch(uuid,text,text,text,bigint,uuid,bigint,bigint[],text[],bytea[],bytea) CALLED ON NULL INPUT").execute(owner).await?;
    assert_eq!(
        result.map_err(|e| e.kind()),
        Err(ErrorKind::StorageContract)
    );
    assert_eq!(rec.calls.load(Ordering::SeqCst), 1);
    assert_eq!(snapshot(owner, &s).await?, (None, 0, vec![], 0));
    Ok(())
}
