use super::*;

fn corruptions() -> Vec<(Vec<String>, serde_json::Value)> {
    let mut cases = Vec::new();
    for path in [
        vec!["ciphertext", "bytes", "0"],
        vec!["aad", "0"],
        vec!["digest", "0"],
    ] {
        for value in [
            serde_json::json!(256),
            serde_json::json!(-1),
            serde_json::json!(1.0),
            serde_json::json!(0.5),
            serde_json::json!("1"),
            serde_json::Value::Null,
            serde_json::json!({}),
        ] {
            cases.push((path.iter().map(|p| p.to_string()).collect(), value));
        }
    }
    for field in ["format", "seq", "attempt"] {
        cases.push((vec![field.into()], serde_json::json!("1")));
    }
    cases
}

pub(super) async fn writes(
    store: &PgStore,
    owner: &PgPool,
    pool: &PgPool,
    c: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    let d = definition(&["one"])?;
    let effects = Arc::new(Effects::default());
    effects.unknown_once.store(true, Ordering::SeqCst);
    let s = scope("71717171-2222-4333-8444-555555555555")?;
    let e = Executor::new(
        store.clone(),
        protection()?,
        registry(d.clone(), effects, false)?,
        read_budget()?,
    );
    e.register(s, &d, history_capacity()?, c).await?;
    assert!(matches!(e.run(s,1,c).await,Err(e) if e.kind()==ErrorKind::EffectUnknown));
    let lease = store.claim(s, Duration::from_secs(30), c).await?;
    let mut snapshot = store.snapshot(&lease, read_budget()?, c).await?;
    let before = snapshot.head().clone();
    // Shape-only fixture: poisoned calls are always rolled back; successful recovery seals the real receipt.
    let receipt: ProtectedReceipt = serde_json::from_value(
        serde_json::json!({"ciphertext":{"key_ref":"test-aes-v1","bytes":[0]},"key_id":"integrity-v1","digest":vec![0;32],"aad":[0],"format":1,"attempt":1,"seq":1}),
    )?;
    let event = Event {
        seq: 1,
        step: 0,
        attempt: 1,
        kind: EventKind::ForwardApplied,
        receipt: Some(receipt),
    };
    snapshot.apply(event.clone())?;
    let after = snapshot.head();
    let key = d.effect_key(s, 0, Phase::Forward)?;
    reject_definer(pool, &lease, &before, after, &event, &key).await?;
    store.release(&lease, c).await?;
    assert_eq!(e.run(s, 1, c).await?.status, Status::Succeeded);
    reject_check(owner, s).await?;
    Ok(())
}

pub(super) async fn upgrade(owner: &PgPool) -> anyhow::Result<()> {
    let row: (uuid::Uuid, i32, sqlx::types::Json<serde_json::Value>) = sqlx::query_as(
        "SELECT saga_id,step,protected FROM rss_saga.step_receipts ORDER BY saga_id,step LIMIT 1",
    )
    .fetch_one(owner)
    .await?;
    for (path, value) in corruptions() {
        sqlx::query("UPDATE rss_saga.step_receipts SET protected=jsonb_set(protected,$2,$3) WHERE saga_id=$1 AND step=$4").bind(row.0).bind(path).bind(sqlx::types::Json(value)).bind(row.1).execute(owner).await?;
        let mut conn = owner.acquire().await?;
        sqlx::raw_sql("SET ROLE saga_owner")
            .execute(&mut *conn)
            .await?;
        let result = sqlx::raw_sql(UPGRADE_SQL).execute(&mut *conn).await;
        sqlx::raw_sql("ROLLBACK; RESET ROLE")
            .execute(&mut *conn)
            .await?;
        assert!(
            matches!(result,Err(ref e) if e.as_database_error().is_some_and(|d|d.code().as_deref()==Some("RS003")))
        );
        sqlx::query("UPDATE rss_saga.step_receipts SET protected=$2 WHERE saga_id=$1 AND step=$3")
            .bind(row.0)
            .bind(&row.2)
            .bind(row.1)
            .execute(owner)
            .await?;
    }
    Ok(())
}

async fn reject_definer(
    pool: &PgPool,
    lease: &Lease,
    before: &HistoryHead,
    after: &HistoryHead,
    event: &Event,
    key: &EffectKey,
) -> anyhow::Result<()> {
    let s = lease.scope();
    let original = serde_json::to_value(event)?;
    let mut accepted = Vec::new();
    for (path, value) in corruptions() {
        let mut altered = original.clone();
        let pointer = format!("/receipt/{}", path.join("/"));
        *altered.pointer_mut(&pointer).ok_or(ErrorKind::Integrity)? = value.clone();
        assert!(serde_json::from_value::<Event>(altered.clone()).is_err());
        let mut tx = pool.begin().await?;
        sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
            .bind(s.tenant().to_string())
            .execute(&mut *tx)
            .await?;
        let result = sqlx::query("SELECT rss_saga.commit_event($1,$2,$3,$4,$5,$6,$7)")
            .bind(s.id())
            .bind(lease.token())
            .bind(lease.epoch())
            .bind(sqlx::types::Json(&altered))
            .bind(key.as_bytes().as_slice())
            .bind(sqlx::types::Json(&before))
            .bind(sqlx::types::Json(after))
            .execute(&mut *tx)
            .await;
        tx.rollback().await?;
        if !matches!(result,Err(ref e) if e.as_database_error().is_some_and(|d|d.code().as_deref()==Some("RS003")))
        {
            accepted.push((path, value));
        }
    }
    anyhow::ensure!(
        accepted.is_empty(),
        "definer accepted invalid receipt bytes: {accepted:?}"
    );
    Ok(())
}

async fn reject_check(owner: &PgPool, s: Scope) -> anyhow::Result<()> {
    for (path, value) in corruptions() {
        let result=sqlx::query("UPDATE rss_saga.journal SET protected=jsonb_set(protected,$2,$3) WHERE saga_id=$1 AND kind='ForwardApplied'").bind(s.id()).bind(path).bind(sqlx::types::Json(value)).execute(owner).await;
        assert!(
            matches!(result,Err(ref e) if e.as_database_error().is_some_and(|d|d.code().as_deref()==Some("RS003")))
        );
    }
    Ok(())
}
