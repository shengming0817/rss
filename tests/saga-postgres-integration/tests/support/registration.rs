use super::*;
use sqlx::PgConnection;

async fn tenant_tx(
    pool: &PgPool,
    s: Scope,
) -> anyhow::Result<sqlx::Transaction<'static, sqlx::Postgres>> {
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(s.tenant().to_string())
        .execute(&mut *tx)
        .await?;
    Ok(tx)
}

async fn register(conn: &mut PgConnection, s: Scope, d: &Definition) -> anyhow::Result<()> {
    sqlx::query("SELECT rss_saga.register($1,$2,$3)")
        .bind(s.id())
        .bind(sqlx::types::Json(d))
        .bind(sqlx::types::Json(history_capacity()?))
        .execute(conn)
        .await?;
    Ok(())
}

async fn wait_for_competitor(owner: &PgPool, blocker: i32) -> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let blocked: bool = sqlx::query_scalar("SELECT EXISTS(SELECT FROM pg_stat_activity WHERE usename='saga_runtime' AND $1=ANY(pg_blocking_pids(pid)))")
                .bind(blocker).fetch_one(owner).await?;
            if blocked { return anyhow::Ok(()); }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }).await??;
    Ok(())
}

async fn first_registration(
    store: &PgStore,
    pool: &PgPool,
    owner: &PgPool,
    contender: &Definition,
    commit: bool,
    c: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    let first = definition(&["one"])?;
    let a = scope(&uuid::Uuid::new_v4().to_string())?;
    let b = Scope::new(a.tenant(), uuid::Uuid::new_v4());
    let mut tx = tenant_tx(pool, a).await?;
    let blocker: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *tx)
        .await?;
    register(&mut tx, a, &first).await?;
    let (result, observed) = tokio::join!(
        store.register(b, contender, history_capacity()?, c),
        async {
            wait_for_competitor(owner, blocker).await?;
            if commit {
                tx.commit().await?;
            } else {
                tx.rollback().await?;
            }
            anyhow::Ok(())
        }
    );
    observed?;
    let conflict = commit && &first != contender;
    if conflict {
        let error = result
            .err()
            .ok_or_else(|| anyhow::anyhow!("accepted conflicting immutable version"))?;
        assert_eq!(error.kind(), ErrorKind::Conflict);
        assert_eq!(error.diagnostic().and_then(|d| d.sqlstate()), Some("RS002"));
    } else {
        result?;
    }
    let (bodies, ids): (Vec<sqlx::types::Json<Definition>>, Vec<uuid::Uuid>) = sqlx::query_as(
        "SELECT ARRAY(SELECT definition FROM rss_saga.definitions WHERE tenant_id=$1::text::uuid), ARRAY(SELECT saga_id FROM rss_saga.instances WHERE tenant_id=$1::text::uuid)")
        .bind(a.tenant().to_string()).fetch_one(owner).await?;
    assert_eq!(bodies.len(), 1);
    assert_eq!(&bodies[0].0, if commit { &first } else { contender });
    assert_eq!(ids.len(), usize::from(commit) + usize::from(!conflict));
    assert_eq!(ids.contains(&a.id()), commit);
    assert_eq!(ids.contains(&b.id()), !conflict);
    Ok(())
}

pub(super) async fn verify(
    store: &PgStore,
    pool: &PgPool,
    owner: &PgPool,
    c: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    // A pool may inherit REPEATABLE READ. The registering adapter owns the fresh-snapshot protocol.
    let stricter = PgPoolOptions::new()
        .max_connections(2)
        .after_connect(|conn, _| {
            Box::pin(async move {
                sqlx::query("SET default_transaction_isolation='repeatable read'")
                    .execute(conn)
                    .await?;
                Ok(())
            })
        })
        .connect_with((*pool.connect_options()).clone())
        .await?;
    let contender_store = PgStore::new(stricter, c).await?;
    let one = definition(&["one"])?;
    let two = definition(&["one", "two"])?;
    first_registration(&contender_store, pool, owner, &one, true, c).await?;
    first_registration(&contender_store, pool, owner, &two, true, c).await?;
    first_registration(&contender_store, pool, owner, &two, false, c).await?;
    contender_store.close(c).await;
    reuse(store, pool, &one, &two, c).await
}

async fn reuse(
    store: &PgStore,
    pool: &PgPool,
    one: &Definition,
    two: &Definition,
    c: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    let a = scope(&uuid::Uuid::new_v4().to_string())?;
    let b = Scope::new(a.tenant(), uuid::Uuid::new_v4());
    let other = Scope::new(TenantId::parse(&uuid::Uuid::new_v4().to_string())?, a.id());
    let capacity = history_capacity()?;
    for invalid in [
        serde_json::Value::Null,
        serde_json::json!("1"),
        serde_json::json!(0),
        serde_json::json!(4294967296_u64),
    ] {
        let mut tx = tenant_tx(pool, a).await?;
        let mut body = serde_json::to_value(one)?;
        body["steps"][0]["max_failures"] = invalid;
        let rejected = sqlx::query("SELECT rss_saga.register($1,$2,$3)")
            .bind(a.id())
            .bind(sqlx::types::Json(body))
            .bind(sqlx::types::Json(capacity))
            .execute(&mut *tx)
            .await;
        assert!(
            matches!(rejected, Err(e) if e.as_database_error().and_then(|d| d.code()).as_deref() == Some("23514"))
        );
        tx.rollback().await?;
    }
    store.register(a, one, capacity, c).await?;
    store.register(other, two, capacity, c).await?;
    let mut tx = tenant_tx(pool, a).await?;
    register(&mut tx, b, one).await?;
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM rss_saga.definitions WHERE tenant_id=$1::text::uuid",
    )
    .bind(other.tenant().to_string())
    .fetch_one(&mut *tx)
    .await?;
    assert_eq!(count, 0);
    let next = Scope::new(a.tenant(), uuid::Uuid::new_v4());
    tokio::time::timeout(
        Duration::from_secs(5),
        store.register(next, one, capacity, c),
    )
    .await??;
    let denied = sqlx::query("UPDATE rss_saga.definitions SET definition=definition")
        .execute(&mut *tx)
        .await
        .err()
        .ok_or_else(|| anyhow::anyhow!("allowed direct runtime write"))?;
    assert_eq!(
        denied.as_database_error().and_then(|e| e.code()).as_deref(),
        Some("42501")
    );
    tx.rollback().await?;
    let v2 = Definition::new(
        "orders",
        Identity::new(
            one.identity().contract().clone(),
            rss_contract::ContractVersion::from_static_major(2),
            one.identity().schema().clone(),
            one.identity().generation().clone(),
        ),
        two.steps().to_vec(),
    )?;
    assert!(
        matches!(store.register(a,&v2,capacity,c).await,Err(e) if e.kind()==ErrorKind::Conflict)
    );
    let mut tx = tenant_tx(pool, a).await?;
    let versions: Vec<String> = sqlx::query_scalar("SELECT version FROM rss_saga.definitions")
        .fetch_all(&mut *tx)
        .await?;
    assert_eq!(versions, ["v1"]);
    tx.commit().await?;
    store.register(b, &v2, capacity, c).await?;
    let mut expected = [a.id(), b.id(), next.id()];
    expected.sort_unstable();
    let page = store
        .candidates(CandidateFilter::Runnable, a.tenant(), None, 100, c)
        .await?;
    assert_eq!(page.iter().map(|s| s.id()).collect::<Vec<_>>(), expected);
    for (s, d) in [(a, one), (b, &v2), (other, two)] {
        let registry = registry(d.clone(), Arc::new(Effects::default()), false)?;
        let executor = Executor::new(store.clone(), protection()?, registry, read_budget()?);
        assert!(
            store
                .candidates(CandidateFilter::Runnable, s.tenant(), None, 100, c)
                .await?
                .contains(&s)
        );
        assert_eq!(
            executor.run(s, 10, c).await?.head().revision(),
            2 * d.steps().len() as u64
        );
    }
    Ok(())
}
