use super::*;

pub(crate) async fn rejects_dangerous_acl(pool: &PgPool, owner: &PgPool) -> anyhow::Result<()> {
    for (grant, revoke) in [
        (
            "GRANT UPDATE(position,epoch,worker_token) ON rss_projection.checkpoints TO projection_runtime",
            "REVOKE UPDATE(position,epoch,worker_token) ON rss_projection.checkpoints FROM projection_runtime",
        ),
        (
            "GRANT INSERT(position) ON rss_projection.checkpoints TO projection_runtime",
            "REVOKE INSERT(position) ON rss_projection.checkpoints FROM projection_runtime",
        ),
        (
            "GRANT TRIGGER ON rss_projection.events TO projection_runtime",
            "REVOKE TRIGGER ON rss_projection.events FROM projection_runtime",
        ),
        (
            "GRANT projection_owner TO projection_runtime WITH INHERIT FALSE, SET TRUE",
            "REVOKE projection_owner FROM projection_runtime",
        ),
    ] {
        sqlx::raw_sql(grant).execute(owner).await?;
        let adoption = PgStore::new(pool.clone()).await;
        sqlx::raw_sql(revoke).execute(owner).await?;
        assert!(
            matches!(adoption, Err(error) if error.kind() == rss_projection::ErrorKind::StorageContract)
        );
        PgStore::new(pool.clone()).await?;
    }
    isolation_contract(pool, owner).await?;
    required_function_permissions(pool, owner).await
}

pub(crate) async fn borrowed_timeout_rolls_back(
    pool: &PgPool,
    store: &PgStore,
    control: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    let s = scope("borrowed-timeout", TENANT)?;
    let mut holder = pool.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(TENANT)
        .execute(&mut *holder)
        .await?;
    append_in_transaction(&mut holder, s.source(), "holder", b"x", control).await?;
    let mut blocked = pool.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(TENANT)
        .execute(&mut *blocked)
        .await?;
    let clock = ServerWatchdogTimer;
    let cancel = CancellationToken::new();
    let short = Control::new(&clock, Duration::from_millis(80), &cancel);
    let result = append_in_transaction(&mut blocked, s.source(), "blocked", b"x", &short).await;
    assert!(matches!(
        result.err().map(|error| error.kind()),
        Some(ErrorKind::CommitUnknown | ErrorKind::Unavailable)
    ));
    tokio::time::timeout(Duration::from_secs(2), blocked.rollback()).await??;
    holder.rollback().await?;
    assert_eq!(store.high_water(s.source()).await?, None);
    assert_eq!(append(store, &s, "after", b"x", control).await?.get(), 0);
    Ok(())
}

// A paused host timer isolates the database watchdog from the outer cancellation race.
struct ServerWatchdogTimer;
impl Timer for ServerWatchdogTimer {
    fn now(&self) -> Duration {
        Duration::ZERO
    }
    async fn sleep_until(&self, _: Duration) {
        std::future::pending::<()>().await;
    }
}

pub(crate) async fn store_identity(
    pool: &PgPool,
    store: &PgStore,
    control: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    let s = scope("claim-identity", TENANT)?;
    store
        .initialize(
            &s,
            &DEFINITION,
            GenerationStart::beginning(),
            ReplayBound::Live,
            control,
        )
        .await?;
    let second = PgStore::new(pool.clone()).await?;
    assert!(
        matches!(second.projection(store.takeover(&s, &DEFINITION, control).await?, Counter), Err(e) if e.kind() == ErrorKind::ScopeMismatch)
    );
    assert!(
        matches!(second.external_checkpoint(store.takeover(&s, &DEFINITION, control).await?), Err(e) if e.kind() == ErrorKind::ScopeMismatch)
    );
    store.projection(store.takeover(&s, &DEFINITION, control).await?, Counter)?;
    store.external_checkpoint(store.takeover(&s, &DEFINITION, control).await?)?;

    Ok(())
}

pub(crate) async fn bounded_close(
    pool: &PgPool,
    store: &PgStore,
    control: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    let s = scope("closed-pool", TENANT)?;
    // A held checkout must not make close exceed its caller's budget.
    let held = pool.acquire().await?;
    let clock = Clock::new();
    let cancel = CancellationToken::new();
    let short = Control::new(&clock, Duration::from_millis(30), &cancel);
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), store.close(&short)).await?,
        CloseOutcome::Deadline
    );
    assert!(pool.is_closed());
    assert!(matches!(pool.acquire().await, Err(sqlx::Error::PoolClosed)));
    let error = store
        .high_water(s.source())
        .await
        .err()
        .ok_or_else(|| anyhow::anyhow!("closed pool served read"))?;
    assert_eq!(error.kind(), ErrorKind::StorageContract);
    assert_eq!(
        error
            .diagnostic()
            .ok_or_else(|| anyhow::anyhow!("missing checkout evidence"))?
            .phase(),
        Phase::Acquire
    );
    cancel.cancel();
    assert_eq!(store.close(&short).await, CloseOutcome::Cancelled);
    drop(held);
    assert_eq!(store.close(control).await, CloseOutcome::Drained);
    Ok(())
}

pub(crate) async fn application_error_cannot_claim_settlement(
    store: &PgStore,
    control: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    let s = scope("application-error", TENANT)?;
    let source = s.source().clone();
    let result: Result<(), Error> = store.local_tx(s.source(), control, move |tx| Box::pin(async move {
        tx.append(&source, "rolled-back", b"x").await?;
        tx.with_connection(|conn| Box::pin(async move {
            sqlx::raw_sql("DO $$ BEGIN RAISE EXCEPTION 'password=private-value' USING ERRCODE='P1002'; END $$").execute(conn).await?;
            Ok(())
        })).await
    })).await;
    let error = result
        .err()
        .ok_or_else(|| anyhow::anyhow!("application SQL succeeded"))?;
    assert_eq!(error.kind(), ErrorKind::Rejected);
    let diagnostic = error
        .diagnostic()
        .ok_or_else(|| anyhow::anyhow!("missing SQL evidence"))?;
    assert_eq!(diagnostic.phase(), Phase::Application);
    assert_eq!(diagnostic.sqlstate(), Some("P1002"));
    assert!(!format!("{error:?} {error}").contains("private-value"));
    let source = std::error::Error::source(&error)
        .ok_or_else(|| anyhow::anyhow!("missing redacted evidence"))?;
    assert!(source.source().is_none());
    assert!(!format!("{source:?} {source}").contains("private-value"));
    assert_eq!(store.high_water(s.source()).await?, None);
    Ok(())
}

async fn required_function_permissions(pool: &PgPool, owner: &PgPool) -> anyhow::Result<()> {
    for (revoke, grant) in [
        (
            "REVOKE EXECUTE ON FUNCTION rss_projection.initialize(uuid,text,text,text,bigint,boolean,bigint,text[],bytea[],bytea) FROM projection_runtime",
            "GRANT EXECUTE ON FUNCTION rss_projection.initialize(uuid,text,text,text,bigint,boolean,bigint,text[],bytea[],bytea) TO projection_runtime",
        ),
        (
            "REVOKE EXECUTE ON FUNCTION rss_projection.takeover(uuid,text,text,text,uuid,bytea) FROM projection_runtime",
            "GRANT EXECUTE ON FUNCTION rss_projection.takeover(uuid,text,text,text,uuid,bytea) TO projection_runtime",
        ),
        (
            "REVOKE EXECUTE ON FUNCTION rss_projection.lock_event(uuid,text,text,text,bigint,uuid,bigint,bigint,text,bytea,bytea) FROM projection_runtime",
            "GRANT EXECUTE ON FUNCTION rss_projection.lock_event(uuid,text,text,text,bigint,uuid,bigint,bigint,text,bytea,bytea) TO projection_runtime",
        ),
        (
            "REVOKE EXECUTE ON FUNCTION rss_projection.finish_event(uuid,text,text,text,bigint,uuid,bigint,bigint,text,bytea,bytea) FROM projection_runtime",
            "GRANT EXECUTE ON FUNCTION rss_projection.finish_event(uuid,text,text,text,bigint,uuid,bigint,bigint,text,bytea,bytea) TO projection_runtime",
        ),
    ] {
        sqlx::raw_sql(revoke).execute(owner).await?;
        let adoption = PgStore::new(pool.clone()).await;
        sqlx::raw_sql(grant).execute(owner).await?;
        assert!(
            matches!(adoption, Err(error) if error.kind() == ErrorKind::StorageContract),
            "missing EXECUTE must reject store admission"
        );
        PgStore::new(pool.clone()).await?;
    }
    Ok(())
}

// F4.1: each drift must fail its own admission check, then restore the supported schema.
async fn isolation_contract(pool: &PgPool, owner: &PgPool) -> anyhow::Result<()> {
    for (change, restore) in [
        (
            "GRANT USAGE ON SCHEMA rss_projection TO PUBLIC",
            "REVOKE USAGE ON SCHEMA rss_projection FROM PUBLIC",
        ),
        (
            "GRANT EXECUTE ON FUNCTION rss_projection.append_event(uuid,text,text,bytea) TO PUBLIC",
            "REVOKE EXECUTE ON FUNCTION rss_projection.append_event(uuid,text,text,bytea) FROM PUBLIC",
        ),
        (
            "GRANT SELECT ON rss_projection.events TO PUBLIC",
            "REVOKE SELECT ON rss_projection.events FROM PUBLIC",
        ),
        (
            "GRANT SELECT(position) ON rss_projection.events TO PUBLIC",
            "REVOKE SELECT(position) ON rss_projection.events FROM PUBLIC",
        ),
    ] {
        assert_drift(pool, owner, change, restore).await?;
    }
    for table in ["sources", "events", "checkpoints", "receipts"] {
        let create = format!(
            "CREATE POLICY tenant_scope ON rss_projection.{table} USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid)"
        );
        let drop_policy = format!("DROP POLICY tenant_scope ON rss_projection.{table}");
        for replacement in [
            "",
            "CREATE POLICY tenant_scope ON {table} USING(true) WITH CHECK(true)",
            "CREATE POLICY tenant_scope ON {table} AS RESTRICTIVE USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid)",
            "CREATE POLICY tenant_scope ON {table} FOR SELECT USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid)",
            "CREATE POLICY tenant_scope ON {table} TO projection_runtime USING(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid)",
        ] {
            let replacement = replacement.replace("{table}", &format!("rss_projection.{table}"));
            let restore = if replacement.is_empty() {
                create.clone()
            } else {
                format!("{drop_policy}; {create}")
            };
            assert_drift(
                pool,
                owner,
                &format!("{drop_policy}; {replacement}"),
                &restore,
            )
            .await?;
        }
        assert_drift(
            pool,
            owner,
            &format!("CREATE POLICY extra ON rss_projection.{table} USING(true)"),
            &format!("DROP POLICY extra ON rss_projection.{table}"),
        )
        .await?;
        assert_drift(pool, owner,
            &format!("ALTER POLICY tenant_scope ON rss_projection.{table} WITH CHECK(true)"),
            &format!("ALTER POLICY tenant_scope ON rss_projection.{table} WITH CHECK(tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid)")).await?;
    }
    // Independent maintenance roles and a restricted inherited group remain supported.
    sqlx::raw_sql("CREATE ROLE projection_reader NOLOGIN; CREATE ROLE projection_maintenance NOLOGIN; GRANT USAGE ON SCHEMA rss_projection TO projection_reader; GRANT SELECT ON ALL TABLES IN SCHEMA rss_projection TO projection_reader; GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA rss_projection TO projection_reader; GRANT projection_reader TO projection_runtime; GRANT UPDATE ON rss_projection.events TO projection_maintenance; REVOKE SELECT ON ALL TABLES IN SCHEMA rss_projection FROM projection_runtime").execute(owner).await?;
    let admitted = PgStore::new(pool.clone()).await;
    sqlx::raw_sql("GRANT SELECT ON ALL TABLES IN SCHEMA rss_projection TO projection_runtime; REVOKE projection_reader FROM projection_runtime; DROP OWNED BY projection_reader, projection_maintenance; DROP ROLE projection_reader, projection_maintenance").execute(owner).await?;
    admitted?;
    Ok(())
}
async fn assert_drift(
    pool: &PgPool,
    owner: &PgPool,
    change: &str,
    restore: &str,
) -> anyhow::Result<()> {
    // SQL comes only from closed test cases and the bundled migration.
    sqlx::raw_sql(sqlx::AssertSqlSafe(change))
        .execute(owner)
        .await?;
    let admitted = PgStore::new(pool.clone()).await;
    sqlx::raw_sql(sqlx::AssertSqlSafe(restore))
        .execute(owner)
        .await?;
    assert!(
        matches!(admitted, Err(e) if e.kind()==ErrorKind::StorageContract),
        "accepted drift: {change}"
    );
    PgStore::new(pool.clone()).await?;
    Ok(())
}

pub(crate) async fn application_lock_timeout_rolls_back(
    store: &PgStore,
    owner: &PgPool,
    control: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    let s = scope("classification-lock", TENANT)?;
    let mut holder = owner.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(2374)")
        .execute(&mut *holder)
        .await?;
    let source = s.source().clone();
    let result: Result<(), Error> = store
        .local_tx(s.source(), control, move |tx| {
            Box::pin(async move {
                tx.append(&source, "must-roll-back", b"secret").await?;
                tx.with_connection(|conn| {
                    Box::pin(async move {
                        sqlx::query("SELECT set_config('lock_timeout','20ms',true)")
                            .execute(&mut *conn)
                            .await?;
                        sqlx::query("SELECT pg_advisory_xact_lock(2374)")
                            .execute(conn)
                            .await?;
                        Ok(())
                    })
                })
                .await
            })
        })
        .await;
    holder.rollback().await?;
    let error = result
        .err()
        .ok_or_else(|| anyhow::anyhow!("lock unexpectedly acquired"))?;
    assert_eq!(error.kind(), ErrorKind::Unavailable);
    assert_eq!(error.diagnostic().and_then(|d| d.sqlstate()), Some("55P03"));
    assert_eq!(
        error.diagnostic().map(|d| d.phase()),
        Some(Phase::Application)
    );
    assert_eq!(store.high_water(s.source()).await?, None);
    Ok(())
}
