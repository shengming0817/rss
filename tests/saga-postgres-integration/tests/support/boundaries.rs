use super::*;
use tokio::sync::Notify;
struct Gated {
    entered: Arc<Notify>,
    released: Arc<Notify>,
}
impl Step for Gated {
    type Receipt = String;
    fn name(&self) -> &str {
        "one"
    }
    fn receipt_schema(&self) -> &str {
        "receipt.v1"
    }
    async fn execute(&self, _: EffectContext) -> EffectOutcome<String> {
        self.entered.notify_one();
        self.released.notified().await;
        EffectOutcome::Applied("one".into())
    }
    async fn probe(&self, _: EffectContext) -> ProbeOutcome<String> {
        ProbeOutcome::Unknown
    }
    async fn compensate(&self, _: EffectContext, _: String) -> EffectOutcome<()> {
        EffectOutcome::Unknown
    }
    async fn probe_compensation(&self, _: EffectContext, _: String) -> ProbeOutcome<()> {
        ProbeOutcome::Unknown
    }
}
pub(super) async fn fence_during_effect(
    store: &PgStore,
    owner: &PgPool,
    d: &Definition,
    control: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    let scope = scope(TENANT)?;
    let entered = Arc::new(Notify::new());
    let released = Arc::new(Notify::new());
    let effects = Arc::new(Effects::default());
    let builder = DefinitionBuilder::new(d.clone())?
        .step(Gated {
            entered: entered.clone(),
            released: released.clone(),
        })?
        .step(Action {
            name: "two",
            fail: false,
            effects: effects.clone(),
        })?
        .step(Action {
            name: "three",
            fail: false,
            effects,
        })?;
    let e = Executor::new(
        store.clone(),
        protection()?,
        Registry::builder().register(builder)?.finish(),
    );
    let e = e.with_lease_policy(LeasePolicy::new(Duration::from_millis(300))?);
    e.register(scope, d, control).await?;
    let takeover = async {
        entered.notified().await;
        tokio::time::sleep(Duration::from_millis(700)).await;
        assert_active_claim_rejected(store, scope, control).await?;
        expire(owner, scope).await?;
        let fresh = store.claim(scope, Duration::from_secs(30), control).await?;
        released.notify_one();
        Ok::<_, anyhow::Error>(fresh)
    };
    let (old, fresh) = tokio::join!(e.run(scope, 30, control), takeover);
    assert!(matches!(old, Err(ref failure) if failure.kind()==rss_saga::ErrorKind::Fenced));
    let fresh = fresh?;
    let snapshot = store.snapshot(&fresh, control).await?;
    assert_eq!(snapshot.revision(), 1);
    assert_eq!(snapshot.events()[0].kind, EventKind::ForwardIntent);
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM rss_saga.step_receipts WHERE saga_id=$1")
            .bind(scope.id())
            .fetch_one(owner)
            .await?;
    assert_eq!(count, 0);
    store.release(&fresh, control).await?;
    Ok(())
}
pub(super) async fn admission_drift(
    pool: &PgPool,
    owner: &PgPool,
    control: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    reachable_and_logged(pool, owner, control).await?;
    for (break_sql, restore_sql) in [
        (
            "GRANT TRIGGER ON rss_saga.journal TO saga_runtime",
            "REVOKE TRIGGER ON rss_saga.journal FROM saga_runtime",
        ),
        (
            "GRANT UPDATE (revision) ON rss_saga.instances TO saga_runtime",
            "REVOKE UPDATE (revision) ON rss_saga.instances FROM saga_runtime",
        ),
        (
            "CREATE TRIGGER extra_trigger AFTER INSERT ON rss_saga.journal FOR EACH ROW EXECUTE FUNCTION rss_saga.assert_receipt_pair()",
            "DROP TRIGGER extra_trigger ON rss_saga.journal",
        ),
        (
            "DROP TRIGGER receipt_pair ON rss_saga.journal; CREATE CONSTRAINT TRIGGER receipt_pair AFTER UPDATE ON rss_saga.journal DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION rss_saga.assert_receipt_pair()",
            "DROP TRIGGER receipt_pair ON rss_saga.journal; CREATE CONSTRAINT TRIGGER receipt_pair AFTER INSERT ON rss_saga.journal DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION rss_saga.assert_receipt_pair()",
        ),
        (
            "GRANT UPDATE ON rss_saga.instances TO saga_runtime",
            "REVOKE UPDATE ON rss_saga.instances FROM saga_runtime",
        ),
        (
            "ALTER TABLE rss_saga.instances DISABLE ROW LEVEL SECURITY",
            "ALTER TABLE rss_saga.instances ENABLE ROW LEVEL SECURITY",
        ),
        (
            "ALTER TABLE rss_saga.journal DISABLE TRIGGER receipt_pair",
            "ALTER TABLE rss_saga.journal ENABLE TRIGGER receipt_pair",
        ),
        (
            "ALTER POLICY tenant ON rss_saga.journal USING (true) WITH CHECK (true)",
            "ALTER POLICY tenant ON rss_saga.journal USING (tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid) WITH CHECK (tenant_id=nullif(current_setting('rss.tenant_id',true),'')::uuid)",
        ),
    ] {
        sqlx::raw_sql(break_sql).execute(owner).await?;
        let result = PgStore::new(pool.clone(), control).await;
        sqlx::raw_sql(restore_sql).execute(owner).await?;
        assert!(
            matches!(result, Err(ref failure) if failure.kind()==rss_saga::ErrorKind::StorageContract)
        );
    }
    Ok(())
}

// F4.2: a non-owner role avoids the pre-existing owner membership rejection.
async fn reachable_and_logged(
    pool: &PgPool,
    owner: &PgPool,
    control: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    sqlx::raw_sql("CREATE ROLE saga_escalation NOLOGIN; GRANT saga_escalation TO saga_runtime WITH INHERIT FALSE, SET TRUE").execute(owner).await?;
    let result = reachable_grants(pool, owner, control).await;
    sqlx::raw_sql("REVOKE saga_escalation FROM saga_runtime; DROP OWNED BY saga_escalation; DROP ROLE saga_escalation").execute(owner).await?;
    result?;
    logged_tables(pool, owner, control).await
}
async fn logged_tables(
    pool: &PgPool,
    owner: &PgPool,
    control: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    // Detach incoming fixture FKs so exactly one relation can be UNLOGGED at a time.
    // PostgreSQL supplies quoted DDL and the original definitions; no second migration copy.
    for table in ["step_receipts", "journal", "instances"] {
        let incoming: Vec<(String, String)> = sqlx::query_as("SELECT format('ALTER TABLE %s DROP CONSTRAINT %I',conrelid::regclass,conname), format('ALTER TABLE %s ADD CONSTRAINT %I %s',conrelid::regclass,conname,pg_get_constraintdef(oid)) FROM pg_constraint WHERE contype='f' AND confrelid=to_regclass($1)")
            .bind(format!("rss_saga.{table}")).fetch_all(owner).await?;
        for (detach, _) in &incoming {
            sqlx::raw_sql(sqlx::AssertSqlSafe(detach.as_str()))
                .execute(owner)
                .await?;
        }
        let result = single_unlogged(pool, owner, control, table).await;
        for (_, restore) in &incoming {
            sqlx::raw_sql(sqlx::AssertSqlSafe(restore.as_str()))
                .execute(owner)
                .await?;
        }
        result?;
        PgStore::new(pool.clone(), control).await?;
    }
    Ok(())
}
async fn single_unlogged(
    pool: &PgPool,
    owner: &PgPool,
    control: &Control<'_, Clock>,
    table: &str,
) -> anyhow::Result<()> {
    PgStore::new(pool.clone(), control).await?;
    // Identifier is selected exclusively from the closed fixture table list above.
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
        "ALTER TABLE rss_saga.{table} SET UNLOGGED"
    )))
    .execute(owner)
    .await?;
    let rejected = PgStore::new(pool.clone(), control).await;
    let drifted = sqlx::query_scalar::<_, String>("SELECT c.relname::text FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='rss_saga' AND c.relkind='r' AND c.relpersistence<>'p'").fetch_all(owner).await;
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
        "ALTER TABLE rss_saga.{table} SET LOGGED"
    )))
    .execute(owner)
    .await?;
    anyhow::ensure!(
        drifted? == [table],
        "persistence case must isolate its target"
    );
    anyhow::ensure!(
        matches!(rejected, Err(e) if e.kind()==ErrorKind::StorageContract),
        "accepted unlogged {table}"
    );
    PgStore::new(pool.clone(), control).await?;
    Ok(())
}
async fn reachable_grants(
    pool: &PgPool,
    owner: &PgPool,
    control: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    PgStore::new(pool.clone(), control).await?;
    for (change, restore) in [
        (
            "GRANT UPDATE ON rss_saga.instances TO saga_escalation",
            "REVOKE UPDATE ON rss_saga.instances FROM saga_escalation",
        ),
        (
            "GRANT UPDATE(revision) ON rss_saga.instances TO saga_escalation",
            "REVOKE UPDATE(revision) ON rss_saga.instances FROM saga_escalation",
        ),
        (
            "GRANT CREATE ON SCHEMA rss_saga TO saga_escalation",
            "REVOKE CREATE ON SCHEMA rss_saga FROM saga_escalation",
        ),
        (
            "ALTER ROLE saga_escalation BYPASSRLS",
            "ALTER ROLE saga_escalation NOBYPASSRLS",
        ),
        (
            "ALTER ROLE saga_escalation CREATEROLE",
            "ALTER ROLE saga_escalation NOCREATEROLE",
        ),
    ] {
        sqlx::raw_sql(change).execute(owner).await?;
        let rejected = PgStore::new(pool.clone(), control).await;
        sqlx::raw_sql(restore).execute(owner).await?;
        anyhow::ensure!(
            matches!(rejected, Err(e) if e.kind()==ErrorKind::StorageContract),
            "accepted reachable privilege: {change}"
        );
        PgStore::new(pool.clone(), control).await?;
    }
    Ok(())
}
