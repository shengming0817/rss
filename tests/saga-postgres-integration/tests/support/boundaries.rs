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
