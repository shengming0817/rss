use super::*;
use tokio::sync::Notify;
struct Gated {
    name: &'static str,
    entered: Arc<Notify>,
    released: Arc<Notify>,
}
impl Step for Gated {
    type Receipt = String;
    fn name(&self) -> &str {
        self.name
    }
    fn receipt_schema(&self) -> &str {
        "receipt.v1"
    }
    async fn execute(&self, _: EffectContext) -> EffectOutcome<String> {
        self.entered.notify_one();
        self.released.notified().await;
        EffectOutcome::Applied(self.name.into())
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
pub(super) async fn fair_arrival(
    store: &PgStore,
    control: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    let tenant = TenantId::parse("43634363-2222-4333-8444-555555555555")?;
    let low = Scope::new(tenant, uuid::Uuid::from_u128(1));
    let high = Scope::new(tenant, uuid::Uuid::from_u128(2));
    let d = definition(&["one", "two", "three", "four", "five"])?;
    let entered = Arc::new(Notify::new());
    let released = Arc::new(Notify::new());
    let gate = Gated {
        name: "two",
        entered: entered.clone(),
        released: released.clone(),
    };
    let executor = Executor::new(
        store.clone(),
        protection()?,
        arrival_registry(d.clone(), gate)?,
        read_budget()?,
    );
    executor
        .register(high, &d, history_capacity()?, control)
        .await?;
    let arrival = async {
        executor
            .register(low, &d, history_capacity()?, control)
            .await?;
        Ok(())
    };
    let budget = SweepBudget::new(2, 8)?;
    let (page, ()) = at_gate(
        Box::pin(executor.run_once(tenant, Some(low), budget, control)),
        &entered,
        &released,
        arrival,
    )
    .await?;
    assert_eq!(page.next_cursor, Some(high));
    assert_eq!(turns(&page)?, [(high, 2, Status::Running)]);
    let end = executor
        .run_once(tenant, page.next_cursor, budget, control)
        .await?;
    assert_eq!(end.next_cursor, None);
    assert!(end.items.is_empty());

    let both = executor
        .run_once(tenant, end.next_cursor, budget, control)
        .await?;
    assert_eq!(
        turns(&both)?,
        [(low, 1, Status::Running), (high, 1, Status::Running)]
    );
    released.notify_one(); // low's second effect
    assert_eq!(executor.run(low, 3, control).await?.advances, 3);
    let last = executor
        .run_once(tenant, None, SweepBudget::new(2, 3)?, control)
        .await?;
    assert_eq!(
        turns(&last)?,
        [(low, 1, Status::Succeeded), (high, 2, Status::Succeeded)]
    );
    Ok(())
}
// Poll the sweep (including its lease renewal) throughout the coordination. A premature
// result should report the actual error or progress immediately, even if no step signalled.
async fn at_gate<R>(
    mut sweep: impl Future<Output = Result<SweepReport, Error>> + Unpin,
    entered: &Notify,
    released: &Notify,
    operation: impl Future<Output = anyhow::Result<R>>,
) -> anyhow::Result<(SweepReport, R)> {
    let coordination = async {
        tokio::select! {
            biased;
            () = entered.notified() => {}
            early = &mut sweep => anyhow::bail!("sweep finished before entering gate: {:?}", early?),
        }
        // Once the step is inside the gate, fencing the old sweep is a valid result even
        // before the new holder receives its claim acknowledgement. Drive both to completion.
        let change = Box::pin(async {
            let result = operation.await;
            released.notify_one();
            result
        });
        let (page, observed) = tokio::join!(sweep, change);
        Ok((page?, observed?))
    };
    tokio::time::timeout(Duration::from_secs(20), Box::pin(coordination)).await?
}

#[tokio::test]
async fn gated_takeover_can_finish_after_old_sweep() -> anyhow::Result<()> {
    let entered = Notify::new();
    let released = Notify::new();
    let fenced = Notify::new();
    let old_done = Notify::new();
    let old_sweep = async {
        entered.notify_one();
        fenced.notified().await;
        old_done.notify_one();
        Ok(SweepReport {
            items: Vec::new(),
            next_cursor: None,
            stop: SweepStop::PageComplete,
        })
    };
    let takeover = async {
        fenced.notify_one();
        old_done.notified().await;
        Ok(())
    };
    let (page, ()) = at_gate(Box::pin(old_sweep), &entered, &released, takeover).await?;
    assert_eq!(page.stop, SweepStop::PageComplete);
    Ok(())
}

fn arrival_registry(d: Definition, gate: Gated) -> Result<Registry, Error> {
    let effects = Arc::new(Effects::default());
    let mut builder = DefinitionBuilder::new(d)?
        .step(Action {
            name: "one",
            fail: false,
            effects: effects.clone(),
        })?
        .step(gate)?;
    for name in ["three", "four", "five"] {
        builder = builder.step(Action {
            name,
            fail: false,
            effects: effects.clone(),
        })?;
    }
    Ok(Registry::builder().register(builder)?.finish())
}
fn turns(page: &SweepReport) -> anyhow::Result<Vec<(Scope, u32, Status)>> {
    page.items
        .iter()
        .map(|item| {
            let report = item.result.as_ref().map_err(Clone::clone)?;
            Ok((item.scope, report.advances, report.head().status()))
        })
        .collect()
}

pub(super) async fn fence_during_effect(
    store: &PgStore,
    owner: &PgPool,
    d: &Definition,
    control: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    let scope = scope("41634163-2222-4333-8444-555555555555")?;
    let entered = Arc::new(Notify::new());
    let released = Arc::new(Notify::new());
    let effects = Arc::new(Effects::default());
    let builder = DefinitionBuilder::new(d.clone())?
        .step(Action {
            name: "one",
            fail: false,
            effects: effects.clone(),
        })?
        .step(Gated {
            name: "two",
            entered: entered.clone(),
            released: released.clone(),
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
        read_budget()?,
    );
    let e = e.with_lease_policy(LeasePolicy::new(Duration::from_millis(300))?);
    e.register(scope, d, history_capacity()?, control).await?;
    let takeover = async {
        tokio::time::sleep(Duration::from_millis(700)).await;
        assert_active_claim_rejected(store, scope, control).await?;
        expire(owner, scope).await?;
        let fresh = store.claim(scope, Duration::from_secs(30), control).await?;
        Ok::<_, anyhow::Error>(fresh)
    };
    let (page, fresh) = at_gate(
        Box::pin(e.run_once(scope.tenant(), None, SweepBudget::new(1, 30)?, control)),
        &entered,
        &released,
        takeover,
    )
    .await?;
    let failure = page.items[0]
        .result
        .as_ref()
        .err()
        .ok_or_else(|| anyhow::anyhow!("expected fenced instance"))?;
    assert_eq!(failure.error.kind(), ErrorKind::Fenced);
    assert_eq!(failure.head().map(HistoryHead::revision), Some(3));
    assert_eq!(failure.advances, 1);
    let snapshot = store.snapshot(&fresh, read_budget()?, control).await?;
    assert_eq!(snapshot.revision(), 3);
    assert_eq!(snapshot.events()[2].kind, EventKind::ForwardIntent);
    assert_eq!(snapshot.events()[2].step, 1);
    assert_eq!(snapshot.receipt(0)?.seq, 1);
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM rss_saga.journal WHERE protected IS NOT NULL AND saga_id=$1",
    )
    .bind(scope.id())
    .fetch_one(owner)
    .await?;
    assert_eq!(count, 1);
    store.release(&fresh, control).await?;
    Ok(())
}
pub(super) async fn admission_drift(
    pool: &PgPool,
    owner: &PgPool,
    control: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    admission_contract::drift(pool, owner, control).await?;
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
            "CREATE FUNCTION rss_saga.test_trigger() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NEW; END $$; CREATE TRIGGER extra_trigger AFTER INSERT ON rss_saga.journal FOR EACH ROW EXECUTE FUNCTION rss_saga.test_trigger()",
            "DROP TRIGGER extra_trigger ON rss_saga.journal; DROP FUNCTION rss_saga.test_trigger()",
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
    // PostgreSQL forbids a LOGGED journal referencing UNLOGGED instances. Keep every FK present
    // and test the valid non-durable combinations, so rejection is caused by persistence drift.
    for (change, restore, expected) in [
        (
            "ALTER TABLE rss_saga.journal SET UNLOGGED",
            "ALTER TABLE rss_saga.journal SET LOGGED",
            vec!["journal"],
        ),
        (
            "ALTER TABLE rss_saga.journal SET UNLOGGED; ALTER TABLE rss_saga.instances SET UNLOGGED",
            "ALTER TABLE rss_saga.instances SET LOGGED; ALTER TABLE rss_saga.journal SET LOGGED",
            vec!["instances", "journal"],
        ),
    ] {
        PgStore::new(pool.clone(), control).await?;
        sqlx::raw_sql(change).execute(owner).await?;
        let rejected = PgStore::new(pool.clone(), control).await;
        let drifted=sqlx::query_scalar::<_,String>("SELECT c.relname::text FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='rss_saga' AND c.relkind='r' AND c.relpersistence<>'p' ORDER BY c.relname").fetch_all(owner).await;
        sqlx::raw_sql(restore).execute(owner).await?;
        assert_eq!(drifted?, expected);
        assert!(matches!(rejected,Err(e) if e.kind()==ErrorKind::StorageContract));
        PgStore::new(pool.clone(), control).await?;
    }
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
