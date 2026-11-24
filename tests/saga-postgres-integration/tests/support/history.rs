use super::*;
const HISTORY_TENANT: &str = "91919191-2222-4333-8444-555555555555";

pub(super) async fn bounds(
    store: &PgStore,
    owner: &PgPool,
    control: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    let d = definition(&["one"])?;
    let effects = Arc::new(Effects::default());
    let read = ReadBudget::new(HistoryCapacity::new(100, 64 * 1024 * 1024)?, 1024 * 1024)?;
    let executor = Executor::new(
        store.clone(),
        protection()?,
        registry(d.clone(), effects.clone(), false)?,
        read,
    );
    let s = scope(HISTORY_TENANT)?;
    let small = HistoryCapacity::new(4, 32 * 1024 * 1024)?;
    executor.register(s, &d, small, control).await?;
    assert_eq!(
        executor.run(s, 10, control).await?.stop,
        RunStop::HistoryLimited(HistoryLimit::DurableCapacity)
    );
    assert!(
        effects
            .calls
            .lock()
            .map_err(|_| Error::new(ErrorKind::Store))?
            .is_empty()
    );
    assert!(
        store
            .candidates(
                CandidateFilter::Runnable,
                TenantId::parse(HISTORY_TENANT)?,
                None,
                10,
                control
            )
            .await?
            .is_empty()
    );
    registration_capacity(&executor, &d, s, small, control).await?;
    grow_and_settle(&executor, effects.clone(), s, small, control).await?;
    inline_pair(owner, s).await?;
    reject_corrupt_rows(&executor, owner, s, control).await?;
    read_and_byte_bounds(store, &d, effects, s, control).await?;
    capacity_discovery(store, control).await?;
    accounting_contract(owner).await?;
    long_recovery(store, owner, control).await?;

    Ok(())
}

async fn long_recovery(
    store: &PgStore,
    owner: &PgPool,
    control: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    let s = scope(HISTORY_TENANT)?;
    let d = definition(&["one"])?;
    let read = read_budget()?;
    measurement::seed_entries(store, owner, s, &d, 400, read, control).await?;
    let lease = store.claim(s, Duration::from_secs(90_000), control).await?;
    store.renew(&lease, Duration::from_secs(90_001), control).await?;
    let tiny = ReadBudget::new(HistoryCapacity::new(10, 4096)?, PLAINTEXT_BYTES)?;
    assert!(matches!(store.snapshot(&lease, tiny, control).await, Err(e) if e.kind() == ErrorKind::HistoryReadLimit));
    let snapshot = store.snapshot(&lease, read, control).await?;
    assert_eq!(snapshot.definition(), &d);
    assert_eq!(snapshot.revision(), 400);
    store.release(&lease, control).await?;
    verify_candidate_projection(store, &snapshot, s, control).await?;
    let executor = Executor::new(store.clone(), protection()?, registry(d, Arc::new(Effects::default()), false)?, read);
    assert_eq!(executor.run(s, 20, control).await?.head().status(), Status::Succeeded);
    Ok(())
}

async fn inline_pair(owner: &PgPool, s: Scope) -> anyhow::Result<()> {
    let paired: bool = sqlx::query_scalar("SELECT protected IS NOT NULL FROM rss_saga.journal WHERE tenant_id=$1::text::uuid AND saga_id=$2 AND kind='ForwardApplied'").bind(HISTORY_TENANT).bind(s.id()).fetch_one(owner).await?;
    assert!(paired);
    Ok(())
}

async fn read_and_byte_bounds(
    store: &PgStore,
    d: &Definition,
    effects: Arc<Effects>,
    s: Scope,
    control: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    let executor = Executor::new(
        store.clone(),
        protection()?,
        registry(d.clone(), effects.clone(), false)?,
        ReadBudget::new(HistoryCapacity::new(100, 64 * 1024 * 1024)?, 1024 * 1024)?,
    );
    for capacity in [
        HistoryCapacity::new(1, 32 * 1024 * 1024)?,
        HistoryCapacity::new(100, 256)?,
    ] {
        assert_read_limited(store, d, effects.clone(), s, capacity, control).await?;
    }
    let byte_scope = scope(HISTORY_TENANT)?;
    let byte_small = HistoryCapacity::new(100, 5 * EVENT_BYTES + RECEIPT_BYTES - 1)?;
    executor
        .register(byte_scope, d, byte_small, control)
        .await?;
    assert_eq!(
        executor.run(byte_scope, 1, control).await?.stop,
        RunStop::HistoryLimited(HistoryLimit::DurableCapacity)
    );
    Ok(())
}

async fn grow_and_settle(
    executor: &Executor<PgStore, Crypto>,
    effects: Arc<Effects>,
    s: Scope,
    small: HistoryCapacity,
    control: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    let head = executor.history_head(s, control).await?;
    assert_eq!(head.revision(), 0);
    let enlarged = HistoryCapacity::new(5, 32 * 1024 * 1024)?;
    executor
        .extend_history(s, head.revision(), small, enlarged, control)
        .await?;
    assert!(
        matches!(executor.extend_history(s, 0, small, enlarged, control).await, Err(e) if e.kind()==ErrorKind::Conflict)
    );
    effects.unknown_once.store(true, Ordering::SeqCst);
    assert!(
        matches!(executor.run(s, 10, control).await, Err(e) if e.kind()==ErrorKind::EffectUnknown)
    );
    assert_eq!(
        executor.run(s, 10, control).await?.head().status(),
        Status::Succeeded
    );
    Ok(())
}

async fn reject_corrupt_rows(
    executor: &Executor<PgStore, Crypto>,
    owner: &PgPool,
    s: Scope,
    c: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    sqlx::query("UPDATE rss_saga.instances SET history_encoded_bytes=history_encoded_bytes+1 WHERE tenant_id=$1::text::uuid AND saga_id=$2").bind(s.tenant().to_string()).bind(s.id()).execute(owner).await?;
    let rejected = executor.run(s, 1, c).await;
    sqlx::query("UPDATE rss_saga.instances SET history_encoded_bytes=history_encoded_bytes-1 WHERE tenant_id=$1::text::uuid AND saga_id=$2").bind(s.tenant().to_string()).bind(s.id()).execute(owner).await?;
    assert!(matches!(rejected,Err(e) if e.kind()==ErrorKind::Integrity));
    reject_oversized_row(executor, owner, s, c).await
}
async fn reject_oversized_row(
    executor: &Executor<PgStore, Crypto>,
    owner: &PgPool,
    s: Scope,
    c: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    let original:sqlx::types::Json<ProtectedReceipt>=sqlx::query_scalar("SELECT protected FROM rss_saga.journal WHERE tenant_id=$1::text::uuid AND saga_id=$2 AND kind='ForwardApplied'").bind(s.tenant().to_string()).bind(s.id()).fetch_one(owner).await?;
    // Owner corruption after handle admission: SQL must withhold the oversized row before client decoding.
    sqlx::raw_sql("ALTER TABLE rss_saga.journal DROP CONSTRAINT saga_history_journal")
        .execute(owner)
        .await?;
    sqlx::query("UPDATE rss_saga.journal SET protected=jsonb_set(protected,'{ciphertext,bytes}',to_jsonb(array_fill(255,ARRAY[2097153]))) WHERE tenant_id=$1::text::uuid AND saga_id=$2 AND kind='ForwardApplied'").bind(s.tenant().to_string()).bind(s.id()).execute(owner).await?;
    let rejected = executor.run(s, 1, c).await;
    sqlx::query("UPDATE rss_saga.journal SET protected=$3 WHERE tenant_id=$1::text::uuid AND saga_id=$2 AND kind='ForwardApplied'").bind(s.tenant().to_string()).bind(s.id()).bind(original).execute(owner).await?;
    sqlx::raw_sql("ALTER TABLE rss_saga.journal ADD CONSTRAINT saga_history_journal CHECK(rss_saga.valid_journal(kind,seq,attempt,effect_key,protected,encoded_bytes))").execute(owner).await?;
    assert!(matches!(rejected,Err(e) if e.kind()==ErrorKind::HistoryReadLimit));
    Ok(())
}

async fn registration_capacity(
    executor: &Executor<PgStore, Crypto>,
    d: &Definition,
    s: Scope,
    small: HistoryCapacity,
    control: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    executor.register(s, d, small, control).await?;
    for changed in [
        HistoryCapacity::new(5, 32 * 1024 * 1024)?,
        HistoryCapacity::new(4, 33 * 1024 * 1024)?,
    ] {
        assert!(
            matches!(executor.register(s,d,changed,control).await,Err(e) if e.kind()==ErrorKind::Conflict)
        );
        assert_eq!(executor.history_head(s, control).await?.capacity(), small);
    }
    Ok(())
}

async fn assert_read_limited(
    store: &PgStore,
    d: &Definition,
    effects: Arc<Effects>,
    s: Scope,
    capacity: HistoryCapacity,
    c: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    let executor = Executor::new(
        store.clone(),
        protection()?,
        registry(d.clone(), effects, false)?,
        ReadBudget::new(capacity, PLAINTEXT_BYTES)?,
    );
    assert!(matches!(executor.run(s,1,c).await,Err(e) if e.kind()==ErrorKind::HistoryReadLimit));
    assert_eq!(executor.history_head(s, c).await?.revision(), 2);
    Ok(())
}

async fn capacity_discovery(store: &PgStore, c: &Control<'_, Clock>) -> anyhow::Result<()> {
    let tenant = TenantId::parse("63636363-2222-4333-8444-555555555555")?;
    let d = definition(&["one"])?;
    let effects = Arc::new(Effects::default());
    let executor = Executor::new(
        store.clone(),
        protection()?,
        registry(d.clone(), effects.clone(), false)?,
        ReadBudget::new(HistoryCapacity::new(1, 1)?, 1)?,
    );
    let small = HistoryCapacity::new(4, 32 * 1024 * 1024)?;
    let enough = HistoryCapacity::new(5, 32 * 1024 * 1024)?;
    let mut blocked = vec![
        Scope::new(tenant, uuid::Uuid::new_v4()),
        Scope::new(tenant, uuid::Uuid::new_v4()),
    ];
    blocked.sort_by_key(|s| s.id());
    for s in &blocked {
        executor.register(*s, &d, small, c).await?;
    }
    let ready = Scope::new(tenant, uuid::Uuid::new_v4());
    executor.register(ready, &d, enough, c).await?;
    discovery_pages(&executor, tenant, &blocked, c).await?;
    assert_eq!(
        store
            .candidates(CandidateFilter::Runnable, tenant, None, 10, c)
            .await?,
        vec![ready]
    );
    let report = executor
        .run_once(tenant, None, SweepBudget::new(1, 1)?, c)
        .await?;
    assert_eq!(report.items[0].scope, ready);
    assert_eq!(
        report.items[0].result.as_ref().map_err(Clone::clone)?.stop,
        RunStop::HistoryLimited(HistoryLimit::ReadBudget)
    );
    let head = executor.history_head(blocked[0], c).await?;
    executor
        .extend_history(blocked[0], head.revision(), head.capacity(), enough, c)
        .await?;
    assert_eq!(
        executor.capacity_blocked(tenant, None, 10, c).await?,
        vec![blocked[1]]
    );
    assert!(
        effects
            .calls
            .lock()
            .map_err(|_| ErrorKind::Store)?
            .is_empty()
    );
    Ok(())
}
async fn discovery_pages(
    executor: &Executor<PgStore, Crypto>,
    tenant: TenantId,
    blocked: &[Scope],
    c: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    assert_eq!(
        executor.capacity_blocked(tenant, None, 1, c).await?,
        vec![blocked[0]]
    );
    assert_eq!(
        executor
            .capacity_blocked(tenant, Some(blocked[0]), 1, c)
            .await?,
        vec![blocked[1]]
    );
    assert!(
        executor
            .capacity_blocked(tenant, Some(blocked[1]), 1, c)
            .await?
            .is_empty()
    );
    assert!(
        executor
            .capacity_blocked(TenantId::parse(OTHER)?, None, 10, c)
            .await?
            .is_empty()
    );
    discovery_inputs(executor, tenant, blocked[0], c).await?;
    Ok(())
}

async fn discovery_inputs(
    executor: &Executor<PgStore, Crypto>,
    tenant: TenantId,
    first: Scope,
    c: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    assert!(
        matches!(executor.capacity_blocked(TenantId::parse(OTHER)?,Some(first),10,c).await,Err(e) if e.kind()==ErrorKind::Definition)
    );
    assert!(
        matches!(executor.capacity_blocked(tenant,None,0,c).await,Err(e) if e.kind()==ErrorKind::InvalidBudget)
    );
    Ok(())
}

async fn verify_candidate_projection(
    store: &PgStore,
    snapshot: &Snapshot,
    s: Scope,
    c: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    let expected = snapshot.candidate_filter()?;
    for filter in [CandidateFilter::Runnable, CandidateFilter::CapacityBlocked] {
        assert_eq!(
            store
                .candidates(filter, s.tenant(), None, 1000, c)
                .await?
                .contains(&s),
            expected == Some(filter)
        );
    }
    Ok(())
}

async fn accounting_contract(owner: &PgPool) -> anyhow::Result<()> {
    for (bytes, aad, key_ref, key_id) in [
        (0, 0, String::new(), String::new()),
        (1, 0, "k".into(), "i".into()),
        (2, 3, "中\"\\".into(), "键\"\\".into()),
        (2 * 1024 * 1024, 4096, "\"".repeat(1024), "\\".repeat(64)),
    ] {
        let receipt = if bytes == 0 {
            serde_json::Value::Null
        } else {
            serde_json::json!({"ciphertext":{"key_ref":key_ref,"bytes":vec![255;bytes]},
                "key_id":key_id,"digest":vec![0;32],"aad":vec![255;aad],"format":1,"attempt":u32::MAX,"seq":i64::MAX})
        };
        let raw = serde_json::json!({"seq":i64::MAX,"step":0,"attempt":u32::MAX,"kind":if bytes==0 {"ForwardNotApplied"} else {"ForwardApplied"},"receipt":receipt});
        let event: Event = serde_json::from_value(raw.clone())?;
        let charged: i64 = sqlx::query_scalar("SELECT rss_saga.history_charge($1)")
            .bind(sqlx::types::Json(&raw["receipt"]))
            .fetch_one(owner)
            .await?;
        assert_eq!(event.encoded_bytes()?, charged as u64);
    }
    let read = ReadBudget::new(
        HistoryCapacity::new(10000, 2 * 1024 * 1024 * 1024)?,
        2 * 1024 * 1024 * 1024,
    )?;
    for (status, forward, compensation, attempt, pending, last) in [
        ("Ready", 0, None, 0, None, None),
        (
            "Running",
            1023,
            None,
            0,
            Some("ForwardIntent"),
            Some("ForwardIntent"),
        ),
        ("Compensating", 1024, Some(1023), 0, None, Some("Abort")),
        (
            "Compensating",
            1024,
            Some(1023),
            1,
            Some("CompensationIntent"),
            Some("CompensationIntent"),
        ),
        (
            "CompensationFailed",
            1,
            Some(0),
            1,
            None,
            Some("CompensationFailed"),
        ),
        ("Compensating", 1, Some(0), 1, None, Some("Resume")),
        ("Succeeded", 1024, None, 0, None, Some("ForwardApplied")),
        ("Compensated", 1, None, 1, None, Some("CompensationApplied")),
    ] {
        let progress = serde_json::json!({"status":status,"forward":forward,"forwardAttempt":1,"forwardFailures":0,
            "compensation":compensation,"compensationAttempt":attempt,"pending":pending.map(|kind|serde_json::json!({"kind":kind,"step":1023,"attempt":1})),"lastKind":last});
        let reserved: sqlx::types::Json<serde_json::Value> =
            sqlx::query_scalar("SELECT rss_saga.history_reserve($1)")
                .bind(sqlx::types::Json(&progress))
                .fetch_one(owner)
                .await?;
        let entries = reserved.0["entries"].as_u64().ok_or(ErrorKind::Integrity)?;
        let bytes = reserved.0["bytes"].as_u64().ok_or(ErrorKind::Integrity)?;
        let mut head = serde_json::json!({"revision":0,"encodedBytes":0,"progress":progress,
            "capacity":{"maxEntries":entries.max(1),"maxEncodedBytes":bytes.max(1)}});
        let exact: HistoryHead = serde_json::from_value(head.clone())?;
        assert_eq!(exact.reserve()?, (entries, bytes));
        exact.check_admission(read)?;
        if bytes > 1 {
            head["capacity"]["maxEncodedBytes"] = (bytes - 1).into();
            let short: HistoryHead = serde_json::from_value(head)?;
            assert!(
                matches!(short.check_admission(read), Err(e) if e.kind()==ErrorKind::HistoryLimited(HistoryLimit::DurableCapacity))
            );
        }
    }
    Ok(())
}
