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
        RunStop::HistoryLimited
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
            .candidates(TenantId::parse(HISTORY_TENANT)?, None, 10, control)
            .await?
            .is_empty()
    );
    registration_capacity(&executor, &d, s, small, control).await?;
    grow_and_settle(&executor, effects.clone(), s, small, control).await?;
    inline_pair(owner, s).await?;
    reject_corrupt_rows(&executor, owner, s, control).await?;
    read_and_byte_bounds(store, &d, effects, s, control).await?;

    Ok(())
}

pub(super) async fn upgrade(
    owner: &PgPool,
    pool: &PgPool,
    control: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    let tenant = "81818181-2222-4333-8444-555555555555";
    let d = definition(&["one", "two", "three"])?;
    let store = PgStore::new(pool.clone(), control).await?;
    let read = ReadBudget::new(
        HistoryCapacity::new(2000, 64 * 1024 * 1024)?,
        4 * 1024 * 1024,
    )?;
    let effects = Arc::new(Effects::default());
    let mut captured = Vec::new();
    for kind in 0..3 {
        captured.push(capture_case(&store, &d, effects.clone(), read, kind, control).await?);
    }
    let long = scope(tenant)?;
    let events = (0..400)
        .map(|seq| Event {
            seq,
            step: 0,
            attempt: (seq / 2 + 1) as u32,
            kind: if seq % 2 == 0 {
                EventKind::ForwardIntent
            } else {
                EventKind::ForwardProbeNotApplied
            },
            receipt: None,
        })
        .collect();
    captured.push((long, events));
    seed_v1(owner, &d, &captured).await?;
    receipt_domain::upgrade(owner).await?;
    // Reconstruct the same committed V1 history to exclude failed-upgrade bloat from measurement.
    seed_v1(owner, &d, &captured).await?;
    install_upgrade(owner, pool, control).await?;
    let store = PgStore::new(pool.clone(), control).await?;
    verify_upgraded(&store, &d, effects, read, &captured, control).await?;

    Ok(())
}

async fn inline_pair(owner: &PgPool, s: Scope) -> anyhow::Result<()> {
    let paired: bool = sqlx::query_scalar("SELECT protected IS NOT NULL FROM rss_saga.journal WHERE tenant_id=$1::text::uuid AND saga_id=$2 AND kind='ForwardApplied'").bind(HISTORY_TENANT).bind(s.id()).fetch_one(owner).await?;
    assert!(paired);
    let old_table: bool =
        sqlx::query_scalar("SELECT to_regclass('rss_saga.step_receipts') IS NULL")
            .fetch_one(owner)
            .await?;
    assert!(old_table);
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
    let tiny = Executor::new(
        store.clone(),
        protection()?,
        registry(d.clone(), effects.clone(), false)?,
        ReadBudget::new(HistoryCapacity::new(1, 256)?, 1024 * 1024)?,
    );
    assert!(matches!(tiny.run(s,1,control).await,Err(e) if e.kind()==ErrorKind::HistoryReadLimit));
    assert_eq!(tiny.history_head(s, control).await?.revision(), 2);
    let byte_scope = scope(HISTORY_TENANT)?;
    let byte_small = HistoryCapacity::new(100, 5 * EVENT_BYTES + RECEIPT_BYTES - 1)?;
    executor
        .register(byte_scope, d, byte_small, control)
        .await?;
    assert_eq!(
        executor.run(byte_scope, 1, control).await?.stop,
        RunStop::HistoryLimited
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

async fn seed_v1(
    owner: &PgPool,
    d: &Definition,
    captured: &[(Scope, Vec<Event>)],
) -> anyhow::Result<()> {
    // Dedicated disposable fixture only: reconstruct V1 data through its original writer, then retire that writer.
    let mut connection = owner.acquire().await?;
    sqlx::raw_sql("DROP SCHEMA rss_saga CASCADE; SET ROLE saga_owner")
        .execute(&mut *connection)
        .await?;
    sqlx::raw_sql(include_str!(
        "../../../../crates/saga-postgres/migrations/0001_create_saga.sql"
    ))
    .execute(&mut *connection)
    .await?;
    sqlx::raw_sql("RESET ROLE; GRANT USAGE ON SCHEMA rss_saga TO saga_runtime; GRANT SELECT ON ALL TABLES IN SCHEMA rss_saga TO saga_runtime; GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA rss_saga TO saga_runtime").execute(&mut *connection).await?;
    for (s, events) in captured {
        sqlx::query("SELECT set_config('rss.tenant_id',$1,false)")
            .bind(s.tenant().to_string())
            .execute(&mut *connection)
            .await?;
        sqlx::query("SELECT rss_saga.register($1,$2)")
            .bind(s.id())
            .bind(sqlx::types::Json(&d))
            .execute(&mut *connection)
            .await?;
        let token = uuid::Uuid::new_v4();
        let epoch: i64 = sqlx::query_scalar("SELECT rss_saga.claim($1,$2,86400000)")
            .bind(s.id())
            .bind(token)
            .fetch_one(&mut *connection)
            .await?;
        for event in events {
            sqlx::query("SELECT rss_saga.commit_event($1,$2,$3,$4,$5)")
                .bind(s.id())
                .bind(token)
                .bind(epoch)
                .bind(sqlx::types::Json(event))
                .bind(
                    d.effect_key(*s, event.step, event.kind.phase())?
                        .as_bytes()
                        .as_slice(),
                )
                .execute(&mut *connection)
                .await?;
        }
        sqlx::query("SELECT rss_saga.lease($1,$2,$3,0)")
            .bind(s.id())
            .bind(token)
            .bind(epoch)
            .execute(&mut *connection)
            .await?;
    }
    Ok(())
}

async fn capture_case(
    store: &PgStore,
    d: &Definition,
    effects: Arc<Effects>,
    read: ReadBudget,
    kind: u8,
    control: &Control<'_, Clock>,
) -> anyhow::Result<(Scope, Vec<Event>)> {
    let tenant = "81818181-2222-4333-8444-555555555555";
    let s = scope(tenant)?;
    effects.unknown_once.store(kind == 0, Ordering::SeqCst);
    effects.fail_undo.store(kind == 1, Ordering::SeqCst);
    let executor = Executor::new(
        store.clone(),
        protection()?,
        registry(d.clone(), effects.clone(), kind == 1)?,
        read,
    );
    executor.register(s, d, read.history(), control).await?;
    let result = executor.run(s, 30, control).await;
    if kind == 0 {
        assert!(matches!(result,Err(e) if e.kind()==ErrorKind::EffectUnknown));
    } else {
        assert_eq!(
            result?.head().status(),
            if kind == 1 {
                Status::CompensationFailed
            } else {
                Status::Succeeded
            }
        );
    }
    let lease = store.claim(s, Duration::from_secs(30), control).await?;
    let snapshot = store.snapshot(&lease, read, control).await?;
    let captured = (s, snapshot.events().to_vec());
    store.release(&lease, control).await?;
    Ok(captured)
}

async fn verify_pending(
    executor: &Executor<PgStore, Crypto>,
    s: Scope,
    _head: HistoryHead,
    read: ReadBudget,
    control: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    let settled = executor.run(s, 1, control).await?;
    assert_eq!(settled.head().revision(), 2);
    assert_eq!(settled.head().status(), Status::Running);
    let current = executor.history_head(s, control).await?;
    executor
        .extend_history(
            s,
            current.revision(),
            current.capacity(),
            read.history(),
            control,
        )
        .await?;
    assert_eq!(
        executor.run(s, 20, control).await?.head().status(),
        Status::Succeeded
    );

    Ok(())
}

async fn verify_paused(
    executor: &Executor<PgStore, Crypto>,
    s: Scope,
    head: HistoryHead,
    read: ReadBudget,
    control: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    assert_eq!(
        executor.resume(s, head.revision(), 20, control).await?.stop,
        RunStop::HistoryLimited
    );
    executor
        .extend_history(s, head.revision(), head.capacity(), read.history(), control)
        .await?;
    assert_eq!(
        executor
            .resume(s, head.revision(), 20, control)
            .await?
            .head()
            .status(),
        Status::Compensated
    );

    Ok(())
}

async fn verify_terminal(
    executor: &Executor<PgStore, Crypto>,
    s: Scope,
    _head: HistoryHead,
    _read: ReadBudget,
    control: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    assert_eq!(
        executor.run(s, 1, control).await?.head().status(),
        Status::Succeeded
    );

    Ok(())
}

async fn verify_long(
    executor: &Executor<PgStore, Crypto>,
    d: &Definition,
    effects: Arc<Effects>,
    s: Scope,
    head: HistoryHead,
    read: ReadBudget,
    control: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    let store = executor.store();
    let tiny = Executor::new(
        store.clone(),
        protection()?,
        registry(d.clone(), effects.clone(), false)?,
        ReadBudget::new(HistoryCapacity::new(10, 4096)?, 3 * 1024 * 1024)?,
    );
    assert!(matches!(tiny.run(s,1,control).await,Err(e) if e.kind()==ErrorKind::HistoryReadLimit));
    assert_eq!(tiny.history_head(s, control).await?.revision(), 400);
    tiny.extend_history(s, head.revision(), head.capacity(), read.history(), control)
        .await?;
    assert_eq!(
        executor.run(s, 20, control).await?.head().status(),
        Status::Succeeded
    );
    Ok(())
}

async fn verify_upgraded(
    store: &PgStore,
    d: &Definition,
    effects: Arc<Effects>,
    read: ReadBudget,
    captured: &[(Scope, Vec<Event>)],
    control: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    for (index, (s, events)) in captured.iter().enumerate() {
        let lease = store.claim(*s, Duration::from_secs(30), control).await?;
        let snapshot = store.snapshot(&lease, read, control).await?;
        assert_eq!(
            serde_json::to_vec(snapshot.events())?,
            serde_json::to_vec(events)?
        );
        let head = snapshot.head().clone();
        store.release(&lease, control).await?;
        let executor = Executor::new(
            store.clone(),
            protection()?,
            registry(d.clone(), effects.clone(), index == 1)?,
            read,
        );
        match index {
            0 => verify_pending(&executor, *s, head, read, control).await?,
            1 => verify_paused(&executor, *s, head, read, control).await?,
            2 => verify_terminal(&executor, *s, head, read, control).await?,
            _ => verify_long(&executor, d, effects.clone(), *s, head, read, control).await?,
        }
    }
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

async fn measure_upgrade(
    owner: &PgPool,
    connection: &mut sqlx::PgConnection,
) -> anyhow::Result<()> {
    let before_lsn: String = sqlx::query_scalar("SELECT pg_current_wal_lsn()::text")
        .fetch_one(owner)
        .await?;
    let before_size = component_size(owner).await?;
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM rss_saga.journal")
        .fetch_one(owner)
        .await?;
    let clock = Clock::new();
    let start = clock.now();
    sqlx::raw_sql(UPGRADE_SQL).execute(connection).await?;
    let millis = clock.now().saturating_sub(start).as_secs_f64() * 1000.0;
    let wal: i64 =
        sqlx::query_scalar("SELECT pg_wal_lsn_diff(pg_current_wal_lsn(),$1::pg_lsn)::bigint")
            .bind(before_lsn)
            .fetch_one(owner)
            .await?;
    let after_size = component_size(owner).await?;
    eprintln!(
        "SAGA_HISTORY_UPGRADE entries={count} migration_ms={millis:.3} wal_bytes={wal} relation_bytes_before={before_size} relation_bytes_after={after_size}"
    );
    Ok(())
}
async fn component_size(owner: &PgPool) -> anyhow::Result<i64> {
    Ok(sqlx::query_scalar("SELECT coalesce(sum(pg_total_relation_size(c.oid)),0)::bigint FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='rss_saga' AND c.relkind='r'").fetch_one(owner).await?)
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

async fn install_upgrade(
    owner: &PgPool,
    pool: &PgPool,
    control: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    let mut connection = owner.acquire().await?;
    assert!(
        matches!(PgStore::new(pool.clone(),control).await,Err(e) if e.kind()==ErrorKind::StorageContract)
    );
    sqlx::raw_sql("SET ROLE saga_owner")
        .execute(&mut *connection)
        .await?;
    measure_upgrade(owner, &mut connection).await?;
    sqlx::raw_sql("RESET ROLE; GRANT SELECT ON ALL TABLES IN SCHEMA rss_saga TO saga_runtime; GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA rss_saga TO saga_runtime").execute(&mut *connection).await?;
    drop(connection);
    Ok(())
}
