mod baseline;
pub(super) use baseline::{
    baseline_receipts_prevent_cross_start_duplicates, invalid_baselines_are_atomic,
};
mod external;
pub(super) use external::{direct_advance_obeys_control, external_recovery};
mod admission;
use super::*;
pub(super) use admission::{
    application_error_cannot_claim_settlement, borrowed_timeout_rolls_back, bounded_close,
    rejects_dangerous_acl, store_identity,
};
use sqlx::Connection;

pub(super) async fn atomic_recovery(
    store: &PgStore,
    owner: &PgPool,
    control: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    let s = scope("atomic", TENANT)?;
    let first = event(&s, 0, "fact", b"one")?;
    let old = session(store, &s, control).await?;
    let current = store.projection(store.takeover(&s, control).await?, Counter)?;
    assert_eq!(
        old.execute(None, &first, control).await,
        Err(Error::new(rss_projection::ErrorKind::Fenced))
    );
    assert_eq!(count(owner, &s).await?, 0);
    store.inject_next_fault(PgFault::CommitUnknownAfterAck);
    assert_eq!(
        current.execute(None, &first, control).await,
        Err(Error::new(rss_projection::ErrorKind::CommitUnknown))
    );
    assert_eq!(current.checkpoint().await?.position, Some(first.position()));
    assert_eq!(count(owner, &s).await?, 1);
    let position = duplicates(&current, owner, &s, &first, control).await?;
    rollback_cases(store, owner, &s, position, control).await
}
async fn duplicates(
    current: &PgProjection<Counter>,
    owner: &PgPool,
    s: &ProjectionScope,
    first: &Event,
    control: &Control<'_, Clock>,
) -> anyhow::Result<Position> {
    let duplicate = event(s, 1, "fact", b"one")?;
    assert_eq!(
        current
            .execute(Some(first.position()), &duplicate, control)
            .await?,
        ApplyOutcome::Duplicate
    );
    assert_eq!(count(owner, s).await?, 1);
    assert_eq!(
        current
            .execute(
                Some(duplicate.position()),
                &event(s, 2, "fact", b"changed")?,
                control
            )
            .await,
        Err(Error::new(rss_projection::ErrorKind::Conflict))
    );
    assert_eq!(
        current.checkpoint().await?.position,
        Some(duplicate.position())
    );
    assert_eq!(
        current
            .execute(Some(duplicate.position()), first, control)
            .await,
        Err(Error::new(rss_projection::ErrorKind::OutOfOrder))
    );
    Ok(duplicate.position())
}
async fn rollback_cases(
    store: &PgStore,
    owner: &PgPool,
    s: &ProjectionScope,
    position: Position,
    control: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    let rejected = store.projection(store.takeover(s, control).await?, Reject)?;
    let next = event(s, 2, "new", b"two")?;
    assert_eq!(
        rejected.execute(Some(position), &next, control).await,
        Err(Error::new(ErrorKind::Rejected))
    );
    assert_eq!(count(owner, s).await?, 1);
    assert_eq!(rejected.checkpoint().await?.position, Some(position));
    store.inject_next_fault(PgFault::RollbackFailedAfterAck);
    assert_eq!(
        rejected.execute(Some(position), &next, control).await,
        Err(Error::new(rss_projection::ErrorKind::RollbackFailed))
    );
    assert_eq!(count(owner, s).await?, 1);
    Ok(())
}
struct Reject;
impl PgEffect for Reject {
    async fn apply(
        &self,
        tx: &mut PgTransaction<'_>,
        scope: &ProjectionScope,
        _: &Event,
    ) -> Result<PgEffectOutcome, PgOperationError> {
        increment(tx, scope).await?;
        Err(PgOperationError::rejected())
    }
}
pub(super) async fn isolation(
    store: &PgStore,
    pool: &PgPool,
    owner: &PgPool,
    control: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    let left = scope("isolation", TENANT)?;
    let right = scope("isolation", OTHER)?;
    let a = session(store, &left, control).await?;
    let b = session(store, &right, control).await?;
    let ae = event(&left, 0, "same", b"a")?;
    let be = event(&right, 0, "same", b"b")?;
    assert_eq!(
        a.execute(None, &be, control).await,
        Err(Error::new(rss_projection::ErrorKind::ScopeMismatch))
    );
    a.execute(None, &ae, control).await?;
    b.execute(None, &be, control).await?;
    assert_eq!(count(owner, &left).await?, 1);
    assert_eq!(count(owner, &right).await?, 1);
    runtime_isolation(pool).await?;
    let source = right.source().clone();
    assert_eq!(
        store
            .local_tx(left.source(), control, move |tx| Box::pin(async move {
                tx.append(&source, "bad", b"x").await
            }))
            .await,
        Err(Error::new(rss_projection::ErrorKind::ScopeMismatch))
    );
    Ok(())
}
async fn runtime_isolation(pool: &PgPool) -> anyhow::Result<()> {
    let mut conn = pool.acquire().await?;
    let mut tx = conn.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(TENANT)
        .execute(&mut *tx)
        .await?;
    let hidden: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM rss_projection.checkpoints WHERE tenant_id=$1::uuid",
    )
    .bind(OTHER)
    .fetch_one(&mut *tx)
    .await?;
    assert_eq!(hidden, 0);
    let hidden: i64 =
        sqlx::query_scalar("SELECT count(*) FROM public.counts WHERE tenant_id=$1::uuid")
            .bind(OTHER)
            .fetch_one(&mut *tx)
            .await?;
    assert_eq!(hidden, 0);
    assert!(
        sqlx::query("SELECT rss_projection.append_event($1::uuid,'wrong','x','x'::bytea)")
            .bind(OTHER)
            .execute(&mut *tx)
            .await
            .is_err()
    );
    tx.rollback().await?;
    for statement in [
        "INSERT INTO rss_projection.sources VALUES('f47ac10b-58cc-4372-a567-0e02b2c3d479','bypass',0)",
        "UPDATE rss_projection.checkpoints SET epoch=0",
        "DELETE FROM rss_projection.receipts",
        "TRUNCATE rss_projection.events",
    ] {
        assert!(sqlx::raw_sql(statement).execute(&mut *conn).await.is_err());
    }
    Ok(())
}
pub(super) async fn ordered_append(
    store: &PgStore,
    control: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    let s = scope("ordered", TENANT)?;
    let entered = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let source = s.source().clone();
    let e = entered.clone();
    let r = release.clone();
    let first = store.local_tx(s.source(), control, move |tx| {
        Box::pin(async move {
            let p = tx.append(&source, "first", b"1").await?;
            e.notify_one();
            r.notified().await;
            Ok(p)
        })
    });
    let second = async {
        entered.notified().await;
        assert_eq!(store.high_water(s.source()).await?, None);
        let pending = append(store, &s, "second", b"2", control);
        tokio::pin!(pending);
        assert!(
            tokio::time::timeout(Duration::from_millis(100), &mut pending)
                .await
                .is_err()
        );
        release.notify_one();
        pending.await
    };
    let (a, b) = tokio::join!(first, second);
    assert_eq!(a?.get(), 0);
    assert_eq!(b?.get(), 1);
    assert_eq!(
        store
            .read(s.source(), None, BatchLimit::new(10)?)
            .await?
            .len(),
        2
    );
    assert_eq!(append(store, &s, "first", b"1", control).await?.get(), 0);
    assert_eq!(
        append(store, &s, "first", b"changed", control).await,
        Err(Error::new(rss_projection::ErrorKind::Conflict))
    );
    let source = s.source().clone();
    let rolled_back: Result<(), Error> = store
        .local_tx(s.source(), control, move |tx| {
            Box::pin(async move {
                tx.append(&source, "aborted", b"3").await?;
                Err(PgOperationError::rejected())
            })
        })
        .await;
    assert_eq!(
        rolled_back,
        Err(Error::new(rss_projection::ErrorKind::Rejected))
    );
    assert_eq!(store.high_water(s.source()).await?, Some(Position::new(1)?));
    Ok(())
}
pub(super) async fn replay(
    store: &PgStore,
    owner: &PgPool,
    control: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    let s = scope("replay", TENANT)?;
    append(store, &s, "a", b"1", control).await?;
    append(store, &s, "b", b"2", control).await?;
    let bound = ReplayBound::Through(store.high_water(s.source()).await?);
    store
        .initialize(&s, GenerationStart::beginning(), bound, control)
        .await?;
    let projection = store.projection(store.takeover(&s, control).await?, Counter)?;
    append(store, &s, "later", b"3", control).await?;
    let limit = RunLimit::new(BatchLimit::new(10)?, 1)?;
    let report = run(store, &projection, control, limit).await;
    assert_eq!(report.applied, 1);
    replay_resume(store, owner, &s, control).await?;
    replay_new_generation(store, owner, &s, control).await
}
async fn replay_resume(
    store: &PgStore,
    owner: &PgPool,
    s: &ProjectionScope,
    control: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    let next = store.projection(store.takeover(s, control).await?, Counter)?;
    let report = run(
        store,
        &next,
        control,
        RunLimit::new(BatchLimit::new(10)?, 10)?,
    )
    .await;
    assert_eq!(report.applied, 1);
    assert_eq!(report.stop, Stop::CaughtUp);
    assert_eq!(count(owner, s).await?, 2);
    assert_eq!(
        store
            .initialize(s, GenerationStart::beginning(), ReplayBound::Live, control)
            .await,
        Err(Error::new(rss_projection::ErrorKind::Conflict))
    );
    Ok(())
}
async fn replay_new_generation(
    store: &PgStore,
    owner: &PgPool,
    s: &ProjectionScope,
    control: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    let fresh = ProjectionScope::new(s.source().clone(), s.projection(), "v2")?;
    store
        .initialize(
            &fresh,
            GenerationStart::after(
                Position::new(1)?,
                vec![
                    BaselineReceipt::from_event(&event(s, 0, "a", b"1")?),
                    BaselineReceipt::from_event(&event(s, 1, "b", b"2")?),
                ],
            )?,
            ReplayBound::Through(Some(Position::new(2)?)),
            control,
        )
        .await?;
    let new = store.projection(store.takeover(&fresh, control).await?, Counter)?;
    let report = run(
        store,
        &new,
        control,
        RunLimit::new(BatchLimit::new(10)?, 10)?,
    )
    .await;
    assert_eq!(report.applied, 1);
    assert_eq!(count(owner, &fresh).await?, 1);
    assert_eq!(count(owner, s).await?, 2);
    Ok(())
}
pub(super) async fn interruption(store: &PgStore, owner: &PgPool) -> anyhow::Result<()> {
    let clock = Clock::new();
    let cancel = CancellationToken::new();
    let control = Control::new(&clock, Duration::from_secs(10), &cancel);
    let s = scope("interrupt", TENANT)?;
    let projection = session(store, &s, &control).await?;
    store.inject_next_fault(PgFault::CommitPending);
    let short = Control::new(&clock, clock.now() + Duration::from_millis(100), &cancel);
    assert_eq!(
        projection
            .execute(None, &event(&s, 0, "x", b"x")?, &short)
            .await,
        Err(Error::new(rss_projection::ErrorKind::CommitUnknown))
    );
    assert_eq!(projection.checkpoint().await?.position, None);
    assert_eq!(count(owner, &s).await?, 0);
    projection
        .execute(None, &event(&s, 0, "x", b"x")?, &control)
        .await?;
    assert_eq!(count(owner, &s).await?, 1);
    Ok(())
}

struct HeldEffect {
    entered: Arc<tokio::sync::Notify>,
    release: Arc<tokio::sync::Notify>,
}
impl PgEffect for HeldEffect {
    async fn apply(
        &self,
        tx: &mut PgTransaction<'_>,
        scope: &ProjectionScope,
        _: &Event,
    ) -> Result<PgEffectOutcome, PgOperationError> {
        increment(tx, scope).await?;
        self.entered.notify_one();
        self.release.notified().await;
        Ok(PgEffectOutcome::Applied)
    }
}
pub(super) async fn takeover_waits_for_the_old_transaction(
    store: &PgStore,
    owner: &PgPool,
    control: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    let s = scope("handoff", TENANT)?;
    store
        .initialize(&s, GenerationStart::beginning(), ReplayBound::Live, control)
        .await?;
    let entered = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let old = store.projection(
        store.takeover(&s, control).await?,
        HeldEffect {
            entered: entered.clone(),
            release: release.clone(),
        },
    )?;
    let fact = event(&s, 0, "one", b"one")?;
    let applying = old.execute(None, &fact, control);
    let taking = async {
        entered.notified().await;
        let taking = store.takeover(&s, control);
        tokio::pin!(taking);
        assert!(
            tokio::time::timeout(Duration::from_millis(100), &mut taking)
                .await
                .is_err()
        );
        release.notify_one();
        taking.await
    };
    let (applied, claim) = tokio::join!(applying, taking);
    assert_eq!(applied?, ApplyOutcome::Applied);
    let next = store.projection(claim?, Counter)?;
    assert_eq!(next.checkpoint().await?.position, Some(fact.position()));
    assert_eq!(
        old.checkpoint().await,
        Err(Error::new(rss_projection::ErrorKind::Fenced))
    );
    assert_eq!(count(owner, &s).await?, 1);
    Ok(())
}
pub(super) async fn cancel_after_apply_discards_the_transaction(
    store: &PgStore,
    owner: &PgPool,
) -> anyhow::Result<()> {
    let s = scope("cancel", TENANT)?;
    let clock = Clock::new();
    let cancel = CancellationToken::new();
    let control = Control::new(&clock, Duration::from_secs(10), &cancel);
    store
        .initialize(
            &s,
            GenerationStart::beginning(),
            ReplayBound::Live,
            &control,
        )
        .await?;
    let entered = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let projection = store.projection(
        store.takeover(&s, &control).await?,
        HeldEffect {
            entered: entered.clone(),
            release,
        },
    )?;
    let fact = event(&s, 0, "one", b"one")?;
    let applying = projection.execute(None, &fact, &control);
    let cancelling = async {
        entered.notified().await;
        cancel.cancel();
    };
    let (result, ()) = tokio::join!(applying, cancelling);
    assert_eq!(
        result,
        Err(Error::new(rss_projection::ErrorKind::CommitUnknown))
    );
    assert_eq!(projection.checkpoint().await?.position, None);
    assert_eq!(count(owner, &s).await?, 0);
    Ok(())
}

pub(super) async fn borrowed_append_rolls_back(
    pool: &PgPool,
    store: &PgStore,
    control: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    let s = scope("borrowed", TENANT)?;
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(TENANT)
        .execute(&mut *tx)
        .await?;
    assert_eq!(
        append_in_transaction(&mut tx, s.source(), "one", b"one", control)
            .await?
            .get(),
        0
    );
    tx.rollback().await?;
    assert_eq!(store.high_water(s.source()).await?, None);
    Ok(())
}

struct Filter {
    calls: Arc<std::sync::atomic::AtomicU64>,
}
impl PgEffect for Filter {
    async fn apply(
        &self,
        _: &mut PgTransaction<'_>,
        _: &ProjectionScope,
        _: &Event,
    ) -> Result<PgEffectOutcome, PgOperationError> {
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(PgEffectOutcome::Filtered)
    }
}
pub(super) async fn filtered_receipts(
    store: &PgStore,
    owner: &PgPool,
    control: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    let s = scope("filtered", TENANT)?;
    append(store, &s, "fact", b"x", control).await?;
    append(store, &s, "next", b"y", control).await?;
    store
        .initialize(&s, GenerationStart::beginning(), ReplayBound::Live, control)
        .await?;
    let calls = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let execution = store.projection(
        store.takeover(&s, control).await?,
        Filter {
            calls: calls.clone(),
        },
    )?;
    let report = run(
        store,
        &execution,
        control,
        RunLimit::new(BatchLimit::new(1)?, 1)?,
    )
    .await
    .into_result()?;
    assert_eq!(
        (
            report.filtered,
            report.applied,
            report.duplicates,
            report.position,
            report.stop
        ),
        (1, 0, 0, Some(Position::new(0)?), Stop::EventLimit)
    );
    let duplicate = event(&s, 1, "fact", b"x")?;
    assert_eq!(
        execution
            .execute(Some(Position::new(0)?), &duplicate, control)
            .await?,
        ApplyOutcome::Duplicate
    );
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(
        execution.checkpoint().await?.position,
        Some(Position::new(1)?)
    );
    assert_eq!(count(owner, &s).await?, 0);
    Ok(())
}
