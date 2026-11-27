//! Runtime ports share the same budget through acquisition, SQL and settlement.
use super::startup::{ManualTimer, assert_replacement, wait_for_retirement};
use super::*;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
const GUARD: Duration = Duration::from_secs(10);

pub(crate) async fn verify(owner: &PgPool, options: &PgConnectOptions) -> anyhow::Result<()> {
    let timer = ManualTimer::new();
    let acquired = timer.clone();
    let armed = Arc::new(AtomicBool::new(false));
    let trigger = armed.clone();
    let attempts = Arc::new(AtomicUsize::new(0));
    let observed = attempts.clone();
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .test_before_acquire(false)
        .before_acquire(move |_, _| {
            observed.fetch_add(1, Ordering::SeqCst);
            if trigger.load(Ordering::SeqCst) {
                acquired.advance(Duration::from_secs(31));
            }
            Box::pin(async { Ok(true) })
        })
        .connect_with(options.clone())
        .await?;
    let cancel = CancellationToken::new();
    let control = Control::new(&timer, Duration::from_secs(60), &cancel);
    let store = PgStore::new(pool.clone(), &control).await?;
    let scope = scope("runtime-budget", TENANT)?;
    store
        .initialize(
            &scope,
            &DEFINITION,
            GenerationStart::beginning(),
            ReplayBound::Live,
            &control,
        )
        .await?;
    let projection = store.projection(
        store.takeover(&scope, &DEFINITION, &control).await?,
        Counter,
    )?;
    let external_scope = super::scope("external-budget", TENANT)?;
    store
        .initialize(
            &external_scope,
            &DEFINITION,
            GenerationStart::beginning(),
            ReplayBound::Live,
            &control,
        )
        .await?;
    let checkpoint = store.external_checkpoint(
        store
            .takeover(&external_scope, &DEFINITION, &control)
            .await?,
    )?;
    for stage in 0..4 {
        preflight(&store, &projection, &checkpoint, &timer, &attempts, stage).await?;
        acquire_wait(&pool, &store, &projection, &checkpoint, &timer, stage).await?;
    }
    sql_budgets(&store, &scope, &timer, &armed, &control).await?;
    interrupted_read(owner, &pool, &store, &projection, &checkpoint, &timer).await?;
    rollback_stage(&store, scope.source(), &timer).await?;
    post_lock_admission(owner, &pool, &store, &control).await?;
    pool.close().await;
    Ok(())
}
async fn read(
    store: &PgStore,
    projection: &PgProjection<Counter>,
    checkpoint: &PgCheckpoint,
    stage: u8,
    control: &Control<'_, ManualTimer>,
) -> Result<(), Error> {
    match stage {
        0 => store
            .high_water(projection.scope().source(), control)
            .await
            .map(|_| ()),
        1 => store
            .read(
                projection.scope().source(),
                None,
                PageBudget::new(1, Event::MAX_PAYLOAD_BYTES)?,
                control,
            )
            .await
            .map(|_| ()),
        2 => projection.checkpoint(control).await.map(|_| ()),
        _ => checkpoint.load(control).await.map(|_| ()),
    }
}
async fn interrupted_read(
    owner: &PgPool,
    pool: &PgPool,
    store: &PgStore,
    projection: &PgProjection<Counter>,
    checkpoint: &PgCheckpoint,
    timer: &ManualTimer,
) -> anyhow::Result<()> {
    for stage in 0..4 {
        let mut held = pool.acquire().await?;
        let original: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *held)
            .await?;
        drop(held);
        let mut blocker = owner.begin().await?;
        let table = if stage < 2 {
            "LOCK TABLE rss_projection.events IN ACCESS EXCLUSIVE MODE"
        } else {
            "LOCK TABLE rss_projection.checkpoints IN ACCESS EXCLUSIVE MODE"
        };
        sqlx::query(table).execute(&mut *blocker).await?;
        let cancel = CancellationToken::new();
        let control = Control::new(timer, Duration::from_secs(60), &cancel);
        let mut operation = Box::pin(read(store, projection, checkpoint, stage, &control));
        tokio::time::timeout(GUARD, async {
            tokio::select! {
                result = &mut operation => anyhow::bail!("read did not wait: {result:?}"),
                result = wait_for_lock(owner,original) => result,
            }
        })
        .await??;
        cancel.cancel();
        assert_eq!(
            operation.await.err().map(|e| e.kind()),
            Some(ErrorKind::Cancelled)
        );
        assert_replacement(pool, original).await?;
        blocker.rollback().await?;
        wait_for_retirement(owner, original).await?;
    }
    Ok(())
}
async fn wait_for_lock(owner: &PgPool, pid: i32) -> anyhow::Result<()> {
    loop {
        if sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT FROM pg_stat_activity WHERE pid=$1 AND wait_event_type='Lock')",
        )
        .bind(pid)
        .fetch_one(owner)
        .await?
        {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}
async fn rollback_stage(
    store: &PgStore,
    scope: &SourceScope,
    timer: &ManualTimer,
) -> anyhow::Result<()> {
    let cancel = CancellationToken::new();
    let control = Control::new(timer, Duration::from_secs(60), &cancel);
    store.inject_next_fault(PgFault::RollbackPending);
    let (ready, entered) = tokio::sync::oneshot::channel();
    let work = store.local_tx(scope, &control, move |_| {
        Box::pin(async move {
            let _ = ready.send(());
            Err::<(), _>(PgOperationError::rejected(
                Phase::Application,
                None,
                None,
                std::io::Error::other("fixture rejection"),
            ))
        })
    });
    let interrupt = async {
        entered.await?;
        tokio::task::yield_now().await;
        cancel.cancel();
        Ok::<_, anyhow::Error>(())
    };
    let (result, signal) = tokio::join!(work, interrupt);
    signal?;
    assert_eq!(
        result.err().map(|e| e.kind()),
        Some(ErrorKind::RollbackFailed)
    );
    Ok(())
}

async fn preflight(
    store: &PgStore,
    projection: &PgProjection<Counter>,
    checkpoint: &PgCheckpoint,
    timer: &ManualTimer,
    attempts: &AtomicUsize,
    stage: u8,
) -> anyhow::Result<()> {
    for (expired, cancelled, expected) in [
        (true, false, ErrorKind::Deadline),
        (false, true, ErrorKind::Cancelled),
        (true, true, ErrorKind::Cancelled),
    ] {
        timer.advance(if expired {
            Duration::from_secs(60)
        } else {
            Duration::ZERO
        });
        let signal = CancellationToken::new();
        if cancelled {
            signal.cancel();
        }
        let limited = Control::new(timer, Duration::from_secs(60), &signal);
        let before = attempts.load(Ordering::SeqCst);
        assert_eq!(
            read(store, projection, checkpoint, stage, &limited)
                .await
                .err()
                .map(|e| e.kind()),
            Some(expected)
        );
        assert_eq!(attempts.load(Ordering::SeqCst), before);
    }
    timer.advance(Duration::ZERO);
    let signal = CancellationToken::new();
    let huge = Control::new(timer, Duration::MAX, &signal);
    let before = attempts.load(Ordering::SeqCst);
    assert_eq!(
        read(store, projection, checkpoint, stage, &huge)
            .await
            .err()
            .map(|e| e.kind()),
        Some(ErrorKind::InvalidInput)
    );
    assert_eq!(attempts.load(Ordering::SeqCst), before);
    Ok(())
}
async fn acquire_wait(
    pool: &PgPool,
    store: &PgStore,
    projection: &PgProjection<Counter>,
    checkpoint: &PgCheckpoint,
    timer: &ManualTimer,
    stage: u8,
) -> anyhow::Result<()> {
    for cancelled in [false, true] {
        let held = pool.acquire().await?;
        let signal = CancellationToken::new();
        let limited = Control::new(timer, Duration::from_secs(60), &signal);
        let mut operation = Box::pin(read(store, projection, checkpoint, stage, &limited));
        assert!(futures::poll!(operation.as_mut()).is_pending());
        timer.advance(Duration::from_secs(31));
        assert!(futures::poll!(operation.as_mut()).is_pending());
        if cancelled {
            signal.cancel();
        } else {
            timer.advance(Duration::from_secs(60));
        }
        assert_eq!(
            tokio::time::timeout(GUARD, operation)
                .await?
                .err()
                .map(|e| e.kind()),
            Some(if cancelled {
                ErrorKind::Cancelled
            } else {
                ErrorKind::Deadline
            })
        );
        drop(held);
        timer.advance(Duration::ZERO);
    }
    Ok(())
}

async fn sql_budgets(
    store: &PgStore,
    scope: &ProjectionScope,
    timer: &ManualTimer,
    armed: &AtomicBool,
    control: &Control<'_, ManualTimer>,
) -> anyhow::Result<()> {
    // Spend 31 of 60 seconds at acquire: setup must use 29 seconds, never 60 or a fixed 30.
    armed.store(true, Ordering::SeqCst);
    let values = store.local_tx(scope.source(),control,|tx|Box::pin(async move {
        tx.with_connection(|connection| Box::pin(async move {
            sqlx::query_as::<_,(String,String)>("SELECT current_setting('statement_timeout'),current_setting('lock_timeout')").fetch_one(connection).await
        })).await
    })).await?;
    assert_eq!(values, ("29s".into(), "29s".into()));
    armed.store(false, Ordering::SeqCst);
    timer.advance(Duration::ZERO);
    let values = store
        .local_tx(scope.source(), control, |tx| {
            Box::pin(async move {
                tx.with_connection(|connection| {
                    Box::pin(async move {
                        sqlx::query_scalar::<_, String>(
                            "SELECT current_setting('statement_timeout')",
                        )
                        .fetch_one(connection)
                        .await
                    })
                })
                .await
            })
        })
        .await?;
    assert_eq!(values, "1min");
    Ok(())
}

// Suppress the outer timer wake only to isolate the synchronous phase-admission check.
// Normal Timer wake/cancellation is covered by acquire_wait and interrupted_read above.
struct PhaseTimer(AtomicBool);
impl Timer for PhaseTimer {
    fn now(&self) -> Duration {
        if self.0.load(Ordering::SeqCst) {
            Duration::from_secs(60)
        } else {
            Duration::ZERO
        }
    }
    async fn sleep_until(&self, _: Duration) {
        std::future::pending::<()>().await;
    }
}
struct EnteredEffect(Arc<AtomicUsize>);
impl PgEffect for EnteredEffect {
    type Item = rss_projection::Event;
    async fn apply(
        &self,
        _: &mut PgTransaction<'_>,
        _: &ProjectionScope,
        _: &Event,
    ) -> Result<PgEffectOutcome, PgOperationError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(PgEffectOutcome::Filtered)
    }
}
async fn post_lock_admission(
    owner: &PgPool,
    pool: &PgPool,
    store: &PgStore,
    control: &Control<'_, ManualTimer>,
) -> anyhow::Result<()> {
    let scope = scope("post-lock-budget", TENANT)?;
    store
        .initialize(
            &scope,
            &DEFINITION,
            GenerationStart::beginning(),
            ReplayBound::Live,
            control,
        )
        .await?;
    let entered = Arc::new(AtomicUsize::new(0));
    let projection = store.projection(
        store.takeover(&scope, &DEFINITION, control).await?,
        EnteredEffect(entered.clone()),
    )?;
    let mut held = pool.acquire().await?;
    let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *held)
        .await?;
    drop(held);
    let mut blocker = owner.begin().await?;
    sqlx::query("LOCK TABLE rss_projection.checkpoints IN ACCESS EXCLUSIVE MODE")
        .execute(&mut *blocker)
        .await?;
    let timer = PhaseTimer(AtomicBool::new(false));
    let cancel = CancellationToken::new();
    let limited = Control::new(&timer, Duration::from_secs(60), &cancel);
    let event = event(&scope, 0, "phase-budget", b"one")?;
    let mut work = Box::pin(projection.execute(None, &event, &limited));
    tokio::time::timeout(GUARD, async {
        tokio::select! {
            result = &mut work => anyhow::bail!("event did not wait for its lock: {result:?}"),
            result = wait_for_lock(owner,pid) => result,
        }
    })
    .await??;
    timer.0.store(true, Ordering::SeqCst);
    blocker.rollback().await?;
    let result = tokio::time::timeout(GUARD, work).await?;
    assert_eq!(result.err().map(|e| e.kind()), Some(ErrorKind::Deadline));
    assert_eq!(
        entered.load(Ordering::SeqCst),
        0,
        "expired lock stage entered user effect"
    );
    assert_eq!(projection.checkpoint(control).await?.position, None);
    Ok(())
}
