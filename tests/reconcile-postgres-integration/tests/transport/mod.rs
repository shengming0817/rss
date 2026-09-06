use super::*;
use tokio::sync::oneshot;

pub async fn run(
    owner: &PgPool,
    options: PgConnectOptions,
    c: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    commit_cut(owner, options.clone(), c).await?;
    rollback_cut(owner, options.clone(), c).await?;
    for cancelled in [true, false] {
        bounded_close(options.clone(), c, cancelled).await?;
    }
    Ok(())
}
async fn isolated(
    options: PgConnectOptions,
    c: &Control<'_, Clock>,
) -> anyhow::Result<(PgStore, PgPool)> {
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_secs(1))
        .connect_with(options)
        .await?;
    let store = PgStore::new(pool.clone(), c).await?;
    Ok((store, pool))
}
async fn staged(tx: &mut PgTransaction<'_>, id: &'static str) -> Result<i32, PgOperationError> {
    effect(tx, id.to_owned()).await?;
    tx.with_connection(|conn| {
        Box::pin(async move {
            sqlx::query_scalar("SELECT pg_backend_pid()")
                .fetch_one(conn)
                .await
        })
    })
    .await
}
async fn kill_when(
    owner: &PgPool,
    receiver: oneshot::Receiver<i32>,
    query: &str,
) -> anyhow::Result<i32> {
    let pid = receiver.await?;
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let state: Option<(String, Option<String>, String)> = sqlx::query_as(
                "SELECT query,wait_event_type,state FROM pg_stat_activity WHERE pid=$1",
            )
            .bind(pid)
            .fetch_optional(owner)
            .await?;
            if state.is_some_and(|(running, wait, activity)| {
                running.starts_with(query)
                    && activity == "active"
                    && wait.as_deref() == Some(if query == "COMMIT" { "Lock" } else { "Timeout" })
            }) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        Ok::<(), anyhow::Error>(())
    })
    .await??;
    let killed: bool = sqlx::query_scalar("SELECT pg_terminate_backend($1)")
        .bind(pid)
        .fetch_one(owner)
        .await?;
    assert!(killed);
    Ok(pid)
}
async fn replacement(pool: &PgPool, old: i32) -> anyhow::Result<()> {
    // A one-connection pool must open another backend after unacknowledged settlement.
    let new: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(pool)
        .await?;
    assert_ne!(old, new);
    Ok(())
}
async fn commit_cut(
    owner: &PgPool,
    options: PgConnectOptions,
    c: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    // Test-only business trigger blocks inside COMMIT, not before the client sends COMMIT.
    sqlx::raw_sql("CREATE FUNCTION public.block_test_commit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_advisory_xact_lock(2290929); RETURN NEW; END $$; CREATE CONSTRAINT TRIGGER block_test_commit AFTER INSERT ON public.effects DEFERRABLE INITIALLY DEFERRED FOR EACH ROW WHEN (NEW.id='transport-commit') EXECUTE FUNCTION public.block_test_commit();").execute(owner).await?;
    let mut blocker = owner.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(2290929)")
        .execute(&mut *blocker)
        .await?;
    let (store, pool) = isolated(options, c).await?;
    let t = target("transport-commit", TENANT)?;
    store.wake(&t, c).await?;
    let claim = claim(&store, &t, Duration::from_secs(3), c).await?;
    let (send, receive) = oneshot::channel();
    let control = c.child(Duration::from_secs(4));
    let write = store.protect(&claim, &control, (), move |_, tx| {
        Box::pin(async move {
            let pid = staged(tx, "transport-commit").await?;
            send.send(pid).map_err(|_| PgOperationError::rejected())?;
            Ok(())
        })
    });
    let (outcome, killed) = tokio::join!(write, kill_when(owner, receive, "COMMIT"));
    let pid = killed?;
    blocker.rollback().await?;
    verify_cut(
        outcome,
        ErrorKind::CommitUnknown,
        owner,
        "transport-commit",
        &pool,
        pid,
    )
    .await?;
    sqlx::raw_sql("DROP TRIGGER block_test_commit ON public.effects; DROP FUNCTION public.block_test_commit()").execute(owner).await?;
    assert_eq!(store.close(c).await, CloseOutcome::Drained);
    Ok(())
}
async fn rollback_cut(
    owner: &PgPool,
    options: PgConnectOptions,
    c: &Control<'_, Clock>,
) -> anyhow::Result<()> {
    let (store, pool) = isolated(options, c).await?;
    let t = target("transport-rollback", TENANT)?;
    store.wake(&t, c).await?;
    let claim = claim(&store, &t, Duration::from_secs(3), c).await?;
    let (send, receive) = oneshot::channel();
    let control = c.child(Duration::from_secs(4));
    let write = store.protect(&claim, &control, (), move |_, tx| {
        Box::pin(async move {
            let pid = staged(tx, "transport-rollback").await?;
            let pending = tx.with_connection(|conn| {
                Box::pin(async move {
                    sqlx::query("SELECT pg_sleep(60)").execute(conn).await?;
                    Ok(())
                })
            });
            // Drop the query future with a genuine server response still outstanding. Returning
            // the callback error makes rollback wait on the actual connection's protocol I/O.
            if tokio::time::timeout(Duration::from_millis(20), pending)
                .await
                .is_ok()
            {
                return Err(PgOperationError::rejected());
            }
            send.send(pid).map_err(|_| PgOperationError::rejected())?;
            Err::<(), _>(PgOperationError::rejected())
        })
    });
    // Both futures are polled by this task: after send the write branch enters rollback
    // and returns Pending before the controller branch can terminate the backend.
    let (outcome, killed) = tokio::join!(write, kill_when(owner, receive, "SELECT pg_sleep"));
    let pid = killed?;
    verify_cut(
        outcome,
        ErrorKind::RollbackFailed,
        owner,
        "transport-rollback",
        &pool,
        pid,
    )
    .await?;
    assert_eq!(store.close(c).await, CloseOutcome::Drained);
    Ok(())
}
async fn bounded_close(
    options: PgConnectOptions,
    c: &Control<'_, Clock>,
    cancelled: bool,
) -> anyhow::Result<()> {
    let (store, pool) = isolated(options, c).await?;
    let borrower = pool.acquire().await?;
    let token = CancellationToken::new();
    let clock = Clock::new();
    if cancelled {
        token.cancel();
    }
    let close = Control::new(
        &clock,
        if cancelled {
            Duration::from_secs(1)
        } else {
            Duration::from_millis(5)
        },
        &token,
    );
    let outcome = store.close(&close).await;
    assert_eq!(
        outcome,
        if cancelled {
            CloseOutcome::Cancelled
        } else {
            CloseOutcome::Deadline
        }
    );
    assert!(pool.is_closed());
    assert!(pool.acquire().await.is_err());
    drop(borrower);
    assert_eq!(store.close(c).await, CloseOutcome::Drained);
    Ok(())
}

async fn verify_cut(
    outcome: Result<(), Error>,
    kind: ErrorKind,
    owner: &PgPool,
    id: &str,
    pool: &PgPool,
    pid: i32,
) -> anyhow::Result<()> {
    assert!(matches!(outcome,Err(e) if e.kind()==kind));
    assert_eq!(count(owner, id).await?, 0);
    replacement(pool, pid).await
}
