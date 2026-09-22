use super::*;
use sqlx::{Acquire, Postgres, Transaction};

// ref: launchbadge/sqlx sqlx-core/src/{transaction.rs,pool/connection.rs}@v0.9.0
pub(super) async fn run<T: Timer>(
    store: &PgLedger,
    pool: &PgPool,
    owner: &PgPool,
    control: &Control<'_, T>,
) -> anyhow::Result<()> {
    // A one-connection pool makes reuse of the interrupted backend observable.
    let single = PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_secs(10))
        .connect_with((*pool.connect_options()).clone())
        .await?;
    for case in [
        ("append-cancel", true, true),
        ("append-deadline", true, false),
        ("read-cancel", false, true),
        ("read-deadline", false, false),
    ] {
        interrupted(store, &single, owner, control, case).await?;
    }
    single.close().await;
    Ok(())
}

async fn interrupted<T: Timer>(
    store: &PgLedger,
    single: &PgPool,
    owner: &PgPool,
    control: &Control<'_, T>,
    case: (&str, bool, bool),
) -> anyhow::Result<()> {
    let (id, _, _) = case;
    let request = request(&format!("borrowed-{id}"), "event", b"exact")?;
    let mut blocker = owner.begin().await?;
    sqlx::query("LOCK TABLE rss_ledger.entries IN ACCESS EXCLUSIVE MODE")
        .execute(&mut *blocker)
        .await?;
    let blocker_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *blocker)
        .await?;
    let mut lease = single.acquire().await?;
    // The host, not the borrowing API, owns uncertain-settlement isolation.
    lease.close_on_drop();
    let mut tx = lease.begin().await?;
    let (pid, _): (i32, String) =
        sqlx::query_as("SELECT pg_backend_pid(),set_config('rss.tenant_id',$1,true)")
            .bind(TENANT)
            .fetch_one(&mut *tx)
            .await?;
    interrupt(&mut tx, &request, owner, (pid, blocker_pid), case).await?;
    // The backend is still blocked: dropping the API future is not rollback ACK.
    // A separate bounded host cleanup attempt cannot confirm settlement either.
    assert!(
        tokio::time::timeout(Duration::from_millis(50), tx.rollback())
            .await
            .is_err()
    );
    drop(lease);
    blocker.rollback().await?;
    wait_retired(owner, pid).await?;
    let replacement: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(single)
        .await?;
    assert_ne!(replacement, pid);
    recover(store, single, &request, control).await
}

async fn recover<T: Timer>(
    store: &PgLedger,
    single: &PgPool,
    request: &AppendRequest,
    control: &Control<'_, T>,
) -> anyhow::Result<()> {
    assert!(
        committed(
            store
                .find(request.ledger(), request.record_id(), control)
                .await
        )?
        .is_none()
    );
    assert!(committed(store.append(request, control).await)?.inserted());
    let mut tx = single.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(TENANT)
        .execute(&mut *tx)
        .await?;
    let window = read_window_in_transaction(
        &mut tx,
        &auth()?,
        request.ledger(),
        Sequence::new(0),
        ReadLimit::new(1, 4096)?,
        control,
    )
    .await?;
    assert_eq!(window.entries().len(), 1);
    assert_eq!(window.entries()[0].payload(), b"exact");
    tx.rollback().await?;
    Ok(())
}

async fn interrupt(
    tx: &mut Transaction<'_, Postgres>,
    request: &AppendRequest,
    owner: &PgPool,
    pids: (i32, i32),
    case: (&str, bool, bool),
) -> anyhow::Result<()> {
    let (id, append, cancelled) = case;
    let clock = Clock::new();
    let cancel = CancellationToken::new();
    let budget = Control::new(&clock, Duration::from_secs(3), &cancel);
    let authenticator = auth()?;
    let operation = operate(tx, &authenticator, request, &budget, append);
    let interrupt = async {
        wait_blocked(owner, pids.0, pids.1).await?;
        if cancelled {
            cancel.cancel();
        }
        Ok::<_, anyhow::Error>(())
    };
    let (result, observed) = tokio::join!(operation, interrupt);
    observed?;
    match result {
        Err(Error::Cancelled(LocalTxDeadlineStage::Operation)) if cancelled => Ok(()),
        Err(Error::Deadline(LocalTxDeadlineStage::Operation)) if !cancelled => Ok(()),
        _ => anyhow::bail!("{id}: missing in-flight interruption"),
    }
}

async fn operate<T: Timer>(
    tx: &mut Transaction<'_, Postgres>,
    authenticator: &Authenticator,
    request: &AppendRequest,
    control: &Control<'_, T>,
    append: bool,
) -> Result<(), Error> {
    if append {
        append_in_transaction(tx, authenticator, request, control)
            .await
            .map(|_| ())
    } else {
        read_window_in_transaction(
            tx,
            authenticator,
            request.ledger(),
            Sequence::new(0),
            ReadLimit::new(1, 4096)?,
            control,
        )
        .await
        .map(|_| ())
    }
}

async fn wait_blocked(owner: &PgPool, pid: i32, blocker: i32) -> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let blocked: bool = sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE pid=$1 \
                 AND wait_event_type='Lock' AND $2=ANY(pg_blocking_pids(pid)))",
            )
            .bind(pid)
            .bind(blocker)
            .fetch_one(owner)
            .await?;
            if blocked {
                return Ok::<_, anyhow::Error>(());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await??;
    Ok(())
}

async fn wait_retired(owner: &PgPool, pid: i32) -> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(6), async {
        loop {
            let exists: bool =
                sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE pid=$1)")
                    .bind(pid)
                    .fetch_one(owner)
                    .await?;
            if !exists {
                return Ok::<_, anyhow::Error>(());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await??;
    Ok(())
}
