use super::*;
use rss_transactional_messaging::transaction::LocalTxDeadlineStage as Stage;

pub(super) async fn run(
    plain: &PgAudit,
    ledger: &PgAudit,
    admin: &PgPool,
    control: &Control<'_, TestClock>,
) -> anyhow::Result<()> {
    typed_failures(ledger, control).await?;
    precommit_failure(plain, control).await?;
    precommit_failure(ledger, control).await?;
    cancelled_operation(ledger, control).await?;
    sqlx::raw_sql(
        "CREATE TABLE public.commit_barrier(id text PRIMARY KEY); \
         GRANT SELECT,INSERT ON public.commit_barrier TO audit_runtime; \
         CREATE FUNCTION public.commit_barrier_wait() RETURNS trigger LANGUAGE plpgsql AS $$ \
         BEGIN PERFORM pg_advisory_xact_lock(2497,1084); RETURN NEW; END $$; \
         CREATE CONSTRAINT TRIGGER commit_barrier_wait AFTER INSERT ON public.commit_barrier \
         DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.commit_barrier_wait();",
    )
    .execute(admin)
    .await?;
    for (id, store) in [("inflight-plain", plain), ("inflight-ledger", ledger)] {
        in_flight(store, admin, control, id).await?;
        settlement_window(store, admin, id).await?;
    }
    Ok(())
}

async fn typed_failures(store: &PgAudit, control: &Control<'_, TestClock>) -> anyhow::Result<()> {
    for failure in [
        BusinessError::Audit(Error::Conflict),
        BusinessError::Sql(sqlx::Error::RowNotFound),
    ] {
        let expected = business_kind(&failure);
        let attempt = store
            .write_tx_with_context(tenant()?, control, (), move |_, _| {
                Box::pin(async move { Err::<(), _>(failure) })
            })
            .await;
        assert_eq!(
            attempt.fold(
                |_| 0,
                |_| 0,
                |e| match e {
                    TransactionError::Operation(e) => business_kind(&e),
                    _ => 0,
                },
                |_| 0,
                |_| 0,
                |_| 0,
            ),
            expected
        );
    }
    Ok(())
}

fn business_kind(error: &BusinessError) -> u8 {
    match error {
        BusinessError::Audit(Error::Conflict) => 1,
        BusinessError::Sql(sqlx::Error::RowNotFound) => 2,
        _ => 0,
    }
}

async fn cancelled_operation(
    store: &PgAudit,
    control: &Control<'_, TestClock>,
) -> anyhow::Result<()> {
    let request = store
        .prepare(
            event(tenant()?, "atomic", "cancelled-error", vec![])?,
            control,
        )
        .await?;
    let clock = TestClock;
    let cancel = CancellationToken::new();
    let operation_cancel = cancel.clone();
    let cutoff = Deadline::from_timeout(&clock, Duration::from_secs(10))?;
    let budget = Control::new(&clock, cutoff, cutoff, &cancel);
    let staged = request.clone();
    let attempt = store
        .write_tx_with_context(tenant()?, &budget, (), move |_, tx| {
            Box::pin(async move {
                tx.append(&staged).await.map_err(BusinessError::Audit)?;
                // The error and cancellation become ready in the same callback poll.
                operation_cancel.cancel();
                Err::<(), BusinessError>(BusinessError::Declined("cancelled-business-rule"))
            })
        })
        .await;
    assert!(attempt.fold(
        |_| false,
        |_| false,
        |_| false,
        |error| matches!(error, TransactionError::Rollback { operation, settlement: Error::Cancelled(Stage::Rollback) }
            if matches!(*operation, TransactionError::Operation(BusinessError::Declined("cancelled-business-rule")))),
        |_| false,
        |_| false,
    ));
    // No rollback ACK was claimed. Original bytes serialize recovery after lease retirement.
    assert!(committed(store.append(&request, control).await)?.inserted());
    Ok(())
}

async fn in_flight(
    store: &PgAudit,
    admin: &PgPool,
    control: &Control<'_, TestClock>,
    id: &'static str,
) -> anyhow::Result<()> {
    let request = store
        .prepare(event(tenant()?, "atomic", id, vec![8])?, control)
        .await?;
    let mut blocker = admin.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(2497,1084)")
        .execute(&mut *blocker)
        .await?;
    let blocker_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *blocker)
        .await?;
    let cancel = CancellationToken::new();
    let clock = TestClock;
    let cutoff = Deadline::from_timeout(&clock, Duration::from_secs(15))?;
    let budget = Control::new(&clock, cutoff, cutoff, &cancel);
    let (sender, receiver) = tokio::sync::oneshot::channel();
    let staged = request.clone();
    let operation = store.write_tx_with_context(tenant()?, &budget, (), move |_, tx| {
        Box::pin(async move {
            tx.append(&staged).await?;
            let pid = tx
                .with_connection(move |c| {
                    Box::pin(async move {
                        sqlx::query("INSERT INTO public.commit_barrier VALUES ($1)")
                            .bind(id)
                            .execute(&mut *c)
                            .await?;
                        sqlx::query_scalar::<_, i32>("SELECT pg_backend_pid()")
                            .fetch_one(c)
                            .await
                    })
                })
                .await?;
            sender.send(pid).map_err(|_| Error::StorageContract)?;
            Ok::<(), Error>(())
        })
    });
    let interrupt = async {
        let pid = receiver.await?;
        wait_commit(admin, pid, blocker_pid).await?;
        cancel.cancel();
        Ok::<_, anyhow::Error>(pid)
    };
    let (attempt, observed) = tokio::join!(operation, interrupt);
    let pid = observed?;
    assert!(attempt.fold(
        |_| false,
        |_| false,
        |_| false,
        |_| false,
        |e| matches!(e, TransactionError::Audit(Error::Cancelled(Stage::Commit))),
        |_| false,
    ));
    blocker.rollback().await?;
    wait_retired(admin, pid).await?;
    recover(store, admin, control, request, id).await
}

async fn recover(
    store: &PgAudit,
    admin: &PgPool,
    control: &Control<'_, TestClock>,
    request: PreparedAuditV1,
    id: &'static str,
) -> anyhow::Result<()> {
    // Disconnecting in-flight COMMIT may leave either outcome; never guess which one.
    let audit_rows: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM rss_audit.records WHERE tenant_id=$1::uuid AND source_id='atomic' AND event_id=$2",
    ).bind(tenant()?.to_string()).bind(id).fetch_one(admin).await?;
    let business_rows: i64 =
        sqlx::query_scalar("SELECT count(*) FROM public.commit_barrier WHERE id=$1")
            .bind(id)
            .fetch_one(admin)
            .await?;
    assert_eq!(audit_rows, business_rows);
    let restored = PreparedAuditV1::from_canonical_bytes(request.canonical_bytes())?;
    let retry = committed(
        store
            .write_tx_with_context(tenant()?, control, (), move |_, tx| {
                Box::pin(async move {
                    let staged = tx.append(&restored).await?;
                    tx.with_connection(move |c| {
                        Box::pin(async move {
                            sqlx::query(
                                "INSERT INTO public.commit_barrier VALUES ($1) ON CONFLICT DO NOTHING",
                            )
                            .bind(id)
                            .execute(c)
                            .await
                            .map(|_| ())
                        })
                    })
                    .await?;
                    Ok::<_, Error>(staged)
                })
            })
            .await,
    )?;
    assert_eq!(retry.inserted(), audit_rows == 0);
    assert_eq!(
        retry.record().prepared().canonical_bytes(),
        request.canonical_bytes()
    );
    assert!(!committed(store.append(&request, control).await)?.inserted());
    let business_rows: i64 =
        sqlx::query_scalar("SELECT count(*) FROM public.commit_barrier WHERE id=$1")
            .bind(id)
            .fetch_one(admin)
            .await?;
    assert_eq!(business_rows, 1);
    Ok(())
}

async fn wait_commit(admin: &PgPool, pid: i32, blocker: i32) -> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let blocked: bool = sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE pid=$1 \
                 AND query='COMMIT' AND wait_event_type='Lock' AND $2=ANY(pg_blocking_pids(pid)))",
            )
            .bind(pid)
            .bind(blocker)
            .fetch_one(admin)
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

async fn wait_retired(admin: &PgPool, pid: i32) -> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(6), async {
        loop {
            let exists: bool =
                sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE pid=$1)")
                    .bind(pid)
                    .fetch_one(admin)
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

// Deferred work at COMMIT uses total, not the already exhausted operation cutoff.
async fn settlement_window(store: &PgAudit, admin: &PgPool, id: &str) -> anyhow::Result<()> {
    let mut blocker = admin.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(2497,1084)")
        .execute(&mut *blocker)
        .await?;
    let blocker_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *blocker)
        .await?;
    let clock = TestClock;
    let cancel = CancellationToken::new();
    let operation = Deadline::from_timeout(&clock, Duration::from_secs(1))?;
    let total = Deadline::from_timeout(&clock, Duration::from_secs(10))?;
    let budget = Control::new(&clock, total, operation, &cancel);
    let id = format!("settlement-window-{id}");
    let (sender, receiver) = tokio::sync::oneshot::channel();
    let attempt = store.write_tx_with_context(tenant()?, &budget, (), move |_, tx| {
        Box::pin(async move {
            let pid = tx
                .with_connection(move |c| {
                    Box::pin(async move {
                        sqlx::query("INSERT INTO public.commit_barrier VALUES($1)")
                            .bind(id)
                            .execute(&mut *c)
                            .await?;
                        sqlx::query_scalar::<_, i32>("SELECT pg_backend_pid()")
                            .fetch_one(c)
                            .await
                    })
                })
                .await?;
            sender.send(pid).map_err(|_| Error::StorageContract)?;
            Ok::<_, Error>(())
        })
    });
    let unblock = async {
        let pid = receiver.await?;
        wait_commit(admin, pid, blocker_pid).await?;
        clock
            .sleep_until(Deadline::at(
                operation.instant() + Duration::from_millis(100),
            ))
            .await;
        blocker.rollback().await?;
        Ok::<_, anyhow::Error>(())
    };
    let (attempt, released) = tokio::join!(attempt, unblock);
    released?;
    committed(attempt)?;
    assert!(budget.operation_remaining().is_zero());
    assert!(!budget.total_remaining().is_zero());
    Ok(())
}

async fn precommit_failure(
    store: &PgAudit,
    control: &Control<'_, TestClock>,
) -> anyhow::Result<()> {
    let attempt = store
        .write_tx_with_context(tenant()?, control, (), |_, tx| {
            Box::pin(async move {
                // PostgreSQL has aborted the transaction. A callback returning Ok cannot make
                // the subsequent settlement setup SQL succeed, nor does it attempt COMMIT.
                assert!(
                    tx.with_connection(|c| Box::pin(async move {
                        sqlx::query("SELECT 1/0").execute(c).await
                    }))
                    .await
                    .is_err()
                );
                Ok::<_, BusinessError>(())
            })
        })
        .await;
    rolled_back(attempt, |e| matches!(e, TransactionError::Audit(_)));
    Ok(())
}
