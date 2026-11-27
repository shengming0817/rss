use super::*;
use rss_audit_postgres::PgFault;
mod settlement;

// Host-owned reason; it need not implement a formatting or standard error trait.
pub(super) enum BusinessError {
    Audit(Error),
    Sql(sqlx::Error),
    Declined(&'static str),
}

pub(super) async fn run(
    plain: &PgAudit,
    ledger: &PgAudit,
    admin: &PgPool,
    control: &Control<'_, TestClock>,
) -> anyhow::Result<()> {
    sqlx::raw_sql("CREATE TABLE public.business_changes(id text PRIMARY KEY); GRANT SELECT,INSERT ON public.business_changes TO audit_runtime;").execute(admin).await?;
    rollback(ledger, admin, control).await?;
    settlement::run(plain, ledger, admin, control).await?;
    unknown(plain, "unknown-plain", control).await?;
    unknown(ledger, "unknown-ledger", control).await?;
    racing(plain, "racing-plain", control).await?;
    racing(ledger, "racing-ledger", control).await?;
    termination(plain, control).await?;
    Ok(())
}

async fn rollback(
    store: &PgAudit,
    admin: &PgPool,
    control: &Control<'_, TestClock>,
) -> anyhow::Result<()> {
    let t = tenant()?;
    let request = store
        .prepare(event(t, "atomic", "rolled-back", vec![])?, control)
        .await?;
    let staged = request.clone();
    rolled_back(
        store
            .write_tx_with_context(t, control, (), move |_, tx| {
                Box::pin(async move {
                    tx.append(&staged).await.map_err(BusinessError::Audit)?;
                    tx.with_connection(|c| {
                        Box::pin(async move {
                            sqlx::query(
                                "INSERT INTO public.business_changes VALUES ('rolled-back')",
                            )
                            .execute(c)
                            .await?;
                            Ok::<(), sqlx::Error>(())
                        })
                    })
                    .await
                    .map_err(BusinessError::Sql)?;
                    Err::<(), BusinessError>(BusinessError::Declined("business-rule"))
                })
            })
            .await,
        |e| {
            matches!(
                e,
                TransactionError::Operation(BusinessError::Declined("business-rule"))
            )
        },
    );
    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM public.business_changes")
        .fetch_one(admin)
        .await?;
    assert_eq!(rows, 0);
    assert!(committed(store.append(&request, control).await)?.inserted());
    let request = store
        .prepare(event(t, "atomic", "rollback-ack-loss", vec![])?, control)
        .await?;
    store.inject_next_fault(PgFault::RollbackFailedAfterAck);
    let staged = request.clone();
    let attempt = store
        .write_tx_with_context(t, control, (), move |_, tx| {
            Box::pin(async move {
                tx.append(&staged).await.map_err(BusinessError::Audit)?;
                Err::<(), BusinessError>(BusinessError::Declined("rollback-ack-loss"))
            })
        })
        .await;
    assert!(attempt.fold(
        |_| false,
        |_| false,
        |_| false,
        |e| matches!(e,TransactionError::Rollback {operation,..}
            if matches!(*operation,TransactionError::Operation(BusinessError::Declined("rollback-ack-loss")))),
        |_| false,
        |_| false
    ));
    assert!(committed(store.append(&request, control).await)?.inserted());
    Ok(())
}

async fn unknown(
    store: &PgAudit,
    id: &str,
    control: &Control<'_, TestClock>,
) -> anyhow::Result<()> {
    // Use distinct source IDs for the two explicit modes; timestamp and bytes never regenerate.
    let request = store
        .prepare(event(tenant()?, id, "commit-ack-loss", vec![4])?, control)
        .await?;
    store.inject_next_fault(PgFault::CommitUnknownAfterAck);
    assert!(store.append(&request, control).await.fold(
        |_| false,
        |_| false,
        |_| false,
        |_| false,
        |_| true,
        |_| false
    ));
    let replay = committed(
        store
            .append(
                &PreparedAuditV1::from_canonical_bytes(request.canonical_bytes())?,
                control,
            )
            .await,
    )?;
    assert!(!replay.inserted());
    assert_eq!(
        replay.record().prepared().canonical_bytes(),
        request.canonical_bytes()
    );
    let clock = TestClock;
    let cancel = CancellationToken::new();
    let cutoff = Deadline::from_timeout(&clock, Duration::from_millis(400))?;
    let short = Control::new(&clock, cutoff, cutoff, &cancel);
    let pending = store
        .prepare(event(tenant()?, id, "before-commit", vec![])?, control)
        .await?;
    store.inject_next_fault(PgFault::BeforeCommitPending);
    assert!(store.append(&pending, &short).await.fold(
        |_| false,
        |_| false,
        |_| false,
        |_| true,
        |_| false,
        |_| false
    ));
    assert!(committed(store.append(&pending, control).await)?.inserted());
    cancel.cancel();
    assert!(store.append(&pending, &short).await.fold(
        |_| false,
        |e| matches!(e, Error::Cancelled(_)),
        |_| false,
        |_| false,
        |_| false,
        |_| false
    ));
    Ok(())
}

async fn racing(
    store: &PgAudit,
    source: &str,
    control: &Control<'_, TestClock>,
) -> anyhow::Result<()> {
    let request = store
        .prepare(event(tenant()?, source, "same", vec![7])?, control)
        .await?;
    let all = futures::future::join_all((0..8).map(|_| store.append(&request, control))).await;
    let mut inserted = 0;
    for attempt in all {
        inserted += usize::from(committed(attempt)?.inserted());
    }
    assert_eq!(inserted, 1);
    let first = store
        .prepare(event(tenant()?, source, "conflict", vec![1])?, control)
        .await?;
    let second = store
        .prepare(event(tenant()?, source, "conflict", vec![2])?, control)
        .await?;
    let (a, b) = tokio::join!(
        store.append(&first, control),
        store.append(&second, control)
    );
    let classify = |attempt: LocalTxAttempt<Committed<rss_audit_postgres::StagedAppend>, Error>| {
        attempt.fold(
            |_| 1,
            |_| 0,
            |e| if matches!(e, Error::Conflict) { 2 } else { 0 },
            |_| 0,
            |_| 0,
            |_| 0,
        )
    };
    assert_eq!(classify(a) + classify(b), 3);
    Ok(())
}
async fn termination(store: &PgAudit, control: &Control<'_, TestClock>) -> anyhow::Result<()> {
    let request = store
        .prepare(
            event(tenant()?, "terminated", "operation", vec![])?,
            control,
        )
        .await?;
    let staged = request.clone();
    let result = store
        .write_tx_with_context(tenant()?, control, (), move |_, tx| {
            Box::pin(async move {
                tx.append(&staged).await?;
                tx.with_connection(|c| {
                    Box::pin(async move {
                        sqlx::query("SELECT pg_terminate_backend(pg_backend_pid())")
                            .execute(c)
                            .await?;
                        Ok::<(), Error>(())
                    })
                })
                .await
            })
        })
        .await;
    assert!(result.fold(
        |_| false,
        |_| false,
        |_| false,
        |_| true,
        |_| true,
        |_| false
    ));
    assert!(committed(store.append(&request, control).await)?.inserted());
    Ok(())
}
