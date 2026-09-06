use super::{Timer, deadline, message, outbox_budget};
use rss_transactional_messaging::{
    error::MessagingErrorKind,
    outbox::{AppendOutcome, OutboxStore, PendingMessage},
    transaction::LocalTxAttempt,
};
use rss_transactional_messaging_postgres::{
    PgConfig, PgError, PgOutboxStore, PgRuntime, PgTransaction,
};
use std::{
    future::{Future, poll_fn},
    sync::Arc,
    task::Poll,
    time::Duration,
};

async fn write_business(tx: &mut PgTransaction<'_>, id: &'static str) -> Result<(), PgError> {
    let tenant = tx.tenant_id().to_string();
    tx.with_connection(move |connection| {
        Box::pin(async move {
            sqlx::query("INSERT INTO public.business_effects(tenant_id,id) VALUES($1::uuid,$2)")
                .bind(tenant)
                .bind(id)
                .execute(connection)
                .await?;
            Ok(())
        })
    })
    .await
}

pub(super) async fn business_outbox_atomicity(
    runtime: Arc<PgRuntime>,
    owner: &sqlx::PgPool,
) -> anyhow::Result<()> {
    for (id, rollback) in [("atomic-commit", false), ("atomic-rollback", true)] {
        let envelope = message(id);
        let tenant = envelope.metadata().tenant_id();
        let store = PgOutboxStore::<()>::new(
            runtime.clone(),
            envelope.metadata().domain().clone(),
            outbox_budget(Duration::from_secs(60)),
        )?;
        let attempt = runtime
            .local_tx(tenant, deadline(), move |tx| {
                Box::pin(async move {
                    write_business(tx, id).await?;
                    assert_eq!(
                        store.append(tx, PendingMessage::new(envelope)).await?,
                        AppendOutcome::Inserted
                    );
                    if rollback {
                        return Err(sqlx::Error::RowNotFound.into());
                    }
                    Ok(())
                })
            })
            .await;
        let committed = attempt.fold(|()| Ok(true), Err, |_| Ok(false), Err, Err, Err)?;
        assert_eq!(committed, !rollback);
        let counts: (i64, i64) = sqlx::query_as("SELECT (SELECT count(*) FROM public.business_effects WHERE id=$1), (SELECT count(*) FROM rss_transactional_messaging.outbox WHERE message_id=$1)")
            .bind(id).fetch_one(owner).await?;
        let expected = i64::from(!rollback);
        assert_eq!(counts, (expected, expected));
    }
    Ok(())
}

pub(super) async fn close_during_transaction(
    config: PgConfig,
    owner: &sqlx::PgPool,
) -> anyhow::Result<()> {
    let runtime = Arc::new(PgRuntime::connect(config.with_pool_limits(2, 2), Timer::new()).await?);
    let tenant = message("close").metadata().tenant_id();
    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    let transaction_runtime = runtime.clone();
    let transaction = tokio::spawn(async move {
        transaction_runtime
            .local_tx(tenant, deadline(), move |tx| {
                Box::pin(async move {
                    write_business(tx, "close-commit").await?;
                    entered_tx.send(()).expect("owner waiting for transaction");
                    release_rx.await.expect("owner releases transaction");
                    Ok(())
                })
            })
            .await
    });
    entered_rx.await?;
    {
        // Poll exactly once: close must start, but cannot finish while the transaction is held.
        let mut closing = Box::pin(runtime.close());
        assert!(
            poll_fn(|cx| Poll::Ready(closing.as_mut().poll(cx)))
                .await
                .is_pending()
        );
        // Dropping this pending future simulates the host cancelling its shutdown wait.
    }
    assert!(runtime.is_closed());
    assert_admission_stopped(&runtime).await;
    let mut first = Box::pin(runtime.close());
    let mut second = Box::pin(runtime.close());
    assert!(
        poll_fn(|cx| Poll::Ready(first.as_mut().poll(cx)))
            .await
            .is_pending()
    );
    assert!(
        poll_fn(|cx| Poll::Ready(second.as_mut().poll(cx)))
            .await
            .is_pending()
    );
    release_tx
        .send(())
        .expect("transaction remains alive during close");
    let ((), (), result) = tokio::join!(first, second, transaction);
    result?.fold(Ok, Err, Err, Err, Err, Err)?;
    runtime.close().await;
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM public.business_effects WHERE id='close-commit'")
            .fetch_one(owner)
            .await?;
    assert_eq!(
        count, 1,
        "close must preserve acknowledged transaction commit"
    );
    Ok(())
}

async fn assert_admission_stopped(runtime: &PgRuntime) {
    let tenant = message("closed-pool").metadata().tenant_id();
    let rejected: LocalTxAttempt<(), PgError> = runtime
        .local_tx(tenant, deadline(), |_| {
            Box::pin(async { panic!("closed pool must not start the operation") })
        })
        .await;
    let not_started = rejected.fold(
        |()| false,
        |error| {
            assert_eq!(error.kind(), MessagingErrorKind::Permanent);
            true
        },
        |_| false,
        |_| false,
        |_| false,
        |_| false,
    );
    assert!(not_started);
}

#[cfg(feature = "rss-runtime")]
pub(super) async fn managed_close(config: PgConfig) -> anyhow::Result<()> {
    let runtime = PgRuntime::connect(config, Timer::new()).await?;
    assert!(!runtime.is_closed());
    rss_runtime::ManagedResource::shutdown(&runtime).await?;
    assert!(runtime.is_closed());
    runtime.close().await;
    Ok(())
}
