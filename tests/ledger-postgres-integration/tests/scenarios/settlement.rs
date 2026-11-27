use super::*;

pub(super) async fn run(store: &PgLedger, control: &Control<'_, TestClock>) -> anyhow::Result<()> {
    let item = request("settlement-state", "staged", b"bytes")?;
    let staged = item.clone();
    let result = store
        .local_tx(item.ledger().tenant(), control, move |tx| {
            Box::pin(async move {
                tx.append(&staged).await?;
                let caught = tx
                    .with_connection(|c| {
                        Box::pin(async move { sqlx::query("SELECT 1 / 0").execute(c).await })
                    })
                    .await;
                assert!(caught.is_err());
                Ok(())
            })
        })
        .await;
    assert!(matches!(
        observe(result),
        Observed::RolledBack(Error::Storage(_))
    ));
    assert!(committed(store.find(item.ledger(), item.record_id(), control).await)?.is_none());

    let clock = TestClock;
    let token = CancellationToken::new();
    let signal = token.clone();
    let long = Control::new(
        &clock,
        Deadline::from_timeout(&clock, Duration::from_secs(60 * 60 * 24 * 365))?,
        &token,
    );
    let result = store.local_tx(item.ledger().tenant(), &long, move |tx| Box::pin(async move {
        let millis = tx.with_connection(|c| Box::pin(async move {
            sqlx::query_scalar::<_, i64>("SELECT setting::bigint FROM pg_settings WHERE name='statement_timeout'")
                .fetch_one(c).await
        })).await?;
        assert_eq!(millis, i64::from(i32::MAX));
        signal.cancel();
        Err::<(), Error>(Error::Rejected)
    })).await;
    assert!(
        matches!(observe(result), Observed::CommitUnknown(Error::Rollback { operation, settlement })
        if matches!(*operation, Error::Rejected) && matches!(*settlement, Error::Cancelled(LocalTxDeadlineStage::Rollback)))
    );
    Ok(())
}
