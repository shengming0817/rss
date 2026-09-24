use super::*;

#[allow(clippy::cognitive_complexity)]
// reason: one bounded two-transaction scenario keeps reservation and settlement assertions together.
pub(super) async fn run<T: Timer>(pool: &PgPool, control: &Control<'_, T>) -> anyhow::Result<()> {
    let r = request("lock-first", "conditional", b"final fact")?;
    let a = auth()?;
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(TENANT)
        .execute(&mut *tx)
        .await?;
    lock_head_in_transaction(&mut tx, &a, r.ledger(), control).await?;
    lock_head_in_transaction(&mut tx, &a, r.ledger(), control).await?;
    let empty: bool = sqlx::query_scalar("SELECT seq IS NULL FROM rss_ledger.heads WHERE tenant_id=$1::uuid AND chain_id='lock-first'").bind(TENANT).fetch_one(&mut *tx).await?;
    assert!(empty);
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM rss_ledger.entries WHERE tenant_id=$1::uuid AND chain_id='lock-first'").bind(TENANT).fetch_one(&mut *tx).await?;
    assert_eq!(count, 0);
    // A second transaction cannot overtake the reservation, even on an empty chain.
    let mut second = pool.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(TENANT)
        .execute(&mut *second)
        .await?;
    let clock = Clock::new();
    let cancel = CancellationToken::new();
    let short = Control::new(&clock, Duration::from_millis(250), &cancel);
    // Only the transaction owner configures server execution limits.
    sqlx::query("SET LOCAL statement_timeout='100ms'")
        .execute(&mut *second)
        .await?;
    assert!(matches!(
        lock_head_in_transaction(&mut second, &a, r.ledger(), &short).await,
        Err(Error::Cancelled(LocalTxDeadlineStage::Operation)
            | Error::Deadline(LocalTxDeadlineStage::Operation))
    ));
    // The blocker remains held: owner-projected server timeout must permit rollback.
    tokio::time::timeout(Duration::from_millis(500), second.rollback()).await??;
    assert!(
        append_in_transaction(&mut tx, &a, &r, control)
            .await?
            .inserted()
    );
    tx.commit().await?;

    let mut tx = pool.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(TENANT)
        .execute(&mut *tx)
        .await?;
    lock_head_in_transaction(&mut tx, &a, r.ledger(), control).await?;
    assert!(
        !append_in_transaction(&mut tx, &a, &r, control)
            .await?
            .inserted()
    );
    tx.rollback().await?;
    Ok(())
}
