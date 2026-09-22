use super::*;

pub(super) async fn run<T: Timer>(
    store: &PgLedger,
    pool: &PgPool,
    owner: &PgPool,
    control: &Control<'_, T>,
) -> anyhow::Result<()> {
    scope(pool, control).await?;
    visibility(store, pool, control).await?;
    commit(store, pool, control).await?;
    replay(pool, control).await?;
    cancellation(pool).await?;
    permissions(pool, owner, control).await
}

async fn scope<T: Timer>(pool: &PgPool, control: &Control<'_, T>) -> anyhow::Result<()> {
    let request = request("borrowed", "event", b"original")?;
    let authenticator = auth()?;
    let mut tx = pool.begin().await?;
    for tenant in ["", "f47ac10b-58cc-4372-a567-0e02b2c3d480", "invalid"] {
        sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
            .bind(tenant)
            .execute(&mut *tx)
            .await?;
        assert!(matches!(
            append_in_transaction(&mut tx, &authenticator, &request, control).await,
            Err(Error::Protocol(rss_ledger::Error::ScopeMismatch))
        ));
        assert!(matches!(
            read_window_in_transaction(
                &mut tx,
                &authenticator,
                request.ledger(),
                Sequence::new(0),
                ReadLimit::new(1, 4096)?,
                control
            )
            .await,
            Err(Error::Protocol(rss_ledger::Error::ScopeMismatch))
        ));
    }
    tx.rollback().await?;
    Ok(())
}

async fn visibility<T: Timer>(
    store: &PgLedger,
    pool: &PgPool,
    control: &Control<'_, T>,
) -> anyhow::Result<()> {
    let request = request("borrowed", "event", b"original")?;
    let authenticator = auth()?;
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(TENANT)
        .execute(&mut *tx)
        .await?;
    let staged = append_in_transaction(&mut tx, &authenticator, &request, control).await?;
    assert!(staged.inserted());
    let window = read_window_in_transaction(
        &mut tx,
        &authenticator,
        request.ledger(),
        Sequence::new(0),
        ReadLimit::new(1, 4096)?,
        control,
    )
    .await?;
    assert_eq!(window.entries().len(), 1);
    assert!(
        committed(
            store
                .find(request.ledger(), request.record_id(), control)
                .await
        )?
        .is_none()
    );
    let tenant: String = sqlx::query_scalar("SELECT current_setting('rss.tenant_id')")
        .fetch_one(&mut *tx)
        .await?;
    assert_eq!(tenant, TENANT);
    tx.rollback().await?;
    assert!(
        committed(
            store
                .find(request.ledger(), request.record_id(), control)
                .await
        )?
        .is_none()
    );

    Ok(())
}

async fn commit<T: Timer>(
    store: &PgLedger,
    pool: &PgPool,
    control: &Control<'_, T>,
) -> anyhow::Result<()> {
    let request = request("borrowed", "event", b"original")?;
    let authenticator = auth()?;
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(TENANT)
        .execute(&mut *tx)
        .await?;
    append_in_transaction(&mut tx, &authenticator, &request, control).await?;
    tx.commit().await?;
    assert!(
        committed(
            store
                .find(request.ledger(), request.record_id(), control)
                .await
        )?
        .is_some()
    );
    Ok(())
}

async fn replay<T: Timer>(pool: &PgPool, control: &Control<'_, T>) -> anyhow::Result<()> {
    let request = request("borrowed", "event", b"original")?;
    let authenticator = auth()?;
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(TENANT)
        .execute(&mut *tx)
        .await?;
    assert!(
        !append_in_transaction(&mut tx, &authenticator, &request, control)
            .await?
            .inserted()
    );
    let changed = super::request("borrowed", "event", b"changed")?;
    assert!(matches!(
        append_in_transaction(&mut tx, &authenticator, &changed, control).await,
        Err(Error::Conflict)
    ));
    assert!(matches!(
        read_window_in_transaction(
            &mut tx,
            &authenticator,
            request.ledger(),
            Sequence::new(0),
            ReadLimit::new(1, 1)?,
            control
        )
        .await,
        Err(Error::ReadBudgetExceeded)
    ));
    tx.rollback().await?;

    Ok(())
}

async fn cancellation(pool: &PgPool) -> anyhow::Result<()> {
    let request = request("borrowed", "event", b"original")?;
    let authenticator = auth()?;
    let clock = Clock::new();
    let cancel = CancellationToken::new();
    cancel.cancel();
    let stopped = Control::new(&clock, Duration::from_secs(5), &cancel);
    let mut tx = pool.begin().await?;
    assert!(matches!(
        append_in_transaction(&mut tx, &authenticator, &request, &stopped).await,
        Err(Error::Cancelled(LocalTxDeadlineStage::Operation))
    ));
    assert!(matches!(
        read_window_in_transaction(
            &mut tx,
            &authenticator,
            request.ledger(),
            Sequence::new(0),
            ReadLimit::new(1, 4096)?,
            &stopped
        )
        .await,
        Err(Error::Cancelled(LocalTxDeadlineStage::Operation))
    ));
    tx.rollback().await?;

    Ok(())
}

async fn permissions<T: Timer>(
    pool: &PgPool,
    owner: &PgPool,
    control: &Control<'_, T>,
) -> anyhow::Result<()> {
    let request = request("borrowed", "event", b"original")?;
    let authenticator = auth()?;
    sqlx::raw_sql("GRANT UPDATE ON rss_ledger.entries TO ledger_runtime")
        .execute(owner)
        .await?;
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(TENANT)
        .execute(&mut *tx)
        .await?;
    assert!(matches!(
        append_in_transaction(&mut tx, &authenticator, &request, control).await,
        Err(Error::Admission(_))
    ));
    assert!(matches!(
        read_window_in_transaction(
            &mut tx,
            &authenticator,
            request.ledger(),
            Sequence::new(0),
            ReadLimit::new(1, 4096)?,
            control
        )
        .await,
        Err(Error::Admission(_))
    ));
    tx.rollback().await?;
    sqlx::raw_sql("REVOKE UPDATE ON rss_ledger.entries FROM ledger_runtime")
        .execute(owner)
        .await?;
    Ok(())
}
