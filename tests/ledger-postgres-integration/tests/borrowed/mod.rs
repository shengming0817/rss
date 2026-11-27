use super::*;
mod batches;
mod interruption;
mod locking;

pub(super) async fn run<T: ExecutionTimer>(
    store: &PgLedger,
    pool: &PgPool,
    owner: &PgPool,
    control: &Control<'_, T>,
) -> anyhow::Result<()> {
    locking::run(pool, control).await?;
    scope(pool, control).await?;
    same_chain_batch(pool, control).await?;
    batches::run(pool, owner, control).await?;
    visibility(store, pool, control).await?;
    commit(store, pool, control).await?;
    replay(pool, control).await?;
    validation_budget(pool).await?;
    cancellation(pool).await?;
    interruption::run(store, pool, owner, control).await?;
    permissions(pool, owner, control).await
}

async fn scope<T: ExecutionTimer>(pool: &PgPool, control: &Control<'_, T>) -> anyhow::Result<()> {
    let request = request("borrowed", "event", b"original")?;
    let authenticator = auth()?;
    let mut tx = pool.begin().await?;
    for tenant in ["", "f47ac10b-58cc-4372-a567-0e02b2c3d480", "invalid"] {
        sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
            .bind(tenant)
            .execute(&mut *tx)
            .await?;
        assert!(matches!(
            lock_head_in_transaction(&mut tx, &authenticator, request.ledger(), control).await,
            Err(Error::Protocol(rss_ledger::Error::ScopeMismatch))
        ));
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

async fn visibility<T: ExecutionTimer>(
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
    lock_head_in_transaction(&mut tx, &authenticator, request.ledger(), control).await?;
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
    assert_eq!(window.verified().entries().len(), 1);
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

async fn commit<T: ExecutionTimer>(
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

async fn replay<T: ExecutionTimer>(pool: &PgPool, control: &Control<'_, T>) -> anyhow::Result<()> {
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
    let clock = TestClock;
    let cancel = CancellationToken::new();
    cancel.cancel();
    let stopped = Control::new(
        &clock,
        Deadline::from_timeout(&clock, Duration::from_secs(5))?,
        &cancel,
    );
    let mut tx = pool.begin().await?;
    assert!(matches!(
        lock_head_in_transaction(&mut tx, &authenticator, request.ledger(), &stopped).await,
        Err(Error::Cancelled(LocalTxDeadlineStage::Operation))
    ));
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

async fn permissions<T: ExecutionTimer>(
    pool: &PgPool,
    owner: &PgPool,
    control: &Control<'_, T>,
) -> anyhow::Result<()> {
    let mut connection = pool.acquire().await?;
    validate_connection(&mut connection, control).await?;
    sqlx::raw_sql("GRANT UPDATE ON rss_ledger.entries TO ledger_runtime")
        .execute(owner)
        .await?;
    assert!(matches!(
        validate_connection(&mut connection, control).await,
        Err(Error::Admission(_))
    ));
    sqlx::raw_sql("REVOKE UPDATE ON rss_ledger.entries FROM ledger_runtime")
        .execute(owner)
        .await?;
    validate_connection(&mut connection, control).await?;
    Ok(())
}

async fn validation_budget(pool: &PgPool) -> anyhow::Result<()> {
    let clock = TestClock;
    let cancel = CancellationToken::new();
    cancel.cancel();
    let stopped = Control::new(
        &clock,
        Deadline::from_timeout(&clock, Duration::from_secs(5))?,
        &cancel,
    );
    let mut tx = pool.begin().await?;
    assert!(matches!(
        validate_connection(&mut tx, &stopped).await,
        Err(Error::Cancelled(LocalTxDeadlineStage::Setup))
    ));
    let running = CancellationToken::new();
    let expired = Control::new(&clock, Deadline::at(clock.now()), &running);
    assert!(matches!(
        validate_connection(&mut tx, &expired).await,
        Err(Error::Deadline(LocalTxDeadlineStage::Setup))
    ));
    tx.rollback().await?;
    Ok(())
}

async fn same_chain_batch<T: ExecutionTimer>(
    pool: &PgPool,
    control: &Control<'_, T>,
) -> anyhow::Result<()> {
    let auth = auth()?;
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(TENANT)
        .execute(&mut *tx)
        .await?;
    let mut rows = (0..33)
        .map(|i| request("batch", &format!("r{i}"), &[i]))
        .collect::<anyhow::Result<Vec<_>>>()?;
    rows.insert(1, rows[0].clone());
    rows.push(rows[0].clone());
    let ledger = rows[0].ledger().clone();
    assert!(
        append_batch_in_transaction(&mut tx, &auth, &[], control)
            .await?
            .is_empty()
    );
    assert!(matches!(
        append_batch_in_transaction(
            &mut tx,
            &auth,
            &[rows[0].clone(), request("different", "one", b"")?],
            control
        )
        .await,
        Err(Error::Protocol(rss_ledger::Error::ScopeMismatch))
    ));
    let first = append_batch_in_transaction(&mut tx, &auth, &rows, control).await?;
    assert_batch_positions(&first);
    let window = read_window_in_transaction(
        &mut tx,
        &auth,
        &ledger,
        Sequence::new(0),
        ReadLimit::new(33, 65536)?,
        control,
    )
    .await?;
    assert_eq!(window.verified().entries().len(), 33);
    let replay = append_batch_in_transaction(&mut tx, &auth, &rows, control).await?;
    assert!(
        replay
            .iter()
            .zip(first)
            .all(|((seq, added), (expected, _))| !added && *seq == expected)
    );
    tx.rollback().await?;
    Ok(())
}

fn assert_batch_positions(first: &[(Sequence, bool)]) {
    assert_eq!(first.len(), 35);
    assert_eq!(first[0], (Sequence::new(0), true));
    assert_eq!(first[1], (Sequence::new(0), false));
    assert_eq!(first[33], (Sequence::new(32), true));
    assert_eq!(first[34], (Sequence::new(0), false));
}
