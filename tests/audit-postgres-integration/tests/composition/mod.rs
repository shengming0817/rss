use super::*;
mod deadline;
mod locking;
mod readonly;

pub(super) async fn run(
    plain: &PgAudit,
    ledger: &PgAudit,
    admin: &PgPool,
    control: &Control<'_, TestClock>,
) -> anyhow::Result<()> {
    readonly::run(plain, ledger, admin, control).await?;
    deadline::run(plain).await?;
    for (mode, store) in [("compose-plain", plain), ("compose-ledger", ledger)] {
        let empty_tenant = TenantId::parse(if mode == "compose-plain" {
            "f47ac10b-58cc-4372-a567-0e02b2c3d481"
        } else {
            "f47ac10b-58cc-4372-a567-0e02b2c3d482"
        })?;
        committed(store.write_tx_with_context(empty_tenant, control, (), move |_, tx| Box::pin(async move {
            tx.with_connection(move |c| Box::pin(async move {
                let records: i64 = sqlx::query_scalar("SELECT count(*) FROM rss_audit.records WHERE tenant_id=$1::uuid").bind(empty_tenant.to_string()).fetch_one(c).await?;
                assert_eq!(records, 0);
                Ok::<_,Error>(())
            })).await
        })).await)?;
        let e = event(tenant()?, mode, "final-fact", vec![7])?;
        let prepared = store.prepare(e, control).await?;
        let bytes = committed(
            store
                .write_tx_with_context(tenant()?, control, (), move |_, tx| {
                    Box::pin(async move {
                        let appended = tx.append(&prepared).await?;
                        assert!(appended.inserted());
                        Ok::<_, Error>(appended.record().prepared().canonical_bytes().to_vec())
                    })
                })
                .await,
        )?;
        let mut recovered = Vec::new();
        committed(
            store
                .write_tx_with_context(
                    tenant()?,
                    control,
                    (&bytes, &mut recovered),
                    |(expected, recovered), tx| {
                        Box::pin(async move {
                            tx.with_connection_context(recovered, |buffer, c| {
                                Box::pin(async move {
                                    let marker: i32 =
                                        sqlx::query_scalar("SELECT 1").fetch_one(c).await?;
                                    assert_eq!(marker, 1);
                                    assert!(buffer.is_empty());
                                    Ok::<_, sqlx::Error>(())
                                })
                            })
                            .await
                            .map_err(Error::from)?;
                            let prepared =
                                PreparedAuditV1::from_canonical_bytes(expected.as_slice())?;
                            let appended = tx.append(&prepared).await?;
                            recovered
                                .extend_from_slice(appended.record().prepared().canonical_bytes());
                            assert!(!appended.inserted());
                            Ok::<_, Error>(())
                        })
                    },
                )
                .await,
        )?;
        assert_eq!(recovered, bytes);
    }
    Ok(())
}

pub(super) async fn single_connection(pool: &PgPool) -> anyhow::Result<()> {
    locking::run(pool).await?;
    let one = PgPoolOptions::new()
        .max_connections(1)
        .connect_with(pool.connect_options().as_ref().clone())
        .await?;
    let clock = TestClock;
    let cancel = CancellationToken::new();
    let cutoff = Deadline::from_timeout(&clock, Duration::from_secs(5))?;
    let control = Control::new(&clock, cutoff, cutoff, &cancel);
    let store = PgAudit::new(
        one.clone(),
        Integrity::Ledger(auth()?),
        write_budget()?,
        &control,
    )
    .await?;
    let prepared = store
        .prepare(
            event(tenant()?, "single-connection", "id", vec![4])?,
            &control,
        )
        .await?;
    committed(
        store
            .write_tx_with_context(tenant()?, &control, (), move |_, tx| {
                Box::pin(async move {
                    tx.append(&prepared).await?;
                    Ok::<_, Error>(())
                })
            })
            .await,
    )?;
    let wrong = TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d480")?;
    let foreign = store
        .prepare(event(wrong, "scope", "id", vec![])?, &control)
        .await?;
    rolled_back(
        store
            .write_tx_with_context(tenant()?, &control, (), move |_, tx| {
                Box::pin(async move {
                    assert!(matches!(
                        tx.append(&foreign).await,
                        Err(Error::ScopeMismatch)
                    ));
                    Err::<(), Error>(Error::ScopeMismatch)
                })
            })
            .await,
        |e| matches!(e, TransactionError::Operation(Error::ScopeMismatch)),
    );
    one.close().await;
    Ok(())
}
