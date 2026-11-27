use super::*;
use rss_ledger::Sequence;
use rss_ledger_postgres::ReadLimit as WindowLimit;

pub(super) async fn verified_reads(
    store: &PgAudit,
    admin: &PgPool,
    control: &Control<'_, TestClock>,
) -> anyhow::Result<()> {
    let tenant = TenantId::parse("abe11111-1111-4111-8111-111111111111")?;
    let read = async |start, rows| {
        let limit = WindowLimit::new(rows, 4 << 20)?;
        Ok::<_, anyhow::Error>(
            store
                .read_verified(tenant, Sequence::new(start), limit, control)
                .await,
        )
    };
    // Keep setup outside the SQL/authentication/decoding measurement.
    let check = async |start: u64, limit, expected: usize, chunks| -> anyhow::Result<()> {
        let counts = Counts::default();
        let subscriber = tracing_subscriber::registry().with(counts.clone());
        let window = committed(read(start, limit).with_subscriber(subscriber).await?)?;
        assert_eq!(counts.associations.load(Ordering::Relaxed), chunks);
        assert_eq!(
            counts.authenticated.load(Ordering::Relaxed),
            expected + usize::from(start > 0)
        );
        assert_eq!(counts.decoded.load(Ordering::Relaxed), expected);
        assert_eq!(window.records().len(), expected);
        for (offset, row) in window.records().iter().enumerate() {
            let seq = start + offset as u64;
            assert_eq!(row.sequence().get(), seq);
            assert_eq!(
                row.record().event().identity().event_id().as_str(),
                format!("r{seq}")
            );
        }
        Ok(())
    };
    check(0, 1, 0, 0).await?;
    seed_window(store, tenant, control).await?;
    for (start, limit, count, chunks) in [
        (0, 1, 1, 1),
        (0, 8, 8, 1),
        (0, 32, 32, 1),
        (0, 33, 33, 2),
        (0, 1024, 1024, 32),
        (1, 32, 32, 1),
        // The eighth fits in the canonical-byte budget but exceeds the complete Bind budget.
        (1024, 7, 7, 1),
        (1024, 8, 8, 2),
        (1032, 1, 0, 0),
    ] {
        check(start, limit, count, chunks).await?;
    }

    cancelled_before_association(store, tenant).await?;
    // The second chunk contains a good row (32) followed by a damaged row (33).
    for statement in [
        "UPDATE rss_audit.records SET canonical=set_byte(canonical,octet_length(canonical)-1,8) WHERE tenant_id=$1::uuid AND ledger_sequence=33",
        "DELETE FROM rss_audit.records WHERE tenant_id=$1::uuid AND ledger_sequence=33",
    ] {
        assert_eq!(
            sqlx::query(statement)
                .bind(tenant.to_string())
                .execute(admin)
                .await?
                .rows_affected(),
            1
        );
        rolled_back(read(0, 34).await?, |err| {
            matches!(err, Error::StorageContract)
        });
    }

    // Read an intact entry whose predecessor no longer authenticates.
    sqlx::query("UPDATE rss_ledger.entries SET payload=decode('00','hex') WHERE tenant_id=$1::uuid AND seq=0")
        .bind(tenant.to_string()).execute(admin).await?;
    rolled_back(read(1, 1).await?, |err| {
        matches!(
            err,
            Error::Ledger(rss_ledger_postgres::Error::Protocol(
                rss_ledger::Error::Authentication
            ))
        )
    });
    Ok(())
}

async fn seed_window(
    store: &PgAudit,
    tenant: TenantId,
    control: &Control<'_, TestClock>,
) -> anyhow::Result<()> {
    for (start, count, large) in [(0, 1024, false), (1024, 8, true)] {
        let at = Timepoint::try_from(321_i64)?;
        let mut records = Vec::with_capacity(count);
        for seq in start..start + count {
            let id = format!("r{seq}");
            let size = if large {
                // Leave 400 bytes of payload headroom across eight records: the tenant,
                // headers and IDs fit there only if row framing is incorrectly omitted.
                let headroom = if seq == start + count - 1 { 400 } else { 0 };
                MAX_RECORD_BYTES - canonical_len(&event(tenant, "cost", &id, vec![])?)? - headroom
            } else {
                1
            };
            records.push(prepare(event(tenant, "cost", &id, vec![7; size])?, at)?);
        }
        committed(
            store
                .write_tx_with_context(
                    tenant,
                    control,
                    Some(store.try_admit(&records)?),
                    |batch, tx| {
                        Box::pin(async move {
                            tx.append_admitted(batch.take().ok_or(Error::StorageContract)?)
                                .await?;
                            Ok::<_, Error>(())
                        })
                    },
                )
                .await,
        )?;
    }
    Ok(())
}

async fn cancelled_before_association(store: &PgAudit, tenant: TenantId) -> anyhow::Result<()> {
    use rss_transactional_messaging::transaction::LocalTxDeadlineStage as Stage;
    let cancel = CancellationToken::new();
    let cutoff = Deadline::from_timeout(&TestClock, Duration::from_secs(10))?;
    let control = Control::new(&TestClock, cutoff, cutoff, &cancel);
    let counts = Counts {
        cancel_on_decode: Some(cancel.clone()),
        ..Counts::default()
    };
    let attempt = store
        .read_verified(
            tenant,
            Sequence::new(0),
            WindowLimit::new(1, 10_000)?,
            &control,
        )
        .with_subscriber(tracing_subscriber::registry().with(counts.clone()))
        .await;
    let failure = attempt.fold(|_| None, |_| None, |_| None, Some, |_| None, |_| None);
    assert!(
        matches!(failure, Some(Error::Rollback {operation, settlement})
        if matches!(*operation, Error::Cancelled(Stage::Operation)) && matches!(*settlement, Error::Cancelled(Stage::Rollback)))
    );
    assert_eq!(counts.decoded.load(Ordering::Relaxed), 1);
    assert_eq!(counts.associations.load(Ordering::Relaxed), 0);
    Ok(())
}
