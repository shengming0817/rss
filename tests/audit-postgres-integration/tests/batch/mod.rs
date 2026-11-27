//! Logical order and durable outcomes across physical chunk boundaries.
use super::*;
use rss_audit_postgres::PgFault;

pub(super) async fn semantics(
    plain: &PgAudit,
    ledger: &PgAudit,
    pool: &PgPool,
    admin: &PgPool,
    control: &Control<'_, TestClock>,
) -> anyhow::Result<()> {
    competing_plain(plain, pool, admin, control).await?;
    replay_errors(ledger, pool, admin, control).await?;
    divergent_input(ledger, pool, admin, control).await?;
    for (mode, owner) in [("plain", plain), ("ledger", ledger)] {
        let tenant = TenantId::parse(if mode == "plain" {
            "10555663-d15a-46a0-bff3-9f73991fe730"
        } else {
            "10555663-d15a-46a0-bff3-9f73991fe731"
        })?;
        let at = Timepoint::try_from(456_i64)?;
        let make = |id: &str, payload| -> anyhow::Result<_> {
            Ok(prepare(event(tenant, mode, id, payload)?, at)?)
        };
        let old = make("old", vec![1])?;
        let original = committed(owner.append(&old, control).await)?;
        let mut rows = (0..33)
            .rev()
            .map(|i| make(&format!("r{i:02}"), vec![i]))
            .collect::<anyhow::Result<Vec<_>>>()?;
        rows.insert(1, old.clone());
        rows.extend([rows[0].clone(), old.clone()]);
        ordered(
            owner,
            pool,
            control,
            &rows,
            original.record().position(),
            mode,
        )
        .await?;
        let mut conflict = (0..32)
            .map(|i| make(&format!("rollback{i}"), vec![i]))
            .collect::<anyhow::Result<Vec<_>>>()?;
        conflict.push(make("old", vec![0])?);
        rollback_prefix(owner, admin, control, mode, conflict).await?;
        recover(owner, pool, admin, control, rows).await?;
    }
    Ok(())
}

async fn ordered(
    owner: &PgAudit,
    pool: &PgPool,
    control: &Control<'_, TestClock>,
    rows: &[PreparedAuditV1],
    original_position: u64,
    mode: &str,
) -> anyhow::Result<()> {
    let tenant = rows[0].identity().tenant();
    let mut tx = scoped_tx(pool, tenant).await?;
    let staged = owner
        .append_batch_in_transaction(&mut tx, owner.try_admit(rows)?, control)
        .await?;
    for (i, (receipt, request)) in staged.iter().zip(rows).enumerate() {
        assert_eq!(receipt.inserted(), i != 1 && i < 34);
        assert!(std::ptr::eq(
            receipt.record().prepared().canonical_bytes(),
            request.canonical_bytes()
        ));
    }
    assert_eq!(staged[1].record().position(), original_position);
    assert_eq!(
        staged[34].record().position(),
        staged[0].record().position()
    );
    assert_eq!(staged[35].record().position(), original_position);
    if mode == "ledger" {
        assert_eq!(staged[0].record().ledger_sequence(), Some(1));
        assert_eq!(staged[33].record().ledger_sequence(), Some(33));
    }
    tx.rollback().await?;

    Ok(())
}
async fn rollback_prefix(
    owner: &PgAudit,
    admin: &PgPool,
    control: &Control<'_, TestClock>,
    mode: &str,
    conflict: Vec<PreparedAuditV1>,
) -> anyhow::Result<()> {
    let tenant = conflict[0].identity().tenant();
    let scratch = format!("batch-{mode}");
    sqlx::raw_sql("CREATE TABLE IF NOT EXISTS public.batch_effect(id text PRIMARY KEY); GRANT INSERT ON public.batch_effect TO audit_runtime").execute(admin).await?;
    let attempt = owner
        .write_tx_with_context(
            tenant,
            control,
            (conflict, owner.clone(), scratch.clone()),
            |(rows, owner, id), tx| {
                Box::pin(async move {
                    tx.with_connection_context(id, |id, c| {
                        Box::pin(async move {
                            sqlx::query("INSERT INTO public.batch_effect VALUES($1)")
                                .bind(id.as_str())
                                .execute(c)
                                .await?;
                            Ok::<(), Error>(())
                        })
                    })
                    .await?;
                    tx.append_admitted(owner.try_admit(rows)?).await
                })
            },
        )
        .await;
    rolled_back(attempt, |e| {
        matches!(e, TransactionError::Operation(Error::Conflict))
    });
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM public.batch_effect WHERE id=$1")
            .bind(scratch)
            .fetch_one(admin)
            .await?,
        0
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM rss_audit.records WHERE tenant_id=$1::uuid"
        )
        .bind(tenant.to_string())
        .fetch_one(admin)
        .await?,
        1
    );
    if mode == "ledger" {
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT seq FROM rss_ledger.heads WHERE tenant_id=$1::uuid"
            )
            .bind(tenant.to_string())
            .fetch_one(admin)
            .await?,
            0
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT count(*) FROM rss_ledger.entries WHERE tenant_id=$1::uuid"
            )
            .bind(tenant.to_string())
            .fetch_one(admin)
            .await?,
            1
        );
    }

    Ok(())
}
async fn recover(
    owner: &PgAudit,
    pool: &PgPool,
    admin: &PgPool,
    control: &Control<'_, TestClock>,
    rows: Vec<PreparedAuditV1>,
) -> anyhow::Result<()> {
    let tenant = rows[0].identity().tenant();
    owner.inject_next_fault(PgFault::CommitUnknownAfterAck);
    let outcome = owner
        .write_tx_with_context(
            tenant,
            control,
            (rows.clone(), owner.clone()),
            |(rows, owner), tx| {
                Box::pin(async move { tx.append_admitted(owner.try_admit(rows)?).await })
            },
        )
        .await;
    assert!(outcome.fold(
        |_| false,
        |_| false,
        |_| false,
        |_| false,
        |_| true,
        |_| false
    ));
    let before = sqlx::query_as::<_, (String, i64, Option<i64>)>(
        "SELECT event_id,position,ledger_sequence FROM rss_audit.records WHERE tenant_id=$1::uuid",
    )
    .bind(tenant.to_string())
    .fetch_all(admin)
    .await?;
    let coords: std::collections::HashMap<_, _> = before
        .into_iter()
        .map(|(id, pos, seq)| (id, (pos, seq)))
        .collect();
    let mut tx = scoped_tx(pool, tenant).await?;
    let replay = owner
        .append_batch_in_transaction(&mut tx, owner.try_admit(&rows)?, control)
        .await?;
    for (receipt, request) in replay.iter().zip(&rows) {
        assert!(!receipt.inserted());
        let record = receipt.record();
        assert_eq!(record.prepared().recorded_at(), request.recorded_at());
        assert_eq!(
            record.prepared().canonical_bytes(),
            request.canonical_bytes()
        );
        assert_eq!(
            (
                record.position() as i64,
                record.ledger_sequence().map(|v| v as i64)
            ),
            coords[request.identity().event_id().as_str()]
        );
    }
    tx.commit().await?;
    Ok(())
}

async fn competing_plain(
    owner: &PgAudit,
    pool: &PgPool,
    admin: &PgPool,
    control: &Control<'_, TestClock>,
) -> anyhow::Result<()> {
    let tenant = TenantId::parse("9749781a-3274-43cf-9560-99feeb0c2753")?;
    for (id, loser_payload) in [("retry", 1u8), ("conflict", 2u8)] {
        let at = Timepoint::try_from(11_i64)?;
        let first = prepare(event(tenant, "wait", id, vec![1])?, at)?;
        let second = prepare(event(tenant, "wait", id, vec![loser_payload])?, at)?;
        let mut winner = pool.begin().await?;
        let pid: i32 =
            sqlx::query_scalar("SELECT pg_backend_pid() FROM set_config('rss.tenant_id',$1,true)")
                .bind(tenant.to_string())
                .fetch_one(&mut *winner)
                .await?;
        let original = owner
            .append_in_transaction(&mut winner, &first, control)
            .await?;
        let wait_and_release = async {
            tokio::time::timeout(Duration::from_secs(5),async {
                loop {
                    let blocked:bool=sqlx::query_scalar("SELECT EXISTS(SELECT FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid)))").bind(pid).fetch_one(admin).await?;
                    if blocked { return Ok::<(),sqlx::Error>(()); }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            }).await??;
            winner.commit().await?;
            Ok::<(), anyhow::Error>(())
        };
        let (outcome, released) = tokio::join!(owner.append(&second, control), wait_and_release);
        released?;
        if loser_payload == 1 {
            let replay = committed(outcome)?;
            assert!(!replay.inserted());
            assert_eq!(replay.record().position(), original.record().position());
        } else {
            rolled_back(outcome, |e| matches!(e, Error::Conflict));
        }
    }
    Ok(())
}

async fn replay_errors(
    owner: &PgAudit,
    pool: &PgPool,
    admin: &PgPool,
    control: &Control<'_, TestClock>,
) -> anyhow::Result<()> {
    let tenant = TenantId::parse("286618bf-2800-49a7-9730-b20d27930f10")?;
    let at = Timepoint::try_from(11_i64)?;
    let make = |id, payload| -> anyhow::Result<_> {
        Ok(prepare(event(tenant, "classify", id, payload)?, at)?)
    };
    let a = make("a", vec![1])?;
    let b = make("b", vec![1])?;
    committed(owner.append(&a, control).await)?;
    committed(owner.append(&b, control).await)?;
    sqlx::query("UPDATE rss_audit.records SET ledger_sequence=100 WHERE tenant_id=$1::uuid AND event_id='b'").bind(tenant.to_string()).execute(admin).await?;
    for (payload, reversed, ordinary_conflict) in [
        (vec![2, 3], true, true),
        (vec![2], false, true),
        (vec![2], true, false),
    ] {
        let different = make("a", payload)?;
        sqlx::query(
            "UPDATE rss_audit.records SET canonical=$2 WHERE tenant_id=$1::uuid AND event_id='a'",
        )
        .bind(tenant.to_string())
        .bind(different.canonical_bytes())
        .execute(admin)
        .await?;
        let rows = if reversed {
            [b.clone(), a.clone()]
        } else {
            [a.clone(), b.clone()]
        };
        let mut tx = scoped_tx(pool, tenant).await?;
        let result = owner
            .append_batch_in_transaction(&mut tx, owner.try_admit(&rows)?, control)
            .await;
        if ordinary_conflict {
            assert!(matches!(result, Err(Error::Conflict)));
        } else {
            assert!(matches!(result, Err(Error::StorageContract)));
        }
        tx.rollback().await?;
    }
    Ok(())
}

async fn scoped_tx(
    pool: &PgPool,
    tenant: TenantId,
) -> anyhow::Result<sqlx::Transaction<'static, sqlx::Postgres>> {
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(tenant.to_string())
        .execute(&mut *tx)
        .await?;
    Ok(tx)
}

async fn divergent_input(
    owner: &PgAudit,
    pool: &PgPool,
    admin: &PgPool,
    control: &Control<'_, TestClock>,
) -> anyhow::Result<()> {
    let tenant = TenantId::parse("286618bf-2800-49a7-9730-b20d27930f11")?;
    let make = |id: &str, v| -> anyhow::Result<_> {
        Ok(prepare(
            event(tenant, "bad-tail", id, vec![v])?,
            Timepoint::try_from(1_i64)?,
        )?)
    };
    let seed = make("seed", 1)?;
    committed(owner.append(&seed, control).await)?;
    let mut rows = (0..33)
        .map(|i| make(&format!("r{i}"), i))
        .collect::<anyhow::Result<Vec<_>>>()?;
    rows.push(make("r0", 255)?);
    let mut tx = scoped_tx(pool, tenant).await?;
    let added = owner
        .append_batch_in_transaction(&mut tx, owner.try_admit(&rows)?, control)
        .await;
    assert!(matches!(added, Err(Error::Conflict)));
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM rss_ledger.entries")
        .fetch_one(&mut *tx)
        .await?;
    assert_eq!(count, 1);
    tx.rollback().await?;
    sqlx::query("UPDATE rss_ledger.entries SET payload='bad'::bytea WHERE tenant_id=$1::uuid")
        .bind(tenant.to_string())
        .execute(admin)
        .await?;
    let mut tx = scoped_tx(pool, tenant).await?;
    let result = owner
        .append_batch_in_transaction(&mut tx, owner.try_admit(&rows)?, control)
        .await;
    assert!(matches!(
        result,
        Err(Error::Ledger(rss_ledger_postgres::Error::Protocol(
            rss_ledger::Error::Authentication
        )))
    ));
    tx.rollback().await?;
    Ok(())
}
