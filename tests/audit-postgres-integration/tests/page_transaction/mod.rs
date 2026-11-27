//! Storage invariants shared by audited and read-only page consumers.
use super::*;

pub(super) async fn run(
    pg: &PgAudit,
    ledger: &PgAudit,
    pool: &PgPool,
    admin: &PgPool,
    control: &Control<'_, TestClock>,
) -> anyhow::Result<()> {
    let (tenant, bytes) = seed_capacity(pg, ledger, pool, control).await?;
    page_limits(pg, tenant, bytes, control).await?;
    self_audit(pg, tenant, bytes, admin, control).await?;
    interrupted_read(pg, admin, tenant, false).await?;
    interrupted_read(pg, admin, tenant, true).await
}

async fn page_limits(
    pg: &PgAudit,
    tenant: TenantId,
    bytes: u64,
    control: &Control<'_, TestClock>,
) -> anyhow::Result<()> {
    let cursor = Cursor::start(tenant);
    let exact = ReadLimit::new(1024, bytes)?;
    let short = ReadLimit::new(1024, bytes - 1)?;
    let page = committed(pg.read_page(cursor, exact, control).await)?;
    assert_eq!(page.records().len(), 1024);
    assert!(page.next().is_none());
    assert!(page.records()[0].ledger_sequence().is_some());
    assert!(
        page.records()[1..]
            .iter()
            .all(|r| r.ledger_sequence().is_none())
    );
    let first = committed(
        pg.read_page(cursor, ReadLimit::new(1000, bytes)?, control)
            .await,
    )?;
    let tail = committed(
        pg.read_page(first.next().context("continuation")?, exact, control)
            .await,
    )?;
    assert_eq!((first.records().len(), tail.records().len()), (1000, 24));
    assert_eq!(
        first.records()[999].position() + 1,
        tail.records()[0].position()
    );
    assert!(tail.next().is_none());
    rolled_back(pg.read_page(cursor, short, control).await, |e| {
        matches!(e, Error::ReadBudgetExceeded)
    });

    Ok(())
}

async fn self_audit(
    pg: &PgAudit,
    tenant: TenantId,
    bytes: u64,
    admin: &PgPool,
    control: &Control<'_, TestClock>,
) -> anyhow::Result<()> {
    let cursor = Cursor::start(tenant);
    let exact = ReadLimit::new(1024, bytes)?;
    let short = ReadLimit::new(1024, bytes - 1)?;
    let query = pg
        .prepare(event(tenant, "query", "audit-page", vec![])?, control)
        .await?;
    let audited_read = |limit| {
        let batch = pg.try_admit(std::slice::from_ref(&query))?;
        Ok::<_, Error>(
            pg.write_tx_with_context(tenant, control, Some(batch), move |batch, tx| {
                Box::pin(async move {
                    let page = tx.read_page(cursor, limit).await?;
                    tx.append_admitted(batch.take().ok_or(Error::StorageContract)?)
                        .await?;
                    Ok::<_, Error>(page)
                })
            }),
        )
    };
    rolled_back(audited_read(short)?.await, |e| {
        matches!(e, TransactionError::Operation(Error::ReadBudgetExceeded))
    });
    let count_query =
        || {
            sqlx::query_scalar::<_, i64>(
        "SELECT count(*) FROM rss_audit.records WHERE tenant_id=$1::uuid AND source_id='query'"
    ).bind(tenant.to_string()).fetch_one(admin)
        };
    assert_eq!(count_query().await?, 0);
    pg.inject_next_fault(rss_audit_postgres::PgFault::CommitUnknownAfterAck);
    assert!(audited_read(exact)?.await.fold(
        |_| false,
        |_| false,
        |_| false,
        |_| false,
        |_| true,
        |_| false
    ));
    assert_eq!(count_query().await?, 1);
    assert!(!committed(pg.append(&query, control).await)?.inserted());
    Ok(())
}

async fn seed_capacity(
    pg: &PgAudit,
    ledger: &PgAudit,
    pool: &PgPool,
    control: &Control<'_, TestClock>,
) -> anyhow::Result<(TenantId, u64)> {
    let tenant = TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d502")?;
    let token = "a".repeat(255);
    let base = event(tenant, &token, &token, vec![])?;
    let maximal = AuditEventV1::new(
        base.identity().clone(),
        EventFacts::new(
            ActorRef::new(ActorKind::parse("user")?, ActorId::parse("actor")?),
            Action::parse(&token)?,
            ResourceRef::new(
                ResourceKind::parse("device")?,
                ResourceId::parse("resource")?,
            ),
            Outcome::Succeeded,
            Timepoint::try_from(123_i64)?,
        ),
        EventContext::new(
            Coordinates::new(None, None, None),
            AuditPayload::new(vec![])?,
        ),
    );
    let first = prepare(maximal, Timepoint::try_from(456_i64)?)?;
    committed(ledger.append(&first, control).await)?;
    let rows = (1..1024)
        .map(|n| -> anyhow::Result<PreparedAuditV1> {
            Ok(prepare(
                event(tenant, "capacity", &format!("event-{n:04}"), vec![])?,
                Timepoint::try_from(456_i64)?,
            )?)
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    let total_bytes = first.canonical_bytes().len() as u64
        + rows
            .iter()
            .map(|p| p.canonical_bytes().len() as u64)
            .sum::<u64>();
    let mut tx = pool.begin().await?;
    sqlx::query(
        "SELECT set_config('rss.tenant_id',$1,true),set_config('statement_timeout','5000',true)",
    )
    .bind(tenant.to_string())
    .execute(&mut *tx)
    .await?;
    pg.append_batch_in_transaction(&mut tx, pg.try_admit(&rows)?, control)
        .await?;
    tx.commit().await?;
    Ok((tenant, total_bytes))
}

async fn interrupted_read(
    pg: &PgAudit,
    admin: &PgPool,
    tenant: TenantId,
    abort: bool,
) -> anyhow::Result<()> {
    let mut blocker = admin.begin().await?;
    sqlx::query("LOCK TABLE rss_audit.records IN ACCESS EXCLUSIVE MODE")
        .execute(&mut *blocker)
        .await?;
    let cancel = CancellationToken::new();
    let store = pg.clone();
    let token = cancel.clone();
    let task = tokio::spawn(async move {
        let clock = TestClock;
        let deadline = Deadline::from_timeout(&clock, Duration::from_secs(15))?;
        let control = Control::new(&clock, deadline, deadline, &token);
        let attempt = store
            .read_page(Cursor::start(tenant), ReadLimit::new(1, 131072)?, &control)
            .await;
        Ok::<_, anyhow::Error>(attempt)
    });
    let pid = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let pid: Option<i32> = sqlx::query_scalar("SELECT pid FROM pg_stat_activity WHERE usename='audit_runtime' AND wait_event_type='Lock' ORDER BY query_start DESC LIMIT 1").fetch_optional(admin).await?;
            if let Some(pid) = pid { return Ok::<_, sqlx::Error>(pid); }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }).await??;
    if abort {
        task.abort();
        assert!(task.await.is_err_and(|err| err.is_cancelled()));
    } else {
        cancel.cancel();
        assert!(task.await??.fold(
            |_| false,
            |_| false,
            |_| false,
            |_| true,
            |_| false,
            |_| false
        ));
    }
    blocker.rollback().await?;
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let live: bool =
                sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1)")
                    .bind(pid)
                    .fetch_one(admin)
                    .await?;
            if !live {
                return Ok::<_, sqlx::Error>(());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await??;
    Ok(())
}
