use super::*;
use rss_audit_postgres::PgAuditReader;

pub(super) async fn run(
    writer: &PgAudit,
    pool: &PgPool,
    admin: &PgPool,
    control: &Control<'_, TestClock>,
) -> anyhow::Result<()> {
    assert!(
        PgAuditReader::new(pool.clone(), Integrity::Ledger(auth()?), control)
            .await
            .is_err()
    );
    let prepared = writer
        .prepare(event(tenant()?, "reader", "source", vec![42])?, control)
        .await?;
    committed(writer.append(&prepared, control).await)?;
    sqlx::raw_sql("REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA rss_audit FROM audit_runtime")
        .execute(admin)
        .await?;
    assert!(
        PgAuditReader::new(pool.clone(), Integrity::Plain, control)
            .await
            .is_err(),
        "Plain reader must reject direct Ledger append authority"
    );
    sqlx::raw_sql("REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA rss_ledger FROM audit_runtime")
        .execute(admin)
        .await?;
    PgAuditReader::new(pool.clone(), Integrity::Plain, control).await?;
    assert!(
        PgAudit::new(
            pool.clone(),
            Integrity::Ledger(auth()?),
            write_budget()?,
            control
        )
        .await
        .is_err()
    );
    let reader = PgAuditReader::new(pool.clone(), Integrity::Ledger(auth()?), control).await?;
    read_and_reject_write(&reader, control).await?;
    write_authority(pool, admin, control).await?;
    Ok(())
}

async fn read_and_reject_write(
    reader: &PgAuditReader,
    control: &Control<'_, TestClock>,
) -> anyhow::Result<()> {
    let page = committed(
        reader
            .read_page(
                Cursor::start(tenant()?),
                ReadLimit::new(1, 131072)?,
                control,
            )
            .await,
    )?;
    assert!(!page.records().is_empty());
    let verified = committed(
        reader
            .read_verified(
                tenant()?,
                rss_ledger::Sequence::new(0),
                rss_ledger_postgres::ReadLimit::new(1, 1_048_576)?,
                control,
            )
            .await,
    )?;
    assert!(verified.ledger_verification().count() > 0);
    let tenant_id = tenant()?.to_string();
    let attempt = reader
        .read_tx_with_context(tenant()?, control, (), move |_, tx| {
            Box::pin(async move {
                tx.with_connection(move |c| {
                    Box::pin(async move {
                        sqlx::query("SELECT * FROM rss_audit.append_batch($1::uuid,ARRAY[]::text[],ARRAY[]::text[],ARRAY[]::bigint[],ARRAY[]::bytea[],ARRAY[]::bigint[])")
                            .bind(tenant_id)
                            .execute(c)
                            .await?;
                        Ok::<_, sqlx::Error>(())
                    })
                })
                .await
            })
        })
        .await;
    assert!(attempt.fold(
        |_| false,
        |_| false,
        |_| true,
        |_| false,
        |_| false,
        |_| false
    ));
    Ok(())
}

async fn write_authority(
    pool: &PgPool,
    admin: &PgPool,
    control: &Control<'_, TestClock>,
) -> anyhow::Result<()> {
    plain_ledger_privileges(pool, admin, control).await?;
    sqlx::raw_sql("CREATE ROLE audit_reader_indirect NOLOGIN; GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA rss_ledger TO audit_reader_indirect; GRANT audit_reader_indirect TO audit_runtime WITH INHERIT FALSE,SET TRUE").execute(admin).await?;
    assert!(
        PgAuditReader::new(pool.clone(), Integrity::Plain, control)
            .await
            .is_err(),
        "Plain reader must reject SET-role Ledger append authority"
    );
    sqlx::raw_sql("REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA rss_ledger FROM audit_reader_indirect; GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA rss_audit TO audit_reader_indirect").execute(admin).await?;
    assert!(
        PgAuditReader::new(pool.clone(), Integrity::Ledger(auth()?), control)
            .await
            .is_err()
    );
    sqlx::raw_sql("REVOKE audit_reader_indirect FROM audit_runtime; REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA rss_audit FROM audit_reader_indirect; GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA rss_audit,rss_ledger TO audit_runtime").execute(admin).await?;
    PgAudit::new(
        pool.clone(),
        Integrity::Ledger(auth()?),
        write_budget()?,
        control,
    )
    .await?;
    Ok(())
}

async fn plain_ledger_privileges(
    pool: &PgPool,
    admin: &PgPool,
    control: &Control<'_, TestClock>,
) -> anyhow::Result<()> {
    sqlx::raw_sql("REVOKE SELECT ON ALL TABLES IN SCHEMA rss_ledger FROM audit_runtime; CREATE ROLE audit_reader_table_indirect NOLOGIN; GRANT audit_reader_table_indirect TO audit_runtime WITH INHERIT FALSE,SET TRUE").execute(admin).await?;
    // Plain has no Ledger read requirement, even when the optional schema exists.
    PgAuditReader::new(pool.clone(), Integrity::Plain, control).await?;
    for (grant, revoke) in [
        (
            "GRANT UPDATE ON rss_ledger.entries TO audit_runtime",
            "REVOKE UPDATE ON rss_ledger.entries FROM audit_runtime",
        ),
        (
            "GRANT UPDATE(payload) ON rss_ledger.entries TO audit_runtime",
            "REVOKE UPDATE(payload) ON rss_ledger.entries FROM audit_runtime",
        ),
        (
            "GRANT TRUNCATE ON rss_ledger.entries TO audit_runtime",
            "REVOKE TRUNCATE ON rss_ledger.entries FROM audit_runtime",
        ),
        (
            "GRANT CREATE ON SCHEMA rss_ledger TO audit_runtime",
            "REVOKE CREATE ON SCHEMA rss_ledger FROM audit_runtime",
        ),
        (
            "GRANT UPDATE(payload) ON rss_ledger.entries TO audit_reader_table_indirect",
            "REVOKE UPDATE(payload) ON rss_ledger.entries FROM audit_reader_table_indirect",
        ),
        (
            "GRANT TRUNCATE ON rss_ledger.entries TO audit_reader_table_indirect",
            "REVOKE TRUNCATE ON rss_ledger.entries FROM audit_reader_table_indirect",
        ),
    ] {
        sqlx::raw_sql(grant).execute(admin).await?;
        assert!(
            PgAuditReader::new(pool.clone(), Integrity::Plain, control)
                .await
                .is_err(),
            "Plain reader accepted sink write permission"
        );
        sqlx::raw_sql(revoke).execute(admin).await?;
        PgAuditReader::new(pool.clone(), Integrity::Plain, control).await?;
    }
    sqlx::raw_sql("REVOKE audit_reader_table_indirect FROM audit_runtime; GRANT SELECT ON ALL TABLES IN SCHEMA rss_ledger TO audit_runtime").execute(admin).await?;
    Ok(())
}
