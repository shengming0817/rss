use super::*;
mod budget;
pub(super) async fn run(
    pool: &PgPool,
    admin: &PgPool,
    control: &Control<'_, TestClock>,
) -> anyhow::Result<()> {
    budget::run(pool).await?;
    foreign_role(pool, admin, control).await?;
    borrowed(pool, admin, control).await?;
    sqlx::raw_sql("CREATE ROLE unrelated_audit_reader NOLOGIN; GRANT SELECT ON rss_audit.records TO unrelated_audit_reader").execute(admin).await?;
    // Grants to an unreachable role are permitted; no ACL grantee whitelist is implied.
    PgAudit::new(pool.clone(), Integrity::Plain, write_budget()?, control).await?;
    assert!(
        PgAudit::new(admin.clone(), Integrity::Plain, write_budget()?, control)
            .await
            .is_err()
    );
    for (change, restore) in [
        (
            "GRANT UPDATE ON rss_audit.records TO audit_runtime",
            "REVOKE UPDATE ON rss_audit.records FROM audit_runtime",
        ),
        (
            "GRANT SELECT ON rss_audit.records TO PUBLIC",
            "REVOKE SELECT ON rss_audit.records FROM PUBLIC",
        ),
        (
            "GRANT SELECT(canonical) ON rss_audit.records TO PUBLIC",
            "REVOKE SELECT(canonical) ON rss_audit.records FROM PUBLIC",
        ),
        (
            "GRANT USAGE ON SCHEMA rss_audit TO audit_runtime WITH GRANT OPTION",
            "REVOKE GRANT OPTION FOR USAGE ON SCHEMA rss_audit FROM audit_runtime",
        ),
        (
            "ALTER TABLE rss_audit.records NO FORCE ROW LEVEL SECURITY",
            "ALTER TABLE rss_audit.records FORCE ROW LEVEL SECURITY",
        ),
        (
            "ALTER POLICY tenant_scope ON rss_audit.records USING (true)",
            "ALTER POLICY tenant_scope ON rss_audit.records USING (tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid)",
        ),
        (
            "ALTER FUNCTION rss_audit.append_batch(uuid,text[],text[],bigint[],bytea[],bigint[]) SET search_path=public",
            "ALTER FUNCTION rss_audit.append_batch(uuid,text[],text[],bigint[],bytea[],bigint[]) SET search_path=pg_catalog,rss_audit",
        ),
        (
            "ALTER TABLE rss_audit.records ADD COLUMN extra integer DEFAULT 1",
            "ALTER TABLE rss_audit.records DROP COLUMN extra",
        ),
    ] {
        sqlx::raw_sql(change).execute(admin).await?;
        assert!(
            PgAudit::new(pool.clone(), Integrity::Plain, write_budget()?, control)
                .await
                .is_err(),
            "accepted drift: {change}"
        );
        sqlx::raw_sql(restore).execute(admin).await?;
        // Dropped columns remain physical drift: the fresh schema contract intentionally rejects them.
        if !change.contains("ADD COLUMN") {
            PgAudit::new(pool.clone(), Integrity::Plain, write_budget()?, control).await?;
        }
    }
    Ok(())
}

async fn borrowed(
    pool: &PgPool,
    admin: &PgPool,
    control: &Control<'_, TestClock>,
) -> anyhow::Result<()> {
    let ledger = PgAudit::new(
        pool.clone(),
        Integrity::Ledger(auth()?),
        write_budget()?,
        control,
    )
    .await?;
    let mut actual = pool.acquire().await?;
    sqlx::raw_sql("GRANT UPDATE ON rss_ledger.entries TO audit_runtime")
        .execute(admin)
        .await?;
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
    assert!(matches!(
        ledger.validate_connection(&mut actual, control).await,
        Err(Error::Ledger(rss_ledger_postgres::Error::Admission(_)))
    ));
    // Plain Audit does not require Ledger privileges or installation.
    PgAudit::new(pool.clone(), Integrity::Plain, write_budget()?, control).await?;
    sqlx::raw_sql("REVOKE UPDATE ON rss_ledger.entries FROM audit_runtime")
        .execute(admin)
        .await?;
    PgAudit::new(
        pool.clone(),
        Integrity::Ledger(auth()?),
        write_budget()?,
        control,
    )
    .await?;
    ledger.validate_connection(&mut actual, control).await?;
    drop(actual);
    Ok(())
}

async fn foreign_role(
    pool: &PgPool,
    admin: &PgPool,
    control: &Control<'_, TestClock>,
) -> anyhow::Result<()> {
    let plain = PgAudit::new(pool.clone(), Integrity::Plain, write_budget()?, control).await?;
    let mut foreign = admin.acquire().await?;
    assert!(matches!(
        plain.validate_connection(&mut foreign, control).await,
        Err(Error::Admission(_))
    ));
    let mut actual = pool.acquire().await?;
    plain.validate_connection(&mut actual, control).await?;
    Ok(())
}
