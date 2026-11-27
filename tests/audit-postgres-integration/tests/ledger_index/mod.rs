use super::*;
use rss_audit_postgres::{AdmissionViolation, PgAuditReader};

const INDEX: &str = "records_tenant_ledger_sequence_uidx";

pub(super) async fn run(
    plain: &PgAudit,
    ledger: &PgAudit,
    pool: &PgPool,
    admin: &PgPool,
    control: &Control<'_, TestClock>,
) -> anyhow::Result<()> {
    let a = TenantId::parse("ab000000-0000-4000-8000-000000000001")?;
    let b = TenantId::parse("ab000000-0000-4000-8000-000000000002")?;
    for id in ["plain-1", "plain-2"] {
        let request = plain
            .prepare(event(a, "index", id, vec![1])?, control)
            .await?;
        let append = committed(plain.append(&request, control).await)?;
        assert!(append.inserted());
        assert_eq!(append.record().ledger_sequence(), None);
    }
    for tenant in [a, b] {
        let request = ledger
            .prepare(event(tenant, "index", "ledger", vec![2])?, control)
            .await?;
        let append = committed(ledger.append(&request, control).await)?;
        assert!(append.inserted());
        assert_eq!(append.record().ledger_sequence(), Some(0));
    }

    duplicate_in_tenant(pool, a).await?;
    admission(pool, admin, control).await
}

async fn duplicate_in_tenant(pool: &PgPool, tenant: TenantId) -> anyhow::Result<()> {
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(tenant.to_string())
        .execute(&mut *tx)
        .await?;
    let visible: Vec<String> =
        sqlx::query_scalar("SELECT tenant_id::text FROM rss_audit.records WHERE ledger_sequence=0")
            .fetch_all(&mut *tx)
            .await?;
    assert_eq!(visible, [tenant.to_string()]);

    // append_batch allocates a fresh position. Only the tenant/sequence pair repeats.
    let result = sqlx::query(
        "SELECT * FROM rss_audit.append_batch($1::uuid, ARRAY['index'], ARRAY['new-event'], \
         ARRAY[1]::bigint[], ARRAY['x'::bytea], ARRAY[0]::bigint[])",
    )
    .bind(tenant.to_string())
    .execute(&mut *tx)
    .await;
    let error = result.err().context("duplicate ledger sequence accepted")?;
    let db = error
        .as_database_error()
        .context("expected a PostgreSQL error")?;
    assert_eq!(db.code().as_deref(), Some("23505"));
    assert_eq!(db.constraint(), Some(INDEX));
    tx.rollback().await?;
    Ok(())
}

async fn admission(
    pool: &PgPool,
    admin: &PgPool,
    control: &Control<'_, TestClock>,
) -> anyhow::Result<()> {
    let reader = reader_pool(pool, admin).await?;
    sqlx::raw_sql("CREATE OPERATOR CLASS public.fixture_int8_ops FOR TYPE bigint USING btree FAMILY pg_catalog.integer_ops AS STORAGE bigint")
        .execute(admin).await?;
    PgAuditReader::new(reader.clone(), Integrity::Plain, control).await?;
    for drift in [
        None,
        Some(
            "CREATE INDEX records_tenant_ledger_sequence_uidx ON rss_audit.records (tenant_id, ledger_sequence) WHERE ledger_sequence IS NOT NULL",
        ),
        Some(
            "CREATE UNIQUE INDEX records_tenant_ledger_sequence_uidx ON rss_audit.records (tenant_id, ledger_sequence) WHERE ledger_sequence > 0",
        ),
        Some(
            "CREATE UNIQUE INDEX records_tenant_ledger_sequence_uidx ON rss_audit.records (ledger_sequence, tenant_id) WHERE ledger_sequence IS NOT NULL",
        ),
        Some(
            "CREATE UNIQUE INDEX records_tenant_ledger_sequence_uidx ON rss_audit.records (tenant_id, ledger_sequence public.fixture_int8_ops) WHERE ledger_sequence IS NOT NULL",
        ),
        Some("ALTER TABLE rss_audit.records ADD UNIQUE (tenant_id, ledger_sequence)"),
    ] {
        sqlx::raw_sql("DROP INDEX rss_audit.records_tenant_ledger_sequence_uidx")
            .execute(admin)
            .await?;
        if let Some(ddl) = drift {
            sqlx::raw_sql(ddl).execute(admin).await?;
        }
        reject_drift(pool, &reader, control, drift).await?;
        sqlx::raw_sql("ALTER TABLE rss_audit.records DROP CONSTRAINT IF EXISTS records_tenant_id_ledger_sequence_key;
            DROP INDEX IF EXISTS rss_audit.records_tenant_ledger_sequence_uidx;
            CREATE UNIQUE INDEX records_tenant_ledger_sequence_uidx ON rss_audit.records (tenant_id, ledger_sequence) WHERE ledger_sequence IS NOT NULL")
            .execute(admin)
            .await?;
        PgAudit::new(pool.clone(), Integrity::Plain, write_budget()?, control).await?;
        PgAuditReader::new(reader.clone(), Integrity::Plain, control).await?;
    }
    Ok(())
}

async fn reader_pool(pool: &PgPool, admin: &PgPool) -> anyhow::Result<PgPool> {
    sqlx::raw_sql(
        "CREATE ROLE audit_index_reader LOGIN PASSWORD 'fixture-password';
        GRANT USAGE ON SCHEMA rss_audit TO audit_index_reader;
        GRANT SELECT ON rss_audit.records TO audit_index_reader",
    )
    .execute(admin)
    .await?;
    Ok(PgPoolOptions::new()
        .max_connections(1)
        .connect_with(
            pool.connect_options()
                .as_ref()
                .clone()
                .username("audit_index_reader")
                .password("fixture-password"),
        )
        .await?)
}

async fn reject_drift(
    writer: &PgPool,
    reader: &PgPool,
    control: &Control<'_, TestClock>,
    drift: Option<&str>,
) -> anyhow::Result<()> {
    let write = PgAudit::new(writer.clone(), Integrity::Plain, write_budget()?, control)
        .await
        .err();
    let read = PgAuditReader::new(reader.clone(), Integrity::Plain, control)
        .await
        .err();
    for (role, result) in [("writer", write), ("reader", read)] {
        assert!(
            matches!(result, Some(Error::Admission(AdmissionViolation::Shape))),
            "{role} returned {result:?} for index drift {drift:?}"
        );
    }
    Ok(())
}
