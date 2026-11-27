use super::*;
use rss_audit_postgres::{AdmissionViolation, validate_structure};

const CUSTOM_SETTINGS: &str =
    "SET LOCAL search_path=rss_audit,pg_temp,pg_catalog; SET LOCAL quote_all_identifiers=on";

async fn settings(c: &mut sqlx::PgConnection) -> anyhow::Result<(String, String)> {
    Ok(sqlx::query_as("SELECT pg_catalog.current_setting('search_path'),pg_catalog.current_setting('quote_all_identifiers')")
        .fetch_one(c).await?)
}

pub(super) async fn run(admin: &PgPool) -> anyhow::Result<()> {
    let mut snapshot = admin.begin().await?;
    sqlx::raw_sql(
        "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY; SET LOCAL ROLE audit_owner",
    )
    .execute(&mut *snapshot)
    .await?;
    sqlx::raw_sql(CUSTOM_SETTINGS)
        .execute(&mut *snapshot)
        .await?;
    let original = settings(&mut snapshot).await?;
    validate_structure(&mut snapshot).await?;
    assert_eq!(settings(&mut snapshot).await?, original);
    snapshot.rollback().await?;

    // A raw BEGIN is invisible to SQLx's transaction-depth counter. Preserve its
    // settings and uncommitted work even when the component rejects drift.
    let mut raw = admin.acquire().await?;
    sqlx::raw_sql(
        "BEGIN; ALTER TABLE rss_audit.records RENAME CONSTRAINT records_pkey TO renamed_pkey",
    )
    .execute(&mut *raw)
    .await?;
    sqlx::raw_sql(CUSTOM_SETTINGS).execute(&mut *raw).await?;
    let original = settings(&mut raw).await?;
    assert!(matches!(
        validate_structure(&mut raw).await,
        Err(Error::Admission(AdmissionViolation::Shape))
    ));
    assert_eq!(settings(&mut raw).await?, original);
    sqlx::raw_sql("ALTER TABLE rss_audit.records RENAME CONSTRAINT renamed_pkey TO records_pkey")
        .execute(&mut *raw)
        .await?;
    validate_structure(&mut raw).await?;
    assert_eq!(settings(&mut raw).await?, original);
    sqlx::raw_sql("ROLLBACK").execute(&mut *raw).await?;
    drop(raw);

    for change in [
        "DROP INDEX rss_audit.records_tenant_ledger_sequence_uidx",
        "ALTER TABLE rss_audit.records DROP CONSTRAINT records_recorded_at_check",
    ] {
        let mut tx = admin.begin().await?;
        sqlx::raw_sql(change).execute(&mut *tx).await?;
        assert!(
            matches!(
                validate_structure(&mut tx).await,
                Err(Error::Admission(AdmissionViolation::Shape))
            ),
            "{change}"
        );
        tx.rollback().await?;
    }

    // Keep the function properties and body identical when testing output drift,
    // and keep the signature identical when testing implementation drift.
    for (original, replacement, recreate) in [
        (
            "RETURNS TABLE(source_id text",
            "RETURNS TABLE(source_alias text",
            true,
        ),
        ("audit tenant mismatch", "changed fixture message", false),
    ] {
        let mut tx = admin.begin().await?;
        sqlx::raw_sql("SET LOCAL ROLE audit_owner")
            .execute(&mut *tx)
            .await?;
        let definition: String = sqlx::query_scalar(
            "SELECT pg_get_functiondef('rss_audit.append_batch(uuid,text[],text[],bigint[],bytea[],bigint[])'::regprocedure)"
        ).fetch_one(&mut *tx).await?;
        assert!(definition.contains(original));
        if recreate {
            sqlx::raw_sql("DROP FUNCTION rss_audit.append_batch(uuid,text[],text[],bigint[],bytea[],bigint[])")
                .execute(&mut *tx).await?;
        }
        sqlx::raw_sql(sqlx::AssertSqlSafe(definition.replacen(
            original,
            replacement,
            1,
        )))
        .execute(&mut *tx)
        .await?;
        if recreate {
            sqlx::raw_sql("REVOKE ALL ON ALL FUNCTIONS IN SCHEMA rss_audit FROM PUBLIC; GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA rss_audit TO audit_runtime")
                .execute(&mut *tx).await?;
        }
        assert!(
            matches!(
                validate_structure(&mut tx).await,
                Err(Error::Admission(AdmissionViolation::Functions))
            ),
            "{original}"
        );
        tx.rollback().await?;
    }
    Ok(())
}
