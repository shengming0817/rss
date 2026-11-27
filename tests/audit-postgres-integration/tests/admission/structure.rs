use super::*;
use rss_audit_postgres::{AdmissionViolation, validate_structure};

pub(super) async fn run(admin: &PgPool) -> anyhow::Result<()> {
    let mut snapshot = admin.begin().await?;
    sqlx::raw_sql(
        "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY; SET LOCAL ROLE audit_owner",
    )
    .execute(&mut *snapshot)
    .await?;
    validate_structure(&mut snapshot).await?;
    snapshot.rollback().await?;

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
