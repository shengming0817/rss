use crate::{AdmissionViolation, Control, Error, MIGRATION_SQL, Timer, error::sql_error};
use sqlx::{PgConnection, PgPool, Row};
pub(crate) async fn validate(pool: &PgPool) -> Result<(), Error> {
    let mut connection = pool.acquire().await.map_err(sql_error)?;
    inspect(&mut connection).await
}
/// Validate the actual runtime role and Ledger schema at installation or startup.
///
/// Uses the host's connection and absolute budget; does not acquire another connection,
/// change settings, repair the schema or settle a transaction. Validate every distinct
/// runtime credential before accepting work. An unrelated pool's validation is insufficient.
/// The host must bound server statements and retire the connection if cancellation leaves
/// execution or settlement unconfirmed. Controlled schema/role changes require draining
/// writers and validating again before resuming; live administrator drift is not polled.
pub async fn validate_connection<T: Timer>(
    connection: &mut PgConnection,
    control: &Control<'_, T>,
) -> Result<(), Error> {
    control.run(inspect(connection)).await
}

pub(crate) async fn inspect(connection: &mut PgConnection) -> Result<(), Error> {
    let violation: Option<String> = sqlx::query_scalar(include_str!("probe.sql"))
        .fetch_optional(&mut *connection)
        .await
        .map_err(sql_error)?;
    if let Some(reason) = violation {
        let kind = match reason.as_str() {
            "role" => AdmissionViolation::Role,
            "permissions" => AdmissionViolation::Permissions,
            "rls" => AdmissionViolation::Rls,
            "functions" => AdmissionViolation::Functions,
            "columns" => AdmissionViolation::Columns,
            "constraints" => AdmissionViolation::Constraints,
            _ => AdmissionViolation::Schema,
        };
        return Err(Error::Admission(kind));
    }
    // Function source identity is derived from the shipped migration, never a second copy.
    let expected: Vec<&str> = MIGRATION_SQL
        .split(" AS $$")
        .skip(1)
        .filter_map(|s| s.split("$$;").next())
        .collect();
    let rows=sqlx::query("SELECT prosrc FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='rss_ledger' ORDER BY proname")
        .fetch_all(&mut *connection).await.map_err(sql_error)?;
    if rows.len() != expected.len() {
        return Err(Error::Admission(AdmissionViolation::Functions));
    }
    for row in rows {
        let source: String = row.try_get("prosrc").map_err(sql_error)?;
        if !expected.contains(&source.as_str()) {
            return Err(Error::Admission(AdmissionViolation::Functions));
        }
    }
    Ok(())
}
