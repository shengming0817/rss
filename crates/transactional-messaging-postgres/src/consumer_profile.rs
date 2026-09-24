//! Version-matched consumer grants; the host owns role creation and migration execution.
use crate::PgError;

/// Grant the component's relay and Inbox permissions, never producer function access.
/// Call inside the host's installation transaction after installing `MIGRATION_SQL`.
/// Existing excess privileges are not silently revoked: `connect_consumer` rejects them.
pub async fn grant_consumer(
    connection: &mut sqlx::PgConnection,
    role: &str,
) -> Result<(), PgError> {
    if role.is_empty() || role.len() > 63 || role.contains('\0') {
        return Err(sqlx::Error::Protocol("invalid consumer role".into()).into());
    }
    let role = format!("\"{}\"", role.replace('"', "\"\""));
    let sql = include_str!("grants-consumer.sql").replace("{role}", &role);
    sqlx::raw_sql(sqlx::AssertSqlSafe(sql))
        .execute(connection)
        .await?;
    Ok(())
}
