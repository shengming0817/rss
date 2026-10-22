//! Version-matched consumer grants; the host owns role creation and migration execution.
use crate::PgError;

pub(crate) async fn verify_scope(
    runtime: &crate::PgRuntime,
    cutoff: rss_request_context::Deadline,
) -> Result<(), PgError> {
    let bodies: Vec<_> = include_str!("../migrations/0012_scope_local_projection.sql")
        .split("$f$")
        .collect();
    let valid = rss_transactional_messaging::policy::within(&runtime.timer, cutoff, |_| async {
        sqlx::query_scalar::<_, bool>(include_str!("consumer_scope_probe.sql"))
            .bind(bodies[1])
            .bind(bodies[3])
            .bind(bodies[5])
            .bind(bodies[7])
            .fetch_one(&runtime.pool)
            .await
    })
    .await??;
    if !valid {
        return Err(PgError::IncompatibleStorageContract(
            crate::PgStorageContractFailure::Functions,
        ));
    }
    Ok(())
}

/// Bind a dedicated LOGIN to exactly one source domain and consumer group, then grant the
/// standard consumer operations. The binding follows session_user even through SET ROLE.
/// Invoke in the external migrator's transaction; an existing different binding is rejected.
pub async fn grant_local_projection(
    connection: &mut sqlx::PgConnection,
    role: &str,
    domain: &rss_transactional_messaging::message::MessagingDomain,
    group: &rss_transactional_messaging::inbox::ConsumerGroup,
) -> Result<(), PgError> {
    let login: bool = sqlx::query_scalar("SELECT coalesce((SELECT rolcanlogin AND NOT rolsuper AND NOT rolbypassrls AND NOT rolcreaterole FROM pg_roles WHERE rolname=$1),false)")
        .bind(role).fetch_one(&mut *connection).await?;
    if !login {
        return Err(PgError::invariant());
    }
    sqlx::query("INSERT INTO rss_transactional_messaging.consumer_scope(login_role,domain,consumer_group) VALUES($1,$2,$3) ON CONFLICT DO NOTHING")
        .bind(role).bind(domain.as_str()).bind(group.as_str()).execute(&mut *connection).await?;
    let matches: bool = sqlx::query_scalar("SELECT domain=$2 AND consumer_group=$3 FROM rss_transactional_messaging.consumer_scope WHERE login_role=$1")
        .bind(role).bind(domain.as_str()).bind(group.as_str()).fetch_one(&mut *connection).await?;
    if !matches {
        return Err(PgError::invariant());
    }
    grant_consumer(connection, role).await
}

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
