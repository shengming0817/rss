use rss_observation::{Error, ErrorKind};
use sqlx::PgConnection;
// PostgreSQL 16 canonical columns/constraints/indexes/policies/functions. A change requires a
// new component storage revision and a matching fresh-install proof, never a bypass.
const CATALOG: &str = "6fb3c38e54618e889d9f1e0298d26a2e";
pub(crate) async fn validate(
    connection: &mut PgConnection,
    maintenance: bool,
) -> Result<(), Error> {
    let valid: Option<bool> = sqlx::query_scalar(include_str!("probe.sql"))
        .bind(maintenance)
        .fetch_one(&mut *connection)
        .await
        .map_err(super::transaction::sql_error)?;
    let catalog: Option<String> = sqlx::query_scalar(include_str!("catalog.sql"))
        .fetch_one(connection)
        .await
        .map_err(super::transaction::sql_error)?;
    if valid != Some(true) || catalog.as_deref() != Some(CATALOG) {
        return Err(ErrorKind::Invariant.into());
    }
    Ok(())
}
