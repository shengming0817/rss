use crate::transaction::sql_error;
use rss_timeseries::Error;
use sqlx::{Connection, PgPool};
// PostgreSQL 17 catalog projection; functions, columns, constraints, indexes and policies.
const CATALOG: &str = "52e4b3887022335814771d52dd6ba471";
pub(crate) async fn validate(pool: &PgPool) -> Result<String, Error> {
    let mut lease = pool.acquire().await.map_err(sql_error)?;
    // Admission cancellation must not return a possibly open transaction to the pool.
    lease.close_on_drop();
    let mut tx = lease.begin().await.map_err(sql_error)?;
    let valid: Option<bool> = sqlx::query_scalar(include_str!("probe.sql"))
        .fetch_one(&mut *tx)
        .await
        .map_err(sql_error)?;
    let catalog: Option<String> = sqlx::query_scalar(include_str!("catalog.sql"))
        .fetch_one(&mut *tx)
        .await
        .map_err(sql_error)?;
    if valid != Some(true) || catalog.as_deref() != Some(CATALOG) {
        return Err(Error::Invariant);
    }
    let instance:String=sqlx::query_scalar("SELECT obj_description(oid,'pg_namespace') FROM pg_namespace WHERE nspname='rss_timeseries'")
        .fetch_one(&mut *tx).await.map_err(sql_error)?;
    if !instance.starts_with("rss-timeseries-postgres:3:") || instance.len() != 62 {
        return Err(Error::Invariant);
    }
    tx.rollback().await.map_err(sql_error)?;
    Ok(instance)
}
