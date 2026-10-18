use crate::transaction::sql_error;
use rss_timeseries::Error;
use sqlx::{Connection, PgPool};
// PostgreSQL 16 catalog projection; functions, columns, constraints, indexes and policies.
const CATALOG: &str = "630dd3daf264f31f39e39bc1772a0662";
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
    if !instance.starts_with("rss-timeseries-postgres:1:") || instance.len() != 62 {
        return Err(Error::Invariant);
    }
    tx.rollback().await.map_err(sql_error)?;
    Ok(instance)
}
