//! Verify complete RLS/guard definitions rather than trusting schema comments.
use crate::transaction::sql_error;
use rss_timeseries::Error;
use sqlx::PgPool;
// PostgreSQL 16 canonical columns/constraints/indexes/RLS/view contract.
const CATALOG: &str = "6f61d8279baa41d508c8e6af9975d9b0";
pub(crate) async fn validate(pool: &PgPool) -> Result<(), Error> {
    let catalog: Option<String> = sqlx::query_scalar(include_str!("catalog.sql"))
        .fetch_one(pool)
        .await
        .map_err(sql_error)?;
    if catalog.as_deref() != Some(CATALOG) {
        #[cfg(feature = "integration")]
        eprintln!("control catalog fingerprint: {:?}", catalog);
        return Err(Error::Invariant);
    }
    let owner:bool=sqlx::query_scalar("SELECT bool_and(c.relowner=n.nspowner) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='rss_ts_ch' AND c.relkind IN ('r','p','v')").fetch_one(pool).await.map_err(sql_error)?;
    if !owner {
        return Err(Error::Unauthorized);
    }
    let guard:Option<bool>=sqlx::query_scalar("SELECT r.rolcanlogin AND NOT r.rolsuper AND NOT r.rolbypassrls AND NOT r.rolcreaterole AND NOT r.rolcreatedb AND NOT r.rolreplication AND NOT EXISTS(SELECT FROM pg_auth_members WHERE member=r.oid) AND has_schema_privilege(r.oid,'rss_ts_ch','USAGE') AND NOT has_schema_privilege(r.oid,'rss_ts_ch','CREATE') AND NOT EXISTS(SELECT FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname NOT IN ('pg_catalog','information_schema') AND n.nspname NOT LIKE 'pg_toast%' AND c.relkind IN ('r','p','v','m','f') AND (has_table_privilege(r.oid,c.oid,'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') OR has_any_column_privilege(r.oid,c.oid,'INSERT,UPDATE,REFERENCES') OR has_any_column_privilege(r.oid,c.oid,'SELECT')<>(n.nspname='rss_ts_ch' AND c.relname IN ('active_attempts','guard_identity')))) FROM pg_roles r WHERE r.rolname='ch_guard'")
        .fetch_optional(pool).await.map_err(sql_error)?;
    if guard != Some(true) {
        return Err(Error::Unauthorized);
    }
    Ok(())
}
