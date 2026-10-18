use super::EXTENSION_VERSION;
use crate::{StorageProfile, transaction::sql_error};
use rss_timeseries::Error;
use sqlx::{Connection, PgConnection, PgPool, Row};

// Fixed PostgreSQL 16 common schema fingerprint, populated from the canonical T2 catalog.
const COMMON_CATALOG: &str = "0cc0899f0d0209220075419d9b13dcf8";
pub(crate) async fn validate(
    pool: &PgPool,
    profile: &StorageProfile,
    maintenance: Option<&PgPool>,
) -> Result<String, Error> {
    let (kind, tenant, chunk, resolutions) = match profile {
        StorageProfile::TimescaleSharedRls(c) => ("shared", None, c.chunk_micros, Vec::new()),
        StorageProfile::TimescaleDedicatedTenant(c) => (
            "dedicated",
            Some(c.tenant.to_string()),
            c.hypertable.chunk_micros,
            c.resolutions.clone(),
        ),
        StorageProfile::PostgreSQL => return Err(Error::Invariant),
    };
    if (kind == "dedicated") != maintenance.is_some() {
        return Err(Error::InvalidInput);
    }
    let mut lease = pool.acquire().await.map_err(sql_error)?;
    lease.close_on_drop();
    let mut tx = lease.begin().await.map_err(sql_error)?;
    let version:Option<String>=sqlx::query_scalar("SELECT extversion FROM pg_extension e JOIN pg_namespace n ON n.oid=e.extnamespace WHERE extname='timescaledb' AND n.nspname='public'").fetch_optional(&mut *tx).await.map_err(sql_error)?;
    if version.as_deref() != Some(EXTENSION_VERSION) {
        return Err(Error::Unsupported);
    }
    let row=sqlx::query("SELECT profile,tenant::text,chunk_micros,resolutions FROM rss_timeseries.deployment WHERE singleton").fetch_one(&mut *tx).await.map_err(sql_error)?;
    if row.try_get::<String, _>("profile").map_err(sql_error)? != kind
        || row
            .try_get::<Option<String>, _>("tenant")
            .map_err(sql_error)?
            != tenant
        || row.try_get::<i64, _>("chunk_micros").map_err(sql_error)? != chunk
        || row
            .try_get::<Vec<i64>, _>("resolutions")
            .map_err(sql_error)?
            != resolutions
    {
        return Err(Error::Invariant);
    }
    validate_catalog(&mut tx, kind == "dedicated", chunk, &resolutions).await?;
    validate_views(&mut tx, &resolutions).await?;
    if let Some(tenant) = &tenant {
        let valid:bool=sqlx::query_scalar("SELECT count(*)=11 AND bool_and(pg_get_constraintdef(c.oid,true)=format('CHECK (tenant_id = %L::uuid)',$1::text)) FROM pg_constraint c JOIN pg_class r ON r.oid=c.conrelid JOIN pg_namespace n ON n.oid=r.relnamespace WHERE n.nspname='rss_timeseries' AND c.conname='installation_tenant'").bind(tenant).fetch_one(&mut *tx).await.map_err(sql_error)?;
        if !valid {
            return Err(Error::Invariant);
        }
    }
    let instance:String=sqlx::query_scalar("SELECT obj_description(oid,'pg_namespace') FROM pg_namespace WHERE nspname='rss_timeseries'").fetch_one(&mut *tx).await.map_err(sql_error)?;
    if !instance.starts_with("rss-timeseries-postgres:3:") || instance.len() != 62 {
        return Err(Error::Invariant);
    }
    tx.rollback().await.map_err(sql_error)?;
    if let Some(maintenance) = maintenance {
        let valid:bool=sqlx::query_scalar("SELECT current_user=r.rolname AND NOT r.rolsuper AND NOT r.rolbypassrls AND NOT r.rolcanlogin AND NOT r.rolcreaterole AND NOT r.rolreplication FROM pg_namespace n JOIN pg_roles r ON r.oid=n.nspowner WHERE n.nspname='rss_timeseries'").fetch_one(maintenance).await.map_err(sql_error)?;
        if !valid {
            return Err(Error::Unauthorized);
        }
        let other:String=sqlx::query_scalar("SELECT obj_description(oid,'pg_namespace') FROM pg_namespace WHERE nspname='rss_timeseries'").fetch_one(maintenance).await.map_err(sql_error)?;
        if other != instance {
            return Err(Error::Invariant);
        }
    }
    Ok(format!(
        "{instance}:{kind}:{}",
        tenant.as_deref().unwrap_or("shared")
    ))
}

async fn validate_catalog(
    c: &mut PgConnection,
    dedicated: bool,
    chunk: i64,
    resolutions: &[i64],
) -> Result<(), Error> {
    let valid: Option<bool> = sqlx::query_scalar(include_str!("probe.sql"))
        .bind(dedicated)
        .bind(chunk)
        .bind(resolutions)
        .fetch_one(&mut *c)
        .await
        .map_err(sql_error)?;
    let catalog: Option<String> = sqlx::query_scalar(include_str!("catalog.sql"))
        .fetch_one(&mut *c)
        .await
        .map_err(sql_error)?;
    let raw: Option<String> = sqlx::query_scalar(include_str!("samples_catalog.sql"))
        .fetch_one(&mut *c)
        .await
        .map_err(sql_error)?;
    let native: Option<String> = sqlx::query_scalar(include_str!("native_catalog.sql"))
        .fetch_one(&mut *c)
        .await
        .map_err(sql_error)?;
    let (raw_expected, native_expected) = if dedicated {
        (
            "af7f58837bd788a21f4c89d84c9f41cc",
            "ecce843e26996ec0d6c5addf51eee193",
        )
    } else {
        (
            "af0d8d79a9e299f0db78d5b5750dc207",
            "1e697b54909ca080b12e0a447e38ded9",
        )
    };
    if valid != Some(true)
        || catalog.as_deref() != Some(COMMON_CATALOG)
        || raw.as_deref() != Some(raw_expected)
        || native.as_deref() != Some(native_expected)
    {
        return Err(Error::Invariant);
    }
    Ok(())
}
async fn validate_views(c: &mut PgConnection, resolutions: &[i64]) -> Result<(), Error> {
    for resolution in resolutions {
        let definition:String=sqlx::query_scalar("SELECT view_definition FROM timescaledb_information.continuous_aggregates WHERE view_schema='rss_timeseries' AND view_name=$1").bind(format!("gauge_{resolution}")).fetch_one(&mut *c).await.map_err(sql_error)?;
        let expected = format!(
            "SELECT time_bucket(({resolution})::bigint, observed_at) AS bucket, tenant_id, namespace, source, generation, series_digest, gauge_kind, sum(gauge_value) AS total, count(gauge_value) AS valid, min(gauge_value) AS minimum, max(gauge_value) AS maximum, (count(*) - count(gauge_value)) AS defects FROM rss_timeseries.samples WHERE (aggregate_visible AND (gauge_kind = ANY (ARRAY['i64'::text, 'u64'::text]))) GROUP BY (time_bucket(({resolution})::bigint, observed_at)), tenant_id, namespace, source, generation, series_digest, gauge_kind;"
        );
        if definition
            .split_whitespace()
            .ne(expected.split_whitespace())
        {
            return Err(Error::Invariant);
        }
    }
    Ok(())
}
