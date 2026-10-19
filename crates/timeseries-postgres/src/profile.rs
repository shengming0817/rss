use rss_timeseries::Error;
use sqlx::PgPool;

/// Explicit installation and runtime contract; feature selection never changes defaults.
#[derive(Clone)]
pub enum StorageProfile {
    PostgreSQL,
    #[cfg(feature = "timescaledb")]
    TimescaleSharedRls(crate::timescale::Hypertable),
    #[cfg(feature = "timescaledb")]
    TimescaleDedicatedTenant(crate::timescale::DedicatedTenant),
}
impl StorageProfile {
    /// Owner-executed, fresh-only installation. Construction never runs this SQL.
    pub fn installation_sql(&self) -> Result<String, Error> {
        let mut sql = String::from(crate::TABLES_SQL);
        sql.push_str(crate::SAMPLES_SQL);
        match self {
            Self::PostgreSQL => sql.push_str(" PARTITION BY RANGE (observed_at);\n"),
            #[cfg(feature = "timescaledb")]
            _ => sql.push_str(";\n"),
        }
        sql.push_str(crate::FUNCTIONS_SQL);
        match self {
            Self::PostgreSQL => sql.push_str(crate::PARTITIONS_SQL),
            #[cfg(feature = "timescaledb")]
            Self::TimescaleSharedRls(config) => {
                sql.push_str(&crate::timescale::install::shared(config)?);
            }
            #[cfg(feature = "timescaledb")]
            Self::TimescaleDedicatedTenant(config) => {
                sql.push_str(&crate::timescale::install::dedicated(config)?);
            }
        }
        sql.push_str("REVOKE ALL ON ALL FUNCTIONS IN SCHEMA rss_timeseries FROM PUBLIC;\nREVOKE ALL ON ALL TABLES IN SCHEMA rss_timeseries FROM PUBLIC;\n");
        Ok(sql)
    }
    pub(crate) async fn validate(
        &self,
        pool: &PgPool,
        maintenance: Option<&PgPool>,
    ) -> Result<String, Error> {
        match self {
            Self::PostgreSQL => {
                if maintenance.is_some() {
                    return Err(Error::InvalidInput);
                }
                crate::probe::validate(pool).await
            }
            #[cfg(feature = "timescaledb")]
            _ => crate::timescale::probe::validate(pool, self, maintenance).await,
        }
    }

    pub(crate) fn check_tenant(&self, tenant: rss_request_context::TenantId) -> Result<(), Error> {
        #[cfg(feature = "timescaledb")]
        if let Self::TimescaleDedicatedTenant(config) = self
            && config.tenant != tenant
        {
            return Err(Error::Unauthorized);
        }
        // reason: shared installations authorize tenants per request, without a fixed tenant.
        let _ = tenant;
        Ok(())
    }
}

/// Adopted connection owners. Native operations require a separate, explicitly
/// privileged pool; a runtime pool alone cannot construct the dedicated profile.
pub enum StoreConnections {
    Runtime(PgPool),
    #[cfg(feature = "timescaledb")]
    Native {
        runtime: PgPool,
        maintenance: PgPool,
    },
}
impl StoreConnections {
    pub(crate) fn into_pools(self) -> (PgPool, Option<PgPool>) {
        match self {
            Self::Runtime(pool) => (pool, None),
            #[cfg(feature = "timescaledb")]
            Self::Native {
                runtime,
                maintenance,
            } => (runtime, Some(maintenance)),
        }
    }
}
