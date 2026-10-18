use rss_timeseries::Error;
use sqlx::PgPool;

/// Explicit installation and runtime contract; feature selection never changes defaults.
#[derive(Clone, Debug)]
pub enum StorageProfile {
    PostgreSQL,
}
impl StorageProfile {
    pub(crate) async fn validate(&self, pool: &PgPool) -> Result<String, Error> {
        match self {
            Self::PostgreSQL => crate::probe::validate(pool).await,
        }
    }
}
