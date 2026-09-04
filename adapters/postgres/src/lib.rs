//! Provider-neutral PostgreSQL consistency adapter.
//!
//! RSS never creates or migrates database objects. A provider must implement
//! [`STORAGE_CONTRACT`] before [`PgRuntime::connect`] succeeds.

use std::sync::Arc;
use std::time::Duration;

use futures::future::BoxFuture;
use rss_request_context::TenantId;
use rustls::RootCertStore;
use rustls_pki_types::CertificateDer;
use rustls_pki_types::pem::PemObject as _;
use sqlx::PgPool;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions, PgSslMode};

const APPLICATION_NAME: &str = "rss-postgres-consistency";

/// Versioned provider-facing storage contract. This is a schema description, not migration DDL.
pub const STORAGE_CONTRACT: PgStorageContract = PgStorageContract {
    id: "rss.postgres.consistency.v1",
    relations: &["rss_fences(tenant_id uuid, key text, epoch bigint); unique(tenant_id, key)"],
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PgStorageContract {
    pub id: &'static str,
    pub relations: &'static [&'static str],
}

/// Password material is redacted and has no `Display` implementation.
#[derive(Clone)]
pub struct PgPassword(zeroize::Zeroizing<String>);

impl PgPassword {
    pub fn new(secret: impl Into<String>) -> Self {
        Self(zeroize::Zeroizing::new(secret.into()))
    }
}

impl std::fmt::Debug for PgPassword {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PgPassword(<redacted>)")
    }
}

/// Validated, non-empty explicit CA bundle appended to SQLx's roots under `VerifyFull`.
#[derive(Clone)]
pub struct PgPrivateCa {
    pem: Arc<[u8]>,
}

#[derive(Debug, thiserror::Error)]
#[error("invalid PostgreSQL private CA PEM")]
pub struct PgPrivateCaError;

impl PgPrivateCa {
    pub fn from_pem(pem: Vec<u8>) -> Result<Self, PgPrivateCaError> {
        let certificates = CertificateDer::pem_slice_iter(&pem)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| PgPrivateCaError)?;
        if certificates.is_empty() {
            return Err(PgPrivateCaError);
        }
        let mut roots = RootCertStore::empty();
        for certificate in certificates {
            roots
                .add(certificate.into_owned())
                .map_err(|_| PgPrivateCaError)?;
        }
        Ok(Self {
            pem: Arc::from(pem),
        })
    }
}

impl std::fmt::Debug for PgPrivateCa {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PgPrivateCa(<redacted>)")
    }
}

#[derive(Clone, Debug)]
enum PgTlsTrust {
    PrivateCa(PgPrivateCa),
    #[cfg(any(test, feature = "test-support"))]
    PlaintextForTest,
}

/// Security-closed PostgreSQL pool configuration. Production always uses `VerifyFull`.
#[derive(Clone, Debug)]
pub struct PgConfig {
    host: String,
    port: u16,
    database: String,
    username: String,
    password: PgPassword,
    tls: PgTlsTrust,
    min_connections: u32,
    max_connections: u32,
    acquire_timeout: Duration,
}

impl PgConfig {
    #[must_use]
    pub fn new(
        host: impl Into<String>,
        port: u16,
        database: impl Into<String>,
        username: impl Into<String>,
        password: PgPassword,
        private_ca: PgPrivateCa,
    ) -> Self {
        Self::new_with_tls(
            host,
            port,
            database,
            username,
            password,
            PgTlsTrust::PrivateCa(private_ca),
        )
    }

    #[cfg(any(test, feature = "test-support"))]
    #[must_use]
    pub fn new_for_test_plaintext(
        host: impl Into<String>,
        port: u16,
        database: impl Into<String>,
        username: impl Into<String>,
        password: PgPassword,
    ) -> Self {
        Self::new_with_tls(
            host,
            port,
            database,
            username,
            password,
            PgTlsTrust::PlaintextForTest,
        )
    }

    fn new_with_tls(
        host: impl Into<String>,
        port: u16,
        database: impl Into<String>,
        username: impl Into<String>,
        password: PgPassword,
        tls: PgTlsTrust,
    ) -> Self {
        Self {
            host: host.into(),
            port,
            database: database.into(),
            username: username.into(),
            password,
            tls,
            min_connections: 0,
            max_connections: 10,
            acquire_timeout: Duration::from_secs(5),
        }
    }

    #[must_use]
    pub fn with_pool_limits(mut self, min_connections: u32, max_connections: u32) -> Self {
        self.min_connections = min_connections;
        self.max_connections = max_connections;
        self
    }

    #[must_use]
    pub fn with_acquire_timeout(mut self, acquire_timeout: Duration) -> Self {
        self.acquire_timeout = acquire_timeout;
        self
    }

    fn validate(&self) -> Result<(), PgError> {
        if self.host.trim().is_empty()
            || self.database.trim().is_empty()
            || self.username.trim().is_empty()
            || self.password.0.is_empty()
            || self.port == 0
        {
            return Err(PgError::InvalidConnectionConfig);
        }
        if self.max_connections == 0 || self.min_connections > self.max_connections {
            return Err(PgError::InvalidPoolLimits);
        }
        if self.acquire_timeout.is_zero() {
            return Err(PgError::InvalidAcquireTimeout);
        }
        Ok(())
    }

    fn connect_options(&self) -> PgConnectOptions {
        let options = PgConnectOptions::new()
            .host(&self.host)
            .port(self.port)
            .database(&self.database)
            .username(&self.username)
            .password(&self.password.0)
            .application_name(APPLICATION_NAME);
        match &self.tls {
            PgTlsTrust::PrivateCa(ca) => options
                .ssl_mode(PgSslMode::VerifyFull)
                .ssl_root_cert_from_pem(ca.pem.to_vec()),
            #[cfg(any(test, feature = "test-support"))]
            PgTlsTrust::PlaintextForTest => options.ssl_mode(PgSslMode::Disable),
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PgError {
    #[error("postgres connection configuration is invalid")]
    InvalidConnectionConfig,
    #[error("postgres pool limits are invalid")]
    InvalidPoolLimits,
    #[error("postgres acquire timeout is invalid")]
    InvalidAcquireTimeout,
    #[error("postgres connection failed")]
    Connect(#[source] sqlx::Error),
    #[error("postgres storage contract probe failed")]
    StorageContractProbe(#[source] sqlx::Error),
    #[error("postgres provider does not implement the required storage contract")]
    IncompatibleStorageContract,
    #[error("postgres transaction begin failed")]
    Begin(#[source] sqlx::Error),
    #[error("postgres transaction commit outcome is unknown")]
    CommitUnknown(#[source] sqlx::Error),
    #[error("postgres transaction rollback failed")]
    RollbackFailed(#[source] sqlx::Error),
    #[error("postgres consistency operation failed")]
    Operation(#[source] sqlx::Error),
    #[error("postgres consistency value is invalid")]
    InvalidValue,
}

pub struct PgRuntime {
    pool: PgPool,
}

impl PgRuntime {
    pub async fn connect(config: PgConfig) -> Result<Self, PgError> {
        config.validate()?;
        let pool = PgPoolOptions::new()
            .min_connections(config.min_connections)
            .max_connections(config.max_connections)
            .acquire_timeout(config.acquire_timeout)
            .test_before_acquire(true)
            .connect_with(config.connect_options())
            .await
            .map_err(PgError::Connect)?;
        if !probe_storage_contract(&pool).await? {
            pool.close().await;
            return Err(PgError::IncompatibleStorageContract);
        }
        Ok(Self { pool })
    }

    /// Execute one tenant-bound local transaction. RSS never creates schema in this path.
    pub async fn local_tx<T, F>(&self, tenant_id: TenantId, operation: F) -> Result<T, PgError>
    where
        F: for<'tx> FnOnce(&'tx mut PgLocalTx<'_>) -> BoxFuture<'tx, Result<T, PgError>>,
    {
        let mut transaction = self.pool.begin().await.map_err(PgError::Begin)?;
        let tenant = tenant_id.to_string();
        sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
            .bind(&tenant)
            .execute(&mut *transaction)
            .await
            .map_err(PgError::Operation)?;
        let mut transaction = PgLocalTx {
            transaction,
            tenant,
        };
        match operation(&mut transaction).await {
            Ok(value) => {
                transaction
                    .transaction
                    .commit()
                    .await
                    .map_err(PgError::CommitUnknown)?;
                Ok(value)
            }
            Err(error) => match transaction.transaction.rollback().await {
                Ok(()) => Err(error),
                Err(source) => Err(PgError::RollbackFailed(source)),
            },
        }
    }

    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.pool.is_closed()
    }
}

async fn probe_storage_contract(pool: &PgPool) -> Result<bool, PgError> {
    let compatible: bool = sqlx::query_scalar(SCHEMA_PROBE_SQL)
        .fetch_one(pool)
        .await
        .map_err(PgError::StorageContractProbe)?;
    Ok(compatible)
}

const SCHEMA_PROBE_SQL: &str = r#"
WITH required(relation_name, column_name, data_type, nullable) AS (VALUES
 ('rss_fences','tenant_id','uuid',false),
 ('rss_fences','key','text',false), ('rss_fences','epoch','bigint',false)
), columns_ok AS (
 SELECT NOT EXISTS (SELECT 1 FROM required r LEFT JOIN information_schema.columns c
  ON c.table_schema='public' AND c.table_name=r.relation_name AND c.column_name=r.column_name
  WHERE c.column_name IS NULL OR c.data_type<>r.data_type OR (c.is_nullable='YES')<>r.nullable) AS ok
), unique_ok AS (
 SELECT bool_and(EXISTS (SELECT 1 FROM pg_index i WHERE i.indrelid=to_regclass('public.'||v.rel)
  AND i.indisunique AND (SELECT array_agg(a.attname ORDER BY u.ord) FROM unnest(i.indkey) WITH ORDINALITY u(attnum,ord)
  JOIN pg_attribute a ON a.attrelid=i.indrelid AND a.attnum=u.attnum)=v.cols)) AS ok
 FROM (VALUES ('rss_fences',ARRAY['tenant_id','key']::name[])) v(rel,cols)
) SELECT columns_ok.ok AND unique_ok.ok FROM columns_ok, unique_ok
"#;

impl rss_runtime::ManagedResource for PgRuntime {
    fn name(&self) -> &str {
        "postgres"
    }
    async fn shutdown(&self) -> Result<(), rss_runtime::ShutdownError> {
        self.pool.close().await;
        Ok(())
    }
}

pub struct PgLocalTx<'connection> {
    transaction: sqlx::Transaction<'connection, sqlx::Postgres>,
    tenant: String,
}

impl PgLocalTx<'_> {
    pub async fn advance_fence(&mut self, key: &str, epoch: u64) -> Result<bool, PgError> {
        let epoch = validate_fence(key, epoch)?;
        let result = sqlx::query("INSERT INTO rss_fences (tenant_id,key,epoch) VALUES ($1::uuid,$2,$3) \
            ON CONFLICT (tenant_id,key) DO UPDATE SET epoch=EXCLUDED.epoch WHERE rss_fences.epoch<EXCLUDED.epoch")
            .bind(&self.tenant).bind(key).bind(epoch).execute(&mut *self.transaction)
            .await.map_err(PgError::Operation)?;
        Ok(result.rows_affected() == 1)
    }
}

fn validate_fence(key: &str, epoch: u64) -> Result<i64, PgError> {
    if key.is_empty() || epoch == 0 {
        return Err(PgError::InvalidValue);
    }
    i64::try_from(epoch).map_err(|_| PgError::InvalidValue)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> PgConfig {
        PgConfig::new_for_test_plaintext("localhost", 5432, "rss", "rss", PgPassword::new("secret"))
    }

    #[allow(clippy::expect_used)]
    // reason: generated test certificate must be accepted by the focused constructor assertions.
    fn private_ca_pem() -> Vec<u8> {
        let mut params = rcgen::CertificateParams::default();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        rcgen::CertifiedIssuer::self_signed(
            params,
            rcgen::KeyPair::generate().expect("generate CA key"),
        )
        .expect("generate CA certificate")
        .pem()
        .into_bytes()
    }

    #[test]
    fn production_contract_is_versioned_and_complete() {
        assert_eq!(STORAGE_CONTRACT.id, "rss.postgres.consistency.v1");
        assert_eq!(STORAGE_CONTRACT.relations.len(), 1);
        for identity in ["tenant_id", "epoch", "unique(tenant_id"] {
            assert!(
                STORAGE_CONTRACT
                    .relations
                    .iter()
                    .any(|relation| relation.contains(identity))
            );
        }
    }

    #[test]
    fn config_validation_is_database_free() {
        assert!(matches!(
            config().with_pool_limits(2, 1).validate(),
            Err(PgError::InvalidPoolLimits)
        ));
        assert!(matches!(
            config().with_acquire_timeout(Duration::ZERO).validate(),
            Err(PgError::InvalidAcquireTimeout)
        ));
    }

    #[test]
    fn private_ca_accepts_ca_certificate_and_rejects_invalid_pem() {
        assert!(PgPrivateCa::from_pem(Vec::new()).is_err());
        assert!(PgPrivateCa::from_pem(b"not a certificate".to_vec()).is_err());
        assert!(PgPrivateCa::from_pem(private_ca_pem()).is_ok());
    }

    #[test]
    fn claim_and_fence_boundaries_reject_invalid_values_without_database() {
        assert!(matches!(validate_fence("", 1), Err(PgError::InvalidValue)));
        assert!(matches!(
            validate_fence("key", 0),
            Err(PgError::InvalidValue)
        ));
        assert!(matches!(
            validate_fence("key", u64::MAX),
            Err(PgError::InvalidValue)
        ));
    }

    #[test]
    #[allow(clippy::expect_used)]
    // reason: generated PEM is valid UTF-8 and its absence from SQLx options must fail the test.
    fn production_connect_options_force_verify_full_with_explicit_ca() {
        let pem = private_ca_pem();
        let expected_root = String::from_utf8(pem.clone()).expect("PEM is UTF-8");
        let config = PgConfig::new(
            "db.example.test",
            5432,
            "rss",
            "rss",
            PgPassword::new("secret"),
            PgPrivateCa::from_pem(pem).expect("valid CA PEM"),
        );

        let options = config.connect_options();
        assert!(matches!(options.get_ssl_mode(), PgSslMode::VerifyFull));
        let explicit_root = sqlx::ConnectOptions::to_url_lossy(&options)
            .query_pairs()
            .find_map(|(name, value)| (name == "sslrootcert").then(|| value.into_owned()));
        assert_eq!(explicit_root.as_deref(), Some(expected_root.as_str()));
    }
}
