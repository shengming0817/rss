//! Provider-neutral PostgreSQL consistency adapter.
//!
//! RSS never creates or migrates database objects. A provider must implement
//! [`STORAGE_CONTRACT`] before [`PgRuntime::connect`] succeeds.

use std::sync::Arc;
use std::time::Duration;

use consistency::{
    ConsumerGroup, EventEntry, IdemKey, LeaseToken, OutboxAppendOutcome, OutboxFactConflict,
};
use futures::future::BoxFuture;
use rss_request_context::TenantId;
use rustls::RootCertStore;
use rustls_pki_types::CertificateDer;
use rustls_pki_types::pem::PemObject as _;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions, PgSslMode};
use sqlx::{PgPool, Row as _};

const APPLICATION_NAME: &str = "rss-postgres-consistency";

/// Versioned provider-facing storage contract. This is a schema description, not migration DDL.
pub const STORAGE_CONTRACT: PgStorageContract = PgStorageContract {
    id: "rss.postgres.consistency.v1",
    relations: &[
        "rss_inbox_receipts(tenant_id uuid, consumer_group text, event_id text); unique(tenant_id, consumer_group, event_id)",
        "rss_outbox(tenant_id uuid, id text, topic text, payload bytea, status text, lease_token text nullable, lease_until timestamptz nullable); unique(tenant_id, id)",
        "rss_fences(tenant_id uuid, key text, epoch bigint); unique(tenant_id, key)",
    ],
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
    #[error(transparent)]
    FactConflict(#[from] OutboxFactConflict),
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

    pub async fn claim_outbox(
        &self,
        tenant_id: TenantId,
        lease_token: LeaseToken,
        lease_for: Duration,
        limit: u32,
    ) -> Result<Vec<PgOutboxClaim>, PgError> {
        let lease_micros = validate_claim_parameters(lease_for, limit)?;
        let tenant = tenant_id.to_string();
        let rows = sqlx::query(
            "WITH candidates AS (SELECT id FROM rss_outbox WHERE tenant_id = $1::uuid AND \
             (status = 'pending' OR (status = 'publishing' AND lease_until <= clock_timestamp())) \
             ORDER BY id FOR UPDATE SKIP LOCKED LIMIT $2) UPDATE rss_outbox AS o SET \
             status = 'publishing', lease_token = $3, lease_until = clock_timestamp() + \
             ($4::bigint * interval '1 microsecond') FROM candidates WHERE o.tenant_id = $1::uuid \
             AND o.id = candidates.id RETURNING o.id, o.topic, o.payload, o.lease_until::text",
        )
        .bind(&tenant)
        .bind(i64::from(limit))
        .bind(lease_token.as_str())
        .bind(lease_micros)
        .fetch_all(&self.pool)
        .await
        .map_err(PgError::Operation)?;
        rows.into_iter()
            .map(|row| {
                Ok(PgOutboxClaim {
                    tenant_id: tenant.clone(),
                    id: row.try_get("id").map_err(PgError::Operation)?,
                    topic: row.try_get("topic").map_err(PgError::Operation)?,
                    payload: row.try_get("payload").map_err(PgError::Operation)?,
                    lease_token: lease_token.as_str().into(),
                    lease_until: row.try_get("lease_until").map_err(PgError::Operation)?,
                })
            })
            .collect()
    }

    pub async fn settle_published(&self, claim: PgOutboxClaim) -> Result<bool, PgError> {
        let result = sqlx::query("UPDATE rss_outbox SET status = 'published', lease_token = NULL, \
            lease_until = NULL WHERE tenant_id = $1::uuid AND id = $2 AND status = 'publishing' \
            AND lease_token = $3 AND lease_until = $4::timestamptz AND lease_until > clock_timestamp()")
            .bind(claim.tenant_id).bind(claim.id).bind(claim.lease_token).bind(claim.lease_until)
            .execute(&self.pool).await.map_err(PgError::Operation)?;
        Ok(result.rows_affected() == 1)
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
 ('rss_inbox_receipts','tenant_id','uuid',false), ('rss_inbox_receipts','consumer_group','text',false),
 ('rss_inbox_receipts','event_id','text',false), ('rss_outbox','tenant_id','uuid',false),
 ('rss_outbox','id','text',false), ('rss_outbox','topic','text',false), ('rss_outbox','payload','bytea',false),
 ('rss_outbox','status','text',false), ('rss_outbox','lease_token','text',true),
 ('rss_outbox','lease_until','timestamp with time zone',true), ('rss_fences','tenant_id','uuid',false),
 ('rss_fences','key','text',false), ('rss_fences','epoch','bigint',false)
), columns_ok AS (
 SELECT NOT EXISTS (SELECT 1 FROM required r LEFT JOIN information_schema.columns c
  ON c.table_schema='public' AND c.table_name=r.relation_name AND c.column_name=r.column_name
  WHERE c.column_name IS NULL OR c.data_type<>r.data_type OR (c.is_nullable='YES')<>r.nullable) AS ok
), unique_ok AS (
 SELECT bool_and(EXISTS (SELECT 1 FROM pg_index i WHERE i.indrelid=to_regclass('public.'||v.rel)
  AND i.indisunique AND (SELECT array_agg(a.attname ORDER BY u.ord) FROM unnest(i.indkey) WITH ORDINALITY u(attnum,ord)
  JOIN pg_attribute a ON a.attrelid=i.indrelid AND a.attnum=u.attnum)=v.cols)) AS ok
 FROM (VALUES ('rss_inbox_receipts',ARRAY['tenant_id','consumer_group','event_id']::name[]),
  ('rss_outbox',ARRAY['tenant_id','id']::name[]), ('rss_fences',ARRAY['tenant_id','key']::name[])) v(rel,cols)
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
    pub async fn try_claim_inbox(
        &mut self,
        consumer_group: &ConsumerGroup,
        event_id: &IdemKey,
    ) -> Result<PgInboxClaim, PgError> {
        let result = sqlx::query(
            "INSERT INTO rss_inbox_receipts (tenant_id, consumer_group, event_id) \
            VALUES ($1::uuid, $2, $3) ON CONFLICT (tenant_id, consumer_group, event_id) DO NOTHING",
        )
        .bind(&self.tenant)
        .bind(consumer_group.as_str())
        .bind(event_id.as_str())
        .execute(&mut *self.transaction)
        .await
        .map_err(PgError::Operation)?;
        Ok(if result.rows_affected() == 1 {
            PgInboxClaim::Fresh
        } else {
            PgInboxClaim::Duplicate
        })
    }

    pub async fn append_outbox(
        &mut self,
        entry: &EventEntry,
    ) -> Result<OutboxAppendOutcome, PgError> {
        let row = sqlx::query("WITH inserted AS (INSERT INTO rss_outbox \
            (tenant_id,id,topic,payload,status) VALUES ($1::uuid,$2,$3,$4,'pending') \
            ON CONFLICT (tenant_id,id) DO NOTHING RETURNING true AS inserted, true AS same_fact) \
            SELECT inserted,same_fact FROM inserted UNION ALL SELECT false, topic=$3 AND payload=$4 \
            FROM rss_outbox WHERE tenant_id=$1::uuid AND id=$2 LIMIT 1")
            .bind(&self.tenant).bind(entry.idem_key().as_str()).bind(entry.topic().as_str()).bind(entry.payload())
            .fetch_one(&mut *self.transaction).await.map_err(PgError::Operation)?;
        let inserted: bool = row.try_get("inserted").map_err(PgError::Operation)?;
        let same_fact: bool = row.try_get("same_fact").map_err(PgError::Operation)?;
        if inserted {
            Ok(OutboxAppendOutcome::Inserted)
        } else if same_fact {
            Ok(OutboxAppendOutcome::SameFact)
        } else {
            Err(OutboxFactConflict.into())
        }
    }

    pub async fn advance_fence(&mut self, key: &str, epoch: u64) -> Result<bool, PgError> {
        let epoch = validate_fence(key, epoch)?;
        let result = sqlx::query("INSERT INTO rss_fences (tenant_id,key,epoch) VALUES ($1::uuid,$2,$3) \
            ON CONFLICT (tenant_id,key) DO UPDATE SET epoch=EXCLUDED.epoch WHERE rss_fences.epoch<EXCLUDED.epoch")
            .bind(&self.tenant).bind(key).bind(epoch).execute(&mut *self.transaction)
            .await.map_err(PgError::Operation)?;
        Ok(result.rows_affected() == 1)
    }
}

fn validate_claim_parameters(lease_for: Duration, limit: u32) -> Result<i64, PgError> {
    if lease_for.is_zero() || limit == 0 {
        return Err(PgError::InvalidValue);
    }
    i64::try_from(lease_for.as_micros()).map_err(|_| PgError::InvalidValue)
}

fn validate_fence(key: &str, epoch: u64) -> Result<i64, PgError> {
    if key.is_empty() || epoch == 0 {
        return Err(PgError::InvalidValue);
    }
    i64::try_from(epoch).map_err(|_| PgError::InvalidValue)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PgInboxClaim {
    Fresh,
    Duplicate,
}

/// Move-only receipt carrying the complete lease identity used by settlement CAS.
pub struct PgOutboxClaim {
    tenant_id: String,
    id: String,
    topic: String,
    payload: Vec<u8>,
    lease_token: String,
    lease_until: String,
}

impl PgOutboxClaim {
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }
    #[must_use]
    pub fn topic(&self) -> &str {
        &self.topic
    }
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use static_assertions::assert_not_impl_any;

    assert_not_impl_any!(PgOutboxClaim: Clone, Copy);

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
        assert_eq!(STORAGE_CONTRACT.relations.len(), 3);
        for identity in ["tenant_id", "lease_until", "unique(tenant_id"] {
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
        assert!(matches!(
            validate_claim_parameters(Duration::ZERO, 1),
            Err(PgError::InvalidValue)
        ));
        assert!(matches!(
            validate_claim_parameters(Duration::from_secs(1), 0),
            Err(PgError::InvalidValue)
        ));
        assert!(matches!(
            validate_claim_parameters(Duration::from_secs(u64::MAX), 1),
            Err(PgError::InvalidValue)
        ));
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
