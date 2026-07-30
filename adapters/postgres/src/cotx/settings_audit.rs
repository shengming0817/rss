//! Closed PostgreSQL transaction facades for settings and audit concerns.
//!
//! Repository code receives only concern operations. Canonical SQL and bind order remain here;
//! raw connections, generic executors, and transaction settlement stay owned by `cotx`.

use futures::future::BoxFuture;
use sqlx::PgConnection;

#[cfg(feature = "domain-audit")]
use super::AuditAdminReadLane;
use super::{LocalTxAttempt, ServingReadLane, ServingWriteLane, TenantDb, TenantScopeHandle};
use crate::tx_retry::LocalTxDeadline;

#[cfg(feature = "domain-settings")]
use consistency::EventEntry;
#[cfg(feature = "domain-settings")]
use settings::ports::{ConfigMutation, ConfigRepoError, ConfigTombstone, SettingKey};

#[cfg(feature = "domain-settings")]
use crate::outbox::OutboxEnvelope;

#[cfg(feature = "domain-audit")]
use std::time::{Duration, UNIX_EPOCH};

#[cfg(feature = "domain-audit")]
use audit::ports::{
    AuditChainHasher, AuditEntry, AuditError, AuditLedgerVerifyReport, AuditListResult,
    AuditOutcome, AuditRecord, EntryHash, ResourceRef, actor_kind_from_db, actor_kind_to_db,
};
#[cfg(feature = "domain-audit")]
use base64::Engine as _;
#[cfg(feature = "domain-audit")]
use primitives::MacVerifier;
#[cfg(feature = "domain-audit")]
use sqlx::Row;

// ---------------------------------------------------------------------------
// Settings configuration
// ---------------------------------------------------------------------------

/// Encoded settings value accepted by the sole configuration mutation operation.
#[cfg(feature = "domain-settings")]
#[derive(Clone)]
pub(crate) struct EncodedConfigValue {
    pub(crate) value: Option<String>,
    pub(crate) protection_scheme: i32,
    pub(crate) value_enc: Option<Vec<u8>>,
    pub(crate) key_id: Option<String>,
}

/// Canonical inputs that identify one retryable settings mutation and its emitted fact.
#[cfg(feature = "domain-settings")]
pub(crate) struct ConfigProducerRequest<'a> {
    entry: &'a EventEntry,
    envelope: &'a OutboxEnvelope,
}

#[cfg(feature = "domain-settings")]
impl<'a> ConfigProducerRequest<'a> {
    pub(crate) fn new(entry: &'a EventEntry, envelope: &'a OutboxEnvelope) -> Self {
        Self { entry, envelope }
    }
}

/// Read-only settings transaction surface.
#[cfg(feature = "domain-settings")]
pub(crate) struct ConfigReadTx<'tx> {
    conn: &'tx mut PgConnection,
    tenant: vocab::TenantId,
}

#[cfg(feature = "domain-settings")]
impl ConfigReadTx<'_> {
    pub(crate) async fn find_latest(
        &mut self,
        key: &SettingKey,
    ) -> Result<Option<sqlx::postgres::PgRow>, sqlx::Error> {
        sqlx::query(
            r#"
            SELECT config_key, value, version, deleted, protection_scheme, value_enc, key_id
            FROM config_entries
            WHERE tenant_id = $1::uuid AND config_key = $2
            ORDER BY version DESC
            LIMIT 1
            "#,
        )
        .bind(tenant_param(self.tenant))
        .bind(key.as_str())
        .fetch_optional(&mut *self.conn)
        .await
    }

    pub(crate) async fn find_version(
        &mut self,
        key: &SettingKey,
        version: u64,
    ) -> Result<Option<sqlx::postgres::PgRow>, sqlx::Error> {
        sqlx::query(
            r#"
            SELECT config_key, value, version, deleted, protection_scheme, value_enc, key_id
            FROM config_entries
            WHERE tenant_id = $1::uuid AND config_key = $2 AND version = $3
            "#,
        )
        .bind(tenant_param(self.tenant))
        .bind(key.as_str())
        .bind(version_param(version))
        .fetch_optional(&mut *self.conn)
        .await
    }

    pub(crate) async fn head(
        &mut self,
        key: &SettingKey,
    ) -> Result<Option<(i64, bool)>, sqlx::Error> {
        sqlx::query_as(
            "SELECT version, deleted FROM config_entries \
             WHERE tenant_id = $1::uuid AND config_key = $2 \
             ORDER BY version DESC LIMIT 1",
        )
        .bind(tenant_param(self.tenant))
        .bind(key.as_str())
        .fetch_optional(&mut *self.conn)
        .await
    }
}

/// Non-interchangeable settings mutation capability minted only by config producer runners.
///
/// The type itself stays feature-ungated so L2 rust-type carriers can name it; operation
/// methods remain behind `domain-settings`.
pub(crate) struct ConfigWriteTx<'tx> {
    #[cfg_attr(not(feature = "domain-settings"), allow(dead_code))]
    conn: &'tx mut PgConnection,
    #[cfg_attr(not(feature = "domain-settings"), allow(dead_code))]
    tenant: vocab::TenantId,
}

#[cfg(feature = "domain-settings")]
impl ConfigWriteTx<'_> {
    pub(crate) async fn apply_mutation(
        &mut self,
        mutation: &ConfigMutation,
        encoded: &EncodedConfigValue,
    ) -> Result<(), ConfigRepoError> {
        if mutation.tenant() != self.tenant {
            return Err(config_storage(sqlx::Error::Protocol(
                "config mutation tenant does not match transaction tenant".to_owned(),
            )));
        }
        let result = match mutation {
            ConfigMutation::Put(entry) => {
                sqlx::query(
                    r#"
                    INSERT INTO config_entries (
                        tenant_id, config_key, version, value, protection_scheme, value_enc, key_id
                    )
                    SELECT $1::uuid, $2, $3, $4, $5, $6, $7
                    WHERE $3 = 1 + COALESCE(
                        (SELECT max(version) FROM config_entries
                         WHERE tenant_id = $1::uuid AND config_key = $2),
                        0
                    )
                    "#,
                )
                .bind(tenant_param(self.tenant))
                .bind(entry.key().as_str())
                .bind(version_param(entry.version()))
                .bind(encoded.value.as_deref())
                .bind(encoded.protection_scheme)
                .bind(encoded.value_enc.as_deref())
                .bind(encoded.key_id.as_deref())
                .execute(&mut *self.conn)
                .await
            }
            ConfigMutation::Delete(tombstone) => {
                insert_tombstone(&mut *self.conn, self.tenant, tombstone, encoded).await
            }
        };
        match result {
            Ok(done) if done.rows_affected() == 1 => Ok(()),
            Ok(_) => Err(ConfigRepoError::VersionConflict),
            Err(error)
                if error
                    .as_database_error()
                    .is_some_and(|database| database.is_unique_violation()) =>
            {
                Err(ConfigRepoError::VersionConflict)
            }
            Err(error) => Err(config_storage(error)),
        }
    }
}

#[cfg(feature = "domain-settings")]
async fn insert_tombstone(
    conn: &mut PgConnection,
    tenant: vocab::TenantId,
    tombstone: &ConfigTombstone,
    encoded: &EncodedConfigValue,
) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error> {
    sqlx::query(
        r#"
        INSERT INTO config_entries (
            tenant_id, config_key, version, value, deleted, protection_scheme, value_enc, key_id
        )
        SELECT $1::uuid, $2, $3, $4, true, $5, $6, $7
        WHERE $3 = 1 + COALESCE(
            (SELECT max(version) FROM config_entries
             WHERE tenant_id = $1::uuid AND config_key = $2),
            0
        )
          AND COALESCE(
            (SELECT NOT deleted FROM config_entries
             WHERE tenant_id = $1::uuid AND config_key = $2
             ORDER BY version DESC LIMIT 1),
            false
          )
        "#,
    )
    .bind(tenant_param(tenant))
    .bind(tombstone.key().as_str())
    .bind(version_param(tombstone.version()))
    .bind(encoded.value.as_deref())
    .bind(encoded.protection_scheme)
    .bind(encoded.value_enc.as_deref())
    .bind(encoded.key_id.as_deref())
    .execute(conn)
    .await
}

#[cfg(feature = "domain-settings")]
fn tenant_param(tenant: vocab::TenantId) -> String {
    tenant.as_uuid().to_string()
}

#[cfg(feature = "domain-settings")]
fn version_param(version: u64) -> i64 {
    i64::try_from(version).unwrap_or(i64::MAX)
}

#[cfg(feature = "domain-settings")]
fn config_storage(error: sqlx::Error) -> ConfigRepoError {
    ConfigRepoError::Storage(Box::new(error))
}

#[cfg(feature = "domain-settings")]
impl TenantDb<ServingReadLane> {
    pub(crate) async fn config_read<S, T, F>(&self, scope: S, read: F) -> Result<T, sqlx::Error>
    where
        S: TenantScopeHandle,
        F: for<'tx> FnOnce(ConfigReadTx<'tx>) -> BoxFuture<'tx, Result<T, sqlx::Error>> + Send,
        T: Send,
    {
        self.read(scope, move |tx| {
            let tenant = tx.tenant;
            read(ConfigReadTx {
                conn: &mut *tx.conn,
                tenant,
            })
        })
        .await
    }

    pub(crate) async fn config_head<S>(
        &self,
        scope: S,
        key: SettingKey,
    ) -> Result<Option<(i64, bool)>, sqlx::Error>
    where
        S: TenantScopeHandle,
    {
        self.config_read(scope, move |mut tx| {
            Box::pin(async move { tx.head(&key).await })
        })
        .await
    }
}

#[cfg(feature = "domain-settings")]
impl TenantDb<ServingWriteLane> {
    pub(crate) async fn retry_config_producer_tx<S, A, T, F, E>(
        &self,
        scope: S,
        deadline: LocalTxDeadline,
        request: ConfigProducerRequest<'_>,
        write: F,
        map_storage: impl Fn(sqlx::Error) -> E + Send + Sync,
    ) -> LocalTxAttempt<T, E>
    where
        S: TenantScopeHandle,
        F: for<'tx> FnOnce(
                ConfigWriteTx<'tx>,
            )
                -> BoxFuture<'tx, Result<super::ProducerTxOutcome<A, T>, E>>
            + Send,
        E: super::MapOutboxAppendError + std::error::Error + Send + Sync + 'static,
        A: super::ProducerFactAuthorization,
        T: Send + 'static,
    {
        self.retry_producer_tx(
            scope,
            deadline,
            request.entry,
            request.envelope,
            move |tx| {
                let tenant = tx.tenant;
                write(ConfigWriteTx {
                    conn: &mut *tx.conn,
                    tenant,
                })
            },
            map_storage,
        )
        .await
    }
}

// ---------------------------------------------------------------------------
// Audit hash-chain ledger
// ---------------------------------------------------------------------------

#[cfg(feature = "domain-audit")]
const AUDIT_SELECT_COLUMNS: &str = "tenant_id::text AS tenant_id, seq, prev_hash, entry_hash, key_id, actor::text AS actor, actor_kind, \
                                    action, resource_kind, resource_id, outcome, recorded_at_secs, recorded_at_nanos";
#[cfg(feature = "domain-audit")]
const AUDIT_TABLE: &str = "audit_entries";

/// Append-only audit-ledger transaction surface.
#[cfg(feature = "domain-audit")]
pub(crate) struct AuditWriteTx<'tx> {
    conn: &'tx mut PgConnection,
    tenant: vocab::TenantId,
}

#[cfg(feature = "domain-audit")]
impl AuditWriteTx<'_> {
    pub(crate) async fn append<M: MacVerifier>(
        &mut self,
        record: &AuditRecord,
        hasher: &AuditChainHasher<M>,
    ) -> Result<(), AuditError> {
        if record.tenant != self.tenant {
            return Err(AuditError::storage(std::io::Error::other(
                "audit append tenant scope mismatch",
            )));
        }
        let tenant = audit_tenant_param(self.tenant);
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(advisory_lock_key(self.tenant))
            .execute(&mut *self.conn)
            .await
            .map_err(audit_storage)?;

        let (sequence, previous) = self.read_tail(&tenant).await?;
        let raw = AuditEntry::hydrate(
            sequence,
            previous,
            EntryHash::genesis(),
            record.actor,
            record.actor_kind,
            record.tenant,
            record.action.clone(),
            record.resource.clone(),
            record.outcome,
            record.recorded_at,
        );
        let entry_hash = hasher.link(&previous, &raw);
        self.insert_entry(&tenant, sequence, &previous, &entry_hash, record)
            .await
    }

    async fn read_tail(&mut self, tenant: &str) -> Result<(u64, EntryHash), AuditError> {
        let row = sqlx::query(&format!(
            "SELECT seq, entry_hash FROM {AUDIT_TABLE} \
             WHERE tenant_id = $1::uuid ORDER BY seq DESC LIMIT 1"
        ))
        .bind(tenant)
        .fetch_optional(&mut *self.conn)
        .await
        .map_err(audit_storage)?;
        let Some(row) = row else {
            return Ok((0, EntryHash::genesis()));
        };
        let sequence = u64::try_from(row.try_get::<i64, _>("seq").map_err(audit_storage)?)
            .map_err(AuditError::storage)?;
        let next = sequence.checked_add(1).ok_or(AuditError::SequenceGap)?;
        let hash: Vec<u8> = row.try_get("entry_hash").map_err(audit_storage)?;
        let hash = hash
            .try_into()
            .map_err(|_| invalid_audit_data("tail entry_hash wrong length"))?;
        Ok((next, EntryHash::new(hash)))
    }

    async fn insert_entry(
        &mut self,
        tenant: &str,
        sequence: u64,
        previous: &EntryHash,
        entry_hash: &EntryHash,
        record: &AuditRecord,
    ) -> Result<(), AuditError> {
        let sequence = i64::try_from(sequence).map_err(AuditError::storage)?;
        let since_epoch = record
            .recorded_at
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO);
        let seconds = i64::try_from(since_epoch.as_secs()).unwrap_or(i64::MAX);
        let nanos = since_epoch.subsec_nanos() as i32;
        sqlx::query(&format!(
            "INSERT INTO {AUDIT_TABLE} \
             (tenant_id, seq, prev_hash, entry_hash, actor, actor_kind, action, \
              resource_kind, resource_id, outcome, recorded_at_secs, recorded_at_nanos, key_id) \
             VALUES ($1::uuid, $2, $3, $4, $5::uuid, $6, $7, $8, $9, $10, $11, $12, $13)"
        ))
        .bind(tenant)
        .bind(sequence)
        .bind(previous.as_bytes().as_slice())
        .bind(entry_hash.as_bytes().as_slice())
        .bind(record.actor.as_uuid().to_string())
        .bind(actor_kind_to_db(record.actor_kind))
        .bind(record.action.as_str())
        .bind(record.resource.kind())
        .bind(record.resource.id())
        .bind(record.outcome.to_db())
        .bind(seconds)
        .bind(nanos)
        .bind(crate::audit_repo::AuditChainKeyIdentity::V1.as_i16())
        .execute(&mut *self.conn)
        .await
        .map_err(audit_storage)?;
        Ok(())
    }
}

/// Verified audit read operations; low-level predecessor/window queries are not exposed.
#[cfg(feature = "domain-audit")]
pub(crate) struct AuditReadTx<'tx> {
    conn: &'tx mut PgConnection,
    tenant: vocab::TenantId,
}

#[cfg(feature = "domain-audit")]
impl AuditReadTx<'_> {
    pub(crate) async fn list<M: MacVerifier>(
        &mut self,
        start_sequence: u64,
        limit: usize,
        hasher: &AuditChainHasher<M>,
    ) -> Result<AuditListResult, AuditError> {
        let start = i64::try_from(start_sequence).map_err(AuditError::storage)?;
        let fetch_limit = i64::try_from(limit + 1).unwrap_or(i64::MAX);
        let predecessor = if start_sequence > 0 {
            self.predecessor(start - 1).await?
        } else {
            None
        };
        let tenant = audit_tenant_param(self.tenant);
        let rows = sqlx::query(&format!(
            "SELECT {AUDIT_SELECT_COLUMNS} FROM {AUDIT_TABLE} \
             WHERE tenant_id = $1::uuid AND seq >= $2 ORDER BY seq ASC LIMIT $3"
        ))
        .bind(tenant)
        .bind(start)
        .bind(fetch_limit)
        .fetch_all(&mut *self.conn)
        .await
        .map_err(audit_storage)?;
        let mut entries = rows
            .iter()
            .map(|row| hydrate_audit_row(row, self.tenant))
            .collect::<Result<Vec<_>, _>>()?;
        let has_more = entries.len() > limit;
        if has_more {
            entries.truncate(limit);
        }
        hasher.verify_window(predecessor.as_ref(), &entries)?;
        let next_cursor = if has_more {
            Some(encode_audit_cursor(start_sequence + limit as u64)?)
        } else {
            None
        };
        Ok(AuditListResult {
            entries,
            next_cursor,
            has_more,
        })
    }

    pub(crate) async fn verify_tail<M: MacVerifier>(
        &mut self,
        limit: u32,
        hasher: &AuditChainHasher<M>,
    ) -> Result<(), AuditError> {
        let tenant = audit_tenant_param(self.tenant);
        let mut rows = sqlx::query(&format!(
            "SELECT {AUDIT_SELECT_COLUMNS} FROM {AUDIT_TABLE} \
             WHERE tenant_id = $1::uuid ORDER BY seq DESC LIMIT $2"
        ))
        .bind(tenant)
        .bind(i64::from(limit))
        .fetch_all(&mut *self.conn)
        .await
        .map_err(audit_storage)?;
        rows.reverse();
        let entries = rows
            .iter()
            .map(|row| hydrate_audit_row(row, self.tenant))
            .collect::<Result<Vec<_>, _>>()?;
        let predecessor = match entries.first() {
            Some(first) if first.seq() > 0 => {
                let sequence = i64::try_from(first.seq() - 1).map_err(AuditError::storage)?;
                self.predecessor(sequence).await?
            }
            _ => None,
        };
        hasher.verify_window(predecessor.as_ref(), &entries)
    }

    pub(crate) async fn verify_full<M: MacVerifier>(
        &mut self,
        batch: usize,
        hasher: &AuditChainHasher<M>,
    ) -> Result<AuditLedgerVerifyReport, AuditError> {
        if batch == 0 {
            return Err(AuditError::storage(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "audit ledger verify batch must be greater than zero",
            )));
        }
        let mut start = 0u64;
        let mut checked_entries = 0u64;
        loop {
            let result = self.list(start, batch, hasher).await?;
            let window = u64::try_from(result.entries.len()).map_err(AuditError::storage)?;
            checked_entries = checked_entries
                .checked_add(window)
                .ok_or(AuditError::SequenceGap)?;
            if !result.has_more {
                break;
            }
            if window == 0 {
                return Err(AuditError::SequenceGap);
            }
            start = start.checked_add(window).ok_or(AuditError::SequenceGap)?;
        }
        Ok(AuditLedgerVerifyReport {
            tenant: self.tenant,
            checked_entries,
        })
    }

    async fn predecessor(&mut self, sequence: i64) -> Result<Option<AuditEntry>, AuditError> {
        let tenant = audit_tenant_param(self.tenant);
        let row = sqlx::query(&format!(
            "SELECT {AUDIT_SELECT_COLUMNS} FROM {AUDIT_TABLE} \
             WHERE tenant_id = $1::uuid AND seq = $2"
        ))
        .bind(tenant)
        .bind(sequence)
        .fetch_optional(&mut *self.conn)
        .await
        .map_err(audit_storage)?;
        row.as_ref()
            .map(|row| hydrate_audit_row(row, self.tenant))
            .transpose()
    }
}

#[cfg(feature = "domain-audit")]
pub(crate) fn audit_write_tx<'tx>(
    tx: &'tx mut super::eventing::ConsumerTx<'_>,
) -> AuditWriteTx<'tx> {
    let (conn, tenant) = tx.parts();
    AuditWriteTx { conn, tenant }
}

#[cfg(feature = "domain-audit")]
impl TenantDb<ServingWriteLane> {
    pub(crate) async fn retry_audit_write<S, T, F, E>(
        &self,
        scope: S,
        deadline: LocalTxDeadline,
        write: F,
        map_storage: impl Fn(sqlx::Error) -> E + Send,
    ) -> LocalTxAttempt<T, E>
    where
        S: TenantScopeHandle,
        F: for<'tx> FnOnce(AuditWriteTx<'tx>) -> BoxFuture<'tx, Result<T, E>> + Send,
        E: std::error::Error + Send + Sync + 'static,
        T: Send,
    {
        self.retry_write(
            scope,
            deadline,
            move |tx| {
                let tenant = tx.tenant;
                write(AuditWriteTx {
                    conn: &mut *tx.conn,
                    tenant,
                })
            },
            map_storage,
        )
        .await
    }
}

#[cfg(feature = "domain-audit")]
macro_rules! audit_read_runner {
    ($lane:ty, $method:ident) => {
        impl TenantDb<$lane> {
            pub(crate) async fn $method<S, T, F, E>(
                &self,
                scope: S,
                read: F,
                map_storage: impl Fn(sqlx::Error) -> E + Send,
            ) -> Result<T, E>
            where
                S: TenantScopeHandle,
                F: for<'tx> FnOnce(AuditReadTx<'tx>) -> BoxFuture<'tx, Result<T, E>> + Send,
                E: Send,
                T: Send,
            {
                self.read_map(
                    scope,
                    move |tx| {
                        let tenant = tx.tenant;
                        read(AuditReadTx {
                            conn: &mut *tx.conn,
                            tenant,
                        })
                    },
                    map_storage,
                )
                .await
            }
        }
    };
}

#[cfg(feature = "domain-audit")]
audit_read_runner!(ServingReadLane, audit_read);
#[cfg(feature = "domain-audit")]
audit_read_runner!(AuditAdminReadLane, audit_admin_read);

#[cfg(feature = "domain-audit")]
fn audit_tenant_param(tenant: vocab::TenantId) -> String {
    tenant.as_uuid().to_string()
}

#[cfg(feature = "domain-audit")]
pub(crate) fn advisory_lock_key(tenant: vocab::TenantId) -> i64 {
    let bytes = *tenant.as_uuid().as_bytes();
    let high = i64::from_be_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]);
    let low = i64::from_be_bytes([
        bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
    ]);
    high ^ low
}

#[cfg(feature = "domain-audit")]
fn audit_storage(error: sqlx::Error) -> AuditError {
    AuditError::storage(error)
}

#[cfg(feature = "domain-audit")]
fn invalid_audit_data(message: &'static str) -> AuditError {
    AuditError::storage(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        message,
    ))
}

#[cfg(feature = "domain-audit")]
fn encode_audit_cursor(next_sequence: u64) -> Result<vocab::Cursor, AuditError> {
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(next_sequence.to_string());
    vocab::Cursor::parse(&raw)
        .map_err(|_| AuditError::storage(std::io::Error::other("cursor encode failed")))
}

#[cfg(feature = "domain-audit")]
fn hydrate_audit_row(
    row: &sqlx::postgres::PgRow,
    tenant: vocab::TenantId,
) -> Result<AuditEntry, AuditError> {
    let row_tenant = row
        .try_get::<String, _>("tenant_id")
        .map_err(audit_storage)
        .and_then(|value| vocab::TenantId::parse(&value).map_err(AuditError::storage))?;
    if row_tenant != tenant {
        return Err(AuditError::ChainBroken);
    }
    let key_id: i16 = row.try_get("key_id").map_err(audit_storage)?;
    if key_id != crate::audit_repo::AuditChainKeyIdentity::V1.as_i16() {
        return Err(AuditError::ChainBroken);
    }
    let sequence = u64::try_from(row.try_get::<i64, _>("seq").map_err(audit_storage)?)
        .map_err(AuditError::storage)?;
    let previous: Vec<u8> = row.try_get("prev_hash").map_err(audit_storage)?;
    let previous = previous
        .try_into()
        .map_err(|_| invalid_audit_data("prev_hash wrong length"))?;
    let hash: Vec<u8> = row.try_get("entry_hash").map_err(audit_storage)?;
    let hash = hash
        .try_into()
        .map_err(|_| invalid_audit_data("entry_hash wrong length"))?;
    let actor = row
        .try_get::<String, _>("actor")
        .map_err(audit_storage)
        .and_then(|value| ids::UserId::parse(&value).map_err(AuditError::storage))?;
    let actor_kind = row
        .try_get::<String, _>("actor_kind")
        .map_err(audit_storage)
        .and_then(|value| {
            actor_kind_from_db(&value).ok_or_else(|| invalid_audit_data("unknown actor_kind"))
        })?;
    let action = row
        .try_get::<String, _>("action")
        .map_err(audit_storage)
        .and_then(|value| vocab::Action::parse(&value).map_err(AuditError::storage))?;
    let resource = ResourceRef::new(
        row.try_get::<String, _>("resource_kind")
            .map_err(audit_storage)?,
        row.try_get::<String, _>("resource_id")
            .map_err(audit_storage)?,
    );
    let outcome = row
        .try_get::<String, _>("outcome")
        .map_err(audit_storage)
        .and_then(|value| {
            AuditOutcome::from_db(&value).ok_or_else(|| invalid_audit_data("unknown outcome"))
        })?;
    let seconds = u64::try_from(
        row.try_get::<i64, _>("recorded_at_secs")
            .map_err(audit_storage)?,
    )
    .unwrap_or(0);
    let nanos = u32::try_from(
        row.try_get::<i32, _>("recorded_at_nanos")
            .map_err(audit_storage)?,
    )
    .unwrap_or(0);
    Ok(AuditEntry::hydrate(
        sequence,
        EntryHash::new(previous),
        EntryHash::new(hash),
        actor,
        actor_kind,
        tenant,
        action,
        resource,
        outcome,
        UNIX_EPOCH + Duration::new(seconds, nanos),
    ))
}

// ---------------------------------------------------------------------------
// Flat auth audit tenant append
// ---------------------------------------------------------------------------

#[cfg(feature = "domain-audit")]
const INSERT_AUTH_AUDIT_EVENT: &str = "INSERT INTO auth_audit_events \
     (occurred_at_secs, occurred_at_nanos, principal_id, principal_kind, tenant_context, \
      resource_kind, resource_id, action, outcome, failure_reason, request_id, correlation_id) \
     VALUES ($1, $2, $3, $4, $5::uuid, $6, $7, $8, $9, $10, $11, $12)";

#[cfg(feature = "domain-audit")]
#[derive(Clone)]
pub(crate) struct EncodedAuditEvent {
    pub(crate) occurred_at_secs: i64,
    pub(crate) occurred_at_nanos: i32,
    pub(crate) principal_id: String,
    pub(crate) principal_kind: &'static str,
    pub(crate) tenant_context: Option<String>,
    pub(crate) resource_kind: &'static str,
    pub(crate) resource_id: String,
    pub(crate) action: &'static str,
    pub(crate) outcome: &'static str,
    pub(crate) failure_reason: Option<&'static str>,
    pub(crate) request_id: Option<String>,
    pub(crate) correlation_id: Option<String>,
}

#[cfg(feature = "domain-audit")]
pub(crate) struct AuthAuditWriteTx<'tx> {
    conn: &'tx mut PgConnection,
    tenant: vocab::TenantId,
}

#[cfg(feature = "domain-audit")]
impl AuthAuditWriteTx<'_> {
    pub(crate) async fn append_event(
        &mut self,
        event: EncodedAuditEvent,
    ) -> Result<(), sqlx::Error> {
        let tenant = self.tenant.as_uuid().to_string();
        if event.tenant_context.as_deref() != Some(tenant.as_str()) {
            return Err(sqlx::Error::Protocol(
                "auth audit event tenant does not match transaction tenant".to_string(),
            ));
        }
        sqlx::query(INSERT_AUTH_AUDIT_EVENT)
            .bind(event.occurred_at_secs)
            .bind(event.occurred_at_nanos)
            .bind(event.principal_id)
            .bind(event.principal_kind)
            .bind(tenant)
            .bind(event.resource_kind)
            .bind(event.resource_id)
            .bind(event.action)
            .bind(event.outcome)
            .bind(event.failure_reason)
            .bind(event.request_id)
            .bind(event.correlation_id)
            .execute(&mut *self.conn)
            .await
            .map(|_| ())
    }

    #[cfg(all(test, feature = "integration"))]
    pub(crate) async fn inject_commit_unknown_after_commit(&mut self) -> Result<(), sqlx::Error> {
        sqlx::query("SELECT set_config('rss.test_commit_unknown_after_commit', '1', true)")
            .execute(&mut *self.conn)
            .await
            .map(|_| ())
    }

    #[cfg(all(test, feature = "integration"))]
    pub(crate) async fn inject_rollback_failed_after_rollback(
        &mut self,
    ) -> Result<(), sqlx::Error> {
        sqlx::query("SELECT set_config('rss.test_rollback_failed_after_rollback', '1', true)")
            .execute(&mut *self.conn)
            .await
            .map(|_| ())
    }
}

#[cfg(feature = "domain-audit")]
impl TenantDb<ServingWriteLane> {
    pub(crate) async fn retry_auth_audit_write<S, T, F, E>(
        &self,
        scope: S,
        deadline: LocalTxDeadline,
        write: F,
        map_storage: impl Fn(sqlx::Error) -> E + Send,
    ) -> LocalTxAttempt<T, E>
    where
        S: TenantScopeHandle,
        F: for<'tx> FnOnce(AuthAuditWriteTx<'tx>) -> BoxFuture<'tx, Result<T, E>> + Send,
        E: std::error::Error + Send + Sync + 'static,
        T: Send,
    {
        self.retry_write(
            scope,
            deadline,
            move |tx| {
                write(AuthAuditWriteTx {
                    conn: &mut *tx.conn,
                    tenant: tx.tenant,
                })
            },
            map_storage,
        )
        .await
    }
}
