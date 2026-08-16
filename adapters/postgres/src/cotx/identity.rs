//! Exact-lane PostgreSQL façades for tenant identity and security stores.
//!
//! SQL text, tenant binding and row execution live here. Callers receive only named operations on
//! an exact serving lane; neither façade exposes the underlying connection or a generic executor.

use futures::future::BoxFuture;
#[cfg(feature = "domain-identity")]
use std::time::SystemTime;

#[cfg(any(feature = "domain-settings", feature = "domain-identity"))]
use super::LocalTxAttempt;
#[cfg(feature = "domain-identity")]
use super::{
    MapOutboxAppendError, ProducerFactAuthorization, ProducerTxAttempt, ProducerTxOutcome,
};
use super::{ServingReadLane, ServingWriteLane, TenantDb, TenantScopeHandle, TenantTx};
#[cfg(feature = "domain-settings")]
use crate::tx_retry::LocalTxDeadline;

#[cfg(feature = "domain-identity")]
pub(crate) struct CanonicalDeviceIngressFact {
    entry: consistency::EventEntry,
    envelope: crate::outbox::OutboxEnvelope,
}

#[cfg(feature = "domain-identity")]
impl CanonicalDeviceIngressFact {
    pub(crate) fn from_reviewed_event(
        scope: ::identity::ports::device_certificate::DeviceCertificateScope,
        event: eventexec::event::ReviewedEvent,
        occurred_at: SystemTime,
        credential_generation: u64,
    ) -> Result<Self, crate::outbox::OutboxAppendError> {
        let (entry, envelope, fact) = event.into_parts();
        let expected_device = scope.device().as_uuid().to_string();
        let envelope_valid = envelope.tenant() == scope.tenant()
            && envelope.subject_id().as_str() == expected_device
            && envelope.actor().kind() == rss_request_context::PrincipalKind::Device
            && envelope.actor().actor_id().as_str() == expected_device
            && envelope.actor().tenant() == Some(scope.tenant())
            && envelope.actor().scope() == vocab::VisibilityScope::Tenant
            && envelope.causation_id().is_none();
        if fact != ::identity::ports::device_certificate::device_ingress_receipt_fact()
            || !envelope_valid
        {
            return Err(crate::outbox::OutboxAppendError::InvalidIdentity);
        }
        let (contract, tenant, subject_id, actor, partition_key, causation_id) =
            envelope.into_parts();
        let mut metadata = crate::outbox::OutboxMetadata::new(
            crate::outbox::unix_secs(occurred_at),
            tenant,
            contract,
        )
        .with_subject_id(subject_id)
        .with_actor(actor);
        metadata
            .try_insert(
                "credentialGeneration",
                serde_json::Value::from(credential_generation),
            )
            .map_err(|_| crate::outbox::OutboxAppendError::InvalidIdentity)?;
        let envelope = crate::outbox::OutboxEnvelope::new(
            contract.domain().to_string(),
            contract.contract_id().to_string(),
            metadata,
        )
        .with_partition_key_opt(partition_key)
        .with_causation_id_opt(causation_id);
        Ok(Self { entry, envelope })
    }

    pub(crate) fn tenant(&self) -> rss_request_context::TenantId {
        self.envelope.tenant()
    }

    pub(crate) fn event_id(&self) -> &str {
        self.entry.idem_key().as_str()
    }

    pub(crate) fn fingerprint(&self) -> consistency::OutboxFactFingerprint {
        crate::outbox::CanonicalOutboxFact::from_entry_env(&self.entry, &self.envelope)
            .fingerprint()
    }

    fn into_parts(self) -> (consistency::EventEntry, crate::outbox::OutboxEnvelope) {
        (self.entry, self.envelope)
    }
}

#[cfg(feature = "domain-identity")]
pub(crate) struct DeviceIngressTxOutcome<T> {
    value: T,
    fact: CanonicalDeviceIngressFact,
}

#[cfg(feature = "domain-identity")]
impl<T> DeviceIngressTxOutcome<T> {
    pub(crate) const fn new(value: T, fact: CanonicalDeviceIngressFact) -> Self {
        Self { value, fact }
    }
}

/// Non-interchangeable identity authority minted only by the identity transaction runners.
pub struct IdentityTx<'borrow, 'tx, L: super::TenantLane> {
    tx: &'borrow mut TenantTx<'tx, L>,
}

impl<L: super::TenantLane> IdentityTx<'_, '_, L> {
    pub(crate) fn tenant(&self) -> rss_request_context::TenantId {
        self.tx.tenant()
    }
}

#[cfg(all(test, feature = "integration"))]
impl IdentityTx<'_, '_, ServingWriteLane> {
    pub(crate) async fn inject_commit_unknown_after_commit(&mut self) -> Result<(), sqlx::Error> {
        self.tx.inject_commit_unknown_after_commit().await
    }

    pub(crate) async fn inject_failure_after_outbox_append_before_commit(
        &mut self,
    ) -> Result<(), sqlx::Error> {
        self.tx
            .inject_failure_after_outbox_append_before_commit()
            .await
    }

    pub(crate) async fn inject_failure_after_projection_append(
        &mut self,
    ) -> Result<(), sqlx::Error> {
        self.tx.inject_failure_after_projection_append().await
    }
}

/// Non-interchangeable settings-secret authority minted only by the secret runners.
#[cfg_attr(not(feature = "domain-settings"), allow(dead_code))]
pub(crate) struct SecretTx<'borrow, 'tx, L: super::TenantLane> {
    tx: &'borrow mut TenantTx<'tx, L>,
}

#[cfg(all(test, feature = "integration"))]
impl SecretTx<'_, '_, ServingWriteLane> {
    pub(crate) async fn inject_commit_unknown_after_commit(&mut self) -> Result<(), sqlx::Error> {
        self.tx.inject_commit_unknown_after_commit().await
    }
}

/// Non-interchangeable certificate-revocation authority.
pub(crate) struct RevocationTx<'borrow, 'tx> {
    tx: &'borrow mut TenantTx<'tx, ServingWriteLane>,
}

#[cfg(feature = "domain-identity")]
pub(crate) struct IdentityRead<'borrow, 'tx> {
    tx: &'borrow mut TenantTx<'tx, ServingReadLane>,
}

#[cfg(feature = "domain-identity")]
pub struct IdentityWrite<'borrow, 'tx> {
    tx: &'borrow mut TenantTx<'tx, ServingWriteLane>,
}

#[cfg(all(test, feature = "integration", feature = "domain-identity"))]
pub(crate) enum IdentityOutboxFault {
    RefreshSecurity,
    CredentialSecurity,
}

#[cfg(feature = "domain-identity")]
impl<'borrow, 'tx> IdentityTx<'borrow, 'tx, ServingReadLane> {
    pub(crate) fn identity(&mut self) -> IdentityRead<'_, 'tx> {
        IdentityRead { tx: self.tx }
    }
}

#[cfg(feature = "domain-identity")]
impl<'borrow, 'tx> IdentityTx<'borrow, 'tx, ServingWriteLane> {
    pub(crate) fn identity(&mut self) -> IdentityWrite<'_, 'tx> {
        IdentityWrite { tx: self.tx }
    }
}

#[cfg(feature = "domain-settings")]
pub(crate) struct SecretRead<'borrow, 'tx> {
    tx: &'borrow mut TenantTx<'tx, ServingReadLane>,
}

#[cfg(feature = "domain-settings")]
pub(crate) struct SecretWrite<'borrow, 'tx> {
    tx: &'borrow mut TenantTx<'tx, ServingWriteLane>,
}

#[cfg(feature = "domain-settings")]
pub(crate) struct LockedSecretKey<'borrow, 'tx> {
    tx: &'borrow mut TenantTx<'tx, ServingWriteLane>,
    key: settings::ports::SecretKey,
}

pub(crate) struct RevocationWrite<'borrow, 'tx> {
    tx: &'borrow mut TenantTx<'tx, ServingWriteLane>,
}

impl<'borrow, 'tx> RevocationTx<'borrow, 'tx> {
    pub(crate) fn revocations(&mut self) -> RevocationWrite<'_, 'tx> {
        RevocationWrite { tx: self.tx }
    }
}

#[cfg(feature = "domain-identity")]
impl TenantDb<ServingReadLane> {
    pub(crate) async fn identity_read<S, T, F>(&self, scope: S, read: F) -> Result<T, sqlx::Error>
    where
        S: TenantScopeHandle,
        F: for<'borrow, 'tx> FnOnce(
                IdentityTx<'borrow, 'tx, ServingReadLane>,
            ) -> BoxFuture<'borrow, Result<T, sqlx::Error>>
            + Send,
        T: Send,
    {
        self.read(scope, move |tx| read(IdentityTx { tx })).await
    }

    pub(crate) async fn identity_repeatable_read_map<S, T, F, E>(
        &self,
        scope: S,
        read: F,
        map_storage: impl Fn(sqlx::Error) -> E + Send,
    ) -> Result<T, E>
    where
        S: TenantScopeHandle,
        F: for<'borrow, 'tx> FnOnce(
                IdentityTx<'borrow, 'tx, ServingReadLane>,
            ) -> BoxFuture<'borrow, Result<T, E>>
            + Send,
        E: Send,
        T: Send,
    {
        self.repeatable_read_map(scope, move |tx| read(IdentityTx { tx }), map_storage)
            .await
    }
}

#[cfg(feature = "domain-identity")]
impl TenantDb<ServingWriteLane> {
    #[cfg(all(test, feature = "integration"))]
    pub(crate) async fn identity_write_attempt<S, T, F, E>(
        &self,
        scope: S,
        write: F,
        map_storage: impl Fn(sqlx::Error) -> E + Send,
    ) -> LocalTxAttempt<T, E>
    where
        S: TenantScopeHandle,
        F: for<'borrow, 'tx> FnOnce(
                IdentityTx<'borrow, 'tx, ServingWriteLane>,
            ) -> BoxFuture<'borrow, Result<T, E>>
            + Send,
        E: std::error::Error + Send + Sync + 'static,
        T: Send,
    {
        self.write_attempt(scope, move |tx| write(IdentityTx { tx }), map_storage)
            .await
    }

    /// Execute the authenticated ACK/report mutation and its generated public receipt in one
    /// tenant transaction. The event is produced by the business body only after the immutable
    /// internal receipt has been classified at database transaction time.
    pub(crate) async fn identity_device_ingress_attempt<S, T, F, E>(
        &self,
        scope: S,
        write: F,
        map_storage: impl Fn(sqlx::Error) -> E + Send,
    ) -> LocalTxAttempt<T, E>
    where
        S: TenantScopeHandle,
        F: for<'borrow, 'tx> FnOnce(
                IdentityTx<'borrow, 'tx, ServingWriteLane>,
            )
                -> BoxFuture<'borrow, Result<DeviceIngressTxOutcome<T>, E>>
            + Send
            + 'static,
        E: super::MapOutboxAppendError + std::error::Error + Send + Sync + 'static,
        T: Send,
    {
        let projection_registry = self.projection_registry();
        self.write_attempt(
            scope,
            move |tx| {
                Box::pin(async move {
                    let outcome = write(IdentityTx { tx: &mut *tx }).await?;
                    let DeviceIngressTxOutcome { value, fact } = outcome;
                    if fact.tenant() != tx.tenant() {
                        return Err(E::from_outbox_append(
                            crate::outbox::OutboxAppendError::InvalidIdentity,
                        ));
                    }
                    let (entry, env) = fact.into_parts();
                    {
                        let mut outbox = super::eventing::EventingTx::<
                            ServingWriteLane,
                            super::eventing::OutboxConcern,
                        >::from_raw(tx);
                        let _append = crate::outbox::append_outbox_with_projection(
                            &mut outbox,
                            &entry,
                            &env,
                            &projection_registry,
                        )
                        .await
                        .map_err(E::from_outbox_append)?;
                    }
                    #[cfg(all(test, feature = "integration"))]
                    if super::test_failure_after_outbox_append_requested(tx).await {
                        return Err(E::from_outbox_append(
                            crate::outbox::OutboxAppendError::Storage(sqlx::Error::Protocol(
                                "injected failure after device ingress outbox append".to_owned(),
                            )),
                        ));
                    }
                    Ok(value)
                })
            },
            map_storage,
        )
        .await
    }

    pub(crate) async fn identity_write<S, T, F, E>(
        &self,
        scope: S,
        write: F,
        map_storage: impl Fn(sqlx::Error) -> E + Send,
    ) -> Result<T, E>
    where
        S: TenantScopeHandle,
        F: for<'borrow, 'tx> FnOnce(
                IdentityTx<'borrow, 'tx, ServingWriteLane>,
            ) -> BoxFuture<'borrow, Result<T, E>>
            + Send,
        E: std::error::Error + Send + Sync + 'static,
        T: Send,
    {
        self.write(scope, move |tx| write(IdentityTx { tx }), map_storage)
            .await
    }

    pub(crate) async fn identity_producer_tx<S, A, T, F, E>(
        &self,
        scope: S,
        entry: &consistency::EventEntry,
        env: &crate::outbox::OutboxEnvelope,
        write: F,
        map_storage: impl Fn(sqlx::Error) -> E + Send + Sync,
    ) -> ProducerTxAttempt<T, E>
    where
        S: TenantScopeHandle,
        F: for<'borrow, 'tx> FnOnce(
                IdentityTx<'borrow, 'tx, ServingWriteLane>,
            )
                -> BoxFuture<'borrow, Result<ProducerTxOutcome<A, T>, E>>
            + Send,
        E: MapOutboxAppendError + std::error::Error + Send + Sync + 'static,
        A: ProducerFactAuthorization,
        T: Send + 'static,
    {
        self.producer_tx(
            scope,
            entry,
            env,
            move |tx| write(IdentityTx { tx }),
            map_storage,
        )
        .await
    }
}

#[cfg(feature = "domain-settings")]
impl TenantDb<ServingReadLane> {
    pub(crate) async fn secret_read<S, T, F>(&self, scope: S, read: F) -> Result<T, sqlx::Error>
    where
        S: TenantScopeHandle,
        F: for<'borrow, 'tx> FnOnce(
                SecretTx<'borrow, 'tx, ServingReadLane>,
            ) -> BoxFuture<'borrow, Result<T, sqlx::Error>>
            + Send,
        T: Send,
    {
        self.read(scope, move |tx| read(SecretTx { tx })).await
    }
}

#[cfg(feature = "domain-settings")]
impl TenantDb<ServingWriteLane> {
    pub(crate) async fn secret_write<S, T, F, E>(
        &self,
        scope: S,
        write: F,
        map_storage: impl Fn(sqlx::Error) -> E + Send,
    ) -> Result<T, E>
    where
        S: TenantScopeHandle,
        F: for<'borrow, 'tx> FnOnce(
                SecretTx<'borrow, 'tx, ServingWriteLane>,
            ) -> BoxFuture<'borrow, Result<T, E>>
            + Send,
        E: std::error::Error + Send + Sync + 'static,
        T: Send,
    {
        self.write(scope, move |tx| write(SecretTx { tx }), map_storage)
            .await
    }

    pub(crate) async fn retry_secret_write<S, T, F, E>(
        &self,
        scope: S,
        deadline: LocalTxDeadline,
        write: F,
        map_storage: impl Fn(sqlx::Error) -> E + Send,
    ) -> LocalTxAttempt<T, E>
    where
        S: TenantScopeHandle,
        F: for<'borrow, 'tx> FnOnce(
                SecretTx<'borrow, 'tx, ServingWriteLane>,
            ) -> BoxFuture<'borrow, Result<T, E>>
            + Send,
        E: std::error::Error + Send + Sync + 'static,
        T: Send,
    {
        self.retry_write(
            scope,
            deadline,
            move |tx| write(SecretTx { tx }),
            map_storage,
        )
        .await
    }
}

impl TenantDb<ServingWriteLane> {
    pub(crate) async fn revocation_write<S, T, F, E>(
        &self,
        scope: S,
        write: F,
        map_storage: impl Fn(sqlx::Error) -> E + Send,
    ) -> Result<T, E>
    where
        S: TenantScopeHandle,
        F: for<'borrow, 'tx> FnOnce(RevocationTx<'borrow, 'tx>) -> BoxFuture<'borrow, Result<T, E>>
            + Send,
        E: std::error::Error + Send + Sync + 'static,
        T: Send,
    {
        self.write(scope, move |tx| write(RevocationTx { tx }), map_storage)
            .await
    }

    pub(crate) async fn revocation_receipt_read<S, T, F, E>(
        &self,
        receipt: &crate::revocation::RevocationCapabilityReceipt,
        scope: S,
        read: F,
        map_storage: impl Fn(sqlx::Error) -> E + Send,
    ) -> Result<T, E>
    where
        S: TenantScopeHandle,
        F: for<'borrow, 'tx> FnOnce(RevocationTx<'borrow, 'tx>) -> BoxFuture<'borrow, Result<T, E>>
            + Send,
        E: std::error::Error + Send + Sync + 'static,
        T: Send,
    {
        self.revocation_read(
            receipt,
            scope,
            move |tx| read(RevocationTx { tx }),
            map_storage,
        )
        .await
    }
}

impl RevocationWrite<'_, '_> {
    pub(crate) async fn revoke_certificate(
        &mut self,
        scope: diport::CertScope,
        serial: diport::CertSerial,
        not_after: diport::CertNotAfter,
    ) -> Result<(), diport::RevocationStoreError> {
        if scope.tenant() != self.tx.tenant {
            return Err(crate::revocation::operation_error(
                crate::revocation::RevocationOperationError::EvidenceMissing,
            ));
        }
        let tenant = self.tx.tenant.to_string();
        let device = scope.device().as_uuid().to_string();
        let serial = serial.as_bytes().to_vec();
        let not_after = not_after.unix_seconds();
        let active: bool =
            sqlx::query_scalar("SELECT pg_catalog.to_timestamp($1) > pg_catalog.clock_timestamp()")
                .bind(not_after)
                .fetch_one(&mut *self.tx.conn)
                .await
                .map_err(crate::revocation::storage_error)?;
        if !active {
            return Err(crate::revocation::operation_error(
                crate::revocation::RevocationOperationError::CertificateExpired,
            ));
        }
        sqlx::query(
            r#"
            INSERT INTO public.certificate_revocations
                (tenant_id, device_id, serial, not_after)
            VALUES ($1::uuid, $2::uuid, $3, pg_catalog.to_timestamp($4))
            ON CONFLICT (tenant_id, device_id, serial) DO NOTHING
            "#,
        )
        .bind(&tenant)
        .bind(&device)
        .bind(&serial)
        .bind(not_after)
        .execute(&mut *self.tx.conn)
        .await
        .map_err(crate::revocation::storage_error)?;
        let same_expiry: Option<bool> = sqlx::query_scalar(
            r#"
            SELECT not_after = pg_catalog.to_timestamp($4)
            FROM public.certificate_revocations
            WHERE tenant_id = $1::uuid AND device_id = $2::uuid AND serial = $3
            "#,
        )
        .bind(tenant)
        .bind(device)
        .bind(serial)
        .bind(not_after)
        .fetch_optional(&mut *self.tx.conn)
        .await
        .map_err(crate::revocation::storage_error)?;
        match same_expiry {
            Some(true) => Ok(()),
            Some(false) => Err(crate::revocation::operation_error(
                crate::revocation::RevocationOperationError::ExpiryConflict,
            )),
            None => Err(crate::revocation::operation_error(
                crate::revocation::RevocationOperationError::EvidenceMissing,
            )),
        }
    }

    pub(crate) async fn is_certificate_revoked(
        &mut self,
        scope: diport::CertScope,
        serial: diport::CertSerial,
    ) -> Result<bool, diport::RevocationStoreError> {
        if scope.tenant() != self.tx.tenant {
            return Err(crate::revocation::operation_error(
                crate::revocation::RevocationOperationError::ScopeMismatch,
            ));
        }
        let revoked: Option<bool> = sqlx::query_scalar(
            r#"
            SELECT true FROM public.certificate_revocations
            WHERE tenant_id = $1::uuid AND device_id = $2::uuid AND serial = $3
              AND not_after > pg_catalog.clock_timestamp()
            "#,
        )
        .bind(self.tx.tenant.to_string())
        .bind(scope.device().as_uuid().to_string())
        .bind(serial.as_bytes() as &[u8])
        .fetch_optional(&mut *self.tx.conn)
        .await
        .map_err(crate::revocation::storage_error)?;
        Ok(revoked.unwrap_or(false))
    }
}

#[cfg(feature = "domain-settings")]
impl<'borrow, 'tx> SecretTx<'borrow, 'tx, ServingReadLane> {
    pub(crate) fn secrets(&mut self) -> SecretRead<'_, 'tx> {
        SecretRead { tx: self.tx }
    }
}

#[cfg(feature = "domain-settings")]
impl<'borrow, 'tx> SecretTx<'borrow, 'tx, ServingWriteLane> {
    pub(crate) fn secrets(&mut self) -> SecretWrite<'_, 'tx> {
        SecretWrite { tx: self.tx }
    }
}

#[cfg(feature = "domain-settings")]
impl SecretRead<'_, '_> {
    pub(crate) async fn find(
        &mut self,
        key: &settings::ports::SecretKey,
    ) -> Result<Option<crate::secret_repo::SecretRow>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT secret_key, store_id, ref_key, ref_version, version, deleted
            FROM secret_refs
            WHERE tenant_id = $1::uuid AND secret_key = $2
            ORDER BY version DESC LIMIT 1
            "#,
        )
        .bind(self.tx.tenant.to_string())
        .bind(key.as_str())
        .fetch_optional(&mut *self.tx.conn)
        .await
    }

    pub(crate) async fn find_version(
        &mut self,
        key: &settings::ports::SecretKey,
        version: u64,
    ) -> Result<Option<crate::secret_repo::SecretRow>, sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT secret_key, store_id, ref_key, ref_version, version, deleted
            FROM secret_refs
            WHERE tenant_id = $1::uuid AND secret_key = $2 AND version = $3
            "#,
        )
        .bind(self.tx.tenant.to_string())
        .bind(key.as_str())
        .bind(i64::try_from(version).unwrap_or(i64::MAX))
        .fetch_optional(&mut *self.tx.conn)
        .await
    }

    pub(crate) async fn latest_version(
        &mut self,
        key: &settings::ports::SecretKey,
    ) -> Result<Option<i64>, sqlx::Error> {
        sqlx::query_scalar(
            "SELECT max(version) FROM secret_refs \
             WHERE tenant_id = $1::uuid AND secret_key = $2",
        )
        .bind(self.tx.tenant.to_string())
        .bind(key.as_str())
        .fetch_one(&mut *self.tx.conn)
        .await
    }
}

#[cfg(feature = "domain-settings")]
impl<'borrow, 'tx> SecretWrite<'borrow, 'tx> {
    pub(crate) async fn lock_key(
        self,
        key: &settings::ports::SecretKey,
    ) -> Result<LockedSecretKey<'borrow, 'tx>, settings::ports::SecretRepoError> {
        #[cfg(all(test, feature = "integration"))]
        crate::secret_repo::wait_at_secret_key_lock_rendezvous(key.as_str()).await;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1 || chr(31) || $2, 0))")
            .bind(self.tx.tenant.to_string())
            .bind(key.as_str())
            .execute(&mut *self.tx.conn)
            .await
            .map_err(|error| settings::ports::SecretRepoError::Storage(Box::new(error)))?;
        Ok(LockedSecretKey {
            tx: self.tx,
            key: key.clone(),
        })
    }
}

#[cfg(feature = "domain-settings")]
impl LockedSecretKey<'_, '_> {
    pub(crate) async fn cas_insert(
        self,
        entry: &settings::ports::SecretEntry,
    ) -> Result<(), settings::ports::SecretRepoError> {
        if entry.tenant() != self.tx.tenant || entry.key() != &self.key {
            return Err(settings::ports::SecretRepoError::Storage(Box::new(
                std::io::Error::other("locked secret coordinate does not match entry"),
            )));
        }
        let result = sqlx::query(
            r#"
            INSERT INTO secret_refs
                (tenant_id, secret_key, version, store_id, ref_key, ref_version)
            SELECT $1::uuid, $2, $3, $4, $5, $6
            WHERE $3 = 1 + COALESCE(
                (SELECT max(version) FROM secret_refs
                 WHERE tenant_id = $1::uuid AND secret_key = $2), 0)
            "#,
        )
        .bind(self.tx.tenant.to_string())
        .bind(self.key.as_str())
        .bind(i64::try_from(entry.version()).unwrap_or(i64::MAX))
        .bind(entry.secret_ref().store_id().as_str())
        .bind(entry.secret_ref().ref_key())
        .bind(entry.secret_ref().ref_version())
        .execute(&mut *self.tx.conn)
        .await;
        match result {
            Ok(done) if done.rows_affected() == 1 => Ok(()),
            Ok(_) => Err(settings::ports::SecretRepoError::VersionConflict),
            Err(error)
                if error
                    .as_database_error()
                    .is_some_and(|database| database.is_unique_violation()) =>
            {
                Err(settings::ports::SecretRepoError::VersionConflict)
            }
            Err(error) => Err(settings::ports::SecretRepoError::Storage(Box::new(error))),
        }
    }

    pub(crate) async fn append_tombstone(self) -> Result<(), settings::ports::SecretRepoError> {
        sqlx::query(
            r#"
            INSERT INTO secret_refs
                (tenant_id, secret_key, version, store_id, ref_key, ref_version, deleted)
            SELECT $1::uuid, $2, 1 + COALESCE(max(version), 0), '', '', NULL, true
            FROM secret_refs
            WHERE tenant_id = $1::uuid AND secret_key = $2
            HAVING NOT COALESCE(
                (SELECT deleted FROM secret_refs
                 WHERE tenant_id = $1::uuid AND secret_key = $2
                 ORDER BY version DESC LIMIT 1), true)
            "#,
        )
        .bind(self.tx.tenant.to_string())
        .bind(self.key.as_str())
        .execute(&mut *self.tx.conn)
        .await
        .map(|_| ())
        .map_err(|error| settings::ports::SecretRepoError::Storage(Box::new(error)))
    }
}

#[cfg(feature = "domain-identity")]
impl IdentityRead<'_, '_> {
    pub(crate) fn device_commands(&mut self) -> crate::device_command::DeviceCommandReadTx<'_> {
        crate::device_command::DeviceCommandReadTx::new(&mut *self.tx.conn)
    }
}

#[cfg(feature = "domain-identity")]
impl IdentityRead<'_, '_> {
    pub(crate) fn device_ingress_readback(
        &mut self,
    ) -> crate::device_command::DeviceIngressReadbackTx<'_> {
        crate::device_command::DeviceIngressReadbackTx::new(&mut *self.tx.conn)
    }

    pub(crate) fn device_certificates(
        &mut self,
    ) -> crate::device_certificate::DeviceCertificateReadTx<'_> {
        crate::device_certificate::DeviceCertificateReadTx::new(&mut *self.tx.conn)
    }

    pub(crate) async fn account_security_row(
        &mut self,
        user_id: &ids::UserId,
    ) -> Result<Option<crate::account_security_repo::SecurityRow>, sqlx::Error> {
        sqlx::query_as::<_, crate::account_security_repo::SecurityRow>(
            r#"
            SELECT status,
                   authn_epoch,
                   version,
                   (extract(epoch from status_changed_at) * 1000000)::bigint
                       AS status_changed_at_micros,
                   (extract(epoch from updated_at) * 1000000)::bigint AS updated_at_micros
            FROM account_security_states
            WHERE tenant_id = $1::uuid AND user_id = $2::uuid
            "#,
        )
        .bind(self.tx.tenant.to_string())
        .bind(user_id.as_uuid().to_string())
        .fetch_optional(&mut *self.tx.conn)
        .await
    }

    pub(crate) async fn auth_grant_validation_row(
        &mut self,
        grant_id: &authn::AuthGrantId,
        user_id: &ids::UserId,
    ) -> Result<Option<crate::auth_grant_validator::ValidationRow>, sqlx::Error> {
        sqlx::query_as::<_, crate::auth_grant_validator::ValidationRow>(
            r#"
            SELECT g.user_id = $3::uuid AS grant_user_matches,
                   extract(epoch from g.auth_time)::bigint AS grant_auth_time,
                   g.authn_epoch_at_issue AS grant_epoch,
                   g.status AS grant_status,
                   extract(epoch from g.expires_at)::bigint AS grant_expires_at,
                   s.user_id = $3::uuid AS account_user_matches,
                   s.status AS account_status,
                   s.authn_epoch AS account_epoch
            FROM auth_grants AS g
            LEFT JOIN account_security_states AS s
              ON s.tenant_id = g.tenant_id
             AND s.user_id = g.user_id
            WHERE g.tenant_id = $1::uuid
              AND g.grant_id = $2
            "#,
        )
        .bind(self.tx.tenant.to_string())
        .bind(grant_id.to_wire())
        .bind(user_id.as_uuid().to_string())
        .fetch_optional(&mut *self.tx.conn)
        .await
    }

    pub(crate) async fn active_auth_grant_row(
        &mut self,
        grant_id: &authn::AuthGrantId,
        observed_at: std::time::SystemTime,
    ) -> Result<Option<crate::auth_grant_lifecycle::AuthGrantRow>, sqlx::Error> {
        sqlx::query_as::<_, crate::auth_grant_lifecycle::AuthGrantRow>(
            r#"
            SELECT user_id::text,
                   extract(epoch from auth_time)::bigint AS auth_time,
                   authn_epoch_at_issue,
                   status,
                   extract(epoch from expires_at)::bigint AS expires_at,
                   extract(epoch from created_at)::bigint AS created_at,
                   extract(epoch from closed_at)::bigint AS closed_at,
                   close_reason
            FROM auth_grants
            WHERE tenant_id = $1::uuid
              AND grant_id = $2
              AND status = 'active'
              AND expires_at > to_timestamp($3)
            "#,
        )
        .bind(self.tx.tenant.to_string())
        .bind(grant_id.to_wire())
        .bind(crate::outbox::unix_secs(observed_at))
        .fetch_optional(&mut *self.tx.conn)
        .await
    }

    pub(crate) async fn refresh_token_by_hash(
        &mut self,
        hash: &::identity::ports::RefreshTokenHash,
    ) -> Result<Option<crate::refresh_token_store::RefreshTokenRow>, sqlx::Error> {
        sqlx::query_as::<_, crate::refresh_token_store::RefreshTokenRow>(
            r#"
            SELECT id::text, auth_grant_id, user_id::text, authn_epoch_at_issue,
                   auth_grant_status, parent_id::text, lineage_id::text, status,
                   extract(epoch from issued_at)::bigint AS issued_at,
                   extract(epoch from expires_at)::bigint AS expires_at
            FROM refresh_tokens
            WHERE tenant_id = $1::uuid AND token_hash = $2
            "#,
        )
        .bind(self.tx.tenant.to_string())
        .bind(hash.as_bytes() as &[u8])
        .fetch_optional(&mut *self.tx.conn)
        .await
    }

    pub(crate) async fn credential_by_user(
        &mut self,
        user_id: &ids::UserId,
    ) -> Result<Option<(String, String, i64)>, sqlx::Error> {
        use sqlx::Row;

        let row = sqlx::query(
            "SELECT login, password_hash, version FROM credentials \
             WHERE tenant_id = $1::uuid AND user_id = $2::uuid",
        )
        .bind(self.tx.tenant.to_string())
        .bind(user_id.as_uuid().to_string())
        .fetch_optional(&mut *self.tx.conn)
        .await?;
        row.map(|row| {
            Ok((
                row.try_get("login")?,
                row.try_get("password_hash")?,
                row.try_get("version")?,
            ))
        })
        .transpose()
    }

    pub(crate) async fn role_row(
        &mut self,
        id: &::identity::ports::RoleId,
    ) -> Result<Option<(String, Vec<String>)>, sqlx::Error> {
        use sqlx::Row;

        let row = sqlx::query(
            "SELECT revision.name, revision.permissions \
             FROM roles AS role \
             JOIN LATERAL (SELECT name, permissions FROM role_revisions \
                           WHERE tenant_id = role.tenant_id AND role_id = role.id \
                           ORDER BY version DESC LIMIT 1) AS revision ON true \
             WHERE role.tenant_id = $1::uuid AND role.id = $2",
        )
        .bind(self.tx.tenant.to_string())
        .bind(id.as_str())
        .fetch_optional(&mut *self.tx.conn)
        .await?;
        row.map(|row| Ok((row.try_get("name")?, row.try_get("permissions")?)))
            .transpose()
    }

    pub(crate) async fn role_rows(
        &mut self,
        after: Option<&::identity::ports::RoleId>,
        limit: i64,
    ) -> Result<Vec<(String, String, Vec<String>)>, sqlx::Error> {
        use sqlx::Row;

        let rows = sqlx::query(
            r#"
            SELECT role.id, revision.name, revision.permissions
            FROM roles AS role
            JOIN LATERAL (
                SELECT name, permissions
                FROM role_revisions
                WHERE tenant_id = role.tenant_id AND role_id = role.id
                ORDER BY version DESC
                LIMIT 1
            ) AS revision ON true
            WHERE role.tenant_id = $1::uuid
              AND ($2::text IS NULL OR role.id > $2)
            ORDER BY role.id ASC
            LIMIT $3
            "#,
        )
        .bind(self.tx.tenant.to_string())
        .bind(after.map(|id| id.as_str()))
        .bind(limit)
        .fetch_all(&mut *self.tx.conn)
        .await?;
        rows.into_iter()
            .map(|row| {
                Ok((
                    row.try_get("id")?,
                    row.try_get("name")?,
                    row.try_get("permissions")?,
                ))
            })
            .collect()
    }

    pub(crate) async fn role_binding_rows(
        &mut self,
        subject: &str,
    ) -> Result<Vec<(String, String)>, sqlx::Error> {
        sqlx::query_as(
            "SELECT role_id, subject FROM role_bindings \
             WHERE tenant_id = $1::uuid AND subject = $2 ORDER BY role_id ASC",
        )
        .bind(self.tx.tenant.to_string())
        .bind(subject)
        .fetch_all(&mut *self.tx.conn)
        .await
    }

    pub(crate) async fn policy_row(
        &mut self,
        id: &::identity::ports::PolicyId,
    ) -> Result<Option<crate::policy_repo::RawPolicy>, sqlx::Error> {
        let row = sqlx::query(
            r#"
            SELECT id, version, contract_id, permission,
                   extract(epoch from effective_from)::bigint AS effective_from,
                   extract(epoch from effective_until)::bigint AS effective_until,
                   rules::text AS rules_json
            FROM abac_policies
            WHERE tenant_id = $1::uuid AND id = $2 AND deleted_at IS NULL
            "#,
        )
        .bind(self.tx.tenant.to_string())
        .bind(id.as_str())
        .fetch_optional(&mut *self.tx.conn)
        .await?;
        row.map(crate::policy_repo::row_to_raw).transpose()
    }

    pub(crate) async fn active_policy_rows(
        &mut self,
        after: Option<&::identity::ports::PolicyId>,
        fetch_limit: i64,
    ) -> Result<Vec<crate::policy_repo::RawPolicy>, sqlx::Error> {
        let rows = sqlx::query(
            r#"
            SELECT id, version, contract_id, permission,
                   extract(epoch from effective_from)::bigint AS effective_from,
                   extract(epoch from effective_until)::bigint AS effective_until,
                   rules::text AS rules_json
            FROM abac_policies
            WHERE tenant_id = $1::uuid
              AND ($2::text IS NULL OR id > $2)
              AND deleted_at IS NULL
            ORDER BY id ASC
            LIMIT $3
            "#,
        )
        .bind(self.tx.tenant.to_string())
        .bind(after.map(|id| id.as_str()))
        .bind(fetch_limit)
        .fetch_all(&mut *self.tx.conn)
        .await?;
        rows.into_iter()
            .map(crate::policy_repo::row_to_raw)
            .collect()
    }

    pub(crate) async fn effective_policy_rows(
        &mut self,
        scope: &::identity::ports::PolicyRouteScope,
        at: std::time::SystemTime,
    ) -> Result<Vec<crate::policy_repo::RawPolicy>, sqlx::Error> {
        let rows = sqlx::query(
            r#"
            SELECT id, version, contract_id, permission,
                   extract(epoch from effective_from)::bigint AS effective_from,
                   extract(epoch from effective_until)::bigint AS effective_until,
                   rules::text AS rules_json
            FROM abac_policies
            WHERE tenant_id = $1::uuid
              AND contract_id = $2
              AND permission = $3
              AND effective_from <= to_timestamp($4)
              AND (effective_until IS NULL OR effective_until > to_timestamp($4))
              AND deleted_at IS NULL
            ORDER BY id ASC
            "#,
        )
        .bind(self.tx.tenant.to_string())
        .bind(scope.contract_id())
        .bind(scope.permission().as_str())
        .bind(crate::outbox::unix_secs(at))
        .fetch_all(&mut *self.tx.conn)
        .await?;
        rows.into_iter()
            .map(crate::policy_repo::row_to_raw)
            .collect()
    }

    pub(crate) async fn resource_security_fact_rows(
        &mut self,
        device: ::ids::DeviceId,
        required_keys: &[::identity::ports::ResourceSecurityFactKey],
    ) -> Result<Vec<crate::resource_security_fact_repo::RawResourceSecurityFact>, sqlx::Error> {
        let keys = required_keys
            .iter()
            .map(|key| key.as_str())
            .collect::<Vec<_>>();
        let rows = sqlx::query(
            r#"
            SELECT DISTINCT ON (fact_key)
                   fact_key, revision, source_id, owner_principal_id, risk_class,
                   (extract(epoch from observed_at) * 1000000)::bigint AS observed_at_micros,
                   (extract(epoch from expires_at) * 1000000)::bigint AS expires_at_micros
            FROM resource_security_fact_revisions
            WHERE tenant_id = $1::uuid AND device_id = $2::uuid
              AND fact_key = ANY($3::text[])
            ORDER BY fact_key, revision DESC
            "#,
        )
        .bind(self.tx.tenant.to_string())
        .bind(device.as_uuid().to_string())
        .bind(keys)
        .fetch_all(&mut *self.tx.conn)
        .await?;
        rows.into_iter()
            .map(crate::resource_security_fact_repo::row_to_raw)
            .collect()
    }
}

#[cfg(feature = "domain-identity")]
impl IdentityWrite<'_, '_> {
    pub(crate) fn device_commands(&mut self) -> crate::device_command::DeviceCommandWriteTx<'_> {
        crate::device_command::DeviceCommandWriteTx::new(&mut *self.tx.conn)
    }
}

#[cfg(feature = "domain-identity")]
impl IdentityWrite<'_, '_> {
    pub(crate) fn device_certificates(
        &mut self,
    ) -> crate::device_certificate::DeviceCertificateWriteTx<'_> {
        crate::device_certificate::DeviceCertificateWriteTx::new(&mut *self.tx.conn)
    }

    pub(crate) fn device_policy(&mut self) -> crate::device_certificate::DevicePolicyTx<'_> {
        crate::device_certificate::DevicePolicyTx::new(&mut *self.tx.conn)
    }

    #[cfg(all(test, feature = "integration"))]
    pub(crate) async fn force_identity_outbox_failure(
        &mut self,
        fault: IdentityOutboxFault,
    ) -> Result<(), sqlx::Error> {
        let name = match fault {
            IdentityOutboxFault::RefreshSecurity => "refresh_security_outbox_fault",
            IdentityOutboxFault::CredentialSecurity => "credential_security_outbox_fault",
        };
        let statement =
            format!("ALTER TABLE public.outbox ADD CONSTRAINT {name} CHECK (false) NOT VALID");
        sqlx::query(&statement)
            .execute(&mut *self.tx.conn)
            .await
            .map(|_| ())
    }

    pub(crate) async fn lock_refresh_account(
        &mut self,
        user_id: &ids::UserId,
    ) -> Result<Option<(String, i64)>, ::identity::ports::IdentityError> {
        sqlx::query_as(
            "SELECT status, authn_epoch FROM account_security_states \
             WHERE tenant_id = $1::uuid AND user_id = $2::uuid FOR UPDATE",
        )
        .bind(self.tx.tenant.to_string())
        .bind(user_id.as_uuid().to_string())
        .fetch_optional(&mut *self.tx.conn)
        .await
        .map_err(crate::tx_retry::identity_storage_error)
    }

    pub(crate) async fn lock_refresh_family(
        &mut self,
        grant_id: &authn::AuthGrantId,
    ) -> Result<
        Vec<crate::identity_security_lifecycle::LockedRefreshRow>,
        ::identity::ports::IdentityError,
    > {
        let rows = sqlx::query(
            "SELECT id::text, user_id::text, authn_epoch_at_issue, auth_grant_status, \
                    token_hash, parent_id::text, lineage_id::text, status, \
                    (extract(epoch from issued_at) * 1000000)::bigint AS issued_at_micros, \
                    (extract(epoch from expires_at) * 1000000)::bigint AS expires_at_micros \
             FROM refresh_tokens WHERE tenant_id = $1::uuid AND auth_grant_id = $2 \
             ORDER BY id FOR UPDATE",
        )
        .bind(self.tx.tenant.to_string())
        .bind(grant_id.to_wire())
        .fetch_all(&mut *self.tx.conn)
        .await
        .map_err(crate::tx_retry::identity_storage_error)?;
        rows.into_iter()
            .map(crate::identity_security_lifecycle::LockedRefreshRow::from_row)
            .collect()
    }

    pub(crate) async fn lock_refresh_grant(
        &mut self,
        grant_id: &authn::AuthGrantId,
    ) -> Result<
        Option<crate::identity_security_lifecycle::LockedGrantRow>,
        ::identity::ports::IdentityError,
    > {
        use sqlx::Row;

        let row = sqlx::query(
            "SELECT user_id::text, authn_epoch_at_issue, status, \
                    (extract(epoch from expires_at) * 1000000)::bigint AS expires_at_micros \
             FROM auth_grants WHERE tenant_id = $1::uuid AND grant_id = $2 FOR UPDATE",
        )
        .bind(self.tx.tenant.to_string())
        .bind(grant_id.to_wire())
        .fetch_optional(&mut *self.tx.conn)
        .await
        .map_err(crate::tx_retry::identity_storage_error)?;
        row.map(|row| {
            Ok(crate::identity_security_lifecycle::LockedGrantRow {
                user: row
                    .try_get("user_id")
                    .map_err(crate::tx_retry::identity_storage_error)?,
                epoch: row
                    .try_get("authn_epoch_at_issue")
                    .map_err(crate::tx_retry::identity_storage_error)?,
                status: row
                    .try_get("status")
                    .map_err(crate::tx_retry::identity_storage_error)?,
                expires_at_micros: row
                    .try_get("expires_at_micros")
                    .map_err(crate::tx_retry::identity_storage_error)?,
            })
        })
        .transpose()
    }

    pub(crate) async fn database_now_micros(
        &mut self,
    ) -> Result<i64, ::identity::ports::IdentityError> {
        sqlx::query_scalar("SELECT (extract(epoch from clock_timestamp()) * 1000000)::bigint")
            .fetch_one(&mut *self.tx.conn)
            .await
            .map_err(crate::tx_retry::identity_storage_error)
    }

    pub(crate) async fn consume_active_refresh(
        &mut self,
        id: &::identity::ports::RefreshTokenId,
    ) -> Result<u64, ::identity::ports::IdentityError> {
        sqlx::query(
            "UPDATE refresh_tokens SET status = 'consumed' \
             WHERE tenant_id = $1::uuid AND id = $2::uuid AND status = 'active'",
        )
        .bind(self.tx.tenant.to_string())
        .bind(id.as_str())
        .execute(&mut *self.tx.conn)
        .await
        .map(|done| done.rows_affected())
        .map_err(crate::tx_retry::identity_storage_error)
    }

    pub(crate) async fn revoke_exact_refresh_family(
        &mut self,
        grant_id: &authn::AuthGrantId,
    ) -> Result<u64, ::identity::ports::IdentityError> {
        sqlx::query(
            "UPDATE refresh_tokens SET status = 'revoked' \
             WHERE tenant_id = $1::uuid AND auth_grant_id = $2 AND status <> 'revoked'",
        )
        .bind(self.tx.tenant.to_string())
        .bind(grant_id.to_wire())
        .execute(&mut *self.tx.conn)
        .await
        .map(|done| done.rows_affected())
        .map_err(crate::tx_retry::identity_storage_error)
    }

    pub(crate) async fn mark_refresh_grant_compromised(
        &mut self,
        grant_id: &authn::AuthGrantId,
        database_now_micros: i64,
    ) -> Result<u64, ::identity::ports::IdentityError> {
        sqlx::query(
            "UPDATE auth_grants SET status = 'compromised', \
                 closed_at = TIMESTAMPTZ 'epoch' + $3 * INTERVAL '1 microsecond', \
                 close_reason = 'refresh_reuse_detected' \
             WHERE tenant_id = $1::uuid AND grant_id = $2 \
               AND status IN ('active', 'revoked')",
        )
        .bind(self.tx.tenant.to_string())
        .bind(grant_id.to_wire())
        .bind(database_now_micros)
        .execute(&mut *self.tx.conn)
        .await
        .map(|done| done.rows_affected())
        .map_err(crate::tx_retry::identity_storage_error)
    }

    pub(crate) async fn insert_rotated_refresh(
        &mut self,
        record: &::identity::ports::RefreshTokenRecord,
    ) -> Result<(), ::identity::ports::IdentityError> {
        if record.tenant() != self.tx.tenant {
            return Err(::identity::ports::IdentityError::Storage(Box::new(
                std::io::Error::other("rotated refresh tenant does not match transaction"),
            )));
        }
        let epoch = i64::try_from(record.issuance_epoch().get()).map_err(|_| {
            ::identity::ports::IdentityError::Storage(Box::new(std::io::Error::other(
                "refresh child epoch exceeds bigint",
            )))
        })?;
        sqlx::query(
            "INSERT INTO refresh_tokens \
             (id, tenant_id, auth_grant_id, user_id, authn_epoch_at_issue, \
              auth_grant_status, token_hash, parent_id, lineage_id, status, issued_at, expires_at) \
             VALUES ($1::uuid, $2::uuid, $3, $4::uuid, $5, $6, $7, $8::uuid, $9::uuid, $10, \
                     to_timestamp($11), to_timestamp($12))",
        )
        .bind(record.id().as_str())
        .bind(self.tx.tenant.to_string())
        .bind(record.auth_grant_id().to_wire())
        .bind(record.user_id().as_uuid().to_string())
        .bind(epoch)
        .bind(record.auth_grant_status().as_db_str())
        .bind(record.token_hash().as_bytes() as &[u8])
        .bind(record.parent_id().map(|id| id.as_str()))
        .bind(record.lineage_id().as_str())
        .bind(record.status().as_db_str())
        .bind(crate::outbox::unix_secs(record.issued_at()))
        .bind(crate::outbox::unix_secs(record.expires_at()))
        .execute(&mut *self.tx.conn)
        .await
        .map(|_| ())
        .map_err(crate::tx_retry::identity_storage_error)
    }

    pub(crate) async fn apply_credential_cas(
        &mut self,
        row: &crate::identity_security_lifecycle::CredentialCasRow,
    ) -> Result<bool, ::identity::ports::IdentityError> {
        if row.tenant != self.tx.tenant {
            return Err(::identity::ports::IdentityError::Storage(Box::new(
                std::io::Error::other("credential CAS tenant does not match transaction"),
            )));
        }
        sqlx::query(
            r#"
            UPDATE credentials SET password_hash = $5, version = $6
            WHERE tenant_id = $1::uuid AND user_id = $2::uuid AND login = $3
              AND password_hash = $4 AND version = $7
            "#,
        )
        .bind(self.tx.tenant.to_string())
        .bind(&row.user)
        .bind(&row.login)
        .bind(&row.expected_hash)
        .bind(&row.next_hash)
        .bind(row.next_version)
        .bind(row.expected_version)
        .execute(&mut *self.tx.conn)
        .await
        .map(|done| done.rows_affected() == 1)
        .map_err(crate::tx_retry::identity_storage_error)
    }

    pub(crate) async fn apply_account_state_cas(
        &mut self,
        row: &crate::identity_security_lifecycle::AccountStateCasRow,
    ) -> Result<bool, ::identity::ports::IdentityError> {
        if row.tenant != self.tx.tenant {
            return Err(::identity::ports::IdentityError::Storage(Box::new(
                std::io::Error::other("account-state CAS tenant does not match transaction"),
            )));
        }
        sqlx::query(
            r#"
            UPDATE account_security_states
            SET status = $3, authn_epoch = $4, version = $5,
                status_changed_at = TIMESTAMPTZ 'epoch' + $6 * INTERVAL '1 microsecond',
                updated_at = TIMESTAMPTZ 'epoch' + $7 * INTERVAL '1 microsecond'
            WHERE tenant_id = $1::uuid AND user_id = $2::uuid AND status = $8
              AND authn_epoch = $9 AND version = $10
              AND status_changed_at = TIMESTAMPTZ 'epoch' + $11 * INTERVAL '1 microsecond'
              AND updated_at = TIMESTAMPTZ 'epoch' + $12 * INTERVAL '1 microsecond'
            "#,
        )
        .bind(self.tx.tenant.to_string())
        .bind(&row.user)
        .bind(row.next_status)
        .bind(row.next_epoch)
        .bind(row.next_version)
        .bind(row.status_changed_at_micros)
        .bind(row.updated_at_micros)
        .bind(row.expected_status)
        .bind(row.expected_epoch)
        .bind(row.expected_version)
        .bind(row.expected_status_changed_at_micros)
        .bind(row.expected_updated_at_micros)
        .execute(&mut *self.tx.conn)
        .await
        .map(|done| done.rows_affected() == 1)
        .map_err(crate::tx_retry::identity_storage_error)
    }

    pub(crate) async fn revoke_refresh_families_for_account(
        &mut self,
        state: &crate::identity_security_lifecycle::AccountStateCasRow,
    ) -> Result<(), ::identity::ports::IdentityError> {
        if state.tenant != self.tx.tenant {
            return Err(::identity::ports::IdentityError::Storage(Box::new(
                std::io::Error::other("refresh revocation tenant does not match transaction"),
            )));
        }
        let tenant = self.tx.tenant.to_string();
        sqlx::query(
            "SELECT refresh.id FROM refresh_tokens AS refresh \
             WHERE refresh.tenant_id = $1::uuid AND refresh.user_id = $2::uuid \
             ORDER BY refresh.auth_grant_id, refresh.id FOR UPDATE",
        )
        .bind(&tenant)
        .bind(&state.user)
        .fetch_all(&mut *self.tx.conn)
        .await
        .map_err(crate::tx_retry::identity_storage_error)?;
        sqlx::query(
            r#"
            UPDATE refresh_tokens AS refresh SET status = 'revoked'
            FROM auth_grants AS root
            WHERE root.tenant_id = $1::uuid AND root.user_id = $2::uuid
              AND root.status = 'active' AND refresh.tenant_id = root.tenant_id
              AND refresh.auth_grant_id = root.grant_id AND refresh.user_id = root.user_id
              AND refresh.authn_epoch_at_issue = root.authn_epoch_at_issue
              AND refresh.auth_grant_status = root.status AND refresh.status <> 'revoked'
            "#,
        )
        .bind(&tenant)
        .bind(&state.user)
        .execute(&mut *self.tx.conn)
        .await
        .map(|_| ())
        .map_err(crate::tx_retry::identity_storage_error)
    }

    pub(crate) async fn revoke_auth_grants_for_account(
        &mut self,
        row: &crate::identity_security_lifecycle::AccountSecurityRow,
    ) -> Result<(), ::identity::ports::IdentityError> {
        if row.state.tenant != self.tx.tenant {
            return Err(::identity::ports::IdentityError::Storage(Box::new(
                std::io::Error::other("grant revocation tenant does not match transaction"),
            )));
        }
        let tenant = self.tx.tenant.to_string();
        sqlx::query(
            "SELECT grant_id FROM auth_grants \
             WHERE tenant_id = $1::uuid AND user_id = $2::uuid AND status = 'active' \
             ORDER BY grant_id FOR UPDATE",
        )
        .bind(&tenant)
        .bind(&row.state.user)
        .fetch_all(&mut *self.tx.conn)
        .await
        .map_err(crate::tx_retry::identity_storage_error)?;
        sqlx::query(
            "UPDATE auth_grants SET status = 'revoked', closed_at = to_timestamp($3), \
             close_reason = $4 WHERE tenant_id = $1::uuid AND user_id = $2::uuid \
             AND status = 'active'",
        )
        .bind(&tenant)
        .bind(&row.state.user)
        .bind(row.occurred_at)
        .bind(row.reason)
        .execute(&mut *self.tx.conn)
        .await
        .map(|_| ())
        .map_err(crate::tx_retry::identity_storage_error)
    }

    pub(crate) async fn create_policy(
        &mut self,
        policy: &::identity::ports::Policy,
        rules_json: &str,
    ) -> Result<u64, ::identity::ports::IdentityError> {
        if policy.tenant() != self.tx.tenant {
            return Err(::identity::ports::IdentityError::InvalidPolicy);
        }
        let version = i32::try_from(policy.version().get())
            .map_err(|error| ::identity::ports::IdentityError::Storage(Box::new(error)))?;
        sqlx::query(
            r#"
            INSERT INTO abac_policies
                (tenant_id, id, version, contract_id, permission,
                 effective_from, effective_until, rules)
            VALUES ($1::uuid, $2, $3, $4, $5, to_timestamp($6), to_timestamp($7), $8::jsonb)
            ON CONFLICT (tenant_id, id) DO NOTHING
            "#,
        )
        .bind(self.tx.tenant.to_string())
        .bind(policy.id().as_str())
        .bind(version)
        .bind(policy.route_scope().contract_id())
        .bind(policy.route_scope().permission().as_str())
        .bind(crate::outbox::unix_secs(policy.effective_from()))
        .bind(policy.effective_until().map(crate::outbox::unix_secs))
        .bind(rules_json)
        .execute(&mut *self.tx.conn)
        .await
        .map(|done| done.rows_affected())
        .map_err(crate::tx_retry::identity_storage_error)
    }

    pub(crate) async fn update_policy(
        &mut self,
        policy: &::identity::ports::Policy,
        expected: ::identity::ports::PolicyVersion,
        rules_json: &str,
    ) -> Result<(Option<crate::policy_repo::RawPolicy>, bool), ::identity::ports::IdentityError>
    {
        if policy.tenant() != self.tx.tenant {
            return Err(::identity::ports::IdentityError::InvalidPolicy);
        }
        let expected = i32::try_from(expected.get())
            .map_err(|error| ::identity::ports::IdentityError::Storage(Box::new(error)))?;
        let tenant = self.tx.tenant.to_string();
        let row = sqlx::query(
            r#"
            UPDATE abac_policies
            SET version = version + 1, contract_id = $4, permission = $5,
                effective_from = to_timestamp($6), effective_until = to_timestamp($7),
                rules = $8::jsonb, updated_at = now()
            WHERE tenant_id = $1::uuid AND id = $2 AND version = $3 AND deleted_at IS NULL
            RETURNING id, version, contract_id, permission,
                      extract(epoch from effective_from)::bigint AS effective_from,
                      extract(epoch from effective_until)::bigint AS effective_until,
                      rules::text AS rules_json
            "#,
        )
        .bind(&tenant)
        .bind(policy.id().as_str())
        .bind(expected)
        .bind(policy.route_scope().contract_id())
        .bind(policy.route_scope().permission().as_str())
        .bind(crate::outbox::unix_secs(policy.effective_from()))
        .bind(policy.effective_until().map(crate::outbox::unix_secs))
        .bind(rules_json)
        .fetch_optional(&mut *self.tx.conn)
        .await
        .map_err(crate::tx_retry::identity_storage_error)?;
        let row = row
            .map(crate::policy_repo::row_to_raw)
            .transpose()
            .map_err(crate::tx_retry::identity_storage_error)?;
        let exists = if row.is_none() {
            sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM abac_policies \
                 WHERE tenant_id = $1::uuid AND id = $2 AND deleted_at IS NULL)",
            )
            .bind(&tenant)
            .bind(policy.id().as_str())
            .fetch_one(&mut *self.tx.conn)
            .await
            .map_err(crate::tx_retry::identity_storage_error)?
        } else {
            false
        };
        Ok((row, exists))
    }

    pub(crate) async fn deactivate_policy(
        &mut self,
        id: &::identity::ports::PolicyId,
        expected: ::identity::ports::PolicyVersion,
    ) -> Result<(u64, bool), ::identity::ports::IdentityError> {
        let expected = i32::try_from(expected.get())
            .map_err(|error| ::identity::ports::IdentityError::Storage(Box::new(error)))?;
        let tenant = self.tx.tenant.to_string();
        let rows = sqlx::query(
            r#"
            UPDATE abac_policies
            SET version = version + 1, deleted_at = now(), updated_at = now()
            WHERE tenant_id = $1::uuid AND id = $2 AND version = $3 AND deleted_at IS NULL
            "#,
        )
        .bind(&tenant)
        .bind(id.as_str())
        .bind(expected)
        .execute(&mut *self.tx.conn)
        .await
        .map_err(crate::tx_retry::identity_storage_error)?
        .rows_affected();
        let exists = if rows == 0 {
            sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM abac_policies \
                 WHERE tenant_id = $1::uuid AND id = $2 AND deleted_at IS NULL)",
            )
            .bind(&tenant)
            .bind(id.as_str())
            .fetch_one(&mut *self.tx.conn)
            .await
            .map_err(crate::tx_retry::identity_storage_error)?
        } else {
            false
        };
        Ok((rows, exists))
    }

    pub(crate) async fn clear_credential_lockout(
        &mut self,
        login: &str,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "UPDATE credentials SET failure_count = 0, lockout_window_start = NULL, \
             locked_until = NULL WHERE tenant_id = $1::uuid AND login = $2",
        )
        .bind(self.tx.tenant.to_string())
        .bind(login)
        .execute(&mut *self.tx.conn)
        .await
        .map(|_| ())
    }

    pub(crate) async fn write_credential_lockout(
        &mut self,
        login: &str,
        lockout: &::identity::ports::AccountLockout,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "UPDATE credentials SET failure_count = $3, \
             lockout_window_start = to_timestamp($4), locked_until = to_timestamp($5) \
             WHERE tenant_id = $1::uuid AND login = $2",
        )
        .bind(self.tx.tenant.to_string())
        .bind(login)
        .bind(i64::from(lockout.failure_count()))
        .bind(crate::outbox::unix_secs(lockout.window_start()))
        .bind(lockout.locked_until().map(crate::outbox::unix_secs))
        .execute(&mut *self.tx.conn)
        .await
        .map(|_| ())
    }

    pub(crate) async fn replace_credential_password_hash(
        &mut self,
        login: &str,
        replacement: &secure::PasswordHash,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "UPDATE credentials SET password_hash = $3 \
             WHERE tenant_id = $1::uuid AND login = $2",
        )
        .bind(self.tx.tenant.to_string())
        .bind(login)
        .bind(replacement.as_str())
        .execute(&mut *self.tx.conn)
        .await
        .map(|_| ())
    }

    pub(crate) async fn lock_credential_auth_row(
        &mut self,
        login: &str,
    ) -> Result<Option<crate::credential_repo::AuthRow>, sqlx::Error> {
        use sqlx::Row;

        let row = sqlx::query(
            r#"
            SELECT user_id::text AS user_id, password_hash, failure_count,
                   extract(epoch from lockout_window_start)::bigint AS lockout_window_start,
                   extract(epoch from locked_until)::bigint AS locked_until
            FROM credentials
            WHERE tenant_id = $1::uuid AND login = $2
            FOR UPDATE
            "#,
        )
        .bind(self.tx.tenant.to_string())
        .bind(login)
        .fetch_optional(&mut *self.tx.conn)
        .await?;
        row.map(|row| {
            Ok((
                row.try_get("user_id")?,
                row.try_get("password_hash")?,
                row.try_get("failure_count")?,
                row.try_get("lockout_window_start")?,
                row.try_get("locked_until")?,
            ))
        })
        .transpose()
    }

    pub(crate) async fn lock_account_security_row(
        &mut self,
        user_id: &str,
    ) -> Result<Option<crate::account_security_repo::SecurityRow>, sqlx::Error> {
        sqlx::query_as::<_, crate::account_security_repo::SecurityRow>(
            r#"
            SELECT status, authn_epoch, version,
                   (extract(epoch from status_changed_at) * 1000000)::bigint
                       AS status_changed_at_micros,
                   (extract(epoch from updated_at) * 1000000)::bigint AS updated_at_micros
            FROM account_security_states
            WHERE tenant_id = $1::uuid AND user_id = $2::uuid
            FOR UPDATE
            "#,
        )
        .bind(self.tx.tenant.to_string())
        .bind(user_id)
        .fetch_optional(&mut *self.tx.conn)
        .await
    }

    pub(crate) async fn insert_credential_with_security(
        &mut self,
        credential: &::identity::ports::Credential,
    ) -> Result<(), sqlx::Error> {
        if credential.tenant() != self.tx.tenant {
            return Err(sqlx::Error::Protocol(
                "credential tenant does not match transaction".to_owned(),
            ));
        }
        let tenant = self.tx.tenant.to_string();
        sqlx::query(
            r#"
            INSERT INTO credentials (tenant_id, user_id, login, password_hash, version)
            VALUES ($1::uuid, $2::uuid, $3, $4, $5)
            "#,
        )
        .bind(&tenant)
        .bind(credential.user_id().as_uuid().to_string())
        .bind(credential.login().as_str())
        .bind(credential.password_hash().as_str())
        .bind(i64::from(credential.version()))
        .execute(&mut *self.tx.conn)
        .await?;
        sqlx::query(
            r#"
            INSERT INTO account_security_states (
                tenant_id, user_id, status, authn_epoch, version,
                status_changed_at, updated_at
            ) VALUES ($1::uuid, $2::uuid, 'active', 0, 1, clock_timestamp(), clock_timestamp())
            "#,
        )
        .bind(&tenant)
        .bind(credential.user_id().as_uuid().to_string())
        .execute(&mut *self.tx.conn)
        .await
        .map(|_| ())
    }

    pub(crate) async fn lock_active_login_account(
        &mut self,
        grant: &authn::AuthGrant,
    ) -> Result<bool, sqlx::Error> {
        if grant.tenant() != self.tx.tenant {
            return Err(sqlx::Error::Protocol(
                "auth grant tenant does not match transaction".to_owned(),
            ));
        }
        let expected_epoch = i64::try_from(grant.authn_epoch_at_issue().get())
            .map_err(|_| sqlx::Error::Protocol("auth grant epoch exceeds bigint".to_owned()))?;
        let state: Option<(String, i64)> = sqlx::query_as(
            r#"
            SELECT status, authn_epoch
            FROM account_security_states
            WHERE tenant_id = $1::uuid AND user_id = $2::uuid
            FOR UPDATE
            "#,
        )
        .bind(self.tx.tenant.to_string())
        .bind(grant.user_id().as_uuid().to_string())
        .fetch_optional(&mut *self.tx.conn)
        .await?;
        Ok(matches!(state, Some((status, epoch)) if status == "active" && epoch == expected_epoch))
    }

    pub(crate) async fn insert_auth_grant(
        &mut self,
        grant: &authn::AuthGrant,
    ) -> Result<(), sqlx::Error> {
        if grant.tenant() != self.tx.tenant {
            return Err(sqlx::Error::Protocol(
                "auth grant tenant does not match transaction".to_owned(),
            ));
        }
        let epoch = i64::try_from(grant.authn_epoch_at_issue().get())
            .map_err(|_| sqlx::Error::Protocol("auth grant epoch exceeds bigint".to_owned()))?;
        sqlx::query(
            r#"
            INSERT INTO auth_grants (
                tenant_id, grant_id, user_id, auth_time, authn_epoch_at_issue,
                status, expires_at, created_at, closed_at, close_reason
            ) VALUES (
                $1::uuid, $2, $3::uuid, to_timestamp($4), $5,
                $6, to_timestamp($7), to_timestamp($8), NULL, NULL
            )
            "#,
        )
        .bind(self.tx.tenant.to_string())
        .bind(grant.id().to_wire())
        .bind(grant.user_id().as_uuid().to_string())
        .bind(crate::outbox::unix_secs(grant.auth_time()))
        .bind(epoch)
        .bind(grant.status().as_db_str())
        .bind(crate::outbox::unix_secs(grant.expires_at()))
        .bind(crate::outbox::unix_secs(grant.created_at()))
        .execute(&mut *self.tx.conn)
        .await
        .map(|_| ())
    }

    pub(crate) async fn insert_initial_refresh(
        &mut self,
        record: &::identity::ports::RefreshTokenRecord,
    ) -> Result<(), sqlx::Error> {
        if record.tenant() != self.tx.tenant {
            return Err(sqlx::Error::Protocol(
                "refresh token tenant does not match transaction".to_owned(),
            ));
        }
        let epoch = i64::try_from(record.issuance_epoch().get())
            .map_err(|_| sqlx::Error::Protocol("refresh epoch exceeds bigint".to_owned()))?;
        sqlx::query(
            r#"
            INSERT INTO refresh_tokens (
                id, tenant_id, auth_grant_id, user_id, authn_epoch_at_issue,
                auth_grant_status, token_hash, parent_id, lineage_id, status, issued_at, expires_at
            ) VALUES (
                $1::uuid, $2::uuid, $3, $4::uuid, $5,
                $6, $7, NULL, $8::uuid, $9, to_timestamp($10), to_timestamp($11)
            )
            "#,
        )
        .bind(record.id().as_str())
        .bind(self.tx.tenant.to_string())
        .bind(record.auth_grant_id().to_wire())
        .bind(record.user_id().as_uuid().to_string())
        .bind(epoch)
        .bind(record.auth_grant_status().as_db_str())
        .bind(record.token_hash().as_bytes() as &[u8])
        .bind(record.lineage_id().as_str())
        .bind(record.status().as_db_str())
        .bind(crate::outbox::unix_secs(record.issued_at()))
        .bind(crate::outbox::unix_secs(record.expires_at()))
        .execute(&mut *self.tx.conn)
        .await
        .map(|_| ())
    }

    pub(crate) async fn close_auth_grant_cas(
        &mut self,
        close: &crate::auth_grant_lifecycle::GrantCloseCas,
    ) -> Result<bool, sqlx::Error> {
        if close.tenant != self.tx.tenant {
            return Err(sqlx::Error::Protocol(
                "auth grant close tenant does not match transaction".to_owned(),
            ));
        }
        let tenant = self.tx.tenant.to_string();
        let account_locked: Option<i32> = sqlx::query_scalar(
            r#"
            SELECT 1 FROM account_security_states
            WHERE tenant_id = $1::uuid AND user_id = $2::uuid
            FOR UPDATE
            "#,
        )
        .bind(&tenant)
        .bind(&close.user_id)
        .fetch_optional(&mut *self.tx.conn)
        .await?;
        if account_locked.is_none() {
            return Ok(false);
        }

        sqlx::query(
            "SELECT id FROM refresh_tokens \
             WHERE tenant_id = $1::uuid AND auth_grant_id = $2 \
               AND user_id = $3::uuid AND authn_epoch_at_issue = $4 \
             ORDER BY id FOR UPDATE",
        )
        .bind(&tenant)
        .bind(&close.grant_id)
        .bind(&close.user_id)
        .bind(close.epoch)
        .fetch_all(&mut *self.tx.conn)
        .await?;

        let closed: Option<String> = sqlx::query_scalar(
            r#"
            WITH revoked AS (
                UPDATE refresh_tokens SET status = 'revoked'
                WHERE tenant_id = $1::uuid AND auth_grant_id = $2
                  AND user_id = $3::uuid AND authn_epoch_at_issue = $4
                  AND auth_grant_status = $8 AND status <> 'revoked'
                RETURNING 1
            )
            UPDATE auth_grants
            SET status = $5, closed_at = to_timestamp($6), close_reason = $7
            WHERE tenant_id = $1::uuid AND grant_id = $2 AND user_id = $3::uuid
              AND authn_epoch_at_issue = $4 AND status = $8
              AND closed_at IS NOT DISTINCT FROM to_timestamp($9)
              AND close_reason IS NOT DISTINCT FROM $10
              AND (SELECT count(*) FROM revoked) >= 0
            RETURNING grant_id
            "#,
        )
        .bind(&tenant)
        .bind(&close.grant_id)
        .bind(&close.user_id)
        .bind(close.epoch)
        .bind(close.next_status)
        .bind(close.closed_at)
        .bind(close.reason)
        .bind(close.expected_status)
        .bind(close.expected_closed_at)
        .bind(close.expected_reason)
        .fetch_optional(&mut *self.tx.conn)
        .await?;
        Ok(closed.as_deref() == Some(close.grant_id.as_str()))
    }

    #[cfg(all(test, feature = "integration"))]
    pub(crate) async fn record_role_revision(
        &mut self,
        actor: &::identity::ports::RoleMutationActor,
        role: &::identity::ports::Role,
    ) -> Result<(i64, bool), sqlx::Error> {
        let permissions: Vec<String> = role.permission_ids().collect();
        sqlx::query_as(
            r#"
            SELECT version, changed
            FROM rss_record_role_revision($1, $2, $3, $4::uuid, $5)
            "#,
        )
        .bind(role.id().as_str())
        .bind(role.name())
        .bind(permissions)
        .bind(actor.user_id().as_uuid().to_string())
        .bind(actor.kind().as_actor_metadata_label())
        .fetch_one(&mut *self.tx.conn)
        .await
    }

    pub(crate) async fn upsert_role_binding(
        &mut self,
        binding: &::identity::ports::RoleBinding,
    ) -> Result<(), sqlx::Error> {
        if binding.tenant() != self.tx.tenant {
            return Err(sqlx::Error::Protocol(
                "role binding tenant does not match transaction".to_owned(),
            ));
        }
        sqlx::query(
            r#"
            INSERT INTO role_bindings (tenant_id, role_id, subject)
            VALUES ($1::uuid, $2, $3)
            ON CONFLICT (tenant_id, role_id, subject) DO UPDATE
            SET assigned_at = now()
            "#,
        )
        .bind(self.tx.tenant.to_string())
        .bind(binding.role_id().as_str())
        .bind(binding.subject())
        .execute(&mut *self.tx.conn)
        .await
        .map(|_| ())
    }

    pub(crate) async fn delete_role_binding(
        &mut self,
        role_id: &::identity::ports::RoleId,
        subject: &str,
    ) -> Result<bool, sqlx::Error> {
        sqlx::query(
            "DELETE FROM role_bindings \
             WHERE tenant_id = $1::uuid AND role_id = $2 AND subject = $3",
        )
        .bind(self.tx.tenant.to_string())
        .bind(role_id.as_str())
        .bind(subject)
        .execute(&mut *self.tx.conn)
        .await
        .map(|done| done.rows_affected() > 0)
    }
}

impl RevocationWrite<'_, '_> {
    pub(crate) async fn load_schema_probe(
        &mut self,
    ) -> Result<Option<crate::revocation::RevocationSchemaProbe>, crate::pool::PgError> {
        sqlx::query_as(
        r#"
        SELECT relation.relrowsecurity AS rls_enabled,
               relation.relforcerowsecurity AS rls_forced,
               (
                   SELECT pg_catalog.string_agg(
                       attribute.attname || ':'
                           || pg_catalog.format_type(attribute.atttypid, attribute.atttypmod)
                           || ':' || attribute.attnotnull::text,
                       ',' ORDER BY attribute.attnum
                   )
                   FROM pg_catalog.pg_attribute AS attribute
                   WHERE attribute.attrelid = relation.oid
                     AND attribute.attnum > 0
                     AND NOT attribute.attisdropped
               ) = 'tenant_id:uuid:true,device_id:uuid:true,serial:bytea:true,revoked_at:timestamp with time zone:true,not_after:timestamp with time zone:true'
                   AS columns_exact,
               COALESCE((
                   SELECT pg_catalog.string_agg(attribute.attname, ',' ORDER BY key.ordinality)
                   FROM pg_catalog.pg_constraint AS constraint_row
                   CROSS JOIN LATERAL pg_catalog.unnest(constraint_row.conkey)
                       WITH ORDINALITY AS key(attnum, ordinality)
                   JOIN pg_catalog.pg_attribute AS attribute
                     ON attribute.attrelid = constraint_row.conrelid
                    AND attribute.attnum = key.attnum
                   WHERE constraint_row.conrelid = relation.oid
                     AND constraint_row.contype = 'p'
               ) = 'tenant_id,device_id,serial', false) AS primary_key_exact,
               EXISTS (
                   SELECT 1 FROM pg_catalog.pg_constraint AS constraint_row
                   WHERE constraint_row.conrelid = relation.oid
                     AND constraint_row.contype = 'c'
                     AND constraint_row.conname = 'certificate_revocations_serial_length'
                     AND pg_catalog.regexp_replace(
                         pg_catalog.pg_get_constraintdef(constraint_row.oid, true),
                         '[[:space:]()]', '', 'g'
                     ) = 'CHECKoctet_lengthserial>=1ANDoctet_lengthserial<=20'
               ) AS serial_check_exact,
               EXISTS (
                   SELECT 1 FROM pg_catalog.pg_constraint AS constraint_row
                   WHERE constraint_row.conrelid = relation.oid
                     AND constraint_row.contype = 'c'
                     AND constraint_row.conname = 'certificate_revocations_time_order'
                     AND pg_catalog.regexp_replace(
                         pg_catalog.pg_get_constraintdef(constraint_row.oid, true),
                         '[[:space:]()]', '', 'g'
                     ) = 'CHECKrevoked_at<not_after'
               ) AS time_check_exact,
               COALESCE((
                   SELECT pg_catalog.pg_get_expr(default_value.adbin, default_value.adrelid)
                   FROM pg_catalog.pg_attribute AS attribute
                   JOIN pg_catalog.pg_attrdef AS default_value
                     ON default_value.adrelid = attribute.attrelid
                    AND default_value.adnum = attribute.attnum
                   WHERE attribute.attrelid = relation.oid
                     AND attribute.attname = 'revoked_at'
               ) = 'clock_timestamp()', false) AS default_exact,
               EXISTS (
                   SELECT 1
                   FROM pg_catalog.pg_index AS index
                   JOIN pg_catalog.pg_class AS index_relation ON index_relation.oid = index.indexrelid
                   JOIN pg_catalog.pg_am AS access_method
                     ON access_method.oid = index_relation.relam
                   WHERE index.indrelid = relation.oid
                     AND index.indisvalid
                     AND index.indisready
                     AND index.indislive
                     AND NOT index.indisunique
                     AND NOT index.indisexclusion
                     AND index.indpred IS NULL
                     AND index.indexprs IS NULL
                     AND index.indnkeyatts = 4
                     AND index.indnatts = 4
                     AND index_relation.relkind = 'i'
                     AND index_relation.reloptions IS NULL
                     AND index_relation.relname = 'certificate_revocations_retention_idx'
                     AND access_method.amname = 'btree'
                     AND (
                         SELECT pg_catalog.string_agg(
                             attribute.attname,
                             ',' ORDER BY key.ordinality
                         )
                         FROM pg_catalog.unnest(index.indkey)
                             WITH ORDINALITY AS key(attnum, ordinality)
                         JOIN pg_catalog.pg_attribute AS attribute
                           ON attribute.attrelid = index.indrelid
                          AND attribute.attnum = key.attnum
                     ) = 'not_after,tenant_id,device_id,serial'
                     AND NOT EXISTS (
                         SELECT 1
                         FROM pg_catalog.unnest(index.indoption)
                             WITH ORDINALITY AS key_option(bits, ordinality)
                         WHERE key_option.bits <> 0
                     )
                     AND NOT EXISTS (
                         SELECT 1
                         FROM pg_catalog.unnest(index.indcollation)
                             WITH ORDINALITY AS key_collation(collation_oid, ordinality)
                         WHERE key_collation.collation_oid <> 0
                     )
                     AND NOT EXISTS (
                         SELECT 1
                         FROM pg_catalog.unnest(index.indclass)
                             WITH ORDINALITY AS key_opclass(opclass_oid, ordinality)
                         JOIN pg_catalog.unnest(index.indkey)
                             WITH ORDINALITY AS key_column(attnum, ordinality)
                           ON key_column.ordinality = key_opclass.ordinality
                         JOIN pg_catalog.pg_attribute AS attribute
                           ON attribute.attrelid = index.indrelid
                          AND attribute.attnum = key_column.attnum
                         JOIN pg_catalog.pg_opclass AS opclass
                           ON opclass.oid = key_opclass.opclass_oid
                         WHERE opclass.opcmethod <> access_method.oid
                            OR NOT opclass.opcdefault
                            OR opclass.opcintype <> attribute.atttypid
                     )
               ) AS retention_index_exact,
               EXISTS (
                   SELECT 1
                   FROM pg_catalog.pg_policy AS policy
                   WHERE policy.polrelid = relation.oid
                     AND policy.polname = 'tenant_isolation'
                     AND policy.polpermissive
                     AND policy.polcmd = '*'
                     AND policy.polroles = ARRAY[0::oid]
                     AND pg_catalog.pg_get_expr(policy.polqual, policy.polrelid)
                         = '(tenant_id = (NULLIF(current_setting(''rss.tenant_id''::text, true), ''''::text))::uuid)'
                     AND pg_catalog.pg_get_expr(policy.polwithcheck, policy.polrelid)
                         = '(tenant_id = (NULLIF(current_setting(''rss.tenant_id''::text, true), ''''::text))::uuid)'
               ) AS tenant_policy_exact
        FROM pg_catalog.pg_class AS relation
        JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = relation.relnamespace
        WHERE namespace.nspname = 'public'
          AND relation.relname = 'certificate_revocations'
          AND relation.relkind = 'r'
        "#,
    )
    .fetch_optional(&mut *self.tx.conn)
    .await
    .map_err(crate::pool::PgError::RevocationCapability)
    }

    pub(crate) async fn load_relation_acl_probe(
        &mut self,
    ) -> Result<crate::revocation::RelationAclProbe, crate::pool::PgError> {
        sqlx::query_as(
            r#"
        WITH relation AS (
            SELECT relation.oid, relation.relowner, relation.relacl
            FROM pg_catalog.pg_class AS relation
            JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = relation.relnamespace
            WHERE namespace.nspname = 'public'
              AND relation.relname = 'certificate_revocations'
        ), actual AS (
            SELECT CASE WHEN acl.grantee = 0 THEN 'PUBLIC'
                        ELSE pg_catalog.pg_get_userbyid(acl.grantee) END AS grantee,
                   acl.privilege_type,
                   NULL::text AS column_name,
                   acl.is_grantable
            FROM relation
            CROSS JOIN LATERAL pg_catalog.aclexplode(
                COALESCE(relation.relacl, pg_catalog.acldefault('r', relation.relowner))
            ) AS acl
            WHERE acl.grantee <> relation.relowner
            UNION ALL
            SELECT CASE WHEN acl.grantee = 0 THEN 'PUBLIC'
                        ELSE pg_catalog.pg_get_userbyid(acl.grantee) END,
                   acl.privilege_type,
                   attribute.attname,
                   acl.is_grantable
            FROM relation
            JOIN pg_catalog.pg_attribute AS attribute ON attribute.attrelid = relation.oid
            CROSS JOIN LATERAL pg_catalog.aclexplode(attribute.attacl) AS acl
            WHERE attribute.attnum > 0 AND NOT attribute.attisdropped
        ), expected(grantee, privilege_type, column_name, is_grantable) AS (
            VALUES
                ('rss_app'::text, 'SELECT'::text, NULL::text, false),
                ('rss_app_read', 'SELECT', NULL, false),
                ('rss_device_certificate_funnel_owner', 'SELECT', NULL, false),
                ('rss_revocation_maintenance', 'SELECT', NULL, false),
                ('rss_revocation_maintenance', 'UPDATE', NULL, false),
                ('rss_revocation_maintenance', 'DELETE', NULL, false),
                ('rss_device_certificate_funnel_owner', 'SELECT', NULL, false),
                ('rss_app', 'INSERT', 'tenant_id', false),
                ('rss_app', 'INSERT', 'device_id', false),
                ('rss_app', 'INSERT', 'serial', false),
                ('rss_app', 'INSERT', 'not_after', false)
        )
        SELECT NOT EXISTS (SELECT * FROM actual EXCEPT SELECT * FROM expected)
                   AS no_unexpected_grants,
               NOT EXISTS (SELECT * FROM expected EXCEPT SELECT * FROM actual)
                   AS no_missing_grants
        "#,
        )
        .fetch_one(&mut *self.tx.conn)
        .await
        .map_err(crate::pool::PgError::RevocationCapability)
    }

    pub(crate) async fn load_maintenance_role_probe(
        &mut self,
    ) -> Result<crate::revocation::MaintenanceRoleProbe, crate::pool::PgError> {
        sqlx::query_as(
            r#"
        WITH target_role AS (
            SELECT role.oid,
                   NOT role.rolcanlogin
                       AND NOT role.rolsuper
                       AND NOT role.rolcreatedb
                       AND NOT role.rolcreaterole
                       AND NOT role.rolinherit
                       AND NOT role.rolreplication
                       AND role.rolbypassrls AS attributes_exact
            FROM pg_catalog.pg_roles AS role
            WHERE role.rolname = 'rss_revocation_maintenance'
        ), target_relation AS (
            SELECT relation.oid
            FROM pg_catalog.pg_class AS relation
            JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = relation.relnamespace
            WHERE namespace.nspname = 'public'
              AND relation.relname = 'certificate_revocations'
        ), target_functions AS (
            SELECT procedure.oid
            FROM pg_catalog.pg_proc AS procedure
            JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = procedure.pronamespace
            WHERE namespace.nspname = 'public'
              AND procedure.proname IN (
                  'rss_sweep_expired_certificate_revocations',
                  'rss_certificate_revocation_retention_backlog'
              )
              AND procedure.pronargs = 0
        ), namespace_actual AS (
            SELECT namespace.nspname,
                   acl.privilege_type,
                   acl.is_grantable
            FROM target_role AS role
            CROSS JOIN pg_catalog.pg_namespace AS namespace
            CROSS JOIN LATERAL pg_catalog.aclexplode(
                COALESCE(
                    namespace.nspacl,
                    pg_catalog.acldefault('n', namespace.nspowner)
                )
            ) AS acl
            WHERE acl.grantee = role.oid
        ), namespace_expected(nspname, privilege_type, is_grantable) AS (
            VALUES ('public'::name, 'USAGE'::text, false)
        )
        SELECT COALESCE((SELECT role.attributes_exact FROM target_role AS role), false)
                   AS attributes_exact,
               COALESCE((
                   SELECT NOT EXISTS (
                       SELECT 1
                       FROM pg_catalog.pg_auth_members AS membership
                       WHERE membership.roleid = role.oid OR membership.member = role.oid
                   )
                   FROM target_role AS role
               ), false) AS no_memberships,
               NOT EXISTS (
                   SELECT * FROM namespace_actual
                   EXCEPT SELECT * FROM namespace_expected
               )
                   AND NOT EXISTS (
                       SELECT * FROM namespace_expected
                       EXCEPT SELECT * FROM namespace_actual
                   )
                   AND NOT EXISTS (
                       SELECT 1
                       FROM pg_catalog.pg_namespace AS namespace
                       JOIN target_role AS role ON namespace.nspowner = role.oid
                   ) AS namespace_capabilities_exact,
               COALESCE((
                   SELECT NOT EXISTS (
                       SELECT relation.oid
                       FROM pg_catalog.pg_class AS relation
                       WHERE relation.relowner = role.oid
                         AND relation.oid <> COALESCE(
                             (SELECT target_relation.oid FROM target_relation), 0
                         )
                       UNION
                       SELECT relation.oid
                       FROM pg_catalog.pg_class AS relation
                       CROSS JOIN LATERAL pg_catalog.aclexplode(
                           COALESCE(
                               relation.relacl,
                               pg_catalog.acldefault(
                                   CASE WHEN relation.relkind = 'S' THEN 'S'::"char"
                                        ELSE 'r'::"char" END,
                                   relation.relowner
                               )
                           )
                       ) AS acl
                       WHERE acl.grantee = role.oid
                         AND relation.relkind IN ('r', 'p', 'v', 'm', 'f', 'S')
                         AND relation.oid <> COALESCE(
                             (SELECT target_relation.oid FROM target_relation), 0
                         )
                   )
                   FROM target_role AS role
               ), false) AS no_extra_relation_capabilities,
               COALESCE((
                   SELECT NOT EXISTS (
                       SELECT procedure.oid
                       FROM pg_catalog.pg_proc AS procedure
                       WHERE procedure.proowner = role.oid
                         AND procedure.oid NOT IN (
                             SELECT target_functions.oid FROM target_functions
                         )
                       UNION
                       SELECT procedure.oid
                       FROM pg_catalog.pg_proc AS procedure
                       CROSS JOIN LATERAL pg_catalog.aclexplode(
                           COALESCE(
                               procedure.proacl,
                               pg_catalog.acldefault('f', procedure.proowner)
                           )
                       ) AS acl
                       WHERE acl.grantee = role.oid
                         AND procedure.oid NOT IN (
                             SELECT target_functions.oid FROM target_functions
                         )
                   )
                   FROM target_role AS role
               ), false) AS no_extra_function_capabilities
        "#,
        )
        .fetch_one(&mut *self.tx.conn)
        .await
        .map_err(crate::pool::PgError::RevocationCapability)
    }

    pub(crate) async fn load_maintenance_function_probe(
        &mut self,
    ) -> Result<crate::revocation::MaintenanceFunctionProbe, crate::pool::PgError> {
        sqlx::query_as(
        r#"
        WITH target_function AS (
            SELECT procedure.oid,
                   procedure.proname,
                   procedure.proowner,
                   procedure.proacl,
                   procedure.prosecdef,
                   procedure.proconfig,
                   procedure.prorettype,
                   procedure.proretset,
                   procedure.proallargtypes,
                   procedure.proargmodes,
                   procedure.proargnames,
                   procedure.prokind,
                   procedure.prosrc,
                   language.lanname
            FROM pg_catalog.pg_proc AS procedure
            JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = procedure.pronamespace
            JOIN pg_catalog.pg_language AS language ON language.oid = procedure.prolang
            WHERE namespace.nspname = 'public'
              AND procedure.proname IN (
                  'rss_sweep_expired_certificate_revocations',
                  'rss_certificate_revocation_retention_backlog'
              )
              AND procedure.pronargs = 0
        ), actual AS (
            SELECT target_function.proname AS function_name,
                   CASE WHEN acl.grantee = 0 THEN 'PUBLIC'
                        ELSE pg_catalog.pg_get_userbyid(acl.grantee) END AS grantee,
                   acl.privilege_type,
                   acl.is_grantable
            FROM target_function
            CROSS JOIN LATERAL pg_catalog.aclexplode(
                COALESCE(
                    target_function.proacl,
                    pg_catalog.acldefault('f', target_function.proowner)
                )
            ) AS acl
            WHERE acl.grantee <> target_function.proowner
        ), expected(function_name, grantee, privilege_type, is_grantable) AS (
            VALUES
                ('rss_sweep_expired_certificate_revocations'::name,
                 'rss_app'::text, 'EXECUTE'::text, false),
                ('rss_certificate_revocation_retention_backlog'::name,
                 'rss_app'::text, 'EXECUTE'::text, false)
        )
        SELECT COALESCE((
                   SELECT pg_catalog.count(*) = 2
                      AND pg_catalog.count(*) FILTER (
                          WHERE target_function.proname =
                              'rss_sweep_expired_certificate_revocations'
                      ) = 1
                      AND pg_catalog.count(*) FILTER (
                          WHERE target_function.proname =
                              'rss_certificate_revocation_retention_backlog'
                      ) = 1
                   FROM target_function
               ), false) AS exact_count,
               COALESCE((
                   SELECT pg_catalog.bool_and(target_function.prosecdef)
                   FROM target_function
               ), false) AS security_definer,
               COALESCE((
                   SELECT pg_catalog.bool_and(
                       pg_catalog.pg_get_userbyid(target_function.proowner)
                           = 'rss_revocation_maintenance'
                   )
                   FROM target_function
               ), false) AS owner_exact,
               COALESCE((
                   SELECT pg_catalog.bool_and(
                       CASE target_function.proname
                           WHEN 'rss_sweep_expired_certificate_revocations'
                               THEN target_function.lanname = 'plpgsql'
                           WHEN 'rss_certificate_revocation_retention_backlog'
                               THEN target_function.lanname = 'sql'
                           ELSE false
                       END
                   )
                   FROM target_function
               ), false) AS language_exact,
               COALESCE((
                   SELECT pg_catalog.bool_and(
                       CASE target_function.proname
                           WHEN 'rss_sweep_expired_certificate_revocations' THEN
                               target_function.prokind = 'f'
                               AND NOT target_function.proretset
                               AND target_function.prorettype =
                                   'pg_catalog.int8'::pg_catalog.regtype
                               AND target_function.proallargtypes IS NULL
                               AND target_function.proargmodes IS NULL
                               AND target_function.proargnames IS NULL
                           WHEN 'rss_certificate_revocation_retention_backlog' THEN
                               target_function.prokind = 'f'
                               AND target_function.proretset
                               AND target_function.prorettype =
                                   'pg_catalog.record'::pg_catalog.regtype
                               AND target_function.proallargtypes = ARRAY[
                                   'pg_catalog.int8'::pg_catalog.regtype::oid,
                                   'pg_catalog.int8'::pg_catalog.regtype::oid
                               ]::oid[]
                               AND target_function.proargmodes = ARRAY[
                                   't'::"char", 't'::"char"
                               ]
                               AND target_function.proargnames = ARRAY[
                                   'depth'::text, 'oldest_age_seconds'::text
                               ]
                           ELSE false
                       END
                   )
                   FROM target_function
               ), false) AS signature_exact,
               COALESCE((
                   SELECT pg_catalog.bool_and(
                       pg_catalog.cardinality(target_function.proconfig) = 1
                       AND 'search_path=pg_catalog, pg_temp' = ANY(target_function.proconfig)
                   )
                   FROM target_function
               ), false) AS search_path_exact,
               COALESCE((
                   SELECT pg_catalog.bool_and(
                       CASE target_function.proname
                           WHEN 'rss_sweep_expired_certificate_revocations' THEN
                               pg_catalog.btrim(target_function.prosrc) = pg_catalog.btrim($sweep_body$
DECLARE
    deleted_rows bigint;
BEGIN
    WITH expired AS (
        SELECT tenant_id, device_id, serial
        FROM public.certificate_revocations
        WHERE not_after <= pg_catalog.clock_timestamp() - interval '5 minutes'
        ORDER BY not_after, tenant_id, device_id, serial
        LIMIT 1000
        FOR UPDATE SKIP LOCKED
    )
    DELETE FROM public.certificate_revocations AS revocation
    USING expired
    WHERE revocation.tenant_id = expired.tenant_id
      AND revocation.device_id = expired.device_id
      AND revocation.serial = expired.serial;

    GET DIAGNOSTICS deleted_rows = ROW_COUNT;
    RETURN deleted_rows;
END;
$sweep_body$)
                           WHEN 'rss_certificate_revocation_retention_backlog' THEN
                               pg_catalog.btrim(target_function.prosrc) = pg_catalog.btrim($backlog_body$
    SELECT pg_catalog.count(*)::bigint AS depth,
           COALESCE(
               pg_catalog.floor(
                   EXTRACT(
                       EPOCH FROM pg_catalog.clock_timestamp()
                           - (pg_catalog.min(not_after) + interval '5 minutes')
                   )
               )::bigint,
               0::bigint
           ) AS oldest_age_seconds
    FROM public.certificate_revocations
    WHERE not_after <= pg_catalog.clock_timestamp() - interval '5 minutes'
$backlog_body$)
                           ELSE false
                       END
                   )
                   FROM target_function
               ), false) AS body_exact,
               NOT EXISTS (SELECT * FROM actual EXCEPT SELECT * FROM expected)
                   AS no_unexpected_grants,
               NOT EXISTS (SELECT * FROM expected EXCEPT SELECT * FROM actual)
                   AS no_missing_grants
        "#,
    )
    .fetch_one(&mut *self.tx.conn)
    .await
    .map_err(crate::pool::PgError::RevocationCapability)
    }
}
