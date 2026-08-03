//! Narrow real-PostgreSQL probes for tenant-transaction and cross-runtime integration tests.
//!
//! Every method owns fixed SQL. This module deliberately provides no raw connection, executor,
//! SQL argument, or transaction constructor. Named fault-injection methods may perform one closed
//! lifecycle mutation; proof ownership and acceptance semantics remain in the calling behavior test.

use futures::future::BoxFuture;

use super::eventing::{
    InboxWriteTx, OutboxConcern, OutboxTx, SagaInstanceRow, SagaJournalExistingRow,
    SagaLeaseMutation, SagaLeaseRow, SagaWriteTx,
};
use super::{
    LocalTxAttempt, MapOutboxAppendError, ProducerFactAuthorization, ProducerTxOutcome,
    ServingReadLane, ServingWriteLane, TenantDb, TenantLane, TenantScopeHandle, TenantTx,
};
use crate::saga::{
    ClaimFields, InstanceFields, JournalEntryFields, LeaseFields, RegistrationFields,
};
use crate::tx_retry::LocalTxDeadline;

pub(crate) struct TestTx<'borrow, 'tx, L: TenantLane> {
    tx: &'borrow mut TenantTx<'tx, L>,
}

impl<L: TenantLane> TestTx<'_, '_, L> {
    pub(crate) fn tenant(&self) -> vocab::TenantId {
        self.tx.tenant()
    }
}

impl OutboxTx<'_> {
    pub(crate) async fn inject_commit_unknown_after_commit(&mut self) -> Result<(), sqlx::Error> {
        sqlx::query("SELECT set_config('rss.test_commit_unknown_after_commit', '1', true)")
            .execute(&mut *self.conn)
            .await
            .map(|_| ())
    }

    pub(crate) async fn inject_rollback_failed_after_rollback(
        &mut self,
    ) -> Result<(), sqlx::Error> {
        sqlx::query("SELECT set_config('rss.test_rollback_failed_after_rollback', '1', true)")
            .execute(&mut *self.conn)
            .await
            .map(|_| ())
    }

    pub(crate) async fn inject_rollback_timeout(&mut self) -> Result<(), sqlx::Error> {
        sqlx::query("SELECT set_config('rss.test_rollback_timeout', '1', true)")
            .execute(&mut *self.conn)
            .await
            .map(|_| ())
    }

    pub(crate) async fn inbox_claim_receipt(
        &mut self,
        fields: &crate::inbox::ReceiptFields,
        event_id: &str,
        lease_token: &str,
        lease_ttl_seconds: i64,
    ) -> Result<bool, sqlx::Error> {
        let mut inbox = InboxWriteTx::from_parts(&mut *self.conn, self.tenant);
        inbox
            .inbox_claim_receipt(fields, event_id, lease_token, lease_ttl_seconds)
            .await
    }

    pub(crate) async fn inbox_load_identity(
        &mut self,
        fields: &crate::inbox::ReceiptFields,
        event_id: &str,
    ) -> Result<Option<super::eventing::InboxIdentityRow>, sqlx::Error> {
        let mut inbox = InboxWriteTx::from_parts(&mut *self.conn, self.tenant);
        inbox.inbox_load_identity(fields, event_id).await
    }

    pub(crate) async fn inbox_extend_receipt(
        &mut self,
        fields: &crate::inbox::ReceiptFields,
        event_id: &str,
        lease_token: &str,
    ) -> Result<bool, sqlx::Error> {
        let mut inbox = InboxWriteTx::from_parts(&mut *self.conn, self.tenant);
        inbox
            .inbox_extend_receipt(fields, event_id, lease_token)
            .await
    }

    pub(crate) async fn inbox_commit_receipt(
        &mut self,
        fields: &crate::inbox::ReceiptFields,
        event_id: &str,
        lease_token: &str,
    ) -> Result<bool, sqlx::Error> {
        let mut inbox = InboxWriteTx::from_parts(&mut *self.conn, self.tenant);
        inbox
            .inbox_commit_receipt(fields, event_id, lease_token)
            .await
    }

    pub(crate) async fn inbox_release_receipt(
        &mut self,
        fields: &crate::inbox::ReceiptFields,
        event_id: &str,
        lease_token: &str,
    ) -> Result<(), sqlx::Error> {
        let mut inbox = InboxWriteTx::from_parts(&mut *self.conn, self.tenant);
        inbox
            .inbox_release_receipt(fields, event_id, lease_token)
            .await
    }

    pub(crate) async fn saga_register_instance(
        &mut self,
        fields: &RegistrationFields,
    ) -> Result<(), sqlx::Error> {
        let mut saga = SagaWriteTx::from_parts(&mut *self.conn, self.tenant);
        saga.saga_register_instance(fields).await
    }

    pub(crate) async fn saga_load_instance(
        &mut self,
        fields: &InstanceFields,
    ) -> Result<SagaInstanceRow, sqlx::Error> {
        let mut saga = SagaWriteTx::from_parts(&mut *self.conn, self.tenant);
        saga.saga_load_instance(fields).await
    }

    pub(crate) async fn saga_claim(
        &mut self,
        fields: &ClaimFields,
    ) -> Result<Option<SagaLeaseRow>, sqlx::Error> {
        let mut saga = SagaWriteTx::from_parts(&mut *self.conn, self.tenant);
        saga.saga_claim(fields).await
    }

    pub(crate) async fn saga_cas_lease(
        &mut self,
        fields: &LeaseFields,
        mutation: SagaLeaseMutation,
    ) -> Result<bool, sqlx::Error> {
        let mut saga = SagaWriteTx::from_parts(&mut *self.conn, self.tenant);
        saga.saga_cas_lease(fields, mutation).await
    }

    pub(crate) async fn saga_insert_journal(
        &mut self,
        fields: &LeaseFields,
        entry: &JournalEntryFields,
    ) -> Result<bool, sqlx::Error> {
        let mut saga = SagaWriteTx::from_parts(&mut *self.conn, self.tenant);
        saga.saga_insert_journal(fields, entry).await
    }

    pub(crate) async fn saga_lease_is_held(
        &mut self,
        fields: &LeaseFields,
    ) -> Result<bool, sqlx::Error> {
        let mut saga = SagaWriteTx::from_parts(&mut *self.conn, self.tenant);
        saga.saga_lease_is_held(fields).await
    }

    pub(crate) async fn saga_load_journal_entry(
        &mut self,
        fields: &InstanceFields,
        seq: i64,
    ) -> Result<Option<SagaJournalExistingRow>, sqlx::Error> {
        let mut saga = SagaWriteTx::from_parts(&mut *self.conn, self.tenant);
        saga.saga_load_journal_entry(fields, seq).await
    }
}

impl TenantDb<ServingReadLane> {
    pub(crate) async fn test_read<S, T, F>(&self, scope: S, read: F) -> Result<T, sqlx::Error>
    where
        S: TenantScopeHandle,
        F: for<'borrow, 'tx> FnOnce(
                TestTx<'borrow, 'tx, ServingReadLane>,
            ) -> BoxFuture<'borrow, Result<T, sqlx::Error>>
            + Send,
        T: Send,
    {
        self.read(scope, move |tx| read(TestTx { tx })).await
    }

    pub(crate) async fn test_read_map<S, T, F, E>(
        &self,
        scope: S,
        read: F,
        map_storage: impl Fn(sqlx::Error) -> E + Send,
    ) -> Result<T, E>
    where
        S: TenantScopeHandle,
        F: for<'borrow, 'tx> FnOnce(
                TestTx<'borrow, 'tx, ServingReadLane>,
            ) -> BoxFuture<'borrow, Result<T, E>>
            + Send,
        E: Send,
        T: Send,
    {
        self.read_map(scope, move |tx| read(TestTx { tx }), map_storage)
            .await
    }
}

impl TenantDb<ServingWriteLane> {
    pub(crate) async fn test_write<S, T, F, E>(
        &self,
        scope: S,
        write: F,
        map_storage: impl Fn(sqlx::Error) -> E + Send,
    ) -> Result<T, E>
    where
        S: TenantScopeHandle,
        F: for<'borrow, 'tx> FnOnce(&'borrow mut OutboxTx<'tx>) -> BoxFuture<'borrow, Result<T, E>>
            + Send
            + 'static,
        E: std::error::Error + Send + Sync + 'static,
        T: Send,
    {
        self.write(
            scope,
            move |tx| {
                Box::pin(async move {
                    let mut capability = super::eventing::EventingTx::<
                        ServingWriteLane,
                        OutboxConcern,
                    >::from_raw(tx);
                    write(&mut capability).await
                })
            },
            map_storage,
        )
        .await
    }

    /// Force one reconcile lease to expire inside the current tenant-scoped write transaction.
    pub(crate) async fn test_expire_reconcile_lease<S>(
        &self,
        scope: S,
        target_id: String,
    ) -> Result<(), sqlx::Error>
    where
        S: TenantScopeHandle,
    {
        self.write(
            scope,
            move |tx| {
                Box::pin(async move {
                    let done = sqlx::query(
                        "UPDATE reconcile_leases \
                         SET expires_at = acquired_at + interval '1 microsecond' \
                         WHERE tenant_id = $1::uuid AND target_id = $2::uuid",
                    )
                    .bind(tx.tenant.as_uuid().to_string())
                    .bind(target_id)
                    .execute(&mut *tx.conn)
                    .await?;
                    if done.rows_affected() != 1 {
                        return Err(sqlx::Error::RowNotFound);
                    }
                    Ok(())
                })
            },
            std::convert::identity,
        )
        .await
    }

    pub(crate) async fn test_retry_write<S, T, F, E>(
        &self,
        scope: S,
        deadline: LocalTxDeadline,
        write: F,
        map_storage: impl Fn(sqlx::Error) -> E + Send,
    ) -> LocalTxAttempt<T, E>
    where
        S: TenantScopeHandle,
        F: for<'borrow, 'tx> FnOnce(&'borrow mut OutboxTx<'tx>) -> BoxFuture<'borrow, Result<T, E>>
            + Send
            + 'static,
        E: std::error::Error + Send + Sync + 'static,
        T: Send,
    {
        self.retry_write(
            scope,
            deadline,
            move |tx| {
                Box::pin(async move {
                    let mut capability = OutboxTx::from_raw(tx);
                    write(&mut capability).await
                })
            },
            map_storage,
        )
        .await
    }

    pub(crate) async fn test_retry_producer_tx<S, A, T, F, E>(
        &self,
        scope: S,
        deadline: LocalTxDeadline,
        entry: &consistency::EventEntry,
        env: &crate::outbox::OutboxEnvelope,
        write: F,
        map_storage: impl Fn(sqlx::Error) -> E + Send + Sync,
    ) -> LocalTxAttempt<T, E>
    where
        S: TenantScopeHandle,
        F: for<'borrow, 'tx> FnOnce(
                &'borrow mut OutboxTx<'tx>,
            )
                -> BoxFuture<'borrow, Result<ProducerTxOutcome<A, T>, E>>
            + Send
            + 'static,
        E: MapOutboxAppendError + std::error::Error + Send + Sync + 'static,
        A: ProducerFactAuthorization,
        T: Send + 'static,
    {
        self.retry_producer_tx(
            scope,
            deadline,
            entry,
            env,
            move |tx| {
                Box::pin(async move {
                    let mut capability = OutboxTx::from_raw(tx);
                    write(&mut capability).await
                })
            },
            map_storage,
        )
        .await
    }
}

/// Tenant-scoped observation counts for a device-certificate / reconcile worker join.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DeviceCertificateJoinObservation {
    pub(crate) artifacts: i64,
    pub(crate) artifact_id: Option<String>,
    pub(crate) journal: i64,
    pub(crate) device_commands: i64,
    pub(crate) actions: i64,
    pub(crate) outbox: i64,
    pub(crate) attempts_at_epoch: i64,
    pub(crate) results_at_epoch: i64,
}

impl TestTx<'_, '_, ServingReadLane> {
    pub(crate) async fn test_transaction_read_only(&mut self) -> Result<String, sqlx::Error> {
        sqlx::query_scalar("SHOW transaction_read_only")
            .fetch_one(&mut *self.tx.conn)
            .await
    }

    pub(crate) async fn test_role_count(&mut self, role_id: &str) -> Result<i64, sqlx::Error> {
        sqlx::query_scalar("SELECT count(*) FROM roles WHERE id = $1")
            .bind(role_id)
            .fetch_one(&mut *self.tx.conn)
            .await
    }

    pub(crate) async fn test_attempt_role_update(
        &mut self,
        role_id: &str,
        name: &str,
    ) -> Result<sqlx::postgres::PgQueryResult, sqlx::Error> {
        sqlx::query("UPDATE roles SET name = $1 WHERE id = $2 AND tenant_id = $3::uuid")
            .bind(name)
            .bind(role_id)
            .bind(self.tx.tenant.as_uuid().to_string())
            .execute(&mut *self.tx.conn)
            .await
    }

    /// Current reconcile lease epoch for `target_id` under this capability's tenant.
    pub(crate) async fn reconcile_lease_epoch(
        &mut self,
        target_id: &str,
    ) -> Result<i64, sqlx::Error> {
        sqlx::query_scalar(
            "SELECT epoch FROM reconcile_leases \
             WHERE tenant_id = $1::uuid AND target_id = $2::uuid",
        )
        .bind(self.tx.tenant.as_uuid().to_string())
        .bind(target_id)
        .fetch_one(&mut *self.tx.conn)
        .await
    }

    /// Observe device-certificate writes at `(device, generation, epoch)`.
    pub(crate) async fn device_certificate_join_observation(
        &mut self,
        device_id: &str,
        target_id: &str,
        generation: i64,
        epoch: i64,
    ) -> Result<DeviceCertificateJoinObservation, sqlx::Error> {
        let row: (i64, Option<String>, i64, i64, i64, i64, i64, i64) = sqlx::query_as(
            "SELECT \
               (SELECT count(*)::bigint FROM device_certificate_authorized_artifacts \
                WHERE tenant_id = $1::uuid AND device_id = $2::uuid AND generation = $3), \
               (SELECT min(artifact_id) FROM device_certificate_authorized_artifacts \
                WHERE tenant_id = $1::uuid AND device_id = $2::uuid AND generation = $3), \
               (SELECT count(*)::bigint FROM command_journal journal \
                WHERE journal.tenant_id = $1::uuid AND journal.command_id IN ( \
                  SELECT command_id FROM device_commands \
                  WHERE tenant_id = $1::uuid AND device_id = $2::uuid \
                    AND generation = $3 AND fence_epoch = $4)), \
               (SELECT count(*)::bigint FROM device_commands \
                WHERE tenant_id = $1::uuid AND device_id = $2::uuid \
                  AND generation = $3 AND fence_epoch = $4), \
               (SELECT count(*)::bigint FROM reconcile_actions action \
                JOIN reconcile_attempts attempt \
                  ON attempt.tenant_id = action.tenant_id \
                 AND attempt.attempt_id = action.attempt_id \
                WHERE attempt.tenant_id = $1::uuid AND attempt.target_id = $5::uuid \
                  AND attempt.epoch = $4), \
               (SELECT count(*)::bigint FROM outbox \
                WHERE tenant_id = $1::uuid AND event_id IN ( \
                  SELECT command_id FROM device_commands \
                  WHERE tenant_id = $1::uuid AND device_id = $2::uuid \
                    AND generation = $3 AND fence_epoch = $4)), \
               (SELECT count(*)::bigint FROM reconcile_attempts \
                WHERE tenant_id = $1::uuid AND target_id = $5::uuid AND epoch = $4), \
               (SELECT count(*)::bigint FROM reconcile_attempt_results result \
                JOIN reconcile_attempts attempt \
                  ON attempt.tenant_id = result.tenant_id \
                 AND attempt.attempt_id = result.attempt_id \
                WHERE attempt.tenant_id = $1::uuid AND attempt.target_id = $5::uuid \
                  AND attempt.epoch = $4)",
        )
        .bind(self.tx.tenant.as_uuid().to_string())
        .bind(device_id)
        .bind(generation)
        .bind(epoch)
        .bind(target_id)
        .fetch_one(&mut *self.tx.conn)
        .await?;
        Ok(DeviceCertificateJoinObservation {
            artifacts: row.0,
            artifact_id: row.1,
            journal: row.2,
            device_commands: row.3,
            actions: row.4,
            outbox: row.5,
            attempts_at_epoch: row.6,
            results_at_epoch: row.7,
        })
    }

    /// Count `device_commands` for this tenant at `(device_id, generation, fence_epoch)`.
    pub(crate) async fn device_command_count_at_epoch(
        &mut self,
        device_id: &str,
        generation: i64,
        epoch: i64,
    ) -> Result<i64, sqlx::Error> {
        sqlx::query_scalar(
            "SELECT count(*)::bigint FROM device_commands \
             WHERE tenant_id = $1::uuid AND device_id = $2::uuid \
               AND generation = $3 AND fence_epoch = $4",
        )
        .bind(self.tx.tenant.as_uuid().to_string())
        .bind(device_id)
        .bind(generation)
        .bind(epoch)
        .fetch_one(&mut *self.tx.conn)
        .await
    }

    /// Count reconcile attempts for this tenant at `(target_id, trigger_kind, epoch)`.
    pub(crate) async fn reconcile_attempt_count_for_trigger(
        &mut self,
        target_id: &str,
        trigger_kind: &str,
        epoch: i64,
    ) -> Result<i64, sqlx::Error> {
        sqlx::query_scalar(
            "SELECT count(*)::bigint FROM reconcile_attempts \
             WHERE tenant_id = $1::uuid AND target_id = $2::uuid \
               AND trigger_kind = $3 AND epoch = $4",
        )
        .bind(self.tx.tenant.as_uuid().to_string())
        .bind(target_id)
        .bind(trigger_kind)
        .bind(epoch)
        .fetch_one(&mut *self.tx.conn)
        .await
    }
}

impl OutboxTx<'_> {
    pub(crate) async fn test_abort_transaction(&mut self) -> Result<(), sqlx::Error> {
        sqlx::query("SELECT 1 / 0")
            .execute(&mut *self.conn)
            .await
            .map(|_| ())
    }

    pub(crate) async fn test_backend_pid(&mut self) -> Result<i32, sqlx::Error> {
        sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *self.conn)
            .await
    }

    pub(crate) async fn test_local_timeouts(&mut self) -> Result<(i32, i32), sqlx::Error> {
        sqlx::query_as(
            "SELECT \
             (EXTRACT(EPOCH FROM current_setting('statement_timeout')::interval) * 1000)::int, \
             (EXTRACT(EPOCH FROM current_setting('lock_timeout')::interval) * 1000)::int",
        )
        .fetch_one(&mut *self.conn)
        .await
    }

    pub(crate) async fn test_insert_config(
        &mut self,
        key: &str,
        value: &str,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO config_entries \
             (tenant_id, config_key, version, value, protection_scheme) \
             VALUES ($1::uuid, $2, 1, $3, 0)",
        )
        .bind(self.tenant.as_uuid().to_string())
        .bind(key)
        .bind(value)
        .execute(&mut *self.conn)
        .await
        .map(|_| ())
    }

    pub(crate) async fn test_config_count(&mut self, key: &str) -> Result<i64, sqlx::Error> {
        sqlx::query_scalar(
            "SELECT count(*) FROM config_entries WHERE config_key = $1 AND version = 1",
        )
        .bind(key)
        .fetch_one(&mut *self.conn)
        .await
    }

    pub(crate) async fn test_config_values(
        &mut self,
        key: &str,
    ) -> Result<Vec<String>, sqlx::Error> {
        sqlx::query_scalar("SELECT value FROM config_entries WHERE config_key = $1 ORDER BY value")
            .bind(key)
            .fetch_all(&mut *self.conn)
            .await
    }

    pub(crate) async fn test_sleep_one_second(&mut self) -> Result<(), sqlx::Error> {
        sqlx::query("SELECT pg_sleep(1)")
            .execute(&mut *self.conn)
            .await
            .map(|_| ())
    }
}
