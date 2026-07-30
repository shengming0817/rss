//! Narrow real-PostgreSQL probes for transaction-kernel integration tests.
//!
//! Every method owns fixed SQL. This module deliberately provides no raw connection, executor,
//! SQL argument, lifecycle operation, or transaction constructor.

use futures::future::BoxFuture;

use super::eventing::{
    InboxWriteTx, OutboxConcern, OutboxTx, SagaInstanceRow, SagaJournalExistingRow,
    SagaLeaseMutation, SagaLeaseRow, SagaWriteTx,
};
use super::{
    LocalTxAttempt, MapOutboxAppendError, ProducerFactAuthorization, ProducerTxOutcome,
    ServingReadLane, ServingWriteLane, TenantDb, TenantLane, TenantScopeHandle, TenantTx,
};
use crate::saga::{InstanceFields, JournalEntryFields, LeaseFields, RegistrationFields};
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

    pub(crate) async fn saga_acquire_lease(
        &mut self,
        fields: &InstanceFields,
        holder_id: &str,
        ttl_secs: i64,
    ) -> Result<Option<SagaLeaseRow>, sqlx::Error> {
        let mut saga = SagaWriteTx::from_parts(&mut *self.conn, self.tenant);
        saga.saga_acquire_lease(fields, holder_id, ttl_secs).await
    }

    pub(crate) async fn saga_cas_lease(
        &mut self,
        fields: &LeaseFields,
        mutation: SagaLeaseMutation<'_>,
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
