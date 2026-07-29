//! `producer_tx` —— authorized generated-fact producer 的唯一事务骨架：begin → SET LOCAL tenant →
//! 业务写闭包返回 typed outcome → 授权校验 → canonical append → 单 commit；任一步 Err ⇒ rollback +
//! warn。授权来自 HTTP mounted-producer receipt，或 credential-security sealed command 派生的
//! move-only authorization；调用方均不能选择、覆盖或独立铸造 fact proof。
//!
//! 抽取自 session co-tx 范式（`auth_grant_lifecycle.rs`），供 session 创建与配置写
//! `PgConfigUnitOfWork` 复用。
//!
//! 错误泛型 `E`：业务写闭包返回 `Result<ProducerTxOutcome<A, T>, E>`（如 CAS 0 行 → 域
//! `VersionConflict`）；骨架自身产生的 sqlx
//! 错误（begin / SET LOCAL / `append_outbox` / commit）经调用方传入的 `map_storage: Fn(sqlx::Error)->E` 收敛进
//! 同一 `E`——**不**要求 `E: From<sqlx::Error>`（域错误 `ConfigRepoError` 不依赖 sqlx，无法 impl `From`）。
//! 这正是不直接复用 `PgStore::run_global_transaction`（要求 `E: From<sqlx::Error>`）的原因。
//!
//! # INVARIANT: OUTBOX-COTX-CONFIG-01 { level = "Medium", exec = "manual/opt-in", source = "code" }
//!
//! 业务写行与 outbox 行在**同一**事务内写入 → 共 commit / 共 rollback；业务写失败（含 CAS 冲突）⇒ 整事务
//! 回滚 ⇒ outbox 行不落库（消除 write-without-event 窗口）。anti-vacuity 由集成测试守（正向 commit 两行皆在
//! ↔ 负向业务写 Err 两写共回滚 + CAS 冲突 → 无 outbox 行）。
//!
//! ref: debezium outbox SMT / MassTransit Bus Outbox（业务写 + outbox 行同一本地事务，producer 侧 durable）

#[cfg(any(feature = "domain-settings", feature = "domain-identity"))]
use consistency::EventEntry;
#[cfg(any(feature = "domain-settings", feature = "domain-identity"))]
use diport::OutboxEmitError;
use futures::future::BoxFuture;
#[cfg(any(feature = "domain-settings", feature = "domain-identity"))]
use httpserve::ProducerAuthorization;
use sqlx::{Acquire, PgConnection, PgPool, Postgres, Transaction};
use tokio::time::Instant;
use vocab::TenantId;

#[cfg(any(feature = "domain-settings", feature = "domain-identity"))]
use crate::outbox::{OutboxAppendError, OutboxEnvelope, append_outbox_with_projection};
use crate::pool::{
    VerifiedPgAuditAdminStore, VerifiedPgMaintenanceStore, VerifiedPgReadStore,
    VerifiedPgWriteStore,
};
use crate::projection_events::ProjectionWriteRegistry;
#[cfg(any(feature = "domain-settings", feature = "domain-audit"))]
use crate::tx_retry::LocalTxDeadline;
use crate::tx_retry::{
    LocalTxAcquireDeadline, LocalTxBeginDeadline, LocalTxCommitDeadline, LocalTxOperationDeadline,
    LocalTxRollbackDeadline, LocalTxSetupDeadline, LocalTxStageResult,
};
#[cfg(feature = "domain-identity")]
use crate::tx_retry::{OUTBOX_PRODUCER_BOUNDARY, record_settlement};

mod settlement;

#[cfg(any(feature = "domain-settings", feature = "domain-audit"))]
pub(crate) use settlement::{LocalTxAttempt, LocalTxRetryError, commit_unknown};
#[cfg(not(any(feature = "domain-settings", feature = "domain-audit")))]
pub(crate) use settlement::{LocalTxAttempt, commit_unknown};
use settlement::{LocalTxConnectionLease, LocalTxTransaction, rollback_failed};

/// Tokio I/O deadlines require a monotonic clock; the wall-clock [`diport::Clock`] contract cannot
/// represent or safely derive these instants. Keeping this one adapter-private boundary also makes
/// paused-time tests deterministic.
#[allow(clippy::disallowed_methods)]
pub(crate) fn io_deadline_after(duration: std::time::Duration) -> Instant {
    Instant::now() + duration
}

pub(crate) trait TenantScopeHandle: Copy + Send {
    fn tenant(self) -> TenantId;
}

/// Crate-private tenant capability for postgres-owned infrastructure paths
/// such as outbox, inbox, DLQ, saga, and reconcile workers.
#[derive(Clone, Copy)]
pub(crate) struct InfraTenantScope {
    tenant: TenantId,
    _seal: (),
}

impl InfraTenantScope {
    fn from_infra_capability(tenant: TenantId) -> Self {
        Self { tenant, _seal: () }
    }

    pub(crate) fn tenant(&self) -> TenantId {
        self.tenant
    }
}

impl TenantScopeHandle for InfraTenantScope {
    fn tenant(self) -> TenantId {
        InfraTenantScope::tenant(&self)
    }
}

impl TenantScopeHandle for diport::CertScope {
    fn tenant(self) -> TenantId {
        diport::CertScope::tenant(&self)
    }
}

pub(crate) fn infra_tenant_scope(tenant: TenantId) -> InfraTenantScope {
    InfraTenantScope::from_infra_capability(tenant)
}

#[cfg(feature = "domain-settings")]
impl TenantScopeHandle for settings::ports::TenantRepoScope {
    fn tenant(self) -> TenantId {
        settings::ports::TenantRepoScope::tenant(&self)
    }
}

#[cfg(feature = "domain-identity")]
impl TenantScopeHandle for identity::ports::TenantRepoScope {
    fn tenant(self) -> TenantId {
        identity::ports::TenantRepoScope::tenant(&self)
    }
}

#[cfg(feature = "domain-audit")]
impl TenantScopeHandle for audit::ports::TenantRepoScope {
    fn tenant(self) -> TenantId {
        audit::ports::TenantRepoScope::tenant(&self)
    }
}

#[cfg(any(feature = "domain-settings", feature = "domain-identity"))]
#[derive(Debug, thiserror::Error)]
#[error("outbox envelope tenant does not match tenant-scoped transaction")]
struct OutboxTenantMismatch;

#[cfg(any(feature = "domain-settings", feature = "domain-identity"))]
#[derive(Debug, thiserror::Error)]
#[error("producer authorization does not match outbox envelope")]
struct ProducerAuthorizationMismatch;

#[cfg(any(feature = "domain-settings", feature = "domain-identity"))]
struct ProducerTxWrite<'a> {
    tenant: TenantId,
    entry: &'a EventEntry,
    env: &'a OutboxEnvelope,
}

mod producer_fact_authorization_seal {
    pub(crate) trait Sealed {}
}

/// Crate-closed authorization for the exact generated fact appended by [`producer_tx`](PgTenantWritePool::producer_tx).
///
/// Production HTTP routes obtain this capability from their mounted producer receipt; no domain
/// command can independently mint an active fact authorization.
#[cfg(any(feature = "domain-settings", feature = "domain-identity"))]
pub(crate) trait ProducerFactAuthorization:
    producer_fact_authorization_seal::Sealed + Send + 'static
{
    fn fact(&self) -> vocab::EventFactBinding;
}

#[cfg(any(feature = "domain-settings", feature = "domain-identity"))]
impl<M> producer_fact_authorization_seal::Sealed for ProducerAuthorization<M> {}

#[cfg(any(feature = "domain-settings", feature = "domain-identity"))]
impl<M: Send + 'static> ProducerFactAuthorization for ProducerAuthorization<M> {
    fn fact(&self) -> vocab::EventFactBinding {
        ProducerAuthorization::fact(self)
    }
}

#[cfg(all(test, feature = "domain-identity", feature = "integration"))]
pub(crate) struct IntegrationCredentialSecurityAuthorization;

#[cfg(all(test, feature = "domain-identity", feature = "integration"))]
impl IntegrationCredentialSecurityAuthorization {
    pub(crate) const fn new() -> Self {
        Self
    }
}

#[cfg(all(test, feature = "domain-identity", feature = "integration"))]
impl producer_fact_authorization_seal::Sealed for IntegrationCredentialSecurityAuthorization {}

#[cfg(all(test, feature = "domain-identity", feature = "integration"))]
impl ProducerFactAuthorization for IntegrationCredentialSecurityAuthorization {
    fn fact(&self) -> vocab::EventFactBinding {
        identity::ports::SECURITY_EVENT_FACT
    }
}

/// Field-closed result of an authorized producer business mutation.
///
/// The emitted branch can only carry an unforgeable authorization derived from the exact mounted
/// producer marker. The two fact-free branches preserve the authoritative mutation truth:
/// `MutatedWithoutFact` commits a business mutation without appending a fact, while `NoMutation`
/// proves that the business body made no durable change.
#[cfg(any(feature = "domain-settings", feature = "domain-identity"))]
pub(crate) enum ProducerTxOutcome<A, T> {
    Emitted(T, A),
    #[cfg(feature = "domain-identity")]
    MutatedWithoutFact(T),
    #[cfg(feature = "domain-identity")]
    NoMutation(T),
}

/// One non-retrying producer attempt whose only result projection records its typed settlement.
#[cfg(feature = "domain-identity")]
#[must_use = "producer settlement must be observed through ProducerTxAttempt::into_result"]
pub(crate) struct ProducerTxAttempt<T, E> {
    attempt: LocalTxAttempt<T, E>,
}

#[cfg(feature = "domain-identity")]
impl<T, E> ProducerTxAttempt<T, E> {
    fn new(attempt: LocalTxAttempt<T, E>) -> Self {
        Self { attempt }
    }

    /// Consume the attempt after routing every acknowledged final settlement through the shared
    /// low-cardinality metric and unsafe-settlement WARN owner. There is deliberately no replay API.
    pub(crate) fn into_result(self) -> Result<T, E> {
        record_settlement(OUTBOX_PRODUCER_BOUNDARY, self.attempt.settlement());
        self.attempt.into_result()
    }

    /// Consume a refresh producer attempt and mint its acknowledgement only from the committed
    /// branch of the opaque settlement carrier. Unknown commits and rollbacks cannot reach it.
    pub(crate) fn into_refresh_commit_result(
        self,
    ) -> Result<(T, identity::ports::RefreshCommitAcknowledgement), E> {
        record_settlement(OUTBOX_PRODUCER_BOUNDARY, self.attempt.settlement());
        self.attempt
            .into_result()
            .map(|value| (value, identity::ports::acknowledge_durable_refresh_commit()))
    }
}

/// Postgres 事务能力令牌。
///
/// 只有本 crate 能从 live [`sqlx::Transaction`] 铸造本类型；外部 crate 无法构造、无法从
/// [`PgPool`] / [`PgConnection`] mint。`append_outbox` 只接受本令牌，确保 outbox 双写入口不能被裸连接调用。
///
/// `ref: sqlx sqlx-core/src/transaction.rs@v0.8.6`（`Transaction` 从 `begin` 到 `commit`/`rollback` 持有连接，
/// 并通过 `DerefMut` 借出底层 connection）。
///
/// # INVARIANT: PG-TX-CAPABILITY-SEAL-01 { level = "Hard", exec = "native-compile", source = "code", native = "type boundary and trybuild UI" }
pub(crate) struct TxCapability<'tx> {
    conn: &'tx mut PgConnection,
    _seal: (),
}

impl<'tx> TxCapability<'tx> {
    /// 从真实 `sqlx::Transaction` 铸造事务能力令牌。
    pub(crate) fn from_transaction(tx: &'tx mut Transaction<'_, Postgres>) -> Self {
        Self {
            conn: &mut **tx,
            _seal: (),
        }
    }

    /// 借出事务内连接供 adapter 内 SQL helper 使用。
    pub(crate) fn conn(&mut self) -> &mut PgConnection {
        self.conn
    }

    /// Integration-only seam that simulates losing the commit acknowledgement after PostgreSQL
    /// has accepted the commit. The transaction-local marker is consumed by the settlement funnel;
    /// the default production feature graph cannot construct or trigger it. External journey
    /// access is admitted only through the named store constructor behind `journey-fault-support`.
    #[cfg(all(test, feature = "integration"))]
    pub(crate) async fn inject_commit_unknown_after_commit(&mut self) -> Result<(), sqlx::Error> {
        sqlx::query("SELECT set_config('rss.test_commit_unknown_after_commit', '1', true)")
            .execute(&mut *self.conn)
            .await
            .map(|_| ())
    }

    /// Integration-only seam consumed after the sole producer funnel has successfully appended
    /// its OutboxFact but before the transaction can commit. The transaction-local marker cannot
    /// be set by the production feature graph.
    #[cfg(all(test, feature = "integration"))]
    pub(crate) async fn inject_failure_after_outbox_append_before_commit(
        &mut self,
    ) -> Result<(), sqlx::Error> {
        sqlx::query("SELECT set_config('rss.test_fail_after_outbox_append', '1', true)")
            .execute(&mut *self.conn)
            .await
            .map(|_| ())
    }

    /// Integration-only seam consumed after the projection mirror has been appended. This proves
    /// rollback at the real projection boundary rather than failing inside the business mutation.
    #[cfg(all(test, feature = "integration"))]
    pub(crate) async fn inject_failure_after_projection_append(
        &mut self,
    ) -> Result<(), sqlx::Error> {
        sqlx::query("SELECT set_config('rss.test_fail_after_projection_append', '1', true)")
            .execute(&mut *self.conn)
            .await
            .map(|_| ())
    }

    /// Integration-only seam that performs a real rollback and then simulates losing its
    /// acknowledgement. The settlement funnel consumes the transaction-local marker and reports
    /// `RollbackFailed`, which must never be replayed.
    #[cfg(all(test, feature = "integration"))]
    pub(crate) async fn inject_rollback_failed_after_rollback(
        &mut self,
    ) -> Result<(), sqlx::Error> {
        sqlx::query("SELECT set_config('rss.test_rollback_failed_after_rollback', '1', true)")
            .execute(&mut *self.conn)
            .await
            .map(|_| ())
    }

    /// Integration-only seam that leaves rollback without an acknowledgement until the caller's
    /// timeout cancels the LocalTx future. The armed connection lease must quarantine the backend.
    #[cfg(all(test, feature = "integration"))]
    pub(crate) async fn inject_rollback_timeout(&mut self) -> Result<(), sqlx::Error> {
        sqlx::query("SELECT set_config('rss.test_rollback_timeout', '1', true)")
            .execute(&mut *self.conn)
            .await
            .map(|_| ())
    }
}

/// Tenant-scoped PostgreSQL read capability.
///
/// The capability exposes only `read`/`read_map`; durable mutation methods are absent. Production
/// construction requires a verified reader store, while the raw-store source exists only under
/// `cfg(test)` for database integration tests.
///
/// # INVARIANT: TENANCY-PG-TX-FUNNEL-01 { level = "Medium", exec = "manual/opt-in", source = "code" }
///
/// `cargo xtask pg-tenant-tx-guard` is the Medium backstop for raw-pool and lane crossover drift.
#[derive(Clone)]
pub(crate) struct PgReadPool<L> {
    pool: PgPool,
    _lane: std::marker::PhantomData<fn() -> L>,
}

#[derive(Clone, Copy)]
pub(crate) enum ServingReadLane {}
#[allow(dead_code)]
pub(crate) enum AuditAdminReadLane {}
pub(crate) enum MaintenanceReadLane {}

pub(crate) type PgTenantReadPool = PgReadPool<ServingReadLane>;
#[allow(dead_code)]
pub(crate) type PgAuditAdminReadPool = PgReadPool<AuditAdminReadLane>;
pub(crate) type PgMaintenanceReadPool = PgReadPool<MaintenanceReadLane>;

impl PgReadPool<ServingReadLane> {
    pub(crate) fn new(store: &VerifiedPgReadStore) -> Self {
        Self {
            pool: store.pool().clone(),
            _lane: std::marker::PhantomData,
        }
    }

    #[cfg(any(test, feature = "fault-matrix-test-support"))]
    #[allow(dead_code)]
    pub(crate) fn from_unverified_for_test(store: &crate::PgStore) -> Self {
        Self {
            pool: store.pool.clone(),
            _lane: std::marker::PhantomData,
        }
    }
}

impl PgReadPool<AuditAdminReadLane> {
    #[allow(dead_code)]
    pub(crate) fn new_admin(store: &VerifiedPgAuditAdminStore) -> Self {
        Self {
            pool: store.pool().clone(),
            _lane: std::marker::PhantomData,
        }
    }

    #[cfg(any(test, feature = "fault-matrix-test-support"))]
    #[allow(dead_code)]
    pub(crate) fn from_unverified_for_test(store: &crate::PgStore) -> Self {
        Self {
            pool: store.pool.clone(),
            _lane: std::marker::PhantomData,
        }
    }
}

impl PgReadPool<MaintenanceReadLane> {
    pub(crate) fn new_maintenance(store: &VerifiedPgMaintenanceStore) -> Self {
        Self {
            pool: store.pool().clone(),
            _lane: std::marker::PhantomData,
        }
    }
}

impl<L> PgReadPool<L> {
    /// Run a tenant-scoped read transaction.
    pub(crate) async fn read<S, T, F>(&self, scope: S, read: F) -> Result<T, sqlx::Error>
    where
        S: TenantScopeHandle,
        F: for<'c> FnOnce(&'c mut PgConnection) -> BoxFuture<'c, Result<T, sqlx::Error>> + Send,
        T: Send,
    {
        let tenant = scope.tenant();
        tenant_scoped_read(&self.pool, tenant, read).await
    }

    /// Run a tenant-scoped read transaction whose closure can return domain errors.
    pub(crate) async fn read_map<S, T, F, E>(
        &self,
        scope: S,
        read: F,
        map_storage: impl Fn(sqlx::Error) -> E + Send,
    ) -> Result<T, E>
    where
        S: TenantScopeHandle,
        F: for<'c> FnOnce(&'c mut PgConnection) -> BoxFuture<'c, Result<T, E>> + Send,
        E: Send,
        T: Send,
    {
        let tenant = scope.tenant();
        tenant_scoped_read_map(&self.pool, tenant, read, map_storage).await
    }
}

/// Tenant-scoped PostgreSQL write capability.
///
/// Read helpers are deliberately absent: independent reads must be wired through
/// [`PgTenantReadPool`]. SELECT statements required inside a write/CAS/co-transaction remain
/// available through the transaction capability supplied to the write closure.
#[derive(Clone)]
pub(crate) struct PgWritePool<L> {
    pool: PgPool,
    projection_registry: ProjectionWriteRegistry,
    _lane: std::marker::PhantomData<fn() -> L>,
}

#[derive(Clone, Copy)]
pub(crate) enum ServingWriteLane {}
pub(crate) enum MaintenanceWriteLane {}

pub(crate) type PgTenantWritePool = PgWritePool<ServingWriteLane>;
pub(crate) type PgMaintenanceWritePool = PgWritePool<MaintenanceWriteLane>;

impl PgWritePool<ServingWriteLane> {
    pub(crate) fn new(store: &VerifiedPgWriteStore) -> Self {
        Self {
            pool: store.pool().clone(),
            projection_registry: ProjectionWriteRegistry::empty(),
            _lane: std::marker::PhantomData,
        }
    }

    pub(crate) fn with_projection_registry(
        store: &VerifiedPgWriteStore,
        projection_registry: ProjectionWriteRegistry,
    ) -> Self {
        Self {
            pool: store.pool().clone(),
            projection_registry,
            _lane: std::marker::PhantomData,
        }
    }

    /// Run the receipt-gated, fail-closed revocation lookup on the authoritative writer lane.
    ///
    /// This is deliberately narrower than a generic writer-side read API: only the private
    /// startup receipt can select this lane, so independent repositories cannot bypass
    /// [`PgTenantReadPool`].
    pub(crate) async fn revocation_read<S, T, F, E>(
        &self,
        _receipt: &crate::revocation::RevocationCapabilityReceipt,
        scope: S,
        read: F,
        map_storage: impl Fn(sqlx::Error) -> E + Send,
    ) -> Result<T, E>
    where
        S: TenantScopeHandle,
        F: for<'c, 'tx> FnOnce(&'c mut TxCapability<'tx>) -> BoxFuture<'c, Result<T, E>> + Send,
        E: std::error::Error + Send + Sync + 'static,
        T: Send,
    {
        self.write(scope, read, map_storage).await
    }

    #[cfg(any(test, feature = "fault-matrix-test-support"))]
    #[allow(dead_code)]
    pub(crate) fn from_unverified_for_test(store: &crate::PgStore) -> Self {
        Self {
            pool: store.pool.clone(),
            projection_registry: ProjectionWriteRegistry::empty(),
            _lane: std::marker::PhantomData,
        }
    }
}

impl PgWritePool<MaintenanceWriteLane> {
    pub(crate) fn new_maintenance(store: &VerifiedPgMaintenanceStore) -> Self {
        Self {
            pool: store.pool().clone(),
            projection_registry: ProjectionWriteRegistry::empty(),
            _lane: std::marker::PhantomData,
        }
    }
}

impl<L> PgWritePool<L> {
    pub(crate) fn projection_registry(&self) -> ProjectionWriteRegistry {
        self.projection_registry
    }

    /// Run a tenant-scoped write transaction.
    pub(crate) async fn write<S, T, F, E>(
        &self,
        scope: S,
        write: F,
        map_storage: impl Fn(sqlx::Error) -> E + Send,
    ) -> Result<T, E>
    where
        S: TenantScopeHandle,
        F: for<'c, 'tx> FnOnce(&'c mut TxCapability<'tx>) -> BoxFuture<'c, Result<T, E>> + Send,
        E: std::error::Error + Send + Sync + 'static,
        T: Send,
    {
        let tenant = scope.tenant();
        tenant_scoped_write_inner(&self.pool, tenant, write, map_storage)
            .await
            .into_result()
    }

    /// Run one tenant-scoped transaction before an absolute deadline. The connection is owned by
    /// this operation so a client-side timeout can poison it instead of returning an executor with
    /// an unknown PostgreSQL backend state to the idle pool.
    pub(crate) async fn deadline_write<S, T, F, E>(
        &self,
        scope: S,
        deadline: Instant,
        write: F,
        map_storage: impl Fn(sqlx::Error) -> E + Send + Sync,
        map_timeout: impl Fn() -> E + Send + Sync,
    ) -> Result<T, E>
    where
        S: TenantScopeHandle,
        F: for<'c> FnOnce(&'c mut PgConnection) -> BoxFuture<'c, Result<T, E>> + Send,
        E: Send,
        T: Send,
    {
        deadline_transaction(
            &self.pool,
            Some(scope.tenant()),
            deadline,
            write,
            map_storage,
            map_timeout,
        )
        .await
    }

    /// Run a tenant-scoped write transaction with a per-attempt lock wait bound.
    #[cfg(any(feature = "domain-settings", feature = "domain-audit"))]
    pub(crate) async fn retry_write<S, T, F, E>(
        &self,
        scope: S,
        deadline: LocalTxDeadline,
        write: F,
        map_storage: impl Fn(sqlx::Error) -> E + Send,
    ) -> LocalTxAttempt<T, E>
    where
        S: TenantScopeHandle,
        F: for<'c, 'tx> FnOnce(&'c mut TxCapability<'tx>) -> BoxFuture<'c, Result<T, E>> + Send,
        E: std::error::Error + Send + Sync + 'static,
        T: Send,
    {
        let tenant = scope.tenant();
        tenant_scoped_retry_write_inner(&self.pool, tenant, deadline, write, map_storage).await
    }

    /// Run one authorized generated-fact mutation through the only transaction funnel.
    ///
    /// Authorization is supplied by either an HTTP mounted-producer receipt or a
    /// credential-security sealed command's move-only proof.
    #[cfg(feature = "domain-identity")]
    pub(crate) async fn producer_tx<S, A, T, F, E>(
        &self,
        scope: S,
        entry: &EventEntry,
        env: &OutboxEnvelope,
        business_write: F,
        map_storage: impl Fn(sqlx::Error) -> E + Send + Sync,
    ) -> ProducerTxAttempt<T, E>
    where
        S: TenantScopeHandle,
        F: for<'c, 'tx> FnOnce(
                &'c mut TxCapability<'tx>,
            ) -> BoxFuture<'c, Result<ProducerTxOutcome<A, T>, E>>
            + Send,
        E: MapOutboxAppendError + std::error::Error + Send + Sync + 'static,
        A: ProducerFactAuthorization,
        T: Send + 'static,
    {
        let tenant = scope.tenant();
        ProducerTxAttempt::new(
            producer_tx_inner(
                &self.pool,
                self.projection_registry,
                ProducerTxWrite { tenant, entry, env },
                LocalTxExecutionPolicy::Plain,
                business_write,
                map_storage,
            )
            .await,
        )
    }

    /// Run one retry attempt through the same authorized generated-fact transaction funnel.
    ///
    /// Authorization is supplied by an HTTP mounted-producer receipt; credential-security uses
    /// the non-retrying [`Self::producer_tx`] path with its command-derived move-only proof.
    #[cfg(feature = "domain-settings")]
    pub(crate) async fn retry_producer_tx<S, A, T, F, E>(
        &self,
        scope: S,
        deadline: LocalTxDeadline,
        entry: &EventEntry,
        env: &OutboxEnvelope,
        business_write: F,
        map_storage: impl Fn(sqlx::Error) -> E + Send + Sync,
    ) -> LocalTxAttempt<T, E>
    where
        S: TenantScopeHandle,
        F: for<'c, 'tx> FnOnce(
                &'c mut TxCapability<'tx>,
            ) -> BoxFuture<'c, Result<ProducerTxOutcome<A, T>, E>>
            + Send,
        E: MapOutboxAppendError + std::error::Error + Send + Sync + 'static,
        A: ProducerFactAuthorization,
        T: Send + 'static,
    {
        let tenant = scope.tenant();
        producer_tx_inner(
            &self.pool,
            self.projection_registry,
            ProducerTxWrite { tenant, entry, env },
            LocalTxExecutionPolicy::Deadline(deadline),
            business_write,
            map_storage,
        )
        .await
    }
}

/// Run one unscoped infrastructure transaction before an absolute deadline.
///
/// Acquire, transaction setup, operation and commit all consume the same deadline. Once a
/// connection has been acquired, elapsed timeout marks it `close_on_drop`; SQLx must never ping an
/// executor with an unknown in-flight query back into the idle pool.
pub(crate) async fn deadline_global_transaction<T, F, E>(
    pool: &PgPool,
    deadline: Instant,
    operation: F,
    map_storage: impl Fn(sqlx::Error) -> E + Send + Sync,
    map_timeout: impl Fn() -> E + Send + Sync,
) -> Result<T, E>
where
    F: for<'c> FnOnce(&'c mut PgConnection) -> BoxFuture<'c, Result<T, E>> + Send,
    E: Send,
    T: Send,
{
    deadline_transaction(pool, None, deadline, operation, map_storage, map_timeout).await
}

async fn deadline_transaction<T, F, E>(
    pool: &PgPool,
    tenant: Option<TenantId>,
    deadline: Instant,
    operation: F,
    map_storage: impl Fn(sqlx::Error) -> E + Send + Sync,
    map_timeout: impl Fn() -> E + Send + Sync,
) -> Result<T, E>
where
    F: for<'c> FnOnce(&'c mut PgConnection) -> BoxFuture<'c, Result<T, E>> + Send,
    E: Send,
    T: Send,
{
    let mut connection = match tokio::time::timeout_at(deadline, pool.acquire()).await {
        Ok(Ok(connection)) => connection,
        Ok(Err(error)) => return Err(map_storage(error)),
        Err(_) => return Err(map_timeout()),
    };

    let transaction = async {
        let mut tx = connection.begin().await.map_err(&map_storage)?;
        set_local_deadline_timeouts(&mut tx, deadline)
            .await
            .map_err(&map_storage)?;
        if let Some(tenant) = tenant {
            set_local_tenant(&mut tx, tenant)
                .await
                .map_err(&map_storage)?;
        }
        let result = operation(&mut tx).await;
        match result {
            Ok(value) => {
                tx.commit().await.map_err(&map_storage)?;
                Ok(value)
            }
            Err(error) => {
                let _ = tx.rollback().await;
                Err(error)
            }
        }
    };

    match tokio::time::timeout_at(deadline, transaction).await {
        Ok(result) => result,
        Err(_) => {
            connection.close_on_drop();
            Err(map_timeout())
        }
    }
}

async fn set_local_deadline_timeouts(
    connection: &mut PgConnection,
    deadline: Instant,
) -> Result<(), sqlx::Error> {
    let remaining_millis = deadline
        .saturating_duration_since(io_deadline_after(std::time::Duration::ZERO))
        .as_millis();
    // The server must fire before the outer Tokio deadline. Connection poisoning remains the
    // fail-safe for sub-3ms residual windows and broken transports.
    let statement_millis = remaining_millis.saturating_sub(2).max(1);
    let lock_millis = statement_millis.saturating_sub(1).max(1);
    sqlx::query("SELECT set_config('statement_timeout', $1, true)")
        .bind(format!("{statement_millis}ms"))
        .execute(&mut *connection)
        .await?;
    sqlx::query("SELECT set_config('lock_timeout', $1, true)")
        .bind(format!("{lock_millis}ms"))
        .execute(connection)
        .await?;
    Ok(())
}

/// tenant-scoped 只读事务：`BEGIN READ ONLY` → SET LOCAL `rss.tenant_id` → 读闭包 → commit。
///
/// 与写侧 [`PgTenantWritePool::producer_tx`]（producer write + outbox）对称，是读路径的 RLS policy
/// `current_setting('rss.tenant_id', true)` 锚点（#1298）。读闭包仅做 SQL fetch 返回 owned 原始值
/// （`Option<PgRow>` / 标量 / tuple），hydrate（域类型转换 / 域错误映射）在 tx 外执行，保持域错误
/// 语义不变且不依赖 sqlx。失败时 rollback（不覆盖原错误）。
///
/// `tenant`：类型化租户标识（`vocab::TenantId`）；funnel 内部 stringify 成 canonical UUID 后
/// 经 `set_config` 参数化绑定（防注入）。非 `TenantId` 的裸字符串无法进入 funnel（Hard 收口，
/// INVARIANT TENANCY-SETLOCAL-FUNNEL-01）。
///
/// # INVARIANT: RLS-TENANT-SCOPE-READ-01 { level = "Medium", exec = "manual/opt-in", source = "code" }
///
/// 所有独立 tenant relation 读取经此 helper 注入 SET LOCAL，并由显式事务属性拒绝 durable DML。
/// 生产连接同时使用 `rss_app_read` 的默认只读与精确 SELECT ACL；三层防线彼此独立。
pub(crate) async fn tenant_scoped_read<T, F>(
    pool: &PgPool,
    tenant: TenantId,
    read: F,
) -> Result<T, sqlx::Error>
where
    F: for<'c> FnOnce(&'c mut PgConnection) -> BoxFuture<'c, Result<T, sqlx::Error>> + Send,
    T: Send,
{
    let mut tx = begin_tenant_read(pool, tenant).await?;
    let result = read(&mut tx).await;
    // 读事务：成功 commit（RLS fail-closed 时 `read` 已 Err）；失败 rollback（warn 定位，不覆盖原错误）。
    match result {
        Ok(v) => {
            tx.commit().await?;
            Ok(v)
        }
        Err(e) => {
            if let Err(rb) = tx.rollback().await {
                tracing::warn!(
                    target: "postgres",
                    tenant_id = %tenant,
                    error = %secure::redact_error(&rb),
                    "tenant_scoped_read: rollback failed after read error"
                );
            }
            Err(e)
        }
    }
}

/// tenant-scoped read variant for closures that return domain errors while storage errors
/// still flow through `map_storage`.
pub(crate) async fn tenant_scoped_read_map<T, F, E>(
    pool: &PgPool,
    tenant: TenantId,
    read: F,
    map_storage: impl Fn(sqlx::Error) -> E + Send,
) -> Result<T, E>
where
    F: for<'c> FnOnce(&'c mut PgConnection) -> BoxFuture<'c, Result<T, E>> + Send,
    E: Send,
    T: Send,
{
    let mut tx = begin_tenant_read(pool, tenant)
        .await
        .map_err(&map_storage)?;
    match read(&mut tx).await {
        Ok(v) => {
            tx.commit().await.map_err(|e| {
                tracing::warn!(
                    target: "postgres",
                    tenant_id = %tenant,
                    error = %secure::redact_error(&e),
                    "tenant_scoped_read_map: commit failed"
                );
                map_storage(e)
            })?;
            Ok(v)
        }
        Err(e) => {
            if let Err(rb) = tx.rollback().await {
                tracing::warn!(
                    target: "postgres",
                    tenant_id = %tenant,
                    error = %secure::redact_error(&rb),
                    "tenant_scoped_read_map: rollback failed after read error"
                );
            }
            Err(e)
        }
    }
}

/// Open the shared read-lane transaction skeleton atomically as PostgreSQL `READ ONLY` before
/// executing the first tenant-scoped statement.
///
/// `ref: sqlx sqlx-core/src/pool/mod.rs@v0.8.6` — `Pool::begin_with` owns the acquired connection
/// and sends the custom top-level `BEGIN` through SQLx's transaction manager.
async fn begin_tenant_read(
    pool: &PgPool,
    tenant: TenantId,
) -> Result<Transaction<'static, Postgres>, sqlx::Error> {
    let mut tx = pool.begin_with("BEGIN READ ONLY").await?;
    set_local_tenant(&mut tx, tenant).await?;
    Ok(tx)
}

/// 在事务内注入 tenant scope（SET LOCAL `rss.tenant_id`，参数化绑定防注入；tenancy.md §RLS 与 PG scope）。
/// producer 写（[`PgTenantWritePool::producer_tx`]）与 plain tenant-scoped 写
/// 共享，保证所有 postgres 写路径经统一 SET LOCAL 收口（未来 RLS policy 的 current_setting 锚点，不留绕过面）。
///
/// # INVARIANT: TENANCY-SETLOCAL-FUNNEL-01 { level = "Medium", exec = "manual/opt-in", source = "code" }
///
/// 这是 postgres 生产路径**唯一**注入 `rss.tenant_id` GUC 的位置——funnel 入参类型化为
/// `vocab::TenantId`（Hard：裸 `&str` 无法进入），`set_config('rss.tenant_id', ..)` literal 仅此一处出现
/// （xtask `setlocal-funnel` 守卫，Medium：禁止该 literal 出现在 cotx.rs 之外的生产源；测试代码豁免）。
pub(crate) async fn set_local_tenant(
    conn: &mut PgConnection,
    tenant: TenantId,
) -> Result<(), sqlx::Error> {
    // SET LOCAL 不接 bind ⇒ 用 set_config(is_local=true) 参数化绑定；canonical UUID 字符串。
    let tenant_uuid = tenant.as_uuid().to_string();
    sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
        .bind(tenant_uuid)
        .execute(conn)
        .await
        .map(|_| ())
}

#[cfg(any(feature = "domain-settings", feature = "domain-audit"))]
async fn set_local_retry_deadlines(
    conn: &mut PgConnection,
    deadline: LocalTxDeadline,
) -> Result<(), sqlx::Error> {
    let (statement_millis, lock_millis) = deadline.server_timeout_millis();
    sqlx::query(
        "SELECT set_config('statement_timeout', $1, true), \
                set_config('lock_timeout', $2, true)",
    )
    .bind(format!("{statement_millis}ms"))
    .bind(format!("{lock_millis}ms"))
    .execute(conn)
    .await
    .map(|_| ())
}

async fn set_local_plain_lock_timeout(conn: &mut PgConnection) -> Result<(), sqlx::Error> {
    sqlx::query("SELECT set_config('lock_timeout', '5s', true)")
        .execute(conn)
        .await
        .map(|_| ())
}

async fn tenant_scoped_write_inner<T, F, E>(
    pool: &PgPool,
    tenant: TenantId,
    write: F,
    map_storage: impl Fn(sqlx::Error) -> E + Send,
) -> LocalTxAttempt<T, E>
where
    F: for<'c, 'tx> FnOnce(&'c mut TxCapability<'tx>) -> BoxFuture<'c, Result<T, E>> + Send,
    E: std::error::Error + Send + Sync + 'static,
    T: Send,
{
    execute_local_tx(
        pool,
        tenant,
        LocalTxExecutionPolicy::Plain,
        PlainLocalTxOperation(write),
        map_storage,
        "tenant-scoped-write",
    )
    .await
}

#[cfg(any(feature = "domain-settings", feature = "domain-audit"))]
async fn tenant_scoped_retry_write_inner<T, F, E>(
    pool: &PgPool,
    tenant: TenantId,
    deadline: LocalTxDeadline,
    write: F,
    map_storage: impl Fn(sqlx::Error) -> E + Send,
) -> LocalTxAttempt<T, E>
where
    F: for<'c, 'tx> FnOnce(&'c mut TxCapability<'tx>) -> BoxFuture<'c, Result<T, E>> + Send,
    E: std::error::Error + Send + Sync + 'static,
    T: Send,
{
    execute_local_tx(
        pool,
        tenant,
        LocalTxExecutionPolicy::Deadline(deadline),
        PlainLocalTxOperation(write),
        map_storage,
        "tenant-scoped-write",
    )
    .await
}

/// 在单事务内：注入 tenant scope（SET LOCAL）→ 业务写闭包 → `append_outbox` → 单 commit。
///
#[cfg(any(feature = "domain-settings", feature = "domain-identity"))]
async fn producer_tx_inner<A, T, F, E>(
    pool: &PgPool,
    projection_registry: ProjectionWriteRegistry,
    write: ProducerTxWrite<'_>,
    policy: LocalTxExecutionPolicy,
    business_write: F,
    map_storage: impl Fn(sqlx::Error) -> E + Send + Sync,
) -> LocalTxAttempt<T, E>
where
    F: for<'c, 'tx> FnOnce(
            &'c mut TxCapability<'tx>,
        ) -> BoxFuture<'c, Result<ProducerTxOutcome<A, T>, E>>
        + Send,
    E: MapOutboxAppendError + std::error::Error + Send + Sync + 'static,
    A: ProducerFactAuthorization,
    T: Send + 'static,
{
    execute_producer_local_tx(
        pool,
        projection_registry,
        write,
        policy,
        business_write,
        map_storage,
    )
    .await
}

#[derive(Clone, Copy)]
enum LocalTxExecutionPolicy {
    Plain,
    #[cfg(any(feature = "domain-settings", feature = "domain-audit"))]
    Deadline(LocalTxDeadline),
}

impl LocalTxExecutionPolicy {
    async fn acquire(
        self,
        pool: &PgPool,
    ) -> LocalTxStageResult<LocalTxConnectionLease, sqlx::Error, LocalTxAcquireDeadline> {
        match self {
            Self::Plain => match LocalTxConnectionLease::acquire(pool).await {
                Ok(lease) => LocalTxStageResult::Complete(lease),
                Err(error) => LocalTxStageResult::Failed(error),
            },
            #[cfg(any(feature = "domain-settings", feature = "domain-audit"))]
            Self::Deadline(deadline) => {
                deadline
                    .acquire(LocalTxConnectionLease::acquire(pool))
                    .await
            }
        }
    }

    async fn begin<'lease>(
        self,
        lease: &'lease mut LocalTxConnectionLease,
    ) -> LocalTxStageResult<LocalTxTransaction<'lease>, sqlx::Error, LocalTxBeginDeadline> {
        match self {
            Self::Plain => match lease.begin().await {
                Ok(tx) => LocalTxStageResult::Complete(tx),
                Err(error) => LocalTxStageResult::Failed(error),
            },
            #[cfg(any(feature = "domain-settings", feature = "domain-audit"))]
            Self::Deadline(deadline) => deadline.begin(lease.begin()).await,
        }
    }

    async fn setup(
        self,
        tx: &mut TxCapability<'_>,
        tenant: TenantId,
    ) -> LocalTxStageResult<(), sqlx::Error, LocalTxSetupDeadline> {
        let setup = async {
            #[cfg(all(test, feature = "integration"))]
            pause_localtx_stage_for_test(LocalTxTestPauseStage::Setup).await;
            set_local_tenant(tx.conn(), tenant).await?;
            match self {
                Self::Plain => set_local_plain_lock_timeout(tx.conn()).await?,
                #[cfg(any(feature = "domain-settings", feature = "domain-audit"))]
                Self::Deadline(deadline) => {
                    // Compute immediately before this single round-trip; the following statement in
                    // `execute_local_tx` is the mutation itself.
                    set_local_retry_deadlines(tx.conn(), deadline).await?;
                }
            }
            Ok(())
        };
        match self {
            Self::Plain => match setup.await {
                Ok(()) => LocalTxStageResult::Complete(()),
                Err(error) => LocalTxStageResult::Failed(error),
            },
            #[cfg(any(feature = "domain-settings", feature = "domain-audit"))]
            Self::Deadline(deadline) => deadline.setup(setup).await,
        }
    }

    async fn operation<F, T, E>(
        self,
        future: F,
    ) -> LocalTxStageResult<T, E, LocalTxOperationDeadline>
    where
        F: std::future::Future<Output = Result<T, E>>,
        E: std::error::Error + 'static,
    {
        match self {
            Self::Plain => match future.await {
                Ok(value) => LocalTxStageResult::Complete(value),
                Err(error) => LocalTxStageResult::Failed(error),
            },
            #[cfg(any(feature = "domain-settings", feature = "domain-audit"))]
            Self::Deadline(deadline) => deadline.operation(future).await,
        }
    }

    async fn commit(
        self,
        future: impl std::future::Future<Output = Result<(), sqlx::Error>>,
    ) -> LocalTxStageResult<(), sqlx::Error, LocalTxCommitDeadline> {
        match self {
            Self::Plain => match future.await {
                Ok(()) => LocalTxStageResult::Complete(()),
                Err(error) => LocalTxStageResult::Failed(error),
            },
            #[cfg(any(feature = "domain-settings", feature = "domain-audit"))]
            Self::Deadline(deadline) => deadline.commit(future).await,
        }
    }

    async fn rollback(
        self,
        future: impl std::future::Future<Output = Result<(), sqlx::Error>>,
    ) -> LocalTxStageResult<(), sqlx::Error, LocalTxRollbackDeadline> {
        match self {
            Self::Plain => match future.await {
                Ok(()) => LocalTxStageResult::Complete(()),
                Err(error) => LocalTxStageResult::Failed(error),
            },
            #[cfg(any(feature = "domain-settings", feature = "domain-audit"))]
            Self::Deadline(deadline) => deadline.rollback(future).await,
        }
    }
}

enum LocalTxBodyResult<T, E> {
    Success(T),
    Failed(E),
    SetupDeadline(E, LocalTxSetupDeadline),
    OperationDeadline(E, LocalTxOperationDeadline),
}

trait LocalTxOperation<T, E>: Send {
    fn execute<'c, 'tx>(self, tx: &'c mut TxCapability<'tx>) -> BoxFuture<'c, Result<T, E>>
    where
        Self: 'c;
}

struct PlainLocalTxOperation<F>(F);

impl<T, E, F> LocalTxOperation<T, E> for PlainLocalTxOperation<F>
where
    F: for<'c, 'tx> FnOnce(&'c mut TxCapability<'tx>) -> BoxFuture<'c, Result<T, E>> + Send,
{
    fn execute<'c, 'tx>(self, tx: &'c mut TxCapability<'tx>) -> BoxFuture<'c, Result<T, E>>
    where
        Self: 'c,
    {
        (self.0)(tx)
    }
}

#[cfg(any(feature = "domain-settings", feature = "domain-identity"))]
struct ProducerLocalTxOperation<'a, F> {
    projection_registry: ProjectionWriteRegistry,
    write: ProducerTxWrite<'a>,
    business_write: F,
}

#[cfg(any(feature = "domain-settings", feature = "domain-identity"))]
impl<'a, A, T, F, E> LocalTxOperation<T, ProducerTxWriteError<E>>
    for ProducerLocalTxOperation<'a, F>
where
    F: for<'c, 'tx> FnOnce(
            &'c mut TxCapability<'tx>,
        ) -> BoxFuture<'c, Result<ProducerTxOutcome<A, T>, E>>
        + Send,
    E: std::error::Error + Send + Sync + 'static,
    A: ProducerFactAuthorization,
    T: Send + 'static,
{
    fn execute<'c, 'tx>(
        self,
        tx: &'c mut TxCapability<'tx>,
    ) -> BoxFuture<'c, Result<T, ProducerTxWriteError<E>>>
    where
        Self: 'c,
    {
        Box::pin(complete_producer_write(
            tx,
            self.projection_registry,
            self.write.tenant,
            self.write.entry,
            self.write.env,
            self.business_write,
        ))
    }
}

#[derive(Clone, Copy)]
enum LocalTxPrimaryDeadline {
    Setup(LocalTxSetupDeadline),
    Operation(LocalTxOperationDeadline),
}

/// The only tenant mutation transaction core.
async fn execute_local_tx<T, O, E>(
    pool: &PgPool,
    tenant: TenantId,
    policy: LocalTxExecutionPolicy,
    write: O,
    map_storage: impl Fn(sqlx::Error) -> E,
    operation: &'static str,
) -> LocalTxAttempt<T, E>
where
    O: LocalTxOperation<T, E>,
    E: std::error::Error + Send + Sync + 'static,
    T: Send,
{
    let mut lease = match policy.acquire(pool).await {
        LocalTxStageResult::Complete(lease) => lease,
        LocalTxStageResult::Failed(error) => {
            return LocalTxAttempt::unsettled(map_storage(error));
        }
        LocalTxStageResult::Deadline { evidence, .. } => {
            return LocalTxAttempt::unsettled_acquire_deadline(
                map_storage(localtx_timeout_error()),
                evidence,
            );
        }
    };
    let mut tx = match policy.begin(&mut lease).await {
        LocalTxStageResult::Complete(tx) => tx,
        LocalTxStageResult::Failed(error) => {
            return LocalTxAttempt::unsettled(map_storage(error));
        }
        LocalTxStageResult::Deadline { evidence, .. } => {
            return LocalTxAttempt::unsettled_begin_deadline(
                map_storage(localtx_timeout_error()),
                evidence,
            );
        }
    };

    let setup_result = {
        let mut tx_cap = tx.capability();
        policy.setup(&mut tx_cap, tenant).await
    };
    let body_result = match setup_result {
        LocalTxStageResult::Complete(()) => {
            let mut tx_cap = tx.capability();
            match policy.operation(write.execute(&mut tx_cap)).await {
                LocalTxStageResult::Complete(value) => LocalTxBodyResult::Success(value),
                LocalTxStageResult::Failed(error) => LocalTxBodyResult::Failed(error),
                LocalTxStageResult::Deadline { source, evidence } => {
                    LocalTxBodyResult::OperationDeadline(
                        source.unwrap_or_else(|| map_storage(localtx_timeout_error())),
                        evidence,
                    )
                }
            }
        }
        LocalTxStageResult::Failed(error) => LocalTxBodyResult::Failed(map_storage(error)),
        LocalTxStageResult::Deadline { source, evidence } => LocalTxBodyResult::SetupDeadline(
            map_storage(source.unwrap_or_else(localtx_timeout_error)),
            evidence,
        ),
    };
    finish_local_tx(tx, body_result, map_storage, operation, tenant, policy).await
}

#[cfg(any(feature = "domain-settings", feature = "domain-identity"))]
async fn execute_producer_local_tx<A, T, F, E>(
    pool: &PgPool,
    projection_registry: ProjectionWriteRegistry,
    write: ProducerTxWrite<'_>,
    policy: LocalTxExecutionPolicy,
    business_write: F,
    map_storage: impl Fn(sqlx::Error) -> E + Send + Sync,
) -> LocalTxAttempt<T, E>
where
    F: for<'c, 'tx> FnOnce(
            &'c mut TxCapability<'tx>,
        ) -> BoxFuture<'c, Result<ProducerTxOutcome<A, T>, E>>
        + Send,
    E: MapOutboxAppendError + std::error::Error + Send + Sync + 'static,
    A: ProducerFactAuthorization,
    T: Send + 'static,
{
    let attempt = execute_local_tx(
        pool,
        write.tenant,
        policy,
        ProducerLocalTxOperation {
            projection_registry,
            write: ProducerTxWrite {
                tenant: write.tenant,
                entry: write.entry,
                env: write.env,
            },
            business_write,
        },
        ProducerTxWriteError::TenantScope,
        "producer-tx",
    )
    .await;
    attempt.map_error(|error| {
        log_producer_tx_write_error(write.entry, write.env, &error);
        error.into_domain(&map_storage)
    })
}

/// Settle every LocalTx attempt through the only commit/explicit-rollback branch.
async fn finish_local_tx<T, E>(
    tx: LocalTxTransaction<'_>,
    result: LocalTxBodyResult<T, E>,
    map_storage: impl Fn(sqlx::Error) -> E,
    operation: &'static str,
    tenant: TenantId,
    policy: LocalTxExecutionPolicy,
) -> LocalTxAttempt<T, E>
where
    E: std::error::Error + Send + Sync + 'static,
{
    match result {
        LocalTxBodyResult::Success(value) => {
            commit_local_tx(tx, value, map_storage, operation, tenant, policy).await
        }
        LocalTxBodyResult::Failed(error) => {
            rollback_local_tx(tx, error, None, map_storage, operation, tenant, policy).await
        }
        LocalTxBodyResult::SetupDeadline(error, evidence) => {
            rollback_local_tx(
                tx,
                error,
                Some(LocalTxPrimaryDeadline::Setup(evidence)),
                map_storage,
                operation,
                tenant,
                policy,
            )
            .await
        }
        LocalTxBodyResult::OperationDeadline(error, evidence) => {
            rollback_local_tx(
                tx,
                error,
                Some(LocalTxPrimaryDeadline::Operation(evidence)),
                map_storage,
                operation,
                tenant,
                policy,
            )
            .await
        }
    }
}

async fn commit_local_tx<T, E>(
    tx: LocalTxTransaction<'_>,
    value: T,
    map_storage: impl Fn(sqlx::Error) -> E,
    operation: &'static str,
    tenant: TenantId,
    policy: LocalTxExecutionPolicy,
) -> LocalTxAttempt<T, E> {
    #[allow(unused_mut)]
    let mut tx = tx;
    #[cfg(any(all(test, feature = "integration"), feature = "journey-fault-support"))]
    let inject_commit_unknown = {
        let mut tx_cap = tx.capability();
        test_commit_unknown_after_commit_requested(&mut tx_cap).await
    };
    #[cfg(any(all(test, feature = "integration"), feature = "journey-fault-support"))]
    let commit_result = if inject_commit_unknown {
        policy.commit(tx.commit_unknown_after_ack()).await
    } else {
        policy.commit(tx.commit()).await
    };
    #[cfg(not(any(all(test, feature = "integration"), feature = "journey-fault-support")))]
    let commit_result = policy.commit(tx.commit()).await;

    match commit_result {
        LocalTxStageResult::Complete(()) => LocalTxAttempt::committed(value),
        LocalTxStageResult::Failed(error) => {
            finish_local_tx_commit_result(Err(error), value, map_storage, operation, tenant)
        }
        LocalTxStageResult::Deadline { source, evidence } => {
            tracing::debug!(
                target: "postgres",
                operation,
                tenant_id = %tenant,
                "local transaction commit exceeded final deadline"
            );
            LocalTxAttempt::commit_unknown_deadline(
                map_storage(commit_unknown(source.unwrap_or_else(localtx_timeout_error))),
                evidence,
            )
        }
    }
}

async fn rollback_local_tx<T, E>(
    tx: LocalTxTransaction<'_>,
    error: E,
    primary: Option<LocalTxPrimaryDeadline>,
    map_storage: impl Fn(sqlx::Error) -> E,
    operation: &'static str,
    tenant: TenantId,
    policy: LocalTxExecutionPolicy,
) -> LocalTxAttempt<T, E>
where
    E: std::error::Error + Send + Sync + 'static,
{
    let rollback_result = run_local_tx_rollback(tx, policy).await;
    match rollback_result {
        LocalTxStageResult::Complete(()) => match primary {
            None => LocalTxAttempt::rolled_back(error),
            Some(LocalTxPrimaryDeadline::Setup(evidence)) => {
                LocalTxAttempt::rolled_back_setup_deadline(error, evidence)
            }
            Some(LocalTxPrimaryDeadline::Operation(evidence)) => {
                LocalTxAttempt::rolled_back_operation_deadline(error, evidence)
            }
        },
        LocalTxStageResult::Failed(rollback_error) => finish_local_tx_rollback_result(
            Err(rollback_error),
            error,
            map_storage,
            operation,
            tenant,
        ),
        LocalTxStageResult::Deadline { source, evidence } => {
            let mapped = map_storage(rollback_failed(
                error,
                source.unwrap_or_else(localtx_timeout_error),
            ));
            match primary {
                None => LocalTxAttempt::rollback_failed_deadline(mapped, evidence),
                Some(LocalTxPrimaryDeadline::Setup(setup)) => {
                    LocalTxAttempt::rollback_failed_setup_deadline(mapped, setup, evidence)
                }
                Some(LocalTxPrimaryDeadline::Operation(operation)) => {
                    LocalTxAttempt::rollback_failed_operation_deadline(mapped, operation, evidence)
                }
            }
        }
    }
}

async fn run_local_tx_rollback(
    tx: LocalTxTransaction<'_>,
    policy: LocalTxExecutionPolicy,
) -> LocalTxStageResult<(), sqlx::Error, LocalTxRollbackDeadline> {
    #[allow(unused_mut)]
    let mut tx = tx;
    #[cfg(all(test, feature = "integration"))]
    let inject_rollback_timeout = {
        let mut tx_cap = tx.capability();
        test_rollback_timeout_requested(&mut tx_cap).await
    };
    #[cfg(all(test, feature = "integration"))]
    let inject_rollback_failed = {
        let mut tx_cap = tx.capability();
        test_rollback_failed_after_rollback_requested(&mut tx_cap).await
    };
    #[cfg(all(test, feature = "integration"))]
    if inject_rollback_timeout {
        return policy.rollback(tx.rollback_paused_before_ack()).await;
    }
    #[cfg(all(test, feature = "integration"))]
    if inject_rollback_failed {
        return policy.rollback(tx.rollback_failed_after_ack()).await;
    }
    policy.rollback(tx.rollback()).await
}

fn localtx_timeout_error() -> sqlx::Error {
    sqlx::Error::Io(std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        "LocalTx execution deadline exceeded",
    ))
}

#[cfg(all(test, feature = "integration"))]
static TEST_ROLLBACK_TIMEOUT_ENTERED: tokio::sync::Notify = tokio::sync::Notify::const_new();

#[cfg(all(test, feature = "integration"))]
static TEST_LOCALTX_PAUSE_SEAM: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[cfg(all(test, feature = "integration"))]
tokio::task_local! {
    static TEST_LOCALTX_PAUSE_STAGE: LocalTxTestPauseStage;
}

#[cfg(all(test, feature = "integration"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LocalTxTestPauseStage {
    Begin,
    Setup,
    Commit,
}

#[cfg(all(test, feature = "integration"))]
pub(crate) async fn with_localtx_pause_for_test<T>(
    stage: LocalTxTestPauseStage,
    future: impl std::future::Future<Output = T>,
) -> T {
    TEST_LOCALTX_PAUSE_STAGE.scope(stage, future).await
}

#[cfg(all(test, feature = "integration"))]
async fn pause_localtx_stage_for_test(stage: LocalTxTestPauseStage) {
    if TEST_LOCALTX_PAUSE_STAGE
        .try_with(|requested| *requested == stage)
        .unwrap_or(false)
    {
        std::future::pending::<()>().await;
    }
}

#[cfg(all(test, feature = "integration"))]
fn notify_rollback_pause_entered_for_test() {
    TEST_ROLLBACK_TIMEOUT_ENTERED.notify_one();
}

#[cfg(all(test, feature = "integration"))]
pub(crate) async fn lock_rollback_timeout_seam_for_test() -> tokio::sync::MutexGuard<'static, ()> {
    TEST_LOCALTX_PAUSE_SEAM.lock().await
}

#[cfg(all(test, feature = "integration"))]
pub(crate) async fn wait_for_rollback_timeout_for_test() {
    TEST_ROLLBACK_TIMEOUT_ENTERED.notified().await;
}

#[cfg(any(all(test, feature = "integration"), feature = "journey-fault-support"))]
async fn test_commit_unknown_after_commit_requested(tx: &mut TxCapability<'_>) -> bool {
    sqlx::query_scalar::<_, Option<String>>(
        "SELECT current_setting('rss.test_commit_unknown_after_commit', true)",
    )
    .fetch_one(tx.conn())
    .await
    .ok()
    .flatten()
    .is_some_and(|value| value == "1")
}

#[cfg(all(test, feature = "integration"))]
async fn test_failure_after_outbox_append_requested(tx: &mut TxCapability<'_>) -> bool {
    sqlx::query_scalar::<_, Option<String>>(
        "SELECT current_setting('rss.test_fail_after_outbox_append', true)",
    )
    .fetch_one(tx.conn())
    .await
    .ok()
    .flatten()
    .is_some_and(|value| value == "1")
}

#[cfg(all(test, feature = "integration"))]
async fn test_failure_after_projection_append_requested(tx: &mut TxCapability<'_>) -> bool {
    sqlx::query_scalar::<_, Option<String>>(
        "SELECT current_setting('rss.test_fail_after_projection_append', true)",
    )
    .fetch_one(tx.conn())
    .await
    .ok()
    .flatten()
    .is_some_and(|value| value == "1")
}

#[cfg(all(test, feature = "integration"))]
async fn test_rollback_failed_after_rollback_requested(tx: &mut TxCapability<'_>) -> bool {
    sqlx::query_scalar::<_, Option<String>>(
        "SELECT current_setting('rss.test_rollback_failed_after_rollback', true)",
    )
    .fetch_one(tx.conn())
    .await
    .ok()
    .flatten()
    .is_some_and(|value| value == "1")
}

#[cfg(all(test, feature = "integration"))]
async fn test_rollback_timeout_requested(tx: &mut TxCapability<'_>) -> bool {
    sqlx::query_scalar::<_, Option<String>>(
        "SELECT current_setting('rss.test_rollback_timeout', true)",
    )
    .fetch_one(tx.conn())
    .await
    .ok()
    .flatten()
    .is_some_and(|value| value == "1")
}

fn finish_local_tx_commit_result<T, E>(
    result: Result<(), sqlx::Error>,
    value: T,
    map_storage: impl FnOnce(sqlx::Error) -> E,
    operation: &'static str,
    tenant: TenantId,
) -> LocalTxAttempt<T, E> {
    match result {
        Ok(()) => LocalTxAttempt::committed(value),
        Err(error) => {
            let redacted_error = secure::redact_error(&error);
            // Actionable WARN ownership belongs to the typed runner: generic routing or HTTP
            // LocalTx observation. This common funnel stays below WARN to avoid duplicate pages.
            tracing::debug!(
                target: "postgres",
                operation,
                tenant_id = %tenant,
                error = %redacted_error,
                "local transaction commit result is unknown"
            );
            LocalTxAttempt::commit_unknown(map_storage(commit_unknown(error)))
        }
    }
}

fn finish_local_tx_rollback_result<T, E>(
    result: Result<(), sqlx::Error>,
    error: E,
    map_storage: impl FnOnce(sqlx::Error) -> E,
    operation: &'static str,
    tenant: TenantId,
) -> LocalTxAttempt<T, E>
where
    E: std::error::Error + Send + Sync + 'static,
{
    match result {
        Ok(()) => LocalTxAttempt::rolled_back(error),
        Err(rollback_error) => {
            let redacted_error = secure::redact_error(&rollback_error);
            // Actionable WARN ownership belongs to the typed runner: generic routing or HTTP
            // LocalTx observation. This common funnel stays below WARN to avoid duplicate pages.
            tracing::debug!(
                target: "postgres",
                operation,
                tenant_id = %tenant,
                error = %redacted_error,
                "local transaction rollback failed"
            );
            LocalTxAttempt::rollback_failed(map_storage(rollback_failed(error, rollback_error)))
        }
    }
}

#[cfg(any(feature = "domain-settings", feature = "domain-identity"))]
async fn complete_producer_write<A, T, F, E>(
    tx: &mut TxCapability<'_>,
    projection_registry: ProjectionWriteRegistry,
    tenant: TenantId,
    entry: &EventEntry,
    env: &OutboxEnvelope,
    business_write: F,
) -> Result<T, ProducerTxWriteError<E>>
where
    F: for<'c, 'tx> FnOnce(
            &'c mut TxCapability<'tx>,
        ) -> BoxFuture<'c, Result<ProducerTxOutcome<A, T>, E>>
        + Send,
    E: std::error::Error + 'static,
    A: ProducerFactAuthorization,
{
    if env.tenant() != tenant {
        return Err(ProducerTxWriteError::TenantMismatch(
            sqlx::Error::AnyDriverError(Box::new(OutboxTenantMismatch)),
        ));
    }
    let outcome = business_write(tx)
        .await
        .map_err(ProducerTxWriteError::BusinessWrite)?;
    match outcome {
        ProducerTxOutcome::Emitted(value, authorization) => {
            let authorized_fact = authorization.fact();
            if !env.matches_contract(authorized_fact.contract())
                || entry.generated_fact() != Some(authorized_fact)
            {
                return Err(ProducerTxWriteError::AuthorizationMismatch(
                    sqlx::Error::AnyDriverError(Box::new(ProducerAuthorizationMismatch)),
                ));
            }
            let _outcome = append_outbox_with_projection(tx, entry, env, &projection_registry)
                .await
                .map_err(ProducerTxWriteError::AppendOutbox)?;
            #[cfg(all(test, feature = "integration"))]
            if test_failure_after_projection_append_requested(tx).await {
                return Err(ProducerTxWriteError::AppendOutbox(
                    OutboxAppendError::Storage(sqlx::Error::Protocol(
                        "injected failure after projection append".to_owned(),
                    )),
                ));
            }
            #[cfg(all(test, feature = "integration"))]
            if test_failure_after_outbox_append_requested(tx).await {
                return Err(ProducerTxWriteError::AppendOutbox(
                    OutboxAppendError::Storage(sqlx::Error::Protocol(
                        "injected failure after outbox append before commit".to_owned(),
                    )),
                ));
            }
            Ok(value)
        }
        #[cfg(feature = "domain-identity")]
        ProducerTxOutcome::MutatedWithoutFact(value) | ProducerTxOutcome::NoMutation(value) => {
            Ok(value)
        }
    }
}

#[cfg(any(feature = "domain-settings", feature = "domain-identity"))]
#[derive(Debug, thiserror::Error)]
enum ProducerTxWriteError<E: std::error::Error + 'static> {
    #[error("failed to establish tenant transaction state")]
    TenantScope(#[source] sqlx::Error),
    #[error("outbox tenant does not match transaction tenant")]
    TenantMismatch(#[source] sqlx::Error),
    #[error("producer authorization does not match outbox envelope")]
    AuthorizationMismatch(#[source] sqlx::Error),
    #[error("business write failed")]
    BusinessWrite(#[source] E),
    #[error("outbox append failed")]
    AppendOutbox(#[source] OutboxAppendError),
}

#[cfg(any(feature = "domain-settings", feature = "domain-identity"))]
pub(crate) trait MapOutboxAppendError {
    fn from_outbox_append(error: OutboxAppendError) -> Self;
}

#[cfg(any(feature = "domain-settings", feature = "domain-identity"))]
impl MapOutboxAppendError for OutboxEmitError {
    fn from_outbox_append(error: OutboxAppendError) -> Self {
        error.into_emit_error()
    }
}

#[cfg(feature = "domain-settings")]
impl MapOutboxAppendError for settings::ports::ConfigRepoError {
    fn from_outbox_append(error: OutboxAppendError) -> Self {
        match error {
            OutboxAppendError::Conflict(conflict) => Self::OutboxFactConflict(conflict),
            other => Self::Storage(Box::new(other)),
        }
    }
}

#[cfg(feature = "domain-identity")]
impl MapOutboxAppendError for identity::ports::IdentityError {
    fn from_outbox_append(error: OutboxAppendError) -> Self {
        match error {
            OutboxAppendError::Conflict(conflict) => Self::OutboxFactConflict(conflict),
            OutboxAppendError::Storage(error) => crate::tx_retry::identity_storage_error(error),
            other => Self::Storage(Box::new(other)),
        }
    }
}

#[cfg(any(feature = "domain-settings", feature = "domain-identity"))]
impl<E: MapOutboxAppendError + std::error::Error + 'static> ProducerTxWriteError<E> {
    fn stage(&self) -> &'static str {
        match self {
            Self::TenantScope(_) => "set-local-tenant",
            Self::TenantMismatch(_) => "outbox-tenant-match",
            Self::AuthorizationMismatch(_) => "producer-authorization-match",
            Self::BusinessWrite(_) => "business-write",
            Self::AppendOutbox(_) => "append-outbox",
        }
    }

    fn sqlx_source(&self) -> Option<&sqlx::Error> {
        match self {
            Self::TenantScope(e) | Self::TenantMismatch(e) | Self::AuthorizationMismatch(e) => {
                Some(e)
            }
            Self::AppendOutbox(OutboxAppendError::Storage(e)) => Some(e),
            Self::AppendOutbox(
                OutboxAppendError::Conflict(_)
                | OutboxAppendError::CanonicalDrift
                | OutboxAppendError::InvalidIdentity,
            )
            | Self::BusinessWrite(_) => None,
        }
    }

    fn into_domain(self, map_storage: &(impl Fn(sqlx::Error) -> E + Send)) -> E {
        match self {
            Self::TenantScope(e) | Self::TenantMismatch(e) | Self::AuthorizationMismatch(e) => {
                map_storage(e)
            }
            Self::AppendOutbox(e) => E::from_outbox_append(e),
            Self::BusinessWrite(e) => e,
        }
    }
}

#[cfg(any(feature = "domain-settings", feature = "domain-identity"))]
fn log_producer_tx_write_error<E: MapOutboxAppendError + std::error::Error + 'static>(
    entry: &EventEntry,
    env: &OutboxEnvelope,
    error: &ProducerTxWriteError<E>,
) {
    if let ProducerTxWriteError::AppendOutbox(append_error) = error
        && log_producer_tx_identity_error(append_error)
    {
        return;
    }
    if let Some(source) = error.sqlx_source() {
        log_producer_tx_sqlx_error(entry, env, error.stage(), source);
    } else {
        log_producer_tx_domain_error(entry, env, error.stage());
    }
}

#[cfg(any(feature = "domain-settings", feature = "domain-identity"))]
const PRODUCER_TX_ROLLBACK_MESSAGE: &str = "producer tx: write failed; rolling back";

#[cfg(any(feature = "domain-settings", feature = "domain-identity"))]
fn log_producer_tx_identity_error(error: &OutboxAppendError) -> bool {
    let Some(reason) = error.identity_failure_reason() else {
        return false;
    };
    tracing::warn!(
        target: "postgres",
        stage = "append-outbox",
        reason,
        message = PRODUCER_TX_ROLLBACK_MESSAGE,
    );
    true
}

#[cfg(any(feature = "domain-settings", feature = "domain-identity"))]
fn log_producer_tx_sqlx_error(
    entry: &EventEntry,
    env: &OutboxEnvelope,
    stage: &'static str,
    source: &sqlx::Error,
) {
    tracing::warn!(
        target: "postgres",
        event_id = entry.idem_key().as_str(),
        domain = env.domain(),
        topic = entry.topic().as_str(),
        stage,
        error = %secure::redact_error(source),
        message = PRODUCER_TX_ROLLBACK_MESSAGE,
    );
}

#[cfg(any(feature = "domain-settings", feature = "domain-identity"))]
fn log_producer_tx_domain_error(entry: &EventEntry, env: &OutboxEnvelope, stage: &'static str) {
    tracing::warn!(
        target: "postgres",
        event_id = entry.idem_key().as_str(),
        domain = env.domain(),
        topic = entry.topic().as_str(),
        stage,
        message = PRODUCER_TX_ROLLBACK_MESSAGE,
    );
}

#[cfg(test)]
mod tx_capability_tests {
    use consistency::LocalTxFinalStatus;

    use super::{Postgres, Transaction, TxCapability, finish_local_tx_commit_result};

    #[cfg(feature = "domain-identity")]
    #[test]
    fn identity_outbox_append_unavailable_remains_retryable_to_http_boundary() {
        use super::MapOutboxAppendError as _;

        let error = identity::ports::IdentityError::from_outbox_append(
            crate::outbox::OutboxAppendError::Storage(sqlx::Error::PoolTimedOut),
        );
        assert!(matches!(
            error,
            identity::ports::IdentityError::ProviderUnavailable(_)
        ));
    }

    fn tenant() -> Result<vocab::TenantId, String> {
        vocab::TenantId::parse("11111111-1111-1111-1111-111111111111")
            .map_err(|error| format!("invalid tenant fixture: {error:?}"))
    }

    #[test]
    fn tx_capability_mint_signature_is_crate_private() {
        fn mint_from_sqlx_transaction<'tx, 'p>(
            tx: &'tx mut Transaction<'p, Postgres>,
        ) -> TxCapability<'tx> {
            TxCapability::from_transaction(tx)
        }

        let _ = mint_from_sqlx_transaction;
    }

    #[test]
    fn commit_result_is_mapped_to_committed_or_unknown() -> Result<(), String> {
        let committed = finish_local_tx_commit_result::<_, sqlx::Error>(
            Ok(()),
            7,
            core::convert::identity,
            "test",
            tenant()?,
        );
        assert_eq!(committed.settlement(), Some(LocalTxFinalStatus::Committed));
        assert!(matches!(committed.into_result(), Ok(7)));

        let unknown = finish_local_tx_commit_result(
            Err(sqlx::Error::PoolTimedOut),
            (),
            core::convert::identity,
            "test",
            tenant()?,
        );
        assert_eq!(
            unknown.settlement(),
            Some(LocalTxFinalStatus::CommitUnknown)
        );
        assert!(unknown.into_result().is_err());
        Ok(())
    }

    #[cfg(feature = "domain-settings")]
    #[test]
    fn rollback_result_preserves_primary_on_success_and_settlement_error_on_failure()
    -> Result<(), String> {
        use settings::ports::ConfigRepoError;

        use super::finish_local_tx_rollback_result;

        let rolled_back = finish_local_tx_rollback_result::<(), _>(
            Ok(()),
            ConfigRepoError::VersionConflict,
            |error| ConfigRepoError::Storage(Box::new(error)),
            "test",
            tenant()?,
        );
        assert_eq!(
            rolled_back.settlement(),
            Some(LocalTxFinalStatus::RolledBack)
        );
        assert!(matches!(
            rolled_back.into_result(),
            Err(ConfigRepoError::VersionConflict)
        ));

        let failed = finish_local_tx_rollback_result::<(), _>(
            Err(sqlx::Error::PoolTimedOut),
            ConfigRepoError::VersionConflict,
            |error| ConfigRepoError::Storage(Box::new(error)),
            "test",
            tenant()?,
        );
        assert_eq!(
            failed.settlement(),
            Some(LocalTxFinalStatus::RollbackFailed)
        );
        let err = match failed.into_result() {
            Err(error) => error,
            Ok(_) => return Err("rollback-failed must err".into()),
        };
        assert!(
            matches!(err, ConfigRepoError::Storage(_)),
            "rollback-failed must surface storage settlement error, got {err:?}"
        );
        assert!(
            !matches!(err, ConfigRepoError::VersionConflict),
            "rollback-failed must not resurface retryable VersionConflict"
        );
        Ok(())
    }

    #[cfg(feature = "domain-settings")]
    #[tokio::test]
    async fn begin_failure_is_unsettled_for_all_write_adapters() -> Result<(), String> {
        use settings::ports::ConfigRepoError;
        use sqlx::postgres::PgPoolOptions;

        use super::PgTenantWritePool;
        use crate::outbox::{OutboxEnvelope, OutboxMetadata};
        let tenant = tenant()?;
        let pool = PgPoolOptions::new()
            .acquire_timeout(core::time::Duration::from_millis(10))
            .connect_lazy("postgres://127.0.0.1:1/rss")
            .map_err(|error| error.to_string())?;
        let store = crate::PgStore { pool };
        let scoped = PgTenantWritePool::from_unverified_for_test(&store);
        let map_storage = |error: sqlx::Error| ConfigRepoError::Storage(Box::new(error));

        let plain = scoped
            .write(
                settings::ports::TenantRepoScope::for_test(tenant),
                |_| Box::pin(async { Ok::<(), ConfigRepoError>(()) }),
                map_storage,
            )
            .await;
        assert!(plain.is_err());

        let retry = scoped
            .retry_write(
                settings::ports::TenantRepoScope::for_test(tenant),
                crate::tx_retry::localtx_deadline_for_test(),
                |_| Box::pin(async { Ok::<(), ConfigRepoError>(()) }),
                map_storage,
            )
            .await;
        assert_eq!(retry.settlement(), None);

        let contract = vocab::ContractBinding::from_static(
            "settings",
            "settings.config-updated",
            "v1",
            "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        );
        let entry = consistency::EventEntry::new(
            consistency::EventTopic::parse("settings.config-updated")
                .map_err(|error| format!("event topic: {error:?}"))?,
            consistency::IdemKey::parse("localtx-begin-failure")
                .map_err(|error| format!("idem key: {error:?}"))?,
            consistency::OutboxPayload::from_reviewed_event_bytes(Vec::new()),
        );
        let env = OutboxEnvelope::new(
            "settings".to_string(),
            "settings.config-updated".to_string(),
            OutboxMetadata::new(0, tenant, contract),
        );

        let authorization = settings::config_publish_receipt_for_test()
            .authorize(
                <generated::event::settings_v1::SettingsConfigVersionChangedPayload as vocab::GeneratedEventPayload>::FACT,
                settings::ports::CONFIG_VERSION_CHANGED_CONTRACT,
            )
            .ok_or_else(|| "test producer authorization missing".to_owned())?;
        let producer_tx = scoped
            .producer_tx(
                settings::ports::TenantRepoScope::for_test(tenant),
                &entry,
                &env,
                move |_| {
                    Box::pin(async move {
                        Ok::<_, ConfigRepoError>(super::ProducerTxOutcome::Emitted(
                            (),
                            authorization,
                        ))
                    })
                },
                map_storage,
            )
            .await;
        assert!(producer_tx.into_result().is_err());

        let retry_producer_tx = scoped
            .retry_producer_tx(
                settings::ports::TenantRepoScope::for_test(tenant),
                crate::tx_retry::localtx_deadline_for_test(),
                &entry,
                &env,
                move |_| {
                    Box::pin(async move {
                        Ok::<_, ConfigRepoError>(super::ProducerTxOutcome::Emitted(
                            (),
                            authorization,
                        ))
                    })
                },
                map_storage,
            )
            .await;
        assert_eq!(retry_producer_tx.settlement(), None);
        Ok(())
    }

    #[cfg(feature = "domain-settings")]
    #[test]
    fn rollback_failed_is_non_retryable_internal_not_conflict() -> Result<(), String> {
        use settings::ports::ConfigRepoError;

        use super::finish_local_tx_rollback_result;

        let failed = finish_local_tx_rollback_result::<(), _>(
            Err(sqlx::Error::PoolTimedOut),
            ConfigRepoError::VersionConflict,
            |error| ConfigRepoError::Storage(Box::new(error)),
            "test",
            tenant()?,
        );
        let err = match failed.into_result() {
            Err(error) => error,
            Ok(_) => return Err("rollback-failed must err".into()),
        };
        let kind = match err {
            ConfigRepoError::VersionConflict => vocab::CoreErrorKind::VersionConflict,
            ConfigRepoError::Storage(_) => vocab::CoreErrorKind::Internal,
            other => {
                return Err(format!("unexpected error: {other:?}"));
            }
        };
        assert_eq!(kind, vocab::CoreErrorKind::Internal);
        assert!(
            !kind.retryable(),
            "rollback-failed must fail-closed as non-retryable"
        );
        assert_eq!(
            crate::tx_retry::classify_config_repo_error(&err),
            consistency::TxRetryClass::Permanent
        );
        Ok(())
    }
}

#[cfg(all(test, any(feature = "domain-settings", feature = "domain-identity")))]
mod retry_settlement_tests {
    #[cfg(feature = "domain-settings")]
    use std::{
        collections::BTreeMap,
        sync::{
            Arc, Mutex,
            atomic::{AtomicU32, Ordering},
        },
    };

    use consistency::TxRetryClass;
    #[cfg(feature = "domain-settings")]
    use tracing::{Event, Id, Metadata, Subscriber, field::Visit};

    use super::LocalTxAttempt;
    #[cfg(feature = "domain-settings")]
    use super::ProducerTxAttempt;
    use crate::tx_retry::run_pg_localtx_retry;
    #[cfg(feature = "domain-settings")]
    use crate::tx_retry::{SETTINGS_CONFIG_BOUNDARY, SETTINGS_SECRET_BOUNDARY, run_pg_tx_retry};

    #[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
    enum FakeError {
        #[error("transient")]
        Transient,
        #[error("conflict")]
        Conflict,
        #[cfg(feature = "domain-settings")]
        #[error("permanent")]
        Permanent,
        #[error("ownership lost")]
        #[cfg(feature = "domain-settings")]
        OwnershipLost,
    }

    fn classify_fake(error: &FakeError) -> TxRetryClass {
        match error {
            FakeError::Transient => TxRetryClass::Transient,
            FakeError::Conflict => TxRetryClass::Conflict,
            #[cfg(feature = "domain-settings")]
            FakeError::Permanent => TxRetryClass::Permanent,
            #[cfg(feature = "domain-settings")]
            FakeError::OwnershipLost => TxRetryClass::OwnershipLost,
        }
    }

    #[cfg(feature = "domain-settings")]
    #[derive(Default)]
    struct CapturedFields(BTreeMap<String, String>);

    #[cfg(feature = "domain-settings")]
    impl Visit for CapturedFields {
        fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
            self.0.insert(field.name().to_owned(), value.to_owned());
        }

        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn core::fmt::Debug) {
            self.0.insert(field.name().to_owned(), format!("{value:?}"));
        }
    }

    #[cfg(feature = "domain-settings")]
    #[derive(Clone, Default)]
    struct WarnCapture {
        records: Arc<Mutex<Vec<BTreeMap<String, String>>>>,
    }

    #[cfg(feature = "domain-settings")]
    impl Subscriber for WarnCapture {
        fn enabled(&self, metadata: &Metadata<'_>) -> bool {
            *metadata.level() == tracing::Level::WARN
        }

        fn new_span(&self, _: &tracing::span::Attributes<'_>) -> Id {
            Id::from_u64(1)
        }

        fn record(&self, _: &Id, _: &tracing::span::Record<'_>) {}

        fn record_follows_from(&self, _: &Id, _: &Id) {}

        fn event(&self, event: &Event<'_>) {
            let mut fields = CapturedFields::default();
            event.record(&mut fields);
            self.records
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .push(fields.0);
        }

        fn enter(&self, _: &Id) {}

        fn exit(&self, _: &Id) {}
    }

    #[cfg(feature = "domain-settings")]
    fn assert_generic_unsafe_warning_scope(records: &[BTreeMap<String, String>]) {
        let unsafe_warnings: Vec<_> = records
            .iter()
            .filter(|fields| fields.contains_key("final_status"))
            .collect();
        assert_eq!(
            unsafe_warnings.len(),
            2,
            "generic unsafe settlements must each emit one routing WARN: {records:?}"
        );
        for final_status in ["commit_unknown", "rollback_failed"] {
            assert!(
                unsafe_warnings.iter().any(|fields| {
                    fields.get("boundary").map(String::as_str)
                        == Some(SETTINGS_SECRET_BOUNDARY.as_label())
                        && fields.get("final_status").map(String::as_str) == Some(final_status)
                }),
                "metric routing scope has no matching WARN for {final_status}: {records:?}"
            );
        }
        for fields in unsafe_warnings {
            assert!(
                fields
                    .keys()
                    .all(|key| matches!(key.as_str(), "message" | "boundary" | "final_status")),
                "generic unsafe WARN escaped the closed routing fields: {fields:?}"
            );
        }
    }

    #[test]
    #[cfg(feature = "domain-settings")]
    fn retry_metrics_emit_closed_labels() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        let capture = WarnCapture::default();
        let records = Arc::clone(&capture.records);
        let dispatch = tracing::Dispatch::new(capture);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()?;
        let _dispatch_guard = tracing::dispatcher::set_default(&dispatch);
        metrics::with_local_recorder(&recorder, || {
            runtime.block_on(async {
                let attempts = AtomicU32::new(0);
                let ok = run_pg_tx_retry(
                    SETTINGS_CONFIG_BOUNDARY,
                    |attempt, _deadline| {
                        attempts.store(attempt, Ordering::Release);
                        async move {
                            if attempt == 1 {
                                LocalTxAttempt::rolled_back(FakeError::Transient)
                            } else {
                                LocalTxAttempt::committed(())
                            }
                        }
                    },
                    classify_fake,
                )
                .await;
                assert!(ok.is_ok());
                assert_eq!(attempts.load(Ordering::Acquire), 2);

                let conflict = run_pg_tx_retry(
                    SETTINGS_CONFIG_BOUNDARY,
                    |_attempt, _deadline| async {
                        LocalTxAttempt::<(), _>::rolled_back(FakeError::Conflict)
                    },
                    classify_fake,
                )
                .await;
                assert!(matches!(conflict, Err(FakeError::Conflict)));

                let exhausted = run_pg_tx_retry(
                    SETTINGS_CONFIG_BOUNDARY,
                    |_attempt, _deadline| async {
                        LocalTxAttempt::<(), _>::rolled_back(FakeError::Transient)
                    },
                    classify_fake,
                )
                .await;
                assert!(matches!(exhausted, Err(FakeError::Transient)));

                for terminal in [
                    LocalTxAttempt::<(), _>::commit_unknown(FakeError::Transient),
                    LocalTxAttempt::rollback_failed(FakeError::Transient),
                ] {
                    let calls = AtomicU32::new(0);
                    let mut terminal = Some(terminal);
                    let result = run_pg_tx_retry(
                        SETTINGS_SECRET_BOUNDARY,
                        |_attempt, _deadline| {
                            calls.fetch_add(1, Ordering::Relaxed);
                            core::future::ready(match terminal.take() {
                                Some(attempt) => attempt,
                                None => LocalTxAttempt::committed(()),
                            })
                        },
                        classify_fake,
                    )
                    .await;
                    assert!(result.is_err());
                    assert_eq!(calls.load(Ordering::Relaxed), 1);
                }
            });
        });
        let rendered = handle.render();
        assert!(rendered.contains("tx_retry_attempts_total"), "{rendered}");
        assert!(rendered.contains("tx_retry_final_total"), "{rendered}");
        assert!(rendered.contains("tx_retry_attempts"), "{rendered}");
        assert!(
            rendered.contains("boundary=\"settings.config\""),
            "{rendered}"
        );
        assert!(rendered.contains("class=\"transient\""), "{rendered}");
        assert!(rendered.contains("status=\"success\""), "{rendered}");
        assert!(rendered.contains("status=\"conflict\""), "{rendered}");
        assert!(rendered.contains("status=\"exhausted\""), "{rendered}");
        assert!(rendered.contains("tx_settlement_final_total"), "{rendered}");
        assert!(
            rendered.contains("boundary=\"settings.secret\""),
            "{rendered}"
        );
        assert!(
            rendered.contains("final_status=\"commit_unknown\""),
            "{rendered}"
        );
        assert!(
            rendered.contains("final_status=\"rollback_failed\""),
            "{rendered}"
        );
        assert!(
            !rendered.contains("localtx_"),
            "generic retry must not emit contract-attributed LocalTx telemetry: {rendered}"
        );
        let records = records.lock().unwrap_or_else(|error| error.into_inner());
        assert_generic_unsafe_warning_scope(&records);
        Ok(())
    }

    #[cfg(feature = "domain-settings")]
    fn settings_secret_observation()
    -> observ::LocalTxObservation<generated::http::settings_v2::RouteMarker> {
        use generated::http::settings_v2::{LOCAL_TX, ROUTE};

        observ::LocalTxObservation::new(ROUTE, LOCAL_TX.boundary)
    }

    #[tokio::test]
    #[cfg(feature = "domain-settings")]
    async fn settings_localtx_retry_accepts_generated_observation()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let result = run_pg_localtx_retry(
            settings_secret_observation(),
            |_attempt, _deadline| async { LocalTxAttempt::<(), FakeError>::committed(()) },
            classify_fake,
        )
        .await;
        assert_eq!(result, Ok(()));
        Ok(())
    }

    #[test]
    #[cfg(feature = "domain-settings")]
    fn localtx_unsafe_settlement_does_not_emit_generic_routing_telemetry()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        let capture = WarnCapture::default();
        let records = Arc::clone(&capture.records);
        let dispatch = tracing::Dispatch::new(capture);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()?;
        let observation = settings_secret_observation();

        let _dispatch_guard = tracing::dispatcher::set_default(&dispatch);
        metrics::with_local_recorder(&recorder, || {
            runtime.block_on(async {
                let result = run_pg_localtx_retry(
                    observation,
                    |_attempt, _deadline| async {
                        LocalTxAttempt::<(), _>::commit_unknown(FakeError::Transient)
                    },
                    classify_fake,
                )
                .await;
                assert_eq!(result, Err(FakeError::Transient));
            });
        });

        let rendered = handle.render();
        assert!(rendered.contains("localtx_final_total"), "{rendered}");
        assert!(
            !rendered.contains("tx_settlement_final_total"),
            "HTTP LocalTx must not duplicate generic settlement metrics: {rendered}"
        );
        let records = records.lock().unwrap_or_else(|error| error.into_inner());
        assert!(
            records.iter().any(|fields| {
                fields.get("boundary").map(String::as_str) == Some("single_domain")
                    && fields.get("final_status").map(String::as_str) == Some("commit_unknown")
            }),
            "HTTP LocalTx must retain its contract-attributed unsafe WARN: {records:?}"
        );
        assert!(
            records.iter().all(|fields| {
                fields.get("boundary").map(String::as_str)
                    != Some(SETTINGS_SECRET_BOUNDARY.as_label())
            }),
            "HTTP LocalTx must not duplicate the generic routing WARN: {records:?}"
        );
        Ok(())
    }

    #[test]
    #[cfg(feature = "domain-settings")]
    fn common_settlement_funnel_does_not_duplicate_runner_warnings()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let capture = WarnCapture::default();
        let records = Arc::clone(&capture.records);
        let dispatch = tracing::Dispatch::new(capture);
        let _dispatch_guard = tracing::dispatcher::set_default(&dispatch);
        let tenant = vocab::TenantId::parse("00000000-0000-4000-8000-000000000001")?;

        let _commit_unknown = super::finish_local_tx_commit_result(
            Err(sqlx::Error::PoolTimedOut),
            (),
            |_| FakeError::Permanent,
            "test",
            tenant,
        );
        let _rollback_failed = super::finish_local_tx_rollback_result::<(), _>(
            Err(sqlx::Error::PoolTimedOut),
            FakeError::Conflict,
            |_| FakeError::Permanent,
            "test",
            tenant,
        );

        let records = records.lock().unwrap_or_else(|error| error.into_inner());
        assert!(
            records.is_empty(),
            "common settlement funnel must leave unsafe WARN ownership to the runner: {records:?}"
        );
        Ok(())
    }

    #[test]
    #[cfg(feature = "domain-settings")]
    fn plain_producer_attempt_observes_unsafe_settlement_before_result_flattening()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        let capture = WarnCapture::default();
        let records = Arc::clone(&capture.records);
        let dispatch = tracing::Dispatch::new(capture);
        let _dispatch_guard = tracing::dispatcher::set_default(&dispatch);

        metrics::with_local_recorder(&recorder, || {
            for attempt in [
                ProducerTxAttempt::new(LocalTxAttempt::<(), _>::commit_unknown(
                    FakeError::Transient,
                )),
                ProducerTxAttempt::new(LocalTxAttempt::<(), _>::rollback_failed(
                    FakeError::Transient,
                )),
            ] {
                assert!(attempt.into_result().is_err());
            }
        });

        let rendered = handle.render();
        assert!(rendered.contains("tx_settlement_final_total"), "{rendered}");
        assert!(
            rendered.contains("boundary=\"outbox.producer\""),
            "{rendered}"
        );
        assert!(
            rendered.contains("final_status=\"commit_unknown\""),
            "{rendered}"
        );
        assert!(
            rendered.contains("final_status=\"rollback_failed\""),
            "{rendered}"
        );
        let records = records.lock().unwrap_or_else(|error| error.into_inner());
        let unsafe_warnings: Vec<_> = records
            .iter()
            .filter(|fields| fields.contains_key("final_status"))
            .collect();
        assert_eq!(unsafe_warnings.len(), 2, "{records:?}");
        for final_status in ["commit_unknown", "rollback_failed"] {
            assert!(
                unsafe_warnings.iter().any(|fields| {
                    fields.get("boundary").map(String::as_str) == Some("outbox.producer")
                        && fields.get("final_status").map(String::as_str) == Some(final_status)
                }),
                "plain producer has no actionable WARN for {final_status}: {records:?}"
            );
        }
        Ok(())
    }

    #[tokio::test]
    #[cfg(feature = "domain-settings")]
    async fn settlement_safety_controls_retry() {
        let attempts = AtomicU32::new(0);
        let unsettled = run_pg_tx_retry(
            SETTINGS_CONFIG_BOUNDARY,
            |attempt, _deadline| {
                attempts.store(attempt, Ordering::Release);
                async move {
                    if attempt == 1 {
                        LocalTxAttempt::unsettled(FakeError::Transient)
                    } else {
                        LocalTxAttempt::committed(())
                    }
                }
            },
            classify_fake,
        )
        .await;
        assert_eq!(unsettled, Ok(()));
        assert_eq!(attempts.load(Ordering::Acquire), 2);

        for terminal in [
            LocalTxAttempt::<(), _>::rollback_failed(FakeError::Transient),
            LocalTxAttempt::commit_unknown(FakeError::Transient),
            LocalTxAttempt::rolled_back(FakeError::Conflict),
            LocalTxAttempt::rolled_back(FakeError::Permanent),
            LocalTxAttempt::rolled_back(FakeError::OwnershipLost),
        ] {
            let attempts = AtomicU32::new(0);
            let mut terminal = Some(terminal);
            let result = run_pg_tx_retry(
                SETTINGS_CONFIG_BOUNDARY,
                |attempt, _deadline| {
                    attempts.store(attempt, Ordering::Release);
                    core::future::ready(match terminal.take() {
                        Some(attempt) => attempt,
                        None => LocalTxAttempt::committed(()),
                    })
                },
                classify_fake,
            )
            .await;
            assert!(result.is_err());
            assert_eq!(attempts.load(Ordering::Acquire), 1);
        }
    }
}
