//! `co_tx_with_outbox` —— 通用 **co-tx** 骨架：begin → SET LOCAL tenant → 业务写闭包 → `append_outbox` →
//! 单 commit；任一步 Err ⇒ rollback + warn（#1249，吸收 #1232 co-tx）。
//!
//! 抽取自 session co-tx 范式（`session_lifecycle.rs`），供 session 创建与配置写
//! `PgConfigUnitOfWork` 复用。
//!
//! 错误泛型 `E`：业务写闭包返回 `Result<(), E>`（如 CAS 0 行 → 域 `VersionConflict`）；骨架自身产生的 sqlx
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
use sqlx::{Acquire, PgConnection, PgPool, Postgres, Transaction};
use tokio::time::Instant;
use vocab::TenantId;

use crate::PgStore;
#[cfg(any(feature = "domain-settings", feature = "domain-identity"))]
use crate::outbox::{OutboxAppendError, OutboxEnvelope, append_outbox_with_projection};
use crate::projection_events::ProjectionWriteRegistry;

mod settlement;

use settlement::rollback_failed;
#[cfg(any(
    feature = "domain-settings",
    feature = "domain-identity",
    feature = "domain-audit"
))]
pub(crate) use settlement::{LocalTxAttempt, LocalTxRetryError, commit_unknown};
#[cfg(not(any(
    feature = "domain-settings",
    feature = "domain-identity",
    feature = "domain-audit"
)))]
pub(crate) use settlement::{LocalTxAttempt, commit_unknown};

const TX_RETRY_LOCK_TIMEOUT: &str = "5s";

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
struct CoTxOutboxWrite<'a> {
    tenant: TenantId,
    entry: &'a EventEntry,
    env: &'a OutboxEnvelope,
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
    /// production callers cannot construct or trigger it.
    #[cfg(all(test, feature = "integration"))]
    pub(crate) async fn inject_commit_unknown_after_commit(&mut self) -> Result<(), sqlx::Error> {
        sqlx::query("SELECT set_config('rss.test_commit_unknown_after_commit', '1', true)")
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
}

/// tenant-scoped Postgres pool wrapper.
///
/// This is the typed production entry for RLS tenant-table access. It is cloneable for repo
/// structs, but it does not expose raw [`PgPool`], `begin`, `acquire`, or `Executor`; callers can
/// only run scoped read/write/co-tx closures after this module has injected `SET LOCAL
/// rss.tenant_id`.
///
/// # INVARIANT: TENANCY-PG-TX-FUNNEL-01 { level = "Medium", exec = "manual/opt-in", source = "code" }
///
/// Tenant-table adapters hold `PgTenantPool`, not `sqlx::PgPool`; direct raw-pool tenant-table
/// access is therefore not expressible through their fields. `cargo xtask pg-tenant-tx-guard`
/// is the Medium backstop that catches drift and explicit raw global exceptions.
#[derive(Clone)]
pub(crate) struct PgTenantPool {
    pool: PgPool,
    projection_registry: ProjectionWriteRegistry,
}

impl PgTenantPool {
    /// Build the scoped wrapper from the crate-private store. The raw pool remains owned by
    /// [`PgStore`] and is not exposed through this wrapper.
    pub(crate) fn new(store: &PgStore) -> Self {
        Self {
            pool: store.pool.clone(),
            projection_registry: ProjectionWriteRegistry::empty(),
        }
    }

    pub(crate) fn with_projection_registry(
        store: &PgStore,
        projection_registry: ProjectionWriteRegistry,
    ) -> Self {
        Self {
            pool: store.pool.clone(),
            projection_registry,
        }
    }

    pub(crate) fn projection_registry(&self) -> ProjectionWriteRegistry {
        self.projection_registry
    }

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
        tenant_scoped_write_inner(&self.pool, tenant, write, map_storage, false)
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

    /// Run a tenant-scoped write with a lock wait bound but without replaying the operation.
    ///
    /// This is for mutation paths such as an idempotent tombstone append that have no generated
    /// LocalTx retry contract but still acquire a blocking PostgreSQL advisory lock.
    #[cfg(feature = "domain-settings")]
    pub(crate) async fn lock_bounded_write<S, T, F, E>(
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
        tenant_scoped_write_inner(&self.pool, tenant, write, map_storage, true)
            .await
            .into_result()
    }

    /// Run a tenant-scoped write transaction with a per-attempt lock wait bound.
    #[cfg(any(
        feature = "domain-settings",
        feature = "domain-identity",
        feature = "domain-audit"
    ))]
    pub(crate) async fn retry_write<S, T, F, E>(
        &self,
        scope: S,
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
        tenant_scoped_write_inner(&self.pool, tenant, write, map_storage, true).await
    }

    /// Run a tenant-scoped business write followed by outbox append in the same transaction.
    #[cfg(feature = "domain-identity")]
    pub(crate) async fn co_tx_with_outbox<S, F, E>(
        &self,
        scope: S,
        entry: &EventEntry,
        env: &OutboxEnvelope,
        business_write: F,
        map_storage: impl Fn(sqlx::Error) -> E + Send,
    ) -> Result<(), E>
    where
        S: TenantScopeHandle,
        F: for<'c, 'tx> FnOnce(&'c mut TxCapability<'tx>) -> BoxFuture<'c, Result<(), E>> + Send,
        E: MapOutboxAppendError + std::error::Error + Send + Sync + 'static,
    {
        let tenant = scope.tenant();
        co_tx_with_outbox(
            &self.pool,
            self.projection_registry,
            tenant,
            entry,
            env,
            business_write,
            map_storage,
        )
        .await
    }

    /// Run a tenant-scoped co-transaction with a per-attempt lock wait bound.
    #[cfg(feature = "domain-settings")]
    pub(crate) async fn retry_co_tx_with_outbox<S, F, E>(
        &self,
        scope: S,
        entry: &EventEntry,
        env: &OutboxEnvelope,
        business_write: F,
        map_storage: impl Fn(sqlx::Error) -> E + Send,
    ) -> LocalTxAttempt<(), E>
    where
        S: TenantScopeHandle,
        F: for<'c, 'tx> FnOnce(&'c mut TxCapability<'tx>) -> BoxFuture<'c, Result<(), E>> + Send,
        E: MapOutboxAppendError + std::error::Error + Send + Sync + 'static,
    {
        let tenant = scope.tenant();
        co_tx_with_outbox_inner(
            &self.pool,
            self.projection_registry,
            CoTxOutboxWrite { tenant, entry, env },
            business_write,
            map_storage,
            true,
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

/// tenant-scoped 只读事务：begin → SET LOCAL `rss.tenant_id` → 读闭包 → commit。
///
/// 与写侧 [`co_tx_with_outbox`]（co-tx + outbox）对称，是读路径的 RLS policy
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
/// sessions / config_entries / roles 三表所有读路径（`find` / `find_version` / `latest_version`）
/// 经此 helper 注入 SET LOCAL，与 0009 迁移的 RLS policy `current_setting` 对齐；当前业务池可能以
/// owner/superuser 连接（superuser 绕过 RLS）；`tenant_scoped_read` 已就位 SET LOCAL 锚点，业务池切
/// rss_app（dual-pool follow-up）后 DB 层 RLS 方强制生效；t20–t22 验证 rss_app 角色下的强制力。
pub(crate) async fn tenant_scoped_read<T, F>(
    pool: &PgPool,
    tenant: TenantId,
    read: F,
) -> Result<T, sqlx::Error>
where
    F: for<'c> FnOnce(&'c mut PgConnection) -> BoxFuture<'c, Result<T, sqlx::Error>> + Send,
    T: Send,
{
    let mut tx = pool.begin().await?;
    // SET LOCAL 注入 tenant scope（事务内有效，commit/rollback 自动失效；与写侧 set_local_tenant 共享锚点）。
    set_local_tenant(&mut tx, tenant).await?;
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
    let mut tx = pool.begin().await.map_err(&map_storage)?;
    set_local_tenant(&mut tx, tenant)
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

/// 在事务内注入 tenant scope（SET LOCAL `rss.tenant_id`，参数化绑定防注入；tenancy.md §RLS 与 PG scope）。
/// co-tx 写（[`PgTenantPool::co_tx_with_outbox`]）与 plain 写（`config_repo` 的 tenant-scoped save/delete，#1249 F3）
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

async fn set_local_retry_lock_timeout(conn: &mut PgConnection) -> Result<(), sqlx::Error> {
    sqlx::query("SELECT set_config('lock_timeout', $1, true)")
        .bind(TX_RETRY_LOCK_TIMEOUT)
        .execute(conn)
        .await
        .map(|_| ())
}

async fn tenant_scoped_write_inner<T, F, E>(
    pool: &PgPool,
    tenant: TenantId,
    write: F,
    map_storage: impl Fn(sqlx::Error) -> E + Send,
    bound_lock_wait: bool,
) -> LocalTxAttempt<T, E>
where
    F: for<'c, 'tx> FnOnce(&'c mut TxCapability<'tx>) -> BoxFuture<'c, Result<T, E>> + Send,
    E: std::error::Error + Send + Sync + 'static,
    T: Send,
{
    let mut tx = match pool.begin().await {
        Ok(tx) => tx,
        Err(error) => return LocalTxAttempt::unsettled(map_storage(error)),
    };
    let result = async {
        set_local_tenant(&mut tx, tenant)
            .await
            .map_err(&map_storage)?;
        if bound_lock_wait {
            set_local_retry_lock_timeout(&mut tx)
                .await
                .map_err(&map_storage)?;
        }
        let mut tx_cap = TxCapability::from_transaction(&mut tx);
        write(&mut tx_cap).await
    }
    .await;
    finish_local_tx(tx, result, map_storage, "tenant-scoped-write", tenant).await
}

/// 在单事务内：注入 tenant scope（SET LOCAL）→ 业务写闭包 → `append_outbox` → 单 commit。
///
/// `business_write(&mut TxCapability) -> Result<(), E>`：在同一事务内执行业务写（如 CAS INSERT），可返回业务
/// 错误 `E`（如 `VersionConflict`）使整事务回滚。骨架自身 sqlx 错误经 `map_storage` 映射为 `E`。任一步 Err ⇒
/// 显式 rollback：成功则保留原错误为 `RolledBack`；rollback 本身失败则经 `map_storage` 收口为独立
/// settlement Storage 错误（保留 primary+rollback 因果链），不再把可重试领域冲突冒泡到 HTTP。
/// `tenant` 为类型化租户标识（funnel 内 stringify + SET LOCAL 绑定）。
///
/// # Examples
///
/// ```ignore
/// // 调用方在 `business_write` 闭包内执行业务写（HRTB + BoxFuture 绕过异步闭包借用规则）；
/// // sqlx 错误经 `map_storage` 收口为域错误 E（绕开 `E: From<sqlx::Error>` 跨 crate 约束）。
/// PgTenantPool::new(&store)
///     .co_tx_with_outbox(
///         tenant,
///         &outbox_entry,
///         &env,
///         move |tx| Box::pin(async move { cas_insert(tx.conn(), tenant, &entry).await }),
///         |e| ConfigRepoError::Storage(Box::new(e)),
///     )
///     .await
/// ```
#[cfg(feature = "domain-identity")]
async fn co_tx_with_outbox<F, E>(
    pool: &PgPool,
    projection_registry: ProjectionWriteRegistry,
    tenant: TenantId,
    entry: &EventEntry,
    env: &OutboxEnvelope,
    business_write: F,
    map_storage: impl Fn(sqlx::Error) -> E + Send,
) -> Result<(), E>
where
    F: for<'c, 'tx> FnOnce(&'c mut TxCapability<'tx>) -> BoxFuture<'c, Result<(), E>> + Send,
    E: MapOutboxAppendError + std::error::Error + Send + Sync + 'static,
{
    co_tx_with_outbox_inner(
        pool,
        projection_registry,
        CoTxOutboxWrite { tenant, entry, env },
        business_write,
        map_storage,
        false,
    )
    .await
    .into_result()
}

#[cfg(any(feature = "domain-settings", feature = "domain-identity"))]
async fn co_tx_with_outbox_inner<F, E>(
    pool: &PgPool,
    projection_registry: ProjectionWriteRegistry,
    write: CoTxOutboxWrite<'_>,
    business_write: F,
    map_storage: impl Fn(sqlx::Error) -> E + Send,
    bound_lock_wait: bool,
) -> LocalTxAttempt<(), E>
where
    F: for<'c, 'tx> FnOnce(&'c mut TxCapability<'tx>) -> BoxFuture<'c, Result<(), E>> + Send,
    E: MapOutboxAppendError + std::error::Error + Send + Sync + 'static,
{
    let mut tx = match pool.begin().await {
        Ok(tx) => tx,
        Err(error) => return LocalTxAttempt::unsettled(map_storage(error)),
    };
    let result = match write_in_tx(
        &mut tx,
        projection_registry,
        write.tenant,
        write.entry,
        write.env,
        business_write,
        bound_lock_wait,
    )
    .await
    {
        Ok(()) => Ok(()),
        Err(e) => {
            log_cotx_write_error(write.entry, write.env, &e);
            Err(e.into_domain(&map_storage))
        }
    };
    finish_local_tx(tx, result, map_storage, "co-tx-with-outbox", write.tenant).await
}

/// Settle one LocalTx attempt through the only commit/explicit-rollback branch.
async fn finish_local_tx<T, E>(
    tx: Transaction<'_, Postgres>,
    result: Result<T, E>,
    map_storage: impl Fn(sqlx::Error) -> E,
    operation: &'static str,
    tenant: TenantId,
) -> LocalTxAttempt<T, E>
where
    E: std::error::Error + Send + Sync + 'static,
{
    match result {
        Ok(value) => {
            #[allow(unused_mut)]
            let mut tx = tx;
            #[cfg(all(test, feature = "integration"))]
            let inject_commit_unknown = test_commit_unknown_after_commit_requested(&mut tx).await;
            let commit_result = tx.commit().await;
            #[cfg(all(test, feature = "integration"))]
            let commit_result = if inject_commit_unknown && commit_result.is_ok() {
                Err(sqlx::Error::PoolTimedOut)
            } else {
                commit_result
            };
            finish_local_tx_commit_result(commit_result, value, map_storage, operation, tenant)
        }
        Err(error) => {
            #[allow(unused_mut)]
            let mut tx = tx;
            #[cfg(all(test, feature = "integration"))]
            let inject_rollback_failed =
                test_rollback_failed_after_rollback_requested(&mut tx).await;
            let rollback_result = tx.rollback().await;
            #[cfg(all(test, feature = "integration"))]
            let rollback_result = if inject_rollback_failed && rollback_result.is_ok() {
                Err(sqlx::Error::PoolTimedOut)
            } else {
                rollback_result
            };
            finish_local_tx_rollback_result(rollback_result, error, map_storage, operation, tenant)
        }
    }
}

#[cfg(all(test, feature = "integration"))]
async fn test_commit_unknown_after_commit_requested(tx: &mut Transaction<'_, Postgres>) -> bool {
    sqlx::query_scalar::<_, Option<String>>(
        "SELECT current_setting('rss.test_commit_unknown_after_commit', true)",
    )
    .fetch_one(&mut **tx)
    .await
    .ok()
    .flatten()
    .is_some_and(|value| value == "1")
}

#[cfg(all(test, feature = "integration"))]
async fn test_rollback_failed_after_rollback_requested(tx: &mut Transaction<'_, Postgres>) -> bool {
    sqlx::query_scalar::<_, Option<String>>(
        "SELECT current_setting('rss.test_rollback_failed_after_rollback', true)",
    )
    .fetch_one(&mut **tx)
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

/// 事务体：SET LOCAL tenant → 业务写 → `append_outbox`（任一步 Err 即冒泡，由调用方 rollback）。
#[cfg(any(feature = "domain-settings", feature = "domain-identity"))]
async fn write_in_tx<F, E>(
    tx: &mut Transaction<'_, Postgres>,
    projection_registry: ProjectionWriteRegistry,
    tenant: TenantId,
    entry: &EventEntry,
    env: &OutboxEnvelope,
    business_write: F,
    bound_lock_wait: bool,
) -> Result<(), CoTxWriteError<E>>
where
    F: for<'c, 'tx> FnOnce(&'c mut TxCapability<'tx>) -> BoxFuture<'c, Result<(), E>> + Send,
{
    // tenant scope（事务级，commit/rollback 自动失效；与 plain 写共享 set_local_tenant，F3）。
    set_local_tenant(tx, tenant)
        .await
        .map_err(CoTxWriteError::TenantScope)?;
    if env.tenant() != tenant {
        return Err(CoTxWriteError::TenantMismatch(sqlx::Error::AnyDriverError(
            Box::new(OutboxTenantMismatch),
        )));
    }
    if bound_lock_wait {
        set_local_retry_lock_timeout(tx)
            .await
            .map_err(CoTxWriteError::RetryLockTimeout)?;
    }
    // 业务写（同 tx；CAS 0 行 → 业务 E::VersionConflict）。tx_cap 是从 live Transaction 铸造的能力令牌；
    // append_outbox 也只接受该令牌，裸 PgPool/PgConnection 无法调用 outbox 双写入口。
    let mut tx_cap = TxCapability::from_transaction(tx);
    business_write(&mut tx_cap)
        .await
        .map_err(CoTxWriteError::BusinessWrite)?;
    // outbox append（同 tx — co-tx 原子性；复用 append_outbox + OUTBOX-ATOMIC-IDEM-01）。
    append_outbox_with_projection(&mut tx_cap, entry, env, &projection_registry)
        .await
        .map(|_| ())
        .map_err(CoTxWriteError::AppendOutbox)
}

#[cfg(any(feature = "domain-settings", feature = "domain-identity"))]
enum CoTxWriteError<E> {
    TenantScope(sqlx::Error),
    TenantMismatch(sqlx::Error),
    RetryLockTimeout(sqlx::Error),
    BusinessWrite(E),
    AppendOutbox(OutboxAppendError),
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
            other => Self::Storage(Box::new(other)),
        }
    }
}

#[cfg(any(feature = "domain-settings", feature = "domain-identity"))]
impl<E: MapOutboxAppendError> CoTxWriteError<E> {
    fn stage(&self) -> &'static str {
        match self {
            Self::TenantScope(_) => "set-local-tenant",
            Self::TenantMismatch(_) => "outbox-tenant-match",
            Self::RetryLockTimeout(_) => "set-local-retry-lock-timeout",
            Self::BusinessWrite(_) => "business-write",
            Self::AppendOutbox(_) => "append-outbox",
        }
    }

    fn sqlx_source(&self) -> Option<&sqlx::Error> {
        match self {
            Self::TenantScope(e) | Self::TenantMismatch(e) | Self::RetryLockTimeout(e) => Some(e),
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
            Self::TenantScope(e) | Self::TenantMismatch(e) | Self::RetryLockTimeout(e) => {
                map_storage(e)
            }
            Self::AppendOutbox(e) => E::from_outbox_append(e),
            Self::BusinessWrite(e) => e,
        }
    }
}

#[cfg(any(feature = "domain-settings", feature = "domain-identity"))]
fn log_cotx_write_error<E: MapOutboxAppendError>(
    entry: &EventEntry,
    env: &OutboxEnvelope,
    error: &CoTxWriteError<E>,
) {
    if let CoTxWriteError::AppendOutbox(append_error) = error
        && log_cotx_identity_error(append_error)
    {
        return;
    }
    if let Some(source) = error.sqlx_source() {
        log_cotx_sqlx_error(entry, env, error.stage(), source);
    } else {
        log_cotx_domain_error(entry, env, error.stage());
    }
}

#[cfg(any(feature = "domain-settings", feature = "domain-identity"))]
fn log_cotx_identity_error(error: &OutboxAppendError) -> bool {
    let Some(reason) = error.identity_failure_reason() else {
        return false;
    };
    tracing::warn!(
        target: "postgres",
        stage = "append-outbox",
        reason,
        "co-tx: write failed; rolling back"
    );
    true
}

#[cfg(any(feature = "domain-settings", feature = "domain-identity"))]
fn log_cotx_sqlx_error(
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
        "co-tx: write failed; rolling back"
    );
}

#[cfg(any(feature = "domain-settings", feature = "domain-identity"))]
fn log_cotx_domain_error(entry: &EventEntry, env: &OutboxEnvelope, stage: &'static str) {
    tracing::warn!(
        target: "postgres",
        event_id = entry.idem_key().as_str(),
        domain = env.domain(),
        topic = entry.topic().as_str(),
        stage,
        "co-tx: write failed; rolling back"
    );
}

#[cfg(test)]
mod tx_capability_tests {
    use consistency::LocalTxFinalStatus;

    use super::{Postgres, Transaction, TxCapability, finish_local_tx_commit_result};

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

        use super::PgTenantPool;
        use crate::outbox::{OutboxEnvelope, OutboxMetadata};
        use crate::projection_events::ProjectionWriteRegistry;

        let tenant = tenant()?;
        let pool = PgPoolOptions::new()
            .acquire_timeout(core::time::Duration::from_millis(10))
            .connect_lazy("postgres://127.0.0.1:1/rss")
            .map_err(|error| error.to_string())?;
        let scoped = PgTenantPool {
            pool,
            projection_registry: ProjectionWriteRegistry::empty(),
        };
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

        #[cfg(feature = "domain-identity")]
        {
            let co_tx = scoped
                .co_tx_with_outbox(
                    settings::ports::TenantRepoScope::for_test(tenant),
                    &entry,
                    &env,
                    |_| Box::pin(async { Ok::<(), ConfigRepoError>(()) }),
                    map_storage,
                )
                .await;
            assert!(co_tx.is_err());
        }

        let retry_co_tx = scoped
            .retry_co_tx_with_outbox(
                settings::ports::TenantRepoScope::for_test(tenant),
                &entry,
                &env,
                |_| Box::pin(async { Ok::<(), ConfigRepoError>(()) }),
                map_storage,
            )
            .await;
        assert_eq!(retry_co_tx.settlement(), None);
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
                    |attempt| {
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
                    |_attempt| async { LocalTxAttempt::<(), _>::rolled_back(FakeError::Conflict) },
                    classify_fake,
                )
                .await;
                assert!(matches!(conflict, Err(FakeError::Conflict)));

                let exhausted = run_pg_tx_retry(
                    SETTINGS_CONFIG_BOUNDARY,
                    |_attempt| async { LocalTxAttempt::<(), _>::rolled_back(FakeError::Transient) },
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
                        |_attempt| {
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
            |_attempt| async { LocalTxAttempt::<(), FakeError>::committed(()) },
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
                    |_attempt| async {
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

    #[cfg(feature = "domain-identity")]
    fn password_change_observation()
    -> observ::LocalTxObservation<generated::http::identity_v1::password_change::RouteMarker> {
        use generated::http::identity_v1::password_change::{LOCAL_TX, ROUTE};

        observ::LocalTxObservation::new(ROUTE, LOCAL_TX.boundary)
    }

    #[test]
    #[cfg(feature = "domain-identity")]
    fn localtx_retry_metrics_preserve_retry_and_settlement_axes()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()?;
        let committed_observation = password_change_observation();
        let terminal_observations = [
            password_change_observation(),
            password_change_observation(),
            password_change_observation(),
        ];
        let exhausted_observation = password_change_observation();
        metrics::with_local_recorder(&recorder, || {
            runtime.block_on(async {
                let committed = run_pg_localtx_retry(
                    committed_observation,
                    |attempt| async move {
                        if attempt == 1 {
                            LocalTxAttempt::rolled_back(FakeError::Transient)
                        } else {
                            LocalTxAttempt::committed(())
                        }
                    },
                    classify_fake,
                )
                .await;
                assert_eq!(committed, Ok(()));

                for (attempt, observation) in [
                    LocalTxAttempt::<(), _>::rolled_back(FakeError::Conflict),
                    LocalTxAttempt::commit_unknown(FakeError::Transient),
                    LocalTxAttempt::rollback_failed(FakeError::Transient),
                ]
                .into_iter()
                .zip(terminal_observations)
                {
                    let mut attempt = Some(attempt);
                    let result = run_pg_localtx_retry(
                        observation,
                        |_attempt| {
                            core::future::ready(match attempt.take() {
                                Some(attempt) => attempt,
                                None => LocalTxAttempt::committed(()),
                            })
                        },
                        classify_fake,
                    )
                    .await;
                    assert!(result.is_err());
                    assert!(attempt.is_none(), "terminal settlement must not retry");
                }

                let exhausted = run_pg_localtx_retry(
                    exhausted_observation,
                    |_attempt| async { LocalTxAttempt::<(), _>::rolled_back(FakeError::Transient) },
                    classify_fake,
                )
                .await;
                assert_eq!(exhausted, Err(FakeError::Transient));
            });
        });

        let rendered = handle.render();
        for expected in [
            "localtx_retry_attempts_total",
            "localtx_final_total",
            "localtx_attempts",
            "domain=\"identity\"",
            "contract_id=\"identity.password-change\"",
            "boundary=\"single_domain\"",
            "retry_class=\"transient\"",
            "retry_class=\"conflict\"",
            "retry_class=\"permanent\"",
            "final_status=\"committed\"",
            "final_status=\"rolled_back\"",
            "final_status=\"commit_unknown\"",
            "final_status=\"rollback_failed\"",
            "status=\"exhausted\"",
        ] {
            assert!(
                rendered.contains(expected),
                "missing {expected}: {rendered}"
            );
        }
        Ok(())
    }

    #[test]
    #[cfg(feature = "domain-identity")]
    fn last_real_settlement_survives_later_unsettled_attempts()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()?;
        let observation = password_change_observation();
        metrics::with_local_recorder(&recorder, || {
            runtime.block_on(async {
                let result = run_pg_localtx_retry(
                    observation,
                    |attempt| async move {
                        if attempt == 1 {
                            LocalTxAttempt::<(), _>::rolled_back(FakeError::Transient)
                        } else {
                            LocalTxAttempt::unsettled(FakeError::Transient)
                        }
                    },
                    classify_fake,
                )
                .await;
                assert_eq!(result, Err(FakeError::Transient));
            });
        });
        let rendered = handle.render();
        assert!(
            rendered.contains("localtx_retry_attempts_total"),
            "{rendered}"
        );
        assert!(rendered.contains("localtx_final_total"), "{rendered}");
        assert!(
            rendered.contains("final_status=\"rolled_back\""),
            "{rendered}"
        );
        assert!(
            rendered.contains("localtx_attempts_sum{domain=\"identity\",contract_id=\"identity.password-change\",boundary=\"single_domain\",final_status=\"rolled_back\"} 3"),
            "histogram must record all retry attempts: {rendered}"
        );
        Ok(())
    }

    #[test]
    #[cfg(feature = "domain-identity")]
    fn entirely_unsettled_retry_does_not_forge_localtx_final()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()?;
        let observation = password_change_observation();
        metrics::with_local_recorder(&recorder, || {
            runtime.block_on(async {
                let result = run_pg_localtx_retry(
                    observation,
                    |_attempt| async { LocalTxAttempt::<(), _>::unsettled(FakeError::Transient) },
                    classify_fake,
                )
                .await;
                assert_eq!(result, Err(FakeError::Transient));
            });
        });
        let rendered = handle.render();
        assert!(
            rendered.contains("localtx_retry_attempts_total"),
            "{rendered}"
        );
        assert!(!rendered.contains("localtx_final_total"), "{rendered}");
        assert!(!rendered.contains("localtx_attempts{"), "{rendered}");
        Ok(())
    }

    #[tokio::test]
    #[cfg(feature = "domain-settings")]
    async fn settlement_safety_controls_retry() {
        let attempts = AtomicU32::new(0);
        let unsettled = run_pg_tx_retry(
            SETTINGS_CONFIG_BOUNDARY,
            |attempt| {
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
                |attempt| {
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
