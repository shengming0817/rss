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

use consistency::Entry;
use futures::future::BoxFuture;
use sqlx::{PgConnection, PgPool, Postgres, Transaction};
use vocab::TenantId;

use crate::PgStore;
use crate::outbox::{OutboxEnvelope, append_outbox};

const TX_RETRY_LOCK_TIMEOUT: &str = "5s";

/// Commit returned an error after the server may already have accepted the transaction.
///
/// Callers must not treat this like a pre-commit transient error: retrying the same UoW can turn
/// "committed but response lost" into a false CAS conflict or duplicate side effect.
#[derive(Debug, thiserror::Error)]
#[error("postgres transaction commit result is unknown")]
pub(crate) struct PgTxCommitError {
    #[source]
    source: sqlx::Error,
}

impl PgTxCommitError {
    fn new(source: sqlx::Error) -> Self {
        Self { source }
    }
}

pub(crate) fn commit_unknown(source: sqlx::Error) -> sqlx::Error {
    sqlx::Error::AnyDriverError(Box::new(PgTxCommitError::new(source)))
}

#[derive(Debug, thiserror::Error)]
#[error("outbox envelope tenant does not match tenant-scoped transaction")]
struct OutboxTenantMismatch;

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
}

impl PgTenantPool {
    /// Build the scoped wrapper from the crate-private store. The raw pool remains owned by
    /// [`PgStore`] and is not exposed through this wrapper.
    pub(crate) fn new(store: &PgStore) -> Self {
        Self {
            pool: store.pool.clone(),
        }
    }

    /// Run a tenant-scoped read transaction.
    pub(crate) async fn read<T, F>(&self, tenant: TenantId, read: F) -> Result<T, sqlx::Error>
    where
        F: for<'c> FnOnce(&'c mut PgConnection) -> BoxFuture<'c, Result<T, sqlx::Error>> + Send,
        T: Send,
    {
        tenant_scoped_read(&self.pool, tenant, read).await
    }

    /// Run a tenant-scoped read transaction whose closure can return domain errors.
    pub(crate) async fn read_map<T, F, E>(
        &self,
        tenant: TenantId,
        read: F,
        map_storage: impl Fn(sqlx::Error) -> E + Send,
    ) -> Result<T, E>
    where
        F: for<'c> FnOnce(&'c mut PgConnection) -> BoxFuture<'c, Result<T, E>> + Send,
        E: Send,
        T: Send,
    {
        tenant_scoped_read_map(&self.pool, tenant, read, map_storage).await
    }

    /// Run a tenant-scoped write transaction.
    pub(crate) async fn write<T, F, E>(
        &self,
        tenant: TenantId,
        write: F,
        map_storage: impl Fn(sqlx::Error) -> E + Send,
    ) -> Result<T, E>
    where
        F: for<'c, 'tx> FnOnce(&'c mut TxCapability<'tx>) -> BoxFuture<'c, Result<T, E>> + Send,
        E: Send,
        T: Send,
    {
        tenant_scoped_write_inner(&self.pool, tenant, write, map_storage, false).await
    }

    /// Run a tenant-scoped write transaction with a per-attempt lock wait bound.
    pub(crate) async fn retry_write<T, F, E>(
        &self,
        tenant: TenantId,
        write: F,
        map_storage: impl Fn(sqlx::Error) -> E + Send,
    ) -> Result<T, E>
    where
        F: for<'c, 'tx> FnOnce(&'c mut TxCapability<'tx>) -> BoxFuture<'c, Result<T, E>> + Send,
        E: Send,
        T: Send,
    {
        tenant_scoped_write_inner(&self.pool, tenant, write, map_storage, true).await
    }

    /// Run a tenant-scoped business write followed by outbox append in the same transaction.
    pub(crate) async fn co_tx_with_outbox<F, E>(
        &self,
        tenant: TenantId,
        entry: &Entry,
        env: &OutboxEnvelope,
        business_write: F,
        map_storage: impl Fn(sqlx::Error) -> E + Send,
    ) -> Result<(), E>
    where
        F: for<'c, 'tx> FnOnce(&'c mut TxCapability<'tx>) -> BoxFuture<'c, Result<(), E>> + Send,
        E: Send,
    {
        co_tx_with_outbox(&self.pool, tenant, entry, env, business_write, map_storage).await
    }

    /// Run a tenant-scoped co-transaction with a per-attempt lock wait bound.
    pub(crate) async fn retry_co_tx_with_outbox<F, E>(
        &self,
        tenant: TenantId,
        entry: &Entry,
        env: &OutboxEnvelope,
        business_write: F,
        map_storage: impl Fn(sqlx::Error) -> E + Send,
    ) -> Result<(), E>
    where
        F: for<'c, 'tx> FnOnce(&'c mut TxCapability<'tx>) -> BoxFuture<'c, Result<(), E>> + Send,
        E: Send,
    {
        co_tx_with_outbox_inner(
            &self.pool,
            tenant,
            entry,
            env,
            business_write,
            map_storage,
            true,
        )
        .await
    }
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
/// co-tx 写（[`co_tx_with_outbox`]）与 plain 写（`config_repo` 的 tenant-scoped save/delete，#1249 F3）共享，
/// 保证所有 postgres 写路径经统一 SET LOCAL 收口（未来 RLS policy 的 current_setting 锚点，不留绕过面）。
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
) -> Result<T, E>
where
    F: for<'c, 'tx> FnOnce(&'c mut TxCapability<'tx>) -> BoxFuture<'c, Result<T, E>> + Send,
    E: Send,
    T: Send,
{
    let mut tx = begin_tenant_scoped_write(pool, tenant, &map_storage, bound_lock_wait).await?;
    let result = {
        let mut tx_cap = TxCapability::from_transaction(&mut tx);
        write(&mut tx_cap).await
    };
    match result {
        Ok(v) => {
            tx.commit().await.map_err(|e| {
                tracing::warn!(
                    target: "postgres",
                    tenant_id = %tenant,
                    error = %secure::redact_error(&e),
                    "tenant_scoped_write: commit failed"
                );
                map_storage(commit_unknown(e))
            })?;
            Ok(v)
        }
        Err(e) => {
            if let Err(rb) = tx.rollback().await {
                tracing::warn!(
                    target: "postgres",
                    tenant_id = %tenant,
                    error = %secure::redact_error(&rb),
                    "tenant_scoped_write: rollback failed after write error"
                );
            }
            Err(e)
        }
    }
}

async fn begin_tenant_scoped_write<'p, E>(
    pool: &'p PgPool,
    tenant: TenantId,
    map_storage: &(impl Fn(sqlx::Error) -> E + Send),
    bound_lock_wait: bool,
) -> Result<Transaction<'p, Postgres>, E> {
    let mut tx = pool.begin().await.map_err(map_storage)?;
    set_local_tenant(&mut tx, tenant)
        .await
        .map_err(map_storage)?;
    if bound_lock_wait {
        set_local_retry_lock_timeout(&mut tx)
            .await
            .map_err(map_storage)?;
    }
    Ok(tx)
}

/// 在单事务内：注入 tenant scope（SET LOCAL）→ 业务写闭包 → `append_outbox` → 单 commit。
///
/// `business_write(&mut TxCapability) -> Result<(), E>`：在同一事务内执行业务写（如 CAS INSERT），可返回业务
/// 错误 `E`（如 `VersionConflict`）使整事务回滚。骨架自身 sqlx 错误经 `map_storage` 映射为 `E`。任一步 Err ⇒
/// rollback（失败仅 warn，不覆盖原错误）。`tenant` 为类型化租户标识（funnel 内 stringify + SET LOCAL 绑定）。
///
/// # Examples
///
/// ```ignore
/// // 调用方在 `business_write` 闭包内执行业务写（HRTB + BoxFuture 绕过异步闭包借用规则）；
/// // sqlx 错误经 `map_storage` 收口为域错误 E（绕开 `E: From<sqlx::Error>` 跨 crate 约束）。
/// co_tx_with_outbox(
///     &pool, tenant, &outbox_entry, &env,
///     move |tx| Box::pin(async move { cas_insert(tx.conn(), tenant, &entry).await }),
///     |e| ConfigRepoError::Storage(Box::new(e)),
/// ).await
/// ```
pub(crate) async fn co_tx_with_outbox<F, E>(
    pool: &PgPool,
    tenant: TenantId,
    entry: &Entry,
    env: &OutboxEnvelope,
    business_write: F,
    map_storage: impl Fn(sqlx::Error) -> E + Send,
) -> Result<(), E>
where
    F: for<'c, 'tx> FnOnce(&'c mut TxCapability<'tx>) -> BoxFuture<'c, Result<(), E>> + Send,
    E: Send,
{
    co_tx_with_outbox_inner(pool, tenant, entry, env, business_write, map_storage, false).await
}

async fn co_tx_with_outbox_inner<F, E>(
    pool: &PgPool,
    tenant: TenantId,
    entry: &Entry,
    env: &OutboxEnvelope,
    business_write: F,
    map_storage: impl Fn(sqlx::Error) -> E + Send,
    bound_lock_wait: bool,
) -> Result<(), E>
where
    F: for<'c, 'tx> FnOnce(&'c mut TxCapability<'tx>) -> BoxFuture<'c, Result<(), E>> + Send,
    E: Send,
{
    let mut tx = pool.begin().await.map_err(&map_storage)?;
    match write_in_tx(&mut tx, tenant, entry, env, business_write, bound_lock_wait).await {
        Ok(()) => tx.commit().await.map_err(|e| {
            tracing::warn!(
                target: "postgres",
                event_id = entry.idem_key().as_str(),
                domain = env.domain(),
                topic = entry.topic().as_str(),
                error = %secure::redact_error(&e),
                "co-tx: commit failed"
            );
            map_storage(commit_unknown(e))
        }),
        Err(e) => {
            log_cotx_write_error(entry, env, &e);
            // rollback 失败是运维高价值事件（连接泄漏 / PG 断线）——补齐 event_id/domain/topic 定位字段
            // （与 commit 分支对齐），便于按域 / 事件排障。
            if let Err(rb) = tx.rollback().await {
                tracing::warn!(
                    target: "postgres",
                    event_id = entry.idem_key().as_str(),
                    domain = env.domain(),
                    topic = entry.topic().as_str(),
                    error = %secure::redact_error(&rb),
                    "co-tx: rollback failed after write error"
                );
            }
            Err(e.into_domain(&map_storage))
        }
    }
}

/// 事务体：SET LOCAL tenant → 业务写 → `append_outbox`（任一步 Err 即冒泡，由调用方 rollback）。
async fn write_in_tx<F, E>(
    tx: &mut Transaction<'_, Postgres>,
    tenant: TenantId,
    entry: &Entry,
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
    append_outbox(&mut tx_cap, entry, env)
        .await
        .map_err(CoTxWriteError::AppendOutbox)
}

enum CoTxWriteError<E> {
    TenantScope(sqlx::Error),
    TenantMismatch(sqlx::Error),
    RetryLockTimeout(sqlx::Error),
    BusinessWrite(E),
    AppendOutbox(sqlx::Error),
}

impl<E> CoTxWriteError<E> {
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
            Self::TenantScope(e)
            | Self::TenantMismatch(e)
            | Self::RetryLockTimeout(e)
            | Self::AppendOutbox(e) => Some(e),
            Self::BusinessWrite(_) => None,
        }
    }

    fn into_domain(self, map_storage: &(impl Fn(sqlx::Error) -> E + Send)) -> E {
        match self {
            Self::TenantScope(e)
            | Self::TenantMismatch(e)
            | Self::RetryLockTimeout(e)
            | Self::AppendOutbox(e) => map_storage(e),
            Self::BusinessWrite(e) => e,
        }
    }
}

fn log_cotx_write_error<E>(entry: &Entry, env: &OutboxEnvelope, error: &CoTxWriteError<E>) {
    if let Some(source) = error.sqlx_source() {
        log_cotx_sqlx_error(entry, env, error.stage(), source);
    } else {
        log_cotx_domain_error(entry, env, error.stage());
    }
}

fn log_cotx_sqlx_error(
    entry: &Entry,
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

fn log_cotx_domain_error(entry: &Entry, env: &OutboxEnvelope, stage: &'static str) {
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
    use super::{Postgres, Transaction, TxCapability};

    #[test]
    fn tx_capability_mint_signature_is_crate_private() {
        fn mint_from_sqlx_transaction<'tx, 'p>(
            tx: &'tx mut Transaction<'p, Postgres>,
        ) -> TxCapability<'tx> {
            TxCapability::from_transaction(tx)
        }

        let _ = mint_from_sqlx_transaction;
    }
}
