//! `co_tx_with_outbox` —— 通用 **co-tx** 骨架：begin → SET LOCAL tenant → 业务写闭包 → `append_outbox` →
//! 单 commit；任一步 Err ⇒ rollback + warn（#1249，吸收 #1232 co-tx）。
//!
//! 抽取自 session co-tx 范式（`session_lifecycle.rs`），供配置写 `PgConfigUnitOfWork` 复用。identity
//! `PgSessionLifecycle` 迁移到本骨架延后（保留 t11/t12/t14 不动，见 #1271）。
//!
//! 错误泛型 `E`：业务写闭包返回 `Result<(), E>`（如 CAS 0 行 → 域 `VersionConflict`）；骨架自身产生的 sqlx
//! 错误（begin / SET LOCAL / `append_outbox` / commit）经调用方传入的 `map_storage: Fn(sqlx::Error)->E` 收敛进
//! 同一 `E`——**不**要求 `E: From<sqlx::Error>`（域错误 `ConfigRepoError` 不依赖 sqlx，无法 impl `From`）。
//! 这正是不直接复用 `PgStore::run_in_transaction`（要求 `E: From<sqlx::Error>`）的原因。
//!
//! # INVARIANT: OUTBOX-COTX-CONFIG-01
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

use crate::outbox::{OutboxEnvelope, append_outbox};

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
/// # INVARIANT: RLS-TENANT-SCOPE-READ-01
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

/// 在事务内注入 tenant scope（SET LOCAL `rss.tenant_id`，参数化绑定防注入；tenancy.md §RLS 与 PG scope）。
/// co-tx 写（[`co_tx_with_outbox`]）与 plain 写（`config_repo` 的 tenant-scoped save/delete，#1249 F3）共享，
/// 保证所有 postgres 写路径经统一 SET LOCAL 收口（未来 RLS policy 的 current_setting 锚点，不留绕过面）。
///
/// # INVARIANT: TENANCY-SETLOCAL-FUNNEL-01
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

/// 在单事务内：注入 tenant scope（SET LOCAL）→ 业务写闭包 → `append_outbox` → 单 commit。
///
/// `business_write(&mut PgConnection) -> Result<(), E>`：在同一事务内执行业务写（如 CAS INSERT），可返回业务
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
///     move |conn| Box::pin(async move { cas_insert(conn, tenant, &entry).await }),
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
    F: for<'c> FnOnce(&'c mut PgConnection) -> BoxFuture<'c, Result<(), E>> + Send,
    E: Send,
{
    let mut tx = pool.begin().await.map_err(&map_storage)?;
    match write_in_tx(&mut tx, tenant, entry, env, business_write, &map_storage).await {
        Ok(()) => tx.commit().await.map_err(|e| {
            tracing::warn!(
                target: "postgres",
                event_id = entry.idem_key().as_str(),
                domain = env.domain(),
                topic = entry.topic().as_str(),
                error = %secure::redact_error(&e),
                "co-tx: commit failed"
            );
            map_storage(e)
        }),
        Err(e) => {
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
            Err(e)
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
    map_storage: &(impl Fn(sqlx::Error) -> E + Send),
) -> Result<(), E>
where
    F: for<'c> FnOnce(&'c mut PgConnection) -> BoxFuture<'c, Result<(), E>> + Send,
{
    // tenant scope（事务级，commit/rollback 自动失效；与 plain 写共享 set_local_tenant，F3）。
    set_local_tenant(tx, tenant).await.map_err(map_storage)?;
    // 业务写（同 tx；CAS 0 行 → 业务 E::VersionConflict）。`tx: &mut Transaction` 经 DerefMut 自动强制成
    // 闭包参数 `&mut PgConnection`（reborrow，非 move——append_outbox 仍可再借）。
    business_write(tx).await?;
    // outbox append（同 tx — co-tx 原子性；复用 append_outbox + OUTBOX-ATOMIC-IDEM-01）。
    append_outbox(tx, entry, env).await.map_err(map_storage)
}
