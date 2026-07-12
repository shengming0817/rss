//! `PgSessionLifecycle` —— identity 会话生命周期 adapter（impl `identity::ports::SessionLifecycle`，合并原
//! `PgSessionUnitOfWork`，#1278）。
//!
//! **完整生命周期均 durable 交付**（#1278，原 #1116 session 闭合）：创建（co-tx）+ 查询 `find`（tenant-scope
//! SELECT + `revoked = false` 过滤 + `Session::hydrate` 重建）+ 软撤销 `revoke`（tenant-scoped tx
//! `UPDATE ... SET revoked = true`，幂等）。`revoked` 列由 `0011_add_sessions_revoked.sql` 迁移引入。
//! 合并为单一 `SessionLifecycle` 后 postgres provider **不留 `todo!()` 半实现**——`LoginService::logout` 经
//! `revoke` 落到真实软撤销路径（消除「trait 看似完整、生产 read/revoke panic」的接缝，PR #273 codex F1）。
//!
//! L2 OutboxFact 完整语义（FR-003）：把一次登录的 [`Session`] 业务写与 outbox(`identity.session-created`)
//! append **同一本地事务**原子落库（both-or-neither）。取代「emit-only `PgEmitter` + 无 session 持久化」的
//! 单事实路径——因登录现已有业务写（session）。emit-only [`crate::PgEmitter`] 仍保留，作无业务写
//! OutboxFact 事件的通用能力（二者语义正交，#1083/#1192）。
//!
//! # INVARIANT: OUTBOX-COTX-SESSION-01 { level = "Medium", exec = "manual/opt-in", source = "code" }
//!
//! session 行与 outbox 行在**同一** `PgStore` 事务内写入 → 共 commit / 共 rollback；无 API 可单提交其一。
//! adapter 独占事务边界（`begin` → `SET LOCAL` tenant → INSERT session → `append_outbox` → 单 `commit`）；
//! 域经 combined 方法 `persist_session_and_emit` 调用，**无半开事务句柄**——co-tx 不可拆解在类型层成立
//! （**Hard**：域 split-tx 不可表达）。`append_outbox` 既有 OUTBOX-ATOMIC-IDEM-01（`&mut TxCapability`-only）
//! 保证 outbox 只能由 postgres adapter 从 live `sqlx::Transaction` 铸造的 capability 写入；session INSERT
//! 通过 `conn()` 在同一 capability 生命周期内借出连接执行。adapter same-tx 接线由集成测试 anti-vacuity 守：
//! `t11`（真实 method commit 两行皆在）↔ 负向 `t12`（co-tx SQL 序列强制 Err 两写共回滚）+ `t14`（**直测真实
//! method** rollback 分支：session INSERT 溢出 → 两行皆无）。
//!
//! tenant scope（tenancy.md §RLS 与 PG scope）：INSERT 前在同一 tx 内经 cotx [`set_local_tenant`] 注入
//! `rss.tenant_id` GUC（= SET LOCAL，参数化绑 typed [`TenantId`]，防注入；GUC 注入 literal 收口 cotx.rs）。
//! 预 GA 仓内尚无 RLS policy，故此刻 SET LOCAL 为前向兼容锚点；session 行 `tenant_id` 列显式写入已保证写入
//! tenant-correct。
//!
//! ref: debezium outbox SMT（业务写 + outbox 行同一本地事务，producer 侧 durable 落库）
//! ref: MassTransit Bus Outbox（一应用方法 co-persist 实体 + outbox 经共享事务/scoped DbContext）

use consistency::EventEntry;
use diport::{Clock, OutboxEmitError, OutboxEnvelopeParts};
use identity::ports::{IdentityError, Session, SessionId, SessionLifecycle, TenantRepoScope};
use sqlx::Row;

use crate::PgStore;
use crate::cotx::PgTenantPool;
use crate::outbox::{OutboxEnvelope, epoch_secs_to_time, metadata_with_ambient, unix_secs};
use crate::projection_events::ProjectionWriteRegistry;

/// PostgreSQL 会话生命周期 adapter（impl [`SessionLifecycle`]：创建 co-tx + durable find/revoke 均已交付，#1278）。
///
/// 经 [`PgStore`] 的 `pool`（`pub(crate)`，share-pool 注入，与 [`crate::PgEmitter`] 同形）clone 构造；
/// 不持 `PgStore`（避免 ManagedResource 所有权耦合）。
///
/// `clock` 是注入的 [`Clock`]（必填构造器位置参，`Box<dyn Clock>`，同 [`crate::PgEmitter`] 与全项目约定）：
/// envelope `occurred_at` 时间源（#1129）。
pub struct PgSessionLifecycle {
    pool: PgTenantPool,
    clock: Box<dyn Clock>,
    #[cfg(all(test, feature = "integration"))]
    revoke_post_update_hook: Option<fn() -> Result<(), IdentityError>>,
}

impl PgSessionLifecycle {
    /// 由 [`PgStore`] 构造（clone 其 `pool`）+ 注入 [`Clock`]（envelope `occurred_at` 时间源）。
    ///
    /// `pub(crate)`（#1423，PG-BUNDLE-FUNNEL-01）：经 [`crate::PgDomainDeps`]`<caps::Identity>::session_lifecycle` 收口。
    #[cfg(all(test, feature = "integration"))]
    pub(crate) fn new(store: &PgStore, clock: Box<dyn Clock>) -> Self {
        Self::new_with_projection_registry(store, clock, ProjectionWriteRegistry::empty())
    }

    pub(crate) fn new_with_projection_registry(
        store: &PgStore,
        clock: Box<dyn Clock>,
        projection_registry: ProjectionWriteRegistry,
    ) -> Self {
        Self {
            pool: PgTenantPool::with_projection_registry(store, projection_registry),
            clock,
            #[cfg(all(test, feature = "integration"))]
            revoke_post_update_hook: None,
        }
    }

    /// 测试专用：让 `revoke` 在真实 UPDATE 后、事务提交前返回 storage error。
    #[cfg(all(test, feature = "integration"))]
    pub(crate) fn with_revoke_post_update_error(mut self) -> Self {
        self.revoke_post_update_hook = Some(revoke_post_update_error);
        self
    }
}

impl SessionLifecycle for PgSessionLifecycle {
    async fn persist_session_and_emit(
        &self,
        scope: TenantRepoScope,
        session: Session,
        entry: EventEntry,
        envelope: OutboxEnvelopeParts,
    ) -> Result<(), OutboxEmitError> {
        // opaque parts → sealed OutboxMetadata funnel（仅 opaque subjectId，FR-020；同 PgEmitter）。`contract` 是
        // 契约派生绑定（#1193），routing 列经 `domain()`/`contract_id()` 取。reserved key occurred_at 由
        // `OutboxMetadata::new` **构造期必填**从注入 Clock 注入（#1129/#262 F1）；trace / correlation 经 sealed
        // setter（源待 #1296）、principal 待 #1296——业务侧均不可伪造（同 PgEmitter）。
        let (contract, env_tenant, subject_id, actor, partition_key, causation_id) =
            envelope.into_parts();
        let tenant = session.tenant();
        if scope.tenant() != tenant {
            return Err(OutboxEmitError::new(std::io::Error::other(
                "session co-tx: scope tenant does not match session tenant",
            )));
        }
        if env_tenant != tenant {
            return Err(OutboxEmitError::new(std::io::Error::other(
                "session co-tx: outbox envelope tenant does not match session tenant",
            )));
        }
        let env = OutboxEnvelope::new(
            contract.domain().to_string(),
            contract.contract_id().to_string(),
            metadata_with_ambient(unix_secs(self.clock.now()), tenant, contract)
                .with_subject_id(subject_id)
                .with_actor(actor),
        )
        .with_partition_key_opt(partition_key)
        .with_causation_id_opt(causation_id);
        self.pool
            .co_tx_with_outbox(
                scope,
                &entry,
                &env,
                move |conn| {
                    Box::pin(async move {
                        write_session(conn.conn(), &session)
                            .await
                            .map_err(OutboxEmitError::new)
                    })
                },
                OutboxEmitError::new,
            )
            .await
    }

    async fn find(
        &self,
        scope: TenantRepoScope,
        session_id: SessionId,
    ) -> Result<Option<Session>, IdentityError> {
        let tenant = scope.tenant();
        // 读经 cotx [`tenant_scoped_read`] 注入 SET LOCAL（与 `PgRoleRepo` / `PgConfigRepo` / `PgSecretRepo` /
        // `PgCredentialRepo` / `PgRefreshTokenStore` 读路径**统一收口**，对齐 0009 RLS policy current_setting
        // 锚点）+ 显式 `WHERE tenant_id` 双保险；跨租 → 0 行 → None（fail-closed）。`revoked = false` 过滤软撤销。
        // **不**过滤过期：expiry 是下游 / JWT-TTL 关注，与 in-mem `InMemSessionLifecycle` / demo
        // `MemSessionLifecycle` 的 find 语义对齐（provider 行为一致；硬吊销延 #1003）。读闭包仅 fetch + try_get
        // 返 owned 原始值（不借连接）；`Session::hydrate` 在 tx 外执行（域错误不依赖 sqlx）。时刻经持久化 epoch 列
        // 还原（`extract(epoch ...)::bigint`，与写路径 `to_timestamp(unix_secs)` 编码对称，不加 sqlx 时间 feature）。
        let tenant_uuid = tenant.as_uuid().to_string();
        let session_id_q = session_id.as_str().to_owned();
        let raw = self
            .pool
            .read(scope, move |conn| {
                Box::pin(async move {
                    let row = sqlx::query(
                        r#"
                    SELECT subject,
                           extract(epoch from expires_at)::bigint AS expires_at,
                           extract(epoch from created_at)::bigint AS created_at
                    FROM sessions
                    WHERE tenant_id = $1::uuid AND session_id = $2 AND revoked = false
                    "#,
                    )
                    .bind(tenant_uuid)
                    .bind(session_id_q)
                    .fetch_optional(&mut *conn)
                    .await?;
                    match row {
                        None => Ok(None),
                        Some(r) => {
                            let subject: String = r.try_get("subject")?;
                            let expires_at: i64 = r.try_get("expires_at")?;
                            let created_at: i64 = r.try_get("created_at")?;
                            Ok(Some((subject, expires_at, created_at)))
                        }
                    }
                })
            })
            .await
            .map_err(storage)?;
        match raw {
            None => Ok(None),
            // 受控重建（WHERE 已锁 session_id / tenant = 入参，复用即存储值，同 `Role::hydrate` 复用 id）。
            Some((subject, expires_at, created_at)) => Ok(Some(Session::hydrate(
                session_id.as_str(),
                subject,
                tenant,
                epoch_secs_to_time(expires_at),
                epoch_secs_to_time(created_at),
            ))),
        }
    }

    async fn revoke(
        &self,
        scope: TenantRepoScope,
        session_id: SessionId,
    ) -> Result<(), IdentityError> {
        let tenant = scope.tenant();
        // 软撤销 = tenant-scoped 事务（SET LOCAL 锚点，与 co-tx 写 / `PgRoleRepo::save` 统一收口）内
        // `UPDATE ... SET revoked = true`。幂等：未知 / 跨租（`WHERE tenant_id` 不匹配）/ 已撤销均 0 行影响、仍
        // `Ok(())`（与 in-mem / demo provider 的幂等 no-op 语义对齐）。软撤销不删行（保留审计 + 幂等）。
        let tenant_uuid = tenant.as_uuid().to_string();
        #[cfg(all(test, feature = "integration"))]
        let post_update_hook = self.revoke_post_update_hook;
        self.pool
            .write(
                scope,
                move |conn| {
                    Box::pin(async move {
                        sqlx::query(
                            "UPDATE sessions SET revoked = true WHERE tenant_id = $1::uuid AND session_id = $2",
                        )
                        .bind(&tenant_uuid)
                        .bind(session_id.as_str())
                        .execute(conn.conn())
                        .await
                        .map_err(storage)?;
                        #[cfg(all(test, feature = "integration"))]
                        if let Some(hook) = post_update_hook {
                            hook()?;
                        }
                        Ok(())
                    })
                },
                storage,
            )
            .await
    }
}

#[cfg(all(test, feature = "integration"))]
fn revoke_post_update_error() -> Result<(), IdentityError> {
    Err(IdentityError::Storage(Box::new(std::io::Error::other(
        "forced post-update revoke failure",
    ))))
}

/// sqlx 错误 → 域 storage 错误（装箱保留 source；域 crate 不依赖 sqlx，adapter 边界收口；同 `PgRoleRepo`）。
fn storage(e: sqlx::Error) -> IdentityError {
    IdentityError::Storage(Box::new(e))
}

/// 同一 tenant-scoped 事务内写 session；outbox append 由 [`PgTenantPool::co_tx_with_outbox`] 接续执行。
async fn write_session(
    conn: &mut sqlx::PgConnection,
    session: &Session,
) -> Result<(), sqlx::Error> {
    let tenant = session.tenant().as_uuid().to_string();
    // session 行（同 tx；ON CONFLICT 幂等——重试登录安全，同 append_outbox 范式）。
    sqlx::query(
        r#"
        INSERT INTO sessions (session_id, subject, tenant_id, expires_at, created_at)
        VALUES ($1, $2, $3::uuid, to_timestamp($4), to_timestamp($5))
        ON CONFLICT (session_id) DO NOTHING
        "#,
    )
    .bind(session.id().as_str())
    .bind(session.subject())
    .bind(&tenant)
    .bind(unix_secs(session.expires_at()))
    .bind(unix_secs(session.created_at()))
    .execute(conn)
    .await
    .map(|_| ())
}
