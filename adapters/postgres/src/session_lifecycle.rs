//! `PgSessionLifecycle` —— identity 会话生命周期 adapter（impl `identity::ports::SessionLifecycle`，合并原
//! `PgSessionUnitOfWork`，#1278）。
//!
//! **完整生命周期均 durable 交付**（#1278，原 #1116 session 闭合）：创建（co-tx）+ 查询 `find`（tenant-scope
//! SELECT + `revoked = false` 过滤 + `Session::hydrate` 重建）+ 软撤销 `revoke`（tenant-scoped tx
//! `UPDATE ... SET revoked = true`，幂等）。`revoked` 列由 `0009_add_sessions_revoked.sql` 迁移引入。
//! 合并为单一 `SessionLifecycle` 后 postgres provider **不留 `todo!()` 半实现**——`LoginService::logout` 经
//! `revoke` 落到真实软撤销路径（消除「trait 看似完整、生产 read/revoke panic」的接缝，PR #273 codex F1）。
//!
//! L2 OutboxFact 完整语义（FR-003）：把一次登录的 [`Session`] 业务写与 outbox(`identity.session-created`)
//! append **同一本地事务**原子落库（both-or-neither）。取代「emit-only `PgEmitter` + 无 session 持久化」的
//! 单事实路径——因登录现已有业务写（session）。emit-only [`crate::PgEmitter`] 仍保留，作无业务写
//! OutboxFact 事件的通用能力（二者语义正交，#1083/#1192）。
//!
//! # INVARIANT: OUTBOX-COTX-SESSION-01
//!
//! session 行与 outbox 行在**同一** `PgStore` 事务内写入 → 共 commit / 共 rollback；无 API 可单提交其一。
//! adapter 独占事务边界（`begin` → `SET LOCAL` tenant → INSERT session → `append_outbox` → 单 `commit`）；
//! 域经 combined 方法 `persist_session_and_emit` 调用，**无半开事务句柄**——co-tx 不可拆解在类型层成立
//! （**Hard**：域 split-tx 不可表达）。`append_outbox` 既有 OUTBOX-ATOMIC-IDEM-01（`&mut PgConnection`-only）
//! 保证 outbox 写在同一 tx；session INSERT 同 `&mut *tx`。adapter same-tx 接线由集成测试 anti-vacuity 守：
//! `t11`（真实 method commit 两行皆在）↔ 负向 `t12`（co-tx SQL 序列强制 Err 两写共回滚）+ `t14`（**直测真实
//! method** rollback 分支：session INSERT 溢出 → 两行皆无）。
//!
//! tenant scope（tenancy.md §RLS 与 PG scope）：INSERT 前在同一 tx 内 `set_config('rss.tenant_id', $1, true)`
//! （= SET LOCAL，参数化绑 typed [`TenantId`]，防注入；SET LOCAL 不接 bind 故用 set_config(is_local=true)）。
//! 预 GA 仓内尚无 RLS policy，故此刻 SET LOCAL 为前向兼容锚点；session 行 `tenant_id` 列显式写入已保证写入
//! tenant-correct。
//!
//! ref: debezium outbox SMT（业务写 + outbox 行同一本地事务，producer 侧 durable 落库）
//! ref: MassTransit Bus Outbox（一应用方法 co-persist 实体 + outbox 经共享事务/scoped DbContext）

use consistency::Entry;
use diport::{Clock, OutboxEmitError, OutboxEnvelopeParts};
use identity::ports::{IdentityError, Session, SessionId, SessionLifecycle, TenantId};
use sqlx::{PgPool, Row};

use crate::PgStore;
use crate::cotx::set_local_tenant;
use crate::outbox::{OutboxEnvelope, OutboxMetadata, append_outbox, epoch_secs_to_time, unix_secs};

/// PostgreSQL 会话生命周期 adapter（impl [`SessionLifecycle`]：创建 co-tx + durable find/revoke 均已交付，#1278）。
///
/// 经 [`PgStore`] 的 `pool`（`pub(crate)`，share-pool 注入，与 [`crate::PgEmitter`] 同形）clone 构造；
/// 不持 `PgStore`（避免 ManagedResource 所有权耦合）。
///
/// `clock` 是注入的 [`Clock`]（必填构造器位置参，`Box<dyn Clock>`，同 [`crate::PgEmitter`] 与全项目约定）：
/// envelope `occurred_at` 时间源（#1129）。
pub struct PgSessionLifecycle {
    pool: PgPool,
    clock: Box<dyn Clock>,
}

impl PgSessionLifecycle {
    /// 由 [`PgStore`] 构造（clone 其 `pool`）+ 注入 [`Clock`]（envelope `occurred_at` 时间源）。
    pub fn new(store: &PgStore, clock: Box<dyn Clock>) -> Self {
        Self {
            pool: store.pool.clone(),
            clock,
        }
    }
}

impl SessionLifecycle for PgSessionLifecycle {
    async fn persist_session_and_emit(
        &self,
        session: Session,
        entry: Entry,
        envelope: OutboxEnvelopeParts,
    ) -> Result<(), OutboxEmitError> {
        // opaque parts → sealed OutboxMetadata funnel（仅 opaque subjectId，FR-020；同 PgEmitter）。`contract` 是
        // 契约派生绑定（#1193），routing 列经 `domain()`/`contract_id()` 取。reserved key occurred_at 由
        // `OutboxMetadata::new` **构造期必填**从注入 Clock 注入（#1129/#262 F1）；trace / correlation 经 sealed
        // setter（源待 #1296）、principal 待 #1296——业务侧均不可伪造（同 PgEmitter）。
        let (contract, subject_id) = envelope.into_parts();
        let env = OutboxEnvelope::new(
            contract.domain().to_string(),
            contract.contract_id().to_string(),
            OutboxMetadata::new(unix_secs(self.clock.now())).with_subject_id(subject_id),
        );
        let tx = self.pool.begin().await.map_err(OutboxEmitError::new)?;
        persist_and_emit_in_tx(tx, &session, &entry, &env).await
    }

    async fn find(
        &self,
        tenant: TenantId,
        session_id: SessionId,
    ) -> Result<Option<Session>, IdentityError> {
        // 读经 pool 直查 + 显式 `WHERE tenant_id`（pre-GA 无 RLS policy，读路径不注入 SET LOCAL——同
        // `PgRoleRepo::find` / `PgConfigRepo::find` 仓库范围一致约定）；跨租 → 0 行 → None（fail-closed）。
        // `revoked = false` 过滤软撤销。**不**过滤过期：expiry 是下游 / JWT-TTL 关注，与 in-mem
        // `InMemSessionLifecycle` / demo `MemSessionLifecycle` 的 find 语义对齐（provider 行为一致；硬吊销延 #1003）。
        // 时刻经持久化 epoch 列还原（`extract(epoch ...)::bigint`，与写路径 `to_timestamp(unix_secs)` 编码对称，
        // 不加 sqlx 时间 feature）。
        let row = sqlx::query(
            r#"
            SELECT subject,
                   extract(epoch from expires_at)::bigint AS expires_at,
                   extract(epoch from created_at)::bigint AS created_at
            FROM sessions
            WHERE tenant_id = $1::uuid AND session_id = $2 AND revoked = false
            "#,
        )
        .bind(tenant.as_uuid().to_string())
        .bind(session_id.as_str())
        .fetch_optional(&self.pool)
        .await
        .map_err(storage)?;
        match row {
            None => Ok(None),
            Some(r) => {
                let subject: String = r.try_get("subject").map_err(storage)?;
                let expires_at: i64 = r.try_get("expires_at").map_err(storage)?;
                let created_at: i64 = r.try_get("created_at").map_err(storage)?;
                // 受控重建（WHERE 已锁 session_id / tenant = 入参，复用即存储值，同 `Role::hydrate` 复用 id）。
                Ok(Some(Session::hydrate(
                    session_id.as_str(),
                    subject,
                    tenant,
                    epoch_secs_to_time(expires_at),
                    epoch_secs_to_time(created_at),
                )))
            }
        }
    }

    async fn revoke(&self, tenant: TenantId, session_id: SessionId) -> Result<(), IdentityError> {
        // 软撤销 = tenant-scoped 事务（SET LOCAL 锚点，与 co-tx 写 / `PgRoleRepo::save` 统一收口）内
        // `UPDATE ... SET revoked = true`。幂等：未知 / 跨租（`WHERE tenant_id` 不匹配）/ 已撤销均 0 行影响、仍
        // `Ok(())`（与 in-mem / demo provider 的幂等 no-op 语义对齐）。软撤销不删行（保留审计 + 幂等）。
        let tenant_uuid = tenant.as_uuid().to_string();
        let mut tx = self.pool.begin().await.map_err(storage)?;
        set_local_tenant(&mut tx, &tenant_uuid)
            .await
            .map_err(storage)?;
        let result = sqlx::query(
            "UPDATE sessions SET revoked = true WHERE tenant_id = $1::uuid AND session_id = $2",
        )
        .bind(&tenant_uuid)
        .bind(session_id.as_str())
        .execute(&mut *tx)
        .await;
        match result {
            Ok(_) => tx.commit().await.map_err(|e| {
                tracing::warn!(
                    target: "postgres",
                    error = %secure::redact_error(&e),
                    "session revoke: commit failed"
                );
                storage(e)
            }),
            Err(e) => {
                // rollback 失败是运维高价值事件（连接泄漏 / PG 断线），补 warn（与 co-tx / role save 分支对齐）；
                // 不覆盖原写错误；Transaction Drop 亦兜底回滚。
                if let Err(rb) = tx.rollback().await {
                    tracing::warn!(
                        target: "postgres",
                        error = %secure::redact_error(&rb),
                        "session revoke: rollback failed after update error"
                    );
                }
                Err(storage(e))
            }
        }
    }
}

/// sqlx 错误 → 域 storage 错误（装箱保留 source；域 crate 不依赖 sqlx，adapter 边界收口；同 `PgRoleRepo`）。
fn storage(e: sqlx::Error) -> IdentityError {
    IdentityError::Storage(Box::new(e))
}

/// co-tx 事务体：写两行（SET LOCAL + INSERT session + append_outbox）→ 单 commit；失败 rollback + warn
/// （与 emit 分离以控认知复杂度，同 emitter.rs `emit_in_tx`）。
async fn persist_and_emit_in_tx(
    mut tx: sqlx::Transaction<'_, sqlx::Postgres>,
    session: &Session,
    entry: &Entry,
    env: &OutboxEnvelope,
) -> Result<(), OutboxEmitError> {
    if let Err(e) = write_session_and_outbox(&mut tx, session, entry, env).await {
        tracing::warn!(
            target: "postgres",
            event_id = entry.idem_key().as_str(),
            domain = env.domain(),
            topic = entry.topic().as_str(),
            error = %secure::redact_error(&e),
            "session co-tx: session+outbox write failed"
        );
        rollback_warn(tx).await;
        return Err(OutboxEmitError::new(e));
    }
    tx.commit().await.map_err(|e| {
        tracing::warn!(
            target: "postgres",
            event_id = entry.idem_key().as_str(),
            domain = env.domain(),
            topic = entry.topic().as_str(),
            error = %secure::redact_error(&e),
            "session co-tx: commit failed"
        );
        OutboxEmitError::new(e)
    })
}

/// 同一事务内：注入 tenant scope（SET LOCAL）→ INSERT session → append outbox（co-tx 双写）。
async fn write_session_and_outbox(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    session: &Session,
    entry: &Entry,
    env: &OutboxEnvelope,
) -> Result<(), sqlx::Error> {
    let tenant = session.tenant().as_uuid().to_string();
    // tenant scope（事务级，commit/rollback 自动失效）。SET LOCAL 不接 bind ⇒ 用 set_config(is_local=true)。
    sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
        .bind(&tenant)
        .execute(&mut **tx)
        .await?;
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
    .execute(&mut **tx)
    .await?;
    // outbox append（同 tx — co-tx 原子性 FR-003；复用既有 append_outbox + OUTBOX-ATOMIC-IDEM-01）。
    // `tx: &mut Transaction` 经 deref 强制成 append_outbox 的 `&mut PgConnection`（auto-deref）。
    append_outbox(tx, entry, env).await
}

/// rollback 并在失败时记 warn（不覆盖调用方原错误；同 emitter.rs `rollback_warn`）。
async fn rollback_warn(tx: sqlx::Transaction<'_, sqlx::Postgres>) {
    if let Err(rb) = tx.rollback().await {
        tracing::warn!(
            target: "postgres",
            error = %secure::redact_error(&rb),
            "session co-tx: rollback failed after write error"
        );
    }
}
