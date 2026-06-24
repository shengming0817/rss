//! `PgEmitter` —— durable outbox 发射 adapter（impl `diport::OutboxEmitter`）。
//!
//! producer 侧 durable 落库端口：域 crate（如 identity 登录）经 `diport::OutboxEmitter` 触发，把一条
//! `consistency::Entry`（topic + idem_key(EventId) + 编码 payload）写进 `outbox` 表（pending）；relay
//! （[`crate::PgOutbox`]）随后 CAS 中继到 broker。域**不**命名 `PgConnection` / `OutboxEnvelope`——envelope
//! 字段以 opaque `diport::OutboxEnvelopeParts` 传入，本 adapter 经 sealed [`crate::outbox::OutboxMetadata`]
//! funnel 组装（仅 opaque subject_id，FR-020 / `observability.md` §Outbox Envelope）。
//!
//! **单事实 emit 语义（#1100）**：本 adapter 将一条 [`consistency::Entry`] 原子落库（单事务）；outbox 写是
//! 此阶段唯一 durable 写，自成 OutboxFact。与业务写（如 session 持久化）同事务的 **co-tx 原子性**
//! （FR-003 完整 L2）属 #1083——届时 session 写入经域 repo + unit-of-work 接缝与 `append_outbox`
//! 同一事务；本 adapter 的单事实写语义不变。`consistencyLevel=OutboxFact` 的 co-tx 维度为已跟踪缺口（#1083）。
//!
//! ref: debezium outbox SMT（业务写 + outbox 行同一本地事务，producer 侧 durable 落库）

use consistency::Entry;
use diport::{OutboxEmitError, OutboxEmitter, OutboxEnvelopeParts};
use sqlx::PgPool;

use crate::PgStore;
use crate::outbox::{OutboxEnvelope, OutboxMetadata, append_outbox};

/// PostgreSQL outbox 发射 adapter（impl [`OutboxEmitter`]）。
///
/// 经 [`PgStore`] 的 `pool`（`pub(crate)`，share-pool 注入，与 [`crate::PgOutbox`] 同形）clone 构造；
/// 不持 `PgStore`（避免 ManagedResource 所有权耦合）。
pub struct PgEmitter {
    pool: PgPool,
}

impl PgEmitter {
    /// 由 [`PgStore`] 构造（clone 其 `pool`）。
    pub fn new(store: &PgStore) -> Self {
        Self {
            pool: store.pool.clone(),
        }
    }
}

impl OutboxEmitter for PgEmitter {
    async fn emit(
        &self,
        entry: Entry,
        envelope: OutboxEnvelopeParts,
    ) -> Result<(), OutboxEmitError> {
        // opaque parts → sealed OutboxMetadata funnel（仅 opaque subject_id，FR-020）。reserved key
        // （trace / correlation / occurred_at）的受控注入路径属后续（funnel 现 fail-closed 拒 reserved、
        // 无 sealed setter）——见 PR 说明 / #1100 OOS。
        let env = OutboxEnvelope::new(
            envelope.domain,
            envelope.contract_id,
            OutboxMetadata::new().with_subject_id(envelope.subject_id),
        );
        // durable 写入事务内执行（`append_outbox` 类型层强制 `&mut PgConnection` ⇒ 必在事务内）。与
        // `PgStore::run_in_transaction` 同形（PgEmitter 经 share-pool 注入持 pool、非 PgStore 方法，故此处
        // 自持事务）；#1083 接入真实 session 持久化时，session 写入此处与 append 同事务（FR-003 co-tx 原子性）。
        let tx = self.pool.begin().await.map_err(OutboxEmitError::new)?;
        emit_in_tx(tx, &entry, &env).await
    }
}

/// outbox 写入事务体（与 emit 分离以控制认知复杂度）。
async fn emit_in_tx(
    mut tx: sqlx::Transaction<'_, sqlx::Postgres>,
    entry: &Entry,
    env: &OutboxEnvelope,
) -> Result<(), OutboxEmitError> {
    if let Err(e) = append_outbox(&mut tx, entry, env).await {
        tracing::warn!(
            target: "postgres",
            event_id = entry.idem_key().as_str(),
            domain = env.domain(),
            topic = entry.topic().as_str(),
            error = %secure::redact_error(&e),
            "outbox emit: append failed"
        );
        rollback_warn(tx).await;
        return Err(OutboxEmitError::new(e));
    }
    tx.commit().await.map_err(|e| {
        tracing::warn!(
            target: "postgres",
            event_id = entry.idem_key().as_str(),
            domain = env.domain(),
            error = %secure::redact_error(&e),
            "outbox emit: commit failed"
        );
        OutboxEmitError::new(e)
    })
}

/// rollback 并在失败时记 warn（不覆盖调用方原错误）。
async fn rollback_warn(tx: sqlx::Transaction<'_, sqlx::Postgres>) {
    if let Err(rb) = tx.rollback().await {
        tracing::warn!(
            target: "postgres",
            error = %secure::redact_error(&rb),
            "outbox emit: rollback failed after append error"
        );
    }
}
