//! `PgEmitter` —— durable outbox 发射 adapter（impl `diport::OutboxEmitter`）。
//!
//! producer 侧 durable 落库端口：域 crate（如 identity 登录）经 `diport::OutboxEmitter` 触发，把一条
//! `consistency::Entry`（topic + idem_key(EventId) + 编码 payload）写进 `outbox` 表（pending）；relay
//! （[`crate::PgOutbox`]）随后 CAS 中继到 broker。域**不**命名 `PgConnection` / `OutboxEnvelope`——envelope
//! 字段以 opaque `diport::OutboxEnvelopeParts` 传入，本 adapter 经 sealed [`crate::outbox::OutboxMetadata`]
//! funnel 组装（仅 opaque subject_id，FR-020 / `observability.md` §Outbox Envelope）。
//!
//! **单事实 emit 语义（#1100）**：本 adapter 将一条 [`consistency::Entry`] 原子落库（单事务），用于**无
//! co-located 业务写**的 OutboxFact 事件（纯通知）。与业务写（如 session 持久化）同事务的 **co-tx 原子性**
//! （FR-003 完整 L2）**已交付**（#1083/#1192）：经 [`crate::PgSessionUnitOfWork`]（复用 `append_outbox` + 同
//! 一事务写 session 行，INVARIANT OUTBOX-COTX-SESSION-01）承载，与本 emit-only adapter 语义正交。本 adapter
//! 的单事实写语义不变。
//!
//! ref: debezium outbox SMT（业务写 + outbox 行同一本地事务，producer 侧 durable 落库）

use consistency::Entry;
use diport::{Clock, OutboxEmitError, OutboxEmitter, OutboxEnvelopeParts};
use sqlx::PgPool;

use crate::PgStore;
use crate::outbox::{OutboxEnvelope, OutboxMetadata, append_outbox, unix_secs};

/// PostgreSQL outbox 发射 adapter（impl [`OutboxEmitter`]）。
///
/// 经 [`PgStore`] 的 `pool`（`pub(crate)`，share-pool 注入，与 [`crate::PgOutbox`] 同形）clone 构造；
/// 不持 `PgStore`（避免 ManagedResource 所有权耦合）。
///
/// **时间源**：`clock` 是注入的 [`Clock`]（必填构造器位置参，缺失即编译错误——rust-standards §工程护栏），
/// 仅用于 envelope `occurred_at`。与 [`crate::PgOutbox`] 刻意用 SQL `now()` 的 lease/retry 谓词（多实例需单一、
/// 无跨进程偏移的时间源）**不同**：那是 relay 端时间，本 emitter 的 `occurred_at` 是 producer 端事件发生时刻，
/// 故注入 `Clock`（#1129）。
pub struct PgEmitter {
    pool: PgPool,
    clock: Box<dyn Clock>,
}

impl PgEmitter {
    /// 由 [`PgStore`] 构造（clone 其 `pool`）+ 注入 [`Clock`]（envelope `occurred_at` 时间源）。
    /// `clock` 为 `Box<dyn Clock>`（与全项目 clock 注入约定及 `diport::Clock` rustdoc 一致；adapter 独占其
    /// 时钟、不跨线程共享，无需 `Arc`）。
    pub fn new(store: &PgStore, clock: Box<dyn Clock>) -> Self {
        Self {
            pool: store.pool.clone(),
            clock,
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
        // occurred_at 由 `OutboxMetadata::new` **构造期必填**从注入 Clock 注入（#1129/#262 F1：漏接编译期不可表达）；
        // trace / correlation / principal 为后续 follow-up（#1296）接线的空接缝。reserved key 业务侧不可伪造：
        // 构造期注入 + free-form `try_insert` fail-closed 拒（observability.md §Outbox Envelope）。
        let env = OutboxEnvelope::new(
            envelope.domain,
            envelope.contract_id,
            OutboxMetadata::new(unix_secs(self.clock.now())).with_subject_id(envelope.subject_id),
        );
        // durable 写入事务内执行（`append_outbox` 类型层强制 `&mut PgConnection` ⇒ 必在事务内）。与
        // `PgStore::run_in_transaction` 同形（PgEmitter 经 share-pool 注入持 pool、非 PgStore 方法，故此处
        // 自持事务）。co-tx（session 写 + append 同事务）走 [`crate::PgSessionUnitOfWork`]，非本 emit-only 路径。
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
