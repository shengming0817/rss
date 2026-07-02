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
//! （FR-003 完整 L2）**已交付**（#1083/#1192）：经 [`crate::PgSessionLifecycle`]（复用 `append_outbox` + 同
//! 一事务写 session 行，INVARIANT OUTBOX-COTX-SESSION-01）承载，与本 emit-only adapter 语义正交。本 adapter
//! 的单事实写语义不变。
//!
//! ref: debezium outbox SMT（业务写 + outbox 行同一本地事务，producer 侧 durable 落库）

use consistency::Entry;
use diport::{Clock, OutboxEmitError, OutboxEmitter, OutboxEnvelopeParts};

use crate::PgStore;
use crate::cotx::PgTenantPool;
use crate::outbox::{OutboxEnvelope, append_outbox, metadata_with_ambient, unix_secs};

/// PostgreSQL outbox 发射 adapter（impl [`OutboxEmitter`]）。
///
/// 经 [`PgTenantPool`] 持有 tenant-scoped write funnel；不暴露裸 pool / begin 出口。
///
/// **时间源**：`clock` 是注入的 [`Clock`]（必填构造器位置参，缺失即编译错误——rust-standards §工程护栏），
/// 仅用于 envelope `occurred_at`。与 [`crate::PgOutbox`] 刻意用 SQL `now()` 的 lease/retry 谓词（多实例需单一、
/// 无跨进程偏移的时间源）**不同**：那是 relay 端时间，本 emitter 的 `occurred_at` 是 producer 端事件发生时刻，
/// 故注入 `Clock`（#1129）。
pub struct PgEmitter {
    pool: PgTenantPool,
    clock: Box<dyn Clock>,
}

impl PgEmitter {
    /// 由 [`PgStore`] 构造 tenant-scoped pool wrapper + 注入 [`Clock`]（envelope `occurred_at` 时间源）。
    /// `clock` 为 `Box<dyn Clock>`（与全项目 clock 注入约定及 `diport::Clock` rustdoc 一致；adapter 独占其
    /// 时钟、不跨线程共享，无需 `Arc`）。
    ///
    /// `pub(crate)`（#1423，PG-BUNDLE-FUNNEL-01）：经 [`crate::PgInfraDeps::emitter`] 收口（provider-agnostic 基建，非单域）。
    pub(crate) fn new(store: &PgStore, clock: Box<dyn Clock>) -> Self {
        Self {
            pool: PgTenantPool::new(store),
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
        // opaque parts → sealed OutboxMetadata funnel（仅 opaque subject_id，FR-020）。`contract` 是契约派生
        // 绑定（#1193/#1618：domain + contract_id + version + schema_hash 同源、business 不可伪造），
        // routing 列经 `domain()`/`contract_id()` 取，标准 header 经 `version()`/`schema_hash()` 盖章。
        // reserved key occurred_at 由 `OutboxMetadata::new` **构造期必填**从注入 Clock 注入（#1129/#262 F1：漏接
        // 编译期不可表达）；trace / correlation 经 sealed setter（源待 #1296）、principal 待 #1296——业务侧均不可
        // 伪造：构造期注入 + free-form `try_insert` fail-closed 拒（observability.md §Outbox Envelope）。
        let (contract, tenant, subject_id, actor, partition_key, causation_id) =
            envelope.into_parts();
        let env = OutboxEnvelope::new(
            contract.domain().to_string(),
            contract.contract_id().to_string(),
            metadata_with_ambient(unix_secs(self.clock.now()), tenant, contract)
                .with_subject_id(subject_id)
                .with_actor(actor),
        )
        .with_partition_key_opt(partition_key)
        .with_causation_id_opt(causation_id);
        // durable 写入事务内执行；事务打开、SET LOCAL、commit_unknown 与 rollback 统一由 PgTenantPool::write 承载。
        self.pool
            .write(
                env.tenant(),
                move |tx| {
                    Box::pin(async move {
                        append_outbox(tx, &entry, &env)
                            .await
                            .map_err(OutboxEmitError::new)
                    })
                },
                OutboxEmitError::new,
            )
            .await
    }
}
