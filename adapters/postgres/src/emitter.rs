//! `PgEmitter` —— durable reviewed-event writer.
//!
//! Producer-side durable persistence accepts only an `eventexec::event::ReviewedEvent`, whose
//! generated fact, encoded payload, tenant, subject and actor were bound before this adapter is
//! reached. The adapter writes one pending `outbox` row; [`crate::PgOutbox`] later relays it through
//! the CAS state machine. No raw entry/envelope production API is implemented.
//!
//! **单事实 emit 语义（#1100）**：本 adapter 将一条 [`consistency::EventEntry`] 原子落库（单事务），用于**无
//! co-located 业务写**的 OutboxFact 事件（纯通知）。与业务写（如 session 持久化）同事务的 **co-tx 原子性**
//! （INVARIANT OUTBOX-COTX-SESSION-01）**已交付**（#1083/#1192）：经 [`crate::PgAuthGrantLifecycle`]（复用 `append_outbox` + 同
//! 一事务写 session 行，INVARIANT OUTBOX-COTX-SESSION-01）承载，与本 emit-only adapter 语义正交。本 adapter
//! 的单事实写语义不变。
//!
//! ref: debezium outbox SMT（业务写 + outbox 行同一本地事务，producer 侧 durable 落库）

use diport::OutboxEmitError;
use eventexec::event::{ReviewedEvent, ReviewedEventWriter};

#[cfg(all(test, feature = "integration"))]
use crate::PgStore;
use crate::cotx::{ServingWriteLane, TenantDb, infra_tenant_scope};
use crate::outbox::{
    OutboxAppendError, OutboxEnvelope, append_outbox_with_projection, metadata_from_reviewed_event,
};
use crate::pool::VerifiedPgWriteStore;
use crate::projection_events::ProjectionWriteRegistry;

/// PostgreSQL durable outbox writer for sealed [`ReviewedEvent`] capabilities.
///
/// 经 exact serving-write [`TenantDb`] 持有 tenant-scoped write funnel；不暴露裸 pool / begin 出口。
///
/// Envelope `occurred_at` comes from the sealed [`ReviewedEvent`]; this provider cannot resample
/// or substitute an adapter clock.
pub struct PgEmitter {
    pool: TenantDb<ServingWriteLane>,
}

impl PgEmitter {
    /// 由 [`PgStore`] 构造 tenant-scoped pool wrapper。
    ///
    /// `pub(crate)`（#1423，PG-BUNDLE-FUNNEL-01）：经 [`crate::PgInfraDeps::emitter`] 收口（provider-agnostic 基建，非单域）。
    #[cfg(all(test, feature = "integration"))]
    pub(crate) fn new(store: &PgStore) -> Self {
        Self {
            pool: TenantDb::<ServingWriteLane>::from_unverified_for_test(store),
        }
    }

    pub(crate) fn new_with_projection_registry(
        store: &VerifiedPgWriteStore,
        projection_registry: ProjectionWriteRegistry,
    ) -> Self {
        Self {
            pool: TenantDb::<ServingWriteLane>::with_projection_registry(
                store,
                projection_registry,
            ),
        }
    }
}

impl ReviewedEventWriter for PgEmitter {
    async fn write(&self, event: ReviewedEvent) -> Result<(), OutboxEmitError> {
        let (entry, envelope, metadata, _fact) = event.into_parts();
        // opaque parts → sealed OutboxMetadata funnel（仅 opaque subject_id；OUTBOX-METADATA-FUNNEL-01）。`contract` 是契约派生
        // 绑定（#1193/#1618：domain + contract_id + version + schema_hash 同源、business 不可伪造），
        // routing 列经 `domain()`/`contract_id()` 取，标准 header 经 `version()`/`schema_hash()` 盖章。
        // reserved key occurred_at 由 sealed ReviewedEvent **构造期必填**携带；trace / correlation 经
        // sealed setter（源待 #1296）、principal 待 #1296——业务侧均不可
        // 伪造：构造期注入 + free-form `try_insert` fail-closed 拒（`crates/observ`、`secure::redact_error` 与 typed metric enums）。
        let (contract, _tenant, subject_id, actor, partition_key, causation_id) =
            envelope.into_parts();
        let env = OutboxEnvelope::new(
            contract.domain().to_string(),
            contract.contract_id().to_string(),
            metadata_from_reviewed_event(&metadata, contract)
                .with_subject_id(subject_id)
                .with_actor(actor),
        )
        .with_partition_key_opt(partition_key)
        .with_causation_id_opt(causation_id);
        // durable 写入事务内执行；事务打开、SET LOCAL、commit_unknown 与 rollback 统一由 exact serving-write funnel 承载。
        let projection_registry = self.pool.projection_registry();
        self.pool
            .outbox_write(
                infra_tenant_scope(env.tenant()),
                move |mut tx| {
                    Box::pin(async move {
                        append_outbox_with_projection(&mut tx, &entry, &env, &projection_registry)
                            .await
                            .map(|_| ())
                            .map_err(OutboxAppendError::into_observed_emit_error)
                    })
                },
                OutboxEmitError::new,
            )
            .await
    }
}
