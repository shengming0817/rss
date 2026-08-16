//! postgres inbox_receipts adapter（消费幂等去重 + 租约 CAS，L2 一致性锚点，#1118 / #1213）。
//!
//! `PgInboxStore` 实现 [`consistency::InboxStore`] 引擎策略 trait（native AFIT，泛型静态分发消费，
//! 零 box，**非** diport DI port）。
//!
//! # 状态机：absent → claimed(lease_token) → done
//!
//! - **`try_claim`（claim-or-reclaim-or-skip）**：
//!   `INSERT ... ON CONFLICT DO UPDATE ... WHERE status='claimed' AND claimed_at <= now()-TTL`
//!   \+ `RETURNING`：
//!   - RETURNING 行存在（`Some`）→ [`SeenState::Fresh`]：首次插入，或 TTL 过期的 claimed 行被新 token 接管
//!     （stale reclaim，修复 crash-after-claim 时 key 永久 Duplicate 的丢消息风险，#1213）。
//!   - RETURNING 无行（`None`）后读冲突行：已 done → [`SeenState::Duplicate`]；他人持有
//!     有效 claim（lease 仍在 TTL 内）→ [`SeenState::InProgress`]，由 consumer lease-aware 延迟 Requeue，
//!     不得 Ack 丢失未完成的处理，也不得伪装成 backend transient。
//! - **`extend`（续租）**：刷新 `claimed_at`（CAS：lease_token + status='claimed'）；
//!   `rows_affected == 1` → [`LeaseOutcome::Held`]，否则 `Lost`（token 不符或已 done/absent）。
//! - **`commit`（claimed→done）**：CAS；`rows_affected == 1` → `Held`（保留窗口内去重），`0` → `Lost`（hard-fence）。
//! - **`release`（claimed→absent）**：DELETE CAS；token 不符为幂等 no-op（不误删他人 claim）。
//!
//! **时间源**：`claimed_at` 更新全部用 PostgreSQL `now()`（DB 事务时间），**刻意不注入 `Clock`**——多实例并发
//! 下需要单一、无跨进程偏移的时间源（TTL 比较在 DB 端一致求值，同 `outbox.rs:274` 既定理由）。
//!
//! 后端暂不可用（sqlx 错误）映射为 [`consistency::EngineErrorKind::Transient`]（可重试），
//! 原始 sqlx 错误不进 Display（PII 边界，error-handling.md §Message 与 PII）。
//!
//! ref: serverlesstechnology/cqrs（postgres persistence 幂等消费，INSERT ON CONFLICT 范式）。

use consistency::{
    BacklogSample, ConsumerGroup, EngineError, EngineErrorKind, IdemKey, InboxReceiptContext,
    InboxStore, LeaseOutcome, LeaseToken, RetentionSweeper, SeenState,
};
use eventexec::{
    InboxBacklogObservation, InboxBacklogSample, InboxBacklogSelection, InboxBacklogSource,
};
use sqlx::{PgPool, Row};

use crate::PgStore;
use crate::cotx::eventing::{EventingTx, InboxOperationConcern};
use crate::cotx::{ServingWriteLane, TenantDb, infra_tenant_scope};
use crate::delivery_policy::EventDeliveryPolicy;
use crate::pool::{VerifiedPgReadStore, VerifiedPgWriteStore};

/// inbox 租约过期阈值（秒）；claimed 行超此阈值未续租即可被 TTL 重捞（镜 outbox `LEASE_TTL_SECONDS`，#1213）。
///
/// `pub` 暴露供组合根读取——不应被业务代码直接使用；通过 [`PgInboxStore::lease_ttl`] 取类型化值。
pub const INBOX_LEASE_TTL_SECONDS: i64 = 60;

/// postgres inbox_receipts 幂等去重 store（claim-or-reclaim-or-skip + 租约 CAS + TTL 重捞，#1213）。
///
/// 私有字段分别持 typed read/write capability；tenant 表访问必须经对应 scope funnel。
pub struct PgInboxStore {
    write_pool: TenantDb<ServingWriteLane>,
}

#[cfg(all(test, feature = "integration"))]
impl PgStore {
    /// 构造 [`PgInboxStore`]。tenant/group scope 来自每次调用的 [`InboxReceiptContext`]。
    ///
    /// `pub(crate)`（#1423，PG-BUNDLE-FUNNEL-01）：经 [`crate::PgDomainDeps`]`<caps::Identity>::inbox` 收口。
    pub(crate) fn inbox(&self) -> PgInboxStore {
        PgInboxStore {
            write_pool: TenantDb::<ServingWriteLane>::from_unverified_for_test(self),
        }
    }

    /// Test-only construction of the cross-tenant aggregate source. Production construction is
    /// restricted to a verified `rss_app_read` capability.
    pub(crate) fn inbox_backlog_source(&self) -> PgInboxBacklogSource {
        PgInboxBacklogSource {
            pool: self.pool.clone(),
        }
    }
}

impl PgInboxStore {
    pub(crate) fn new(writer: &VerifiedPgWriteStore) -> Self {
        Self {
            write_pool: TenantDb::<ServingWriteLane>::new(writer),
        }
    }

    /// 供组合根派生 `eventexec::LeaseConfig::from_ttl(store.lease_ttl())`，使续租间隔与后端 claim TTL
    /// 同源（杜绝 mismatch footgun，#1213 review #3）。
    pub fn lease_ttl(&self) -> std::time::Duration {
        std::time::Duration::from_secs(INBOX_LEASE_TTL_SECONDS as u64)
    }
}

/// Function-only, cross-tenant inbox backlog source backed by the verified reader role.
pub struct PgInboxBacklogSource {
    pool: PgPool,
}

impl PgInboxBacklogSource {
    pub(crate) fn new(reader: &VerifiedPgReadStore) -> Self {
        Self {
            pool: reader.pool().clone(),
        }
    }
}

#[derive(sqlx::FromRow)]
struct InboxBacklogSampleRow {
    tenant_id: String,
    consumer_group: String,
    depth: i64,
    oldest_age_seconds: i64,
}

impl InboxBacklogSource for PgInboxBacklogSource {
    async fn sample_backlog(
        &self,
        selection: &InboxBacklogSelection,
    ) -> Result<InboxBacklogObservation, EngineError> {
        let groups = selection
            .groups()
            .iter()
            .map(|group| group.as_str().to_owned())
            .collect::<Vec<_>>();
        let rows: Vec<InboxBacklogSampleRow> = sqlx::query_as(
            "SELECT tenant_id::text, consumer_group, depth, oldest_age_seconds \
             FROM public.rss_inbox_sample_backlog($1::text[])",
        )
        .bind(groups)
        .fetch_all(&self.pool)
        .await
        .map_err(|error| {
            tracing::warn!(
                target: "postgres",
                operation = "rss_inbox_sample_backlog",
                error = %secure::redact_error(&error),
                "inbox backlog function failed"
            );
            EngineError::new(EngineErrorKind::Transient)
        })?;

        let samples = rows
            .into_iter()
            .map(|row| {
                let tenant_id = rss_request_context::TenantId::parse(&row.tenant_id)
                    .map_err(|_| EngineError::new(EngineErrorKind::Invariant))?;
                let consumer_group = ConsumerGroup::parse(&row.consumer_group)
                    .map_err(|_| EngineError::new(EngineErrorKind::Invariant))?;
                let depth = u64::try_from(row.depth)
                    .map_err(|_| EngineError::new(EngineErrorKind::Invariant))?;
                let oldest_age_seconds = u64::try_from(row.oldest_age_seconds)
                    .map_err(|_| EngineError::new(EngineErrorKind::Invariant))?;
                Ok(InboxBacklogSample::new(
                    tenant_id,
                    consumer_group,
                    BacklogSample::new(depth, oldest_age_seconds),
                ))
            })
            .collect::<Result<Vec<_>, EngineError>>()?;
        Ok(InboxBacklogObservation::Active(samples))
    }
}

/// postgres `inbox_receipts` 保留期清理 sweeper（**全域**，与 consumer_group 无关，#1210）。
///
/// 去重写路径 [`PgInboxStore`] 按 `consumer_group` 绑定，但保留清理是跨所有组的全表操作——故独立类型
/// 持裸 `pool`（避免「sweep 只影响本组」的语义陷阱）。经 [`PgStore::inbox_sweeper`] 构造。
pub struct PgInboxSweeper {
    pool: PgPool,
    expected_retain_seconds: u64,
}

impl PgStore {
    /// 构造全域 [`PgInboxSweeper`]（pool clone 自 `PgStore`，轻量）。
    ///
    /// `pub(crate)`（PG-BUNDLE-FUNNEL-01）：经组合根 bundle 收口注入保留期 sweeper worker。
    pub(crate) fn inbox_sweeper(&self, policy: EventDeliveryPolicy) -> PgInboxSweeper {
        PgInboxSweeper {
            pool: self.pool.clone(),
            expected_retain_seconds: policy.inbox_receipt_retention_seconds(),
        }
    }
}

impl PgInboxSweeper {
    /// Return the only retention accepted by this policy-bound capability.
    #[must_use]
    pub fn retention_seconds(&self) -> u64 {
        self.expected_retain_seconds
    }
}

impl RetentionSweeper for PgInboxSweeper {
    /// 删除 `status='done'` 且 `committed_at` 早于保留期的去重记录，返回删除条数。
    /// `claimed` 行（活跃 claim / 进行中）不删；保留期内的 `done` 行不删。
    ///
    /// 时间谓词用 PostgreSQL `now()`（DB 事务时间），刻意不注入 `Clock`——多实例并发下需单一无偏移时间源
    /// （同本文件顶注既定理由）。
    async fn sweep(&self, retain_seconds: u64) -> Result<u64, EngineError> {
        if retain_seconds != self.expected_retain_seconds {
            return Err(EngineError::new(EngineErrorKind::Invariant));
        }
        let result = sqlx::query("SELECT rss_sweep_inbox_receipts()::bigint")
        .fetch_one(&self.pool)
        .await
        .map_err(|e| {
            tracing::warn!(target: "postgres", error = %secure::redact_error(&e), "inbox: sweep db error");
            EngineError::new(EngineErrorKind::Transient)
        })?;

        let deleted: i64 = result.get(0);
        u64::try_from(deleted).map_err(|_| EngineError::new(EngineErrorKind::Invariant))
    }
}

#[derive(Clone)]
pub(crate) struct ReceiptFields {
    pub(crate) tenant: rss_request_context::TenantId,
    pub(crate) consumer_group: String,
    pub(crate) domain: String,
    pub(crate) topic: String,
    pub(crate) contract_id: String,
    pub(crate) contract_version: String,
    pub(crate) schema_hash: String,
    pub(crate) trace: Option<String>,
    pub(crate) correlation_id: Option<String>,
}

impl ReceiptFields {
    pub(crate) fn from_context(ctx: &InboxReceiptContext) -> Self {
        let tenant = ctx.tenant_id();
        Self {
            tenant,
            consumer_group: ctx.consumer_group().as_str().to_string(),
            domain: ctx.domain().to_string(),
            topic: ctx.topic().to_string(),
            contract_id: ctx.contract_id().to_string(),
            contract_version: ctx.contract_version().to_string(),
            schema_hash: ctx.schema_hash().to_string(),
            trace: ctx.trace().map(str::to_string),
            correlation_id: ctx.correlation_id().map(str::to_string),
        }
    }
}

fn inbox_db_error(operation: &'static str, error: sqlx::Error) -> EngineError {
    tracing::warn!(
        target: "postgres",
        operation,
        error = %secure::redact_error(&error),
        "inbox: db error"
    );
    EngineError::new(EngineErrorKind::Transient)
}

/// Mark a claimed inbox receipt as done inside an existing tenant-scoped transaction.
///
/// This is the ConsumerTx commit leg: callers must execute business writes and outbox appends on
/// the same [`TenantTx`] before calling this helper, then commit the surrounding transaction.
#[cfg(any(feature = "domain-settings", feature = "domain-audit"))]
pub(crate) async fn commit_in_tx<C: InboxOperationConcern>(
    tx: &mut EventingTx<'_, ServingWriteLane, C>,
    ctx: &InboxReceiptContext,
    key: &IdemKey,
    lease: &LeaseToken,
) -> Result<LeaseOutcome, EngineError> {
    let fields = ReceiptFields::from_context(ctx);
    commit_fields_in_tx(
        tx,
        &fields,
        key.as_str(),
        lease.as_str(),
        "inbox_commit_in_tx",
    )
    .await
}

async fn commit_fields_in_tx(
    tx: &mut EventingTx<'_, ServingWriteLane, impl InboxOperationConcern>,
    fields: &ReceiptFields,
    key: &str,
    lease: &str,
    operation: &'static str,
) -> Result<LeaseOutcome, EngineError> {
    let held = tx
        .inbox_commit_receipt(fields, key, lease)
        .await
        .map_err(|e| inbox_db_error(operation, e))?;

    Ok(if held {
        LeaseOutcome::Held
    } else {
        LeaseOutcome::Lost
    })
}

impl InboxStore for PgInboxStore {
    /// claim-or-reclaim-or-skip：INSERT + CAS TTL 重捞。
    ///
    /// RETURNING 行存在 → `Fresh`（首次插入或 TTL 过期 claimed 行被新 token 接管）；
    /// 无行后读冲突状态：已 done → `Duplicate`；active claimed → `InProgress`（延迟 Requeue）。
    ///
    /// 后端暂不可用 → `EngineErrorKind::Transient`；原始 sqlx 错误不进 Display（PII 边界）。
    async fn try_claim(
        &self,
        ctx: &InboxReceiptContext,
        key: &IdemKey,
        lease: &LeaseToken,
    ) -> Result<SeenState, EngineError> {
        let fields = ReceiptFields::from_context(ctx);
        let key = key.as_str().to_string();
        let lease = lease.as_str().to_string();
        self.write_pool
            .inbox_write(
                infra_tenant_scope(fields.tenant),
                move |mut tx| {
                    let fields = fields.clone();
                    let key = key.clone();
                    let lease = lease.clone();
                    Box::pin(async move {
                        let claimed = tx
                            .inbox_claim_receipt(&fields, &key, &lease, INBOX_LEASE_TTL_SECONDS)
                            .await
                            .map_err(|e| inbox_db_error("inbox_try_claim", e))?;

                        if claimed {
                            return Ok(SeenState::Fresh);
                        }

                        let existing = tx
                            .inbox_load_identity(&fields, &key)
                            .await
                            .map_err(|e| inbox_db_error("inbox_try_claim_conflict_read", e))?;

                        if existing.as_ref().is_some_and(|row| {
                            row.domain != fields.domain
                                || row.topic != fields.topic
                                || row.contract_id != fields.contract_id
                                || row.contract_version != fields.contract_version
                                || row.schema_hash != fields.schema_hash
                        }) {
                            return Err(EngineError::new(EngineErrorKind::Invariant));
                        }

                        match existing.as_ref().map(|row| row.status.as_str()) {
                            Some("done") => Ok(SeenState::Duplicate),
                            Some("claimed") => Ok(SeenState::InProgress),
                            None => Err(EngineError::new(EngineErrorKind::Transient)),
                            Some(_) => Err(EngineError::new(EngineErrorKind::Invariant)),
                        }
                    })
                },
                |e| inbox_db_error("inbox_try_claim_tx", e),
            )
            .await
    }

    /// 续租：刷新 `claimed_at`（CAS：event_id + consumer_group + lease_token + status='claimed'）。
    ///
    /// `rows_affected == 1` → `Held`（token 仍匹配，续租成功）；
    /// `0` → `Lost`（token 不符、已 done 或 absent——hard-fence 信号）。
    ///
    /// 后端暂不可用 → `EngineErrorKind::Transient`；原始 sqlx 错误不进 Display（PII 边界）。
    async fn extend(
        &self,
        ctx: &InboxReceiptContext,
        key: &IdemKey,
        lease: &LeaseToken,
    ) -> Result<LeaseOutcome, EngineError> {
        let fields = ReceiptFields::from_context(ctx);
        let key = key.as_str().to_string();
        let lease = lease.as_str().to_string();
        self.write_pool
            .inbox_write(
                infra_tenant_scope(fields.tenant),
                move |mut tx| {
                    let fields = fields.clone();
                    let key = key.clone();
                    let lease = lease.clone();
                    Box::pin(async move {
                        let held = tx
                            .inbox_extend_receipt(&fields, &key, &lease)
                            .await
                            .map_err(|e| inbox_db_error("inbox_extend", e))?;

                        Ok(if held {
                            LeaseOutcome::Held
                        } else {
                            LeaseOutcome::Lost
                        })
                    })
                },
                |e| inbox_db_error("inbox_extend_tx", e),
            )
            .await
    }

    /// claimed→done（CAS）：仅当 `lease` 仍匹配时标记保留窗口内去重。
    ///
    /// `rows_affected == 1` → `Held`（提交成功）；
    /// `0` → `Lost`（token 不符——hard-fence：消费方不得 Ack）。
    ///
    /// 后端暂不可用 → `EngineErrorKind::Transient`；原始 sqlx 错误不进 Display（PII 边界）。
    async fn commit(
        &self,
        ctx: &InboxReceiptContext,
        key: &IdemKey,
        lease: &LeaseToken,
    ) -> Result<LeaseOutcome, EngineError> {
        let fields = ReceiptFields::from_context(ctx);
        let key = key.as_str().to_string();
        let lease = lease.as_str().to_string();
        self.write_pool
            .inbox_write(
                infra_tenant_scope(fields.tenant),
                move |mut tx| {
                    let fields = fields.clone();
                    let key = key.clone();
                    let lease = lease.clone();
                    Box::pin(async move {
                        commit_fields_in_tx(&mut tx, &fields, &key, &lease, "inbox_commit").await
                    })
                },
                |e| inbox_db_error("inbox_commit_tx", e),
            )
            .await
    }

    /// claimed→absent（DELETE CAS）：仅当 `lease` 仍匹配时释放 claim。
    ///
    /// token 不符（已被 TTL 重捞、他人接管）为幂等 no-op（`Ok(())`，不误删他人 claim）；
    /// absent key 同样 no-op。
    ///
    /// 后端暂不可用 → `EngineErrorKind::Transient`；原始 sqlx 错误不进 Display（PII 边界）。
    async fn release(
        &self,
        ctx: &InboxReceiptContext,
        key: &IdemKey,
        lease: &LeaseToken,
    ) -> Result<(), EngineError> {
        let fields = ReceiptFields::from_context(ctx);
        let key = key.as_str().to_string();
        let lease = lease.as_str().to_string();
        self.write_pool
            .inbox_write(
                infra_tenant_scope(fields.tenant),
                move |mut tx| {
                    let fields = fields.clone();
                    let key = key.clone();
                    let lease = lease.clone();
                    Box::pin(async move {
                        tx.inbox_release_receipt(&fields, &key, &lease)
                            .await
                            .map_err(|e| inbox_db_error("inbox_release", e))
                    })
                },
                |e| inbox_db_error("inbox_release_tx", e),
            )
            .await
    }
}

#[cfg(test)]
mod sweep_smoke {
    //! `PgInboxSweeper: RetentionSweeper` 编译期冻结 + sweep 入口 fail-closed 守卫单测（免 PG，#327 review F1/F4）。
    //! INVARIANT: ADAPTER-PORT-FREEZE-08 { level = "Hard", exec = "native-compile", source = "code", native = "type or rustdoc boundary" }—— RetentionSweeper on PgInboxSweeper；去掉 impl 即编译失败（anti-vacuity）。
    use core::marker::PhantomData;

    use consistency::{EngineErrorKind, RetentionSweeper};
    use sqlx::postgres::{PgConnectOptions, PgPoolOptions};

    use super::PgInboxSweeper;
    use crate::PgStore;
    use crate::delivery_policy::EventDeliveryPolicy;

    fn assert_retention_sweeper<T: RetentionSweeper>(_: PhantomData<T>) {}

    #[test]
    fn pg_inbox_sweeper_impl_frozen() {
        assert_retention_sweeper(PhantomData::<PgInboxSweeper>);
    }

    /// lazy pool（`connect_lazy_with`，不发真实连接）——两条 fail-closed 守卫均在**触 pool 前**返回，故免 DB。
    fn lazy_sweeper() -> PgInboxSweeper {
        let opts = PgConnectOptions::new()
            .host("127.0.0.1")
            .port(5999)
            .database("rss_test")
            .username("u")
            .password("p");
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect_lazy_with(opts);
        PgStore { pool }.inbox_sweeper(EventDeliveryPolicy::release())
    }

    // Every policy mismatch, including conversion edges, is rejected before pool access.
    #[tokio::test]
    async fn sweep_rejects_every_non_policy_retention_before_pool_access() {
        let sweeper = lazy_sweeper();
        let expected = sweeper.retention_seconds();
        for retain_seconds in [0, expected - 1, expected + 1, u64::MAX] {
            let result = sweeper.sweep(retain_seconds).await;
            assert!(
                matches!(result, Err(e) if e.kind() == EngineErrorKind::Invariant),
                "non-policy retention {retain_seconds} must fail closed before pool access"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    //! postgres inbox_receipts 集成测试（租约 CAS + TTL 重捞，#1213）。
    //!
    //! integration 测试需要活 PG 实例，由 `integration` feature 门控。

    #[cfg(feature = "integration")]
    mod integration {
        use std::sync::Arc;

        use consistency::{
            EngineErrorKind, IdemKey, InboxReceiptContext, InboxStore, LeaseOutcome, LeaseToken,
            SeenState,
        };
        use sqlx::Row;
        use tokio::sync::Barrier;

        type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

        #[derive(Debug, PartialEq, Eq)]
        struct ReceiptSnapshot {
            tenant_id: String,
            event_id: String,
            consumer_group: String,
            domain: String,
            topic: String,
            contract_id: String,
            contract_version: String,
            schema_hash: String,
            trace: Option<String>,
            correlation_id: Option<String>,
            status: String,
            lease_token: String,
            receive_count: i32,
            claimed_at: String,
            committed_at: Option<String>,
            updated_at: String,
        }

        #[allow(clippy::unwrap_used)]
        // reason: 测试 setup — 已知非空 raw，item-level carve-out（error-handling.md §Carve-out）。
        fn k(raw: &str) -> IdemKey {
            IdemKey::parse(raw).unwrap()
        }

        /// 铸出唯一租约 token（uuid v4）。
        fn lease() -> LeaseToken {
            LeaseToken::mint()
        }

        #[allow(clippy::unwrap_used)]
        // reason: 测试 fixture 使用固定合法 receipt metadata，构造失败即测试配置错误。
        fn ctx(group: &str) -> InboxReceiptContext {
            InboxReceiptContext::new(
                rss_request_context::TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479")
                    .unwrap(),
                consistency::ConsumerGroup::parse(group).unwrap(),
                "identity",
                "identity.session-created",
                "identity.session-created",
                "v1",
                "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                None,
                None,
            )
            .unwrap()
        }

        #[allow(clippy::unwrap_used)]
        // reason: 测试 fixture 使用固定合法 receipt metadata，构造失败即测试配置错误。
        fn ctx_with_schema(group: &str, schema_hash: &str) -> InboxReceiptContext {
            InboxReceiptContext::new(
                rss_request_context::TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479")
                    .unwrap(),
                consistency::ConsumerGroup::parse(group).unwrap(),
                "identity",
                "identity.session-created",
                "identity.session-created",
                "v1",
                schema_hash,
                None,
                None,
            )
            .unwrap()
        }

        /// 铸出 per-run 唯一 inbox key（`{prefix}-{uuid v4}`）——集成测试可复用长存外部 PG，固定
        /// event_id 在 receipt 保留窗口内被 `commit` 标成 `done`，同 key claim 会退化成 `Duplicate`；
        /// 经此 funnel 让每次运行用全新 key，杜绝跨运行持久状态污染（亦消除散落的 `format!(uuid)` 重复）。
        fn uk(prefix: &str) -> IdemKey {
            k(&format!("{prefix}-{}", uuid::Uuid::new_v4()))
        }

        async fn receipt_snapshot(
            store: &crate::PgStore,
            ctx: &InboxReceiptContext,
            key: &IdemKey,
        ) -> Result<ReceiptSnapshot, sqlx::Error> {
            let row = sqlx::query(
                "SELECT tenant_id::text AS tenant_id, event_id, consumer_group, \
                        domain, topic, contract_id, contract_version, schema_hash, \
                        trace, correlation_id, status, lease_token::text AS lease_token, \
                        receive_count, claimed_at::text AS claimed_at, \
                        committed_at::text AS committed_at, updated_at::text AS updated_at \
                 FROM inbox_receipts \
                 WHERE tenant_id = $1::uuid AND event_id = $2 AND consumer_group = $3",
            )
            .bind(ctx.tenant_id().to_string())
            .bind(key.as_str())
            .bind(ctx.consumer_group().as_str())
            .fetch_one(&store.pool)
            .await?;

            Ok(ReceiptSnapshot {
                tenant_id: row.try_get("tenant_id")?,
                event_id: row.try_get("event_id")?,
                consumer_group: row.try_get("consumer_group")?,
                domain: row.try_get("domain")?,
                topic: row.try_get("topic")?,
                contract_id: row.try_get("contract_id")?,
                contract_version: row.try_get("contract_version")?,
                schema_hash: row.try_get("schema_hash")?,
                trace: row.try_get("trace")?,
                correlation_id: row.try_get("correlation_id")?,
                status: row.try_get("status")?,
                lease_token: row.try_get("lease_token")?,
                receive_count: row.try_get("receive_count")?,
                claimed_at: row.try_get("claimed_at")?,
                committed_at: row.try_get("committed_at")?,
                updated_at: row.try_get("updated_at")?,
            })
        }

        async fn receipt_count(
            store: &crate::PgStore,
            ctx: &InboxReceiptContext,
            key: &IdemKey,
        ) -> Result<i64, sqlx::Error> {
            sqlx::query_as::<_, (i64,)>(
                "SELECT count(*)::bigint FROM inbox_receipts \
                 WHERE tenant_id = $1::uuid AND event_id = $2 AND consumer_group = $3",
            )
            .bind(ctx.tenant_id().to_string())
            .bind(key.as_str())
            .bind(ctx.consumer_group().as_str())
            .fetch_one(&store.pool)
            .await
            .map(|(count,)| count)
        }

        /// claim → commit → try_claim = Duplicate（done 在 receipt 保留窗口内去重，PG 往返）。
        #[tokio::test(flavor = "multi_thread")]
        #[allow(clippy::unwrap_used)]
        // reason: 集成测试断言 fail-loud（往返结果必 Ok）；item-level carve-out（error-handling.md §Carve-out）。
        async fn commit_makes_key_duplicate_while_receipt_is_retained() -> TestResult {
            let (_pg, store) = crate::test_pg::connect_pg().await?;
            store.run_migrations().await?;
            let inbox = store.inbox();
            let ctx = ctx("test-group");
            let key = uk("pg-commit-evt");
            let lease_a = lease();
            assert_eq!(
                inbox.try_claim(&ctx, &key, &lease_a).await.unwrap(),
                SeenState::Fresh
            );
            assert_eq!(
                inbox.commit(&ctx, &key, &lease_a).await.unwrap(),
                LeaseOutcome::Held
            );
            // done 行：任意新 token try_claim → Duplicate（DO UPDATE WHERE status='claimed' 为 false）。
            assert_eq!(
                inbox.try_claim(&ctx, &key, &lease()).await.unwrap(),
                SeenState::Duplicate
            );
            Ok(())
        }

        /// active claim 返回 InProgress、done 返回 Duplicate，且两条冲突路径均不得改写 receipt。
        #[tokio::test(flavor = "multi_thread")]
        #[allow(clippy::unwrap_used)]
        // reason: 集成测试断言 fail-loud；item-level carve-out（error-handling.md §Carve-out）。
        async fn duplicate_paths_preserve_receipt_row() -> TestResult {
            let (_pg, store) = crate::test_pg::connect_pg().await?;
            store.run_migrations().await?;
            let inbox = store.inbox();
            let ctx = ctx("duplicate-preserve-grp");

            let active_key = uk("pg-active-duplicate-preserve");
            let active_lease = lease();
            assert_eq!(
                inbox
                    .try_claim(&ctx, &active_key, &active_lease)
                    .await
                    .unwrap(),
                SeenState::Fresh
            );
            let active_before = receipt_snapshot(&store, &ctx, &active_key).await?;
            assert_eq!(
                inbox.try_claim(&ctx, &active_key, &lease()).await.unwrap(),
                SeenState::InProgress
            );
            let active_after = receipt_snapshot(&store, &ctx, &active_key).await?;
            assert_eq!(
                active_after, active_before,
                "active conflict must not rewrite the existing receipt row"
            );

            let done_key = uk("pg-done-duplicate-preserve");
            let done_lease = lease();
            assert_eq!(
                inbox.try_claim(&ctx, &done_key, &done_lease).await.unwrap(),
                SeenState::Fresh
            );
            assert_eq!(
                inbox.commit(&ctx, &done_key, &done_lease).await.unwrap(),
                LeaseOutcome::Held
            );
            let done_before = receipt_snapshot(&store, &ctx, &done_key).await?;
            assert_eq!(
                inbox.try_claim(&ctx, &done_key, &lease()).await.unwrap(),
                SeenState::Duplicate
            );
            let done_after = receipt_snapshot(&store, &ctx, &done_key).await?;
            assert_eq!(
                done_after, done_before,
                "done Duplicate must not rewrite terminal receipt row"
            );
            Ok(())
        }

        /// anti-vacuity: receipt 快照必须看见 identity 与租约时间锚变化，否则“不改写”断言会真空通过。
        #[tokio::test(flavor = "multi_thread")]
        #[allow(clippy::unwrap_used)]
        // reason: 集成测试断言 fail-loud；item-level carve-out（error-handling.md §Carve-out）。
        async fn receipt_snapshot_detects_receipt_semantic_columns() -> TestResult {
            let (_pg, store) = crate::test_pg::connect_pg().await?;
            store.run_migrations().await?;
            let inbox = store.inbox();
            let ctx = ctx("snapshot-anti-vacuity-grp");
            let key = uk("pg-snapshot-anti-vacuity");
            let lease = lease();

            assert_eq!(
                inbox.try_claim(&ctx, &key, &lease).await.unwrap(),
                SeenState::Fresh
            );
            let before = receipt_snapshot(&store, &ctx, &key).await?;
            sqlx::query(
                "UPDATE inbox_receipts \
                 SET domain = 'identity-renamed', \
                     topic = 'identity.session-renamed', \
                     contract_id = 'identity.session-renamed', \
                     contract_version = 'v2', \
                     schema_hash = 'sha256:1111111111111111111111111111111111111111111111111111111111111111', \
                     trace = 'trace-anti-vacuity', \
                     correlation_id = 'corr-anti-vacuity', \
                     claimed_at = claimed_at - interval '1 second', \
                     updated_at = updated_at + interval '1 second' \
                 WHERE tenant_id = $1::uuid AND event_id = $2 AND consumer_group = $3",
            )
            .bind(ctx.tenant_id().to_string())
            .bind(key.as_str())
            .bind(ctx.consumer_group().as_str())
            .execute(&store.pool)
            .await?;
            let after = receipt_snapshot(&store, &ctx, &key).await?;

            assert_ne!(
                after, before,
                "receipt snapshot must include identity columns and lease timestamp anchors"
            );
            Ok(())
        }

        /// 同一 receipt key 首次并发 claim：Postgres PK + ON CONFLICT 必须只产生一个 Fresh。
        #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
        async fn concurrent_try_claim_same_receipt_single_fresh_winner() -> TestResult {
            const CLAIMERS: usize = 8;

            let (_pg, store) = crate::test_pg::connect_pg().await?;
            store.run_migrations().await?;
            let store = Arc::new(store);
            let ctx = Arc::new(ctx("concurrent-claim-grp"));
            let key = Arc::new(uk("pg-concurrent-claim"));
            let barrier = Arc::new(Barrier::new(CLAIMERS));
            let mut tasks = Vec::with_capacity(CLAIMERS);

            for _ in 0..CLAIMERS {
                let store = Arc::clone(&store);
                let ctx = Arc::clone(&ctx);
                let key = Arc::clone(&key);
                let barrier = Arc::clone(&barrier);
                tasks.push(tokio::spawn(async move {
                    let lease = lease();
                    barrier.wait().await;
                    let seen = store.inbox().try_claim(&ctx, &key, &lease).await;
                    (seen, lease)
                }));
            }

            let mut fresh = Vec::new();
            let mut active_conflicts = 0usize;
            for task in tasks {
                let (seen, lease) = task.await?;
                match seen {
                    Ok(SeenState::Fresh) => fresh.push(lease),
                    Ok(SeenState::InProgress) => active_conflicts += 1,
                    Ok(SeenState::Duplicate) => {
                        return Err("active conflict must not report durable Duplicate".into());
                    }
                    Err(error) => return Err(error.into()),
                }
            }

            assert_eq!(fresh.len(), 1, "only one concurrent claimer may win Fresh");
            assert_eq!(
                active_conflicts,
                CLAIMERS - 1,
                "all losing concurrent claimers must observe InProgress"
            );
            assert_eq!(receipt_count(&store, &ctx, &key).await?, 1);
            let row = receipt_snapshot(&store, &ctx, &key).await?;
            assert_eq!(row.status, "claimed");
            assert_eq!(row.lease_token, fresh[0].as_str());
            assert_eq!(row.receive_count, 1);
            assert!(row.committed_at.is_none());
            Ok(())
        }

        /// 同一 stale receipt 并发重捞：只能一个新 lease 接管，旧 lease commit 必须 Lost。
        #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
        #[allow(clippy::unwrap_used)]
        // reason: 集成测试断言 fail-loud；item-level carve-out（error-handling.md §Carve-out）。
        async fn concurrent_stale_reclaim_single_fresh_winner() -> TestResult {
            const CLAIMERS: usize = 8;

            let (_pg, store) = crate::test_pg::connect_pg().await?;
            store.run_migrations().await?;
            let store = Arc::new(store);
            let ctx = Arc::new(ctx("concurrent-stale-reclaim-grp"));
            let key = Arc::new(uk("pg-concurrent-stale-reclaim"));
            let stale_lease = lease();
            assert_eq!(
                store
                    .inbox()
                    .try_claim(&ctx, &key, &stale_lease)
                    .await
                    .unwrap(),
                SeenState::Fresh
            );

            sqlx::query(
                "UPDATE inbox_receipts \
                 SET claimed_at = now() - make_interval(secs => $1), updated_at = now() - make_interval(secs => $1) \
                 WHERE tenant_id = $2::uuid AND event_id = $3 AND consumer_group = $4",
            )
            .bind(super::super::INBOX_LEASE_TTL_SECONDS + 1)
            .bind(ctx.tenant_id().to_string())
            .bind(key.as_str())
            .bind(ctx.consumer_group().as_str())
            .execute(&store.pool)
            .await?;

            let barrier = Arc::new(Barrier::new(CLAIMERS));
            let mut tasks = Vec::with_capacity(CLAIMERS);
            for _ in 0..CLAIMERS {
                let store = Arc::clone(&store);
                let ctx = Arc::clone(&ctx);
                let key = Arc::clone(&key);
                let barrier = Arc::clone(&barrier);
                tasks.push(tokio::spawn(async move {
                    let lease = lease();
                    barrier.wait().await;
                    let seen = store.inbox().try_claim(&ctx, &key, &lease).await;
                    (seen, lease)
                }));
            }

            let mut fresh = Vec::new();
            let mut active_conflicts = 0usize;
            for task in tasks {
                let (seen, lease) = task.await?;
                match seen {
                    Ok(SeenState::Fresh) => fresh.push(lease),
                    Ok(SeenState::InProgress) => active_conflicts += 1,
                    Ok(SeenState::Duplicate) => {
                        return Err("active conflict must not report durable Duplicate".into());
                    }
                    Err(error) => return Err(error.into()),
                }
            }

            assert_eq!(fresh.len(), 1, "only one stale reclaim may win Fresh");
            assert_eq!(
                active_conflicts,
                CLAIMERS - 1,
                "all losing stale reclaimers must observe InProgress"
            );
            let winner = &fresh[0];
            let row = receipt_snapshot(&store, &ctx, &key).await?;
            assert_eq!(row.status, "claimed");
            assert_eq!(row.lease_token, winner.as_str());
            assert_eq!(row.receive_count, 2);
            assert!(row.committed_at.is_none());
            assert_eq!(
                store
                    .inbox()
                    .commit(&ctx, &key, &stale_lease)
                    .await
                    .unwrap(),
                LeaseOutcome::Lost
            );
            assert_eq!(
                store.inbox().commit(&ctx, &key, winner).await.unwrap(),
                LeaseOutcome::Held
            );
            Ok(())
        }

        /// 同 PK 但 receipt identity 不一致时，不能静默 Duplicate；必须暴露 Invariant。
        #[tokio::test(flavor = "multi_thread")]
        #[allow(clippy::unwrap_used)]
        // reason: 集成测试断言 fail-loud；item-level carve-out（error-handling.md §Carve-out）。
        async fn try_claim_identity_mismatch_returns_invariant() -> TestResult {
            let (_pg, store) = crate::test_pg::connect_pg().await?;
            store.run_migrations().await?;
            let inbox = store.inbox();
            let key = uk("pg-identity-mismatch");
            let group = "identity-mismatch-grp";
            let original = ctx(group);
            let mismatched = ctx_with_schema(
                group,
                "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            );
            let original_lease = lease();

            assert_eq!(
                inbox
                    .try_claim(&original, &key, &original_lease)
                    .await
                    .unwrap(),
                SeenState::Fresh
            );
            let before = receipt_snapshot(&store, &original, &key).await?;
            let err = match inbox.try_claim(&mismatched, &key, &lease()).await {
                Err(err) => err,
                Ok(_) => {
                    return Err(
                        std::io::Error::other("schema identity mismatch must fail closed").into(),
                    );
                }
            };
            assert_eq!(err.kind(), EngineErrorKind::Invariant);
            let after = receipt_snapshot(&store, &original, &key).await?;
            assert_eq!(
                after, before,
                "identity mismatch must not rewrite the existing receipt"
            );
            Ok(())
        }

        /// claim → release(CAS) → 再 try_claim = Fresh（释放后可重领，PG 往返）。
        #[tokio::test(flavor = "multi_thread")]
        #[allow(clippy::unwrap_used)]
        // reason: 集成测试断言 fail-loud（往返结果必 Ok）；item-level carve-out（error-handling.md §Carve-out）。
        async fn release_allows_reclaim() -> TestResult {
            let (_pg, store) = crate::test_pg::connect_pg().await?;
            store.run_migrations().await?;
            let inbox = store.inbox();
            let ctx = ctx("test-group");
            let key = uk("pg-release-evt");
            let lease_a = lease();
            assert_eq!(
                inbox.try_claim(&ctx, &key, &lease_a).await.unwrap(),
                SeenState::Fresh
            );
            inbox.release(&ctx, &key, &lease_a).await.unwrap();
            // absent 行：新 token try_claim → Fresh。
            assert_eq!(
                inbox.try_claim(&ctx, &key, &lease()).await.unwrap(),
                SeenState::Fresh
            );
            Ok(())
        }

        /// commit 对 absent key 返 Lost（hard-fence；无行匹配 CAS）。
        #[tokio::test(flavor = "multi_thread")]
        async fn commit_on_absent_returns_lost() -> TestResult {
            let (_pg, store) = crate::test_pg::connect_pg().await?;
            store.run_migrations().await?;
            let inbox = store.inbox();
            let ctx = ctx("test-group");
            let key = uk("pg-absent-commit");
            assert_eq!(
                inbox.commit(&ctx, &key, &lease()).await?,
                LeaseOutcome::Lost
            );
            Ok(())
        }

        /// release 对 absent key 幂等 no-op（不报错）。
        #[tokio::test(flavor = "multi_thread")]
        async fn release_on_absent_is_ok() -> TestResult {
            let (_pg, store) = crate::test_pg::connect_pg().await?;
            store.run_migrations().await?;
            let inbox = store.inbox();
            let ctx = ctx("test-group");
            let key = uk("pg-absent-release");
            assert!(inbox.release(&ctx, &key, &lease()).await.is_ok());
            Ok(())
        }

        /// extend Held/Lost（#1213 租约续租 CAS）：
        /// claim → extend Held；模拟他人接管（覆盖 lease_token）→ extend Lost。
        #[tokio::test(flavor = "multi_thread")]
        #[allow(clippy::unwrap_used)]
        // reason: 集成测试断言 fail-loud；item-level carve-out（error-handling.md §Carve-out）。
        async fn extend_held_then_lost_on_takeover() -> TestResult {
            let (_pg, store) = crate::test_pg::connect_pg().await?;
            store.run_migrations().await?;
            let grp = "extend-takeover-grp";
            let inbox = store.inbox();
            let ctx = ctx(grp);
            let key = uk("pg-extend-takeover");
            let lease_a = lease();

            // claim。
            assert_eq!(
                inbox.try_claim(&ctx, &key, &lease_a).await.unwrap(),
                SeenState::Fresh
            );

            // 持有期间续租 → Held。
            assert_eq!(
                inbox.extend(&ctx, &key, &lease_a).await.unwrap(),
                LeaseOutcome::Held
            );

            // 模拟他人接管：覆盖 DB 中 lease_token。
            sqlx::query(
                "UPDATE inbox_receipts SET lease_token = gen_random_uuid() \
                 WHERE tenant_id = $1::uuid AND event_id = $2 AND consumer_group = $3",
            )
            .bind(ctx.tenant_id().to_string())
            .bind(key.as_str())
            .bind(grp)
            .execute(&store.pool)
            .await?;

            // 旧 token 续租 → Lost（已被他人接管，CAS 不命中）。
            assert_eq!(
                inbox.extend(&ctx, &key, &lease_a).await.unwrap(),
                LeaseOutcome::Lost
            );
            Ok(())
        }

        /// TTL 重捞 + commit CAS hard-fence（#1213 核心场景）：
        /// token A claim → backdate claimed_at 过期 → token B reclaim（Fresh）→
        /// token A commit = Lost（hard-fence）→ token B commit = Held。
        #[tokio::test(flavor = "multi_thread")]
        #[allow(clippy::unwrap_used)]
        // reason: 集成测试断言 fail-loud；item-level carve-out（error-handling.md §Carve-out）。
        async fn ttl_reclaim_and_commit_hard_fence() -> TestResult {
            let (_pg, store) = crate::test_pg::connect_pg().await?;
            store.run_migrations().await?;
            let grp = "ttl-reclaim-grp";
            let inbox = store.inbox();
            let ctx = ctx(grp);
            let key = uk("pg-ttl-reclaim");
            let lease_a = lease();
            let ttl = super::super::INBOX_LEASE_TTL_SECONDS;

            // token A claim。
            assert_eq!(
                inbox.try_claim(&ctx, &key, &lease_a).await.unwrap(),
                SeenState::Fresh
            );

            // 回拨 claimed_at 超过 TTL（模拟 crash-after-claim，lease 过期）。
            sqlx::query(
                "UPDATE inbox_receipts \
                 SET claimed_at = now() - make_interval(secs => $1) \
                 WHERE tenant_id = $2::uuid AND event_id = $3 AND consumer_group = $4",
            )
            .bind(ttl + 1)
            .bind(ctx.tenant_id().to_string())
            .bind(key.as_str())
            .bind(grp)
            .execute(&store.pool)
            .await?;

            // token B try_claim → Fresh（TTL 重捞，stale claimed 行被新 token 接管）。
            let lease_b = lease();
            assert_eq!(
                inbox.try_claim(&ctx, &key, &lease_b).await.unwrap(),
                SeenState::Fresh
            );

            // token A commit → Lost（已被 B 接管，CAS 不命中；hard-fence）。
            assert_eq!(
                inbox.commit(&ctx, &key, &lease_a).await.unwrap(),
                LeaseOutcome::Lost
            );

            // token B commit → Held（B 是当前持有者，CAS 命中，done 在 retention window 内去重）。
            assert_eq!(
                inbox.commit(&ctx, &key, &lease_b).await.unwrap(),
                LeaseOutcome::Held
            );
            Ok(())
        }

        /// commit/release token-CAS 围栏（#1213 hard-fence）：
        /// 错误 token commit → Lost；错误 token release → no-op（行不被误删，仍 Duplicate）。
        #[tokio::test(flavor = "multi_thread")]
        #[allow(clippy::unwrap_used)]
        // reason: 集成测试断言 fail-loud；item-level carve-out（error-handling.md §Carve-out）。
        async fn commit_and_release_wrong_token_cas_fence() -> TestResult {
            let (_pg, store) = crate::test_pg::connect_pg().await?;
            store.run_migrations().await?;
            let grp = "cas-fence-grp";
            let inbox = store.inbox();
            let ctx = ctx(grp);

            // ── commit wrong token ──────────────────────────────────────────────
            let key_c = uk("pg-commit-fence");
            let lease_mine = lease();
            let lease_wrong = lease();

            assert_eq!(
                inbox.try_claim(&ctx, &key_c, &lease_mine).await.unwrap(),
                SeenState::Fresh
            );

            // 错误 token commit → Lost（CAS 不命中，行仍 claimed）。
            assert_eq!(
                inbox.commit(&ctx, &key_c, &lease_wrong).await.unwrap(),
                LeaseOutcome::Lost
            );
            // 正确 token commit → Held（行正确结算 done）。
            assert_eq!(
                inbox.commit(&ctx, &key_c, &lease_mine).await.unwrap(),
                LeaseOutcome::Held
            );

            // ── release wrong token ─────────────────────────────────────────────
            let key_r = uk("pg-release-fence");
            let lease_mine2 = lease();
            let lease_wrong2 = lease();

            assert_eq!(
                inbox.try_claim(&ctx, &key_r, &lease_mine2).await.unwrap(),
                SeenState::Fresh
            );

            // 错误 token release → no-op（不误删他人 claim）。
            inbox.release(&ctx, &key_r, &lease_wrong2).await.unwrap();

            // 行仍被 mine2 持有 → InProgress（DO UPDATE WHERE claimed_at 仍在 TTL 内）。
            assert_eq!(
                inbox.try_claim(&ctx, &key_r, &lease()).await.unwrap(),
                SeenState::InProgress
            );
            Ok(())
        }
    }
}
