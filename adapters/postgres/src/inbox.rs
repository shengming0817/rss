//! postgres inbox_dedup adapter（消费幂等去重 + 租约 CAS，L2 一致性锚点，#1118 / #1213）。
//!
//! `PgInboxStore` 实现 [`consistency::IdempotencyStore`] 引擎策略 trait（native AFIT，泛型静态分发消费，
//! 零 box，**非** diport DI port）。
//!
//! # 状态机：absent → claimed(lease_token) → done
//!
//! - **`try_claim`（claim-or-reclaim-or-skip）**：
//!   `INSERT ... ON CONFLICT DO UPDATE ... WHERE status='claimed' AND claimed_at <= now()-TTL`
//!   \+ `RETURNING`：
//!   - RETURNING 行存在（`Some`）→ [`SeenState::Fresh`]：首次插入，或 TTL 过期的 claimed 行被新 token 接管
//!     （stale reclaim，修复 crash-after-claim 时 key 永久 Duplicate 的丢消息风险，#1213）。
//!   - RETURNING 无行（`None`）→ [`SeenState::Duplicate`]：他人持有有效 claim（lease 仍在 TTL 内）或已 done
//!     （DO UPDATE WHERE false，不修改行，幂等短路）。
//! - **`extend`（续租）**：刷新 `claimed_at`（CAS：lease_token + status='claimed'）；
//!   `rows_affected == 1` → [`LeaseOutcome::Held`]，否则 `Lost`（token 不符或已 done/absent）。
//! - **`commit`（claimed→done）**：CAS；`rows_affected == 1` → `Held`（永久去重），`0` → `Lost`（hard-fence）。
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
    EngineError, EngineErrorKind, IdemKey, IdempotencyStore, LeaseOutcome, LeaseToken, SeenState,
};
use sqlx::PgPool;

use crate::PgStore;

/// inbox 租约过期阈值（秒）；claimed 行超此阈值未续租即可被 TTL 重捞（镜 outbox `LEASE_TTL_SECONDS`，#1213）。
///
/// `pub` 暴露供组合根读取——不应被业务代码直接使用；通过 [`PgInboxStore::lease_ttl`] 取类型化值。
pub const INBOX_LEASE_TTL_SECONDS: i64 = 60;

/// postgres inbox_dedup 幂等去重 store（claim-or-reclaim-or-skip + 租约 CAS + TTL 重捞，#1213）。
///
/// 私有字段 `pool` / `group`；经 [`PgStore::inbox`] 构造。
pub struct PgInboxStore {
    pool: PgPool,
    group: consistency::ConsumerGroup,
}

impl PgStore {
    /// 构造绑定指定消费者组的 [`PgInboxStore`]。
    ///
    /// `group` 是幂等 claim 的第二 PK 维度（`consumer_group` 列）——同一 `event_id` 在不同组各自首见。
    pub fn inbox(&self, group: consistency::ConsumerGroup) -> PgInboxStore {
        PgInboxStore {
            pool: self.pool.clone(),
            group,
        }
    }
}

impl PgInboxStore {
    /// 供组合根派生 `eventexec::LeaseConfig::from_ttl(store.lease_ttl())`，使续租间隔与后端 claim TTL
    /// 同源（杜绝 mismatch footgun，#1213 review #3）。
    pub fn lease_ttl(&self) -> std::time::Duration {
        std::time::Duration::from_secs(INBOX_LEASE_TTL_SECONDS as u64)
    }
}

impl IdempotencyStore for PgInboxStore {
    /// claim-or-reclaim-or-skip：INSERT + CAS TTL 重捞。
    ///
    /// RETURNING 行存在 → `Fresh`（首次插入或 TTL 过期 claimed 行被新 token 接管）；
    /// 无行 → `Duplicate`（他人持有有效 claim 或已 done，幂等短路）。
    ///
    /// 后端暂不可用 → `EngineErrorKind::Transient`；原始 sqlx 错误不进 Display（PII 边界）。
    async fn try_claim(&self, key: &IdemKey, lease: &LeaseToken) -> Result<SeenState, EngineError> {
        let row: Option<(String,)> = sqlx::query_as(
            r#"
            INSERT INTO inbox_dedup (event_id, consumer_group, lease_token)
            VALUES ($1, $2, $3::uuid)
            ON CONFLICT (event_id, consumer_group) DO UPDATE
              SET lease_token = $3::uuid, claimed_at = now()
              WHERE inbox_dedup.status = 'claimed'
                AND inbox_dedup.claimed_at <= now() - make_interval(secs => $4)
            RETURNING lease_token::text
            "#,
        )
        .bind(key.as_str())
        .bind(self.group.as_str())
        .bind(lease.as_str())
        .bind(INBOX_LEASE_TTL_SECONDS)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| {
            tracing::warn!(target: "postgres", operation = "inbox_try_claim", error = %secure::redact_error(&e), "inbox: try_claim db error");
            EngineError::new(EngineErrorKind::Transient)
        })?;

        Ok(if row.is_some() {
            SeenState::Fresh
        } else {
            SeenState::Duplicate
        })
    }

    /// 续租：刷新 `claimed_at`（CAS：event_id + consumer_group + lease_token + status='claimed'）。
    ///
    /// `rows_affected == 1` → `Held`（token 仍匹配，续租成功）；
    /// `0` → `Lost`（token 不符、已 done 或 absent——hard-fence 信号）。
    ///
    /// 后端暂不可用 → `EngineErrorKind::Transient`；原始 sqlx 错误不进 Display（PII 边界）。
    async fn extend(&self, key: &IdemKey, lease: &LeaseToken) -> Result<LeaseOutcome, EngineError> {
        let result = sqlx::query(
            r#"
            UPDATE inbox_dedup SET claimed_at = now()
            WHERE event_id = $1 AND consumer_group = $2
              AND lease_token = $3::uuid AND status = 'claimed'
            "#,
        )
        .bind(key.as_str())
        .bind(self.group.as_str())
        .bind(lease.as_str())
        .execute(&self.pool)
        .await
        .map_err(|e| {
            tracing::warn!(target: "postgres", operation = "inbox_extend", error = %secure::redact_error(&e), "inbox: extend db error");
            EngineError::new(EngineErrorKind::Transient)
        })?;

        Ok(if result.rows_affected() == 1 {
            LeaseOutcome::Held
        } else {
            LeaseOutcome::Lost
        })
    }

    /// claimed→done（CAS）：仅当 `lease` 仍匹配时标记永久去重。
    ///
    /// `rows_affected == 1` → `Held`（提交成功）；
    /// `0` → `Lost`（token 不符——hard-fence：消费方不得 Ack）。
    ///
    /// 后端暂不可用 → `EngineErrorKind::Transient`；原始 sqlx 错误不进 Display（PII 边界）。
    async fn commit(&self, key: &IdemKey, lease: &LeaseToken) -> Result<LeaseOutcome, EngineError> {
        let result = sqlx::query(
            r#"
            UPDATE inbox_dedup SET status = 'done'
            WHERE event_id = $1 AND consumer_group = $2
              AND lease_token = $3::uuid AND status = 'claimed'
            "#,
        )
        .bind(key.as_str())
        .bind(self.group.as_str())
        .bind(lease.as_str())
        .execute(&self.pool)
        .await
        .map_err(|e| {
            tracing::warn!(target: "postgres", operation = "inbox_commit", error = %secure::redact_error(&e), "inbox: commit db error");
            EngineError::new(EngineErrorKind::Transient)
        })?;

        Ok(if result.rows_affected() == 1 {
            LeaseOutcome::Held
        } else {
            LeaseOutcome::Lost
        })
    }

    /// claimed→absent（DELETE CAS）：仅当 `lease` 仍匹配时释放 claim。
    ///
    /// token 不符（已被 TTL 重捞、他人接管）为幂等 no-op（`Ok(())`，不误删他人 claim）；
    /// absent key 同样 no-op。
    ///
    /// 后端暂不可用 → `EngineErrorKind::Transient`；原始 sqlx 错误不进 Display（PII 边界）。
    async fn release(&self, key: &IdemKey, lease: &LeaseToken) -> Result<(), EngineError> {
        sqlx::query(
            r#"
            DELETE FROM inbox_dedup
            WHERE event_id = $1 AND consumer_group = $2
              AND lease_token = $3::uuid AND status = 'claimed'
            "#,
        )
        .bind(key.as_str())
        .bind(self.group.as_str())
        .bind(lease.as_str())
        .execute(&self.pool)
        .await
        .map_err(|e| {
            tracing::warn!(target: "postgres", operation = "inbox_release", error = %secure::redact_error(&e), "inbox: release db error");
            EngineError::new(EngineErrorKind::Transient)
        })?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    //! postgres inbox_dedup 集成测试（租约 CAS + TTL 重捞，#1213）。
    //!
    //! integration 测试需要活 PG 实例，由 `integration` feature 门控。

    #[cfg(feature = "integration")]
    mod integration {
        use consistency::{
            ConsumerGroup, IdemKey, IdempotencyStore, LeaseOutcome, LeaseToken, SeenState,
        };

        type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

        #[allow(clippy::unwrap_used)]
        // reason: 测试 setup — 已知非空 raw，item-level carve-out（error-handling.md §Carve-out）。
        fn k(raw: &str) -> IdemKey {
            IdemKey::parse(raw).unwrap()
        }

        #[allow(clippy::unwrap_used)]
        // reason: 测试 setup — 已知非空组名，item-level carve-out。
        fn g(raw: &str) -> ConsumerGroup {
            ConsumerGroup::parse(raw).unwrap()
        }

        /// 铸出唯一租约 token（uuid v4）。
        fn lease() -> LeaseToken {
            LeaseToken::mint()
        }

        /// 铸出 per-run 唯一 inbox key（`{prefix}-{uuid v4}`）——集成测试可复用长存外部 PG，固定
        /// event_id 一旦被 `commit` 标成永久 `done`，下一轮同 key 首次 claim 会退化成 `Duplicate`；
        /// 经此 funnel 让每次运行用全新 key，杜绝跨运行持久状态污染（亦消除散落的 `format!(uuid)` 重复）。
        fn uk(prefix: &str) -> IdemKey {
            k(&format!("{prefix}-{}", uuid::Uuid::new_v4()))
        }

        /// claim → commit → try_claim = Duplicate（done 永久去重，PG 往返）。
        #[tokio::test(flavor = "multi_thread")]
        #[allow(clippy::unwrap_used)]
        // reason: 集成测试断言 fail-loud（往返结果必 Ok）；item-level carve-out（error-handling.md §Carve-out）。
        async fn commit_makes_key_permanently_duplicate() -> TestResult {
            let (_pg, store) = crate::test_pg::connect_pg().await?;
            store.run_migrations().await?;
            let inbox = store.inbox(g("test-group"));
            let key = uk("pg-commit-evt");
            let lease_a = lease();
            assert_eq!(
                inbox.try_claim(&key, &lease_a).await.unwrap(),
                SeenState::Fresh
            );
            assert_eq!(
                inbox.commit(&key, &lease_a).await.unwrap(),
                LeaseOutcome::Held
            );
            // done 行：任意新 token try_claim → Duplicate（DO UPDATE WHERE status='claimed' 为 false）。
            assert_eq!(
                inbox.try_claim(&key, &lease()).await.unwrap(),
                SeenState::Duplicate
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
            let inbox = store.inbox(g("test-group"));
            let key = uk("pg-release-evt");
            let lease_a = lease();
            assert_eq!(
                inbox.try_claim(&key, &lease_a).await.unwrap(),
                SeenState::Fresh
            );
            inbox.release(&key, &lease_a).await.unwrap();
            // absent 行：新 token try_claim → Fresh。
            assert_eq!(
                inbox.try_claim(&key, &lease()).await.unwrap(),
                SeenState::Fresh
            );
            Ok(())
        }

        /// commit 对 absent key 返 Lost（hard-fence；无行匹配 CAS）。
        #[tokio::test(flavor = "multi_thread")]
        async fn commit_on_absent_returns_lost() -> TestResult {
            let (_pg, store) = crate::test_pg::connect_pg().await?;
            store.run_migrations().await?;
            let inbox = store.inbox(g("test-group"));
            let key = uk("pg-absent-commit");
            assert_eq!(inbox.commit(&key, &lease()).await?, LeaseOutcome::Lost);
            Ok(())
        }

        /// release 对 absent key 幂等 no-op（不报错）。
        #[tokio::test(flavor = "multi_thread")]
        async fn release_on_absent_is_ok() -> TestResult {
            let (_pg, store) = crate::test_pg::connect_pg().await?;
            store.run_migrations().await?;
            let inbox = store.inbox(g("test-group"));
            let key = uk("pg-absent-release");
            assert!(inbox.release(&key, &lease()).await.is_ok());
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
            let inbox = store.inbox(g(grp));
            let key = uk("pg-extend-takeover");
            let lease_a = lease();

            // claim。
            assert_eq!(
                inbox.try_claim(&key, &lease_a).await.unwrap(),
                SeenState::Fresh
            );

            // 持有期间续租 → Held。
            assert_eq!(
                inbox.extend(&key, &lease_a).await.unwrap(),
                LeaseOutcome::Held
            );

            // 模拟他人接管：覆盖 DB 中 lease_token。
            sqlx::query(
                "UPDATE inbox_dedup SET lease_token = gen_random_uuid() \
                 WHERE event_id = $1 AND consumer_group = $2",
            )
            .bind(key.as_str())
            .bind(grp)
            .execute(&store.pool)
            .await?;

            // 旧 token 续租 → Lost（已被他人接管，CAS 不命中）。
            assert_eq!(
                inbox.extend(&key, &lease_a).await.unwrap(),
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
            let inbox = store.inbox(g(grp));
            let key = uk("pg-ttl-reclaim");
            let lease_a = lease();
            let ttl = super::super::INBOX_LEASE_TTL_SECONDS;

            // token A claim。
            assert_eq!(
                inbox.try_claim(&key, &lease_a).await.unwrap(),
                SeenState::Fresh
            );

            // 回拨 claimed_at 超过 TTL（模拟 crash-after-claim，lease 过期）。
            sqlx::query(
                "UPDATE inbox_dedup \
                 SET claimed_at = now() - make_interval(secs => $1) \
                 WHERE event_id = $2 AND consumer_group = $3",
            )
            .bind(ttl + 1)
            .bind(key.as_str())
            .bind(grp)
            .execute(&store.pool)
            .await?;

            // token B try_claim → Fresh（TTL 重捞，stale claimed 行被新 token 接管）。
            let lease_b = lease();
            assert_eq!(
                inbox.try_claim(&key, &lease_b).await.unwrap(),
                SeenState::Fresh
            );

            // token A commit → Lost（已被 B 接管，CAS 不命中；hard-fence）。
            assert_eq!(
                inbox.commit(&key, &lease_a).await.unwrap(),
                LeaseOutcome::Lost
            );

            // token B commit → Held（B 是当前持有者，CAS 命中，done 永久去重）。
            assert_eq!(
                inbox.commit(&key, &lease_b).await.unwrap(),
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
            let inbox = store.inbox(g(grp));

            // ── commit wrong token ──────────────────────────────────────────────
            let key_c = uk("pg-commit-fence");
            let lease_mine = lease();
            let lease_wrong = lease();

            assert_eq!(
                inbox.try_claim(&key_c, &lease_mine).await.unwrap(),
                SeenState::Fresh
            );

            // 错误 token commit → Lost（CAS 不命中，行仍 claimed）。
            assert_eq!(
                inbox.commit(&key_c, &lease_wrong).await.unwrap(),
                LeaseOutcome::Lost
            );
            // 正确 token commit → Held（行正确结算 done）。
            assert_eq!(
                inbox.commit(&key_c, &lease_mine).await.unwrap(),
                LeaseOutcome::Held
            );

            // ── release wrong token ─────────────────────────────────────────────
            let key_r = uk("pg-release-fence");
            let lease_mine2 = lease();
            let lease_wrong2 = lease();

            assert_eq!(
                inbox.try_claim(&key_r, &lease_mine2).await.unwrap(),
                SeenState::Fresh
            );

            // 错误 token release → no-op（不误删他人 claim）。
            inbox.release(&key_r, &lease_wrong2).await.unwrap();

            // 行仍被 mine2 持有 → Duplicate（DO UPDATE WHERE claimed_at 仍在 TTL 内）。
            assert_eq!(
                inbox.try_claim(&key_r, &lease()).await.unwrap(),
                SeenState::Duplicate
            );
            Ok(())
        }
    }
}
