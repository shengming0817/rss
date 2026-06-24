//! postgres inbox_dedup adapter（消费幂等去重，L2 一致性锚点，#1118）。
//!
//! `PgInboxStore` 实现 [`consistency::IdempotencyStore`] 引擎策略 trait（native AFIT，泛型静态分发消费，
//! 零 box，**非** diport DI port）。claim-or-skip 语义经
//! `INSERT INTO inbox_dedup ... ON CONFLICT DO NOTHING`：
//! - `rows_affected == 1` → 首见 → [`consistency::SeenState::Fresh`]（应执行副作用）。
//! - `rows_affected == 0` → 冲突（已记录）→ [`consistency::SeenState::Duplicate`]（幂等短路）。
//!
//! `status`/`claimed_at` 用表 DEFAULT（`'claimed'` / `now()`），INSERT 不显式传以避免注入 Clock。
//! 后端暂不可用（sqlx 错误）映射为 [`consistency::EngineErrorKind::Transient`]（可重试），
//! 原始 sqlx 错误不进 Display（PII 边界，error-handling.md §Message 与 PII）。
//!
//! `ref: serverlesstechnology/cqrs`（postgres persistence 幂等消费，INSERT ON CONFLICT DO NOTHING 范式）。

use consistency::{EngineError, EngineErrorKind, IdemKey, IdempotencyStore, SeenState};
use sqlx::PgPool;

use crate::PgStore;

/// postgres inbox_dedup 幂等去重 store（claim-or-skip）。
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

impl IdempotencyStore for PgInboxStore {
    /// claim-or-skip：`INSERT INTO inbox_dedup ON CONFLICT DO NOTHING`。
    ///
    /// - `Fresh`：rows_affected == 1（首次 claim，应执行副作用）。
    /// - `Duplicate`：rows_affected == 0（冲突，已 claim/done，幂等短路）。
    ///
    /// 后端暂不可用 → `EngineErrorKind::Transient`（可重试）；原始 sqlx 错误不进 Display（PII 边界）。
    async fn check(&self, key: &IdemKey) -> Result<SeenState, EngineError> {
        let affected = sqlx::query(
            "INSERT INTO inbox_dedup (event_id, consumer_group) \
             VALUES ($1, $2) \
             ON CONFLICT (event_id, consumer_group) DO NOTHING",
        )
        .bind(key.as_str())
        .bind(self.group.as_str())
        .execute(&self.pool)
        .await
        // 后端暂不可用=可重试；原始 sqlx 错误不进 Display 消息（PII 边界）。
        .map_err(|_e| EngineError::new(EngineErrorKind::Transient))?
        .rows_affected();

        Ok(if affected == 1 {
            SeenState::Fresh
        } else {
            SeenState::Duplicate
        })
    }

    /// claimed→done：`UPDATE inbox_dedup SET status='done' WHERE ... AND status='claimed'`。
    ///
    /// 对 absent key（无行匹配）为幂等 no-op（`Ok(())`）；对 done 行（status≠'claimed'）同样幂等跳过。
    /// 后端暂不可用 → `EngineErrorKind::Transient`；原始 sqlx 错误不进 Display（PII 边界）。
    async fn commit(&self, key: &IdemKey) -> Result<(), EngineError> {
        sqlx::query(
            "UPDATE inbox_dedup SET status = 'done' \
             WHERE event_id = $1 AND consumer_group = $2 AND status = 'claimed'",
        )
        .bind(key.as_str())
        .bind(self.group.as_str())
        .execute(&self.pool)
        .await
        .map_err(|_e| EngineError::new(EngineErrorKind::Transient))?;
        Ok(())
    }

    /// claimed→absent：`DELETE FROM inbox_dedup WHERE ... AND status='claimed'`。
    ///
    /// 释放 claim，使后续重放可重新得到 `Fresh`。对 absent key 为幂等 no-op（`Ok(())`）。
    /// 后端暂不可用 → `EngineErrorKind::Transient`；原始 sqlx 错误不进 Display（PII 边界）。
    async fn release(&self, key: &IdemKey) -> Result<(), EngineError> {
        sqlx::query(
            "DELETE FROM inbox_dedup \
             WHERE event_id = $1 AND consumer_group = $2 AND status = 'claimed'",
        )
        .bind(key.as_str())
        .bind(self.group.as_str())
        .execute(&self.pool)
        .await
        .map_err(|_e| EngineError::new(EngineErrorKind::Transient))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    //! postgres inbox_dedup 的 commit/release 往返测试。
    //!
    //! integration 测试需要活 PG 实例，由 `integration` feature 门控。
    //! 单元骨架确保编译通过；往返验收见 integration 门控测试。

    #[cfg(feature = "integration")]
    mod integration {
        use consistency::{ConsumerGroup, IdemKey, IdempotencyStore, SeenState};

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

        /// claim → commit → check = Duplicate（done 永久去重，PG 往返）。
        #[tokio::test(flavor = "multi_thread")]
        #[allow(clippy::unwrap_used)]
        // reason: 集成测试断言 fail-loud（往返结果必 Ok）；item-level carve-out（error-handling.md §Carve-out）。
        async fn commit_makes_key_permanently_duplicate() -> TestResult {
            let (_pg, store) = crate::test_pg::connect_pg().await?;
            store.run_migrations().await?;
            let inbox = store.inbox(g("test-group"));
            let key = k("pg-commit-evt-1");
            assert_eq!(inbox.check(&key).await.unwrap(), SeenState::Fresh);
            inbox.commit(&key).await.unwrap();
            assert_eq!(inbox.check(&key).await.unwrap(), SeenState::Duplicate);
            Ok(())
        }

        /// claim → release → check = Fresh（释放后可重领，PG 往返）。
        #[tokio::test(flavor = "multi_thread")]
        #[allow(clippy::unwrap_used)]
        // reason: 集成测试断言 fail-loud（往返结果必 Ok）；item-level carve-out（error-handling.md §Carve-out）。
        async fn release_allows_reclaim() -> TestResult {
            let (_pg, store) = crate::test_pg::connect_pg().await?;
            store.run_migrations().await?;
            let inbox = store.inbox(g("test-group"));
            let key = k("pg-release-evt-1");
            assert_eq!(inbox.check(&key).await.unwrap(), SeenState::Fresh);
            inbox.release(&key).await.unwrap();
            assert_eq!(inbox.check(&key).await.unwrap(), SeenState::Fresh);
            Ok(())
        }

        /// commit 对 absent key 幂等（不报错）。
        #[tokio::test(flavor = "multi_thread")]
        async fn commit_on_absent_is_ok() -> TestResult {
            let (_pg, store) = crate::test_pg::connect_pg().await?;
            store.run_migrations().await?;
            let inbox = store.inbox(g("test-group"));
            let key = k("pg-absent-commit");
            assert!(inbox.commit(&key).await.is_ok());
            Ok(())
        }

        /// release 对 absent key 幂等（不报错）。
        #[tokio::test(flavor = "multi_thread")]
        async fn release_on_absent_is_ok() -> TestResult {
            let (_pg, store) = crate::test_pg::connect_pg().await?;
            store.run_migrations().await?;
            let inbox = store.inbox(g("test-group"));
            let key = k("pg-absent-release");
            assert!(inbox.release(&key).await.is_ok());
            Ok(())
        }
    }
}
