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
    /// - `Duplicate`：rows_affected == 0（冲突，已 claim，幂等短路）。
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
}
