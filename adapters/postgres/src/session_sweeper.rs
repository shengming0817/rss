//! `PgSessionSweeper` —— sessions 过期行维护 adapter（#1233）。
//!
//! 会话生命周期仍由 [`PgSessionLifecycle`](crate::PgSessionLifecycle) 承担；过期清理是 postgres/runtime
//! maintenance 能力，不进入 identity 域端口。runtime serving pool 仅调用迁移安装的固定
//! `rss_sweep_expired_sessions()` SECURITY DEFINER 函数；本类型不暴露 tenant、raw pool、SQL 或 retain 参数。

use consistency::{EngineError, EngineErrorKind};
use sqlx::PgPool;

use crate::PgStore;

/// PostgreSQL sessions 过期行清理器。
///
/// 字段私有，唯一构造入口为 [`crate::PgInfraDeps::session_sweeper`]；对外只暴露
/// [`Self::sweep_expired`]。
pub struct PgSessionSweeper {
    pool: PgPool,
}

impl PgStore {
    /// 构造 [`PgSessionSweeper`]（pool clone 自 `PgStore`，轻量）。
    ///
    /// `pub(crate)`（PG-BUNDLE-FUNNEL-01）：经 [`crate::PgInfraDeps::session_sweeper`] 收口。
    pub(crate) fn session_sweeper(&self) -> PgSessionSweeper {
        PgSessionSweeper {
            pool: self.pool.clone(),
        }
    }
}

impl PgSessionSweeper {
    /// 删除 `expires_at <= now()` 的 session 行，返回删除条数。
    ///
    /// SQL 固定在迁移函数 `rss_sweep_expired_sessions()` 内，避免 runtime 拼装全域 DELETE。
    pub async fn sweep_expired(&self) -> Result<u64, EngineError> {
        let (deleted,): (i64,) = sqlx::query_as("SELECT rss_sweep_expired_sessions()::bigint")
            .fetch_one(&self.pool)
            .await
            .map_err(|e| {
                tracing::warn!(
                    target: "postgres",
                    error = %secure::redact_error(&e),
                    "sessions: sweep expired db error"
                );
                EngineError::new(EngineErrorKind::Transient)
            })?;

        Ok(u64::try_from(deleted).unwrap_or(0))
    }
}

#[cfg(test)]
mod smoke {
    use super::PgSessionSweeper;

    fn assert_send_sync<T: Send + Sync>() {}

    #[test]
    fn pg_session_sweeper_is_send_sync() {
        assert_send_sync::<PgSessionSweeper>();
    }
}
