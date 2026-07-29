//! `PgAuthGrantSweeper` —— AuthGrant 过期根维护 adapter。
//!
//! AuthGrant 生命周期仍由 [`PgAuthGrantLifecycle`](crate::PgAuthGrantLifecycle) 承担；过期清理是 postgres/runtime
//! maintenance 能力，不进入 identity 域端口。runtime serving pool 仅调用迁移安装的固定
//! `rss_sweep_expired_auth_grants()` SECURITY DEFINER 函数；本类型不暴露 tenant、raw pool、SQL 或 retain 参数。

use std::future::Future;
use std::time::Duration;

use consistency::{EngineError, EngineErrorKind};
use sqlx::{Acquire, PgPool};

use crate::PgStore;

/// PostgreSQL AuthGrant 过期根清理器。
///
/// 字段私有，唯一构造入口为 [`crate::PgInfraDeps::auth_grant_sweeper`]；对外只暴露
/// [`Self::sweep_expired`]。
pub struct PgAuthGrantSweeper {
    pool: PgPool,
    #[cfg(all(test, feature = "integration"))]
    pause: Option<(AuthGrantSweepStage, Duration)>,
}

/// One absolute monotonic deadline for the complete AuthGrant database sweep.
///
/// The instant is private so callers and adapters cannot reset the budget between pool acquire,
/// transaction begin, timeout setup, the maintenance query, and commit.
#[derive(Clone, Copy, Debug)]
pub struct AuthGrantSweepDeadline {
    operation: tokio::time::Instant,
}

impl AuthGrantSweepDeadline {
    /// Mint a deadline from a non-zero caller budget.
    pub fn from_timeout(timeout: Duration) -> Result<Self, EngineError> {
        if timeout.is_zero() {
            return Err(EngineError::new(EngineErrorKind::Permanent));
        }
        #[allow(clippy::disallowed_methods)]
        let operation = tokio::time::Instant::now()
            .checked_add(timeout)
            .ok_or_else(|| EngineError::new(EngineErrorKind::Permanent))?;
        Ok(Self { operation })
    }

    async fn run<F: Future>(self, future: F) -> Result<F::Output, EngineError> {
        #[allow(clippy::disallowed_methods)]
        if tokio::time::Instant::now() >= self.operation {
            return Err(EngineError::new(EngineErrorKind::Transient));
        }
        tokio::time::timeout_at(self.operation, future)
            .await
            .map_err(|_| EngineError::new(EngineErrorKind::Transient))
    }

    fn server_timeout_millis(self) -> Result<(u64, u64), EngineError> {
        #[allow(clippy::disallowed_methods)]
        let remaining = self
            .operation
            .saturating_duration_since(tokio::time::Instant::now());
        let remaining_millis = u64::try_from(remaining.as_millis()).unwrap_or(u64::MAX);
        let statement_millis = remaining_millis
            .checked_sub(2)
            .filter(|millis| *millis > 0)
            .ok_or_else(|| EngineError::new(EngineErrorKind::Transient))?;
        Ok((statement_millis, statement_millis.min(5_000)))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AuthGrantSweepStage {
    Acquire,
    Begin,
    Setup,
    Query,
    Commit,
}

impl AuthGrantSweepStage {
    #[cfg(all(test, feature = "integration"))]
    pub(crate) const ALL: &'static [Self] = &[
        Self::Acquire,
        Self::Begin,
        Self::Setup,
        Self::Query,
        Self::Commit,
    ];
}

impl PgStore {
    /// 构造 [`PgAuthGrantSweeper`]（pool clone 自 `PgStore`，轻量）。
    ///
    /// `pub(crate)`（PG-BUNDLE-FUNNEL-01）：经 [`crate::PgInfraDeps::auth_grant_sweeper`] 收口。
    pub(crate) fn auth_grant_sweeper(&self) -> PgAuthGrantSweeper {
        PgAuthGrantSweeper {
            pool: self.pool.clone(),
            #[cfg(all(test, feature = "integration"))]
            pause: None,
        }
    }
}

impl PgAuthGrantSweeper {
    #[cfg(all(test, feature = "integration"))]
    pub(crate) fn with_pause_for_test(
        mut self,
        stage: AuthGrantSweepStage,
        pause: Duration,
    ) -> Self {
        self.pause = Some((stage, pause));
        self
    }

    /// 删除 `expires_at <= now()` 的 AuthGrant 根：先稳定锁定并显式删除 refresh family，
    /// 再重新验证 root 已过期并删除 root。
    ///
    /// SQL 固定在迁移函数 `rss_sweep_expired_auth_grants()` 内。
    pub async fn sweep_expired(
        &self,
        deadline: AuthGrantSweepDeadline,
    ) -> Result<u64, EngineError> {
        let mut connection = self
            .run_stage(deadline, AuthGrantSweepStage::Acquire, self.pool.acquire())
            .await?;
        let mut transaction = self
            .run_stage(deadline, AuthGrantSweepStage::Begin, connection.begin())
            .await?;
        let (statement_timeout_ms, lock_timeout_ms) = deadline.server_timeout_millis()?;
        self.run_stage(
            deadline,
            AuthGrantSweepStage::Setup,
            sqlx::query(
                "SELECT set_config('statement_timeout', $1, true), \
                        set_config('lock_timeout', $2, true)",
            )
            .bind(format!("{statement_timeout_ms}ms"))
            .bind(format!("{lock_timeout_ms}ms"))
            .execute(&mut *transaction),
        )
        .await?;
        let (deleted,): (i64,) = self
            .run_stage(
                deadline,
                AuthGrantSweepStage::Query,
                sqlx::query_as("SELECT rss_sweep_expired_auth_grants()::bigint")
                    .fetch_one(&mut *transaction),
            )
            .await?;
        self.run_stage(deadline, AuthGrantSweepStage::Commit, transaction.commit())
            .await?;

        Ok(u64::try_from(deleted).unwrap_or(0))
    }

    async fn run_stage<T, F>(
        &self,
        deadline: AuthGrantSweepDeadline,
        stage: AuthGrantSweepStage,
        future: F,
    ) -> Result<T, EngineError>
    where
        F: Future<Output = Result<T, sqlx::Error>>,
    {
        #[cfg(all(test, feature = "integration"))]
        let operation = self.pause_stage(stage, future);
        #[cfg(not(all(test, feature = "integration")))]
        let operation = {
            let _ = stage;
            future
        };
        deadline
            .run(operation)
            .await
            .map_err(log_sweep_deadline)?
            .map_err(log_sweep_database)
    }

    #[cfg(all(test, feature = "integration"))]
    async fn pause_stage<T, F>(
        &self,
        stage: AuthGrantSweepStage,
        future: F,
    ) -> Result<T, sqlx::Error>
    where
        F: Future<Output = Result<T, sqlx::Error>>,
    {
        if let Some((paused, duration)) = self.pause
            && paused == stage
        {
            tokio::time::sleep(duration).await;
        }
        future.await
    }
}

fn log_sweep_database(error: sqlx::Error) -> EngineError {
    tracing::warn!(
        target: "postgres",
        error = %secure::redact_error(&error),
        "auth grants: sweep expired db error"
    );
    EngineError::new(EngineErrorKind::Transient)
}

fn log_sweep_deadline(error: EngineError) -> EngineError {
    tracing::warn!(
        target: "postgres",
        "auth grants: sweep expired deadline elapsed"
    );
    error
}

#[cfg(test)]
mod smoke {
    use super::PgAuthGrantSweeper;

    fn assert_send_sync<T: Send + Sync>() {}

    #[test]
    fn pg_auth_grant_sweeper_is_send_sync() {
        assert_send_sync::<PgAuthGrantSweeper>();
    }
}
