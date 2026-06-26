//! Migrator：用 `sqlx::migrate!` 编译期内嵌 `migrations/` 并应用到连接池（eventexec 持久化基座，#1116）。
//!
//! `ref: sqlx sqlx-core/src/migrate/migrator.rs@v0.8.6` · `ref: sqlx sqlx-macros-core/src/migrate.rs@v0.8.6`。

use crate::PgStore;
use crate::pool::PgError;

impl PgStore {
    /// 应用 `adapters/postgres/migrations/` 下全部迁移（`migrate!` 编译期 `include_str!` 内嵌，不依赖运行时文件系统）。
    ///
    /// `locking` 默认（pg advisory lock）防多实例启动重复迁移；`_sqlx_migrations.checksum` 守 "已提交
    /// migration 只增不改"（改了报 `VersionMismatch`）。幂等：已应用的迁移再跑为 no-op。
    ///
    /// 调用时机：组合根 / bootstrap 中、`Domain::init` **之前**（init 不做外部 I/O，`domain-patterns.md`
    /// §Init fail-fast）。
    ///
    /// `pub(crate)`（#1423，PG-BUNDLE-FUNNEL-01）：迁移收口进 [`crate::PgRuntimeDeps::setup`]（connect 后即跑）。
    pub(crate) async fn run_migrations(&self) -> Result<(), PgError> {
        sqlx::migrate!("./migrations")
            .run(&self.pool)
            .await
            .inspect_err(|err| {
                // reason: 迁移失败是启动关键路径，error! 记账（observability.md §日志级别）；第三方
                // MigrateError 经 secure::redact_error 统一脱敏 funnel；版本号保留在 source。
                tracing::error!(target: "postgres", error = %secure::redact_error(err), "postgres migrations failed");
            })
            .map_err(PgError::Migrate)?;
        // reason: 迁移是启动生命周期事件，成功须 info! 记账（observability.md §日志级别）。
        tracing::info!(target: "postgres", "postgres migrations applied");
        Ok(())
    }
}
