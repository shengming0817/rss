//! Deterministic test support for migrations that are expected to fail.

use std::time::Duration;

use sqlx::migrate::{MigrateError, Migrator};
use sqlx::pool::PoolConnection;
use sqlx::{PgPool, Postgres};

use super::{PgStore, TestError};

const STANDARD_STAGE_TIMEOUT: Duration = Duration::from_secs(10);
const DIAGNOSTIC_TIMEOUT: Duration = Duration::from_secs(2);
const SESSION_FALLBACK_TIMEOUT: &str = "15s";

enum StageOutcome {
    Finished(Result<(), MigrateError>),
    TimedOut(String),
}

/// Owns the exact PostgreSQL backend used by expected-failure migration tests.
///
/// SQLx holds its migration advisory lock at session scope and only unlocks it after a fully
/// successful run. Keeping the connection private makes rollback flushing and exact-session
/// cleanup mandatory for every canonical expected-failure attempt.
pub(in super::super) struct ExpectedMigrationFailureSession {
    connection: Option<PoolConnection<Postgres>>,
    diagnostics: PgPool,
    backend_pid: i32,
    clean: bool,
}

impl ExpectedMigrationFailureSession {
    pub(in super::super) async fn acquire(store: &PgStore) -> Result<Self, TestError> {
        let mut connection = store.pool.acquire().await?;
        let backend_pid = sqlx::query_scalar("SELECT pg_catalog.pg_backend_pid()")
            .fetch_one(&mut *connection)
            .await?;
        Ok(Self {
            connection: Some(connection),
            diagnostics: store.pool.clone(),
            backend_pid,
            clean: true,
        })
    }

    pub(in super::super) fn backend_pid(&self) -> i32 {
        self.backend_pid
    }

    pub(in super::super) async fn run_success(
        &mut self,
        migrator: &Migrator,
        stage: &'static str,
    ) -> Result<(), TestError> {
        match self
            .run_stage(migrator, stage, STANDARD_STAGE_TIMEOUT)
            .await?
        {
            StageOutcome::Finished(Ok(())) => self.cleanup_and_verify(stage, false).await,
            StageOutcome::Finished(Err(error)) => {
                self.cleanup_and_verify(stage, false).await?;
                Err(format!("migration stage={stage} failed unexpectedly: {error}").into())
            }
            StageOutcome::TimedOut(diagnostic) => {
                Err(format!("migration stage timed out: {diagnostic}").into())
            }
        }
    }

    pub(in super::super) async fn expect_failure(
        &mut self,
        migrator: &Migrator,
        stage: &'static str,
        expected_error: &str,
    ) -> Result<(), TestError> {
        match self
            .run_stage(migrator, stage, STANDARD_STAGE_TIMEOUT)
            .await?
        {
            StageOutcome::Finished(Err(error)) => {
                let rendered = error.to_string();
                self.cleanup_and_verify(stage, true).await?;
                if rendered.contains(expected_error) {
                    Ok(())
                } else {
                    Err(
                        format!("migration stage={stage} returned an unexpected error: {rendered}")
                            .into(),
                    )
                }
            }
            StageOutcome::Finished(Ok(())) => {
                self.cleanup_and_verify(stage, false).await?;
                Err(format!("migration stage={stage} unexpectedly succeeded").into())
            }
            StageOutcome::TimedOut(diagnostic) => {
                Err(format!("migration stage timed out: {diagnostic}").into())
            }
        }
    }

    async fn run_stage(
        &mut self,
        migrator: &Migrator,
        stage: &'static str,
        timeout: Duration,
    ) -> Result<StageOutcome, TestError> {
        self.clean = false;
        if let Err(error) = self.configure_timeouts().await {
            self.poison_connection();
            return Err(format!("migration stage={stage} timeout setup failed: {error}").into());
        }
        let diagnostics = self.diagnostics.clone();
        let backend_pid = self.backend_pid;
        let outcome = {
            let connection = self
                .connection
                .as_mut()
                .ok_or("migration session is unavailable after a previous timeout")?;
            let migration = migrator.run_direct(&mut **connection);
            tokio::pin!(migration);
            tokio::select! {
                result = &mut migration => StageOutcome::Finished(result),
                () = tokio::time::sleep(timeout) => {
                    let diagnostic = match tokio::time::timeout(
                        DIAGNOSTIC_TIMEOUT,
                        Self::diagnose(&diagnostics, backend_pid, stage),
                    )
                    .await
                    {
                        Ok(Ok(diagnostic)) => diagnostic,
                        Ok(Err(error)) => format!(
                            "stage={stage} pid={backend_pid} diagnostic_error={error}"
                        ),
                        Err(_) => format!(
                            "stage={stage} pid={backend_pid} diagnostic_timeout"
                        ),
                    };
                    StageOutcome::TimedOut(diagnostic)
                }
            }
        };

        if matches!(outcome, StageOutcome::TimedOut(_)) {
            self.poison_connection();
        }
        Ok(outcome)
    }

    async fn configure_timeouts(&mut self) -> Result<(), TestError> {
        let connection = self
            .connection
            .as_mut()
            .ok_or("migration session is unavailable after a previous timeout")?;
        // The client deadline must win first so it can inspect the still-waiting backend. These
        // server settings remain a fail-safe if the task is not polled or client cancellation is
        // delayed; migration-local GUCs may still impose tighter DDL limits after lock acquisition.
        sqlx::query("SELECT pg_catalog.set_config('lock_timeout', $1, false)")
            .bind(SESSION_FALLBACK_TIMEOUT)
            .execute(&mut **connection)
            .await?;
        sqlx::query("SELECT pg_catalog.set_config('statement_timeout', $1, false)")
            .bind(SESSION_FALLBACK_TIMEOUT)
            .execute(&mut **connection)
            .await?;
        Ok(())
    }

    async fn cleanup_and_verify(
        &mut self,
        stage: &'static str,
        expect_held_lock: bool,
    ) -> Result<(), TestError> {
        if expect_held_lock {
            let held = match self.advisory_lock_count().await {
                Ok(held) => held,
                Err(error) => {
                    self.poison_connection();
                    return Err(format!(
                        "migration stage={stage} pre-cleanup lock verification failed: {error}"
                    )
                    .into());
                }
            };
            if held == 0 {
                self.poison_connection();
                return Err(format!(
                    "migration stage={stage} failed without the expected SQLx session advisory lock"
                )
                .into());
            }
        }

        let cleanup = async {
            let connection = self
                .connection
                .as_mut()
                .ok_or("migration session is unavailable after a previous timeout")?;
            // The first exact-session roundtrip also flushes SQLx's queued transaction rollback.
            sqlx::query("SELECT pg_catalog.pg_advisory_unlock_all()")
                .execute(&mut **connection)
                .await?;
            sqlx::query("RESET lock_timeout")
                .execute(&mut **connection)
                .await?;
            sqlx::query("RESET statement_timeout")
                .execute(&mut **connection)
                .await?;
            let probe: i32 = sqlx::query_scalar("SELECT 1")
                .fetch_one(&mut **connection)
                .await?;
            if probe != 1 {
                return Err::<(), TestError>("migration session health probe failed".into());
            }
            Ok::<(), TestError>(())
        }
        .await;
        if let Err(error) = cleanup {
            self.poison_connection();
            return Err(format!("migration stage={stage} cleanup failed: {error}").into());
        }

        let remaining = match self.advisory_lock_count().await {
            Ok(remaining) => remaining,
            Err(error) => {
                self.poison_connection();
                return Err(format!(
                    "migration stage={stage} post-cleanup lock verification failed: {error}"
                )
                .into());
            }
        };
        if remaining != 0 {
            self.poison_connection();
            return Err(format!(
                "migration stage={stage} leaked {remaining} session advisory lock(s)"
            )
            .into());
        }
        self.clean = true;
        Ok(())
    }

    async fn advisory_lock_count(&self) -> Result<i64, TestError> {
        Ok(sqlx::query_scalar(
            "SELECT count(*) FROM pg_catalog.pg_locks \
             WHERE pid = $1 AND locktype = 'advisory' AND granted",
        )
        .bind(self.backend_pid)
        .fetch_one(&self.diagnostics)
        .await?)
    }

    async fn diagnose(
        diagnostics: &PgPool,
        backend_pid: i32,
        stage: &'static str,
    ) -> Result<String, sqlx::Error> {
        let activity: Option<(Option<String>, Option<String>, Option<String>)> = sqlx::query_as(
            "SELECT state, wait_event_type, wait_event \
             FROM pg_catalog.pg_stat_activity WHERE pid = $1",
        )
        .bind(backend_pid)
        .fetch_optional(diagnostics)
        .await?;
        let locks: Vec<(String, String, bool)> = sqlx::query_as(
            "SELECT locktype, mode, granted FROM pg_catalog.pg_locks \
             WHERE pid = $1 ORDER BY locktype, mode, granted",
        )
        .bind(backend_pid)
        .fetch_all(diagnostics)
        .await?;
        let blockers: Vec<i32> =
            sqlx::query_scalar("SELECT unnest(pg_catalog.pg_blocking_pids($1))")
                .bind(backend_pid)
                .fetch_all(diagnostics)
                .await?;

        let (state, wait_type, wait_event) = activity.unwrap_or_default();
        let rendered_locks = locks
            .into_iter()
            .map(|(lock_type, mode, granted)| {
                format!(
                    "{lock_type}:{mode}:{}",
                    if granted { "granted" } else { "waiting" }
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        Ok(format!(
            "stage={stage} pid={backend_pid} state={} wait={}/{} locks=[{}] blockers={blockers:?}",
            state.as_deref().unwrap_or("unknown"),
            wait_type.as_deref().unwrap_or("none"),
            wait_event.as_deref().unwrap_or("none"),
            rendered_locks
        ))
    }

    fn poison_connection(&mut self) {
        if let Some(mut connection) = self.connection.take() {
            connection.close_on_drop();
            drop(connection);
        }
    }
}

impl Drop for ExpectedMigrationFailureSession {
    fn drop(&mut self) {
        if !self.clean {
            self.poison_connection();
        }
    }
}
