//! Postgres integration tests — transaction seam.

use super::support::*;

#[tokio::test(flavor = "multi_thread")]
async fn transaction_commit_persists_and_rollback_discards() -> TestResult {
    let (_pg, store) = connect_pg().await?;

    // setup：干净表 + 1 行，commit（committed 数据对所有池连接可见）。
    store
        .raw_fixture_transaction::<_, _, sqlx::Error>(|cap| {
            Box::pin(async move {
                sqlx::query("DROP TABLE IF EXISTS rss_tx_probe")
                    .execute(&mut *cap)
                    .await?;
                sqlx::query("CREATE TABLE rss_tx_probe (id int)")
                    .execute(&mut *cap)
                    .await?;
                sqlx::query("INSERT INTO rss_tx_probe (id) VALUES (1)")
                    .execute(&mut *cap)
                    .await?;
                Ok(())
            }) as BoxFuture<'_, Result<(), sqlx::Error>>
        })
        .await?;
    assert_eq!(probe_count(&store).await?, 1);

    // rollback 路径：插入后强制 Err → fixture_transaction 回滚。
    let rolled_back = store
        .raw_fixture_transaction::<_, (), sqlx::Error>(|cap| {
            Box::pin(async move {
                sqlx::query("INSERT INTO rss_tx_probe (id) VALUES (2)")
                    .execute(&mut *cap)
                    .await?;
                Err(sqlx::Error::RowNotFound)
            }) as BoxFuture<'_, Result<(), sqlx::Error>>
        })
        .await;
    assert!(rolled_back.is_err());
    assert_eq!(probe_count(&store).await?, 1); // 回滚 → 行数不变

    // commit 路径：插入后 Ok → 持久化。
    store
        .raw_fixture_transaction::<_, _, sqlx::Error>(|cap| {
            Box::pin(async move {
                sqlx::query("INSERT INTO rss_tx_probe (id) VALUES (3)")
                    .execute(&mut *cap)
                    .await?;
                Ok(())
            }) as BoxFuture<'_, Result<(), sqlx::Error>>
        })
        .await?;
    assert_eq!(probe_count(&store).await?, 2);

    // cleanup
    store
        .raw_fixture_transaction::<_, _, sqlx::Error>(|cap| {
            Box::pin(async move {
                sqlx::query("DROP TABLE rss_tx_probe")
                    .execute(&mut *cap)
                    .await?;
                Ok(())
            }) as BoxFuture<'_, Result<(), sqlx::Error>>
        })
        .await?;

    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn timed_out_owned_transaction_evicts_backend_and_recovers_a_max_two_pool() -> TestResult {
    use std::sync::atomic::{AtomicI32, Ordering};

    let (pg, owner) = connect_pg().await?;
    setup_outbox(&owner).await?;
    let app = connect_pg_rss_app_role_with_limits(&pg, &owner, 2, Duration::from_secs(2)).await?;
    let held = app.pool.acquire().await?;
    let timed_out_pid = Arc::new(AtomicI32::new(0));
    let operation_pid = Arc::clone(&timed_out_pid);
    let deadline = crate::cotx::io_deadline_after(Duration::from_millis(100));
    let result = crate::cotx::deadline_global_transaction(
        &app.pool,
        deadline,
        move |connection| {
            Box::pin(async move {
                let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
                    .fetch_one(connection)
                    .await
                    .map_err(|_| consistency::EngineError::new(EngineErrorKind::Transient))?;
                operation_pid.store(pid, Ordering::SeqCst);
                std::future::pending::<Result<(), consistency::EngineError>>().await
            })
        },
        |_| consistency::EngineError::new(EngineErrorKind::Transient),
        || consistency::EngineError::new(EngineErrorKind::Transient),
    )
    .await;
    assert!(matches!(
        result,
        Err(error) if error.kind() == EngineErrorKind::Transient
    ));
    let old_pid = timed_out_pid.load(Ordering::SeqCst);
    assert!(
        old_pid > 0,
        "the timed-out transaction must acquire a real backend"
    );

    let mut replacement =
        tokio::time::timeout(Duration::from_secs(1), app.pool.acquire()).await??;
    let replacement_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *replacement)
        .await?;
    assert_ne!(
        replacement_pid, old_pid,
        "the poisoned backend must not be reused"
    );
    await_try(Duration::from_secs(1), async || {
        let count =
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM pg_stat_activity WHERE pid = $1")
                .bind(old_pid)
                .fetch_one(&owner.pool)
                .await?;
        Ok::<Option<()>, TestError>((count == 0).then_some(()))
    })
    .await
    .map_err(|error| format!("close_on_drop must terminate the timed-out backend: {error}"))?;

    drop(replacement);
    drop(held);
    app.shutdown().await?;
    owner.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn externally_cancelled_global_transaction_returns_only_ready_clean_connection() -> TestResult
{
    use sqlx::Acquire as _;

    const CANCELLATION_LOCK: i64 = 1_799_008;

    let (pg, owner) = connect_pg().await?;
    setup_outbox(&owner).await?;
    let app = connect_pg_rss_app_role_with_limits(&pg, &owner, 1, Duration::from_secs(5)).await?;
    let cancelled_pool = app.pool.clone();
    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
    let cancelled = tokio::spawn(async move {
        crate::cotx::deadline_global_transaction(
            &cancelled_pool,
            crate::cotx::io_deadline_after(Duration::from_secs(30)),
            move |connection| {
                Box::pin(async move {
                    let backend_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
                        .fetch_one(&mut *connection)
                        .await
                        .map_err(|_| consistency::EngineError::new(EngineErrorKind::Transient))?;
                    sqlx::query("SELECT pg_catalog.pg_advisory_xact_lock($1)")
                        .bind(CANCELLATION_LOCK)
                        .execute(&mut *connection)
                        .await
                        .map_err(|_| consistency::EngineError::new(EngineErrorKind::Transient))?;
                    sqlx::query("SELECT pg_catalog.set_config('rss.cancel_probe', 'dirty', true)")
                        .execute(&mut *connection)
                        .await
                        .map_err(|_| consistency::EngineError::new(EngineErrorKind::Transient))?;
                    let _ = entered_tx.send(backend_pid);
                    std::future::pending::<Result<(), consistency::EngineError>>().await
                })
            },
            |_| consistency::EngineError::new(EngineErrorKind::Transient),
            || consistency::EngineError::new(EngineErrorKind::Transient),
        )
        .await
    });

    let cancelled_pid = tokio::time::timeout(Duration::from_secs(5), entered_rx).await??;
    cancelled.abort();
    assert!(
        cancelled.await.is_err_and(|error| error.is_cancelled()),
        "global transaction must be cancelled after its transaction-local state is dirty"
    );

    let mut ready = tokio::time::timeout(Duration::from_secs(5), app.pool.acquire()).await??;
    let (ready_pid, leaked_setting): (i32, Option<String>) = sqlx::query_as(
        "SELECT pg_catalog.pg_backend_pid(), \
                NULLIF(current_setting('rss.cancel_probe', true), '')",
    )
    .fetch_one(&mut *ready)
    .await?;
    assert!(cancelled_pid > 0 && ready_pid > 0);
    assert_eq!(
        leaked_setting, None,
        "rollback-on-drop and release ping must clear transaction-local GUC state"
    );
    let mut next_tx = ready.begin().await?;
    let lock_is_free: bool = sqlx::query_scalar("SELECT pg_catalog.pg_try_advisory_xact_lock($1)")
        .bind(CANCELLATION_LOCK)
        .fetch_one(&mut *next_tx)
        .await?;
    assert!(
        lock_is_free,
        "outer cancellation must release the prior transaction's xact lock"
    );
    next_tx.rollback().await?;

    drop(ready);
    app.shutdown().await?;
    owner.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::panic)]
async fn localtx_deadline_real_postgres_fault_matrix() -> TestResult {
    use std::sync::atomic::{AtomicI32, Ordering};

    use consistency::{LocalTxDeadlineStage, LocalTxExecutionBudget, LocalTxFinalStatus};
    use settings::ports::ConfigRepoError;

    let (pg, owner) = connect_pg().await?;
    owner.run_migrations().await?;
    let app = connect_pg_rss_app_role_with_limits(&pg, &owner, 1, Duration::from_secs(7)).await?;
    let tenant = vocab::TenantId::parse(&uuid::Uuid::new_v4().to_string())?;
    let scoped = crate::cotx::TenantDb::<ServingWriteLane>::from_unverified_for_test(&app);
    let budget =
        LocalTxExecutionBudget::new(Duration::from_millis(300), Duration::from_millis(100))?;
    let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
    let handle = recorder.handle();
    let started = tokio::time::Instant::now();

    metrics::with_local_recorder(&recorder, || {
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                // Acquire: exhaust the sole pool slot until the operation deadline.
                let held = app.pool.acquire().await?;
                let before = localtx_deadline_stage_count(&handle, LocalTxDeadlineStage::Acquire);
                let final_before = localtx_final_total(&handle);
                let case_started = std::time::Instant::now();
                let (acquire, attempts) = run_localtx_deadline_write(&scoped, tenant, budget, |_tx| {
                    Box::pin(async { Ok::<(), ConfigRepoError>(()) })
                })
                .await;
                drop(held);
                assert!(acquire.is_err());
                assert_eq!(attempts, 1, "acquire deadline must not replay");
                assert!(case_started.elapsed() <= budget.total() + Duration::from_millis(250));
                assert_eq!(
                    localtx_deadline_stage_count(&handle, LocalTxDeadlineStage::Acquire),
                    before + 1.0
                );
                assert_eq!(localtx_final_total(&handle), final_before);

                // Begin: the armed lease must quarantine the backend when begin is cancelled.
                let mut connection = app.pool.acquire().await?;
                let begin_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
                    .fetch_one(&mut *connection)
                    .await?;
                drop(connection);
                let before = localtx_deadline_stage_count(&handle, LocalTxDeadlineStage::Begin);
                let final_before = localtx_final_total(&handle);
                let case_started = std::time::Instant::now();
                let (begin, attempts) = crate::cotx::with_localtx_pause_for_test(
                    crate::cotx::LocalTxTestPauseStage::Begin,
                    run_localtx_deadline_write(&scoped, tenant, budget, |_tx| {
                        Box::pin(async { Ok::<(), ConfigRepoError>(()) })
                    }),
                )
                .await;
                assert!(begin.is_err());
                assert_eq!(attempts, 1, "begin deadline must not replay");
                assert!(case_started.elapsed() <= budget.total() + Duration::from_millis(250));
                assert_eq!(
                    localtx_deadline_stage_count(&handle, LocalTxDeadlineStage::Begin),
                    before + 1.0
                );
                assert_eq!(localtx_final_total(&handle), final_before);
                localtx_assert_backend_quarantined(&owner, &app.pool, begin_pid, "begin deadline")
                    .await?;

                // Setup: timeout before mutation, followed by an acknowledged rollback and reuse.
                let mut connection = app.pool.acquire().await?;
                let setup_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
                    .fetch_one(&mut *connection)
                    .await?;
                drop(connection);
                let before = localtx_deadline_stage_count(&handle, LocalTxDeadlineStage::Setup);
                let final_before =
                    localtx_final_status_count(&handle, LocalTxFinalStatus::RolledBack);
                let case_started = std::time::Instant::now();
                let (setup, attempts) = crate::cotx::with_localtx_pause_for_test(
                    crate::cotx::LocalTxTestPauseStage::Setup,
                    run_localtx_deadline_write(&scoped, tenant, budget, |_tx| {
                        Box::pin(async { Ok::<(), ConfigRepoError>(()) })
                    }),
                )
                .await;
                assert!(setup.is_err());
                assert_eq!(attempts, 1, "setup deadline must not replay");
                assert!(case_started.elapsed() <= budget.total() + Duration::from_millis(250));
                assert_eq!(
                    localtx_deadline_stage_count(&handle, LocalTxDeadlineStage::Setup),
                    before + 1.0
                );
                assert_eq!(
                    localtx_final_status_count(&handle, LocalTxFinalStatus::RolledBack),
                    final_before + 1.0
                );
                localtx_assert_backend_reused(&app.pool, setup_pid, "setup deadline rollback ack")
                    .await?;

                // Operation: a durable write before cancellation must still roll back.
                let operation_pid = std::sync::Arc::new(AtomicI32::new(0));
                let pid_out = std::sync::Arc::clone(&operation_pid);
                let statement_timeout_ms = std::sync::Arc::new(AtomicI32::new(0));
                let statement_timeout_out = std::sync::Arc::clone(&statement_timeout_ms);
                let lock_timeout_ms = std::sync::Arc::new(AtomicI32::new(0));
                let lock_timeout_out = std::sync::Arc::clone(&lock_timeout_ms);
                let key = format!("localtx-deadline-operation-{}", uuid::Uuid::new_v4());
                let key_for_write = key.clone();
                let before = localtx_deadline_stage_count(&handle, LocalTxDeadlineStage::Operation);
                let final_before =
                    localtx_final_status_count(&handle, LocalTxFinalStatus::RolledBack);
                let case_started = std::time::Instant::now();
                let (operation, attempts) = run_localtx_deadline_write(&scoped, tenant, budget, move |tx| {
                    let pid_out = std::sync::Arc::clone(&pid_out);
                    let statement_timeout_out = std::sync::Arc::clone(&statement_timeout_out);
                    let lock_timeout_out = std::sync::Arc::clone(&lock_timeout_out);
                    let key = key_for_write.clone();
                    Box::pin(async move {
                        let pid = tx.test_backend_pid().await
                            .map_err(|error| ConfigRepoError::Storage(Box::new(error)))?;
                        pid_out.store(pid, Ordering::SeqCst);
                        let (statement_ms, lock_ms) = tx
                            .test_local_timeouts()
                            .await
                        .map_err(|error| ConfigRepoError::Storage(Box::new(error)))?;
                        statement_timeout_out.store(statement_ms, Ordering::SeqCst);
                        lock_timeout_out.store(lock_ms, Ordering::SeqCst);
                        tx.test_insert_config(&key, "pending")
                        .await
                        .map_err(|error| ConfigRepoError::Storage(Box::new(error)))?;
                        tx.test_sleep_one_second()
                            .await
                            .map_err(|error| ConfigRepoError::Storage(Box::new(error)))
                    })
                })
                .await;
                assert!(operation.is_err());
                assert_eq!(attempts, 1, "server 57014 operation deadline must not replay");
                assert!(case_started.elapsed() <= budget.total() + Duration::from_millis(250));
                assert_eq!(
                    localtx_deadline_stage_count(&handle, LocalTxDeadlineStage::Operation),
                    before + 1.0
                );
                assert_eq!(
                    localtx_final_status_count(&handle, LocalTxFinalStatus::RolledBack),
                    final_before + 1.0
                );
                let statement_ms = statement_timeout_ms.load(Ordering::SeqCst);
                assert!(
                    (1..200).contains(&statement_ms),
                    "dynamic statement_timeout must use the latest residual budget: {statement_ms}ms"
                );
                assert_eq!(
                    lock_timeout_ms.load(Ordering::SeqCst),
                    statement_ms,
                    "sub-5s statement budget must also bound lock wait"
                );
                let durable: i64 =
                    sqlx::query_scalar("SELECT count(*) FROM config_entries WHERE config_key = $1")
                        .bind(&key)
                        .fetch_one(&owner.pool)
                        .await?;
                assert_eq!(
                    durable, 0,
                    "operation timeout must rollback the pending write"
                );
                localtx_assert_backend_reused(
                    &app.pool,
                    operation_pid.load(Ordering::SeqCst),
                    "operation deadline rollback ack",
                )
                .await?;

                // Backoff: a retryable rolled-back attempt must not sleep beyond the budget.
                let before = localtx_deadline_stage_count(&handle, LocalTxDeadlineStage::Backoff);
                let final_before =
                    localtx_final_status_count(&handle, LocalTxFinalStatus::RolledBack);
                let case_started = std::time::Instant::now();
                let backoff_pid = std::sync::Arc::new(AtomicI32::new(0));
                let pid_out = std::sync::Arc::clone(&backoff_pid);
                let (backoff, attempts) = crate::tx_retry::with_localtx_backoff_delay_for_test(
                    Duration::from_millis(250),
                    run_localtx_deadline_write(&scoped, tenant, budget, move |tx| {
                        let pid_out = std::sync::Arc::clone(&pid_out);
                        Box::pin(async move {
                            let pid = tx.test_backend_pid().await
                                .map_err(|error| ConfigRepoError::Storage(Box::new(error)))?;
                            pid_out.store(pid, Ordering::SeqCst);
                            Err::<(), _>(ConfigRepoError::Storage(Box::new(
                                sqlx::Error::PoolTimedOut,
                            )))
                        })
                    }),
                )
                .await;
                assert!(backoff.is_err());
                assert_eq!(attempts, 1, "exhausted backoff must not start a second attempt");
                assert!(case_started.elapsed() <= budget.total() + Duration::from_millis(250));
                assert_eq!(
                    localtx_deadline_stage_count(&handle, LocalTxDeadlineStage::Backoff),
                    before + 1.0
                );
                assert_eq!(
                    localtx_final_status_count(&handle, LocalTxFinalStatus::RolledBack),
                    final_before + 1.0
                );
                localtx_assert_backend_reused(
                    &app.pool,
                    backoff_pid.load(Ordering::SeqCst),
                    "backoff exhaustion after rollback ack",
                )
                .await?;

                // Commit: no ACK means CommitUnknown, no replay, and connection quarantine.
                let commit_pid = std::sync::Arc::new(AtomicI32::new(0));
                let pid_out = std::sync::Arc::clone(&commit_pid);
                let before = localtx_deadline_stage_count(&handle, LocalTxDeadlineStage::Commit);
                let final_before =
                    localtx_final_status_count(&handle, LocalTxFinalStatus::CommitUnknown);
                let case_started = std::time::Instant::now();
                let (commit, attempts) = crate::cotx::with_localtx_pause_for_test(
                    crate::cotx::LocalTxTestPauseStage::Commit,
                    run_localtx_deadline_write(&scoped, tenant, budget, move |tx| {
                        let pid_out = std::sync::Arc::clone(&pid_out);
                        Box::pin(async move {
                            let pid = tx.test_backend_pid().await
                                .map_err(|error| ConfigRepoError::Storage(Box::new(error)))?;
                            pid_out.store(pid, Ordering::SeqCst);
                            Ok(())
                        })
                    }),
                )
                .await;
                assert!(commit.is_err());
                assert_eq!(attempts, 1, "CommitUnknown must never replay");
                assert!(case_started.elapsed() <= budget.total() + Duration::from_millis(250));
                assert_eq!(
                    localtx_deadline_stage_count(&handle, LocalTxDeadlineStage::Commit),
                    before + 1.0
                );
                assert_eq!(
                    localtx_final_status_count(&handle, LocalTxFinalStatus::CommitUnknown),
                    final_before + 1.0
                );
                localtx_assert_backend_quarantined(
                    &owner,
                    &app.pool,
                    commit_pid.load(Ordering::SeqCst),
                    "commit deadline",
                )
                .await?;

                // Rollback: failed settlement carries Rollback evidence and quarantines the PID.
                let rollback_pid = std::sync::Arc::new(AtomicI32::new(0));
                let pid_out = std::sync::Arc::clone(&rollback_pid);
                let before = localtx_deadline_stage_count(&handle, LocalTxDeadlineStage::Rollback);
                let final_before =
                    localtx_final_status_count(&handle, LocalTxFinalStatus::RollbackFailed);
                let case_started = std::time::Instant::now();
                let (rollback, attempts) = run_localtx_deadline_write(&scoped, tenant, budget, move |tx| {
                    let pid_out = std::sync::Arc::clone(&pid_out);
                    Box::pin(async move {
                        let pid = tx.test_backend_pid().await
                            .map_err(|error| ConfigRepoError::Storage(Box::new(error)))?;
                        pid_out.store(pid, Ordering::SeqCst);
                        tx.inject_rollback_timeout()
                            .await
                            .map_err(|error| ConfigRepoError::Storage(Box::new(error)))?;
                        Err::<(), _>(ConfigRepoError::VersionConflict)
                    })
                })
                .await;
                assert!(rollback.is_err());
                assert_eq!(attempts, 1, "RollbackFailed must never replay");
                assert!(case_started.elapsed() <= budget.total() + Duration::from_millis(250));
                assert_eq!(
                    localtx_deadline_stage_count(&handle, LocalTxDeadlineStage::Rollback),
                    before + 1.0
                );
                assert_eq!(
                    localtx_final_status_count(&handle, LocalTxFinalStatus::RollbackFailed),
                    final_before + 1.0
                );
                // Consume this case's notification so a later exact cancellation test cannot
                // observe a stale permit and abort before its own rollback stage is armed.
                crate::cotx::wait_for_rollback_timeout_for_test().await;
                localtx_assert_backend_quarantined(
                    &owner,
                    &app.pool,
                    rollback_pid.load(Ordering::SeqCst),
                    "rollback deadline",
                )
                .await?;

                // Dynamic GUC cap: a residual budget above five seconds keeps statement_timeout
                // inside the client deadline while capping lock_timeout at five seconds.
                let cap_budget = LocalTxExecutionBudget::new(
                    Duration::from_millis(6_200),
                    Duration::from_millis(100),
                )?;
                let (guc_result, attempts) = run_localtx_deadline_write(
                    &scoped,
                    tenant,
                    cap_budget,
                    |tx| {
                        Box::pin(async move {
                            tx.test_local_timeouts().await
                            .map_err(|error| ConfigRepoError::Storage(Box::new(error)))
                        })
                    },
                )
                .await;
                let (statement_ms, lock_ms) = guc_result?;
                assert_eq!(attempts, 1);
                assert!(
                    (5_000..6_100).contains(&statement_ms),
                    "statement timeout must retain the latest >5s residual: {statement_ms}ms"
                );
                assert_eq!(lock_ms, 5_000, "lock timeout must be capped at five seconds");
                Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
            })
        })
    })?;

    assert!(
        started.elapsed() < Duration::from_secs(5),
        "fault matrix exceeded the aggregate elapsed bound: {:?}",
        started.elapsed()
    );
    let rendered = handle.render();
    assert!(
        rendered.contains("localtx_deadline_exceeded_total"),
        "{rendered}"
    );
    for stage in LocalTxDeadlineStage::ALL {
        assert!(
            rendered.contains(&format!("stage=\"{}\"", stage.as_label())),
            "missing deadline stage {}: {rendered}",
            stage.as_label()
        );
    }
    for sensitive in ["tenant_id", "sql", "error", "duration"] {
        assert!(
            !rendered.lines().any(|line| {
                line.starts_with("localtx_deadline_exceeded_total") && line.contains(sensitive)
            }),
            "deadline metric leaked {sensitive}: {rendered}"
        );
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::panic)]
async fn localtx_settlement_connection_policy() -> TestResult {
    use std::sync::atomic::{AtomicI32, AtomicUsize, Ordering};

    use consistency::LocalTxFinalStatus;
    use settings::ports::{ConfigRepoError, TenantRepoScope};

    let (pg, owner) = connect_pg().await?;
    owner.run_migrations().await?;
    let app = connect_pg_rss_app_role_with_limits(&pg, &owner, 1, Duration::from_secs(7)).await?;
    let tenant = vocab::TenantId::parse(&uuid::Uuid::new_v4().to_string())?;
    let scoped = crate::cotx::TenantDb::<ServingWriteLane>::from_unverified_for_test(&app);

    let committed = scoped
        .test_retry_write(
            TenantRepoScope::for_test(tenant),
            crate::tx_retry::localtx_deadline_for_test(),
            |tx| {
                Box::pin(async move {
                    tx.test_backend_pid()
                        .await
                        .map_err(|error| ConfigRepoError::Storage(Box::new(error)))
                })
            },
            |error| ConfigRepoError::Storage(Box::new(error)),
        )
        .await;
    assert_eq!(committed.settlement(), Some(LocalTxFinalStatus::Committed));
    let committed_pid = committed.into_result()?;
    localtx_assert_backend_reused(&app.pool, committed_pid, "commit ack").await?;

    let tenant_b = vocab::TenantId::parse(&uuid::Uuid::new_v4().to_string())?;
    let isolation_key = format!("localtx-cross-tenant-{}", uuid::Uuid::new_v4());
    let tenant_a_id = tenant.to_string();
    let tenant_b_id = tenant_b.to_string();
    let key_for_a = isolation_key.clone();
    let tenant_a_pid = scoped
        .test_retry_write(
            TenantRepoScope::for_test(tenant),
            crate::tx_retry::localtx_deadline_for_test(),
            move |tx| {
                Box::pin(async move {
                    let pid: i32 = tx
                        .test_backend_pid()
                        .await
                        .map_err(|error| ConfigRepoError::Storage(Box::new(error)))?;
                    tx.test_insert_config(&key_for_a, "value-a")
                        .await
                        .map_err(|error| ConfigRepoError::Storage(Box::new(error)))?;
                    Ok(pid)
                })
            },
            |error| ConfigRepoError::Storage(Box::new(error)),
        )
        .await
        .into_result()?;

    let key_for_b = isolation_key.clone();
    let (tenant_b_pid, tenant_b_visible_before_insert) = scoped
        .test_retry_write(
            TenantRepoScope::for_test(tenant_b),
            crate::tx_retry::localtx_deadline_for_test(),
            move |tx| {
                Box::pin(async move {
                    let pid: i32 = tx
                        .test_backend_pid()
                        .await
                        .map_err(|error| ConfigRepoError::Storage(Box::new(error)))?;
                    let visible = tx
                        .test_config_count(&key_for_b)
                        .await
                        .map_err(|error| ConfigRepoError::Storage(Box::new(error)))?;
                    tx.test_insert_config(&key_for_b, "value-b")
                        .await
                        .map_err(|error| ConfigRepoError::Storage(Box::new(error)))?;
                    Ok((pid, visible))
                })
            },
            |error| ConfigRepoError::Storage(Box::new(error)),
        )
        .await
        .into_result()?;
    assert_eq!(
        tenant_b_visible_before_insert, 0,
        "tenant B must not observe tenant A state on a safely reused backend"
    );

    let key_for_a = isolation_key.clone();
    let (tenant_a_return_pid, tenant_a_values) = scoped
        .test_retry_write(
            TenantRepoScope::for_test(tenant),
            crate::tx_retry::localtx_deadline_for_test(),
            move |tx| {
                Box::pin(async move {
                    let pid: i32 = tx
                        .test_backend_pid()
                        .await
                        .map_err(|error| ConfigRepoError::Storage(Box::new(error)))?;
                    let values = tx
                        .test_config_values(&key_for_a)
                        .await
                        .map_err(|error| ConfigRepoError::Storage(Box::new(error)))?;
                    Ok((pid, values))
                })
            },
            |error| ConfigRepoError::Storage(Box::new(error)),
        )
        .await
        .into_result()?;
    assert_eq!(tenant_a_values, ["value-a"]);
    assert_eq!(
        [tenant_a_pid, tenant_b_pid, tenant_a_return_pid],
        [tenant_a_pid; 3],
        "safe A→B→A transactions must rebuild tenant scope on the same backend"
    );
    let durable_rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT tenant_id::text, value FROM config_entries WHERE config_key = $1 ORDER BY value",
    )
    .bind(&isolation_key)
    .fetch_all(&owner.pool)
    .await?;
    assert_eq!(
        durable_rows,
        [
            (tenant_a_id, "value-a".to_owned()),
            (tenant_b_id, "value-b".to_owned()),
        ],
        "owner snapshot must retain one isolated durable value per tenant"
    );

    let rolled_back_pid = Arc::new(AtomicI32::new(0));
    let operation_pid = Arc::clone(&rolled_back_pid);
    let rolled_back = scoped
        .test_retry_write(
            TenantRepoScope::for_test(tenant),
            crate::tx_retry::localtx_deadline_for_test(),
            move |tx| {
                Box::pin(async move {
                    let pid = tx
                        .test_backend_pid()
                        .await
                        .map_err(|error| ConfigRepoError::Storage(Box::new(error)))?;
                    operation_pid.store(pid, Ordering::SeqCst);
                    Err::<(), _>(ConfigRepoError::VersionConflict)
                })
            },
            |error| ConfigRepoError::Storage(Box::new(error)),
        )
        .await;
    assert_eq!(
        rolled_back.settlement(),
        Some(LocalTxFinalStatus::RolledBack)
    );
    assert!(matches!(
        rolled_back.into_result(),
        Err(ConfigRepoError::VersionConflict)
    ));
    localtx_assert_backend_reused(
        &app.pool,
        rolled_back_pid.load(Ordering::SeqCst),
        "rollback ack",
    )
    .await?;

    let backend_pid = Arc::new(AtomicI32::new(0));
    let attempts = Arc::new(AtomicUsize::new(0));
    let operation_pid = Arc::clone(&backend_pid);
    let operation_attempts = Arc::clone(&attempts);

    let attempt = scoped
        .test_retry_write(
            TenantRepoScope::for_test(tenant),
            crate::tx_retry::localtx_deadline_for_test(),
            move |tx| {
                Box::pin(async move {
                    operation_attempts.fetch_add(1, Ordering::SeqCst);
                    let pid = tx
                        .test_backend_pid()
                        .await
                        .map_err(|error| ConfigRepoError::Storage(Box::new(error)))?;
                    operation_pid.store(pid, Ordering::SeqCst);
                    tx.inject_commit_unknown_after_commit()
                        .await
                        .map_err(|error| ConfigRepoError::Storage(Box::new(error)))?;
                    Ok(())
                })
            },
            |error| ConfigRepoError::Storage(Box::new(error)),
        )
        .await;

    assert_eq!(
        attempt.settlement(),
        Some(LocalTxFinalStatus::CommitUnknown)
    );
    assert!(attempt.into_result().is_err());
    assert_eq!(attempts.load(Ordering::SeqCst), 1);
    let old_pid = backend_pid.load(Ordering::SeqCst);
    assert!(old_pid > 0, "LocalTx attempt must acquire a real backend");
    localtx_assert_backend_quarantined(&owner, &app.pool, old_pid, "commit unknown").await?;

    let backend_pid = Arc::new(AtomicI32::new(0));
    let attempts = Arc::new(AtomicUsize::new(0));
    let operation_pid = Arc::clone(&backend_pid);
    let operation_attempts = Arc::clone(&attempts);
    let attempt = scoped
        .test_retry_write(
            TenantRepoScope::for_test(tenant),
            crate::tx_retry::localtx_deadline_for_test(),
            move |tx| {
                Box::pin(async move {
                    operation_attempts.fetch_add(1, Ordering::SeqCst);
                    let pid = tx
                        .test_backend_pid()
                        .await
                        .map_err(|error| ConfigRepoError::Storage(Box::new(error)))?;
                    operation_pid.store(pid, Ordering::SeqCst);
                    tx.inject_rollback_failed_after_rollback()
                        .await
                        .map_err(|error| ConfigRepoError::Storage(Box::new(error)))?;
                    Err::<(), _>(ConfigRepoError::VersionConflict)
                })
            },
            |error| ConfigRepoError::Storage(Box::new(error)),
        )
        .await;
    assert_eq!(
        attempt.settlement(),
        Some(LocalTxFinalStatus::RollbackFailed)
    );
    assert!(matches!(
        attempt.into_result(),
        Err(ConfigRepoError::Storage(_))
    ));
    assert_eq!(attempts.load(Ordering::SeqCst), 1);
    localtx_assert_backend_quarantined(
        &owner,
        &app.pool,
        backend_pid.load(Ordering::SeqCst),
        "rollback failed",
    )
    .await?;

    let backend_pid = Arc::new(AtomicI32::new(0));
    let attempts = Arc::new(AtomicUsize::new(0));
    let operation_pid = Arc::clone(&backend_pid);
    let operation_attempts = Arc::clone(&attempts);
    let (body_entered_tx, body_entered_rx) = tokio::sync::oneshot::channel();
    let cancellation_scoped =
        crate::cotx::TenantDb::<ServingWriteLane>::from_unverified_for_test(&app);
    let cancelled = tokio::spawn(async move {
        cancellation_scoped
            .test_retry_write(
                TenantRepoScope::for_test(tenant),
                crate::tx_retry::localtx_deadline_for_test(),
                move |tx| {
                    Box::pin(async move {
                        operation_attempts.fetch_add(1, Ordering::SeqCst);
                        let pid = tx
                            .test_backend_pid()
                            .await
                            .map_err(|error| ConfigRepoError::Storage(Box::new(error)))?;
                        operation_pid.store(pid, Ordering::SeqCst);
                        let _ = body_entered_tx.send(());
                        std::future::pending::<Result<(), ConfigRepoError>>().await
                    })
                },
                |error| ConfigRepoError::Storage(Box::new(error)),
            )
            .await
    });
    tokio::time::timeout(Duration::from_secs(5), body_entered_rx).await??;
    cancelled.abort();
    assert!(
        cancelled.await.is_err_and(|error| error.is_cancelled()),
        "pending LocalTx body must be cancelled after entering the target stage"
    );
    assert_eq!(attempts.load(Ordering::SeqCst), 1);
    localtx_assert_backend_quarantined(
        &owner,
        &app.pool,
        backend_pid.load(Ordering::SeqCst),
        "body cancellation",
    )
    .await?;

    let backend_pid = Arc::new(AtomicI32::new(0));
    let operation_pid = Arc::clone(&backend_pid);
    let panic_scoped = crate::cotx::TenantDb::<ServingWriteLane>::from_unverified_for_test(&app);
    let panicked = tokio::spawn(async move {
        panic_scoped
            .test_retry_write(
                TenantRepoScope::for_test(tenant),
                crate::tx_retry::localtx_deadline_for_test(),
                move |tx| {
                    Box::pin(async move {
                        let pid = tx
                            .test_backend_pid()
                            .await
                            .map_err(|error| ConfigRepoError::Storage(Box::new(error)))?;
                        operation_pid.store(pid, Ordering::SeqCst);
                        panic!("synthetic LocalTx body panic");
                        #[allow(unreachable_code)]
                        Ok::<(), ConfigRepoError>(())
                    })
                },
                |error| ConfigRepoError::Storage(Box::new(error)),
            )
            .await
    })
    .await;
    assert!(
        panicked.is_err_and(|error| error.is_panic()),
        "LocalTx body panic must unwind the armed lease"
    );
    localtx_assert_backend_quarantined(
        &owner,
        &app.pool,
        backend_pid.load(Ordering::SeqCst),
        "body panic",
    )
    .await?;

    let backend_pid = Arc::new(AtomicI32::new(0));
    let attempts = Arc::new(AtomicUsize::new(0));
    let operation_pid = Arc::clone(&backend_pid);
    let operation_attempts = Arc::clone(&attempts);
    let rollback_timeout_seam = crate::cotx::lock_rollback_timeout_seam_for_test().await;
    let rollback_scoped = crate::cotx::TenantDb::<ServingWriteLane>::from_unverified_for_test(&app);
    let rollback_timeout = tokio::spawn(async move {
        rollback_scoped
            .test_retry_write(
                TenantRepoScope::for_test(tenant),
                crate::tx_retry::localtx_deadline_for_test(),
                move |tx| {
                    Box::pin(async move {
                        operation_attempts.fetch_add(1, Ordering::SeqCst);
                        let pid = tx
                            .test_backend_pid()
                            .await
                            .map_err(|error| ConfigRepoError::Storage(Box::new(error)))?;
                        operation_pid.store(pid, Ordering::SeqCst);
                        tx.inject_rollback_timeout()
                            .await
                            .map_err(|error| ConfigRepoError::Storage(Box::new(error)))?;
                        Err::<(), _>(ConfigRepoError::VersionConflict)
                    })
                },
                |error| ConfigRepoError::Storage(Box::new(error)),
            )
            .await
    });
    tokio::time::timeout(
        Duration::from_secs(5),
        crate::cotx::wait_for_rollback_timeout_for_test(),
    )
    .await?;
    rollback_timeout.abort();
    assert!(
        rollback_timeout
            .await
            .is_err_and(|error| error.is_cancelled()),
        "rollback must be cancelled after entering the no-ack stage"
    );
    assert_eq!(attempts.load(Ordering::SeqCst), 1);
    localtx_assert_backend_quarantined(
        &owner,
        &app.pool,
        backend_pid.load(Ordering::SeqCst),
        "rollback timeout",
    )
    .await?;
    drop(rollback_timeout_seam);

    let occurred_at = i64::try_from(TEST_OCCURRED_SECS)?;
    let contract = settings::ports::CONFIG_VERSION_CHANGED_CONTRACT;
    let entry = config_outbox_entry(&unique_event_id("localtx-co-tx-commit"));
    let env = OutboxEnvelope::new(
        contract.domain().to_owned(),
        contract.contract_id().to_owned(),
        OutboxMetadata::new(occurred_at, tenant, contract)
            .with_subject_id(subject_id("localtx-co-tx-commit")),
    );
    let co_tx_pid = Arc::new(AtomicI32::new(0));
    let operation_pid = Arc::clone(&co_tx_pid);
    let authorization = settings::config_publish_receipt_for_test()
        .authorize(
            generated::event::settings_v1::FACT,
            settings::ports::CONFIG_VERSION_CHANGED_CONTRACT,
        )
        .ok_or_else(|| std::io::Error::other("config producer authorization missing"))?;
    let attempt = scoped
        .test_retry_producer_tx(
            settings_scope(tenant),
            crate::tx_retry::localtx_deadline_for_test(),
            &entry,
            &env,
            move |tx| {
                Box::pin(async move {
                    let pid = tx
                        .test_backend_pid()
                        .await
                        .map_err(|error| ConfigRepoError::Storage(Box::new(error)))?;
                    operation_pid.store(pid, Ordering::SeqCst);
                    Ok(crate::cotx::ProducerTxOutcome::Emitted((), authorization))
                })
            },
            |error| ConfigRepoError::Storage(Box::new(error)),
        )
        .await;
    assert_eq!(attempt.settlement(), Some(LocalTxFinalStatus::Committed));
    attempt.into_result()?;
    localtx_assert_backend_reused(
        &app.pool,
        co_tx_pid.load(Ordering::SeqCst),
        "co-tx commit ack",
    )
    .await?;

    let contract = settings::ports::CONFIG_VERSION_CHANGED_CONTRACT;
    let entry = config_outbox_entry(&unique_event_id("localtx-co-tx-unknown"));
    let env = OutboxEnvelope::new(
        contract.domain().to_owned(),
        contract.contract_id().to_owned(),
        OutboxMetadata::new(occurred_at, tenant, contract)
            .with_subject_id(subject_id("localtx-co-tx-unknown")),
    );
    let co_tx_pid = Arc::new(AtomicI32::new(0));
    let operation_pid = Arc::clone(&co_tx_pid);
    let authorization = settings::config_publish_receipt_for_test()
        .authorize(
            generated::event::settings_v1::FACT,
            settings::ports::CONFIG_VERSION_CHANGED_CONTRACT,
        )
        .ok_or_else(|| std::io::Error::other("config producer authorization missing"))?;
    let attempt = scoped
        .test_retry_producer_tx(
            settings_scope(tenant),
            crate::tx_retry::localtx_deadline_for_test(),
            &entry,
            &env,
            move |tx| {
                Box::pin(async move {
                    let pid = tx
                        .test_backend_pid()
                        .await
                        .map_err(|error| ConfigRepoError::Storage(Box::new(error)))?;
                    operation_pid.store(pid, Ordering::SeqCst);
                    tx.inject_commit_unknown_after_commit()
                        .await
                        .map_err(|error| ConfigRepoError::Storage(Box::new(error)))?;
                    Ok(crate::cotx::ProducerTxOutcome::Emitted((), authorization))
                })
            },
            |error| ConfigRepoError::Storage(Box::new(error)),
        )
        .await;
    assert_eq!(
        attempt.settlement(),
        Some(LocalTxFinalStatus::CommitUnknown)
    );
    assert!(attempt.into_result().is_err());
    localtx_assert_backend_quarantined(
        &owner,
        &app.pool,
        co_tx_pid.load(Ordering::SeqCst),
        "co-tx commit unknown",
    )
    .await?;

    app.shutdown().await?;
    owner.shutdown().await?;
    Ok(())
}

/// policy L2 co-tx：policy 行写入后若事务失败，policy 与 outbox 必须一起回滚。
#[tokio::test(flavor = "multi_thread")]
async fn policy_repo_cotx_rolls_back_policy_and_outbox() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let tenant = role_tenant(ROLE_TENANT_A)?;
    let tenant_pool = TenantDb::<ServingWriteLane>::from_unverified_for_test(&store);
    let policy = policy_fixture(
        "policy-cotx-rollback",
        tenant,
        1,
        10,
        None,
        PolicyEffect::Allow,
        PolicyObligations::empty(),
    )?;
    let rules_json = principal_kind_rule_json(r#"{"kind":"eq","value":"admin"}"#);
    let event_id = unique_event_id("policy-cotx-rollback");
    let (entry, _) = policy_lifecycle_event_with_id(
        tenant,
        "policy-cotx-rollback",
        "created",
        policy_version(1)?,
        &event_id,
    )?;
    let env = OutboxEnvelope::new(
        POLICY_UPDATED_CONTRACT.domain().to_string(),
        POLICY_UPDATED_CONTRACT.contract_id().to_string(),
        OutboxMetadata::new(expected_occurred_at(), tenant, POLICY_UPDATED_CONTRACT)
            .with_subject_id(subject_id("policy-cotx-rollback")),
    );

    let result = tenant_pool
        .identity_producer_tx(
            identity_scope(tenant),
            &entry,
            &env,
            move |mut conn| {
                Box::pin(async move {
                    let inserted = conn.identity().create_policy(&policy, &rules_json).await?;
                    if inserted != 1 {
                        return Err(IdentityError::PolicyAlreadyExists);
                    }
                    Err::<
                        crate::cotx::ProducerTxOutcome<
                            httpserve::ProducerAuthorization<
                                generated::http::identity_v1::policies_create::RouteMarker,
                            >,
                            (),
                        >,
                        IdentityError,
                    >(IdentityError::VersionConflict)
                })
            },
            |e| IdentityError::Storage(Box::new(e)),
        )
        .await
        .into_result();
    assert!(
        matches!(result, Err(IdentityError::VersionConflict)),
        "forced business failure must bubble"
    );

    let policy_count: (i64,) = sqlx::query_as("SELECT count(*) FROM abac_policies WHERE id = $1")
        .bind("policy-cotx-rollback")
        .fetch_one(&store.pool)
        .await?;
    assert_eq!(policy_count.0, 0, "rolled back policy row must not exist");
    assert!(
        !policy_outbox_exists(&store, &event_id).await?,
        "rolled back transaction must not write outbox"
    );

    store.shutdown().await?;
    Ok(())
}
