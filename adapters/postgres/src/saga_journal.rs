//! PostgreSQL saga journal adapter（append-only，#1121）。
//!
//! [`PgSagaJournal`] impl [`diport::SagaJournal`]——native AFIT（泛型静态分发或
//! `Box<DynSagaJournal>` 组合根注入）。
//!
//! **append 幂等**：`INSERT ... ON CONFLICT (saga_id, seq) DO NOTHING`——崩溃后重 append
//! 同 `(saga_id, seq)` 行安全 no-op。
//!
//! **read 路径**：只回传 `seq`/`step_name`/`status`，不 SELECT `error_summary`
//! （resume 不需要 runtime summary；见 `diport::saga_journal` 模块 doc）。
//!
//! **时间戳**：`occurred_at` 用 DB DEFAULT `now()`（不注入 Clock，时间源保持 DB 端单一，
//! 与 outbox/inbox 同范式）。
//!
//! **错误 PII 边界**：sqlx 错误不进 Display——经 [`diport::SagaJournalError::new`] 包成
//! source（error-handling.md §Message 与 PII）。

use consistency::{
    SagaId, SagaJournalAppendRecord, SagaJournalRecord, SagaJournalStatus, StepName,
};
use diport::{SagaJournal, SagaJournalError};
use sqlx::PgPool;

use crate::PgStore;

/// PostgreSQL saga journal adapter（append-only）。
///
/// 持 `PgPool`（clone 自 [`PgStore`]，池共用 `ManagedResource::shutdown` 统一关）。
/// 经 [`crate::PgInfraDeps::saga_journal`] 构造（`PgStore::saga_journal` 为 `pub(crate)` funnel）。
pub struct PgSagaJournal {
    pool: PgPool,
}

impl PgStore {
    /// 构造 [`PgSagaJournal`]（pool clone 自 `PgStore`，轻量）。
    ///
    /// `pub(crate)`（#1423，PG-BUNDLE-FUNNEL-01）：经 [`crate::PgInfraDeps::saga_journal`] 收口。
    pub(crate) fn saga_journal(&self) -> PgSagaJournal {
        PgSagaJournal {
            pool: self.pool.clone(),
        }
    }
}

impl SagaJournal for PgSagaJournal {
    /// 追加一条 journal 记录（幂等：同 `(saga_id, seq)` 重 append → no-op）。
    ///
    /// `occurred_at` 走 DB DEFAULT `now()`；`error_summary` 落库供运维巡检（const literal，安全）。
    /// step output **不持久化**——DB 无 output 列（零信任，PII 边界）。
    /// sqlx 错误不进 Display——经 [`SagaJournalError::new`] 包成 source（PII 边界）。
    async fn append(
        &self,
        saga_id: &SagaId,
        entry: SagaJournalAppendRecord,
    ) -> Result<(), SagaJournalError> {
        // uuid 经 `.to_string()` 作 text 传入 postgres，server-side 隐式转 uuid 列类型（不给 sqlx 加 uuid feature）。
        let saga_id_str = saga_id.as_uuid().to_string();
        sqlx::query(
            r#"
            INSERT INTO saga_journal (saga_id, seq, step_name, status, error_summary)
            VALUES ($1::uuid, $2, $3, $4, $5)
            ON CONFLICT (saga_id, seq) DO NOTHING
            "#,
        )
        .bind(&saga_id_str)
        .bind(i64::try_from(entry.seq()).map_err(SagaJournalError::new)?)
        .bind(entry.step_name().as_str())
        .bind(entry.status().as_str())
        .bind(entry.error_summary())
        .execute(&self.pool)
        .await
        .map_err(SagaJournalError::new)?;

        Ok(())
    }

    /// 读某 saga 全部 journal 条目，按 `seq` 升序（resume 重建栈用）。
    ///
    /// 回传条目的 `error_summary` 恒 `None`——resume 不需要 runtime summary
    /// （见 `diport::saga_journal` 模块 doc）。parse/convert 失败（我们写入的数据不该无效）
    /// → [`SagaJournalError`]（Invariant 类型错误，不 unwrap）。
    async fn read(&self, saga_id: &SagaId) -> Result<Vec<SagaJournalRecord>, SagaJournalError> {
        let saga_id_str = saga_id.as_uuid().to_string();
        let rows: Vec<(i64, String, String)> = sqlx::query_as(
            r#"
            SELECT seq, step_name, status
            FROM saga_journal
            WHERE saga_id = $1::uuid
            ORDER BY seq ASC
            "#,
        )
        .bind(&saga_id_str)
        .fetch_all(&self.pool)
        .await
        .map_err(SagaJournalError::new)?;

        rows.into_iter()
            .map(|(seq_i64, step_str, status_str)| {
                let seq = u64::try_from(seq_i64).map_err(SagaJournalError::new)?;
                let step_name = StepName::parse(&step_str).map_err(|_| {
                    SagaJournalError::new(InvariantError("invalid step_name in saga_journal"))
                })?;
                let status = SagaJournalStatus::parse(&status_str).ok_or_else(|| {
                    SagaJournalError::new(InvariantError("invalid status in saga_journal"))
                })?;
                Ok(SagaJournalRecord::replayed(seq, step_name, status))
            })
            .collect()
    }

    /// 释放资源（pool 由 `PgStore` 统一管理；此处 no-op）。
    ///
    // reason: pool 的 `close()` 由 `PgStore::shutdown`（impl `ManagedResource`）经
    // `bootstrap::ShutdownStack` 逆序编排统一关闭；`PgSagaJournal` 自身无额外 infra 资源。
    async fn shutdown(&self) -> Result<(), SagaJournalError> {
        Ok(())
    }
}

// ── internal error helper ─────────────────────────────────────────────────────

/// Invariant parse 失败（`step_name` / `status` 无法从 DB 值解析）——我们写入的数据不该
/// 含无效值；进 [`SagaJournalError::new`] source，不 unwrap。
#[derive(Debug)]
struct InvariantError(&'static str);

impl std::fmt::Display for InvariantError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for InvariantError {}

// ── 单测 ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod smoke {
    //! 编译期类型证明：`PgSagaJournal: SagaJournal`（via trait bound）。
    //! INVARIANT: ADAPTER-PORT-FREEZE-08 { level = "Medium", exec = "manual/opt-in", source = "code" }—— SagaJournal on PgSagaJournal；
    //! 去掉 impl 即编译失败（anti-vacuity）。
    use core::marker::PhantomData;

    use diport::SagaJournal;

    fn assert_saga_journal<T: SagaJournal>(_: PhantomData<T>) {}

    #[test]
    fn pg_saga_journal_impl_frozen() {
        assert_saga_journal(PhantomData::<super::PgSagaJournal>);
    }

    // F8 anti-vacuity：解析 0006 migration 的 `CHECK (status IN (...))` 子句，断言与
    // `SagaJournalStatus::ALL.map(|s| s.as_str())` 集合同源（两处任一漂移即红）。
    // 集合相等比较隐式覆盖「五常量互异」——migration 五值互异，若两常量重复则集合不等而失败。
    #[test]
    #[allow(clippy::expect_used)]
    // reason: 测试解析编译期 include_str! 的已知 migration 文本，CHECK 子句缺失即应 fail；
    // item-level carve-out（error-handling.md §Carve-out）。
    fn saga_journal_status_consts_match_migration_check() {
        const MIGRATION: &str = include_str!("../migrations/0007_create_saga_journal.sql");
        let in_pos = MIGRATION
            .find("status IN (")
            .expect("migration must declare status CHECK IN clause");
        let rest = &MIGRATION[in_pos..];
        let open = rest.find('(').expect("IN clause needs '('");
        let close = rest.find(')').expect("IN clause needs ')'");
        let mut migration_values: Vec<&str> = rest[open + 1..close]
            .split(',')
            .map(|s| s.trim().trim_matches('\''))
            .collect();
        migration_values.sort_unstable();

        let mut port_values: Vec<&str> = consistency::SagaJournalStatus::ALL
            .map(|s| s.as_str())
            .to_vec();
        port_values.sort_unstable();

        assert_eq!(
            migration_values, port_values,
            "saga_journal status 集与 migration 0004 CHECK 漂移"
        );
    }
}

/// 集成测试：`PgSagaJournal` append → read 往返（`integration` feature 门控；需真实 postgres）。
#[cfg(all(test, feature = "integration"))]
mod integration_tests {
    use consistency::{SagaId, SagaJournalAppendRecord, SagaJournalStatus, StepName};
    use diport::{ManagedResource, SagaJournal};

    type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

    /// append 7 条 entry（含全部 5 个 migration-CHECK status 值：
    /// Executing/Completed/Compensating/Compensated/Failed），read 回来按 seq 升序，
    /// 断言 step_name/status 往返正确；重 append 同 (saga_id, seq) 是 no-op（幂等）。
    #[tokio::test(flavor = "multi_thread")]
    #[allow(clippy::unwrap_used)]
    // reason: 集成测试 happy-path，已知合法值构造；item-level carve-out（error-handling.md §Carve-out）。
    async fn saga_journal_append_read_roundtrip() -> TestResult {
        let (_pg, store) = crate::test_pg::connect_pg().await?;
        store.run_migrations().await?;

        let journal = store.saga_journal();
        let saga_id = SagaId::new(uuid::Uuid::new_v4());

        // 7 步覆盖全部 5 个 migration-CHECK status 值（含 Failed）。
        let steps = [
            ("reserve_funds", SagaJournalStatus::Executing),
            ("reserve_funds", SagaJournalStatus::Completed),
            ("charge_card", SagaJournalStatus::Executing),
            ("charge_card", SagaJournalStatus::Completed),
            ("charge_card", SagaJournalStatus::Compensating),
            ("charge_card", SagaJournalStatus::Compensated),
            ("charge_card", SagaJournalStatus::Failed),
        ];

        for (i, (step, status)) in steps.iter().enumerate() {
            let step_name = StepName::parse(step).unwrap();
            let entry = match *status {
                SagaJournalStatus::Executing => {
                    SagaJournalAppendRecord::executing(i as u64, step_name)
                }
                SagaJournalStatus::Completed => {
                    SagaJournalAppendRecord::completed(i as u64, step_name)
                }
                SagaJournalStatus::Compensating => {
                    SagaJournalAppendRecord::compensating(i as u64, step_name)
                }
                SagaJournalStatus::Compensated => {
                    SagaJournalAppendRecord::compensated(i as u64, step_name)
                }
                SagaJournalStatus::Failed => {
                    SagaJournalAppendRecord::failed(i as u64, step_name, "compensation failed")
                }
                _ => return Err(format!("unexpected saga status in fixture: {status:?}").into()),
            };
            journal.append(&saga_id, entry).await?;
        }

        // read back，验证 seq 顺序 + step_name/status 往返。
        let entries = journal.read(&saga_id).await?;
        assert_eq!(entries.len(), 7, "should have 7 entries");
        for (i, (expected_step, expected_status)) in steps.iter().enumerate() {
            assert_eq!(entries[i].seq(), i as u64, "seq mismatch at {i}");
            assert_eq!(
                entries[i].step_name().as_str(),
                *expected_step,
                "step_name mismatch at {i}"
            );
            assert_eq!(
                entries[i].status(),
                *expected_status,
                "status mismatch at {i}"
            );
            // read record 类型不暴露 runtime-only error_summary；resume 只消费 seq/step/status。
        }

        // 重 append 同 (saga_id, seq=0) → no-op（幂等）。
        let step_name = StepName::parse("reserve_funds").unwrap();
        let dup_entry = SagaJournalAppendRecord::executing(0, step_name);
        journal.append(&saga_id, dup_entry).await?; // must not error
        let entries2 = journal.read(&saga_id).await?;
        assert_eq!(entries2.len(), 7, "re-append must be no-op (idempotent)");

        journal.shutdown().await?;
        store.shutdown().await?;
        Ok(())
    }
}
