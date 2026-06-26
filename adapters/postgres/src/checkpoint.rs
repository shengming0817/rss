//! PostgreSQL checkpoint store adapter（CAS 版本控制，#1121）。
//!
//! [`PgCheckpointStore`] impl [`diport::OwnerCheckpointStore`]——native AFIT（泛型静态分发或
//! `Box<DynOwnerCheckpointStore>` 组合根注入）。
//!
//! **CAS 语义**：`save_checkpoint` 以 `expected` 版本比对存储版本——
//! - `expected == CheckpointVersion::INITIAL`（首存）：`INSERT ... ON CONFLICT DO NOTHING`，
//!   `rows_affected == 1` → `Saved`，`0` → `StaleVersion`（行已存在，版本竞争）。
//! - 否则：`UPDATE ... WHERE version = $expected`，`rows_affected == 1` → `Saved`，
//!   `0` → `StaleVersion`（版本不符）。
//!
//! ref: outbox `UPDATE ... WHERE ... AND ... RETURNING; rows_affected()==1` CAS idiom。
//!
//! **时间戳**：`updated_at` 用 DB DEFAULT `now()`（不注入 Clock，时间源保持 DB 端单一）。
//!
//! **错误 PII 边界**：sqlx 错误不进 Display——经 [`diport::CheckpointStoreError::new`] 包成
//! source（error-handling.md §Message 与 PII）。

use diport::{
    Checkpoint, CheckpointId, CheckpointOwner, CheckpointStoreError, CheckpointVersion,
    OwnerCheckpointStore, SaveOutcome,
};
use sqlx::PgPool;

use consistency::Lsn;

use crate::PgStore;

/// PostgreSQL checkpoint store adapter（CAS 版本控制）。
///
/// 持 `PgPool`（clone 自 [`PgStore`]，池共用 `ManagedResource::shutdown` 统一关）。
/// 经 [`crate::PgInfraDeps::checkpoint`] 构造（`PgStore::checkpoint` 为 `pub(crate)` funnel）。
pub struct PgCheckpointStore {
    pool: PgPool,
}

impl PgStore {
    /// 构造 [`PgCheckpointStore`]（pool clone 自 `PgStore`，轻量）。
    ///
    /// `pub(crate)`（#1423，PG-BUNDLE-FUNNEL-01）：经 [`crate::PgInfraDeps::checkpoint`] 收口。
    pub(crate) fn checkpoint(&self) -> PgCheckpointStore {
        PgCheckpointStore {
            pool: self.pool.clone(),
        }
    }
}

impl OwnerCheckpointStore for PgCheckpointStore {
    /// 读 `(owner, id)` 当前 checkpoint。`None` ⇒ 从未保存。
    ///
    /// sqlx 错误不进 Display——经 [`CheckpointStoreError::new`] 包成 source（PII 边界）。
    async fn get_checkpoint(
        &self,
        owner: &CheckpointOwner,
        id: &CheckpointId,
    ) -> Result<Option<Checkpoint>, CheckpointStoreError> {
        let row: Option<(i64, i64)> = sqlx::query_as(
            r#"
            SELECT offset_lsn, version
            FROM checkpoint
            WHERE owner = $1 AND checkpoint_id = $2
            "#,
        )
        .bind(owner.as_str())
        .bind(id.as_str())
        .fetch_optional(&self.pool)
        .await
        .map_err(CheckpointStoreError::new)?;

        match row {
            None => Ok(None),
            Some((offset_lsn, version)) => {
                let offset =
                    Lsn::new(u64::try_from(offset_lsn).map_err(CheckpointStoreError::new)?);
                let version = CheckpointVersion::new(
                    u64::try_from(version).map_err(CheckpointStoreError::new)?,
                );
                Ok(Some(Checkpoint { offset, version }))
            }
        }
    }

    /// CAS 保存：仅当存储版本 == `expected` 时成功；`expected == CheckpointVersion::INITIAL` 表首存。
    ///
    /// 两分支均以 `rows_affected() == 1` 判定 [`SaveOutcome::Saved`]，否则 [`SaveOutcome::StaleVersion`]。
    /// sqlx 错误不进 Display——经 [`CheckpointStoreError::new`] 包成 source（PII 边界）。
    async fn save_checkpoint(
        &self,
        owner: &CheckpointOwner,
        id: &CheckpointId,
        offset: Lsn,
        expected: CheckpointVersion,
    ) -> Result<SaveOutcome, CheckpointStoreError> {
        let offset_lsn = i64::try_from(offset.get()).map_err(CheckpointStoreError::new)?;

        let rows_affected = if expected == CheckpointVersion::INITIAL {
            // 首存分支：INSERT ON CONFLICT DO NOTHING（行不存在 → Saved；已存在 → StaleVersion）。
            sqlx::query(
                r#"
                INSERT INTO checkpoint (owner, checkpoint_id, offset_lsn, version)
                VALUES ($1, $2, $3, 1)
                ON CONFLICT (owner, checkpoint_id) DO NOTHING
                "#,
            )
            .bind(owner.as_str())
            .bind(id.as_str())
            .bind(offset_lsn)
            .execute(&self.pool)
            .await
            .map_err(CheckpointStoreError::new)?
            .rows_affected()
        } else {
            // 更新分支：WHERE version = expected → rows_affected==1 表 CAS 命中。
            let expected_ver = i64::try_from(expected.get()).map_err(CheckpointStoreError::new)?;
            sqlx::query(
                r#"
                UPDATE checkpoint
                SET offset_lsn = $3,
                    version = version + 1,
                    updated_at = now()
                WHERE owner = $1
                  AND checkpoint_id = $2
                  AND version = $4
                "#,
            )
            .bind(owner.as_str())
            .bind(id.as_str())
            .bind(offset_lsn)
            .bind(expected_ver)
            .execute(&self.pool)
            .await
            .map_err(CheckpointStoreError::new)?
            .rows_affected()
        };

        if rows_affected == 1 {
            Ok(SaveOutcome::Saved)
        } else {
            Ok(SaveOutcome::StaleVersion)
        }
    }

    /// 释放资源（pool 由 `PgStore` 统一管理；此处 no-op）。
    ///
    // reason: pool 的 `close()` 由 `PgStore::shutdown`（impl `ManagedResource`）经
    // `bootstrap::ShutdownStack` 逆序编排统一关闭；`PgCheckpointStore` 自身无额外 infra 资源。
    async fn shutdown(&self) -> Result<(), CheckpointStoreError> {
        Ok(())
    }
}

// ── 单测 ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod smoke {
    //! 编译期类型证明：`PgCheckpointStore: OwnerCheckpointStore`（via trait bound）。
    //! INVARIANT: ADAPTER-PORT-FREEZE-09 —— OwnerCheckpointStore on PgCheckpointStore；
    //! 去掉 impl 即编译失败（anti-vacuity）。
    use core::marker::PhantomData;

    use diport::OwnerCheckpointStore;

    fn assert_checkpoint_store<T: OwnerCheckpointStore>(_: PhantomData<T>) {}

    #[test]
    fn pg_checkpoint_store_impl_frozen() {
        assert_checkpoint_store(PhantomData::<super::PgCheckpointStore>);
    }
}

/// 集成测试：`PgCheckpointStore` CAS 语义验证（`integration` feature 门控；需真实 postgres）。
#[cfg(all(test, feature = "integration"))]
mod integration_tests {
    use diport::{
        CheckpointId, CheckpointOwner, CheckpointVersion, ManagedResource, OwnerCheckpointStore,
        SaveOutcome,
    };

    use consistency::Lsn;

    type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

    /// CAS 语义验证：
    /// 1. save v0（首存）→ Saved；
    /// 2. update expected=1（版本 1）→ Saved（版本推进到 2）；
    /// 3. update expected=1 再次（旧版本）→ StaleVersion。
    #[tokio::test(flavor = "multi_thread")]
    #[allow(clippy::unwrap_used)]
    // reason: 集成测试 happy-path，已知合法值构造；item-level carve-out（error-handling.md §Carve-out）。
    async fn checkpoint_cas_rejects_stale_version() -> TestResult {
        let (_pg, store) = crate::test_pg::connect_pg().await?;
        store.run_migrations().await?;

        let cp = store.checkpoint();
        // 唯一 owner/id 防测试间污染。
        let owner = CheckpointOwner::new(format!("test-owner-{}", uuid::Uuid::new_v4()));
        let id = CheckpointId::new("saga-checkpoint-1");

        // 首次 get → None（无既存行）。
        assert!(
            cp.get_checkpoint(&owner, &id).await?.is_none(),
            "首次 get 应为 None"
        );

        // save v0 → Saved（首存）。
        let outcome = cp
            .save_checkpoint(&owner, &id, Lsn::new(10), CheckpointVersion::new(0))
            .await?;
        assert_eq!(outcome, SaveOutcome::Saved, "首存应 Saved");

        // get → Some(offset=10, version=1)。
        let ck = cp.get_checkpoint(&owner, &id).await?.unwrap();
        assert_eq!(ck.offset.get(), 10, "offset 应为 10");
        assert_eq!(ck.version.get(), 1, "首存后版本应为 1");

        // update expected=1（当前版本）→ Saved（版本推进到 2）。
        let outcome2 = cp
            .save_checkpoint(&owner, &id, Lsn::new(20), CheckpointVersion::new(1))
            .await?;
        assert_eq!(outcome2, SaveOutcome::Saved, "正确版本应 Saved");

        // get → Some(offset=20, version=2)。
        let ck2 = cp.get_checkpoint(&owner, &id).await?.unwrap();
        assert_eq!(ck2.offset.get(), 20, "更新后 offset 应为 20");
        assert_eq!(ck2.version.get(), 2, "更新后版本应为 2");

        // update expected=1（旧版本）→ StaleVersion（CAS 拒绝）。
        let outcome3 = cp
            .save_checkpoint(&owner, &id, Lsn::new(30), CheckpointVersion::new(1))
            .await?;
        assert_eq!(outcome3, SaveOutcome::StaleVersion, "旧版本应 StaleVersion");

        // 旧版本被拒后行未变（offset 仍 20，version 仍 2）。
        let ck3 = cp.get_checkpoint(&owner, &id).await?.unwrap();
        assert_eq!(ck3.offset.get(), 20, "StaleVersion 后 offset 不变");
        assert_eq!(ck3.version.get(), 2, "StaleVersion 后版本不变");

        cp.shutdown().await?;
        store.shutdown().await?;
        Ok(())
    }
}
