//! PostgreSQL 死信持久化 adapter（DLX，#1120）。
//!
//! [`PgDeadLetterStore`] impl [`diport::DeadLetterStore`]——native AFIT（泛型静态分发或
//! `Box<DynDeadLetterStore>` 组合根注入）。
//!
//! **immutable append**：只 INSERT，不 UPDATE / DELETE。死信记录是不可变审计物料，运维经
//! SELECT 巡检，不修改原记录。
//!
//! **`original_entry` jsonb** 存 `{"bytes": [u8, ...]}` —— JSON 数字数组完整保留原始
//! payload 字节供重放 / 巡检，往返无损，仅用已有的 `serde_json`（不引入额外 base64 依赖）。
//! PII 保留策略属后续治理（backlog 跟踪）；此处不脱敏，完整存入。
//!
//! **时间戳**：`first_attempt_at` / `last_attempt_at` 用 DB DEFAULT `now()`（不注入 Clock，
//! 与 outbox/inbox 同范式：时间源保持 DB 端单一，无跨进程偏移）。
//!
//! **错误 PII 边界**：sqlx 错误不进 Display（经 `DeadLetterStoreError::new` 包成 source，
//! `error-handling.md §Message 与 PII`）。

use diport::{DeadLetterRecord, DeadLetterStore, DeadLetterStoreError};
use sqlx::PgPool;

use crate::PgStore;
use crate::cotx::set_local_tenant;

/// PostgreSQL 死信写入 adapter。
///
/// 持 `PgPool`（clone 自 [`PgStore`]，池共用 `ManagedResource::shutdown` 统一关）。
/// 经 [`crate::PgInfraDeps::dead_letter`] 构造（`PgStore::dead_letter` 为 `pub(crate)` funnel）。
pub struct PgDeadLetterStore {
    pool: PgPool,
}

impl PgStore {
    /// 构造 [`PgDeadLetterStore`]（pool clone 自 `PgStore`，轻量）。
    ///
    /// `pub(crate)`（#1423，PG-BUNDLE-FUNNEL-01）：经 [`crate::PgInfraDeps::dead_letter`] 收口。
    pub(crate) fn dead_letter(&self) -> PgDeadLetterStore {
        PgDeadLetterStore {
            pool: self.pool.clone(),
        }
    }
}

impl DeadLetterStore for PgDeadLetterStore {
    /// 持久化一条死信记录（immutable INSERT，不更新已有行）。
    ///
    /// `original_entry` 存为 jsonb：`{"bytes": [u8, ...]}`（JSON 数字数组）以无损往返原始字节。
    /// 时间戳 `first_attempt_at` / `last_attempt_at` 均走 DB DEFAULT `now()`。
    /// sqlx 错误不进 Display——经 [`DeadLetterStoreError::new`] 包成 source（PII 边界）。
    async fn write_dead_letter(
        &self,
        record: DeadLetterRecord,
    ) -> Result<(), DeadLetterStoreError> {
        // 存为 {"bytes": [u8, ...]} JSON 数组——完整往返原始字节，只用已有 serde_json，不引入 base64 依赖。
        let bytes_arr: Vec<serde_json::Value> = record
            .original_payload()
            .iter()
            .map(|&b| serde_json::Value::Number(b.into()))
            .collect();
        let original_entry = serde_json::json!({"bytes": bytes_arr});

        let mut tx = self.pool.begin().await.map_err(DeadLetterStoreError::new)?;
        set_local_tenant(&mut tx, record.tenant())
            .await
            .map_err(DeadLetterStoreError::new)?;

        sqlx::query(
            r#"
            INSERT INTO dead_letter
                (tenant_id, message_id, domain, contract_id, topic, original_entry, error_summary, num_attempts)
            VALUES ($1::uuid, $2, $3, $4, $5, $6, $7, $8)
            "#,
        )
        .bind(record.tenant().to_string())
        .bind(record.message_id())
        .bind(record.domain())
        .bind(record.contract_id())
        .bind(record.topic())
        .bind(sqlx::types::Json(&original_entry))
        .bind(record.error_summary())
        .bind(i32::try_from(record.num_attempts()).unwrap_or(i32::MAX))
        .execute(&mut *tx)
        .await
        .map_err(DeadLetterStoreError::new)?;

        tx.commit().await.map_err(DeadLetterStoreError::new)?;

        Ok(())
    }

    /// 释放资源（pool 由 `PgStore` 统一管理；此处 no-op）。
    ///
    // reason: pool 的 `close()` 由 `PgStore::shutdown`（impl `ManagedResource`）经
    // `bootstrap::ShutdownStack` 逆序编排统一关闭；`PgDeadLetterStore` 自身无额外 infra 资源。
    async fn shutdown(&self) -> Result<(), DeadLetterStoreError> {
        Ok(())
    }
}

// ── 单测 ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod smoke {
    //! 编译期类型证明：`PgDeadLetterStore: DeadLetterStore`（via trait bound）。
    //! INVARIANT: ADAPTER-PORT-FREEZE-07 —— DeadLetterStore on PgDeadLetterStore；
    //! 去掉 impl 即编译失败（anti-vacuity）。
    use core::marker::PhantomData;

    use diport::DeadLetterStore;

    fn assert_dead_letter_store<T: DeadLetterStore>(_: PhantomData<T>) {}

    #[test]
    fn pg_dead_letter_store_impl_frozen() {
        assert_dead_letter_store(PhantomData::<super::PgDeadLetterStore>);
    }
}

/// 集成测试：`PgDeadLetterStore` 往返验证（写入 → SELECT 断言字段）。
/// `integration` feature 门控；需真实 postgres，经 `testkit::env_or_postgres()` self-provision。
/// 外部 PG 路径须 `RSS_TEST_ALLOW_EXTERNAL_POSTGRES` + 严格库名，单源校验在 testkit。
#[cfg(all(test, feature = "integration"))]
mod integration_tests {
    use diport::{DeadLetterStore, ManagedResource};

    type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

    /// 写入一条死信记录，再 SELECT 回来断言字段往返正确。
    #[tokio::test(flavor = "multi_thread")]
    #[allow(clippy::unwrap_used)]
    // reason: 集成测试 happy-path，已知合法值构造；item-level carve-out。
    async fn write_dead_letter_roundtrips() -> TestResult {
        let (_pg, store) = crate::test_pg::connect_pg().await?;
        store.run_migrations().await?;

        let dl = store.dead_letter();
        let payload = b"original message payload".to_vec();
        let tenant = vocab::TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479")?;
        let record = diport::DeadLetterRecord::new(
            tenant,
            "msg-session-created-1",
            "identity",
            "contract-session",
            "session.created",
            payload.clone(),
            diport::DeadLetterSummary::new("max retries exhausted after 10 attempts"),
            10,
        );

        dl.write_dead_letter(record).await?;

        // SELECT 最新一条（唯一写入）断言各字段。
        let row: (String, String, String, String, String, serde_json::Value, String, i32) = sqlx::query_as(
            r#"SELECT tenant_id::text, message_id, domain, contract_id, topic, original_entry, error_summary, num_attempts
               FROM dead_letter
               WHERE domain = 'identity' AND topic = 'session.created'
               ORDER BY first_attempt_at DESC
               LIMIT 1"#,
        )
        .fetch_one(&store.pool)
        .await?;

        assert_eq!(
            row.0, "f47ac10b-58cc-4372-a567-0e02b2c3d479",
            "tenant_id should match"
        );
        assert_eq!(row.1, "msg-session-created-1", "message_id should match");
        assert_eq!(row.2, "identity", "domain should match");
        assert_eq!(row.3, "contract-session", "contract_id should match");
        assert_eq!(row.4, "session.created", "topic should match");

        // original_entry 是 {"bytes": [u8, ...]}；还原原始字节验证往返。
        let bytes_arr = row.5["bytes"].as_array().unwrap();
        let decoded: Vec<u8> = bytes_arr
            .iter()
            .map(|v| v.as_u64().unwrap() as u8)
            .collect();
        assert_eq!(decoded, payload, "original_payload roundtrip should match");

        assert_eq!(
            row.6, "max retries exhausted after 10 attempts",
            "error_summary should match"
        );
        assert_eq!(row.7, 10, "num_attempts should match");

        store.shutdown().await?;
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn dead_letter_rls_isolates_tenants() -> TestResult {
        let (_pg, store) = crate::test_pg::connect_pg().await?;
        store.run_migrations().await?;

        sqlx::query("GRANT rss_app TO CURRENT_USER")
            .execute(&store.pool)
            .await?;

        let tenant_a = uuid::Uuid::new_v4().to_string();
        let tenant_b = uuid::Uuid::new_v4().to_string();
        let msg_id = format!("dlx-msg-{}", uuid::Uuid::new_v4());

        {
            let mut tx = store.pool.begin().await?;
            sqlx::query("SET LOCAL ROLE rss_app")
                .execute(&mut *tx)
                .await?;
            crate::cotx::set_local_tenant(&mut tx, vocab::TenantId::parse(&tenant_a)?).await?;
            sqlx::query(
                r#"INSERT INTO dead_letter
                   (tenant_id, message_id, domain, contract_id, topic, original_entry, error_summary, num_attempts)
                   VALUES ($1::uuid, $2, 'identity', 'contract-session', 'session.created', '{"bytes":[]}'::jsonb, 'permanent error', 1)"#,
            )
            .bind(&tenant_a)
            .bind(&msg_id)
            .execute(&mut *tx)
            .await?;
            tx.commit().await?;
        }

        {
            let mut tx = store.pool.begin().await?;
            sqlx::query("SET LOCAL ROLE rss_app")
                .execute(&mut *tx)
                .await?;
            crate::cotx::set_local_tenant(&mut tx, vocab::TenantId::parse(&tenant_a)?).await?;
            let cnt: (i64,) =
                sqlx::query_as("SELECT count(*) FROM dead_letter WHERE message_id = $1")
                    .bind(&msg_id)
                    .fetch_one(&mut *tx)
                    .await?;
            assert_eq!(cnt.0, 1, "tenant_a scope should see its DLX row");
            tx.rollback().await?;
        }

        {
            let legacy_msg_id = format!("dlx-legacy-null-{}", uuid::Uuid::new_v4());
            // Simulate a pre-0020 row that existed before tenant_id was introduced. New rows cannot
            // normally do this because the NOT VALID CHECK still applies to future writes.
            sqlx::query("ALTER TABLE dead_letter DROP CONSTRAINT chk_dead_letter_tenant_required")
                .execute(&store.pool)
                .await?;
            sqlx::query("ALTER TABLE dead_letter DISABLE ROW LEVEL SECURITY")
                .execute(&store.pool)
                .await?;
            sqlx::query(
                r#"INSERT INTO dead_letter
                   (message_id, domain, contract_id, topic, original_entry, error_summary, num_attempts)
                   VALUES ($1, 'identity', 'contract-session', 'session.created', '{"bytes":[]}'::jsonb, 'legacy row', 1)"#,
            )
            .bind(&legacy_msg_id)
            .execute(&store.pool)
            .await?;
            sqlx::query("ALTER TABLE dead_letter ENABLE ROW LEVEL SECURITY")
                .execute(&store.pool)
                .await?;
            sqlx::query("ALTER TABLE dead_letter FORCE ROW LEVEL SECURITY")
                .execute(&store.pool)
                .await?;

            let mut tx = store.pool.begin().await?;
            sqlx::query("SET LOCAL ROLE rss_app")
                .execute(&mut *tx)
                .await?;
            crate::cotx::set_local_tenant(&mut tx, vocab::TenantId::parse(&tenant_a)?).await?;
            let cnt: (i64,) =
                sqlx::query_as("SELECT count(*) FROM dead_letter WHERE message_id = $1")
                    .bind(&legacy_msg_id)
                    .fetch_one(&mut *tx)
                    .await?;
            assert_eq!(
                cnt.0, 0,
                "tenant-scoped rss_app must not see historical tenant_id NULL DLX rows"
            );
            tx.rollback().await?;
        }

        {
            let mut tx = store.pool.begin().await?;
            sqlx::query("SET LOCAL ROLE rss_app")
                .execute(&mut *tx)
                .await?;
            crate::cotx::set_local_tenant(&mut tx, vocab::TenantId::parse(&tenant_b)?).await?;
            let cnt: (i64,) =
                sqlx::query_as("SELECT count(*) FROM dead_letter WHERE message_id = $1")
                    .bind(&msg_id)
                    .fetch_one(&mut *tx)
                    .await?;
            assert_eq!(cnt.0, 0, "tenant_b scope must not see tenant_a DLX row");
            tx.rollback().await?;
        }

        {
            let mut tx = store.pool.begin().await?;
            sqlx::query("SET LOCAL ROLE rss_app")
                .execute(&mut *tx)
                .await?;
            let cnt: (i64,) =
                sqlx::query_as("SELECT count(*) FROM dead_letter WHERE message_id = $1")
                    .bind(&msg_id)
                    .fetch_one(&mut *tx)
                    .await?;
            assert_eq!(cnt.0, 0, "unset tenant scope must not see DLX rows");
            tx.rollback().await?;
        }

        {
            let mut tx = store.pool.begin().await?;
            sqlx::query("SET LOCAL ROLE rss_app")
                .execute(&mut *tx)
                .await?;
            crate::cotx::set_local_tenant(&mut tx, vocab::TenantId::parse(&tenant_a)?).await?;
            let err = sqlx::query(
                r#"INSERT INTO dead_letter
                   (tenant_id, message_id, domain, contract_id, topic, original_entry, error_summary, num_attempts)
                   VALUES ($1::uuid, $2, 'identity', 'contract-session', 'session.created', '{"bytes":[]}'::jsonb, 'permanent error', 1)"#,
            )
            .bind(&tenant_b)
            .bind(format!("dlx-msg-{}", uuid::Uuid::new_v4()))
            .execute(&mut *tx)
            .await;
            assert!(
                err.is_err(),
                "tenant_a scope must reject tenant_b DLX insert"
            );
            tx.rollback().await?;
        }

        store.shutdown().await?;
        Ok(())
    }
}
