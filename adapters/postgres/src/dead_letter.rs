//! PostgreSQL 死信持久化 adapter（DLX，#1120）。
//!
//! [`PgDeadLetterStore`] impl [`diport::DeadLetterStore`]——native AFIT（泛型静态分发或
//! `Box<DynDeadLetterStore>` 组合根注入）。
//!
//! **保留期内不可变**：写路径只 INSERT、不 UPDATE。死信是审计物料，运维经 SELECT 巡检、不改原记录；
//! 超 [`DEAD_LETTER_RETENTION_SECONDS`]（默认 30 天）的旧记录由 [`RetentionSweeper`] 清理（膨胀控制，#1210）。
//! runtime 长期连接仍是 `rss_app`；全域保留期删除收束到迁移安装的窄 `rss_sweep_dead_letter(bigint)`
//! SECURITY DEFINER 函数。函数 owner 是 NOLOGIN maintenance role，`rss_app` 无直接 `DELETE`。
//! `dead_letter` 是**约定** append-only（非 REVOKE 强制，与 `projection_events` 不同），DB 层只允许该固定
//! 保留期 DELETE；冷存储导出（合规归档）为 out-of-scope。
//!
//! **`original_entry` jsonb** 只允许 `{"ciphertext": [u8, ...]}`，密文由注入的
//! [`DlxPayloadProtector`] 经 KeyProvider/Vault Transit 产生；本 adapter 不保留 plaintext fallback。
//!
//! **时间戳**：`first_attempt_at` / `last_attempt_at` 用 DB DEFAULT `now()`（不注入 Clock，
//! 与 outbox/inbox 同范式：时间源保持 DB 端单一，无跨进程偏移）。
//!
//! **错误 PII 边界**：sqlx 错误不进 Display（经 `DeadLetterStoreError::new` 包成 source，
//! `error-handling.md §Message 与 PII`）。

use consistency::{EngineError, EngineErrorKind, RetentionSweeper};
use diport::{
    DeadLetterRecord, DeadLetterStore, DeadLetterStoreError, EnvelopeMetadata, KEY_TENANT_AUTHORITY,
};
use sqlx::PgPool;

use crate::PgStore;
use crate::cotx::PgTenantPool;
use crate::dead_letter_payload::{
    DLX_ORIGINAL_ENTRY_ENCODING, DlxPayloadContext, DlxPayloadProtector,
};

/// `dead_letter` 旧死信记录保留期（秒，默认 30 天）。超期由 [`PgDeadLetterStore`] 的 [`RetentionSweeper`]
/// 清理（合规导向膨胀控制，对标 gocell 死信 30 天清理，#1210）。
///
/// `pub` 暴露供组合根读取构造 `eventexec::SweeperConfig`；不应被业务代码直接使用。
pub const DEAD_LETTER_RETENTION_SECONDS: u64 = 30 * 24 * 3600;

/// PostgreSQL 死信写入 adapter。
///
/// 持 `PgPool`（clone 自 [`PgStore`]，池共用 `ManagedResource::shutdown` 统一关）。
/// 经 [`crate::PgInfraDeps::dead_letter`] 构造（`PgStore::dead_letter` 为 `pub(crate)` funnel）。
pub struct PgDeadLetterStore {
    tenant_pool: PgTenantPool,
    maintenance_pool: PgPool,
    payload_protector: DlxPayloadProtector,
}

impl PgStore {
    /// 构造 [`PgDeadLetterStore`]（pool clone 自 `PgStore`，轻量）。
    ///
    /// `pub(crate)`（#1423，PG-BUNDLE-FUNNEL-01）：经 [`crate::PgInfraDeps::dead_letter`] 收口。
    pub(crate) fn dead_letter(&self, payload_protector: DlxPayloadProtector) -> PgDeadLetterStore {
        PgDeadLetterStore {
            tenant_pool: PgTenantPool::new(self),
            maintenance_pool: self.pool.clone(),
            payload_protector,
        }
    }
}

impl DeadLetterStore for PgDeadLetterStore {
    /// 持久化一条死信记录（immutable INSERT，不更新已有行）。
    ///
    /// `original_entry` 存为 jsonb：`{"ciphertext": [u8, ...]}`，key_ref/len/encoding 同行原子写入。
    /// 时间戳 `first_attempt_at` / `last_attempt_at` 均走 DB DEFAULT `now()`。
    /// sqlx 错误不进 Display——经 [`DeadLetterStoreError::new`] 包成 source（PII 边界）。
    async fn write_dead_letter(
        &self,
        record: DeadLetterRecord,
    ) -> Result<(), DeadLetterStoreError> {
        let source_kind = record.source().as_str();
        let protected = self
            .payload_protector
            .encrypt(
                DlxPayloadContext::new(
                    record.tenant(),
                    source_kind,
                    record.domain(),
                    record.contract_id(),
                    record.topic(),
                    record.consumer_group(),
                    record.message_id(),
                ),
                record.original_payload(),
            )
            .await
            .map_err(DeadLetterStoreError::new)?;
        let metadata = metadata_json(record.metadata());

        self.tenant_pool
            .write(
                record.tenant(),
                move |conn| {
                    Box::pin(async move {
                        sqlx::query(
                            r#"
                            INSERT INTO dead_letter
                                (tenant_id, message_id, domain, contract_id, topic, consumer_group,
                                 original_entry, original_entry_key_ref, original_entry_payload_len,
                                 original_entry_encoding, error_summary, num_attempts, source_kind, metadata)
                            VALUES ($1::uuid, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
                            "#,
                        )
                        .bind(record.tenant().to_string())
                        .bind(record.message_id())
                        .bind(record.domain())
                        .bind(record.contract_id())
                        .bind(record.topic())
                        .bind(record.consumer_group())
                        .bind(sqlx::types::Json(protected.original_entry()))
                        .bind(protected.key_ref())
                        .bind(protected.payload_len())
                        .bind(DLX_ORIGINAL_ENTRY_ENCODING)
                        .bind(record.error_summary())
                        .bind(i32::try_from(record.num_attempts()).unwrap_or(i32::MAX))
                        .bind(source_kind)
                        .bind(sqlx::types::Json(&metadata))
                        .execute(&mut *conn)
                        .await
                        .map_err(DeadLetterStoreError::new)
                        .map(|_| ())
                    })
                },
                DeadLetterStoreError::new,
            )
            .await
    }

    /// 释放资源（pool 由 `PgStore` 统一管理；此处 no-op）。
    ///
    // reason: pool 的 `close()` 由 `PgStore::shutdown`（impl `ManagedResource`）经
    // `bootstrap::ShutdownStack` 逆序编排统一关闭；`PgDeadLetterStore` 自身无额外 infra 资源。
    async fn shutdown(&self) -> Result<(), DeadLetterStoreError> {
        Ok(())
    }
}

/// Envelope metadata → jsonb object。值保持 wire string 形态，避免 DLQ 重放时发生隐式类型漂移。
pub(crate) fn metadata_json(metadata: &EnvelopeMetadata) -> serde_json::Value {
    let mut map = serde_json::Map::new();
    for (key, value) in metadata.iter_persisted_metadata() {
        if key == KEY_TENANT_AUTHORITY {
            continue;
        }
        map.insert(
            key.to_string(),
            serde_json::Value::String(value.to_string()),
        );
    }
    serde_json::Value::Object(map)
}

#[cfg(test)]
mod metadata_tests {
    use diport::{EnvelopeMetadata, KEY_CORRELATION, KEY_TENANT_AUTHORITY};

    use super::metadata_json;

    #[test]
    fn metadata_json_drops_tenant_authority_token() {
        let mut metadata = EnvelopeMetadata::empty();
        metadata.insert_wire_pair(KEY_TENANT_AUTHORITY, "SECRET_AUTHORITY");
        metadata.insert_wire_pair(KEY_CORRELATION, "corr-1");
        let rendered = metadata_json(&metadata);

        assert_eq!(rendered[KEY_CORRELATION], "corr-1");
        assert!(
            rendered.get(KEY_TENANT_AUTHORITY).is_none(),
            "tenantAuthority must not be persisted in DLX metadata: {rendered}"
        );
    }
}

impl RetentionSweeper for PgDeadLetterStore {
    /// 删除 `last_attempt_at` 早于保留期的死信行，返回删除条数（**全域**，所有死信均终结，无状态谓词）。
    ///
    /// 时间谓词用 PostgreSQL `now()`（DB 事务时间），刻意不注入 `Clock`——与 outbox/inbox sweep 同范式
    /// （单一无偏移时间源）。`last_attempt_at == first_attempt_at`（immutable INSERT，二者同写入时刻），
    /// 用 `last_attempt_at` 对齐既有 `idx_dead_letter_scan` 语义；专用 `idx_dead_letter_sweep (last_attempt_at)`
    /// 覆盖本全域谓词（迁移 0021）。runtime 经 `rss_app` 调固定 SECURITY DEFINER 函数，不保留 owner
    /// 长期连接，也不授 `rss_app` 直接 `DELETE`。
    async fn sweep(&self, retain_seconds: u64) -> Result<u64, EngineError> {
        if retain_seconds < DEAD_LETTER_RETENTION_SECONDS {
            return Err(EngineError::new(EngineErrorKind::Invariant));
        }
        // u64→i64：超 i64::MAX 的保留期是非法输入（负 interval 会反向清空全表），fail-closed。
        let secs = i64::try_from(retain_seconds)
            .map_err(|_| EngineError::new(EngineErrorKind::Invariant))?;
        let (deleted,): (i64,) = sqlx::query_as("SELECT rss_sweep_dead_letter($1)::bigint")
        .bind(secs)
        .fetch_one(&self.maintenance_pool)
        .await
        .map_err(|e| {
            tracing::warn!(target: "postgres", error = %secure::redact_error(&e), "dead_letter: sweep db error");
            EngineError::new(EngineErrorKind::Transient)
        })?;

        Ok(u64::try_from(deleted).unwrap_or(0))
    }
}

// ── 单测 ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod smoke {
    //! 编译期类型证明：`PgDeadLetterStore: DeadLetterStore + RetentionSweeper`（via trait bound）。
    //! INVARIANT: ADAPTER-PORT-FREEZE-07 { level = "Medium", exec = "manual/opt-in", source = "code" }—— DeadLetterStore on PgDeadLetterStore；
    //! 去掉任一 impl 即编译失败（anti-vacuity）。
    use core::marker::PhantomData;

    use consistency::RetentionSweeper;
    use diport::DeadLetterStore;

    fn assert_dead_letter_store<T: DeadLetterStore>(_: PhantomData<T>) {}
    fn assert_retention_sweeper<T: RetentionSweeper>(_: PhantomData<T>) {}

    #[test]
    fn pg_dead_letter_store_impl_frozen() {
        assert_dead_letter_store(PhantomData::<super::PgDeadLetterStore>);
        assert_retention_sweeper(PhantomData::<super::PgDeadLetterStore>);
    }
}

#[cfg(test)]
mod sweep_fail_closed {
    //! sweep 入口保留期下限 + u64→i64 溢出 fail-closed 守卫单测（免 PG，#327 review F4）。
    use consistency::{EngineErrorKind, RetentionSweeper};
    use sqlx::postgres::{PgConnectOptions, PgPoolOptions};

    use crate::PgStore;

    // u64::MAX 溢出 i64 → Invariant（先于触 pool 返回，故 lazy pool 免 DB）。`#[tokio::test]`：sqlx 池构造需
    // Tokio context。anti-vacuity 由集成测试 `t_dead_letter_sweep_*`（合法保留期走完整 DELETE 路径）配对。
    #[tokio::test]
    async fn sweep_rejects_invalid_retain_seconds() {
        let opts = PgConnectOptions::new()
            .host("127.0.0.1")
            .port(5999)
            .database("rss_test")
            .username("u")
            .password("p");
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect_lazy_with(opts);
        let r = PgStore { pool }
            .dead_letter(crate::dead_letter_payload::tests::test_protector())
            .sweep(u64::MAX)
            .await;
        assert!(
            matches!(r, Err(e) if e.kind() == EngineErrorKind::Invariant),
            "超 i64::MAX 的保留期必须 fail-closed 拒"
        );

        let opts = PgConnectOptions::new()
            .host("127.0.0.1")
            .port(5999)
            .database("rss_test")
            .username("u")
            .password("p");
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect_lazy_with(opts);
        let r = PgStore { pool }
            .dead_letter(crate::dead_letter_payload::tests::test_protector())
            .sweep(super::DEAD_LETTER_RETENTION_SECONDS - 1)
            .await;
        assert!(
            matches!(r, Err(e) if e.kind() == EngineErrorKind::Invariant),
            "低于默认保留期的清理请求必须 fail-closed 拒"
        );
    }
}

/// 集成测试：`PgDeadLetterStore` 往返验证（写入 → SELECT 断言字段）。
/// `integration` feature 门控；需真实 postgres，经 `testkit::env_or_postgres()` self-provision。
/// 外部 PG 路径须 `RSS_TEST_ALLOW_EXTERNAL_POSTGRES` + 严格库名，单源校验在 testkit。
#[cfg(all(test, feature = "integration"))]
mod integration_tests {
    use diport::{DeadLetterStore, ManagedResource};

    use crate::dead_letter_payload::DLX_ORIGINAL_ENTRY_ENCODING;
    use crate::dead_letter_payload::tests::test_protector;

    type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;
    type DeadLetterRow = (
        String,
        String,
        String,
        String,
        String,
        Option<String>,
        serde_json::Value,
        String,
        i64,
        String,
        String,
        i32,
        String,
        serde_json::Value,
    );

    /// 写入一条死信记录，再 SELECT 回来断言字段往返正确。
    #[tokio::test(flavor = "multi_thread")]
    #[allow(clippy::unwrap_used)]
    // reason: 集成测试 happy-path，已知合法值构造；item-level carve-out。
    async fn write_dead_letter_roundtrips() -> TestResult {
        let (_pg, store) = crate::test_pg::connect_pg().await?;
        store.run_migrations().await?;

        let dl = store.dead_letter(test_protector());
        let payload = b"original message payload".to_vec();
        let tenant = vocab::TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479")?;
        let record = diport::DeadLetterRecord::new(
            tenant,
            "msg-session-created-1",
            "identity",
            "contract-session",
            "session.created",
            Some("identity.session.consumer".to_string()),
            payload.clone(),
            diport::DeadLetterSummary::new("max retries exhausted after 10 attempts"),
            10,
            diport::WritableDeadLetterSource::Consumer,
            diport::EnvelopeMetadata::empty(),
        );

        dl.write_dead_letter(record).await?;

        // SELECT 最新一条（唯一写入）断言各字段。
        let row: DeadLetterRow = sqlx::query_as(
            r#"SELECT tenant_id::text, message_id, domain, contract_id, topic, consumer_group,
                      original_entry, original_entry_key_ref, original_entry_payload_len,
                      original_entry_encoding, error_summary, num_attempts, source_kind, metadata
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
        assert_eq!(
            row.5.as_deref(),
            Some("identity.session.consumer"),
            "consumer_group should match"
        );

        // original_entry 只允许 ciphertext shape；fake provider 会做可逆变换，避免密文字节等于原文。
        assert!(
            row.6.get("bytes").is_none(),
            "plaintext shape must not be stored"
        );
        let cipher_arr = row.6["ciphertext"].as_array().unwrap();
        let stored_ciphertext: Vec<u8> = cipher_arr
            .iter()
            .map(|v| v.as_u64().unwrap() as u8)
            .collect();
        assert_ne!(
            stored_ciphertext, payload,
            "stored ciphertext should not equal original payload bytes"
        );
        assert_eq!(row.7, "dlx-test:1", "key ref should match");
        assert_eq!(
            row.8,
            i64::try_from(payload.len()).unwrap(),
            "payload length should match"
        );
        assert_eq!(
            row.9, DLX_ORIGINAL_ENTRY_ENCODING,
            "encoding should be key-provider-v1"
        );

        assert_eq!(
            row.10, "max retries exhausted after 10 attempts",
            "error_summary should match"
        );
        assert_eq!(row.11, 10, "num_attempts should match");
        assert_eq!(row.12, "consumer", "source_kind should match");
        assert_eq!(row.13, serde_json::json!({}), "metadata should match");

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
                   (tenant_id, message_id, domain, contract_id, topic,
                    original_entry, original_entry_key_ref, original_entry_payload_len,
                    original_entry_encoding, error_summary, num_attempts)
                   VALUES ($1::uuid, $2, 'identity', 'contract-session', 'session.created',
                           '{"ciphertext":[]}'::jsonb, 'dlx-test:1', 0,
                           $3, 'permanent error', 1)"#,
            )
            .bind(&tenant_a)
            .bind(&msg_id)
            .bind(DLX_ORIGINAL_ENTRY_ENCODING)
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
                   (message_id, domain, contract_id, topic,
                    original_entry, original_entry_key_ref, original_entry_payload_len,
                    original_entry_encoding, error_summary, num_attempts)
                   VALUES ($1, 'identity', 'contract-session', 'session.created',
                           '{"ciphertext":[]}'::jsonb, 'dlx-test:1', 0,
                           $2, 'legacy row', 1)"#,
            )
            .bind(&legacy_msg_id)
            .bind(DLX_ORIGINAL_ENTRY_ENCODING)
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
                   (tenant_id, message_id, domain, contract_id, topic,
                    original_entry, original_entry_key_ref, original_entry_payload_len,
                    original_entry_encoding, error_summary, num_attempts)
                   VALUES ($1::uuid, $2, 'identity', 'contract-session', 'session.created',
                           '{"ciphertext":[]}'::jsonb, 'dlx-test:1', 0,
                           $3, 'permanent error', 1)"#,
            )
            .bind(&tenant_b)
            .bind(format!("dlx-msg-{}", uuid::Uuid::new_v4()))
            .bind(DLX_ORIGINAL_ENTRY_ENCODING)
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
