//! Postgres integration tests — settings_persistence seam.

use super::support::*;
// reason: LocalTx type-aware resolver does not expand support glob imports; keep the canonical crate path.
use crate::PgSecretUnitOfWork;

/// tc1：save → find round-trip（未写 → None；写后 getter 全字段正确）。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn tc1_config_save_find_roundtrip() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_config(&store).await?;
    let repo = PgConfigRepo::new(&store, fixed_clock_arc(), config_protection());
    let tenant = config_tenant();
    let key = SettingKey::parse("app.timeout").unwrap();

    assert!(
        repo.find(settings_scope(tenant), &key).await?.is_none(),
        "未写入 → None"
    );

    repo.test_put(
        settings_scope(tenant),
        config_entry("app.timeout", "30s", 1),
    )
    .await?;
    let found = repo.find(settings_scope(tenant), &key).await?.unwrap();
    assert_eq!(found.value(), "30s", "find 取回值");
    assert_eq!(found.version(), 1, "find 取回版本");
    assert_eq!(found.key().as_str(), "app.timeout", "find 取回 key");
    assert_eq!(found.tenant(), tenant, "find 取回 tenant（tenant-correct）");
    let raw: (Option<String>, i32, Option<Vec<u8>>, Option<String>) = sqlx::query_as(
        "SELECT value, protection_scheme, value_enc, key_id \
         FROM config_entries WHERE tenant_id = $1::uuid AND config_key = $2 AND version = 1",
    )
    .bind(CONFIG_TENANT)
    .bind("app.timeout")
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(raw.0, None, "新写不得持久化 plaintext value");
    assert_eq!(raw.1, 1, "新写必须使用 encrypted scheme");
    assert!(raw.2.is_some(), "encrypted ciphertext present");
    let ciphertext = raw.2.unwrap();
    assert!(
        !ciphertext.windows(b"30s".len()).any(|w| w == b"30s"),
        "raw ciphertext must not contain plaintext"
    );
    assert_eq!(raw.3.as_deref(), Some("settings-config:1"));

    store.shutdown().await?;
    Ok(())
}

/// tc1a：legacy plaintext 行在 serving 读路径 fail-closed；只有 maintenance backfill 可读取。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn tc1a_config_legacy_plaintext_read_fails_closed() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_config(&store).await?;
    sqlx::query(
        "INSERT INTO config_entries (tenant_id, config_key, version, value, protection_scheme) \
         VALUES ($1::uuid, $2, $3, $4, 0)",
    )
    .bind(CONFIG_TENANT)
    .bind("legacy.value")
    .bind(1_i64)
    .bind("plain-v1")
    .execute(&store.pool)
    .await?;

    let repo = PgConfigRepo::new(&store, fixed_clock_arc(), rejecting_config_protection());
    let tenant = config_tenant();
    let key = SettingKey::parse("legacy.value").unwrap();
    let result = repo.find(settings_scope(tenant), &key).await;
    assert!(
        matches!(result, Err(ConfigRepoError::ProtectionAuthFailure(_))),
        "serving read path must reject legacy plaintext rows"
    );

    store.shutdown().await?;
    Ok(())
}

/// tc1c：fresh schema 不再给 `protection_scheme` 默认值，旧 INSERT 形态不能继续写明文。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn tc1c_config_plaintext_insert_without_scheme_is_rejected() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_config(&store).await?;

    let result = sqlx::query(
        "INSERT INTO config_entries (tenant_id, config_key, version, value) \
         VALUES ($1::uuid, $2, $3, $4)",
    )
    .bind(CONFIG_TENANT)
    .bind("legacy.default.rejected")
    .bind(1_i64)
    .bind("plain-v1")
    .execute(&store.pool)
    .await;

    assert!(
        result.is_err(),
        "old plaintext INSERT shape must fail after 0029 drops protection_scheme default"
    );

    store.shutdown().await?;
    Ok(())
}

/// tc1d：复制 encrypted row 到另一租户后，tenant 维度 AAD mismatch → fail-closed。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn tc1d_config_encrypted_row_cross_tenant_copy_rejected() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_config(&store).await?;
    let repo = PgConfigRepo::new(&store, fixed_clock_arc(), config_protection());
    let tenant_a = config_tenant();
    let tenant_b = TenantId::parse(CONFIG_TENANT_B).unwrap();
    let key = SettingKey::parse("app.aad").unwrap();

    repo.test_put(
        settings_scope(tenant_a),
        config_entry("app.aad", "tenant-a-value", 1),
    )
    .await?;
    sqlx::query(
        "INSERT INTO config_entries (
             tenant_id, config_key, version, value, deleted, protection_scheme, value_enc, key_id
         )
         SELECT $1::uuid, config_key, version, value, deleted, protection_scheme, value_enc, key_id
         FROM config_entries
         WHERE tenant_id = $2::uuid AND config_key = $3 AND version = 1",
    )
    .bind(CONFIG_TENANT_B)
    .bind(CONFIG_TENANT)
    .bind("app.aad")
    .execute(&store.pool)
    .await?;

    let result = repo.find(settings_scope(tenant_b), &key).await;
    assert!(
        matches!(result, Err(ConfigRepoError::ProtectionAuthFailure(_))),
        "copied ciphertext under another tenant must fail AAD authentication"
    );

    store.shutdown().await?;
    Ok(())
}

/// tc1e：encrypted 行读取时 KeyProvider 不可用 → ProtectionUnavailable，且不回退明文。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn tc1e_config_encrypted_read_provider_unavailable() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_config(&store).await?;
    let writer = PgConfigRepo::new(&store, fixed_clock_arc(), config_protection());
    let reader = PgConfigRepo::new(&store, fixed_clock_arc(), unavailable_config_protection());
    let tenant = config_tenant();
    let key = SettingKey::parse("app.kms").unwrap();

    writer
        .test_put(
            settings_scope(tenant),
            config_entry("app.kms", "encrypted-value", 1),
        )
        .await?;
    let result = reader.find(settings_scope(tenant), &key).await;
    assert!(
        matches!(result, Err(ConfigRepoError::ProtectionUnavailable(_))),
        "provider unavailable on encrypted read must surface ProtectionUnavailable"
    );

    store.shutdown().await?;
    Ok(())
}

/// tc1f：encrypted row 元数据损坏（bad key_id）→ ProtectionAuthFailure fail-closed。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn tc1f_config_corrupt_encrypted_metadata_fails_closed() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_config(&store).await?;
    sqlx::query(
        "INSERT INTO config_entries (
             tenant_id, config_key, version, value, protection_scheme, value_enc, key_id
         )
         VALUES ($1::uuid, $2, $3, NULL, 1, $4, $5)",
    )
    .bind(CONFIG_TENANT)
    .bind("app.corrupt")
    .bind(1_i64)
    .bind(&b"ciphertext"[..])
    .bind("not-a-key-ref")
    .execute(&store.pool)
    .await?;

    let repo = PgConfigRepo::new(&store, fixed_clock_arc(), config_protection());
    let result = repo
        .find(
            settings_scope(config_tenant()),
            &SettingKey::parse("app.corrupt").unwrap(),
        )
        .await;
    assert!(
        matches!(result, Err(ConfigRepoError::ProtectionAuthFailure(_))),
        "corrupt encrypted metadata must fail closed as auth failure"
    );

    store.shutdown().await?;
    Ok(())
}

/// tc1g：maintenance dry-run 只统计 legacy plaintext，不写库、不调用 KeyProvider。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn tc1g_config_maintenance_dry_run_counts_legacy_without_provider() -> TestResult {
    use std::sync::Arc;

    let (_pg, store) = connect_pg().await?;
    setup_config(&store).await?;
    sqlx::query(
        "INSERT INTO config_entries (tenant_id, config_key, version, value, protection_scheme) \
         VALUES ($1::uuid, $2, 1, $3, 0)",
    )
    .bind(CONFIG_TENANT)
    .bind("legacy.dry-run")
    .bind("plain-v1")
    .execute(&store.pool)
    .await?;

    let store = Arc::new(store);
    let maintenance = PgConfigValueMaintenance::new(
        Arc::clone(&store),
        rejecting_config_protection(),
        config_maintenance_capability(),
    );
    let report = maintenance
        .run(
            &ConfigValueMaintenanceOptions::new(ConfigValueMaintenanceOperation::Backfill)
                .with_dry_run(true),
        )
        .await?;

    assert_eq!(report.selected, 1);
    assert_eq!(report.backfilled, 0);
    assert_eq!(report.failed, 0);
    assert_eq!(report.remaining_plaintext, 1);
    let row: (Option<String>, i32, Option<Vec<u8>>, Option<String>) = sqlx::query_as(
        "SELECT value, protection_scheme, value_enc, key_id \
         FROM config_entries WHERE config_key = $1",
    )
    .bind("legacy.dry-run")
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(row.0.as_deref(), Some("plain-v1"));
    assert_eq!(row.1, 0);
    assert!(row.2.is_none());
    assert!(row.3.is_none());

    store.shutdown().await?;
    Ok(())
}

/// tc1h：maintenance backfill 把 legacy plaintext 转为 encrypted scheme，随后普通读路径可读回原值。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn tc1h_config_maintenance_backfills_legacy_plaintext() -> TestResult {
    use std::sync::Arc;

    let (_pg, store) = connect_pg().await?;
    setup_config(&store).await?;
    sqlx::query(
        "INSERT INTO config_entries (tenant_id, config_key, version, value, protection_scheme) \
         VALUES ($1::uuid, $2, 1, $3, 0)",
    )
    .bind(CONFIG_TENANT)
    .bind("legacy.backfill")
    .bind("plain-v1")
    .execute(&store.pool)
    .await?;

    let store = Arc::new(store);
    let maintenance = PgConfigValueMaintenance::new(
        Arc::clone(&store),
        config_protection(),
        config_maintenance_capability(),
    );
    let report = maintenance
        .run(&ConfigValueMaintenanceOptions::new(
            ConfigValueMaintenanceOperation::Backfill,
        ))
        .await?;

    assert_eq!(report.selected, 1);
    assert_eq!(report.backfilled, 1);
    assert_eq!(report.remaining_plaintext, 0);
    let raw: (Option<String>, i32, Option<Vec<u8>>, Option<String>) = sqlx::query_as(
        "SELECT value, protection_scheme, value_enc, key_id \
         FROM config_entries WHERE config_key = $1",
    )
    .bind("legacy.backfill")
    .fetch_one(&store.pool)
    .await?;
    assert!(
        raw.0.is_none(),
        "backfill must remove plaintext column value"
    );
    assert_eq!(raw.1, 1);
    assert!(raw.2.is_some());
    assert_eq!(raw.3.as_deref(), Some("settings-config:1"));

    let repo = PgConfigRepo::new(&store, fixed_clock_arc(), config_protection());
    let found = repo
        .find(
            settings_scope(config_tenant()),
            &SettingKey::parse("legacy.backfill").unwrap(),
        )
        .await?
        .unwrap();
    assert_eq!(found.value(), "plain-v1");

    store.shutdown().await?;
    Ok(())
}

/// tc1i：maintenance rewrap 更新 encrypted 行 key_id 到 provider current-primary，不调用 decrypt。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn tc1i_config_maintenance_rewrap_updates_key_ref() -> TestResult {
    use std::sync::Arc;

    let (_pg, store) = connect_pg().await?;
    setup_config(&store).await?;
    let writer = PgConfigRepo::new(&store, fixed_clock_arc(), config_protection());
    writer
        .test_put(
            settings_scope(config_tenant()),
            config_entry("encrypted.rewrap", "v1", 1),
        )
        .await?;

    let store = Arc::new(store);
    let maintenance = PgConfigValueMaintenance::new(
        Arc::clone(&store),
        rewrapping_config_protection(),
        config_maintenance_capability(),
    );
    let report = maintenance
        .run(&ConfigValueMaintenanceOptions::new(
            ConfigValueMaintenanceOperation::Rewrap,
        ))
        .await?;

    assert_eq!(report.selected, 1);
    assert_eq!(report.rewrapped, 1);
    assert_eq!(report.failed, 0);
    let key_id: (String,) =
        sqlx::query_as("SELECT key_id FROM config_entries WHERE config_key = $1")
            .bind("encrypted.rewrap")
            .fetch_one(&store.pool)
            .await?;
    assert_eq!(key_id.0, "settings-config:2");

    let second = maintenance
        .run(&ConfigValueMaintenanceOptions::new(
            ConfigValueMaintenanceOperation::Rewrap,
        ))
        .await?;
    assert_eq!(second.selected, 1);
    assert_eq!(second.unchanged, 1, "repeated rewrap is idempotent");

    store.shutdown().await?;
    Ok(())
}

/// tc1j：maintenance backfill provider failure leaves legacy row intact and reports failure.
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn tc1j_config_maintenance_backfill_failure_preserves_row() -> TestResult {
    use std::sync::Arc;

    let (_pg, store) = connect_pg().await?;
    setup_config(&store).await?;
    sqlx::query(
        "INSERT INTO config_entries (tenant_id, config_key, version, value, protection_scheme) \
         VALUES ($1::uuid, $2, 1, $3, 0)",
    )
    .bind(CONFIG_TENANT)
    .bind("legacy.failure")
    .bind("plain-v1")
    .execute(&store.pool)
    .await?;

    let store = Arc::new(store);
    let maintenance = PgConfigValueMaintenance::new(
        Arc::clone(&store),
        unavailable_config_protection(),
        config_maintenance_capability(),
    );
    let report = maintenance
        .run(&ConfigValueMaintenanceOptions::new(
            ConfigValueMaintenanceOperation::Backfill,
        ))
        .await?;

    assert_eq!(report.selected, 1);
    assert_eq!(report.backfilled, 0);
    assert_eq!(report.failed, 1);
    assert_eq!(report.remaining_plaintext, 1);
    let row: (Option<String>, i32, Option<Vec<u8>>, Option<String>) = sqlx::query_as(
        "SELECT value, protection_scheme, value_enc, key_id \
         FROM config_entries WHERE config_key = $1",
    )
    .bind("legacy.failure")
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(row.0.as_deref(), Some("plain-v1"));
    assert_eq!(row.1, 0);
    assert!(row.2.is_none());
    assert!(row.3.is_none());

    store.shutdown().await?;
    Ok(())
}

/// tc1l：backfill update 带原 plaintext CAS；选中后被改动的行不会被 stale ciphertext 覆盖。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn tc1l_config_maintenance_backfill_stale_row_is_unchanged() -> TestResult {
    use std::sync::Arc;

    let (_pg, store) = connect_pg().await?;
    setup_config(&store).await?;
    sqlx::query(
        "INSERT INTO config_entries (tenant_id, config_key, version, value, protection_scheme) \
         VALUES ($1::uuid, $2, 1, $3, 0)",
    )
    .bind(CONFIG_TENANT)
    .bind("legacy.cas")
    .bind("plain-v1")
    .execute(&store.pool)
    .await?;

    let pool = store.pool.clone();
    let store = Arc::new(store);
    let maintenance = PgConfigValueMaintenance::new(
        Arc::clone(&store),
        mutating_backfill_config_protection(pool),
        config_maintenance_capability(),
    );
    let report = maintenance
        .run(&ConfigValueMaintenanceOptions::new(
            ConfigValueMaintenanceOperation::Backfill,
        ))
        .await?;

    assert_eq!(report.selected, 1);
    assert_eq!(report.backfilled, 0);
    assert_eq!(report.unchanged, 1);
    assert_eq!(report.failed, 0);
    let row: (Option<String>, i32, Option<Vec<u8>>, Option<String>) = sqlx::query_as(
        "SELECT value, protection_scheme, value_enc, key_id \
         FROM config_entries WHERE config_key = $1",
    )
    .bind("legacy.cas")
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(row.0.as_deref(), Some("plain-v2"));
    assert_eq!(row.1, 0);
    assert!(row.2.is_none());
    assert!(row.3.is_none());

    store.shutdown().await?;
    Ok(())
}

/// tc1m：maintenance rewrap provider failure leaves encrypted row intact and reports failure.
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn tc1m_config_maintenance_rewrap_failure_preserves_row() -> TestResult {
    use std::sync::Arc;

    let (_pg, store) = connect_pg().await?;
    setup_config(&store).await?;
    let writer = PgConfigRepo::new(&store, fixed_clock_arc(), config_protection());
    writer
        .test_put(
            settings_scope(config_tenant()),
            config_entry("encrypted.rewrap_failure", "v1", 1),
        )
        .await?;
    let before: (Option<Vec<u8>>, Option<String>) =
        sqlx::query_as("SELECT value_enc, key_id FROM config_entries WHERE config_key = $1")
            .bind("encrypted.rewrap_failure")
            .fetch_one(&store.pool)
            .await?;

    let store = Arc::new(store);
    let maintenance = PgConfigValueMaintenance::new(
        Arc::clone(&store),
        unavailable_config_protection(),
        config_maintenance_capability(),
    );
    let report = maintenance
        .run(&ConfigValueMaintenanceOptions::new(
            ConfigValueMaintenanceOperation::Rewrap,
        ))
        .await?;

    assert_eq!(report.selected, 1);
    assert_eq!(report.rewrapped, 0);
    assert_eq!(report.failed, 1);
    let after: (Option<Vec<u8>>, Option<String>) =
        sqlx::query_as("SELECT value_enc, key_id FROM config_entries WHERE config_key = $1")
            .bind("encrypted.rewrap_failure")
            .fetch_one(&store.pool)
            .await?;
    assert_eq!(after, before);

    store.shutdown().await?;
    Ok(())
}

/// tc1o：rewrap 遇到 malformed key_id 时计入 selected/failed，且消耗 max_rows 预算。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn tc1o_config_maintenance_rewrap_invalid_key_ref_counts_as_failed_selected_row() -> TestResult
{
    use std::sync::Arc;

    let (_pg, store) = connect_pg().await?;
    setup_config(&store).await?;
    sqlx::query(
        "INSERT INTO config_entries (tenant_id, config_key, version, value, protection_scheme, value_enc, key_id) \
         VALUES ($1::uuid, $2, 1, NULL, 1, $3, $4)",
    )
    .bind(CONFIG_TENANT)
    .bind("encrypted.invalid_key_ref")
    .bind(b"ciphertext".as_slice())
    .bind("not-a-key-ref")
    .execute(&store.pool)
    .await?;
    let writer = PgConfigRepo::new(&store, fixed_clock_arc(), config_protection());
    writer
        .test_put(
            settings_scope(config_tenant()),
            config_entry("encrypted.valid_after_invalid", "v1", 1),
        )
        .await?;

    let store = Arc::new(store);
    let maintenance = PgConfigValueMaintenance::new(
        Arc::clone(&store),
        rewrapping_config_protection(),
        config_maintenance_capability(),
    );
    let report = maintenance
        .run(
            &ConfigValueMaintenanceOptions::new(ConfigValueMaintenanceOperation::Rewrap)
                .with_max_rows(Some(1)),
        )
        .await?;

    assert_eq!(report.selected, 1);
    assert_eq!(report.failed, 1);
    assert_eq!(report.rewrapped, 0);
    let key_id: (String,) =
        sqlx::query_as("SELECT key_id FROM config_entries WHERE config_key = $1")
            .bind("encrypted.valid_after_invalid")
            .fetch_one(&store.pool)
            .await?;
    assert_eq!(
        key_id.0, "settings-config:1",
        "malformed selected row must consume the max_rows budget"
    );

    store.shutdown().await?;
    Ok(())
}

/// tc1k：tenant/max_rows 限制只处理指定租户内的限定行数。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn tc1k_config_maintenance_tenant_and_max_rows_limit_scope() -> TestResult {
    use std::sync::Arc;

    let (_pg, store) = connect_pg().await?;
    setup_config(&store).await?;
    for key in ["legacy.scope_a", "legacy.scope_b"] {
        sqlx::query(
            "INSERT INTO config_entries (tenant_id, config_key, version, value, protection_scheme) \
             VALUES ($1::uuid, $2, 1, $3, 0)",
        )
        .bind(CONFIG_TENANT)
        .bind(key)
        .bind("plain")
        .execute(&store.pool)
        .await?;
    }
    sqlx::query(
        "INSERT INTO config_entries (tenant_id, config_key, version, value, protection_scheme) \
         VALUES ($1::uuid, $2, 1, $3, 0)",
    )
    .bind(CONFIG_TENANT_B)
    .bind("legacy.scope.other")
    .bind("plain")
    .execute(&store.pool)
    .await?;

    let store = Arc::new(store);
    let maintenance = PgConfigValueMaintenance::new(
        Arc::clone(&store),
        config_protection(),
        config_maintenance_capability(),
    );
    let report = maintenance
        .run(
            &ConfigValueMaintenanceOptions::new(ConfigValueMaintenanceOperation::Backfill)
                .with_tenant(config_tenant())
                .with_max_rows(Some(1)),
        )
        .await?;

    assert_eq!(report.selected, 1);
    assert_eq!(report.backfilled, 1);
    assert_eq!(report.remaining_plaintext, 1);
    let all_remaining: (i64,) =
        sqlx::query_as("SELECT count(*) FROM config_entries WHERE protection_scheme = 0")
            .fetch_one(&store.pool)
            .await?;
    assert_eq!(
        all_remaining.0, 2,
        "one same-tenant row and one other-tenant row remain"
    );

    store.shutdown().await?;
    Ok(())
}

/// tc1n：默认 both 操作共享 `max_rows` 预算，不会 backfill N 行后再额外 rewrap N 行。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn tc1n_config_maintenance_both_max_rows_is_shared() -> TestResult {
    use std::sync::Arc;

    let (_pg, store) = connect_pg().await?;
    setup_config(&store).await?;
    sqlx::query(
        "INSERT INTO config_entries (tenant_id, config_key, version, value, protection_scheme) \
         VALUES ($1::uuid, $2, 1, $3, 0)",
    )
    .bind(CONFIG_TENANT)
    .bind("legacy.both_budget")
    .bind("plain")
    .execute(&store.pool)
    .await?;
    let writer = PgConfigRepo::new(&store, fixed_clock_arc(), config_protection());
    writer
        .test_put(
            settings_scope(config_tenant()),
            config_entry("encrypted.both_budget", "v1", 1),
        )
        .await?;

    let store = Arc::new(store);
    let maintenance = PgConfigValueMaintenance::new(
        Arc::clone(&store),
        config_protection(),
        config_maintenance_capability(),
    );
    let report = maintenance
        .run(&ConfigValueMaintenanceOptions::default().with_max_rows(Some(1)))
        .await?;

    assert_eq!(report.selected, 1);
    assert_eq!(report.backfilled, 1);
    assert_eq!(report.rewrapped, 0);
    let key_id: (String,) =
        sqlx::query_as("SELECT key_id FROM config_entries WHERE config_key = $1")
            .bind("encrypted.both_budget")
            .fetch_one(&store.pool)
            .await?;
    assert_eq!(key_id.0, "settings-config:1");

    store.shutdown().await?;
    Ok(())
}

/// tc1b：经 `settings_bundle` funnel 解包的 `DynConfigRepo` 在真实 DB 上 save→find 闭合——验证 bundle
/// 预包装的 config 读写路径（非散装 `PgConfigRepo::new`）端到端可用（PG-BUNDLE-SETTINGS-04 集成覆盖，#1424）。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn tc1b_bundle_config_save_find_roundtrip() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_config(&store).await?;
    // 经 funnel：PgRuntimeDeps → for_domain::<Settings> → settings_bundle → into_parts（取 read config box）。
    let handle = crate::PgRuntimeHandle::from_store_for_test(std::sync::Arc::new(store));
    let (configs, writer, _secrets, _secret_writer) = handle
        .for_domain::<crate::caps::Settings>()
        .settings_bundle(fixed_clock_arc(), config_protections())
        .into_parts();
    let tenant = config_tenant();
    let key = SettingKey::parse("bundle.timeout").unwrap();

    assert!(
        configs.find(settings_scope(tenant), &key).await?.is_none(),
        "未写入 → None"
    );
    writer
        .commit_publish(
            settings::config_publish_receipt_for_test(),
            settings_scope(tenant),
            ConfigMutation::Put(config_entry("bundle.timeout", "30s", 1)),
            reviewed_generated_event::<generated::event::settings_v1::Contract>(
                config_outbox_entry(&unique_event_id("bundle-read-write")),
                config_envelope("bundle.timeout"),
            )
            .await?,
        )
        .await?;
    let found = configs.find(settings_scope(tenant), &key).await?.unwrap();
    assert_eq!(found.value(), "30s", "bundle DynConfigRepo find 取回值");
    assert_eq!(found.version(), 1, "bundle DynConfigRepo find 取回版本");
    Ok(())
}

/// tc1c：经 `settings_bundle` funnel 解包的 `writer`（`DynConfigUnitOfWork`）在真实 DB 上 `commit`
/// co-tx 落 config 行 + outbox 行 + 构造期注入 occurred_at——证 bundle write lane 与 direct co-tx（tc5）语义等价
/// （F2，#1424；补 tc1b 只覆盖 read lane 的缺口）。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn tc1c_bundle_writer_cotx_commits_config_and_outbox() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_config(&store).await?;
    // store 即将移入 deps（PG-BUNDLE-POOL-03 无 pool accessor）→ 先 clone pool 供验证查询。
    let pool = store.pool.clone();
    let handle = crate::PgRuntimeHandle::from_store_for_test(std::sync::Arc::new(store));
    let (_configs, writer, _secrets, _secret_writer) = handle
        .for_domain::<crate::caps::Settings>()
        .settings_bundle(fixed_clock_arc(), config_protections())
        .into_parts();
    let tenant = config_tenant();
    let event_id = unique_event_id("cfg-tc1c-evt");

    writer
        .commit_publish(
            settings::config_publish_receipt_for_test(),
            settings_scope(tenant),
            ConfigMutation::Put(config_entry("bundle.cotx", "v1", 1)),
            reviewed_generated_event::<generated::event::settings_v1::Contract>(
                config_outbox_entry(&event_id),
                config_envelope("bundle.cotx"),
            )
            .await?,
        )
        .await?;

    // config 行 + outbox 行 co-tx 两行皆在（tenant-correct）。
    let crow: (i64, String) = sqlx::query_as(
        "SELECT count(*), max(tenant_id::text) FROM config_entries WHERE config_key = $1 AND version = 1",
    )
    .bind("bundle.cotx")
    .fetch_one(&pool)
    .await?;
    assert_eq!(crow.0, 1, "bundle writer：config 行应写入");
    assert_eq!(crow.1, CONFIG_TENANT, "bundle writer：config 行 tenant_id");
    let ob_cnt: (i64,) = sqlx::query_as("SELECT count(*) FROM outbox WHERE event_id = $1")
        .bind(&event_id)
        .fetch_one(&pool)
        .await?;
    assert_eq!(
        ob_cnt.0, 1,
        "bundle writer：outbox 行应写入（co-tx 两行皆在）"
    );
    // occurred_at 来自 bundle 构造期注入的 Arc clock（write lane 经 commit 用）。
    let cfg_meta: (String,) =
        sqlx::query_as("SELECT metadata::text FROM outbox WHERE event_id = $1")
            .bind(&event_id)
            .fetch_one(&pool)
            .await?;
    assert!(
        cfg_meta
            .0
            .replace(' ', "")
            .contains(&format!(r#""occurredAt":{}"#, expected_occurred_at())),
        "bundle writer co-tx outbox metadata 应含注入 clock 的 occurred_at: {}",
        cfg_meta.0
    );
    assert_metadata_text_has_standard_schema_header(
        &cfg_meta.0,
        config_contract().schema_hash(),
        "bundle writer co-tx outbox",
    );
    Ok(())
}

/// tc2：版本历史——find = max(version)；find_version 取精确历史版本；缺失版本 → None。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn tc2_config_find_version_returns_history() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_config(&store).await?;
    let repo = PgConfigRepo::new(&store, fixed_clock_arc(), config_protection());
    let tenant = config_tenant();
    let key = SettingKey::parse("app.k").unwrap();

    repo.test_put(settings_scope(tenant), config_entry("app.k", "v1", 1))
        .await?;
    repo.test_put(settings_scope(tenant), config_entry("app.k", "v2", 2))
        .await?;

    assert_eq!(
        repo.find(settings_scope(tenant), &key)
            .await?
            .unwrap()
            .value(),
        "v2",
        "find = 最高版本"
    );
    assert_eq!(
        repo.find_version(settings_scope(tenant), &key, 1)
            .await?
            .unwrap()
            .value(),
        "v1",
        "find_version(1) = 历史 v1"
    );
    assert_eq!(
        repo.find_version(settings_scope(tenant), &key, 2)
            .await?
            .unwrap()
            .value(),
        "v2"
    );
    assert!(
        repo.find_version(settings_scope(tenant), &key, 9)
            .await?
            .is_none(),
        "缺失版本 → None"
    );

    store.shutdown().await?;
    Ok(())
}

/// tc3：CAS——陈旧版本（重复）与跳版（gap）均 VersionConflict；恰 max+1 成功。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn tc3_config_save_cas_conflict() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_config(&store).await?;
    let repo = PgConfigRepo::new(&store, fixed_clock_arc(), config_protection());
    let tenant = config_tenant();
    let key = SettingKey::parse("app.k").unwrap();

    testkit::repo_conformance::assert_versioned_cas_repo(
        "v1".to_string(),
        "v1b".to_string(),
        "v3".to_string(),
        "v2".to_string(),
        |version, marker| {
            let repo = &repo;
            async move {
                repo.test_put(
                    settings_scope(tenant),
                    config_entry("app.k", &marker, version),
                )
                .await
            }
        },
        || {
            let repo = &repo;
            let key = &key;
            async move {
                repo.find(settings_scope(tenant), key)
                    .await
                    .map(|entry| entry.map(|entry| entry.value().to_string()))
            }
        },
        |e| matches!(e, ConfigRepoError::VersionConflict),
    )
    .await?;

    store.shutdown().await?;
    Ok(())
}

/// tc3b：写前 seal 失败（provider unavailable）→ 不打开业务写事务、不落 config 行。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn tc3b_config_save_provider_unavailable_persists_nothing() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_config(&store).await?;
    let repo = PgConfigRepo::new(&store, fixed_clock_arc(), unavailable_config_protection());
    let tenant = config_tenant();

    let result = repo
        .test_put(
            settings_scope(tenant),
            config_entry("app.kms-down", "no-write", 1),
        )
        .await;
    assert!(
        matches!(result, Err(ConfigRepoError::ProtectionUnavailable(_))),
        "write-time provider unavailable must surface ProtectionUnavailable"
    );
    let cfg_cnt: (i64,) =
        sqlx::query_as("SELECT count(*) FROM config_entries WHERE config_key = $1")
            .bind("app.kms-down")
            .fetch_one(&store.pool)
            .await?;
    assert_eq!(cfg_cnt.0, 0, "seal failure happens before DB write");

    store.shutdown().await?;
    Ok(())
}

/// tc4：delete 软删（tombstone）——find 返 None；历史值行**保留**（find_version 可读）；幂等。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn tc4_config_delete_tombstones_and_is_idempotent() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_config(&store).await?;
    let repo = PgConfigRepo::new(&store, fixed_clock_arc(), config_protection());
    let tenant = config_tenant();
    let key = SettingKey::parse("app.k").unwrap();

    testkit::repo_conformance::assert_tombstone_repo(
        "v1".to_string(),
        "v2".to_string(),
        |version, marker| {
            let repo = &repo;
            async move {
                repo.test_put(
                    settings_scope(tenant),
                    config_entry("app.k", &marker, version),
                )
                .await
            }
        },
        || {
            let repo = &repo;
            let key = &key;
            async move { repo.test_delete(settings_scope(tenant), key).await }
        },
        || {
            let repo = &repo;
            let key = &key;
            async move {
                repo.find(settings_scope(tenant), key)
                    .await
                    .map(|entry| entry.map(|entry| entry.value().to_string()))
            }
        },
        |version| {
            let repo = &repo;
            let key = &key;
            async move {
                repo.find_version(settings_scope(tenant), key, version)
                    .await
                    .map(|entry| entry.map(|entry| entry.value().to_string()))
            }
        },
        || {
            let repo = &repo;
            let key = &key;
            async move {
                repo.head(settings_scope(tenant), key)
                    .await
                    .map(|head| head.map(ConfigHead::version))
            }
        },
    )
    .await?;

    store.shutdown().await?;
    Ok(())
}

/// tc4b：delete no-op（不存在 / 已 tombstone）不得依赖 KeyProvider 可用性。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn tc4b_config_delete_noop_does_not_call_unavailable_provider() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_config(&store).await?;
    let tenant = config_tenant();
    let missing = SettingKey::parse("app.missing").unwrap();
    let key = SettingKey::parse("app.deleted").unwrap();

    let unavailable_repo =
        PgConfigRepo::new(&store, fixed_clock_arc(), unavailable_config_protection());
    unavailable_repo
        .test_delete(settings_scope(tenant), &missing)
        .await?;
    let missing_cnt: (i64,) =
        sqlx::query_as("SELECT count(*) FROM config_entries WHERE config_key = $1")
            .bind("app.missing")
            .fetch_one(&store.pool)
            .await?;
    assert_eq!(missing_cnt.0, 0, "missing-key delete no-op writes nothing");

    let writer = PgConfigRepo::new(&store, fixed_clock_arc(), config_protection());
    writer
        .test_put(settings_scope(tenant), config_entry("app.deleted", "v1", 1))
        .await?;
    writer.test_delete(settings_scope(tenant), &key).await?;
    unavailable_repo
        .test_delete(settings_scope(tenant), &key)
        .await?;

    let latest: (Option<i64>,) =
        sqlx::query_as("SELECT max(version) FROM config_entries WHERE config_key = $1")
            .bind("app.deleted")
            .fetch_one(&store.pool)
            .await?;
    assert_eq!(
        latest.0,
        Some(2),
        "already-deleted no-op must not append another tombstone"
    );

    store.shutdown().await?;
    Ok(())
}

/// tc4c：并发 delete/delete 应保持幂等——唯一键抢占 tombstone 版本时，失败方重读 latest tombstone 后 no-op。
#[tokio::test(flavor = "multi_thread")]
async fn tc4c_config_concurrent_delete_is_idempotent() -> TestResult {
    use std::sync::Arc;

    let (_pg, store) = connect_pg().await?;
    setup_config(&store).await?;
    let repo = Arc::new(PgConfigRepo::new(
        &store,
        fixed_clock_arc(),
        config_protection(),
    ));
    let tenant = config_tenant();
    let key = Arc::new(SettingKey::parse("app.concurrent-delete")?);

    repo.test_put(
        settings_scope(tenant),
        config_entry("app.concurrent-delete", "v1", 1),
    )
    .await?;

    let workers = 12;
    let barrier = Arc::new(tokio::sync::Barrier::new(workers));
    let mut handles = Vec::with_capacity(workers);
    for _ in 0..workers {
        let repo = Arc::clone(&repo);
        let key = Arc::clone(&key);
        let barrier = Arc::clone(&barrier);
        handles.push(tokio::spawn(async move {
            barrier.wait().await;
            repo.test_delete(settings_scope(tenant), &key).await
        }));
    }
    for handle in handles {
        handle.await??;
    }

    assert!(
        repo.find(settings_scope(tenant), &key).await?.is_none(),
        "concurrent delete leaves key deleted"
    );
    assert_eq!(
        repo.head(settings_scope(tenant), &key).await?,
        Some(ConfigHead::Deleted(2)),
        "only one tombstone version is appended"
    );
    let tombstones: (i64,) = sqlx::query_as(
        "SELECT count(*) FROM config_entries WHERE tenant_id = $1::uuid AND config_key = $2 AND deleted",
    )
    .bind(CONFIG_TENANT)
    .bind(key.as_str())
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(tombstones.0, 1, "delete/delete race creates one tombstone");

    store.shutdown().await?;
    Ok(())
}

/// tc5：co-tx commit → config 行 + outbox 行皆在（OUTBOX-COTX-CONFIG-01 正向）。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn tc5_config_cotx_commits_config_and_outbox() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_config(&store).await?;
    let repo = PgConfigRepo::new(&store, fixed_clock_arc(), config_protection());
    let tenant = config_tenant();
    let event_id = unique_event_id("cfg-tc5-evt");
    let plain_value = "settings-value-must-not-leak";

    repo.commit_publish(
        settings::config_publish_receipt_for_test(),
        settings_scope(tenant),
        ConfigMutation::Put(config_entry("app.k", plain_value, 1)),
        reviewed_generated_event::<generated::event::settings_v1::Contract>(
            config_outbox_entry(&event_id),
            config_envelope("app.k"),
        )
        .await?,
    )
    .await?;

    // config 行：恰 1（v1），且 tenant_id 正确落库（tenant-correct，co-tx SET LOCAL + 显式列写入；对齐 t11）。
    let crow: (i64, String) = sqlx::query_as(
        "SELECT count(*), max(tenant_id::text) FROM config_entries WHERE config_key = $1 AND version = 1",
    )
    .bind("app.k")
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(crow.0, 1, "config 行应写入");
    assert_eq!(
        crow.1, CONFIG_TENANT,
        "config 行 tenant_id（tenant-correct）"
    );
    // outbox 行：恰 1。
    let ob_cnt: (i64,) = sqlx::query_as("SELECT count(*) FROM outbox WHERE event_id = $1")
        .bind(&event_id)
        .fetch_one(&store.pool)
        .await?;
    assert_eq!(ob_cnt.0, 1, "outbox 行应写入（co-tx 两行皆在）");
    let outbox_shape: (Vec<u8>, String, String, String) = sqlx::query_as(
        "SELECT payload, metadata::text, contract_version, schema_hash FROM outbox WHERE event_id = $1",
    )
    .bind(&event_id)
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(outbox_shape.2, "v1", "config co-tx contract_version 物理列");
    assert_eq!(
        outbox_shape.3,
        config_contract().schema_hash(),
        "config co-tx schema_hash 物理列"
    );
    assert!(
        !outbox_shape
            .0
            .windows(plain_value.len())
            .any(|window| window == plain_value.as_bytes()),
        "config publish payload 不得包含 ConfigValue plaintext: {}",
        String::from_utf8_lossy(&outbox_shape.0)
    );
    assert!(
        !outbox_shape.1.contains(plain_value),
        "config publish metadata 不得包含 ConfigValue plaintext: {}",
        outbox_shape.1
    );
    // #262 F1：settings config co-tx outbox metadata 含构造期注入的 occurred_at（第三装配点，从注入 Clock）。
    let cfg_meta: (String,) =
        sqlx::query_as("SELECT metadata::text FROM outbox WHERE event_id = $1")
            .bind(&event_id)
            .fetch_one(&store.pool)
            .await?;
    assert!(
        cfg_meta
            .0
            .replace(' ', "")
            .contains(&format!(r#""occurredAt":{}"#, expected_occurred_at())),
        "config co-tx outbox metadata 应含构造期注入的 occurred_at: {}",
        cfg_meta.0
    );
    assert_metadata_text_has_standard_schema_header(
        &cfg_meta.0,
        config_contract().schema_hash(),
        "config co-tx outbox",
    );
    // 值经 find 取回正确。
    assert_eq!(
        repo.find(settings_scope(tenant), &SettingKey::parse("app.k").unwrap())
            .await?
            .unwrap()
            .value(),
        plain_value
    );

    store.shutdown().await?;
    Ok(())
}

/// PG-CONFIG-AMBIENT-CORRELATION-01: the config co-transaction must persist ambient correlation
/// only while `commit_publish` is polled inside the diagnostic scope.
#[tokio::test(flavor = "multi_thread")]
async fn tc5f_config_cotx_persists_only_scoped_ambient_correlation() -> TestResult {
    const CORRELATION: &str = "pg-config-correlation-1399";

    let (_pg, store) = connect_pg().await?;
    setup_config(&store).await?;
    let repo = PgConfigRepo::new(&store, fixed_clock_arc(), config_protection());
    let tenant = config_tenant();
    let scoped_event_id = unique_event_id("cfg-tc5f-scoped");
    let unscoped_event_id = unique_event_id("cfg-tc5f-unscoped");

    let scoped_commit = repo.commit_publish(
        settings::config_publish_receipt_for_test(),
        settings_scope(tenant),
        ConfigMutation::Put(config_entry("app.correlation-scoped", "scoped", 1)),
        reviewed_generated_event::<generated::event::settings_v1::Contract>(
            config_outbox_entry(&scoped_event_id),
            config_envelope("app.correlation-scoped"),
        )
        .await?,
    );
    diagctx::scope(
        diagctx::DiagnosticCtx::new(diagctx::CorrelationId::parse(CORRELATION)?),
        scoped_commit,
    )
    .await?;

    repo.commit_publish(
        settings::config_publish_receipt_for_test(),
        settings_scope(tenant),
        ConfigMutation::Put(config_entry("app.correlation-unscoped", "unscoped", 1)),
        reviewed_generated_event::<generated::event::settings_v1::Contract>(
            config_outbox_entry(&unscoped_event_id),
            config_envelope("app.correlation-unscoped"),
        )
        .await?,
    )
    .await?;

    let scoped_metadata: serde_json::Value =
        sqlx::query_scalar("SELECT metadata FROM outbox WHERE event_id = $1")
            .bind(&scoped_event_id)
            .fetch_one(&store.pool)
            .await?;
    assert_eq!(
        scoped_metadata
            .get("correlation")
            .and_then(serde_json::Value::as_str),
        Some(CORRELATION),
        "scoped config co-transaction must persist the exact ambient correlation: {scoped_metadata}"
    );

    let unscoped_metadata: serde_json::Value =
        sqlx::query_scalar("SELECT metadata FROM outbox WHERE event_id = $1")
            .bind(&unscoped_event_id)
            .fetch_one(&store.pool)
            .await?;
    assert!(
        unscoped_metadata.get("correlation").is_none(),
        "scope completion must not leak correlation into a later config co-transaction: {unscoped_metadata}"
    );

    store.shutdown().await?;
    Ok(())
}

/// Delete 分支同样必须原子提交 tombstone 与唯一 deletion fact；CAS 失败时两者皆不落库。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn tc5d_config_delete_cotx_is_both_or_neither() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_config(&store).await?;
    let repo = PgConfigRepo::new(&store, fixed_clock_arc(), config_protection());
    let tenant = config_tenant();
    let key = SettingKey::parse("app.delete-cotx").unwrap();
    repo.test_put(
        settings_scope(tenant),
        config_entry("app.delete-cotx", "v1", 1),
    )
    .await?;

    let deleted_event = unique_event_id("cfg-tc5d-deleted");
    repo.commit_delete(
        settings::config_delete_receipt_for_test(),
        settings_scope(tenant),
        ConfigMutation::Delete(ConfigTombstone::hydrate(key.clone(), tenant, 2)),
        reviewed_generated_event::<generated::event::settings_v1::Contract>(
            config_deleted_outbox_entry(&deleted_event, key.as_str(), 2),
            config_envelope(key.as_str()),
        )
        .await?,
    )
    .await?;
    assert_eq!(
        repo.head(settings_scope(tenant), &key).await?,
        Some(ConfigHead::Deleted(2))
    );
    let deleted_rows: (i64,) = sqlx::query_as(
        "SELECT count(*) FROM config_entries WHERE tenant_id = $1::uuid AND config_key = $2 AND version = 2 AND deleted",
    )
    .bind(CONFIG_TENANT)
    .bind(key.as_str())
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(deleted_rows.0, 1, "delete commit writes one tombstone");
    let deletion_fact: (Vec<u8>,) =
        sqlx::query_as("SELECT payload FROM outbox WHERE event_id = $1")
            .bind(&deleted_event)
            .fetch_one(&store.pool)
            .await?;
    let payload: serde_json::Value = serde_json::from_slice(&deletion_fact.0)?;
    assert_eq!(payload["changeKind"], "deleted");
    assert_eq!(payload["key"], key.as_str());
    assert_eq!(payload["version"], 2);

    let conflict_event = unique_event_id("cfg-tc5d-conflict");
    let conflict = repo
        .commit_delete(
            settings::config_delete_receipt_for_test(),
            settings_scope(tenant),
            ConfigMutation::Delete(ConfigTombstone::hydrate(key.clone(), tenant, 3)),
            reviewed_generated_event::<generated::event::settings_v1::Contract>(
                config_deleted_outbox_entry(&conflict_event, key.as_str(), 3),
                config_envelope(key.as_str()),
            )
            .await?,
        )
        .await;
    assert!(matches!(conflict, Err(ConfigRepoError::VersionConflict)));
    let conflict_rows: (i64,) = sqlx::query_as("SELECT count(*) FROM outbox WHERE event_id = $1")
        .bind(&conflict_event)
        .fetch_one(&store.pool)
        .await?;
    assert_eq!(conflict_rows.0, 0, "failed delete writes no outbox fact");
    assert_eq!(
        repo.head(settings_scope(tenant), &key).await?,
        Some(ConfigHead::Deleted(2)),
        "failed delete appends no tombstone"
    );

    store.shutdown().await?;
    Ok(())
}

/// Embedded tenant carriers are rejected before issuing their operation SQL. The transaction is
/// first placed in the aborted state: any attempted SQL would return SQLSTATE 25P02 instead of the
/// typed carrier mismatch below.
#[tokio::test(flavor = "multi_thread")]
async fn eventing_facade_rejects_embedded_tenant_mismatch_before_sql() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;
    let tenant_a = vocab::TenantId::parse(COTX_TENANT_A)?;
    let tenant_b = vocab::TenantId::parse(COTX_TENANT_B)?;
    let event_id = unique_event_id("inbox-embedded-tenant-mismatch");
    let observed_event_id = event_id.clone();
    let saga_id = uuid::Uuid::new_v4();
    let observed_saga_id = saga_id.to_string();
    let saga_instance =
        consistency::SagaInstanceRef::new(tenant_b, consistency::SagaId::new(saga_id))?;
    let registration =
        crate::saga::RegistrationFields::from(diport::SagaInstanceRegistration::new(
            saga_instance,
            diport::SagaWorkerIdentity::new(
                "embedded-tenant-mismatch",
                diport::SagaContractId::parse("test.saga")?,
            )?,
            consistency::SagaDefinitionIdentity::new(
                "test.saga",
                "v1",
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            )?,
        )?);
    let instance = crate::saga::InstanceFields {
        instance: saga_instance,
        saga_id: observed_saga_id.clone(),
    };
    let claim = crate::saga::ClaimFields {
        instance: saga_instance,
        saga_id: observed_saga_id.clone(),
        owner: "embedded-tenant-mismatch".to_string(),
        contract_id: "test.saga".to_string(),
        definition_version: "v1".to_string(),
        definition_schema_digest:
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
        action_registry_generation:
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(),
        expected_status: "ready".to_string(),
        holder_id: "holder".to_string(),
        ttl_micros: 30_000_000,
    };
    let lease = crate::saga::LeaseFields {
        instance: saga_instance,
        saga_id: observed_saga_id.clone(),
        lease_token: uuid::Uuid::new_v4().to_string(),
        epoch: 1,
    };
    let journal = crate::saga::JournalEntryFields {
        seq: 1,
        step_name: "embedded-tenant-mismatch".to_string(),
        status: "forward_intent".to_string(),
        error_summary: None,
        attempt: 1,
        effect_key: vec![0x44; 32],
        compensation_cause: None,
    };
    let fields = crate::inbox::ReceiptFields {
        tenant: tenant_b,
        consumer_group: "embedded-tenant-mismatch".to_string(),
        domain: "test".to_string(),
        topic: "test.event".to_string(),
        contract_id: "test.event".to_string(),
        contract_version: "1.0.0".to_string(),
        schema_hash: "sha256:test".to_string(),
        trace: None,
        correlation_id: None,
    };
    let result = store
        .serving_write_fixture::<_, (), sqlx::Error>(tenant_a, move |tx| {
            Box::pin(async move {
                let abort = tx
                    .test_abort_transaction()
                    .await
                    .expect_err("division by zero must abort the backend transaction");
                assert_eq!(
                    abort
                        .as_database_error()
                        .and_then(|error| error.code())
                        .as_deref(),
                    Some("22012")
                );

                for error in [
                    tx.inbox_claim_receipt(&fields, &event_id, COTX_TENANT_B, 30)
                        .await
                        .expect_err("claim must reject the embedded tenant"),
                    match tx.inbox_load_identity(&fields, &event_id).await {
                        Err(error) => error,
                        Ok(_) => panic!("identity load must reject the embedded tenant"),
                    },
                    tx.inbox_extend_receipt(&fields, &event_id, COTX_TENANT_B)
                        .await
                        .expect_err("extend must reject the embedded tenant"),
                    tx.inbox_commit_receipt(&fields, &event_id, COTX_TENANT_B)
                        .await
                        .expect_err("commit must reject the embedded tenant"),
                    tx.inbox_release_receipt(&fields, &event_id, COTX_TENANT_B)
                        .await
                        .expect_err("release must reject the embedded tenant"),
                ] {
                    assert!(
                        error.to_string().contains("inbox receipt tenant"),
                        "mismatch must be returned before SQL, got {error}"
                    );
                }

                for error in [
                    tx.saga_register_instance(&registration)
                        .await
                        .expect_err("registration must reject the embedded tenant"),
                    tx.saga_load_instance(&instance)
                        .await
                        .expect_err("status load must reject the embedded tenant"),
                    match tx.saga_claim(&claim).await {
                        Err(error) => error,
                        Ok(_) => panic!("lease acquisition must reject the embedded tenant"),
                    },
                    tx.saga_cas_lease(&lease, crate::cotx::eventing::SagaLeaseMutation::Release)
                        .await
                        .expect_err("lease mutation must reject the embedded tenant"),
                    tx.saga_insert_journal(&lease, &journal)
                        .await
                        .expect_err("journal insert must reject the embedded tenant"),
                    tx.saga_lease_is_held(&lease)
                        .await
                        .expect_err("lease check must reject the embedded tenant"),
                    match tx.saga_load_journal_entry(&instance, 1).await {
                        Err(error) => error,
                        Ok(_) => panic!("journal load must reject the embedded tenant"),
                    },
                ] {
                    assert!(
                        error.to_string().contains("saga ")
                            && error
                                .to_string()
                                .contains("tenant does not match tenant transaction"),
                        "mismatch must be returned before SQL, got {error}"
                    );
                }

                Err(sqlx::Error::Protocol(
                    "intentional rollback after mismatch proof".to_string(),
                ))
            }) as BoxFuture<'_, Result<(), sqlx::Error>>
        })
        .await;
    assert!(result.is_err(), "proof transaction must roll back");

    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM inbox_receipts WHERE event_id = $1 AND consumer_group = $2",
    )
    .bind(&observed_event_id)
    .bind("embedded-tenant-mismatch")
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(count, 0, "tenant mismatch must not write an inbox receipt");

    let saga_count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM saga_instances WHERE saga_id = $1::uuid")
            .bind(&observed_saga_id)
            .fetch_one(&store.pool)
            .await?;
    assert_eq!(
        saga_count, 0,
        "tenant mismatch must not write a saga instance"
    );

    store.shutdown().await?;
    Ok(())
}

/// Rollback must restore a historical value as a new active version and append exactly one
/// rolledBack fact in the same transaction. A stale version must append neither side.
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn tc5e_config_rollback_cotx_restores_version_and_appends_exact_fact() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_config(&store).await?;
    let repo = PgConfigRepo::new(&store, fixed_clock_arc(), config_protection());
    let tenant = config_tenant();
    let key = SettingKey::parse("app.rollback-cotx").unwrap();

    repo.test_put(
        settings_scope(tenant),
        config_entry(key.as_str(), "historical-v1", 1),
    )
    .await?;
    repo.test_put(
        settings_scope(tenant),
        config_entry(key.as_str(), "current-v2", 2),
    )
    .await?;

    let exact_rollback_fact_count = |rows: &[(Vec<u8>,)]| {
        rows.iter()
            .filter(|(payload,)| {
                serde_json::from_slice::<serde_json::Value>(payload).is_ok_and(|payload| {
                    payload["tenantId"] == tenant.to_string()
                        && payload["key"] == key.as_str()
                        && payload["changeKind"] == "rolledBack"
                        && payload["sourceVersion"] == 1
                        && payload["version"] == 3
                })
            })
            .count()
    };
    let rollback_payloads_before: Vec<(Vec<u8>,)> = sqlx::query_as("SELECT payload FROM outbox")
        .fetch_all(&store.pool)
        .await?;
    let rollback_facts_before = exact_rollback_fact_count(&rollback_payloads_before);

    let rollback_event = unique_event_id("cfg-tc5e-rollback");
    repo.commit_rollback(
        settings::config_rollback_receipt_for_test(),
        settings_scope(tenant),
        ConfigMutation::Put(config_entry(key.as_str(), "historical-v1", 3)),
        reviewed_generated_event::<generated::event::settings_v1::Contract>(
            config_rolled_back_outbox_entry(&rollback_event, key.as_str(), 3, 1),
            config_envelope(key.as_str()),
        )
        .await?,
    )
    .await?;

    let restored = repo
        .find(settings_scope(tenant), &key)
        .await?
        .expect("rollback version must be active");
    assert_eq!(restored.version(), 3);
    assert_eq!(restored.value(), "historical-v1");
    let rollback_payloads_after: Vec<(Vec<u8>,)> = sqlx::query_as("SELECT payload FROM outbox")
        .fetch_all(&store.pool)
        .await?;
    assert_eq!(
        exact_rollback_fact_count(&rollback_payloads_after),
        rollback_facts_before + 1,
        "rollback appends exactly one fact for its tenant/key/version transition"
    );
    let expected_payload: (Vec<u8>,) =
        sqlx::query_as("SELECT payload FROM outbox WHERE event_id = $1")
            .bind(&rollback_event)
            .fetch_one(&store.pool)
            .await?;
    let payload: serde_json::Value = serde_json::from_slice(&expected_payload.0)?;
    assert_eq!(payload["changeKind"], "rolledBack");
    assert_eq!(payload["key"], key.as_str());
    assert_eq!(payload["sourceVersion"], 1);
    assert_eq!(payload["version"], 3);
    let config_rows_after_success: (i64,) = sqlx::query_as(
        "SELECT count(*) FROM config_entries WHERE tenant_id = $1::uuid AND config_key = $2",
    )
    .bind(tenant.to_string())
    .bind(key.as_str())
    .fetch_one(&store.pool)
    .await?;

    let conflict_event = unique_event_id("cfg-tc5e-conflict");
    let conflict = repo
        .commit_rollback(
            settings::config_rollback_receipt_for_test(),
            settings_scope(tenant),
            ConfigMutation::Put(config_entry(key.as_str(), "historical-v1", 3)),
            reviewed_generated_event::<generated::event::settings_v1::Contract>(
                config_rolled_back_outbox_entry(&conflict_event, key.as_str(), 3, 1),
                config_envelope(key.as_str()),
            )
            .await?,
        )
        .await;
    assert!(matches!(conflict, Err(ConfigRepoError::VersionConflict)));
    let conflict_facts: (i64,) = sqlx::query_as("SELECT count(*) FROM outbox WHERE event_id = $1")
        .bind(&conflict_event)
        .fetch_one(&store.pool)
        .await?;
    assert_eq!(conflict_facts.0, 0, "stale rollback writes no fact");
    let rollback_payloads_after_conflict: Vec<(Vec<u8>,)> =
        sqlx::query_as("SELECT payload FROM outbox")
            .fetch_all(&store.pool)
            .await?;
    assert_eq!(
        exact_rollback_fact_count(&rollback_payloads_after_conflict),
        rollback_facts_before + 1,
        "stale rollback appends no second rolledBack fact"
    );
    let config_rows_after_conflict: (i64,) = sqlx::query_as(
        "SELECT count(*) FROM config_entries WHERE tenant_id = $1::uuid AND config_key = $2",
    )
    .bind(tenant.to_string())
    .bind(key.as_str())
    .fetch_one(&store.pool)
    .await?;
    assert_eq!(
        config_rows_after_conflict, config_rows_after_success,
        "stale rollback appends no config version row"
    );
    assert_eq!(
        repo.head(settings_scope(tenant), &key).await?,
        Some(ConfigHead::Active(3)),
        "stale rollback writes no config version"
    );

    store.shutdown().await?;
    Ok(())
}

/// tc5b：config 事务 tenant 与 envelope tenant 不一致 → fail-closed，config / outbox 均不落库。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn tc5b_config_cotx_rejects_envelope_tenant_mismatch() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_config(&store).await?;
    let repo = PgConfigRepo::new(&store, fixed_clock_arc(), config_protection());
    let tenant = config_tenant();
    let event_id = unique_event_id("cfg-tc5b-evt");
    let envelope = OutboxEnvelopeParts::new(
        config_contract(),
        TenantId::parse(CONFIG_TENANT_B).unwrap(),
        subject_id("app.mismatch"),
        actor_for(TenantId::parse(CONFIG_TENANT_B).unwrap()),
    );

    let result = repo
        .commit_publish(
            settings::config_publish_receipt_for_test(),
            settings_scope(tenant),
            ConfigMutation::Put(config_entry("app.mismatch", "v1", 1)),
            reviewed_generated_event::<generated::event::settings_v1::Contract>(
                config_outbox_entry(&event_id),
                envelope,
            )
            .await?,
        )
        .await;
    assert!(
        matches!(result, Err(ConfigRepoError::Storage(_))),
        "config/envelope tenant mismatch must fail closed as storage boundary error"
    );

    let cfg_cnt: (i64,) =
        sqlx::query_as("SELECT count(*) FROM config_entries WHERE config_key = $1")
            .bind("app.mismatch")
            .fetch_one(&store.pool)
            .await?;
    assert_eq!(cfg_cnt.0, 0, "mismatch 不得写 config 行");
    let ob_cnt: (i64,) = sqlx::query_as("SELECT count(*) FROM outbox WHERE event_id = $1")
        .bind(&event_id)
        .fetch_one(&store.pool)
        .await?;
    assert_eq!(ob_cnt.0, 0, "mismatch 不得写 outbox 行");

    store.shutdown().await?;
    Ok(())
}

/// tc5c：config entry tenant 与 repo scope tenant 不一致 → fail-closed，config / outbox 均不落库。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn tc5c_config_cotx_rejects_scope_entry_tenant_mismatch() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_config(&store).await?;
    let repo = PgConfigRepo::new(&store, fixed_clock_arc(), config_protection());
    let scope_tenant = config_tenant();
    let entry_tenant = TenantId::parse(CONFIG_TENANT_B).unwrap();
    let event_id = unique_event_id("cfg-tc5c-evt");
    let key = "app.scope-entry-mismatch";

    let result = repo
        .commit_publish(
            settings::config_publish_receipt_for_test(),
            settings_scope(scope_tenant),
            ConfigMutation::Put(config_entry_for(entry_tenant, key, "v1", 1)),
            reviewed_generated_event::<generated::event::settings_v1::Contract>(
                config_outbox_entry(&event_id),
                config_envelope(key),
            )
            .await?,
        )
        .await;
    assert!(
        matches!(result, Err(ConfigRepoError::Storage(_))),
        "config entry/scope tenant mismatch must fail closed as storage boundary error"
    );

    let cfg_cnt: (i64,) =
        sqlx::query_as("SELECT count(*) FROM config_entries WHERE config_key = $1")
            .bind(key)
            .fetch_one(&store.pool)
            .await?;
    assert_eq!(cfg_cnt.0, 0, "scope mismatch 不得写 config 行");
    let ob_cnt: (i64,) = sqlx::query_as("SELECT count(*) FROM outbox WHERE event_id = $1")
        .bind(&event_id)
        .fetch_one(&store.pool)
        .await?;
    assert_eq!(ob_cnt.0, 0, "scope mismatch 不得写 outbox 行");

    store.shutdown().await?;
    Ok(())
}

/// tc6：producer tx 业务写后强制 Err → config 行 + outbox 行**共回滚**（both-or-neither）。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn tc6_config_cotx_business_failure_rolls_back_both() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_config(&store).await?;
    let tenant = config_tenant();
    let event_id = unique_event_id("cfg-tc6-evt");
    let entry = config_outbox_entry(&event_id);
    let env = OutboxEnvelope::new(
        "settings".to_string(),
        CONFIG_VERSION_CHANGED_TOPIC.to_string(),
        OutboxMetadata::new(0, test_tenant(), test_contract())
            .with_subject_id(subject_id("app.rollback")),
    );
    let tenant_pool = TenantDb::<ServingWriteLane>::from_unverified_for_test(&store);
    let (mutation, encoded) = encrypted_config_fixture("app.rollback");

    // 业务写：真插一行 config（成功）后强制 Err（模拟「配置写后、后续步骤失败」= emit/commit 失败等价物）。
    let result = tenant_pool
        .retry_config_producer_tx(
            settings_scope(tenant),
            crate::tx_retry::localtx_deadline_for_test(),
            crate::cotx::settings_audit::ConfigProducerRequest::new(&entry, &env),
            move |mut conn| {
                Box::pin(async move {
                    conn.apply_mutation(&mutation, &encoded).await?;
                    Err::<
                        crate::cotx::ProducerTxOutcome<
                            httpserve::ProducerAuthorization<
                                generated::http::settings_v1::RouteMarker,
                            >,
                            (),
                        >,
                        ConfigRepoError,
                    >(ConfigRepoError::VersionConflict)
                })
            },
            |e| ConfigRepoError::Storage(Box::new(e)),
        )
        .await
        .into_result();
    assert!(matches!(result, Err(ConfigRepoError::VersionConflict)));

    // both-or-neither：config 行回滚（不落库）+ outbox 行不落库。
    let cfg_cnt: (i64,) =
        sqlx::query_as("SELECT count(*) FROM config_entries WHERE config_key = $1")
            .bind("app.rollback")
            .fetch_one(&store.pool)
            .await?;
    assert_eq!(cfg_cnt.0, 0, "业务写失败 → 配置行回滚（不落库）");
    let ob_cnt: (i64,) = sqlx::query_as("SELECT count(*) FROM outbox WHERE event_id = $1")
        .bind(&event_id)
        .fetch_one(&store.pool)
        .await?;
    assert_eq!(
        ob_cnt.0, 0,
        "业务写失败 → outbox 行不落库（both-or-neither）"
    );

    store.shutdown().await?;
    Ok(())
}

/// A typed entry for another generated fact must not consume config authorization. The business
/// mutation has already run, so the mismatch exercises the transaction rollback boundary rather
/// than a preflight-only rejection.
#[tokio::test(flavor = "multi_thread")]
async fn producer_fact_binding_mismatch_rolls_back_business_write() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_config(&store).await?;
    let tenant = config_tenant();
    let event_id = unique_event_id("producer-fact-binding-mismatch");
    let entry = generated_entry(
        generated::event::identity_v1::session_created::FACT,
        &generated::event::identity_v1::session_created::IdentitySessionCreatedPayload {
            session_id: uuid::Uuid::from_u128(1),
            subject: uuid::Uuid::from_u128(2),
            tenant_id: tenant.as_uuid(),
            occurred_at: i64::try_from(TEST_OCCURRED_SECS)?,
        },
        IdemKey::parse(&event_id)?,
    )?;
    let contract = settings::ports::CONFIG_VERSION_CHANGED_CONTRACT;
    let env = OutboxEnvelope::new(
        contract.domain().to_string(),
        contract.contract_id().to_string(),
        OutboxMetadata::new(i64::try_from(TEST_OCCURRED_SECS)?, tenant, contract)
            .with_subject_id(subject_id("app.fact-binding-mismatch")),
    );
    let authorization = settings::config_publish_receipt_for_test()
        .authorize(
            generated::event::settings_v1::FACT,
            settings::ports::CONFIG_VERSION_CHANGED_CONTRACT,
        )
        .ok_or_else(|| std::io::Error::other("config producer authorization missing"))?;

    let (mutation, encoded) = encrypted_config_fixture("app.fact-binding-mismatch");
    let result = TenantDb::<ServingWriteLane>::from_unverified_for_test(&store)
        .retry_config_producer_tx(
            settings_scope(tenant),
            crate::tx_retry::localtx_deadline_for_test(),
            crate::cotx::settings_audit::ConfigProducerRequest::new(&entry, &env),
            move |mut tx| {
                Box::pin(async move {
                    tx.apply_mutation(&mutation, &encoded).await?;
                    Ok(crate::cotx::ProducerTxOutcome::Emitted((), authorization))
                })
            },
            |error| ConfigRepoError::Storage(Box::new(error)),
        )
        .await
        .into_result();
    assert!(
        matches!(result, Err(ConfigRepoError::Storage(_))),
        "fact binding mismatch must fail closed: {result:?}"
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM config_entries WHERE config_key = $1")
            .bind("app.fact-binding-mismatch")
            .fetch_one(&store.pool)
            .await?,
        0,
        "authorization mismatch must roll back the business mutation"
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM outbox WHERE event_id = $1")
            .bind(&event_id)
            .fetch_one(&store.pool)
            .await?,
        0,
        "authorization mismatch must not append an outbox row"
    );

    store.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn config_fact_conflict_rolls_back_mutation() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_config(&store).await?;
    let tenant = config_tenant();
    let event_id = unique_event_id("config-fact-conflict");
    let key = "app.fact-conflict";
    let seed = seed_conflicting_outbox_fact(&store, tenant, &event_id).await?;
    let repo = PgConfigRepo::new(&store, fixed_clock_arc(), config_protection());

    let conflict = repo
        .commit_publish(
            settings::config_publish_receipt_for_test(),
            settings_scope(tenant),
            ConfigMutation::Put(config_entry(key, "must-rollback", 1)),
            reviewed_generated_event::<generated::event::settings_v1::Contract>(
                config_outbox_entry(&event_id),
                config_envelope(key),
            )
            .await?,
        )
        .await;
    assert!(
        matches!(conflict, Err(ConfigRepoError::OutboxFactConflict(_))),
        "config adapter must preserve typed fact conflict: {conflict:?}"
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM config_entries WHERE config_key = $1")
            .bind(key)
            .fetch_one(&store.pool)
            .await?,
        0,
        "outbox conflict must roll back the config mutation"
    );
    assert_seed_fact_unchanged(&store, &event_id, &seed).await?;

    store.shutdown().await?;
    Ok(())
}

/// tc7：**真实 method** `commit` 的 CAS 冲突分支 → VersionConflict 且**无 outbox 行**
/// （write-without-event 不发生）；原版本不被覆盖。
///
/// 与 tc6（直测 `producer_tx` 骨架的业务写失败回滚）互补：tc7 驱动**真实 method** 的 rollback 路径
/// （CAS Err → 整事务回滚 → outbox 不落库），对齐 session t14「直测真实 method rollback 分支」范式，消除 tc6
/// 仅测骨架的盲区——OUTBOX-COTX-CONFIG-01 anti-vacuity（正向 tc5 ↔ 负向 tc6+tc7）由此闭合。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn tc7_config_cotx_cas_conflict_emits_no_outbox() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_config(&store).await?;
    let repo = PgConfigRepo::new(&store, fixed_clock_arc(), config_protection());
    let tenant = config_tenant();

    repo.test_put(settings_scope(tenant), config_entry("app.k", "v1", 1))
        .await?;

    // 以陈旧 v1 走 co-tx → CAS 冲突 → 整事务回滚（无 outbox 行）。
    let event_id = unique_event_id("cfg-tc7-evt");
    let result = repo
        .commit_publish(
            settings::config_publish_receipt_for_test(),
            settings_scope(tenant),
            ConfigMutation::Put(config_entry("app.k", "v1-stale", 1)),
            reviewed_generated_event::<generated::event::settings_v1::Contract>(
                config_outbox_entry(&event_id),
                config_envelope("app.k"),
            )
            .await?,
        )
        .await;
    assert!(matches!(result, Err(ConfigRepoError::VersionConflict)));

    let ob_cnt: (i64,) = sqlx::query_as("SELECT count(*) FROM outbox WHERE event_id = $1")
        .bind(&event_id)
        .fetch_one(&store.pool)
        .await?;
    assert_eq!(
        ob_cnt.0, 0,
        "CAS 冲突 → 无 outbox 行（write-without-event 不发生）"
    );
    // 原 v1 不被覆盖。
    assert_eq!(
        repo.find(settings_scope(tenant), &SettingKey::parse("app.k").unwrap())
            .await?
            .unwrap()
            .value(),
        "v1",
        "冲突写不覆盖原值"
    );

    store.shutdown().await?;
    Ok(())
}

/// tc7b：`PgConfigRepo` 接入 L2 co-tx conformance：commit 两边皆在；业务失败两边皆无；CAS 冲突无 outbox。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn tc7b_config_cotx_conformance() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_config(&store).await?;
    let repo = PgConfigRepo::new(&store, fixed_clock_arc(), config_protection());
    let tenant = config_tenant();
    let ok_event = unique_event_id("cfg-tc7b-ok");
    let rollback_event = unique_event_id("cfg-tc7b-rollback");
    let conflict_event = unique_event_id("cfg-tc7b-conflict");
    let tenant_pool = TenantDb::<ServingWriteLane>::from_unverified_for_test(&store);

    repo.test_put(
        settings_scope(tenant),
        config_entry("app.cotx-conflict", "v1", 1),
    )
    .await?;

    testkit::repo_conformance::assert_cotx_both_or_neither(
        testkit::repo_conformance::CotxCase {
            action: || async {
                repo.commit_publish(
                    settings::config_publish_receipt_for_test(),
                    settings_scope(tenant),
                    ConfigMutation::Put(config_entry("app.cotx-ok", "v1", 1)),
                    reviewed_generated_event::<generated::event::settings_v1::Contract>(
                        config_outbox_entry(&ok_event),
                        config_envelope("app.cotx-ok"),
                    )
                    .await
                    .map_err(ConfigRepoError::Storage)?,
                )
                .await
            },
            business_exists: || async {
                let key = SettingKey::parse("app.cotx-ok")
                    .map_err(|e| ConfigRepoError::Storage(Box::new(e)))?;
                repo.find(settings_scope(tenant), &key)
                    .await
                    .map(|entry| entry.is_some_and(|entry| entry.value() == "v1"))
            },
            outbox_exists: || async {
                let cnt: (i64,) = sqlx::query_as("SELECT count(*) FROM outbox WHERE event_id = $1")
                    .bind(&ok_event)
                    .fetch_one(&store.pool)
                    .await
                    .map_err(|e| ConfigRepoError::Storage(Box::new(e)))?;
                Ok::<bool, ConfigRepoError>(cnt.0 == 1)
            },
        },
        testkit::repo_conformance::CotxCase {
            action: || async {
                let entry = config_outbox_entry(&rollback_event);
                let env = OutboxEnvelope::new(
                    "settings".to_string(),
                    CONFIG_VERSION_CHANGED_TOPIC.to_string(),
                    OutboxMetadata::new(0, test_tenant(), test_contract())
                        .with_subject_id(subject_id("app.cotx-rollback")),
                );
                let (mutation, encoded) = encrypted_config_fixture("app.cotx-rollback");
                tenant_pool
                    .retry_config_producer_tx(
                        settings_scope(tenant),
                        crate::tx_retry::localtx_deadline_for_test(),
                        crate::cotx::settings_audit::ConfigProducerRequest::new(&entry, &env),
                        move |mut conn| {
                            Box::pin(async move {
                                conn.apply_mutation(&mutation, &encoded).await?;
                                Err::<
                                    crate::cotx::ProducerTxOutcome<
                                        httpserve::ProducerAuthorization<
                                            generated::http::settings_v1::RouteMarker,
                                        >,
                                        (),
                                    >,
                                    ConfigRepoError,
                                >(ConfigRepoError::VersionConflict)
                            })
                        },
                        |e| ConfigRepoError::Storage(Box::new(e)),
                    )
                    .await
                    .into_result()
            },
            business_exists: || async {
                let cnt: (i64,) =
                    sqlx::query_as("SELECT count(*) FROM config_entries WHERE config_key = $1")
                        .bind("app.cotx-rollback")
                        .fetch_one(&store.pool)
                        .await
                        .map_err(|e| ConfigRepoError::Storage(Box::new(e)))?;
                Ok::<bool, ConfigRepoError>(cnt.0 == 1)
            },
            outbox_exists: || async {
                let cnt: (i64,) = sqlx::query_as("SELECT count(*) FROM outbox WHERE event_id = $1")
                    .bind(&rollback_event)
                    .fetch_one(&store.pool)
                    .await
                    .map_err(|e| ConfigRepoError::Storage(Box::new(e)))?;
                Ok::<bool, ConfigRepoError>(cnt.0 == 1)
            },
        },
        testkit::repo_conformance::CotxCase {
            action: || async {
                repo.commit_publish(
                    settings::config_publish_receipt_for_test(),
                    settings_scope(tenant),
                    ConfigMutation::Put(config_entry("app.cotx-conflict", "stale", 1)),
                    reviewed_generated_event::<generated::event::settings_v1::Contract>(
                        config_outbox_entry(&conflict_event),
                        config_envelope("app.cotx-conflict"),
                    )
                    .await
                    .map_err(ConfigRepoError::Storage)?,
                )
                .await
            },
            business_exists: || async {
                let key = SettingKey::parse("app.cotx-conflict")
                    .map_err(|e| ConfigRepoError::Storage(Box::new(e)))?;
                repo.find(settings_scope(tenant), &key)
                    .await
                    .map(|entry| entry.is_some_and(|entry| entry.value() == "stale"))
            },
            outbox_exists: || async {
                let cnt: (i64,) = sqlx::query_as("SELECT count(*) FROM outbox WHERE event_id = $1")
                    .bind(&conflict_event)
                    .fetch_one(&store.pool)
                    .await
                    .map_err(|e| ConfigRepoError::Storage(Box::new(e)))?;
                Ok::<bool, ConfigRepoError>(cnt.0 == 1)
            },
        },
        |e| matches!(e, ConfigRepoError::VersionConflict),
    )
    .await?;

    store.shutdown().await?;
    Ok(())
}

/// tc7c：settings config 的 Postgres retry 边界 conformance。
///
/// transient：第一轮事务内写 config + outbox 后返回 transient storage error，必须整体 rollback；第二轮重建
/// 事务后提交，最终 config/outbox 各 1 行。conflict/permanent：不重试、不提交副作用。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn tc7c_config_retry_boundary_conformance() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_config(&store).await?;
    let repo = PgConfigRepo::new(&store, fixed_clock_arc(), config_protection());
    let tenant = config_tenant();
    let transient_event = unique_event_id("cfg-tc7c-transient");
    let conflict_event = unique_event_id("cfg-tc7c-conflict");
    let permanent_event = unique_event_id("cfg-tc7c-permanent");
    let exhaustion_event = unique_event_id("cfg-tc7c-exhaustion");
    repo.test_put(
        settings_scope(tenant),
        config_entry("app.retry-conflict", "v1", 1),
    )
    .await?;

    testkit::repo_conformance::assert_retry_boundary_policy(
        testkit::repo_conformance::RetryBoundaryCase::new(
            testkit::repo_conformance::TransientSuccessPath::new(
                || {
                    let repo = &repo;
                    let transient_event = transient_event.clone();
                    arm_config_retry_failpoint("app.retry-transient", 1);
                    async move {
                        repo.commit_publish(
                            settings::config_publish_receipt_for_test(),
                            settings_scope(tenant),
                            ConfigMutation::Put(config_entry("app.retry-transient", "v1", 1)),
                            reviewed_generated_event::<generated::event::settings_v1::Contract>(
                                config_outbox_entry(&transient_event),
                                config_envelope("app.retry-transient"),
                            )
                            .await
                            .map_err(ConfigRepoError::Storage)?,
                        )
                        .await
                    }
                },
                config_retry_attempts,
                2,
                || async {
                    let cfg: (i64,) =
                        sqlx::query_as("SELECT count(*) FROM config_entries WHERE config_key = $1")
                            .bind("app.retry-transient")
                            .fetch_one(&store.pool)
                            .await
                            .map_err(|e| ConfigRepoError::Storage(Box::new(e)))?;
                    let outbox: (i64,) =
                        sqlx::query_as("SELECT count(*) FROM outbox WHERE event_id = $1")
                            .bind(&transient_event)
                            .fetch_one(&store.pool)
                            .await
                            .map_err(|e| ConfigRepoError::Storage(Box::new(e)))?;
                    Ok::<usize, ConfigRepoError>(usize::from(cfg.0 == 1 && outbox.0 == 1))
                },
            ),
            testkit::repo_conformance::ConflictPath::new(
                || {
                    let repo = &repo;
                    let conflict_event = conflict_event.clone();
                    arm_config_retry_failpoint("app.retry-conflict", 0);
                    async move {
                        repo.commit_publish(
                            settings::config_publish_receipt_for_test(),
                            settings_scope(tenant),
                            ConfigMutation::Put(config_entry("app.retry-conflict", "stale", 1)),
                            reviewed_generated_event::<generated::event::settings_v1::Contract>(
                                config_outbox_entry(&conflict_event),
                                config_envelope("app.retry-conflict"),
                            )
                            .await
                            .map_err(ConfigRepoError::Storage)?,
                        )
                        .await
                    }
                },
                config_retry_attempts,
                || async {
                    let cfg: (i64,) = sqlx::query_as(
                        "SELECT count(*) FROM config_entries WHERE config_key = $1 AND value = $2",
                    )
                    .bind("app.retry-conflict")
                    .bind("stale")
                    .fetch_one(&store.pool)
                    .await
                    .map_err(|e| ConfigRepoError::Storage(Box::new(e)))?;
                    let outbox: (i64,) =
                        sqlx::query_as("SELECT count(*) FROM outbox WHERE event_id = $1")
                            .bind(&conflict_event)
                            .fetch_one(&store.pool)
                            .await
                            .map_err(|e| ConfigRepoError::Storage(Box::new(e)))?;
                    Ok::<usize, ConfigRepoError>(usize::from(cfg.0 != 0 || outbox.0 != 0))
                },
            ),
            testkit::repo_conformance::PermanentPath::new(
                || {
                    arm_config_retry_permanent_failpoint("app.retry-permanent");
                    async {
                        repo.commit_publish(
                            settings::config_publish_receipt_for_test(),
                            settings_scope(tenant),
                            ConfigMutation::Put(config_entry("app.retry-permanent", "v1", 1)),
                            reviewed_generated_event::<generated::event::settings_v1::Contract>(
                                config_outbox_entry(&permanent_event),
                                config_envelope("app.retry-permanent"),
                            )
                            .await
                            .map_err(ConfigRepoError::Storage)?,
                        )
                        .await
                    }
                },
                config_retry_attempts,
                || async {
                    let cfg: (i64,) =
                        sqlx::query_as("SELECT count(*) FROM config_entries WHERE config_key = $1")
                            .bind("app.retry-permanent")
                            .fetch_one(&store.pool)
                            .await
                            .map_err(|e| ConfigRepoError::Storage(Box::new(e)))?;
                    let outbox: (i64,) =
                        sqlx::query_as("SELECT count(*) FROM outbox WHERE event_id = $1")
                            .bind(&permanent_event)
                            .fetch_one(&store.pool)
                            .await
                            .map_err(|e| ConfigRepoError::Storage(Box::new(e)))?;
                    Ok::<usize, ConfigRepoError>(usize::from(cfg.0 != 0 || outbox.0 != 0))
                },
            ),
            testkit::repo_conformance::TransientExhaustionPath::new(
                || {
                    let repo = &repo;
                    let exhaustion_event = exhaustion_event.clone();
                    arm_config_retry_failpoint("app.retry-exhaustion", 3);
                    async move {
                        repo.commit_publish(
                            settings::config_publish_receipt_for_test(),
                            settings_scope(tenant),
                            ConfigMutation::Put(config_entry("app.retry-exhaustion", "v1", 1)),
                            reviewed_generated_event::<generated::event::settings_v1::Contract>(
                                config_outbox_entry(&exhaustion_event),
                                config_envelope("app.retry-exhaustion"),
                            )
                            .await
                            .map_err(ConfigRepoError::Storage)?,
                        )
                        .await
                    }
                },
                config_retry_attempts,
                3,
                || async {
                    let cfg: (i64,) =
                        sqlx::query_as("SELECT count(*) FROM config_entries WHERE config_key = $1")
                            .bind("app.retry-exhaustion")
                            .fetch_one(&store.pool)
                            .await
                            .map_err(|e| ConfigRepoError::Storage(Box::new(e)))?;
                    let outbox: (i64,) =
                        sqlx::query_as("SELECT count(*) FROM outbox WHERE event_id = $1")
                            .bind(&exhaustion_event)
                            .fetch_one(&store.pool)
                            .await
                            .map_err(|e| ConfigRepoError::Storage(Box::new(e)))?;
                    Ok::<usize, ConfigRepoError>(usize::from(cfg.0 != 0 || outbox.0 != 0))
                },
            ),
        ),
        |error| conformance_retry_category(classify_config_repo_error(error)),
    )
    .await?;

    store.shutdown().await?;
    Ok(())
}

/// tc8：storage 错误通道——关池后 find 返回 `ConfigRepoError::Storage`（基础设施错误分层映射，保留 source）。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn tc8_config_find_maps_storage_error() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_config(&store).await?;
    let repo = PgConfigRepo::new(&store, fixed_clock_arc(), config_protection());
    let tenant = config_tenant();
    let key = SettingKey::parse("app.k").unwrap();

    testkit::repo_conformance::assert_storage_error_mapping(
        || async { store.shutdown().await },
        || async { repo.find(settings_scope(tenant), &key).await.map(|_| ()) },
        |e| matches!(e, ConfigRepoError::Storage(_)),
    )
    .await?;

    Ok(())
}

/// tc9：**跨租户隔离**——tenant A 的配置对 tenant B 不可见，独立版本空间，delete 互不影响。
///
/// tc9 以 owner/superuser 连接（绕过 RLS）验证显式 `WHERE tenant_id` 子句隔离；0009 落地后
/// config_entries 已有 RLS policy，DB 层 RLS 强制力由 t21（rss_app 角色）专门覆盖，二者互补
/// （in-mem 路径由 `application.rs::cross_tenant_isolation` 守，实现不同）。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn tc9_config_cross_tenant_isolation() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_config(&store).await?;
    let repo = PgConfigRepo::new(&store, fixed_clock_arc(), config_protection());
    let tenant_a = config_tenant();
    let tenant_b = TenantId::parse(CONFIG_TENANT_B).unwrap();
    let key = SettingKey::parse("app.k").unwrap();

    testkit::repo_conformance::assert_tenant_scoped_repo(
        testkit::repo_conformance::TenantScopedCase {
            tenant_a,
            tenant_b,
            a_marker: "a-secret".to_string(),
            b_marker: "b-value".to_string(),
            save: |tenant, version, marker: String| {
                let repo = &repo;
                async move {
                    repo.test_put(
                        settings_scope(tenant),
                        ConfigEntry::hydrate(
                            SettingKey::parse("app.k").unwrap(),
                            &marker,
                            tenant,
                            version,
                        ),
                    )
                    .await
                }
            },
            delete: |tenant| {
                let repo = &repo;
                let key = &key;
                async move { repo.test_delete(settings_scope(tenant), key).await }
            },
            current: |tenant| {
                let repo = &repo;
                let key = &key;
                async move {
                    repo.find(settings_scope(tenant), key)
                        .await
                        .map(|entry| entry.map(|entry| entry.value().to_string()))
                }
            },
            history: |tenant, version| {
                let repo = &repo;
                let key = &key;
                async move {
                    repo.find_version(settings_scope(tenant), key, version)
                        .await
                        .map(|entry| entry.map(|entry| entry.value().to_string()))
                }
            },
            latest_version: |tenant| {
                let repo = &repo;
                let key = &key;
                async move {
                    repo.head(settings_scope(tenant), key)
                        .await
                        .map(|head| head.map(ConfigHead::version))
                }
            },
        },
    )
    .await?;

    store.shutdown().await?;
    Ok(())
}
/// tc10：**F1 回归（postgres 层，exercises ON CONFLICT dedup）**——delete 软删后 republish 不复用 event_id，
/// outbox 事件不被吞（write-without-event 不重现）。
///
/// 旧 bug：delete 物理清历史 → republish 经 `latest_version` 回 v1 → event_id `...:v1` 复用 → outbox
/// `append_outbox` 的 `ON CONFLICT (event_id) DO NOTHING` 吞掉新事件（config 写入但事件丢失）。tombstone 软删
/// 使 version 单调（v1 → tombstone v2 → republish v3）→ event_id 不复用 → 两次 publish 各落一条 outbox 行。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn tc10_config_delete_republish_no_event_id_reuse() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_config(&store).await?;
    let repo = PgConfigRepo::new(&store, fixed_clock_arc(), config_protection());
    let tenant = config_tenant();
    let key = SettingKey::parse("app.k").unwrap();

    // publish v1 经 co-tx（content-派生 event_id ...:v1）。
    let ev1 = config_event_id(tenant, "app.k", 1);
    repo.commit_publish(
        settings::config_publish_receipt_for_test(),
        settings_scope(tenant),
        ConfigMutation::Put(config_entry("app.k", "v1", 1)),
        reviewed_generated_event::<generated::event::settings_v1::Contract>(
            config_outbox_entry(&ev1),
            config_envelope("app.k"),
        )
        .await?,
    )
    .await?;

    // delete → tombstone v2（version 不重置）。
    repo.test_delete(settings_scope(tenant), &key).await?;

    // republish：下一版本 = latest_version(含 tombstone) + 1 = 3（**非**重置回 1，旧 bug 的根因）。
    let next = repo
        .head(settings_scope(tenant), &key)
        .await?
        .map_or(1, |head| head.version().saturating_add(1));
    assert_eq!(next, 3, "delete 软删后下一版本 = 3，不重置回 1");
    let ev3 = config_event_id(tenant, "app.k", next);
    assert_ne!(ev1, ev3, "republish event_id 不复用（v1 ≠ v3）");
    repo.commit_publish(
        settings::config_publish_receipt_for_test(),
        settings_scope(tenant),
        ConfigMutation::Put(config_entry("app.k", "v1-again", next)),
        reviewed_generated_event::<generated::event::settings_v1::Contract>(
            config_outbox_entry(&ev3),
            config_envelope("app.k"),
        )
        .await?,
    )
    .await?;

    // 两次 publish 各落一条 outbox 行——republish 事件未被 ON CONFLICT 吞。
    let ob1: (i64,) = sqlx::query_as("SELECT count(*) FROM outbox WHERE event_id = $1")
        .bind(&ev1)
        .fetch_one(&store.pool)
        .await?;
    let ob3: (i64,) = sqlx::query_as("SELECT count(*) FROM outbox WHERE event_id = $1")
        .bind(&ev3)
        .fetch_one(&store.pool)
        .await?;
    assert_eq!(ob1.0, 1, "v1 outbox 行存在");
    assert_eq!(
        ob3.0, 1,
        "republish (v3) outbox 行存在——event_id 不复用，事件未被吞"
    );
    // 活跃值恢复。
    assert_eq!(
        repo.find(settings_scope(tenant), &key)
            .await?
            .unwrap()
            .value(),
        "v1-again",
        "republish 后活跃值恢复"
    );

    store.shutdown().await?;
    Ok(())
}

/// ts1b：ref_version=None（NULL=latest）round-trip。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn ts1b_secret_save_find_ref_version_null() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_secret(&store).await?;
    let repo = store.secret_repo();
    let writer = PgSecretUnitOfWork::from_unverified_for_test(&store);
    let tenant = secret_tenant_a();

    writer
        .publish_internal(
            settings_scope(tenant),
            internal_secret_publish(make_secret_entry(
                "myapp.api-key",
                "k8s-secrets",
                "ns/my-secret",
                None,
                1,
                tenant,
            )),
        )
        .await?;

    let found = repo
        .find(
            settings_scope(tenant),
            &SecretKey::parse("myapp.api-key").unwrap(),
        )
        .await?
        .unwrap();
    assert_eq!(
        found.secret_ref().ref_version(),
        None,
        "ref_version=None 回环"
    );

    store.shutdown().await?;
    Ok(())
}

/// ts2：find_version 历史（精确版本；缺失版本 → None）。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn ts2_secret_find_version_history() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_secret(&store).await?;
    let repo = store.secret_repo();
    let writer = PgSecretUnitOfWork::from_unverified_for_test(&store);
    let tenant = secret_tenant_a();
    let key = SecretKey::parse("myapp.db-pass").unwrap();

    writer
        .publish_internal(
            settings_scope(tenant),
            internal_secret_publish(make_secret_entry(
                "myapp.db-pass",
                "vault",
                "secret/v1",
                None,
                1,
                tenant,
            )),
        )
        .await?;
    writer
        .publish_internal(
            settings_scope(tenant),
            internal_secret_publish(make_secret_entry(
                "myapp.db-pass",
                "vault",
                "secret/v2",
                Some("rev-2"),
                2,
                tenant,
            )),
        )
        .await?;

    // find 取最高版本。
    let latest = repo.find(settings_scope(tenant), &key).await?.unwrap();
    assert_eq!(latest.version(), 2, "find = max version");
    assert_eq!(latest.secret_ref().ref_key(), "secret/v2");

    // find_version 精确历史。
    let v1 = repo
        .find_version(settings_scope(tenant), &key, 1)
        .await?
        .unwrap();
    assert_eq!(v1.secret_ref().ref_key(), "secret/v1", "find_version(1)");
    let v2 = repo
        .find_version(settings_scope(tenant), &key, 2)
        .await?
        .unwrap();
    assert_eq!(
        v2.secret_ref().ref_version(),
        Some("rev-2"),
        "find_version(2)"
    );

    // 缺失版本 → None。
    assert!(
        repo.find_version(settings_scope(tenant), &key, 9)
            .await?
            .is_none(),
        "缺失版本 → None"
    );

    store.shutdown().await?;
    Ok(())
}

/// ts5：storage 错误通道——关池后 find 返回 `SecretRepoError::Storage`（基础设施错误分层映射）。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn ts5_secret_find_maps_storage_error() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    setup_secret(&store).await?;
    let repo = store.secret_repo();
    let tenant = secret_tenant_a();
    let key = SecretKey::parse("myapp.k").unwrap();

    testkit::repo_conformance::assert_storage_error_mapping(
        || async { store.shutdown().await },
        || async { repo.find(settings_scope(tenant), &key).await.map(|_| ()) },
        |e| matches!(e, SecretRepoError::Storage(_)),
    )
    .await?;

    Ok(())
}

/// ts8：material-never-persisted 断言——`information_schema.columns` 校验 secret_refs 列集
/// 恰为 {created_at, deleted, ref_key, ref_version, secret_key, store_id, tenant_id, version}，
/// 无任何 secret 材料列（review-critical）。
#[tokio::test(flavor = "multi_thread")]
async fn ts8_secret_refs_table_has_no_material_column() -> TestResult {
    let (_pg, store) = connect_pg().await?;
    store.run_migrations().await?;

    // 从 information_schema.columns 取 secret_refs 的全部列名（ORDER BY 确定顺序）。
    let rows: Vec<(String,)> = sqlx::query_as(
        "SELECT column_name FROM information_schema.columns \
         WHERE table_name = 'secret_refs' AND table_schema = 'public' \
         ORDER BY column_name",
    )
    .fetch_all(&store.pool)
    .await?;

    let cols: Vec<&str> = rows.iter().map(|(s,)| s.as_str()).collect();

    // 期望的列集（字母序排列后）：坐标列 + 版本标记列，无任何材料列。
    let expected = [
        "created_at",
        "deleted",
        "ref_key",
        "ref_version",
        "secret_key",
        "store_id",
        "tenant_id",
        "version",
    ];
    assert_eq!(
        cols, expected,
        "secret_refs 列集应恰为坐标列（无材料列），实际：{cols:?}"
    );

    store.shutdown().await?;
    Ok(())
}

/// #1703：真实 `rss_app` + `PgSecretRepo` LocalTx 后端矩阵。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::expect_used, clippy::unwrap_used)]
async fn ts9_secret_repo_real_rss_app_localtx_matrix() -> TestResult {
    use std::sync::atomic::{AtomicUsize, Ordering};

    const LOCALTX_BACKEND_PROFILE_SETTINGS_SECRET_PUBLISH: ::vocab::HttpRouteBinding<
        ::generated::http::settings_v2::RouteMarker,
        ::vocab::http::LocalTx,
    > = ::generated::http::settings_v2::ROUTE;
    const LOCALTX_BACKEND_PROVIDER_SETTINGS_SECRET_PUBLISH: ::std::marker::PhantomData<(
        ::generated::http::settings_v2::RouteMarker,
        crate::PgSecretUnitOfWork,
    )> = ::std::marker::PhantomData;
    let _typed_enrollment = LOCALTX_BACKEND_PROFILE_SETTINGS_SECRET_PUBLISH;
    let _typed_provider = LOCALTX_BACKEND_PROVIDER_SETTINGS_SECRET_PUBLISH;

    let (pg, owner) = connect_pg().await?;
    owner.run_migrations().await?;
    let app = connect_pg_rss_app_role(&pg, &owner).await?;
    let tenant_a = TenantId::parse(&uuid::Uuid::new_v4().to_string()).unwrap();

    // Commit proof: the typed conformance helper drives the real repository, then the owner
    // independently confirms the physical row.
    let commit_key_raw = format!("commit.{}", uuid::Uuid::new_v4().simple());
    let commit_key = SecretKey::parse(&commit_key_raw).unwrap();
    let repo = app.secret_repo();
    let writer = PgSecretUnitOfWork::from_unverified_for_test(&app);
    let commit_writes = AtomicUsize::new(0);
    ::rss_conformance::localtx::assert_commit(::rss_conformance::localtx::CommitCase::new(
        || async {
            writer
                .publish(
                    settings_scope(tenant_a),
                    http_secret_publish(make_secret_entry(
                        &commit_key_raw,
                        "vault",
                        "secret/commit",
                        Some("rev-1"),
                        1,
                        tenant_a,
                    )),
                )
                .await
                .map_err(secret_repo_classified)?;
            commit_writes.fetch_add(1, Ordering::Relaxed);
            Ok(())
        },
        || async {
            repo.find(settings_scope(tenant_a), &commit_key)
                .await
                .map(|entry| entry.map(|entry| entry.version()))
                .map_err(secret_repo_classified)
        },
        Some(1),
        || commit_writes.load(Ordering::Relaxed),
    ))
    .await?;
    let committed = repo
        .find(settings_scope(tenant_a), &commit_key)
        .await?
        .expect("committed secret must be readable");
    assert_eq!(committed.version(), 1);
    let committed_rows: (i64,) = sqlx::query_as(
        "SELECT count(*) FROM secret_refs WHERE tenant_id = $1::uuid AND secret_key = $2",
    )
    .bind(tenant_a.as_uuid().to_string())
    .bind(&commit_key_raw)
    .fetch_one(&owner.pool)
    .await?;
    assert_eq!(committed_rows.0, 1, "commit must persist one real row");

    // Explicit rollback proof: fail after INSERT but before settlement; no row may survive.
    let rollback_key_raw = format!("rollback.{}", uuid::Uuid::new_v4().simple());
    let rollback_key = SecretKey::parse(&rollback_key_raw).unwrap();
    crate::secret_repo::fail_secret_save_after_insert_once(&rollback_key);
    let rollback_result = writer
        .publish(
            settings_scope(tenant_a),
            http_secret_publish(make_secret_entry(
                &rollback_key_raw,
                "vault",
                "secret/rollback",
                None,
                1,
                tenant_a,
            )),
        )
        .await;
    assert!(
        matches!(rollback_result, Err(SecretRepoError::Storage(_))),
        "post-insert fault must surface through storage"
    );
    let rolled_back_rows: (i64,) = sqlx::query_as(
        "SELECT count(*) FROM secret_refs WHERE tenant_id = $1::uuid AND secret_key = $2",
    )
    .bind(tenant_a.as_uuid().to_string())
    .bind(&rollback_key_raw)
    .fetch_one(&owner.pool)
    .await?;
    assert_eq!(rolled_back_rows.0, 0, "post-insert error must rollback");

    app.shutdown().await?;
    owner.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::expect_used, clippy::unwrap_used)]
async fn ts9_secret_repo_real_rss_app_tenant_profile() -> TestResult {
    const LOCALTX_BACKEND_PROFILE_SETTINGS_SECRET_PUBLISH: ::vocab::HttpRouteBinding<
        ::generated::http::settings_v2::RouteMarker,
        ::vocab::http::LocalTx,
    > = ::generated::http::settings_v2::ROUTE;
    const LOCALTX_BACKEND_PROVIDER_SETTINGS_SECRET_PUBLISH: ::std::marker::PhantomData<(
        ::generated::http::settings_v2::RouteMarker,
        crate::PgSecretUnitOfWork,
    )> = ::std::marker::PhantomData;
    let _typed_enrollment = LOCALTX_BACKEND_PROFILE_SETTINGS_SECRET_PUBLISH;
    let _typed_provider = LOCALTX_BACKEND_PROVIDER_SETTINGS_SECRET_PUBLISH;

    let (pg, owner) = connect_pg().await?;
    owner.run_migrations().await?;
    let app = connect_pg_rss_app_role(&pg, &owner).await?;
    let tenant_a = TenantId::parse(&uuid::Uuid::new_v4().to_string()).unwrap();
    let tenant_b = TenantId::parse(&uuid::Uuid::new_v4().to_string()).unwrap();
    let repo = app.secret_repo();
    let writer = PgSecretUnitOfWork::from_unverified_for_test(&app);

    // Tenant isolation: the same key has independent version spaces and values. The typed helper
    // proves round-trip, cross-tenant invisibility before tenant B writes, and no interference.
    let shared_key_raw = format!("tenant.{}", uuid::Uuid::new_v4().simple());
    let shared_key = SecretKey::parse(&shared_key_raw).unwrap();
    ::testkit::tenant_conformance::assert_tenant_isolation(
        tenant_a,
        tenant_b,
        |tenant| {
            let store_id = if tenant == tenant_a {
                "vault-a"
            } else {
                "vault-b"
            };
            writer.publish_internal(
                settings_scope(tenant),
                internal_secret_publish(make_secret_entry(
                    &shared_key_raw,
                    store_id,
                    "secret/tenant",
                    None,
                    1,
                    tenant,
                )),
            )
        },
        |tenant| {
            let repo = &repo;
            let shared_key = &shared_key;
            async move {
                repo.find(settings_scope(tenant), shared_key)
                    .await
                    .map(|entry| entry.is_some())
            }
        },
        secret_repo_conformance_category,
    )
    .await?;
    assert_eq!(
        repo.find(settings_scope(tenant_a), &shared_key)
            .await?
            .expect("tenant A value")
            .secret_ref()
            .store_id()
            .as_str(),
        "vault-a"
    );
    assert_eq!(
        repo.find(settings_scope(tenant_b), &shared_key)
            .await?
            .expect("tenant B value")
            .secret_ref()
            .store_id()
            .as_str(),
        "vault-b"
    );

    // Missing GUC is fail-closed for both read and write on the real serving connection.
    let mut missing_read = app.pool.begin().await?;
    let hidden: (i64,) = sqlx::query_as(
        "SELECT count(*) FROM secret_refs WHERE tenant_id = $1::uuid AND secret_key = $2",
    )
    .bind(tenant_a.as_uuid().to_string())
    .bind(&shared_key_raw)
    .fetch_one(&mut *missing_read)
    .await?;
    assert_eq!(hidden.0, 0, "missing tenant GUC must hide all rows");
    missing_read.rollback().await?;

    app.shutdown().await?;
    owner.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn ts9_secret_repo_no_write_probe_antivacuity() -> TestResult {
    let (pg, owner) = connect_pg().await?;
    owner.run_migrations().await?;
    let app = connect_pg_rss_app_role(&pg, &owner).await?;
    let tenant_a = TenantId::parse(&uuid::Uuid::new_v4().to_string()).unwrap();
    let tenant_b = TenantId::parse(&uuid::Uuid::new_v4().to_string()).unwrap();

    // Probe anti-vacuity: a durable row under the wrong tenant must still break the global-key
    // no-write snapshot. This red case prevents the provider matrix from regressing to an
    // expected-coordinate-only query that would miss a bypass mutation.
    let no_write_red_key = format!("no-write-red.{}", uuid::Uuid::new_v4().simple());
    sqlx::query(
        "INSERT INTO secret_refs (tenant_id, secret_key, version, store_id, ref_key) \
         VALUES ($1::uuid, $2, 1, 'vault', 'secret/no-write-red')",
    )
    .bind(tenant_b.as_uuid().to_string())
    .bind(&no_write_red_key)
    .execute(&owner.pool)
    .await?;
    let no_write_red = ::rss_conformance::localtx::assert_rejected_no_write(
        ::rss_conformance::localtx::RejectedNoWriteCase::new(
            || async {
                Err::<(), _>(rss_conformance::localtx::ClassifiedError::new(
                    rss_conformance::ConformanceErrorCategory::Validation,
                    std::io::Error::other("synthetic rejection"),
                ))
            },
            rss_conformance::ConformanceErrorCategory::Validation,
            || async {
                sqlx::query_as::<_, (i64,)>(
                    "SELECT count(*) FROM secret_refs WHERE secret_key = $1",
                )
                .bind(&no_write_red_key)
                .fetch_one(&owner.pool)
                .await
                .map(|count| count.0)
                .map_err(|error| {
                    rss_conformance::localtx::ClassifiedError::new(
                        rss_conformance::ConformanceErrorCategory::Storage,
                        error,
                    )
                })
            },
            0,
            || 0,
        ),
    )
    .await;
    assert!(matches!(
        no_write_red,
        Err(
            rss_conformance::localtx::LocalTxConformanceError::SnapshotMismatch {
                stage: rss_conformance::localtx::LocalTxStage::RejectedSnapshot
            }
        )
    ));
    sqlx::query("DELETE FROM secret_refs WHERE tenant_id = $1::uuid AND secret_key = $2")
        .bind(tenant_b.as_uuid().to_string())
        .bind(&no_write_red_key)
        .execute(&owner.pool)
        .await?;

    // RLS WITH CHECK proof is independent from the opaque repository scope: tenant A's serving
    // transaction cannot write a tenant B row even when raw SQL supplies tenant B explicitly.
    let cross_tenant_key_raw = format!("cross-rls.{}", uuid::Uuid::new_v4().simple());
    let mut cross_tenant_tx = app.pool.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
        .bind(tenant_a.as_uuid().to_string())
        .execute(&mut *cross_tenant_tx)
        .await?;
    let cross_tenant_write = sqlx::query(
        "INSERT INTO secret_refs \
             (tenant_id, secret_key, version, store_id, ref_key) \
         VALUES ($1::uuid, $2, 1, 'vault', 'secret/cross-tenant')",
    )
    .bind(tenant_b.as_uuid().to_string())
    .bind(&cross_tenant_key_raw)
    .execute(&mut *cross_tenant_tx)
    .await;
    assert!(
        cross_tenant_write.is_err(),
        "tenant A GUC must fail secret_refs WITH CHECK for tenant B"
    );
    cross_tenant_tx.rollback().await?;
    let cross_tenant_rows: (i64,) = sqlx::query_as(
        "SELECT count(*) FROM secret_refs WHERE tenant_id = $1::uuid AND secret_key = $2",
    )
    .bind(tenant_b.as_uuid().to_string())
    .bind(&cross_tenant_key_raw)
    .fetch_one(&owner.pool)
    .await?;
    assert_eq!(cross_tenant_rows.0, 0, "RLS rejection must write nothing");

    app.shutdown().await?;
    owner.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn ts9_secret_repo_real_rss_app_validation_profile() -> TestResult {
    const LOCALTX_BACKEND_PROFILE_SETTINGS_SECRET_PUBLISH: ::vocab::HttpRouteBinding<
        ::generated::http::settings_v2::RouteMarker,
        ::vocab::http::LocalTx,
    > = ::generated::http::settings_v2::ROUTE;
    const LOCALTX_BACKEND_PROVIDER_SETTINGS_SECRET_PUBLISH: ::std::marker::PhantomData<(
        ::generated::http::settings_v2::RouteMarker,
        crate::PgSecretUnitOfWork,
    )> = ::std::marker::PhantomData;
    let _typed_enrollment = LOCALTX_BACKEND_PROFILE_SETTINGS_SECRET_PUBLISH;
    let _typed_provider = LOCALTX_BACKEND_PROVIDER_SETTINGS_SECRET_PUBLISH;

    let (pg, owner) = connect_pg().await?;
    owner.run_migrations().await?;
    let app = connect_pg_rss_app_role(&pg, &owner).await?;
    let tenant_a = TenantId::parse(&uuid::Uuid::new_v4().to_string()).unwrap();
    let tenant_b = TenantId::parse(&uuid::Uuid::new_v4().to_string()).unwrap();
    let writer = PgSecretUnitOfWork::from_unverified_for_test(&app);

    let invalid_scope_key_raw = format!("scope-mismatch.{}", uuid::Uuid::new_v4().simple());
    let invalid_scope_key = SecretKey::parse(&invalid_scope_key_raw).unwrap();
    ::rss_conformance::localtx::assert_rejected_no_write(
        ::rss_conformance::localtx::RejectedNoWriteCase::new(
            || async {
                writer
                    .publish(
                        settings_scope(tenant_a),
                        http_secret_publish(make_secret_entry(
                            &invalid_scope_key_raw,
                            "vault",
                            "secret/scope-mismatch",
                            None,
                            1,
                            tenant_b,
                        )),
                    )
                    .await
                    .map_err(|error| {
                        rss_conformance::localtx::ClassifiedError::new(
                            rss_conformance::ConformanceErrorCategory::Validation,
                            error,
                        )
                    })
            },
            rss_conformance::ConformanceErrorCategory::Validation,
            || async {
                sqlx::query_as::<_, (i64,)>(
                    "SELECT count(*) FROM secret_refs WHERE secret_key = $1",
                )
                .bind(&invalid_scope_key_raw)
                .fetch_one(&owner.pool)
                .await
                .map(|count| count.0)
                .map_err(|error| {
                    rss_conformance::localtx::ClassifiedError::new(
                        rss_conformance::ConformanceErrorCategory::Storage,
                        error,
                    )
                })
            },
            0,
            || crate::secret_repo::secret_save_attempts(&invalid_scope_key),
        ),
    )
    .await?;

    app.shutdown().await?;
    owner.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::expect_used, clippy::unwrap_used)]
async fn ts9_secret_repo_concurrency_and_lifecycle() -> TestResult {
    let (pg, owner) = connect_pg().await?;
    owner.run_migrations().await?;
    let app = connect_pg_rss_app_role(&pg, &owner).await?;
    let tenant_a = TenantId::parse(&uuid::Uuid::new_v4().to_string()).unwrap();
    let tenant_b = TenantId::parse(&uuid::Uuid::new_v4().to_string()).unwrap();
    let repo = app.secret_repo();
    let writer = PgSecretUnitOfWork::from_unverified_for_test(&app);
    let commit_key_raw = format!("lifecycle.{}", uuid::Uuid::new_v4().simple());
    writer
        .publish_internal(
            settings_scope(tenant_a),
            internal_secret_publish(make_secret_entry(
                &commit_key_raw,
                "vault",
                "secret/v1",
                None,
                1,
                tenant_a,
            )),
        )
        .await?;
    let shared_key_raw = format!("lifecycle-tenant.{}", uuid::Uuid::new_v4().simple());
    let shared_key = SecretKey::parse(&shared_key_raw).unwrap();
    for (tenant, store_id) in [(tenant_a, "vault-a"), (tenant_b, "vault-b")] {
        writer
            .publish_internal(
                settings_scope(tenant),
                internal_secret_publish(make_secret_entry(
                    &shared_key_raw,
                    store_id,
                    "secret/shared",
                    None,
                    1,
                    tenant,
                )),
            )
            .await?;
    }

    // Sequential stale CAS conflict is explicit and does not overwrite the head.
    let stale = writer
        .publish_internal(
            settings_scope(tenant_a),
            internal_secret_publish(make_secret_entry(
                &commit_key_raw,
                "vault",
                "secret/stale",
                None,
                1,
                tenant_a,
            )),
        )
        .await;
    assert!(matches!(stale, Err(SecretRepoError::VersionConflict)));
    let gap = writer
        .publish_internal(
            settings_scope(tenant_a),
            internal_secret_publish(make_secret_entry(
                &commit_key_raw,
                "vault",
                "secret/gap",
                None,
                3,
                tenant_a,
            )),
        )
        .await;
    assert!(
        matches!(gap, Err(SecretRepoError::VersionConflict)),
        "version gaps must fail closed"
    );

    // Two concurrent v2 writers serialize under the keyed lock: exactly one commit and one conflict.
    let concurrent_key_raw = format!("concurrent.{}", uuid::Uuid::new_v4().simple());
    let concurrent_key = SecretKey::parse(&concurrent_key_raw).unwrap();
    writer
        .publish_internal(
            settings_scope(tenant_a),
            internal_secret_publish(make_secret_entry(
                &concurrent_key_raw,
                "vault",
                "secret/v1",
                None,
                1,
                tenant_a,
            )),
        )
        .await?;
    let writer_a = PgSecretUnitOfWork::from_unverified_for_test(&app);
    let writer_b = PgSecretUnitOfWork::from_unverified_for_test(&app);
    let entry_a = make_secret_entry(
        &concurrent_key_raw,
        "vault",
        "secret/v2-a",
        None,
        2,
        tenant_a,
    );
    let entry_b = make_secret_entry(
        &concurrent_key_raw,
        "vault",
        "secret/v2-b",
        None,
        2,
        tenant_a,
    );
    crate::secret_repo::rendezvous_secret_key_lock_attempts(&concurrent_key, 2);
    let (write_a, write_b) = tokio::join!(
        writer_a.publish_internal(settings_scope(tenant_a), internal_secret_publish(entry_a)),
        writer_b.publish_internal(settings_scope(tenant_a), internal_secret_publish(entry_b)),
    );
    let successes = usize::from(write_a.is_ok()) + usize::from(write_b.is_ok());
    let conflicts = usize::from(matches!(write_a, Err(SecretRepoError::VersionConflict)))
        + usize::from(matches!(write_b, Err(SecretRepoError::VersionConflict)));
    assert_eq!((successes, conflicts), (1, 1));
    assert_eq!(
        repo.latest_version(settings_scope(tenant_a), &concurrent_key)
            .await?,
        Some(2)
    );

    // Concurrent delete/delete appends one tombstone; save/delete has only serialized outcomes.
    let delete_a = PgSecretUnitOfWork::from_unverified_for_test(&app);
    let delete_b = PgSecretUnitOfWork::from_unverified_for_test(&app);
    crate::secret_repo::rendezvous_secret_key_lock_attempts(&concurrent_key, 2);
    let (deleted_a, deleted_b) = tokio::join!(
        delete_a.delete(settings_scope(tenant_a), &concurrent_key),
        delete_b.delete(settings_scope(tenant_a), &concurrent_key),
    );
    deleted_a?;
    deleted_b?;
    let tombstones: (i64,) = sqlx::query_as(
        "SELECT count(*) FROM secret_refs \
         WHERE tenant_id = $1::uuid AND secret_key = $2 AND deleted",
    )
    .bind(tenant_a.as_uuid().to_string())
    .bind(&concurrent_key_raw)
    .fetch_one(&owner.pool)
    .await?;
    assert_eq!(
        tombstones.0, 1,
        "concurrent delete must append one tombstone"
    );
    assert!(
        repo.find_version(settings_scope(tenant_a), &concurrent_key, 1)
            .await?
            .is_some(),
        "tombstone append must preserve historical active versions"
    );

    let phantom_key_raw = format!("phantom.{}", uuid::Uuid::new_v4().simple());
    let phantom_key = SecretKey::parse(&phantom_key_raw).unwrap();
    writer
        .delete(settings_scope(tenant_a), &phantom_key)
        .await?;
    assert_eq!(
        repo.latest_version(settings_scope(tenant_a), &phantom_key)
            .await?,
        None,
        "deleting an absent key must be a physical no-op"
    );

    // A tenant-scoped delete preserves that tenant's history and cannot disturb the same key in B.
    writer.delete(settings_scope(tenant_a), &shared_key).await?;
    assert!(
        repo.find(settings_scope(tenant_a), &shared_key)
            .await?
            .is_none()
    );
    assert!(
        repo.find_version(settings_scope(tenant_a), &shared_key, 1)
            .await?
            .is_some()
    );
    assert_eq!(
        repo.latest_version(settings_scope(tenant_a), &shared_key)
            .await?,
        Some(2)
    );
    assert!(
        repo.find(settings_scope(tenant_b), &shared_key)
            .await?
            .is_some(),
        "tenant A delete must not hide tenant B's active value"
    );
    assert_eq!(
        repo.latest_version(settings_scope(tenant_b), &shared_key)
            .await?,
        Some(1)
    );

    let race_key_raw = format!("race.{}", uuid::Uuid::new_v4().simple());
    let race_key = SecretKey::parse(&race_key_raw).unwrap();
    writer
        .publish_internal(
            settings_scope(tenant_a),
            internal_secret_publish(make_secret_entry(
                &race_key_raw,
                "vault",
                "secret/race-v1",
                None,
                1,
                tenant_a,
            )),
        )
        .await?;
    let race_writer = PgSecretUnitOfWork::from_unverified_for_test(&app);
    let race_deleter = PgSecretUnitOfWork::from_unverified_for_test(&app);
    crate::secret_repo::rendezvous_secret_key_lock_attempts(&race_key, 2);
    let (race_save, race_delete) = tokio::join!(
        race_writer.publish_internal(
            settings_scope(tenant_a),
            internal_secret_publish(make_secret_entry(
                &race_key_raw,
                "vault",
                "secret/race-v2",
                None,
                2,
                tenant_a,
            )),
        ),
        race_deleter.delete(settings_scope(tenant_a), &race_key),
    );
    assert!(
        race_save.is_ok() || matches!(race_save, Err(SecretRepoError::VersionConflict)),
        "save/delete race must not leak storage errors"
    );
    race_delete?;
    assert!(
        repo.find(settings_scope(tenant_a), &race_key)
            .await?
            .is_none(),
        "delete wins or follows the save in both serial orders"
    );
    let deleted_version = repo
        .latest_version(settings_scope(tenant_a), &race_key)
        .await?
        .expect("race must retain a tombstone head");
    assert!(matches!(deleted_version, 2 | 3));

    // Republish never reuses a version after the tombstone.
    let republished_version = deleted_version + 1;
    writer
        .republish(
            settings_scope(tenant_a),
            secret_republish(make_secret_entry(
                &race_key_raw,
                "vault",
                "secret/republished",
                None,
                republished_version,
                tenant_a,
            )),
        )
        .await?;
    assert_eq!(
        repo.find(settings_scope(tenant_a), &race_key)
            .await?
            .expect("republished value")
            .version(),
        republished_version
    );

    // Delete has no generated retry contract, but its advisory-lock wait is still bounded. Hold
    // the exact key lock from an owner transaction and prove delete returns without replay/write.
    let bounded_key_raw = format!("bounded-delete.{}", uuid::Uuid::new_v4().simple());
    let bounded_key = SecretKey::parse(&bounded_key_raw).unwrap();
    writer
        .publish_internal(
            settings_scope(tenant_a),
            internal_secret_publish(make_secret_entry(
                &bounded_key_raw,
                "vault",
                "secret/bounded-delete",
                None,
                1,
                tenant_a,
            )),
        )
        .await?;
    let mut lock_holder = owner.pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1 || chr(31) || $2, 0))")
        .bind(tenant_a.as_uuid().to_string())
        .bind(&bounded_key_raw)
        .execute(&mut *lock_holder)
        .await?;
    let bounded_delete = tokio::time::timeout(
        std::time::Duration::from_secs(7),
        writer.delete(settings_scope(tenant_a), &bounded_key),
    )
    .await
    .expect("delete advisory lock wait must be bounded");
    assert!(
        matches!(bounded_delete, Err(SecretRepoError::Storage(_))),
        "lock timeout must surface as storage without replay"
    );
    let bounded_tombstones: (i64,) = sqlx::query_as(
        "SELECT count(*) FROM secret_refs \
         WHERE tenant_id = $1::uuid AND secret_key = $2 AND deleted",
    )
    .bind(tenant_a.as_uuid().to_string())
    .bind(&bounded_key_raw)
    .fetch_one(&owner.pool)
    .await?;
    assert_eq!(
        bounded_tombstones.0, 0,
        "timed-out delete must append nothing"
    );
    lock_holder.rollback().await?;

    app.shutdown().await?;
    owner.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn ts9_secret_repo_real_rss_app_retry_profile() -> TestResult {
    const LOCALTX_BACKEND_PROFILE_SETTINGS_SECRET_PUBLISH: ::vocab::HttpRouteBinding<
        ::generated::http::settings_v2::RouteMarker,
        ::vocab::http::LocalTx,
    > = ::generated::http::settings_v2::ROUTE;
    const LOCALTX_BACKEND_PROVIDER_SETTINGS_SECRET_PUBLISH: ::std::marker::PhantomData<(
        ::generated::http::settings_v2::RouteMarker,
        crate::PgSecretUnitOfWork,
    )> = ::std::marker::PhantomData;
    let _typed_enrollment = LOCALTX_BACKEND_PROFILE_SETTINGS_SECRET_PUBLISH;
    let _typed_provider = LOCALTX_BACKEND_PROVIDER_SETTINGS_SECRET_PUBLISH;

    let (pg, owner) = connect_pg().await?;
    owner.run_migrations().await?;
    let app = connect_pg_rss_app_role(&pg, &owner).await?;
    let tenant_a = TenantId::parse(&uuid::Uuid::new_v4().to_string()).unwrap();
    let writer = PgSecretUnitOfWork::from_unverified_for_test(&app);

    // The profile helpers below execute the real PgSecretRepo + retry_write + settlement funnel.
    let retry_success_key_raw = format!("retry-success.{}", uuid::Uuid::new_v4().simple());
    let retry_success_key = SecretKey::parse(&retry_success_key_raw).unwrap();
    crate::secret_repo::fail_secret_save_transient_after_insert(&retry_success_key, 1);
    let retry_conflict_key_raw = format!("retry-conflict.{}", uuid::Uuid::new_v4().simple());
    let retry_conflict_key = SecretKey::parse(&retry_conflict_key_raw).unwrap();
    let retry_permanent_key_raw = format!("retry-permanent.{}", uuid::Uuid::new_v4().simple());
    let retry_permanent_key = SecretKey::parse(&retry_permanent_key_raw).unwrap();
    crate::secret_repo::fail_secret_save_after_insert_once(&retry_permanent_key);
    let retry_exhaustion_key_raw = format!("retry-exhaustion.{}", uuid::Uuid::new_v4().simple());
    let retry_exhaustion_key = SecretKey::parse(&retry_exhaustion_key_raw).unwrap();
    crate::secret_repo::fail_secret_save_transient_after_insert(&retry_exhaustion_key, 3);
    ::testkit::repo_conformance::assert_retry_boundary_policy(
        ::testkit::repo_conformance::RetryBoundaryCase::new(
            ::testkit::repo_conformance::TransientSuccessPath::new(
                || async {
                    writer
                        .publish(
                            settings_scope(tenant_a),
                            http_secret_publish(make_secret_entry(
                                &retry_success_key_raw,
                                "vault",
                                "secret/retry-success",
                                None,
                                1,
                                tenant_a,
                            )),
                        )
                        .await
                },
                || crate::secret_repo::secret_save_attempts(&retry_success_key),
                2,
                || secret_ref_row_count(&owner, tenant_a, &retry_success_key),
            ),
            ::testkit::repo_conformance::ConflictPath::new(
                || async {
                    writer
                        .publish(
                            settings_scope(tenant_a),
                            http_secret_publish(make_secret_entry(
                                &retry_conflict_key_raw,
                                "vault",
                                "secret/retry-conflict-gap",
                                None,
                                2,
                                tenant_a,
                            )),
                        )
                        .await
                },
                || crate::secret_repo::secret_save_attempts(&retry_conflict_key),
                || secret_ref_row_count(&owner, tenant_a, &retry_conflict_key),
            ),
            ::testkit::repo_conformance::PermanentPath::new(
                || async {
                    writer
                        .publish(
                            settings_scope(tenant_a),
                            http_secret_publish(make_secret_entry(
                                &retry_permanent_key_raw,
                                "vault",
                                "secret/retry-permanent",
                                None,
                                1,
                                tenant_a,
                            )),
                        )
                        .await
                },
                || crate::secret_repo::secret_save_attempts(&retry_permanent_key),
                || secret_ref_row_count(&owner, tenant_a, &retry_permanent_key),
            ),
            ::testkit::repo_conformance::TransientExhaustionPath::new(
                || async {
                    writer
                        .publish(
                            settings_scope(tenant_a),
                            http_secret_publish(make_secret_entry(
                                &retry_exhaustion_key_raw,
                                "vault",
                                "secret/retry-exhaustion",
                                None,
                                1,
                                tenant_a,
                            )),
                        )
                        .await
                },
                || crate::secret_repo::secret_save_attempts(&retry_exhaustion_key),
                3,
                || secret_ref_row_count(&owner, tenant_a, &retry_exhaustion_key),
            ),
        ),
        |error| conformance_retry_category(crate::tx_retry::classify_secret_repo_error(error)),
    )
    .await?;

    app.shutdown().await?;
    owner.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn ts9_secret_repo_real_rss_app_commit_unknown_profile() -> TestResult {
    const LOCALTX_BACKEND_PROFILE_SETTINGS_SECRET_PUBLISH: ::vocab::HttpRouteBinding<
        ::generated::http::settings_v2::RouteMarker,
        ::vocab::http::LocalTx,
    > = ::generated::http::settings_v2::ROUTE;
    const LOCALTX_BACKEND_PROVIDER_SETTINGS_SECRET_PUBLISH: ::std::marker::PhantomData<(
        ::generated::http::settings_v2::RouteMarker,
        crate::PgSecretUnitOfWork,
    )> = ::std::marker::PhantomData;
    let _typed_enrollment = LOCALTX_BACKEND_PROFILE_SETTINGS_SECRET_PUBLISH;
    let _typed_provider = LOCALTX_BACKEND_PROVIDER_SETTINGS_SECRET_PUBLISH;

    let (pg, owner) = connect_pg().await?;
    owner.run_migrations().await?;
    let app = connect_pg_rss_app_role(&pg, &owner).await?;
    let tenant_a = TenantId::parse(&uuid::Uuid::new_v4().to_string()).unwrap();
    let writer = PgSecretUnitOfWork::from_unverified_for_test(&app);

    let unknown_key_raw = format!("commit-unknown.{}", uuid::Uuid::new_v4().simple());
    let unknown_key = SecretKey::parse(&unknown_key_raw).unwrap();
    crate::secret_repo::fail_secret_save_commit_unknown_after_insert_once(&unknown_key);
    ::rss_conformance::localtx::assert_commit_unknown_no_replay(
        ::rss_conformance::localtx::CommitUnknownCase::new(
            || async {
                writer
                    .publish(
                        settings_scope(tenant_a),
                        http_secret_publish(make_secret_entry(
                            &unknown_key_raw,
                            "vault",
                            "secret/commit-unknown",
                            None,
                            1,
                            tenant_a,
                        )),
                    )
                    .await
                    .map_err(|error| {
                        rss_conformance::localtx::ClassifiedError::new(
                            rss_conformance::ConformanceErrorCategory::CommitUnknown,
                            error,
                        )
                    })
            },
            rss_conformance::ConformanceErrorCategory::CommitUnknown,
            || crate::secret_repo::secret_save_attempts(&unknown_key),
        ),
    )
    .await?;
    app.shutdown().await?;
    owner.shutdown().await?;
    Ok(())
}

/// #1703：`secret_refs` 由 PostgreSQL 强制 append-only，且版本必须为正数。
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::unwrap_used)]
async fn ts10_secret_refs_database_hardening() -> TestResult {
    let (pg, owner) = connect_pg().await?;
    owner.run_migrations().await?;
    let app = connect_pg_rss_app_role(&pg, &owner).await?;
    let tenant = uuid::Uuid::new_v4().to_string();
    let key = format!("hardening.{}", uuid::Uuid::new_v4().simple());

    let mut tx = app.pool.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
        .bind(&tenant)
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "INSERT INTO secret_refs (tenant_id, secret_key, version, store_id, ref_key) \
         VALUES ($1::uuid, $2, 1, 'vault', 'secret/ref')",
    )
    .bind(&tenant)
    .bind(&key)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;

    let mut tx = app.pool.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
        .bind(&tenant)
        .execute(&mut *tx)
        .await?;
    let update = sqlx::query(
        "UPDATE secret_refs SET ref_key = 'mutated' \
         WHERE tenant_id = $1::uuid AND secret_key = $2",
    )
    .bind(&tenant)
    .bind(&key)
    .execute(&mut *tx)
    .await;
    assert!(
        update.is_err(),
        "rss_app must not UPDATE append-only secret_refs"
    );
    tx.rollback().await?;

    let mut tx = app.pool.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id', $1, true)")
        .bind(&tenant)
        .execute(&mut *tx)
        .await?;
    let delete =
        sqlx::query("DELETE FROM secret_refs WHERE tenant_id = $1::uuid AND secret_key = $2")
            .bind(&tenant)
            .bind(&key)
            .execute(&mut *tx)
            .await;
    assert!(
        delete.is_err(),
        "rss_app must not DELETE append-only secret_refs"
    );
    tx.rollback().await?;

    for invalid in [0_i64, -1] {
        let invalid_version = sqlx::query(
            "INSERT INTO secret_refs (tenant_id, secret_key, version, store_id, ref_key) \
             VALUES ($1::uuid, $2, $3, 'vault', 'secret/ref')",
        )
        .bind(&tenant)
        .bind(format!("{key}.invalid{}", invalid.unsigned_abs()))
        .bind(invalid)
        .execute(&owner.pool)
        .await;
        assert!(
            invalid_version.is_err(),
            "database must reject non-positive secret version {invalid}"
        );
    }

    app.shutdown().await?;
    owner.shutdown().await?;
    Ok(())
}
