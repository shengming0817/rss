use super::*;

// Keep PgSecretUnitOfWork off this glob; seams import the crate path for LocalTx type-aware resolution.

pub(in super::super) use settings::ports::{
    ConfigEntry, ConfigHead, ConfigMutation, ConfigRepo, ConfigRepoError, ConfigTombstone,
    ConfigUnitOfWork, SettingKey, TenantRepoScope,
};

pub(in super::super) use crate::config_repo::{
    arm_config_retry_failpoint, arm_config_retry_permanent_failpoint, config_retry_attempts,
};

pub(in super::super) use crate::cotx::{ServingWriteLane, TenantDb};

pub(in super::super) use crate::tx_retry::{classify_config_repo_error, classify_identity_error};

pub(in super::super) use crate::{
    ConfigValueMaintenanceCapability, ConfigValueMaintenanceOperation,
    ConfigValueMaintenanceOptions, ConfigValueProtection, ConfigValueProtections, PgConfigRepo,
    PgConfigValueMaintenance,
};

pub(in super::super) fn conformance_retry_category(
    retry_class: consistency::TxRetryClass,
) -> testkit::ConformanceErrorCategory {
    match retry_class {
        consistency::TxRetryClass::Transient => testkit::ConformanceErrorCategory::Transient,
        consistency::TxRetryClass::Conflict => testkit::ConformanceErrorCategory::Conflict,
        consistency::TxRetryClass::Permanent => testkit::ConformanceErrorCategory::Permanent,
        consistency::TxRetryClass::OwnershipLost => {
            testkit::ConformanceErrorCategory::OwnershipLost
        }
    }
}

/// config 测试用 canonical 租户 UUID（复用 co-tx 段 [`COTX_TENANT_A`] 同值，避免两 const 漂移）。
pub(in super::super) const CONFIG_TENANT: &str = COTX_TENANT_A;

/// 第二租户（跨租户隔离测试 tc9）——与 `application.rs` 单测 TENANT_B 同值。
pub(in super::super) const CONFIG_TENANT_B: &str = "00000000-0000-4000-8000-000000000abc";

/// config-version-changed 契约 topic 局部单源。
pub(in super::super) const CONFIG_VERSION_CHANGED_TOPIC: &str = "settings.config-version-changed";

#[allow(clippy::unwrap_used)]
// reason: 集成测试 happy-path 构造已知合法值；item-level carve-out（error-handling.md §Carve-out）。
pub(in super::super) fn config_tenant() -> TenantId {
    TenantId::parse(CONFIG_TENANT).unwrap()
}

#[allow(clippy::unwrap_used)]
pub(in super::super) fn config_maintenance_capability() -> ConfigValueMaintenanceCapability {
    ConfigValueMaintenanceCapability::from_verified_maintenance_service_operator(
        &authn::test_support::maintenance_service_operator_proof(),
    )
}

/// 构造 ConfigEntry（经 `ConfigEntry::hydrate` 跨 crate pub funnel）。
#[allow(clippy::unwrap_used)]
pub(in super::super) fn config_entry(key: &str, value: &str, version: u64) -> ConfigEntry {
    config_entry_for(config_tenant(), key, value, version)
}

#[allow(clippy::unwrap_used)]
pub(in super::super) fn config_entry_for(
    tenant: TenantId,
    key: &str,
    value: &str,
    version: u64,
) -> ConfigEntry {
    ConfigEntry::hydrate(SettingKey::parse(key).unwrap(), value, tenant, version)
}

pub(in super::super) fn encrypted_config_fixture(
    key: &str,
) -> (
    ConfigMutation,
    crate::cotx::settings_audit::EncodedConfigValue,
) {
    (
        ConfigMutation::Put(config_entry(key, "encrypted-fixture", 1)),
        crate::cotx::settings_audit::EncodedConfigValue {
            value: None,
            protection_scheme: 1,
            value_enc: Some(b"ciphertext".to_vec()),
            key_id: Some("settings-config:1".to_owned()),
        },
    )
}

pub(in super::super) struct AadBoundKeyProvider;

impl diport::KeyProvider for AadBoundKeyProvider {
    async fn encrypt(
        &self,
        key: diport::KeyName,
        plaintext: secure::Plaintext,
        aad: secure::DerivedAad,
    ) -> Result<diport::EncryptOutput, diport::KeyProviderError> {
        let aad_bytes = aad.as_canonical_bytes();
        let mut ciphertext = Vec::with_capacity(4 + aad_bytes.len() + plaintext.expose().len());
        ciphertext.extend_from_slice(&(aad_bytes.len() as u32).to_be_bytes());
        ciphertext.extend_from_slice(aad_bytes);
        ciphertext.extend(plaintext.expose().iter().map(|b| b ^ 0xA5));
        Ok(diport::EncryptOutput::new(
            ciphertext,
            diport::KeyRef::new(key, diport::KeyVersion::new(1)),
        ))
    }

    async fn decrypt(
        &self,
        ciphertext: diport::RedactedBytes,
        _key: diport::KeyRef,
        aad: secure::DerivedAad,
    ) -> Result<secure::Plaintext, diport::KeyProviderError> {
        let raw = ciphertext.as_bytes();
        if raw.len() < 4 {
            return Err(config_key_rejected());
        }
        let aad_len = u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]) as usize;
        if raw.len() < 4 + aad_len {
            return Err(config_key_rejected());
        }
        let (stored_aad, plaintext) = raw[4..].split_at(aad_len);
        if stored_aad != aad.as_canonical_bytes() {
            return Err(config_key_rejected());
        }
        Ok(secure::Plaintext::new(
            plaintext.iter().map(|b| b ^ 0xA5).collect(),
        ))
    }

    async fn rewrap(
        &self,
        ciphertext: diport::RedactedBytes,
        key: diport::KeyRef,
        _aad: secure::DerivedAad,
    ) -> Result<diport::EncryptOutput, diport::KeyProviderError> {
        Ok(diport::EncryptOutput::new(ciphertext.into_bytes(), key))
    }

    async fn shutdown(&self) -> Result<(), diport::KeyProviderError> {
        Ok(())
    }
}

pub(in super::super) struct RejectingKeyProvider;

impl diport::KeyProvider for RejectingKeyProvider {
    async fn encrypt(
        &self,
        _key: diport::KeyName,
        _plaintext: secure::Plaintext,
        _aad: secure::DerivedAad,
    ) -> Result<diport::EncryptOutput, diport::KeyProviderError> {
        Err(config_key_rejected())
    }

    async fn decrypt(
        &self,
        _ciphertext: diport::RedactedBytes,
        _key: diport::KeyRef,
        _aad: secure::DerivedAad,
    ) -> Result<secure::Plaintext, diport::KeyProviderError> {
        Err(config_key_rejected())
    }

    async fn rewrap(
        &self,
        _ciphertext: diport::RedactedBytes,
        _key: diport::KeyRef,
        _aad: secure::DerivedAad,
    ) -> Result<diport::EncryptOutput, diport::KeyProviderError> {
        Err(config_key_rejected())
    }

    async fn shutdown(&self) -> Result<(), diport::KeyProviderError> {
        Ok(())
    }
}

pub(in super::super) struct UnavailableKeyProvider;

impl diport::KeyProvider for UnavailableKeyProvider {
    async fn encrypt(
        &self,
        _key: diport::KeyName,
        _plaintext: secure::Plaintext,
        _aad: secure::DerivedAad,
    ) -> Result<diport::EncryptOutput, diport::KeyProviderError> {
        Err(config_key_unavailable())
    }

    async fn decrypt(
        &self,
        _ciphertext: diport::RedactedBytes,
        _key: diport::KeyRef,
        _aad: secure::DerivedAad,
    ) -> Result<secure::Plaintext, diport::KeyProviderError> {
        Err(config_key_unavailable())
    }

    async fn rewrap(
        &self,
        _ciphertext: diport::RedactedBytes,
        _key: diport::KeyRef,
        _aad: secure::DerivedAad,
    ) -> Result<diport::EncryptOutput, diport::KeyProviderError> {
        Err(config_key_unavailable())
    }

    async fn shutdown(&self) -> Result<(), diport::KeyProviderError> {
        Ok(())
    }
}

pub(in super::super) struct RewrappingKeyProvider;

impl diport::KeyProvider for RewrappingKeyProvider {
    async fn encrypt(
        &self,
        _key: diport::KeyName,
        _plaintext: secure::Plaintext,
        _aad: secure::DerivedAad,
    ) -> Result<diport::EncryptOutput, diport::KeyProviderError> {
        Err(config_key_rejected())
    }

    async fn decrypt(
        &self,
        _ciphertext: diport::RedactedBytes,
        _key: diport::KeyRef,
        _aad: secure::DerivedAad,
    ) -> Result<secure::Plaintext, diport::KeyProviderError> {
        Err(config_key_rejected())
    }

    async fn rewrap(
        &self,
        ciphertext: diport::RedactedBytes,
        key: diport::KeyRef,
        _aad: secure::DerivedAad,
    ) -> Result<diport::EncryptOutput, diport::KeyProviderError> {
        Ok(diport::EncryptOutput::new(
            ciphertext.into_bytes(),
            diport::KeyRef::new(key.name().clone(), diport::KeyVersion::new(2)),
        ))
    }

    async fn shutdown(&self) -> Result<(), diport::KeyProviderError> {
        Ok(())
    }
}

pub(in super::super) struct MutatingBackfillKeyProvider {
    pub(in super::super) pool: sqlx::PgPool,
}

impl diport::KeyProvider for MutatingBackfillKeyProvider {
    async fn encrypt(
        &self,
        _key: diport::KeyName,
        _plaintext: secure::Plaintext,
        _aad: secure::DerivedAad,
    ) -> Result<diport::EncryptOutput, diport::KeyProviderError> {
        sqlx::query("UPDATE config_entries SET value = $1 WHERE config_key = $2")
            .bind("plain-v2")
            .bind("legacy.cas")
            .execute(&self.pool)
            .await
            .map_err(|_| config_key_unavailable())?;
        let key_name =
            diport::KeyName::try_new("settings-config").map_err(|_| config_key_rejected())?;
        Ok(diport::EncryptOutput::new(
            b"stale-ciphertext".to_vec(),
            diport::KeyRef::new(key_name, diport::KeyVersion::new(1)),
        ))
    }

    async fn decrypt(
        &self,
        _ciphertext: diport::RedactedBytes,
        _key: diport::KeyRef,
        _aad: secure::DerivedAad,
    ) -> Result<secure::Plaintext, diport::KeyProviderError> {
        Err(config_key_rejected())
    }

    async fn rewrap(
        &self,
        _ciphertext: diport::RedactedBytes,
        _key: diport::KeyRef,
        _aad: secure::DerivedAad,
    ) -> Result<diport::EncryptOutput, diport::KeyProviderError> {
        Err(config_key_rejected())
    }

    async fn shutdown(&self) -> Result<(), diport::KeyProviderError> {
        Ok(())
    }
}

pub(in super::super) fn config_key_rejected() -> diport::KeyProviderError {
    diport::KeyProviderError::new(
        diport::key_provider::KeyProviderErrorKind::Rejected,
        std::io::Error::other("test key provider rejected"),
    )
}

pub(in super::super) fn config_key_unavailable() -> diport::KeyProviderError {
    diport::KeyProviderError::new(
        diport::key_provider::KeyProviderErrorKind::Unavailable,
        std::io::Error::other("test key provider unavailable"),
    )
}

#[allow(clippy::unwrap_used)]
pub(in super::super) fn config_protection() -> ConfigValueProtection {
    ConfigValueProtection::new(
        diport::DynKeyProvider::new_box(AadBoundKeyProvider),
        diport::KeyName::try_new("settings-config").unwrap(),
    )
}

#[allow(clippy::unwrap_used)]
pub(in super::super) fn config_protections() -> ConfigValueProtections {
    ConfigValueProtections::new(
        diport::DynKeyProvider::new_box(AadBoundKeyProvider),
        diport::DynKeyProvider::new_box(AadBoundKeyProvider),
        diport::KeyName::try_new("settings-config").unwrap(),
    )
}

#[allow(clippy::unwrap_used)]
pub(in super::super) fn rejecting_config_protection() -> ConfigValueProtection {
    ConfigValueProtection::new(
        diport::DynKeyProvider::new_box(RejectingKeyProvider),
        diport::KeyName::try_new("settings-config").unwrap(),
    )
}

#[allow(clippy::unwrap_used)]
pub(in super::super) fn unavailable_config_protection() -> ConfigValueProtection {
    ConfigValueProtection::new(
        diport::DynKeyProvider::new_box(UnavailableKeyProvider),
        diport::KeyName::try_new("settings-config").unwrap(),
    )
}

#[allow(clippy::unwrap_used)]
pub(in super::super) fn rewrapping_config_protection() -> ConfigValueProtection {
    ConfigValueProtection::new(
        diport::DynKeyProvider::new_box(RewrappingKeyProvider),
        diport::KeyName::try_new("settings-config").unwrap(),
    )
}

#[allow(clippy::unwrap_used)]
pub(in super::super) fn mutating_backfill_config_protection(
    pool: sqlx::PgPool,
) -> ConfigValueProtection {
    ConfigValueProtection::new(
        diport::DynKeyProvider::new_box(MutatingBackfillKeyProvider { pool }),
        diport::KeyName::try_new("settings-config").unwrap(),
    )
}

/// 构造 config-version-changed outbox EventEntry。
#[allow(clippy::unwrap_used)]
pub(in super::super) fn config_outbox_entry(event_id: &str) -> EventEntry {
    generated_entry(
        generated::event::settings_v1::FACT,
        &generated::event::settings_v1::SettingsConfigVersionChangedPayload {
            change_kind: generated::event::settings_v1::SettingsConfigChangeKind::Published,
            key: "app.k".to_string(),
            occurred_at: i64::try_from(TEST_OCCURRED_SECS).unwrap(),
            source_version: None,
            tenant_id: CONFIG_TENANT.to_string(),
            version: 1,
        },
        IdemKey::parse(event_id).unwrap(),
    )
    .unwrap()
}

#[allow(clippy::unwrap_used)]
pub(in super::super) fn config_deleted_outbox_entry(
    event_id: &str,
    key: &str,
    version: u64,
) -> EventEntry {
    generated_entry(
        generated::event::settings_v1::FACT,
        &generated::event::settings_v1::SettingsConfigVersionChangedPayload {
            change_kind: generated::event::settings_v1::SettingsConfigChangeKind::Deleted,
            key: key.to_string(),
            occurred_at: i64::try_from(TEST_OCCURRED_SECS).unwrap(),
            source_version: None,
            tenant_id: CONFIG_TENANT.to_string(),
            version: i64::try_from(version).unwrap(),
        },
        IdemKey::parse(event_id).unwrap(),
    )
    .unwrap()
}

#[allow(clippy::unwrap_used)]
pub(in super::super) fn config_rolled_back_outbox_entry(
    event_id: &str,
    key: &str,
    version: u64,
    source_version: u64,
) -> EventEntry {
    generated_entry(
        generated::event::settings_v1::FACT,
        &generated::event::settings_v1::SettingsConfigVersionChangedPayload {
            change_kind: generated::event::settings_v1::SettingsConfigChangeKind::RolledBack,
            key: key.to_string(),
            occurred_at: i64::try_from(TEST_OCCURRED_SECS).unwrap(),
            source_version: Some(i64::try_from(source_version).unwrap()),
            tenant_id: CONFIG_TENANT.to_string(),
            version: i64::try_from(version).unwrap(),
        },
        IdemKey::parse(event_id).unwrap(),
    )
    .unwrap()
}

/// 构造 config-version-changed envelope（opaque subject = 配置 key）。
pub(in super::super) fn config_envelope(subject: &str) -> OutboxEnvelopeParts {
    config_envelope_for(config_tenant(), subject)
}

pub(in super::super) fn config_envelope_for(
    tenant: TenantId,
    subject: &str,
) -> OutboxEnvelopeParts {
    OutboxEnvelopeParts::new(
        config_contract(),
        tenant,
        subject_id(subject),
        actor_for(tenant),
    )
}

pub(in super::super) trait ConfigTestWrite {
    async fn test_put(
        &self,
        scope: TenantRepoScope,
        entry: ConfigEntry,
    ) -> Result<(), ConfigRepoError>;

    async fn test_delete(
        &self,
        scope: TenantRepoScope,
        key: &SettingKey,
    ) -> Result<(), ConfigRepoError>;
}

impl ConfigTestWrite for PgConfigRepo {
    async fn test_put(
        &self,
        scope: TenantRepoScope,
        entry: ConfigEntry,
    ) -> Result<(), ConfigRepoError> {
        let tenant = entry.tenant();
        let subject = entry.key().as_str().to_string();
        self.commit_publish(
            settings::config_publish_receipt_for_test(),
            scope,
            ConfigMutation::Put(entry),
            reviewed_generated_event::<generated::event::settings_v1::Contract>(
                config_outbox_entry(&unique_event_id("config-test-put")),
                config_envelope_for(tenant, &subject),
            )
            .await
            .map_err(ConfigRepoError::Storage)?,
        )
        .await
    }

    async fn test_delete(
        &self,
        scope: TenantRepoScope,
        key: &SettingKey,
    ) -> Result<(), ConfigRepoError> {
        let tenant = scope.tenant();
        let Some(ConfigHead::Active(version)) = self.head(scope, key).await? else {
            return Ok(());
        };
        let result = self
            .commit_delete(
                settings::config_delete_receipt_for_test(),
                scope,
                ConfigMutation::Delete(ConfigTombstone::hydrate(
                    key.clone(),
                    tenant,
                    version.saturating_add(1),
                )),
                reviewed_generated_event::<generated::event::settings_v1::Contract>(
                    config_outbox_entry(&unique_event_id("config-test-delete")),
                    config_envelope_for(tenant, key.as_str()),
                )
                .await
                .map_err(ConfigRepoError::Storage)?,
            )
            .await;
        match result {
            Err(ConfigRepoError::VersionConflict)
                if matches!(self.head(scope, key).await?, Some(ConfigHead::Deleted(_))) =>
            {
                Ok(())
            }
            other => other,
        }
    }
}

/// setup：应用 migration（含 config_entries 表），清空 config_entries（防测试间污染）。outbox 用唯一
/// event_id 隔离断言，无需全表清。integration profile 串行执行（`.config/nextest.toml` `integration`
/// group `max-threads = 1` + self-provision 容器每轮独占），故全表 DELETE 无并发竞态。
pub(in super::super) async fn setup_config(
    store: &PgStore,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    store.run_migrations().await?;
    sqlx::query("DELETE FROM config_entries")
        .execute(&store.pool)
        .await?;
    Ok(())
}

/// 构造 application 同款 event_id（`{topic}:{tenant}:{key}:v{version}`）——tc10 验 delete+republish 不复用。
pub(in super::super) fn config_event_id(tenant: TenantId, key: &str, version: u64) -> String {
    format!("{CONFIG_VERSION_CHANGED_TOPIC}:{tenant}:{key}:v{version}")
}

pub(in super::super) use settings::ports::{
    SecretEntry, SecretInternalPublishCommand, SecretKey, SecretPublishCommand, SecretRef,
    SecretRepo, SecretRepoError, SecretRepublishCommand, SecretUnitOfWork, StoreId,
};

/// secret 测试用 canonical 租户 UUID（复用 co-tx 段 [`COTX_TENANT_A`] 同值）。
pub(in super::super) const SECRET_TENANT_A: &str = COTX_TENANT_A;

/// setup：应用 migration（含 secret_refs 表），清空 secret_refs（防测试间污染）。
pub(in super::super) async fn setup_secret(
    store: &PgStore,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    store.run_migrations().await?;
    sqlx::query("DELETE FROM secret_refs")
        .execute(&store.pool)
        .await?;
    Ok(())
}

#[allow(clippy::unwrap_used)]
// reason: 集成测试 happy-path 构造已知合法值；item-level carve-out（error-handling.md §Carve-out）。
pub(in super::super) fn secret_tenant_a() -> TenantId {
    TenantId::parse(SECRET_TENANT_A).unwrap()
}

/// 构造 SecretEntry（经 `SecretRef::parse` + `SecretEntry::hydrate` 跨 crate pub funnel）。
#[allow(clippy::unwrap_used)]
pub(in super::super) fn make_secret_entry(
    key: &str,
    store_id: &str,
    ref_key: &str,
    ref_version: Option<&str>,
    version: u64,
    tenant: TenantId,
) -> SecretEntry {
    let secret_ref =
        SecretRef::parse(StoreId::parse(store_id).unwrap(), ref_key, ref_version).unwrap();
    SecretEntry::hydrate(SecretKey::parse(key).unwrap(), secret_ref, tenant, version)
}

pub(in super::super) fn internal_secret_publish(
    entry: SecretEntry,
) -> SecretInternalPublishCommand {
    SecretInternalPublishCommand::for_test(entry)
}

pub(in super::super) fn http_secret_publish(entry: SecretEntry) -> SecretPublishCommand {
    SecretPublishCommand::for_test(entry)
}

pub(in super::super) fn secret_republish(entry: SecretEntry) -> SecretRepublishCommand {
    SecretRepublishCommand::for_test(entry)
}

pub(in super::super) async fn secret_ref_row_count(
    store: &PgStore,
    tenant: TenantId,
    key: &SecretKey,
) -> Result<usize, SecretRepoError> {
    let (count,): (i64,) = sqlx::query_as(
        "SELECT count(*) FROM secret_refs WHERE tenant_id = $1::uuid AND secret_key = $2",
    )
    .bind(tenant.as_uuid().to_string())
    .bind(key.as_str())
    .fetch_one(&store.pool)
    .await
    .map_err(|error| SecretRepoError::Storage(Box::new(error)))?;
    usize::try_from(count).map_err(|error| SecretRepoError::Storage(Box::new(error)))
}
