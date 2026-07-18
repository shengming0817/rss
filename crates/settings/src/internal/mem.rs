//! settings 配置 / flag / secret 仓储 in-memory 实现（RW-W 种子数据 + Join 追踪弹）。生产持久化（postgres adapter
//! impl [`crate::ports::ConfigRepo`] / [`crate::ports::ConfigUnitOfWork`] / [`crate::ports::SecretRepo`]）
//! 见 #1249 / #1274。
//!
//! 锁中毒（仅持锁线程 panic 时发生）恢复 guard 而非 panic：in-mem 替身不在持锁时 panic，且 lib 禁
//! `unwrap`/`expect`（clippy deny）。`unwrap_or_else(into_inner)` 取回 guard，clippy-clean（对标 memory adapter）。
//!
//! 读端口 [`InMemConfigRepo`] 与写 UoW [`InMemConfigUnitOfWork`] 经 `Arc` **共享同一 store**（`with_seed`
//! clone 注入）——保证 `find` 读得到 `commit` 写入（与 postgres 同 pool 数据一致性对齐）。
//!
//! [`InMemSecretRepo`] 为独立 store（L1 本地事务，无 outbox，`Arc<Mutex<...>>` 共享）。

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use consistency::EventEntry;
use diport::{OutboxEmitter, OutboxEnvelopeParts};
use vocab::TenantId;

use super::ports::FlagStore;
use crate::domain::{
    ConfigEntry, ConfigHead, ConfigMutation, ConfigRepoError, FlagKey, FlagState, SettingKey,
};
#[cfg(any(test, feature = "seed-data"))]
use crate::domain::{SecretEntry, SecretKey, SecretRepoError};
use crate::ports::{
    ConfigDeleteReceipt, ConfigPublishReceipt, ConfigRepo, ConfigRollbackReceipt, ConfigUnitOfWork,
    TenantRepoScope,
};
#[cfg(any(test, feature = "seed-data"))]
use crate::ports::{
    SecretInternalPublishCommand, SecretPublishCommand, SecretRepo, SecretRepublishCommand,
    SecretUnitOfWork,
};

/// 复合存储键（租户隔离）：(tenant, key 字符串)。
type StoreKey = (TenantId, String);

/// 单条版本行：配置条目 + tombstone 标记（`deleted=true` ⇒ 删除墓碑，`find` 视为已删；对齐 postgres
/// `config_entries.deleted` 列，#1249 F1）。`pub(crate)` 因 [`ConfigStore`] 别名入 `pub(crate)` 构造器签名；
/// 字段私有，仅本模块构造 / 读取。
#[derive(Clone)]
pub(crate) struct ConfigRow {
    entry: ConfigEntry,
    deleted: bool,
}

/// in-mem 版本化配置 store：版本历史与 co-tx commit lock 必须共享同一个 `Arc`。多个 UoW 若只共享
/// entries 而各持一把锁，失败 emit 的回滚会与另一 UoW 的后续版本交错并留下 ghost row。
pub(crate) struct ConfigStoreInner {
    entries: Mutex<HashMap<StoreKey, Vec<ConfigRow>>>,
    commit_lock: tokio::sync::Mutex<()>,
}

type ConfigStore = Arc<ConfigStoreInner>;

/// 新建空共享 store（`with_seed` 经此建一份、clone 进读端口与写 UoW）。
pub(crate) fn new_config_store() -> ConfigStore {
    Arc::new(ConfigStoreInner {
        entries: Mutex::new(HashMap::new()),
        commit_lock: tokio::sync::Mutex::new(()),
    })
}

/// CAS 追加新版本到共享 store：新版本号须恰为当前最高版本 + 1（首版 = 1），否则乐观并发写冲突。
/// `len()` 含 tombstone ⇒ delete 后 version 单调不重置（与 postgres CAS `max(version)+1` 同语义，F1）。
fn cas_insert(
    store: &ConfigStore,
    tenant: TenantId,
    entry: ConfigEntry,
) -> Result<(), ConfigRepoError> {
    let mut entries = store.entries.lock().unwrap_or_else(|e| e.into_inner());
    let history = entries
        .entry((tenant, entry.key().as_str().to_string()))
        .or_default();
    // reason: history.len() 超 u64::MAX（实践不可能）→ saturating 到 MAX 使 CAS 永不通过，fail-closed
    let expected = u64::try_from(history.len())
        .unwrap_or(u64::MAX)
        .saturating_add(1);
    if entry.version() != expected {
        return Err(ConfigRepoError::VersionConflict);
    }
    history.push(ConfigRow {
        entry,
        deleted: false,
    });
    Ok(())
}

fn cas_mutation(
    store: &ConfigStore,
    tenant: TenantId,
    mutation: &ConfigMutation,
) -> Result<(), ConfigRepoError> {
    if mutation.tenant() != tenant {
        return Err(ConfigRepoError::Storage(Box::new(std::io::Error::other(
            "config tenant mismatch",
        ))));
    }
    match mutation {
        ConfigMutation::Put(entry) => cas_insert(store, tenant, entry.clone()),
        ConfigMutation::Delete(tombstone) => {
            let mut entries = store.entries.lock().unwrap_or_else(|e| e.into_inner());
            let Some(history) = entries.get_mut(&(tenant, tombstone.key().as_str().to_string()))
            else {
                return Err(ConfigRepoError::VersionConflict);
            };
            let expected = u64::try_from(history.len())
                .unwrap_or(u64::MAX)
                .saturating_add(1);
            if tombstone.version() != expected || history.last().is_none_or(|row| row.deleted) {
                return Err(ConfigRepoError::VersionConflict);
            }
            history.push(ConfigRow {
                entry: ConfigEntry::hydrate(
                    tombstone.key().clone(),
                    "",
                    tenant,
                    tombstone.version(),
                ),
                deleted: true,
            });
            Ok(())
        }
    }
}

/// emit 失败时撤销刚追加的 mutation。commit lock 保证同一 UoW 不会在追加与撤销之间交错写入。
fn rollback_mutation(store: &ConfigStore, tenant: TenantId, mutation: &ConfigMutation) {
    let store_key = (tenant, mutation.key().as_str().to_string());
    let mut entries = store.entries.lock().unwrap_or_else(|e| e.into_inner());
    let should_remove = entries.get_mut(&store_key).is_some_and(|history| {
        if history
            .last()
            .is_some_and(|row| row.entry.version() == mutation.version())
        {
            history.pop();
        }
        history.is_empty()
    });
    if should_remove {
        entries.remove(&store_key);
    }
}

/// in-memory 版本化配置仓储（纯读）。共享 [`ConfigStore`]。
pub(crate) struct InMemConfigRepo {
    entries: ConfigStore,
}

impl InMemConfigRepo {
    /// 由共享 store 构造（`with_seed`：与写 UoW 同源；repo-only 单测传独立 `new_config_store()`）。
    pub(crate) fn from_shared(entries: ConfigStore) -> Self {
        Self { entries }
    }
}

impl ConfigRepo for InMemConfigRepo {
    async fn find(
        &self,
        scope: TenantRepoScope,
        key: &SettingKey,
    ) -> Result<Option<ConfigEntry>, ConfigRepoError> {
        let tenant = scope.tenant();
        let entries = self
            .entries
            .entries
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        // 活跃值 = latest 行且非 tombstone（latest 为 tombstone ⇒ 已删 None）。
        Ok(entries
            .get(&(tenant, key.as_str().to_string()))
            .and_then(|history| history.last())
            .filter(|row| !row.deleted)
            .map(|row| row.entry.clone()))
    }

    async fn find_version(
        &self,
        scope: TenantRepoScope,
        key: &SettingKey,
        version: u64,
    ) -> Result<Option<ConfigEntry>, ConfigRepoError> {
        let tenant = scope.tenant();
        let entries = self
            .entries
            .entries
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        Ok(entries
            .get(&(tenant, key.as_str().to_string()))
            .and_then(|history| history.iter().find(|row| row.entry.version() == version))
            .filter(|row| !row.deleted)
            .map(|row| row.entry.clone()))
    }

    async fn head(
        &self,
        scope: TenantRepoScope,
        key: &SettingKey,
    ) -> Result<Option<ConfigHead>, ConfigRepoError> {
        let tenant = scope.tenant();
        let entries = self
            .entries
            .entries
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        // 真实最高版本（含 tombstone）——业务层算下一版本用，delete 后不重置。
        Ok(entries
            .get(&(tenant, key.as_str().to_string()))
            .and_then(|history| history.last())
            .map(|row| {
                if row.deleted {
                    ConfigHead::Deleted(row.entry.version())
                } else {
                    ConfigHead::Active(row.entry.version())
                }
            }))
    }
}

/// in-memory 配置写 **co-tx** UoW 替身（追踪弹 / demo）：CAS save（共享 store）+ emit。
///
/// 泛型于**具体** emitter `E`（非 `Box<DynOutboxEmitter>`）：`ConfigUnitOfWork` 是 `: Send` 端口，其
/// `&self` future 须 Send ⇒ 本类型须 `Sync`；而 `DynOutboxEmitter` dyn wrapper 仅 `Send` 非 `Sync`（持之则
/// 非 Sync）。`E` 取具体 `Sync` 类型（`memory::MemEmitter` / 测试 `CapturingEmitter`，均 `Arc` 底座）即满足。
///
/// in-memory 没有数据库事务，因此以串行 commit + emit 失败撤销实现 both-or-neither 的可观察终态；生产
/// `PgConfigUnitOfWork` 仍以数据库同事务提供完整隔离。
pub(crate) struct InMemConfigUnitOfWork<E> {
    entries: ConfigStore,
    emitter: E,
}

impl<E> InMemConfigUnitOfWork<E> {
    /// 由共享 store + 具体 outbox emitter 构造（`with_seed` 注入 `memory::MemEmitter`）。
    pub(crate) fn new(entries: ConfigStore, emitter: E) -> Self {
        Self { entries, emitter }
    }
}

fn authorize_entry<M>(
    receipt: httpserve::ProducerAssuranceReceipt<M>,
    entry: &EventEntry,
    envelope: &OutboxEnvelopeParts,
    expected_contract: vocab::ContractBinding,
) -> Option<httpserve::ProducerAuthorization<M>> {
    let fact = entry.generated_fact()?;
    if *envelope.contract() != fact.contract() {
        return None;
    }
    receipt.authorize(fact, expected_contract)
}

impl<E: OutboxEmitter + Send + Sync + 'static> InMemConfigUnitOfWork<E> {
    async fn commit_authorized(
        &self,
        authorized_fact: vocab::ContractBinding,
        scope: TenantRepoScope,
        mutation: ConfigMutation,
        outbox_entry: EventEntry,
        envelope: OutboxEnvelopeParts,
    ) -> Result<(), ConfigRepoError> {
        let _commit = self.entries.commit_lock.lock().await;
        let tenant = scope.tenant();
        if mutation.tenant() != tenant
            || envelope.tenant() != tenant
            || *envelope.contract() != authorized_fact
        {
            return Err(ConfigRepoError::Storage(Box::new(std::io::Error::other(
                "config producer authorization mismatch",
            ))));
        }
        cas_mutation(&self.entries, tenant, &mutation)?;
        if let Err(error) = self.emitter.emit(outbox_entry, envelope).await {
            rollback_mutation(&self.entries, tenant, &mutation);
            return Err(ConfigRepoError::Storage(Box::new(error)));
        }
        Ok(())
    }
}

impl<E: OutboxEmitter + Send + Sync + 'static> ConfigUnitOfWork for InMemConfigUnitOfWork<E> {
    async fn commit_publish(
        &self,
        receipt: ConfigPublishReceipt,
        scope: TenantRepoScope,
        mutation: ConfigMutation,
        outbox_entry: EventEntry,
        envelope: OutboxEnvelopeParts,
    ) -> Result<(), ConfigRepoError> {
        let authorization = authorize_entry(
            receipt,
            &outbox_entry,
            &envelope,
            crate::ports::CONFIG_VERSION_CHANGED_CONTRACT,
        )
        .ok_or_else(|| {
            ConfigRepoError::Storage(Box::new(std::io::Error::other(
                "config publish receipt does not authorize generated fact",
            )))
        })?;
        self.commit_authorized(
            authorization.fact_contract(),
            scope,
            mutation,
            outbox_entry,
            envelope,
        )
        .await
    }

    async fn commit_delete(
        &self,
        receipt: ConfigDeleteReceipt,
        scope: TenantRepoScope,
        mutation: ConfigMutation,
        outbox_entry: EventEntry,
        envelope: OutboxEnvelopeParts,
    ) -> Result<(), ConfigRepoError> {
        let authorization = authorize_entry(
            receipt,
            &outbox_entry,
            &envelope,
            crate::ports::CONFIG_VERSION_CHANGED_CONTRACT,
        )
        .ok_or_else(|| {
            ConfigRepoError::Storage(Box::new(std::io::Error::other(
                "config delete receipt does not authorize generated fact",
            )))
        })?;
        self.commit_authorized(
            authorization.fact_contract(),
            scope,
            mutation,
            outbox_entry,
            envelope,
        )
        .await
    }

    async fn commit_rollback(
        &self,
        receipt: ConfigRollbackReceipt,
        scope: TenantRepoScope,
        mutation: ConfigMutation,
        outbox_entry: EventEntry,
        envelope: OutboxEnvelopeParts,
    ) -> Result<(), ConfigRepoError> {
        let authorization = authorize_entry(
            receipt,
            &outbox_entry,
            &envelope,
            crate::ports::CONFIG_VERSION_CHANGED_CONTRACT,
        )
        .ok_or_else(|| {
            ConfigRepoError::Storage(Box::new(std::io::Error::other(
                "config rollback receipt does not authorize generated fact",
            )))
        })?;
        self.commit_authorized(
            authorization.fact_contract(),
            scope,
            mutation,
            outbox_entry,
            envelope,
        )
        .await
    }
}

// ---------------------------------------------------------------------------
// InMemSecretRepo
// ---------------------------------------------------------------------------

/// 单条 secret 版本行（镜像 [`ConfigRow`]）。
#[cfg(any(test, feature = "seed-data"))]
#[derive(Clone)]
// reason: secret 版本行供 InMemSecretRepo 内部使用（测试替身 / seed-data 演示）；非生产常规路径。
#[allow(dead_code)]
pub(crate) struct SecretRow {
    entry: SecretEntry,
    /// tombstone 标记（`deleted=true` ⇒ 软删；`find` 视为已删，version 单调不重置）。
    deleted: bool,
}

/// in-mem secret 版本化 store：每 key 一条 append-only 版本历史（含 tombstone）。
/// `Arc` 共享供测试 / seed-data 使用（`SecretService::new` 注入同一 store）。
#[cfg(any(test, feature = "seed-data"))]
type SecretStore = Arc<Mutex<HashMap<(TenantId, String), Vec<SecretRow>>>>;

/// 新建空共享 secret store。
#[cfg(any(test, feature = "seed-data"))]
// reason: 供测试与 seed-data 演示场景调用；生产路径不用（PgSecretRepo 替代）。
#[allow(dead_code)]
pub(crate) fn new_secret_store() -> SecretStore {
    Arc::new(Mutex::new(HashMap::new()))
}

/// CAS 追加新 secret 版本（镜像 `cas_insert` for ConfigStore）。
#[cfg(any(test, feature = "seed-data"))]
fn secret_cas_insert(
    store: &SecretStore,
    tenant: TenantId,
    entry: SecretEntry,
) -> Result<(), SecretRepoError> {
    let mut entries = store.lock().unwrap_or_else(|e| e.into_inner());
    let history = entries
        .entry((tenant, entry.key().as_str().to_string()))
        .or_default();
    // reason: len() 超 u64::MAX（实践不可能）→ saturating MAX 使 CAS 永不通过，fail-closed。
    let expected = u64::try_from(history.len())
        .unwrap_or(u64::MAX)
        .saturating_add(1);
    if entry.version() != expected {
        return Err(SecretRepoError::VersionConflict);
    }
    history.push(SecretRow {
        entry,
        deleted: false,
    });
    Ok(())
}

/// in-memory secret 仓储（`#[cfg(any(test, feature = "seed-data"))]`）。
///
/// CAS 版本化 + tombstone 软删（镜像 [`InMemConfigRepo`]）。无 outbox（L1 本地事务）。
#[cfg(any(test, feature = "seed-data"))]
// reason: 测试替身 / seed-data 演示用；生产路径使用 PgSecretRepo。
#[allow(dead_code)]
pub(crate) struct InMemSecretRepo {
    entries: SecretStore,
}

#[cfg(any(test, feature = "seed-data"))]
impl InMemSecretRepo {
    /// 由共享 store 构造（测试：独立 `new_secret_store()`；seed-data：与 service 同源）。
    // reason: 供测试场景调用（SecretService::new 注入替身）；seed-data 生产模式暂未接线。
    #[allow(dead_code)]
    pub(crate) fn from_shared(entries: SecretStore) -> Self {
        Self { entries }
    }

    fn append_active_entry(
        &self,
        scope: TenantRepoScope,
        entry: SecretEntry,
    ) -> Result<(), SecretRepoError> {
        let tenant = scope.tenant();
        if entry.tenant() != tenant {
            return Err(SecretRepoError::Storage(Box::new(std::io::Error::other(
                "secret mutation tenant mismatch",
            ))));
        }
        secret_cas_insert(&self.entries, tenant, entry)
    }
}

#[cfg(any(test, feature = "seed-data"))]
impl SecretRepo for InMemSecretRepo {
    async fn find(
        &self,
        scope: TenantRepoScope,
        key: &SecretKey,
    ) -> Result<Option<SecretEntry>, SecretRepoError> {
        let tenant = scope.tenant();
        let entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        Ok(entries
            .get(&(tenant, key.as_str().to_string()))
            .and_then(|h| h.last())
            .filter(|row| !row.deleted)
            .map(|row| row.entry.clone()))
    }

    async fn find_version(
        &self,
        scope: TenantRepoScope,
        key: &SecretKey,
        version: u64,
    ) -> Result<Option<SecretEntry>, SecretRepoError> {
        let tenant = scope.tenant();
        let entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        Ok(entries
            .get(&(tenant, key.as_str().to_string()))
            .and_then(|h| h.iter().find(|row| row.entry.version() == version))
            .filter(|row| !row.deleted)
            .map(|row| row.entry.clone()))
    }

    async fn latest_version(
        &self,
        scope: TenantRepoScope,
        key: &SecretKey,
    ) -> Result<Option<u64>, SecretRepoError> {
        let tenant = scope.tenant();
        let entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        Ok(entries
            .get(&(tenant, key.as_str().to_string()))
            .and_then(|h| h.last())
            .map(|row| row.entry.version()))
    }
}

#[cfg(any(test, feature = "seed-data"))]
impl SecretUnitOfWork for InMemSecretRepo {
    async fn publish(
        &self,
        scope: TenantRepoScope,
        command: SecretPublishCommand,
    ) -> Result<(), SecretRepoError> {
        let (entry, _observation) = command.into_parts();
        self.append_active_entry(scope, entry)
    }

    async fn publish_internal(
        &self,
        scope: TenantRepoScope,
        command: SecretInternalPublishCommand,
    ) -> Result<(), SecretRepoError> {
        self.append_active_entry(scope, command.into_entry())
    }

    async fn republish(
        &self,
        scope: TenantRepoScope,
        command: SecretRepublishCommand,
    ) -> Result<(), SecretRepoError> {
        self.append_active_entry(scope, command.into_entry())
    }

    async fn delete(&self, scope: TenantRepoScope, key: &SecretKey) -> Result<(), SecretRepoError> {
        let tenant = scope.tenant();
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        // 软删（tombstone）：仅当 latest 非 tombstone 时追加（幂等；version 单调不重置）。
        if let Some(history) = entries.get_mut(&(tenant, key.as_str().to_string()))
            && history.last().is_some_and(|row| !row.deleted)
        {
            // reason: len() 超 u64::MAX 实践不可能 → saturating MAX，fail-closed。
            let version = u64::try_from(history.len())
                .unwrap_or(u64::MAX)
                .saturating_add(1);
            // 构造 tombstone entry（经 hydrate 受信路径——静态占位，不被 `find` 读取（deleted=true））。
            use crate::domain::StoreId;
            #[allow(clippy::expect_used)]
            let tombstone_store =
                StoreId::parse("tombstone").expect("static tombstone store id is valid");
            let tombstone =
                SecretEntry::hydrate(key.clone(), tombstone_store, "_", None, tenant, version);
            history.push(SecretRow {
                entry: tombstone,
                deleted: true,
            });
        }
        Ok(())
    }
}

/// in-memory flag 仓储：(tenant, flag key) → 最新 flag 状态快照。
pub(crate) struct InMemFlagStore {
    flags: Mutex<HashMap<StoreKey, FlagState>>,
}

impl InMemFlagStore {
    /// 新建空 flag 仓储。
    pub(crate) fn new() -> Self {
        Self {
            flags: Mutex::new(HashMap::new()),
        }
    }

    /// 种子一条 flag（单测）。本 PR flag 写入路径未落地（订阅缓存 consumer #1120 填充），故仅测试消费。
    #[cfg(test)]
    pub(crate) fn with_flag(self, tenant: TenantId, flag: FlagState) -> Self {
        {
            let mut flags = self.flags.lock().unwrap_or_else(|e| e.into_inner());
            flags.insert((tenant, flag.key().as_str().to_string()), flag);
        }
        self
    }
}

impl FlagStore for InMemFlagStore {
    fn find(&self, tenant: TenantId, key: &FlagKey) -> Option<FlagState> {
        let flags = self.flags.lock().unwrap_or_else(|e| e.into_inner());
        flags.get(&(tenant, key.as_str().to_string())).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{ConfigValue, ConfigVersion, SecretKey, StoreId};
    use diport::{EnvelopeSubjectId, OpaqueActorId, OutboxActor};

    const TENANT_A: &str = "f47ac10b-58cc-4372-a567-0e02b2c3d479";
    const TENANT_B: &str = "00000000-0000-4000-8000-000000000abc";

    #[derive(Clone, Default)]
    struct CountingEmitter {
        emits: Arc<Mutex<usize>>,
    }

    impl CountingEmitter {
        fn emitted(&self) -> usize {
            *self.emits.lock().unwrap_or_else(|e| e.into_inner())
        }
    }

    impl OutboxEmitter for CountingEmitter {
        async fn emit(
            &self,
            _entry: EventEntry,
            _envelope: OutboxEnvelopeParts,
        ) -> Result<(), diport::OutboxEmitError> {
            *self.emits.lock().unwrap_or_else(|e| e.into_inner()) += 1;
            Ok(())
        }
    }

    struct FailingEmitter;

    impl OutboxEmitter for FailingEmitter {
        async fn emit(
            &self,
            _entry: EventEntry,
            _envelope: OutboxEnvelopeParts,
        ) -> Result<(), diport::OutboxEmitError> {
            Err(diport::OutboxEmitError::new(std::io::Error::other(
                "synthetic emit failure",
            )))
        }
    }

    struct BlockingFailingEmitter {
        entered: Arc<tokio::sync::Notify>,
        release: Arc<tokio::sync::Notify>,
    }

    impl OutboxEmitter for BlockingFailingEmitter {
        async fn emit(
            &self,
            _entry: EventEntry,
            _envelope: OutboxEnvelopeParts,
        ) -> Result<(), diport::OutboxEmitError> {
            self.entered.notify_one();
            self.release.notified().await;
            Err(diport::OutboxEmitError::new(std::io::Error::other(
                "synthetic delayed emit failure",
            )))
        }
    }

    #[allow(clippy::expect_used)]
    fn tenant(raw: &str) -> TenantId {
        TenantId::parse(raw).expect("canonical tenant")
    }

    fn scope(raw: &str) -> TenantRepoScope {
        TenantRepoScope::for_test(tenant(raw))
    }

    #[allow(clippy::expect_used)]
    fn setting_key(raw: &str) -> SettingKey {
        SettingKey::parse(raw).expect("valid setting key")
    }

    #[allow(clippy::expect_used)]
    fn secret_key(raw: &str) -> SecretKey {
        SecretKey::parse(raw).expect("valid secret key")
    }

    #[allow(clippy::expect_used)]
    fn config_entry(raw_key: &str, tenant_raw: &str) -> ConfigEntry {
        config_entry_version(raw_key, tenant_raw, 1)
    }

    #[allow(clippy::expect_used)]
    fn config_entry_version(raw_key: &str, tenant_raw: &str, version: u64) -> ConfigEntry {
        ConfigEntry::new(
            setting_key(raw_key),
            ConfigValue::new("v1"),
            tenant(tenant_raw),
            ConfigVersion::new(version),
        )
    }

    #[allow(clippy::expect_used)]
    fn secret_entry(raw_key: &str, tenant_raw: &str) -> SecretEntry {
        SecretEntry::hydrate(
            secret_key(raw_key),
            StoreId::parse("vault").expect("valid store"),
            "secret/path",
            None,
            tenant(tenant_raw),
            1,
        )
    }

    #[allow(clippy::expect_used)]
    fn entry(event_id: &str) -> EventEntry {
        let payload = generated::event::settings_v1::SettingsConfigVersionChangedPayload {
            change_kind: generated::event::settings_v1::SettingsConfigChangeKind::Published,
            key: "app.test".to_string(),
            occurred_at: 1,
            source_version: None,
            tenant_id: TENANT_A.to_string(),
            version: 1,
        };
        EventEntry::from_generated_payload(
            &payload,
            consistency::IdemKey::parse(event_id).expect("event id"),
        )
        .expect("test payload encodes")
    }

    #[allow(clippy::expect_used)]
    fn missing_fact_entry(event_id: &str) -> EventEntry {
        EventEntry::new(
            consistency::EventTopic::parse("settings.config-version-changed").expect("topic"),
            consistency::IdemKey::parse(event_id).expect("event id"),
            consistency::OutboxPayload::from_reviewed_event_bytes(b"{}".to_vec()),
        )
    }

    #[allow(clippy::expect_used)]
    fn wrong_fact_entry(event_id: &str) -> EventEntry {
        let payload =
            generated::event::identity_v1::session_created::IdentitySessionCreatedPayload {
                occurred_at: 1,
                session_id: "session-test".to_string(),
                subject: "11111111-2222-4333-8444-555555555555"
                    .parse()
                    .expect("uuid"),
                tenant_id: TENANT_A.to_string(),
            };
        EventEntry::from_generated_payload(
            &payload,
            consistency::IdemKey::parse(event_id).expect("event id"),
        )
        .expect("test payload encodes")
    }

    #[allow(clippy::expect_used)]
    fn envelope(tenant_raw: &str) -> OutboxEnvelopeParts {
        let tenant = tenant(tenant_raw);
        OutboxEnvelopeParts::new(
            generated::event::settings_v1::CONTRACT,
            tenant,
            EnvelopeSubjectId::from_opaque("app.scope").expect("subject"),
            OutboxActor::scoped(
                vocab::PrincipalKind::Admin,
                OpaqueActorId::from_opaque("actor").expect("actor"),
                tenant,
                vocab::ScopedTenant::Tenant,
            ),
        )
    }

    fn publish_receipt() -> ConfigPublishReceipt {
        httpserve::ProducerMarker::for_test(generated::http::settings_v1::PRODUCER).into_receipt()
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn config_uow_rejects_missing_and_wrong_entry_fact_before_mutation() {
        for (suffix, outbox_entry) in [
            ("missing", missing_fact_entry("evt-config-missing-fact")),
            ("wrong", wrong_fact_entry("evt-config-wrong-entry-fact")),
        ] {
            let store = new_config_store();
            let emitter = CountingEmitter::default();
            let uow = InMemConfigUnitOfWork::new(store.clone(), emitter.clone());
            let repo = InMemConfigRepo::from_shared(store);
            let raw_key = format!("app.{suffix}-fact");
            let key = setting_key(&raw_key);

            let result = uow
                .commit_publish(
                    publish_receipt(),
                    scope(TENANT_A),
                    ConfigMutation::Put(config_entry(&raw_key, TENANT_A)),
                    outbox_entry,
                    envelope(TENANT_A),
                )
                .await;

            assert!(
                matches!(result, Err(ConfigRepoError::Storage(_))),
                "{suffix} generated fact must fail closed"
            );
            assert!(
                repo.find(scope(TENANT_A), &key)
                    .await
                    .expect("find")
                    .is_none(),
                "{suffix} generated fact must fail before mutation"
            );
            assert_eq!(
                emitter.emitted(),
                0,
                "{suffix} generated fact must fail before emit"
            );
        }
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn config_uow_rejects_entry_tenant_mismatch_without_write_or_emit() {
        let store = new_config_store();
        let emitter = CountingEmitter::default();
        let uow = InMemConfigUnitOfWork::new(store.clone(), emitter.clone());
        let repo = InMemConfigRepo::from_shared(store);
        let key = setting_key("app.scope");

        let result = uow
            .commit_publish(
                publish_receipt(),
                scope(TENANT_A),
                ConfigMutation::Put(config_entry("app.scope", TENANT_B)),
                entry("evt-config-entry-mismatch"),
                envelope(TENANT_A),
            )
            .await;

        assert!(matches!(result, Err(ConfigRepoError::Storage(_))));
        assert!(
            repo.find(scope(TENANT_B), &key)
                .await
                .expect("find")
                .is_none()
        );
        assert_eq!(emitter.emitted(), 0);
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn config_uow_rejects_envelope_tenant_mismatch_without_write_or_emit() {
        let store = new_config_store();
        let emitter = CountingEmitter::default();
        let uow = InMemConfigUnitOfWork::new(store.clone(), emitter.clone());
        let repo = InMemConfigRepo::from_shared(store);
        let key = setting_key("app.envelope");

        let result = uow
            .commit_publish(
                publish_receipt(),
                scope(TENANT_A),
                ConfigMutation::Put(config_entry("app.envelope", TENANT_A)),
                entry("evt-config-envelope-mismatch"),
                envelope(TENANT_B),
            )
            .await;

        assert!(matches!(result, Err(ConfigRepoError::Storage(_))));
        assert!(
            repo.find(scope(TENANT_A), &key)
                .await
                .expect("find")
                .is_none()
        );
        assert_eq!(emitter.emitted(), 0);
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn config_uow_rejects_fact_not_authorized_by_publish_receipt() {
        let store = new_config_store();
        let emitter = CountingEmitter::default();
        let uow = InMemConfigUnitOfWork::new(store.clone(), emitter.clone());
        let repo = InMemConfigRepo::from_shared(store);
        let key = setting_key("app.wrong-fact");
        let tenant = tenant(TENANT_A);
        let wrong_envelope = OutboxEnvelopeParts::new(
            generated::event::identity_v1::session_created::CONTRACT,
            tenant,
            EnvelopeSubjectId::from_opaque("app.wrong-fact").expect("subject"),
            OutboxActor::scoped(
                vocab::PrincipalKind::Admin,
                OpaqueActorId::from_opaque("actor").expect("actor"),
                tenant,
                vocab::ScopedTenant::Tenant,
            ),
        );

        let result = uow
            .commit_publish(
                publish_receipt(),
                scope(TENANT_A),
                ConfigMutation::Put(config_entry("app.wrong-fact", TENANT_A)),
                entry("evt-config-wrong-fact"),
                wrong_envelope,
            )
            .await;

        assert!(matches!(result, Err(ConfigRepoError::Storage(_))));
        assert!(
            repo.find(scope(TENANT_A), &key)
                .await
                .expect("find")
                .is_none()
        );
        assert_eq!(emitter.emitted(), 0);
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn config_uow_rolls_back_mutation_when_emit_fails() {
        let store = new_config_store();
        let uow = InMemConfigUnitOfWork::new(store.clone(), FailingEmitter);
        let repo = InMemConfigRepo::from_shared(store);
        let key = setting_key("app.rollback");

        let result = uow
            .commit_publish(
                publish_receipt(),
                scope(TENANT_A),
                ConfigMutation::Put(config_entry("app.rollback", TENANT_A)),
                entry("evt-config-emit-failure"),
                envelope(TENANT_A),
            )
            .await;

        assert!(matches!(result, Err(ConfigRepoError::Storage(_))));
        assert!(
            repo.find(scope(TENANT_A), &key)
                .await
                .expect("find")
                .is_none()
        );
        assert!(
            repo.head(scope(TENANT_A), &key)
                .await
                .expect("head")
                .is_none()
        );
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn config_uow_shared_store_serializes_rollback_across_distinct_uows() {
        let store = new_config_store();
        let entered = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let failing = InMemConfigUnitOfWork::new(
            store.clone(),
            BlockingFailingEmitter {
                entered: Arc::clone(&entered),
                release: Arc::clone(&release),
            },
        );
        let succeeding = InMemConfigUnitOfWork::new(store.clone(), CountingEmitter::default());
        let key = setting_key("app.concurrent-rollback");

        let first = tokio::spawn(async move {
            failing
                .commit_publish(
                    publish_receipt(),
                    scope(TENANT_A),
                    ConfigMutation::Put(config_entry_version(
                        "app.concurrent-rollback",
                        TENANT_A,
                        1,
                    )),
                    entry("evt-config-delayed-failure"),
                    envelope(TENANT_A),
                )
                .await
        });
        entered.notified().await;
        let second = tokio::spawn(async move {
            succeeding
                .commit_publish(
                    publish_receipt(),
                    scope(TENANT_A),
                    ConfigMutation::Put(config_entry_version(
                        "app.concurrent-rollback",
                        TENANT_A,
                        2,
                    )),
                    entry("evt-config-concurrent-success"),
                    envelope(TENANT_A),
                )
                .await
        });
        tokio::task::yield_now().await;
        release.notify_one();

        assert!(matches!(
            first.await.expect("first task"),
            Err(ConfigRepoError::Storage(_))
        ));
        assert!(matches!(
            second.await.expect("second task"),
            Err(ConfigRepoError::VersionConflict)
        ));
        let repo = InMemConfigRepo::from_shared(store);
        assert!(
            repo.head(scope(TENANT_A), &key)
                .await
                .expect("head")
                .is_none()
        );
    }

    #[tokio::test]
    #[allow(clippy::expect_used)]
    async fn secret_internal_publish_rejects_entry_tenant_mismatch_without_write() {
        let store = new_secret_store();
        let repo = InMemSecretRepo::from_shared(store);
        let key = secret_key("app.secret");

        let result = repo
            .publish_internal(
                scope(TENANT_A),
                SecretInternalPublishCommand::from_entry(secret_entry("app.secret", TENANT_B)),
            )
            .await;

        assert!(matches!(result, Err(SecretRepoError::Storage(_))));
        assert!(
            repo.find(scope(TENANT_B), &key)
                .await
                .expect("find")
                .is_none()
        );
    }
}
