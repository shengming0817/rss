//! settings 配置 / flag / secret 仓储 in-memory 实现（RW-W 种子数据 + Join 追踪弹）。生产持久化（postgres adapter
//! impl [`crate::ports::ConfigRepo`] / [`crate::ports::ConfigUnitOfWork`] / [`crate::ports::SecretRepo`]）
//! 见 #1249 / #1274。
//!
//! 锁中毒（仅持锁线程 panic 时发生）恢复 guard 而非 panic：in-mem 替身不在持锁时 panic，且 lib 禁
//! `unwrap`/`expect`（clippy deny）。`unwrap_or_else(into_inner)` 取回 guard，clippy-clean（对标 memory adapter）。
//!
//! 读端口 [`InMemConfigRepo`] 与写 UoW [`InMemConfigUnitOfWork`] 经 `Arc` **共享同一 store**（`with_seed`
//! clone 注入）——保证 `find` 读得到 `save_and_append_outbox` 写入（与 postgres 同 pool 数据一致性对齐）。
//!
//! [`InMemSecretRepo`] 为独立 store（L1 本地事务，无 outbox，`Arc<Mutex<...>>` 共享）。

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use consistency::Entry;
use diport::{OutboxEmitter, OutboxEnvelopeParts};
use vocab::TenantId;

use super::ports::FlagStore;
use crate::domain::{ConfigEntry, ConfigRepoError, FlagKey, FlagState, SettingKey};
#[cfg(any(test, feature = "seed-data"))]
use crate::domain::{SecretEntry, SecretKey, SecretRepoError};
#[cfg(any(test, feature = "seed-data"))]
use crate::ports::SecretRepo;
use crate::ports::{ConfigRepo, ConfigUnitOfWork};

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

/// in-mem 版本化配置 store：每 key 一条 append-only 版本历史（`Vec` index `i` ⇒ 版本号 `i + 1`，含 tombstone）。
/// `Arc` 共享供读端口与写 UoW 同源（见模块头）。
type ConfigStore = Arc<Mutex<HashMap<StoreKey, Vec<ConfigRow>>>>;

/// 新建空共享 store（`with_seed` 经此建一份、clone 进读端口与写 UoW）。
pub(crate) fn new_config_store() -> ConfigStore {
    Arc::new(Mutex::new(HashMap::new()))
}

/// CAS 追加新版本到共享 store：新版本号须恰为当前最高版本 + 1（首版 = 1），否则乐观并发写冲突。
/// `len()` 含 tombstone ⇒ delete 后 version 单调不重置（与 postgres CAS `max(version)+1` 同语义，F1）。
fn cas_insert(
    store: &ConfigStore,
    tenant: TenantId,
    entry: ConfigEntry,
) -> Result<(), ConfigRepoError> {
    let mut entries = store.lock().unwrap_or_else(|e| e.into_inner());
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

/// in-memory 版本化配置仓储（读 + plain save + delete）。共享 [`ConfigStore`]。
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
        tenant: TenantId,
        key: &SettingKey,
    ) -> Result<Option<ConfigEntry>, ConfigRepoError> {
        let entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        // 活跃值 = latest 行且非 tombstone（latest 为 tombstone ⇒ 已删 None）。
        Ok(entries
            .get(&(tenant, key.as_str().to_string()))
            .and_then(|history| history.last())
            .filter(|row| !row.deleted)
            .map(|row| row.entry.clone()))
    }

    async fn find_version(
        &self,
        tenant: TenantId,
        key: &SettingKey,
        version: u64,
    ) -> Result<Option<ConfigEntry>, ConfigRepoError> {
        let entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        Ok(entries
            .get(&(tenant, key.as_str().to_string()))
            .and_then(|history| history.iter().find(|row| row.entry.version() == version))
            .filter(|row| !row.deleted)
            .map(|row| row.entry.clone()))
    }

    async fn latest_version(
        &self,
        tenant: TenantId,
        key: &SettingKey,
    ) -> Result<Option<u64>, ConfigRepoError> {
        let entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        // 真实最高版本（含 tombstone）——业务层算下一版本用，delete 后不重置。
        Ok(entries
            .get(&(tenant, key.as_str().to_string()))
            .and_then(|history| history.last())
            .map(|row| row.entry.version()))
    }

    async fn save(&self, tenant: TenantId, entry: ConfigEntry) -> Result<(), ConfigRepoError> {
        cas_insert(&self.entries, tenant, entry)
    }

    async fn delete(&self, tenant: TenantId, key: &SettingKey) -> Result<(), ConfigRepoError> {
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        // 软删：仅当 key 存在且 latest 非 tombstone 时追加 tombstone（幂等；version 单调不重置，F1）。
        if let Some(history) = entries.get_mut(&(tenant, key.as_str().to_string()))
            && history.last().is_some_and(|row| !row.deleted)
        {
            // reason: len() 超 u64::MAX 实践不可能 → saturating MAX，fail-closed。
            let version = u64::try_from(history.len())
                .unwrap_or(u64::MAX)
                .saturating_add(1);
            let tombstone = ConfigEntry::hydrate(key.clone(), "", tenant, version);
            history.push(ConfigRow {
                entry: tombstone,
                deleted: true,
            });
        }
        Ok(())
    }
}

/// in-memory 配置写 **co-tx** UoW 替身（追踪弹 / demo）：CAS save（共享 store）+ emit。
///
/// 泛型于**具体** emitter `E`（非 `Box<DynOutboxEmitter>`）：`ConfigUnitOfWork` 是 `: Send` 端口，其
/// `&self` future 须 Send ⇒ 本类型须 `Sync`；而 `DynOutboxEmitter` dyn wrapper 仅 `Send` 非 `Sync`（持之则
/// 非 Sync）。`E` 取具体 `Sync` 类型（`memory::MemEmitter` / 测试 `CapturingEmitter`，均 `Arc` 底座）即满足。
///
/// **非原子**（in-mem 无事务）——save 后 emit；emit 失败包 [`ConfigRepoError::Storage`]。真实 both-or-neither
/// 原子性由 postgres `PgConfigUnitOfWork`（同事务）承载（#1249），journey 闭环只验「写入 → 事件投递」语义。
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

impl<E: OutboxEmitter + Send + Sync + 'static> ConfigUnitOfWork for InMemConfigUnitOfWork<E> {
    async fn save_and_append_outbox(
        &self,
        tenant: TenantId,
        entry: ConfigEntry,
        outbox_entry: Entry,
        envelope: OutboxEnvelopeParts,
    ) -> Result<(), ConfigRepoError> {
        cas_insert(&self.entries, tenant, entry)?;
        self.emitter
            .emit(outbox_entry, envelope)
            .await
            .map_err(|e| ConfigRepoError::Storage(Box::new(e)))
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
}

#[cfg(any(test, feature = "seed-data"))]
impl SecretRepo for InMemSecretRepo {
    async fn find(
        &self,
        tenant: TenantId,
        key: &SecretKey,
    ) -> Result<Option<SecretEntry>, SecretRepoError> {
        let entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        Ok(entries
            .get(&(tenant, key.as_str().to_string()))
            .and_then(|h| h.last())
            .filter(|row| !row.deleted)
            .map(|row| row.entry.clone()))
    }

    async fn find_version(
        &self,
        tenant: TenantId,
        key: &SecretKey,
        version: u64,
    ) -> Result<Option<SecretEntry>, SecretRepoError> {
        let entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        Ok(entries
            .get(&(tenant, key.as_str().to_string()))
            .and_then(|h| h.iter().find(|row| row.entry.version() == version))
            .filter(|row| !row.deleted)
            .map(|row| row.entry.clone()))
    }

    async fn latest_version(
        &self,
        tenant: TenantId,
        key: &SecretKey,
    ) -> Result<Option<u64>, SecretRepoError> {
        let entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        Ok(entries
            .get(&(tenant, key.as_str().to_string()))
            .and_then(|h| h.last())
            .map(|row| row.entry.version()))
    }

    async fn save(&self, tenant: TenantId, entry: SecretEntry) -> Result<(), SecretRepoError> {
        secret_cas_insert(&self.entries, tenant, entry)
    }

    async fn delete(&self, tenant: TenantId, key: &SecretKey) -> Result<(), SecretRepoError> {
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
