//! settings 配置 / flag 仓储 in-memory 实现（RW-W 种子数据 + Join 追踪弹）。生产持久化（postgres adapter
//! impl [`crate::ports::ConfigRepo`] / [`crate::ports::ConfigUnitOfWork`]）见 #1249。
//!
//! 锁中毒（仅持锁线程 panic 时发生）恢复 guard 而非 panic：in-mem 替身不在持锁时 panic，且 lib 禁
//! `unwrap`/`expect`（clippy deny）。`unwrap_or_else(into_inner)` 取回 guard，clippy-clean（对标 memory adapter）。
//!
//! 读端口 [`InMemConfigRepo`] 与写 UoW [`InMemConfigUnitOfWork`] 经 `Arc` **共享同一 store**（`with_seed`
//! clone 注入）——保证 `find` 读得到 `save_and_append_outbox` 写入（与 postgres 同 pool 数据一致性对齐）。

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use consistency::Entry;
use diport::{OutboxEmitter, OutboxEnvelopeParts};
use vocab::TenantId;

use super::ports::FlagStore;
use crate::domain::{ConfigEntry, ConfigRepoError, FlagKey, FlagState, SettingKey};
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
