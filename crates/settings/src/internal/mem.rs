//! settings 配置 / flag 仓储 in-memory 实现（RW-W 种子数据）。生产持久化（postgres adapter impl
//! [`crate::ports::ConfigRepo`]）留 Join。
//!
//! 锁中毒（仅持锁线程 panic 时发生）恢复 guard 而非 panic：in-mem 替身不在持锁时 panic，且 lib 禁
//! `unwrap`/`expect`（clippy deny）。`unwrap_or_else(into_inner)` 取回 guard，clippy-clean（对标 memory adapter）。

use std::collections::HashMap;
use std::sync::Mutex;

use vocab::TenantId;

use super::ports::FlagStore;
use crate::domain::{ConfigEntry, FlagKey, FlagState, SettingKey, SettingsError};
use crate::ports::ConfigRepo;

/// 复合存储键（租户隔离）：(tenant, key 字符串)。
type StoreKey = (TenantId, String);

/// in-memory 版本化配置仓储：每 key 一条版本历史（`Vec` index `i` ⇒ 版本号 `i + 1`）。
pub(crate) struct InMemConfigRepo {
    entries: Mutex<HashMap<StoreKey, Vec<ConfigEntry>>>,
}

impl InMemConfigRepo {
    /// 新建空仓储。
    pub(crate) fn new() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
        }
    }
}

impl ConfigRepo for InMemConfigRepo {
    async fn find(
        &self,
        tenant: TenantId,
        key: &SettingKey,
    ) -> Result<Option<ConfigEntry>, SettingsError> {
        let entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        Ok(entries
            .get(&(tenant, key.as_str().to_string()))
            .and_then(|history| history.last().cloned()))
    }

    async fn find_version(
        &self,
        tenant: TenantId,
        key: &SettingKey,
        version: u64,
    ) -> Result<Option<ConfigEntry>, SettingsError> {
        let entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        Ok(entries
            .get(&(tenant, key.as_str().to_string()))
            .and_then(|history| {
                history
                    .iter()
                    .find(|entry| entry.version().get() == version)
                    .cloned()
            }))
    }

    async fn save(&self, tenant: TenantId, entry: ConfigEntry) -> Result<(), SettingsError> {
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        let history = entries
            .entry((tenant, entry.key().as_str().to_string()))
            .or_default();
        // CAS：新版本号须恰为当前最高版本 + 1（首版 = 1），否则乐观并发写冲突。
        // reason: history.len() 超 u64::MAX（实践不可能）→ saturating 到 MAX 使 CAS 永不通过，fail-closed
        let expected = u64::try_from(history.len())
            .unwrap_or(u64::MAX)
            .saturating_add(1);
        if entry.version().get() != expected {
            return Err(SettingsError::VersionConflict);
        }
        history.push(entry);
        Ok(())
    }

    async fn delete(&self, tenant: TenantId, key: &SettingKey) -> Result<(), SettingsError> {
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        entries.remove(&(tenant, key.as_str().to_string()));
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
