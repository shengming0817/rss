//! 域内 flag 仓储 port（非 DI-swappable provider，留域内——domain-patterns.md §internal 模块例外）。

use vocab::TenantId;

use crate::domain::{FlagKey, FlagState};

/// flag 状态仓储 port（域内；sync——in-mem 快照读，无 I/O）。
///
/// 与可替换-provider 的**配置**仓储不同：flag 快照本 PR 仅 in-mem（生产订阅缓存消费者维护快照留 #1120），
/// 非跨 adapter 可替换 provider，故留域内 `internal/ports`（非域形 DI port）。
pub(crate) trait FlagStore: Send + Sync {
    /// 按租户 + key 取 flag 状态快照；不存在返回 `None`（求值侧 fail-closed 视为禁用）。
    fn find(&self, tenant: TenantId, key: &FlagKey) -> Option<FlagState>;
}
