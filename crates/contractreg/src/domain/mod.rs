//! contractreg 域类型与纯逻辑。
//!
//! 所有类型 `pub(crate)`，字段私有，只经显式构造 funnel 创建——外部不可伪造（ADR-001）。
//! 域类型**严禁** derive `Serialize`/`Deserialize`（dylint 守护区，ADR-004 C6）。
//!
//! # 签名冻结（ADR-004 C8 豁免覆盖率）
//!
//! 函数体全为 `todo!()`；smoke test 只绑函数指针 / 构造 Copy enum，不触 body。
//!
//! ref: casbin/casbin-rs src/model/mod.rs@master（命名空间 (domain,kind,version) + lifecycle 状态机）。

pub(crate) use rss_contract::ContractId;

// ---------------------------------------------------------------------------
// ContractKind
// ---------------------------------------------------------------------------

/// 契约种类（闭值集，`#[non_exhaustive]`）。
// reason: 签名冻结期枚举尚无调用方，dead_code 来自冻结期（ADR-004 C8）。
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub(crate) enum ContractKind {
    /// HTTP 请求/响应契约。
    Http,
    /// 事件发布/订阅契约。
    Event,
    /// 命令下发契约。
    Command,
    /// Saga 编排契约（对标 saga.md `kind:saga`）。
    Saga,
}

// ---------------------------------------------------------------------------
// ContractStatus
// ---------------------------------------------------------------------------

/// 契约生命周期状态（闭值集，`#[non_exhaustive]`；fail-closed：未知 → `Draft`）。
///
/// 状态机合法迁移由 [`can_transition`] 守护。
// reason: fail-closed 注释——未知状态退化为 Draft，外部无法伪造已激活契约（ADR-001）；
//         签名冻结期枚举尚无调用方，dead_code 来自冻结期（ADR-004 C8）。
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub(crate) enum ContractStatus {
    /// 草稿，未经验证。
    Draft,
    /// 已激活，生产可用。
    Active,
    /// 已弃用，即将下线。
    Deprecated,
    /// 已退役，不可使用。
    Retired,
}

// ---------------------------------------------------------------------------
// ConsistencyLevel
// ---------------------------------------------------------------------------

/// 一致性等级（L0–L4；`Copy`；`#[non_exhaustive]`）。
///
/// 级别**声明**在 `contract.toml` 的 `consistencyLevel` 字段（单一事实源，决策 #1）；
/// 此枚举用于域内运行时表达，不替代 contract.toml 的治理作用。
// reason: 签名冻结期枚举尚无调用方，dead_code 来自冻结期（ADR-004 C8）。
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub(crate) enum ConsistencyLevel {
    /// L0 LocalOnly：排除业务持久化/outbox/publish，不排除 provider-owned read-path transaction。
    L0,
    /// L1 单域本地事务。
    L1,
    /// L2 本地事务 + outbox。
    L2,
    /// L3 跨域最终一致。
    L3,
    /// L4 设备长延迟闭环。
    L4,
}

// ---------------------------------------------------------------------------
// ContractRecord
// ---------------------------------------------------------------------------

/// 契约登记记录（私有字段；构造经 `new` funnel）。
// reason: 签名冻结期字段已声明但 accessor body 全为 todo!()（ADR-004 C8）。
#[allow(dead_code)]
pub(crate) struct ContractRecord {
    id: ContractId,
    owner: assembly_schema::ContractOwner,
    kind: ContractKind,
    status: ContractStatus,
    consistency_level: ConsistencyLevel,
}

// reason: 签名冻结期方法尚无调用方，dead_code 来自冻结期（ADR-004 C8）。
#[allow(dead_code)]
impl ContractRecord {
    /// 构造契约记录（位置参必填）。
    pub(crate) fn new(
        _id: ContractId,
        _owner: assembly_schema::ContractOwner,
        _kind: ContractKind,
        _status: ContractStatus,
        _consistency_level: ConsistencyLevel,
    ) -> Self {
        todo!()
    }

    /// 契约标识。
    pub(crate) fn id(&self) -> &ContractId {
        todo!()
    }

    /// 契约归属（owner→域解析经 `ContractOwner::domain()`）。
    pub(crate) fn owner(&self) -> &assembly_schema::ContractOwner {
        todo!()
    }

    /// 契约种类。
    pub(crate) fn kind(&self) -> ContractKind {
        todo!()
    }

    /// 生命周期状态。
    pub(crate) fn status(&self) -> ContractStatus {
        todo!()
    }

    /// 一致性等级。
    pub(crate) fn consistency_level(&self) -> ConsistencyLevel {
        todo!()
    }
}

impl std::fmt::Debug for ContractRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ContractRecord")
            .field("id", &self.id)
            .field("owner", &self.owner)
            .field("kind", &self.kind)
            .field("status", &self.status)
            .field("consistency_level", &self.consistency_level)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// 纯逻辑（签名冻结，body=todo!()）
// ---------------------------------------------------------------------------

/// 判断契约生命周期状态是否可合法迁移（`from` → `to`）。
///
/// 合法路径：Draft→Active，Active→Deprecated，Deprecated→Retired。
/// 逆向迁移和跨级跳转均非法（fail-closed）。
// reason: 签名冻结期函数尚无调用方，dead_code 来自冻结期（ADR-004 C8）。
#[allow(dead_code)]
pub(crate) fn can_transition(_from: ContractStatus, _to: ContractStatus) -> bool {
    todo!()
}

/// 校验契约元数据完整性。
///
/// 检查 id 格式、owner 有效性、kind/status/consistency_level 合法组合（fail-closed）。
/// Saga kind 合法 consistency_level 仅 L3（实现待行为 PR）。
// reason: 签名冻结期函数尚无调用方，dead_code 来自冻结期（ADR-004 C8）。
#[allow(dead_code)]
pub(crate) fn validate_metadata(_record: &ContractRecord) -> Result<(), ContractRegError> {
    todo!()
}

// ---------------------------------------------------------------------------
// 错误枚举
// ---------------------------------------------------------------------------

/// contractreg 域错误（库枚举；`thiserror`；message 为 `&'static str` const literal）。
// reason: 签名冻结期枚举尚无调用方，dead_code 来自冻结期（ADR-004 C8）。
#[allow(dead_code)]
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub(crate) enum ContractRegError {
    #[error("contract id has invalid format")]
    IdInvalid,
    #[error("contract status transition is not permitted")]
    IllegalTransition,
    #[error("contract metadata is invalid")]
    MetadataInvalid,
}
