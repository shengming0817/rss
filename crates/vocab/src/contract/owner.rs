//! 契约归属 `ContractOwner`（sealed：私有内层 enum，构造经受控关联函数 `framework()` / `of_domain()`）。
//! owner→域解析只经 [`ContractOwner::domain`]；Framework 归属返回 None（类型层收口，无运行期 guard）。
//!
//! INVARIANT: CONTRACT-OWNER-SEAL-01 —— 外部 crate 无法命名私有内层 [`Owner`] enum，故无法 raw-mint 任意
//! owner；构造只经 [`ContractOwner::framework`] / [`ContractOwner::of_domain`] 受控入口（type-layer Hard
//! seal，对齐 house `vocab::tenant::CrossTenantCapability` 私有构造封闭先例——该先例用私有字段 `_seal: ()`，
//! 本 PR 用私有内层 enum，二者同属类型层 Hard seal）。

/// 契约归属。`Framework` 是 provider-agnostic 中立契约的保留 sentinel，不绑定单一域。
///
/// 构造经 [`ContractOwner::framework`] / [`ContractOwner::of_domain`] 受控入口；内层 [`Owner`] 变体私有，
/// 外部 crate 无法 raw-mint 任意 owner（INVARIANT: CONTRACT-OWNER-SEAL-01）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContractOwner(Owner);

/// `ContractOwner` 私有内层（不 `pub`、不 re-export）——封闭构造面：外部无法命名 ⇒ 无法 mint。
// ADR-004 C8 签名冻结：构造/accessor 体为 todo!()，变体未在 crate 内构造，落地前 dead_code 预期（carve-out item-level）。
// reason: ADR-004 C8 签名冻结——私有内层变体待行为 PR 构造
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
enum Owner {
    Domain(DomainName),
    Framework,
}

impl ContractOwner {
    /// Framework 归属 sentinel（provider-agnostic 中立契约，不绑定单一域）。
    pub fn framework() -> Self {
        todo!()
    }

    /// 域归属（`name` 经 [`DomainName`] fallible funnel 校验后传入）。
    ///
    /// 注：本入口只保证 `name` 格式合法（newtype funnel），**不**校验「该域有真实契约背书」——provenance
    /// （owner 须源于已注册契约）在 vocab 基础层跨 crate 不可 Hard 强制，残留说明见 `contract-fanout.md`
    /// §契约归属 + tracking issue #1091。
    pub fn of_domain(_name: DomainName) -> Self {
        todo!()
    }

    /// 解析归属域 crate；`Framework` 归属返回 `None`。
    pub fn domain(&self) -> Option<&DomainName> {
        todo!()
    }
}

/// `DomainName` 解析错误。空值 / 非法字符（非 crate-name 形）非法（校验在行为 PR 兑现）。
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DomainNameError {
    #[error("domain name is empty")]
    Empty,
    #[error("domain name has invalid format")]
    Format,
}

/// 域名 newtype（私有字段，构造经 fallible funnel）。
///
/// 域名是契约归属路径段（crate-name 形）——冻结为可失败构造，拒绝空值 / 非法字符。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainName(String);

impl DomainName {
    /// 解析域名；拒绝空值 / 非法格式（校验在行为 PR 兑现）。
    pub fn parse(_raw: &str) -> Result<Self, DomainNameError> {
        todo!()
    }

    pub fn as_str(&self) -> &str {
        todo!()
    }
}

#[cfg(test)]
mod smoke {
    //! build smoke：证明 `ContractOwner` 受控构造面（`framework` / `of_domain`）+ `domain` accessor 签名可
    //! 引用（绑定函数指针、不调用 → 不触 `todo!()`）。seal 的负向证明（外部无法 mint）由类型系统编译期
    //! 成立——私有内层 [`Owner`] enum 在 crate 外不可命名 ⇒ 无法构造，故无需 trybuild 负向用例（私有内层
    //! enum 模式不同于 sealed-trait，无外部 impl 面需 `compile_fail` 守）。
    use super::{ContractOwner, DomainName, DomainNameError};

    // INVARIANT: CONTRACT-OWNER-SEAL-01
    #[test]
    fn contract_owner_seal_signatures_are_consumable() {
        // 受控构造入口签名可绑定（不调用 → 不触 todo!()）：raw 变体在外部不可表达，仅此二函数可 mint。
        let _framework: fn() -> ContractOwner = ContractOwner::framework;
        let _of_domain: fn(DomainName) -> ContractOwner = ContractOwner::of_domain;

        // owner→域解析 accessor 签名可绑定；Framework 归属返回 None（类型层收口）。
        let _domain: fn(&ContractOwner) -> Option<&DomainName> = ContractOwner::domain;

        // DomainName fallible funnel 签名可绑定（owner 的 Domain 段唯一构造来源）。
        let _parse: fn(&str) -> Result<DomainName, DomainNameError> = DomainName::parse;
        let _as_str: fn(&DomainName) -> &str = DomainName::as_str;
    }
}
