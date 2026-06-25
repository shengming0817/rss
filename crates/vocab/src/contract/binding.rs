//! 契约绑定 `ContractBinding`——把一份 `contract.toml` 的 `domain` + `id` 两字段**同源**绑成一个
//! 类型化常量，供 outbox envelope / 事件 producer 以「契约归属」而非裸 string 传入。
//!
//! 设计要点：domain 与 contract_id **不**互相派生（`id` 首段 ≠ `domain`——`_seed` 反例：domain `_seed`、
//! id `seed.thing-happened`；且 contract `id` 容连字符 [`is_dotted_id`]、`domain` 是 crate-name 形
//! [`is_safe_segment`]，二者字母表不同）。两字段各自来自 manifest 的对应字段，由 `cargo xtask codegen` 派生为
//! `pub const CONTRACT: ContractBinding`、golden 字节锁。domain 与 contract_id 收进**单一绑定值**——故二者
//! 之间无法漂移（只有一个 `ContractBinding`，不存在两个独立可分别 author 的裸字段）。
//!
//! INVARIANT: CONTRACT-BINDING-FUNNEL-01（**Medium**）—— generated 的 `CONTRACT` 常量 domain/contract_id
//! 同源单一 manifest + golden 字节锁（`cargo xtask codegen --check`）：保证**派生常量**正确、不漂移。上游
//! `xtask/contract/validate.rs` R7（`is_safe_segment` domain / `is_dotted_id` id 语法）+ R3（磁盘段 domain =
//! manifest domain）背书 `from_static` 不在运行期重校验。
//!
//! **不是 Hard seal（residual，#1327 / 同 `ContractOwner::of_domain` #1091）**：[`ContractBinding::from_static`]
//! 是普通 `pub` 构造器，任意依赖 `vocab` 的 crate 可裸构造任意 `(domain, contract_id)`——跨 crate sealing 在
//! vocab 基础层不可 Hard 强制。「业务只用 generated `CONTRACT`、不伪造」当前靠**约定 + golden**（业务伪造面无
//! 机器守卫），统一 enforcement 见 #1327。下游强度：generated 常量正确性 = golden（Medium）；业务伪造拒绝 = 未守（residual）。

/// 契约绑定（domain + contract_id 同源常量）。字段私有——只读 accessor 暴露；两字段收进单一值，彼此不可漂移。
///
/// 预期生产 mint 经 [`ContractBinding::from_static`]（`cargo xtask codegen` 从 `contract.toml` 派生为
/// `CONTRACT` 常量 + golden 锁）；但 `from_static` 是普通 `pub` 构造器、非 Hard seal（业务伪造面 residual，
/// 同 `ContractOwner::of_domain`，#1327 / #1091）。INVARIANT: CONTRACT-BINDING-FUNNEL-01（Medium，见 mod doc）。
///
/// 仅持 `&'static str`（绑定值来自 codegen 字面量 / 测试字面量，无运行期 mint）⇒ `Copy` + 全 `const fn`
/// accessor：消费方可在 const 上下文复用（如域 crate `const DOMAIN = CONTRACT.domain();` 单源 tracing 标签）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContractBinding {
    /// 发布域（= `contract.toml` `domain` 字段，crate-name 形）。
    domain: &'static str,
    /// 契约 ID（= `contract.toml` `id` 字段，点分小写名，可含连字符）。
    contract_id: &'static str,
}

impl ContractBinding {
    /// 由 `&'static str`（codegen 字面量）构造——const-evaluable，**不**运行期校验。
    ///
    /// 唯一生产 mint 面：`generated::event::{domain}_v1::CONTRACT`（codegen 从 manifest `domain` + `id`
    /// 同源派生 + golden 锁）。格式合法性由上游 `xtask/contract/validate.rs`（R7 语法 + R3 路径↔字段一致）
    /// 静态背书，故此处不重校验（避免无生产调用方的 runtime 校验码）。测试用字面量直构。
    #[must_use]
    pub const fn from_static(domain: &'static str, contract_id: &'static str) -> Self {
        Self {
            domain,
            contract_id,
        }
    }

    /// 借出发布域（outbox 行 `domain` 路由列）。
    #[must_use]
    pub const fn domain(&self) -> &'static str {
        self.domain
    }

    /// 借出契约 ID（outbox 行 `contract_id` 路由列）。
    #[must_use]
    pub const fn contract_id(&self) -> &'static str {
        self.contract_id
    }
}

#[cfg(test)]
mod tests {
    use super::ContractBinding;

    #[test]
    fn from_static_exposes_both_fields_verbatim() {
        let b = ContractBinding::from_static("identity", "identity.session-created");
        assert_eq!(b.domain(), "identity");
        assert_eq!(b.contract_id(), "identity.session-created");
    }

    #[test]
    fn domain_and_contract_id_are_independent_not_derived() {
        // `_seed` 反例：domain (`_seed`) ≠ contract_id 首段 (`seed`)，且 id 含连字符 (`thing-happened`)。
        // 证明二字段独立保真——若实现从 id 前缀派生 domain，本断言会破。
        let b = ContractBinding::from_static("_seed", "seed.thing-happened");
        assert_eq!(b.domain(), "_seed", "domain 必须按字面保真，不可从 id 派生");
        assert_eq!(b.contract_id(), "seed.thing-happened");
        assert_ne!(
            b.domain(),
            b.contract_id().split('.').next().unwrap_or_default(),
            "前提：本反例的 domain 与 id 首段确实不同（否则该测试无意义）"
        );
    }

    #[test]
    fn settings_binding_round_trips() {
        let b = ContractBinding::from_static("settings", "settings.config-version-changed");
        assert_eq!(b.domain(), "settings");
        assert_eq!(b.contract_id(), "settings.config-version-changed");
    }

    #[test]
    fn copy_and_eq_hold() {
        let a = ContractBinding::from_static("identity", "identity.session-created");
        let b = a; // Copy（两 &'static str）——同值相等。
        assert_eq!(a, b);
        let c = ContractBinding::from_static("identity", "identity.other");
        assert_ne!(a, c);
    }

    #[test]
    fn from_static_is_const_usable() {
        // const 上下文可用（codegen 以 `pub const CONTRACT: ContractBinding = …from_static(..)` 发射）。
        const C: ContractBinding =
            ContractBinding::from_static("identity", "identity.session-created");
        assert_eq!(C.domain(), "identity");
    }
}
