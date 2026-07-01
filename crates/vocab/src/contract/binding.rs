//! 契约绑定 `ContractBinding`——把一份 `contract.toml` 的 `domain` + `id` + `version` + `schema_hash`
//! 四字段**同源**绑成一个类型化常量，供 outbox envelope / 事件 producer 以「契约归属 + schema 指纹」
//! 而非裸 string 传入。
//!
//! 设计要点：domain 与 contract_id **不**互相派生（`id` 首段 ≠ `domain`——`_seed` 反例：domain `_seed`、
//! id `seed.thing-happened`；且 contract `id` 容连字符 [`is_dotted_id`]、`domain` 是 crate-name 形
//! [`is_safe_segment`]，二者字母表不同）。两字段各自来自 manifest 的对应字段，由 `cargo xtask codegen` 派生为
//! `pub const CONTRACT: ContractBinding`、golden 字节锁。domain、contract_id、version 与 schema_hash
//! 收进**单一绑定值**——故 envelope header 不需要在调用点分别 author 这些裸字段。
//!
//! INVARIANT: CONTRACT-BINDING-FUNNEL-01 { level = "Medium", exec = "manual/opt-in", source = "code" }（**Medium**）—— generated 的 `CONTRACT` 常量
//! 同源单一 manifest + golden 字节锁（`cargo xtask codegen --check`）：保证**派生常量**正确、不漂移。上游
//! `xtask/contract/validate.rs` R7（`is_safe_segment` domain / `is_dotted_id` id / `v{N}` version 语法）+
//! R3（磁盘段 domain/version = manifest domain/version）背书 `from_static` 不在运行期重校验。
//!
//! **不是 Hard seal（residual，同 `ContractOwner::of_domain` #1091）**：[`ContractBinding::from_static`]
//! 是普通 `pub` 构造器，任意依赖 `vocab` 的 crate 可裸构造任意字段——跨 crate sealing 在 vocab
//! 基础层不可 Hard 强制。「业务只用 generated `CONTRACT`、不伪造」由 source guard 收口到 generated /
//! 测试 fixture（`cargo xtask verify` 的 `contract-binding-guard`，Medium）；下游强度：generated 常量正确性 =
//! golden（Medium）。

/// 契约绑定（domain + contract_id + version + schema_hash 同源常量）。
/// 字段私有——只读 accessor 暴露；四字段收进单一值，彼此不可漂移。
///
/// 预期生产 mint 经 [`ContractBinding::from_static`]（`cargo xtask codegen` 从 `contract.toml` 派生为
/// `CONTRACT` 常量 + golden 锁）；但 `from_static` 是普通 `pub` 构造器、非 Hard seal（业务伪造面靠
/// source guard 收口）。INVARIANT: CONTRACT-BINDING-FUNNEL-01 { level = "Medium", exec = "manual/opt-in", source = "code" }（Medium，见 mod doc）。
///
/// 仅持 `&'static str`（绑定值来自 codegen 字面量 / 测试字面量，无运行期 mint）⇒ `Copy` + 全 `const fn`
/// accessor：消费方可在 const 上下文复用（如域 crate `const DOMAIN = CONTRACT.domain();` 单源 tracing 标签）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContractBinding {
    /// 发布域（= `contract.toml` `domain` 字段，crate-name 形）。
    domain: &'static str,
    /// 契约 ID（= `contract.toml` `id` 字段，点分小写名，可含连字符）。
    contract_id: &'static str,
    /// 契约版本（= `contract.toml` `version` 字段，`v{N}`）。
    version: &'static str,
    /// 声明 schema bundle 的稳定摘要（`sha256:<64 lowercase hex>`）。
    schema_hash: &'static str,
}

impl ContractBinding {
    /// 由 `&'static str`（codegen 字面量）构造——const-evaluable，**不**运行期校验。
    ///
    /// 唯一生产 mint 面：`generated::{kind}::{domain}_v1::CONTRACT`（codegen 从 manifest + schema
    /// 同源派生 + golden 锁）。格式合法性由上游 `xtask/contract/validate.rs`（R7 语法 + R3 路径↔字段一致）
    /// 静态背书，故此处不重校验（避免无生产调用方的 runtime 校验码）。测试用字面量直构。
    #[must_use]
    pub const fn from_static(
        domain: &'static str,
        contract_id: &'static str,
        version: &'static str,
        schema_hash: &'static str,
    ) -> Self {
        Self {
            domain,
            contract_id,
            version,
            schema_hash,
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

    /// 借出契约版本（`v{N}`）。
    #[must_use]
    pub const fn version(&self) -> &'static str {
        self.version
    }

    /// 借出 schema bundle 摘要（`sha256:<64 lowercase hex>`）。
    #[must_use]
    pub const fn schema_hash(&self) -> &'static str {
        self.schema_hash
    }
}

#[cfg(test)]
mod tests {
    use super::ContractBinding;

    const HASH: &str = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn from_static_exposes_fields_verbatim() {
        let b = ContractBinding::from_static("identity", "identity.session-created", "v1", HASH);
        assert_eq!(b.domain(), "identity");
        assert_eq!(b.contract_id(), "identity.session-created");
        assert_eq!(b.version(), "v1");
        assert_eq!(b.schema_hash(), HASH);
    }

    #[test]
    fn domain_and_contract_id_are_independent_not_derived() {
        // `_seed` 反例：domain (`_seed`) ≠ contract_id 首段 (`seed`)，且 id 含连字符 (`thing-happened`)。
        // 证明二字段独立保真——若实现从 id 前缀派生 domain，本断言会破。
        let b = ContractBinding::from_static("_seed", "seed.thing-happened", "v1", HASH);
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
        let b =
            ContractBinding::from_static("settings", "settings.config-version-changed", "v2", HASH);
        assert_eq!(b.domain(), "settings");
        assert_eq!(b.contract_id(), "settings.config-version-changed");
        assert_eq!(b.version(), "v2");
    }

    #[test]
    fn copy_and_eq_hold() {
        let a = ContractBinding::from_static("identity", "identity.session-created", "v1", HASH);
        let b = a; // Copy（四个 &'static str）——同值相等。
        assert_eq!(a, b);
        let c = ContractBinding::from_static("identity", "identity.other", "v1", HASH);
        assert_ne!(a, c);
    }

    #[test]
    fn from_static_is_const_usable() {
        // const 上下文可用（codegen 以 `pub const CONTRACT: ContractBinding = …from_static(..)` 发射）。
        const C: ContractBinding =
            ContractBinding::from_static("identity", "identity.session-created", "v1", HASH);
        assert_eq!(C.domain(), "identity");
    }
}
