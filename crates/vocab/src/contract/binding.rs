//! 契约绑定 `ContractBinding`——把一份 `contract.toml` 的 `domain` + `id` + `version` + `schema_hash`
//! 四字段**同源**绑成一个类型化常量，供 outbox envelope / 事件 producer 以「契约归属 + schema 指纹」
//! 而非裸 string 传入。
//!
//! 设计要点：domain 与 contract_id **不**互相派生（`id` 首段 ≠ `domain`——`_seed` 反例：domain `_seed`、
//! id `seed.thing-happened`；且 contract `id` 容连字符 [`is_dotted_id`]、`domain` 是 crate-name 形
//! [`is_safe_segment`]，二者字母表不同）。两字段各自来自 manifest 的对应字段，并固化为
//! `pub const CONTRACT: ContractBinding`、golden 字节锁。domain、contract_id、version 与 schema_hash
//! 收进**单一绑定值**——故 envelope header 不需要在调用点分别 author 这些裸字段。
//!
//! INVARIANT: CONTRACT-BINDING-FUNNEL-01 { level = "Medium", exec = "manual/opt-in", source = "code" }（**Medium**）—— static 的 `CONTRACT` 常量
//! 同源单一 manifest + owner crate 测试：保证**派生常量**正确、不漂移。字段语法由
//! `is_safe_segment` domain / `is_dotted_id` id / `v{N}` version 谓词定义，
//! R3（磁盘段 domain/version = manifest domain/version）背书 `from_static` 不在运行期重校验。
//!
//! **不是 Hard seal**：[`ContractBinding::from_static`]
//! 是普通 `pub` 构造器，任意依赖 `vocab` 的 crate 可裸构造任意字段——跨 crate sealing 在 vocab
//! 基础层不可 Hard 强制。「业务只用 static `CONTRACT`、不伪造」由 source guard 收口到 static /
//! 测试 fixture；下游强度：static 常量正确性 =
//! golden（Medium）。

/// 契约绑定（domain + contract_id + version + schema_hash 同源常量）。
/// 字段私有——只读 accessor 暴露；四字段收进单一值，彼此不可漂移。
///
/// 预期生产 mint 经 [`ContractBinding::from_static`]（从 `contract.toml` 派生为
/// `CONTRACT` 常量 + golden 锁）；但 `from_static` 是普通 `pub` 构造器、非 Hard seal（业务伪造面靠
/// source guard 收口）。INVARIANT: CONTRACT-BINDING-FUNNEL-01 { level = "Medium", exec = "manual/opt-in", source = "code" }（Medium，见 mod doc）。
///
/// 仅持 `&'static str`（绑定值来自 consumer tooling 字面量 / 测试字面量，无运行期 mint）⇒ `Copy` + 全 `const fn`
/// accessor：消费方可在 const 上下文复用（如域 crate `const DOMAIN = CONTRACT.domain();` 单源 tracing 标签）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContractBinding {
    /// 发布域（= `contract.toml` `domain` 字段，crate-name 形）。
    domain: &'static str,
    /// 契约 ID（= `contract.toml` `id` 字段，点分小写名，可含连字符）。
    descriptor: rss_contract::ContractDescriptor,
    version_label: &'static str,
}

impl ContractBinding {
    /// Compose internal domain semantics around one canonical Foundation descriptor.
    #[must_use]
    pub const fn from_descriptor(
        domain: &'static str,
        descriptor: rss_contract::ContractDescriptor,
        version_label: &'static str,
    ) -> Self {
        assert!(descriptor.version().major() == parse_static_version(version_label));
        Self {
            domain,
            descriptor,
            version_label,
        }
    }

    /// 由 `&'static str` 字面量构造——const-evaluable，**不**运行期校验。
    ///
    /// 静态构造面由仓外 consumer 从其契约清单生成或手写；RSS 不持有业务 consumer tooling。
    /// 格式合法性由 consumer 负责；此处不重复运行期校验。
    #[must_use]
    pub const fn from_static(
        domain: &'static str,
        contract_id: &'static str,
        version: &'static str,
        schema_hash: &'static str,
    ) -> Self {
        let version_major = parse_static_version(version);
        Self::from_descriptor(
            domain,
            rss_contract::ContractDescriptor::from_static(contract_id, version_major, schema_hash),
            version,
        )
    }

    /// 借出发布域（outbox 行 `domain` 路由列）。
    #[must_use]
    pub const fn domain(&self) -> &'static str {
        self.domain
    }

    /// 借出契约 ID（outbox 行 `contract_id` 路由列）。
    #[must_use]
    pub const fn contract_id(&self) -> &'static str {
        self.descriptor.id()
    }

    /// 借出契约版本（`v{N}`）。
    #[must_use]
    pub const fn version(&self) -> &'static str {
        self.version_label
    }

    /// 借出 schema bundle 摘要（`sha256:<64 lowercase hex>`）。
    #[must_use]
    pub const fn schema_hash(&self) -> &'static str {
        self.descriptor.schema_digest()
    }

    /// Canonical Foundation descriptor shared by code generation and runtime consumers.
    #[must_use]
    pub const fn descriptor(&self) -> &rss_contract::ContractDescriptor {
        &self.descriptor
    }
}

const fn parse_static_version(value: &str) -> u32 {
    let bytes = value.as_bytes();
    assert!(
        bytes.len() >= 2 && bytes[0] == b'v',
        "invalid contract version"
    );
    let mut index = 1;
    let mut major = 0_u32;
    while index < bytes.len() {
        let byte = bytes[index];
        assert!(byte.is_ascii_digit(), "invalid contract version");
        major = major * 10 + (byte - b'0') as u32;
        index += 1;
    }
    assert!(major != 0, "invalid contract version");
    major
}

/// Static identity of one event fact, binding its contract columns and broker topic atomically.
///
/// Code generation is the production mint surface. Active producer authorization and typed event
/// encoding carry this value as one unit, so an entry topic cannot drift from its contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EventFactBinding {
    contract: ContractBinding,
    topic: &'static str,
}

impl EventFactBinding {
    /// Construct a static event fact binding from manifest-derived constants.
    #[must_use]
    pub const fn from_static(contract: ContractBinding, topic: &'static str) -> Self {
        Self { contract, topic }
    }

    /// Static contract identity for the fact.
    #[must_use]
    pub const fn contract(&self) -> ContractBinding {
        self.contract
    }

    /// Static broker topic for the same fact.
    #[must_use]
    pub const fn topic(&self) -> &'static str {
        self.topic
    }
}

#[cfg(test)]
mod tests {
    use super::ContractBinding;

    const HASH: &str = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn from_static_exposes_fields_verbatim() {
        let b = ContractBinding::from_static("runtime", "runtime.fact-recorded", "v1", HASH);
        assert_eq!(b.domain(), "runtime");
        assert_eq!(b.contract_id(), "runtime.fact-recorded");
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
    fn platform_binding_round_trips() {
        let b = ContractBinding::from_static("platform", "platform.fact-updated", "v2", HASH);
        assert_eq!(b.domain(), "platform");
        assert_eq!(b.contract_id(), "platform.fact-updated");
        assert_eq!(b.version(), "v2");
    }

    #[test]
    fn copy_and_eq_hold() {
        let a = ContractBinding::from_static("runtime", "runtime.fact-recorded", "v1", HASH);
        let b = a; // Copy（四个 &'static str）——同值相等。
        assert_eq!(a, b);
        let c = ContractBinding::from_static("runtime", "runtime.other", "v1", HASH);
        assert_ne!(a, c);
    }

    #[test]
    fn from_static_is_const_usable() {
        // const 上下文可用（consumer tooling 以 `pub const CONTRACT: ContractBinding = …from_static(..)` 发射）。
        const C: ContractBinding =
            ContractBinding::from_static("runtime", "runtime.fact-recorded", "v1", HASH);
        assert_eq!(C.domain(), "runtime");
    }
}
