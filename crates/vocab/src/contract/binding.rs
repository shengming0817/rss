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

/// Generated identity of one event fact, binding its contract columns and broker topic atomically.
///
/// Code generation is the production mint surface. Active producer authorization and typed event
/// encoding carry this value as one unit, so an entry topic cannot drift from its contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EventFactBinding {
    contract: ContractBinding,
    topic: &'static str,
}

impl EventFactBinding {
    /// Construct a generated event fact binding from manifest-derived constants.
    #[must_use]
    pub const fn from_static(contract: ContractBinding, topic: &'static str) -> Self {
        Self { contract, topic }
    }

    /// Generated contract identity for the fact.
    #[must_use]
    pub const fn contract(&self) -> ContractBinding {
        self.contract
    }

    /// Generated broker topic for the same fact.
    #[must_use]
    pub const fn topic(&self) -> &'static str {
        self.topic
    }
}

/// Payload type generated from one event contract.
///
/// Implementations are emitted next to the generated DTO. Producer code selects authorization by
/// payload type instead of passing a freely chosen contract or topic.
pub trait GeneratedEventPayload {
    /// Contract and topic that own this generated payload type.
    const FACT: EventFactBinding;
}

/// Projection workflow input binding generated from `[capabilities.workflow].inputs`.
///
/// The projection id and input event contract are emitted by `cargo xtask codegen` from the
/// contract manifests. Runtime projection writers consume only this static binding surface; they
/// do not accept handwritten `(contract_id, topic)` registry rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProjectionInputBinding {
    projection_id: &'static str,
    contract: ContractBinding,
    topic: &'static str,
}

impl ProjectionInputBinding {
    /// Construct a generated projection input binding from static manifest literals.
    #[must_use]
    pub const fn from_static(
        projection_id: &'static str,
        domain: &'static str,
        contract_id: &'static str,
        version: &'static str,
        schema_hash: &'static str,
        topic: &'static str,
    ) -> Self {
        Self {
            projection_id,
            contract: ContractBinding::from_static(domain, contract_id, version, schema_hash),
            topic,
        }
    }

    /// Projection workflow contract id.
    #[must_use]
    pub const fn projection_id(&self) -> &'static str {
        self.projection_id
    }

    /// Input event contract binding.
    #[must_use]
    pub const fn contract(&self) -> ContractBinding {
        self.contract
    }

    /// Input event topic.
    #[must_use]
    pub const fn topic(&self) -> &'static str {
        self.topic
    }

    /// Input event contract id.
    #[must_use]
    pub const fn contract_id(&self) -> &'static str {
        self.contract.contract_id()
    }

    /// Input event domain.
    #[must_use]
    pub const fn domain(&self) -> &'static str {
        self.contract.domain()
    }

    /// Input event schema version.
    #[must_use]
    pub const fn version(&self) -> &'static str {
        self.contract.version()
    }

    /// Input event schema hash.
    #[must_use]
    pub const fn schema_hash(&self) -> &'static str {
        self.contract.schema_hash()
    }
}

/// Saga runtime policy spec generated from `[saga].retryMillis` / `[saga].timeoutMillis`.
///
/// This is the contract-facing representation only: raw millisecond values stay in `vocab` so
/// generated contract glue can expose them without depending on runtime crates. Runtime validation
/// and interpretation live at the `eventexec::saga::SagaPolicy` conversion boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SagaRuntimePolicySpec {
    retry_millis: u64,
    timeout_millis: u64,
}

impl SagaRuntimePolicySpec {
    /// Construct a generated saga runtime policy spec from static manifest literals.
    #[must_use]
    pub const fn from_millis(retry_millis: u64, timeout_millis: u64) -> Self {
        Self {
            retry_millis,
            timeout_millis,
        }
    }

    /// Fixed retry delay in milliseconds. `0` means retry is disabled.
    #[must_use]
    pub const fn retry_millis(&self) -> u64 {
        self.retry_millis
    }

    /// Total timeout budget for one saga step phase in milliseconds. `0` means timeout is disabled.
    #[must_use]
    pub const fn timeout_millis(&self) -> u64 {
        self.timeout_millis
    }
}

/// Static saga step binding generated from `[saga].steps`.
///
/// The parent saga contract and the step fields are carried as one atom so typed runtime
/// registration cannot bind a same-shaped step from a different saga contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SagaStepBinding {
    contract: ContractBinding,
    name: &'static str,
    output_schema: &'static str,
}

impl SagaStepBinding {
    /// Construct a generated saga step binding from static manifest literals.
    #[must_use]
    pub const fn from_static(
        contract: ContractBinding,
        name: &'static str,
        output_schema: &'static str,
    ) -> Self {
        Self {
            contract,
            name,
            output_schema,
        }
    }

    /// Parent saga contract binding.
    #[must_use]
    pub const fn contract(&self) -> ContractBinding {
        self.contract
    }

    /// Parent saga domain.
    #[must_use]
    pub const fn domain(&self) -> &'static str {
        self.contract.domain()
    }

    /// Parent saga contract id.
    #[must_use]
    pub const fn contract_id(&self) -> &'static str {
        self.contract.contract_id()
    }

    /// Parent saga contract version.
    #[must_use]
    pub const fn version(&self) -> &'static str {
        self.contract.version()
    }

    /// Parent saga schema bundle hash.
    #[must_use]
    pub const fn schema_hash(&self) -> &'static str {
        self.contract.schema_hash()
    }

    /// Stable saga step name from `contract.toml`.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        self.name
    }

    /// Step output schema file from `contract.toml`.
    #[must_use]
    pub const fn output_schema(&self) -> &'static str {
        self.output_schema
    }
}

/// Marker generated for the DTO that corresponds to one saga step output schema.
///
/// Production implementations are emitted by contract codegen next to the DTO. Runtime registration
/// compares this binding against the step's generated binding, so a typed step cannot silently
/// return another step's output DTO.
pub trait SagaStepOutputBinding {
    /// Generated saga step binding for this output DTO.
    const BINDING: SagaStepBinding;
}

/// Saga contract binding generated from a saga `contract.toml`.
///
/// `contract`, `policy`, and ordered `steps` are carried as one atom so runtime composition does
/// not hand-author contract id, runtime policy, or action order independently from the generated
/// saga contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SagaContractBinding {
    contract: ContractBinding,
    policy: SagaRuntimePolicySpec,
    steps: &'static [SagaStepBinding],
}

impl SagaContractBinding {
    /// Construct a generated saga binding from static manifest-derived parts.
    #[must_use]
    pub const fn from_parts(
        contract: ContractBinding,
        policy: SagaRuntimePolicySpec,
        steps: &'static [SagaStepBinding],
    ) -> Self {
        Self {
            contract,
            policy,
            steps,
        }
    }

    /// Contract metadata binding.
    #[must_use]
    pub const fn contract(&self) -> ContractBinding {
        self.contract
    }

    /// Runtime policy spec.
    #[must_use]
    pub const fn policy(&self) -> SagaRuntimePolicySpec {
        self.policy
    }

    /// Ordered saga step bindings generated from `[saga].steps`.
    #[must_use]
    pub const fn steps(&self) -> &'static [SagaStepBinding] {
        self.steps
    }

    /// Saga contract id.
    #[must_use]
    pub const fn contract_id(&self) -> &'static str {
        self.contract.contract_id()
    }

    /// Saga domain.
    #[must_use]
    pub const fn domain(&self) -> &'static str {
        self.contract.domain()
    }

    /// Saga contract version.
    #[must_use]
    pub const fn version(&self) -> &'static str {
        self.contract.version()
    }

    /// Saga schema bundle hash.
    #[must_use]
    pub const fn schema_hash(&self) -> &'static str {
        self.contract.schema_hash()
    }
}

#[cfg(test)]
mod tests {
    use super::{ContractBinding, SagaContractBinding, SagaRuntimePolicySpec, SagaStepBinding};

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

    #[test]
    fn saga_runtime_policy_spec_exposes_millis_verbatim() {
        let disabled = SagaRuntimePolicySpec::from_millis(0, 0);
        assert_eq!(disabled.retry_millis(), 0);
        assert_eq!(disabled.timeout_millis(), 0);

        const BOUNDED: SagaRuntimePolicySpec = SagaRuntimePolicySpec::from_millis(5000, 30000);
        assert_eq!(BOUNDED.retry_millis(), 5000);
        assert_eq!(BOUNDED.timeout_millis(), 30000);
    }

    #[test]
    fn saga_contract_binding_keeps_contract_and_policy_atomic() {
        const CONTRACT: ContractBinding =
            ContractBinding::from_static("billing", "billing.checkout", "v1", HASH);
        const POLICY: SagaRuntimePolicySpec = SagaRuntimePolicySpec::from_millis(5000, 30000);
        const STEPS: &[SagaStepBinding] = &[
            SagaStepBinding::from_static(CONTRACT, "reserve_funds", "reserve.schema.json"),
            SagaStepBinding::from_static(CONTRACT, "capture", "capture.schema.json"),
        ];
        const BINDING: SagaContractBinding =
            SagaContractBinding::from_parts(CONTRACT, POLICY, STEPS);

        assert_eq!(BINDING.steps()[0].contract(), CONTRACT);
        assert_eq!(BINDING.steps()[0].contract_id(), "billing.checkout");
        assert_eq!(BINDING.domain(), "billing");
        assert_eq!(BINDING.contract_id(), "billing.checkout");
        assert_eq!(BINDING.version(), "v1");
        assert_eq!(BINDING.schema_hash(), HASH);
        assert_eq!(BINDING.contract(), CONTRACT);
        assert_eq!(BINDING.policy(), POLICY);
        assert_eq!(BINDING.steps(), STEPS);
        assert_eq!(BINDING.steps()[0].name(), "reserve_funds");
        assert_eq!(BINDING.steps()[0].output_schema(), "reserve.schema.json");
    }

    #[test]
    fn projection_input_binding_exposes_generated_contract_and_topic() {
        const B: super::ProjectionInputBinding = super::ProjectionInputBinding::from_static(
            "audit.session-projection",
            "identity",
            "identity.session-created",
            "v1",
            HASH,
            "identity.session.created",
        );
        assert_eq!(B.projection_id(), "audit.session-projection");
        assert_eq!(B.contract_id(), "identity.session-created");
        assert_eq!(B.domain(), "identity");
        assert_eq!(B.version(), "v1");
        assert_eq!(B.schema_hash(), HASH);
        assert_eq!(B.topic(), "identity.session.created");
    }
}
