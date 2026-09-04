//! 契约元数据声明（`contract.toml`）的共享冻结类型。
//!
//! INVARIANT: CONTRACT-FREEZE-01 { level = "Hard", exec = "native-compile", source = "code", native = "deny_unknown_fields plus required typed enum fields" }— `ContractManifest` 字段集 + 枚举即 `contract.toml` 格式的
//! 单一事实源（Hard，类型层）：`#[serde(deny_unknown_fields)]` + 非 `Option` 枚举字段使「坏格式」
//! 解析即 `Err`，错误不可表达。新增/删字段须同步 `contracts/README.md` 与种子 golden。
//! Hard 类型层部分（字段冻结、枚举解析拒绝）在本文件；运行期跨字段不变式见 `validate.rs`（CONTRACT-FREEZE-01）。
//!
//! per-kind 字段（#1035）：http 的 `path`/`method`、event 的 `topic`/`delivery`、saga 的 `[saga]` block
//! 是 per-kind 可选字段（缺省 `None`，按 kind × lifecycle 由 `validate.rs` R8 报必填）。「坏值不可表达」
//! 尽量上移类型层（Hard）：`HttpMethod`/`Delivery`/Saga policy 枚举解析拒非法 variant、saga
//! duration 用 `u64` 使「负 duration」不可表达、嵌套结构 `deny_unknown_fields`。
//!
//! event 订阅声明（#1120/#1822）：`[[subscriptions]]` 声明 event 契约的 consumer 域、consumer group
//! 与非可选 closed `externalEffectPolicy`，由仓外 consumer tooling 派生 typed `SubscriptionSpec` 并接线
//! （EVENT-ACTIVE-SUB-01 / SUBSCRIPTION-EXTERNAL-EFFECT-POLICY-01 守）。
//! `#[serde(default)]` 将未声明 subscriptions 精确表达为空集合；active 非空约束由 validate R14 承担。

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use vocab::StepName;

/// event 订阅声明字段名常量（#1120）——DRY 于 validate R14 + consumer tooling 订阅 glue（消除裸串重复）。
pub const FIELD_SUBSCRIPTIONS: &str = "[[subscriptions]]";

/// schema 键名常量——DRY 于 validate + consumer tooling 双处引用（消除裸串重复）。
pub const SCHEMA_KEY_REQUEST: &str = "request";
pub const SCHEMA_KEY_RESPONSE: &str = "response";
pub const SCHEMA_KEY_PAYLOAD: &str = "payload";
pub const SCHEMA_KEY_PROJECTION: &str = "projection";

/// per-kind / governance block 字段名常量（#1035）——DRY 于 validate R8/R9/R22 + finding 文案（对齐
/// SCHEMA_KEY_* 范式，防裸串拼写漂移）。`FIELD_*` block 常量用 TOML 表形态指代，与文案一致。
pub const FIELD_PATH: &str = "path";
pub const FIELD_METHOD: &str = "method";
pub const FIELD_TOPIC: &str = "topic";
pub const FIELD_DELIVERY: &str = "delivery";
pub const FIELD_SAGA: &str = "[saga]";
pub const FIELD_COMMAND: &str = "[command]";
pub const FIELD_RECONCILE: &str = "[reconcile]";
pub const FIELD_EFFECT_PROFILE: &str = "[effectProfile]";
pub const FIELD_ENDPOINTS_HTTP_AUTH: &str = "[endpoints.http.auth]";
pub const FIELD_ENDPOINTS_HTTP_HEADERS: &str = "[endpoints.http.headers]";
pub const FIELD_ENDPOINTS_HTTP_RESOURCE_SHARING: &str = "[endpoints.http.resourceSharing]";

/// `contract.toml` 的解析目标。字段集冻结——见模块 INVARIANT。
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ContractManifest {
    pub id: String,
    pub kind: ContractKind,
    pub domain: String,
    pub version: String,
    pub(crate) owner: RawContractOwner,
    #[serde(rename = "consistencyLevel")]
    pub consistency_level: ConsistencyLevel,
    pub lifecycle: Lifecycle,
    #[serde(default)]
    pub schemas: Schemas,
    /// HTTP serving metadata. The only accepted nested shape is:
    /// `[endpoints.http.auth]` + `[endpoints.http.headers]`; nested structs use
    /// `deny_unknown_fields`, so typos fail at parse time instead of becoming
    /// silently ignored governance holes.
    #[serde(default)]
    pub endpoints: Option<Endpoints>,
    /// http per-kind：业务路径（`/api/v{N}/{domain}/…` 约定）。active http 必填（R8）。
    #[serde(default)]
    pub path: Option<String>,
    /// http per-kind：HTTP 方法。active http 必填（R8）；非法值解析即 `Err`（Hard）。
    #[serde(default)]
    pub method: Option<HttpMethod>,
    /// event per-kind：稳定 dotted topic 名。active event 必填（R8）。
    #[serde(default)]
    pub topic: Option<String>,
    /// event per-kind：投递语义。active event 必填（R8）；非法值解析即 `Err`（Hard）。
    #[serde(default)]
    pub delivery: Option<Delivery>,
    /// saga per-kind：`[saga]` 专属 block。active saga 必填（R8）；内部良构由 R10 守。
    #[serde(default)]
    pub saga: Option<SagaBlock>,
    /// HTTP route effect vocabulary. This is a declarative carrier for consumer tooling
    /// and later L0/L1 gates; R22 ensures every HTTP contract declares it.
    #[serde(default, rename = "effectProfile")]
    pub effect_profile: Option<EffectProfile>,
    /// event 订阅声明（#1120）：`[[subscriptions]]` 数组，每项声明一个消费者域 + consumer group。
    /// `#[serde(default)]` ⇒ 未声明 subscriptions 时为空集合；draft/deprecated 可合法为空。
    /// active event 必须非空（EVENT-ACTIVE-SUB-01，R14）；draft/deprecated 豁免。
    #[serde(default)]
    pub subscriptions: Vec<Subscription>,
    /// L0-L4 consistency capability evidence. `consistencyLevel` names the intended
    /// semantics; this typed block provides the machine-checkable proof surface.
    #[serde(default)]
    pub capabilities: Capabilities,
}

impl ContractManifest {
    /// 解析 `contract.toml` 文本。坏枚举 / 未知字段 / 缺字段即 `Err`（CONTRACT-FREEZE-01）。
    pub fn from_toml_str(text: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(text)
    }

    /// Domain spelling declared by this raw manifest, or `None` for the framework sentinel.
    /// Canonical owner promotion remains owned by repository discovery.
    pub fn owner_domain(&self) -> Option<&str> {
        match &self.owner {
            RawContractOwner::Domain(domain) => Some(domain),
            RawContractOwner::Framework => None,
        }
    }

    /// Whether this raw manifest declares the framework sentinel.
    pub fn is_framework_owned(&self) -> bool {
        matches!(self.owner, RawContractOwner::Framework)
    }

    /// Test-only owner mutation seam for synthetic manifest fixtures.
    #[cfg(feature = "test-support")]
    #[doc(hidden)]
    pub fn test_set_domain_owner(&mut self, domain: impl Into<String>) {
        self.owner = RawContractOwner::Domain(domain.into());
    }

    /// Test-only framework-owner mutation seam for synthetic manifest fixtures.
    #[cfg(feature = "test-support")]
    #[doc(hidden)]
    pub fn test_set_framework_owner(&mut self) {
        self.owner = RawContractOwner::Framework;
    }

    /// 全部已声明的 schema 文件名 = `[schemas]` 声明 ∪ 各 saga step `receiptSchema`
    /// （DRY 单源：R5 存在性 + R6 防逃逸统一消费 schema 文件完整性，含 saga step 引用）。
    pub fn declared_schema_files(&self) -> Vec<&str> {
        let mut files = self.schemas.declared_files();
        files.extend(self.schemas.responses.values().map(String::as_str));
        if let Some(saga) = &self.saga {
            files.extend(saga.steps.iter().map(|s| s.receipt_schema.as_str()));
        }
        files
    }
}

/// 契约种类。`kind` 决定 wire 形态与 consumer tooling 走向；磁盘段 `contracts/{kind}/...` 与之同源。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ContractKind {
    Http,
    Event,
    Saga,
    Projection,
}

impl ContractKind {
    /// 磁盘目录段（与 `contracts/{kind}/...` 路径一致）。
    pub fn as_dir(self) -> &'static str {
        match self {
            ContractKind::Http => "http",
            ContractKind::Event => "event",
            ContractKind::Saga => "saga",
            ContractKind::Projection => "projection",
        }
    }
}

/// L0–L4 一致性等级（与 wire 语义同源，决策 #1）。拼写大小写敏感。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
pub enum ConsistencyLevel {
    LocalOnly,
    LocalTx,
    OutboxFact,
    WorkflowEventual,
}

/// Typed capability evidence for `consistencyLevel`.
///
/// Blocks are optional at parse time so diagnostics can be emitted as governance
/// findings with contract ids. Unknown fields and unknown enum values still fail
/// at parse time via `deny_unknown_fields` and closed enums.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Capabilities {
    #[serde(default)]
    pub local_tx: Option<LocalTxCapability>,
    #[serde(default)]
    pub outbox: Option<OutboxCapability>,
    #[serde(default)]
    pub workflow: Option<WorkflowCapability>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct LocalTxCapability {
    pub boundary: LocalTxBoundary,
    pub tx_model: LocalTxModel,
    pub retry: LocalTxRetry,
    pub commit_unknown: LocalTxCommitUnknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum LocalTxBoundary {
    SingleDomain,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum LocalTxModel {
    TenantScopedUow,
    RepoAtomicCas,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum LocalTxRetry {
    BoundedTransient,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum LocalTxCommitUnknown {
    NotRetryable,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EffectProfile {
    pub effects: Vec<EffectKind>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum EffectKind {
    Read,
    Auth,
    Projection,
    BusinessWrite,
    BusinessTransaction,
    Outbox,
    Publish,
    Workflow,
    Saga,
    Reconcile,
    Worker,
}

impl EffectKind {
    /// Stable `contract.toml` wire name shared by every effect governance consumer.
    pub fn as_wire(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Auth => "auth",
            Self::Projection => "projection",
            Self::BusinessWrite => "business-write",
            Self::BusinessTransaction => "business-transaction",
            Self::Outbox => "outbox",
            Self::Publish => "publish",
            Self::Workflow => "workflow",
            Self::Saga => "saga",
            Self::Reconcile => "reconcile",
            Self::Worker => "worker",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OutboxCapability {
    pub role: OutboxRole,
    #[serde(default)]
    pub atomicity: Option<OutboxAtomicity>,
    #[serde(default)]
    pub emits: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum OutboxRole {
    Producer,
    Fact,
    Command,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum OutboxAtomicity {
    SameTransaction,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowCapability {
    pub mode: WorkflowMode,
    #[serde(default)]
    pub inputs: Vec<String>,
    #[serde(default)]
    pub ordering: Option<WorkflowOrdering>,
    #[serde(default)]
    pub checkpoint: Option<WorkflowRequirement>,
    #[serde(default)]
    pub replay: Option<WorkflowRequirement>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum WorkflowMode {
    Saga,
    Projection,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum WorkflowOrdering {
    SerialInOrder,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum WorkflowRequirement {
    Required,
}

/// 契约生命周期。`active` 才需 assembly 接线（见 `contract.toml`、schema consumer tooling 与 contract validation）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Lifecycle {
    Draft,
    Active,
    Deprecated,
}

/// Serde-only contract owner DTO. Repository consumers receive the sealed, manifest-backed
/// `repository_contract::ContractOwner` after source promotion; this raw shape never crosses the
/// assembly-schema crate boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RawContractOwner {
    Domain(String),
    Framework,
}

impl<'de> Deserialize<'de> for RawContractOwner {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Ok(if raw == "_framework" {
            RawContractOwner::Framework
        } else {
            RawContractOwner::Domain(raw)
        })
    }
}

impl Serialize for RawContractOwner {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(match self {
            Self::Domain(domain) => domain,
            Self::Framework => "_framework",
        })
    }
}

/// 契约声明的 schema 文件名（按 kind 取用子集；缺省全 `None`，由 validate R4 报形态错）。
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Schemas {
    #[serde(default)]
    pub request: Option<String>,
    #[serde(default)]
    pub response: Option<String>,
    #[serde(default)]
    pub payload: Option<String>,
    #[serde(default)]
    pub projection: Option<String>,
    #[serde(default)]
    pub responses: BTreeMap<HttpStatusCode, String>,
}

impl Schemas {
    /// 已声明的 schema 文件名，顺序 request → response → payload → projection（DRY 单源，供
    /// consumer tooling + validate 复用）。
    pub fn declared_files(&self) -> Vec<&str> {
        [
            self.request.as_deref(),
            self.response.as_deref(),
            self.payload.as_deref(),
            self.projection.as_deref(),
        ]
        .into_iter()
        .flatten()
        .collect()
    }

    pub fn response(&self, success_status: u16) -> Option<&str> {
        let status = HttpStatusCode::new(success_status);
        self.responses
            .get(&status)
            .map(String::as_str)
            .or(self.response.as_deref())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct HttpStatusCode(u16);

impl HttpStatusCode {
    pub const fn new(value: u16) -> Self {
        assert!(
            value >= 100 && value <= 599,
            "HTTP status must be in 100..=599"
        );
        Self(value)
    }

    pub const fn get(self) -> u16 {
        self.0
    }
}

impl std::fmt::Display for HttpStatusCode {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(formatter)
    }
}

impl<'de> Deserialize<'de> for HttpStatusCode {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct Visitor;

        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = HttpStatusCode;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("an HTTP status in 100..=599")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                let value = value.parse::<u16>().map_err(E::custom)?;
                if !(100..=599).contains(&value) {
                    return Err(E::custom("HTTP status must be in 100..=599"));
                }
                Ok(HttpStatusCode::new(value))
            }

            fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                let value = u16::try_from(value).map_err(E::custom)?;
                if !(100..=599).contains(&value) {
                    return Err(E::custom("HTTP status must be in 100..=599"));
                }
                Ok(HttpStatusCode::new(value))
            }
        }

        deserializer.deserialize_any(Visitor)
    }
}

/// HTTP 方法（http 契约 per-kind 字段）。闭值集 = rust-standards §API 动词集；
/// 非法值（如 `"FETCH"`）解析即 `Err`（Hard，类型层），无需运行期规则。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Patch,
    Delete,
}

impl HttpMethod {
    pub fn as_wire(self) -> &'static str {
        match self {
            HttpMethod::Get => "GET",
            HttpMethod::Post => "POST",
            HttpMethod::Put => "PUT",
            HttpMethod::Patch => "PATCH",
            HttpMethod::Delete => "DELETE",
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Endpoints {
    #[serde(default)]
    pub http: Option<HttpEndpoint>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HttpEndpoint {
    #[serde(rename = "successStatus")]
    pub success_status: u16,
    pub idempotency: HttpIdempotency,
    #[serde(default)]
    pub auth: Option<HttpAuth>,
    #[serde(default)]
    pub resource: Option<String>,
    #[serde(default, rename = "selfScoped")]
    pub self_scoped: bool,
    #[serde(default, rename = "resourceSharing")]
    pub resource_sharing: Option<HttpResourceSharing>,
    #[serde(default)]
    pub headers: BTreeMap<String, HttpHeaderMode>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum HttpIdempotency {
    Idempotent,
    NonIdempotent,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HttpResourceSharing {
    pub mode: HttpResourceSharingMode,
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum HttpResourceSharingMode {
    TenantScoped,
    Global,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HttpAuth {
    pub mode: HttpAuthMode,
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum HttpAuthMode {
    Public,
    Bootstrap,
    ClientsOnly,
    ServiceOwned,
}

impl HttpAuthMode {
    pub fn as_wire(self) -> &'static str {
        match self {
            HttpAuthMode::Public => "public",
            HttpAuthMode::Bootstrap => "bootstrap",
            HttpAuthMode::ClientsOnly => "clientsOnly",
            HttpAuthMode::ServiceOwned => "serviceOwned",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum HttpHeaderMode {
    PopulateOnly,
    ServiceTokenTenantBound,
}

/// 事件投递语义（event 契约 per-kind 字段）。三标准投递保证；非法值解析即 `Err`（Hard，类型层）。
///
/// **当前实现路径**：RSS outbox + 幂等消费者 = `at-least-once`（见 `external provider manifests`、static output 与 `crates/consistency`）。
/// `AtMostOnce` / `ExactlyOnce` 为前瞻保留值——当前 broker 链路无对应运行时保证。三值保留供 draft/deprecated
/// 表达前瞻设计，但 **active event 经 validate R11 机器拒**（仅放行 `at-least-once`），不虚开语义承诺。
/// README §字段表 同步此说明。
// reason: 三标准投递保证的规范命名天然共享后缀 "Once"（at-least/most/exactly-once），enum_variant_names
// 在此为误报；保留全描述式命名（同 ConsistencyLevel）优先于改名（改名须连带改 serde wire 值，得不偿失）。
// stock 风格 lint、非 RSS 自定义治理的 item-level carve-out。carve-out 登记：
// 项目 ADR registry 尚未建立，暂记于此，待 registry 落地迁入。
#[allow(clippy::enum_variant_names)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Delivery {
    AtLeastOnce,
    AtMostOnce,
    ExactlyOnce,
}

impl Delivery {
    /// wire 值（kebab-case，与 `contract.toml` / serde rename 同源）——供 validate 文案与 contract.toml 对齐。
    pub fn as_wire(self) -> &'static str {
        match self {
            Delivery::AtLeastOnce => "at-least-once",
            Delivery::AtMostOnce => "at-most-once",
            Delivery::ExactlyOnce => "exactly-once",
        }
    }
}

/// saga 补偿顺序——仅 `reverse`（static output、`diport::SagaDurableStore` 与 saga conformance governance）。单 variant ⇒ 取值类型层固定（Hard）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CompensationOrder {
    Reverse,
}

/// saga 专属 block（saga 契约 per-kind 字段，TOML `[saga]` 表）。
///
/// duration 用 `u64` ⇒「负 duration」不可表达（Hard）；闭合枚举拒绝未知执行语义。
/// 内部良构（≥1 step、step name 合法唯一、receipt/effect scope 非空、retry budget 有效）
/// 由 validate R10 守（运行期，Medium）；step `receiptSchema` 文件完整性经 [`ContractManifest::declared_schema_files`]
/// 复用 R5/R6。
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SagaBlock {
    pub steps: Vec<SagaStep>,
    pub compensation_order: CompensationOrder,
    pub retry: SagaRetryPolicy,
}

/// Saga retry budget 与 backoff policy。所有字段必填，不提供默认。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SagaRetryPolicy {
    pub max_attempts: u32,
    pub time_budget_millis: u64,
    pub backoff: SagaBackoff,
    pub initial_backoff_millis: u64,
    pub max_backoff_millis: u64,
    pub jitter: SagaJitter,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SagaBackoff {
    Fixed,
    Exponential,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SagaJitter {
    None,
    Full,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SagaIdempotencyClass {
    DeterministicKey,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SagaCompensationInput {
    Receipt,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SagaRetryClass {
    Never,
    Transient,
}

/// saga 单步的完整执行语义。
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SagaStep {
    pub name: StepName,
    pub receipt_schema: String,
    pub effect_scope: String,
    pub compensation_effect_scope: String,
    pub idempotency_class: SagaIdempotencyClass,
    pub compensation_input: SagaCompensationInput,
    pub retry_class: SagaRetryClass,
}

/// event 订阅声明（#1120/#1438）——TOML `[[subscriptions]]` 数组元素。
///
/// `consumer`：消费者域标识。`group`：稳定 consumer group 名。
/// `[subscriptions.topology]`：该 consumer 的 L2 topology gate，声明 partition key 策略与 readiness 要求。
/// 三者均为必填，未知子键由 `deny_unknown_fields` 拒（CONTRACT-FREEZE-01 扩展）。
///
/// 供仓外 consumer tooling 派生并接线订阅注册 glue（`SUBSCRIPTIONS: &[SubscriptionSpec]`）。
/// EVENT-ACTIVE-SUB-01（R12）：active event 必须 `!subscriptions.is_empty()`。
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Subscription {
    /// 消费者域标识。
    pub consumer: String,
    /// 稳定 consumer group 名——broker 用此键唯一标识消费位点。
    pub group: String,
    /// handler 执行边界。必填闭值，runtime 不得再按 consumer 推断行为。
    pub execution: SubscriptionExecution,
    /// 事务外副作用策略。每条 subscription 必须显式声明；无默认或兼容别名。
    #[serde(rename = "externalEffectPolicy")]
    pub external_effect_policy: ExternalEffectPolicy,
    /// L2 topology gate：partition key 策略 + subscriber readiness 要求。
    pub topology: SubscriptionTopology,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SubscriptionExecution {
    AdapterNative,
    DomainEffect,
}

/// Closed policy for side effects that cannot be protected by the ConsumerTx database transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ExternalEffectPolicy {
    TransactionalOnly,
    IdempotencyKey,
    Reconcile,
    Compensated,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SubscriptionTopology {
    /// producer 是否必须提供 partition key。`aggregate` 表示应用层用 tenant-scoped aggregate key
    /// 调 `OutboxEnvelopeParts::with_partition_key`，`none` 表示无序并行。
    pub partition_key: PartitionKeyStrategy,
    /// active subscriber/provisioning readiness 要求。当前闭值集仅 `required`，表示组合根必须 fail-closed。
    pub readiness: SubscriberReadiness,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PartitionKeyStrategy {
    None,
    Aggregate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SubscriberReadiness {
    Required,
}
