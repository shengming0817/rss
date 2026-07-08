//! 契约元数据声明（`contract.toml`）的冻结类型。
//!
//! INVARIANT: CONTRACT-FREEZE-01 { level = "Medium", exec = "verify", source = "code" }— `ContractManifest` 字段集 + 枚举即 `contract.toml` 格式的
//! 单一事实源（Hard，类型层）：`#[serde(deny_unknown_fields)]` + 非 `Option` 枚举字段使「坏格式」
//! 解析即 `Err`，错误不可表达。新增/删字段须同步 `contracts/README.md` 与种子 golden。
//! Hard 类型层部分（字段冻结、枚举解析拒绝）在本文件；运行期跨字段不变式见 `validate.rs`（CONTRACT-FREEZE-01）。
//!
//! per-kind 字段（#1035）：http 的 `path`/`method`、event 的 `topic`/`delivery`、saga 的 `[saga]` block
//! 是 per-kind 可选字段（缺省 `None`，按 kind × lifecycle 由 `validate.rs` R8 报必填）。「坏值不可表达」
//! 尽量上移类型层（Hard）：`HttpMethod`/`Delivery`/`CompensationOrder` 枚举解析拒非法 variant、saga
//! `retryMillis`/`timeoutMillis` 用 `u64` 使「负 duration」不可表达、嵌套结构 `deny_unknown_fields`。
//!
//! event 订阅声明（#1120）：`[[subscriptions]]` 声明 event 契约的 consumer 域与 consumer group，
//! 由 codegen 派生订阅注册 glue（`SUBSCRIPTIONS` 常量数组），供 bootstrap 接线消费（EVENT-ACTIVE-SUB-01 守）。
//! `#[serde(default)]` 保证现有无 subscriptions 的契约仍解析（空 vec），不破坏 CONTRACT-FREEZE-01。

use serde::Deserialize;
use std::collections::BTreeMap;

/// event 订阅声明字段名常量（#1120）——DRY 于 validate R14 + codegen 订阅 glue（消除裸串重复）。
pub(crate) const FIELD_SUBSCRIPTIONS: &str = "[[subscriptions]]";

/// schema 键名常量——DRY 于 validate + codegen 双处引用（消除裸串重复）。
pub(crate) const SCHEMA_KEY_REQUEST: &str = "request";
pub(crate) const SCHEMA_KEY_RESPONSE: &str = "response";
pub(crate) const SCHEMA_KEY_PAYLOAD: &str = "payload";

/// per-kind 字段名常量（#1035）——DRY 于 validate R8/R9 + finding 文案（对齐 SCHEMA_KEY_* 范式，
/// 防裸串拼写漂移）。`FIELD_SAGA` 用 `[saga]` 形态指代 TOML 表，与文案一致。
pub(crate) const FIELD_PATH: &str = "path";
pub(crate) const FIELD_METHOD: &str = "method";
pub(crate) const FIELD_TOPIC: &str = "topic";
pub(crate) const FIELD_DELIVERY: &str = "delivery";
pub(crate) const FIELD_SAGA: &str = "[saga]";
pub(crate) const FIELD_ENDPOINTS_HTTP_AUTH: &str = "[endpoints.http.auth]";
pub(crate) const FIELD_ENDPOINTS_HTTP_HEADERS: &str = "[endpoints.http.headers]";
pub(crate) const FIELD_ENDPOINTS_HTTP_PROJECTION: &str = "[endpoints.http.projection]";
pub(crate) const FIELD_ENDPOINTS_HTTP_RESOURCE_SHARING: &str = "[endpoints.http.resourceSharing]";

/// `contract.toml` 的解析目标。字段集冻结——见模块 INVARIANT。
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ContractManifest {
    pub(crate) id: String,
    pub(crate) kind: ContractKind,
    pub(crate) domain: String,
    pub(crate) version: String,
    pub(crate) owner: ContractOwner,
    #[serde(rename = "consistencyLevel")]
    pub(crate) consistency_level: ConsistencyLevel,
    pub(crate) lifecycle: Lifecycle,
    #[serde(default)]
    pub(crate) schemas: Schemas,
    /// HTTP serving metadata. The only accepted nested shape is:
    /// `[endpoints.http.auth]` + `[endpoints.http.headers]`; nested structs use
    /// `deny_unknown_fields`, so typos fail at parse time instead of becoming
    /// silently ignored governance holes.
    #[serde(default)]
    pub(crate) endpoints: Option<Endpoints>,
    /// http per-kind：业务路径（`/api/v{N}/{domain}/…` 约定）。active http 必填（R8）。
    #[serde(default)]
    pub(crate) path: Option<String>,
    /// http per-kind：HTTP 方法。active http 必填（R8）；非法值解析即 `Err`（Hard）。
    #[serde(default)]
    pub(crate) method: Option<HttpMethod>,
    /// event per-kind：稳定 dotted topic 名。active event 必填（R8）。
    #[serde(default)]
    pub(crate) topic: Option<String>,
    /// event per-kind：投递语义。active event 必填（R8）；非法值解析即 `Err`（Hard）。
    #[serde(default)]
    pub(crate) delivery: Option<Delivery>,
    /// saga per-kind：`[saga]` 专属 block。active saga 必填（R8）；内部良构由 R10 守。
    #[serde(default)]
    pub(crate) saga: Option<SagaBlock>,
    /// event 订阅声明（#1120）：`[[subscriptions]]` 数组，每项声明一个消费者域 + consumer group。
    /// `#[serde(default)]` ⇒ 无 subscriptions 字段的既有契约仍解析（空 vec，不破坏 CONTRACT-FREEZE-01）。
    /// active event 必须非空（EVENT-ACTIVE-SUB-01，R14）；draft/deprecated 豁免。
    #[serde(default)]
    pub(crate) subscriptions: Vec<Subscription>,
    /// L0-L4 consistency capability evidence. `consistencyLevel` names the intended
    /// semantics; this typed block provides the machine-checkable proof surface.
    #[serde(default)]
    pub(crate) capabilities: Capabilities,
}

impl ContractManifest {
    /// 解析 `contract.toml` 文本。坏枚举 / 未知字段 / 缺字段即 `Err`（CONTRACT-FREEZE-01）。
    pub(crate) fn from_toml_str(text: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(text)
    }

    /// 全部已声明的 schema 文件名 = `[schemas]` 声明 ∪ 各 saga step `outputSchema`
    /// （DRY 单源：R5 存在性 + R6 防逃逸统一消费 schema 文件完整性，含 saga step 引用）。
    pub(crate) fn declared_schema_files(&self) -> Vec<&str> {
        let mut files = self.schemas.declared_files();
        if let Some(saga) = &self.saga {
            files.extend(saga.steps.iter().map(|s| s.output_schema.as_str()));
        }
        files
    }
}

/// 契约种类。`kind` 决定 wire 形态与 codegen 走向；磁盘段 `contracts/{kind}/...` 与之同源。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum ContractKind {
    Http,
    Event,
    Command,
    Saga,
}

impl ContractKind {
    /// 磁盘目录段（与 `contracts/{kind}/...` 路径一致）。
    pub(crate) fn as_dir(self) -> &'static str {
        match self {
            ContractKind::Http => "http",
            ContractKind::Event => "event",
            ContractKind::Command => "command",
            ContractKind::Saga => "saga",
        }
    }
}

/// L0–L4 一致性等级（与 wire 语义同源，决策 #1）。拼写大小写敏感。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub(crate) enum ConsistencyLevel {
    LocalOnly,
    LocalTx,
    OutboxFact,
    WorkflowEventual,
    DeviceLatent,
}

/// Typed capability evidence for `consistencyLevel`.
///
/// Blocks are optional at parse time so diagnostics can be emitted as governance
/// findings with contract ids. Unknown fields and unknown enum values still fail
/// at parse time via `deny_unknown_fields` and closed enums.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct Capabilities {
    #[serde(default)]
    pub(crate) local_tx: Option<LocalTxCapability>,
    #[serde(default)]
    pub(crate) outbox: Option<OutboxCapability>,
    #[serde(default)]
    pub(crate) workflow: Option<WorkflowCapability>,
    #[serde(default)]
    pub(crate) device_latent: Option<DeviceLatentCapability>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LocalTxCapability {
    pub(crate) boundary: LocalTxBoundary,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum LocalTxBoundary {
    SingleDomain,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OutboxCapability {
    pub(crate) role: OutboxRole,
    #[serde(default)]
    pub(crate) atomicity: Option<OutboxAtomicity>,
    #[serde(default)]
    pub(crate) emits: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum OutboxRole {
    Producer,
    Fact,
    Command,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum OutboxAtomicity {
    SameTransaction,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct WorkflowCapability {
    pub(crate) mode: WorkflowMode,
    #[serde(default)]
    pub(crate) inputs: Vec<String>,
    #[serde(default)]
    pub(crate) ordering: Option<WorkflowOrdering>,
    #[serde(default)]
    pub(crate) checkpoint: Option<WorkflowRequirement>,
    #[serde(default)]
    pub(crate) replay: Option<WorkflowRequirement>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum WorkflowMode {
    Saga,
    Projection,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum WorkflowOrdering {
    SerialInOrder,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum WorkflowRequirement {
    Required,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct DeviceLatentCapability {
    #[serde(rename = "loop")]
    pub(crate) loop_kind: DeviceLatentLoop,
    pub(crate) tenancy: DeviceLatentTenancy,
    pub(crate) trigger: DeviceLatentTrigger,
    pub(crate) fencing: DeviceLatentFencing,
    pub(crate) late_message_policy: DeviceLatentLateMessagePolicy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum DeviceLatentLoop {
    Reconcile,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum DeviceLatentTenancy {
    SingleTenant,
    TenantScoped,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum DeviceLatentTrigger {
    Interval,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum DeviceLatentFencing {
    Required,
    SingleProcess,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum DeviceLatentLateMessagePolicy {
    Idempotent,
}

/// 契约生命周期。`active` 才需 assembly 接线（见 contract-fanout.md §契约归属）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Lifecycle {
    Draft,
    Active,
    Deprecated,
}

/// 契约归属。`_framework` sentinel = provider-agnostic 中立契约归框架；其余为域名。
///
/// reason: G0.3 仅需「是否框架归属」（R2 用）；owner→域名解析（`owner().domain()`）+ sealed 封闭
/// （`Framework` 类型层无法解析成域）已收口到 `vocab::ContractOwner`（PR #188，构造封闭）。本 `String`-based
/// 解析 enum 与 `vocab::ContractOwner` 的双类型消重收口到 contract-registry 行为 PR，已登记 issue #1091
/// 跟踪（见 .claude/rules/rss/contract-fanout.md §契约归属）；本单元不预置未用 API。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ContractOwner {
    Domain(String),
    Framework,
}

impl<'de> Deserialize<'de> for ContractOwner {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Ok(if raw == "_framework" {
            ContractOwner::Framework
        } else {
            ContractOwner::Domain(raw)
        })
    }
}

/// 契约声明的 schema 文件名（按 kind 取用子集；缺省全 `None`，由 validate R4 报形态错）。
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Schemas {
    #[serde(default)]
    pub(crate) request: Option<String>,
    #[serde(default)]
    pub(crate) response: Option<String>,
    #[serde(default)]
    pub(crate) payload: Option<String>,
}

impl Schemas {
    /// 已声明的 schema 文件名，顺序 request → response → payload（DRY 单源，供 codegen + validate 复用）。
    pub(crate) fn declared_files(&self) -> Vec<&str> {
        [
            self.request.as_deref(),
            self.response.as_deref(),
            self.payload.as_deref(),
        ]
        .into_iter()
        .flatten()
        .collect()
    }
}

/// HTTP 方法（http 契约 per-kind 字段）。闭值集 = rust-standards §API 动词集；
/// 非法值（如 `"FETCH"`）解析即 `Err`（Hard，类型层），无需运行期规则。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub(crate) enum HttpMethod {
    Get,
    Post,
    Put,
    Patch,
    Delete,
}

impl HttpMethod {
    pub(crate) fn as_wire(self) -> &'static str {
        match self {
            HttpMethod::Get => "GET",
            HttpMethod::Post => "POST",
            HttpMethod::Put => "PUT",
            HttpMethod::Patch => "PATCH",
            HttpMethod::Delete => "DELETE",
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Endpoints {
    #[serde(default)]
    pub(crate) http: Option<HttpEndpoint>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HttpEndpoint {
    #[serde(default)]
    pub(crate) auth: Option<HttpAuth>,
    #[serde(default)]
    pub(crate) resource: Option<String>,
    #[serde(default, rename = "selfScoped")]
    pub(crate) self_scoped: bool,
    #[serde(default, rename = "resourceSharing")]
    pub(crate) resource_sharing: Option<HttpResourceSharing>,
    #[serde(default)]
    pub(crate) headers: BTreeMap<String, HttpHeaderMode>,
    #[serde(default)]
    pub(crate) projection: Option<HttpProjection>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HttpResourceSharing {
    pub(crate) mode: HttpResourceSharingMode,
    #[serde(default)]
    pub(crate) reason: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) enum HttpResourceSharingMode {
    TenantScoped,
    Global,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HttpAuth {
    pub(crate) mode: HttpAuthMode,
    #[serde(default)]
    pub(crate) reason: Option<String>,
    #[serde(default)]
    pub(crate) permission: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) enum HttpAuthMode {
    Permission,
    Public,
    Bootstrap,
    ClientsOnly,
    ServiceOwned,
}

impl HttpAuthMode {
    pub(crate) fn as_wire(self) -> &'static str {
        match self {
            HttpAuthMode::Permission => "permission",
            HttpAuthMode::Public => "public",
            HttpAuthMode::Bootstrap => "bootstrap",
            HttpAuthMode::ClientsOnly => "clientsOnly",
            HttpAuthMode::ServiceOwned => "serviceOwned",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum HttpHeaderMode {
    PopulateOnly,
    ServiceTokenTenantBound,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HttpProjection {
    #[serde(default)]
    pub(crate) fields: Vec<HttpProjectionField>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct HttpProjectionField {
    pub(crate) field: HttpProjectionFieldName,
    pub(crate) permission: String,
    pub(crate) obligation_key: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) enum HttpProjectionFieldName {
    AuditActor,
    AuditResourceId,
}

impl HttpProjectionFieldName {
    pub(crate) fn as_wire(self) -> &'static str {
        match self {
            Self::AuditActor => "auditActor",
            Self::AuditResourceId => "auditResourceId",
        }
    }

    pub(crate) fn as_vocab_variant(self) -> &'static str {
        match self {
            Self::AuditActor => "AuditActor",
            Self::AuditResourceId => "AuditResourceId",
        }
    }
}

/// 事件投递语义（event 契约 per-kind 字段）。三标准投递保证；非法值解析即 `Err`（Hard，类型层）。
///
/// **当前实现路径**：RSS outbox + 幂等消费者 = `at-least-once`（见 docs/rules/eventbus.md）。
/// `AtMostOnce` / `ExactlyOnce` 为前瞻保留值——当前 broker 链路无对应运行时保证。三值保留供 draft/deprecated
/// 表达前瞻设计，但 **active event 经 validate R11 机器拒**（仅放行 `at-least-once`），不虚开语义承诺。
/// README §字段表 同步此说明。
// reason: 三标准投递保证的规范命名天然共享后缀 "Once"（at-least/most/exactly-once），enum_variant_names
// 在此为误报；保留全描述式命名（同 ConsistencyLevel）优先于改名（改名须连带改 serde wire 值，得不偿失）。
// stock 风格 lint、非 RSS 自定义治理的 item-level carve-out（error-handling.md §Carve-out）。carve-out 登记：
// 项目 ADR registry 尚未建立（同 crates/bootstrap/src/shutdown.rs 既有先例），暂记于此，待 registry 落地迁入。
#[allow(clippy::enum_variant_names)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Delivery {
    AtLeastOnce,
    AtMostOnce,
    ExactlyOnce,
}

impl Delivery {
    /// wire 值（kebab-case，与 `contract.toml` / serde rename 同源）——供 validate 文案与 contract.toml 对齐。
    pub(crate) fn as_wire(self) -> &'static str {
        match self {
            Delivery::AtLeastOnce => "at-least-once",
            Delivery::AtMostOnce => "at-most-once",
            Delivery::ExactlyOnce => "exactly-once",
        }
    }
}

/// saga 补偿顺序——仅 `reverse`（saga.md governance）。单 variant ⇒ 取值类型层固定（Hard）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum CompensationOrder {
    Reverse,
}

/// saga 专属 block（saga 契约 per-kind 字段，TOML `[saga]` 表）。
///
/// `retryMillis`/`timeoutMillis` 用 `u64` ⇒「负 duration」不可表达（Hard）；`compensationOrder`
/// 用单 variant 枚举 ⇒ 仅 `reverse`（Hard）。内部良构（≥1 step、step name 合法唯一、outputSchema 非空）
/// 由 validate R10 守（运行期，Medium）；step `outputSchema` 文件完整性经 [`ContractManifest::declared_schema_files`]
/// 复用 R5/R6。
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct SagaBlock {
    pub(crate) steps: Vec<SagaStep>,
    pub(crate) compensation_order: CompensationOrder,
    pub(crate) retry_millis: u64,
    pub(crate) timeout_millis: u64,
}

/// saga 单步：`name`（可生成唯一 Rust 标识符，R10 守）+ `outputSchema`（输出 schema 文件名）。
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct SagaStep {
    pub(crate) name: String,
    pub(crate) output_schema: String,
}

/// event 订阅声明（#1120/#1438）——TOML `[[subscriptions]]` 数组元素。
///
/// `consumer`：消费者域 DomainId（如 `audit`）。`group`：稳定 consumer group 名（如 `audit.session-created`）。
/// `[subscriptions.topology]`：该 consumer 的 L2 topology gate，声明 partition key 策略与 readiness 要求。
/// 三者均为必填，未知子键由 `deny_unknown_fields` 拒（CONTRACT-FREEZE-01 扩展）。
///
/// 供 codegen 派生订阅注册 glue（`SUBSCRIPTIONS: &[SubscriptionSpec]`）；bootstrap 消费 glue 接线。
/// EVENT-ACTIVE-SUB-01（R12）：active event 必须 `!subscriptions.is_empty()`。
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Subscription {
    /// 消费者域 DomainId（如 `audit`、`devicestate`）。
    pub(crate) consumer: String,
    /// 稳定 consumer group 名（如 `audit.session-created`）——broker 用此键唯一标识消费位点。
    pub(crate) group: String,
    /// L2 topology gate：partition key 策略 + subscriber readiness 要求。
    pub(crate) topology: SubscriptionTopology,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct SubscriptionTopology {
    /// producer 是否必须提供 partition key。`aggregate` 表示应用层用 tenant-scoped aggregate key
    /// 调 `OutboxEnvelopeParts::with_partition_key`，`none` 表示无序并行。
    pub(crate) partition_key: PartitionKeyStrategy,
    /// active subscriber/provisioning readiness 要求。当前闭值集仅 `required`，表示组合根必须 fail-closed。
    pub(crate) readiness: SubscriberReadiness,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum PartitionKeyStrategy {
    None,
    Aggregate,
}

impl PartitionKeyStrategy {
    pub(crate) fn as_wire(self) -> &'static str {
        match self {
            PartitionKeyStrategy::None => "none",
            PartitionKeyStrategy::Aggregate => "aggregate",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum SubscriberReadiness {
    Required,
}

impl SubscriberReadiness {
    pub(crate) fn as_wire(self) -> &'static str {
        match self {
            SubscriberReadiness::Required => "required",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // golden 含 per-kind 字段（path/method）⇒ 绿用例真实演练 #1035 新字段解析。
    const VALID_HTTP: &str = r#"
        id = "seed.echo"
        kind = "http"
        domain = "_seed"
        version = "v1"
        owner = "_framework"
        consistencyLevel = "LocalOnly"
        lifecycle = "draft"
        path = "/api/v1/_seed/echo"
        method = "POST"
        [schemas]
        request = "request.schema.json"
        response = "response.schema.json"
    "#;

    const VALID_EVENT: &str = r#"
        id = "seed.thing-happened"
        kind = "event"
        domain = "_seed"
        version = "v1"
        owner = "_framework"
        consistencyLevel = "OutboxFact"
        lifecycle = "draft"
        topic = "seed.thing-happened"
        delivery = "at-least-once"
        [schemas]
        payload = "payload.schema.json"
    "#;

    const VALID_SAGA: &str = r#"
        id = "billing.checkout"
        kind = "saga"
        domain = "billing"
        version = "v1"
        owner = "billing"
        consistencyLevel = "WorkflowEventual"
        lifecycle = "draft"
        [schemas]
        payload = "payload.schema.json"
        [saga]
        compensationOrder = "reverse"
        retryMillis = 5000
        timeoutMillis = 30000
        steps = [
            { name = "reserve_funds", outputSchema = "reserve.schema.json" },
            { name = "capture", outputSchema = "capture.schema.json" },
        ]
    "#;

    #[test]
    fn parses_valid_http_manifest() -> anyhow::Result<()> {
        let m = ContractManifest::from_toml_str(VALID_HTTP)?;
        assert_eq!(m.id, "seed.echo");
        assert_eq!(m.kind, ContractKind::Http);
        assert_eq!(m.kind.as_dir(), "http");
        assert_eq!(m.consistency_level, ConsistencyLevel::LocalOnly);
        assert_eq!(m.lifecycle, Lifecycle::Draft);
        assert_eq!(m.owner, ContractOwner::Framework);
        assert_eq!(m.schemas.request.as_deref(), Some("request.schema.json"));
        assert_eq!(m.schemas.payload, None);
        // per-kind http 字段（#1035）。
        assert_eq!(m.path.as_deref(), Some("/api/v1/_seed/echo"));
        assert_eq!(m.method, Some(HttpMethod::Post));
        assert_eq!(m.topic, None);
        assert_eq!(m.delivery, None);
        assert_eq!(m.saga, None);
        Ok(())
    }

    #[test]
    fn parses_event_with_topic_delivery() -> anyhow::Result<()> {
        let m = ContractManifest::from_toml_str(VALID_EVENT)?;
        assert_eq!(m.kind, ContractKind::Event);
        assert_eq!(m.topic.as_deref(), Some("seed.thing-happened"));
        assert_eq!(m.delivery, Some(Delivery::AtLeastOnce));
        assert_eq!(m.path, None);
        Ok(())
    }

    #[test]
    fn parses_saga_block() -> anyhow::Result<()> {
        let m = ContractManifest::from_toml_str(VALID_SAGA)?;
        assert_eq!(m.kind, ContractKind::Saga);
        let saga = m
            .saga
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("saga block 应解析"))?;
        assert_eq!(saga.compensation_order, CompensationOrder::Reverse);
        assert_eq!(saga.retry_millis, 5000);
        assert_eq!(saga.timeout_millis, 30000);
        assert_eq!(saga.steps.len(), 2);
        assert_eq!(saga.steps[0].name, "reserve_funds");
        assert_eq!(saga.steps[0].output_schema, "reserve.schema.json");
        // saga step outputSchema 进入聚合器（供 R5/R6）。
        assert_eq!(
            m.declared_schema_files(),
            vec![
                "payload.schema.json",
                "reserve.schema.json",
                "capture.schema.json"
            ]
        );
        Ok(())
    }

    #[test]
    fn parses_typed_capabilities() -> anyhow::Result<()> {
        let toml = format!(
            r#"{VALID_HTTP}

            [capabilities.localTx]
            boundary = "single-domain"

            [capabilities.outbox]
            role = "producer"
            atomicity = "same-transaction"
            emits = ["identity.session-created"]

            [capabilities.workflow]
            mode = "projection"
            inputs = ["identity.session-created"]
            ordering = "serial-in-order"
            checkpoint = "required"
            replay = "required"

            [capabilities.deviceLatent]
            loop = "reconcile"
            tenancy = "tenant-scoped"
            trigger = "interval"
            fencing = "required"
            lateMessagePolicy = "idempotent"
        "#
        );
        let m = ContractManifest::from_toml_str(&toml)?;
        assert_eq!(
            m.capabilities.local_tx.as_ref().map(|c| c.boundary),
            Some(LocalTxBoundary::SingleDomain)
        );
        let outbox = m
            .capabilities
            .outbox
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("outbox capability should parse"))?;
        assert_eq!(outbox.role, OutboxRole::Producer);
        assert_eq!(outbox.atomicity, Some(OutboxAtomicity::SameTransaction));
        assert_eq!(outbox.emits, vec!["identity.session-created"]);
        let workflow = m
            .capabilities
            .workflow
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("workflow capability should parse"))?;
        assert_eq!(workflow.mode, WorkflowMode::Projection);
        assert_eq!(workflow.ordering, Some(WorkflowOrdering::SerialInOrder));
        assert_eq!(workflow.checkpoint, Some(WorkflowRequirement::Required));
        assert_eq!(workflow.replay, Some(WorkflowRequirement::Required));
        let device = m
            .capabilities
            .device_latent
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("deviceLatent capability should parse"))?;
        assert_eq!(device.loop_kind, DeviceLatentLoop::Reconcile);
        assert_eq!(device.tenancy, DeviceLatentTenancy::TenantScoped);
        assert_eq!(device.trigger, DeviceLatentTrigger::Interval);
        assert_eq!(device.fencing, DeviceLatentFencing::Required);
        assert_eq!(
            device.late_message_policy,
            DeviceLatentLateMessagePolicy::Idempotent
        );
        Ok(())
    }

    #[test]
    fn rejects_unknown_method() {
        let toml = VALID_HTTP.replace("\"POST\"", "\"FETCH\"");
        assert!(ContractManifest::from_toml_str(&toml).is_err());
    }

    #[test]
    fn rejects_unknown_delivery() {
        let toml = VALID_EVENT.replace("\"at-least-once\"", "\"maybe-once\"");
        assert!(ContractManifest::from_toml_str(&toml).is_err());
    }

    #[test]
    fn rejects_unknown_compensation_order() {
        let toml = VALID_SAGA.replace("\"reverse\"", "\"forward\"");
        assert!(ContractManifest::from_toml_str(&toml).is_err());
    }

    #[test]
    fn rejects_unknown_capability_value() {
        let toml = format!(
            r#"{VALID_HTTP}

            [capabilities.outbox]
            role = "maybe"
        "#
        );
        assert!(ContractManifest::from_toml_str(&toml).is_err());
    }

    #[test]
    fn rejects_incomplete_device_latent_capability() {
        let toml = format!(
            r#"{VALID_HTTP}

            [capabilities.deviceLatent]
            loop = "reconcile"
            tenancy = "tenant-scoped"
            trigger = "interval"
            fencing = "required"
        "#
        );
        assert!(ContractManifest::from_toml_str(&toml).is_err());
    }

    #[test]
    fn rejects_unknown_saga_field() {
        // SagaBlock deny_unknown_fields：未知子键解析即 Err（Hard）。
        let toml = VALID_SAGA.replace("retryMillis = 5000", "retryMillis = 5000\nbogus = 1");
        assert!(ContractManifest::from_toml_str(&toml).is_err());
    }

    #[test]
    fn rejects_negative_retry_millis() {
        // u64 字段：负值不可表达（Hard，类型层）。
        let toml = VALID_SAGA.replace("retryMillis = 5000", "retryMillis = -1");
        assert!(ContractManifest::from_toml_str(&toml).is_err());
    }

    #[test]
    fn domain_owner_resolves_to_name() -> anyhow::Result<()> {
        let toml = VALID_HTTP.replace("\"_framework\"", "\"identity\"");
        let m = ContractManifest::from_toml_str(&toml)?;
        assert_eq!(m.owner, ContractOwner::Domain("identity".to_string()));
        Ok(())
    }

    #[test]
    fn all_kinds_have_distinct_dirs() {
        // anti-vacuity：四种 kind 的磁盘段两两不同且枚举可解析。
        for (text, want) in [
            ("http", ContractKind::Http),
            ("event", ContractKind::Event),
            ("command", ContractKind::Command),
            ("saga", ContractKind::Saga),
        ] {
            assert_eq!(want.as_dir(), text);
        }
    }

    #[test]
    fn rejects_unknown_kind() {
        let toml = VALID_HTTP.replace("\"http\"", "\"rpc\"");
        assert!(ContractManifest::from_toml_str(&toml).is_err());
    }

    #[test]
    fn rejects_unknown_consistency_level() {
        let toml = VALID_HTTP.replace("\"LocalOnly\"", "\"Strong\"");
        assert!(ContractManifest::from_toml_str(&toml).is_err());
    }

    #[test]
    fn rejects_unknown_field() {
        let toml = format!("{VALID_HTTP}\nbogus = 1\n");
        assert!(ContractManifest::from_toml_str(&toml).is_err());
    }

    #[test]
    fn rejects_missing_required_field() {
        let toml = VALID_HTTP.replace("id = \"seed.echo\"", "");
        assert!(ContractManifest::from_toml_str(&toml).is_err());
    }

    #[test]
    fn rejects_unknown_schema_key() {
        let toml = VALID_HTTP.replace("request = ", "bogus = \"x\"\nrequest = ");
        assert!(ContractManifest::from_toml_str(&toml).is_err());
    }

    #[test]
    fn schemas_declared_files_returns_present_in_order() {
        let s = Schemas {
            request: Some("request.schema.json".to_string()),
            response: Some("response.schema.json".to_string()),
            payload: None,
        };
        assert_eq!(
            s.declared_files(),
            vec!["request.schema.json", "response.schema.json"]
        );

        let s2 = Schemas {
            request: None,
            response: None,
            payload: Some("payload.schema.json".to_string()),
        };
        assert_eq!(s2.declared_files(), vec!["payload.schema.json"]);

        let s3 = Schemas::default();
        assert!(s3.declared_files().is_empty());
    }

    // ── [[subscriptions]] 解析测试（#1120，CONTRACT-FREEZE-01 扩展）────────

    /// 绿用例：`[[subscriptions]]` 正确解析为 Vec<Subscription>，consumer/group 两字段均正确。
    #[test]
    fn parses_event_with_subscriptions() -> anyhow::Result<()> {
        let toml = r#"
            id = "identity.session-created"
            kind = "event"
            domain = "identity"
            version = "v1"
            owner = "identity"
            consistencyLevel = "OutboxFact"
            lifecycle = "active"
            topic = "identity.session-created"
            delivery = "at-least-once"
            [schemas]
            payload = "payload.schema.json"
            [[subscriptions]]
            consumer = "audit"
            group = "audit.session-created"
            [subscriptions.topology]
            partitionKey = "none"
            readiness = "required"
            [[subscriptions]]
            consumer = "devicestate"
            group = "devicestate.session-watch"
            [subscriptions.topology]
            partitionKey = "aggregate"
            readiness = "required"
        "#;
        let m = ContractManifest::from_toml_str(toml)?;
        assert_eq!(m.subscriptions.len(), 2);
        assert_eq!(m.subscriptions[0].consumer, "audit");
        assert_eq!(m.subscriptions[0].group, "audit.session-created");
        assert_eq!(
            m.subscriptions[0].topology.partition_key,
            PartitionKeyStrategy::None
        );
        assert_eq!(
            m.subscriptions[0].topology.readiness,
            SubscriberReadiness::Required
        );
        assert_eq!(m.subscriptions[1].consumer, "devicestate");
        assert_eq!(m.subscriptions[1].group, "devicestate.session-watch");
        assert_eq!(
            m.subscriptions[1].topology.partition_key,
            PartitionKeyStrategy::Aggregate
        );
        assert_eq!(
            m.subscriptions[1].topology.readiness,
            SubscriberReadiness::Required
        );
        Ok(())
    }

    /// 绿用例（anti-vacuity）：无 subscriptions 字段的既有契约仍解析（`#[serde(default)]`，空 vec）。
    /// 守卫现有合约兼容性：CONTRACT-FREEZE-01 扩展不破坏旧格式。
    #[test]
    fn event_without_subscriptions_parses_as_empty() -> anyhow::Result<()> {
        let m = ContractManifest::from_toml_str(VALID_EVENT)?;
        assert!(
            m.subscriptions.is_empty(),
            "无 [[subscriptions]] 字段应解析为空 vec（serde default）"
        );
        Ok(())
    }

    /// 红用例：[[subscriptions]] 顶层含未知子键时，`deny_unknown_fields` 应拒绝解析（CONTRACT-FREEZE-01）。
    #[test]
    fn subscription_rejects_unknown_field() {
        let toml = r#"
            id = "identity.session-created"
            kind = "event"
            domain = "identity"
            version = "v1"
            owner = "identity"
            consistencyLevel = "OutboxFact"
            lifecycle = "draft"
            topic = "identity.session-created"
            delivery = "at-least-once"
            [schemas]
            payload = "payload.schema.json"
            [[subscriptions]]
            consumer = "audit"
            group = "audit.session-created"
            bogus = "unexpected"
            [subscriptions.topology]
            partitionKey = "none"
            readiness = "required"
        "#;
        assert!(
            ContractManifest::from_toml_str(toml).is_err(),
            "[[subscriptions]] 顶层未知子键应使解析失败（deny_unknown_fields）"
        );
    }

    /// 红用例：[subscriptions.topology] 含未知子键时，`deny_unknown_fields` 应拒绝解析。
    #[test]
    fn subscription_topology_rejects_unknown_field() {
        let toml = r#"
            id = "identity.session-created"
            kind = "event"
            domain = "identity"
            version = "v1"
            owner = "identity"
            consistencyLevel = "OutboxFact"
            lifecycle = "draft"
            topic = "identity.session-created"
            delivery = "at-least-once"
            [schemas]
            payload = "payload.schema.json"
            [[subscriptions]]
            consumer = "audit"
            group = "audit.session-created"
            [subscriptions.topology]
            partitionKey = "none"
            readiness = "required"
            bogus = "unexpected"
        "#;
        assert!(
            ContractManifest::from_toml_str(toml).is_err(),
            "[subscriptions.topology] 未知子键应使解析失败（deny_unknown_fields）"
        );
    }

    /// 红用例：[[subscriptions]] 缺 `consumer` 字段时应拒绝解析。
    #[test]
    fn subscription_rejects_missing_consumer() {
        let toml = r#"
            id = "identity.session-created"
            kind = "event"
            domain = "identity"
            version = "v1"
            owner = "identity"
            consistencyLevel = "OutboxFact"
            lifecycle = "draft"
            topic = "identity.session-created"
            delivery = "at-least-once"
            [schemas]
            payload = "payload.schema.json"
            [[subscriptions]]
            group = "audit.session-created"
            [subscriptions.topology]
            partitionKey = "none"
            readiness = "required"
        "#;
        assert!(
            ContractManifest::from_toml_str(toml).is_err(),
            "缺 consumer 字段应使解析失败"
        );
    }

    /// 红用例：[[subscriptions]] 缺 `group` 字段时应拒绝解析。
    #[test]
    fn subscription_rejects_missing_group() {
        let toml = r#"
            id = "identity.session-created"
            kind = "event"
            domain = "identity"
            version = "v1"
            owner = "identity"
            consistencyLevel = "OutboxFact"
            lifecycle = "draft"
            topic = "identity.session-created"
            delivery = "at-least-once"
            [schemas]
            payload = "payload.schema.json"
            [[subscriptions]]
            consumer = "audit"
            [subscriptions.topology]
            partitionKey = "none"
            readiness = "required"
        "#;
        assert!(
            ContractManifest::from_toml_str(toml).is_err(),
            "缺 group 字段应使解析失败"
        );
    }

    /// 红用例：[[subscriptions]] 缺 topology block 时应拒绝解析（L2 topology contract gate）。
    #[test]
    fn subscription_rejects_missing_topology() {
        let toml = r#"
            id = "identity.session-created"
            kind = "event"
            domain = "identity"
            version = "v1"
            owner = "identity"
            consistencyLevel = "OutboxFact"
            lifecycle = "draft"
            topic = "identity.session-created"
            delivery = "at-least-once"
            [schemas]
            payload = "payload.schema.json"
            [[subscriptions]]
            consumer = "audit"
            group = "audit.session-created"
        "#;
        assert!(
            ContractManifest::from_toml_str(toml).is_err(),
            "缺 [subscriptions.topology] 应使解析失败"
        );
    }

    #[test]
    fn subscription_rejects_unknown_partition_key_strategy() {
        let toml = r#"
            id = "identity.session-created"
            kind = "event"
            domain = "identity"
            version = "v1"
            owner = "identity"
            consistencyLevel = "OutboxFact"
            lifecycle = "draft"
            topic = "identity.session-created"
            delivery = "at-least-once"
            [schemas]
            payload = "payload.schema.json"
            [[subscriptions]]
            consumer = "audit"
            group = "audit.session-created"
            [subscriptions.topology]
            partitionKey = "payload-field"
            readiness = "required"
        "#;
        assert!(
            ContractManifest::from_toml_str(toml).is_err(),
            "未知 partitionKey 策略应使解析失败"
        );
    }

    #[test]
    fn subscription_rejects_unknown_readiness() {
        let toml = r#"
            id = "identity.session-created"
            kind = "event"
            domain = "identity"
            version = "v1"
            owner = "identity"
            consistencyLevel = "OutboxFact"
            lifecycle = "draft"
            topic = "identity.session-created"
            delivery = "at-least-once"
            [schemas]
            payload = "payload.schema.json"
            [[subscriptions]]
            consumer = "audit"
            group = "audit.session-created"
            [subscriptions.topology]
            partitionKey = "none"
            readiness = "best-effort"
        "#;
        assert!(
            ContractManifest::from_toml_str(toml).is_err(),
            "未知 readiness 策略应使解析失败"
        );
    }
}
