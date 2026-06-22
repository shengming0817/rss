//! 契约元数据声明（`contract.toml`）的冻结类型。
//!
//! INVARIANT: CONTRACT-FREEZE-01 — `ContractManifest` 字段集 + 枚举即 `contract.toml` 格式的
//! 单一事实源（Hard，类型层）：`#[serde(deny_unknown_fields)]` + 非 `Option` 枚举字段使「坏格式」
//! 解析即 `Err`，错误不可表达。新增/删字段须同步 `contracts/README.md` 与种子 golden。
//! Hard 类型层部分（字段冻结、枚举解析拒绝）在本文件；运行期跨字段不变式见 `validate.rs`（CONTRACT-FREEZE-01）。
//!
//! per-kind 字段（#1035）：http 的 `path`/`method`、event 的 `topic`/`delivery`、saga 的 `[saga]` block
//! 是 per-kind 可选字段（缺省 `None`，按 kind × lifecycle 由 `validate.rs` R8 报必填）。「坏值不可表达」
//! 尽量上移类型层（Hard）：`HttpMethod`/`Delivery`/`CompensationOrder` 枚举解析拒非法 variant、saga
//! `retryMillis`/`timeoutMillis` 用 `u64` 使「负 duration」不可表达、嵌套结构 `deny_unknown_fields`。

use serde::Deserialize;

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
}
