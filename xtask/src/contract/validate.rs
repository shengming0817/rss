//! 契约元数据校验（规则集见下方执行顺序 + `Rule` 枚举单源）——`cargo xtask contract validate`。
//!
//! INVARIANT: CONTRACT-FANOUT-01 { level = "Medium", exec = "verify", source = "code" }— schema 引用完整性 + kind→形态一致（R4/R5，含 saga step `outputSchema`）。
//! INVARIANT: CONTRACT-FREEZE-01 { level = "Medium", exec = "verify", source = "code" }（运行期部分）— 跨字段不变式（R1 saga⇒L3 / R2 framework⇒http|event）、
//! 路径↔字段一致（R3）、authoring 标识符语法（R7：domain/version/id/owner 在拼进派生路径 / module 名前先收口）、
//! per-kind 字段（#1035）的 active 发布接线必填（R8）/ 跨 kind 卫生（R9）/ saga block 结构语义（R10）/
//! active event 投递语义可兑现性（R11）。
//! INVARIANT: SAGA-CONTRACT-01 { level = "Medium", exec = "verify", source = "code" }— kind:saga 契约治理（docs/rules/saga.md §Governance）= R1（saga ⇒
//! consistencyLevel WorkflowEventual/L3）+ R10（非空 `[saga]` block：≥1 step、step name 合法非关键字 Rust
//! 标识符且唯一、每步 outputSchema 非空；retry/timeout 非负 + compensationOrder=reverse 由 manifest.rs
//! 类型层 Hard 守）。负用例见 R1/R10 synthetic reds；正用例 = `contracts/saga/billing` 经 validate 全过
//! （Medium，CI 门，#1121）。
//! INVARIANT: CONTRACT-IDUNIQ-01 { level = "Medium", exec = "verify", source = "code" }— contract `id` 跨契约全局唯一（R12，`validate_cross` 跨契约扫描；
//! 依据 api-versioning.md：破坏式 wire 变更新建版本目录 **且** 新 contract ID ⇒ id 是全局注册标识，须唯一）。
//! INVARIANT: CONTRACT-TITLE-01 { level = "Medium", exec = "verify", source = "code" }— declared schema（喂 codegen TypeSpace 的 request/response/payload；saga 另含 step outputSchema）的
//! root 须有 string `title`（缺则 typify `add_root_schema` 返回 `Ok(None)`、根类型静默丢失），且全部
//! （含嵌套）title 须 PascalCase + **契约内**唯一（R13；title→typify Rust 类型名）。契约内重复 / 缺 root
//! title **未必**被 codegen 兜底（前者可能被合并 / 类型歧义、后者直接丢根类型，均非 compile error、非
//! fail-closed）；本规则在 validate 阶段提供 fail-fast + 清晰诊断（早于 codegen）+ PascalCase 形态。
//! INVARIANT: EVENT-ACTIVE-SUB-01 { level = "Medium", exec = "verify", source = "code", synthetic_red = "tests::r14_active_event_empty_subscriptions_rejected", anti_vacuity = "tests::r14_active_event_with_subscription_ok" }— `lifecycle=active && kind=event` ⇒ `[[subscriptions]]` 非空（R14，Medium）；
//! active event 无 subscriber 即死事件，视为错误配置（#1120）。
//! INVARIANT: CONTRACT-REDACTION-POLICY-01 { level = "Medium", exec = "verify", source = "code" }— declared schema property 上的 `x-pii` / `x-redaction`
//! 是 generated 安全 `Debug` 的单源（R16）。遗留 `x-sensitive`、未知枚举、高风险字段未标注、
//! `x-redaction=hash` 均 fail-closed。
//! INVARIANT: CONTRACT-PROTECTION-POLICY-01 { level = "Medium", exec = "verify", source = "code" }— declared schema 的 `x-protection`（at-rest 加密声明）+
//! `x-at-rest`（持久化 opt-in）合法且完整（R17，#1468，ADR-011 D1b 声明层）。block 内部一致、AAD 维度
//! 完整（D2）、deterministic/blindIndex 须 reason 且 aad 稳定子集（D4）、`x-at-rest` schema 高风险字段
//! 须显式 `x-protection`、加密字段不得 nullable、blindIndex 只允许非 nullable scalar，均 fail-closed。
//! 与 R16 observe redaction **正交不混用**（ADR-011 D1）。
//! INVARIANT: CONTRACT-HTTP-SERVING-01 { level = "Medium", exec = "verify", source = "code" }— active HTTP serving 必须声明 fail-closed auth/header metadata（R18）；
//! HTTP request schema 不得声明 `tenantId`，tenant scope 必须来自认证上下文、声明式 populate-only header
//! 或 service-token MAC 绑定 header（R19）；target tenant 必须来自显式 path 参数，不保留 request schema 例外。
//! INVARIANT: CONTRACT-HTTP-PROJECTION-COVERAGE-01 { level = "Medium", exec = "verify", source = "code" }— active GET response
//! 中的 `x-pii` 字段与 `tenantId` 字段必须经 `[endpoints.http.projection]` 的 `responsePath` 精确 enrollment（R23）；
//! contract metadata/codegen 是唯一 carrier，handler 不维护人工矩阵。
//! INVARIANT: CONTRACT-CONSISTENCY-CAPABILITY-01 { level = "Medium", exec = "verify", source = "code" }— `consistencyLevel`
//! 必须有 typed `[capabilities.*]` 证据，且能力块不得跨等级漂移（R22）。HTTP L2 producer 的 `emits`
//! 须引用存在的 L2 active event contract，L3 只接受当前 manifest 能表达的 workflow 证据；L4 还要求
//! device-latent evidence + `[reconcile]` block。
//! Medium（CI 门）；每条规则配 synthetic red case（见 `#[cfg(test)]`），
//! anti-vacuity：全合法绿用例必过、各红用例必失。
//! Hard 类型层部分（字段集冻结、枚举解析拒绝、`u64` 非负、嵌套 `deny_unknown_fields`）见 `manifest.rs`
//! （CONTRACT-FREEZE-01）；R8–R15 / R17–R19 是条件化跨字段 / schema 内容不变式（依赖 lifecycle/kind/值
//! 组合或 JSON Schema 内容），类型层无法免费表达，
//! 故与 R1–R7 同属 Medium——「能 Hard 则 Hard、余下 Medium」的正确分层。
//!
//! 嵌套多契约（同 `{domain}/{version}` 多端点 / 多事件，第 4 段 slug）的 slug 段语法（R20）+ 扁平/嵌套
//! 形态不可混用（R21）；前者逐契约、后者跨契约。
//!
//! 规则执行顺序（注释编号 = 执行先后）：
//!   逐契约（validate_contract）：R1 SagaConsistency → R2 FrameworkKind → R3 PathMismatch → R4 SchemaShape
//!   → R5 MissingSchema → R6 UnsafeSchemaPath → R7 IdentSyntax → R8 PerKindActiveFields
//!   → R9 PerKindFieldScope → R18 HttpAuth → R19 HttpTenantSource → R23 HttpProjectionCoverage → R10 SagaBlock
//!   → R11 ActiveDeliverySupported → R13 SchemaTitle → R16 SchemaRedaction → R17 SchemaProtection
//!   → R14 ActiveSubscriber → R20 SlugSyntax
//!   跨契约（validate_cross，需全局视图）：R12 DuplicateId → R21 SlugMixing → R22 ConsistencyCapability

use anyhow::{Context as _, Result};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use syn::visit::Visit;

use super::manifest::{
    Capabilities, ConsistencyLevel, ContractKind, ContractManifest, ContractOwner, Delivery,
    FIELD_COMMAND, FIELD_DELIVERY, FIELD_EFFECT_PROFILE, FIELD_ENDPOINTS_HTTP_AUTH,
    FIELD_ENDPOINTS_HTTP_HEADERS, FIELD_ENDPOINTS_HTTP_PROJECTION,
    FIELD_ENDPOINTS_HTTP_RESOURCE_SHARING, FIELD_METHOD, FIELD_PATH, FIELD_RECONCILE, FIELD_SAGA,
    FIELD_SUBSCRIPTIONS, FIELD_TOPIC, HttpAuth, HttpAuthMode, HttpEndpoint, HttpHeaderMode,
    HttpMethod, HttpResourceSharingMode, Lifecycle, LocalTxBoundary, LocalTxCommitUnknown,
    LocalTxModel, LocalTxRetry, OutboxAtomicity, OutboxRole, SCHEMA_KEY_PAYLOAD,
    SCHEMA_KEY_REQUEST, SCHEMA_KEY_RESPONSE, WorkflowMode, WorkflowOrdering, WorkflowRequirement,
};
use super::protection;
use super::redaction;
use super::{DiscoveredContract, discover, schema_declares_property};
use crate::diagnostic::{self, GovernanceCheck, finding};
use crate::pathsafe;

pub(crate) type Finding = diagnostic::Finding<Rule>;

const CAP_LOCAL_TX: &str = "capabilities.localTx";
const CAP_OUTBOX: &str = "capabilities.outbox";
const CAP_WORKFLOW: &str = "capabilities.workflow";
const CAP_DEVICE_LATENT: &str = "capabilities.deviceLatent";

const CAP_OUTBOX_ROLE_FACT: &str = "capabilities.outbox.role=fact";
const CAP_OUTBOX_ROLE_COMMAND: &str = "capabilities.outbox.role=command";
const CAP_OUTBOX_ROLE_PRODUCER: &str = "capabilities.outbox.role=producer";
const CAP_OUTBOX_ATOMICITY: &str = "capabilities.outbox.atomicity";
const CAP_OUTBOX_EMITS: &str = "capabilities.outbox.emits";
const CAP_OUTBOX_EMITS_ACTIVE: &str = "capabilities.outbox.emits.active";
const CAP_OUTBOX_FIELD_SCOPE: &str = "capabilities.outbox.field-scope";
const CAP_RUNTIME_RELAY_DOMAIN: &str = "runtime.relay.domain";
const CAP_RUNTIME_RELAY_WIRING: &str = "runtime.relay.wiring";
const CAP_WORKFLOW_MODE_SAGA: &str = "capabilities.workflow.mode=saga";
const CAP_WORKFLOW_INPUTS: &str = "capabilities.workflow.inputs";
const CAP_WORKFLOW_ORDERING: &str = "capabilities.workflow.ordering";
const CAP_WORKFLOW_CHECKPOINT: &str = "capabilities.workflow.checkpoint";
const CAP_WORKFLOW_REPLAY: &str = "capabilities.workflow.replay";
const CAP_WORKFLOW_FIELD_SCOPE: &str = "capabilities.workflow.field-scope";
const CAP_CAPABILITY_SCOPE: &str = "capability-scope";
const CAP_EFFECT_PROFILE_EFFECTS: &str = "effectProfile.effects";
const RUNTIME_EVENT_TRANSPORT_RS: &str = "assemblies/runtime/src/event_transport.rs";

/// 被违反的规则（供测试精确断言）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Rule {
    /// R1：`kind = saga` ⇒ `consistencyLevel = WorkflowEventual`。
    SagaConsistency,
    /// R2：`owner = _framework` ⇒ `kind ∈ {http, event, command}`。
    FrameworkKind,
    /// R3：磁盘段 `{kind}/{domain}/{version}` 须等于 manifest 字段。
    PathMismatch,
    /// R4：kind→schema 形态须一致（http 需 request+response、event/saga 需 payload、command 需 request）。
    SchemaShape,
    /// R5：声明的每个 schema 文件须存在于契约目录。
    MissingSchema,
    /// R6：schema 文件名须为纯文件名，不得含路径分量（防 `../` 逃逸）。
    UnsafeSchemaPath,
    /// R7：authoring 标识符（domain/version/id/owner）+ per-kind 字符串字段（http `path` / event `topic` /
    /// event `[[subscriptions]]` 的 consumer/group）语法须先收口（拼进派生路径 / module 名 / 鉴权挂载点 /
    /// wire routing key / generated 注册 glue 字符串字面量 前）。
    IdentSyntax,
    /// R8：`lifecycle=active` ⇒ 按 kind 必填 active 发布接线字段（http path+method / event topic+delivery）。
    PerKindActiveFields,
    /// R9：per-kind 字段只允许出现在匹配 kind（错配 silently-ignored，须拒）。
    PerKindFieldScope,
    /// R10：`kind=saga` ⇒ 须有非空 `[saga]` block（无条件）+ block 内部良构（≥1 step、step name 合法
    /// 唯一、outputSchema 非空）。
    SagaBlock,
    /// R11：`lifecycle=active` 的 event 只能声明当前可兑现的投递语义（仅 `at-least-once`）；
    /// `at-most-once`/`exactly-once` 当前 broker 链路无运行时保证，能力落地前限 draft/deprecated。
    ActiveDeliverySupported,
    /// R12：contract `id` 须跨**全部**契约全局唯一（跨契约规则，在 [`validate_cross`]，非逐契约）。
    /// id 是契约注册标识（事件 routing / 鉴权挂载 / registry）；api-versioning.md 要求破坏式 wire 变更
    /// 新建版本目录 **且** 新 contract ID ⇒ id 全局唯一。
    DuplicateId,
    /// R13：每个 declared schema（喂 codegen TypeSpace 的 request/response/payload）的 `title`
    /// 须 PascalCase（`^[A-Z][A-Za-z0-9]*$`）且**契约内**唯一（title→typify 生成的 Rust 类型名）。
    SchemaTitle,
    /// R14：`lifecycle=active && kind=event` 的契约必须至少有一个 `[[subscriptions]]` 声明。
    ///
    /// INVARIANT: EVENT-ACTIVE-SUB-01 { level = "Medium", exec = "verify", source = "code", synthetic_red = "tests::r14_active_event_empty_subscriptions_rejected", anti_vacuity = "tests::r14_active_event_with_subscription_ok" }— active event 契约无 subscriber 即"死事件"（发出无消费），
    /// 视为错误配置（Medium，CI 门）。draft/deprecated 豁免（种子 / 前瞻 / 退役契约不受约束）。
    /// synthetic red：active event + 空 subscriptions → Finding；
    /// anti-vacuity：① active event + ≥1 subscription → 通过；② draft event + 空 subscriptions → 通过。
    ActiveSubscriber,
    /// R15：`kind = command` ⇒ `consistencyLevel = OutboxFact`（无条件，同 R1 saga）。
    ///
    /// command 分发 = 本地事务 + outbox 发布（L2 OutboxFact 语义，`docs/rules/eventbus.md` §command
    /// dispatch）：经 outbox relay 投递、consumer 侧 claimer 两阶段去重。consistencyLevel 是 kind 内蕴
    /// wire 语义（与 lifecycle 无关），R8 此前只校验 active command 的 `topic`、未机器锁一致性等级（#1124
    /// review F6）；本规则补足，防 command 契约误标 L0/L1/L3/L4 致 outbox 接线语义漂移。
    CommandConsistency,
    /// R24：command 必须显式声明 `[command]`，非 command 禁止声明。
    CommandPolicy,
    /// R16：schema property 的 `x-pii` / `x-redaction` 字段级策略须合法且完整。
    ///
    /// INVARIANT: CONTRACT-REDACTION-POLICY-01 { level = "Medium", exec = "verify", source = "code" }— generated wire DTO 的安全 `Debug` 从 contract JSON
    /// Schema 单源派生。遗留 `x-sensitive`、未知枚举、hash redaction、以及高风险字段未声明策略均拒绝。
    SchemaRedaction,
    /// R17：schema property 的 `x-protection`（at-rest storage 加密声明）+ schema 级 `x-at-rest`
    /// opt-in 须合法且完整。
    ///
    /// INVARIANT: CONTRACT-PROTECTION-POLICY-01 { level = "Medium", exec = "verify", source = "code" }— at-rest 加密声明面单源（#1468，ADR-011 D1b 声明层）。
    /// `x-protection` block 内部一致（atRest:encrypt 须 keyScope+完整 aad；deterministic/blindIndex 须
    /// reason 且 aad 稳定子集排除 schemaVersion；plain 不携带 encrypt 参数），`x-at-rest:true` 的 schema
    /// 内高风险字段缺 `x-protection` 均拒绝；encrypt 字段不得 nullable，blindIndex 仅支持非 nullable scalar。
    /// 与 R16（observe redaction）正交不混用。
    SchemaProtection,
    /// R18：active HTTP serving 必须声明 fail-closed auth/header metadata。
    ///
    /// `mode=permission` 需要 permission 且禁止 reason；public/bootstrap/clientsOnly/serviceOwned 需要
    /// non-empty reason 且禁止 permission。当前最小 header 面只接受 `X-Tenant-ID` 的闭值模式，
    /// identity.login public serving 必须声明该 header。
    HttpAuth,
    /// R19：HTTP request schema 不得声明 tenantId；tenant scope 必须来自认证上下文、声明式
    /// populate-only header 或 service-token MAC 绑定 header，target tenant 则来自显式 path 参数。
    HttpTenantSource,
    /// R23：active GET response 中的 `x-pii` 字段与 `tenantId` 字段必须由 projection responsePath 精确覆盖。
    HttpProjectionCoverage,
    /// R20：嵌套形态（`{kind}/{domain}/{version}/{slug}/`）的 slug 段语法须收口——slug 经 kebab→snake 拼进
    /// generated `pub mod <slug_ident>`（见 codegen），须为合法 Rust 模块标识符前体（首 `a-z`、余 `[a-z0-9_-]`、
    /// 无首尾 `-`），杜绝坏值流入生成子模块名 / 路径。与 codegen 写盘前防逃逸守卫互为表里。
    ///
    /// INVARIANT: CONTRACT-SLUG-SYNTAX-01 { level = "Medium", exec = "verify", source = "code" }— 嵌套端点 slug 须为合法 module ident 前体（Medium，CI 门；authoring
    /// 上游闸门）；下游 codegen `slug_module_ident` 经 `syn::Ident` 自守（Hard），二者互为闭环 funnel。
    SlugSyntax,
    /// R21：同一 `{kind}/{domain}/{version}` 下扁平（直接 `contract.toml`，单契约）与嵌套（`<slug>/contract.toml`，
    /// 多契约）形态**不可混用**——混用使 generated `{domain}_{version}.rs` 既要裸常量又要子模块、语义二义。
    ///
    /// INVARIANT: CONTRACT-NEST-EXCLUSIVE-01 { level = "Medium", exec = "verify", source = "code" }— 一个 `{domain}/{version}` 模块要么全扁平（恰一契约）、要么全嵌套
    /// （≥1 子契约），不得既含直接 `contract.toml` 又含子目录契约（Medium，CI 门）。跨契约规则（需 group 视图）。
    SlugMixing,
    /// R22：`consistencyLevel` 须匹配 typed `[capabilities.*]` 证据；HTTP L2 producer 的 emits 引用须存在且为 L2 event；
    /// L4 DeviceLatent 须声明 `[reconcile]` block。
    ///
    /// INVARIANT: CONTRACT-CONSISTENCY-CAPABILITY-01 { level = "Medium", exec = "verify", source = "code" }— 一致性等级不能只停留在字符串枚举；
    /// 必须有闭值 typed 能力证据，禁止跨等级 stray capability，防 L2/L3/L4 语义虚开。
    ConsistencyCapability,
}

/// `cargo xtask contract validate` 校验器（issue #1058：经 [`GovernanceCheck`] 统一编排）。
pub(crate) struct ContractValidate;

impl GovernanceCheck for ContractValidate {
    type Rule = Rule;
    fn name(&self) -> &'static str {
        "contract validate"
    }
    fn check(&self) -> Result<(String, Vec<Finding>)> {
        let root = crate::workspace_root()?;
        let (count, findings) = validate_workspace(&root)?;
        Ok((format!("{count} 契约全部通过"), findings))
    }
}

fn validate_workspace(root: &Path) -> Result<(usize, Vec<Finding>)> {
    let contracts_root = root.join("contracts");
    let contracts = discover(&contracts_root)?;
    let runtime_relay = read_runtime_relay_wiring(root)?;
    let mut findings = validate_discovered_contracts(&contracts);
    findings.extend(rule_runtime_relay_coverage(&contracts, &runtime_relay));
    Ok((contracts.len(), findings))
}

/// 校验给定根下全部契约，返回（契约数, findings）。根可注入便于测试。
#[cfg(test)]
pub(crate) fn validate_root(contracts_root: &Path) -> Result<(usize, Vec<Finding>)> {
    let contracts = discover(contracts_root)?;
    let findings = validate_discovered_contracts(&contracts);
    Ok((contracts.len(), findings))
}

fn validate_discovered_contracts(contracts: &[DiscoveredContract]) -> Vec<Finding> {
    let mut findings = Vec::new();
    for c in contracts {
        findings.extend(validate_contract(c));
    }
    findings.extend(validate_cross(contracts));
    findings
}

/// 跨契约规则聚合点：需要**全局视图**（看到所有契约才能判定），无法在逐契约的 [`validate_contract`]
/// 内表达。现含 R12 DuplicateId、R21 SlugMixing、R22 ConsistencyCapability；后续跨契约不变式在此追加。
fn validate_cross(contracts: &[DiscoveredContract]) -> Vec<Finding> {
    let mut out = rule_duplicate_id(contracts);
    out.extend(rule_slug_mixing(contracts));
    out.extend(rule_consistency_capability(contracts));
    out
}

fn read_runtime_relay_wiring(root: &Path) -> Result<RuntimeRelayWiring> {
    let path = root.join(RUNTIME_EVENT_TRANSPORT_RS);
    let content = std::fs::read_to_string(&path)
        .with_context(|| format!("读取 runtime event transport 接线 {}", path.display()))?;
    parse_runtime_relay_wiring(&content)
        .with_context(|| format!("解析 runtime event transport 接线 {}", path.display()))
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct RuntimeRelayWiring {
    uses_generated_registry: bool,
    has_complete_generated_loop: bool,
}

fn parse_runtime_relay_wiring(content: &str) -> Result<RuntimeRelayWiring> {
    let file = syn::parse_file(content)?;
    let mut visitor = RuntimeRelayVisitor::default();
    visitor.visit_file(&file);
    Ok(visitor.wiring)
}

#[derive(Default)]
struct RuntimeRelayVisitor {
    wiring: RuntimeRelayWiring,
}

impl<'ast> Visit<'ast> for RuntimeRelayVisitor {
    fn visit_expr_for_loop(&mut self, node: &'ast syn::ExprForLoop) {
        let syn::Pat::Ident(producer) = &*node.pat else {
            syn::visit::visit_expr_for_loop(self, node);
            return;
        };
        if expr_references_generated_producer_domains(&node.expr) {
            self.wiring.uses_generated_registry = true;
            let mut evidence = RelayLoopEvidence::new(producer.ident.to_string());
            evidence.visit_block(&node.body);
            self.wiring.has_complete_generated_loop |=
                evidence.wires_generated_domain && evidence.exhaustively_maps_producer;
        }
        syn::visit::visit_expr_for_loop(self, node);
    }
}

fn expr_references_generated_producer_domains(expr: &syn::Expr) -> bool {
    #[derive(Default)]
    struct ExactPathVisitor(bool);

    impl<'ast> Visit<'ast> for ExactPathVisitor {
        fn visit_expr_path(&mut self, node: &'ast syn::ExprPath) {
            let segments = node
                .path
                .segments
                .iter()
                .map(|segment| segment.ident.to_string())
                .collect::<Vec<_>>();
            self.0 |= segments == ["generated", "event", "PRODUCER_DOMAINS"];
            syn::visit::visit_expr_path(self, node);
        }
    }

    let mut visitor = ExactPathVisitor::default();
    visitor.visit_expr(expr);
    visitor.0
}

struct RelayLoopEvidence {
    producer: String,
    domain_aliases: BTreeSet<String>,
    wires_generated_domain: bool,
    exhaustively_maps_producer: bool,
}

impl RelayLoopEvidence {
    fn new(producer: String) -> Self {
        Self {
            producer,
            domain_aliases: BTreeSet::new(),
            wires_generated_domain: false,
            exhaustively_maps_producer: false,
        }
    }

    fn is_domain_expr(&self, expr: &syn::Expr) -> bool {
        expr_path_ident(expr).is_some_and(|ident| self.domain_aliases.contains(&ident))
            || expr_method_on_ident(expr, "as_str", &self.producer)
    }
}

impl<'ast> Visit<'ast> for RelayLoopEvidence {
    fn visit_local(&mut self, node: &'ast syn::Local) {
        if let syn::Pat::Ident(alias) = &node.pat
            && node
                .init
                .as_ref()
                .is_some_and(|init| expr_method_on_ident(&init.expr, "as_str", &self.producer))
        {
            self.domain_aliases.insert(alias.ident.to_string());
        }
        syn::visit::visit_local(self, node);
    }

    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        if expr_call_is_ident(&node.func, "wire_domain_relay")
            && let Some(first) = node.args.first()
            && self.is_domain_expr(first)
        {
            self.wires_generated_domain = true;
        }
        syn::visit::visit_expr_call(self, node);
    }

    fn visit_expr_match(&mut self, node: &'ast syn::ExprMatch) {
        if expr_path_is_ident(&node.expr, &self.producer)
            && !node.arms.is_empty()
            && node
                .arms
                .iter()
                .all(|arm| !matches!(arm.pat, syn::Pat::Wild(_)))
        {
            self.exhaustively_maps_producer = true;
        }
        syn::visit::visit_expr_match(self, node);
    }

    fn visit_expr_for_loop(&mut self, _node: &'ast syn::ExprForLoop) {
        // Evidence from a nested loop must not satisfy the enclosing generated-registry loop.
    }
}

fn expr_path_ident(expr: &syn::Expr) -> Option<String> {
    match expr {
        syn::Expr::Path(path) if path.path.segments.len() == 1 => path
            .path
            .segments
            .first()
            .map(|segment| segment.ident.to_string()),
        syn::Expr::Group(group) => expr_path_ident(&group.expr),
        syn::Expr::Paren(paren) => expr_path_ident(&paren.expr),
        _ => None,
    }
}

fn expr_method_on_ident(expr: &syn::Expr, method: &str, receiver: &str) -> bool {
    match expr {
        syn::Expr::MethodCall(call) => {
            call.method == method && expr_path_is_ident(&call.receiver, receiver)
        }
        syn::Expr::Group(group) => expr_method_on_ident(&group.expr, method, receiver),
        syn::Expr::Paren(paren) => expr_method_on_ident(&paren.expr, method, receiver),
        _ => false,
    }
}

fn expr_path_is_ident(expr: &syn::Expr, ident: &str) -> bool {
    match expr {
        syn::Expr::Path(path) => path
            .path
            .segments
            .last()
            .is_some_and(|segment| segment.ident == ident),
        syn::Expr::Group(group) => expr_path_is_ident(&group.expr, ident),
        syn::Expr::Paren(paren) => expr_path_is_ident(&paren.expr, ident),
        _ => false,
    }
}

fn expr_call_is_ident(expr: &syn::Expr, ident: &str) -> bool {
    match expr {
        syn::Expr::Path(path) => path
            .path
            .segments
            .last()
            .is_some_and(|segment| segment.ident == ident),
        syn::Expr::Group(group) => expr_call_is_ident(&group.expr, ident),
        syn::Expr::Paren(paren) => expr_call_is_ident(&paren.expr, ident),
        _ => false,
    }
}

fn rule_runtime_relay_coverage(
    contracts: &[DiscoveredContract],
    runtime: &RuntimeRelayWiring,
) -> Vec<Finding> {
    let by_id: BTreeMap<&str, &DiscoveredContract> = contracts
        .iter()
        .map(|contract| (contract.manifest.id.as_str(), contract))
        .collect();
    let mut out = Vec::new();
    for producer in contracts {
        let manifest = &producer.manifest;
        if manifest.kind != ContractKind::Http
            || manifest.lifecycle != Lifecycle::Active
            || manifest.consistency_level != ConsistencyLevel::OutboxFact
        {
            continue;
        }
        let Some(outbox) = &manifest.capabilities.outbox else {
            continue;
        };
        if outbox.role != OutboxRole::Producer {
            continue;
        }
        let label = contract_label(producer);
        for emitted_id in &outbox.emits {
            let Some(target) = by_id.get(emitted_id.as_str()) else {
                continue;
            };
            if !active_outbox_event_ready(target) {
                continue;
            }
            let domain = target.manifest.domain.as_str();
            if !runtime.uses_generated_registry {
                out.push(finding(
                    Rule::ConsistencyCapability,
                    label.clone(),
                    format!(
                        "contract id={} missing capability={CAP_RUNTIME_RELAY_DOMAIN} missing capability ref={emitted_id}；active HTTP OutboxFact producer 发出的 active event domain={domain} 必须由 {RUNTIME_EVENT_TRANSPORT_RS} 迭代 generated::event::PRODUCER_DOMAINS",
                        manifest.id
                    ),
                ));
            }
            if !runtime.has_complete_generated_loop {
                out.push(finding(
                    Rule::ConsistencyCapability,
                    label.clone(),
                    format!(
                        "contract id={} missing capability={CAP_RUNTIME_RELAY_WIRING} missing capability ref={emitted_id}；active HTTP OutboxFact producer 发出的 active event domain={domain} 必须经 PRODUCER_DOMAINS 循环调用 wire_domain_relay，并以无 wildcard 的 ProducerDomain match 穷举 provider capability",
                        manifest.id
                    ),
                ));
            }
        }
    }
    out
}

fn active_outbox_event_ready(contract: &DiscoveredContract) -> bool {
    let manifest = &contract.manifest;
    manifest.kind == ContractKind::Event
        && manifest.lifecycle == Lifecycle::Active
        && manifest.consistency_level == ConsistencyLevel::OutboxFact
        && !manifest.subscriptions.is_empty()
}

/// R22：consistencyLevel capability gate。跨契约原因：HTTP L2 producer 的 `emits` 必须引用存在的
/// `kind=event && consistencyLevel=OutboxFact` contract id。
fn rule_consistency_capability(contracts: &[DiscoveredContract]) -> Vec<Finding> {
    let by_id: BTreeMap<&str, &DiscoveredContract> = contracts
        .iter()
        .map(|contract| (contract.manifest.id.as_str(), contract))
        .collect();
    let mut out = Vec::new();
    for contract in contracts {
        let label = contract_label(contract);
        out.extend(rule_consistency_capability_one(contract, &label, &by_id));
    }
    out
}

fn rule_consistency_capability_one(
    c: &DiscoveredContract,
    label: &str,
    by_id: &BTreeMap<&str, &DiscoveredContract>,
) -> Vec<Finding> {
    let m = &c.manifest;
    let mut out = Vec::new();
    out.extend(rule_effect_profile(m, label));
    match m.consistency_level {
        ConsistencyLevel::LocalOnly => {
            if m.kind != ContractKind::Http {
                out.push(consistency_capability_finding(
                    m,
                    label,
                    "local-only-http",
                    "LocalOnly 当前只允许 kind=http 契约声明本地纯能力",
                ));
            }
            out.extend(unexpected_capabilities(m, label, &[]));
        }
        ConsistencyLevel::LocalTx => {
            if m.kind != ContractKind::Http {
                out.push(consistency_capability_finding(
                    m,
                    label,
                    CAP_LOCAL_TX,
                    "LocalTx 须由 kind=http + [capabilities.localTx] 证明",
                ));
            }
            match &m.capabilities.local_tx {
                Some(local_tx)
                    if local_tx.boundary == LocalTxBoundary::SingleDomain
                        && local_tx.tx_model == LocalTxModel::TenantScopedUow
                        && local_tx.retry == LocalTxRetry::BoundedTransient
                        && local_tx.commit_unknown == LocalTxCommitUnknown::NotRetryable => {}
                _ => out.push(consistency_capability_finding(
                    m,
                    label,
                    CAP_LOCAL_TX,
                    "LocalTx 须声明 boundary=\"single-domain\" + txModel=\"tenant-scoped-uow\" + retry=\"bounded-transient\" + commitUnknown=\"not-retryable\"",
                )),
            }
            out.extend(unexpected_capabilities(m, label, &[CAP_LOCAL_TX]));
        }
        ConsistencyLevel::OutboxFact => {
            out.extend(rule_outbox_capability(c, label, by_id));
            out.extend(unexpected_capabilities(m, label, &[CAP_OUTBOX]));
        }
        ConsistencyLevel::WorkflowEventual => {
            out.extend(rule_workflow_capability(c, label, by_id));
            out.extend(unexpected_capabilities(m, label, &[CAP_WORKFLOW]));
        }
        ConsistencyLevel::DeviceLatent => {
            out.extend(rule_device_latent_capability(c, label));
            out.extend(unexpected_capabilities(m, label, &[CAP_DEVICE_LATENT]));
        }
    }
    if m.consistency_level != ConsistencyLevel::DeviceLatent && m.reconcile.is_some() {
        out.push(consistency_capability_finding(
            m,
            label,
            CAP_CAPABILITY_SCOPE,
            "[reconcile] 仅允许用于 consistencyLevel=DeviceLatent",
        ));
    }
    out
}

fn rule_effect_profile(m: &ContractManifest, label: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    let Some(profile) = &m.effect_profile else {
        if m.kind == ContractKind::Http {
            out.push(consistency_capability_finding(
                m,
                label,
                FIELD_EFFECT_PROFILE,
                "kind=http 契约必须声明 [effectProfile] effects 作为 L0/L1 共享 effect carrier",
            ));
        }
        return out;
    };
    if m.kind != ContractKind::Http {
        out.push(consistency_capability_finding(
            m,
            label,
            FIELD_EFFECT_PROFILE,
            "[effectProfile] 仅允许用于 kind=http 契约",
        ));
    }
    if profile.effects.is_empty() {
        out.push(consistency_capability_finding(
            m,
            label,
            CAP_EFFECT_PROFILE_EFFECTS,
            "[effectProfile].effects 必须至少声明一个 effect",
        ));
    }
    let mut seen = BTreeSet::new();
    for effect in &profile.effects {
        if !seen.insert(*effect) {
            out.push(consistency_capability_finding(
                m,
                label,
                CAP_EFFECT_PROFILE_EFFECTS,
                &format!("[effectProfile].effects 不得重复声明 effect={effect:?}"),
            ));
        }
    }
    out
}

fn rule_outbox_capability(
    c: &DiscoveredContract,
    label: &str,
    by_id: &BTreeMap<&str, &DiscoveredContract>,
) -> Vec<Finding> {
    let m = &c.manifest;
    let mut out = Vec::new();
    let Some(outbox) = &m.capabilities.outbox else {
        return vec![consistency_capability_finding(
            m,
            label,
            CAP_OUTBOX,
            "OutboxFact 须声明 [capabilities.outbox]",
        )];
    };
    match m.kind {
        ContractKind::Event => {
            if outbox.role != OutboxRole::Fact {
                out.push(consistency_capability_finding(
                    m,
                    label,
                    CAP_OUTBOX_ROLE_FACT,
                    "kind=event 的 OutboxFact 须声明 outbox fact role",
                ));
            }
            out.extend(unexpected_outbox_payload_fields(
                m,
                label,
                outbox.atomicity.is_some(),
                !outbox.emits.is_empty(),
                "event fact",
            ));
        }
        ContractKind::Command => {
            if outbox.role != OutboxRole::Command {
                out.push(consistency_capability_finding(
                    m,
                    label,
                    CAP_OUTBOX_ROLE_COMMAND,
                    "kind=command 的 OutboxFact 须声明 command role",
                ));
            }
            out.extend(unexpected_outbox_payload_fields(
                m,
                label,
                outbox.atomicity.is_some(),
                !outbox.emits.is_empty(),
                "command",
            ));
        }
        ContractKind::Http => {
            if outbox.role != OutboxRole::Producer {
                out.push(consistency_capability_finding(
                    m,
                    label,
                    CAP_OUTBOX_ROLE_PRODUCER,
                    "kind=http 的 OutboxFact 须声明 producer role",
                ));
            }
            if outbox.atomicity != Some(OutboxAtomicity::SameTransaction) {
                out.push(consistency_capability_finding(
                    m,
                    label,
                    CAP_OUTBOX_ATOMICITY,
                    "HTTP OutboxFact producer 须声明 atomicity=\"same-transaction\"",
                ));
            }
            if outbox.emits.is_empty() {
                out.push(consistency_capability_finding(
                    m,
                    label,
                    CAP_OUTBOX_EMITS,
                    "HTTP OutboxFact producer 须声明至少一个 emitted event contract id",
                ));
            }
            for emitted_id in &outbox.emits {
                match by_id.get(emitted_id.as_str()) {
                    Some(target)
                        if target.manifest.kind == ContractKind::Event
                            && target.manifest.consistency_level == ConsistencyLevel::OutboxFact =>
                    {
                        if m.lifecycle == Lifecycle::Active
                            && (target.manifest.lifecycle != Lifecycle::Active
                                || target.manifest.subscriptions.is_empty())
                        {
                            out.push(finding(
                                Rule::ConsistencyCapability,
                                label,
                                format!(
                                    "contract id={} missing capability={CAP_OUTBOX_EMITS_ACTIVE} missing capability ref={emitted_id}；active HTTP OutboxFact producer 的 [capabilities.outbox].emits 必须引用 active 且声明 [[subscriptions]] readiness 的 L2 event contract",
                                    m.id
                                ),
                            ));
                        }
                    }
                    _ => out.push(finding(
                        Rule::ConsistencyCapability,
                        label,
                        format!(
                            "contract id={} missing capability ref={emitted_id}；[capabilities.outbox].emits 必须引用存在的 kind=event 且 consistencyLevel=OutboxFact 的 contract id",
                            m.id
                        ),
                    )),
                }
            }
        }
        ContractKind::Saga => out.push(consistency_capability_finding(
            m,
            label,
            "outbox-compatible-kind",
            "OutboxFact 不允许 kind=saga；saga workflow 须使用 consistencyLevel=WorkflowEventual",
        )),
    }
    out
}

fn rule_workflow_capability(
    c: &DiscoveredContract,
    label: &str,
    by_id: &BTreeMap<&str, &DiscoveredContract>,
) -> Vec<Finding> {
    let m = &c.manifest;
    let mut out = Vec::new();
    let Some(workflow) = &m.capabilities.workflow else {
        return vec![consistency_capability_finding(
            m,
            label,
            CAP_WORKFLOW,
            "WorkflowEventual 须声明 [capabilities.workflow]",
        )];
    };
    match workflow.mode {
        WorkflowMode::Saga => {
            if m.kind != ContractKind::Saga || m.saga.is_none() {
                out.push(consistency_capability_finding(
                    m,
                    label,
                    CAP_WORKFLOW_MODE_SAGA,
                    "saga workflow 须由 kind=saga + [saga] block 共同证明",
                ));
            }
            if !workflow.inputs.is_empty()
                || workflow.ordering.is_some()
                || workflow.checkpoint.is_some()
                || workflow.replay.is_some()
            {
                out.push(consistency_capability_finding(
                    m,
                    label,
                    CAP_WORKFLOW_FIELD_SCOPE,
                    "saga workflow 不得携带 projection-only inputs/ordering/checkpoint/replay 字段",
                ));
            }
        }
        WorkflowMode::Projection => {
            if workflow.inputs.is_empty() {
                out.push(consistency_capability_finding(
                    m,
                    label,
                    CAP_WORKFLOW_INPUTS,
                    "projection workflow 须声明至少一个 input contract id",
                ));
            }
            for input_id in &workflow.inputs {
                match by_id.get(input_id.as_str()) {
                    Some(target)
                        if target.manifest.kind == ContractKind::Event
                            && target.manifest.consistency_level == ConsistencyLevel::OutboxFact => {}
                    _ => out.push(finding(
                        Rule::ConsistencyCapability,
                        label,
                        format!(
                            "contract id={} missing capability ref={input_id}；[capabilities.workflow].inputs 必须引用存在的 kind=event 且 consistencyLevel=OutboxFact 的 contract id",
                            m.id
                        ),
                    )),
                }
            }
            if workflow.ordering != Some(WorkflowOrdering::SerialInOrder) {
                out.push(consistency_capability_finding(
                    m,
                    label,
                    CAP_WORKFLOW_ORDERING,
                    "projection workflow 须声明 ordering=\"serial-in-order\"",
                ));
            }
            if workflow.checkpoint != Some(WorkflowRequirement::Required) {
                out.push(consistency_capability_finding(
                    m,
                    label,
                    CAP_WORKFLOW_CHECKPOINT,
                    "projection workflow 须声明 checkpoint=\"required\"",
                ));
            }
            if workflow.replay != Some(WorkflowRequirement::Required) {
                out.push(consistency_capability_finding(
                    m,
                    label,
                    CAP_WORKFLOW_REPLAY,
                    "projection workflow 须声明 replay=\"required\"",
                ));
            }
        }
    }
    out
}

fn rule_device_latent_capability(c: &DiscoveredContract, label: &str) -> Vec<Finding> {
    let m = &c.manifest;
    let mut out = Vec::new();
    if m.kind != ContractKind::Http {
        out.push(consistency_capability_finding(
            m,
            label,
            CAP_DEVICE_LATENT,
            "DeviceLatent 当前须由 kind=http + [capabilities.deviceLatent] 声明设备长延迟收敛入口",
        ));
    }
    if m.capabilities.device_latent.is_none() {
        out.push(consistency_capability_finding(
            m,
            label,
            CAP_DEVICE_LATENT,
            "DeviceLatent 须声明 [capabilities.deviceLatent] 且 loop=\"reconcile\"",
        ));
    }
    if m.reconcile.is_none() {
        out.push(consistency_capability_finding(
            m,
            label,
            FIELD_RECONCILE,
            "DeviceLatent 须声明 [reconcile] tenancy/trigger/fencing/lateMessagePolicy",
        ));
    }
    out
}

fn unexpected_capabilities(
    m: &ContractManifest,
    label: &str,
    allowed: &[&'static str],
) -> Vec<Finding> {
    present_capabilities(&m.capabilities)
        .into_iter()
        .filter(|(name, _)| !allowed.contains(name))
        .map(|(name, _)| {
            consistency_capability_finding(
                m,
                label,
                CAP_CAPABILITY_SCOPE,
                &format!(
                    "unexpected capability={name} 不允许用于 consistencyLevel={:?}",
                    m.consistency_level
                ),
            )
        })
        .collect()
}

fn present_capabilities(caps: &Capabilities) -> Vec<(&'static str, bool)> {
    [
        (CAP_LOCAL_TX, caps.local_tx.is_some()),
        (CAP_OUTBOX, caps.outbox.is_some()),
        (CAP_WORKFLOW, caps.workflow.is_some()),
        (CAP_DEVICE_LATENT, caps.device_latent.is_some()),
    ]
    .into_iter()
    .filter(|(_, present)| *present)
    .collect()
}

fn unexpected_outbox_payload_fields(
    m: &ContractManifest,
    label: &str,
    has_atomicity: bool,
    has_emits: bool,
    role_label: &str,
) -> Vec<Finding> {
    let mut out = Vec::new();
    if has_atomicity {
        out.push(consistency_capability_finding(
            m,
            label,
            CAP_OUTBOX_FIELD_SCOPE,
            &format!("{role_label} outbox capability 不得声明 producer-only atomicity 字段"),
        ));
    }
    if has_emits {
        out.push(consistency_capability_finding(
            m,
            label,
            CAP_OUTBOX_FIELD_SCOPE,
            &format!("{role_label} outbox capability 不得声明 producer-only emits 字段"),
        ));
    }
    out
}

fn consistency_capability_finding(
    m: &ContractManifest,
    label: &str,
    missing: &str,
    detail: &str,
) -> Finding {
    finding(
        Rule::ConsistencyCapability,
        label,
        format!(
            "contract id={} missing capability={missing}；{detail}",
            m.id
        ),
    )
}

/// R21：同 `{kind}/{domain}/{version}` 下扁平 / 嵌套形态不可混用（INVARIANT: CONTRACT-NEST-EXCLUSIVE-01 { level = "Medium", exec = "verify", source = "code" }）。
/// 按三段 group；某 group 同时含扁平契约（`slug=None`）与嵌套契约（`slug=Some`）即报（同根因 1 条）。
/// synthetic red：version 目录直放 `contract.toml` 又含 `<slug>/contract.toml` → Finding；
/// anti-vacuity：纯扁平（1×None）/ 纯嵌套（N×Some）group 均通过（见 `r21_*` 测试）。
fn rule_slug_mixing(contracts: &[DiscoveredContract]) -> Vec<Finding> {
    let mut by_group: BTreeMap<String, (bool, bool)> = BTreeMap::new();
    for c in contracts {
        let key = format!("{}/{}/{}", c.path_kind, c.path_domain, c.path_version);
        let entry = by_group.entry(key).or_insert((false, false));
        match c.slug {
            None => entry.0 = true,    // 含扁平
            Some(_) => entry.1 = true, // 含嵌套
        }
    }
    by_group
        .into_iter()
        .filter(|(_, (flat, nested))| *flat && *nested)
        .map(|(label, _)| {
            finding(
                Rule::SlugMixing,
                &label,
                "同 {kind}/{domain}/{version} 既含直接 contract.toml（扁平）又含 <slug>/contract.toml（嵌套）；\
                 二选一：单契约用扁平、多契约全部移入各自 <slug>/ 子目录"
                    .to_string(),
            )
        })
        .collect()
}

/// R12：contract `id` 须跨全部契约全局唯一（INVARIANT: CONTRACT-IDUNIQ-01 { level = "Medium", exec = "verify", source = "code" }）。同根因（同一重复 id）
/// 只报 1 条（subject = 该 id），detail 列全部冲突契约 label（排序，跨机确定性）。
fn rule_duplicate_id(contracts: &[DiscoveredContract]) -> Vec<Finding> {
    let mut by_id: BTreeMap<&str, Vec<String>> = BTreeMap::new();
    for c in contracts {
        let label = contract_label(c);
        by_id.entry(c.manifest.id.as_str()).or_default().push(label);
    }
    by_id
        .into_iter()
        .filter(|(_, labels)| labels.len() > 1)
        .map(|(id, mut labels)| {
            labels.sort();
            finding(
                Rule::DuplicateId,
                id,
                format!("contract id 跨契约重复，出现于: {}", labels.join("、")),
            )
        })
        .collect()
}

/// 契约诊断 label：相对 `{kind}/{domain}/{version}`，**嵌套契约附 `/{slug}` 段**（机器稳定、跨机一致；
/// 嵌套 sibling 出错时精确定位到端点子目录，不退化为三段歧义）。注：R21 mixing 的 group **键**仍用三段
/// （按 `{domain}/{version}` 聚合才能检出混用），不经本 helper。
fn contract_label(c: &DiscoveredContract) -> String {
    match &c.slug {
        Some(slug) => format!(
            "{}/{}/{}/{}",
            c.path_kind, c.path_domain, c.path_version, slug
        ),
        None => format!("{}/{}/{}", c.path_kind, c.path_domain, c.path_version),
    }
}

/// 对单契约跑全部 per-contract 规则（执行顺序 = 下方 `extend` 调用序）。跨契约规则（R12 DuplicateId）
/// 在 [`validate_cross`]，不在此（它需全局视图）。
pub(crate) fn validate_contract(c: &DiscoveredContract) -> Vec<Finding> {
    // label 用相对 `{kind}/{domain}/{version}[/{slug}]`（机器稳定、跨机一致；嵌套带 slug 段精确定位），
    // 不用绝对磁盘路径——CI / 多开发机的 finding 输出须可对应 repo 路径，便于定位。
    let label = contract_label(c);
    let mut findings = Vec::new();
    findings.extend(rule_saga_consistency(&c.manifest, &label));
    findings.extend(rule_command_consistency(&c.manifest, &label));
    findings.extend(rule_command_policy(&c.manifest, &label));
    findings.extend(rule_framework_kind(&c.manifest, &label));
    findings.extend(rule_path_match(c, &label));
    findings.extend(rule_schema_shape(&c.manifest, &label));
    findings.extend(rule_schema_files_exist(c, &label));
    findings.extend(rule_unsafe_schema_path(&c.manifest, &label));
    findings.extend(rule_ident_syntax(&c.manifest, &label));
    findings.extend(rule_perkind_active_fields(&c.manifest, &label));
    findings.extend(rule_perkind_field_scope(&c.manifest, &label));
    findings.extend(rule_http_auth(&c.manifest, &label));
    findings.extend(rule_http_request_tenant_source(c, &label));
    findings.extend(rule_http_projection_response_coverage(c, &label));
    findings.extend(rule_saga_block(&c.manifest, &label));
    findings.extend(rule_active_delivery_supported(&c.manifest, &label));
    findings.extend(rule_schema_title(c, &label));
    findings.extend(rule_schema_redaction(c, &label));
    findings.extend(rule_schema_protection(c, &label));
    findings.extend(rule_active_subscriber(&c.manifest, &label));
    findings.extend(rule_slug_syntax(c, &label));
    findings
}

/// R20：嵌套 slug 段语法（INVARIANT: CONTRACT-SLUG-SYNTAX-01 { level = "Medium", exec = "verify", source = "code" }）。扁平契约（`slug=None`）豁免。
/// slug 经 kebab→snake 拼进 generated `pub mod <slug_ident>`，须为合法 module ident 前体。
fn rule_slug_syntax(c: &DiscoveredContract, label: &str) -> Option<Finding> {
    let slug = c.slug.as_deref()?;
    if is_safe_slug(slug) {
        return None;
    }
    Some(finding(
        Rule::SlugSyntax,
        label,
        format!(
            "slug 段非法：须首字符 a-z、余 [a-z0-9_-]、无首尾连字符（kebab→snake 作 generated 子模块名），实为 {slug:?}"
        ),
    ))
}

/// R1：saga ⇒ WorkflowEventual。
fn rule_saga_consistency(m: &ContractManifest, label: &str) -> Option<Finding> {
    if m.kind == ContractKind::Saga && m.consistency_level != ConsistencyLevel::WorkflowEventual {
        return Some(finding(
            Rule::SagaConsistency,
            label,
            format!(
                "kind=saga 须 consistencyLevel=WorkflowEventual，实为 {:?}",
                m.consistency_level
            ),
        ));
    }
    None
}

/// R15：command ⇒ OutboxFact（无条件，同 R1 saga）。kind 内蕴 wire 语义，防误标致 outbox 接线漂移。
fn rule_command_consistency(m: &ContractManifest, label: &str) -> Option<Finding> {
    if m.kind == ContractKind::Command && m.consistency_level != ConsistencyLevel::OutboxFact {
        return Some(finding(
            Rule::CommandConsistency,
            label,
            format!(
                "kind=command 须 consistencyLevel=OutboxFact（docs/rules/eventbus.md §command dispatch），实为 {:?}",
                m.consistency_level
            ),
        ));
    }
    None
}

/// R24：command journal policy 不允许默认；跨 kind block 不允许被静默忽略。
fn rule_command_policy(m: &ContractManifest, label: &str) -> Option<Finding> {
    let valid = matches!(m.kind, ContractKind::Command) == m.command.is_some();
    (!valid).then(|| {
        finding(
            Rule::CommandPolicy,
            label,
            if m.kind == ContractKind::Command {
                format!("kind=command 必须显式声明 {FIELD_COMMAND} journal=required|none")
            } else {
                format!("{FIELD_COMMAND} 只允许用于 kind=command")
            },
        )
    })
}

/// R2：framework owner ⇒ kind ∈ {http, event, command}。
///
/// command 是 framework-neutral 分发机制（provider-agnostic：claimer / outbox provider 可互换），与设备
/// 身份 / 证书签发同列对齐 cert-manager/SPIFFE 的 `_framework` 归属语义（#1124）。saga 仍排除——saga 是
/// 跨域编排，天然绑定某域 owner（R1 + saga.md）。
fn rule_framework_kind(m: &ContractManifest, label: &str) -> Option<Finding> {
    let framework = matches!(m.owner, ContractOwner::Framework);
    let kind_ok = matches!(
        m.kind,
        ContractKind::Http | ContractKind::Event | ContractKind::Command
    );
    if framework && !kind_ok {
        return Some(finding(
            Rule::FrameworkKind,
            label,
            format!(
                "owner=_framework 仅允许 kind ∈ {{http,event,command}}，实为 {:?}",
                m.kind
            ),
        ));
    }
    None
}

/// R3：磁盘段须等于 manifest 字段。
fn rule_path_match(c: &DiscoveredContract, label: &str) -> Option<Finding> {
    let want_kind = c.manifest.kind.as_dir();
    let mut diffs = Vec::new();
    if c.path_kind != want_kind {
        diffs.push(format!("kind 段 {} ≠ 字段 {}", c.path_kind, want_kind));
    }
    if c.path_domain != c.manifest.domain {
        diffs.push(format!(
            "domain 段 {} ≠ 字段 {}",
            c.path_domain, c.manifest.domain
        ));
    }
    if c.path_version != c.manifest.version {
        diffs.push(format!(
            "version 段 {} ≠ 字段 {}",
            c.path_version, c.manifest.version
        ));
    }
    if diffs.is_empty() {
        return None;
    }
    Some(finding(Rule::PathMismatch, label, diffs.join("；")))
}

/// R4：kind→schema 形态一致。返回缺失的必需 schema 声明（可多条）。
fn rule_schema_shape(m: &ContractManifest, label: &str) -> Vec<Finding> {
    let s = &m.schemas;
    let required: &[(&str, bool)] = match m.kind {
        ContractKind::Http => &[
            (SCHEMA_KEY_REQUEST, s.request.is_some()),
            (SCHEMA_KEY_RESPONSE, s.response.is_some()),
        ],
        ContractKind::Event | ContractKind::Saga => &[(SCHEMA_KEY_PAYLOAD, s.payload.is_some())],
        ContractKind::Command => &[(SCHEMA_KEY_REQUEST, s.request.is_some())],
    };
    required
        .iter()
        .filter(|(_, present)| !present)
        .map(|(key, _)| {
            finding(
                Rule::SchemaShape,
                label,
                format!("kind={:?} 缺必需 schema 声明 [schemas].{key}", m.kind),
            )
        })
        .collect()
}

/// R5：声明的每个 schema 文件须存在（含 saga step `outputSchema`，经 `declared_schema_files()` 聚合）。
fn rule_schema_files_exist(c: &DiscoveredContract, label: &str) -> Vec<Finding> {
    c.manifest
        .declared_schema_files()
        .into_iter()
        .filter(|file| !c.dir.join(file).is_file())
        .map(|file| {
            finding(
                Rule::MissingSchema,
                label,
                format!("声明的 schema 文件不存在: {file}"),
            )
        })
        .collect()
}

/// R6：schema 文件名须为纯文件名（不含 `/`、`\`、`..` 分量或绝对路径），防路径逃逸。
/// 防逃逸判定单源见 `crate::pathsafe`（codegen 写盘守卫同源）；含 saga step `outputSchema`。
fn rule_unsafe_schema_path(m: &ContractManifest, label: &str) -> Vec<Finding> {
    m.declared_schema_files()
        .into_iter()
        .filter(|file| pathsafe::is_unsafe_segment(file))
        .map(|file| {
            finding(
                Rule::UnsafeSchemaPath,
                label,
                format!("schema 文件名含路径分量（防逃逸）: {file}"),
            )
        })
        .collect()
}

/// R7：authoring 标识符 / per-kind 字符串字段语法。domain/version/id 拼进派生 module 名 / 文件路径
/// （见 codegen），owner 决定契约归属，http `path` 是鉴权挂载点、event `topic` 是 wire routing key、
/// event `[[subscriptions]]` 的 consumer/group 拼进 generated 注册 glue 字符串字面量——均须先收口形态，
/// 杜绝坏值流入生成路径 / 归属解析 / 路由注册 / 生成代码。与 codegen 写盘前防逃逸 / 防注入守卫互为表里。
fn rule_ident_syntax(m: &ContractManifest, label: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    if !is_safe_segment(&m.domain) {
        out.push(finding(
            Rule::IdentSyntax,
            label,
            format!(
                "domain 非法：须 [a-z0-9_]+、首字符 a-z 或 _、无路径分量，实为 {:?}",
                m.domain
            ),
        ));
    }
    if !is_version(&m.version) {
        out.push(finding(
            Rule::IdentSyntax,
            label,
            format!("version 非法：须 v{{N}}（如 v1），实为 {:?}", m.version),
        ));
    }
    if !is_dotted_id(&m.id) {
        out.push(finding(
            Rule::IdentSyntax,
            label,
            format!(
                "id 非法：须点分小写名（如 seed.echo / config.entry-upserted），实为 {:?}",
                m.id
            ),
        ));
    }
    if let ContractOwner::Domain(name) = &m.owner
        && !is_domain_name(name)
    {
        out.push(finding(
            Rule::IdentSyntax,
            label,
            format!(
                "owner 非法：须合法域名（[a-z][a-z0-9_]*，不可空 / 不可 _ 前缀保留段）或 _framework，实为 {name:?}"
            ),
        ));
    }
    // http `path`（若声明）：收口注入 / 逃逸面（鉴权挂载点）。
    if let Some(path) = &m.path
        && !is_safe_http_path(path)
    {
        out.push(finding(
            Rule::IdentSyntax,
            label,
            format!(
                "path 非法：须绝对路径（/ 开头、非 // 协议相对、非裸 /、无 .. 逃逸、无空白 / 控制符），实为 {path:?}"
            ),
        ));
    }
    // event `topic`（若声明）：是 wire routing key，须与 id 同点分小写形态。
    if let Some(topic) = &m.topic
        && !is_dotted_id(topic)
    {
        out.push(finding(
            Rule::IdentSyntax,
            label,
            format!("topic 非法：须点分小写名（如 seed.thing-happened），实为 {topic:?}"),
        ));
    }
    // event `[[subscriptions]]` 的 consumer / group：codegen 把二者拼进 generated 注册 glue 的
    // `SubscriptionSpec { consumer: "…", group: "…" }` Rust **字符串字面量**（review #216 F6）。consumer 是
    // 消费者域名、group 是稳定 consumer group 名（broker 消费位点）——须先收口形态，杜绝坏值注入生成代码 /
    // 路由（与 codegen 写盘前 `is_safe_codegen_ident` 防御守卫互为上下游闭环 funnel）。
    for sub in &m.subscriptions {
        if !is_domain_name(&sub.consumer) {
            out.push(finding(
                Rule::IdentSyntax,
                label,
                format!(
                    "subscription consumer 非法：须合法消费者域名（[a-z][a-z0-9_]*），实为 {:?}",
                    sub.consumer
                ),
            ));
        }
        if !is_dotted_id(&sub.group) {
            out.push(finding(
                Rule::IdentSyntax,
                label,
                format!(
                    "subscription group 非法：须点分小写名（如 audit.session-created），实为 {:?}",
                    sub.group
                ),
            ));
        }
    }
    out
}

/// http path（per-kind）安全形态：绝对路径、非协议相对（`//`）、非裸 `/`、无 `..` 逃逸、无空白 / 控制符。
/// 不锁定 `/api/v{N}/{domain}` vs `/internal/v{N}` 命名空间（route 注册期管），仅收口注入 / 逃逸面。
fn is_safe_http_path(s: &str) -> bool {
    s.starts_with('/')
        && !s.starts_with("//")
        && s.len() > 1
        && !s.contains("..")
        && !s
            .bytes()
            .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
}

/// R8：`lifecycle=active` ⇒ 按 kind 必填 **active 发布接线**字段（http path+method / event topic+delivery /
/// command topic）。draft/deprecated 豁免（种子 draft 不受约束）。每缺一项一条 finding。字段值形态由 R7 守。
///
/// **command topic**：命令分发的 broker routing key（`<domain>.commands.<name>`，#1124），active command
/// 无 topic ⇒ 无路由出口 = 死分发，故必填（与 active event 要求 topic 同理；command 无 `delivery`——OutboxFact
/// 经 outbox relay 投递，delivery 语义由 outbox 引擎固定，不在契约面声明）。request schema 仍由 R4 守。
///
/// **saga 不在此**：`[saga]` block 是 saga 契约的**结构语义**（saga.md governance），非「仅 active 生效的
/// 发布接线字段」，故 `kind=saga` 无条件必填（不论 lifecycle）由 R10 守——不混进本 active-only 集。
fn rule_perkind_active_fields(m: &ContractManifest, label: &str) -> Vec<Finding> {
    if m.lifecycle != Lifecycle::Active {
        return Vec::new();
    }
    let required: &[(&str, bool)] = match m.kind {
        ContractKind::Http => &[
            (FIELD_PATH, m.path.is_some()),
            (FIELD_METHOD, m.method.is_some()),
        ],
        ContractKind::Event => &[
            (FIELD_TOPIC, m.topic.is_some()),
            (FIELD_DELIVERY, m.delivery.is_some()),
        ],
        // command：active 必有 topic（路由出口）；request schema 由 R4 守。
        ContractKind::Command => &[(FIELD_TOPIC, m.topic.is_some())],
        // saga block 无条件必填（R10）。
        ContractKind::Saga => &[],
    };
    required
        .iter()
        .filter(|(_, present)| !present)
        .map(|(field, _)| {
            finding(
                Rule::PerKindActiveFields,
                label,
                format!(
                    "lifecycle=active 的 kind={} 契约缺 per-kind 必填字段 {field}（见 contracts/README.md §contract.toml 字段）",
                    m.kind.as_dir()
                ),
            )
        })
        .collect()
}

/// R9：per-kind 字段只允许出现在匹配 kind——错配（如 event 带 `path`、http 带 `[saga]`）会被
/// 后续派生 silently-ignored，故拒。不沿用 `Schemas`「只查必填、放任 stray」旧惯例（彻底性）。
fn rule_perkind_field_scope(m: &ContractManifest, label: &str) -> Vec<Finding> {
    // （字段名, 是否出现, 合法 kind 集）。`topic` 是 event ∪ command 的 routing key，故双 kind 合法；
    // 其余字段单 kind。
    let checks: [(&str, bool, &[ContractKind]); 5] = [
        (FIELD_PATH, m.path.is_some(), &[ContractKind::Http]),
        (FIELD_METHOD, m.method.is_some(), &[ContractKind::Http]),
        (
            FIELD_TOPIC,
            m.topic.is_some(),
            &[ContractKind::Event, ContractKind::Command],
        ),
        (FIELD_DELIVERY, m.delivery.is_some(), &[ContractKind::Event]),
        (FIELD_SAGA, m.saga.is_some(), &[ContractKind::Saga]),
    ];
    checks
        .iter()
        .filter(|(_, present, allowed)| *present && !allowed.contains(&m.kind))
        .map(|(field, _, allowed)| {
            let allowed_dirs = allowed
                .iter()
                .map(|k| k.as_dir())
                .collect::<Vec<_>>()
                .join("/");
            finding(
                Rule::PerKindFieldScope,
                label,
                format!(
                    "per-kind 字段 {field} 仅允许 kind={allowed_dirs}，实为 kind={}",
                    m.kind.as_dir()
                ),
            )
        })
        .collect()
}

fn rule_http_auth(m: &ContractManifest, label: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    let http_endpoint = m.endpoints.as_ref().and_then(|e| e.http.as_ref());
    if http_endpoint.is_some() && m.kind != ContractKind::Http {
        out.push(finding(
            Rule::HttpAuth,
            label,
            "endpoints.http 仅允许 kind=http 契约声明".to_string(),
        ));
    }
    let Some(http) = http_endpoint else {
        if m.kind == ContractKind::Http && m.lifecycle == Lifecycle::Active {
            out.push(finding(
                Rule::HttpAuth,
                label,
                format!("lifecycle=active 的 kind=http 契约缺 {FIELD_ENDPOINTS_HTTP_AUTH}"),
            ));
        }
        return out;
    };

    rule_http_header_modes(http, label, &mut out);
    rule_http_projection_fields(http, label, &mut out);

    if m.kind != ContractKind::Http || m.lifecycle != Lifecycle::Active {
        return out;
    }
    let Some(auth) = &http.auth else {
        out.push(finding(
            Rule::HttpAuth,
            label,
            format!("lifecycle=active 的 kind=http 契约缺 {FIELD_ENDPOINTS_HTTP_AUTH}"),
        ));
        return out;
    };
    let reason_present = auth.reason.as_ref().is_some_and(|s| !s.trim().is_empty());
    let permission_present = auth
        .permission
        .as_ref()
        .is_some_and(|s| !s.trim().is_empty());
    rule_http_resource_shape(http, label, &mut out);
    rule_http_resource_sharing(http, label, &mut out);
    match auth.mode {
        HttpAuthMode::Permission => {
            rule_http_permission_auth(m, http, auth, permission_present, label, &mut out)
        }
        HttpAuthMode::Public
        | HttpAuthMode::Bootstrap
        | HttpAuthMode::ClientsOnly
        | HttpAuthMode::ServiceOwned => {
            rule_http_opt_out_auth(http, auth, reason_present, label, &mut out);
        }
    }
    let tenant_header_mode = http.headers.get("X-Tenant-ID").copied();
    rule_http_service_token_header_coupling(auth.mode, tenant_header_mode, label, &mut out);
    if m.id == "identity.login"
        && matches!(auth.mode, HttpAuthMode::Public)
        && tenant_header_mode != Some(HttpHeaderMode::PopulateOnly)
    {
        out.push(finding(
            Rule::HttpAuth,
            label,
            "identity.login public serving 必须声明 X-Tenant-ID = populate-only".to_string(),
        ));
    }
    out
}

fn rule_http_projection_fields(http: &HttpEndpoint, label: &str, out: &mut Vec<Finding>) {
    let Some(projection) = &http.projection else {
        return;
    };
    let mut fields = BTreeSet::new();
    let mut permissions = BTreeSet::new();
    let mut obligations = BTreeSet::new();
    let mut response_paths = BTreeSet::new();
    for field in &projection.fields {
        if !fields.insert(field.field) {
            out.push(finding(
                Rule::HttpProjectionCoverage,
                label,
                format!(
                    "{FIELD_ENDPOINTS_HTTP_PROJECTION} field {:?} 重复",
                    field.field.as_wire()
                ),
            ));
        }
        if let Some(permission_finding) = validate_route_permission_literal(
            &field.permission,
            &format!("{FIELD_ENDPOINTS_HTTP_PROJECTION} permission"),
            label,
            Rule::HttpProjectionCoverage,
        ) {
            out.push(permission_finding);
        } else if !permissions.insert(field.permission.as_str()) {
            out.push(finding(
                Rule::HttpProjectionCoverage,
                label,
                format!(
                    "{FIELD_ENDPOINTS_HTTP_PROJECTION} permission {:?} 重复",
                    field.permission
                ),
            ));
        }
        if field.permission != field.field.canonical_permission() {
            out.push(finding(
                Rule::HttpProjectionCoverage,
                label,
                format!(
                    "{FIELD_ENDPOINTS_HTTP_PROJECTION} field {:?} permission 必须为 {:?}",
                    field.field.as_wire(),
                    field.field.canonical_permission()
                ),
            ));
        }
        if field.obligation_key.trim().is_empty() {
            out.push(finding(
                Rule::HttpProjectionCoverage,
                label,
                format!("{FIELD_ENDPOINTS_HTTP_PROJECTION} obligationKey 必须非空"),
            ));
        } else if !obligations.insert(field.obligation_key.as_str()) {
            out.push(finding(
                Rule::HttpProjectionCoverage,
                label,
                format!(
                    "{FIELD_ENDPOINTS_HTTP_PROJECTION} obligationKey {:?} 重复",
                    field.obligation_key
                ),
            ));
        }
        if field.obligation_key != field.field.canonical_obligation_key() {
            out.push(finding(
                Rule::HttpProjectionCoverage,
                label,
                format!(
                    "{FIELD_ENDPOINTS_HTTP_PROJECTION} field {:?} obligationKey 必须为 {:?}",
                    field.field.as_wire(),
                    field.field.canonical_obligation_key()
                ),
            ));
        }
        if field.response_path.trim().is_empty() {
            out.push(finding(
                Rule::HttpProjectionCoverage,
                label,
                format!("{FIELD_ENDPOINTS_HTTP_PROJECTION} responsePath 必须非空"),
            ));
        } else if !response_paths.insert(field.response_path.as_str()) {
            out.push(finding(
                Rule::HttpProjectionCoverage,
                label,
                format!(
                    "{FIELD_ENDPOINTS_HTTP_PROJECTION} responsePath {:?} 重复",
                    field.response_path
                ),
            ));
        }
        if field.response_path != field.field.canonical_response_path() {
            out.push(finding(
                Rule::HttpProjectionCoverage,
                label,
                format!(
                    "{FIELD_ENDPOINTS_HTTP_PROJECTION} field {:?} responsePath 必须为 {:?}",
                    field.field.as_wire(),
                    field.field.canonical_response_path()
                ),
            ));
        }
    }
}

fn rule_http_header_modes(http: &HttpEndpoint, label: &str, out: &mut Vec<Finding>) {
    for (name, mode) in &http.headers {
        let allowed_mode = matches!(
            mode,
            HttpHeaderMode::PopulateOnly | HttpHeaderMode::ServiceTokenTenantBound
        );
        if name != "X-Tenant-ID" || !allowed_mode {
            out.push(finding(
                Rule::HttpAuth,
                label,
                format!(
                    "{FIELD_ENDPOINTS_HTTP_HEADERS} 当前仅接受 \"X-Tenant-ID\" = \"populate-only\" 或 \"service-token-tenant-bound\"，实为 {name:?} = {:?}",
                    mode
                ),
            ));
        }
    }
}

fn rule_http_resource_shape(http: &HttpEndpoint, label: &str, out: &mut Vec<Finding>) {
    let resource_present = http.resource.as_ref().is_some_and(|s| !s.trim().is_empty());
    if http.resource.is_some() && !resource_present {
        out.push(finding(
            Rule::HttpAuth,
            label,
            "endpoints.http.resource 必须为非空 path 参数名".to_string(),
        ));
    }
    if resource_present && http.self_scoped {
        out.push(finding(
            Rule::HttpAuth,
            label,
            "endpoints.http.resource 与 endpoints.http.selfScoped 互斥".to_string(),
        ));
    }
}

fn rule_http_resource_sharing(http: &HttpEndpoint, label: &str, out: &mut Vec<Finding>) {
    let Some(sharing) = &http.resource_sharing else {
        return;
    };
    match sharing.mode {
        HttpResourceSharingMode::Global => {
            let reason_present = sharing
                .reason
                .as_deref()
                .is_some_and(|reason| !reason.trim().is_empty());
            if !reason_present {
                out.push(finding(
                    Rule::HttpAuth,
                    label,
                    format!(
                        "{FIELD_ENDPOINTS_HTTP_RESOURCE_SHARING} mode=global 必须声明非空 reason"
                    ),
                ));
            }
            if http
                .resource
                .as_ref()
                .is_none_or(|resource| resource.trim().is_empty())
            {
                out.push(finding(
                    Rule::HttpAuth,
                    label,
                    format!("{FIELD_ENDPOINTS_HTTP_RESOURCE_SHARING} mode=global 必须声明 endpoints.http.resource"),
                ));
            }
        }
        HttpResourceSharingMode::TenantScoped => {
            if sharing.reason.is_some() {
                out.push(finding(
                    Rule::HttpAuth,
                    label,
                    format!(
                        "{FIELD_ENDPOINTS_HTTP_RESOURCE_SHARING} mode=tenantScoped 禁止 reason"
                    ),
                ));
            }
        }
    }
}

fn rule_http_permission_auth(
    m: &ContractManifest,
    http: &HttpEndpoint,
    auth: &HttpAuth,
    permission_present: bool,
    label: &str,
    out: &mut Vec<Finding>,
) {
    if !permission_present {
        out.push(finding(
            Rule::HttpAuth,
            label,
            "endpoints.http.auth mode=permission 必须声明非空 permission".to_string(),
        ));
    } else if let Some(permission) = auth.permission.as_deref()
        && let Some(permission_finding) = validate_route_permission_literal(
            permission,
            "endpoints.http.auth permission",
            label,
            Rule::HttpAuth,
        )
    {
        out.push(permission_finding);
    }
    if auth.reason.is_some() {
        out.push(finding(
            Rule::HttpAuth,
            label,
            "endpoints.http.auth mode=permission 禁止 reason".to_string(),
        ));
    }
    if let Some(resource) = http.resource.as_ref().filter(|s| !s.trim().is_empty()) {
        let path = m.path.as_deref().unwrap_or_default();
        if !http_path_params(path).any(|param| param == resource.trim()) {
            out.push(finding(
                Rule::HttpAuth,
                label,
                format!("endpoints.http.resource={resource:?} 必须匹配 HTTP path 中的 {{param}}"),
            ));
        }
    }
}

fn route_permission_is_cataloged(value: &str) -> bool {
    vocab::RoutePermissionId::parse(value).is_ok()
}

fn validate_route_permission_literal(
    value: &str,
    field: &str,
    label: &str,
    rule: Rule,
) -> Option<Finding> {
    if value.trim().is_empty() {
        return Some(finding(rule, label, format!("{field} 必须非空")));
    }
    if value != value.trim() {
        return Some(finding(
            rule,
            label,
            format!(
                "{field} {value:?} 必须精确匹配 vocab::RoutePermissionId 闭值集成员，禁止前后空白"
            ),
        ));
    }
    if !route_permission_is_cataloged(value) {
        return Some(finding(
            rule,
            label,
            format!("{field} {value:?} 未注册到 vocab::RoutePermissionId 闭值集"),
        ));
    }
    None
}

fn rule_http_opt_out_auth(
    http: &HttpEndpoint,
    auth: &HttpAuth,
    reason_present: bool,
    label: &str,
    out: &mut Vec<Finding>,
) {
    if !reason_present {
        out.push(finding(
            Rule::HttpAuth,
            label,
            format!(
                "endpoints.http.auth mode={} 必须声明非空 reason",
                auth.mode.as_wire()
            ),
        ));
    }
    if auth.permission.is_some() {
        out.push(finding(
            Rule::HttpAuth,
            label,
            format!(
                "endpoints.http.auth mode={} 禁止 permission",
                auth.mode.as_wire()
            ),
        ));
    }
    if http.resource.is_some() {
        out.push(finding(
            Rule::HttpAuth,
            label,
            format!(
                "endpoints.http.auth mode={} 禁止 resource",
                auth.mode.as_wire()
            ),
        ));
    }
    if http.self_scoped {
        out.push(finding(
            Rule::HttpAuth,
            label,
            format!(
                "endpoints.http.auth mode={} 禁止 selfScoped",
                auth.mode.as_wire()
            ),
        ));
    }
}

fn http_path_params(path: &str) -> impl Iterator<Item = &str> {
    path.split('/').filter_map(|segment| {
        segment
            .strip_prefix('{')
            .and_then(|s| s.strip_suffix('}'))
            .filter(|s| !s.is_empty())
    })
}

fn rule_http_service_token_header_coupling(
    auth_mode: HttpAuthMode,
    tenant_header_mode: Option<HttpHeaderMode>,
    label: &str,
    out: &mut Vec<Finding>,
) {
    if tenant_header_mode == Some(HttpHeaderMode::ServiceTokenTenantBound)
        && !matches!(auth_mode, HttpAuthMode::ServiceOwned)
    {
        out.push(finding(
            Rule::HttpAuth,
            label,
            "X-Tenant-ID = service-token-tenant-bound 仅允许 serviceOwned HTTP auth mode"
                .to_string(),
        ));
    }
    if matches!(auth_mode, HttpAuthMode::ServiceOwned)
        && tenant_header_mode != Some(HttpHeaderMode::ServiceTokenTenantBound)
    {
        out.push(finding(
            Rule::HttpAuth,
            label,
            "serviceOwned HTTP auth mode 必须声明 X-Tenant-ID = service-token-tenant-bound"
                .to_string(),
        ));
    }
}

fn rule_http_request_tenant_source(c: &DiscoveredContract, label: &str) -> Vec<Finding> {
    let m = &c.manifest;
    if m.kind != ContractKind::Http {
        return Vec::new();
    }
    let Some(request) = m.schemas.request.as_deref() else {
        return Vec::new();
    };
    if pathsafe::is_unsafe_segment(request) {
        return Vec::new();
    }
    let Ok(text) = std::fs::read_to_string(c.dir.join(request)) else {
        return Vec::new();
    };
    let Ok(value) = serde_json::from_str::<serde_json::Value>(&text) else {
        return Vec::new();
    };
    if schema_declares_property(&value, "tenantId") {
        return vec![finding(
            Rule::HttpTenantSource,
            label,
            format!(
                "HTTP request schema {request} 声明 tenantId；tenant scope 必须来自{}，不得来自 body",
                super::TENANT_SCOPE_SOURCE_RULE
            ),
        )];
    }
    Vec::new()
}

fn rule_http_projection_response_coverage(c: &DiscoveredContract, label: &str) -> Vec<Finding> {
    let m = &c.manifest;
    if m.kind != ContractKind::Http
        || m.lifecycle != Lifecycle::Active
        || m.method != Some(HttpMethod::Get)
    {
        return Vec::new();
    }
    let Some(response) = m.schemas.response.as_deref() else {
        return Vec::new();
    };
    if pathsafe::is_unsafe_segment(response) {
        return Vec::new();
    }
    let Ok(text) = std::fs::read_to_string(c.dir.join(response)) else {
        return Vec::new();
    };
    let Ok(schema) = serde_json::from_str::<serde_json::Value>(&text) else {
        return Vec::new();
    };
    let protected = protected_response_paths(&schema);
    let declared = m
        .endpoints
        .as_ref()
        .and_then(|endpoints| endpoints.http.as_ref())
        .and_then(|http| http.projection.as_ref())
        .map(|projection| {
            projection
                .fields
                .iter()
                .map(|field| field.response_path.as_str())
                .collect::<BTreeSet<_>>()
        })
        .unwrap_or_default();

    let mut out = Vec::new();
    for path in &protected {
        if !declared.contains(path.as_str()) {
            out.push(finding(
                Rule::HttpProjectionCoverage,
                label,
                format!(
                    "active GET response protected field {path:?} 必须声明 {FIELD_ENDPOINTS_HTTP_PROJECTION} responsePath"
                ),
            ));
        }
    }
    for path in declared {
        if !response_path_exists(&schema, path) {
            out.push(finding(
                Rule::HttpProjectionCoverage,
                label,
                format!(
                    "{FIELD_ENDPOINTS_HTTP_PROJECTION} responsePath {path:?} 不存在于 response schema {response}"
                ),
            ));
        } else if !protected.contains(path) {
            out.push(finding(
                Rule::HttpProjectionCoverage,
                label,
                format!(
                    "{FIELD_ENDPOINTS_HTTP_PROJECTION} responsePath {path:?} 未指向 x-pii 或 tenantId protected field"
                ),
            ));
        }
    }
    out
}

fn protected_response_paths(schema: &serde_json::Value) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    collect_protected_response_paths(schema, "", &mut out);
    out
}

fn collect_protected_response_paths(
    schema: &serde_json::Value,
    prefix: &str,
    out: &mut BTreeSet<String>,
) {
    let serde_json::Value::Object(map) = schema else {
        return;
    };
    if let Some(serde_json::Value::Object(properties)) = map.get("properties") {
        for (name, child) in properties {
            let path = join_response_path(prefix, name);
            if name == "tenantId" || child.get("x-pii").is_some() {
                out.insert(path.clone());
            }
            collect_protected_response_paths(child, &path, out);
        }
    }
    if let Some(items) = map.get("items") {
        let array_prefix = format!("{prefix}[]");
        collect_protected_response_paths(items, &array_prefix, out);
    }
}

fn join_response_path(prefix: &str, field: &str) -> String {
    if prefix.is_empty() {
        field.to_string()
    } else {
        format!("{prefix}.{field}")
    }
}

fn response_path_exists(schema: &serde_json::Value, path: &str) -> bool {
    if path.trim().is_empty() {
        return false;
    }
    let mut current = schema;
    for segment in path.split('.') {
        if segment.is_empty() {
            return false;
        }
        let (property, array) = match segment.strip_suffix("[]") {
            Some(property) if !property.is_empty() => (property, true),
            Some(_) => return false,
            None => (segment, false),
        };
        let Some(next) = current
            .get("properties")
            .and_then(serde_json::Value::as_object)
            .and_then(|properties| properties.get(property))
        else {
            return false;
        };
        current = next;
        if array {
            let Some(items) = current.get("items") else {
                return false;
            };
            current = items;
        }
    }
    true
}

/// R10：saga 契约的 `[saga]` block 结构语义（saga.md governance，**无条件、不论 lifecycle**）：
/// `kind=saga` ⇒ 须有非空 block；block 存在即查良构——≥1 step、step name 合法非关键字 Rust 标识符
/// （`syn`，拒 raw `r#`）且唯一、outputSchema 非空。retry/timeout 非负与 compensationOrder 取值由
/// `manifest.rs` 类型层守（Hard），R10 不重复；step outputSchema 文件完整性由 R5/R6 经
/// `declared_schema_files()` 覆盖。非-saga kind 误带 `[saga]` 由 R9 拒（本规则只校验 block 内部）。
fn rule_saga_block(m: &ContractManifest, label: &str) -> Vec<Finding> {
    let Some(saga) = &m.saga else {
        // saga 契约缺 block：saga.md 要求 kind:saga 必有非空 saga block（无条件、不论 lifecycle）。
        if m.kind == ContractKind::Saga {
            return vec![finding(
                Rule::SagaBlock,
                label,
                "kind=saga 须声明非空 [saga] block（saga.md governance，无条件、不论 lifecycle）"
                    .to_string(),
            )];
        }
        return Vec::new();
    };
    let mut out = Vec::new();
    if saga.steps.is_empty() {
        out.push(finding(
            Rule::SagaBlock,
            label,
            "saga block 须至少声明一个 step".to_string(),
        ));
    }
    let mut seen = BTreeSet::new();
    for step in &saga.steps {
        let name = step.name.as_str();
        // `syn` 拒裸关键字 / 坏语法；额外拒 raw identifier（`r#fn`）——它是合法 `syn::Ident` 但
        // 不是干净的 step 名（流入 codegen 生成符号会带 `r#` 前缀歧义）。
        if name.starts_with("r#") || syn::parse_str::<syn::Ident>(name).is_err() {
            out.push(finding(
                Rule::SagaBlock,
                label,
                format!(
                    "saga step name 须为合法非关键字 Rust 标识符（拒 raw `r#`），实为 {name:?}"
                ),
            ));
        }
        if !seen.insert(name) {
            out.push(finding(
                Rule::SagaBlock,
                label,
                format!("saga step name 重复: {name:?}"),
            ));
        }
        if step.output_schema.is_empty() {
            out.push(finding(
                Rule::SagaBlock,
                label,
                format!("saga step {name:?} 的 outputSchema 不可为空"),
            ));
        }
    }
    out
}

/// R11：`lifecycle=active` 的 event 契约只能声明当前**可兑现**的投递语义。RSS outbox + 幂等消费者
/// 当前仅兑现 `at-least-once`（见 docs/rules/eventbus.md）；`at-most-once`/`exactly-once` broker 链路
/// 无运行时保证——active 契约声明它们会虚开语义承诺，故拒（能力落地前限 draft/deprecated 表达前瞻设计）。
/// 把 manifest.rs / README 的「不建议」升级为机器强制（对齐 cert-manager/k8s：active 资源不得声明系统不能兑现的能力）。
fn rule_active_delivery_supported(m: &ContractManifest, label: &str) -> Option<Finding> {
    if m.lifecycle != Lifecycle::Active || m.kind != ContractKind::Event {
        return None;
    }
    match m.delivery {
        Some(d) if d != Delivery::AtLeastOnce => Some(finding(
            Rule::ActiveDeliverySupported,
            label,
            format!(
                "active event 当前仅支持 delivery=at-least-once（outbox + 幂等消费者）；{} 暂无运行时保证，能力落地前限 draft/deprecated",
                d.as_wire()
            ),
        )),
        _ => None,
    }
}

/// R14：`lifecycle=active && kind=event` ⇒ `subscriptions` 非空（EVENT-ACTIVE-SUB-01，Medium）。
///
/// active event 契约无 subscriber 即「死事件」——发出后无消费者处理，视为错误配置。
/// draft/deprecated 豁免：种子契约 / 前瞻设计 / 退役契约不受约束。
/// 与 R11 同为 active-event-only 规则，置于逐契约规则末尾（R13 后）执行。
fn rule_active_subscriber(m: &ContractManifest, label: &str) -> Option<Finding> {
    if m.lifecycle != Lifecycle::Active || m.kind != ContractKind::Event {
        return None;
    }
    if m.subscriptions.is_empty() {
        return Some(finding(
            Rule::ActiveSubscriber,
            label,
            format!(
                "active event 契约缺 {FIELD_SUBSCRIPTIONS} 声明（EVENT-ACTIVE-SUB-01）：\
                active event 无 subscriber 即死事件，须在 contract.toml 中声明至少一个 [[subscriptions]] 条目"
            ),
        ));
    }
    None
}

/// R13：每个喂 codegen TypeSpace 的 declared schema（`[schemas]` request/response/payload；saga 另含 step
/// outputSchema）的 `title`
/// 须 PascalCase 且**契约内**唯一（INVARIANT: CONTRACT-TITLE-01 { level = "Medium", exec = "verify", source = "code" }）。title 是 typify 生成的 Rust 类型名
/// （顶层 + 嵌套对象都成类型）：非 PascalCase 产生非惯用类型名；契约内重复（一契约的全部 declared schema
/// 喂同一 TypeSpace）产生类型冲突。
///
/// schema 文件口径**严格对齐 codegen** `render_contract_body`：saga 用
/// [`super::manifest::ContractManifest::declared_schema_files`]（payload + step outputSchema），其它 kind 用
/// `Schemas::declared_files()`。
/// reason: 校验口径锚定「实际生成类型的那批 schema」，勿误把两个 accessor 统一。
///
/// 读不到 / JSON parse 失败 → skip（不报）：文件缺失由 R5（MissingSchema）报，JSON 良构由 codegen parse
/// 门兜底；本规则只在能解析的 schema 上校验 title。
fn rule_schema_title(c: &DiscoveredContract, label: &str) -> Vec<Finding> {
    let (titles, missing_root) = collect_contract_titles(c);
    let mut out = Vec::new();
    // ⓪ root title 必填：每个 declared schema 的 root 须有 string `title`。typify `add_root_schema`
    // 仅在 root metadata 含 title 时生成根类型（缺则 Ok(None)、根类型静默丢失，见 codegen render_contract）。
    for file in &missing_root {
        out.push(finding(
            Rule::SchemaTitle,
            label,
            format!("declared schema 缺 root title（须 string；否则 typify 不生成根类型）：{file}"),
        ));
    }
    // ① 非 PascalCase。
    for (title, file) in &titles {
        if !is_pascal_case(title) {
            out.push(finding(
                Rule::SchemaTitle,
                label,
                format!(
                    "schema title 须 PascalCase（^[A-Z][A-Za-z0-9]*$），实为 {title:?}（{file}）"
                ),
            ));
        }
    }
    // ② 契约内重复（跨该契约全部 declared schema 文件聚合判重）。
    let mut by_title: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for (title, file) in &titles {
        by_title
            .entry(title.as_str())
            .or_default()
            .push(file.as_str());
    }
    for (title, mut files) in by_title {
        if files.len() > 1 {
            // len 判重用原始计数（同文件内重复也是重复）；显示前 dedup，避免同名文件列两次。
            files.sort();
            files.dedup();
            out.push(finding(
                Rule::SchemaTitle,
                label,
                format!(
                    "schema title 契约内重复: {title:?}（出现于 {}）",
                    files.join("、")
                ),
            ));
        }
    }
    out
}

/// 读契约的全部 declared schema（口径 = codegen `render_contract_body` 的 schema 文件集），
/// 返回（`(title, 来源文件名)` 全集, root title 缺失的文件名集）。读不到 / parse 失败的文件 skip
/// （见 [`rule_schema_title`] doc）；能解析但 root 无 string title 的文件计入第二项（供 ⓪ root 必填门）。
fn collect_contract_titles(c: &DiscoveredContract) -> (Vec<(String, String)>, Vec<String>) {
    let mut titles = Vec::new();
    let mut missing_root = Vec::new();
    let schema_files = if c.manifest.kind == ContractKind::Saga {
        c.manifest.declared_schema_files()
    } else {
        c.manifest.schemas.declared_files()
    };
    for file in schema_files {
        if pathsafe::is_unsafe_segment(file) {
            // 防御性 fail-safe：含路径分量的文件名由 R6 报；R13 不主动 `join` 读它（不依赖
            // 文件系统拒绝来保护自身），与 R6 意图一致。
            continue;
        }
        let Ok(text) = std::fs::read_to_string(c.dir.join(file)) else {
            continue; // 缺失由 R5 报
        };
        let Ok(value) = serde_json::from_str::<serde_json::Value>(&text) else {
            continue; // JSON 良构由 codegen parse 门兜底
        };
        if !has_root_title(&value) {
            missing_root.push(file.to_string());
        }
        let mut found = Vec::new();
        collect_schema_titles(&value, &mut found);
        for t in found {
            titles.push((t, file.to_string()));
        }
    }
    (titles, missing_root)
}

/// declared schema 的 root（顶层节点）是否声明了 string `title`。typify `add_root_schema` 仅在
/// root metadata 含 title 时生成根类型（否则 `Ok(None)`、根类型丢失），故 root title 必填。
/// 空 string / 非 PascalCase title 由 ①PascalCase 门另抓（空串会被 `collect_schema_titles` 收进 titles）。
fn has_root_title(schema: &serde_json::Value) -> bool {
    matches!(schema.get("title"), Some(serde_json::Value::String(_)))
}

/// 递归收集一个 JSON Schema (draft-07) 文档里所有**内联 schema 节点**的 `title`（仅 string 值）。
/// 只在「已知为 schema 的 Value」上读 `title`，并仅下钻 schema 承载关键字——不进 property **名**、
/// `required`/`enum`/`const`/`default`/`description`/`$ref` 等非 schema 文本（杜绝把字面叫 "title" 的
/// property key 当类型名）。不走 `if`/`then`/`else`（draft-07 conditional，typify 0.7 支持有限；
/// 漏检比误检安全）。入口对 root schema 调用一次（含 root 自身 title）。
fn collect_schema_titles(schema: &serde_json::Value, out: &mut Vec<String>) {
    let serde_json::Value::Object(map) = schema else {
        return;
    };
    if let Some(serde_json::Value::String(title)) = map.get("title") {
        out.push(title.clone());
    }
    // 子 schema = 这些关键字下 object 的各 value（properties / patternProperties / definitions / $defs 成员）。
    for key in ["properties", "patternProperties", "definitions", "$defs"] {
        recurse_map_values(map.get(key), out);
    }
    // 子 schema = 这些关键字的值（单 schema 或 schema 数组）：items（object 或 tuple array）、
    // additionalProperties（object；bool 经入口 no-op）、not、allOf/anyOf/oneOf。
    for key in [
        "items",
        "additionalProperties",
        "not",
        "allOf",
        "anyOf",
        "oneOf",
    ] {
        if let Some(v) = map.get(key) {
            recurse_subschemas(v, out);
        }
    }
}

/// R16：字段级 redaction 扩展校验。按 manifest 声明的完整 schema slot 扫描，
/// 包含 request/response/payload 与 saga step output schema。
fn rule_schema_redaction(c: &DiscoveredContract, label: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    for file in c.manifest.declared_schema_files() {
        if pathsafe::is_unsafe_segment(file) {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(c.dir.join(file)) else {
            continue;
        };
        let Ok(value) = serde_json::from_str::<serde_json::Value>(&text) else {
            continue;
        };
        for violation in redaction::validate_schema(&value) {
            out.push(finding(
                Rule::SchemaRedaction,
                label,
                format!("{file} {}: {}", violation.pointer, violation.detail),
            ));
        }
    }
    out
}

/// R17：字段级 storage-protection 扩展校验（`x-protection` / `x-at-rest`）。按 manifest 声明的完整
/// schema slot 扫描，与 R16（observe redaction）同款遍历但两面正交（ADR-011 D1）。
fn rule_schema_protection(c: &DiscoveredContract, label: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    for file in c.manifest.declared_schema_files() {
        if pathsafe::is_unsafe_segment(file) {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(c.dir.join(file)) else {
            continue;
        };
        let Ok(value) = serde_json::from_str::<serde_json::Value>(&text) else {
            continue;
        };
        for violation in protection::validate_schema(&value) {
            out.push(finding(
                Rule::SchemaProtection,
                label,
                format!("{file} {}: {}", violation.pointer, violation.detail),
            ));
        }
    }
    out
}

/// 下钻一个 object-of-subschemas（如 `properties` / `$defs`）的各 value；非 object ⇒ no-op。
fn recurse_map_values(value: Option<&serde_json::Value>, out: &mut Vec<String>) {
    if let Some(serde_json::Value::Object(children)) = value {
        for child in children.values() {
            collect_schema_titles(child, out);
        }
    }
}

/// 下钻一个 schema 承载值：array ⇒ 逐项递归（allOf/anyOf/oneOf/tuple items），否则单 schema 递归
/// （非 object 在 [`collect_schema_titles`] 入口 no-op，如 `additionalProperties: false`）。
fn recurse_subschemas(v: &serde_json::Value, out: &mut Vec<String>) {
    match v {
        serde_json::Value::Array(items) => {
            for item in items {
                collect_schema_titles(item, out);
            }
        }
        other => collect_schema_titles(other, out),
    }
}

/// PascalCase 形态（`^[A-Z][A-Za-z0-9]*$`）：非空、首字符 `A-Z`、其余 `[A-Za-z0-9]`（拒下划线 / 连字符 /
/// snake / 数字开头 / 空）。手写 char 谓词，同 `is_safe_segment` / `is_version` 等的非-regex 范式
/// （dotted-id 文法已单源到 `consistency::Topic`，见 `is_dotted_id`）。
fn is_pascal_case(s: &str) -> bool {
    matches!(s.bytes().next(), Some(b) if b.is_ascii_uppercase())
        && s.bytes().all(|b| b.is_ascii_alphanumeric())
}

/// 路径段（domain 用）：非空、全 `[a-z0-9_]`、首字符 `a-z` 或 `_`（容 `_seed` 等保留段，
/// 拒数字开头 / 大写 / `.`、`/`、`\` 等路径分量）。
fn is_safe_segment(s: &str) -> bool {
    matches!(s.bytes().next(), Some(b) if b.is_ascii_lowercase() || b == b'_')
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

/// 版本段：`v{N}`，N 为非空数字串。
fn is_version(s: &str) -> bool {
    matches!(s.strip_prefix('v'), Some(n) if !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
}

/// 嵌套端点 slug 段：非空、首字符 `a-z`、余 `[a-z0-9_-]`、无首尾连字符（kebab）。slug 经 `-`→`_`
/// 转换后作 generated `pub mod <ident>`；首字符 `a-z` + 该字符集保证 snake 形态是合法 Rust 标识符。
/// 拒大写 / 数字开头 / `.`、`/`、`\` 等路径分量 / 首尾 `-`（`-foo`/`foo-`/`-`）。
fn is_safe_slug(s: &str) -> bool {
    matches!(s.bytes().next(), Some(b) if b.is_ascii_lowercase())
        && !s.ends_with('-')
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
}

/// 点分 id 文法谓词：每段首字符 `a-z`、余 `[a-z0-9-]`（如 `seed.echo`、`config.entry-upserted`）。
/// R7 用它统一校验三类**同形**字段——contract `id`、event `topic`、`[[subscriptions]].group`（见各调用点）；
/// 三者文法一致，故共用单源。小写连字符同 RSS 事件命名约定（见 CLAUDE.md：`session.created` /
/// `config.entry-upserted`），拒 camelCase。
///
/// 文法单一事实源是只读谓词 `consistency::is_canonical_topic_name`。治理校验不得调用任何 topic
/// authoring constructor，否则读取 manifest 会意外获得持久化写入 authority。
fn is_dotted_id(s: &str) -> bool {
    consistency::is_canonical_topic_name(s)
}

/// 域名（owner 用）：`[a-z][a-z0-9_]*`，非空、首字符字母（拒 `_` 前缀保留段与空串）。
fn is_domain_name(s: &str) -> bool {
    matches!(s.bytes().next(), Some(b) if b.is_ascii_lowercase())
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contract::manifest::{
        Capabilities, CompensationOrder, Delivery, DeviceLatentCapability, DeviceLatentFencing,
        DeviceLatentLateMessagePolicy, DeviceLatentLoop, DeviceLatentTenancy, DeviceLatentTrigger,
        EffectKind, EffectProfile, Endpoints, HttpAuth, HttpAuthMode, HttpEndpoint, HttpHeaderMode,
        HttpMethod, HttpProjection, HttpProjectionField, HttpProjectionFieldName,
        HttpResourceSharing, HttpResourceSharingMode, Lifecycle, LocalTxCapability,
        OutboxCapability, PartitionKeyStrategy, ReconcileBlock, SagaBlock, SagaStep, Schemas,
        SubscriberReadiness, Subscription, SubscriptionTopology, WorkflowCapability,
    };
    use crate::testutil::unique_tmp;
    use rstest::rstest;
    use std::path::PathBuf;

    fn manifest(
        kind: ContractKind,
        level: ConsistencyLevel,
        owner: ContractOwner,
        schemas: Schemas,
    ) -> ContractManifest {
        ContractManifest {
            id: "seed.x".to_string(),
            kind,
            domain: "_seed".to_string(),
            version: "v1".to_string(),
            owner,
            consistency_level: level,
            lifecycle: Lifecycle::Draft,
            schemas,
            endpoints: None,
            path: None,
            method: None,
            topic: None,
            delivery: None,
            saga: None,
            command: None,
            reconcile: None,
            effect_profile: None,
            subscriptions: Vec::new(),
            capabilities: Capabilities::default(),
        }
    }

    fn public_http_endpoints() -> Endpoints {
        Endpoints {
            http: Some(HttpEndpoint {
                auth: Some(HttpAuth {
                    mode: HttpAuthMode::Public,
                    reason: Some("public endpoint".to_string()),
                    permission: None,
                }),
                resource: None,
                self_scoped: false,
                resource_sharing: None,
                headers: BTreeMap::from([(
                    "X-Tenant-ID".to_string(),
                    HttpHeaderMode::PopulateOnly,
                )]),
                projection: None,
            }),
        }
    }

    fn one_subscription() -> Subscription {
        Subscription {
            consumer: "audit".to_string(),
            group: "audit.session-created".to_string(),
            topology: SubscriptionTopology {
                partition_key: PartitionKeyStrategy::None,
                readiness: SubscriberReadiness::Required,
            },
        }
    }

    fn http_schemas() -> Schemas {
        Schemas {
            request: Some("request.schema.json".to_string()),
            response: Some("response.schema.json".to_string()),
            payload: None,
        }
    }

    fn payload_schemas() -> Schemas {
        Schemas {
            payload: Some("payload.schema.json".to_string()),
            ..Schemas::default()
        }
    }

    fn local_tx_capability() -> Capabilities {
        Capabilities {
            local_tx: Some(LocalTxCapability {
                boundary: LocalTxBoundary::SingleDomain,
                tx_model: LocalTxModel::TenantScopedUow,
                retry: LocalTxRetry::BoundedTransient,
                commit_unknown: LocalTxCommitUnknown::NotRetryable,
            }),
            ..Capabilities::default()
        }
    }

    fn effect_profile(effects: &[EffectKind]) -> Option<EffectProfile> {
        Some(EffectProfile {
            effects: effects.to_vec(),
        })
    }

    fn outbox_fact_capability() -> Capabilities {
        Capabilities {
            outbox: Some(OutboxCapability {
                role: OutboxRole::Fact,
                atomicity: None,
                emits: Vec::new(),
            }),
            ..Capabilities::default()
        }
    }

    fn outbox_command_capability() -> Capabilities {
        Capabilities {
            outbox: Some(OutboxCapability {
                role: OutboxRole::Command,
                atomicity: None,
                emits: Vec::new(),
            }),
            ..Capabilities::default()
        }
    }

    fn outbox_producer_capability(emits: &[&str]) -> Capabilities {
        Capabilities {
            outbox: Some(OutboxCapability {
                role: OutboxRole::Producer,
                atomicity: Some(OutboxAtomicity::SameTransaction),
                emits: emits.iter().map(|s| (*s).to_string()).collect(),
            }),
            ..Capabilities::default()
        }
    }

    fn workflow_saga_capability() -> Capabilities {
        Capabilities {
            workflow: Some(WorkflowCapability {
                mode: WorkflowMode::Saga,
                inputs: Vec::new(),
                ordering: None,
                checkpoint: None,
                replay: None,
            }),
            ..Capabilities::default()
        }
    }

    fn workflow_projection_capability() -> Capabilities {
        workflow_projection_capability_with_inputs(&["identity.session-created"])
    }

    fn workflow_projection_capability_with_inputs(inputs: &[&str]) -> Capabilities {
        Capabilities {
            workflow: Some(WorkflowCapability {
                mode: WorkflowMode::Projection,
                inputs: inputs.iter().map(|s| (*s).to_string()).collect(),
                ordering: Some(WorkflowOrdering::SerialInOrder),
                checkpoint: Some(WorkflowRequirement::Required),
                replay: Some(WorkflowRequirement::Required),
            }),
            ..Capabilities::default()
        }
    }

    fn device_latent_capability() -> Capabilities {
        Capabilities {
            device_latent: Some(DeviceLatentCapability {
                loop_kind: DeviceLatentLoop::Reconcile,
            }),
            ..Capabilities::default()
        }
    }

    fn valid_reconcile_block() -> ReconcileBlock {
        ReconcileBlock {
            tenancy: DeviceLatentTenancy::TenantScoped,
            trigger: DeviceLatentTrigger::Interval,
            fencing: DeviceLatentFencing::Required,
            late_message_policy: DeviceLatentLateMessagePolicy::Idempotent,
        }
    }

    /// 合法 saga block（1 step、reverse、非负 duration）——R10 绿基线，红用例在其上变异。
    fn valid_saga_block() -> SagaBlock {
        SagaBlock {
            steps: vec![SagaStep {
                name: "reserve_funds".to_string(),
                output_schema: "reserve.schema.json".to_string(),
            }],
            compensation_order: CompensationOrder::Reverse,
            retry_millis: 1000,
            timeout_millis: 5000,
        }
    }

    /// saga 契约骨架（kind=saga / L3 / domain owner / payload schema），按需挂 saga block。
    fn saga_manifest(block: Option<SagaBlock>) -> ContractManifest {
        let mut m = manifest(
            ContractKind::Saga,
            ConsistencyLevel::WorkflowEventual,
            ContractOwner::Domain("billing".to_string()),
            payload_schemas(),
        );
        m.domain = "billing".to_string();
        m.id = "billing.checkout".to_string();
        m.saga = block;
        m
    }

    fn discovered(m: ContractManifest, dir: PathBuf) -> DiscoveredContract {
        DiscoveredContract {
            path_kind: m.kind.as_dir().to_string(),
            path_domain: m.domain.clone(),
            path_version: m.version.clone(),
            slug: None,
            dir,
            manifest: m,
        }
    }

    #[test]
    fn green_http_contract_has_no_findings() -> anyhow::Result<()> {
        // anti-vacuity（正向）：全合法契约不产生任何 finding。schema 带合法 root title（R13 ⓪ 必填）。
        let dir = unique_tmp("validate");
        std::fs::create_dir_all(&dir)?;
        std::fs::write(dir.join("request.schema.json"), r#"{"title":"GreenReq"}"#)?;
        std::fs::write(dir.join("response.schema.json"), r#"{"title":"GreenResp"}"#)?;
        let m = manifest(
            ContractKind::Http,
            ConsistencyLevel::LocalOnly,
            ContractOwner::Framework,
            http_schemas(),
        );
        let findings = validate_contract(&discovered(m, dir.clone()));
        let _ = std::fs::remove_dir_all(&dir);
        assert!(findings.is_empty(), "{findings:?}");
        Ok(())
    }

    /// R17 wiring：声明 schema 内非法 `x-protection` block → `Rule::SchemaProtection` finding，
    /// detail 携文件名 + JSON 指针（细粒度 block 语义在 `protection.rs` 单测覆盖，此处只验装配）。
    #[test]
    fn r17_invalid_protection_block_reports_schema_protection() -> anyhow::Result<()> {
        let dir = unique_tmp("validate-protection");
        std::fs::create_dir_all(&dir)?;
        std::fs::write(
            dir.join("request.schema.json"),
            r#"{"title":"Req","type":"object","properties":{"value":{"type":"string","x-protection":{"atRest":"encrypt"}}}}"#,
        )?;
        std::fs::write(dir.join("response.schema.json"), r#"{"title":"Resp"}"#)?;
        let m = manifest(
            ContractKind::Http,
            ConsistencyLevel::LocalOnly,
            ContractOwner::Framework,
            http_schemas(),
        );
        let findings = rule_schema_protection(&discovered(m, dir.clone()), "http/_seed/v1");
        let _ = std::fs::remove_dir_all(&dir);
        assert!(
            findings.iter().all(|f| f.rule == Rule::SchemaProtection),
            "{findings:?}"
        );
        assert!(
            findings.iter().any(|f| f.detail.contains("keyScope")),
            "{findings:?}"
        );
        Ok(())
    }

    /// R17 anti-vacuity：合法 `x-protection` block → 零 R17 finding（守卫真会沉默）。
    #[test]
    fn r17_valid_protection_block_is_clean() -> anyhow::Result<()> {
        let dir = unique_tmp("validate-protection-ok");
        std::fs::create_dir_all(&dir)?;
        std::fs::write(
            dir.join("request.schema.json"),
            r#"{"title":"Req","type":"object","properties":{"value":{"type":"string","x-protection":{"atRest":"encrypt","keyScope":"tenant","aad":["tenant","configKey","field","schemaVersion"]}}}}"#,
        )?;
        std::fs::write(dir.join("response.schema.json"), r#"{"title":"Resp"}"#)?;
        let m = manifest(
            ContractKind::Http,
            ConsistencyLevel::LocalOnly,
            ContractOwner::Framework,
            http_schemas(),
        );
        let findings = rule_schema_protection(&discovered(m, dir.clone()), "http/_seed/v1");
        let _ = std::fs::remove_dir_all(&dir);
        assert!(findings.is_empty(), "{findings:?}");
        Ok(())
    }

    #[test]
    fn r1_saga_must_be_workflow_eventual() {
        let m = manifest(
            ContractKind::Saga,
            ConsistencyLevel::LocalTx,
            ContractOwner::Domain("identity".to_string()),
            Schemas {
                payload: Some("payload.schema.json".to_string()),
                ..Schemas::default()
            },
        );
        let f = rule_saga_consistency(&m, "x");
        assert_eq!(f.as_ref().map(|f| f.rule), Some(Rule::SagaConsistency));
        assert_eq!(
            f.map(|f| f.subject),
            Some("x".to_string()),
            "subject 须为传入 label"
        );
    }

    #[test]
    fn r1_saga_l3_ok() {
        let m = manifest(
            ContractKind::Saga,
            ConsistencyLevel::WorkflowEventual,
            ContractOwner::Domain("identity".to_string()),
            Schemas {
                payload: Some("payload.schema.json".to_string()),
                ..Schemas::default()
            },
        );
        assert!(rule_saga_consistency(&m, "x").is_none());
    }

    /// 测试辅助：command 契约骨架（request schema，level 可变）。
    fn command_manifest(level: ConsistencyLevel) -> ContractManifest {
        let mut m = manifest(
            ContractKind::Command,
            level,
            ContractOwner::Framework,
            Schemas {
                request: Some("request.schema.json".to_string()),
                ..Schemas::default()
            },
        );
        m.id = "seed.do-thing".to_string();
        m.command = Some(crate::contract::manifest::CommandBlock {
            journal: crate::contract::manifest::CommandJournalPolicy::Required,
        });
        m
    }

    #[test]
    fn r24_command_policy_is_mandatory_and_scoped() {
        let mut command = command_manifest(ConsistencyLevel::OutboxFact);
        command.command = None;
        assert_eq!(
            rule_command_policy(&command, "command/_seed/v1").map(|f| f.rule),
            Some(Rule::CommandPolicy)
        );

        let mut event = manifest(
            ContractKind::Event,
            ConsistencyLevel::OutboxFact,
            ContractOwner::Framework,
            payload_schemas(),
        );
        event.command = Some(crate::contract::manifest::CommandBlock {
            journal: crate::contract::manifest::CommandJournalPolicy::None,
        });
        assert_eq!(
            rule_command_policy(&event, "event/_seed/v1").map(|f| f.rule),
            Some(Rule::CommandPolicy)
        );
    }

    /// R15 红向（#1124 F6）：command + 非 OutboxFact（如 LocalTx）→ CommandConsistency，subject=label。
    #[test]
    fn r15_command_must_be_outboxfact() {
        let m = command_manifest(ConsistencyLevel::LocalTx);
        let f = rule_command_consistency(&m, "command/_seed/v1");
        assert_eq!(
            f.as_ref().map(|f| f.rule),
            Some(Rule::CommandConsistency),
            "command 非 OutboxFact 应报 R15"
        );
        assert_eq!(f.map(|f| f.subject), Some("command/_seed/v1".to_string()));
    }

    /// R15 绿向：command + OutboxFact → 通过；非 command kind（event + 任意 level）→ R15 不适用、不误报。
    #[test]
    fn r15_command_outboxfact_ok_and_noncommand_unaffected() {
        assert!(
            rule_command_consistency(&command_manifest(ConsistencyLevel::OutboxFact), "x")
                .is_none(),
            "command + OutboxFact 应通过"
        );
        // anti-vacuity（非 command kind 不触 R15）：event + LocalTx 不报。
        let ev = manifest(
            ContractKind::Event,
            ConsistencyLevel::LocalTx,
            ContractOwner::Framework,
            payload_schemas(),
        );
        assert!(
            rule_command_consistency(&ev, "x").is_none(),
            "非 command kind 不应触 R15"
        );
    }

    /// R2（#1124）：kind=Command + owner=Framework → **允许**（command 是 framework-neutral 分发机制）。
    /// anti-vacuity 对照见 `r2_framework_saga_rejected`（saga 仍拒）。
    #[test]
    fn r2_framework_command_allowed() {
        let m = manifest(
            ContractKind::Command,
            ConsistencyLevel::OutboxFact,
            ContractOwner::Framework,
            Schemas {
                request: Some("request.schema.json".to_string()),
                ..Schemas::default()
            },
        );
        assert!(
            rule_framework_kind(&m, "x").is_none(),
            "framework-owned command 应允许（#1124）"
        );
    }

    /// R2 新增：kind=Saga + owner=Framework → 应触发 FrameworkKind。
    #[test]
    fn r2_framework_saga_rejected() {
        let m = manifest(
            ContractKind::Saga,
            ConsistencyLevel::WorkflowEventual,
            ContractOwner::Framework,
            Schemas {
                payload: Some("payload.schema.json".to_string()),
                ..Schemas::default()
            },
        );
        assert_eq!(
            rule_framework_kind(&m, "x").map(|f| f.rule),
            Some(Rule::FrameworkKind)
        );
    }

    #[test]
    fn r2_framework_http_ok_and_domain_command_ok() {
        let http = manifest(
            ContractKind::Http,
            ConsistencyLevel::LocalOnly,
            ContractOwner::Framework,
            http_schemas(),
        );
        assert!(rule_framework_kind(&http, "x").is_none());
        let cmd = manifest(
            ContractKind::Command,
            ConsistencyLevel::LocalTx,
            ContractOwner::Domain("identity".to_string()),
            Schemas {
                request: Some("request.schema.json".to_string()),
                ..Schemas::default()
            },
        );
        assert!(rule_framework_kind(&cmd, "x").is_none());
    }

    /// R3 参数化：各段不符 / 三段全符。
    /// 每 case：(path_kind, path_domain, path_version, manifest_domain, manifest_version, expect_finding)
    #[rstest]
    // 全符 → 无 finding
    #[case("http", "_seed", "v1", "_seed", "v1", false)]
    // kind 段不符
    #[case("event", "_seed", "v1", "_seed", "v1", true)]
    // domain 段不符
    #[case("http", "other", "v1", "_seed", "v1", true)]
    // version 段不符
    #[case("http", "_seed", "v2", "_seed", "v1", true)]
    fn r3_path_match_parametrized(
        #[case] path_kind: &str,
        #[case] path_domain: &str,
        #[case] path_version: &str,
        #[case] manifest_domain: &str,
        #[case] manifest_version: &str,
        #[case] expect_finding: bool,
    ) {
        let m = manifest(
            ContractKind::Http,
            ConsistencyLevel::LocalOnly,
            ContractOwner::Framework,
            http_schemas(),
        );
        let mut c = discovered(m, PathBuf::from("/x"));
        c.manifest.domain = manifest_domain.to_string();
        c.manifest.version = manifest_version.to_string();
        c.path_kind = path_kind.to_string();
        c.path_domain = path_domain.to_string();
        c.path_version = path_version.to_string();
        let result = rule_path_match(&c, "x");
        assert_eq!(
            result.map(|f| f.rule),
            if expect_finding {
                Some(Rule::PathMismatch)
            } else {
                None
            }
        );
    }

    #[test]
    fn r4_command_needs_request() {
        let m = manifest(
            ContractKind::Command,
            ConsistencyLevel::LocalTx,
            ContractOwner::Domain("identity".to_string()),
            Schemas::default(), // 无 request
        );
        let findings = rule_schema_shape(&m, "x");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule, Rule::SchemaShape);
        assert_eq!(findings[0].subject, "x", "subject 须为传入 label");
    }

    #[test]
    fn r4_saga_needs_payload() {
        let m = manifest(
            ContractKind::Saga,
            ConsistencyLevel::WorkflowEventual,
            ContractOwner::Domain("identity".to_string()),
            Schemas::default(), // 无 payload
        );
        let findings = rule_schema_shape(&m, "x");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule, Rule::SchemaShape);
    }

    #[test]
    fn r4_http_missing_response_shape() {
        let m = manifest(
            ContractKind::Http,
            ConsistencyLevel::LocalOnly,
            ContractOwner::Framework,
            Schemas {
                request: Some("request.schema.json".to_string()),
                ..Schemas::default()
            },
        );
        let findings = rule_schema_shape(&m, "x");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule, Rule::SchemaShape);
    }

    #[test]
    fn r4_event_needs_payload() {
        let m = manifest(
            ContractKind::Event,
            ConsistencyLevel::OutboxFact,
            ContractOwner::Framework,
            Schemas::default(),
        );
        let findings = rule_schema_shape(&m, "x");
        assert_eq!(
            findings
                .iter()
                .filter(|f| f.rule == Rule::SchemaShape)
                .count(),
            1
        );
    }

    #[test]
    fn r5_missing_schema_file_detected() -> anyhow::Result<()> {
        let dir = unique_tmp("validate");
        std::fs::create_dir_all(&dir)?;
        std::fs::write(dir.join("request.schema.json"), "{}")?; // 只建 request，缺 response
        let m = manifest(
            ContractKind::Http,
            ConsistencyLevel::LocalOnly,
            ContractOwner::Framework,
            http_schemas(),
        );
        let findings = rule_schema_files_exist(&discovered(m, dir.clone()), "x");
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule, Rule::MissingSchema);
        assert_eq!(findings[0].subject, "x", "subject 须为传入 label");
        Ok(())
    }

    #[test]
    fn r6_unsafe_schema_path_dotdot_rejected() {
        let m = manifest(
            ContractKind::Http,
            ConsistencyLevel::LocalOnly,
            ContractOwner::Framework,
            Schemas {
                request: Some("../x/request.schema.json".to_string()),
                response: Some("response.schema.json".to_string()),
                ..Schemas::default()
            },
        );
        let findings = rule_unsafe_schema_path(&m, "x");
        assert!(!findings.is_empty());
        assert!(findings.iter().all(|f| f.rule == Rule::UnsafeSchemaPath));
    }

    #[test]
    fn r6_safe_schema_path_ok() {
        let m = manifest(
            ContractKind::Http,
            ConsistencyLevel::LocalOnly,
            ContractOwner::Framework,
            http_schemas(),
        );
        let findings = rule_unsafe_schema_path(&m, "x");
        assert!(findings.is_empty());
    }

    /// R7 参数化红用例：domain/version/id 各非法形态须触发 IdentSyntax。
    /// case：(domain, version, id)
    #[rstest]
    #[case("../evil", "v1", "seed.echo")] // domain 含路径分量
    #[case("Bad", "v1", "seed.echo")] // domain 大写
    #[case("9x", "v1", "seed.echo")] // domain 数字开头
    #[case("_seed", "1", "seed.echo")] // version 非 v{N}
    #[case("_seed", "v", "seed.echo")] // version 缺数字
    #[case("_seed", "v1", "Seed.Echo")] // id 大写
    #[case("_seed", "v1", "")] // id 空
    #[case("_seed", "v1", "seed.")] // id 尾段空
    fn r7_ident_syntax_rejects_malformed(
        #[case] domain: &str,
        #[case] version: &str,
        #[case] id: &str,
    ) {
        let mut m = manifest(
            ContractKind::Http,
            ConsistencyLevel::LocalOnly,
            ContractOwner::Framework,
            http_schemas(),
        );
        m.domain = domain.to_string();
        m.version = version.to_string();
        m.id = id.to_string();
        let findings = rule_ident_syntax(&m, "x");
        assert!(!findings.is_empty(), "应触发 IdentSyntax");
        assert!(findings.iter().all(|f| f.rule == Rule::IdentSyntax));
    }

    /// R7 owner 红用例：Domain 空串 / `_` 前缀保留段 / 大写须触发 IdentSyntax。
    #[rstest]
    #[case("")]
    #[case("_seed")]
    #[case("_framework")] // 作为 Domain 出现（非 sentinel 解析路径）须拒
    #[case("Bad")]
    fn r7_owner_domain_rejects_malformed(#[case] owner: &str) {
        let m = manifest(
            ContractKind::Http,
            ConsistencyLevel::LocalOnly,
            ContractOwner::Domain(owner.to_string()),
            http_schemas(),
        );
        let findings = rule_ident_syntax(&m, "x");
        assert!(findings.iter().any(|f| f.rule == Rule::IdentSyntax));
    }

    /// R7 anti-vacuity（正向）：合法 framework / domain 契约不产生 IdentSyntax finding。
    #[test]
    fn r7_valid_fields_ok() {
        let fw = manifest(
            ContractKind::Http,
            ConsistencyLevel::LocalOnly,
            ContractOwner::Framework,
            http_schemas(),
        );
        assert!(rule_ident_syntax(&fw, "x").is_empty());
        let dom = manifest(
            ContractKind::Command,
            ConsistencyLevel::LocalTx,
            ContractOwner::Domain("identity".to_string()),
            Schemas {
                request: Some("request.schema.json".to_string()),
                ..Schemas::default()
            },
        );
        assert!(rule_ident_syntax(&dom, "x").is_empty());
        // 连字符 id（RSS 事件命名约定，如 config.entry-upserted）须合法。
        let mut hyphen = dom.clone();
        hyphen.id = "config.entry-upserted".to_string();
        assert!(
            rule_ident_syntax(&hyphen, "x").is_empty(),
            "连字符 id 应合法"
        );
    }

    /// R7 path 红用例：非法 http path 形态须触发 IdentSyntax（收口注入 / 逃逸面）。
    #[rstest]
    #[case("")] // 空
    #[case("/")] // 裸 /
    #[case("relative/x")] // 非绝对
    #[case("//evil.com/x")] // 协议相对 URL
    #[case("/api/v1/../secret")] // .. 逃逸
    #[case("/api/v1/ x")] // 含空白
    fn r7_bad_path_rejected(#[case] path: &str) {
        let mut m = manifest(
            ContractKind::Http,
            ConsistencyLevel::LocalOnly,
            ContractOwner::Framework,
            http_schemas(),
        );
        m.path = Some(path.to_string());
        let findings = rule_ident_syntax(&m, "x");
        assert!(
            findings.iter().any(|f| f.rule == Rule::IdentSyntax),
            "path {path:?} 应触发 IdentSyntax"
        );
    }

    /// R7 topic 红用例：非点分小写 topic 须触发 IdentSyntax（wire routing key 收口）。
    #[rstest]
    #[case("UPPER.case")]
    #[case("../evil")]
    #[case("trailing.")]
    fn r7_bad_topic_rejected(#[case] topic: &str) {
        let mut m = manifest(
            ContractKind::Event,
            ConsistencyLevel::OutboxFact,
            ContractOwner::Framework,
            payload_schemas(),
        );
        m.topic = Some(topic.to_string());
        let findings = rule_ident_syntax(&m, "x");
        assert!(
            findings.iter().any(|f| f.rule == Rule::IdentSyntax),
            "topic {topic:?} 应触发 IdentSyntax"
        );
    }

    /// R7 anti-vacuity：合法 path / topic 不触发。
    #[test]
    fn r7_valid_path_topic_ok() {
        let mut http = manifest(
            ContractKind::Http,
            ConsistencyLevel::LocalOnly,
            ContractOwner::Framework,
            http_schemas(),
        );
        http.path = Some("/api/v1/_seed/echo".to_string());
        assert!(rule_ident_syntax(&http, "x").is_empty());
        let mut event = manifest(
            ContractKind::Event,
            ConsistencyLevel::OutboxFact,
            ContractOwner::Framework,
            payload_schemas(),
        );
        event.topic = Some("seed.thing-happened".to_string());
        assert!(rule_ident_syntax(&event, "x").is_empty());
    }

    /// R7 subscription 红用例（review #216 F6）：consumer / group 非法形态须触发 IdentSyntax——
    /// 二者拼进 generated 注册 glue 的 Rust 字符串字面量，含引号 / 大写 / 空 / 尾段空均须拒（防注入 + 形态）。
    /// case：(consumer, group)
    #[rstest]
    #[case("Audit", "audit.session-created")] // consumer 大写
    #[case("audit\"; evil", "audit.session-created")] // consumer 含引号（codegen 注入面）
    #[case("", "audit.session-created")] // consumer 空
    #[case("audit", "Audit.Session")] // group 大写
    #[case("audit", "audit\"; evil")] // group 含引号（codegen 注入面）
    #[case("audit", "")] // group 空
    #[case("audit", "trailing.")] // group 尾段空
    fn r7_subscription_syntax_rejects_malformed(#[case] consumer: &str, #[case] group: &str) {
        let mut m = manifest(
            ContractKind::Event,
            ConsistencyLevel::OutboxFact,
            ContractOwner::Domain("identity".to_string()),
            payload_schemas(),
        );
        m.subscriptions = vec![Subscription {
            consumer: consumer.to_string(),
            group: group.to_string(),
            topology: SubscriptionTopology {
                partition_key: PartitionKeyStrategy::None,
                readiness: SubscriberReadiness::Required,
            },
        }];
        let findings = rule_ident_syntax(&m, "x");
        assert!(
            findings.iter().any(|f| f.rule == Rule::IdentSyntax),
            "consumer={consumer:?} group={group:?} 应触发 IdentSyntax"
        );
    }

    /// R7 subscription anti-vacuity（正向）：合法 consumer / group 不触发 IdentSyntax。
    #[test]
    fn r7_valid_subscription_ok() {
        let mut m = manifest(
            ContractKind::Event,
            ConsistencyLevel::OutboxFact,
            ContractOwner::Domain("identity".to_string()),
            payload_schemas(),
        );
        m.subscriptions = vec![one_subscription()];
        assert!(
            rule_ident_syntax(&m, "x").is_empty(),
            "合法 subscription 不应触发 IdentSyntax"
        );
    }

    /// `is_dotted_id` 谓词隔离 accept/reject 表——锁 R7 dotted-id 文法在 xtask 边界的行为
    /// （此前仅经 `rule_ident_syntax` 间接覆盖 id/topic/group）。用例集对齐 consistency 侧文法单源
    /// `is_canonical_topic_name` 的接受/拒绝集（只读治理谓词，不取得 authoring authority）。
    /// anti-vacuity：含正反两类用例；禁与被委托谓词做自指等价断言，一律硬编码期望布尔。
    #[rstest]
    #[case("seed.thing-happened", true)]
    #[case("session.created", true)]
    #[case("a.b", true)]
    #[case("foo", true)] // 单段
    #[case("rss.session.created", true)]
    #[case("domain1.event-2.v3", true)]
    #[case("config.entry-upserted", true)] // 连字符（RSS 事件命名约定）
    #[case("", false)] // 空
    #[case(".x", false)] // 前导点 → 空段
    #[case("x.", false)] // 尾随点 → 空段
    #[case("a..b", false)] // 连续点 → 空段
    #[case("Foo", false)] // 段首大写
    #[case("foo.Bar", false)] // 次段大写
    #[case("1a", false)] // 段首数字
    #[case("-a", false)] // 段首连字符
    #[case("a_b", false)] // 下划线不在 [a-z0-9-]
    #[case("a b", false)] // 空格
    #[case("a.b ", false)] // 段含空格
    fn r7_is_dotted_id_accepts_rejects(#[case] input: &str, #[case] expected: bool) {
        assert_eq!(is_dotted_id(input), expected, "input={input:?}");
    }

    // ── R8 PerKindActiveFields（active 必填）──────────────────────────────

    #[test]
    fn r8_active_http_missing_path_method() {
        let mut m = manifest(
            ContractKind::Http,
            ConsistencyLevel::LocalOnly,
            ContractOwner::Framework,
            http_schemas(),
        );
        m.lifecycle = Lifecycle::Active; // 无 path/method
        let findings = rule_perkind_active_fields(&m, "x");
        assert_eq!(findings.len(), 2, "应缺 path + method 两项");
        assert!(findings.iter().all(|f| f.rule == Rule::PerKindActiveFields));
        assert!(
            findings.iter().all(|f| f.subject == "x"),
            "subject 须为 label"
        );
    }

    #[test]
    fn r8_active_event_missing_topic_delivery() {
        let mut m = manifest(
            ContractKind::Event,
            ConsistencyLevel::OutboxFact,
            ContractOwner::Framework,
            payload_schemas(),
        );
        m.lifecycle = Lifecycle::Active;
        let findings = rule_perkind_active_fields(&m, "x");
        assert_eq!(findings.len(), 2, "应缺 topic + delivery 两项");
        assert!(findings.iter().all(|f| f.rule == Rule::PerKindActiveFields));
    }

    #[test]
    fn r8_saga_block_not_active_field_but_r10_requires() {
        // F1：saga block 是结构语义、非「active 发布接线字段」——R8 不管（不论 lifecycle）；
        // 无条件必填由 R10 守。active saga 缺 block ⇒ R8 空、R10 报。
        let mut m = saga_manifest(None);
        m.lifecycle = Lifecycle::Active;
        assert!(
            rule_perkind_active_fields(&m, "x").is_empty(),
            "saga block 不应在 R8 active 集"
        );
        let r10 = rule_saga_block(&m, "x");
        assert_eq!(r10.len(), 1, "R10 应无条件要求 saga block");
        assert_eq!(r10[0].rule, Rule::SagaBlock);
    }

    #[test]
    fn r8_active_full_ok_and_draft_exempt() {
        // active http 全填 → 无 finding。
        let mut active = manifest(
            ContractKind::Http,
            ConsistencyLevel::LocalOnly,
            ContractOwner::Framework,
            http_schemas(),
        );
        active.lifecycle = Lifecycle::Active;
        active.path = Some("/api/v1/_seed/echo".to_string());
        active.method = Some(HttpMethod::Post);
        active.endpoints = Some(public_http_endpoints());
        assert!(rule_perkind_active_fields(&active, "x").is_empty());
        // draft 缺字段 → 豁免（种子 draft 不受约束）。
        let draft = manifest(
            ContractKind::Http,
            ConsistencyLevel::LocalOnly,
            ContractOwner::Framework,
            http_schemas(),
        );
        assert!(rule_perkind_active_fields(&draft, "x").is_empty());
        // deprecated 缺字段 → 同豁免（注释声明的 deprecated 豁免须有 synthetic 绿证明）。
        let mut deprecated = draft.clone();
        deprecated.lifecycle = Lifecycle::Deprecated;
        assert!(rule_perkind_active_fields(&deprecated, "x").is_empty());
        // command active 全填 topic → 无 finding（#1124：active command 必有 topic 路由出口）。
        let mut cmd = manifest(
            ContractKind::Command,
            ConsistencyLevel::OutboxFact,
            ContractOwner::Domain("identity".to_string()),
            Schemas {
                request: Some("request.schema.json".to_string()),
                ..Schemas::default()
            },
        );
        cmd.lifecycle = Lifecycle::Active;
        cmd.topic = Some("identity.commands.revoke-session".to_string());
        assert!(rule_perkind_active_fields(&cmd, "x").is_empty());
    }

    #[test]
    fn r18_active_http_without_auth_fails() {
        let mut m = manifest(
            ContractKind::Http,
            ConsistencyLevel::LocalOnly,
            ContractOwner::Framework,
            http_schemas(),
        );
        m.lifecycle = Lifecycle::Active;
        m.path = Some("/api/v1/_seed/echo".to_string());
        m.method = Some(HttpMethod::Post);
        let findings = rule_http_auth(&m, "x");
        assert!(
            findings.iter().any(|f| f.rule == Rule::HttpAuth),
            "{findings:?}"
        );
    }

    #[test]
    fn r18_public_http_empty_reason_fails() {
        let mut m = manifest(
            ContractKind::Http,
            ConsistencyLevel::LocalOnly,
            ContractOwner::Framework,
            http_schemas(),
        );
        m.lifecycle = Lifecycle::Active;
        m.path = Some("/api/v1/_seed/echo".to_string());
        m.method = Some(HttpMethod::Post);
        m.endpoints = Some(Endpoints {
            http: Some(HttpEndpoint {
                auth: Some(HttpAuth {
                    mode: HttpAuthMode::Public,
                    reason: Some(" ".to_string()),
                    permission: None,
                }),
                resource: None,
                self_scoped: false,
                resource_sharing: None,
                headers: BTreeMap::from([(
                    "X-Tenant-ID".to_string(),
                    HttpHeaderMode::PopulateOnly,
                )]),
                projection: None,
            }),
        });
        let findings = rule_http_auth(&m, "x");
        assert!(
            findings
                .iter()
                .any(|f| f.detail.contains("必须声明非空 reason")),
            "{findings:?}"
        );
    }

    #[test]
    fn r18_permission_mode_forbids_reason() {
        let mut m = manifest(
            ContractKind::Http,
            ConsistencyLevel::LocalOnly,
            ContractOwner::Framework,
            http_schemas(),
        );
        m.lifecycle = Lifecycle::Active;
        m.path = Some("/api/v1/_seed/echo".to_string());
        m.method = Some(HttpMethod::Post);
        m.endpoints = Some(Endpoints {
            http: Some(HttpEndpoint {
                auth: Some(HttpAuth {
                    mode: HttpAuthMode::Permission,
                    reason: Some("not allowed".to_string()),
                    permission: Some("identity:profile:read".to_string()),
                }),
                resource: None,
                self_scoped: false,
                resource_sharing: None,
                headers: BTreeMap::new(),
                projection: None,
            }),
        });
        let findings = rule_http_auth(&m, "x");
        assert!(
            findings.iter().any(|f| f.detail.contains("禁止 reason")),
            "{findings:?}"
        );
    }

    #[test]
    fn r18_permission_self_scoped_is_allowed() {
        let mut m = manifest(
            ContractKind::Http,
            ConsistencyLevel::LocalOnly,
            ContractOwner::Framework,
            http_schemas(),
        );
        m.lifecycle = Lifecycle::Active;
        m.path = Some("/api/v1/_seed/profile".to_string());
        m.method = Some(HttpMethod::Get);
        m.endpoints = Some(Endpoints {
            http: Some(HttpEndpoint {
                auth: Some(HttpAuth {
                    mode: HttpAuthMode::Permission,
                    reason: None,
                    permission: Some("identity:profile:read".to_string()),
                }),
                resource: None,
                self_scoped: true,
                resource_sharing: None,
                headers: BTreeMap::new(),
                projection: None,
            }),
        });
        assert!(rule_http_auth(&m, "x").is_empty());
    }

    #[test]
    fn r18_permission_must_be_route_permission_catalog_value() {
        let mut m = manifest(
            ContractKind::Http,
            ConsistencyLevel::LocalOnly,
            ContractOwner::Framework,
            http_schemas(),
        );
        m.lifecycle = Lifecycle::Active;
        m.path = Some("/api/v1/_seed/profile".to_string());
        m.method = Some(HttpMethod::Get);
        m.endpoints = Some(Endpoints {
            http: Some(HttpEndpoint {
                auth: Some(HttpAuth {
                    mode: HttpAuthMode::Permission,
                    reason: None,
                    permission: Some("seed.profile.read".to_string()),
                }),
                resource: None,
                self_scoped: true,
                resource_sharing: None,
                headers: BTreeMap::new(),
                projection: None,
            }),
        });
        let findings = rule_http_auth(&m, "x");
        assert!(
            findings.iter().any(|f| f.detail.contains("闭值集")),
            "{findings:?}"
        );
    }

    #[test]
    fn r18_permission_rejects_surrounding_whitespace() {
        let mut m = manifest(
            ContractKind::Http,
            ConsistencyLevel::LocalOnly,
            ContractOwner::Framework,
            http_schemas(),
        );
        m.lifecycle = Lifecycle::Active;
        m.path = Some("/api/v1/_seed/profile".to_string());
        m.method = Some(HttpMethod::Get);
        m.endpoints = Some(Endpoints {
            http: Some(HttpEndpoint {
                auth: Some(HttpAuth {
                    mode: HttpAuthMode::Permission,
                    reason: None,
                    permission: Some(" identity:profile:read ".to_string()),
                }),
                resource: None,
                self_scoped: true,
                resource_sharing: None,
                headers: BTreeMap::new(),
                projection: None,
            }),
        });
        let findings = rule_http_auth(&m, "x");
        assert!(
            findings.iter().any(|f| f.detail.contains("精确匹配")),
            "{findings:?}"
        );
    }

    #[test]
    fn r18_permission_catalog_accepts_every_vocab_permission() {
        for permission in vocab::RoutePermissionId::ALL {
            assert!(
                route_permission_is_cataloged(permission.as_str()),
                "{} must be accepted by contract validation",
                permission.as_str()
            );
        }
    }

    #[test]
    fn r18_projection_fields_are_allowed() {
        let mut m = manifest(
            ContractKind::Http,
            ConsistencyLevel::LocalOnly,
            ContractOwner::Framework,
            http_schemas(),
        );
        m.lifecycle = Lifecycle::Active;
        m.path = Some("/api/v1/audit/entries".to_string());
        m.method = Some(HttpMethod::Get);
        m.endpoints = Some(Endpoints {
            http: Some(HttpEndpoint {
                auth: Some(HttpAuth {
                    mode: HttpAuthMode::Permission,
                    reason: None,
                    permission: Some("audit:read".to_string()),
                }),
                resource: None,
                self_scoped: false,
                resource_sharing: None,
                headers: BTreeMap::new(),
                projection: Some(HttpProjection {
                    fields: vec![
                        HttpProjectionField {
                            field: HttpProjectionFieldName::AuditActor,
                            permission: "audit:field:actor".to_string(),
                            obligation_key: "audit.actor".to_string(),
                            response_path: "data[].actor".to_string(),
                        },
                        HttpProjectionField {
                            field: HttpProjectionFieldName::AuditResourceId,
                            permission: "audit:field:resource_id".to_string(),
                            obligation_key: "audit.resource_id".to_string(),
                            response_path: "data[].resourceId".to_string(),
                        },
                    ],
                }),
            }),
        });
        assert!(rule_http_auth(&m, "x").is_empty());
    }

    #[test]
    fn r18_projection_permission_must_be_route_permission_catalog_value() {
        let mut m = manifest(
            ContractKind::Http,
            ConsistencyLevel::LocalOnly,
            ContractOwner::Framework,
            http_schemas(),
        );
        m.lifecycle = Lifecycle::Active;
        m.path = Some("/api/v1/audit/entries".to_string());
        m.method = Some(HttpMethod::Get);
        m.endpoints = Some(Endpoints {
            http: Some(HttpEndpoint {
                auth: Some(HttpAuth {
                    mode: HttpAuthMode::Permission,
                    reason: None,
                    permission: Some("audit:read".to_string()),
                }),
                resource: None,
                self_scoped: false,
                resource_sharing: None,
                headers: BTreeMap::new(),
                projection: Some(HttpProjection {
                    fields: vec![HttpProjectionField {
                        field: HttpProjectionFieldName::AuditActor,
                        permission: "audit:field:email".to_string(),
                        obligation_key: "audit.actor".to_string(),
                        response_path: "data[].actor".to_string(),
                    }],
                }),
            }),
        });
        let findings = rule_http_auth(&m, "x");
        assert!(
            findings.iter().any(|f| f.detail.contains("闭值集")),
            "{findings:?}"
        );
    }

    #[test]
    fn r18_projection_permission_rejects_surrounding_whitespace() {
        let mut m = manifest(
            ContractKind::Http,
            ConsistencyLevel::LocalOnly,
            ContractOwner::Framework,
            http_schemas(),
        );
        m.lifecycle = Lifecycle::Active;
        m.path = Some("/api/v1/audit/entries".to_string());
        m.method = Some(HttpMethod::Get);
        m.endpoints = Some(Endpoints {
            http: Some(HttpEndpoint {
                auth: Some(HttpAuth {
                    mode: HttpAuthMode::Permission,
                    reason: None,
                    permission: Some("audit:read".to_string()),
                }),
                resource: None,
                self_scoped: false,
                resource_sharing: None,
                headers: BTreeMap::new(),
                projection: Some(HttpProjection {
                    fields: vec![HttpProjectionField {
                        field: HttpProjectionFieldName::AuditActor,
                        permission: " audit:field:actor ".to_string(),
                        obligation_key: "audit.actor".to_string(),
                        response_path: "data[].actor".to_string(),
                    }],
                }),
            }),
        });
        let findings = rule_http_auth(&m, "x");
        assert!(
            findings.iter().any(|f| f.detail.contains("精确匹配")),
            "{findings:?}"
        );
    }

    #[test]
    fn r18_projection_duplicate_permission_fails() {
        let mut m = manifest(
            ContractKind::Http,
            ConsistencyLevel::LocalOnly,
            ContractOwner::Framework,
            http_schemas(),
        );
        m.lifecycle = Lifecycle::Active;
        m.path = Some("/api/v1/audit/entries".to_string());
        m.method = Some(HttpMethod::Get);
        m.endpoints = Some(Endpoints {
            http: Some(HttpEndpoint {
                auth: Some(HttpAuth {
                    mode: HttpAuthMode::Permission,
                    reason: None,
                    permission: Some("audit:read".to_string()),
                }),
                resource: None,
                self_scoped: false,
                resource_sharing: None,
                headers: BTreeMap::new(),
                projection: Some(HttpProjection {
                    fields: vec![
                        HttpProjectionField {
                            field: HttpProjectionFieldName::AuditActor,
                            permission: "audit:field:actor".to_string(),
                            obligation_key: "audit.actor".to_string(),
                            response_path: "data[].actor".to_string(),
                        },
                        HttpProjectionField {
                            field: HttpProjectionFieldName::AuditResourceId,
                            permission: "audit:field:actor".to_string(),
                            obligation_key: "audit.resource_id".to_string(),
                            response_path: "data[].resourceId".to_string(),
                        },
                    ],
                }),
            }),
        });
        let findings = rule_http_auth(&m, "x");
        assert!(
            findings.iter().any(|f| {
                f.rule == Rule::HttpProjectionCoverage
                    && f.detail.contains("permission")
                    && f.detail.contains("重复")
            }),
            "{findings:?}"
        );
    }

    #[test]
    fn r18_permission_resource_must_match_path_param() {
        let mut m = manifest(
            ContractKind::Http,
            ConsistencyLevel::LocalOnly,
            ContractOwner::Framework,
            http_schemas(),
        );
        m.lifecycle = Lifecycle::Active;
        m.path = Some("/api/v1/_seed/roles/{roleId}".to_string());
        m.method = Some(HttpMethod::Delete);
        m.endpoints = Some(Endpoints {
            http: Some(HttpEndpoint {
                auth: Some(HttpAuth {
                    mode: HttpAuthMode::Permission,
                    reason: None,
                    permission: Some("identity:role:revoke".to_string()),
                }),
                resource: Some("subject".to_string()),
                self_scoped: false,
                resource_sharing: None,
                headers: BTreeMap::new(),
                projection: None,
            }),
        });
        let findings = rule_http_auth(&m, "x");
        assert!(
            findings.iter().any(|f| f.detail.contains("必须匹配")),
            "{findings:?}"
        );
    }

    #[test]
    fn r18_resource_and_self_scoped_are_mutually_exclusive() {
        let mut m = manifest(
            ContractKind::Http,
            ConsistencyLevel::LocalOnly,
            ContractOwner::Framework,
            http_schemas(),
        );
        m.lifecycle = Lifecycle::Active;
        m.path = Some("/api/v1/_seed/roles/{roleId}".to_string());
        m.method = Some(HttpMethod::Delete);
        m.endpoints = Some(Endpoints {
            http: Some(HttpEndpoint {
                auth: Some(HttpAuth {
                    mode: HttpAuthMode::Permission,
                    reason: None,
                    permission: Some("identity:role:revoke".to_string()),
                }),
                resource: Some("roleId".to_string()),
                self_scoped: true,
                resource_sharing: None,
                headers: BTreeMap::new(),
                projection: None,
            }),
        });
        let findings = rule_http_auth(&m, "x");
        assert!(
            findings.iter().any(|f| f.detail.contains("互斥")),
            "{findings:?}"
        );
    }

    #[test]
    fn r18_public_route_forbids_self_scoped_metadata() {
        let mut m = manifest(
            ContractKind::Http,
            ConsistencyLevel::LocalOnly,
            ContractOwner::Framework,
            http_schemas(),
        );
        m.lifecycle = Lifecycle::Active;
        m.path = Some("/api/v1/_seed/echo".to_string());
        m.method = Some(HttpMethod::Post);
        m.endpoints = Some(Endpoints {
            http: Some(HttpEndpoint {
                auth: Some(HttpAuth {
                    mode: HttpAuthMode::Public,
                    reason: Some("public".to_string()),
                    permission: None,
                }),
                resource: None,
                self_scoped: true,
                resource_sharing: None,
                headers: BTreeMap::new(),
                projection: None,
            }),
        });
        let findings = rule_http_auth(&m, "x");
        assert!(
            findings
                .iter()
                .any(|f| f.detail.contains("禁止 selfScoped")),
            "{findings:?}"
        );
    }

    #[test]
    fn r18_public_route_forbids_resource_metadata() {
        let mut m = manifest(
            ContractKind::Http,
            ConsistencyLevel::LocalOnly,
            ContractOwner::Framework,
            http_schemas(),
        );
        m.lifecycle = Lifecycle::Active;
        m.path = Some("/api/v1/_seed/echo/{id}".to_string());
        m.method = Some(HttpMethod::Post);
        m.endpoints = Some(Endpoints {
            http: Some(HttpEndpoint {
                auth: Some(HttpAuth {
                    mode: HttpAuthMode::Public,
                    reason: Some("public".to_string()),
                    permission: None,
                }),
                resource: Some("id".to_string()),
                self_scoped: false,
                resource_sharing: None,
                headers: BTreeMap::new(),
                projection: None,
            }),
        });
        let findings = rule_http_auth(&m, "x");
        assert!(
            findings.iter().any(|f| f.detail.contains("禁止 resource")),
            "{findings:?}"
        );
    }

    #[test]
    fn r18_empty_resource_is_rejected() {
        let mut m = manifest(
            ContractKind::Http,
            ConsistencyLevel::LocalOnly,
            ContractOwner::Framework,
            http_schemas(),
        );
        m.lifecycle = Lifecycle::Active;
        m.path = Some("/api/v1/_seed/roles/{roleId}".to_string());
        m.method = Some(HttpMethod::Delete);
        m.endpoints = Some(Endpoints {
            http: Some(HttpEndpoint {
                auth: Some(HttpAuth {
                    mode: HttpAuthMode::Permission,
                    reason: None,
                    permission: Some("identity:role:revoke".to_string()),
                }),
                resource: Some(" ".to_string()),
                self_scoped: false,
                resource_sharing: None,
                headers: BTreeMap::new(),
                projection: None,
            }),
        });
        let findings = rule_http_auth(&m, "x");
        assert!(
            findings.iter().any(|f| f.detail.contains("必须为非空")),
            "{findings:?}"
        );
    }

    #[test]
    fn r18_global_resource_sharing_requires_reason_and_resource() {
        let mut m = manifest(
            ContractKind::Http,
            ConsistencyLevel::LocalOnly,
            ContractOwner::Framework,
            http_schemas(),
        );
        m.lifecycle = Lifecycle::Active;
        m.path = Some("/api/v1/_seed/roles/{roleId}".to_string());
        m.method = Some(HttpMethod::Delete);
        m.endpoints = Some(Endpoints {
            http: Some(HttpEndpoint {
                auth: Some(HttpAuth {
                    mode: HttpAuthMode::Permission,
                    reason: None,
                    permission: Some("identity:role:revoke".to_string()),
                }),
                resource: None,
                self_scoped: false,
                resource_sharing: Some(HttpResourceSharing {
                    mode: HttpResourceSharingMode::Global,
                    reason: Some(" ".to_string()),
                }),
                headers: BTreeMap::new(),
                projection: None,
            }),
        });
        let findings = rule_http_auth(&m, "x");
        assert!(
            findings
                .iter()
                .any(|f| f.detail.contains("mode=global") && f.detail.contains("reason")),
            "{findings:?}"
        );
        assert!(
            findings
                .iter()
                .any(|f| f.detail.contains("必须声明 endpoints.http.resource")),
            "{findings:?}"
        );
    }

    #[test]
    fn r18_resource_sharing_tenant_scoped_forbids_reason() {
        let mut m = manifest(
            ContractKind::Http,
            ConsistencyLevel::LocalOnly,
            ContractOwner::Framework,
            http_schemas(),
        );
        m.lifecycle = Lifecycle::Active;
        m.path = Some("/api/v1/_seed/roles/{roleId}".to_string());
        m.method = Some(HttpMethod::Delete);
        m.endpoints = Some(Endpoints {
            http: Some(HttpEndpoint {
                auth: Some(HttpAuth {
                    mode: HttpAuthMode::Permission,
                    reason: None,
                    permission: Some("identity:role:revoke".to_string()),
                }),
                resource: Some("roleId".to_string()),
                self_scoped: false,
                resource_sharing: Some(HttpResourceSharing {
                    mode: HttpResourceSharingMode::TenantScoped,
                    reason: Some("redundant".to_string()),
                }),
                headers: BTreeMap::new(),
                projection: None,
            }),
        });
        let findings = rule_http_auth(&m, "x");
        assert!(
            findings
                .iter()
                .any(|f| f.detail.contains("mode=tenantScoped") && f.detail.contains("禁止 reason")),
            "{findings:?}"
        );
    }

    #[test]
    fn r18_service_token_tenant_bound_header_mode_is_allowed() {
        let mut m = manifest(
            ContractKind::Http,
            ConsistencyLevel::LocalOnly,
            ContractOwner::Framework,
            http_schemas(),
        );
        m.lifecycle = Lifecycle::Active;
        m.path = Some("/api/v1/_seed/internal".to_string());
        m.method = Some(HttpMethod::Post);
        m.endpoints = Some(Endpoints {
            http: Some(HttpEndpoint {
                auth: Some(HttpAuth {
                    mode: HttpAuthMode::ServiceOwned,
                    reason: Some("internal service-token route".to_string()),
                    permission: None,
                }),
                resource: None,
                self_scoped: false,
                resource_sharing: None,
                headers: BTreeMap::from([(
                    "X-Tenant-ID".to_string(),
                    HttpHeaderMode::ServiceTokenTenantBound,
                )]),
                projection: None,
            }),
        });
        assert!(rule_http_auth(&m, "x").is_empty());
    }

    #[test]
    fn r18_service_token_tenant_bound_permission_mode_fails() {
        let mut m = manifest(
            ContractKind::Http,
            ConsistencyLevel::LocalOnly,
            ContractOwner::Framework,
            http_schemas(),
        );
        m.lifecycle = Lifecycle::Active;
        m.path = Some("/api/v1/_seed/internal".to_string());
        m.method = Some(HttpMethod::Post);
        m.endpoints = Some(Endpoints {
            http: Some(HttpEndpoint {
                auth: Some(HttpAuth {
                    mode: HttpAuthMode::Permission,
                    reason: None,
                    permission: Some("identity:policy:read".to_string()),
                }),
                resource: None,
                self_scoped: false,
                resource_sharing: None,
                headers: BTreeMap::from([(
                    "X-Tenant-ID".to_string(),
                    HttpHeaderMode::ServiceTokenTenantBound,
                )]),
                projection: None,
            }),
        });
        let findings = rule_http_auth(&m, "x");
        assert!(
            findings
                .iter()
                .any(|f| f.detail.contains("仅允许 serviceOwned")),
            "{findings:?}"
        );
    }

    #[test]
    fn r18_service_owned_without_tenant_bound_header_fails() {
        let mut m = manifest(
            ContractKind::Http,
            ConsistencyLevel::LocalOnly,
            ContractOwner::Framework,
            http_schemas(),
        );
        m.lifecycle = Lifecycle::Active;
        m.path = Some("/api/v1/_seed/internal".to_string());
        m.method = Some(HttpMethod::Post);
        m.endpoints = Some(Endpoints {
            http: Some(HttpEndpoint {
                auth: Some(HttpAuth {
                    mode: HttpAuthMode::ServiceOwned,
                    reason: Some("internal service-token route".to_string()),
                    permission: None,
                }),
                resource: None,
                self_scoped: false,
                resource_sharing: None,
                headers: BTreeMap::new(),
                projection: None,
            }),
        });
        let findings = rule_http_auth(&m, "x");
        assert!(
            findings
                .iter()
                .any(|f| f.detail.contains("必须声明 X-Tenant-ID")),
            "{findings:?}"
        );
    }

    #[test]
    fn r18_service_token_tenant_bound_wrong_header_name_fails() {
        let mut m = manifest(
            ContractKind::Http,
            ConsistencyLevel::LocalOnly,
            ContractOwner::Framework,
            http_schemas(),
        );
        m.lifecycle = Lifecycle::Active;
        m.path = Some("/api/v1/_seed/internal".to_string());
        m.method = Some(HttpMethod::Post);
        m.endpoints = Some(Endpoints {
            http: Some(HttpEndpoint {
                auth: Some(HttpAuth {
                    mode: HttpAuthMode::Permission,
                    reason: None,
                    permission: Some("identity:policy:read".to_string()),
                }),
                resource: None,
                self_scoped: false,
                resource_sharing: None,
                headers: BTreeMap::from([(
                    "X-Other-Tenant".to_string(),
                    HttpHeaderMode::ServiceTokenTenantBound,
                )]),
                projection: None,
            }),
        });
        let findings = rule_http_auth(&m, "x");
        assert!(
            findings.iter().any(|f| f.detail.contains("X-Tenant-ID")),
            "{findings:?}"
        );
    }

    #[test]
    fn r18_identity_public_login_requires_tenant_header() {
        let mut m = manifest(
            ContractKind::Http,
            ConsistencyLevel::OutboxFact,
            ContractOwner::Domain("identity".to_string()),
            http_schemas(),
        );
        m.id = "identity.login".to_string();
        m.domain = "identity".to_string();
        m.lifecycle = Lifecycle::Active;
        m.path = Some("/api/v1/identity/login".to_string());
        m.method = Some(HttpMethod::Post);
        m.endpoints = Some(Endpoints {
            http: Some(HttpEndpoint {
                auth: Some(HttpAuth {
                    mode: HttpAuthMode::Public,
                    reason: Some("public login".to_string()),
                    permission: None,
                }),
                resource: None,
                self_scoped: false,
                resource_sharing: None,
                headers: BTreeMap::new(),
                projection: None,
            }),
        });
        let findings = rule_http_auth(&m, "x");
        assert!(
            findings
                .iter()
                .any(|f| f.detail.contains("X-Tenant-ID = populate-only")),
            "{findings:?}"
        );
    }

    #[test]
    fn r19_http_request_tenant_id_is_rejected() -> anyhow::Result<()> {
        let (c, dir) = http_contract_with_schemas(
            r#"{"title":"LoginRequest","type":"object","properties":{"tenantId":{"type":"string"}}}"#,
            r#"{"title":"LoginResponse"}"#,
        )?;
        let findings = rule_http_request_tenant_source(&c, "x");
        let _ = std::fs::remove_dir_all(&dir);
        assert!(
            findings
                .iter()
                .any(|f| f.rule == Rule::HttpTenantSource && f.detail.contains("tenantId")),
            "{findings:?}"
        );
        Ok(())
    }

    #[test]
    fn r19_http_request_nested_tenant_id_is_rejected() -> anyhow::Result<()> {
        let (c, dir) = http_contract_with_schemas(
            r#"{"title":"LoginRequest","type":"object","properties":{"profile":{"type":"object","properties":{"tenantId":{"type":"string"}}}}}"#,
            r#"{"title":"LoginResponse"}"#,
        )?;
        let findings = rule_http_request_tenant_source(&c, "x");
        let _ = std::fs::remove_dir_all(&dir);
        assert!(
            findings.iter().any(|f| f.rule == Rule::HttpTenantSource),
            "{findings:?}"
        );
        Ok(())
    }

    #[test]
    fn r19_audit_list_target_tenant_query_is_rejected() -> anyhow::Result<()> {
        let (mut c, dir) = http_contract_with_schemas(
            r#"{"title":"AuditListEntriesRequest","type":"object","properties":{"tenantId":{"type":"string"}}}"#,
            r#"{"title":"AuditListEntriesResponse"}"#,
        )?;
        c.manifest.id = "audit.list-entries".to_string();
        c.manifest.domain = "audit".to_string();
        c.manifest.version = "v1".to_string();
        c.manifest.method = Some(HttpMethod::Get);
        c.manifest.path = Some("/api/v1/audit/entries".to_string());
        let findings = rule_http_request_tenant_source(&c, "x");
        let _ = std::fs::remove_dir_all(&dir);
        assert!(
            findings.iter().any(|f| f.rule == Rule::HttpTenantSource),
            "{findings:?}"
        );
        Ok(())
    }

    #[test]
    fn r19_audit_list_nested_tenant_id_is_rejected() -> anyhow::Result<()> {
        let (mut c, dir) = http_contract_with_schemas(
            r#"{"title":"AuditListEntriesRequest","type":"object","properties":{"filter":{"type":"object","properties":{"tenantId":{"type":"string"}}}}}"#,
            r#"{"title":"AuditListEntriesResponse"}"#,
        )?;
        c.manifest.id = "audit.list-entries".to_string();
        c.manifest.domain = "audit".to_string();
        c.manifest.version = "v1".to_string();
        c.manifest.method = Some(HttpMethod::Get);
        c.manifest.path = Some("/api/v1/audit/entries".to_string());
        let findings = rule_http_request_tenant_source(&c, "x");
        let _ = std::fs::remove_dir_all(&dir);
        assert!(
            findings.iter().any(|f| f.rule == Rule::HttpTenantSource),
            "{findings:?}"
        );
        Ok(())
    }

    #[test]
    fn r19_response_tenant_id_does_not_trip_request_rule() -> anyhow::Result<()> {
        let (c, dir) = http_contract_with_schemas(
            r#"{"title":"LoginRequest","type":"object","properties":{"username":{"type":"string"}}}"#,
            r#"{"title":"LoginResponse","type":"object","properties":{"tenantId":{"type":"string"}}}"#,
        )?;
        let findings = rule_http_request_tenant_source(&c, "x");
        let _ = std::fs::remove_dir_all(&dir);
        assert!(findings.is_empty(), "{findings:?}");
        Ok(())
    }

    #[test]
    fn r23_active_get_protected_response_requires_projection_path() -> anyhow::Result<()> {
        let (mut c, dir) = http_contract_with_schemas(
            r#"{"title":"ProfileRequest","type":"object","properties":{}}"#,
            r#"{"title":"ProfileResponse","type":"object","properties":{"data":{"type":"object","properties":{"subject":{"type":"string","x-pii":"generic"},"tenantId":{"type":"string"}}}}}"#,
        )?;
        make_active_get(&mut c.manifest, "/api/v1/profile", "profile:read", None);

        let findings = rule_http_projection_response_coverage(&c, "x");

        let _ = std::fs::remove_dir_all(&dir);
        assert!(
            findings.iter().any(|f| {
                f.rule == Rule::HttpProjectionCoverage && f.detail.contains("data.subject")
            }),
            "{findings:?}"
        );
        assert!(
            findings.iter().any(|f| {
                f.rule == Rule::HttpProjectionCoverage && f.detail.contains("data.tenantId")
            }),
            "{findings:?}"
        );
        Ok(())
    }

    #[test]
    fn r23_projection_response_path_must_exist() -> anyhow::Result<()> {
        let (mut c, dir) = http_contract_with_schemas(
            r#"{"title":"ProfileRequest","type":"object","properties":{}}"#,
            r#"{"title":"ProfileResponse","type":"object","properties":{"data":{"type":"object","properties":{"subject":{"type":"string","x-pii":"generic"}}}}}"#,
        )?;
        make_active_get(
            &mut c.manifest,
            "/api/v1/profile",
            "profile:read",
            Some(HttpProjection {
                fields: vec![HttpProjectionField {
                    field: HttpProjectionFieldName::IdentityProfileSubject,
                    permission: "identity:profile:field:subject".to_string(),
                    obligation_key: "identity.profile.subject".to_string(),
                    response_path: "data.missing".to_string(),
                }],
            }),
        );

        let findings = rule_http_projection_response_coverage(&c, "x");

        let _ = std::fs::remove_dir_all(&dir);
        assert!(
            findings.iter().any(|f| {
                f.rule == Rule::HttpProjectionCoverage && f.detail.contains("不存在")
            }),
            "{findings:?}"
        );
        Ok(())
    }

    #[test]
    fn r23_active_get_without_protected_response_does_not_require_projection() -> anyhow::Result<()>
    {
        let (mut c, dir) = http_contract_with_schemas(
            r#"{"title":"RolesRequest","type":"object","properties":{}}"#,
            r#"{"title":"RolesResponse","type":"object","properties":{"data":{"type":"array","items":{"type":"object","properties":{"roleId":{"type":"string"}}}}}}"#,
        )?;
        make_active_get(&mut c.manifest, "/api/v1/roles", "roles:read", None);

        let findings = rule_http_projection_response_coverage(&c, "x");

        let _ = std::fs::remove_dir_all(&dir);
        assert!(findings.is_empty(), "{findings:?}");
        Ok(())
    }

    #[test]
    fn r23_declared_projection_path_without_protected_response_fails() -> anyhow::Result<()> {
        let (mut c, dir) = http_contract_with_schemas(
            r#"{"title":"RolesRequest","type":"object","properties":{}}"#,
            r#"{"title":"RolesResponse","type":"object","properties":{"data":{"type":"array","items":{"type":"object","properties":{"roleId":{"type":"string"}}}}}}"#,
        )?;
        make_active_get(
            &mut c.manifest,
            "/api/v1/roles",
            "roles:read",
            Some(HttpProjection {
                fields: vec![HttpProjectionField {
                    field: HttpProjectionFieldName::IdentityProfileSubject,
                    permission: "identity:profile:field:subject".to_string(),
                    obligation_key: "identity.profile.subject".to_string(),
                    response_path: "data[].roleId".to_string(),
                }],
            }),
        );

        let findings = rule_http_projection_response_coverage(&c, "x");

        let _ = std::fs::remove_dir_all(&dir);
        assert!(
            findings.iter().any(|f| {
                f.rule == Rule::HttpProjectionCoverage && f.detail.contains("未指向")
            }),
            "{findings:?}"
        );
        Ok(())
    }

    #[test]
    fn r23_projection_field_tuple_must_match_closed_vocabulary() -> anyhow::Result<()> {
        let (mut c, dir) = http_contract_with_schemas(
            r#"{"title":"ProfileRequest","type":"object","properties":{}}"#,
            r#"{"title":"ProfileResponse","type":"object","properties":{"data":{"type":"object","properties":{"subject":{"type":"string","x-pii":"generic"},"tenantId":{"type":"string"}}}}}"#,
        )?;
        make_active_get(
            &mut c.manifest,
            "/api/v1/profile",
            "profile:read",
            Some(HttpProjection {
                fields: vec![
                    HttpProjectionField {
                        field: HttpProjectionFieldName::IdentityProfileSubject,
                        permission: "identity:profile:field:tenant_id".to_string(),
                        obligation_key: "identity.profile.tenant_id".to_string(),
                        response_path: "data.tenantId".to_string(),
                    },
                    HttpProjectionField {
                        field: HttpProjectionFieldName::IdentityProfileTenantId,
                        permission: "identity:profile:field:subject".to_string(),
                        obligation_key: "identity.profile.subject".to_string(),
                        response_path: "data.subject".to_string(),
                    },
                ],
            }),
        );

        let findings = validate_contract(&c);

        let _ = std::fs::remove_dir_all(&dir);
        assert!(
            findings.iter().any(|f| {
                f.rule == Rule::HttpProjectionCoverage
                    && f.detail.contains("identityProfileSubject")
                    && f.detail.contains("permission")
            }),
            "{findings:?}"
        );
        assert!(
            findings.iter().any(|f| {
                f.rule == Rule::HttpProjectionCoverage
                    && f.detail.contains("identityProfileTenantId")
                    && f.detail.contains("responsePath")
            }),
            "{findings:?}"
        );
        Ok(())
    }

    /// R8（#1124 红用例）：active command 缺 topic → 缺路由出口 = 死分发，须报 PerKindActiveFields。
    /// anti-vacuity 绿对照见 `r8_active_full_ok_and_draft_exempt`（active command + topic → 空）。
    #[test]
    fn r8_active_command_missing_topic() {
        let mut m = manifest(
            ContractKind::Command,
            ConsistencyLevel::OutboxFact,
            ContractOwner::Framework,
            Schemas {
                request: Some("request.schema.json".to_string()),
                ..Schemas::default()
            },
        );
        m.lifecycle = Lifecycle::Active; // 无 topic
        let findings = rule_perkind_active_fields(&m, "x");
        assert_eq!(findings.len(), 1, "active command 缺 topic 应报 1 条");
        assert_eq!(findings[0].rule, Rule::PerKindActiveFields);
    }

    #[test]
    fn r8_active_event_full_ok() {
        // anti-vacuity：active event 全填 topic+delivery → 无 finding。
        let mut m = manifest(
            ContractKind::Event,
            ConsistencyLevel::OutboxFact,
            ContractOwner::Framework,
            payload_schemas(),
        );
        m.lifecycle = Lifecycle::Active;
        m.topic = Some("seed.thing-happened".to_string());
        m.delivery = Some(Delivery::AtLeastOnce);
        assert!(rule_perkind_active_fields(&m, "x").is_empty());
    }

    #[test]
    fn r8_active_saga_full_ok() {
        // anti-vacuity：active saga 带 block → 无 finding（block 良构由 R10 单独守）。
        let mut m = saga_manifest(Some(valid_saga_block()));
        m.lifecycle = Lifecycle::Active;
        assert!(rule_perkind_active_fields(&m, "x").is_empty());
    }

    // ── R9 PerKindFieldScope（跨 kind 卫生）──────────────────────────────

    #[test]
    fn r9_event_with_http_field_rejected() {
        let mut m = manifest(
            ContractKind::Event,
            ConsistencyLevel::OutboxFact,
            ContractOwner::Framework,
            payload_schemas(),
        );
        m.path = Some("/api/v1/_seed/echo".to_string()); // path 仅 http 合法
        let findings = rule_perkind_field_scope(&m, "x");
        assert!(findings.iter().any(|f| f.rule == Rule::PerKindFieldScope));
    }

    #[test]
    fn r9_http_with_saga_block_rejected() {
        let mut m = manifest(
            ContractKind::Http,
            ConsistencyLevel::LocalOnly,
            ContractOwner::Framework,
            http_schemas(),
        );
        m.saga = Some(valid_saga_block()); // [saga] 仅 saga 合法
        let findings = rule_perkind_field_scope(&m, "x");
        assert!(findings.iter().any(|f| f.rule == Rule::PerKindFieldScope));
    }

    #[test]
    fn r9_fields_in_right_kind_ok() {
        let mut http = manifest(
            ContractKind::Http,
            ConsistencyLevel::LocalOnly,
            ContractOwner::Framework,
            http_schemas(),
        );
        http.path = Some("/api/v1/_seed/echo".to_string());
        http.method = Some(HttpMethod::Post);
        assert!(rule_perkind_field_scope(&http, "x").is_empty());
        let mut event = manifest(
            ContractKind::Event,
            ConsistencyLevel::OutboxFact,
            ContractOwner::Framework,
            payload_schemas(),
        );
        event.topic = Some("seed.thing-happened".to_string());
        event.delivery = Some(Delivery::AtLeastOnce);
        assert!(rule_perkind_field_scope(&event, "x").is_empty());
        assert!(rule_perkind_field_scope(&saga_manifest(Some(valid_saga_block())), "x").is_empty());
        // #1124：command 带 topic 合法（topic = event ∪ command 的 routing key）。
        let mut cmd = manifest(
            ContractKind::Command,
            ConsistencyLevel::OutboxFact,
            ContractOwner::Framework,
            Schemas {
                request: Some("request.schema.json".to_string()),
                ..Schemas::default()
            },
        );
        cmd.topic = Some("seed.commands.do-thing".to_string());
        assert!(rule_perkind_field_scope(&cmd, "x").is_empty());
    }

    /// R9 参数化：per-kind 字段出现在错 kind 须触发 PerKindFieldScope。case：(kind, 字段名)
    #[rstest]
    #[case(ContractKind::Event, "method")]
    #[case(ContractKind::Saga, "method")]
    #[case(ContractKind::Command, "method")]
    #[case(ContractKind::Http, "topic")]
    #[case(ContractKind::Saga, "topic")]
    #[case(ContractKind::Command, "delivery")]
    #[case(ContractKind::Saga, "path")]
    #[case(ContractKind::Event, "[saga]")]
    #[case(ContractKind::Command, "[saga]")]
    fn r9_field_on_wrong_kind_rejected(#[case] kind: ContractKind, #[case] field: &str) {
        let mut m = manifest(
            kind,
            ConsistencyLevel::WorkflowEventual,
            ContractOwner::Domain("billing".to_string()),
            payload_schemas(),
        );
        match field {
            "path" => m.path = Some("/api/v1/billing/x".to_string()),
            "method" => m.method = Some(HttpMethod::Post),
            "topic" => m.topic = Some("billing.thing".to_string()),
            "delivery" => m.delivery = Some(Delivery::AtLeastOnce),
            "[saga]" => m.saga = Some(valid_saga_block()),
            _ => {} // 未知字段：不设 → 下方断言失败暴露（self-protecting，不 panic）
        }
        let findings = rule_perkind_field_scope(&m, "x");
        assert!(
            findings.iter().any(|f| f.rule == Rule::PerKindFieldScope),
            "{field} on {kind:?} 应触发 PerKindFieldScope"
        );
    }

    // ── R10 SagaBlock（内部良构）──────────────────────────────────────────

    #[test]
    fn r10_saga_zero_steps_rejected() {
        let mut b = valid_saga_block();
        b.steps.clear();
        let findings = rule_saga_block(&saga_manifest(Some(b)), "x");
        assert!(findings.iter().any(|f| f.rule == Rule::SagaBlock));
    }

    #[test]
    fn r10_saga_duplicate_step_rejected() {
        let mut b = valid_saga_block();
        b.steps.push(SagaStep {
            name: "reserve_funds".to_string(), // 与首 step 重名
            output_schema: "other.schema.json".to_string(),
        });
        let findings = rule_saga_block(&saga_manifest(Some(b)), "x");
        assert!(findings.iter().any(|f| f.rule == Rule::SagaBlock));
    }

    #[rstest]
    #[case("9bad")] // 数字开头
    #[case("bad-name")] // 连字符非 Rust 标识符
    #[case("")] // 空
    #[case("fn")] // Rust 关键字
    #[case("r#fn")] // raw identifier（合法 syn::Ident 但须拒）
    fn r10_saga_bad_ident_step_rejected(#[case] name: &str) {
        let mut b = valid_saga_block();
        b.steps[0].name = name.to_string();
        let findings = rule_saga_block(&saga_manifest(Some(b)), "x");
        assert!(
            findings.iter().any(|f| f.rule == Rule::SagaBlock),
            "step name {name:?} 应触发 SagaBlock"
        );
    }

    #[test]
    fn r10_saga_empty_output_schema_rejected() {
        let mut b = valid_saga_block();
        b.steps[0].output_schema = String::new();
        let findings = rule_saga_block(&saga_manifest(Some(b)), "x");
        assert!(findings.iter().any(|f| f.rule == Rule::SagaBlock));
    }

    #[test]
    fn r10_multiple_violations_each_reported() {
        // 同一 step 多重违规（非法 ident + 空 outputSchema）各报一条，互不吞没。
        let mut b = valid_saga_block();
        b.steps[0].name = "9bad".to_string();
        b.steps[0].output_schema = String::new();
        let findings = rule_saga_block(&saga_manifest(Some(b)), "x");
        assert_eq!(
            findings.len(),
            2,
            "非法 ident + 空 outputSchema 应各报一条，实得 {findings:?}"
        );
        assert!(findings.iter().all(|f| f.rule == Rule::SagaBlock));
    }

    #[test]
    fn r10_valid_saga_block_ok() {
        // anti-vacuity：合法 saga block 不产生 finding。
        assert!(rule_saga_block(&saga_manifest(Some(valid_saga_block())), "x").is_empty());
    }

    #[test]
    fn r10_saga_kind_requires_block_even_draft() {
        // F1：kind=saga 无条件须有 block（saga.md，不论 lifecycle）——draft saga 缺 block 也拒。
        let m = saga_manifest(None); // saga_manifest 默认 lifecycle=draft
        assert_eq!(m.lifecycle, Lifecycle::Draft);
        let findings = rule_saga_block(&m, "x");
        assert_eq!(findings.len(), 1, "draft saga 缺 block 也须报");
        assert_eq!(findings[0].rule, Rule::SagaBlock);
    }

    #[test]
    fn r10_non_saga_absent_block_ok() {
        // 非-saga kind 无 [saga] block → R10 不查（saga 结构语义只约束 saga kind；误带 block 由 R9 拒）。
        let http = manifest(
            ContractKind::Http,
            ConsistencyLevel::LocalOnly,
            ContractOwner::Framework,
            http_schemas(),
        );
        assert!(rule_saga_block(&http, "x").is_empty());
    }

    // ── R11 ActiveDeliverySupported（active event 投递语义可兑现性）────────

    #[rstest]
    #[case(Delivery::AtMostOnce)]
    #[case(Delivery::ExactlyOnce)]
    fn r11_active_event_unsupported_delivery_rejected(#[case] delivery: Delivery) {
        let mut m = manifest(
            ContractKind::Event,
            ConsistencyLevel::OutboxFact,
            ContractOwner::Framework,
            payload_schemas(),
        );
        m.lifecycle = Lifecycle::Active;
        m.topic = Some("seed.thing-happened".to_string());
        m.delivery = Some(delivery);
        let f = rule_active_delivery_supported(&m, "x");
        assert_eq!(
            f.map(|f| f.rule),
            Some(Rule::ActiveDeliverySupported),
            "active event {delivery:?} 应被拒"
        );
    }

    #[test]
    fn r11_active_event_atleastonce_ok() {
        let mut m = manifest(
            ContractKind::Event,
            ConsistencyLevel::OutboxFact,
            ContractOwner::Framework,
            payload_schemas(),
        );
        m.lifecycle = Lifecycle::Active;
        m.topic = Some("seed.thing-happened".to_string());
        m.delivery = Some(Delivery::AtLeastOnce);
        assert!(rule_active_delivery_supported(&m, "x").is_none());
    }

    #[test]
    fn r11_draft_event_unsupported_delivery_ok() {
        // draft 可表达前瞻投递语义（R11 只管 active）。
        let mut m = manifest(
            ContractKind::Event,
            ConsistencyLevel::OutboxFact,
            ContractOwner::Framework,
            payload_schemas(),
        );
        m.delivery = Some(Delivery::ExactlyOnce); // 默认 draft
        assert!(rule_active_delivery_supported(&m, "x").is_none());
    }

    #[test]
    fn r11_non_event_active_ok() {
        // 非 event kind 不受 R11 约束。
        let mut http = manifest(
            ContractKind::Http,
            ConsistencyLevel::LocalOnly,
            ContractOwner::Framework,
            http_schemas(),
        );
        http.lifecycle = Lifecycle::Active;
        http.path = Some("/api/v1/_seed/echo".to_string());
        http.method = Some(HttpMethod::Post);
        assert!(rule_active_delivery_supported(&http, "x").is_none());
    }

    // ── R14 ActiveSubscriber（EVENT-ACTIVE-SUB-01）────────────────────────

    /// synthetic red：active event + 空 subscriptions → 产生 ActiveSubscriber finding。
    /// INVARIANT: EVENT-ACTIVE-SUB-01 { level = "Medium", exec = "verify", source = "code", synthetic_red = "tests::r14_active_event_empty_subscriptions_rejected", anti_vacuity = "tests::r14_active_event_with_subscription_ok" }
    #[test]
    fn r14_active_event_empty_subscriptions_rejected() {
        let mut m = manifest(
            ContractKind::Event,
            ConsistencyLevel::OutboxFact,
            ContractOwner::Domain("identity".to_string()),
            payload_schemas(),
        );
        m.lifecycle = Lifecycle::Active;
        m.topic = Some("identity.session-created".to_string());
        m.delivery = Some(Delivery::AtLeastOnce);
        // subscriptions 为空（manifest() 默认）
        let f = rule_active_subscriber(&m, "x");
        assert_eq!(
            f.as_ref().map(|f| f.rule),
            Some(Rule::ActiveSubscriber),
            "active event + 空 subscriptions 应产生 ActiveSubscriber finding"
        );
        assert_eq!(f.map(|f| f.subject), Some("x".to_string()));
    }

    /// anti-vacuity 绿用例 1：active event + ≥1 subscription → 通过。
    #[test]
    fn r14_active_event_with_subscription_ok() {
        let mut m = manifest(
            ContractKind::Event,
            ConsistencyLevel::OutboxFact,
            ContractOwner::Domain("identity".to_string()),
            payload_schemas(),
        );
        m.lifecycle = Lifecycle::Active;
        m.topic = Some("identity.session-created".to_string());
        m.delivery = Some(Delivery::AtLeastOnce);
        m.subscriptions = vec![one_subscription()];
        assert!(
            rule_active_subscriber(&m, "x").is_none(),
            "active event + 1 subscription 应通过"
        );
    }

    /// anti-vacuity 绿用例 2：draft event + 空 subscriptions → 通过（draft 豁免）。
    #[test]
    fn r14_draft_event_empty_subscriptions_ok() {
        let m = manifest(
            ContractKind::Event,
            ConsistencyLevel::OutboxFact,
            ContractOwner::Framework,
            payload_schemas(),
        );
        // lifecycle 默认 draft，subscriptions 默认空
        assert_eq!(m.lifecycle, Lifecycle::Draft);
        assert!(
            rule_active_subscriber(&m, "x").is_none(),
            "draft event 空 subscriptions 应豁免"
        );
    }

    /// anti-vacuity：deprecated event + 空 subscriptions → 通过（deprecated 豁免）。
    #[test]
    fn r14_deprecated_event_empty_subscriptions_ok() {
        let mut m = manifest(
            ContractKind::Event,
            ConsistencyLevel::OutboxFact,
            ContractOwner::Framework,
            payload_schemas(),
        );
        m.lifecycle = Lifecycle::Deprecated;
        assert!(
            rule_active_subscriber(&m, "x").is_none(),
            "deprecated event 应豁免 R14"
        );
    }

    /// 非 event kind（http / command / saga）active 时不受 R14 约束。
    #[test]
    fn r14_non_event_active_ok() {
        let mut http = manifest(
            ContractKind::Http,
            ConsistencyLevel::LocalOnly,
            ContractOwner::Framework,
            http_schemas(),
        );
        http.lifecycle = Lifecycle::Active;
        assert!(
            rule_active_subscriber(&http, "x").is_none(),
            "非 event kind 不受 R14 约束"
        );
    }

    // ── R5/R6 扩展：saga step outputSchema 纳入 schema 文件完整性 ──────────

    #[test]
    fn r5_saga_step_schema_missing_detected() -> anyhow::Result<()> {
        let dir = unique_tmp("validate");
        std::fs::create_dir_all(&dir)?;
        std::fs::write(dir.join("payload.schema.json"), "{}")?; // 建 payload，缺 saga step schema
        let m = saga_manifest(Some(valid_saga_block()));
        let findings = rule_schema_files_exist(&discovered(m, dir.clone()), "x");
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(findings.len(), 1, "缺 reserve.schema.json 一条");
        assert_eq!(findings[0].rule, Rule::MissingSchema);
        Ok(())
    }

    #[test]
    fn r6_saga_step_unsafe_schema_rejected() {
        let mut b = valid_saga_block();
        b.steps[0].output_schema = "../evil.schema.json".to_string();
        let findings = rule_unsafe_schema_path(&saga_manifest(Some(b)), "x");
        assert!(findings.iter().any(|f| f.rule == Rule::UnsafeSchemaPath));
    }

    // ── 全契约绿（active 全填）：anti-vacuity 正向 ────────────────────────

    #[test]
    fn green_active_http_contract_has_no_findings() -> anyhow::Result<()> {
        let dir = unique_tmp("validate");
        std::fs::create_dir_all(&dir)?;
        std::fs::write(dir.join("request.schema.json"), r#"{"title":"ActiveReq"}"#)?;
        std::fs::write(
            dir.join("response.schema.json"),
            r#"{"title":"ActiveResp"}"#,
        )?;
        let mut m = manifest(
            ContractKind::Http,
            ConsistencyLevel::LocalOnly,
            ContractOwner::Framework,
            http_schemas(),
        );
        m.lifecycle = Lifecycle::Active;
        m.path = Some("/api/v1/_seed/echo".to_string());
        m.method = Some(HttpMethod::Post);
        m.endpoints = Some(public_http_endpoints());
        let findings = validate_contract(&discovered(m, dir.clone()));
        let _ = std::fs::remove_dir_all(&dir);
        assert!(findings.is_empty(), "{findings:?}");
        Ok(())
    }

    // ── R12 DuplicateId（跨契约，喂 &[DiscoveredContract]，不读盘）────────────

    /// 构造一个 discovered 契约（id / 三段 label 可定制）。DuplicateId 只看 manifest.id + 路径段，不读盘。
    fn discovered_with(id: &str, kind: &str, domain: &str, version: &str) -> DiscoveredContract {
        let mut m = manifest(
            ContractKind::Http,
            ConsistencyLevel::LocalOnly,
            ContractOwner::Framework,
            http_schemas(),
        );
        m.id = id.to_string();
        let mut c = discovered(m, PathBuf::from("/x"));
        c.path_kind = kind.to_string();
        c.path_domain = domain.to_string();
        c.path_version = version.to_string();
        c
    }

    #[test]
    fn r12_duplicate_id_across_two_contracts_detected() {
        let contracts = vec![
            discovered_with("identity.login", "http", "identity", "v1"),
            discovered_with("identity.login", "http", "identity", "v2"),
        ];
        let findings = rule_duplicate_id(&contracts);
        assert_eq!(findings.len(), 1, "同根因仅 1 条: {findings:?}");
        assert_eq!(findings[0].rule, Rule::DuplicateId);
        assert_eq!(findings[0].subject, "identity.login", "subject 须为重复 id");
        assert!(findings[0].detail.contains("http/identity/v1"));
        assert!(findings[0].detail.contains("http/identity/v2"));
    }

    #[test]
    fn r12_three_contracts_same_id_still_one_finding() {
        let contracts = vec![
            discovered_with("seed.echo", "http", "_seed", "v1"),
            discovered_with("seed.echo", "event", "_seed", "v1"),
            discovered_with("seed.echo", "http", "other", "v1"),
        ];
        let findings = rule_duplicate_id(&contracts);
        assert_eq!(findings.len(), 1, "三契约同 id 仍 1 条: {findings:?}");
        assert_eq!(findings[0].rule, Rule::DuplicateId);
    }

    #[test]
    fn r12_duplicate_id_detail_is_deterministic() {
        // 乱序输入，detail 的 label 列表稳定排序（BTreeMap + sort）。
        let a = vec![
            discovered_with("dup.id", "http", "b", "v1"),
            discovered_with("dup.id", "http", "a", "v1"),
        ];
        let b = vec![
            discovered_with("dup.id", "http", "a", "v1"),
            discovered_with("dup.id", "http", "b", "v1"),
        ];
        assert_eq!(
            rule_duplicate_id(&a)[0].detail,
            rule_duplicate_id(&b)[0].detail
        );
    }

    #[test]
    fn r12_distinct_ids_ok() {
        // anti-vacuity：id 各异 → 无 finding。
        let contracts = vec![
            discovered_with("seed.echo", "http", "_seed", "v1"),
            discovered_with("identity.login", "http", "identity", "v1"),
            discovered_with("seed.thing-happened", "event", "_seed", "v1"),
        ];
        assert!(rule_duplicate_id(&contracts).is_empty());
    }

    #[test]
    fn r12_single_contract_no_finding() {
        // 边界：唯一一个契约 → 无重复。
        let contracts = vec![discovered_with("seed.echo", "http", "_seed", "v1")];
        assert!(rule_duplicate_id(&contracts).is_empty());
    }

    #[test]
    fn r12_empty_contracts_ok() {
        // 边界：零契约 → 无 finding（不 panic）。
        assert!(rule_duplicate_id(&[]).is_empty());
    }

    // ── R20 SlugSyntax（per-contract，读 c.slug）─────────────────────────────

    /// 构造一个带 slug 的 event 契约（嵌套形态）。
    fn discovered_event_slug(
        domain: &str,
        version: &str,
        slug: Option<&str>,
    ) -> DiscoveredContract {
        let m = manifest(
            ContractKind::Event,
            ConsistencyLevel::OutboxFact,
            ContractOwner::Domain(domain.to_string()),
            payload_schemas(),
        );
        let mut c = discovered(m, PathBuf::from("/x"));
        c.path_kind = "event".to_string();
        c.path_domain = domain.to_string();
        c.path_version = version.to_string();
        c.slug = slug.map(str::to_string);
        c
    }

    #[test]
    fn r20_flat_slug_none_no_finding() {
        // anti-vacuity：扁平契约（slug=None）豁免 R20。
        let c = discovered_event_slug("identity", "v1", None);
        assert!(rule_slug_syntax(&c, "event/identity/v1").is_none());
    }

    #[test]
    fn r20_valid_kebab_slug_no_finding() {
        // anti-vacuity（正向）：合法 kebab slug 通过（kebab→snake 合法 ident）。
        let c = discovered_event_slug("identity", "v1", Some("role-assigned"));
        assert!(rule_slug_syntax(&c, "event/identity/v1/role-assigned").is_none());
    }

    #[rstest]
    #[case("Role-Assigned")] // 大写
    #[case("1role")] // 数字开头
    #[case("role-")] // 尾连字符
    #[case("role.assigned")] // 点（路径分量）
    #[case("role/assigned")] // 斜杠（逃逸）
    fn r20_unsafe_slug_finding(#[case] slug: &str) {
        // synthetic red：非法 slug → SlugSyntax finding。
        let c = discovered_event_slug("identity", "v1", Some(slug));
        let f = rule_slug_syntax(&c, "event/identity/v1");
        assert_eq!(
            f.map(|f| f.rule),
            Some(Rule::SlugSyntax),
            "slug {slug:?} 应被拒"
        );
    }

    // ── R21 SlugMixing（跨契约，看同 {kind}/{domain}/{version} group）──────────

    #[test]
    fn r21_pure_flat_no_finding() {
        // anti-vacuity：纯扁平（1×None）group 通过。
        let contracts = vec![discovered_event_slug("identity", "v1", None)];
        assert!(rule_slug_mixing(&contracts).is_empty());
    }

    #[test]
    fn r21_pure_nested_no_finding() {
        // anti-vacuity：纯嵌套（N×Some）group 通过。
        let contracts = vec![
            discovered_event_slug("identity", "v1", Some("role-assigned")),
            discovered_event_slug("identity", "v1", Some("role-revoked")),
        ];
        assert!(rule_slug_mixing(&contracts).is_empty());
    }

    #[test]
    fn r21_mixed_flat_and_nested_finding() {
        // synthetic red：同 group 含扁平 + 嵌套 → SlugMixing（同根因 1 条）。
        let contracts = vec![
            discovered_event_slug("identity", "v1", None),
            discovered_event_slug("identity", "v1", Some("role-assigned")),
        ];
        let findings = rule_slug_mixing(&contracts);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule, Rule::SlugMixing);
    }

    #[test]
    fn r21_distinct_groups_not_mixed() {
        // 不同 {domain}/{version}：flat identity/v1 + nested identity/v2 → 各自纯净，不报。
        let contracts = vec![
            discovered_event_slug("identity", "v1", None),
            discovered_event_slug("identity", "v2", Some("role-assigned")),
        ];
        assert!(rule_slug_mixing(&contracts).is_empty());
    }

    // ── R22 ConsistencyCapability（L0-L4 ability gate）──────────────────────

    fn assert_r22_detail(findings: &[Finding], contract_id: &str, missing: &str) {
        assert!(
            findings.iter().any(|f| {
                f.rule == Rule::ConsistencyCapability
                    && f.detail.contains(&format!("contract id={contract_id}"))
                    && f.detail.contains(&format!("missing capability={missing}"))
            }),
            "expected R22 finding for id={contract_id}, missing={missing}; got {findings:?}"
        );
    }

    fn active_http_outbox_producer(domain: &str, id: &str, emits: &[&str]) -> DiscoveredContract {
        let mut m = manifest(
            ContractKind::Http,
            ConsistencyLevel::OutboxFact,
            ContractOwner::Domain(domain.to_string()),
            http_schemas(),
        );
        m.id = id.to_string();
        m.domain = domain.to_string();
        m.lifecycle = Lifecycle::Active;
        m.capabilities = outbox_producer_capability(emits);
        discovered(m, PathBuf::from(format!("/{id}")))
    }

    fn active_outbox_event(domain: &str, id: &str) -> DiscoveredContract {
        let mut m = manifest(
            ContractKind::Event,
            ConsistencyLevel::OutboxFact,
            ContractOwner::Domain(domain.to_string()),
            payload_schemas(),
        );
        m.id = id.to_string();
        m.domain = domain.to_string();
        m.lifecycle = Lifecycle::Active;
        m.subscriptions = vec![one_subscription()];
        m.capabilities = outbox_fact_capability();
        discovered(m, PathBuf::from(format!("/{id}")))
    }

    fn runtime_relay_wiring(
        uses_generated_registry: bool,
        has_complete_generated_loop: bool,
    ) -> RuntimeRelayWiring {
        RuntimeRelayWiring {
            uses_generated_registry,
            has_complete_generated_loop,
        }
    }

    #[test]
    fn r22_runtime_relay_parser_reads_registry_and_wiring_calls() -> anyhow::Result<()> {
        let wiring = parse_runtime_relay_wiring(
            r#"
            fn wire() -> anyhow::Result<()> {
                for producer in generated::event::PRODUCER_DOMAINS.iter().copied() {
                    let domain = producer.as_str();
                    let outbox = match producer {
                        ProducerDomain::Identity => identity_outbox,
                        ProducerDomain::Settings => settings_outbox,
                    };
                    wire_domain_relay(domain, outbox, &timing, &mut module)?;
                }
                Ok(())
            }
            "#,
        )?;
        assert_eq!(wiring, runtime_relay_wiring(true, true));
        Ok(())
    }

    #[test]
    fn r22_runtime_relay_parser_rejects_wildcard_provider_mapping() -> anyhow::Result<()> {
        let wiring = parse_runtime_relay_wiring(
            r#"
            fn wire() {
                for producer in generated::event::PRODUCER_DOMAINS {
                    let outbox = match producer {
                        ProducerDomain::Identity => identity_outbox,
                        _ => fallback_outbox,
                    };
                    wire_domain_relay(producer.as_str(), outbox, &timing, &mut module);
                }
            }
            "#,
        )?;
        assert!(wiring.uses_generated_registry);
        assert!(!wiring.has_complete_generated_loop);
        Ok(())
    }

    #[test]
    fn r22_runtime_relay_parser_rejects_dispersed_evidence() -> anyhow::Result<()> {
        let wiring = parse_runtime_relay_wiring(
            r#"
            fn registry_only() {
                for producer in generated::event::PRODUCER_DOMAINS {
                    let _ = producer.as_str();
                }
            }
            fn unrelated_match(producer: ProducerDomain) {
                match producer {
                    ProducerDomain::Identity => identity_outbox,
                    ProducerDomain::Settings => settings_outbox,
                };
            }
            fn unrelated_wire(domain: &str) {
                wire_domain_relay(domain, outbox, &timing, &mut module);
            }
            "#,
        )?;
        assert!(wiring.uses_generated_registry);
        assert!(!wiring.has_complete_generated_loop);
        Ok(())
    }

    #[test]
    fn r22_active_http_outbox_emits_requires_runtime_relay_domain_registry() {
        let contracts = vec![
            active_http_outbox_producer(
                "billing",
                "billing.invoice-create",
                &["billing.invoice-created"],
            ),
            active_outbox_event("billing", "billing.invoice-created"),
        ];
        let runtime = runtime_relay_wiring(false, true);
        let findings = rule_runtime_relay_coverage(&contracts, &runtime);
        assert_r22_detail(
            &findings,
            "billing.invoice-create",
            CAP_RUNTIME_RELAY_DOMAIN,
        );
    }

    #[test]
    fn r22_active_http_outbox_emits_requires_runtime_relay_wiring() {
        let contracts = vec![
            active_http_outbox_producer(
                "billing",
                "billing.invoice-create",
                &["billing.invoice-created"],
            ),
            active_outbox_event("billing", "billing.invoice-created"),
        ];
        let runtime = runtime_relay_wiring(true, false);
        let findings = rule_runtime_relay_coverage(&contracts, &runtime);
        assert_r22_detail(
            &findings,
            "billing.invoice-create",
            CAP_RUNTIME_RELAY_WIRING,
        );
    }

    #[test]
    fn r22_consistency_http_requires_effect_profile() {
        let mut m = manifest(
            ContractKind::Http,
            ConsistencyLevel::LocalOnly,
            ContractOwner::Framework,
            http_schemas(),
        );
        m.id = "seed.local".to_string();
        let findings = rule_consistency_capability(&[discovered(m, PathBuf::from("/x"))]);
        assert_r22_detail(&findings, "seed.local", FIELD_EFFECT_PROFILE);
    }

    #[test]
    fn r22_consistency_effect_profile_forbidden_on_non_http() {
        let mut m = manifest(
            ContractKind::Event,
            ConsistencyLevel::OutboxFact,
            ContractOwner::Domain("identity".to_string()),
            payload_schemas(),
        );
        m.id = "identity.session-created".to_string();
        m.capabilities = outbox_fact_capability();
        m.effect_profile = effect_profile(&[EffectKind::Read]);
        let findings = rule_consistency_capability(&[discovered(m, PathBuf::from("/x"))]);
        assert_r22_detail(&findings, "identity.session-created", FIELD_EFFECT_PROFILE);
    }

    #[test]
    fn r22_consistency_effect_profile_requires_effects_and_no_duplicates() {
        let mut empty = manifest(
            ContractKind::Http,
            ConsistencyLevel::LocalOnly,
            ContractOwner::Framework,
            http_schemas(),
        );
        empty.id = "seed.empty".to_string();
        empty.effect_profile = effect_profile(&[]);

        let mut duplicate = manifest(
            ContractKind::Http,
            ConsistencyLevel::LocalOnly,
            ContractOwner::Framework,
            http_schemas(),
        );
        duplicate.id = "seed.duplicate".to_string();
        duplicate.effect_profile = effect_profile(&[EffectKind::Auth, EffectKind::Auth]);

        let findings = rule_consistency_capability(&[
            discovered(empty, PathBuf::from("/empty")),
            discovered(duplicate, PathBuf::from("/duplicate")),
        ]);
        assert_r22_detail(&findings, "seed.empty", CAP_EFFECT_PROFILE_EFFECTS);
        assert_r22_detail(&findings, "seed.duplicate", CAP_EFFECT_PROFILE_EFFECTS);
    }

    #[test]
    fn r22_consistency_localonly_event_and_stray_outbox_rejected() {
        let mut m = manifest(
            ContractKind::Event,
            ConsistencyLevel::LocalOnly,
            ContractOwner::Framework,
            payload_schemas(),
        );
        m.id = "seed.local-event".to_string();
        m.capabilities = outbox_fact_capability();
        let findings = rule_consistency_capability(&[discovered(m, PathBuf::from("/x"))]);
        assert_r22_detail(&findings, "seed.local-event", "local-only-http");
        assert_r22_detail(&findings, "seed.local-event", "capability-scope");
    }

    #[test]
    fn r22_consistency_localtx_requires_http_and_localtx_capability() {
        let mut m = manifest(
            ContractKind::Event,
            ConsistencyLevel::LocalTx,
            ContractOwner::Domain("identity".to_string()),
            payload_schemas(),
        );
        m.id = "identity.local-tx-event".to_string();
        let findings = rule_consistency_capability(&[discovered(m, PathBuf::from("/x"))]);
        assert_r22_detail(&findings, "identity.local-tx-event", CAP_LOCAL_TX);
    }

    #[test]
    fn r22_consistency_event_outbox_wrong_role_and_stray_payload_fields_rejected() {
        let mut m = manifest(
            ContractKind::Event,
            ConsistencyLevel::OutboxFact,
            ContractOwner::Domain("identity".to_string()),
            payload_schemas(),
        );
        m.id = "identity.session-created".to_string();
        m.capabilities = outbox_producer_capability(&["identity.session-created"]);
        let findings = rule_consistency_capability(&[discovered(m, PathBuf::from("/x"))]);
        assert_r22_detail(&findings, "identity.session-created", CAP_OUTBOX_ROLE_FACT);
        assert_r22_detail(
            &findings,
            "identity.session-created",
            CAP_OUTBOX_FIELD_SCOPE,
        );
    }

    #[test]
    fn r22_consistency_command_outbox_wrong_role_rejected() {
        let mut m = command_manifest(ConsistencyLevel::OutboxFact);
        m.capabilities = outbox_fact_capability();
        let findings = rule_consistency_capability(&[discovered(m, PathBuf::from("/x"))]);
        assert_r22_detail(&findings, "seed.do-thing", CAP_OUTBOX_ROLE_COMMAND);
    }

    #[test]
    fn r22_consistency_http_outbox_missing_producer_rejected() {
        let mut m = manifest(
            ContractKind::Http,
            ConsistencyLevel::OutboxFact,
            ContractOwner::Domain("identity".to_string()),
            http_schemas(),
        );
        m.id = "identity.login".to_string();
        let findings = rule_consistency_capability(&[discovered(m, PathBuf::from("/x"))]);
        assert_r22_detail(&findings, "identity.login", "capabilities.outbox");
    }

    #[test]
    fn r22_consistency_http_outbox_missing_emits_rejected() {
        let mut m = manifest(
            ContractKind::Http,
            ConsistencyLevel::OutboxFact,
            ContractOwner::Domain("identity".to_string()),
            http_schemas(),
        );
        m.id = "identity.login".to_string();
        m.capabilities = outbox_producer_capability(&[]);
        let findings = rule_consistency_capability(&[discovered(m, PathBuf::from("/x"))]);
        assert_r22_detail(&findings, "identity.login", "capabilities.outbox.emits");
    }

    #[test]
    fn r22_consistency_http_outbox_emits_ref_must_target_l2_event() {
        let mut m = manifest(
            ContractKind::Http,
            ConsistencyLevel::OutboxFact,
            ContractOwner::Domain("identity".to_string()),
            http_schemas(),
        );
        m.id = "identity.login".to_string();
        m.capabilities = outbox_producer_capability(&["identity.missing-event"]);
        let findings = rule_consistency_capability(&[discovered(m, PathBuf::from("/x"))]);
        assert!(
            findings.iter().any(|f| {
                f.rule == Rule::ConsistencyCapability
                    && f.detail.contains("contract id=identity.login")
                    && f.detail
                        .contains("missing capability ref=identity.missing-event")
            }),
            "{findings:?}"
        );
    }

    #[test]
    fn r22_consistency_http_outbox_emits_ref_rejects_non_event_target() {
        let mut producer = manifest(
            ContractKind::Http,
            ConsistencyLevel::OutboxFact,
            ContractOwner::Domain("identity".to_string()),
            http_schemas(),
        );
        producer.id = "identity.login".to_string();
        producer.capabilities = outbox_producer_capability(&["identity.create-session"]);

        let mut command = command_manifest(ConsistencyLevel::OutboxFact);
        command.id = "identity.create-session".to_string();
        command.capabilities = outbox_command_capability();

        let findings = rule_consistency_capability(&[
            discovered(producer, PathBuf::from("/producer")),
            discovered(command, PathBuf::from("/command")),
        ]);
        assert!(
            findings.iter().any(|f| {
                f.rule == Rule::ConsistencyCapability
                    && f.detail.contains("contract id=identity.login")
                    && f.detail
                        .contains("missing capability ref=identity.create-session")
            }),
            "{findings:?}"
        );
    }

    #[test]
    fn r22_consistency_active_http_outbox_emits_ref_requires_active_event_readiness() {
        let mut producer = manifest(
            ContractKind::Http,
            ConsistencyLevel::OutboxFact,
            ContractOwner::Domain("identity".to_string()),
            http_schemas(),
        );
        producer.id = "identity.roles-assign".to_string();
        producer.lifecycle = Lifecycle::Active;
        producer.capabilities = outbox_producer_capability(&["identity.role-assigned"]);

        let mut draft_event = manifest(
            ContractKind::Event,
            ConsistencyLevel::OutboxFact,
            ContractOwner::Domain("identity".to_string()),
            payload_schemas(),
        );
        draft_event.id = "identity.role-assigned".to_string();
        draft_event.lifecycle = Lifecycle::Draft;
        draft_event.capabilities = outbox_fact_capability();

        let findings = rule_consistency_capability(&[
            discovered(producer, PathBuf::from("/producer")),
            discovered(draft_event, PathBuf::from("/event")),
        ]);
        assert!(
            findings.iter().any(|f| {
                f.rule == Rule::ConsistencyCapability
                    && f.detail.contains("contract id=identity.roles-assign")
                    && f.detail
                        .contains("missing capability ref=identity.role-assigned")
            }),
            "{findings:?}"
        );
    }

    #[test]
    fn r22_consistency_workflow_missing_capability_rejected() {
        let mut m = manifest(
            ContractKind::Http,
            ConsistencyLevel::WorkflowEventual,
            ContractOwner::Domain("billing".to_string()),
            http_schemas(),
        );
        m.id = "billing.projection".to_string();
        let findings = rule_consistency_capability(&[discovered(m, PathBuf::from("/x"))]);
        assert_r22_detail(&findings, "billing.projection", "capabilities.workflow");
    }

    #[test]
    fn r22_consistency_saga_workflow_requires_saga_block() {
        let mut m = saga_manifest(None);
        m.capabilities = workflow_saga_capability();
        let findings = rule_consistency_capability(&[discovered(m, PathBuf::from("/x"))]);
        assert_r22_detail(
            &findings,
            "billing.checkout",
            "capabilities.workflow.mode=saga",
        );
    }

    #[test]
    fn r22_consistency_saga_workflow_rejects_projection_only_fields() {
        let mut m = saga_manifest(Some(valid_saga_block()));
        m.capabilities = workflow_saga_capability();
        let Some(workflow) = m.capabilities.workflow.as_mut() else {
            unreachable!("workflow_saga_capability sets workflow");
        };
        workflow.inputs = vec!["identity.session-created".to_string()];
        workflow.ordering = Some(WorkflowOrdering::SerialInOrder);
        let findings = rule_consistency_capability(&[discovered(m, PathBuf::from("/x"))]);
        assert_r22_detail(&findings, "billing.checkout", CAP_WORKFLOW_FIELD_SCOPE);
    }

    #[test]
    fn r22_consistency_projection_inputs_ref_must_target_l2_event() {
        let mut projection = manifest(
            ContractKind::Http,
            ConsistencyLevel::WorkflowEventual,
            ContractOwner::Domain("audit".to_string()),
            http_schemas(),
        );
        projection.id = "audit.session-projection".to_string();
        projection.capabilities =
            workflow_projection_capability_with_inputs(&["identity.create-session"]);

        let mut command = command_manifest(ConsistencyLevel::OutboxFact);
        command.id = "identity.create-session".to_string();
        command.capabilities = outbox_command_capability();

        let findings = rule_consistency_capability(&[
            discovered(projection, PathBuf::from("/projection")),
            discovered(command, PathBuf::from("/command")),
        ]);
        assert!(
            findings.iter().any(|f| {
                f.rule == Rule::ConsistencyCapability
                    && f.detail.contains("contract id=audit.session-projection")
                    && f.detail
                        .contains("missing capability ref=identity.create-session")
            }),
            "{findings:?}"
        );
    }

    #[test]
    fn r22_consistency_projection_missing_evidence_fields_rejected() {
        let mut m = manifest(
            ContractKind::Http,
            ConsistencyLevel::WorkflowEventual,
            ContractOwner::Domain("audit".to_string()),
            http_schemas(),
        );
        m.id = "audit.session-projection".to_string();
        m.capabilities = workflow_projection_capability_with_inputs(&[]);
        let Some(workflow) = m.capabilities.workflow.as_mut() else {
            unreachable!("workflow_projection_capability_with_inputs sets workflow");
        };
        workflow.ordering = None;
        workflow.checkpoint = None;
        workflow.replay = None;
        let findings = rule_consistency_capability(&[discovered(m, PathBuf::from("/x"))]);
        assert_r22_detail(&findings, "audit.session-projection", CAP_WORKFLOW_INPUTS);
        assert_r22_detail(&findings, "audit.session-projection", CAP_WORKFLOW_ORDERING);
        assert_r22_detail(
            &findings,
            "audit.session-projection",
            CAP_WORKFLOW_CHECKPOINT,
        );
        assert_r22_detail(&findings, "audit.session-projection", CAP_WORKFLOW_REPLAY);
    }

    #[test]
    fn r22_consistency_workflow_eventual_does_not_require_reconcile() {
        let mut saga = saga_manifest(Some(valid_saga_block()));
        saga.capabilities = workflow_saga_capability();

        let mut event = manifest(
            ContractKind::Event,
            ConsistencyLevel::OutboxFact,
            ContractOwner::Domain("identity".to_string()),
            payload_schemas(),
        );
        event.id = "identity.session-created".to_string();
        event.capabilities = outbox_fact_capability();

        let mut projection = manifest(
            ContractKind::Http,
            ConsistencyLevel::WorkflowEventual,
            ContractOwner::Domain("audit".to_string()),
            http_schemas(),
        );
        projection.id = "audit.session-projection".to_string();
        projection.capabilities = workflow_projection_capability();
        projection.effect_profile =
            effect_profile(&[EffectKind::Auth, EffectKind::Read, EffectKind::Projection]);

        let findings = rule_consistency_capability(&[
            discovered(saga, PathBuf::from("/saga")),
            discovered(event, PathBuf::from("/event")),
            discovered(projection, PathBuf::from("/projection")),
        ]);
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn r22_consistency_non_device_latent_reconcile_block_rejected() {
        let mut m = manifest(
            ContractKind::Http,
            ConsistencyLevel::LocalOnly,
            ContractOwner::Framework,
            http_schemas(),
        );
        m.id = "seed.local".to_string();
        m.reconcile = Some(valid_reconcile_block());
        let findings = rule_consistency_capability(&[discovered(m, PathBuf::from("/x"))]);
        assert_r22_detail(&findings, "seed.local", CAP_CAPABILITY_SCOPE);
    }

    #[test]
    fn r22_consistency_device_latent_missing_capability_rejected() {
        let mut m = manifest(
            ContractKind::Http,
            ConsistencyLevel::DeviceLatent,
            ContractOwner::Domain("device".to_string()),
            http_schemas(),
        );
        m.id = "device.cert-reconcile".to_string();
        let findings = rule_consistency_capability(&[discovered(m, PathBuf::from("/x"))]);
        assert_r22_detail(
            &findings,
            "device.cert-reconcile",
            "capabilities.deviceLatent",
        );
    }

    #[test]
    fn r22_consistency_device_latent_requires_http_kind() {
        let mut m = manifest(
            ContractKind::Event,
            ConsistencyLevel::DeviceLatent,
            ContractOwner::Domain("device".to_string()),
            payload_schemas(),
        );
        m.id = "device.cert-reconcile".to_string();
        m.capabilities = device_latent_capability();
        let findings = rule_consistency_capability(&[discovered(m, PathBuf::from("/x"))]);
        assert_r22_detail(&findings, "device.cert-reconcile", CAP_DEVICE_LATENT);
    }

    #[test]
    fn r22_consistency_device_latent_missing_reconcile_block_rejected() {
        let mut m = manifest(
            ContractKind::Http,
            ConsistencyLevel::DeviceLatent,
            ContractOwner::Domain("device".to_string()),
            http_schemas(),
        );
        m.id = "device.cert-reconcile".to_string();
        m.capabilities = device_latent_capability();
        let findings = rule_consistency_capability(&[discovered(m, PathBuf::from("/x"))]);
        assert_r22_detail(&findings, "device.cert-reconcile", "[reconcile]");
    }

    #[test]
    fn r22_consistency_valid_matrix_ok() {
        let mut local = manifest(
            ContractKind::Http,
            ConsistencyLevel::LocalOnly,
            ContractOwner::Framework,
            http_schemas(),
        );
        local.id = "seed.local".to_string();
        local.effect_profile = effect_profile(&[EffectKind::Auth, EffectKind::Read]);

        let mut local_tx = manifest(
            ContractKind::Http,
            ConsistencyLevel::LocalTx,
            ContractOwner::Domain("identity".to_string()),
            http_schemas(),
        );
        local_tx.id = "identity.logout".to_string();
        local_tx.capabilities = local_tx_capability();
        local_tx.effect_profile =
            effect_profile(&[EffectKind::Auth, EffectKind::Write, EffectKind::Transaction]);

        let mut fact = manifest(
            ContractKind::Event,
            ConsistencyLevel::OutboxFact,
            ContractOwner::Domain("identity".to_string()),
            payload_schemas(),
        );
        fact.id = "identity.session-created".to_string();
        fact.capabilities = outbox_fact_capability();

        let mut command = command_manifest(ConsistencyLevel::OutboxFact);
        command.capabilities = outbox_command_capability();

        let mut producer = manifest(
            ContractKind::Http,
            ConsistencyLevel::OutboxFact,
            ContractOwner::Domain("identity".to_string()),
            http_schemas(),
        );
        producer.id = "identity.login".to_string();
        producer.capabilities = outbox_producer_capability(&["identity.session-created"]);
        producer.effect_profile = effect_profile(&[
            EffectKind::Auth,
            EffectKind::Write,
            EffectKind::Transaction,
            EffectKind::Outbox,
            EffectKind::Publish,
        ]);

        let mut saga = saga_manifest(Some(valid_saga_block()));
        saga.capabilities = workflow_saga_capability();

        let mut projection = manifest(
            ContractKind::Http,
            ConsistencyLevel::WorkflowEventual,
            ContractOwner::Domain("audit".to_string()),
            http_schemas(),
        );
        projection.id = "audit.session-projection".to_string();
        projection.capabilities = workflow_projection_capability();
        projection.effect_profile =
            effect_profile(&[EffectKind::Auth, EffectKind::Read, EffectKind::Projection]);

        let mut device = manifest(
            ContractKind::Http,
            ConsistencyLevel::DeviceLatent,
            ContractOwner::Domain("device".to_string()),
            http_schemas(),
        );
        device.id = "device.cert-reconcile".to_string();
        device.capabilities = device_latent_capability();
        device.reconcile = Some(valid_reconcile_block());
        device.effect_profile =
            effect_profile(&[EffectKind::Auth, EffectKind::Reconcile, EffectKind::Worker]);

        let contracts = vec![
            discovered(local, PathBuf::from("/x")),
            discovered(local_tx, PathBuf::from("/x")),
            discovered(fact, PathBuf::from("/x")),
            discovered(command, PathBuf::from("/x")),
            discovered(producer, PathBuf::from("/x")),
            discovered(saga, PathBuf::from("/x")),
            discovered(projection, PathBuf::from("/x")),
            discovered(device, PathBuf::from("/x")),
        ];
        let findings = rule_consistency_capability(&contracts);
        assert!(findings.is_empty(), "{findings:?}");
    }

    // ── R13 SchemaTitle（per-contract，读 declared schema 文件）──────────────

    /// 写一个 http 契约目录（request/response schema 内容自定），返回 (DiscoveredContract, dir)。
    /// 调用方负责 `remove_dir_all` 清理。
    fn http_contract_with_schemas(
        request: &str,
        response: &str,
    ) -> anyhow::Result<(DiscoveredContract, PathBuf)> {
        let dir = unique_tmp("validate-title");
        std::fs::create_dir_all(&dir)?;
        std::fs::write(dir.join("request.schema.json"), request)?;
        std::fs::write(dir.join("response.schema.json"), response)?;
        let m = manifest(
            ContractKind::Http,
            ConsistencyLevel::LocalOnly,
            ContractOwner::Framework,
            http_schemas(),
        );
        Ok((discovered(m, dir.clone()), dir))
    }

    /// 写一个 saga 契约目录（payload + reserve step output schema 内容自定），返回 (DiscoveredContract, dir)。
    /// 调用方负责 `remove_dir_all` 清理。
    fn saga_contract_with_schemas(
        payload: &str,
        reserve: &str,
    ) -> anyhow::Result<(DiscoveredContract, PathBuf)> {
        let dir = unique_tmp("validate-title-saga");
        std::fs::create_dir_all(&dir)?;
        std::fs::write(dir.join("payload.schema.json"), payload)?;
        std::fs::write(dir.join("reserve.schema.json"), reserve)?;
        Ok((
            discovered(saga_manifest(Some(valid_saga_block())), dir.clone()),
            dir,
        ))
    }

    fn make_active_get(
        m: &mut ContractManifest,
        path: &str,
        permission: &str,
        projection: Option<HttpProjection>,
    ) {
        m.lifecycle = Lifecycle::Active;
        m.path = Some(path.to_string());
        m.method = Some(HttpMethod::Get);
        m.endpoints = Some(Endpoints {
            http: Some(HttpEndpoint {
                auth: Some(HttpAuth {
                    mode: HttpAuthMode::Permission,
                    reason: None,
                    permission: Some(permission.to_string()),
                }),
                resource: None,
                self_scoped: false,
                resource_sharing: None,
                headers: BTreeMap::new(),
                projection,
            }),
        });
    }

    #[test]
    fn r13_non_pascal_top_level_title_detected() -> anyhow::Result<()> {
        let (c, dir) = http_contract_with_schemas(
            r#"{"title":"seed_echo"}"#,
            r#"{"title":"SeedEchoResponse"}"#,
        )?;
        let findings = rule_schema_title(&c, "x");
        let _ = std::fs::remove_dir_all(&dir);
        assert!(findings.iter().any(|f| f.rule == Rule::SchemaTitle));
        assert!(findings.iter().any(|f| f.detail.contains("seed_echo")));
        Ok(())
    }

    #[test]
    fn r13_non_pascal_nested_title_detected() -> anyhow::Result<()> {
        // walker 须下钻 properties value 收集嵌套对象 title。
        let (c, dir) = http_contract_with_schemas(
            r#"{"title":"SeedEchoRequest"}"#,
            r#"{"title":"SeedEchoResponse","properties":{"data":{"title":"echo_data"}}}"#,
        )?;
        let findings = rule_schema_title(&c, "x");
        let _ = std::fs::remove_dir_all(&dir);
        assert!(
            findings
                .iter()
                .any(|f| f.rule == Rule::SchemaTitle && f.detail.contains("echo_data"))
        );
        Ok(())
    }

    #[test]
    fn r13_intra_contract_duplicate_across_files_detected() -> anyhow::Result<()> {
        // 同一契约 request + response 喂同一 TypeSpace → title 须契约内唯一。
        let (c, dir) = http_contract_with_schemas(r#"{"title":"Dup"}"#, r#"{"title":"Dup"}"#)?;
        let findings = rule_schema_title(&c, "x");
        let _ = std::fs::remove_dir_all(&dir);
        assert!(
            findings
                .iter()
                .any(|f| f.rule == Rule::SchemaTitle && f.detail.contains("契约内重复"))
        );
        Ok(())
    }

    #[test]
    fn r13_top_level_vs_nested_duplicate_detected() -> anyhow::Result<()> {
        let (c, dir) = http_contract_with_schemas(
            r#"{"title":"SeedEchoRequest"}"#,
            r#"{"title":"Foo","properties":{"data":{"title":"Foo"}}}"#,
        )?;
        let findings = rule_schema_title(&c, "x");
        let _ = std::fs::remove_dir_all(&dir);
        assert!(
            findings
                .iter()
                .any(|f| f.rule == Rule::SchemaTitle && f.detail.contains("Foo"))
        );
        Ok(())
    }

    #[test]
    fn r13_valid_titles_ok() -> anyhow::Result<()> {
        // anti-vacuity：仿真实 seed 契约，全 PascalCase 且契约内唯一 → 无 finding。
        let (c, dir) = http_contract_with_schemas(
            r#"{"title":"SeedEchoRequest","type":"object","properties":{"msg":{"type":"string"}}}"#,
            r#"{"title":"SeedEchoResponse","properties":{"data":{"title":"SeedEchoData"}}}"#,
        )?;
        let findings = rule_schema_title(&c, "x");
        let _ = std::fs::remove_dir_all(&dir);
        assert!(findings.is_empty(), "{findings:?}");
        Ok(())
    }

    #[test]
    fn r13_property_named_title_not_treated_as_type() -> anyhow::Result<()> {
        // 防误报关键：property **名**恰为 "title" 不被当作 schema 的 title 关键字。
        // root title 合法存在（满足 ⓪ 必填门），被测的只是 properties 下名为 "title" 的字段不被收集。
        let (c, dir) = http_contract_with_schemas(
            r#"{"title":"SeedEchoRequest","type":"object","properties":{"title":{"type":"string"}}}"#,
            r#"{"title":"SeedEchoResponse"}"#,
        )?;
        let findings = rule_schema_title(&c, "x");
        let _ = std::fs::remove_dir_all(&dir);
        assert!(
            findings.is_empty(),
            "property 名 title 不该被当类型名: {findings:?}"
        );
        Ok(())
    }

    #[test]
    fn r13_unparseable_schema_skipped() -> anyhow::Result<()> {
        // JSON 良构由 codegen parse 门兜底；本规则对坏 JSON skip（不 panic、不报）。
        let (c, dir) =
            http_contract_with_schemas(r#"{ this is not json"#, r#"{"title":"SeedEchoResponse"}"#)?;
        let findings = rule_schema_title(&c, "x");
        let _ = std::fs::remove_dir_all(&dir);
        assert!(findings.is_empty(), "坏 JSON 应 skip: {findings:?}");
        Ok(())
    }

    #[test]
    fn r13_missing_schema_file_skipped() -> anyhow::Result<()> {
        // 文件缺失由 R5 报；SchemaTitle 不重复报、不 panic。
        let dir = unique_tmp("validate-title");
        std::fs::create_dir_all(&dir)?;
        std::fs::write(
            dir.join("response.schema.json"),
            r#"{"title":"SeedEchoResponse"}"#,
        )?;
        // request.schema.json 声明但不建。
        let m = manifest(
            ContractKind::Http,
            ConsistencyLevel::LocalOnly,
            ContractOwner::Framework,
            http_schemas(),
        );
        let findings = rule_schema_title(&discovered(m, dir.clone()), "x");
        let _ = std::fs::remove_dir_all(&dir);
        assert!(findings.is_empty(), "{findings:?}");
        Ok(())
    }

    #[test]
    fn r13_walker_covers_defs_items_oneof() -> anyhow::Result<()> {
        // walker 须下钻 $defs / items(数组 tuple) / oneOf——内嵌 title 纳入唯一性集。
        // 此处各位置 title 合法且唯一 → 无 finding（验 walker 不漏不误）。
        let req = r#"{
            "title":"ReqRoot",
            "$defs":{"Inner":{"title":"DefInner"}},
            "properties":{
                "tup":{"items":[{"title":"TupA"},{"title":"TupB"}]},
                "choice":{"oneOf":[{"title":"ChoiceA"},{"title":"ChoiceB"}]}
            }
        }"#;
        let (c, dir) = http_contract_with_schemas(req, r#"{"title":"RespRoot"}"#)?;
        let findings = rule_schema_title(&c, "x");
        let _ = std::fs::remove_dir_all(&dir);
        assert!(findings.is_empty(), "{findings:?}");
        Ok(())
    }

    #[test]
    fn r13_intra_file_duplicate_detected() -> anyhow::Result<()> {
        // 同一文件内两处同 title（顶层 + 嵌套）→ 契约内重复；诊断不应重复列同一文件名（dedup）。
        let (c, dir) = http_contract_with_schemas(
            r#"{"title":"Dup","properties":{"data":{"title":"Dup"}}}"#,
            r#"{"title":"SeedEchoResponse"}"#,
        )?;
        let findings = rule_schema_title(&c, "x");
        let _ = std::fs::remove_dir_all(&dir);
        let dups: Vec<_> = findings
            .iter()
            .filter(|f| f.rule == Rule::SchemaTitle && f.detail.contains("契约内重复"))
            .collect();
        assert_eq!(dups.len(), 1, "同文件内重复应报 1 条: {findings:?}");
        assert!(
            !dups[0]
                .detail
                .contains("request.schema.json、request.schema.json"),
            "诊断不应重复列同名文件: {}",
            dups[0].detail
        );
        Ok(())
    }

    #[test]
    fn r13_unsafe_schema_path_skipped() -> anyhow::Result<()> {
        // 防御性 fail-safe：declared schema 含路径分量（R6 已报）→ R13 主动 skip，不 `join` 读它。
        let dir = unique_tmp("validate-title");
        std::fs::create_dir_all(&dir)?;
        std::fs::write(
            dir.join("response.schema.json"),
            r#"{"title":"SeedEchoResponse"}"#,
        )?;
        let m = manifest(
            ContractKind::Http,
            ConsistencyLevel::LocalOnly,
            ContractOwner::Framework,
            Schemas {
                request: Some("../request.schema.json".to_string()),
                response: Some("response.schema.json".to_string()),
                ..Schemas::default()
            },
        );
        let findings = rule_schema_title(&discovered(m, dir.clone()), "x");
        let _ = std::fs::remove_dir_all(&dir);
        assert!(findings.is_empty(), "R13 应 skip 不安全路径: {findings:?}");
        Ok(())
    }

    #[test]
    fn r13_missing_root_title_detected() -> anyhow::Result<()> {
        // 复现：declared schema 无 root title → typify add_root_schema 返回 Ok(None)、不生成根类型。
        // R13 须 fail-fast 报缺 root title（此前只校验已收集到的 title，root 缺 title 静默放过）。
        let (c, dir) = http_contract_with_schemas(
            r#"{"type":"object","properties":{"msg":{"type":"string"}}}"#, // 无 root title
            r#"{"title":"SeedEchoResponse"}"#,
        )?;
        let findings = rule_schema_title(&c, "x");
        let _ = std::fs::remove_dir_all(&dir);
        assert!(
            findings
                .iter()
                .any(|f| f.rule == Rule::SchemaTitle && f.detail.contains("root title")),
            "缺 root title 须报 SchemaTitle: {findings:?}"
        );
        Ok(())
    }

    #[test]
    fn r13_non_string_root_title_detected() -> anyhow::Result<()> {
        // root title 非 string（如数字）→ 既不被 collect_schema_titles 收集（只收 string），
        // 也等同 typify「无 title」语义 → 须报缺 root title。
        let (c, dir) =
            http_contract_with_schemas(r#"{"title":123}"#, r#"{"title":"SeedEchoResponse"}"#)?;
        let findings = rule_schema_title(&c, "x");
        let _ = std::fs::remove_dir_all(&dir);
        assert!(
            findings
                .iter()
                .any(|f| f.rule == Rule::SchemaTitle && f.detail.contains("root title")),
            "非 string root title 须报 SchemaTitle: {findings:?}"
        );
        Ok(())
    }

    #[test]
    fn r13_saga_step_output_missing_root_title_detected() -> anyhow::Result<()> {
        let (c, dir) = saga_contract_with_schemas(
            r#"{"title":"BillingCheckoutSagaPayload"}"#,
            r#"{"type":"object","properties":{"reservationId":{"type":"string"}}}"#,
        )?;
        let findings = rule_schema_title(&c, "x");
        let _ = std::fs::remove_dir_all(&dir);
        assert!(
            findings.iter().any(|f| {
                f.rule == Rule::SchemaTitle
                    && f.detail.contains("root title")
                    && f.detail.contains("reserve.schema.json")
            }),
            "saga step outputSchema 缺 root title 须报 SchemaTitle: {findings:?}"
        );
        Ok(())
    }

    #[test]
    fn r13_saga_step_output_non_pascal_title_detected() -> anyhow::Result<()> {
        let (c, dir) = saga_contract_with_schemas(
            r#"{"title":"BillingCheckoutSagaPayload"}"#,
            r#"{"title":"reserve_output","type":"object"}"#,
        )?;
        let findings = rule_schema_title(&c, "x");
        let _ = std::fs::remove_dir_all(&dir);
        assert!(
            findings.iter().any(|f| {
                f.rule == Rule::SchemaTitle
                    && f.detail.contains("reserve_output")
                    && f.detail.contains("reserve.schema.json")
            }),
            "saga step outputSchema 非 PascalCase title 须报 SchemaTitle: {findings:?}"
        );
        Ok(())
    }

    #[test]
    fn r13_saga_step_output_duplicate_title_detected() -> anyhow::Result<()> {
        let (c, dir) = saga_contract_with_schemas(r#"{"title":"Dup"}"#, r#"{"title":"Dup"}"#)?;
        let findings = rule_schema_title(&c, "x");
        let _ = std::fs::remove_dir_all(&dir);
        assert!(
            findings.iter().any(|f| {
                f.rule == Rule::SchemaTitle
                    && f.detail.contains("契约内重复")
                    && f.detail.contains("reserve.schema.json")
            }),
            "saga payload + step outputSchema 重复 title 须报 SchemaTitle: {findings:?}"
        );
        Ok(())
    }

    #[rstest]
    #[case("SeedEchoData", true)]
    #[case("A", true)]
    #[case("Foo9Bar", true)]
    #[case("seed_echo", false)] // snake
    #[case("seedEcho", false)] // camel（首字符小写）
    #[case("9Foo", false)] // 数字开头
    #[case("Foo-Bar", false)] // 连字符
    #[case("Foo_Bar", false)] // 下划线
    #[case("", false)] // 空
    fn r13_is_pascal_case(#[case] s: &str, #[case] want: bool) {
        assert_eq!(is_pascal_case(s), want, "is_pascal_case({s:?})");
    }

    // ── R16 SchemaRedaction（contract → generated 安全 Debug 单源）────────

    #[test]
    fn r16_rejects_invalid_redaction_extensions() -> anyhow::Result<()> {
        let dir = unique_tmp("validate");
        std::fs::create_dir_all(&dir)?;
        std::fs::write(
            dir.join("request.schema.json"),
            r#"{
              "title":"RedactionReq",
              "type":"object",
              "x-sensitive": true,
              "properties": {
                "password": {"type":"string"},
                "email": {"type":"string", "x-pii":"bogus"},
                "phone": {"type":"string", "x-pii":"phone", "x-redaction":"hash"}
              }
            }"#,
        )?;
        let c = discovered(
            manifest(
                ContractKind::Http,
                ConsistencyLevel::LocalOnly,
                ContractOwner::Framework,
                Schemas {
                    request: Some("request.schema.json".to_string()),
                    ..Schemas::default()
                },
            ),
            dir.clone(),
        );
        let findings = rule_schema_redaction(&c, "http/_seed/v1");
        let _ = std::fs::remove_dir_all(&dir);
        assert!(
            findings
                .iter()
                .any(|f| f.rule == Rule::SchemaRedaction && f.detail.contains("x-sensitive")),
            "遗留 x-sensitive 须报错: {findings:?}"
        );
        assert!(
            findings
                .iter()
                .any(|f| f.detail.contains("password") && f.detail.contains("高风险字段")),
            "高风险字段未声明须报错: {findings:?}"
        );
        assert!(
            findings.iter().any(|f| f.detail.contains("bogus")),
            "非法 x-pii 须报错: {findings:?}"
        );
        assert!(
            findings.iter().any(|f| f.detail.contains("hash")),
            "x-redaction=hash 须报错: {findings:?}"
        );
        Ok(())
    }

    #[test]
    fn r16_accepts_nested_field_policies() -> anyhow::Result<()> {
        let dir = unique_tmp("validate");
        std::fs::create_dir_all(&dir)?;
        std::fs::write(
            dir.join("request.schema.json"),
            r#"{
              "title":"RedactionReq",
              "type":"object",
              "properties": {
                "username": {"type":"string"},
                "password": {"type":"string", "x-redaction":"secret"},
                "data": {
                  "title":"RedactionData",
                  "type":"object",
                  "properties": {
                    "subject": {"type":"string", "x-pii":"generic"}
                  }
                }
              }
            }"#,
        )?;
        let c = discovered(
            manifest(
                ContractKind::Http,
                ConsistencyLevel::LocalOnly,
                ContractOwner::Framework,
                Schemas {
                    request: Some("request.schema.json".to_string()),
                    ..Schemas::default()
                },
            ),
            dir.clone(),
        );
        let findings = rule_schema_redaction(&c, "http/_seed/v1");
        let _ = std::fs::remove_dir_all(&dir);
        assert!(findings.is_empty(), "{findings:?}");
        Ok(())
    }

    #[test]
    fn r16_rejects_saga_step_output_schema_redaction_violations() -> anyhow::Result<()> {
        let dir = unique_tmp("validate");
        std::fs::create_dir_all(&dir)?;
        std::fs::write(
            dir.join("payload.schema.json"),
            r#"{"title":"SagaPayload","type":"object","properties":{}}"#,
        )?;
        std::fs::write(
            dir.join("reserve.schema.json"),
            r#"{
              "title":"ReserveFundsOutput",
              "type":"object",
              "properties": {
                "sessionId": {"type":"string"}
              }
            }"#,
        )?;
        let c = discovered(saga_manifest(Some(valid_saga_block())), dir.clone());
        let findings = rule_schema_redaction(&c, "saga/_seed/v1");
        let _ = std::fs::remove_dir_all(&dir);
        assert!(
            findings.iter().any(|f| {
                f.rule == Rule::SchemaRedaction
                    && f.detail.contains("reserve.schema.json")
                    && f.detail.contains("sessionId")
            }),
            "saga step outputSchema redaction violations must be checked: {findings:?}"
        );
        Ok(())
    }

    #[test]
    fn real_contracts_pass_all_rules() -> anyhow::Result<()> {
        // anti-vacuity（正向，真实数据）：仓库 contracts/ 全部契约经 validate_root 零 finding——
        // 同时守 R12/R13 不在真实契约 / title 上误报。
        let root = crate::workspace_root()?.join("contracts");
        let (count, findings) = validate_root(&root)?;
        assert!(count > 0, "应发现至少一个契约");
        assert!(findings.is_empty(), "真实契约应零 finding: {findings:?}");
        Ok(())
    }
}
