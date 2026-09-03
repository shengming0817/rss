//! `cargo xtask contract validate` 的契约语义 executor 与 prerequisite。
//!
//! 规则身份、顺序、owner/source、handler binding 与生成文档的唯一真源是
//! `contract::governance` typed catalog；本模块不得定义平行 catalog，只实现其 executor。
//!
//! INVARIANT: CONTRACT-FANOUT-01 { level = "Medium", exec = "check", source = "code" }— schema 引用完整性 + kind→形态一致（R4/R5，含 saga step `receiptSchema`）。
//! INVARIANT: CONTRACT-SCHEMA-PARSE-01 { level = "Medium", exec = "check", source = "code", synthetic_red = "contract::governance::tests::malformed_schema_yields_one_canonical_source_finding", anti_vacuity = "contract::governance::tests::real_workspace_loads_through_governance_ir" }— repository inspection 按物理路径 parse once；malformed source 只投影一次 canonical R5 finding，且不能提升为 schema consumer 可见的 typed IR。
//! INVARIANT: CONTRACT-FREEZE-01 { level = "Medium", exec = "check", source = "code" }（运行期部分）— 跨字段不变式（R1 saga⇒L3 / R2 framework⇒http|event）、
//! 路径↔字段一致（R3）、authoring 标识符语法（R7：domain/version/id/owner 在拼进派生路径 / module 名前先收口）、
//! per-kind 字段（#1035）的 active 发布接线必填（R8）/ 跨 kind 卫生（R9）/ saga block 结构语义（R10）/
//! active event 投递语义可兑现性（R11）。
//! INVARIANT: SAGA-CONTRACT-01 { level = "Medium", exec = "check", source = "code" }— kind:saga 契约治理（generated / diport::SagaDurableStore / saga conformance）= R1（saga ⇒
//! consistencyLevel WorkflowEventual/L3）+ R10（非空 `[saga]` block：≥1 step、step name 合法非关键字 Rust
//! 标识符且唯一、每步 receiptSchema/effect scope 非空；retry budget/backoff 由 manifest.rs + R10
//! 类型层 Hard 守）。负用例见 R1/R10 synthetic reds；正用例 = `contracts/saga/billing` 经 validate 全过
//! （Medium，CI 门，#1121）。
//! INVARIANT: CONTRACT-IDUNIQ-01 { level = "Medium", exec = "check", source = "code" }— contract `id` 跨契约全局唯一（R12，`validate_cross` 跨契约扫描；
//! 依据 cargo xtask contract breaking / cargo public-api：破坏式 wire 变更新建版本目录 **且** 新 contract ID ⇒ id 是全局注册标识，须唯一）。
//! INVARIANT: CONTRACT-TITLE-01 { level = "Medium", exec = "check", source = "code" }— declared schema（喂 codegen TypeSpace 的 request/response/payload；saga 另含 step receiptSchema）的
//! root 须有 string `title`（缺则 typify `add_root_schema` 返回 `Ok(None)`、根类型静默丢失），且全部
//! （含嵌套）title 须 PascalCase + **契约内**唯一（R13；title→typify Rust 类型名）。契约内重复 / 缺 root
//! title **未必**被 codegen 兜底（前者可能被合并 / 类型歧义、后者直接丢根类型，均非 compile error、非
//! fail-closed）；本规则在 validate 阶段提供 fail-fast + 清晰诊断（早于 codegen）+ PascalCase 形态。
//! INVARIANT: EVENT-ACTIVE-SUB-01 { level = "Medium", exec = "check", source = "code", synthetic_red = "tests::r14_active_event_empty_subscriptions_rejected", anti_vacuity = "tests::r14_active_event_with_subscription_ok" }— `lifecycle=active && kind=event` ⇒ `[[subscriptions]]` 非空（R14，Medium）；
//! active event 无 subscriber 即死事件，视为错误配置（#1120）。
//! INVARIANT: SUBSCRIPTION-EXTERNAL-EFFECT-POLICY-01 { level = "Medium", exec = "check", source = "code", synthetic_red = "tests::wire_metadata_rejects_external_effect_policy_mismatch", anti_vacuity = "tests::wire_metadata_accepts_valid_closed_shapes" }— 每条 subscription 的 execution/effect/externalEffectPolicy 必须命中闭合语义矩阵；未知或缺失 policy 由 manifest 闭枚举/必填字段在解析期 Hard 拒绝。
//! INVARIANT: CONTRACT-REDACTION-POLICY-01 { level = "Medium", exec = "check", source = "code" }— declared schema property 上的 `x-pii` / `x-redaction`
//! 是 generated 安全 `Debug` 的单源（R16）。遗留 `x-sensitive`、未知枚举、高风险字段未标注、
//! `x-redaction=hash` 均 fail-closed。
//! INVARIANT: CONTRACT-PROTECTION-POLICY-01 { level = "Medium", exec = "check", source = "code" }— declared schema 的 `x-protection`（at-rest 加密声明）+
//! `x-at-rest`（持久化 opt-in）合法且完整（R17，#1468，ADR-011 D1b 声明层）。block 内部一致、AAD 维度
//! 完整（D2）、deterministic/blindIndex 须 reason 且 aad 稳定子集（D4）、`x-at-rest` schema 高风险字段
//! 须显式 `x-protection`、加密字段不得 nullable、blindIndex 只允许非 nullable scalar，均 fail-closed。
//! 与 R16 observe redaction **正交不混用**（ADR-011 D1）。
//! INVARIANT: CONTRACT-HTTP-SERVING-01 { level = "Medium", exec = "check", source = "code" }— active HTTP serving 必须声明 fail-closed auth/header metadata（R18）；
//! HTTP request schema 不得声明 `tenantId`，tenant scope 必须来自认证上下文、声明式 populate-only header
//! 或 service-token exact-one header challenger（与 signed typed tenant claim equality）（R19）；target tenant 必须来自显式 path 参数，不保留 request schema 例外。
//! INVARIANT: CONTRACT-HTTP-PROJECTION-COVERAGE-01 { level = "Medium", exec = "check", source = "code" }— active GET response
//! 中的 `x-pii` 字段与 `tenantId` 字段必须经 `[endpoints.http.projection]` 的 `responsePath` 精确 enrollment（R23）；
//! contract metadata/codegen 是唯一 carrier，handler 不维护人工矩阵。
//! INVARIANT: CONTRACT-CONSISTENCY-CAPABILITY-01 { level = "Medium", exec = "check", source = "code", synthetic_red = "tests::r22_http_outbox_emits_must_stay_in_producer_domain_for_every_lifecycle", anti_vacuity = "tests::r22_http_outbox_emits_accepts_same_domain_for_every_lifecycle" }— `consistencyLevel`
//! 必须有 typed `[capabilities.*]` 证据，且能力块不得跨等级漂移（R22）。HTTP L2 producer 的 `emits`
//! 在 draft/active/deprecated 全 lifecycle 都须引用同 domain 中存在的 L2 event；active producer 还要求目标
//! active 且有 subscriber readiness。L3 只接受当前 manifest 能表达的 workflow 证据；L4 还要求
//! device-latent evidence + `[reconcile]` block。
//! INVARIANT: CONTRACT-DEVICE-CERTIFICATE-HTTP-CLOSURE-01 { level = "Medium", exec = "check", source = "code", synthetic_red = "tests::r25_device_certificate_policy_route_auth_and_consistency_are_exact", anti_vacuity = "tests::r25_device_certificate_draft_pair_is_anti_vacuity_green" }—
//! 设备证书 desired-state/status HTTP 契约族的 identity/route/auth/schema/L4 metadata/links 由 R25
//! 精确闭合；draft linked target 若存在必须 kind/consistency 正确，source active 则四 target
//! 必须全存在且 active。
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
//! 下列 INVARIANT 只解释 executor 语义与失败原因；规则身份和 catalog 仍只属于
//! `contract::governance`。

use anyhow::Result;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use super::DeviceCertificateCandidateId;
use super::manifest::{
    Capabilities, ConsistencyLevel, ContractKind, ContractManifest, Delivery, DeviceLatentFencing,
    DeviceLatentLateMessagePolicy, DeviceLatentLoop, DeviceLatentProfile, DeviceLatentTenancy,
    DeviceLatentTrigger, ExternalEffectPolicy, FIELD_COMMAND, FIELD_DELIVERY, FIELD_EFFECT_PROFILE,
    FIELD_ENDPOINTS_HTTP_AUTH, FIELD_ENDPOINTS_HTTP_HEADERS, FIELD_ENDPOINTS_HTTP_PROJECTION,
    FIELD_ENDPOINTS_HTTP_RESOURCE_SHARING, FIELD_METHOD, FIELD_PATH, FIELD_RECONCILE, FIELD_SAGA,
    FIELD_SUBSCRIPTIONS, FIELD_TOPIC, HttpAuth, HttpAuthMode, HttpEndpoint, HttpHeaderMode,
    HttpIdempotency, HttpMethod, HttpResourceSharingMode, HttpStatusCode, Lifecycle,
    LocalTxBoundary, LocalTxCommitUnknown, LocalTxModel, LocalTxRetry, OutboxAtomicity, OutboxRole,
    SCHEMA_KEY_PAYLOAD, SCHEMA_KEY_PROJECTION, SCHEMA_KEY_REQUEST, SCHEMA_KEY_RESPONSE,
    SubscriptionEffect, SubscriptionExecution, WorkflowMode, WorkflowOrdering, WorkflowRequirement,
};
use super::protection;
use super::redaction;
use super::schema_declares_property;
use crate::diagnostic::{self, GovernanceCheck, finding};
use crate::pathsafe;
use assembly_schema::repository_contract::RepositoryContract;

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
const CAP_WORKFLOW_MODE_SAGA: &str = "capabilities.workflow.mode=saga";
const CAP_WORKFLOW_MODE_PROJECTION: &str = "capabilities.workflow.mode=projection";
const CAP_WORKFLOW_INPUTS: &str = "capabilities.workflow.inputs";
const CAP_WORKFLOW_ORDERING: &str = "capabilities.workflow.ordering";
const CAP_WORKFLOW_CHECKPOINT: &str = "capabilities.workflow.checkpoint";
const CAP_WORKFLOW_REPLAY: &str = "capabilities.workflow.replay";
const CAP_WORKFLOW_FIELD_SCOPE: &str = "capabilities.workflow.field-scope";
const CAP_CAPABILITY_SCOPE: &str = "capability-scope";
const CAP_EFFECT_PROFILE_EFFECTS: &str = "effectProfile.effects";

const R25_POLICY_ID: &str = DeviceCertificateCandidateId::PolicyPut.spec().id;
const R25_STATUS_ID: &str = DeviceCertificateCandidateId::StatusGet.spec().id;
const R25_LEGACY_ID: &str = "identity.reconcile-loop";
const R25_POLICY_PATH: &str = "/api/v2/identity/devices/{deviceId}/certificate-policy";
const R25_STATUS_PATH: &str = "/api/v2/identity/devices/{deviceId}/certificate-status";
const R25_HTTP_PATH_PREFIX: &str = "/api/v2/identity/devices/{deviceId}/certificate";
const R25_PERMISSION_PREFIX: &str = "identity:device-certificate";
const R25_POLICY_PERMISSION: vocab::RoutePermissionId =
    vocab::RoutePermissionId::IdentityDeviceCertificatePolicyWrite;
const R25_STATUS_PERMISSION: vocab::RoutePermissionId =
    vocab::RoutePermissionId::IdentityDeviceCertificateStatusRead;
const R25_COMMAND_ID: &str = DeviceCertificateCandidateId::ApplyCommand.spec().id;
const R25_ACK_EVENT_ID: &str = DeviceCertificateCandidateId::CommandAcked.spec().id;
const R25_REPORTED_EVENT_ID: &str = DeviceCertificateCandidateId::CertificateReported.spec().id;
const R25_INGRESS_RECEIPT_EVENT_ID: &str = DeviceCertificateCandidateId::IngressReceipted.spec().id;
const IDENTITY_ABAC_OPERATOR_COMPONENT: &str = "rss://component/identity/v1/common-abac-operator";

pub(crate) use super::governance::ContractRuleId as Rule;

/// `cargo xtask contract validate` 校验器（issue #1058：经 [`GovernanceCheck`] 统一编排）。
pub(crate) struct ContractValidate;

impl GovernanceCheck for ContractValidate {
    type Rule = Rule;
    fn name(&self) -> &'static str {
        "contract validate"
    }
    fn check(&self) -> Result<(String, Vec<Finding>)> {
        super::governance::validate_catalog()?;
        let root = crate::workspace_root()?;
        super::source_funnel::validate_source_funnel(&root)?;
        let (count, findings) = validate_workspace(&root)?;
        Ok((format!("{count} 契约全部通过"), findings))
    }
}

fn validate_workspace(root: &Path) -> Result<(usize, Vec<Finding>)> {
    let inspection = super::governance::ContractGovernanceIr::inspect_workspace(root)?;
    Ok((inspection.source_count(), inspection.findings().to_vec()))
}

/// Run the complete workspace contract validation against an already discovered catalog.
///
/// Consumers that need both validation and a typed projection must discover exactly once and
/// pass that immutable universe here; this prevents validation/build time-of-check drift.
pub(crate) fn validate_discovered_workspace(
    _root: &Path,
    contracts: &[RepositoryContract],
) -> Result<(usize, Vec<Finding>)> {
    Ok((contracts.len(), validate_discovered_contracts(contracts)))
}

#[cfg(test)]
fn validate_root(contracts_root: &Path) -> Result<(usize, Vec<Finding>)> {
    let inspection =
        super::governance::ContractGovernanceIr::inspect_contracts_root(contracts_root)?;
    Ok((inspection.source_count(), inspection.findings().to_vec()))
}

pub(crate) fn validate_discovered_contracts(contracts: &[RepositoryContract]) -> Vec<Finding> {
    let mut findings = Vec::new();
    for c in contracts {
        findings.extend(validate_contract(c));
    }
    findings.extend(validate_cross(contracts));
    findings
}

/// Validate an isolated codegen fixture repository with every per-contract rule plus the generic
/// repository closure rules. Workspace-specific canonical-family and production-owner
/// anti-vacuity rules intentionally remain exclusive to the production catalog.
pub(crate) fn validate_discovered_codegen_fixtures(
    contracts: &[RepositoryContract],
) -> Vec<Finding> {
    let mut findings = Vec::new();
    for contract in contracts {
        findings.extend(validate_contract(contract));
    }
    for (_, handler) in super::governance::codegen_fixture_catalog_validation_plan() {
        findings.extend(handler(contracts));
    }
    findings
}

/// Execute catalog-scoped rules from the canonical rule plan.
fn validate_cross(contracts: &[RepositoryContract]) -> Vec<Finding> {
    let mut out = Vec::new();
    for (_, handler) in super::governance::catalog_validation_plan() {
        out.extend(handler(contracts));
    }
    out
}

pub(crate) fn execute_duplicate_id(contracts: &[RepositoryContract]) -> Vec<Finding> {
    rule_duplicate_id(contracts)
}

pub(crate) fn execute_slug_mixing(contracts: &[RepositoryContract]) -> Vec<Finding> {
    rule_slug_mixing(contracts)
}

pub(crate) fn execute_consistency_capability(contracts: &[RepositoryContract]) -> Vec<Finding> {
    rule_consistency_capability(contracts)
}

pub(crate) fn execute_device_certificate_http_closure(
    contracts: &[RepositoryContract],
) -> Vec<Finding> {
    rule_device_certificate_http_closure(contracts)
}

/// R25：device-certificate 六份 Draft candidate 与唯一 HTTP operator surface 的闭包。
fn rule_device_certificate_http_closure(contracts: &[RepositoryContract]) -> Vec<Finding> {
    let by_id: BTreeMap<&str, &RepositoryContract> = contracts
        .iter()
        .map(|contract| (contract.manifest().id.as_str(), contract))
        .collect();
    let mut out = r25_candidate_exact_set_findings(contracts);

    out.extend(r25_operator_surface_findings(contracts, &by_id));
    out.extend(r25_http_contract_findings(&by_id));
    out.extend(r25_linked_target_findings(&by_id));
    out
}

fn r25_candidate_exact_set_findings(contracts: &[RepositoryContract]) -> Vec<Finding> {
    let mut out = Vec::new();
    for candidate in DeviceCertificateCandidateId::ALL {
        let expected = candidate.spec();
        let matches = contracts
            .iter()
            .filter(|contract| contract.manifest().id == expected.id)
            .collect::<Vec<_>>();
        if matches.is_empty() {
            out.push(finding(
                Rule::DeviceCertificateHttpClosure,
                expected.source_dir,
                format!("required draft candidate contract id={} 缺失", expected.id),
            ));
            continue;
        }
        if matches.len() != 1 {
            out.push(r25_finding(
                matches[0],
                format!(
                    "draft candidate contract id={} 必须恰好出现一次，实为 {} 次",
                    expected.id,
                    matches.len()
                ),
            ));
        }
        for contract in matches {
            let manifest = contract.manifest();
            if manifest.kind != expected.kind {
                out.push(r25_finding(
                    contract,
                    format!(
                        "draft candidate id={} 必须 kind={}，实为 kind={}",
                        expected.id,
                        expected.kind.as_dir(),
                        manifest.kind.as_dir()
                    ),
                ));
            }
            if manifest.consistency_level != expected.consistency_level {
                out.push(r25_finding(
                    contract,
                    format!(
                        "draft candidate id={} 必须 consistencyLevel={:?}，实为 {:?}",
                        expected.id, expected.consistency_level, manifest.consistency_level
                    ),
                ));
            }
            if manifest.lifecycle != expected.lifecycle {
                out.push(r25_finding(
                    contract,
                    format!(
                        "draft candidate id={} 必须 lifecycle=draft，实为 {:?}",
                        expected.id, manifest.lifecycle
                    ),
                ));
            }
            if manifest.domain != "identity"
                || contract.owner().domain().map(|owner| owner.as_str()) != Some("identity")
            {
                out.push(r25_finding(
                    contract,
                    format!(
                        "draft candidate id={} 必须 domain/owner=identity，实为 domain={:?} owner={:?}",
                        expected.id,
                        manifest.domain,
                        contract.owner().as_str()
                    ),
                ));
            }
            if expected
                .source_dir
                .strip_prefix("contracts/")
                .is_none_or(|source_dir| !contract.dir().ends_with(source_dir))
            {
                out.push(r25_finding(
                    contract,
                    format!(
                        "draft candidate id={} 必须位于 canonical sourceDir={}，实为 {}",
                        expected.id,
                        expected.source_dir,
                        contract.dir().display()
                    ),
                ));
            }
        }
    }
    out
}

fn r25_operator_surface_findings(
    contracts: &[RepositoryContract],
    by_id: &BTreeMap<&str, &RepositoryContract>,
) -> Vec<Finding> {
    let mut out = Vec::new();
    if let Some(legacy) = by_id.get(R25_LEGACY_ID) {
        out.push(r25_finding(
            legacy,
            format!(
                "旧 contract id={R25_LEGACY_ID} 已被 {R25_POLICY_ID} + {R25_STATUS_ID} 直接替换，禁止 alias/shim 或并存"
            ),
        ));
    }

    for carrier in contracts.iter().filter(|contract| {
        contract.manifest().id != R25_POLICY_ID
            && contract.manifest().consistency_level == ConsistencyLevel::DeviceLatent
            && contract
                .manifest()
                .capabilities
                .device_latent
                .as_ref()
                .is_some_and(|capability| {
                    matches!(
                        &capability.profile,
                        DeviceLatentProfile::DeviceCertificate { .. }
                    )
                })
    }) {
        out.push(r25_finding(
            carrier,
            format!(
                "DeviceLatent resourceKind=device-certificate 只允许 canonical contract id={R25_POLICY_ID}，实为 id={}",
                carrier.manifest().id
            ),
        ));
    }

    let candidate_ids = DeviceCertificateCandidateId::ALL
        .into_iter()
        .map(|candidate| candidate.spec().id)
        .collect::<BTreeSet<_>>();
    for carrier in contracts.iter().filter(|contract| {
        let manifest = contract.manifest();
        if manifest.kind != ContractKind::Http || candidate_ids.contains(manifest.id.as_str()) {
            return false;
        }
        let path_matches = manifest
            .path
            .as_deref()
            .is_some_and(|path| path.starts_with(R25_HTTP_PATH_PREFIX));
        let permission_matches = manifest
            .endpoints
            .as_ref()
            .and_then(|endpoints| endpoints.http.as_ref())
            .and_then(|http| http.auth.as_ref())
            .and_then(|auth| auth.permission.as_deref())
            .is_some_and(|permission| permission.starts_with(R25_PERMISSION_PREFIX));
        path_matches || permission_matches
    }) {
        out.push(r25_finding(
            carrier,
            format!(
                "device-certificate HTTP operator surface 只允许 canonical draft candidate IDs，实为 id={}",
                carrier.manifest().id
            ),
        ));
    }
    out
}

fn r25_http_contract_findings(by_id: &BTreeMap<&str, &RepositoryContract>) -> Vec<Finding> {
    let mut out = Vec::new();
    let policy = by_id.get(R25_POLICY_ID).copied();
    let status = by_id.get(R25_STATUS_ID).copied();
    match policy {
        Some(policy) => out.extend(rule_device_certificate_policy(policy)),
        None => out.push(finding(
            Rule::DeviceCertificateHttpClosure,
            "http/identity/v2",
            format!("required contract id={R25_POLICY_ID} 缺失"),
        )),
    }
    match status {
        Some(status) => out.extend(rule_device_certificate_status(status)),
        None => out.push(finding(
            Rule::DeviceCertificateHttpClosure,
            "http/identity/v2",
            format!("required contract id={R25_STATUS_ID} 缺失"),
        )),
    }
    out
}

fn r25_linked_target_findings(by_id: &BTreeMap<&str, &RepositoryContract>) -> Vec<Finding> {
    let Some(policy) = by_id.get(R25_POLICY_ID).copied() else {
        return Vec::new();
    };
    let targets = [
        (R25_COMMAND_ID, ContractKind::Command),
        (R25_ACK_EVENT_ID, ContractKind::Event),
        (R25_REPORTED_EVENT_ID, ContractKind::Event),
        (R25_INGRESS_RECEIPT_EVENT_ID, ContractKind::Event),
    ];
    let mut out = Vec::new();
    for (target_id, expected_kind) in targets {
        let Some(target) = by_id.get(target_id).copied() else {
            out.push(r25_finding(
                policy,
                format!(
                    "draft source contract id={R25_POLICY_ID} 的 linked target id={target_id} 必须存在且 lifecycle=draft"
                ),
            ));
            continue;
        };
        out.extend(r25_linked_target_metadata_findings(
            policy,
            target,
            expected_kind,
        ));
    }
    out
}

fn r25_linked_target_metadata_findings(
    policy: &RepositoryContract,
    target: &RepositoryContract,
    expected_kind: ContractKind,
) -> Vec<Finding> {
    let manifest = target.manifest();
    let mut out = Vec::new();
    if manifest.kind != expected_kind {
        out.push(r25_linked_target_finding(
            policy,
            target,
            format!(
                "必须 kind={}，实为 kind={}",
                expected_kind.as_dir(),
                manifest.kind.as_dir()
            ),
        ));
    }
    if manifest.consistency_level != ConsistencyLevel::OutboxFact {
        out.push(r25_linked_target_finding(
            policy,
            target,
            format!(
                "必须 consistencyLevel=OutboxFact，实为 {:?}",
                manifest.consistency_level
            ),
        ));
    }
    if manifest.domain != "identity" {
        out.push(r25_linked_target_finding(
            policy,
            target,
            format!(
                "必须 target domain=identity，实为 domain={:?}",
                manifest.domain
            ),
        ));
    }
    if target.owner().domain().map(|owner| owner.as_str()) != Some("identity") {
        out.push(r25_linked_target_finding(
            policy,
            target,
            format!(
                "必须 target owner=identity，实为 owner={:?}",
                target.owner().as_str()
            ),
        ));
    }
    if manifest.lifecycle != Lifecycle::Draft {
        out.push(r25_linked_target_finding(
            policy,
            target,
            format!("必须 lifecycle=draft，实为 {:?}", manifest.lifecycle),
        ));
    }
    out
}

fn rule_device_certificate_policy(c: &RepositoryContract) -> Vec<Finding> {
    let mut out = rule_device_certificate_http_surface(
        c,
        ConsistencyLevel::DeviceLatent,
        HttpMethod::Put,
        R25_POLICY_PATH,
        R25_POLICY_PERMISSION,
    );
    let m = &c.manifest();
    let label = contract_label(c);

    if let Some((schema_file, request)) =
        r25_read_schema(c, R25_POLICY_ID, SCHEMA_KEY_REQUEST, &mut out)
    {
        if schema_declares_property(&request, "tenantId")
            || schema_declares_property(&request, "deviceId")
        {
            out.push(r25_finding(
                c,
                format!(
                    "contract id={R25_POLICY_ID} {schema_file} request root 禁止 tenantId/deviceId；tenant 来自认证上下文且 deviceId 来自 path"
                ),
            ));
        }
        for (pointer, property, annotation, expected) in [
            (
                "/properties/idempotencyKey",
                "idempotencyKey",
                "x-redaction",
                "internal",
            ),
            (
                "/properties/policy/properties/keyUsages",
                "keyUsages",
                "x-redaction",
                "internal",
            ),
            (
                "/properties/policy/properties/sans",
                "sans",
                "x-pii",
                "generic",
            ),
            (
                "/properties/policy/properties/sans",
                "sans",
                "x-redaction",
                "drop",
            ),
        ] {
            r25_validate_schema_annotation(
                c,
                R25_POLICY_ID,
                &schema_file,
                &request,
                pointer,
                property,
                annotation,
                expected,
                &mut out,
            );
        }
    }

    let _ = r25_read_schema(c, R25_POLICY_ID, SCHEMA_KEY_RESPONSE, &mut out);

    let expected_responses = BTreeSet::from([200, 400, 404, 409, 503]);
    let actual_responses: BTreeSet<u16> = m
        .schemas
        .responses
        .keys()
        .copied()
        .map(HttpStatusCode::get)
        .collect();
    if actual_responses != expected_responses {
        out.push(r25_finding(
            c,
            format!(
                "contract id={R25_POLICY_ID} typed response status 必须精确等于 {expected_responses:?}，实为 {actual_responses:?}"
            ),
        ));
    }

    let Some(device_latent) = &m.capabilities.device_latent else {
        out.push(finding(
            Rule::DeviceCertificateHttpClosure,
            label,
            format!(
                "contract id={R25_POLICY_ID} 必须声明 capabilities.deviceLatent profile resourceKind/links"
            ),
        ));
        return out;
    };
    if device_latent.loop_kind != DeviceLatentLoop::Reconcile
        || !matches!(
            &device_latent.profile,
            DeviceLatentProfile::DeviceCertificate { .. }
        )
    {
        out.push(finding(
            Rule::DeviceCertificateHttpClosure,
            label.clone(),
            format!(
                "contract id={R25_POLICY_ID} capabilities.deviceLatent 必须 loop=reconcile + resourceKind=device-certificate"
            ),
        ));
    }
    let DeviceLatentProfile::DeviceCertificate { links } = &device_latent.profile;
    for (field, actual, expected) in [
        ("command", links.command.as_str(), R25_COMMAND_ID),
        ("ackEvent", links.ack_event.as_str(), R25_ACK_EVENT_ID),
        (
            "reportedEvent",
            links.reported_event.as_str(),
            R25_REPORTED_EVENT_ID,
        ),
        (
            "ingressReceiptEvent",
            links.ingress_receipt_event.as_str(),
            R25_INGRESS_RECEIPT_EVENT_ID,
        ),
    ] {
        if actual != expected {
            out.push(finding(
                Rule::DeviceCertificateHttpClosure,
                label.clone(),
                format!(
                    "contract id={R25_POLICY_ID} capabilities.deviceLatent.profile.links.{field} 必须精确等于 {expected:?}，实为 {actual:?}"
                ),
            ));
        }
    }
    match &m.reconcile {
        Some(reconcile)
            if reconcile.tenancy == DeviceLatentTenancy::TenantScoped
                && reconcile.trigger == DeviceLatentTrigger::Interval
                && reconcile.fencing == DeviceLatentFencing::Required
                && reconcile.late_message_policy == DeviceLatentLateMessagePolicy::Idempotent => {}
        _ => out.push(finding(
            Rule::DeviceCertificateHttpClosure,
            label,
            format!(
                "contract id={R25_POLICY_ID} [reconcile] 必须 tenancy=tenant-scoped + trigger=interval + fencing=required + lateMessagePolicy=idempotent"
            ),
        )),
    }
    out
}

fn rule_device_certificate_status(c: &RepositoryContract) -> Vec<Finding> {
    let mut out = rule_device_certificate_http_surface(
        c,
        ConsistencyLevel::LocalOnly,
        HttpMethod::Get,
        R25_STATUS_PATH,
        R25_STATUS_PERMISSION,
    );
    let _ = r25_read_schema(c, R25_STATUS_ID, SCHEMA_KEY_REQUEST, &mut out);
    if let Some((schema_file, response)) =
        r25_read_schema(c, R25_STATUS_ID, SCHEMA_KEY_RESPONSE, &mut out)
        && schema_declares_property(&response, "payload")
    {
        out.push(r25_finding(
            c,
            format!(
                "contract id={R25_STATUS_ID} {schema_file} activeCommand 禁止 payload，仅允许 payload-free summary"
            ),
        ));
    }
    let expected_responses = BTreeSet::from([200, 400, 503]);
    let actual_responses = c
        .manifest()
        .schemas
        .responses
        .keys()
        .copied()
        .map(HttpStatusCode::get)
        .collect::<BTreeSet<_>>();
    if actual_responses != expected_responses {
        out.push(r25_finding(
            c,
            format!(
                "contract id={R25_STATUS_ID} typed response status 必须精确等于 {expected_responses:?}，实为 {actual_responses:?}"
            ),
        ));
    }
    out
}

fn r25_read_schema(
    c: &RepositoryContract,
    contract_id: &str,
    schema_role: &str,
    out: &mut Vec<Finding>,
) -> Option<(String, serde_json::Value)> {
    let schema_file = match schema_role {
        SCHEMA_KEY_REQUEST => c.manifest().schemas.request.as_deref(),
        SCHEMA_KEY_RESPONSE => c
            .manifest()
            .endpoints
            .as_ref()
            .and_then(|endpoints| endpoints.http.as_ref())
            .and_then(|http| c.manifest().schemas.response(http.success_status)),
        _ => None,
    };
    let Some(schema_file) = schema_file else {
        out.push(r25_finding(
            c,
            format!("contract id={contract_id} 必须声明非空 {schema_role} schema"),
        ));
        return None;
    };
    let value = match c.schema(schema_file) {
        Some(value) => value,
        None => {
            out.push(r25_finding(
                c,
                format!("contract id={contract_id} {schema_file} 必须是可读取的 JSON Schema"),
            ));
            return None;
        }
    };
    Some((schema_file.to_string(), value.value().clone()))
}

#[allow(clippy::too_many_arguments)]
fn r25_validate_schema_annotation(
    c: &RepositoryContract,
    contract_id: &str,
    schema_file: &str,
    schema: &serde_json::Value,
    pointer: &str,
    property: &str,
    annotation: &str,
    expected: &str,
    out: &mut Vec<Finding>,
) {
    let actual = schema
        .pointer(pointer)
        .and_then(|node| node.get(annotation))
        .and_then(serde_json::Value::as_str);
    if actual != Some(expected) {
        out.push(r25_finding(
            c,
            format!(
                "contract id={contract_id} {schema_file} {property} {annotation}={expected} 必填，实为 {actual:?}"
            ),
        ));
    }
}

fn rule_device_certificate_http_surface(
    c: &RepositoryContract,
    consistency: ConsistencyLevel,
    method: HttpMethod,
    path: &str,
    permission: vocab::RoutePermissionId,
) -> Vec<Finding> {
    let m = c.manifest();
    let label = contract_label(c);
    let mut out = Vec::new();
    let expected_id = if consistency == ConsistencyLevel::DeviceLatent {
        R25_POLICY_ID
    } else {
        R25_STATUS_ID
    };
    let mut reject = |detail: String| {
        out.push(finding(
            Rule::DeviceCertificateHttpClosure,
            label.clone(),
            format!("contract id={expected_id} {detail}"),
        ));
    };

    if m.kind != ContractKind::Http {
        reject(format!("must kind=http，实为 kind={}", m.kind.as_dir()));
    }
    if m.domain != "identity" || m.version != "v2" {
        reject(format!(
            "必须 domain=identity + version=v2，实为 domain={} version={}",
            m.domain, m.version
        ));
    }
    if c.owner().domain().map(|owner| owner.as_str()) != Some("identity") {
        reject(format!(
            "must owner=identity，实为 owner={:?}",
            c.owner().as_str()
        ));
    }
    if m.consistency_level != consistency {
        reject(format!(
            "必须 consistencyLevel={consistency:?}，实为 {:?}",
            m.consistency_level
        ));
    }
    if m.method != Some(method) {
        reject(format!(
            "必须 method={}，实为 {:?}",
            method.as_wire(),
            m.method
        ));
    }
    if m.path.as_deref() != Some(path) {
        reject(format!("必须 path={path:?}，实为 {:?}", m.path.as_deref()));
    }
    let Some(http) = m
        .endpoints
        .as_ref()
        .and_then(|endpoints| endpoints.http.as_ref())
    else {
        reject("必须声明 endpoints.http route/auth metadata".to_string());
        return out;
    };
    if http.success_status != 200 {
        reject(format!(
            "endpoints.http 必须 successStatus=200，实为 {}",
            http.success_status
        ));
    }
    if http.idempotency != HttpIdempotency::Idempotent {
        reject(format!(
            "endpoints.http 必须 idempotency=idempotent，实为 {:?}",
            http.idempotency
        ));
    }
    if http.resource.as_deref() != Some("deviceId")
        || http.self_scoped
        || http.resource_sharing.is_some()
    {
        reject(format!(
            "endpoints.http 必须 resource=deviceId + selfScoped=false + resourceSharing 未声明，实为 resource={:?} selfScoped={} resourceSharing={:?}",
            http.resource, http.self_scoped, http.resource_sharing
        ));
    }
    let permission_literal = permission.as_str();
    if !r25_http_auth_matches(http.auth.as_ref(), permission) {
        reject(format!(
            "endpoints.http.auth 必须 mode=permission + permission={permission_literal:?}（可由 vocab::RoutePermissionId parse）+ 无 reason，实为 {auth:?}",
            auth = http.auth.as_ref()
        ));
    }
    out
}

fn r25_http_auth_matches(auth: Option<&HttpAuth>, permission: vocab::RoutePermissionId) -> bool {
    let Some(auth) = auth else {
        return false;
    };
    let Some(actual) = auth.permission.as_deref() else {
        return false;
    };
    auth.mode == HttpAuthMode::Permission
        && actual == permission.as_str()
        && vocab::RoutePermissionId::parse(actual) == Ok(permission)
        && auth.reason.is_none()
}

fn r25_finding(c: &RepositoryContract, detail: String) -> Finding {
    finding(
        Rule::DeviceCertificateHttpClosure,
        contract_label(c),
        detail,
    )
}

fn r25_linked_target_finding(
    source: &RepositoryContract,
    target: &RepositoryContract,
    detail: String,
) -> Finding {
    finding(
        Rule::DeviceCertificateHttpClosure,
        contract_label(target),
        format!(
            "source contract id={} linked target id={} {detail}",
            source.manifest().id,
            target.manifest().id
        ),
    )
}

/// R22：consistencyLevel capability gate。跨契约原因：HTTP L2 producer 的 `emits` 必须在所有
/// lifecycle 引用同 domain 中存在的 `kind=event && consistencyLevel=OutboxFact` contract id；active
/// producer 另加 active target + subscriber readiness 门。
fn rule_consistency_capability(contracts: &[RepositoryContract]) -> Vec<Finding> {
    let by_id: BTreeMap<&str, &RepositoryContract> = contracts
        .iter()
        .map(|contract| (contract.manifest().id.as_str(), contract))
        .collect();
    let mut out = Vec::new();
    for contract in contracts {
        let label = contract_label(contract);
        out.extend(rule_consistency_capability_one(contract, &label, &by_id));
    }
    out
}

fn rule_consistency_capability_one(
    c: &RepositoryContract,
    label: &str,
    by_id: &BTreeMap<&str, &RepositoryContract>,
) -> Vec<Finding> {
    let m = &c.manifest();
    let mut out = Vec::new();
    out.extend(rule_effect_profile(m, label));
    match m.consistency_level {
        ConsistencyLevel::LocalOnly => {
            if m.kind != ContractKind::Http {
                out.push(consistency_capability_finding(
                    m,
                    label,
                    "local-only-http",
                    "LocalOnly 当前只允许 kind=http；LocalOnly 约束业务持久化/outbox/publish，不排除 provider-owned read-path transaction",
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
                        && matches!(
                            local_tx.tx_model,
                            LocalTxModel::TenantScopedUow | LocalTxModel::RepoAtomicCas
                        )
                        && local_tx.retry == LocalTxRetry::BoundedTransient
                        && local_tx.commit_unknown == LocalTxCommitUnknown::NotRetryable => {}
                _ => out.push(consistency_capability_finding(
                    m,
                    label,
                    CAP_LOCAL_TX,
                    "LocalTx 须声明 boundary=\"single-domain\" + txModel ∈ {\"tenant-scoped-uow\", \"repo-atomic-cas\"} + retry=\"bounded-transient\" + commitUnknown=\"not-retryable\"",
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
    c: &RepositoryContract,
    label: &str,
    by_id: &BTreeMap<&str, &RepositoryContract>,
) -> Vec<Finding> {
    let m = &c.manifest();
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
                        if target.manifest().kind == ContractKind::Event
                            && target.manifest().consistency_level == ConsistencyLevel::OutboxFact =>
                    {
                        if target.manifest().domain != m.domain {
                            out.push(finding(
                                Rule::ConsistencyCapability,
                                label,
                                format!(
                                    "contract id={} emitted fact domain={} must equal producer domain={} for capability ref={emitted_id}",
                                    m.id, target.manifest().domain, m.domain
                                ),
                            ));
                        }
                        if m.lifecycle == Lifecycle::Active
                            && (target.manifest().lifecycle != Lifecycle::Active
                                || target.manifest().subscriptions.is_empty())
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
        ContractKind::Projection => out.push(consistency_capability_finding(
            m,
            label,
            CAP_WORKFLOW_MODE_PROJECTION,
            "kind=projection 仅允许 consistencyLevel=WorkflowEventual + workflow.mode=projection",
        )),
    }
    out
}

fn rule_workflow_capability(
    c: &RepositoryContract,
    label: &str,
    by_id: &BTreeMap<&str, &RepositoryContract>,
) -> Vec<Finding> {
    let m = &c.manifest();
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
            if m.kind != ContractKind::Projection {
                out.push(consistency_capability_finding(
                    m,
                    label,
                    CAP_WORKFLOW_MODE_PROJECTION,
                    "projection workflow 须由 kind=projection 承载；禁止借用 HTTP/event/command/saga carrier",
                ));
            }
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
                        if target.manifest().kind == ContractKind::Event
                            && target.manifest().consistency_level == ConsistencyLevel::OutboxFact => {}
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

fn rule_device_latent_capability(c: &RepositoryContract, label: &str) -> Vec<Finding> {
    let m = &c.manifest();
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

/// R21：同 `{kind}/{domain}/{version}` 下扁平 / 嵌套形态不可混用（INVARIANT: CONTRACT-NEST-EXCLUSIVE-01 { level = "Medium", exec = "check", source = "code" }）。
/// 按三段 group；某 group 同时含扁平契约（`slug=None`）与嵌套契约（`slug=Some`）即报（同根因 1 条）。
/// synthetic red：version 目录直放 `contract.toml` 又含 `<slug>/contract.toml` → Finding；
/// anti-vacuity：纯扁平（1×None）/ 纯嵌套（N×Some）group 均通过（见 `r21_*` 测试）。
fn rule_slug_mixing(contracts: &[RepositoryContract]) -> Vec<Finding> {
    let mut by_group: BTreeMap<String, (bool, bool)> = BTreeMap::new();
    for c in contracts {
        let key = format!("{}/{}/{}", c.path_kind(), c.path_domain(), c.path_version());
        let entry = by_group.entry(key).or_insert((false, false));
        match c.slug() {
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

/// R12：contract `id` 须跨全部契约全局唯一（INVARIANT: CONTRACT-IDUNIQ-01 { level = "Medium", exec = "check", source = "code" }）。同根因（同一重复 id）
/// 只报 1 条（subject = 该 id），detail 列全部冲突契约 label（排序，跨机确定性）。
fn rule_duplicate_id(contracts: &[RepositoryContract]) -> Vec<Finding> {
    let mut by_id: BTreeMap<&str, Vec<String>> = BTreeMap::new();
    for c in contracts {
        let label = contract_label(c);
        by_id
            .entry(c.manifest().id.as_str())
            .or_default()
            .push(label);
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
fn contract_label(c: &RepositoryContract) -> String {
    match &c.slug() {
        Some(slug) => format!(
            "{}/{}/{}/{}",
            c.path_kind(),
            c.path_domain(),
            c.path_version(),
            slug
        ),
        None => format!("{}/{}/{}", c.path_kind(), c.path_domain(), c.path_version()),
    }
}

/// Execute per-contract rules in canonical stable-ID plan order.
pub(crate) fn validate_contract(c: &RepositoryContract) -> Vec<Finding> {
    // label 用相对 `{kind}/{domain}/{version}[/{slug}]`（机器稳定、跨机一致；嵌套带 slug 段精确定位），
    // 不用绝对磁盘路径——CI / 多开发机的 finding 输出须可对应 repo 路径，便于定位。
    let label = contract_label(c);
    let mut findings = Vec::new();
    for (_, handler) in super::governance::per_contract_validation_plan() {
        findings.extend(handler(c, &label));
    }
    findings
}

macro_rules! manifest_option_handler {
    ($name:ident, $rule:ident) => {
        pub(crate) fn $name(contract: &RepositoryContract, label: &str) -> Vec<Finding> {
            $rule(contract.manifest(), label).into_iter().collect()
        }
    };
}

macro_rules! manifest_vec_handler {
    ($name:ident, $rule:ident) => {
        pub(crate) fn $name(contract: &RepositoryContract, label: &str) -> Vec<Finding> {
            $rule(contract.manifest(), label)
        }
    };
}

macro_rules! contract_option_handler {
    ($name:ident, $rule:ident) => {
        pub(crate) fn $name(contract: &RepositoryContract, label: &str) -> Vec<Finding> {
            $rule(contract, label).into_iter().collect()
        }
    };
}

macro_rules! contract_vec_handler {
    ($name:ident, $rule:ident) => {
        pub(crate) fn $name(contract: &RepositoryContract, label: &str) -> Vec<Finding> {
            $rule(contract, label)
        }
    };
}

manifest_option_handler!(execute_saga_consistency, rule_saga_consistency);
manifest_option_handler!(execute_command_consistency, rule_command_consistency);
manifest_option_handler!(execute_command_policy, rule_command_policy);
contract_option_handler!(execute_framework_kind, rule_framework_kind);
contract_option_handler!(execute_path_mismatch, rule_path_match);
manifest_vec_handler!(execute_schema_shape, rule_schema_shape);
manifest_vec_handler!(execute_ident_syntax, rule_ident_syntax);
manifest_vec_handler!(execute_per_kind_active_fields, rule_perkind_active_fields);
manifest_vec_handler!(execute_per_kind_field_scope, rule_perkind_field_scope);
manifest_vec_handler!(execute_manifest_wire_metadata, rule_manifest_wire_metadata);
manifest_vec_handler!(execute_http_auth, rule_http_auth);
contract_vec_handler!(execute_http_tenant_source, rule_http_request_tenant_source);
contract_vec_handler!(
    execute_http_projection_coverage,
    rule_http_projection_response_coverage
);
manifest_vec_handler!(execute_saga_block, rule_saga_block);
manifest_option_handler!(
    execute_active_delivery_supported,
    rule_active_delivery_supported
);
contract_vec_handler!(execute_schema_title, rule_schema_title);
pub(crate) fn execute_identity_abac_operator_ssot(
    contracts: &[RepositoryContract],
) -> Vec<Finding> {
    rule_identity_abac_operator_ssot(contracts)
}
contract_vec_handler!(execute_schema_redaction, rule_schema_redaction);
contract_vec_handler!(execute_schema_protection, rule_schema_protection);
manifest_option_handler!(execute_active_subscriber, rule_active_subscriber);
contract_option_handler!(execute_slug_syntax, rule_slug_syntax);

fn rule_manifest_wire_metadata(m: &ContractManifest, label: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    if let Some(http) = m
        .endpoints
        .as_ref()
        .and_then(|endpoints| endpoints.http.as_ref())
    {
        if !(200..=299).contains(&http.success_status) {
            out.push(finding(
                Rule::ManifestWireMetadata,
                label,
                format!(
                    "endpoints.http.successStatus 必须位于 200..=299，实为 {}",
                    http.success_status
                ),
            ));
        }
        if !m.schemas.responses.is_empty()
            && !m
                .schemas
                .responses
                .contains_key(&HttpStatusCode::new(http.success_status))
        {
            out.push(finding(
                Rule::ManifestWireMetadata,
                label,
                format!(
                    "schemas.responses 必须包含 successStatus={} 的 typed schema",
                    http.success_status
                ),
            ));
        }
        if m.schemas.response.is_some() && !m.schemas.responses.is_empty() {
            out.push(finding(
                Rule::ManifestWireMetadata,
                label,
                "HTTP contract 不得同时声明 schemas.response 与 schemas.responses；typed response map 是唯一响应 schema 来源",
            ));
        }
    }

    let mut subscription_identities = BTreeSet::new();
    for subscription in &m.subscriptions {
        let valid_effect_shape = matches!(
            (
                subscription.execution,
                subscription.effect,
                subscription.external_effect_policy
            ),
            (
                SubscriptionExecution::AdapterNative,
                None,
                ExternalEffectPolicy::TransactionalOnly
            ) | (
                SubscriptionExecution::DomainEffect,
                Some(SubscriptionEffect::SettingsConfigVersionRefresh),
                ExternalEffectPolicy::Reconcile
            )
        );
        if !valid_effect_shape {
            out.push(finding(
                Rule::ManifestWireMetadata,
                label,
                format!(
                    "subscription consumer={} group={} 的 execution/effect/externalEffectPolicy 组合非法：adapter-native 仅允许 transactional-only 且禁止 effect；settings-config-version-refresh 必须为 domain-effect + reconcile",
                    subscription.consumer, subscription.group
                ),
            ));
        }
        if !subscription_identities.insert((&subscription.consumer, &subscription.group)) {
            out.push(finding(
                Rule::ManifestWireMetadata,
                label,
                format!(
                    "subscription identity 重复：consumer={} group={}",
                    subscription.consumer, subscription.group
                ),
            ));
        }
    }

    if let Some(outbox) = m.capabilities.outbox.as_ref() {
        let mut emitted_ids = BTreeSet::new();
        for emitted_id in &outbox.emits {
            if !emitted_ids.insert(emitted_id) {
                out.push(finding(
                    Rule::ManifestWireMetadata,
                    label,
                    format!("capabilities.outbox.emits 含重复 contract id={emitted_id}"),
                ));
            }
        }
    }
    out
}

/// R20：嵌套 slug 段语法（INVARIANT: CONTRACT-SLUG-SYNTAX-01 { level = "Medium", exec = "check", source = "code" }）。扁平契约（`slug=None`）豁免。
/// slug 经 kebab→snake 拼进 generated `pub mod <slug_ident>`，须为合法 module ident 前体。
fn rule_slug_syntax(c: &RepositoryContract, label: &str) -> Option<Finding> {
    let slug = c.slug()?;
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
                "kind=command 须 consistencyLevel=OutboxFact，实为 {:?}",
                m.consistency_level
            ),
        ));
    }
    None
}

/// R24：command journal policy 不允许默认；跨 kind block 不允许被静默忽略。
fn rule_command_policy(m: &ContractManifest, label: &str) -> Option<Finding> {
    let valid = matches!(m.kind, ContractKind::Command) == m.command.is_some()
        && m.command.is_none_or(|command| {
            command.reconcile.is_none()
                || command.journal == crate::contract::manifest::CommandJournalPolicy::Required
        });
    (!valid).then(|| {
        finding(
            Rule::CommandPolicy,
            label,
            if m.kind == ContractKind::Command {
                format!(
                    "kind=command 必须显式声明 {FIELD_COMMAND} journal=required|none，且 reconcile command 必须 journal=required"
                )
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
/// 跨域编排，天然绑定某域 owner（R1 + generated / diport::SagaDurableStore / saga conformance）。
fn rule_framework_kind(c: &RepositoryContract, label: &str) -> Option<Finding> {
    let m = c.manifest();
    let framework = c.owner().is_framework_owned();
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
fn rule_path_match(c: &RepositoryContract, label: &str) -> Option<Finding> {
    let want_kind = c.manifest().kind.as_dir();
    let mut diffs = Vec::new();
    if c.path_kind() != want_kind {
        diffs.push(format!("kind 段 {} ≠ 字段 {}", c.path_kind(), want_kind));
    }
    if c.path_domain() != c.manifest().domain {
        diffs.push(format!(
            "domain 段 {} ≠ 字段 {}",
            c.path_domain(),
            c.manifest().domain
        ));
    }
    if c.path_version() != c.manifest().version {
        diffs.push(format!(
            "version 段 {} ≠ 字段 {}",
            c.path_version(),
            c.manifest().version
        ));
    }
    if diffs.is_empty() {
        return None;
    }
    Some(finding(Rule::PathMismatch, label, diffs.join("；")))
}

/// R4：kind→schema 形态一致。返回缺失的必需 schema 声明（可多条）。
#[allow(
    clippy::unreachable,
    reason = "the projection branch returns before the closed non-projection schema mapping"
)]
fn rule_schema_shape(m: &ContractManifest, label: &str) -> Vec<Finding> {
    let s = &m.schemas;
    if m.kind == ContractKind::Projection {
        let mut out = Vec::new();
        if s.projection.is_none() {
            out.push(finding(
                Rule::SchemaShape,
                label,
                format!("kind=Projection 缺必需 schema 声明 [schemas].{SCHEMA_KEY_PROJECTION}"),
            ));
        }
        for (slot, present) in [
            (SCHEMA_KEY_REQUEST, s.request.is_some()),
            (SCHEMA_KEY_RESPONSE, s.response.is_some()),
            (SCHEMA_KEY_PAYLOAD, s.payload.is_some()),
            ("responses", !s.responses.is_empty()),
        ] {
            if present {
                out.push(finding(
                    Rule::SchemaShape,
                    label,
                    format!(
                        "kind=Projection 仅允许 [schemas].{SCHEMA_KEY_PROJECTION}，禁止 [schemas].{slot}"
                    ),
                ));
            }
        }
        return out;
    }
    let http_success_response = s.response.is_some()
        || m.endpoints
            .as_ref()
            .and_then(|endpoints| endpoints.http.as_ref())
            .is_some_and(|http| s.response(http.success_status).is_some());
    let required: &[(&str, bool)] = match m.kind {
        ContractKind::Http => &[
            (SCHEMA_KEY_REQUEST, s.request.is_some()),
            (SCHEMA_KEY_RESPONSE, http_success_response),
        ],
        ContractKind::Event | ContractKind::Saga => &[(SCHEMA_KEY_PAYLOAD, s.payload.is_some())],
        ContractKind::Command => &[(SCHEMA_KEY_REQUEST, s.request.is_some())],
        ContractKind::Projection => unreachable!("projection schema shape returned above"),
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
            format!(
                "version 非法：须无前导零的正整数 v{{N}}（如 v1），实为 {:?}",
                m.version
            ),
        ));
    }
    if !is_contract_id(&m.id) {
        out.push(finding(
            Rule::IdentSyntax,
            label,
            format!(
                "id 非法：须点分小写名（如 seed.echo / config.entry-upserted），实为 {:?}",
                m.id
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
/// **saga 不在此**：`[saga]` block 是 saga 契约的**结构语义**（`generated`、`diport::SagaDurableStore` 与 saga conformance governance），非「仅 active 生效的
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
        // projection 是后台 workflow definition，不声明 serving 字段。
        ContractKind::Projection => &[],
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
    let checks: [(&str, bool, &[ContractKind]); 6] = [
        (FIELD_PATH, m.path.is_some(), &[ContractKind::Http]),
        (FIELD_METHOD, m.method.is_some(), &[ContractKind::Http]),
        (
            FIELD_TOPIC,
            m.topic.is_some(),
            &[ContractKind::Event, ContractKind::Command],
        ),
        (FIELD_DELIVERY, m.delivery.is_some(), &[ContractKind::Event]),
        (FIELD_SAGA, m.saga.is_some(), &[ContractKind::Saga]),
        (
            FIELD_SUBSCRIPTIONS,
            !m.subscriptions.is_empty(),
            &[ContractKind::Event],
        ),
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
    if let Some(resource) = http.resource.as_ref().filter(|s| !s.trim().is_empty())
        && !http
            .resource_sharing
            .as_ref()
            .is_some_and(|sharing| sharing.mode == HttpResourceSharingMode::Global)
    {
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

fn rule_http_request_tenant_source(c: &RepositoryContract, label: &str) -> Vec<Finding> {
    let m = c.manifest();
    if m.kind != ContractKind::Http {
        return Vec::new();
    }
    let Some(request) = m.schemas.request.as_deref() else {
        return Vec::new();
    };
    if pathsafe::is_unsafe_segment(request) {
        return Vec::new();
    }
    let Some(value) = c.schema(request) else {
        return Vec::new();
    };
    if schema_declares_property(value, "tenantId") {
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

fn rule_http_projection_response_coverage(c: &RepositoryContract, label: &str) -> Vec<Finding> {
    let m = c.manifest();
    if m.kind != ContractKind::Http
        || m.lifecycle != Lifecycle::Active
        || m.method != Some(HttpMethod::Get)
    {
        return Vec::new();
    }
    let Some(response) = m
        .endpoints
        .as_ref()
        .and_then(|endpoints| endpoints.http.as_ref())
        .and_then(|http| m.schemas.response(http.success_status))
    else {
        return Vec::new();
    };
    if pathsafe::is_unsafe_segment(response) {
        return Vec::new();
    }
    let Some(schema) = c.schema(response) else {
        return Vec::new();
    };
    let protected = protected_response_paths(schema);
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
        if !response_path_exists(schema, path) {
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

/// R10：saga 契约的 `[saga]` block 结构语义（`generated`、`diport::SagaDurableStore` 与 saga conformance governance，**无条件、不论 lifecycle**）：
/// `kind=saga` ⇒ 须有非空 block；block 存在即查良构——≥1 step、step name 经 canonical
/// [`vocab::StepName`] grammar 校验且唯一，receiptSchema/effect scope 非空；retry budget 不为零且
/// backoff 不倒置。
/// 闭合 policy 枚举与 duration 非负由 `manifest.rs` 类型层守（Hard）；step receiptSchema 文件完整性由 R5/R6 经
/// `declared_schema_files()` 覆盖。非-saga kind 误带 `[saga]` 由 R9 拒（本规则只校验 block 内部）。
fn rule_saga_block(m: &ContractManifest, label: &str) -> Vec<Finding> {
    let Some(saga) = &m.saga else {
        // saga 契约缺 block：generated / diport::SagaDurableStore / saga conformance 要求 kind:saga 必有非空 saga block（无条件、不论 lifecycle）。
        if m.kind == ContractKind::Saga {
            return vec![finding(
                Rule::SagaBlock,
                label,
                "kind=saga 须声明非空 [saga] block（`generated`、`diport::SagaDurableStore` 与 saga conformance governance，无条件、不论 lifecycle）"
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
    if saga.retry.max_attempts == 0 {
        out.push(finding(
            Rule::SagaBlock,
            label,
            "saga.retry.maxAttempts 须大于 0（含首次调用）".to_string(),
        ));
    }
    if saga.retry.time_budget_millis == 0 {
        out.push(finding(
            Rule::SagaBlock,
            label,
            "saga.retry.timeBudgetMillis 须大于 0".to_string(),
        ));
    }
    if saga.retry.initial_backoff_millis > saga.retry.max_backoff_millis {
        out.push(finding(
            Rule::SagaBlock,
            label,
            "saga.retry.initialBackoffMillis 不得大于 maxBackoffMillis".to_string(),
        ));
    }
    let mut seen = BTreeSet::new();
    for step in &saga.steps {
        let name = step.name.as_str();
        if !seen.insert(name) {
            out.push(finding(
                Rule::SagaBlock,
                label,
                format!("saga step name 重复: {name:?}"),
            ));
        }
        if step.receipt_schema.is_empty() {
            out.push(finding(
                Rule::SagaBlock,
                label,
                format!("saga step {name:?} 的 receiptSchema 不可为空"),
            ));
        }
        for (field, value) in [
            ("effectScope", step.effect_scope.as_str()),
            (
                "compensationEffectScope",
                step.compensation_effect_scope.as_str(),
            ),
        ] {
            if value.is_empty() {
                out.push(finding(
                    Rule::SagaBlock,
                    label,
                    format!("saga step {name:?} 的 {field} 不可为空"),
                ));
            }
        }
    }
    out
}

/// R11：`lifecycle=active` 的 event 契约只能声明当前**可兑现**的投递语义。RSS outbox + 幂等消费者
/// 当前仅兑现 `at-least-once`（见 `contracts/**/contract.toml`、`generated` 与 `crates/consistency`）；`at-most-once`/`exactly-once` broker 链路
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
/// receiptSchema）的 `title`
/// 须 PascalCase 且**契约内**唯一（INVARIANT: CONTRACT-TITLE-01 { level = "Medium", exec = "check", source = "code" }）。title 是 typify 生成的 Rust 类型名
/// （顶层 + 嵌套对象都成类型）：非 PascalCase 产生非惯用类型名；契约内重复（一契约的全部 declared schema
/// 喂同一 TypeSpace）产生类型冲突。
///
/// schema 文件口径**严格对齐 codegen** `render_contract_body`：saga 用
/// [`super::manifest::ContractManifest::declared_schema_files`]（payload + step receiptSchema），其它 kind 用
/// `Schemas::declared_files()`。
/// reason: 校验口径锚定「实际生成类型的那批 schema」，勿误把两个 accessor 统一。
///
/// 本规则只接收已由 repository inspection 完整提升的 typed contract；missing、unsafe 或 malformed
/// source 已由 canonical R5/R6 source stage 拒绝，不能到达本 executor。
fn rule_schema_title(c: &RepositoryContract, label: &str) -> Vec<Finding> {
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
    for (title, file, _, _, _) in &titles {
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
    let mut by_title: BTreeMap<&str, Vec<(&str, &serde_json::Value, bool, bool)>> = BTreeMap::new();
    for (title, file, schema, is_root, from_component) in &titles {
        by_title.entry(title.as_str()).or_default().push((
            file.as_str(),
            schema,
            *is_root,
            *from_component,
        ));
    }
    for (title, occurrences) in by_title {
        if occurrences.len() > 1 {
            let shared_component_definition = occurrences
                .iter()
                .all(|(_, _, is_root, from_component)| !is_root && *from_component)
                && occurrences.windows(2).all(|pair| pair[0].1 == pair[1].1);
            if shared_component_definition {
                continue;
            }
            let mut files = occurrences
                .iter()
                .map(|(file, _, _, _)| *file)
                .collect::<Vec<_>>();
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

/// INVARIANT: IDENTITY-ABAC-OPERATOR-SSOT-01 { level = "Medium", exec = "check", source = "code",
/// synthetic_red = "inline operator schema is rejected", anti_vacuity = "every active identity
/// active identity schema containing an operator property must use the direct canonical ref" }
fn rule_identity_abac_operator_ssot(contracts: &[RepositoryContract]) -> Vec<Finding> {
    let mut out = Vec::new();
    let mut active_consumers = 0usize;
    let mut canonical_refs = 0usize;
    for contract in contracts.iter().filter(|contract| {
        contract.manifest().lifecycle == Lifecycle::Active && contract.path_domain() == "identity"
    }) {
        let label = contract_label(contract);
        for file in contract.manifest().declared_schema_files() {
            if pathsafe::is_unsafe_segment(file) {
                continue;
            }
            let Some(schema) = contract.declared_schema(file) else {
                continue;
            };
            let references = schema.property_references("operator");
            if references.is_empty() {
                continue;
            }
            active_consumers += 1;
            for reference in references {
                if reference.as_deref() == Some(IDENTITY_ABAC_OPERATOR_COMPONENT) {
                    canonical_refs += 1;
                } else {
                    out.push(finding(
                        Rule::IdentityAbacOperatorSsot,
                        label.clone(),
                        format!(
                            "{file} 的 operator property 必须直接 $ref={IDENTITY_ABAC_OPERATOR_COMPONENT:?}，实为 {reference:?}"
                        ),
                    ));
                }
            }
        }
    }
    if active_consumers == 0 || canonical_refs == 0 {
        out.push(finding(
            Rule::IdentityAbacOperatorSsot,
            "contracts/identity".to_owned(),
            format!(
                "SSOT carrier anti-vacuity 失败：active identity operator consumer={active_consumers}，canonical ref={canonical_refs}"
            ),
        ));
    }
    out
}

/// 读契约的全部 declared schema（口径 = codegen `render_contract_body` 的 schema 文件集），
/// 返回（`(title, 来源文件名)` 全集, root title 缺失的文件名集）。能解析但 root 无 string title
/// 的文件计入第二项（供 ⓪ root 必填门）。
type ContractTitle = (String, String, serde_json::Value, bool, bool);
type ContractTitles = (Vec<ContractTitle>, Vec<String>);

fn collect_contract_titles(c: &RepositoryContract) -> ContractTitles {
    let mut titles = Vec::new();
    let mut missing_root = Vec::new();
    let schema_files = c.manifest().declared_schema_files();
    for file in schema_files {
        if pathsafe::is_unsafe_segment(file) {
            // 防御性 fail-safe：含路径分量的文件名由 R6 报；R13 不主动 `join` 读它（不依赖
            // 文件系统拒绝来保护自身），与 R6 意图一致。
            continue;
        }
        let Some(value) = c.schema(file) else {
            continue;
        };
        if !has_root_title(value) {
            missing_root.push(file.to_string());
        }
        let mut found = Vec::new();
        collect_schema_titles(
            value,
            &mut found,
            true,
            false,
            Some(value.component_definition_names()),
        );
        for (title, schema, is_root, from_component) in found {
            titles.push((title, file.to_string(), schema, is_root, from_component));
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
fn collect_schema_titles(
    schema: &serde_json::Value,
    out: &mut Vec<(String, serde_json::Value, bool, bool)>,
    is_root: bool,
    from_component: bool,
    root_component_definitions: Option<&BTreeSet<String>>,
) {
    let serde_json::Value::Object(map) = schema else {
        return;
    };
    if let Some(serde_json::Value::String(title)) = map.get("title") {
        out.push((title.clone(), schema.clone(), is_root, from_component));
    }
    // 子 schema = 这些关键字下 object 的各 value（properties / patternProperties / $defs 成员）。
    for key in ["properties", "patternProperties", "$defs"] {
        recurse_map_values(map.get(key), out, from_component);
    }
    if let Some(serde_json::Value::Object(definitions)) = map.get("definitions") {
        for (name, child) in definitions {
            let child_from_component = from_component
                || (is_root
                    && root_component_definitions.is_some_and(|names| names.contains(name)));
            collect_schema_titles(child, out, false, child_from_component, None);
        }
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
            recurse_subschemas(v, out, from_component);
        }
    }
}

/// R16：字段级 redaction 扩展校验。按 manifest 声明的完整 schema slot 扫描，
/// 包含 request/response/payload 与 Saga generated receipt schema。
fn rule_schema_redaction(c: &RepositoryContract, label: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    for file in c.manifest().declared_schema_files() {
        if pathsafe::is_unsafe_segment(file) {
            continue;
        }
        let Some(value) = c.schema(file) else {
            continue;
        };
        for violation in redaction::validate_schema(value) {
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
fn rule_schema_protection(c: &RepositoryContract, label: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    for file in c.manifest().declared_schema_files() {
        if pathsafe::is_unsafe_segment(file) {
            continue;
        }
        let Some(value) = c.schema(file) else {
            continue;
        };
        for violation in protection::validate_schema(value) {
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
fn recurse_map_values(
    value: Option<&serde_json::Value>,
    out: &mut Vec<(String, serde_json::Value, bool, bool)>,
    from_component: bool,
) {
    if let Some(serde_json::Value::Object(children)) = value {
        for child in children.values() {
            collect_schema_titles(child, out, false, from_component, None);
        }
    }
}

/// 下钻一个 schema 承载值：array ⇒ 逐项递归（allOf/anyOf/oneOf/tuple items），否则单 schema 递归
/// （非 object 在 [`collect_schema_titles`] 入口 no-op，如 `additionalProperties: false`）。
fn recurse_subschemas(
    v: &serde_json::Value,
    out: &mut Vec<(String, serde_json::Value, bool, bool)>,
    from_component: bool,
) {
    match v {
        serde_json::Value::Array(items) => {
            for item in items {
                collect_schema_titles(item, out, false, from_component, None);
            }
        }
        other => collect_schema_titles(other, out, false, from_component, None),
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

/// Canonical 版本段：`v{N}`，N 为无前导零的正整数。
fn is_version(s: &str) -> bool {
    matches!(
        s.strip_prefix('v'),
        Some(n)
            if matches!(n.bytes().next(), Some(b) if b.is_ascii_digit() && b != b'0')
                && n.bytes().all(|b| b.is_ascii_digit())
    )
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

fn is_contract_id(s: &str) -> bool {
    rss_contract::ContractId::parse(s).is_ok()
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
        Capabilities, CompensationOrder, Delivery, DeviceCertificateLinks, DeviceLatentCapability,
        DeviceLatentFencing, DeviceLatentLateMessagePolicy, DeviceLatentLoop, DeviceLatentProfile,
        DeviceLatentTenancy, DeviceLatentTrigger, EffectKind, EffectProfile, Endpoints,
        ExternalEffectPolicy, HttpAuth, HttpAuthMode, HttpEndpoint, HttpHeaderMode,
        HttpIdempotency, HttpMethod, HttpProjection, HttpProjectionField, HttpProjectionFieldName,
        HttpResourceSharing, HttpResourceSharingMode, Lifecycle, LocalTxCapability,
        OutboxCapability, PartitionKeyStrategy, ReconcileBlock, SagaBackoff, SagaBlock,
        SagaCompensationInput, SagaIdempotencyClass, SagaJitter, SagaRetryClass, SagaRetryPolicy,
        SagaStep, Schemas, SubscriberReadiness, Subscription, SubscriptionEffect,
        SubscriptionExecution, SubscriptionTopology, WorkflowCapability,
    };
    use crate::testutil::unique_tmp;
    use anyhow::Context as _;
    use assembly_schema::repository_contract::RepositoryContractTestBuilder;
    use rstest::rstest;
    use std::path::PathBuf;

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum RawContractOwner {
        Domain(String),
        Framework,
    }

    #[allow(
        clippy::expect_used,
        reason = "fixed-valid base manifest keeps the test fixture API infallible"
    )]
    fn manifest(
        kind: ContractKind,
        level: ConsistencyLevel,
        owner: RawContractOwner,
        schemas: Schemas,
    ) -> ContractManifest {
        let mut manifest = ContractManifest::from_toml_str(
            r#"
id = "seed.x"
kind = "http"
domain = "_seed"
version = "v1"
owner = "_framework"
consistencyLevel = "LocalOnly"
lifecycle = "draft"
[schemas]
"#,
        )
        .expect("static synthetic manifest must parse");
        manifest.kind = kind;
        manifest.consistency_level = level;
        manifest.schemas = schemas;
        match owner {
            RawContractOwner::Domain(domain) => manifest.test_set_domain_owner(domain),
            RawContractOwner::Framework => manifest.test_set_framework_owner(),
        }
        manifest
    }

    fn public_http_endpoints() -> Endpoints {
        Endpoints {
            http: Some(HttpEndpoint {
                success_status: 200,
                idempotency: HttpIdempotency::Idempotent,
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
            execution: SubscriptionExecution::AdapterNative,
            effect: None,
            external_effect_policy: ExternalEffectPolicy::TransactionalOnly,
            topology: SubscriptionTopology {
                partition_key: PartitionKeyStrategy::None,
                readiness: SubscriberReadiness::Required,
            },
        }
    }

    #[test]
    fn wire_metadata_rejects_invalid_http_status_and_subscription_execution_shape() {
        let mut http = manifest(
            ContractKind::Http,
            ConsistencyLevel::LocalOnly,
            RawContractOwner::Framework,
            http_schemas(),
        );
        for invalid_status in [0, 199, 300, u16::MAX] {
            http.endpoints = Some(Endpoints {
                http: Some(HttpEndpoint {
                    success_status: invalid_status,
                    idempotency: HttpIdempotency::Idempotent,
                    auth: None,
                    resource: None,
                    self_scoped: false,
                    resource_sharing: None,
                    headers: BTreeMap::new(),
                    projection: None,
                }),
            });
            assert_eq!(rule_manifest_wire_metadata(&http, "http").len(), 1);
        }

        let mut event = manifest(
            ContractKind::Event,
            ConsistencyLevel::OutboxFact,
            RawContractOwner::Framework,
            payload_schemas(),
        );
        event.subscriptions = vec![Subscription {
            execution: SubscriptionExecution::DomainEffect,
            effect: None,
            ..one_subscription()
        }];
        assert_eq!(rule_manifest_wire_metadata(&event, "event").len(), 1);

        event.subscriptions[0].execution = SubscriptionExecution::AdapterNative;
        event.subscriptions[0].effect = Some(SubscriptionEffect::SettingsConfigVersionRefresh);
        assert_eq!(rule_manifest_wire_metadata(&event, "event").len(), 1);
    }

    #[test]
    fn wire_metadata_rejects_legacy_and_typed_http_response_sources_together() {
        let mut http = manifest(
            ContractKind::Http,
            ConsistencyLevel::LocalOnly,
            RawContractOwner::Framework,
            http_schemas(),
        );
        http.endpoints = Some(public_http_endpoints());
        http.schemas
            .responses
            .insert(HttpStatusCode::new(200), "response.schema.json".to_string());

        let findings = rule_manifest_wire_metadata(&http, "http");

        assert_eq!(findings.len(), 1);
        assert!(
            findings[0]
                .detail
                .contains("不得同时声明 schemas.response 与 schemas.responses")
        );
    }

    #[test]
    fn wire_metadata_rejects_duplicate_subscription_identity_and_emits() {
        let mut event = manifest(
            ContractKind::Event,
            ConsistencyLevel::OutboxFact,
            RawContractOwner::Framework,
            payload_schemas(),
        );
        event.subscriptions = vec![one_subscription(), one_subscription()];
        assert_eq!(rule_manifest_wire_metadata(&event, "event").len(), 1);

        event.subscriptions.clear();
        event.capabilities.outbox = Some(OutboxCapability {
            role: OutboxRole::Producer,
            atomicity: Some(OutboxAtomicity::SameTransaction),
            emits: vec![
                "identity.session-created".into(),
                "identity.session-created".into(),
            ],
        });
        assert_eq!(rule_manifest_wire_metadata(&event, "event").len(), 1);
    }

    #[test]
    fn wire_metadata_accepts_valid_closed_shapes() {
        let mut event = manifest(
            ContractKind::Event,
            ConsistencyLevel::OutboxFact,
            RawContractOwner::Framework,
            payload_schemas(),
        );
        event.subscriptions = vec![Subscription {
            execution: SubscriptionExecution::DomainEffect,
            effect: Some(SubscriptionEffect::SettingsConfigVersionRefresh),
            external_effect_policy: ExternalEffectPolicy::Reconcile,
            ..one_subscription()
        }];
        assert!(rule_manifest_wire_metadata(&event, "event").is_empty());
    }

    #[test]
    fn wire_metadata_rejects_external_effect_policy_mismatch() {
        let mut event = manifest(
            ContractKind::Event,
            ConsistencyLevel::OutboxFact,
            RawContractOwner::Framework,
            payload_schemas(),
        );
        event.subscriptions = vec![one_subscription()];

        for invalid in [
            ExternalEffectPolicy::IdempotencyKey,
            ExternalEffectPolicy::Reconcile,
            ExternalEffectPolicy::Compensated,
        ] {
            event.subscriptions[0].external_effect_policy = invalid;
            assert_eq!(
                rule_manifest_wire_metadata(&event, "event").len(),
                1,
                "adapter-native audit subscription accepted invalid policy {invalid:?}"
            );
        }

        event.subscriptions[0] = Subscription {
            execution: SubscriptionExecution::DomainEffect,
            effect: Some(SubscriptionEffect::SettingsConfigVersionRefresh),
            external_effect_policy: ExternalEffectPolicy::Reconcile,
            ..one_subscription()
        };
        assert!(
            rule_manifest_wire_metadata(&event, "event").is_empty(),
            "settings refresh should accept reconcile"
        );
        for invalid in [
            ExternalEffectPolicy::TransactionalOnly,
            ExternalEffectPolicy::IdempotencyKey,
            ExternalEffectPolicy::Compensated,
        ] {
            event.subscriptions[0].external_effect_policy = invalid;
            assert_eq!(
                rule_manifest_wire_metadata(&event, "event").len(),
                1,
                "settings refresh accepted invalid policy {invalid:?}"
            );
        }
    }

    fn http_schemas() -> Schemas {
        Schemas {
            request: Some("request.schema.json".to_string()),
            response: Some("response.schema.json".to_string()),
            payload: None,
            projection: None,
            responses: BTreeMap::new(),
        }
    }

    fn payload_schemas() -> Schemas {
        Schemas {
            payload: Some("payload.schema.json".to_string()),
            ..Schemas::default()
        }
    }

    fn projection_schemas() -> Schemas {
        Schemas {
            projection: Some("projection.schema.json".to_string()),
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

    fn repo_atomic_cas_local_tx_capability() -> Capabilities {
        Capabilities {
            local_tx: Some(LocalTxCapability {
                boundary: LocalTxBoundary::SingleDomain,
                tx_model: LocalTxModel::RepoAtomicCas,
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
                profile: DeviceLatentProfile::DeviceCertificate {
                    links: DeviceCertificateLinks {
                        command: "identity.apply-device-certificate".to_string(),
                        ack_event: "identity.device-command-acked".to_string(),
                        reported_event: "identity.device-certificate-reported".to_string(),
                        ingress_receipt_event: "identity.device-ingress-receipted".to_string(),
                    },
                },
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

    /// 合法 saga block（1 step、reverse、完整执行语义）——R10 绿基线，红用例在其上变异。
    #[allow(
        clippy::expect_used,
        reason = "fixed canonical step keeps saga fixture construction infallible"
    )]
    fn valid_saga_block() -> SagaBlock {
        let step_name =
            vocab::StepName::parse("reserve_funds").expect("canonical test step must parse");
        SagaBlock {
            steps: vec![SagaStep {
                name: step_name,
                receipt_schema: "reserve.schema.json".to_string(),
                effect_scope: "billing.reserve".to_string(),
                compensation_effect_scope: "billing.release".to_string(),
                idempotency_class: SagaIdempotencyClass::DeterministicKey,
                compensation_input: SagaCompensationInput::Receipt,
                retry_class: SagaRetryClass::Transient,
            }],
            compensation_order: CompensationOrder::Reverse,
            retry: SagaRetryPolicy {
                max_attempts: 3,
                time_budget_millis: 5000,
                backoff: SagaBackoff::Fixed,
                initial_backoff_millis: 1000,
                max_backoff_millis: 1000,
                jitter: SagaJitter::None,
            },
        }
    }

    /// saga 契约骨架（kind=saga / L3 / domain owner / payload schema），按需挂 saga block。
    fn saga_manifest(block: Option<SagaBlock>) -> ContractManifest {
        let mut m = manifest(
            ContractKind::Saga,
            ConsistencyLevel::WorkflowEventual,
            RawContractOwner::Domain("billing".to_string()),
            payload_schemas(),
        );
        m.domain = "billing".to_string();
        m.id = "billing.checkout".to_string();
        m.saga = block;
        m
    }

    fn projection_manifest(
        id: &str,
        domain: &str,
        lifecycle: Lifecycle,
        input: &str,
    ) -> ContractManifest {
        let mut manifest = manifest(
            ContractKind::Projection,
            ConsistencyLevel::WorkflowEventual,
            RawContractOwner::Domain(domain.to_string()),
            projection_schemas(),
        );
        manifest.id = id.to_string();
        manifest.domain = domain.to_string();
        manifest.lifecycle = lifecycle;
        manifest.capabilities = workflow_projection_capability_with_inputs(&[input]);
        manifest
    }

    fn projection_input_event(id: &str) -> ContractManifest {
        let domain = id.split_once('.').map_or("identity", |(domain, _)| domain);
        let mut event = manifest(
            ContractKind::Event,
            ConsistencyLevel::OutboxFact,
            RawContractOwner::Domain(domain.to_string()),
            payload_schemas(),
        );
        event.id = id.to_string();
        event.domain = domain.to_string();
        event.capabilities = outbox_fact_capability();
        event
    }

    #[allow(
        clippy::expect_used,
        reason = "fixture builder synthesizes every declared schema before promotion"
    )]
    fn discovered(m: ContractManifest, dir: PathBuf) -> RepositoryContract {
        fixture_builder(m, dir)
            .build()
            .expect("synthetic repository contract must build")
    }

    fn fixture_builder(manifest: ContractManifest, dir: PathBuf) -> RepositoryContractTestBuilder {
        let missing = manifest
            .declared_schema_files()
            .into_iter()
            .filter(|file| !crate::pathsafe::is_unsafe_segment(file) && !dir.join(file).is_file())
            .map(str::to_owned)
            .collect::<Vec<_>>();
        let mut builder = RepositoryContractTestBuilder::new(manifest, dir);
        for (index, file) in missing.into_iter().enumerate() {
            builder = builder.schema(
                file,
                serde_json::json!({
                    "title": format!("SyntheticSchema{index}"),
                    "type": "object"
                }),
            );
        }
        builder
    }

    #[allow(
        clippy::expect_used,
        reason = "rebuild preserves the already validated synthetic fixture shape"
    )]
    fn rebuild_contract(
        contract: &RepositoryContract,
        manifest: ContractManifest,
        path_kind: &str,
        path_domain: &str,
        path_version: &str,
        slug: Option<&str>,
    ) -> RepositoryContract {
        let needs_authorization_receipt = contract.declared_schemas().any(|schema| {
            schema
                .resolved()
                .component_ids()
                .iter()
                .any(|id| id == "rss://component/identity/v1/authorization-receipt-id")
        });
        let mut builder = fixture_builder(manifest, contract.dir().to_path_buf())
            .path_kind(path_kind)
            .path_domain(path_domain)
            .path_version(path_version)
            .slug(slug);
        if needs_authorization_receipt {
            builder = builder.component(
                "rss://component/identity/v1/authorization-receipt-id",
                serde_json::from_str(include_str!(
                    "../../../contracts/components/identity/v1/authorization-receipt-id.schema.json"
                ))
                .expect("committed authorization receipt component must parse"),
            );
        }
        builder
            .build()
            .expect("rebuilt synthetic repository contract must build")
    }

    fn mutate_contract<T>(
        contract: &mut RepositoryContract,
        mutate: impl FnOnce(&mut ContractManifest) -> T,
    ) -> T {
        let mut manifest = contract.manifest().clone();
        let output = mutate(&mut manifest);
        *contract = rebuild_contract(
            contract,
            manifest,
            contract.path_kind(),
            contract.path_domain(),
            contract.path_version(),
            contract.slug(),
        );
        output
    }

    fn set_contract_path(
        contract: &mut RepositoryContract,
        path_kind: &str,
        path_domain: &str,
        path_version: &str,
        slug: Option<&str>,
    ) {
        *contract = rebuild_contract(
            contract,
            contract.manifest().clone(),
            path_kind,
            path_domain,
            path_version,
            slug,
        );
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
            RawContractOwner::Framework,
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
            RawContractOwner::Framework,
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
            RawContractOwner::Framework,
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
            RawContractOwner::Domain("identity".to_string()),
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
            RawContractOwner::Domain("identity".to_string()),
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
            RawContractOwner::Framework,
            Schemas {
                request: Some("request.schema.json".to_string()),
                ..Schemas::default()
            },
        );
        m.id = "seed.do-thing".to_string();
        m.command = Some(crate::contract::manifest::CommandBlock {
            journal: crate::contract::manifest::CommandJournalPolicy::Required,
            reconcile: None,
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
            RawContractOwner::Framework,
            payload_schemas(),
        );
        event.command = Some(crate::contract::manifest::CommandBlock {
            journal: crate::contract::manifest::CommandJournalPolicy::None,
            reconcile: None,
        });
        assert_eq!(
            rule_command_policy(&event, "event/_seed/v1").map(|f| f.rule),
            Some(Rule::CommandPolicy)
        );

        let mut fenced = command_manifest(ConsistencyLevel::OutboxFact);
        fenced.command = Some(crate::contract::manifest::CommandBlock {
            journal: crate::contract::manifest::CommandJournalPolicy::None,
            reconcile: Some(crate::contract::manifest::CommandReconcileBlock {
                fencing:
                    crate::contract::manifest::CommandReconcileFencing::DeviceGenerationEpochV1,
            }),
        });
        assert_eq!(
            rule_command_policy(&fenced, "command/_seed/v1").map(|f| f.rule),
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
            RawContractOwner::Framework,
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
            RawContractOwner::Framework,
            Schemas {
                request: Some("request.schema.json".to_string()),
                ..Schemas::default()
            },
        );
        let c = discovered(m, PathBuf::from("/x"));
        assert!(
            rule_framework_kind(&c, "x").is_none(),
            "framework-owned command 应允许（#1124）"
        );
    }

    /// R2 新增：kind=Saga + owner=Framework → 应触发 FrameworkKind。
    #[test]
    fn r2_framework_saga_rejected() {
        let m = manifest(
            ContractKind::Saga,
            ConsistencyLevel::WorkflowEventual,
            RawContractOwner::Framework,
            Schemas {
                payload: Some("payload.schema.json".to_string()),
                ..Schemas::default()
            },
        );
        let c = discovered(m, PathBuf::from("/x"));
        assert_eq!(
            rule_framework_kind(&c, "x").map(|f| f.rule),
            Some(Rule::FrameworkKind)
        );
    }

    #[test]
    fn r2_framework_http_ok_and_domain_command_ok() {
        let http = manifest(
            ContractKind::Http,
            ConsistencyLevel::LocalOnly,
            RawContractOwner::Framework,
            http_schemas(),
        );
        let http = discovered(http, PathBuf::from("/x"));
        assert!(rule_framework_kind(&http, "x").is_none());
        let cmd = manifest(
            ContractKind::Command,
            ConsistencyLevel::LocalTx,
            RawContractOwner::Domain("identity".to_string()),
            Schemas {
                request: Some("request.schema.json".to_string()),
                ..Schemas::default()
            },
        );
        let cmd = discovered(cmd, PathBuf::from("/x"));
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
        let mut m = manifest(
            ContractKind::Http,
            ConsistencyLevel::LocalOnly,
            RawContractOwner::Framework,
            http_schemas(),
        );
        m.domain = manifest_domain.to_string();
        m.version = manifest_version.to_string();
        let mut c = discovered(m, PathBuf::from("/x"));
        set_contract_path(&mut c, path_kind, path_domain, path_version, None);
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
            RawContractOwner::Domain("identity".to_string()),
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
            RawContractOwner::Domain("identity".to_string()),
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
            RawContractOwner::Framework,
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
            RawContractOwner::Framework,
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
    fn r4_projection_accepts_only_projection_schema_slot() {
        let exact = projection_manifest(
            "settings.config-projection",
            "settings",
            Lifecycle::Active,
            "settings.config-version-changed",
        );
        assert!(rule_schema_shape(&exact, "projection/settings/v3").is_empty());

        let mut missing = exact.clone();
        missing.schemas.projection = None;
        assert!(
            rule_schema_shape(&missing, "projection/settings/v3")
                .iter()
                .any(|finding| finding.rule == Rule::SchemaShape),
            "kind=projection without schemas.projection must fail closed"
        );

        type SchemaMutation = fn(&mut Schemas);
        let forbidden_slots: [(&str, SchemaMutation); 4] = [
            ("request", |schemas: &mut Schemas| {
                schemas.request = Some("request.schema.json".to_string());
            }),
            ("response", |schemas: &mut Schemas| {
                schemas.response = Some("response.schema.json".to_string());
            }),
            ("payload", |schemas: &mut Schemas| {
                schemas.payload = Some("payload.schema.json".to_string());
            }),
            ("responses", |schemas: &mut Schemas| {
                schemas
                    .responses
                    .insert(HttpStatusCode::new(200), "response.schema.json".to_string());
            }),
        ];
        for (slot, mutate) in forbidden_slots {
            let mut stray = exact.clone();
            mutate(&mut stray.schemas);
            let findings = rule_schema_shape(&stray, "projection/settings/v3");
            assert!(
                findings
                    .iter()
                    .any(|finding| finding.rule == Rule::SchemaShape),
                "kind=projection accepted forbidden schemas.{slot}: {findings:?}"
            );
        }
    }

    /// R7 参数化红用例：domain/version/id 各非法形态须触发 IdentSyntax。
    /// case：(domain, version, id)
    #[rstest]
    #[case("../evil", "v1", "seed.echo")] // domain 含路径分量
    #[case("Bad", "v1", "seed.echo")] // domain 大写
    #[case("9x", "v1", "seed.echo")] // domain 数字开头
    #[case("_seed", "1", "seed.echo")] // version 非 v{N}
    #[case("_seed", "v", "seed.echo")] // version 缺数字
    #[case("_seed", "v0", "seed.echo")] // version 必须为正整数
    #[case("_seed", "v00", "seed.echo")] // version 禁止零与前导零
    #[case("_seed", "v01", "seed.echo")] // version 禁止前导零
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
            RawContractOwner::Framework,
            http_schemas(),
        );
        m.domain = domain.to_string();
        m.version = version.to_string();
        m.id = id.to_string();
        let findings = rule_ident_syntax(&m, "x");
        assert!(!findings.is_empty(), "应触发 IdentSyntax");
        assert!(findings.iter().all(|f| f.rule == Rule::IdentSyntax));
    }

    /// Owner promotion rejects malformed domains before validation executors receive the IR.
    #[rstest]
    #[case("")]
    #[case("_seed")]
    #[case("Bad")]
    fn owner_provenance_rejects_malformed_domain(#[case] owner: &str) -> anyhow::Result<()> {
        let m = manifest(
            ContractKind::Http,
            ConsistencyLevel::LocalOnly,
            RawContractOwner::Domain(owner.to_string()),
            http_schemas(),
        );
        let Err(error) = RepositoryContractTestBuilder::new(m, PathBuf::from("/x")).build() else {
            anyhow::bail!("malformed owner must fail before governance projection")
        };
        assert!(
            error.to_string().contains("canonical domain name"),
            "{error}"
        );
        Ok(())
    }

    /// R7 anti-vacuity（正向）：合法 framework / domain 契约不产生 IdentSyntax finding。
    #[test]
    fn r7_valid_fields_ok() {
        let fw = manifest(
            ContractKind::Http,
            ConsistencyLevel::LocalOnly,
            RawContractOwner::Framework,
            http_schemas(),
        );
        assert!(rule_ident_syntax(&fw, "x").is_empty());
        let dom = manifest(
            ContractKind::Command,
            ConsistencyLevel::LocalTx,
            RawContractOwner::Domain("identity".to_string()),
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
            RawContractOwner::Framework,
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
            RawContractOwner::Framework,
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
            RawContractOwner::Framework,
            http_schemas(),
        );
        http.path = Some("/api/v1/_seed/echo".to_string());
        assert!(rule_ident_syntax(&http, "x").is_empty());
        let mut event = manifest(
            ContractKind::Event,
            ConsistencyLevel::OutboxFact,
            RawContractOwner::Framework,
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
            RawContractOwner::Domain("identity".to_string()),
            payload_schemas(),
        );
        m.subscriptions = vec![Subscription {
            consumer: consumer.to_string(),
            group: group.to_string(),
            execution: SubscriptionExecution::AdapterNative,
            effect: None,
            external_effect_policy: ExternalEffectPolicy::TransactionalOnly,
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
            RawContractOwner::Domain("identity".to_string()),
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
            RawContractOwner::Framework,
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
            RawContractOwner::Framework,
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
            RawContractOwner::Framework,
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
            RawContractOwner::Framework,
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
            RawContractOwner::Domain("identity".to_string()),
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
            RawContractOwner::Framework,
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
            RawContractOwner::Framework,
            http_schemas(),
        );
        m.lifecycle = Lifecycle::Active;
        m.path = Some("/api/v1/_seed/echo".to_string());
        m.method = Some(HttpMethod::Post);
        m.endpoints = Some(Endpoints {
            http: Some(HttpEndpoint {
                success_status: 200,
                idempotency: HttpIdempotency::Idempotent,
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
            RawContractOwner::Framework,
            http_schemas(),
        );
        m.lifecycle = Lifecycle::Active;
        m.path = Some("/api/v1/_seed/echo".to_string());
        m.method = Some(HttpMethod::Post);
        m.endpoints = Some(Endpoints {
            http: Some(HttpEndpoint {
                success_status: 200,
                idempotency: HttpIdempotency::Idempotent,
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
            RawContractOwner::Framework,
            http_schemas(),
        );
        m.lifecycle = Lifecycle::Active;
        m.path = Some("/api/v1/_seed/profile".to_string());
        m.method = Some(HttpMethod::Get);
        m.endpoints = Some(Endpoints {
            http: Some(HttpEndpoint {
                success_status: 200,
                idempotency: HttpIdempotency::Idempotent,
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
            RawContractOwner::Framework,
            http_schemas(),
        );
        m.lifecycle = Lifecycle::Active;
        m.path = Some("/api/v1/_seed/profile".to_string());
        m.method = Some(HttpMethod::Get);
        m.endpoints = Some(Endpoints {
            http: Some(HttpEndpoint {
                success_status: 200,
                idempotency: HttpIdempotency::Idempotent,
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
            RawContractOwner::Framework,
            http_schemas(),
        );
        m.lifecycle = Lifecycle::Active;
        m.path = Some("/api/v1/_seed/profile".to_string());
        m.method = Some(HttpMethod::Get);
        m.endpoints = Some(Endpoints {
            http: Some(HttpEndpoint {
                success_status: 200,
                idempotency: HttpIdempotency::Idempotent,
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
            RawContractOwner::Framework,
            http_schemas(),
        );
        m.lifecycle = Lifecycle::Active;
        m.path = Some("/api/v1/audit/entries".to_string());
        m.method = Some(HttpMethod::Get);
        m.endpoints = Some(Endpoints {
            http: Some(HttpEndpoint {
                success_status: 200,
                idempotency: HttpIdempotency::Idempotent,
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
            RawContractOwner::Framework,
            http_schemas(),
        );
        m.lifecycle = Lifecycle::Active;
        m.path = Some("/api/v1/audit/entries".to_string());
        m.method = Some(HttpMethod::Get);
        m.endpoints = Some(Endpoints {
            http: Some(HttpEndpoint {
                success_status: 200,
                idempotency: HttpIdempotency::Idempotent,
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
            RawContractOwner::Framework,
            http_schemas(),
        );
        m.lifecycle = Lifecycle::Active;
        m.path = Some("/api/v1/audit/entries".to_string());
        m.method = Some(HttpMethod::Get);
        m.endpoints = Some(Endpoints {
            http: Some(HttpEndpoint {
                success_status: 200,
                idempotency: HttpIdempotency::Idempotent,
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
            RawContractOwner::Framework,
            http_schemas(),
        );
        m.lifecycle = Lifecycle::Active;
        m.path = Some("/api/v1/audit/entries".to_string());
        m.method = Some(HttpMethod::Get);
        m.endpoints = Some(Endpoints {
            http: Some(HttpEndpoint {
                success_status: 200,
                idempotency: HttpIdempotency::Idempotent,
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
            RawContractOwner::Framework,
            http_schemas(),
        );
        m.lifecycle = Lifecycle::Active;
        m.path = Some("/api/v1/_seed/roles/{roleId}".to_string());
        m.method = Some(HttpMethod::Delete);
        m.endpoints = Some(Endpoints {
            http: Some(HttpEndpoint {
                success_status: 200,
                idempotency: HttpIdempotency::Idempotent,
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
            RawContractOwner::Framework,
            http_schemas(),
        );
        m.lifecycle = Lifecycle::Active;
        m.path = Some("/api/v1/_seed/roles/{roleId}".to_string());
        m.method = Some(HttpMethod::Delete);
        m.endpoints = Some(Endpoints {
            http: Some(HttpEndpoint {
                success_status: 200,
                idempotency: HttpIdempotency::Idempotent,
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
            RawContractOwner::Framework,
            http_schemas(),
        );
        m.lifecycle = Lifecycle::Active;
        m.path = Some("/api/v1/_seed/echo".to_string());
        m.method = Some(HttpMethod::Post);
        m.endpoints = Some(Endpoints {
            http: Some(HttpEndpoint {
                success_status: 200,
                idempotency: HttpIdempotency::Idempotent,
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
            RawContractOwner::Framework,
            http_schemas(),
        );
        m.lifecycle = Lifecycle::Active;
        m.path = Some("/api/v1/_seed/echo/{id}".to_string());
        m.method = Some(HttpMethod::Post);
        m.endpoints = Some(Endpoints {
            http: Some(HttpEndpoint {
                success_status: 200,
                idempotency: HttpIdempotency::Idempotent,
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
            RawContractOwner::Framework,
            http_schemas(),
        );
        m.lifecycle = Lifecycle::Active;
        m.path = Some("/api/v1/_seed/roles/{roleId}".to_string());
        m.method = Some(HttpMethod::Delete);
        m.endpoints = Some(Endpoints {
            http: Some(HttpEndpoint {
                success_status: 200,
                idempotency: HttpIdempotency::Idempotent,
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
            RawContractOwner::Framework,
            http_schemas(),
        );
        m.lifecycle = Lifecycle::Active;
        m.path = Some("/api/v1/_seed/roles/{roleId}".to_string());
        m.method = Some(HttpMethod::Delete);
        m.endpoints = Some(Endpoints {
            http: Some(HttpEndpoint {
                success_status: 200,
                idempotency: HttpIdempotency::Idempotent,
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
    fn r18_global_resource_is_canonical_not_a_dynamic_path_attribute() {
        let mut m = manifest(
            ContractKind::Http,
            ConsistencyLevel::LocalOnly,
            RawContractOwner::Framework,
            http_schemas(),
        );
        m.lifecycle = Lifecycle::Active;
        m.path = Some("/api/v1/runtime/inventory".to_string());
        m.method = Some(HttpMethod::Get);
        m.endpoints = Some(Endpoints {
            http: Some(HttpEndpoint {
                success_status: 200,
                idempotency: HttpIdempotency::Idempotent,
                auth: Some(HttpAuth {
                    mode: HttpAuthMode::Permission,
                    reason: None,
                    permission: Some("runtime:inventory:read".to_string()),
                }),
                resource: Some("runtimeInventory".to_string()),
                self_scoped: false,
                resource_sharing: Some(HttpResourceSharing {
                    mode: HttpResourceSharingMode::Global,
                    reason: Some("process-wide operator state".to_string()),
                }),
                headers: BTreeMap::new(),
                projection: None,
            }),
        });
        let findings = rule_http_auth(&m, "runtime.inventory");
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn r18_resource_sharing_tenant_scoped_forbids_reason() {
        let mut m = manifest(
            ContractKind::Http,
            ConsistencyLevel::LocalOnly,
            RawContractOwner::Framework,
            http_schemas(),
        );
        m.lifecycle = Lifecycle::Active;
        m.path = Some("/api/v1/_seed/roles/{roleId}".to_string());
        m.method = Some(HttpMethod::Delete);
        m.endpoints = Some(Endpoints {
            http: Some(HttpEndpoint {
                success_status: 200,
                idempotency: HttpIdempotency::Idempotent,
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
            RawContractOwner::Framework,
            http_schemas(),
        );
        m.lifecycle = Lifecycle::Active;
        m.path = Some("/api/v1/_seed/internal".to_string());
        m.method = Some(HttpMethod::Post);
        m.endpoints = Some(Endpoints {
            http: Some(HttpEndpoint {
                success_status: 200,
                idempotency: HttpIdempotency::Idempotent,
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
            RawContractOwner::Framework,
            http_schemas(),
        );
        m.lifecycle = Lifecycle::Active;
        m.path = Some("/api/v1/_seed/internal".to_string());
        m.method = Some(HttpMethod::Post);
        m.endpoints = Some(Endpoints {
            http: Some(HttpEndpoint {
                success_status: 200,
                idempotency: HttpIdempotency::Idempotent,
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
            RawContractOwner::Framework,
            http_schemas(),
        );
        m.lifecycle = Lifecycle::Active;
        m.path = Some("/api/v1/_seed/internal".to_string());
        m.method = Some(HttpMethod::Post);
        m.endpoints = Some(Endpoints {
            http: Some(HttpEndpoint {
                success_status: 200,
                idempotency: HttpIdempotency::Idempotent,
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
            RawContractOwner::Framework,
            http_schemas(),
        );
        m.lifecycle = Lifecycle::Active;
        m.path = Some("/api/v1/_seed/internal".to_string());
        m.method = Some(HttpMethod::Post);
        m.endpoints = Some(Endpoints {
            http: Some(HttpEndpoint {
                success_status: 200,
                idempotency: HttpIdempotency::Idempotent,
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
            RawContractOwner::Domain("identity".to_string()),
            http_schemas(),
        );
        m.id = "identity.login".to_string();
        m.domain = "identity".to_string();
        m.lifecycle = Lifecycle::Active;
        m.path = Some("/api/v1/identity/login".to_string());
        m.method = Some(HttpMethod::Post);
        m.endpoints = Some(Endpoints {
            http: Some(HttpEndpoint {
                success_status: 200,
                idempotency: HttpIdempotency::Idempotent,
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
        mutate_contract(&mut c, |manifest| {
            manifest.id = "audit.list-entries".to_string();
            manifest.domain = "audit".to_string();
            manifest.version = "v1".to_string();
            manifest.method = Some(HttpMethod::Get);
            manifest.path = Some("/api/v1/audit/entries".to_string());
        });
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
        mutate_contract(&mut c, |manifest| {
            manifest.id = "audit.list-entries".to_string();
            manifest.domain = "audit".to_string();
            manifest.version = "v1".to_string();
            manifest.method = Some(HttpMethod::Get);
            manifest.path = Some("/api/v1/audit/entries".to_string());
        });
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
        mutate_contract(&mut c, |manifest| {
            make_active_get(manifest, "/api/v1/profile", "profile:read", None);
        });

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
        mutate_contract(&mut c, |manifest| {
            make_active_get(
                manifest,
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
        });

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
        mutate_contract(&mut c, |manifest| {
            make_active_get(manifest, "/api/v1/roles", "roles:read", None);
        });

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
        mutate_contract(&mut c, |manifest| {
            make_active_get(
                manifest,
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
        });

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
        mutate_contract(&mut c, |manifest| {
            make_active_get(
                manifest,
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
        });

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
            RawContractOwner::Framework,
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
            RawContractOwner::Framework,
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
            RawContractOwner::Framework,
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
            RawContractOwner::Framework,
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
            RawContractOwner::Framework,
            http_schemas(),
        );
        http.path = Some("/api/v1/_seed/echo".to_string());
        http.method = Some(HttpMethod::Post);
        assert!(rule_perkind_field_scope(&http, "x").is_empty());
        let mut event = manifest(
            ContractKind::Event,
            ConsistencyLevel::OutboxFact,
            RawContractOwner::Framework,
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
            RawContractOwner::Framework,
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
            RawContractOwner::Domain("billing".to_string()),
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

    #[rstest]
    #[case("path")]
    #[case("method")]
    #[case("endpoints.http")]
    #[case("effectProfile")]
    #[case("topic")]
    #[case("delivery")]
    #[case("subscriptions")]
    #[case("command")]
    #[case("saga")]
    fn projection_rejects_http_command_event_and_saga_fields(#[case] field: &str) -> Result<()> {
        let mut manifest = projection_manifest(
            "settings.config-projection",
            "settings",
            Lifecycle::Active,
            "settings.config-version-changed",
        );
        match field {
            "path" => manifest.path = Some("/api/v3/settings/projection".to_string()),
            "method" => manifest.method = Some(HttpMethod::Get),
            "endpoints.http" => manifest.endpoints = Some(public_http_endpoints()),
            "effectProfile" => manifest.effect_profile = effect_profile(&[EffectKind::Projection]),
            "topic" => manifest.topic = Some("settings.config-projection".to_string()),
            "delivery" => manifest.delivery = Some(Delivery::AtLeastOnce),
            "subscriptions" => manifest.subscriptions = vec![one_subscription()],
            "command" => {
                manifest.command = Some(crate::contract::manifest::CommandBlock {
                    journal: crate::contract::manifest::CommandJournalPolicy::Required,
                    reconcile: None,
                });
            }
            "saga" => manifest.saga = Some(valid_saga_block()),
            _ => anyhow::bail!("closed consistency field fixture `{field}` escaped"),
        }

        let rejected = match field {
            "endpoints.http" => rule_http_auth(&manifest, "projection/settings/v3")
                .iter()
                .any(|finding| finding.rule == Rule::HttpAuth),
            "effectProfile" => {
                rule_consistency_capability(&[discovered(manifest, PathBuf::from("/projection"))])
                    .iter()
                    .any(|finding| finding.rule == Rule::ConsistencyCapability)
            }
            "command" => rule_command_policy(&manifest, "projection/settings/v3")
                .is_some_and(|finding| finding.rule == Rule::CommandPolicy),
            _ => rule_perkind_field_scope(&manifest, "projection/settings/v3")
                .iter()
                .any(|finding| finding.rule == Rule::PerKindFieldScope),
        };
        assert!(rejected, "kind=projection accepted forbidden field {field}");
        Ok(())
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
    fn r10_saga_duplicate_step_rejected() -> Result<()> {
        let mut b = valid_saga_block();
        let step_name = vocab::StepName::parse("reserve_funds")
            .context("canonical duplicate test step must parse")?;
        b.steps.push(SagaStep {
            name: step_name, // 与首 step 重名
            receipt_schema: "other.schema.json".to_string(),
            effect_scope: "billing.other".to_string(),
            compensation_effect_scope: "billing.undo_other".to_string(),
            idempotency_class: SagaIdempotencyClass::DeterministicKey,
            compensation_input: SagaCompensationInput::Receipt,
            retry_class: SagaRetryClass::Never,
        });
        let findings = rule_saga_block(&saga_manifest(Some(b)), "x");
        assert!(findings.iter().any(|f| f.rule == Rule::SagaBlock));
        Ok(())
    }

    #[rstest]
    #[case("9bad")] // 数字开头
    #[case("bad-name")] // 连字符非 Rust 标识符
    #[case("")] // 空
    #[case("fn")] // Rust 关键字
    #[case("r#fn")] // raw identifier（合法 syn::Ident 但须拒）
    #[case("föö")] // Unicode XID：runtime StepName 的 canonical ASCII grammar 拒绝
    fn r10_saga_bad_ident_step_rejected(#[case] name: &str) {
        assert!(
            vocab::StepName::parse(name).is_err(),
            "step name {name:?} must fail at the authoring type boundary"
        );
    }

    #[test]
    fn r10_saga_empty_receipt_schema_rejected() {
        let mut b = valid_saga_block();
        b.steps[0].receipt_schema = String::new();
        let findings = rule_saga_block(&saga_manifest(Some(b)), "x");
        assert!(findings.iter().any(|f| f.rule == Rule::SagaBlock));
    }

    #[test]
    fn r10_saga_retry_budget_and_backoff_are_fail_closed() {
        let mut zero_attempts = valid_saga_block();
        zero_attempts.retry.max_attempts = 0;
        assert!(
            rule_saga_block(&saga_manifest(Some(zero_attempts)), "x")
                .iter()
                .any(|finding| finding.detail.contains("maxAttempts"))
        );

        let mut zero_budget = valid_saga_block();
        zero_budget.retry.time_budget_millis = 0;
        assert!(
            rule_saga_block(&saga_manifest(Some(zero_budget)), "x")
                .iter()
                .any(|finding| finding.detail.contains("timeBudgetMillis"))
        );

        let mut inverted = valid_saga_block();
        inverted.retry.initial_backoff_millis = 1001;
        assert!(
            rule_saga_block(&saga_manifest(Some(inverted)), "x")
                .iter()
                .any(|finding| finding.detail.contains("maxBackoffMillis"))
        );
    }

    #[test]
    fn r10_saga_effect_scopes_are_required() {
        for compensation in [false, true] {
            let mut block = valid_saga_block();
            if compensation {
                block.steps[0].compensation_effect_scope.clear();
            } else {
                block.steps[0].effect_scope.clear();
            }
            assert!(
                rule_saga_block(&saga_manifest(Some(block)), "x")
                    .iter()
                    .any(|finding| finding.detail.contains("Scope"))
            );
        }
    }

    #[test]
    fn r10_authoring_type_and_cross_field_validation_are_both_fail_closed() {
        assert!(vocab::StepName::parse("9bad").is_err());
        let mut b = valid_saga_block();
        b.steps[0].receipt_schema = String::new();
        let findings = rule_saga_block(&saga_manifest(Some(b)), "x");
        assert_eq!(
            findings.len(),
            1,
            "typed name rejection and receipt validation must stay at their canonical boundaries: {findings:?}"
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
        // F1：kind=saga 无条件须有 block（generated / diport::SagaDurableStore / saga conformance，不论 lifecycle）——draft saga 缺 block 也拒。
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
            RawContractOwner::Framework,
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
            RawContractOwner::Framework,
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
            RawContractOwner::Framework,
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
            RawContractOwner::Framework,
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
            RawContractOwner::Framework,
            http_schemas(),
        );
        http.lifecycle = Lifecycle::Active;
        http.path = Some("/api/v1/_seed/echo".to_string());
        http.method = Some(HttpMethod::Post);
        assert!(rule_active_delivery_supported(&http, "x").is_none());
    }

    // ── R14 ActiveSubscriber（EVENT-ACTIVE-SUB-01）────────────────────────

    /// synthetic red：active event + 空 subscriptions → 产生 ActiveSubscriber finding。
    /// INVARIANT: EVENT-ACTIVE-SUB-01 { level = "Medium", exec = "check", source = "code", synthetic_red = "tests::r14_active_event_empty_subscriptions_rejected", anti_vacuity = "tests::r14_active_event_with_subscription_ok" }
    #[test]
    fn r14_active_event_empty_subscriptions_rejected() {
        let mut m = manifest(
            ContractKind::Event,
            ConsistencyLevel::OutboxFact,
            RawContractOwner::Domain("identity".to_string()),
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
            RawContractOwner::Domain("identity".to_string()),
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
            RawContractOwner::Framework,
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
            RawContractOwner::Framework,
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
            RawContractOwner::Framework,
            http_schemas(),
        );
        http.lifecycle = Lifecycle::Active;
        assert!(
            rule_active_subscriber(&http, "x").is_none(),
            "非 event kind 不受 R14 约束"
        );
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
            RawContractOwner::Framework,
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

    // ── R12 DuplicateId（跨契约，喂 &[RepositoryContract]，不读盘）────────────

    /// 构造一个 discovered 契约（id / 三段 label 可定制）。DuplicateId 只看 manifest.id + 路径段，不读盘。
    fn discovered_with(id: &str, kind: &str, domain: &str, version: &str) -> RepositoryContract {
        let mut m = manifest(
            ContractKind::Http,
            ConsistencyLevel::LocalOnly,
            RawContractOwner::Framework,
            http_schemas(),
        );
        m.id = id.to_string();
        let mut c = discovered(m, PathBuf::from("/x"));
        set_contract_path(&mut c, kind, domain, version, None);
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

    // ── R20 SlugSyntax（per-contract，读 c.slug()）─────────────────────────────

    /// 构造一个带 slug 的 event 契约（嵌套形态）。
    fn discovered_event_slug(
        domain: &str,
        version: &str,
        slug: Option<&str>,
    ) -> RepositoryContract {
        let m = manifest(
            ContractKind::Event,
            ConsistencyLevel::OutboxFact,
            RawContractOwner::Domain(domain.to_string()),
            payload_schemas(),
        );
        let mut c = discovered(m, PathBuf::from("/x"));
        set_contract_path(&mut c, "event", domain, version, slug);
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

    fn http_outbox_producer(
        lifecycle: Lifecycle,
        domain: &str,
        id: &str,
        emits: &[&str],
    ) -> RepositoryContract {
        let mut m = manifest(
            ContractKind::Http,
            ConsistencyLevel::OutboxFact,
            RawContractOwner::Domain(domain.to_string()),
            http_schemas(),
        );
        m.id = id.to_string();
        m.domain = domain.to_string();
        m.lifecycle = lifecycle;
        m.capabilities = outbox_producer_capability(emits);
        discovered(m, PathBuf::from(format!("/{id}")))
    }

    fn outbox_event(lifecycle: Lifecycle, domain: &str, id: &str) -> RepositoryContract {
        let mut m = manifest(
            ContractKind::Event,
            ConsistencyLevel::OutboxFact,
            RawContractOwner::Domain(domain.to_string()),
            payload_schemas(),
        );
        m.id = id.to_string();
        m.domain = domain.to_string();
        m.lifecycle = lifecycle;
        m.subscriptions = vec![one_subscription()];
        m.capabilities = outbox_fact_capability();
        discovered(m, PathBuf::from(format!("/{id}")))
    }

    #[test]
    fn r22_consistency_http_requires_effect_profile() {
        let mut m = manifest(
            ContractKind::Http,
            ConsistencyLevel::LocalOnly,
            RawContractOwner::Framework,
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
            RawContractOwner::Domain("identity".to_string()),
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
            RawContractOwner::Framework,
            http_schemas(),
        );
        empty.id = "seed.empty".to_string();
        empty.effect_profile = effect_profile(&[]);

        let mut duplicate = manifest(
            ContractKind::Http,
            ConsistencyLevel::LocalOnly,
            RawContractOwner::Framework,
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
            RawContractOwner::Framework,
            payload_schemas(),
        );
        m.id = "seed.local-event".to_string();
        m.capabilities = outbox_fact_capability();
        let findings = rule_consistency_capability(&[discovered(m, PathBuf::from("/x"))]);
        assert_r22_detail(&findings, "seed.local-event", "local-only-http");
        assert_r22_detail(&findings, "seed.local-event", "capability-scope");
        for required in [
            "LocalOnly 当前只允许 kind=http",
            "业务持久化/outbox/publish",
            "不排除 provider-owned read-path transaction",
        ] {
            assert!(
                findings.iter().any(|finding| {
                    finding
                        .detail
                        .contains("missing capability=local-only-http")
                        && finding.detail.contains(required)
                }),
                "R22 LocalOnly diagnostic missing {required:?}: {findings:?}"
            );
        }
    }

    #[test]
    fn r22_consistency_localtx_requires_http_and_localtx_capability() {
        let mut m = manifest(
            ContractKind::Event,
            ConsistencyLevel::LocalTx,
            RawContractOwner::Domain("identity".to_string()),
            payload_schemas(),
        );
        m.id = "identity.local-tx-event".to_string();
        let findings = rule_consistency_capability(&[discovered(m, PathBuf::from("/x"))]);
        assert_r22_detail(&findings, "identity.local-tx-event", CAP_LOCAL_TX);
        assert!(findings.iter().any(|finding| {
            finding
                .detail
                .contains("txModel ∈ {\"tenant-scoped-uow\", \"repo-atomic-cas\"}")
        }));
    }

    #[test]
    fn r22_consistency_localtx_accepts_repo_atomic_cas_model() {
        let mut manifest = manifest(
            ContractKind::Http,
            ConsistencyLevel::LocalTx,
            RawContractOwner::Domain("settings".to_string()),
            http_schemas(),
        );
        manifest.id = "settings.secret-publish".to_string();
        manifest.capabilities = repo_atomic_cas_local_tx_capability();
        manifest.effect_profile = effect_profile(&[
            EffectKind::Auth,
            EffectKind::BusinessWrite,
            EffectKind::BusinessTransaction,
        ]);

        assert!(
            rule_consistency_capability(&[discovered(manifest, PathBuf::from("/settings"))])
                .is_empty()
        );
    }

    #[test]
    fn r22_consistency_event_outbox_wrong_role_and_stray_payload_fields_rejected() {
        let mut m = manifest(
            ContractKind::Event,
            ConsistencyLevel::OutboxFact,
            RawContractOwner::Domain("identity".to_string()),
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
            RawContractOwner::Domain("identity".to_string()),
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
            RawContractOwner::Domain("identity".to_string()),
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
            RawContractOwner::Domain("identity".to_string()),
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

    #[rstest]
    #[case(Lifecycle::Draft)]
    #[case(Lifecycle::Active)]
    #[case(Lifecycle::Deprecated)]
    fn r22_http_outbox_emits_must_stay_in_producer_domain_for_every_lifecycle(
        #[case] lifecycle: Lifecycle,
    ) {
        let contracts = vec![
            http_outbox_producer(
                lifecycle,
                "identity",
                "identity.roles-assign",
                &["settings.config-version-changed"],
            ),
            outbox_event(lifecycle, "settings", "settings.config-version-changed"),
        ];

        let findings = rule_consistency_capability(&contracts);
        assert!(
            findings.iter().any(|finding| {
                finding.rule == Rule::ConsistencyCapability
                    && finding.detail.contains("contract id=identity.roles-assign")
                    && finding.detail.contains(
                        "emitted fact domain=settings must equal producer domain=identity",
                    )
            }),
            "{lifecycle:?} cross-domain emits must fail closed: {findings:?}"
        );
    }

    #[rstest]
    #[case(Lifecycle::Draft)]
    #[case(Lifecycle::Active)]
    #[case(Lifecycle::Deprecated)]
    fn r22_http_outbox_emits_accepts_same_domain_for_every_lifecycle(#[case] lifecycle: Lifecycle) {
        let contracts = vec![
            http_outbox_producer(
                lifecycle,
                "identity",
                "identity.roles-assign",
                &["identity.role-assigned"],
            ),
            outbox_event(lifecycle, "identity", "identity.role-assigned"),
        ];

        let findings = rule_consistency_capability(&contracts);
        assert!(
            findings
                .iter()
                .all(|finding| !finding.detail.contains("emitted fact domain=")),
            "{lifecycle:?} same-domain emits must pass domain guard: {findings:?}"
        );
    }

    #[test]
    fn r22_consistency_http_outbox_emits_ref_rejects_non_event_target() {
        let mut producer = manifest(
            ContractKind::Http,
            ConsistencyLevel::OutboxFact,
            RawContractOwner::Domain("identity".to_string()),
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
            RawContractOwner::Domain("identity".to_string()),
            http_schemas(),
        );
        producer.id = "identity.roles-assign".to_string();
        producer.lifecycle = Lifecycle::Active;
        producer.capabilities = outbox_producer_capability(&["identity.role-assigned"]);

        let mut draft_event = manifest(
            ContractKind::Event,
            ConsistencyLevel::OutboxFact,
            RawContractOwner::Domain("identity".to_string()),
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
            RawContractOwner::Domain("billing".to_string()),
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
    fn r22_consistency_saga_workflow_rejects_projection_only_fields() -> Result<()> {
        let mut m = saga_manifest(Some(valid_saga_block()));
        m.capabilities = workflow_saga_capability();
        let workflow = m
            .capabilities
            .workflow
            .as_mut()
            .context("workflow_saga_capability sets workflow")?;
        workflow.inputs = vec!["identity.session-created".to_string()];
        workflow.ordering = Some(WorkflowOrdering::SerialInOrder);
        let findings = rule_consistency_capability(&[discovered(m, PathBuf::from("/x"))]);
        assert_r22_detail(&findings, "billing.checkout", CAP_WORKFLOW_FIELD_SCOPE);
        Ok(())
    }

    #[test]
    fn r22_consistency_projection_inputs_ref_must_target_l2_event() {
        let mut projection = manifest(
            ContractKind::Http,
            ConsistencyLevel::WorkflowEventual,
            RawContractOwner::Domain("audit".to_string()),
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
    fn r22_projection_kind_requires_workflow_eventual_and_projection_mode() {
        let base = projection_manifest(
            "audit.session-projection",
            "audit",
            Lifecycle::Draft,
            "identity.session-created",
        );

        let mut wrong_level = base.clone();
        wrong_level.consistency_level = ConsistencyLevel::LocalTx;
        let findings =
            rule_consistency_capability(&[discovered(wrong_level, PathBuf::from("/projection"))]);
        assert!(
            findings
                .iter()
                .any(|finding| finding.rule == Rule::ConsistencyCapability),
            "kind=projection must reject non-WorkflowEventual consistency"
        );

        let mut missing_workflow = base.clone();
        missing_workflow.capabilities.workflow = None;
        let findings = rule_consistency_capability(&[discovered(
            missing_workflow,
            PathBuf::from("/projection"),
        )]);
        assert_r22_detail(&findings, "audit.session-projection", CAP_WORKFLOW);

        let mut saga_mode = base;
        saga_mode.capabilities.workflow = Some(WorkflowCapability {
            mode: WorkflowMode::Saga,
            inputs: Vec::new(),
            ordering: None,
            checkpoint: None,
            replay: None,
        });
        let findings =
            rule_consistency_capability(&[discovered(saga_mode, PathBuf::from("/projection"))]);
        assert!(
            findings
                .iter()
                .any(|finding| finding.rule == Rule::ConsistencyCapability),
            "kind=projection must reject workflow.mode=saga"
        );
    }

    #[test]
    fn r22_projection_workflow_mode_is_reserved_for_projection_kind() {
        let mut legacy_http = manifest(
            ContractKind::Http,
            ConsistencyLevel::WorkflowEventual,
            RawContractOwner::Domain("audit".to_string()),
            http_schemas(),
        );
        legacy_http.id = "audit.session-projection".to_string();
        legacy_http.capabilities = workflow_projection_capability();
        legacy_http.effect_profile =
            effect_profile(&[EffectKind::Auth, EffectKind::Read, EffectKind::Projection]);

        let findings = rule_consistency_capability(&[
            discovered(legacy_http, PathBuf::from("/http")),
            discovered(
                projection_input_event("identity.session-created"),
                PathBuf::from("/event"),
            ),
        ]);
        assert!(
            findings
                .iter()
                .any(|finding| finding.rule == Rule::ConsistencyCapability),
            "workflow.mode=projection must not remain valid on legacy kind=http"
        );
    }

    #[test]
    fn r22_settings_active_and_audit_draft_projection_carriers_validate_without_routes() {
        for (id, domain, lifecycle, input) in [
            (
                "settings.config-projection",
                "settings",
                Lifecycle::Active,
                "settings.config-version-changed",
            ),
            (
                "audit.session-projection",
                "audit",
                Lifecycle::Draft,
                "identity.session-created",
            ),
        ] {
            let projection = projection_manifest(id, domain, lifecycle, input);
            assert!(projection.path.is_none());
            assert!(projection.method.is_none());
            assert!(projection.endpoints.is_none());
            assert!(
                rule_schema_shape(&projection, "projection").is_empty(),
                "{id} must use the exact projection schema shape"
            );
            assert!(
                rule_perkind_active_fields(&projection, "projection").is_empty(),
                "active projection must not acquire HTTP/event/command serving fields"
            );
            assert!(
                rule_perkind_field_scope(&projection, "projection").is_empty(),
                "{id} must not carry fields from another contract kind"
            );
            assert!(rule_http_auth(&projection, "projection").is_empty());

            let findings = rule_consistency_capability(&[
                discovered(projection, PathBuf::from("/projection")),
                discovered(projection_input_event(input), PathBuf::from("/event")),
            ]);
            assert!(findings.is_empty(), "{id} must validate: {findings:?}");
        }
    }

    #[test]
    fn r22_consistency_projection_missing_evidence_fields_rejected() -> Result<()> {
        let mut m = manifest(
            ContractKind::Http,
            ConsistencyLevel::WorkflowEventual,
            RawContractOwner::Domain("audit".to_string()),
            http_schemas(),
        );
        m.id = "audit.session-projection".to_string();
        m.capabilities = workflow_projection_capability_with_inputs(&[]);
        let workflow = m
            .capabilities
            .workflow
            .as_mut()
            .context("workflow_projection_capability_with_inputs sets workflow")?;
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
        Ok(())
    }

    #[test]
    fn r22_consistency_workflow_eventual_does_not_require_reconcile() {
        let mut saga = saga_manifest(Some(valid_saga_block()));
        saga.capabilities = workflow_saga_capability();

        let mut event = manifest(
            ContractKind::Event,
            ConsistencyLevel::OutboxFact,
            RawContractOwner::Domain("identity".to_string()),
            payload_schemas(),
        );
        event.id = "identity.session-created".to_string();
        event.capabilities = outbox_fact_capability();

        let projection = projection_manifest(
            "audit.session-projection",
            "audit",
            Lifecycle::Draft,
            "identity.session-created",
        );

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
            RawContractOwner::Framework,
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
            RawContractOwner::Domain("device".to_string()),
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
            RawContractOwner::Domain("device".to_string()),
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
            RawContractOwner::Domain("device".to_string()),
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
            RawContractOwner::Framework,
            http_schemas(),
        );
        local.id = "seed.local".to_string();
        local.effect_profile = effect_profile(&[EffectKind::Auth, EffectKind::Read]);

        let mut local_tx = manifest(
            ContractKind::Http,
            ConsistencyLevel::LocalTx,
            RawContractOwner::Domain("identity".to_string()),
            http_schemas(),
        );
        local_tx.id = "identity.logout".to_string();
        local_tx.capabilities = local_tx_capability();
        local_tx.effect_profile = effect_profile(&[
            EffectKind::Auth,
            EffectKind::BusinessWrite,
            EffectKind::BusinessTransaction,
        ]);

        let mut fact = manifest(
            ContractKind::Event,
            ConsistencyLevel::OutboxFact,
            RawContractOwner::Domain("identity".to_string()),
            payload_schemas(),
        );
        fact.id = "identity.session-created".to_string();
        fact.capabilities = outbox_fact_capability();

        let mut command = command_manifest(ConsistencyLevel::OutboxFact);
        command.capabilities = outbox_command_capability();

        let mut producer = manifest(
            ContractKind::Http,
            ConsistencyLevel::OutboxFact,
            RawContractOwner::Domain("identity".to_string()),
            http_schemas(),
        );
        producer.id = "identity.login".to_string();
        producer.capabilities = outbox_producer_capability(&["identity.session-created"]);
        producer.effect_profile = effect_profile(&[
            EffectKind::Auth,
            EffectKind::BusinessWrite,
            EffectKind::BusinessTransaction,
            EffectKind::Outbox,
            EffectKind::Publish,
        ]);

        let mut saga = saga_manifest(Some(valid_saga_block()));
        saga.capabilities = workflow_saga_capability();

        let projection = projection_manifest(
            "audit.session-projection",
            "audit",
            Lifecycle::Draft,
            "identity.session-created",
        );

        let mut device = manifest(
            ContractKind::Http,
            ConsistencyLevel::DeviceLatent,
            RawContractOwner::Domain("device".to_string()),
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
            discovered(projection, PathBuf::from("/projection")),
            discovered(device, PathBuf::from("/x")),
        ];
        let findings = rule_consistency_capability(&contracts);
        assert!(findings.is_empty(), "{findings:?}");
    }

    // ── R25 DeviceCertificateHttpClosure ──────────────────────────────

    const DEVICE_CERT_POLICY_ID: &str = "identity.device-certificate-policy-put";
    const DEVICE_CERT_STATUS_ID: &str = "identity.device-certificate-status-get";
    const DEVICE_CERT_POLICY_PATH: &str = "/api/v2/identity/devices/{deviceId}/certificate-policy";
    const DEVICE_CERT_STATUS_PATH: &str = "/api/v2/identity/devices/{deviceId}/certificate-status";
    const DEVICE_CERT_POLICY_PERMISSION: &str =
        vocab::RoutePermissionId::IdentityDeviceCertificatePolicyWrite.as_str();
    const DEVICE_CERT_STATUS_PERMISSION: &str =
        vocab::RoutePermissionId::IdentityDeviceCertificateStatusRead.as_str();

    fn assert_r25_detail(findings: &[Finding], detail: &str) {
        assert!(
            findings.iter().any(|finding| {
                finding.rule == Rule::DeviceCertificateHttpClosure
                    && finding.detail.contains(detail)
            }),
            "expected R25 finding containing {detail:?}; got {findings:?}"
        );
    }

    fn assert_r25_subject_detail(findings: &[Finding], subject: &str, detail: &str) {
        assert!(
            findings.iter().any(|finding| {
                finding.rule == Rule::DeviceCertificateHttpClosure
                    && finding.subject == subject
                    && finding.detail.contains(detail)
            }),
            "expected R25 finding subject={subject:?} containing {detail:?}; got {findings:?}"
        );
    }

    fn device_certificate_endpoint(permission: &str) -> Endpoints {
        Endpoints {
            http: Some(HttpEndpoint {
                success_status: 200,
                idempotency: HttpIdempotency::Idempotent,
                auth: Some(HttpAuth {
                    mode: HttpAuthMode::Permission,
                    reason: None,
                    permission: Some(permission.to_string()),
                }),
                resource: Some("deviceId".to_string()),
                self_scoped: false,
                resource_sharing: None,
                headers: BTreeMap::new(),
                projection: None,
            }),
        }
    }

    fn device_certificate_http_pair(
        policy_lifecycle: Lifecycle,
    ) -> anyhow::Result<(Vec<RepositoryContract>, PathBuf)> {
        let root = unique_tmp("validate-r25");
        let policy_dir = root.join(DeviceCertificateCandidateId::PolicyPut.spec().source_dir);
        let status_dir = root.join(DeviceCertificateCandidateId::StatusGet.spec().source_dir);
        std::fs::create_dir_all(&policy_dir)?;
        std::fs::create_dir_all(&status_dir)?;
        std::fs::write(
            policy_dir.join("request.schema.json"),
            include_str!(
                "../../../contracts/http/identity/v2/device-certificate-policy-put/request.schema.json"
            ),
        )?;
        std::fs::write(
            policy_dir.join("response.schema.json"),
            include_str!(
                "../../../contracts/http/identity/v2/device-certificate-policy-put/response.schema.json"
            ),
        )?;
        std::fs::write(
            status_dir.join("request.schema.json"),
            include_str!(
                "../../../contracts/http/identity/v2/device-certificate-status-get/request.schema.json"
            ),
        )?;
        std::fs::write(
            status_dir.join("response.schema.json"),
            include_str!(
                "../../../contracts/http/identity/v2/device-certificate-status-get/response.schema.json"
            ),
        )?;

        let mut policy = manifest(
            ContractKind::Http,
            ConsistencyLevel::DeviceLatent,
            RawContractOwner::Domain("identity".to_string()),
            http_schemas(),
        );
        policy.id = DEVICE_CERT_POLICY_ID.to_string();
        policy.domain = "identity".to_string();
        policy.version = "v2".to_string();
        policy.lifecycle = policy_lifecycle;
        policy.path = Some(DEVICE_CERT_POLICY_PATH.to_string());
        policy.method = Some(HttpMethod::Put);
        policy.endpoints = Some(device_certificate_endpoint(DEVICE_CERT_POLICY_PERMISSION));
        policy.schemas.response = None;
        policy.schemas.responses = BTreeMap::from([
            (HttpStatusCode::new(200), "response.schema.json".to_string()),
            (HttpStatusCode::new(400), "response.schema.json".to_string()),
            (HttpStatusCode::new(404), "response.schema.json".to_string()),
            (HttpStatusCode::new(409), "response.schema.json".to_string()),
            (HttpStatusCode::new(503), "response.schema.json".to_string()),
        ]);
        policy.capabilities = device_latent_capability();
        policy.reconcile = Some(valid_reconcile_block());
        policy.effect_profile = effect_profile(&[
            EffectKind::Auth,
            EffectKind::BusinessWrite,
            EffectKind::BusinessTransaction,
            EffectKind::Reconcile,
        ]);
        let authorization_receipt: serde_json::Value = serde_json::from_str(include_str!(
            "../../../contracts/components/identity/v1/authorization-receipt-id.schema.json"
        ))?;
        let mut policy = fixture_builder(policy, policy_dir)
            .component(
                "rss://component/identity/v1/authorization-receipt-id",
                authorization_receipt.clone(),
            )
            .build()?;
        set_contract_path(
            &mut policy,
            "http",
            "identity",
            "v2",
            Some("device-certificate-policy-put"),
        );

        let mut status = manifest(
            ContractKind::Http,
            ConsistencyLevel::LocalOnly,
            RawContractOwner::Domain("identity".to_string()),
            http_schemas(),
        );
        status.id = DEVICE_CERT_STATUS_ID.to_string();
        status.domain = "identity".to_string();
        status.version = "v2".to_string();
        status.lifecycle = policy_lifecycle;
        status.path = Some(DEVICE_CERT_STATUS_PATH.to_string());
        status.method = Some(HttpMethod::Get);
        status.endpoints = Some(device_certificate_endpoint(DEVICE_CERT_STATUS_PERMISSION));
        status.schemas.response = None;
        status.schemas.responses = BTreeMap::from([
            (HttpStatusCode::new(200), "response.schema.json".to_string()),
            (HttpStatusCode::new(400), "response.schema.json".to_string()),
            (HttpStatusCode::new(503), "response.schema.json".to_string()),
        ]);
        status.effect_profile =
            effect_profile(&[EffectKind::Auth, EffectKind::Read, EffectKind::Projection]);
        let mut status = fixture_builder(status, status_dir)
            .component(
                "rss://component/identity/v1/authorization-receipt-id",
                authorization_receipt,
            )
            .build()?;
        set_contract_path(
            &mut status,
            "http",
            "identity",
            "v2",
            Some("device-certificate-status-get"),
        );

        Ok((vec![policy, status], root))
    }

    fn device_certificate_target(
        id: &str,
        kind: ContractKind,
        lifecycle: Lifecycle,
    ) -> anyhow::Result<RepositoryContract> {
        let schemas = match kind {
            ContractKind::Command => Schemas {
                request: Some("request.schema.json".to_string()),
                ..Schemas::default()
            },
            _ => payload_schemas(),
        };
        let mut target = manifest(
            kind,
            ConsistencyLevel::OutboxFact,
            RawContractOwner::Domain("identity".to_string()),
            schemas,
        );
        target.id = id.to_string();
        target.domain = "identity".to_string();
        target.lifecycle = lifecycle;
        let source_dir = DeviceCertificateCandidateId::ALL
            .into_iter()
            .find(|candidate| candidate.spec().id == id)
            .with_context(|| format!("R25 target `{id}` must be a canonical candidate"))?
            .spec()
            .source_dir;
        let mut contract = discovered(target, PathBuf::from("/fixture").join(source_dir));
        let mut segments = source_dir
            .strip_prefix("contracts/")
            .context("candidate sourceDir must be repository-relative")?
            .split('/');
        let kind = segments
            .next()
            .context("candidate sourceDir missing kind")?;
        let domain = segments
            .next()
            .context("candidate sourceDir missing domain")?;
        let version = segments
            .next()
            .context("candidate sourceDir missing version")?;
        set_contract_path(&mut contract, kind, domain, version, segments.next());
        Ok(contract)
    }

    fn append_device_certificate_targets(
        contracts: &mut Vec<RepositoryContract>,
        lifecycle: Lifecycle,
    ) -> anyhow::Result<()> {
        contracts.extend([
            device_certificate_target(
                "identity.apply-device-certificate",
                ContractKind::Command,
                lifecycle,
            )?,
            device_certificate_target(
                "identity.device-command-acked",
                ContractKind::Event,
                lifecycle,
            )?,
            device_certificate_target(
                "identity.device-certificate-reported",
                ContractKind::Event,
                lifecycle,
            )?,
            device_certificate_target(
                "identity.device-ingress-receipted",
                ContractKind::Event,
                lifecycle,
            )?,
        ]);
        Ok(())
    }

    fn r25_schema_value(
        contract: &RepositoryContract,
        schema_file: &str,
    ) -> anyhow::Result<serde_json::Value> {
        let path = contract.dir().join(schema_file);
        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("读取 R25 测试 schema {}", path.display()))?;
        serde_json::from_str(&text)
            .with_context(|| format!("解析 R25 测试 schema {}", path.display()))
    }

    fn write_r25_schema_value(
        contract: &mut RepositoryContract,
        schema_file: &str,
        value: &serde_json::Value,
    ) -> anyhow::Result<()> {
        let path = contract.dir().join(schema_file);
        let bytes = serde_json::to_vec_pretty(value).context("序列化 R25 测试 schema")?;
        std::fs::write(&path, bytes)
            .with_context(|| format!("写入 R25 测试 schema {}", path.display()))?;
        mutate_contract(contract, |_| {});
        Ok(())
    }

    fn r25_schema_object_mut<'a>(
        schema: &'a mut serde_json::Value,
        pointer: &str,
    ) -> anyhow::Result<&'a mut serde_json::Map<String, serde_json::Value>> {
        schema
            .pointer_mut(pointer)
            .and_then(serde_json::Value::as_object_mut)
            .with_context(|| format!("R25 测试 schema pointer {pointer:?} 必须指向 object"))
    }

    #[test]
    fn r25_device_certificate_http_pair_is_required_and_legacy_id_is_forbidden() {
        let findings = rule_device_certificate_http_closure(&[]);
        assert_r25_detail(&findings, DEVICE_CERT_POLICY_ID);
        assert_r25_detail(&findings, DEVICE_CERT_STATUS_ID);

        let mut legacy = manifest(
            ContractKind::Http,
            ConsistencyLevel::DeviceLatent,
            RawContractOwner::Domain("identity".to_string()),
            http_schemas(),
        );
        legacy.id = "identity.reconcile-loop".to_string();
        let findings =
            rule_device_certificate_http_closure(&[discovered(legacy, PathBuf::from("/legacy"))]);
        assert_r25_detail(&findings, "identity.reconcile-loop");
    }

    #[test]
    fn r25_device_certificate_draft_exact_set_is_anti_vacuity_green() -> anyhow::Result<()> {
        assert_eq!(
            vocab::RoutePermissionId::parse(DEVICE_CERT_POLICY_PERMISSION),
            Ok(vocab::RoutePermissionId::IdentityDeviceCertificatePolicyWrite)
        );
        assert_eq!(
            vocab::RoutePermissionId::parse(DEVICE_CERT_STATUS_PERMISSION),
            Ok(vocab::RoutePermissionId::IdentityDeviceCertificateStatusRead)
        );
        let (mut contracts, root) = device_certificate_http_pair(Lifecycle::Draft)?;
        append_device_certificate_targets(&mut contracts, Lifecycle::Draft)?;
        let findings = rule_device_certificate_http_closure(&contracts);
        std::fs::remove_dir_all(root)?;
        assert!(findings.is_empty(), "{findings:?}");
        Ok(())
    }

    #[test]
    fn r25_device_certificate_exact_set_rejects_duplicate_and_equal_count_replacement()
    -> anyhow::Result<()> {
        let (mut contracts, root) = device_certificate_http_pair(Lifecycle::Draft)?;
        append_device_certificate_targets(&mut contracts, Lifecycle::Draft)?;

        let mut duplicate = contracts.clone();
        duplicate.push(contracts[2].clone());
        assert_r25_detail(
            &rule_device_certificate_http_closure(&duplicate),
            "必须恰好出现一次",
        );

        let mut replacement = contracts.clone();
        mutate_contract(&mut replacement[2], |manifest| {
            manifest.id = "identity.apply-device-certificate-v2".to_string();
        });
        assert_r25_detail(
            &rule_device_certificate_http_closure(&replacement),
            "identity.apply-device-certificate",
        );

        std::fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn r25_device_certificate_rejects_extra_operator_route_or_permission() -> anyhow::Result<()> {
        let (mut contracts, root) = device_certificate_http_pair(Lifecycle::Draft)?;
        append_device_certificate_targets(&mut contracts, Lifecycle::Draft)?;
        let mut mutation = contracts[1].clone();
        mutate_contract(&mut mutation, |manifest| {
            manifest.id = "identity.device-certificate-resync-post".to_string();
            manifest.domain = "settings".to_string();
            manifest.test_set_domain_owner("settings");
            manifest.path =
                Some("/api/v2/identity/devices/{deviceId}/certificate/resync".to_string());
        });
        set_contract_path(
            &mut mutation,
            "http",
            "identity",
            "v2",
            Some("device-certificate-resync-post"),
        );
        contracts.push(mutation);

        assert_r25_detail(
            &rule_device_certificate_http_closure(&contracts),
            "operator surface 只允许 canonical draft candidate IDs",
        );
        std::fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn r25_device_certificate_rejects_noncanonical_source_directory() -> anyhow::Result<()> {
        let (mut contracts, root) = device_certificate_http_pair(Lifecycle::Draft)?;
        append_device_certificate_targets(&mut contracts, Lifecycle::Draft)?;
        let source = &contracts[2];
        contracts[2] = fixture_builder(
            source.manifest().clone(),
            root.join("contracts/command/identity/v1-shadow"),
        )
        .path_version("v1-shadow")
        .path_kind(source.path_kind())
        .path_domain(source.path_domain())
        .slug(source.slug())
        .build()?;

        assert_r25_detail(
            &rule_device_certificate_http_closure(&contracts),
            "canonical sourceDir=contracts/command/identity/v1",
        );
        std::fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn r25_policy_request_schema_enforces_security_metadata() -> anyhow::Result<()> {
        let (mut contracts, root) = device_certificate_http_pair(Lifecycle::Draft)?;
        let original = r25_schema_value(&contracts[0], "request.schema.json")?;

        let mut invalid = original.clone();
        r25_schema_object_mut(&mut invalid, "/properties")?.insert(
            "tenantId".to_string(),
            serde_json::json!({"type": "string"}),
        );
        write_r25_schema_value(&mut contracts[0], "request.schema.json", &invalid)?;
        assert_r25_detail(
            &rule_device_certificate_http_closure(&contracts),
            "tenantId/deviceId",
        );

        for (pointer, annotation, wrong, detail) in [
            (
                "/properties/idempotencyKey",
                "x-redaction",
                "drop",
                "idempotencyKey x-redaction=internal",
            ),
            (
                "/properties/policy/properties/keyUsages",
                "x-redaction",
                "drop",
                "keyUsages x-redaction=internal",
            ),
            (
                "/properties/policy/properties/sans",
                "x-pii",
                "none",
                "sans x-pii=generic",
            ),
            (
                "/properties/policy/properties/sans",
                "x-redaction",
                "internal",
                "sans x-redaction=drop",
            ),
        ] {
            let mut invalid = original.clone();
            r25_schema_object_mut(&mut invalid, pointer)?.insert(
                annotation.to_string(),
                serde_json::Value::String(wrong.to_string()),
            );
            write_r25_schema_value(&mut contracts[0], "request.schema.json", &invalid)?;
            assert_r25_detail(&rule_device_certificate_http_closure(&contracts), detail);
        }

        std::fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn r25_policy_response_schema_shape_is_owned_by_json_schema() -> anyhow::Result<()> {
        let (mut contracts, root) = device_certificate_http_pair(Lifecycle::Draft)?;
        let mut extended = r25_schema_value(&contracts[0], "response.schema.json")?;
        r25_schema_object_mut(&mut extended, "/properties/data")?
            .get_mut("properties")
            .and_then(serde_json::Value::as_object_mut)
            .context("R25 policy response properties")?
            .insert(
                "completed".to_string(),
                serde_json::json!({"type": "boolean"}),
            );
        write_r25_schema_value(&mut contracts[0], "response.schema.json", &extended)?;

        let findings = rule_device_certificate_http_closure(&contracts);
        assert!(
            findings.iter().all(|finding| {
                !finding.detail.contains("properties")
                    && !finding.detail.contains("additionalProperties")
            }),
            "R25 must not mirror JSON Schema field sets: {findings:?}"
        );

        std::fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn r25_status_response_schema_enforces_payload_free_summary() -> anyhow::Result<()> {
        let (mut contracts, root) = device_certificate_http_pair(Lifecycle::Draft)?;
        let original = r25_schema_value(&contracts[1], "response.schema.json")?;

        let mut invalid = original.clone();
        r25_schema_object_mut(&mut invalid, "/definitions/activeCommand/properties")?
            .insert("payload".to_string(), serde_json::json!({"type": "string"}));
        write_r25_schema_value(&mut contracts[1], "response.schema.json", &invalid)?;
        assert_r25_detail(
            &rule_device_certificate_http_closure(&contracts),
            "activeCommand 禁止 payload",
        );

        std::fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn r25_forbidden_identity_and_payload_properties_are_recursive() -> anyhow::Result<()> {
        let (mut contracts, root) = device_certificate_http_pair(Lifecycle::Draft)?;
        let policy = r25_schema_value(&contracts[0], "request.schema.json")?;
        let status = r25_schema_value(&contracts[1], "response.schema.json")?;

        for fragment in [
            serde_json::json!({"definitions": {"nested": {"type": "object", "properties": {"tenantId": {"type": "string"}}}}}),
            serde_json::json!({"properties": {"nested": {"type": "array", "items": {"type": "object", "properties": {"deviceId": {"type": "string"}}}}}}),
            serde_json::json!({"allOf": [{"type": "object", "properties": {"tenantId": {"type": "string"}}}]}),
        ] {
            let mut invalid = policy.clone();
            invalid
                .as_object_mut()
                .context("R25 policy schema object")?
                .extend(fragment.as_object().context("R25 policy fragment")?.clone());
            write_r25_schema_value(&mut contracts[0], "request.schema.json", &invalid)?;
            assert_r25_detail(
                &rule_device_certificate_http_closure(&contracts),
                "tenantId/deviceId",
            );
        }

        for fragment in [
            serde_json::json!({"$defs": {"nested": {"type": "object", "properties": {"payload": {"type": "string"}}}}}),
            serde_json::json!({"properties": {"nested": {"type": "array", "items": {"type": "object", "properties": {"payload": {"type": "string"}}}}}}),
            serde_json::json!({"anyOf": [{"type": "object", "properties": {"payload": {"type": "string"}}}]}),
            serde_json::json!({"oneOf": [{"type": "object", "properties": {"payload": {"type": "string"}}}]}),
        ] {
            let mut invalid = status.clone();
            invalid
                .as_object_mut()
                .context("R25 status schema object")?
                .extend(fragment.as_object().context("R25 status fragment")?.clone());
            write_r25_schema_value(&mut contracts[1], "response.schema.json", &invalid)?;
            assert_r25_detail(
                &rule_device_certificate_http_closure(&contracts),
                "activeCommand 禁止 payload",
            );
        }

        std::fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn r25_device_certificate_policy_route_auth_and_consistency_are_exact() -> anyhow::Result<()> {
        let (contracts, root) = device_certificate_http_pair(Lifecycle::Draft)?;

        let mut invalid = contracts.clone();
        mutate_contract(&mut invalid[0], |manifest| {
            manifest.kind = ContractKind::Event;
        });
        assert_r25_detail(&rule_device_certificate_http_closure(&invalid), "kind=http");

        let mut invalid = contracts.clone();
        mutate_contract(&mut invalid[0], |manifest| {
            manifest.consistency_level = ConsistencyLevel::LocalOnly;
        });
        assert_r25_detail(
            &rule_device_certificate_http_closure(&invalid),
            "consistencyLevel=DeviceLatent",
        );

        let mut invalid = contracts.clone();
        mutate_contract(&mut invalid[0], |manifest| {
            manifest.method = Some(HttpMethod::Get);
        });
        assert_r25_detail(
            &rule_device_certificate_http_closure(&invalid),
            "method=PUT",
        );

        let mut invalid = contracts.clone();
        mutate_contract(&mut invalid[0], |manifest| {
            manifest.path = Some("/api/v2/identity/devices/{deviceId}".to_string());
        });
        assert_r25_detail(
            &rule_device_certificate_http_closure(&invalid),
            DEVICE_CERT_POLICY_PATH,
        );

        let mut invalid = contracts.clone();
        mutate_contract(&mut invalid[0], |manifest| -> anyhow::Result<()> {
            manifest
                .endpoints
                .as_mut()
                .and_then(|endpoints| endpoints.http.as_mut())
                .context("R25 policy endpoint fixture")?
                .resource = Some("tenantId".to_string());
            Ok(())
        })?;
        assert_r25_detail(
            &rule_device_certificate_http_closure(&invalid),
            "resource=deviceId",
        );

        // 合法但更宽的已登记权限也必须失败，防止仅做“属于目录”校验。
        let mut invalid = contracts.clone();
        mutate_contract(&mut invalid[0], |manifest| -> anyhow::Result<()> {
            manifest
                .endpoints
                .as_mut()
                .and_then(|endpoints| endpoints.http.as_mut())
                .and_then(|http| http.auth.as_mut())
                .context("R25 policy auth fixture")?
                .permission = Some("identity:policy:deactivate".to_string());
            Ok(())
        })?;
        assert_r25_detail(
            &rule_device_certificate_http_closure(&invalid),
            DEVICE_CERT_POLICY_PERMISSION,
        );

        let mut invalid = contracts.clone();
        mutate_contract(&mut invalid[0], |manifest| -> anyhow::Result<()> {
            let http = manifest
                .endpoints
                .as_mut()
                .and_then(|endpoints| endpoints.http.as_mut())
                .context("R25 policy endpoint fixture")?;
            http.success_status = 201;
            http.idempotency = HttpIdempotency::NonIdempotent;
            Ok(())
        })?;
        let findings = rule_device_certificate_http_closure(&invalid);
        assert_r25_detail(&findings, "successStatus=200");
        assert_r25_detail(&findings, "idempotency=idempotent");

        std::fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn r25_device_certificate_policy_requires_exact_l4_metadata() -> anyhow::Result<()> {
        let (contracts, root) = device_certificate_http_pair(Lifecycle::Draft)?;

        let mut invalid = contracts.clone();
        mutate_contract(&mut invalid[0], |manifest| {
            manifest.capabilities.device_latent = None;
        });
        assert_r25_detail(
            &rule_device_certificate_http_closure(&invalid),
            "capabilities.deviceLatent",
        );

        for (field, expected) in [
            ("command", R25_COMMAND_ID),
            ("ackEvent", R25_ACK_EVENT_ID),
            ("reportedEvent", R25_REPORTED_EVENT_ID),
            ("ingressReceiptEvent", R25_INGRESS_RECEIPT_EVENT_ID),
        ] {
            let mut invalid = contracts.clone();
            mutate_contract(&mut invalid[0], |manifest| -> anyhow::Result<()> {
                let profile = &mut manifest
                    .capabilities
                    .device_latent
                    .as_mut()
                    .context("R25 DeviceLatent fixture")?
                    .profile;
                let DeviceLatentProfile::DeviceCertificate { links } = profile;
                match field {
                    "command" => links.command = "identity.wrong-command".to_string(),
                    "ackEvent" => links.ack_event = "identity.wrong-ack".to_string(),
                    "reportedEvent" => links.reported_event = "identity.wrong-report".to_string(),
                    "ingressReceiptEvent" => {
                        links.ingress_receipt_event = "identity.wrong-receipt".to_string()
                    }
                    _ => anyhow::bail!("closed R25 link field `{field}` escaped"),
                }
                Ok(())
            })?;
            assert_r25_detail(&rule_device_certificate_http_closure(&invalid), expected);
        }

        let mut invalid = contracts.clone();
        mutate_contract(&mut invalid[0], |manifest| {
            manifest.reconcile = None;
        });
        assert_r25_detail(
            &rule_device_certificate_http_closure(&invalid),
            "[reconcile]",
        );

        let mut invalid = contracts.clone();
        mutate_contract(&mut invalid[0], |manifest| -> anyhow::Result<()> {
            manifest
                .reconcile
                .as_mut()
                .context("R25 reconcile fixture")?
                .tenancy = DeviceLatentTenancy::SingleTenant;
            Ok(())
        })?;
        assert_r25_detail(
            &rule_device_certificate_http_closure(&invalid),
            "tenancy=tenant-scoped",
        );

        std::fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn r25_device_certificate_status_route_auth_and_consistency_are_exact() -> anyhow::Result<()> {
        let (contracts, root) = device_certificate_http_pair(Lifecycle::Draft)?;

        let mut invalid = contracts.clone();
        mutate_contract(&mut invalid[1], |manifest| {
            manifest.consistency_level = ConsistencyLevel::DeviceLatent;
        });
        assert_r25_detail(
            &rule_device_certificate_http_closure(&invalid),
            "consistencyLevel=LocalOnly",
        );

        let mut invalid = contracts.clone();
        mutate_contract(&mut invalid[1], |manifest| {
            manifest.method = Some(HttpMethod::Put);
        });
        assert_r25_detail(
            &rule_device_certificate_http_closure(&invalid),
            "method=GET",
        );

        let mut invalid = contracts.clone();
        mutate_contract(&mut invalid[1], |manifest| {
            manifest.path = Some("/api/v2/identity/devices/{deviceId}".to_string());
        });
        assert_r25_detail(
            &rule_device_certificate_http_closure(&invalid),
            DEVICE_CERT_STATUS_PATH,
        );

        let mut invalid = contracts.clone();
        mutate_contract(&mut invalid[1], |manifest| -> anyhow::Result<()> {
            manifest
                .endpoints
                .as_mut()
                .and_then(|endpoints| endpoints.http.as_mut())
                .and_then(|http| http.auth.as_mut())
                .context("R25 status auth fixture")?
                .permission = Some("identity:policy:read".to_string());
            Ok(())
        })?;
        assert_r25_detail(
            &rule_device_certificate_http_closure(&invalid),
            DEVICE_CERT_STATUS_PERMISSION,
        );

        let mut invalid = contracts.clone();
        mutate_contract(&mut invalid[1], |manifest| -> anyhow::Result<()> {
            let http = manifest
                .endpoints
                .as_mut()
                .and_then(|endpoints| endpoints.http.as_mut())
                .context("R25 status endpoint fixture")?;
            http.resource = Some("tenantId".to_string());
            http.success_status = 204;
            http.idempotency = HttpIdempotency::NonIdempotent;
            Ok(())
        })?;
        let findings = rule_device_certificate_http_closure(&invalid);
        assert_r25_detail(&findings, "resource=deviceId");
        assert_r25_detail(&findings, "successStatus=200");
        assert_r25_detail(&findings, "idempotency=idempotent");

        std::fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn r25_device_certificate_links_validate_present_targets_for_draft() -> anyhow::Result<()> {
        let (mut contracts, root) = device_certificate_http_pair(Lifecycle::Draft)?;
        contracts.push(device_certificate_target(
            "identity.apply-device-certificate",
            ContractKind::Event,
            Lifecycle::Draft,
        )?);
        assert_r25_detail(
            &rule_device_certificate_http_closure(&contracts),
            "identity.apply-device-certificate 必须 kind=command",
        );

        contracts.pop();
        let mut wrong_consistency = device_certificate_target(
            "identity.device-command-acked",
            ContractKind::Event,
            Lifecycle::Draft,
        )?;
        mutate_contract(&mut wrong_consistency, |manifest| {
            manifest.consistency_level = ConsistencyLevel::LocalOnly;
        });
        contracts.push(wrong_consistency);
        assert_r25_detail(
            &rule_device_certificate_http_closure(&contracts),
            "identity.device-command-acked 必须 consistencyLevel=OutboxFact",
        );

        std::fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn r25_present_link_target_reports_target_and_requires_identity_ownership() -> anyhow::Result<()>
    {
        let (mut contracts, root) = device_certificate_http_pair(Lifecycle::Draft)?;
        let mut target =
            device_certificate_target(R25_COMMAND_ID, ContractKind::Command, Lifecycle::Draft)?;
        let target_subject = contract_label(&target);
        mutate_contract(&mut target, |manifest| {
            manifest.domain = "settings".to_string();
        });
        contracts.push(target);
        let findings = rule_device_certificate_http_closure(&contracts);
        assert_r25_subject_detail(&findings, &target_subject, "source contract id=");
        assert_r25_subject_detail(&findings, &target_subject, "target domain=identity");

        contracts.pop();
        let mut target =
            device_certificate_target(R25_COMMAND_ID, ContractKind::Command, Lifecycle::Draft)?;
        let target_subject = contract_label(&target);
        mutate_contract(&mut target, |manifest| {
            manifest.test_set_domain_owner("settings");
        });
        contracts.push(target);
        assert_r25_subject_detail(
            &rule_device_certificate_http_closure(&contracts),
            &target_subject,
            "target owner=identity",
        );

        std::fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn r25_draft_missing_link_target_stays_on_source_subject() -> anyhow::Result<()> {
        let (contracts, root) = device_certificate_http_pair(Lifecycle::Draft)?;
        let source_subject = contract_label(&contracts[0]);
        assert_r25_subject_detail(
            &rule_device_certificate_http_closure(&contracts),
            &source_subject,
            "linked target id=identity.apply-device-certificate 必须存在",
        );
        std::fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn r25_device_certificate_resource_rejects_distinct_alias_carrier() -> anyhow::Result<()> {
        let (mut contracts, root) = device_certificate_http_pair(Lifecycle::Draft)?;
        let mut alias = contracts[0].clone();
        mutate_contract(&mut alias, |manifest| {
            manifest.id = "identity.device-certificate-policy-alias".to_string();
        });
        set_contract_path(
            &mut alias,
            "http",
            "identity",
            "v2",
            Some("device-certificate-policy-alias"),
        );
        let alias_subject = contract_label(&alias);
        contracts.push(alias);

        assert_r25_subject_detail(
            &rule_device_certificate_http_closure(&contracts),
            &alias_subject,
            "只允许 canonical contract id=identity.device-certificate-policy-put",
        );

        std::fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn r25_active_device_certificate_exact_set_is_rejected() -> anyhow::Result<()> {
        let (mut contracts, root) = device_certificate_http_pair(Lifecycle::Active)?;
        append_device_certificate_targets(&mut contracts, Lifecycle::Active)?;
        assert_r25_detail(
            &rule_device_certificate_http_closure(&contracts),
            "lifecycle=draft",
        );
        std::fs::remove_dir_all(root)?;
        Ok(())
    }

    // ── R13 SchemaTitle（per-contract，读 declared schema 文件）──────────────

    /// 写一个 http 契约目录（request/response schema 内容自定），返回 (RepositoryContract, dir)。
    /// 调用方负责 `remove_dir_all` 清理。
    fn http_contract_with_schemas(
        request: &str,
        response: &str,
    ) -> anyhow::Result<(RepositoryContract, PathBuf)> {
        let dir = unique_tmp("validate-title");
        std::fs::create_dir_all(&dir)?;
        std::fs::write(dir.join("request.schema.json"), request)?;
        std::fs::write(dir.join("response.schema.json"), response)?;
        let m = manifest(
            ContractKind::Http,
            ConsistencyLevel::LocalOnly,
            RawContractOwner::Framework,
            http_schemas(),
        );
        Ok((discovered(m, dir.clone()), dir))
    }

    /// 写一个 Saga 契约目录（payload + reserve generated receipt schema 内容自定），返回 (RepositoryContract, dir)。
    /// 调用方负责 `remove_dir_all` 清理。
    fn saga_contract_with_schemas(
        payload: &str,
        reserve: &str,
    ) -> anyhow::Result<(RepositoryContract, PathBuf)> {
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
                success_status: 200,
                idempotency: HttpIdempotency::Idempotent,
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
    fn r13_identical_inline_definitions_are_not_mistaken_for_components() -> anyhow::Result<()> {
        let shared = r#"{"title":"SeedEchoRequest","definitions":{"Inline":{"title":"Inline","type":"string"}}}"#;
        let response = r#"{"title":"SeedEchoResponse","definitions":{"Inline":{"title":"Inline","type":"string"}}}"#;
        let (c, dir) = http_contract_with_schemas(shared, response)?;
        let findings = rule_schema_title(&c, "x");
        let _ = std::fs::remove_dir_all(&dir);
        assert!(
            findings
                .iter()
                .any(|finding| finding.rule == Rule::SchemaTitle
                    && finding.detail.contains("Inline")
                    && finding.detail.contains("契约内重复")),
            "only resolver-proven component definitions may repeat: {findings:?}"
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
    fn r13_saga_step_receipt_missing_root_title_detected() -> anyhow::Result<()> {
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
            "saga step receiptSchema 缺 root title 须报 SchemaTitle: {findings:?}"
        );
        Ok(())
    }

    #[test]
    fn r13_saga_step_receipt_non_pascal_title_detected() -> anyhow::Result<()> {
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
            "saga step receiptSchema 非 PascalCase title 须报 SchemaTitle: {findings:?}"
        );
        Ok(())
    }

    #[test]
    fn r13_saga_step_receipt_duplicate_title_detected() -> anyhow::Result<()> {
        let (c, dir) = saga_contract_with_schemas(r#"{"title":"Dup"}"#, r#"{"title":"Dup"}"#)?;
        let findings = rule_schema_title(&c, "x");
        let _ = std::fs::remove_dir_all(&dir);
        assert!(
            findings.iter().any(|f| {
                f.rule == Rule::SchemaTitle
                    && f.detail.contains("契约内重复")
                    && f.detail.contains("reserve.schema.json")
            }),
            "saga payload + step receiptSchema 重复 title 须报 SchemaTitle: {findings:?}"
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
                RawContractOwner::Framework,
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
                RawContractOwner::Framework,
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
    fn r16_rejects_saga_step_receipt_schema_redaction_violations() -> anyhow::Result<()> {
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
            "saga step receiptSchema redaction violations must be checked: {findings:?}"
        );
        Ok(())
    }

    #[test]
    fn r27_identity_abac_operator_ssot_rejects_inline_and_accepts_exact_ref() -> anyhow::Result<()>
    {
        fn policy_contract(
            dir: &std::path::Path,
            operator: serde_json::Value,
            slug: &str,
            nested_in_rules: bool,
            lifecycle: Lifecycle,
        ) -> anyhow::Result<RepositoryContract> {
            let uses_component = operator.get("$ref").and_then(serde_json::Value::as_str)
                == Some(IDENTITY_ABAC_OPERATOR_COMPONENT);
            let properties = if nested_in_rules {
                serde_json::json!({
                    "rules": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {"operator": operator}
                        }
                    }
                })
            } else {
                serde_json::json!({"operator": operator})
            };
            std::fs::write(
                dir.join("request.schema.json"),
                serde_json::to_vec(&serde_json::json!({
                    "title": "IdentityPolicySyntheticRequest",
                    "type": "object",
                    "properties": properties
                }))?,
            )?;
            let mut manifest = manifest(
                ContractKind::Http,
                ConsistencyLevel::LocalOnly,
                RawContractOwner::Domain("identity".to_string()),
                Schemas {
                    request: Some("request.schema.json".to_string()),
                    ..Schemas::default()
                },
            );
            manifest.id = format!("identity.{slug}");
            manifest.domain = "identity".to_string();
            manifest.lifecycle = lifecycle;
            let mut builder = RepositoryContractTestBuilder::new(manifest, dir.to_path_buf())
                .path_kind("http")
                .path_domain("identity")
                .path_version("v1")
                .slug(Some(slug));
            if uses_component {
                builder = builder.component(
                    IDENTITY_ABAC_OPERATOR_COMPONENT,
                    serde_json::json!({
                        "$id": IDENTITY_ABAC_OPERATOR_COMPONENT,
                        "title": "CommonAbacOperator",
                        "type": "string"
                    }),
                );
            }
            builder.build().context("build synthetic policy contract")
        }

        let dir = unique_tmp("abac-operator-ssot");
        std::fs::create_dir_all(&dir)?;
        let inline = policy_contract(
            &dir,
            serde_json::json!({"type": "object"}),
            "policies-synthetic",
            true,
            Lifecycle::Active,
        )?;
        let inline_findings = rule_identity_abac_operator_ssot(std::slice::from_ref(&inline));
        assert!(
            inline_findings
                .iter()
                .any(|finding| finding.detail.contains("必须直接 $ref")),
            "inline operator must be rejected: {inline_findings:?}"
        );
        let referenced = policy_contract(
            &dir,
            serde_json::json!({"$ref": IDENTITY_ABAC_OPERATOR_COMPONENT}),
            "policies-synthetic",
            true,
            Lifecycle::Active,
        )?;
        assert!(
            rule_identity_abac_operator_ssot(std::slice::from_ref(&referenced)).is_empty(),
            "exact component ref is the only accepted carrier"
        );
        assert_eq!(
            rule_identity_abac_operator_ssot(&[]).len(),
            1,
            "an empty active identity consumer set must fail anti-vacuity"
        );

        let renamed = policy_contract(
            &dir,
            serde_json::json!({"$ref": IDENTITY_ABAC_OPERATOR_COMPONENT}),
            "renamed-abac",
            false,
            Lifecycle::Active,
        )?;
        assert!(
            rule_identity_abac_operator_ssot(&[renamed]).is_empty(),
            "carrier discovery must not depend on policy slug naming"
        );
        let draft_only = policy_contract(
            &dir,
            serde_json::json!({"$ref": IDENTITY_ABAC_OPERATOR_COMPONENT}),
            "draft-abac",
            false,
            Lifecycle::Draft,
        )?;
        assert_eq!(
            rule_identity_abac_operator_ssot(&[draft_only]).len(),
            1,
            "draft-only consumers must not satisfy active anti-vacuity"
        );
        std::fs::remove_dir_all(dir)?;
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
