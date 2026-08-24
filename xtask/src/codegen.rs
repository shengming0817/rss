//! 契约 schema → committed `generated/` 派生码（typify → prettyplease → rustfmt）。
//!
//! INVARIANT: CODEGEN-DRIFT-01 { level = "Medium", exec = "check", source = "code" }— committed `generated/src/**` 与 `contracts/` 的派生结果字节一致、
//! 且无孤儿文件（删契约残留）。Medium（CI 门，`cargo xtask codegen --check`）。
//! INVARIANT: EVENT-TOPOLOGY-GENERATED-01 { level = "Hard", exec = "check", source = "codegen", facet = "single-registry", golden = "generated/src/event/mod.rs", synthetic_red = "codegen::tests::event_partition_strategy_mismatch_rejected", anti_vacuity = "codegen::tests::event_glue_with_subscription_emitted" }
//! INVARIANT: COMMAND-JOURNAL-GENERATED-01 { level = "Hard", exec = "check", source = "codegen", facet = "manifest-policy", golden = "generated/src/command/mod.rs", synthetic_red = "codegen::tests::command_missing_policy_is_rejected", anti_vacuity = "codegen::tests::command_glue_with_wrappers_emitted" }
//! INVARIANT: COMMAND-FENCING-GENERATED-01 { level = "Hard", exec = "check", source = "codegen", facet = "typed-device-generation-epoch-fencing", golden = "generated/src/command/identity_v1.rs", synthetic_red = "codegen::tests::fenced_reconcile_rejects_noncanonical_schema", anti_vacuity = "codegen::tests::fenced_reconcile_command_is_schema_derived_and_seed_is_unfenced" }
//! INVARIANT: ROUTE-EVIDENCE-CODEGEN-01 { level = "Hard", exec = "check", source = "codegen", facet = "manifest-to-generated-atomic-http-route", golden = "generated/src/http/mod.rs", synthetic_red = "codegen::tests::codegen_rejects_active_http_without_effect_profile", anti_vacuity = "codegen::tests::codegen_emits_http_consistency_level_inside_route_evidence" }
//! INVARIANT: HTTP-PRODUCER-CODEGEN-01 { level = "Hard", exec = "check", source = "codegen", facet = "manifest-emits-to-generated-producer-binding", golden = "generated/src/http/mod.rs", synthetic_red = "codegen::tests::producer_codegen_rejects_duplicate_emitted_fact", anti_vacuity = "codegen::tests::codegen_emits_typed_http_producer_binding_and_closed_registry" }
//! INVARIANT: HTTP-RESPONSE-BINDING-01 { level = "Hard", exec = "check", source = "codegen", facet = "status-indexed-response-schema-to-generated-type-binding", golden = "generated/src/http/identity_v2.rs", synthetic_red = "assembly_schema::contract_manifest::tests::http_responses_are_indexed_by_status_code", anti_vacuity = "codegen::tests::codegen_binds_each_typed_http_response_to_its_status" }
//! INVARIANT: LOCAL-ONLY-RECEIPT-TARGET-01 { level = "Hard", exec = "check", source = "codegen", facet = "active-http-local-only-marker-registry", golden = "generated/src/http/mod.rs", synthetic_red = "codegen::tests::local_only_receipt_targets_exclude_non_active_and_non_local_only_http", anti_vacuity = "codegen::tests::codegen_emits_local_only_receipt_target" }
//! INVARIANT: GENERATED-TUPLE-REDACTION-01 { level = "Hard", exec = "check", source = "codegen", facet = "constrained-scalar-redaction", golden = "generated/src/http/identity_v1.rs", synthetic_red = "codegen::tests::constrained_newtypes_inherit_exact_redaction_policy", anti_vacuity = "codegen::tests::constrained_newtypes_inherit_exact_redaction_policy" }
//! INVARIANT: DEFERRED-STRING-LENGTH-VALIDATION-01 { level = "Hard", exec = "check", source = "codegen", facet = "schema-marked-transport-policy-boundary", golden = "generated/src/http/identity_v1.rs", synthetic_red = "codegen::tests::deferred_string_length_marker_rejects_other_validation_keywords", anti_vacuity = "codegen::tests::schema_marker_defers_transport_length_checks" }
//! INVARIANT: GENERATED-RUSTDOC-01 { level = "Medium", exec = "check", source = "code", synthetic_red = "codegen::tests::owned_event_and_command_seam_templates_document_public_api", anti_vacuity = "codegen::tests::command_glue_with_wrappers_emitted" }—— owned event/command templates require rustdoc on every public item, variant, accessor and associated item.
//! golden = committed 文件 diff（rust-analyzer `ensure_file_contents` 模式）；
//! anti-vacuity：注入漂移 / 孤儿文件必失（见 `#[cfg(test)]`）。
//!
//! 成形三段：typify（schema→Rust token）→ prettyplease（可读 `///` doc）→ **rustfmt**（与 `cargo fmt`
//! 同一 formatter，令派生文件 rustfmt-canonical，杜绝 `cargo fmt --all` 重排造成漂移）。rustfmt.toml
//! `ignore` 仅 nightly、`#![rustfmt::skip]` 内属性 stable 编不过，故走 rustfmt-as-formatter 守边界。
//!
//! ref: typify typify-impl/src/lib.rs@0.7.0（TypeSpace::new/add_root_schema/to_stream）
//! ref: rust-analyzer xtask/src/codegen.rs@master（ensure_file_contents 漂移门）

use anyhow::{Context, Result, bail};
use schemars::schema::RootSchema;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use typify::{TypeSpace, TypeSpaceSettings};

use crate::contract::governance::ContractGovernanceIr;
use crate::contract::manifest::{
    CommandJournalPolicy, CommandReconcileFencing, ConsistencyLevel, ContractKind, EffectKind,
    ExternalEffectPolicy, HttpAuthMode, HttpHeaderMode, HttpIdempotency, HttpMethod,
    HttpResourceSharingMode, Lifecycle, LocalTxBoundary, LocalTxCommitUnknown, LocalTxModel,
    LocalTxRetry, OutboxRole, SagaBackoff, SagaJitter, SagaRetryClass, SubscriptionEffect,
    SubscriptionExecution,
};
use crate::contract::protection::{self, AadDim, AtRest, ProtectionMode, StructProtectionPolicies};
use crate::contract::redaction::{self, FieldPolicy, PiiKind, Sensitivity, StructPolicies};
use crate::contract::{
    DeviceCertificateCandidateId, GovernedContract, TENANT_SCOPE_SOURCE_RULE,
    schema_declares_property,
};
use crate::pathsafe;
use assembly_schema::repository_contract::validate_schema_filename;

/// 入口：生成（`check=false`）或校验漂移（`check=true`）真实仓的 committed 派生码。
pub(crate) fn run(check: bool) -> Result<()> {
    let root = crate::workspace_root()?;
    run_root(&root, check)
}

fn run_root(root: &Path, check: bool) -> Result<()> {
    let governance = ContractGovernanceIr::load_consumer_workspace(root)?;
    let fixture_governance = ContractGovernanceIr::load_codegen_fixture_root(
        &root.join("crates/testkit/fixtures/contracts"),
    )?;
    let mut transaction = governance.read(|contracts| {
        fixture_governance.read(|fixtures| plan_codegen_transaction(root, contracts, fixtures))
    })?;
    if check {
        return transaction.check();
    }
    let result = governance.commit(|| transaction.apply());
    if let Err(error) = result {
        transaction.rollback().with_context(|| {
            format!("codegen failed and rollback could not restore every output; original error: {error:#}")
        })?;
        return Err(error);
    }
    Ok(())
}

const CONTRACT_RULE_DOCS_BEGIN: &str = "<!-- @generated:contract-governance:start -->";
const CONTRACT_RULE_DOCS_END: &str = "<!-- @generated:contract-governance:end -->";

fn render_projected_contract_rule_docs(root: &Path) -> Result<String> {
    let path = root.join("contracts/README.md");
    let current =
        std::fs::read_to_string(&path).with_context(|| format!("读取 {}", path.display()))?;
    let begin = current
        .find(CONTRACT_RULE_DOCS_BEGIN)
        .context("contracts/README.md 缺 contract governance generated begin marker")?;
    let end_offset = current[begin..]
        .find(CONTRACT_RULE_DOCS_END)
        .context("contracts/README.md 缺 contract governance generated end marker")?;
    let end = begin + end_offset + CONTRACT_RULE_DOCS_END.len();
    let generated = crate::contract::governance::render_rule_docs();
    let replacement = format!("{CONTRACT_RULE_DOCS_BEGIN}\n{generated}{CONTRACT_RULE_DOCS_END}");
    let mut next = String::with_capacity(current.len() + replacement.len());
    next.push_str(&current[..begin]);
    next.push_str(&replacement);
    next.push_str(&current[end..]);
    Ok(next)
}

#[derive(Debug)]
struct PlannedOutput {
    path: PathBuf,
    original: Option<Vec<u8>>,
    expected: Option<Vec<u8>>,
}

#[derive(Debug)]
struct CodegenTransaction {
    outputs: Vec<PlannedOutput>,
    touched: Vec<usize>,
}

impl CodegenTransaction {
    fn check(&self) -> Result<()> {
        let drift = self
            .outputs
            .iter()
            .filter(|output| output.original != output.expected)
            .collect::<Vec<_>>();
        if drift.is_empty() {
            return Ok(());
        }
        for output in &drift {
            eprintln!("  派生漂移: {}", output.path.display());
        }
        bail!(
            "派生漂移：{} 个 contract-governed 输出不一致；运行 `cargo xtask codegen`",
            drift.len()
        )
    }

    fn apply(&mut self) -> Result<()> {
        self.apply_with_hook(|_, _| Ok(()))
    }

    fn apply_with_hook(
        &mut self,
        mut before_output: impl FnMut(usize, &Path) -> Result<()>,
    ) -> Result<()> {
        for output in &self.outputs {
            let current = read_optional_bytes(&output.path)?;
            if current != output.original {
                bail!(
                    "codegen output changed after planning: {}",
                    output.path.display()
                );
            }
        }
        for (index, output) in self.outputs.iter().enumerate() {
            if output.original == output.expected {
                continue;
            }
            before_output(index, &output.path)?;
            match &output.expected {
                Some(content) => {
                    crate::generated_file::atomic_replace(&output.path, content)
                        .with_context(|| format!("原子写入 {} 失败", output.path.display()))?;
                    eprintln!("  regenerated {}", output.path.display());
                }
                None => {
                    let metadata = std::fs::symlink_metadata(&output.path)
                        .with_context(|| format!("检查孤儿 {}", output.path.display()))?;
                    if metadata.file_type().is_symlink() || !metadata.is_file() {
                        bail!(
                            "codegen orphan must be a real file: {}",
                            output.path.display()
                        );
                    }
                    std::fs::remove_file(&output.path)
                        .with_context(|| format!("删除孤儿 {}", output.path.display()))?;
                    eprintln!("  removed orphan {}", output.path.display());
                }
            }
            self.touched.push(index);
        }
        Ok(())
    }

    fn rollback(&mut self) -> Result<()> {
        let mut failures = Vec::new();
        for index in self.touched.drain(..).rev() {
            let output = &self.outputs[index];
            let restore = match &output.original {
                Some(content) => crate::generated_file::atomic_replace(&output.path, content),
                None => match std::fs::remove_file(&output.path) {
                    Ok(()) => Ok(()),
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
                    Err(error) => Err(error.into()),
                },
            };
            if let Err(error) = restore {
                failures.push(format!("{}: {error:#}", output.path.display()));
            }
        }
        if failures.is_empty() {
            Ok(())
        } else {
            bail!("codegen rollback failures:\n{}", failures.join("\n"))
        }
    }
}

fn plan_codegen_transaction(
    root: &Path,
    contracts: &[GovernedContract],
    saga_test_fixtures: &[GovernedContract],
) -> Result<CodegenTransaction> {
    let gen_src = root.join("generated/src");
    let rendered = render_all(contracts)?;
    let mut outputs = Vec::new();
    let mut expected_paths = BTreeSet::new();
    for (relative, source) in rendered {
        let path = gen_src.join(relative);
        let content = normalize(&format_rust(&source)?).into_bytes();
        expected_paths.insert(path.clone());
        outputs.push(planned_output(path, Some(content))?);
    }
    for (relative, source) in render_saga_test_support(saga_test_fixtures)? {
        let path = gen_src.join(relative);
        let content = normalize(&format_rust(&source)?).into_bytes();
        expected_paths.insert(path.clone());
        outputs.push(planned_output(path, Some(content))?);
    }

    let mut actual = Vec::new();
    collect_rs_files(&gen_src, &mut actual)?;
    actual.sort();
    for orphan in actual
        .into_iter()
        .filter(|path| !expected_paths.contains(path))
    {
        outputs.push(planned_output(orphan, None)?);
    }

    let inventory = normalize(&format_rust(&render_migration_projection_inputs(
        contracts,
    )?)?)
    .into_bytes();
    outputs.push(planned_output(
        root.join("crates/postgres-migration-inventory/src/projection_inputs.rs"),
        Some(inventory),
    )?);
    outputs.push(planned_output(
        root.join("contracts/README.md"),
        Some(normalize(&render_projected_contract_rule_docs(root)?).into_bytes()),
    )?);

    let public_root = root.join("crates/devicesecuritycontracts");
    let public = render_public_device_security_contracts(contracts)?;
    let mut public_expected = BTreeSet::new();
    for (relative, source) in public.rust {
        let path = public_root.join(relative);
        let content = normalize(&format_rust(&source)?).into_bytes();
        public_expected.insert(path.clone());
        outputs.push(planned_output(path, Some(content))?);
    }
    for (relative, bytes) in public.schemas {
        let path = public_root.join(relative);
        public_expected.insert(path.clone());
        outputs.push(planned_output(path, Some(bytes))?);
    }
    let mut public_actual = Vec::new();
    collect_rs_files(&public_root.join("src"), &mut public_actual)?;
    collect_regular_files(&public_root.join("schema"), &mut public_actual)?;
    public_actual.sort();
    for orphan in public_actual
        .into_iter()
        .filter(|path| !public_expected.contains(path))
    {
        outputs.push(planned_output(orphan, None)?);
    }

    let mut unique = BTreeSet::new();
    for output in &outputs {
        if !unique.insert(output.path.clone()) {
            bail!(
                "codegen planned duplicate output: {}",
                output.path.display()
            );
        }
    }
    outputs.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(CodegenTransaction {
        outputs,
        touched: Vec::new(),
    })
}

/// Project the exact framework-owned active HTTP contract set into the publishable façade.
///
/// The experimental release accepts one reviewed schema shape. A canonical manifest/schema change
/// fails closed until its deterministic façade projection is deliberately approved in the same PR.
fn planned_output(path: PathBuf, expected: Option<Vec<u8>>) -> Result<PlannedOutput> {
    let original = read_optional_bytes(&path)?;
    Ok(PlannedOutput {
        path,
        original,
        expected,
    })
}

fn read_optional_bytes(path: &Path) -> Result<Option<Vec<u8>>> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("读取 {}", path.display())),
    }
}

/// 把 `contracts_root` 派生进 `gen_src`。根可注入便于测试。
#[cfg(test)]
pub(crate) fn generate(contracts_root: &Path, gen_src: &Path, check: bool) -> Result<()> {
    let governance = ContractGovernanceIr::load_test_fixture_root(contracts_root)?;
    governance.read(|contracts| generate_contracts(contracts, gen_src, check))
}

#[cfg(test)]
fn load_contract_fixtures(contracts_root: &Path) -> Result<Vec<GovernedContract>> {
    let governance = ContractGovernanceIr::load_test_fixture_root(contracts_root)?;
    governance.read(|contracts| Ok(contracts.to_vec()))
}

#[cfg(test)]
fn generate_contracts(contracts: &[GovernedContract], gen_src: &Path, check: bool) -> Result<()> {
    let files = render_all_with_device_certificate_requirement(contracts, false)?;
    for (rel, code) in &files {
        let formatted = format_rust(code)?; // rustfmt-canonical（同 cargo fmt），见模块 doc
        ensure_file_contents(&gen_src.join(rel), &formatted, check)?;
    }
    let expected: BTreeSet<PathBuf> = files.iter().map(|(rel, _)| gen_src.join(rel)).collect();
    reconcile_orphans(gen_src, &expected, check)?;
    Ok(())
}

/// mod.rs 特化档：event kind 注入 `SubscriptionSpec` POD，command kind 注入 `CommandEmit`/`CommandRegister`
/// seam，saga kind 注入 `SagaSpec` POD；projection 只生成 definition binding，不注入 HTTP/DTO seam。
/// 同一 `kind_dir` 内所有契约同 kind，故每 kind_dir 单一 `ModKind`。
#[derive(Clone, Copy, PartialEq, Eq)]
enum ModKind {
    Http,
    Event,
    Command,
    Saga,
    Projection,
}

/// Closed set of generated Rust items that governance carriers may name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GeneratedItem {
    Contract,
    Spec,
    Producer,
}

impl GeneratedItem {
    const fn ident(self) -> &'static str {
        match self {
            Self::Contract => "CONTRACT",
            Self::Spec => "SPEC",
            Self::Producer => "PRODUCER",
        }
    }
}

/// One exact generated-file/symbol carrier projected with the same naming functions as codegen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GeneratedItemProjection {
    pub(crate) repo_path: String,
    pub(crate) symbol: String,
}

/// Typed generated module projection; callers cannot independently author path and FQN strings.
#[derive(Debug, Clone)]
pub(crate) struct GeneratedCarrier {
    repo_path: String,
    module_path: String,
    kind: ContractKind,
    lifecycle: Lifecycle,
    is_http_producer: bool,
}

impl GeneratedCarrier {
    pub(crate) fn from_contract(contract: &GovernedContract) -> Result<Self> {
        let manifest = contract.manifest();
        let kind = manifest.kind;
        let kind_dir = kind.as_dir();
        let module = module_name(&manifest.domain, &manifest.version);
        if pathsafe::is_unsafe_segment(&module) {
            bail!("generated carrier module is unsafe: {module}");
        }
        let mut module_path = format!("generated::{kind_dir}::{module}");
        if let Some(slug) = contract.slug() {
            module_path.push_str("::");
            module_path.push_str(&slug_module_ident(slug)?);
        }
        Ok(Self {
            repo_path: format!("generated/src/{kind_dir}/{module}.rs"),
            module_path,
            kind,
            lifecycle: manifest.lifecycle,
            is_http_producer: kind == ContractKind::Http
                && manifest.lifecycle == Lifecycle::Active
                && manifest.consistency_level == ConsistencyLevel::OutboxFact
                && manifest
                    .capabilities
                    .outbox
                    .as_ref()
                    .is_some_and(|outbox| outbox.role == OutboxRole::Producer),
        })
    }

    /// Canonical generated HTTP module key used by runtime/source assurance joins.
    pub(crate) fn route_key(&self) -> Result<&str> {
        if self.kind != ContractKind::Http {
            bail!("only HTTP contracts have a generated route key");
        }
        self.module_path
            .strip_prefix("generated::http::")
            .context("generated HTTP module path lost its canonical prefix")
    }

    pub(crate) fn item(&self, item: GeneratedItem) -> Result<GeneratedItemProjection> {
        match item {
            GeneratedItem::Contract => {}
            GeneratedItem::Spec => {
                if self.kind == ContractKind::Http && self.lifecycle != Lifecycle::Active {
                    bail!("inactive HTTP contract has no generated SPEC");
                }
            }
            GeneratedItem::Producer => {
                if !self.is_http_producer {
                    bail!("only active OutboxFact HTTP producers have generated PRODUCER");
                }
            }
        }
        Ok(GeneratedItemProjection {
            repo_path: self.repo_path.clone(),
            symbol: format!("{}::{}", self.module_path, item.ident()),
        })
    }
}

/// 渲染全部期望文件（相对 `generated/src` 的路径 → 内容），确定性排序。
///
/// 同 `{kind}/{domain}/{version}` 的全部契约聚合进**一个** `{domain}_{version}.rs`（module）。两形态：
/// - **扁平**（单契约，`slug=None`）：裸顶层常量（与历史输出字节一致，不迁移其它域）。
/// - **嵌套**（多契约，`slug=Some`）：每契约一个 `pub mod <slug_ident> { payload + glue }`，glue 内 POD
///   引用（`SubscriptionSpec`/`HttpSpec`/`CommandEmit` 等，定义在 `{kind}/mod.rs`）路径深一级 → `super::super::`。
///
/// 扁平 / 嵌套不可混用（同 module 既裸常量又子模块语义二义）；validate R21 守 authoring 面，此处 codegen
/// 自守（独立于 validate 运行）。
fn render_all(contracts: &[GovernedContract]) -> Result<Vec<(PathBuf, String)>> {
    render_all_with_device_certificate_requirement(contracts, true)
}

fn render_all_with_device_certificate_requirement(
    contracts: &[GovernedContract],
    require_device_certificate: bool,
) -> Result<Vec<(PathBuf, String)>> {
    let mut files: Vec<(PathBuf, String)> = Vec::new();
    // group: (kind_dir, module) → (mod_kind, 同 module 的契约切片)。BTreeMap 保确定性序。
    let mut groups: BTreeMap<(String, String), (ModKind, Vec<&GovernedContract>)> = BTreeMap::new();
    // kinds: kind_dir → (modules, mod_kind) ——event/command kind 需在 mod.rs 特化加 POD / seam 定义。
    let mut kinds: BTreeMap<String, (BTreeSet<String>, ModKind)> = BTreeMap::new();
    for c in contracts {
        if (c.manifest().kind == ContractKind::Command) != c.manifest().command.is_some() {
            bail!(
                "契约 {}/{}/{} 的 [command] block 与 kind 不匹配（codegen fail-closed）",
                c.manifest().kind.as_dir(),
                c.manifest().domain,
                c.manifest().version
            );
        }
        let kind_dir = c.manifest().kind.as_dir().to_string();
        let module = module_name(&c.manifest().domain, &c.manifest().version);
        // 防御性安全校验：domain/version 派生的 module 名须为纯路径段，防 `../` 逃逸。
        // codegen 可独立于 `contract validate` 运行，故不能依赖 R3/R7 已先收口字段——自守。
        if pathsafe::is_unsafe_segment(&module) {
            bail!(
                "契约 {}/{}/{} 派生 module 名含路径分量（防逃逸）: {module}",
                kind_dir,
                c.manifest().domain,
                c.manifest().version
            );
        }
        let mod_kind = match c.manifest().kind {
            ContractKind::Http => ModKind::Http,
            ContractKind::Event => ModKind::Event,
            ContractKind::Command => ModKind::Command,
            ContractKind::Saga => ModKind::Saga,
            ContractKind::Projection => ModKind::Projection,
        };
        groups
            .entry((kind_dir.clone(), module.clone()))
            .or_insert_with(|| (mod_kind, Vec::new()))
            .1
            .push(c);
        let entry = kinds
            .entry(kind_dir)
            .or_insert_with(|| (BTreeSet::new(), mod_kind));
        entry.0.insert(module);
        entry.1 = mod_kind; // 同 kind_dir 内所有契约同 kind
    }
    for ((kind_dir, module), (_mod_kind, group)) in &groups {
        let rel = PathBuf::from(kind_dir).join(format!("{module}.rs"));
        files.push((rel, render_module_file(group, contracts, "contracts")?));
    }
    for (kind_dir, (modules, mod_kind)) in &kinds {
        let mut mod_rs = render_mod_rs(modules, *mod_kind);
        if *mod_kind == ModKind::Http {
            mod_rs.push_str(&render_http_root_specs(contracts)?);
        }
        if *mod_kind == ModKind::Event {
            mod_rs.push_str(&render_event_dispatch_keys(contracts)?);
            mod_rs.push_str(&render_event_root_subscriptions(contracts)?);
            mod_rs.push_str(&render_event_root_projection_definitions(contracts)?);
            mod_rs.push_str(&render_event_root_projection_inputs(contracts)?);
            mod_rs.push_str(&render_event_root_producer_domains(contracts)?);
        }
        if *mod_kind == ModKind::Saga {
            mod_rs.push_str(&render_saga_root_specs(
                contracts,
                SagaCatalogKind::Production,
            )?);
            mod_rs.push_str(
                "\n#[cfg(feature = \"test-support\")]\n/// Sealed test-only Saga definitions generated from the testkit fixture source.\npub mod test_support;\n",
            );
        }
        files.push((PathBuf::from(kind_dir).join("mod.rs"), mod_rs));
    }
    let device_certificate =
        render_device_certificate_candidates(contracts, require_device_certificate)?;
    let has_device_certificate = device_certificate.is_some();
    if let Some(source) = device_certificate {
        files.push((PathBuf::from("device_certificate.rs"), source));
    }
    files.push((
        PathBuf::from("lib.rs"),
        render_lib_rs(kinds.keys(), has_device_certificate),
    ));
    Ok(files)
}

fn render_device_certificate_candidates(
    contracts: &[GovernedContract],
    required: bool,
) -> Result<Option<String>> {
    let candidate_ids = DeviceCertificateCandidateId::ALL
        .into_iter()
        .map(|candidate| candidate.spec().id)
        .collect::<BTreeSet<_>>();
    if !contracts
        .iter()
        .any(|contract| candidate_ids.contains(contract.id()))
    {
        if required {
            bail!("device-certificate candidate set is entirely missing from production codegen");
        }
        return Ok(None);
    }

    let mut entries = Vec::new();
    for candidate in DeviceCertificateCandidateId::ALL {
        let expected = candidate.spec();
        let matches = contracts
            .iter()
            .filter(|contract| contract.id() == expected.id)
            .collect::<Vec<_>>();
        let [contract] = matches.as_slice() else {
            bail!(
                "device-certificate candidate id={} must occur exactly once for codegen; found {}",
                expected.id,
                matches.len()
            );
        };
        let manifest = contract.manifest();
        let Some(source_dir) = expected.source_dir.strip_prefix("contracts/") else {
            bail!(
                "device-certificate candidate id={} sourceDir must be repository-relative",
                expected.id
            );
        };
        if manifest.kind != expected.kind
            || manifest.consistency_level != expected.consistency_level
            || manifest.lifecycle != expected.lifecycle
            || manifest.domain != "identity"
            || contract.owner().domain().map(|owner| owner.as_str()) != Some("identity")
            || !contract.dir().ends_with(source_dir)
        {
            bail!(
                "device-certificate candidate id={} metadata/source drifted from the typed catalog",
                expected.id
            );
        }
        let symbol = GeneratedCarrier::from_contract(contract)?
            .item(GeneratedItem::Contract)?
            .symbol
            .replacen("generated::", "crate::", 1);
        entries.push(format!(
            "    DeviceCertificateCandidateSpec::new({symbol}, \
             ::assembly_schema::contract_manifest::ContractKind::{kind:?}, \
             ::assembly_schema::contract_manifest::ConsistencyLevel::{consistency:?}, \
             ::assembly_schema::contract_manifest::Lifecycle::Draft),",
            kind = expected.kind,
            consistency = expected.consistency_level,
        ));
    }

    Ok(Some(format!(
        r#"//! Device-certificate draft activation candidates generated from the canonical contract set.
//!
//! This registry is governance metadata only. Draft candidates are deliberately excluded from
//! active HTTP/event registries, L2 assurance, runtime wiring, and production artifacts.

/// A non-nil, opaque authorization correlation identity shared by the generated Draft carriers.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, ::secure::Redact)]
pub struct AuthorizationReceiptId(
    #[redact(sensitivity = internal)]
    ::uuid::Uuid,
);

/// A generated authorization receipt identity was nil or malformed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthorizationReceiptIdError;

impl ::std::fmt::Display for AuthorizationReceiptIdError {{
    fn fmt(&self, formatter: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {{
        formatter.write_str("authorization receipt identity is invalid")
    }}
}}

impl ::std::error::Error for AuthorizationReceiptIdError {{}}

impl AuthorizationReceiptId {{
    /// Restore a non-nil correlation identity at a trusted boundary.
    pub fn try_from_uuid(value: ::uuid::Uuid) -> Result<Self, AuthorizationReceiptIdError> {{
        (!value.is_nil()).then_some(Self(value)).ok_or(AuthorizationReceiptIdError)
    }}

    /// Return the opaque UUID value. It is not an authorization capability.
    pub const fn as_uuid(self) -> ::uuid::Uuid {{ self.0 }}
}}

impl ::std::str::FromStr for AuthorizationReceiptId {{
    type Err = AuthorizationReceiptIdError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {{
        let value = ::uuid::Uuid::parse_str(value).map_err(|_| AuthorizationReceiptIdError)?;
        Self::try_from_uuid(value)
    }}
}}

impl ::std::convert::TryFrom<::uuid::Uuid> for AuthorizationReceiptId {{
    type Error = AuthorizationReceiptIdError;

    fn try_from(value: ::uuid::Uuid) -> Result<Self, Self::Error> {{
        Self::try_from_uuid(value)
    }}
}}

impl ::serde::Serialize for AuthorizationReceiptId {{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where S: ::serde::Serializer {{
        <::uuid::Uuid as ::serde::Serialize>::serialize(&self.0, serializer)
    }}
}}

impl<'de> ::serde::Deserialize<'de> for AuthorizationReceiptId {{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where D: ::serde::Deserializer<'de> {{
        let value = <::uuid::Uuid as ::serde::Deserialize>::deserialize(deserializer)?;
        Self::try_from_uuid(value).map_err(<D::Error as ::serde::de::Error>::custom)
    }}
}}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Typed governance metadata for one device-certificate Draft candidate.
pub struct DeviceCertificateCandidateSpec {{
    binding: ::vocab::ContractBinding,
    kind: ::assembly_schema::contract_manifest::ContractKind,
    consistency_level: ::assembly_schema::contract_manifest::ConsistencyLevel,
    lifecycle: ::assembly_schema::contract_manifest::Lifecycle,
}}

impl DeviceCertificateCandidateSpec {{
    const fn new(
        binding: ::vocab::ContractBinding,
        kind: ::assembly_schema::contract_manifest::ContractKind,
        consistency_level: ::assembly_schema::contract_manifest::ConsistencyLevel,
        lifecycle: ::assembly_schema::contract_manifest::Lifecycle,
    ) -> Self {{
        Self {{ binding, kind, consistency_level, lifecycle }}
    }}

    /// Return the canonical contract binding.
    pub const fn binding(self) -> ::vocab::ContractBinding {{ self.binding }}
    /// Return the governed contract kind.
    pub const fn kind(self) -> ::assembly_schema::contract_manifest::ContractKind {{ self.kind }}
    /// Return the governed consistency level.
    pub const fn consistency_level(self) -> ::assembly_schema::contract_manifest::ConsistencyLevel {{ self.consistency_level }}
    /// Return the governed lifecycle.
    pub const fn lifecycle(self) -> ::assembly_schema::contract_manifest::Lifecycle {{ self.lifecycle }}
}}

/// Exact generated projection of the six device-certificate Draft candidates.
pub const CANDIDATE_CONTRACTS: &[DeviceCertificateCandidateSpec] = &[
{}
];
"#,
        entries.join("\n")
    )))
}

struct PublicDeviceSecurityProjection {
    rust: Vec<(PathBuf, String)>,
    schemas: Vec<(PathBuf, Vec<u8>)>,
}

fn render_public_device_security_contracts(
    contracts: &[GovernedContract],
) -> Result<PublicDeviceSecurityProjection> {
    render_device_certificate_candidates(contracts, true)?;
    validate_public_authorization_receipt_shape(contracts)?;
    let mut rust = Vec::new();
    let mut schemas = Vec::new();
    let mut modules = Vec::new();
    for candidate in DeviceCertificateCandidateId::ALL {
        let spec = candidate.spec();
        let contract = contracts
            .iter()
            .find(|contract| contract.id() == spec.id)
            .with_context(|| format!("public device-security contract {} is missing", spec.id))?;
        modules.push(spec.public_module);
        rust.push((
            PathBuf::from("src").join(format!("{}.rs", spec.public_module)),
            render_public_device_security_module(contract, spec.public_module)?,
        ));
        for file in contract.manifest().declared_schema_files() {
            let schema = contract.declared_schema(file).with_context(|| {
                format!(
                    "public device-security schema {}/{} is missing",
                    spec.id, file
                )
            })?;
            schemas.push((
                PathBuf::from("schema").join(spec.public_module).join(file),
                public_schema_bytes(schema)?,
            ));
        }
    }
    rust.push((
        PathBuf::from("src/lib.rs"),
        render_public_device_security_lib(&modules),
    ));
    Ok(PublicDeviceSecurityProjection { rust, schemas })
}

fn validate_public_authorization_receipt_shape(contracts: &[GovernedContract]) -> Result<()> {
    for candidate in DeviceCertificateCandidateId::ALL {
        let spec = candidate.spec();
        let contract = contracts
            .iter()
            .find(|contract| contract.id() == spec.id)
            .with_context(|| format!("public device-security contract {} is missing", spec.id))?;
        let mut property_count = 0;
        for file in contract.manifest().declared_schema_files() {
            let schema = contract.declared_schema(file).with_context(|| {
                format!(
                    "public device-security schema {}/{} is missing",
                    spec.id, file
                )
            })?;
            let authored = schema.authored();
            let before = property_count;
            validate_authorization_receipt_document(spec.id, file, authored, &mut property_count)?;
            if property_count > before {
                validate_authorization_receipt_component(spec.id, file, schema.resolved().value())?;
            }
        }
        validate_authorization_receipt_ownership(
            spec.id,
            spec.carries_authorization_lineage,
            property_count,
        )?;
    }
    Ok(())
}

fn validate_authorization_receipt_component(
    contract_id: &str,
    file: &str,
    resolved: &serde_json::Value,
) -> Result<()> {
    let canonical = serde_json::json!({
        "title": "AuthorizationReceiptId",
        "type": "string",
        "format": "uuid",
        "x-redaction": "internal",
        "not": {"const": "00000000-0000-0000-0000-000000000000"}
    });
    if resolved.pointer("/definitions/AuthorizationReceiptId") != Some(&canonical) {
        bail!("public authorization receipt component diverged in {contract_id}/{file}");
    }
    Ok(())
}

fn validate_authorization_receipt_ownership(
    contract_id: &str,
    expected_lineage: bool,
    property_count: usize,
) -> Result<()> {
    if expected_lineage != (property_count > 0) {
        bail!(
            "public authorization receipt ownership diverged for {contract_id}: expected_lineage={expected_lineage} properties={property_count}"
        );
    }
    Ok(())
}

fn validate_authorization_receipt_document(
    contract_id: &str,
    file: &str,
    authored: &serde_json::Value,
    property_count: &mut usize,
) -> Result<()> {
    let canonical_property = serde_json::json!({
        "$ref": "rss://component/identity/v1/authorization-receipt-id",
        "x-redaction": "internal"
    });
    visit_named_json_property(authored, "authorizationReceiptId", &mut |property| {
        *property_count += 1;
        if property != &canonical_property {
            bail!("public authorization receipt property diverged in {contract_id}/{file}");
        }
        Ok(())
    })
}

fn visit_named_json_property(
    value: &serde_json::Value,
    name: &str,
    visitor: &mut impl FnMut(&serde_json::Value) -> Result<()>,
) -> Result<()> {
    match value {
        serde_json::Value::Object(object) => {
            if let Some(property) = object.get("properties").and_then(|value| value.get(name)) {
                visitor(property)?;
            }
            for child in object.values() {
                visit_named_json_property(child, name, visitor)?;
            }
        }
        serde_json::Value::Array(items) => {
            for child in items {
                visit_named_json_property(child, name, visitor)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn render_public_device_security_module(
    contract: &GovernedContract,
    module: &str,
) -> Result<String> {
    let mut settings = TypeSpaceSettings::default();
    settings.with_struct_builder(false);
    settings.with_replacement(
        "AuthorizationReceiptId",
        "crate::AuthorizationReceiptId",
        std::iter::empty::<typify::TypeSpaceImpl>(),
    );
    let mut space = TypeSpace::new(&settings);
    let mut shared_definitions = BTreeMap::new();
    let mut roots = Vec::new();
    for file in contract.manifest().declared_schema_files() {
        let schema = contract.declared_schema(file).with_context(|| {
            format!(
                "public device-security schema {}/{} is missing",
                contract.id(),
                file
            )
        })?;
        let mut root: RootSchema = serde_json::from_value(schema.resolved().value().clone())
            .with_context(|| {
                format!(
                    "parse public device-security schema {}/{}",
                    contract.id(),
                    file
                )
            })?;
        for (name, definition) in std::mem::take(&mut root.definitions) {
            if let Some(existing) = shared_definitions.get(&name) {
                if existing != &definition {
                    bail!(
                        "public device-security definition {name:?} conflicts in {}",
                        contract.id()
                    );
                }
            } else {
                shared_definitions.insert(name, definition);
            }
        }
        roots.push((file.to_owned(), root));
    }
    space.add_ref_types(shared_definitions).map_err(|error| {
        anyhow::anyhow!("derive public definitions for {}: {error}", contract.id())
    })?;
    for (file, root) in roots {
        space.add_root_schema(root).map_err(|error| {
            anyhow::anyhow!("derive public schema {}/{}: {error}", contract.id(), file)
        })?;
    }
    let mut parsed = syn::parse2::<syn::File>(space.to_stream())
        .with_context(|| format!("parse public DTO tokens for {}", contract.id()))?;
    remove_debug_derives(&mut parsed);
    if module == "policy_put" {
        privatize_struct_fields(
            &mut parsed,
            &[
                "IdentityDeviceCertificatePolicyPutPolicy",
                "IdentityDeviceCertificatePolicyPutRequest",
            ],
        );
        remove_deserialize_derives(
            &mut parsed,
            &[
                "IdentityDeviceCertificatePolicyPutPolicy",
                "IdentityDeviceCertificatePolicyPutRequest",
            ],
        );
    }
    allow_derivable_default_impls(&mut parsed);
    allow_unwrap_in_defaults_mod(&mut parsed);
    allow_unwrap_in_static_regex_impls(&mut parsed);
    let mut dto = prettyplease::unparse(&parsed);
    if module == "policy_put" {
        dto.push_str(PUBLIC_POLICY_PUT_VALIDATION);
    }
    let mut schema_entries = Vec::new();
    for file in contract.manifest().declared_schema_files() {
        let schema = contract.declared_schema(file).with_context(|| {
            format!(
                "public device-security schema {}/{} is missing",
                contract.id(),
                file
            )
        })?;
        let role = public_schema_role(contract, file)?;
        let schema_bytes = public_schema_bytes(schema)?;
        let digest = format!("sha256:{:x}", sha2::Sha256::digest(&schema_bytes));
        schema_entries.push(format!(
            "    crate::SchemaArtifact::new({role:?}, {digest:?}, include_bytes!(\"../schema/{module}/{file}\")),",
        ));
    }
    let operation = render_public_http_operation(contract)?;
    Ok(format!(
        "//! Generated from the canonical `{id}` Draft contract. Do not edit.\n\n{dto}\n\
         /// Canonical contract identity and aggregate schema digest.\n\
         pub const DESCRIPTOR: ::rss_contract::ContractDescriptor = ::rss_contract::ContractDescriptor::from_static_version({id:?}, {version:?}, {digest:?});\n\
         {operation}\
         /// Candidate lifecycle; this package does not activate the contract.\n\
         pub const LIFECYCLE: &str = \"draft\";\n\
         /// Exact authored schema artifacts embedded in this package.\n\
         pub const SCHEMAS: &[crate::SchemaArtifact] = &[\n{}\n];\n",
        schema_entries.join("\n"),
        id = contract.id(),
        version = contract.manifest().version,
        digest = contract.schema_hash(),
    ))
}

fn render_public_http_operation(contract: &GovernedContract) -> Result<String> {
    if contract.manifest().kind != ContractKind::Http {
        return Ok(String::new());
    }
    let path = contract
        .manifest()
        .path
        .as_deref()
        .context("public HTTP contract is missing path")?;
    let method = contract
        .manifest()
        .method
        .context("public HTTP contract is missing method")?;
    if !is_safe_codegen_string(path) {
        bail!(
            "public HTTP contract {} has an unsafe path literal: {path:?}",
            contract.id()
        );
    }
    let method = match method {
        HttpMethod::Get => "Get",
        HttpMethod::Post => "Post",
        HttpMethod::Put => "Put",
        HttpMethod::Patch => "Patch",
        HttpMethod::Delete => "Delete",
    };
    Ok(format!(
        "/// Authority-free HTTP operation metadata generated from the canonical contract.\n\
         pub const OPERATION: crate::HttpOperationDescriptor = crate::HttpOperationDescriptor::new(DESCRIPTOR, crate::HttpMethod::{method}, {path:?});\n"
    ))
}

fn public_schema_bytes(
    schema: assembly_schema::repository_contract::DeclaredSchema<'_>,
) -> Result<Vec<u8>> {
    const AUTHORIZATION_RECEIPT_COMPONENT: &str =
        "rss://component/identity/v1/authorization-receipt-id";
    if !schema
        .property_references("authorizationReceiptId")
        .iter()
        .flatten()
        .any(|reference| reference == AUTHORIZATION_RECEIPT_COMPONENT)
    {
        return Ok(schema.bytes().to_vec());
    }
    let mut bytes = serde_json::to_vec_pretty(schema.resolved().value())?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn public_schema_role(contract: &GovernedContract, file: &str) -> Result<String> {
    let schemas = &contract.manifest().schemas;
    if schemas.request.as_deref() == Some(file) {
        return Ok("request".to_owned());
    }
    if schemas.response.as_deref() == Some(file) {
        return Ok("response".to_owned());
    }
    if schemas.payload.as_deref() == Some(file) {
        return Ok("payload".to_owned());
    }
    if let Some((status, _)) = schemas
        .responses
        .iter()
        .find(|(_, schema_file)| schema_file.as_str() == file)
    {
        return Ok(format!("response:{}", status.get()));
    }
    bail!(
        "public device-security schema role is not declared for {}/{}",
        contract.id(),
        file
    )
}

fn render_public_device_security_lib(modules: &[&str]) -> String {
    let module_declarations = modules
        .iter()
        .map(|module| format!("pub mod {module};"))
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        r#"#![doc = include_str!("../README.md")]

/// Opaque, authority-free correlation identity for one durable authorization decision.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AuthorizationReceiptId(::uuid::Uuid);

/// Stable, payload-free error returned for malformed or nil receipt identities.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthorizationReceiptIdError;

impl ::std::fmt::Display for AuthorizationReceiptIdError {{
    fn fmt(&self, formatter: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {{
        formatter.write_str("invalid authorization receipt id")
    }}
}}

impl ::std::error::Error for AuthorizationReceiptIdError {{}}

impl AuthorizationReceiptId {{
    /// Restore a non-nil correlation identity at a trusted boundary.
    pub fn try_from_uuid(value: ::uuid::Uuid) -> Result<Self, AuthorizationReceiptIdError> {{
        (!value.is_nil())
            .then_some(Self(value))
            .ok_or(AuthorizationReceiptIdError)
    }}

    /// Return the opaque UUID value. This value is not an authorization capability.
    #[must_use]
    pub const fn as_uuid(self) -> ::uuid::Uuid {{ self.0 }}
}}

impl ::std::fmt::Debug for AuthorizationReceiptId {{
    fn fmt(&self, formatter: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {{
        formatter.write_str("AuthorizationReceiptId(<redacted>)")
    }}
}}

impl ::std::str::FromStr for AuthorizationReceiptId {{
    type Err = AuthorizationReceiptIdError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {{
        let value = ::uuid::Uuid::parse_str(value).map_err(|_| AuthorizationReceiptIdError)?;
        Self::try_from_uuid(value)
    }}
}}

impl ::std::convert::TryFrom<::uuid::Uuid> for AuthorizationReceiptId {{
    type Error = AuthorizationReceiptIdError;

    fn try_from(value: ::uuid::Uuid) -> Result<Self, Self::Error> {{
        Self::try_from_uuid(value)
    }}
}}

impl ::serde::Serialize for AuthorizationReceiptId {{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where S: ::serde::Serializer {{
        <::uuid::Uuid as ::serde::Serialize>::serialize(&self.0, serializer)
    }}
}}

impl<'de> ::serde::Deserialize<'de> for AuthorizationReceiptId {{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where D: ::serde::Deserializer<'de> {{
        let value = <::uuid::Uuid as ::serde::Deserialize>::deserialize(deserializer)?;
        Self::try_from_uuid(value).map_err(<D::Error as ::serde::de::Error>::custom)
    }}
}}

/// Closed HTTP method vocabulary used by generated public operation descriptors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpMethod {{
    /// HTTP GET.
    Get,
    /// HTTP POST.
    Post,
    /// HTTP PUT.
    Put,
    /// HTTP PATCH.
    Patch,
    /// HTTP DELETE.
    Delete,
}}

impl HttpMethod {{
    /// Return the canonical uppercase wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {{
        match self {{
            Self::Get => "GET",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Patch => "PATCH",
            Self::Delete => "DELETE",
        }}
    }}
}}

/// Authority-free identity of one generated public HTTP operation.
///
/// This descriptor does not authorize a caller, activate a route, or prove service availability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HttpOperationDescriptor {{
    contract: ::rss_contract::ContractDescriptor,
    method: HttpMethod,
    path_template: &'static str,
}}

impl HttpOperationDescriptor {{
    pub(crate) const fn new(
        contract: ::rss_contract::ContractDescriptor,
        method: HttpMethod,
        path_template: &'static str,
    ) -> Self {{
        Self {{ contract, method, path_template }}
    }}

    /// Return the canonical contract identity bound to this operation.
    #[must_use]
    pub const fn contract(self) -> ::rss_contract::ContractDescriptor {{ self.contract }}
    /// Return the closed HTTP method bound to this operation.
    #[must_use]
    pub const fn method(self) -> HttpMethod {{ self.method }}
    /// Return the unbound origin-relative path template.
    #[must_use]
    pub const fn path_template(self) -> &'static str {{ self.path_template }}
}}

/// One standalone resolved JSON Schema artifact embedded in the candidate package.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SchemaArtifact {{
    role: &'static str,
    digest: &'static str,
    json: &'static [u8],
}}

impl SchemaArtifact {{
    pub(crate) const fn new(role: &'static str, digest: &'static str, json: &'static [u8]) -> Self {{
        Self {{ role, digest, json }}
    }}

    /// Manifest schema role such as `request`, `response`, or `payload`.
    #[must_use]
    pub const fn role(self) -> &'static str {{ self.role }}
    /// SHA-256 digest of the exact authored schema bytes.
    #[must_use]
    pub const fn digest(self) -> &'static str {{ self.digest }}
    /// Standalone resolved JSON Schema bytes.
    #[must_use]
    pub const fn json(self) -> &'static [u8] {{ self.json }}
}}

{module_declarations}
"#,
    )
}

fn remove_debug_derives(file: &mut syn::File) {
    for item in &mut file.items {
        let attrs = match item {
            syn::Item::Struct(item) => &mut item.attrs,
            syn::Item::Enum(item) => &mut item.attrs,
            _ => continue,
        };
        for attr in attrs {
            if !attr.path().is_ident("derive") {
                continue;
            }
            let Ok(paths) = attr.parse_args_with(
                syn::punctuated::Punctuated::<syn::Path, syn::Token![,]>::parse_terminated,
            ) else {
                continue;
            };
            let kept: syn::punctuated::Punctuated<syn::Path, syn::Token![,]> = paths
                .into_iter()
                .filter(|path| {
                    path.segments
                        .last()
                        .is_none_or(|segment| segment.ident != "Debug")
                })
                .collect();
            attr.meta = syn::parse_quote!(derive(#kept));
        }
    }
}

fn remove_deserialize_derives(file: &mut syn::File, struct_names: &[&str]) {
    for item in &mut file.items {
        let syn::Item::Struct(item) = item else {
            continue;
        };
        if !struct_names.iter().any(|name| item.ident == *name) {
            continue;
        }
        for attr in &mut item.attrs {
            if !attr.path().is_ident("derive") {
                continue;
            }
            let Ok(paths) = attr.parse_args_with(
                syn::punctuated::Punctuated::<syn::Path, syn::Token![,]>::parse_terminated,
            ) else {
                continue;
            };
            let kept: syn::punctuated::Punctuated<syn::Path, syn::Token![,]> = paths
                .into_iter()
                .filter(|path| {
                    path.segments
                        .last()
                        .is_none_or(|segment| segment.ident != "Deserialize")
                })
                .collect();
            attr.meta = syn::parse_quote!(derive(#kept));
        }
    }
}

fn privatize_struct_fields(file: &mut syn::File, struct_names: &[&str]) {
    for item in &mut file.items {
        let syn::Item::Struct(item) = item else {
            continue;
        };
        if struct_names.iter().any(|name| item.ident == *name) {
            for field in &mut item.fields {
                field.vis = syn::Visibility::Inherited;
            }
        }
    }
}

const PUBLIC_POLICY_PUT_VALIDATION: &str = r#"
/// Stable, payload-free policy constraint violation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PolicyConstraintError;

impl ::std::fmt::Display for PolicyConstraintError {
    fn fmt(&self, formatter: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        formatter.write_str("device certificate policy violates schema constraints")
    }
}

impl ::std::error::Error for PolicyConstraintError {}

impl IdentityDeviceCertificatePolicyPutPolicy {
    pub fn try_new(
        key_usages: Vec<IdentityDeviceCertificatePolicyPutPolicyKeyUsagesItem>,
        renew_before_seconds: i64,
        sans: Option<Vec<IdentityDeviceCertificatePolicyPutPolicySansItem>>,
        validity_seconds: i64,
    ) -> Result<Self, PolicyConstraintError> {
        if !(300..=31_536_000).contains(&validity_seconds)
            || !(60..=31_535_999).contains(&renew_before_seconds)
            || renew_before_seconds >= validity_seconds
            || key_usages.is_empty()
            || key_usages.iter().collect::<::std::collections::BTreeSet<_>>().len()
                != key_usages.len()
            || sans.as_ref().is_some_and(|sans| {
                sans.len() > 32
                    || sans.iter().collect::<::std::collections::BTreeSet<_>>().len() != sans.len()
            })
        {
            return Err(PolicyConstraintError);
        }
        Ok(Self { key_usages, renew_before_seconds, sans, validity_seconds })
    }

    pub fn key_usages(&self) -> &[IdentityDeviceCertificatePolicyPutPolicyKeyUsagesItem] {
        &self.key_usages
    }
    pub const fn renew_before_seconds(&self) -> i64 { self.renew_before_seconds }
    pub fn sans(&self) -> Option<&[IdentityDeviceCertificatePolicyPutPolicySansItem]> {
        self.sans.as_deref()
    }
    pub const fn validity_seconds(&self) -> i64 { self.validity_seconds }
}

#[derive(::serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct IdentityDeviceCertificatePolicyPutPolicyWire {
    #[serde(rename = "keyUsages")]
    key_usages: Vec<IdentityDeviceCertificatePolicyPutPolicyKeyUsagesItem>,
    #[serde(rename = "renewBeforeSeconds")]
    renew_before_seconds: i64,
    #[serde(default)]
    sans: Option<Vec<IdentityDeviceCertificatePolicyPutPolicySansItem>>,
    #[serde(rename = "validitySeconds")]
    validity_seconds: i64,
}

impl<'de> ::serde::Deserialize<'de> for IdentityDeviceCertificatePolicyPutPolicy {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where D: ::serde::Deserializer<'de> {
        let wire = <IdentityDeviceCertificatePolicyPutPolicyWire as ::serde::Deserialize>::deserialize(deserializer)?;
        Self::try_new(
            wire.key_usages,
            wire.renew_before_seconds,
            wire.sans,
            wire.validity_seconds,
        ).map_err(<D::Error as ::serde::de::Error>::custom)
    }
}

#[derive(::serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct IdentityDeviceCertificatePolicyPutRequestWire {
    #[serde(rename = "expectedGeneration")]
    expected_generation: i64,
    #[serde(rename = "idempotencyKey")]
    idempotency_key: ::uuid::Uuid,
    policy: IdentityDeviceCertificatePolicyPutPolicy,
}

impl<'de> ::serde::Deserialize<'de> for IdentityDeviceCertificatePolicyPutRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where D: ::serde::Deserializer<'de> {
        let wire = <IdentityDeviceCertificatePolicyPutRequestWire as ::serde::Deserialize>::deserialize(deserializer)?;
        Self::try_new(wire.expected_generation, wire.idempotency_key, wire.policy)
            .map_err(<D::Error as ::serde::de::Error>::custom)
    }
}

impl IdentityDeviceCertificatePolicyPutRequest {
    pub fn try_new(
        expected_generation: i64,
        idempotency_key: ::uuid::Uuid,
        policy: IdentityDeviceCertificatePolicyPutPolicy,
    ) -> Result<Self, PolicyConstraintError> {
        if expected_generation < 0 { return Err(PolicyConstraintError); }
        Ok(Self { expected_generation, idempotency_key, policy })
    }
    pub const fn expected_generation(&self) -> i64 { self.expected_generation }
    pub const fn idempotency_key(&self) -> ::uuid::Uuid { self.idempotency_key }
    pub const fn policy(&self) -> &IdentityDeviceCertificatePolicyPutPolicy { &self.policy }
}
"#;

fn render_saga_test_support(fixtures: &[GovernedContract]) -> Result<Vec<(PathBuf, String)>> {
    if fixtures
        .iter()
        .any(|fixture| fixture.manifest().kind != ContractKind::Saga)
    {
        bail!("testkit Saga fixture root may contain only Saga contracts");
    }
    let mut groups: BTreeMap<String, Vec<&GovernedContract>> = BTreeMap::new();
    for fixture in fixtures {
        groups
            .entry(module_name(
                &fixture.manifest().domain,
                &fixture.manifest().version,
            ))
            .or_default()
            .push(fixture);
    }
    let mut files = Vec::new();
    for (module, group) in &groups {
        let rendered = render_module_file(group, fixtures, "crates/testkit/fixtures/contracts")?;
        files.push((
            PathBuf::from("saga/test_support").join(format!("{module}.rs")),
            rendered,
        ));
    }
    let modules = groups
        .keys()
        .map(|module| format!("pub mod {module};"))
        .collect::<Vec<_>>()
        .join("\n");
    let specs = render_saga_root_specs(fixtures, SagaCatalogKind::TestSupport)?;
    let root = format!(
        "{}\npub(crate) use super::sealed;\npub use super::{{Definition, End, Receipt, SagaSpec, Step, StepMarker}};\n{modules}\n{specs}",
        generated_header("crates/testkit/fixtures/contracts/saga/")
    );
    files.push((PathBuf::from("saga/test_support/mod.rs"), root));
    Ok(files)
}

/// 模块名 `{domain}_{version}`（如 `_seed_v1`）。同 `{domain}_{version}` 的多契约（嵌套形态）聚合进一个
/// 模块文件，经 `pub mod <slug>` 子命名空间隔离类型名。
fn module_name(domain: &str, version: &str) -> String {
    format!("{domain}_{version}")
}

fn typify_regex_unwrap_lint(body: &str) -> &'static str {
    if body.contains("::regress::Regex") {
        "#![allow(clippy::unwrap_used)] // reason: typify emits infallible static regex initialization.\n"
    } else {
        ""
    }
}

/// 渲染一个 `{domain}_{version}.rs` 模块文件（含 1 个 `@generated` 头 + 1..N 个契约 body）。
/// 扁平（单契约 `slug=None`）→ 裸 body；嵌套（多契约 `slug=Some`）→ 每契约 `pub mod <slug_ident> { body }`。
fn render_module_file(
    group: &[&GovernedContract],
    contracts: &[GovernedContract],
    source_root: &str,
) -> Result<String> {
    let first = group
        .first()
        .context("空契约 group（codegen 不变式被破坏）")?;
    let source = format!(
        "{source_root}/{}/{}/{}/",
        first.manifest().kind.as_dir(),
        first.manifest().domain,
        first.manifest().version
    );
    let header = generated_header(&source);

    let has_flat = group.iter().any(|c| c.slug().is_none());
    let has_nested = group.iter().any(|c| c.slug().is_some());
    if has_flat && has_nested {
        bail!(
            "module {}/{} 同时含扁平（直接 contract.toml）与嵌套（<slug>/contract.toml）契约——二义（CONTRACT-NEST-EXCLUSIVE-01）",
            first.manifest().domain,
            first.manifest().version
        );
    }
    // 扁平：恰一契约，裸 body（顶层常量，POD 引用 super::）——与历史输出字节一致。
    if has_flat {
        if group.len() != 1 {
            bail!(
                "module {}/{} 扁平形态却有 {} 个契约（扁平须恰一）",
                first.manifest().domain,
                first.manifest().version,
                group.len()
            );
        }
        let body = render_contract_body(first, "super::", contracts)?;
        let generated_regex_lint = typify_regex_unwrap_lint(&body);
        return Ok(format!("{header}{generated_regex_lint}{body}"));
    }

    // 嵌套：每契约一个 `pub mod <slug_ident> { body }`，body POD 引用深一级 super::super::。
    let mut ordered: Vec<&&GovernedContract> = group.iter().collect();
    ordered.sort_by(|a, b| a.slug().cmp(&b.slug())); // 按 slug 确定性序
    let mut seen_idents: BTreeSet<String> = BTreeSet::new();
    let mut out = header;
    for c in ordered {
        let slug = c.slug().context("嵌套契约缺 slug（codegen 不变式）")?;
        let ident = slug_module_ident(slug)?;
        if !seen_idents.insert(ident.clone()) {
            bail!(
                "module {}/{} 的 slug {slug:?} 派生重复子模块名 {ident}（kebab→snake 碰撞）",
                first.manifest().domain,
                first.manifest().version
            );
        }
        let body = render_contract_body(c, "super::super::", contracts)?;
        let generated_regex_lint = typify_regex_unwrap_lint(&body);
        out.push_str(&format!(
            "\n/// 端点 `{slug}` 派生契约（源 `{slug}/contract.toml`）。由 `cargo xtask codegen` 派生；勿手改。\npub mod {ident} {{\n{generated_regex_lint}{body}\n}}\n"
        ));
    }
    Ok(out)
}

fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(char::from(HEX[usize::from(byte >> 4)]));
        out.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    out
}

/// slug（kebab）→ generated 子模块标识符（snake）。经 `syn::Ident` 收口（拒非法标识符 / raw `r#`），与
/// command request title 同款防注入闭环；R20 是 authoring 上游闸门，本守卫是 codegen 写盘前自守。
fn slug_module_ident(slug: &str) -> Result<String> {
    let ident = slug.replace('-', "_");
    if ident.starts_with("r#") || syn::parse_str::<syn::Ident>(&ident).is_err() {
        bail!("slug {slug:?} 派生非法 Rust 模块标识符 {ident:?}（防注入生成代码）");
    }
    Ok(ident)
}

/// Contract domain label → Rust enum variant. Separator-delimited segments become UpperCamelCase;
/// `syn::Ident` closes the generated-code injection boundary. Callers reject cross-label collisions.
fn producer_domain_variant(domain: &str) -> Result<String> {
    rust_enum_variant(domain, "event domain")
}

fn rust_enum_variant(label: &str, subject: &str) -> Result<String> {
    let mut variant = String::new();
    for segment in label.split(['.', '-', '_']).filter(|part| !part.is_empty()) {
        let mut chars = segment.chars();
        if let Some(first) = chars.next() {
            variant.push(first.to_ascii_uppercase());
            variant.extend(chars);
        }
    }
    if variant.starts_with("r#") || syn::parse_str::<syn::Ident>(&variant).is_err() {
        bail!("{subject} {label:?} 派生非法 Rust enum variant {variant:?}");
    }
    Ok(variant)
}

/// Stable event identity + version + consumer → closed generated dispatch variant.
fn subscription_dispatch_variant(c: &GovernedContract, consumer: &str) -> Result<String> {
    let mut variant = String::new();
    for segment in [
        c.manifest().id.as_str(),
        c.manifest().version.as_str(),
        consumer,
    ]
    .into_iter()
    .flat_map(|value| value.split(['.', '-', '_']))
    .filter(|part| !part.is_empty())
    {
        let mut chars = segment.chars();
        if let Some(first) = chars.next() {
            variant.push(first.to_ascii_uppercase());
            variant.extend(chars);
        }
    }
    if variant.starts_with("r#") || syn::parse_str::<syn::Ident>(&variant).is_err() {
        bail!(
            "event subscription {}@{} consumer {:?} 派生非法 dispatch variant {:?}",
            c.manifest().id,
            c.manifest().version,
            consumer,
            variant
        );
    }
    Ok(variant)
}

/// 单契约的 typify 派生 body（payload DTO + 派生 glue，**不含** `@generated` 头）。
/// `sup` 是 POD 引用前缀：扁平 body 用 `"super::"`（POD 在父 `{kind}/mod.rs`）、嵌套 body 在
/// `pub mod <slug>` 内故用 `"super::super::"`。对 event kind 追加 sealed emit/subscription glue
///（CONTRACT_ID / TOPIC / SPEC + typed subscription carriers），http kind 追加 SPEC，command kind 追加
/// emit/register wrapper。
fn render_contract_body(
    c: &GovernedContract,
    sup: &str,
    contracts: &[GovernedContract],
) -> Result<String> {
    if c.manifest().kind == ContractKind::Projection {
        return render_projection_glue(c);
    }
    let mut settings = TypeSpaceSettings::default();
    settings.with_struct_builder(false); // 不要 builder 噪声
    settings.with_replacement(
        "AuthorizationReceiptId",
        "crate::device_certificate::AuthorizationReceiptId",
        std::iter::empty::<typify::TypeSpaceImpl>(),
    );
    let mut space = TypeSpace::new(&settings);
    let source = format!(
        "contracts/{}/{}/{}/",
        c.manifest().kind.as_dir(),
        c.manifest().domain,
        c.manifest().version
    );
    let mut redaction_policies: StructPolicies = BTreeMap::new();
    let mut protection_policies: StructProtectionPolicies = BTreeMap::new();
    let mut deferred_string_lengths: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut utf8_byte_length_markers = BTreeSet::new();
    // ref: typify-impl/src/{lib.rs,convert.rs}@01153fa2fea45d660400e3060d91fa2e102976d8
    // `add_ref_types` is the narrow upstream seam for registering resolved shared definitions
    // before roots; RSS keeps resolution local and deterministic instead of adding a registry.
    let mut shared_definitions = BTreeMap::new();
    let mut roots = Vec::new();
    let schema_files = c.manifest().declared_schema_files();
    for schema_file in schema_files {
        // 防御性安全校验：schema 文件名须为纯文件名，防 `../` 路径逃逸（codegen 可独立于 validate 运行）。
        validate_schema_filename(schema_file)
            .with_context(|| format!("契约 {source} 的 schema 文件名不安全: {schema_file}"))?;
        let schema = c
            .declared_schema(schema_file)
            .with_context(|| format!("契约 {source} 未捕获 promoted schema: {schema_file}"))?;
        let schema_label = schema.file();
        let value = schema.resolved();
        let authored = schema.authored();
        merge_deferred_string_lengths(
            &mut deferred_string_lengths,
            collect_deferred_string_lengths(value)
                .with_context(|| format!("解析 schema {schema_label} 的 deferred string marker"))?,
        );
        utf8_byte_length_markers.extend(
            collect_utf8_byte_length_markers(value).with_context(|| {
                format!("解析 schema {schema_label} 的 UTF-8 byte length marker")
            })?,
        );
        if c.manifest().kind == ContractKind::Http
            && c.manifest().schemas.request.as_deref() == Some(schema_file)
            && schema_declares_property(value, "tenantId")
        {
            bail!(
                "HTTP request schema {} 声明 tenantId；tenant scope 必须来自{}，不得来自 body",
                schema_label,
                TENANT_SCOPE_SOURCE_RULE
            );
        }
        // Redaction annotations on `$ref` siblings belong to the authored property. Resolution
        // deliberately feeds typify, but must not erase those sibling annotations before policy
        // collection.
        let schema_policies =
            redaction::collect_struct_policies(authored).map_err(|violations| {
                anyhow::anyhow!(
                    "redaction policy invalid in {}: {}",
                    schema_label,
                    violations
                        .iter()
                        .map(|v| format!("{}: {}", v.pointer, v.detail))
                        .collect::<Vec<_>>()
                        .join("; ")
                )
            })?;
        redaction_policies.extend(schema_policies);
        let schema_protection_policies =
            protection::collect_struct_policies(value).map_err(|violations| {
                anyhow::anyhow!(
                    "protection policy invalid in {}: {}",
                    schema_label,
                    violations
                        .iter()
                        .map(|v| format!("{}: {}", v.pointer, v.detail))
                        .collect::<Vec<_>>()
                        .join("; ")
                )
            })?;
        protection_policies.extend(schema_protection_policies);
        let mut root: RootSchema = serde_json::from_value(value.value().clone())
            .with_context(|| format!("解析 schema {schema_label}"))?;
        for (name, definition) in std::mem::take(&mut root.definitions) {
            if let Some(existing) = shared_definitions.get(&name) {
                if existing != &definition {
                    bail!("契约 {source} 的 resolved definition {name:?} 在多个 schema 中冲突");
                }
            } else {
                shared_definitions.insert(name, definition);
            }
        }
        roots.push((schema_label.to_owned(), root));
    }
    space
        .add_ref_types(shared_definitions)
        .map_err(|error| anyhow::anyhow!("typify 派生契约 {source} 的共享 definitions: {error}"))?;
    for (schema_label, root) in roots {
        space
            .add_root_schema(root)
            .map_err(|error| anyhow::anyhow!("typify 派生 {schema_label}: {error}"))?;
    }
    let mut parsed =
        syn::parse2::<syn::File>(space.to_stream()).context("syn 解析 typify token 流")?;
    defer_marked_string_length_validation(&mut parsed, &deferred_string_lengths)?;
    rewrite_utf8_byte_length_validation(&mut parsed, &utf8_byte_length_markers)?;
    apply_redaction_policy(&mut parsed, &redaction_policies);
    allow_derivable_default_impls(&mut parsed);
    allow_unwrap_in_defaults_mod(&mut parsed);
    seal_runtime_inventory_response(c, &mut parsed)?;
    let mut payload = prettyplease::unparse(&parsed);
    payload.push_str(&render_field_protection_impls(
        &parsed,
        &protection_policies,
    ));

    // event kind：在 payload DTO 之后追加订阅注册 glue（从 manifest 而非 schema 派生）。
    // generated 保持零额外依赖——glue 全为 `&'static str` POD，`SubscriptionSpec` 定义在 event/mod.rs。
    // command kind：追加 CONTRACT/CONTRACT_ID/TOPIC + policy-exclusive typed wrapper（generated seam 顶层；
    // 泛型收口到 command/mod.rs 的 CommandEmit/CommandRegister seam）。`sup` = POD 引用前缀（嵌套深一级）。
    match c.manifest().kind {
        ContractKind::Event => Ok(format!("{}{}", payload, render_event_glue(c, sup)?)),
        ContractKind::Command => Ok(format!("{}{}", payload, render_command_glue(c, sup)?)),
        ContractKind::Http => Ok(format!(
            "{}{}{}",
            payload,
            render_http_glue(c, sup, contracts)?,
            render_runtime_inventory_projection(c)?
        )),
        ContractKind::Saga => Ok(format!("{}{}", payload, render_saga_glue(c, sup)?)),
        ContractKind::Projection => bail!("projection returned before DTO generation"),
    }
}

fn is_runtime_inventory_v1(c: &GovernedContract) -> bool {
    c.manifest().kind == ContractKind::Http
        && c.manifest().id == "runtime.inventory"
        && c.manifest().version == "v1"
}

fn runtime_inventory_schema_version(c: &GovernedContract) -> Result<i64> {
    let response_schema = c
        .manifest()
        .schemas
        .response(200)
        .context("runtime.inventory@v1 must declare its 200 response schema")?;
    let schema = c
        .schema(response_schema)
        .with_context(|| format!("resolve runtime inventory response schema {response_schema}"))?;
    let version = schema
        .pointer("/properties/data/properties/schemaVersion/const")
        .and_then(serde_json::Value::as_i64)
        .context(
            "runtime.inventory@v1 response schema must declare integer data.schemaVersion.const",
        )?;
    anyhow::ensure!(
        version > 0,
        "runtime.inventory@v1 data.schemaVersion.const must be positive"
    );
    Ok(version)
}

fn seal_runtime_inventory_response(c: &GovernedContract, file: &mut syn::File) -> Result<()> {
    if !is_runtime_inventory_v1(c) {
        return Ok(());
    }
    let response = file.items.iter_mut().find_map(|item| match item {
        syn::Item::Struct(item) if item.ident == "RuntimeInventoryResponse" => Some(item),
        _ => None,
    });
    let response = response
        .context("runtime.inventory@v1 response schema must generate RuntimeInventoryResponse")?;
    response.attrs.push(syn::parse_quote!(#[non_exhaustive]));
    let data = file
        .items
        .iter_mut()
        .find_map(|item| match item {
            syn::Item::Struct(item) if item.ident == "RuntimeInventoryData" => Some(item),
            _ => None,
        })
        .context("runtime.inventory@v1 response schema must generate RuntimeInventoryData")?;
    let schema_version = data
        .fields
        .iter_mut()
        .find(|field| {
            field
                .ident
                .as_ref()
                .is_some_and(|ident| ident == "schema_version")
        })
        .context("RuntimeInventoryData must contain schema_version")?;
    schema_version.ty = syn::parse_quote!(RuntimeInventorySchemaVersion);
    let version = runtime_inventory_schema_version(c)?;
    let version_variant = syn::Ident::new(&format!("V{version}"), proc_macro2::Span::call_site());
    let version_error = syn::LitStr::new(
        &format!("runtime inventory schemaVersion must be {version}"),
        proc_macro2::Span::call_site(),
    );
    let redacted_version = syn::LitStr::new(
        &format!("RuntimeInventorySchemaVersion::{version_variant}"),
        proc_macro2::Span::call_site(),
    );
    file.items.push(syn::parse_quote! {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, ::serde::Serialize, ::serde::Deserialize)]
        #[serde(try_from = "i64", into = "i64")]
        pub enum RuntimeInventorySchemaVersion { #version_variant }
    });
    file.items.push(syn::parse_quote! {
        impl ::std::convert::TryFrom<i64> for RuntimeInventorySchemaVersion {
            type Error = &'static str;
            fn try_from(value: i64) -> Result<Self, Self::Error> {
                if value == #version { Ok(Self::#version_variant) } else { Err(#version_error) }
            }
        }
    });
    file.items.push(syn::parse_quote! {
        impl ::std::convert::From<RuntimeInventorySchemaVersion> for i64 {
            fn from(_: RuntimeInventorySchemaVersion) -> Self { #version }
        }
    });
    file.items.push(syn::parse_quote! {
        impl ::secure::Redact for RuntimeInventorySchemaVersion {
            fn redact_scoped(&self, _scope: ::secure::RedactScope) -> ::std::string::String {
                #redacted_version.to_owned()
            }
        }
    });
    Ok(())
}

fn render_runtime_inventory_projection(c: &GovernedContract) -> Result<String> {
    if !is_runtime_inventory_v1(c) {
        return Ok(String::new());
    }
    let schema_version = runtime_inventory_schema_version(c)?;
    let schema_version_variant = format!("V{schema_version}");
    Ok(r#"
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Closed, non-sensitive stages at which neutral facts can fail wire projection.
pub enum RuntimeInventoryProjectionStage {
    ActivatedWorkflowDefinitionSchemaDigest,
    ActivatedWorkflowDefinitionVersion,
    ActivatedWorkflowId,
    ActivatedWorkflowTargetGeneration,
    ActivatedWorkflowSelectedGeneration,
    ListenerEndpointHost,
    ListenerEndpointPort,
    ListenerId,
    ProviderId,
    PlacementEndpointHost,
    PlacementEndpointPort,
    PlacementSpiffeIdentity,
    PlacementWorkload,
    AssemblyFingerprint,
    BuildImageDigest,
    BuildSourceRevision,
    RuntimePlanFingerprint,
}

impl RuntimeInventoryProjectionStage {
    /// Return a stable diagnostic coordinate without runtime values.
    pub const fn diagnostic_stage(self) -> &'static str {
        match self {
            Self::ActivatedWorkflowDefinitionSchemaDigest => "projection.activated_workflow.definition_schema_digest",
            Self::ActivatedWorkflowDefinitionVersion => "projection.activated_workflow.definition_version",
            Self::ActivatedWorkflowId => "projection.activated_workflow.id",
            Self::ActivatedWorkflowTargetGeneration => "projection.activated_workflow.target_generation",
            Self::ActivatedWorkflowSelectedGeneration => "projection.activated_workflow.selected_generation",
            Self::ListenerEndpointHost => "projection.listener.endpoint.host",
            Self::ListenerEndpointPort => "projection.listener.endpoint.port",
            Self::ListenerId => "projection.listener.id",
            Self::ProviderId => "projection.provider.id",
            Self::PlacementEndpointHost => "projection.placement.endpoint.host",
            Self::PlacementEndpointPort => "projection.placement.endpoint.port",
            Self::PlacementSpiffeIdentity => "projection.placement.spiffe_identity",
            Self::PlacementWorkload => "projection.placement.workload",
            Self::AssemblyFingerprint => "projection.assembly_fingerprint",
            Self::BuildImageDigest => "projection.build_metadata.image_digest",
            Self::BuildSourceRevision => "projection.build_metadata.source_revision",
            Self::RuntimePlanFingerprint => "projection.runtime_plan_fingerprint",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeInventoryProjectionError {
    stage: RuntimeInventoryProjectionStage,
}

impl RuntimeInventoryProjectionError {
    /// Return the closed stage that rejected a value.
    pub const fn stage(self) -> RuntimeInventoryProjectionStage {
        self.stage
    }
}

impl ::std::fmt::Display for RuntimeInventoryProjectionError {
    fn fmt(&self, formatter: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        write!(formatter, "runtime inventory projection failed at {:?}", self.stage)
    }
}

impl ::std::error::Error for RuntimeInventoryProjectionError {}

fn runtime_inventory_parse<T>(
    value: &str,
    stage: RuntimeInventoryProjectionStage,
) -> Result<T, RuntimeInventoryProjectionError>
where
    T: ::std::str::FromStr,
{
    value.parse().map_err(|_| RuntimeInventoryProjectionError { stage })
}

fn runtime_inventory_endpoint(
    endpoint: &::assembly_schema::runtime_inventory::RuntimeInventoryEndpoint,
    host_stage: RuntimeInventoryProjectionStage,
    port_stage: RuntimeInventoryProjectionStage,
) -> Result<RuntimeListenerEndpoint, RuntimeInventoryProjectionError> {
    Ok(RuntimeListenerEndpoint {
        scheme: match endpoint.scheme() {
            ::assembly_schema::runtime_inventory::RuntimeInventoryEndpointScheme::Http => RuntimeListenerEndpointScheme::Http,
            ::assembly_schema::runtime_inventory::RuntimeInventoryEndpointScheme::Https => RuntimeListenerEndpointScheme::Https,
        },
        host: runtime_inventory_parse(endpoint.host(), host_stage)?,
        port: ::std::num::NonZeroU64::new(u64::from(endpoint.port()))
            .ok_or(RuntimeInventoryProjectionError { stage: port_stage })?,
    })
}

fn runtime_inventory_selected_generation(
    selected: &::assembly_schema::runtime_inventory::RuntimeInventorySelectedGeneration,
) -> Result<RuntimeProjectionSelectedGeneration, RuntimeInventoryProjectionError> {
    use ::assembly_schema::runtime_inventory::RuntimeInventorySelectedGeneration as Source;
    Ok(match selected {
        Source::None => RuntimeProjectionSelectedGeneration::None(RuntimeProjectionSelectedGenerationNone { state: RuntimeProjectionSelectedGenerationNoneState::None }),
        Source::Uniform(generation) => RuntimeProjectionSelectedGeneration::Uniform(RuntimeProjectionSelectedGenerationUniform {
            generation: runtime_inventory_parse(generation, RuntimeInventoryProjectionStage::ActivatedWorkflowSelectedGeneration)?,
            state: RuntimeProjectionSelectedGenerationUniformState::Uniform,
        }),
        Source::Mixed => RuntimeProjectionSelectedGeneration::Mixed(RuntimeProjectionSelectedGenerationMixed { state: RuntimeProjectionSelectedGenerationMixedState::Mixed }),
    })
}

fn runtime_inventory_retryable_reason(reason: ::assembly_schema::runtime_inventory::RuntimeInventoryRetryableReason) -> RuntimeProjectionRetryableReason {
    use ::assembly_schema::runtime_inventory::RuntimeInventoryRetryableReason as Source;
    match reason {
        Source::CheckpointUnread => RuntimeProjectionRetryableReason::CheckpointUnread,
        Source::CheckpointUnsaved => RuntimeProjectionRetryableReason::CheckpointUnsaved,
        Source::DeadLetterUnsaved => RuntimeProjectionRetryableReason::DeadLetterUnsaved,
        Source::ApplyTransient => RuntimeProjectionRetryableReason::ApplyTransient,
        Source::CommitUnknown => RuntimeProjectionRetryableReason::CommitUnknown,
        Source::SourceTransient => RuntimeProjectionRetryableReason::SourceTransient,
        Source::QuarantinePersistence => RuntimeProjectionRetryableReason::QuarantinePersistence,
    }
}

fn runtime_inventory_retryable_reasons(reasons: &::assembly_schema::runtime_inventory::RuntimeInventoryReasonPosture<::assembly_schema::runtime_inventory::RuntimeInventoryRetryableReason>) -> RuntimeProjectionRetryableReasons {
    match reasons {
        ::assembly_schema::runtime_inventory::RuntimeInventoryReasonPosture::Uniform(reason) => RuntimeProjectionRetryableReasons::Uniform(RuntimeProjectionRetryableReasonsUniform { reason: runtime_inventory_retryable_reason(*reason), state: RuntimeProjectionRetryableReasonsUniformState::Uniform }),
        ::assembly_schema::runtime_inventory::RuntimeInventoryReasonPosture::Mixed => RuntimeProjectionRetryableReasons::Mixed(RuntimeProjectionRetryableReasonsMixed { state: RuntimeProjectionRetryableReasonsMixedState::Mixed }),
    }
}

fn runtime_inventory_quarantine_reason(reason: ::assembly_schema::runtime_inventory::RuntimeInventoryQuarantineReason) -> RuntimeProjectionQuarantineReason {
    use ::assembly_schema::runtime_inventory::RuntimeInventoryQuarantineReason as Source;
    match reason {
        Source::TargetDefinitionDrift => RuntimeProjectionQuarantineReason::TargetDefinitionDrift,
        Source::InputBindingDrift => RuntimeProjectionQuarantineReason::InputBindingDrift,
        Source::TenantDrift => RuntimeProjectionQuarantineReason::TenantDrift,
        Source::PayloadMalformed => RuntimeProjectionQuarantineReason::PayloadMalformed,
        Source::PayloadValueInvalid => RuntimeProjectionQuarantineReason::PayloadValueInvalid,
        Source::VersionRegression => RuntimeProjectionQuarantineReason::VersionRegression,
        Source::ProviderInvariant => RuntimeProjectionQuarantineReason::ProviderInvariant,
        Source::ProviderPermanent => RuntimeProjectionQuarantineReason::ProviderPermanent,
        Source::Conflict => RuntimeProjectionQuarantineReason::Conflict,
        Source::ApplyOutOfOrder => RuntimeProjectionQuarantineReason::ApplyOutOfOrder,
        Source::RollbackFailed => RuntimeProjectionQuarantineReason::RollbackFailed,
        Source::SourceOutOfOrder => RuntimeProjectionQuarantineReason::SourceOutOfOrder,
    }
}

fn runtime_inventory_quarantine_reasons(reasons: &::assembly_schema::runtime_inventory::RuntimeInventoryReasonPosture<::assembly_schema::runtime_inventory::RuntimeInventoryQuarantineReason>) -> RuntimeProjectionQuarantineReasons {
    match reasons {
        ::assembly_schema::runtime_inventory::RuntimeInventoryReasonPosture::Uniform(reason) => RuntimeProjectionQuarantineReasons::Uniform(RuntimeProjectionQuarantineReasonsUniform { reason: runtime_inventory_quarantine_reason(*reason), state: RuntimeProjectionQuarantineReasonsUniformState::Uniform }),
        ::assembly_schema::runtime_inventory::RuntimeInventoryReasonPosture::Mixed => RuntimeProjectionQuarantineReasons::Mixed(RuntimeProjectionQuarantineReasonsMixed { state: RuntimeProjectionQuarantineReasonsMixedState::Mixed }),
    }
}

fn runtime_inventory_worker_status(status: &::assembly_schema::runtime_inventory::RuntimeInventoryProjectionWorkerStatus) -> Result<RuntimeProjectionWorkerStatus, RuntimeInventoryProjectionError> {
    use ::assembly_schema::runtime_inventory::RuntimeInventoryProjectionWorkerStatus as Source;
    Ok(match status {
        Source::Starting => RuntimeProjectionWorkerStatus::Starting(RuntimeProjectionWorkerStarting { state: RuntimeProjectionWorkerStartingState::Starting }),
        Source::Healthy { selected_generation, max_lag } => RuntimeProjectionWorkerStatus::Healthy(RuntimeProjectionWorkerHealthy { max_lag: *max_lag, selected_generation: runtime_inventory_selected_generation(selected_generation)?, state: RuntimeProjectionWorkerHealthyState::Healthy }),
        Source::Retryable { selected_generation, max_lag, reasons } => RuntimeProjectionWorkerStatus::Retryable(RuntimeProjectionWorkerRetryable { max_lag: *max_lag, reasons: runtime_inventory_retryable_reasons(reasons), selected_generation: runtime_inventory_selected_generation(selected_generation)?, state: RuntimeProjectionWorkerRetryableState::Retryable }),
        Source::Quarantined { selected_generation, max_lag, reasons } => RuntimeProjectionWorkerStatus::Quarantined(RuntimeProjectionWorkerQuarantined { max_lag: *max_lag, reasons: runtime_inventory_quarantine_reasons(reasons), selected_generation: runtime_inventory_selected_generation(selected_generation)?, state: RuntimeProjectionWorkerQuarantinedState::Quarantined }),
        Source::Mixed { selected_generation, max_lag, retryable_reasons, quarantine_reasons } => RuntimeProjectionWorkerStatus::Mixed(RuntimeProjectionWorkerMixed { max_lag: *max_lag, quarantine_reasons: runtime_inventory_quarantine_reasons(quarantine_reasons), retryable_reasons: runtime_inventory_retryable_reasons(retryable_reasons), selected_generation: runtime_inventory_selected_generation(selected_generation)?, state: RuntimeProjectionWorkerMixedState::Mixed }),
        Source::Unavailable(reason) => RuntimeProjectionWorkerStatus::Unavailable(RuntimeProjectionWorkerUnavailable {
            reason: match reason { ::assembly_schema::runtime_inventory::RuntimeInventoryUnavailableReason::StartupObservation => RuntimeProjectionWorkerUnavailableReason::StartupObservation, ::assembly_schema::runtime_inventory::RuntimeInventoryUnavailableReason::SweepIncomplete => RuntimeProjectionWorkerUnavailableReason::SweepIncomplete, ::assembly_schema::runtime_inventory::RuntimeInventoryUnavailableReason::TenantObservation => RuntimeProjectionWorkerUnavailableReason::TenantObservation },
            state: RuntimeProjectionWorkerUnavailableState::Unavailable,
        }),
        Source::Stopped(reason) => RuntimeProjectionWorkerStatus::Stopped(RuntimeProjectionWorkerStopped {
            reason: match reason { ::assembly_schema::runtime_inventory::RuntimeInventoryStoppedReason::RuntimeBuildFailed => RuntimeProjectionWorkerStoppedReason::RuntimeBuildFailed, ::assembly_schema::runtime_inventory::RuntimeInventoryStoppedReason::WorkerPanicked => RuntimeProjectionWorkerStoppedReason::WorkerPanicked, ::assembly_schema::runtime_inventory::RuntimeInventoryStoppedReason::TenantCatalogUnavailable => RuntimeProjectionWorkerStoppedReason::TenantCatalogUnavailable, ::assembly_schema::runtime_inventory::RuntimeInventoryStoppedReason::SelectedGenerationUnavailable => RuntimeProjectionWorkerStoppedReason::SelectedGenerationUnavailable, ::assembly_schema::runtime_inventory::RuntimeInventoryStoppedReason::SelectedGenerationIdentityInvalid => RuntimeProjectionWorkerStoppedReason::SelectedGenerationIdentityInvalid, ::assembly_schema::runtime_inventory::RuntimeInventoryStoppedReason::InvalidTenant => RuntimeProjectionWorkerStoppedReason::InvalidTenant, ::assembly_schema::runtime_inventory::RuntimeInventoryStoppedReason::TenantQuarantineUnavailable => RuntimeProjectionWorkerStoppedReason::TenantQuarantineUnavailable, ::assembly_schema::runtime_inventory::RuntimeInventoryStoppedReason::StartupSourceUnavailable => RuntimeProjectionWorkerStoppedReason::StartupSourceUnavailable, ::assembly_schema::runtime_inventory::RuntimeInventoryStoppedReason::ProjectionOutcomeInvalid => RuntimeProjectionWorkerStoppedReason::ProjectionOutcomeInvalid, ::assembly_schema::runtime_inventory::RuntimeInventoryStoppedReason::CoordinateOverflow => RuntimeProjectionWorkerStoppedReason::CoordinateOverflow, ::assembly_schema::runtime_inventory::RuntimeInventoryStoppedReason::TargetConfigInvalid => RuntimeProjectionWorkerStoppedReason::TargetConfigInvalid },
            state: RuntimeProjectionWorkerStoppedState::Stopped,
            stop_class: RuntimeProjectionWorkerStoppedStopClass::Fatal,
        }),
    })
}

impl ::std::convert::TryFrom<::assembly_schema::runtime_inventory::RuntimeInventoryObservation>
    for RuntimeInventoryResponse
{
    type Error = RuntimeInventoryProjectionError;

    fn try_from(
        observation: ::assembly_schema::runtime_inventory::RuntimeInventoryObservation,
    ) -> Result<Self, Self::Error> {
        use ::assembly_schema::runtime_inventory as model;
        let activated_workflows = observation.activated_workflows().iter().map(|workflow| {
            match workflow.shape() {
                model::RuntimeInventoryActivatedWorkflowShape::ProjectionCapture => {
                    Ok(RuntimeActivatedWorkflow::ProjectionCapture(RuntimeActivatedProjectionCapture {
                        activation: RuntimeActivatedProjectionCaptureActivation::CaptureOnly,
                        definition_schema_digest: runtime_inventory_parse(workflow.definition_schema_digest().as_str(), RuntimeInventoryProjectionStage::ActivatedWorkflowDefinitionSchemaDigest)?,
                        definition_version: runtime_inventory_parse(workflow.definition_version(), RuntimeInventoryProjectionStage::ActivatedWorkflowDefinitionVersion)?, id: runtime_inventory_parse(workflow.id(), RuntimeInventoryProjectionStage::ActivatedWorkflowId)?, mode: RuntimeActivatedProjectionCaptureMode::Projection,
                    }))
                }
                model::RuntimeInventoryActivatedWorkflowShape::ProjectionExecuting { activation, execution } => {
                    Ok(RuntimeActivatedWorkflow::ProjectionExecuting(RuntimeActivatedProjectionExecuting {
                        activation: match activation { model::RuntimeInventoryExecutingProjectionActivation::Shadow => RuntimeActivatedProjectionExecutingActivation::Shadow, model::RuntimeInventoryExecutingProjectionActivation::Active => RuntimeActivatedProjectionExecutingActivation::Active },
                        definition_schema_digest: runtime_inventory_parse(workflow.definition_schema_digest().as_str(), RuntimeInventoryProjectionStage::ActivatedWorkflowDefinitionSchemaDigest)?,
                        definition_version: runtime_inventory_parse(workflow.definition_version(), RuntimeInventoryProjectionStage::ActivatedWorkflowDefinitionVersion)?, id: runtime_inventory_parse(workflow.id(), RuntimeInventoryProjectionStage::ActivatedWorkflowId)?, mode: RuntimeActivatedProjectionExecutingMode::Projection,
                        target_generation: runtime_inventory_parse(execution.target_generation(), RuntimeInventoryProjectionStage::ActivatedWorkflowTargetGeneration)?,
                        worker_status: runtime_inventory_worker_status(execution.worker_status())?,
                    }))
                }
                model::RuntimeInventoryActivatedWorkflowShape::SagaActive => {
                    Ok(RuntimeActivatedWorkflow::Saga(RuntimeActivatedSaga {
                        activation: RuntimeActivatedSagaActivation::Active,
                        definition_schema_digest: runtime_inventory_parse(workflow.definition_schema_digest().as_str(), RuntimeInventoryProjectionStage::ActivatedWorkflowDefinitionSchemaDigest)?,
                        definition_version: runtime_inventory_parse(workflow.definition_version(), RuntimeInventoryProjectionStage::ActivatedWorkflowDefinitionVersion)?,
                        id: runtime_inventory_parse(workflow.id(), RuntimeInventoryProjectionStage::ActivatedWorkflowId)?,
                        mode: RuntimeActivatedSagaMode::Saga,
                    }))
                }
            }
        }).collect::<Result<Vec<_>, RuntimeInventoryProjectionError>>()?;
        let listeners = observation.listeners().iter().map(|listener| {
            Ok(RuntimeListener {
                auth_scheme: match listener.auth() {
                    ::assembly_schema::ListenerAuth::NoAuth => RuntimeAuthScheme::NoAuth,
                    ::assembly_schema::ListenerAuth::RssAccessToken => RuntimeAuthScheme::RssAccessToken,
                    ::assembly_schema::ListenerAuth::FederatedAccessToken => RuntimeAuthScheme::FederatedAccessToken,
                    ::assembly_schema::ListenerAuth::Mtls => RuntimeAuthScheme::Mtls,
                    ::assembly_schema::ListenerAuth::ServiceToken => RuntimeAuthScheme::ServiceToken,
                },
                endpoint: runtime_inventory_endpoint(listener.endpoint(), RuntimeInventoryProjectionStage::ListenerEndpointHost, RuntimeInventoryProjectionStage::ListenerEndpointPort)?,
                id: runtime_inventory_parse(listener.id(), RuntimeInventoryProjectionStage::ListenerId)?,
                kind: match listener.kind() {
                    ::assembly_schema::AssemblyListenerKind::Primary => RuntimeListenerKind::Primary,
                    ::assembly_schema::AssemblyListenerKind::Internal => RuntimeListenerKind::Internal,
                    ::assembly_schema::AssemblyListenerKind::Health => RuntimeListenerKind::Health,
                    ::assembly_schema::AssemblyListenerKind::Admin => RuntimeListenerKind::Admin,
                },
            })
        }).collect::<Result<Vec<_>, RuntimeInventoryProjectionError>>()?;
        let provider_posture = observation.provider_posture().iter().map(|provider| {
            Ok(RuntimeProviderPosture {
                id: runtime_inventory_parse(provider.id(), RuntimeInventoryProjectionStage::ProviderId)?,
                state: match provider.state() {
                    model::RuntimeInventoryProviderState::Unobserved => RuntimeProviderPostureState::Unobserved,
                    model::RuntimeInventoryProviderState::Ready => RuntimeProviderPostureState::Ready,
                    model::RuntimeInventoryProviderState::Degraded => RuntimeProviderPostureState::Degraded,
                    model::RuntimeInventoryProviderState::Unavailable => RuntimeProviderPostureState::Unavailable,
                },
            })
        }).collect::<Result<Vec<_>, RuntimeInventoryProjectionError>>()?;
        let placements = observation.placements().iter().map(|placement| {
            Ok(RuntimePlacement {
                domain: match placement.domain() {
                    ::assembly_schema::AssemblyDomain::Identity => RuntimeDomain::Identity,
                    ::assembly_schema::AssemblyDomain::Settings => RuntimeDomain::Settings,
                    ::assembly_schema::AssemblyDomain::Audit => RuntimeDomain::Audit,
                    ::assembly_schema::AssemblyDomain::Contractreg => RuntimeDomain::Contractreg,
                    ::assembly_schema::AssemblyDomain::Syshealth => RuntimeDomain::Syshealth,
                },
                endpoint: placement.endpoint().map(|endpoint| runtime_inventory_endpoint(endpoint, RuntimeInventoryProjectionStage::PlacementEndpointHost, RuntimeInventoryProjectionStage::PlacementEndpointPort)).transpose()?,
                mode: match placement.mode() {
                    model::RuntimeInventoryPlacementMode::Local => RuntimePlacementMode::Local,
                    model::RuntimeInventoryPlacementMode::Remote => RuntimePlacementMode::Remote,
                },
                readiness: match placement.readiness() {
                    model::RuntimeInventoryPlacementReadiness::Ready => RuntimePlacementReadiness::Ready,
                    model::RuntimeInventoryPlacementReadiness::MtlsSourceUnavailable => RuntimePlacementReadiness::MtlsSourceUnavailable,
                },
                spiffe_identity: placement.spiffe_identity().map(|identity| runtime_inventory_parse(identity, RuntimeInventoryProjectionStage::PlacementSpiffeIdentity)).transpose()?,
                workload: runtime_inventory_parse(placement.workload(), RuntimeInventoryProjectionStage::PlacementWorkload)?,
            })
        }).collect::<Result<Vec<_>, RuntimeInventoryProjectionError>>()?;
        Ok(Self {
            data: RuntimeInventoryData {
                activated_workflows,
                assembly_fingerprint: runtime_inventory_parse(observation.assembly_fingerprint().as_str(), RuntimeInventoryProjectionStage::AssemblyFingerprint)?,
                build_metadata: observation.build_metadata().map(|metadata| {
                    Ok(RuntimeBuildMetadata {
                        image_digest: runtime_inventory_parse(metadata.image_digest().as_str(), RuntimeInventoryProjectionStage::BuildImageDigest)?,
                        source_revision: runtime_inventory_parse(metadata.source_revision(), RuntimeInventoryProjectionStage::BuildSourceRevision)?,
                    })
                }).transpose()?,
                domains: observation.domains().iter().copied().map(|domain| match domain {
                    ::assembly_schema::AssemblyDomain::Identity => RuntimeDomain::Identity,
                    ::assembly_schema::AssemblyDomain::Settings => RuntimeDomain::Settings,
                    ::assembly_schema::AssemblyDomain::Audit => RuntimeDomain::Audit,
                    ::assembly_schema::AssemblyDomain::Contractreg => RuntimeDomain::Contractreg,
                    ::assembly_schema::AssemblyDomain::Syshealth => RuntimeDomain::Syshealth,
                }).collect(),
                listeners,
                placements,
                provider_posture,
                runtime_plan_fingerprint: runtime_inventory_parse(observation.runtime_plan_fingerprint().as_str(), RuntimeInventoryProjectionStage::RuntimePlanFingerprint)?,
                schema_version: RuntimeInventorySchemaVersion::__RUNTIME_INVENTORY_SCHEMA_VERSION_VARIANT__,
            },
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Closed failure classes produced by runtime inventory read and projection.
pub enum RuntimeInventoryProjectionFailure {
    /// The live inventory has not published all required evidence yet.
    ProviderUnavailable,
    /// The reader rejected published facts at one closed invariant category.
    ObservationInvariant(::assembly_schema::runtime_inventory::RuntimeInventoryInvariantKind),
    /// A reader-minted observation failed at one closed wire projection stage.
    Projection(RuntimeInventoryProjectionStage),
}

impl RuntimeInventoryProjectionFailure {
    /// Return the canonical core error classification used for logging policy.
    pub fn core_error(self) -> ::vocab::CoreError {
        match self {
            Self::ProviderUnavailable => ::vocab::CoreError::new(::vocab::CoreErrorKind::ProviderUnavailable),
            Self::ObservationInvariant(_) | Self::Projection(_) => {
                ::vocab::CoreError::new(::vocab::CoreErrorKind::Internal)
            }
        }
    }

    /// Return a stable, non-sensitive stage for structured internal diagnostics.
    pub const fn diagnostic_stage(self) -> Option<&'static str> {
        match self {
            Self::ProviderUnavailable => None,
            Self::ObservationInvariant(kind) => Some(kind.diagnostic_stage()),
            Self::Projection(stage) => Some(stage.diagnostic_stage()),
        }
    }

    /// Consume the failure into the contract-declared fixed error response.
    pub fn into_response_error(
        self,
        request_id: ::requestidmint::WireRequestId,
    ) -> RuntimeInventoryResponseError {
        match self {
            Self::ProviderUnavailable => RuntimeInventoryResponseError::status_503(request_id),
            Self::ObservationInvariant(_) | Self::Projection(_) => {
                RuntimeInventoryResponseError::status_500(request_id)
            }
        }
    }
}

/// Project one live read into the only success carrier accepted by the declared route seam.
pub fn project_read_result(
    result: Result<
        ::assembly_schema::runtime_inventory::RuntimeInventoryObservation,
        ::assembly_schema::runtime_inventory::RuntimeInventoryReadFailure,
    >,
) -> Result<RuntimeInventoryProjectedSuccess, RuntimeInventoryProjectionFailure> {
    match result {
        Ok(observation) => RuntimeInventoryResponse::try_from(observation)
            .map(RuntimeInventoryProjectedSuccess)
            .map_err(|error| RuntimeInventoryProjectionFailure::Projection(error.stage())),
        Err(::assembly_schema::runtime_inventory::RuntimeInventoryReadFailure::Unavailable) => {
            Err(RuntimeInventoryProjectionFailure::ProviderUnavailable)
        }
        Err(::assembly_schema::runtime_inventory::RuntimeInventoryReadFailure::Invariant(kind)) => {
            Err(RuntimeInventoryProjectionFailure::ObservationInvariant(kind))
        }
    }
}
"#
    .replace(
        "__RUNTIME_INVENTORY_SCHEMA_VERSION_VARIANT__",
        &schema_version_variant,
    ))
}

fn render_projection_glue(c: &GovernedContract) -> Result<String> {
    let domain = &c.manifest().domain;
    let contract_id = &c.manifest().id;
    let version = &c.manifest().version;
    let schema_hash = c.schema_hash();
    for (field, value) in [
        ("domain", domain.as_str()),
        ("id", contract_id.as_str()),
        ("version", version.as_str()),
    ] {
        if !is_safe_codegen_ident(value) {
            bail!(
                "projection 契约 {}/{}/{} 的 {field} 含不安全字符（防注入生成字面量）: {value:?}",
                c.manifest().kind.as_dir(),
                c.manifest().domain,
                c.manifest().version,
            );
        }
    }
    if !is_safe_codegen_string(schema_hash) {
        bail!(
            "projection 契约 {}/{}/{} 的 schema_hash 含不安全字符（防注入生成字面量）: {schema_hash:?}",
            c.manifest().kind.as_dir(),
            c.manifest().domain,
            c.manifest().version,
        );
    }
    Ok(format!(
        r#"
/// Projection 契约 ID（`contract.toml` `id` 字段，单一事实源）。由 `cargo xtask codegen` 从 manifest 派生；勿手改。
pub const CONTRACT_ID: &str = "{contract_id}";

/// Projection definition 归属绑定。该后台 carrier 不生成 HTTP route、request/response DTO 或 serving spec。
pub const DESCRIPTOR: ::rss_contract::ContractDescriptor =
    ::rss_contract::ContractDescriptor::from_static_version("{contract_id}", "{version}", "{schema_hash}");

pub const CONTRACT: ::vocab::ContractBinding =
    ::vocab::ContractBinding::from_descriptor("{domain}", DESCRIPTOR, "{version}");
"#
    ))
}

fn render_saga_glue(c: &GovernedContract, sup: &str) -> Result<String> {
    let saga = c
        .manifest()
        .saga
        .as_ref()
        .context("saga 契约缺 [saga] block（codegen fail-closed）")?;
    let domain = &c.manifest().domain;
    let contract_id = &c.manifest().id;
    let version = &c.manifest().version;
    let schema_hash = c.schema_hash();
    let action_registry_generation = saga_action_registry_generation(saga);
    for (field, value) in [
        ("domain", domain.as_str()),
        ("id", contract_id.as_str()),
        ("version", version.as_str()),
    ] {
        if !is_safe_codegen_ident(value) {
            bail!(
                "契约 {}/{}/{} 的 {field} 含不安全字符（防注入生成字面量）: {value:?}",
                c.manifest().kind.as_dir(),
                c.manifest().domain,
                c.manifest().version,
            );
        }
    }
    if !is_safe_codegen_string(schema_hash) {
        bail!(
            "契约 {}/{}/{} 的 schema_hash 含不安全字符（防注入生成字面量）: {schema_hash:?}",
            c.manifest().kind.as_dir(),
            c.manifest().domain,
            c.manifest().version,
        );
    }
    let retry = saga.retry;
    let backoff = match retry.backoff {
        SagaBackoff::Fixed => "Fixed",
        SagaBackoff::Exponential => "Exponential",
    };
    let jitter = match retry.jitter {
        SagaJitter::None => "None",
        SagaJitter::Full => "Full",
    };
    let mut step_consts = Vec::new();
    let mut step_entries = Vec::new();
    let mut cursor_impls = Vec::new();
    let mut cursor_types = Vec::new();
    for (idx, step) in saga.steps.iter().enumerate() {
        for (field, value) in [
            ("saga step name", step.name.as_str()),
            ("saga step receiptSchema", step.receipt_schema.as_str()),
            ("saga step effectScope", step.effect_scope.as_str()),
            (
                "saga step compensationEffectScope",
                step.compensation_effect_scope.as_str(),
            ),
        ] {
            if !is_safe_codegen_string(value) {
                bail!(
                    "契约 {}/{}/{} 的 {field} 含不安全字符（防注入生成字面量）: {value:?}",
                    c.manifest().kind.as_dir(),
                    c.manifest().domain,
                    c.manifest().version,
                );
            }
        }
        validate_schema_filename(&step.receipt_schema).with_context(|| {
            format!(
                "契约 {}/{}/{} 的 saga step receiptSchema 不安全: {}",
                c.manifest().kind.as_dir(),
                c.manifest().domain,
                c.manifest().version,
                step.receipt_schema
            )
        })?;
        let const_name = format!("STEP_{idx}");
        let receipt_ty = schema_root_type_name(c, &step.receipt_schema, "saga step receiptSchema")?;
        let cursor_ty = format!("{}Step", producer_domain_variant(step.name.as_str())?);
        let retry_class = match step.retry_class {
            SagaRetryClass::Never => "Never",
            SagaRetryClass::Transient => "Transient",
        };
        step_consts.push(format!(
            r#"
/// Saga step `{}` binding generated from `[saga].steps[{idx}]`.
pub const {const_name}: ::vocab::SagaStepBinding =
    ::vocab::SagaStepBinding::from_static(CONTRACT, "{}", "{}", "{}", "{}", ::vocab::SagaRetryClass::{retry_class});
"#,
            step.name,
            step.name,
            step.receipt_schema,
            step.effect_scope,
            step.compensation_effect_scope,
        ));
        cursor_types.push((cursor_ty, receipt_ty, const_name.clone()));
        step_entries.push(const_name);
    }
    for (idx, (cursor_ty, receipt_ty, const_name)) in cursor_types.iter().enumerate() {
        let next_ty = cursor_types
            .get(idx + 1)
            .map_or("End", |(next, _, _)| next.as_str());
        cursor_impls.push(format!(
            r#"
/// Generated typestate cursor for this ordered Saga step.
#[derive(Debug, Clone, Copy)]
pub struct {cursor_ty};

impl {sup}sealed::StepMarker for {cursor_ty} {{}}
impl {sup}StepMarker for {cursor_ty} {{
    type Receipt = {receipt_ty};
    const BINDING: ::vocab::SagaStepBinding = {const_name};
}}
impl {sup}sealed::Step<Definition> for {cursor_ty} {{}}
impl {sup}Step<Definition> for {cursor_ty} {{
    type Next = {next_ty};
}}

impl {sup}sealed::Receipt<{cursor_ty}> for {receipt_ty} {{}}
impl {sup}Receipt<{cursor_ty}> for {receipt_ty} {{}}
"#
        ));
    }
    let steps_body = if step_entries.is_empty() {
        String::new()
    } else {
        format!("\n{},\n", step_entries.join(",\n"))
    };
    let step_consts = step_consts.join("");
    let cursor_impls = cursor_impls.join("");
    let first_cursor = cursor_types
        .first()
        .map(|(cursor, _, _)| cursor.as_str())
        .context("saga 至少须有一个 step（codegen fail-closed）")?;
    Ok(format!(
        r#"
/// Saga 契约 ID（`contract.toml` `id` 字段，单一事实源）。由 `cargo xtask codegen` 从 manifest 派生；勿手改。
pub const CONTRACT_ID: &str = "{contract_id}";

/// 契约归属绑定（`domain` + `id` + `version` + `schema_hash` 同源派生）。由 `cargo xtask codegen` 从 manifest 派生；勿手改。
pub const DESCRIPTOR: ::rss_contract::ContractDescriptor =
    ::rss_contract::ContractDescriptor::from_static_version("{contract_id}", "{version}", "{schema_hash}");

pub const CONTRACT: ::vocab::ContractBinding =
    ::vocab::ContractBinding::from_descriptor("{domain}", DESCRIPTOR, "{version}");

/// Ordered action semantics generation, domain-separated and length-prefixed before SHA-256.
pub const ACTION_REGISTRY_GENERATION: &str = "{action_registry_generation}";

/// Saga runtime retry policy. 由 `cargo xtask codegen` 从 manifest 派生；勿手改。
pub const POLICY: ::vocab::SagaRuntimePolicySpec =
    ::vocab::SagaRuntimePolicySpec::from_static(
        {max_attempts},
        {time_budget_millis},
        ::vocab::SagaBackoff::{backoff},
        {initial_backoff_millis},
        {max_backoff_millis},
        ::vocab::SagaJitter::{jitter},
    );
{step_consts}
/// Ordered saga step bindings generated from `[saga].steps`.
pub const STEPS: &[::vocab::SagaStepBinding] = &[{steps_body}];

/// Saga contract spec（契约绑定 + runtime policy spec + ordered steps）。由 `cargo xtask codegen` 从 manifest 派生；勿手改。
pub const SPEC: {sup}SagaSpec =
    {sup}SagaSpec::from_parts(CONTRACT, POLICY, STEPS, ACTION_REGISTRY_GENERATION);

/// Sealed generated definition marker for this exact Saga identity.
#[derive(Debug, Clone, Copy)]
pub struct Definition;

impl {sup}sealed::Definition for Definition {{}}
impl {sup}Definition for Definition {{
    type Start = {first_cursor};
    const SPEC: {sup}SagaSpec = self::SPEC;
}}
{cursor_impls}
/// Terminal typestate cursor; only this cursor can finish factory construction.
#[derive(Debug, Clone, Copy)]
pub struct End;

impl {sup}sealed::End<Definition> for End {{}}
impl {sup}End<Definition> for End {{}}
"#,
        max_attempts = retry.max_attempts,
        time_budget_millis = retry.time_budget_millis,
        initial_backoff_millis = retry.initial_backoff_millis,
        max_backoff_millis = retry.max_backoff_millis,
    ))
}

fn saga_action_registry_generation(saga: &crate::contract::manifest::SagaBlock) -> String {
    fn field(hasher: &mut Sha256, value: &str) {
        hasher.update((value.len() as u64).to_be_bytes());
        hasher.update(value.as_bytes());
    }

    let mut hasher = Sha256::new();
    field(&mut hasher, "rss:saga-action-registry:v1");
    field(&mut hasher, "reverse");
    field(&mut hasher, &saga.retry.max_attempts.to_string());
    field(&mut hasher, &saga.retry.time_budget_millis.to_string());
    field(
        &mut hasher,
        match saga.retry.backoff {
            SagaBackoff::Fixed => "fixed",
            SagaBackoff::Exponential => "exponential",
        },
    );
    field(&mut hasher, &saga.retry.initial_backoff_millis.to_string());
    field(&mut hasher, &saga.retry.max_backoff_millis.to_string());
    field(
        &mut hasher,
        match saga.retry.jitter {
            SagaJitter::None => "none",
            SagaJitter::Full => "full",
        },
    );
    field(&mut hasher, &saga.steps.len().to_string());
    for step in &saga.steps {
        field(&mut hasher, step.name.as_str());
        field(&mut hasher, &step.receipt_schema);
        field(&mut hasher, &step.effect_scope);
        field(&mut hasher, &step.compensation_effect_scope);
        field(&mut hasher, "deterministic-key");
        field(&mut hasher, "receipt");
        field(
            &mut hasher,
            match step.retry_class {
                SagaRetryClass::Never => "never",
                SagaRetryClass::Transient => "transient",
            },
        );
    }
    format!("sha256:{}", lower_hex(&hasher.finalize()))
}

fn render_http_glue(
    c: &GovernedContract,
    sup: &str,
    contracts: &[GovernedContract],
) -> Result<String> {
    let domain = &c.manifest().domain;
    let owner = match c.owner().domain() {
        Some(owner) => format!("::vocab::HttpContractOwner::domain(\"{}\")", owner.as_str()),
        None => "::vocab::HttpContractOwner::framework()".to_string(),
    };
    let contract_id = &c.manifest().id;
    let version = &c.manifest().version;
    let schema_hash = c.schema_hash();
    for (field, value) in [
        ("domain", domain.as_str()),
        ("id", contract_id.as_str()),
        ("version", version.as_str()),
    ] {
        if !is_safe_codegen_ident(value) {
            bail!(
                "契约 {}/{}/{} 的 {field} 含不安全字符（防注入生成字面量）: {value:?}",
                c.manifest().kind.as_dir(),
                c.manifest().domain,
                c.manifest().version,
            );
        }
    }
    if !is_safe_codegen_string(schema_hash) {
        bail!(
            "契约 {}/{}/{} 的 schema_hash 含不安全字符（防注入生成字面量）: {schema_hash:?}",
            c.manifest().kind.as_dir(),
            c.manifest().domain,
            c.manifest().version,
        );
    }
    let mut out = format!(
        r#"
/// HTTP 契约 ID（`contract.toml` `id` 字段，单一事实源）。由 `cargo xtask codegen` 从 manifest 派生；勿手改。
pub const CONTRACT_ID: &str = "{contract_id}";

/// 契约归属绑定（`domain` + `id` + `version` + `schema_hash` 同源派生）。由 `cargo xtask codegen` 从 manifest 派生；勿手改。
pub const DESCRIPTOR: ::rss_contract::ContractDescriptor =
    ::rss_contract::ContractDescriptor::from_static_version("{contract_id}", "{version}", "{schema_hash}");

pub const CONTRACT: ::vocab::ContractBinding =
    ::vocab::ContractBinding::from_descriptor("{domain}", DESCRIPTOR, "{version}");
"#
    );
    out.push_str(&render_http_response_bindings(c, sup)?);
    if c.manifest().lifecycle != Lifecycle::Active {
        return Ok(out);
    }
    let path = c
        .manifest()
        .path
        .as_deref()
        .context("active http 契约缺 path（codegen fail-closed）")?;
    let method = c
        .manifest()
        .method
        .context("active http 契约缺 method（codegen fail-closed）")?;
    let http = c
        .manifest()
        .endpoints
        .as_ref()
        .and_then(|e| e.http.as_ref())
        .context("active http 契约缺 endpoints.http（codegen fail-closed）")?;
    let auth = http
        .auth
        .as_ref()
        .context("active http 契约缺 endpoints.http.auth（codegen fail-closed）")?;
    for (field, value) in [("path", path), ("method", method.as_wire())] {
        if !is_safe_codegen_string(value) {
            bail!(
                "契约 {}/{}/{} 的 {field} 含不安全字符（防注入生成字面量）: {value:?}",
                c.manifest().kind.as_dir(),
                c.manifest().domain,
                c.manifest().version,
            );
        }
    }
    let auth = match auth.mode {
        HttpAuthMode::Permission => {
            let permission = auth
                .permission
                .as_deref()
                .context("active permission http 契约缺 permission（codegen fail-closed）")?;
            format!(
                "::vocab::HttpRouteAuth::Permission({})",
                render_route_permission_expr(permission, "permission")?
            )
        }
        HttpAuthMode::Public => "::vocab::HttpRouteAuth::Public".to_string(),
        HttpAuthMode::Bootstrap => "::vocab::HttpRouteAuth::Bootstrap".to_string(),
        HttpAuthMode::ClientsOnly => "::vocab::HttpRouteAuth::ClientsOnly".to_string(),
        HttpAuthMode::ServiceOwned => "::vocab::HttpRouteAuth::ServiceOwned".to_string(),
    };
    let consistency_level = render_http_consistency_level(c.manifest().consistency_level);
    let local_only_conformance_marker =
        render_local_only_conformance_marker(c.manifest().consistency_level);
    let mount_key = render_http_mount_key(c)?;
    let success_status = http.success_status;
    let idempotency = match http.idempotency {
        HttpIdempotency::Idempotent => "Idempotent",
        HttpIdempotency::NonIdempotent => "NonIdempotent",
    };
    let query_parameters = render_http_query_parameters(c, method.as_wire())?;
    let effect_profile = render_http_effect_profile_consts(c)?;
    let (local_tx_evidence, local_tx) = render_http_local_tx(c, sup)?;
    let producer_binding = render_http_producer_binding(c, contracts)?;
    let response_marker = render_http_response_marker(c)?;
    let resource = render_option_str(http.resource.as_deref(), "resource")?;
    let self_scoped = http.self_scoped;
    let resource_present = http
        .resource
        .as_deref()
        .is_some_and(|resource| !resource.trim().is_empty());
    let (resource_sharing_mode, resource_sharing_reason) = match http.resource_sharing.as_ref() {
        Some(sharing) => match sharing.mode {
            HttpResourceSharingMode::Global => {
                let reason = sharing
                    .reason
                    .as_deref()
                    .filter(|reason| !reason.trim().is_empty())
                    .with_context(|| {
                        format!(
                            "契约 {}/{}/{} resourceSharing mode=global 必须声明非空 reason（codegen fail-closed）",
                            c.manifest().kind.as_dir(),
                            c.manifest().domain,
                            c.manifest().version,
                        )
                    })?;
                if !resource_present {
                    bail!(
                        "契约 {}/{}/{} resourceSharing mode=global 必须声明 endpoints.http.resource（codegen fail-closed）",
                        c.manifest().kind.as_dir(),
                        c.manifest().domain,
                        c.manifest().version,
                    );
                }
                (
                    "Global",
                    render_option_str(Some(reason), "resourceSharing.reason")?,
                )
            }
            HttpResourceSharingMode::TenantScoped => {
                if sharing.reason.is_some() {
                    bail!(
                        "契约 {}/{}/{} resourceSharing mode=tenantScoped 禁止 reason（codegen fail-closed）",
                        c.manifest().kind.as_dir(),
                        c.manifest().domain,
                        c.manifest().version,
                    );
                }
                ("TenantScoped", "None".to_string())
            }
        },
        None => ("TenantScoped", "None".to_string()),
    };
    let mut projection_fields = Vec::new();
    if let Some(projection) = &http.projection {
        for field in &projection.fields {
            for (name, value) in [
                ("projection permission", field.permission.as_str()),
                ("projection obligationKey", field.obligation_key.as_str()),
                ("projection responsePath", field.response_path.as_str()),
            ] {
                if !is_safe_codegen_string(value) {
                    bail!(
                        "契约 {}/{}/{} 的 {name} 含不安全字符（防注入生成字面量）: {value:?}",
                        c.manifest().kind.as_dir(),
                        c.manifest().domain,
                        c.manifest().version,
                    );
                }
            }
            let variant = field.field.as_vocab_variant();
            let permission =
                render_route_permission_expr(&field.permission, "projection permission")?;
            let obligation_key = &field.obligation_key;
            let response_path = &field.response_path;
            projection_fields.push(format!(
                "    {sup}HttpProjectionFieldSpec {{ field: ::vocab::ProjectionField::{variant}, permission: {permission}, obligation_key: \"{obligation_key}\", response_path: \"{response_path}\" }}"
            ));
        }
    }
    let projection_fields_body = if projection_fields.is_empty() {
        String::new()
    } else {
        format!("\n{},\n", projection_fields.join(",\n"))
    };
    let mut headers = Vec::with_capacity(http.headers.len());
    for (name, mode) in &http.headers {
        if !is_safe_codegen_string(name) {
            bail!(
                "契约 {}/{}/{} 的 header name 含不安全字符（防注入生成字面量）: {name:?}",
                c.manifest().kind.as_dir(),
                c.manifest().domain,
                c.manifest().version,
            );
        }
        let header_mode = match mode {
            HttpHeaderMode::PopulateOnly => "PopulateOnly",
            HttpHeaderMode::ServiceTokenTenantBound => "ServiceTokenTenantBound",
        };
        headers.push(format!(
            "    {sup}HttpHeaderSpec {{ name: \"{name}\", mode: {sup}HttpHeaderMode::{header_mode} }}"
        ));
    }
    let headers_body = if headers.is_empty() {
        String::new()
    } else {
        format!("\n{},\n", headers.join(",\n"))
    };
    out.push_str(&format!(
        r#"
/// 业务绝对 HTTP path（来自 `contract.toml` `path`）。由 `cargo xtask codegen` 从 manifest 派生；勿手改。
pub const PATH: &str = "{path}";

/// Query parameter vocabulary derived from this GET contract's request schema.
pub const QUERY_PARAMETERS: &[::vocab::http::HttpQueryParameterSpec] = &[{query_parameters}];

/// Field projection metadata（来自 `contract.toml` `[endpoints.http.projection]`）。由 `cargo xtask codegen` 从 manifest 派生；勿手改。
pub const PROJECTION_FIELDS: &[{sup}HttpProjectionFieldSpec] = &[{projection_fields_body}];
{effect_profile}
{local_only_conformance_marker}

/// Contract-specific route identity. Each generated HTTP contract owns a distinct marker type.
pub enum RouteMarker {{}}
{response_marker}

/// Typed route binding（metadata + contract identity 单一载体）。由 codegen 派生；勿手改。
pub const ROUTE: ::vocab::HttpRouteBinding<RouteMarker, ::vocab::http::{consistency_level}> = ::vocab::HttpRouteBinding::from_static(
    {owner},
    CONTRACT,
    PATH,
    "{method}",
    QUERY_PARAMETERS,
    ::vocab::http::HttpSuccessStatus::new({success_status}),
    ::vocab::http::HttpIdempotency::{idempotency},
    {auth},
    {resource},
    {self_scoped},
    ::vocab::http::HttpResourceSharing::{resource_sharing_mode},
    EFFECT_PROFILE,
);
{producer_binding}
{local_tx_evidence}

/// HTTP serving metadata（path/method/auth/header 单源）。由 `cargo xtask codegen` 从 manifest 派生；勿手改。
pub const SPEC: {sup}HttpSpec = {sup}HttpSpec {{
    mount_key: "{mount_key}",
    route: ROUTE.evidence(),
    local_tx: {local_tx},
    resource_sharing: {sup}HttpResourceSharingSpec {{
        mode: ROUTE.evidence().resource_sharing(),
        reason: {resource_sharing_reason},
    }},
    projection_fields: PROJECTION_FIELDS,
    headers: &[{headers_body}],
}};
"#,
        method = method.as_wire(),
    ));
    Ok(out)
}

fn render_http_query_parameters(c: &GovernedContract, method: &str) -> Result<String> {
    if method != "GET" {
        return Ok(String::new());
    }
    let Some(schema_file) = c.manifest().schemas.request.as_deref() else {
        return Ok(String::new());
    };
    let schema = c
        .schema(schema_file)
        .with_context(|| format!("parse resolved HTTP request schema {schema_file}"))?;
    let properties = schema
        .get("properties")
        .and_then(serde_json::Value::as_object)
        .with_context(|| format!("GET request schema {schema_file} must declare properties"))?;
    let required = schema
        .get("required")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(serde_json::Value::as_str)
        .collect::<BTreeSet<_>>();
    let mut rendered = Vec::with_capacity(properties.len());
    for name in properties.keys() {
        if !is_safe_codegen_string(name) {
            bail!("GET query parameter name contains unsafe characters: {name:?}");
        }
        rendered.push(format!(
            "\n    ::vocab::http::HttpQueryParameterSpec::from_static(\"{name}\", {}),",
            required.contains(name.as_str())
        ));
    }
    if !rendered.is_empty() {
        rendered.push("\n".to_string());
    }
    Ok(rendered.concat())
}

fn render_http_response_bindings(c: &GovernedContract, sup: &str) -> Result<String> {
    if c.manifest().schemas.responses.is_empty() {
        return Ok(String::new());
    }

    let mut implementations = Vec::with_capacity(c.manifest().schemas.responses.len());
    let mut specs = Vec::with_capacity(c.manifest().schemas.responses.len());
    let mut responses = Vec::with_capacity(c.manifest().schemas.responses.len());
    for (status, schema_file) in &c.manifest().schemas.responses {
        validate_schema_filename(schema_file).with_context(|| {
            format!(
                "契约 {}/{}/{} 的 response {status} schema 文件名不安全: {schema_file}",
                c.manifest().kind.as_dir(),
                c.manifest().domain,
                c.manifest().version,
            )
        })?;
        let response_ty = schema_root_type_name(c, schema_file, "HTTP response schema")?;
        implementations.push(format!(
            r#"
impl {sup}HttpResponseBinding for {response_ty} {{
    const CONTRACT: ::vocab::ContractBinding = CONTRACT;
    const STATUS: u16 = {status};
    const SCHEMA: &'static str = "{schema_file}";
}}

impl ::axum::response::IntoResponse for {response_ty} {{
    fn into_response(self) -> ::axum::response::Response {{
        let status = ::axum::http::StatusCode::from_u16(
            <Self as {sup}HttpResponseBinding>::STATUS,
        )
        .unwrap_or(::axum::http::StatusCode::INTERNAL_SERVER_ERROR);
        (status, ::axum::Json(self)).into_response()
    }}
}}
"#
        ));
        responses.push((status.get(), response_ty, schema_file.clone()));
        specs.push(format!(
            "    {sup}HttpResponseSpec {{ status: {status}, schema: \"{schema_file}\" }}"
        ));
    }
    let specs = specs.join(",\n");
    let aggregates = render_http_response_aggregates(c, &responses, sup)?;
    Ok(format!(
        r#"
{}
{aggregates}
/// Known HTTP responses, indexed by status in `contract.toml`.
pub const RESPONSES: &[{sup}HttpResponseSpec] = &[
{specs}
];
"#,
        implementations.join("")
    ))
}

struct FixedHttpErrorEnvelope {
    code: String,
    message: String,
    retryable: bool,
}

fn fixed_http_error_envelope(
    c: &GovernedContract,
    schema_file: &str,
) -> Result<Option<FixedHttpErrorEnvelope>> {
    let schema = c
        .schema(schema_file)
        .with_context(|| format!("parse declared HTTP error schema {schema_file}"))?;
    let exact_string_set = |value: Option<&serde_json::Value>, expected: &[&str]| {
        value
            .and_then(serde_json::Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(serde_json::Value::as_str)
                    .collect::<BTreeSet<_>>()
                    == expected.iter().copied().collect::<BTreeSet<_>>()
            })
            .unwrap_or(false)
    };
    let exact_object_keys = |value: &serde_json::Value, expected: &[&str]| {
        value
            .as_object()
            .map(|object| {
                object.keys().map(String::as_str).collect::<BTreeSet<_>>()
                    == expected.iter().copied().collect::<BTreeSet<_>>()
            })
            .unwrap_or(false)
    };
    let Some(root_properties) = schema
        .get("properties")
        .and_then(serde_json::Value::as_object)
    else {
        return Ok(None);
    };
    if !exact_object_keys(
        schema,
        &[
            "$schema",
            "title",
            "type",
            "required",
            "properties",
            "additionalProperties",
        ],
    ) || schema.get("type").and_then(serde_json::Value::as_str) != Some("object")
        || root_properties
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>()
            != BTreeSet::from(["error"])
        || !exact_string_set(schema.get("required"), &["error"])
        || schema
            .get("additionalProperties")
            .and_then(serde_json::Value::as_bool)
            != Some(false)
    {
        return Ok(None);
    }
    let Some(error_schema) = root_properties.get("error") else {
        return Ok(None);
    };
    let Some(error) = error_schema
        .get("properties")
        .and_then(serde_json::Value::as_object)
    else {
        return Ok(None);
    };
    let fixed_fields = ["code", "details", "message", "requestId", "retryable"];
    if !exact_object_keys(
        error_schema,
        &[
            "title",
            "type",
            "required",
            "properties",
            "additionalProperties",
        ],
    ) || error_schema.get("type").and_then(serde_json::Value::as_str) != Some("object")
        || error.keys().map(String::as_str).collect::<BTreeSet<_>>()
            != fixed_fields.iter().copied().collect::<BTreeSet<_>>()
        || !exact_string_set(error_schema.get("required"), &fixed_fields)
        || error_schema
            .get("additionalProperties")
            .and_then(serde_json::Value::as_bool)
            != Some(false)
    {
        return Ok(None);
    }
    let singleton_string = |field: &str| -> Option<String> {
        let values = error
            .get(field)
            .and_then(|value| value.get("enum"))
            .and_then(serde_json::Value::as_array)?;
        if values.len() != 1 {
            return None;
        }
        values[0].as_str().map(str::to_owned)
    };
    let Some(retryable) = error
        .get("retryable")
        .and_then(|value| value.get("const"))
        .and_then(serde_json::Value::as_bool)
    else {
        return Ok(None);
    };
    let details_is_empty = error
        .get("details")
        .and_then(|value| value.get("type"))
        .and_then(serde_json::Value::as_str)
        == Some("array")
        && error
            .get("details")
            .and_then(|value| value.get("maxItems"))
            .and_then(serde_json::Value::as_u64)
            == Some(0)
        && error
            .get("details")
            .is_some_and(|value| exact_object_keys(value, &["type", "maxItems", "items"]));
    if !details_is_empty {
        return Ok(None);
    }
    let request_id_is_string = error
        .get("requestId")
        .and_then(|value| value.get("type"))
        .and_then(serde_json::Value::as_str)
        == Some("string")
        && error
            .get("requestId")
            .is_some_and(|value| exact_object_keys(value, &["type"]));
    if !request_id_is_string {
        return Ok(None);
    }
    let (Some(code), Some(message)) = (singleton_string("code"), singleton_string("message"))
    else {
        return Ok(None);
    };
    if !error
        .get("code")
        .is_some_and(|value| exact_object_keys(value, &["type", "enum"]))
        || !error
            .get("message")
            .is_some_and(|value| exact_object_keys(value, &["type", "enum"]))
        || !error
            .get("retryable")
            .is_some_and(|value| exact_object_keys(value, &["type", "const"]))
    {
        return Ok(None);
    }
    Ok(Some(FixedHttpErrorEnvelope {
        code,
        message,
        retryable,
    }))
}

fn render_http_response_aggregates(
    c: &GovernedContract,
    responses: &[(u16, String, String)],
    sup: &str,
) -> Result<String> {
    let Some(http) = c
        .manifest()
        .endpoints
        .as_ref()
        .and_then(|endpoints| endpoints.http.as_ref())
    else {
        return Ok(String::new());
    };
    let Some((_, success_ty, _)) = responses
        .iter()
        .find(|(status, _, _)| *status == http.success_status)
    else {
        bail!(
            "契约 {}/{}/{} 的 schemas.responses 缺 successStatus={} schema",
            c.manifest().kind.as_dir(),
            c.manifest().domain,
            c.manifest().version,
            http.success_status,
        );
    };
    let errors = responses
        .iter()
        .filter(|(status, _, _)| *status != http.success_status)
        .collect::<Vec<_>>();
    if errors.is_empty() {
        return Ok(String::new());
    }
    let error_ty = format!("{success_ty}Error");
    let envelope_ty = format!("{success_ty}Envelope");
    let (success_carrier_ty, success_carrier_definition) = if is_runtime_inventory_v1(c) {
        (
            "RuntimeInventoryProjectedSuccess".to_owned(),
            format!(
                r#"
/// Opaque server-success carrier constructible only by the canonical inventory projection.
pub struct RuntimeInventoryProjectedSuccess({success_ty});

impl ::axum::response::IntoResponse for RuntimeInventoryProjectedSuccess {{
    fn into_response(self) -> ::axum::response::Response {{
        self.0.into_response()
    }}
}}
"#,
            ),
        )
    } else {
        (success_ty.clone(), String::new())
    };
    let handler_result_ty = format!(
        "{}HandlerResult",
        success_ty.strip_suffix("Response").unwrap_or(success_ty)
    );
    let framework_failure_ty = format!(
        "{}FrameworkFailure",
        success_ty.strip_suffix("Response").unwrap_or(success_ty)
    );
    let mut error_variants = Vec::with_capacity(errors.len());
    let mut error_arms = Vec::with_capacity(errors.len());
    let mut error_factories = Vec::with_capacity(errors.len());
    let mut fixed_carriers = Vec::new();
    for (status, ty, schema_file) in errors {
        let Some(fixed) = fixed_http_error_envelope(c, schema_file)? else {
            error_variants.push(format!("    Status{status}({ty})"));
            error_arms.push(format!(
                "            {error_ty}Kind::Status{status}(response) => response.into_response()"
            ));
            error_factories.push(format!(
                r#"
    /// Wrap a typed `{status}` response declared by the contract.
    pub fn status_{status}(response: {ty}) -> Self {{
        Self({error_ty}Kind::Status{status}(response))
    }}
"#
            ));
            continue;
        };
        let fixed_ty = format!("{error_ty}Status{status}");
        let code = format!("{:?}", fixed.code);
        let message = format!("{:?}", fixed.message);
        let retryable = fixed.retryable;
        error_variants.push(format!("    Status{status}({fixed_ty})"));
        error_arms.push(format!(
            "            {error_ty}Kind::Status{status}(response) => response.into_response()"
        ));
        error_factories.push(format!(
            r#"
    /// Construct the validator-approved fixed `{status}` response.
    pub fn status_{status}(request_id: ::requestidmint::WireRequestId) -> Self {{
        Self({error_ty}Kind::Status{status}({fixed_ty} {{ request_id }}))
    }}
"#
        ));
        fixed_carriers.push(format!(
            r#"
struct {fixed_ty} {{
    request_id: ::requestidmint::WireRequestId,
}}

impl ::axum::response::IntoResponse for {fixed_ty} {{
    fn into_response(self) -> ::axum::response::Response {{
        let status = ::axum::http::StatusCode::from_u16(
            <{ty} as {sup}HttpResponseBinding>::STATUS,
        )
        .unwrap_or(::axum::http::StatusCode::INTERNAL_SERVER_ERROR);
        (status, ::axum::Json(::serde_json::json!({{
            "error": {{
                "code": {code},
                "message": {message},
                "retryable": {retryable},
                "details": [],
                "requestId": self.request_id.as_str(),
            }}
        }}))).into_response()
    }}
}}
"#
        ));
    }
    let error_variants = error_variants.join(",\n");
    let error_arms = error_arms.join(",\n");
    let error_factories = error_factories.join("");
    let fixed_carriers = fixed_carriers.join("");
    Ok(format!(
        r#"
/// Declared business error responses for this contract.
pub struct {error_ty}({error_ty}Kind);

{fixed_carriers}

enum {error_ty}Kind {{
{error_variants},
}}

impl {error_ty} {{
{error_factories}}}

impl ::axum::response::IntoResponse for {error_ty} {{
    fn into_response(self) -> ::axum::response::Response {{
        match self.0 {{
{error_arms},
        }}
    }}
}}

{success_carrier_definition}
/// Complete declared response envelope. Outer `Err` is reserved for framework failures.
pub enum {envelope_ty} {{
    Success({success_carrier_ty}),
    Error({error_ty}),
}}

impl ::axum::response::IntoResponse for {envelope_ty} {{
    fn into_response(self) -> ::axum::response::Response {{
        match self {{
            Self::Success(response) => response.into_response(),
            Self::Error(response) => response.into_response(),
        }}
    }}
}}

/// Closed framework failure channel. It cannot be created from arbitrary `IntoResponse` values.
pub struct {framework_failure_ty} {{
    request_id: ::requestidmint::WireRequestId,
}}

impl {framework_failure_ty} {{
    /// Construct the fail-closed response used when framework request context is unavailable.
    pub fn internal(request_id: ::requestidmint::WireRequestId) -> Self {{
        Self {{ request_id }}
    }}
}}

impl ::axum::response::IntoResponse for {framework_failure_ty} {{
    fn into_response(self) -> ::axum::response::Response {{
        (
            ::axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            ::axum::Json(::serde_json::json!({{
                "error": {{
                    "code": "ERR_CORE_INTERNAL",
                    "message": "internal error",
                    "retryable": false,
                    "details": [],
                    "requestId": self.request_id.as_str(),
                }}
            }})),
        ).into_response()
    }}
}}

/// Exact handler output required by the generated route marker.
pub type {handler_result_ty} = ::std::result::Result<
    {envelope_ty},
    {framework_failure_ty},
>;
"#
    ))
}

fn render_http_response_marker(c: &GovernedContract) -> Result<String> {
    let Some(http) = c
        .manifest()
        .endpoints
        .as_ref()
        .and_then(|endpoints| endpoints.http.as_ref())
    else {
        return Ok("impl ::vocab::http::OpenHttpResponseMarker for RouteMarker {}".to_string());
    };
    let responses = &c.manifest().schemas.responses;
    let has_declared_error = responses
        .keys()
        .any(|status| status.get() != http.success_status);
    if !has_declared_error {
        return Ok("impl ::vocab::http::OpenHttpResponseMarker for RouteMarker {}".to_string());
    }
    let success_schema = c
        .manifest()
        .schemas
        .response(http.success_status)
        .context("declared HTTP responses must include the success schema")?;
    let success_ty = schema_root_type_name(c, success_schema, "HTTP success response schema")?;
    let handler_result_ty = format!(
        "{}HandlerResult",
        success_ty.strip_suffix("Response").unwrap_or(&success_ty)
    );
    Ok(format!(
        "impl ::vocab::http::DeclaredHttpResponseMarker for RouteMarker {{\n    type HandlerOutput = {handler_result_ty};\n}}"
    ))
}

fn render_http_consistency_level(level: ConsistencyLevel) -> &'static str {
    match level {
        ConsistencyLevel::LocalOnly => "LocalOnly",
        ConsistencyLevel::LocalTx => "LocalTx",
        ConsistencyLevel::OutboxFact => "OutboxFact",
        ConsistencyLevel::WorkflowEventual => "WorkflowEventual",
        ConsistencyLevel::DeviceLatent => "DeviceLatent",
    }
}

fn render_http_producer_binding(
    producer: &GovernedContract,
    contracts: &[GovernedContract],
) -> Result<String> {
    let producer_manifest = producer.manifest();
    if producer_manifest.consistency_level != ConsistencyLevel::OutboxFact {
        return Ok(String::new());
    }
    let outbox = producer_manifest
        .capabilities
        .outbox
        .as_ref()
        .with_context(|| {
            format!(
                "active OutboxFact HTTP {} lacks producer capability (codegen fail-closed)",
                producer_manifest.id
            )
        })?;
    if outbox.role != OutboxRole::Producer {
        bail!(
            "active OutboxFact HTTP {} has non-producer outbox role {:?} (codegen fail-closed)",
            producer_manifest.id,
            outbox.role
        );
    }
    if outbox.emits.is_empty() {
        bail!(
            "active OutboxFact HTTP {} has empty emits (codegen fail-closed)",
            producer_manifest.id
        );
    }

    let mut seen = BTreeSet::new();
    let mut emitted = Vec::with_capacity(outbox.emits.len());
    for emitted_id in &outbox.emits {
        if !seen.insert(emitted_id.as_str()) {
            bail!(
                "active OutboxFact HTTP {} repeats emitted fact {} (codegen fail-closed)",
                producer_manifest.id,
                emitted_id
            );
        }
        let matches = contracts
            .iter()
            .filter(|candidate| {
                candidate.manifest().kind == ContractKind::Event
                    && candidate.manifest().lifecycle == Lifecycle::Active
                    && candidate.manifest().id == *emitted_id
            })
            .collect::<Vec<_>>();
        let [fact] = matches.as_slice() else {
            bail!(
                "active OutboxFact HTTP {} emitted fact {} resolves to {} active events (expected exactly one)",
                producer_manifest.id,
                emitted_id,
                matches.len()
            );
        };
        let fact_manifest = fact.manifest();
        let fact_outbox = fact_manifest
            .capabilities
            .outbox
            .as_ref()
            .with_context(|| format!("emitted event {emitted_id} lacks outbox capability"))?;
        if fact_manifest.consistency_level != ConsistencyLevel::OutboxFact
            || fact_outbox.role != OutboxRole::Fact
            || fact_manifest.domain != producer_manifest.domain
        {
            bail!(
                "HTTP producer {} emitted contract {} is not a same-domain active OutboxFact fact",
                producer_manifest.id,
                emitted_id
            );
        }
        let module = module_name(&fact_manifest.domain, &fact_manifest.version);
        let path = match fact.slug() {
            Some(slug) => format!("{module}::{}", slug_module_ident(slug)?),
            None => module,
        };
        emitted.push(format!("    crate::event::{path}::CONTRACT"));
    }
    let emitted = format!("\n{},\n", emitted.join(",\n"));
    Ok(format!(
        r#"
/// Exact emitted event contracts derived from `[capabilities.outbox].emits`.
pub const EMITTED_FACTS: &[::vocab::ContractBinding] = &[{emitted}];

/// Generated producer binding（route + exact emitted facts 单一载体）。由 codegen 派生；勿手改。
pub const PRODUCER: ::vocab::http::HttpProducerBinding<RouteMarker> =
    ::vocab::http::HttpProducerBinding::from_static(ROUTE, EMITTED_FACTS);
"#
    ))
}

fn render_local_only_conformance_marker(level: ConsistencyLevel) -> &'static str {
    match level {
        ConsistencyLevel::LocalOnly => {
            r#"
/// Receipt target proving this active LocalOnly HTTP contract has a canonical conformance site.
pub enum LocalOnlyConformanceMarker {}
"#
        }
        ConsistencyLevel::LocalTx
        | ConsistencyLevel::OutboxFact
        | ConsistencyLevel::WorkflowEventual
        | ConsistencyLevel::DeviceLatent => "",
    }
}

fn render_http_mount_key(c: &GovernedContract) -> Result<String> {
    let module = module_name(&c.manifest().domain, &c.manifest().version);
    c.slug().map_or(Ok(module.clone()), |slug| {
        Ok(format!("{module}::{}", slug_module_ident(slug)?))
    })
}

pub(crate) fn rendered_http_route_evidence_path(c: &GovernedContract) -> Result<String> {
    let module = module_name(&c.manifest().domain, &c.manifest().version);
    let path = match c.slug() {
        Some(slug) => format!("{module}::{}", slug_module_ident(slug)?),
        None => module,
    };
    Ok(format!("::generated::http::{path}::ROUTE.evidence()"))
}

fn render_http_effect_profile_consts(c: &GovernedContract) -> Result<String> {
    let profile = c
        .manifest()
        .effect_profile
        .as_ref()
        .context("active http 契约缺 [effectProfile]（codegen fail-closed）")?;
    if profile.effects.is_empty() {
        bail!("active http 契约 [effectProfile].effects 为空（codegen fail-closed）");
    }

    let mut seen = BTreeSet::new();
    let mut effects = Vec::with_capacity(profile.effects.len());
    for effect in &profile.effects {
        if !seen.insert(*effect) {
            bail!("active http 契约 [effectProfile].effects 含重复值（codegen fail-closed）");
        }
        effects.push(format!(
            "    ::vocab::HttpEffectKind::{}",
            render_http_effect_kind(*effect)
        ));
    }
    let effects_body = format!("\n{},\n", effects.join(",\n"));
    Ok(format!(
        r#"
/// HTTP effect metadata（来自 `contract.toml` `[effectProfile]`）。由 `cargo xtask codegen` 从 manifest 派生；勿手改。
pub const EFFECTS: &[::vocab::HttpEffectKind] = &[{effects_body}];

/// HTTP effect profile（闭 effect vocabulary + required field）。由 `cargo xtask codegen` 从 manifest 派生；勿手改。
pub const EFFECT_PROFILE: ::vocab::HttpEffectProfile =
    ::vocab::HttpEffectProfile::new(EFFECTS);
"#
    ))
}

fn render_http_effect_kind(effect: EffectKind) -> &'static str {
    match effect {
        EffectKind::Read => "Read",
        EffectKind::Auth => "Auth",
        EffectKind::Projection => "Projection",
        EffectKind::BusinessWrite => "BusinessWrite",
        EffectKind::BusinessTransaction => "BusinessTransaction",
        EffectKind::Outbox => "Outbox",
        EffectKind::Publish => "Publish",
        EffectKind::Workflow => "Workflow",
        EffectKind::Saga => "Saga",
        EffectKind::Reconcile => "Reconcile",
        EffectKind::Worker => "Worker",
        EffectKind::CrossTenantAudit => "CrossTenantAudit",
    }
}

fn render_http_local_tx(c: &GovernedContract, sup: &str) -> Result<(String, &'static str)> {
    if c.manifest().consistency_level != ConsistencyLevel::LocalTx {
        if c.manifest().capabilities.local_tx.is_some() {
            bail!("非 LocalTx http 契约不得声明 [capabilities.localTx]（codegen fail-closed）");
        }
        return Ok((String::new(), "None"));
    }

    let local_tx = c
        .manifest()
        .capabilities
        .local_tx
        .as_ref()
        .context("LocalTx http 契约缺 [capabilities.localTx]（codegen fail-closed）")?;
    let evidence = format!(
        r#"
/// Required LocalTx capability evidence derived from `[capabilities.localTx]`.
pub const LOCAL_TX: {sup}LocalTxSpec = {sup}LocalTxSpec {{
    boundary: ::vocab::LocalTxBoundary::{},
    tx_model: ::vocab::LocalTxModel::{},
    retry: ::vocab::LocalTxRetry::{},
    commit_unknown: ::vocab::LocalTxCommitUnknown::{},
}};
"#,
        render_local_tx_boundary(local_tx.boundary),
        render_local_tx_model(local_tx.tx_model),
        render_local_tx_retry(local_tx.retry),
        render_local_tx_commit_unknown(local_tx.commit_unknown),
    );
    Ok((evidence, "Some(LOCAL_TX)"))
}

fn render_local_tx_boundary(boundary: LocalTxBoundary) -> &'static str {
    match boundary {
        LocalTxBoundary::SingleDomain => "SingleDomain",
    }
}

fn render_local_tx_model(model: LocalTxModel) -> &'static str {
    match model {
        LocalTxModel::TenantScopedUow => "TenantScopedUow",
        LocalTxModel::RepoAtomicCas => "RepoAtomicCas",
    }
}

fn render_local_tx_retry(retry: LocalTxRetry) -> &'static str {
    match retry {
        LocalTxRetry::BoundedTransient => "BoundedTransient",
    }
}

fn render_local_tx_commit_unknown(commit_unknown: LocalTxCommitUnknown) -> &'static str {
    match commit_unknown {
        LocalTxCommitUnknown::NotRetryable => "NotRetryable",
    }
}

fn render_option_str(value: Option<&str>, field: &str) -> Result<String> {
    match value {
        Some(value) => {
            if !is_safe_codegen_string(value) {
                bail!("{field} 含不安全字符（防注入生成字面量）: {value:?}");
            }
            Ok(format!("Some(\"{value}\")"))
        }
        None => Ok("None".to_string()),
    }
}

fn render_route_permission_expr(value: &str, field: &str) -> Result<String> {
    if !is_safe_codegen_string(value) {
        bail!("{field} 含不安全字符（防注入生成字面量）: {value:?}");
    }
    let variant = vocab::RoutePermissionId::parse(value)
        .map_err(|_| {
            anyhow::anyhow!("{field} 未注册到 vocab::RoutePermissionId 闭值集: {value:?}")
        })?
        .variant_name();
    Ok(format!("::vocab::RoutePermissionId::{variant}"))
}

/// command kind 派生 glue：CONTRACT / CONTRACT_ID / TOPIC 常量 + policy-exclusive producer / typed handler
/// wrapper。wrapper 泛型收口到 `command/mod.rs` 的 `CommandEmit` / `CommandJournal` / `CommandRegister`
/// seam——generated 不命名 runtime（`eventexec` Service 层），故经 seam 注入。
///
/// typed `Request` 类型名 = request schema 的 `title`（typify 用作根类型名）；拼进生成源前经
/// `syn::Ident` 收口（防注入非法标识符）。CONTRACT_ID/TOPIC 由 manifest 派生（draft 无 topic 回退用 id）。
fn render_command_glue(c: &GovernedContract, sup: &str) -> Result<String> {
    let domain = &c.manifest().domain;
    let contract_id = &c.manifest().id;
    let version = &c.manifest().version;
    let schema_hash = c.schema_hash();
    let topic = c
        .manifest()
        .topic
        .as_deref()
        .unwrap_or(contract_id.as_str());
    for (field, value) in [
        ("domain", domain.as_str()),
        ("id", contract_id.as_str()),
        ("version", version.as_str()),
        ("topic", topic),
    ] {
        if !is_safe_codegen_ident(value) {
            bail!(
                "契约 {}/{}/{} 的 {field} 含不安全字符（防注入生成字面量）: {value:?}",
                c.manifest().kind.as_dir(),
                c.manifest().domain,
                c.manifest().version,
            );
        }
    }
    if !is_safe_codegen_string(schema_hash) {
        bail!(
            "契约 {}/{}/{} 的 schema_hash 含不安全字符（防注入生成字面量）: {schema_hash:?}",
            c.manifest().kind.as_dir(),
            c.manifest().domain,
            c.manifest().version,
        );
    }
    let request_ty = command_request_type_name(c)?;
    let command = c
        .manifest()
        .command
        .as_ref()
        .context("command 契约缺 [command] block（codegen fail-closed）")?;
    if command.reconcile.is_some() && command.journal != CommandJournalPolicy::Required {
        bail!(
            "fenced reconcile command {} must declare command.journal=required",
            c.manifest().id
        );
    }
    let policy = command.journal;
    let (policy_variant, policy_trait, wrapper) = match policy {
        CommandJournalPolicy::Required => (
            "Required",
            "JournaledCommandContract",
            format!(
                r#"
/// Journal-required producer wrapper；idempotency key 不提供随机降级路径。
pub async fn journal_async<J: {sup}CommandJournal>(
    journal: &J,
    request: {request_ty},
    tenant: ::rss_request_context::TenantId,
    subject_id: J::SubjectId,
    actor: J::Actor,
    idempotency_key: ::std::string::String,
) -> ::core::result::Result<J::Outcome, J::Error> {{
    journal.journal::<Contract>(&request, tenant, subject_id, actor, &idempotency_key).await
}}
"#,
            ),
        ),
        CommandJournalPolicy::None => (
            "None",
            "DirectCommandContract",
            format!(
                r#"
/// Direct producer wrapper；仅 manifest 明确 `journal = "none"` 时生成。
pub async fn emit_async<E: {sup}CommandEmit>(
    emitter: &E,
    request: {request_ty},
    tenant: ::rss_request_context::TenantId,
    subject_id: E::SubjectId,
    actor: E::Actor,
    idempotency_key: ::core::option::Option<::std::string::String>,
) -> ::core::result::Result<(), E::Error> {{
    emitter.emit::<Contract>(&request, tenant, subject_id, actor, idempotency_key.as_deref()).await
}}
"#,
            ),
        ),
    };
    // A fenced reconcile contract has exactly one producer funnel: the generated fenced carrier
    // consumed by eventexec's attempt-scoped mint. Its journal policy remains metadata for the
    // provider transaction, but it must not also acquire the ordinary producer marker/wrapper.
    let (policy_impl, wrapper) = if command.reconcile.is_some() {
        (String::new(), String::new())
    } else {
        (
            format!("impl {sup}{policy_trait} for Contract {{}}"),
            wrapper,
        )
    };
    let fenced_reconcile = match command.reconcile {
        Some(reconcile) => {
            match reconcile.fencing {
                CommandReconcileFencing::DeviceGenerationEpochV1 => {
                    validate_device_generation_epoch_v1_schema(c)?;
                }
            }
            format!(
                r#"
/// Schema-typed device reconcile input whose generation and epoch fence are carried by the request.
/// The request is private so callers cannot pair canonical fence fields with a different payload.
#[derive(Debug)]
pub struct FencedReconcileCommand {{
    request: {request_ty},
}}

impl {sup}private::Sealed for FencedReconcileCommand {{}}

impl {sup}FencedCommandSpec for FencedReconcileCommand {{
    type Contract = Contract;

    fn request(&self) -> &<Self::Contract as {sup}CommandContract>::Request {{ &self.request }}
    fn device_id(&self) -> ::uuid::Uuid {{ self.request.device_id }}
    fn desired_generation(&self) -> ::std::num::NonZeroU64 {{ self.request.desired_generation }}
    fn fence_epoch(&self) -> ::std::num::NonZeroU64 {{ self.request.fence_epoch }}
    fn intent_digest(&self) -> &str {{ self.request.intent_digest.as_str() }}
    fn deadline_epoch_seconds(&self) -> ::std::num::NonZeroU64 {{ self.request.deadline_epoch_seconds }}
}}

/// Build the only reconcile-authoring carrier for this fenced command.
pub fn fenced_reconcile_command(request: {request_ty}) -> FencedReconcileCommand {{
    FencedReconcileCommand {{ request }}
}}
"#,
            )
        }
        None => String::new(),
    };
    Ok(format!(
        r#"
/// 命令契约 ID（`contract.toml` `id` 字段，单一事实源）。由 `cargo xtask codegen` 从 manifest 派生；勿手改。
pub const CONTRACT_ID: &str = "{contract_id}";

/// 契约归属绑定（`domain` + `id` + `version` + `schema_hash` 同源派生）。由 `cargo xtask codegen` 从 manifest 派生；勿手改。
pub const DESCRIPTOR: ::rss_contract::ContractDescriptor =
    ::rss_contract::ContractDescriptor::from_static_version("{contract_id}", "{version}", "{schema_hash}");

pub const CONTRACT: ::vocab::ContractBinding =
    ::vocab::ContractBinding::from_descriptor("{domain}", DESCRIPTOR, "{version}");

/// 稳定命令 topic（broker routing key，`<domain>.commands.<name>`；active command 来自 `contract.toml`
/// `topic`，draft 回退用 id）。由 `cargo xtask codegen` 从 manifest 派生；勿手改。
pub const TOPIC: &str = "{topic}";

/// command manifest 的 sealed generated 表示；构造器仅 generated crate 可见。
pub const SPEC: {sup}CommandSpec =
    {sup}CommandSpec::new(CONTRACT, TOPIC, {sup}CommandJournalPolicy::{policy_variant});

/// Zero-sized generated carrier that binds this command's request schema, routing metadata and policy.
pub struct Contract;

impl {sup}private::Sealed for Contract {{}}

impl {sup}CommandContract for Contract {{
    type Request = {request_ty};
    const SPEC: {sup}CommandSpec = SPEC;
}}

{policy_impl}

{fenced_reconcile}

{wrapper}

/// Consumer wrapper（consumer 侧对称收口）：把 typed [`{request_ty}`] handler 注册到注入的
/// [`super::CommandRegister`]。baked `CONTRACT` / `TOPIC`。由 `cargo xtask codegen` 派生；勿手改。
pub fn register_handler<Reg, H, Fut>(registrar: &mut Reg, handler: H) -> Reg::Output
where
    Reg: {sup}CommandRegister,
    H: Fn({request_ty}) -> Fut + ::core::marker::Send + ::core::marker::Sync + 'static,
    Fut: ::core::future::Future<Output = Reg::Outcome> + ::core::marker::Send + 'static,
{{
    registrar.register::<Contract, H, Fut>(handler)
}}
"#
    ))
}

fn validate_device_generation_epoch_v1_schema(c: &GovernedContract) -> Result<()> {
    let schema_file = c
        .manifest()
        .schemas
        .request
        .as_deref()
        .context("fenced command 契约缺 [schemas].request")?;
    let declared = c
        .declared_schema(schema_file)
        .with_context(|| format!("fenced command request schema 未捕获: {schema_file}"))?;
    let schema = declared.resolved();
    if schema.get("type").and_then(serde_json::Value::as_str) != Some("object")
        || schema
            .get("additionalProperties")
            .and_then(serde_json::Value::as_bool)
            != Some(false)
    {
        bail!(
            "fenced command request schema {} 必须是 additionalProperties=false 的 object",
            schema_file
        );
    }
    let required = schema
        .get("required")
        .and_then(serde_json::Value::as_array)
        .context("fenced command request schema 缺 required array")?;
    let properties = schema
        .get("properties")
        .and_then(serde_json::Value::as_object)
        .context("fenced command request schema 缺 properties object")?;
    let canonical = [
        (
            "deviceId",
            serde_json::json!({"type": "string", "format": "uuid"}),
        ),
        (
            "desiredGeneration",
            serde_json::json!({
                "type": "integer", "format": "int64", "minimum": 1,
                "maximum": 9_223_372_036_854_775_807_u64
            }),
        ),
        (
            "fenceEpoch",
            serde_json::json!({
                "type": "integer", "format": "int64", "minimum": 1,
                "maximum": 9_223_372_036_854_775_807_u64
            }),
        ),
        (
            "intentDigest",
            serde_json::json!({
                "type": "string",
                "pattern": "^sha256:[0-9a-f]{64}$",
                "x-redaction": "secret"
            }),
        ),
        (
            "deadlineEpochSeconds",
            serde_json::json!({
                "type": "integer", "format": "int64", "minimum": 1,
                "maximum": 9_223_372_036_854_u64
            }),
        ),
    ];
    for (field, expected) in canonical {
        let is_required = required
            .iter()
            .any(|value| value.as_str().is_some_and(|value| value == field));
        if !is_required || properties.get(field) != Some(&expected) {
            bail!(
                "fenced command request schema {} 的 canonical 字段 {field} 类型/约束不准确",
                schema_file
            );
        }
    }
    Ok(())
}

/// 从 command 契约的 request schema 提取 typify 根类型名（= schema `title`）。拼进生成源前经
/// `syn::Ident` 收口——拒非法 Rust 标识符 / raw `r#`（防注入生成代码；与 R7 互为上下游 funnel）。
fn command_request_type_name(c: &GovernedContract) -> Result<String> {
    let file = c
        .manifest()
        .schemas
        .request
        .as_deref()
        .context("command 契约缺 [schemas].request（R4 应已守）")?;
    schema_root_type_name(c, file, "command request schema")
}

fn schema_root_type_name(
    c: &GovernedContract,
    schema_file: &str,
    label: &'static str,
) -> Result<String> {
    validate_schema_filename(schema_file).with_context(|| {
        format!(
            "契约 {}/{}/{} 的 {label} 文件名不安全: {schema_file}",
            c.manifest().kind.as_dir(),
            c.manifest().domain,
            c.manifest().version
        )
    })?;
    let declared = c
        .declared_schema(schema_file)
        .with_context(|| format!("{label} 未捕获 promoted schema: {schema_file}"))?;
    let value = declared.resolved();
    let title = value
        .get("title")
        .and_then(serde_json::Value::as_str)
        .with_context(|| format!("{label} {schema_file} 缺 title（codegen 派生类型名所需）"))?;
    if title.starts_with("r#") || syn::parse_str::<syn::Ident>(title).is_err() {
        bail!("{label} title 非法 Rust 类型标识符（防注入生成代码）: {title:?}");
    }
    Ok(title.to_string())
}

/// event kind 订阅注册 glue（从 manifest 派生，不消费 schema）。
///
/// 派生 `CONTRACT_ID`、`TOPIC`（active 必有 topic；draft 无 topic 则回退用 id）、sealed emit carrier，
/// 以及每个 `[[subscriptions]]` 的 typed subscription carrier。`SubscriptionSpec` 类型定义在
/// `event/mod.rs`（特化 event mod.rs），并嵌入单一 `EventSpec`；本文件经 `sup` 前缀引用（扁平
/// `super::` / 嵌套子模块 `super::super::`），避免每个 event 模块重复定义同名 struct
///（INVARIANT CODEGEN-DRIFT-01）。
///
/// **防注入守卫（review #216 F6）**：consumer / group 被拼进 Rust 字符串字面量；codegen 可独立于
/// `cargo xtask contract validate`（R7）运行，故此处经 [`is_safe_codegen_ident`] 再次校验形态，含引号 /
/// 反斜杠 / 空白等可破坏字面量 / 注入源码的字符即 `bail!`。与 R7 互为上下游闭环 funnel（authoring 拒绝 +
/// 派生防御），非只锁单侧 callsite。
fn render_event_glue(c: &GovernedContract, sup: &str) -> Result<String> {
    let contract_id = &c.manifest().id;
    // domain + id + version + schema_hash 同源绑成 `CONTRACT: ContractBinding`（#1193/#1618）；
    // domain 取自 manifest domain 字段（非 id 派生），schema_hash 取 declared schema canonical digest。
    let domain = &c.manifest().domain;
    let version = &c.manifest().version;
    let schema_hash = c.schema_hash();
    // active event 必有 topic（R8）；draft 无 topic 则回退用 id，保持确定性（不出现 Option 条件代码分歧）。
    let topic = c
        .manifest()
        .topic
        .as_deref()
        .unwrap_or(contract_id.as_str());
    let payload_type = event_payload_type_name(c)?;
    // 防注入自守（review #271 F4）：domain / id / topic 拼进生成 Rust 字符串字面量（`CONTRACT_ID` / `TOPIC` /
    // `CONTRACT::from_static`），与 consumer / group 同款经 [`is_safe_codegen_ident`] 收口——codegen 可独立于
    // `contract validate`（R7）运行，故不依赖上游已收口，自守拒引号 / 反斜杠 / 控制字符等可破坏字面量的字符
    // （容 `[a-z0-9._-]`：`_seed` / 点分 id / 连字符 topic 均合法）。红用例 `event_glue_rejects_unsafe_domain`。
    for (field, value) in [
        ("domain", domain.as_str()),
        ("id", contract_id.as_str()),
        ("version", version.as_str()),
        ("topic", topic),
    ] {
        if !is_safe_codegen_ident(value) {
            bail!(
                "契约 {}/{}/{} 的 {field} 含不安全字符（防注入生成字面量）: {value:?}",
                c.manifest().kind.as_dir(),
                c.manifest().domain,
                c.manifest().version,
            );
        }
    }
    if !is_safe_codegen_string(schema_hash) {
        bail!(
            "契约 {}/{}/{} 的 schema_hash 含不安全字符（防注入生成字面量）: {schema_hash:?}",
            c.manifest().kind.as_dir(),
            c.manifest().domain,
            c.manifest().version,
        );
    }
    // producer partition strategy 与 subscription list 同属一个 EventSpec；不同订阅不得各自漂移。
    let mut subscription_defs: Vec<String> = Vec::with_capacity(c.manifest().subscriptions.len());
    let mut subscription_refs: Vec<String> = Vec::with_capacity(c.manifest().subscriptions.len());
    let mut subscription_wrappers: Vec<String> =
        Vec::with_capacity(c.manifest().subscriptions.len());
    let mut seen_consumers = BTreeSet::new();
    let partition_key = c
        .manifest()
        .subscriptions
        .first()
        .map(|subscription| subscription.topology.partition_key)
        .unwrap_or(crate::contract::manifest::PartitionKeyStrategy::None);
    for s in &c.manifest().subscriptions {
        if !is_safe_codegen_ident(&s.consumer) {
            bail!(
                "契约 {}/{}/{} 的 subscription consumer 含不安全字符（防注入生成字面量）: {:?}",
                c.manifest().kind.as_dir(),
                c.manifest().domain,
                c.manifest().version,
                s.consumer
            );
        }
        if !is_safe_codegen_ident(&s.group) {
            bail!(
                "契约 {}/{}/{} 的 subscription group 含不安全字符（防注入生成字面量）: {:?}",
                c.manifest().kind.as_dir(),
                c.manifest().domain,
                c.manifest().version,
                s.group
            );
        }
        if !seen_consumers.insert(s.consumer.as_str()) {
            bail!(
                "契约 {}/{}/{} 对 consumer {:?} 声明多个 subscription；typed wrapper 名无法唯一派生",
                c.manifest().kind.as_dir(),
                c.manifest().domain,
                c.manifest().version,
                s.consumer,
            );
        }
        if s.topology.partition_key != partition_key {
            bail!(
                "契约 {}/{}/{} 的 subscriptions partitionKey 不一致；producer strategy 必须单源",
                c.manifest().kind.as_dir(),
                c.manifest().domain,
                c.manifest().version,
            );
        }
        let execution = match s.execution {
            SubscriptionExecution::AdapterNative => "AdapterNative",
            SubscriptionExecution::DomainEffect => "DomainEffect",
        };
        let effect = match s.effect {
            None => "None".to_string(),
            Some(SubscriptionEffect::SettingsConfigVersionRefresh) => {
                format!("Some({sup}SubscriptionEffect::SettingsConfigVersionRefresh)")
            }
        };
        let external_effect_policy = match s.external_effect_policy {
            ExternalEffectPolicy::TransactionalOnly => "TransactionalOnly",
            ExternalEffectPolicy::IdempotencyKey => "IdempotencyKey",
            ExternalEffectPolicy::Reconcile => "Reconcile",
            ExternalEffectPolicy::Compensated => "Compensated",
        };
        let dispatch = subscription_dispatch_variant(c, &s.consumer)?;
        let consumer_type = producer_domain_variant(&s.consumer)?;
        let consumer_fn = s.consumer.replace(['.', '-'], "_");
        let subscription_const = format!("{}_SUBSCRIPTION", consumer_fn.to_ascii_uppercase());
        let spec = format!(
            "{sup}SubscriptionSpec::new(\"{}\", \"{}\", {sup}SubscriptionDispatchKey::{dispatch}, {sup}SubscriberReadiness::{}, {sup}SubscriptionExecution::{execution}, {effect}, ::vocab::ExternalEffectPolicy::{external_effect_policy})",
            s.consumer,
            s.group,
            match s.topology.readiness {
                crate::contract::manifest::SubscriberReadiness::Required => "Required",
            }
        );
        subscription_defs.push(format!(
            "/// Generated subscription coordinates for consumer `{}`.\npub const {subscription_const}: {sup}SubscriptionSpec = {spec};",
            s.consumer
        ));
        subscription_refs.push(format!("    {subscription_const}"));
        subscription_wrappers.push(format!(
            r#"
/// Sealed subscription carrier for consumer `{consumer}`.
pub struct {consumer_type}Subscription;

impl {sup}private::Sealed for {consumer_type}Subscription {{}}

impl {sup}EventSubscription for {consumer_type}Subscription {{
    type Contract = Contract;
    const SPEC: {sup}SubscriptionSpec = {subscription_const};
}}

/// Register the generated `{consumer}` subscription without caller-authored transport coordinates.
pub fn subscribe_{consumer_fn}<Reg: {sup}EventSubscribe>(
    registrar: &mut Reg,
    capability: Reg::Capability,
) -> Reg::Output {{
    registrar.subscribe::<{consumer_type}Subscription>(capability)
}}
"#,
            consumer = s.consumer,
        ));
    }
    let subscription_defs = if subscription_defs.is_empty() {
        String::new()
    } else {
        format!("\n{}\n", subscription_defs.join("\n\n"))
    };
    let subs_body = if subscription_refs.is_empty() {
        String::new()
    } else {
        format!("\n{},\n", subscription_refs.join(",\n"))
    };
    let subscription_wrappers = subscription_wrappers.join("");

    Ok(format!(
        r#"
/// 契约 ID（`contract.toml` `id` 字段，单一事实源）。由 `cargo xtask codegen` 从 manifest 派生；勿手改。
pub const CONTRACT_ID: &str = "{contract_id}";

/// 稳定事件 topic（broker routing key；active event 来自 `contract.toml` `topic` 字段，draft 回退用 id）。
/// 由 `cargo xtask codegen` 从 manifest 派生；勿手改。
pub const TOPIC: &str = "{topic}";

/// 契约绑定（`domain` + `id` + `version` + `schema_hash` 同源类型化常量，#1193/#1618）。sealed event carrier
/// 把该绑定交给 runtime encoder 生成 `eventexec::event::ReviewedEvent`，杜绝调用方分别 author
/// domain / contract_id / topic。
/// 由 `cargo xtask codegen` 从 manifest `domain` + `id` + `version` + declared schema 派生；勿手改（golden 字节锁，INVARIANT
/// CONTRACT-BINDING-FUNNEL-01）。
pub const DESCRIPTOR: ::rss_contract::ContractDescriptor =
    ::rss_contract::ContractDescriptor::from_static_version("{contract_id}", "{version}", "{schema_hash}");

pub const CONTRACT: ::vocab::ContractBinding =
    ::vocab::ContractBinding::from_descriptor("{domain}", DESCRIPTOR, "{version}");

/// Generated contract + topic identity carried by this event payload.
pub const FACT: ::vocab::EventFactBinding =
    ::vocab::EventFactBinding::from_static(CONTRACT, TOPIC);

/// Zero-sized generated carrier binding this event payload to its exact contract and topology.
pub struct Contract;

impl {sup}private::Sealed for Contract {{}}

impl {sup}EventContract for Contract {{
    type Payload = {payload_type};
    const SPEC: {sup}EventSpec = SPEC;
    const FACT: ::vocab::EventFactBinding = FACT;
}}

/// Author this event through the only typed generated emit seam.
pub async fn emit<E: {sup}EventEmit>(
    emitter: &E,
    payload: {payload_type},
    tenant: ::rss_request_context::TenantId,
    occurred_at: ::rss_contract::Timepoint,
    subject_id: E::SubjectId,
    actor: E::Actor,
    idempotency_key: E::IdempotencyKey,
) -> ::core::result::Result<E::Output, E::Error> {{
    emitter
        .emit::<Contract>(&payload, tenant, occurred_at, subject_id, actor, idempotency_key)
        .await
}}

{subscription_defs}

/// 单一事件 topology spec；producer 与 subscriptions 不存在平行 registry。
pub const SPEC: {sup}EventSpec = {sup}EventSpec::new(
    CONTRACT,
    TOPIC,
    {sup}PartitionKeyStrategy::{partition_variant},
    &[{subs_body}],
);

{subscription_wrappers}
"#,
        partition_variant = match partition_key {
            crate::contract::manifest::PartitionKeyStrategy::None => "None",
            crate::contract::manifest::PartitionKeyStrategy::Aggregate => "Aggregate",
        },
    ))
}

fn event_payload_type_name(c: &GovernedContract) -> Result<String> {
    let file = c
        .manifest()
        .schemas
        .payload
        .as_deref()
        .context("event 契约缺 [schemas].payload（R4 应已守）")?;
    schema_root_type_name(c, file, "event payload schema")
}

/// codegen 安全标识符（review #216 F6）：仅 `[a-z0-9._-]`（消费者域名 ∪ 点分 group 名的字符全集）——
/// 拒引号 / 反斜杠 / 空白 / 控制符等可破坏生成字符串字面量 / 注入 Rust 源的字符。精确语法（域名 vs 点分 id）
/// 由 validate R7 守（authoring 闸门）；本守卫只做字面量安全的下界（防注入），与 R7 互为闭环 funnel。
fn is_safe_codegen_ident(s: &str) -> bool {
    !s.is_empty()
        && s.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-' || b == b'_'
        })
}

fn is_safe_codegen_string(s: &str) -> bool {
    !s.bytes()
        .any(|b| b == b'"' || b == b'\\' || b.is_ascii_control())
}

const DEFER_STRING_LENGTH_VALIDATION: &str = "x-defer-string-length-validation";
const RSS_LENGTH_UNIT: &str = "x-rss-length-unit";
const UTF8_BYTES_LENGTH_UNIT: &str = "utf8-bytes";
const DEFERRED_LENGTH_ALLOWED_KEYS: &[&str] = &[
    "$comment",
    "default",
    "deprecated",
    "description",
    "examples",
    "maxLength",
    "minLength",
    "readOnly",
    "title",
    "type",
    "writeOnly",
    "x-pii",
    "x-protection",
    "x-redaction",
    DEFER_STRING_LENGTH_VALIDATION,
];

/// 收集由 schema 显式声明“长度约束留给领域 policy”的 string 字段。marker 只改变 generated
/// transport constructor；原 schema 的 min/max 继续参与文档、hash 与外部契约元数据。
fn collect_deferred_string_lengths(
    schema: &serde_json::Value,
) -> Result<BTreeMap<String, BTreeSet<String>>> {
    fn visit(node: &serde_json::Value, out: &mut BTreeMap<String, BTreeSet<String>>) -> Result<()> {
        if let Some(object) = node.as_object() {
            if let Some(properties) = object.get("properties").and_then(|value| value.as_object()) {
                for (property_name, property) in properties {
                    let Some(marker) = property.get(DEFER_STRING_LENGTH_VALIDATION) else {
                        continue;
                    };
                    let defer = marker.as_bool().ok_or_else(|| {
                        anyhow::anyhow!(
                            "{DEFER_STRING_LENGTH_VALIDATION} at property {property_name:?} must be boolean"
                        )
                    })?;
                    if !defer {
                        continue;
                    }
                    let property_schema = property.as_object().ok_or_else(|| {
                        anyhow::anyhow!(
                            "{DEFER_STRING_LENGTH_VALIDATION} at property {property_name:?} requires an object schema"
                        )
                    })?;
                    let unsupported: Vec<&str> = property_schema
                        .keys()
                        .map(String::as_str)
                        .filter(|key| !DEFERRED_LENGTH_ALLOWED_KEYS.contains(key))
                        .collect();
                    if !unsupported.is_empty() {
                        bail!(
                            "{DEFER_STRING_LENGTH_VALIDATION} at property {property_name:?} cannot discard additional schema keywords: {}",
                            unsupported.join(", ")
                        );
                    }
                    if property.get("type").and_then(|value| value.as_str()) != Some("string")
                        || !(property.get("minLength").is_some()
                            || property.get("maxLength").is_some())
                    {
                        bail!(
                            "{DEFER_STRING_LENGTH_VALIDATION} at property {property_name:?} requires a constrained string"
                        );
                    }
                    let title = object.get("title").and_then(|value| value.as_str()).ok_or_else(
                        || {
                            anyhow::anyhow!(
                                "{DEFER_STRING_LENGTH_VALIDATION} at property {property_name:?} requires a titled containing object"
                            )
                        },
                    )?;
                    out.entry(title.to_string())
                        .or_default()
                        .insert(property_name.clone());
                }
            }
            for value in object.values() {
                visit(value, out)?;
            }
        } else if let Some(items) = node.as_array() {
            for value in items {
                visit(value, out)?;
            }
        }
        Ok(())
    }

    let mut out = BTreeMap::new();
    visit(schema, &mut out)?;
    Ok(out)
}

fn merge_deferred_string_lengths(
    target: &mut BTreeMap<String, BTreeSet<String>>,
    source: BTreeMap<String, BTreeSet<String>>,
) {
    for (struct_name, fields) in source {
        target.entry(struct_name).or_default().extend(fields);
    }
}

/// 收集 RSS UTF-8 byte 长度 marker。最近的 titled schema 与相对 JSON path 共同构成稳定
/// identity：可区分 property/oneOf/array.items，也能消除 resolved shared definition 的重复展开。
fn collect_utf8_byte_length_markers(schema: &serde_json::Value) -> Result<BTreeSet<String>> {
    fn visit(
        node: &serde_json::Value,
        anchor: Option<&str>,
        path: &mut Vec<String>,
        out: &mut BTreeSet<String>,
    ) -> Result<()> {
        if let Some(items) = node.as_array() {
            for (index, value) in items.iter().enumerate() {
                path.push(index.to_string());
                visit(value, anchor, path, out)?;
                path.pop();
            }
            return Ok(());
        }
        let Some(object) = node.as_object() else {
            return Ok(());
        };
        let title = object.get("title").and_then(serde_json::Value::as_str);
        let saved_path = title.map(|_| std::mem::take(path));
        let anchor = title.or(anchor);
        if let Some(unit) = object.get(RSS_LENGTH_UNIT) {
            let unit = unit.as_str().ok_or_else(|| {
                anyhow::anyhow!("{RSS_LENGTH_UNIT} at /{} must be a string", path.join("/"))
            })?;
            if unit != UTF8_BYTES_LENGTH_UNIT {
                bail!(
                    "{RSS_LENGTH_UNIT} at /{} only accepts {UTF8_BYTES_LENGTH_UNIT:?}, got {unit:?}",
                    path.join("/")
                );
            }
            if object.get("type").and_then(serde_json::Value::as_str) != Some("string") {
                bail!(
                    "{RSS_LENGTH_UNIT} at /{} requires type=string",
                    path.join("/")
                );
            }
            let max = object
                .get("maxLength")
                .and_then(serde_json::Value::as_u64)
                .filter(|max| *max > 0)
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "{RSS_LENGTH_UNIT} at /{} requires a positive integer maxLength",
                        path.join("/")
                    )
                })?;
            let anchor = anchor.ok_or_else(|| {
                anyhow::anyhow!(
                    "{RSS_LENGTH_UNIT} at /{} requires a titled ancestor",
                    path.join("/")
                )
            })?;
            let identity = format!("{anchor}:/{}:{max}", path.join("/"));
            if !out.insert(identity.clone()) {
                bail!("duplicate {RSS_LENGTH_UNIT} marker identity {identity}");
            }
        }
        for (key, value) in object {
            path.push(key.clone());
            visit(value, anchor, path, out)?;
            path.pop();
        }
        if let Some(saved_path) = saved_path {
            *path = saved_path;
        }
        Ok(())
    }

    let mut out = BTreeSet::new();
    visit(schema, None, &mut Vec::new(), &mut out)?;
    Ok(out)
}

fn tuple_schema(attrs: &[syn::Attribute]) -> Result<Option<serde_json::Value>> {
    let mut docs = String::new();
    for attr in attrs.iter().filter(|attr| attr.path().is_ident("doc")) {
        let syn::Meta::NameValue(meta) = &attr.meta else {
            continue;
        };
        let syn::Expr::Lit(expr) = &meta.value else {
            continue;
        };
        let syn::Lit::Str(line) = &expr.lit else {
            continue;
        };
        docs.push_str(&line.value());
        docs.push('\n');
    }
    let Some((_, tail)) = docs.split_once("```json") else {
        return Ok(None);
    };
    let Some((json, _)) = tail.split_once("```") else {
        bail!("generated tuple rustdoc has an unterminated JSON schema fence");
    };
    Ok(Some(
        serde_json::from_str(json.trim()).context("parse generated tuple JSON schema rustdoc")?,
    ))
}

/// typify 继续生成 sealed newtype constructor funnel；本 pass 只重写标记类型的 maximum
/// comparator。minLength/pattern 与未标 standard maxLength 仍保持 Draft-07 字符语义。
fn rewrite_utf8_byte_length_validation(
    file: &mut syn::File,
    marker_identities: &BTreeSet<String>,
) -> Result<()> {
    let mut marked_types = BTreeMap::<String, usize>::new();
    for item in &file.items {
        let syn::Item::Struct(item) = item else {
            continue;
        };
        if !matches!(item.fields, syn::Fields::Unnamed(_)) {
            continue;
        }
        let Some(schema) = tuple_schema(&item.attrs)? else {
            continue;
        };
        let Some(unit) = schema.get(RSS_LENGTH_UNIT) else {
            continue;
        };
        if unit.as_str() != Some(UTF8_BYTES_LENGTH_UNIT)
            || schema.get("type").and_then(serde_json::Value::as_str) != Some("string")
        {
            bail!(
                "generated marked tuple {} lost closed string marker shape",
                item.ident
            );
        }
        let max = schema
            .get("maxLength")
            .and_then(serde_json::Value::as_u64)
            .and_then(|max| usize::try_from(max).ok())
            .ok_or_else(|| {
                anyhow::anyhow!("generated marked tuple {} lost maxLength", item.ident)
            })?;
        marked_types.insert(item.ident.to_string(), max);
    }
    if marked_types.len() != marker_identities.len() {
        bail!(
            "{RSS_LENGTH_UNIT} marker/type count mismatch: markers={}, generated_types={}",
            marker_identities.len(),
            marked_types.len()
        );
    }

    struct MaximumToBytes<'a> {
        argument: &'a syn::Ident,
        max: usize,
        comparisons: usize,
    }
    impl syn::visit_mut::VisitMut for MaximumToBytes<'_> {
        fn visit_expr_binary_mut(&mut self, node: &mut syn::ExprBinary) {
            syn::visit_mut::visit_expr_binary_mut(self, node);
            if !matches!(node.op, syn::BinOp::Gt(_)) {
                return;
            }
            let syn::Expr::MethodCall(count) = node.left.as_ref() else {
                return;
            };
            if count.method != "count" || !count.args.is_empty() {
                return;
            }
            let syn::Expr::MethodCall(chars) = count.receiver.as_ref() else {
                return;
            };
            if chars.method != "chars" || !chars.args.is_empty() {
                return;
            }
            let syn::Expr::Path(receiver) = chars.receiver.as_ref() else {
                return;
            };
            if !receiver.path.is_ident(self.argument) {
                return;
            }
            let syn::Expr::Lit(limit) = node.right.as_ref() else {
                return;
            };
            let syn::Lit::Int(limit) = &limit.lit else {
                return;
            };
            if limit.base10_parse::<usize>().ok() != Some(self.max) {
                return;
            }
            let argument = self.argument;
            *node.left = syn::parse_quote!(#argument.len());
            self.comparisons += 1;
        }

        fn visit_lit_str_mut(&mut self, literal: &mut syn::LitStr) {
            let expected = format!("longer than {} characters", self.max);
            if literal.value() == expected {
                *literal = syn::LitStr::new(
                    &format!("longer than {} UTF-8 bytes", self.max),
                    literal.span(),
                );
            }
        }
    }

    let mut rewritten = BTreeSet::new();
    for item in &mut file.items {
        let syn::Item::Impl(item) = item else {
            continue;
        };
        let Some((_, trait_path, _)) = &item.trait_ else {
            continue;
        };
        if trait_path
            .segments
            .last()
            .is_none_or(|segment| segment.ident != "FromStr")
        {
            continue;
        }
        let syn::Type::Path(self_type) = item.self_ty.as_ref() else {
            continue;
        };
        let Some(type_name) = self_type
            .path
            .segments
            .last()
            .map(|segment| segment.ident.to_string())
        else {
            continue;
        };
        let Some(max) = marked_types.get(&type_name).copied() else {
            continue;
        };
        let method = item
            .items
            .iter_mut()
            .find_map(|item| match item {
                syn::ImplItem::Fn(method) if method.sig.ident == "from_str" => Some(method),
                _ => None,
            })
            .ok_or_else(|| anyhow::anyhow!("marked type {type_name} has no FromStr constructor"))?;
        let argument = method
            .sig
            .inputs
            .first()
            .and_then(|argument| match argument {
                syn::FnArg::Typed(argument) => match argument.pat.as_ref() {
                    syn::Pat::Ident(ident) => Some(&ident.ident),
                    _ => None,
                },
                syn::FnArg::Receiver(_) => None,
            })
            .ok_or_else(|| {
                anyhow::anyhow!("marked type {type_name} has unexpected FromStr input")
            })?;
        let mut visitor = MaximumToBytes {
            argument,
            max,
            comparisons: 0,
        };
        syn::visit_mut::VisitMut::visit_block_mut(&mut visitor, &mut method.block);
        if visitor.comparisons != 1 {
            bail!(
                "marked type {type_name} maximum rewrite count must be 1, got {}",
                visitor.comparisons
            );
        }
        rewritten.insert(type_name);
    }
    if rewritten.len() != marker_identities.len() || rewritten.len() != marked_types.len() {
        bail!(
            "{RSS_LENGTH_UNIT} rewrite count mismatch: markers={}, types={}, rewrites={}",
            marker_identities.len(),
            marked_types.len(),
            rewritten.len()
        );
    }
    Ok(())
}

/// typify 为 constrained string 生成 tuple newtype，并让 `FromStr` 承载 min/max 检查。对显式 marker
/// 字段重写这一唯一 constructor 漏斗；`Deserialize` 与各 `TryFrom` 均委托 `FromStr`，因此不会在认证前
/// 拒绝原始输入，最终 NFC 后的 authoritative policy 仍由 secure::PasswordPolicy 执行。
fn defer_marked_string_length_validation(
    file: &mut syn::File,
    policies: &BTreeMap<String, BTreeSet<String>>,
) -> Result<()> {
    let tuple_names: BTreeSet<String> = file
        .items
        .iter()
        .filter_map(|item| {
            let syn::Item::Struct(item) = item else {
                return None;
            };
            matches!(item.fields, syn::Fields::Unnamed(_)).then(|| item.ident.to_string())
        })
        .collect();
    let mut deferred_types = BTreeSet::new();
    for (struct_name, fields) in policies {
        let item = file
            .items
            .iter()
            .find_map(|item| match item {
                syn::Item::Struct(item) if item.ident == struct_name => Some(item),
                _ => None,
            })
            .ok_or_else(|| {
                anyhow::anyhow!("marked containing type {struct_name:?} was not generated")
            })?;
        for wire_name in fields {
            let field = item
                .fields
                .iter()
                .find(|field| {
                    field.ident.as_ref().is_some_and(|ident| {
                        serde_rename(field).unwrap_or_else(|| ident.to_string()) == *wire_name
                    })
                })
                .ok_or_else(|| {
                    anyhow::anyhow!("marked field {struct_name}.{wire_name} was not generated")
                })?;
            let referenced = referenced_tuple_structs(&field.ty, &tuple_names);
            if referenced.len() != 1 {
                bail!(
                    "marked field {struct_name}.{wire_name} must reference exactly one constrained string type, found {}",
                    referenced.len()
                );
            }
            deferred_types.extend(referenced);
        }
    }

    let mut rewritten = BTreeSet::new();
    for item in &mut file.items {
        let syn::Item::Impl(item) = item else {
            continue;
        };
        let Some((_, trait_path, _)) = &item.trait_ else {
            continue;
        };
        if trait_path
            .segments
            .last()
            .is_none_or(|segment| segment.ident != "FromStr")
        {
            continue;
        }
        let syn::Type::Path(self_type) = item.self_ty.as_ref() else {
            continue;
        };
        let Some(type_name) = self_type
            .path
            .segments
            .last()
            .map(|segment| segment.ident.to_string())
        else {
            continue;
        };
        if !deferred_types.contains(&type_name) {
            continue;
        }
        let method = item
            .items
            .iter_mut()
            .find_map(|item| match item {
                syn::ImplItem::Fn(method) if method.sig.ident == "from_str" => Some(method),
                _ => None,
            })
            .ok_or_else(|| anyhow::anyhow!("marked type {type_name} has no FromStr constructor"))?;
        let value = method
            .sig
            .inputs
            .first()
            .and_then(|argument| match argument {
                syn::FnArg::Typed(argument) => match argument.pat.as_ref() {
                    syn::Pat::Ident(ident) => Some(&ident.ident),
                    _ => None,
                },
                syn::FnArg::Receiver(_) => None,
            })
            .ok_or_else(|| {
                anyhow::anyhow!("marked type {type_name} has unexpected FromStr input")
            })?;
        method.block = syn::parse_quote!({ Ok(Self(#value.to_string())) });
        rewritten.insert(type_name);
    }
    if rewritten != deferred_types {
        bail!(
            "marked constrained string constructors were not rewritten: expected {deferred_types:?}, got {rewritten:?}"
        );
    }
    Ok(())
}

/// generated struct 统一派生 `secure::Redact`，字段策略从 schema property 的 `x-pii` / `x-redaction`
/// 注入为 `#[redact(...)]`。非敏感字段默认 `public`，使所有 generated DTO 都有安全 `Debug`，不再裸
/// derive `Debug` 或把敏感类型去掉 `Debug`。
fn apply_redaction_policy(file: &mut syn::File, policies: &StructPolicies) {
    let tuple_policies = tuple_struct_policies(file, policies);
    for item in &mut file.items {
        let syn::Item::Struct(s) = item else {
            continue;
        };
        rewrite_struct_derives(&mut s.attrs);
        let struct_policies = policies.get(&s.ident.to_string());
        for field in &mut s.fields {
            let policy = if let Some(ident) = &field.ident {
                let wire_name = serde_rename(field).unwrap_or_else(|| ident.to_string());
                struct_policies
                    .and_then(|fields| fields.get(&wire_name))
                    .copied()
                    .unwrap_or_default()
            } else {
                tuple_policies
                    .get(&s.ident.to_string())
                    .copied()
                    .unwrap_or_default()
            };
            field.attrs.push(redact_attr(policy));
        }
    }
}

/// typify 将含 `minLength`/`maxLength` 等约束的 scalar property 提升为 tuple newtype。
/// schema redaction 单源仍挂在父 property，因此沿生成 AST 的字段类型引用把策略传给 tuple 字段。
fn tuple_struct_policies(
    file: &syn::File,
    policies: &StructPolicies,
) -> BTreeMap<String, FieldPolicy> {
    let tuple_names: BTreeSet<String> = file
        .items
        .iter()
        .filter_map(|item| {
            let syn::Item::Struct(item) = item else {
                return None;
            };
            matches!(item.fields, syn::Fields::Unnamed(_)).then(|| item.ident.to_string())
        })
        .collect();
    let mut tuple_policies = BTreeMap::new();

    for item in &file.items {
        let syn::Item::Struct(item) = item else {
            continue;
        };
        let struct_policies = policies.get(&item.ident.to_string());
        for field in &item.fields {
            let Some(ident) = &field.ident else {
                continue;
            };
            let wire_name = serde_rename(field).unwrap_or_else(|| ident.to_string());
            let policy = struct_policies
                .and_then(|fields| fields.get(&wire_name))
                .copied()
                .unwrap_or_default();
            for tuple_name in referenced_tuple_structs(&field.ty, &tuple_names) {
                tuple_policies
                    .entry(tuple_name)
                    .and_modify(|current| *current = merge_tuple_policy(*current, policy))
                    .or_insert(policy);
            }
        }
    }
    tuple_policies
}

fn referenced_tuple_structs(ty: &syn::Type, tuple_names: &BTreeSet<String>) -> BTreeSet<String> {
    struct TupleReferenceVisitor<'a> {
        tuple_names: &'a BTreeSet<String>,
        referenced: BTreeSet<String>,
    }

    impl<'ast> syn::visit::Visit<'ast> for TupleReferenceVisitor<'_> {
        fn visit_type_path(&mut self, node: &'ast syn::TypePath) {
            for segment in &node.path.segments {
                let name = segment.ident.to_string();
                if self.tuple_names.contains(&name) {
                    self.referenced.insert(name);
                }
            }
            syn::visit::visit_type_path(self, node);
        }
    }

    let mut visitor = TupleReferenceVisitor {
        tuple_names,
        referenced: BTreeSet::new(),
    };
    syn::visit::Visit::visit_type(&mut visitor, ty);
    visitor.referenced
}

/// 同一 tuple type 被复用且字段策略冲突时取更保守策略；两个非 public 策略不一致则固定 secret，
/// 避免 schema 复用令生成类型的独立 Debug 暴露任一调用点视为敏感的值。
fn merge_tuple_policy(left: FieldPolicy, right: FieldPolicy) -> FieldPolicy {
    if left == right || right == FieldPolicy::default() {
        left
    } else if left == FieldPolicy::default() {
        right
    } else {
        FieldPolicy {
            sensitivity: Sensitivity::Secret,
            mode: None,
        }
    }
}

fn rewrite_struct_derives(attrs: &mut Vec<syn::Attribute>) {
    for attr in attrs {
        if !attr.path().is_ident("derive") {
            continue;
        }
        let Ok(paths) = attr.parse_args_with(
            syn::punctuated::Punctuated::<syn::Path, syn::Token![,]>::parse_terminated,
        ) else {
            continue;
        };
        let mut kept: syn::punctuated::Punctuated<syn::Path, syn::Token![,]> = paths
            .into_iter()
            .filter(|p| p.segments.last().is_none_or(|seg| seg.ident != "Debug"))
            .collect();
        let has_redact = kept
            .iter()
            .any(|p| p.segments.last().is_some_and(|seg| seg.ident == "Redact"));
        if !has_redact {
            kept.push(syn::parse_quote!(::secure::Redact));
        }
        attr.meta = syn::parse_quote!(derive(#kept));
    }
}

fn redact_attr(policy: FieldPolicy) -> syn::Attribute {
    let mode = policy
        .mode
        .map(|mode| syn::LitStr::new(mode.as_wire(), proc_macro2::Span::call_site()));
    match (policy.sensitivity, mode) {
        (Sensitivity::Public, None) => syn::parse_quote!(#[redact(sensitivity = public)]),
        (Sensitivity::Public, Some(mode)) => {
            syn::parse_quote!(#[redact(sensitivity = public, mode = #mode)])
        }
        (Sensitivity::Internal, None) => syn::parse_quote!(#[redact(sensitivity = internal)]),
        (Sensitivity::Internal, Some(mode)) => {
            syn::parse_quote!(#[redact(sensitivity = internal, mode = #mode)])
        }
        (Sensitivity::Secret, None) => syn::parse_quote!(#[redact(sensitivity = secret)]),
        (Sensitivity::Secret, Some(mode)) => {
            syn::parse_quote!(#[redact(sensitivity = secret, mode = #mode)])
        }
        (Sensitivity::Pii(kind), None) => {
            let kind = sensitivity_ident(kind);
            syn::parse_quote!(#[redact(sensitivity = #kind)])
        }
        (Sensitivity::Pii(kind), Some(mode)) => {
            let kind = sensitivity_ident(kind);
            syn::parse_quote!(#[redact(sensitivity = #kind, mode = #mode)])
        }
    }
}

fn sensitivity_ident(kind: PiiKind) -> syn::Ident {
    syn::Ident::new(kind.as_sensitivity(), proc_macro2::Span::call_site())
}

fn render_field_protection_impls(file: &syn::File, policies: &StructProtectionPolicies) -> String {
    let mut out = String::new();
    for item in &file.items {
        let syn::Item::Struct(s) = item else {
            continue;
        };
        let struct_name = s.ident.to_string();
        let Some(fields) = policies.get(&struct_name) else {
            continue;
        };
        if fields.is_empty() {
            continue;
        }
        out.push_str(&format!(
            "\nimpl crate::FieldProtectionMetadata for {struct_name} {{\n    const FIELD_PROTECTIONS: &'static [crate::FieldProtectionSpec] = &[\n"
        ));
        for (field_path, policy) in fields {
            out.push_str(&format!(
                "        crate::FieldProtectionSpec {{ field_path: {}, at_rest: {}, mode: {}, key_scope: {}, aad: {}, reason: {} }},\n",
                rust_string_lit(field_path),
                render_at_rest(policy.at_rest),
                render_protection_mode(policy.mode),
                render_option_string(policy.key_scope.as_deref()),
                render_aad_dims(&policy.aad),
                render_option_string(policy.reason.as_deref()),
            ));
        }
        out.push_str("    ];\n}\n");
    }
    out
}

fn render_at_rest(at_rest: AtRest) -> &'static str {
    match at_rest {
        AtRest::Plain => "crate::ProtectionAtRest::Plain",
        AtRest::Encrypt => "crate::ProtectionAtRest::Encrypt",
    }
}

fn render_protection_mode(mode: Option<ProtectionMode>) -> String {
    match mode {
        Some(ProtectionMode::Randomized) => "Some(crate::ProtectionMode::Randomized)".to_string(),
        Some(ProtectionMode::Deterministic) => {
            "Some(crate::ProtectionMode::Deterministic)".to_string()
        }
        Some(ProtectionMode::BlindIndex) => "Some(crate::ProtectionMode::BlindIndex)".to_string(),
        None => "None".to_string(),
    }
}

fn render_aad_dims(dims: &[AadDim]) -> String {
    if dims.is_empty() {
        return "&[]".to_string();
    }
    let values = dims
        .iter()
        .map(|dim| match dim {
            AadDim::Tenant => "crate::ProtectionAadDim::Tenant",
            AadDim::ConfigKey => "crate::ProtectionAadDim::ConfigKey",
            AadDim::Field => "crate::ProtectionAadDim::Field",
            AadDim::SchemaVersion => "crate::ProtectionAadDim::SchemaVersion",
        })
        .collect::<Vec<_>>()
        .join(", ");
    format!("&[{values}]")
}

fn render_option_string(value: Option<&str>) -> String {
    value
        .map(|value| format!("Some({})", rust_string_lit(value)))
        .unwrap_or_else(|| "None".to_string())
}

fn rust_string_lit(value: &str) -> String {
    format!("{value:?}")
}

fn serde_rename(field: &syn::Field) -> Option<String> {
    for attr in &field.attrs {
        if !attr.path().is_ident("serde") {
            continue;
        }
        let mut rename = None;
        let _ = attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("rename") {
                let value: syn::LitStr = meta.value()?.parse()?;
                rename = Some(value.value());
            }
            Ok(())
        });
        if rename.is_some() {
            return rename;
        }
    }
    None
}

/// typify 对**全 optional 字段** struct（如 GET 列表端点的纯分页 query）生成手写 `impl Default`——clippy
/// `derivable_impls` 判其等价于 `#[derive(Default)]`。committed generated 勿手改（`codegen --check` 守）+
/// 章程禁 module/crate-level allow ⇒ codegen 注入 **item-level** `#[allow(clippy::derivable_impls)]` 到每个
/// `impl Default` 块（与 [`strip_sensitive_debug`] 同款 syn 后处理，单源在 codegen，输出由 golden 锁）。
/// `INVARIANT: CODEGEN-DERIVABLE-DEFAULT-ALLOW-01` { level = "Medium", exec = "check", source = "code" }。
fn allow_derivable_default_impls(file: &mut syn::File) {
    for item in &mut file.items {
        let syn::Item::Impl(imp) = item else {
            continue;
        };
        // 仅 `impl Default for X`（trait impl，trait path 末段标识符 == Default）。
        let is_default_impl = imp
            .trait_
            .as_ref()
            .and_then(|(_, path, _)| path.segments.last())
            .is_some_and(|seg| seg.ident == "Default");
        if is_default_impl {
            imp.attrs
                .push(syn::parse_quote!(#[allow(clippy::derivable_impls)]));
        }
    }
}

/// typify 的 `pub mod defaults` 包含 `default_u64<T, const V: u64>() -> T` 辅助函数，内部用
/// `.unwrap()` 将 `u64` const 转换到目标类型——const 泛型保证转换不会失败，但 clippy `unwrap_used`
/// 无法感知 const 语义，会误报。章程禁 module-level allow ⇒ codegen 注入 **item-level**
/// `#[allow(clippy::unwrap_used)]` 到 `defaults` 模块内的每个 `fn`（与 `allow_derivable_default_impls`
/// 同款 syn 后处理，单源在 codegen，输出由 golden 锁）。
/// `INVARIANT: CODEGEN-DEFAULTS-UNWRAP-ALLOW-01` { level = "Medium", exec = "check", source = "code" }。
fn allow_unwrap_in_defaults_mod(file: &mut syn::File) {
    for item in &mut file.items {
        let syn::Item::Mod(module) = item else {
            continue;
        };
        // 仅 `pub mod defaults`。
        if module.ident != "defaults" {
            continue;
        }
        let Some((_, ref mut content)) = module.content else {
            continue;
        };
        for inner in content.iter_mut() {
            if let syn::Item::Fn(f) = inner {
                f.attrs
                    .push(syn::parse_quote!(#[allow(clippy::unwrap_used)]));
            }
        }
    }
}

/// typify emits fallible construction for compile-time-authored `regress` patterns inside
/// conversion impls. The canonical schema has already been parsed and governed, so the static
/// pattern cannot be caller-controlled. Keep the exception on only the generated impls that
/// contain such initialization.
fn allow_unwrap_in_static_regex_impls(file: &mut syn::File) {
    use quote::ToTokens as _;

    for item in &mut file.items {
        let syn::Item::Impl(item) = item else {
            continue;
        };
        if item
            .to_token_stream()
            .to_string()
            .contains("regress :: Regex")
        {
            item.attrs
                .push(syn::parse_quote!(#[allow(clippy::unwrap_used)]));
        }
    }
}

/// 文件头：`@generated` 标记。派生码经 typify→prettyplease→rustfmt 三段成形（见模块 doc），勿手改。
fn generated_header(source: &str) -> String {
    format!("// @generated by `cargo xtask codegen` — DO NOT EDIT. Source: {source}\n")
}

/// event kind mod.rs 特化：含 `SubscriptionSpec` POD 定义（零额外依赖，纯 `&'static str` 字段）。
/// 各 event `{domain}_{version}.rs` 经 `super::SubscriptionSpec` 引用此定义，消除重复（CODEGEN-DRIFT-01）。
const SUBSCRIPTION_SPEC_DEF: &str = r#"
mod private {
    /// Private implementation seal shared by generated event and subscription carriers.
    pub trait Sealed {}
}

/// Schema, contract and topology carrier generated once per event contract.
///
/// The private supertrait prevents downstream implementations, so callers cannot pair an
/// arbitrary payload with another event's contract, schema hash or topic.
pub trait EventContract: private::Sealed {
    /// Schema-generated payload type for this event.
    type Payload: ::serde::Serialize;
    /// Exact generated topology for this event.
    const SPEC: EventSpec;
    /// Exact generated contract and topic binding for this event.
    const FACT: ::vocab::EventFactBinding;
}

/// Runtime bridge used exclusively by per-event generated `emit` wrappers.
///
/// Implementations receive a sealed [`EventContract`]; no raw contract, schema, topic or envelope
/// coordinate appears in this API.
pub trait EventEmit {
    /// Event authoring failure.
    type Error;
    /// Reviewed event value returned to the caller.
    type Output;
    /// Runtime-owned envelope subject identity.
    type SubjectId: ::core::marker::Send;
    /// Runtime-owned envelope actor.
    type Actor: ::core::marker::Send;
    /// Runtime-owned stable idempotency input.
    type IdempotencyKey: ::core::marker::Send;
    /// Encode and review one payload through its sealed generated carrier.
    #[allow(clippy::too_many_arguments)]
    fn emit<C>(
        &self,
        payload: &C::Payload,
        tenant: ::rss_request_context::TenantId,
        occurred_at: ::rss_contract::Timepoint,
        subject_id: Self::SubjectId,
        actor: Self::Actor,
        idempotency_key: Self::IdempotencyKey,
    ) -> impl ::core::future::Future<
        Output = ::core::result::Result<Self::Output, Self::Error>,
    > + ::core::marker::Send
    where
        C: EventContract,
        C::Payload: ::core::marker::Send + ::core::marker::Sync;
}

/// One manifest-derived subscription bound to its event contract and transport coordinates.
pub trait EventSubscription: private::Sealed {
    /// Event contract consumed by this subscription.
    type Contract: EventContract;
    /// Generated consumer, group, dispatch and execution policy.
    const SPEC: SubscriptionSpec;
}

/// Bootstrap registration bridge used exclusively by generated subscription wrappers.
pub trait EventSubscribe {
    /// Runtime-owned handler capability associated with the generated subscription.
    type Capability;
    /// Registration result.
    type Output;
    /// Register one sealed subscription without caller-authored coordinates.
    fn subscribe<S: EventSubscription>(&mut self, capability: Self::Capability) -> Self::Output;
}

/// Partition-key policy generated from event topology metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PartitionKeyStrategy {
    /// The event is not partitioned by an aggregate key.
    None,
    /// The event carries exactly one aggregate partition key.
    Aggregate,
}

/// Startup-readiness policy for a generated subscriber.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubscriberReadiness {
    /// The subscriber must be healthy before the runtime is ready.
    Required,
}

/// Handler execution boundary generated from subscription metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubscriptionExecution {
    /// The adapter owns decoding and execution without a domain callback.
    AdapterNative,
    /// Runtime assembly must inject the declared domain effect handler.
    DomainEffect,
}

/// Closed set of domain effects supported by generated subscriptions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubscriptionEffect {
    /// Refresh settings configuration after a version-change fact.
    SettingsConfigVersionRefresh,
}

/// 一个 event contract 的唯一 producer/subscriber topology 规格。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EventSpec {
    contract: ::vocab::ContractBinding,
    topic: &'static str,
    partition_key: PartitionKeyStrategy,
    subscriptions: &'static [SubscriptionSpec],
}

impl EventSpec {
    pub(crate) const fn new(
        contract: ::vocab::ContractBinding,
        topic: &'static str,
        partition_key: PartitionKeyStrategy,
        subscriptions: &'static [SubscriptionSpec],
    ) -> Self { Self { contract, topic, partition_key, subscriptions } }
    /// Contract binding carried by producer and consumer paths.
    pub const fn contract(self) -> ::vocab::ContractBinding { self.contract }
    /// Stable contract identifier.
    pub const fn contract_id(self) -> &'static str { self.contract.contract_id() }
    /// Stable event topic.
    pub const fn topic(self) -> &'static str { self.topic }
    /// Generated schema version.
    pub const fn schema_version(self) -> &'static str { self.contract.version() }
    /// Generated schema fingerprint.
    pub const fn schema_hash(self) -> &'static str { self.contract.schema_hash() }
    /// Partition-key policy.
    pub const fn partition_key(self) -> PartitionKeyStrategy { self.partition_key }
    /// Generated subscriber declarations.
    pub const fn subscriptions(self) -> &'static [SubscriptionSpec] { self.subscriptions }
}

/// 订阅只表达 consumer 端事实；producer 事实由外层 EventSpec 单源携带。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SubscriptionSpec {
    consumer: &'static str,
    group: &'static str,
    dispatch: SubscriptionDispatchKey,
    readiness: SubscriberReadiness,
    execution: SubscriptionExecution,
    effect: Option<SubscriptionEffect>,
    external_effect_policy: ::vocab::ExternalEffectPolicy,
}

impl SubscriptionSpec {
    pub(crate) const fn new(
        consumer: &'static str,
        group: &'static str,
        dispatch: SubscriptionDispatchKey,
        readiness: SubscriberReadiness,
        execution: SubscriptionExecution,
        effect: Option<SubscriptionEffect>,
        external_effect_policy: ::vocab::ExternalEffectPolicy,
    ) -> Self {
        Self {
            consumer,
            group,
            dispatch,
            readiness,
            execution,
            effect,
            external_effect_policy,
        }
    }
    /// Consumer domain identifier.
    pub const fn consumer(self) -> &'static str { self.consumer }
    /// Durable consumer group.
    pub const fn group(self) -> &'static str { self.group }
    /// Closed runtime dispatch identity derived from the contract identity and consumer.
    pub const fn dispatch(self) -> SubscriptionDispatchKey { self.dispatch }
    /// Runtime-readiness policy.
    pub const fn readiness(self) -> SubscriberReadiness { self.readiness }
    /// Handler execution boundary.
    pub const fn execution(self) -> SubscriptionExecution { self.execution }
    /// Domain effect required by this subscription, when execution is domain-owned.
    pub const fn effect(self) -> Option<SubscriptionEffect> { self.effect }
    /// Policy for effects outside the ConsumerTx database transaction.
    pub const fn external_effect_policy(self) -> ::vocab::ExternalEffectPolicy {
        self.external_effect_policy
    }
}
"#;

const HTTP_SPEC_DEF: &str = r#"
/// Type-level binding between a generated response DTO and its contract status.
pub trait HttpResponseBinding {
    const CONTRACT: ::vocab::ContractBinding;
    const STATUS: u16;
    const SCHEMA: &'static str;
}

/// Erased response metadata for documentation and runtime registries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HttpResponseSpec {
    pub status: u16,
    pub schema: &'static str,
}

/// HTTP serving metadata generated from `contract.toml`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HttpSpec {
    /// Canonical `Domain::init` mount identity derived from generated module + discovered slug.
    pub mount_key: &'static str,
    pub route: ::vocab::HttpRouteEvidence,
    pub local_tx: Option<LocalTxSpec>,
    pub resource_sharing: HttpResourceSharingSpec,
    pub projection_fields: &'static [HttpProjectionFieldSpec],
    pub headers: &'static [HttpHeaderSpec],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocalTxSpec {
    pub boundary: ::vocab::LocalTxBoundary,
    pub tx_model: ::vocab::LocalTxModel,
    pub retry: ::vocab::LocalTxRetry,
    pub commit_unknown: ::vocab::LocalTxCommitUnknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HttpResourceSharingSpec {
    pub mode: ::vocab::http::HttpResourceSharing,
    pub reason: Option<&'static str>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HttpProjectionFieldSpec {
    pub field: ::vocab::ProjectionField,
    pub permission: ::vocab::RoutePermissionId,
    pub obligation_key: &'static str,
    pub response_path: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HttpHeaderSpec {
    pub name: &'static str,
    pub mode: HttpHeaderMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpHeaderMode {
    PopulateOnly,
    ServiceTokenTenantBound,
}
"#;

const SAGA_SPEC_DEF: &str = r#"
/// Saga contract metadata generated from `contract.toml`.
pub type SagaSpec = ::vocab::SagaContractBinding;

pub(crate) mod sealed {
    pub trait Definition {}
    pub trait StepMarker {}
    pub trait Step<D: super::Definition> {}
    pub trait Receipt<S: super::StepMarker> {}
    pub trait End<D: super::Definition> {}
}

/// Sealed marker for one exact generated Saga definition.
pub trait Definition: sealed::Definition + Sized {
    /// First cursor in the generated ordered step chain.
    type Start: Step<Self>;
    /// Complete pinned identity and execution semantics.
    const SPEC: SagaSpec;
}

/// Definition-independent sealed marker used by the authoring `SagaStep<Marker>` trait.
pub trait StepMarker: sealed::StepMarker + Sized {
    /// The only receipt DTO accepted for this step.
    type Receipt: Receipt<Self>;
    /// Complete generated step binding.
    const BINDING: ::vocab::SagaStepBinding;
}

/// One cursor in a definition-specific ordered typestate chain.
pub trait Step<D: Definition>: StepMarker + sealed::Step<D> {
    /// Next cursor; either another `Step<D>` or the generated terminal `End<D>`.
    type Next;
}

/// Sealed association between a generated receipt DTO and its owning step marker.
pub trait Receipt<S: StepMarker>: sealed::Receipt<S> {}

/// Sealed terminal cursor. Factory `finish()` is only available in this state.
pub trait End<D: Definition>: sealed::End<D> {}
"#;

/// command kind mod.rs 特化：定义 policy-exclusive `CommandEmit` / `CommandJournal` 与
/// `CommandRegister` seam。generated 仅依赖 basis（serde），无法命名 runtime（`eventexec` Service 层）；
/// runtime 以 typed dispatcher 实现 seam，并在 crate 内构造 reviewed DTO。零额外依赖（serde + core）。
const COMMAND_SEAM_DEF: &str = r#"
/// Durable journal policy generated from command contract metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandJournalPolicy {
    /// The command must use the durable journal path.
    Required,
    /// The command may use the direct dispatch path.
    None,
}

/// Generated routing and schema metadata for one command contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommandSpec {
    contract: ::vocab::ContractBinding,
    topic: &'static str,
    journal: CommandJournalPolicy,
}

impl CommandSpec {
    pub(crate) const fn new(
        contract: ::vocab::ContractBinding,
        topic: &'static str,
        journal: CommandJournalPolicy,
    ) -> Self { Self { contract, topic, journal } }
    /// Contract ownership and schema binding.
    pub const fn contract(self) -> ::vocab::ContractBinding { self.contract }
    /// Stable command topic.
    pub const fn topic(self) -> &'static str { self.topic }
    /// Durable journal policy.
    pub const fn journal(self) -> CommandJournalPolicy { self.journal }
}

mod private {
    /// Private implementation seal shared by generated carriers.
    pub trait Sealed {}
}

/// Schema and routing carrier generated once per command contract.
///
/// The private supertrait prevents downstream implementations, so a request type and [`CommandSpec`]
/// cannot be paired independently at a public seam.
pub trait CommandContract: private::Sealed {
    /// Schema-generated request type for this command.
    type Request: ::serde::Serialize;
    /// Routing, schema and journal metadata bound to [`Self::Request`].
    const SPEC: CommandSpec;
}

/// Marker for contracts whose policy permits direct dispatch.
pub trait DirectCommandContract: CommandContract {}

/// Marker for contracts whose policy requires durable journaling.
pub trait JournaledCommandContract: CommandContract {}

/// Sealed schema-typed input for generation/epoch-fenced device reconcile commands.
///
/// Implementations are generated only when the manifest opts into the closed fencing protocol and
/// its request schema carries the exact canonical fields. Runtime identity is deliberately absent.
pub trait FencedCommandSpec: private::Sealed {
    /// Per-command carrier that binds the request and routing metadata.
    type Contract: CommandContract;

    /// Borrow the generated request.
    fn request(&self) -> &<Self::Contract as CommandContract>::Request;
    /// Canonical target device identifier.
    fn device_id(&self) -> ::uuid::Uuid;
    /// Canonical desired generation.
    fn desired_generation(&self) -> ::std::num::NonZeroU64;
    /// Canonical fencing epoch.
    fn fence_epoch(&self) -> ::std::num::NonZeroU64;
    /// Canonical digest of the device command intent.
    fn intent_digest(&self) -> &str;
    /// Canonical absolute deadline in epoch seconds.
    fn deadline_epoch_seconds(&self) -> ::std::num::NonZeroU64;
}

/// Producer 收口 seam——仅供 `journal = "none"` 的命令直接 dispatch。
///
/// per-command `emit_async` wrapper 经本 seam 泛型收口；runtime 的 typed dispatcher 将不可外部构造的
/// `CommandSpec` 转换为 reviewed command，再交 `CommandDispatchStore`。由 `cargo xtask codegen` 派生；勿手改。
pub trait CommandEmit {
    /// emit 失败类型（实现绑定，如 `eventexec::command::CommandEmitError`）。
    type Error;
    /// bridge 绑定的事件主体类型（生产 impl 应绑定为 `diport::EnvelopeSubjectId`）。
    type SubjectId: ::core::marker::Send;
    /// bridge 绑定的 actor 类型（生产 impl 应绑定为 `diport::OutboxActor`）。
    type Actor: ::core::marker::Send;
    /// 把 typed 命令 `request` 经 runtime emit 落 durable outbox。`contract` / `topic` 由 `C` 的
    /// associated `SPEC` 注入；`request` 是 associated typed payload（实现侧 `serde_json` 编码）；`tenant` 是
    /// **runtime 必填**的 typed RLS scope；`subject_id` / `actor` 是
    /// **runtime 必填**的 typed envelope identity；`idempotency_key`
    /// 是**可选**业务幂等键——`Some` ⇒ runtime 以独立 keyring 派生 keyed alias probes，`None` ⇒ provider
    /// 在事务内 mint fresh canonical id；raw key 不进入 provider 或持久化。
    ///
    /// # Impl guide（runtime dispatcher 作者参考）
    ///
    /// 实现须序列化 typed request、派生 sealed alias probes、透传 identity，并只把 reviewed intent 交给 provider store。
    /// 域 crate 不得直接 impl 本 trait（生产 impl 集合由 `COMMAND-IMPL-ALLOWLIST-01#provider-set` 守）。
    #[allow(clippy::too_many_arguments)]
    fn emit<C>(
        &self,
        request: &C::Request,
        tenant: ::rss_request_context::TenantId,
        subject_id: Self::SubjectId,
        actor: Self::Actor,
        idempotency_key: ::core::option::Option<&str>,
    ) -> impl ::core::future::Future<Output = ::core::result::Result<(), Self::Error>> + ::core::marker::Send
    where
        C: DirectCommandContract,
        C::Request: ::core::marker::Send + ::core::marker::Sync;
}

/// Durable journal seam；journal-required wrapper 强制传递业务幂等键。
pub trait CommandJournal {
    /// Journal dispatch failure.
    type Error;
    /// Stable journal dispatch outcome.
    type Outcome;
    /// Bridge-bound envelope subject type.
    type SubjectId: ::core::marker::Send;
    /// Bridge-bound envelope actor type.
    type Actor: ::core::marker::Send;
    /// Persist one typed command through its generated journaled contract carrier.
    #[allow(clippy::too_many_arguments)]
    fn journal<C>(
        &self,
        request: &C::Request,
        tenant: ::rss_request_context::TenantId,
        subject_id: Self::SubjectId,
        actor: Self::Actor,
        idempotency_key: &str,
    ) -> impl ::core::future::Future<Output = ::core::result::Result<Self::Outcome, Self::Error>> + ::core::marker::Send
    where
        C: JournaledCommandContract,
        C::Request: ::core::marker::Send + ::core::marker::Sync;
}

/// Consumer 收口 seam——命令 handler 注册能力（consumer 侧对称收口）。
///
/// per-command `register_handler` wrapper 经本 seam 泛型收口；唯一 sanctioned 实现是组合根 registrar
/// （委托 `eventexec::command::register_command_handler` → `run_consumer` + claimer 两阶段去重）。
/// 由 `cargo xtask codegen` 派生；勿手改。
pub trait CommandRegister {
    /// handler 返回的处置结果类型（实现绑定，如 `consistency::HandleResult`）。
    type Outcome;
    /// `register` 的返回类型（如 `Result<(), KernelError>`）。
    type Output;
    /// 把 `C::Request` handler 绑到同一 carrier 的 contract/topic。typed decode + claimer 接线在实现侧。
    fn register<C, H, Fut>(
        &mut self,
        handler: H,
    ) -> Self::Output
    where
        C: CommandContract,
        C::Request: for<'de> ::serde::Deserialize<'de> + ::core::marker::Send + 'static,
        H: Fn(C::Request) -> Fut + ::core::marker::Send + ::core::marker::Sync + 'static,
        Fut: ::core::future::Future<Output = Self::Outcome> + ::core::marker::Send + 'static;
}
"#;

const FIELD_PROTECTION_METADATA_DEF: &str = r#"
/// Field-level at-rest protection metadata generated from schema `x-protection`.
///
/// This is declarative metadata only. It does not perform encryption/decryption and intentionally
/// does not depend on runtime protection types such as `KeyProvider`, `ProtectionContext`, or AAD
/// constructors.
pub trait FieldProtectionMetadata {
    /// Field protection declarations for this DTO, expressed in wire field paths.
    const FIELD_PROTECTIONS: &'static [FieldProtectionSpec];
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FieldProtectionSpec {
    /// Dotted wire path from the DTO root, for example `value` or `profile.secret`.
    ///
    /// Rust field names produced by codegen, such as `store_id`, are never used here.
    pub field_path: &'static str,
    /// At-rest declaration. `Plain` is emitted only when schema explicitly says `atRest: plain`.
    pub at_rest: ProtectionAtRest,
    /// Encryption mode for encrypted fields. `None` means `at_rest` is `Plain`.
    pub mode: Option<ProtectionMode>,
    /// Wire key scope from schema, currently for example `tenant`.
    pub key_scope: Option<&'static str>,
    /// AAD dimensions declared by schema, preserved in declaration order.
    pub aad: &'static [ProtectionAadDim],
    /// Required rationale for equality-revealing modes.
    pub reason: Option<&'static str>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtectionAtRest {
    /// The field is explicitly declared as not encrypted at rest.
    Plain,
    /// The field is declared as encrypted at rest.
    Encrypt,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtectionMode {
    /// Randomized encryption: same plaintext may produce different ciphertext.
    Randomized,
    /// Deterministic encryption: exposes plaintext equality by design.
    Deterministic,
    /// Blind index: exposes a stable lookup token by design.
    BlindIndex,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtectionAadDim {
    /// Tenant boundary dimension.
    Tenant,
    /// Settings/config key dimension.
    ConfigKey,
    /// Field path dimension.
    Field,
    /// Schema version dimension.
    SchemaVersion,
}
"#;

fn render_mod_rs(modules: &BTreeSet<String>, kind: ModKind) -> String {
    let mut s = generated_header("cargo xtask codegen (module funnel)");
    // event kind：定义 SubscriptionSpec POD；command kind：定义 CommandEmit/CommandRegister seam
    // （各子模块经 `super::` 引用，消除重复定义）。
    match kind {
        ModKind::Http => s.push_str(HTTP_SPEC_DEF),
        ModKind::Event => s.push_str(SUBSCRIPTION_SPEC_DEF),
        ModKind::Command => s.push_str(COMMAND_SEAM_DEF),
        ModKind::Saga => s.push_str(SAGA_SPEC_DEF),
        ModKind::Projection => {}
    }
    for m in modules {
        s.push_str(&format!("pub mod {m};\n"));
    }
    s
}

fn render_http_spec_path(c: &GovernedContract) -> Result<String> {
    let module = module_name(&c.manifest().domain, &c.manifest().version);
    match c.slug() {
        Some(slug) => Ok(format!("{module}::{}::SPEC", slug_module_ident(slug)?)),
        None => Ok(format!("{module}::SPEC")),
    }
}

fn render_http_producer_path(c: &GovernedContract) -> Result<String> {
    let module = module_name(&c.manifest().domain, &c.manifest().version);
    match c.slug() {
        Some(slug) => Ok(format!(
            "{module}::{}::PRODUCER.evidence()",
            slug_module_ident(slug)?
        )),
        None => Ok(format!("{module}::PRODUCER.evidence()")),
    }
}

fn render_http_root_specs(contracts: &[GovernedContract]) -> Result<String> {
    let mut entries = Vec::new();
    let mut local_only_entries = Vec::new();
    let mut local_tx_entries = Vec::new();
    let mut producer_entries = Vec::new();
    for c in contracts
        .iter()
        .filter(|c| c.manifest().kind == ContractKind::Http)
        .filter(|c| c.manifest().lifecycle == Lifecycle::Active)
    {
        let path = render_http_spec_path(c)?;
        match c.manifest().consistency_level {
            ConsistencyLevel::LocalOnly => local_only_entries.push(format!("    {path}")),
            ConsistencyLevel::LocalTx => local_tx_entries.push(format!("    {path}")),
            ConsistencyLevel::OutboxFact => {
                producer_entries.push(format!("    {}", render_http_producer_path(c)?))
            }
            ConsistencyLevel::WorkflowEventual | ConsistencyLevel::DeviceLatent => {}
        }
        entries.push(format!("    {path}"));
    }
    let body = if entries.is_empty() {
        String::new()
    } else {
        format!("\n{},\n", entries.join(",\n"))
    };
    let local_tx_body = if local_tx_entries.is_empty() {
        String::new()
    } else {
        format!("\n{},\n", local_tx_entries.join(",\n"))
    };
    let local_only_body = if local_only_entries.is_empty() {
        String::new()
    } else {
        format!("\n{},\n", local_only_entries.join(",\n"))
    };
    let producer_body = if producer_entries.is_empty() {
        String::new()
    } else {
        format!("\n{},\n", producer_entries.join(",\n"))
    };
    Ok(format!(
        r#"
/// Root registry for active HTTP specs generated from every HTTP contract.
pub const SPECS: &[HttpSpec] = &[{body}];

/// Root registry for active LocalOnly HTTP specs generated from `consistencyLevel = "LocalOnly"`.
pub const LOCAL_ONLY_SPECS: &[HttpSpec] = &[{local_only_body}];

/// Root registry for active LocalTx HTTP specs generated from `consistencyLevel = "LocalTx"`.
pub const LOCAL_TX_SPECS: &[HttpSpec] = &[{local_tx_body}];

/// Closed registry of every active OutboxFact HTTP producer and its exact generated fact set.
pub const OUTBOX_PRODUCERS: &[::vocab::http::HttpProducerEvidence] = &[{producer_body}];
"#
    ))
}

fn render_event_dispatch_keys(contracts: &[GovernedContract]) -> Result<String> {
    let mut variants = BTreeMap::new();
    for c in contracts
        .iter()
        .filter(|c| c.manifest().kind == ContractKind::Event)
        .filter(|c| c.manifest().lifecycle == Lifecycle::Active)
    {
        for subscription in &c.manifest().subscriptions {
            let variant = subscription_dispatch_variant(c, &subscription.consumer)?;
            let identity = format!(
                "{}@{}:{}",
                c.manifest().id,
                c.manifest().version,
                subscription.consumer
            );
            if let Some(previous) = variants.insert(variant.clone(), identity.clone()) {
                bail!(
                    "event subscription dispatch variant {variant} 冲突: {previous} / {identity}"
                );
            }
        }
    }

    let body = variants
        .into_iter()
        .map(|(variant, identity)| {
            format!("    /// Generated dispatch identity for `{identity}`.\n    {variant},")
        })
        .collect::<Vec<_>>()
        .join("\n");
    Ok(format!(
        r#"
/// Closed runtime dispatch identities derived from active event subscriptions.
///
/// Runtime assembly must match this enum exhaustively. Adding a subscription therefore makes a
/// missing handler binding a compile-time error instead of extending a handwritten registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubscriptionDispatchKey {{
{body}
}}
"#
    ))
}

fn render_event_root_subscriptions(contracts: &[GovernedContract]) -> Result<String> {
    let mut entries = Vec::new();
    for c in contracts
        .iter()
        .filter(|c| c.manifest().kind == ContractKind::Event)
        .filter(|c| c.manifest().lifecycle == Lifecycle::Active)
    {
        let module = module_name(&c.manifest().domain, &c.manifest().version);
        let path = match c.slug() {
            Some(slug) => format!("{module}::{}", slug_module_ident(slug)?),
            None => module,
        };
        entries.push(format!("    {path}::SPEC"));
    }
    let body = if entries.is_empty() {
        String::new()
    } else {
        format!("\n{},\n", entries.join(",\n"))
    };
    Ok(format!(
        r#"
/// Root event topology registry aggregated from every active generated event `SPEC`.
///
/// Runtime composition consumes this single registry through its bridge before constructing
/// consumer bundle inputs. Do not enumerate per-contract subscription slices in runtime wiring.
pub const EVENTS: &[EventSpec] = &[{body}];
"#
    ))
}

fn render_event_root_projection_inputs(contracts: &[GovernedContract]) -> Result<String> {
    let (generation, entries) = projection_input_entries(contracts)?;
    let entries = entries
        .iter()
        .map(|entry| {
            format!(
                "    ::vocab::ProjectionInputBinding::from_static(\"{}\", \"{}\", \"{}\", \"{}\", \"{}\", \"{}\")",
                entry.projection_id,
                entry.domain,
                entry.contract_id,
                entry.version,
                entry.schema_hash,
                entry.topic
            )
        })
        .collect::<Vec<_>>();
    let body = if entries.is_empty() {
        String::new()
    } else {
        format!("\n{},\n", entries.join(",\n"))
    };
    Ok(format!(
        r#"
/// Root projection input registry aggregated from `[capabilities.workflow].inputs`.
///
/// This is repository definition metadata, not deployment activation. Runtime capture first joins
/// it with the sealed assembly workflow plan and must not consume this catalog directly.
pub const PROJECTION_INPUT_GENERATION: &str = "{generation}";

/// Projection bindings that belong to [`PROJECTION_INPUT_GENERATION`].
pub const PROJECTION_INPUTS: &[::vocab::ProjectionInputBinding] = &[{body}];
"#
    ))
}

fn render_event_root_projection_definitions(contracts: &[GovernedContract]) -> Result<String> {
    let mut projections = contracts
        .iter()
        .filter(|contract| contract.manifest().kind == ContractKind::Projection)
        .collect::<Vec<_>>();
    projections.sort_by_key(|contract| contract.manifest().id.as_str());
    let entries = projections
        .into_iter()
        .map(|contract| {
            let module = module_name(&contract.manifest().domain, &contract.manifest().version);
            match contract.slug() {
                Some(slug) => Ok(format!(
                    "    crate::projection::{module}::{}::CONTRACT",
                    slug_module_ident(slug)?
                )),
                None => Ok(format!("    crate::projection::{module}::CONTRACT")),
            }
        })
        .collect::<Result<Vec<_>>>()?;
    let body = if entries.is_empty() {
        String::new()
    } else {
        format!("\n{},\n", entries.join(",\n"))
    };
    Ok(format!(
        r#"
/// Complete repository Projection definition catalog.
///
/// Presence here never activates a workflow; [`eventexec`](https://docs.rs/eventexec) performs the
/// only production join with a sealed assembly runtime plan before exposing runtime views.
pub const PROJECTION_DEFINITIONS: &[::vocab::ContractBinding] = &[{body}];
"#
    ))
}

#[derive(Clone, Copy)]
enum SagaCatalogKind {
    Production,
    TestSupport,
}

fn render_saga_root_specs(
    contracts: &[GovernedContract],
    catalog: SagaCatalogKind,
) -> Result<String> {
    let mut sagas = contracts
        .iter()
        .filter(|contract| contract.manifest().kind == ContractKind::Saga)
        .collect::<Vec<_>>();
    sagas.sort_by_key(|contract| contract.manifest().id.as_str());
    let entries = sagas
        .into_iter()
        .map(|contract| {
            let module = module_name(&contract.manifest().domain, &contract.manifest().version);
            match contract.slug() {
                Some(slug) => Ok(format!("    {module}::{}::SPEC", slug_module_ident(slug)?)),
                None => Ok(format!("    {module}::SPEC")),
            }
        })
        .collect::<Result<Vec<_>>>()?;
    let body = if entries.is_empty() {
        String::new()
    } else {
        format!("\n{},\n", entries.join(",\n"))
    };
    let rustdoc = match catalog {
        SagaCatalogKind::Production => {
            "Complete repository Saga definition catalog.\n\nDraft and inactive definitions remain visible for identity validation but never imply runtime\naction, store, worker, or probe activation."
        }
        SagaCatalogKind::TestSupport => {
            "Complete test-only Saga conformance fixture catalog.\n\nThese sealed definitions are generated only for compile-time and T2 provider/runtime conformance;\nthey never participate in the production Saga catalog or imply runtime activation."
        }
    };
    let rustdoc = rustdoc
        .lines()
        .map(|line| format!("/// {line}"))
        .collect::<Vec<_>>()
        .join("\n");
    Ok(format!(
        "\n{rustdoc}\npub const SPECS: &[SagaSpec] = &[{body}];\n"
    ))
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct ProjectionInputEntry {
    projection_id: String,
    projection_definition_version: String,
    projection_definition_schema_digest: String,
    domain: String,
    contract_id: String,
    version: String,
    schema_hash: String,
    topic: String,
}

fn projection_input_entries(
    contracts: &[GovernedContract],
) -> Result<(String, Vec<ProjectionInputEntry>)> {
    let by_id: BTreeMap<&str, &GovernedContract> = contracts
        .iter()
        .map(|contract| (contract.manifest().id.as_str(), contract))
        .collect();
    let mut entries = Vec::new();
    let mut generation_tuples = Vec::new();
    for projection in contracts
        .iter()
        .filter(|contract| contract.manifest().kind == ContractKind::Projection)
    {
        let projection_id = projection.manifest().id.as_str();
        let projection_definition_version = projection.manifest().version.as_str();
        let projection_definition_schema_digest = projection.schema_hash();
        for (field, value) in [
            ("projection_id", projection_id),
            (
                "projection_definition_version",
                projection_definition_version,
            ),
        ] {
            if !is_safe_codegen_ident(value) {
                bail!("projection workflow {field} 含不安全字符（防注入生成字面量）: {value:?}");
            }
        }
        if !is_safe_codegen_string(projection_definition_schema_digest) {
            bail!(
                "projection definition schema digest 含不安全字符（防注入生成字面量）: {projection_definition_schema_digest:?}"
            );
        }
        let Some(workflow) = projection.manifest().capabilities.workflow.as_ref() else {
            continue;
        };
        for input_id in &workflow.inputs {
            let input = by_id.get(input_id.as_str()).with_context(|| {
                format!(
                    "projection workflow {} input {} 不存在（codegen fail-closed）",
                    projection.manifest().id,
                    input_id
                )
            })?;
            if input.manifest().kind != ContractKind::Event {
                bail!(
                    "projection workflow {} input {} 不是 event contract（codegen fail-closed）",
                    projection.manifest().id,
                    input_id
                );
            }
            let domain = input.manifest().domain.as_str();
            let contract_id = input.manifest().id.as_str();
            let version = input.manifest().version.as_str();
            let topic = input.manifest().topic.as_deref().unwrap_or(contract_id);
            for (field, value) in [
                ("projection_id", projection_id),
                ("domain", domain),
                ("contract_id", contract_id),
                ("version", version),
                ("topic", topic),
            ] {
                if !is_safe_codegen_ident(value) {
                    bail!(
                        "projection input binding 的 {field} 含不安全字符（防注入生成字面量）: {value:?}"
                    );
                }
            }
            let schema_hash = input.schema_hash();
            if !is_safe_codegen_string(schema_hash) {
                bail!(
                    "projection input binding 的 schema_hash 含不安全字符（防注入生成字面量）: {schema_hash:?}"
                );
            }
            entries.push(ProjectionInputEntry {
                projection_id: projection_id.to_owned(),
                projection_definition_version: projection_definition_version.to_owned(),
                projection_definition_schema_digest: projection_definition_schema_digest.to_owned(),
                domain: domain.to_owned(),
                contract_id: contract_id.to_owned(),
                version: version.to_owned(),
                schema_hash: schema_hash.to_owned(),
                topic: topic.to_owned(),
            });
            generation_tuples.push([
                projection_id.to_string(),
                projection_definition_version.to_string(),
                projection_definition_schema_digest.to_owned(),
                domain.to_string(),
                contract_id.to_string(),
                version.to_string(),
                schema_hash.to_owned(),
                topic.to_string(),
            ]);
        }
    }
    entries.sort();
    let generation = projection_input_generation(&mut generation_tuples);
    Ok((generation, entries))
}

fn render_migration_projection_inputs(contracts: &[GovernedContract]) -> Result<String> {
    let (generation, entries) = projection_input_entries(contracts)?;
    let body = entries
        .iter()
        .map(|entry| {
            format!(
                "    super::ProjectionInputIdentity::from_static(\"{}\", \"{}\", \"{}\", \"{}\", \"{}\", \"{}\", \"{}\", \"{}\"),",
                entry.projection_id,
                entry.projection_definition_version,
                entry.projection_definition_schema_digest,
                entry.domain,
                entry.contract_id,
                entry.version,
                entry.schema_hash,
                entry.topic
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    Ok(format!(
        "// @generated by `cargo xtask codegen`; DO NOT EDIT.\n\
         pub(super) const PROJECTION_INPUT_GENERATION: &str = \"{generation}\";\n\
         pub(super) static PROJECTION_INPUTS: &[super::ProjectionInputIdentity] = &[\n{body}\n];\n"
    ))
}

fn projection_input_generation(tuples: &mut [[String; 8]]) -> String {
    tuples.sort_unstable();
    let mut hasher = Sha256::new();
    for tuple in tuples {
        for field in tuple {
            hasher.update((field.len() as u64).to_be_bytes());
            hasher.update(field.as_bytes());
        }
    }
    format!("sha256:{}", lower_hex(&hasher.finalize()))
}

fn render_event_root_producer_domains(contracts: &[GovernedContract]) -> Result<String> {
    let domains: BTreeSet<&str> = contracts
        .iter()
        .filter(|contract| contract.manifest().kind == ContractKind::Event)
        .filter(|contract| contract.manifest().lifecycle == Lifecycle::Active)
        .filter(|contract| contract.manifest().consistency_level == ConsistencyLevel::OutboxFact)
        .map(|contract| contract.manifest().domain.as_str())
        .collect();
    let mut variants = Vec::new();
    let mut seen = BTreeMap::<String, &str>::new();
    for domain in domains {
        let variant = producer_domain_variant(domain)?;
        if let Some(previous) = seen.insert(variant.clone(), domain) {
            bail!(
                "active event domains {previous:?} and {domain:?} collide on ProducerDomain::{variant}"
            );
        }
        variants.push((variant, domain));
    }
    let declarations = variants
        .iter()
        .map(|(variant, _)| format!("    {variant},"))
        .collect::<Vec<_>>()
        .join("\n");
    let match_arms = variants
        .iter()
        .map(|(variant, domain)| format!("            Self::{variant} => \"{domain}\","))
        .collect::<Vec<_>>()
        .join("\n");
    let entries = variants
        .iter()
        .map(|(variant, _)| format!("    ProducerDomain::{variant},"))
        .collect::<Vec<_>>()
        .join("\n");
    Ok(format!(
        r#"
/// Closed producer-domain topology derived from active OutboxFact [`EVENTS`].
///
/// Runtime must exhaustively match this enum when binding domain-specific relay providers; adding
/// an active producer domain therefore becomes a compile-time wiring change instead of a silent
/// omission from a handwritten string list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProducerDomain {{
{declarations}
}}

impl ProducerDomain {{
    pub const fn as_str(self) -> &'static str {{
        match self {{
{match_arms}
        }}
    }}
}}

/// Deduplicated producer domains for every active OutboxFact generated event.
pub const PRODUCER_DOMAINS: &[ProducerDomain] = &[
{entries}
];
"#
    ))
}

fn render_lib_rs<'a>(
    kinds: impl Iterator<Item = &'a String>,
    has_device_certificate: bool,
) -> String {
    let mut s = String::new();
    s.push_str("//! generated — 契约派生 wire 类型（committed，一等审查材料）。\n");
    s.push_str("//! 由 `cargo xtask codegen` 生成；勿手改。漂移由 `cargo xtask codegen --check` 守（CI 门）。\n");
    s.push_str(FIELD_PROTECTION_METADATA_DEF);
    for k in kinds {
        s.push_str(&format!("pub mod {k};\n"));
    }
    if has_device_certificate {
        s.push_str("pub mod device_certificate;\n");
    }
    s
}

/// rust-analyzer 模式：内容一致则 noop；`check` 下漂移即 `bail`；否则写盘（建父目录）。
/// 漂移错误消息附带 contracts/ 源路径，便于作者定位触发变更的契约。
#[cfg(test)]
fn ensure_file_contents(path: &Path, contents: &str, check: bool) -> Result<()> {
    let normalized = normalize(contents);
    let current = std::fs::read_to_string(path).ok();
    if current.as_deref() == Some(normalized.as_str()) {
        return Ok(());
    }
    if check {
        // 从 @generated 头提取 contracts/ 源路径，辅助作者定位。
        let source_hint = extract_source_from_header(&normalized)
            .map(|s| format!("（来源：{s}）"))
            .unwrap_or_default();
        bail!(
            "派生漂移：{} 与 contracts/ 不一致{}。跑 `cargo xtask codegen` 重生成并提交。",
            path.display(),
            source_hint,
        );
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).with_context(|| format!("建目录 {}", parent.display()))?;
    }
    std::fs::write(path, normalized.as_bytes())
        .with_context(|| format!("写 {}", path.display()))?;
    eprintln!("  regenerated {}", path.display());
    Ok(())
}

/// 从 `@generated` 注释行提取 `Source:` 后的路径。
#[cfg(test)]
fn extract_source_from_header(contents: &str) -> Option<&str> {
    contents
        .lines()
        .next()
        .and_then(|line| line.split("Source:").nth(1))
        .map(str::trim)
}

fn normalize(s: &str) -> String {
    let mut out = s.trim_end().to_string();
    out.push('\n');
    out
}

/// 经 rustfmt 规范化（与 `cargo fmt` 同一 formatter）——派生 committed 文件须 rustfmt-canonical，
/// 否则 `cargo fmt --all` 会重排 prettyplease 输出（如 `fn fmt(..)` 换行）造成 codegen 漂移。
/// 用 rust-toolchain.toml 钉的 rustfmt（component）；edition 显式 2024 与 generated crate 一致。
/// 经 [`crate::cmd::external_cmd`] 清洗 ambient 环境（剥 `RUSTUP_TOOLCHAIN` 等），确保用 rust-toolchain.toml
/// 钉的 1.96 rustfmt、不被外部 toolchain override 改变 golden 派生（INVARIANT CODEGEN-DRIFT-01）。
pub(crate) fn format_rust(code: &str) -> Result<String> {
    use std::io::Write;
    use std::process::Stdio;
    let mut child = crate::cmd::external_cmd(
        crate::cmd::ExternalProgram::Rustfmt,
        &["--edition", "2024"],
        &[],
        None,
    )
    .stdin(Stdio::piped())
    .stdout(Stdio::piped())
    .stderr(Stdio::piped())
    .spawn()
    .context("spawn rustfmt（需 rustfmt component，见 rust-toolchain.toml）")?;
    let mut stdin = child.stdin.take().context("rustfmt stdin 不可用")?;
    stdin
        .write_all(code.as_bytes())
        .context("写 rustfmt stdin")?;
    drop(stdin); // 关闭 stdin → rustfmt 读到 EOF
    let out = child.wait_with_output().context("等待 rustfmt")?;
    if !out.status.success() {
        bail!("rustfmt 失败: {}", String::from_utf8_lossy(&out.stderr));
    }
    String::from_utf8(out.stdout).context("rustfmt 输出非 UTF-8")
}

/// 孤儿检测：`gen_src` 下任何非期望 `.rs`（删契约残留）。`check` 下 `bail`；否则删除。
#[cfg(test)]
fn reconcile_orphans(gen_src: &Path, expected: &BTreeSet<PathBuf>, check: bool) -> Result<()> {
    let mut actual = Vec::new();
    collect_rs_files(gen_src, &mut actual)?;
    let mut orphans: Vec<PathBuf> = actual
        .into_iter()
        .filter(|p| !expected.contains(p))
        .collect();
    orphans.sort();
    if orphans.is_empty() {
        return Ok(());
    }
    if check {
        for o in &orphans {
            eprintln!("  孤儿派生文件: {}", o.display());
        }
        bail!(
            "派生漂移：{} 个孤儿文件（对应契约已删）。跑 `cargo xtask codegen`。",
            orphans.len()
        );
    }
    for o in &orphans {
        std::fs::remove_file(o).with_context(|| format!("删孤儿 {}", o.display()))?;
        eprintln!("  removed orphan {}", o.display());
    }
    Ok(())
}

fn collect_rs_files(dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    if !dir.is_dir() {
        return Ok(());
    }
    for entry in std::fs::read_dir(dir).with_context(|| format!("读目录 {}", dir.display()))? {
        let path = entry?.path();
        if path.is_dir() {
            collect_rs_files(&path, out)?;
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            out.push(path);
        }
    }
    Ok(())
}

fn collect_regular_files(dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    if !dir.is_dir() {
        return Ok(());
    }
    for entry in std::fs::read_dir(dir).with_context(|| format!("读目录 {}", dir.display()))? {
        let path = entry?.path();
        if path.is_dir() {
            collect_regular_files(&path, out)?;
        } else if path.is_file() {
            out.push(path);
        } else {
            bail!(
                "generated public schema path must be a regular file: {}",
                path.display()
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contract::DeviceCertificateCandidateId;
    use crate::testutil::unique_tmp;

    const BUSINESS_LOCAL_TX_EFFECT_PROFILE: &str = concat!(
        "[effectProfile]\n",
        "effects = [\"auth\", \"business-write\", \"business-transaction\"]\n",
    );

    fn assert_generated_contains(source: &str, needle: &str, message: &str) {
        assert!(source.contains(needle), "{message}:\n{source}");
    }

    #[test]
    fn public_authorization_receipt_shape_has_synthetic_red_proofs() -> Result<()> {
        let canonical = serde_json::json!({
            "properties": {"authorizationReceiptId": {
                "$ref": "rss://component/identity/v1/authorization-receipt-id",
                "x-redaction": "internal"
            }}
        });
        let mut count = 0;
        validate_authorization_receipt_document(
            "identity.test",
            "payload.json",
            &canonical,
            &mut count,
        )?;
        validate_authorization_receipt_ownership("identity.test", true, count)?;

        let resolved = serde_json::json!({"definitions": {"AuthorizationReceiptId": {
            "title": "AuthorizationReceiptId", "type": "string", "format": "uuid",
            "x-redaction": "internal",
            "not": {"const": "00000000-0000-0000-0000-000000000000"}
        }}});
        validate_authorization_receipt_component("identity.test", "payload.json", &resolved)?;
        let mut nil_allowed = resolved.clone();
        nil_allowed
            .pointer_mut("/definitions/AuthorizationReceiptId/not")
            .expect("definition")
            .take();
        assert!(
            validate_authorization_receipt_component("identity.test", "payload.json", &nil_allowed)
                .is_err()
        );

        let mut parallel_definition = canonical.clone();
        parallel_definition
            .pointer_mut("/properties/authorizationReceiptId/$ref")
            .expect("property")
            .clone_from(&serde_json::json!("#/definitions/authorizationReceiptId"));
        let mut red_count = 0;
        assert!(
            validate_authorization_receipt_document(
                "identity.test",
                "payload.json",
                &parallel_definition,
                &mut red_count
            )
            .is_err()
        );

        let mut unredacted = canonical.clone();
        unredacted
            .pointer_mut("/properties/authorizationReceiptId/x-redaction")
            .expect("property")
            .take();
        let mut red_count = 0;
        assert!(
            validate_authorization_receipt_document(
                "identity.test",
                "payload.json",
                &unredacted,
                &mut red_count
            )
            .is_err()
        );
        assert!(validate_authorization_receipt_ownership("identity.lineaged", true, 0).is_err());
        assert!(validate_authorization_receipt_ownership("identity.unlineaged", false, 1).is_err());
        Ok(())
    }

    fn assert_subscription_wire_semantics(rendered: &str, root_module: &str) {
        assert!(
            rendered.contains("super::SubscriptionExecution::AdapterNative")
                && rendered.contains("None"),
            "SPEC 缺 manifest-derived execution/effect 闭值:\n{rendered}"
        );
        for required in [
            "pub enum SubscriptionDispatchKey",
            "pub enum SubscriptionExecution",
            "pub enum SubscriptionEffect",
            "::vocab::ExternalEffectPolicy",
            "pub const fn dispatch",
            "pub const fn execution",
            "pub const fn effect",
            "pub const fn external_effect_policy",
        ] {
            assert!(
                root_module.contains(required),
                "event root module 缺 subscription wire API {required}:\n{root_module}"
            );
        }
    }

    fn generated_http_spec_slice<'a>(source: &'a str, const_name: &str) -> Result<&'a str> {
        let marker = format!("pub const {const_name}: &[HttpSpec] = &[");
        let Some(start) = source.find(&marker) else {
            bail!("generated HTTP root module should contain {const_name}");
        };
        let rest = &source[start..];
        let Some(end) = rest.find("];").map(|idx| idx + "];".len()) else {
            bail!("generated HTTP root module should close {const_name}");
        };
        Ok(&rest[..end])
    }

    /// 在 `root/contracts/http/_seed/v1` 落一个最小 http 契约。
    fn seed_http(root: &Path) -> Result<()> {
        let dir = root.join("contracts/http/_seed/v1");
        std::fs::create_dir_all(&dir)?;
        std::fs::write(
            dir.join("contract.toml"),
            "id = \"seed.echo\"\nkind = \"http\"\ndomain = \"_seed\"\nversion = \"v1\"\nowner = \"_framework\"\nconsistencyLevel = \"LocalOnly\"\nlifecycle = \"draft\"\n[schemas]\nrequest = \"request.schema.json\"\nresponse = \"response.schema.json\"\n",
        )?;
        let schema = "{\"$schema\":\"http://json-schema.org/draft-07/schema#\",\"title\":\"T\",\"type\":\"object\",\"required\":[\"m\"],\"properties\":{\"m\":{\"type\":\"string\"}},\"additionalProperties\":false}";
        std::fs::write(
            dir.join("request.schema.json"),
            schema.replace("\"T\"", "\"SeedEchoRequest\""),
        )?;
        std::fs::write(
            dir.join("response.schema.json"),
            schema.replace("\"T\"", "\"SeedEchoResponse\""),
        )?;
        Ok(())
    }

    #[test]
    fn malformed_schema_is_rejected_before_codegen_writes() -> anyhow::Result<()> {
        let root = unique_tmp("codegen-malformed-schema");
        seed_http(&root)?;
        std::fs::write(
            root.join("contracts/http/_seed/v1/request.schema.json"),
            br#"{"title":"SeedEchoRequest""#,
        )?;
        let gen_src = root.join("generated/src");
        std::fs::create_dir_all(&gen_src)?;
        let sentinel = gen_src.join("sentinel.rs");
        std::fs::write(&sentinel, "preserve\n")?;

        let Err(error) = generate(&root.join("contracts"), &gen_src, false) else {
            anyhow::bail!("malformed schema unexpectedly passed code generation")
        };
        assert!(
            error.to_string().contains("invalid schema source"),
            "{error:#}"
        );
        assert_eq!(std::fs::read_to_string(&sentinel)?, "preserve\n");
        assert_eq!(std::fs::read_dir(&gen_src)?.count(), 1);
        std::fs::remove_dir_all(root)?;
        Ok(())
    }

    fn seed_http_with_typed_responses(root: &Path) -> Result<()> {
        seed_http(root)?;
        let dir = root.join("contracts/http/_seed/v1");
        std::fs::write(
            dir.join("contract.toml"),
            concat!(
                "id = \"seed.echo\"\n",
                "kind = \"http\"\n",
                "domain = \"_seed\"\n",
                "version = \"v1\"\n",
                "owner = \"_framework\"\n",
                "consistencyLevel = \"LocalOnly\"\n",
                "lifecycle = \"active\"\n",
                "path = \"/api/v1/_seed/echo\"\n",
                "method = \"POST\"\n",
                "[endpoints.http]\n",
                "successStatus = 200\n",
                "idempotency = \"idempotent\"\n",
                "[endpoints.http.auth]\n",
                "mode = \"public\"\n",
                "[schemas]\n",
                "request = \"request.schema.json\"\n",
                "[schemas.responses]\n",
                "200 = \"response.schema.json\"\n",
                "404 = \"not-found.schema.json\"\n",
                "409 = \"conflict.schema.json\"\n",
                "[effectProfile]\n",
                "effects = [\"read\"]\n",
            ),
        )?;
        for (file, title) in [
            ("not-found.schema.json", "SeedEchoNotFoundResponse"),
            ("conflict.schema.json", "SeedEchoConflictResponse"),
        ] {
            std::fs::write(
                dir.join(file),
                format!(
                    "{{\"$schema\":\"http://json-schema.org/draft-07/schema#\",\"title\":\"{title}\",\"type\":\"object\",\"properties\":{{}},\"additionalProperties\":false}}"
                ),
            )?;
        }
        Ok(())
    }

    fn synthetic_fixed_error_schema(
        title: &str,
        code: &str,
        extra_required: bool,
        request_id_max_length: Option<u64>,
    ) -> serde_json::Value {
        let mut request_id = serde_json::json!({ "type": "string" });
        if let Some(max_length) = request_id_max_length {
            request_id["maxLength"] = serde_json::json!(max_length);
        }
        let mut required = vec!["code", "message", "retryable", "details", "requestId"];
        let mut properties = serde_json::json!({
            "code": { "type": "string", "enum": [code] },
            "message": { "type": "string", "enum": ["fixed error"] },
            "retryable": { "type": "boolean", "const": false },
            "details": {
                "type": "array",
                "maxItems": 0,
                "items": { "type": "object" }
            },
            "requestId": request_id
        });
        if extra_required {
            required.push("extra");
            properties["extra"] = serde_json::json!({ "type": "string" });
        }
        serde_json::json!({
            "$schema": "http://json-schema.org/draft-07/schema#",
            "title": title,
            "type": "object",
            "required": ["error"],
            "properties": {
                "error": {
                    "title": format!("{title}Error"),
                    "type": "object",
                    "required": required,
                    "properties": properties,
                    "additionalProperties": false
                }
            },
            "additionalProperties": false
        })
    }

    fn write_seed_active_http(root: &Path, endpoints_http: &str) -> Result<()> {
        write_seed_active_http_contract(
            root,
            "LocalOnly",
            endpoints_http,
            Some(concat!(
                "[effectProfile]\n",
                "effects = [\"auth\", \"read\"]\n",
            )),
            "",
        )
    }

    fn write_seed_active_http_without_effect_profile(
        root: &Path,
        endpoints_http: &str,
    ) -> Result<()> {
        write_seed_active_http_contract(root, "LocalOnly", endpoints_http, None, "")
    }

    fn write_seed_active_http_contract(
        root: &Path,
        consistency_level: &str,
        endpoints_http: &str,
        effect_profile: Option<&str>,
        capabilities: &str,
    ) -> Result<()> {
        let dir = root.join("contracts/http/_seed/v1");
        let manifest = format!(
            concat!(
                "id = \"seed.echo\"\n",
                "kind = \"http\"\n",
                "domain = \"_seed\"\n",
                "version = \"v1\"\n",
                "owner = \"_framework\"\n",
                "consistencyLevel = \"{consistency_level}\"\n",
                "lifecycle = \"active\"\n",
                "path = \"/api/v1/_seed/echo/{{resourceId}}\"\n",
                "method = \"POST\"\n",
                "[schemas]\n",
                "request = \"request.schema.json\"\n",
                "response = \"response.schema.json\"\n",
            ),
            consistency_level = consistency_level,
        );
        let wire_semantics =
            "[endpoints.http]\nsuccessStatus = 200\nidempotency = \"idempotent\"\n";
        let endpoints_http = if endpoints_http.contains("[endpoints.http]\n") {
            endpoints_http.replacen("[endpoints.http]\n", wire_semantics, 1)
        } else {
            format!("{wire_semantics}{endpoints_http}")
        };
        std::fs::write(
            dir.join("contract.toml"),
            format!(
                "{}{}{}{}",
                manifest,
                endpoints_http,
                effect_profile.unwrap_or(""),
                capabilities,
            ),
        )?;
        Ok(())
    }

    /// 在 `root/contracts/event/_seed/v1` 落一个最小 event 契约（无 subscriptions，draft）。
    fn seed_event(root: &Path) -> Result<()> {
        let dir = root.join("contracts/event/_seed/v1");
        std::fs::create_dir_all(&dir)?;
        std::fs::write(
            dir.join("contract.toml"),
            "id = \"seed.happened\"\nkind = \"event\"\ndomain = \"_seed\"\nversion = \"v1\"\nowner = \"_framework\"\nconsistencyLevel = \"OutboxFact\"\nlifecycle = \"draft\"\n[schemas]\npayload = \"payload.schema.json\"\n",
        )?;
        let schema = "{\"$schema\":\"http://json-schema.org/draft-07/schema#\",\"title\":\"SeedHappenedPayload\",\"type\":\"object\",\"required\":[\"id\"],\"properties\":{\"id\":{\"type\":\"string\"}},\"additionalProperties\":false}";
        std::fs::write(dir.join("payload.schema.json"), schema)?;
        Ok(())
    }

    /// 在 `root/contracts/event/_seed/v1` 落一个含 `[[subscriptions]]` 的 event 契约（#1120，供订阅 glue 测试）。
    fn seed_event_with_subscription(root: &Path) -> Result<()> {
        let dir = root.join("contracts/event/_seed/v1");
        std::fs::create_dir_all(&dir)?;
        std::fs::write(
            dir.join("contract.toml"),
            concat!(
                "id = \"seed.happened\"\n",
                "kind = \"event\"\n",
                "domain = \"_seed\"\n",
                "version = \"v1\"\n",
                "owner = \"_framework\"\n",
                "consistencyLevel = \"OutboxFact\"\n",
                "lifecycle = \"active\"\n",
                "topic = \"seed.happened\"\n",
                "delivery = \"at-least-once\"\n",
                "[schemas]\n",
                "payload = \"payload.schema.json\"\n",
                "[capabilities.outbox]\n",
                "role = \"fact\"\n",
                "[[subscriptions]]\n",
                "consumer = \"audit\"\n",
                "group = \"audit.seed-happened\"\n",
                "execution = \"adapter-native\"\n",
                "externalEffectPolicy = \"transactional-only\"\n",
                "[subscriptions.topology]\n",
                "partitionKey = \"none\"\n",
                "readiness = \"required\"\n",
            ),
        )?;
        let schema = "{\"$schema\":\"http://json-schema.org/draft-07/schema#\",\"title\":\"SeedHappenedPayload\",\"type\":\"object\",\"required\":[\"id\"],\"properties\":{\"id\":{\"type\":\"string\"}},\"additionalProperties\":false}";
        std::fs::write(dir.join("payload.schema.json"), schema)?;
        Ok(())
    }

    /// 在 `root/contracts/saga/billing/v1` 落一个最小 Saga 契约（payload + generated receipt schemas）。
    fn seed_saga(root: &Path) -> Result<()> {
        let dir = root.join("contracts/saga/billing/v1");
        std::fs::create_dir_all(&dir)?;
        std::fs::write(
            dir.join("contract.toml"),
            concat!(
                "id = \"billing.checkout\"\n",
                "kind = \"saga\"\n",
                "domain = \"billing\"\n",
                "version = \"v1\"\n",
                "owner = \"billing\"\n",
                "consistencyLevel = \"WorkflowEventual\"\n",
                "lifecycle = \"draft\"\n",
                "[schemas]\n",
                "payload = \"payload.schema.json\"\n",
                "[saga]\n",
                "compensationOrder = \"reverse\"\n",
                "steps = [\n",
                "  { name = \"reserve_funds\", receiptSchema = \"reserve.schema.json\", effectScope = \"billing.reserve\", compensationEffectScope = \"billing.release\", idempotencyClass = \"deterministic-key\", compensationInput = \"receipt\", retryClass = \"transient\" },\n",
                "  { name = \"capture\", receiptSchema = \"capture.schema.json\", effectScope = \"billing.capture\", compensationEffectScope = \"billing.refund\", idempotencyClass = \"deterministic-key\", compensationInput = \"receipt\", retryClass = \"never\" },\n",
                "]\n",
                "[saga.retry]\n",
                "maxAttempts = 3\n",
                "timeBudgetMillis = 30000\n",
                "backoff = \"exponential\"\n",
                "initialBackoffMillis = 100\n",
                "maxBackoffMillis = 5000\n",
                "jitter = \"full\"\n",
            ),
        )?;
        let payload = "{\"$schema\":\"http://json-schema.org/draft-07/schema#\",\"title\":\"BillingCheckoutPayload\",\"type\":\"object\",\"required\":[\"checkoutId\"],\"properties\":{\"checkoutId\":{\"type\":\"string\"}},\"additionalProperties\":false}";
        let reserve = "{\"$schema\":\"http://json-schema.org/draft-07/schema#\",\"title\":\"ReserveFundsReceipt\",\"type\":\"object\",\"required\":[\"reserved\"],\"properties\":{\"reserved\":{\"type\":\"boolean\"}},\"additionalProperties\":false}";
        let capture = "{\"$schema\":\"http://json-schema.org/draft-07/schema#\",\"title\":\"CaptureReceipt\",\"type\":\"object\",\"required\":[\"captured\"],\"properties\":{\"captured\":{\"type\":\"boolean\"}},\"additionalProperties\":false}";
        std::fs::write(dir.join("payload.schema.json"), payload)?;
        std::fs::write(dir.join("reserve.schema.json"), reserve)?;
        std::fs::write(dir.join("capture.schema.json"), capture)?;
        Ok(())
    }

    /// 落一个 projection workflow 契约，input 指向 `seed.happened` event 契约。
    fn seed_projection_workflow(root: &Path) -> Result<()> {
        let dir = root.join("contracts/projection/audit/v1");
        std::fs::create_dir_all(&dir)?;
        std::fs::write(
            dir.join("contract.toml"),
            concat!(
                "id = \"audit.seed-projection\"\n",
                "kind = \"projection\"\n",
                "domain = \"audit\"\n",
                "version = \"v1\"\n",
                "owner = \"audit\"\n",
                "consistencyLevel = \"WorkflowEventual\"\n",
                "lifecycle = \"draft\"\n",
                "[schemas]\n",
                "projection = \"projection.schema.json\"\n",
                "[capabilities.workflow]\n",
                "mode = \"projection\"\n",
                "inputs = [\"seed.happened\"]\n",
                "ordering = \"serial-in-order\"\n",
                "checkpoint = \"required\"\n",
                "replay = \"required\"\n",
            ),
        )?;
        let projection = "{\"$schema\":\"http://json-schema.org/draft-07/schema#\",\"title\":\"AuditSeedProjection\",\"type\":\"object\",\"properties\":{},\"additionalProperties\":false}";
        std::fs::write(dir.join("projection.schema.json"), projection)?;
        Ok(())
    }

    /// 落一个 http 契约：request 含敏感字段 `password`、response 仅非敏感字段——
    /// 用于验 codegen 对含凭据字段的 struct 剥 `Debug`、非敏感 struct 保留 `Debug`（#1096，PR #186 F2）。
    fn seed_http_sensitive(root: &Path) -> Result<()> {
        let dir = root.join("contracts/http/_seed/v1");
        std::fs::create_dir_all(&dir)?;
        std::fs::write(
            dir.join("contract.toml"),
            "id = \"seed.login\"\nkind = \"http\"\ndomain = \"_seed\"\nversion = \"v1\"\nowner = \"_framework\"\nconsistencyLevel = \"LocalOnly\"\nlifecycle = \"draft\"\n[schemas]\nrequest = \"request.schema.json\"\nresponse = \"response.schema.json\"\n",
        )?;
        std::fs::write(
            dir.join("request.schema.json"),
            "{\"$schema\":\"http://json-schema.org/draft-07/schema#\",\"title\":\"SensitiveSeedRequest\",\"type\":\"object\",\"required\":[\"password\",\"username\"],\"properties\":{\"password\":{\"type\":\"string\",\"x-redaction\":\"secret\"},\"username\":{\"type\":\"string\"}},\"additionalProperties\":false}",
        )?;
        std::fs::write(
            dir.join("response.schema.json"),
            "{\"$schema\":\"http://json-schema.org/draft-07/schema#\",\"title\":\"SensitiveSeedResponse\",\"type\":\"object\",\"required\":[\"ok\"],\"properties\":{\"ok\":{\"type\":\"string\"}},\"additionalProperties\":false}",
        )?;
        Ok(())
    }

    /// 落一个 http 契约：request 字段声明 `x-redaction`（坐标类：storeId）——
    /// 验 codegen 经 schema 字段策略注入 `#[redact]`；response 未标记字段默认 public。
    fn seed_http_redaction_policy(root: &Path) -> Result<()> {
        let dir = root.join("contracts/http/_xsens/v1");
        std::fs::create_dir_all(&dir)?;
        std::fs::write(
            dir.join("contract.toml"),
            "id = \"xsens.publish\"\nkind = \"http\"\ndomain = \"_xsens\"\nversion = \"v1\"\nowner = \"_framework\"\nconsistencyLevel = \"LocalOnly\"\nlifecycle = \"draft\"\n[schemas]\nrequest = \"request.schema.json\"\nresponse = \"response.schema.json\"\n",
        )?;
        std::fs::write(
            dir.join("request.schema.json"),
            "{\"$schema\":\"http://json-schema.org/draft-07/schema#\",\"title\":\"XSensCoordRequest\",\"type\":\"object\",\"required\":[\"storeId\"],\"properties\":{\"storeId\":{\"type\":\"string\",\"x-redaction\":\"internal\"}},\"additionalProperties\":false}",
        )?;
        std::fs::write(
            dir.join("response.schema.json"),
            "{\"$schema\":\"http://json-schema.org/draft-07/schema#\",\"title\":\"XSensCoordResponse\",\"type\":\"object\",\"required\":[\"ok\"],\"properties\":{\"ok\":{\"type\":\"string\"}},\"additionalProperties\":false}",
        )?;
        Ok(())
    }

    fn seed_http_protection_policy(root: &Path) -> Result<()> {
        let dir = root.join("contracts/http/_prot/v1");
        std::fs::create_dir_all(&dir)?;
        std::fs::write(
            dir.join("contract.toml"),
            "id = \"prot.publish\"\nkind = \"http\"\ndomain = \"_prot\"\nversion = \"v1\"\nowner = \"_framework\"\nconsistencyLevel = \"LocalOnly\"\nlifecycle = \"draft\"\n[schemas]\nrequest = \"request.schema.json\"\nresponse = \"response.schema.json\"\n",
        )?;
        std::fs::write(
            dir.join("request.schema.json"),
            r#"{
  "$schema":"http://json-schema.org/draft-07/schema#",
  "title":"ProtectionRequest",
  "type":"object",
  "required":["storeId","value","profile","plaintext","note"],
  "properties":{
    "storeId":{"type":"string","x-protection":{"atRest":"encrypt","keyScope":"tenant","aad":["tenant","configKey","field","schemaVersion"]}},
    "value":{"type":"string","x-protection":{"atRest":"encrypt","mode":"blindIndex","keyScope":"tenant","aad":["tenant","configKey","field"],"reason":"lookup"}},
    "profile":{"type":"object","required":["secret"],"properties":{"secret":{"type":"string","x-redaction":"secret","x-protection":{"atRest":"encrypt","keyScope":"tenant","aad":["tenant","configKey","field","schemaVersion"]}},"note":{"type":"string"}},"additionalProperties":false},
    "plaintext":{"type":"string","x-protection":{"atRest":"plain"}},
    "note":{"type":"string"}
  },
  "additionalProperties":false
}"#,
        )?;
        std::fs::write(
            dir.join("response.schema.json"),
            r#"{"$schema":"http://json-schema.org/draft-07/schema#","title":"ProtectionResponse","type":"object","required":["ok"],"properties":{"ok":{"type":"string"}},"additionalProperties":false}"#,
        )?;
        Ok(())
    }

    /// 派生 .rs 中名为 `name` 的 struct derive 列表里是否含末段 `derive_name`。
    fn struct_derives(file: &syn::File, name: &str, derive_name: &str) -> bool {
        file.items.iter().any(|item| {
            let syn::Item::Struct(s) = item else {
                return false;
            };
            if s.ident != name {
                return false;
            }
            s.attrs.iter().any(|attr| {
                attr.path().is_ident("derive")
                    && attr
                        .parse_args_with(
                            syn::punctuated::Punctuated::<syn::Path, syn::Token![,]>::parse_terminated,
                        )
                        .is_ok_and(|paths| {
                            paths
                                .iter()
                                .any(|p| p.segments.last().is_some_and(|seg| seg.ident == derive_name))
                        })
            })
        })
    }

    fn field_has_redact_attr(
        file: &syn::File,
        struct_name: &str,
        field_name: &str,
        needle: &str,
    ) -> bool {
        file.items.iter().any(|item| {
            let syn::Item::Struct(s) = item else {
                return false;
            };
            if s.ident != struct_name {
                return false;
            }
            s.fields.iter().any(|field| {
                field.ident.as_ref().is_some_and(|ident| ident == field_name)
                    && field.attrs.iter().any(|attr| {
                        attr.path().is_ident("redact")
                            && matches!(&attr.meta, syn::Meta::List(list) if list.tokens.to_string().contains(needle))
                    })
            })
        })
    }

    fn tuple_field_has_redact_attr(file: &syn::File, struct_name: &str, needle: &str) -> bool {
        file.items.iter().any(|item| {
            let syn::Item::Struct(s) = item else {
                return false;
            };
            s.ident == struct_name
                && s.fields.iter().any(|field| {
                    field.ident.is_none()
                        && field.attrs.iter().any(|attr| {
                            attr.path().is_ident("redact")
                                && matches!(&attr.meta, syn::Meta::List(list) if list.tokens.to_string().contains(needle))
                        })
                })
        })
    }

    /// generated wire struct 须统一 derive `secure::Redact` 并去掉裸 `Debug` derive；
    /// 字段策略由 schema `x-redaction` 注入，未标记字段默认 public。
    #[test]
    fn generated_structs_derive_redact_and_inject_field_attrs() -> anyhow::Result<()> {
        let root = unique_tmp("codegen");
        seed_http_sensitive(&root)?;
        let contracts = root.join("contracts");
        let gen_src = root.join("generated/src");
        generate(&contracts, &gen_src, false)?;
        let rendered = std::fs::read_to_string(gen_src.join("http/_seed_v1.rs"))?;
        let _ = std::fs::remove_dir_all(&root);

        let parsed = syn::parse_str::<syn::File>(&rendered).context("解析派生 .rs")?;
        assert!(
            struct_derives(&parsed, "SensitiveSeedRequest", "Redact"),
            "request 应 derive secure::Redact:\n{rendered}"
        );
        assert!(
            !struct_derives(&parsed, "SensitiveSeedRequest", "Debug"),
            "request 不应裸 derive Debug:\n{rendered}"
        );
        assert!(
            field_has_redact_attr(&parsed, "SensitiveSeedRequest", "password", "secret"),
            "password 应注入 #[redact(sensitivity = secret)]:\n{rendered}"
        );
        assert!(
            field_has_redact_attr(&parsed, "SensitiveSeedRequest", "username", "public"),
            "username 未标记字段应默认 public:\n{rendered}"
        );
        assert!(
            struct_derives(&parsed, "SensitiveSeedResponse", "Redact"),
            "非敏感 response 也应 derive Redact（全量安全 Debug）:\n{rendered}"
        );
        Ok(())
    }

    /// schema 字段级策略驱动 `#[redact]` 注入，非字段名启发式。
    #[test]
    fn field_redaction_policy_drives_redact_attr() -> anyhow::Result<()> {
        let root = unique_tmp("codegen");
        seed_http_redaction_policy(&root)?;
        let contracts = root.join("contracts");
        let gen_src = root.join("generated/src");
        generate(&contracts, &gen_src, false)?;
        let rendered = std::fs::read_to_string(gen_src.join("http/_xsens_v1.rs"))?;
        let _ = std::fs::remove_dir_all(&root);

        let parsed = syn::parse_str::<syn::File>(&rendered).context("解析派生 .rs")?;
        assert!(
            field_has_redact_attr(&parsed, "XSensCoordRequest", "store_id", "internal"),
            "storeId 应按 x-redaction=internal 注入字段策略:\n{rendered}"
        );
        Ok(())
    }

    fn constrained_redaction_fixture() -> anyhow::Result<(syn::File, String)> {
        let root = unique_tmp("codegen");
        seed_http_sensitive(&root)?;
        std::fs::write(
            root.join("contracts/http/_seed/v1/request.schema.json"),
            r#"{"$schema":"http://json-schema.org/draft-07/schema#","title":"SensitiveSeedRequest","type":"object","required":["opaque","label"],"properties":{"opaque":{"type":"string","minLength":1,"maxLength":64,"x-defer-string-length-validation":true,"x-redaction":"secret"},"label":{"type":"string","minLength":1,"maxLength":64}},"additionalProperties":false}"#,
        )?;
        let gen_src = root.join("generated/src");
        generate(&root.join("contracts"), &gen_src, false)?;
        let rendered = std::fs::read_to_string(gen_src.join("http/_seed_v1.rs"))?;
        let _ = std::fs::remove_dir_all(&root);

        let parsed = syn::parse_str::<syn::File>(&rendered).context("解析派生 .rs")?;
        Ok((parsed, rendered))
    }

    /// typify constrained tuple newtype 必须精确继承 secret/public 策略；public 样本防止
    /// 用“全部标 secret”掩盖传播缺失。
    #[test]
    fn constrained_newtypes_inherit_exact_redaction_policy() -> anyhow::Result<()> {
        let (parsed, rendered) = constrained_redaction_fixture()?;
        assert!(
            tuple_field_has_redact_attr(&parsed, "SensitiveSeedRequestOpaque", "secret"),
            "secret constrained string newtype 应继承 secret 策略:\n{rendered}"
        );
        assert!(
            tuple_field_has_redact_attr(&parsed, "SensitiveSeedRequestLabel", "public"),
            "未标记 constrained string newtype 应保持 public:\n{rendered}"
        );
        assert!(
            !tuple_field_has_redact_attr(&parsed, "SensitiveSeedRequestLabel", "secret"),
            "public anti-vacuity 样本不得被一律提升成 secret:\n{rendered}"
        );
        Ok(())
    }

    fn generated_from_str_impl<'a>(rendered: &'a str, type_name: &str) -> anyhow::Result<&'a str> {
        let start = format!("impl ::std::str::FromStr for {type_name}");
        let (_, tail) = rendered
            .split_once(&start)
            .ok_or_else(|| anyhow::anyhow!("missing FromStr impl for {type_name}"))?;
        Ok(tail
            .split("\n}\nimpl ")
            .next()
            .unwrap_or_else(|| tail.split("\n    impl ").next().unwrap_or(tail)))
    }

    fn utf8_byte_length_fixture() -> anyhow::Result<String> {
        let root = unique_tmp("codegen-utf8-bytes");
        seed_http_sensitive(&root)?;
        std::fs::write(
            root.join("contracts/http/_seed/v1/request.schema.json"),
            r#"{"$schema":"http://json-schema.org/draft-07/schema#","title":"SensitiveSeedRequest","type":"object","required":["literal","values","pattern","label"],"properties":{"literal":{"type":"string","maxLength":4,"x-rss-length-unit":"utf8-bytes"},"values":{"type":"array","items":{"type":"string","maxLength":4,"x-rss-length-unit":"utf8-bytes"}},"pattern":{"type":"string","minLength":1,"maxLength":4,"x-rss-length-unit":"utf8-bytes"},"label":{"type":"string","maxLength":4}},"additionalProperties":false}"#,
        )?;
        let gen_src = root.join("generated/src");
        generate(&root.join("contracts"), &gen_src, false)?;
        let rendered = std::fs::read_to_string(gen_src.join("http/_seed_v1.rs"))?;
        let _ = std::fs::remove_dir_all(&root);
        Ok(rendered)
    }

    #[test]
    fn utf8_byte_length_marker_rewrites_only_marked_maximum_checks() -> anyhow::Result<()> {
        let rendered = utf8_byte_length_fixture()?;
        for type_name in [
            "SensitiveSeedRequestLiteral",
            "SensitiveSeedRequestValuesItem",
            "SensitiveSeedRequestPattern",
        ] {
            let constructor = generated_from_str_impl(&rendered, type_name)?;
            assert!(
                constructor.contains("value.len() > 4usize")
                    && constructor.contains("longer than 4 UTF-8 bytes"),
                "marked type must enforce bytes in its sealed constructor: {constructor}"
            );
        }
        let pattern = generated_from_str_impl(&rendered, "SensitiveSeedRequestPattern")?;
        assert!(
            pattern.contains("value.chars().count() < 1usize"),
            "marker must preserve standard minLength semantics: {pattern}"
        );
        let control = generated_from_str_impl(&rendered, "SensitiveSeedRequestLabel")?;
        assert!(
            control.contains("value.chars().count() > 4usize") && !control.contains("value.len()"),
            "unmarked maxLength is the anti-vacuity control: {control}"
        );
        Ok(())
    }

    #[test]
    fn utf8_byte_length_marker_is_closed_and_fail_closed() {
        for (label, schema) in [
            (
                "unknown unit",
                serde_json::json!({"title":"Root","type":"string","maxLength":4,"x-rss-length-unit":"characters"}),
            ),
            (
                "missing maxLength",
                serde_json::json!({"title":"Root","type":"string","x-rss-length-unit":"utf8-bytes"}),
            ),
            (
                "wrong schema type",
                serde_json::json!({"title":"Root","type":"integer","maxLength":4,"x-rss-length-unit":"utf8-bytes"}),
            ),
            (
                "wrong marker type",
                serde_json::json!({"title":"Root","type":"string","maxLength":4,"x-rss-length-unit":true}),
            ),
        ] {
            assert!(
                collect_utf8_byte_length_markers(&schema).is_err(),
                "{label} must fail closed"
            );
        }
        let duplicate_identity = serde_json::json!({
            "title": "Root",
            "allOf": [
                {"title":"Repeated","type":"string","maxLength":4,"x-rss-length-unit":"utf8-bytes"},
                {"title":"Repeated","type":"string","maxLength":4,"x-rss-length-unit":"utf8-bytes"}
            ]
        });
        assert!(
            collect_utf8_byte_length_markers(&duplicate_identity).is_err(),
            "duplicate marker identity must fail closed"
        );
    }

    #[test]
    fn utf8_byte_length_marker_covers_property_one_of_and_array_items() -> anyhow::Result<()> {
        let schema = serde_json::json!({
            "title":"Root",
            "type":"object",
            "properties":{
                "direct":{"type":"string","maxLength":4,"x-rss-length-unit":"utf8-bytes"},
                "choice":{"oneOf":[{"type":"string","maxLength":4,"x-rss-length-unit":"utf8-bytes"},{"type":"boolean"}]},
                "values":{"type":"array","items":{"type":"string","maxLength":4,"x-rss-length-unit":"utf8-bytes"}}
            }
        });
        let markers = collect_utf8_byte_length_markers(&schema)?;
        assert_eq!(markers.len(), 3);
        assert!(
            markers
                .iter()
                .any(|marker| marker.contains("properties/direct"))
        );
        assert!(markers.iter().any(|marker| marker.contains("oneOf/0")));
        assert!(markers.iter().any(|marker| marker.contains("items")));
        Ok(())
    }

    /// marker 必须只移除被标 constrained string 的 transport constructor 检查；未标样本继续检查，
    /// 防止实现退化为全局移除 typify 约束，且生成文档仍携带原 min/max 与 marker 元数据。
    #[test]
    fn schema_marker_defers_transport_length_checks() -> anyhow::Result<()> {
        let (_, rendered) = constrained_redaction_fixture()?;
        let deferred = generated_from_str_impl(&rendered, "SensitiveSeedRequestOpaque")?;
        let enforced = generated_from_str_impl(&rendered, "SensitiveSeedRequestLabel")?;
        assert!(
            deferred.contains("Ok(Self(value.to_string()))")
                && !deferred.contains("chars().count()"),
            "marked constructor must accept raw transport strings:\n{deferred}"
        );
        assert!(
            enforced.contains("chars().count()"),
            "unmarked constrained string is the anti-vacuity control:\n{enforced}"
        );
        assert!(
            rendered.contains("\"minLength\": 1")
                && rendered.contains("\"maxLength\": 64")
                && rendered.contains("\"x-defer-string-length-validation\": true"),
            "generated schema docs must retain constraint metadata:\n{rendered}"
        );
        Ok(())
    }

    /// constructor 重写会移除整个 typify validation body，因此 marker 与 pattern 等额外约束组合时
    /// 必须 codegen fail-closed，不能把 schema 声明的约束静默变成无效元数据。
    #[test]
    fn deferred_string_length_marker_rejects_other_validation_keywords() -> anyhow::Result<()> {
        let root = unique_tmp("codegen-deferred-pattern");
        seed_http_sensitive(&root)?;
        std::fs::write(
            root.join("contracts/http/_seed/v1/request.schema.json"),
            r#"{"$schema":"http://json-schema.org/draft-07/schema#","title":"SensitiveSeedRequest","type":"object","required":["opaque"],"properties":{"opaque":{"type":"string","minLength":1,"maxLength":64,"pattern":"^[a-z]+$","x-defer-string-length-validation":true,"x-redaction":"secret"}},"additionalProperties":false}"#,
        )?;
        let error = match generate(&root.join("contracts"), &root.join("generated/src"), false) {
            Ok(()) => anyhow::bail!("marked min/max + pattern must fail closed"),
            Err(error) => error,
        };
        let _ = std::fs::remove_dir_all(&root);
        let message = format!("{error:#}");
        assert!(
            message.contains(DEFER_STRING_LENGTH_VALIDATION) && message.contains("pattern"),
            "error must identify the marker and discarded keyword: {message}"
        );
        Ok(())
    }

    #[test]
    fn field_protection_policy_drives_metadata() -> anyhow::Result<()> {
        let root = unique_tmp("codegen");
        seed_http_protection_policy(&root)?;
        let contracts = root.join("contracts");
        let gen_src = root.join("generated/src");
        generate(&contracts, &gen_src, false)?;
        let rendered = std::fs::read_to_string(gen_src.join("http/_prot_v1.rs"))?;
        let lib_rs = std::fs::read_to_string(gen_src.join("lib.rs"))?;
        let _ = std::fs::remove_dir_all(&root);

        assert!(
            lib_rs.contains("pub trait FieldProtectionMetadata"),
            "lib.rs 应定义字段保护 metadata trait:\n{lib_rs}"
        );
        assert!(
            rendered.contains("impl crate::FieldProtectionMetadata for ProtectionRequest"),
            "request 应实现字段保护 metadata:\n{rendered}"
        );
        assert!(
            rendered.contains("field_path: \"value\"")
                && rendered.contains("crate::ProtectionMode::BlindIndex")
                && rendered.contains("reason: Some(\"lookup\")"),
            "value 字段应携带 blindIndex protection metadata:\n{rendered}"
        );
        Ok(())
    }

    #[test]
    fn field_protection_metadata_uses_wire_field_path() -> anyhow::Result<()> {
        let root = unique_tmp("codegen");
        seed_http_protection_policy(&root)?;
        let gen_src = root.join("generated/src");
        generate(&root.join("contracts"), &gen_src, false)?;
        let rendered = std::fs::read_to_string(gen_src.join("http/_prot_v1.rs"))?;
        let _ = std::fs::remove_dir_all(&root);

        assert!(
            rendered.contains("field_path: \"storeId\""),
            "metadata 必须使用 wire field path storeId:\n{rendered}"
        );
        assert!(
            !rendered.contains("field_path: \"store_id\""),
            "metadata 不得使用 Rust 字段名 store_id:\n{rendered}"
        );
        Ok(())
    }

    #[test]
    fn field_protection_metadata_uses_nested_wire_field_path() -> anyhow::Result<()> {
        let root = unique_tmp("codegen");
        seed_http_protection_policy(&root)?;
        let gen_src = root.join("generated/src");
        generate(&root.join("contracts"), &gen_src, false)?;
        let rendered = std::fs::read_to_string(gen_src.join("http/_prot_v1.rs"))?;
        let _ = std::fs::remove_dir_all(&root);

        assert!(
            rendered.contains("field_path: \"profile.secret\""),
            "nested protection metadata must use dotted wire field path:\n{rendered}"
        );
        assert!(
            !rendered.contains("field_path: \"secret\""),
            "nested protection metadata must not collapse to local field name:\n{rendered}"
        );
        Ok(())
    }

    #[test]
    fn field_protection_metadata_resolves_local_ref_wire_field_path() -> anyhow::Result<()> {
        let root = unique_tmp("codegen");
        seed_http(&root)?;
        std::fs::write(
            root.join("contracts/http/_seed/v1/request.schema.json"),
            r##"{
  "$schema":"http://json-schema.org/draft-07/schema#",
  "title":"SeedEchoRequest",
  "type":"object",
  "required":["profile"],
  "properties":{
    "profile":{"$ref":"#/$defs/Profile"}
  },
  "$defs":{
    "Profile":{
      "type":"object",
      "required":["secret"],
      "properties":{
        "secret":{"type":"string","x-redaction":"secret","x-protection":{"atRest":"encrypt","keyScope":"tenant","aad":["tenant","configKey","field","schemaVersion"]}}
      },
      "additionalProperties":false
    }
  },
  "additionalProperties":false
}"##,
        )?;
        let gen_src = root.join("generated/src");
        generate(&root.join("contracts"), &gen_src, false)?;
        let rendered = std::fs::read_to_string(gen_src.join("http/_seed_v1.rs"))?;
        let _ = std::fs::remove_dir_all(&root);

        assert!(
            rendered.contains("field_path: \"profile.secret\""),
            "$ref target protection metadata must keep the referring wire path:\n{rendered}"
        );
        Ok(())
    }

    #[test]
    fn field_protection_plain_and_absent_fields_are_distinct() -> anyhow::Result<()> {
        let root = unique_tmp("codegen");
        seed_http_protection_policy(&root)?;
        let gen_src = root.join("generated/src");
        generate(&root.join("contracts"), &gen_src, false)?;
        let rendered = std::fs::read_to_string(gen_src.join("http/_prot_v1.rs"))?;
        let _ = std::fs::remove_dir_all(&root);

        assert!(
            rendered.contains("field_path: \"plaintext\"")
                && rendered.contains("at_rest: crate::ProtectionAtRest::Plain"),
            "atRest:plain 字段应显式进入 metadata:\n{rendered}"
        );
        assert!(
            !rendered.contains("field_path: \"note\""),
            "未声明 x-protection 的字段不应进入 metadata:\n{rendered}"
        );
        Ok(())
    }

    #[test]
    fn codegen_rejects_invalid_protection_policy_without_validate_first() -> anyhow::Result<()> {
        let root = unique_tmp("codegen");
        seed_http(&root)?;
        std::fs::write(
            root.join("contracts/http/_seed/v1/request.schema.json"),
            r#"{"$schema":"http://json-schema.org/draft-07/schema#","title":"SeedEchoRequest","type":"object","required":["memo"],"properties":{"memo":{"type":"string","x-protection":{"atRest":"encrypt"}}},"additionalProperties":false}"#,
        )?;
        let result = generate(&root.join("contracts"), &root.join("generated/src"), false);
        let _ = std::fs::remove_dir_all(&root);
        let err = match result {
            Ok(()) => anyhow::bail!("codegen must fail closed on protection policy violations"),
            Err(err) => err,
        };
        let message = format!("{err:#}");
        assert!(
            message.contains("protection policy invalid") && message.contains("memo"),
            "错误应指向 protection policy 与字段名:\n{message}"
        );
        Ok(())
    }

    #[test]
    fn codegen_rejects_pattern_property_protection_metadata() -> anyhow::Result<()> {
        let root = unique_tmp("codegen");
        seed_http(&root)?;
        std::fs::write(
            root.join("contracts/http/_seed/v1/request.schema.json"),
            r#"{
  "$schema":"http://json-schema.org/draft-07/schema#",
  "title":"SeedEchoRequest",
  "type":"object",
  "required":["labels"],
  "properties":{
    "labels":{
      "type":"object",
      "patternProperties":{
        "^x-":{"type":"string","x-protection":{"atRest":"encrypt","keyScope":"tenant","aad":["tenant","configKey","field","schemaVersion"]}}
      },
      "additionalProperties":false
    }
  },
  "additionalProperties":false
}"#,
        )?;
        let result = generate(&root.join("contracts"), &root.join("generated/src"), false);
        let _ = std::fs::remove_dir_all(&root);
        let err = match result {
            Ok(()) => {
                anyhow::bail!("codegen must fail closed on patternProperties protection metadata")
            }
            Err(err) => err,
        };
        let message = format!("{err:#}");
        assert!(
            message.contains("patternProperties") && message.contains("FieldProtectionMetadata"),
            "错误应说明 patternProperties 无稳定 protection metadata path:\n{message}"
        );
        Ok(())
    }

    #[test]
    fn codegen_rejects_invalid_redaction_policy_without_validate_first() -> anyhow::Result<()> {
        let root = unique_tmp("codegen");
        seed_http(&root)?;
        std::fs::write(
            root.join("contracts/http/_seed/v1/request.schema.json"),
            "{\"$schema\":\"http://json-schema.org/draft-07/schema#\",\"title\":\"SeedEchoRequest\",\"type\":\"object\",\"required\":[\"apiKey\"],\"properties\":{\"apiKey\":{\"type\":\"string\"}},\"additionalProperties\":false}",
        )?;
        let result = generate(&root.join("contracts"), &root.join("generated/src"), false);
        let _ = std::fs::remove_dir_all(&root);
        let err = match result {
            Ok(()) => anyhow::bail!("codegen must fail closed on redaction policy violations"),
            Err(err) => err,
        };
        let message = format!("{err:#}");
        assert!(
            message.contains("redaction policy invalid") && message.contains("apiKey"),
            "错误应指向 redaction policy 与字段名:\n{message}"
        );
        Ok(())
    }

    #[test]
    fn codegen_rejects_active_http_without_auth_mode() -> anyhow::Result<()> {
        let root = unique_tmp("codegen");
        seed_http(&root)?;
        let dir = root.join("contracts/http/_seed/v1");
        std::fs::write(
            dir.join("contract.toml"),
            concat!(
                "id = \"seed.echo\"\n",
                "kind = \"http\"\n",
                "domain = \"_seed\"\n",
                "version = \"v1\"\n",
                "owner = \"_framework\"\n",
                "consistencyLevel = \"LocalOnly\"\n",
                "lifecycle = \"active\"\n",
                "path = \"/api/v1/_seed/echo\"\n",
                "method = \"POST\"\n",
                "[schemas]\n",
                "request = \"request.schema.json\"\n",
                "response = \"response.schema.json\"\n",
            ),
        )?;
        let result = generate(&root.join("contracts"), &root.join("generated/src"), false);
        let _ = std::fs::remove_dir_all(&root);
        assert!(
            result.is_err(),
            "active HTTP 缺 auth 时 codegen 须 fail-closed"
        );
        Ok(())
    }

    #[test]
    fn codegen_rejects_invalid_resource_sharing_without_validate_first() -> anyhow::Result<()> {
        let root = unique_tmp("codegen");
        seed_http(&root)?;
        write_seed_active_http(
            &root,
            concat!(
                "[endpoints.http]\n",
                "resource = \"resourceId\"\n",
                "[endpoints.http.auth]\n",
                "mode = \"permission\"\n",
                "permission = \"identity:policy:read\"\n",
                "[endpoints.http.resourceSharing]\n",
                "mode = \"tenantScoped\"\n",
                "reason = \"tenant-scoped routes must not carry opt-out reasons\"\n",
            ),
        )?;
        let result = generate(&root.join("contracts"), &root.join("generated/src"), false);
        let _ = std::fs::remove_dir_all(&root);
        assert!(
            result
                .as_ref()
                .err()
                .is_some_and(|err| err.to_string().contains("tenantScoped")),
            "tenantScoped + reason 须被 codegen 自守拒绝: {result:?}"
        );

        let root = unique_tmp("codegen");
        seed_http(&root)?;
        write_seed_active_http(
            &root,
            concat!(
                "[endpoints.http.auth]\n",
                "mode = \"permission\"\n",
                "permission = \"identity:policy:read\"\n",
                "[endpoints.http.resourceSharing]\n",
                "mode = \"global\"\n",
                "reason = \"shared route\"\n",
            ),
        )?;
        let result = generate(&root.join("contracts"), &root.join("generated/src"), false);
        let _ = std::fs::remove_dir_all(&root);
        assert!(
            result
                .as_ref()
                .err()
                .is_some_and(|err| err.to_string().contains("mode=global")),
            "global resourceSharing 缺 resource 须被 codegen 自守拒绝: {result:?}"
        );
        Ok(())
    }

    #[test]
    fn codegen_emits_global_resource_sharing_into_root_specs() -> anyhow::Result<()> {
        let root = unique_tmp("codegen");
        seed_http(&root)?;
        write_seed_active_http(
            &root,
            concat!(
                "[endpoints.http]\n",
                "resource = \"resourceId\"\n",
                "[endpoints.http.auth]\n",
                "mode = \"permission\"\n",
                "permission = \"identity:policy:read\"\n",
                "[endpoints.http.resourceSharing]\n",
                "mode = \"global\"\n",
                "reason = \"shared route\"\n",
            ),
        )?;
        let gen_src = root.join("generated/src");
        generate(&root.join("contracts"), &gen_src, false)?;
        let rendered = std::fs::read_to_string(gen_src.join("http/_seed_v1.rs"))?;
        let root_mod = std::fs::read_to_string(gen_src.join("http/mod.rs"))?;
        let _ = std::fs::remove_dir_all(&root);

        assert_generated_contains(
            &rendered,
            "::vocab::http::HttpResourceSharing::Global",
            "typed route evidence 应携带 global resourceSharing mode",
        );
        assert_generated_contains(
            &rendered,
            "mode: ROUTE.evidence().resource_sharing()",
            "endpoint SPEC sharing mode 应从 route evidence 派生",
        );
        assert_generated_contains(
            &rendered,
            "reason: Some(\"shared route\")",
            "endpoint SPEC 应携带 global opt-out reason",
        );
        assert_generated_contains(
            &root_mod,
            "_seed_v1::SPEC",
            "active global HTTP spec 应进入 root SPECS registry",
        );
        Ok(())
    }

    #[test]
    fn codegen_emits_http_consistency_level_inside_route_evidence() -> anyhow::Result<()> {
        let root = unique_tmp("codegen");
        seed_http(&root)?;
        write_seed_active_http(
            &root,
            concat!(
                "[endpoints.http.auth]\n",
                "mode = \"permission\"\n",
                "permission = \"identity:policy:read\"\n",
            ),
        )?;
        let gen_src = root.join("generated/src");
        generate(&root.join("contracts"), &gen_src, false)?;
        let rendered = std::fs::read_to_string(gen_src.join("http/_seed_v1.rs"))?;
        let root_mod = std::fs::read_to_string(gen_src.join("http/mod.rs"))?;
        let _ = std::fs::remove_dir_all(&root);

        assert!(
            !root_mod.contains("pub enum HttpConsistencyLevel"),
            "generated must not mirror the canonical vocab consistency enum"
        );
        assert!(
            !rendered.contains("::vocab::HttpConsistencyLevel::LocalOnly"),
            "runtime consistency must derive from the typed binding marker"
        );
        assert_generated_contains(
            &root_mod,
            "pub route: ::vocab::HttpRouteEvidence",
            "HttpSpec should expose one atomic route proof",
        );
        assert_generated_contains(
            &root_mod,
            "pub mount_key: &'static str",
            "HttpSpec should expose the canonical generated mount identity",
        );
        for removed in [
            "pub contract_id:",
            "pub contract:",
            "pub consistency_level:",
            "pub effect_profile:",
            "pub path:",
            "pub method:",
            "pub auth:",
            "pub resource:",
            "pub self_scoped:",
        ] {
            assert!(
                !root_mod.contains(removed),
                "parallel HttpSpec field must be removed: {removed}"
            );
        }
        assert_generated_contains(
            &rendered,
            "pub const ROUTE: ::vocab::HttpRouteBinding<RouteMarker, ::vocab::http::LocalOnly>",
            "endpoint should expose a contract-specific typed route binding",
        );
        assert_generated_contains(
            &rendered,
            "route: ROUTE.evidence()",
            "HttpSpec should derive runtime evidence from the typed binding",
        );
        assert_generated_contains(
            &rendered,
            "::vocab::HttpContractOwner::framework()",
            "framework owner must be carried by generated route evidence",
        );
        assert_generated_contains(
            &rendered,
            "mount_key: \"_seed_v1\"",
            "flat HTTP SPEC should carry its canonical generated mount identity",
        );
        assert_generated_contains(
            &rendered,
            "::vocab::http::HttpSuccessStatus::new(200)",
            "success status should be sealed inside route evidence",
        );
        assert_generated_contains(
            &rendered,
            "::vocab::http::HttpIdempotency::Idempotent",
            "idempotency should be sealed inside route evidence",
        );
        for removed in ["pub success_status:", "pub idempotency:"] {
            assert!(
                !root_mod.contains(removed),
                "wire semantics must not create a parallel HttpSpec field: {removed}"
            );
        }
        Ok(())
    }

    #[test]
    fn codegen_binds_get_request_schema_properties_as_query_vocabulary() -> anyhow::Result<()> {
        let root = unique_tmp("codegen-query-parameters");
        seed_http(&root)?;
        write_seed_active_http(
            &root,
            concat!(
                "[endpoints.http.auth]\n",
                "mode = \"permission\"\n",
                "permission = \"identity:policy:read\"\n",
            ),
        )?;
        let dir = root.join("contracts/http/_seed/v1");
        let manifest = std::fs::read_to_string(dir.join("contract.toml"))?
            .replace("method = \"POST\"", "method = \"GET\"");
        std::fs::write(dir.join("contract.toml"), manifest)?;
        std::fs::write(
            dir.join("request.schema.json"),
            r#"{"$schema":"http://json-schema.org/draft-07/schema#","title":"SeedEchoRequest","type":"object","required":["limit"],"properties":{"cursor":{"type":"string"},"limit":{"type":"integer"}},"additionalProperties":false}"#,
        )?;
        let gen_src = root.join("generated/src");

        generate(&root.join("contracts"), &gen_src, false)?;

        let rendered = std::fs::read_to_string(gen_src.join("http/_seed_v1.rs"))?;
        let _ = std::fs::remove_dir_all(&root);
        assert_generated_contains(
            &rendered,
            "HttpQueryParameterSpec::from_static(\"cursor\", false)",
            "optional GET query property must be generated",
        );
        assert_generated_contains(
            &rendered,
            "HttpQueryParameterSpec::from_static(\"limit\", true)",
            "required GET query property must be generated",
        );
        assert_generated_contains(
            &rendered,
            "\"GET\",\n        QUERY_PARAMETERS,",
            "route evidence must own the generated query vocabulary",
        );
        Ok(())
    }

    #[test]
    fn codegen_binds_each_typed_http_response_to_its_status() -> anyhow::Result<()> {
        let root = unique_tmp("codegen-http-responses");
        seed_http_with_typed_responses(&root)?;
        let gen_src = root.join("generated/src");
        generate(&root.join("contracts"), &gen_src, false)?;
        let rendered = std::fs::read_to_string(gen_src.join("http/_seed_v1.rs"))?;
        let root_mod = std::fs::read_to_string(gen_src.join("http/mod.rs"))?;
        let _ = std::fs::remove_dir_all(&root);

        for needle in [
            "impl super::HttpResponseBinding for SeedEchoResponse",
            "impl super::HttpResponseBinding for SeedEchoNotFoundResponse",
            "impl super::HttpResponseBinding for SeedEchoConflictResponse",
            "const STATUS: u16 = 200",
            "const STATUS: u16 = 404",
            "const STATUS: u16 = 409",
            "pub const RESPONSES: &[super::HttpResponseSpec]",
            "pub struct SeedEchoResponseError(SeedEchoResponseErrorKind)",
            "enum SeedEchoResponseErrorKind",
            "Status404(SeedEchoNotFoundResponse)",
            "Status409(SeedEchoConflictResponse)",
            "pub fn status_404(response: SeedEchoNotFoundResponse) -> Self",
            "pub fn status_409(response: SeedEchoConflictResponse) -> Self",
            "pub enum SeedEchoResponseEnvelope",
            "Success(SeedEchoResponse)",
            "Error(SeedEchoResponseError)",
            "pub struct SeedEchoFrameworkFailure",
            "pub type SeedEchoHandlerResult =",
            "::std::result::Result<SeedEchoResponseEnvelope, SeedEchoFrameworkFailure>",
            "impl ::vocab::http::DeclaredHttpResponseMarker for RouteMarker",
            "type HandlerOutput = SeedEchoHandlerResult",
        ] {
            assert_generated_contains(
                &rendered,
                needle,
                "typed response binding must preserve status-to-schema identity",
            );
        }
        for response_ty in [
            "SeedEchoResponse",
            "SeedEchoNotFoundResponse",
            "SeedEchoConflictResponse",
            "SeedEchoResponseError",
            "SeedEchoResponseEnvelope",
        ] {
            assert_generated_contains(
                &rendered,
                &format!("impl ::axum::response::IntoResponse for {response_ty}"),
                "typed responses and aggregate envelopes must own their wire conversion",
            );
        }
        assert_generated_contains(
            &root_mod,
            "pub trait HttpResponseBinding",
            "generated clients and servers need a common typed response seam",
        );
        Ok(())
    }

    #[test]
    fn codegen_fixed_error_factory_falls_back_for_unowned_constraints() -> anyhow::Result<()> {
        let root = unique_tmp("codegen-http-fixed-response-fallback");
        seed_http_with_typed_responses(&root)?;
        let dir = root.join("contracts/http/_seed/v1");
        std::fs::write(
            dir.join("not-found.schema.json"),
            serde_json::to_vec_pretty(&synthetic_fixed_error_schema(
                "SeedEchoNotFoundResponse",
                "ERR_NOT_FOUND",
                true,
                None,
            ))?,
        )?;
        std::fs::write(
            dir.join("conflict.schema.json"),
            serde_json::to_vec_pretty(&synthetic_fixed_error_schema(
                "SeedEchoConflictResponse",
                "ERR_CONFLICT",
                false,
                Some(8),
            ))?,
        )?;
        let gen_src = root.join("generated/src");
        generate(&root.join("contracts"), &gen_src, false)?;
        let rendered = std::fs::read_to_string(gen_src.join("http/_seed_v1.rs"))?;
        let _ = std::fs::remove_dir_all(&root);

        for needle in [
            "pub fn status_404(response: SeedEchoNotFoundResponse) -> Self",
            "pub fn status_409(response: SeedEchoConflictResponse) -> Self",
        ] {
            assert_generated_contains(
                &rendered,
                needle,
                "constraints not wholly owned by the generated factory must retain typed input",
            );
        }
        Ok(())
    }

    #[test]
    fn codegen_fixed_error_factory_requires_an_exact_panic_free_schema_proof() -> anyhow::Result<()>
    {
        for (case, mutate) in [
            ("root-composition", 0_u8),
            ("error-composition", 1),
            ("wrong-details-type", 2),
        ] {
            let root = unique_tmp(&format!("codegen-http-fixed-response-{case}"));
            seed_http_with_typed_responses(&root)?;
            let mut schema = synthetic_fixed_error_schema(
                "SeedEchoNotFoundResponse",
                "ERR_NOT_FOUND",
                false,
                None,
            );
            match mutate {
                0 => schema["allOf"] = serde_json::json!([]),
                1 => schema["properties"]["error"]["minProperties"] = serde_json::json!(5),
                2 => {
                    schema["properties"]["error"]["properties"]["details"]["type"] =
                        serde_json::json!("object")
                }
                _ => bail!("closed invalid-schema fixture index escaped"),
            }
            let dir = root.join("contracts/http/_seed/v1");
            std::fs::write(
                dir.join("not-found.schema.json"),
                serde_json::to_vec_pretty(&schema)?,
            )?;
            let gen_src = root.join("generated/src");
            generate(&root.join("contracts"), &gen_src, false)?;
            let rendered = std::fs::read_to_string(gen_src.join("http/_seed_v1.rs"))?;
            let _ = std::fs::remove_dir_all(&root);
            assert_generated_contains(
                &rendered,
                "pub fn status_404(response: SeedEchoNotFoundResponse) -> Self",
                "unproved constraints must fall back to the ordinary typed DTO factory",
            );
        }

        let root = unique_tmp("codegen-http-fixed-response-panic-free");
        seed_http_with_typed_responses(&root)?;
        let dir = root.join("contracts/http/_seed/v1");
        std::fs::write(
            dir.join("not-found.schema.json"),
            serde_json::to_vec_pretty(&synthetic_fixed_error_schema(
                "SeedEchoNotFoundResponse",
                "ERR_NOT_FOUND",
                false,
                None,
            ))?,
        )?;
        let gen_src = root.join("generated/src");
        generate(&root.join("contracts"), &gen_src, false)?;
        let rendered = std::fs::read_to_string(gen_src.join("http/_seed_v1.rs"))?;
        let _ = std::fs::remove_dir_all(&root);
        assert_generated_contains(
            &rendered,
            "pub fn status_404(request_id: ::requestidmint::WireRequestId) -> Self",
            "proved fixed factories must require transport-owned request-id authority",
        );
        assert!(!rendered.contains("serde_json::from_value"));
        assert!(!rendered.contains("unreachable!"));
        Ok(())
    }

    #[test]
    fn codegen_marks_single_response_http_routes_as_open() -> anyhow::Result<()> {
        let root = unique_tmp("codegen-open-http-response");
        seed_http(&root)?;
        write_seed_active_http(
            &root,
            concat!("[endpoints.http.auth]\n", "mode = \"public\"\n"),
        )?;
        let gen_src = root.join("generated/src");
        generate(&root.join("contracts"), &gen_src, false)?;
        let rendered = std::fs::read_to_string(gen_src.join("http/_seed_v1.rs"))?;
        let _ = std::fs::remove_dir_all(&root);

        assert_generated_contains(
            &rendered,
            "impl ::vocab::http::OpenHttpResponseMarker for RouteMarker",
            "single-response routes must stay on the open response constructor",
        );
        assert!(
            !rendered.contains("DeclaredHttpResponseMarker for RouteMarker"),
            "single-response routes must not select the declared response constructor"
        );
        Ok(())
    }

    #[test]
    fn codegen_emits_typed_http_producer_binding_and_closed_registry() -> anyhow::Result<()> {
        let root = unique_tmp("codegen-http-producer");
        seed_http(&root)?;
        seed_event_with_subscription(&root)?;
        write_seed_active_http_contract(
            &root,
            "OutboxFact",
            concat!(
                "[endpoints.http.auth]\n",
                "mode = \"permission\"\n",
                "permission = \"identity:policy:read\"\n",
            ),
            Some(concat!(
                "[effectProfile]\n",
                "effects = [\"auth\", \"business-write\", \"business-transaction\", \"outbox\", \"publish\"]\n",
            )),
            concat!(
                "[capabilities.outbox]\n",
                "role = \"producer\"\n",
                "atomicity = \"same-transaction\"\n",
                "emits = [\"seed.happened\"]\n",
            ),
        )?;
        let contracts = load_contract_fixtures(&root.join("contracts"))?;
        let producer_contract = contracts
            .iter()
            .find(|contract| contract.manifest().id == "seed.echo")
            .context("seed producer")?;
        let carrier = GeneratedCarrier::from_contract(producer_contract)?;
        assert_eq!(carrier.route_key()?, "_seed_v1");
        assert_eq!(
            carrier.item(GeneratedItem::Producer)?.symbol,
            "generated::http::_seed_v1::PRODUCER"
        );

        let gen_src = root.join("generated/src");
        generate(&root.join("contracts"), &gen_src, false)?;
        let rendered = std::fs::read_to_string(gen_src.join("http/_seed_v1.rs"))?;
        let root_mod = std::fs::read_to_string(gen_src.join("http/mod.rs"))?;
        let _ = std::fs::remove_dir_all(&root);

        for needle in [
            "pub const EMITTED_FACTS: &[::vocab::ContractBinding]",
            "crate::event::_seed_v1::CONTRACT",
            "pub const PRODUCER: ::vocab::http::HttpProducerBinding<RouteMarker>",
            "HttpProducerBinding::from_static(ROUTE, EMITTED_FACTS)",
        ] {
            assert_generated_contains(
                &rendered,
                needle,
                "OutboxFact producer should carry a generated typed binding",
            );
        }
        assert_generated_contains(
            &root_mod,
            "pub const OUTBOX_PRODUCERS: &[::vocab::http::HttpProducerEvidence]",
            "HTTP root module should expose a closed producer registry",
        );
        assert_generated_contains(
            &root_mod,
            "_seed_v1::PRODUCER.evidence()",
            "active producer should enter the closed registry",
        );
        Ok(())
    }

    #[test]
    fn producer_codegen_rejects_duplicate_emitted_fact() -> anyhow::Result<()> {
        let root = unique_tmp("codegen-http-producer-duplicate");
        seed_http(&root)?;
        seed_event_with_subscription(&root)?;
        write_seed_active_http_contract(
            &root,
            "OutboxFact",
            concat!(
                "[endpoints.http.auth]\n",
                "mode = \"permission\"\n",
                "permission = \"identity:policy:read\"\n",
            ),
            Some(concat!(
                "[effectProfile]\n",
                "effects = [\"business-write\", \"business-transaction\", \"outbox\", \"publish\"]\n",
            )),
            concat!(
                "[capabilities.outbox]\n",
                "role = \"producer\"\n",
                "atomicity = \"same-transaction\"\n",
                "emits = [\"seed.happened\", \"seed.happened\"]\n",
            ),
        )?;
        let result = generate(&root.join("contracts"), &root.join("generated/src"), false);
        let _ = std::fs::remove_dir_all(&root);
        let error = match result {
            Ok(()) => anyhow::bail!("duplicate emitted facts unexpectedly passed codegen"),
            Err(error) => error,
        };
        assert!(
            error
                .to_string()
                .contains("repeats emitted fact seed.happened"),
            "unexpected error: {error:#}"
        );
        Ok(())
    }

    #[test]
    fn http_mount_key_uses_discovered_slug_not_contract_id_suffix() -> anyhow::Result<()> {
        let root = unique_tmp("codegen-mount-key");
        seed_http(&root)?;
        let domain_dir = root.join("contracts/http/_seed");
        let flat = domain_dir.join("v1");
        let staged = domain_dir.join("v1-staged");
        std::fs::rename(&flat, &staged)?;
        std::fs::create_dir_all(&flat)?;
        let nested = flat.join("filesystem-slug");
        std::fs::rename(&staged, &nested)?;
        let manifest_path = nested.join("contract.toml");
        let manifest = std::fs::read_to_string(&manifest_path)?
            .replace("id = \"seed.echo\"", "id = \"seed.semantic-name\"");
        std::fs::write(&manifest_path, manifest)?;
        let contract = load_contract_fixtures(&root.join("contracts"))?
            .pop()
            .context("seed contract missing")?;

        assert_eq!(
            render_http_mount_key(&contract)?,
            "_seed_v1::filesystem_slug"
        );
        let _ = std::fs::remove_dir_all(root);
        Ok(())
    }

    #[test]
    fn runtime_inventory_projection_derives_schema_version_from_schema_const() -> anyhow::Result<()>
    {
        let root = unique_tmp("codegen-runtime-inventory-schema-version");
        seed_http(&root)?;
        let dir = root.join("contracts/http/_seed/v1");
        let manifest = std::fs::read_to_string(dir.join("contract.toml"))?
            .replace("id = \"seed.echo\"", "id = \"runtime.inventory\"")
            .replace("domain = \"_seed\"", "domain = \"runtime\"");
        std::fs::write(dir.join("contract.toml"), manifest)?;
        std::fs::write(
            dir.join("response.schema.json"),
            r#"{"$schema":"http://json-schema.org/draft-07/schema#","title":"RuntimeInventoryResponse","type":"object","required":["data"],"properties":{"data":{"type":"object","required":["schemaVersion"],"properties":{"schemaVersion":{"type":"integer","const":7}},"additionalProperties":false}},"additionalProperties":false}"#,
        )?;
        let contract = load_contract_fixtures(&root.join("contracts"))?
            .pop()
            .context("runtime inventory contract missing")?;
        let rendered = render_runtime_inventory_projection(&contract)?;
        assert!(rendered.contains("schema_version: RuntimeInventorySchemaVersion::V7"));

        let schema_path = dir.join("response.schema.json");
        let schema = std::fs::read_to_string(&schema_path)?.replace("\"const\":7", "\"minimum\":1");
        std::fs::write(schema_path, schema)?;
        let contract = load_contract_fixtures(&root.join("contracts"))?
            .pop()
            .context("runtime inventory contract missing")?;
        let error = match render_runtime_inventory_projection(&contract) {
            Ok(_) => anyhow::bail!("missing schemaVersion const must fail closed"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("schemaVersion.const"));
        let _ = std::fs::remove_dir_all(root);
        Ok(())
    }

    #[test]
    fn codegen_emits_http_effect_profile_into_spec() -> anyhow::Result<()> {
        let root = unique_tmp("codegen");
        seed_http(&root)?;
        write_seed_active_http(
            &root,
            concat!(
                "[endpoints.http.auth]\n",
                "mode = \"permission\"\n",
                "permission = \"identity:policy:read\"\n",
            ),
        )?;
        let gen_src = root.join("generated/src");
        generate(&root.join("contracts"), &gen_src, false)?;
        let rendered = std::fs::read_to_string(gen_src.join("http/_seed_v1.rs"))?;
        let root_mod = std::fs::read_to_string(gen_src.join("http/mod.rs"))?;
        let _ = std::fs::remove_dir_all(&root);

        assert!(
            !root_mod.contains("pub struct EffectProfile"),
            "generated must not mirror the canonical vocab effect profile"
        );
        assert!(
            !root_mod.contains("pub enum EffectKind"),
            "generated must not mirror the canonical vocab effect enum"
        );
        assert_generated_contains(
            &rendered,
            "pub const EFFECTS: &[::vocab::HttpEffectKind]",
            "endpoint module should emit canonical vocab effect kind slice",
        );
        assert_generated_contains(
            &rendered,
            "::vocab::HttpEffectKind::Auth",
            "endpoint effects should include auth",
        );
        assert_generated_contains(
            &rendered,
            "::vocab::HttpEffectKind::Read",
            "endpoint effects should include read",
        );
        assert_generated_contains(
            &rendered,
            "pub const EFFECT_PROFILE: ::vocab::HttpEffectProfile = ::vocab::HttpEffectProfile::new(EFFECTS);",
            "endpoint module should construct the validated canonical profile",
        );
        assert_generated_contains(
            &rendered,
            "    EFFECT_PROFILE,",
            "route evidence should carry the generated effect profile",
        );
        assert_generated_contains(
            &rendered,
            "local_tx: None",
            "non-LocalTx endpoint SPEC should explicitly carry no LocalTx evidence",
        );
        assert!(
            !rendered.contains("pub const LOCAL_TX:"),
            "non-LocalTx endpoint modules must not expose LocalTx contract evidence"
        );
        Ok(())
    }

    #[test]
    fn codegen_emits_all_http_effect_kind_variants() -> anyhow::Result<()> {
        let root = unique_tmp("codegen");
        seed_http(&root)?;
        write_seed_active_http_contract(
            &root,
            "LocalOnly",
            concat!(
                "[endpoints.http.auth]\n",
                "mode = \"permission\"\n",
                "permission = \"identity:policy:read\"\n",
            ),
            Some(concat!(
                "[effectProfile]\n",
                "effects = [\n",
                "  \"read\",\n",
                "  \"auth\",\n",
                "  \"projection\",\n",
                "  \"business-write\",\n",
                "  \"business-transaction\",\n",
                "  \"outbox\",\n",
                "  \"publish\",\n",
                "  \"workflow\",\n",
                "  \"saga\",\n",
                "  \"reconcile\",\n",
                "  \"worker\",\n",
                "  \"cross-tenant-audit\",\n",
                "]\n",
            )),
            "",
        )?;
        let gen_src = root.join("generated/src");
        generate(&root.join("contracts"), &gen_src, false)?;
        let rendered = std::fs::read_to_string(gen_src.join("http/_seed_v1.rs"))?;
        let _ = std::fs::remove_dir_all(&root);

        for variant in [
            "Read",
            "Auth",
            "Projection",
            "BusinessWrite",
            "BusinessTransaction",
            "Outbox",
            "Publish",
            "Workflow",
            "Saga",
            "Reconcile",
            "Worker",
            "CrossTenantAudit",
        ] {
            assert_generated_contains(
                &rendered,
                &format!("::vocab::HttpEffectKind::{variant}"),
                "all manifest effect values should render to canonical vocab variants",
            );
        }
        Ok(())
    }

    #[test]
    fn codegen_emits_local_tx_registry() -> anyhow::Result<()> {
        let root = unique_tmp("codegen");
        seed_http(&root)?;
        write_seed_active_http_contract(
            &root,
            "LocalTx",
            concat!(
                "[endpoints.http.auth]\n",
                "mode = \"permission\"\n",
                "permission = \"identity:policy:read\"\n",
            ),
            Some(BUSINESS_LOCAL_TX_EFFECT_PROFILE),
            concat!(
                "[capabilities.localTx]\n",
                "boundary = \"single-domain\"\n",
                "txModel = \"tenant-scoped-uow\"\n",
                "retry = \"bounded-transient\"\n",
                "commitUnknown = \"not-retryable\"\n",
            ),
        )?;
        let gen_src = root.join("generated/src");
        generate(&root.join("contracts"), &gen_src, false)?;
        let rendered = std::fs::read_to_string(gen_src.join("http/_seed_v1.rs"))?;
        let root_mod = std::fs::read_to_string(gen_src.join("http/mod.rs"))?;
        let local_tx_specs = generated_http_spec_slice(&root_mod, "LOCAL_TX_SPECS")?;
        let _ = std::fs::remove_dir_all(&root);

        assert_generated_contains(
            &root_mod,
            "pub struct LocalTxSpec",
            "HTTP root module should expose generated LocalTx metadata",
        );
        for forbidden in [
            "pub enum LocalTxBoundary",
            "pub enum LocalTxModel",
            "pub enum LocalTxRetry",
            "pub enum LocalTxCommitUnknown",
        ] {
            assert!(
                !root_mod.contains(forbidden),
                "HTTP root module must consume the canonical vocab type instead of generating a duplicate: {forbidden}"
            );
        }
        assert_generated_contains(
            &root_mod,
            "pub const LOCAL_TX_SPECS: &[HttpSpec]",
            "HTTP root module should expose active LocalTx registry",
        );
        assert_generated_contains(
            local_tx_specs,
            "_seed_v1::SPEC",
            "active LocalTx endpoint should enter LOCAL_TX_SPECS",
        );
        assert_generated_contains(
            &rendered,
            "pub const LOCAL_TX: super::LocalTxSpec",
            "LocalTx endpoint modules should expose non-optional typed contract evidence",
        );
        assert_generated_contains(
            &rendered,
            "local_tx: Some(LOCAL_TX)",
            "LocalTx endpoint SPEC should reuse its module-local evidence constant",
        );
        for needle in [
            "boundary: ::vocab::LocalTxBoundary::SingleDomain",
            "tx_model: ::vocab::LocalTxModel::TenantScopedUow",
            "retry: ::vocab::LocalTxRetry::BoundedTransient",
            "commit_unknown: ::vocab::LocalTxCommitUnknown::NotRetryable",
        ] {
            assert_generated_contains(
                &rendered,
                needle,
                "LocalTx endpoint SPEC should carry generated closed-enum evidence",
            );
        }
        Ok(())
    }

    #[test]
    fn codegen_emits_local_only_receipt_target() -> anyhow::Result<()> {
        let root = unique_tmp("codegen-local-only-receipt-target");
        seed_http(&root)?;
        write_seed_active_http(
            &root,
            concat!(
                "[endpoints.http.auth]\n",
                "mode = \"permission\"\n",
                "permission = \"identity:policy:read\"\n",
            ),
        )?;
        let gen_src = root.join("generated/src");
        generate(&root.join("contracts"), &gen_src, false)?;
        let rendered = std::fs::read_to_string(gen_src.join("http/_seed_v1.rs"))?;
        let root_mod = std::fs::read_to_string(gen_src.join("http/mod.rs"))?;
        let local_only_specs = generated_http_spec_slice(&root_mod, "LOCAL_ONLY_SPECS")?;
        let _ = std::fs::remove_dir_all(&root);

        assert_generated_contains(
            &rendered,
            "pub enum LocalOnlyConformanceMarker {}",
            "active LocalOnly HTTP endpoint should expose its unforgeable receipt target type",
        );
        assert_generated_contains(
            local_only_specs,
            "_seed_v1::SPEC",
            "active LocalOnly HTTP endpoint should enter LOCAL_ONLY_SPECS",
        );
        Ok(())
    }

    #[test]
    fn local_only_receipt_targets_exclude_non_active_and_non_local_only_http() -> anyhow::Result<()>
    {
        for lifecycle in ["draft", "deprecated"] {
            let root = unique_tmp("codegen-non-active-local-only-receipt-target");
            seed_http(&root)?;
            let manifest_path = root.join("contracts/http/_seed/v1/contract.toml");
            let manifest = std::fs::read_to_string(&manifest_path)?.replace(
                "lifecycle = \"draft\"",
                &format!("lifecycle = \"{lifecycle}\""),
            );
            std::fs::write(manifest_path, manifest)?;
            let gen_src = root.join("generated/src");
            generate(&root.join("contracts"), &gen_src, false)?;
            let rendered = std::fs::read_to_string(gen_src.join("http/_seed_v1.rs"))?;
            let root_mod = std::fs::read_to_string(gen_src.join("http/mod.rs"))?;
            let _ = std::fs::remove_dir_all(&root);

            assert!(
                !rendered.contains("LocalOnlyConformanceMarker"),
                "{lifecycle} LocalOnly HTTP endpoint must not expose a receipt target"
            );
            assert!(
                generated_http_spec_slice(&root_mod, "LOCAL_ONLY_SPECS")?.contains("&[]"),
                "{lifecycle} LocalOnly HTTP endpoint must not enter LOCAL_ONLY_SPECS"
            );
        }

        let root = unique_tmp("codegen-non-local-only-receipt-target");
        seed_http(&root)?;
        write_seed_active_http_contract(
            &root,
            "LocalTx",
            concat!(
                "[endpoints.http.auth]\n",
                "mode = \"permission\"\n",
                "permission = \"identity:policy:read\"\n",
            ),
            Some(BUSINESS_LOCAL_TX_EFFECT_PROFILE),
            concat!(
                "[capabilities.localTx]\n",
                "boundary = \"single-domain\"\n",
                "txModel = \"tenant-scoped-uow\"\n",
                "retry = \"bounded-transient\"\n",
                "commitUnknown = \"not-retryable\"\n",
            ),
        )?;
        let gen_src = root.join("generated/src");
        generate(&root.join("contracts"), &gen_src, false)?;
        let rendered = std::fs::read_to_string(gen_src.join("http/_seed_v1.rs"))?;
        let root_mod = std::fs::read_to_string(gen_src.join("http/mod.rs"))?;
        let _ = std::fs::remove_dir_all(&root);

        assert!(
            !rendered.contains("LocalOnlyConformanceMarker"),
            "active non-LocalOnly HTTP endpoint must not expose a receipt target"
        );
        assert!(
            generated_http_spec_slice(&root_mod, "LOCAL_ONLY_SPECS")?.contains("&[]"),
            "active non-LocalOnly HTTP endpoint must not enter LOCAL_ONLY_SPECS"
        );
        Ok(())
    }

    #[test]
    fn codegen_emits_repo_atomic_cas_local_tx_model() -> anyhow::Result<()> {
        let root = unique_tmp("codegen-repo-atomic-cas");
        seed_http(&root)?;
        write_seed_active_http_contract(
            &root,
            "LocalTx",
            concat!(
                "[endpoints.http.auth]\n",
                "mode = \"permission\"\n",
                "permission = \"identity:policy:read\"\n",
            ),
            Some(BUSINESS_LOCAL_TX_EFFECT_PROFILE),
            concat!(
                "[capabilities.localTx]\n",
                "boundary = \"single-domain\"\n",
                "txModel = \"repo-atomic-cas\"\n",
                "retry = \"bounded-transient\"\n",
                "commitUnknown = \"not-retryable\"\n",
            ),
        )?;
        let gen_src = root.join("generated/src");
        generate(&root.join("contracts"), &gen_src, false)?;
        let rendered = std::fs::read_to_string(gen_src.join("http/_seed_v1.rs"))?;
        let _ = std::fs::remove_dir_all(&root);

        assert_generated_contains(
            &rendered,
            "tx_model: ::vocab::LocalTxModel::RepoAtomicCas",
            "repo atomic CAS manifest model should render to canonical vocab evidence",
        );
        Ok(())
    }

    #[test]
    fn codegen_rejects_active_http_without_effect_profile() -> anyhow::Result<()> {
        let root = unique_tmp("codegen");
        seed_http(&root)?;
        write_seed_active_http_without_effect_profile(
            &root,
            concat!(
                "[endpoints.http.auth]\n",
                "mode = \"permission\"\n",
                "permission = \"identity:policy:read\"\n",
            ),
        )?;
        let result = generate(&root.join("contracts"), &root.join("generated/src"), false);
        let _ = std::fs::remove_dir_all(&root);
        assert!(
            result
                .as_ref()
                .err()
                .is_some_and(|err| err.to_string().contains("effectProfile")),
            "active HTTP 缺 effectProfile 须被 codegen 自守拒绝: {result:?}"
        );
        Ok(())
    }

    #[test]
    fn codegen_rejects_local_tx_without_capability() -> anyhow::Result<()> {
        let root = unique_tmp("codegen");
        seed_http(&root)?;
        write_seed_active_http_contract(
            &root,
            "LocalTx",
            concat!(
                "[endpoints.http.auth]\n",
                "mode = \"permission\"\n",
                "permission = \"identity:policy:read\"\n",
            ),
            Some(BUSINESS_LOCAL_TX_EFFECT_PROFILE),
            "",
        )?;
        let result = generate(&root.join("contracts"), &root.join("generated/src"), false);
        let _ = std::fs::remove_dir_all(&root);
        assert!(
            result
                .as_ref()
                .err()
                .is_some_and(|err| err.to_string().contains("capabilities.localTx")),
            "LocalTx HTTP 缺 capabilities.localTx 须被 codegen 自守拒绝: {result:?}"
        );
        Ok(())
    }

    #[test]
    fn codegen_emits_all_http_consistency_level_variants() {
        for (level, expected) in [
            (ConsistencyLevel::LocalOnly, "LocalOnly"),
            (ConsistencyLevel::LocalTx, "LocalTx"),
            (ConsistencyLevel::OutboxFact, "OutboxFact"),
            (ConsistencyLevel::WorkflowEventual, "WorkflowEventual"),
            (ConsistencyLevel::DeviceLatent, "DeviceLatent"),
        ] {
            assert_eq!(
                render_http_consistency_level(level),
                expected,
                "HTTP consistencyLevel manifest variant should map to generated enum variant"
            );
        }
    }

    #[test]
    fn codegen_rejects_http_request_tenant_id() -> anyhow::Result<()> {
        let root = unique_tmp("codegen");
        seed_http(&root)?;
        std::fs::write(
            root.join("contracts/http/_seed/v1/request.schema.json"),
            r#"{"$schema":"http://json-schema.org/draft-07/schema#","title":"SeedEchoRequest","type":"object","required":["tenantId"],"properties":{"tenantId":{"type":"string"}},"additionalProperties":false}"#,
        )?;
        let result = generate(&root.join("contracts"), &root.join("generated/src"), false);
        let _ = std::fs::remove_dir_all(&root);
        assert!(
            result
                .as_ref()
                .err()
                .is_some_and(|err| err.to_string().contains("tenantId")),
            "HTTP request tenantId 须被 codegen 拒绝: {result:?}"
        );
        Ok(())
    }

    #[test]
    fn module_name_joins_domain_version() {
        assert_eq!(module_name("_seed", "v1"), "_seed_v1");
    }

    #[test]
    fn route_permission_expr_accepts_every_vocab_permission() -> anyhow::Result<()> {
        for permission in vocab::RoutePermissionId::ALL {
            let expr = render_route_permission_expr(permission.as_str(), "test permission")?;
            assert_eq!(
                expr,
                format!("::vocab::RoutePermissionId::{}", permission.variant_name())
            );
        }
        Ok(())
    }

    #[test]
    fn normalize_enforces_single_trailing_newline() {
        assert_eq!(normalize("a\n\n\n"), "a\n");
        assert_eq!(normalize("a"), "a\n");
    }

    #[test]
    fn generate_then_check_is_clean_and_idempotent() -> anyhow::Result<()> {
        let root = unique_tmp("codegen");
        seed_http(&root)?;
        let contracts = root.join("contracts");
        let gen_src = root.join("generated/src");
        generate(&contracts, &gen_src, false)?; // 写
        generate(&contracts, &gen_src, true)?; // 校验：无漂移
        let first = std::fs::read_to_string(gen_src.join("http/_seed_v1.rs"))?;
        generate(&contracts, &gen_src, false)?; // 二次生成
        let second = std::fs::read_to_string(gen_src.join("http/_seed_v1.rs"))?;
        let _ = std::fs::remove_dir_all(&root);
        assert_eq!(first, second, "派生须确定性（prettyplease 幂等）");
        assert!(first.contains("SeedEchoRequest") && first.contains("SeedEchoResponse"));
        Ok(())
    }

    #[test]
    fn check_fails_on_injected_drift() -> anyhow::Result<()> {
        // anti-vacuity（负向）：篡改 committed 文件后 --check 必失。
        let root = unique_tmp("codegen");
        seed_http(&root)?;
        let contracts = root.join("contracts");
        let gen_src = root.join("generated/src");
        generate(&contracts, &gen_src, false)?;
        std::fs::write(gen_src.join("http/_seed_v1.rs"), "// tampered\n")?;
        let drift = generate(&contracts, &gen_src, true);
        let _ = std::fs::remove_dir_all(&root);
        assert!(drift.is_err(), "漂移须被 --check 抓住");
        Ok(())
    }

    #[test]
    fn check_fails_on_orphan_file() -> anyhow::Result<()> {
        // anti-vacuity（负向）：多出无契约支撑的 .rs 必失。
        let root = unique_tmp("codegen");
        seed_http(&root)?;
        let contracts = root.join("contracts");
        let gen_src = root.join("generated/src");
        generate(&contracts, &gen_src, false)?;
        std::fs::write(gen_src.join("http/orphan.rs"), "// stray\n")?;
        let orphan = generate(&contracts, &gen_src, true);
        assert!(orphan.is_err(), "孤儿文件须被 --check 抓住");
        // 写模式删除孤儿后再 check 通过。
        generate(&contracts, &gen_src, false)?;
        let after = generate(&contracts, &gen_src, true);
        let _ = std::fs::remove_dir_all(&root);
        assert!(after.is_ok(), "写模式应已删孤儿");
        Ok(())
    }

    /// 多 kind 测试：同时含 http + event 两个契约，lib.rs 须同时含 `pub mod event;` 与 `pub mod http;`。
    #[test]
    fn generate_multi_kind_produces_both_mod_entries() -> anyhow::Result<()> {
        let root = unique_tmp("codegen");
        seed_http(&root)?;
        seed_event(&root)?;
        let contracts = root.join("contracts");
        let gen_src = root.join("generated/src");
        generate(&contracts, &gen_src, false)?;
        let lib_rs = std::fs::read_to_string(gen_src.join("lib.rs"))?;
        let _ = std::fs::remove_dir_all(&root);
        assert!(
            lib_rs.contains("pub mod event;"),
            "lib.rs 缺 event mod: {lib_rs}"
        );
        assert!(
            lib_rs.contains("pub mod http;"),
            "lib.rs 缺 http mod: {lib_rs}"
        );
        Ok(())
    }

    /// format_rust 失败路径：传非法 Rust 须返回 Err。
    #[test]
    fn format_rust_rejects_invalid_syntax() {
        let result = format_rust("fn (");
        assert!(result.is_err(), "非法 Rust 须使 format_rust 返 Err");
    }

    /// event glue 测试（#1120）：含 `[[subscriptions]]` 的 event 契约派生 .rs 须含：
    /// - `CONTRACT_ID` 常量（绑定 `contract.toml` id 字段）
    /// - `TOPIC` 常量（绑定 topic 字段）
    /// - 单一 `EventSpec` 内嵌 manifest-derived subscription coordinates
    /// - typed subscription carrier 绑定 consumer / group，`SubscriptionSpec` 定义在 `event/mod.rs`
    ///
    /// anti-vacuity：无 subscriptions 的 draft event 仍生成 sealed emit carrier + CONTRACT_ID / TOPIC。
    ///
    /// INVARIANT: CONTRACT-BINDING-FUNNEL-01 { level = "Medium", exec = "check", source = "code" }—— 守 `CONTRACT: ContractBinding` 由 manifest `domain` + `id`
    /// + `version` + declared schema hash 同源派生（domain 取自 manifest 而非 id 前缀），golden 锁。
    #[test]
    #[allow(clippy::cognitive_complexity)] // reason: golden glue emission asserts many sealed carriers in one fixture.
    fn event_glue_with_subscription_emitted() -> anyhow::Result<()> {
        let root = unique_tmp("codegen_glue");
        seed_event_with_subscription(&root)?;
        let contracts = root.join("contracts");
        let gen_src = root.join("generated/src");
        generate(&contracts, &gen_src, false)?;
        let rendered = std::fs::read_to_string(gen_src.join("event/_seed_v1.rs"))?;
        let mod_rs = std::fs::read_to_string(gen_src.join("event/mod.rs"))?;
        let _ = std::fs::remove_dir_all(&root);

        // CONTRACT_ID 和 TOPIC 常量
        assert!(
            rendered.contains(r#"pub const CONTRACT_ID: &str = "seed.happened";"#),
            "缺 CONTRACT_ID 常量:\n{rendered}"
        );
        assert!(
            rendered.contains(r#"pub const TOPIC: &str = "seed.happened";"#),
            "缺 TOPIC 常量:\n{rendered}"
        );
        // CONTRACT binding（#1193/#1618）：domain + id + version + schema_hash 同源；domain "_seed" ≠ id 首段 "seed" ⇒ 证明 domain
        // 取自 manifest domain 字段而非从 id 派生（rustfmt 可能换行，断言 from_static 调用子串）。
        assert!(
            rendered.contains("::vocab::ContractBinding::from_descriptor(")
                && rendered.contains(r#""_seed","#)
                && rendered.contains(r#""seed.happened","#)
                && rendered.contains(r#""v1","#)
                && rendered.contains(r#""sha256:"#),
            "缺 CONTRACT binding 常量:\n{rendered}"
        );
        assert!(
            rendered.contains("pub struct Contract")
                && rendered.contains("impl super::EventContract for Contract")
                && rendered.contains("type Payload = SeedHappenedPayload")
                && rendered.contains("pub async fn emit<E: super::EventEmit>"),
            "event payload must be bound to a sealed generated emit carrier:\n{rendered}"
        );
        assert!(
            !rendered.contains("GeneratedEventPayload"),
            "open event payload provenance must not remain in generated output:\n{rendered}"
        );
        // 每事件只有一个 SPEC，subscription 嵌套在同一 EventSpec。
        assert!(
            rendered.contains("SubscriptionSpec::new(")
                && rendered.contains(r#""audit""#)
                && rendered.contains(r#""audit.seed-happened""#)
                && rendered.contains("SubscriptionDispatchKey::SeedHappenedV1Audit")
                && rendered.contains("::vocab::ExternalEffectPolicy::TransactionalOnly"),
            "SPEC 缺 consumer 字面量:\n{rendered}"
        );
        assert_subscription_wire_semantics(&rendered, &mod_rs);
        assert!(
            rendered.contains("super::PartitionKeyStrategy::None"),
            "SPEC 缺 typed partition strategy:\n{rendered}"
        );
        assert!(
            rendered.contains("super::SubscriberReadiness::Required"),
            "SPEC 缺 typed readiness:\n{rendered}"
        );
        // SubscriptionSpec 定义在 mod.rs（子模块经 super:: 引用）
        assert!(
            mod_rs.contains("pub struct SubscriptionSpec"),
            "mod.rs 缺 SubscriptionSpec 定义:\n{mod_rs}"
        );
        assert!(
            mod_rs.contains("pub trait EventContract: private::Sealed")
                && mod_rs.contains("pub trait EventEmit")
                && mod_rs.contains("pub trait EventSubscription: private::Sealed")
                && mod_rs.contains("pub trait EventSubscribe"),
            "event/mod.rs 缺 sealed authoring/subscription seams:\n{mod_rs}"
        );
        assert!(
            rendered.contains("pub struct AuditSubscription")
                && rendered.contains("impl super::EventSubscription for AuditSubscription")
                && rendered.contains("pub fn subscribe_audit<Reg: super::EventSubscribe>"),
            "event module 缺 manifest-derived typed subscription wrapper:\n{rendered}"
        );
        assert!(
            mod_rs.contains("pub const EVENTS: &[EventSpec]"),
            "mod.rs 缺 root EVENTS registry:\n{mod_rs}"
        );
        assert!(
            mod_rs.contains("_seed_v1::SPEC"),
            "root registry 应只引用每事件 SPEC:\n{mod_rs}"
        );
        assert!(mod_rs.contains("pub const fn schema_hash"));
        // 子模块通过 super:: 引用（不重复定义）
        assert!(
            rendered.contains("pub const SPEC: super::EventSpec"),
            "子模块应生成单一 EventSpec:\n{rendered}"
        );
        assert!(!rendered.contains("pub const SUBSCRIPTIONS"));
        assert!(!mod_rs.contains("pub const SUBSCRIPTIONS"));
        Ok(())
    }

    #[test]
    fn event_partition_strategy_mismatch_rejected() -> anyhow::Result<()> {
        let root = unique_tmp("codegen_event_partition_mismatch");
        seed_event_with_subscription(&root)?;
        let manifest = root.join("contracts/event/_seed/v1/contract.toml");
        let mut text = std::fs::read_to_string(&manifest)?;
        text.push_str(concat!(
            "[[subscriptions]]\n",
            "consumer = \"settings\"\n",
            "group = \"settings.seed-happened\"\n",
            "execution = \"adapter-native\"\n",
            "externalEffectPolicy = \"transactional-only\"\n",
            "[subscriptions.topology]\n",
            "partitionKey = \"aggregate\"\n",
            "readiness = \"required\"\n",
        ));
        std::fs::write(&manifest, text)?;
        let result = generate(&root.join("contracts"), &root.join("generated/src"), false);
        let _ = std::fs::remove_dir_all(&root);
        assert!(
            result.is_err(),
            "同一 event 的 partition strategy 漂移必须失败"
        );
        Ok(())
    }

    /// saga glue 测试（#1651）：saga 契约派生 .rs 须含 CONTRACT_ID / CONTRACT / POLICY / SPEC；
    /// `SagaSpec` 定义在 `saga/mod.rs`，per-saga 模块经 `super::` 引用到 vocab 原子 binding。
    #[test]
    fn saga_glue_with_policy_spec_emitted() -> anyhow::Result<()> {
        let root = unique_tmp("codegen_saga");
        seed_saga(&root)?;
        let contracts = root.join("contracts");
        let gen_src = root.join("generated/src");
        generate(&contracts, &gen_src, false)?;
        let rendered = std::fs::read_to_string(gen_src.join("saga/billing_v1.rs"))?;
        let mod_rs = std::fs::read_to_string(gen_src.join("saga/mod.rs"))?;
        let _ = std::fs::remove_dir_all(&root);

        assert!(
            rendered.contains(r#"pub const CONTRACT_ID: &str = "billing.checkout";"#),
            "缺 CONTRACT_ID:\n{rendered}"
        );
        assert!(
            rendered.contains("::vocab::ContractBinding::from_descriptor(")
                && rendered.contains(r#""billing","#)
                && rendered.contains(r#""billing.checkout","#)
                && rendered.contains(r#""v1","#)
                && rendered.contains(r#""sha256:"#),
            "缺 CONTRACT binding:\n{rendered}"
        );
        assert!(
            rendered.contains("::vocab::SagaRuntimePolicySpec::from_static(")
                && rendered.contains("::vocab::SagaBackoff::Exponential")
                && rendered.contains("::vocab::SagaJitter::Full"),
            "缺 saga runtime policy spec:\n{rendered}"
        );
        assert!(
            rendered.contains("pub struct ReserveFundsReceipt")
                && rendered.contains("pub struct CaptureReceipt"),
            "缺 saga step receipt DTO:\n{rendered}"
        );
        assert!(
            rendered.contains("impl super::Receipt<ReserveFundsStep> for ReserveFundsReceipt")
                && rendered.contains("impl super::Receipt<CaptureStep> for CaptureReceipt")
                && rendered.contains("impl super::Step<Definition> for ReserveFundsStep")
                && rendered.contains("type Next = CaptureStep;")
                && rendered.contains("type Next = End;"),
            "缺 sealed receipt/typestate marker:\n{rendered}"
        );
        assert!(
            rendered.contains(r#""reserve_funds","#)
                && rendered.contains(r#""reserve.schema.json","#)
                && rendered.contains(r#""billing.reserve","#)
                && rendered.contains(r#""billing.release","#)
                && rendered.contains("::vocab::SagaRetryClass::Transient")
                && rendered.contains("::vocab::SagaRetryClass::Never"),
            "缺 saga step binding constants:\n{rendered}"
        );
        assert!(
            rendered.contains("pub const STEPS: &[::vocab::SagaStepBinding] = &[STEP_0, STEP_1];"),
            "缺 ordered saga STEPS:\n{rendered}"
        );
        assert!(
            rendered.contains(
                "super::SagaSpec::from_parts(CONTRACT, POLICY, STEPS, ACTION_REGISTRY_GENERATION);"
            ),
            "缺 SagaSpec 常量:\n{rendered}"
        );
        assert!(
            mod_rs.contains("pub type SagaSpec = ::vocab::SagaContractBinding;"),
            "saga/mod.rs 缺 SagaSpec type alias:\n{mod_rs}"
        );
        assert!(
            rendered.contains("pub const ACTION_REGISTRY_GENERATION: &str =\n    \"sha256:")
                && rendered.contains("pub struct Definition;")
                && rendered.contains("impl super::End<Definition> for End"),
            "缺 action generation / definition seal:\n{rendered}"
        );
        assert!(
            mod_rs.contains("pub trait StepMarker: sealed::StepMarker")
                && mod_rs.contains("pub trait Definition: sealed::Definition")
                && mod_rs.contains("pub trait End<D: Definition>: sealed::End<D>"),
            "saga/mod.rs 缺 sealed marker API:\n{mod_rs}"
        );
        assert!(
            mod_rs.contains("pub const SPECS: &[SagaSpec]") && mod_rs.contains("billing_v1::SPEC"),
            "saga/mod.rs 缺完整 definition catalog:\n{mod_rs}"
        );
        Ok(())
    }

    #[test]
    fn saga_action_generation_covers_every_ordered_execution_semantic() -> anyhow::Result<()> {
        let root = unique_tmp("codegen_saga_generation");
        seed_saga(&root)?;
        let contracts = load_contract_fixtures(&root.join("contracts"))?;
        let saga = contracts
            .first()
            .and_then(|contract| contract.manifest().saga.as_ref())
            .ok_or_else(|| anyhow::anyhow!("seed saga was not discovered"))?;
        let baseline = saga_action_registry_generation(saga);
        assert_eq!(
            baseline,
            "sha256:87da7dd4d4738e9ae0bf54d36d999949f7da89200278f425261a857afeaed62e"
        );

        let mut variants = Vec::new();
        let mut changed = saga.clone();
        changed.retry.max_attempts += 1;
        variants.push(changed);
        let mut changed = saga.clone();
        changed.retry.time_budget_millis += 1;
        variants.push(changed);
        let mut changed = saga.clone();
        changed.retry.backoff = SagaBackoff::Fixed;
        variants.push(changed);
        let mut changed = saga.clone();
        changed.retry.initial_backoff_millis += 1;
        variants.push(changed);
        let mut changed = saga.clone();
        changed.retry.max_backoff_millis += 1;
        variants.push(changed);
        let mut changed = saga.clone();
        changed.retry.jitter = SagaJitter::None;
        variants.push(changed);
        let mut changed = saga.clone();
        changed.steps.swap(0, 1);
        variants.push(changed);
        let mut changed = saga.clone();
        changed.steps[0].name = vocab::StepName::parse(&format!("{}x", changed.steps[0].name))?;
        variants.push(changed);
        for mutate in [
            |s: &mut crate::contract::manifest::SagaStep| s.receipt_schema.push('x'),
            |s: &mut crate::contract::manifest::SagaStep| s.effect_scope.push('x'),
            |s: &mut crate::contract::manifest::SagaStep| s.compensation_effect_scope.push('x'),
        ] {
            let mut changed = saga.clone();
            mutate(&mut changed.steps[0]);
            variants.push(changed);
        }
        let mut changed = saga.clone();
        changed.steps[0].retry_class = SagaRetryClass::Never;
        variants.push(changed);

        for changed in variants {
            assert_ne!(baseline, saga_action_registry_generation(&changed));
        }

        let manifest_path = root.join("contracts/saga/billing/v1/contract.toml");
        let source = std::fs::read_to_string(&manifest_path)?;
        let reordered = source.replace(
            "maxAttempts = 3\ntimeBudgetMillis = 30000\nbackoff = \"exponential\"",
            "backoff = \"exponential\"\ntimeBudgetMillis = 30000\nmaxAttempts = 3",
        );
        assert_ne!(
            source, reordered,
            "anti-vacuity: fixture retry keys must be reordered"
        );
        let parsed = crate::contract::manifest::ContractManifest::from_toml_str(&reordered)?;
        assert_eq!(
            baseline,
            saga_action_registry_generation(
                parsed
                    .saga
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("reordered manifest lost [saga]"))?,
            ),
            "TOML key order is authoring syntax, not execution semantics"
        );
        let _ = std::fs::remove_dir_all(&root);
        Ok(())
    }

    /// event 无 subscriptions（draft）仍生成 sealed emit carrier、空 topology 与 CONTRACT_ID / TOPIC。
    ///
    /// INVARIANT: CONTRACT-BINDING-FUNNEL-01 { level = "Medium", exec = "check", source = "code" }—— draft event 亦发射 `CONTRACT` 绑定常量（正向对照）。
    #[test]
    fn event_glue_empty_subscriptions_draft() -> anyhow::Result<()> {
        let root = unique_tmp("codegen_glue_empty");
        seed_event(&root)?;
        let contracts = root.join("contracts");
        let gen_src = root.join("generated/src");
        generate(&contracts, &gen_src, false)?;
        let rendered = std::fs::read_to_string(gen_src.join("event/_seed_v1.rs"))?;
        let _ = std::fs::remove_dir_all(&root);

        // draft event 无 topic → 回退用 id
        assert!(
            rendered.contains(r#"pub const CONTRACT_ID: &str = "seed.happened";"#),
            "缺 CONTRACT_ID:\n{rendered}"
        );
        // CONTRACT binding 仍发射（draft 亦有；domain "_seed" 取自 manifest，#1193/#1618）
        assert!(
            rendered.contains("::vocab::ContractBinding::from_descriptor(")
                && rendered.contains(r#""_seed","#)
                && rendered.contains(r#""seed.happened","#)
                && rendered.contains(r#""v1","#)
                && rendered.contains(r#""sha256:"#),
            "draft 缺 CONTRACT binding 常量:\n{rendered}"
        );
        // draft 仍有完整 EventSpec，但不进入 root active EVENTS。
        assert!(
            rendered.contains("pub const SPEC: super::EventSpec")
                && rendered.contains("super::PartitionKeyStrategy::None, &[]"),
            "空 subscriptions 应生成 sealed EventSpec:\n{rendered}"
        );
        Ok(())
    }

    /// projection workflow 的 inputs 须派生成根级 `PROJECTION_INPUTS`，且 input metadata 来自目标 event
    /// contract，而不是运行时手写 topic list。
    #[test]
    fn event_root_projection_inputs_emitted_from_workflow_contracts() -> anyhow::Result<()> {
        let root = unique_tmp("codegen_projection_inputs");
        seed_event_with_subscription(&root)?;
        seed_projection_workflow(&root)?;
        let gen_src = root.join("generated/src");
        generate(&root.join("contracts"), &gen_src, false)?;
        let mod_rs = std::fs::read_to_string(gen_src.join("event/mod.rs"))?;
        let projection_rs = std::fs::read_to_string(gen_src.join("projection/audit_v1.rs"))?;
        let projection_mod_rs = std::fs::read_to_string(gen_src.join("projection/mod.rs"))?;
        let lib_rs = std::fs::read_to_string(gen_src.join("lib.rs"))?;
        let inventory =
            render_migration_projection_inputs(&load_contract_fixtures(&root.join("contracts"))?)?;
        let _ = std::fs::remove_dir_all(&root);

        assert!(
            mod_rs.contains("pub const PROJECTION_INPUTS: &[::vocab::ProjectionInputBinding]"),
            "event/mod.rs 缺 projection input root registry:\n{mod_rs}"
        );
        assert!(
            mod_rs.contains("pub const PROJECTION_DEFINITIONS: &[::vocab::ContractBinding]")
                && mod_rs.contains("crate::projection::audit_v1::CONTRACT"),
            "event/mod.rs 缺 projection definition root registry:\n{mod_rs}"
        );
        assert!(
            projection_mod_rs.contains("pub mod audit_v1;")
                && lib_rs.contains("pub mod projection;"),
            "projection modules must be emitted through the canonical generated funnel"
        );
        assert!(
            projection_rs.contains(r#"pub const CONTRACT_ID: &str = "audit.seed-projection";"#)
                && projection_rs.contains("pub const CONTRACT: ::vocab::ContractBinding")
                && !projection_rs.contains("HttpSpec")
                && !projection_rs.contains("Request")
                && !projection_rs.contains("Response")
                && !projection_rs.contains("pub struct"),
            "projection carrier must expose only definition identity, never HTTP route/DTO:\n{projection_rs}"
        );
        assert!(
            !gen_src.join("http/audit_v1.rs").exists(),
            "projection workflow must not leave a generated HTTP carrier"
        );
        assert!(
            mod_rs.contains("pub const PROJECTION_INPUT_GENERATION: &str =")
                && mod_rs.contains("\"sha256:"),
            "event/mod.rs 缺 projection input generation digest:\n{mod_rs}"
        );
        assert_generated_contains(
            &mod_rs,
            "::vocab::ProjectionInputBinding::from_static(",
            "PROJECTION_INPUTS 应由 ProjectionInputBinding 常量构造",
        );
        assert!(
            mod_rs.contains(r#""audit.seed-projection""#),
            "projection_id 应来自 workflow contract id:\n{mod_rs}"
        );
        assert!(
            mod_rs.contains(r#""_seed""#)
                && mod_rs.contains(r#""seed.happened""#)
                && mod_rs.contains(r#""v1""#)
                && mod_rs.contains(r#""seed.happened""#)
                && mod_rs.contains(r#""sha256:"#),
            "input binding 应包含目标 event 的 domain/id/version/topic/schema_hash:\n{mod_rs}"
        );
        assert!(
            inventory.contains("const PROJECTION_INPUT_GENERATION: &str = \"sha256:")
                && inventory.contains("super::ProjectionInputIdentity::from_static(")
                && inventory.contains(r#""audit.seed-projection""#)
                && inventory.contains(r#""seed.happened""#),
            "migration inventory must be derived from the same projection input model:\n{inventory}"
        );
        Ok(())
    }

    #[test]
    fn projection_input_generation_is_sorted_u64_length_prefixed_known_answer() {
        let seed = [
            "audit.seed-projection".to_string(),
            "v1".to_string(),
            format!("sha256:{}", "1".repeat(64)),
            "_seed".to_string(),
            "seed.happened".to_string(),
            "v1".to_string(),
            "sha256:e75b5df7855eff522195aacdad81fd493b4290ecef710d871fe038efe9e43e07".to_string(),
            "seed.happened".to_string(),
        ];
        let other = [
            "audit.alpha-projection".to_string(),
            "v2".to_string(),
            format!("sha256:{}", "2".repeat(64)),
            "alpha".to_string(),
            "alpha.changed".to_string(),
            "v2".to_string(),
            format!("sha256:{}", "0".repeat(64)),
            "alpha.changed".to_string(),
        ];
        let mut single = vec![seed.clone()];
        assert_eq!(
            projection_input_generation(&mut single),
            "sha256:f31df429039e85aecc671deddc20cb5df6931354850aa28d36502033a2590781"
        );

        let mut forward = vec![seed.clone(), other.clone()];
        let mut reversed = vec![other, seed];
        assert_eq!(
            projection_input_generation(&mut forward),
            projection_input_generation(&mut reversed),
            "generation must depend on the sorted tuple set, not manifest discovery order"
        );
    }

    /// F3 anti-vacuity（负向）：contract.toml 的 domain 含 `../` 时，codegen 须 bail（防逃逸），
    /// 即使 `contract validate`（R3/R7）未先跑——codegen 自守。
    #[test]
    fn codegen_rejects_path_traversal_domain() -> anyhow::Result<()> {
        let root = unique_tmp("codegen");
        let dir = root.join("contracts/http/_seed/v1");
        std::fs::create_dir_all(&dir)?;
        // domain 写成 ../evil（磁盘段仍是 _seed）——模拟 authoring 字段逃逸尝试。
        std::fs::write(
            dir.join("contract.toml"),
            "id = \"seed.echo\"\nkind = \"http\"\ndomain = \"../evil\"\nversion = \"v1\"\nowner = \"_framework\"\nconsistencyLevel = \"LocalOnly\"\nlifecycle = \"draft\"\n[schemas]\nrequest = \"request.schema.json\"\nresponse = \"response.schema.json\"\n",
        )?;
        let schema = "{\"$schema\":\"http://json-schema.org/draft-07/schema#\",\"title\":\"T\",\"type\":\"object\",\"properties\":{},\"additionalProperties\":false}";
        std::fs::write(
            dir.join("request.schema.json"),
            schema.replace("\"T\"", "\"R\""),
        )?;
        std::fs::write(
            dir.join("response.schema.json"),
            schema.replace("\"T\"", "\"S\""),
        )?;
        let result = generate(&root.join("contracts"), &root.join("generated/src"), false);
        let _ = std::fs::remove_dir_all(&root);
        assert!(result.is_err(), "domain 含 ../ 时 codegen 须防逃逸 bail");
        Ok(())
    }

    /// review #271 F4（anti-vacuity）：`render_event_glue` 把 domain / id / topic 拼进生成字符串字面量
    /// （`CONTRACT::from_static` / `CONTRACT_ID` / `TOPIC`）前经 `is_safe_codegen_ident` 自守。domain 含引号
    /// （可破坏 `from_static("...")` 字面量）→ codegen bail，即使 validate 未先跑（codegen 自守）。
    /// `is_unsafe_segment` 只拦路径分量（`/` `\` `..`）放行引号——故本红用例覆盖 path-traversal 测不到的注入面。
    #[test]
    fn event_glue_rejects_unsafe_domain() -> anyhow::Result<()> {
        let root = unique_tmp("codegen_unsafe_dom");
        let dir = root.join("contracts/event/_seed/v1");
        std::fs::create_dir_all(&dir)?;
        // domain 值含转义引号 `ev"il`——非路径逃逸（is_unsafe_segment 放行），但会破坏生成字面量。
        std::fs::write(
            dir.join("contract.toml"),
            "id = \"seed.happened\"\nkind = \"event\"\ndomain = \"ev\\\"il\"\nversion = \"v1\"\nowner = \"_framework\"\nconsistencyLevel = \"OutboxFact\"\nlifecycle = \"draft\"\n[schemas]\npayload = \"payload.schema.json\"\n",
        )?;
        let schema = "{\"$schema\":\"http://json-schema.org/draft-07/schema#\",\"title\":\"P\",\"type\":\"object\",\"properties\":{},\"additionalProperties\":false}";
        std::fs::write(dir.join("payload.schema.json"), schema)?;
        let result = generate(&root.join("contracts"), &root.join("generated/src"), false);
        let _ = std::fs::remove_dir_all(&root);
        assert!(result.is_err(), "domain 含引号时 codegen 须防注入 bail");
        Ok(())
    }

    /// review #216 F6：`is_safe_codegen_ident` 守 codegen 字面量注入下界——安全字符集 `[a-z0-9._-]` 放行，
    /// 引号 / 反斜杠 / 空白 / 大写 / 空串拒（anti-vacuity：合法 consumer/group 必过、各注入面必拒）。
    #[test]
    fn is_safe_codegen_ident_table() {
        for ok in [
            "audit",
            "audit.session-created",
            "devicestate.session-watch",
            "a1",
            "_x",
        ] {
            assert!(is_safe_codegen_ident(ok), "{ok:?} 应安全");
        }
        for bad in [
            "",
            "Audit",
            "audit\"; evil",
            "audit\\x",
            "audit x",
            "audit\nx",
            "审计",
        ] {
            assert!(!is_safe_codegen_ident(bad), "{bad:?} 应被拒");
        }
    }

    /// `allow_derivable_default_impls` 守卫 anti-vacuity 测试：
    /// - 正向：`impl Default for Foo {}` 块经 `allow_derivable_default_impls` 后携带
    ///   `#[allow(clippy::derivable_impls)]`。
    /// - 负向控制：`impl SomethingElse for Foo {}` 不被注入该 allow 属性。
    ///
    /// INVARIANT: CODEGEN-DERIVABLE-DEFAULT-ALLOW-01 { level = "Medium", exec = "check", source = "code" }（anti-vacuity，Medium）。
    #[test]
    fn allow_derivable_default_impls_injects_only_default_impls() -> anyhow::Result<()> {
        // 构造包含 impl Default 和 impl SomethingElse 的 syn::File。
        let mut file: syn::File = syn::parse_quote! {
            struct Foo;
            impl Default for Foo {
                fn default() -> Self {
                    Foo
                }
            }
            impl SomethingElse for Foo {}
        };

        allow_derivable_default_impls(&mut file);

        /// 辅助：判断 impl 块是否有 #[allow(clippy::derivable_impls)]。
        fn has_derivable_allow(items: &[syn::Item], trait_name: &str) -> anyhow::Result<bool> {
            let item = items
                .iter()
                .find(|item| {
                    if let syn::Item::Impl(imp) = item {
                        imp.trait_
                            .as_ref()
                            .and_then(|(_, path, _)| path.segments.last())
                            .is_some_and(|seg| seg.ident == trait_name)
                    } else {
                        false
                    }
                })
                .ok_or_else(|| anyhow::anyhow!("找不到 impl {trait_name} for Foo"))?;
            let syn::Item::Impl(imp) = item else {
                anyhow::bail!("应为 Impl item");
            };
            Ok(imp.attrs.iter().any(|attr| {
                attr.path().is_ident("allow")
                    && attr
                        .parse_args::<syn::Path>()
                        .is_ok_and(|p| p.segments.iter().any(|seg| seg.ident == "derivable_impls"))
            }))
        }

        // 正向：impl Default 块须携带 #[allow(clippy::derivable_impls)]。
        assert!(
            has_derivable_allow(&file.items, "Default")?,
            "impl Default 块须被注入 #[allow(clippy::derivable_impls)]（anti-vacuity：守卫非恒真）"
        );

        // 负向控制：impl SomethingElse 不应携带该 allow 属性。
        assert!(
            !has_derivable_allow(&file.items, "SomethingElse")?,
            "非 Default impl 不应被注入 #[allow(clippy::derivable_impls)]（控制组）"
        );
        Ok(())
    }

    /// review #216 F6（codegen 防注入红用例）：subscription group 含引号时，render_event_glue 经
    /// `is_safe_codegen_ident` 防御性 `bail!`——codegen 独立于 validate R7 运行也不把坏值拼进生成字面量。
    /// 正向对照见 `event_glue_with_subscription_emitted`（合法 subscription 正常生成）。
    #[test]
    fn subscription_unsafe_group_rejected_by_codegen() -> anyhow::Result<()> {
        let root = unique_tmp("codegen");
        let dir = root.join("contracts/event/_seed/v1");
        std::fs::create_dir_all(&dir)?;
        std::fs::write(
            dir.join("contract.toml"),
            concat!(
                "id = \"seed.happened\"\n",
                "kind = \"event\"\n",
                "domain = \"_seed\"\n",
                "version = \"v1\"\n",
                "owner = \"_framework\"\n",
                "consistencyLevel = \"OutboxFact\"\n",
                "lifecycle = \"draft\"\n",
                "topic = \"seed.happened\"\n",
                "delivery = \"at-least-once\"\n",
                "[schemas]\n",
                "payload = \"payload.schema.json\"\n",
                "[[subscriptions]]\n",
                "consumer = \"audit\"\n",
                "group = \"audit\\\"; evil\"\n", // TOML 转义 → group 值含引号（注入面）
                "[subscriptions.topology]\n",
                "partitionKey = \"none\"\n",
                "readiness = \"required\"\n",
            ),
        )?;
        let schema = "{\"$schema\":\"http://json-schema.org/draft-07/schema#\",\"title\":\"SeedHappenedPayload\",\"type\":\"object\",\"required\":[\"id\"],\"properties\":{\"id\":{\"type\":\"string\"}},\"additionalProperties\":false}";
        std::fs::write(dir.join("payload.schema.json"), schema)?;
        let result = generate(&root.join("contracts"), &root.join("generated/src"), false);
        let _ = std::fs::remove_dir_all(&root);
        assert!(
            result.is_err(),
            "含引号的 subscription group 须被 codegen 防注入守卫 bail"
        );
        Ok(())
    }

    /// 在 `root/contracts/command/_seed/v1` 落一个最小 command 契约（draft，request schema + topic）。
    fn seed_command(root: &Path) -> Result<()> {
        let dir = root.join("contracts/command/_seed/v1");
        std::fs::create_dir_all(&dir)?;
        std::fs::write(
            dir.join("contract.toml"),
            concat!(
                "id = \"seed.do-thing\"\n",
                "kind = \"command\"\n",
                "domain = \"_seed\"\n",
                "version = \"v1\"\n",
                "owner = \"_framework\"\n",
                "consistencyLevel = \"OutboxFact\"\n",
                "lifecycle = \"draft\"\n",
                "topic = \"seed.commands.do-thing\"\n",
                "[schemas]\n",
                "request = \"request.schema.json\"\n",
                "[command]\n",
                "journal = \"required\"\n",
            ),
        )?;
        // schema 与真实 contracts/command/_seed/v1/request.schema.json 对齐（targetId + amount）。
        let schema = "{\"$schema\":\"http://json-schema.org/draft-07/schema#\",\"title\":\"SeedDoThingRequest\",\"type\":\"object\",\"required\":[\"targetId\",\"amount\"],\"properties\":{\"targetId\":{\"type\":\"string\"},\"amount\":{\"type\":\"integer\",\"format\":\"int64\"}},\"additionalProperties\":false}";
        std::fs::write(dir.join("request.schema.json"), schema)?;
        Ok(())
    }

    fn seed_fenced_command(root: &Path) -> Result<()> {
        seed_command(root)?;
        let dir = root.join("contracts/command/_seed/v1");
        let manifest = std::fs::read_to_string(dir.join("contract.toml"))?.replace(
            "journal = \"required\"\n",
            concat!(
                "journal = \"required\"\n",
                "[command.reconcile]\n",
                "fencing = \"device-generation-epoch-v1\"\n",
            ),
        );
        std::fs::write(dir.join("contract.toml"), manifest)?;
        std::fs::write(
            dir.join("request.schema.json"),
            r#"{"$schema":"http://json-schema.org/draft-07/schema#","title":"SeedDoThingRequest","type":"object","required":["deviceId","desiredGeneration","fenceEpoch","intentDigest","deadlineEpochSeconds"],"properties":{"deviceId":{"type":"string","format":"uuid"},"desiredGeneration":{"type":"integer","format":"int64","minimum":1,"maximum":9223372036854775807},"fenceEpoch":{"type":"integer","format":"int64","minimum":1,"maximum":9223372036854775807},"intentDigest":{"type":"string","pattern":"^sha256:[0-9a-f]{64}$","x-redaction":"secret"},"deadlineEpochSeconds":{"type":"integer","format":"int64","minimum":1,"maximum":9223372036854}},"additionalProperties":false}"#,
        )?;
        Ok(())
    }

    #[test]
    fn fenced_reconcile_command_is_schema_derived_and_seed_is_unfenced() -> anyhow::Result<()> {
        let fenced_root = unique_tmp("codegen_fenced_cmd");
        seed_fenced_command(&fenced_root)?;
        let fenced_src = fenced_root.join("generated/src");
        generate(&fenced_root.join("contracts"), &fenced_src, false)?;
        let fenced = std::fs::read_to_string(fenced_src.join("command/_seed_v1.rs"))?;
        let fenced_mod = std::fs::read_to_string(fenced_src.join("command/mod.rs"))?;
        let _ = std::fs::remove_dir_all(&fenced_root);

        assert!(
            fenced.contains("pub struct FencedReconcileCommand")
                && fenced.contains("impl super::FencedCommandSpec for FencedReconcileCommand",)
                && fenced.contains("pub fn fenced_reconcile_command("),
            "fenced manifest + canonical schema must derive the sealed carrier:\n{fenced}"
        );

        let invalid_root = unique_tmp("codegen_fenced_cmd_direct_policy");
        seed_fenced_command(&invalid_root)?;
        let manifest = invalid_root.join("contracts/command/_seed/v1/contract.toml");
        let invalid = std::fs::read_to_string(&manifest)?
            .replace("journal = \"required\"", "journal = \"none\"");
        std::fs::write(&manifest, invalid)?;
        let error = match generate(
            &invalid_root.join("contracts"),
            &invalid_root.join("generated/src"),
            false,
        ) {
            Err(error) => error,
            Ok(()) => anyhow::bail!("fenced reconcile command with direct policy passed codegen"),
        };
        assert!(error.to_string().contains("journal"));
        let _ = std::fs::remove_dir_all(&invalid_root);
        assert!(
            fenced.contains(
                "pub struct FencedReconcileCommand {\n    request: SeedDoThingRequest,\n}",
            ),
            "fenced carrier must contain only the private typed request:\n{fenced}"
        );
        for forbidden in ["pub struct ReconcileCommand", "pub fn reconcile_command"] {
            assert!(
                !fenced.contains(forbidden),
                "legacy reconcile path `{forbidden}` must be absent:\n{fenced}"
            );
        }
        for forbidden in [
            "impl super::JournaledCommandContract for Contract",
            "impl super::DirectCommandContract for Contract",
            "pub async fn journal_async",
            "pub async fn emit_async",
        ] {
            assert!(
                !fenced.contains(forbidden),
                "fenced contract must not expose ordinary producer path `{forbidden}`:\n{fenced}"
            );
        }
        assert!(
            fenced.contains("pub fn register_handler<Reg, H, Fut>"),
            "fenced contract must retain consumer registration:\n{fenced}"
        );
        assert!(
            fenced_mod.contains("pub trait FencedCommandSpec: private::Sealed")
                && !fenced_mod.contains("pub trait TypedCommandSpec"),
            "command seam must expose only the sealed fenced trait:\n{fenced_mod}"
        );

        let seed_root = unique_tmp("codegen_unfenced_cmd");
        seed_command(&seed_root)?;
        let seed_src = seed_root.join("generated/src");
        generate(&seed_root.join("contracts"), &seed_src, false)?;
        let seed = std::fs::read_to_string(seed_src.join("command/_seed_v1.rs"))?;
        let _ = std::fs::remove_dir_all(&seed_root);
        assert!(
            !seed.contains("FencedReconcileCommand")
                && !seed.contains("ReconcileCommand")
                && !seed.contains("reconcile_command"),
            "unfenced seed command must not receive a reconcile carrier:\n{seed}"
        );
        Ok(())
    }

    #[test]
    fn fenced_reconcile_rejects_noncanonical_schema() -> anyhow::Result<()> {
        let canonical = r#"{"$schema":"http://json-schema.org/draft-07/schema#","title":"SeedDoThingRequest","type":"object","required":["deviceId","desiredGeneration","fenceEpoch","intentDigest","deadlineEpochSeconds"],"properties":{"deviceId":{"type":"string","format":"uuid"},"desiredGeneration":{"type":"integer","format":"int64","minimum":1,"maximum":9223372036854775807},"fenceEpoch":{"type":"integer","format":"int64","minimum":1,"maximum":9223372036854775807},"intentDigest":{"type":"string","pattern":"^sha256:[0-9a-f]{64}$","x-redaction":"secret"},"deadlineEpochSeconds":{"type":"integer","format":"int64","minimum":1,"maximum":9223372036854}},"additionalProperties":false}"#;
        for (case, malformed) in [
            (
                "device format",
                canonical.replacen("\"format\":\"uuid\"", "\"format\":\"uri\"", 1),
            ),
            (
                "positive generation",
                canonical.replacen("\"minimum\":1", "\"minimum\":0", 1),
            ),
            (
                "persistable generation maximum",
                canonical.replacen(
                    ",\"maximum\":9223372036854775807",
                    "",
                    1,
                ),
            ),
            (
                "persistable fence maximum",
                canonical.replace(
                    "\"fenceEpoch\":{\"type\":\"integer\",\"format\":\"int64\",\"minimum\":1,\"maximum\":9223372036854775807}",
                    "\"fenceEpoch\":{\"type\":\"integer\",\"format\":\"int64\",\"minimum\":1,\"maximum\":9223372036854775806}",
                ),
            ),
            (
                "intent digest",
                canonical.replace("^sha256:[0-9a-f]{64}$", "^sha256:[0-9A-F]{64}$"),
            ),
            (
                "required deadline",
                canonical.replacen(",\"deadlineEpochSeconds\"]", "]", 1),
            ),
            (
                "persistable deadline maximum",
                canonical.replace(
                    "\"maximum\":9223372036854",
                    "\"maximum\":9223372036855",
                ),
            ),
        ] {
            let root = unique_tmp("codegen_bad_fenced_cmd");
            seed_fenced_command(&root)?;
            std::fs::write(
                root.join("contracts/command/_seed/v1/request.schema.json"),
                malformed,
            )?;
            let result = generate(&root.join("contracts"), &root.join("generated/src"), false);
            let _ = std::fs::remove_dir_all(&root);
            assert!(result.is_err(), "noncanonical {case} must fail codegen");
        }
        Ok(())
    }

    /// Flat command modules must carry typify's static-pattern unwrap lint allowance at their
    /// module root. Nested contracts already place the same generated-only allowance inside each
    /// child module; this locks the flat path used by `contracts/command/<domain>/<version>`.
    #[test]
    fn flat_command_pattern_schema_allows_generated_regex_unwrap() -> anyhow::Result<()> {
        let root = unique_tmp("codegen_cmd_pattern");
        seed_command(&root)?;
        std::fs::write(
            root.join("contracts/command/_seed/v1/request.schema.json"),
            r#"{"$schema":"http://json-schema.org/draft-07/schema#","title":"SeedDoThingRequest","type":"object","required":["targetId","amount"],"properties":{"targetId":{"type":"string","pattern":"^[a-z]+$"},"amount":{"type":"integer","format":"int64"}},"additionalProperties":false}"#,
        )?;
        let gen_src = root.join("generated/src");
        generate(&root.join("contracts"), &gen_src, false)?;
        let rendered = std::fs::read_to_string(gen_src.join("command/_seed_v1.rs"))?;
        let _ = std::fs::remove_dir_all(&root);

        assert!(
            rendered.contains("::regress::Regex") && rendered.contains(".unwrap()"),
            "pattern fixture must exercise typify's static regex unwrap:\n{rendered}"
        );
        assert!(
            rendered.contains(
                "#![allow(clippy::unwrap_used)] // reason: typify emits infallible static regex initialization."
            ),
            "flat generated module must scope the typify regex lint allowance:\n{rendered}"
        );
        Ok(())
    }

    /// command glue 测试（#1124）：journal=required 仅派生 typed `journal_async`，不派生 `emit_async`。
    /// `register_handler` wrapper（generated seam 顶层，锁 typed Request = schema title）；seam
    /// `CommandEmit` / `CommandRegister` 定义在 `command/mod.rs`，子模块经 `super::` 引用（无重复定义）。
    /// anti-vacuity：合法 command 契约正常派生全部 wrapper + seam。
    #[test]
    fn command_glue_with_wrappers_emitted() -> anyhow::Result<()> {
        let root = unique_tmp("codegen_cmd");
        seed_command(&root)?;
        let contracts = root.join("contracts");
        let gen_src = root.join("generated/src");
        generate(&contracts, &gen_src, false)?;
        let rendered = std::fs::read_to_string(gen_src.join("command/_seed_v1.rs"))?;
        let mod_rs = std::fs::read_to_string(gen_src.join("command/mod.rs"))?;
        let _ = std::fs::remove_dir_all(&root);

        assert!(
            rendered.contains(r#"pub const CONTRACT_ID: &str = "seed.do-thing";"#),
            "缺 CONTRACT_ID:\n{rendered}"
        );
        assert!(
            rendered.contains(r#"pub const TOPIC: &str = "seed.commands.do-thing";"#),
            "缺 TOPIC:\n{rendered}"
        );
        assert!(
            rendered.contains("pub async fn journal_async<J: super::CommandJournal>"),
            "缺 journal_async wrapper:\n{rendered}"
        );
        assert!(!rendered.contains("pub async fn emit_async"));
        assert!(
            rendered.contains("pub fn register_handler<Reg, H, Fut>"),
            "缺 register_handler wrapper:\n{rendered}"
        );
        assert!(
            !rendered.contains("ReconcileCommand") && !rendered.contains("reconcile_command"),
            "unfenced command 不得派生 reconcile carrier:\n{rendered}"
        );
        assert!(
            rendered.contains("registrar.register::<Contract, H, Fut>(handler)"),
            "register_handler 必须只把 per-command carrier 传给 seam:\n{rendered}"
        );
        // wrapper 锁 typed Request（= request schema title 派生）
        assert!(
            rendered.contains("request: SeedDoThingRequest"),
            "journal_async 须锁 typed Request:\n{rendered}"
        );
        // required wrapper 把 tenant/identity 与非可选业务幂等键纳入类型面。
        assert!(
            rendered.contains("tenant: ::rss_request_context::TenantId")
                && rendered.contains("subject_id: J::SubjectId")
                && rendered.contains("actor: J::Actor")
                && rendered.contains("idempotency_key: ::std::string::String"),
            "journal_async wrapper 须含必填 idempotency_key:\n{rendered}"
        );
        assert!(
            mod_rs.contains("tenant: ::rss_request_context::TenantId")
                && mod_rs.contains("type SubjectId: ::core::marker::Send")
                && mod_rs.contains("type Actor: ::core::marker::Send")
                && mod_rs.contains("subject_id: Self::SubjectId")
                && mod_rs.contains("actor: Self::Actor")
                && mod_rs.contains("idempotency_key: &str"),
            "CommandJournal seam 须含 tenant + subject_id + actor + idempotency_key 参数:\n{mod_rs}"
        );
        assert!(
            mod_rs.contains("pub trait CommandContract: private::Sealed")
                && mod_rs.contains("type Request: ::serde::Serialize")
                && mod_rs.contains("const SPEC: CommandSpec")
                && rendered.contains("pub struct Contract")
                && rendered.contains("impl super::CommandContract for Contract")
                && rendered.contains("impl super::JournaledCommandContract for Contract"),
            "Command seams 须由 per-command carrier 绑定 Request/SPEC/policy:\n{mod_rs}\n{rendered}"
        );
        assert!(
            !mod_rs.contains("spec: CommandSpec")
                && !mod_rs.contains("fn emit<R:")
                && !mod_rs.contains("fn journal<R:")
                && !mod_rs.contains("fn register<R,"),
            "Command seams 不得保留独立 spec + arbitrary R seam:\n{mod_rs}"
        );
        // seam 定义在 mod.rs，子模块经 super:: 引用
        assert!(
            mod_rs.contains("pub trait CommandEmit")
                && mod_rs.contains("pub trait CommandJournal")
                && mod_rs.contains("pub trait CommandRegister")
                && mod_rs.contains("pub trait FencedCommandSpec: private::Sealed")
                && !mod_rs.contains("pub trait TypedCommandSpec"),
            "mod.rs 缺 command seams:\n{mod_rs}"
        );
        assert!(
            rendered.contains("super::CommandJournal"),
            "wrapper 应经 super:: 引用 seam:\n{rendered}"
        );
        Ok(())
    }

    fn has_doc(attrs: &[syn::Attribute]) -> bool {
        attrs.iter().any(|attr| attr.path().is_ident("doc"))
    }

    fn documented(attrs: &[syn::Attribute], label: impl std::fmt::Display) {
        assert!(
            has_doc(attrs),
            "generated owned public item lacks rustdoc: {label}"
        );
    }

    fn assert_public_enum_documented(item: &syn::ItemEnum) {
        if !matches!(item.vis, syn::Visibility::Public(_)) {
            return;
        }
        documented(&item.attrs, &item.ident);
        for variant in &item.variants {
            documented(&variant.attrs, format!("{}::{}", item.ident, variant.ident));
        }
    }

    fn assert_public_struct_documented(item: &syn::ItemStruct) {
        if !matches!(item.vis, syn::Visibility::Public(_)) {
            return;
        }
        documented(&item.attrs, &item.ident);
        for field in &item.fields {
            if matches!(field.vis, syn::Visibility::Public(_)) {
                documented(
                    &field.attrs,
                    field
                        .ident
                        .as_ref()
                        .map_or_else(|| item.ident.to_string(), ToString::to_string),
                );
            }
        }
    }

    fn assert_public_trait_documented(item: &syn::ItemTrait) {
        if !matches!(item.vis, syn::Visibility::Public(_)) {
            return;
        }
        documented(&item.attrs, &item.ident);
        for trait_item in &item.items {
            match trait_item {
                syn::TraitItem::Const(item) => documented(&item.attrs, &item.ident),
                syn::TraitItem::Fn(item) => documented(&item.attrs, &item.sig.ident),
                syn::TraitItem::Type(item) => documented(&item.attrs, &item.ident),
                _ => {}
            }
        }
    }

    fn assert_public_impl_items_documented(item: &syn::ItemImpl) {
        for impl_item in &item.items {
            match impl_item {
                syn::ImplItem::Const(item) if matches!(item.vis, syn::Visibility::Public(_)) => {
                    documented(&item.attrs, &item.ident);
                }
                syn::ImplItem::Fn(item) if matches!(item.vis, syn::Visibility::Public(_)) => {
                    documented(&item.attrs, &item.sig.ident);
                }
                syn::ImplItem::Type(item) if matches!(item.vis, syn::Visibility::Public(_)) => {
                    documented(&item.attrs, &item.ident);
                }
                _ => {}
            }
        }
    }

    fn assert_public_api_documented(source: &str) -> syn::Result<()> {
        let file = syn::parse_file(source)?;
        for item in &file.items {
            match item {
                syn::Item::Enum(item) => assert_public_enum_documented(item),
                syn::Item::Struct(item) => assert_public_struct_documented(item),
                syn::Item::Trait(item) => assert_public_trait_documented(item),
                syn::Item::Impl(item) => assert_public_impl_items_documented(item),
                _ => {}
            }
        }
        Ok(())
    }

    /// F10 reproduction: owned event/command templates are a public API and every public item,
    /// enum variant, accessor and associated item must carry rustdoc.
    #[test]
    fn owned_event_and_command_seam_templates_document_public_api() -> syn::Result<()> {
        assert_public_api_documented(SUBSCRIPTION_SPEC_DEF)?;
        assert_public_api_documented(COMMAND_SEAM_DEF)?;
        Ok(())
    }

    #[test]
    fn event_root_producer_domains_derive_from_active_events() -> anyhow::Result<()> {
        let root = unique_tmp("codegen_producer_domains");
        for (domain, id, slug) in [
            ("settings", "settings.changed", "changed"),
            ("identity", "identity.created", "created"),
            ("identity", "identity.updated", "updated"),
        ] {
            let dir = root.join(format!("contracts/event/{domain}/v1/{slug}"));
            std::fs::create_dir_all(&dir)?;
            std::fs::write(
                dir.join("contract.toml"),
                format!(
                    "id = \"{id}\"\nkind = \"event\"\ndomain = \"{domain}\"\nversion = \"v1\"\nowner = \"{domain}\"\nconsistencyLevel = \"OutboxFact\"\nlifecycle = \"active\"\ntopic = \"{id}\"\ndelivery = \"at-least-once\"\n[schemas]\npayload = \"payload.schema.json\"\n"
                ),
            )?;
            std::fs::write(
                dir.join("payload.schema.json"),
                "{\"title\":\"EventPayload\",\"type\":\"object\",\"properties\":{},\"additionalProperties\":false}",
            )?;
        }
        for (domain, lifecycle, level) in [
            ("draftdomain", "draft", "OutboxFact"),
            ("localdomain", "active", "LocalOnly"),
        ] {
            let dir = root.join(format!("contracts/event/{domain}/v1/ignored"));
            std::fs::create_dir_all(&dir)?;
            std::fs::write(
                dir.join("contract.toml"),
                format!(
                    "id = \"{domain}.ignored\"\nkind = \"event\"\ndomain = \"{domain}\"\nversion = \"v1\"\nowner = \"{domain}\"\nconsistencyLevel = \"{level}\"\nlifecycle = \"{lifecycle}\"\ntopic = \"{domain}.ignored\"\ndelivery = \"at-least-once\"\n[schemas]\npayload = \"payload.schema.json\"\n"
                ),
            )?;
            std::fs::write(
                dir.join("payload.schema.json"),
                "{\"title\":\"IgnoredPayload\",\"type\":\"object\",\"properties\":{},\"additionalProperties\":false}",
            )?;
        }
        let gen_src = root.join("generated/src");
        generate(&root.join("contracts"), &gen_src, false)?;
        let mod_rs = std::fs::read_to_string(gen_src.join("event/mod.rs"))?;
        let _ = std::fs::remove_dir_all(&root);

        assert_generated_contains(
            &mod_rs,
            "pub enum ProducerDomain",
            "event root 应生成闭合 producer-domain enum",
        );
        assert_generated_contains(
            &mod_rs,
            "pub const PRODUCER_DOMAINS: &[ProducerDomain]",
            "event root 应生成 active producer-domain registry",
        );
        assert_eq!(
            mod_rs.matches("ProducerDomain::Identity").count(),
            1,
            "同 domain 多 active events 必须去重:\n{mod_rs}"
        );
        assert!(
            mod_rs.contains("ProducerDomain::Identity")
                && mod_rs.contains("ProducerDomain::Settings")
                && !mod_rs.contains("ProducerDomain::Draftdomain")
                && !mod_rs.contains("ProducerDomain::Localdomain"),
            "producer domains 必须只来自 active OutboxFact events:\n{mod_rs}"
        );
        Ok(())
    }

    #[test]
    fn command_journal_none_emits_only_direct_wrapper() -> anyhow::Result<()> {
        let root = unique_tmp("codegen_cmd_none");
        seed_command(&root)?;
        let manifest = root.join("contracts/command/_seed/v1/contract.toml");
        let text = std::fs::read_to_string(&manifest)?
            .replace("journal = \"required\"", "journal = \"none\"");
        std::fs::write(&manifest, text)?;
        let gen_src = root.join("generated/src");
        generate(&root.join("contracts"), &gen_src, false)?;
        let rendered = std::fs::read_to_string(gen_src.join("command/_seed_v1.rs"))?;
        let _ = std::fs::remove_dir_all(&root);
        assert!(rendered.contains("pub async fn emit_async<E: super::CommandEmit>"));
        assert!(!rendered.contains("pub async fn journal_async"));
        assert!(rendered.contains("super::CommandJournalPolicy::None"));
        Ok(())
    }

    #[test]
    fn command_missing_policy_is_rejected() -> anyhow::Result<()> {
        let root = unique_tmp("codegen_cmd_missing_policy");
        seed_command(&root)?;
        let manifest = root.join("contracts/command/_seed/v1/contract.toml");
        let text =
            std::fs::read_to_string(&manifest)?.replace("[command]\njournal = \"required\"\n", "");
        std::fs::write(&manifest, text)?;
        let result = generate(&root.join("contracts"), &root.join("generated/src"), false);
        let _ = std::fs::remove_dir_all(&root);
        assert!(
            result.is_err(),
            "command 缺 journal policy 时 codegen 必须失败"
        );
        Ok(())
    }

    #[test]
    fn non_command_policy_is_rejected() -> anyhow::Result<()> {
        let root = unique_tmp("codegen_non_cmd_policy");
        seed_event(&root)?;
        let manifest = root.join("contracts/event/_seed/v1/contract.toml");
        let mut text = std::fs::read_to_string(&manifest)?;
        text.push_str("[command]\njournal = \"none\"\n");
        std::fs::write(&manifest, text)?;
        let result = generate(&root.join("contracts"), &root.join("generated/src"), false);
        let _ = std::fs::remove_dir_all(&root);
        assert!(result.is_err(), "非 command 的 [command] block 必须失败");
        Ok(())
    }

    /// #1124 防注入红用例：command request schema title 非合法 Rust 标识符时 codegen 须 bail——typify 用
    /// title 作根类型名，generated wrapper 也用同名，坏 title 会注入生成源码 / 致类型名不匹配。
    /// 正向对照见 `command_glue_with_wrappers_emitted`（合法 title 正常派生）。
    #[test]
    fn command_request_title_injection_rejected() -> anyhow::Result<()> {
        let root = unique_tmp("codegen_cmd");
        let dir = root.join("contracts/command/_seed/v1");
        std::fs::create_dir_all(&dir)?;
        std::fs::write(
            dir.join("contract.toml"),
            concat!(
                "id = \"seed.do-thing\"\n",
                "kind = \"command\"\n",
                "domain = \"_seed\"\n",
                "version = \"v1\"\n",
                "owner = \"_framework\"\n",
                "consistencyLevel = \"OutboxFact\"\n",
                "lifecycle = \"draft\"\n",
                "topic = \"seed.commands.do-thing\"\n",
                "[schemas]\n",
                "request = \"request.schema.json\"\n",
                "[command]\n",
                "journal = \"required\"\n",
            ),
        )?;
        // title 含空格 / 分号 → 非法 Rust 标识符（typify 类型名注入面）
        let schema = "{\"$schema\":\"http://json-schema.org/draft-07/schema#\",\"title\":\"Bad Title; evil\",\"type\":\"object\",\"properties\":{},\"additionalProperties\":false}";
        std::fs::write(dir.join("request.schema.json"), schema)?;
        let result = generate(&root.join("contracts"), &root.join("generated/src"), false);
        let _ = std::fs::remove_dir_all(&root);
        assert!(
            result.is_err(),
            "非法 title 须被 codegen bail（防注入类型名）"
        );
        Ok(())
    }

    /// 嵌套形态种子：同 `event/identity/v1` 下两个 `<slug>/contract.toml`（draft，无 subscriptions）。
    fn seed_nested_events(root: &Path) -> Result<()> {
        for (slug, title) in [
            ("role-assigned", "IdentityRoleAssignedPayload"),
            ("role-revoked", "IdentityRoleRevokedPayload"),
        ] {
            let dir = root.join(format!("contracts/event/identity/v1/{slug}"));
            std::fs::create_dir_all(&dir)?;
            std::fs::write(
                dir.join("contract.toml"),
                format!(
                    "id = \"identity.{slug}\"\n\
                     kind = \"event\"\n\
                     domain = \"identity\"\n\
                     version = \"v1\"\n\
                     owner = \"identity\"\n\
                     consistencyLevel = \"OutboxFact\"\n\
                     lifecycle = \"draft\"\n\
                     topic = \"identity.{slug}\"\n\
                     [schemas]\n\
                     payload = \"payload.schema.json\"\n"
                ),
            )?;
            std::fs::write(
                dir.join("payload.schema.json"),
                format!(
                    "{{\"$schema\":\"http://json-schema.org/draft-07/schema#\",\"title\":\"{title}\",\
                     \"type\":\"object\",\"required\":[\"roleId\"],\
                     \"properties\":{{\"roleId\":{{\"type\":\"string\"}}}},\"additionalProperties\":false}}"
                ),
            )?;
        }
        Ok(())
    }

    /// 嵌套聚合（#1190）：同 `{domain}/{version}` 多契约聚合进**一个** `event/identity_v1.rs`，每契约一个
    /// `pub mod <slug_ident>`，glue POD 引用深一级 `super::super::`，且全文件只有一个 `@generated` 头。
    /// synthetic positive + 幂等无漂移（anti-vacuity：扁平 golden 不受影响由 `--check` 真仓守）。
    #[test]
    fn nested_events_aggregate_into_one_module_with_submodules() -> anyhow::Result<()> {
        let root = unique_tmp("codegen_nested");
        seed_nested_events(&root)?;
        let contracts = root.join("contracts");
        let gen_src = root.join("generated/src");
        generate(&contracts, &gen_src, false)?;
        generate(&contracts, &gen_src, true)?; // 幂等：无漂移
        let file = std::fs::read_to_string(gen_src.join("event/identity_v1.rs"))?;
        let _ = std::fs::remove_dir_all(&root);
        assert!(
            file.contains("pub mod role_assigned"),
            "缺 role_assigned 子模块: {file}"
        );
        assert!(
            file.contains("pub mod role_revoked"),
            "缺 role_revoked 子模块: {file}"
        );
        assert!(
            file.contains("pub const SPEC: super::super::EventSpec"),
            "嵌套 glue 须 super::super:: 引用父 mod EventSpec: {file}"
        );
        assert_eq!(
            file.matches("@generated").count(),
            1,
            "聚合文件须单一 @generated 头: {file}"
        );
        Ok(())
    }

    /// codegen 自守（独立于 validate）：同 `{domain}/{version}` 扁平 + 嵌套混用须 bail。
    #[test]
    fn mixed_flat_and_nested_in_one_module_bails() -> anyhow::Result<()> {
        let root = unique_tmp("codegen_mixed");
        seed_nested_events(&root)?;
        // 再在同 version 目录直放一个扁平 contract.toml（混用）。
        let flat = root.join("contracts/event/identity/v1");
        std::fs::write(
            flat.join("contract.toml"),
            "id = \"identity.flat\"\nkind = \"event\"\ndomain = \"identity\"\nversion = \"v1\"\n\
             owner = \"identity\"\nconsistencyLevel = \"OutboxFact\"\nlifecycle = \"draft\"\n\
             topic = \"identity.flat\"\n[schemas]\npayload = \"payload.schema.json\"\n",
        )?;
        std::fs::write(
            flat.join("payload.schema.json"),
            "{\"title\":\"IdentityFlatPayload\",\"type\":\"object\",\"properties\":{},\"additionalProperties\":false}",
        )?;
        let result = generate(&root.join("contracts"), &root.join("generated/src"), false);
        let _ = std::fs::remove_dir_all(&root);
        assert!(result.is_err(), "扁平/嵌套混用须被 codegen 自守 bail");
        Ok(())
    }

    #[test]
    fn transactional_batch_restores_prior_outputs_after_late_failure() -> anyhow::Result<()> {
        let root = unique_tmp("codegen-transaction-rollback");
        std::fs::create_dir_all(&root)?;
        let first = root.join("first.rs");
        let second = root.join("second.rs");
        std::fs::write(&first, b"old-first\n")?;
        std::fs::write(&second, b"old-second\n")?;
        let mut transaction = CodegenTransaction {
            outputs: vec![
                planned_output(first.clone(), Some(b"new-first\n".to_vec()))?,
                planned_output(second.clone(), Some(b"new-second\n".to_vec()))?,
            ],
            touched: Vec::new(),
        };

        let Err(error) = transaction.apply_with_hook(|index, _| {
            if index == 1 {
                bail!("synthetic final output failure")
            }
            Ok(())
        }) else {
            anyhow::bail!("late output failure unexpectedly committed the batch")
        };
        assert!(error.to_string().contains("synthetic final output failure"));
        transaction.rollback()?;
        assert_eq!(std::fs::read(&first)?, b"old-first\n");
        assert_eq!(std::fs::read(&second)?, b"old-second\n");
        std::fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn public_candidate_outputs_fail_closed_on_missing_drift_and_orphan() -> anyhow::Result<()> {
        let root = unique_tmp("codegen-public-candidate-drift");
        let module = root.join("crates/devicesecuritycontracts/src/policy.rs");
        let schema = root.join("crates/devicesecuritycontracts/schema/policy/response.schema.json");
        let orphan = root.join("crates/devicesecuritycontracts/src/orphan.rs");
        std::fs::create_dir_all(module.parent().context("module parent")?)?;
        std::fs::create_dir_all(schema.parent().context("schema parent")?)?;
        std::fs::write(&module, b"// tampered\n")?;
        std::fs::write(&orphan, b"// forbidden seventh output\n")?;
        let mut transaction = CodegenTransaction {
            outputs: vec![
                planned_output(module.clone(), Some(b"// governed module\n".to_vec()))?,
                planned_output(schema.clone(), Some(br#"{"title":"Governed"}"#.to_vec()))?,
                planned_output(orphan.clone(), None)?,
            ],
            touched: Vec::new(),
        };

        assert!(transaction.check().is_err());
        transaction.apply()?;
        assert_eq!(std::fs::read(&module)?, b"// governed module\n");
        assert_eq!(std::fs::read(&schema)?, br#"{"title":"Governed"}"#);
        assert!(!orphan.exists());
        std::fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn empty_contract_repository_cannot_touch_existing_outputs() -> anyhow::Result<()> {
        let root = unique_tmp("codegen-empty-contract-repository");
        let contracts = root.join("contracts");
        let sentinel = root.join("generated/src/sentinel.rs");
        std::fs::create_dir_all(&contracts)?;
        std::fs::create_dir_all(sentinel.parent().context("sentinel path has no parent")?)?;
        std::fs::write(&sentinel, b"preserve me\n")?;

        let Err(error) = run_root(&root, false) else {
            anyhow::bail!("empty production corpus unexpectedly passed code generation")
        };
        assert!(
            error.to_string().contains("contains no contracts"),
            "unexpected error: {error:#}"
        );
        assert_eq!(std::fs::read(&sentinel)?, b"preserve me\n");
        std::fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn device_certificate_candidate_registry_is_exact_draft_projection() -> anyhow::Result<()> {
        let root = crate::workspace_root()?;
        let governance = ContractGovernanceIr::load_consumer_workspace(&root)?;
        governance.read(|contracts| {
            let rendered = render_all(contracts)?;
            let source = rendered
                .iter()
                .find_map(|(path, source)| {
                    (path == Path::new("device_certificate.rs")).then_some(source.as_str())
                })
                .context("codegen must emit device_certificate.rs")?;

            for candidate in DeviceCertificateCandidateId::ALL {
                let spec = candidate.spec();
                let contract = contracts
                    .iter()
                    .find(|contract| contract.id() == spec.id)
                    .with_context(|| format!("missing governed candidate {}", spec.id))?;
                let symbol = GeneratedCarrier::from_contract(contract)?
                    .item(GeneratedItem::Contract)?
                    .symbol
                    .replacen("generated::", "crate::", 1);
                assert!(
                    source.contains(&symbol),
                    "missing candidate symbol {symbol}"
                );
            }
            assert_eq!(
                source
                    .matches("DeviceCertificateCandidateSpec::new(")
                    .count(),
                DeviceCertificateCandidateId::ALL.len()
            );
            assert!(
                source.contains("::assembly_schema::contract_manifest::Lifecycle::Draft"),
                "candidate registry must carry typed draft lifecycle"
            );
            assert!(source.contains("pub const CANDIDATE_CONTRACTS"));

            let mut all_missing = contracts.to_vec();
            all_missing.retain(|contract| {
                !DeviceCertificateCandidateId::ALL
                    .into_iter()
                    .any(|candidate| contract.id() == candidate.spec().id)
            });
            let Err(error) = render_all(&all_missing) else {
                anyhow::bail!("entirely missing candidate set unexpectedly rendered")
            };
            assert!(error.to_string().contains("entirely missing"));

            let mut missing = contracts.to_vec();
            missing.retain(|contract| {
                contract.id() != DeviceCertificateCandidateId::CommandAcked.spec().id
            });
            let Err(error) = render_device_certificate_candidates(&missing, true) else {
                anyhow::bail!("missing candidate unexpectedly rendered")
            };
            assert!(error.to_string().contains("must occur exactly once"));

            let mut duplicate = contracts.to_vec();
            duplicate.push(
                contracts
                    .iter()
                    .find(|contract| {
                        contract.id() == DeviceCertificateCandidateId::CertificateReported.spec().id
                    })
                    .context("reported candidate exists")?
                    .clone(),
            );
            let Err(error) = render_device_certificate_candidates(&duplicate, true) else {
                anyhow::bail!("duplicate candidate unexpectedly rendered")
            };
            assert!(error.to_string().contains("must occur exactly once"));

            for candidate in DeviceCertificateCandidateId::ALL {
                let spec = candidate.spec();
                if !matches!(spec.kind, ContractKind::Http | ContractKind::Event) {
                    continue;
                }
                let contract = contracts
                    .iter()
                    .find(|contract| contract.id() == spec.id)
                    .with_context(|| format!("missing governed candidate {}", spec.id))?;
                let kind_dir = spec.kind.as_dir();
                let registry_path = format!("{kind_dir}/mod.rs");
                let root_registry = rendered
                    .iter()
                    .find_map(|(path, source)| {
                        (path == Path::new(&registry_path)).then_some(source)
                    })
                    .with_context(|| format!("missing generated {registry_path}"))?;
                let symbol = GeneratedCarrier::from_contract(contract)?
                    .item(GeneratedItem::Contract)?
                    .symbol
                    .strip_prefix(&format!("generated::{kind_dir}::"))
                    .context("root registry symbol must be kind-relative")?
                    .replace("::CONTRACT", "::SPEC");
                assert!(
                    !root_registry.contains(&symbol),
                    "Draft candidate {} leaked into active {registry_path} as {symbol}",
                    spec.id
                );
            }

            let public = render_public_device_security_contracts(contracts)?;
            let expected_modules = DeviceCertificateCandidateId::ALL
                .into_iter()
                .map(|candidate| format!("src/{}.rs", candidate.spec().public_module))
                .chain(std::iter::once("src/lib.rs".to_owned()))
                .map(PathBuf::from)
                .collect::<BTreeSet<_>>();
            let actual_modules = public
                .rust
                .iter()
                .map(|(path, _)| path.clone())
                .collect::<BTreeSet<_>>();
            assert_eq!(actual_modules, expected_modules);
            let rendered_public = public
                .rust
                .iter()
                .map(|(_, source)| source.as_str())
                .collect::<String>();
            assert!(!rendered_public.contains("resource-security-fact"));
            for candidate in DeviceCertificateCandidateId::ALL {
                let spec = candidate.spec();
                let module = public
                    .rust
                    .iter()
                    .find_map(|(path, source)| {
                        (path == &PathBuf::from(format!("src/{}.rs", spec.public_module)))
                            .then_some(source)
                    })
                    .context("candidate public module exists")?;
                assert!(module.contains("pub const LIFECYCLE: &str = \"draft\""));
                assert!(module.contains(spec.id));
            }
            let expected_schemas = DeviceCertificateCandidateId::ALL
                .into_iter()
                .flat_map(|candidate| {
                    let spec = candidate.spec();
                    contracts
                        .iter()
                        .find(|contract| contract.id() == spec.id)
                        .into_iter()
                        .flat_map(move |contract| {
                            contract.manifest().declared_schema_files().into_iter().map(
                                move |file| {
                                    PathBuf::from("schema").join(spec.public_module).join(file)
                                },
                            )
                        })
                })
                .collect::<BTreeSet<_>>();
            assert_eq!(
                public
                    .schemas
                    .iter()
                    .map(|(path, _)| path.clone())
                    .collect::<BTreeSet<_>>(),
                expected_schemas
            );
            Ok(())
        })
    }

    fn public_device_security_source<'a>(
        public: &'a PublicDeviceSecurityProjection,
        module: &str,
    ) -> anyhow::Result<&'a str> {
        public
            .rust
            .iter()
            .find_map(|(path, source)| {
                (path == &PathBuf::from(format!("src/{module}.rs"))).then_some(source.as_str())
            })
            .with_context(|| format!("public {module} module exists"))
    }

    fn assert_public_http_operation(
        public: &PublicDeviceSecurityProjection,
        module: &str,
        method: &str,
        path: &str,
    ) -> anyhow::Result<()> {
        let source = public_device_security_source(public, module)?;
        assert!(source.contains("pub const OPERATION"));
        assert!(source.contains(&format!("crate::HttpMethod::{method}")));
        assert!(source.contains(path));
        Ok(())
    }

    fn assert_public_http_operations(contracts: &[GovernedContract]) -> anyhow::Result<()> {
        let public = render_public_device_security_contracts(contracts)?;

        let root = public_device_security_source(&public, "lib")?;
        assert!(root.contains("pub enum HttpMethod"));
        assert!(root.contains("pub struct HttpOperationDescriptor"));

        for (module, method, path) in [
            (
                "policy_put",
                "Put",
                "/api/v2/identity/devices/{deviceId}/certificate-policy",
            ),
            (
                "status_get",
                "Get",
                "/api/v2/identity/devices/{deviceId}/certificate-status",
            ),
        ] {
            assert_public_http_operation(&public, module, method, path)?;
        }

        for module in [
            "apply_device_certificate",
            "device_command_acked",
            "device_certificate_reported",
            "device_ingress_receipted",
        ] {
            assert!(
                !public_device_security_source(&public, module)?.contains("pub const OPERATION"),
                "non-HTTP module {module} exposed an HTTP operation"
            );
        }
        assert_eq!(
            public
                .rust
                .iter()
                .map(|(_, source)| source.matches("pub const OPERATION").count())
                .sum::<usize>(),
            2
        );
        Ok(())
    }

    #[test]
    fn public_device_security_http_operations_are_exact() -> anyhow::Result<()> {
        let root = crate::workspace_root()?;
        let governance = ContractGovernanceIr::load_consumer_workspace(&root)?;
        governance.read(assert_public_http_operations)
    }
}
