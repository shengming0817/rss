//! 契约 schema → committed `generated/` 派生码（typify → prettyplease → rustfmt）。
//!
//! INVARIANT: CODEGEN-DRIFT-01 { level = "Medium", exec = "verify", source = "code" }— committed `generated/src/**` 与 `contracts/` 的派生结果字节一致、
//! 且无孤儿文件（删契约残留）。Medium（CI 门，`cargo xtask codegen --check`）。
//! INVARIANT: EVENT-TOPOLOGY-GENERATED-01 { level = "Hard", exec = "verify", source = "codegen", facet = "single-registry", golden = "generated/src/event/mod.rs", synthetic_red = "codegen::tests::event_partition_strategy_mismatch_rejected", anti_vacuity = "codegen::tests::event_glue_with_subscription_emitted" }
//! INVARIANT: COMMAND-JOURNAL-GENERATED-01 { level = "Hard", exec = "verify", source = "codegen", facet = "manifest-policy", golden = "generated/src/command/mod.rs", synthetic_red = "codegen::tests::command_missing_policy_is_rejected", anti_vacuity = "codegen::tests::command_glue_with_wrappers_emitted" }
//! INVARIANT: ROUTE-EVIDENCE-CODEGEN-01 { level = "Hard", exec = "verify", source = "codegen", facet = "manifest-to-generated-atomic-http-route", golden = "generated/src/http/mod.rs", synthetic_red = "codegen::tests::codegen_rejects_active_http_without_effect_profile", anti_vacuity = "codegen::tests::codegen_emits_http_consistency_level_inside_route_evidence" }
//! INVARIANT: GENERATED-RUSTDOC-01 { level = "Medium", exec = "verify", source = "code", synthetic_red = "codegen::tests::owned_event_and_command_seam_templates_document_public_api", anti_vacuity = "codegen::tests::command_glue_with_wrappers_emitted" }—— owned event/command templates require rustdoc on every public item, variant, accessor and associated item.
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

use crate::contract::manifest::{
    CommandJournalPolicy, ConsistencyLevel, ContractKind, EffectKind, HttpAuthMode, HttpHeaderMode,
    HttpResourceSharingMode, Lifecycle, LocalTxBoundary, LocalTxCommitUnknown, LocalTxModel,
    LocalTxRetry, WorkflowMode,
};
use crate::contract::protection::{self, AadDim, AtRest, ProtectionMode, StructProtectionPolicies};
use crate::contract::redaction::{self, FieldPolicy, PiiKind, Sensitivity, StructPolicies};
use crate::contract::{
    DiscoveredContract, TENANT_SCOPE_SOURCE_RULE, discover, schema_declares_property,
};
use crate::pathsafe;

/// 入口：生成（`check=false`）或校验漂移（`check=true`）真实仓的 committed 派生码。
pub(crate) fn run(check: bool) -> Result<()> {
    let root = crate::workspace_root()?;
    generate(
        &root.join("contracts"),
        &root.join("generated").join("src"),
        check,
    )
}

/// 把 `contracts_root` 派生进 `gen_src`。根可注入便于测试。
pub(crate) fn generate(contracts_root: &Path, gen_src: &Path, check: bool) -> Result<()> {
    let contracts = discover(contracts_root)?;
    let files = render_all(&contracts)?;
    for (rel, code) in &files {
        let formatted = format_rust(code)?; // rustfmt-canonical（同 cargo fmt），见模块 doc
        ensure_file_contents(&gen_src.join(rel), &formatted, check)?;
    }
    let expected: BTreeSet<PathBuf> = files.iter().map(|(rel, _)| gen_src.join(rel)).collect();
    reconcile_orphans(gen_src, &expected, check)?;
    Ok(())
}

/// mod.rs 特化档：event kind 注入 `SubscriptionSpec` POD，command kind 注入 `CommandEmit`/`CommandRegister`
/// seam，saga kind 注入 `SagaSpec` POD，其余无特化。同一 `kind_dir` 内所有契约同 kind，故每 kind_dir
/// 单一 `ModKind`。
#[derive(Clone, Copy, PartialEq, Eq)]
enum ModKind {
    Http,
    Event,
    Command,
    Saga,
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
fn render_all(contracts: &[DiscoveredContract]) -> Result<Vec<(PathBuf, String)>> {
    let mut files: Vec<(PathBuf, String)> = Vec::new();
    // group: (kind_dir, module) → (mod_kind, 同 module 的契约切片)。BTreeMap 保确定性序。
    let mut groups: BTreeMap<(String, String), (ModKind, Vec<&DiscoveredContract>)> =
        BTreeMap::new();
    // kinds: kind_dir → (modules, mod_kind) ——event/command kind 需在 mod.rs 特化加 POD / seam 定义。
    let mut kinds: BTreeMap<String, (BTreeSet<String>, ModKind)> = BTreeMap::new();
    for c in contracts {
        if (c.manifest.kind == ContractKind::Command) != c.manifest.command.is_some() {
            bail!(
                "契约 {}/{}/{} 的 [command] block 与 kind 不匹配（codegen fail-closed）",
                c.manifest.kind.as_dir(),
                c.manifest.domain,
                c.manifest.version
            );
        }
        let kind_dir = c.manifest.kind.as_dir().to_string();
        let module = module_name(&c.manifest.domain, &c.manifest.version);
        // 防御性安全校验：domain/version 派生的 module 名须为纯路径段，防 `../` 逃逸。
        // codegen 可独立于 `contract validate` 运行，故不能依赖 R3/R7 已先收口字段——自守。
        if pathsafe::is_unsafe_segment(&module) {
            bail!(
                "契约 {}/{}/{} 派生 module 名含路径分量（防逃逸）: {module}",
                kind_dir,
                c.manifest.domain,
                c.manifest.version
            );
        }
        let mod_kind = match c.manifest.kind {
            ContractKind::Http => ModKind::Http,
            ContractKind::Event => ModKind::Event,
            ContractKind::Command => ModKind::Command,
            ContractKind::Saga => ModKind::Saga,
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
        files.push((rel, render_module_file(group)?));
    }
    for (kind_dir, (modules, mod_kind)) in &kinds {
        let mut mod_rs = render_mod_rs(modules, *mod_kind);
        if *mod_kind == ModKind::Http {
            mod_rs.push_str(&render_http_root_specs(contracts)?);
        }
        if *mod_kind == ModKind::Event {
            mod_rs.push_str(&render_event_root_subscriptions(contracts)?);
            mod_rs.push_str(&render_event_root_projection_inputs(contracts)?);
            mod_rs.push_str(&render_event_root_producer_domains(contracts)?);
        }
        files.push((PathBuf::from(kind_dir).join("mod.rs"), mod_rs));
    }
    files.push((PathBuf::from("lib.rs"), render_lib_rs(kinds.keys())));
    Ok(files)
}

/// 模块名 `{domain}_{version}`（如 `_seed_v1`）。同 `{domain}_{version}` 的多契约（嵌套形态）聚合进一个
/// 模块文件，经 `pub mod <slug>` 子命名空间隔离类型名。
fn module_name(domain: &str, version: &str) -> String {
    format!("{domain}_{version}")
}

/// 渲染一个 `{domain}_{version}.rs` 模块文件（含 1 个 `@generated` 头 + 1..N 个契约 body）。
/// 扁平（单契约 `slug=None`）→ 裸 body；嵌套（多契约 `slug=Some`）→ 每契约 `pub mod <slug_ident> { body }`。
fn render_module_file(group: &[&DiscoveredContract]) -> Result<String> {
    let first = group
        .first()
        .context("空契约 group（codegen 不变式被破坏）")?;
    let source = format!(
        "contracts/{}/{}/{}/",
        first.manifest.kind.as_dir(),
        first.manifest.domain,
        first.manifest.version
    );
    let header = generated_header(&source);

    let has_flat = group.iter().any(|c| c.slug.is_none());
    let has_nested = group.iter().any(|c| c.slug.is_some());
    if has_flat && has_nested {
        bail!(
            "module {}/{} 同时含扁平（直接 contract.toml）与嵌套（<slug>/contract.toml）契约——二义（CONTRACT-NEST-EXCLUSIVE-01）",
            first.manifest.domain,
            first.manifest.version
        );
    }
    // 扁平：恰一契约，裸 body（顶层常量，POD 引用 super::）——与历史输出字节一致。
    if has_flat {
        if group.len() != 1 {
            bail!(
                "module {}/{} 扁平形态却有 {} 个契约（扁平须恰一）",
                first.manifest.domain,
                first.manifest.version,
                group.len()
            );
        }
        return Ok(format!(
            "{header}{}",
            render_contract_body(first, "super::")?
        ));
    }

    // 嵌套：每契约一个 `pub mod <slug_ident> { body }`，body POD 引用深一级 super::super::。
    let mut ordered: Vec<&&DiscoveredContract> = group.iter().collect();
    ordered.sort_by(|a, b| a.slug.cmp(&b.slug)); // 按 slug 确定性序
    let mut seen_idents: BTreeSet<String> = BTreeSet::new();
    let mut out = header;
    for c in ordered {
        let slug = c
            .slug
            .as_deref()
            .context("嵌套契约缺 slug（codegen 不变式）")?;
        let ident = slug_module_ident(slug)?;
        if !seen_idents.insert(ident.clone()) {
            bail!(
                "module {}/{} 的 slug {slug:?} 派生重复子模块名 {ident}（kebab→snake 碰撞）",
                first.manifest.domain,
                first.manifest.version
            );
        }
        let body = render_contract_body(c, "super::super::")?;
        out.push_str(&format!(
            "\n/// 端点 `{slug}` 派生契约（源 `{slug}/contract.toml`）。由 `cargo xtask codegen` 派生；勿手改。\npub mod {ident} {{\n{body}\n}}\n"
        ));
    }
    Ok(out)
}

fn schema_hash(c: &DiscoveredContract) -> Result<String> {
    let mut hasher = Sha256::new();
    hasher.update(b"rss-schema-hash-v1\0");
    for file in c.manifest.declared_schema_files() {
        validate_schema_filename(file)?;
        let path = c.dir.join(file);
        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("读 schema {}", path.display()))?;
        let value: serde_json::Value = serde_json::from_str(&text)
            .with_context(|| format!("解析 schema {}", path.display()))?;
        let canonical = serde_json::to_vec(&canonical_json(value))
            .with_context(|| format!("canonicalize schema {}", path.display()))?;
        hasher.update(file.as_bytes());
        hasher.update(b"\0");
        hasher.update(canonical.len().to_string().as_bytes());
        hasher.update(b"\0");
        hasher.update(&canonical);
        hasher.update(b"\0");
    }
    Ok(format!("sha256:{}", lower_hex(&hasher.finalize())))
}

fn canonical_json(value: serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Array(values) => {
            serde_json::Value::Array(values.into_iter().map(canonical_json).collect())
        }
        serde_json::Value::Object(map) => {
            let sorted: BTreeMap<String, serde_json::Value> = map
                .into_iter()
                .map(|(k, v)| (k, canonical_json(v)))
                .collect();
            let mut out = serde_json::Map::new();
            for (k, v) in sorted {
                out.insert(k, v);
            }
            serde_json::Value::Object(out)
        }
        other => other,
    }
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
    let mut variant = String::new();
    for segment in domain
        .split(['.', '-', '_'])
        .filter(|part| !part.is_empty())
    {
        let mut chars = segment.chars();
        if let Some(first) = chars.next() {
            variant.push(first.to_ascii_uppercase());
            variant.extend(chars);
        }
    }
    if variant.starts_with("r#") || syn::parse_str::<syn::Ident>(&variant).is_err() {
        bail!("event domain {domain:?} 派生非法 Rust enum variant {variant:?}");
    }
    Ok(variant)
}

/// 单契约的 typify 派生 body（payload DTO + 派生 glue，**不含** `@generated` 头）。
/// `sup` 是 POD 引用前缀：扁平 body 用 `"super::"`（POD 在父 `{kind}/mod.rs`）、嵌套 body 在
/// `pub mod <slug>` 内故用 `"super::super::"`。对 event kind 追加订阅注册 glue（CONTRACT_ID / TOPIC /
/// SUBSCRIPTIONS），http kind 追加 SPEC，command kind 追加 emit/register wrapper。
fn render_contract_body(c: &DiscoveredContract, sup: &str) -> Result<String> {
    let mut settings = TypeSpaceSettings::default();
    settings.with_struct_builder(false); // 不要 builder 噪声
    let mut space = TypeSpace::new(&settings);
    let source = format!(
        "contracts/{}/{}/{}/",
        c.manifest.kind.as_dir(),
        c.manifest.domain,
        c.manifest.version
    );
    let mut redaction_policies: StructPolicies = BTreeMap::new();
    let mut protection_policies: StructProtectionPolicies = BTreeMap::new();
    let schema_files = if c.manifest.kind == ContractKind::Saga {
        c.manifest.declared_schema_files()
    } else {
        c.manifest.schemas.declared_files()
    };
    for schema_file in schema_files {
        // 防御性安全校验：schema 文件名须为纯文件名，防 `../` 路径逃逸（codegen 可独立于 validate 运行）。
        validate_schema_filename(schema_file)
            .with_context(|| format!("契约 {source} 的 schema 文件名不安全: {schema_file}"))?;
        let path = c.dir.join(schema_file);
        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("读 schema {}", path.display()))?;
        let value: serde_json::Value = serde_json::from_str(&text)
            .with_context(|| format!("解析 schema {}", path.display()))?;
        if c.manifest.kind == ContractKind::Http
            && c.manifest.schemas.request.as_deref() == Some(schema_file)
            && schema_declares_property(&value, "tenantId")
        {
            bail!(
                "HTTP request schema {} 声明 tenantId；tenant scope 必须来自{}，不得来自 body",
                path.display(),
                TENANT_SCOPE_SOURCE_RULE
            );
        }
        let schema_policies = redaction::collect_struct_policies(&value).map_err(|violations| {
            anyhow::anyhow!(
                "redaction policy invalid in {}: {}",
                path.display(),
                violations
                    .iter()
                    .map(|v| format!("{}: {}", v.pointer, v.detail))
                    .collect::<Vec<_>>()
                    .join("; ")
            )
        })?;
        redaction_policies.extend(schema_policies);
        let schema_protection_policies =
            protection::collect_struct_policies(&value).map_err(|violations| {
                anyhow::anyhow!(
                    "protection policy invalid in {}: {}",
                    path.display(),
                    violations
                        .iter()
                        .map(|v| format!("{}: {}", v.pointer, v.detail))
                        .collect::<Vec<_>>()
                        .join("; ")
                )
            })?;
        protection_policies.extend(schema_protection_policies);
        let root: RootSchema = serde_json::from_str(&text)
            .with_context(|| format!("解析 schema {}", path.display()))?;
        space
            .add_root_schema(root)
            .map_err(|e| anyhow::anyhow!("typify 派生 {}: {e}", path.display()))?;
    }
    let mut parsed =
        syn::parse2::<syn::File>(space.to_stream()).context("syn 解析 typify token 流")?;
    apply_redaction_policy(&mut parsed, &redaction_policies);
    allow_derivable_default_impls(&mut parsed);
    allow_unwrap_in_defaults_mod(&mut parsed);
    let mut payload = prettyplease::unparse(&parsed);
    payload.push_str(&render_field_protection_impls(
        &parsed,
        &protection_policies,
    ));

    // event kind：在 payload DTO 之后追加订阅注册 glue（从 manifest 而非 schema 派生）。
    // generated 保持零额外依赖——glue 全为 `&'static str` POD，`SubscriptionSpec` 定义在 event/mod.rs。
    // command kind：追加 CONTRACT/CONTRACT_ID/TOPIC + policy-exclusive typed wrapper（generated seam 顶层；
    // 泛型收口到 command/mod.rs 的 CommandEmit/CommandRegister seam）。`sup` = POD 引用前缀（嵌套深一级）。
    match c.manifest.kind {
        ContractKind::Event => Ok(format!("{}{}", payload, render_event_glue(c, sup)?)),
        ContractKind::Command => Ok(format!("{}{}", payload, render_command_glue(c, sup)?)),
        ContractKind::Http => Ok(format!("{}{}", payload, render_http_glue(c, sup)?)),
        ContractKind::Saga => Ok(format!("{}{}", payload, render_saga_glue(c, sup)?)),
    }
}

fn render_saga_glue(c: &DiscoveredContract, sup: &str) -> Result<String> {
    let saga = c
        .manifest
        .saga
        .as_ref()
        .context("saga 契约缺 [saga] block（codegen fail-closed）")?;
    let domain = &c.manifest.domain;
    let contract_id = &c.manifest.id;
    let version = &c.manifest.version;
    let schema_hash = schema_hash(c)?;
    for (field, value) in [
        ("domain", domain.as_str()),
        ("id", contract_id.as_str()),
        ("version", version.as_str()),
    ] {
        if !is_safe_codegen_ident(value) {
            bail!(
                "契约 {}/{}/{} 的 {field} 含不安全字符（防注入生成字面量）: {value:?}",
                c.manifest.kind.as_dir(),
                c.manifest.domain,
                c.manifest.version,
            );
        }
    }
    if !is_safe_codegen_string(&schema_hash) {
        bail!(
            "契约 {}/{}/{} 的 schema_hash 含不安全字符（防注入生成字面量）: {schema_hash:?}",
            c.manifest.kind.as_dir(),
            c.manifest.domain,
            c.manifest.version,
        );
    }
    let retry_millis = saga.retry_millis;
    let timeout_millis = saga.timeout_millis;
    let mut step_consts = Vec::new();
    let mut step_entries = Vec::new();
    for (idx, step) in saga.steps.iter().enumerate() {
        for (field, value) in [
            ("saga step name", step.name.as_str()),
            ("saga step outputSchema", step.output_schema.as_str()),
        ] {
            if !is_safe_codegen_string(value) {
                bail!(
                    "契约 {}/{}/{} 的 {field} 含不安全字符（防注入生成字面量）: {value:?}",
                    c.manifest.kind.as_dir(),
                    c.manifest.domain,
                    c.manifest.version,
                );
            }
        }
        validate_schema_filename(&step.output_schema).with_context(|| {
            format!(
                "契约 {}/{}/{} 的 saga step outputSchema 不安全: {}",
                c.manifest.kind.as_dir(),
                c.manifest.domain,
                c.manifest.version,
                step.output_schema
            )
        })?;
        let const_name = format!("STEP_{idx}");
        let output_ty = schema_root_type_name(c, &step.output_schema, "saga step outputSchema")?;
        step_consts.push(format!(
            r#"
/// Saga step `{}` binding generated from `[saga].steps[{idx}]`.
pub const {const_name}: ::vocab::SagaStepBinding =
    ::vocab::SagaStepBinding::from_static(CONTRACT, "{}", "{}");

impl ::vocab::SagaStepOutputBinding for {output_ty} {{
    const BINDING: ::vocab::SagaStepBinding = {const_name};
}}
"#,
            step.name, step.name, step.output_schema
        ));
        step_entries.push(const_name);
    }
    let steps_body = if step_entries.is_empty() {
        String::new()
    } else {
        format!("\n{},\n", step_entries.join(",\n"))
    };
    let step_consts = step_consts.join("");
    Ok(format!(
        r#"
/// Saga 契约 ID（`contract.toml` `id` 字段，单一事实源）。由 `cargo xtask codegen` 从 manifest 派生；勿手改。
pub const CONTRACT_ID: &str = "{contract_id}";

/// 契约归属绑定（`domain` + `id` + `version` + `schema_hash` 同源派生）。由 `cargo xtask codegen` 从 manifest 派生；勿手改。
pub const CONTRACT: ::vocab::ContractBinding =
    ::vocab::ContractBinding::from_static("{domain}", "{contract_id}", "{version}", "{schema_hash}");

/// Saga runtime policy spec（来自 `[saga].retryMillis` / `[saga].timeoutMillis`）。由 `cargo xtask codegen` 从 manifest 派生；勿手改。
pub const POLICY: ::vocab::SagaRuntimePolicySpec =
    ::vocab::SagaRuntimePolicySpec::from_millis({retry_millis}, {timeout_millis});
{step_consts}
/// Ordered saga step bindings generated from `[saga].steps`.
pub const STEPS: &[::vocab::SagaStepBinding] = &[{steps_body}];

/// Saga contract spec（契约绑定 + runtime policy spec + ordered steps）。由 `cargo xtask codegen` 从 manifest 派生；勿手改。
pub const SPEC: {sup}SagaSpec = {sup}SagaSpec::from_parts(CONTRACT, POLICY, STEPS);
"#
    ))
}

fn render_http_glue(c: &DiscoveredContract, sup: &str) -> Result<String> {
    let domain = &c.manifest.domain;
    let contract_id = &c.manifest.id;
    let version = &c.manifest.version;
    let schema_hash = schema_hash(c)?;
    for (field, value) in [
        ("domain", domain.as_str()),
        ("id", contract_id.as_str()),
        ("version", version.as_str()),
    ] {
        if !is_safe_codegen_ident(value) {
            bail!(
                "契约 {}/{}/{} 的 {field} 含不安全字符（防注入生成字面量）: {value:?}",
                c.manifest.kind.as_dir(),
                c.manifest.domain,
                c.manifest.version,
            );
        }
    }
    if !is_safe_codegen_string(&schema_hash) {
        bail!(
            "契约 {}/{}/{} 的 schema_hash 含不安全字符（防注入生成字面量）: {schema_hash:?}",
            c.manifest.kind.as_dir(),
            c.manifest.domain,
            c.manifest.version,
        );
    }
    let mut out = format!(
        r#"
/// HTTP 契约 ID（`contract.toml` `id` 字段，单一事实源）。由 `cargo xtask codegen` 从 manifest 派生；勿手改。
pub const CONTRACT_ID: &str = "{contract_id}";

/// 契约归属绑定（`domain` + `id` + `version` + `schema_hash` 同源派生）。由 `cargo xtask codegen` 从 manifest 派生；勿手改。
pub const CONTRACT: ::vocab::ContractBinding =
    ::vocab::ContractBinding::from_static("{domain}", "{contract_id}", "{version}", "{schema_hash}");
"#
    );
    if c.manifest.lifecycle != Lifecycle::Active {
        return Ok(out);
    }
    let path = c
        .manifest
        .path
        .as_deref()
        .context("active http 契约缺 path（codegen fail-closed）")?;
    let method = c
        .manifest
        .method
        .context("active http 契约缺 method（codegen fail-closed）")?;
    let http = c
        .manifest
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
                c.manifest.kind.as_dir(),
                c.manifest.domain,
                c.manifest.version,
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
    let consistency_level = render_http_consistency_level(c.manifest.consistency_level);
    let effect_profile = render_http_effect_profile_consts(c)?;
    let local_tx = render_http_local_tx(c, sup)?;
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
                            c.manifest.kind.as_dir(),
                            c.manifest.domain,
                            c.manifest.version,
                        )
                    })?;
                if !resource_present {
                    bail!(
                        "契约 {}/{}/{} resourceSharing mode=global 必须声明 endpoints.http.resource（codegen fail-closed）",
                        c.manifest.kind.as_dir(),
                        c.manifest.domain,
                        c.manifest.version,
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
                        c.manifest.kind.as_dir(),
                        c.manifest.domain,
                        c.manifest.version,
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
                        c.manifest.kind.as_dir(),
                        c.manifest.domain,
                        c.manifest.version,
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
                c.manifest.kind.as_dir(),
                c.manifest.domain,
                c.manifest.version,
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

/// Field projection metadata（来自 `contract.toml` `[endpoints.http.projection]`）。由 `cargo xtask codegen` 从 manifest 派生；勿手改。
pub const PROJECTION_FIELDS: &[{sup}HttpProjectionFieldSpec] = &[{projection_fields_body}];
{effect_profile}

/// Contract-specific route identity. Each generated HTTP contract owns a distinct marker type.
pub enum RouteMarker {{}}

/// Typed route binding（metadata + contract identity 单一载体）。由 codegen 派生；勿手改。
pub const ROUTE: ::vocab::HttpRouteBinding<RouteMarker, ::vocab::http::{consistency_level}> = ::vocab::HttpRouteBinding::from_static(
    CONTRACT,
    PATH,
    "{method}",
    {auth},
    {resource},
    {self_scoped},
    EFFECT_PROFILE,
);

/// HTTP serving metadata（path/method/auth/header 单源）。由 `cargo xtask codegen` 从 manifest 派生；勿手改。
pub const SPEC: {sup}HttpSpec = {sup}HttpSpec {{
    route: ROUTE.evidence(),
    local_tx: {local_tx},
    resource_sharing: {sup}HttpResourceSharingSpec {{
        mode: {sup}HttpResourceSharingMode::{resource_sharing_mode},
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

fn render_http_consistency_level(level: ConsistencyLevel) -> &'static str {
    match level {
        ConsistencyLevel::LocalOnly => "LocalOnly",
        ConsistencyLevel::LocalTx => "LocalTx",
        ConsistencyLevel::OutboxFact => "OutboxFact",
        ConsistencyLevel::WorkflowEventual => "WorkflowEventual",
        ConsistencyLevel::DeviceLatent => "DeviceLatent",
    }
}

fn render_http_effect_profile_consts(c: &DiscoveredContract) -> Result<String> {
    let profile = c
        .manifest
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
        EffectKind::Write => "Write",
        EffectKind::Transaction => "Transaction",
        EffectKind::Outbox => "Outbox",
        EffectKind::Publish => "Publish",
        EffectKind::Workflow => "Workflow",
        EffectKind::Saga => "Saga",
        EffectKind::Reconcile => "Reconcile",
        EffectKind::Worker => "Worker",
        EffectKind::CrossTenantAudit => "CrossTenantAudit",
    }
}

fn render_http_local_tx(c: &DiscoveredContract, sup: &str) -> Result<String> {
    if c.manifest.consistency_level != ConsistencyLevel::LocalTx {
        if c.manifest.capabilities.local_tx.is_some() {
            bail!("非 LocalTx http 契约不得声明 [capabilities.localTx]（codegen fail-closed）");
        }
        return Ok("None".to_string());
    }

    let local_tx = c
        .manifest
        .capabilities
        .local_tx
        .as_ref()
        .context("LocalTx http 契约缺 [capabilities.localTx]（codegen fail-closed）")?;
    let spec = format!(
        "{sup}LocalTxSpec {{ boundary: ::vocab::LocalTxBoundary::{}, tx_model: ::vocab::LocalTxModel::{}, retry: ::vocab::LocalTxRetry::{}, commit_unknown: ::vocab::LocalTxCommitUnknown::{} }}",
        render_local_tx_boundary(local_tx.boundary),
        render_local_tx_model(local_tx.tx_model),
        render_local_tx_retry(local_tx.retry),
        render_local_tx_commit_unknown(local_tx.commit_unknown),
    );
    Ok(format!("Some({spec})"))
}

fn render_local_tx_boundary(boundary: LocalTxBoundary) -> &'static str {
    match boundary {
        LocalTxBoundary::SingleDomain => "SingleDomain",
    }
}

fn render_local_tx_model(model: LocalTxModel) -> &'static str {
    match model {
        LocalTxModel::TenantScopedUow => "TenantScopedUow",
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
fn render_command_glue(c: &DiscoveredContract, sup: &str) -> Result<String> {
    let domain = &c.manifest.domain;
    let contract_id = &c.manifest.id;
    let version = &c.manifest.version;
    let schema_hash = schema_hash(c)?;
    let topic = c.manifest.topic.as_deref().unwrap_or(contract_id.as_str());
    for (field, value) in [
        ("domain", domain.as_str()),
        ("id", contract_id.as_str()),
        ("version", version.as_str()),
        ("topic", topic),
    ] {
        if !is_safe_codegen_ident(value) {
            bail!(
                "契约 {}/{}/{} 的 {field} 含不安全字符（防注入生成字面量）: {value:?}",
                c.manifest.kind.as_dir(),
                c.manifest.domain,
                c.manifest.version,
            );
        }
    }
    if !is_safe_codegen_string(&schema_hash) {
        bail!(
            "契约 {}/{}/{} 的 schema_hash 含不安全字符（防注入生成字面量）: {schema_hash:?}",
            c.manifest.kind.as_dir(),
            c.manifest.domain,
            c.manifest.version,
        );
    }
    let request_ty = command_request_type_name(c)?;
    let policy = c
        .manifest
        .command
        .as_ref()
        .context("command 契约缺 [command] block（codegen fail-closed）")?
        .journal;
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
    tenant: ::vocab::TenantId,
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
    tenant: ::vocab::TenantId,
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
    Ok(format!(
        r#"
/// 命令契约 ID（`contract.toml` `id` 字段，单一事实源）。由 `cargo xtask codegen` 从 manifest 派生；勿手改。
pub const CONTRACT_ID: &str = "{contract_id}";

/// 契约归属绑定（`domain` + `id` + `version` + `schema_hash` 同源派生）。由 `cargo xtask codegen` 从 manifest 派生；勿手改。
pub const CONTRACT: ::vocab::ContractBinding =
    ::vocab::ContractBinding::from_static("{domain}", "{contract_id}", "{version}", "{schema_hash}");

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

impl {sup}{policy_trait} for Contract {{}}

/// Typed reconcile input for this command. Fields are private and routing is baked into [`SPEC`].
pub struct ReconcileCommand<S, A> {{
    request: {request_ty},
    tenant: ::vocab::TenantId,
    subject_id: S,
    actor: A,
    idempotency_key: ::std::string::String,
}}

impl<S, A> {sup}private::Sealed for ReconcileCommand<S, A> {{}}

impl<S, A> {sup}TypedCommandSpec for ReconcileCommand<S, A> {{
    type Contract = Contract;
    type SubjectId = S;
    type Actor = A;

    fn request(&self) -> &<Self::Contract as {sup}CommandContract>::Request {{ &self.request }}
    fn tenant(&self) -> ::vocab::TenantId {{ self.tenant }}
    fn idempotency_key(&self) -> &str {{ &self.idempotency_key }}
    fn into_identity(self) -> (Self::SubjectId, Self::Actor) {{ (self.subject_id, self.actor) }}
}}

/// Build the only reconcile-authoring input for this command. Topic, contract, and payload type are
/// generated facts rather than caller-supplied strings/bytes.
pub fn reconcile_command<S, A>(
    request: {request_ty},
    tenant: ::vocab::TenantId,
    subject_id: S,
    actor: A,
    idempotency_key: ::std::string::String,
) -> ReconcileCommand<S, A> {{
    ReconcileCommand {{ request, tenant, subject_id, actor, idempotency_key }}
}}

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

/// 从 command 契约的 request schema 提取 typify 根类型名（= schema `title`）。拼进生成源前经
/// `syn::Ident` 收口——拒非法 Rust 标识符 / raw `r#`（防注入生成代码；与 R7 互为上下游 funnel）。
fn command_request_type_name(c: &DiscoveredContract) -> Result<String> {
    let file = c
        .manifest
        .schemas
        .request
        .as_deref()
        .context("command 契约缺 [schemas].request（R4 应已守）")?;
    schema_root_type_name(c, file, "command request schema")
}

fn schema_root_type_name(
    c: &DiscoveredContract,
    schema_file: &str,
    label: &'static str,
) -> Result<String> {
    validate_schema_filename(schema_file).with_context(|| {
        format!(
            "契约 {}/{}/{} 的 {label} 文件名不安全: {schema_file}",
            c.manifest.kind.as_dir(),
            c.manifest.domain,
            c.manifest.version
        )
    })?;
    let path = c.dir.join(schema_file);
    let text =
        std::fs::read_to_string(&path).with_context(|| format!("读 {label} {}", path.display()))?;
    let value: serde_json::Value =
        serde_json::from_str(&text).with_context(|| format!("解析 {label} {}", path.display()))?;
    let title = value
        .get("title")
        .and_then(serde_json::Value::as_str)
        .with_context(|| {
            format!(
                "{label} {} 缺 title（codegen 派生类型名所需）",
                path.display()
            )
        })?;
    if title.starts_with("r#") || syn::parse_str::<syn::Ident>(title).is_err() {
        bail!("{label} title 非法 Rust 类型标识符（防注入生成代码）: {title:?}");
    }
    Ok(title.to_string())
}

/// event kind 订阅注册 glue（从 manifest 派生，不消费 schema）。
///
/// 派生 `CONTRACT_ID`、`TOPIC`（active 必有 topic；draft 无 topic 则回退用 id）、以及
/// `SUBSCRIPTIONS` 常量切片（每个 `[[subscriptions]]` 条目一行）。`SubscriptionSpec` 类型定义在
/// `event/mod.rs`（特化 event mod.rs），本文件经 `sup` 前缀引用（扁平 `super::` / 嵌套子模块 `super::super::`）
/// ——避免每个 event 模块重复定义同名 struct（INVARIANT CODEGEN-DRIFT-01）。
///
/// **防注入守卫（review #216 F6）**：consumer / group 被拼进 Rust 字符串字面量；codegen 可独立于
/// `cargo xtask contract validate`（R7）运行，故此处经 [`is_safe_codegen_ident`] 再次校验形态，含引号 /
/// 反斜杠 / 空白等可破坏字面量 / 注入源码的字符即 `bail!`。与 R7 互为上下游闭环 funnel（authoring 拒绝 +
/// 派生防御），非只锁单侧 callsite。
fn render_event_glue(c: &DiscoveredContract, sup: &str) -> Result<String> {
    let contract_id = &c.manifest.id;
    // domain + id + version + schema_hash 同源绑成 `CONTRACT: ContractBinding`（#1193/#1618）；
    // domain 取自 manifest domain 字段（非 id 派生），schema_hash 取 declared schema canonical digest。
    let domain = &c.manifest.domain;
    let version = &c.manifest.version;
    let schema_hash = schema_hash(c)?;
    // active event 必有 topic（R8）；draft 无 topic 则回退用 id，保持确定性（不出现 Option 条件代码分歧）。
    let topic = c.manifest.topic.as_deref().unwrap_or(contract_id.as_str());
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
                c.manifest.kind.as_dir(),
                c.manifest.domain,
                c.manifest.version,
            );
        }
    }
    if !is_safe_codegen_string(&schema_hash) {
        bail!(
            "契约 {}/{}/{} 的 schema_hash 含不安全字符（防注入生成字面量）: {schema_hash:?}",
            c.manifest.kind.as_dir(),
            c.manifest.domain,
            c.manifest.version,
        );
    }
    // producer partition strategy 与 subscription list 同属一个 EventSpec；不同订阅不得各自漂移。
    let mut subs: Vec<String> = Vec::with_capacity(c.manifest.subscriptions.len());
    let partition_key = c
        .manifest
        .subscriptions
        .first()
        .map(|subscription| subscription.topology.partition_key)
        .unwrap_or(crate::contract::manifest::PartitionKeyStrategy::None);
    for s in &c.manifest.subscriptions {
        if !is_safe_codegen_ident(&s.consumer) {
            bail!(
                "契约 {}/{}/{} 的 subscription consumer 含不安全字符（防注入生成字面量）: {:?}",
                c.manifest.kind.as_dir(),
                c.manifest.domain,
                c.manifest.version,
                s.consumer
            );
        }
        if !is_safe_codegen_ident(&s.group) {
            bail!(
                "契约 {}/{}/{} 的 subscription group 含不安全字符（防注入生成字面量）: {:?}",
                c.manifest.kind.as_dir(),
                c.manifest.domain,
                c.manifest.version,
                s.group
            );
        }
        if s.topology.partition_key != partition_key {
            bail!(
                "契约 {}/{}/{} 的 subscriptions partitionKey 不一致；producer strategy 必须单源",
                c.manifest.kind.as_dir(),
                c.manifest.domain,
                c.manifest.version,
            );
        }
        subs.push(format!(
            "    {sup}SubscriptionSpec::new(\"{}\", \"{}\", {sup}SubscriberReadiness::{})",
            s.consumer,
            s.group,
            match s.topology.readiness {
                crate::contract::manifest::SubscriberReadiness::Required => "Required",
            }
        ));
    }
    let subs_body = if subs.is_empty() {
        String::new()
    } else {
        format!("\n{},\n", subs.join(",\n"))
    };

    Ok(format!(
        r#"
/// 契约 ID（`contract.toml` `id` 字段，单一事实源）。由 `cargo xtask codegen` 从 manifest 派生；勿手改。
pub const CONTRACT_ID: &str = "{contract_id}";

/// 稳定事件 topic（broker routing key；active event 来自 `contract.toml` `topic` 字段，draft 回退用 id）。
/// 由 `cargo xtask codegen` 从 manifest 派生；勿手改。
pub const TOPIC: &str = "{topic}";

/// 契约绑定（`domain` + `id` + `version` + `schema_hash` 同源类型化常量，#1193/#1618）。outbox envelope / 事件 producer 以
/// `OutboxEnvelopeParts::new(CONTRACT, ..)` 传入契约归属，杜绝裸 string 分别 author domain / contract_id。
/// 由 `cargo xtask codegen` 从 manifest `domain` + `id` + `version` + declared schema 派生；勿手改（golden 字节锁，INVARIANT
/// CONTRACT-BINDING-FUNNEL-01）。
pub const CONTRACT: ::vocab::ContractBinding =
    ::vocab::ContractBinding::from_static("{domain}", "{contract_id}", "{version}", "{schema_hash}");

/// 单一事件 topology spec；producer 与 subscriptions 不存在平行 registry。
pub const SPEC: {sup}EventSpec = {sup}EventSpec::new(
    CONTRACT,
    TOPIC,
    {sup}PartitionKeyStrategy::{partition_variant},
    &[{subs_body}],
);
"#,
        partition_variant = match partition_key {
            crate::contract::manifest::PartitionKeyStrategy::None => "None",
            crate::contract::manifest::PartitionKeyStrategy::Aggregate => "Aggregate",
        },
    ))
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

/// generated struct 统一派生 `secure::Redact`，字段策略从 schema property 的 `x-pii` / `x-redaction`
/// 注入为 `#[redact(...)]`。非敏感字段默认 `public`，使所有 generated DTO 都有安全 `Debug`，不再裸
/// derive `Debug` 或把敏感类型去掉 `Debug`。
fn apply_redaction_policy(file: &mut syn::File, policies: &StructPolicies) {
    for item in &mut file.items {
        let syn::Item::Struct(s) = item else {
            continue;
        };
        rewrite_struct_derives(&mut s.attrs);
        let struct_policies = policies.get(&s.ident.to_string());
        for field in &mut s.fields {
            let Some(ident) = &field.ident else {
                continue;
            };
            let wire_name = serde_rename(field).unwrap_or_else(|| ident.to_string());
            let policy = struct_policies
                .and_then(|fields| fields.get(&wire_name))
                .copied()
                .unwrap_or_default();
            field.attrs.push(redact_attr(policy));
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
/// `INVARIANT: CODEGEN-DERIVABLE-DEFAULT-ALLOW-01` { level = "Medium", exec = "verify", source = "code" }。
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
/// `INVARIANT: CODEGEN-DEFAULTS-UNWRAP-ALLOW-01` { level = "Medium", exec = "verify", source = "code" }。
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

/// 校验 schema 文件名为纯文件名（无路径分量）。防逃逸单源见 `crate::pathsafe`。
fn validate_schema_filename(file: &str) -> Result<()> {
    if pathsafe::is_unsafe_segment(file) {
        bail!("schema 文件名含路径分量（防逃逸）: {file}");
    }
    Ok(())
}

/// 文件头：`@generated` 标记。派生码经 typify→prettyplease→rustfmt 三段成形（见模块 doc），勿手改。
fn generated_header(source: &str) -> String {
    format!("// @generated by `cargo xtask codegen` — DO NOT EDIT. Source: {source}\n")
}

/// event kind mod.rs 特化：含 `SubscriptionSpec` POD 定义（零额外依赖，纯 `&'static str` 字段）。
/// 各 event `{domain}_{version}.rs` 经 `super::SubscriptionSpec` 引用此定义，消除重复（CODEGEN-DRIFT-01）。
const SUBSCRIPTION_SPEC_DEF: &str = r#"
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
    readiness: SubscriberReadiness,
}

impl SubscriptionSpec {
    pub(crate) const fn new(
        consumer: &'static str,
        group: &'static str,
        readiness: SubscriberReadiness,
    ) -> Self { Self { consumer, group, readiness } }
    /// Consumer domain identifier.
    pub const fn consumer(self) -> &'static str { self.consumer }
    /// Durable consumer group.
    pub const fn group(self) -> &'static str { self.group }
    /// Runtime-readiness policy.
    pub const fn readiness(self) -> SubscriberReadiness { self.readiness }
}
"#;

const HTTP_SPEC_DEF: &str = r#"
/// HTTP serving metadata generated from `contract.toml`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HttpSpec {
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
    pub mode: HttpResourceSharingMode,
    pub reason: Option<&'static str>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpResourceSharingMode {
    TenantScoped,
    Global,
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

/// Schema-typed reconcile command input generated per command contract.
///
/// The private supertrait prevents downstream implementations, so callers cannot pair an arbitrary
/// request type with another command's routing metadata. Implementations bake one sealed
/// [`CommandSpec`] and keep request/envelope fields private.
pub trait TypedCommandSpec: private::Sealed {
    /// Per-command carrier that binds the request and routing metadata.
    type Contract: CommandContract;
    /// Envelope subject identity supplied by the runtime.
    type SubjectId;
    /// Envelope actor supplied by the runtime.
    type Actor;

    /// Borrow the generated request.
    fn request(&self) -> &<Self::Contract as CommandContract>::Request;
    /// Tenant scope for the command.
    fn tenant(&self) -> ::vocab::TenantId;
    /// Caller-provided idempotency key.
    fn idempotency_key(&self) -> &str;
    /// Consume the wrapper into envelope identity values.
    fn into_identity(self) -> (Self::SubjectId, Self::Actor);
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
        tenant: ::vocab::TenantId,
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
        tenant: ::vocab::TenantId,
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
    }
    for m in modules {
        s.push_str(&format!("pub mod {m};\n"));
    }
    s
}

fn render_http_spec_path(c: &DiscoveredContract) -> Result<String> {
    let module = module_name(&c.manifest.domain, &c.manifest.version);
    match c.slug.as_deref() {
        Some(slug) => Ok(format!("{module}::{}::SPEC", slug_module_ident(slug)?)),
        None => Ok(format!("{module}::SPEC")),
    }
}

fn render_http_root_specs(contracts: &[DiscoveredContract]) -> Result<String> {
    let mut entries = Vec::new();
    let mut local_tx_entries = Vec::new();
    for c in contracts
        .iter()
        .filter(|c| c.manifest.kind == ContractKind::Http)
        .filter(|c| c.manifest.lifecycle == Lifecycle::Active)
    {
        let path = render_http_spec_path(c)?;
        if c.manifest.consistency_level == ConsistencyLevel::LocalTx {
            local_tx_entries.push(format!("    {path}"));
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
    Ok(format!(
        r#"
/// Root registry for active HTTP specs generated from every HTTP contract.
pub const SPECS: &[HttpSpec] = &[{body}];

/// Root registry for active LocalTx HTTP specs generated from `consistencyLevel = "LocalTx"`.
pub const LOCAL_TX_SPECS: &[HttpSpec] = &[{local_tx_body}];
"#
    ))
}

fn render_event_root_subscriptions(contracts: &[DiscoveredContract]) -> Result<String> {
    let mut entries = Vec::new();
    for c in contracts
        .iter()
        .filter(|c| c.manifest.kind == ContractKind::Event)
        .filter(|c| c.manifest.lifecycle == Lifecycle::Active)
    {
        let module = module_name(&c.manifest.domain, &c.manifest.version);
        let path = match c.slug.as_deref() {
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

fn render_event_root_projection_inputs(contracts: &[DiscoveredContract]) -> Result<String> {
    let by_id: BTreeMap<&str, &DiscoveredContract> = contracts
        .iter()
        .map(|contract| (contract.manifest.id.as_str(), contract))
        .collect();
    let mut entries = Vec::new();
    let mut generation_tuples = Vec::new();
    for projection in contracts.iter().filter(|contract| {
        contract
            .manifest
            .capabilities
            .workflow
            .as_ref()
            .is_some_and(|workflow| workflow.mode == WorkflowMode::Projection)
    }) {
        let projection_id = projection.manifest.id.as_str();
        if !is_safe_codegen_ident(projection_id) {
            bail!("projection workflow id 含不安全字符（防注入生成字面量）: {projection_id:?}");
        }
        let Some(workflow) = projection.manifest.capabilities.workflow.as_ref() else {
            continue;
        };
        for input_id in &workflow.inputs {
            let input = by_id.get(input_id.as_str()).with_context(|| {
                format!(
                    "projection workflow {} input {} 不存在（codegen fail-closed）",
                    projection.manifest.id, input_id
                )
            })?;
            if input.manifest.kind != ContractKind::Event {
                bail!(
                    "projection workflow {} input {} 不是 event contract（codegen fail-closed）",
                    projection.manifest.id,
                    input_id
                );
            }
            let domain = input.manifest.domain.as_str();
            let contract_id = input.manifest.id.as_str();
            let version = input.manifest.version.as_str();
            let topic = input.manifest.topic.as_deref().unwrap_or(contract_id);
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
            let schema_hash = schema_hash(input)?;
            if !is_safe_codegen_string(&schema_hash) {
                bail!(
                    "projection input binding 的 schema_hash 含不安全字符（防注入生成字面量）: {schema_hash:?}"
                );
            }
            entries.push(format!(
                "    ::vocab::ProjectionInputBinding::from_static(\"{projection_id}\", \"{domain}\", \"{contract_id}\", \"{version}\", \"{schema_hash}\", \"{topic}\")"
            ));
            generation_tuples.push([
                contract_id.to_string(),
                version.to_string(),
                schema_hash,
                topic.to_string(),
            ]);
        }
    }
    entries.sort();
    let generation = projection_input_generation(&mut generation_tuples);
    let body = if entries.is_empty() {
        String::new()
    } else {
        format!("\n{},\n", entries.join(",\n"))
    };
    Ok(format!(
        r#"
/// Root projection input registry aggregated from `[capabilities.workflow].inputs`.
///
/// Postgres projection writers consume this static registry to decide which outbox facts are also
/// mirrored into `projection_events`. Runtime code must not enumerate projection topics by hand.
pub const PROJECTION_INPUT_GENERATION: &str = "{generation}";

/// Projection bindings that belong to [`PROJECTION_INPUT_GENERATION`].
pub const PROJECTION_INPUTS: &[::vocab::ProjectionInputBinding] = &[{body}];
"#
    ))
}

fn projection_input_generation(tuples: &mut [[String; 4]]) -> String {
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

fn render_event_root_producer_domains(contracts: &[DiscoveredContract]) -> Result<String> {
    let domains: BTreeSet<&str> = contracts
        .iter()
        .filter(|contract| contract.manifest.kind == ContractKind::Event)
        .filter(|contract| contract.manifest.lifecycle == Lifecycle::Active)
        .filter(|contract| contract.manifest.consistency_level == ConsistencyLevel::OutboxFact)
        .map(|contract| contract.manifest.domain.as_str())
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

fn render_lib_rs<'a>(kinds: impl Iterator<Item = &'a String>) -> String {
    let mut s = String::new();
    s.push_str("//! generated — 契约派生 wire 类型（committed，一等审查材料）。\n");
    s.push_str("//! 由 `cargo xtask codegen` 生成；勿手改。漂移由 `cargo xtask codegen --check` 守（CI 门）。\n");
    s.push_str(FIELD_PROTECTION_METADATA_DEF);
    for k in kinds {
        s.push_str(&format!("pub mod {k};\n"));
    }
    s
}

/// rust-analyzer 模式：内容一致则 noop；`check` 下漂移即 `bail`；否则写盘（建父目录）。
/// 漂移错误消息附带 contracts/ 源路径，便于作者定位触发变更的契约。
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
/// 经 [`crate::cmd::clean_cmd`] 清洗 ambient 环境（剥 `RUSTUP_TOOLCHAIN` 等），确保用 rust-toolchain.toml
/// 钉的 1.96 rustfmt、不被外部 toolchain override 改变 golden 派生（INVARIANT CODEGEN-DRIFT-01）。
pub(crate) fn format_rust(code: &str) -> Result<String> {
    use std::io::Write;
    use std::process::Stdio;
    let mut child = crate::cmd::clean_cmd("rustfmt", &["--edition", "2024"], &[], None)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::unique_tmp;

    fn assert_generated_contains(source: &str, needle: &str, message: &str) {
        assert!(source.contains(needle), "{message}:\n{source}");
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
                "[[subscriptions]]\n",
                "consumer = \"audit\"\n",
                "group = \"audit.seed-happened\"\n",
                "[subscriptions.topology]\n",
                "partitionKey = \"none\"\n",
                "readiness = \"required\"\n",
            ),
        )?;
        let schema = "{\"$schema\":\"http://json-schema.org/draft-07/schema#\",\"title\":\"SeedHappenedPayload\",\"type\":\"object\",\"required\":[\"id\"],\"properties\":{\"id\":{\"type\":\"string\"}},\"additionalProperties\":false}";
        std::fs::write(dir.join("payload.schema.json"), schema)?;
        Ok(())
    }

    /// 在 `root/contracts/saga/billing/v1` 落一个最小 saga 契约（payload + step output schemas）。
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
                "retryMillis = 5000\n",
                "timeoutMillis = 30000\n",
                "steps = [\n",
                "  { name = \"reserve_funds\", outputSchema = \"reserve.schema.json\" },\n",
                "  { name = \"capture\", outputSchema = \"capture.schema.json\" },\n",
                "]\n",
            ),
        )?;
        let payload = "{\"$schema\":\"http://json-schema.org/draft-07/schema#\",\"title\":\"BillingCheckoutPayload\",\"type\":\"object\",\"required\":[\"checkoutId\"],\"properties\":{\"checkoutId\":{\"type\":\"string\"}},\"additionalProperties\":false}";
        let reserve = "{\"$schema\":\"http://json-schema.org/draft-07/schema#\",\"title\":\"ReserveFundsOutput\",\"type\":\"object\",\"required\":[\"reserved\"],\"properties\":{\"reserved\":{\"type\":\"boolean\"}},\"additionalProperties\":false}";
        let capture = "{\"$schema\":\"http://json-schema.org/draft-07/schema#\",\"title\":\"CaptureOutput\",\"type\":\"object\",\"required\":[\"captured\"],\"properties\":{\"captured\":{\"type\":\"boolean\"}},\"additionalProperties\":false}";
        std::fs::write(dir.join("payload.schema.json"), payload)?;
        std::fs::write(dir.join("reserve.schema.json"), reserve)?;
        std::fs::write(dir.join("capture.schema.json"), capture)?;
        Ok(())
    }

    /// 落一个 projection workflow 契约，input 指向 `seed.happened` event 契约。
    fn seed_projection_workflow(root: &Path) -> Result<()> {
        let dir = root.join("contracts/http/audit/v1");
        std::fs::create_dir_all(&dir)?;
        std::fs::write(
            dir.join("contract.toml"),
            concat!(
                "id = \"audit.seed-projection\"\n",
                "kind = \"http\"\n",
                "domain = \"audit\"\n",
                "version = \"v1\"\n",
                "owner = \"audit\"\n",
                "consistencyLevel = \"WorkflowEventual\"\n",
                "lifecycle = \"draft\"\n",
                "[schemas]\n",
                "request = \"request.schema.json\"\n",
                "response = \"response.schema.json\"\n",
                "[capabilities.workflow]\n",
                "mode = \"projection\"\n",
                "inputs = [\"seed.happened\"]\n",
                "ordering = \"serial-in-order\"\n",
                "checkpoint = \"required\"\n",
                "replay = \"required\"\n",
            ),
        )?;
        let request = "{\"$schema\":\"http://json-schema.org/draft-07/schema#\",\"title\":\"AuditSeedProjectionRequest\",\"type\":\"object\",\"properties\":{},\"additionalProperties\":false}";
        let response = "{\"$schema\":\"http://json-schema.org/draft-07/schema#\",\"title\":\"AuditSeedProjectionResponse\",\"type\":\"object\",\"properties\":{},\"additionalProperties\":false}";
        std::fs::write(dir.join("request.schema.json"), request)?;
        std::fs::write(dir.join("response.schema.json"), response)?;
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
            "mode: super::HttpResourceSharingMode::Global",
            "endpoint SPEC 应携带 global resourceSharing mode",
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
                "  \"write\",\n",
                "  \"transaction\",\n",
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
            "Write",
            "Transaction",
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
            Some(concat!(
                "[effectProfile]\n",
                "effects = [\"auth\", \"write\", \"transaction\"]\n",
            )),
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
            "local_tx: Some(super::LocalTxSpec",
            "LocalTx endpoint SPEC should carry LocalTx evidence",
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
            Some(concat!(
                "[effectProfile]\n",
                "effects = [\"auth\", \"write\", \"transaction\"]\n",
            )),
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
    /// - `SUBSCRIPTIONS` 常量切片（含 consumer / group 字面量）
    /// - `SubscriptionSpec` 定义在 `event/mod.rs`（子模块经 `super::` 引用，无重复定义）
    ///
    /// anti-vacuity：无 subscriptions 的 draft event 仍生成空 SUBSCRIPTIONS 切片 + CONTRACT_ID / TOPIC（正向对照）。
    ///
    /// INVARIANT: CONTRACT-BINDING-FUNNEL-01 { level = "Medium", exec = "verify", source = "code" }—— 守 `CONTRACT: ContractBinding` 由 manifest `domain` + `id`
    /// + `version` + declared schema hash 同源派生（domain 取自 manifest 而非 id 前缀），golden 锁。
    #[test]
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
            rendered.contains("::vocab::ContractBinding::from_static(")
                && rendered.contains(r#""_seed","#)
                && rendered.contains(r#""seed.happened","#)
                && rendered.contains(r#""v1","#)
                && rendered.contains(r#""sha256:"#),
            "缺 CONTRACT binding 常量:\n{rendered}"
        );
        // 每事件只有一个 SPEC，subscription 嵌套在同一 EventSpec。
        assert!(
            rendered.contains("SubscriptionSpec::new(")
                && rendered.contains(r#""audit""#)
                && rendered.contains(r#""audit.seed-happened""#),
            "SPEC 缺 consumer 字面量:\n{rendered}"
        );
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
            rendered.contains("::vocab::ContractBinding::from_static(")
                && rendered.contains(r#""billing","#)
                && rendered.contains(r#""billing.checkout","#)
                && rendered.contains(r#""v1","#)
                && rendered.contains(r#""sha256:"#),
            "缺 CONTRACT binding:\n{rendered}"
        );
        assert!(
            rendered.contains("::vocab::SagaRuntimePolicySpec::from_millis(5000, 30000)"),
            "缺 saga runtime policy spec:\n{rendered}"
        );
        assert!(
            rendered.contains("pub struct ReserveFundsOutput")
                && rendered.contains("pub struct CaptureOutput"),
            "缺 saga step output DTO:\n{rendered}"
        );
        assert!(
            rendered.contains("impl ::vocab::SagaStepOutputBinding for ReserveFundsOutput")
                && rendered.contains("impl ::vocab::SagaStepOutputBinding for CaptureOutput"),
            "缺 saga step output DTO binding marker:\n{rendered}"
        );
        assert!(
            rendered.contains(
                r#"pub const STEP_0: ::vocab::SagaStepBinding =
    ::vocab::SagaStepBinding::from_static(CONTRACT, "reserve_funds", "reserve.schema.json");"#
            ) && rendered.contains(
                r#"pub const STEP_1: ::vocab::SagaStepBinding =
    ::vocab::SagaStepBinding::from_static(CONTRACT, "capture", "capture.schema.json");"#
            ),
            "缺 saga step binding constants:\n{rendered}"
        );
        assert!(
            rendered.contains("pub const STEPS: &[::vocab::SagaStepBinding] = &[STEP_0, STEP_1];"),
            "缺 ordered saga STEPS:\n{rendered}"
        );
        assert!(
            rendered.contains(
                "pub const SPEC: super::SagaSpec = super::SagaSpec::from_parts(CONTRACT, POLICY, STEPS);"
            ),
            "缺 SagaSpec 常量:\n{rendered}"
        );
        assert!(
            mod_rs.contains("pub type SagaSpec = ::vocab::SagaContractBinding;"),
            "saga/mod.rs 缺 SagaSpec type alias:\n{mod_rs}"
        );
        Ok(())
    }

    /// event 无 subscriptions（draft）→ SUBSCRIPTIONS 为空切片，CONTRACT_ID / TOPIC 仍存在（anti-vacuity）。
    ///
    /// INVARIANT: CONTRACT-BINDING-FUNNEL-01 { level = "Medium", exec = "verify", source = "code" }—— draft event 亦发射 `CONTRACT` 绑定常量（正向对照）。
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
            rendered.contains("::vocab::ContractBinding::from_static(")
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
        let _ = std::fs::remove_dir_all(&root);

        assert!(
            mod_rs.contains("pub const PROJECTION_INPUTS: &[::vocab::ProjectionInputBinding]"),
            "event/mod.rs 缺 projection input root registry:\n{mod_rs}"
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
        Ok(())
    }

    #[test]
    fn projection_input_generation_is_sorted_u64_length_prefixed_known_answer() {
        let seed = [
            "seed.happened".to_string(),
            "v1".to_string(),
            "sha256:e75b5df7855eff522195aacdad81fd493b4290ecef710d871fe038efe9e43e07".to_string(),
            "seed.happened".to_string(),
        ];
        let other = [
            "alpha.changed".to_string(),
            "v2".to_string(),
            format!("sha256:{}", "0".repeat(64)),
            "alpha.changed".to_string(),
        ];
        let mut single = vec![seed.clone()];
        assert_eq!(
            projection_input_generation(&mut single),
            "sha256:b9b30e01a1a96f97c64f9f36e3cd88fc90fe7f69433cf7ec17c71def3a88071d"
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

    /// `allow_derivable_default_impls` 守卫 anti-vacuity 测试（ai-robust.md §运行期 governance 测试要求）：
    /// - 正向：`impl Default for Foo {}` 块经 `allow_derivable_default_impls` 后携带
    ///   `#[allow(clippy::derivable_impls)]`。
    /// - 负向控制：`impl SomethingElse for Foo {}` 不被注入该 allow 属性。
    ///
    /// INVARIANT: CODEGEN-DERIVABLE-DEFAULT-ALLOW-01 { level = "Medium", exec = "verify", source = "code" }（anti-vacuity，Medium）。
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
            rendered.contains("pub struct ReconcileCommand")
                && rendered
                    .contains("impl<S, A> super::TypedCommandSpec for ReconcileCommand<S, A>")
                && rendered.contains("pub fn reconcile_command<S, A>"),
            "缺 per-command typed reconcile wrapper/spec impl:\n{rendered}"
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
            rendered.contains("tenant: ::vocab::TenantId")
                && rendered.contains("subject_id: J::SubjectId")
                && rendered.contains("actor: J::Actor")
                && rendered.contains("idempotency_key: ::std::string::String"),
            "journal_async wrapper 须含必填 idempotency_key:\n{rendered}"
        );
        assert!(
            mod_rs.contains("tenant: ::vocab::TenantId")
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
                && mod_rs.contains("pub trait TypedCommandSpec: private::Sealed"),
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
}
