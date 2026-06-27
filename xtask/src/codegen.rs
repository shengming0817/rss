//! 契约 schema → committed `generated/` 派生码（typify → prettyplease → rustfmt）。
//!
//! INVARIANT: CODEGEN-DRIFT-01 — committed `generated/src/**` 与 `contracts/` 的派生结果字节一致、
//! 且无孤儿文件（删契约残留）。Medium（CI 门，`cargo xtask codegen --check`）。
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
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use typify::{TypeSpace, TypeSpaceSettings};

use crate::contract::manifest::{ContractKind, HttpAuthMode, HttpHeaderMode, Lifecycle};
use crate::contract::redaction::{self, FieldPolicy, PiiKind, Sensitivity, StructPolicies};
use crate::contract::{DiscoveredContract, discover, schema_declares_property};
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
/// seam，其余无特化。同一 `kind_dir` 内所有契约同 kind，故每 kind_dir 单一 `ModKind`。
#[derive(Clone, Copy, PartialEq, Eq)]
enum ModKind {
    Plain,
    Http,
    Event,
    Command,
}

/// 渲染全部期望文件（相对 `generated/src` 的路径 → 内容），确定性排序。
fn render_all(contracts: &[DiscoveredContract]) -> Result<Vec<(PathBuf, String)>> {
    let mut files: Vec<(PathBuf, String)> = Vec::new();
    // kinds: kind_dir → (modules, mod_kind) ——event/command kind 需在 mod.rs 特化加 POD / seam 定义。
    let mut kinds: BTreeMap<String, (BTreeSet<String>, ModKind)> = BTreeMap::new();
    for c in contracts {
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
            ContractKind::Saga => ModKind::Plain,
        };
        let rel = PathBuf::from(&kind_dir).join(format!("{module}.rs"));
        files.push((rel, render_contract(c)?));
        let entry = kinds
            .entry(kind_dir)
            .or_insert_with(|| (BTreeSet::new(), mod_kind));
        entry.0.insert(module);
        entry.1 = mod_kind; // 同 kind_dir 内所有契约同 kind
    }
    for (kind_dir, (modules, mod_kind)) in &kinds {
        files.push((
            PathBuf::from(kind_dir).join("mod.rs"),
            render_mod_rs(modules, *mod_kind),
        ));
    }
    files.push((PathBuf::from("lib.rs"), render_lib_rs(kinds.keys())));
    Ok(files)
}

/// 模块名 `{domain}_{version}`（如 `_seed_v1`）——每契约独立模块，跨契约类型名天然无碰撞。
fn module_name(domain: &str, version: &str) -> String {
    format!("{domain}_{version}")
}

/// 单契约的 typify 派生：按声明顺序把 schema 文件喂进一个 TypeSpace。
/// 对 event kind 额外追加从 manifest 派生的订阅注册 glue（CONTRACT_ID / TOPIC / SUBSCRIPTIONS）。
fn render_contract(c: &DiscoveredContract) -> Result<String> {
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
    for schema_file in c.manifest.schemas.declared_files() {
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
                "HTTP request schema {} 声明 tenantId；tenant scope 必须来自 X-Tenant-ID/JWT，不得来自 body",
                path.display()
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
    let payload = prettyplease::unparse(&parsed);

    // event kind：在 payload DTO 之后追加订阅注册 glue（从 manifest 而非 schema 派生）。
    // generated 保持零额外依赖——glue 全为 `&'static str` POD，`SubscriptionSpec` 定义在 event/mod.rs。
    // command kind：追加 CONTRACT/CONTRACT_ID/TOPIC + typed emit/register wrapper（triple funnel 顶层；
    // 泛型收口到 command/mod.rs 的 CommandEmit/CommandRegister seam）。
    match c.manifest.kind {
        ContractKind::Event => {
            let glue = render_event_glue(c)?;
            Ok(format!("{}{}{}", generated_header(&source), payload, glue))
        }
        ContractKind::Command => {
            let glue = render_command_glue(c)?;
            Ok(format!("{}{}{}", generated_header(&source), payload, glue))
        }
        ContractKind::Http => {
            let glue = render_http_glue(c)?;
            Ok(format!("{}{}{}", generated_header(&source), payload, glue))
        }
        ContractKind::Saga => Ok(format!("{}{}", generated_header(&source), payload)),
    }
}

fn render_http_glue(c: &DiscoveredContract) -> Result<String> {
    let domain = &c.manifest.domain;
    let contract_id = &c.manifest.id;
    for (field, value) in [("domain", domain.as_str()), ("id", contract_id.as_str())] {
        if !is_safe_codegen_ident(value) {
            bail!(
                "契约 {}/{}/{} 的 {field} 含不安全字符（防注入生成字面量）: {value:?}",
                c.manifest.kind.as_dir(),
                c.manifest.domain,
                c.manifest.version,
            );
        }
    }
    let mut out = format!(
        r#"
/// HTTP 契约 ID（`contract.toml` `id` 字段，单一事实源）。由 `cargo xtask codegen` 从 manifest 派生；勿手改。
pub const CONTRACT_ID: &str = "{contract_id}";

/// 契约归属绑定（`domain` + `id` 同源派生）。由 `cargo xtask codegen` 从 manifest 派生；勿手改。
pub const CONTRACT: ::vocab::ContractBinding =
    ::vocab::ContractBinding::from_static("{domain}", "{contract_id}");
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
    let mode = match auth.mode {
        HttpAuthMode::Permission => "Permission",
        HttpAuthMode::Public => "Public",
        HttpAuthMode::Bootstrap => "Bootstrap",
        HttpAuthMode::ClientsOnly => "ClientsOnly",
        HttpAuthMode::ServiceOwned => "ServiceOwned",
    };
    let reason = render_option_str(auth.reason.as_deref(), "reason")?;
    let permission = render_option_str(auth.permission.as_deref(), "permission")?;
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
        };
        headers.push(format!(
            "    super::HttpHeaderSpec {{ name: \"{name}\", mode: super::HttpHeaderMode::{header_mode} }}"
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

/// HTTP serving metadata（path/method/auth/header 单源）。由 `cargo xtask codegen` 从 manifest 派生；勿手改。
pub const SPEC: super::HttpSpec = super::HttpSpec {{
    contract_id: CONTRACT_ID,
    contract: CONTRACT,
    path: PATH,
    method: "{method}",
    auth: super::HttpAuthSpec {{
        mode: super::HttpAuthMode::{mode},
        reason: {reason},
        permission: {permission},
    }},
    headers: &[{headers_body}],
}};
"#,
        method = method.as_wire(),
    ));
    Ok(out)
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

/// command kind 派生 glue：CONTRACT / CONTRACT_ID / TOPIC 常量 + per-command typed `emit_async` / `register_handler`
/// wrapper（triple funnel 顶层）。wrapper 泛型收口到 `command/mod.rs` 的 `CommandEmit` / `CommandRegister`
/// seam——generated 不命名 runtime（`eventexec` Service 层），故经 seam 注入。
///
/// typed `Request` 类型名 = request schema 的 `title`（typify 用作根类型名）；拼进生成源前经
/// `syn::Ident` 收口（防注入非法标识符）。CONTRACT_ID/TOPIC 由 manifest 派生（draft 无 topic 回退用 id）。
fn render_command_glue(c: &DiscoveredContract) -> Result<String> {
    let domain = &c.manifest.domain;
    let contract_id = &c.manifest.id;
    let topic = c.manifest.topic.as_deref().unwrap_or(contract_id.as_str());
    let request_ty = command_request_type_name(c)?;
    Ok(format!(
        r#"
/// 命令契约 ID（`contract.toml` `id` 字段，单一事实源）。由 `cargo xtask codegen` 从 manifest 派生；勿手改。
pub const CONTRACT_ID: &str = "{contract_id}";

/// 契约归属绑定（`domain` + `id` 同源派生）。由 `cargo xtask codegen` 从 manifest 派生；勿手改。
pub const CONTRACT: ::vocab::ContractBinding =
    ::vocab::ContractBinding::from_static("{domain}", "{contract_id}");

/// 稳定命令 topic（broker routing key，`<domain>.commands.<name>`；active command 来自 `contract.toml`
/// `topic`，draft 回退用 id）。由 `cargo xtask codegen` 从 manifest 派生；勿手改。
pub const TOPIC: &str = "{topic}";

/// Producer wrapper（triple funnel 顶层）：把 typed [`{request_ty}`] 经注入的 [`super::CommandEmit`] 落
/// durable outbox。baked `CONTRACT` / `TOPIC`——业务不裸传 topic / payload、不直调 runtime emit。
/// `subject_id` 是不透明主体标识（落 outbox envelope.subject，必填）；`idempotency_key` 是可选业务幂等键
/// （`Some` ⇒ 稳定 `DispatchId`、同键二次 emit 被拒；`None` ⇒ 随机 `DispatchId`）。
/// 由 `cargo xtask codegen` 派生；勿手改。
pub async fn emit_async<E: super::CommandEmit>(
    emitter: &E,
    request: {request_ty},
    subject_id: ::std::string::String,
    idempotency_key: ::core::option::Option<::std::string::String>,
) -> ::core::result::Result<(), E::Error> {{
    emitter
        .emit(CONTRACT, TOPIC, &request, &subject_id, idempotency_key.as_deref())
        .await
}}

/// Consumer wrapper（consumer 侧对称收口）：把 typed [`{request_ty}`] handler 注册到注入的
/// [`super::CommandRegister`]。baked `CONTRACT_ID` / `TOPIC`。由 `cargo xtask codegen` 派生；勿手改。
pub fn register_handler<Reg, H, Fut>(registrar: &mut Reg, handler: H) -> Reg::Output
where
    Reg: super::CommandRegister,
    H: Fn({request_ty}) -> Fut + ::core::marker::Send + ::core::marker::Sync + 'static,
    Fut: ::core::future::Future<Output = Reg::Outcome> + ::core::marker::Send + 'static,
{{
    registrar.register::<{request_ty}, H, Fut>(CONTRACT_ID, TOPIC, handler)
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
    validate_schema_filename(file)?;
    let path = c.dir.join(file);
    let text = std::fs::read_to_string(&path)
        .with_context(|| format!("读 request schema {}", path.display()))?;
    let value: serde_json::Value = serde_json::from_str(&text)
        .with_context(|| format!("解析 request schema {}", path.display()))?;
    let title = value
        .get("title")
        .and_then(serde_json::Value::as_str)
        .with_context(|| {
            format!(
                "request schema {} 缺 title（codegen 派生类型名所需）",
                path.display()
            )
        })?;
    if title.starts_with("r#") || syn::parse_str::<syn::Ident>(title).is_err() {
        bail!("command request schema title 非法 Rust 类型标识符（防注入生成代码）: {title:?}");
    }
    Ok(title.to_string())
}

/// event kind 订阅注册 glue（从 manifest 派生，不消费 schema）。
///
/// 派生 `CONTRACT_ID`、`TOPIC`（active 必有 topic；draft 无 topic 则回退用 id）、以及
/// `SUBSCRIPTIONS: &[super::SubscriptionSpec]` 常量切片（每个 `[[subscriptions]]` 条目一行）。
/// `SubscriptionSpec` 类型定义在 `event/mod.rs`（特化 event mod.rs），本文件通过 `super::` 引用——
/// 避免每个 event 模块重复定义同名 struct（INVARIANT CODEGEN-DRIFT-01）。
///
/// **防注入守卫（review #216 F6）**：consumer / group 被拼进 Rust 字符串字面量；codegen 可独立于
/// `cargo xtask contract validate`（R7）运行，故此处经 [`is_safe_codegen_ident`] 再次校验形态，含引号 /
/// 反斜杠 / 空白等可破坏字面量 / 注入源码的字符即 `bail!`。与 R7 互为上下游闭环 funnel（authoring 拒绝 +
/// 派生防御），非只锁单侧 callsite。
fn render_event_glue(c: &DiscoveredContract) -> Result<String> {
    let contract_id = &c.manifest.id;
    // domain + id 同源绑成 `CONTRACT: ContractBinding`（#1193）；domain 取自 manifest domain 字段（非 id 派生）。
    let domain = &c.manifest.domain;
    // active event 必有 topic（R8）；draft 无 topic 则回退用 id，保持确定性（不出现 Option 条件代码分歧）。
    let topic = c.manifest.topic.as_deref().unwrap_or(contract_id.as_str());
    // 防注入自守（review #271 F4）：domain / id / topic 拼进生成 Rust 字符串字面量（`CONTRACT_ID` / `TOPIC` /
    // `CONTRACT::from_static`），与 consumer / group 同款经 [`is_safe_codegen_ident`] 收口——codegen 可独立于
    // `contract validate`（R7）运行，故不依赖上游已收口，自守拒引号 / 反斜杠 / 控制字符等可破坏字面量的字符
    // （容 `[a-z0-9._-]`：`_seed` / 点分 id / 连字符 topic 均合法）。红用例 `event_glue_rejects_unsafe_domain`。
    for (field, value) in [
        ("domain", domain.as_str()),
        ("id", contract_id.as_str()),
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
    // 每个 [[subscriptions]] 条目一行 SubscriptionSpec 字面量；拼前防注入收口（见函数 doc）。
    let mut subs: Vec<String> = Vec::with_capacity(c.manifest.subscriptions.len());
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
        subs.push(format!(
            "    super::SubscriptionSpec {{ contract_id: CONTRACT_ID, topic: TOPIC, consumer: \"{}\", group: \"{}\" }}",
            s.consumer, s.group
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

/// 契约绑定（`domain` + `id` 同源类型化常量，#1193）。outbox envelope / 事件 producer 以
/// `OutboxEnvelopeParts::new(CONTRACT, ..)` 传入契约归属，杜绝裸 string 分别 author domain / contract_id。
/// 由 `cargo xtask codegen` 从 manifest `domain` + `id` 派生；勿手改（golden 字节锁，INVARIANT
/// CONTRACT-BINDING-FUNNEL-01）。
pub const CONTRACT: ::vocab::ContractBinding =
    ::vocab::ContractBinding::from_static("{domain}", "{contract_id}");

/// 订阅注册声明（从 `[[subscriptions]]` 派生，供 bootstrap 接线）。
/// 每项含 `contract_id`、`topic`、`consumer`（消费者域）、`group`（稳定 consumer group）。
/// `SubscriptionSpec` 类型定义见父 mod（`event/mod.rs`）；此处通过 `super::` 引用，无重复定义。
/// 由 `cargo xtask codegen` 从 manifest 派生；勿手改。
pub const SUBSCRIPTIONS: &[super::SubscriptionSpec] = &[{subs_body}];
"#
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
        (Sensitivity::Public, None) => syn::parse_quote!(#[redact(public)]),
        (Sensitivity::Public, Some(mode)) => syn::parse_quote!(#[redact(public, mode = #mode)]),
        (Sensitivity::Internal, None) => syn::parse_quote!(#[redact(internal)]),
        (Sensitivity::Internal, Some(mode)) => {
            syn::parse_quote!(#[redact(internal, mode = #mode)])
        }
        (Sensitivity::Secret, None) => syn::parse_quote!(#[redact(secret)]),
        (Sensitivity::Secret, Some(mode)) => syn::parse_quote!(#[redact(secret, mode = #mode)]),
        (Sensitivity::Pii(kind), None) => {
            let kind = pii_lit(kind);
            syn::parse_quote!(#[redact(pii = #kind)])
        }
        (Sensitivity::Pii(kind), Some(mode)) => {
            let kind = pii_lit(kind);
            syn::parse_quote!(#[redact(pii = #kind, mode = #mode)])
        }
    }
}

fn pii_lit(kind: PiiKind) -> syn::LitStr {
    syn::LitStr::new(kind.as_wire(), proc_macro2::Span::call_site())
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
/// `INVARIANT: CODEGEN-DERIVABLE-DEFAULT-ALLOW-01`。
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
/// `INVARIANT: CODEGEN-DEFAULTS-UNWRAP-ALLOW-01`。
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
/// 订阅注册规格——event 契约 `[[subscriptions]]` 的 codegen 派生表示。
///
/// 全字段均为 `&'static str`（零运行时分配）；`contract_id`/`topic` 由同模块的
/// `CONTRACT_ID`/`TOPIC` 常量绑定（generated，勿手改）。bootstrap 消费 `SUBSCRIPTIONS` 切片接线。
///
/// 由 `cargo xtask codegen` 从 `contract.toml` `[[subscriptions]]` 派生；勿手改。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SubscriptionSpec {
    /// 契约 ID（`contract.toml` `id`）。
    pub contract_id: &'static str,
    /// 事件 topic（broker routing key）。
    pub topic: &'static str,
    /// 消费者域 DomainId。
    pub consumer: &'static str,
    /// 稳定 consumer group 名（broker 消费位点唯一键）。
    pub group: &'static str,
}
"#;

const HTTP_SPEC_DEF: &str = r#"
/// HTTP serving metadata generated from `contract.toml`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HttpSpec {
    pub contract_id: &'static str,
    pub contract: ::vocab::ContractBinding,
    pub path: &'static str,
    pub method: &'static str,
    pub auth: HttpAuthSpec,
    pub headers: &'static [HttpHeaderSpec],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HttpAuthSpec {
    pub mode: HttpAuthMode,
    pub reason: Option<&'static str>,
    pub permission: Option<&'static str>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpAuthMode {
    Permission,
    Public,
    Bootstrap,
    ClientsOnly,
    ServiceOwned,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HttpHeaderSpec {
    pub name: &'static str,
    pub mode: HttpHeaderMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpHeaderMode {
    PopulateOnly,
}
"#;

/// command kind mod.rs 特化：定义 `CommandEmit` / `CommandRegister` 收口 seam（各 `{domain}_{version}.rs`
/// 经 `super::` 引用）。generated 仅依赖 basis（serde），无法命名 runtime（`eventexec` Service 层），故
/// per-command wrapper 经这两个泛型 seam 注入——唯一 sanctioned 实现是组合根 bridge / registrar（委托
/// `eventexec::command::emit_async` / `register_command_handler`）。零额外依赖（serde + core）。
const COMMAND_SEAM_DEF: &str = r#"
/// Producer 收口 seam——命令 emit 能力（triple funnel 中层接缝）。
///
/// per-command `emit_async` wrapper 经本 seam 泛型收口；唯一 sanctioned 实现是组合根 bridge（委托
/// `eventexec::command::emit_async` → `outbox::Entry::new`）。由 `cargo xtask codegen` 派生；勿手改。
pub trait CommandEmit {
    /// emit 失败类型（实现绑定，如 `eventexec::command::CommandEmitError`）。
    type Error;
    /// 把 typed 命令 `request` 经 runtime emit 落 durable outbox。`contract` / `topic` 是 generated
    /// wrapper 注入的 baked 常量；`request` 是 typed payload（实现侧 `serde_json` 编码）；`subject_id` 是
    /// **runtime 必填**的不透明主体标识（落 outbox envelope.subject，如设备 / 会话 ID）；`idempotency_key`
    /// 是**可选**业务幂等键——`Some` ⇒ 经它 mint 稳定 `DispatchId`（同键二次 emit 被 claimer 拒），`None`
    /// ⇒ bridge mint 随机 `DispatchId`（无业务去重）。
    ///
    /// # Impl guide（bridge 作者参考）
    ///
    /// 实现本方法须依次完成以下四步：
    ///
    /// 1. **序列化 payload**：`let bytes = serde_json::to_vec(request)?;`
    /// 2. **生成 DispatchId**：`idempotency_key` 为 `Some(k)` ⇒
    ///    `eventexec::command::DispatchId::from_idempotency_key(k)?`（稳定业务幂等键）；为 `None` ⇒
    ///    `eventexec::command::DispatchId::from_idempotency_key(&Uuid::new_v4().to_string())?`（随机）。
    /// 3. **透传 subject_id**：直接转发本参数（runtime 写入 outbox envelope.subject，不再由 bridge 编造）。
    /// 4. **委托 runtime emit**：`eventexec::command::emit_async(emitter, dispatch_id, topic, contract, bytes, subject_id.to_owned()).await`
    ///
    /// 组合根 bridge 是唯一 sanctioned 实现者；域 crate 不得直接 impl 本 trait（机器守 `COMMAND-IMPL-ALLOWLIST-01`）。
    fn emit<R: ::serde::Serialize + ::core::marker::Send + ::core::marker::Sync>(
        &self,
        contract: ::vocab::ContractBinding,
        topic: &'static str,
        request: &R,
        subject_id: &str,
        idempotency_key: ::core::option::Option<&str>,
    ) -> impl ::core::future::Future<Output = ::core::result::Result<(), Self::Error>>
    + ::core::marker::Send;
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
    /// 把 typed `R` handler 绑到 `contract_id` / `topic`。typed decode + claimer 接线在实现侧。
    fn register<R, H, Fut>(
        &mut self,
        contract_id: &'static str,
        topic: &'static str,
        handler: H,
    ) -> Self::Output
    where
        R: for<'de> ::serde::Deserialize<'de> + ::core::marker::Send + 'static,
        H: Fn(R) -> Fut + ::core::marker::Send + ::core::marker::Sync + 'static,
        Fut: ::core::future::Future<Output = Self::Outcome> + ::core::marker::Send + 'static;
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
        ModKind::Plain => {}
    }
    for m in modules {
        s.push_str(&format!("pub mod {m};\n"));
    }
    s
}

fn render_lib_rs<'a>(kinds: impl Iterator<Item = &'a String>) -> String {
    let mut s = String::new();
    s.push_str("//! generated — 契约派生 wire 类型（committed，一等审查材料）。\n");
    s.push_str("//! 由 `cargo xtask codegen` 生成；勿手改。漂移由 `cargo xtask codegen --check` 守（CI 门）。\n");
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
                "lifecycle = \"draft\"\n",
                "topic = \"seed.happened\"\n",
                "delivery = \"at-least-once\"\n",
                "[schemas]\n",
                "payload = \"payload.schema.json\"\n",
                "[[subscriptions]]\n",
                "consumer = \"audit\"\n",
                "group = \"audit.seed-happened\"\n",
            ),
        )?;
        let schema = "{\"$schema\":\"http://json-schema.org/draft-07/schema#\",\"title\":\"SeedHappenedPayload\",\"type\":\"object\",\"required\":[\"id\"],\"properties\":{\"id\":{\"type\":\"string\"}},\"additionalProperties\":false}";
        std::fs::write(dir.join("payload.schema.json"), schema)?;
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
            "password 应注入 #[redact(secret)]:\n{rendered}"
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
    /// INVARIANT: CONTRACT-BINDING-FUNNEL-01 —— 守 `CONTRACT: ContractBinding` 由 manifest `domain` + `id`
    /// 同源派生（domain 取自 manifest 而非 id 前缀；`from_static("_seed", "seed.happened")`），golden 锁。
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
        // CONTRACT binding（#1193）：domain + id 同源；domain "_seed" ≠ id 首段 "seed" ⇒ 证明 domain
        // 取自 manifest domain 字段而非从 id 派生（rustfmt 可能换行，断言 from_static 调用子串）。
        assert!(
            rendered.contains(r#"::vocab::ContractBinding::from_static("_seed", "seed.happened")"#),
            "缺 CONTRACT binding 常量:\n{rendered}"
        );
        // SUBSCRIPTIONS 切片含 consumer / group 字面量
        assert!(
            rendered.contains(r#"consumer: "audit""#),
            "SUBSCRIPTIONS 缺 consumer 字面量:\n{rendered}"
        );
        assert!(
            rendered.contains(r#"group: "audit.seed-happened""#),
            "SUBSCRIPTIONS 缺 group 字面量:\n{rendered}"
        );
        // SubscriptionSpec 定义在 mod.rs（子模块经 super:: 引用）
        assert!(
            mod_rs.contains("pub struct SubscriptionSpec"),
            "mod.rs 缺 SubscriptionSpec 定义:\n{mod_rs}"
        );
        // 子模块通过 super:: 引用（不重复定义）
        assert!(
            rendered.contains("super::SubscriptionSpec"),
            "子模块应通过 super:: 引用 SubscriptionSpec:\n{rendered}"
        );
        Ok(())
    }

    /// event 无 subscriptions（draft）→ SUBSCRIPTIONS 为空切片，CONTRACT_ID / TOPIC 仍存在（anti-vacuity）。
    ///
    /// INVARIANT: CONTRACT-BINDING-FUNNEL-01 —— draft event 亦发射 `CONTRACT` 绑定常量（正向对照）。
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
        // CONTRACT binding 仍发射（draft 亦有；domain "_seed" 取自 manifest，#1193）
        assert!(
            rendered.contains(r#"::vocab::ContractBinding::from_static("_seed", "seed.happened")"#),
            "draft 缺 CONTRACT binding 常量:\n{rendered}"
        );
        // 空 subscriptions 切片
        assert!(
            rendered.contains("pub const SUBSCRIPTIONS: &[super::SubscriptionSpec] = &[];"),
            "空 subscriptions 应生成空切片:\n{rendered}"
        );
        Ok(())
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
    /// INVARIANT: CODEGEN-DERIVABLE-DEFAULT-ALLOW-01（anti-vacuity，Medium）。
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
            ),
        )?;
        // schema 与真实 contracts/command/_seed/v1/request.schema.json 对齐（targetId + amount）。
        let schema = "{\"$schema\":\"http://json-schema.org/draft-07/schema#\",\"title\":\"SeedDoThingRequest\",\"type\":\"object\",\"required\":[\"targetId\",\"amount\"],\"properties\":{\"targetId\":{\"type\":\"string\"},\"amount\":{\"type\":\"integer\",\"format\":\"int64\"}},\"additionalProperties\":false}";
        std::fs::write(dir.join("request.schema.json"), schema)?;
        Ok(())
    }

    /// command glue 测试（#1124）：command 契约派生 .rs 须含 CONTRACT_ID / TOPIC + typed `emit_async` /
    /// `register_handler` wrapper（triple funnel 顶层，锁 typed Request = schema title）；seam
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
            rendered.contains("pub async fn emit_async<E: super::CommandEmit>"),
            "缺 emit_async wrapper:\n{rendered}"
        );
        assert!(
            rendered.contains("pub fn register_handler<Reg, H, Fut>"),
            "缺 register_handler wrapper:\n{rendered}"
        );
        // wrapper 锁 typed Request（= request schema title 派生）
        assert!(
            rendered.contains("request: SeedDoThingRequest"),
            "emit_async 须锁 typed Request:\n{rendered}"
        );
        // F1（#1124 review）：wrapper + seam 把 subject_id（必填）+ idempotency_key（可选）纳入类型面，
        // 否则 bridge 拿不到 runtime 必需的 per-call subject / 业务幂等键。
        assert!(
            rendered.contains("subject_id: ::std::string::String")
                && rendered
                    .contains("idempotency_key: ::core::option::Option<::std::string::String>"),
            "emit_async wrapper 须含 subject_id + idempotency_key 参数:\n{rendered}"
        );
        assert!(
            mod_rs.contains("subject_id: &str")
                && mod_rs.contains("idempotency_key: ::core::option::Option<&str>"),
            "CommandEmit::emit seam 须含 subject_id + idempotency_key 参数:\n{mod_rs}"
        );
        // seam 定义在 mod.rs，子模块经 super:: 引用
        assert!(
            mod_rs.contains("pub trait CommandEmit")
                && mod_rs.contains("pub trait CommandRegister"),
            "mod.rs 缺 CommandEmit/CommandRegister seam:\n{mod_rs}"
        );
        assert!(
            rendered.contains("super::CommandEmit"),
            "wrapper 应经 super:: 引用 seam:\n{rendered}"
        );
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
}
