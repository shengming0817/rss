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

use crate::contract::manifest::ContractKind;
use crate::contract::{DiscoveredContract, discover};
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

/// 渲染全部期望文件（相对 `generated/src` 的路径 → 内容），确定性排序。
fn render_all(contracts: &[DiscoveredContract]) -> Result<Vec<(PathBuf, String)>> {
    let mut files: Vec<(PathBuf, String)> = Vec::new();
    // kinds: kind_dir → (modules, is_event_kind) ——event kind 需在 mod.rs 特化加 SubscriptionSpec 定义。
    let mut kinds: BTreeMap<String, (BTreeSet<String>, bool)> = BTreeMap::new();
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
        let rel = PathBuf::from(&kind_dir).join(format!("{module}.rs"));
        files.push((rel, render_contract(c)?));
        let entry = kinds
            .entry(kind_dir)
            .or_insert_with(|| (BTreeSet::new(), false));
        entry.0.insert(module);
        if c.manifest.kind == ContractKind::Event {
            entry.1 = true;
        }
    }
    for (kind_dir, (modules, is_event)) in &kinds {
        files.push((
            PathBuf::from(kind_dir).join("mod.rs"),
            render_mod_rs(modules, *is_event),
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
    for schema_file in c.manifest.schemas.declared_files() {
        // 防御性安全校验：schema 文件名须为纯文件名，防 `../` 路径逃逸（codegen 可独立于 validate 运行）。
        validate_schema_filename(schema_file)
            .with_context(|| format!("契约 {source} 的 schema 文件名不安全: {schema_file}"))?;
        let path = c.dir.join(schema_file);
        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("读 schema {}", path.display()))?;
        let root: RootSchema = serde_json::from_str(&text)
            .with_context(|| format!("解析 schema {}", path.display()))?;
        space
            .add_root_schema(root)
            .map_err(|e| anyhow::anyhow!("typify 派生 {}: {e}", path.display()))?;
    }
    let mut parsed =
        syn::parse2::<syn::File>(space.to_stream()).context("syn 解析 typify token 流")?;
    strip_sensitive_debug(&mut parsed);
    let payload = prettyplease::unparse(&parsed);

    // event kind：在 payload DTO 之后追加订阅注册 glue（从 manifest 而非 schema 派生）。
    // generated 保持零额外依赖——glue 全为 `&'static str` POD，`SubscriptionSpec` 定义在 event/mod.rs。
    if c.manifest.kind == ContractKind::Event {
        let glue = render_event_glue(c)?;
        Ok(format!("{}{}{}", generated_header(&source), payload, glue))
    } else {
        Ok(format!("{}{}", generated_header(&source), payload))
    }
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
    // active event 必有 topic（R8）；draft 无 topic 则回退用 id，保持确定性（不出现 Option 条件代码分歧）。
    let topic = c.manifest.topic.as_deref().unwrap_or(contract_id.as_str());
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

/// 含凭据级字段（password/secret/token/credential）的 generated struct 去掉 `Debug` derive——
/// 杜绝 `{:?}` 泄露凭据进日志（PR #186 F2）。sensitive-field redaction 单源在 codegen（不手改 committed
/// generated）；去 Debug 后该类型从类型层**不可** Debug-format（Hard），输出由 golden 锁。
/// `INVARIANT: CODEGEN-SENSITIVE-NODEBUG-01`。
fn strip_sensitive_debug(file: &mut syn::File) {
    const SENSITIVE: &[&str] = &["password", "passwd", "secret", "token", "credential"];
    for item in &mut file.items {
        let syn::Item::Struct(s) = item else {
            continue;
        };
        let has_sensitive = s.fields.iter().any(|f| {
            f.ident.as_ref().is_some_and(|id| {
                let name = id.to_string().to_ascii_lowercase();
                SENSITIVE.iter().any(|kw| name.contains(kw))
            })
        });
        if !has_sensitive {
            continue;
        }
        for attr in &mut s.attrs {
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
                .filter(|p| p.segments.last().is_none_or(|seg| seg.ident != "Debug"))
                .collect();
            attr.meta = syn::parse_quote!(derive(#kept));
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

fn render_mod_rs(modules: &BTreeSet<String>, is_event: bool) -> String {
    let mut s = generated_header("cargo xtask codegen (module funnel)");
    // event kind：在 mod.rs 定义 SubscriptionSpec（各子模块经 `super::` 引用，消除重复定义）。
    if is_event {
        s.push_str(SUBSCRIPTION_SPEC_DEF);
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
            "{\"$schema\":\"http://json-schema.org/draft-07/schema#\",\"title\":\"SensitiveSeedRequest\",\"type\":\"object\",\"required\":[\"password\",\"username\"],\"properties\":{\"password\":{\"type\":\"string\"},\"username\":{\"type\":\"string\"}},\"additionalProperties\":false}",
        )?;
        std::fs::write(
            dir.join("response.schema.json"),
            "{\"$schema\":\"http://json-schema.org/draft-07/schema#\",\"title\":\"SensitiveSeedResponse\",\"type\":\"object\",\"required\":[\"ok\"],\"properties\":{\"ok\":{\"type\":\"string\"}},\"additionalProperties\":false}",
        )?;
        Ok(())
    }

    /// 派生 .rs 中名为 `name` 的 struct 是否 derive `Debug`。
    fn struct_derives_debug(file: &syn::File, name: &str) -> bool {
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
                                .any(|p| p.segments.last().is_some_and(|seg| seg.ident == "Debug"))
                        })
            })
        })
    }

    /// 含敏感字段（`password` 等）的 generated wire struct 须被 codegen 剥 `Debug` derive
    /// （`strip_sensitive_debug`，`INVARIANT: CODEGEN-SENSITIVE-NODEBUG-01`）；非敏感 struct 保留 `Debug`
    /// 作 anti-vacuity 对照——杜绝 `{:?}` 把凭据打进日志（#1096，PR #186 F2）。
    ///
    /// anti-vacuity（结构保证）：typify 默认给所有派生 struct 加 `Debug`；若 `strip_sensitive_debug`
    /// 退化为 no-op，`SensitiveSeedRequest` 仍带 `Debug`，下方第一个 `assert!` 必失——守卫非恒真。
    #[test]
    fn sensitive_field_struct_drops_debug_derive() -> anyhow::Result<()> {
        let root = unique_tmp("codegen");
        seed_http_sensitive(&root)?;
        let contracts = root.join("contracts");
        let gen_src = root.join("generated/src");
        generate(&contracts, &gen_src, false)?;
        let rendered = std::fs::read_to_string(gen_src.join("http/_seed_v1.rs"))?;
        let _ = std::fs::remove_dir_all(&root);

        let parsed = syn::parse_str::<syn::File>(&rendered).context("解析派生 .rs")?;
        assert!(
            !struct_derives_debug(&parsed, "SensitiveSeedRequest"),
            "含 password 的 struct 不应 derive Debug（防 {{:?}} 泄露凭据）:\n{rendered}"
        );
        assert!(
            struct_derives_debug(&parsed, "SensitiveSeedResponse"),
            "非敏感 struct 应保留 Debug（anti-vacuity 对照）:\n{rendered}"
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
}
