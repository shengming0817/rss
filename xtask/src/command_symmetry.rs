//! `command-symmetry` —— generated command 模块双侧对称性 + 裸 emit / durable journal 出口封堵 +
//! impl-site 收口（治理门）。
//!
//! INVARIANT: COMMAND-SYMMETRY-01 { level = "Medium", exec = "verify", source = "code" }（Medium，Rule 1+2）· COMMAND-IMPL-ALLOWLIST-01（Medium，Rule 3）
//!
//! 守住三条约束：
//!
//! **Rule 1：双侧对称 + codegen 完整性（`MissingEmitWrapper` / `MissingRegisterWrapper` /
//! `MissingCommandConst`）**
//! `generated/src/command/` 下每个 per-command `.rs`（排除 `mod.rs`）必须同时含：
//! - `pub async fn emit_async`（producer 收口）
//! - `pub fn register_handler`（consumer 收口）
//! - `pub const CONTRACT_ID`
//! - `pub const TOPIC`
//!
//! 缺任一即 finding。其价值：golden 字节 diff 无法捕获 "codegen render_command_glue 丢掉一侧"——
//! regenerate 后 golden 同步更新、无漂移红；此语义检查则确保双侧恒在。generated 为 codegen 受控
//! 输出，故 Rule 1 用 substring（无字符串/注释盲区风险）。
//!
//! **Rule 2：裸 emit 出口封堵（`BareEmitExit`，`syn` AST 扫描）**
//! 扫生产 + 组合根 src（`crates` / `bins` / `adapters` / `assemblies` 的 member + leaf `journeys`），
//! **显式排除** `crate::src_scan::SCAN_EXCLUDED_SEGMENTS`（`eventexec` runtime 宿主 / `generated` 派生 /
//! `xtask` 工具自身 / `lints` 独立 workspace）。命中两类旁路 generated typed wrapper 的 runtime emit 调用：
//! - path 末两段 `command::emit_async` 的调用（含 `eventexec::command::emit_async` 完整路径）；
//! - 文件 `use ...::command::emit_async;` 后的裸 `emit_async(...)` 调用。
//!
//! 业务须经 `generated::command::<module>::emit_async` typed wrapper 进入，不得直调 runtime 收口。
//! 扫描根**比 `pdpallow` 宽**（含 `adapters`/`assemblies`/`journeys`——infra 与组合根亦不得裸 emit），
//! 故二者根集不共享（#1124 review F5）。
//!
//! **Rule 3：durable journal 出口封堵（`BareJournalExit`，`syn` AST 扫描）**
//! 生产 / 组合根 src 不得直接构造 `ReviewedCommandJournal::new` 或直接调用
//! `CommandJournalStore::record_command` / `record_command_with_business_write`；这些调用点只允许在
//! Postgres sanctioned seam `adapters/postgres/src/command_journal.rs` 内出现（测试夹具除外）。业务 durable
//! command 必须经 generated wrapper / domain-shaped postgres UoW 接线，不得从任意 crate 直接开 journal path。
//!
//! **Rule 4：impl-site 收口（`CommandImplOutsideRoot`，`syn` AST 扫描）**
//! `impl CommandEmit` / `impl CommandRegister`（generated seam 实现）**仅允许**在组合根 `bins/` /
//! `assemblies/`（sanctioned bridge / registrar 站点）。扫非组合根根集（`crates` / `adapters` + leaf
//! `journeys`），出现 such impl 即 finding（旁路唯一 sanctioned bridge；对齐 `DIPORT-IMPL-ALLOWLIST-01`）。
//! 当前 bridge 延迟落地 ⇒ 此扫描 vacuous-green，作 canary 守未来违例（anti-vacuity 见 `#[cfg(test)]`）。
//!
//! **载体说明（AI-robust）：** Rule 2/3/4 均 Medium（`syn` AST governance 扫描，CMD-FUNNEL-01 同款范式）。
//! Hard 不可达——generated `CommandEmit`/`CommandRegister` 是 **public** trait，无法 seal 阻止外部 crate
//! impl（同 `diport` DI port 之困，ADR-003 §4.2）；真 Hard 化（base crate sealed `CommandTopic` 阻
//! 裸 `Entry::new` 构造 command topic）见 follow-up issue（#1124 review F2 defer）。AST 级 ⇒ 字符串 /
//! 注释内同名文本天然不计，无 text-scan 盲区。
//!
//! **残留盲区（AI-robust 写明）：** `use eventexec::command::emit_async as alias; alias(...)`——重命名
//! 导入后裸调 `alias(...)` 不被 Rule 2 捕获（罕见；import 检测只认 `emit_async` 末名）。真 Hard 化（F2
//! sealed `CommandTopic`）覆盖此残留。
//!
//! 评级 Medium（接入 `cargo xtask verify`，no-compile meta 步）；synthetic red + anti-vacuity green 见
//! `#[cfg(test)]`：红向（缺侧 / 裸 emit 多形态 / 裸 journal / 越界 impl）+ 绿向（完整 module / 字符串注释不误报 /
//! 真工作区 0 finding）。

use std::path::{Path, PathBuf};

use anyhow::{Result, bail};
use syn::visit::Visit;

use crate::diagnostic::{self, GovernanceCheck, finding};
use crate::src_scan::{is_excluded, member_dirs, rs_files};

pub(crate) type Finding = diagnostic::Finding<Rule>;

/// 被违反的规则（供测试精确断言）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Rule {
    /// COMMAND-SYMMETRY-01：per-command module 缺 `pub async fn emit_async`（producer 收口缺失）。
    MissingEmitWrapper,
    /// COMMAND-SYMMETRY-01：per-command module 缺 `pub fn register_handler`（consumer 收口缺失）。
    MissingRegisterWrapper,
    /// COMMAND-SYMMETRY-01：per-command module 缺 `pub const CONTRACT_ID` 或 `pub const TOPIC`。
    MissingCommandConst,
    /// COMMAND-SYMMETRY-01：生产/组合根 src 内 `command::emit_async` 裸调（旁路 generated typed wrapper）。
    BareEmitExit,
    /// COMMAND-SYMMETRY-01：生产/组合根 src 内 durable journal 裸调（旁路 sanctioned wrapper/UoW）。
    BareJournalExit,
    /// COMMAND-IMPL-ALLOWLIST-01：非组合根 src 内 `impl CommandEmit`/`impl CommandRegister`（旁路 sanctioned bridge）。
    CommandImplOutsideRoot,
}

/// generated command 模块目录（相对 workspace root）。
const COMMAND_GEN_DIR: &str = "generated/src/command";

/// 裸 emit 禁用路径末段（concept needle，doc / summary 用；实际判定经 AST path 末两段匹配）。
const BARE_EMIT_NEEDLE: &str = "command::emit_async";

/// runtime emit 函数名（AST 末段匹配 + use-import leaf 名）。
const EMIT_FN: &str = "emit_async";
/// runtime emit 的所属 module 段名（path 末二段 `command::emit_async` / use 前缀含 `command`）。
const EMIT_MOD: &str = "command";
/// durable command journal DTO 构造器类型名。
const JOURNAL_DTO: &str = "ReviewedCommandJournal";
/// durable command journal store trait 名。
const JOURNAL_STORE: &str = "CommandJournalStore";
/// durable command journal DTO 构造器方法名。
const JOURNAL_NEW: &str = "new";
/// durable command public record function name.
const JOURNAL_RECORD: &str = "record_command";
/// Postgres-only co-tx helper method name.
const JOURNAL_RECORD_WITH_BUSINESS: &str = "record_command_with_business_write";
/// generated seam trait 名（Rule 3 impl-site 收口目标）。
const SEAM_TRAITS: &[&str] = &["CommandEmit", "CommandRegister"];

/// Rule 2/3 扫描的 member-root 顶层目录（其直接子目录是 member crate）。
/// `(top, impl_forbidden)`——`bins`/`assemblies` 是 sanctioned bridge/registrar impl 站点（Rule 3 不扫
/// impl），但仍扫 Rule 2 裸 emit（组合根业务接线也须经 wrapper，只有 bridge impl 体内合法调 runtime）。
const COMMAND_MEMBER_ROOTS: &[(&str, bool)] = &[
    ("crates", true),
    ("adapters", true),
    ("bins", false),
    ("assemblies", false),
];

/// leaf 组合根 crate（直接含 `src/`，非 root-of-members）。journeys = 集成验收宿主，其 src 接线亦须经
/// wrapper、不得 impl seam（生产 bridge 属 bins/assemblies；test 替身放 `tests/`、不在 `src/` 扫描内）。
const COMMAND_LEAF_CRATES: &[&str] = &["journeys"];

pub(crate) struct CommandSymmetry;

impl GovernanceCheck for CommandSymmetry {
    type Rule = Rule;
    fn name(&self) -> &'static str {
        "command-symmetry"
    }
    fn check(&self) -> Result<(String, Vec<Finding>)> {
        let root = crate::workspace_root()?;
        let (mod_scanned, mut findings) = scan_command_modules(&root)?;
        // anti-vacuity：至少扫到 1 个 per-command module（_seed_v1 是基准 canary）。
        if mod_scanned < 1 {
            bail!(
                "command-symmetry: 仅找到 {mod_scanned} 个 per-command module（排除 mod.rs），\
                 疑似 generated/src/command/ 结构异常；期望至少 1 个（_seed_v1.rs 基准 canary）"
            );
        }

        let (src_scanned, bare, impls) = scan_sources_ast(&root)?;
        // anti-vacuity：生产/组合根 src 应有相当数量的 .rs；过少说明结构异常或路径漂移。
        if src_scanned < 10 {
            bail!(
                "command-symmetry: 仅扫到 {src_scanned} 个生产/组合根 src 文件，\
                 疑似 crates/bins/adapters/journeys 结构异常；期望至少 10 个"
            );
        }
        findings.extend(bare);
        findings.extend(impls);

        let summary = format!(
            "{mod_scanned} 个 per-command module 双侧对称完整；\
             {src_scanned} 个生产/组合根 src 无裸 `{BARE_EMIT_NEEDLE}` / durable journal 出口、无越界 CommandEmit/CommandRegister impl"
        );
        Ok((summary, findings))
    }
}

// ---- Rule 1：per-command module 扫描（双侧对称 + codegen 完整性）----

/// 扫描 `generated/src/command/` 下每个 per-command `.rs`（排除 `mod.rs`），
/// 校验双侧对称 + 常量存在。返回 `(模块数, findings)`。
fn scan_command_modules(root: &Path) -> Result<(usize, Vec<Finding>)> {
    let cmd_dir = root.join(COMMAND_GEN_DIR);
    let mut findings = Vec::new();
    let mut scanned = 0usize;

    if !cmd_dir.is_dir() {
        // 目录不存在 → 0 模块，由调用方 canary 兜底。
        return Ok((0, findings));
    }

    let entries = std::fs::read_dir(&cmd_dir)
        .map_err(|e| anyhow::anyhow!("command-symmetry: 读目录 {} 失败: {e}", cmd_dir.display()))?;

    let mut paths: Vec<PathBuf> = entries
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| {
            p.extension().is_some_and(|x| x == "rs")
                && p.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n != "mod.rs")
        })
        .collect();
    paths.sort();

    for path in paths {
        scanned += 1;
        let content = std::fs::read_to_string(&path)
            .map_err(|e| anyhow::anyhow!("command-symmetry: 读 {} 失败: {e}", path.display()))?;
        let subj = path.display().to_string();
        for rule in scan_command_module(&content) {
            let detail = match rule {
                Rule::MissingEmitWrapper => {
                    "per-command module 缺 `pub async fn emit_async`（producer 收口缺失；codegen render_command_glue 可能丢掉 emit 侧）"
                }
                Rule::MissingRegisterWrapper => {
                    "per-command module 缺 `pub fn register_handler`（consumer 收口缺失；codegen render_command_glue 可能丢掉 register 侧）"
                }
                Rule::MissingCommandConst => {
                    "per-command module 缺 `pub const CONTRACT_ID` 或 `pub const TOPIC`（routing 常量缺失）"
                }
                Rule::BareEmitExit | Rule::CommandImplOutsideRoot => {
                    unreachable!("scan_command_module 只产出对称/常量规则")
                }
                Rule::BareJournalExit => {
                    unreachable!("scan_command_module 只产出对称/常量规则")
                }
            };
            findings.push(finding(rule, subj.clone(), detail));
        }
    }

    Ok((scanned, findings))
}

/// 纯函数：扫单个 per-command module 内容，返回违反的对称 / 常量规则。
/// 不扫 `BareEmitExit` / `CommandImplOutsideRoot`（那是 src 树 AST 扫描）。
pub(crate) fn scan_command_module(content: &str) -> Vec<Rule> {
    let mut rules = Vec::new();

    if !content.contains("pub async fn emit_async") {
        rules.push(Rule::MissingEmitWrapper);
    }
    if !content.contains("pub fn register_handler") {
        rules.push(Rule::MissingRegisterWrapper);
    }
    // 常量：两个同查，任一缺都报 MissingCommandConst。
    let has_contract_id = content.contains("pub const CONTRACT_ID");
    let has_topic = content.contains("pub const TOPIC");
    if !has_contract_id || !has_topic {
        rules.push(Rule::MissingCommandConst);
    }

    rules
}

// ---- Rule 2/3：src 树 AST 扫描（parse-once，跑两 visitor）----

/// 单次遍历 command 扫描根：每文件 `syn::parse_file` 一次，跑 Rule 2（裸 emit）+ Rule 3（越界 impl，
/// 仅 `impl_forbidden` 根）。返回 `(扫描文件数, bare-emit findings, impl-allowlist findings)`。
fn scan_sources_ast(root: &Path) -> Result<(usize, Vec<Finding>, Vec<Finding>)> {
    let mut scanned = 0usize;
    let mut bare = Vec::new();
    let mut impls = Vec::new();

    for (top, impl_forbidden) in COMMAND_MEMBER_ROOTS {
        for member in member_dirs(&root.join(top))? {
            if is_excluded(&member) {
                continue;
            }
            scan_src_dir(
                &member.join("src"),
                *impl_forbidden,
                &mut scanned,
                &mut bare,
                &mut impls,
            )?;
        }
    }
    for leaf in COMMAND_LEAF_CRATES {
        let dir = root.join(leaf);
        if !is_excluded(&dir) {
            // leaf 组合根 src 内禁 seam impl（生产 bridge 属 bins/assemblies）。
            scan_src_dir(&dir.join("src"), true, &mut scanned, &mut bare, &mut impls)?;
        }
    }

    Ok((scanned, bare, impls))
}

/// 扫一个 `src/` 目录下全部 `.rs`：parse → 跑 visitor。`impl_forbidden` 时附加 Rule 3 检查。
fn scan_src_dir(
    src: &Path,
    impl_forbidden: bool,
    scanned: &mut usize,
    bare: &mut Vec<Finding>,
    impls: &mut Vec<Finding>,
) -> Result<()> {
    if !src.is_dir() {
        return Ok(());
    }
    for path in rs_files(src)? {
        *scanned += 1;
        let content = std::fs::read_to_string(&path)
            .map_err(|e| anyhow::anyhow!("command-symmetry: 读 {} 失败: {e}", path.display()))?;
        let file = syn::parse_file(&content)
            .map_err(|e| anyhow::anyhow!("command-symmetry: 解析 {} 失败: {e}", path.display()))?;
        if file_bare_emit_count(&file) > 0 {
            bare.push(finding(
                Rule::BareEmitExit,
                path.display().to_string(),
                format!(
                    "src 内 `{BARE_EMIT_NEEDLE}` 裸调（含 use-import 后裸 `{EMIT_FN}`）——\
                     业务须经 `generated::command::<module>::emit_async` typed wrapper，不得直调 runtime emit 收口"
                ),
            ));
        }
        if !is_sanctioned_journal_call_site(&path) && file_bare_journal_count(&file) > 0 {
            bare.push(finding(
                Rule::BareJournalExit,
                path.display().to_string(),
                "src 内 durable command journal 裸调（ReviewedCommandJournal::new / \
                 CommandJournalStore::record_command / record_command_with_business_write）——\
                 业务须经 generated durable wrapper 或 sanctioned Postgres UoW seam",
            ));
        }
        if impl_forbidden && file_command_impl_count(&file) > 0 {
            impls.push(finding(
                Rule::CommandImplOutsideRoot,
                path.display().to_string(),
                "非组合根 src 内 `impl CommandEmit`/`impl CommandRegister`——seam 实现仅允许在组合根 \
                 bins/assemblies（sanctioned bridge/registrar）；旁路唯一 sanctioned bridge",
            ));
        }
    }
    Ok(())
}

fn is_sanctioned_journal_call_site(path: &Path) -> bool {
    path.ends_with("adapters/postgres/src/command_journal.rs")
        || path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.ends_with("_tests.rs") || name == "integration_tests.rs")
}

/// AST 访问者：检测旁路 generated wrapper 的 runtime command emit 调用。AST 级 ⇒ 字符串 / 注释内
/// 同名文本不计。命中：① path 末两段 `command::emit_async` 的调用；② 文件 `use ...command::emit_async;`
/// 后的裸 `emit_async(...)` 调用。
#[derive(Default)]
struct EmitImportVisitor {
    imported: bool,
}

impl<'ast> Visit<'ast> for EmitImportVisitor {
    fn visit_use_tree(&mut self, node: &'ast syn::UseTree) {
        if use_tree_imports_runtime_emit(node, false) {
            self.imported = true;
        }
        syn::visit::visit_use_tree(self, node);
    }
}

struct EmitCallVisitor {
    imported: bool,
    hits: usize,
}

impl<'ast> Visit<'ast> for EmitCallVisitor {
    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        if let syn::Expr::Path(p) = node.func.as_ref()
            && call_path_is_runtime_emit(&p.path, self.imported)
        {
            self.hits += 1;
        }
        syn::visit::visit_expr_call(self, node); // 继续下探嵌套调用
    }
}

/// `use` 树是否导入了 runtime `command::emit_async`（前缀含 `command` 段、leaf 名 `emit_async`）。
/// `seen_command` 记录前缀是否已出现 `command` 段。重命名导入（`as alias`）不认（残留盲区，见模块 doc）。
fn use_tree_imports_runtime_emit(tree: &syn::UseTree, seen_command: bool) -> bool {
    match tree {
        syn::UseTree::Path(p) => {
            use_tree_imports_runtime_emit(&p.tree, seen_command || p.ident == EMIT_MOD)
        }
        syn::UseTree::Name(n) => seen_command && n.ident == EMIT_FN,
        syn::UseTree::Group(g) => g
            .items
            .iter()
            .any(|t| use_tree_imports_runtime_emit(t, seen_command)),
        // Rename（`emit_async as alias`）/ Glob（`command::*`）不认——见模块 doc 残留盲区。
        syn::UseTree::Rename(_) | syn::UseTree::Glob(_) => false,
    }
}

/// 调用 path 是否 runtime emit：末两段 `command::emit_async`，或（文件已 import 时）裸单段 `emit_async`。
fn call_path_is_runtime_emit(path: &syn::Path, imported: bool) -> bool {
    let segs = &path.segments;
    let n = segs.len();
    if n >= 2 && segs[n - 1].ident == EMIT_FN && segs[n - 2].ident == EMIT_MOD {
        return true;
    }
    imported && n == 1 && segs[0].ident == EMIT_FN
}

/// 一个已解析文件里旁路 runtime emit 调用的个数（两阶段：先判 import，再计调用）。
fn file_bare_emit_count(file: &syn::File) -> usize {
    let mut imp = EmitImportVisitor::default();
    imp.visit_file(file);
    let mut calls = EmitCallVisitor {
        imported: imp.imported,
        hits: 0,
    };
    calls.visit_file(file);
    calls.hits
}

/// AST 访问者：检测 durable command journal 裸出口。AST 级 ⇒ 字符串 / 注释内同名文本不计。
#[derive(Default)]
struct JournalCallVisitor {
    hits: usize,
}

impl<'ast> Visit<'ast> for JournalCallVisitor {
    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        if let syn::Expr::Path(p) = node.func.as_ref()
            && call_path_is_runtime_journal(&p.path)
        {
            self.hits += 1;
        }
        syn::visit::visit_expr_call(self, node);
    }

    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        if node.method == JOURNAL_RECORD || node.method == JOURNAL_RECORD_WITH_BUSINESS {
            self.hits += 1;
        }
        syn::visit::visit_expr_method_call(self, node);
    }
}

fn call_path_is_runtime_journal(path: &syn::Path) -> bool {
    let segs = &path.segments;
    let n = segs.len();
    n >= 2
        && ((segs[n - 1].ident == JOURNAL_NEW && segs[n - 2].ident == JOURNAL_DTO)
            || (segs[n - 1].ident == JOURNAL_RECORD && segs[n - 2].ident == JOURNAL_STORE))
}

fn file_bare_journal_count(file: &syn::File) -> usize {
    let mut v = JournalCallVisitor::default();
    v.visit_file(file);
    v.hits
}

/// AST 访问者：统计 `impl CommandEmit`/`impl CommandRegister`（trait path 末段匹配 SEAM_TRAITS）。
/// 含 `impl super::CommandEmit` / `impl generated::command::CommandRegister`。
#[derive(Default)]
struct CommandImplVisitor {
    hits: usize,
}

impl<'ast> Visit<'ast> for CommandImplVisitor {
    fn visit_item_impl(&mut self, node: &'ast syn::ItemImpl) {
        if let Some((_, trait_path, _)) = &node.trait_
            && let Some(last) = trait_path.segments.last()
            && SEAM_TRAITS.iter().any(|t| last.ident == t)
        {
            self.hits += 1;
        }
        syn::visit::visit_item_impl(self, node);
    }
}

/// 一个已解析文件里 `impl CommandEmit`/`impl CommandRegister` 的个数。
fn file_command_impl_count(file: &syn::File) -> usize {
    let mut v = CommandImplVisitor::default();
    v.visit_file(file);
    v.hits
}

#[cfg(test)]
mod tests {
    //! INVARIANT: COMMAND-SYMMETRY-01 + COMMAND-IMPL-ALLOWLIST-01 { level = "Medium", exec = "verify", source = "code" }—— synthetic red + anti-vacuity green。

    use super::*;

    /// 测试辅助：parse + 计裸 emit 调用。
    fn bare_emit_count(src: &str) -> syn::Result<usize> {
        Ok(file_bare_emit_count(&syn::parse_file(src)?))
    }
    /// 测试辅助：parse + 计 durable journal 裸调用。
    fn bare_journal_count(src: &str) -> syn::Result<usize> {
        Ok(file_bare_journal_count(&syn::parse_file(src)?))
    }
    /// 测试辅助：parse + 计 seam impl。
    fn command_impl_count(src: &str) -> syn::Result<usize> {
        Ok(file_command_impl_count(&syn::parse_file(src)?))
    }

    // ---- Rule 1：双侧对称 + codegen 完整性 ----

    /// 红向：emit 缺失 → MissingEmitWrapper。
    #[test]
    fn missing_emit_wrapper_is_flagged() {
        let content = r#"
pub fn register_handler<Reg, H, Fut>(registrar: &mut Reg, handler: H) -> Reg::Output
where Reg: super::CommandRegister { todo!() }
pub const CONTRACT_ID: &str = "foo.do-bar";
pub const TOPIC: &str = "foo.commands.do-bar";
"#;
        let rules = scan_command_module(content);
        assert!(
            rules.contains(&Rule::MissingEmitWrapper),
            "缺 emit_async 应报 MissingEmitWrapper，实际 {rules:?}"
        );
        assert!(
            !rules.contains(&Rule::MissingRegisterWrapper),
            "register_handler 在场，不应报 MissingRegisterWrapper"
        );
    }

    /// 红向：register 缺失 → MissingRegisterWrapper。
    #[test]
    fn missing_register_wrapper_is_flagged() {
        let content = r#"
pub async fn emit_async<E: super::CommandEmit>(emitter: &E, request: FooRequest) -> Result<(), E::Error> { todo!() }
pub const CONTRACT_ID: &str = "foo.do-bar";
pub const TOPIC: &str = "foo.commands.do-bar";
"#;
        let rules = scan_command_module(content);
        assert!(
            rules.contains(&Rule::MissingRegisterWrapper),
            "缺 register_handler 应报 MissingRegisterWrapper，实际 {rules:?}"
        );
        assert!(
            !rules.contains(&Rule::MissingEmitWrapper),
            "emit_async 在场，不应报 MissingEmitWrapper"
        );
    }

    /// 红向：CONTRACT_ID 缺失 → MissingCommandConst。
    #[test]
    fn missing_contract_id_const_is_flagged() {
        let content = r#"
pub async fn emit_async<E: super::CommandEmit>(emitter: &E, request: FooRequest) -> Result<(), E::Error> { todo!() }
pub fn register_handler<Reg, H, Fut>(registrar: &mut Reg, handler: H) -> Reg::Output { todo!() }
pub const TOPIC: &str = "foo.commands.do-bar";
"#;
        let rules = scan_command_module(content);
        assert!(
            rules.contains(&Rule::MissingCommandConst),
            "缺 CONTRACT_ID 应报 MissingCommandConst，实际 {rules:?}"
        );
    }

    /// 红向：TOPIC 缺失 → MissingCommandConst。
    #[test]
    fn missing_topic_const_is_flagged() {
        let content = r#"
pub async fn emit_async<E: super::CommandEmit>(emitter: &E, request: FooRequest) -> Result<(), E::Error> { todo!() }
pub fn register_handler<Reg, H, Fut>(registrar: &mut Reg, handler: H) -> Reg::Output { todo!() }
pub const CONTRACT_ID: &str = "foo.do-bar";
"#;
        let rules = scan_command_module(content);
        assert!(
            rules.contains(&Rule::MissingCommandConst),
            "缺 TOPIC 应报 MissingCommandConst，实际 {rules:?}"
        );
    }

    /// 绿向：emit + register + 两常量均在 → 无 finding。
    #[test]
    fn complete_module_has_no_findings() {
        let content = r#"
pub async fn emit_async<E: super::CommandEmit>(emitter: &E, request: FooRequest) -> Result<(), E::Error> { todo!() }
pub fn register_handler<Reg, H, Fut>(registrar: &mut Reg, handler: H) -> Reg::Output { todo!() }
pub const CONTRACT_ID: &str = "foo.do-bar";
pub const TOPIC: &str = "foo.commands.do-bar";
"#;
        let rules = scan_command_module(content);
        assert!(
            rules.is_empty(),
            "完整 module 不应有 finding，实际 {rules:?}"
        );
    }

    /// 绿向：真实 _seed_v1 内容无 finding（确认 canary module 符合对称约束）。
    #[test]
    #[allow(clippy::expect_used)]
    fn seed_v1_module_passes_symmetry_check() {
        let root = crate::workspace_root().expect("workspace root");
        let path = root.join("generated/src/command/_seed_v1.rs");
        let content = std::fs::read_to_string(&path)
            .expect("读 _seed_v1.rs 失败（基准 canary module 应存在）");
        let rules = scan_command_module(&content);
        assert!(
            rules.is_empty(),
            "_seed_v1.rs 是 canary，应通过对称检查，实际 finding: {rules:?}"
        );
    }

    // ---- Rule 2：裸 emit 出口封堵（AST）----

    /// 红向：`eventexec::command::emit_async(...)` 完整路径调用 → 命中。
    #[test]
    fn bare_emit_full_path_is_flagged() -> syn::Result<()> {
        let src = "fn f() { let _ = eventexec::command::emit_async(id); }";
        assert_eq!(bare_emit_count(src)?, 1);
        Ok(())
    }

    /// 红向：`command::emit_async(...)` 部分路径调用 → 命中。
    #[test]
    fn bare_emit_partial_path_is_flagged() -> syn::Result<()> {
        let src = "fn f() { let _ = command::emit_async(a); }";
        assert_eq!(bare_emit_count(src)?, 1);
        Ok(())
    }

    /// 红向：直接构造 durable journal DTO → 命中。
    #[test]
    fn bare_journal_dto_new_is_flagged() -> syn::Result<()> {
        let src = "fn f() { let _ = eventexec::command::ReviewedCommandJournal::new(a, b, c, d, e, f, g, h); }";
        assert_eq!(bare_journal_count(src)?, 1);
        Ok(())
    }

    /// 红向：直接调 public journal store trait → 命中。
    #[test]
    fn bare_journal_store_record_is_flagged() -> syn::Result<()> {
        let src = "fn f() { let _ = CommandJournalStore::record_command(&store, cmd, summary); }";
        assert_eq!(bare_journal_count(src)?, 1);
        Ok(())
    }

    /// 红向：直接调 public journal store trait method-call → 命中。
    #[test]
    fn bare_journal_store_record_method_call_is_flagged() -> syn::Result<()> {
        let src = "fn f() { let _ = store.record_command(cmd, summary); }";
        assert_eq!(bare_journal_count(src)?, 1);
        Ok(())
    }

    /// 红向：直接调 Postgres co-tx helper → 命中。
    #[test]
    fn bare_journal_business_helper_is_flagged() -> syn::Result<()> {
        let src = "fn f() { let _ = store.record_command_with_business_write(cmd, op); }";
        assert_eq!(bare_journal_count(src)?, 1);
        Ok(())
    }

    /// 绿向：字符串中的 durable journal 名称不误报。
    #[test]
    fn bare_journal_string_literal_is_not_flagged() -> syn::Result<()> {
        let src = r#"fn f() { let _ = "ReviewedCommandJournal::new"; }"#;
        assert_eq!(bare_journal_count(src)?, 0);
        Ok(())
    }

    /// 绿向：sanctioned adapter seam / test fixtures are allowed call sites.
    #[test]
    fn journal_call_site_allowlist_is_narrow() {
        assert!(is_sanctioned_journal_call_site(Path::new(
            "/repo/adapters/postgres/src/command_journal.rs"
        )));
        assert!(is_sanctioned_journal_call_site(Path::new(
            "/repo/adapters/postgres/src/integration_tests.rs"
        )));
        assert!(!is_sanctioned_journal_call_site(Path::new(
            "/repo/crates/foo/src/lib.rs"
        )));
    }

    /// 红向（F4 修复点 #1 whitespace）：`command :: emit_async (..)` 含空格——AST 归一化，substring 旧扫描
    /// 漏判，AST 命中。
    #[test]
    fn bare_emit_whitespace_in_path_is_flagged() -> syn::Result<()> {
        let src = "fn f() { let _ = command :: emit_async ( a ) ; }";
        assert_eq!(bare_emit_count(src)?, 1);
        Ok(())
    }

    /// 红向（F4 修复点 #2 use-import）：`use ...command::emit_async;` 后裸 `emit_async(..)`——旧 substring
    /// 漏判，AST 经 import 追踪命中。
    #[test]
    fn bare_emit_via_use_import_is_flagged() -> syn::Result<()> {
        let src = "use eventexec::command::emit_async;\nfn f() { let _ = emit_async(a); }";
        assert_eq!(bare_emit_count(src)?, 1);
        Ok(())
    }

    /// 红向（grouped use）：`use eventexec::command::{emit_async, DispatchId};` 后裸调亦命中。
    #[test]
    fn bare_emit_via_grouped_use_is_flagged() -> syn::Result<()> {
        let src =
            "use eventexec::command::{emit_async, DispatchId};\nfn f() { let _ = emit_async(a); }";
        assert_eq!(bare_emit_count(src)?, 1);
        Ok(())
    }

    /// 绿向（AST 无 text 盲区）：字符串字面量 / 行注释 / 块注释内的 needle 均不计（substring 旧扫描会
    /// 误判字符串、靠 strip_comments 处理注释；AST 天然全免）。
    #[test]
    fn bare_emit_in_string_or_comment_not_flagged() -> syn::Result<()> {
        assert_eq!(
            bare_emit_count(r#"fn f() { let _s = "command::emit_async"; }"#)?,
            0
        );
        assert_eq!(
            bare_emit_count("// command::emit_async 示例\nfn f() {}")?,
            0
        );
        assert_eq!(
            bare_emit_count("/* command::emit_async 块注释 */\nfn f() {}")?,
            0
        );
        Ok(())
    }

    /// 绿向：未 import 时裸 `emit_async(..)`（无 command 路径、无 use）不计——避免对同名无关函数误报。
    #[test]
    fn bare_unimported_emit_async_not_flagged() -> syn::Result<()> {
        let src = "fn f() { let _ = emit_async(a); }";
        assert_eq!(bare_emit_count(src)?, 0);
        Ok(())
    }

    /// 绿向：`pub async fn emit_async(..)` 定义形（runtime 宿主声明）不计——只计调用表达式。
    #[test]
    fn emit_async_definition_not_flagged() -> syn::Result<()> {
        let src = "pub async fn emit_async(id: &str) { let _ = id; }";
        assert_eq!(bare_emit_count(src)?, 0);
        Ok(())
    }

    /// 残留盲区钉死：`use ...emit_async as alias; alias(..)` 重命名导入不被命中（见模块 doc）。
    /// 钉住当前行为，防静默改变；真 Hard 化（F2 sealed CommandTopic）覆盖此残留。
    #[test]
    fn bare_emit_rename_alias_is_residual_blind_spot() -> syn::Result<()> {
        let src = "use eventexec::command::emit_async as send;\nfn f() { let _ = send(a); }";
        assert_eq!(
            bare_emit_count(src)?,
            0,
            "rename-import alias 是已知残留盲区（非行为改变）"
        );
        Ok(())
    }

    // ---- Rule 3：impl-site 收口（AST）----

    /// 红向：`impl CommandEmit for X` 直接 trait 名 → 命中。
    #[test]
    fn impl_command_emit_is_flagged() -> syn::Result<()> {
        let src = "struct X; impl CommandEmit for X { type Error = (); }";
        assert_eq!(command_impl_count(src)?, 1);
        Ok(())
    }

    /// 红向：`impl super::CommandRegister for Y` 带路径前缀 → 末段匹配命中。
    #[test]
    fn impl_command_register_pathed_is_flagged() -> syn::Result<()> {
        let src =
            "struct Y; impl super::CommandRegister for Y { type Outcome = (); type Output = (); }";
        assert_eq!(command_impl_count(src)?, 1);
        Ok(())
    }

    /// 红向：`impl generated::command::CommandEmit for Z` 完整路径 → 命中。
    #[test]
    fn impl_command_emit_full_path_is_flagged() -> syn::Result<()> {
        let src = "struct Z; impl generated::command::CommandEmit for Z { type Error = (); }";
        assert_eq!(command_impl_count(src)?, 1);
        Ok(())
    }

    /// 绿向：impl 无关 trait → 不计；`trait CommandEmit {}` 定义形（非 impl）→ 不计。
    #[test]
    fn impl_unrelated_or_trait_def_not_flagged() -> syn::Result<()> {
        assert_eq!(
            command_impl_count("struct X; impl Clone for X { fn clone(&self) -> Self { X } }")?,
            0
        );
        assert_eq!(
            command_impl_count("pub trait CommandEmit { type Error; }")?,
            0
        );
        // inherent impl（无 trait）不计。
        assert_eq!(
            command_impl_count("struct X; impl X { fn f(&self) {} }")?,
            0
        );
        Ok(())
    }

    // ---- 真工作区绿向门（anti-vacuity）----

    /// 绿向工作区门：真实 crates/bins/adapters/assemblies/journeys src 无裸 emit 出口、无越界 seam impl
    /// （接 verify 机器门）。bridge 延迟落地 ⇒ Rule 3 当前 vacuous-green（canary）。
    #[test]
    #[allow(clippy::expect_used)]
    fn real_sources_pass_emit_and_impl_gates() {
        let root = crate::workspace_root().expect("workspace root");
        let (scanned, bare, impls) = scan_sources_ast(&root).expect("scan sources");
        assert!(
            scanned >= 10,
            "至少扫到 10 个生产/组合根 src 文件，实际 {scanned}"
        );
        assert!(
            bare.is_empty(),
            "src 不应有裸 `{BARE_EMIT_NEEDLE}` 出口: {bare:?}"
        );
        assert!(
            impls.is_empty(),
            "非组合根不应有 CommandEmit/CommandRegister impl: {impls:?}"
        );
    }

    /// 绿向工作区门：真实 generated/src/command/ per-command module 全部对称完整。
    #[test]
    #[allow(clippy::expect_used)]
    fn real_command_modules_pass_symmetry() {
        let root = crate::workspace_root().expect("workspace root");
        let (scanned, findings) = scan_command_modules(&root).expect("scan command modules");
        assert!(
            scanned >= 1,
            "至少找到 1 个 per-command module（_seed_v1 canary），实际 {scanned}"
        );
        assert!(
            findings.is_empty(),
            "per-command module 应全部对称完整: {findings:?}"
        );
    }
}
