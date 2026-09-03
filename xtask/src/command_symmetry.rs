//! `command-symmetry`：manifest policy-exclusive wrapper 与 command provider 集合治理门。
//!
//! INVARIANT: COMMAND-SYMMETRY-01 { level = "Medium", exec = "check", source = "code", facet = "manifest-policy" }——
//! 普通 generated command module 必须按 `CommandJournalPolicy` 只生成 `journal_async` 或
//! `emit_async`；fenced reconcile module 则只能生成 `fenced_reconcile_command`，不得恢复普通 producer
//! wrapper。两类 module 都须生成 `register_handler`、`CONTRACT_ID`、`TOPIC`、sealed `SPEC`。
//! INVARIANT: COMMAND-IMPL-ALLOWLIST-01 { level = "Medium", exec = "check", source = "code", facet = "provider-set", synthetic_red = "tests::rename_glob_and_type_alias_cannot_hide_provider_impl", anti_vacuity = "tests::exact_runtime_and_postgres_impls_are_allowed" }——
//! generated seam 只允许由 eventexec typed dispatcher 实现；provider store impl 与调用点使用 AST 集合
//! allowlist，解析 rename/glob import 与 type alias，避免别名绕过。
//!
//! command raw authoring 已由私有 reviewed DTO/type boundary Hard 化，因此本门不再维护 brittle 的
//! `emit_async`/DTO substring 扫描，只守类型系统无法表达的跨文件集合事实。

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use anyhow::{Result, bail};
use syn::visit::Visit;

use crate::diagnostic::{self, GovernanceCheck, finding};
use crate::src_scan::{member_dirs, rs_files};

pub(crate) type Finding = diagnostic::Finding<Rule>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Rule {
    MissingPolicyWrapper,
    ConflictingPolicyWrapper,
    MissingRegisterWrapper,
    MissingCommandConst,
    ProviderImplOutsideAllowlist,
    ProviderCallOutsideAllowlist,
    RuntimeBridgeDrift,
    MissingProviderImpl,
}

const COMMAND_GEN_DIR: &str = "generated/src/command";
const SOURCE_MEMBER_ROOTS: &[&str] = &["crates", "adapters"];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Policy {
    Required,
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Port {
    Emit,
    Journal,
    Register,
    DispatchStore,
    JournalStore,
}

impl Port {
    fn parse(name: &str) -> Option<Self> {
        match name {
            "CommandEmit" => Some(Self::Emit),
            "CommandJournal" => Some(Self::Journal),
            "CommandRegister" => Some(Self::Register),
            "CommandDispatchStore" => Some(Self::DispatchStore),
            "CommandJournalStore" => Some(Self::JournalStore),
            _ => None,
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::Emit => "CommandEmit",
            Self::Journal => "CommandJournal",
            Self::Register => "CommandRegister",
            Self::DispatchStore => "CommandDispatchStore",
            Self::JournalStore => "CommandJournalStore",
        }
    }
}

#[derive(Debug)]
struct ImplSite {
    path: PathBuf,
    port: Port,
    target: String,
}

#[derive(Debug)]
struct CallSite {
    path: PathBuf,
    port: Port,
}

#[derive(Debug, Default)]
struct ModuleAudit {
    scanned: usize,
    policies: BTreeSet<Policy>,
    findings: Vec<Finding>,
}

#[derive(Debug, Default)]
struct SourceAudit {
    scanned: usize,
    impls: Vec<ImplSite>,
    calls: Vec<CallSite>,
}

pub(crate) struct CommandSymmetry;

impl GovernanceCheck for CommandSymmetry {
    type Rule = Rule;

    fn name(&self) -> &'static str {
        "command-symmetry"
    }

    fn check(&self) -> Result<(String, Vec<Finding>)> {
        let root = crate::workspace_root()?;
        let modules = scan_command_modules(&root)?;
        if modules.scanned == 0 {
            bail!("command-symmetry: 未找到 per-command generated module");
        }

        let sources = scan_sources(&root)?;
        if sources.scanned < 10 {
            bail!(
                "command-symmetry: 生产源扫描数异常，仅 {} 个",
                sources.scanned
            );
        }

        let mut findings = modules.findings;
        findings.extend(validate_source_set(&sources, &modules.policies));
        Ok((
            format!(
                "{} 个 command module policy-exclusive；{} 个生产源的 typed dispatcher/provider 集合已校验",
                modules.scanned, sources.scanned
            ),
            findings,
        ))
    }
}

fn scan_command_modules(root: &Path) -> Result<ModuleAudit> {
    let mut audit = ModuleAudit::default();
    let dir = root.join(COMMAND_GEN_DIR);
    if !dir.is_dir() {
        return Ok(audit);
    }
    let mut paths = std::fs::read_dir(&dir)
        .map_err(|error| anyhow::anyhow!("读取 {}: {error}", dir.display()))?
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| {
            path.extension().is_some_and(|ext| ext == "rs")
                && path.file_name().and_then(|name| name.to_str()) != Some("mod.rs")
        })
        .collect::<Vec<_>>();
    paths.sort();

    for path in paths {
        audit.scanned += 1;
        let content = std::fs::read_to_string(&path)?;
        let (policy, rules) = scan_command_module(&content);
        if let Some(policy) = policy {
            audit.policies.insert(policy);
        }
        for rule in rules {
            audit.findings.push(finding(
                rule,
                path.display().to_string(),
                module_rule_detail(rule),
            ));
        }
    }
    Ok(audit)
}

fn scan_command_module(content: &str) -> (Option<Policy>, Vec<Rule>) {
    let required = content.contains("CommandJournalPolicy::Required");
    let none = content.contains("CommandJournalPolicy::None");
    let policy = match (required, none) {
        (true, false) => Some(Policy::Required),
        (false, true) => Some(Policy::None),
        _ => None,
    };
    let has_emit = content.contains("pub async fn emit_async");
    let has_journal = content.contains("pub async fn journal_async");
    let is_fenced = content.contains("impl super::FencedCommandSpec for");
    let has_fenced_wrapper = content.contains("pub fn fenced_reconcile_command");
    let mut rules = Vec::new();

    if is_fenced {
        if !has_fenced_wrapper {
            rules.push(Rule::MissingPolicyWrapper);
        }
        if has_emit || has_journal {
            rules.push(Rule::ConflictingPolicyWrapper);
        }
    } else {
        match policy {
            Some(Policy::Required) => {
                if !has_journal {
                    rules.push(Rule::MissingPolicyWrapper);
                }
                if has_emit {
                    rules.push(Rule::ConflictingPolicyWrapper);
                }
            }
            Some(Policy::None) => {
                if !has_emit {
                    rules.push(Rule::MissingPolicyWrapper);
                }
                if has_journal {
                    rules.push(Rule::ConflictingPolicyWrapper);
                }
            }
            None => rules.push(Rule::MissingPolicyWrapper),
        }
    }
    if !content.contains("pub fn register_handler") {
        rules.push(Rule::MissingRegisterWrapper);
    }
    if !content.contains("pub const CONTRACT_ID")
        || !content.contains("pub const TOPIC")
        || !content.contains("pub const SPEC")
    {
        rules.push(Rule::MissingCommandConst);
    }
    (policy, rules)
}

const fn module_rule_detail(rule: Rule) -> &'static str {
    match rule {
        Rule::MissingPolicyWrapper => {
            "manifest policy 对应 producer wrapper 缺失或 policy 不可判定"
        }
        Rule::ConflictingPolicyWrapper => {
            "同一 command module 同时暴露了 policy 禁止的 producer wrapper"
        }
        Rule::MissingRegisterWrapper => "command module 缺 register_handler",
        Rule::MissingCommandConst => "command module 缺 CONTRACT_ID/TOPIC/SPEC",
        _ => "非 module 规则",
    }
}

fn scan_sources(root: &Path) -> Result<SourceAudit> {
    let mut audit = SourceAudit::default();
    for top in SOURCE_MEMBER_ROOTS {
        for member in member_dirs(&root.join(top))? {
            scan_src_dir(&member.join("src"), &mut audit)?;
        }
    }
    Ok(audit)
}

fn scan_src_dir(dir: &Path, audit: &mut SourceAudit) -> Result<()> {
    for path in rs_files(dir)? {
        if is_test_source(&path) {
            continue;
        }
        audit.scanned += 1;
        let source = std::fs::read_to_string(&path)?;
        let file = syn::parse_file(&source)
            .map_err(|error| anyhow::anyhow!("解析 {}: {error}", path.display()))?;
        let resolver = Resolver::from_file(&file);
        let mut visitor = SourceVisitor::new(&resolver);
        visitor.visit_file(&file);
        audit
            .impls
            .extend(visitor.impls.into_iter().map(|(port, target)| ImplSite {
                path: path.clone(),
                port,
                target,
            }));
        audit
            .calls
            .extend(visitor.calls.into_iter().map(|port| CallSite {
                path: path.clone(),
                port,
            }));
    }
    Ok(())
}

fn is_test_source(path: &Path) -> bool {
    path.components()
        .any(|component| component.as_os_str() == "tests")
        || crate::src_scan::is_crate_internal_integration_test_source(path)
        || path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.ends_with("_tests.rs"))
}

fn validate_source_set(audit: &SourceAudit, policies: &BTreeSet<Policy>) -> Vec<Finding> {
    let mut findings = Vec::new();
    for site in &audit.impls {
        if !impl_allowed(site) {
            findings.push(finding(
                Rule::ProviderImplOutsideAllowlist,
                site.path.display().to_string(),
                format!(
                    "`impl {} for {}` 不在 typed dispatcher/provider allowlist",
                    site.port.label(),
                    site.target
                ),
            ));
        }
    }
    for site in &audit.calls {
        if !call_allowed(site) {
            findings.push(finding(
                Rule::ProviderCallOutsideAllowlist,
                site.path.display().to_string(),
                format!(
                    "{} provider call 只能位于 eventexec typed dispatcher",
                    site.port.label()
                ),
            ));
        }
    }

    for (port, target) in [
        (Port::Emit, "DirectCommandDispatcher"),
        (Port::Journal, "JournaledCommandDispatcher"),
    ] {
        let count = audit
            .impls
            .iter()
            .filter(|site| site.port == port && site.target == target && impl_allowed(site))
            .count();
        if count != 1 {
            findings.push(finding(
                Rule::RuntimeBridgeDrift,
                "crates/eventexec/src/command.rs",
                format!(
                    "期望唯一 `impl {} for {target}`，实际 {count}",
                    port.label()
                ),
            ));
        }
    }

    let required_ports = [
        (Policy::Required, Port::JournalStore),
        (Policy::None, Port::DispatchStore),
    ];
    for (policy, port) in required_ports {
        if policies.contains(&policy)
            && !audit
                .impls
                .iter()
                .any(|site| site.port == port && impl_allowed(site))
        {
            findings.push(finding(
                Rule::MissingProviderImpl,
                COMMAND_GEN_DIR,
                format!(
                    "存在 {policy:?} command，但缺 sanctioned {} provider impl",
                    port.label()
                ),
            ));
        }
    }

    for port in [Port::DispatchStore, Port::JournalStore] {
        let count = audit
            .calls
            .iter()
            .filter(|site| site.port == port && call_allowed(site))
            .count();
        if count == 0 {
            findings.push(finding(
                Rule::RuntimeBridgeDrift,
                "crates/eventexec/src/command.rs",
                format!("typed dispatcher 缺 {} 调用证据", port.label()),
            ));
        }
    }
    findings
}

fn impl_allowed(site: &ImplSite) -> bool {
    match site.port {
        Port::Emit => {
            site.target == "DirectCommandDispatcher"
                && site.path.ends_with("crates/eventexec/src/command.rs")
        }
        Port::Journal => {
            site.target == "JournaledCommandDispatcher"
                && site.path.ends_with("crates/eventexec/src/command.rs")
        }
        Port::Register => false,
        Port::JournalStore => {
            site.target == "PgCommandJournal"
                && site
                    .path
                    .ends_with("adapters/postgres/src/command_journal.rs")
        }
        Port::DispatchStore => {
            site.target == "PgCommandJournal"
                && site
                    .path
                    .ends_with("adapters/postgres/src/command_journal.rs")
        }
    }
}

fn call_allowed(site: &CallSite) -> bool {
    matches!(site.port, Port::DispatchStore | Port::JournalStore)
        && site.path.ends_with("crates/eventexec/src/command.rs")
}

#[derive(Debug, Default)]
struct Resolver {
    imports: BTreeMap<String, String>,
    aliases: BTreeMap<String, String>,
}

impl Resolver {
    fn from_file(file: &syn::File) -> Self {
        let mut resolver = Self::default();
        for item in &file.items {
            match item {
                syn::Item::Use(item) if !has_cfg_test(&item.attrs) => {
                    collect_use(&item.tree, &mut Vec::new(), &mut resolver.imports);
                }
                syn::Item::Type(item) if !has_cfg_test(&item.attrs) => {
                    if let syn::Type::Path(path) = item.ty.as_ref()
                        && let Some(last) = path.path.segments.last()
                    {
                        resolver
                            .aliases
                            .insert(item.ident.to_string(), last.ident.to_string());
                    }
                }
                _ => {}
            }
        }
        resolver
    }

    fn resolve_name(&self, name: &str) -> String {
        let mut current = name.to_string();
        for _ in 0..8 {
            let next = self
                .aliases
                .get(&current)
                .or_else(|| self.imports.get(&current));
            let Some(next) = next else { break };
            if *next == current {
                break;
            }
            current.clone_from(next);
        }
        current
    }

    fn resolve_port(&self, path: &syn::Path) -> Option<Port> {
        path.segments
            .last()
            .map(|segment| self.resolve_name(&segment.ident.to_string()))
            .and_then(|name| Port::parse(&name))
    }

    fn resolve_target(&self, ty: &syn::Type) -> String {
        let syn::Type::Path(path) = ty else {
            return "<non-path>".to_string();
        };
        path.path
            .segments
            .last()
            .map(|segment| self.resolve_name(&segment.ident.to_string()))
            .unwrap_or_else(|| "<empty>".to_string())
    }
}

fn collect_use(
    tree: &syn::UseTree,
    prefix: &mut Vec<String>,
    imports: &mut BTreeMap<String, String>,
) {
    match tree {
        syn::UseTree::Path(path) => {
            prefix.push(path.ident.to_string());
            collect_use(&path.tree, prefix, imports);
            prefix.pop();
        }
        syn::UseTree::Name(name) => {
            let canonical = name.ident.to_string();
            if Port::parse(&canonical).is_some() {
                imports.insert(canonical.clone(), canonical);
            }
        }
        syn::UseTree::Rename(rename) => {
            let canonical = rename.ident.to_string();
            if Port::parse(&canonical).is_some() {
                imports.insert(rename.rename.to_string(), canonical);
            }
        }
        syn::UseTree::Group(group) => {
            for item in &group.items {
                collect_use(item, prefix, imports);
            }
        }
        syn::UseTree::Glob(_) => {
            if prefix.last().is_some_and(|segment| segment == "command") {
                for port in [
                    Port::Emit,
                    Port::Journal,
                    Port::Register,
                    Port::DispatchStore,
                    Port::JournalStore,
                ] {
                    imports.insert(port.label().to_string(), port.label().to_string());
                }
            }
        }
    }
}

struct SourceVisitor<'a> {
    resolver: &'a Resolver,
    impls: Vec<(Port, String)>,
    calls: Vec<Port>,
}

impl<'a> SourceVisitor<'a> {
    const fn new(resolver: &'a Resolver) -> Self {
        Self {
            resolver,
            impls: Vec::new(),
            calls: Vec::new(),
        }
    }
}

impl<'ast> Visit<'ast> for SourceVisitor<'_> {
    fn visit_item_mod(&mut self, node: &'ast syn::ItemMod) {
        if !has_cfg_test(&node.attrs) {
            syn::visit::visit_item_mod(self, node);
        }
    }

    fn visit_item_impl(&mut self, node: &'ast syn::ItemImpl) {
        if has_cfg_test(&node.attrs) {
            return;
        }
        if let Some((_, trait_path, _)) = &node.trait_
            && let Some(port) = self.resolver.resolve_port(trait_path)
        {
            self.impls
                .push((port, self.resolver.resolve_target(&node.self_ty)));
        }
        syn::visit::visit_item_impl(self, node);
    }

    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        if let syn::Expr::Path(path) = node.func.as_ref()
            && path.path.segments.len() >= 2
            && let Some(method) = path.path.segments.last()
        {
            let owner_index = path.path.segments.len() - 2;
            let owner = self
                .resolver
                .resolve_name(&path.path.segments[owner_index].ident.to_string());
            let port = Port::parse(&owner);
            match (port, method.ident.to_string().as_str()) {
                (Some(Port::DispatchStore), "dispatch_command") => {
                    self.calls.push(Port::DispatchStore);
                }
                (Some(Port::JournalStore), "record_command") => {
                    self.calls.push(Port::JournalStore);
                }
                _ => {}
            }
        }
        syn::visit::visit_expr_call(self, node);
    }
}

fn has_cfg_test(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|attr| {
        if !attr.path().is_ident("cfg") {
            return false;
        }
        attr.parse_args_with(
            syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated,
        )
        .is_ok_and(|items| items.iter().any(meta_contains_test))
    })
}

fn meta_contains_test(meta: &syn::Meta) -> bool {
    match meta {
        syn::Meta::Path(path) => path.is_ident("test"),
        syn::Meta::List(list) => list
            .parse_args_with(
                syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated,
            )
            .is_ok_and(|items| items.iter().any(meta_contains_test)),
        syn::Meta::NameValue(_) => false,
    }
}

#[cfg(test)]
mod tests {
    //! INVARIANT: COMMAND-SYMMETRY-01 + COMMAND-IMPL-ALLOWLIST-01 { level = "Medium", exec = "check", source = "code", facet = "synthetic-proof" }—— synthetic red + anti-vacuity。

    use super::*;

    type SourceEvidence = (Vec<(Port, String)>, Vec<Port>);

    fn audit_source(source: &str) -> syn::Result<SourceEvidence> {
        let file = syn::parse_file(source)?;
        let resolver = Resolver::from_file(&file);
        let mut visitor = SourceVisitor::new(&resolver);
        visitor.visit_file(&file);
        Ok((visitor.impls, visitor.calls))
    }

    fn complete(policy: &str, wrapper: &str) -> String {
        format!(
            "pub const CONTRACT_ID: &str = \"x.do\";\npub const TOPIC: &str = \"x.commands.do\";\npub const SPEC: CommandSpec = CommandSpec::new(CommandJournalPolicy::{policy});\n{wrapper}\npub fn register_handler() {{}}"
        )
    }

    #[test]
    fn required_policy_requires_only_journal_wrapper() {
        let good = complete("Required", "pub async fn journal_async() {}");
        assert!(scan_command_module(&good).1.is_empty());

        let bad = complete(
            "Required",
            "pub async fn journal_async() {} pub async fn emit_async() {}",
        );
        assert!(
            scan_command_module(&bad)
                .1
                .contains(&Rule::ConflictingPolicyWrapper)
        );
    }

    #[test]
    fn none_policy_requires_only_emit_wrapper() {
        let good = complete("None", "pub async fn emit_async() {}");
        assert!(scan_command_module(&good).1.is_empty());
        let missing = complete("None", "");
        assert!(
            scan_command_module(&missing)
                .1
                .contains(&Rule::MissingPolicyWrapper)
        );
    }

    #[test]
    fn fenced_policy_requires_only_fenced_wrapper() {
        let good = complete(
            "Required",
            "impl super::FencedCommandSpec for Command {} pub fn fenced_reconcile_command() {}",
        );
        assert!(scan_command_module(&good).1.is_empty());

        let bypass = complete(
            "Required",
            "impl super::FencedCommandSpec for Command {} pub fn fenced_reconcile_command() {} pub async fn journal_async() {}",
        );
        assert!(
            scan_command_module(&bypass)
                .1
                .contains(&Rule::ConflictingPolicyWrapper)
        );
    }

    #[test]
    fn missing_register_or_spec_is_rejected() {
        let source = "pub const CONTRACT_ID: &str = \"x\"; pub const TOPIC: &str = \"x.commands.y\"; pub async fn journal_async() {} CommandJournalPolicy::Required";
        let rules = scan_command_module(source).1;
        assert!(rules.contains(&Rule::MissingRegisterWrapper));
        assert!(rules.contains(&Rule::MissingCommandConst));
    }

    #[test]
    fn rename_glob_and_type_alias_cannot_hide_provider_impl() -> syn::Result<()> {
        let (renamed, _) = audit_source(
            "use eventexec::command::CommandJournalStore as Store; struct Evil; impl Store for Evil {}",
        )?;
        assert_eq!(renamed, vec![(Port::JournalStore, "Evil".to_string())]);

        let (glob, _) = audit_source(
            "use eventexec::command::*; struct Evil; impl CommandDispatchStore for Evil {}",
        )?;
        assert_eq!(glob, vec![(Port::DispatchStore, "Evil".to_string())]);

        let (aliased, _) = audit_source(
            "type Store = eventexec::command::CommandJournalStore; struct Evil; impl Store for Evil {}",
        )?;
        assert_eq!(aliased, vec![(Port::JournalStore, "Evil".to_string())]);

        let (renamed_register, _) = audit_source(
            "use generated::command::CommandRegister as Registrar; struct Evil; impl Registrar for Evil {}",
        )?;
        assert_eq!(renamed_register, vec![(Port::Register, "Evil".to_string())]);

        let (glob_register, _) = audit_source(
            "use generated::command::*; struct Evil; impl CommandRegister for Evil {}",
        )?;
        assert_eq!(glob_register, vec![(Port::Register, "Evil".to_string())]);

        let (aliased_register, _) = audit_source(
            "type Registrar = generated::command::CommandRegister; struct Evil; impl Registrar for Evil {}",
        )?;
        assert_eq!(aliased_register, vec![(Port::Register, "Evil".to_string())]);

        Ok(())
    }

    #[test]
    fn alias_cannot_hide_associated_provider_call() -> syn::Result<()> {
        let (_, calls) = audit_source(
            "use eventexec::command::CommandJournalStore as Store; fn f(s: &S) { Store::record_command(s, a, b); }",
        )?;
        assert_eq!(calls, vec![Port::JournalStore]);
        Ok(())
    }

    #[test]
    fn unrelated_same_named_methods_are_not_provider_calls() -> syn::Result<()> {
        let (_, calls) = audit_source(
            "struct Business; impl Business { fn dispatch_command(&self) {} fn record_command(&self) {} } fn f(b: &Business) { b.dispatch_command(); b.record_command(); }",
        )?;
        assert!(calls.is_empty());
        Ok(())
    }

    #[test]
    fn cfg_test_provider_fakes_are_ignored() -> syn::Result<()> {
        let (impls, calls) = audit_source(
            "#[cfg(test)] mod tests { struct Fake; impl CommandJournalStore for Fake {} fn f(s: S) { s.record_command(a,b); } }",
        )?;
        assert!(impls.is_empty());
        assert!(calls.is_empty());
        Ok(())
    }

    #[test]
    fn exact_runtime_and_postgres_impls_are_allowed() {
        let runtime_emit = ImplSite {
            path: PathBuf::from("/repo/crates/eventexec/src/command.rs"),
            port: Port::Emit,
            target: "DirectCommandDispatcher".to_string(),
        };
        let runtime_journal = ImplSite {
            path: PathBuf::from("/repo/crates/eventexec/src/command.rs"),
            port: Port::Journal,
            target: "JournaledCommandDispatcher".to_string(),
        };
        let postgres = ImplSite {
            path: PathBuf::from("/repo/adapters/postgres/src/command_journal.rs"),
            port: Port::JournalStore,
            target: "PgCommandJournal".to_string(),
        };
        let postgres_direct = ImplSite {
            path: PathBuf::from("/repo/adapters/postgres/src/command_journal.rs"),
            port: Port::DispatchStore,
            target: "PgCommandJournal".to_string(),
        };
        assert!(impl_allowed(&runtime_emit));
        assert!(impl_allowed(&runtime_journal));
        assert!(impl_allowed(&postgres));
        assert!(impl_allowed(&postgres_direct));
    }

    #[test]
    fn command_register_is_a_governed_port() {
        assert!(Port::parse("CommandRegister").is_some());
    }

    #[test]
    fn command_register_impl_is_rejected() {
        let domain_register = ImplSite {
            path: PathBuf::from("/repo/crates/settings/src/application.rs"),
            port: Port::Register,
            target: "SettingsRegistrar".to_string(),
        };
        assert!(!impl_allowed(&domain_register));
    }

    #[test]
    fn is_test_source_integration_tests_support_without_tests_suffix() {
        assert!(is_test_source(Path::new(
            "adapters/postgres/src/integration_tests/support/helpers.rs"
        )));
        assert!(is_test_source(Path::new(
            "adapters/postgres/src/integration_tests.rs"
        )));
        assert!(!is_test_source(Path::new(
            "adapters/postgres/src/outbox.rs"
        )));
        assert!(!is_test_source(Path::new(
            "adapters/postgres/src/support/helpers.rs"
        )));
    }

    #[test]
    fn real_workspace_policy_and_provider_sets_pass() -> Result<()> {
        let root = crate::workspace_root()?;
        let modules = scan_command_modules(&root)?;
        assert!(modules.scanned >= 1);
        assert!(modules.findings.is_empty(), "{:?}", modules.findings);
        let sources = scan_sources(&root)?;
        let findings = validate_source_set(&sources, &modules.policies);
        assert!(findings.is_empty(), "{findings:?}");
        Ok(())
    }
}
