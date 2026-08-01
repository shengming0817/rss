//! `repo-scope-guard` —— tenant/row scoped repository port signature guard.
//!
//! INVARIANT: TENANCY-REPO-SCOPE-SIGNATURE-01 { level = "Medium", exec = "check", source = "code", synthetic_red = "tests::red_method_without_scope_handle_fails_even_when_other_method_has_handle + tests::red_same_named_projection_scope_from_wrong_module_is_rejected + tests::red_projection_scope_type_alias_is_rejected", anti_vacuity = "tests::green_tenant_repo_scope_param_is_allowed + tests::green_domain_projection_scope_handles_are_allowed" }——
//! tenant-scoped domain repository ports in `settings` / `identity` / `audit` must accept opaque
//! `TenantRepoScope` / `RowRepoScope` or domain-owned projection scope handles, not bare
//! `TenantId`, `RowVisibility`, or `RowScope`.
//! Admin / maintenance ports keep their own explicit entry points and are not normal repo scope
//! ports.
//!
//! This is a Medium drift backstop for the Hard Rust types in the domain crates: the type system
//! blocks external construction, while this scan keeps future port edits from reintroducing raw
//! scope parameters.

use anyhow::{Context, Result};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use syn::visit::Visit;

use crate::diagnostic::{self, GovernanceCheck, finding};

pub(crate) type Finding = diagnostic::Finding<Rule>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Rule {
    BareTenantScopeParam,
    BareRowScopeParam,
    ScopePortsAbsent,
    ScopeHandleParamsAbsent,
    MethodScopeHandleParamAbsent,
    InfraTenantScopeCallsiteNotAllowed,
    InfraTenantScopeCallsitesAbsent,
}

pub(crate) struct RepoScopeGuard;

impl GovernanceCheck for RepoScopeGuard {
    type Rule = Rule;

    fn name(&self) -> &'static str {
        "repo-scope-guard"
    }

    fn check(&self) -> Result<(String, Vec<Finding>)> {
        let root = crate::workspace_root()?;
        let files = load_port_files(&root)?;
        let postgres_files = load_postgres_files(&root)?;
        let (port_summary, mut findings) = scan_repo_scope(&files);
        let (infra_calls, mut infra_findings) = scan_infra_tenant_scope(&postgres_files);
        findings.append(&mut infra_findings);
        Ok((
            format!(
                "{port_summary}; {infra_calls} 个 infra_tenant_scope 调用点 allowlist 扫描通过"
            ),
            findings,
        ))
    }
}

fn load_port_files(root: &Path) -> Result<Vec<(String, String)>> {
    let paths = [
        "crates/settings/src/ports.rs",
        "crates/identity/src/ports.rs",
        "crates/audit/src/ports.rs",
    ];
    let mut files = Vec::new();
    for rel in paths {
        let path = root.join(rel);
        let content = std::fs::read_to_string(&path)
            .with_context(|| format!("读 {} 失败", path.display()))?;
        files.push((rel.to_string(), content));
    }
    Ok(files)
}

fn load_postgres_files(root: &Path) -> Result<Vec<(String, String)>> {
    let mut files = Vec::new();
    load_rs_files_under(root, Path::new("adapters/postgres/src"), &mut files)?;
    Ok(files)
}

fn load_rs_files_under(
    root: &Path,
    rel_dir: &Path,
    files: &mut Vec<(String, String)>,
) -> Result<()> {
    let dir = root.join(rel_dir);
    for entry in
        std::fs::read_dir(&dir).with_context(|| format!("读目录 {} 失败", dir.display()))?
    {
        let entry = entry.with_context(|| format!("读目录项 {} 失败", dir.display()))?;
        let path = entry.path();
        let file_name = entry.file_name();
        let child_rel = rel_dir.join(file_name);
        if path.is_dir() {
            load_rs_files_under(root, &child_rel, files)?;
            continue;
        }
        if path.extension().and_then(|ext| ext.to_str()) != Some("rs") {
            continue;
        }
        let content = std::fs::read_to_string(&path)
            .with_context(|| format!("读 {} 失败", path.display()))?;
        files.push((child_rel.to_string_lossy().into_owned(), content));
    }
    Ok(())
}

pub(crate) fn scan_repo_scope(files: &[(String, String)]) -> (String, Vec<Finding>) {
    let mut findings = Vec::new();
    let mut scoped_methods = 0usize;
    let mut handle_params = 0usize;

    for (rel, content) in files {
        let ast = match syn::parse_file(content) {
            Ok(ast) => ast,
            Err(err) => {
                findings.push(finding(
                    Rule::ScopePortsAbsent,
                    rel,
                    format!("ports.rs 解析失败，无法扫描 repo scope 签名: {err}"),
                ));
                continue;
            }
        };
        let scope_types = ScopeTypeResolver::from_file(&ast);

        for item in &ast.items {
            let syn::Item::Trait(trait_item) = item else {
                continue;
            };
            let trait_name = trait_item.ident.to_string();
            if !is_scoped_repo_trait(&trait_name) {
                continue;
            }
            scoped_methods += trait_item
                .items
                .iter()
                .filter(|item| matches!(item, syn::TraitItem::Fn(_)))
                .count();
            for item in &trait_item.items {
                let syn::TraitItem::Fn(method) = item else {
                    continue;
                };
                let method_subject = format!("{rel}::{trait_name}::{}", method.sig.ident);
                let mut method_handle_params = 0usize;
                for input in &method.sig.inputs {
                    let syn::FnArg::Typed(arg) = input else {
                        continue;
                    };
                    if is_scope_handle_param_type(&arg.ty, &scope_types) {
                        handle_params += 1;
                        method_handle_params += 1;
                    }
                    if contains_bare_tenant_type(&arg.ty) {
                        findings.push(finding(
                            Rule::BareTenantScopeParam,
                            &method_subject,
                            "normal tenant-scoped repo port must accept TenantRepoScope, not bare TenantId",
                        ));
                    }
                    if contains_bare_row_scope_type(&arg.ty) {
                        findings.push(finding(
                            Rule::BareRowScopeParam,
                            &method_subject,
                            "normal row-scoped repo port must accept RowRepoScope, not bare RowVisibility/RowScope",
                        ));
                    }
                }
                if method_handle_params == 0 {
                    findings.push(finding(
                        Rule::MethodScopeHandleParamAbsent,
                        &method_subject,
                        "normal repo-scope port method must accept an opaque tenant/row/projection scope handle",
                    ));
                }
            }
        }
    }

    if scoped_methods == 0 {
        findings.push(finding(
            Rule::ScopePortsAbsent,
            "domain ports",
            "未扫描到 repo/lifecycle/unit-of-work/store port 方法，guard 真空化",
        ));
    }
    if handle_params == 0 {
        findings.push(finding(
            Rule::ScopeHandleParamsAbsent,
            "domain ports",
            "未扫描到 opaque tenant/row/projection scope handle 参数，guard 真空化",
        ));
    }

    let summary = format!(
        "{scoped_methods} 个 repo-scope port 方法、{handle_params} 个 scope handle 参数扫描通过"
    );
    (summary, findings)
}

const INFRA_TENANT_SCOPE_ALLOWED_CALLS: &[(&str, &str)] = &[
    ("adapters/postgres/src/audit_repo.rs", "list_tenant"),
    ("adapters/postgres/src/audit_repo.rs", "verify_tenant"),
    (
        "adapters/postgres/src/consumer_tx.rs",
        "append_and_mark_done",
    ),
    (
        "adapters/postgres/src/consumer_tx.rs",
        "resolve_append_and_mark_done",
    ),
    ("adapters/postgres/src/consumer_tx.rs", "mark_done_only"),
    (
        "adapters/postgres/src/command_journal.rs",
        "record_command_with_business_write",
    ),
    (
        "adapters/postgres/src/command_journal.rs",
        "dispatch_command",
    ),
    ("adapters/postgres/src/dead_letter.rs", "write_dead_letter"),
    ("adapters/postgres/src/dlq.rs", "inspect_dead_letter"),
    ("adapters/postgres/src/dlq.rs", "inspect_outbox_dlx"),
    ("adapters/postgres/src/dlq.rs", "list_dead_letter"),
    ("adapters/postgres/src/dlq.rs", "list_outbox_dlx"),
    ("adapters/postgres/src/dlq.rs", "redrive_outbox"),
    ("adapters/postgres/src/dlq.rs", "resolve_expired_outbox"),
    ("adapters/postgres/src/dlq.rs", "replay_dead_letter"),
    ("adapters/postgres/src/emitter.rs", "write"),
    ("adapters/postgres/src/inbox.rs", "commit"),
    ("adapters/postgres/src/inbox.rs", "extend"),
    ("adapters/postgres/src/inbox.rs", "release"),
    ("adapters/postgres/src/inbox.rs", "sample_inbox_backlog"),
    ("adapters/postgres/src/inbox.rs", "try_claim"),
    (
        "adapters/postgres/src/outbox/settlement.rs",
        "execute_published",
    ),
    (
        "adapters/postgres/src/outbox/settlement.rs",
        "execute_retry",
    ),
    ("adapters/postgres/src/outbox/settlement.rs", "execute_dlx"),
    ("adapters/postgres/src/outbox_cdc.rs", "write"),
    (
        "adapters/postgres/src/revocation.rs",
        "verify_revocation_capability",
    ),
    ("adapters/postgres/src/saga.rs", "acquire_lease"),
    ("adapters/postgres/src/saga.rs", "append"),
    ("adapters/postgres/src/saga.rs", "cas_lease"),
    ("adapters/postgres/src/saga.rs", "commit_completed"),
    (
        "adapters/postgres/src/saga.rs",
        "commit_forward_completion_inner",
    ),
    ("adapters/postgres/src/saga.rs", "get"),
    ("adapters/postgres/src/saga.rs", "list_runnable"),
    ("adapters/postgres/src/saga.rs", "operator_status"),
    ("adapters/postgres/src/saga.rs", "retry_compensation"),
    ("adapters/postgres/src/saga.rs", "claim_repair"),
    ("adapters/postgres/src/saga.rs", "terminate"),
    ("adapters/postgres/src/saga.rs", "load_exact"),
    ("adapters/postgres/src/saga.rs", "mutate_journal"),
    ("adapters/postgres/src/saga.rs", "mutate_lifecycle"),
    ("adapters/postgres/src/saga.rs", "read"),
    (
        "adapters/postgres/src/saga.rs",
        "read_back_commit_unknown_completion",
    ),
    (
        "adapters/postgres/src/saga.rs",
        "read_back_commit_unknown_journal",
    ),
    ("adapters/postgres/src/saga.rs", "claim"),
    ("adapters/postgres/src/saga.rs", "claim_operator"),
    ("adapters/postgres/src/saga.rs", "recovery_snapshot"),
    ("adapters/postgres/src/saga.rs", "register"),
    ("adapters/postgres/src/saga.rs", "terminal_receipt"),
];

pub(crate) fn scan_infra_tenant_scope(files: &[(String, String)]) -> (usize, Vec<Finding>) {
    let mut findings = Vec::new();
    let mut calls = 0usize;

    for (rel, content) in files {
        let ast = match syn::parse_file(content) {
            Ok(ast) => ast,
            Err(err) => {
                findings.push(finding(
                    Rule::InfraTenantScopeCallsiteNotAllowed,
                    rel,
                    format!("postgres source parse failed; infra tenant scope callsites cannot be scanned: {err}"),
                ));
                continue;
            }
        };
        let mut visitor = InfraTenantScopeCallVisitor::default();
        visitor.visit_file(&ast);
        calls += visitor.calls.len();
        for call in visitor.calls {
            if !infra_tenant_scope_call_allowed(rel, &call) {
                findings.push(finding(
                    Rule::InfraTenantScopeCallsiteNotAllowed,
                    call_subject(rel, &call),
                    "infra tenant scope is limited to registered postgres-owned infra/admin funnels; normal repo adapters must accept domain TenantRepoScope",
                ));
            }
        }
    }

    if calls == 0 {
        findings.push(finding(
            Rule::InfraTenantScopeCallsitesAbsent,
            "adapters/postgres/src",
            "未扫描到 infra_tenant_scope 调用点，allowlist guard 真空化",
        ));
    }

    (calls, findings)
}

#[derive(Debug, Clone, Copy)]
enum InfraTenantScopeCallee {
    Helper,
    Constructor,
}

#[derive(Debug, Clone)]
struct InfraTenantScopeCall {
    callee: InfraTenantScopeCallee,
    function: Option<String>,
}

#[derive(Default)]
struct InfraTenantScopeCallVisitor {
    function_stack: Vec<String>,
    calls: Vec<InfraTenantScopeCall>,
}

impl<'ast> Visit<'ast> for InfraTenantScopeCallVisitor {
    fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
        self.with_function(item.sig.ident.to_string(), |this| {
            syn::visit::visit_item_fn(this, item);
        });
    }

    fn visit_impl_item_fn(&mut self, item: &'ast syn::ImplItemFn) {
        self.with_function(item.sig.ident.to_string(), |this| {
            syn::visit::visit_impl_item_fn(this, item);
        });
    }

    fn visit_expr_call(&mut self, expr: &'ast syn::ExprCall) {
        if let Some(callee) = infra_tenant_scope_callee(&expr.func) {
            self.calls.push(InfraTenantScopeCall {
                callee,
                function: self.function_stack.last().cloned(),
            });
        }
        syn::visit::visit_expr_call(self, expr);
    }
}

impl InfraTenantScopeCallVisitor {
    fn with_function(&mut self, function: String, f: impl FnOnce(&mut Self)) {
        self.function_stack.push(function);
        f(self);
        self.function_stack.pop();
    }
}

fn infra_tenant_scope_callee(expr: &syn::Expr) -> Option<InfraTenantScopeCallee> {
    let syn::Expr::Path(path) = expr else {
        return None;
    };
    let last = path.path.segments.last()?.ident.to_string();
    match last.as_str() {
        "infra_tenant_scope" => Some(InfraTenantScopeCallee::Helper),
        "from_infra_capability" => Some(InfraTenantScopeCallee::Constructor),
        _ => None,
    }
}

fn infra_tenant_scope_call_allowed(rel: &str, call: &InfraTenantScopeCall) -> bool {
    match call.callee {
        InfraTenantScopeCallee::Helper => call.function.as_deref().is_some_and(|function| {
            INFRA_TENANT_SCOPE_ALLOWED_CALLS
                .iter()
                .any(|(file, allowed_function)| *file == rel && *allowed_function == function)
        }),
        InfraTenantScopeCallee::Constructor => {
            rel == "adapters/postgres/src/cotx/mod.rs"
                && call.function.as_deref() == Some("infra_tenant_scope")
        }
    }
}

fn call_subject(rel: &str, call: &InfraTenantScopeCall) -> String {
    let callee = match call.callee {
        InfraTenantScopeCallee::Helper => "infra_tenant_scope",
        InfraTenantScopeCallee::Constructor => "InfraTenantScope::from_infra_capability",
    };
    match call.function.as_deref() {
        Some(function) => format!("{rel}::{function}::{callee}"),
        None => format!("{rel}::<module>::{callee}"),
    }
}

fn is_scoped_repo_trait(name: &str) -> bool {
    if name.contains("Admin") || name.contains("Maintenance") || name.contains("Retention") {
        return false;
    }
    name.ends_with("RepoLocal")
        || name.ends_with("LifecycleLocal")
        || name.ends_with("UnitOfWorkLocal")
        || name.ends_with("StoreLocal")
}

const CANONICAL_PROJECTION_SCOPE_PATHS: &[&[&str]] = &[
    &["crate", "projection", "SettingsProjectionReadScope"],
    &["crate", "projection", "SettingsProjectionApplyScope"],
];

#[derive(Default)]
struct ScopeTypeResolver {
    local_scope_structs: BTreeSet<String>,
    imported_origins: BTreeMap<String, Vec<String>>,
}

impl ScopeTypeResolver {
    fn from_file(file: &syn::File) -> Self {
        let mut resolver = Self::default();
        for item in &file.items {
            match item {
                syn::Item::Struct(item)
                    if matches!(
                        item.ident.to_string().as_str(),
                        "TenantRepoScope" | "RowRepoScope"
                    ) =>
                {
                    resolver.local_scope_structs.insert(item.ident.to_string());
                }
                syn::Item::Use(item) => {
                    collect_use_origins(
                        &item.tree,
                        &mut Vec::new(),
                        &mut resolver.imported_origins,
                    );
                }
                _ => {}
            }
        }
        resolver
    }

    fn is_canonical_scope_path(&self, path: &syn::Path) -> bool {
        if path.leading_colon.is_some()
            || path
                .segments
                .iter()
                .any(|segment| !matches!(segment.arguments, syn::PathArguments::None))
        {
            return false;
        }
        let mut parts = path
            .segments
            .iter()
            .map(|segment| segment.ident.to_string())
            .collect::<Vec<_>>();
        if parts.len() == 1 && self.local_scope_structs.contains(&parts[0]) {
            return true;
        }
        if let Some(origin) = parts
            .first()
            .and_then(|local| self.imported_origins.get(local))
        {
            let mut resolved = origin.clone();
            resolved.extend(parts.drain(1..));
            parts = resolved;
        }
        CANONICAL_PROJECTION_SCOPE_PATHS.iter().any(|canonical| {
            parts
                .iter()
                .map(String::as_str)
                .eq(canonical.iter().copied())
        })
    }
}

fn collect_use_origins(
    tree: &syn::UseTree,
    prefix: &mut Vec<String>,
    origins: &mut BTreeMap<String, Vec<String>>,
) {
    match tree {
        syn::UseTree::Path(path) => {
            prefix.push(path.ident.to_string());
            collect_use_origins(&path.tree, prefix, origins);
            prefix.pop();
        }
        syn::UseTree::Name(name) => {
            let mut origin = prefix.clone();
            origin.push(name.ident.to_string());
            origins.insert(name.ident.to_string(), origin);
        }
        syn::UseTree::Rename(rename) => {
            let mut origin = prefix.clone();
            origin.push(rename.ident.to_string());
            origins.insert(rename.rename.to_string(), origin);
        }
        syn::UseTree::Group(group) => {
            for tree in &group.items {
                collect_use_origins(tree, prefix, origins);
            }
        }
        syn::UseTree::Glob(_) => {}
    }
}

fn is_scope_handle_param_type(ty: &syn::Type, resolver: &ScopeTypeResolver) -> bool {
    match ty {
        syn::Type::Group(group) => is_scope_handle_param_type(&group.elem, resolver),
        syn::Type::Paren(paren) => is_scope_handle_param_type(&paren.elem, resolver),
        syn::Type::Path(path) => resolver.is_canonical_scope_path(&path.path),
        syn::Type::Reference(reference) => is_scope_handle_param_type(&reference.elem, resolver),
        _ => false,
    }
}

fn contains_bare_tenant_type(ty: &syn::Type) -> bool {
    type_contains_path(ty, |path| {
        path_last_matches(path, |name| name == "TenantId")
    })
}

fn contains_bare_row_scope_type(ty: &syn::Type) -> bool {
    type_contains_path(ty, |path| {
        path_last_matches(path, |name| {
            matches!(name, "RowVisibility" | "RowScope" | "ScopedTenant")
        })
    })
}

fn type_contains_path(ty: &syn::Type, predicate: impl Copy + Fn(&syn::Path) -> bool) -> bool {
    match ty {
        syn::Type::Array(array) => type_contains_path(&array.elem, predicate),
        syn::Type::BareFn(bare_fn) => {
            bare_fn
                .inputs
                .iter()
                .any(|input| type_contains_path(&input.ty, predicate))
                || match &bare_fn.output {
                    syn::ReturnType::Default => false,
                    syn::ReturnType::Type(_, ty) => type_contains_path(ty, predicate),
                }
        }
        syn::Type::Group(group) => type_contains_path(&group.elem, predicate),
        syn::Type::ImplTrait(impl_trait) => impl_trait
            .bounds
            .iter()
            .any(|bound| type_param_bound_contains_path(bound, predicate)),
        syn::Type::Paren(paren) => type_contains_path(&paren.elem, predicate),
        syn::Type::Path(path) => {
            predicate(&path.path)
                || path
                    .path
                    .segments
                    .iter()
                    .any(|segment| path_arguments_contain_type(&segment.arguments, predicate))
        }
        syn::Type::Ptr(ptr) => type_contains_path(&ptr.elem, predicate),
        syn::Type::Reference(reference) => type_contains_path(&reference.elem, predicate),
        syn::Type::Slice(slice) => type_contains_path(&slice.elem, predicate),
        syn::Type::TraitObject(trait_object) => trait_object
            .bounds
            .iter()
            .any(|bound| type_param_bound_contains_path(bound, predicate)),
        syn::Type::Tuple(tuple) => tuple
            .elems
            .iter()
            .any(|elem| type_contains_path(elem, predicate)),
        _ => false,
    }
}

fn path_arguments_contain_type(
    args: &syn::PathArguments,
    predicate: impl Copy + Fn(&syn::Path) -> bool,
) -> bool {
    match args {
        syn::PathArguments::None => false,
        syn::PathArguments::AngleBracketed(args) => args.args.iter().any(|arg| match arg {
            syn::GenericArgument::Type(ty) => type_contains_path(ty, predicate),
            syn::GenericArgument::AssocType(assoc) => type_contains_path(&assoc.ty, predicate),
            syn::GenericArgument::Constraint(constraint) => constraint
                .bounds
                .iter()
                .any(|bound| type_param_bound_contains_path(bound, predicate)),
            _ => false,
        }),
        syn::PathArguments::Parenthesized(args) => {
            args.inputs
                .iter()
                .any(|input| type_contains_path(input, predicate))
                || match &args.output {
                    syn::ReturnType::Default => false,
                    syn::ReturnType::Type(_, ty) => type_contains_path(ty, predicate),
                }
        }
    }
}

fn type_param_bound_contains_path(
    bound: &syn::TypeParamBound,
    predicate: impl Copy + Fn(&syn::Path) -> bool,
) -> bool {
    match bound {
        syn::TypeParamBound::Trait(trait_bound) => {
            predicate(&trait_bound.path)
                || trait_bound
                    .path
                    .segments
                    .iter()
                    .any(|segment| path_arguments_contain_type(&segment.arguments, predicate))
        }
        _ => false,
    }
}

fn path_last_matches(path: &syn::Path, predicate: impl Fn(&str) -> bool) -> bool {
    path.segments
        .last()
        .is_some_and(|segment| predicate(&segment.ident.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scan(src: &str) -> Vec<Finding> {
        scan_raw(&format!(
            r#"
            pub struct TenantRepoScope;
            pub struct RowRepoScope;
            use crate::projection::{{SettingsProjectionApplyScope, SettingsProjectionReadScope}};
            {src}
            "#
        ))
    }

    fn scan_raw(src: &str) -> Vec<Finding> {
        let files = vec![("crates/example/src/ports.rs".to_string(), src.to_string())];
        let (_, findings) = scan_repo_scope(&files);
        findings
    }

    #[test]
    fn green_tenant_repo_scope_param_is_allowed() {
        let findings = scan(
            r#"
            pub trait ConfigRepoLocal {
                async fn find(&self, scope: TenantRepoScope, key: SettingKey) -> Result<(), Error>;
            }
            "#,
        );
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn green_domain_projection_scope_handles_are_allowed() {
        let findings = scan_raw(
            r#"
            use crate::projection::{
                SettingsProjectionApplyScope as ApplyScope,
                SettingsProjectionReadScope as ReadScope,
            };

            pub trait SettingsProjectionReadRepoLocal {
                async fn find(&self, scope: ReadScope) -> Result<(), Error>;
            }
            pub trait SettingsProjectionApplyStoreLocal {
                async fn apply(&self, scope: ApplyScope) -> Result<(), Error>;
            }
            "#,
        );
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn red_same_named_projection_scope_from_wrong_module_is_rejected() {
        let findings = scan_raw(
            r#"
            use wrong_module::SettingsProjectionReadScope;

            pub trait SettingsProjectionReadRepoLocal {
                async fn find(&self, scope: SettingsProjectionReadScope) -> Result<(), Error>;
            }
            "#,
        );
        assert!(
            findings
                .iter()
                .any(|finding| finding.rule == Rule::MethodScopeHandleParamAbsent),
            "{findings:?}"
        );
    }

    #[test]
    fn red_projection_scope_type_alias_is_rejected() {
        let findings = scan_raw(
            r#"
            type SettingsProjectionApplyScope = TenantId;

            pub trait SettingsProjectionApplyStoreLocal {
                async fn apply(&self, scope: SettingsProjectionApplyScope) -> Result<(), Error>;
            }
            "#,
        );
        assert!(
            findings
                .iter()
                .any(|finding| finding.rule == Rule::MethodScopeHandleParamAbsent),
            "{findings:?}"
        );
    }

    #[test]
    fn red_bare_tenant_id_param_is_rejected() {
        let findings = scan(
            r#"
            pub trait ConfigRepoLocal {
                async fn find(&self, tenant: TenantId, key: SettingKey) -> Result<(), Error>;
            }
            "#,
        );
        assert!(
            findings
                .iter()
                .any(|finding| finding.rule == Rule::BareTenantScopeParam),
            "{findings:?}"
        );
    }

    #[test]
    fn red_wrapped_bare_tenant_id_param_is_rejected() {
        let findings = scan(
            r#"
            pub trait ConfigRepoLocal {
                async fn find(
                    &self,
                    scope: TenantRepoScope,
                    fallback: Option<vocab::TenantId>,
                ) -> Result<(), Error>;
            }
            "#,
        );
        assert!(
            findings
                .iter()
                .any(|finding| finding.rule == Rule::BareTenantScopeParam),
            "{findings:?}"
        );
        assert!(
            !findings
                .iter()
                .any(|finding| finding.rule == Rule::MethodScopeHandleParamAbsent),
            "{findings:?}"
        );
    }

    #[test]
    fn red_impl_trait_bare_tenant_id_param_is_rejected() {
        let findings = scan(
            r#"
            pub trait ConfigRepoLocal {
                async fn find(
                    &self,
                    scope: TenantRepoScope,
                    tenant: impl Into<TenantId>,
                ) -> Result<(), Error>;
            }
            "#,
        );
        assert!(
            findings
                .iter()
                .any(|finding| finding.rule == Rule::BareTenantScopeParam),
            "{findings:?}"
        );
    }

    #[test]
    fn red_trait_object_bare_row_visibility_param_is_rejected() {
        let findings = scan(
            r#"
            pub trait RowRepoLocal {
                async fn visible(
                    &self,
                    scope: TenantRepoScope,
                    visibility: Box<dyn Uses<RowVisibility>>,
                ) -> Result<(), Error>;
            }
            "#,
        );
        assert!(
            findings
                .iter()
                .any(|finding| finding.rule == Rule::BareRowScopeParam),
            "{findings:?}"
        );
    }

    #[test]
    fn red_bare_row_visibility_and_row_scope_are_rejected() {
        let findings = scan(
            r#"
            pub trait RowRepoLocal {
                async fn visible(&self, scope: TenantRepoScope, visibility: Vec<vocab::RowVisibility>) -> Result<(), Error>;
                async fn all(&self, scope: TenantRepoScope, row_scope: RowScope) -> Result<(), Error>;
            }
            "#,
        );
        let row_findings = findings
            .iter()
            .filter(|finding| finding.rule == Rule::BareRowScopeParam)
            .count();
        assert_eq!(row_findings, 2, "{findings:?}");
    }

    #[test]
    fn red_method_without_scope_handle_fails_even_when_other_method_has_handle() {
        let findings = scan(
            r#"
            pub trait ConfigRepoLocal {
                async fn find(&self, scope: TenantRepoScope, key: SettingKey) -> Result<(), Error>;
                async fn count(&self, key: SettingKey) -> Result<(), Error>;
            }
            "#,
        );
        assert!(
            findings
                .iter()
                .any(|finding| finding.rule == Rule::MethodScopeHandleParamAbsent
                    && finding.subject.contains("count")),
            "{findings:?}"
        );
        assert!(
            !findings
                .iter()
                .any(|finding| finding.rule == Rule::ScopeHandleParamsAbsent),
            "{findings:?}"
        );
    }

    #[test]
    fn green_admin_repo_bare_tenant_is_own_entry_point() {
        let findings = scan(
            r#"
            pub trait AuditAdminRepoLocal {
                async fn list_tenant(&self, tenant: TenantId) -> Result<(), Error>;
            }
            pub trait AuditReadRepoLocal {
                async fn list(&self, scope: TenantRepoScope) -> Result<(), Error>;
            }
            "#,
        );
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn anti_vacuity_no_repo_ports_fails() {
        let findings = scan("pub trait Clock { fn now(&self) -> SystemTime; }");
        assert!(
            findings
                .iter()
                .any(|finding| finding.rule == Rule::ScopePortsAbsent),
            "{findings:?}"
        );
    }

    #[test]
    fn anti_vacuity_no_handle_params_fails() {
        let findings = scan(
            r#"
            pub trait ConfigRepoLocal {
                async fn count(&self) -> Result<(), Error>;
            }
            "#,
        );
        assert!(
            findings
                .iter()
                .any(|finding| finding.rule == Rule::ScopeHandleParamsAbsent),
            "{findings:?}"
        );
    }

    #[test]
    fn green_infra_tenant_scope_allowed_for_infra_funnels() {
        let files = vec![
            (
                "adapters/postgres/src/outbox/settlement.rs".to_string(),
                "async fn execute_published() { infra_tenant_scope(tenant); }\n\
                 async fn execute_retry() { infra_tenant_scope(tenant); }\n\
                 async fn execute_dlx() { infra_tenant_scope(tenant); }"
                    .to_string(),
            ),
            (
                "adapters/postgres/src/command_journal.rs".to_string(),
                "async fn record_command_with_business_write() { infra_tenant_scope(tenant); }\n\
                 async fn dispatch_command() { infra_tenant_scope(tenant); }"
                    .to_string(),
            ),
            (
                "adapters/postgres/src/emitter.rs".to_string(),
                "async fn write() { infra_tenant_scope(tenant); }".to_string(),
            ),
            (
                "adapters/postgres/src/outbox_cdc.rs".to_string(),
                "async fn write() { infra_tenant_scope(tenant); }".to_string(),
            ),
            (
                "adapters/postgres/src/saga.rs".to_string(),
                "async fn list_runnable() { infra_tenant_scope(tenant); }\n\
                 async fn commit_completed() { infra_tenant_scope(tenant); }\n\
                 async fn load_exact() { infra_tenant_scope(tenant); }\n\
                 async fn operator_status() { infra_tenant_scope(tenant); }\n\
                 async fn retry_compensation() { infra_tenant_scope(tenant); }\n\
                 async fn claim_repair() { infra_tenant_scope(tenant); }\n\
                 async fn terminate() { infra_tenant_scope(tenant); }"
                    .to_string(),
            ),
            (
                "adapters/postgres/src/revocation.rs".to_string(),
                "async fn verify_revocation_capability() { infra_tenant_scope(tenant); }"
                    .to_string(),
            ),
        ];
        let (_, findings) = scan_infra_tenant_scope(&files);
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn red_infra_tenant_scope_rejected_in_unregistered_integration_test() {
        let files = vec![(
            "adapters/postgres/src/integration_tests.rs".to_string(),
            "async fn normal_repository_test() { infra_tenant_scope(tenant); }".to_string(),
        )];
        let (_, findings) = scan_infra_tenant_scope(&files);
        assert!(
            findings
                .iter()
                .any(|finding| finding.rule == Rule::InfraTenantScopeCallsiteNotAllowed),
            "{findings:?}"
        );
    }

    #[test]
    fn red_infra_tenant_scope_rejected_in_concern_owned_funnels() {
        let files = vec![
            (
                "adapters/postgres/src/reconcile.rs".to_string(),
                "async fn inspect_target() { infra_tenant_scope(tenant); }".to_string(),
            ),
            (
                "adapters/postgres/src/dlq.rs".to_string(),
                "async fn normal_repository_write() { infra_tenant_scope(tenant); }".to_string(),
            ),
        ];
        let (_, findings) = scan_infra_tenant_scope(&files);
        assert_eq!(
            findings
                .iter()
                .filter(|finding| finding.rule == Rule::InfraTenantScopeCallsiteNotAllowed)
                .count(),
            2,
            "{findings:?}"
        );
    }

    #[test]
    fn red_infra_tenant_scope_rejected_in_allowlisted_file_normal_repo_method() {
        let files = vec![(
            "adapters/postgres/src/outbox.rs".to_string(),
            r#"
            impl ConfigRepo for PgConfigRepo {
                async fn save(&self) {
                    infra_tenant_scope(tenant);
                }
            }
            "#
            .to_string(),
        )];
        let (_, findings) = scan_infra_tenant_scope(&files);
        assert!(
            findings
                .iter()
                .any(|finding| finding.rule == Rule::InfraTenantScopeCallsiteNotAllowed),
            "{findings:?}"
        );
    }

    #[test]
    fn red_infra_tenant_scope_rejected_in_normal_repo_adapter() {
        let files = vec![(
            "adapters/postgres/src/config_repo.rs".to_string(),
            "fn f() { infra_tenant_scope(tenant); }".to_string(),
        )];
        let (_, findings) = scan_infra_tenant_scope(&files);
        assert!(
            findings
                .iter()
                .any(|finding| finding.rule == Rule::InfraTenantScopeCallsiteNotAllowed),
            "{findings:?}"
        );
    }

    #[test]
    fn red_direct_infra_tenant_scope_constructor_rejected_outside_helper() {
        let files = vec![(
            "adapters/postgres/src/config_repo.rs".to_string(),
            "fn f() { InfraTenantScope::from_infra_capability(tenant); }".to_string(),
        )];
        let (_, findings) = scan_infra_tenant_scope(&files);
        assert!(
            findings
                .iter()
                .any(|finding| finding.rule == Rule::InfraTenantScopeCallsiteNotAllowed),
            "{findings:?}"
        );
    }

    #[test]
    fn anti_vacuity_comment_or_string_infra_tenant_scope_does_not_count_as_call() {
        let files = vec![(
            "adapters/postgres/src/outbox.rs".to_string(),
            r#"
            // infra_tenant_scope(tenant);
            fn f() {
                let _s = "infra_tenant_scope(tenant)";
            }
            "#
            .to_string(),
        )];
        let (_, findings) = scan_infra_tenant_scope(&files);
        assert!(
            findings
                .iter()
                .any(|finding| finding.rule == Rule::InfraTenantScopeCallsitesAbsent),
            "{findings:?}"
        );
    }

    #[test]
    fn anti_vacuity_no_infra_tenant_scope_calls_fails() {
        let files = vec![(
            "adapters/postgres/src/outbox.rs".to_string(),
            "fn f() { tenant_scope(tenant); }".to_string(),
        )];
        let (_, findings) = scan_infra_tenant_scope(&files);
        assert!(
            findings
                .iter()
                .any(|finding| finding.rule == Rule::InfraTenantScopeCallsitesAbsent),
            "{findings:?}"
        );
    }
}
