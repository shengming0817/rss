//! DLX archive-before-purge 单漏斗守卫。
//!
//! INVARIANT: DLX-LIFECYCLE-FUNNEL-01 { level = "Medium", exec = "verify", source = "code", synthetic_red = "tests::synthetic_red_rejects_every_bypass_class", anti_vacuity = "tests::canonical_lifecycle_sources_are_accepted" } ——
//! hot DLX 只能经 typed lifecycle repository 与不可删除的 verified WORM provider 归档后清理；旧
//! retention/env/decoder 与 raw DELETE 不得回流，runtime 必须显式注入独立 PG/S3/Vault provider。

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result};
use quote::ToTokens as _;
use syn::visit::Visit as _;

use crate::diagnostic::{Finding, GovernanceCheck, finding};
use crate::phase_helper_expand::{
    PhaseExpandError, inherent_entry_method, private_production_methods, production_inherent_impl,
    self_or_owner_call, self_receiver_helper_call,
};
use crate::workspace_root;

const LIFECYCLE_REPOSITORY: &str = "adapters/postgres/src/dlx_lifecycle.rs";
const ARCHIVE_PROVIDER: &str = "adapters/s3/src/dlx_archive.rs";
const CUTOVER_MIGRATION: &str = "adapters/postgres/migrations/0062_prepare_dead_letter_cutover.sql";
const LIFECYCLE_MIGRATION: &str = "adapters/postgres/migrations/0063_dead_letter_lifecycle.sql";
const RUNTIME_INFRA_PHASE: &str = "assemblies/runtime/src/phase/infra.rs";
const RUNTIME_INFRA_FLOW: &str = "DLX preflight→migration→ACL→runtime deps→lifecycle wire";
const RUNTIME_INFRA_REQUIRED: &[&str] = &[
    "after_required_preflight(",
    "PgDlxLifecycleRuntime::preflight_identities(&dlx_archiver_pg_config,&dlx_verifier_pg_config,&dlx_purger_pg_config,)",
    "archive_store.verify()",
    "verify_dlx_vault_key_capability(&hot_vault_provider",
    "verify_dlx_vault_key_capability(&archive_vault_provider",
    "Ok(PhaseADlxVerified{dlx_archiver_pg_config,dlx_verifier_pg_config,dlx_purger_pg_config,archive_store,archive_vault_provider,})",
    "PgRuntimeDeps::setup_with_audit_admin_config(",
    "PgDlxLifecycleRuntime::setup(&dlx_archiver_pg_config,&dlx_verifier_pg_config,&dlx_purger_pg_config,hot_payload_protector,)",
    "DlxLifecycleRuntimeDeps::new(dlx_pg_owner,archive_store,archive_vault_provider,archive_key",
    "wire_dlx_lifecycle(dlx_lifecycle,dlx_worker)",
];

pub(crate) const FIXED_FUNCTIONS: &[&str] = &[
    "rss_dlx_claim_archive_candidates",
    "rss_dlx_settle_archive_retry",
    "rss_dlx_quarantine_archive_candidate",
    "rss_dlx_record_archive_receipt",
    "rss_dlx_purge_verified",
    "rss_dlx_reconcile_expired_receipts",
    "rss_dlx_delete_missing_archive_receipt",
    "rss_dlx_archive_backlog",
];

const REQUIRED_RUNTIME_SOURCES: &[&str] = &[
    "crates/diport/src/dlx_lifecycle.rs",
    "assemblies/runtime/src/infra/pg.rs",
    "assemblies/runtime/src/infra/s3.rs",
    "assemblies/runtime/src/event_transport.rs",
    "assemblies/runtime/assembly.toml",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Rule {
    RetiredSurface,
    RawDeadLetterDelete,
    LifecycleFunctionEscape,
    DeletableArchiveProvider,
    MissingRuntimeProvider,
}

pub(crate) struct DlxLifecycleFunnel;

impl GovernanceCheck for DlxLifecycleFunnel {
    type Rule = Rule;

    fn name(&self) -> &'static str {
        "dlx-lifecycle-funnel"
    }

    fn check(&self) -> Result<(String, Vec<Finding<Self::Rule>>)> {
        let root = workspace_root()?;
        let findings = scan_workspace(&root)?;
        Ok((
            "DLX 仅经 verified WORM archive-before-purge 单漏斗，独立 runtime providers 完整"
                .to_string(),
            findings,
        ))
    }
}

fn scan_workspace(root: &Path) -> Result<Vec<Finding<Rule>>> {
    let mut findings = Vec::new();
    for rel in collect_production_sources(root)? {
        let content = std::fs::read_to_string(root.join(&rel))
            .with_context(|| format!("dlx-lifecycle-funnel: read {}", rel.display()))?;
        findings.extend(scan_content(&rel, &content));
    }
    for rel in REQUIRED_RUNTIME_SOURCES {
        let path = root.join(rel);
        match std::fs::read_to_string(&path) {
            Ok(content) => {
                findings.extend(required_runtime_source_findings(Path::new(rel), &content));
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => findings.push(finding(
                Rule::MissingRuntimeProvider,
                (*rel).to_string(),
                "DLX lifecycle 必需 runtime/provider 载体缺失".to_string(),
            )),
            Err(err) => {
                return Err(err).with_context(|| format!("dlx-lifecycle-funnel: read {rel}"));
            }
        }
    }
    findings.extend(runtime_phase_funnel_findings(root)?);
    Ok(findings)
}

fn runtime_phase_funnel_findings(root: &Path) -> Result<Vec<Finding<Rule>>> {
    let owners = [(
        RUNTIME_INFRA_PHASE,
        "ProvidersBuilt",
        "build_infra",
        RUNTIME_INFRA_REQUIRED,
        RUNTIME_INFRA_FLOW,
    )];
    let mut findings = Vec::new();
    for (path, owner, method, required, flow) in owners {
        match std::fs::read_to_string(root.join(path)) {
            Ok(source) => findings.extend(runtime_phase_owner_findings(
                Path::new(path),
                &source,
                owner,
                method,
                required,
                flow,
            )),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => findings.push(finding(
                Rule::MissingRuntimeProvider,
                path.to_owned(),
                format!("生产 phase owner `{owner}::{method}` 载体缺失"),
            )),
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("dlx-lifecycle-funnel: read phase owner {path}"));
            }
        }
    }
    Ok(findings)
}

fn runtime_phase_owner_findings(
    path: &Path,
    source: &str,
    owner: &str,
    method: &str,
    required: &[&str],
    flow: &str,
) -> Vec<Finding<Rule>> {
    let file = match syn::parse_file(source) {
        Ok(file) => file,
        Err(error) => {
            return vec![finding(
                Rule::MissingRuntimeProvider,
                path.display().to_string(),
                format!("无法解析生产 phase owner `{owner}::{method}`: {error}"),
            )];
        }
    };
    let implementation = match production_inherent_impl(&file, owner) {
        Ok(implementation) => implementation,
        Err(error) => {
            return vec![finding(
                Rule::MissingRuntimeProvider,
                path.display().to_string(),
                production_phase_helper_expansion_failed(owner, method, &error),
            )];
        }
    };
    let methods = match private_production_methods(implementation) {
        Ok(methods) => methods,
        Err(error) => {
            return vec![finding(
                Rule::MissingRuntimeProvider,
                path.display().to_string(),
                production_phase_helper_expansion_failed(owner, method, &error),
            )];
        }
    };
    let selected_method = match inherent_entry_method(implementation, method) {
        Ok(selected) if selected.sig.asyncness.is_some() => selected,
        Ok(_) => {
            return vec![finding(
                Rule::MissingRuntimeProvider,
                path.display().to_string(),
                format!(
                    "生产 async phase owner `{owner}::{method}` 必须且只能存在一个；实际非 async"
                ),
            )];
        }
        Err(error) => {
            return vec![finding(
                Rule::MissingRuntimeProvider,
                path.display().to_string(),
                production_phase_helper_expansion_failed(owner, method, &error),
            )];
        }
    };
    let mut evidence = RuntimePhaseEvidence::new(required);
    let mut stack = Vec::new();
    let mut error = None;
    {
        let mut expanding = ExpandingRuntimePhaseEvidence {
            inner: &mut evidence,
            owner,
            methods: &methods,
            stack: &mut stack,
            error: &mut error,
        };
        expanding.visit_block(&selected_method.block);
    }
    if let Some(error) = error {
        return vec![finding(
            Rule::MissingRuntimeProvider,
            path.display().to_string(),
            production_phase_helper_expansion_failed(owner, method, &error),
        )];
    }
    let expected = (0..required.len()).collect::<Vec<_>>();
    if evidence.observed != expected {
        let first_missing = expected
            .iter()
            .find(|index| !evidence.observed.contains(index))
            .and_then(|index| required.get(*index))
            .copied()
            .unwrap_or("<duplicate or reordered evidence>");
        return vec![finding(
            Rule::MissingRuntimeProvider,
            path.display().to_string(),
            format!(
                "phase owner `{owner}::{method}` {flow} 数据流缺失、重复或乱序: `{first_missing}`"
            ),
        )];
    }
    Vec::new()
}

struct RuntimePhaseEvidence<'a> {
    required: &'a [&'a str],
    observed: Vec<usize>,
}

impl<'a> RuntimePhaseEvidence<'a> {
    fn new(required: &'a [&'a str]) -> Self {
        Self {
            required,
            observed: Vec::new(),
        }
    }

    fn record(&mut self, expression: &impl quote::ToTokens) {
        let code = expression
            .to_token_stream()
            .to_string()
            .chars()
            .filter(|character| !character.is_whitespace())
            .collect::<String>();
        let canonical = code
            .strip_prefix("crate::event_transport::")
            .unwrap_or(&code);
        for (index, expected) in self.required.iter().enumerate() {
            if canonical.starts_with(expected) {
                self.observed.push(index);
            }
        }
    }
}

fn production_phase_helper_expansion_failed(
    owner: &str,
    method: &str,
    error: &impl std::fmt::Display,
) -> String {
    format!("生产 async phase owner `{owner}::{method}` helper expansion failed: {error}")
}

struct ExpandingRuntimePhaseEvidence<'a, 'm, 'ast> {
    inner: &'a mut RuntimePhaseEvidence<'m>,
    owner: &'a str,
    methods: &'a BTreeMap<String, &'ast syn::ImplItemFn>,
    stack: &'a mut Vec<String>,
    error: &'a mut Option<PhaseExpandError>,
}

impl<'a, 'm, 'ast> ExpandingRuntimePhaseEvidence<'a, 'm, 'ast> {
    fn expand_helper(
        &mut self,
        helper: &'ast syn::ImplItemFn,
        args: &'ast syn::punctuated::Punctuated<syn::Expr, syn::token::Comma>,
    ) -> bool {
        let name = helper.sig.ident.to_string();
        if self.stack.iter().any(|frame| frame == &name) {
            *self.error = Some(PhaseExpandError::Cycle(name));
            return false;
        }
        for arg in args {
            self.visit_expr(arg);
            if self.error.is_some() {
                return false;
            }
        }
        self.stack.push(name);
        self.visit_block(&helper.block);
        self.stack.pop();
        self.error.is_none()
    }
}

impl<'ast> syn::visit::Visit<'ast> for ExpandingRuntimePhaseEvidence<'_, '_, 'ast> {
    fn visit_block(&mut self, block: &'ast syn::Block) {
        for statement in &block.stmts {
            if dlx_statement_has_test_attr(statement) {
                continue;
            }
            self.visit_stmt(statement);
            if self.error.is_some() {
                return;
            }
            if matches!(
                statement,
                syn::Stmt::Expr(
                    syn::Expr::Return(_) | syn::Expr::Break(_) | syn::Expr::Continue(_),
                    _
                )
            ) {
                break;
            }
        }
    }

    fn visit_expr_block(&mut self, block: &'ast syn::ExprBlock) {
        if !has_test_attribute(&block.attrs) {
            syn::visit::visit_expr_block(self, block);
        }
    }

    fn visit_expr_if(&mut self, if_: &'ast syn::ExprIf) {
        if has_test_attribute(&if_.attrs) {
            return;
        }
        let condition = if_.cond.to_token_stream().to_string();
        if condition.trim() == "false"
            || condition
                .chars()
                .filter(|character| !character.is_whitespace())
                .collect::<String>()
                == "cfg!(test)"
        {
            if let Some((_, alternative)) = &if_.else_branch {
                self.visit_expr(alternative);
            }
            return;
        }
        syn::visit::visit_expr_if(self, if_);
    }

    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if self.error.is_some() {
            return;
        }
        if let Some((helper, args)) = self_or_owner_call(call, self.owner, self.methods) {
            let _ = self.expand_helper(helper, args);
            return;
        }
        self.inner.record(call);
        syn::visit::visit_expr_call(self, call);
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        if self.error.is_some() {
            return;
        }
        if let Some((helper, args)) = self_receiver_helper_call(call, self.methods) {
            let _ = self.expand_helper(helper, args);
            return;
        }
        if call.method == "verify" {
            self.inner.record(call);
        }
        syn::visit::visit_expr_method_call(self, call);
    }
}

fn dlx_statement_has_test_attr(statement: &syn::Stmt) -> bool {
    match statement {
        syn::Stmt::Local(local) => has_test_attribute(&local.attrs),
        syn::Stmt::Item(item) => match item {
            syn::Item::Fn(item) => has_test_attribute(&item.attrs),
            syn::Item::Impl(item) => has_test_attribute(&item.attrs),
            syn::Item::Macro(item) => has_test_attribute(&item.attrs),
            syn::Item::Mod(item) => has_test_attribute(&item.attrs),
            _ => false,
        },
        syn::Stmt::Expr(syn::Expr::Block(block), _) => has_test_attribute(&block.attrs),
        syn::Stmt::Expr(syn::Expr::If(if_), _) => has_test_attribute(&if_.attrs),
        syn::Stmt::Expr(syn::Expr::Macro(macro_), _) => has_test_attribute(&macro_.attrs),
        syn::Stmt::Macro(statement) => has_test_attribute(&statement.attrs),
        syn::Stmt::Expr(_, _) => false,
    }
}

fn has_test_attribute(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|attr| {
        attr.path().is_ident("test")
            || (attr.path().is_ident("cfg")
                && attr.meta.to_token_stream().to_string().contains("test"))
    })
}

fn collect_production_sources(root: &Path) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    let manifest: toml::Value = std::fs::read_to_string(root.join("Cargo.toml"))
        .context("dlx-lifecycle-funnel: read workspace Cargo.toml")?
        .parse()
        .context("dlx-lifecycle-funnel: parse workspace Cargo.toml")?;
    let members = manifest
        .get("workspace")
        .and_then(|workspace| workspace.get("members"))
        .and_then(toml::Value::as_array)
        .context("dlx-lifecycle-funnel: workspace.members missing")?;
    for production_root in members.iter().filter_map(toml::Value::as_str) {
        // The guard implementation contains its own synthetic-red tokens; all shipped members,
        // including bins and composition roots, remain discovered from the workspace manifest.
        if production_root == "xtask" {
            continue;
        }
        let directory = root.join(production_root);
        if directory.exists() {
            collect_sources_recursive(root, &directory, &mut files)?;
        }
    }
    let rules = root.join("docs/rules");
    if rules.exists() {
        collect_sources_recursive(root, &rules, &mut files)?;
    }
    files.sort();
    files.dedup();
    Ok(files)
}

fn collect_sources_recursive(
    root: &Path,
    directory: &Path,
    files: &mut Vec<PathBuf>,
) -> Result<()> {
    let entries = std::fs::read_dir(directory)
        .with_context(|| format!("dlx-lifecycle-funnel: walk {}", directory.display()))?;
    for entry in entries {
        let path = entry?.path();
        if path.is_dir() {
            collect_sources_recursive(root, &path, files)?;
            continue;
        }
        let rel = path
            .strip_prefix(root)
            .with_context(|| format!("dlx-lifecycle-funnel: relativize {}", path.display()))?;
        if is_production_source(rel) {
            files.push(rel.to_path_buf());
        }
    }
    Ok(())
}

fn is_production_source(path: &Path) -> bool {
    let extension = path.extension().and_then(|value| value.to_str());
    match extension {
        Some("rs") => {
            path.components()
                .any(|component| component.as_os_str() == "src")
                && !path.components().any(|component| {
                    matches!(
                        component.as_os_str().to_str(),
                        Some("tests" | "benches" | "examples")
                    )
                })
                && !path
                    .file_name()
                    .and_then(|value| value.to_str())
                    .is_some_and(|name| {
                        name == "integration_tests.rs" || name.ends_with("_tests.rs")
                    })
        }
        Some("toml") => path.starts_with("assemblies"),
        Some("md") => path.starts_with("docs/rules"),
        Some("sql") => is_migration_in_guard_scope(path),
        _ => false,
    }
}

fn is_migration_in_guard_scope(path: &Path) -> bool {
    let migration_dir = Path::new("adapters/postgres/migrations");
    if !path.starts_with(migration_dir) {
        return false;
    }
    path.file_name()
        .and_then(|value| value.to_str())
        .and_then(|name| name.get(..4))
        .and_then(|ordinal| ordinal.parse::<u16>().ok())
        .is_some_and(|ordinal| ordinal >= 62)
}

fn is_lifecycle_migration(path: &Path) -> bool {
    path == Path::new(LIFECYCLE_MIGRATION)
}

fn is_authorized_dead_letter_delete(path: &Path) -> bool {
    path == Path::new(CUTOVER_MIGRATION) || is_lifecycle_migration(path)
}

fn scan_content(path: &Path, content: &str) -> Vec<Finding<Rule>> {
    let mut findings = Vec::new();
    let normalized = content.to_ascii_lowercase();

    for token in retired_tokens() {
        if content.contains(&token) && !is_authorized_retired_tombstone(path, content, &token) {
            findings.push(finding(
                Rule::RetiredSurface,
                path.display().to_string(),
                format!("已退役 DLX surface `{token}` 不得回流"),
            ));
        }
    }

    if contains_dead_letter_delete(content) && !is_authorized_dead_letter_delete(path) {
        findings.push(finding(
            Rule::RawDeadLetterDelete,
            path.display().to_string(),
            "dead_letter DELETE 只能封装在 lifecycle repository 的固定函数调用中".to_string(),
        ));
    }

    if path != Path::new(LIFECYCLE_REPOSITORY) && !is_lifecycle_migration(path) {
        for function in FIXED_FUNCTIONS {
            if normalized.contains(function) {
                findings.push(finding(
                    Rule::LifecycleFunctionEscape,
                    path.display().to_string(),
                    format!(
                        "固定 lifecycle 函数 `{function}` 只能由 PgDlxLifecycleRepository 调用"
                    ),
                ));
            }
        }
    }

    if path == Path::new(ARCHIVE_PROVIDER)
        || content.contains("DlxArchiveStore for")
        || content.contains("impl DlxArchiveStore")
    {
        for token in [
            "delete_object",
            "DeleteObject",
            "list_objects",
            "ListObjects",
        ] {
            if content.contains(token) {
                findings.push(finding(
                    Rule::DeletableArchiveProvider,
                    path.display().to_string(),
                    format!("WORM archive provider 禁止暴露 `{token}` 能力"),
                ));
            }
        }
    }

    findings
}

fn contains_dead_letter_delete(content: &str) -> bool {
    let normalized = normalize_sql_code(content);
    let compact = normalized
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect::<String>();
    [
        "deletefromdead_letter",
        "deletefromonlydead_letter",
        "deletefrompublic.dead_letter",
        "deletefromonlypublic.dead_letter",
    ]
    .iter()
    .any(|pattern| compact.contains(pattern))
        || compact
            .find("deletefrom")
            .and_then(|start| compact.get(start + "deletefrom".len()..))
            .is_some_and(|tail| {
                let tail = tail.strip_prefix("only").unwrap_or(tail);
                tail.split([';', '(', ')', ','])
                    .next()
                    .is_some_and(|table| table.ends_with(".dead_letter"))
            })
}

fn normalize_sql_code(content: &str) -> String {
    let bytes = content.as_bytes();
    let mut output = String::with_capacity(content.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index..].starts_with(b"--") {
            index += 2;
            while index < bytes.len() && bytes[index] != b'\n' {
                index += 1;
            }
        } else if bytes[index..].starts_with(b"/*") {
            index += 2;
            while index + 1 < bytes.len() && !bytes[index..].starts_with(b"*/") {
                index += 1;
            }
            index = (index + 2).min(bytes.len());
        } else if bytes[index] == b'\'' {
            index += 1;
            while index < bytes.len() {
                if bytes[index] == b'\'' {
                    index += 1;
                    if index < bytes.len() && bytes[index] == b'\'' {
                        index += 1;
                        continue;
                    }
                    break;
                }
                index += 1;
            }
            output.push(' ');
        } else if bytes[index] == b'"' {
            index += 1;
            while index < bytes.len() && bytes[index] != b'"' {
                output.push((bytes[index] as char).to_ascii_lowercase());
                index += 1;
            }
            index = (index + 1).min(bytes.len());
        } else {
            output.push((bytes[index] as char).to_ascii_lowercase());
            index += 1;
        }
    }
    output
}

fn is_authorized_retired_tombstone(path: &Path, content: &str, token: &str) -> bool {
    token == "rss_sweep_dead_letter"
        && is_lifecycle_migration(path)
        && content
            .lines()
            .filter(|line| line.contains(token))
            .all(|line| {
                line.trim_start()
                    .starts_with("DROP FUNCTION IF EXISTS public.rss_sweep_dead_letter")
            })
}

fn retired_tokens() -> [String; 10] {
    [
        ["RSS_DEAD_LETTER_", "RETAIN_SECONDS"].concat(),
        ["rss_sweep_dead_", "letter"].concat(),
        ["key-provider-", "v1"].concat(),
        ["key-provider-", "v2"].concat(),
        ["DeadLetterSource::", "Legacy"].concat(),
        ["eventexec::DlxLifecycle", "Repository"].concat(),
        ["eventexec::DlxArchive", "Store"].concat(),
        ["eventexec::DlxArchive", "Cipher"].concat(),
        ["KeyProviderDlxArchive", "Cipher"].concat(),
        ["trait DlxArchive", "Cipher:"].concat(),
    ]
}

fn required_runtime_source_findings(path: &Path, content: &str) -> Vec<Finding<Rule>> {
    const DIPORT: &str = "crates/diport/src/dlx_lifecycle.rs";
    const PG: &str = "assemblies/runtime/src/infra/pg.rs";
    const S3: &str = "assemblies/runtime/src/infra/s3.rs";
    const EVENT_TRANSPORT: &str = "assemblies/runtime/src/event_transport.rs";
    const ASSEMBLY: &str = "assemblies/runtime/assembly.toml";

    if path == Path::new(ASSEMBLY) {
        return required_assembly_provider_findings(path, content);
    }
    let file = match syn::parse_file(content) {
        Ok(file) => file,
        Err(error) => {
            return vec![missing_runtime_shape(
                path,
                format!("无法解析必需 Rust provider 载体: {error}"),
            )];
        }
    };
    let mut missing = Vec::new();
    match path.to_str() {
        Some(DIPORT) => {
            for trait_name in ["DlxLifecycleRepositoryLocal", "DlxArchiveStoreLocal"] {
                if !has_trait(&file, trait_name) {
                    missing.push(format!("trait `{trait_name}`"));
                }
            }
        }
        Some(PG) => {
            missing.extend(required_pg_shapes(&file));
        }
        Some(S3) => {
            missing.extend(required_s3_shapes(&file));
        }
        Some(EVENT_TRANSPORT) => {
            for (name, value) in [
                ("DLX_ARCHIVE_KEY_NAME_ENV", "RSS_DLX_ARCHIVE_KEY_NAME"),
                ("DLX_HOT_VAULT_TOKEN_ENV", "RSS_DLX_HOT_VAULT_TOKEN"),
                ("DLX_ARCHIVE_VAULT_TOKEN_ENV", "RSS_DLX_ARCHIVE_VAULT_TOKEN"),
            ] {
                if const_string_value(&file, name).as_deref() != Some(value) {
                    missing.push(format!("const `{name}` = `{value}`"));
                }
            }
            if !has_struct(&file, "DlxLifecycleRuntimeDeps") {
                missing.push("struct `DlxLifecycleRuntimeDeps`".to_owned());
            }
            if !has_function(&file, "wire_dlx_lifecycle") {
                missing.push("fn `wire_dlx_lifecycle`".to_owned());
            }
        }
        _ => missing.push("registered runtime provider source".to_owned()),
    }
    missing
        .into_iter()
        .map(|shape| missing_runtime_shape(path, format!("缺少必需结构 `{shape}`")))
        .collect()
}

fn required_pg_shapes(file: &syn::File) -> Vec<String> {
    const ROLES: [(&str, &str, &str, &str, &str, &str); 3] = [
        (
            "dlx_archiver",
            "PG_DLX_ARCHIVER_ROLE_KEYS",
            "PG_DLX_ARCHIVER_USERNAME_ENV",
            "RSS_PG_DLX_ARCHIVER_USERNAME",
            "PG_DLX_ARCHIVER_PASSWORD_ENV",
            "RSS_PG_DLX_ARCHIVER_PASSWORD",
        ),
        (
            "dlx_verifier",
            "PG_DLX_VERIFIER_ROLE_KEYS",
            "PG_DLX_VERIFIER_USERNAME_ENV",
            "RSS_PG_DLX_VERIFIER_USERNAME",
            "PG_DLX_VERIFIER_PASSWORD_ENV",
            "RSS_PG_DLX_VERIFIER_PASSWORD",
        ),
        (
            "dlx_purger",
            "PG_DLX_PURGER_ROLE_KEYS",
            "PG_DLX_PURGER_USERNAME_ENV",
            "RSS_PG_DLX_PURGER_USERNAME",
            "PG_DLX_PURGER_PASSWORD_ENV",
            "RSS_PG_DLX_PURGER_PASSWORD",
        ),
    ];
    let fields = file.items.iter().find_map(|item| match item {
        syn::Item::Struct(item) if item.ident == "PgRuntimeConfig" => match &item.fields {
            syn::Fields::Named(fields) => Some(fields),
            _ => None,
        },
        _ => None,
    });
    let constructor = file.items.iter().find_map(|item| match item {
        syn::Item::Impl(item)
            if item.trait_.is_none()
                && item.self_ty.to_token_stream().to_string() == "PgRuntimeConfig" =>
        {
            item.items.iter().find_map(|item| match item {
                syn::ImplItem::Fn(method) if method.sig.ident == "from_snapshot" => Some(method),
                _ => None,
            })
        }
        _ => None,
    });
    let valid = fields.is_some_and(|fields| {
        ROLES.iter().all(|(binding, _, _, _, _, _)| {
            fields
                .named
                .iter()
                .filter(|field| field.ident.as_ref().is_some_and(|ident| ident == *binding))
                .count()
                == 1
        })
    }) && ROLES.iter().all(
        |(_, descriptor, username_const, username, password_const, password)| {
            const_string_value(file, username_const).as_deref() == Some(*username)
                && const_string_value(file, password_const).as_deref() == Some(*password)
                && exact_pg_role_descriptor(file, descriptor, username_const, password_const)
        },
    ) && constructor
        .is_some_and(|constructor| exact_pg_dlx_role_mapping(constructor, &ROLES));
    (!valid)
        .then(|| "typed `PgRuntimeConfig::from_snapshot` DLX role mapping".to_owned())
        .into_iter()
        .collect()
}

fn exact_pg_dlx_role_mapping(
    method: &syn::ImplItemFn,
    roles: &[(&str, &str, &str, &str, &str, &str)],
) -> bool {
    let snapshot_argument_is_exact = method.sig.inputs.iter().any(|argument| {
        let syn::FnArg::Typed(argument) = argument else {
            return false;
        };
        let syn::Pat::Ident(binding) = argument.pat.as_ref() else {
            return false;
        };
        binding.ident == "config" && type_path_is_exact(argument.ty.as_ref(), "SnapshotConfig")
    });
    if !snapshot_argument_is_exact {
        return false;
    }

    let mut calls = DlxRoleConfigCallCount::default();
    syn::visit::Visit::visit_block(&mut calls, &method.block);
    calls.0 == roles.len()
        && roles.iter().all(|(binding, descriptor, _, _, _, _)| {
            exact_role_local(method, binding, descriptor)
                && returned_self_field_is_exact(&method.block, binding)
        })
}

fn exact_pg_role_descriptor(
    file: &syn::File,
    descriptor: &str,
    username_const: &str,
    password_const: &str,
) -> bool {
    let descriptors = file.items.iter().filter_map(|item| match item {
        syn::Item::Const(item) if item.ident == descriptor => Some(item),
        _ => None,
    });
    let mut descriptors = descriptors.collect::<Vec<_>>();
    let Some(item) = (descriptors.len() == 1).then(|| descriptors.remove(0)) else {
        return false;
    };
    if !matches!(item.vis, syn::Visibility::Inherited)
        || !type_path_is_exact(&item.ty, "PgRoleKeys")
    {
        return false;
    }
    let syn::Expr::Struct(value) = item.expr.as_ref() else {
        return false;
    };
    if !path_is_ident(&value.path, "PgRoleKeys") || value.rest.is_some() || value.fields.len() != 2
    {
        return false;
    }
    let field_is = |name: &str, expected: &str| {
        value
            .fields
            .iter()
            .filter(|field| {
                matches!(&field.member, syn::Member::Named(member) if member == name)
                    && expression_is_ident(&field.expr, expected)
            })
            .count()
            == 1
    };
    field_is("username", username_const) && field_is("password", password_const)
}

fn type_path_is_exact(ty: &syn::Type, expected: &str) -> bool {
    let syn::Type::Path(path) = ty else {
        return false;
    };
    path.qself.is_none()
        && path.path.segments.len() == 1
        && path
            .path
            .segments
            .first()
            .is_some_and(|segment| segment.ident == expected)
}

fn exact_role_local(method: &syn::ImplItemFn, binding: &str, descriptor: &str) -> bool {
    let mut locals = method.block.stmts.iter().filter_map(|statement| {
        let syn::Stmt::Local(local) = statement else {
            return None;
        };
        let syn::Pat::Ident(local_binding) = &local.pat else {
            return None;
        };
        if local_binding.ident != binding
            || local_binding.by_ref.is_some()
            || local_binding.mutability.is_some()
            || local_binding.subpat.is_some()
        {
            return None;
        }
        Some(local.init.as_ref()?.expr.as_ref())
    });
    let Some(expression) = locals.next() else {
        return false;
    };
    if locals.next().is_some() {
        return false;
    }
    let syn::Expr::Try(expression) = expression else {
        return false;
    };
    let syn::Expr::MethodCall(call) = expression.expr.as_ref() else {
        return false;
    };
    call.method == "role_config"
        && call.turbofish.is_none()
        && expression_is_ident(call.receiver.as_ref(), "shared")
        && call.args.len() == 2
        && expression_is_ident(&call.args[0], "config")
        && expression_is_ident(&call.args[1], descriptor)
}

fn expression_is_ident(expression: &syn::Expr, expected: &str) -> bool {
    let syn::Expr::Path(path) = expression else {
        return false;
    };
    path.qself.is_none()
        && path.path.segments.len() == 1
        && path
            .path
            .segments
            .first()
            .is_some_and(|segment| segment.ident == expected)
}

fn returned_self_field_is_exact(block: &syn::Block, binding: &str) -> bool {
    let Some(syn::Stmt::Expr(syn::Expr::Call(ok), None)) = block.stmts.last() else {
        return false;
    };
    if !expression_is_ident(ok.func.as_ref(), "Ok") || ok.args.len() != 1 {
        return false;
    }
    let syn::Expr::Struct(returned) = &ok.args[0] else {
        return false;
    };
    if returned.rest.is_some() || !path_is_ident(&returned.path, "Self") {
        return false;
    }
    let mut fields = returned
        .fields
        .iter()
        .filter(|field| matches!(&field.member, syn::Member::Named(member) if member == binding));
    fields
        .next()
        .is_some_and(|field| expression_is_ident(&field.expr, binding))
        && fields.next().is_none()
}

fn path_is_ident(path: &syn::Path, expected: &str) -> bool {
    path.segments.len() == 1
        && path
            .segments
            .first()
            .is_some_and(|segment| segment.ident == expected)
}

#[derive(Default)]
struct DlxRoleConfigCallCount(usize);

impl<'ast> syn::visit::Visit<'ast> for DlxRoleConfigCallCount {
    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        if call.method == "role_config"
            && call.args.iter().any(|argument| {
                matches!(argument, syn::Expr::Path(path)
                if path.path.segments.last().is_some_and(|segment| {
                    segment.ident.to_string().starts_with("PG_DLX_")
                        && segment.ident.to_string().ends_with("_ROLE_KEYS")
                }))
            })
        {
            self.0 += 1;
        }
        syn::visit::visit_expr_method_call(self, call);
    }
}

fn required_s3_shapes(file: &syn::File) -> Vec<String> {
    let mut missing = Vec::new();
    if const_string_value(file, "DLX_ARCHIVE_S3_BUCKET_ENV").as_deref()
        != Some("RSS_DLX_ARCHIVE_S3_BUCKET")
    {
        missing.push("const `DLX_ARCHIVE_S3_BUCKET_ENV` = `RSS_DLX_ARCHIVE_S3_BUCKET`".to_owned());
    }
    if !s3_dlx_archive_builder_is_exact(file) {
        missing.push(
            "typed DLX S3 identity inequality plus refreshable credential-provider handoff"
                .to_owned(),
        );
    }
    missing
}

const S3_DLX_ARCHIVE_BODY: &str = r#"{
    let S3DlxArchiveConfig {
        settings,
        bucket,
        general_identity,
    } = config;
    let http_client = s3_http_client(&settings.endpoint);
    let region = aws_sdk_s3::config::Region::new(settings.region.clone());
    let provider_config = aws_config::provider_config::ProviderConfig::without_region()
        .with_region(Some(region.clone()))
        .with_http_client(http_client.clone());
    let credentials_provider =
        aws_config::default_provider::credentials::DefaultCredentialsChain::builder()
            .region(region)
            .configure(provider_config)
            .build()
            .await;
    let credentials_provider =
        DlxIsolatedCredentialsProvider::new(credentials_provider, general_identity);
    credentials_provider
        .provide_credentials()
        .await
        .context("validate isolated DLX archive credentials from the AWS default provider chain")?;
    let client = build_s3_dlx_client_from_settings(&settings, credentials_provider, http_client);
    S3DlxArchiveStore::new(client, bucket, clock).context("construct DLX archive S3 store")
}"#;

const S3_DLX_IDENTITY_CAPABILITY_SHAPE: &str = r#"
struct S3GeneralIdentityMarker(secure::SecretText);

impl S3GeneralIdentityMarker {
    fn from_credentials(credentials: &aws_sdk_s3::config::Credentials) -> Self {
        Self(secure::SecretText::from_string(
            credentials.access_key_id().to_owned(),
        ))
    }

    fn collides_with(&self, credentials: &aws_sdk_s3::config::Credentials) -> bool {
        self.0.expose() == credentials.access_key_id()
    }
}

pub(crate) struct S3DlxArchiveConfig {
    settings: Arc<S3ClientSettings>,
    bucket: String,
    general_identity: S3GeneralIdentityMarker,
}
"#;

const DLX_ISOLATED_PROVIDER_SHAPE: &str = r#"
struct DlxIsolatedCredentialsProvider<P> {
    inner: P,
    general_identity: S3GeneralIdentityMarker,
}

impl<P> DlxIsolatedCredentialsProvider<P> {
    fn new(inner: P, general_identity: S3GeneralIdentityMarker) -> Self {
        Self {
            inner,
            general_identity,
        }
    }

    fn identity_is_distinct(&self, credentials: &aws_sdk_s3::config::Credentials) -> bool {
        !self.general_identity.collides_with(credentials)
    }
}

impl<P> aws_sdk_s3::config::ProvideCredentials for DlxIsolatedCredentialsProvider<P>
where
    P: aws_sdk_s3::config::ProvideCredentials,
{
    fn provide_credentials<'a>(
        &'a self,
    ) -> aws_credential_types::provider::future::ProvideCredentials<'a>
    where
        Self: 'a,
    {
        aws_credential_types::provider::future::ProvideCredentials::new(async move {
            let credentials = self.inner.provide_credentials().await?;
            if self.identity_is_distinct(&credentials) {
                Ok(credentials)
            } else {
                Err(
                    aws_credential_types::provider::error::CredentialsError::invalid_configuration(
                        DLX_IDENTITY_COLLISION_ERROR,
                    ),
                )
            }
        })
    }

    fn fallback_on_interrupt(&self) -> Option<aws_sdk_s3::config::Credentials> {
        self.inner
            .fallback_on_interrupt()
            .filter(|credentials| self.identity_is_distinct(credentials))
    }
}
"#;

fn compact_tokens(tokens: &impl quote::ToTokens) -> String {
    tokens
        .to_token_stream()
        .to_string()
        .split_whitespace()
        .collect()
}

fn s3_dlx_archive_builder_is_exact(file: &syn::File) -> bool {
    let Ok(expected_capabilities) = syn::parse_file(S3_DLX_IDENTITY_CAPABILITY_SHAPE) else {
        return false;
    };
    let Ok(expected_provider) = syn::parse_file(DLX_ISOLATED_PROVIDER_SHAPE) else {
        return false;
    };
    let expected_marker = expected_capabilities
        .items
        .iter()
        .find_map(|item| match item {
            syn::Item::Struct(item) if item.ident == "S3GeneralIdentityMarker" => Some(item),
            _ => None,
        });
    let expected_archive_config = expected_capabilities
        .items
        .iter()
        .find_map(|item| match item {
            syn::Item::Struct(item) if item.ident == "S3DlxArchiveConfig" => Some(item),
            _ => None,
        });
    let expected_marker_impl = expected_capabilities
        .items
        .iter()
        .find_map(|item| match item {
            syn::Item::Impl(item)
                if compact_tokens(item.self_ty.as_ref()) == "S3GeneralIdentityMarker"
                    && item.trait_.is_none() =>
            {
                Some(item)
            }
            _ => None,
        });
    let expected_struct = expected_provider.items.iter().find_map(|item| match item {
        syn::Item::Struct(item) => Some(item),
        _ => None,
    });
    let expected_impls = expected_provider
        .items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Impl(item) => Some(item),
            _ => None,
        })
        .collect::<Vec<_>>();
    let actual_structs = file
        .items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Struct(item) if item.ident == "DlxIsolatedCredentialsProvider" => Some(item),
            _ => None,
        })
        .collect::<Vec<_>>();
    let actual_marker = file.items.iter().filter_map(|item| match item {
        syn::Item::Struct(item) if item.ident == "S3GeneralIdentityMarker" => Some(item),
        _ => None,
    });
    let actual_archive_config = file.items.iter().filter_map(|item| match item {
        syn::Item::Struct(item) if item.ident == "S3DlxArchiveConfig" => Some(item),
        _ => None,
    });
    let actual_marker_impl = file.items.iter().filter_map(|item| match item {
        syn::Item::Impl(item)
            if compact_tokens(item.self_ty.as_ref()) == "S3GeneralIdentityMarker"
                && item.trait_.is_none() =>
        {
            Some(item)
        }
        _ => None,
    });
    let actual_impls = file
        .items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Impl(item)
                if compact_tokens(item.self_ty.as_ref()) == "DlxIsolatedCredentialsProvider<P>"
                    && item.trait_.as_ref().is_none_or(|(_, path, _)| {
                        compact_tokens(path) == "aws_sdk_s3::config::ProvideCredentials"
                    }) =>
            {
                Some(item)
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    let actual_marker = actual_marker.collect::<Vec<_>>();
    let actual_archive_config = actual_archive_config.collect::<Vec<_>>();
    let actual_marker_impl = actual_marker_impl.collect::<Vec<_>>();
    let identity_capability_is_exact = expected_marker.is_some_and(|expected| {
        actual_marker.len() == 1 && compact_tokens(actual_marker[0]) == compact_tokens(expected)
    }) && expected_archive_config.is_some_and(|expected| {
        actual_archive_config.len() == 1
            && compact_tokens(actual_archive_config[0]) == compact_tokens(expected)
    }) && expected_marker_impl.is_some_and(|expected| {
        actual_marker_impl.len() == 1
            && compact_tokens(actual_marker_impl[0]) == compact_tokens(expected)
    });
    let provider_shape_is_exact = expected_struct.is_some_and(|expected| {
        actual_structs.len() == 1
            && compact_tokens(actual_structs[0]) == compact_tokens(expected)
            && actual_impls.len() == expected_impls.len()
            && expected_impls.iter().all(|expected_impl| {
                actual_impls.iter().any(|actual_impl| {
                    compact_tokens(*actual_impl) == compact_tokens(expected_impl)
                })
            })
    });
    let builders = file
        .items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Fn(function) if function.sig.ident == "build_s3_dlx_archive_store" => {
                Some(function)
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    let Some(builder) = builders.first().filter(|_| builders.len() == 1) else {
        return false;
    };
    let inputs = builder.sig.inputs.iter().collect::<Vec<_>>();
    let input_is = |index: usize, binding: &str, ty: &str| {
        inputs.get(index).is_some_and(|input| {
            matches!(input, syn::FnArg::Typed(input)
            if matches!(input.pat.as_ref(), syn::Pat::Ident(ident)
                if ident.ident == binding
                    && ident.by_ref.is_none()
                    && ident.mutability.is_none()
                    && ident.subpat.is_none())
                && compact_tokens(input.ty.as_ref()) == ty)
        })
    };
    let expected_body = syn::parse_str::<syn::Block>(S3_DLX_ARCHIVE_BODY).ok();
    identity_capability_is_exact
        && provider_shape_is_exact
        && matches!(builder.vis, syn::Visibility::Restricted(_))
        && builder.sig.asyncness.is_some()
        && builder.sig.constness.is_none()
        && builder.sig.unsafety.is_none()
        && builder.sig.generics.params.is_empty()
        && inputs.len() == 2
        && input_is(0, "config", "S3DlxArchiveConfig")
        && input_is(1, "clock", "Arc<dyndiport::Clock>")
        && matches!(&builder.sig.output, syn::ReturnType::Type(_, ty)
            if compact_tokens(ty.as_ref()) == "anyhow::Result<S3DlxArchiveStore>")
        && expected_body
            .as_ref()
            .is_some_and(|expected| compact_tokens(&builder.block) == compact_tokens(expected))
}

fn required_assembly_provider_findings(path: &Path, content: &str) -> Vec<Finding<Rule>> {
    let manifest: toml::Value = match content.parse() {
        Ok(manifest) => manifest,
        Err(error) => {
            return vec![missing_runtime_shape(
                path,
                format!("无法解析 assembly manifest: {error}"),
            )];
        }
    };
    let providers = manifest
        .get("diportProviders")
        .and_then(toml::Value::as_array);
    [
        (
            "diport::DlxLifecycleRepository",
            "postgres::PgDlxLifecycleRepository",
            "dead-letter-archive-receipt-purge-reconcile",
        ),
        (
            "diport::DlxArchiveStore",
            "s3::VerifiedS3DlxArchiveStore",
            "dead-letter-compliance-worm-archive",
        ),
        (
            "diport::KeyProvider",
            "vault::VaultKeyProvider",
            "dead-letter-independent-archive-key-provider",
        ),
    ]
    .into_iter()
    .filter(|(port, provider, purpose)| {
        !providers.is_some_and(|providers| {
            providers.iter().any(|entry| {
                entry.get("port").and_then(toml::Value::as_str) == Some(*port)
                    && entry.get("provider").and_then(toml::Value::as_str) == Some(*provider)
                    && entry.get("purpose").and_then(toml::Value::as_str) == Some(*purpose)
            })
        })
    })
    .map(|(port, provider, _)| {
        missing_runtime_shape(
            path,
            format!("缺少 provider record `{port}` -> `{provider}`"),
        )
    })
    .collect()
}

fn missing_runtime_shape(path: &Path, detail: String) -> Finding<Rule> {
    finding(
        Rule::MissingRuntimeProvider,
        path.display().to_string(),
        detail,
    )
}

fn has_trait(file: &syn::File, name: &str) -> bool {
    file.items
        .iter()
        .any(|item| matches!(item, syn::Item::Trait(item) if item.ident == name))
}

fn has_struct(file: &syn::File, name: &str) -> bool {
    file.items
        .iter()
        .any(|item| matches!(item, syn::Item::Struct(item) if item.ident == name))
}

fn has_function(file: &syn::File, name: &str) -> bool {
    file.items
        .iter()
        .any(|item| matches!(item, syn::Item::Fn(item) if item.sig.ident == name))
}

fn const_string_value(file: &syn::File, name: &str) -> Option<String> {
    file.items.iter().find_map(|item| match item {
        syn::Item::Const(item) if item.ident == name => match item.expr.as_ref() {
            syn::Expr::Lit(literal) => match &literal.lit {
                syn::Lit::Str(value) => Some(value.value()),
                _ => None,
            },
            _ => None,
        },
        _ => None,
    })
}

#[cfg(test)]
fn function_ends_with_string_config_call(
    file: &syn::File,
    function: &str,
    callee: &str,
    expected_strings: &[&str],
) -> bool {
    let Some(item) = file.items.iter().find_map(|item| match item {
        syn::Item::Fn(item) if item.sig.ident == function => Some(item),
        _ => None,
    }) else {
        return false;
    };
    let Some(syn::Stmt::Expr(syn::Expr::Call(call), None)) = item.block.stmts.last() else {
        return false;
    };
    let syn::Expr::Path(path) = call.func.as_ref() else {
        return false;
    };
    if path
        .path
        .segments
        .last()
        .is_none_or(|segment| segment.ident != callee)
    {
        return false;
    }
    let actual = call
        .args
        .iter()
        .filter_map(|argument| match argument {
            syn::Expr::Lit(literal) => match &literal.lit {
                syn::Lit::Str(value) => Some(value.value()),
                _ => None,
            },
            _ => None,
        })
        .collect::<Vec<_>>();
    actual == expected_strings
}

#[cfg(test)]
fn function_has_path_call(file: &syn::File, function: &str, expected: &str) -> bool {
    let Some(item) = file.items.iter().find_map(|item| match item {
        syn::Item::Fn(item) if item.sig.ident == function => Some(item),
        _ => None,
    }) else {
        return false;
    };
    #[derive(Default)]
    struct PathCalls(Vec<String>);
    impl<'ast> syn::visit::Visit<'ast> for PathCalls {
        fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
            if let syn::Expr::Path(path) = call.func.as_ref() {
                self.0.push(
                    path.path
                        .segments
                        .iter()
                        .map(|segment| segment.ident.to_string())
                        .collect::<Vec<_>>()
                        .join("::"),
                );
            }
            syn::visit::visit_expr_call(self, call);
        }
    }
    let mut calls = PathCalls::default();
    syn::visit::Visit::visit_block(&mut calls, &item.block);
    calls.0.iter().any(|call| call == expected)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn canonical_runtime_infra_phase_fixture() -> &'static str {
        r#"
            impl<'a> ProvidersBuilt<'a> {
                async fn build_infra(self) {
                    after_required_preflight();
                    PgDlxLifecycleRuntime::preflight_identities(
                        &dlx_archiver_pg_config,
                        &dlx_verifier_pg_config,
                        &dlx_purger_pg_config,
                    );
                    archive_store.verify();
                    verify_dlx_vault_key_capability(&hot_vault_provider);
                    verify_dlx_vault_key_capability(&archive_vault_provider);
                    Ok(PhaseADlxVerified {
                        dlx_archiver_pg_config,
                        dlx_verifier_pg_config,
                        dlx_purger_pg_config,
                        archive_store,
                        archive_vault_provider,
                    });
                    PgRuntimeDeps::setup_with_audit_admin_config();
                    PgDlxLifecycleRuntime::setup(
                        &dlx_archiver_pg_config,
                        &dlx_verifier_pg_config,
                        &dlx_purger_pg_config,
                        hot_payload_protector,
                    );
                    DlxLifecycleRuntimeDeps::new(
                        dlx_pg_owner,
                        archive_store,
                        archive_vault_provider,
                        archive_key,
                    );
                    wire_dlx_lifecycle(dlx_lifecycle, dlx_worker);
                }
            }
        "#
    }

    fn helper_expanded_runtime_infra_phase_fixture() -> &'static str {
        r#"
            impl<'a> ProvidersBuilt<'a> {
                async fn build_infra(self) {
                    after_required_preflight(
                        Self::phase_a_run_dlx_preflight(),
                        |verified| Self::phase_b_setup_postgres_after_preflight(verified),
                    );
                    PgDlxLifecycleRuntime::setup(
                        &dlx_archiver_pg_config,
                        &dlx_verifier_pg_config,
                        &dlx_purger_pg_config,
                        hot_payload_protector,
                    );
                    DlxLifecycleRuntimeDeps::new(
                        dlx_pg_owner,
                        archive_store,
                        archive_vault_provider,
                        archive_key,
                    );
                    wire_dlx_lifecycle(dlx_lifecycle, dlx_worker);
                }

                async fn phase_a_run_dlx_preflight() {
                    PgDlxLifecycleRuntime::preflight_identities(
                        &dlx_archiver_pg_config,
                        &dlx_verifier_pg_config,
                        &dlx_purger_pg_config,
                    );
                    archive_store.verify();
                    verify_dlx_vault_key_capability(&hot_vault_provider);
                    verify_dlx_vault_key_capability(&archive_vault_provider);
                    Ok(PhaseADlxVerified {
                        dlx_archiver_pg_config,
                        dlx_verifier_pg_config,
                        dlx_purger_pg_config,
                        archive_store,
                        archive_vault_provider,
                    });
                }

                async fn phase_b_setup_postgres_after_preflight(verified: ()) {
                    Self::phase_b_setup_postgres();
                    verified
                }

                async fn phase_b_setup_postgres() {
                    PgRuntimeDeps::setup_with_audit_admin_config();
                }
            }
        "#
    }

    fn canonical_s3_archive_builder_fixture() -> &'static str {
        r#"
const DLX_ARCHIVE_S3_BUCKET_ENV: &str = "RSS_DLX_ARCHIVE_S3_BUCKET";
const DLX_IDENTITY_COLLISION_ERROR: &str = "DLX archive workload identity must differ";
struct S3GeneralIdentityMarker(secure::SecretText);
impl S3GeneralIdentityMarker {
    fn from_credentials(credentials: &aws_sdk_s3::config::Credentials) -> Self {
        Self(secure::SecretText::from_string(
            credentials.access_key_id().to_owned(),
        ))
    }
    fn collides_with(&self, credentials: &aws_sdk_s3::config::Credentials) -> bool {
        self.0.expose() == credentials.access_key_id()
    }
}
pub(crate) struct S3DlxArchiveConfig {
    settings: Arc<S3ClientSettings>,
    bucket: String,
    general_identity: S3GeneralIdentityMarker,
}
struct DlxIsolatedCredentialsProvider<P> {
    inner: P,
    general_identity: S3GeneralIdentityMarker,
}
impl<P> DlxIsolatedCredentialsProvider<P> {
    fn new(inner: P, general_identity: S3GeneralIdentityMarker) -> Self {
        Self {
            inner,
            general_identity,
        }
    }
    fn identity_is_distinct(&self, credentials: &aws_sdk_s3::config::Credentials) -> bool {
        !self.general_identity.collides_with(credentials)
    }
}
impl<P> aws_sdk_s3::config::ProvideCredentials for DlxIsolatedCredentialsProvider<P>
where
    P: aws_sdk_s3::config::ProvideCredentials,
{
    fn provide_credentials<'a>(
        &'a self,
    ) -> aws_credential_types::provider::future::ProvideCredentials<'a>
    where
        Self: 'a,
    {
        aws_credential_types::provider::future::ProvideCredentials::new(async move {
            let credentials = self.inner.provide_credentials().await?;
            if self.identity_is_distinct(&credentials) {
                Ok(credentials)
            } else {
                Err(
                    aws_credential_types::provider::error::CredentialsError::invalid_configuration(
                        DLX_IDENTITY_COLLISION_ERROR,
                    ),
                )
            }
        })
    }
    fn fallback_on_interrupt(&self) -> Option<aws_sdk_s3::config::Credentials> {
        self.inner
            .fallback_on_interrupt()
            .filter(|credentials| self.identity_is_distinct(credentials))
    }
}
pub(crate) async fn build_s3_dlx_archive_store(
    config: S3DlxArchiveConfig,
    clock: Arc<dyn diport::Clock>,
) -> anyhow::Result<S3DlxArchiveStore> {
    let S3DlxArchiveConfig { settings, bucket, general_identity, } = config;
    let http_client = s3_http_client(&settings.endpoint);
    let region = aws_sdk_s3::config::Region::new(settings.region.clone());
    let provider_config = aws_config::provider_config::ProviderConfig::without_region()
        .with_region(Some(region.clone()))
        .with_http_client(http_client.clone());
    let credentials_provider =
        aws_config::default_provider::credentials::DefaultCredentialsChain::builder()
            .region(region)
            .configure(provider_config)
            .build()
            .await;
    let credentials_provider =
        DlxIsolatedCredentialsProvider::new(credentials_provider, general_identity);
    credentials_provider
        .provide_credentials()
        .await
        .context("validate isolated DLX archive credentials from the AWS default provider chain")?;
    let client = build_s3_dlx_client_from_settings(&settings, credentials_provider, http_client);
    S3DlxArchiveStore::new(client, bucket, clock).context("construct DLX archive S3 store")
}
"#
    }

    fn canonical_pg_runtime_config_fixture() -> &'static str {
        r#"
            use crate::config::SnapshotConfig;

            const PG_DLX_ARCHIVER_USERNAME_ENV: &str = "RSS_PG_DLX_ARCHIVER_USERNAME";
            const PG_DLX_ARCHIVER_PASSWORD_ENV: &str = "RSS_PG_DLX_ARCHIVER_PASSWORD";
            const PG_DLX_VERIFIER_USERNAME_ENV: &str = "RSS_PG_DLX_VERIFIER_USERNAME";
            const PG_DLX_VERIFIER_PASSWORD_ENV: &str = "RSS_PG_DLX_VERIFIER_PASSWORD";
            const PG_DLX_PURGER_USERNAME_ENV: &str = "RSS_PG_DLX_PURGER_USERNAME";
            const PG_DLX_PURGER_PASSWORD_ENV: &str = "RSS_PG_DLX_PURGER_PASSWORD";

            struct PgRoleKeys {
                username: &'static str,
                password: &'static str,
            }

            const PG_DLX_ARCHIVER_ROLE_KEYS: PgRoleKeys = PgRoleKeys {
                username: PG_DLX_ARCHIVER_USERNAME_ENV,
                password: PG_DLX_ARCHIVER_PASSWORD_ENV,
            };
            const PG_DLX_VERIFIER_ROLE_KEYS: PgRoleKeys = PgRoleKeys {
                username: PG_DLX_VERIFIER_USERNAME_ENV,
                password: PG_DLX_VERIFIER_PASSWORD_ENV,
            };
            const PG_DLX_PURGER_ROLE_KEYS: PgRoleKeys = PgRoleKeys {
                username: PG_DLX_PURGER_USERNAME_ENV,
                password: PG_DLX_PURGER_PASSWORD_ENV,
            };

            pub(crate) struct PgRuntimeConfig {
                dlx_archiver: PgConfig,
                dlx_verifier: PgConfig,
                dlx_purger: PgConfig,
            }

            impl PgRuntimeConfig {
                pub(crate) fn from_snapshot(config: SnapshotConfig<'_>) -> Result<Self, ()> {
                    let shared = PgSharedValues::from_snapshot(config)?;
                    let dlx_archiver =
                        shared.role_config(config, PG_DLX_ARCHIVER_ROLE_KEYS)?;
                    let dlx_verifier =
                        shared.role_config(config, PG_DLX_VERIFIER_ROLE_KEYS)?;
                    let dlx_purger = shared.role_config(config, PG_DLX_PURGER_ROLE_KEYS)?;
                    Ok(Self {
                        dlx_archiver,
                        dlx_verifier,
                        dlx_purger,
                    })
                }
            }
        "#
    }

    #[test]
    #[allow(clippy::cognitive_complexity)]
    fn synthetic_red_rejects_every_bypass_class() {
        let retired = scan_content(
            Path::new("assemblies/runtime/src/event_transport.rs"),
            "RSS_DEAD_LETTER_RETAIN_SECONDS DeadLetterSource::Legacy key-provider-v2",
        );
        assert!(retired.iter().any(|item| item.rule == Rule::RetiredSurface));

        for retired_port in [
            ["eventexec::DlxLifecycle", "Repository"].concat(),
            ["eventexec::DlxArchive", "Store"].concat(),
            ["eventexec::DlxArchive", "Cipher"].concat(),
            ["KeyProviderDlxArchive", "Cipher"].concat(),
        ] {
            assert_eq!(
                scan_content(Path::new("crates/eventexec/src/rogue.rs"), &retired_port)[0].rule,
                Rule::RetiredSurface
            );
        }

        let raw_delete = scan_content(
            Path::new("adapters/postgres/src/dead_letter.rs"),
            "DELETE FROM dead_letter WHERE id = $1",
        );
        assert_eq!(raw_delete[0].rule, Rule::RawDeadLetterDelete);

        let function_escape = scan_content(
            Path::new("assemblies/runtime/src/event_transport.rs"),
            "SELECT rss_dlx_purge_verified()",
        );
        assert_eq!(function_escape[0].rule, Rule::LifecycleFunctionEscape);

        let deletable = scan_content(
            Path::new(ARCHIVE_PROVIDER),
            "client.delete_object().send().await",
        );
        assert_eq!(deletable[0].rule, Rule::DeletableArchiveProvider);

        let missing = required_runtime_source_findings(
            Path::new("assemblies/runtime/src/infra/pg.rs"),
            "pub(crate) fn unrelated() {}",
        );
        assert_eq!(missing[0].rule, Rule::MissingRuntimeProvider);
        let canonical = canonical_pg_runtime_config_fixture();
        let wrong_role = canonical.replace(
            "RSS_PG_DLX_ARCHIVER_USERNAME",
            "RSS_PG_DLX_VERIFIER_USERNAME",
        );
        assert_ne!(wrong_role, canonical);
        assert!(
            !required_runtime_source_findings(
                Path::new("assemblies/runtime/src/infra/pg.rs"),
                &wrong_role,
            )
            .is_empty()
        );

        let crossed_credentials = canonical
            .replace("RSS_PG_DLX_ARCHIVER_USERNAME", "SWAPPED_USERNAME")
            .replace(
                "RSS_PG_DLX_VERIFIER_USERNAME",
                "RSS_PG_DLX_ARCHIVER_USERNAME",
            )
            .replace("SWAPPED_USERNAME", "RSS_PG_DLX_VERIFIER_USERNAME")
            .replace("RSS_PG_DLX_ARCHIVER_PASSWORD", "SWAPPED_PASSWORD")
            .replace(
                "RSS_PG_DLX_VERIFIER_PASSWORD",
                "RSS_PG_DLX_ARCHIVER_PASSWORD",
            )
            .replace("SWAPPED_PASSWORD", "RSS_PG_DLX_VERIFIER_PASSWORD");
        assert!(
            !required_runtime_source_findings(
                Path::new("assemblies/runtime/src/infra/pg.rs"),
                &crossed_credentials,
            )
            .is_empty(),
            "username/password must not be permuted across DLX roles",
        );

        let crossed_descriptors = canonical
            .replace("PG_DLX_ARCHIVER_ROLE_KEYS)?", "SWAPPED_ROLE_KEYS)?")
            .replace("PG_DLX_VERIFIER_ROLE_KEYS)?", "PG_DLX_ARCHIVER_ROLE_KEYS)?")
            .replace("SWAPPED_ROLE_KEYS)?", "PG_DLX_VERIFIER_ROLE_KEYS)?");
        assert_ne!(crossed_descriptors, canonical);
        assert!(
            !required_runtime_source_findings(
                Path::new("assemblies/runtime/src/infra/pg.rs"),
                &crossed_descriptors,
            )
            .is_empty(),
            "role locals must consume their exact descriptor rather than a transposed descriptor",
        );

        let crossed_descriptor_fields = canonical.replacen(
            "username: PG_DLX_ARCHIVER_USERNAME_ENV,\n                password: PG_DLX_ARCHIVER_PASSWORD_ENV,",
            "username: PG_DLX_ARCHIVER_PASSWORD_ENV,\n                password: PG_DLX_ARCHIVER_USERNAME_ENV,",
            1,
        );
        assert_ne!(crossed_descriptor_fields, canonical);
        assert!(
            !required_runtime_source_findings(
                Path::new("assemblies/runtime/src/infra/pg.rs"),
                &crossed_descriptor_fields,
            )
            .is_empty(),
            "descriptor username/password fields must not be transposed",
        );

        let transposed_fields = canonical.replace(
            "Ok(Self {\n                        dlx_archiver,\n                        dlx_verifier,",
            "Ok(Self {\n                        dlx_archiver: dlx_verifier,\n                        dlx_verifier: dlx_archiver,",
        );
        assert_ne!(transposed_fields, canonical);
        assert!(
            !required_runtime_source_findings(
                Path::new("assemblies/runtime/src/infra/pg.rs"),
                &transposed_fields,
            )
            .is_empty(),
            "Self fields must be filled from their same-name role bindings",
        );

        let duplicate_bait = canonical.replace(
            "let dlx_archiver =\n                        shared.role_config(",
            "let _compliant_bait =\n                        shared.role_config(config, PG_DLX_ARCHIVER_ROLE_KEYS)?;\n\
                    let dlx_archiver =\n                        shared.role_config(",
        );
        assert_ne!(duplicate_bait, canonical);
        assert!(
            !required_runtime_source_findings(
                Path::new("assemblies/runtime/src/infra/pg.rs"),
                &duplicate_bait,
            )
            .is_empty(),
            "an unused compliant call must not bait the typed mapping guard",
        );

        let wrapper_bait = duplicate_bait.replacen(
            "let dlx_archiver =\n                        shared.role_config(",
            "let dlx_archiver =\n                        wrapper_role_config(",
            1,
        );
        assert!(
            !required_runtime_source_findings(
                Path::new("assemblies/runtime/src/infra/pg.rs"),
                &wrapper_bait,
            )
            .is_empty(),
            "a wrapper plus compliant bait must not satisfy the direct mapping",
        );

        let canonical_s3 = canonical_s3_archive_builder_fixture();
        let canonical_s3_findings = required_runtime_source_findings(
            Path::new("assemblies/runtime/src/infra/s3.rs"),
            canonical_s3,
        );
        assert!(
            canonical_s3_findings.is_empty(),
            "canonical S3 identity/refresh flow is the anti-vacuity green: {canonical_s3_findings:?}"
        );
        for (label, mutated) in [
            (
                "identity inequality deleted",
                canonical_s3.replace(
                    "        !self.general_identity.collides_with(credentials)\n",
                    "        true\n",
                ),
            ),
            (
                "identity inequality reversed",
                canonical_s3.replace(
                    "        !self.general_identity.collides_with(credentials)",
                    "        self.general_identity.collides_with(credentials)",
                ),
            ),
            (
                "identity comparison same binding",
                canonical_s3.replace(
                    "self.0.expose() == credentials.access_key_id()",
                    "credentials.access_key_id() == credentials.access_key_id()",
                ),
            ),
            (
                "refresh wrapper deleted",
                canonical_s3.replace(
                    "DlxIsolatedCredentialsProvider::new(credentials_provider, general_identity)",
                    "credentials_provider",
                ),
            ),
            (
                "identity string bait",
                canonical_s3.replace(
                    "        !self.general_identity.collides_with(credentials)",
                    "        let _bait = \"!self.general_identity.collides_with(credentials)\";\n        true",
                ),
            ),
            (
                "full credentials capability in archive config",
                canonical_s3.replacen(
                    "    general_identity: S3GeneralIdentityMarker,\n}",
                    "    general_identity: S3GeneralIdentityMarker,\n    general_credentials: aws_sdk_s3::config::Credentials,\n}",
                    1,
                ),
            ),
            (
                "full credentials capability in provider",
                canonical_s3.replace(
                    "    general_identity: S3GeneralIdentityMarker,\n}\nimpl<P> DlxIsolatedCredentialsProvider<P>",
                    "    general_identity: S3GeneralIdentityMarker,\n    general_credentials: aws_sdk_s3::config::Credentials,\n}\nimpl<P> DlxIsolatedCredentialsProvider<P>",
                ),
            ),
            (
                "full credentials identity marker",
                canonical_s3.replace(
                    "struct S3GeneralIdentityMarker(secure::SecretText);",
                    "struct S3GeneralIdentityMarker(aws_sdk_s3::config::Credentials);",
                ),
            ),
        ] {
            assert_ne!(mutated, canonical_s3, "mutation must change {label}");
            assert!(
                !required_runtime_source_findings(
                    Path::new("assemblies/runtime/src/infra/s3.rs"),
                    &mutated,
                )
                .is_empty(),
                "S3 DLX shape must reject {label}"
            );
        }
    }

    #[test]
    fn canonical_lifecycle_sources_are_accepted() -> Result<()> {
        let repository = FIXED_FUNCTIONS.join(" ");
        assert!(scan_content(Path::new(LIFECYCLE_REPOSITORY), &repository).is_empty());
        assert!(
            scan_content(
                Path::new(ARCHIVE_PROVIDER),
                "conditional_put ciphertext_get head verify",
            )
            .is_empty()
        );
        assert!(
            required_runtime_source_findings(
                Path::new("assemblies/runtime/src/infra/pg.rs"),
                canonical_pg_runtime_config_fixture(),
            )
            .is_empty(),
        );
        let root = workspace_root()?;
        assert!(
            runtime_phase_funnel_findings(&root)?.is_empty(),
            "canonical phase owners are the runtime anti-vacuity witness",
        );
        Ok(())
    }

    #[test]
    fn canonical_workspace_governance_check_is_green() -> Result<()> {
        let check = DlxLifecycleFunnel;
        assert_eq!(check.name(), "dlx-lifecycle-funnel");
        let (summary, findings) = check.check()?;
        assert_eq!(
            summary,
            "DLX 仅经 verified WORM archive-before-purge 单漏斗，独立 runtime providers 完整"
        );
        assert!(findings.is_empty(), "workspace findings: {findings:?}");
        Ok(())
    }

    #[test]
    fn required_runtime_provider_rejects_comment_and_string_bait() {
        let bait = r#"
            // RSS_PG_DLX_ARCHIVER_USERNAME
            const BAIT: &str = "RSS_PG_DLX_ARCHIVER_PASSWORD";
        "#;
        let missing =
            required_runtime_source_findings(Path::new("assemblies/runtime/src/infra/pg.rs"), bait);
        assert_eq!(
            missing.len(),
            1,
            "comments and unrelated literals are not a typed PG role bundle"
        );

        let s3_bait = r#"
            const DLX_ARCHIVE_S3_BUCKET_ENV: &str = "RSS_DLX_ARCHIVE_S3_BUCKET";
            const BAIT: &str = "aws_config::default_provider::credentials::DefaultCredentialsChain::builder build_s3_client_from_settings provide_credentials";
        "#;
        let missing = required_runtime_source_findings(
            Path::new("assemblies/runtime/src/infra/s3.rs"),
            s3_bait,
        );
        assert_eq!(
            missing.len(),
            1,
            "string bait is not a refreshable provider chain"
        );
    }

    #[test]
    fn structured_guard_rejects_malformed_and_incomplete_runtime_sources() -> Result<()> {
        let root = crate::testutil::unique_tmp("dlx-structured-red");
        std::fs::create_dir_all(root.join("assemblies/runtime/src/phase"))?;
        std::fs::write(root.join(RUNTIME_INFRA_PHASE), "fn {")?;
        assert_eq!(
            runtime_phase_funnel_findings(&root)?[0].rule,
            Rule::MissingRuntimeProvider
        );
        std::fs::write(
            root.join(RUNTIME_INFRA_PHASE),
            "pub async fn build_infra() {}",
        )?;
        assert_eq!(
            runtime_phase_funnel_findings(&root)?[0].rule,
            Rule::MissingRuntimeProvider
        );

        for (path, source) in [
            (
                "crates/diport/src/dlx_lifecycle.rs",
                "pub fn unrelated() {}",
            ),
            (
                "assemblies/runtime/src/event_transport.rs",
                "pub fn unrelated() {}",
            ),
            ("assemblies/runtime/src/unknown.rs", "pub fn unrelated() {}"),
        ] {
            assert!(!required_runtime_source_findings(Path::new(path), source).is_empty());
        }
        assert!(
            !required_runtime_source_findings(
                Path::new("assemblies/runtime/src/infra/pg.rs"),
                "fn {",
            )
            .is_empty()
        );
        assert!(
            !required_runtime_source_findings(
                Path::new("assemblies/runtime/src/infra/s3.rs"),
                "pub fn unrelated() {}",
            )
            .is_empty()
        );
        assert!(
            !required_runtime_source_findings(Path::new("assemblies/runtime/assembly.toml"), "[[",)
                .is_empty()
        );
        assert_eq!(
            required_runtime_source_findings(
                Path::new("assemblies/runtime/assembly.toml"),
                "diportProviders = []",
            )
            .len(),
            3
        );

        std::fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn structured_guard_rejects_malformed_helper_shapes() -> Result<()> {
        let helpers = syn::parse_file(
            r#"
                const NON_STRING: u8 = 1;
                fn not_a_call() { let _value = 1; }
                fn wrong_callee() { unrelated("one", "two"); }
                fn non_string_argument() { build_pg_config_with_user_env(1, "two"); }
                fn closure_call() { (|| {})(); }
            "#,
        )?;
        assert!(const_string_value(&helpers, "NON_STRING").is_none());
        assert!(!function_ends_with_string_config_call(
            &helpers,
            "not_a_call",
            "build_pg_config_with_user_env",
            &["one", "two"],
        ));
        assert!(!function_ends_with_string_config_call(
            &helpers,
            "wrong_callee",
            "build_pg_config_with_user_env",
            &["one", "two"],
        ));
        assert!(!function_ends_with_string_config_call(
            &helpers,
            "non_string_argument",
            "build_pg_config_with_user_env",
            &["one", "two"],
        ));
        assert!(!function_has_path_call(&helpers, "closure_call", "missing"));
        Ok(())
    }

    #[test]
    fn migration_authority_is_exactly_0062_and_0063() {
        let cutover = Path::new(CUTOVER_MIGRATION);
        let lifecycle = Path::new(LIFECYCLE_MIGRATION);
        let future = Path::new("adapters/postgres/migrations/0064_dead_letter_lifecycle.sql");

        assert!(is_migration_in_guard_scope(cutover));
        assert!(is_migration_in_guard_scope(lifecycle));
        assert!(is_authorized_dead_letter_delete(cutover));
        assert!(is_authorized_dead_letter_delete(lifecycle));
        assert!(scan_content(cutover, "DELETE FROM public.dead_letter").is_empty());
        assert!(scan_content(lifecycle, "DELETE FROM public.dead_letter").is_empty());

        assert!(is_migration_in_guard_scope(future));
        assert!(!is_authorized_dead_letter_delete(future));
        assert_eq!(
            scan_content(future, "DELETE FROM public.dead_letter")[0].rule,
            Rule::RawDeadLetterDelete
        );
    }

    #[test]
    fn sql_detection_rejects_case_quotes_only_schema_and_ignores_comments() {
        for sql in [
            r#"DeLeTe FrOm ONLY "public"."dead_letter" WHERE id = $1"#,
            r#"DELETE/**/FROM "tenant_schema"."dead_letter""#,
            "delete from dead_letter",
        ] {
            assert!(contains_dead_letter_delete(sql), "must detect: {sql}");
        }
        assert!(!contains_dead_letter_delete(
            "-- DELETE FROM dead_letter\nSELECT 1 /* DELETE FROM public.dead_letter */"
        ));
    }

    #[test]
    fn anti_vacuity_discovers_unregistered_production_file() -> Result<()> {
        let root = crate::testutil::unique_tmp("dlx-funnel");
        let bypass = root.join("adapters/rogue/src/new_provider.rs");
        let Some(parent) = bypass.parent() else {
            anyhow::bail!("temporary bypass path has no parent");
        };
        std::fs::create_dir_all(parent)?;
        std::fs::write(
            root.join("Cargo.toml"),
            "[workspace]\nresolver = \"2\"\nmembers = [\"adapters/rogue\"]\n",
        )?;
        std::fs::write(
            root.join("adapters/rogue/Cargo.toml"),
            "[package]\nname = \"rogue\"\nversion = \"0.0.0\"\nedition = \"2024\"\n",
        )?;
        std::fs::write(&bypass, "DELETE FROM dead_letter WHERE id = $1")?;

        let findings = scan_workspace(&root)?;
        assert!(findings.iter().any(|item| {
            item.rule == Rule::RawDeadLetterDelete
                && item.subject == "adapters/rogue/src/new_provider.rs"
        }));
        std::fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn runtime_phase_gate_rejects_missing_reordered_comment_string_and_test_bait() -> Result<()> {
        let canonical = canonical_runtime_infra_phase_fixture();
        assert!(
            runtime_phase_owner_findings(
                Path::new(RUNTIME_INFRA_PHASE),
                canonical,
                "ProvidersBuilt",
                "build_infra",
                RUNTIME_INFRA_REQUIRED,
                RUNTIME_INFRA_FLOW,
            )
            .is_empty(),
            "canonical synthetic phase fixture must stay green",
        );

        let helper_expanded = helper_expanded_runtime_infra_phase_fixture();
        assert!(
            runtime_phase_owner_findings(
                Path::new(RUNTIME_INFRA_PHASE),
                helper_expanded,
                "ProvidersBuilt",
                "build_infra",
                RUNTIME_INFRA_REQUIRED,
                RUNTIME_INFRA_FLOW,
            )
            .is_empty(),
            "required tokens in Phase A/B helpers must pass after expansion",
        );
        let helper_uncalled = r#"
            impl<'a> ProvidersBuilt<'a> {
                async fn build_infra(self) {
                    after_required_preflight();
                    PgDlxLifecycleRuntime::setup(
                        &dlx_archiver_pg_config,
                        &dlx_verifier_pg_config,
                        &dlx_purger_pg_config,
                        hot_payload_protector,
                    );
                    DlxLifecycleRuntimeDeps::new(
                        dlx_pg_owner,
                        archive_store,
                        archive_vault_provider,
                        archive_key,
                    );
                    wire_dlx_lifecycle(dlx_lifecycle, dlx_worker);
                }

                async fn phase_a_run_dlx_preflight() {
                    PgDlxLifecycleRuntime::preflight_identities(
                        &dlx_archiver_pg_config,
                        &dlx_verifier_pg_config,
                        &dlx_purger_pg_config,
                    );
                    archive_store.verify();
                    verify_dlx_vault_key_capability(&hot_vault_provider);
                    verify_dlx_vault_key_capability(&archive_vault_provider);
                    Ok(PhaseADlxVerified {
                        dlx_archiver_pg_config,
                        dlx_verifier_pg_config,
                        dlx_purger_pg_config,
                        archive_store,
                        archive_vault_provider,
                    });
                }

                async fn phase_b_setup_postgres() {
                    PgRuntimeDeps::setup_with_audit_admin_config();
                }
            }
        "#;
        assert!(
            !runtime_phase_owner_findings(
                Path::new(RUNTIME_INFRA_PHASE),
                helper_uncalled,
                "ProvidersBuilt",
                "build_infra",
                RUNTIME_INFRA_REQUIRED,
                RUNTIME_INFRA_FLOW,
            )
            .is_empty(),
            "tokens only in uncalled helpers must fail closed without expansion reachability",
        );

        let helper_reordered_verify = helper_expanded.replace(
            "archive_store.verify();\n                    verify_dlx_vault_key_capability(&hot_vault_provider);",
            "verify_dlx_vault_key_capability(&hot_vault_provider);\n                    archive_store.verify();",
        );
        assert_ne!(
            helper_reordered_verify, helper_expanded,
            "helper-expanded verify reorder must change fixture text"
        );
        assert!(
            !runtime_phase_owner_findings(
                Path::new(RUNTIME_INFRA_PHASE),
                &helper_reordered_verify,
                "ProvidersBuilt",
                "build_infra",
                RUNTIME_INFRA_REQUIRED,
                RUNTIME_INFRA_FLOW,
            )
            .is_empty(),
            "verify reorder inside Phase A helper must fail closed after expansion",
        );

        let reordered = canonical
            .replace(
                "archive_store.verify();\n                    verify_dlx_vault_key_capability(&hot_vault_provider);",
                "verify_dlx_vault_key_capability(&hot_vault_provider);\n                    archive_store.verify();",
            );
        assert_ne!(reordered, canonical);
        let missing = "impl<'a> ProvidersBuilt<'a> { async fn unrelated(self) {} }";
        let comment_bait = r#"
            impl<'a> ProvidersBuilt<'a> {
                async fn build_infra(self) {
                    // after_required_preflight() PgDlxLifecycleRuntime::preflight_identities(
                    // archive_store.verify() verify_dlx_vault_key_capability(
                    // PgRuntimeDeps::setup_with_audit_admin_config(
                    // PgDlxLifecycleRuntime::setup( DlxLifecycleRuntimeDeps::new(
                }
            }
        "#;
        let string_bait = r#"
            impl<'a> ProvidersBuilt<'a> {
                async fn build_infra(self) {
                    let _bait = "after_required_preflight() PgDlxLifecycleRuntime::preflight_identities(&dlx_archiver_pg_config,&dlx_verifier_pg_config,&dlx_purger_pg_config,) archive_store.verify() verify_dlx_vault_key_capability(&hot_vault_provider) verify_dlx_vault_key_capability(&archive_vault_provider) PgRuntimeDeps::setup_with_audit_admin_config() PgDlxLifecycleRuntime::setup(&dlx_archiver_pg_config,&dlx_verifier_pg_config,&dlx_purger_pg_config,hot_payload_protector,) DlxLifecycleRuntimeDeps::new(dlx_pg_owner,archive_store,archive_vault_provider,archive_key)";
                }
            }
        "#;
        let test_bait = format!(
            "#[cfg(test)] {}\nimpl<'a> OtherPhase<'a> {{ async fn build_infra(self) {{}} }}",
            canonical
        );
        let body_start = canonical
            .find("                    after_required_preflight();")
            .ok_or_else(|| anyhow::anyhow!("canonical body start"))?;
        let body_end = canonical
            .rfind("                }\n            }")
            .ok_or_else(|| anyhow::anyhow!("canonical body end"))?;
        let nested_test_bait = format!(
            "{}                    #[cfg(test)] {{\n{}                    }}\n{}",
            &canonical[..body_start],
            &canonical[body_start..body_end],
            &canonical[body_end..]
        );
        let dead_branch_bait = format!(
            "{}                    if false {{\n{}                    }}\n{}",
            &canonical[..body_start],
            &canonical[body_start..body_end],
            &canonical[body_end..]
        );
        for (name, source) in [
            ("missing owner", missing),
            ("reordered preflight", reordered.as_str()),
            ("comment bait", comment_bait),
            ("string bait", string_bait),
            ("cfg(test) owner bait", test_bait.as_str()),
            ("nested cfg(test) statement bait", nested_test_bait.as_str()),
            ("dead constant branch bait", dead_branch_bait.as_str()),
        ] {
            let findings = runtime_phase_owner_findings(
                Path::new(RUNTIME_INFRA_PHASE),
                source,
                "ProvidersBuilt",
                "build_infra",
                RUNTIME_INFRA_REQUIRED,
                RUNTIME_INFRA_FLOW,
            );
            assert!(!findings.is_empty(), "{name} must fail closed");
        }
        Ok(())
    }
}
