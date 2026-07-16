//! DLX archive-before-purge 单漏斗守卫。
//!
//! INVARIANT: DLX-LIFECYCLE-FUNNEL-01 { level = "Medium", exec = "verify", source = "code", synthetic_red = "tests::synthetic_red_rejects_every_bypass_class", anti_vacuity = "tests::canonical_lifecycle_sources_are_accepted" } ——
//! hot DLX 只能经 typed lifecycle repository 与不可删除的 verified WORM provider 归档后清理；旧
//! retention/env/decoder 与 raw DELETE 不得回流，runtime 必须显式注入独立 PG/S3/Vault provider。

use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result};
use quote::ToTokens as _;

use crate::diagnostic::{Finding, GovernanceCheck, finding};
use crate::workspace_root;

const LIFECYCLE_REPOSITORY: &str = "adapters/postgres/src/dlx_lifecycle.rs";
const ARCHIVE_PROVIDER: &str = "adapters/s3/src/dlx_archive.rs";
const CUTOVER_MIGRATION: &str = "adapters/postgres/migrations/0062_prepare_dead_letter_cutover.sql";
const LIFECYCLE_MIGRATION: &str = "adapters/postgres/migrations/0063_dead_letter_lifecycle.sql";

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
    findings.extend(runtime_run_funnel_findings(root)?);
    Ok(findings)
}

fn runtime_run_funnel_findings(root: &Path) -> Result<Vec<Finding<Rule>>> {
    const RUNTIME: &str = "assemblies/runtime/src/lib.rs";
    let source = std::fs::read_to_string(root.join(RUNTIME))
        .context("dlx-lifecycle-funnel: read runtime composition root")?;
    let file = match syn::parse_file(&source) {
        Ok(file) => file,
        Err(error) => {
            return Ok(vec![finding(
                Rule::MissingRuntimeProvider,
                RUNTIME.to_owned(),
                format!("无法解析生产 runtime run_startup(): {error}"),
            )]);
        }
    };
    let Some(run) = file.items.iter().find_map(|item| match item {
        syn::Item::Fn(item) if item.sig.ident == "run_startup" && item.sig.asyncness.is_some() => {
            Some(item)
        }
        _ => None,
    }) else {
        return Ok(vec![finding(
            Rule::MissingRuntimeProvider,
            RUNTIME.to_owned(),
            "生产 async run_startup() 缺失".to_owned(),
        )]);
    };
    let rendered = run.block.to_token_stream().to_string();
    let code = mask_rust_strings(&rendered)
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect::<String>();
    let required = [
        "after_required_preflight(",
        "PgDlxLifecycleRuntime::preflight_identities(&dlx_archiver_pg_config,&dlx_verifier_pg_config,&dlx_purger_pg_config,)",
        "archive_store.verify()",
        "verify_dlx_vault_key_capability(&hot_vault_provider",
        "verify_dlx_vault_key_capability(&archive_vault_provider",
        "Ok((dlx_archiver_pg_config,dlx_verifier_pg_config,dlx_purger_pg_config,archive_store,archive_vault_provider,))",
        "PgRuntimeDeps::setup_with_audit_admin_config(",
        "PgDlxLifecycleRuntime::setup(&dlx_archiver_pg_config,&dlx_verifier_pg_config,&dlx_purger_pg_config,hot_payload_protector,)",
        "DlxLifecycleRuntimeDeps::new(dlx_pg_owner,archive_store,archive_vault_provider,archive_key",
        "wire_dlx_lifecycle(dlx_lifecycle)",
    ];
    let mut cursor = 0;
    for expected in required {
        let Some(relative) = code.get(cursor..).and_then(|tail| tail.find(expected)) else {
            return Ok(vec![finding(
                Rule::MissingRuntimeProvider,
                RUNTIME.to_owned(),
                format!(
                    "run_startup() DLX preflight→migration→ACL→wire 数据流缺失或乱序: `{expected}`"
                ),
            )]);
        };
        cursor += relative + expected.len();
    }
    Ok(Vec::new())
}

fn mask_rust_strings(source: &str) -> String {
    let mut output = String::with_capacity(source.len());
    let mut quoted = false;
    let mut escaped = false;
    for character in source.chars() {
        if quoted {
            if escaped {
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else if character == '"' {
                quoted = false;
            }
            output.push(' ');
        } else if character == '"' {
            quoted = true;
            output.push(' ');
        } else {
            output.push(character);
        }
    }
    output
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
            for (port, provider) in [
                (
                    "diport::DlxLifecycleRepository",
                    "postgres::PgDlxLifecycleRepository",
                ),
                ("diport::DlxArchiveStore", "s3::VerifiedS3DlxArchiveStore"),
                ("diport::KeyProvider", "vault::VaultKeyProvider"),
            ] {
                if !has_provider_output_binding(&file, port, provider) {
                    missing.push(format!("provider binding `{port}` -> `{provider}`"));
                }
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
    [
        (
            "build_pg_dlx_archiver_config_from",
            "RSS_PG_DLX_ARCHIVER_USERNAME",
            "RSS_PG_DLX_ARCHIVER_PASSWORD",
        ),
        (
            "build_pg_dlx_verifier_config_from",
            "RSS_PG_DLX_VERIFIER_USERNAME",
            "RSS_PG_DLX_VERIFIER_PASSWORD",
        ),
        (
            "build_pg_dlx_purger_config_from",
            "RSS_PG_DLX_PURGER_USERNAME",
            "RSS_PG_DLX_PURGER_PASSWORD",
        ),
    ]
    .into_iter()
    .filter(|(function, username, password)| {
        !function_ends_with_string_config_call(
            file,
            function,
            "build_pg_config_with_user_env",
            &[username, password],
        )
    })
    .map(|(function, _, _)| format!("structured `{function}` PG env builder"))
    .collect()
}

fn required_s3_shapes(file: &syn::File) -> Vec<String> {
    let mut missing = Vec::new();
    if const_string_value(file, "DLX_ARCHIVE_S3_BUCKET_ENV").as_deref()
        != Some("RSS_DLX_ARCHIVE_S3_BUCKET")
    {
        missing.push("const `DLX_ARCHIVE_S3_BUCKET_ENV` = `RSS_DLX_ARCHIVE_S3_BUCKET`".to_owned());
    }
    for required_call in [
        "aws_config::provider_config::ProviderConfig::without_region",
        "aws_config::default_provider::credentials::DefaultCredentialsChain::builder",
        "build_s3_client_from_settings",
    ] {
        if !function_has_path_call(file, "build_s3_dlx_archive_store_from", required_call) {
            missing.push(format!("DLX refreshable provider call `{required_call}`"));
        }
    }
    if !function_has_method_call(
        file,
        "build_s3_dlx_archive_store_from",
        "provide_credentials",
    ) {
        missing.push("DLX provider startup credential resolution".to_owned());
    }
    missing
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

fn function_has_path_call(file: &syn::File, function: &str, expected: &str) -> bool {
    let Some(item) = file.items.iter().find_map(|item| match item {
        syn::Item::Fn(item) if item.sig.ident == function => Some(item),
        _ => None,
    }) else {
        return false;
    };
    let mut calls = FunctionCalls::default();
    syn::visit::Visit::visit_block(&mut calls, &item.block);
    calls.path_calls.iter().any(|call| call == expected)
}

fn function_has_method_call(file: &syn::File, function: &str, expected: &str) -> bool {
    let Some(item) = file.items.iter().find_map(|item| match item {
        syn::Item::Fn(item) if item.sig.ident == function => Some(item),
        _ => None,
    }) else {
        return false;
    };
    let mut calls = FunctionCalls::default();
    syn::visit::Visit::visit_block(&mut calls, &item.block);
    calls.method_calls.iter().any(|call| call == expected)
}

#[derive(Default)]
struct FunctionCalls {
    path_calls: Vec<String>,
    method_calls: Vec<String>,
}

impl<'ast> syn::visit::Visit<'ast> for FunctionCalls {
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let syn::Expr::Path(path) = call.func.as_ref() {
            self.path_calls.push(
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

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        self.method_calls.push(call.method.to_string());
        syn::visit::visit_expr_method_call(self, call);
    }
}

fn has_provider_output_binding(file: &syn::File, port: &str, provider: &str) -> bool {
    let Some(binding_const) = file.items.iter().find_map(|item| match item {
        syn::Item::Const(item) if item.ident == "PROVIDER_OUTPUT_BINDINGS" => Some(item),
        _ => None,
    }) else {
        return false;
    };
    let array = match binding_const.expr.as_ref() {
        syn::Expr::Reference(reference) => match reference.expr.as_ref() {
            syn::Expr::Array(array) => Some(array),
            _ => None,
        },
        syn::Expr::Array(array) => Some(array),
        _ => None,
    };
    array.is_some_and(|array| {
        array.elems.iter().any(|element| {
            let syn::Expr::Struct(binding) = element else {
                return false;
            };
            let field = |name: &str| {
                binding.fields.iter().find_map(|field| {
                    let syn::Member::Named(member) = &field.member else {
                        return None;
                    };
                    if member != name {
                        return None;
                    }
                    match &field.expr {
                        syn::Expr::Lit(literal) => match &literal.lit {
                            syn::Lit::Str(value) => Some(value.value()),
                            _ => None,
                        },
                        _ => None,
                    }
                })
            };
            field("port").as_deref() == Some(port) && field("provider").as_deref() == Some(provider)
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
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
    }

    #[test]
    fn canonical_lifecycle_sources_are_accepted() {
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
                r#"
                    pub(crate) fn build_pg_dlx_archiver_config_from(
                        get: impl Fn(&str) -> Option<String>,
                    ) -> Result<(), ()> {
                        build_pg_config_with_user_env(
                            &get,
                            "RSS_PG_DLX_ARCHIVER_USERNAME",
                            "RSS_PG_DLX_ARCHIVER_PASSWORD",
                        )
                    }
                    pub(crate) fn build_pg_dlx_verifier_config_from(
                        get: impl Fn(&str) -> Option<String>,
                    ) -> Result<(), ()> {
                        build_pg_config_with_user_env(
                            &get,
                            "RSS_PG_DLX_VERIFIER_USERNAME",
                            "RSS_PG_DLX_VERIFIER_PASSWORD",
                        )
                    }
                    pub(crate) fn build_pg_dlx_purger_config_from(
                        get: impl Fn(&str) -> Option<String>,
                    ) -> Result<(), ()> {
                        build_pg_config_with_user_env(
                            &get,
                            "RSS_PG_DLX_PURGER_USERNAME",
                            "RSS_PG_DLX_PURGER_PASSWORD",
                        )
                    }
                "#,
            )
            .is_empty(),
        );
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
            3,
            "comments and unrelated literals are not providers"
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
            4,
            "string bait is not a refreshable provider chain"
        );
    }

    #[test]
    fn structured_guard_rejects_malformed_and_incomplete_runtime_sources() -> Result<()> {
        let root = crate::testutil::unique_tmp("dlx-structured-red");
        std::fs::create_dir_all(root.join("assemblies/runtime/src"))?;
        std::fs::write(root.join("assemblies/runtime/src/lib.rs"), "fn {")?;
        assert_eq!(
            runtime_run_funnel_findings(&root)?[0].rule,
            Rule::MissingRuntimeProvider
        );
        std::fs::write(
            root.join("assemblies/runtime/src/lib.rs"),
            "pub fn run_startup() {}",
        )?;
        assert_eq!(
            runtime_run_funnel_findings(&root)?[0].rule,
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
                const PROVIDER_OUTPUT_BINDINGS: &[Binding] = &[Binding {
                    port: "diport::DlxLifecycleRepository",
                    provider: 1,
                }];
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
        assert!(!has_provider_output_binding(
            &helpers,
            "diport::DlxLifecycleRepository",
            "postgres::PgDlxLifecycleRepository",
        ));

        let scalar_binding = syn::parse_file("const PROVIDER_OUTPUT_BINDINGS: u8 = 1;")?;
        assert!(!has_provider_output_binding(
            &scalar_binding,
            "port",
            "provider"
        ));
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
        std::fs::create_dir_all(root.join("assemblies/runtime/src"))?;
        std::fs::write(
            root.join("assemblies/runtime/src/lib.rs"),
            "pub async fn run_startup() {}\n",
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
    fn runtime_order_gate_rejects_string_bait_and_missing_live_preflight() -> Result<()> {
        let root = crate::testutil::unique_tmp("dlx-runtime-order");
        std::fs::create_dir_all(root.join("assemblies/runtime/src"))?;
        std::fs::write(
            root.join("assemblies/runtime/src/lib.rs"),
            r#"pub async fn run_startup() {
                let _bait = "after_required_preflight(PgDlxLifecycleRuntime::preflight_identity(&dlx_pg_config))";
            }
            "#,
        )?;
        let findings = runtime_run_funnel_findings(&root)?;
        assert!(findings.iter().any(|item| {
            item.rule == Rule::MissingRuntimeProvider
                && item.detail.contains("preflight→migration→ACL→wire")
        }));
        std::fs::remove_dir_all(root)?;
        Ok(())
    }
}
