//! `pg-tenant-tx-guard` —— Postgres tenant-table raw-pool / TxManager bypass guard.
//!
//! INVARIANT: TENANCY-PG-TX-FUNNEL-01 { level = "Medium", exec = "verify", source = "code", synthetic_red = "tests::red_core_file_exception_does_not_mask_raw_tenant_access", anti_vacuity = "tests::green_scoped_tenant_and_global_tables_pass" } —
//! tenant-table production paths must go through
//! `PgTenantPool::{read,write,co_tx_with_outbox}` or the lower-level `cotx` funnel. Raw
//! `sqlx::PgPool` / direct connection / global transaction paths are allowed only for explicitly
//! named global infrastructure or maintenance exceptions.
//!
//! This guard is a Medium backstop for the Hard typed wrapper in `adapters/postgres/src/cotx/`
//! and the canonical fact funnels in `outbox.rs` / `outbox_cdc.rs`.
//!
//! INVARIANT: LOCALTX-PG-RETRY-PLACEMENT-01 { level = "Medium", exec = "verify", source = "code", synthetic_red = "tests::retry_guard_rejects_secret_contract_attribution_bypasses", anti_vacuity = "tests::retry_guard_real_workspace_contains_all_exact_boundaries" } —
//! Postgres retry wrappers are confined to their exact config commit, secret mutation, password
//! change, and session logout boundaries. Each LocalTx owner must consume its command-carried
//! generated observation beside `retry_write`; `PgSecretUnitOfWork::publish` is the only settings
//! secret LocalTx owner;
//! internal publish / republish must use the generic runner and may not impersonate the HTTP
//! contract.
//!
//! INVARIANT: TENANCY-SECRET-KEY-MUTATION-01 { level = "Medium", exec = "verify", source = "code", synthetic_red = "tests::secret_ref_mutation_guard_rejects_split_or_legacy_owners", anti_vacuity = "tests::secret_ref_mutation_guard_real_workspace_has_exact_capability_sites" } —
//! production `secret_refs` mutations are append-only INSERTs confined to the transaction-bound
//! `key_lock::LockedSecretKey::{cas_insert,append_tombstone}` capability. `SecretRepo` is read-only;
//! `PgSecretUnitOfWork::{publish,publish_internal,republish}` share one `cas_insert_locked` funnel,
//! while `delete` alone acquires the same keyed capability and appends a tombstone. The capability
//! has one exact mint site: `acquire`, which must bind the stored tenant/key to the transaction
//! advisory lock before returning the value.
//!
//! INVARIANT: OUTBOX-FACT-FUNNEL-01 { level = "Medium", exec = "verify", source = "code", synthetic_red = "tests::red_outbox_log_insert_outside_cdc_funnel", anti_vacuity = "tests::green_outbox_log_insert_is_owned_by_cdc_funnel" } —
//! production `outbox` / `outbox_log` INSERTs are confined to their canonical fingerprint funnels.
//! It intentionally does not replace `setlocal-funnel`: that guard owns "GUC write literal is
//! unique"; this guard owns "tenant table SQL cannot be reached through raw pool/TxManager".
//!
//! `ref: rust-analyzer xtask/src/main.rs@8d38942ce80559c09548f6f88a0564d8c1fff6d2`
//! `ref: sqlx sqlx-core/src/transaction.rs@bab1b022bd56a64f9a08b46b36b97c5cff19d77e`

use anyhow::{Context, Result};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use crate::diagnostic::{self, GovernanceCheck, finding};

pub(crate) type Finding = diagnostic::Finding<Rule>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Rule {
    RawTenantTableAccess,
    RawTenantPoolField,
    RawOutboxInsert,
    OutboxAppendBypass,
    TxCapabilityMintOutsideFunnel,
    TenantTablesAbsent,
    ProdFilesAbsent,
    SqlSitesAbsent,
    OutboxInsertSitesAbsent,
    StaleException,
    /// transaction retry primitive or postgres wrapper used outside the sanctioned UoW boundary.
    RetryPlacement,
    /// real workspace scan did not find every required retry boundary.
    RetrySitesAbsent,
    /// `secret_refs` mutation escaped the keyed `LockedSecretKey` capability.
    SecretRefMutationBypass,
    /// canonical `LockedSecretKey` mutation sites are absent or duplicated.
    SecretRefMutationSitesAbsent,
}

pub(crate) struct PgTenantTxGuard;

const FAULT_MATRIX_FILE: &str = "fault_matrix.rs";
const FAULT_MATRIX_LIB_GATE: &str = "#[cfg(feature = \"fault-matrix-test-support\")]";
const FAULT_MATRIX_OWNER_POOL: &str = "fault-matrix-owner-pool";
const FAULT_MATRIX_SEED_OUTBOX: &str = "fault-matrix-seed-outbox";
const FAULT_MATRIX_OUTBOX_STATUS_COUNT: &str = "fault-matrix-outbox-status-count";
const FAULT_MATRIX_DEAD_LETTER_OBSERVATION: &str = "fault-matrix-dead-letter-observation";
const FAULT_MATRIX_OUTBOX_CONTRACT_COUNT: &str = "fault-matrix-outbox-contract-count";
const FAULT_MATRIX_AGE_OUTBOX_PUBLISHING: &str = "fault-matrix-age-outbox-publishing";
const FAULT_MATRIX_AGE_INBOX_CLAIM: &str = "fault-matrix-age-inbox-claim";

impl GovernanceCheck for PgTenantTxGuard {
    type Rule = Rule;

    fn name(&self) -> &'static str {
        "pg-tenant-tx-guard"
    }

    fn check(&self) -> Result<(String, Vec<Finding>)> {
        let root = crate::workspace_root()?;
        let migrations = load_sql_files(&root.join("adapters/postgres/migrations"))?;
        let files = load_prod_rs(&root.join("adapters/postgres/src"))?;
        let settings_ports_path = root.join("crates/settings/src/ports.rs");
        let settings_ports = std::fs::read_to_string(&settings_ports_path)
            .with_context(|| format!("读 {} 失败", settings_ports_path.display()))?;
        let (summary, mut findings) = scan_guard(&migrations, &files);
        findings.extend(secret_repo_read_only_findings(
            "crates/settings/src/ports.rs",
            &settings_ports,
        ));
        Ok((summary, findings))
    }
}

fn load_sql_files(dir: &Path) -> Result<Vec<(String, String)>> {
    let mut entries: Vec<_> = std::fs::read_dir(dir)
        .with_context(|| format!("读迁移目录 {} 失败", dir.display()))?
        .collect::<Result<Vec<_>, _>>()
        .with_context(|| "遍历迁移目录条目失败")?;
    entries.sort_by_key(|e| e.file_name());
    let mut files = Vec::new();
    for entry in entries {
        let path = entry.path();
        if path.extension().is_some_and(|e| e == "sql") {
            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("")
                .to_string();
            files.push((
                name,
                std::fs::read_to_string(&path)
                    .with_context(|| format!("读迁移文件 {} 失败", path.display()))?,
            ));
        }
    }
    Ok(files)
}

fn load_prod_rs(dir: &Path) -> Result<Vec<(String, String)>> {
    let mut paths = collect_rs_paths(dir)?;
    paths.sort();
    let mut files = Vec::new();
    for path in paths {
        if is_test_file(&path) || is_feature_gated_harness(dir, &path)? {
            continue;
        }
        let rel = path
            .strip_prefix(dir)
            .unwrap_or(&path)
            .to_string_lossy()
            .replace('\\', "/");
        files.push((
            rel,
            std::fs::read_to_string(&path)
                .with_context(|| format!("读 {} 失败", path.display()))?,
        ));
    }
    Ok(files)
}

fn collect_rs_paths(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    if !dir.is_dir() {
        return Ok(out);
    }
    for entry in std::fs::read_dir(dir).with_context(|| format!("遍历 {} 失败", dir.display()))?
    {
        let path = entry
            .with_context(|| format!("读条目失败（{}）", dir.display()))?
            .path();
        if path.is_dir() {
            out.extend(collect_rs_paths(&path)?);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
    Ok(out)
}

fn is_feature_gated_harness(src_dir: &Path, path: &Path) -> Result<bool> {
    let rel = path
        .strip_prefix(src_dir)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/");
    if rel != "fault_matrix.rs" {
        return Ok(false);
    }
    let lib_content = std::fs::read_to_string(src_dir.join("lib.rs"))
        .with_context(|| format!("读 {} 失败", src_dir.join("lib.rs").display()))?;
    Ok(is_feature_gated_harness_rel(&rel, &lib_content))
}

fn is_feature_gated_harness_rel(rel: &str, lib_content: &str) -> bool {
    rel == "fault_matrix.rs" && fault_matrix_module_has_feature_gate(lib_content)
}

fn fault_matrix_module_has_feature_gate(lib_content: &str) -> bool {
    let stripped = strip_rust_comment_lines(lib_content);
    let mut pending_attrs = Vec::new();
    for line in stripped.lines().map(str::trim) {
        if line.is_empty() {
            continue;
        }
        if line.starts_with("#[") {
            pending_attrs.push(line);
            continue;
        }
        if matches!(line, "pub mod fault_matrix;" | "mod fault_matrix;") {
            return pending_attrs.iter().any(|attr| {
                attr.starts_with("#[cfg(")
                    && attr.contains("feature")
                    && attr.contains("\"fault-matrix-test-support\"")
            });
        }
        pending_attrs.clear();
    }
    false
}

fn is_test_file(path: &Path) -> bool {
    let stem = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    stem == "integration_tests.rs"
        || stem == "test_pg.rs"
        || stem.ends_with("_test.rs")
        || stem.ends_with("_tests.rs")
        || path.components().any(|c| c.as_os_str() == "tests")
}

pub(crate) fn scan_guard(
    migrations: &[(String, String)],
    files: &[(String, String)],
) -> (String, Vec<Finding>) {
    let tenant_tables = tenant_tables_from_migrations(migrations);
    let mut findings = Vec::new();
    if tenant_tables.is_empty() {
        findings.push(finding(
            Rule::TenantTablesAbsent,
            "adapters/postgres/migrations",
            "未从迁移派生到任何 tenant 表，guard 真空化",
        ));
    }
    if files.is_empty() {
        findings.push(finding(
            Rule::ProdFilesAbsent,
            "adapters/postgres/src",
            "未扫描到任何生产 Rust 源文件，guard 真空化",
        ));
    }

    let mut state = ScanState::default();
    findings.extend(fault_matrix_exception_staleness(files));

    for (rel, content) in files {
        findings.extend(scan_source_file(rel, content, &tenant_tables, &mut state));
    }

    for expected in [
        "config-legacy-plaintext-startup-probe",
        "config-value-maintenance",
    ] {
        if !state.allowed_exceptions.contains(expected) {
            findings.push(finding(
                Rule::StaleException,
                expected,
                "命名 raw-pool 例外未命中任何生产 site；删除例外或恢复对应测试覆盖",
            ));
        }
    }

    if state.tenant_sql_sites == 0 {
        findings.push(finding(
            Rule::SqlSitesAbsent,
            "adapters/postgres/src",
            "未扫描到任何 tenant-table SQL site，guard 真空化",
        ));
    }
    if files
        .iter()
        .any(|(rel, _)| matches!(rel.as_str(), "outbox.rs" | "outbox_cdc.rs"))
    {
        for required in [
            "outbox.rs::append_outbox",
            "outbox.rs::append_replayed_outbox",
            "outbox_cdc.rs::append_outbox_log",
        ] {
            if state.outbox_insert_sites.get(required).copied() != Some(1) {
                findings.push(finding(
                    Rule::OutboxInsertSitesAbsent,
                    required,
                    "canonical outbox INSERT must occur exactly once in its exact owner symbol",
                ));
            }
        }
    }
    findings.extend(required_retry_site_findings(files, &state.retry_sites));
    findings.extend(required_secret_ref_site_findings(
        files,
        &state.secret_ref_mutation_sites,
    ));

    let summary = format!(
        "{} tenant 表；{} 个生产文件；{} 个 tenant SQL 文件；{} 个 raw pattern",
        tenant_tables.len(),
        files.len(),
        state.tenant_sql_sites,
        state.raw_sites
    );
    (summary, findings)
}

fn required_retry_site_findings(
    files: &[(String, String)],
    sites: &BTreeSet<&'static str>,
) -> Vec<Finding> {
    if !files.iter().any(|(rel, _)| rel == "tx_retry.rs") {
        return Vec::new();
    }
    [
        "settings-config-commit",
        "settings-secret-publish",
        "settings-secret-publish-internal",
        "settings-secret-republish",
        "identity-password-change",
        "identity-session-logout",
    ]
    .into_iter()
    .filter(|required| !sites.contains(required))
    .map(|required| {
        finding(
            Rule::RetrySitesAbsent,
            required,
            "sanctioned transaction retry boundary was not found",
        )
    })
    .collect()
}

fn required_secret_ref_site_findings(
    files: &[(String, String)],
    sites: &BTreeMap<&'static str, usize>,
) -> Vec<Finding> {
    if !files.iter().any(|(rel, _)| rel == "secret_repo.rs") {
        return Vec::new();
    }
    [
        "secret-key-lock-acquire",
        "secret-key-advisory-lock",
        "secret-key-capability-mint",
        "secret-key-cas-insert",
        "secret-key-append-tombstone",
        "secret-uow-cas-funnel",
        "secret-uow-publish-cas",
        "secret-uow-publish-internal-cas",
        "secret-uow-republish-cas",
        "secret-uow-delete-tombstone",
    ]
        .into_iter()
        .filter(|required| sites.get(required).copied() != Some(1))
        .map(|required| {
            finding(
                Rule::SecretRefMutationSitesAbsent,
                required,
                "SecretRepo must stay read-only and PgSecretUnitOfWork must own the exact shared CAS and keyed tombstone funnels",
            )
        })
        .collect()
}

#[derive(Default)]
struct ScanState {
    tenant_sql_sites: usize,
    raw_sites: usize,
    allowed_exceptions: BTreeSet<&'static str>,
    retry_sites: BTreeSet<&'static str>,
    outbox_insert_sites: BTreeMap<&'static str, usize>,
    secret_ref_mutation_sites: BTreeMap<&'static str, usize>,
}

fn scan_source_file(
    rel: &str,
    content: &str,
    tenant_tables: &BTreeSet<String>,
    state: &mut ScanState,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let stripped = strip_rust_comment_lines(&strip_cfg_test_modules(content));
    let expanded = expand_simple_table_consts(&stripped).to_lowercase();
    findings.extend(retry_placement_findings(
        rel,
        &stripped,
        &mut state.retry_sites,
    ));
    findings.extend(secret_ref_mutation_findings(
        rel,
        &stripped,
        &mut state.secret_ref_mutation_sites,
    ));
    let tenant_hits = tenant_table_hits(&expanded, tenant_tables);
    state.tenant_sql_sites += usize::from(!tenant_hits.is_empty());
    let helper_tables = tenant_pgconnection_helpers(&expanded, tenant_tables);
    let (raw_hits, site_exceptions) =
        raw_tenant_accesses(rel, &expanded, tenant_tables, &helper_tables);
    let (outbox_insert_hits, outbox_exceptions, outbox_insert_sites) =
        raw_outbox_insert_sites(rel, &expanded);
    let append_bypass_hits = outbox_append_bypass_sites(rel, &expanded);
    let capability_mint_hits = tx_capability_mint_sites(rel, &expanded);
    state.allowed_exceptions.extend(site_exceptions);
    state.allowed_exceptions.extend(outbox_exceptions);
    for site in outbox_insert_sites {
        *state.outbox_insert_sites.entry(site).or_default() += 1;
    }
    let raw_pool_field_hits = raw_tenant_pool_fields(&expanded);
    let raw_pool_field_exception = raw_pool_field_exception(rel, &expanded);
    note_raw_pool_field_exception(
        &mut state.allowed_exceptions,
        raw_pool_field_exception,
        &raw_pool_field_hits,
    );
    state.raw_sites += raw_hits.len()
        + raw_pool_field_hits.len()
        + outbox_insert_hits.len()
        + append_bypass_hits.len()
        + capability_mint_hits.len();

    findings.extend(outbox_insert_hits.iter().map(|hit| {
        finding(
            Rule::RawOutboxInsert,
            site_subject(rel, hit.line),
            "outbox rows must be created through outbox.rs TxCapability append funnel",
        )
    }));
    findings.extend(append_bypass_hits.iter().map(|hit| {
        finding(
            Rule::OutboxAppendBypass,
            site_subject(rel, hit.line),
            format!(
                "outbox producer opens a raw transaction near {:?}; use PgTenantPool write/co-tx funnel",
                hit.pattern
            ),
        )
    }));
    findings.extend(capability_mint_hits.iter().map(|hit| {
        finding(
            Rule::TxCapabilityMintOutsideFunnel,
            site_subject(rel, hit.line),
            "TxCapability minting is restricted to transaction funnel modules",
        )
    }));
    findings.extend(raw_pool_field_findings(
        rel,
        &tenant_hits,
        &raw_pool_field_hits,
        raw_pool_field_exception,
    ));
    findings.extend(raw_hits.iter().map(|hit| {
        finding(
            Rule::RawTenantTableAccess,
            site_subject(rel, hit.line),
            format!(
                "tenant tables {:?} touched through raw pattern {:?}; use PgTenantPool scoped methods",
                hit.tables, hit.pattern
            ),
        )
    }));
    findings
}

fn retry_placement_findings(
    rel: &str,
    content: &str,
    sites: &mut BTreeSet<&'static str>,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let syntax = match syn::parse_file(content) {
        Ok(syntax) => syntax,
        Err(error) => {
            findings.push(finding(
                Rule::RetryPlacement,
                rel,
                format!("cannot parse production Rust for retry placement: {error}"),
            ));
            return findings;
        }
    };
    let aliases = retry_aliases(&syntax);
    let mut scan = RetryAstScan::new(aliases);
    syn::visit::Visit::visit_file(&mut scan, &syntax);

    for call in &scan.direct_calls {
        if rel != "tx_retry.rs" || call.function.as_deref() != Some("run_pg_tx_retry_core") {
            findings.push(finding(
                Rule::RetryPlacement,
                site_subject(rel, call.line),
                "consistency::run_tx_retry may only be called by tx_retry.rs::run_pg_tx_retry_core",
            ));
        }
    }
    findings.extend(scan.legacy_command_evidence_calls.iter().map(|(line, function)| {
        finding(
            Rule::RetryPlacement,
            site_subject(rel, *line),
            format!(
                "Postgres adapter function {} must consume typed command evidence; removed optional LocalTx observation factories are forbidden",
                function.as_deref().unwrap_or("<module>")
            ),
        )
    }));
    if scan.wrapper_calls.is_empty() {
        return findings;
    }

    if rel == "secret_repo.rs" {
        findings.extend(settings_secret_retry_findings(&scan, sites));
        return findings;
    }

    let allowed = match rel {
        "config_repo.rs" => Some(("commit", "settings-config-commit")),
        "credential_repo.rs" => Some(("apply_password_change", "identity-password-change")),
        "session_lifecycle.rs" => Some(("logout", "identity-session-logout")),
        "refresh_token_store.rs" => Some(("rotate", "identity-refresh-rotate")),
        "audit_repo.rs" => Some(("append", "audit-append")),
        _ => None,
    };
    let Some((fn_marker, site)) = allowed else {
        for call in scan.wrapper_calls {
            findings.push(finding(
                Rule::RetryPlacement,
                site_subject(rel, call.line),
                "Postgres retry wrappers are restricted to the closed settings, identity, and audit transaction owners",
            ));
        }
        return findings;
    };

    for call in &scan.wrapper_calls {
        if call.function.as_deref() != Some(fn_marker) {
            findings.push(finding(
                Rule::RetryPlacement,
                site_subject(rel, call.line),
                format!("Postgres retry wrapper call must remain inside {fn_marker}"),
            ));
        }
    }
    let calls: Vec<_> = scan
        .wrapper_calls
        .iter()
        .filter(|call| call.function.as_deref() == Some(fn_marker))
        .collect();
    let valid = calls.len() == 1
        && match rel {
            "config_repo.rs" => valid_settings_retry(calls[0]),
            "credential_repo.rs" => valid_identity_password_retry(calls[0]),
            "session_lifecycle.rs" => valid_identity_logout_retry(calls[0]),
            "refresh_token_store.rs" => valid_identity_refresh_retry(calls[0]),
            "audit_repo.rs" => valid_audit_append_retry(calls[0]),
            _ => false,
        };
    if valid {
        sites.insert(site);
    } else {
        findings.push(finding(
            Rule::RetryPlacement,
            rel,
            format!(
                "{fn_marker} must contain exactly one correctly typed retry wrapper call with its closed boundary and transaction primitive"
            ),
        ));
    }
    findings
}

fn settings_secret_retry_findings(
    scan: &RetryAstScan,
    sites: &mut BTreeSet<&'static str>,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let exact_owners = [
        (
            "publish",
            "settings-secret-publish",
            valid_settings_secret_retry as fn(&RetryCall) -> bool,
        ),
        (
            "publish_internal",
            "settings-secret-publish-internal",
            valid_settings_secret_generic_retry as fn(&RetryCall) -> bool,
        ),
        (
            "republish",
            "settings-secret-republish",
            valid_settings_secret_generic_retry as fn(&RetryCall) -> bool,
        ),
    ];
    for (function, site, valid) in exact_owners {
        let calls = scan
            .wrapper_calls
            .iter()
            .filter(|call| {
                call.impl_type.as_deref() == Some("PgSecretUnitOfWork")
                    && call.function.as_deref() == Some(function)
            })
            .collect::<Vec<_>>();
        if calls.len() == 1 && valid(calls[0]) {
            sites.insert(site);
        } else if !calls.is_empty() {
            findings.push(finding(
                Rule::RetryPlacement,
                format!("secret_repo.rs::PgSecretUnitOfWork::{function}"),
                format!(
                    "{function} must contain exactly one correctly typed retry wrapper, closed settings secret boundary, and retry_write transaction primitive"
                ),
            ));
        }
    }
    for call in &scan.wrapper_calls {
        let allowed_owner = call.impl_type.as_deref() == Some("PgSecretUnitOfWork")
            && matches!(
                call.function.as_deref(),
                Some("publish" | "publish_internal" | "republish")
            );
        if !allowed_owner {
            findings.push(finding(
                Rule::RetryPlacement,
                site_subject("secret_repo.rs", call.line),
                "settings secret retry wrappers are restricted to PgSecretUnitOfWork::{publish,publish_internal,republish}; SecretRepo::save and private/delete owners are forbidden",
            ));
        }
    }
    findings
}

type RetryScope = BTreeMap<String, Option<RetryBinding>>;
type ObservationScope = BTreeMap<String, Option<CommandEvidence>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RetryBinding {
    Symbol(RetrySymbol),
    ConsistencyModule,
    TxRetryModule,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RetrySymbol {
    Direct,
    Generic,
    Local,
}

fn retry_aliases(file: &syn::File) -> RetryScope {
    let mut aliases = RetryScope::from([
        (
            "run_tx_retry".to_string(),
            Some(RetryBinding::Symbol(RetrySymbol::Direct)),
        ),
        (
            "run_pg_tx_retry".to_string(),
            Some(RetryBinding::Symbol(RetrySymbol::Generic)),
        ),
        (
            "run_pg_localtx_retry".to_string(),
            Some(RetryBinding::Symbol(RetrySymbol::Local)),
        ),
    ]);
    for item in &file.items {
        if let syn::Item::Use(item_use) = item {
            collect_retry_use_aliases(&item_use.tree, &[], &mut aliases);
        }
    }
    for item in &file.items {
        if let syn::Item::Fn(item_fn) = item {
            aliases.insert(item_fn.sig.ident.to_string(), None);
        }
    }
    aliases
}

fn collect_retry_use_aliases(tree: &syn::UseTree, prefix: &[String], aliases: &mut RetryScope) {
    match tree {
        syn::UseTree::Path(path) => {
            let mut nested = prefix.to_vec();
            nested.push(path.ident.to_string());
            collect_retry_use_aliases(&path.tree, &nested, aliases);
        }
        syn::UseTree::Group(group) => {
            for item in &group.items {
                collect_retry_use_aliases(item, prefix, aliases);
            }
        }
        syn::UseTree::Name(name) => note_retry_alias(
            prefix,
            &name.ident.to_string(),
            &name.ident.to_string(),
            aliases,
        ),
        syn::UseTree::Rename(rename) => note_retry_alias(
            prefix,
            &rename.ident.to_string(),
            &rename.rename.to_string(),
            aliases,
        ),
        syn::UseTree::Glob(_) => note_retry_glob(prefix, aliases),
    }
}

fn note_retry_alias(prefix: &[String], original: &str, local: &str, aliases: &mut RetryScope) {
    if let Some(binding) = retry_binding_for_import(prefix, original) {
        aliases.insert(local.to_string(), Some(binding));
    }
}

fn note_retry_glob(prefix: &[String], aliases: &mut RetryScope) {
    for name in ["run_tx_retry", "run_pg_tx_retry", "run_pg_localtx_retry"] {
        note_retry_alias(prefix, name, name, aliases);
    }
}

fn retry_symbol_for_import(prefix: &[String], name: &str) -> Option<RetrySymbol> {
    match (prefix, name) {
        ([root], "run_tx_retry") if root == "consistency" => Some(RetrySymbol::Direct),
        ([root, module], "run_pg_tx_retry")
            if matches!(root.as_str(), "crate" | "super" | "self") && module == "tx_retry" =>
        {
            Some(RetrySymbol::Generic)
        }
        ([root, module], "run_pg_localtx_retry")
            if matches!(root.as_str(), "crate" | "super" | "self") && module == "tx_retry" =>
        {
            Some(RetrySymbol::Local)
        }
        _ => None,
    }
}

fn retry_binding_for_import(prefix: &[String], name: &str) -> Option<RetryBinding> {
    if let Some(symbol) = retry_symbol_for_import(prefix, name) {
        return Some(RetryBinding::Symbol(symbol));
    }
    match (prefix, name) {
        ([], "consistency") => Some(RetryBinding::ConsistencyModule),
        ([root], "consistency") if matches!(root.as_str(), "crate" | "super" | "self") => {
            Some(RetryBinding::ConsistencyModule)
        }
        ([], "tx_retry") => Some(RetryBinding::TxRetryModule),
        ([root], "tx_retry") if matches!(root.as_str(), "crate" | "super" | "self") => {
            Some(RetryBinding::TxRetryModule)
        }
        _ => None,
    }
}

fn retry_symbol_from_module(binding: RetryBinding, name: &str) -> Option<RetrySymbol> {
    match (binding, name) {
        (RetryBinding::ConsistencyModule, "run_tx_retry") => Some(RetrySymbol::Direct),
        (RetryBinding::TxRetryModule, "run_pg_tx_retry") => Some(RetrySymbol::Generic),
        (RetryBinding::TxRetryModule, "run_pg_localtx_retry") => Some(RetrySymbol::Local),
        _ => None,
    }
}

#[derive(Debug)]
struct RetryCall {
    line: usize,
    impl_type: Option<String>,
    function: Option<String>,
    wrapper: Option<RetryWrapper>,
    arguments: Vec<RetryExprFacts>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RetryWrapper {
    Generic,
    Local,
}

#[derive(Debug, Default)]
struct RetryExprFacts {
    exact_path: Option<String>,
    command_evidence: Option<CommandEvidence>,
    operation_method: Option<String>,
    scoped_operation_calls: usize,
    legacy_write: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CommandEvidence {
    PasswordChange,
    SessionLogout,
    RefreshRotation,
    SecretPublish,
}

struct RetryAstScan {
    scopes: Vec<RetryScope>,
    observation_scopes: Vec<ObservationScope>,
    current_impl: Option<String>,
    current_function: Option<String>,
    current_typed_command: Option<(String, CommandEvidence)>,
    direct_calls: Vec<RetryCall>,
    wrapper_calls: Vec<RetryCall>,
    legacy_command_evidence_calls: Vec<(usize, Option<String>)>,
}

impl RetryAstScan {
    fn new(aliases: RetryScope) -> Self {
        Self {
            scopes: vec![aliases],
            observation_scopes: vec![ObservationScope::new()],
            current_impl: None,
            current_function: None,
            current_typed_command: None,
            direct_calls: Vec::new(),
            wrapper_calls: Vec::new(),
            legacy_command_evidence_calls: Vec::new(),
        }
    }

    fn visit_function(&mut self, name: String, signature: &syn::Signature, block: &syn::Block) {
        let previous = self.current_function.replace(name.clone());
        let previous_command = std::mem::replace(
            &mut self.current_typed_command,
            typed_command_param(signature),
        );
        self.scopes.push(RetryScope::new());
        self.observation_scopes.push(ObservationScope::new());
        for input in &signature.inputs {
            if let syn::FnArg::Typed(typed) = input {
                self.shadow_pattern(&typed.pat);
            }
        }
        <Self as syn::visit::Visit>::visit_block(self, block);
        self.observation_scopes.pop();
        self.scopes.pop();
        self.current_typed_command = previous_command;
        self.current_function = previous;
    }

    fn resolve(&self, path: &syn::Path) -> Option<RetrySymbol> {
        let segments = path
            .segments
            .iter()
            .map(|segment| segment.ident.to_string())
            .collect::<Vec<_>>();
        if segments.len() == 1 {
            return self
                .scopes
                .iter()
                .rev()
                .find_map(|scope| scope.get(&segments[0]).copied())
                .flatten()
                .and_then(|binding| match binding {
                    RetryBinding::Symbol(symbol) => Some(symbol),
                    RetryBinding::ConsistencyModule | RetryBinding::TxRetryModule => None,
                });
        }
        retry_symbol_for_import(
            &segments[..segments.len() - 1],
            &segments[segments.len() - 1],
        )
        .or_else(|| {
            if segments.len() != 2 {
                return None;
            }
            let binding = self
                .scopes
                .iter()
                .rev()
                .find_map(|scope| scope.get(&segments[0]).copied())
                .flatten()?;
            retry_symbol_from_module(binding, &segments[1])
        })
    }

    fn shadow_pattern(&mut self, pattern: &syn::Pat) {
        let mut names = Vec::new();
        collect_pattern_names(pattern, &mut names);
        if let Some(scope) = self.scopes.last_mut() {
            for name in &names {
                scope.insert(name.clone(), None);
            }
        }
        if let Some(scope) = self.observation_scopes.last_mut() {
            for name in names {
                scope.insert(name, None);
            }
        }
    }

    fn note_observation_binding(&mut self, local: &syn::Local) {
        let Some(init) = &local.init else {
            return;
        };
        if let Some((command, factory)) = self.current_typed_command.as_ref()
            && let Some(binding) =
                command_observation_binding(&local.pat, &init.expr, Some(command.as_str()))
            && let Some(scope) = self.observation_scopes.last_mut()
        {
            scope.insert(binding, Some(*factory));
        }
    }

    fn command_evidence(&self, expr: &syn::Expr) -> Option<CommandEvidence> {
        let path = exact_expr_path(expr)?;
        if path.contains("::") {
            return None;
        }
        self.observation_scopes
            .iter()
            .rev()
            .find_map(|scope| scope.get(&path).copied())
            .flatten()
    }

    fn invalidate_observation_binding(&mut self, expr: &syn::Expr) {
        let Some(path) = exact_expr_path(expr) else {
            return;
        };
        if path.contains("::") {
            return;
        }
        if let Some(scope) = self
            .observation_scopes
            .iter_mut()
            .rev()
            .find(|scope| scope.contains_key(&path))
        {
            scope.insert(path, None);
        }
    }

    fn retry_expr_facts(&self, expr: &syn::Expr) -> RetryExprFacts {
        let operation_scan = scoped_operation_scan(expr);
        RetryExprFacts {
            exact_path: exact_expr_path(expr),
            command_evidence: self.command_evidence(expr),
            operation_method: canonical_retry_operation(expr),
            scoped_operation_calls: operation_scan.calls,
            legacy_write: operation_scan.legacy_write,
        }
    }
}

impl<'ast> syn::visit::Visit<'ast> for RetryAstScan {
    fn visit_item_impl(&mut self, node: &'ast syn::ItemImpl) {
        let previous = self.current_impl.replace(impl_type_name(&node.self_ty));
        syn::visit::visit_item_impl(self, node);
        self.current_impl = previous;
    }

    fn visit_item_fn(&mut self, node: &syn::ItemFn) {
        self.visit_function(node.sig.ident.to_string(), &node.sig, &node.block);
    }

    fn visit_impl_item_fn(&mut self, node: &syn::ImplItemFn) {
        self.visit_function(node.sig.ident.to_string(), &node.sig, &node.block);
    }

    fn visit_block(&mut self, node: &'ast syn::Block) {
        let mut scope = RetryScope::new();
        for statement in &node.stmts {
            if let syn::Stmt::Item(syn::Item::Use(item_use)) = statement {
                collect_retry_use_aliases(&item_use.tree, &[], &mut scope);
            } else if let syn::Stmt::Item(syn::Item::Fn(item_fn)) = statement {
                scope.insert(item_fn.sig.ident.to_string(), None);
            }
        }
        self.scopes.push(scope);
        self.observation_scopes.push(ObservationScope::new());
        for statement in &node.stmts {
            syn::visit::visit_stmt(self, statement);
            if let syn::Stmt::Local(local) = statement {
                self.shadow_pattern(&local.pat);
                self.note_observation_binding(local);
            }
        }
        self.observation_scopes.pop();
        self.scopes.pop();
    }

    fn visit_expr_closure(&mut self, node: &'ast syn::ExprClosure) {
        self.scopes.push(RetryScope::new());
        self.observation_scopes.push(ObservationScope::new());
        for input in &node.inputs {
            self.shadow_pattern(input);
        }
        syn::visit::visit_expr(self, &node.body);
        self.observation_scopes.pop();
        self.scopes.pop();
    }

    fn visit_expr_call(&mut self, node: &syn::ExprCall) {
        use syn::spanned::Spanned as _;
        if matches!(
            exact_expr_path(&node.func).as_deref(),
            Some(
                "identity::password_change_localtx_observation"
                    | "settings::secret_publish_localtx_observation"
            )
        ) {
            self.legacy_command_evidence_calls
                .push((node.func.span().start().line, self.current_function.clone()));
        }
        if let syn::Expr::Path(path) = &*node.func
            && let Some(symbol) = self.resolve(&path.path)
        {
            let call = |wrapper| RetryCall {
                line: node.func.span().start().line,
                impl_type: self.current_impl.clone(),
                function: self.current_function.clone(),
                wrapper,
                arguments: node
                    .args
                    .iter()
                    .map(|argument| self.retry_expr_facts(argument))
                    .collect(),
            };
            match symbol {
                RetrySymbol::Direct => self.direct_calls.push(call(None)),
                RetrySymbol::Generic => self.wrapper_calls.push(call(Some(RetryWrapper::Generic))),
                RetrySymbol::Local => self.wrapper_calls.push(call(Some(RetryWrapper::Local))),
            }
        }
        syn::visit::visit_expr_call(self, node);
    }

    fn visit_expr_assign(&mut self, node: &'ast syn::ExprAssign) {
        syn::visit::visit_expr_assign(self, node);
        self.invalidate_observation_binding(&node.left);
    }
}

fn valid_settings_retry(call: &RetryCall) -> bool {
    call.wrapper == Some(RetryWrapper::Generic)
        && call.arguments.len() == 3
        && call.arguments[0].exact_path.as_deref() == Some("SETTINGS_CONFIG_BOUNDARY")
        && call.arguments[1].operation_method.as_deref() == Some("retry_co_tx_with_outbox")
        && call.arguments[1].scoped_operation_calls == 1
        && !call.arguments[1].legacy_write
}

fn valid_identity_password_retry(call: &RetryCall) -> bool {
    call.wrapper == Some(RetryWrapper::Local)
        && call.arguments.len() == 3
        && call.arguments[0].command_evidence == Some(CommandEvidence::PasswordChange)
        && call.arguments[1].operation_method.as_deref() == Some("retry_write")
        && call.arguments[1].scoped_operation_calls == 1
        && !call.arguments[1].legacy_write
}

fn valid_identity_logout_retry(call: &RetryCall) -> bool {
    call.wrapper == Some(RetryWrapper::Local)
        && call.arguments.len() == 3
        && call.arguments[0].command_evidence == Some(CommandEvidence::SessionLogout)
        && call.arguments[1].operation_method.as_deref() == Some("retry_write")
        && call.arguments[1].scoped_operation_calls == 1
        && !call.arguments[1].legacy_write
}

fn valid_identity_refresh_retry(call: &RetryCall) -> bool {
    call.wrapper == Some(RetryWrapper::Local)
        && call.arguments.len() == 3
        && call.arguments[0].command_evidence == Some(CommandEvidence::RefreshRotation)
        && call.arguments[1].operation_method.as_deref() == Some("retry_write")
        && call.arguments[1].scoped_operation_calls == 1
        && !call.arguments[1].legacy_write
}

fn valid_audit_append_retry(call: &RetryCall) -> bool {
    call.wrapper == Some(RetryWrapper::Generic)
        && call.arguments.len() == 3
        && call.arguments[0].exact_path.as_deref() == Some("AUDIT_APPEND_BOUNDARY")
        && call.arguments[1].operation_method.as_deref() == Some("retry_write")
        && call.arguments[1].scoped_operation_calls == 1
        && !call.arguments[1].legacy_write
}

fn valid_settings_secret_retry(call: &RetryCall) -> bool {
    call.wrapper == Some(RetryWrapper::Local)
        && call.arguments.len() == 3
        && call.arguments[0].command_evidence == Some(CommandEvidence::SecretPublish)
        && call.arguments[1].operation_method.as_deref() == Some("retry_write")
        && call.arguments[1].scoped_operation_calls == 1
        && !call.arguments[1].legacy_write
}

fn valid_settings_secret_generic_retry(call: &RetryCall) -> bool {
    call.wrapper == Some(RetryWrapper::Generic)
        && call.arguments.len() == 3
        && call.arguments[0].exact_path.as_deref() == Some("SETTINGS_SECRET_BOUNDARY")
        && call.arguments[1].operation_method.as_deref() == Some("retry_write")
        && call.arguments[1].scoped_operation_calls == 1
        && !call.arguments[1].legacy_write
}

fn collect_pattern_names(pattern: &syn::Pat, names: &mut Vec<String>) {
    match pattern {
        syn::Pat::Ident(ident) => names.push(ident.ident.to_string()),
        syn::Pat::Reference(reference) => collect_pattern_names(&reference.pat, names),
        syn::Pat::Tuple(tuple) => {
            for element in &tuple.elems {
                collect_pattern_names(element, names);
            }
        }
        syn::Pat::TupleStruct(tuple) => {
            for element in &tuple.elems {
                collect_pattern_names(element, names);
            }
        }
        syn::Pat::Struct(structure) => {
            for field in &structure.fields {
                collect_pattern_names(&field.pat, names);
            }
        }
        syn::Pat::Slice(slice) => {
            for element in &slice.elems {
                collect_pattern_names(element, names);
            }
        }
        syn::Pat::Type(typed) => collect_pattern_names(&typed.pat, names),
        syn::Pat::Or(or) => {
            for case in &or.cases {
                collect_pattern_names(case, names);
            }
        }
        _ => {}
    }
}

fn typed_command_param(signature: &syn::Signature) -> Option<(String, CommandEvidence)> {
    signature.inputs.iter().find_map(|input| {
        let syn::FnArg::Typed(typed) = input else {
            return None;
        };
        let syn::Type::Path(path) = &*typed.ty else {
            return None;
        };
        let factory = match path.path.segments.last()?.ident.to_string().as_str() {
            "SecretPublishCommand" => CommandEvidence::SecretPublish,
            "PasswordChangeMutation" => CommandEvidence::PasswordChange,
            "SessionLogoutMutation" => CommandEvidence::SessionLogout,
            "RefreshRotationMutation" => CommandEvidence::RefreshRotation,
            _ => return None,
        };
        let syn::Pat::Ident(binding) = &*typed.pat else {
            return None;
        };
        Some((binding.ident.to_string(), factory))
    })
}

fn command_observation_binding(
    pattern: &syn::Pat,
    initializer: &syn::Expr,
    command: Option<&str>,
) -> Option<String> {
    let command = command?;
    let syn::Pat::Tuple(tuple) = pattern else {
        return None;
    };
    if tuple.elems.len() < 2 {
        return None;
    }
    let syn::Pat::Ident(observation) = tuple.elems.last()? else {
        return None;
    };
    let syn::Expr::MethodCall(call) = transparent_expr(initializer) else {
        return None;
    };
    (call.method == "into_parts"
        && call.args.is_empty()
        && exact_expr_path(&call.receiver).as_deref() == Some(command))
    .then(|| observation.ident.to_string())
}

fn transparent_expr(expr: &syn::Expr) -> &syn::Expr {
    match expr {
        syn::Expr::Group(group) => transparent_expr(&group.expr),
        syn::Expr::Paren(paren) => transparent_expr(&paren.expr),
        _ => expr,
    }
}

fn exact_expr_path(expr: &syn::Expr) -> Option<String> {
    let syn::Expr::Path(path) = transparent_expr(expr) else {
        return None;
    };
    Some(
        path.path
            .segments
            .iter()
            .map(|segment| segment.ident.to_string())
            .collect::<Vec<_>>()
            .join("::"),
    )
}

fn secret_repo_read_only_findings(rel: &str, content: &str) -> Vec<Finding> {
    let syntax = match syn::parse_file(content) {
        Ok(syntax) => syntax,
        Err(error) => {
            return vec![finding(
                Rule::SecretRefMutationBypass,
                rel,
                format!("cannot parse settings ports for SecretRepo ownership: {error}"),
            )];
        }
    };
    let Some(repo) = syntax.items.iter().find_map(|item| match item {
        syn::Item::Trait(item) if item.ident == "SecretRepoLocal" => Some(item),
        _ => None,
    }) else {
        return vec![finding(
            Rule::SecretRefMutationSitesAbsent,
            rel,
            "SecretRepoLocal trait is absent; read-only mutation separation is vacuous",
        )];
    };
    let mut names = BTreeSet::new();
    let methods_are_exact = repo.items.len() == SECRET_REPO_READ_METHODS.len()
        && repo.items.iter().all(|item| match item {
            syn::TraitItem::Fn(method) => {
                method.default.is_none()
                    && canonical_secret_repo_signature(&method.sig)
                    && names.insert(method.sig.ident.to_string())
            }
            _ => false,
        });
    if compact_tokens(&repo.supertraits) == "Send+Sync" && methods_are_exact {
        Vec::new()
    } else {
        vec![finding(
            Rule::SecretRefMutationBypass,
            format!("{rel}::SecretRepoLocal"),
            "SecretRepoLocal must remain Send + Sync with exactly find/find_version/latest_version and their canonical read-only signatures",
        )]
    }
}

const SECRET_REPO_READ_METHODS: [&str; 3] = ["find", "find_version", "latest_version"];

fn canonical_secret_repo_signature(signature: &syn::Signature) -> bool {
    let normalized = compact_tokens(signature).replace(",)->", ")->");
    matches!(
        normalized.as_str(),
        "asyncfnfind(&self,scope:TenantRepoScope,key:&SecretKey)->Result<Option<SecretEntry>,SecretRepoError>"
            | "asyncfnfind_version(&self,scope:TenantRepoScope,key:&SecretKey,version:u64)->Result<Option<SecretEntry>,SecretRepoError>"
            | "asyncfnlatest_version(&self,scope:TenantRepoScope,key:&SecretKey)->Result<Option<u64>,SecretRepoError>"
    )
}

fn secret_ref_mutation_findings(
    rel: &str,
    content: &str,
    sites: &mut BTreeMap<&'static str, usize>,
) -> Vec<Finding> {
    let syntax = match syn::parse_file(content) {
        Ok(syntax) => syntax,
        Err(error) => {
            return vec![finding(
                Rule::SecretRefMutationBypass,
                rel,
                format!("cannot parse production Rust for secret_refs mutation ownership: {error}"),
            )];
        }
    };
    let mut scan = SecretRefMutationScan::new(rel, sites);
    syn::visit::Visit::visit_file(&mut scan, &syntax);
    scan.finish()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SecretRefMutationKind {
    Insert,
    Destructive,
}

struct SecretRefMutationScan<'a> {
    rel: &'a str,
    modules: Vec<String>,
    current_impl: Option<String>,
    current_function: Option<String>,
    current_acquire_shape_is_valid: bool,
    impl_functions: BTreeSet<(String, String)>,
    pg_secret_repo_seen: bool,
    pg_secret_repo_trait_impls: usize,
    locked_key_scopes: Vec<BTreeMap<String, bool>>,
    branch_depth: usize,
    acquire_calls: BTreeMap<(String, String), usize>,
    cas_insert_calls: BTreeMap<(String, String), usize>,
    append_tombstone_calls: BTreeMap<(String, String), usize>,
    cas_funnel_calls: BTreeMap<(String, String), usize>,
    sites: &'a mut BTreeMap<&'static str, usize>,
    findings: Vec<Finding>,
}

impl<'a> SecretRefMutationScan<'a> {
    fn new(rel: &'a str, sites: &'a mut BTreeMap<&'static str, usize>) -> Self {
        Self {
            rel,
            modules: Vec::new(),
            current_impl: None,
            current_function: None,
            current_acquire_shape_is_valid: false,
            impl_functions: BTreeSet::new(),
            pg_secret_repo_seen: false,
            pg_secret_repo_trait_impls: 0,
            locked_key_scopes: Vec::new(),
            branch_depth: 0,
            acquire_calls: BTreeMap::new(),
            cas_insert_calls: BTreeMap::new(),
            append_tombstone_calls: BTreeMap::new(),
            cas_funnel_calls: BTreeMap::new(),
            sites,
            findings: Vec::new(),
        }
    }

    fn owner(&self) -> (String, String) {
        (
            self.current_impl.clone().unwrap_or_default(),
            self.current_function.clone().unwrap_or_default(),
        )
    }

    fn note_call(map: &mut BTreeMap<(String, String), usize>, owner: (String, String)) {
        *map.entry(owner).or_default() += 1;
    }

    fn note_sql(&mut self, sql: &str, line: usize) {
        let normalized = normalize_sql(sql);
        if self.rel == "secret_repo.rs" && normalized.contains("pg_advisory_xact_lock") {
            if self.is_canonical_acquire_context() && exact_secret_key_lock_sql(&normalized) {
                *self.sites.entry("secret-key-advisory-lock").or_default() += 1;
            } else {
                self.findings.push(finding(
                    Rule::SecretRefMutationBypass,
                    site_subject(self.rel, line),
                    "LockedSecretKey advisory lock must occur exactly once inside the canonical acquire method",
                ));
            }
        }
        let Some(kind) = secret_ref_mutation_kind(sql) else {
            return;
        };
        if let Some(site) = self.canonical_site(kind) {
            *self.sites.entry(site).or_default() += 1;
            return;
        }
        self.findings.push(finding(
            Rule::SecretRefMutationBypass,
            site_subject(self.rel, line),
            "secret_refs mutations must be append-only INSERTs owned by key_lock::LockedSecretKey::{cas_insert,append_tombstone}",
        ));
    }

    fn canonical_site(&self, kind: SecretRefMutationKind) -> Option<&'static str> {
        if kind != SecretRefMutationKind::Insert
            || self.rel != "secret_repo.rs"
            || self.modules.len() != 1
            || self.modules[0] != "key_lock"
            || self.current_impl.as_deref() != Some("LockedSecretKey")
        {
            return None;
        }
        match self.current_function.as_deref() {
            Some("cas_insert") => Some("secret-key-cas-insert"),
            Some("append_tombstone") => Some("secret-key-append-tombstone"),
            _ => None,
        }
    }

    fn is_canonical_acquire_context(&self) -> bool {
        self.rel == "secret_repo.rs"
            && self.modules.as_slice() == ["key_lock"]
            && self.current_impl.as_deref() == Some("LockedSecretKey")
            && self.current_function.as_deref() == Some("acquire")
            && self.current_acquire_shape_is_valid
    }

    fn inspect_pg_secret_repo_impl(&mut self, node: &syn::ItemImpl) {
        if impl_type_name(&node.self_ty) != "PgSecretRepo" {
            return;
        }
        self.pg_secret_repo_seen = true;
        let trait_impl = node.trait_.as_ref().map(|(polarity, path, _)| {
            (
                polarity.is_none(),
                path.segments
                    .last()
                    .map(|segment| segment.ident.to_string())
                    .unwrap_or_default(),
            )
        });
        match trait_impl {
            Some((true, trait_name)) if trait_name == "SecretRepo" => {
                self.pg_secret_repo_trait_impls += 1;
                let mut names = BTreeSet::new();
                let methods_are_exact = node.items.len() == SECRET_REPO_READ_METHODS.len()
                    && node.items.iter().all(|item| match item {
                        syn::ImplItem::Fn(method) => {
                            matches!(method.vis, syn::Visibility::Inherited)
                                && canonical_secret_repo_signature(&method.sig)
                                && names.insert(method.sig.ident.to_string())
                        }
                        _ => false,
                    });
                if node.unsafety.is_some() || node.defaultness.is_some() || !methods_are_exact {
                    self.findings.push(finding(
                        Rule::SecretRefMutationBypass,
                        site_subject(self.rel, node.impl_token.span.start().line),
                        "PgSecretRepo must use one ordinary positive SecretRepo impl with exactly find/find_version/latest_version and their canonical signatures",
                    ));
                }
            }
            Some(_) => self.findings.push(finding(
                Rule::SecretRefMutationBypass,
                site_subject(self.rel, node.impl_token.span.start().line),
                "PgSecretRepo may implement only its canonical SecretRepo read trait",
            )),
            None => {
                for item in &node.items {
                    let allowed_constructor =
                        matches!(item, syn::ImplItem::Fn(method) if method.sig.ident == "new");
                    if !allowed_constructor {
                        self.findings.push(finding(
                            Rule::SecretRefMutationBypass,
                            "secret_repo.rs::PgSecretRepo",
                            "PgSecretRepo inherent impl is restricted to its constructor; all repository methods belong to the exact SecretRepo read impl",
                        ));
                    }
                }
            }
        }
    }

    fn finish_pg_secret_repo_contract(&mut self) {
        if !self.pg_secret_repo_seen {
            return;
        }
        if self.pg_secret_repo_trait_impls != 1 {
            self.findings.push(finding(
                Rule::SecretRefMutationBypass,
                "secret_repo.rs::PgSecretRepo",
                "PgSecretRepo must have exactly one positive SecretRepo trait impl",
            ));
        }
    }

    fn note_locked_key_binding(&mut self, local: &syn::Local) {
        let mut names = Vec::new();
        collect_pattern_names(&local.pat, &mut names);
        let Some(scope) = self.locked_key_scopes.last_mut() else {
            return;
        };
        for name in names {
            scope.insert(name, false);
        }
        let syn::Pat::Ident(binding) = &local.pat else {
            return;
        };
        if binding.subpat.is_some() || binding.mutability.is_some() {
            return;
        }
        let Some(init) = &local.init else {
            return;
        };
        if self.branch_depth == 0 && is_locked_key_acquire_result(&init.expr) {
            scope.insert(binding.ident.to_string(), true);
        }
    }

    fn locked_key_receiver_is_valid(&self, receiver: &syn::Expr) -> bool {
        if self.branch_depth != 0 {
            return false;
        }
        if is_locked_key_acquire_result(receiver) {
            return true;
        }
        let Some(name) = exact_expr_path(receiver).filter(|path| !path.contains("::")) else {
            return false;
        };
        self.locked_key_scopes
            .iter()
            .rev()
            .find_map(|scope| scope.get(&name).copied())
            .unwrap_or(false)
    }

    fn invalidate_locked_key_binding(&mut self, receiver: &syn::Expr) {
        let Some(name) = exact_expr_path(receiver).filter(|path| !path.contains("::")) else {
            return;
        };
        if let Some(scope) = self
            .locked_key_scopes
            .iter_mut()
            .rev()
            .find(|scope| scope.contains_key(&name))
        {
            scope.insert(name, false);
        }
    }

    fn finish(mut self) -> Vec<Finding> {
        if self.rel != "secret_repo.rs" {
            return self.findings;
        }
        self.finish_pg_secret_repo_contract();
        if !self
            .impl_functions
            .iter()
            .any(|(owner, _)| owner == "PgSecretUnitOfWork")
        {
            return self.findings;
        }

        let uow_owner = |function: &str| ("PgSecretUnitOfWork".to_string(), function.to_string());
        let cas_funnel = uow_owner("cas_insert_locked");
        let cas_funnel_is_exact = self.impl_functions.contains(&cas_funnel)
            && self.acquire_calls.get(&cas_funnel).copied() == Some(1)
            && self.cas_insert_calls.get(&cas_funnel).copied() == Some(1)
            && !self.append_tombstone_calls.contains_key(&cas_funnel);
        if cas_funnel_is_exact {
            *self.sites.entry("secret-uow-cas-funnel").or_default() += 1;
        } else {
            self.findings.push(finding(
                Rule::SecretRefMutationBypass,
                "secret_repo.rs::PgSecretUnitOfWork::cas_insert_locked",
                "canonical CAS funnel must acquire LockedSecretKey exactly once and call cas_insert exactly once",
            ));
        }

        for (function, site) in [
            ("publish", "secret-uow-publish-cas"),
            ("publish_internal", "secret-uow-publish-internal-cas"),
            ("republish", "secret-uow-republish-cas"),
        ] {
            let owner = uow_owner(function);
            let exact = self.impl_functions.contains(&owner)
                && self.cas_funnel_calls.get(&owner).copied() == Some(1)
                && !self.acquire_calls.contains_key(&owner)
                && !self.cas_insert_calls.contains_key(&owner)
                && !self.append_tombstone_calls.contains_key(&owner);
            if exact {
                *self.sites.entry(site).or_default() += 1;
            } else {
                self.findings.push(finding(
                    Rule::SecretRefMutationBypass,
                    format!("secret_repo.rs::PgSecretUnitOfWork::{function}"),
                    format!(
                        "{function} must call the shared cas_insert_locked funnel exactly once and must not mint or consume LockedSecretKey directly"
                    ),
                ));
            }
        }

        let delete = uow_owner("delete");
        let delete_is_exact = self.impl_functions.contains(&delete)
            && self.acquire_calls.get(&delete).copied() == Some(1)
            && self.append_tombstone_calls.get(&delete).copied() == Some(1)
            && !self.cas_insert_calls.contains_key(&delete)
            && !self.cas_funnel_calls.contains_key(&delete);
        if delete_is_exact {
            *self.sites.entry("secret-uow-delete-tombstone").or_default() += 1;
        } else {
            self.findings.push(finding(
                Rule::SecretRefMutationBypass,
                "secret_repo.rs::PgSecretUnitOfWork::delete",
                "delete must acquire LockedSecretKey exactly once and append_tombstone exactly once",
            ));
        }

        for (owners, expected, operation) in [
            (
                &self.acquire_calls,
                vec![cas_funnel.clone(), delete],
                "acquire",
            ),
            (&self.cas_insert_calls, vec![cas_funnel], "cas_insert"),
        ] {
            for owner in owners.keys().filter(|owner| !expected.contains(owner)) {
                self.findings.push(finding(
                    Rule::SecretRefMutationBypass,
                    format!("secret_repo.rs::{}::{}", owner.0, owner.1),
                    format!("LockedSecretKey::{operation} is outside its canonical UoW owner"),
                ));
            }
        }
        for owner in self
            .append_tombstone_calls
            .keys()
            .filter(|owner| **owner != uow_owner("delete"))
        {
            self.findings.push(finding(
                Rule::SecretRefMutationBypass,
                format!("secret_repo.rs::{}::{}", owner.0, owner.1),
                "LockedSecretKey::append_tombstone is outside PgSecretUnitOfWork::delete",
            ));
        }
        let expected_publishers = [
            uow_owner("publish"),
            uow_owner("publish_internal"),
            uow_owner("republish"),
        ];
        for owner in self
            .cas_funnel_calls
            .keys()
            .filter(|owner| !expected_publishers.contains(owner))
        {
            self.findings.push(finding(
                Rule::SecretRefMutationBypass,
                format!("secret_repo.rs::{}::{}", owner.0, owner.1),
                "cas_insert_locked may only be called by the three typed secret publish entries",
            ));
        }

        self.findings
    }
}

impl<'ast> syn::visit::Visit<'ast> for SecretRefMutationScan<'_> {
    fn visit_item_mod(&mut self, node: &'ast syn::ItemMod) {
        let Some((_, items)) = &node.content else {
            return;
        };
        self.modules.push(node.ident.to_string());
        for item in items {
            syn::visit::Visit::visit_item(self, item);
        }
        self.modules.pop();
    }

    fn visit_item_impl(&mut self, node: &'ast syn::ItemImpl) {
        self.inspect_pg_secret_repo_impl(node);
        let previous = self.current_impl.replace(impl_type_name(&node.self_ty));
        for item in &node.items {
            syn::visit::Visit::visit_impl_item(self, item);
        }
        self.current_impl = previous;
    }

    fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
        let previous = self.current_function.replace(node.sig.ident.to_string());
        if let Some(current_impl) = &self.current_impl {
            self.impl_functions
                .insert((current_impl.clone(), node.sig.ident.to_string()));
        }
        let previous_acquire_shape = self.current_acquire_shape_is_valid;
        self.current_acquire_shape_is_valid = false;
        if self.rel == "secret_repo.rs"
            && self.modules.as_slice() == ["key_lock"]
            && self.current_impl.as_deref() == Some("LockedSecretKey")
            && node.sig.ident == "acquire"
        {
            if canonical_secret_key_acquire(node) {
                self.current_acquire_shape_is_valid = true;
                *self.sites.entry("secret-key-lock-acquire").or_default() += 1;
            } else {
                self.findings.push(finding(
                    Rule::SecretRefMutationBypass,
                    site_subject(self.rel, node.sig.ident.span().start().line),
                    "LockedSecretKey::acquire must take &mut TxCapability plus tenant/key, bind those coordinates to the exact advisory lock, and return the same stored fields",
                ));
            }
        }
        syn::visit::Visit::visit_block(self, &node.block);
        self.current_acquire_shape_is_valid = previous_acquire_shape;
        self.current_function = previous;
    }

    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        let previous_impl = self.current_impl.take();
        let previous_function = self.current_function.replace(node.sig.ident.to_string());
        let previous_acquire_shape = self.current_acquire_shape_is_valid;
        self.current_acquire_shape_is_valid = false;
        syn::visit::Visit::visit_block(self, &node.block);
        self.current_acquire_shape_is_valid = previous_acquire_shape;
        self.current_function = previous_function;
        self.current_impl = previous_impl;
    }

    fn visit_block(&mut self, node: &'ast syn::Block) {
        self.locked_key_scopes.push(BTreeMap::new());
        for statement in &node.stmts {
            syn::visit::visit_stmt(self, statement);
            if let syn::Stmt::Local(local) = statement {
                self.note_locked_key_binding(local);
            }
        }
        self.locked_key_scopes.pop();
    }

    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        match exact_expr_path(&node.func).as_deref() {
            Some("LockedSecretKey::acquire") => {
                let owner = self.owner();
                Self::note_call(&mut self.acquire_calls, owner);
            }
            Some("Self::cas_insert_locked") => {
                let owner = self.owner();
                Self::note_call(&mut self.cas_funnel_calls, owner);
            }
            _ => {}
        }
        syn::visit::visit_expr_call(self, node);
    }

    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        let owner = self.owner();
        let method = node.method.to_string();
        if matches!(method.as_str(), "cas_insert" | "append_tombstone") {
            if self.locked_key_receiver_is_valid(&node.receiver) {
                if method == "cas_insert" {
                    Self::note_call(&mut self.cas_insert_calls, owner);
                } else {
                    Self::note_call(&mut self.append_tombstone_calls, owner);
                }
                self.invalidate_locked_key_binding(&node.receiver);
            } else {
                self.findings.push(finding(
                    Rule::SecretRefMutationBypass,
                    site_subject(self.rel, node.method.span().start().line),
                    format!(
                        "LockedSecretKey::{method} receiver must be the unconditional, unmodified result of LockedSecretKey::acquire"
                    ),
                ));
            }
        }
        syn::visit::visit_expr_method_call(self, node);
    }

    fn visit_expr_assign(&mut self, node: &'ast syn::ExprAssign) {
        syn::visit::visit_expr_assign(self, node);
        self.invalidate_locked_key_binding(&node.left);
    }

    fn visit_expr_closure(&mut self, node: &'ast syn::ExprClosure) {
        let mut scope = BTreeMap::new();
        for input in &node.inputs {
            let mut names = Vec::new();
            collect_pattern_names(input, &mut names);
            scope.extend(names.into_iter().map(|name| (name, false)));
        }
        self.locked_key_scopes.push(scope);
        syn::visit::visit_expr_closure(self, node);
        self.locked_key_scopes.pop();
    }

    fn visit_expr_if(&mut self, node: &'ast syn::ExprIf) {
        self.branch_depth += 1;
        syn::visit::visit_expr_if(self, node);
        self.branch_depth -= 1;
    }

    fn visit_expr_match(&mut self, node: &'ast syn::ExprMatch) {
        self.branch_depth += 1;
        syn::visit::visit_expr_match(self, node);
        self.branch_depth -= 1;
    }

    fn visit_expr_for_loop(&mut self, node: &'ast syn::ExprForLoop) {
        self.branch_depth += 1;
        syn::visit::visit_expr_for_loop(self, node);
        self.branch_depth -= 1;
    }

    fn visit_expr_while(&mut self, node: &'ast syn::ExprWhile) {
        self.branch_depth += 1;
        syn::visit::visit_expr_while(self, node);
        self.branch_depth -= 1;
    }

    fn visit_expr_loop(&mut self, node: &'ast syn::ExprLoop) {
        self.branch_depth += 1;
        syn::visit::visit_expr_loop(self, node);
        self.branch_depth -= 1;
    }

    fn visit_expr_struct(&mut self, node: &'ast syn::ExprStruct) {
        use syn::spanned::Spanned as _;

        let constructor = node
            .path
            .segments
            .last()
            .map(|segment| segment.ident.to_string());
        let constructs_locked_key = constructor.as_deref() == Some("LockedSecretKey")
            || (constructor.as_deref() == Some("Self")
                && self.current_impl.as_deref() == Some("LockedSecretKey"));
        if constructs_locked_key {
            if self.is_canonical_acquire_context() && canonical_locked_key_mint(node) {
                *self.sites.entry("secret-key-capability-mint").or_default() += 1;
            } else {
                self.findings.push(finding(
                    Rule::SecretRefMutationBypass,
                    site_subject(self.rel, node.path.span().start().line),
                    "LockedSecretKey may only be constructed by its canonical advisory-lock acquire method",
                ));
            }
        }
        syn::visit::visit_expr_struct(self, node);
    }

    fn visit_lit_str(&mut self, node: &'ast syn::LitStr) {
        self.note_sql(&node.value(), node.span().start().line);
    }

    fn visit_macro(&mut self, node: &'ast syn::Macro) {
        use syn::spanned::Spanned as _;
        let combined = macro_string_literals(&node.tokens).join(" ");
        self.note_sql(&combined, node.path.span().start().line);
    }
}

fn is_locked_key_acquire_result(expr: &syn::Expr) -> bool {
    match transparent_expr(expr) {
        syn::Expr::Await(awaited) => is_locked_key_acquire_result(&awaited.base),
        syn::Expr::Try(tried) => is_locked_key_acquire_result(&tried.expr),
        syn::Expr::MethodCall(call)
            if (call.method == "unwrap" && call.args.is_empty())
                || (call.method == "expect" && call.args.len() == 1) =>
        {
            is_locked_key_acquire_result(&call.receiver)
        }
        syn::Expr::Call(call) => {
            exact_expr_path(&call.func).as_deref() == Some("LockedSecretKey::acquire")
                && call.args.len() == 3
        }
        _ => false,
    }
}

fn impl_type_name(ty: &syn::Type) -> String {
    let syn::Type::Path(path) = ty else {
        return String::new();
    };
    path.path
        .segments
        .last()
        .map(|segment| segment.ident.to_string())
        .unwrap_or_default()
}

fn macro_string_literals(tokens: &proc_macro2::TokenStream) -> Vec<String> {
    let mut values = Vec::new();
    for token in tokens.clone() {
        match token {
            proc_macro2::TokenTree::Group(group) => {
                values.extend(macro_string_literals(&group.stream()));
            }
            proc_macro2::TokenTree::Literal(literal) => {
                if let Ok(syn::Lit::Str(value)) = syn::parse_str::<syn::Lit>(&literal.to_string()) {
                    values.push(value.value());
                }
            }
            _ => {}
        }
    }
    values
}

fn secret_ref_mutation_kind(sql: &str) -> Option<SecretRefMutationKind> {
    let normalized = normalize_sql(sql);
    if !normalized.contains("secret_refs") {
        return None;
    }
    let statement = normalized.trim_start();
    if statement.starts_with("update ")
        || statement.starts_with("delete from")
        || statement.starts_with("merge into")
        || statement.starts_with("truncate ")
    {
        return Some(SecretRefMutationKind::Destructive);
    }
    statement
        .starts_with("insert into")
        .then_some(SecretRefMutationKind::Insert)
}

fn normalize_sql(sql: &str) -> String {
    strip_sql_comments(sql)
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_lowercase()
}

fn exact_secret_key_lock_sql(normalized: &str) -> bool {
    normalized == "select pg_advisory_xact_lock(hashtextextended($1 || chr(31) || $2, 0))"
}

fn canonical_secret_key_acquire(node: &syn::ImplItemFn) -> bool {
    if node.sig.asyncness.is_none() || node.sig.inputs.len() != 3 {
        return false;
    }
    let signature = compact_tokens(&node.sig);
    if signature
        != "asyncfnacquire(tx:&'capmutTxCapability<'tx>,tenant:TenantId,key:&SecretKey,)->Result<Self,SecretRepoError>"
    {
        return false;
    }
    let statements: Vec<_> = node.block.stmts.iter().map(compact_tokens).collect();
    let prefix = [
        "lettenant_uuid=tenant_param(tenant);",
        "letkey=key.as_str().to_owned();",
    ];
    if statements.get(..2).is_none_or(|actual| actual != prefix) {
        return false;
    }
    let lock_index = if statements.get(2).is_some_and(|statement| {
        statement
            == "#[cfg(all(test,feature=\"integration\"))]wait_at_secret_key_lock_rendezvous(&key).await;"
            || statement == "wait_at_secret_key_lock_rendezvous(&key).await;"
    }) {
        3
    } else {
        2
    };
    let required_tail = [
        "sqlx::query(\"SELECTpg_advisory_xact_lock(hashtextextended($1||chr(31)||$2,0))\").bind(&tenant_uuid).bind(&key).execute(tx.conn()).await.map_err(storage)?;",
    ];
    statements
        .get(lock_index)
        .is_some_and(|statement| statement == required_tail[0])
        && statements.len() == lock_index + 2
        && statements.get(lock_index + 1).is_some_and(|statement| {
            matches!(
                statement.as_str(),
                "Ok(Self{tx,tenant,tenant_uuid,key})" | "Ok(Self{tx,tenant,tenant_uuid,key,})"
            )
        })
}

fn compact_tokens(tokens: &impl quote::ToTokens) -> String {
    tokens
        .to_token_stream()
        .to_string()
        .replace(char::is_whitespace, "")
}

fn canonical_locked_key_mint(node: &syn::ExprStruct) -> bool {
    if node.rest.is_some() || node.fields.len() != 4 {
        return false;
    }
    node.fields
        .iter()
        .zip(["tx", "tenant", "tenant_uuid", "key"])
        .all(|(field, expected)| {
            let syn::Member::Named(member) = &field.member else {
                return false;
            };
            member == expected && compact_tokens(&field.expr) == expected
        })
}

fn canonical_retry_operation(expr: &syn::Expr) -> Option<String> {
    let syn::Expr::Closure(closure) = transparent_expr(expr) else {
        return None;
    };
    canonical_retry_tail(&closure.body)
}

#[derive(Default)]
struct ScopedOperationScan {
    calls: usize,
    legacy_write: bool,
}

impl<'ast> syn::visit::Visit<'ast> for ScopedOperationScan {
    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        if is_self_pool(&node.receiver) {
            match node.method.to_string().as_str() {
                "retry_write" | "retry_co_tx_with_outbox" => self.calls += 1,
                "write" | "co_tx_with_outbox" => {
                    self.calls += 1;
                    self.legacy_write = true;
                }
                _ => {}
            }
        }
        syn::visit::visit_expr_method_call(self, node);
    }
}

fn scoped_operation_scan(expr: &syn::Expr) -> ScopedOperationScan {
    let mut scan = ScopedOperationScan::default();
    syn::visit::Visit::visit_expr(&mut scan, expr);
    scan
}

fn canonical_retry_tail(expr: &syn::Expr) -> Option<String> {
    match transparent_expr(expr) {
        syn::Expr::Async(async_expr) => {
            block_tail(&async_expr.block).and_then(canonical_retry_tail)
        }
        syn::Expr::Block(block) => block_tail(&block.block).and_then(canonical_retry_tail),
        syn::Expr::Await(await_expr) => canonical_retry_tail(&await_expr.base),
        syn::Expr::MethodCall(method)
            if matches!(
                method.method.to_string().as_str(),
                "retry_write" | "retry_co_tx_with_outbox"
            ) && is_self_pool(&method.receiver) =>
        {
            Some(method.method.to_string())
        }
        _ => None,
    }
}

fn block_tail(block: &syn::Block) -> Option<&syn::Expr> {
    match block.stmts.last()? {
        syn::Stmt::Expr(expr, None) => Some(expr),
        _ => None,
    }
}

fn is_self_pool(expr: &syn::Expr) -> bool {
    let syn::Expr::Field(pool) = transparent_expr(expr) else {
        return false;
    };
    let syn::Member::Named(member) = &pool.member else {
        return false;
    };
    member == "pool" && exact_expr_path(&pool.base).as_deref() == Some("self")
}

fn tenant_tables_from_migrations(files: &[(String, String)]) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for (_, raw) in files {
        let sql = strip_sql_comments(raw).to_lowercase();
        collect_create_table_tenant_columns(&sql, &mut out);
        collect_alter_table_tenant_columns(&sql, &mut out);
    }
    out
}

fn collect_create_table_tenant_columns(sql: &str, out: &mut BTreeSet<String>) {
    let mut rest = sql;
    while let Some(idx) = rest.find("create table") {
        rest = &rest[idx + "create table".len()..];
        let (table, after_table) = split_token(rest);
        let Some(open) = after_table.find('(') else {
            continue;
        };
        if let Some(body) = parens_body(&after_table[open + 1..])
            && body.contains("tenant_id")
        {
            out.insert(unqualified_table(table).to_string());
        }
        rest = after_table;
    }
}

fn collect_alter_table_tenant_columns(sql: &str, out: &mut BTreeSet<String>) {
    let mut rest = sql;
    while let Some(idx) = rest.find("alter table") {
        rest = &rest[idx + "alter table".len()..];
        let (table, after_table) = split_token(rest);
        if after_table.contains("add column tenant_id") {
            out.insert(unqualified_table(table).to_string());
        }
        rest = after_table;
    }
}

fn tenant_table_hits(content: &str, tenant_tables: &BTreeSet<String>) -> Vec<String> {
    tenant_tables
        .iter()
        .filter(|t| {
            [
                format!("from {t}"),
                format!("into {t}"),
                format!("update {t}"),
                format!("delete from {t}"),
                format!("join {t}"),
                format!("table {t}"),
            ]
            .iter()
            .any(|needle| content.contains(needle))
        })
        .cloned()
        .collect()
}

#[derive(Debug)]
struct RawTenantAccess {
    tables: Vec<String>,
    pattern: String,
    line: usize,
}

#[derive(Debug)]
struct RawPoolFieldAccess {
    pattern: &'static str,
    line: usize,
}

#[derive(Debug)]
struct RawOutboxAccess {
    pattern: &'static str,
    line: usize,
}

fn raw_outbox_insert_sites(
    rel: &str,
    content: &str,
) -> (
    Vec<RawOutboxAccess>,
    BTreeSet<&'static str>,
    Vec<&'static str>,
) {
    let mut exceptions = BTreeSet::new();
    let mut owned_sites = Vec::new();
    let mut findings = Vec::new();
    for (needle, owner, symbols, pattern) in [
        (
            "insert into outbox",
            "outbox.rs",
            &["append_outbox", "append_replayed_outbox"][..],
            "INSERT INTO outbox",
        ),
        (
            "insert into outbox_log",
            "outbox_cdc.rs",
            &["append_outbox_log"][..],
            "INSERT INTO outbox_log",
        ),
    ] {
        for (idx, _) in content.match_indices(needle) {
            let suffix = &content[idx + needle.len()..];
            if needle == "insert into outbox"
                && suffix
                    .chars()
                    .next()
                    .is_some_and(|ch| ch == '_' || ch.is_ascii_alphanumeric())
            {
                continue;
            }
            if rel == owner
                && let Some(symbol) = enclosing_function_name(content, idx)
                && symbols.contains(&symbol)
            {
                let site = match (rel, symbol) {
                    ("outbox.rs", "append_outbox") => "outbox.rs::append_outbox",
                    ("outbox.rs", "append_replayed_outbox") => "outbox.rs::append_replayed_outbox",
                    ("outbox_cdc.rs", "append_outbox_log") => "outbox_cdc.rs::append_outbox_log",
                    _ => unreachable!("symbol checked against exact owner allowlist"),
                };
                owned_sites.push(site);
                continue;
            }
            let (_, end) = raw_access_window(content, idx, ".execute(pool");
            let window = &content[idx.saturating_sub(400)..end];
            if needle == "insert into outbox"
                && let Some(exception) = allowed_fault_matrix_outbox_insert(rel, window)
            {
                exceptions.insert(exception);
                continue;
            }
            findings.push(RawOutboxAccess {
                pattern,
                line: line_number(content, idx),
            });
        }
    }
    (findings, exceptions, owned_sites)
}

fn enclosing_function_name(content: &str, target: usize) -> Option<&str> {
    for (fn_idx, _) in content.match_indices("fn ") {
        let name_start = fn_idx + "fn ".len();
        let (name, after_name) = split_token(&content[name_start..]);
        if name.is_empty() {
            continue;
        }
        let open_rel = after_name.find('{')?;
        let body_start = name_start + name.len() + open_rel + 1;
        let (_, consumed) = braced_body(&content[body_start..])?;
        let body_end = body_start + consumed;
        if (body_start..body_end).contains(&target) {
            return Some(name);
        }
    }
    None
}

fn is_cotx_funnel(rel: &str) -> bool {
    matches!(rel, "cotx.rs" | "cotx/mod.rs") || rel.starts_with("cotx/")
}

fn outbox_append_bypass_sites(rel: &str, content: &str) -> Vec<RawOutboxAccess> {
    if is_cotx_funnel(rel)
        || matches!(rel, "outbox.rs" | "tx.rs")
        || !content.contains("append_outbox(")
    {
        return Vec::new();
    }
    ["pool.begin().await", "run_global_transaction"]
        .into_iter()
        .flat_map(|pattern| {
            content
                .match_indices(pattern)
                .map(move |(idx, _)| RawOutboxAccess {
                    pattern,
                    line: line_number(content, idx),
                })
        })
        .collect()
}

fn tx_capability_mint_sites(rel: &str, content: &str) -> Vec<RawOutboxAccess> {
    if is_cotx_funnel(rel) || rel == "tx.rs" {
        return Vec::new();
    }
    content
        .match_indices("txcapability::from_transaction")
        .map(|(idx, _)| RawOutboxAccess {
            pattern: "TxCapability::from_transaction",
            line: line_number(content, idx),
        })
        .collect()
}

fn raw_tenant_accesses(
    rel: &str,
    content: &str,
    tenant_tables: &BTreeSet<String>,
    helper_tables: &BTreeMap<String, Vec<String>>,
) -> (Vec<RawTenantAccess>, BTreeSet<&'static str>) {
    let mut out = Vec::new();
    let mut allowed_exceptions = BTreeSet::new();
    for pattern in raw_access_patterns(content) {
        for (idx, _) in content.match_indices(pattern.as_str()) {
            let (start, end) = raw_access_window(content, idx, &pattern);
            let window = &content[start..end];
            let mut tables = tenant_table_hits(window, tenant_tables);
            for (helper, helper_hits) in helper_tables {
                if window.contains(&format!("{helper}(")) {
                    tables.extend(helper_hits.iter().cloned());
                }
            }
            tables.sort();
            tables.dedup();
            if !tables.is_empty() {
                if let Some(exception) = allowed_site_exception(rel, &pattern, &tables, window) {
                    allowed_exceptions.insert(exception);
                    continue;
                }
                out.push(RawTenantAccess {
                    tables,
                    pattern: pattern.clone(),
                    line: line_number(content, idx),
                });
            }
        }
    }
    (out, allowed_exceptions)
}

fn raw_access_window(content: &str, idx: usize, pattern: &str) -> (usize, usize) {
    if is_executor_pattern(pattern) {
        let prefix = &content[..idx];
        let query_start = prefix
            .rfind("sqlx::query")
            .or_else(|| prefix.rfind("query_as"))
            .unwrap_or(idx.saturating_sub(900));
        let suffix = &content[idx..];
        let await_end = suffix
            .find(".await")
            .map(|end| idx + end + ".await".len())
            .unwrap_or((idx + pattern.len() + 200).min(content.len()));
        return (query_start, await_end.min(content.len()));
    }
    (
        idx.saturating_sub(2_500),
        (idx + pattern.len() + 2_500).min(content.len()),
    )
}

fn is_executor_pattern(pattern: &str) -> bool {
    pattern.starts_with(".execute(")
        || pattern.starts_with(".fetch_optional(")
        || pattern.starts_with(".fetch_one(")
        || pattern.starts_with(".fetch_all(")
}

fn tenant_pgconnection_helpers(
    content: &str,
    tenant_tables: &BTreeSet<String>,
) -> BTreeMap<String, Vec<String>> {
    let mut out = BTreeMap::new();
    let mut offset = 0usize;
    while let Some(idx) = content[offset..].find("fn ") {
        let fn_start = offset + idx + "fn ".len();
        let (name, after_name) = split_token(&content[fn_start..]);
        if name.is_empty() {
            offset = fn_start;
            continue;
        }
        let Some(open_idx) = after_name.find('{') else {
            break;
        };
        let signature = &after_name[..open_idx];
        let body_start = fn_start + name.len() + open_idx + 1;
        let Some((body, consumed)) = braced_body(&content[body_start..]) else {
            break;
        };
        if signature.contains("pgconnection") {
            let tables = tenant_table_hits(body, tenant_tables);
            if !tables.is_empty() {
                out.insert(name.to_string(), tables);
            }
        }
        offset = body_start + consumed;
    }
    out
}

fn raw_access_patterns(content: &str) -> Vec<String> {
    let mut patterns: BTreeSet<String> = [
        "pool.begin().await",
        ".pool.begin().await",
        "pool.acquire().await",
        ".pool.acquire().await",
        ".execute(&self.",
        ".fetch_optional(&self.",
        ".fetch_one(&self.",
        ".fetch_all(&self.",
        ".execute(pool",
        ".fetch_optional(pool",
        ".fetch_one(pool",
        ".fetch_all(pool",
        ".execute(&pool",
        ".fetch_optional(&pool",
        ".fetch_one(&pool",
        ".fetch_all(&pool",
        ".execute(&store.pool",
        ".fetch_optional(&store.pool",
        ".fetch_one(&store.pool",
        ".fetch_all(&store.pool",
        ".execute(&mut conn",
        ".fetch_optional(&mut conn",
        ".fetch_one(&mut conn",
        ".fetch_all(&mut conn",
        "pgconnection::connect",
        "pgpooloptions::new().connect",
        "pgpooloptions::new().connect_with",
        "run_global_transaction",
        "run_in_transaction",
    ]
    .into_iter()
    .map(str::to_string)
    .collect();

    for name in local_pgpool_vars(content) {
        for method in ["execute", "fetch_optional", "fetch_one", "fetch_all"] {
            patterns.insert(format!(".{method}({name}"));
            patterns.insert(format!(".{method}(&{name}"));
        }
    }

    for name in local_raw_transaction_vars(content) {
        for method in ["execute", "fetch_optional", "fetch_one", "fetch_all"] {
            patterns.insert(format!(".{method}(&mut {name}"));
            patterns.insert(format!(".{method}(&mut *{name}"));
        }
    }

    patterns.into_iter().collect()
}

fn local_pgpool_vars(content: &str) -> BTreeSet<String> {
    let mut out = Vec::new();
    for line in content.lines() {
        let line = line.trim_start();
        let Some(idx) = line.find("let ") else {
            continue;
        };
        let mut rest = line[idx + "let ".len()..].trim_start();
        if let Some(after_mut) = rest.strip_prefix("mut ") {
            rest = after_mut.trim_start();
        }
        let (name, after_name) = split_token(rest);
        if name.is_empty() {
            continue;
        }
        if after_name.contains(": pgpool")
            || after_name.contains("pgpooloptions::new")
            || after_name.contains(".pool.clone()")
        {
            out.push(name.to_string());
        }
    }
    out.into_iter().collect()
}

fn local_raw_transaction_vars(content: &str) -> BTreeSet<String> {
    let mut out = Vec::new();
    for line in content.lines() {
        let line = line.trim_start();
        let Some(idx) = line.find("let ") else {
            continue;
        };
        let mut rest = line[idx + "let ".len()..].trim_start();
        if let Some(after_mut) = rest.strip_prefix("mut ") {
            rest = after_mut.trim_start();
        }
        let (name, after_name) = split_token(rest);
        if name.is_empty() {
            continue;
        }
        if after_name.contains(".begin().await") {
            out.push(name.to_string());
        }
    }
    out.into_iter().collect()
}

fn raw_tenant_pool_fields(content: &str) -> Vec<RawPoolFieldAccess> {
    let mut out = Vec::new();
    for (line_idx, line) in content.lines().enumerate() {
        let line = line.trim_start();
        let is_pool_field = line.starts_with("pool:")
            || line.starts_with("pub pool:")
            || line.starts_with("pub(crate) pool:");
        if is_pool_field && (line.contains("pgpool") || line.contains("pg_pool")) {
            out.push(RawPoolFieldAccess {
                pattern: "pool: PgPool",
                line: line_idx + 1,
            });
        }
    }
    out
}

fn allowed_site_exception(
    rel: &str,
    _pattern: &str,
    tables: &[String],
    window: &str,
) -> Option<&'static str> {
    if let Some(exception) = allowed_fault_matrix_raw_tenant_site(rel, tables, window) {
        return Some(exception);
    }
    if rel == "migrator.rs"
        && tables == ["config_entries"]
        && window.contains("select count(*)::bigint from config_entries")
        && window.contains("protection_scheme = 0")
    {
        return Some("config-legacy-plaintext-startup-probe");
    }
    if rel == "migrator.rs"
        && tables == ["config_entries"]
        && window.contains("protection_scheme = 0")
        && window.contains("fetch_one(&self.pool")
    {
        return Some("config-legacy-plaintext-startup-probe");
    }
    if rel == "config_repo.rs"
        && tables == ["config_entries"]
        && window.contains("select tenant_id::text, config_key, version, value, value_enc, key_id")
        && window.contains("from config_entries")
        && window.contains("protection_scheme = $1")
        && window.contains("fetch_all(&self.store.pool")
    {
        return Some("config-value-maintenance");
    }
    if rel == "config_repo.rs"
        && tables == ["config_entries"]
        && window.contains("update config_entries")
        && window.contains("protection_scheme = 0")
        && window.contains("execute(&self.store.pool")
    {
        return Some("config-value-maintenance");
    }
    if rel == "config_repo.rs"
        && tables == ["config_entries"]
        && window.contains("update config_entries")
        && window.contains("protection_scheme = 1")
        && window.contains("execute(&self.store.pool")
    {
        return Some("config-value-maintenance");
    }
    if rel == "config_repo.rs"
        && tables == ["config_entries"]
        && window.contains("select count(*)::bigint from config_entries")
        && window.contains("protection_scheme = 0")
        && window.contains("fetch_one(&self.store.pool")
    {
        return Some("config-value-maintenance");
    }
    None
}

fn allowed_fault_matrix_raw_tenant_site(
    rel: &str,
    tables: &[String],
    window: &str,
) -> Option<&'static str> {
    if rel != FAULT_MATRIX_FILE {
        return None;
    }
    if tables == ["outbox"]
        && window.contains("insert into outbox (")
        && window.contains(".execute(pool)")
    {
        return Some(FAULT_MATRIX_SEED_OUTBOX);
    }
    if tables == ["outbox"]
        && window.contains("select count(*)::bigint from outbox")
        && window.contains("event_id = $2")
        && window.contains("status = $3")
        && window.contains(".fetch_one(&self.owner_pool)")
    {
        return Some(FAULT_MATRIX_OUTBOX_STATUS_COUNT);
    }
    if tables == ["dead_letter"]
        && window.contains("from dead_letter")
        && window.contains("source_kind")
        && window.contains("message_id = $2")
        && window.contains(".fetch_optional(&self.owner_pool)")
    {
        return Some(FAULT_MATRIX_DEAD_LETTER_OBSERVATION);
    }
    if tables == ["outbox"]
        && window.contains("select count(*)::bigint from outbox")
        && window.contains("topic = $2")
        && window.contains("contract_id = $3")
        && window.contains(".fetch_one(pool)")
    {
        return Some(FAULT_MATRIX_OUTBOX_CONTRACT_COUNT);
    }
    if tables == ["outbox"]
        && window.contains("update outbox set updated_at")
        && window.contains("status = $3")
        && window.contains(".execute(pool)")
    {
        return Some(FAULT_MATRIX_AGE_OUTBOX_PUBLISHING);
    }
    if tables == ["inbox_receipts"]
        && window.contains("update inbox_receipts set claimed_at")
        && window.contains("consumer_group = $3")
        && window.contains(".execute(pool)")
    {
        return Some(FAULT_MATRIX_AGE_INBOX_CLAIM);
    }
    None
}

fn allowed_fault_matrix_outbox_insert(rel: &str, window: &str) -> Option<&'static str> {
    if rel == FAULT_MATRIX_FILE
        && window.contains("insert into outbox (")
        && window.contains(".execute(pool)")
    {
        return Some(FAULT_MATRIX_SEED_OUTBOX);
    }
    None
}

fn note_raw_pool_field_exception(
    allowed_exceptions: &mut BTreeSet<&'static str>,
    is_exception: bool,
    hits: &[RawPoolFieldAccess],
) {
    if is_exception && !hits.is_empty() {
        allowed_exceptions.insert(FAULT_MATRIX_OWNER_POOL);
    }
}

fn raw_pool_field_findings(
    rel: &str,
    tenant_hits: &[String],
    hits: &[RawPoolFieldAccess],
    is_exception: bool,
) -> Vec<Finding> {
    if tenant_hits.is_empty() || hits.is_empty() || is_exception {
        return Vec::new();
    }
    hits.iter()
        .map(|hit| {
            finding(
                Rule::RawTenantPoolField,
                site_subject(rel, hit.line),
                format!(
                    "tenant tables {:?} share a file with raw pool field {:?}; tenant repositories must store PgTenantPool",
                    tenant_hits, hit.pattern
                ),
            )
        })
        .collect()
}

fn raw_pool_field_exception(rel: &str, content: &str) -> bool {
    if rel == FAULT_MATRIX_FILE {
        return content.matches("owner_pool: pgpool").count() == 1;
    }
    is_raw_pool_field_exception(rel)
}

fn is_raw_pool_field_exception(rel: &str) -> bool {
    matches!(
        rel,
        "auth_audit_sink.rs"
            | "cas_store.rs"
            | "checkpoint.rs"
            | "dead_letter.rs"
            | "dlq.rs"
            | "inbox.rs"
            | "outbox.rs"
            | "projection_events.rs"
    )
}

fn fault_matrix_exception_staleness(files: &[(String, String)]) -> Vec<Finding> {
    let Some((_, fault_matrix)) = files.iter().find(|(rel, _)| rel == FAULT_MATRIX_FILE) else {
        return Vec::new();
    };
    let mut findings = Vec::new();
    let gate_ok = files.iter().any(|(rel, content)| {
        rel == "lib.rs"
            && content.contains(FAULT_MATRIX_LIB_GATE)
            && content.contains("pub mod fault_matrix;")
    });
    if !gate_ok {
        findings.push(finding(
            Rule::StaleException,
            "fault-matrix-test-support-gate",
            "fault_matrix raw-access exceptions require the lib.rs feature gate",
        ));
    }

    let content = strip_rust_comment_lines(&strip_cfg_test_modules(fault_matrix)).to_lowercase();
    for (name, needles) in [
        (FAULT_MATRIX_OWNER_POOL, &["owner_pool: pgpool"][..]),
        (
            FAULT_MATRIX_SEED_OUTBOX,
            &["insert into outbox (", ".execute(pool)"][..],
        ),
        (
            FAULT_MATRIX_OUTBOX_STATUS_COUNT,
            &[
                "select count(*)::bigint from outbox",
                "event_id = $2",
                "status = $3",
                ".fetch_one(&self.owner_pool)",
            ][..],
        ),
        (
            FAULT_MATRIX_DEAD_LETTER_OBSERVATION,
            &[
                "from dead_letter",
                "source_kind",
                "message_id = $2",
                ".fetch_optional(&self.owner_pool)",
            ][..],
        ),
        (
            FAULT_MATRIX_OUTBOX_CONTRACT_COUNT,
            &[
                "select count(*)::bigint from outbox",
                "topic = $2",
                "contract_id = $3",
                ".fetch_one(pool)",
            ][..],
        ),
        (
            FAULT_MATRIX_AGE_OUTBOX_PUBLISHING,
            &[
                "update outbox set updated_at",
                "status = $3",
                ".execute(pool)",
            ][..],
        ),
        (
            FAULT_MATRIX_AGE_INBOX_CLAIM,
            &[
                "update inbox_receipts set claimed_at",
                "consumer_group = $3",
                ".execute(pool)",
            ][..],
        ),
    ] {
        if !needles.iter().all(|needle| content.contains(needle)) {
            findings.push(finding(
                Rule::StaleException,
                name,
                "fault_matrix raw-access exception target is absent or no longer exact",
            ));
        }
    }
    findings
}

fn site_subject(rel: &str, line: usize) -> String {
    format!("{rel}:{line}")
}

fn line_number(content: &str, idx: usize) -> usize {
    content[..idx].bytes().filter(|b| *b == b'\n').count() + 1
}

fn expand_simple_table_consts(src: &str) -> String {
    let consts = simple_table_consts(src);
    let mut out = src.to_string();
    for (name, value) in consts {
        out = out.replace(&format!("{{{name}}}"), &value);
        out = out.replace(&format!("{{{}}}", name.to_lowercase()), &value);
    }
    out
}

fn simple_table_consts(src: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for line in src.lines() {
        let trimmed = line.trim();
        if !trimmed.starts_with("const ") || !trimmed.contains(": &str") {
            continue;
        }
        let Some((lhs, rhs)) = trimmed.split_once('=') else {
            continue;
        };
        let name = lhs
            .trim_start_matches("const ")
            .split(':')
            .next()
            .unwrap_or("")
            .trim();
        let value = rhs.split(';').next().unwrap_or("").trim().trim_matches('"');
        if !name.is_empty() && !value.is_empty() {
            out.insert(name.to_string(), value.to_string());
        }
    }
    out
}

fn strip_cfg_test_modules(src: &str) -> String {
    let mut out = String::with_capacity(src.len());
    let mut pending_cfg_test = false;
    let mut skipping = false;
    let mut depth = 0isize;
    for line in src.lines() {
        let trimmed = line.trim_start();
        if skipping {
            depth += brace_delta(line);
            if depth <= 0 {
                skipping = false;
                depth = 0;
            }
            out.push('\n');
            continue;
        }
        if trimmed.starts_with("#[cfg(") && trimmed.contains("test") {
            pending_cfg_test = true;
            out.push('\n');
            continue;
        }
        if pending_cfg_test && trimmed.starts_with("mod ") {
            depth = brace_delta(line);
            skipping = depth > 0;
            pending_cfg_test = false;
            out.push('\n');
            continue;
        }
        pending_cfg_test = false;
        out.push_str(line);
        out.push('\n');
    }
    out
}

fn strip_rust_comment_lines(src: &str) -> String {
    let mut out = String::with_capacity(src.len());
    for line in src.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("//") || trimmed.starts_with("///") || trimmed.starts_with("//!") {
            out.push('\n');
        } else {
            out.push_str(line);
            out.push('\n');
        }
    }
    out
}

fn brace_delta(line: &str) -> isize {
    line.chars().filter(|c| *c == '{').count() as isize
        - line.chars().filter(|c| *c == '}').count() as isize
}

fn strip_sql_comments(src: &str) -> String {
    let mut out = String::with_capacity(src.len());
    for line in src.lines() {
        let before_comment = line.split("--").next().unwrap_or("");
        out.push_str(before_comment);
        out.push('\n');
    }
    out
}

fn split_token(s: &str) -> (&str, &str) {
    let s = s.trim_start();
    let end = s
        .find(|c: char| !c.is_alphanumeric() && c != '_' && c != '.')
        .unwrap_or(s.len());
    (&s[..end], &s[end..])
}

fn unqualified_table(token: &str) -> &str {
    token.rsplit('.').next().unwrap_or(token)
}

fn parens_body(s: &str) -> Option<&str> {
    let mut depth = 1usize;
    for (i, c) in s.char_indices() {
        match c {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(&s[..i]);
                }
            }
            _ => {}
        }
    }
    None
}

fn braced_body(s: &str) -> Option<(&str, usize)> {
    let mut depth = 1usize;
    for (i, c) in s.char_indices() {
        match c {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return Some((&s[..i], i + c.len_utf8()));
                }
            }
            _ => {}
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn migrations() -> Vec<(String, String)> {
        vec![(
            "0001.sql".to_string(),
            "CREATE TABLE roles (tenant_id uuid NOT NULL, id text);\n\
             CREATE TABLE credentials (tenant_id uuid NOT NULL, id text);\n\
             CREATE TABLE config_entries (tenant_id uuid NOT NULL, key text, protection_scheme int);\n\
             CREATE TABLE audit_entries (tenant_id uuid NOT NULL, seq bigint);\n\
             CREATE TABLE command_journal (tenant_id uuid NOT NULL, command_id text);\n\
             CREATE TABLE outbox (event_id text);\n\
             CREATE TABLE dead_letter (tenant_id uuid NOT NULL, id uuid);"
                .to_string(),
        )]
    }

    fn files(entries: &[(&str, &str)]) -> Vec<(String, String)> {
        entries
            .iter()
            .map(|(p, c)| ((*p).to_string(), (*c).to_string()))
            .collect()
    }

    fn secret_retry_green_source() -> &'static str {
        r#"
impl SecretUnitOfWork for PgSecretUnitOfWork {
    async fn publish(&self, command: SecretPublishCommand) {
        let (entry, observation) = command.into_parts();
        run_pg_localtx_retry(
            observation,
            |_attempt| async { self.pool.retry_write() },
            classify,
        ).await;
    }

    async fn publish_internal(&self, command: SecretInternalPublishCommand) {
        run_pg_tx_retry(
            SETTINGS_SECRET_BOUNDARY,
            |_attempt| async { self.pool.retry_write() },
            classify,
        ).await;
    }

    async fn republish(&self, command: SecretRepublishCommand) {
        run_pg_tx_retry(
            SETTINGS_SECRET_BOUNDARY,
            |_attempt| async { self.pool.retry_write() },
            classify,
        ).await;
    }
}
"#
    }

    fn secret_mutation_green_source() -> &'static str {
        r#"
impl PgSecretUnitOfWork {
    async fn cas_insert_locked(tx: &mut TxCapability<'_>, tenant: TenantId, entry: SecretEntry) {
        let key = entry.key();
        LockedSecretKey::acquire(tx, tenant, key).await.unwrap().cas_insert(&entry).await;
    }
}

impl SecretUnitOfWork for PgSecretUnitOfWork {
    async fn publish(&self) { Self::cas_insert_locked(tx, tenant, entry).await; }
    async fn publish_internal(&self) { Self::cas_insert_locked(tx, tenant, entry).await; }
    async fn republish(&self) { Self::cas_insert_locked(tx, tenant, entry).await; }
    async fn delete(&self) {
        LockedSecretKey::acquire(tx, tenant, key).await.unwrap().append_tombstone().await;
    }
}

mod key_lock {
    impl<'cap, 'tx> LockedSecretKey<'cap, 'tx> {
        pub(super) async fn acquire(
            tx: &'cap mut TxCapability<'tx>,
            tenant: TenantId,
            key: &SecretKey,
        ) -> Result<Self, SecretRepoError> {
            let tenant_uuid = tenant_param(tenant);
            let key = key.as_str().to_owned();
            sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1 || chr(31) || $2, 0))")
                .bind(&tenant_uuid)
                .bind(&key)
                .execute(tx.conn())
                .await
                .map_err(storage)?;
            Ok(Self { tx, tenant, tenant_uuid, key })
        }

        async fn cas_insert(self) {
            sqlx::query("INSERT INTO secret_refs (tenant_id, secret_key) VALUES ($1, $2)").execute(self.conn()).await;
        }

        async fn append_tombstone(self) {
            sqlx::query("INSERT INTO secret_refs (tenant_id, secret_key, deleted) VALUES ($1, $2, TRUE)").execute(self.conn()).await;
        }
    }
}
"#
    }

    #[test]
    fn feature_harness_skip_requires_exact_fault_matrix_module_gate() {
        let gated_lib = r#"
#[cfg(feature = "fault-matrix-test-support")]
pub mod fault_matrix;
"#;
        assert!(is_feature_gated_harness_rel("fault_matrix.rs", gated_lib));
        assert!(!is_feature_gated_harness_rel(
            "subsystem/fault_matrix.rs",
            gated_lib
        ));
    }

    #[test]
    fn feature_harness_skip_requires_feature_gate() {
        assert!(!is_feature_gated_harness_rel(
            "fault_matrix.rs",
            "pub mod fault_matrix;"
        ));
        assert!(!is_feature_gated_harness_rel(
            "fault_matrix.rs",
            r#"
#[cfg(test)]
pub mod fault_matrix;
"#
        ));
    }

    #[test]
    fn red_direct_pool_begin_touching_tenant_table() {
        let (_, findings) = scan_guard(
            &migrations(),
            &files(&[
                (
                    "dead_letter.rs",
                    "fn sweep(){ sqlx::query(\"DELETE FROM dead_letter WHERE last_attempt_at <= now() - make_interval(secs => $1)\").execute(&self.maintenance_pool); }",
                ),
                (
                    "role_repo.rs",
                    "async fn f(){ let mut tx = self.pool.begin().await; sqlx::query(\"SELECT * FROM roles\"); }",
                ),
            ]),
        );
        assert!(
            findings
                .iter()
                .any(|f| f.rule == Rule::RawTenantTableAccess)
        );
    }

    #[test]
    fn red_direct_pool_executor_touching_tenant_table() {
        let (_, findings) = scan_guard(
            &migrations(),
            &files(&[
                (
                    "dead_letter.rs",
                    "fn sweep(){ sqlx::query(\"DELETE FROM dead_letter WHERE last_attempt_at <= now() - make_interval(secs => $1)\").execute(&self.maintenance_pool); }",
                ),
                (
                    "credential_repo.rs",
                    "async fn f(){ sqlx::query(\"SELECT * FROM credentials\").fetch_optional(&self.pool).await; }",
                ),
            ]),
        );
        assert!(
            findings
                .iter()
                .any(|f| f.rule == Rule::RawTenantTableAccess)
        );
    }

    #[test]
    fn command_journal_is_derived_as_tenant_table_and_raw_access_is_reported() {
        let tenant_tables = tenant_tables_from_migrations(&migrations());
        assert!(
            tenant_tables.contains("command_journal"),
            "{tenant_tables:?}"
        );

        let (_, findings) = scan_guard(
            &migrations(),
            &files(&[
                (
                    "dead_letter.rs",
                    "fn sweep(){ sqlx::query(\"DELETE FROM dead_letter WHERE last_attempt_at <= now() - make_interval(secs => $1)\").execute(&self.maintenance_pool); }",
                ),
                (
                    "command_journal.rs",
                    "async fn f(){ sqlx::query(\"SELECT * FROM command_journal\").fetch_one(&self.pool).await; }",
                ),
            ]),
        );
        assert!(
            findings.iter().any(|f| {
                f.rule == Rule::RawTenantTableAccess && f.subject.starts_with("command_journal.rs:")
            }),
            "{findings:?}"
        );
    }

    #[test]
    fn red_tenant_repo_storing_raw_pgpool() {
        let (_, findings) = scan_guard(
            &migrations(),
            &files(&[
                (
                    "dead_letter.rs",
                    "fn sweep(){ sqlx::query(\"DELETE FROM dead_letter WHERE last_attempt_at <= now() - make_interval(secs => $1)\").execute(&self.maintenance_pool); }",
                ),
                (
                    "role_repo.rs",
                    "struct Repo {\n    pool: PgPool,\n}\nfn f(){ sqlx::query(\"SELECT * FROM roles\"); }",
                ),
            ]),
        );
        assert!(findings.iter().any(|f| f.rule == Rule::RawTenantPoolField));
    }

    #[test]
    fn red_outbox_insert_outside_outbox_funnel() {
        let (_, findings) = scan_guard(
            &migrations(),
            &files(&[
                (
                    "dead_letter.rs",
                    "fn sweep(){ sqlx::query(\"DELETE FROM dead_letter WHERE last_attempt_at <= now() - make_interval(secs => $1)\").execute(&self.maintenance_pool); }",
                ),
                (
                    "dlq.rs",
                    "async fn replay(){ sqlx::query(\"INSERT INTO outbox (event_id) VALUES ($1)\").execute(conn.conn()).await; }",
                ),
            ]),
        );
        assert!(
            findings.iter().any(|f| f.rule == Rule::RawOutboxInsert),
            "{findings:?}"
        );
    }

    #[test]
    fn green_outbox_log_insert_is_owned_by_cdc_funnel() {
        let (_, findings) = scan_guard(
            &migrations(),
            &files(&[
                (
                    "dead_letter.rs",
                    "fn sweep(){ sqlx::query(\"DELETE FROM dead_letter WHERE last_attempt_at <= now() - make_interval(secs => $1)\").execute(&self.maintenance_pool); }",
                ),
                (
                    "outbox.rs",
                    "async fn append_outbox(){ sqlx::query(\"INSERT INTO outbox (event_id) VALUES ($1)\").execute(conn.conn()).await; }\n\
                     async fn append_replayed_outbox(){ sqlx::query(\"INSERT INTO outbox (event_id) VALUES ($1)\").execute(conn.conn()).await; }",
                ),
                (
                    "outbox_cdc.rs",
                    "async fn append_outbox_log(){ sqlx::query(\"INSERT INTO outbox_log (event_id) VALUES ($1)\").execute(conn.conn()).await; }",
                ),
            ]),
        );
        assert!(
            !findings.iter().any(|f| f.rule == Rule::RawOutboxInsert),
            "{findings:?}"
        );
    }

    #[test]
    fn red_outbox_insert_in_owner_file_but_wrong_symbol() {
        let (_, findings) = scan_guard(
            &migrations(),
            &files(&[
                (
                    "dead_letter.rs",
                    "fn sweep(){ sqlx::query(\"DELETE FROM dead_letter WHERE last_attempt_at <= now() - make_interval(secs => $1)\").execute(&self.maintenance_pool); }",
                ),
                (
                    "outbox.rs",
                    "async fn append_outbox(){ sqlx::query(\"INSERT INTO outbox (event_id) VALUES ($1)\").execute(conn.conn()).await; }\n\
                     async fn append_replayed_outbox(){ sqlx::query(\"INSERT INTO outbox (event_id) VALUES ($1)\").execute(conn.conn()).await; }\n\
                     async fn accidental_bypass(){ sqlx::query(\"INSERT INTO outbox (event_id) VALUES ($1)\").execute(conn.conn()).await; }",
                ),
                (
                    "outbox_cdc.rs",
                    "async fn append_outbox_log(){ sqlx::query(\"INSERT INTO outbox_log (event_id) VALUES ($1)\").execute(conn.conn()).await; }",
                ),
            ]),
        );
        assert!(
            findings.iter().any(|finding| {
                finding.rule == Rule::RawOutboxInsert && finding.subject.starts_with("outbox.rs:")
            }),
            "{findings:?}"
        );
    }

    #[test]
    fn red_duplicate_outbox_insert_inside_allowed_owner_symbol() {
        let (_, findings) = scan_guard(
            &migrations(),
            &files(&[
                (
                    "dead_letter.rs",
                    "fn sweep(){ sqlx::query(\"DELETE FROM dead_letter WHERE last_attempt_at <= now() - make_interval(secs => $1)\").execute(&self.maintenance_pool); }",
                ),
                (
                    "outbox.rs",
                    "async fn append_outbox(){ \
                         sqlx::query(\"INSERT INTO outbox (event_id) VALUES ($1)\").execute(conn.conn()).await; \
                         sqlx::query(\"INSERT INTO outbox (event_id) VALUES ($1)\").execute(conn.conn()).await; \
                     }\n\
                     async fn append_replayed_outbox(){ sqlx::query(\"INSERT INTO outbox (event_id) VALUES ($1)\").execute(conn.conn()).await; }",
                ),
                (
                    "outbox_cdc.rs",
                    "async fn append_outbox_log(){ sqlx::query(\"INSERT INTO outbox_log (event_id) VALUES ($1)\").execute(conn.conn()).await; }",
                ),
            ]),
        );
        assert!(
            findings.iter().any(|finding| {
                finding.rule == Rule::OutboxInsertSitesAbsent
                    && finding.subject == "outbox.rs::append_outbox"
            }),
            "{findings:?}"
        );
    }

    #[test]
    fn anti_vacuity_missing_exact_outbox_owner_symbol_is_reported() {
        let (_, findings) = scan_guard(
            &migrations(),
            &files(&[
                (
                    "dead_letter.rs",
                    "fn sweep(){ sqlx::query(\"DELETE FROM dead_letter WHERE last_attempt_at <= now() - make_interval(secs => $1)\").execute(&self.maintenance_pool); }",
                ),
                (
                    "outbox.rs",
                    "async fn append_outbox(){ sqlx::query(\"INSERT INTO outbox (event_id) VALUES ($1)\").execute(conn.conn()).await; }",
                ),
                (
                    "outbox_cdc.rs",
                    "async fn append_outbox_log(){ sqlx::query(\"INSERT INTO outbox_log (event_id) VALUES ($1)\").execute(conn.conn()).await; }",
                ),
            ]),
        );
        assert!(
            findings.iter().any(|finding| {
                finding.rule == Rule::OutboxInsertSitesAbsent
                    && finding.subject == "outbox.rs::append_replayed_outbox"
            }),
            "{findings:?}"
        );
    }

    #[test]
    fn red_outbox_log_insert_outside_cdc_funnel() {
        let (_, findings) = scan_guard(
            &migrations(),
            &files(&[
                (
                    "dead_letter.rs",
                    "fn sweep(){ sqlx::query(\"DELETE FROM dead_letter WHERE last_attempt_at <= now() - make_interval(secs => $1)\").execute(&self.maintenance_pool); }",
                ),
                (
                    "emitter.rs",
                    "async fn append(){ sqlx::query(\"INSERT INTO outbox_log (event_id) VALUES ($1)\").execute(conn.conn()).await; }",
                ),
            ]),
        );
        assert!(
            findings.iter().any(|f| f.rule == Rule::RawOutboxInsert),
            "{findings:?}"
        );
    }

    #[test]
    fn red_outbox_producer_opening_raw_transaction_for_append() {
        let (_, findings) = scan_guard(
            &migrations(),
            &files(&[
                (
                    "dead_letter.rs",
                    "fn sweep(){ sqlx::query(\"DELETE FROM dead_letter WHERE last_attempt_at <= now() - make_interval(secs => $1)\").execute(&self.maintenance_pool); }",
                ),
                (
                    "emitter.rs",
                    "async fn emit(){ let tx = self.pool.begin().await; append_outbox(&mut tx, &entry, &env).await; }",
                ),
            ]),
        );
        assert!(
            findings.iter().any(|f| f.rule == Rule::OutboxAppendBypass),
            "{findings:?}"
        );
    }

    #[test]
    fn red_outbox_producer_run_global_transaction_for_append() {
        let (_, findings) = scan_guard(
            &migrations(),
            &files(&[
                (
                    "dead_letter.rs",
                    "fn sweep(){ sqlx::query(\"DELETE FROM dead_letter WHERE last_attempt_at <= now() - make_interval(secs => $1)\").execute(&self.maintenance_pool); }",
                ),
                (
                    "role_binding_lifecycle.rs",
                    "async fn bind(){ store.run_global_transaction(|cap| append_outbox(cap, &entry, &env)); }",
                ),
            ]),
        );
        assert!(
            findings.iter().any(|f| f.rule == Rule::OutboxAppendBypass),
            "{findings:?}"
        );
    }

    #[test]
    fn red_tx_capability_mint_outside_funnel() {
        let (_, findings) = scan_guard(
            &migrations(),
            &files(&[
                (
                    "dead_letter.rs",
                    "fn sweep(){ sqlx::query(\"DELETE FROM dead_letter WHERE last_attempt_at <= now() - make_interval(secs => $1)\").execute(&self.maintenance_pool); }",
                ),
                (
                    "emitter.rs",
                    "async fn emit(){ let mut cap = TxCapability::from_transaction(&mut tx); append_outbox(&mut cap, &entry, &env).await; }",
                ),
            ]),
        );
        assert!(
            findings
                .iter()
                .any(|f| f.rule == Rule::TxCapabilityMintOutsideFunnel),
            "{findings:?}"
        );
    }

    #[test]
    fn red_pool_acquire_and_global_tx_touching_tenant_table() {
        let (_, findings) = scan_guard(
            &migrations(),
            &files(&[
                (
                    "outbox.rs",
                    "fn settle_dlx(){ set_local_tenant(); sqlx::query(\"INSERT INTO dead_letter VALUES (1)\"); pool.begin().await; }",
                ),
                (
                    "dead_letter.rs",
                    "fn sweep(){ sqlx::query(\"DELETE FROM dead_letter WHERE last_attempt_at <= now() - make_interval(secs => $1)\").execute(&self.maintenance_pool); }",
                ),
                (
                    "session_lifecycle.rs",
                    "async fn f(){ let c = pool.acquire().await; store.run_global_transaction(|_| sqlx::query(\"UPDATE roles SET id=id\")); }",
                ),
            ]),
        );
        assert!(
            findings
                .iter()
                .any(|f| f.rule == Rule::RawTenantTableAccess)
        );
    }

    #[test]
    fn red_dynamic_table_const_is_resolved() {
        let (_, findings) = scan_guard(
            &migrations(),
            &files(&[
                (
                    "outbox.rs",
                    "fn settle_dlx(){ set_local_tenant(); sqlx::query(\"INSERT INTO dead_letter VALUES (1)\"); pool.begin().await; }",
                ),
                (
                    "dead_letter.rs",
                    "fn sweep(){ sqlx::query(\"DELETE FROM dead_letter WHERE last_attempt_at <= now() - make_interval(secs => $1)\").execute(&self.maintenance_pool); }",
                ),
                (
                    "audit_repo.rs",
                    "const TABLE: &str = \"audit_entries\"; async fn f(){ sqlx::query(&format!(\"SELECT * FROM {TABLE}\")).execute(&self.pool).await; }",
                ),
            ]),
        );
        assert!(
            findings
                .iter()
                .any(|f| f.rule == Rule::RawTenantTableAccess)
        );
    }

    #[test]
    fn red_named_exception_file_does_not_mask_extra_raw_tenant_access() {
        let (_, findings) = scan_guard(
            &migrations(),
            &files(&[
                (
                    "outbox.rs",
                    "fn settle_dlx(){ set_local_tenant(); sqlx::query(\"INSERT INTO dead_letter VALUES (1)\"); pool.begin().await; }",
                ),
                (
                    "dead_letter.rs",
                    "fn sweep(){ sqlx::query(\"DELETE FROM dead_letter WHERE last_attempt_at <= now() - make_interval(secs => $1)\").execute(&self.maintenance_pool); }\n\
                     async fn bypass(){ let mut tx = self.maintenance_pool.begin().await; sqlx::query(\"UPDATE roles SET id=id\"); }",
                ),
            ]),
        );
        assert!(
            findings
                .iter()
                .any(|f| f.rule == Rule::RawTenantTableAccess),
            "{findings:?}"
        );
    }

    #[test]
    fn red_direct_connection_executor_touching_tenant_table() {
        let (_, findings) = scan_guard(
            &migrations(),
            &files(&[
                (
                    "outbox.rs",
                    "fn settle_dlx(){ set_local_tenant(); sqlx::query(\"INSERT INTO dead_letter VALUES (1)\"); pool.begin().await; }",
                ),
                (
                    "dead_letter.rs",
                    "fn sweep(){ sqlx::query(\"DELETE FROM dead_letter WHERE last_attempt_at <= now() - make_interval(secs => $1)\").execute(&self.maintenance_pool); }",
                ),
                (
                    "role_repo.rs",
                    "async fn f(){ let mut conn = PgConnection::connect(url).await; sqlx::query(\"SELECT * FROM roles\").fetch_all(&mut conn).await; }",
                ),
            ]),
        );
        assert!(
            findings
                .iter()
                .any(|f| f.rule == Rule::RawTenantTableAccess),
            "{findings:?}"
        );
    }

    #[test]
    fn red_global_tx_calling_tenant_pgconnection_helper() {
        let (_, findings) = scan_guard(
            &migrations(),
            &files(&[
                (
                    "outbox.rs",
                    "fn settle_dlx(){ set_local_tenant(); sqlx::query(\"INSERT INTO dead_letter VALUES (1)\"); pool.begin().await; }",
                ),
                (
                    "dead_letter.rs",
                    "fn sweep(){ sqlx::query(\"DELETE FROM dead_letter WHERE last_attempt_at <= now() - make_interval(secs => $1)\").execute(&self.maintenance_pool); }",
                ),
                (
                    "session_lifecycle.rs",
                    "async fn write_session(conn: &mut PgConnection){ sqlx::query(\"INSERT INTO roles VALUES (1)\").execute(&mut *conn).await; }\n\
                     async fn f(){ store.run_global_transaction(|conn| write_session(conn)); }",
                ),
            ]),
        );
        assert!(
            findings
                .iter()
                .any(|f| f.rule == Rule::RawTenantTableAccess),
            "{findings:?}"
        );
    }

    #[test]
    fn red_core_file_exception_does_not_mask_raw_tenant_access() {
        let (_, findings) = scan_guard(
            &migrations(),
            &files(&[
                (
                    "outbox.rs",
                    "fn settle_dlx(){ set_local_tenant(); sqlx::query(\"INSERT INTO dead_letter VALUES (1)\"); pool.begin().await; }",
                ),
                (
                    "dead_letter.rs",
                    "fn sweep(){ sqlx::query(\"DELETE FROM dead_letter WHERE last_attempt_at <= now() - make_interval(secs => $1)\").execute(&self.maintenance_pool); }",
                ),
                (
                    "pool.rs",
                    "async fn bypass(){ let mut tx = self.pool.begin().await; sqlx::query(\"SELECT * FROM roles\"); }",
                ),
                (
                    "tx.rs",
                    "async fn bypass(){ store.run_global_transaction(|_| sqlx::query(\"UPDATE credentials SET id=id\")); }",
                ),
            ]),
        );
        assert!(
            findings
                .iter()
                .filter(|f| f.rule == Rule::RawTenantTableAccess)
                .count()
                >= 2,
            "{findings:?}"
        );
    }

    #[test]
    fn red_raw_pool_executor_argument_touching_tenant_table() {
        let (_, findings) = scan_guard(
            &migrations(),
            &files(&[
                (
                    "outbox.rs",
                    "fn settle_dlx(){ set_local_tenant(); sqlx::query(\"INSERT INTO dead_letter VALUES (1)\"); pool.begin().await; }",
                ),
                (
                    "dead_letter.rs",
                    "fn sweep(){ sqlx::query(\"DELETE FROM dead_letter WHERE last_attempt_at <= now() - make_interval(secs => $1)\").execute(&self.maintenance_pool); }",
                ),
                (
                    "role_repo.rs",
                    "async fn f(pool: &PgPool, store: Store){ sqlx::query(\"SELECT * FROM roles\").fetch_one(pool).await; sqlx::query(\"UPDATE credentials SET id=id\").execute(&store.pool).await; }",
                ),
            ]),
        );
        assert!(
            findings
                .iter()
                .any(|f| f.rule == Rule::RawTenantTableAccess),
            "{findings:?}"
        );
    }

    #[test]
    fn red_dead_letter_raw_retention_sweep_is_not_allowlisted() {
        let (_, findings) = scan_guard(
            &migrations(),
            &files(&[
                (
                    "dead_letter.rs",
                    "fn sweep(){ sqlx::query(\"DELETE FROM dead_letter WHERE last_attempt_at <= now() - make_interval(secs => $1)\").execute(&self.maintenance_pool); }",
                ),
                (
                    "migrator.rs",
                    "fn legacy_config_plaintext_count(){ sqlx::query_scalar(\"SELECT COUNT(*)::bigint FROM config_entries WHERE protection_scheme = 0\").fetch_one(&self.pool).await; }",
                ),
            ]),
        );
        assert!(
            findings.iter().any(|f| f.rule == Rule::RawTenantTableAccess
                && f.subject.starts_with("dead_letter.rs:")),
            "{findings:?}"
        );
    }

    #[test]
    fn green_fault_matrix_test_support_is_file_level_exception() {
        let (_, findings) = scan_guard(
            &migrations(),
            &files(&[
                (
                    "role_repo.rs",
                    "fn safe_site(){ sqlx::query(\"SELECT id FROM roles WHERE tenant_id = $1\"); }",
                ),
                (
                    "fault_matrix.rs",
                    "struct Harness { owner_pool: PgPool } \
                     async fn seed(pool: &PgPool) { \
                         sqlx::query(\"INSERT INTO outbox (event_id) VALUES ($1)\").execute(pool).await; \
                         sqlx::query(\"DELETE FROM inbox_receipts WHERE tenant_id = $1\").execute(pool).await; \
                     }",
                ),
            ]),
        );
        assert!(
            findings.iter().all(|finding| !matches!(
                finding.rule,
                Rule::RawTenantTableAccess | Rule::RawTenantPoolField | Rule::RawOutboxInsert
            )),
            "{findings:?}"
        );
    }

    #[test]
    fn red_fault_matrix_extra_raw_tenant_access_is_not_file_level_exception() {
        let (_, findings) = scan_guard(
            &migrations(),
            &files(&[
                (
                    "role_repo.rs",
                    "fn safe_site(){ sqlx::query(\"SELECT id FROM roles WHERE tenant_id = $1\"); }",
                ),
                (
                    "fault_matrix.rs",
                    "struct Harness { owner_pool: PgPool } \
                     async fn seed(pool: &PgPool) { \
                         sqlx::query(\"INSERT INTO outbox (event_id) VALUES ($1)\").execute(pool).await; \
                     } \
                     async fn accidental(&self) { \
                         sqlx::query(\"DELETE FROM roles WHERE tenant_id = $1\").execute(&self.owner_pool).await; \
                     }",
                ),
            ]),
        );
        assert!(
            findings
                .iter()
                .any(|finding| finding.rule == Rule::RawTenantTableAccess),
            "{findings:?}"
        );
    }

    #[test]
    fn red_local_pgpool_variable_touching_tenant_table() {
        let (_, findings) = scan_guard(
            &migrations(),
            &files(&[
                (
                    "outbox.rs",
                    "fn settle_dlx(){ set_local_tenant(); sqlx::query(\"INSERT INTO dead_letter VALUES (1)\"); pool.begin().await; }",
                ),
                (
                    "dead_letter.rs",
                    "fn sweep(){ sqlx::query(\"DELETE FROM dead_letter WHERE last_attempt_at <= now() - make_interval(secs => $1)\").execute(&self.maintenance_pool); }",
                ),
                (
                    "role_repo.rs",
                    "async fn f(){ let raw_pool: PgPool = make_pool(); sqlx::query(\"SELECT * FROM roles\").fetch_all(&raw_pool).await; }",
                ),
            ]),
        );
        assert!(
            findings
                .iter()
                .any(|f| f.rule == Rule::RawTenantTableAccess),
            "{findings:?}"
        );
    }

    #[test]
    fn red_raw_tenant_access_finding_reports_file_line() {
        let (_, findings) = scan_guard(
            &migrations(),
            &files(&[
                (
                    "outbox.rs",
                    "fn settle_dlx(){ set_local_tenant(); sqlx::query(\"INSERT INTO dead_letter VALUES (1)\"); pool.begin().await; }",
                ),
                (
                    "dead_letter.rs",
                    "fn sweep(){ sqlx::query(\"DELETE FROM dead_letter WHERE last_attempt_at <= now() - make_interval(secs => $1)\").execute(&self.maintenance_pool); }",
                ),
                (
                    "role_repo.rs",
                    "fn ok() {}\n\nasync fn f(){ sqlx::query(\"SELECT * FROM roles\").fetch_optional(&self.pool).await; }",
                ),
            ]),
        );
        assert!(
            findings
                .iter()
                .any(|f| f.rule == Rule::RawTenantTableAccess && f.subject == "role_repo.rs:3"),
            "{findings:?}"
        );
    }

    #[test]
    fn red_outbox_dlx_real_settlement_shape_is_reported() {
        let padding = "let _padding = 1;\n".repeat(220);
        let outbox = format!(
            "async fn settle_dlx(pool: &sqlx::PgPool) {{\n\
             let mut tx = pool.begin().await?;\n\
             let row = sqlx::query_as(\"SELECT tenant_id, domain FROM rss_outbox_mark_dlx($1, $2, $3::uuid)\")\n\
             .fetch_optional(&mut *tx).await?;\n\
             {padding}\n\
             sqlx::query(\"INSERT INTO dead_letter (tenant_id, message_id) VALUES ($1::uuid, $2)\")\n\
             .execute(&mut *tx).await?;\n\
             tx.commit().await?;\n\
             }}"
        );
        let (_, findings) = scan_guard(
            &migrations(),
            &files(&[
                ("outbox.rs", outbox.as_str()),
                (
                    "migrator.rs",
                    "fn legacy_config_plaintext_count(){ sqlx::query_scalar(\"SELECT COUNT(*)::bigint FROM config_entries WHERE protection_scheme = 0\").fetch_one(&self.pool).await; }",
                ),
                (
                    "config_repo.rs",
                    "async fn select_maintenance_rows(&self){ sqlx::query(\"SELECT tenant_id::text, config_key, version, value, value_enc, key_id FROM config_entries WHERE protection_scheme = $1 ORDER BY tenant_id::text, config_key, version LIMIT $2\").fetch_all(&self.store.pool).await; }\n\
                     async fn backfill_row(&self){ sqlx::query(\"UPDATE config_entries SET value = NULL, protection_scheme = $4 WHERE tenant_id = $1::uuid AND protection_scheme = 0\").execute(&self.store.pool).await; }\n\
                     async fn rewrap_row(&self){ sqlx::query(\"UPDATE config_entries SET value_enc = $4 WHERE tenant_id = $1::uuid AND protection_scheme = 1\").execute(&self.store.pool).await; }\n\
                     async fn remaining_plaintext(&self){ sqlx::query_scalar(\"SELECT COUNT(*)::bigint FROM config_entries WHERE protection_scheme = 0\").fetch_one(&self.store.pool).await; }",
                ),
            ]),
        );
        assert!(
            findings.iter().any(|f| {
                f.rule == Rule::RawTenantTableAccess && f.subject.starts_with("outbox.rs:")
            }),
            "{findings:?}"
        );
    }

    #[test]
    fn green_scoped_tenant_and_global_tables_pass() {
        let (_, findings) = scan_guard(
            &migrations(),
            &files(&[
                (
                    "role_repo.rs",
                    "struct R { pool: PgTenantPool } async fn f(){ self.pool.read(tenant, |conn| Box::pin(async move { sqlx::query(\"SELECT * FROM roles\").fetch_optional(&mut *conn).await })); }",
                ),
                (
                    "config_repo.rs",
                    "async fn f(){ self.pool.write(tenant, |conn| Box::pin(async move { sqlx::query(\"UPDATE credentials SET id=id\").execute(&mut *conn).await.map_err(storage) }), storage); }",
                ),
                (
                    "migrator.rs",
                    "fn legacy_config_plaintext_count(){ sqlx::query_scalar(\"SELECT COUNT(*)::bigint FROM config_entries WHERE protection_scheme = 0\").fetch_one(&self.pool).await; }",
                ),
                (
                    "migrator.rs",
                    "async fn legacy_config_plaintext_count(&self){ sqlx::query_scalar(\"SELECT COUNT(*)::bigint FROM config_entries WHERE protection_scheme = 0\").fetch_one(&self.pool).await; }",
                ),
                (
                    "config_repo.rs",
                    "async fn select_maintenance_rows(&self){ sqlx::query(\"SELECT tenant_id::text, config_key, version, value, value_enc, key_id FROM config_entries WHERE protection_scheme = $1 ORDER BY tenant_id::text, config_key, version LIMIT $2\").fetch_all(&self.store.pool).await; }",
                ),
                (
                    "config_repo.rs",
                    "async fn backfill_row(&self){ sqlx::query(\"UPDATE config_entries SET value = NULL, protection_scheme = $4 WHERE tenant_id = $1::uuid AND protection_scheme = 0\").execute(&self.store.pool).await; }",
                ),
                (
                    "config_repo.rs",
                    "async fn rewrap_row(&self){ sqlx::query(\"UPDATE config_entries SET value_enc = $4 WHERE tenant_id = $1::uuid AND protection_scheme = 1\").execute(&self.store.pool).await; }",
                ),
                (
                    "config_repo.rs",
                    "async fn remaining_plaintext(&self){ sqlx::query_scalar(\"SELECT COUNT(*)::bigint FROM config_entries WHERE protection_scheme = 0\").fetch_one(&self.store.pool).await; }",
                ),
            ]),
        );
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn anti_vacuity_no_tenant_tables_or_files_or_sites() {
        let (_, findings) = scan_guard(&[], &[]);
        assert!(findings.iter().any(|f| f.rule == Rule::TenantTablesAbsent));
        assert!(findings.iter().any(|f| f.rule == Rule::ProdFilesAbsent));
        assert!(findings.iter().any(|f| f.rule == Rule::SqlSitesAbsent));
    }

    #[test]
    fn stale_exception_is_reported() {
        let (_, findings) = scan_guard(
            &migrations(),
            &files(&[(
                "role_repo.rs",
                "self.pool.read(tenant, |conn| Box::pin(async move { sqlx::query(\"SELECT * FROM roles\").fetch_optional(&mut *conn).await }));",
            )]),
        );
        assert!(findings.iter().any(|f| f.rule == Rule::StaleException));
    }

    #[test]
    fn cfg_test_modules_are_ignored() {
        let stripped = strip_cfg_test_modules(
            "#[cfg(test)]\nmod tests { fn f(){ self.pool.begin().await; } }\nfn prod() {}\n",
        );
        assert!(!stripped.contains("self.pool.begin"));
        assert!(stripped.contains("fn prod"));

        let stripped = strip_cfg_test_modules(
            "#[cfg(all(test, feature = \"integration\"))]\n\
             mod integration_tests {\n\
                 fn f(){ self.pool.begin().await; }\n\
             }\n\
             fn prod() {}\n",
        );
        assert!(!stripped.contains("self.pool.begin"));
        assert!(stripped.contains("fn prod"));
    }

    #[test]
    fn retry_guard_rejects_direct_engine_retry_and_alias_outside_boundary() {
        let mut sites = BTreeSet::new();
        let direct = retry_placement_findings(
            "role_repo.rs",
            "async fn save(){ run_tx_retry(policy, op, classify, sleep).await; }",
            &mut sites,
        );
        assert!(direct.iter().any(|f| f.rule == Rule::RetryPlacement));

        let alias = retry_placement_findings(
            "role_repo.rs",
            "use crate::tx_retry::run_pg_tx_retry as retry; async fn save(){ retry(B, op, c).await; }",
            &mut sites,
        );
        assert!(alias.iter().any(|f| f.rule == Rule::RetryPlacement));
    }

    #[test]
    fn retry_guard_allows_engine_retry_only_in_private_core_including_alias() {
        let mut sites = BTreeSet::new();
        for source in [
            "async fn run_pg_tx_retry_core(){ run_tx_retry(policy, op, classify, sleep).await; }",
            "use consistency::run_tx_retry as engine_retry; async fn run_pg_tx_retry_core(){ engine_retry(policy, op, classify, sleep).await; }",
        ] {
            let findings = retry_placement_findings("tx_retry.rs", source, &mut sites);
            assert!(
                findings.is_empty(),
                "core engine call rejected: {findings:?}"
            );
        }
    }

    #[test]
    fn retry_guard_resolves_grouped_multiline_direct_alias_and_glob() {
        let mut sites = BTreeSet::new();
        for source in [
            "use consistency::{\n run_tx_retry as retry\n}; async fn save(){ retry(policy, op, classify, sleep).await; }",
            "use consistency::*; async fn save(){ run_tx_retry(policy, op, classify, sleep).await; }",
        ] {
            let findings = retry_placement_findings("role_repo.rs", source, &mut sites);
            assert!(
                findings.iter().any(|f| f.rule == Rule::RetryPlacement),
                "alias/glob must not bypass retry placement: {findings:?}"
            );
        }
    }

    #[test]
    fn retry_guard_resolves_block_local_aliases_and_respects_shadowing() {
        let mut sites = BTreeSet::new();
        for source in [
            "async fn save(){ use consistency::run_tx_retry as retry; retry(policy, op, classify, sleep).await; }",
            "async fn save(){ use crate::tx_retry::run_pg_tx_retry as retry; retry(B, op, c).await; }",
        ] {
            let findings = retry_placement_findings("role_repo.rs", source, &mut sites);
            assert!(
                findings
                    .iter()
                    .any(|finding| finding.rule == Rule::RetryPlacement),
                "block-local alias must not bypass retry placement: {findings:?}"
            );
        }

        let findings = retry_placement_findings(
            "role_repo.rs",
            "use crate::tx_retry::run_pg_tx_retry as retry; async fn save(){ let retry = helper; retry(B, op, c).await; }",
            &mut sites,
        );
        assert!(
            findings.is_empty(),
            "a lexical value binding must shadow the imported wrapper: {findings:?}"
        );
    }

    #[test]
    fn retry_guard_ast_ignores_comment_and_string_bait() {
        let mut sites = BTreeSet::new();
        let findings = retry_placement_findings(
            "role_repo.rs",
            r#"async fn save(){ let _ = "run_tx_retry(policy, op, classify, sleep)"; /* run_pg_tx_retry(B, op, c) */ }"#,
            &mut sites,
        );
        assert!(
            findings.is_empty(),
            "non-call bait must be ignored: {findings:?}"
        );
    }

    #[test]
    fn retry_guard_accepts_grouped_generic_wrapper_alias_inside_exact_boundary() {
        let mut sites = BTreeSet::new();
        let findings = retry_placement_findings(
            "config_repo.rs",
            "use crate::tx_retry::{run_pg_tx_retry as retry}; impl Uow { async fn commit(&self){ retry(SETTINGS_CONFIG_BOUNDARY, || async { self.pool.retry_co_tx_with_outbox() }, classify).await; } }",
            &mut sites,
        );
        assert!(findings.is_empty(), "{findings:?}");
        assert!(sites.contains("settings-config-commit"));
    }

    #[test]
    fn retry_guard_accepts_local_wrapper_alias_with_typed_identity_command() {
        let mut sites = BTreeSet::new();
        let findings = retry_placement_findings(
            "credential_repo.rs",
            "use crate::tx_retry::{run_pg_localtx_retry as retry}; impl Repo { async fn apply_password_change(&self, mutation: PasswordChangeMutation){ let (_, _, observation) = mutation.into_parts(); retry(observation, || async { self.pool.retry_write() }, classify).await; } }",
            &mut sites,
        );
        assert!(findings.is_empty(), "{findings:?}");
        assert!(sites.contains("identity-password-change"));
    }

    #[test]
    fn retry_guard_accepts_command_carried_settings_secret_observation() {
        let mut sites = BTreeSet::new();
        let source = r#"
use crate::tx_retry::run_pg_localtx_retry as retry;
impl SecretUnitOfWork for PgSecretUnitOfWork {
    async fn publish(&self, command: SecretPublishCommand) {
        let (entry, observation) = command.into_parts();
        retry(
            observation,
            |_attempt| async { self.pool.retry_write() },
            classify,
        ).await;
    }
}
"#;
        let findings = retry_placement_findings("secret_repo.rs", source, &mut sites);
        assert!(findings.is_empty(), "{findings:?}");
        assert!(sites.contains("settings-secret-publish"));
    }

    #[test]
    fn retry_guard_rejects_wrong_wrapper_or_unbound_identity_evidence() {
        let mut sites = BTreeSet::new();
        for source in [
            "impl Repo { async fn bump_version(&self){ run_pg_tx_retry(IDENTITY_CREDENTIAL_BOUNDARY, || async { self.pool.retry_write() }, classify).await; } }",
            "impl Repo { async fn bump_version(&self){ run_pg_localtx_retry(IDENTITY_CREDENTIAL_BOUNDARY, observation, || async { self.pool.retry_write() }, classify).await; } }",
            "impl Uow { async fn commit(&self){ run_pg_localtx_retry(SETTINGS_CONFIG_BOUNDARY, observation, || async { self.pool.retry_co_tx_with_outbox() }, classify).await; } }",
            "impl Repo { async fn save(&self){ run_pg_tx_retry(SETTINGS_SECRET_BOUNDARY, || async { self.pool.retry_write() }, classify).await; } }",
            "impl Repo { async fn save(&self){ run_pg_localtx_retry(SETTINGS_SECRET_BOUNDARY, observation, || async { self.pool.retry_write() }, classify).await; } }",
            "impl Repo { async fn save(&self){ run_pg_localtx_retry(SETTINGS_SECRET_BOUNDARY, identity::password_change_localtx_observation().ok_or_else(missing)?, || async { self.pool.retry_write() }, classify).await; } }",
            "impl Repo { async fn save(&self){ let mut observation = settings::secret_publish_localtx_observation().ok_or_else(missing)?; observation = handmade(); run_pg_localtx_retry(SETTINGS_SECRET_BOUNDARY, observation, || async { self.pool.retry_write() }, classify).await; } }",
            "impl Repo { async fn save(&self){ run_pg_localtx_retry(SETTINGS_SECRET_BOUNDARY, settings::secret_publish_localtx_observation().ok_or_else(missing)?, || async { self.pool.write() }, classify).await; } }",
            "impl Repo { async fn save(&self){ run_pg_localtx_retry(SETTINGS_SECRET_BOUNDARY, settings::secret_publish_localtx_observation().ok_or_else(missing)?, || async { self.pool.write().await; self.pool.retry_write().await }, classify).await; } }",
        ] {
            let rel = if source.contains("SETTINGS_SECRET_BOUNDARY") {
                "secret_repo.rs"
            } else if source.contains("impl Repo") {
                "credential_repo.rs"
            } else {
                "config_repo.rs"
            };
            let findings = retry_placement_findings(rel, source, &mut sites);
            assert!(
                findings
                    .iter()
                    .any(|finding| finding.rule == Rule::RetryPlacement),
                "wrong wrapper/evidence must fail closed: {findings:?}"
            );
        }
    }

    #[test]
    fn retry_guard_rejects_secret_contract_attribution_bypasses() {
        for source in [
            r#"impl SecretRepo for PgSecretRepo { async fn save(&self) { run_pg_localtx_retry(SETTINGS_SECRET_BOUNDARY, observation, |_attempt| async { self.pool.retry_write() }, classify).await; } }"#,
            r#"impl SecretUnitOfWork for PgSecretUnitOfWork { async fn publish(&self, command: SecretPublishCommand) { let (_, observation) = command.into_parts(); run_pg_tx_retry(SETTINGS_SECRET_BOUNDARY, |_attempt| async { self.pool.retry_write() }, classify).await; } }"#,
            r#"impl SecretUnitOfWork for PgSecretUnitOfWork { async fn publish(&self, command: SecretPublishCommand) { let (_, command_observation) = command.into_parts(); let observation = handmade(); run_pg_localtx_retry(SETTINGS_SECRET_BOUNDARY, observation, |_attempt| async { self.pool.retry_write() }, classify).await; } }"#,
            r#"impl SecretUnitOfWork for PgSecretUnitOfWork { async fn publish(&self, command: SecretPublishCommand) { let (_, command_observation) = command.into_parts(); run_pg_localtx_retry(SETTINGS_SECRET_BOUNDARY, settings::secret_publish_localtx_observation().unwrap(), |_attempt| async { self.pool.retry_write() }, classify).await; } }"#,
            r#"impl SecretUnitOfWork for PgSecretUnitOfWork { async fn publish(&self, command: SecretPublishCommand) { let (_, observation) = command.into_parts(); run_pg_localtx_retry(SETTINGS_SECRET_BOUNDARY, observation, |_attempt| async { self.pool.write() }, classify).await; } }"#,
            r#"impl SecretUnitOfWork for PgSecretUnitOfWork { async fn publish_internal(&self) { run_pg_localtx_retry(SETTINGS_SECRET_BOUNDARY, observation, |_attempt| async { self.pool.retry_write() }, classify).await; } }"#,
            r#"impl SecretUnitOfWork for PgSecretUnitOfWork { async fn republish(&self) { run_pg_localtx_retry(SETTINGS_SECRET_BOUNDARY, observation, |_attempt| async { self.pool.retry_write() }, classify).await; } }"#,
        ] {
            let mut sites = BTreeSet::new();
            let findings = retry_placement_findings("secret_repo.rs", source, &mut sites);
            assert!(
                findings
                    .iter()
                    .any(|finding| finding.rule == Rule::RetryPlacement),
                "secret retry attribution bypass must fail closed: {findings:?}"
            );
        }
    }

    #[test]
    fn retry_guard_rejects_protected_module_alias_bypasses() {
        for (rel, source) in [
            (
                "role_repo.rs",
                "use consistency as c; async fn load(){ c::run_tx_retry(work).await; }",
            ),
            (
                "role_repo.rs",
                "use crate::tx_retry as retry; async fn load(){ retry::run_pg_tx_retry(boundary, operation, classify).await; }",
            ),
        ] {
            let mut sites = BTreeSet::new();
            let findings = retry_placement_findings(rel, source, &mut sites);
            assert!(
                findings
                    .iter()
                    .any(|finding| finding.rule == Rule::RetryPlacement),
                "protected retry module alias must not bypass owner checks: {findings:?}"
            );
        }
    }

    #[test]
    fn retry_guard_accepts_protected_module_aliases_in_exact_owners() {
        let mut sites = BTreeSet::new();
        let direct = retry_placement_findings(
            "tx_retry.rs",
            "use consistency as c; async fn run_pg_tx_retry_core(){ c::run_tx_retry(work).await; }",
            &mut sites,
        );
        let wrapper = retry_placement_findings(
            "config_repo.rs",
            "use crate::tx_retry as retry; impl Uow { async fn commit(&self){ retry::run_pg_tx_retry(SETTINGS_CONFIG_BOUNDARY, || async { self.pool.retry_co_tx_with_outbox() }, classify).await; } }",
            &mut sites,
        );
        assert!(direct.is_empty(), "{direct:?}");
        assert!(wrapper.is_empty(), "{wrapper:?}");
        assert!(sites.contains("settings-config-commit"));
    }

    #[test]
    fn secret_ref_mutation_guard_rejects_raw_and_destructive_bypasses() {
        for source in [
            r#"async fn save(conn: &mut PgConnection) { sqlx::query("INSERT INTO secret_refs (tenant_id) VALUES ($1)").execute(conn).await; }"#,
            r#"mod key_lock { impl LockedSecretKey<'_, '_> { async fn update(self) { sqlx::query("UPDATE secret_refs SET deleted = TRUE").execute(self.conn()).await; } } }"#,
            r#"mod key_lock { impl LockedSecretKey<'_, '_> { async fn delete(self) { sqlx::query("DELETE FROM secret_refs").execute(self.conn()).await; } } }"#,
            r#"mod key_lock { impl LockedSecretKey<'_, '_> { async fn truncate(self) { sqlx::query("TRUNCATE secret_refs").execute(self.conn()).await; } } }"#,
            r#"
mod key_lock {
    impl<'cap, 'tx> LockedSecretKey<'cap, 'tx> {
        pub(super) async fn acquire(
            tx: &'cap mut TxCapability<'tx>,
            tenant: TenantId,
            key: &SecretKey,
        ) -> Result<Self, SecretRepoError> {
            let tenant_uuid = tenant_param(tenant);
            let key = key.as_str().to_owned();
            sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1 || chr(31) || $2, 0))")
                .bind(&tenant_uuid)
                .bind(&key)
                .execute(tx.conn())
                .await
                .map_err(storage)?;
            Ok(Self { tx, tenant, tenant_uuid, key })
        }

        fn unchecked(tx: &'cap mut TxCapability<'tx>, tenant: TenantId, key: String) -> Self {
            Self { tx, tenant, tenant_uuid: tenant_param(tenant), key }
        }
    }
}
"#,
            r#"
mod key_lock {
    impl<'cap, 'tx> LockedSecretKey<'cap, 'tx> {
        pub(super) async fn acquire(
            tx: &'cap mut TxCapability<'tx>,
            tenant: TenantId,
            key: &SecretKey,
        ) -> Result<Self, SecretRepoError> {
            let tenant_uuid = tenant_param(tenant);
            let key = key.as_str().to_owned();
            if false {
                sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1 || chr(31) || $2, 0))")
                    .bind(&tenant_uuid)
                    .bind(&key)
                    .execute(tx.conn())
                    .await
                    .map_err(storage)?;
            }
            Ok(Self { tx, tenant, tenant_uuid, key })
        }
    }
}
"#,
        ] {
            let mut sites = BTreeMap::new();
            let findings = secret_ref_mutation_findings("secret_repo.rs", source, &mut sites);
            assert!(
                findings
                    .iter()
                    .any(|finding| finding.rule == Rule::SecretRefMutationBypass),
                "raw/destructive mutation must fail closed: {findings:?}"
            );
        }
    }

    #[test]
    fn secret_ref_mutation_guard_accepts_only_exact_locked_capability_sites() {
        let mut sites = BTreeMap::new();
        let findings = secret_ref_mutation_findings(
            "secret_repo.rs",
            secret_mutation_green_source(),
            &mut sites,
        );
        assert!(findings.is_empty(), "{findings:?}");
        assert_eq!(
            sites,
            BTreeMap::from([
                ("secret-key-advisory-lock", 1),
                ("secret-key-capability-mint", 1),
                ("secret-key-cas-insert", 1),
                ("secret-key-append-tombstone", 1),
                ("secret-key-lock-acquire", 1),
                ("secret-uow-cas-funnel", 1),
                ("secret-uow-delete-tombstone", 1),
                ("secret-uow-publish-cas", 1),
                ("secret-uow-publish-internal-cas", 1),
                ("secret-uow-republish-cas", 1),
            ])
        );
    }

    #[test]
    fn secret_ref_mutation_guard_accepts_stable_acquire_bindings() {
        let source = secret_mutation_green_source().replacen(
            "LockedSecretKey::acquire(tx, tenant, key).await.unwrap().cas_insert(&entry).await;",
            "let locked = LockedSecretKey::acquire(tx, tenant, key).await.unwrap(); locked.cas_insert(&entry).await;",
            1,
        );
        let mut sites = BTreeMap::new();
        let findings = secret_ref_mutation_findings("secret_repo.rs", &source, &mut sites);
        assert!(findings.is_empty(), "{findings:?}");
        assert_eq!(sites.get("secret-uow-cas-funnel"), Some(&1));
    }

    #[test]
    fn secret_ref_mutation_guard_rejects_receiver_provenance_bait() {
        for (original, replacement) in [
            (
                "LockedSecretKey::acquire(tx, tenant, key).await.unwrap().cas_insert(&entry).await;",
                "let _locked = LockedSecretKey::acquire(tx, tenant, key).await.unwrap(); decoy.cas_insert(&entry).await;",
            ),
            (
                "LockedSecretKey::acquire(tx, tenant, key).await.unwrap().cas_insert(&entry).await;",
                "let mut locked = LockedSecretKey::acquire(tx, tenant, key).await.unwrap(); locked = decoy; locked.cas_insert(&entry).await;",
            ),
            (
                "LockedSecretKey::acquire(tx, tenant, key).await.unwrap().cas_insert(&entry).await;",
                "let locked = if false { LockedSecretKey::acquire(tx, tenant, key).await.unwrap() } else { decoy }; locked.cas_insert(&entry).await;",
            ),
            (
                "LockedSecretKey::acquire(tx, tenant, key).await.unwrap().cas_insert(&entry).await;",
                "let locked = LockedSecretKey::acquire(tx, tenant, key).await.unwrap(); (|locked| async { locked.cas_insert(&entry).await })(decoy).await; drop(locked);",
            ),
            (
                "LockedSecretKey::acquire(tx, tenant, key).await.unwrap().append_tombstone().await;",
                "let _locked = LockedSecretKey::acquire(tx, tenant, key).await.unwrap(); decoy.append_tombstone().await;",
            ),
        ] {
            let broken = secret_mutation_green_source().replacen(original, replacement, 1);
            let mut sites = BTreeMap::new();
            let findings = secret_ref_mutation_findings("secret_repo.rs", &broken, &mut sites);
            assert!(
                findings
                    .iter()
                    .any(|finding| finding.rule == Rule::SecretRefMutationBypass),
                "only an unmodified LockedSecretKey::acquire receiver may consume cas_insert: {findings:?}"
            );
        }
    }

    #[test]
    fn secret_ref_mutation_guard_rejects_split_or_legacy_owners() {
        let mut broken = secret_mutation_green_source().to_string();
        broken = broken.replacen(
            "async fn publish_internal(&self) { Self::cas_insert_locked(tx, tenant, entry).await; }",
            "async fn publish_internal(&self) { raw_insert(entry).await; }",
            1,
        );
        let mut sites = BTreeMap::new();
        let findings = secret_ref_mutation_findings("secret_repo.rs", &broken, &mut sites);
        assert!(
            findings
                .iter()
                .any(|finding| finding.rule == Rule::SecretRefMutationBypass),
            "split CAS owner must fail closed: {findings:?}"
        );

        let mut sites = BTreeMap::new();
        let findings = secret_ref_mutation_findings(
            "secret_repo.rs",
            "impl SecretRepo for PgSecretRepo { async fn save(&self) {} async fn delete(&self) {} }",
            &mut sites,
        );
        assert!(
            findings
                .iter()
                .any(|finding| finding.rule == Rule::SecretRefMutationBypass),
            "legacy read-repo mutation methods must fail: {findings:?}"
        );
    }

    #[test]
    fn secret_repo_port_guard_rejects_write_methods() {
        let green = r#"
pub trait SecretRepoLocal: Send + Sync {
    async fn find(&self, scope: TenantRepoScope, key: &SecretKey) -> Result<Option<SecretEntry>, SecretRepoError>;
    async fn find_version(&self, scope: TenantRepoScope, key: &SecretKey, version: u64) -> Result<Option<SecretEntry>, SecretRepoError>;
    async fn latest_version(&self, scope: TenantRepoScope, key: &SecretKey) -> Result<Option<u64>, SecretRepoError>;
}
"#;
        assert!(secret_repo_read_only_findings("ports.rs", green).is_empty());
        let red = green.replacen("}", "async fn save(&self); async fn delete(&self); }", 1);
        let findings = secret_repo_read_only_findings("ports.rs", &red);
        assert!(
            findings
                .iter()
                .any(|finding| finding.rule == Rule::SecretRefMutationBypass),
            "SecretRepo write methods must fail closed: {findings:?}"
        );
    }

    #[test]
    fn secret_repo_guard_rejects_unknown_methods_and_contract_drift() {
        let canonical_methods = r#"
async fn find(&self, scope: TenantRepoScope, key: &SecretKey) -> Result<Option<SecretEntry>, SecretRepoError>;
async fn find_version(&self, scope: TenantRepoScope, key: &SecretKey, version: u64) -> Result<Option<SecretEntry>, SecretRepoError>;
async fn latest_version(&self, scope: TenantRepoScope, key: &SecretKey) -> Result<Option<u64>, SecretRepoError>;
"#;
        let trait_with_unknown = format!(
            "pub trait SecretRepoLocal: Send + Sync {{ {canonical_methods} async fn upsert(&self); }}"
        );
        let wrong_signature = r#"
pub trait SecretRepoLocal: Send + Sync {
    async fn find(&self) -> Result<Option<SecretEntry>, SecretRepoError>;
    async fn find_version(&self, scope: TenantRepoScope, key: &SecretKey, version: u64) -> Result<Option<SecretEntry>, SecretRepoError>;
    async fn latest_version(&self, scope: TenantRepoScope, key: &SecretKey) -> Result<Option<u64>, SecretRepoError>;
}
"#;
        for source in [&trait_with_unknown, wrong_signature] {
            let findings = secret_repo_read_only_findings("ports.rs", source);
            assert!(
                findings
                    .iter()
                    .any(|finding| finding.rule == Rule::SecretRefMutationBypass),
                "SecretRepoLocal must keep the exact read-only contract: {findings:?}"
            );
        }

        for source in [
            format!(
                "impl SecretRepo for PgSecretRepo {{ {} async fn upsert(&self) {{}} }}",
                canonical_methods.replace(';', " {}")
            ),
            format!(
                "impl ImpostorRepo for PgSecretRepo {{ {} }}",
                canonical_methods.replace(';', " {}")
            ),
        ] {
            let mut sites = BTreeMap::new();
            let findings = secret_ref_mutation_findings("secret_repo.rs", &source, &mut sites);
            assert!(
                findings
                    .iter()
                    .any(|finding| finding.rule == Rule::SecretRefMutationBypass),
                "PgSecretRepo must implement only the exact SecretRepo read surface: {findings:?}"
            );
        }
    }

    #[test]
    fn secret_ref_mutation_guard_allows_select_for_update() {
        let source = r#"async fn read(conn: &mut PgConnection) {
            sqlx::query("SELECT version FROM secret_refs WHERE tenant_id = $1 FOR UPDATE")
                .fetch_all(conn)
                .await;
        }"#;
        let mut sites = BTreeMap::new();
        let findings = secret_ref_mutation_findings("secret_repo.rs", source, &mut sites);
        assert!(findings.is_empty(), "{findings:?}");
        assert!(sites.is_empty());
    }

    #[test]
    fn retry_guard_rejects_block_tuple_and_dead_branch_argument_bait() {
        let mut sites = BTreeSet::new();
        for source in [
            "impl Repo { async fn bump_version(&self){ run_pg_localtx_retry({ let _ = IDENTITY_CREDENTIAL_BOUNDARY; WRONG_BOUNDARY }, identity::password_change_localtx_observation().ok_or_else(missing)?, |_attempt| async { self.pool.retry_write() }, classify).await; } }",
            "impl Repo { async fn bump_version(&self){ run_pg_localtx_retry(IDENTITY_CREDENTIAL_BOUNDARY, (identity::password_change_localtx_observation(), observation).1, |_attempt| async { self.pool.retry_write() }, classify).await; } }",
            "impl Repo { async fn bump_version(&self){ run_pg_localtx_retry(IDENTITY_CREDENTIAL_BOUNDARY, match identity::password_change_localtx_observation() { Some(observation) => fake_observation, None => return Err(missing) }, |_attempt| async { self.pool.retry_write() }, classify).await; } }",
            "impl Repo { async fn bump_version(&self){ run_pg_localtx_retry(IDENTITY_CREDENTIAL_BOUNDARY, identity::password_change_localtx_observation().ok_or_else(missing)?, |_attempt| async { if false { self.pool.retry_write() } else { raw_write() } }, classify).await; } }",
        ] {
            let findings = retry_placement_findings("credential_repo.rs", source, &mut sites);
            assert!(
                findings
                    .iter()
                    .any(|finding| finding.rule == Rule::RetryPlacement),
                "argument bait must not satisfy the canonical retry shape: {findings:?}"
            );
        }
    }

    #[test]
    fn retry_guard_rejects_removed_optional_observation_factories() {
        for (rel, source) in [
            (
                "credential_repo.rs",
                "impl Repo { async fn apply_password_change(&self, mutation: PasswordChangeMutation){ let (_, _, command_observation) = mutation.into_parts(); let observation = identity::password_change_localtx_observation().unwrap(); run_pg_localtx_retry(observation, || async { self.pool.retry_write() }, classify).await; } }",
            ),
            (
                "secret_repo.rs",
                "impl Uow { async fn publish(&self, command: SecretPublishCommand){ let (_, command_observation) = command.into_parts(); let observation = settings::secret_publish_localtx_observation().unwrap(); run_pg_localtx_retry(observation, || async { self.pool.retry_write() }, classify).await; } }",
            ),
        ] {
            let mut sites = BTreeSet::new();
            let findings = retry_placement_findings(rel, source, &mut sites);
            assert!(
                findings
                    .iter()
                    .any(|finding| finding.rule == Rule::RetryPlacement),
                "removed optional factory syntax must remain synthetic-red: {findings:?}"
            );
        }
    }

    #[test]
    fn retry_guard_accepts_all_exact_boundaries() {
        let mut sites = BTreeSet::new();
        let config = retry_placement_findings(
            "config_repo.rs",
            "impl Uow { async fn commit(&self){ run_pg_tx_retry(SETTINGS_CONFIG_BOUNDARY, || async { self.pool.retry_co_tx_with_outbox() }, classify).await; } }",
            &mut sites,
        );
        let identity = retry_placement_findings(
            "credential_repo.rs",
            "impl Repo { async fn apply_password_change(&self, mutation: PasswordChangeMutation){ let (_, _, observation) = mutation.into_parts(); run_pg_localtx_retry(observation, || async { self.pool.retry_write() }, classify).await; } }",
            &mut sites,
        );
        let logout = retry_placement_findings(
            "session_lifecycle.rs",
            "impl Repo { async fn logout(&self, mutation: SessionLogoutMutation){ let (_, observation) = mutation.into_parts(); run_pg_localtx_retry(observation, || async { self.pool.retry_write() }, classify).await; } }",
            &mut sites,
        );
        let refresh = retry_placement_findings(
            "refresh_token_store.rs",
            "impl Repo { async fn rotate(&self, mutation: RefreshRotationMutation){ let (_, observation) = mutation.into_parts(); run_pg_localtx_retry(observation, || async { self.pool.retry_write() }, classify).await; } }",
            &mut sites,
        );
        let audit = retry_placement_findings(
            "audit_repo.rs",
            "impl Repo { async fn append(&self){ run_pg_tx_retry(AUDIT_APPEND_BOUNDARY, || async { self.pool.retry_write() }, classify).await; } }",
            &mut sites,
        );
        let secret =
            retry_placement_findings("secret_repo.rs", secret_retry_green_source(), &mut sites);
        assert!(config.is_empty(), "{config:?}");
        assert!(identity.is_empty(), "{identity:?}");
        assert!(logout.is_empty(), "{logout:?}");
        assert!(refresh.is_empty(), "{refresh:?}");
        assert!(audit.is_empty(), "{audit:?}");
        assert!(secret.is_empty(), "{secret:?}");
        assert!(sites.contains("settings-config-commit"));
        assert!(sites.contains("settings-secret-publish"));
        assert!(sites.contains("settings-secret-publish-internal"));
        assert!(sites.contains("settings-secret-republish"));
        assert!(sites.contains("identity-password-change"));
        assert!(sites.contains("identity-session-logout"));
        assert!(sites.contains("identity-refresh-rotate"));
        assert!(sites.contains("audit-append"));
    }

    #[test]
    fn retry_guard_rejects_wrong_refresh_and_audit_boundaries() {
        for (rel, source) in [
            (
                "refresh_token_store.rs",
                "impl Repo { async fn rotate(&self, mutation: RefreshRotationMutation){ let (_, observation) = mutation.into_parts(); run_pg_tx_retry(IDENTITY_REFRESH_BOUNDARY, || async { self.pool.retry_write() }, classify).await; } }",
            ),
            (
                "audit_repo.rs",
                "impl Repo { async fn append(&self){ run_pg_tx_retry(SETTINGS_CONFIG_BOUNDARY, || async { self.pool.retry_write() }, classify).await; } }",
            ),
        ] {
            let mut sites = BTreeSet::new();
            let findings = retry_placement_findings(rel, source, &mut sites);
            assert!(
                findings
                    .iter()
                    .any(|finding| finding.rule == Rule::RetryPlacement),
                "wrong retry boundary must remain synthetic-red: {findings:?}"
            );
        }
    }

    #[test]
    fn retry_guard_real_workspace_contains_all_exact_boundaries() -> Result<()> {
        let root = crate::workspace_root()?;
        let files = load_prod_rs(&root.join("adapters/postgres/src"))?;
        let mut sites = BTreeSet::new();
        let mut findings = Vec::new();
        for (rel, source) in files.iter().filter(|(rel, _)| {
            matches!(
                rel.as_str(),
                "tx_retry.rs"
                    | "config_repo.rs"
                    | "secret_repo.rs"
                    | "credential_repo.rs"
                    | "session_lifecycle.rs"
                    | "refresh_token_store.rs"
                    | "audit_repo.rs"
            )
        }) {
            findings.extend(retry_placement_findings(rel, source, &mut sites));
        }
        assert!(findings.is_empty(), "{findings:?}");
        assert_eq!(
            sites,
            BTreeSet::from([
                "identity-password-change",
                "identity-refresh-rotate",
                "identity-session-logout",
                "audit-append",
                "settings-config-commit",
                "settings-secret-publish",
                "settings-secret-publish-internal",
                "settings-secret-republish",
            ])
        );
        Ok(())
    }

    #[test]
    fn secret_ref_mutation_guard_real_workspace_has_exact_capability_sites() -> Result<()> {
        let root = crate::workspace_root()?;
        let source = std::fs::read_to_string(root.join("adapters/postgres/src/secret_repo.rs"))?;
        let mut sites = BTreeMap::new();
        let findings = secret_ref_mutation_findings("secret_repo.rs", &source, &mut sites);
        assert!(findings.is_empty(), "{findings:?}");
        assert_eq!(
            sites,
            BTreeMap::from([
                ("secret-key-advisory-lock", 1),
                ("secret-key-capability-mint", 1),
                ("secret-key-cas-insert", 1),
                ("secret-key-append-tombstone", 1),
                ("secret-key-lock-acquire", 1),
                ("secret-uow-cas-funnel", 1),
                ("secret-uow-delete-tombstone", 1),
                ("secret-uow-publish-cas", 1),
                ("secret-uow-publish-internal-cas", 1),
                ("secret-uow-republish-cas", 1),
            ])
        );
        let ports = std::fs::read_to_string(root.join("crates/settings/src/ports.rs"))?;
        let port_findings = secret_repo_read_only_findings("crates/settings/src/ports.rs", &ports);
        assert!(port_findings.is_empty(), "{port_findings:?}");
        Ok(())
    }
}
