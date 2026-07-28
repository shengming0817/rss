//! `pg-tenant-tx-guard` —— Postgres tenant-table raw-pool / TxManager bypass guard.
//!
//! INVARIANT: TENANCY-PG-TX-FUNNEL-01 { level = "Medium", exec = "verify", source = "code", synthetic_red = "tests::red_core_file_exception_does_not_mask_raw_tenant_access", anti_vacuity = "tests::green_distinct_read_and_write_lanes_accept_their_owned_sql" } —
//! tenant-table production paths must go through
//! `PgTenantReadPool::{read,read_map}` for independent reads or `PgTenantWritePool` for mutation
//! transactions. Raw `sqlx::PgPool` / `PgStore` / direct connection / global transaction paths are
//! allowed only for explicitly named global infrastructure or maintenance exceptions.
//!
//! INVARIANT: TENANCY-PG-READ-LANE-01 { level = "Medium", exec = "verify", source = "code", synthetic_red = "tests::red_tenant_lane_crossovers_are_rejected", anti_vacuity = "tests::anti_vacuity_missing_typed_read_and_write_lane_sites_is_reported" } —
//! the removed mixed `PgTenantPool` must have zero production occurrences; read helpers exist only
//! on the typed reader lane, while write/deadline/retry/co-tx helpers exist only on the typed writer
//! lane. SELECT statements inside a writer transaction remain valid because the enclosing typed
//! write capability owns that transaction.
//!
//! This guard is a Medium backstop for the Hard typed wrapper in `adapters/postgres/src/cotx/`
//! and the canonical fact funnels in `outbox.rs` / `outbox_cdc.rs`.
//!
//! INVARIANT: LOCALTX-PG-RETRY-PLACEMENT-01 { level = "Medium", exec = "verify", source = "code", synthetic_red = "tests::retry_guard_rejects_secret_contract_attribution_bypasses|tests::localtx_deadline_guard_rejects_legacy_missing_forged_and_escaped_tokens|tests::localtx_deadline_observation_guard_rejects_rogue_and_fabricated_stages", anti_vacuity = "tests::retry_guard_real_workspace_contains_all_exact_boundaries|tests::localtx_deadline_guard_real_workspace_closes_mint_and_nine_dataflows|tests::localtx_deadline_observation_guard_real_workspace_closes_exact_sink" } —
//! Postgres retry wrappers are confined to their exact config, secret, identity, and audit
//! mutation boundaries. Each LocalTx owner must consume its command-carried
//! generated observation beside `retry_write`; `PgSecretUnitOfWork::publish` is the only settings
//! secret LocalTx owner;
//! internal publish / republish must use the generic runner and may not impersonate the HTTP
//! contract. Deadline observations are emitted only by the typed retry runner: attempt stages must
//! originate from `LocalTxRetryError::deadline_stages`, and backoff exhaustion from the canonical
//! runner callback.
//!
//! INVARIANT: PG-LOCALTX-QUARANTINE-FUNNEL-01 { level = "Medium", exec = "verify", source = "code", synthetic_red = "tests::localtx_quarantine_guard_rejects_bypass_and_escape_classes", anti_vacuity = "tests::localtx_quarantine_guard_real_workspace_closes_exact_sites" } —
//! all four LocalTx entries must flow through one typed execution core that acquires and begins
//! through the private armed lease, then tail-settles the exact branded transaction once. The core
//! carries one runner-minted deadline policy through every bounded stage; every non-retrying plain
//! transaction installs the same five-second PostgreSQL lock timeout without a caller-selectable
//! bypass. The wrapper borrow-binds that transaction
//! to its lease's closed quarantine stage; only a top-level consuming commit/rollback ACK may clear
//! it. The lease, wrapper, settlement dataflow, observability, and `close_on_drop` fallback are
//! closed against conditional, helper, raw, macro, and disarm escapes.
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
use syn::spanned::Spanned as _;

use crate::diagnostic::{self, GovernanceCheck, finding};
use crate::dlx_lifecycle_funnel::FIXED_FUNCTIONS as DLX_FIXED_FUNCTIONS;

pub(crate) type Finding = diagnostic::Finding<Rule>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Rule {
    RawTenantTableAccess,
    RawTenantPoolField,
    /// Removed mixed pool, typed lane crossover, or another read/write capability mismatch.
    TenantLaneViolation,
    /// Exact typed reader/writer production sites are missing (anti-vacuity).
    TenantLaneSitesAbsent,
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
    /// LocalTx pooled connection bypassed or weakened the armed quarantine lease.
    LocalTxQuarantineBypass,
    /// The exact LocalTx lease, unique core, or one of its four production entries disappeared.
    LocalTxQuarantineSitesAbsent,
    /// `secret_refs` mutation escaped the keyed `LockedSecretKey` capability.
    SecretRefMutationBypass,
    /// canonical `LockedSecretKey` mutation sites are absent or duplicated.
    SecretRefMutationSitesAbsent,
    /// DLX cross-tenant repository escaped its fixed SECURITY DEFINER function funnel.
    DlxLifecycleBypass,
    /// Exact DLX lifecycle repository/function sites are missing (anti-vacuity).
    DlxLifecycleSitesAbsent,
    /// An authorized generated-fact producer bypassed the single typed transaction funnel.
    ProducerFunnelBypass,
    /// An exact authorized generated-fact provider call site disappeared.
    ProducerFunnelSitesAbsent,
    /// The feature-gated fault harness attempted to author a production terminal state directly.
    FaultMatrixTerminalBypass,
}

pub(crate) struct PgTenantTxGuard;

const FAULT_MATRIX_FILE: &str = "fault_matrix.rs";
const MAX_FAULT_MATRIX_GUARD_SOURCE_BYTES: u64 = 512 * 1024;
const FAULT_MATRIX_LIB_GATE: &str = "#[cfg(feature = \"fault-matrix-test-support\")]";
const FAULT_MATRIX_OWNER_POOL: &str = "fault-matrix-owner-pool";
const FAULT_MATRIX_EXACT_OUTBOX_CLAIM: &str = "fault-matrix-exact-outbox-claim";
const FAULT_MATRIX_SEED_OUTBOX: &str = "fault-matrix-seed-outbox";
const FAULT_MATRIX_SEED_SESSION_CREATED: &str = "fault-matrix-seed-session-created";
const FAULT_MATRIX_SESSION_RETRY_DUE: &str = "fault-matrix-session-retry-due";
const FAULT_MATRIX_PUBLISH_BUDGET_RETRY_DUE: &str = "fault-matrix-publish-budget-retry-due";
const FAULT_MATRIX_OUTBOX_RETRY_OBSERVATION: &str = "fault-matrix-outbox-retry-observation";
const FAULT_MATRIX_RECONCILE_ALIAS_OBSERVATION: &str = "fault-matrix-reconcile-alias-observation";
const FAULT_MATRIX_SESSION_AUDIT_COUNT: &str = "fault-matrix-session-audit-count";
const FAULT_MATRIX_SESSION_INBOX_DONE_COUNT: &str = "fault-matrix-session-inbox-done-count";
const FAULT_MATRIX_EXPIRED_DEADLINE: &str = "fault-matrix-expired-deadline";
const FAULT_MATRIX_OUTBOX_STATUS_OBSERVATION: &str = "fault-matrix-outbox-status-observation";
const FAULT_MATRIX_TERMINAL_OBSERVATION: &str = "fault-matrix-terminal-observation";
const FAULT_MATRIX_OUTBOX_STATUS_COUNT: &str = "fault-matrix-outbox-status-count";
const FAULT_MATRIX_DEAD_LETTER_OBSERVATION: &str = "fault-matrix-dead-letter-observation";
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
        let workspace_files = load_workspace_prod_rs(&root)?;
        let settings_ports_path = root.join("crates/settings/src/ports.rs");
        let settings_ports = std::fs::read_to_string(&settings_ports_path)
            .with_context(|| format!("读 {} 失败", settings_ports_path.display()))?;
        let (summary, mut findings) = scan_guard(&migrations, &files);
        findings.extend(load_fault_matrix_governance_findings(
            &migrations,
            &root.join("adapters/postgres/src"),
        )?);
        findings.extend(producer_funnel_findings(&files));
        findings.extend(localtx_required_carriers_missing(&files));
        findings.extend(localtx_deadline_observation_findings(&workspace_files));
        let dlx_path = root.join("adapters/postgres/src/dlx_lifecycle.rs");
        let dlx_source = std::fs::read_to_string(&dlx_path)
            .with_context(|| format!("读 {} 失败", dlx_path.display()))?;
        findings.extend(dlx_lifecycle_funnel_findings(&dlx_source));
        findings.extend(secret_repo_read_only_findings(
            "crates/settings/src/ports.rs",
            &settings_ports,
        ));
        Ok((summary, findings))
    }
}

fn load_fault_matrix_governance_findings(
    migrations: &[(String, String)],
    src_dir: &Path,
) -> Result<Vec<Finding>> {
    let mut files = Vec::new();
    for rel in ["lib.rs", FAULT_MATRIX_FILE] {
        let path = src_dir.join(rel);
        let source = crate::generated_file::read_stable_utf8_file(
            &path,
            MAX_FAULT_MATRIX_GUARD_SOURCE_BYTES,
            "PostgreSQL fault-matrix governance source",
        )
        .with_context(|| format!("稳定读取 {} 失败", path.display()))?;
        files.push((rel.to_string(), source));
    }
    let mut findings = fault_matrix_exception_staleness(&files);
    findings.extend(fault_matrix_terminal_bypass_findings(&files));
    let tenant_tables = tenant_tables_from_migrations(migrations);
    if let Some((rel, source)) = files.iter().find(|(rel, _)| rel == FAULT_MATRIX_FILE) {
        let stripped = strip_rust_comment_lines(&strip_cfg_test_modules(source));
        let expanded = expand_simple_table_consts(&stripped).to_lowercase();
        let helper_tables = tenant_pgconnection_helpers(&expanded, &tenant_tables);
        let (raw_tenant_hits, _) =
            raw_tenant_accesses(rel, &expanded, &tenant_tables, &helper_tables);
        let (raw_outbox_hits, _, _) = raw_outbox_insert_sites(rel, &expanded);
        findings.extend(raw_tenant_hits.iter().map(|hit| {
            finding(
                Rule::RawTenantTableAccess,
                site_subject(rel, hit.line),
                format!(
                    "tenant tables {:?} touched through raw pattern {:?}; use PgTenantReadPool/PgTenantWritePool scoped methods",
                    hit.tables, hit.pattern
                ),
            )
        }));
        findings.extend(raw_outbox_hits.iter().map(|hit| {
            finding(
                Rule::RawOutboxInsert,
                site_subject(rel, hit.line),
                "outbox rows must be created through outbox.rs TxCapability append funnel",
            )
        }));
    }
    Ok(findings)
}

fn producer_funnel_findings(files: &[(String, String)]) -> Vec<Finding> {
    use syn::visit::Visit as _;

    const EXPECTED_PRODUCER_CALLS: &[(&str, &str, usize)] = &[
        ("auth_grant_lifecycle.rs", "producer_tx", 1),
        ("identity_security_lifecycle.rs", "producer_tx", 1),
        ("policy_repo.rs", "producer_tx", 3),
        ("role_binding_lifecycle.rs", "producer_tx", 2),
        ("config_repo.rs", "retry_producer_tx", 1),
    ];

    #[derive(Default)]
    struct CallScan {
        producer_tx: usize,
        retry_producer_tx: usize,
        forbidden: Vec<String>,
    }

    impl<'ast> syn::visit::Visit<'ast> for CallScan {
        fn visit_item_mod(&mut self, node: &'ast syn::ItemMod) {
            if !attributes_are_test_only(&node.attrs) {
                syn::visit::visit_item_mod(self, node);
            }
        }

        fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
            if !attributes_are_test_only(&node.attrs) {
                syn::visit::visit_item_fn(self, node);
            }
        }

        fn visit_item_impl(&mut self, node: &'ast syn::ItemImpl) {
            if !attributes_are_test_only(&node.attrs) {
                syn::visit::visit_item_impl(self, node);
            }
        }

        fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
            if !attributes_are_test_only(&node.attrs) {
                syn::visit::visit_impl_item_fn(self, node);
            }
        }

        fn visit_trait_item_fn(&mut self, node: &'ast syn::TraitItemFn) {
            if !attributes_are_test_only(&node.attrs) {
                syn::visit::visit_trait_item_fn(self, node);
            }
        }

        fn visit_stmt(&mut self, node: &'ast syn::Stmt) {
            if !localtx_test_only_statement(node) {
                syn::visit::visit_stmt(self, node);
            }
        }

        fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
            let method = node.method.to_string();
            match method.as_str() {
                "producer_tx" => self.producer_tx += 1,
                "retry_producer_tx" => self.retry_producer_tx += 1,
                "write" | "co_tx_with_outbox" | "retry_co_tx_with_outbox" | "publish" | "emit" => {
                    self.forbidden.push(method)
                }
                _ => {}
            }
            syn::visit::visit_expr_method_call(self, node);
        }

        fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
            if let syn::Expr::Path(path) = &*node.func
                && path
                    .path
                    .segments
                    .last()
                    .is_some_and(|segment| segment.ident == "append_outbox_with_projection")
            {
                self.forbidden
                    .push("append_outbox_with_projection".to_owned());
            }
            syn::visit::visit_expr_call(self, node);
        }
    }

    let mut findings = Vec::new();
    let expected = EXPECTED_PRODUCER_CALLS
        .iter()
        .map(|(path, method, count)| ((*path, *method), *count))
        .collect::<BTreeMap<_, _>>();
    let mut observed = BTreeMap::<(&str, &str), usize>::new();
    for (path, source) in files {
        let Ok(parsed) = syn::parse_file(source) else {
            findings.push(finding(
                Rule::ProducerFunnelBypass,
                path,
                "production provider cannot be parsed while closing producer callsites fail-closed",
            ));
            continue;
        };
        let mut scan = CallScan::default();
        scan.visit_file(&parsed);
        for (method, count) in [
            ("producer_tx", scan.producer_tx),
            ("retry_producer_tx", scan.retry_producer_tx),
        ] {
            if count != 0 {
                observed.insert((path.as_str(), method), count);
            }
        }
        if EXPECTED_PRODUCER_CALLS
            .iter()
            .any(|(expected_path, _, _)| expected_path == path)
        {
            for forbidden in scan.forbidden {
                findings.push(finding(
                    Rule::ProducerFunnelBypass,
                    path,
                    format!(
                        "authorized generated-fact producer provider calls forbidden `{forbidden}` path"
                    ),
                ));
            }
        }
    }

    for ((path, method), expected_count) in &expected {
        let observed_count = observed.get(&(*path, *method)).copied().unwrap_or_default();
        if observed_count != *expected_count {
            findings.push(finding(
                Rule::ProducerFunnelSitesAbsent,
                *path,
                format!(
                    "expected exact producer funnel call ({path}, {method}, {expected_count}); found count={observed_count}",
                ),
            ));
        }
    }
    for ((path, method), count) in &observed {
        if !expected.contains_key(&(*path, *method)) {
            findings.push(finding(
                Rule::ProducerFunnelBypass,
                *path,
                format!("unexpected production producer funnel call ({path}, {method}, {count})"),
            ));
        }
    }
    findings
}

fn dlx_lifecycle_funnel_findings(source: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let parsed = syn::parse_file(source).ok();
    if parsed.as_ref().is_none_or(|file| {
        !file.items.iter().any(
            |item| matches!(item, syn::Item::Struct(item) if item.ident == "PgDlxLifecycleRuntime"),
        )
    }) {
        findings.push(finding(
            Rule::DlxLifecycleSitesAbsent,
            "dlx_lifecycle.rs",
            "dedicated DLX lifecycle funnel missing struct `PgDlxLifecycleRuntime`".to_owned(),
        ));
    }
    for (method, required) in [
        ("archive_backlog", DLX_FIXED_FUNCTIONS[7]),
        ("claim_archive_candidates", DLX_FIXED_FUNCTIONS[0]),
        ("settle_archive_failure", DLX_FIXED_FUNCTIONS[1]),
        ("settle_archive_failure", DLX_FIXED_FUNCTIONS[2]),
        ("record_verified_receipt", DLX_FIXED_FUNCTIONS[3]),
        ("purge_verified", DLX_FIXED_FUNCTIONS[4]),
        ("claim_expired_receipts", DLX_FIXED_FUNCTIONS[5]),
        ("delete_expired_receipt", DLX_FIXED_FUNCTIONS[6]),
    ] {
        if parsed.as_ref().is_none_or(|file| {
            !repository_method_sql_literals(file, method)
                .iter()
                .any(|sql| sql_calls_function(sql, required))
        }) {
            findings.push(finding(
                Rule::DlxLifecycleSitesAbsent,
                "dlx_lifecycle.rs",
                format!("dedicated DLX lifecycle method `{method}` missing `{required}` SQL call"),
            ));
        }
    }
    for forbidden in [
        "DELETE FROM dead_letter",
        "INSERT INTO dead_letter_archive_receipts",
        "UPDATE dead_letter SET",
        "pub fn pool(",
        "pub pool:",
        "PgTenantPool",
        "run_global_transaction",
    ] {
        if source.contains(forbidden) {
            findings.push(finding(
                Rule::DlxLifecycleBypass,
                "dlx_lifecycle.rs",
                format!("DLX lifecycle repository bypasses fixed functions via `{forbidden}`"),
            ));
        }
    }
    findings
}

fn repository_method_sql_literals(file: &syn::File, method: &str) -> Vec<String> {
    use syn::visit::Visit as _;

    let Some(item) = file.items.iter().find_map(|item| match item {
        syn::Item::Impl(item)
            if item.trait_.as_ref().is_some_and(|(_, path, _)| {
                path.segments
                    .last()
                    .is_some_and(|segment| segment.ident == "DlxLifecycleRepository")
            }) =>
        {
            Some(item)
        }
        _ => None,
    }) else {
        return Vec::new();
    };
    let Some(method) = item.items.iter().find_map(|item| match item {
        syn::ImplItem::Fn(item) if item.sig.ident == method => Some(item),
        _ => None,
    }) else {
        return Vec::new();
    };
    #[derive(Default)]
    struct StringLiterals(Vec<String>);
    impl<'ast> syn::visit::Visit<'ast> for StringLiterals {
        fn visit_lit_str(&mut self, literal: &'ast syn::LitStr) {
            self.0.push(literal.value());
        }
    }
    let mut literals = StringLiterals::default();
    literals.visit_block(&method.block);
    literals.0
}

fn sql_calls_function(sql: &str, function: &str) -> bool {
    let compact = sql
        .chars()
        .filter(|character| !character.is_whitespace())
        .flat_map(char::to_lowercase)
        .collect::<String>();
    compact.contains(&format!("select{function}(")) || compact.contains(&format!("from{function}("))
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

fn load_workspace_prod_rs(root: &Path) -> Result<Vec<(String, String)>> {
    let manifest_path = root.join("Cargo.toml");
    let manifest_source = std::fs::read_to_string(&manifest_path)
        .with_context(|| format!("读 {} 失败", manifest_path.display()))?;
    let manifest: toml::Value = toml::from_str(&manifest_source)
        .with_context(|| format!("解析 {} 失败", manifest_path.display()))?;
    let members = manifest
        .get("workspace")
        .and_then(|workspace| workspace.get("members"))
        .and_then(toml::Value::as_array)
        .context("workspace.members missing from root Cargo.toml")?;

    let mut paths = Vec::new();
    for member in members {
        let member = member
            .as_str()
            .context("workspace member must be a string path")?;
        paths.extend(collect_rs_paths(&root.join(member).join("src"))?);
    }
    paths.sort();
    paths.dedup();

    let mut files = Vec::new();
    for path in paths {
        if is_test_file(&path) {
            continue;
        }
        let rel = path
            .strip_prefix(root)
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
    let writer_sql_helpers = workspace_writer_sql_helpers(files);
    findings.extend(fault_matrix_exception_staleness(files));
    findings.extend(fault_matrix_terminal_bypass_findings(files));
    findings.extend(localtx_quarantine_findings(files));

    for (rel, content) in files {
        findings.extend(scan_source_file(
            rel,
            content,
            &tenant_tables,
            writer_sql_helpers.get(rel),
            &mut state,
        ));
    }

    for (sites, required, detail) in [
        (
            state.tenant_read_lane_sites,
            "PgTenantReadPool::read",
            "typed reader lane has no production read/read_map site",
        ),
        (
            state.tenant_write_lane_sites,
            "PgTenantWritePool::write",
            "typed writer lane has no production write/deadline/retry/co-tx site",
        ),
    ] {
        if sites == 0 {
            findings.push(finding(
                Rule::TenantLaneSitesAbsent,
                required,
                format!("{detail}; required capability {required} disappeared"),
            ));
        }
    }

    for expected in ["config-value-maintenance"] {
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
        "{} tenant 表；{} 个生产文件；{} 个 tenant SQL 文件；{} reader lane sites；{} writer lane sites；{} 个 raw pattern",
        tenant_tables.len(),
        files.len(),
        state.tenant_sql_sites,
        state.tenant_read_lane_sites,
        state.tenant_write_lane_sites,
        state.raw_sites
    );
    (summary, findings)
}

fn localtx_quarantine_findings(files: &[(String, String)]) -> Vec<Finding> {
    let cotx = files
        .iter()
        .find(|(path, _)| matches!(path.as_str(), "cotx.rs" | "cotx/mod.rs"));
    let settlement = files.iter().find(|(path, _)| path == "cotx/settlement.rs");
    if cotx.is_none() && settlement.is_none() {
        return Vec::new();
    }

    let mut findings = Vec::new();
    match cotx {
        Some((path, source)) => {
            let stripped = strip_cfg_test_modules(source);
            match syn::parse_file(&stripped) {
                Ok(syntax) => {
                    findings.extend(localtx_transaction_core_findings(path, &syntax));
                }
                Err(error) => findings.push(finding(
                    Rule::LocalTxQuarantineBypass,
                    path,
                    format!("cannot parse LocalTx funnel source: {error}"),
                )),
            }
        }
        None => findings.push(finding(
            Rule::LocalTxQuarantineSitesAbsent,
            "cotx/mod.rs",
            "LocalTx production funnel module is missing",
        )),
    }

    match settlement {
        Some((path, source)) => {
            let stripped = strip_cfg_test_modules(source);
            match syn::parse_file(&stripped) {
                Ok(syntax) => findings.extend(localtx_lease_shape_findings(path, &syntax)),
                Err(error) => findings.push(finding(
                    Rule::LocalTxQuarantineBypass,
                    path,
                    format!("cannot parse LocalTx settlement source: {error}"),
                )),
            }
        }
        None => findings.push(finding(
            Rule::LocalTxQuarantineSitesAbsent,
            "cotx/settlement.rs",
            "LocalTx armed connection lease carrier is missing",
        )),
    }
    for (path, source) in files
        .iter()
        .filter(|(path, _)| path != "cotx/settlement.rs")
    {
        let Ok(syntax) = syn::parse_file(&strip_cfg_test_modules(source)) else {
            continue;
        };
        if contains_localtx_foreign_impl_or_macro(&syntax.items) {
            findings.push(finding(
                Rule::LocalTxQuarantineBypass,
                path,
                "LocalTx lease and branded transaction impls or opaque macros must remain confined to cotx/settlement.rs",
            ));
        }
    }
    findings.extend(localtx_unsafe_seam_call_findings(files));
    findings
}

fn simple_binding(pattern: &syn::Pat) -> Option<String> {
    match pattern {
        syn::Pat::Ident(ident) if ident.subpat.is_none() => Some(ident.ident.to_string()),
        syn::Pat::Type(typed) => simple_binding(&typed.pat),
        syn::Pat::Paren(paren) => simple_binding(&paren.pat),
        _ => None,
    }
}

fn local_initializer(local: &syn::Local) -> Option<&syn::Expr> {
    local.init.as_ref().map(|init| init.expr.as_ref())
}

fn localtx_transaction_core_findings(path: &str, syntax: &syn::File) -> Vec<Finding> {
    let mut findings = Vec::new();
    if !localtx_execution_policy_is_closed(syntax) {
        findings.push(finding(
            Rule::LocalTxQuarantineBypass,
            format!("{path}::LocalTxExecutionPolicy"),
            "LocalTxExecutionPolicy must use one fixed lock-bounded Plain variant or privately carry the single deadline token through closed acquire/begin/setup/operation/commit/rollback stage arms and setup GUCs",
        ));
    }
    if !localtx_ingress_graph_is_closed(syntax) {
        findings.push(finding(
            Rule::LocalTxQuarantineSitesAbsent,
            format!("{path}::execute_local_tx"),
            "all four plain/retry write/outbox entries must exist exactly once and tail-flow through the unique execute_local_tx core with their unchanged policy/deadline binding",
        ));
    }
    if !localtx_execute_core_is_closed(syntax) {
        findings.push(finding(
            Rule::LocalTxQuarantineBypass,
            format!("{path}::execute_local_tx"),
            "execute_local_tx must bind one policy through acquire→begin→setup→operation and tail-settle the same transaction/body/policy once, without shadow, reassignment, nested/dead-branch, timeout, or helper escape",
        ));
    }
    if !localtx_settlement_graph_is_closed(syntax) {
        findings.push(finding(
            Rule::LocalTxQuarantineBypass,
            format!("{path}::finish_local_tx"),
            "execute_local_tx must be the sole caller of one finish_local_tx settlement funnel, whose closed commit/rollback branches own all settlement helpers",
        ));
    }
    findings
}

fn free_functions<'a>(syntax: &'a syn::File, name: &str) -> Vec<&'a syn::ItemFn> {
    syntax
        .items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Fn(function) if function.sig.ident == name => Some(function),
            _ => None,
        })
        .collect()
}

fn localtx_execution_policy_is_closed(syntax: &syn::File) -> bool {
    let policies = syntax
        .items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Enum(item) if item.ident == "LocalTxExecutionPolicy" => Some(item),
            _ => None,
        })
        .collect::<Vec<_>>();
    let Some(policy) = policies.first().filter(|_| policies.len() == 1) else {
        return false;
    };
    if !matches!(policy.vis, syn::Visibility::Inherited)
        || policy.variants.len() != 2
        || !policy.variants.iter().any(canonical_plain_policy_variant)
        || !policy
            .variants
            .iter()
            .any(canonical_deadline_policy_variant)
    {
        return false;
    }
    let methods = syntax
        .items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Impl(item)
                if type_last_ident(&item.self_ty).as_deref() == Some("LocalTxExecutionPolicy") =>
            {
                Some(item)
            }
            _ => None,
        })
        .flat_map(|item| item.items.iter())
        .filter_map(|item| match item {
            syn::ImplItem::Fn(method) => Some(method),
            _ => None,
        })
        .collect::<Vec<_>>();
    [
        "acquire",
        "begin",
        "setup",
        "operation",
        "commit",
        "rollback",
    ]
    .into_iter()
    .all(|stage| {
        let matching = methods
            .iter()
            .filter(|method| method.sig.ident == stage)
            .copied()
            .collect::<Vec<_>>();
        matching.len() == 1 && canonical_policy_stage_arm(matching[0], stage)
    }) && methods
        .iter()
        .find(|method| method.sig.ident == "setup")
        .is_some_and(|method| canonical_policy_timeout_setup(method))
        && canonical_plain_lock_timeout_helper(syntax)
}

fn canonical_plain_policy_variant(variant: &syn::Variant) -> bool {
    variant.ident == "Plain" && matches!(variant.fields, syn::Fields::Unit)
}

fn canonical_deadline_policy_variant(variant: &syn::Variant) -> bool {
    variant.ident == "Deadline"
        && matches!(&variant.fields, syn::Fields::Unnamed(fields)
        if fields.unnamed.len() == 1
            && fields.unnamed.first().is_some_and(|field| {
                type_last_ident(&field.ty).as_deref() == Some("LocalTxDeadline")
            }))
}

fn canonical_policy_stage_arm(method: &syn::ImplItemFn, stage: &str) -> bool {
    let Some(syn::Stmt::Expr(expression, None)) = method.block.stmts.last() else {
        return false;
    };
    let syn::Expr::Match(stage_match) = transparent_expr(expression) else {
        return false;
    };
    if exact_expr_path(&stage_match.expr).as_deref() != Some("self") {
        return false;
    }
    let deadline_arms = stage_match
        .arms
        .iter()
        .filter_map(|arm| deadline_arm_binding(&arm.pat).map(|binding| (arm, binding)))
        .collect::<Vec<_>>();
    let Some((arm, deadline)) = deadline_arms.first().filter(|_| deadline_arms.len() == 1) else {
        return false;
    };
    let Some(call) = awaited_method_tail(&arm.body) else {
        return false;
    };
    call.method == stage
        && call.args.len() == 1
        && exact_expr_path(&call.receiver).as_deref() == Some(deadline)
        && !expression_shadows_or_assigns(&arm.body, deadline)
}

fn deadline_arm_binding(pattern: &syn::Pat) -> Option<String> {
    let syn::Pat::TupleStruct(pattern) = pattern else {
        return None;
    };
    if compact_tokens(&pattern.path) != "Self::Deadline" || pattern.elems.len() != 1 {
        return None;
    }
    simple_binding(pattern.elems.first()?)
}

fn awaited_method_tail(expression: &syn::Expr) -> Option<&syn::ExprMethodCall> {
    match transparent_expr(expression) {
        syn::Expr::Block(block) => block_tail(&block.block).and_then(awaited_method_tail),
        syn::Expr::Await(awaited) => match transparent_expr(&awaited.base) {
            syn::Expr::MethodCall(call) => Some(call),
            _ => None,
        },
        _ => None,
    }
}

fn expression_shadows_or_assigns(expression: &syn::Expr, binding: &str) -> bool {
    let statement = syn::Stmt::Expr(expression.clone(), None);
    statements_shadow_or_assign(std::slice::from_ref(&statement), binding)
}

fn canonical_policy_timeout_setup(method: &syn::ImplItemFn) -> bool {
    struct SetupScan {
        plain_calls: usize,
        deadline_calls: usize,
    }
    impl<'ast> syn::visit::Visit<'ast> for SetupScan {
        fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
            match exact_expr_path(&node.func).as_deref() {
                Some("set_local_plain_lock_timeout")
                    if node.args.len() == 1
                        && node
                            .args
                            .first()
                            .is_some_and(|arg| compact_tokens(arg) == "tx.conn()") =>
                {
                    self.plain_calls += 1;
                }
                Some("set_local_retry_deadlines")
                    if node.args.len() == 2
                        && node.args.get(1).and_then(exact_expr_path).as_deref()
                            == Some("deadline") =>
                {
                    self.deadline_calls += 1;
                }
                _ => {}
            }
            syn::visit::visit_expr_call(self, node);
        }
    }
    let mut scan = SetupScan {
        plain_calls: 0,
        deadline_calls: 0,
    };
    syn::visit::Visit::visit_block(&mut scan, &method.block);
    scan.plain_calls == 1 && scan.deadline_calls == 1
}

fn canonical_plain_lock_timeout_helper(syntax: &syn::File) -> bool {
    let helpers = free_functions(syntax, "set_local_plain_lock_timeout");
    let Some(helper) = helpers.first().filter(|_| helpers.len() == 1) else {
        return false;
    };
    let Some(syn::Expr::MethodCall(map)) = block_tail(&helper.block).map(transparent_expr) else {
        return false;
    };
    if map.method != "map" || map.args.len() != 1 {
        return false;
    }
    let syn::Expr::Await(awaited) = transparent_expr(&map.receiver) else {
        return false;
    };
    let syn::Expr::MethodCall(execute) = transparent_expr(&awaited.base) else {
        return false;
    };
    if execute.method != "execute"
        || execute.args.len() != 1
        || execute
            .args
            .first()
            .is_none_or(|argument| compact_tokens(argument) != "conn")
    {
        return false;
    }
    let syn::Expr::Call(query) = transparent_expr(&execute.receiver) else {
        return false;
    };
    exact_expr_path(&query.func).as_deref() == Some("sqlx::query")
        && query.args.len() == 1
        && matches!(query.args.first().map(transparent_expr), Some(syn::Expr::Lit(literal))
            if matches!(&literal.lit, syn::Lit::Str(sql)
                if sql.value() == "SELECT set_config('lock_timeout', '5s', true)"))
}

fn localtx_ingress_graph_is_closed(syntax: &syn::File) -> bool {
    let entries = [
        ("tenant_scoped_write_inner", "execute_local_tx", false, 2),
        (
            "tenant_scoped_retry_write_inner",
            "execute_local_tx",
            true,
            2,
        ),
    ];
    let plain_entries_closed = entries
        .into_iter()
        .all(|(name, target, deadline, policy_index)| {
            let functions = free_functions(syntax, name);
            functions.len() == 1
                && canonical_localtx_entry(functions[0], target, deadline, policy_index)
        });
    let producer_entries = free_functions(syntax, "producer_tx_inner");
    let producer_entry_closed = producer_entries.len() == 1
        && canonical_policy_forward_entry(producer_entries[0], "execute_producer_local_tx", 3);
    let bridges = free_functions(syntax, "execute_producer_local_tx");
    let bridge_closed = bridges.len() == 1 && canonical_outbox_bridge(bridges[0]);
    let owners = execute_core_call_owners(syntax);
    let owners_closed = owners
        == BTreeSet::from([
            "execute_producer_local_tx".to_owned(),
            "tenant_scoped_retry_write_inner".to_owned(),
            "tenant_scoped_write_inner".to_owned(),
        ]);
    let removed_compat_api_absent = !syntax.items.iter().any(|item| {
        matches!(item, syn::Item::Impl(item_impl)
            if item_impl.items.iter().any(|item| matches!(item,
                syn::ImplItem::Fn(method) if method.sig.ident == "lock_bounded_write")))
    });
    plain_entries_closed
        && producer_entry_closed
        && bridge_closed
        && owners_closed
        && removed_compat_api_absent
}

fn canonical_policy_forward_entry(
    function: &syn::ItemFn,
    target: &str,
    policy_index: usize,
) -> bool {
    let Some(call) = awaited_call_tail(&function.block) else {
        return false;
    };
    let Some(policy) = signature_binding_of_type(&function.sig, "LocalTxExecutionPolicy") else {
        return false;
    };
    exact_expr_path(&call.func).as_deref() == Some(target)
        && call
            .args
            .get(policy_index)
            .and_then(exact_expr_path)
            .as_deref()
            == Some(&policy)
        && !statements_shadow_or_assign(&function.block.stmts, &policy)
}

fn canonical_localtx_entry(
    function: &syn::ItemFn,
    target: &str,
    deadline: bool,
    policy_index: usize,
) -> bool {
    let Some(call) = awaited_call_tail(&function.block) else {
        return false;
    };
    if exact_expr_path(&call.func).as_deref() != Some(target) {
        return false;
    }
    let deadline_binding = signature_binding_of_type(&function.sig, "LocalTxDeadline");
    if deadline != deadline_binding.is_some() {
        return false;
    }
    call.args.get(policy_index).is_some_and(|policy| {
        if let Some(deadline) = deadline_binding.as_deref() {
            deadline_policy_expr(policy, deadline)
        } else {
            plain_policy_expr(policy)
        }
    })
}

fn canonical_outbox_bridge(function: &syn::ItemFn) -> bool {
    if function.block.stmts.len() != 2 {
        return false;
    }
    let syn::Stmt::Local(attempt) = &function.block.stmts[0] else {
        return false;
    };
    if simple_binding(&attempt.pat).as_deref() != Some("attempt") {
        return false;
    }
    let Some(initializer) = local_initializer(attempt) else {
        return false;
    };
    let syn::Expr::Await(awaited) = transparent_expr(initializer) else {
        return false;
    };
    let syn::Expr::Call(call) = transparent_expr(&awaited.base) else {
        return false;
    };
    let Some(policy) = signature_binding_of_type(&function.sig, "LocalTxExecutionPolicy") else {
        return false;
    };
    let tail_maps_attempt = matches!(block_tail(&function.block).map(transparent_expr), Some(syn::Expr::MethodCall(mapper))
        if mapper.method == "map_error"
            && exact_expr_path(&mapper.receiver).as_deref() == Some("attempt")
            && mapper.args.len() == 1);
    exact_expr_path(&call.func).as_deref() == Some("execute_local_tx")
        && call.args.get(2).and_then(exact_expr_path).as_deref() == Some(&policy)
        && call.args.get(3).is_some_and(canonical_outbox_operation)
        && !statements_shadow_or_assign(&function.block.stmts, &policy)
        && tail_maps_attempt
}

fn canonical_outbox_operation(expression: &syn::Expr) -> bool {
    let syn::Expr::Struct(operation) = transparent_expr(expression) else {
        return false;
    };
    if compact_tokens(&operation.path) != "ProducerLocalTxOperation"
        || operation.rest.is_some()
        || operation.fields.len() != 3
    {
        return false;
    }
    operation.fields.iter().all(|field| {
        let syn::Member::Named(member) = &field.member else {
            return false;
        };
        match member.to_string().as_str() {
            "projection_registry" => compact_tokens(&field.expr) == "projection_registry",
            "business_write" => compact_tokens(&field.expr) == "business_write",
            "write" => matches!(transparent_expr(&field.expr), syn::Expr::Struct(write)
                if compact_tokens(&write.path) == "ProducerTxWrite"
                    && write.rest.is_none()
                    && write.fields.len() == 3),
            _ => false,
        }
    })
}

fn signature_binding_of_type(signature: &syn::Signature, expected: &str) -> Option<String> {
    let matches = signature
        .inputs
        .iter()
        .filter_map(|argument| match argument {
            syn::FnArg::Typed(argument)
                if type_last_ident(&argument.ty).as_deref() == Some(expected) =>
            {
                simple_binding(&argument.pat)
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    matches.first().filter(|_| matches.len() == 1).cloned()
}

fn deadline_policy_expr(expression: &syn::Expr, deadline: &str) -> bool {
    let syn::Expr::Call(call) = transparent_expr(expression) else {
        return false;
    };
    exact_expr_path(&call.func).as_deref() == Some("LocalTxExecutionPolicy::Deadline")
        && call.args.len() == 1
        && call.args.first().and_then(exact_expr_path).as_deref() == Some(deadline)
}

fn plain_policy_expr(expression: &syn::Expr) -> bool {
    exact_expr_path(expression).as_deref() == Some("LocalTxExecutionPolicy::Plain")
}

fn awaited_call_tail(block: &syn::Block) -> Option<&syn::ExprCall> {
    let expression = block_tail(block)?;
    let syn::Expr::Await(awaited) = transparent_expr(expression) else {
        return None;
    };
    let syn::Expr::Call(call) = transparent_expr(&awaited.base) else {
        return None;
    };
    Some(call)
}

fn execute_core_call_owners(syntax: &syn::File) -> BTreeSet<String> {
    syntax
        .items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Fn(function) if function_call_count(function, "execute_local_tx") == 1 => {
                Some(function.sig.ident.to_string())
            }
            _ => None,
        })
        .collect()
}

struct CoreStageScan {
    policy: String,
    statement: usize,
    branch_depth: usize,
    closure_depth: usize,
    stages: Vec<(String, usize, usize, usize, Vec<String>)>,
    finishes: Vec<(usize, usize, usize, Vec<String>)>,
    outer_timeout: bool,
}

impl<'ast> syn::visit::Visit<'ast> for CoreStageScan {
    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        if exact_expr_path(&node.receiver).as_deref() == Some(&self.policy)
            && matches!(
                node.method.to_string().as_str(),
                "acquire" | "begin" | "setup" | "operation"
            )
        {
            self.stages.push((
                node.method.to_string(),
                self.statement,
                self.branch_depth,
                self.closure_depth,
                node.args.iter().map(compact_tokens).collect(),
            ));
        }
        syn::visit::visit_expr_method_call(self, node);
    }

    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        match exact_expr_path(&node.func).as_deref() {
            Some("finish_local_tx") => self.finishes.push((
                self.statement,
                self.branch_depth,
                self.closure_depth,
                node.args.iter().map(compact_tokens).collect(),
            )),
            Some("tokio::time::timeout" | "tokio::time::timeout_at") => {
                self.outer_timeout = true;
            }
            _ => {}
        }
        syn::visit::visit_expr_call(self, node);
    }

    fn visit_expr_closure(&mut self, node: &'ast syn::ExprClosure) {
        self.closure_depth += 1;
        syn::visit::visit_expr_closure(self, node);
        self.closure_depth -= 1;
    }

    fn visit_expr_match(&mut self, node: &'ast syn::ExprMatch) {
        syn::visit::Visit::visit_expr(self, &node.expr);
        self.branch_depth += 1;
        for arm in &node.arms {
            syn::visit::Visit::visit_pat(self, &arm.pat);
            if let Some((_, guard)) = &arm.guard {
                syn::visit::Visit::visit_expr(self, guard);
            }
            syn::visit::Visit::visit_expr(self, &arm.body);
        }
        self.branch_depth -= 1;
    }

    fn visit_expr_if(&mut self, node: &'ast syn::ExprIf) {
        syn::visit::Visit::visit_expr(self, &node.cond);
        self.branch_depth += 1;
        syn::visit::Visit::visit_block(self, &node.then_branch);
        if let Some((_, branch)) = &node.else_branch {
            syn::visit::Visit::visit_expr(self, branch);
        }
        self.branch_depth -= 1;
    }
}

fn localtx_execute_core_is_closed(syntax: &syn::File) -> bool {
    let cores = free_functions(syntax, "execute_local_tx");
    let Some(core) = cores.first().filter(|_| cores.len() == 1) else {
        return false;
    };
    let Some(policy) = signature_binding_of_type(&core.sig, "LocalTxExecutionPolicy") else {
        return false;
    };
    let Some((lease, tx, setup_result, body_result)) = core_top_level_bindings(&core.block) else {
        return false;
    };
    if statements_shadow_or_assign(&core.block.stmts, &policy) {
        return false;
    }
    let mut scan = CoreStageScan {
        policy: policy.clone(),
        statement: 0,
        branch_depth: 0,
        closure_depth: 0,
        stages: Vec::new(),
        finishes: Vec::new(),
        outer_timeout: false,
    };
    for (index, statement) in core.block.stmts.iter().enumerate() {
        scan.statement = index;
        syn::visit::Visit::visit_stmt(&mut scan, statement);
    }
    let stages_closed = canonical_core_stages(&scan, &lease);
    let finish_closed = canonical_core_finish(&scan, &tx, &body_result, &policy);
    stages_closed
        && finish_closed
        && !scan.outer_timeout
        && top_level_binding_is_unique(&core.block, &lease)
        && top_level_binding_is_unique(&core.block, &tx)
        && top_level_binding_is_unique(&core.block, &setup_result)
        && top_level_binding_is_unique(&core.block, &body_result)
        && !statements_shadow_or_assign(&core.block.stmts[1..], &lease)
        && !statements_shadow_or_assign(&core.block.stmts[2..], &tx)
}

fn core_top_level_bindings(block: &syn::Block) -> Option<(String, String, String, String)> {
    if block.stmts.len() != 5 {
        return None;
    }
    let bindings = block
        .stmts
        .iter()
        .take(4)
        .filter_map(|statement| match statement {
            syn::Stmt::Local(local) => simple_binding(&local.pat),
            _ => None,
        })
        .collect::<Vec<_>>();
    (bindings.len() == 4).then(|| {
        (
            bindings[0].clone(),
            bindings[1].clone(),
            bindings[2].clone(),
            bindings[3].clone(),
        )
    })
}

fn canonical_core_stages(scan: &CoreStageScan, lease: &str) -> bool {
    let expected = [
        ("acquire", 0, 0, vec!["pool".to_owned()]),
        ("begin", 1, 0, vec![format!("&mut{lease}")]),
        (
            "setup",
            2,
            0,
            vec!["&muttx_cap".to_owned(), "tenant".to_owned()],
        ),
        (
            "operation",
            3,
            1,
            vec!["write.execute(&muttx_cap)".to_owned()],
        ),
    ];
    scan.stages.len() == expected.len()
        && scan.stages.iter().zip(expected).all(
            |((stage, statement, branch, closure, arguments), expected)| {
                stage == expected.0
                    && *statement == expected.1
                    && *branch == expected.2
                    && *closure == 0
                    && *arguments == expected.3
            },
        )
}

fn canonical_core_finish(
    scan: &CoreStageScan,
    transaction: &str,
    body_result: &str,
    policy: &str,
) -> bool {
    scan.finishes.len() == 1
        && scan
            .finishes
            .first()
            .is_some_and(|(statement, branch, closure, arguments)| {
                *statement == 4
                    && *branch == 0
                    && *closure == 0
                    && arguments.first().is_some_and(|arg| arg == transaction)
                    && arguments.get(1).is_some_and(|arg| arg == body_result)
                    && arguments.last().is_some_and(|arg| arg == policy)
            })
}

fn top_level_binding_is_unique(block: &syn::Block, binding: &str) -> bool {
    block
        .stmts
        .iter()
        .filter_map(|statement| match statement {
            syn::Stmt::Local(local) => simple_binding(&local.pat),
            _ => None,
        })
        .filter(|candidate| candidate == binding)
        .count()
        == 1
}

fn localtx_settlement_graph_is_closed(syntax: &syn::File) -> bool {
    let settlements = free_functions(syntax, "finish_local_tx");
    let Some(settlement) = settlements.first().filter(|_| settlements.len() == 1) else {
        return false;
    };
    function_call_count(settlement, "commit_local_tx") == 1
        && function_call_count(settlement, "rollback_local_tx") == 3
        && call_owners(syntax, "finish_local_tx") == BTreeSet::from(["execute_local_tx".to_owned()])
        && call_owners(syntax, "commit_local_tx") == BTreeSet::from(["finish_local_tx".to_owned()])
        && call_owners(syntax, "rollback_local_tx")
            == BTreeSet::from(["finish_local_tx".to_owned()])
}

fn function_call_count(function: &syn::ItemFn, target: &str) -> usize {
    struct FunctionCallScan<'a> {
        target: &'a str,
        calls: usize,
    }
    impl<'ast> syn::visit::Visit<'ast> for FunctionCallScan<'_> {
        fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
            if exact_expr_path(&node.func).as_deref() == Some(self.target) {
                self.calls += 1;
            }
            syn::visit::visit_expr_call(self, node);
        }
    }
    let mut scan = FunctionCallScan { target, calls: 0 };
    syn::visit::Visit::visit_block(&mut scan, &function.block);
    scan.calls
}

fn call_owners(syntax: &syn::File, target: &str) -> BTreeSet<String> {
    syntax
        .items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Fn(function) if function_call_count(function, target) > 0 => {
                Some(function.sig.ident.to_string())
            }
            _ => None,
        })
        .collect()
}

fn localtx_unsafe_seam_call_findings(files: &[(String, String)]) -> Vec<Finding> {
    let Some((funnel_path, _)) = files
        .iter()
        .find(|(path, _)| matches!(path.as_str(), "cotx.rs" | "cotx/mod.rs"))
    else {
        return Vec::new();
    };
    let mut calls = Vec::new();
    for (path, source) in files.iter().filter(|(path, _)| {
        matches!(path.as_str(), "cotx.rs" | "cotx/mod.rs") || path.starts_with("cotx/")
    }) {
        let stripped = strip_cfg_test_modules(source);
        let Ok(syntax) = syn::parse_file(&stripped) else {
            return vec![finding(
                Rule::LocalTxQuarantineBypass,
                path,
                "cannot parse production cotx source while counting unsafe settlement seam calls",
            )];
        };
        let mut visitor = LocalTxUnsafeSeamCallVisitor::new(path);
        syn::visit::Visit::visit_file(&mut visitor, &syntax);
        calls.extend(visitor.calls);
    }
    calls.sort();
    let mut expected = vec![
        (
            "commit_unknown_after_ack".to_owned(),
            format!("{funnel_path}::commit_local_tx"),
        ),
        (
            "rollback_failed_after_ack".to_owned(),
            format!("{funnel_path}::run_local_tx_rollback"),
        ),
        (
            "rollback_paused_before_ack".to_owned(),
            format!("{funnel_path}::run_local_tx_rollback"),
        ),
    ];
    expected.sort();
    if calls == expected {
        Vec::new()
    } else {
        vec![finding(
            Rule::LocalTxQuarantineBypass,
            format!("{funnel_path}::finish_local_tx"),
            format!(
                "unsafe LocalTx seams must each have one production call in the closed commit/rollback branches beneath finish_local_tx; found {calls:?}"
            ),
        )]
    }
}

struct LocalTxUnsafeSeamCallVisitor {
    path: String,
    owners: Vec<String>,
    calls: Vec<(String, String)>,
}

impl LocalTxUnsafeSeamCallVisitor {
    fn new(path: &str) -> Self {
        Self {
            path: path.to_owned(),
            owners: Vec::new(),
            calls: Vec::new(),
        }
    }

    fn record(&mut self, name: &str) {
        let owner = self.owners.last().map_or_else(
            || format!("{}::<module>", self.path),
            |owner| format!("{}::{owner}", self.path),
        );
        self.calls.push((name.to_owned(), owner));
    }

    fn is_unsafe_seam(name: &str) -> bool {
        matches!(
            name,
            "commit_unknown_after_ack" | "rollback_failed_after_ack" | "rollback_paused_before_ack"
        )
    }
}

impl<'ast> syn::visit::Visit<'ast> for LocalTxUnsafeSeamCallVisitor {
    fn visit_item_fn(&mut self, function: &'ast syn::ItemFn) {
        self.owners.push(function.sig.ident.to_string());
        syn::visit::visit_item_fn(self, function);
        self.owners.pop();
    }

    fn visit_impl_item_fn(&mut self, function: &'ast syn::ImplItemFn) {
        self.owners.push(function.sig.ident.to_string());
        syn::visit::visit_impl_item_fn(self, function);
        self.owners.pop();
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        let name = call.method.to_string();
        if Self::is_unsafe_seam(&name) {
            self.record(&name);
        }
        syn::visit::visit_expr_method_call(self, call);
    }

    fn visit_expr_path(&mut self, path: &'ast syn::ExprPath) {
        if let Some(segment) = path.path.segments.last() {
            let name = segment.ident.to_string();
            if Self::is_unsafe_seam(&name) {
                self.record(&name);
            }
        }
        syn::visit::visit_expr_path(self, path);
    }

    fn visit_item_use(&mut self, item_use: &'ast syn::ItemUse) {
        let tokens = compact_tokens(item_use);
        for name in [
            "commit_unknown_after_ack",
            "rollback_failed_after_ack",
            "rollback_paused_before_ack",
        ] {
            if tokens.contains(name) {
                self.record(name);
            }
        }
        syn::visit::visit_item_use(self, item_use);
    }

    fn visit_macro(&mut self, invocation: &'ast syn::Macro) {
        let tokens = compact_tokens(&invocation.tokens);
        for name in [
            "commit_unknown_after_ack",
            "rollback_failed_after_ack",
            "rollback_paused_before_ack",
        ] {
            if tokens.contains(name) {
                self.record(name);
            }
        }
        syn::visit::visit_macro(self, invocation);
    }
}

fn contains_localtx_foreign_impl_or_macro(items: &[syn::Item]) -> bool {
    items.iter().any(|item| match item {
        syn::Item::Impl(item_impl) => matches!(
            type_last_ident(&item_impl.self_ty).as_deref(),
            Some("LocalTxConnectionLease" | "LocalTxTransaction" | "LocalTxQuarantineStage")
        ),
        syn::Item::Mod(module) => module
            .content
            .as_ref()
            .is_some_and(|(_, items)| contains_localtx_foreign_impl_or_macro(items)),
        syn::Item::Macro(item_macro) => {
            let tokens = compact_tokens(item_macro);
            tokens.contains("LocalTxConnectionLease")
                || tokens.contains("LocalTxTransaction")
                || tokens.contains("LocalTxQuarantineStage")
                || tokens.contains("quarantine_stage")
        }
        _ => false,
    })
}

fn localtx_required_carriers_missing(files: &[(String, String)]) -> Vec<Finding> {
    let has_cotx = files
        .iter()
        .any(|(path, _)| matches!(path.as_str(), "cotx.rs" | "cotx/mod.rs"));
    let has_settlement = files.iter().any(|(path, _)| path == "cotx/settlement.rs");
    if has_cotx || has_settlement {
        Vec::new()
    } else {
        vec![finding(
            Rule::LocalTxQuarantineSitesAbsent,
            "cotx/mod.rs + cotx/settlement.rs",
            "both LocalTx quarantine carriers are missing from the production workspace scan",
        )]
    }
}

fn super_visible(visibility: &syn::Visibility) -> bool {
    matches!(visibility, syn::Visibility::Restricted(restricted) if restricted.path.is_ident("super"))
}

fn localtx_stage_option(ty: &syn::Type) -> bool {
    type_last_ident(ty).as_deref() == Some("Option")
        && nested_type(ty).and_then(type_last_ident).as_deref() == Some("LocalTxQuarantineStage")
}

fn localtx_stage_reference(ty: &syn::Type) -> bool {
    matches!(ty, syn::Type::Reference(reference)
        if reference.mutability.is_some() && localtx_stage_option(&reference.elem))
}

fn named_fields(item: &syn::ItemStruct) -> BTreeMap<String, &syn::Field> {
    item.fields
        .iter()
        .filter_map(|field| field.ident.as_ref().map(|name| (name.to_string(), field)))
        .collect()
}

fn path_string(path: &syn::Path) -> String {
    path.segments
        .iter()
        .map(|segment| segment.ident.to_string())
        .collect::<Vec<_>>()
        .join("::")
}

fn localtx_test_only_statement(statement: &syn::Stmt) -> bool {
    let statement = compact_tokens(statement);
    statement.starts_with("#[cfg(") && statement.contains("test")
}

fn localtx_production_statements(block: &syn::Block) -> Vec<&syn::Stmt> {
    block
        .stmts
        .iter()
        .filter(|statement| !localtx_test_only_statement(statement))
        .collect()
}

fn call_argument<'ast>(expression: &'ast syn::Expr, function: &str) -> Option<&'ast syn::Expr> {
    let syn::Expr::Call(call) = transparent_expr(expression) else {
        return None;
    };
    (exact_expr_path(&call.func).as_deref() == Some(function) && call.args.len() == 1)
        .then(|| call.args.first())
        .flatten()
}

fn localtx_stage_value(expression: &syn::Expr, stage: &str) -> bool {
    call_argument(expression, "Some").is_some_and(|argument| {
        exact_expr_path(argument).as_deref()
            == Some(format!("LocalTxQuarantineStage::{stage}").as_str())
    })
}

fn localtx_stage_cleared(expression: &syn::Expr) -> bool {
    exact_expr_path(expression).as_deref() == Some("None")
}

fn self_destructure_bindings(statement: &syn::Stmt) -> Option<BTreeMap<String, String>> {
    let syn::Stmt::Local(local) = statement else {
        return None;
    };
    let syn::Pat::Struct(pattern) = &local.pat else {
        return None;
    };
    if !pattern.path.is_ident("Self") || pattern.rest.is_some() {
        return None;
    }
    pattern
        .fields
        .iter()
        .map(|field| {
            let syn::Member::Named(member) = &field.member else {
                return None;
            };
            Some((member.to_string(), simple_binding(&field.pat)?))
        })
        .collect()
}

fn expression_references_binding(expression: &syn::Expr, binding: &str) -> bool {
    match transparent_expr(expression) {
        syn::Expr::Path(_) => exact_expr_path(expression).as_deref() == Some(binding),
        syn::Expr::Reference(reference) => expression_references_binding(&reference.expr, binding),
        syn::Expr::Unary(unary) if matches!(unary.op, syn::UnOp::Deref(_)) => {
            expression_references_binding(&unary.expr, binding)
        }
        _ => false,
    }
}

fn awaited_try_method_statement(statement: &syn::Stmt, receiver: &str, method: &str) -> bool {
    let syn::Stmt::Expr(expression, Some(_)) = statement else {
        return false;
    };
    let syn::Expr::Try(expression) = transparent_expr(expression) else {
        return false;
    };
    let syn::Expr::Await(expression) = transparent_expr(&expression.expr) else {
        return false;
    };
    matches!(transparent_expr(&expression.base), syn::Expr::MethodCall(call)
        if call.method == method
            && call.args.is_empty()
            && expression_references_binding(&call.receiver, receiver))
}

fn stage_assignment(statement: &syn::Stmt, binding: &str, stage: Option<&str>) -> bool {
    let syn::Stmt::Expr(expression, Some(_)) = statement else {
        return false;
    };
    let syn::Expr::Assign(assignment) = transparent_expr(expression) else {
        return false;
    };
    expression_references_binding(&assignment.left, binding)
        && stage.map_or_else(
            || localtx_stage_cleared(&assignment.right),
            |stage| localtx_stage_value(&assignment.right, stage),
        )
}

fn result_unit_tail(statement: &syn::Stmt) -> bool {
    let syn::Stmt::Expr(expression, None) = statement else {
        return false;
    };
    call_argument(expression, "Ok").is_some_and(|argument| {
        matches!(transparent_expr(argument), syn::Expr::Tuple(tuple) if tuple.elems.is_empty())
    })
}

fn consuming_self(signature: &syn::Signature) -> bool {
    matches!(signature.inputs.first(), Some(syn::FnArg::Receiver(receiver))
        if receiver.reference.is_none() && signature.inputs.len() == 1)
}

fn localtx_ack_then_disarm(
    method: &syn::ImplItemFn,
    transaction_field: &str,
    stage_field: &str,
    settlement: &str,
    stage: &str,
) -> bool {
    let statements = localtx_production_statements(&method.block);
    let Some(bindings) = statements
        .first()
        .and_then(|statement| self_destructure_bindings(statement))
    else {
        return false;
    };
    let (Some(transaction), Some(stage_binding)) =
        (bindings.get(transaction_field), bindings.get(stage_field))
    else {
        return false;
    };
    consuming_self(&method.sig)
        && method.sig.asyncness.is_some()
        && statements.len() == 5
        && bindings.len() == 2
        && statements
            .get(1)
            .is_some_and(|statement| stage_assignment(statement, stage_binding, Some(stage)))
        && statements.get(2).is_some_and(|statement| {
            awaited_try_method_statement(statement, transaction, settlement)
        })
        && statements
            .get(3)
            .is_some_and(|statement| stage_assignment(statement, stage_binding, None))
        && statements
            .last()
            .is_some_and(|statement| result_unit_tail(statement))
}

fn self_field(expression: &syn::Expr, field: &str) -> bool {
    matches!(transparent_expr(expression), syn::Expr::Field(access)
        if matches!(&access.member, syn::Member::Named(member) if member == field)
            && exact_expr_path(&access.base).as_deref() == Some("self"))
}

fn test_seam_signature_is_closed(method: &syn::ImplItemFn) -> bool {
    attributes_are_test_only(&method.attrs)
        && super_visible(&method.vis)
        && consuming_self(&method.sig)
        && method.sig.asyncness.is_some()
        && compact_tokens(&method.sig).contains("->Result<(),sqlx::Error>")
}

struct SeamEscapeScan<'a> {
    stage: &'a str,
    escaped: bool,
}

impl<'ast> syn::visit::Visit<'ast> for SeamEscapeScan<'_> {
    fn visit_expr_path(&mut self, path: &'ast syn::ExprPath) {
        self.escaped |= path.path.is_ident("None");
        syn::visit::visit_expr_path(self, path);
    }

    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        self.escaped |= call
            .args
            .iter()
            .any(|argument| expression_references_binding(argument, self.stage));
        syn::visit::visit_expr_call(self, call);
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        self.escaped |= expression_references_binding(&call.receiver, self.stage)
            && matches!(call.method.to_string().as_str(), "take" | "replace");
        syn::visit::visit_expr_method_call(self, call);
    }

    fn visit_macro(&mut self, _invocation: &'ast syn::Macro) {
        self.escaped = true;
    }
}

fn test_seam_stays_armed(
    method: &syn::ImplItemFn,
    stage_field: &str,
    expected_stage: &str,
) -> bool {
    let statements = localtx_production_statements(&method.block);
    let Some(stage) = statements
        .first()
        .and_then(|statement| self_destructure_bindings(statement))
        .and_then(|bindings| bindings.get(stage_field).cloned())
    else {
        return false;
    };
    let mut scan = SeamEscapeScan {
        stage: &stage,
        escaped: false,
    };
    syn::visit::Visit::visit_block(&mut scan, &method.block);
    test_seam_signature_is_closed(method)
        && statements
            .iter()
            .skip(1)
            .all(|statement| !matches!(statement, syn::Stmt::Local(_)))
        && statements
            .iter()
            .any(|statement| stage_assignment(statement, &stage, Some(expected_stage)))
        && !scan.escaped
}

fn some_pattern_binding(pattern: &syn::Pat) -> Option<String> {
    let syn::Pat::TupleStruct(pattern) = pattern else {
        return None;
    };
    (path_string(&pattern.path) == "Some" && pattern.elems.len() == 1)
        .then(|| pattern.elems.first().and_then(simple_binding))
        .flatten()
}

fn localtx_drop_is_fail_closed(
    method: &syn::ImplItemFn,
    connection_field: &str,
    stage_field: &str,
) -> bool {
    let [syn::Stmt::Expr(syn::Expr::If(branch), _)] = method.block.stmts.as_slice() else {
        return false;
    };
    let syn::Expr::Let(condition) = transparent_expr(&branch.cond) else {
        return false;
    };
    if some_pattern_binding(&condition.pat).is_none()
        || !self_field(&condition.expr, stage_field)
        || branch.else_branch.is_some()
    {
        return false;
    }
    let body = compact_tokens(&branch.then_branch);
    body.match_indices(".close_on_drop()").count() == 1
        && body.contains("metrics::counter!")
        && body.contains("tracing::warn!")
        && branch.then_branch.stmts.iter().any(|statement| {
            matches!(statement, syn::Stmt::Expr(syn::Expr::MethodCall(call), Some(_))
                if call.method == "close_on_drop" && self_field(&call.receiver, connection_field))
        })
}

fn localtx_lease_shape_findings(path: &str, syntax: &syn::File) -> Vec<Finding> {
    let mut findings = Vec::new();
    let lease_struct = syntax.items.iter().find_map(|item| match item {
        syn::Item::Struct(item) if item.ident == "LocalTxConnectionLease" => Some(item),
        _ => None,
    });
    let Some(lease_struct) = lease_struct else {
        return vec![finding(
            Rule::LocalTxQuarantineSitesAbsent,
            path,
            "private LocalTxConnectionLease struct is missing",
        )];
    };
    let lease_fields = named_fields(lease_struct);
    let connection_field = lease_fields.iter().find_map(|(name, field)| {
        (type_last_ident(&field.ty).as_deref() == Some("PoolConnection")).then_some(name.as_str())
    });
    let stage_field = lease_fields
        .iter()
        .find_map(|(name, field)| localtx_stage_option(&field.ty).then_some(name.as_str()));
    let fields_are_closed = super_visible(&lease_struct.vis)
        && lease_fields.len() == 2
        && lease_fields
            .values()
            .all(|field| matches!(field.vis, syn::Visibility::Inherited))
        && connection_field.is_some()
        && stage_field.is_some();
    let (Some(connection_field), Some(stage_field)) = (connection_field, stage_field) else {
        findings.push(finding(
            Rule::LocalTxQuarantineBypass,
            path,
            "LocalTx lease must have only private PoolConnection and Option<LocalTxQuarantineStage> fields",
        ));
        return findings;
    };

    let transaction_struct = syntax.items.iter().find_map(|item| match item {
        syn::Item::Struct(item) if item.ident == "LocalTxTransaction" => Some(item),
        _ => None,
    });
    let transaction_fields = transaction_struct.map(named_fields).unwrap_or_default();
    let transaction_field = transaction_fields.iter().find_map(|(name, field)| {
        (type_last_ident(&field.ty).as_deref() == Some("Transaction")).then_some(name.as_str())
    });
    let transaction_stage_field = transaction_fields
        .iter()
        .find_map(|(name, field)| localtx_stage_reference(&field.ty).then_some(name.as_str()));
    let transaction_fields_are_bound = transaction_struct.is_some_and(|item| {
        super_visible(&item.vis)
            && transaction_fields.len() == 2
            && transaction_fields
                .values()
                .all(|field| matches!(field.vis, syn::Visibility::Inherited))
            && transaction_field.is_some()
            && transaction_stage_field == Some(stage_field)
    });
    let Some(transaction_field) = transaction_field else {
        findings.push(finding(
            Rule::LocalTxQuarantineBypass,
            path,
            "LocalTxTransaction must privately borrow-bind the transaction and quarantine stage",
        ));
        return findings;
    };

    let stage_enum_is_closed = syntax.items.iter().any(|item| {
        matches!(item, syn::Item::Enum(item)
            if item.ident == "LocalTxQuarantineStage"
                && matches!(item.vis, syn::Visibility::Inherited)
                && item.variants.iter().all(|variant| matches!(variant.fields, syn::Fields::Unit))
                && item.variants.iter().map(|variant| variant.ident.to_string()).collect::<BTreeSet<_>>()
                    == BTreeSet::from(["Begin".to_owned(), "Body".to_owned(), "Commit".to_owned(), "Rollback".to_owned()]))
    });

    let mut lease_methods = BTreeMap::new();
    let mut transaction_methods = BTreeMap::new();
    let mut transaction_traits = BTreeSet::new();
    let mut drop_method = None;
    let mut lease_trait_escape = false;
    for item in &syntax.items {
        let syn::Item::Impl(item_impl) = item else {
            continue;
        };
        let owner = type_last_ident(&item_impl.self_ty);
        if owner.as_deref() == Some("LocalTxConnectionLease") {
            if let Some((_, trait_path, _)) = &item_impl.trait_ {
                if trait_path
                    .segments
                    .last()
                    .is_some_and(|segment| segment.ident == "Drop")
                {
                    drop_method = item_impl.items.iter().find_map(|item| match item {
                        syn::ImplItem::Fn(method) if method.sig.ident == "drop" => Some(method),
                        _ => None,
                    });
                } else {
                    lease_trait_escape = true;
                }
            } else {
                for item in &item_impl.items {
                    if let syn::ImplItem::Fn(method) = item {
                        lease_methods.insert(method.sig.ident.to_string(), method);
                    }
                }
            }
        } else if owner.as_deref() == Some("LocalTxTransaction") {
            if let Some((_, trait_path, _)) = &item_impl.trait_ {
                if let Some(segment) = trait_path.segments.last() {
                    transaction_traits.insert(segment.ident.to_string());
                }
            } else {
                for item in &item_impl.items {
                    if let syn::ImplItem::Fn(method) = item {
                        transaction_methods.insert(method.sig.ident.to_string(), method);
                    }
                }
            }
        }
    }

    let lease_surface_is_closed = lease_methods.keys().map(String::as_str).collect::<Vec<_>>()
        == ["acquire", "begin"]
        && !lease_trait_escape
        && lease_methods
            .values()
            .all(|method| super_visible(&method.vis));
    let transaction_surface_is_closed = transaction_traits.is_empty()
        && transaction_methods
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>()
            == BTreeSet::from([
                "capability",
                "commit",
                "commit_unknown_after_ack",
                "rollback",
                "rollback_failed_after_ack",
                "rollback_paused_before_ack",
            ])
        && transaction_methods.values().all(|method| {
            let signature = compact_tokens(&method.sig);
            super_visible(&method.vis)
                && !signature.contains("PoolConnection")
                && !signature.contains("Transaction<")
        })
        && transaction_methods
            .get("commit_unknown_after_ack")
            .is_some_and(|method| test_seam_stays_armed(method, stage_field, "Commit"))
        && transaction_methods
            .get("rollback_failed_after_ack")
            .is_some_and(|method| test_seam_stays_armed(method, stage_field, "Rollback"))
        && transaction_methods
            .get("rollback_paused_before_ack")
            .is_some_and(|method| test_seam_stays_armed(method, stage_field, "Rollback"));
    let acknowledged_settlement_is_bound =
        transaction_methods.get("commit").is_some_and(|method| {
            localtx_ack_then_disarm(method, transaction_field, stage_field, "commit", "Commit")
        }) && transaction_methods.get("rollback").is_some_and(|method| {
            localtx_ack_then_disarm(
                method,
                transaction_field,
                stage_field,
                "rollback",
                "Rollback",
            )
        });
    let drop_is_fail_closed = drop_method
        .is_some_and(|method| localtx_drop_is_fail_closed(method, connection_field, stage_field));
    let free_function_escape = syntax.items.iter().any(|item| {
        matches!(item, syn::Item::Fn(function) if {
            let tokens = compact_tokens(function);
            tokens.contains("LocalTxConnectionLease")
                || tokens.contains("LocalTxTransaction")
                || tokens.contains("LocalTxQuarantineStage")
                || tokens.contains(stage_field)
        })
    });
    let opaque_nested_scope = syntax
        .items
        .iter()
        .any(|item| matches!(item, syn::Item::Mod(_) | syn::Item::Macro(_)));
    if !fields_are_closed
        || !transaction_fields_are_bound
        || !stage_enum_is_closed
        || !lease_surface_is_closed
        || !transaction_surface_is_closed
        || !acknowledged_settlement_is_bound
        || !drop_is_fail_closed
        || free_function_escape
        || opaque_nested_scope
    {
        findings.push(finding(
            Rule::LocalTxQuarantineBypass,
            path,
            "LocalTx lease must AST-bind its private stage through Begin→Body and consuming Commit/Rollback→ACK→None flows, keep test seams armed, observe and close every armed Drop, and reject carrier escapes",
        ));
    }
    findings
}

fn required_retry_site_findings(
    files: &[(String, String)],
    sites: &BTreeSet<&'static str>,
) -> Vec<Finding> {
    let Some((_, runner)) = files.iter().find(|(rel, _)| rel == "tx_retry.rs") else {
        return Vec::new();
    };
    let mut findings = localtx_deadline_authority_findings(&strip_cfg_test_modules(runner));
    findings.extend(
        [
            "settings-config-commit",
            "settings-secret-publish",
            "settings-secret-publish-internal",
            "settings-secret-republish",
            "identity-password-change",
            "identity-session-logout",
            "identity-refresh-rotate",
            "audit-append",
            "audit-list-tenant-append",
        ]
        .into_iter()
        .filter(|required| !sites.contains(required))
        .map(|required| {
            finding(
                Rule::RetrySitesAbsent,
                required,
                "sanctioned transaction retry boundary was not found",
            )
        }),
    );
    findings
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
    tenant_read_lane_sites: usize,
    tenant_write_lane_sites: usize,
    allowed_exceptions: BTreeSet<&'static str>,
    retry_sites: BTreeSet<&'static str>,
    outbox_insert_sites: BTreeMap<&'static str, usize>,
    secret_ref_mutation_sites: BTreeMap<&'static str, usize>,
}

fn scan_source_file(
    rel: &str,
    content: &str,
    tenant_tables: &BTreeSet<String>,
    writer_sql_helpers: Option<&BTreeMap<String, WriterSqlAssessment>>,
    state: &mut ScanState,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let stripped = strip_rust_comment_lines(&strip_cfg_test_modules(content));
    let expanded = expand_simple_table_consts(&stripped).to_lowercase();
    let lane_scan = tenant_lane_scan(rel, &stripped, writer_sql_helpers);
    state.tenant_read_lane_sites += lane_scan.read_sites;
    state.tenant_write_lane_sites += lane_scan.write_sites;
    findings.extend(lane_scan.findings);
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
    let raw_pool_field_hits = raw_tenant_pool_fields(&stripped);
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
                "outbox producer opens a raw transaction near {:?}; use PgTenantWritePool write/co-tx funnel",
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
                "tenant tables {:?} touched through raw pattern {:?}; use PgTenantReadPool/PgTenantWritePool scoped methods",
                hit.tables, hit.pattern
            ),
        )
    }));
    findings
}

fn deadline_type_aliases(syntax: &syn::File) -> BTreeSet<String> {
    fn collect_use(tree: &syn::UseTree, aliases: &mut BTreeSet<String>) {
        match tree {
            syn::UseTree::Path(path) => collect_use(&path.tree, aliases),
            syn::UseTree::Group(group) => {
                for item in &group.items {
                    collect_use(item, aliases);
                }
            }
            syn::UseTree::Name(name) if name.ident == "LocalTxDeadline" => {
                aliases.insert(name.ident.to_string());
            }
            syn::UseTree::Rename(rename) if rename.ident == "LocalTxDeadline" => {
                aliases.insert(rename.rename.to_string());
            }
            syn::UseTree::Name(_) | syn::UseTree::Rename(_) | syn::UseTree::Glob(_) => {}
        }
    }

    let mut aliases = BTreeSet::from(["LocalTxDeadline".to_owned()]);
    for item in &syntax.items {
        match item {
            syn::Item::Use(item) => collect_use(&item.tree, &mut aliases),
            syn::Item::Type(item)
                if type_last_ident(&item.ty).as_deref() == Some("LocalTxDeadline") =>
            {
                aliases.insert(item.ident.to_string());
            }
            _ => {}
        }
    }
    aliases
}

struct DeadlineEscapeScan {
    aliases: BTreeSet<String>,
    deadline_impl: bool,
    sites: Vec<usize>,
}

impl DeadlineEscapeScan {
    fn path_is_deadline(&self, path: &syn::Path) -> bool {
        path.segments
            .last()
            .is_some_and(|segment| self.aliases.contains(&segment.ident.to_string()))
    }

    fn path_is_mint(&self, path: &syn::Path) -> bool {
        let segments = path.segments.iter().collect::<Vec<_>>();
        segments
            .last()
            .is_some_and(|segment| segment.ident == "mint")
            && segments
                .get(segments.len().saturating_sub(2))
                .is_some_and(|segment| {
                    self.aliases.contains(&segment.ident.to_string())
                        || (segment.ident == "Self" && self.deadline_impl)
                })
    }
}

impl<'ast> syn::visit::Visit<'ast> for DeadlineEscapeScan {
    fn visit_item_impl(&mut self, node: &'ast syn::ItemImpl) {
        let previous = self.deadline_impl;
        self.deadline_impl =
            type_last_ident(&node.self_ty).is_some_and(|name| self.aliases.contains(&name));
        syn::visit::visit_item_impl(self, node);
        self.deadline_impl = previous;
    }

    fn visit_expr_struct(&mut self, node: &'ast syn::ExprStruct) {
        if self.path_is_deadline(&node.path) || (node.path.is_ident("Self") && self.deadline_impl) {
            self.sites.push(node.span().start().line);
        }
        syn::visit::visit_expr_struct(self, node);
    }

    fn visit_expr_path(&mut self, node: &'ast syn::ExprPath) {
        if self.path_is_mint(&node.path) {
            self.sites.push(node.span().start().line);
        }
        syn::visit::visit_expr_path(self, node);
    }
}

fn deadline_escape_findings(rel: &str, syntax: &syn::File) -> Vec<Finding> {
    if rel == "tx_retry.rs" {
        return Vec::new();
    }
    let mut scan = DeadlineEscapeScan {
        aliases: deadline_type_aliases(syntax),
        deadline_impl: false,
        sites: Vec::new(),
    };
    syn::visit::Visit::visit_file(&mut scan, syntax);
    scan.sites
        .into_iter()
        .map(|line| {
            finding(
                Rule::RetryPlacement,
                site_subject(rel, line),
                "LocalTxDeadline construction and mint references are confined to tx_retry.rs",
            )
        })
        .collect()
}

#[derive(Clone)]
struct DeadlineAuthoritySite {
    function: Option<String>,
    test_only: bool,
    loop_depth: usize,
    closure_depth: usize,
    path: String,
}

struct DeadlineAuthorityScan {
    aliases: BTreeSet<String>,
    deadline_impl: bool,
    function: Option<String>,
    test_only: bool,
    loop_depth: usize,
    closure_depth: usize,
    constructors: Vec<DeadlineAuthoritySite>,
    mint_references: Vec<DeadlineAuthoritySite>,
}

impl DeadlineAuthorityScan {
    fn site(&self, path: String) -> DeadlineAuthoritySite {
        DeadlineAuthoritySite {
            function: self.function.clone(),
            test_only: self.test_only,
            loop_depth: self.loop_depth,
            closure_depth: self.closure_depth,
            path,
        }
    }

    fn path_is_deadline(&self, path: &syn::Path) -> bool {
        path.segments
            .last()
            .is_some_and(|segment| self.aliases.contains(&segment.ident.to_string()))
    }

    fn path_is_mint(&self, path: &syn::Path) -> bool {
        let segments = path.segments.iter().collect::<Vec<_>>();
        segments
            .last()
            .is_some_and(|segment| segment.ident == "mint")
            && segments
                .get(segments.len().saturating_sub(2))
                .is_some_and(|segment| {
                    self.aliases.contains(&segment.ident.to_string())
                        || (segment.ident == "Self" && self.deadline_impl)
                })
    }

    fn visit_function(
        &mut self,
        name: String,
        attributes: &[syn::Attribute],
        block: &'_ syn::Block,
    ) {
        let previous_function = self.function.replace(name);
        let previous_test_only = self.test_only;
        self.test_only |= attributes_guarantee_test(attributes);
        syn::visit::Visit::visit_block(self, block);
        self.test_only = previous_test_only;
        self.function = previous_function;
    }
}

impl<'ast> syn::visit::Visit<'ast> for DeadlineAuthorityScan {
    fn visit_item_impl(&mut self, node: &'ast syn::ItemImpl) {
        let previous_impl = self.deadline_impl;
        let previous_test_only = self.test_only;
        self.deadline_impl =
            type_last_ident(&node.self_ty).is_some_and(|name| self.aliases.contains(&name));
        self.test_only |= attributes_guarantee_test(&node.attrs);
        syn::visit::visit_item_impl(self, node);
        self.test_only = previous_test_only;
        self.deadline_impl = previous_impl;
    }

    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        self.visit_function(node.sig.ident.to_string(), &node.attrs, &node.block);
    }

    fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
        self.visit_function(node.sig.ident.to_string(), &node.attrs, &node.block);
    }

    fn visit_expr_struct(&mut self, node: &'ast syn::ExprStruct) {
        if self.path_is_deadline(&node.path) || (node.path.is_ident("Self") && self.deadline_impl) {
            self.constructors
                .push(self.site(compact_tokens(&node.path)));
        }
        syn::visit::visit_expr_struct(self, node);
    }

    fn visit_expr_path(&mut self, node: &'ast syn::ExprPath) {
        if self.path_is_mint(&node.path) {
            self.mint_references
                .push(self.site(compact_tokens(&node.path)));
        }
        syn::visit::visit_expr_path(self, node);
    }

    fn visit_expr_closure(&mut self, node: &'ast syn::ExprClosure) {
        self.closure_depth += 1;
        syn::visit::visit_expr_closure(self, node);
        self.closure_depth -= 1;
    }

    fn visit_expr_for_loop(&mut self, node: &'ast syn::ExprForLoop) {
        self.loop_depth += 1;
        syn::visit::visit_expr_for_loop(self, node);
        self.loop_depth -= 1;
    }

    fn visit_expr_while(&mut self, node: &'ast syn::ExprWhile) {
        self.loop_depth += 1;
        syn::visit::visit_expr_while(self, node);
        self.loop_depth -= 1;
    }

    fn visit_expr_loop(&mut self, node: &'ast syn::ExprLoop) {
        self.loop_depth += 1;
        syn::visit::visit_expr_loop(self, node);
        self.loop_depth -= 1;
    }
}

fn attributes_guarantee_test(attributes: &[syn::Attribute]) -> bool {
    attributes.iter().any(|attribute| {
        if !attribute.path().is_ident("cfg") {
            return false;
        }
        let cfg = compact_tokens(&attribute.meta);
        cfg == "cfg(test)" || cfg.starts_with("cfg(all(test,")
    })
}

fn localtx_deadline_authority_findings(source: &str) -> Vec<Finding> {
    let syntax = match syn::parse_file(source) {
        Ok(syntax) => syntax,
        Err(error) => {
            return vec![finding(
                Rule::RetryPlacement,
                "tx_retry.rs",
                format!("cannot parse LocalTxDeadline authority source: {error}"),
            )];
        }
    };
    let aliases = deadline_type_aliases(&syntax);
    let mut scan = DeadlineAuthorityScan {
        aliases,
        deadline_impl: false,
        function: None,
        test_only: false,
        loop_depth: 0,
        closure_depth: 0,
        constructors: Vec::new(),
        mint_references: Vec::new(),
    };
    syn::visit::Visit::visit_file(&mut scan, &syntax);

    let structure_is_closed = deadline_struct_is_private(&syntax)
        && deadline_mint_is_canonical(&syntax)
        && production_deadline_mint_is_canonical(&syntax, &scan)
        && test_deadline_mints_are_explicit(&scan)
        && scan.constructors.len() == 1
        && scan.constructors.first().is_some_and(|site| {
            site.function.as_deref() == Some("mint")
                && !site.test_only
                && site.loop_depth == 0
                && site.closure_depth == 0
                && site.path == "Self"
        });
    if structure_is_closed {
        Vec::new()
    } else {
        vec![finding(
            Rule::RetryPlacement,
            "tx_retry.rs::LocalTxDeadline",
            format!(
                "LocalTxDeadline must keep private fields and one private canonical mint, with exactly one pre-attempt LocalTxDeadline::mint binding in run_pg_tx_retry_core; direct/aliased/Self/reset construction is forbidden and only an explicit cfg(test) helper may reuse mint (constructors={}, mint_refs={})",
                scan.constructors.len(),
                scan.mint_references.len()
            ),
        )]
    }
}

fn deadline_struct_is_private(syntax: &syn::File) -> bool {
    let definitions = syntax
        .items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Struct(item) if item.ident == "LocalTxDeadline" => Some(item),
            _ => None,
        })
        .collect::<Vec<_>>();
    let Some(definition) = definitions.first().filter(|_| definitions.len() == 1) else {
        return false;
    };
    let syn::Fields::Named(fields) = &definition.fields else {
        return false;
    };
    fields.named.len() == 2
        && fields.named.iter().all(|field| {
            matches!(field.vis, syn::Visibility::Inherited)
                && field.ident.as_ref().is_some_and(|ident| {
                    matches!(ident.to_string().as_str(), "operation" | "final_settlement")
                })
        })
}

fn deadline_mint_is_canonical(syntax: &syn::File) -> bool {
    let methods = syntax
        .items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Impl(item)
                if type_last_ident(&item.self_ty).as_deref() == Some("LocalTxDeadline") =>
            {
                Some(item)
            }
            _ => None,
        })
        .flat_map(|item| item.items.iter())
        .filter_map(|item| match item {
            syn::ImplItem::Fn(item) if item.sig.ident == "mint" => Some(item),
            _ => None,
        })
        .collect::<Vec<_>>();
    methods.len() == 1 && canonical_deadline_mint(methods[0])
}

fn canonical_deadline_mint(method: &syn::ImplItemFn) -> bool {
    let Some((budget, started, constructor)) = canonical_mint_bindings(method) else {
        return false;
    };
    constructor.rest.is_none()
        && constructor.path.is_ident("Self")
        && constructor.fields.len() == 2
        && constructor.fields.iter().all(|field| {
            let syn::Member::Named(member) = &field.member else {
                return false;
            };
            let budget_method = match member.to_string().as_str() {
                "operation" => "operation",
                "final_settlement" => "total",
                _ => return false,
            };
            deadline_sum_expr(&field.expr, &started, &budget, budget_method)
        })
}

fn canonical_mint_bindings(method: &syn::ImplItemFn) -> Option<(String, String, &syn::ExprStruct)> {
    if !matches!(method.vis, syn::Visibility::Inherited)
        || method.sig.asyncness.is_some()
        || method.sig.inputs.len() != 1
        || !matches!(method.sig.output, syn::ReturnType::Type(_, ref ty) if type_last_ident(ty).as_deref() == Some("Self"))
        || method.block.stmts.len() != 2
    {
        return None;
    }
    let syn::FnArg::Typed(argument) = method.sig.inputs.first()? else {
        return None;
    };
    if type_last_ident(&argument.ty).as_deref() != Some("LocalTxExecutionBudget") {
        return None;
    }
    let budget = simple_binding(&argument.pat)?;
    let syn::Stmt::Local(local) = &method.block.stmts[0] else {
        return None;
    };
    let started = simple_binding(&local.pat)?;
    let syn::Expr::Call(now) = transparent_expr(local_initializer(local)?) else {
        return None;
    };
    if exact_expr_path(&now.func).as_deref() != Some("tokio::time::Instant::now")
        || !now.args.is_empty()
    {
        return None;
    }
    let syn::Stmt::Expr(expression, None) = &method.block.stmts[1] else {
        return None;
    };
    let syn::Expr::Struct(constructor) = transparent_expr(expression) else {
        return None;
    };
    Some((budget, started, constructor))
}

fn deadline_sum_expr(expression: &syn::Expr, started: &str, budget: &str, method: &str) -> bool {
    let syn::Expr::Binary(binary) = transparent_expr(expression) else {
        return false;
    };
    let syn::BinOp::Add(_) = binary.op else {
        return false;
    };
    let syn::Expr::MethodCall(duration) = transparent_expr(&binary.right) else {
        return false;
    };
    exact_expr_path(&binary.left).as_deref() == Some(started)
        && duration.method == method
        && duration.args.is_empty()
        && exact_expr_path(&duration.receiver).as_deref() == Some(budget)
}

fn production_deadline_mint_is_canonical(syntax: &syn::File, scan: &DeadlineAuthorityScan) -> bool {
    let production = scan
        .mint_references
        .iter()
        .filter(|site| !site.test_only)
        .collect::<Vec<_>>();
    let cores = syntax
        .items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Fn(function)
                if function.sig.ident == "run_pg_tx_retry_core"
                    && !attributes_guarantee_test(&function.attrs) =>
            {
                Some(function)
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    production.len() == 1
        && production[0].function.as_deref() == Some("run_pg_tx_retry_core")
        && production[0].path == "LocalTxDeadline::mint"
        && production[0].loop_depth == 0
        && production[0].closure_depth == 0
        && cores.len() == 1
        && core_mints_before_engine(cores[0])
}

fn core_mints_before_engine(core: &syn::ItemFn) -> bool {
    let mint_bindings = core
        .block
        .stmts
        .iter()
        .enumerate()
        .filter_map(|(index, statement)| {
            let syn::Stmt::Local(local) = statement else {
                return None;
            };
            let binding = simple_binding(&local.pat)?;
            let syn::Expr::Call(call) = transparent_expr(local_initializer(local)?) else {
                return None;
            };
            (exact_expr_path(&call.func).as_deref() == Some("LocalTxDeadline::mint")
                && call.args.len() == 1)
                .then_some((index, binding))
        })
        .collect::<Vec<_>>();
    let Some((mint_index, binding)) = mint_bindings.first().filter(|_| mint_bindings.len() == 1)
    else {
        return false;
    };
    let engine_indices = core
        .block
        .stmts
        .iter()
        .enumerate()
        .filter_map(|(index, statement)| {
            statement_contains_call(statement, "run_tx_retry").then_some(index)
        })
        .collect::<Vec<_>>();
    let Some(engine_index) = engine_indices.first().filter(|_| engine_indices.len() == 1) else {
        return false;
    };
    mint_index < engine_index
        && statement_path_count(&core.block.stmts[*engine_index], binding) > 0
        && !statements_shadow_or_assign(&core.block.stmts[mint_index + 1..], binding)
}

fn statement_contains_call(statement: &syn::Stmt, function: &str) -> bool {
    struct CallScan<'a> {
        function: &'a str,
        calls: usize,
    }
    impl<'ast> syn::visit::Visit<'ast> for CallScan<'_> {
        fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
            if exact_expr_path(&node.func)
                .is_some_and(|path| path.rsplit("::").next() == Some(self.function))
            {
                self.calls += 1;
            }
            syn::visit::visit_expr_call(self, node);
        }
    }
    let mut scan = CallScan { function, calls: 0 };
    syn::visit::Visit::visit_stmt(&mut scan, statement);
    scan.calls == 1
}

fn statement_path_count(statement: &syn::Stmt, binding: &str) -> usize {
    struct PathScan<'a> {
        binding: &'a str,
        paths: usize,
    }
    impl<'ast> syn::visit::Visit<'ast> for PathScan<'_> {
        fn visit_expr_path(&mut self, node: &'ast syn::ExprPath) {
            if exact_expr_path(&syn::Expr::Path(node.clone())).as_deref() == Some(self.binding) {
                self.paths += 1;
            }
            syn::visit::visit_expr_path(self, node);
        }
    }
    let mut scan = PathScan { binding, paths: 0 };
    syn::visit::Visit::visit_stmt(&mut scan, statement);
    scan.paths
}

fn statements_shadow_or_assign(statements: &[syn::Stmt], binding: &str) -> bool {
    struct MutationScan<'a> {
        binding: &'a str,
        mutated: bool,
    }
    impl<'ast> syn::visit::Visit<'ast> for MutationScan<'_> {
        fn visit_pat_ident(&mut self, node: &'ast syn::PatIdent) {
            if node.ident == self.binding {
                self.mutated = true;
            }
            syn::visit::visit_pat_ident(self, node);
        }

        fn visit_expr_assign(&mut self, node: &'ast syn::ExprAssign) {
            if exact_expr_path(&node.left).as_deref() == Some(self.binding) {
                self.mutated = true;
            }
            syn::visit::visit_expr_assign(self, node);
        }
    }
    let mut scan = MutationScan {
        binding,
        mutated: false,
    };
    for statement in statements {
        syn::visit::Visit::visit_stmt(&mut scan, statement);
    }
    scan.mutated
}

fn test_deadline_mints_are_explicit(scan: &DeadlineAuthorityScan) -> bool {
    let test_sites = scan
        .mint_references
        .iter()
        .filter(|site| site.test_only)
        .collect::<Vec<_>>();
    test_sites.len() <= 1
        && test_sites.first().is_none_or(|site| {
            site.function.as_deref() == Some("localtx_deadline_for_test")
                && site.path == "LocalTxDeadline::mint"
                && site.loop_depth == 0
                && site.closure_depth == 0
        })
}

#[derive(Debug)]
struct LocalTxDeadlineObservationSite {
    file: String,
    impl_trait: Option<String>,
    impl_type: Option<String>,
    function: Option<String>,
    receiver: String,
    argument: String,
    line: usize,
}

#[derive(Default)]
struct LocalTxDeadlineObservationScan {
    impl_trait: Option<String>,
    impl_type: Option<String>,
    function: Option<String>,
    emissions: Vec<LocalTxDeadlineObservationSite>,
    stage_sources: Vec<LocalTxDeadlineObservationSite>,
}

impl<'ast> syn::visit::Visit<'ast> for LocalTxDeadlineObservationScan {
    fn visit_item_mod(&mut self, node: &'ast syn::ItemMod) {
        if !attributes_are_test_only(&node.attrs) {
            syn::visit::visit_item_mod(self, node);
        }
    }

    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        if attributes_are_test_only(&node.attrs) {
            return;
        }
        let previous = self.function.replace(node.sig.ident.to_string());
        syn::visit::visit_block(self, &node.block);
        self.function = previous;
    }

    fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
        if attributes_are_test_only(&node.attrs) {
            return;
        }
        let previous = self.function.replace(node.sig.ident.to_string());
        syn::visit::visit_block(self, &node.block);
        self.function = previous;
    }

    fn visit_item_impl(&mut self, node: &'ast syn::ItemImpl) {
        let previous_trait = std::mem::replace(
            &mut self.impl_trait,
            node.trait_
                .as_ref()
                .map(|(_, path, _)| compact_tokens(path)),
        );
        let previous_type = self.impl_type.replace(compact_tokens(&node.self_ty));
        syn::visit::visit_item_impl(self, node);
        self.impl_trait = previous_trait;
        self.impl_type = previous_type;
    }

    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        let method = node.method.to_string();
        if matches!(
            method.as_str(),
            "record_deadline_exceeded" | "deadline_stages"
        ) {
            let site = LocalTxDeadlineObservationSite {
                file: String::new(),
                impl_trait: self.impl_trait.clone(),
                impl_type: self.impl_type.clone(),
                function: self.function.clone(),
                receiver: compact_tokens(&node.receiver),
                argument: node.args.first().map_or_else(String::new, compact_tokens),
                line: node.method.span().start().line,
            };
            if method == "record_deadline_exceeded" {
                self.emissions.push(site);
            } else {
                self.stage_sources.push(site);
            }
        }
        syn::visit::visit_expr_method_call(self, node);
    }
}

fn localtx_deadline_observation_findings(files: &[(String, String)]) -> Vec<Finding> {
    fn is_runner_file(path: &str) -> bool {
        matches!(path, "tx_retry.rs" | "adapters/postgres/src/tx_retry.rs")
    }

    let mut findings = Vec::new();
    let mut emissions = Vec::new();
    let mut stage_sources = Vec::new();
    let mut runner_syntax = None;

    for (rel, content) in files {
        let syntax = match syn::parse_file(content) {
            Ok(syntax) => syntax,
            Err(error) => {
                findings.push(finding(
                    Rule::RetryPlacement,
                    rel,
                    format!(
                        "cannot parse production Rust for LocalTx deadline observation ownership: {error}"
                    ),
                ));
                continue;
            }
        };
        let mut scan = LocalTxDeadlineObservationScan::default();
        syn::visit::Visit::visit_file(&mut scan, &syntax);
        for site in scan.emissions.iter_mut().chain(&mut scan.stage_sources) {
            site.file.clone_from(rel);
        }
        emissions.extend(scan.emissions);
        stage_sources.extend(scan.stage_sources);
        if is_runner_file(rel) {
            if runner_syntax.is_some() {
                findings.push(finding(
                    Rule::RetryPlacement,
                    "tx_retry.rs",
                    "LocalTx deadline observation owner must be unique",
                ));
            } else {
                runner_syntax = Some(syntax);
            }
        }
    }

    let is_runner_emission = |site: &LocalTxDeadlineObservationSite| {
        is_runner_file(&site.file)
            && site.function.as_deref() == Some("run_pg_localtx_retry")
            && site.receiver == "observation"
            && site.argument == "stage"
    };
    let is_closed_forwarder = |site: &LocalTxDeadlineObservationSite| {
        is_runner_file(&site.file)
            && site.impl_trait.as_deref() == Some("PgLocalTxObservation")
            && site.function.as_deref() == Some("record_deadline_exceeded")
            && site.argument == "stage"
            && matches!(
                (site.impl_type.as_deref(), site.receiver.as_str()),
                (Some("LocalTxObservation<M>"), "self")
                    | (
                        Some("identity::ports::AuthGrantCloseObservation"),
                        "observation"
                    )
            )
    };

    for site in &emissions {
        if !is_runner_emission(site) && !is_closed_forwarder(site) {
            findings.push(finding(
                Rule::RetryPlacement,
                site_subject(&site.file, site.line),
                "LocalTx deadline observations may only emit the runner-provided stage inside run_pg_localtx_retry or its exact sealed observation forwarders",
            ));
        }
    }

    let canonical_source = stage_sources.len() == 1
        && is_runner_file(&stage_sources[0].file)
        && stage_sources[0].function.as_deref() == Some("run_pg_tx_retry_core")
        && stage_sources[0].receiver == "error"
        && stage_sources[0].argument.is_empty();
    if !canonical_source {
        findings.push(finding(
            Rule::RetryPlacement,
            "tx_retry.rs::run_pg_tx_retry_core",
            "attempt deadline stages must have one exact LocalTxRetryError::deadline_stages source",
        ));
    }

    let canonical_runner = runner_syntax.as_ref().is_some_and(|syntax| {
        let runners = free_functions(syntax, "run_pg_localtx_retry");
        let cores = free_functions(syntax, "run_pg_tx_retry_core");
        let (Some(runner), Some(core)) = (
            runners.first().filter(|_| runners.len() == 1),
            cores.first().filter(|_| cores.len() == 1),
        ) else {
            return false;
        };
        let runner = compact_tokens(&runner.block);
        let core_tokens = compact_tokens(&core.block);
        let runner_emissions = emissions
            .iter()
            .filter(|site| is_runner_emission(site))
            .count();
        let generic_forwarders = emissions
            .iter()
            .filter(|site| {
                is_closed_forwarder(site)
                    && site.impl_type.as_deref() == Some("LocalTxObservation<M>")
            })
            .count();
        let auth_grant_forwarders = emissions
            .iter()
            .filter(|site| {
                is_closed_forwarder(site)
                    && site.impl_type.as_deref()
                        == Some("identity::ports::AuthGrantCloseObservation")
            })
            .count();
        runner_emissions == 2
            && generic_forwarders == 1
            && auth_grant_forwarders == 1
            && emissions.len() == 4
            && runner.contains(
                "|attempt,retry_class,settlement,stages|{observation.record_failed_attempt(attempt,retry_class,settlement);forstageinstages.into_iter().flatten(){observation.record_deadline_exceeded(stage);}}",
            )
            && runner.contains("|stage|observation.record_deadline_exceeded(stage)")
            && core_tokens.contains(
                "on_failed(attempt,error.class(),settlement,error.deadline_stages());",
            )
            && core_tokens.contains(
                "ifbackoff_exhausted.load(Ordering::Relaxed){on_deadline(LocalTxDeadlineStage::Backoff);}",
            )
            && function_call_count(core, "on_deadline") == 1
    });
    if !canonical_runner {
        findings.push(finding(
            Rule::RetryPlacement,
            "tx_retry.rs::run_pg_localtx_retry",
            "deadline observation sink must contain exactly two canonical emissions sourced from typed attempt evidence and backoff exhaustion",
        ));
    }

    findings
}

fn retry_placement_findings(
    rel: &str,
    content: &str,
    sites: &mut BTreeSet<&'static str>,
) -> Vec<Finding> {
    let syntax = match syn::parse_file(content) {
        Ok(syntax) => syntax,
        Err(error) => {
            return vec![finding(
                Rule::RetryPlacement,
                rel,
                format!("cannot parse production Rust for retry placement: {error}"),
            )];
        }
    };
    let aliases = retry_aliases(&syntax);
    let mut scan = RetryAstScan::new(aliases);
    syn::visit::Visit::visit_file(&mut scan, &syntax);

    let mut findings = deadline_escape_findings(rel, &syntax);
    findings.extend(legacy_deadline_helper_findings(rel, &syntax));
    findings.extend(retry_primitive_signature_findings(rel, &syntax));
    findings.extend(direct_retry_placement_findings(rel, &scan));
    findings.extend(legacy_command_evidence_findings(rel, &scan));
    if scan.wrapper_calls.is_empty() {
        return findings;
    }

    if rel == "secret_repo.rs" {
        findings.extend(settings_secret_retry_findings(&scan, sites));
        return findings;
    }

    let allowed = match rel {
        "config_repo.rs" => Some(("commit_authorized", "settings-config-commit")),
        "credential_repo.rs" => Some(("apply_password_change", "identity-password-change")),
        "auth_grant_lifecycle.rs" => Some(("close", "identity-session-logout")),
        "refresh_token_store.rs" => Some(("rotate", "identity-refresh-rotate")),
        "audit_repo.rs" => Some(("append", "audit-append")),
        "auth_audit_sink.rs" => Some(("append", "audit-list-tenant-append")),
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
            "auth_grant_lifecycle.rs" => valid_identity_logout_retry(calls[0]),
            "refresh_token_store.rs" => valid_identity_refresh_retry(calls[0]),
            "audit_repo.rs" => valid_audit_append_retry(calls[0]),
            "auth_audit_sink.rs" => valid_audit_list_tenant_retry(calls[0]),
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

fn legacy_deadline_helper_findings(rel: &str, syntax: &syn::File) -> Vec<Finding> {
    let forbidden = syntax.items.iter().filter_map(|item| match item {
        syn::Item::Fn(function)
            if matches!(
                function.sig.ident.to_string().as_str(),
                "set_local_retry_lock_timeout" | "set_local_retry_statement_timeout"
            ) =>
        {
            Some(function.sig.ident.to_string())
        }
        _ => None,
    });
    forbidden
        .map(|helper| {
            finding(
                Rule::RetryPlacement,
                format!("{rel}::{helper}"),
                "legacy fixed LocalTx retry timeout helpers are forbidden",
            )
        })
        .collect()
}

fn retry_primitive_signature_findings(rel: &str, syntax: &syn::File) -> Vec<Finding> {
    if rel != "cotx/mod.rs" {
        return Vec::new();
    }
    ["retry_write", "retry_producer_tx"]
        .into_iter()
        .filter(|method| !has_unique_deadline_primitive(syntax, method))
        .map(|method| {
            finding(
                Rule::RetryPlacement,
                format!("cotx/mod.rs::{method}"),
                "LocalTx retry mutation primitive must require the runner-issued deadline as its second typed argument with no legacy overload",
            )
        })
        .collect()
}

fn has_unique_deadline_primitive(syntax: &syn::File, method: &str) -> bool {
    let matches = syntax
        .items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Impl(item) => Some(item),
            _ => None,
        })
        .flat_map(|item| item.items.iter())
        .filter_map(|item| match item {
            syn::ImplItem::Fn(item) if item.sig.ident == method => Some(item),
            _ => None,
        })
        .collect::<Vec<_>>();
    let Some(function) = matches.first().filter(|_| matches.len() == 1) else {
        return false;
    };
    let typed = function
        .sig
        .inputs
        .iter()
        .filter_map(|input| match input {
            syn::FnArg::Typed(typed) => Some(typed),
            syn::FnArg::Receiver(_) => None,
        })
        .collect::<Vec<_>>();
    typed.get(1).is_some_and(|argument| {
        type_last_ident(&argument.ty).as_deref() == Some("LocalTxDeadline")
            && simple_binding(&argument.pat).as_deref() == Some("deadline")
    })
}

fn direct_retry_placement_findings(rel: &str, scan: &RetryAstScan) -> Vec<Finding> {
    scan.direct_calls
        .iter()
        .filter(|call| {
            rel != "tx_retry.rs" || call.function.as_deref() != Some("run_pg_tx_retry_core")
        })
        .map(|call| {
            finding(
                Rule::RetryPlacement,
                site_subject(rel, call.line),
                "consistency::run_tx_retry may only be called by tx_retry.rs::run_pg_tx_retry_core",
            )
        })
        .collect()
}

fn legacy_command_evidence_findings(rel: &str, scan: &RetryAstScan) -> Vec<Finding> {
    scan.legacy_command_evidence_calls
        .iter()
        .map(|(line, function)| {
            finding(
                Rule::RetryPlacement,
                site_subject(rel, *line),
                format!(
                    "Postgres adapter function {} must consume typed command evidence; removed optional LocalTx observation factories are forbidden",
                    function.as_deref().unwrap_or("<module>")
                ),
            )
        })
        .collect()
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
    deadline_dataflow: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CommandEvidence {
    PasswordChange,
    SessionLogout,
    RefreshRotation,
    SecretPublish,
    AuditListTenantAppend,
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
            deadline_dataflow: canonical_deadline_dataflow(expr),
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
        && call.arguments[1].operation_method.as_deref() == Some("retry_producer_tx")
        && call.arguments[1].scoped_operation_calls == 1
        && !call.arguments[1].legacy_write
        && call.arguments[1].deadline_dataflow
}

fn valid_identity_password_retry(call: &RetryCall) -> bool {
    call.wrapper == Some(RetryWrapper::Local)
        && call.arguments.len() == 3
        && call.arguments[0].command_evidence == Some(CommandEvidence::PasswordChange)
        && call.arguments[1].operation_method.as_deref() == Some("retry_write")
        && call.arguments[1].scoped_operation_calls == 1
        && !call.arguments[1].legacy_write
        && call.arguments[1].deadline_dataflow
}

fn valid_identity_logout_retry(call: &RetryCall) -> bool {
    call.wrapper == Some(RetryWrapper::Local)
        && call.arguments.len() == 3
        && call.arguments[0].command_evidence == Some(CommandEvidence::SessionLogout)
        && call.arguments[1].operation_method.as_deref() == Some("retry_write")
        && call.arguments[1].scoped_operation_calls == 1
        && !call.arguments[1].legacy_write
        && call.arguments[1].deadline_dataflow
}

fn valid_identity_refresh_retry(call: &RetryCall) -> bool {
    call.wrapper == Some(RetryWrapper::Local)
        && call.arguments.len() == 3
        && call.arguments[0].command_evidence == Some(CommandEvidence::RefreshRotation)
        && call.arguments[1].operation_method.as_deref() == Some("retry_write")
        && call.arguments[1].scoped_operation_calls == 1
        && !call.arguments[1].legacy_write
        && call.arguments[1].deadline_dataflow
}

fn valid_audit_append_retry(call: &RetryCall) -> bool {
    call.wrapper == Some(RetryWrapper::Generic)
        && call.arguments.len() == 3
        && call.arguments[0].exact_path.as_deref() == Some("AUDIT_APPEND_BOUNDARY")
        && call.arguments[1].operation_method.as_deref() == Some("retry_write")
        && call.arguments[1].scoped_operation_calls == 1
        && !call.arguments[1].legacy_write
        && call.arguments[1].deadline_dataflow
}

fn valid_audit_list_tenant_retry(call: &RetryCall) -> bool {
    call.wrapper == Some(RetryWrapper::Local)
        && call.arguments.len() == 3
        && call.arguments[0].command_evidence == Some(CommandEvidence::AuditListTenantAppend)
        && call.arguments[1].operation_method.as_deref() == Some("retry_write")
        && call.arguments[1].scoped_operation_calls == 1
        && !call.arguments[1].legacy_write
        && call.arguments[1].deadline_dataflow
}

fn valid_settings_secret_retry(call: &RetryCall) -> bool {
    call.wrapper == Some(RetryWrapper::Local)
        && call.arguments.len() == 3
        && call.arguments[0].command_evidence == Some(CommandEvidence::SecretPublish)
        && call.arguments[1].operation_method.as_deref() == Some("retry_write")
        && call.arguments[1].scoped_operation_calls == 1
        && !call.arguments[1].legacy_write
        && call.arguments[1].deadline_dataflow
}

fn valid_settings_secret_generic_retry(call: &RetryCall) -> bool {
    call.wrapper == Some(RetryWrapper::Generic)
        && call.arguments.len() == 3
        && call.arguments[0].exact_path.as_deref() == Some("SETTINGS_SECRET_BOUNDARY")
        && call.arguments[1].operation_method.as_deref() == Some("retry_write")
        && call.arguments[1].scoped_operation_calls == 1
        && !call.arguments[1].legacy_write
        && call.arguments[1].deadline_dataflow
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
            "AuthGrantCloseCommand" => CommandEvidence::SessionLogout,
            "RefreshRotationMutation" => CommandEvidence::RefreshRotation,
            "AuditListTenantAppend" => CommandEvidence::AuditListTenantAppend,
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

fn canonical_deadline_dataflow(expr: &syn::Expr) -> bool {
    let syn::Expr::Closure(closure) = transparent_expr(expr) else {
        return false;
    };
    if closure.inputs.len() != 2 {
        return false;
    }
    let Some(syn::Pat::Ident(deadline)) = closure.inputs.iter().nth(1) else {
        return false;
    };
    if deadline.by_ref.is_some() || deadline.mutability.is_some() || deadline.subpat.is_some() {
        return false;
    }
    let deadline = deadline.ident.to_string();

    #[derive(Default)]
    struct DeadlineFlow {
        deadline: String,
        uses: usize,
        shadows: usize,
        operation_calls: usize,
        correctly_bound_calls: usize,
    }
    impl<'ast> syn::visit::Visit<'ast> for DeadlineFlow {
        fn visit_pat_ident(&mut self, node: &'ast syn::PatIdent) {
            if node.ident == self.deadline {
                self.shadows += 1;
            }
            syn::visit::visit_pat_ident(self, node);
        }

        fn visit_expr_path(&mut self, node: &'ast syn::ExprPath) {
            if exact_expr_path(&syn::Expr::Path(node.clone())).as_deref()
                == Some(self.deadline.as_str())
            {
                self.uses += 1;
            }
            syn::visit::visit_expr_path(self, node);
        }

        fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
            if is_self_pool(&node.receiver)
                && matches!(
                    node.method.to_string().as_str(),
                    "retry_write" | "retry_producer_tx"
                )
            {
                self.operation_calls += 1;
                if node.args.iter().nth(1).and_then(exact_expr_path).as_deref()
                    == Some(self.deadline.as_str())
                {
                    self.correctly_bound_calls += 1;
                }
            }
            syn::visit::visit_expr_method_call(self, node);
        }
    }

    let mut flow = DeadlineFlow {
        deadline,
        ..DeadlineFlow::default()
    };
    syn::visit::Visit::visit_expr(&mut flow, &closure.body);
    flow.uses == 1
        && flow.shadows == 0
        && flow.operation_calls == 1
        && flow.correctly_bound_calls == 1
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
                "retry_write" | "retry_producer_tx" => self.calls += 1,
                "write" | "producer_tx" => {
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
                "retry_write" | "retry_producer_tx"
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
    (member == "pool" || member == "write_pool")
        && exact_expr_path(&pool.base).as_deref() == Some("self")
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum TenantLane {
    Read,
    Write,
}

impl TenantLane {
    fn type_name(self) -> &'static str {
        match self {
            Self::Read => "PgTenantReadPool",
            Self::Write => "PgTenantWritePool",
        }
    }
}

#[derive(Default)]
struct TenantLaneScan {
    read_sites: usize,
    write_sites: usize,
    findings: Vec<Finding>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct TenantLaneCall {
    line: usize,
    lane: TenantLane,
    field: String,
    method: String,
    direct_select_only: bool,
    unclassified_writer_sql: bool,
}

fn tenant_lane_scan(
    rel: &str,
    content: &str,
    workspace_helpers: Option<&BTreeMap<String, WriterSqlAssessment>>,
) -> TenantLaneScan {
    let mut scan = TenantLaneScan::default();
    for (removed, replacement) in [
        ("PgTenantPool", "PgTenantReadPool/PgTenantWritePool"),
        ("PgTenantReadStoreSource", "VerifiedPgReadStore"),
        ("PgTenantWriteStoreSource", "VerifiedPgWriteStore"),
    ] {
        for (idx, _) in content.match_indices(removed) {
            scan.findings.push(finding(
                Rule::TenantLaneViolation,
                site_subject(rel, line_number(content, idx)),
                format!("removed {removed} is forbidden; use {replacement}"),
            ));
        }
    }

    let Ok(syntax) = syn::parse_file(content) else {
        return scan;
    };
    let structs = tenant_lane_struct_fields(&syntax);
    let sqlx_query_aliases = sqlx_query_aliases(&syntax);
    let sql_string_constants = sql_string_constants(&syntax);
    let local_writer_sql_helpers;
    let writer_sql_helpers = if let Some(helpers) = workspace_helpers {
        helpers
    } else {
        local_writer_sql_helpers = writer_sql_helper_assessments(
            &syntax,
            &sqlx_query_aliases,
            &sql_string_constants,
            &BTreeMap::new(),
        );
        &local_writer_sql_helpers
    };
    let mut calls = BTreeSet::new();
    let empty_fields = BTreeMap::new();

    for item in &syntax.items {
        let syn::Item::Impl(item_impl) = item else {
            continue;
        };
        let Some(owner) = type_last_ident(&item_impl.self_ty) else {
            continue;
        };
        let fields = structs.get(&owner).unwrap_or(&empty_fields);
        let mut visitor = TenantLaneCallVisitor {
            fields,
            owner: Some(&owner),
            skip_impls: false,
            parameter_bindings: BTreeMap::new(),
            capability_callables: BTreeSet::new(),
            sqlx_query_aliases: &sqlx_query_aliases,
            sql_string_constants: &sql_string_constants,
            writer_sql_helpers,
            calls: &mut calls,
        };
        syn::visit::Visit::visit_item_impl(&mut visitor, item_impl);
    }

    // Synthetic fixtures and constructor helpers may contain `self.<field>` outside an impl item.
    // Only use a global fallback when a field name maps to exactly one lane across the file, so two
    // repository structs both named `pool` cannot contaminate each other's method ownership.
    let mut candidates: BTreeMap<String, BTreeSet<TenantLane>> = BTreeMap::new();
    for fields in structs.values() {
        for (field, lane) in fields {
            candidates.entry(field.clone()).or_default().insert(*lane);
        }
    }
    let unique_fields = candidates
        .into_iter()
        .filter_map(|(field, lanes)| {
            if lanes.len() != 1 {
                return None;
            }
            lanes.into_iter().next().map(|lane| (field, lane))
        })
        .collect();
    let mut visitor = TenantLaneCallVisitor {
        fields: &unique_fields,
        owner: None,
        skip_impls: true,
        parameter_bindings: BTreeMap::new(),
        capability_callables: BTreeSet::new(),
        sqlx_query_aliases: &sqlx_query_aliases,
        sql_string_constants: &sql_string_constants,
        writer_sql_helpers,
        calls: &mut calls,
    };
    syn::visit::Visit::visit_file(&mut visitor, &syntax);

    for call in calls {
        let is_read = matches!(call.method.as_str(), "read" | "read_map");
        let is_write = matches!(
            call.method.as_str(),
            "write" | "deadline_write" | "retry_write" | "producer_tx" | "retry_producer_tx"
        );
        scan.read_sites += usize::from(call.lane == TenantLane::Read && is_read);
        scan.write_sites += usize::from(call.lane == TenantLane::Write && is_write);

        if (call.lane == TenantLane::Read && is_write)
            || (call.lane == TenantLane::Write && is_read)
        {
            let api = format!("{}::{}", call.lane.type_name(), call.method);
            scan.findings.push(finding(
                Rule::TenantLaneViolation,
                site_subject(rel, call.line),
                format!("{api} is forbidden by the typed tenant read/write lane boundary"),
            ));
        }
        if call.lane == TenantLane::Write && is_write && call.direct_select_only {
            scan.findings.push(finding(
                Rule::TenantLaneViolation,
                site_subject(rel, call.line),
                "SELECT-only writer transaction is forbidden; independent tenant reads must use PgTenantReadPool and writer SELECTs require mutation/lock/co-tx evidence",
            ));
        }
        if call.lane == TenantLane::Write && is_write && call.unclassified_writer_sql {
            scan.findings.push(finding(
                Rule::TenantLaneViolation,
                site_subject(rel, call.line),
                "writer transaction contains dynamic, indirect, multi-statement, or otherwise unclassified SQL; writer SQL must provide statically verified mutation/lock/co-tx evidence",
            ));
        }
    }
    scan
}

fn tenant_lane_struct_fields(syntax: &syn::File) -> BTreeMap<String, BTreeMap<String, TenantLane>> {
    let mut structs = BTreeMap::new();
    for item in &syntax.items {
        let syn::Item::Struct(item_struct) = item else {
            continue;
        };
        let mut fields = BTreeMap::new();
        for field in &item_struct.fields {
            let (Some(name), Some(lane)) = (&field.ident, tenant_lane_type(&field.ty)) else {
                continue;
            };
            fields.insert(name.to_string(), lane);
        }
        if !fields.is_empty() {
            structs.insert(item_struct.ident.to_string(), fields);
        }
    }
    structs
}

fn tenant_lane_type(ty: &syn::Type) -> Option<TenantLane> {
    match type_last_ident(ty).as_deref() {
        Some("PgTenantReadPool") => Some(TenantLane::Read),
        Some("PgTenantWritePool") => Some(TenantLane::Write),
        _ => nested_type(ty).and_then(tenant_lane_type),
    }
}

fn type_last_ident(ty: &syn::Type) -> Option<String> {
    match ty {
        syn::Type::Path(path) => path
            .path
            .segments
            .last()
            .map(|segment| segment.ident.to_string()),
        syn::Type::Reference(reference) => type_last_ident(&reference.elem),
        syn::Type::Paren(paren) => type_last_ident(&paren.elem),
        syn::Type::Group(group) => type_last_ident(&group.elem),
        _ => None,
    }
}

fn nested_type(ty: &syn::Type) -> Option<&syn::Type> {
    let syn::Type::Path(path) = ty else {
        return None;
    };
    let segment = path.path.segments.last()?;
    let syn::PathArguments::AngleBracketed(arguments) = &segment.arguments else {
        return None;
    };
    arguments.args.iter().find_map(|argument| match argument {
        syn::GenericArgument::Type(ty) => Some(ty),
        _ => None,
    })
}

fn tenant_lane_parameter_bindings(signature: &syn::Signature) -> BTreeMap<String, TenantLane> {
    let mut bindings = BTreeMap::new();
    for input in &signature.inputs {
        let syn::FnArg::Typed(typed) = input else {
            continue;
        };
        collect_tenant_lane_pattern_bindings(&typed.pat, &typed.ty, &mut bindings);
    }
    bindings
}

fn collect_tenant_lane_pattern_bindings(
    pattern: &syn::Pat,
    ty: &syn::Type,
    bindings: &mut BTreeMap<String, TenantLane>,
) {
    match pattern {
        syn::Pat::Ident(ident) => {
            if let Some(lane) = tenant_lane_type(ty) {
                bindings.insert(ident.ident.to_string(), lane);
            }
            if let Some((_, subpattern)) = &ident.subpat {
                collect_tenant_lane_pattern_bindings(subpattern, ty, bindings);
            }
        }
        syn::Pat::Reference(reference) => {
            let inner = match ty {
                syn::Type::Reference(reference) => reference.elem.as_ref(),
                _ => ty,
            };
            collect_tenant_lane_pattern_bindings(&reference.pat, inner, bindings);
        }
        syn::Pat::Paren(paren) => {
            let inner = match ty {
                syn::Type::Paren(paren) => paren.elem.as_ref(),
                syn::Type::Group(group) => group.elem.as_ref(),
                _ => ty,
            };
            collect_tenant_lane_pattern_bindings(&paren.pat, inner, bindings);
        }
        syn::Pat::Type(typed) => {
            collect_tenant_lane_pattern_bindings(&typed.pat, &typed.ty, bindings);
        }
        syn::Pat::Tuple(tuple) => {
            if let syn::Type::Tuple(types) = ty {
                for (element, element_ty) in tuple.elems.iter().zip(&types.elems) {
                    collect_tenant_lane_pattern_bindings(element, element_ty, bindings);
                }
            }
        }
        syn::Pat::TupleStruct(tuple) => {
            if let Some(types) = nested_type_arguments(ty)
                && types.len() == tuple.elems.len()
            {
                for (element, element_ty) in tuple.elems.iter().zip(types) {
                    collect_tenant_lane_pattern_bindings(element, element_ty, bindings);
                }
            }
        }
        syn::Pat::Slice(slice) => {
            let element_ty = match ty {
                syn::Type::Array(array) => Some(array.elem.as_ref()),
                syn::Type::Slice(slice) => Some(slice.elem.as_ref()),
                _ => None,
            };
            if let Some(element_ty) = element_ty {
                for element in &slice.elems {
                    collect_tenant_lane_pattern_bindings(element, element_ty, bindings);
                }
            }
        }
        syn::Pat::Or(or) => {
            for case in &or.cases {
                collect_tenant_lane_pattern_bindings(case, ty, bindings);
            }
        }
        _ => {}
    }
}

fn nested_type_arguments(ty: &syn::Type) -> Option<Vec<&syn::Type>> {
    let syn::Type::Path(path) = ty else {
        return None;
    };
    let segment = path.path.segments.last()?;
    let syn::PathArguments::AngleBracketed(arguments) = &segment.arguments else {
        return None;
    };
    Some(
        arguments
            .args
            .iter()
            .filter_map(|argument| match argument {
                syn::GenericArgument::Type(ty) => Some(ty),
                _ => None,
            })
            .collect(),
    )
}

fn tenant_lane_parameter_receiver(expr: &syn::Expr) -> Option<String> {
    match transparent_expr(expr) {
        syn::Expr::Path(path) if path.qself.is_none() && path.path.segments.len() == 1 => path
            .path
            .segments
            .first()
            .map(|segment| segment.ident.to_string()),
        syn::Expr::Reference(reference) => tenant_lane_parameter_receiver(&reference.expr),
        syn::Expr::Unary(unary) if matches!(unary.op, syn::UnOp::Deref(_)) => {
            tenant_lane_parameter_receiver(&unary.expr)
        }
        _ => None,
    }
}

struct TenantLaneCallVisitor<'a> {
    fields: &'a BTreeMap<String, TenantLane>,
    owner: Option<&'a str>,
    skip_impls: bool,
    parameter_bindings: BTreeMap<String, TenantLane>,
    capability_callables: BTreeSet<String>,
    sqlx_query_aliases: &'a BTreeSet<String>,
    sql_string_constants: &'a BTreeMap<String, String>,
    writer_sql_helpers: &'a BTreeMap<String, WriterSqlAssessment>,
    calls: &'a mut BTreeSet<TenantLaneCall>,
}

impl<'ast> syn::visit::Visit<'ast> for TenantLaneCallVisitor<'_> {
    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        let receiver = self_field_name(&node.receiver)
            .and_then(|field| self.fields.get(&field).copied().map(|lane| (field, lane)))
            .or_else(|| {
                tenant_lane_parameter_receiver(&node.receiver).and_then(|binding| {
                    self.parameter_bindings
                        .get(&binding)
                        .copied()
                        .map(|lane| (binding, lane))
                })
            });
        if let Some((field, lane)) = receiver {
            let (direct_select_only, unclassified_writer_sql) = writer_call_sql_assessment(
                node,
                self.owner,
                &self.capability_callables,
                self.sqlx_query_aliases,
                self.sql_string_constants,
                self.writer_sql_helpers,
            );
            self.calls.insert(TenantLaneCall {
                line: node.method.span().start().line,
                lane,
                field,
                method: node.method.to_string(),
                direct_select_only,
                unclassified_writer_sql,
            });
        }
        syn::visit::visit_expr_method_call(self, node);
    }

    fn visit_item_impl(&mut self, item: &'ast syn::ItemImpl) {
        if !self.skip_impls {
            syn::visit::visit_item_impl(self, item);
        }
    }

    fn visit_impl_item_fn(&mut self, function: &'ast syn::ImplItemFn) {
        let previous_parameters = std::mem::replace(
            &mut self.parameter_bindings,
            tenant_lane_parameter_bindings(&function.sig),
        );
        let previous_callables = std::mem::replace(
            &mut self.capability_callables,
            capability_callback_bindings(&function.sig),
        );
        syn::visit::visit_impl_item_fn(self, function);
        self.capability_callables = previous_callables;
        self.parameter_bindings = previous_parameters;
    }

    fn visit_item_fn(&mut self, function: &'ast syn::ItemFn) {
        let previous_parameters = std::mem::replace(
            &mut self.parameter_bindings,
            tenant_lane_parameter_bindings(&function.sig),
        );
        let previous_callables = std::mem::replace(
            &mut self.capability_callables,
            capability_callback_bindings(&function.sig),
        );
        syn::visit::visit_item_fn(self, function);
        self.capability_callables = previous_callables;
        self.parameter_bindings = previous_parameters;
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct SqlQuerySite {
    line: usize,
    column: usize,
    sql: Option<String>,
}

struct WriterSqlEvidenceVisitor<'a> {
    aliases: &'a BTreeSet<String>,
    constants: &'a BTreeMap<String, String>,
    capability_bindings: BTreeSet<String>,
    capability_callables: BTreeSet<String>,
    call_owner: Option<String>,
    call_module: Option<String>,
    queries: BTreeSet<SqlQuerySite>,
    executed: BTreeSet<SqlQuerySite>,
    helper_calls: BTreeSet<String>,
    executed_helper_calls: BTreeSet<String>,
    capability_helper_calls: BTreeSet<String>,
    unresolved_capability_call: bool,
    unclassified_sql_provenance: bool,
    conditional_depth: usize,
    awaited_execution_depth: usize,
}

impl<'a> WriterSqlEvidenceVisitor<'a> {
    fn new(
        aliases: &'a BTreeSet<String>,
        constants: &'a BTreeMap<String, String>,
        capability_bindings: BTreeSet<String>,
        capability_callables: BTreeSet<String>,
        call_owner: Option<String>,
        call_module: Option<String>,
    ) -> Self {
        Self {
            aliases,
            constants,
            capability_bindings,
            capability_callables,
            call_owner,
            call_module,
            queries: BTreeSet::new(),
            executed: BTreeSet::new(),
            helper_calls: BTreeSet::new(),
            executed_helper_calls: BTreeSet::new(),
            capability_helper_calls: BTreeSet::new(),
            unresolved_capability_call: false,
            unclassified_sql_provenance: false,
            conditional_depth: 0,
            awaited_execution_depth: 0,
        }
    }

    fn in_conditional_scope(&mut self, visit: impl FnOnce(&mut Self)) {
        self.conditional_depth += 1;
        visit(self);
        self.conditional_depth -= 1;
    }

    fn expression_is_capability_value(&self, expression: &syn::Expr) -> bool {
        expression_is_capability_value(expression, &self.capability_bindings)
    }
}

impl<'ast> syn::visit::Visit<'ast> for WriterSqlEvidenceVisitor<'_> {
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let Some(site) = sqlx_query_call_site(call, self.aliases, self.constants) {
            self.queries.insert(site);
        } else if let syn::Expr::Path(function) = call.func.as_ref()
            && let Some(name) = function.path.segments.last()
        {
            let name = name.ident.to_string();
            let passes_capability = call
                .args
                .iter()
                .any(|argument| self.expression_is_capability_value(argument));
            let is_typed_capability_callback = self.capability_callables.contains(&name);
            if let Some(callable) = callable_identity(
                &function.path,
                self.call_owner.as_deref(),
                self.call_module.as_deref(),
            ) {
                self.helper_calls.insert(callable.clone());
                if self.conditional_depth == 0 && self.awaited_execution_depth > 0 {
                    self.executed_helper_calls.insert(callable.clone());
                }
                if passes_capability && !is_typed_capability_callback {
                    self.capability_helper_calls.insert(callable);
                }
            } else if passes_capability && !is_typed_capability_callback {
                self.unresolved_capability_call = true;
            }
            if sqlx_query_name(&name) && function.path.segments.len() > 1 {
                self.unclassified_sql_provenance = true;
            }
        }
        syn::visit::visit_expr_call(self, call);
    }

    fn visit_expr_macro(&mut self, expression: &'ast syn::ExprMacro) {
        if let Some(site) = sqlx_query_macro_site(expression, self.aliases, self.constants) {
            self.queries.insert(site);
        }
        syn::visit::visit_expr_macro(self, expression);
    }

    fn visit_expr_method_call(&mut self, method: &'ast syn::ExprMethodCall) {
        if matches!(
            method.method.to_string().as_str(),
            "execute" | "fetch" | "fetch_all" | "fetch_one" | "fetch_optional" | "fetch_many"
        ) && let Some(site) =
            sqlx_query_site_in_receiver(&method.receiver, self.aliases, self.constants)
        {
            if self.conditional_depth == 0 && self.awaited_execution_depth > 0 {
                self.executed.insert(site);
            }
        } else if let Some(owner) = self.call_owner.as_deref()
            && expression_is_self(&method.receiver)
        {
            let callable = format!("{owner}::{}", method.method);
            self.helper_calls.insert(callable.clone());
            if self.conditional_depth == 0 && self.awaited_execution_depth > 0 {
                self.executed_helper_calls.insert(callable.clone());
            }
            if method
                .args
                .iter()
                .any(|argument| self.expression_is_capability_value(argument))
            {
                self.capability_helper_calls.insert(callable);
            }
        } else if !matches!(
            method.method.to_string().as_str(),
            "execute"
                | "fetch"
                | "fetch_all"
                | "fetch_one"
                | "fetch_optional"
                | "fetch_many"
                | "conn"
        ) && (self.expression_is_capability_value(&method.receiver)
            || method
                .args
                .iter()
                .any(|argument| self.expression_is_capability_value(argument)))
        {
            self.unresolved_capability_call = true;
        }
        syn::visit::visit_expr_method_call(self, method);
    }

    fn visit_stmt(&mut self, statement: &'ast syn::Stmt) {
        let test_only = match statement {
            syn::Stmt::Local(local) => attributes_are_test_only(&local.attrs),
            syn::Stmt::Macro(statement_macro) => attributes_are_test_only(&statement_macro.attrs),
            syn::Stmt::Expr(syn::Expr::If(expression), _) => {
                attributes_are_test_only(&expression.attrs)
            }
            _ => false,
        };
        if !test_only {
            syn::visit::visit_stmt(self, statement);
        }
    }

    fn visit_expr_await(&mut self, expression: &'ast syn::ExprAwait) {
        if let syn::Expr::Async(async_expression) = expression.base.as_ref() {
            syn::visit::Visit::visit_block(self, &async_expression.block);
            return;
        }
        self.awaited_execution_depth += 1;
        syn::visit::Visit::visit_expr(self, &expression.base);
        self.awaited_execution_depth -= 1;
    }

    fn visit_expr_async(&mut self, expression: &'ast syn::ExprAsync) {
        self.in_conditional_scope(|visitor| {
            syn::visit::Visit::visit_block(visitor, &expression.block);
        });
    }

    fn visit_expr_if(&mut self, expression: &'ast syn::ExprIf) {
        if attributes_are_test_only(&expression.attrs) {
            return;
        }
        syn::visit::Visit::visit_expr(self, &expression.cond);
        self.in_conditional_scope(|visitor| {
            syn::visit::Visit::visit_block(visitor, &expression.then_branch);
            if let Some((_, otherwise)) = &expression.else_branch {
                syn::visit::Visit::visit_expr(visitor, otherwise);
            }
        });
    }

    fn visit_expr_match(&mut self, expression: &'ast syn::ExprMatch) {
        syn::visit::Visit::visit_expr(self, &expression.expr);
        self.in_conditional_scope(|visitor| {
            for arm in &expression.arms {
                if let Some((_, guard)) = &arm.guard {
                    syn::visit::Visit::visit_expr(visitor, guard);
                }
                syn::visit::Visit::visit_expr(visitor, &arm.body);
            }
        });
    }

    fn visit_expr_loop(&mut self, expression: &'ast syn::ExprLoop) {
        self.in_conditional_scope(|visitor| {
            syn::visit::Visit::visit_block(visitor, &expression.body);
        });
    }

    fn visit_expr_while(&mut self, expression: &'ast syn::ExprWhile) {
        syn::visit::Visit::visit_expr(self, &expression.cond);
        self.in_conditional_scope(|visitor| {
            syn::visit::Visit::visit_block(visitor, &expression.body);
        });
    }

    fn visit_expr_for_loop(&mut self, expression: &'ast syn::ExprForLoop) {
        syn::visit::Visit::visit_expr(self, &expression.expr);
        self.in_conditional_scope(|visitor| {
            syn::visit::Visit::visit_block(visitor, &expression.body);
        });
    }
}

fn writer_call_sql_assessment(
    node: &syn::ExprMethodCall,
    owner: Option<&str>,
    capability_callables: &BTreeSet<String>,
    aliases: &BTreeSet<String>,
    constants: &BTreeMap<String, String>,
    helpers: &BTreeMap<String, WriterSqlAssessment>,
) -> (bool, bool) {
    if matches!(
        node.method.to_string().as_str(),
        "producer_tx" | "retry_producer_tx"
    ) {
        return (false, false);
    }
    let mut evidence = WriterSqlEvidenceVisitor::new(
        aliases,
        constants,
        BTreeSet::new(),
        capability_callables.clone(),
        owner.map(str::to_owned),
        None,
    );
    for argument in &node.args {
        if let Some((body, bindings)) = closure_body_and_bindings(argument) {
            evidence.capability_bindings.extend(bindings);
            visit_transaction_future_root(&mut evidence, body);
        }
    }
    let mut assessment = writer_sql_evidence_assessment(&evidence);
    for helper in &evidence.executed_helper_calls {
        if let Some(helper_assessment) = helpers.get(helper) {
            assessment.merge(*helper_assessment);
        }
    }
    if evidence.unresolved_capability_call
        || evidence.unclassified_sql_provenance
        || evidence
            .capability_helper_calls
            .iter()
            .any(|helper| !helpers.contains_key(helper))
    {
        assessment.unclassified = true;
    }
    (
        assessment.has_plain_read && !assessment.has_write_or_lock,
        assessment.unclassified,
    )
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct WriterSqlAssessment {
    has_plain_read: bool,
    has_write_or_lock: bool,
    unclassified: bool,
}

impl WriterSqlAssessment {
    fn merge(&mut self, other: Self) {
        self.has_plain_read |= other.has_plain_read;
        self.has_write_or_lock |= other.has_write_or_lock;
        self.unclassified |= other.unclassified;
    }
}

fn writer_sql_evidence_assessment(evidence: &WriterSqlEvidenceVisitor<'_>) -> WriterSqlAssessment {
    let mut assessment = WriterSqlAssessment {
        unclassified: evidence.unresolved_capability_call || evidence.unclassified_sql_provenance,
        ..WriterSqlAssessment::default()
    };
    for query in &evidence.queries {
        let Some(sql) = query.sql.as_deref() else {
            assessment.unclassified = true;
            continue;
        };
        match classify_writer_sql(sql) {
            WriterSqlKind::PlainRead => assessment.has_plain_read = true,
            WriterSqlKind::Mutation | WriterSqlKind::LockingRead => {
                assessment.has_write_or_lock |= evidence.executed.contains(query);
            }
            WriterSqlKind::Unclassified => assessment.unclassified = true,
        }
    }
    assessment
}

#[derive(Default)]
struct WriterSqlHelperEvidence {
    direct: WriterSqlAssessment,
    calls: BTreeSet<String>,
    capability_calls: BTreeSet<String>,
}

fn writer_sql_helper_assessments(
    syntax: &syn::File,
    aliases: &BTreeSet<String>,
    constants: &BTreeMap<String, String>,
    external: &BTreeMap<String, WriterSqlAssessment>,
) -> BTreeMap<String, WriterSqlAssessment> {
    fn record(
        helpers: &mut BTreeMap<String, WriterSqlHelperEvidence>,
        name: String,
        block: &syn::Block,
        signature: &syn::Signature,
        identity_context: (Option<&str>, Option<&str>),
        aliases: &BTreeSet<String>,
        constants: &BTreeMap<String, String>,
    ) {
        let (owner, module) = identity_context;
        let qualified_owner = owner.map(|owner| qualify_rust_identity(module, owner));
        let mut visitor = WriterSqlEvidenceVisitor::new(
            aliases,
            constants,
            signature_capability_bindings(signature),
            capability_callback_bindings(signature),
            qualified_owner.clone(),
            module.map(str::to_owned),
        );
        syn::visit::Visit::visit_block(&mut visitor, block);
        let identity = qualified_owner.map_or_else(
            || qualify_rust_identity(module, &name),
            |owner| format!("{owner}::{name}"),
        );
        let entry = helpers.entry(identity).or_default();
        entry.direct.merge(writer_sql_evidence_assessment(&visitor));
        entry.calls.extend(visitor.executed_helper_calls);
        entry
            .capability_calls
            .extend(visitor.capability_helper_calls);
    }

    fn record_items(
        helpers: &mut BTreeMap<String, WriterSqlHelperEvidence>,
        items: &[syn::Item],
        module: &mut Vec<String>,
        aliases: &BTreeSet<String>,
        constants: &BTreeMap<String, String>,
    ) {
        for item in items {
            match item {
                syn::Item::Fn(function) => record(
                    helpers,
                    function.sig.ident.to_string(),
                    &function.block,
                    &function.sig,
                    (
                        None,
                        (!module.is_empty()).then(|| module.join("::")).as_deref(),
                    ),
                    aliases,
                    constants,
                ),
                syn::Item::Impl(item_impl) => {
                    let Some(owner) = type_last_ident(&item_impl.self_ty) else {
                        continue;
                    };
                    for item in &item_impl.items {
                        if let syn::ImplItem::Fn(function) = item {
                            record(
                                helpers,
                                function.sig.ident.to_string(),
                                &function.block,
                                &function.sig,
                                (
                                    Some(&owner),
                                    (!module.is_empty()).then(|| module.join("::")).as_deref(),
                                ),
                                aliases,
                                constants,
                            );
                        }
                    }
                }
                syn::Item::Mod(item_module) => {
                    if let Some((_, items)) = &item_module.content {
                        let module_name = item_module.ident.to_string();
                        module.push(module_name);
                        record_items(helpers, items, module, aliases, constants);
                        module.pop();
                    }
                }
                _ => {}
            }
        }
    }

    let mut helpers = BTreeMap::new();
    record_items(
        &mut helpers,
        &syntax.items,
        &mut Vec::new(),
        aliases,
        constants,
    );
    let local_aliases = writer_sql_local_aliases(syntax, helpers.keys());

    let helper_names = helpers
        .keys()
        .chain(external.keys())
        .chain(local_aliases.keys())
        .cloned()
        .collect::<BTreeSet<_>>();
    for helper in helpers.values_mut() {
        if helper
            .capability_calls
            .iter()
            .any(|callee| !helper_names.contains(callee))
        {
            helper.direct.unclassified = true;
        }
    }

    let mut resolved = external.clone();
    resolved.extend(
        helpers
            .iter()
            .map(|(name, helper)| (name.clone(), helper.direct)),
    );
    for _ in 0..helpers.len() + local_aliases.len() {
        let mut changed = false;
        for (local, target) in &local_aliases {
            if let Some(assessment) = resolved.get(target).copied()
                && resolved.get(local) != Some(&assessment)
            {
                resolved.insert(local.clone(), assessment);
                changed = true;
            }
        }
        for (name, helper) in &helpers {
            let mut next = helper.direct;
            for callee in &helper.calls {
                if let Some(assessment) = resolved.get(callee) {
                    next.merge(*assessment);
                }
            }
            if resolved.get(name) != Some(&next) {
                resolved.insert(name.clone(), next);
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    resolved
}

fn writer_sql_local_aliases<'a>(
    syntax: &syn::File,
    helper_names: impl Iterator<Item = &'a String>,
) -> BTreeMap<String, String> {
    fn collect(tree: &syn::UseTree, prefix: &mut Vec<String>, imports: &mut Vec<WriterSqlImport>) {
        match tree {
            syn::UseTree::Path(path) => {
                prefix.push(path.ident.to_string());
                collect(&path.tree, prefix, imports);
                prefix.pop();
            }
            syn::UseTree::Name(name) => imports.push(WriterSqlImport {
                module: prefix.join("::"),
                item: name.ident.to_string(),
                local: name.ident.to_string(),
            }),
            syn::UseTree::Rename(rename) => imports.push(WriterSqlImport {
                module: prefix.join("::"),
                item: rename.ident.to_string(),
                local: rename.rename.to_string(),
            }),
            syn::UseTree::Group(group) => {
                for tree in &group.items {
                    collect(tree, prefix, imports);
                }
            }
            syn::UseTree::Glob(_) => {}
        }
    }

    let helper_names = helper_names.cloned().collect::<Vec<_>>();
    let mut imports = Vec::new();
    for item in &syntax.items {
        if let syn::Item::Use(item_use) = item {
            collect(&item_use.tree, &mut Vec::new(), &mut imports);
        }
    }
    let mut aliases = BTreeMap::new();
    for import in imports {
        if matches!(
            import.module.split("::").next(),
            Some("crate" | "self" | "super")
        ) {
            continue;
        }
        let target = if import.module.is_empty() {
            import.item
        } else {
            format!("{}::{}", import.module, import.item)
        };
        for helper in &helper_names {
            if helper == &target {
                aliases.insert(import.local.clone(), target.clone());
            } else if let Some(suffix) = helper.strip_prefix(&format!("{target}::")) {
                aliases.insert(format!("{}::{suffix}", import.local), helper.clone());
            }
        }
    }
    aliases
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct WriterSqlImport {
    module: String,
    item: String,
    local: String,
}

fn workspace_writer_sql_helpers(
    files: &[(String, String)],
) -> BTreeMap<String, BTreeMap<String, WriterSqlAssessment>> {
    struct FileContext {
        syntax: syn::File,
        aliases: BTreeSet<String>,
        constants: BTreeMap<String, String>,
        imports: Vec<WriterSqlImport>,
    }

    let contexts = files
        .iter()
        .filter_map(|(rel, content)| {
            let stripped = strip_rust_comment_lines(&strip_cfg_test_modules(content));
            let syntax = syn::parse_file(&stripped).ok()?;
            let aliases = sqlx_query_aliases(&syntax);
            let constants = sql_string_constants(&syntax);
            let imports = writer_sql_imports(&syntax);
            Some((
                rel.clone(),
                FileContext {
                    syntax,
                    aliases,
                    constants,
                    imports,
                },
            ))
        })
        .collect::<BTreeMap<_, _>>();
    let modules = contexts
        .keys()
        .map(|rel| (rust_module_path(rel), rel.clone()))
        .collect::<BTreeMap<_, _>>();
    let mut resolved: BTreeMap<String, BTreeMap<String, WriterSqlAssessment>> = BTreeMap::new();

    for _ in 0..=contexts.len() {
        let mut next = BTreeMap::new();
        for (rel, context) in &contexts {
            let mut external = BTreeMap::new();
            for import in &context.imports {
                let Some(target_rel) = modules.get(&import.module) else {
                    continue;
                };
                let Some(targets) = resolved.get(target_rel) else {
                    continue;
                };
                if let Some(assessment) = targets.get(&import.item) {
                    external.insert(import.local.clone(), *assessment);
                }
                let prefix = format!("{}::", import.item);
                for (target, assessment) in targets {
                    if let Some(suffix) = target.strip_prefix(&prefix) {
                        external.insert(format!("{}::{suffix}", import.local), *assessment);
                    }
                }
            }
            next.insert(
                rel.clone(),
                writer_sql_helper_assessments(
                    &context.syntax,
                    &context.aliases,
                    &context.constants,
                    &external,
                ),
            );
        }
        if next == resolved {
            return next;
        }
        resolved = next;
    }
    resolved
}

fn rust_module_path(rel: &str) -> String {
    let without_suffix = rel.strip_suffix(".rs").unwrap_or(rel);
    without_suffix
        .strip_suffix("/mod")
        .unwrap_or(without_suffix)
        .replace('/', "::")
}

fn writer_sql_imports(syntax: &syn::File) -> Vec<WriterSqlImport> {
    fn collect(tree: &syn::UseTree, prefix: &mut Vec<String>, imports: &mut Vec<WriterSqlImport>) {
        match tree {
            syn::UseTree::Path(path) => {
                prefix.push(path.ident.to_string());
                collect(&path.tree, prefix, imports);
                prefix.pop();
            }
            syn::UseTree::Name(name) => {
                record_import(
                    prefix,
                    name.ident.to_string(),
                    name.ident.to_string(),
                    imports,
                );
            }
            syn::UseTree::Rename(rename) => {
                record_import(
                    prefix,
                    rename.ident.to_string(),
                    rename.rename.to_string(),
                    imports,
                );
            }
            syn::UseTree::Group(group) => {
                for tree in &group.items {
                    collect(tree, prefix, imports);
                }
            }
            syn::UseTree::Glob(_) => {}
        }
    }

    fn record_import(
        prefix: &[String],
        item: String,
        local: String,
        imports: &mut Vec<WriterSqlImport>,
    ) {
        if prefix.first().is_none_or(|root| root != "crate") || prefix.len() < 2 {
            return;
        }
        imports.push(WriterSqlImport {
            module: prefix[1..].join("::"),
            item,
            local,
        });
    }

    let mut imports = Vec::new();
    for item in &syntax.items {
        if let syn::Item::Use(item_use) = item {
            collect(&item_use.tree, &mut Vec::new(), &mut imports);
        }
    }
    imports
}

fn closure_body_and_bindings(expression: &syn::Expr) -> Option<(&syn::Expr, BTreeSet<String>)> {
    match expression {
        syn::Expr::Closure(closure) => {
            let mut bindings = BTreeSet::new();
            for input in &closure.inputs {
                collect_pattern_bindings(input, &mut bindings);
            }
            Some((&closure.body, bindings))
        }
        syn::Expr::Paren(paren) => closure_body_and_bindings(&paren.expr),
        syn::Expr::Group(group) => closure_body_and_bindings(&group.expr),
        _ => None,
    }
}

fn visit_transaction_future_root(
    visitor: &mut WriterSqlEvidenceVisitor<'_>,
    expression: &syn::Expr,
) {
    if let syn::Expr::Block(block) = expression {
        if let Some((tail, prefix)) = block.block.stmts.split_last() {
            for statement in prefix {
                syn::visit::Visit::visit_stmt(visitor, statement);
            }
            if let syn::Stmt::Expr(tail, _) = tail {
                visit_transaction_future_root(visitor, tail);
            } else {
                syn::visit::Visit::visit_stmt(visitor, tail);
            }
        }
    } else if let syn::Expr::Cast(cast) = expression {
        visit_transaction_future_root(visitor, &cast.expr);
    } else if let syn::Expr::Paren(paren) = expression {
        visit_transaction_future_root(visitor, &paren.expr);
    } else if let syn::Expr::Group(group) = expression {
        visit_transaction_future_root(visitor, &group.expr);
    } else if let syn::Expr::Call(call) = expression
        && matches!(call.func.as_ref(), syn::Expr::Path(path) if path.path.segments.iter().map(|segment| segment.ident.to_string()).collect::<Vec<_>>() == ["Box", "pin"])
        && let Some(future) = call.args.first()
    {
        visit_transaction_future_root(visitor, future);
    } else if let syn::Expr::Async(async_expression) = expression {
        syn::visit::Visit::visit_block(visitor, &async_expression.block);
    } else {
        syn::visit::Visit::visit_expr(visitor, expression);
    }
}

fn attributes_are_test_only(attributes: &[syn::Attribute]) -> bool {
    attributes.iter().any(|attribute| {
        attribute.path().is_ident("cfg") && compact_tokens(&attribute.meta).contains("test")
    })
}

fn collect_pattern_bindings(pattern: &syn::Pat, bindings: &mut BTreeSet<String>) {
    match pattern {
        syn::Pat::Ident(ident) => {
            bindings.insert(ident.ident.to_string());
        }
        syn::Pat::Type(typed) => collect_pattern_bindings(&typed.pat, bindings),
        syn::Pat::Reference(reference) => collect_pattern_bindings(&reference.pat, bindings),
        syn::Pat::Paren(paren) => collect_pattern_bindings(&paren.pat, bindings),
        syn::Pat::Tuple(tuple) => {
            for element in &tuple.elems {
                collect_pattern_bindings(element, bindings);
            }
        }
        _ => {}
    }
}

fn signature_capability_bindings(signature: &syn::Signature) -> BTreeSet<String> {
    signature
        .inputs
        .iter()
        .filter_map(|argument| {
            let syn::FnArg::Typed(typed) = argument else {
                return None;
            };
            if !is_postgres_transaction_capability_type(&typed.ty) {
                return None;
            }
            let syn::Pat::Ident(ident) = typed.pat.as_ref() else {
                return None;
            };
            Some(ident.ident.to_string())
        })
        .collect()
}

fn capability_callback_bindings(signature: &syn::Signature) -> BTreeSet<String> {
    fn is_capability_callback_bound(
        bounds: &syn::punctuated::Punctuated<syn::TypeParamBound, syn::Token![+]>,
    ) -> bool {
        bounds.iter().any(|bound| {
            let syn::TypeParamBound::Trait(trait_bound) = bound else {
                return false;
            };
            trait_bound
                .path
                .segments
                .last()
                .is_some_and(|segment| segment.ident == "FnOnce")
                && compact_tokens(bound).contains("TxCapability")
        })
    }

    let mut callback_types = signature
        .generics
        .params
        .iter()
        .filter_map(|parameter| {
            let syn::GenericParam::Type(parameter) = parameter else {
                return None;
            };
            is_capability_callback_bound(&parameter.bounds).then(|| parameter.ident.to_string())
        })
        .collect::<BTreeSet<_>>();
    if let Some(where_clause) = &signature.generics.where_clause {
        for predicate in &where_clause.predicates {
            let syn::WherePredicate::Type(predicate) = predicate else {
                continue;
            };
            let syn::Type::Path(bounded) = &predicate.bounded_ty else {
                continue;
            };
            if bounded.path.segments.len() == 1
                && is_capability_callback_bound(&predicate.bounds)
                && let Some(segment) = bounded.path.segments.last()
            {
                callback_types.insert(segment.ident.to_string());
            }
        }
    }

    signature
        .inputs
        .iter()
        .filter_map(|argument| {
            let syn::FnArg::Typed(argument) = argument else {
                return None;
            };
            let syn::Pat::Ident(binding) = argument.pat.as_ref() else {
                return None;
            };
            let direct = compact_tokens(&argument.ty).contains("FnOnce")
                && compact_tokens(&argument.ty).contains("TxCapability");
            let generic = matches!(argument.ty.as_ref(), syn::Type::Path(path) if path.path.segments.len() == 1 && path.path.segments.last().is_some_and(|segment| callback_types.contains(&segment.ident.to_string())));
            (direct || generic).then(|| binding.ident.to_string())
        })
        .collect()
}

fn is_postgres_transaction_capability_type(ty: &syn::Type) -> bool {
    matches!(
        type_last_ident(ty).as_deref(),
        Some("PgConnection" | "Transaction" | "TxCapability" | "PgWriteTx")
    )
}

fn expression_is_capability_value(expression: &syn::Expr, bindings: &BTreeSet<String>) -> bool {
    match expression {
        syn::Expr::Path(path) if path.path.segments.len() == 1 => path
            .path
            .segments
            .last()
            .is_some_and(|segment| bindings.contains(&segment.ident.to_string())),
        syn::Expr::Reference(reference) => {
            expression_is_capability_value(&reference.expr, bindings)
        }
        syn::Expr::Unary(unary) if matches!(unary.op, syn::UnOp::Deref(_)) => {
            expression_is_capability_value(&unary.expr, bindings)
        }
        syn::Expr::Cast(cast) => expression_is_capability_value(&cast.expr, bindings),
        syn::Expr::Paren(paren) => expression_is_capability_value(&paren.expr, bindings),
        syn::Expr::Group(group) => expression_is_capability_value(&group.expr, bindings),
        syn::Expr::MethodCall(method) if method.method == "conn" => {
            expression_is_capability_value(&method.receiver, bindings)
        }
        _ => false,
    }
}

fn expression_is_self(expression: &syn::Expr) -> bool {
    matches!(expression, syn::Expr::Path(path) if path.path.is_ident("self"))
}

fn qualify_rust_identity(module: Option<&str>, identity: &str) -> String {
    module.map_or_else(
        || identity.to_string(),
        |module| format!("{module}::{identity}"),
    )
}

fn callable_identity(
    path: &syn::Path,
    owner: Option<&str>,
    module: Option<&str>,
) -> Option<String> {
    let segments = path.segments.iter().collect::<Vec<_>>();
    match segments.as_slice() {
        [name] => Some(qualify_rust_identity(module, &name.ident.to_string())),
        [qualifier, name] if qualifier.ident == "Self" => {
            owner.map(|owner| format!("{owner}::{}", name.ident))
        }
        [qualifier, name] => Some(qualify_rust_identity(
            module,
            &format!("{}::{}", qualifier.ident, name.ident),
        )),
        _ => None,
    }
}

fn sql_string_constants(syntax: &syn::File) -> BTreeMap<String, String> {
    syntax
        .items
        .iter()
        .filter_map(|item| {
            let syn::Item::Const(item_const) = item else {
                return None;
            };
            let syn::Expr::Lit(syn::ExprLit {
                lit: syn::Lit::Str(literal),
                ..
            }) = item_const.expr.as_ref()
            else {
                return None;
            };
            Some((item_const.ident.to_string(), literal.value()))
        })
        .collect()
}

fn resolve_static_sql_expr(
    expression: &syn::Expr,
    constants: &BTreeMap<String, String>,
) -> Option<String> {
    match expression {
        syn::Expr::Lit(syn::ExprLit {
            lit: syn::Lit::Str(literal),
            ..
        }) => Some(literal.value()),
        syn::Expr::Path(path) if path.path.segments.len() == 1 => path
            .path
            .segments
            .last()
            .and_then(|segment| constants.get(&segment.ident.to_string()))
            .cloned(),
        syn::Expr::Macro(expression)
            if expression
                .mac
                .path
                .segments
                .last()
                .is_some_and(|segment| segment.ident == "format") =>
        {
            use syn::parse::Parser as _;

            let arguments =
                syn::punctuated::Punctuated::<syn::Expr, syn::Token![,]>::parse_terminated
                    .parse2(expression.mac.tokens.clone())
                    .ok()?;
            if arguments.len() != 1 {
                return None;
            }
            let syn::Expr::Lit(syn::ExprLit {
                lit: syn::Lit::Str(template),
                ..
            }) = arguments.first()?
            else {
                return None;
            };
            expand_static_format_captures(&template.value(), constants)
        }
        syn::Expr::Reference(reference) => resolve_static_sql_expr(&reference.expr, constants),
        syn::Expr::Paren(paren) => resolve_static_sql_expr(&paren.expr, constants),
        syn::Expr::Group(group) => resolve_static_sql_expr(&group.expr, constants),
        _ => None,
    }
}

fn expand_static_format_captures(
    template: &str,
    constants: &BTreeMap<String, String>,
) -> Option<String> {
    let characters = template.chars().collect::<Vec<_>>();
    let mut expanded = String::with_capacity(template.len());
    let mut index = 0;
    while index < characters.len() {
        match characters[index] {
            '{' if characters.get(index + 1) == Some(&'{') => {
                expanded.push('{');
                index += 2;
            }
            '{' => {
                let close = characters[index + 1..]
                    .iter()
                    .position(|item| *item == '}')?
                    + index
                    + 1;
                let name = characters[index + 1..close].iter().collect::<String>();
                if name.is_empty()
                    || !name
                        .chars()
                        .all(|character| character.is_ascii_alphanumeric() || character == '_')
                {
                    return None;
                }
                expanded.push_str(constants.get(&name)?);
                index = close + 1;
            }
            '}' if characters.get(index + 1) == Some(&'}') => {
                expanded.push('}');
                index += 2;
            }
            '}' => return None,
            character => {
                expanded.push(character);
                index += 1;
            }
        }
    }
    Some(expanded)
}

fn sqlx_query_aliases(syntax: &syn::File) -> BTreeSet<String> {
    fn collect(tree: &syn::UseTree, prefix: &mut Vec<String>, aliases: &mut BTreeSet<String>) {
        match tree {
            syn::UseTree::Path(path) => {
                prefix.push(path.ident.to_string());
                collect(&path.tree, prefix, aliases);
                prefix.pop();
            }
            syn::UseTree::Name(name)
                if prefix.as_slice() == ["sqlx"] && sqlx_query_name(&name.ident.to_string()) =>
            {
                aliases.insert(name.ident.to_string());
            }
            syn::UseTree::Rename(rename)
                if prefix.as_slice() == ["sqlx"] && sqlx_query_name(&rename.ident.to_string()) =>
            {
                aliases.insert(rename.rename.to_string());
            }
            syn::UseTree::Rename(rename) if prefix.is_empty() && rename.ident == "sqlx" => {
                aliases.insert(format!("@crate:{}", rename.rename));
            }
            syn::UseTree::Group(group) => {
                for item in &group.items {
                    collect(item, prefix, aliases);
                }
            }
            syn::UseTree::Glob(_) if prefix.as_slice() == ["sqlx"] => {
                aliases.extend(
                    ["query", "query_as", "query_scalar", "raw_sql"]
                        .into_iter()
                        .map(str::to_string),
                );
            }
            _ => {}
        }
    }

    let mut aliases = BTreeSet::new();
    for item in &syntax.items {
        if let syn::Item::Use(item_use) = item {
            collect(&item_use.tree, &mut Vec::new(), &mut aliases);
        } else if let syn::Item::ExternCrate(extern_crate) = item
            && extern_crate.ident == "sqlx"
            && let Some((_, rename)) = &extern_crate.rename
        {
            aliases.insert(format!("@crate:{rename}"));
        }
    }
    aliases
}

fn sqlx_query_name(name: &str) -> bool {
    matches!(name, "query" | "query_as" | "query_scalar" | "raw_sql")
}

fn is_sqlx_query_path(path: &syn::Path, aliases: &BTreeSet<String>) -> bool {
    let segments = path.segments.iter().collect::<Vec<_>>();
    matches!(segments.as_slice(), [root, query] if (root.ident == "sqlx" || aliases.contains(&format!("@crate:{}", root.ident))) && sqlx_query_name(&query.ident.to_string()))
        || matches!(segments.as_slice(), [query] if aliases.contains(&query.ident.to_string()))
}

fn sqlx_query_call_site(
    call: &syn::ExprCall,
    aliases: &BTreeSet<String>,
    constants: &BTreeMap<String, String>,
) -> Option<SqlQuerySite> {
    let syn::Expr::Path(function) = call.func.as_ref() else {
        return None;
    };
    if !is_sqlx_query_path(&function.path, aliases) {
        return None;
    }
    let start = function.path.span().start();
    let sql = call
        .args
        .first()
        .and_then(|argument| resolve_static_sql_expr(argument, constants));
    Some(SqlQuerySite {
        line: start.line,
        column: start.column,
        sql,
    })
}

fn sqlx_query_macro_site(
    expression: &syn::ExprMacro,
    aliases: &BTreeSet<String>,
    constants: &BTreeMap<String, String>,
) -> Option<SqlQuerySite> {
    use syn::parse::Parser as _;

    if !is_sqlx_query_path(&expression.mac.path, aliases) {
        return None;
    }
    let start = expression.mac.path.span().start();
    let sql = syn::punctuated::Punctuated::<syn::Expr, syn::Token![,]>::parse_terminated
        .parse2(expression.mac.tokens.clone())
        .ok()
        .and_then(|arguments| {
            arguments
                .first()
                .and_then(|argument| resolve_static_sql_expr(argument, constants))
        });
    Some(SqlQuerySite {
        line: start.line,
        column: start.column,
        sql,
    })
}

fn sqlx_query_site_in_receiver(
    expression: &syn::Expr,
    aliases: &BTreeSet<String>,
    constants: &BTreeMap<String, String>,
) -> Option<SqlQuerySite> {
    match expression {
        syn::Expr::Call(call) => sqlx_query_call_site(call, aliases, constants),
        syn::Expr::Macro(expression) => sqlx_query_macro_site(expression, aliases, constants),
        syn::Expr::MethodCall(method) => {
            sqlx_query_site_in_receiver(&method.receiver, aliases, constants)
        }
        syn::Expr::Await(awaited) => sqlx_query_site_in_receiver(&awaited.base, aliases, constants),
        syn::Expr::Try(tried) => sqlx_query_site_in_receiver(&tried.expr, aliases, constants),
        syn::Expr::Paren(paren) => sqlx_query_site_in_receiver(&paren.expr, aliases, constants),
        syn::Expr::Group(group) => sqlx_query_site_in_receiver(&group.expr, aliases, constants),
        syn::Expr::Reference(reference) => {
            sqlx_query_site_in_receiver(&reference.expr, aliases, constants)
        }
        _ => None,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WriterSqlKind {
    PlainRead,
    LockingRead,
    Mutation,
    Unclassified,
}

fn classify_writer_sql(sql: &str) -> WriterSqlKind {
    let Some(mut tokens) = sql_tokens(sql) else {
        return WriterSqlKind::Unclassified;
    };
    while tokens.last().is_some_and(|token| token == ";") {
        tokens.pop();
    }
    if tokens.is_empty() || tokens.iter().any(|token| token == ";") {
        return WriterSqlKind::Unclassified;
    }
    let main = if tokens[0] == "WITH" {
        with_main_statement(&tokens)
    } else {
        Some(tokens[0].as_str())
    };
    match main {
        Some("INSERT" | "UPDATE" | "DELETE" | "TRUNCATE" | "MERGE") => WriterSqlKind::Mutation,
        Some("SELECT") if sql_has_mutating_function_evidence(&tokens) => WriterSqlKind::Mutation,
        Some("SELECT") if sql_has_lock_evidence(&tokens) => WriterSqlKind::LockingRead,
        Some("SELECT") => WriterSqlKind::PlainRead,
        _ => WriterSqlKind::Unclassified,
    }
}

fn sql_has_mutating_function_evidence(tokens: &[String]) -> bool {
    const FUNCTIONS: &[&str] = &[
        "RSS_OUTBOX_MARK_DLX",
        "RSS_OUTBOX_SETTLE_PUBLISHED",
        "RSS_OUTBOX_SETTLE_RETRY",
    ];
    tokens.windows(2).any(|pair| {
        matches!(pair, [function, open] if FUNCTIONS.contains(&function.as_str()) && open == "(")
    })
}

fn with_main_statement(tokens: &[String]) -> Option<&str> {
    let mut depth = 0_i32;
    for token in &tokens[1..] {
        match token.as_str() {
            "(" => depth += 1,
            ")" => depth -= 1,
            "SELECT" | "INSERT" | "UPDATE" | "DELETE" | "MERGE" if depth == 0 => {
                return Some(token);
            }
            _ => {}
        }
        if depth < 0 {
            return None;
        }
    }
    None
}

fn sql_has_lock_evidence(tokens: &[String]) -> bool {
    tokens.windows(2).any(|pair| {
        matches!(pair, [function, open] if matches!(function.as_str(), "PG_ADVISORY_LOCK" | "PG_ADVISORY_XACT_LOCK") && open == "(")
    }) || tokens.windows(2).any(|pair| {
        matches!(pair, [first, second] if first == "FOR" && matches!(second.as_str(), "UPDATE" | "SHARE"))
    }) || tokens.windows(4).any(|parts| {
        matches!(parts, [for_kw, no, key, update] if for_kw == "FOR" && no == "NO" && key == "KEY" && update == "UPDATE")
    }) || tokens.windows(3).any(|parts| {
        matches!(parts, [for_kw, key, share] if for_kw == "FOR" && key == "KEY" && share == "SHARE")
    })
}

fn skip_nested_sql_comment(bytes: &[u8], mut index: usize) -> Option<usize> {
    index += 2;
    let mut depth = 1_usize;
    while index < bytes.len() && depth > 0 {
        if bytes.get(index..index + 2) == Some(b"/*") {
            depth += 1;
            index += 2;
        } else if bytes.get(index..index + 2) == Some(b"*/") {
            depth -= 1;
            index += 2;
        } else {
            index += 1;
        }
    }
    (depth == 0).then_some(index)
}

fn skip_sql_quoted(bytes: &[u8], mut index: usize, quote: u8) -> Option<usize> {
    index += 1;
    loop {
        let byte = *bytes.get(index)?;
        index += 1;
        if byte == quote {
            if bytes.get(index) == Some(&quote) {
                index += 1;
            } else {
                return Some(index);
            }
        }
    }
}

fn read_sql_quoted_identifier(sql: &str, mut index: usize) -> Option<(usize, String)> {
    let bytes = sql.as_bytes();
    index += 1;
    let mut identifier = String::new();
    loop {
        let byte = *bytes.get(index)?;
        index += 1;
        if byte == b'"' {
            if bytes.get(index) == Some(&b'"') {
                identifier.push('"');
                index += 1;
            } else {
                return Some((index, identifier.to_ascii_uppercase()));
            }
        } else {
            identifier.push(byte as char);
        }
    }
}

fn skip_sql_dollar_quote(sql: &str, index: usize) -> Option<usize> {
    let bytes = sql.as_bytes();
    let tag_end = bytes[index + 1..]
        .iter()
        .position(|byte| *byte == b'$')
        .map(|offset| index + offset + 1);
    let Some(tag_end) = tag_end.filter(|tag_end| {
        bytes[index + 1..*tag_end]
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
    }) else {
        return Some(index + 1);
    };
    let delimiter = &sql[index..=tag_end];
    let body_start = tag_end + 1;
    let close = sql[body_start..].find(delimiter)?;
    Some(body_start + close + delimiter.len())
}

fn sql_tokens(sql: &str) -> Option<Vec<String>> {
    let bytes = sql.as_bytes();
    let mut tokens = Vec::new();
    let mut index = 0_usize;
    while index < bytes.len() {
        match bytes[index] {
            byte if byte.is_ascii_whitespace() => index += 1,
            b'-' if bytes.get(index + 1) == Some(&b'-') => {
                index += 2;
                while index < bytes.len() && bytes[index] != b'\n' {
                    index += 1;
                }
            }
            b'/' if bytes.get(index + 1) == Some(&b'*') => {
                index = skip_nested_sql_comment(bytes, index)?;
            }
            b'\'' => {
                index = skip_sql_quoted(bytes, index, b'\'')?;
            }
            b'"' => {
                let (next, identifier) = read_sql_quoted_identifier(sql, index)?;
                tokens.push(identifier);
                index = next;
            }
            b'$' => {
                index = skip_sql_dollar_quote(sql, index)?;
            }
            b'(' | b')' | b',' | b';' | b'=' => {
                tokens.push((bytes[index] as char).to_string());
                index += 1;
            }
            byte if byte.is_ascii_alphabetic() || byte == b'_' => {
                let start = index;
                index += 1;
                while index < bytes.len()
                    && (bytes[index].is_ascii_alphanumeric()
                        || matches!(bytes[index], b'_' | b'$' | b'.'))
                {
                    index += 1;
                }
                tokens.push(sql[start..index].to_ascii_uppercase());
            }
            _ => index += 1,
        }
    }
    Some(tokens)
}

fn self_field_name(expr: &syn::Expr) -> Option<String> {
    let syn::Expr::Field(field) = expr else {
        return None;
    };
    let syn::Expr::Path(base) = field.base.as_ref() else {
        return None;
    };
    if !base.path.is_ident("self") {
        return None;
    }
    match &field.member {
        syn::Member::Named(name) => Some(name.to_string()),
        syn::Member::Unnamed(_) => None,
    }
}

#[derive(Debug)]
struct RawTenantAccess {
    tables: Vec<String>,
    pattern: String,
    line: usize,
}

#[derive(Debug)]
struct RawPoolFieldAccess {
    pattern: String,
    line: usize,
    owner: Option<String>,
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
                && let Some(exception) = allowed_fault_matrix_outbox_insert(
                    rel,
                    enclosing_function_name(content, idx),
                    window,
                )
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
                if let Some(exception) = allowed_site_exception(
                    rel,
                    enclosing_function_name(content, idx),
                    &pattern,
                    &tables,
                    window,
                ) {
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
    let Ok(syntax) = syn::parse_file(content) else {
        return out;
    };
    for item in &syntax.items {
        let syn::Item::Struct(item_struct) = item else {
            continue;
        };
        for field in &item_struct.fields {
            use syn::spanned::Spanned as _;

            let Some(raw_type) = raw_store_type(&field.ty) else {
                continue;
            };
            out.push(RawPoolFieldAccess {
                pattern: raw_type.to_owned(),
                line: field.span().start().line,
                owner: Some(item_struct.ident.to_string()),
            });
        }
    }
    out
}

fn raw_store_type(ty: &syn::Type) -> Option<&'static str> {
    match type_last_ident(ty).as_deref() {
        Some("PgPool") => Some("PgPool"),
        Some("PgStore") => Some("PgStore"),
        _ => nested_type(ty).and_then(raw_store_type),
    }
}

fn allowed_site_exception(
    rel: &str,
    symbol: Option<&str>,
    pattern: &str,
    tables: &[String],
    window: &str,
) -> Option<&'static str> {
    if rel == "outbox.rs"
        && symbol == Some("fault_matrix_claim_exact")
        && tables == ["outbox"]
        && ((pattern == "pool.begin().await" && window.contains("owner_pool.begin().await"))
            || (pattern.starts_with(".fetch_optional(&mut *tx")
                && window.contains("from claimed")
                && window.contains(".bind(self.relay_budget.required_budget_millis())")))
    {
        return Some(FAULT_MATRIX_EXACT_OUTBOX_CLAIM);
    }
    if let Some(exception) = allowed_fault_matrix_raw_tenant_site(rel, symbol, tables, window) {
        return Some(exception);
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
    symbol: Option<&str>,
    tables: &[String],
    window: &str,
) -> Option<&'static str> {
    if rel != FAULT_MATRIX_FILE {
        return None;
    }
    if tables == ["outbox"]
        && symbol == Some("seed_session_created")
        && window.contains("insert into outbox (")
        && window.contains(".bind(input.idem_key.as_str())")
        && window.contains(".bind(payload)")
        && window.contains("session_created_fact.contract().schema_hash()")
        && window.contains(".execute(pool)")
    {
        return Some(FAULT_MATRIX_SEED_SESSION_CREATED);
    }
    if tables == ["outbox"]
        && window.contains("insert into outbox (")
        && window.contains("decode('70', 'hex')")
        && window.contains(".execute(pool)")
    {
        return Some(FAULT_MATRIX_SEED_OUTBOX);
    }
    if tables == ["outbox"]
        && symbol == Some("make_session_created_retry_due")
        && window.contains("update outbox set retry_after = clock_timestamp()")
        && window.contains("contract_id = $4 and status = 'pending'")
        && window.contains(".execute(&self.owner_pool)")
    {
        return Some(FAULT_MATRIX_SESSION_RETRY_DUE);
    }
    if tables == ["outbox"]
        && symbol == Some("run_outbox_publish_to_budget")
        && window.contains("update outbox set retry_after = clock_timestamp()")
        && window.contains("event_id = $2 and status = 'pending'")
        && window.contains(".execute(&self.owner_pool)")
    {
        return Some(FAULT_MATRIX_PUBLISH_BUDGET_RETRY_DUE);
    }
    if tables == ["outbox"]
        && symbol == Some("outbox_retry_observation")
        && window.contains("select status, retry_count")
        && window.contains("lease_token is null and lease_until is null")
        && window.contains(".fetch_optional(&self.owner_pool)")
    {
        return Some(FAULT_MATRIX_OUTBOX_RETRY_OBSERVATION);
    }
    if tables == ["command_idempotency_aliases"]
        && symbol == Some("reconcile_dispatch_key_stable")
        && window.contains("select command_id from command_idempotency_aliases")
        && window.contains("alias_digest = $3")
        && window.contains(".fetch_all(&self.owner_pool)")
    {
        return Some(FAULT_MATRIX_RECONCILE_ALIAS_OBSERVATION);
    }
    if tables == ["audit_entries"]
        && window.contains("action = 'identity:login'")
        && window.contains("resource_kind = 'session'")
        && window.contains("resource_id = $2")
        && window.contains(".fetch_one(&self.owner_pool)")
    {
        return Some(FAULT_MATRIX_SESSION_AUDIT_COUNT);
    }
    if tables == ["inbox_receipts"]
        && window.contains("consumer_group = $3")
        && window.contains("contract_id = $5 and status = 'done'")
        && window.contains(".fetch_one(&self.owner_pool)")
    {
        return Some(FAULT_MATRIX_SESSION_INBOX_DONE_COUNT);
    }
    if tables == ["outbox"]
        && window.contains("update outbox set updated_at = clock_timestamp()")
        && window.contains("returning (extract(epoch from lease_until)")
        && window.contains(".fetch_one(&self.owner_pool)")
    {
        return Some(FAULT_MATRIX_EXPIRED_DEADLINE);
    }
    if tables == ["outbox"]
        && window.contains("select status from outbox")
        && window.contains("domain = $3 and contract_id = $4")
        && window.contains(".fetch_one(&self.owner_pool)")
    {
        return Some(FAULT_MATRIX_OUTBOX_STATUS_OBSERVATION);
    }
    if tables == ["outbox"]
        && window.contains("published_at is null and dlx_at is null")
        && window.contains("domain = $3 and contract_id = $4")
        && window.contains(".fetch_one(pool)")
    {
        return Some(FAULT_MATRIX_TERMINAL_OBSERVATION);
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
        && symbol == Some("age_outbox_publishing")
        && window.contains("update outbox")
        && window.contains("set updated_at = clock_timestamp()")
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

fn allowed_fault_matrix_outbox_insert(
    rel: &str,
    symbol: Option<&str>,
    window: &str,
) -> Option<&'static str> {
    if rel == FAULT_MATRIX_FILE
        && symbol == Some("seed_session_created")
        && window.contains("insert into outbox (")
        && window.contains(".bind(input.idem_key.as_str())")
        && window.contains(".bind(payload)")
        && window.contains("session_created_fact.contract().schema_hash()")
        && window.contains(".execute(pool)")
    {
        return Some(FAULT_MATRIX_SEED_SESSION_CREATED);
    }
    if rel == FAULT_MATRIX_FILE
        && window.contains("insert into outbox (")
        && window.contains("decode('70', 'hex')")
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
    if tenant_hits.is_empty() || hits.is_empty() || is_exception || is_cotx_funnel(rel) {
        return Vec::new();
    }
    hits.iter()
        .filter(|hit| {
            !(rel == "config_repo.rs"
                && hit.pattern == "PgStore"
                && hit.owner.as_deref() == Some("PgConfigValueMaintenance"))
        })
        .map(|hit| {
            finding(
                Rule::RawTenantPoolField,
                site_subject(rel, hit.line),
                format!(
                    "tenant tables {:?} share a file with raw capability field {:?}; tenant repositories must store PgTenantReadPool/PgTenantWritePool",
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
        "bundle.rs"
            | "pool.rs"
            | "readiness.rs"
            | "migrator.rs"
            | "auth_audit_sink.rs"
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

    if let Some((_, outbox)) = files.iter().find(|(rel, _)| rel == "outbox.rs") {
        let outbox = strip_rust_comment_lines(&strip_cfg_test_modules(outbox)).to_lowercase();
        if ![
            "#[cfg(feature = \"fault-matrix-test-support\")]",
            "fn fault_matrix_claim_exact",
            "owner_pool.begin().await",
            "with claim_clock as materialized",
            "from claimed",
            ".fetch_optional(&mut *tx)",
        ]
        .iter()
        .all(|needle| outbox.contains(needle))
        {
            findings.push(finding(
                Rule::StaleException,
                FAULT_MATRIX_EXACT_OUTBOX_CLAIM,
                "fault_matrix exact-claim raw-access exception target is absent or no longer exact",
            ));
        }
    }

    let content = strip_rust_comment_lines(&strip_cfg_test_modules(fault_matrix)).to_lowercase();
    for (name, needles) in [
        (FAULT_MATRIX_OWNER_POOL, &["owner_pool: pgpool"][..]),
        (
            FAULT_MATRIX_SEED_OUTBOX,
            &[
                "insert into outbox (",
                "decode('70', 'hex')",
                ".execute(pool)",
            ][..],
        ),
        (
            FAULT_MATRIX_SEED_SESSION_CREATED,
            &[
                "insert into outbox (",
                "serde_json::to_vec(&input.payload)",
                ".bind(input.idem_key.as_str())",
                ".bind(payload)",
                "session_created_fact.contract().schema_hash()",
                ".execute(pool)",
            ][..],
        ),
        (
            FAULT_MATRIX_SESSION_RETRY_DUE,
            &[
                "update outbox set retry_after = clock_timestamp()",
                "contract_id = $4 and status = 'pending'",
                ".execute(&self.owner_pool)",
            ][..],
        ),
        (
            FAULT_MATRIX_PUBLISH_BUDGET_RETRY_DUE,
            &[
                "fn run_outbox_publish_to_budget",
                "update outbox set retry_after = clock_timestamp()",
                "event_id = $2 and status = 'pending'",
                ".execute(&self.owner_pool)",
            ][..],
        ),
        (
            FAULT_MATRIX_OUTBOX_RETRY_OBSERVATION,
            &[
                "fn outbox_retry_observation",
                "select status, retry_count",
                "lease_token is null and lease_until is null",
                ".fetch_optional(&self.owner_pool)",
            ][..],
        ),
        (
            FAULT_MATRIX_RECONCILE_ALIAS_OBSERVATION,
            &[
                "fn reconcile_dispatch_key_stable",
                "select command_id from command_idempotency_aliases",
                "alias_digest = $3",
                ".fetch_all(&self.owner_pool)",
            ][..],
        ),
        (
            FAULT_MATRIX_SESSION_AUDIT_COUNT,
            &[
                "from audit_entries",
                "action = 'identity:login'",
                "resource_kind = 'session'",
                "resource_id = $2",
                ".fetch_one(&self.owner_pool)",
            ][..],
        ),
        (
            FAULT_MATRIX_SESSION_INBOX_DONE_COUNT,
            &[
                "from inbox_receipts",
                "consumer_group = $3",
                "contract_id = $5 and status = 'done'",
                ".fetch_one(&self.owner_pool)",
            ][..],
        ),
        (
            FAULT_MATRIX_EXPIRED_DEADLINE,
            &[
                "update outbox set updated_at = clock_timestamp()",
                "returning (extract(epoch from lease_until)",
                ".fetch_one(&self.owner_pool)",
            ][..],
        ),
        (
            FAULT_MATRIX_OUTBOX_STATUS_OBSERVATION,
            &[
                "select status from outbox",
                "domain = $3 and contract_id = $4",
                ".fetch_one(&self.owner_pool)",
            ][..],
        ),
        (
            FAULT_MATRIX_TERMINAL_OBSERVATION,
            &[
                "published_at is null and dlx_at is null",
                "domain = $3 and contract_id = $4",
                ".fetch_one(pool)",
            ][..],
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
            FAULT_MATRIX_AGE_OUTBOX_PUBLISHING,
            &[
                "fn age_outbox_publishing",
                "update outbox",
                "set updated_at = clock_timestamp()",
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

fn fault_matrix_terminal_bypass_findings(files: &[(String, String)]) -> Vec<Finding> {
    use syn::visit::Visit as _;

    let Some((_, fault_matrix)) = files.iter().find(|(rel, _)| rel == FAULT_MATRIX_FILE) else {
        return Vec::new();
    };
    let production = strip_cfg_test_modules(fault_matrix);
    let Ok(syntax) = syn::parse_file(&production) else {
        return vec![finding(
            Rule::FaultMatrixTerminalBypass,
            FAULT_MATRIX_FILE,
            "fault_matrix production AST could not be parsed; terminal-state SQL check fails closed",
        )];
    };
    let aliases = sqlx_query_aliases(&syntax);
    let constants = sql_string_constants(&syntax);
    struct QueryVisitor<'a> {
        aliases: &'a BTreeSet<String>,
        constants: &'a BTreeMap<String, String>,
        sites: BTreeSet<SqlQuerySite>,
    }
    impl<'ast> syn::visit::Visit<'ast> for QueryVisitor<'_> {
        fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
            if let Some(site) = sqlx_query_call_site(call, self.aliases, self.constants) {
                self.sites.insert(site);
            }
            syn::visit::visit_expr_call(self, call);
        }

        fn visit_expr_macro(&mut self, expression: &'ast syn::ExprMacro) {
            if let Some(site) = sqlx_query_macro_site(expression, self.aliases, self.constants) {
                self.sites.insert(site);
            }
            syn::visit::visit_expr_macro(self, expression);
        }
    }
    let mut visitor = QueryVisitor {
        aliases: &aliases,
        constants: &constants,
        sites: BTreeSet::new(),
    };
    visitor.visit_file(&syntax);
    visitor
        .sites
        .into_iter()
        .filter_map(|site| {
            let detail = match site.sql {
                Some(sql) => fault_matrix_terminal_sql_violation(&sql),
                None => Some(
                    "fault_matrix SQL must be statically resolvable so terminal writes cannot hide behind dynamic text"
                        .to_string(),
                ),
            }?;
            Some(finding(
                Rule::FaultMatrixTerminalBypass,
                site_subject(FAULT_MATRIX_FILE, site.line),
                detail,
            ))
        })
        .collect()
}

fn fault_matrix_terminal_sql_violation(sql: &str) -> Option<String> {
    let tokens = sql_tokens(sql)?;
    for (index, token) in tokens.iter().enumerate() {
        if token == "INSERT"
            && let Some(into) = tokens[index + 1..]
                .iter()
                .position(|candidate| candidate == "INTO")
                .map(|offset| index + offset + 1)
            && tokens[into + 1..]
                .iter()
                .take_while(|candidate| candidate.as_str() != "(")
                .any(|candidate| sql_identifier_is(candidate, "AUDIT_ENTRIES"))
        {
            return Some(
                "fault_matrix must author audit business effects through the production ConsumerTx"
                    .to_string(),
            );
        }
        if token != "UPDATE" {
            continue;
        }
        let Some(set) = tokens[index + 1..]
            .iter()
            .position(|candidate| candidate == "SET")
            .map(|offset| index + offset + 1)
        else {
            return Some("fault_matrix UPDATE SQL could not be classified safely".to_string());
        };
        let target = &tokens[index + 1..set];
        if target
            .iter()
            .any(|candidate| sql_identifier_is(candidate, "OUTBOX"))
            && update_assigns_any(&tokens[set + 1..], &["STATUS", "PUBLISHED_AT", "DLX_AT"])
        {
            return Some(
                "fault_matrix must settle outbox status and terminal timestamps through the production settlement funnel"
                    .to_string(),
            );
        }
        if target
            .iter()
            .any(|candidate| sql_identifier_is(candidate, "INBOX_RECEIPTS"))
            && update_assigns_any(&tokens[set + 1..], &["STATUS"])
        {
            return Some(
                "fault_matrix must commit Inbox Done through the production Inbox/ConsumerTx funnel"
                    .to_string(),
            );
        }
    }
    None
}

fn update_assigns_any(tokens: &[String], forbidden: &[&str]) -> bool {
    let mut depth = 0_i32;
    let mut assignment_start = 0;
    for index in 0..=tokens.len() {
        let token = tokens.get(index).map(String::as_str);
        let boundary = index == tokens.len()
            || (depth == 0 && matches!(token, Some("," | "WHERE" | "RETURNING" | "FROM" | ";")));
        if boundary {
            let assignment = &tokens[assignment_start..index];
            let lhs_end = assignment
                .iter()
                .position(|candidate| candidate == "=")
                .unwrap_or(assignment.len());
            if assignment[..lhs_end].iter().any(|candidate| {
                forbidden
                    .iter()
                    .any(|column| sql_identifier_is(candidate, column))
            }) {
                return true;
            }
            if matches!(token, Some("WHERE" | "RETURNING" | "FROM" | ";") | None) {
                break;
            }
            assignment_start = index + 1;
        }
        match token {
            Some("(") => depth += 1,
            Some(")") => depth -= 1,
            _ => {}
        }
    }
    false
}

fn sql_identifier_is(token: &str, expected: &str) -> bool {
    token.rsplit('.').next() == Some(expected)
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
    let mut pending_attributes = Vec::new();
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
        if !pending_attributes.is_empty() && trimmed.starts_with("#[") {
            pending_attributes.push(line);
            continue;
        }
        if !pending_attributes.is_empty()
            && matches!(trimmed.split_whitespace().next(), Some("mod" | "pub"))
            && (trimmed.starts_with("mod ") || trimmed.starts_with("pub mod "))
        {
            for _ in pending_attributes.drain(..) {
                out.push('\n');
            }
            depth = brace_delta(line);
            skipping = depth > 0;
            out.push('\n');
            continue;
        }
        for attribute in pending_attributes.drain(..) {
            out.push_str(attribute);
            out.push('\n');
        }
        if trimmed.starts_with("#[cfg(") && trimmed.contains("test") {
            pending_attributes.push(line);
            continue;
        }
        out.push_str(line);
        out.push('\n');
    }
    for attribute in pending_attributes {
        out.push_str(attribute);
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

    #[test]
    fn producer_funnel_guard_real_workspace_closes_exact_sites() -> anyhow::Result<()> {
        let root = crate::workspace_root()?;
        let files = load_prod_rs(&root.join("adapters/postgres/src"))?;
        let findings = producer_funnel_findings(&files);
        assert!(findings.is_empty(), "{findings:#?}");
        Ok(())
    }

    #[test]
    fn producer_funnel_guard_rejects_direct_append_bypass_and_missing_callsite() {
        let findings = producer_funnel_findings(&files(&[
            (
                "auth_grant_lifecycle.rs",
                "async fn persist(pool: P) { append_outbox_with_projection(); }",
            ),
            ("identity_security_lifecycle.rs", ""),
            ("policy_repo.rs", ""),
            ("role_binding_lifecycle.rs", ""),
            ("config_repo.rs", ""),
        ]));
        assert!(
            findings
                .iter()
                .any(|finding| finding.rule == Rule::ProducerFunnelBypass),
            "{findings:#?}"
        );
        assert!(
            findings
                .iter()
                .any(|finding| finding.rule == Rule::ProducerFunnelSitesAbsent),
            "{findings:#?}"
        );
    }

    #[test]
    fn producer_funnel_guard_accepts_exact_cross_file_callsite_set() {
        let findings = producer_funnel_findings(&files(&[
            (
                "cotx/mod.rs",
                "struct ProducerInternalsAreTypeCheckedByRust;",
            ),
            (
                "auth_grant_lifecycle.rs",
                "async fn persist(pool: P) { pool.producer_tx().await; }",
            ),
            (
                "identity_security_lifecycle.rs",
                "async fn execute(pool: P) { pool.producer_tx().await; }",
            ),
            (
                "policy_repo.rs",
                "async fn a(pool: P) { pool.producer_tx().await; } async fn b(pool: P) { pool.producer_tx().await; } async fn c(pool: P) { pool.producer_tx().await; }",
            ),
            (
                "role_binding_lifecycle.rs",
                "async fn a(pool: P) { pool.producer_tx().await; } async fn b(pool: P) { pool.producer_tx().await; }",
            ),
            (
                "config_repo.rs",
                "async fn persist(pool: P) { pool.retry_producer_tx().await; }",
            ),
        ]));
        assert!(findings.is_empty(), "{findings:#?}");
    }

    #[test]
    fn producer_funnel_guard_rejects_unexpected_production_file_callsite() {
        let mut sources = files(&[
            (
                "auth_grant_lifecycle.rs",
                "async fn persist(pool: P) { pool.producer_tx().await; }",
            ),
            (
                "identity_security_lifecycle.rs",
                "async fn execute(pool: P) { pool.producer_tx().await; }",
            ),
            (
                "policy_repo.rs",
                "async fn a(pool: P) { pool.producer_tx().await; } async fn b(pool: P) { pool.producer_tx().await; } async fn c(pool: P) { pool.producer_tx().await; }",
            ),
            (
                "role_binding_lifecycle.rs",
                "async fn a(pool: P) { pool.producer_tx().await; } async fn b(pool: P) { pool.producer_tx().await; }",
            ),
            (
                "config_repo.rs",
                "async fn persist(pool: P) { pool.retry_producer_tx().await; }",
            ),
        ]);
        sources.push((
            "unexpected.rs".to_owned(),
            "async fn escape(pool: P) { pool.producer_tx().await; }".to_owned(),
        ));

        let findings = producer_funnel_findings(&sources);
        assert!(
            findings
                .iter()
                .any(|finding| finding.rule == Rule::ProducerFunnelBypass),
            "unexpected production producer callsite must fail closed: {findings:#?}"
        );
    }

    #[test]
    fn producer_funnel_guard_ignores_test_only_members_and_statements() -> anyhow::Result<()> {
        let root = crate::workspace_root()?;
        let mut files = load_prod_rs(&root.join("adapters/postgres/src"))?;
        let session = files
            .iter_mut()
            .find(|(path, _)| path == "auth_grant_lifecycle.rs")
            .context("session provider")?;
        session.1.push_str(
            r#"
impl SyntheticTestBait {
    #[cfg(test)]
    async fn member(&self) {
        self.pool.producer_tx();
        self.pool.write();
    }
    async fn production(&self) {
        #[cfg(test)]
        self.pool.producer_tx();
        #[cfg(test)]
        self.pool.write();
    }
}
"#,
        );

        let findings = producer_funnel_findings(&files);
        assert!(findings.is_empty(), "{findings:#?}");
        Ok(())
    }

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
            |_attempt, deadline| async { self.pool.retry_write(scope, deadline) },
            classify,
        ).await;
    }

    async fn publish_internal(&self, command: SecretInternalPublishCommand) {
        run_pg_tx_retry(
            SETTINGS_SECRET_BOUNDARY,
            |_attempt, deadline| async { self.pool.retry_write(scope, deadline) },
            classify,
        ).await;
    }

    async fn republish(&self, command: SecretRepublishCommand) {
        run_pg_tx_retry(
            SETTINGS_SECRET_BOUNDARY,
            |_attempt, deadline| async { self.pool.retry_write(scope, deadline) },
            classify,
        ).await;
    }
}
"#
    }

    fn deadline_authority_green_source() -> &'static str {
        r#"
pub(crate) struct LocalTxDeadline {
    operation: tokio::time::Instant,
    final_settlement: tokio::time::Instant,
}
impl LocalTxDeadline {
    fn mint(budget: LocalTxExecutionBudget) -> Self {
        let started = tokio::time::Instant::now();
        Self {
            operation: started + budget.operation(),
            final_settlement: started + budget.total(),
        }
    }
}
async fn run_pg_tx_retry_core() {
    let deadline = LocalTxDeadline::mint(localtx_execution_budget());
    run_tx_retry(policy, move || op(deadline)).await
}
#[cfg(test)]
fn localtx_deadline_for_test() -> LocalTxDeadline {
    LocalTxDeadline::mint(LocalTxExecutionBudget::DEFAULT)
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

    fn localtx_quarantine_semantic_fixture() -> Vec<(String, String)> {
        files(&[
            (
                "cotx/mod.rs",
                r#"
async fn set_local_plain_lock_timeout(conn: &mut PgConnection) -> Result<(), sqlx::Error> {
    sqlx::query("SELECT set_config('lock_timeout', '5s', true)")
        .execute(conn)
        .await
        .map(|_| ())
}

enum LocalTxExecutionPolicy {
    Plain,
    Deadline(LocalTxDeadline),
}

impl LocalTxExecutionPolicy {
    async fn acquire(self, pool: &PgPool) {
        match self {
            Self::Plain => LocalTxConnectionLease::acquire(pool).await,
            Self::Deadline(deadline) => deadline.acquire(LocalTxConnectionLease::acquire(pool)).await,
        }
    }
    async fn begin(self, lease: &mut LocalTxConnectionLease) {
        match self {
            Self::Plain => lease.begin().await,
            Self::Deadline(deadline) => deadline.begin(lease.begin()).await,
        }
    }
    async fn setup(self, tx: &mut TxCapability<'_>, tenant: TenantId) {
        let setup = async {
            match self {
                Self::Plain => {
                    plain_setup(tx, tenant).await;
                    set_local_plain_lock_timeout(tx.conn()).await
                }
                Self::Deadline(deadline) => set_local_retry_deadlines(tx.conn(), deadline).await,
            }
        };
        match self {
            Self::Plain => setup.await,
            Self::Deadline(deadline) => deadline.setup(setup).await,
        }
    }
    async fn operation(self, future: Future) {
        match self {
            Self::Plain => future.await,
            Self::Deadline(deadline) => deadline.operation(future).await,
        }
    }
    async fn commit(self, future: Future) {
        match self {
            Self::Plain => future.await,
            Self::Deadline(deadline) => deadline.commit(future).await,
        }
    }
    async fn rollback(self, future: Future) {
        match self {
            Self::Plain => future.await,
            Self::Deadline(deadline) => deadline.rollback(future).await,
        }
    }
}

async fn tenant_scoped_write_inner(pool: &PgPool, tenant: TenantId, write: F) {
    execute_local_tx(pool, tenant, LocalTxExecutionPolicy::Plain, PlainLocalTxOperation(write)).await
}

async fn tenant_scoped_retry_write_inner(pool: &PgPool, tenant: TenantId, deadline: LocalTxDeadline, write: F) {
    execute_local_tx(pool, tenant, LocalTxExecutionPolicy::Deadline(deadline), PlainLocalTxOperation(write)).await
}

async fn producer_tx_inner(pool: &PgPool, projection_registry: Registry, write: ProducerTxWrite<'_>, policy: LocalTxExecutionPolicy, business_write: F) {
    execute_producer_local_tx(pool, projection_registry, write, policy, business_write).await
}

async fn execute_producer_local_tx(pool: &PgPool, projection_registry: Registry, write: ProducerTxWrite<'_>, policy: LocalTxExecutionPolicy, business_write: F) {
    let attempt = execute_local_tx(
        pool,
        write.tenant,
        policy,
        ProducerLocalTxOperation {
            projection_registry,
            write: ProducerTxWrite { tenant: write.tenant, entry: write.entry, env: write.env },
            business_write,
        },
    ).await;
    attempt.map_error(|error| error)
}

async fn execute_local_tx(pool: &PgPool, tenant: TenantId, policy: LocalTxExecutionPolicy, write: O) {
    let mut lease = match policy.acquire(pool).await { Complete(value) => value, _ => return };
    let mut tx = match policy.begin(&mut lease).await { Complete(value) => value, _ => return };
    let setup_result = {
        let mut tx_cap = tx.capability();
        policy.setup(&mut tx_cap, tenant).await
    };
    let body_result = match setup_result {
        Complete(()) => {
            let mut tx_cap = tx.capability();
            match policy.operation(write.execute(&mut tx_cap)).await { Complete(value) => Success(value), _ => Failed }
        }
        _ => Failed,
    };
    finish_local_tx(tx, body_result, map_storage, operation, tenant, policy).await
}

async fn finish_local_tx(mut tx: LocalTxTransaction<'_>) {
    match result {
        Success(value) => commit_local_tx(tx, value).await,
        Failed(error) => rollback_local_tx(tx, error).await,
        SetupDeadline(error) => rollback_local_tx(tx, error).await,
        OperationDeadline(error) => rollback_local_tx(tx, error).await,
    }
}

async fn commit_local_tx(mut tx: LocalTxTransaction<'_>) {
    let commit_result = tx.commit_unknown_after_ack().await;
}

async fn rollback_local_tx(tx: LocalTxTransaction<'_>, error: Error) {
    run_local_tx_rollback(tx, policy).await;
}

async fn run_local_tx_rollback(mut tx: LocalTxTransaction<'_>) {
    let rollback_failed = tx.rollback_failed_after_ack().await;
    let rollback_paused = tx.rollback_paused_before_ack().await;
}
"#,
            ),
            (
                "cotx/settlement.rs",
                r#"
pub(super) struct LocalTxConnectionLease {
    quarantine_stage: Option<LocalTxQuarantineStage>,
    connection: PoolConnection<Postgres>,
}

enum LocalTxQuarantineStage { Rollback, Commit, Body, Begin }

pub(super) struct LocalTxTransaction<'lease> {
    quarantine_stage: &'lease mut Option<LocalTxQuarantineStage>,
    transaction: Transaction<'lease, Postgres>,
}

impl LocalTxConnectionLease {
    pub(super) async fn acquire(pool: &PgPool) -> Result<Self, sqlx::Error> {
        Ok(Self {
            quarantine_stage: Some(LocalTxQuarantineStage::Begin),
            connection: pool.acquire().await?,
        })
    }
    pub(super) async fn begin(&mut self) -> Result<LocalTxTransaction<'_>, sqlx::Error> {
        let Self { quarantine_stage, connection, } = self;
        let transaction = (&mut *connection).begin().await?;
        *quarantine_stage = Some(LocalTxQuarantineStage::Body);
        Ok(LocalTxTransaction { quarantine_stage, transaction, })
    }
}

impl LocalTxTransaction<'_> {
    pub(super) fn capability(&mut self) -> super::TxCapability<'_> {
        super::TxCapability::from_transaction(&mut self.transaction)
    }
    pub(super) async fn commit(self) -> Result<(), sqlx::Error> {
        let Self { quarantine_stage, transaction } = self;
        *quarantine_stage = Some(LocalTxQuarantineStage::Commit);
        transaction.commit().await?;
        *quarantine_stage = None;
        Ok(())
    }
    pub(super) async fn rollback(self) -> Result<(), sqlx::Error> {
        let Self { quarantine_stage, transaction } = self;
        *quarantine_stage = Some(LocalTxQuarantineStage::Rollback);
        transaction.rollback().await?;
        *quarantine_stage = None;
        Ok(())
    }
    #[cfg(test)]
    pub(super) async fn commit_unknown_after_ack(self) -> Result<(), sqlx::Error> {
        let Self { quarantine_stage, transaction } = self;
        *quarantine_stage = Some(LocalTxQuarantineStage::Commit);
        transaction.commit().await?;
        Err(sqlx::Error::PoolTimedOut)
    }
    #[cfg(test)]
    pub(super) async fn rollback_failed_after_ack(self) -> Result<(), sqlx::Error> {
        let Self { quarantine_stage, transaction } = self;
        *quarantine_stage = Some(LocalTxQuarantineStage::Rollback);
        transaction.rollback().await?;
        Err(sqlx::Error::PoolTimedOut)
    }
    #[cfg(test)]
    pub(super) async fn rollback_paused_before_ack(self) -> Result<(), sqlx::Error> {
        let Self { quarantine_stage, transaction } = self;
        *quarantine_stage = Some(LocalTxQuarantineStage::Rollback);
        super::notify_rollback_pause_entered_for_test();
        std::future::pending::<()>().await;
        drop(transaction);
        Ok(())
    }
}

impl Drop for LocalTxConnectionLease {
    fn drop(&mut self) {
        if let Some(stage) = self.quarantine_stage {
            metrics::counter!("postgres_localtx_connection_quarantine_total", "stage" => stage.as_label()).increment(1);
            tracing::warn!(quarantine_stage = stage.as_label(), "localtx connection quarantined");
            self.connection.close_on_drop();
        }
    }
}
"#,
            ),
        ])
    }

    #[test]
    fn localtx_quarantine_guard_accepts_closed_lease_and_semantic_funnels() {
        let findings = localtx_quarantine_findings(&localtx_quarantine_semantic_fixture());
        assert!(
            findings.is_empty(),
            "closed LocalTx lease rejected: {findings:?}"
        );
    }

    #[test]
    fn localtx_quarantine_guard_rejects_non_dominating_ack_control_flow() {
        let cases = [
            (
                "dead-branch",
                "        transaction.commit().await?;",
                "        if false { transaction.commit().await?; }",
            ),
            (
                "closure",
                "        transaction.commit().await?;",
                "        let _ack = || async { transaction.commit().await?; Ok::<(), sqlx::Error>(()) };",
            ),
            (
                "unawaited-async",
                "        transaction.commit().await?;",
                "        let _ack = async { transaction.commit().await?; Ok::<(), sqlx::Error>(()) };",
            ),
            (
                "zero-iteration-loop",
                "        transaction.commit().await?;",
                "        for _ in 0..0 { transaction.commit().await?; }",
            ),
            (
                "helper-indirection",
                "        transaction.commit().await?;",
                "        settle(transaction).await?;",
            ),
            (
                "early-return",
                "        transaction.commit().await?;",
                "        return Ok(());\n        transaction.commit().await?;",
            ),
        ];

        for (name, before, after) in cases {
            let mut sources = localtx_quarantine_semantic_fixture();
            let mutated = sources[1].1.replacen(before, after, 1);
            assert_ne!(sources[1].1, mutated, "{name} fixture must be non-vacuous");
            sources[1].1 = mutated;
            let findings = localtx_quarantine_findings(&sources);
            assert!(
                findings
                    .iter()
                    .any(|finding| finding.rule == Rule::LocalTxQuarantineBypass),
                "{name} must not satisfy ACK-before-disarm: {findings:?}"
            );
        }
    }

    #[test]
    fn localtx_quarantine_guard_accepts_equivalent_binding_and_field_order_changes() {
        let mut sources = localtx_quarantine_semantic_fixture();
        let original_funnel = sources[0].1.clone();
        sources[0].1 = sources[0]
            .1
            .replace("let mut lease", "let mut connection_lease")
            .replace(
                "policy.begin(&mut lease)",
                "policy.begin(&mut connection_lease)",
            )
            .replace("let mut tx =", "let mut local_tx =")
            .replace("tx.capability()", "local_tx.capability()")
            .replace(
                "finish_local_tx(tx, body_result",
                "finish_local_tx(local_tx, body_result",
            );
        assert_ne!(original_funnel, sources[0].1);
        let original_settlement = sources[1].1.clone();
        sources[1].1 = sources[1]
            .1
            .replace(
                "let Self { quarantine_stage, connection, } = self;",
                "let Self { connection, quarantine_stage, } = self;",
            )
            .replace(
                "let Self { quarantine_stage, transaction } = self;",
                "let Self { transaction, quarantine_stage } = self;",
            );
        assert_ne!(original_settlement, sources[1].1);

        let findings = localtx_quarantine_findings(&sources);
        assert!(
            findings.is_empty(),
            "equivalent binding renames and field order must remain green: {findings:?}"
        );
    }

    #[test]
    fn localtx_quarantine_guard_real_workspace_closes_exact_sites() -> Result<()> {
        let root = crate::workspace_root()?;
        let files = load_prod_rs(&root.join("adapters/postgres/src"))?;
        let findings = localtx_quarantine_findings(&files);
        assert!(findings.is_empty(), "{findings:?}");
        assert!(
            files.iter().any(|(path, _)| path == "cotx/mod.rs")
                && files.iter().any(|(path, _)| path == "cotx/settlement.rs"),
            "real workspace must contain both LocalTx quarantine enforcement sites"
        );
        Ok(())
    }

    #[test]
    fn localtx_quarantine_guard_rejects_bypass_and_escape_classes() {
        let cases = [
            (
                "direct-pool-begin",
                "deadline.acquire(LocalTxConnectionLease::acquire(pool)).await",
                "pool.begin().await",
            ),
            (
                "missing-finish",
                "    finish_local_tx(tx, body_result, map_storage, operation, tenant, policy).await\n",
                "    drop(tx);\n",
            ),
            (
                "helper-indirection",
                "    let mut tx = match policy.begin(&mut lease).await { Complete(value) => value, _ => return };",
                "    let mut tx = match helper(&mut lease).await { Complete(value) => value, _ => return };",
            ),
            (
                "tx-shadow",
                "    finish_local_tx(tx, body_result, map_storage, operation, tenant, policy).await",
                "    let mut tx = helper(pool).await;\n    finish_local_tx(tx, body_result, map_storage, operation, tenant, policy).await",
            ),
            (
                "wrong-policy-binding",
                "policy.begin(&mut lease).await",
                "other.begin(&mut lease).await",
            ),
            (
                "dead-operation-branch",
                "policy.operation(write.execute(&mut tx_cap)).await",
                "if false { policy.operation(write.execute(&mut tx_cap)).await } else { forged().await }",
            ),
            (
                "policy-reassignment",
                "    let mut lease = match policy.acquire(pool).await",
                "    policy = forged;\n    let mut lease = match policy.acquire(pool).await",
            ),
            (
                "arbitrary-disarm",
                "    pub(super) async fn begin(&mut self)",
                "    pub(super) fn disarm(&mut self) { self.quarantine_stage = None; }\n    pub(super) async fn begin(&mut self)",
            ),
            (
                "raw-connection-escape",
                "    pub(super) async fn begin(&mut self)",
                "    pub(super) fn into_inner(self) -> PoolConnection<Postgres> { todo!() }\n    pub(super) async fn begin(&mut self)",
            ),
            (
                "free-function-disarm",
                "impl LocalTxConnectionLease {",
                "fn disarm(lease: &mut LocalTxConnectionLease) { lease.quarantine_stage = None; }\n\nimpl LocalTxConnectionLease {",
            ),
            (
                "nested-module-disarm",
                "impl LocalTxConnectionLease {",
                "mod escape { fn disarm(lease: &mut super::LocalTxConnectionLease) { lease.quarantine_stage = None; } }\n\nimpl LocalTxConnectionLease {",
            ),
            (
                "unknown-seam-disarm",
                "        Err(sqlx::Error::PoolTimedOut)",
                "        *quarantine_stage = None;\n        Err(sqlx::Error::PoolTimedOut)",
            ),
            (
                "unknown-seam-mem-take",
                "        Err(sqlx::Error::PoolTimedOut)",
                "        let _ = std::mem::take(quarantine_stage);\n        Err(sqlx::Error::PoolTimedOut)",
            ),
            (
                "missing-close-on-drop",
                "            self.connection.close_on_drop();",
                "            let _ = &self.connection;",
            ),
        ];

        for (name, before, after) in cases {
            let mut sources = localtx_quarantine_semantic_fixture();
            let target = if matches!(
                name,
                "direct-pool-begin"
                    | "missing-finish"
                    | "helper-indirection"
                    | "tx-shadow"
                    | "wrong-policy-binding"
                    | "dead-operation-branch"
                    | "policy-reassignment"
            ) {
                "cotx/mod.rs"
            } else {
                "cotx/settlement.rs"
            };
            let source_index = usize::from(target == "cotx/settlement.rs");
            let source = &mut sources[source_index].1;
            let mutated = source.replacen(before, after, 1);
            assert_ne!(
                *source, mutated,
                "{name} fixture mutation must be non-vacuous"
            );
            *source = mutated;
            let findings = localtx_quarantine_findings(&sources);
            assert!(
                findings.iter().any(|finding| {
                    matches!(
                        finding.rule,
                        Rule::LocalTxQuarantineBypass | Rule::LocalTxQuarantineSitesAbsent
                    )
                }),
                "{name} must fail closed: {findings:?}"
            );
        }

        let mut removed_producer_entry = localtx_quarantine_semantic_fixture();
        removed_producer_entry[0].1 = removed_producer_entry[0]
            .1
            .replace("producer_tx_inner", "removed_producer_tx_inner");
        let findings = localtx_quarantine_findings(&removed_producer_entry);
        assert!(
            findings
                .iter()
                .any(|finding| finding.rule == Rule::LocalTxQuarantineSitesAbsent),
            "producer entry removal must fail closed: {findings:?}"
        );

        let mut unused_unsafe_seam = localtx_quarantine_semantic_fixture();
        unused_unsafe_seam[0].1 = unused_unsafe_seam[0].1.replacen(
            "tx.commit_unknown_after_ack().await",
            "tx.commit().await",
            1,
        );
        let findings = localtx_quarantine_findings(&unused_unsafe_seam);
        assert!(
            findings
                .iter()
                .any(|finding| finding.rule == Rule::LocalTxQuarantineBypass),
            "unused unsafe seam must fail closed: {findings:?}"
        );

        let mut duplicate_unsafe_seam = localtx_quarantine_semantic_fixture();
        duplicate_unsafe_seam[0]
            .1
            .push_str("\nasync fn duplicate(mut tx: LocalTxTransaction<'_>) { let _ = tx.commit_unknown_after_ack().await; }\n");
        let findings = localtx_quarantine_findings(&duplicate_unsafe_seam);
        assert!(
            findings
                .iter()
                .any(|finding| finding.rule == Rule::LocalTxQuarantineBypass),
            "duplicate unsafe seam use must fail closed: {findings:?}"
        );

        let mut ufcs_unsafe_seam = localtx_quarantine_semantic_fixture();
        ufcs_unsafe_seam[0].1.push_str(
            "\nasync fn ufcs_duplicate(tx: LocalTxTransaction<'_>) { let _ = LocalTxTransaction::commit_unknown_after_ack(tx).await; }\n",
        );
        let findings = localtx_quarantine_findings(&ufcs_unsafe_seam);
        assert!(
            findings
                .iter()
                .any(|finding| finding.rule == Rule::LocalTxQuarantineBypass),
            "UFCS unsafe seam use must fail closed: {findings:?}"
        );

        let mut aliased_unsafe_seam = localtx_quarantine_semantic_fixture();
        aliased_unsafe_seam[0].1.push_str(
            "\nuse LocalTxTransaction::commit_unknown_after_ack as unsafe_commit;\nasync fn alias_duplicate(tx: LocalTxTransaction<'_>) { let _ = unsafe_commit(tx).await; }\n",
        );
        let findings = localtx_quarantine_findings(&aliased_unsafe_seam);
        assert!(
            findings
                .iter()
                .any(|finding| finding.rule == Rule::LocalTxQuarantineBypass),
            "aliased unsafe seam use must fail closed: {findings:?}"
        );

        let mut external_unsafe_seam = localtx_quarantine_semantic_fixture();
        external_unsafe_seam.push((
            "cotx/helper.rs".to_owned(),
            "async fn duplicate(mut tx: LocalTxTransaction<'_>) { let _ = tx.rollback_failed_after_ack().await; }".to_owned(),
        ));
        let findings = localtx_quarantine_findings(&external_unsafe_seam);
        assert!(
            findings
                .iter()
                .any(|finding| finding.rule == Rule::LocalTxQuarantineBypass),
            "external-module unsafe seam use must fail closed: {findings:?}"
        );

        let mut foreign_impl = localtx_quarantine_semantic_fixture();
        foreign_impl.push((
            "cotx/escape.rs".to_owned(),
            "impl LocalTxConnectionLease { fn escape(&mut self) {} }".to_owned(),
        ));
        let findings = localtx_quarantine_findings(&foreign_impl);
        assert!(
            findings
                .iter()
                .any(|finding| finding.rule == Rule::LocalTxQuarantineBypass),
            "foreign impl must fail closed: {findings:?}"
        );

        let mut nested_foreign_impl = localtx_quarantine_semantic_fixture();
        nested_foreign_impl.push((
            "cotx/escape.rs".to_owned(),
            "mod nested { impl LocalTxConnectionLease { fn escape(&mut self) {} } }".to_owned(),
        ));
        let findings = localtx_quarantine_findings(&nested_foreign_impl);
        assert!(
            findings
                .iter()
                .any(|finding| finding.rule == Rule::LocalTxQuarantineBypass),
            "nested foreign impl must fail closed: {findings:?}"
        );

        let findings = localtx_required_carriers_missing(&[]);
        assert!(
            findings
                .iter()
                .any(|finding| finding.rule == Rule::LocalTxQuarantineSitesAbsent),
            "missing both carriers must fail the production gate: {findings:?}"
        );
    }

    #[test]
    fn localtx_quarantine_guard_rejects_plain_lock_wait_bypasses() {
        let cases = [
            (
                "unbounded-plain-lock-wait",
                "                    set_local_plain_lock_timeout(tx.conn()).await",
                "                    Ok(())",
            ),
            (
                "weakened-plain-lock-timeout",
                "SELECT set_config('lock_timeout', '5s', true)",
                "SELECT set_config('lock_timeout', '0', true)",
            ),
        ];

        for (name, before, after) in cases {
            let mut sources = localtx_quarantine_semantic_fixture();
            let source = &mut sources[0].1;
            let mutated = source.replacen(before, after, 1);
            assert_ne!(
                *source, mutated,
                "{name} fixture mutation must be non-vacuous"
            );
            *source = mutated;
            let findings = localtx_quarantine_findings(&sources);
            assert!(
                findings.iter().any(|finding| {
                    matches!(
                        finding.rule,
                        Rule::LocalTxQuarantineBypass | Rule::LocalTxQuarantineSitesAbsent
                    )
                }),
                "{name} must fail closed: {findings:?}"
            );
        }

        let mut removed_api_reintroduced = localtx_quarantine_semantic_fixture();
        removed_api_reintroduced[0]
            .1
            .push_str("\nimpl PgWritePool { async fn lock_bounded_write(&self) {} }\n");
        let findings = localtx_quarantine_findings(&removed_api_reintroduced);
        assert!(
            findings
                .iter()
                .any(|finding| finding.rule == Rule::LocalTxQuarantineSitesAbsent),
            "removed caller-selectable lock policy API must fail closed: {findings:?}"
        );
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
                    "auth_grant_lifecycle.rs",
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
                    "auth_grant_lifecycle.rs",
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
                         sqlx::query(\"INSERT INTO outbox (event_id, payload) \
                                      VALUES ($1, decode('70', 'hex'))\").execute(pool).await; \
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
    fn red_fault_matrix_cannot_write_outbox_terminal_status_directly() {
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
                     async fn bypass(&self) { \
                         sqlx::query(\"UPDATE outbox SET status = 'published' \
                                      WHERE tenant_id = $1::uuid AND event_id = $2\") \
                             .execute(&self.owner_pool).await; \
                     }",
                ),
            ]),
        );
        assert!(
            findings
                .iter()
                .any(|finding| finding.rule == Rule::FaultMatrixTerminalBypass),
            "fault harness terminal writes must go through production settlement: {findings:?}"
        );
    }

    #[test]
    fn red_fault_matrix_terminal_column_is_rejected_when_not_first_assignment() {
        let findings = fault_matrix_terminal_bypass_findings(&files(&[(
            "fault_matrix.rs",
            "async fn bypass(pool: &PgPool) { \
                 sqlx::query(\"UPDATE outbox SET retry_after = now(), published_at = now() \
                              WHERE event_id = $1\") \
                     .execute(pool).await; \
             }",
        )]));
        assert!(
            findings
                .iter()
                .any(|finding| finding.rule == Rule::FaultMatrixTerminalBypass),
            "non-first terminal assignment passed: {findings:?}"
        );
    }

    #[test]
    fn red_fault_matrix_schema_qualified_inbox_status_is_rejected() {
        let findings = fault_matrix_terminal_bypass_findings(&files(&[(
            "fault_matrix.rs",
            "async fn bypass(pool: &PgPool) { \
                 sqlx::query(\"UPDATE public.inbox_receipts \
                              SET claimed_at = now(), status = 'done' WHERE event_id = $1\") \
                     .execute(pool).await; \
             }",
        )]));
        assert!(
            findings
                .iter()
                .any(|finding| finding.rule == Rule::FaultMatrixTerminalBypass),
            "schema-qualified Inbox terminal assignment passed: {findings:?}"
        );
    }

    #[test]
    fn red_fault_matrix_schema_qualified_audit_insert_is_rejected() {
        let findings = fault_matrix_terminal_bypass_findings(&files(&[(
            "fault_matrix.rs",
            "async fn bypass(pool: &PgPool) { \
                 sqlx::query(\"INSERT INTO public.audit_entries (tenant_id) VALUES ($1)\") \
                     .execute(pool).await; \
             }",
        )]));
        assert!(
            findings
                .iter()
                .any(|finding| finding.rule == Rule::FaultMatrixTerminalBypass),
            "schema-qualified audit mutation passed: {findings:?}"
        );
    }

    #[test]
    fn red_real_fault_matrix_loader_feeds_specialized_terminal_check() -> Result<()> {
        let root =
            std::env::temp_dir().join(format!("rss-pg-guard-fault-loader-{}", std::process::id()));
        if root.exists() {
            std::fs::remove_dir_all(&root)?;
        }
        std::fs::create_dir_all(&root)?;
        std::fs::write(
            root.join("lib.rs"),
            "#[cfg(feature = \"fault-matrix-test-support\")]\npub mod fault_matrix;\n",
        )?;
        std::fs::write(
            root.join("fault_matrix.rs"),
            "async fn bypass(pool: &PgPool) { \
                 sqlx::query(\"UPDATE outbox SET retry_after = now(), dlx_at = now()\") \
                     .execute(pool).await; \
             }",
        )?;
        let findings = load_fault_matrix_governance_findings(&migrations(), &root)?;
        assert!(
            findings
                .iter()
                .any(|finding| finding.rule == Rule::FaultMatrixTerminalBypass),
            "real fault_matrix loader omitted the specialized terminal check: {findings:?}"
        );
        std::fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn red_real_fault_matrix_loader_feeds_raw_tenant_scan() -> Result<()> {
        let root = std::env::temp_dir().join(format!(
            "rss-pg-guard-fault-raw-loader-{}",
            std::process::id()
        ));
        if root.exists() {
            std::fs::remove_dir_all(&root)?;
        }
        std::fs::create_dir_all(&root)?;
        std::fs::write(
            root.join("lib.rs"),
            "#[cfg(feature = \"fault-matrix-test-support\")]\npub mod fault_matrix;\n",
        )?;
        std::fs::write(
            root.join("fault_matrix.rs"),
            "struct Harness { owner_pool: PgPool } \
             impl Harness { \
                 async fn accidental(&self) { \
                     sqlx::query(\"DELETE FROM roles WHERE tenant_id = $1\") \
                         .execute(&self.owner_pool).await; \
                 } \
             }",
        )?;
        let findings = load_fault_matrix_governance_findings(&migrations(), &root)?;
        assert!(
            findings
                .iter()
                .any(|finding| finding.rule == Rule::RawTenantTableAccess),
            "real fault_matrix loader omitted the shared raw tenant scan: {findings:?}"
        );
        std::fs::remove_dir_all(root)?;
        Ok(())
    }

    #[test]
    fn real_fault_matrix_loader_accepts_only_registered_exact_sites() -> Result<()> {
        let root = crate::workspace_root()?;
        let migrations = load_sql_files(&root.join("adapters/postgres/migrations"))?;
        let findings = load_fault_matrix_governance_findings(
            &migrations,
            &root.join("adapters/postgres/src"),
        )?;
        assert!(
            findings.is_empty(),
            "registered feature-gated fault-matrix sites drifted or a raw access escaped the exact allowlist: {findings:#?}"
        );
        Ok(())
    }

    #[test]
    fn green_fault_matrix_setup_time_and_read_only_sql_pass_terminal_check() {
        let findings = fault_matrix_terminal_bypass_findings(&files(&[(
            "fault_matrix.rs",
            "async fn allowed(pool: &PgPool) { \
                 sqlx::query(\"UPDATE public.outbox SET retry_after = now(), updated_at = now() \
                              WHERE status = 'pending'\").execute(pool).await; \
                 sqlx::query(\"UPDATE inbox_receipts SET claimed_at = now() \
                              WHERE status = 'processing'\").execute(pool).await; \
                 sqlx::query(\"INSERT INTO outbox (event_id, status) VALUES ($1, 'pending')\") \
                     .execute(pool).await; \
                 sqlx::query_scalar(\"SELECT count(*) FROM audit_entries\").fetch_one(pool).await; \
             }",
        )]));
        assert!(
            findings.is_empty(),
            "fixture seed/time injection/read-only observation must remain allowed: {findings:?}"
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
                    "struct R { pool: PgTenantReadPool } async fn f(){ self.pool.read(tenant, |conn| Box::pin(async move { sqlx::query(\"SELECT * FROM roles\").fetch_optional(&mut *conn).await })); }",
                ),
                (
                    "config_repo.rs",
                    "struct R { pool: PgTenantWritePool } async fn f(){ self.pool.write(tenant, |conn| Box::pin(async move { sqlx::query(\"UPDATE credentials SET id=id\").execute(&mut *conn).await.map_err(storage) }), storage); }",
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
    fn red_removed_pg_tenant_pool_is_rejected_even_inside_cotx_funnel() {
        let (_, findings) = scan_guard(
            &migrations(),
            &files(&[
                ("cotx/mod.rs", "struct PgTenantPool { store: PgStore }"),
                (
                    "role_repo.rs",
                    "struct R { pool: PgTenantReadPool } async fn f(){ self.pool.read(tenant, |conn| Box::pin(async move { sqlx::query(\"SELECT * FROM roles\").fetch_optional(&mut *conn).await })); }",
                ),
            ]),
        );

        assert!(
            findings.iter().any(|finding| {
                finding.subject.starts_with("cotx/mod.rs")
                    && finding.detail.contains("PgTenantPool")
            }),
            "removed PgTenantPool must not survive as a stale funnel allowlist: {findings:?}"
        );
    }

    #[test]
    fn red_generic_store_source_traits_cannot_erase_verified_lane_types() {
        let (_, findings) = scan_guard(
            &migrations(),
            &files(&[(
                "role_repo.rs",
                "trait PgTenantReadStoreSource {} trait PgTenantWriteStoreSource {}",
            )]),
        );
        for removed in ["PgTenantReadStoreSource", "PgTenantWriteStoreSource"] {
            assert!(
                findings
                    .iter()
                    .any(|finding| finding.detail.contains(removed)),
                "generic source trait {removed} must never return: {findings:?}"
            );
        }
    }

    #[test]
    fn red_tenant_lane_crossovers_are_rejected() {
        let cases = [
            (
                "writer-read",
                "struct R { pool: PgTenantWritePool } async fn f(){ self.pool.read(tenant, |conn| Box::pin(async move { sqlx::query(\"SELECT * FROM roles\").fetch_optional(&mut *conn).await })); }",
                "PgTenantWritePool::read",
            ),
            (
                "writer-read-map",
                "struct R { pool: PgTenantWritePool } async fn f(){ self.pool.read_map(tenant, |conn| Box::pin(async move { sqlx::query(\"SELECT * FROM roles\").fetch_optional(&mut *conn).await }), storage); }",
                "PgTenantWritePool::read_map",
            ),
            (
                "reader-write",
                "struct R { pool: PgTenantReadPool } async fn f(){ self.pool.write(tenant, |conn| Box::pin(async move { sqlx::query(\"UPDATE roles SET id = id\").execute(&mut *conn).await }), storage); }",
                "PgTenantReadPool::write",
            ),
            (
                "reader-co-tx",
                "struct R { pool: PgTenantReadPool } async fn f(){ self.pool.producer_tx(tenant, |tx| Box::pin(async move { sqlx::query(\"UPDATE roles SET id = id\").execute(tx.conn()).await })); }",
                "PgTenantReadPool::producer_tx",
            ),
        ];

        for (case, source, forbidden_api) in cases {
            let (_, findings) = scan_guard(&migrations(), &files(&[("role_repo.rs", source)]));
            assert!(
                findings.iter().any(|finding| {
                    finding.subject.starts_with("role_repo.rs")
                        && finding.detail.contains(forbidden_api)
                }),
                "{case} must be rejected through the typed lane API, not review convention: {findings:?}"
            );
        }
    }

    #[test]
    fn red_typed_pool_parameters_cannot_bypass_lane_checks() {
        let cases = [
            (
                "free-function-nested-reference",
                "async fn load(reader: &&PgTenantReadPool) { \
                 reader.write(tenant, |conn| Box::pin(async move { \
                 sqlx::query(\"UPDATE roles SET id = id\").execute(&mut *conn).await \
                 }), storage); }",
                "PgTenantReadPool::write",
            ),
            (
                "impl-method-nested-type-and-pattern",
                "struct Repo; impl Repo { async fn load( \
                 &self, (writer, _marker): (Arc<PgTenantWritePool>, usize)) { \
                 writer.read(tenant, |conn| Box::pin(async move { \
                 sqlx::query(\"SELECT * FROM roles\").fetch_all(&mut *conn).await \
                 })); } }",
                "PgTenantWritePool::read",
            ),
        ];

        for (case, source, forbidden_api) in cases {
            let (_, findings) = scan_guard(&migrations(), &files(&[("role_repo.rs", source)]));
            assert!(
                findings.iter().any(|finding| {
                    finding.rule == Rule::TenantLaneViolation
                        && finding.detail.contains(forbidden_api)
                }),
                "{case} must retain the typed lane carried by its parameter binding: {findings:?}"
            );
        }
    }

    #[test]
    fn red_writer_transaction_cannot_hide_an_independent_select() {
        let (_, findings) = scan_guard(
            &migrations(),
            &files(&[(
                "role_repo.rs",
                "mod decoy { fn query(_: &str) {} } \
                 struct R { writer: PgTenantWritePool } async fn load(&self){ \
                 let _outside = sqlx::query(\"UPDATE roles SET id = id\"); \
                 self.writer.write(tenant, |conn| Box::pin(async move { \
                 decoy::query(\"UPDATE roles SET id = id\"); \
                 sqlx::query(\"SELECT * FROM roles\").fetch_all(&mut *conn).await \
                 }), storage); }",
            )]),
        );
        assert!(
            findings
                .iter()
                .any(|finding| finding.detail.contains("SELECT-only writer transaction")),
            "writer.write must not become an untyped reader escape hatch: {findings:?}"
        );
    }

    #[test]
    fn red_writer_sql_classifier_fails_closed_on_indirect_or_plain_reads() {
        let cases = [
            (
                "cte-select",
                "sqlx::query(\"WITH candidate AS (SELECT * FROM roles) SELECT * FROM candidate\").fetch_all(&mut *conn).await",
                "SELECT-only writer transaction",
            ),
            (
                "dynamic-sql",
                "let sql = \"SELECT * FROM roles\"; sqlx::query(sql).fetch_all(&mut *conn).await",
                "unclassified SQL",
            ),
            (
                "lock-string-bait",
                "sqlx::query(\"SELECT 'FOR UPDATE' FROM roles\").fetch_all(&mut *conn).await",
                "SELECT-only writer transaction",
            ),
            (
                "multi-statement",
                "sqlx::raw_sql(\"UPDATE roles SET id = id; SELECT * FROM roles\").execute(&mut *conn).await",
                "unclassified SQL",
            ),
        ];
        for (case, body, expected) in cases {
            let source = format!(
                "struct R {{ writer: PgTenantWritePool }} async fn f(&self){{ \
                 self.writer.write(tenant, |conn| Box::pin(async move {{ {body} }}), storage); }}"
            );
            let (_, findings) = scan_guard(&migrations(), &files(&[("role_repo.rs", &source)]));
            assert!(
                findings.iter().any(|finding| {
                    finding.rule == Rule::TenantLaneViolation && finding.detail.contains(expected)
                }),
                "{case} must fail closed through the writer SQL classifier: {findings:?}"
            );
        }
    }

    #[test]
    fn green_exact_sqlx_alias_provides_executed_mutation_evidence() {
        let (_, findings) = scan_guard(
            &migrations(),
            &files(&[(
                "role_repo.rs",
                "use sqlx::query as pg_query; \
                 struct R { writer: PgTenantWritePool } async fn f(&self){ \
                 self.writer.write(tenant, |conn| Box::pin(async move { \
                 pg_query(\"SELECT * FROM roles\").fetch_all(&mut *conn).await?; \
                 pg_query(\"UPDATE roles SET id = id\").execute(&mut *conn).await \
                 }), storage); }",
            )]),
        );
        assert!(
            findings
                .iter()
                .all(|finding| finding.rule != Rule::TenantLaneViolation),
            "a resolved sqlx alias with executed mutation evidence must pass: {findings:?}"
        );
    }

    #[test]
    fn red_writer_helper_sql_is_resolved_into_lane_assessment() {
        let (_, findings) = scan_guard(
            &migrations(),
            &files(&[(
                "role_repo.rs",
                "async fn helper(conn: &mut sqlx::PgConnection) { \
                 sqlx::query(\"SELECT * FROM roles\").fetch_all(conn).await; } \
                 struct R { writer: PgTenantWritePool } async fn f(&self){ \
                 self.writer.write(tenant, |conn| Box::pin(async move { helper(conn).await }), storage); }",
            )]),
        );
        assert!(
            findings.iter().any(|finding| {
                finding.rule == Rule::TenantLaneViolation
                    && finding.detail.contains("SELECT-only writer transaction")
            }),
            "moving plain tenant SQL behind a helper must still fail closed: {findings:?}"
        );
    }

    #[test]
    fn writer_helper_graph_is_cross_file_and_owner_qualified() {
        let (_, green) = scan_guard(
            &migrations(),
            &files(&[
                (
                    "role_repo.rs",
                    "use crate::write_helper::mutate; struct R { writer: PgTenantWritePool } \
                     impl R { async fn f(&self){ self.writer.write(tenant, |tx| Box::pin(async move { \
                     mutate(tx).await }), storage); } }",
                ),
                (
                    "write_helper.rs",
                    "async fn mutate(tx: &mut TxCapability<'_>) { \
                     sqlx::query(\"UPDATE roles SET id = id\").execute(tx.conn()).await; }",
                ),
            ]),
        );
        assert!(
            green
                .iter()
                .all(|finding| finding.rule != Rule::TenantLaneViolation),
            "an exact crate import must inherit the target helper evidence: {green:?}"
        );

        let (_, unknown) = scan_guard(
            &migrations(),
            &files(&[(
                "role_repo.rs",
                "use crate::missing::mutate; struct R { writer: PgTenantWritePool } \
                 impl R { async fn f(&self){ self.writer.write(tenant, |tx| Box::pin(async move { \
                 mutate(tx).await }), storage); } }",
            )]),
        );
        assert!(
            unknown.iter().any(|finding| {
                finding.rule == Rule::TenantLaneViolation
                    && finding.detail.contains("unclassified SQL")
            }),
            "an unresolved capability helper must fail closed: {unknown:?}"
        );

        let (_, owner_bait) = scan_guard(
            &migrations(),
            &files(&[(
                "role_repo.rs",
                "async fn helper(tx: &mut TxCapability<'_>) { \
                 sqlx::query(\"SELECT * FROM roles\").fetch_all(tx.conn()).await; } \
                 struct Decoy; impl Decoy { async fn helper(tx: &mut TxCapability<'_>) { \
                 sqlx::query(\"UPDATE roles SET id = id\").execute(tx.conn()).await; } } \
                 struct R { writer: PgTenantWritePool } impl R { async fn f(&self){ \
                 self.writer.write(tenant, |tx| Box::pin(async move { helper(tx).await }), storage); } }",
            )]),
        );
        assert!(
            owner_bait.iter().any(|finding| {
                finding.rule == Rule::TenantLaneViolation
                    && finding.detail.contains("SELECT-only writer transaction")
            }),
            "an impl method with the same name must not satisfy a free helper call: {owner_bait:?}"
        );

        let (_, sibling_bait) = scan_guard(
            &migrations(),
            &files(&[(
                "role_repo.rs",
                "mod reads { async fn helper(tx: &mut TxCapability<'_>) { \
                 sqlx::query(\"SELECT * FROM roles\").fetch_all(tx.conn()).await; } } \
                 mod decoy { async fn helper(tx: &mut TxCapability<'_>) { \
                 sqlx::query(\"UPDATE roles SET id = id\").execute(tx.conn()).await; } } \
                 struct R { writer: PgTenantWritePool } impl R { async fn f(&self){ \
                 self.writer.write(tenant, |tx| Box::pin(async move { \
                 reads::helper(tx).await }), storage); } }",
            )]),
        );
        assert!(
            sibling_bait.iter().any(|finding| {
                finding.rule == Rule::TenantLaneViolation
                    && finding.detail.contains("SELECT-only writer transaction")
            }),
            "sibling inline modules must retain distinct helper identities: {sibling_bait:?}"
        );
    }

    #[test]
    fn sqlx_crate_alias_is_exact_and_decoys_are_not_evidence() {
        let (_, green) = scan_guard(
            &migrations(),
            &files(&[(
                "role_repo.rs",
                "use sqlx as db; struct R { writer: PgTenantWritePool } impl R { async fn f(&self){ \
                 self.writer.write(tenant, |tx| Box::pin(async move { \
                 db::query(\"UPDATE roles SET id = id\").execute(tx.conn()).await }), storage); } }",
            )]),
        );
        assert!(
            green
                .iter()
                .all(|finding| finding.rule != Rule::TenantLaneViolation),
            "a real sqlx crate alias must preserve query provenance: {green:?}"
        );

        let (_, decoy) = scan_guard(
            &migrations(),
            &files(&[(
                "role_repo.rs",
                "mod decoy { fn query(_: &str) {} } struct R { writer: PgTenantWritePool } \
                 impl R { async fn f(&self){ self.writer.write(tenant, |tx| Box::pin(async move { \
                 decoy::query(\"UPDATE roles SET id = id\"); \
                 sqlx::query(\"SELECT * FROM roles\").fetch_all(tx.conn()).await }), storage); } }",
            )]),
        );
        assert!(
            decoy.iter().any(|finding| {
                finding.rule == Rule::TenantLaneViolation
                    && finding.detail.contains("SELECT-only writer transaction")
            }),
            "a same-named decoy query function must not mint SQL evidence: {decoy:?}"
        );

        for (fake_import, bait) in [
            (
                "use fake::sqlx::query as q;",
                "q(\"UPDATE roles SET id = id\").execute(tx.conn()).await?;",
            ),
            (
                "use fake::sqlx as db;",
                "db::query(\"UPDATE roles SET id = id\").execute(tx.conn()).await?;",
            ),
        ] {
            let source = format!(
                "{fake_import} struct R {{ writer: PgTenantWritePool }} impl R {{ async fn f(&self){{ \
                 self.writer.write(tenant, |tx| Box::pin(async move {{ {bait} \
                 sqlx::query(\"SELECT * FROM roles\").fetch_all(tx.conn()).await }}), storage); }} }}"
            );
            let (_, findings) =
                scan_guard(&migrations(), &files(&[("role_repo.rs", source.as_str())]));
            assert!(
                findings
                    .iter()
                    .any(|finding| finding.rule == Rule::TenantLaneViolation),
                "nested fake::sqlx imports must never mint trusted provenance: {findings:?}"
            );
        }
    }

    #[test]
    fn dead_or_unawaited_mutations_are_not_writer_evidence() {
        for (case, bait) in [
            (
                "dead-branch",
                "if false { sqlx::query(\"UPDATE roles SET id = id\").execute(tx.conn()).await; }",
            ),
            (
                "unawaited-async",
                "let _unused = async { sqlx::query(\"UPDATE roles SET id = id\").execute(tx.conn()).await; };",
            ),
        ] {
            let source = format!(
                "struct R {{ writer: PgTenantWritePool }} impl R {{ async fn f(&self){{ \
                 self.writer.write(tenant, |tx| Box::pin(async move {{ {bait} \
                 sqlx::query(\"SELECT * FROM roles\").fetch_all(tx.conn()).await }}), storage); }} }}"
            );
            let (_, findings) =
                scan_guard(&migrations(), &files(&[("role_repo.rs", source.as_str())]));
            assert!(
                findings.iter().any(|finding| {
                    finding.rule == Rule::TenantLaneViolation
                        && finding.detail.contains("SELECT-only writer transaction")
                }),
                "{case} mutation bait must not satisfy the writer lane: {findings:?}"
            );
        }

        for (case, bait) in [
            ("dead-helper", "if false { mutate(tx).await; }"),
            ("unawaited-helper", "let _unused = mutate(tx);"),
        ] {
            let source = format!(
                "async fn mutate(tx: &mut TxCapability<'_>) {{ \
                 sqlx::query(\"UPDATE roles SET id = id\").execute(tx.conn()).await; }} \
                 struct R {{ writer: PgTenantWritePool }} impl R {{ async fn f(&self){{ \
                 self.writer.write(tenant, |tx| Box::pin(async move {{ {bait} \
                 sqlx::query(\"SELECT * FROM roles\").fetch_all(tx.conn()).await }}), storage); }} }}"
            );
            let (_, findings) =
                scan_guard(&migrations(), &files(&[("role_repo.rs", source.as_str())]));
            assert!(
                findings.iter().any(|finding| {
                    finding.rule == Rule::TenantLaneViolation
                        && finding.detail.contains("SELECT-only writer transaction")
                }),
                "{case} must not merge helper mutation evidence: {findings:?}"
            );
        }
    }

    #[test]
    fn advisory_lock_evidence_requires_an_actual_function_call() {
        for bait in [
            "SELECT pg_advisory_xact_lock AS bait FROM roles",
            "SELECT role_id AS pg_advisory_xact_lock FROM roles",
        ] {
            let source = format!(
                "struct R {{ writer: PgTenantWritePool }} impl R {{ async fn f(&self){{ \
                 self.writer.write(tenant, |tx| Box::pin(async move {{ \
                 sqlx::query(\"{bait}\").fetch_all(tx.conn()).await }}), storage); }} }}"
            );
            let (_, findings) =
                scan_guard(&migrations(), &files(&[("role_repo.rs", source.as_str())]));
            assert!(
                findings.iter().any(|finding| {
                    finding.rule == Rule::TenantLaneViolation
                        && finding.detail.contains("SELECT-only writer transaction")
                }),
                "advisory-lock identifier bait must fail closed: {findings:?}"
            );
        }

        let (_, green) = scan_guard(
            &migrations(),
            &files(&[(
                "role_repo.rs",
                "struct R { writer: PgTenantWritePool } impl R { async fn f(&self){ \
                 self.writer.write(tenant, |tx| Box::pin(async move { \
                 sqlx::query(\"SELECT pg_advisory_xact_lock($1)\").execute(tx.conn()).await }), storage); } }",
            )]),
        );
        assert!(
            green
                .iter()
                .all(|finding| finding.rule != Rule::TenantLaneViolation),
            "a real advisory lock call is valid locking evidence: {green:?}"
        );
    }

    #[test]
    fn green_writer_selects_with_lock_or_mutation_evidence_pass() {
        let (_, findings) = scan_guard(
            &migrations(),
            &files(&[(
                "role_repo.rs",
                "struct R { writer: PgTenantWritePool } \
                 async fn locked(&self){ self.writer.write(tenant, |conn| Box::pin(async move { \
                     sqlx::query(\"SELECT * FROM roles FOR UPDATE\").fetch_optional(&mut *conn).await \
                 }), storage); } \
                 async fn mutated(&self){ self.writer.write(tenant, |conn| Box::pin(async move { \
                     sqlx::query(\"SELECT * FROM roles\").fetch_optional(&mut *conn).await?; \
                     sqlx::query(\"UPDATE roles SET id = id\").execute(&mut *conn).await \
                 }), storage); }",
            )]),
        );
        assert!(
            findings
                .iter()
                .all(|finding| finding.rule != Rule::TenantLaneViolation),
            "write evidence must remain valid: {findings:?}"
        );
    }

    #[test]
    fn outbox_settlement_function_calls_are_exact_mutation_evidence() {
        for function in [
            "rss_outbox_settle_published",
            "rss_outbox_settle_retry",
            "rss_outbox_mark_dlx",
        ] {
            let source = format!(
                "struct R {{ writer: PgTenantWritePool }} impl R {{ async fn settle(&self) {{ \
                 self.writer.write(tenant, |conn| Box::pin(async move {{ \
                 sqlx::query(\"SELECT {function}($1, $2, $3)\").execute(&mut *conn).await \
                 }}), storage); }} }}"
            );
            let (_, findings) =
                scan_guard(&migrations(), &files(&[("settlement.rs", source.as_str())]));
            assert!(
                findings
                    .iter()
                    .all(|finding| finding.rule != Rule::TenantLaneViolation),
                "exact settlement function call must be mutation evidence: {findings:?}"
            );
        }

        for bait in [
            "SELECT rss_outbox_settle_published FROM roles",
            "SELECT rss_outbox_settle_published_broken($1, $2, $3)",
        ] {
            let source = format!(
                "struct R {{ writer: PgTenantWritePool }} impl R {{ async fn settle(&self) {{ \
                 self.writer.write(tenant, |conn| Box::pin(async move {{ \
                 sqlx::query(\"{bait}\").execute(&mut *conn).await \
                 }}), storage); }} }}"
            );
            let (_, findings) =
                scan_guard(&migrations(), &files(&[("settlement.rs", source.as_str())]));
            assert!(
                findings.iter().any(|finding| {
                    finding.rule == Rule::TenantLaneViolation
                        && finding.detail.contains("SELECT-only writer transaction")
                }),
                "settlement function name bait must fail closed: {findings:?}"
            );
        }
    }

    #[test]
    fn red_tenant_repository_cannot_store_raw_pool_or_store() {
        let cases = [
            (
                "raw-pool",
                "struct Repo { database: sqlx::PgPool } fn sql_site(){ sqlx::query(\"SELECT * FROM roles\"); }",
                "PgPool",
            ),
            (
                "raw-store",
                "struct Repo { store: PgStore } fn sql_site(){ sqlx::query(\"SELECT * FROM roles\"); }",
                "PgStore",
            ),
        ];

        for (case, source, forbidden_type) in cases {
            let (_, findings) = scan_guard(&migrations(), &files(&[("role_repo.rs", source)]));
            assert!(
                findings.iter().any(|finding| {
                    finding.subject.starts_with("role_repo.rs")
                        && finding.detail.contains(forbidden_type)
                }),
                "{case} must not let a tenant repository retain a raw connection capability: {findings:?}"
            );
        }
    }

    #[test]
    fn green_distinct_read_and_write_lanes_accept_their_owned_sql() {
        let (_, findings) = scan_guard(
            &migrations(),
            &files(&[(
                "role_repo.rs",
                "struct R { reader: PgTenantReadPool, writer: PgTenantWritePool } \
                 async fn load(&self){ self.reader.read(tenant, |conn| Box::pin(async move { \
                     sqlx::query(\"SELECT * FROM roles\").fetch_optional(&mut *conn).await \
                 })); } \
                 async fn mutate(&self){ self.writer.write(tenant, |conn| Box::pin(async move { \
                     sqlx::query(\"SELECT * FROM roles\").fetch_optional(&mut *conn).await?; \
                     sqlx::query(\"UPDATE roles SET id = id\").execute(&mut *conn).await \
                 }), storage); }",
            )]),
        );

        assert!(
            findings
                .iter()
                .all(|finding| !finding.subject.starts_with("role_repo.rs")),
            "independent SELECT belongs to the reader; SELECT inside a write transaction remains valid: {findings:?}"
        );
    }

    #[test]
    fn anti_vacuity_missing_typed_read_and_write_lane_sites_is_reported() {
        let (_, findings) = scan_guard(
            &migrations(),
            &files(&[(
                "role_repo.rs",
                "fn sql_site(){ sqlx::query(\"SELECT * FROM roles\"); }",
            )]),
        );

        for required in ["PgTenantReadPool::read", "PgTenantWritePool::write"] {
            assert!(
                findings
                    .iter()
                    .any(|finding| finding.detail.contains(required)),
                "typed lane guard must fail closed when required production site `{required}` disappears: {findings:?}"
            );
        }
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
            "use crate::tx_retry::{run_pg_tx_retry as retry}; impl Uow { async fn commit_authorized(&self){ retry(SETTINGS_CONFIG_BOUNDARY, |_attempt, deadline| async { self.pool.retry_producer_tx(scope, deadline) }, classify).await; } }",
            &mut sites,
        );
        assert!(findings.is_empty(), "{findings:?}");
        assert!(sites.contains("settings-config-commit"));
    }

    #[test]
    fn retry_guard_rejects_settings_retry_outside_private_authorized_funnel() {
        let mut sites = BTreeSet::new();
        let findings = retry_placement_findings(
            "config_repo.rs",
            "impl Uow { async fn commit_publish(&self){ run_pg_tx_retry(SETTINGS_CONFIG_BOUNDARY, || async { self.pool.retry_producer_tx() }, classify).await; } }",
            &mut sites,
        );
        assert!(
            findings
                .iter()
                .any(|finding| finding.rule == Rule::RetryPlacement),
            "public route-specific methods must delegate to the single authorized retry funnel"
        );
    }

    #[test]
    fn retry_guard_accepts_local_wrapper_alias_with_typed_identity_command() {
        let mut sites = BTreeSet::new();
        let findings = retry_placement_findings(
            "credential_repo.rs",
            "use crate::tx_retry::{run_pg_localtx_retry as retry}; impl Repo { async fn apply_password_change(&self, mutation: PasswordChangeMutation){ let (_, _, observation) = mutation.into_parts(); retry(observation, |_attempt, deadline| async { self.pool.retry_write(scope, deadline) }, classify).await; } }",
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
            |_attempt, deadline| async { self.pool.retry_write(scope, deadline) },
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
            "impl Uow { async fn commit(&self){ run_pg_localtx_retry(SETTINGS_CONFIG_BOUNDARY, observation, || async { self.pool.retry_producer_tx() }, classify).await; } }",
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
            "use crate::tx_retry as retry; impl Uow { async fn commit_authorized(&self){ retry::run_pg_tx_retry(SETTINGS_CONFIG_BOUNDARY, |_attempt, deadline| async { self.pool.retry_producer_tx(scope, deadline) }, classify).await; } }",
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
        assert_retry_shape(
            &mut sites,
            "config_repo.rs",
            "impl Uow { async fn commit_authorized(&self){ run_pg_tx_retry(SETTINGS_CONFIG_BOUNDARY, |_attempt, deadline| async { self.pool.retry_producer_tx(scope, deadline) }, classify).await; } }",
        );
        assert_retry_shape(
            &mut sites,
            "credential_repo.rs",
            "impl Repo { async fn apply_password_change(&self, mutation: PasswordChangeMutation){ let (_, _, observation) = mutation.into_parts(); run_pg_localtx_retry(observation, |_attempt, deadline| async { self.pool.retry_write(scope, deadline) }, classify).await; } }",
        );
        assert_retry_shape(
            &mut sites,
            "auth_grant_lifecycle.rs",
            "impl Repo { async fn close(&self, mutation: AuthGrantCloseCommand){ let (_, observation) = mutation.into_parts(); run_pg_localtx_retry(observation, |_attempt, deadline| async { self.pool.retry_write(scope, deadline) }, classify).await; } }",
        );
        assert_retry_shape(
            &mut sites,
            "refresh_token_store.rs",
            "impl Repo { async fn rotate(&self, mutation: RefreshRotationMutation){ let (_, observation) = mutation.into_parts(); run_pg_localtx_retry(observation, |_attempt, deadline| async { self.pool.retry_write(scope, deadline) }, classify).await; } }",
        );
        assert_retry_shape(
            &mut sites,
            "audit_repo.rs",
            "impl Repo { async fn append(&self){ run_pg_tx_retry(AUDIT_APPEND_BOUNDARY, |_attempt, deadline| async { self.pool.retry_write(scope, deadline) }, classify).await; } }",
        );
        assert_retry_shape(
            &mut sites,
            "auth_audit_sink.rs",
            "impl AuditListTenantAppender for PgAuthAuditSink { async fn append(&self, command: AuditListTenantAppend){ let (scope, event, observation) = command.into_parts(); run_pg_localtx_retry(observation, |_attempt, deadline| async { self.pool.retry_write(scope, deadline, |_tx| async { persist(event) }, storage) }, classify).await; } }",
        );
        assert_retry_shape(&mut sites, "secret_repo.rs", secret_retry_green_source());
        assert_eq!(
            sites,
            BTreeSet::from([
                "audit-append",
                "audit-list-tenant-append",
                "identity-password-change",
                "identity-refresh-rotate",
                "identity-session-logout",
                "settings-config-commit",
                "settings-secret-publish",
                "settings-secret-publish-internal",
                "settings-secret-republish",
            ])
        );
    }

    fn assert_retry_shape(sites: &mut BTreeSet<&'static str>, rel: &str, source: &str) {
        let findings = retry_placement_findings(rel, source, sites);
        assert!(findings.is_empty(), "{rel}: {findings:?}");
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
            (
                "auth_audit_sink.rs",
                "impl AuditListTenantAppender for PgAuthAuditSink { async fn append(&self, command: AuditListTenantAppend){ let (scope, event, observation) = command.into_parts(); run_pg_tx_retry(AUDIT_APPEND_BOUNDARY, || async { self.pool.retry_write(scope, |_tx| async { persist(event) }, storage) }, classify).await; } }",
            ),
            (
                "auth_audit_sink.rs",
                "impl AuditListTenantAppender for PgAuthAuditSink { async fn append(&self, command: AuditListTenantAppend){ let (scope, event, observation) = command.into_parts(); run_pg_localtx_retry(observation, || async { raw_write(event) }, classify).await; } }",
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
                    | "auth_grant_lifecycle.rs"
                    | "refresh_token_store.rs"
                    | "audit_repo.rs"
                    | "auth_audit_sink.rs"
            )
        }) {
            let source = strip_cfg_test_modules(source);
            findings.extend(retry_placement_findings(rel, &source, &mut sites));
        }
        assert!(findings.is_empty(), "{findings:?}");
        assert_eq!(
            sites,
            BTreeSet::from([
                "identity-password-change",
                "identity-refresh-rotate",
                "identity-session-logout",
                "audit-append",
                "audit-list-tenant-append",
                "settings-config-commit",
                "settings-secret-publish",
                "settings-secret-publish-internal",
                "settings-secret-republish",
            ])
        );
        Ok(())
    }

    #[test]
    fn localtx_deadline_guard_rejects_legacy_missing_forged_and_escaped_tokens() {
        for (rel, source) in [
            (
                "config_repo.rs",
                "impl Uow { async fn commit(&self){ run_pg_tx_retry(SETTINGS_CONFIG_BOUNDARY, |_attempt| async { self.pool.retry_producer_tx(scope) }, classify).await; } }",
            ),
            (
                "config_repo.rs",
                "impl Uow { async fn commit(&self){ run_pg_tx_retry(SETTINGS_CONFIG_BOUNDARY, |_attempt, deadline| async { self.pool.retry_producer_tx(scope) }, classify).await; } }",
            ),
            (
                "config_repo.rs",
                "impl Uow { async fn commit(&self){ run_pg_tx_retry(SETTINGS_CONFIG_BOUNDARY, |attempt, deadline| async { self.pool.retry_producer_tx(scope, attempt) }, classify).await; } }",
            ),
            (
                "config_repo.rs",
                "impl Uow { async fn commit(&self){ run_pg_tx_retry(SETTINGS_CONFIG_BOUNDARY, |_attempt, deadline| async { inspect(deadline); self.pool.retry_producer_tx(scope, deadline) }, classify).await; } }",
            ),
            (
                "config_repo.rs",
                "impl Uow { async fn commit(&self){ let forged = LocalTxDeadline { operation: now, final_settlement: now }; run_pg_tx_retry(SETTINGS_CONFIG_BOUNDARY, |_attempt, deadline| async { self.pool.retry_producer_tx(scope, deadline) }, classify).await; } }",
            ),
            (
                "config_repo.rs",
                "impl Uow { async fn commit(&self){ let forged = LocalTxDeadline\n{ operation: now, final_settlement: now }; run_pg_tx_retry(SETTINGS_CONFIG_BOUNDARY, |_attempt, deadline| async { self.pool.retry_producer_tx(scope, deadline) }, classify).await; } }",
            ),
            (
                "config_repo.rs",
                "impl Uow { async fn commit(&self){ run_pg_tx_retry(SETTINGS_CONFIG_BOUNDARY, |_attempt, deadline| { let deadline = forged; async { self.pool.retry_producer_tx(scope, deadline) } }, classify).await; } }",
            ),
            (
                "config_repo.rs",
                "impl Uow { async fn commit(&self){ run_pg_tx_retry(SETTINGS_CONFIG_BOUNDARY, |_attempt, mut deadline| { deadline = forged; async { self.pool.retry_producer_tx(scope, deadline) } }, classify).await; } }",
            ),
            (
                "config_repo.rs",
                "impl Uow { async fn commit(&self){ run_pg_tx_retry(SETTINGS_CONFIG_BOUNDARY, |_attempt, deadline| async { if false { self.pool.retry_producer_tx(scope, deadline).await } else { forged().await } }, classify).await; } }",
            ),
            (
                "config_repo.rs",
                "impl LocalTxDeadline { fn reset(self) -> Self { Self { operation: now, final_settlement: now } } }",
            ),
            (
                "cotx/mod.rs",
                "impl<L> PgWritePool<L> { pub(crate) async fn retry_write(&self, scope: Scope) {} pub(crate) async fn retry_producer_tx(&self, scope: Scope) {} }",
            ),
            ("cotx/mod.rs", "async fn set_local_retry_lock_timeout() {}"),
        ] {
            let mut sites = BTreeSet::new();
            let findings = retry_placement_findings(rel, source, &mut sites);
            assert!(
                findings
                    .iter()
                    .any(|finding| finding.rule == Rule::RetryPlacement),
                "deadline bypass must fail closed for {rel}: {findings:?}"
            );
        }
    }

    #[test]
    fn localtx_deadline_observation_guard_rejects_rogue_and_fabricated_stages() {
        let canonical = r#"
async fn run_pg_tx_retry_core(on_failed: impl FnMut(), on_deadline: impl FnMut()) {
    if let Err(error) = &result {
        on_failed(attempt, error.class(), settlement, error.deadline_stages());
    }
    if backoff_exhausted.load(Ordering::Relaxed) {
        on_deadline(LocalTxDeadlineStage::Backoff);
    }
}
async fn run_pg_localtx_retry(observation: LocalTxObservation<M>) {
    run_pg_tx_retry_core(
        op,
        classify,
        |attempt, retry_class, settlement, stages| {
            observation.record_failed_attempt(attempt, retry_class, settlement);
            for stage in stages.into_iter().flatten() {
                observation.record_deadline_exceeded(stage);
            }
        },
        |stage| observation.record_deadline_exceeded(stage),
    ).await;
}
"#;
        let cases = [
            (
                "config_repo.rs",
                "fn rogue(observation: LocalTxObservation<M>) { observation.record_deadline_exceeded(LocalTxDeadlineStage::Commit); }".to_owned(),
            ),
            (
                "tx_retry.rs",
                canonical.replace(
                    "observation.record_deadline_exceeded(stage);",
                    "observation.record_deadline_exceeded(LocalTxDeadlineStage::Commit);",
                ),
            ),
            (
                "tx_retry.rs",
                canonical.replace(
                    "|stage| observation.record_deadline_exceeded(stage)",
                    "|stage| observation.record_deadline_exceeded(LocalTxDeadlineStage::Backoff)",
                ),
            ),
        ];
        for (rel, source) in cases {
            let source_files = if rel == "tx_retry.rs" {
                vec![("tx_retry.rs".to_owned(), source)]
            } else {
                vec![
                    ("tx_retry.rs".to_owned(), canonical.to_owned()),
                    (rel.to_owned(), source),
                ]
            };
            let findings = localtx_deadline_observation_findings(&source_files);
            assert!(
                findings
                    .iter()
                    .any(|finding| finding.rule == Rule::RetryPlacement),
                "deadline observation bypass must remain synthetic-red for {rel}: {findings:?}"
            );
        }
    }

    #[test]
    fn localtx_deadline_observation_guard_real_workspace_closes_exact_sink() -> Result<()> {
        let root = crate::workspace_root()?;
        let files = load_workspace_prod_rs(&root)?;
        let findings = localtx_deadline_observation_findings(&files);
        assert!(findings.is_empty(), "{findings:?}");
        Ok(())
    }

    #[test]
    fn localtx_deadline_authority_rejects_alias_self_reset_and_per_attempt_mint() {
        let green = deadline_authority_green_source();
        assert!(localtx_deadline_authority_findings(green).is_empty());
        let cases = [
            green.replacen(
                "LocalTxDeadline::mint(localtx_execution_budget())",
                "Self::mint(localtx_execution_budget())",
                1,
            ),
            green
                .replacen(
                    "pub(crate) struct LocalTxDeadline",
                    "type DeadlineAlias = LocalTxDeadline;\npub(crate) struct LocalTxDeadline",
                    1,
                )
                .replacen(
                    "LocalTxDeadline::mint(localtx_execution_budget())",
                    "DeadlineAlias::mint(localtx_execution_budget())",
                    1,
                ),
            green.replacen(
                "let deadline = LocalTxDeadline::mint(localtx_execution_budget());\n    run_tx_retry(policy, move || op(deadline)).await",
                "run_tx_retry(policy, move || { let deadline = LocalTxDeadline::mint(localtx_execution_budget()); op(deadline) }).await",
                1,
            ),
            green.replacen(
                "async fn run_pg_tx_retry_core()",
                "impl LocalTxDeadline { fn reset(self) -> Self { Self { operation: self.operation, final_settlement: self.final_settlement } } }\nasync fn run_pg_tx_retry_core()",
                1,
            ),
        ];
        for source in cases {
            assert!(
                !localtx_deadline_authority_findings(&source).is_empty(),
                "mint authority bypass must fail closed: {source}"
            );
        }
    }

    #[test]
    fn localtx_deadline_guard_real_workspace_closes_mint_and_nine_dataflows() -> Result<()> {
        let root = crate::workspace_root()?;
        let files = load_prod_rs(&root.join("adapters/postgres/src"))?;
        let mut sites = BTreeSet::new();
        let mut findings = Vec::new();
        for (rel, source) in files.iter().filter(|(rel, _)| {
            matches!(
                rel.as_str(),
                "tx_retry.rs"
                    | "cotx/mod.rs"
                    | "config_repo.rs"
                    | "secret_repo.rs"
                    | "credential_repo.rs"
                    | "auth_grant_lifecycle.rs"
                    | "refresh_token_store.rs"
                    | "audit_repo.rs"
                    | "auth_audit_sink.rs"
            )
        }) {
            let source = strip_cfg_test_modules(source);
            findings.extend(retry_placement_findings(rel, &source, &mut sites));
        }
        assert!(findings.is_empty(), "{findings:?}");
        assert_eq!(sites.len(), 9, "{sites:?}");

        let runner = files
            .iter()
            .find(|(rel, _)| rel == "tx_retry.rs")
            .map(|(_, source)| source)
            .ok_or_else(|| anyhow::anyhow!("tx_retry.rs missing"))?;
        let runner = strip_cfg_test_modules(runner);
        let authority = localtx_deadline_authority_findings(&runner);
        assert!(authority.is_empty(), "{authority:?}");
        Ok(())
    }

    #[test]
    fn retry_guard_requires_the_closed_nine_site_set() {
        let files = vec![("tx_retry.rs".to_string(), String::new())];
        let findings = required_retry_site_findings(&files, &BTreeSet::new());
        assert_eq!(
            findings
                .iter()
                .filter(|finding| finding.rule == Rule::RetrySitesAbsent)
                .count(),
            9,
            "{findings:?}"
        );
        assert!(
            findings
                .iter()
                .any(|finding| finding.rule == Rule::RetryPlacement),
            "missing deadline authority must fail closed: {findings:?}"
        );
        assert!(
            findings
                .iter()
                .any(|finding| finding.subject == "identity-refresh-rotate")
        );
        assert!(
            findings
                .iter()
                .any(|finding| finding.subject == "audit-append")
        );
        assert!(
            findings
                .iter()
                .any(|finding| finding.subject == "audit-list-tenant-append")
        );
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

    #[test]
    fn dlx_lifecycle_repository_rejects_raw_cross_tenant_sql() {
        let red = dlx_lifecycle_funnel_findings(
            "PgDlxLifecycleRuntime DELETE FROM dead_letter pub fn pool(",
        );
        assert!(
            red.iter()
                .any(|finding| finding.rule == Rule::DlxLifecycleBypass)
        );
        assert!(
            red.iter()
                .any(|finding| finding.rule == Rule::DlxLifecycleSitesAbsent)
        );
    }
}
