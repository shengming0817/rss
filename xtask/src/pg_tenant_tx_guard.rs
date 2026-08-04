//! `pg-tenant-tx-guard` —— Postgres tenant-table raw-pool / TxManager bypass guard.
//!
//! INVARIANT: TENANCY-PG-TX-FUNNEL-01 { level = "Medium", exec = "check", source = "code", synthetic_red = "tests::red_core_file_exception_does_not_mask_raw_tenant_access", anti_vacuity = "tests::anti_vacuity_no_tenant_tables_or_files_or_sites" } —
//! Raw `sqlx::PgPool` / `PgStore` / direct connection / global transaction paths that reach tenant
//! tables are allowed only for explicitly named global infrastructure or maintenance exceptions.
//! Concern façade visibility and exact lane ownership are compile-time invariants and are not
//! duplicated by this scanner.
//!
//! This guard is a Medium backstop for the Hard typed wrapper in `adapters/postgres/src/cotx/`
//! and the canonical fact funnels in `outbox.rs` / `outbox_cdc.rs`.
//!
//! INVARIANT: LOCALTX-PG-RETRY-PLACEMENT-01 { level = "Medium", exec = "check", source = "code", synthetic_red = "tests::retry_guard_rejects_secret_contract_attribution_bypasses|tests::localtx_deadline_guard_rejects_legacy_missing_forged_and_escaped_tokens|tests::localtx_deadline_observation_guard_rejects_rogue_and_fabricated_stages|tests::localtx_quarantine_guard_rejects_legacy_single_file_cotx_shape", anti_vacuity = "tests::retry_guard_real_workspace_contains_all_exact_boundaries|tests::localtx_deadline_guard_real_workspace_closes_mint_and_six_dataflows|tests::localtx_deadline_observation_guard_real_workspace_closes_exact_sink" } —
//! Postgres retry wrappers are confined to their exact config, secret, and audit
//! mutation boundaries. Each LocalTx owner must consume its command-carried
//! generated observation beside `retry_write`; `PgSecretUnitOfWork::publish` is the only settings
//! secret LocalTx owner;
//! internal publish / republish must use the generic runner and may not impersonate the HTTP
//! contract. Deadline observations are emitted only by the typed retry runner: attempt stages must
//! originate from `LocalTxRetryError::deadline_stages`, and backoff exhaustion from the canonical
//! runner callback.
//!
//! INVARIANT: IDENTITY-SECURITY-SQL-OWNER-01 { level = "Medium", exec = "check", source = "code", synthetic_red = "tests::identity_security_sql_owner_gate_rejects_missing_and_extra_sites|tests::refresh_legacy_write_guard_rejects_old_ports_and_application_bypasses", anti_vacuity = "tests::identity_security_sql_owner_gate_accepts_live_workspace|tests::refresh_legacy_write_guard_accepts_live_workspace|producer_assurance::tests::workspace_refresh_writer_callsite_is_exact_and_non_vacuous" } —
//! password rotation, account status CAS, refresh-family revocation, and auth-grant revocation SQL
//! have one exact production owner: `identity_security_lifecycle.rs`. The password-change LocalTx
//! repository/retry seam is removed rather than retained as an alias. Refresh rotation and reuse
//! containment have no LocalTx observation/runner or legacy
//! `rotate`/`revoke_lineage`/`close` write port. The sole mutation entry is
//! `IdentitySecurityLifecycle::execute_refresh` and its producer transaction.
//!
//! INVARIANT: IDENTITY-REACTIVATION-ISOLATION-01 { level = "Medium", exec = "check", source = "code", synthetic_red = "tests::identity_reactivation_gate_rejects_producer_outbox_grant_and_family_paths", anti_vacuity = "tests::identity_reactivation_gate_accepts_live_workspace" } —
//! `execute_reactivation` reaches exactly one typed plain-write lane and the canonical account CAS,
//! but cannot reach producer/retry-producer, outbox, credential, refresh-family, or auth-grant
//! mutation paths through its same-file call graph.
//!
//! INVARIANT: PG-LOCALTX-QUARANTINE-FUNNEL-01 { level = "Medium", exec = "check", source = "code", synthetic_red = "tests::localtx_quarantine_guard_rejects_bypass_and_escape_classes", anti_vacuity = "tests::localtx_quarantine_guard_real_workspace_closes_exact_sites" } —
//! all four LocalTx entries must flow through one typed execution core that acquires and begins
//! through the private armed lease, then tail-settles the exact branded transaction once. The core
//! carries one runner-minted deadline policy through every bounded stage; every non-retrying plain
//! transaction installs the same five-second PostgreSQL lock timeout without a caller-selectable
//! bypass. The wrapper borrow-binds that transaction
//! to its lease's closed quarantine stage; only a top-level consuming commit/rollback ACK may clear
//! it. The lease, wrapper, settlement dataflow, observability, and `close_on_drop` fallback are
//! closed against conditional, helper, raw, macro, and disarm escapes.
//!
//! INVARIANT: TENANCY-SECRET-KEY-MUTATION-01 { level = "Medium", exec = "check", source = "code", synthetic_red = "tests::secret_ref_mutation_guard_rejects_split_or_legacy_owners", anti_vacuity = "tests::secret_ref_mutation_guard_real_workspace_has_exact_sql_sites" } —
//! production `secret_refs` mutations are append-only INSERTs confined to the transaction-bound
//! `cotx::identity::LockedSecretKey::{cas_insert,append_tombstone}` facade. Its key-scoped advisory
//! lock is owned by `cotx::identity::SecretWrite::lock_key`; the exact lane types make the remaining
//! transaction and capability ownership constraints compile-time properties.
//!
//! INVARIANT: OUTBOX-FACT-FUNNEL-01 { level = "Medium", exec = "check", source = "code", synthetic_red = "tests::red_outbox_log_insert_outside_cdc_funnel", anti_vacuity = "tests::green_outbox_log_insert_is_owned_by_cdc_funnel" } —
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
    RawOutboxInsert,
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
    /// Password/account-security SQL escaped the canonical identity security lifecycle owner.
    IdentitySecuritySqlOwnerBypass,
    /// A required canonical password/account-security SQL site disappeared or was duplicated.
    IdentitySecuritySqlOwnerSitesAbsent,
    /// A removed refresh/AuthGrant write API recreated a second mutation funnel.
    IdentityRefreshWriteBypass,
    /// Account reactivation reached producer/outbox/credential/grant/family side effects.
    IdentityReactivationBypass,
    /// The exact non-producing account reactivation write path disappeared.
    IdentityReactivationSitesAbsent,
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
        let (summary, mut findings) = scan_guard(&migrations, &files);
        findings.extend(load_fault_matrix_governance_findings(
            &migrations,
            &root.join("adapters/postgres/src"),
        )?);
        findings.extend(identity_security_sql_funnel_findings(&files));
        findings.extend(localtx_required_carriers_missing(&files));
        findings.extend(localtx_deadline_observation_findings(&workspace_files));
        findings.extend(refresh_legacy_write_findings(&workspace_files));
        let dlx_path = root.join("adapters/postgres/src/dlx_lifecycle.rs");
        let dlx_source = std::fs::read_to_string(&dlx_path)
            .with_context(|| format!("读 {} 失败", dlx_path.display()))?;
        findings.extend(dlx_lifecycle_funnel_findings(&dlx_source));
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
                    "tenant tables {:?} touched through raw pattern {:?}; use exact-lane TenantDb scoped methods",
                    hit.tables, hit.pattern
                ),
            )
        }));
        findings.extend(raw_outbox_hits.iter().map(|hit| {
            finding(
                Rule::RawOutboxInsert,
                site_subject(rel, hit.line),
                "outbox rows must be created through the closed outbox append facade",
            )
        }));
    }
    Ok(findings)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum IdentitySecuritySqlKind {
    PasswordCas,
    AccountCas,
    RefreshFamilyRevoke,
    AuthGrantRevoke,
    OutboxAppend,
}

impl IdentitySecuritySqlKind {
    fn label(self) -> &'static str {
        match self {
            Self::PasswordCas => "password CAS",
            Self::AccountCas => "account-security CAS",
            Self::RefreshFamilyRevoke => "refresh-family revocation",
            Self::AuthGrantRevoke => "auth-grant revocation",
            Self::OutboxAppend => "outbox append",
        }
    }
}

#[derive(Debug, Clone)]
struct IdentitySecuritySqlSite {
    path: String,
    function: String,
    kind: IdentitySecuritySqlKind,
}

fn identity_security_sql_funnel_findings(files: &[(String, String)]) -> Vec<Finding> {
    const SQL_OWNER: &str = "cotx/identity.rs";
    const LIFECYCLE_OWNER: &str = "identity_security_lifecycle.rs";
    let mut findings = Vec::new();
    let mut sites = Vec::new();
    let mut owner_syntax = None;
    for (path, source) in files {
        let Ok(syntax) = syn::parse_file(&strip_cfg_test_modules(source)) else {
            if path == LIFECYCLE_OWNER {
                findings.push(finding(
                    Rule::IdentitySecuritySqlOwnerSitesAbsent,
                    LIFECYCLE_OWNER,
                    "canonical identity security lifecycle cannot be parsed",
                ));
            }
            continue;
        };
        sites.extend(identity_security_sql_sites(path, &syntax));
        if path == LIFECYCLE_OWNER {
            owner_syntax = Some(syntax);
        }
    }

    for kind in [
        IdentitySecuritySqlKind::PasswordCas,
        IdentitySecuritySqlKind::AccountCas,
        IdentitySecuritySqlKind::RefreshFamilyRevoke,
        IdentitySecuritySqlKind::AuthGrantRevoke,
    ] {
        let matching = sites
            .iter()
            .filter(|site| site.kind == kind)
            .collect::<Vec<_>>();
        for site in matching.iter().filter(|site| site.path != SQL_OWNER) {
            findings.push(finding(
                Rule::IdentitySecuritySqlOwnerBypass,
                format!("{}::{}", site.path, site.function),
                format!("{} SQL must be owned only by {SQL_OWNER}", kind.label()),
            ));
        }
        let owner_count = matching
            .iter()
            .filter(|site| site.path == SQL_OWNER)
            .count();
        if owner_count != 1 || matching.len() != 1 {
            findings.push(finding(
                Rule::IdentitySecuritySqlOwnerSitesAbsent,
                format!("{SQL_OWNER}::{}", kind.label()),
                format!(
                    "expected exactly one canonical {} SQL site; owner_count={owner_count} total_count={}",
                    kind.label(),
                    matching.len()
                ),
            ));
        }
    }

    match owner_syntax {
        Some(syntax) => findings.extend(identity_reactivation_findings(LIFECYCLE_OWNER, &syntax)),
        None => findings.push(finding(
            Rule::IdentityReactivationSitesAbsent,
            format!("{LIFECYCLE_OWNER}::execute_reactivation"),
            "canonical identity security lifecycle is missing",
        )),
    }
    findings
}

fn identity_security_sql_sites(path: &str, syntax: &syn::File) -> Vec<IdentitySecuritySqlSite> {
    struct Scan<'a> {
        path: &'a str,
        constants: &'a BTreeMap<String, String>,
        function: Option<String>,
        sites: Vec<IdentitySecuritySqlSite>,
    }

    impl<'ast> syn::visit::Visit<'ast> for Scan<'_> {
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

        fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
            if let Some(kind) = identity_security_sql_call_kind(node, self.constants) {
                self.sites.push(IdentitySecuritySqlSite {
                    path: self.path.to_owned(),
                    function: self
                        .function
                        .clone()
                        .unwrap_or_else(|| "<module>".to_owned()),
                    kind,
                });
            }
            syn::visit::visit_expr_call(self, node);
        }

        fn visit_expr_macro(&mut self, node: &'ast syn::ExprMacro) {
            if let Some(kind) = identity_security_sql_macro_kind(node, self.constants) {
                self.sites.push(IdentitySecuritySqlSite {
                    path: self.path.to_owned(),
                    function: self
                        .function
                        .clone()
                        .unwrap_or_else(|| "<module>".to_owned()),
                    kind,
                });
            }
            syn::visit::visit_expr_macro(self, node);
        }
    }

    let constants = sql_string_constants(syntax);
    let mut scan = Scan {
        path,
        constants: &constants,
        function: None,
        sites: Vec::new(),
    };
    syn::visit::Visit::visit_file(&mut scan, syntax);
    scan.sites
}

fn identity_security_sql_call_kind(
    call: &syn::ExprCall,
    constants: &BTreeMap<String, String>,
) -> Option<IdentitySecuritySqlKind> {
    let syn::Expr::Path(path) = call.func.as_ref() else {
        return None;
    };
    if path.path.segments.last().is_none_or(|segment| {
        !matches!(
            segment.ident.to_string().as_str(),
            "query" | "query_as" | "query_scalar"
        )
    }) {
        return None;
    }
    resolve_static_sql_expr(call.args.first()?, constants)
        .as_deref()
        .and_then(identity_security_sql_kind)
}

fn identity_security_sql_macro_kind(
    expression: &syn::ExprMacro,
    constants: &BTreeMap<String, String>,
) -> Option<IdentitySecuritySqlKind> {
    use syn::parse::Parser as _;

    let name = expression.mac.path.segments.last()?.ident.to_string();
    if !matches!(name.as_str(), "query" | "query_as" | "query_scalar") {
        return None;
    }
    let arguments = syn::punctuated::Punctuated::<syn::Expr, syn::Token![,]>::parse_terminated
        .parse2(expression.mac.tokens.clone())
        .ok()?;
    let sql_index = usize::from(name == "query_as");
    resolve_static_sql_expr(arguments.iter().nth(sql_index)?, constants)
        .as_deref()
        .and_then(identity_security_sql_kind)
}

fn identity_security_sql_kind(sql: &str) -> Option<IdentitySecuritySqlKind> {
    let sql = sql
        .split_ascii_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_lowercase();
    if sql.contains("update credentials")
        && sql.contains("password_hash")
        && sql.contains("version =")
    {
        Some(IdentitySecuritySqlKind::PasswordCas)
    } else if sql.contains("update account_security_states")
        && sql.contains("set status =")
        && sql.contains("authn_epoch =")
        && sql.contains("version =")
    {
        Some(IdentitySecuritySqlKind::AccountCas)
    } else if sql.contains("update refresh_tokens")
        && sql.contains("status = 'revoked'")
        && sql.contains("from auth_grants as root")
        && sql.contains("root.tenant_id")
        && sql.contains("root.user_id")
        && sql.contains("refresh.tenant_id = root.tenant_id")
        && sql.contains("refresh.auth_grant_id = root.grant_id")
    {
        Some(IdentitySecuritySqlKind::RefreshFamilyRevoke)
    } else if sql.contains("update auth_grants set status = 'revoked'")
        && sql.contains("close_reason")
        && sql.contains("user_id")
    {
        Some(IdentitySecuritySqlKind::AuthGrantRevoke)
    } else if sql.contains("insert into outbox") {
        Some(IdentitySecuritySqlKind::OutboxAppend)
    } else {
        None
    }
}

#[derive(Default)]
struct ReactivationReachability {
    plain_writes: usize,
    forbidden_calls: Vec<String>,
    sql: BTreeMap<IdentitySecuritySqlKind, usize>,
    local_calls: BTreeSet<String>,
}

#[derive(Clone)]
struct IdentitySecurityCallable {
    self_ty: Option<String>,
    block: syn::Block,
}

fn identity_security_free_callable(name: &str) -> String {
    format!("identity_security_lifecycle::free::{name}")
}

fn identity_security_method_callable(self_ty: &str, name: &str) -> String {
    format!("identity_security_lifecycle::impl::{self_ty}::{name}")
}

fn identity_reactivation_findings(path: &str, syntax: &syn::File) -> Vec<Finding> {
    const REACTIVATION_OWNER: &str = "PgAccountReactivationLifecycle";
    let callables = identity_security_callables(syntax);
    let constants = sql_string_constants(syntax);
    let root_key = identity_security_method_callable(REACTIVATION_OWNER, "execute_reactivation");
    let roots = callables.get(&root_key).cloned().unwrap_or_default();
    let [root] = roots.as_slice() else {
        return vec![finding(
            Rule::IdentityReactivationSitesAbsent,
            format!("{path}::execute_reactivation"),
            format!(
                "expected one production execute_reactivation method, found {}",
                roots.len()
            ),
        )];
    };

    let mut aggregate = ReactivationReachability::default();
    let mut pending = vec![(root_key, root.clone())];
    let mut visited = BTreeSet::new();
    let mut ambiguous = Vec::new();
    while let Some((name, block)) = pending.pop() {
        if !visited.insert(name) {
            continue;
        }
        let scan = scan_reactivation_block(&block.block, &constants, block.self_ty.as_deref());
        aggregate.plain_writes += scan.plain_writes;
        aggregate.forbidden_calls.extend(scan.forbidden_calls);
        for (kind, count) in scan.sql {
            *aggregate.sql.entry(kind).or_default() += count;
        }
        for called in scan.local_calls {
            let Some(targets) = callables.get(&called) else {
                continue;
            };
            if targets.len() != 1 {
                ambiguous.push(called);
                continue;
            }
            pending.push((called, targets[0].clone()));
        }
    }

    let account_cas = aggregate
        .sql
        .get(&IdentitySecuritySqlKind::AccountCas)
        .copied()
        .unwrap_or_default();
    let forbidden_sql = aggregate
        .sql
        .iter()
        .filter(|(kind, _)| **kind != IdentitySecuritySqlKind::AccountCas)
        .map(|(kind, count)| format!("{}={count}", kind.label()))
        .collect::<Vec<_>>();
    let mut findings = Vec::new();
    if aggregate.plain_writes != 1 || account_cas != 1 || !ambiguous.is_empty() {
        findings.push(finding(
            Rule::IdentityReactivationSitesAbsent,
            format!("{path}::execute_reactivation"),
            format!(
                "reactivation must reach one unique typed plain write and one account CAS; writes={} account_cas={account_cas} ambiguous_helpers={ambiguous:?}",
                aggregate.plain_writes
            ),
        ));
    }
    if !aggregate.forbidden_calls.is_empty() || !forbidden_sql.is_empty() {
        findings.push(finding(
            Rule::IdentityReactivationBypass,
            format!("{path}::execute_reactivation"),
            format!(
                "reactivation reached forbidden producer/outbox/grant/family effects: calls={:?} sql={forbidden_sql:?}",
                aggregate.forbidden_calls
            ),
        ));
    }
    findings
}

fn identity_security_callables(
    syntax: &syn::File,
) -> BTreeMap<String, Vec<IdentitySecurityCallable>> {
    let mut callables = BTreeMap::<String, Vec<IdentitySecurityCallable>>::new();
    for item in &syntax.items {
        match item {
            syn::Item::Fn(function)
                if function.sig.asyncness.is_some()
                    && !attributes_are_test_only(&function.attrs) =>
            {
                callables
                    .entry(identity_security_free_callable(
                        &function.sig.ident.to_string(),
                    ))
                    .or_default()
                    .push(IdentitySecurityCallable {
                        self_ty: None,
                        block: (*function.block).clone(),
                    });
            }
            syn::Item::Impl(item) if !attributes_are_test_only(&item.attrs) => {
                let self_ty = compact_tokens(item.self_ty.as_ref());
                for method in &item.items {
                    if let syn::ImplItem::Fn(method) = method
                        && method.sig.asyncness.is_some()
                        && !attributes_are_test_only(&method.attrs)
                    {
                        callables
                            .entry(identity_security_method_callable(
                                &self_ty,
                                &method.sig.ident.to_string(),
                            ))
                            .or_default()
                            .push(IdentitySecurityCallable {
                                self_ty: Some(self_ty.clone()),
                                block: method.block.clone(),
                            });
                    }
                }
            }
            _ => {}
        }
    }
    callables
}

fn scan_reactivation_block(
    block: &syn::Block,
    constants: &BTreeMap<String, String>,
    self_ty: Option<&str>,
) -> ReactivationReachability {
    struct Scan<'a> {
        result: ReactivationReachability,
        constants: &'a BTreeMap<String, String>,
        self_ty: Option<&'a str>,
    }

    impl<'ast> syn::visit::Visit<'ast> for Scan<'_> {
        fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
            if let Some(kind) = identity_security_sql_call_kind(node, self.constants) {
                *self.result.sql.entry(kind).or_default() += 1;
            }
            if let syn::Expr::Path(path) = node.func.as_ref()
                && let Some(segment) = path.path.segments.last()
            {
                let name = segment.ident.to_string();
                let lower = name.to_ascii_lowercase();
                if lower.contains("outbox")
                    || lower.contains("grant")
                    || lower.contains("refresh")
                    || lower.contains("family")
                {
                    self.result.forbidden_calls.push(name.clone());
                }
                self.result
                    .local_calls
                    .insert(identity_security_free_callable(&name));
            }
            syn::visit::visit_expr_call(self, node);
        }

        fn visit_expr_macro(&mut self, node: &'ast syn::ExprMacro) {
            if let Some(kind) = identity_security_sql_macro_kind(node, self.constants) {
                *self.result.sql.entry(kind).or_default() += 1;
            }
            syn::visit::visit_expr_macro(self, node);
        }

        fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
            let name = node.method.to_string();
            let lower = name.to_ascii_lowercase();
            if matches!(
                node.receiver.as_ref(),
                syn::Expr::Path(path) if path.path.is_ident("self")
            ) && let Some(self_ty) = self.self_ty
            {
                self.result
                    .local_calls
                    .insert(identity_security_method_callable(self_ty, &name));
            }
            if name == "identity_write" {
                self.result.plain_writes += 1;
            }
            if name == "apply_account_state_cas" {
                *self
                    .result
                    .sql
                    .entry(IdentitySecuritySqlKind::AccountCas)
                    .or_default() += 1;
            }
            if matches!(
                name.as_str(),
                "producer_tx" | "identity_producer_tx" | "retry_producer_tx"
            ) || lower.contains("outbox")
                || lower.contains("grant")
                || lower.contains("refresh")
                || lower.contains("family")
            {
                self.result.forbidden_calls.push(name);
            }
            syn::visit::visit_expr_method_call(self, node);
        }
    }

    let mut scan = Scan {
        result: ReactivationReachability::default(),
        constants,
        self_ty,
    };
    syn::visit::Visit::visit_block(&mut scan, block);
    scan.result
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
    if crate::src_scan::is_crate_internal_integration_test_source(path) {
        return true;
    }
    let stem = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    stem == "test_pg.rs"
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
    findings.extend(fault_matrix_terminal_bypass_findings(files));
    findings.extend(localtx_quarantine_findings(files));

    for (rel, content) in files {
        findings.extend(scan_source_file(rel, content, &tenant_tables, &mut state));
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
        "{} tenant 表；{} 个生产文件；{} 个 tenant SQL 文件；{} 个 raw pattern",
        tenant_tables.len(),
        files.len(),
        state.tenant_sql_sites,
        state.raw_sites
    );
    (summary, findings)
}

fn localtx_quarantine_findings(files: &[(String, String)]) -> Vec<Finding> {
    let cotx = files.iter().find(|(path, _)| path == "cotx/mod.rs");
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
        tenant_calls: usize,
        plain_calls: usize,
        deadline_calls: usize,
        tenant_tx_mints: usize,
    }
    impl<'ast> syn::visit::Visit<'ast> for SetupScan {
        fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
            match exact_expr_path(&node.func).as_deref() {
                Some("set_local_tenant")
                    if node.args.len() == 2
                        && node.args.get(1).and_then(exact_expr_path).as_deref()
                            == Some("tenant") =>
                {
                    self.tenant_calls += 1;
                }
                Some("set_local_plain_lock_timeout")
                    if node.args.len() == 1
                        && node
                            .args
                            .first()
                            .is_some_and(|arg| compact_tokens(arg) == "&mut*conn") =>
                {
                    self.plain_calls += 1;
                }
                Some("set_local_retry_deadlines")
                    if node.args.len() == 2
                        && node
                            .args
                            .first()
                            .is_some_and(|arg| compact_tokens(arg) == "&mut*conn")
                        && node.args.get(1).and_then(exact_expr_path).as_deref()
                            == Some("deadline") =>
                {
                    self.deadline_calls += 1;
                }
                Some("TenantTx::from_bound_connection")
                    if node.args.len() == 2
                        && node.args.first().and_then(exact_expr_path).as_deref()
                            == Some("conn")
                        && node.args.get(1).and_then(exact_expr_path).as_deref()
                            == Some("tenant") =>
                {
                    self.tenant_tx_mints += 1;
                }
                _ => {}
            }
            syn::visit::visit_expr_call(self, node);
        }
    }
    let mut scan = SetupScan {
        tenant_calls: 0,
        plain_calls: 0,
        deadline_calls: 0,
        tenant_tx_mints: 0,
    };
    syn::visit::Visit::visit_block(&mut scan, &method.block);
    scan.plain_calls == 1
        && scan.deadline_calls == 1
        && scan.tenant_calls == 1
        && scan.tenant_tx_mints == 1
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
    let stages_closed = canonical_core_stages(&scan, &lease, &tx);
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

fn canonical_core_stages(scan: &CoreStageScan, lease: &str, transaction: &str) -> bool {
    let current = [
        ("acquire", 0, 0, vec!["pool".to_owned()]),
        ("begin", 1, 0, vec![format!("&mut{lease}")]),
        (
            "setup",
            2,
            0,
            vec![format!("{transaction}.connection()"), "tenant".to_owned()],
        ),
        (
            "operation",
            3,
            1,
            vec!["write.execute(&muttenant_tx)".to_owned()],
        ),
    ];
    let matches = |expected: [(&str, usize, usize, Vec<String>); 4]| {
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
    };
    matches(current)
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
    let Some((funnel_path, _)) = files.iter().find(|(path, _)| path == "cotx/mod.rs") else {
        return Vec::new();
    };
    let mut calls = Vec::new();
    for (path, source) in files
        .iter()
        .filter(|(path, _)| path == "cotx/mod.rs" || path.starts_with("cotx/"))
    {
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
    let has_cotx = files.iter().any(|(path, _)| path == "cotx/mod.rs");
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
    let transaction_surface = transaction_methods
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let transaction_surface_is_closed = transaction_traits.is_empty()
        && transaction_surface
            == BTreeSet::from([
                "connection",
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
    if !files.iter().any(|(rel, _)| rel == "cotx/identity.rs") {
        return Vec::new();
    }
    [
        "secret-key-advisory-lock",
        "secret-key-cas-insert",
        "secret-key-append-tombstone",
    ]
    .into_iter()
    .filter(|required| sites.get(required).copied() != Some(1))
    .map(|required| {
        finding(
            Rule::SecretRefMutationSitesAbsent,
            required,
            "cotx/identity.rs must own the exact keyed lock, CAS insert, and tombstone SQL sites",
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
    state.raw_sites += raw_hits.len() + raw_pool_field_hits.len() + outbox_insert_hits.len();

    findings.extend(outbox_insert_hits.iter().map(|hit| {
        finding(
            Rule::RawOutboxInsert,
            site_subject(rel, hit.line),
            "outbox rows must be created through the closed outbox append facade",
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
                "tenant tables {:?} touched through raw pattern {:?}; use exact-lane TenantDb scoped methods",
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
        runner_emissions == 2
            && generic_forwarders == 1
            && emissions.len() == 3
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

#[allow(
    clippy::cognitive_complexity,
    reason = "one closed scanner reports every legacy refresh write shape in a single pass"
)]
fn refresh_legacy_write_findings(files: &[(String, String)]) -> Vec<Finding> {
    const FORBIDDEN_TYPES: &[&str] = &[
        "AuthGrantCloseCommand",
        "AuthGrantCloseObservation",
        "RefreshRotationMutation",
        "RefreshRotationOutcome",
    ];

    let mut findings = Vec::new();
    for (rel, source) in files {
        if rel.contains("/src/")
            && !rel.starts_with("crates/identity/src/")
            && !rel.starts_with("adapters/postgres/src/")
        {
            continue;
        }
        let syntax = match syn::parse_file(source) {
            Ok(syntax) => syntax,
            Err(error) => {
                findings.push(finding(
                    Rule::IdentityRefreshWriteBypass,
                    rel,
                    format!("cannot parse production Rust for refresh write ownership: {error}"),
                ));
                continue;
            }
        };
        for item in &syntax.items {
            match item {
                syn::Item::Struct(item)
                    if !attributes_are_test_only(&item.attrs)
                        && FORBIDDEN_TYPES.contains(&item.ident.to_string().as_str()) =>
                {
                    findings.push(finding(
                        Rule::IdentityRefreshWriteBypass,
                        format!("{rel}::{}", item.ident),
                        "removed refresh/AuthGrant write command type must not return",
                    ));
                }
                syn::Item::Enum(item)
                    if !attributes_are_test_only(&item.attrs)
                        && FORBIDDEN_TYPES.contains(&item.ident.to_string().as_str()) =>
                {
                    findings.push(finding(
                        Rule::IdentityRefreshWriteBypass,
                        format!("{rel}::{}", item.ident),
                        "removed refresh/AuthGrant write outcome type must not return",
                    ));
                }
                syn::Item::Type(item)
                    if !attributes_are_test_only(&item.attrs)
                        && FORBIDDEN_TYPES.contains(&item.ident.to_string().as_str()) =>
                {
                    findings.push(finding(
                        Rule::IdentityRefreshWriteBypass,
                        format!("{rel}::{}", item.ident),
                        "removed refresh/AuthGrant write alias must not return",
                    ));
                }
                syn::Item::Trait(item) if !attributes_are_test_only(&item.attrs) => {
                    let trait_name = item.ident.to_string();
                    for member in &item.items {
                        let syn::TraitItem::Fn(method) = member else {
                            continue;
                        };
                        if attributes_are_test_only(&method.attrs) {
                            continue;
                        }
                        let forbidden = (trait_name == "RefreshTokenStoreLocal"
                            && matches!(
                                method.sig.ident.to_string().as_str(),
                                "rotate" | "revoke_lineage"
                            ))
                            || (trait_name == "AuthGrantLifecycleLocal"
                                && method.sig.ident == "close");
                        if forbidden {
                            findings.push(finding(
                                Rule::IdentityRefreshWriteBypass,
                                format!("{rel}::{trait_name}::{}", method.sig.ident),
                                "legacy write port bypasses IdentitySecurityLifecycle::execute_refresh",
                            ));
                        }
                    }
                }
                syn::Item::Impl(item) if !attributes_are_test_only(&item.attrs) => {
                    let trait_name = item
                        .trait_
                        .as_ref()
                        .and_then(|(_, path, _)| path.segments.last())
                        .map(|segment| segment.ident.to_string());
                    let self_type = type_last_ident(&item.self_ty).unwrap_or_default();
                    for member in &item.items {
                        let syn::ImplItem::Fn(method) = member else {
                            continue;
                        };
                        if attributes_are_test_only(&method.attrs) {
                            continue;
                        }
                        let method_name = method.sig.ident.to_string();
                        let forbidden_port = trait_name.as_deref().is_some_and(|trait_name| {
                            (matches!(trait_name, "RefreshTokenStore" | "RefreshTokenStoreLocal")
                                && matches!(method_name.as_str(), "rotate" | "revoke_lineage"))
                                || (matches!(
                                    trait_name,
                                    "AuthGrantLifecycle" | "AuthGrantLifecycleLocal"
                                ) && method_name == "close")
                        });
                        let forbidden_service = self_type == "RefreshService"
                            && matches!(
                                method_name.as_str(),
                                "revoke" | "compromise_replayed_grant"
                            );
                        if forbidden_port || forbidden_service {
                            findings.push(finding(
                                Rule::IdentityRefreshWriteBypass,
                                format!("{rel}::{self_type}::{method_name}"),
                                "legacy refresh write entry bypasses the sole security lifecycle producer",
                            ));
                        }
                    }
                }
                _ => {}
            }
        }
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
            Some("settings::secret_publish_localtx_observation")
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
        && call.arguments[1].operation_method.as_deref() == Some("retry_config_producer_tx")
        && call.arguments[1].scoped_operation_calls == 1
        && !call.arguments[1].legacy_write
        && call.arguments[1].deadline_dataflow
}

fn valid_audit_append_retry(call: &RetryCall) -> bool {
    call.wrapper == Some(RetryWrapper::Generic)
        && call.arguments.len() == 3
        && call.arguments[0].exact_path.as_deref() == Some("AUDIT_APPEND_BOUNDARY")
        && call.arguments[1].operation_method.as_deref() == Some("retry_audit_write")
        && call.arguments[1].scoped_operation_calls == 1
        && !call.arguments[1].legacy_write
        && call.arguments[1].deadline_dataflow
}

fn valid_audit_list_tenant_retry(call: &RetryCall) -> bool {
    call.wrapper == Some(RetryWrapper::Local)
        && call.arguments.len() == 3
        && call.arguments[0].command_evidence == Some(CommandEvidence::AuditListTenantAppend)
        && call.arguments[1].operation_method.as_deref() == Some("retry_auth_audit_write")
        && call.arguments[1].scoped_operation_calls == 1
        && !call.arguments[1].legacy_write
        && call.arguments[1].deadline_dataflow
}

fn valid_settings_secret_retry(call: &RetryCall) -> bool {
    call.wrapper == Some(RetryWrapper::Local)
        && call.arguments.len() == 3
        && call.arguments[0].command_evidence == Some(CommandEvidence::SecretPublish)
        && call.arguments[1].operation_method.as_deref() == Some("retry_secret_write")
        && call.arguments[1].scoped_operation_calls == 1
        && !call.arguments[1].legacy_write
        && call.arguments[1].deadline_dataflow
}

fn valid_settings_secret_generic_retry(call: &RetryCall) -> bool {
    call.wrapper == Some(RetryWrapper::Generic)
        && call.arguments.len() == 3
        && call.arguments[0].exact_path.as_deref() == Some("SETTINGS_SECRET_BOUNDARY")
        && call.arguments[1].operation_method.as_deref() == Some("retry_secret_write")
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
                format!("cannot parse production Rust for secret_refs SQL ownership: {error}"),
            )];
        }
    };
    let mut scan = SecretSqlScan {
        rel,
        current_impl: None,
        current_function: None,
        sites,
        findings: Vec::new(),
    };
    syn::visit::Visit::visit_file(&mut scan, &syntax);
    scan.findings
}

struct SecretSqlScan<'a> {
    rel: &'a str,
    current_impl: Option<String>,
    current_function: Option<String>,
    sites: &'a mut BTreeMap<&'static str, usize>,
    findings: Vec<Finding>,
}

impl SecretSqlScan<'_> {
    fn note_sql(&mut self, sql: &str, line: usize) {
        let normalized = normalize_sql(sql);
        let canonical_owner = self.rel == "cotx/identity.rs"
            && self.current_impl.as_deref() == Some("SecretWrite")
            && self.current_function.as_deref() == Some("lock_key");
        if exact_secret_key_lock_sql(&normalized) || canonical_owner {
            if canonical_owner && exact_secret_key_lock_sql(&normalized) {
                *self.sites.entry("secret-key-advisory-lock").or_default() += 1;
            } else {
                self.findings.push(finding(
                    Rule::SecretRefMutationBypass,
                    site_subject(self.rel, line),
                    "secret key advisory lock SQL must occur exactly once in cotx/identity.rs::SecretWrite::lock_key",
                ));
            }
        }
        let Some(kind) = secret_ref_mutation_kind(sql) else {
            return;
        };
        let canonical = if kind == SecretRefMutationKind::Insert
            && self.rel == "cotx/identity.rs"
            && self.current_impl.as_deref() == Some("LockedSecretKey")
        {
            match self.current_function.as_deref() {
                Some("cas_insert") => Some("secret-key-cas-insert"),
                Some("append_tombstone") => Some("secret-key-append-tombstone"),
                _ => None,
            }
        } else {
            None
        };
        if let Some(site) = canonical {
            *self.sites.entry(site).or_default() += 1;
        } else {
            self.findings.push(finding(
                Rule::SecretRefMutationBypass,
                site_subject(self.rel, line),
                "secret_refs mutations must be append-only INSERTs owned by cotx/identity.rs::LockedSecretKey::{cas_insert,append_tombstone}",
            ));
        }
    }
}

impl<'ast> syn::visit::Visit<'ast> for SecretSqlScan<'_> {
    fn visit_item_impl(&mut self, node: &'ast syn::ItemImpl) {
        let previous = self.current_impl.replace(impl_type_name(&node.self_ty));
        syn::visit::visit_item_impl(self, node);
        self.current_impl = previous;
    }

    fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
        let previous = self.current_function.replace(node.sig.ident.to_string());
        syn::visit::visit_impl_item_fn(self, node);
        self.current_function = previous;
    }

    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        let previous_impl = self.current_impl.take();
        let previous_function = self.current_function.replace(node.sig.ident.to_string());
        syn::visit::visit_item_fn(self, node);
        self.current_function = previous_function;
        self.current_impl = previous_impl;
    }

    fn visit_lit_str(&mut self, node: &'ast syn::LitStr) {
        self.note_sql(&node.value(), node.span().start().line);
    }

    fn visit_macro(&mut self, node: &'ast syn::Macro) {
        let sql = macro_string_literals(&node.tokens).join(" ");
        self.note_sql(&sql, node.path.span().start().line);
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

#[derive(Clone, Copy, PartialEq, Eq)]
enum SecretRefMutationKind {
    Insert,
    Destructive,
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

fn compact_tokens(tokens: &impl quote::ToTokens) -> String {
    tokens
        .to_token_stream()
        .to_string()
        .replace(char::is_whitespace, "")
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
                    "retry_write"
                        | "retry_secret_write"
                        | "retry_producer_tx"
                        | "retry_config_producer_tx"
                        | "retry_audit_write"
                        | "retry_auth_audit_write"
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
                "retry_write"
                | "retry_secret_write"
                | "retry_producer_tx"
                | "retry_config_producer_tx"
                | "retry_audit_write"
                | "retry_auth_audit_write" => self.calls += 1,
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
                "retry_write"
                    | "retry_secret_write"
                    | "retry_producer_tx"
                    | "retry_config_producer_tx"
                    | "retry_audit_write"
                    | "retry_auth_audit_write"
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

fn attributes_are_test_only(attributes: &[syn::Attribute]) -> bool {
    attributes.iter().any(|attribute| {
        attribute.path().is_ident("cfg") && compact_tokens(&attribute.meta).contains("test")
    })
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct SqlQuerySite {
    line: usize,
    column: usize,
    sql: Option<String>,
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
    for (needle, owner, symbols) in [
        (
            "insert into outbox",
            "cotx/eventing.rs",
            &["outbox_insert_generated", "outbox_insert_replayed"][..],
        ),
        (
            "insert into outbox_log",
            "cotx/eventing.rs",
            &["outbox_log_insert"][..],
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
                    ("cotx/eventing.rs", "outbox_insert_generated") => "outbox.rs::append_outbox",
                    ("cotx/eventing.rs", "outbox_insert_replayed") => {
                        "outbox.rs::append_replayed_outbox"
                    }
                    ("cotx/eventing.rs", "outbox_log_insert") => "outbox_cdc.rs::append_outbox_log",
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
    rel == "cotx/mod.rs" || rel.starts_with("cotx/")
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
                    "tenant tables {:?} share a file with raw capability field {:?}; tenant repositories must store an exact TenantDb lane",
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
    #![allow(clippy::expect_used)]

    use super::*;

    #[test]
    fn is_test_file_integration_tests_support_without_tests_suffix() {
        assert!(is_test_file(Path::new(
            "adapters/postgres/src/integration_tests/support/helpers.rs"
        )));
        assert!(is_test_file(Path::new(
            "adapters/postgres/src/integration_tests.rs"
        )));
        assert!(!is_test_file(Path::new("adapters/postgres/src/outbox.rs")));
        assert!(!is_test_file(Path::new(
            "adapters/postgres/src/support/helpers.rs"
        )));
    }

    fn identity_security_sql_green_source() -> &'static str {
        r#"
impl PgAccountReactivationLifecycle {
    async fn execute_reactivation(&self) {
        self.write_pool.identity_write(
            scope,
            move |tx| Box::pin(async move { apply_account_state_cas(tx, &row).await }),
            storage,
        ).await;
    }
}

async fn apply_account_state_cas(tx: &mut TenantTx<'_, ServingWriteLane>, row: &Row) {
    tx.identity().apply_account_state_cas(row).await;
}
"#
    }

    fn identity_security_sql_green_facade_source() -> &'static str {
        r#"
impl IdentityWrite<'_, '_> {
    async fn apply_credential_cas(&mut self) {
        sqlx::query("UPDATE credentials SET password_hash = $3, version = $4 WHERE tenant_id = $1::uuid AND login = $2").execute(&mut *self.tx.conn).await;
    }
    async fn apply_account_state_cas(&mut self) {
        sqlx::query("UPDATE account_security_states SET status = $3, authn_epoch = $4, version = $5 WHERE tenant_id = $1::uuid AND user_id = $2::uuid").execute(&mut *self.tx.conn).await;
    }
    async fn revoke_refresh_families_for_account(&mut self) {
        sqlx::query("UPDATE refresh_tokens AS refresh SET status = 'revoked' FROM auth_grants AS root WHERE root.tenant_id = $1::uuid AND root.user_id = $2::uuid AND refresh.tenant_id = root.tenant_id AND refresh.auth_grant_id = root.grant_id").execute(&mut *self.tx.conn).await;
    }
    async fn revoke_auth_grants_for_account(&mut self) {
        sqlx::query("UPDATE auth_grants SET status = 'revoked', close_reason = $2 WHERE user_id = $1::uuid").execute(&mut *self.tx.conn).await;
    }
}
"#
    }

    fn identity_security_sql_green_files() -> Vec<(String, String)> {
        files(&[
            (
                "identity_security_lifecycle.rs",
                identity_security_sql_green_source(),
            ),
            (
                "cotx/identity.rs",
                identity_security_sql_green_facade_source(),
            ),
            (
                "auth_grant_lifecycle.rs",
                r#"async fn apply_grant_close_cas(conn: &mut PgConnection) {
                    sqlx::query_scalar(
                        "WITH revoked AS (
                            UPDATE refresh_tokens SET status = 'revoked'
                            WHERE tenant_id = $1::uuid AND auth_grant_id = $2 AND user_id = $3::uuid
                        )
                        UPDATE auth_grants SET status = $5, close_reason = $7
                        WHERE tenant_id = $1::uuid AND grant_id = $2 AND user_id = $3::uuid",
                    ).fetch_optional(conn).await;
                }"#,
            ),
        ])
    }

    #[test]
    fn identity_security_sql_owner_gate_accepts_canonical_shape() {
        let findings = identity_security_sql_funnel_findings(&identity_security_sql_green_files());
        assert!(findings.is_empty(), "{findings:#?}");
    }

    #[test]
    #[allow(clippy::expect_used)] // reason: green fixture must contain the identity facade carrier.
    fn identity_security_sql_owner_gate_rejects_missing_and_extra_sites() {
        let mut missing_files = identity_security_sql_green_files();
        let facade = missing_files
            .iter_mut()
            .find(|(path, _)| path == "cotx/identity.rs")
            .expect("green fixture contains the identity facade");
        facade.1 = facade
            .1
            .replace("password_hash = $3, version = $4", "password_hash = $3");
        let missing = identity_security_sql_funnel_findings(&missing_files);
        assert!(
            missing.iter().any(|finding| {
                finding.rule == Rule::IdentitySecuritySqlOwnerSitesAbsent
                    && finding.subject.contains("password CAS")
            }),
            "missing password CAS must be synthetic-red: {missing:#?}"
        );

        let mut extra = identity_security_sql_green_files();
        extra.push((
            "credential_repo.rs".to_owned(),
            r#"async fn legacy(conn: &mut PgConnection) {
                sqlx::query("UPDATE credentials SET password_hash = $3, version = $4 WHERE tenant_id = $1")
                    .execute(conn).await;
            }"#
                .to_owned(),
        ));
        let extra = identity_security_sql_funnel_findings(&extra);
        assert!(
            extra.iter().any(|finding| {
                finding.rule == Rule::IdentitySecuritySqlOwnerBypass
                    && finding.subject.starts_with("credential_repo.rs::")
            }),
            "extra password owner must be synthetic-red: {extra:#?}"
        );

        for source in [
            r#"const PASSWORD_CAS: &str = "UPDATE credentials SET password_hash = $3, version = $4 WHERE tenant_id = $1";
                async fn legacy(conn: &mut PgConnection) {
                    sqlx::query(PASSWORD_CAS).execute(conn).await;
                }"#,
            r#"async fn legacy(conn: &mut PgConnection) {
                    sqlx::query!("UPDATE credentials SET password_hash = $3, version = $4 WHERE tenant_id = $1")
                        .execute(conn).await;
                }"#,
        ] {
            let mut macro_or_const = identity_security_sql_green_files();
            macro_or_const.push(("credential_repo.rs".to_owned(), source.to_owned()));
            let findings = identity_security_sql_funnel_findings(&macro_or_const);
            assert!(
                findings.iter().any(|finding| {
                    finding.rule == Rule::IdentitySecuritySqlOwnerBypass
                        && finding.subject.starts_with("credential_repo.rs::")
                }),
                "macro/const rogue password owner must be synthetic-red: {findings:#?}"
            );
        }
    }

    #[test]
    fn identity_security_sql_owner_gate_accepts_live_workspace() -> anyhow::Result<()> {
        let root = crate::workspace_root()?;
        let files = load_prod_rs(&root.join("adapters/postgres/src"))?;
        let findings = identity_security_sql_funnel_findings(&files);
        assert!(
            !findings.iter().any(|finding| matches!(
                finding.rule,
                Rule::IdentitySecuritySqlOwnerBypass | Rule::IdentitySecuritySqlOwnerSitesAbsent
            )),
            "{findings:#?}"
        );
        Ok(())
    }

    #[test]
    fn identity_reactivation_gate_accepts_canonical_shape() -> anyhow::Result<()> {
        let syntax = syn::parse_file(identity_security_sql_green_source())?;
        let findings = identity_reactivation_findings("identity_security_lifecycle.rs", &syntax);
        assert!(findings.is_empty(), "{findings:#?}");
        Ok(())
    }

    #[test]
    fn identity_reactivation_call_graph_keeps_free_and_impl_callables_distinct()
    -> anyhow::Result<()> {
        let source = format!(
            "{}\nimpl UnrelatedLifecycle {{\n    async fn apply_account_security_cas(&self) {{\n        self.write_pool.producer_tx(scope, op).await;\n    }}\n}}",
            identity_security_sql_green_source()
        );
        let syntax = syn::parse_file(&source)?;
        let findings = identity_reactivation_findings("identity_security_lifecycle.rs", &syntax);
        assert!(
            findings.is_empty(),
            "an unrelated impl method must not collide with the free helper: {findings:#?}"
        );
        Ok(())
    }

    #[test]
    fn identity_reactivation_gate_rejects_producer_outbox_grant_and_family_paths()
    -> anyhow::Result<()> {
        for (label, source) in [
            (
                "producer",
                identity_security_sql_green_source().replace(
                    "self.write_pool.identity_write(",
                    "self.write_pool.identity_producer_tx(",
                ),
            ),
            (
                "outbox",
                identity_security_sql_green_source().replace(
                    "apply_account_state_cas(tx, &row).await",
                    "append_outbox(tx).await; apply_account_state_cas(tx, &row).await",
                ),
            ),
            (
                "grant/family",
                identity_security_sql_green_source().replace(
                    "apply_account_state_cas(tx, &row).await",
                    "apply_account_state_cas(tx, &row).await; revoke_refresh_families(tx).await",
                ),
            ),
        ] {
            let syntax = syn::parse_file(&source)?;
            let findings =
                identity_reactivation_findings("identity_security_lifecycle.rs", &syntax);
            assert!(
                findings
                    .iter()
                    .any(|finding| finding.rule == Rule::IdentityReactivationBypass),
                "{label} reactivation bypass must be synthetic-red: {findings:#?}"
            );
        }

        let neutral_outbox_helper = format!(
            "{}\nasync fn persist(conn: &mut PgConnection) {{ sqlx::query!(\"INSERT INTO outbox (event_id) VALUES ('rogue')\").execute(conn).await; }}",
            identity_security_sql_green_source().replace(
                "apply_account_state_cas(tx, &row).await",
                "apply_account_state_cas(tx, &row).await; persist(tx).await",
            )
        );
        let syntax = syn::parse_file(&neutral_outbox_helper)?;
        let findings = identity_reactivation_findings("identity_security_lifecycle.rs", &syntax);
        assert!(
            findings
                .iter()
                .any(|finding| finding.rule == Rule::IdentityReactivationBypass),
            "neutral helper with direct outbox SQL must be synthetic-red: {findings:#?}"
        );
        Ok(())
    }

    #[test]
    fn identity_reactivation_gate_rejects_missing_and_extra_plain_writes() -> anyhow::Result<()> {
        for source in [
            identity_security_sql_green_source()
                .replace("self.write_pool.identity_write(", "self.write_pool.identity_read("),
            identity_security_sql_green_source().replace(
                "self.write_pool.identity_write(",
                "self.write_pool.identity_write(scope, op, storage).await; self.write_pool.identity_write(",
            ),
        ] {
            let syntax = syn::parse_file(&source)?;
            let findings =
                identity_reactivation_findings("identity_security_lifecycle.rs", &syntax);
            assert!(
                findings
                    .iter()
                    .any(|finding| finding.rule == Rule::IdentityReactivationSitesAbsent),
                "missing/extra reactivation write must be synthetic-red: {findings:#?}"
            );
        }
        Ok(())
    }

    #[test]
    fn identity_reactivation_gate_accepts_live_workspace() -> anyhow::Result<()> {
        let root = crate::workspace_root()?;
        let files = load_prod_rs(&root.join("adapters/postgres/src"))?;
        let findings = identity_security_sql_funnel_findings(&files);
        assert!(
            !findings.iter().any(|finding| matches!(
                finding.rule,
                Rule::IdentityReactivationBypass | Rule::IdentityReactivationSitesAbsent
            )),
            "{findings:#?}"
        );
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
            |_attempt, deadline| async { self.pool.retry_secret_write(scope, deadline) },
            classify,
        ).await;
    }

    async fn publish_internal(&self, command: SecretInternalPublishCommand) {
        run_pg_tx_retry(
            SETTINGS_SECRET_BOUNDARY,
            |_attempt, deadline| async { self.pool.retry_secret_write(scope, deadline) },
            classify,
        ).await;
    }

    async fn republish(&self, command: SecretRepublishCommand) {
        run_pg_tx_retry(
            SETTINGS_SECRET_BOUNDARY,
            |_attempt, deadline| async { self.pool.retry_secret_write(scope, deadline) },
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
impl SecretWrite<'_, '_> {
    async fn lock_key(self) {
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1 || chr(31) || $2, 0))")
            .execute(self.conn()).await;
    }
}

impl LockedSecretKey<'_, '_> {
    async fn cas_insert(self) {
        sqlx::query("INSERT INTO secret_refs (tenant_id, secret_key) VALUES ($1, $2)")
            .execute(self.conn()).await;
    }

    async fn append_tombstone(self) {
        sqlx::query("INSERT INTO secret_refs (tenant_id, secret_key, deleted) VALUES ($1, $2, TRUE)")
            .execute(self.conn()).await;
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
    async fn setup(self, conn: &mut PgConnection, tenant: TenantId) {
        let setup = async {
            set_local_tenant(&mut *conn, tenant).await?;
            match self {
                Self::Plain => set_local_plain_lock_timeout(&mut *conn).await?,
                Self::Deadline(deadline) => set_local_retry_deadlines(&mut *conn, deadline).await?,
            }
            Ok(TenantTx::from_bound_connection(conn, tenant))
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
    let setup_result = policy.setup(tx.connection(), tenant).await;
    let body_result = match setup_result {
        Complete(mut tenant_tx) => {
            match policy.operation(write.execute(&mut tenant_tx)).await { Complete(value) => Success(value), _ => Failed }
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
    pub(super) fn connection(&mut self) -> &mut PgConnection {
        &mut self.transaction
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
            .replace("tx.connection()", "local_tx.connection()")
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
    fn localtx_quarantine_guard_rejects_legacy_single_file_cotx_shape() {
        let mut sources = localtx_quarantine_semantic_fixture();
        assert_eq!(sources[0].0, "cotx/mod.rs");
        sources[0].0 = "cotx.rs".to_owned();

        let findings = localtx_quarantine_findings(&sources);
        assert!(
            findings.iter().any(|finding| {
                finding.rule == Rule::LocalTxQuarantineSitesAbsent
                    && finding.subject == "cotx/mod.rs"
            }),
            "the removed single-file cotx shape must not satisfy the canonical carrier: {findings:?}"
        );
        assert!(
            !is_cotx_funnel("cotx.rs"),
            "the removed single-file cotx shape must not receive the raw-access exemption"
        );
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
                "policy.operation(write.execute(&mut tenant_tx)).await",
                "if false { policy.operation(write.execute(&mut tenant_tx)).await } else { forged().await }",
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
                "                Self::Plain => set_local_plain_lock_timeout(&mut *conn).await?,",
                "                Self::Plain => (),",
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
                    "cotx/eventing.rs",
                    "async fn outbox_insert_generated(){ sqlx::query(\"INSERT INTO outbox (event_id) VALUES ($1)\").execute(conn.conn()).await; }\n\
                     async fn outbox_insert_replayed(){ sqlx::query(\"INSERT INTO outbox (event_id) VALUES ($1)\").execute(conn.conn()).await; }\n\
                     async fn outbox_log_insert(){ sqlx::query(\"INSERT INTO outbox_log (event_id) VALUES ($1)\").execute(conn.conn()).await; }",
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
                    "struct R { pool: TenantDb<ServingReadLane> } async fn f(){ self.pool.read(tenant, |tx| Box::pin(async move { tx.identity().find_role(id).await })); }",
                ),
                (
                    "config_repo.rs",
                    "struct R { pool: TenantDb<ServingWriteLane> } async fn f(){ self.pool.write(tenant, |tx| Box::pin(async move { tx.identity().save_role(role).await }), storage); }",
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
            "use crate::tx_retry::{run_pg_tx_retry as retry}; impl Uow { async fn commit_authorized(&self){ retry(SETTINGS_CONFIG_BOUNDARY, |_attempt, deadline| async { self.pool.retry_config_producer_tx(scope, deadline) }, classify).await; } }",
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
    fn retry_guard_accepts_command_carried_settings_secret_observation() {
        let mut sites = BTreeSet::new();
        let source = r#"
use crate::tx_retry::run_pg_localtx_retry as retry;
impl SecretUnitOfWork for PgSecretUnitOfWork {
    async fn publish(&self, command: SecretPublishCommand) {
        let (entry, observation) = command.into_parts();
        retry(
            observation,
            |_attempt, deadline| async { self.pool.retry_secret_write(scope, deadline) },
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
    fn retry_guard_rejects_wrong_wrapper_or_unbound_command_evidence() {
        let mut sites = BTreeSet::new();
        for source in [
            "impl Uow { async fn commit(&self){ run_pg_localtx_retry(SETTINGS_CONFIG_BOUNDARY, observation, || async { self.pool.retry_producer_tx() }, classify).await; } }",
            "impl Repo { async fn save(&self){ run_pg_tx_retry(SETTINGS_SECRET_BOUNDARY, || async { self.pool.retry_write() }, classify).await; } }",
            "impl Repo { async fn save(&self){ run_pg_localtx_retry(SETTINGS_SECRET_BOUNDARY, observation, || async { self.pool.retry_write() }, classify).await; } }",
            "impl Repo { async fn save(&self){ let mut observation = settings::secret_publish_localtx_observation().ok_or_else(missing)?; observation = handmade(); run_pg_localtx_retry(SETTINGS_SECRET_BOUNDARY, observation, || async { self.pool.retry_write() }, classify).await; } }",
            "impl Repo { async fn save(&self){ run_pg_localtx_retry(SETTINGS_SECRET_BOUNDARY, settings::secret_publish_localtx_observation().ok_or_else(missing)?, || async { self.pool.write() }, classify).await; } }",
            "impl Repo { async fn save(&self){ run_pg_localtx_retry(SETTINGS_SECRET_BOUNDARY, settings::secret_publish_localtx_observation().ok_or_else(missing)?, || async { self.pool.write().await; self.pool.retry_write().await }, classify).await; } }",
        ] {
            let rel = if source.contains("SETTINGS_SECRET_BOUNDARY") {
                "secret_repo.rs"
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
            "use crate::tx_retry as retry; impl Uow { async fn commit_authorized(&self){ retry::run_pg_tx_retry(SETTINGS_CONFIG_BOUNDARY, |_attempt, deadline| async { self.pool.retry_config_producer_tx(scope, deadline) }, classify).await; } }",
            &mut sites,
        );
        assert!(direct.is_empty(), "{direct:?}");
        assert!(wrapper.is_empty(), "{wrapper:?}");
        assert!(sites.contains("settings-config-commit"));
    }

    #[test]
    fn secret_ref_mutation_guard_rejects_raw_and_destructive_bypasses() {
        for (rel, source) in [
            (
                "secret_repo.rs",
                r#"async fn save(conn: &mut PgConnection) {
                    sqlx::query("INSERT INTO secret_refs (tenant_id) VALUES ($1)")
                        .execute(conn).await;
                }"#,
            ),
            (
                "cotx/identity.rs",
                r#"impl LockedSecretKey<'_, '_> {
                    async fn update(self) {
                        sqlx::query("UPDATE secret_refs SET deleted = TRUE")
                            .execute(self.conn()).await;
                    }
                }"#,
            ),
            (
                "cotx/identity.rs",
                r#"impl LockedSecretKey<'_, '_> {
                    async fn delete(self) {
                        sqlx::query("DELETE FROM secret_refs").execute(self.conn()).await;
                    }
                }"#,
            ),
            (
                "secret_repo.rs",
                r#"impl SecretWrite<'_, '_> {
                    async fn lock_key(self) {
                        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1 || chr(31) || $2, 0))")
                            .execute(self.conn()).await;
                    }
                }"#,
            ),
        ] {
            let mut sites = BTreeMap::new();
            let findings = secret_ref_mutation_findings(rel, source, &mut sites);
            assert!(
                findings
                    .iter()
                    .any(|finding| finding.rule == Rule::SecretRefMutationBypass),
                "raw, destructive, or misplaced SQL must fail closed: {findings:?}"
            );
        }
    }

    #[test]
    fn secret_ref_mutation_guard_accepts_only_exact_sql_sites() {
        let mut sites = BTreeMap::new();
        let findings = secret_ref_mutation_findings(
            "cotx/identity.rs",
            secret_mutation_green_source(),
            &mut sites,
        );
        assert!(findings.is_empty(), "{findings:?}");
        assert_eq!(
            sites,
            BTreeMap::from([
                ("secret-key-advisory-lock", 1),
                ("secret-key-cas-insert", 1),
                ("secret-key-append-tombstone", 1),
            ])
        );
    }

    #[test]
    fn secret_ref_mutation_guard_rejects_split_or_legacy_owners() {
        for broken in [
            secret_mutation_green_source().replacen(
                "impl LockedSecretKey<'_, '_>",
                "impl LegacySecretKey<'_, '_>",
                1,
            ),
            secret_mutation_green_source().replacen(
                "async fn cas_insert(self)",
                "async fn raw_insert(self)",
                1,
            ),
        ] {
            let mut sites = BTreeMap::new();
            let findings = secret_ref_mutation_findings("cotx/identity.rs", &broken, &mut sites);
            assert!(
                findings
                    .iter()
                    .any(|finding| finding.rule == Rule::SecretRefMutationBypass),
                "split or legacy SQL owner must fail closed: {findings:?}"
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
    fn retry_guard_rejects_removed_optional_observation_factories() {
        let source = "impl Uow { async fn publish(&self, command: SecretPublishCommand){ let (_, command_observation) = command.into_parts(); let observation = settings::secret_publish_localtx_observation().unwrap(); run_pg_localtx_retry(observation, || async { self.pool.retry_write() }, classify).await; } }";
        let mut sites = BTreeSet::new();
        let findings = retry_placement_findings("secret_repo.rs", source, &mut sites);
        assert!(
            findings
                .iter()
                .any(|finding| finding.rule == Rule::RetryPlacement),
            "removed optional factory syntax must remain synthetic-red: {findings:?}"
        );
    }

    #[test]
    fn refresh_legacy_write_guard_rejects_old_ports_and_application_bypasses() {
        let decoys = vec![(
            "crates/identity/src/decoy.rs".to_string(),
            r#"
            // struct RefreshRotationMutation;
            const BAIT: &str = "async fn revoke_lineage";
            #[cfg(test)]
            struct AuthGrantCloseCommand;
            #[cfg(test)]
            impl RefreshService {
                async fn compromise_replayed_grant(&self) {}
            }
            "#
            .to_string(),
        )];
        assert!(
            refresh_legacy_write_findings(&decoys).is_empty(),
            "comments, strings, and cfg(test) items are not production bypass evidence"
        );

        for source in [
            "pub struct RefreshRotationMutation;",
            "pub trait RefreshTokenStoreLocal { async fn rotate(&self); }",
            "impl RefreshTokenStore for PgStore { async fn revoke_lineage(&self) {} }",
            "pub trait AuthGrantLifecycleLocal { async fn close(&self); }",
            "impl RefreshService { async fn compromise_replayed_grant(&self) {} }",
            "impl RefreshService { async fn revoke(&self) {} }",
        ] {
            let files = vec![("synthetic.rs".to_string(), source.to_string())];
            let findings = refresh_legacy_write_findings(&files);
            assert!(
                findings
                    .iter()
                    .any(|finding| finding.rule == Rule::IdentityRefreshWriteBypass),
                "legacy refresh write surface must fail closed: {source}; {findings:?}"
            );
        }
    }

    #[test]
    fn refresh_legacy_write_guard_accepts_live_workspace() -> Result<()> {
        let root = crate::workspace_root()?;
        let files = load_workspace_prod_rs(&root)?;
        let findings = refresh_legacy_write_findings(&files);
        assert!(findings.is_empty(), "{findings:?}");
        Ok(())
    }

    #[test]
    fn retry_guard_accepts_all_exact_boundaries() {
        let mut sites = BTreeSet::new();
        assert_retry_shape(
            &mut sites,
            "config_repo.rs",
            "impl Uow { async fn commit_authorized(&self){ run_pg_tx_retry(SETTINGS_CONFIG_BOUNDARY, |_attempt, deadline| async { self.pool.retry_config_producer_tx(scope, deadline) }, classify).await; } }",
        );
        assert_retry_shape(
            &mut sites,
            "audit_repo.rs",
            "impl Repo { async fn append(&self){ run_pg_tx_retry(AUDIT_APPEND_BOUNDARY, |_attempt, deadline| async { self.pool.retry_audit_write(scope, deadline) }, classify).await; } }",
        );
        assert_retry_shape(
            &mut sites,
            "auth_audit_sink.rs",
            "impl AuditListTenantAppender for PgAuthAuditSink { async fn append(&self, command: AuditListTenantAppend){ let (scope, event, observation) = command.into_parts(); run_pg_localtx_retry(observation, |_attempt, deadline| async { self.pool.retry_auth_audit_write(scope, deadline, |_tx| async { persist(event) }, storage) }, classify).await; } }",
        );
        assert_retry_shape(&mut sites, "secret_repo.rs", secret_retry_green_source());
        assert_eq!(
            sites,
            BTreeSet::from([
                "audit-append",
                "audit-list-tenant-append",
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
    fn retry_guard_rejects_removed_refresh_and_wrong_audit_boundaries() {
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
    fn localtx_deadline_guard_real_workspace_closes_mint_and_six_dataflows() -> Result<()> {
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
        assert_eq!(sites.len(), 6, "{sites:?}");

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
    fn retry_guard_requires_the_closed_six_site_set() {
        let files = vec![("tx_retry.rs".to_string(), String::new())];
        let findings = required_retry_site_findings(&files, &BTreeSet::new());
        assert_eq!(
            findings
                .iter()
                .filter(|finding| finding.rule == Rule::RetrySitesAbsent)
                .count(),
            6,
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
                .any(|finding| finding.subject == "audit-append")
        );
        assert!(
            findings
                .iter()
                .any(|finding| finding.subject == "audit-list-tenant-append")
        );
    }

    #[test]
    fn secret_ref_mutation_guard_real_workspace_has_exact_sql_sites() -> Result<()> {
        let root = crate::workspace_root()?;
        let source = std::fs::read_to_string(root.join("adapters/postgres/src/cotx/identity.rs"))?;
        let mut sites = BTreeMap::new();
        let findings = secret_ref_mutation_findings("cotx/identity.rs", &source, &mut sites);
        assert!(findings.is_empty(), "{findings:?}");
        assert_eq!(
            sites,
            BTreeMap::from([
                ("secret-key-advisory-lock", 1),
                ("secret-key-cas-insert", 1),
                ("secret-key-append-tombstone", 1),
            ])
        );
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
