//! `pg-tenant-tx-guard` —— Postgres tenant-table raw-pool / TxManager bypass guard.
//!
//! INVARIANT: TENANCY-PG-TX-FUNNEL-01 { level = "Medium", exec = "verify", source = "code" } —
//! tenant-table production paths must go through
//! `PgTenantPool::{read,write,co_tx_with_outbox}` or the lower-level `cotx.rs` funnel. Raw
//! `sqlx::PgPool` / direct connection / global transaction paths are allowed only for explicitly
//! named global infrastructure or maintenance exceptions.
//!
//! This guard is a Medium backstop for the Hard typed wrapper in `adapters/postgres/src/cotx.rs`.
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
    StaleException,
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
        let (summary, findings) = scan_guard(&migrations, &files);
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

    let mut tenant_sql_sites = 0usize;
    let mut raw_sites = 0usize;
    let mut allowed_exceptions = BTreeSet::new();
    findings.extend(fault_matrix_exception_staleness(files));

    for (rel, content) in files {
        let stripped = strip_rust_comment_lines(&strip_cfg_test_modules(content));
        let expanded = expand_simple_table_consts(&stripped).to_lowercase();
        let tenant_hits = tenant_table_hits(&expanded, &tenant_tables);
        if !tenant_hits.is_empty() {
            tenant_sql_sites += 1;
        }
        let helper_tables = tenant_pgconnection_helpers(&expanded, &tenant_tables);
        let (raw_hits, site_exceptions) =
            raw_tenant_accesses(rel, &expanded, &tenant_tables, &helper_tables);
        let (raw_outbox_insert_hits, outbox_insert_exceptions) =
            raw_outbox_insert_sites(rel, &expanded);
        let outbox_append_bypass_hits = outbox_append_bypass_sites(rel, &expanded);
        let tx_capability_mint_hits = tx_capability_mint_sites(rel, &expanded);
        allowed_exceptions.extend(site_exceptions);
        allowed_exceptions.extend(outbox_insert_exceptions);
        let raw_pool_field_hits = raw_tenant_pool_fields(&expanded);
        let raw_pool_field_exception = raw_pool_field_exception(rel, &expanded);
        note_raw_pool_field_exception(
            &mut allowed_exceptions,
            raw_pool_field_exception,
            &raw_pool_field_hits,
        );
        raw_sites += raw_hits.len();
        raw_sites += raw_pool_field_hits.len();
        raw_sites += raw_outbox_insert_hits.len();
        raw_sites += outbox_append_bypass_hits.len();
        raw_sites += tx_capability_mint_hits.len();
        for hit in &raw_outbox_insert_hits {
            findings.push(finding(
                Rule::RawOutboxInsert,
                site_subject(rel, hit.line),
                "outbox rows must be created through outbox.rs TxCapability append funnel",
            ));
        }
        for hit in &outbox_append_bypass_hits {
            findings.push(finding(
                Rule::OutboxAppendBypass,
                site_subject(rel, hit.line),
                format!(
                    "outbox producer opens a raw transaction near {:?}; use PgTenantPool write/co-tx funnel",
                    hit.pattern
                ),
            ));
        }
        for hit in &tx_capability_mint_hits {
            findings.push(finding(
                Rule::TxCapabilityMintOutsideFunnel,
                site_subject(rel, hit.line),
                "TxCapability minting is restricted to transaction funnel modules",
            ));
        }
        findings.extend(raw_pool_field_findings(
            rel,
            &tenant_hits,
            &raw_pool_field_hits,
            raw_pool_field_exception,
        ));
        if raw_hits.is_empty() {
            continue;
        }
        for hit in &raw_hits {
            findings.push(finding(
                Rule::RawTenantTableAccess,
                site_subject(rel, hit.line),
                format!(
                    "tenant tables {:?} touched through raw pattern {:?}; use PgTenantPool scoped methods",
                    hit.tables, hit.pattern
                ),
            ));
        }
    }

    for expected in [
        "config-legacy-plaintext-startup-probe",
        "config-value-maintenance",
    ] {
        if !allowed_exceptions.contains(expected) {
            findings.push(finding(
                Rule::StaleException,
                expected,
                "命名 raw-pool 例外未命中任何生产 site；删除例外或恢复对应测试覆盖",
            ));
        }
    }

    if tenant_sql_sites == 0 {
        findings.push(finding(
            Rule::SqlSitesAbsent,
            "adapters/postgres/src",
            "未扫描到任何 tenant-table SQL site，guard 真空化",
        ));
    }

    let summary = format!(
        "{} tenant 表；{} 个生产文件；{} 个 tenant SQL 文件；{} 个 raw pattern",
        tenant_tables.len(),
        files.len(),
        tenant_sql_sites,
        raw_sites
    );
    (summary, findings)
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
) -> (Vec<RawOutboxAccess>, BTreeSet<&'static str>) {
    if rel == "outbox.rs" {
        return (Vec::new(), BTreeSet::new());
    }
    const NEEDLE: &str = "insert into outbox";
    let mut exceptions = BTreeSet::new();
    let findings = content
        .match_indices(NEEDLE)
        .filter(|(idx, _)| {
            content[*idx + NEEDLE.len()..]
                .chars()
                .next()
                .is_none_or(|ch| !(ch == '_' || ch.is_ascii_alphanumeric()))
        })
        .filter_map(|(idx, _)| {
            let (_, end) = raw_access_window(content, idx, ".execute(pool");
            let window = &content[idx.saturating_sub(400)..end];
            if let Some(exception) = allowed_fault_matrix_outbox_insert(rel, window) {
                exceptions.insert(exception);
                return None;
            }
            Some(RawOutboxAccess {
                pattern: "INSERT INTO outbox",
                line: line_number(content, idx),
            })
        })
        .collect();
    (findings, exceptions)
}

fn outbox_append_bypass_sites(rel: &str, content: &str) -> Vec<RawOutboxAccess> {
    if matches!(rel, "cotx.rs" | "outbox.rs" | "tx.rs") || !content.contains("append_outbox(") {
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
    if matches!(rel, "cotx.rs" | "tx.rs") {
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
    fn green_outbox_log_insert_is_not_relay_outbox_bypass() {
        let (_, findings) = scan_guard(
            &migrations(),
            &files(&[
                (
                    "dead_letter.rs",
                    "fn sweep(){ sqlx::query(\"DELETE FROM dead_letter WHERE last_attempt_at <= now() - make_interval(secs => $1)\").execute(&self.maintenance_pool); }",
                ),
                (
                    "outbox_cdc.rs",
                    "async fn append(){ sqlx::query(\"INSERT INTO outbox_log (event_id) VALUES ($1)\").execute(conn.conn()).await; }",
                ),
            ]),
        );
        assert!(
            !findings.iter().any(|f| f.rule == Rule::RawOutboxInsert),
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
}
