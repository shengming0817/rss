//! `schema-rls` —— schema RLS 守卫（AI-robust **Medium** 内容扫描门）。
//!
//! 扫 `adapters/postgres/migrations/*.sql`，禁止 tenant 表（含 `tenant_id` 列的 `CREATE TABLE`，或后续
//! `ALTER TABLE ... ADD COLUMN tenant_id`）缺 RLS 三件套：`ENABLE ROW LEVEL SECURITY` +
//! `FORCE ROW LEVEL SECURITY` + 该表的 `CREATE POLICY`。
//! 同时校验 policy 体文本（normalize：小写 + 折叠空白）须含规范等值谓词
//! `tenant_id = current_setting('rss.tenant_id', true)::uuid`（或空 GUC fail-closed 的 NULLIF 形态）
//! 且无明显 ` OR true` 重言旁路；
//! 仅有形同 allow-all 的 policy 亦报错（`PolicyWeak`）。把 `docs/rules/tenancy.md` §RLS
//! 「RLS policy shape 由 schema guard 检查」从规划落成机器门。
//!
//! INVARIANT: TENANCY-RLS-FORCE-01 { level = "Medium", exec = "verify", source = "code" }—— tenant 表（含 tenant_id 列）必须同时具备：
//!   ① `ALTER TABLE <t> ENABLE ROW LEVEL SECURITY`
//!   ② `ALTER TABLE <t> FORCE ROW LEVEL SECURITY`
//!   ③ 至少一条 `CREATE POLICY ... ON <t>`，且 policy 体 normalize 后含规范等值谓词
//!      `tenant_id = current_setting('rss.tenant_id', true)::uuid`（或 NULLIF 形态）且无明显 OR true 重言旁路
//!
//! **评级**：Medium（内容扫描门，接入 `cargo xtask verify`，no-compile meta 步）。
//!
//! **盲区**（文本级扫描，非 SQL AST；故意不引重型 SQL parser，匹配 xtask 轻量设计）：
//!   - 不处理 dollar-quoted 字符串（`$$...$$`）；PL/pgSQL 块内的关键词若误触匹配属静默误判。
//!   - CREATE TABLE 体内含 `)` 的字符串字面量会使 `parens_body` 提前截断（漏判 tenant_id）。
//!   - policy 体经文本 normalize（小写 + 折叠空白）后校验含规范等值谓词
//!     `tenant_id = current_setting('rss.tenant_id', true)::uuid`（或 NULLIF 形态）且无明显 ` OR true` 重言；
//!     **不解析完整 SQL 语义**——任意等价重言 / 列别名 / 函数包裹变形超出文本扫描载体边界
//!     （残留盲区，需 review 兜底）。
//!   - 以上场景在现有 migrations 实际不存在；引入新 migration 前须人工复核。
//!
//! `ref: xtask/src/layerdeps.rs`（内容扫描守卫范式）
//! `ref: postgres ddl-rowsecurity`（FORCE RLS 语义：owner 亦受 policy 约束）

use anyhow::{Context, Result};
use std::collections::{BTreeMap, BTreeSet};

use crate::diagnostic::{self, GovernanceCheck, finding};

pub(crate) type Finding = diagnostic::Finding<Rule>;

/// 被违反的规则（供测试精确断言）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Rule {
    /// TENANCY-RLS-FORCE-01：tenant 表缺 `ALTER TABLE <t> ENABLE ROW LEVEL SECURITY`。
    EnableRls,
    /// TENANCY-RLS-FORCE-01：tenant 表缺 `ALTER TABLE <t> FORCE ROW LEVEL SECURITY`。
    ForceRls,
    /// TENANCY-RLS-FORCE-01：tenant 表无任何 `CREATE POLICY ... ON <t>`。
    PolicyAbsent,
    /// TENANCY-RLS-FORCE-01：tenant 表 policy 最终态（CREATE 经 ALTER 覆盖后）未含规范 NULLIF 等值谓词，
    /// 或含 OR true 重言旁路（形同 allow-all）。旧裸谓词未经 `ALTER POLICY` 升级为 NULLIF 形态亦属此类。
    PolicyWeak,
}

/// 搜索关键词（已小写，配合 `to_lowercase()` 后的内容匹配）。
const ENABLE_RLS: &str = "enable row level security";
const FORCE_RLS: &str = "force row level security";
/// tenant-isolation policy 体规范等值谓词（**目标态**，#332 F6）：空 custom GUC 经 NULLIF 转 NULL，避免 unset
/// GUC cast 空串在 policy 判定前报错。normalize 后 substring 比对；容忍 `=`/`::` 两侧空白（折叠后与此串对比）。
/// 旧裸谓词 `tenant_id = current_setting('rss.tenant_id', true)::uuid` 不再被接受为最终态——须经 forward-only
/// `ALTER POLICY` 升级为本形态，否则 schema-rls 判 `PolicyWeak`（只新增旧谓词不 harden 即门红）。
const POLICY_PREDICATE_NULLIF: &str =
    "tenant_id = nullif(current_setting('rss.tenant_id', true), '')::uuid";
/// 明显重言旁路 — OR true（normalize 后子串；含此则 policy 体视为 PolicyWeak 无效）。
const TAUTOLOGY_OR_TRUE: &str = " or true";
/// 明显重言旁路 — OR (true)（normalize 后子串；含此则 policy 体视为 PolicyWeak 无效）。
const TAUTOLOGY_OR_TRUE_PAREN: &str = " or (true)";

pub(crate) struct SchemaRlsGuard;

impl GovernanceCheck for SchemaRlsGuard {
    type Rule = Rule;

    fn name(&self) -> &'static str {
        "schema-rls"
    }

    fn check(&self) -> Result<(String, Vec<Finding>)> {
        let root = crate::workspace_root()?;
        let dir = root.join("adapters").join("postgres").join("migrations");
        let files = load_sql_files(&dir)?;
        let (tenant_count, findings) = scan_rls(&files);
        let summary = format!(
            "{tenant_count} tenant 表全部具 RLS 三件套（扫 {} 个迁移文件）",
            files.len()
        );
        Ok((summary, findings))
    }
}

/// 读迁移目录下全部 `.sql` 文件（按文件名排序，确定性）。
fn load_sql_files(dir: &std::path::Path) -> Result<Vec<(String, String)>> {
    let mut entries: Vec<_> = std::fs::read_dir(dir)
        .with_context(|| format!("读迁移目录 {} 失败", dir.display()))?
        .collect::<Result<Vec<_>, _>>()
        .with_context(|| "遍历迁移目录条目失败")?;
    entries.sort_by_key(|e| e.file_name());
    let mut files = Vec::new();
    for entry in entries {
        let path = entry.path();
        if path.extension().is_some_and(|e| e == "sql") {
            let fname = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("")
                .to_string();
            let content = std::fs::read_to_string(&path)
                .with_context(|| format!("读迁移文件 {} 失败", path.display()))?;
            files.push((fname, content));
        }
    }
    Ok(files)
}

// ---- 纯函数扫描逻辑（输入 &[(文件名, 内容)]，便于 synthetic 单测）----

/// 主扫描纯函数：输入原始文件列表，返回 `(tenant 表数, findings)`。
/// 先剥注释再解析，防注释散文中的 RLS/tenant_id 关键词干扰匹配（关键：0004/0005/0008 的注释
/// 大量提及 "ROW LEVEL SECURITY"/"tenant_id" 散文，不剥离会产生假阴性）。
pub(crate) fn scan_rls(files: &[(String, String)]) -> (usize, Vec<Finding>) {
    let stripped = strip_and_lowercase(files);
    let tenant_tables = collect_tenant_tables(&stripped);
    let tenant_count = tenant_tables.len();
    if tenant_count == 0 {
        return (0, vec![]);
    }
    let enables = collect_alter_rls(&stripped, ENABLE_RLS);
    let forces = collect_alter_rls(&stripped, FORCE_RLS);
    let policies = collect_policy_tables(&stripped);
    let findings = build_findings(&tenant_tables, &enables, &forces, &policies);
    (tenant_count, findings)
}

/// 对所有文件剥注释并转小写（保留原文件名，仅内容处理）。
fn strip_and_lowercase(files: &[(String, String)]) -> Vec<(String, String)> {
    files
        .iter()
        .map(|(f, c)| (f.clone(), strip_sql_comments(c).to_lowercase()))
        .collect()
}

/// 生成 findings：对每个 tenant 表检查 ENABLE / FORCE / POLICY 三件套（含 policy 体谓词校验）。
///
/// `policies`：`table → bool`；`true` = 该表至少一条 policy 最终态 normalize 后含 [`POLICY_PREDICATE_NULLIF`] 且无重言旁路；
/// `false` = 有 policy 但无合规谓词或含重言旁路（形同 allow-all，报 `PolicyWeak`）；不存在 = 无任何 policy（`PolicyAbsent`）。
fn build_findings(
    tenant_tables: &BTreeMap<String, String>,
    enables: &BTreeSet<String>,
    forces: &BTreeSet<String>,
    policies: &BTreeMap<String, bool>,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (table, fname) in tenant_tables {
        if !enables.contains(table) {
            findings.push(finding(
                Rule::EnableRls,
                table,
                format!("{fname}: 缺 ENABLE ROW LEVEL SECURITY"),
            ));
        }
        if !forces.contains(table) {
            findings.push(finding(
                Rule::ForceRls,
                table,
                format!("{fname}: 缺 FORCE ROW LEVEL SECURITY"),
            ));
        }
        match policies.get(table) {
            None => findings.push(finding(
                Rule::PolicyAbsent,
                table,
                format!("{fname}: 无 CREATE POLICY ... ON {table}"),
            )),
            Some(false) => findings.push(finding(
                Rule::PolicyWeak,
                table,
                format!(
                    "{fname}: POLICY ON {table} 最终态未含规范 NULLIF 等值谓词（须 `tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid`；旧裸谓词须经 ALTER POLICY 升级）或含 OR true 重言旁路（形同 allow-all）"
                ),
            )),
            Some(true) => {}
        }
    }
    findings
}

/// 剥去 `--` 行注释与 `/* */` 块注释（保留 `\n` 以维持行结构；保留字符串字面量内容）。
fn strip_sql_comments(src: &str) -> String {
    #[derive(PartialEq)]
    enum St {
        Code,
        LineComment,
        BlockComment,
        Str,
    }
    let mut out = String::with_capacity(src.len());
    let mut chars = src.chars().peekable();
    let mut st = St::Code;
    while let Some(c) = chars.next() {
        match st {
            St::Code => match c {
                '-' if chars.peek() == Some(&'-') => {
                    chars.next();
                    st = St::LineComment;
                }
                '/' if chars.peek() == Some(&'*') => {
                    chars.next();
                    st = St::BlockComment;
                }
                '\'' => {
                    out.push('\'');
                    st = St::Str;
                }
                other => out.push(other),
            },
            St::LineComment => {
                if c == '\n' {
                    out.push('\n');
                    st = St::Code;
                }
            }
            St::BlockComment => {
                if c == '*' && chars.peek() == Some(&'/') {
                    chars.next();
                    st = St::Code;
                } else if c == '\n' {
                    out.push('\n');
                }
            }
            St::Str => {
                out.push(c);
                if c == '\'' {
                    if chars.peek() == Some(&'\'') {
                        out.push('\'');
                        chars.next();
                    } else {
                        st = St::Code;
                    }
                }
            }
        }
    }
    out
}

/// 取下一个 SQL 标识符 token（`[a-z0-9_.]` 序列，含 schema 前缀 `.`）。
/// 返回 `(token, 剩余)`，token 为空表示输入无标识符起头。
fn split_token(s: &str) -> (&str, &str) {
    let s = s.trim_start();
    let end = s
        .find(|c: char| !c.is_alphanumeric() && c != '_' && c != '.')
        .unwrap_or(s.len());
    (&s[..end], &s[end..])
}

/// 在已消费开括号 `(` 之后，找到配对 `)` 并返回括号体内容（深度计数处理嵌套括号）。
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

/// 从 `create table ` 关键词之后的内容尝试提取含 `tenant_id` 列的表名。
/// 返回 `Some(表名)` 或 `None`（格式不符 / 无 tenant_id 列）。
fn extract_tenant_table(after_kw: &str) -> Option<String> {
    let s = after_kw.trim_start();
    let s = s
        .strip_prefix("if not exists")
        .map_or(s, |r| r.trim_start());
    let (name, rest) = split_token(s);
    if name.is_empty() {
        return None;
    }
    let paren_idx = rest.find('(')?;
    let body = parens_body(&rest[paren_idx + 1..])?;
    body.contains("tenant_id").then(|| name.to_string())
}

/// 从 `alter table ` 关键词之后提取 `ADD COLUMN tenant_id` 的表名。
fn extract_alter_add_tenant_table(after_kw: &str) -> Option<String> {
    let s = after_kw.trim_start();
    let s = s.strip_prefix("if exists").map_or(s, |r| r.trim_start());
    let (name, rest) = split_token(s);
    if name.is_empty() {
        return None;
    }
    let rest = rest.trim_start();
    (rest.starts_with("add column tenant_id") || rest.starts_with("add tenant_id"))
        .then(|| name.to_string())
}

/// 收集含 `tenant_id` 列的表名 → 声明所在文件名（跨文件聚合）。
/// 支持建表时声明 tenant_id，也支持后续 migration 通过 `ALTER TABLE ... ADD COLUMN tenant_id` 租户化旧表。
fn collect_tenant_tables(files: &[(String, String)]) -> BTreeMap<String, String> {
    let mut tables: BTreeMap<String, String> = BTreeMap::new();
    for (fname, content) in files {
        let mut pos = 0;
        while pos < content.len() {
            let Some(rel) = content[pos..].find("create table ") else {
                break;
            };
            let kw_end = pos + rel + "create table ".len();
            if let Some(name) = extract_tenant_table(&content[kw_end..]) {
                tables.entry(name).or_insert_with(|| fname.clone());
            }
            pos = kw_end;
        }
        let mut pos = 0;
        while pos < content.len() {
            let Some(rel) = content[pos..].find("alter table ") else {
                break;
            };
            let kw_end = pos + rel + "alter table ".len();
            if let Some(name) = extract_alter_add_tenant_table(&content[kw_end..]) {
                tables.entry(name).or_insert_with(|| fname.clone());
            }
            pos = kw_end;
        }
    }
    tables
}

/// 收集 `ALTER TABLE <t> <rls_kw>` 中命中的表名集合。
/// `rls_kw` 为 `ENABLE_RLS` 或 `FORCE_RLS`（已小写）。
fn collect_alter_rls(files: &[(String, String)], rls_kw: &str) -> BTreeSet<String> {
    let mut tables = BTreeSet::new();
    for (_, content) in files {
        let mut pos = 0;
        while pos < content.len() {
            let Some(rel) = content[pos..].find("alter table ") else {
                break;
            };
            let kw_end = pos + rel + "alter table ".len();
            let (name, rest) = split_token(&content[kw_end..]);
            if !name.is_empty() && rest.trim_start().starts_with(rls_kw) {
                tables.insert(name.to_string());
            }
            pos = kw_end;
        }
    }
    tables
}

/// policy 体空白折叠：将一个或多个连续空白字符压缩为单个空格（输入已小写）。
/// 配合 `to_lowercase()` 后使用，容忍 `=`/`::` 两侧多余空白的 SQL 格式变体。
fn normalize_whitespace(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut in_ws = false;
    for c in s.chars() {
        if c.is_whitespace() {
            if !in_ws {
                out.push(' ');
                in_ws = true;
            }
        } else {
            out.push(c);
            in_ws = false;
        }
    }
    out
}

/// policy 谓词体**最终态**合规判定（#332 F6）：必须含 [`POLICY_PREDICATE_NULLIF`] 规范谓词且无 `OR true`
/// 重言旁路。旧裸谓词不再被接受为最终态——只新增旧谓词而不经 forward-only `ALTER POLICY` 升级即 `PolicyWeak`。
fn policy_body_is_valid(norm_body: &str) -> bool {
    norm_body.contains(POLICY_PREDICATE_NULLIF)
        && !norm_body.contains(TAUTOLOGY_OR_TRUE)
        && !norm_body.contains(TAUTOLOGY_OR_TRUE_PAREN)
}

/// 收集 tenant policy 的**最终态**合规性：按迁移文件顺序 apply `CREATE POLICY`，再用同名 `ALTER POLICY`
/// 覆盖谓词体（#332 F6——forward-only RLS hardening 经 `ALTER POLICY` 前滚，门必须按最终态判定而非 CREATE
/// 时刻，否则旧裸谓词被 ALTER 升级为 NULLIF 后门仍误判 CREATE 时刻形态）。
///
/// 返回 `BTreeMap<table, bool>`：
/// - `true`  = 该表至少一条 policy 的**最终态** normalize 后含 [`POLICY_PREDICATE_NULLIF`] 且无重言旁路（合规）。
/// - `false` = 该表有 policy 但**所有** policy 最终态均不满足规范谓词（旧裸谓词未 harden、列错、仅提及、或含
///   `OR true` 重言旁路——形同 allow-all 或空 GUC cast 失败）。
/// - 不存在 = 该表无任何 `CREATE POLICY ... ON <t>`（`PolicyAbsent`）。
fn collect_policy_tables(files: &[(String, String)]) -> BTreeMap<String, bool> {
    // (table, policy_name) → 最新 normalize 后的谓词体；CREATE 建、ALTER 覆盖。SQL 语义保证 `ALTER POLICY`
    // 必在同名 `CREATE POLICY` 之后，故按文件顺序先扫 CREATE pass 再扫 ALTER pass 即得最终态。
    let mut final_bodies: BTreeMap<(String, String), String> = BTreeMap::new();
    for (_, content) in files {
        for kw in ["create policy ", "alter policy "] {
            let mut pos = 0;
            while pos < content.len() {
                let Some(rel) = content[pos..].find(kw) else {
                    break;
                };
                let kw_end = pos + rel + kw.len();
                let (policy_name, rest) = split_token(&content[kw_end..]);
                if let Some(after_on) = rest.trim_start().strip_prefix("on ") {
                    let (table, after_table) = split_token(after_on);
                    if !table.is_empty() && !policy_name.is_empty() {
                        // 取 policy 体：从 ON <table> 之后到最近的 `;`（或文件末）。
                        let body = if let Some(semi) = after_table.find(';') {
                            &after_table[..semi]
                        } else {
                            after_table
                        };
                        final_bodies.insert(
                            (table.to_string(), policy_name.to_string()),
                            normalize_whitespace(body),
                        );
                    }
                }
                pos = kw_end;
            }
        }
    }
    // 折叠到 table → 任一 policy 最终态合规。
    let mut tables: BTreeMap<String, bool> = BTreeMap::new();
    for ((table, _policy), body) in &final_bodies {
        let entry = tables.entry(table.clone()).or_insert(false);
        if policy_body_is_valid(body) {
            *entry = true;
        }
    }
    tables
}

#[cfg(test)]
mod tests {
    use super::*;

    fn files(content: &str) -> Vec<(String, String)> {
        vec![("test.sql".to_string(), content.to_string())]
    }

    fn two_files(c1: &str, c2: &str) -> Vec<(String, String)> {
        vec![
            ("file1.sql".to_string(), c1.to_string()),
            ("file2.sql".to_string(), c2.to_string()),
        ]
    }

    // ---- green：三件套齐备 → 0 findings ----

    #[test]
    fn green_all_rls_present() {
        let sql = r#"
CREATE TABLE sessions (
    session_id text PRIMARY KEY,
    tenant_id  uuid NOT NULL
);
ALTER TABLE sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE sessions FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON sessions
    USING (tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid);
"#;
        let (count, findings) = scan_rls(&files(sql));
        assert_eq!(count, 1, "应识别 1 个 tenant 表");
        assert!(
            findings.is_empty(),
            "三件套齐备不应有 findings: {findings:?}"
        );
    }

    #[test]
    fn green_alter_add_tenant_column_with_nullif_policy() {
        let sql = r#"
CREATE TABLE dead_letter (
    id bigserial PRIMARY KEY,
    message_id text NOT NULL
);
ALTER TABLE dead_letter
    ADD COLUMN tenant_id uuid,
    ADD COLUMN message_id text NOT NULL DEFAULT '';
ALTER TABLE dead_letter ENABLE ROW LEVEL SECURITY;
ALTER TABLE dead_letter FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON dead_letter
    USING (tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid);
"#;
        let (count, findings) = scan_rls(&files(sql));
        assert_eq!(count, 1, "ALTER ADD COLUMN tenant_id 应识别为 tenant 表");
        assert!(
            findings.is_empty(),
            "ALTER tenant 表具备 RLS 三件套不应有 findings: {findings:?}"
        );
    }

    #[test]
    fn green_inbox_receipts_target_schema_has_rls() {
        let sql = r#"
CREATE TABLE inbox_receipts (
    tenant_id        uuid        NOT NULL,
    event_id         text        NOT NULL,
    consumer_group   text        NOT NULL,
    contract_version text        NOT NULL,
    schema_hash      text        NOT NULL,
    PRIMARY KEY (tenant_id, event_id, consumer_group)
);
ALTER TABLE inbox_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE inbox_receipts FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON inbox_receipts
    USING (tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid);
"#;
        let (count, findings) = scan_rls(&files(sql));
        assert_eq!(count, 1, "inbox_receipts 应被识别为 tenant 表");
        assert!(
            findings.is_empty(),
            "inbox_receipts 目标 RLS 三件套不应有 findings: {findings:?}"
        );
    }

    #[test]
    fn red_alter_add_tenant_column_missing_rls() {
        let sql = r#"
CREATE TABLE dead_letter (id bigserial PRIMARY KEY);
ALTER TABLE dead_letter ADD COLUMN tenant_id uuid;
"#;
        let (count, findings) = scan_rls(&files(sql));
        assert_eq!(count, 1, "ALTER ADD COLUMN tenant_id 应识别为 tenant 表");
        assert_eq!(
            findings.len(),
            3,
            "ALTER tenant 表缺 RLS 三件套应产生 3 条 finding: {findings:?}"
        );
        let rules: Vec<Rule> = findings.iter().map(|f| f.rule).collect();
        assert!(rules.contains(&Rule::EnableRls));
        assert!(rules.contains(&Rule::ForceRls));
        assert!(rules.contains(&Rule::PolicyAbsent));
    }

    // ---- red 缺 ENABLE ----

    #[test]
    fn red_missing_enable() {
        let sql = r#"
CREATE TABLE sessions (tenant_id uuid NOT NULL);
ALTER TABLE sessions FORCE ROW LEVEL SECURITY;
CREATE POLICY p ON sessions USING (tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid);
"#;
        let (_, findings) = scan_rls(&files(sql));
        assert_eq!(
            findings.len(),
            1,
            "缺 ENABLE 应仅报 1 条 finding: {findings:?}"
        );
        assert_eq!(findings[0].rule, Rule::EnableRls);
        assert_eq!(findings[0].subject, "sessions");
    }

    // ---- red 缺 FORCE ----

    #[test]
    fn red_missing_force() {
        let sql = r#"
CREATE TABLE sessions (tenant_id uuid NOT NULL);
ALTER TABLE sessions ENABLE ROW LEVEL SECURITY;
CREATE POLICY p ON sessions USING (tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid);
"#;
        let (_, findings) = scan_rls(&files(sql));
        assert_eq!(
            findings.len(),
            1,
            "缺 FORCE 应仅报 1 条 finding: {findings:?}"
        );
        assert_eq!(findings[0].rule, Rule::ForceRls);
        assert_eq!(findings[0].subject, "sessions");
    }

    // ---- red 缺 POLICY ----

    #[test]
    fn red_missing_policy() {
        let sql = r#"
CREATE TABLE sessions (tenant_id uuid NOT NULL);
ALTER TABLE sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE sessions FORCE ROW LEVEL SECURITY;
"#;
        let (_, findings) = scan_rls(&files(sql));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule, Rule::PolicyAbsent);
        assert_eq!(findings[0].subject, "sessions");
    }

    // ---- red 全裸：三件套全缺 → 3 findings ----

    #[test]
    fn red_all_bare_three_findings() {
        let sql = "CREATE TABLE sessions (tenant_id uuid NOT NULL);";
        let (_, findings) = scan_rls(&files(sql));
        assert_eq!(
            findings.len(),
            3,
            "三件套全缺应产生 3 条 finding: {findings:?}"
        );
        let rules: Vec<Rule> = findings.iter().map(|f| f.rule).collect();
        assert!(rules.contains(&Rule::EnableRls));
        assert!(rules.contains(&Rule::ForceRls));
        assert!(rules.contains(&Rule::PolicyAbsent));
    }

    // ---- anti-vacuity：非 tenant 表（无 tenant_id）→ 0 findings ----

    #[test]
    fn ignore_non_tenant_table() {
        let sql = r#"
CREATE TABLE outbox (
    event_id   text PRIMARY KEY,
    payload    jsonb NOT NULL
);
"#;
        let (count, findings) = scan_rls(&files(sql));
        assert_eq!(count, 0, "outbox 无 tenant_id 不应被识别为 tenant 表");
        assert!(findings.is_empty(), "非 tenant 表无 RLS 也不应有 findings");
    }

    // ---- 注释鲁棒：RLS 关键词只在 -- 注释里 → 仍被判缺失（证明剥注释生效）----

    #[test]
    fn comment_robustness_rls_only_in_comments() {
        let sql = r#"
-- ALTER TABLE sessions ENABLE ROW LEVEL SECURITY;
-- ALTER TABLE sessions FORCE ROW LEVEL SECURITY;
-- CREATE POLICY tenant_isolation ON sessions USING (true);
CREATE TABLE sessions (tenant_id uuid NOT NULL);
"#;
        let (_, findings) = scan_rls(&files(sql));
        assert_eq!(
            findings.len(),
            3,
            "注释里的 RLS 关键词不应被计为有效声明，应仍报 3 条 finding: {findings:?}"
        );
    }

    // ---- 跨文件聚合：表在 file1 CREATE，RLS 在 file2 ALTER/POLICY → 0 findings ----

    #[test]
    fn cross_file_aggregation() {
        let c1 = "CREATE TABLE sessions (tenant_id uuid NOT NULL);";
        let c2 = r#"
ALTER TABLE sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE sessions FORCE ROW LEVEL SECURITY;
CREATE POLICY p ON sessions USING (tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid);
"#;
        let (count, findings) = scan_rls(&two_files(c1, c2));
        assert_eq!(count, 1);
        assert!(
            findings.is_empty(),
            "跨文件 RLS 声明应聚合，不应有 findings: {findings:?}"
        );
    }

    // ---- red PolicyWeak：policy 体形同 allow-all（无合规谓词）→ PolicyWeak ----

    #[test]
    fn red_policy_weak_allow_all() {
        let sql = r#"
CREATE TABLE sessions (tenant_id uuid NOT NULL);
ALTER TABLE sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE sessions FORCE ROW LEVEL SECURITY;
CREATE POLICY p ON sessions USING (true);
"#;
        let (count, findings) = scan_rls(&files(sql));
        assert_eq!(count, 1, "应识别 1 个 tenant 表");
        assert_eq!(
            findings.len(),
            1,
            "ENABLE/FORCE 齐备但 policy 体形同 allow-all → 应报 1 条 PolicyWeak: {findings:?}"
        );
        assert_eq!(findings[0].rule, Rule::PolicyWeak, "应报 PolicyWeak");
        assert_eq!(findings[0].subject, "sessions");
    }

    #[test]
    fn red_inbox_receipts_policy_must_use_nullif_tenant_predicate() {
        let sql = r#"
CREATE TABLE inbox_receipts (
    tenant_id uuid NOT NULL,
    event_id text NOT NULL,
    consumer_group text NOT NULL
);
ALTER TABLE inbox_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE inbox_receipts FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON inbox_receipts
    USING (tenant_id = current_setting('rss.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('rss.tenant_id', true)::uuid);
"#;
        let (count, findings) = scan_rls(&files(sql));
        assert_eq!(count, 1, "inbox_receipts 应被识别为 tenant 表");
        assert_eq!(
            findings.len(),
            1,
            "旧裸谓词不得通过 inbox_receipts RLS guard: {findings:?}"
        );
        assert_eq!(findings[0].rule, Rule::PolicyWeak);
        assert_eq!(findings[0].subject, "inbox_receipts");
    }

    // ---- strip_sql_comments 单元测试 ----

    #[test]
    fn strip_removes_line_comments() {
        let src = "CREATE TABLE foo -- this is a comment\n(id text);";
        let stripped = strip_sql_comments(src).to_lowercase();
        assert!(!stripped.contains("this is a comment"));
        assert!(stripped.contains("create table foo"));
        assert!(stripped.contains("(id text)"));
    }

    #[test]
    fn strip_removes_block_comments() {
        let src = "CREATE /* block comment */ TABLE foo (id text);";
        let stripped = strip_sql_comments(src).to_lowercase();
        assert!(!stripped.contains("block comment"));
        assert!(stripped.contains("create"));
        assert!(stripped.contains("table foo"));
    }

    #[test]
    fn strip_preserves_string_literals() {
        let src = "SELECT current_setting('rss.tenant_id', true);";
        let stripped = strip_sql_comments(src);
        assert!(stripped.contains("'rss.tenant_id'"));
    }

    // ---- split_token 单元测试 ----

    #[test]
    fn split_token_basic() {
        assert_eq!(split_token("sessions enable"), ("sessions", " enable"));
        assert_eq!(split_token("  foo bar"), ("foo", " bar"));
        assert_eq!(split_token(""), ("", ""));
        assert_eq!(split_token("  "), ("", ""));
    }

    #[test]
    fn split_token_schema_qualified() {
        assert_eq!(split_token("public.sessions "), ("public.sessions", " "));
    }

    // ---- parens_body 单元测试 ----

    #[test]
    fn parens_body_simple() {
        assert_eq!(parens_body("a, b, c)rest"), Some("a, b, c"));
    }

    #[test]
    fn parens_body_nested() {
        assert_eq!(
            parens_body("a, CHECK(b > 0), c)rest"),
            Some("a, CHECK(b > 0), c")
        );
    }

    #[test]
    fn parens_body_unclosed_returns_none() {
        assert_eq!(parens_body("a, b, c"), None);
    }

    // ---- red PolicyWeak 强化：提及 current_setting 但非规范等值谓词 / 含重言旁路 ----

    /// red：policy 体仅含 IS NOT NULL 检查（提及 current_setting 但非等值谓词）→ PolicyWeak。
    #[test]
    fn red_policy_mentions_only() {
        let sql = r#"
CREATE TABLE sessions (tenant_id uuid NOT NULL);
ALTER TABLE sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE sessions FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON sessions
    USING (current_setting('rss.tenant_id', true) IS NOT NULL);
"#;
        let (count, findings) = scan_rls(&files(sql));
        assert_eq!(count, 1, "应识别 1 个 tenant 表");
        assert_eq!(
            findings.len(),
            1,
            "policy 体仅提及 current_setting 而非规范等值谓词 → 应报 PolicyWeak: {findings:?}"
        );
        assert_eq!(findings[0].rule, Rule::PolicyWeak, "应报 PolicyWeak");
        assert_eq!(findings[0].subject, "sessions");
    }

    /// red：policy 体等值谓词列错（store_id 非 tenant_id）→ PolicyWeak。
    #[test]
    fn red_policy_wrong_column() {
        let sql = r#"
CREATE TABLE sessions (tenant_id uuid NOT NULL);
ALTER TABLE sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE sessions FORCE ROW LEVEL SECURITY;
CREATE POLICY p ON sessions USING (store_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid);
"#;
        let (count, findings) = scan_rls(&files(sql));
        assert_eq!(count, 1, "应识别 1 个 tenant 表");
        assert_eq!(
            findings.len(),
            1,
            "policy 体列名错误（store_id 非 tenant_id）→ 应报 PolicyWeak: {findings:?}"
        );
        assert_eq!(findings[0].rule, Rule::PolicyWeak, "应报 PolicyWeak");
        assert_eq!(findings[0].subject, "sessions");
    }

    /// red：policy 体含规范谓词但带 OR true 重言旁路 → PolicyWeak（重言使隔离失效）。
    #[test]
    fn red_policy_tautology_or_true() {
        let sql = r#"
CREATE TABLE sessions (tenant_id uuid NOT NULL);
ALTER TABLE sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE sessions FORCE ROW LEVEL SECURITY;
CREATE POLICY p ON sessions
    USING (tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid OR true);
"#;
        let (count, findings) = scan_rls(&files(sql));
        assert_eq!(count, 1, "应识别 1 个 tenant 表");
        assert_eq!(
            findings.len(),
            1,
            "policy 体含 OR true 重言旁路 → 应报 PolicyWeak（含规范谓词但有重言）: {findings:?}"
        );
        assert_eq!(findings[0].rule, Rule::PolicyWeak, "应报 PolicyWeak");
        assert_eq!(findings[0].subject, "sessions");
    }

    // ---- #332 F6：建模 ALTER POLICY 最终态 + 要求 NULLIF 目标谓词 ----

    /// red（核心）：CREATE POLICY 用旧裸谓词且未经 ALTER 升级 → 最终态非 NULLIF → PolicyWeak。
    /// 只新增旧谓词不 harden 即门红，对齐 `docs/rules/tenancy.md` 目标态。
    #[test]
    fn red_bare_predicate_without_alter_is_weak() {
        let sql = r#"
CREATE TABLE sessions (tenant_id uuid NOT NULL);
ALTER TABLE sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE sessions FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON sessions
    USING (tenant_id = current_setting('rss.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('rss.tenant_id', true)::uuid);
"#;
        let (count, findings) = scan_rls(&files(sql));
        assert_eq!(count, 1, "应识别 1 个 tenant 表");
        assert_eq!(
            findings.len(),
            1,
            "旧裸谓词未经 ALTER 升级为 NULLIF → 应报 1 条 PolicyWeak: {findings:?}"
        );
        assert_eq!(findings[0].rule, Rule::PolicyWeak);
        assert_eq!(findings[0].subject, "sessions");
    }

    /// green：CREATE 旧裸谓词后经同名 ALTER POLICY 前滚升级为 NULLIF → 最终态合规 → 0 findings
    /// （对齐真实迁移 0012 CREATE → 0024 ALTER 的 forward-only hardening；证明门按最终态而非 CREATE 时刻判定）。
    #[test]
    fn green_create_bare_then_alter_nullif_is_valid() {
        let sql = r#"
CREATE TABLE sessions (tenant_id uuid NOT NULL);
ALTER TABLE sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE sessions FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON sessions
    USING (tenant_id = current_setting('rss.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('rss.tenant_id', true)::uuid);
ALTER POLICY tenant_isolation ON sessions
    USING (tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid);
"#;
        let (count, findings) = scan_rls(&files(sql));
        assert_eq!(count, 1, "应识别 1 个 tenant 表");
        assert!(
            findings.is_empty(),
            "CREATE 旧谓词经 ALTER 升级 NULLIF 后最终态合规，不应有 findings: {findings:?}"
        );
    }

    /// green：CREATE（file1）与 ALTER 升级 NULLIF（file2）跨文件——按文件顺序建模最终态 → 0 findings
    /// （对齐 0012_enable_tenant_rls.sql + 0024_harden_tenant_rls_empty_setting.sql 真实分文件形态）。
    #[test]
    fn green_create_bare_then_alter_nullif_cross_file() {
        let c1 = r#"
CREATE TABLE sessions (tenant_id uuid NOT NULL);
ALTER TABLE sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE sessions FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON sessions
    USING (tenant_id = current_setting('rss.tenant_id', true)::uuid);
"#;
        let c2 = r#"
ALTER POLICY tenant_isolation ON sessions
    USING (tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid);
"#;
        let (count, findings) = scan_rls(&two_files(c1, c2));
        assert_eq!(count, 1);
        assert!(
            findings.is_empty(),
            "跨文件 CREATE→ALTER 升级 NULLIF 应聚合为合规最终态: {findings:?}"
        );
    }

    /// red：CREATE NULLIF 后 ALTER 又改回旧裸谓词 → 最终态退化 → PolicyWeak（证明最终态优先、ALTER 漂移可被捕获）。
    #[test]
    fn red_alter_drift_back_to_bare_is_weak() {
        let sql = r#"
CREATE TABLE sessions (tenant_id uuid NOT NULL);
ALTER TABLE sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE sessions FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON sessions
    USING (tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid);
ALTER POLICY tenant_isolation ON sessions
    USING (tenant_id = current_setting('rss.tenant_id', true)::uuid);
"#;
        let (count, findings) = scan_rls(&files(sql));
        assert_eq!(count, 1, "应识别 1 个 tenant 表");
        assert_eq!(
            findings.len(),
            1,
            "ALTER 把 NULLIF 改回旧裸谓词 → 最终态非 NULLIF → 应报 PolicyWeak: {findings:?}"
        );
        assert_eq!(findings[0].rule, Rule::PolicyWeak);
    }

    // ---- normalize_whitespace 单元测试 ----

    #[test]
    fn normalize_whitespace_collapses_multiple_spaces() {
        assert_eq!(
            normalize_whitespace("a  =  b"),
            "a = b",
            "多个空格应折叠为单个"
        );
    }

    #[test]
    fn normalize_whitespace_collapses_tabs_and_newlines() {
        assert_eq!(
            normalize_whitespace("a\t=\n b"),
            "a = b",
            "tab/换行应折叠为单个空格"
        );
    }
}
