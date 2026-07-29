//! `schema-rls` —— schema RLS + LocalOnly reader ACL 守卫（AI-robust **Medium** 内容扫描门）。
//!
//! 扫 `adapters/postgres/migrations/*.sql`，禁止 tenant 表（含 `tenant_id` 列的 `CREATE TABLE`，或后续
//! `ALTER TABLE ... ADD COLUMN tenant_id`）缺 RLS 三件套：`ENABLE ROW LEVEL SECURITY` +
//! `FORCE ROW LEVEL SECURITY` + 该表的 `CREATE POLICY`。
//! 同时校验每条 permissive policy 的 USING/WITH CHECK 最终态均为规范 NULLIF 等值谓词
//! `tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid`；额外收窄必须使用
//! restrictive policy，不能用另一条 permissive policy 拼接。
//! 仅有形同 allow-all 的 policy 亦报错（`PolicyWeak`）。把 `docs/rules/tenancy.md` §RLS
//! 「RLS policy shape 由 schema guard 检查」从规划落成机器门。
//!
//! INVARIANT: TENANCY-RLS-FORCE-01 { level = "Medium", exec = "check", source = "code", synthetic_red = "tests::red_all_bare_three_findings", anti_vacuity = "tests::green_all_rls_present" }—— tenant 表（含 tenant_id 列）必须同时具备：
//!   ① `ALTER TABLE <t> ENABLE ROW LEVEL SECURITY`
//!   ② `ALTER TABLE <t> FORCE ROW LEVEL SECURITY`
//!   ③ 至少一条 `CREATE POLICY ... ON <t>`，且每条 permissive policy 的 USING/WITH CHECK
//!      均精确匹配 canonical NULLIF 等值谓词
//!
//! INVARIANT: TENANCY-PG-READER-ACL-01 { level = "Medium", exec = "check", source = "code", synthetic_red = "tests::red_tenant_relation_without_reader_select_grant", anti_vacuity = "tests::green_tenant_relation_exact_reader_select_grant" }——
//! migration `0067` may dynamically backfill SELECT on the complete pre-existing public tenant
//! relation set. The backfill evidence must bind the catalog query and an executed GRANT format
//! call inside the same dollar-quoted DO block and FOR loop. Every later migration that creates a
//! public tenant relation must grant exact table SELECT to `rss_app_read` in that same file; reader
//! DML and default privileges are always forbidden.
//! Policy name resolution is a two-layer closure: this static guard rejects migration-defined
//! operators or `current_setting` shadows, while the runtime PostgreSQL gate proves every
//! permissive tenant policy has only pinned built-ins plus its own table/column dependencies.
//!
//! **评级**：Medium（内容扫描门，接入 `cargo xtask verify`，no-compile meta 步）。
//!
//! **盲区**（文本级扫描，非 SQL AST；故意不引重型 SQL parser，匹配 xtask 轻量设计）：
//!   - reader backfill understands dollar-quoted `DO $tag$...$tag$` and one-level `FOR ... LOOP`
//!     structure, but is not a general PL/pgSQL parser; nested/generated control flow fails closed.
//!   - CREATE TABLE 体内含 `)` 的字符串字面量会使 `parens_body` 提前截断（漏判 tenant_id）。
//!   - policy 体使用轻量 statement parser + normalize，不解析完整 PostgreSQL 表达式语义；语义等价但
//!     非 canonical 的变体会 fail closed。runtime gate 另以 catalog/dependency 证据封闭实际数据库状态。
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
    /// 未识别到任何 tenant table，守卫不得真空通过。
    TenantTablesAbsent,
    /// TENANCY-RLS-FORCE-01：tenant 表缺 `ALTER TABLE <t> ENABLE ROW LEVEL SECURITY`。
    EnableRls,
    /// TENANCY-RLS-FORCE-01：tenant 表缺 `ALTER TABLE <t> FORCE ROW LEVEL SECURITY`。
    ForceRls,
    /// TENANCY-RLS-FORCE-01：tenant 表无任何 `CREATE POLICY ... ON <t>`。
    PolicyAbsent,
    /// TENANCY-RLS-FORCE-01：tenant 表 policy 最终态（CREATE 经 ALTER 覆盖后）未含规范 NULLIF 等值谓词，
    /// 或含 OR true 重言旁路（形同 allow-all）。旧裸谓词未经 `ALTER POLICY` 升级为 NULLIF 形态亦属此类。
    PolicyWeak,
    /// 同表存在额外 permissive policy，其最终态可放宽 canonical tenant policy。
    PolicyWidening,
    /// Tenant relation is not covered by the reader backfill or an exact same-migration SELECT.
    ReaderSelectAbsent,
    /// `rss_app_read` was granted DML/ALL privileges on a relation.
    ReaderDmlGrant,
    /// `rss_app_read` may delegate a privilege to another role.
    ReaderGrantOption,
    /// Default privileges would grant future/unclassified relations to the reader implicitly.
    ReaderDefaultPrivileges,
    /// A migration defines an operator or shadows `current_setting`, making policy text
    /// insufficient to prove the referenced PostgreSQL semantics.
    PolicyDependencyShadowing,
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
            "{tenant_count} tenant 表全部具 RLS 三件套与 rss_app_read SELECT 边界（扫 {} 个迁移文件）",
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
        return (
            0,
            vec![finding(
                Rule::TenantTablesAbsent,
                "adapters/postgres/migrations",
                "未识别到任何 tenant 表，schema RLS guard 真空化",
            )],
        );
    }
    let enables = collect_alter_rls(&stripped, ENABLE_RLS);
    let forces = collect_alter_rls(&stripped, FORCE_RLS);
    let policies = collect_policy_tables(&stripped);
    let mut findings = build_findings(&tenant_tables, &enables, &forces, &policies);
    findings.extend(policy_dependency_shadowing_findings(&stripped));
    findings.extend(reader_acl_findings(&stripped, &tenant_tables));
    (tenant_count, findings)
}

fn policy_dependency_shadowing_findings(files: &[(String, String)]) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (file, content) in files {
        let normalized = normalize_whitespace(content);
        let defines_operator = normalized.contains("create operator ");
        let shadows_current_setting = ["create function ", "create or replace function "]
            .into_iter()
            .any(|prefix| {
                normalized.match_indices(prefix).any(|(position, _)| {
                    let signature = normalized[position + prefix.len()..].trim_start();
                    signature
                        .split_once('(')
                        .map(|(name, _)| name.trim().rsplit('.').next() == Some("current_setting"))
                        .unwrap_or(false)
                })
            });
        if defines_operator || shadows_current_setting {
            findings.push(finding(
                Rule::PolicyDependencyShadowing,
                file,
                format!(
                    "{file}: migrations must not define operators or shadow current_setting; tenant policy semantics are pinned to pg_catalog built-ins"
                ),
            ));
        }
    }
    findings
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
    policies: &BTreeMap<String, PolicyAssessment>,
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
            Some(PolicyAssessment::Weak) => findings.push(finding(
                Rule::PolicyWeak,
                table,
                format!(
                    "{fname}: POLICY ON {table} 最终态未含规范 NULLIF 等值谓词（须 `tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid`；旧裸谓词须经 ALTER POLICY 升级）或含 OR true 重言旁路（形同 allow-all）"
                ),
            )),
            Some(PolicyAssessment::Widening) => findings.push(finding(
                Rule::PolicyWidening,
                table,
                format!(
                    "{fname}: POLICY ON {table} 含额外 permissive 放宽路径；每条 permissive policy 都必须同时绑定 canonical USING/WITH CHECK"
                ),
            )),
            Some(PolicyAssessment::Valid) => {}
        }
    }
    findings
}

#[derive(Debug)]
struct ReaderGrant {
    privileges: String,
    tables: Vec<String>,
}

#[derive(Debug)]
struct ReaderSelectEvent {
    file: String,
    granted: bool,
}

fn reader_acl_findings(
    files: &[(String, String)],
    tenant_tables: &BTreeMap<String, String>,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let dynamic_backfill = files
        .iter()
        .filter(|(_, content)| is_reader_dynamic_backfill(content))
        .map(|(file, _)| file.clone())
        .max();
    let mut select_events: BTreeMap<String, ReaderSelectEvent> = BTreeMap::new();
    let mut select_grant_sites: BTreeSet<(String, String)> = BTreeSet::new();

    for (file, content) in files {
        let normalized = normalize_whitespace(content);
        if normalized.contains("alter default privileges") && normalized.contains("rss_app_read") {
            findings.push(finding(
                Rule::ReaderDefaultPrivileges,
                file,
                "rss_app_read must not receive ALTER DEFAULT PRIVILEGES; tenant relations require explicit classified SELECT",
            ));
        }

        for statement in content.split(';').map(normalize_whitespace) {
            let statement = statement.trim();
            if statement.contains("grant ")
                && statement.contains(" to rss_app_read")
                && statement.contains(" with grant option")
            {
                findings.push(finding(
                    Rule::ReaderGrantOption,
                    file,
                    format!(
                        "{file}: rss_app_read must never receive WITH GRANT OPTION, including dynamic SQL"
                    ),
                ));
            }
            if let Some(grant) = parse_reader_table_grant(statement) {
                let forbidden = forbidden_reader_privileges(&grant.privileges);
                for table in &grant.tables {
                    if !forbidden.is_empty() {
                        findings.push(finding(
                            Rule::ReaderDmlGrant,
                            table,
                            format!(
                                "{file}: rss_app_read must not receive DML/ALL privileges: {}",
                                forbidden.join(", ")
                            ),
                        ));
                    }
                    if grant.privileges == "select" {
                        select_grant_sites.insert((table.clone(), file.clone()));
                        select_events.insert(
                            table.clone(),
                            ReaderSelectEvent {
                                file: file.clone(),
                                granted: true,
                            },
                        );
                    }
                }
            }
            if !statement.starts_with("grant ") {
                let forbidden = embedded_reader_forbidden_privileges(statement);
                if !forbidden.is_empty() {
                    findings.push(finding(
                        Rule::ReaderDmlGrant,
                        file,
                        format!(
                            "{file}: dynamic rss_app_read grant must not contain DML/ALL privileges: {}",
                            forbidden.join(", ")
                        ),
                    ));
                }
            }
            if let Some(tables) = parse_reader_select_revoke(statement) {
                for table in tables {
                    select_events.insert(
                        table,
                        ReaderSelectEvent {
                            file: file.clone(),
                            granted: false,
                        },
                    );
                }
            }
        }
    }

    for (relation, created_in) in tenant_tables {
        let Some(table) = public_table_name(relation) else {
            continue;
        };
        let event = select_events.get(table);
        let covered_by_same_migration = event.is_some_and(|event| event.granted)
            && select_grant_sites.contains(&(table.to_owned(), created_in.clone()));
        let covered_by_backfill = dynamic_backfill.as_ref().is_some_and(|backfill| {
            created_in <= backfill
                && event.is_none_or(|event| event.file <= *backfill || event.granted)
        });
        if !covered_by_same_migration && !covered_by_backfill {
            findings.push(finding(
                Rule::ReaderSelectAbsent,
                table,
                format!(
                    "{created_in}: rss_app_read requires exact SELECT in the tenant relation's migration (or the pre-existing relation backfill)"
                ),
            ));
        }
    }
    findings
}

fn is_reader_dynamic_backfill(content: &str) -> bool {
    dollar_quoted_do_bodies(content).into_iter().any(|body| {
        reader_backfill_for_loops(body)
            .into_iter()
            .any(|(binding, query, loop_body)| {
                is_reader_relation_catalog_query(&query)
                    && has_executed_reader_grant(&loop_body, &binding)
            })
    })
}

fn dollar_quoted_do_bodies(content: &str) -> Vec<&str> {
    let mut bodies = Vec::new();
    let mut rest = content;
    while let Some(do_offset) = rest.find("do $") {
        let after_do = &rest[do_offset + "do ".len()..];
        let Some(tag_end) = after_do[1..].find('$').map(|offset| offset + 1) else {
            break;
        };
        let delimiter = &after_do[..=tag_end];
        let body_start = delimiter.len();
        let Some(body_end) = after_do[body_start..].find(delimiter) else {
            break;
        };
        bodies.push(&after_do[body_start..body_start + body_end]);
        rest = &after_do[body_start + body_end + delimiter.len()..];
    }
    bodies
}

fn reader_backfill_for_loops(body: &str) -> Vec<(String, String, String)> {
    let normalized = normalize_whitespace(body);
    let mut loops = Vec::new();
    let mut rest = normalized.as_str();
    while let Some(for_offset) = code_mask(rest).find("for ") {
        let after_for = &rest[for_offset + "for ".len()..];
        let Some((binding, after_binding)) = after_for.split_once(" in ") else {
            break;
        };
        let Some(loop_offset) = code_mask(after_binding).find(" loop ") else {
            break;
        };
        let query = &after_binding[..loop_offset];
        let loop_body_start = loop_offset + " loop ".len();
        let after_loop = &after_binding[loop_body_start..];
        let Some(end_offset) = code_mask(after_loop).find(" end loop") else {
            break;
        };
        loops.push((
            binding.trim().to_owned(),
            query.to_owned(),
            after_loop[..end_offset].to_owned(),
        ));
        rest = &after_loop[end_offset + " end loop".len()..];
    }
    loops
}

fn is_reader_relation_catalog_query(query: &str) -> bool {
    let query = normalize_whitespace(query);
    let code = code_mask(&query);
    [
        "from pg_class",
        "pg_namespace",
        "nspname =",
        "relkind in",
        "pg_attribute",
        "attname =",
        "n.nspname as schema_name",
        "c.relname as relation_name",
    ]
    .into_iter()
    .all(|required| code.contains(required))
        && query.contains("nspname = 'public'")
        && query.contains("attname = 'tenant_id'")
        && query.contains("('r', 'p')")
}

fn has_executed_reader_grant(loop_body: &str, binding: &str) -> bool {
    let normalized = normalize_whitespace(loop_body);
    let code = code_mask(&normalized);
    let mut search_from = 0;
    while let Some(offset) = code[search_from..].find("execute format") {
        let execute = search_from + offset;
        let after_execute = execute + "execute format".len();
        let Some(paren_offset) = code[after_execute..].find('(') else {
            return false;
        };
        let open = after_execute + paren_offset;
        if !code[after_execute..open].trim().is_empty() {
            search_from = after_execute;
            continue;
        }
        let Some(call) = parens_body(&normalized[open + 1..]) else {
            return false;
        };
        if call.contains("'grant select on table %i.%i to rss_app_read'")
            && call.contains(&format!("{binding}.schema_name"))
            && call.contains(&format!("{binding}.relation_name"))
        {
            return true;
        }
        search_from = open + 1;
    }
    false
}

/// Mask single-quoted literal contents while preserving byte offsets and code punctuation.
fn code_mask(input: &str) -> String {
    let mut masked = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    let mut in_literal = false;
    while let Some(character) = chars.next() {
        if character == '\'' {
            masked.push(' ');
            if in_literal && chars.peek() == Some(&'\'') {
                masked.push(' ');
                chars.next();
            } else {
                in_literal = !in_literal;
            }
        } else if in_literal {
            masked.extend(std::iter::repeat_n(' ', character.len_utf8()));
        } else {
            masked.push(character);
        }
    }
    masked
}

fn parse_reader_table_grant(statement: &str) -> Option<ReaderGrant> {
    let statement = statement.strip_prefix("grant ")?;
    let (privileges, rest) = statement.split_once(" on ")?;
    let rest = rest.strip_prefix("table ").unwrap_or(rest);
    let (relations, roles) = rest.split_once(" to ")?;
    if !role_list_contains(roles, "rss_app_read") {
        return None;
    }
    let tables = relations
        .split(',')
        .filter_map(|relation| public_table_name(relation.trim()).map(str::to_owned))
        .collect::<Vec<_>>();
    (!tables.is_empty()).then(|| ReaderGrant {
        privileges: normalize_privileges(privileges),
        tables,
    })
}

fn parse_reader_select_revoke(statement: &str) -> Option<Vec<String>> {
    let statement = statement.strip_prefix("revoke ")?;
    let (privileges, rest) = statement.split_once(" on ")?;
    if normalize_privileges(privileges) != "select" {
        return None;
    }
    let rest = rest.strip_prefix("table ").unwrap_or(rest);
    let (relations, roles) = rest.split_once(" from ")?;
    if !role_list_contains(roles, "rss_app_read") {
        return None;
    }
    Some(
        relations
            .split(',')
            .filter_map(|relation| public_table_name(relation.trim()).map(str::to_owned))
            .collect(),
    )
}

fn role_list_contains(roles: &str, role: &str) -> bool {
    roles
        .split([',', ' '])
        .map(str::trim)
        .any(|candidate| candidate == role)
}

fn normalize_privileges(privileges: &str) -> String {
    privileges
        .split(',')
        .map(str::trim)
        .collect::<Vec<_>>()
        .join(",")
}

fn forbidden_reader_privileges(privileges: &str) -> Vec<&'static str> {
    let mut forbidden = Vec::new();
    for (needle, label) in [
        ("insert", "INSERT"),
        ("update", "UPDATE"),
        ("delete", "DELETE"),
        ("truncate", "TRUNCATE"),
        ("all", "ALL"),
    ] {
        if privileges
            .split(',')
            .any(|privilege| privilege == needle || privilege.starts_with(&format!("{needle} (")))
        {
            forbidden.push(label);
        }
    }
    forbidden
}

fn embedded_reader_forbidden_privileges(statement: &str) -> Vec<&'static str> {
    let mut forbidden = BTreeSet::new();
    for (grant_pos, _) in statement.match_indices("grant ") {
        let after_grant = &statement[grant_pos + "grant ".len()..];
        let Some(on_pos) = after_grant.find(" on ") else {
            continue;
        };
        let Some(role_pos) = after_grant.find(" to rss_app_read") else {
            continue;
        };
        if role_pos <= on_pos {
            continue;
        }
        let privileges = normalize_privileges(
            after_grant[..on_pos].trim_matches(|character| matches!(character, '\'' | '"' | '(')),
        );
        forbidden.extend(forbidden_reader_privileges(&privileges));
    }
    forbidden.into_iter().collect()
}

fn public_table_name(relation: &str) -> Option<&str> {
    let relation = relation.trim().trim_matches('"');
    match relation.split_once('.') {
        None => Some(relation),
        Some(("public", table)) => Some(table.trim_matches('"')),
        Some(_) => None,
    }
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

/// policy 谓词体**最终态**合规判定（#332 F6）：每条 permissive policy 的 USING / WITH CHECK
/// 必须精确等于 [`POLICY_PREDICATE_NULLIF`]。额外收窄只能放进独立 `AS RESTRICTIVE` policy；这样
/// `NOT (canonical)`、`canonical = false`、`canonical AND ...` 等易被词法包含门误收的形态全部 fail-closed。
fn policy_body_is_valid(norm_body: &str) -> bool {
    extract_policy_clause(norm_body, "using").is_some_and(policy_clause_is_canonical)
        && extract_policy_clause(norm_body, "with check").is_some_and(policy_clause_is_canonical)
}

fn policy_clause_is_canonical(clause: &str) -> bool {
    strip_balanced_outer_parens(clause.trim()) == POLICY_PREDICATE_NULLIF
}

fn strip_balanced_outer_parens(mut clause: &str) -> &str {
    loop {
        let Some(inner) = clause
            .strip_prefix('(')
            .and_then(|value| value.strip_suffix(')'))
        else {
            return clause;
        };
        let mut depth = 0_i32;
        let wraps_whole_clause = clause.char_indices().all(|(index, ch)| {
            match ch {
                '(' => depth += 1,
                ')' => depth -= 1,
                _ => {}
            }
            depth >= 0 && (depth != 0 || index == clause.len() - 1)
        });
        if !wraps_whole_clause || depth != 0 {
            return clause;
        }
        clause = inner.trim();
    }
}

fn extract_policy_clause<'a>(body: &'a str, keyword: &str) -> Option<&'a str> {
    let start = body.find(keyword)? + keyword.len();
    let rest = body[start..].trim_start();
    let rest = rest.strip_prefix('(')?;
    parens_body(rest)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PolicyAssessment {
    Valid,
    Weak,
    Widening,
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
fn collect_policy_tables(files: &[(String, String)]) -> BTreeMap<String, PolicyAssessment> {
    let mut final_bodies: BTreeMap<(String, String), (String, bool)> = BTreeMap::new();
    for (_, content) in files {
        for statement in content.split(';').map(normalize_whitespace) {
            let statement = statement.trim();
            let (kind, after_kw) = if let Some(rest) = statement.strip_prefix("create policy ") {
                ("create", rest)
            } else if let Some(rest) = statement.strip_prefix("alter policy ") {
                ("alter", rest)
            } else {
                continue;
            };
            let (policy_name, rest) = split_token(after_kw);
            let Some(on_pos) = rest.find(" on ").or_else(|| rest.find("on ")) else {
                continue;
            };
            let after_on = rest[on_pos..].trim_start().trim_start_matches("on ");
            let (table, after_table) = split_token(after_on);
            let after_table = after_table.trim_start();
            if table.is_empty() || policy_name.is_empty() {
                continue;
            }
            let key = (table.to_string(), policy_name.to_string());
            // PostgreSQL grammar places `AS RESTRICTIVE` after `ON <table>`, not before `ON`.
            // Only the policy option prefix counts; occurrences inside predicates must not change kind.
            let restrictive = kind == "create"
                && (after_table == "as restrictive" || after_table.starts_with("as restrictive "));
            if kind == "create" {
                final_bodies.insert(key, (after_table.to_string(), restrictive));
            } else if let Some((existing, _)) = final_bodies.get_mut(&key) {
                if let Some(using_clause) = extract_policy_clause(after_table, "using") {
                    replace_policy_clause(existing, "using", using_clause);
                }
                if let Some(check_clause) = extract_policy_clause(after_table, "with check") {
                    replace_policy_clause(existing, "with check", check_clause);
                }
            }
        }
    }
    let mut grouped: BTreeMap<String, Vec<bool>> = BTreeMap::new();
    for ((table, _), (body, restrictive)) in final_bodies {
        if !restrictive {
            grouped
                .entry(table)
                .or_default()
                .push(policy_body_is_valid(&body));
        }
    }
    grouped
        .into_iter()
        .map(|(table, policies)| {
            let valid = policies.iter().filter(|&&item| item).count();
            let assessment = match (valid, policies.len()) {
                (0, _) => PolicyAssessment::Weak,
                (valid, total) if valid < total => PolicyAssessment::Widening,
                _ => PolicyAssessment::Valid,
            };
            (table, assessment)
        })
        .collect()
}

fn replace_policy_clause(body: &mut String, keyword: &str, clause: &str) {
    if let Some(start) = body.find(keyword) {
        let clause_start = start + keyword.len();
        if let Some(open_rel) = body[clause_start..].find('(') {
            let open = clause_start + open_rel;
            if let Some(existing) = parens_body(&body[open + 1..]) {
                let end = open + 1 + existing.len() + 1;
                body.replace_range(start..end, &format!("{keyword} ({clause})"));
                return;
            }
        }
    }
    body.push_str(&format!(" {keyword} ({clause})"));
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXISTING_READER_GRANTS: &str = r#"
GRANT SELECT ON TABLE sessions TO rss_app_read;
GRANT SELECT ON TABLE dead_letter TO rss_app_read;
GRANT SELECT ON TABLE inbox_receipts TO rss_app_read;
GRANT SELECT ON TABLE dead_letter_archive_receipts TO rss_app_read;
"#;

    fn files(content: &str) -> Vec<(String, String)> {
        vec![(
            "test.sql".to_string(),
            format!("{content}\n{EXISTING_READER_GRANTS}"),
        )]
    }

    fn two_files(c1: &str, c2: &str) -> Vec<(String, String)> {
        vec![
            (
                "file1.sql".to_string(),
                format!("{c1}\n{EXISTING_READER_GRANTS}"),
            ),
            (
                "file2.sql".to_string(),
                format!("{c2}\n{EXISTING_READER_GRANTS}"),
            ),
        ]
    }

    fn reader_acl_files(grant: &str) -> Vec<(String, String)> {
        vec![(
            "0068_reader_fixture.sql".to_string(),
            format!(
                r#"
CREATE TABLE tenant_reader_fixture (
    tenant_id uuid NOT NULL,
    id uuid NOT NULL
);
ALTER TABLE tenant_reader_fixture ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_reader_fixture FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON tenant_reader_fixture
    USING (tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid);
{grant}
"#
            ),
        )]
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
    USING (tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid);
"#;
        let (count, findings) = scan_rls(&files(sql));
        assert_eq!(count, 1, "应识别 1 个 tenant 表");
        assert!(
            findings.is_empty(),
            "三件套齐备不应有 findings: {findings:?}"
        );
    }

    #[test]
    fn red_tenant_relation_without_reader_select_grant() {
        let (count, findings) = scan_rls(&reader_acl_files(""));
        assert_eq!(count, 1);
        assert!(
            findings.iter().any(|finding| {
                finding.subject == "tenant_reader_fixture"
                    && finding.detail.contains("rss_app_read")
                    && finding.detail.contains("SELECT")
            }),
            "new tenant relation must grant exact SELECT to rss_app_read in its migration: {findings:?}"
        );
    }

    #[test]
    fn red_tenant_relation_reader_dml_grant() {
        let (count, findings) = scan_rls(&reader_acl_files(
            "GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE tenant_reader_fixture TO rss_app_read;",
        ));
        assert_eq!(count, 1);
        assert!(
            findings.iter().any(|finding| {
                finding.subject == "tenant_reader_fixture"
                    && finding.detail.contains("rss_app_read")
                    && ["INSERT", "UPDATE", "DELETE"]
                        .iter()
                        .any(|privilege| finding.detail.contains(privilege))
            }),
            "reader ACL must reject every DML privilege, even when SELECT is present: {findings:?}"
        );
    }

    #[test]
    fn green_tenant_relation_exact_reader_select_grant() {
        let (count, findings) = scan_rls(&reader_acl_files(
            "GRANT SELECT ON TABLE tenant_reader_fixture TO rss_app_read;",
        ));
        assert_eq!(count, 1);
        assert!(
            findings.is_empty(),
            "exact tenant-table SELECT grant is the only accepted reader ACL: {findings:?}"
        );
    }

    #[test]
    fn green_dynamic_reader_backfill_covers_preexisting_tenant_relations() {
        let files = vec![
            (
                "0066_existing.sql".to_string(),
                reader_acl_files("")[0].1.clone(),
            ),
            (
                "0067_reader.sql".to_string(),
                r#"
DO $$
DECLARE relation record;
BEGIN
    FOR relation IN
        SELECT n.nspname AS schema_name, c.relname AS relation_name
        FROM pg_class AS c
        JOIN pg_namespace AS n ON n.oid = c.relnamespace
        WHERE n.nspname = 'public'
          AND c.relkind IN ('r', 'p')
          AND EXISTS (
              SELECT 1 FROM pg_attribute AS a
              WHERE a.attrelid = c.oid AND a.attname = 'tenant_id'
          )
    LOOP
        EXECUTE format(
            'GRANT SELECT ON TABLE %I.%I TO rss_app_read',
            relation.schema_name,
            relation.relation_name
        );
    END LOOP;
END
$$;
"#
                .to_string(),
            ),
        ];
        let (count, findings) = scan_rls(&files);
        assert_eq!(count, 1);
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn red_relation_after_dynamic_backfill_requires_same_migration_grant() {
        let files = vec![
            (
                "0067_reader.sql".to_string(),
                r#"
DO $$
DECLARE relation record;
BEGIN
    FOR relation IN
        SELECT n.nspname AS schema_name, c.relname AS relation_name
        FROM pg_class AS c
        JOIN pg_namespace AS n ON n.oid = c.relnamespace
        WHERE n.nspname = 'public'
          AND c.relkind IN ('r', 'p')
          AND EXISTS (
              SELECT 1 FROM pg_attribute AS a
              WHERE a.attrelid = c.oid AND a.attname = 'tenant_id'
          )
    LOOP
        EXECUTE format(
            'GRANT SELECT ON TABLE %I.%I TO rss_app_read',
            relation.schema_name,
            relation.relation_name
        );
    END LOOP;
END
$$;
"#
                .to_string(),
            ),
            (
                "0068_future.sql".to_string(),
                reader_acl_files("")[0].1.clone(),
            ),
        ];
        let (_, findings) = scan_rls(&files);
        assert!(
            findings.iter().any(|finding| {
                finding.rule == Rule::ReaderSelectAbsent
                    && finding.subject == "tenant_reader_fixture"
            }),
            "dynamic backfill must not become implicit future-table authorization: {findings:?}"
        );
    }

    #[test]
    fn red_nonexecuted_format_is_not_a_reader_backfill() {
        let files = vec![
            (
                "0066_existing.sql".to_string(),
                reader_acl_files("")[0].1.clone(),
            ),
            (
                "0067_bait.sql".to_string(),
                "SELECT c.relname FROM pg_class c \
                 JOIN pg_namespace n ON n.oid = c.relnamespace \
                 JOIN pg_attribute a ON a.attrelid = c.oid \
                 WHERE n.nspname = 'public' AND c.relkind = 'r' AND a.attname = 'tenant_id'; \
                 SELECT format('GRANT SELECT ON TABLE %I.%I TO rss_app_read', 'public', 'bait');"
                    .to_string(),
            ),
        ];
        let (_, findings) = scan_rls(&files);
        assert!(
            findings.iter().any(|finding| {
                finding.rule == Rule::ReaderSelectAbsent
                    && finding.subject == "tenant_reader_fixture"
            }),
            "catalog/format string bait without EXECUTE must not satisfy the backfill: {findings:?}"
        );
    }

    #[test]
    fn red_dynamic_backfill_rejects_unrelated_execute_block() {
        let files = vec![
            (
                "0066_existing.sql".to_string(),
                reader_acl_files("")[0].1.clone(),
            ),
            (
                "0067_bait.sql".to_string(),
                r#"
DO $$
BEGIN
    FOR relation IN
        SELECT c.relname
        FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'public'
          AND c.relkind IN ('r', 'p')
          AND EXISTS (
              SELECT 1 FROM pg_attribute a
              WHERE a.attrelid = c.oid AND a.attname = 'tenant_id'
          )
    LOOP
        NULL;
    END LOOP;
END
$$;
DO $grant$
BEGIN
    EXECUTE format(
        'GRANT SELECT ON TABLE %I.%I TO rss_app_read',
        'public',
        'bait'
    );
END
$grant$;
"#
                .to_string(),
            ),
        ];

        let (_, findings) = scan_rls(&files);
        assert!(
            findings.iter().any(|finding| {
                finding.rule == Rule::ReaderSelectAbsent
                    && finding.subject == "tenant_reader_fixture"
            }),
            "catalog FOR and EXECUTE GRANT in unrelated DO blocks must not compose: {findings:?}"
        );
    }

    #[test]
    fn red_dynamic_backfill_rejects_unexecuted_grant_literal() {
        let files = vec![
            (
                "0066_existing.sql".to_string(),
                reader_acl_files("")[0].1.clone(),
            ),
            (
                "0067_bait.sql".to_string(),
                r#"
DO $body$
BEGIN
    FOR relation IN
        SELECT c.relname
        FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'public'
          AND c.relkind IN ('r', 'p')
          AND EXISTS (
              SELECT 1 FROM pg_attribute a
              WHERE a.attrelid = c.oid AND a.attname = 'tenant_id'
          )
    LOOP
        RAISE NOTICE 'EXECUTE format';
        PERFORM format(
            'GRANT SELECT ON TABLE %I.%I TO rss_app_read',
            'public',
            relation.relname
        );
    END LOOP;
END
$body$;
"#
                .to_string(),
            ),
        ];

        let (_, findings) = scan_rls(&files);
        assert!(
            findings.iter().any(|finding| {
                finding.rule == Rule::ReaderSelectAbsent
                    && finding.subject == "tenant_reader_fixture"
            }),
            "an unexecuted GRANT literal and EXECUTE text bait must not satisfy backfill: {findings:?}"
        );
    }

    #[test]
    fn red_dynamic_backfill_rejects_catalog_query_outside_for_source() {
        let files = vec![
            (
                "0066_existing.sql".to_string(),
                reader_acl_files("")[0].1.clone(),
            ),
            (
                "0067_bait.sql".to_string(),
                r#"
DO $$
BEGIN
    PERFORM c.relname
    FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'public'
      AND c.relkind IN ('r', 'p')
      AND EXISTS (
          SELECT 1 FROM pg_attribute a
          WHERE a.attrelid = c.oid AND a.attname = 'tenant_id'
      );

    FOR relation IN SELECT 1 AS relname
    LOOP
        EXECUTE format(
            'GRANT SELECT ON TABLE %I.%I TO rss_app_read',
            'public',
            relation.relname
        );
    END LOOP;
END
$$;
"#
                .to_string(),
            ),
        ];

        let (_, findings) = scan_rls(&files);
        assert!(
            findings.iter().any(|finding| {
                finding.rule == Rule::ReaderSelectAbsent
                    && finding.subject == "tenant_reader_fixture"
            }),
            "catalog bait outside the FOR source must not authorize its loop body: {findings:?}"
        );
    }

    #[test]
    fn red_reader_default_privileges_are_forbidden() {
        let mut files =
            reader_acl_files("GRANT SELECT ON TABLE tenant_reader_fixture TO rss_app_read;");
        files[0].1.push_str(
            "ALTER DEFAULT PRIVILEGES IN SCHEMA public \
             GRANT SELECT ON TABLES TO rss_app_read;",
        );
        let (_, findings) = scan_rls(&files);
        assert!(
            findings
                .iter()
                .any(|finding| finding.rule == Rule::ReaderDefaultPrivileges),
            "default privileges would silently authorize unclassified future tables: {findings:?}"
        );
    }

    #[test]
    fn red_dynamic_reader_dml_grant_is_forbidden() {
        let mut files =
            reader_acl_files("GRANT SELECT ON TABLE tenant_reader_fixture TO rss_app_read;");
        files[0].1.push_str(
            "DO $$ BEGIN EXECUTE format( \
             'GRANT UPDATE ON TABLE %I.%I TO rss_app_read', 'public', 'tenant_reader_fixture'); \
             END $$;",
        );
        let (_, findings) = scan_rls(&files);
        assert!(
            findings.iter().any(|finding| {
                finding.rule == Rule::ReaderDmlGrant && finding.detail.contains("UPDATE")
            }),
            "dynamic SQL must not bypass the reader DML prohibition: {findings:?}"
        );
    }

    #[test]
    fn red_reader_grant_option_is_forbidden() {
        for grant in [
            "GRANT SELECT ON TABLE tenant_reader_fixture TO rss_app_read WITH GRANT OPTION;",
            "GRANT SELECT ON TABLE tenant_reader_fixture TO rss_app_read; \
             DO $$ BEGIN EXECUTE format( \
             'GRANT SELECT ON TABLE %I.%I TO rss_app_read WITH GRANT OPTION', \
             'public', 'tenant_reader_fixture'); END $$;",
        ] {
            let (_, findings) = scan_rls(&reader_acl_files(grant));
            assert!(
                findings
                    .iter()
                    .any(|finding| finding.rule == Rule::ReaderGrantOption),
                "WITH GRANT OPTION must never satisfy the exact reader ACL: {findings:?}"
            );
        }
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
    fn green_dead_letter_archive_receipts_target_schema_has_force_rls() {
        let sql = r#"
CREATE TABLE dead_letter_archive_receipts (
    tenant_id uuid NOT NULL,
    dead_letter_id uuid NOT NULL,
    object_key text NOT NULL,
    PRIMARY KEY (tenant_id, dead_letter_id)
);
ALTER TABLE dead_letter_archive_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE dead_letter_archive_receipts FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON dead_letter_archive_receipts
    USING (tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid);
"#;
        let (count, findings) = scan_rls(&files(sql));
        assert_eq!(count, 1);
        assert!(findings.is_empty(), "{findings:?}");
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
CREATE POLICY p ON sessions
    USING (tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid);
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
CREATE POLICY p ON sessions
    USING (tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid);
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
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule, Rule::TenantTablesAbsent);
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
CREATE POLICY p ON sessions
    USING (tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid);
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
    fn red_policy_missing_with_check_is_weak() {
        let sql = r#"
CREATE TABLE sessions (tenant_id uuid NOT NULL);
ALTER TABLE sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE sessions FORCE ROW LEVEL SECURITY;
CREATE POLICY p ON sessions
    USING (tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid);
"#;
        let (_, findings) = scan_rls(&files(sql));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule, Rule::PolicyWeak);
    }

    #[test]
    fn red_second_permissive_allow_all_is_widening() {
        let sql = r#"
CREATE TABLE sessions (tenant_id uuid NOT NULL);
ALTER TABLE sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE sessions FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON sessions
    USING (tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid);
CREATE POLICY support_bypass ON sessions USING (true) WITH CHECK (true);
"#;
        let (_, findings) = scan_rls(&files(sql));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule, Rule::PolicyWidening);
    }

    #[test]
    fn green_restrictive_policy_may_narrow_canonical_policy() {
        let sql = r#"
CREATE TABLE sessions (tenant_id uuid NOT NULL);
ALTER TABLE sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE sessions FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON sessions
    USING (tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid);
CREATE POLICY deny_all ON sessions AS RESTRICTIVE USING (false) WITH CHECK (false);
"#;
        let (_, findings) = scan_rls(&files(sql));
        assert!(
            findings.is_empty(),
            "restrictive policy cannot widen access: {findings:?}"
        );
    }

    #[test]
    fn red_permissive_policy_cannot_negate_or_compare_canonical_predicate() {
        for predicate in [
            "NOT (tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid)",
            "(tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid) = false",
        ] {
            let sql = format!(
                "CREATE TABLE sessions (tenant_id uuid NOT NULL);\n\
                 ALTER TABLE sessions ENABLE ROW LEVEL SECURITY;\n\
                 ALTER TABLE sessions FORCE ROW LEVEL SECURITY;\n\
                 CREATE POLICY p ON sessions USING ({predicate}) WITH CHECK ({predicate});"
            );
            let (_, findings) = scan_rls(&files(&sql));
            assert_eq!(findings.len(), 1, "predicate must fail closed: {predicate}");
            assert_eq!(findings[0].rule, Rule::PolicyWeak);
        }
    }

    #[test]
    fn red_policy_dependency_shadowing_is_rejected() {
        let tenant_policy = r#"
CREATE TABLE sessions (tenant_id uuid NOT NULL);
ALTER TABLE sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE sessions FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON sessions
    USING (tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid);
"#;
        for shadow in [
            "CREATE OPERATOR tenant_shadow.= (LEFTARG = uuid, RIGHTARG = uuid, FUNCTION = tenant_shadow.always_true);",
            "CREATE OR REPLACE FUNCTION tenant_shadow.current_setting(text, boolean) RETURNS text LANGUAGE sql AS 'SELECT ''''';",
        ] {
            let (_, findings) = scan_rls(&files(&format!("{tenant_policy}\n{shadow}")));
            assert!(
                findings
                    .iter()
                    .any(|finding| finding.rule == Rule::PolicyDependencyShadowing),
                "migration-defined policy dependency shadow must fail closed: {shadow}; {findings:?}"
            );
        }
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

    #[test]
    fn red_using_or_true_is_load_bearing_with_canonical_with_check() {
        let sql = r#"
CREATE TABLE sessions (tenant_id uuid NOT NULL);
ALTER TABLE sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE sessions FORCE ROW LEVEL SECURITY;
CREATE POLICY p ON sessions
    USING (tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid OR true)
    WITH CHECK (tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid);
"#;
        let (_, findings) = scan_rls(&files(sql));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule, Rule::PolicyWeak);
    }

    #[test]
    fn red_with_check_or_true_is_load_bearing_with_canonical_using() {
        let sql = r#"
CREATE TABLE sessions (tenant_id uuid NOT NULL);
ALTER TABLE sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE sessions FORCE ROW LEVEL SECURITY;
CREATE POLICY p ON sessions
    USING (tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid OR true);
"#;
        let (_, findings) = scan_rls(&files(sql));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule, Rule::PolicyWeak);
    }

    #[test]
    fn red_with_check_wrong_column_is_load_bearing_with_canonical_using() {
        let sql = r#"
CREATE TABLE sessions (tenant_id uuid NOT NULL);
ALTER TABLE sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE sessions FORCE ROW LEVEL SECURITY;
CREATE POLICY p ON sessions
    USING (tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid)
    WITH CHECK (store_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid);
"#;
        let (_, findings) = scan_rls(&files(sql));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule, Rule::PolicyWeak);
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
    USING (tenant_id = current_setting('rss.tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('rss.tenant_id', true)::uuid);
"#;
        let c2 = r#"
ALTER POLICY tenant_isolation ON sessions
    USING (tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid);
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
