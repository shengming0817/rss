//! Exact `tenant_id` column detection for migration SQL.
//!
//! Shared by `schema-rls` and `pg-tenant-tx-guard` so both derive the same tenant-table set:
//! only a top-level column named exactly `tenant_id` counts (`scope_tenant_id` /
//! `target_tenant_id` do not).
//!
//! `ref: rust-analyzer xtask/src/main.rs`

use std::collections::{BTreeMap, BTreeSet};

/// Next SQL identifier token (`[a-z0-9_.]`, including schema `.`).
/// Returns `(token, rest)`; empty token means no identifier at the start.
pub(crate) fn split_token(s: &str) -> (&str, &str) {
    let s = s.trim_start();
    let end = s
        .find(|c: char| !c.is_alphanumeric() && c != '_' && c != '.')
        .unwrap_or(s.len());
    (&s[..end], &s[end..])
}

/// After consuming an opening `(`, find the matching `)` and return the body
/// (depth counting handles nested parentheses).
pub(crate) fn parens_body(s: &str) -> Option<&str> {
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

/// Whether a CREATE TABLE body declares an exact column named `tenant_id`.
///
/// Splits on top-level commas and compares each clause's first identifier;
/// substring names like `scope_tenant_id` do not match.
pub(crate) fn body_declares_tenant_id_column(body: &str) -> bool {
    let mut depth = 0usize;
    let mut start = 0usize;
    for (i, c) in body.char_indices() {
        match c {
            '(' => depth += 1,
            ')' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => {
                if clause_starts_with_tenant_id(&body[start..i]) {
                    return true;
                }
                start = i + c.len_utf8();
            }
            _ => {}
        }
    }
    clause_starts_with_tenant_id(&body[start..])
}

pub(crate) fn clause_starts_with_tenant_id(clause: &str) -> bool {
    let (token, _) = split_token(clause);
    token == "tenant_id"
}

/// Extract a table that declares exact `tenant_id` from text after `create table `.
pub(crate) fn extract_tenant_table(after_kw: &str) -> Option<String> {
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
    body_declares_tenant_id_column(body).then(|| name.to_string())
}

/// Keyword followed by end-of-input or whitespace (identifier boundary).
fn strip_sql_keyword<'a>(s: &'a str, kw: &str) -> Option<&'a str> {
    let s = s.trim_start();
    let rest = s.strip_prefix(kw)?;
    if rest.is_empty() || rest.starts_with(|c: char| c.is_whitespace()) {
        Some(rest.trim_start())
    } else {
        None
    }
}

/// Extract a table that gains exact `tenant_id` via `ADD [COLUMN] tenant_id`
/// from text after `alter table `.
pub(crate) fn extract_alter_add_tenant_table(after_kw: &str) -> Option<String> {
    let s = after_kw.trim_start();
    let s = s.strip_prefix("if exists").map_or(s, |r| r.trim_start());
    let (name, rest) = split_token(s);
    if name.is_empty() {
        return None;
    }
    let rest = rest.trim_start();
    let after_add =
        strip_sql_keyword(rest, "add column").or_else(|| strip_sql_keyword(rest, "add"))?;
    let (col, _) = split_token(after_add);
    (col == "tenant_id").then(|| name.to_string())
}

pub(crate) fn unqualified_table(token: &str) -> &str {
    token.rsplit('.').next().unwrap_or(token)
}

/// 剥去 `--` 行注释与 `/* */` 块注释（保留 `\n`；保留字符串字面量内容）。
pub(crate) fn strip_sql_comments(src: &str) -> String {
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
                    out.push(c);
                    st = St::Str;
                }
                _ => out.push(c),
            },
            St::LineComment => {
                if c == '\n' {
                    out.push(c);
                    st = St::Code;
                }
            }
            St::BlockComment => {
                if c == '*' && chars.peek() == Some(&'/') {
                    chars.next();
                    st = St::Code;
                } else if c == '\n' {
                    out.push(c);
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

/// Collect unqualified tenant table names from already-lowercased, comment-stripped SQL.
pub(crate) fn tenant_tables_from_migration_sql(sql: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let mut pos = 0;
    while pos < sql.len() {
        let Some(rel) = sql[pos..].find("create table ") else {
            break;
        };
        let kw_end = pos + rel + "create table ".len();
        if let Some(name) = extract_tenant_table(&sql[kw_end..]) {
            out.insert(unqualified_table(&name).to_string());
        }
        pos = kw_end;
    }
    let mut pos = 0;
    while pos < sql.len() {
        let Some(rel) = sql[pos..].find("alter table ") else {
            break;
        };
        let kw_end = pos + rel + "alter table ".len();
        if let Some(name) = extract_alter_add_tenant_table(&sql[kw_end..]) {
            out.insert(unqualified_table(&name).to_string());
        }
        pos = kw_end;
    }
    out
}

/// Collect unqualified tenant table names from raw migration files
/// (full `--` / `/* */` strip + lowercase).
pub(crate) fn collect_tenant_table_names(files: &[(String, String)]) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for (_, raw) in files {
        let sql = strip_sql_comments(raw).to_lowercase();
        out.extend(tenant_tables_from_migration_sql(&sql));
    }
    out
}

/// Collect unqualified tenant table → first declaring migration file
/// (same strip/collect path as [`collect_tenant_table_names`]).
pub(crate) fn collect_tenant_tables_by_file(
    files: &[(String, String)],
) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for (fname, raw) in files {
        let sql = strip_sql_comments(raw).to_lowercase();
        for name in tenant_tables_from_migration_sql(&sql) {
            out.entry(name).or_insert_with(|| fname.clone());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn tenant_tables_ignore_block_commented_create() {
        let sql = r#"
/* CREATE TABLE public.bait (tenant_id uuid NOT NULL); */
CREATE TABLE public.sessions (tenant_id uuid NOT NULL);
"#;
        let tables = collect_tenant_table_names(&[("t.sql".into(), sql.into())]);
        assert_eq!(
            tables,
            ["sessions"].into_iter().map(str::to_owned).collect(),
            "block-commented CREATE must not enroll: {tables:?}"
        );
    }

    #[test]
    fn tenant_tables_ignore_scope_tenant_id_column() {
        let sql = r#"
CREATE TABLE public.projection_source_capabilities (
    capability_digest bytea PRIMARY KEY,
    scope_tenant_id uuid NOT NULL,
    projection_id text NOT NULL
);
"#;
        let tables = collect_tenant_table_names(&[("0088.sql".into(), sql.into())]);
        assert!(
            !tables.contains("projection_source_capabilities"),
            "scope_tenant_id must not enroll the table: {tables:?}"
        );
    }

    #[test]
    fn tenant_tables_ignore_target_tenant_id_column() {
        let sql = r#"
CREATE TABLE public.l2_dr_recovery_proofs (
    proof_id uuid PRIMARY KEY,
    target_tenant_id uuid NOT NULL,
    epoch_id uuid NOT NULL
);
"#;
        let tables = collect_tenant_table_names(&[("0100.sql".into(), sql.into())]);
        assert!(
            !tables.contains("l2_dr_recovery_proofs"),
            "target_tenant_id must not enroll the table: {tables:?}"
        );
    }

    #[test]
    fn tenant_tables_exact_tenant_id_still_enrolled() {
        let sql = r#"
CREATE TABLE IF NOT EXISTS public.sessions (
    scope_tenant_id uuid NOT NULL,
    tenant_id uuid NOT NULL
);
ALTER TABLE IF EXISTS public.legacy ADD COLUMN tenant_id uuid NOT NULL;
ALTER TABLE public.other ADD tenant_id uuid;
ALTER TABLE public.bait ADD COLUMN tenant_id_extra uuid;
"#;
        let tables = collect_tenant_table_names(&[("t.sql".into(), sql.into())]);
        assert!(
            tables.contains("sessions"),
            "exact tenant_id column must enroll: {tables:?}"
        );
        assert!(
            tables.contains("legacy"),
            "ADD COLUMN tenant_id must enroll: {tables:?}"
        );
        assert!(
            tables.contains("other"),
            "ADD tenant_id must enroll: {tables:?}"
        );
        assert!(
            !tables.contains("bait"),
            "tenant_id_extra must not enroll: {tables:?}"
        );
    }

    #[test]
    fn live_migrations_exclude_projection_source_capabilities() -> anyhow::Result<()> {
        let root = crate::workspace_root()?;
        let dir = root.join("adapters/postgres/migrations");
        let mut files = Vec::new();
        for entry in std::fs::read_dir(&dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("sql") {
                continue;
            }
            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or_default()
                .to_owned();
            files.push((name, std::fs::read_to_string(&path)?));
        }
        let tables = collect_tenant_table_names(&files);
        assert!(
            !tables.contains("projection_source_capabilities"),
            "live migrations must not treat scope_tenant_id table as tenant: {tables:?}"
        );
        Ok(())
    }
}
