//! `reconcile-outbox-command-guard` —— durable reconcile command outbox seam guard.
//!
//! INVARIANT: RECONCILE-COMMAND-OUTBOX-SEAM-01 { level = "Medium", exec = "verify", source = "code" }——
//! eventexec reconcile scheduler must not directly publish, depend on an emitter, or append raw outbox rows.
//! Commands may only flow through generated `TypedCommandSpec` → `ReviewedCommand` →
//! `AttemptScope::record_action_and_enqueue_command`;
//! the Postgres adapter may call `append_outbox` only inside the transactional implementation of that seam.

use std::ops::Range;
use std::path::Path;

use anyhow::{Context as _, Result};

use crate::diagnostic::{Finding, GovernanceCheck, finding};
use crate::src_scan::strip_comments;
use crate::workspace_root;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Rule {
    DirectTransport,
    BareOutboxAppend,
    MissingTransactionalSeam,
    RawCommandAuthoring,
}

pub(crate) struct ReconcileOutboxCommandGuard;

impl GovernanceCheck for ReconcileOutboxCommandGuard {
    type Rule = Rule;

    fn name(&self) -> &'static str {
        "reconcile-outbox-command-guard"
    }

    fn check(&self) -> Result<(String, Vec<Finding<Self::Rule>>)> {
        let root = workspace_root()?;
        let scheduler = root.join("crates/eventexec/src/reconcile.rs");
        let pg_adapter = root.join("adapters/postgres/src/reconcile.rs");
        let scheduler_content = std::fs::read_to_string(&scheduler).with_context(|| {
            format!(
                "reconcile-outbox-command-guard: read {}",
                scheduler.display()
            )
        })?;
        let pg_content = std::fs::read_to_string(&pg_adapter).with_context(|| {
            format!(
                "reconcile-outbox-command-guard: read {}",
                pg_adapter.display()
            )
        })?;

        let mut findings = Vec::new();
        findings.extend(scan_scheduler_content(
            Path::new("crates/eventexec/src/reconcile.rs"),
            &scheduler_content,
        ));
        findings.extend(scan_pg_adapter_content(
            Path::new("adapters/postgres/src/reconcile.rs"),
            &pg_content,
        ));
        Ok((
            "reconcile scheduler command writes stay behind the typed transactional outbox seam"
                .to_string(),
            findings,
        ))
    }
}

fn scan_scheduler_content(path: &Path, content: &str) -> Vec<Finding<Rule>> {
    let stripped = strip_comments(content);
    let mut findings = Vec::new();
    for (line_no, line) in stripped.lines().enumerate() {
        for token in [
            "DynOutboxEmitter",
            "OutboxEmitter",
            "Publisher",
            "PublishRequest",
        ] {
            if line.contains(token) {
                findings.push(finding(
                    Rule::DirectTransport,
                    format!("{}:{}", path.display(), line_no + 1),
                    format!(
                        "reconcile scheduler must not depend on direct transport/emitter token `{token}`; use ReviewedCommand + AttemptScope seam"
                    ),
                ));
            }
        }
        for token in [".publish(", "publish(", ".emit(", "command::emit_async"] {
            if line.contains(token) {
                findings.push(finding(
                    Rule::DirectTransport,
                    format!("{}:{}", path.display(), line_no + 1),
                    format!(
                        "reconcile scheduler must not directly dispatch `{token}`; use the transactional command outbox seam"
                    ),
                ));
            }
        }
        for token in ["append_outbox(", "append_outbox_with_projection("] {
            if line.contains(token) {
                findings.push(finding(
                    Rule::BareOutboxAppend,
                    format!("{}:{}", path.display(), line_no + 1),
                    format!(
                        "eventexec reconcile must not append outbox rows directly (`{token}`); provider owns the transactional seam"
                    ),
                ));
            }
        }
    }
    for token in [
        "pub struct ReviewedCommand",
        "generated::command::TypedCommandSpec",
        "record_action_and_enqueue_command",
    ] {
        if !stripped.contains(token) {
            findings.push(finding(
                Rule::MissingTransactionalSeam,
                path.display().to_string(),
                format!("durable reconcile scheduler must expose `{token}`"),
            ));
        }
    }
    for token in [
        "pub struct StableDispatchKey",
        "dispatch_key: StableDispatchKey",
    ] {
        if stripped.contains(token) {
            findings.push(finding(
                Rule::RawCommandAuthoring,
                path.display().to_string(),
                format!(
                    "durable reconcile must not expose raw command authoring token `{token}`; accept generated typed specs"
                ),
            ));
        }
    }
    findings
}

fn scan_pg_adapter_content(path: &Path, content: &str) -> Vec<Finding<Rule>> {
    let stripped = strip_comments(content);
    let proof_content = strip_comments_preserve_strings(content);
    let seam_range = function_body_range(&stripped, "record_action_and_enqueue_command");
    let mut findings = Vec::new();
    let mut line_start = 0_usize;
    for (line_no, line) in stripped.split_inclusive('\n').enumerate() {
        if line.contains(".publish(")
            || line.contains(".emit(")
            || line.contains("Publisher")
            || line.contains("PublishRequest")
            || line.contains("DynOutboxEmitter")
            || line.contains("OutboxEmitter")
        {
            findings.push(finding(
                Rule::DirectTransport,
                format!("{}:{}", path.display(), line_no + 1),
                "postgres reconcile adapter must not publish directly; it may only append the durable outbox row",
            ));
        }
        if line.contains("append_outbox_with_projection(") {
            findings.push(finding(
                Rule::BareOutboxAppend,
                format!("{}:{}", path.display(), line_no + 1),
                "reconcile command seam must not mirror to projection_events",
            ));
        }
        if line.contains("append_outbox(")
            && !seam_range
                .as_ref()
                .is_some_and(|range| range.contains(&line_start))
        {
            findings.push(finding(
                Rule::BareOutboxAppend,
                format!("{}:{}", path.display(), line_no + 1),
                "append_outbox is allowed only inside record_action_and_enqueue_command",
            ));
        }
        line_start = line_start.saturating_add(line.len());
    }

    for token in [
        "pub struct ReconcileActionInsert",
        "pub async fn append_action",
    ] {
        if stripped.contains(token) {
            findings.push(finding(
                Rule::MissingTransactionalSeam,
                path.display().to_string(),
                format!(
                    "postgres reconcile adapter must not expose action-only public API `{token}`"
                ),
            ));
        }
    }

    match function_body(&proof_content, "record_action_and_enqueue_command") {
        Some(function)
            if transactional_write_body(function)
                .is_some_and(has_ordered_transactional_seam_tokens)
                && function.contains("ReconcileScheduleError::fact_conflict") => {}
        Some(_) | None => findings.push(finding(
            Rule::MissingTransactionalSeam,
            path.display().to_string(),
            "record_action_and_enqueue_command must CAS the lease, append reconcile_actions, and append outbox in one transaction",
        )),
    }
    findings
}

fn function_body<'a>(content: &'a str, name: &str) -> Option<&'a str> {
    let range = function_body_range(content, name)?;
    content.get(range)
}

fn function_body_range(content: &str, name: &str) -> Option<Range<usize>> {
    let needle = format!("fn {name}");
    let start = content.find(&needle)?;
    let open_rel = content[start..].find('{')?;
    braced_range(content, start + open_rel)
}

fn transactional_write_body(content: &str) -> Option<&str> {
    let write = content.find(".write(")?;
    let closure = write + content[write..].find("|tx|")?;
    let open = closure + content[closure..].find('{')?;
    let range = braced_range(content, open)?;
    content.get(range)
}

fn has_ordered_transactional_seam_tokens(content: &str) -> bool {
    let Some(lock) = content.find("lock_held_lease(tx,") else {
        return false;
    };
    let Some(action_rel) = content[lock..].find("INSERT INTO reconcile_actions") else {
        return false;
    };
    let action = lock + action_rel;
    content[action..].contains("append_outbox(tx,")
        && content.contains("begin_reconcile_command_savepoint(tx)")
        && content.contains("rollback_reconcile_command_savepoint(tx)")
        && content.contains("status = 'disabled'")
        && content.contains("CommittedActionOutcome::FactConflictQuarantined")
}

fn braced_range(content: &str, open: usize) -> Option<Range<usize>> {
    let mut depth = 0_u32;
    for (offset, ch) in content[open..].char_indices() {
        match ch {
            '{' => depth = depth.saturating_add(1),
            '}' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return Some(open..open + offset + 1);
                }
            }
            _ => {}
        }
    }
    None
}

fn strip_comments_preserve_strings(src: &str) -> String {
    #[derive(PartialEq)]
    enum State {
        Code,
        LineComment,
        BlockComment,
        String,
        Char,
    }

    let mut out = String::with_capacity(src.len());
    let mut chars = src.chars().peekable();
    let mut state = State::Code;
    while let Some(ch) = chars.next() {
        match state {
            State::Code => match ch {
                '/' if chars.peek() == Some(&'/') => {
                    chars.next();
                    state = State::LineComment;
                }
                '/' if chars.peek() == Some(&'*') => {
                    chars.next();
                    state = State::BlockComment;
                }
                '"' => {
                    state = State::String;
                    out.push(ch);
                }
                '\'' => {
                    state = State::Char;
                    out.push(ch);
                }
                _ => out.push(ch),
            },
            State::LineComment => {
                if ch == '\n' {
                    state = State::Code;
                    out.push('\n');
                }
            }
            State::BlockComment => {
                if ch == '*' && chars.peek() == Some(&'/') {
                    chars.next();
                    state = State::Code;
                } else if ch == '\n' {
                    out.push('\n');
                }
            }
            State::String => {
                out.push(ch);
                if ch == '\\' {
                    if let Some(escaped) = chars.next() {
                        out.push(escaped);
                    }
                } else if ch == '"' {
                    state = State::Code;
                }
            }
            State::Char => {
                out.push(ch);
                if ch == '\\' {
                    if let Some(escaped) = chars.next() {
                        out.push(escaped);
                    }
                } else if ch == '\'' {
                    state = State::Code;
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reconcile_outbox_command_guard_flags_direct_publisher_and_append() {
        let findings = scan_scheduler_content(
            Path::new("crates/eventexec/src/reconcile.rs"),
            r#"
            pub struct ReviewedCommand;
            fn from_spec<C: generated::command::TypedCommandSpec>() {}
            impl AttemptScope {
                async fn record_action_and_enqueue_command(&self) {}
            }
            pub struct StableDispatchKey;
            fn bad(emitter: DynOutboxEmitter, publisher: Publisher) {
                publisher.publish(msg);
                emitter.emit(entry, env);
                append_outbox(tx, entry, env);
            }
            "#,
        );
        assert!(findings.iter().any(|f| f.rule == Rule::DirectTransport));
        assert!(findings.iter().any(|f| f.rule == Rule::BareOutboxAppend));
    }

    #[test]
    fn reconcile_outbox_command_guard_allows_typed_transactional_seam() {
        let scheduler_findings = scan_scheduler_content(
            Path::new("crates/eventexec/src/reconcile.rs"),
            r#"
            pub struct ReviewedCommand { private: () }
            fn from_spec<C: generated::command::TypedCommandSpec>() {}
            impl AttemptScope {
                async fn record_action_and_enqueue_command(&self) {}
            }
            "#,
        );
        let pg_findings = scan_pg_adapter_content(
            Path::new("adapters/postgres/src/reconcile.rs"),
            r#"
            impl ReconcileScheduleStore for PgReconcileStore {
                pub async fn record_action_and_enqueue_command(&self) {
                    self.pool.write(tenant, move |tx| {
                        Box::pin(async move {
                            let held = lock_held_lease(tx, tenant, target, token, epoch).await?;
                            begin_reconcile_command_savepoint(tx).await?;
                            sqlx::query("INSERT INTO reconcile_actions (tenant_id) VALUES ($1)");
                            append_outbox(tx, &entry, &env).await?;
                            rollback_reconcile_command_savepoint(tx).await?;
                            sqlx::query("UPDATE reconcile_targets SET status = 'disabled'");
                            Ok(CommittedActionOutcome::FactConflictQuarantined)
                            ReconcileScheduleError::fact_conflict(reason)
                        })
                    });
                }
            }
            "#,
        );
        assert!(scheduler_findings.is_empty(), "{scheduler_findings:?}");
        assert!(pg_findings.is_empty(), "{pg_findings:?}");
    }

    #[test]
    fn reconcile_outbox_command_guard_requires_fact_conflict_quarantine() {
        let findings = scan_pg_adapter_content(
            Path::new("adapters/postgres/src/reconcile.rs"),
            r#"
            impl ReconcileScheduleStore for PgReconcileStore {
                async fn record_action_and_enqueue_command(&self) {
                    self.pool.write(tenant, move |tx| {
                        Box::pin(async move {
                            let held = lock_held_lease(tx, tenant, target, token, epoch).await?;
                            sqlx::query("INSERT INTO reconcile_actions (tenant_id) VALUES ($1)");
                            append_outbox(tx, &entry, &env).await?;
                        })
                    });
                }
            }
            "#,
        );
        assert!(
            findings
                .iter()
                .any(|finding| finding.rule == Rule::MissingTransactionalSeam)
        );
    }

    #[test]
    fn reconcile_outbox_command_guard_flags_postgres_append_outside_seam() {
        let findings = scan_pg_adapter_content(
            Path::new("adapters/postgres/src/reconcile.rs"),
            r#"
            fn helper() {
                append_outbox(tx, entry, env);
            }
            async fn record_action_and_enqueue_command(&self) {
                self.pool.write(tenant, move |tx| {
                    Box::pin(async move {
                        let held = lock_held_lease(tx, tenant, target, token, epoch).await?;
                        sqlx::query("INSERT INTO reconcile_actions (tenant_id) VALUES ($1)");
                        append_outbox(tx, &entry, &env).await?;
                    })
                });
            }
            "#,
        );
        assert!(findings.iter().any(|f| f.rule == Rule::BareOutboxAppend));
    }

    #[test]
    fn reconcile_outbox_command_guard_ignores_comment_only_seam_tokens() {
        let findings = scan_pg_adapter_content(
            Path::new("adapters/postgres/src/reconcile.rs"),
            r#"
            impl ReconcileScheduleStore for PgReconcileStore {
                async fn record_action_and_enqueue_command(&self) {
                    self.pool.write(tenant, move |tx| {
                        Box::pin(async move {
                            // lock_held_lease(tx, tenant, target, token, epoch).await?;
                            // INSERT INTO reconcile_actions
                            // append_outbox(tx, &entry, &env).await?;
                        })
                    });
                }
            }
            "#,
        );
        assert!(
            findings
                .iter()
                .any(|f| f.rule == Rule::MissingTransactionalSeam)
        );
    }

    #[test]
    fn reconcile_outbox_command_guard_flags_pub_async_helper_after_seam() {
        let findings = scan_pg_adapter_content(
            Path::new("adapters/postgres/src/reconcile.rs"),
            r#"
            impl ReconcileScheduleStore for PgReconcileStore {
                async fn record_action_and_enqueue_command(&self) {
                    self.pool.write(tenant, move |tx| {
                        Box::pin(async move {
                            let held = lock_held_lease(tx, tenant, target, token, epoch).await?;
                            sqlx::query("INSERT INTO reconcile_actions (tenant_id) VALUES ($1)");
                            append_outbox(tx, &entry, &env).await?;
                        })
                    });
                }
            }

            pub async fn helper() {
                append_outbox(tx, &entry, &env).await?;
            }
            "#,
        );
        assert!(findings.iter().any(|f| f.rule == Rule::BareOutboxAppend));
    }

    #[test]
    fn reconcile_outbox_command_guard_flags_action_only_public_api() {
        let findings = scan_pg_adapter_content(
            Path::new("adapters/postgres/src/reconcile.rs"),
            r#"
            pub struct ReconcileActionInsert<'a> {
                pub attempt_id: &'a str,
            }
            pub async fn append_action(&self) {}
            async fn record_action_and_enqueue_command(&self) {
                self.pool.write(tenant, move |tx| {
                    Box::pin(async move {
                        let held = lock_held_lease(tx, tenant, target, token, epoch).await?;
                        sqlx::query("INSERT INTO reconcile_actions (tenant_id) VALUES ($1)");
                        append_outbox(tx, &entry, &env).await?;
                    })
                });
            }
            "#,
        );
        assert!(
            findings
                .iter()
                .any(|f| f.rule == Rule::MissingTransactionalSeam)
        );
    }

    #[test]
    fn reconcile_outbox_command_guard_flags_split_transaction_seam() {
        let findings = scan_pg_adapter_content(
            Path::new("adapters/postgres/src/reconcile.rs"),
            r#"
            impl ReconcileScheduleStore for PgReconcileStore {
                async fn record_action_and_enqueue_command(&self) {
                    self.pool.write(tenant, move |tx| {
                        Box::pin(async move {
                            let held = lock_held_lease(tx, tenant, target, token, epoch).await?;
                            sqlx::query("INSERT INTO reconcile_actions (tenant_id) VALUES ($1)");
                        })
                    });
                    self.pool.write(tenant, move |tx| {
                        Box::pin(async move {
                            append_outbox(tx, &entry, &env).await?;
                        })
                    });
                }
            }
            "#,
        );
        assert!(
            findings
                .iter()
                .any(|f| f.rule == Rule::MissingTransactionalSeam)
        );
    }
}
