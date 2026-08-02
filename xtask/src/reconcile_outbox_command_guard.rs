//! `reconcile-outbox-command-guard` —— durable reconcile command outbox seam guard.
//!
//! INVARIANT: RECONCILE-COMMAND-OUTBOX-SEAM-01 { level = "Medium", exec = "check", source = "code", synthetic_red = "tests::rejects_repository_without_closed_facade_call|tests::rejects_facade_with_split_or_reordered_writes|tests::rejects_string_and_comment_bait", anti_vacuity = "tests::real_workspace_has_repository_to_closed_facade_transaction_topology" }——
//! eventexec reconcile scheduler must not directly publish, depend on an emitter, or append raw outbox rows.
//! Commands may only flow through `DeviceCertificateCommand` → the private reviewed core →
//! `ReviewedFencedCommand`; callers only receive
//! `AttemptScope::record_device_certificate_command`.
//! the Postgres repository must enter one exact-lane transaction and call the closed
//! `ReconcileTx::reconcile_enqueue_command` façade. That façade alone owns the ordered persisted
//! target → attempt/lease → desired-state locks, then command journal, fenced device command,
//! `reconcile_actions`, and outbox writes in the same physical transaction.

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
        let cotx_facade = root.join("adapters/postgres/src/cotx/reconcile.rs");
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
        let cotx_content = std::fs::read_to_string(&cotx_facade).with_context(|| {
            format!(
                "reconcile-outbox-command-guard: read {}",
                cotx_facade.display()
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
        findings.extend(scan_cotx_facade_content(
            Path::new("adapters/postgres/src/cotx/reconcile.rs"),
            &cotx_content,
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
                        "reconcile scheduler must not depend on direct transport/emitter token `{token}`; use ReviewedFencedCommand + AttemptScope seam"
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
        "pub struct ReviewedFencedCommand",
        "generated::command::FencedCommandSpec",
        "record_device_certificate_command",
        "record_reviewed_fenced_command",
        "fn from_spec<C>",
    ] {
        if !stripped.contains(token) {
            findings.push(finding(
                Rule::MissingTransactionalSeam,
                path.display().to_string(),
                format!("durable reconcile scheduler must expose `{token}`"),
            ));
        }
    }
    if stripped.contains("pub fn from_spec") {
        findings.push(finding(
            Rule::RawCommandAuthoring,
            path.display().to_string(),
            "ReviewedFencedCommand::from_spec must remain private to the reconcile module",
        ));
    }
    let governed = stripped.split("#[cfg(test)]").next().unwrap_or(&stripped);
    let mint_calls = governed
        .matches("ReviewedFencedCommand::from_spec(")
        .count();
    let attempt_mint = last_function_body(governed, "record_reviewed_fenced_command")
        .is_some_and(|body| body.contains("ReviewedFencedCommand::from_spec("));
    let shipped_test_mint = content.contains("reconcile-test-support")
        || content.contains("review_fenced_command_for_test");
    if mint_calls != 1 || !attempt_mint || shipped_test_mint {
        findings.push(finding(
            Rule::RawCommandAuthoring,
            path.display().to_string(),
            "reviewed fenced commands must be minted only by AttemptScope; shipped test mint seams are forbidden",
        ));
    }
    if governed.contains("pub async fn record_reviewed_fenced_command")
        || governed.contains("pub async fn record_fenced_command")
    {
        findings.push(finding(
            Rule::RawCommandAuthoring,
            path.display().to_string(),
            "generic fenced command authoring must remain private; only the device-certificate funnel is public",
        ));
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
    let mut findings = Vec::new();
    for (line_no, line) in stripped.lines().enumerate() {
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
        if line.contains("append_outbox_with_projection(") || line.contains("append_outbox(") {
            findings.push(finding(
                Rule::BareOutboxAppend,
                format!("{}:{}", path.display(), line_no + 1),
                "repository must not append outbox or projection rows directly; call the closed reconcile façade",
            ));
        }
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

    let structure = mask_source(content, true);
    match function_body(&structure, "record_fenced_command") {
        Some(function)
            if transactional_write_body(function).is_some_and(|transaction| {
                transaction.contains("tx.reconcile_enqueue_command(ReconcileEnqueue {")
                    && transaction.matches("reconcile_enqueue_command(").count() == 1
            })
                && !function.contains("sqlx::")
                && !function.contains("append_outbox(")
                && !function.contains(".conn")
                && function.contains("CommittedActionOutcome::FactConflictQuarantined")
                && function.contains("ReconcileScheduleError::fact_conflict") => {}
        Some(_) | None => findings.push(finding(
            Rule::MissingTransactionalSeam,
            path.display().to_string(),
            "record_fenced_command must enter one exact-lane write transaction and call tx.reconcile_enqueue_command exactly once; raw SQL/executor access is forbidden",
        )),
    }
    findings
}

fn scan_cotx_facade_content(path: &Path, content: &str) -> Vec<Finding<Rule>> {
    let structure = mask_source(content, true);
    let proof = mask_source(content, false);
    let seam_range = function_body_range(&structure, "reconcile_enqueue_command");
    let mut findings = Vec::new();

    for (offset, _) in structure.match_indices("append_outbox(") {
        if !seam_range
            .as_ref()
            .is_some_and(|range| range.contains(&offset))
        {
            findings.push(finding(
                Rule::BareOutboxAppend,
                path.display().to_string(),
                "append_outbox is allowed only inside ReconcileTx::reconcile_enqueue_command",
            ));
        }
    }

    // Exact-lane ownership is proven by locating the method inside the serving-write impl body;
    // the three-step topology is then checked inside the method's own extracted body.
    let exact_lane_owner = braced_body_after(&structure, "impl ReconcileTx<'_, ServingWriteLane>")
        .is_some_and(|body| body.contains("fn reconcile_enqueue_command"))
        && !structure.contains("impl_reconcile_enqueue_command!");
    if !exact_lane_owner
        || !function_body(&structure, "reconcile_enqueue_command")
            .zip(function_body(&proof, "reconcile_enqueue_command"))
            .is_some_and(|(structure, proof)| has_ordered_facade_steps(structure, proof))
    {
        findings.push(finding(
            Rule::MissingTransactionalSeam,
            path.display().to_string(),
            "ReconcileTx<ServingWriteLane>::reconcile_enqueue_command must own ordered target/attempt/desired-state locks and command-journal/device-command/action/outbox writes in one closed transaction façade, including fact-conflict quarantine",
        ));
    }
    findings
}

fn function_body<'a>(content: &'a str, name: &str) -> Option<&'a str> {
    let range = function_body_range(content, name)?;
    content.get(range)
}

fn last_function_body<'a>(content: &'a str, name: &str) -> Option<&'a str> {
    let needle = format!("fn {name}");
    let start = content.rfind(&needle)?;
    let open = start + content[start..].find('{')?;
    content.get(braced_range(content, open)?)
}

fn function_body_range(content: &str, name: &str) -> Option<Range<usize>> {
    let needle = format!("fn {name}");
    let start = content.find(&needle)?;
    let open_rel = content[start..].find('{')?;
    braced_range(content, start + open_rel)
}

fn braced_body_after<'a>(content: &'a str, header: &str) -> Option<&'a str> {
    let start = content.find(header)?;
    let open = start + content[start..].find('{')?;
    content.get(braced_range(content, open)?)
}

fn transactional_write_body(content: &str) -> Option<&str> {
    let write = content.find(".reconcile_write(")?;
    let closure = write + content[write..].find("|mut tx|")?;
    let open = closure + content[closure..].find('{')?;
    let range = braced_range(content, open)?;
    content.get(range)
}

fn has_ordered_facade_steps(structure: &str, proof: &str) -> bool {
    let Some(target_lock) = structure
        .find(".reconcile_lock_command_target(enqueue.attempt_id, enqueue.fence.target_id)")
    else {
        return false;
    };
    let Some(attempt_lock) =
        structure.find(".reconcile_lock_attempt_evidence(enqueue.attempt_id, &enqueue.fence)")
    else {
        return false;
    };
    let Some(desired_lock) = structure.find(".reconcile_lock_desired_generation(") else {
        return false;
    };
    let Some(prepare) = structure.find("prepare_command(&mut command, enqueue.intent)") else {
        return false;
    };
    let desired_lock_call = &structure[desired_lock..prepare];
    if [
        "enqueue.evidence.device_id()",
        "enqueue.attempt_id",
        "&enqueue.fence",
        "target.claimed_wake_version",
    ]
    .iter()
    .any(|argument| !desired_lock_call.contains(argument))
    {
        return false;
    }
    let Some(journal) = structure.find("insert_journal_claim(") else {
        return false;
    };
    let Some(device_command) = structure.find(".reconcile_install_fenced_command(") else {
        return false;
    };
    let Some(action) = sqlx_query_containing(proof, "INSERT INTO reconcile_actions") else {
        return false;
    };
    let Some(append) =
        structure.find("append_outbox(&mut outbox, &prepared.entry, enqueue.envelope)")
    else {
        return false;
    };
    target_lock < attempt_lock
        && attempt_lock < desired_lock
        && desired_lock < prepare
        && prepare < journal
        && journal < device_command
        && device_command < action
        && action < append
        && proof.contains("SAVEPOINT reconcile_command_write")
        && proof.contains("ROLLBACK TO SAVEPOINT reconcile_command_write")
        && proof.contains("RELEASE SAVEPOINT reconcile_command_write")
        && proof.contains("SET status = 'disabled'")
        && structure.contains("CommittedActionOutcome::FactConflictQuarantined")
}

fn sqlx_query_containing(content: &str, required_sql: &str) -> Option<usize> {
    content
        .match_indices("sqlx::query(")
        .find_map(|(start, _)| {
            let tail = &content[start..];
            let execute = tail.find(".execute(&mut *self.conn)")?;
            let next_query = tail["sqlx::query(".len()..]
                .find("sqlx::query(")
                .map(|next| next + "sqlx::query(".len());
            if next_query.is_some_and(|next| next < execute) {
                return None;
            }
            tail[..execute].contains(required_sql).then_some(start)
        })
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

/// Masks comments and, when requested, string literals while preserving byte offsets.
///
/// Structural proof therefore cannot be satisfied by comments or string bait, while the parallel
/// SQL proof can inspect the literal owned by an actual `sqlx::query` call at the same offsets.
fn mask_source(src: &str, mask_strings: bool) -> String {
    #[derive(PartialEq)]
    enum State {
        Code,
        LineComment,
        BlockComment,
        String,
    }

    let mut out = String::with_capacity(src.len());
    let mut chars = src.chars().peekable();
    let mut state = State::Code;
    while let Some(ch) = chars.next() {
        match state {
            State::Code => match ch {
                '/' if chars.peek() == Some(&'/') => {
                    out.push_str("  ");
                    chars.next();
                    state = State::LineComment;
                }
                '/' if chars.peek() == Some(&'*') => {
                    out.push_str("  ");
                    chars.next();
                    state = State::BlockComment;
                }
                '"' => {
                    state = State::String;
                    push_masked(&mut out, ch, mask_strings);
                }
                _ => out.push(ch),
            },
            State::LineComment => {
                if ch == '\n' {
                    state = State::Code;
                    out.push('\n');
                } else {
                    push_masked(&mut out, ch, true);
                }
            }
            State::BlockComment => {
                if ch == '*' && chars.peek() == Some(&'/') {
                    out.push_str("  ");
                    chars.next();
                    state = State::Code;
                } else if ch == '\n' {
                    out.push('\n');
                } else {
                    push_masked(&mut out, ch, true);
                }
            }
            State::String => {
                push_masked(&mut out, ch, mask_strings);
                if ch == '\\' {
                    if let Some(escaped) = chars.next() {
                        push_masked(&mut out, escaped, mask_strings);
                    }
                } else if ch == '"' {
                    state = State::Code;
                }
            }
        }
    }
    out
}

fn push_masked(out: &mut String, ch: char, mask: bool) {
    if mask && ch != '\n' {
        out.extend(std::iter::repeat_n(' ', ch.len_utf8()));
    } else {
        out.push(ch);
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    const GREEN_REPOSITORY: &str = r#"
        impl ReconcileScheduleStore for PgReconcileStore {
            async fn record_fenced_command(&self) {
                let committed = self.write.reconcile_write(tenant, move |mut tx| {
                    Box::pin(async move {
                        tx.reconcile_enqueue_command(ReconcileEnqueue {
                            attempt_id: &attempt_id,
                            fence,
                            action_kind,
                            intent,
                            envelope: &env,
                        }).await
                    })
                }).await?;
                match committed {
                    CommittedActionOutcome::FactConflictQuarantined => {
                        Err(ReconcileScheduleError::fact_conflict(conflict))
                    }
                    _ => Ok(()),
                }
            }
        }
    "#;

    const GREEN_FACADE: &str = r#"
        impl ReconcileTx<'_, ServingWriteLane> {
            pub(crate) async fn reconcile_enqueue_command(&mut self, enqueue: ReconcileEnqueue<'_>) {
                let target = self
                    .reconcile_lock_command_target(enqueue.attempt_id, enqueue.fence.target_id)
                    .await?;
                let Some(evidence) = self
                    .reconcile_lock_attempt_evidence(enqueue.attempt_id, &enqueue.fence)
                    .await?
                else { return Ok(CommittedActionOutcome::Lost); };
                let desired = self
                    .reconcile_lock_desired_generation(
                        enqueue.evidence.device_id(),
                        enqueue.attempt_id,
                        &enqueue.fence,
                        target.claimed_wake_version,
                    )
                    .await?;
                sqlx::query("SAVEPOINT reconcile_command_write")
                    .execute(&mut *self.conn).await?;
                let mut command = CommandTx::from_parts(&mut *self.conn, self.tenant);
                let prepared = prepare_command(&mut command, enqueue.intent).await?;
                insert_journal_claim(&mut command, &prepared, enqueue.envelope).await?;
                self.reconcile_install_fenced_command(
                    &enqueue.evidence,
                    prepared.entry.idem_key().as_str(),
                    enqueue.deadline_epoch_seconds,
                ).await?;
                sqlx::query("INSERT INTO reconcile_actions (tenant_id) VALUES ($1)")
                    .execute(&mut *self.conn).await?;
                let mut outbox = OutboxTx::from_parts(&mut *self.conn, self.tenant);
                append_outbox(&mut outbox, &prepared.entry, enqueue.envelope).await?;
                sqlx::query("ROLLBACK TO SAVEPOINT reconcile_command_write")
                    .execute(&mut *self.conn).await?;
                sqlx::query("RELEASE SAVEPOINT reconcile_command_write")
                    .execute(&mut *self.conn).await?;
                sqlx::query("UPDATE reconcile_targets SET status = 'disabled'")
                    .execute(&mut *self.conn).await?;
                Ok(CommittedActionOutcome::FactConflictQuarantined)
            }
        }
    "#;

    #[test]
    fn reconcile_outbox_command_guard_flags_direct_publisher_and_append() {
        let findings = scan_scheduler_content(
            Path::new("crates/eventexec/src/reconcile.rs"),
            r#"
            pub struct ReviewedFencedCommand;
            fn from_spec<C>() where C: generated::command::FencedCommandSpec {}
            impl AttemptScope {
                async fn record_fenced_command(&self) {}
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
            pub struct ReviewedFencedCommand { private: () }
            fn from_spec<C>() where C: generated::command::FencedCommandSpec {}
            impl AttemptScope {
                pub async fn record_device_certificate_command(&self) {
                    self.record_reviewed_fenced_command(command).await;
                }
                async fn record_reviewed_fenced_command(&self) {
                    ReviewedFencedCommand::from_spec(command);
                }
            }
            "#,
        );
        let pg_findings = scan_pg_adapter_content(
            Path::new("adapters/postgres/src/reconcile.rs"),
            GREEN_REPOSITORY,
        );
        let facade_findings = scan_cotx_facade_content(
            Path::new("adapters/postgres/src/cotx/reconcile.rs"),
            GREEN_FACADE,
        );
        assert!(scheduler_findings.is_empty(), "{scheduler_findings:?}");
        assert!(pg_findings.is_empty(), "{pg_findings:?}");
        assert!(facade_findings.is_empty(), "{facade_findings:?}");
    }

    #[test]
    fn reconcile_outbox_command_guard_requires_fact_conflict_quarantine() {
        let findings = scan_pg_adapter_content(
            Path::new("adapters/postgres/src/reconcile.rs"),
            r#"
            impl ReconcileScheduleStore for PgReconcileStore {
                async fn record_fenced_command(&self) {
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
            async fn record_fenced_command(&self) {
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
                async fn record_fenced_command(&self) {
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
                async fn record_fenced_command(&self) {
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
            async fn record_fenced_command(&self) {
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
                async fn record_fenced_command(&self) {
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

    #[test]
    fn rejects_repository_without_closed_facade_call() {
        let source = GREEN_REPOSITORY.replace(
            "tx.reconcile_enqueue_command(ReconcileEnqueue {",
            "other.enqueue(ReconcileEnqueue {",
        );
        let findings =
            scan_pg_adapter_content(Path::new("adapters/postgres/src/reconcile.rs"), &source);
        assert!(
            findings
                .iter()
                .any(|finding| finding.rule == Rule::MissingTransactionalSeam),
            "{findings:?}"
        );
    }

    #[test]
    fn rejects_facade_with_split_or_reordered_writes() {
        let missing_action = GREEN_FACADE.replace(
            "INSERT INTO reconcile_actions (tenant_id) VALUES ($1)",
            "SELECT 1",
        );
        let reordered = GREEN_FACADE
            .replacen(
                "INSERT INTO reconcile_actions (tenant_id) VALUES ($1)",
                "SELECT 1",
                1,
            )
            .replace(
                "append_outbox(&mut outbox, &prepared.entry, enqueue.envelope).await?;",
                "append_outbox(&mut outbox, &prepared.entry, enqueue.envelope).await?;\n                // action is intentionally moved after outbox\n                sqlx::query(\"INSERT INTO reconcile_actions (tenant_id) VALUES ($1)\")\n                    .execute(&mut *self.conn).await?;",
            );
        let wrong_lane = GREEN_FACADE.replace("ServingWriteLane", "MaintenanceWriteLane");
        let missing_attempt_fence = GREEN_FACADE.replace(
            ".reconcile_lock_attempt_evidence(enqueue.attempt_id, &enqueue.fence)",
            ".reconcile_lock_held_lease(&enqueue.fence)",
        );
        let missing_journal = GREEN_FACADE.replace("insert_journal_claim(", "skip_journal_claim(");
        let missing_device_command = GREEN_FACADE.replace(
            "self.reconcile_install_fenced_command(",
            "self.unfenced_command_insert(",
        );
        for source in [
            missing_action.as_str(),
            reordered.as_str(),
            wrong_lane.as_str(),
            missing_attempt_fence.as_str(),
            missing_journal.as_str(),
            missing_device_command.as_str(),
        ] {
            let findings = scan_cotx_facade_content(
                Path::new("adapters/postgres/src/cotx/reconcile.rs"),
                source,
            );
            assert!(
                findings
                    .iter()
                    .any(|finding| finding.rule == Rule::MissingTransactionalSeam),
                "{findings:?}"
            );
        }
    }

    #[test]
    fn rejects_string_and_comment_bait() {
        let findings = scan_cotx_facade_content(
            Path::new("adapters/postgres/src/cotx/reconcile.rs"),
            r#"
            impl TenantTx<'_, ServingWriteLane> {
                async fn reconcile_enqueue_command(&mut self) {
                    let bait = "self.reconcile_lock_attempt_evidence(enqueue.attempt_id, &enqueue.fence) \
                        prepare_command(self, enqueue.intent) \
                        append_outbox(self, &prepared.entry, enqueue.envelope) \
                        INSERT INTO reconcile_actions SAVEPOINT reconcile_command_write \
                        ROLLBACK TO SAVEPOINT reconcile_command_write \
                        RELEASE SAVEPOINT reconcile_command_write SET status = 'disabled' \
                        CommittedActionOutcome::FactConflictQuarantined";
                    // self.reconcile_lock_attempt_evidence(enqueue.attempt_id, &enqueue.fence)
                    // append_outbox(self, &prepared.entry, enqueue.envelope)
                }
            }
            "#,
        );
        assert!(
            findings
                .iter()
                .any(|finding| finding.rule == Rule::MissingTransactionalSeam),
            "{findings:?}"
        );
    }

    #[test]
    #[allow(clippy::expect_used)] // reason: real workspace façade methods must exist for topology proof.
    fn real_workspace_has_repository_to_closed_facade_transaction_topology() -> anyhow::Result<()> {
        let root = workspace_root()?;
        let repository = std::fs::read_to_string(root.join("adapters/postgres/src/reconcile.rs"))?;
        let facade = std::fs::read_to_string(root.join("adapters/postgres/src/cotx/reconcile.rs"))?;
        let facade_structure = mask_source(&facade, true);
        let facade_proof = mask_source(&facade, false);
        let facade_structure_body = function_body(&facade_structure, "reconcile_enqueue_command")
            .expect("real façade method must exist");
        let facade_proof_body = function_body(&facade_proof, "reconcile_enqueue_command")
            .expect("real façade SQL body must exist");
        assert!(
            braced_body_after(&facade_structure, "impl ReconcileTx<'_, ServingWriteLane>")
                .is_some_and(|body| body.contains("fn reconcile_enqueue_command")),
            "real façade must belong to the exact serving-write lane"
        );
        assert!(
            has_ordered_facade_steps(facade_structure_body, facade_proof_body),
            "real façade must retain ordered fencing and journal/device-command/action/outbox topology"
        );
        let repository_findings =
            scan_pg_adapter_content(Path::new("adapters/postgres/src/reconcile.rs"), &repository);
        let facade_findings = scan_cotx_facade_content(
            Path::new("adapters/postgres/src/cotx/reconcile.rs"),
            &facade,
        );
        assert!(repository_findings.is_empty(), "{repository_findings:?}");
        assert!(facade_findings.is_empty(), "{facade_findings:?}");
        Ok(())
    }
}
