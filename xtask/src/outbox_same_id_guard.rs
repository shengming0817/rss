//! Cross-SQL/Rust/ops guard for the bounded same-ID outbox delivery funnel.
//!
//! INVARIANT: OUTBOX-SAME-ID-WINDOW-01 { level = "Medium", exec = "check", source = "code", synthetic_red = "tests::scan_content_rejects_same_id_funnel_bypasses", anti_vacuity = "tests::scan_content_accepts_complete_same_id_funnel" }——
//! one no-compile gate binds the 0060/0061 schema, private typed policy, closed publish preflight,
//! expired-resolution evidence/ACL, policy-bound inbox sweep, and executable alert consumer. Each
//! local mechanism is Hard where the database or Rust type system can enforce it; only the
//! cross-language carrier set remains Medium.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context as _, Result};

use crate::diagnostic::{Finding, GovernanceCheck, finding};
use crate::workspace_root;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Rule {
    MissingCarrier,
    MissingSemanticAnchor,
}

pub(crate) struct OutboxSameIdGuard;

impl GovernanceCheck for OutboxSameIdGuard {
    type Rule = Rule;

    fn name(&self) -> &'static str {
        "outbox-same-id-guard"
    }

    fn check(&self) -> Result<(String, Vec<Finding<Self::Rule>>)> {
        let findings = scan_workspace(&workspace_root()?)?;
        Ok((
            "0060/0061 + typed policy + preflight + resolution + sweep + alert funnel complete"
                .to_owned(),
            findings,
        ))
    }
}

#[derive(Clone, Copy)]
struct Carrier {
    path: &'static str,
    purpose: &'static str,
    anchors: &'static [&'static str],
}

const CARRIERS: &[Carrier] = &[
    Carrier {
        path: "adapters/postgres/migrations/0060_bound_same_id_delivery_window.sql",
        purpose: "DB policy, deadlines, preflight, redrive, resolution and ACL",
        anchors: &[
            "CREATE TABLE event_delivery_policy",
            "singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton)",
            "event_delivery_policy_retention_covers_delivery",
            "event_delivery_policy_intervals_bounded",
            "REVOKE ALL ON event_delivery_policy FROM rss_app",
            "GRANT INSERT (",
            "CONSTRAINT outbox_same_id_state_valid",
            "automatic_retry_deadline = COALESCE(",
            "blocker.status NOT IN ('published', 'abandoned')",
            "CREATE FUNCTION rss_outbox_publish_preflight(",
            "RETURN 2;",
            "RETURN 3;",
            "CREATE OR REPLACE FUNCTION rss_outbox_redrive(",
            "IF v_redrive_deadline <= checked_at THEN",
            "RETURN -1;",
            "UPDATE outbox AS o\n    SET status = 'pending'",
            "CREATE TABLE outbox_expired_resolutions",
            "resolution_kind IN ('accepted_gap', 'compensated')",
            "ALTER TABLE outbox_expired_resolutions FORCE ROW LEVEL SECURITY",
            "GRANT SELECT, INSERT ON outbox_expired_resolutions TO rss_outbox_maintenance",
            "CREATE FUNCTION rss_outbox_resolve_expired(",
            "SET status = 'abandoned'",
            "REVOKE ALL ON FUNCTION rss_outbox_resolve_expired(text, uuid, text, text, text, text) FROM rss_app",
            "DROP FUNCTION rss_sweep_inbox_receipts(bigint)",
            "CREATE FUNCTION rss_sweep_inbox_receipts()",
        ],
    },
    Carrier {
        path: "adapters/postgres/migrations/0061_validate_same_id_delivery_constraints.sql",
        purpose: "forward-only validation of the composite same-ID state invariant",
        anchors: &["VALIDATE CONSTRAINT outbox_same_id_state_valid"],
    },
    Carrier {
        path: "adapters/postgres/src/delivery_policy.rs",
        purpose: "private exact typed policy and unknown/multi-row fail-closed hydration",
        anchors: &[
            "pub(crate) struct EventDeliveryPolicy",
            "automatic_retry_window_seconds: u64",
            "same_id_redrive_horizon_seconds: u64",
            "safety_margin_seconds: u64",
            "inbox_receipt_retention_seconds: u64",
            "row.policy_revision != POLICY_REVISION",
            "candidate.automatic_retry_window_seconds != AUTOMATIC_RETRY_WINDOW_SECONDS",
            "candidate.same_id_redrive_horizon_seconds != SAME_ID_REDRIVE_HORIZON_SECONDS",
            "candidate.safety_margin_seconds != SAFETY_MARGIN_SECONDS",
            "candidate.inbox_receipt_retention_seconds != INBOX_RECEIPT_RETENTION_SECONDS",
            ".try_into()",
            "EventDeliveryPolicyMismatch",
        ],
    },
    Carrier {
        path: "adapters/postgres/src/bundle.rs",
        purpose: "serving startup loads DB policy only after verified-writer ledger validation and carries it privately",
        anchors: &[
            "delivery_policy: EventDeliveryPolicy",
            "let mut serving_transaction = PgSetupTransaction::new();",
            "let writer = PgStore::connect_verified_writer(serving_config).await?;",
            "serving_transaction.register(PgStoreGuard::new_named(",
            "let writer_store = writer.store_arc();",
            "let delivery_policy = match preloaded_delivery_policy",
            "serving_transaction.commit();",
        ],
    },
    Carrier {
        path: "adapters/postgres/src/pool.rs",
        purpose: "verified serving writer fails closed on an inexact embedded migration ledger",
        anchors: &[
            "pub(crate) async fn connect_verified_writer(",
            "let store = Arc::new(Self::connect_for(config, \"writer\", WRITER_APPLICATION_NAME).await?);",
            "if let Err(error) = store.verify_migration_ledger().await",
            "return Err(error);",
        ],
    },
    Carrier {
        path: "adapters/postgres/src/outbox.rs",
        purpose: "closed preflight and no-broker expiry settlement",
        anchors: &[
            "enum PublishPreflight",
            "impl TryFrom<i16> for PublishPreflight",
            "_ => Err(PublishPreflightDiscriminantError)",
            "outbox: unknown publish preflight discriminant",
            "match publish_preflight(&self.pool, &claimed, self.relay_budget, preflight_deadline).await?",
            "PublishPreflight::AutomaticExpired",
            "PublishPreflight::RedriveExpired",
            "record_same_id_window_expired",
            "outbox_same_id_window_expired_total",
            "settle_delivery_window_expired",
            ".publish_claimed_before(&claimed, publish_deadline)",
        ],
    },
    Carrier {
        path: "adapters/postgres/src/inbox.rs",
        purpose: "caller retention must equal the startup-verified policy before DB access",
        anchors: &[
            "expected_retain_seconds",
            "if retain_seconds != self.expected_retain_seconds",
            "SELECT rss_sweep_inbox_receipts()",
        ],
    },
    Carrier {
        path: "adapters/postgres/src/dlq.rs",
        purpose: "DLQ operation routes expired resolution through both exact tenant lanes",
        anchors: &[
            "async fn resolve_expired_outbox(",
            "dlq_tenant_scope(tenant)",
            "conn.dlq_resolve_expired_outbox(DlqExpiredResolution {",
            "OutboxExpiredResolutionOutcome::Resolved",
            "OutboxExpiredResolutionOutcome::EvidenceRejected",
        ],
    },
    Carrier {
        path: "adapters/postgres/src/cotx/eventing.rs",
        purpose: "closed DLQ façade owns the canonical expired-resolution SQL and tenant bind",
        anchors: &[
            "pub(crate) struct DlqExpiredResolution<'a>",
            "pub(crate) async fn dlq_resolve_expired_outbox(",
            "input: DlqExpiredResolution<'_>",
            "SELECT rss_outbox_resolve_expired($1, $2::uuid, $3, $4, $5, $6)",
            ".bind(self.tenant.to_string())",
            "impl_dlq_write!(ServingWriteLane);",
            "impl_dlq_write!(MaintenanceWriteLane);",
        ],
    },
    Carrier {
        path: "crates/eventexec/src/dlq.rs",
        purpose: "typed resolution request, closed resolution kind/outcome, and authorized operator receipt",
        anchors: &[
            "pub struct AuthorizedDlqOperatorReceipt",
            "pub const fn from_authenticated_and_authorized(",
            "pub struct VerifiedOperatorSubject(vocab::ServiceCallerDomain)",
            "pub const fn from_authorized_receipt(receipt: AuthorizedDlqOperatorReceipt)",
            "pub struct OutboxExpiredResolutionRequest",
            "pub enum OutboxExpiredResolutionKind",
            "Self::AcceptedGap => \"accepted_gap\"",
            "Self::Compensated => \"compensated\"",
            "pub enum OutboxExpiredResolutionOutcome",
            "EvidenceRejected",
        ],
    },
    Carrier {
        path: "assemblies/runtime/src/operator/dlq.rs",
        purpose: "operator CLI exposes terminal resolution only after authentication and exact grant mint a typed receipt",
        anchors: &[
            "\"resolve-expired-outbox\" =>",
            "async fn dlq_operator_receipt(",
            "AuthorizedDlqOperatorReceipt::from_authenticated_and_authorized(caller)",
            "dlq_operator_receipt(session, parsed, resource_id, principal, self.operator).await?",
            "VerifiedOperatorSubject::from_authorized_receipt(receipt)",
        ],
    },
    Carrier {
        path: "adapters/postgres/src/integration_tests.rs",
        purpose: "real-Postgres acceptance locks both deadlines, resolution, retention and composite state",
        anchors: &[
            "same_id_automatic_deadline_is_frozen_and_expiry_never_calls_broker",
            "same_id_redrive_preflight_expiry_never_calls_broker",
            "same_id_first_dlx_deadline_uses_both_exact_least_branches",
            "expired_outbox_accepted_gap_resolution_is_terminal_audited_and_unblocks_successor",
            "expired_outbox_compensation_requires_published_causation_and_resolution_is_single_winner",
            "once the frozen receipt retention window is swept, the same key is Fresh again",
            "outbox_same_id_checks_reject_each_invalid_state_without_mutation",
        ],
    },
    Carrier {
        path: "lints/rss_dlq_operator_callsite/src/lib.rs",
        purpose: "authorized operator receipt construction remains at the auth/PDP boundary",
        anchors: &[
            "\"operator::dlq::dlq_operator_receipt\"",
            "impl_self_type_named(cx, did, \"AuthorizedDlqOperatorReceipt\")",
            "Funnel::AuthorizedReceipt",
            "is_exact_runtime_path(&def_path, ALLOWED_RUNTIME_RECEIPT_FUNCTION.1)",
        ],
    },
    Carrier {
        path: "lints/rss_dlq_operator_callsite/ui/runtime.rs",
        purpose: "UI red/green locks the exact runtime wrapper and rejects direct or nested forgery",
        anchors: &[
            "fn dlq_operator_receipt(",
            "let _receipt = eventexec::AuthorizedDlqOperatorReceipt::from_authenticated_and_authorized(",
            "vocab::ServiceCallerDomain::MaintenanceOperator",
            "mod nested_runtime_module",
        ],
    },
    Carrier {
        path: "lints/rss_dlq_operator_callsite/ui/runtime.stderr",
        purpose: "UI golden proves both direct and same-named nested runtime calls are rejected",
        anchors: &[
            "authorized DLQ operator receipt 仅认证/PDP 边界可构造",
            "runtime.rs:35:20",
            "runtime.rs:51:9",
            "warning: 4 warnings emitted",
        ],
    },
    Carrier {
        path: "docs/ops/outbox-relay-alerts.rules.yaml",
        purpose: "same-ID expiry alert consumes the bounded label set",
        anchors: &[
            "alert: OutboxSameIdWindowExpired",
            "outbox_same_id_window_expired_total",
            "sum by (domain, phase)",
        ],
    },
    Carrier {
        path: "docs/ops/outbox-relay-alerts.test.yaml",
        purpose: "promtool consumer exercises automatic and redrive expiry",
        anchors: &[
            "- outbox-relay-alerts.rules.yaml",
            "alert_rule_test:",
            "alertname: OutboxSameIdWindowExpired",
            "phase=\"automatic\"",
            "phase=\"redrive\"",
        ],
    },
];

const ORDERED_SEQUENCES: &[(&str, &[&str])] = &[
    (
        "adapters/postgres/migrations/0060_bound_same_id_delivery_window.sql",
        &[
            "CREATE OR REPLACE FUNCTION rss_outbox_redrive(",
            "IF v_redrive_deadline <= checked_at THEN",
            "RETURN -1;",
            "UPDATE outbox AS o\n    SET status = 'pending'",
        ],
    ),
    (
        "adapters/postgres/src/bundle.rs",
        &[
            "let mut serving_transaction = PgSetupTransaction::new();",
            "let writer = PgStore::connect_verified_writer(serving_config).await?;",
            "serving_transaction.register(PgStoreGuard::new_named(",
            "let writer_store = writer.store_arc();",
            "let delivery_policy = match preloaded_delivery_policy",
            "serving_transaction.commit();",
        ],
    ),
    (
        "adapters/postgres/src/outbox.rs",
        &[
            "match publish_preflight(&self.pool, &claimed, self.relay_budget, preflight_deadline).await?",
            "PublishPreflight::AutomaticExpired",
            "settle_delivery_window_expired",
            ".publish_claimed_before(&claimed, publish_deadline)",
        ],
    ),
    (
        "adapters/postgres/src/inbox.rs",
        &[
            "if retain_seconds != self.expected_retain_seconds",
            "SELECT rss_sweep_inbox_receipts()",
        ],
    ),
];

fn scan_workspace(root: &Path) -> Result<Vec<Finding<Rule>>> {
    let mut sources = BTreeMap::new();
    for carrier in CARRIERS {
        let path = root.join(carrier.path);
        if !path.is_file() {
            continue;
        }
        let content = std::fs::read_to_string(&path)
            .with_context(|| format!("outbox-same-id-guard: read {}", path.display()))?;
        sources.insert(carrier.path, content);
    }
    Ok(scan_sources(&sources))
}

fn scan_sources(sources: &BTreeMap<&str, String>) -> Vec<Finding<Rule>> {
    let mut findings = Vec::new();
    for carrier in CARRIERS {
        let Some(content) = sources.get(carrier.path) else {
            findings.push(finding(
                Rule::MissingCarrier,
                carrier.path,
                format!("缺少 same-ID funnel carrier：{}", carrier.purpose),
            ));
            continue;
        };
        for anchor in carrier.anchors {
            if !content.contains(anchor) {
                findings.push(finding(
                    Rule::MissingSemanticAnchor,
                    carrier.path,
                    format!("{} 缺语义锚点 `{anchor}`", carrier.purpose),
                ));
            }
        }
    }
    for (path, sequence) in ORDERED_SEQUENCES {
        let Some(content) = sources.get(path) else {
            continue;
        };
        let mut cursor = 0;
        let ordered = sequence.iter().all(|anchor| {
            let Some(offset) = content[cursor..].find(anchor) else {
                return false;
            };
            cursor += offset + anchor.len();
            true
        });
        if !ordered {
            findings.push(finding(
                Rule::MissingSemanticAnchor,
                *path,
                format!("same-ID fail-closed execution order drifted: {sequence:?}"),
            ));
        }
    }
    scan_expired_resolution_topology(sources, &mut findings);
    findings
}

const DLQ_PATH: &str = "adapters/postgres/src/dlq.rs";
const EVENTING_FACADE_PATH: &str = "adapters/postgres/src/cotx/eventing.rs";
const RESOLUTION_SQL: &str = "SELECT rss_outbox_resolve_expired($1, $2::uuid, $3, $4, $5, $6)";

fn scan_expired_resolution_topology(
    sources: &BTreeMap<&str, String>,
    findings: &mut Vec<Finding<Rule>>,
) {
    if let Some(source) = sources.get(EVENTING_FACADE_PATH) {
        let signature = "pub(crate) async fn dlq_resolve_expired_outbox(";
        let body = rust_item_body(source, signature);
        let owner = rust_item_body(source, "macro_rules! impl_dlq_write");
        let scoped = body.is_some_and(|body| {
            [
                "input: DlqExpiredResolution<'_>",
                RESOLUTION_SQL,
                ".bind(input.event_id)",
                ".bind(self.tenant.to_string())",
                ".bind(input.kind)",
                ".bind(input.change_ticket)",
                ".bind(input.operator_subject)",
                ".bind(input.evidence_event_id)",
                ".fetch_one(&mut *self.conn)",
            ]
            .iter()
            .all(|anchor| body.contains(anchor))
        });
        if !scoped
            || !owner
                .is_some_and(|owner| owner.contains(signature) && owner.contains(RESOLUTION_SQL))
            || source.matches(signature).count() != 1
            || source.matches(RESOLUTION_SQL).count() != 1
        {
            findings.push(finding(
                Rule::MissingSemanticAnchor,
                EVENTING_FACADE_PATH,
                "expired-resolution canonical SQL/binds必须由唯一 closed façade方法拥有",
            ));
        }
    }

    if let Some(source) = sources.get(DLQ_PATH) {
        let signature = "async fn resolve_expired_outbox(";
        let body = rust_item_body(source, signature);
        let call = "conn.dlq_resolve_expired_outbox(DlqExpiredResolution {";
        let sequence = [
            "DlqLane::Serving { write, .. }",
            call,
            "DlqLane::Maintenance { write, .. }",
            call,
            "Ok(1) => Ok(OutboxExpiredResolutionOutcome::Resolved)",
            "Ok(-2) => Ok(OutboxExpiredResolutionOutcome::EvidenceRejected)",
        ];
        let scoped = body.is_some_and(|body| {
            body.matches(call).count() == 2
                && body.matches("dlq_tenant_scope(tenant)").count() == 2
                && body.matches("DlqExpiredResolution {").count() == 2
                && contains_in_order(body, &sequence)
        });
        if source.contains("rss_outbox_resolve_expired(")
            || source.matches(signature).count() != 1
            || source.matches(call).count() != 2
            || !scoped
        {
            findings.push(finding(
                Rule::MissingSemanticAnchor,
                DLQ_PATH,
                "expired-resolution必须由 DLQ operation 经 serving/maintenance tenant lane 调用 closed façade，repo不得拥有 SQL",
            ));
        }
    }
}

fn rust_item_body<'a>(source: &'a str, signature: &str) -> Option<&'a str> {
    let signature_start = source.find(signature)?;
    let open_offset = source[signature_start..].find('{')?;
    let open = signature_start + open_offset;
    let mut depth = 0_u32;
    for (offset, byte) in source.as_bytes()[open..].iter().enumerate() {
        match byte {
            b'{' => depth += 1,
            b'}' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return source.get(signature_start..=open + offset);
                }
            }
            _ => {}
        }
    }
    None
}

fn contains_in_order(content: &str, sequence: &[&str]) -> bool {
    let mut cursor = 0;
    sequence.iter().all(|anchor| {
        let Some(offset) = content[cursor..].find(anchor) else {
            return false;
        };
        cursor += offset + anchor.len();
        true
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    fn complete_sources() -> BTreeMap<&'static str, String> {
        let mut sources: BTreeMap<_, _> = CARRIERS
            .iter()
            .map(|carrier| (carrier.path, carrier.anchors.join("\n")))
            .collect();
        sources.insert(
            EVENTING_FACADE_PATH,
            r#"
pub(crate) struct DlqExpiredResolution<'a> { event_id: &'a str }
macro_rules! impl_dlq_write {
    ($lane:ty) => {
        impl TenantTx<'_, $lane> {
            pub(crate) async fn dlq_resolve_expired_outbox(
                &mut self,
                input: DlqExpiredResolution<'_>,
            ) -> Result<i64, sqlx::Error> {
                sqlx::query_scalar(
                    "SELECT rss_outbox_resolve_expired($1, $2::uuid, $3, $4, $5, $6)"
                )
                .bind(input.event_id)
                .bind(self.tenant.to_string())
                .bind(input.kind)
                .bind(input.change_ticket)
                .bind(input.operator_subject)
                .bind(input.evidence_event_id)
                .fetch_one(&mut *self.conn)
                .await
            }
        }
    };
}
impl_dlq_write!(ServingWriteLane);
impl_dlq_write!(MaintenanceWriteLane);
"#
            .to_owned(),
        );
        sources.insert(
            DLQ_PATH,
            r#"
async fn resolve_expired_outbox(
    &self,
    request: OutboxExpiredResolutionRequest,
) -> Result<OutboxExpiredResolutionOutcome, DlqError> {
    let tenant = request.tenant();
    let result = match &self.lane {
        DlqLane::Serving { write, .. } => write.write(
            dlq_tenant_scope(tenant),
            move |conn| Box::pin(async move {
                conn.dlq_resolve_expired_outbox(DlqExpiredResolution {
                    event_id: &event_id,
                }).await
            }),
        ).await,
        DlqLane::Maintenance { write, .. } => write.write(
            dlq_tenant_scope(tenant),
            move |conn| Box::pin(async move {
                conn.dlq_resolve_expired_outbox(DlqExpiredResolution {
                    event_id: &event_id,
                }).await
            }),
        ).await,
    };
    match result {
        Ok(1) => Ok(OutboxExpiredResolutionOutcome::Resolved),
        Ok(-2) => Ok(OutboxExpiredResolutionOutcome::EvidenceRejected),
        _ => Ok(OutboxExpiredResolutionOutcome::NotFound),
    }
}
"#
            .to_owned(),
        );
        sources
    }

    #[test]
    fn scan_content_rejects_same_id_funnel_bypasses() -> Result<()> {
        for carrier in CARRIERS {
            for anchor in carrier.anchors {
                let mut sources = complete_sources();
                let content = sources
                    .get_mut(carrier.path)
                    .ok_or_else(|| anyhow::anyhow!("fixture carrier missing: {}", carrier.path))?;
                *content = content.replace(anchor, "removed-semantic-anchor");
                let findings = scan_sources(&sources);
                assert!(
                    findings.iter().any(|finding| {
                        finding.rule == Rule::MissingSemanticAnchor
                            && finding.subject == carrier.path
                    }),
                    "removing `{anchor}` from {} must be red",
                    carrier.path
                );
            }
        }
        let mut missing = complete_sources();
        missing.remove(CARRIERS[0].path);
        assert!(
            scan_sources(&missing)
                .iter()
                .any(|finding| finding.rule == Rule::MissingCarrier)
        );
        Ok(())
    }

    #[test]
    fn scan_content_accepts_complete_same_id_funnel() {
        let findings = scan_sources(&complete_sources());
        assert!(findings.is_empty(), "{findings:#?}");
    }

    #[test]
    #[allow(clippy::expect_used)] // reason: complete_sources must carry the eventing façade fixture.
    fn scan_rejects_expired_resolution_sql_moved_outside_closed_facade() {
        let mut sources = complete_sources();
        let content = sources
            .get_mut(EVENTING_FACADE_PATH)
            .expect("eventing façade fixture carrier");
        *content = content.replace(RESOLUTION_SQL, "moved-resolution-sql");
        content.push_str(&format!(
            "\nfn unrelated_sql_owner() {{ /* {RESOLUTION_SQL} */ }}"
        ));

        let findings = scan_sources(&sources);
        assert!(
            findings
                .iter()
                .any(|finding| { finding.subject == EVENTING_FACADE_PATH }),
            "moving resolution SQL outside the closed façade must be red"
        );
    }

    #[test]
    #[allow(clippy::expect_used)] // reason: complete_sources must carry the DLQ fixture.
    fn scan_rejects_expired_resolution_call_moved_outside_dlq_operation() {
        const CALL: &str = "conn.dlq_resolve_expired_outbox(DlqExpiredResolution {";
        let mut sources = complete_sources();
        let content = sources
            .get_mut("adapters/postgres/src/dlq.rs")
            .expect("DLQ fixture carrier");
        *content = content.replace(CALL, "conn.unrelated_operation(DlqExpiredResolution {");
        content.push_str(&format!("\nfn unrelated_call_owner() {{ /* {CALL} */ }}"));

        let findings = scan_sources(&sources);
        assert!(
            findings
                .iter()
                .any(|finding| finding.subject == "adapters/postgres/src/dlq.rs"),
            "moving the façade call outside the DLQ operation must be red"
        );
    }

    #[test]
    #[allow(clippy::expect_used)] // reason: complete_sources must carry the DLQ fixture.
    fn scan_rejects_expired_resolution_sql_restored_to_dlq_repo() {
        let mut sources = complete_sources();
        sources
            .get_mut(DLQ_PATH)
            .expect("DLQ fixture carrier")
            .push_str(&format!("\nfn raw_repo_sql() {{ /* {RESOLUTION_SQL} */ }}"));

        let findings = scan_sources(&sources);
        assert!(
            findings.iter().any(|finding| finding.subject == DLQ_PATH),
            "restoring expired-resolution SQL to the repository must be red"
        );
    }

    #[test]
    fn committed_workspace_has_complete_same_id_funnel() -> Result<()> {
        let findings = scan_workspace(&workspace_root()?)?;
        assert!(findings.is_empty(), "{findings:#?}");
        Ok(())
    }
}
