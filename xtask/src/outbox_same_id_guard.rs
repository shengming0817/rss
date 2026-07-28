//! Cross-SQL/Rust/ops guard for the bounded same-ID outbox delivery funnel.
//!
//! INVARIANT: OUTBOX-SAME-ID-WINDOW-01 { level = "Medium", exec = "verify", source = "code", synthetic_red = "tests::scan_content_rejects_same_id_funnel_bypasses", anti_vacuity = "tests::scan_content_accepts_complete_same_id_funnel" }——
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
        purpose: "typed expired resolution executes only through tenant transaction",
        anchors: &[
            "resolve_expired_outbox",
            "SELECT rss_outbox_resolve_expired(",
            "OutboxExpiredResolutionOutcome::Resolved",
            "OutboxExpiredResolutionOutcome::EvidenceRejected",
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
    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    fn complete_sources() -> BTreeMap<&'static str, String> {
        CARRIERS
            .iter()
            .map(|carrier| (carrier.path, carrier.anchors.join("\n")))
            .collect()
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
    fn committed_workspace_has_complete_same_id_funnel() -> Result<()> {
        let findings = scan_workspace(&workspace_root()?)?;
        assert!(findings.is_empty(), "{findings:#?}");
        Ok(())
    }
}
