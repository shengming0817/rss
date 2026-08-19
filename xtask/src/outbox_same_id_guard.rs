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
use quote::ToTokens;
use syn::spanned::Spanned as _;
use syn::visit::Visit as _;

use crate::diagnostic::{Finding, GovernanceCheck, finding};
use crate::event_transport_guard::parse_outbox_callable_catalog;
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
        purpose: "DLQ repository must not regain provider-owned expired-resolution SQL",
        anchors: &[],
    },
    Carrier {
        path: "adapters/postgres/src/outbox_routine.rs",
        purpose: "provider-owned typed catalog owns expired-resolution SQL identity",
        anchors: &[
            "ResolveExpired => {",
            "function: rss_outbox_resolve_expired",
            "arguments: \"(text,uuid,text,text,text,text)\"",
            "sql: [\"SELECT \", \"($1, $2::uuid, $3, $4, $5, $6)\"]",
        ],
    },
    Carrier {
        path: "adapters/postgres/src/cotx/eventing.rs",
        purpose: "closed DLQ façade is verified structurally against its exact maintenance receiver",
        anchors: &[],
    },
    Carrier {
        path: "adapters/postgres/src/integration_tests/outbox_tests.rs",
        purpose: "real-Postgres acceptance locks both deadlines, resolution, retention and composite state",
        anchors: &[
            "same_id_automatic_deadline_is_frozen_and_expiry_never_calls_broker",
            "same_id_redrive_preflight_expiry_never_calls_broker",
            "same_id_first_dlx_deadline_uses_both_exact_least_branches",
            "expired_outbox_accepted_gap_resolution_is_terminal_audited_and_unblocks_successor",
            "expired_outbox_compensation_requires_published_causation_and_resolution_is_single_winner",
            "outbox_same_id_checks_reject_each_invalid_state_without_mutation",
        ],
    },
    Carrier {
        path: "adapters/postgres/src/integration_tests/inbox_consumer_tests.rs",
        purpose: "real-Postgres inbox retention acceptance proves the frozen same-ID window reopens only after sweep",
        anchors: &[
            "once the frozen receipt retention window is swept, the same key is Fresh again",
        ],
    },
    Carrier {
        path: "lints/rss_operator_authorization_callsite/src/lib.rs",
        purpose: "action authorization issuance remains at the exact runtime mint funnel",
        anchors: &[
            "source_crate: \"diport\"",
            "self_type: \"DlqOperatorAuthorization\"",
            "method: \"issue\"",
            "item_name: \"issue_dlq_authorization\"",
            "caller_module_path(cx, parent)",
        ],
    },
    Carrier {
        path: "lints/rss_operator_authorization_callsite/ui/runtime.rs",
        purpose: "UI red/green locks the exact runtime wrapper and rejects direct or nested forgery",
        anchors: &[
            "fn issue_dlq_authorization<A: diport::DlqOperatorAction>()",
            "diport::DlqOperatorAuthorization::issue(",
            "dlqauthmint::DlqOperatorMint::capability()",
            "mod nested_runtime_module",
        ],
    },
    Carrier {
        path: "lints/rss_operator_authorization_callsite/ui/runtime.stderr",
        purpose: "UI golden proves both direct and same-named nested runtime calls are rejected",
        anchors: &[
            "operator capability `DlqOperatorAuthorization::issue`",
            "不要直接调用或保存 constructor 函数项",
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
    let mut sources = BTreeMap::<String, String>::new();
    for carrier in CARRIERS {
        let path = root.join(carrier.path);
        if !path.is_file() {
            continue;
        }
        let content = std::fs::read_to_string(&path)
            .with_context(|| format!("outbox-same-id-guard: read {}", path.display()))?;
        sources.insert(carrier.path.to_owned(), content);
    }
    for relative in [RESOLUTION_REQUEST_PATH, RESOLUTION_OPERATOR_PATH] {
        let path = root.join(relative);
        sources.insert(
            relative.to_owned(),
            std::fs::read_to_string(&path)
                .with_context(|| format!("outbox-same-id-guard: read {}", path.display()))?,
        );
    }
    collect_postgres_production_sources(root, &root.join("adapters/postgres/src"), &mut sources)?;
    Ok(scan_sources(&sources))
}

fn collect_postgres_production_sources(
    root: &Path,
    directory: &Path,
    sources: &mut BTreeMap<String, String>,
) -> Result<()> {
    for entry in std::fs::read_dir(directory)
        .with_context(|| format!("outbox-same-id-guard: read dir {}", directory.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        let file_type = entry.file_type()?;
        if file_type.is_symlink() {
            anyhow::bail!(
                "outbox-same-id-guard: symlink source is forbidden: {}",
                path.display()
            );
        }
        if file_type.is_dir() {
            if entry.file_name() != "integration_tests" {
                collect_postgres_production_sources(root, &path, sources)?;
            }
            continue;
        }
        if path.extension().is_some_and(|extension| extension == "rs") {
            let relative = path
                .strip_prefix(root)
                .with_context(|| format!("postgres source escaped workspace: {}", path.display()))?
                .to_string_lossy()
                .replace('\\', "/");
            sources.insert(relative, std::fs::read_to_string(&path)?);
        }
    }
    Ok(())
}

fn scan_sources(sources: &BTreeMap<String, String>) -> Vec<Finding<Rule>> {
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
    let catalog_function = sources
        .get("adapters/postgres/src/outbox_routine.rs")
        .and_then(|source| {
            parse_outbox_callable_catalog(source)
                .get("ResolveExpired")
                .cloned()
        });
    if catalog_function.as_deref() != Some("rss_outbox_resolve_expired") {
        findings.push(finding(
            Rule::MissingSemanticAnchor,
            "adapters/postgres/src/outbox_routine.rs",
            "ResolveExpired must structurally bind the canonical rss_outbox_resolve_expired identity",
        ));
    }
    for (path, sequence) in ORDERED_SEQUENCES {
        let Some(content) = sources.get(*path) else {
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
    scan_operator_resolution_chain(sources, &mut findings);
    findings
}

const EVENTING_FACADE_PATH: &str = "adapters/postgres/src/cotx/eventing.rs";
const RESOLUTION_REQUEST_PATH: &str = "crates/eventexec/src/dlq.rs";
const RESOLUTION_OPERATOR_PATH: &str = "assemblies/runtime/src/operator/dlq.rs";
#[cfg(test)]
const RESOLUTION_SQL: &str = "SELECT rss_outbox_resolve_expired($1, $2::uuid, $3, $4, $5, $6)";

fn scan_expired_resolution_topology(
    sources: &BTreeMap<String, String>,
    findings: &mut Vec<Finding<Rule>>,
) {
    let expected_binds = [
        "input.event_id",
        "self.tenant.to_string()",
        "input.kind",
        "input.change_ticket",
        "input.operator_subject",
        "input.evidence_event_id",
    ];
    let mut canonical_methods = 0_usize;
    let mut authority_references = 0_usize;
    for (path, source) in sources {
        if !path.starts_with("adapters/postgres/src/")
            || path.contains("/integration_tests/")
            || (!source.contains("ResolveExpired")
                && !source.contains("SELECT rss_outbox_resolve_expired"))
        {
            continue;
        }
        let file = match syn::parse_file(source) {
            Ok(file) => file,
            Err(error) => {
                findings.push(finding(
                    Rule::MissingSemanticAnchor,
                    path,
                    format!("expired-resolution Rust carrier does not parse: {error}"),
                ));
                continue;
            }
        };
        let mut file_visitor = ResolutionRustVisitor::default();
        file_visitor.visit_file(&file);
        authority_references += file_visitor.authority_references;
        let canonical_sql_owner = path == EVENTING_FACADE_PATH
            && file_visitor.raw_sql_literals == 1
            && file_visitor.opaque_bypasses == 0;
        if file_visitor.raw_sql_literals > 0 && !canonical_sql_owner {
            findings.push(finding(
                Rule::MissingSemanticAnchor,
                path,
                "raw rss_outbox_resolve_expired SQL is forbidden in postgres Rust sources",
            ));
        }

        for item in &file.items {
            let syn::Item::Impl(implementation) = item else {
                continue;
            };
            for item in &implementation.items {
                let syn::ImplItem::Fn(method) = item else {
                    continue;
                };
                let mut visitor = ResolutionRustVisitor::default();
                visitor.visit_block(&method.block);
                if visitor.authority_references == 0 {
                    continue;
                }
                let canonical_owner = path == EVENTING_FACADE_PATH
                    && maintenance_dlq_impl(implementation)
                    && method.sig.ident == "dlq_resolve_expired_outbox";
                let canonical_chain = visitor.resolution_bind_chains.len() == 1
                    && visitor.resolution_bind_chains[0]
                        .iter()
                        .map(String::as_str)
                        .eq(expected_binds);
                if canonical_owner
                    && visitor.authority_references == 1
                    && canonical_chain
                    && visitor.opaque_bypasses == 0
                {
                    canonical_methods += 1;
                } else {
                    findings.push(finding(
                        Rule::MissingSemanticAnchor,
                        format!("{path}:{}", method.span().start().line),
                        "ResolveExpired authority must appear once in the exact MaintenanceWriteLane/DlqConcern façade with canonical binds",
                    ));
                }
            }
        }
        if file_visitor.authority_references > 0
            && path != EVENTING_FACADE_PATH
            && path != "adapters/postgres/src/outbox_routine.rs"
        {
            findings.push(finding(
                Rule::MissingSemanticAnchor,
                path,
                "ResolveExpired authority reference is outside the canonical maintenance façade",
            ));
        }
    }
    if canonical_methods != 1 || authority_references != 1 {
        findings.push(finding(
            Rule::MissingSemanticAnchor,
            EVENTING_FACADE_PATH,
            format!(
                "expired-resolution façade exact-set drift: canonicalMethods={canonical_methods} authorityReferences={authority_references}"
            ),
        ));
    }
}

fn maintenance_dlq_impl(implementation: &syn::ItemImpl) -> bool {
    let syn::Type::Path(owner) = implementation.self_ty.as_ref() else {
        return false;
    };
    let Some(segment) = owner.path.segments.last() else {
        return false;
    };
    if segment.ident != "EventingTx" {
        return false;
    }
    let syn::PathArguments::AngleBracketed(arguments) = &segment.arguments else {
        return false;
    };
    let types = arguments
        .args
        .iter()
        .filter_map(|argument| match argument {
            syn::GenericArgument::Type(syn::Type::Path(path)) => path
                .path
                .segments
                .last()
                .map(|segment| segment.ident.to_string()),
            _ => None,
        })
        .collect::<Vec<_>>();
    types == ["MaintenanceWriteLane", "DlqConcern"]
}

#[derive(Default)]
struct ResolutionRustVisitor {
    authority_references: usize,
    raw_sql_literals: usize,
    opaque_bypasses: usize,
    resolution_bind_chains: Vec<Vec<String>>,
}

impl<'ast> syn::visit::Visit<'ast> for ResolutionRustVisitor {
    fn visit_path(&mut self, path: &'ast syn::Path) {
        let segments = path
            .segments
            .iter()
            .map(|segment| segment.ident.to_string())
            .collect::<Vec<_>>();
        if segments == ["DlqCallableRoutine", "ResolveExpired"] {
            self.authority_references += 1;
        }
        syn::visit::visit_path(self, path);
    }

    fn visit_lit_str(&mut self, literal: &'ast syn::LitStr) {
        if literal
            .value()
            .trim_start()
            .starts_with("SELECT rss_outbox_resolve_expired(")
        {
            self.raw_sql_literals += 1;
        }
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        if call.method == "fetch_one"
            && let Some(binds) = resolution_query_binds(call.receiver.as_ref())
        {
            self.resolution_bind_chains.push(binds);
        }
        syn::visit::visit_expr_method_call(self, call);
    }

    fn visit_macro(&mut self, item: &'ast syn::Macro) {
        let tokens = item.tokens.to_string();
        if tokens.contains("ResolveExpired") || tokens.contains("rss_outbox_resolve_expired") {
            self.opaque_bypasses += 1;
        }
        syn::visit::visit_macro(self, item);
    }

    fn visit_item_use(&mut self, item: &'ast syn::ItemUse) {
        if item
            .to_token_stream()
            .to_string()
            .contains("DlqCallableRoutine")
        {
            self.opaque_bypasses += 1;
        }
        syn::visit::visit_item_use(self, item);
    }

    fn visit_item_type(&mut self, item: &'ast syn::ItemType) {
        if item
            .to_token_stream()
            .to_string()
            .contains("DlqCallableRoutine")
        {
            self.opaque_bypasses += 1;
        }
        syn::visit::visit_item_type(self, item);
    }
}

fn resolution_query_binds(expression: &syn::Expr) -> Option<Vec<String>> {
    let mut expression = expression;
    let mut binds = Vec::new();
    loop {
        match expression {
            syn::Expr::MethodCall(call) => {
                if call.method == "bind" && call.args.len() == 1 {
                    binds.push(
                        call.args[0]
                            .to_token_stream()
                            .to_string()
                            .chars()
                            .filter(|character| !character.is_whitespace())
                            .collect(),
                    );
                }
                expression = call.receiver.as_ref();
            }
            syn::Expr::Call(call) if call.args.len() == 1 => {
                let syn::Expr::Path(function) = call.func.as_ref() else {
                    return None;
                };
                if function.path.segments.last()?.ident != "query_scalar" {
                    return None;
                }
                let syn::Expr::MethodCall(sql) = &call.args[0] else {
                    return None;
                };
                let syn::Expr::Path(routine) = sql.receiver.as_ref() else {
                    return None;
                };
                let segments = routine
                    .path
                    .segments
                    .iter()
                    .map(|segment| segment.ident.to_string())
                    .collect::<Vec<_>>();
                if sql.method != "sql" || segments != ["DlqCallableRoutine", "ResolveExpired"] {
                    return None;
                }
                binds.reverse();
                return Some(binds);
            }
            _ => return None,
        }
    }
}

fn scan_operator_resolution_chain(
    sources: &BTreeMap<String, String>,
    findings: &mut Vec<Finding<Rule>>,
) {
    let request_ok = sources
        .get(RESOLUTION_REQUEST_PATH)
        .and_then(|source| syn::parse_file(source).ok())
        .is_some_and(|file| {
            file.items.iter().any(|item| {
                let syn::Item::Struct(item) = item else {
                    return false;
                };
                item.ident == "OutboxExpiredResolutionRequest" && item.fields.iter().any(|field| {
                    field
                        .ident
                        .as_ref()
                        .is_some_and(|ident| ident == "authorization")
                        && matches!(field.vis, syn::Visibility::Inherited)
                        && token_key(&field.ty)
                            == "DlqOperatorAuthorization<dlq_operator_action::ResolveExpiredOutbox>"
                })
            })
        });
    if !request_ok {
        findings.push(finding(
            Rule::MissingSemanticAnchor,
            RESOLUTION_REQUEST_PATH,
            "expired-resolution request must privately own the action-specific operator authorization",
        ));
    }

    let operator_ok = sources
        .get(RESOLUTION_OPERATOR_PATH)
        .and_then(|source| syn::parse_file(source).ok())
        .is_some_and(|file| {
            let mut resolve_arm = false;
            let mut mint = false;
            let mut calls = OperatorResolutionCalls::default();
            calls.visit_file(&file);
            for item in &file.items {
                let syn::Item::Fn(function) = item else {
                    continue;
                };
                let body = token_key(&function.block);
                if function.sig.ident == "issue_dlq_authorization" {
                    mint = body.contains("DlqOperatorAuthorization::issue(")
                        && token_key(&function.sig.generics)
                            .contains("A:diport::DlqOperatorAction");
                }
                for statement in &function.block.stmts {
                    let tokens = token_key(statement);
                    if tokens.contains("DlqCliCommand::ResolveExpiredOutbox{") {
                        resolve_arm |= tokens.contains(
                            "issue_dlq_authorization::<dlq_operator_action::ResolveExpiredOutbox>(",
                        ) && tokens.contains(
                            "finish_audit_context::<dlq_operator_action::ResolveExpiredOutbox>(",
                        ) && tokens
                            .contains("OutboxExpiredResolutionRequest::accepted_gap(")
                            && tokens.contains("OutboxExpiredResolutionRequest::compensated(")
                            && tokens.contains("AuthorizedDlqRequest::Resolve(request)");
                    }
                }
            }
            if !(resolve_arm && mint && calls.principal && calls.dispatch) {
                return false;
            }
            true
        });
    if !operator_ok {
        findings.push(finding(
            Rule::MissingSemanticAnchor,
            RESOLUTION_OPERATOR_PATH,
            "operator resolution must join principal authentication, action-specific mint, finish audit, typed request construction and dispatch",
        ));
    }
}

#[derive(Default)]
struct OperatorResolutionCalls {
    principal: bool,
    dispatch: bool,
}

impl<'ast> syn::visit::Visit<'ast> for OperatorResolutionCalls {
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let syn::Expr::Path(function) = call.func.as_ref()
            && let Some(name) = function.path.segments.last()
        {
            self.principal |= name.ident == "authorize_dlq_operator_principal";
            self.dispatch |= name.ident == "authorize_dlq_command";
        }
        syn::visit::visit_expr_call(self, call);
    }
}

fn token_key(tokens: &impl ToTokens) -> String {
    tokens
        .to_token_stream()
        .to_string()
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect()
}

#[cfg(test)]
mod tests {

    use super::*;

    fn complete_sources() -> BTreeMap<String, String> {
        let mut sources: BTreeMap<_, _> = CARRIERS
            .iter()
            .map(|carrier| (carrier.path.to_owned(), carrier.anchors.join("\n")))
            .collect();
        sources.insert(
            "adapters/postgres/src/outbox_routine.rs".to_owned(),
            r#"
outbox_routine_catalog! {
    helpers {}
    serving {}
    operator {
        ResolveExpired => {
            function: rss_outbox_resolve_expired,
            arguments: "(text,uuid,text,text,text,text)",
            sql: ["SELECT ", "($1, $2::uuid, $3, $4, $5, $6)"]
        }
    }
}
"#
            .to_owned(),
        );
        sources.insert(
            EVENTING_FACADE_PATH.to_owned(),
            r#"
pub(crate) struct DlqExpiredResolution<'a> { event_id: &'a str }
enum DlqCallableRoutine { ResolveExpired }
impl DlqCallableRoutine {
    const fn sql(self) -> &'static str {
        "SELECT rss_outbox_resolve_expired($1, $2::uuid, $3, $4, $5, $6)"
    }
}
impl EventingTx<'_, MaintenanceWriteLane, DlqConcern> {
    pub(crate) async fn dlq_resolve_expired_outbox(
        &mut self,
        input: DlqExpiredResolution<'_>,
    ) -> Result<i64, sqlx::Error> {
        sqlx::query_scalar(
            DlqCallableRoutine::ResolveExpired.sql()
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
"#
            .to_owned(),
        );
        sources.insert(
            RESOLUTION_REQUEST_PATH.to_owned(),
            "pub struct OutboxExpiredResolutionRequest { authorization: DlqOperatorAuthorization<dlq_operator_action::ResolveExpiredOutbox> }".to_owned(),
        );
        sources.insert(
            RESOLUTION_OPERATOR_PATH.to_owned(),
            r#"
fn issue_dlq_authorization<A: diport::DlqOperatorAction>() { DlqOperatorAuthorization::issue(); }
fn run() {
    authorize_dlq_operator_principal();
    authorize_dlq_command();
    let value = match command {
        DlqCliCommand::ResolveExpiredOutbox { event_id } => {
            issue_dlq_authorization::<dlq_operator_action::ResolveExpiredOutbox>();
            finish_audit_context::<dlq_operator_action::ResolveExpiredOutbox>();
            OutboxExpiredResolutionRequest::accepted_gap();
            OutboxExpiredResolutionRequest::compensated();
            AuthorizedDlqRequest::Resolve(request)
        }
    };
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
    fn scan_rejects_expired_resolution_authority_moved_outside_closed_facade() -> Result<()> {
        let mut sources = complete_sources();
        let content = sources
            .get_mut(EVENTING_FACADE_PATH)
            .context("eventing façade fixture carrier must exist")?;
        *content = content.replace(
            "DlqCallableRoutine::ResolveExpired.sql()",
            "moved_resolution_authority()",
        );
        content.push_str(
            "\nfn unrelated_authority_owner() { let _ = DlqCallableRoutine::ResolveExpired.sql(); }",
        );

        let findings = scan_sources(&sources);
        assert!(
            findings
                .iter()
                .any(|finding| { finding.subject == EVENTING_FACADE_PATH }),
            "moving the typed resolution authority outside the closed façade must be red"
        );
        Ok(())
    }

    #[test]
    fn scan_rejects_fake_resolution_receiver_and_comment_bait() -> Result<()> {
        let mut sources = complete_sources();
        let content = sources
            .get_mut(EVENTING_FACADE_PATH)
            .context("eventing façade fixture carrier must exist")?;
        *content = content.replace(
            "DlqCallableRoutine::ResolveExpired.sql()",
            "fake::DlqCallableRoutine::ResolveExpired.sql()",
        );
        content.push_str("\n// DlqCallableRoutine::ResolveExpired.sql()\n");
        let findings = scan_sources(&sources);
        assert!(
            findings
                .iter()
                .any(|finding| finding.subject == EVENTING_FACADE_PATH),
            "fake receiver plus comment bait must not satisfy the closed façade witness"
        );
        Ok(())
    }

    #[test]
    fn scan_rejects_catalog_identity_drift_with_comment_bait() -> Result<()> {
        let mut sources = complete_sources();
        let catalog = sources
            .get_mut("adapters/postgres/src/outbox_routine.rs")
            .context("outbox routine catalog fixture must exist")?;
        *catalog = catalog.replace(
            "function: rss_outbox_resolve_expired",
            "function: rss_outbox_resolve_expired_broken",
        );
        catalog.push_str("\n// function: rss_outbox_resolve_expired\n");
        let findings = scan_sources(&sources);
        assert!(findings.iter().any(|finding| {
            finding.subject == "adapters/postgres/src/outbox_routine.rs"
                && finding.detail.contains("structurally bind")
        }));
        Ok(())
    }

    #[test]
    fn scan_rejects_expired_resolution_authority_or_sql_in_sibling_module() {
        let mut sources = complete_sources();
        sources.insert(
            "adapters/postgres/src/pool.rs".to_owned(),
            format!("fn bypass() {{ let _ = r#\"{RESOLUTION_SQL}\"#; }}"),
        );

        let findings = scan_sources(&sources);
        assert!(
            findings
                .iter()
                .any(|finding| finding.subject.starts_with("adapters/postgres/src/pool.rs")),
            "a sibling-module authority or raw SQL bypass must be red"
        );
    }

    #[test]
    fn scan_rejects_serving_lane_resolution_owner() -> Result<()> {
        let mut sources = complete_sources();
        let eventing = sources
            .get_mut(EVENTING_FACADE_PATH)
            .context("eventing façade fixture must exist")?;
        *eventing = eventing.replace("MaintenanceWriteLane", "ServingWriteLane");
        assert!(
            scan_sources(&sources)
                .iter()
                .any(|finding| finding.subject.starts_with(EVENTING_FACADE_PATH))
        );
        Ok(())
    }

    #[test]
    fn scan_rejects_resolution_alias_macro_and_operator_chain_breaks() -> Result<()> {
        for mutation in [
            "use self::DlqCallableRoutine as Routine;",
            "macro_rules! bypass { () => { DlqCallableRoutine::ResolveExpired.sql() } }",
        ] {
            let mut sources = complete_sources();
            sources
                .get_mut(EVENTING_FACADE_PATH)
                .context("eventing fixture must exist")?
                .push_str(mutation);
            assert!(!scan_sources(&sources).is_empty(), "must reject {mutation}");
        }

        for path in [RESOLUTION_REQUEST_PATH, RESOLUTION_OPERATOR_PATH] {
            let mut sources = complete_sources();
            *sources
                .get_mut(path)
                .with_context(|| format!("consumer fixture `{path}` must exist"))? =
                "fn detached() {}".to_owned();
            assert!(
                scan_sources(&sources)
                    .iter()
                    .any(|finding| finding.subject == path)
            );
        }
        Ok(())
    }

    #[test]
    fn unrelated_query_binds_do_not_pollute_resolution_chain() -> Result<()> {
        let mut sources = complete_sources();
        let eventing = sources
            .get_mut(EVENTING_FACADE_PATH)
            .context("eventing fixture must exist")?;
        *eventing = eventing.replace(
            "sqlx::query_scalar(",
            "let _ = sqlx::query_scalar(\"SELECT 1 WHERE $1\").bind(7).fetch_one(&mut *self.conn).await; sqlx::query_scalar(",
        );
        assert!(scan_sources(&sources).is_empty());
        Ok(())
    }

    #[test]
    fn committed_workspace_has_complete_same_id_funnel() -> Result<()> {
        let findings = scan_workspace(&workspace_root()?)?;
        assert!(findings.is_empty(), "{findings:#?}");
        Ok(())
    }
}
